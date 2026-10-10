"""Call-local PHP deserialization policy review with original source locations."""
import re
from dataclasses import replace

from .adapters.tokenized import _lex
from .executor import Evidence, ExecutionOutcome
from .text import match_location


def _sensitive_name(name):
    normalized = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', name.lstrip('$'))
    return bool(re.search(r'(?:^|[_.-])(?:app_?key|secret|api[_-]?key|token|password|passwd|encryption_key|access_key|private_key)(?:$|[_.-])', normalized, re.I))


def _arguments(tokens):
    """Split top-level arguments; malformed delimiters remain unresolved."""
    stack, parts, current = [], [], []
    pairs = {')': '(', ']': '[', '}': '{'}
    for token in tokens:
        if token.kind == 'symbol':
            if token.text in {'(', '[', '{'}:
                stack.append(token.text)
            elif token.text in pairs:
                if not stack or stack.pop() != pairs[token.text]:
                    return None
            elif token.text == ',' and not stack:
                parts.append(current)
                current = []
                continue
        current.append(token)
    if stack:
        return None
    if current:
        parts.append(current)
    return parts


def _classes_disabled(tokens):
    if len(tokens) >= 2 and tokens[0].text == '[' and tokens[-1].text == ']':
        body = tokens[1:-1]
    elif len(tokens) >= 3 and tokens[0].text.lower() == 'array' and tokens[1].text == '(' and tokens[-1].text == ')':
        body = tokens[2:-1]
    else:
        return False
    entries = _arguments(body)
    if entries is None:
        return False
    allowed = None
    for entry in entries:
        if len(entry) < 3 or entry[0].kind != 'string' or entry[1].text != '=>':
            return False  # Dynamic keys or spreads can replace the policy.
        if entry[0].text == 'allowed_classes':
            allowed = len(entry) == 3 and entry[2].kind == 'identifier' and entry[2].text.lower() == 'false'
    return allowed is True


def review_deserialization(result, path, text):
    if result.outcome not in {ExecutionOutcome.MATCH, ExecutionOutcome.NO_MATCH}:
        return result
    if not re.search(r'\bunserialize\s*\(', text, re.I):
        return replace(result, outcome=ExecutionOutcome.NO_MATCH, evidence=(), witnesses=())
    tokens = _lex(text, php=True)
    offsets = [0] + [match.end() for match in re.finditer('\n', text)]
    witnesses, errors = [], []
    for index, token in enumerate(tokens[:-1]):
        if token.kind != 'identifier' or token.text.lower() != 'unserialize' or tokens[index+1].text != '(':
            continue
        previous = tokens[index-1].text.lower() if index else ''
        if previous in {'->', '::', 'function', 'new'}:
            continue
        if previous == '\\' and index >= 2 and tokens[index-2].kind == 'identifier':
            errors.append('A namespaced unserialize call does not resolve to the PHP builtin.')
            continue
        # The global-qualified builtin is recognized; namespaced/shadowed calls
        # are unresolved rather than silently treated as safe deserialization.
        depth, end = 0, None
        for cursor in range(index+1, len(tokens)):
            item = tokens[cursor]
            if item.kind == 'symbol' and item.text == '(':
                depth += 1
            elif item.kind == 'symbol' and item.text == ')':
                depth -= 1
                if depth == 0:
                    end = cursor
                    break
        if end is None:
            errors.append('Cannot resolve an unserialize call boundary.')
            continue
        arguments = _arguments(tokens[index+2:end])
        if arguments is None or not arguments:
            errors.append('Cannot resolve unserialize arguments.')
            continue
        if len(arguments) == 2 and _classes_disabled(arguments[1]):
            continue
        start = offsets[token.line-1]+token.column-1
        stop = offsets[tokens[end].line-1]+tokens[end].column
        evidence = Evidence('TEXT_MATCHES', True, location=match_location(path, text, start, stop),
                            explanation='Object-capable PHP deserialization without a literal call-local allowed_classes=false policy. Input trust, allowed types, runtime version and reachable object behavior require review; unrelated JSON decoding is not a mitigation.')
        witnesses.append((evidence,))
        if len(witnesses) >= 100:
            break
    outcome = ExecutionOutcome.INDETERMINATE if errors else ExecutionOutcome.MATCH if witnesses else ExecutionOutcome.NO_MATCH
    return replace(result, outcome=outcome, evidence=tuple(group[0] for group in witnesses),
                   witnesses=tuple(witnesses), errors=tuple(errors))


def review_secret_assignments(result, path, text):
    """A keyword inside SQL/log text is not a credential assignment."""
    if result.outcome not in {ExecutionOutcome.MATCH, ExecutionOutcome.NO_MATCH}:
        return result
    tokens = _lex(text, php=True)
    offsets = [0] + [match.end() for match in re.finditer('\n', text)]
    witnesses = []
    for index, token in enumerate(tokens):
        value = None
        if token.kind == 'identifier' and _sensitive_name(token.text):
            if index+2 < len(tokens) and tokens[index+1].text == '=':
                value = tokens[index+2]
        elif token.kind == 'string' and _sensitive_name(token.text):
            if index+2 < len(tokens) and tokens[index+1].text == '=>':
                value = tokens[index+2]
            elif index+3 < len(tokens) and tokens[index+1].text == ']' and tokens[index+2].text == '=':
                value = tokens[index+3]
            elif index >= 2 and tokens[index-1].text == '(' and tokens[index-2].text.lower() == 'define' and index+2 < len(tokens) and tokens[index+1].text == ',':
                value = tokens[index+2]
        if token.kind == 'string' and re.search(r'\b(?:SELECT|UPDATE|INSERT|DELETE)\b', token.text, re.I):
            # A genuine fixed password in a SQL literal is still embedded
            # credential material. Interpolated SQL values are not static.
            embedded = re.search(r"\b(?:password|passwd|api_key|token|secret)\s*=\s*'([^'$]{8,})'", token.text, re.I)
            if embedded:
                start = offsets[token.line-1]+token.column-1
                witnesses.append((Evidence('TEXT_MATCHES', True, location=match_location(path, text, start, start+1),
                                            explanation='A SQL literal embeds a fixed credential-like value. Verify whether it is an active credential, fixture or intentional public value.'),))
        if value is None or value.kind != 'string':
            continue
        static = value.text
        if value.quote == '"':
            static = re.sub(r'\{\$[A-Za-z_]\w*\}|\$\{[A-Za-z_]\w*\}|\$[A-Za-z_]\w*', '', static)
        if len(static) < 8 or not re.search(r'[A-Za-z0-9]', static):
            continue
        start = offsets[value.line-1]+value.column-1
        # String tokens store decoded delimiters separately; point to the
        # original literal line/column without manufacturing an exact end span.
        evidence = Evidence('TEXT_MATCHES', True,
                            location=match_location(path, text, start, start+1),
                            explanation='A credential-like assignment has a nonempty static literal component. Active secret status, fixture use and service restrictions require independent verification.')
        witnesses.append((evidence,))
        if len(witnesses) >= 100:
            break
    return replace(result, outcome=ExecutionOutcome.MATCH if witnesses else ExecutionOutcome.NO_MATCH,
                   evidence=tuple(group[0] for group in witnesses), witnesses=tuple(witnesses))


def review_sensitive_logging(result, path, text):
    """Review direct secret-like values in PHP logging message arguments."""
    if result.outcome not in {ExecutionOutcome.MATCH, ExecutionOutcome.NO_MATCH}:
        return result
    tokens = _lex(text, php=True)
    offsets = [0] + [m.end() for m in re.finditer('\n', text)]
    witnesses, errors = [], []
    for index, token in enumerate(tokens[:-1]):
        if token.kind != 'identifier' or token.text.lower() not in {'log_message', 'error_log'} or tokens[index+1].text != '(':
            continue
        if index and tokens[index-1].text in {'->', '::', 'function'}:
            continue
        depth, end = 0, None
        for cursor in range(index+1, len(tokens)):
            item = tokens[cursor]
            if item.kind == 'symbol' and item.text == '(':
                depth += 1
            elif item.kind == 'symbol' and item.text == ')':
                depth -= 1
                if depth == 0:
                    end = cursor
                    break
        if end is None:
            errors.append('Cannot resolve logging call boundary.')
            continue
        arguments = _arguments(tokens[index+2:end])
        message_index = 1 if token.text.lower() == 'log_message' else 0
        if arguments is None or len(arguments) <= message_index:
            errors.append('Cannot resolve logging message argument.')
            continue
        depth, exposed = 0, False
        for item in arguments[message_index]:
            if item.kind == 'symbol' and item.text in {'(', '[', '{'}:
                depth += 1
            elif item.kind == 'symbol' and item.text in {')', ']', '}'}:
                depth -= 1
            elif depth == 0 and item.kind == 'identifier' and item.text.startswith('$') and _sensitive_name(item.text):
                exposed = True
            elif depth == 0 and item.kind == 'string' and item.quote == '"':
                from .literal_review import _escaped
                exposed |= any(_sensitive_name(match[1]) for match in re.finditer(r'\$([A-Za-z_]\w*)', item.text)
                               if not _escaped(item.text, match.start()))
        if not exposed:
            continue
        start = offsets[token.line-1]+token.column-1
        stop = offsets[tokens[end].line-1]+tokens[end].column
        witnesses.append((Evidence('TEXT_MATCHES', True, location=match_location(path, text, start, stop),
                                    explanation='A secret-like variable is passed directly in the logging message expression. Resolve its actual value and effective release logging, access and retention before confirming disclosure.'),))
        if len(witnesses) >= 100:
            break
    outcome = ExecutionOutcome.INDETERMINATE if errors else ExecutionOutcome.MATCH if witnesses else ExecutionOutcome.NO_MATCH
    return replace(result, outcome=outcome, evidence=tuple(group[0] for group in witnesses), witnesses=tuple(witnesses), errors=tuple(errors))
