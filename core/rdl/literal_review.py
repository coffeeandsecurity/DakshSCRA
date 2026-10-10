"""Narrow literal refinements; offset-preserving masks retain original evidence."""
import re


def java_fixed_destinations(text):
    """A complete literal dispatch destination contains no caller input."""
    return re.sub(r'\b(?:getRequestDispatcher|sendRedirect)\s*\(\s*"(?:\\.|[^"\\])*"\s*\)',
                  lambda match: ''.join(c if c in '\r\n' else ' ' for c in match.group()), text)


def document_http_identifiers(text):
    """Namespace and tag-library identifiers do not initiate HTTP requests."""
    blank = lambda match: ''.join(c if c in '\r\n' else ' ' for c in match.group())
    catalog = bool(re.search(r'<(?:\w+:)?catalog\b[^>]*urn:oasis:names:tc:entity:xmlns:xml:catalog', text))
    text = re.sub(r'<!DOCTYPE[^>]*>', blank, text, flags=re.I)
    text = re.sub(r"\b(?:xmlns(?::[\w.-]+)?|xsi:schemaLocation)\s*=\s*([\"'])(.*?)\1", blank, text, flags=re.S)
    text = re.sub(r'<%@\s*taglib\b[\s\S]*?%>', blank, text, flags=re.I)
    def identifiers(match, names):
        return re.sub(r'\b(?:'+names+r''')\s*=\s*(["'])(.*?)\1''', blank, match.group(), flags=re.S)
    text = re.sub(r'<(?:\w+:)?macrodef\b[^>]*>', lambda match: identifiers(match, 'uri'), text)
    if catalog:
        text = re.sub(r'<(?:\w+:)?(?:system|public|uri)\b[^>]*>',
                      lambda match: identifiers(match, 'systemId|publicId|name'), text)
    return text


def secret_placeholders(text):
    """A complete property placeholder contains no embedded credential value."""
    return re.sub(r'''(["'])(?:\$|#)\{[^{}\r\n]+\}\1''',
                  lambda match: ' ' * len(match.group()), text)


def php_process_call_names(text):
    """Keep PHP process calls distinct from curl_exec and SQL exec methods."""
    masked = list(text)
    names = {'shell_exec', 'exec', 'passthru', 'system', 'popen'}
    for match in re.finditer(r'\b([A-Za-z_]\w*)\s*\(', text):
        name = match.group(1).lower()
        cursor = match.start() - 1
        while cursor >= 0 and text[cursor].isspace():
            cursor -= 1
        previous = text[max(0, cursor-1):cursor+1]
        if ((name not in names and any(name.endswith(value) for value in names)) or
                (name in names and previous in {'->', '::'})):
            start, end = match.span(1)
            masked[start:end] = ' ' * (end-start)
    return ''.join(masked)


def php_regex_replacements(text):
    """A literal pattern without /e does not evaluate its replacement as PHP."""
    if not re.search(r'\bpreg_replace\b', text, re.I):
        return text
    from .adapters.tokenized import _lex
    tokens = _lex(text, php=True)
    lines = [0] + [match.end() for match in re.finditer('\n', text)]
    masked = list(text)
    endings = {'(': ')', '[': ']', '{': '}', '<': '>'}
    for index, token in enumerate(tokens[:-2]):
        if token.kind != 'identifier' or token.text.lower() != 'preg_replace' or tokens[index+1].text != '(':
            continue
        pattern = tokens[index+2]
        if pattern.kind != 'string' or not pattern.text or (pattern.quote == '"' and '$' in pattern.text):
            continue
        opening = pattern.text[0]
        if opening.isalnum() or opening.isspace() or opening == '\\':
            continue
        closing = endings.get(opening, opening)
        boundary = pattern.text.rfind(closing)
        if boundary <= 0 or _escaped(pattern.text, boundary):
            continue
        flags = pattern.text[boundary+1:]
        if not re.fullmatch('[A-Za-z]*', flags) or 'e' in flags.lower():
            continue
        start = lines[token.line-1] + token.column-1
        masked[start:start+len(token.text)] = ' ' * len(token.text)
    return ''.join(masked)


def _escaped(text, index):
    count = 0
    index -= 1
    while index >= 0 and text[index] == '\\':
        count += 1
        index -= 1
    return count % 2 == 1


def shell_literals(text, stem):
    masked = list(text)
    if stem == 'backtick_command_substitution_with_variable':
        for index, char in enumerate(text):
            if char == '`' and _escaped(text, index):
                masked[index] = ' '
    elif stem == 'unquoted_variable_in_command_context':
        offset = 0
        quote = ''
        for line in text.splitlines(keepends=True):
            # Substitution introduces nested quoting/executable contexts. Keep
            # unresolved cases rather than incorrectly treating them as data.
            safe_line = not quote and '$(' not in line and not any(c == '`' and not _escaped(line, i) for i, c in enumerate(line))
            for index, char in enumerate(line):
                if char in "\"'" and (quote == "'" or not _escaped(line, index)):
                    if not quote:
                        quote = char
                    elif quote == char:
                        quote = ''
                elif safe_line and char == '$' and quote and not _escaped(line, index):
                    masked[offset + index] = ' '
            offset += len(line)
        if quote:
            return text
    return ''.join(masked)


def kotlin_dynamic_literals(text):
    masked = list(text)
    for match in re.finditer(r'"(?:\\.|[^"\\])*"', text):
        if (match.start() and text[match.start()-1] == '"') or text[match.end():match.end()+1] == '"':
            continue
        value = match.group()[1:-1]
        if '\\' in value or '$' not in value:
            continue
        static = re.sub(r'\$\{[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\}|\$[A-Za-z_]\w*', '', value)
        # Separators alone are not embedded credentials. Unresolved executable
        # interpolation and static alphanumeric material remain review leads.
        if not static.strip('|:; ,./_-'):
            for index in range(match.start(), match.end()):
                if text[index] not in '\r\n':
                    masked[index] = ' '
    return ''.join(masked)


def promise_resolver_timers(text):
    # Do not assume the standard constructor/timer contract when a same-file
    # declaration, import, assignment or parameter can shadow either builtin.
    for name in ('Promise', 'setTimeout'):
        escaped = re.escape(name)
        shadows = (r'\b(?:const|let|var|class|function)\s+'+escaped+r'\b|'
                   r'\b(?:const|let|var)\s*[\{\[][^;=\n]*\b'+escaped+r'\b|'
                   r'\bimport\b[^;\n]*\b'+escaped+r'\b|'
                   r'\b'+escaped+r'\s*(?:=(?!=)|=>)|'
                   r'\([^)]*\b'+escaped+r'\b[^)]*\)\s*(?:=>|\{)')
        if re.search(shadows, text):
            return text
    pattern = r'\bnew\s+Promise\s*\(\s*([A-Za-z_$][\w$]*)\s*=>\s*(setTimeout)\s*\(\s*\1\s*,\s*[A-Za-z_0-9\s.*+/-]+\)\s*\)'
    masked = list(text)
    for match in re.finditer(pattern, text):
        start, end = match.span(2)
        masked[start:end] = ' ' * (end-start)
    return ''.join(masked)


def resource_algorithm_words(path, text):
    normalized = str(path).replace('\\', '/')
    if '/res/' not in normalized or not normalized.endswith('.xml'):
        return text
    # In these locale packs, des/Des is an ordinary word. Unrecognized resource
    # prose remains unresolved; exact public-suffix entries are independently
    # recognizable regardless of the locale.
    localized = bool(re.search(r'/values-(?:fr|de|ca)(?:-|/)', normalized))
    masked = list(text)
    for match in re.finditer(r'<(string|item)\b[^>]*>(.*?)</\1\s*>', text, re.S):
        body = match.group(2)
        opening = match.group().split('>', 1)[0]
        if body.strip().lower() == 'des' or re.search(r'algorithm|crypto|digest', opening, re.I) or re.search(r'cipher|algorithm|crypto|encrypt|padding|digest', body, re.I):
            continue
        if not localized and not re.fullmatch(r'\s*des\.[a-z0-9.-]+\s*', body):
            continue
        for segment in re.finditer(r'(?:^|>)([^<]*)(?=<|$)', body):
            for word in re.finditer(r'\b(?:des|Des)\b', segment.group(1)):
                start = match.start(2)+segment.start(1)+word.start()
                masked[start:start+3] = '   '
    return ''.join(masked)
