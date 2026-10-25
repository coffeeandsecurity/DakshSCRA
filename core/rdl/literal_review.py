"""Narrow literal refinements; offset-preserving masks retain original evidence."""
import re


def java_security_operations(text, code, stem):
    """Discard illustrative operation names inside literals, retaining offsets."""
    pattern = (r'\bnew\s+(?:java\.util\.)?Random\s*\('
               if stem == 'insecure_package_java_util_random' else r'\b(?:csrf|disable)\s*\(')
    masked = list(text)
    for match in re.finditer(pattern, text):
        if not re.search(pattern, code[match.start():match.end()]):
            masked[match.start():match.end()] = ''.join(c if c in '\r\n' else ' ' for c in match.group())
    return ''.join(masked)


JAVA_LOG_CALL = r'\b(?:System\s*\.\s*(?:out|err)\s*\.\s*(?:print|println|printf)|(?:log|logger)\s*\.\s*(?:trace|debug|info|warn|error|fatal))\s*\('


def java_sensitive_logs(text, code):
    """Select log calls with credential-valued identifiers, not message labels."""
    retained = [c if c in '\r\n' else ' ' for c in text]
    sensitive = r'\b(?:\w*(?:password|secret|token)|otp|pin|sessionId|accessToken|refreshToken)\b|\bget(?:Password|Secret|Token|Otp|Pin)\s*\('
    for call in re.finditer(JAVA_LOG_CALL, code, re.I):
        depth, end = 1, call.end()
        # Bound local argument inspection; incomplete calls remain unresolved.
        while end < min(len(code), call.end() + 8192) and depth:
            depth += (code[end] == '(') - (code[end] == ')')
            end += 1
        if depth or not re.search(sensitive, code[call.end():end - 1], re.I):
            continue
        retained[call.start():end] = text[call.start():end]
    return ''.join(retained)


def jsp_output_expressions(path, text):
    """Retain raw template output, excluding known control and escaping tags."""
    blank = lambda match: ''.join(c if c in '\r\n' else ' ' for c in match.group())
    retained = [c if c in '\r\n' else ' ' for c in text]
    if not str(path).lower().endswith(('.jsp', '.jspx')):
        return ''.join(retained)
    libraries, bindings = {}, {}
    known = {'jakarta.tags.core': 'core', 'http://java.sun.com/jsp/jstl/core': 'core',
             'jakarta.tags.fmt': 'fmt', 'http://java.sun.com/jsp/jstl/fmt': 'fmt',
             'jakarta.tags.functions': 'functions', 'http://java.sun.com/jsp/jstl/functions': 'functions'}
    def bind(prefix, uri):
        bindings.setdefault(prefix, set()).add(known.get(uri, 'unknown'))
    declarations = re.sub(r'<%--[\s\S]*?(?:--%>|$)', blank, text)
    for declaration in re.finditer(r'<%@\s*taglib\b[^%]*%>', declarations):
        attrs = {m[1]: m[3] for m in re.finditer(r'''(prefix|uri)\s*=\s*(["'])(.*?)\2''', declaration.group())}
        if attrs.get('prefix'):
            bind(attrs['prefix'], attrs.get('uri'))
    namespaces = re.sub(r'<!--[\s\S]*?(?:-->|$)', blank, declarations)
    for namespace in re.finditer(r'''\bxmlns:([\w]+)\s*=\s*(["'])(.*?)\2''', namespaces):
        bind(namespace[1], namespace[3])
    libraries = {prefix: next(iter(kinds)) for prefix, kinds in bindings.items()
                 if len(kinds) == 1 and 'unknown' not in kinds}
    selected = re.sub(r'<%--[\s\S]*?(?:--%>|$)|<%[\s\S]*?(?:%>|$)', blank, text)
    # XML escaping alone does not establish safe script, style or URL output.
    context_spans = [(m.start(), m.end()) for m in re.finditer(
        r'<(?:script|style)\b[^>]*>[\s\S]*?(?:</(?:script|style)\s*>|$)', selected, re.I)]
    for attribute in re.finditer(r'''\b(?:on[\w]+|href|src|action|formaction|style)\s*=\s*(["'])(.*?)\1''', selected, re.I | re.S):
        context_spans.append((attribute.start(2), attribute.end(2)))
    def contextual(position):
        return any(start <= position < end for start, end in context_spans)
    # Body values are captured by set or XML-escaped by out, rather than raw output.
    for body in re.finditer(r'<([\w]+):(set|out)\b([^>]*)(?<!/)>[\s\S]*?</\1:\2\s*>', selected):
        if libraries.get(body[1]) != 'core' or contextual(body.start()):
            continue
        escape = re.search(r'''\bescapeXml\s*=\s*(["'])(.*?)\1''', body[3], re.I)
        if body[2] == 'set' or escape is None or escape[2].strip().lower() == 'true':
            selected = selected[:body.start()] + blank(body) + selected[body.end():]
    for tag in re.finditer(r'''<([\w]+):([\w]+)\b(?:[^>"']|"[^"]*"|'[^']*')*>''', selected):
        library = libraries.get(tag[1])
        if library == 'fmt' and tag[2] in {'formatNumber', 'formatDate'}:
            # Value conversion is typed; user-selected patterns/symbols can emit text.
            for value in re.finditer(r'''\bvalue\s*=\s*(["'])(.*?)\1''', tag.group(), re.S):
                start, end = tag.start() + value.start(), tag.start() + value.end()
                selected = selected[:start] + blank(value) + selected[end:]
            continue
        safe = library == 'core' and tag[2] in {'if', 'when', 'forEach', 'forTokens', 'set', 'choose', 'otherwise'}
        if library == 'core' and tag[2] == 'out':
            # A computed escapeXml value cannot be assumed true.
            attr = re.search(r'''\bescapeXml\s*=\s*(["'])(.*?)\1''', tag.group(), re.I)
            safe = attr is None or attr[2].strip().lower() == 'true'
        if safe and not contextual(tag.start()):
            selected = selected[:tag.start()] + blank(tag) + selected[tag.end():]
    for match in re.finditer(r'\$\{[^}]{1,500}\}', selected):
        expression = match.group()[2:-1].strip()
        literal = r'''(?:'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"|[+-]?\d+(?:\.\d+)?|true|false|null)'''
        # Fixed branch values do not render the condition's input as output.
        if re.fullmatch(literal, expression) or re.fullmatch(r'[^?:]+\?\s*' + literal + r'\s*:\s*' + literal, expression, re.S):
            continue
        escaped = re.match(r'([\w]+):escapeXml\s*\(', expression)
        complete_escape = False
        if escaped and libraries.get(escaped[1]) == 'functions':
            depth, quote, cursor = 1, '', escaped.end()
            while cursor < len(expression) and depth:
                char = expression[cursor]
                if quote:
                    if char == '\\':
                        cursor += 1
                    elif char == quote:
                        quote = ''
                elif char in {'"', "'"}:
                    quote = char
                else:
                    depth += (char == '(') - (char == ')')
                cursor += 1
            complete_escape = depth == 0 and not expression[cursor:].strip()
        if expression == 'pageContext.request.contextPath' or (complete_escape and not contextual(match.start())):
            continue
        retained[match.start():match.end()] = text[match.start():match.end()]
    return ''.join(retained)


def java_fixed_destinations(text):
    """A complete literal dispatch destination contains no caller input."""
    return re.sub(r'\b(?:getRequestDispatcher|sendRedirect)\s*\(\s*"(?:\\.|[^"\\])*"\s*\)',
                  lambda match: ''.join(c if c in '\r\n' else ' ' for c in match.group()), text)


def document_http_identifiers(text):
    """Namespace and tag-library identifiers do not initiate HTTP requests."""
    # A compiled Android XML string pool is not textual request code. Its
    # namespace strings can follow arbitrary binary tokens such as "src".
    # Input coverage reporting separately requires decoding this artifact.
    if text.startswith('\x03\x00\x08\x00'):
        return ''.join(c if c in '\r\n' else ' ' for c in text)
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
    from .adapters.tokenized import _lex
    lines = [0] + [match.end() for match in re.finditer('\n', text)]
    for token in _lex(text, php=True):
        if token.kind != 'string' or token.quote not in {'\"', "'"}:
            continue
        start = lines[token.line-1] + token.column-1
        end = start + len(token.text) + 2
        for match in re.finditer(r'`|\b(?:shell_exec|exec|passthru|system|popen)(?=\s*\()', text[start:end], re.I):
            for offset in range(start+match.start(), start+match.end()):
                masked[offset] = ' '

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


def javascript_request_operations(text, code):
    """Browser APIs and a locally declared fetch are not server request APIs."""
    masked = list(text)
    patterns = [r'\$\.ajax\s*\(', r'\bXMLHttpRequest\s*\.\s*open\s*\(']
    if re.search(r'(?m)^\s*(?:export\s+)?(?:async\s+)?function\s+fetch\s*\(', code):
        patterns.append(r'(?<![\w.$])fetch\s*\(')
    for pattern in patterns:
        for match in re.finditer(pattern, code):
            masked[match.start():match.end()] = [' ' if c not in '\r\n' else c for c in match.group()]
    return ''.join(masked)


def javascript_secret_values(text):
    """Keep real default credentials; remove an explicit display sentinel."""
    return re.sub(r"\bBogusPassword\s*:\s*(['\"])password\1",
                  lambda m: ''.join(c if c in '\r\n' else ' ' for c in m.group()), text)


def password_security_operations(text, code, stem):
    """Select executable password operations with their original source offsets."""
    if stem == 'password_self_comparison':
        return code
    retained = [c if c in '\r\n' else ' ' for c in text]
    pattern = (r'\bfunc\s+(?:\([^)]*\)\s*)?\w*Password\w*\s*\([^{}]*\)\s*[^{}]*\{'
               if stem == 'fast_hashing_of_passwords' else r'\b\w*(?:Encrypt|Decrypt)Password\w*\s*\([^{}]*\)\s*[^{}]*\{')
    for match in re.finditer(pattern, code, re.I):
        depth, end = 1, match.end()
        while end < min(len(code), match.end()+32768) and depth:
            depth += (code[end] == '{') - (code[end] == '}'); end += 1
        if depth: continue
        retained[match.start():end] = code[match.start():end]
    return ''.join(retained)


def jwt_claim_operations(text, code):
    """Review decoded claims per method; unrelated validation cannot suppress it."""
    retained = [c if c in '\r\n' else ' ' for c in code]
    for match in re.finditer(r'\b(?:public|private|protected|internal)\s+(?:(?:static|override|async|virtual)\s+)*[\w.<>\[\]?]+\s+\w+\s*\([^{}]*\)\s*\{', code):
        end, depth = match.end(), 1
        while end < min(len(code), match.end()+32768) and depth:
            depth += (code[end] == '{') - (code[end] == '}'); end += 1
        block = code[match.start():end]
        if depth or not re.search(r'\.Claims\b', block):
            continue
        # Only a preceding, unconditional synchronous validation of the same
        # token can exclude this local review site. An unrelated token, a later
        # call, or an unchecked asynchronous result is not that evidence.
        reads = list(re.finditer(r'\bReadJwtToken\s*\(\s*([A-Za-z_]\w*(?:\.\w+)*)\s*\)', block))
        if not reads and re.search(r'\bReadJwtToken\s*\(', block):
            retained[match.start():end] = block
            continue
        unresolved = False
        for read in reads:
            before = block[:read.start()]
            validations = list(re.finditer(r'\bValidateToken\s*\(\s*' + re.escape(read.group(1)) + r'\s*,', before))
            def validates_current_value(validation):
                prefix = before[:validation.start()]
                if prefix.count('{') - prefix.count('}') != 1:
                    return False
                statement = prefix[max(prefix.rfind(';'), prefix.rfind('{'), prefix.rfind('}')) + 1:]
                if not re.fullmatch(r'\s*(?:(?:[\w.<>]+\s+)?\w+\s*=\s*)?(?:\w+\.)*', statement):
                    return False
                changed = re.search(r'(?<![\w.])' + re.escape(read.group(1)) + r'\s*(?:=(?!=)|\+=|\?\?=)',
                                    before[validation.end():])
                return not changed
            protected = any(validates_current_value(v) for v in validations)
            if not protected:
                unresolved = True
                break
        if unresolved:
            retained[match.start():end] = block
    return ''.join(retained)
