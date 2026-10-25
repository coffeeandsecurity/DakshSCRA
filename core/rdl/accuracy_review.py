"""Operation-specific exclusions shared by pattern and native text rules."""
import re


def review_operations(rule_id, path, content):
    stem = str(rule_id).rsplit('.', 1)[-1]
    if 'dotnet' in str(rule_id) and stem.endswith('_hardcoded_secret_material'):
        # Razor expressions supply a runtime value, rather than embedding a key.
        return re.sub(r'(?:Secret|ApiKey|Token|Password)\s*=\s*"@(?:Model|Context|ViewData|ViewBag|Html|Url)\b[^"\r\n]*"',
                      lambda m: ' ' * len(m.group()), content, flags=re.I)
    if stem == 'weak_mitigation_using_disable_bypass_ignore_suppress_unsafe':
        def translated_label(match):
            key = match.group(1)
            if re.search(r'auth|csrf|xss|cors|tls|ssl|verify|validation|sanitize|security', key, re.I):
                return match.group()
            return re.sub(r'\b(?:disable|bypass|ignore|suppress|unsafe)\b', lambda word: ' ' * len(word.group()), match.group(), flags=re.I)
        # A translated label is not an executable security-control setting.
        return re.sub(r'''["']((?:disable|bypass|ignore|suppress|unsafe) [^"'\r\n]+)["']\s*:\s*["']''', translated_label, content, flags=re.I)
    if stem == 'deprecated_js_function_escape_unescape_eval':
        return re.sub(r'\b(?:window\s*\.\s*)?CSS\s*\.\s*escape\b', lambda m: ' ' * len(m.group()), content)
    if stem == 'insecure_code_execution_assert_and_eval':
        from .source_review import source_views
        text, code = source_views(path, content)
        masked = list(text)
        for match in re.finditer(r'\bassert\s*\(\s*\$[A-Za-z_]\w*\s*(?:===|!==|==|!=|>=|<=|>|<)', code):
            masked[match.start():match.start()+6] = ' ' * 6
        return ''.join(masked)
    if stem not in {'insecure_method_call_eval_settimeout_setinterval', 'ssrf_httpclient_with_user_controlled_url'}:
        return content
    from .source_review import source_views
    text, code = source_views(path, content)
    masked = list(text)
    def erase(start, end):
        masked[start:end] = ''.join(c if c in '\r\n' else ' ' for c in text[start:end])
    if stem == 'insecure_method_call_eval_settimeout_setinterval':
        for match in re.finditer(r'\b(?:setTimeout|setInterval)\s*\(\s*', code):
            argument = code[match.end():]
            # Only syntactically explicit function callbacks are excluded.
            # Variable callbacks remain unresolved rather than assumed safe.
            if re.match(r'(?:async\s+)?function\b|(?:async\s+)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>', argument):
                erase(match.start(), match.end())
    else:
        declared = dict((name, typ) for typ, name in re.findall(r'\b([A-Z]\w*)\s+(\w+)\b', code))
        typed = set(re.findall(r'\b(?:System\.Net\.Http\.)?HttpClient\s+([A-Za-z_]\w*)', code))
        typed.update(re.findall(r'\bvar\s+(\w+)\s*=\s*new\s+(?:System\.Net\.Http\.)?HttpClient\s*\(', code))
        typed.update(re.findall(r'\bvar\s+(\w+)\s*=\s*\w+\.CreateClient\s*\(', code))
        pattern = r'\b(\w+)\s*\.\s*(?:GetAsync|PostAsync|PutAsync|DeleteAsync|SendAsync|GetStringAsync|GetByteArrayAsync)\s*\(\s*'
        for match in re.finditer(pattern, text):
            receiver = match.group(1)
            if not code[match.start():match.start()+len(receiver)].strip():
                erase(match.start(), match.end());continue
            if receiver not in typed and receiver in declared and declared[receiver] != 'HttpClient' and receiver.lower().lstrip('_') != 'httpclient':
                erase(match.start(), match.end());continue
            argument = text[match.end():]
            # A complete fixed URL or relative path has no caller-controlled
            # destination in this expression. BaseAddress needs its own review.
            literal = re.match(r'@?"(?:[^"\\]|\\.|"")*"\s*(?=[,)])', argument)
            if literal:
                erase(match.start(), match.end())
    return ''.join(masked)
