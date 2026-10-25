"""Shared offset-preserving mobile pattern precision across both engines."""
import re
import xml.etree.ElementTree as ET


def blank(text):
    return ''.join(c if c in '\r\n' else ' ' for c in text)


def fixed_sql_calls(path, text):
    """Remove only Java calls whose SQL structure is entirely literal text."""
    if not str(path).endswith('.java') or not any(name in text for name in ('rawQuery', 'execSQL')):
        return text
    from core.mobile_model import views
    comments, code = views(path, text)
    pieces = list(text)
    literal = r'"(?:\\.|[^"\\])*"'
    for hit in re.finditer(r'\b(?:rawQuery|execSQL)\s*\(', code):
        start = hit.end()
        depth, end = 1, start
        while end < min(len(code), start+10000):
            char = code[end]
            if (char == ',' and depth == 1) or (char == ')' and depth == 1):
                break
            depth += (char == '(') - (char == ')')
            end += 1
        if end < len(code) and code[end] in ',)' and depth == 1 and re.fullmatch(r'\s*'+literal+r'(?:\s*\+\s*'+literal+r')*\s*', comments[start:end], re.S):
            pieces[hit.start():hit.end()] = blank(text[hit.start():hit.end()])
    return ''.join(pieces)


def identifier_calls(path, text):
    """Distinguish Java model getter declarations from executable API calls."""
    if not str(path).endswith('.java') or not any(name in text for name in ('getDeviceId', 'getImei', 'getMeid', 'getSubscriberId')):
        return text
    from core.mobile_model import views
    _, code = views(path, text)
    pieces = list(text)
    for hit in re.finditer(r'\b(?:getDeviceId|getImei|getMeid|getSubscriberId)\s*\(', code):
        prefix = code[code.rfind('\n', 0, hit.start())+1:hit.start()]
        declaration = re.fullmatch(r'\s*(?:(?:public|protected|private|final|static|abstract|synchronized|native)\s+)+[\w.$<>?\[\]]+\s+', prefix)
        if declaration:
            pieces[hit.start():hit.end()] = blank(text[hit.start():hit.end()])
    return ''.join(pieces)


def java_secret_markers(path, text):
    """A rendered field label followed by runtime values is not a literal secret."""
    pattern = r'(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*"([^"]{8,})"'
    if not str(path).endswith('.java') or not re.search(pattern, text):
        return text
    from core.mobile_model import views
    comments, code = views(path, text)
    pieces = list(text)
    for hit in re.finditer(pattern, text):
        # Preserve real assignments, embedded literal configuration and even
        # commented credentials. Mask only matches crossing out of Java data
        # into executable expressions such as ", password=" + this.password.
        start, end = hit.span(1)
        value_start, value_end = hit.span(2)
        if (comments[start:end].strip() and not code[start:end].strip()
                and re.search(r'[A-Za-z_$]', code[value_start:value_end])):
            pieces[start:end] = blank(text[start:end])
    return ''.join(pieces)


def immutable_pending_intents(path, text):
    """Mask only calls with a resolved immutable flag; unknown flags remain leads."""
    pattern = r'\bPendingIntent\s*\.\s*(?:getBroadcast|getActivity|getService|getForegroundService)\s*\('
    if not str(path).endswith('.java') or 'PendingIntent' not in text:
        return text
    from core.mobile_model import views
    _, code = views(path, text)
    pieces = list(text)
    values = dict(FLAG_ONE_SHOT=0x40000000, FLAG_NO_CREATE=0x20000000,
                  FLAG_CANCEL_CURRENT=0x10000000, FLAG_UPDATE_CURRENT=0x08000000,
                  FLAG_IMMUTABLE=0x04000000, FLAG_MUTABLE=0x02000000)
    for hit in re.finditer(pattern, code):
        stack, starts, arguments = ['('], hit.end(), []
        for index in range(hit.end(), min(len(code), hit.end()+10000)):
            char = code[index]
            if char in '([{':
                stack.append(char)
            elif char in ')]}':
                if not stack or stack[-1] != {')':'(', ']':'[', '}':'{'}[char]:
                    break
                stack.pop()
                if not stack:
                    arguments.append(code[starts:index])
                    break
            elif char == ',' and len(stack) == 1:
                arguments.append(code[starts:index])
                starts = index+1
        if stack or len(arguments) < 4:
            continue
        expression = re.sub(r'[()]', '', arguments[3])
        flags = 0
        for term in expression.split('|'):
            term = term.strip()
            if len(term) > 100:
                break
            if re.fullmatch(r'(?:0[xX][0-9a-fA-F]+|0|[1-9][0-9]*)', term):
                flags |= int(term, 0)
            elif re.fullmatch(r'(?:android\.app\.)?PendingIntent\.FLAG_\w+', term) and term.rsplit('.',1)[-1] in values:
                flags |= values[term.rsplit('.',1)[-1]]
            else:
                break
        else:
            if flags & values['FLAG_IMMUTABLE'] and not flags & values['FLAG_MUTABLE']:
                pieces[hit.start():hit.end()] = blank(text[hit.start():hit.end()])
    return ''.join(pieces)


def refine(stem, path, text, project_root=None):
    if stem in {'review_android_persistent_device_identifier', 'persistent-device-identifier'}:
        return identifier_calls(path, text)
    if stem == 'android_hardcoded_secret_marker':
        return java_secret_markers(path, text)
    if stem == 'insecure_pendingintent_missing_immutability_flag':
        return immutable_pending_intents(path, text)
    if stem in {'sqlite_raw_query_with_potential_injection', 'review_android_sql_raw_query_surface', 'sql-raw-query-surface'}:
        return fixed_sql_calls(path, text)
    if stem == 'file_sharing_without_content_provider':
        from core.mobile_model import views
        comments, code = views(path,text)
        pieces = list(blank(text))
        imported = re.search(r'\bimport\s+android\.content\.(?:Intent|\*)\s*;',code)
        if not imported and 'android.content.Intent' not in code:
            return ''.join(pieces)
        for hit in re.finditer(r'\bnew\s+(?:android\.content\.)?Intent\s*\(\s*(?:android\.content\.)?Intent\.[A-Z_]+\s*,\s*(?:android\.net\.)?Uri\s*\.\s*parse\s*\(',code):
            if not imported and not hit.group().startswith('new android.content.Intent'):
                continue
            pieces[hit.start():hit.end()] = text[hit.start():hit.end()]
        for hit in re.finditer(r'\b(\w+)\s*\.\s*setData(?:AndType)?\s*\(\s*(?:android\.net\.)?Uri\s*\.\s*parse\s*\(',code):
            name = re.escape(hit[1])
            if re.search(r'\b(?:android\.content\.)?Intent\s+'+name+r'\s*=\s*new\s+(?:android\.content\.)?Intent\s*\(',code[:hit.start()]):
                pieces[hit.start():hit.end()] = text[hit.start():hit.end()]
        return ''.join(pieces)
    if stem == 'credential_http_request':
        if not str(path).endswith('.java'):
            return blank(text)
        from core.mobile_model import views
        from .android_requests import credential_http_requests
        comments, code = views(path, text)
        hits = credential_http_requests(comments, code)
        pieces = list(blank(text))
        for start, end, detail in hits:
            pieces[start:end] = text[start:end]
        return ''.join(pieces)
    if stem == 'otp_completion_navigation':
        from core.mobile_model import views
        from .client_review import review_client, OTP_CALLBACK_PATTERN
        from .executor import ExecutionResult, ExecutionOutcome
        entry = dict(client_check='otp-navigation', pattern=OTP_CALLBACK_PATTERN,
                     description='OTP completion navigation without local verification requires review.')
        comments, code = views(path, text)
        result = review_client(entry, ExecutionResult(ExecutionOutcome.MATCH, stem, ()), path, comments, code)
        return blank(text) if result.outcome == ExecutionOutcome.NO_MATCH else text
    if stem == 'logout_retained_state' and project_root:
        from core.mobile_project import project_for_review
        from .session_contracts import logout_contracts
        contracts, unknown = logout_contracts(project_for_review(project_root), path)
        return text if contracts or unknown else blank(text)
    if stem in {'privacy_api_purpose','credential_backup_correlation'} and project_root:
        from .executor import ExecutionResult, ExecutionOutcome
        from .mobile_review import review_mobile
        from core.mobile_model import views
        comments,code=views(path,text)
        check='privacy' if stem=='privacy_api_purpose' else 'backup'
        entry=dict(rule_id=stem,mobile_check='project-'+check,file_patterns=['Info.plist' if check=='privacy' else 'AndroidManifest.xml'])
        result=review_mobile(entry,ExecutionResult(ExecutionOutcome.NO_MATCH,stem,()),path,comments,code,project_root)
        return blank(text) if result.outcome==ExecutionOutcome.NO_MATCH else text
    if stem in {'release_debug_signing','provider_stream_read'}:
        from core.mobile_model import views
        from core.mobile_project import signing_hits, stream_hits
        comments,code=views(path,text)
        hits=list(signing_hits(path,comments,code) if stem == 'release_debug_signing' else stream_hits(comments,code))
        pieces=list(blank(text))
        for start,end,detail in hits:
            pieces[start:end]=text[start:end]
        return ''.join(pieces)
    if stem == 'react_native_hardcoded_secret_marker':
        def action(hit):
            return blank(hit.group()) if hit.group(1).replace('_','').casefold() == hit.group(3).replace('_','').casefold() else hit.group()
        text = re.sub(r'\bexport\s+const\s+(set_[a-z_]*(?:token|password|secret)[a-z_]*)\s*=\s*(["\'])([A-Za-z_]+)\2', action, text)
    if stem in {'ios_insecure_url_usage','swiftui_insecure_url_usage','react_native_insecure_http_usage','insecure_http_communication'}:
        from .literal_review import document_http_identifiers
        text = document_http_identifiers(text)
        if str(path).endswith('.pbxproj'):
            text = re.sub(r'http://(?:localhost|127\.0\.0\.1)(?=[:/])',lambda h:blank(h.group()),text)
    if stem in {'review_android_deeplink_entry_surface','unsafe_intent_filters'} and str(path).endswith('.xml'):
        try:
            root=ET.fromstring(text)
        except ET.ParseError:
            return text
        from .mobile_review import _tags, ANDROID
        nodes=list(root.iter('intent-filter')); tags=_tags(text,'intent-filter')
        if len(nodes)!=len(tags):
            return text
        pieces=list(text)
        for node,tag in zip(nodes,tags):
            browsable=any(c.get(ANDROID+'name')=='android.intent.category.BROWSABLE' for c in node.findall('category'))
            if not (browsable and node.findall('data')):
                pieces[tag.start():tag.end()]=blank(tag.group())
        text=''.join(pieces)
    if stem == 'nested_intent_component_launch':
        from core.mobile_model import views, enclosing_blocks
        comments,code=views(path,text); pieces=list(text)
        cast=r'(?:\(\s*(?:java\.lang\.)?Class\s*(?:<\s*\?\s*>)?\s*\)\s*)?'
        fixed=r'(?:new\s+)?Intent\s*\([^,;\n]+,\s*'+cast+r'[\w.]+(?:\.class|::class\.java)\s*\)'
        for direct in re.finditer(r'\bstartActivity\s*\(\s*'+fixed+r'\s*\)',code):
            pieces[direct.start():direct.end()]=blank(text[direct.start():direct.end()])
        for hit in re.finditer(r'\bstartActivity\s*\(\s*(\w+)\s*\)',code):
            blocks=enclosing_blocks(code,hit.start());start=blocks[-1] if blocks else 0
            prefix=comments[start:hit.start()];name=re.escape(hit.group(1))
            assignments=list(re.finditer(r'\b'+name+r'\s*=\s*([^;\n]+)',prefix))
            mutation = re.search(r'\b'+name+r'\s*\.\s*(?:setComponent|setClass|setClassName|fillIn)\s*\(',prefix[assignments[-1].end():]) if assignments else None
            if assignments and re.match(fixed,assignments[-1].group(1)) and not mutation:
                pieces[hit.start():hit.end()]=blank(text[hit.start():hit.end()])
            # Locally constructed VIEW intents are outgoing URI boundaries,
            # not evidence that an incoming parcelled Intent is forwarded.
            outgoing = r'new\s+Intent\s*\(\s*Intent\.ACTION_VIEW\s*(?:,|\))'
            escaped = re.search(r'\b\w+\s*\([^;\n]*\b'+name+r'\b', prefix[assignments[-1].end():]) if assignments else None
            reassigned_action = re.search(r'\b'+name+r'\s*\.\s*setAction\s*\(', prefix[assignments[-1].end():]) if assignments else None
            if assignments and re.match(outgoing, assignments[-1].group(1)) and not mutation and not reassigned_action and not escaped:
                pieces[hit.start():hit.end()]=blank(text[hit.start():hit.end()])
        text=''.join(pieces)
    return text
