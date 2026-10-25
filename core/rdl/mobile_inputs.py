"""Located mobile UI input inventory, without invented propagation edges."""
import re


def input_records(path, text):
    if str(path).lower().endswith('.java'):
        return _android_text_records(path, text) + _android_scan_records(path, text)
    if not str(path).lower().endswith(('.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs')):
        return []
    if 'onChangeText' not in text and 'onCodeFilled' not in text:
        return []
    from .source_review import source_views
    comments, code = source_views(path, text)
    bindings = {}
    for hit in re.finditer(r'\bimport\s*\{([^}]+)\}\s*from\s*["\']react-native["\']', comments):
        if code[hit.start():hit.start()+6] != 'import':
            continue
        for name in hit.group(1).split(','):
            parts = re.split(r'\s+as\s+', name.strip())
            if parts[0] == 'TextInput':
                bindings[parts[-1]] = ('onChangeText', 'mobile_text')
    for hit in re.finditer(r'\bimport\s+(\w+)\s+from\s*["\']@twotalltotems/react-native-otp-input["\']', comments):
        if code[hit.start():hit.start()+6] == 'import':
            bindings[hit.group(1)] = ('onCodeFilled', 'mobile_otp')
    records = []
    lines = text.splitlines()
    for binding, (prop, origin) in bindings.items():
        for tag in re.finditer(r'<'+re.escape(binding)+r'\b', code):
            depth, end = 0, tag.end()
            while end < len(code):
                char = code[end]
                if char == '{': depth += 1
                elif char == '}': depth = max(0, depth-1)
                elif char == '>' and depth == 0: break
                end += 1
            if end >= len(code):
                continue
            callback = re.search(r'\b'+prop+r'\s*=\s*\{', code[tag.end():end])
            if not callback:
                continue
            offset = tag.end()+callback.start()
            line = text.count('\n', 0, offset)+1
            location = dict(path=str(path), line=line, column=offset-text.rfind('\n', 0, offset))
            step = dict(predicate='SOURCE', matched=True, symbol=binding+'.'+prop,
                        input_origin=origin, location=location, transition='',
                        snippet=[dict(line=i+1,text=lines[i],highlight=i+1==line) for i in range(max(0,line-3),min(len(lines),line+2))],
                        explanation='Recorded mobile UI callback input; handler binding and propagation are unresolved.')
            finding = dict(title='Recorded mobile input', severity='INFO', analysis_only=True,
                           location=location, evidence=[step], trace=dict(steps=[step],
                           review_note='The imported UI component supplies input to this callback. This partial record establishes neither external reachability nor a vulnerability.',
                           protection_note='Handler binding, validation, storage and sensitive destinations require further review.'))
            records.append(dict(v2_rule_id='mobile-input-inventory',v2_outcome='RECORDED',analysis_only=True,
                                comparison_kind='semantic',context=dict(file_path=str(path)),v2_findings=[finding]))
    return records


def _android_text_records(path, text):
    if 'getText' not in text or 'EditText' not in text:
        return []
    from .source_review import source_views
    _, code = source_views(path, text)
    if not re.search(r'\bimport\s+android\.widget\.EditText\s*;', code) or re.search(r'\bclass\s+EditText\b', code):
        return []
    names = set()
    for declaration in re.finditer(r'\bEditText\s+([^;{}()]+);', code):
        for member in declaration[1].split(','):
            name = re.match(r'\s*([A-Za-z_]\w*)\s*(?:=|$)', member)
            if name:
                names.add(name[1])
    records, lines = [], text.splitlines()
    for name in sorted(names):
        escaped = re.escape(name)
        if not re.search(r'\b'+escaped+r'\s*=\s*(?:\(\s*EditText\s*\)\s*)?(?:\w+\s*\.\s*)?findViewById\s*\(', code):
            continue
        if re.search(r'[(,]\s*(?:final\s+)?\w+\s+'+escaped+r'\s*[,)]', code):
            continue
        for hit in re.finditer(r'\b'+escaped+r'\s*\.\s*getText\s*\(\s*\)', code):
            line = text.count('\n', 0, hit.start())+1
            location = dict(path=str(path),line=line,column=hit.start()-text.rfind('\n',0,hit.start()))
            step = dict(predicate='SOURCE',matched=True,symbol=name+'.getText',input_origin='mobile_text',location=location,
                        snippet=[dict(line=i+1,text=lines[i],highlight=i+1==line) for i in range(max(0,line-2),min(len(lines),line+1))],
                        explanation='An imported Android EditText bound through findViewById supplies UI text. External control, handler reachability and propagation are unresolved.')
            finding = dict(title='Recorded mobile input',severity='INFO',analysis_only=True,location=location,evidence=[step],
                           trace=dict(steps=[step],review_note='Recorded native UI source only; no propagated path or sensitive destination is established.'))
            records.append(dict(v2_rule_id='mobile-input-inventory',v2_outcome='RECORDED',analysis_only=True,comparison_kind='semantic',context=dict(file_path=str(path)),v2_findings=[finding]))
    return records


def _android_scan_records(path, text):
    if 'getContents' not in text or 'ScanContract' not in text:
        return []
    from .source_review import source_views
    from core.mobile_model import block_end
    _, code = source_views(path, text)
    if not re.search(r'\bimport\s+com\.journeyapps\.barcodescanner\.ScanContract\s*;',code) or re.search(r'\bclass\s+ScanContract\b',code):
        return []
    records, lines = [], text.splitlines()
    for callback in re.finditer(r'\bregisterForActivityResult\s*\(\s*new\s+ScanContract\s*\(\s*\)\s*,\s*(\w+)\s*->\s*\{',code):
        end = block_end(code,callback.end()-1)
        if not end:
            continue
        for hit in re.finditer(r'\b'+re.escape(callback[1])+r'\s*\.\s*getContents\s*\(\s*\)',code[callback.end():end-1]):
            offset=callback.end()+hit.start();line=text.count('\n',0,offset)+1
            location=dict(path=str(path),line=line,column=offset-text.rfind('\n',0,offset))
            step=dict(predicate='SOURCE',matched=True,symbol='ScanContract.'+callback[1]+'.getContents',input_origin='mobile_text',input_channel='barcode_scan',location=location,
                      snippet=[dict(line=i+1,text=lines[i],highlight=i+1==line) for i in range(max(0,line-2),min(len(lines),line+1))],
                      explanation='The imported scanner activity-result callback supplies decoded barcode text. Payload validation, replay controls and propagation remain unresolved.')
            finding=dict(title='Recorded mobile scan input',severity='INFO',analysis_only=True,location=location,evidence=[step],
                         trace=dict(steps=[step],review_note='Recorded barcode/QR input source only; no trusted origin, propagated path or sensitive destination is established.'))
            records.append(dict(v2_rule_id='mobile-input-inventory',v2_outcome='RECORDED',analysis_only=True,comparison_kind='semantic',context=dict(file_path=str(path)),v2_findings=[finding]))
    return records
