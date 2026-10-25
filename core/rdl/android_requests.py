"""Bounded Volley request contracts; no backend or runtime verdicts."""
import re

from core.mobile_model import block_end, enclosing_blocks


def credential_http_requests(text, code):
    if not re.search(r'\bimport\s+com\.android\.volley\.toolbox\.StringRequest\s*;', code):
        return []
    if not re.search(r'\bimport\s+com\.android\.volley\.toolbox\.Volley\s*;', code):
        return []
    if re.search(r'\bclass\s+(?:StringRequest|Volley)\b', code):
        return []
    hits = []
    for request in re.finditer(r'\bStringRequest\s+(\w+)\s*=\s*new\s+StringRequest\s*\(', code):
        opening = request.end()-1
        end = block_end(code, opening, '(', ')')
        if not end:
            continue
        commas, depth = [], 0
        for i in range(opening+1, end-1):
            if code[i] in '({[': depth += 1
            elif code[i] in ')}]': depth -= 1
            elif code[i] == ',' and depth == 0: commas.append(i)
        if len(commas) < 2:
            continue
        expression = text[commas[0]+1:commas[1]].strip()
        # Resolve a literal or one uniquely assigned local String plus literals.
        pieces = [part.strip() for part in expression.split('+')]
        resolved = ''
        for piece in pieces:
            literal = re.fullmatch(r'"([^"\\]*)"', piece)
            if literal:
                resolved += literal[1]
                continue
            if not re.fullmatch(r'[A-Za-z_]\w*', piece):
                break
            declarations = list(re.finditer(r'\bString\s+'+re.escape(piece)+r'\s*=\s*"([^"\\]*)"\s*;', text))
            assignments = list(re.finditer(r'\b'+re.escape(piece)+r'\s*=(?!=)', code))
            if len(declarations) != 1 or len(assignments) != 1 or declarations[0].start() >= request.start():
                break
            declared = declarations[0]
            if not code[declared.start():declared.start()+6] == 'String':
                break
            # Method parameters can shadow fields with the same spelling.
            if re.search(r'[(,]\s*(?:final\s+)?String\s+'+re.escape(piece)+r'\s*[,)]', code):
                break
            resolved += declared[1]
        else:
            if not resolved.startswith('http://'):
                continue
            body_start = end
            while body_start < len(code) and code[body_start].isspace(): body_start += 1
            body_end = block_end(code, body_start) if body_start < len(code) and code[body_start] == '{' else None
            if not body_end:
                continue
            body = code[body_start:body_end]
            params = re.search(r'\bgetParams\s*\(\s*\)\s*\{', body)
            if not params:
                continue
            params_start = body_start+params.end()-1
            params_end = block_end(code, params_start)
            scopes = enclosing_blocks(code,request.start())
            scope_end = block_end(code,scopes[-1]) if scopes else len(code)
            queued = re.search(r'\bVolley\s*\.\s*newRequestQueue\s*\([^;]*?\)\s*\.\s*add\s*\(\s*'+re.escape(request[1])+r'\s*\)', code[body_end:scope_end])
            if not queued or not params_end:
                continue
            for field in re.finditer(r'\b(\w+)\s*\.\s*put\s*\(\s*"(password|passwd|access_token|refresh_token|secret)"\s*,\s*([A-Za-z_]\w*)\s*\)', text[params_start:params_end], re.I):
                offset = params_start+field.start()
                if field[3] in {'null','true','false'}:
                    continue
                if not code[offset:offset+len(field[1])] == field[1]:
                    continue
                if not re.search(r'\breturn\s+'+re.escape(field[1])+r'\s*;', code[params_start:params_end]):
                    continue
                hits.append((offset, params_start+field.end(),
                             'The enqueued Volley request returns a '+field[2]+' parameter and its locally resolved URL uses HTTP. Resolve the value origin, selected network policy and release path; TLS protection, backend authorization and actual interception are not established.'))
    return hits
