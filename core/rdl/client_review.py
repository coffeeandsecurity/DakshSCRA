"""Located lexical reviews for reusable JavaScript client patterns."""
import re
from dataclasses import replace

from .executor import Evidence, ExecutionOutcome
from .text import match_location


def review_client(entry, result, path, text, code):
    """Require executable anchors and retain conservative, local evidence."""
    if result.outcome not in {ExecutionOutcome.MATCH, ExecutionOutcome.NO_MATCH}:
        return result
    if not str(path).lower().endswith(('.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs')):
        return replace(result, outcome=ExecutionOutcome.NO_MATCH, evidence=(), witnesses=())
    kind = entry['client_check']
    witnesses = []
    stack, cursor = [], 0
    for hit in re.finditer(entry['pattern'], text):
        # Every pattern begins at an executable identifier. Strings/comments
        # must not supply that anchor, even when the pattern needs literal data.
        anchor = re.match(r'[A-Za-z_$][\w$]*', hit.group())
        if not anchor or code[hit.start():hit.start()+len(anchor[0])] != anchor[0]:
            continue
        if kind == 'image-assets':
            receiver = hit.group(1)
            # Restrict guards to braces enclosing this access, rather than
            # accepting a safe operation in a different callback/function.
            for offset in range(cursor, hit.start()):
                char = code[offset]
                if char == '{':
                    stack.append(offset)
                elif char == '}' and stack:
                    stack.pop()
            cursor = hit.start()
            callback = next((offset for offset in reversed(stack)
                             if re.search(r'=>\s*$|\bfunction\s*\([^)]*\)\s*$', code[max(0, offset-160):offset])), None)
            if callback is None:
                continue
            invocation = (r'\b(?:launchCamera|launchImageLibrary)\s*\(\s*'
                          r'(?:\{[^{}]{0,300}\}|[A-Za-z_$][\w$]*)\s*,\s*'
                          r'(?:\(\s*' + re.escape(receiver) + r'\s*\)|' + re.escape(receiver) + r')\s*=>\s*$')
            if not re.search(invocation, code[max(0, callback-500):callback]):
                continue
            prefix = code[callback+1:hit.start()]
            asset = re.escape(receiver) + r'\s*\.\s*assets'
            # Recognize local rejection and positive enclosing length guards.
            reject = r'if\s*\(\s*!\s*' + asset + r'\s*(?:\?\.|\.)\s*length\s*\)\s*(?:\{\s*)?(?:return|throw)\b'
            positive = r'if\s*\(\s*' + asset + r'\s*(?:\?\.|\.)\s*length\s*(?:>\s*0)?\s*\)\s*$'
            if re.search(reject, prefix) or any(re.search(positive, code[max(callback, offset-180):offset]) for offset in stack if offset > callback):
                continue
        elif kind == 'persist-auth':
            if not re.search(r'\bcombineReducers\s*\(\s*\{[^}]{0,1000}\b(?:authReducer|authentication|auth)\b', code):
                continue
        detail = entry['description'] + ' Located lexical evidence; helper behavior, release inclusion and backend impact are not established.'
        evidence = Evidence('TEXT_MATCHES', True,
                            location=match_location(path, text, hit.start(), hit.end()), explanation=detail)
        witnesses.append((evidence,))
        if len(witnesses) >= 100:
            break
    return replace(result, outcome=ExecutionOutcome.MATCH if witnesses else ExecutionOutcome.NO_MATCH,
                   evidence=tuple(item[0] for item in witnesses), witnesses=tuple(witnesses))
