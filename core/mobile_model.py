"""Bounded source models shared by mobile checks and review evidence.

Source configuration is not a substitute for a selected built artifact. Unknown
variants, identities and predicates remain explicit rather than becoming guards.
"""
import plistlib
import re
from pathlib import Path

ANDROID = '{http://schemas.android.com/apk/res/android}'
SYSTEM_PERMISSIONS = frozenset('android.permission.' + name for name in (
    'BIND_AUTOFILL_SERVICE', 'BIND_ACCESSIBILITY_SERVICE',
    'BIND_CREDENTIAL_PROVIDER_SERVICE', 'BIND_QUICK_SETTINGS_TILE',
    'BIND_JOB_SERVICE', 'BIND_REMOTEVIEWS', 'DUMP'))


def views(path, text):
    from core.rdl.source_review import source_views
    return source_views(str(path), text)


def build_scope(path):
    parts = Path(str(path).replace('\\', '/')).parts
    for index, part in enumerate(parts[:-1]):
        if part == 'src':
            source_set = parts[index + 1]
            module = Path(*parts[:index])
            gradle = any((module / name).is_file() for name in ('build.gradle', 'build.gradle.kts'))
            native = 'android' in parts[:index] or Path(path).name == 'AndroidManifest.xml' or Path(path).suffix in {'.java', '.kt'}
            if source_set in {'debug', 'release', 'main', 'test', 'androidTest'} and (gradle or native):
                return source_set
            if gradle:
                return 'variant:' + source_set
    if any(p.endswith(('Tests', 'UITests')) for p in parts):
        return 'test'
    return 'unresolved'


def block_end(code, start, opening='{', closing='}'):
    depth = 0
    for index in range(start, len(code)):
        if code[index] == opening:
            depth += 1
        elif code[index] == closing:
            depth -= 1
            if depth == 0:
                return index + 1
    return None


def enclosing_blocks(code, offset):
    stack = []
    for hit in re.finditer(r'[{}]', code[:offset]):
        if hit.group() == '{':
            stack.append(hit.start())
        elif stack:
            stack.pop()
    return stack


def module_namespace(manifest, root):
    """Resolve the nearest module only; never borrow a sibling's namespace."""
    root = Path(root).resolve()
    for folder in (Path(manifest).resolve().parent,) + tuple(Path(manifest).resolve().parents):
        if folder != root and root not in folder.parents:
            break
        candidates = []
        for name in ('build.gradle', 'build.gradle.kts'):
            path = folder / name
            if path.is_file():
                from utils.source_cache import read_source_text
                text = read_source_text(path,encoding='utf-8')
                comments, code = views(path, text)
                for hit in re.finditer(r'\bnamespace\s*(?:=\s*|\(\s*)?["\']([\w.]+)["\']', comments):
                    if code[hit.start():hit.start()+9] == 'namespace':
                        candidates.append(hit.group(1))
        if candidates:
            return candidates[0] if len(set(candidates)) == 1 else ''
        if folder == root:
            break
    return ''


def enabled(component, application=None):
    return component.get(ANDROID+'enabled') != 'false' and (
        application is None or application.get(ANDROID+'enabled') != 'false')


def signature_permission(name, root):
    definitions = [p for p in root.findall('permission') if p.get(ANDROID+'name') == name]
    if len(definitions) > 1:
        return False
    if definitions:
        level = definitions[0].get(ANDROID+'protectionLevel', 'normal')
        if re.search(r'(?:^|\|)\s*signature\s*(?:\||$)', level):
            return True
        try:
            return int(level, 0) & 15 == 2
        except ValueError:
            return False
    return name in SYSTEM_PERMISSIONS


def component_permissions(component, root, application=None):
    """Return restrictions independently for provider read/write operations."""
    inherited = application.get(ANDROID+'permission', '') if application is not None else ''
    if component.tag == 'activity-alias':
        target = next((n for n in application.findall('activity')
                       if n.get(ANDROID+'name') == component.get(ANDROID+'targetActivity')), None) if application is not None else None
        # An unresolved alias contract must not borrow an application-level
        # restriction. Only an explicit target or alias permission is modeled.
        inherited = target.get(ANDROID+'permission', '') if target is not None else ''
    general = component.get(ANDROID+'permission', inherited)
    directions = ('read', 'write') if component.tag == 'provider' else ('invoke',)
    return {direction: signature_permission(component.get(ANDROID+direction+'Permission', general)
            if direction != 'invoke' else general, root) for direction in directions}


def load_plist(path):
    """Strict types and duplicate keys; plistlib alone silently keeps duplicates."""
    import xml.etree.ElementTree as ET
    from utils.source_cache import read_source_bytes
    raw = read_source_bytes(path)
    if raw.startswith(b'bplist'):
        raise ValueError('Binary plist requires selected artifact inspection')
    root = ET.fromstring(raw)
    for node in root.iter('dict'):
        children = list(node)
        keys = [n.text for n in children[::2] if n.tag == 'key']
        if len(children) % 2 or len(keys) * 2 != len(children) or len(set(keys)) != len(keys):
            raise ValueError('Invalid or duplicate plist dictionary key')
    value = plistlib.loads(raw)
    if not isinstance(value, dict):
        raise ValueError('Expected a plist dictionary')
    bool_keys = {'NSAllowsArbitraryLoads','NSAllowsArbitraryLoadsInWebContent','NSAllowsArbitraryLoadsForMedia',
                 'NSExceptionAllowsInsecureHTTPLoads','NSIncludesSubdomains','get-task-allow','UIFileSharingEnabled'}
    def validate(node):
        if isinstance(node,dict):
            for key,item in node.items():
                if key in bool_keys and not isinstance(item,bool):
                    raise ValueError('Expected a Boolean for '+key)
                validate(item)
        elif isinstance(node,list):
            for item in node:
                validate(item)
    validate(value)
    return value


def preference_writes(text, code):
    """Locate typed editor writes, chains and Kotlin receiver scopes."""
    editor = r'[A-Za-z_]\w*'
    known = set(re.findall(r'\b('+editor+r')\s*=\s*(?:'+editor+r'\s*\.\s*)+edit\s*\(', code))
    known.update(re.findall(r'\bSharedPreferences\s*\.\s*Editor\s+('+editor+r')', code))
    known.update(re.findall(r'\b('+editor+r')\s*:\s*(?:SharedPreferences\s*\.\s*)?Editor\b', code))
    def bound_editor(name, offset):
        events=[]
        escaped=re.escape(name)
        declarations=r'\b(?P<type>[A-Z][\w.<>]*)\s+'+escaped+r'\b|\b'+escaped+r'\s*:\s*(?P<ktype>[A-Z][\w.<>]*)\b|\b'+escaped+r'\s*=\s*(?P<assigned>[^;\n]+)'
        for binding in re.finditer(declarations,code[:offset]):
            blocks=enclosing_blocks(code,binding.start())
            start=blocks[-1] if blocks else 0
            stop=block_end(code,start) if blocks else len(code)
            # Parameters belong to the following method body, not their class.
            header=code[start:binding.start()]
            if header.count('(')>header.count(')'):
                body=code.find('{',binding.end(),min(len(code),binding.end()+500))
                semicolon=code.find(';',binding.end(),body if body>=0 else binding.end()+500)
                if body>=0 and semicolon<0:
                    start,stop=body,block_end(code,body)
            if start<=offset<(stop or len(code)):
                kind=binding.group('type') or binding.group('ktype') or ''
                valid=kind.rsplit('.',1)[-1]=='Editor' or bool(binding.group('assigned') and re.match(r'\w+\s*\.\s*edit\s*\(',binding.group('assigned')))
                events.append((start,binding.start(),valid))
        return bool(events and max(events,key=lambda value:(value[0],value[1]))[2])
    scopes = []
    for hit in re.finditer(r'\b\w+\s*\.\s*edit\s*\([^)]*\)\s*\.\s*(?:apply|run)\s*\{', code):
        end = block_end(code, hit.end()-1)
        if end:
            scopes.append((hit.end(), end))
    pattern = r'(?:(?P<chain>\b\w+\s*\.\s*edit\s*\([^)]*\)\s*\.)|(?P<receiver>\b\w+)\s*\.)?\bputString\s*\(\s*["\'](?P<key>password|passwd|token|access_token|refresh_token|secret|credential|api_key)["\']\s*,\s*(?P<value>[^,;)\n]+)'
    hits = []
    for hit in re.finditer(pattern, text, re.I):
        anchor = hit.start()
        if not code[anchor:anchor+1].strip():
            continue
        if not (hit.group('chain') or (hit.group('receiver') in known and bound_editor(hit.group('receiver'),anchor)) or
                (not hit.group('receiver') and any(a <= anchor < b for a, b in scopes))):
            continue
        if hit.group('value').strip() in {'null', '""', "''"}:
            continue
        hits.append((hit.start(), hit.end(), hit.group('key')))
    return hits


def url_guarded(text, code, offset, expression):
    """Recognize a small enforced positive host/protocol contract, not names."""
    match = re.fullmatch(r'\s*(\w+)\s*\.\s*(?:href|toString\s*\(\s*\))\s*', expression)
    if not match:
        return False
    name = re.escape(match.group(1))
    for opening in enclosing_blocks(code, offset):
        prefix = text[max(0, opening-600):opening]
        head = re.search(r'\bif\s*\(([^{}]+)\)\s*$', prefix)
        if not head or '||' in head.group(1) or '!' in head.group(1):
            continue
        condition = head.group(1)
        protocol = re.search(r'\b'+name+r'\.protocol\s*===?\s*["\']https:["\']', condition)
        host = re.search(r'\b'+name+r'\.(?:hostname|host)\s*===?\s*["\']([A-Za-z0-9.-]+)["\']', condition)
        if protocol and host and '.' in host.group(1):
            return True
    return False


def sensitive_logs(text, code, otp_only=False):
    """Bind callback parameters and aliases to log arguments, preserving offsets."""
    spans = []
    sources = r'onCodeFilled|onCodeChanged|watchPosition|getCurrentPosition'
    for callback in re.finditer(r'\b('+sources+r')\s*(?:=\s*\{|\(\s*)\s*\(?\s*(\w+)\s*\)?\s*=>\s*\{', code):
        end = block_end(code, callback.end()-1)
        if end:
            spans.append((callback.end(), end, {callback.group(2)}, callback.group(1)))
    # Explicitly named secret/OTP parameters need no UI-specific spelling.
    for hit in re.finditer(r'\bconsole\s*\.\s*(?:log|debug|info|warn|error)\s*\(', code):
        end = block_end(code, hit.end()-1, '(', ')')
        if not end:
            continue
        args = text[hit.end():end-1]
        active = code[hit.end():end-1]
        names = set(re.findall(r'\b(?:otp|otpCode|verificationCode|oneTimePassword)\b', active, re.I))
        if not otp_only:
            names.update(re.findall(r'\b(?:password|passwd|token|secret|credential)\b', active, re.I))
        for start, stop, source_names, source in spans:
            if not start <= hit.start() < stop or (otp_only and source not in {'onCodeFilled', 'onCodeChanged'}):
                continue
            local = set(source_names)
            for assignment in re.finditer(r'\b(?:const|let|var)\s+(\w+)\s*=\s*([^;\n]+)', code[start:hit.start()]):
                if any(re.search(r'\b'+re.escape(n)+r'\b', assignment.group(2)) for n in local):
                    local.add(assignment.group(1))
            names.update(n for n in local if re.search(r'\b'+re.escape(n)+r'\b', active) or
                         re.search(r'\$\{[^}]*\b'+re.escape(n)+r'\b', args))
        # Interpolation retains its expression even if the lexer masks strings.
        tokens = r'otp|otpCode|verificationCode|oneTimePassword' if otp_only else r'otp|otpCode|verificationCode|oneTimePassword|password|passwd|token|secret|credential'
        if re.search(r'\$\{[^}]*\b(?:'+tokens+r')\b', args, re.I):
            names.add('interpolated sensitive value')
        if names:
            spans_hit = (hit.start(), end, 'Sensitive callback/value reaches console output; verify release logging and active callers.')
            yield spans_hit
