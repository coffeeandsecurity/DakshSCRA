"""Bounded, declaration-local mobile review refinements for supplemental v2 rules.

Capabilities and suspicious operations are review leads, never malware verdicts.
Unresolved build variants, runtime guards and binary behavior need manual review.
"""
import fnmatch
import re
import xml.etree.ElementTree as ET
from dataclasses import replace
from pathlib import Path

from .executor import Evidence, ExecutionOutcome
from .text import match_location

ANDROID = '{http://schemas.android.com/apk/res/android}'
MAX_WITNESSES = 1000
# Exact system-only binding contracts; unknown BIND_* names are not controls.
SYSTEM_BINDING_PERMISSIONS = frozenset('android.permission.' + name for name in (
    'BIND_AUTOFILL_SERVICE', 'BIND_ACCESSIBILITY_SERVICE',
    'BIND_CREDENTIAL_PROVIDER_SERVICE', 'BIND_QUICK_SETTINGS_TILE',
))


def _result(result, path, text, hits, error=None):
    if error:
        return replace(result, outcome=ExecutionOutcome.INDETERMINATE,
                       evidence=(), witnesses=(), errors=(error,))
    if len(hits) > MAX_WITNESSES:
        return _result(result, path, text, [], 'Mobile evidence budget exceeded.')
    witnesses = tuple((Evidence('TEXT_MATCHES', True,
                      location=match_location(path, text, start, end), explanation=detail),)
                      for start, end, detail in hits)
    return replace(result, outcome=ExecutionOutcome.MATCH if hits else ExecutionOutcome.NO_MATCH,
                   evidence=tuple(e for group in witnesses for e in group), witnesses=witnesses,
                   errors=())


def _tags(text, name):
    # XML parsers discard comments even when the source lexer cannot identify
    # a plist/entitlements dialect. Keep lexical tag association consistent with
    # the parsed tree without changing original line/character offsets.
    text = re.sub(r'<!--.*?-->', lambda match: ''.join(
        '\n' if char == '\n' else ' ' for char in match.group()), text, flags=re.S)
    return list(re.finditer(r'<'+re.escape(name)+r'(?=[\s/>])(?:[^>"\']|"[^"]*"|\'[^\']*\')*>', text))


def _manifest(entry, result, path, text):
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        return _result(result, path, text, [], 'Cannot resolve Android manifest: '+str(exc))
    if root.tag != 'manifest':
        return _result(result, path, text, [])
    app = root.find('application')
    check = entry['mobile_check']
    hits = []
    if check == 'manifest-permission':
        for name in ('uses-permission', 'uses-permission-sdk-23'):
            nodes, tags = list(root.iter(name)), _tags(text, name)
            if len(nodes) != len(tags):
                return _result(result, path, text, [], 'Cannot associate permission declarations with source locations.')
            for node, tag in zip(nodes, tags):
                if node.get(ANDROID+'name') in entry['permissions']:
                    hits.append((tag.start(), tag.end(), entry['description']))
        return _result(result, path, text, hits)
    if app is None or app.get(ANDROID+'enabled') == 'false':
        return _result(result, path, text, [])
    # Use the same comment-free view for parsing and offsets. A declaration in
    # an XML comment must not be paired with an active component.
    names = ('activity', 'activity-alias', 'service', 'receiver')
    permissions = {node.get(ANDROID+'name'): node.get(ANDROID+'protectionLevel', 'normal')
                   for node in root.findall('permission')}
    if len(permissions) != len(root.findall('permission')):
        return _result(result, path, text, [], 'Duplicate permission declarations need manifest-merge resolution.')
    for name in names:
        nodes, tags = list(app.iter(name)), _tags(text, name)
        if len(nodes) != len(tags):
            return _result(result, path, text, [], 'Cannot associate mobile declarations with source locations.')
        for node, tag in zip(nodes, tags):
            if node.get(ANDROID+'enabled') == 'false':
                continue
            exported = node.get(ANDROID+'exported')
            filters = node.findall('intent-filter')
            detail = None
            unresolved = exported is not None and exported not in {'true', 'false'}
            if check == 'manifest-export' and (exported == 'true' or unresolved or (exported is None and filters)):
                permission = node.get(ANDROID+'permission', '' if name == 'activity-alias' else app.get(ANDROID+'permission', ''))
                level = permissions.get(permission, '')
                # Accept exact system binding contracts and local signature
                # declarations; unknown or conflicting definitions stay leads.
                signature = (permission in SYSTEM_BINDING_PERMISSIONS and permission not in permissions) or bool(re.search(r'(?:^|\|)\s*signature\s*(?:\||$)', level))
                if not signature:
                    detail = '{} {}: exported={}, permission={!r}; signature restriction is not locally established. Resolve merged manifests, SDK defaults and runtime authorization.'.format(name, node.get(ANDROID+'name', '(unnamed)'), exported or 'implicit/SDK-dependent', permission)
            if check == 'manifest-deeplink' and exported != 'false':
                for intent_filter in filters:
                    browsable = any(c.get(ANDROID+'name') == 'android.intent.category.BROWSABLE'
                                    for c in intent_filter.findall('category'))
                    if browsable and intent_filter.findall('data'):
                        detail = 'Browsable deep-link entry point: {}. Verify scheme, host, path, verification state and authorization before sensitive actions; registration alone is not a vulnerability.'.format(node.get(ANDROID+'name', '(unnamed)'))
            if detail:
                hits.append((tag.start(), tag.end(), detail))
    return _result(result, path, text, hits)


def review_network_config(entry, result, path, text):
    """Resolve declaration scope and inheritance; build selection stays explicit."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        return _result(result, path, text, [], 'Cannot resolve network security configuration: '+str(exc))
    if root.tag != 'network-security-config':
        return _result(result, path, text, [])
    nodes = list(root.iter())
    locations = {}
    for name in ('base-config', 'domain-config', 'debug-overrides', 'certificates'):
        matching = [node for node in nodes if node.tag == name]
        tags = _tags(text, name)
        if len(matching) != len(tags):
            return _result(result, path, text, [], 'Cannot associate network declarations with source locations.')
        locations.update({id(node): tag for node, tag in zip(matching, tags)})
    if len(root.findall('base-config')) > 1 or len(root.findall('debug-overrides')) > 1:
        return _result(result, path, text, [], 'Duplicate network configuration needs resource resolution.')
    hits = []
    anchors_check = entry['rule_id'] == 'android.user-trust-anchors'
    base = root.find('base-config')
    def settings(node, parent):
        clear, anchors = parent
        if node is None:
            return parent
        declared = node.get('cleartextTrafficPermitted')
        if declared is not None:
            if declared not in {'true', 'false'}:
                raise ValueError('Unresolved cleartextTrafficPermitted value')
            clear = declared == 'true'
        trust = node.find('trust-anchors')
        if trust is not None:
            anchors = tuple(cert.get('src', '') for cert in trust.findall('certificates'))
        return clear, anchors
    def add(node, detail):
        tag = locations[id(node)]
        hits.append((tag.start(), tag.end(), detail))
    def describe(node, scope, parent, inherited=False, depth=0):
        if depth > 64:
            raise ValueError('Network domain nesting exceeds review budget')
        effective = settings(node, parent)
        clear, anchors = effective
        risky = 'user' in anchors if anchors_check else clear is True
        if risky:
            property_text = 'user-installed certificate trust' if anchors_check else 'cleartext traffic permission'
            detail = scope+': '+property_text+' is enabled'+(' through inheritance' if inherited else '')+'. '
            children = node.findall('domain-config')
            if children:
                detail += 'Nested domain configurations may override this scope; apply the most specific matching domain. '
            detail += 'Resolve the selected build resource and manifest reference; configuration alone does not prove sensitive traffic or interception.'
            add(node, detail)
        for child in node.findall('domain-config'):
            domains = [((domain.text or '').strip()+(' (including subdomains)' if domain.get('includeSubdomains') == 'true' else '')) for domain in child.findall('domain')]
            if not domains or any(not (domain.text or '').strip() for domain in child.findall('domain')):
                raise ValueError('Domain configuration lacks a resolvable domain')
            describe(child, 'Domains '+', '.join(domains), effective,
                     child.find('trust-anchors') is None if anchors_check else child.get('cleartextTrafficPermitted') is None, depth+1)
    try:
        defaults = settings(base, (None, ()))
        if base is not None:
            describe(base, 'Base policy for destinations without a more specific domain policy', (None, ()))
        for domain in root.findall('domain-config'):
            for child in (domain,):
                domains = [(d.text or '').strip()+(' (including subdomains)' if d.get('includeSubdomains') == 'true' else '') for d in child.findall('domain')]
                if not domains or any(not (d.text or '').strip() for d in child.findall('domain')):
                    raise ValueError('Domain configuration lacks a resolvable domain')
                describe(child, 'Domains '+', '.join(domains), defaults,
                         child.find('trust-anchors') is None if anchors_check else child.get('cleartextTrafficPermitted') is None)
        debug = root.find('debug-overrides')
        if anchors_check and debug is not None and 'user' in settings(debug, (None, ()))[1]:
            add(debug, 'Debug-only additional user-installed trust anchors: active only when android:debuggable is true; verify merged build configuration. This is not evidence of release trust bypass.')
    except ValueError as exc:
        return _result(result, path, text, [], str(exc))
    return _result(result, path, text, hits)


def _device_admin(entry, result, path, text, code):
    hits, unresolved = [], False
    manager_type = r'(?:android\.app\.admin\.)?DevicePolicyManager'
    aliases = re.findall(r'\bimport\s+android\.app\.admin\.DevicePolicyManager\s+as\s+(\w+)', code)
    if aliases:
        manager_type += '|'+'|'.join(map(re.escape, aliases))
    typed = {}
    for match in re.finditer(r'\b(\w+)\s*:\s*([\w.]+)', text):
        if code[match.start():match.start()+1].strip():
            typed.setdefault(match.group(1), set()).add(match.group(2))
    for match in re.finditer(r'\b('+manager_type+r')\s+(\w+)\b', code):
        typed.setdefault(match.group(2), set()).add(match.group(1))
    for match in re.finditer(r'\b(?:val|var)\s+(\w+)\s*=\s*[^\n;]{0,240}\bgetSystemService\s*\([^\n;]{0,100}\bDevicePolicyManager\s*::\s*class', text):
        if code[match.start():match.start()+1].strip():
            typed.setdefault(match.group(1), set()).add('DevicePolicyManager')
    for declaration in re.finditer(r'\b(?:val|var)\s+(\w+)\s*=\s*([^\n;]+)', code):
        if 'getSystemService' not in declaration.group(2) or 'DevicePolicyManager' not in declaration.group(2):
            typed.setdefault(declaration.group(1), set()).add(None)
    for match in re.finditer(entry['pattern'], text):
        if not code[match.start():match.start()+1].strip():
            continue
        name = re.match(r'\w+', match.group()).group()
        prefix = code[max(0, match.start()-200):match.start()]
        # Function declarations are not executed administrative operations.
        if re.search(r'\bfun\s+(?:[\w.?<>]+\s*\.\s*)?$', prefix) or re.search(r'\b(?:void|boolean|Boolean|int|Unit)\s+$', prefix):
            continue
        receiver = re.search(r'(\w+)\s*\.\s*$', prefix)
        if receiver:
            values = typed.get(receiver.group(1), set())
            value = next(iter(values)) if len(values) == 1 else None
            if value:
                if not re.fullmatch(manager_type, value):
                    # Account reset APIs often share this method name, but the
                    # Android method takes exactly (password, flags). Otherwise
                    # a foreign/wrapper receiver stays unresolved, not safe.
                    depth, end, commas = 1, match.end(), 0
                    brackets = braces = 0
                    while end < len(code) and depth:
                        char = code[end]
                        if char == '(':
                            depth += 1
                        elif char == ')':
                            depth -= 1
                        elif char == '[':
                            brackets += 1
                        elif char == ']':
                            brackets -= 1
                        elif char == '{':
                            braces += 1
                        elif char == '}':
                            braces -= 1
                        elif char == ',' and depth == 1 and not brackets and not braces:
                            commas += 1
                        end += 1
                    args = code[match.end():end-1].strip()
                    trailing = text[match.end():end-1].rstrip().endswith(',')
                    arity = commas + 1 - int(trailing) if args else 0
                    if name == 'resetPassword' and not depth and '<' not in args and '>' not in args and arity != 2:
                        continue
                    unresolved = True
                    continue
            else:
                unresolved = True
                continue
        elif name == 'resetPassword' and re.match(r'\s*\)', code[match.end():]):
            # The Android resetPassword API requires password and flags.
            continue
        else:
            unresolved = True
            continue
        hits.append((match.start(), match.end(), entry['description']))
    if unresolved and not hits:
        return _result(result, path, text, [], 'Administrative method name found but receiver type is unresolved; no device-control verdict is established.')
    out = _result(result, path, text, hits)
    if unresolved:
        out = replace(out, errors=('Additional administrative method receiver types remain unresolved.',))
    return out


def gradle_variant(code, text, offset):
    """Identify explicit build-type containers without relying on whole-file flags."""
    stack = []
    for match in re.finditer(r'[{}]', code[:offset]):
        if match.group() == '}':
            if stack:
                stack.pop()
            continue
        prefix = text[max(0, match.start()-180):match.start()]
        direct = re.search(r'\b(debug|release)\s*$', prefix)
        named = re.search(r'\b(?:create|getByName|named)\s*\(\s*["\']([\w.-]+)["\']\s*\)\s*$', prefix)
        variant = (direct or named).group(1) if direct or named else None
        if re.search(r'\bbuildTypes\s*$', prefix):
            variant = '@buildTypes'
        if variant == 'debug' and '@buildTypes' not in stack and not re.search(r'\bbuildTypes\s*\.\s*(?:create|getByName|named)', prefix):
            variant = None
        stack.append(variant)
    return next((name for name in reversed(stack) if name and name != '@buildTypes'), None)


def review_gradle(entry, result, path, text, code):
    hits = []
    for match in re.finditer(entry['pattern'], text):
        if not code[match.start():match.start()+1].strip():
            continue
        variant = gradle_variant(code, text, match.start())
        if variant == 'debug':
            continue
        property_text = 'Debugging is enabled in ' if entry['rule_id'].endswith('debuggable_build_enabled') else 'Code shrinking is disabled in '
        detail = property_text+('the '+variant+' build type' if variant else 'an unresolved build scope')+'. Verify the final application release configuration; library and debug settings do not establish missing application hardening.'
        hits.append((match.start(), match.end(), detail))
    return _result(result, path, text, hits)


def _plist(entry, result, path, text):
    try:
        root = ET.fromstring(text)
        # Do not silently accept duplicate keys (plistlib would keep the last).
        def decode(node, depth=0):
            if depth > 64:
                raise ValueError('plist nesting exceeds review budget')
            if node.tag == 'dict':
                children, values = list(node), {}
                if len(children) % 2:
                    raise ValueError('unpaired dictionary key')
                for index in range(0, len(children), 2):
                    key = children[index]
                    if key.tag != 'key' or key.text in values:
                        raise ValueError('invalid or duplicate dictionary key')
                    values[key.text] = (key, decode(children[index+1], depth+1))
                return values
            if node.tag == 'array':
                return [decode(child, depth+1) for child in node]
            if node.tag in {'true', 'false'}:
                return node.tag == 'true'
            if node.tag == 'integer':
                return int(node.text or '')
            if node.tag == 'string':
                return node.text or ''
            return None
        if root.tag != 'plist' or len(root) != 1 or root[0].tag != 'dict':
            raise ValueError('expected a plist dictionary')
        values = decode(root[0])
        tags = _tags(text, 'key')
        keys = list(root.iter('key'))
        if len(tags) != len(keys):
            raise ValueError('cannot associate plist keys with source locations')
        locations = {id(key): tag for key, tag in zip(keys, tags)}
        hits = []
        def visit(current, components):
            if not isinstance(current, dict):
                raise ValueError('expected a dictionary at '+components[0])
            for key, (node, value) in current.items():
                if components[0] not in {'*', key}:
                    continue
                if len(components) > 1:
                    visit(value, components[1:])
                    continue
                predicate = entry.get('plist_value', 'true')
                risky = (value is True if predicate == 'true' else
                         isinstance(value, str) and value in entry.get('plist_values', []) if predicate == 'one-of' else
                         isinstance(value, list) and bool(value) if predicate == 'nonempty-array' else False)
                # Wrong types are incomplete configuration evidence, not safety.
                if predicate == 'true' and not isinstance(value, bool):
                    raise ValueError('expected a Boolean for '+key)
                if predicate == 'one-of' and not isinstance(value, str):
                    raise ValueError('expected a string for '+key)
                if predicate == 'one-of' and value not in {'TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'}:
                    raise ValueError('unrecognized TLS version for '+key)
                if predicate == 'nonempty-array' and not isinstance(value, list):
                    raise ValueError('expected an array for '+key)
                if risky:
                    tag = locations[id(node)]
                    # Include the value in the original evidence excerpt.
                    key_end = text.find('</key>', tag.end())+len('</key>')
                    tail = re.match(r'\s*<[^>]+>(?:[^<]*</[^>]+>)?', text[key_end:])
                    end = key_end + (tail.end() if tail else 0)
                    hits.append((tag.start(), end, entry['description']))
        visit(values, entry['plist_path'].split('/'))
        return _result(result, path, text, hits)
    except (ET.ParseError, ValueError) as exc:
        return _result(result, path, text, [], 'Cannot resolve Apple configuration: '+str(exc))


def review_mobile(entry, result, path, text, code):
    """Preserve original offsets; gate checks by real source/configuration kind."""
    if not any(fnmatch.fnmatch(Path(path).name, pattern) for pattern in entry['file_patterns']):
        return _result(result, path, text, [])
    if len(text) > 4*1024*1024:
        return _result(result, path, text, [], 'Mobile input exceeds 4 MiB budget.')
    check = entry['mobile_check']
    if check == 'network-config':
        return review_network_config(entry, result, path, text)
    if check == 'device-admin':
        return _device_admin(entry, result, path, text, code)
    if check == 'gradle-minification':
        return review_gradle(entry, result, path, text, code)
    if check.startswith('manifest-'):
        return _manifest(entry, result, path, text)
    if check == 'plist':
        return _plist(entry, result, path, text)
    if check == 'preference-secret':
        # A literal secret key is not itself a secret. Require a value write
        # through a preferences editor; unrelated encrypted stores are not
        # a file-wide exemption for another editor's write.
        editors = set(re.findall(r'\b([A-Za-z_]\w*)\s*=\s*[A-Za-z_]\w*\s*\.\s*edit\s*\(', code))
        hits = []
        for match in re.finditer(entry['pattern'], text):
            if not code[match.start():match.start()+1].strip():
                continue
            receiver = match.group('receiver')
            if receiver not in editors:
                continue
            value = match.group('value').strip()
            if value in {'null', '""', "''"}:
                continue
            hits.append((match.start(), match.end(), entry['description'] +
                ' Preferences editor: '+receiver+'. Resolve value protection and the actual backing store; a key name alone does not establish plaintext.'))
        return _result(result, path, text, hits)
    hits = []
    for match in re.finditer(entry['pattern'], text):
        # API names inside comments and string literals are not executable calls.
        # Literal arguments remain available to patterns (e.g. "/system/bin/su").
        if check == 'operation' and not code[match.start():match.start()+1].strip():
            continue
        if entry['rule_id'] == 'android.content-provider-query-surface':
            depth, end = 1, match.end()
            while end < len(code) and depth:
                depth += (code[end] == '(') - (code[end] == ')')
                end += 1
            tail = code[end:]
            if not depth and (re.match(r'\s*(?::[^={}\n]{1,120})?\s*=\s*null(?=\s*(?:\n|$|[;}]))', tail) or re.match(r'\s*\{\s*return\s+null\s*;\s*\}', tail)):
                continue
        hits.append((match.start(), match.end(), entry['description']))
        if len(hits) > MAX_WITNESSES:
            break
    return _result(result, path, text, hits)
