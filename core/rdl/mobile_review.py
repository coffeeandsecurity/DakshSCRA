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
from core.mobile_model import component_permissions, preference_writes, sensitive_logs, SYSTEM_PERMISSIONS

ANDROID = '{http://schemas.android.com/apk/res/android}'
MAX_WITNESSES = 1000
# Exact platform-restricted contracts; unknown permission names are not controls.
# DUMP can also be explicitly granted for development; it is not ordinary access.
SYSTEM_BINDING_PERMISSIONS = SYSTEM_PERMISSIONS


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
    names = ('activity', 'activity-alias', 'service', 'receiver', 'provider')
    components = {id(node) for node in app if node.tag in names}
    permissions = {node.get(ANDROID+'name'): node.get(ANDROID+'protectionLevel', 'normal')
                   for node in root.findall('permission')}
    if len(permissions) != len(root.findall('permission')):
        return _result(result, path, text, [], 'Duplicate permission declarations need manifest-merge resolution.')
    for name in names:
        # Lexical tags cover the whole document, including package-visibility
        # queries. Associate all tags first, then restrict review to actual
        # application components so queries cannot mask or create findings.
        nodes, tags = list(root.iter(name)), _tags(text, name)
        if len(nodes) != len(tags):
            return _result(result, path, text, [], 'Cannot associate mobile declarations with source locations.')
        for node, tag in zip(nodes, tags):
            if id(node) not in components:
                continue
            if node.get(ANDROID+'enabled') == 'false':
                continue
            exported = node.get(ANDROID+'exported')
            filters = node.findall('intent-filter')
            detail = None
            unresolved = exported is not None and exported not in {'true', 'false'}
            if check == 'manifest-export' and (exported == 'true' or unresolved or (exported is None and filters)):
                permission = node.get(ANDROID+'permission', '' if name == 'activity-alias' else app.get(ANDROID+'permission', ''))
                level = permissions.get(permission, '')
                # Accept exact platform-restricted contracts and local signature
                # declarations; unknown or conflicting definitions stay leads.
                restrictions = component_permissions(node, root, app)
                signature = all(restrictions.values())
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
        def visit(current, components, trail=()):
            if not isinstance(current, dict):
                raise ValueError('expected a dictionary at '+components[0])
            for key, (node, value) in current.items():
                if components[0] not in {'*', key}:
                    continue
                if len(components) > 1:
                    visit(value, components[1:], trail+(key,))
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
                    detail=entry['description']+' Configuration scope: '+' / '.join(trail+(key,))+'.'
                    if trail and trail[0]=='NSAppTransportSecurity':
                        detail+=' A domain-specific exception does not establish a global transport bypass.'
                    hits.append((tag.start(), end, detail))
        visit(values, entry['plist_path'].split('/'))
        return _result(result, path, text, hits)
    except (ET.ParseError, ValueError) as exc:
        return _result(result, path, text, [], 'Cannot resolve Apple configuration: '+str(exc))


def _xml_config(entry, result, path, text):
    """Associate risky attributes with active declarations in the expected document."""
    try:
        root = ET.fromstring(text)
        expected = entry['root_tag']
        root_name = root.tag.rsplit('}', 1)[-1]
        namespace = root.tag[1:].split('}', 1)[0] if root.tag.startswith('{') else ''
        if namespace and not (root_name == 'widget' and namespace == 'http://www.w3.org/ns/widgets'):
            return _result(result, path, text, [], 'Unsupported configuration namespace: '+namespace)
        if root_name not in (expected if isinstance(expected, list) else [expected]):
            return _result(result, path, text, [])
        hits = []
        parents = {child: parent for parent in root.iter() for child in parent}
        for name in entry['xml_tags']:
            nodes = [node for node in root.iter() if node.tag.rsplit('}', 1)[-1] == name]
            tags = list(re.finditer(r'<(?:[A-Za-z_][\w.-]*:)?'+re.escape(name)+r'(?=[\s/>])(?:[^>\"\']|\"[^\"]*\"|\'[^\']*\')*>', text))
            if len(nodes) != len(tags):
                raise ValueError('cannot associate configuration declarations with source locations')
            for node, tag in zip(nodes, tags):
                node_namespace = node.tag[1:].split('}', 1)[0] if node.tag.startswith('{') else ''
                if node_namespace != namespace:
                    continue
                policy = entry['attribute_policy']
                value = node.get('path', '')
                risky = False
                if policy in {'broad-path','backup-root'} and re.search(r'\$\{|\$\(|^@', value):
                    raise ValueError('unresolved path configuration')
                if policy == 'broad-path':
                    risky = name == 'root-path' or value in {'', '.', '/', './', '..', '../'}
                elif policy == 'pin-override':
                    value = node.get('overridePins')
                    if value is not None and value not in {'true', 'false'}:
                        raise ValueError('unresolved overridePins value')
                    risky = value == 'true'
                elif policy == 'weak-permission':
                    value = node.get(ANDROID+'protectionLevel', 'normal')
                    if re.search(r'\$\{|\$\(|^@', value):
                        raise ValueError('unresolved protection level')
                    try:
                        base = int(value, 0) & 0xf
                    except ValueError:
                        base = value.split('|')[0].strip()
                    risky = base in {'normal', 'dangerous', 0, 1}
                elif policy == 'backup-root':
                    risky = value in {'.', '/', './', '', '..', '../'}
                    parent = parents.get(node)
                    if parent is None or parent.tag not in {'cloud-backup','device-transfer','full-backup-content'} or not node.get('domain'):
                        raise ValueError('unresolved backup section or domain')
                    # An exact exclusion in the same domain and backup section overrides this include.
                    if any(exclude.get('domain') == node.get('domain') and exclude.get('path') == value for exclude in parent.findall('exclude')):
                        risky = False
                elif policy == 'wildcard-navigation':
                    risky = node.get('href') in {'*', '*://*/*', 'http://*/*', 'https://*/*', 'data:*'}
                elif policy == 'cordova-preference':
                    preference, value = node.get('name', '').lower(), node.get('value', '')
                    risky = (preference == 'ignoresslerrors' and value.lower() in {'true','yes'}) if 'ssl-bypass' in entry['rule_id'] else preference in {'androidextrafilesystems','iosextrafilesystems'} and bool(re.search(r'(?:^|,)\s*root\s*(?:,|$)', value))
                if risky:
                    hits.append((tag.start(), tag.end(), entry['description'] + ' Resolve the selected configuration and its associated resource; unrelated declarations do not protect this scope.'))
        return _result(result, path, text, hits)
    except (ET.ParseError, ValueError) as exc:
        return _result(result, path, text, [], 'Cannot resolve mobile configuration: '+str(exc))


def _configuration(entry, result, path, text, code):
    if Path(path).suffix == '.json':
        import json
        def unique_pairs(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError('duplicate JSON configuration key '+key)
                value[key] = item
            return value
        try:
            json.loads(text, object_pairs_hook=unique_pairs)
        except (ValueError, TypeError) as exc:
            return _result(result, path, text, [], 'Cannot resolve JSON configuration: '+str(exc))
    elif Path(path).suffix in {'.plist', '.xml'}:
        try:
            ET.fromstring(text)
        except ET.ParseError as exc:
            return _result(result, path, text, [], 'Cannot resolve mobile configuration: '+str(exc))
    hits = []
    for match in re.finditer(entry['pattern'], text):
        # Unquoted configuration identifiers inside source string examples are not active settings.
        if Path(path).suffix in {'.js','.ts'} and not code[match.start():match.start()+1].strip():
            colon = text.find(':', match.start(), match.end())
            if text[match.start()] not in {'"', "'"} or colon < 0 or not code[colon:colon+1].strip():
                continue
        hits.append((match.start(), match.end(), entry['description']+' Resolve generated configuration, object scope and release overrides.'))
    return _result(result, path, text, hits)


def _contextual_operation(entry, result, path, text, code):
    """Bound a candidate to the relevant local widget, catch block or assignment."""
    hits = []
    for match in re.finditer(entry['pattern'], text):
        if not code[match.start():match.start()+1].strip():
            continue
        check = entry['mobile_check']
        if check == 'sensitive-widget':
            # Locate the enclosing TextField constructor using balanced parentheses.
            constructors = list(re.finditer(r'\b(?:TextField|TextFormField)\s*\(', code[:match.start()]))
            if not constructors:
                continue
            start = constructors[-1].end()-1
            depth, end = 1, start+1
            while end < len(code) and depth:
                depth += (code[end] == '(') - (code[end] == ')')
                end += 1
            if depth:
                return _result(result, path, text, [], 'Cannot resolve sensitive widget boundaries')
            if match.start() >= end or not re.search(r'\bobscureText\s*:\s*true\b', code[start:end]):
                continue
        elif check == 'storage-fallback':
            if re.match(r'\s*,\s*(?:null|\"\"|string\.Empty)\s*\)', text[match.end():]):
                continue
            catches = list(re.finditer(r'\bcatch\s*(?:\([^)]*\))?\s*\{', code[:match.start()]))
            if not catches:
                continue
            start = catches[-1].end()-1
            depth, end = 1, start+1
            while end < len(code) and depth:
                depth += (code[end] == '{') - (code[end] == '}')
                end += 1
            if depth or match.start() >= end:
                continue
            tries = list(re.finditer(r'\btry\s*\{', code[:start]))
            if not tries:
                continue
            try_start=tries[-1].end()-1
            depth, try_end=1,try_start+1
            while try_end < start and depth:
                depth += (code[try_end] == '{') - (code[try_end] == '}')
                try_end += 1
            if depth or not re.search(r'\bSecureStorage(?:\.Default)?\s*\.\s*(?:SetAsync|GetAsync)\s*\(', code[try_start:try_end]):
                continue
        elif check == 'security-random':
            line = code[code.rfind('\n',0,match.start())+1:match.start()]
            if not re.search(r'(?i)\b(?:token|secret|password|nonce|iv|salt|key)\w*\s*(?::[^=]+)?=\s*$',line):
                continue
        hits.append((match.start(), match.end(), entry['description']+' The local operation context is recorded; value sensitivity and runtime policy require review.'))
    return _result(result, path, text, hits)


def review_mobile(entry, result, path, text, code, project_root=None):
    """Preserve original offsets; gate checks by real source/configuration kind."""
    if not any(fnmatch.fnmatch(Path(path).name, pattern) for pattern in entry['file_patterns']):
        return _result(result, path, text, [])
    if len(text) > 4*1024*1024:
        return _result(result, path, text, [], 'Mobile input exceeds 4 MiB budget.')
    check = entry['mobile_check']
    if entry['rule_id'] == 'android.sql-raw-query-surface':
        from .mobile_precision import fixed_sql_calls
        text = fixed_sql_calls(path, text)
    if entry['rule_id'] == 'android.persistent-device-identifier':
        from .mobile_precision import identifier_calls
        text = identifier_calls(path, text)
    if check == 'credential-http-request':
        from .android_requests import credential_http_requests
        return _result(result, path, text, credential_http_requests(text, code))
    if check in {'release-signing', 'provider-stream', 'project-privacy', 'project-backup', 'project-logout'}:
        from core.mobile_project import signing_hits, stream_hits, project_for_review
        if check == 'release-signing':
            return _result(result,path,text,list(signing_hits(path,text,code)))
        if check == 'provider-stream':
            return _result(result,path,text,list(stream_hits(text,code)))
        if not project_root:
            return _result(result,path,text,[],'Project root is unavailable for mobile correlation')
        project = project_for_review(project_root)
        if project.issues:
            return _result(result,path,text,[],'; '.join(project.issues[:8]))
        if check == 'project-logout':
            from .session_contracts import logout_contracts
            contracts, unknown = logout_contracts(project, path)
            if unknown and not contracts:
                return _result(result,path,text,[],'; '.join(unknown[:8]))
            hits = []
            for contract in contracts:
                line = contract['source']['line']
                start = sum(len(row) for row in text.splitlines(keepends=True)[:line-1])
                hits.append((start, min(len(text),start+len(text.splitlines()[line-1])),
                             'Local logout clears '+', '.join(contract['cleared_fields'])+' but its reducer spread retains '+', '.join(contract['retained_fields'])+' in '+contract['store']+'. Resolve delegated cleanup and account/session scoping.'))
            return _result(result,path,text,hits)
        if check == 'project-privacy':
            contracts,unknown = project.purpose_hits(path)
            if unknown and not contracts:
                return _result(result,path,text,[],'; '.join(unknown))
            detail = '; '.join(c['key']+' required by '+c['source']['file']+':'+str(c['source']['line']) for c in contracts)
        else:
            contracts=[c for c in project.backup_contracts(path) if c['state']=='potentially_included']
            detail='; '.join(str(c['store'])+' credential-related write at '+c['source']['file']+':'+str(c['source']['line'])+' may enter '+c['section'] for c in contracts)
        return _result(result,path,text,[(0,min(len(text),80),detail+'. Resolve active callers, selected build, platform versions and final configuration.')] if contracts else [])
    if check == 'xml-config':
        return _xml_config(entry, result, path, text)
    if check == 'configuration':
        return _configuration(entry, result, path, text, code)
    if check in {'sensitive-widget', 'storage-fallback', 'security-random'}:
        return _contextual_operation(entry, result, path, text, code)
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
        hits = [(start, end, entry['description'] + ' Sensitive preferences write; resolve backing-store protection, backup policy and cleanup at callers.')
                for start, end, key in preference_writes(text, code)]
        return _result(result, path, text, hits)
    if entry['rule_id'] == 'reactnative.sensitive-console':
        return _result(result, path, text, list(sensitive_logs(text, code)))
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
