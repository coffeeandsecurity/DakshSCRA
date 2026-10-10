"""Shared check taxonomy for per-run selection and the scan configuration UI."""
import json
import re
from functools import lru_cache
from pathlib import Path

# Ordering matters: specific destinations precede broad input/auth reviews.
CHECK_GROUPS = [
    ('injection', 'Injection flaws', [
        ('sql', 'SQL injection', r'sql|database quer|query construction|preparedstatement|jdbc'),
        ('xss', 'Cross-site scripting (XSS)', r'\bxss\b|cross.site scripting|html injection|html output|application response|innerhtml|document.write'),
        ('command', 'Command injection', r'command|shell|processbuilder|runtime.*exec|popen|system\('),
        ('code', 'Code & template injection', r'code.injection|javascript.injection|eval|dynamic.*execut|template.*inject'),
        ('xml', 'XML & entity injection', r'\bxml\b|\bxxe\b|external.entit|xpath'),
        ('ldap', 'LDAP injection', r'ldap'),
        ('input', 'Untrusted input & validation', r'untrusted|input|validation|sanitiz'),
    ]),
    ('authentication', 'Authentication', [
        ('session', 'Sessions, cookies & tokens', r'session|cookie|jwt|token|logout'),
        ('authentication', 'Login & identity verification', r'authenticat|login|biometric|password.*(?:policy|reset|verif)'),
    ]),
    ('authorization', 'Authorization', [
        ('authorization', 'Access control & permissions', r'authoriz|access.control|permission|privilege|ownership|idor|binder|exported.component|content.provider|component.exposure'),
        ('csrf', 'Cross-site request forgery', r'csrf|cross.site.request.forgery'),
    ]),
    ('configuration', 'Configuration flaws', [
        ('configuration', 'Deployment & platform configuration', r'config|debug|backup|compiler|manifest|entitlement|setting|misconfig|errexit|pipefail'),
        ('dependency', 'Dependencies & supply chain', r'dependen|package|third.party|download|integrity'),
    ]),
    ('data', 'Data protection', [
        ('secrets', 'Secrets & credentials', r'secret|credential|private.key|hardcod|password|api.key'),
        ('crypto', 'Cryptography & randomness', r'crypt|cipher|hash|random|digest|\biv\b|entropy'),
        ('storage', 'Sensitive storage, logging & privacy', r'storage|sensitive|logging|logcat|clipboard|screenshot|recent.task|pasteboard|keychain|sharedpreference'),
    ]),
    ('network', 'Network & communications', [
        ('tls', 'TLS & certificate validation', r'certificate|\btls\b|\bssl\b|trust.*(?:manager|valid)|pinning'),
        ('transport', 'Cleartext transport', r'cleartext|insecure.transport|unencrypted|\bhttp\b|arbitrary.loads'),
        ('ssrf', 'Server-side request forgery', r'ssrf|server.side.request.forgery'),
        ('redirect', 'Redirects, links & URL handling', r'redirect|deep.link|url|uri|scheme|app.link'),
        ('cors', 'Cross-origin & browser policy', r'cors|cross.origin|content.security.policy|clickjack'),
    ]),
    ('files', 'Files & resource handling', [
        ('traversal', 'Path traversal', r'traversal|path.manipulation|untrusted.path'),
        ('upload', 'Uploads & file operations', r'upload|file|directory|temporary|symlink|filesystem'),
        ('serialization', 'Serialization & parsing', r'serializ|unsafe.*(?:load|pars)|objectinputstream'),
        ('memory', 'Memory safety & resource exhaustion', r'buffer|memory|overflow|allocation|null.pointer|resource|dos|denial.of.service|regex'),
    ]),
    ('logic', 'Application logic', [
        ('logic', 'Business logic, concurrency & state', r'logic|race|concurr|state|grade|attendance|transaction|notification'),
        ('webview', 'WebViews & native bridges', r'webview|bridge|javascript.interface'),
        ('review', 'Other code review surfaces', r'.*'),
    ]),
    ('custom', 'Project-specific checks', [('custom', 'Custom RDL packs', r'custom\.')]),
]
CHECK_IDS = frozenset(item[0] for _, _, checks in CHECK_GROUPS for item in checks)
_MATCHERS = [(key, re.compile(pattern, re.I)) for group, _, checks in CHECK_GROUPS
             if group != 'custom' for key, _, pattern in checks if key != 'review']


def check_class(title='', category='', rule_id=''):
    if str(rule_id).startswith('custom.'):
        return 'custom'
    # Titles/IDs are deliberately preferred over broad inventory categories.
    text = ' '.join((str(title), str(rule_id))).replace('_', ' ')
    for key, pattern in _MATCHERS:
        if pattern.search(text):
            return key
    for key, pattern in _MATCHERS:
        if pattern.search(str(category)):
            return key
    return 'review'


@lru_cache(maxsize=1)
def registered_classes():
    root = Path(__file__).resolve().parents[1]
    classes = {}
    for name in ('baseline.json', 'additional.json'):
        for entry in json.loads((root / 'rules/scanning/metadata/rdl' / name).read_text())['entries']:
            value = check_class(entry['title'], entry.get('category', ''), entry['rule_id'])
            for key in (entry['rule_id'], entry.get('v1_ref'), entry['v2_rule']):
                if key:
                    classes[key] = value
    return classes


def check_catalog(root):
    """Read the registered inventory, rather than advertise invented checks."""
    root = Path(root)
    entries = []
    for name in ('baseline.json', 'additional.json'):
        entries.extend(json.loads((root / 'rules/scanning/metadata/rdl' / name).read_text())['entries'])
    shadow = json.loads((root / 'rules/scanning/metadata/rdl/shadow-mappings.json').read_text())['mappings']
    from core.rdl.portable_profiles import project_mappings
    for reference, mapping in dict(shadow, **project_mappings()).items():
        entries.append(dict(title=Path(mapping['v2_rule']).stem.replace('_', ' ').title(),
                            rule_id=reference, v2_rule=mapping['v2_rule'], scope=mapping.get('language', ''),
                            source_kind='semantic'))
    from core.analysis.report import VULNERABILITY_RULES, MITIGATION_RULES
    for kind, inventory in [('analyzer', VULNERABILITY_RULES), ('mitigation', MITIGATION_RULES)]:
        for platform, rules in inventory.items():
            for rule in rules:
                entries.append(dict(title=rule['title'], rule_id=rule['kind'],
                                    v2_rule=kind + '/' + platform + '/' + rule['kind'],
                                    scope=platform + ' / ' + kind, source_kind=kind))
    buckets = {key: {} for key in CHECK_IDS}
    for entry in entries:
        key = registered_classes().get(entry.get('rule_id')) or check_class(entry.get('title'), entry.get('category'), entry.get('rule_id'))
        identity = entry['v2_rule']
        buckets[key][identity] = dict(title=entry['title'], scope=entry.get('scope', ''),
                                     kind=entry.get('source_kind', ''))
    return {'groups': [dict(id=group, label=label, checks=[
        dict(id=key, label=name, count=len(buckets[key]),
             rules=sorted(buckets[key].values(), key=lambda item: (item['title'], item['scope'])))
        for key, name, _ in checks]) for group, label, checks in CHECK_GROUPS],
        'default': 'all', 'scope': 'Available source/RDL and vulnerability checks; applicable platforms and engines run selected checks. Flow traces remain available for context.'}
