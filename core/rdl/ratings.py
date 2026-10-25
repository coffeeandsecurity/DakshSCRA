"""Scope-aware review ratings; observation certainty is not exploitability."""
import plistlib
import re
import xml.etree.ElementTree as ET
from pathlib import Path


def rating_context(rule_id, path, text, location=None):
    from core.mobile_model import build_scope, ANDROID
    scope = build_scope(path)
    result = {'build_scope': scope}
    rule = str(rule_id).lower()
    if rule == 'android.sensitive-preference-write':
        result.update(severity='MEDIUM', rating_basis='The matched local preferences write requires review of value protection, extraction prerequisites and backup inclusion. It does not establish remotely exploitable credential theft or a calibrated high-risk rating.')
    if Path(path).suffix in {'.java', '.kt'} and any(word in rule for word in ('stack_trace', 'error_disclosure')):
        line = (location or {}).get('line')
        if line:
            from core.mobile_model import views, enclosing_blocks
            _, code = views(path, text)
            offset = sum(len(row) for row in code.splitlines(keepends=True)[:line-1])
            offset += max(0, int((location or {}).get('column') or 1)-1)
            if any(re.search(r'\bif\s*\(\s*BuildConfig\.DEBUG\s*\)\s*$', code[max(0,start-120):start]) for start in enclosing_blocks(code, offset)):
                result.update(severity='INFO', build_scope='debug_guarded',
                              rating_basis='This operation is inside a BuildConfig.DEBUG branch in source. Verify the generated build constant and logging configuration before claiming release error disclosure.')
    if scope in {'debug', 'test', 'androidTest'} and any(word in rule for word in ('cleartext', 'overlay', 'insecure_permissions')):
        result.update(severity='INFO', rating_basis='This declaration is in a debug/test source set. Release inclusion and affected runtime operations are not established.')
    if Path(path).suffix == '.plist' and any(word in rule for word in ('ats', 'http_exception')):
        try:
            policy = plistlib.loads(text.encode('utf-8')).get('NSAppTransportSecurity', {})
            domains = policy.get('NSExceptionDomains', {})
            global_keys = ('NSAllowsArbitraryLoads', 'NSAllowsArbitraryLoadsInWebContent', 'NSAllowsArbitraryLoadsForMedia')
            if (isinstance(domains, dict) and set(domains) == {'localhost'}
                    and isinstance(domains['localhost'], dict)
                    and domains['localhost'].get('NSExceptionAllowsInsecureHTTPLoads') is True
                    and all(policy.get(key) is None or policy.get(key) is False for key in global_keys)):
                result.update(severity='INFO', transport_scope='localhost',
                              rating_basis='The recorded ATS exception is limited to localhost. It does not disable transport protection for arbitrary remote hosts. Review any local-service trust boundary separately.')
        except (ValueError, TypeError, AttributeError, ET.ParseError):
            pass
    if Path(path).name == 'AndroidManifest.xml' and any(word in rule for word in ('component', 'exported')):
        try:
            root = ET.fromstring(text)
            from .mobile_review import _tags
            nodes = list(root.iter('activity'))
            tags = _tags(text, 'activity')
            line = (location or {}).get('line')
            column = (location or {}).get('column')
            offset = sum(len(row) for row in text.splitlines(keepends=True)[:line-1]) + column-1 if line and column else None
            for node, tag in zip(nodes, tags):
                end = text.find('</activity>', tag.end()) if not tag.group().rstrip().endswith('/>') else tag.end()
                if not line or end < 0 or not (text.count('\n', 0, tag.start())+1 <= line <= text.count('\n', 0, end)+1):
                    continue
                if offset is not None and not tag.start() <= offset <= end:
                    continue
                if offset is None and sum(text.count('\n', 0, other.start())+1 == line for name in ('activity', 'activity-alias', 'service', 'receiver', 'provider') for other in _tags(text, name)) != 1:
                    continue
                filters = node.findall('intent-filter')
                launcher = filters and all(
                    {a.get(ANDROID+'name') for a in f.findall('action')} == {'android.intent.action.MAIN'}
                    and {c.get(ANDROID+'name') for c in f.findall('category')} == {'android.intent.category.LAUNCHER'}
                    and not f.findall('data') for f in filters)
                if launcher:
                    result.update(severity='INFO', exposure_scope='launcher_entry',
                                  rating_basis='A launcher activity is an expected app entry point. Registration alone does not establish authorization bypass, deep-link handling, or a sensitive action reached through intent extras.')
        except (ET.ParseError, TypeError):
            pass
    return result


def apply_rating_context(finding, rule_id, path, text):
    context = rating_context(rule_id, path, text, finding.get('location'))
    if context.get('severity') and str(finding.get('severity', '')).upper() != 'INFO':
        context['unadjusted_severity'] = finding.get('severity')
    finding.update(context)
    return finding
