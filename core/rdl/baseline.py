"""Authoring-time conversion to independently executable v2 baseline rules."""
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from .compiler import _compile_v1, _regex_parts
from core.pattern_rules import load_pack


def slug(value):
    return re.sub(r'[^a-z0-9]+', '_', value.lower()).strip('_')


def regex_predicate(pattern, flags, missing=False):
    # Preserve the repeated language while removing ambiguous backtracking.
    # Positive-lookahead capture/backreference emulates an atomic segment on Python 3.8.
    pattern = pattern.replace(r'(.*;\s*)*', r'(?:(?=(?P<rdl_cookie_segment>[^\n]*?;\s*))(?P=rdl_cookie_segment))*')
    pattern = pattern.replace(r'(\s*\w+\s*)*', r'(?:\s*\w[\s\w]*)?')
    letters = ''.join(letter for letter, flag in [('i', re.I), ('m', re.M), ('s', re.S)] if flags & flag)
    return '{} {} {}'.format('TEXT_MISSING' if missing else 'TEXT_MATCHES', json.dumps(pattern), json.dumps(letters))


def translate_expression(expression, warnings=None):
    # Reuse the legacy syntax reader only at authoring time, never in v2 execution.
    from core.rdl_engine import _strip_wrapping_parentheses, _split_top_level
    expression = _strip_wrapping_parentheses(expression)
    for delimiter, operator in [('||', 'OR'), ('&&', 'AND')]:
        parts = _split_top_level(expression, delimiter)
        if len(parts) > 1:
            return '(' + (' ' + operator + ' ').join(translate_expression(part, warnings) for part in parts) + ')'
    if expression.startswith('!'):
        return 'NOT (' + translate_expression(expression[1:].strip(), warnings) + ')'
    match = re.fullmatch(r'(PRESENT|MISSING|EXISTS)\s*:(.+)', expression, re.I | re.S)
    if not match:
        if warnings is not None:
            warnings.append('V1 treats this unrecognized expression operand as false: ' + expression)
        return regex_predicate(r'(?!)', 0)
    return regex_predicate(match[2].strip(), re.I | re.M, match[1].upper() == 'MISSING')


def translate(source, identifier, title, path_rule=False, warnings=None):
    document = _compile_v1(source)
    if not document.valid:
        raise ValueError('Invalid v1 source: ' + str(document.diagnostics))
    lines = ['VERSION 2', 'RULE ' + identifier + ' VERSION 1', 'IN PATH' if path_rule else 'IN FILE']
    for instruction in document.instructions:
        kind, value = instruction.kind, instruction.operand
        if kind in {'when_present', 'when_missing', 'when_current_file_matches', 'unless_current_file_matches'}:
            pattern, flags, _ = _regex_parts(value)
            lines.append('WHEN ' + regex_predicate(pattern, flags, kind in {'when_missing', 'unless_current_file_matches'}))
        elif kind == 'when_expr':
            lines.append('WHEN ' + translate_expression(value, warnings))
        elif kind == 'when_file_name_is':
            lines.append('WHEN FILE_NAME_IS ' + json.dumps(value))
        elif kind == 'when_file_path_matches':
            lines.append('WHEN FILE_PATH_GLOB ' + json.dumps(value))
        elif kind == 'observe_project_has_glob':
            lines.append('WHEN PROJECT_OBSERVATION ' + json.dumps(value.rsplit(' AS ', 1)[0].strip()))
        elif kind not in {'version', 'report_as', 'reason', 'fail_reason', 'trace'}:
            raise ValueError('Untranslatable v1 command: ' + kind)
    # Includes review surfaces and mitigations; never label these confirmed bugs.
    lines += ['REPORT ' + json.dumps(title), 'SEVERITY INFO', 'CONFIDENCE LOW', 'WITH TRACE']
    return '\n'.join(lines) + '\n'


def inventory(root):
    root = Path(root)
    definitions, entries, referenced, identities = {}, [], set(), set()
    for marker in sorted((root / 'rules/scanning/platform').rglob('_pack.yaml')):
        pack = marker.parent
        xml = pack.with_suffix('.xml')
        tree = load_pack(pack)
        for element in tree.iter():
            if element.find('name') is None or (element.find('regex') is None and element.find('rdl_ref') is None):
                continue
            identity = element.get('pattern_id')
            if identity in identities: raise ValueError('Duplicate Pattern Rule identity: ' + identity)
            identities.add(identity)
            title = element.findtext('name').strip()
            reference = (element.findtext('rdl_ref') or '').strip()
            path_rule = xml.name == 'filepaths.xml'
            category = next((item.get('name') for item in tree if element in list(item)), None)
            if reference:
                legacy = root / 'rules/scanning' / reference
                relative = Path(reference).relative_to('logic/rdl/v1')
                scope, stem = relative.parent, relative.stem
                source = element.findtext("pattern_logic") or legacy.read_text()
                referenced.add(legacy.resolve())
            else:
                scope = xml.parent.relative_to(root / 'rules/scanning/platform') / 'core'
                stem = slug(title)
                source = 'VERSION 1\nWHEN PRESENT ' + (element.findtext('regex') or '') + '\n'
            identifier = 'baseline.' + '.'.join(scope.parts) + '.' + stem
            family = slug(category or ('review_surface' if path_rule else 'security'))
            relative_v2 = Path('rules/scanning/logic/rdl/v2') / scope / 'baseline' / family / (stem + '.rdl')
            warnings = []
            if reference:
                text = translate(source, identifier, title, path_rule, warnings)
            else:
                # XML-only scanner regexes are case-sensitive and line-based.
                pattern = element.findtext('regex') or ''
                text = '\n'.join(['VERSION 2', 'RULE ' + identifier + ' VERSION 1', 'IN FILE',
                    'WHEN ' + regex_predicate(pattern, re.M), 'REPORT ' + json.dumps(title),
                    'SEVERITY INFO', 'CONFIDENCE LOW', 'WITH TRACE']) + '\n'
            if str(relative_v2) in definitions and definitions[str(relative_v2)] != text:
                raise ValueError('Conflicting baseline owner: ' + str(relative_v2))
            definitions[str(relative_v2)] = text
            entries.append(dict(translation_notes=warnings, rule_id=identifier, title=title, source_kind='rdl_v1' if reference else 'xml_pattern',
                v1_ref=reference, xml_pack=xml.relative_to(root).as_posix(), v2_rule=relative_v2.as_posix(),
                pattern_file=Path(element.get('pattern_file')).relative_to(root).as_posix(), rule_type='pattern',
                scope=scope.as_posix(), category=category or 'Review surface', path_rule=path_rule,
                source_sha256=hashlib.sha256(source.encode()).hexdigest(),
                pattern=element.findtext('regex') or '',
                description=element.findtext('rule_desc') or '',
                impact=element.findtext('vuln_desc') or '',
                remediation=element.findtext('developer') or '',
                reviewer=element.findtext('reviewer') or ''))
    actual = {p.resolve() for p in (root / 'rules/scanning/logic/rdl/v1').rglob('*.rdl')}
    if actual - referenced:
        raise ValueError('Unmapped legacy definitions: ' + str(actual - referenced))
    return definitions, dict(schema_version=1, coverage_kind='native_v2_rule_predicate_parity',
        limitations=['Rule-predicate parity is not proof of semantic/data-flow parity or runtime exploitability.',
                      'V1 report grouping, confidence ranking, baselines and human suppressions are separate layers.'],
        entries=entries)
