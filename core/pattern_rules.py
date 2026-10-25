"""Single-file Pattern Rule authoring and compatibility with scanner records."""
import re
from functools import lru_cache
from pathlib import Path
import xml.etree.ElementTree as ET

import yaml

FORMAT = 'daksh-pattern-rule/v1'
PACK_FORMAT = 'daksh-pattern-pack/v1'
FIELDS = {'format', 'id', 'title', 'category', 'order', 'detection', 'reporting', 'scan_config'}
DETECTION_FIELDS = {'pattern', 'conditions'}
REPORT_FIELDS = {'type', 'reason', 'fail_reason', 'trace', 'summary', 'description', 'impact', 'remediation', 'reviewer',
                 'recommendations', 'review_steps'}
SCAN_FIELDS = {'match_mode', 'context_type', 'context_lines_before', 'context_lines_after', 'context_pattern',
               'context_depth', 'aggregate', 'report_format', 'highlight_enabled', 'highlight_target',
               'highlight_groups', 'highlight_pattern', 'highlight_color', 'marks'}


class _RuleLoader(getattr(yaml, 'CSafeLoader', yaml.SafeLoader)):
    def construct_mapping(self, node, deep=False):
        keys = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in keys
                keys.add(key)
            except TypeError:
                raise ValueError(f'line {key_node.start_mark.line + 1}: mapping keys must be scalar')
            if duplicate:
                raise ValueError(f'line {key_node.start_mark.line + 1}: duplicate field {key}')
        return super().construct_mapping(node, deep=deep)


def resolve_pack(path):
    path = Path(path)
    unified = path.with_suffix('.rules') if path.suffix == '.xml' else path
    return unified if unified.is_dir() else path


def _mapping(value, fields, path, field):
    if not isinstance(value, dict):
        raise ValueError(f'{path}: {field} must be a mapping')
    unknown = set(value) - fields
    if unknown:
        raise ValueError(f'{path}: unknown {field} fields: {sorted(unknown)}')
    return value


def logic_source(rule):
    detection, reporting = rule['detection'], rule.get('reporting', {})
    conditions = detection.get('conditions', [])
    lines = ['VERSION 1']
    for condition in conditions:
        value = condition.replace('${pattern}', detection.get('pattern', ''))
        lines.append(value)
    for field, command in [('type', 'REPORT AS'), ('reason', 'REASON'), ('fail_reason', 'FAIL_REASON')]:
        if reporting.get(field):
            lines.append(command + ' ' + reporting[field])
    lines.extend('TRACE ' + item for item in reporting.get('trace', []))
    return '\n'.join(lines) + '\n' if conditions else ''


def load_rule(path, *, validate_logic=True):
    path = Path(path)
    stamp = path.stat()
    return _load_rule_cached(str(path), (stamp.st_mtime_ns, stamp.st_size), validate_logic)


@lru_cache(maxsize=4096)
def _load_rule_cached(path, stamp, validate_logic):
    path = Path(path)
    try:
        if path.stat().st_size > 256 * 1024:
            raise ValueError('Pattern Rule exceeds 256 KiB')
        rule = yaml.load(path.read_text(encoding='utf-8'), Loader=_RuleLoader)
    except (yaml.YAMLError, ValueError) as exc:
        raise ValueError(f'{path}: invalid YAML: {exc}') from exc
    _mapping(rule, FIELDS, path, 'rule')
    if rule.get('format') != FORMAT:
        raise ValueError(f'{path}: format must be {FORMAT}')
    for key in ('id', 'title'):
        if not isinstance(rule.get(key), str) or not rule[key].strip():
            raise ValueError(f'{path}: {key} must be a non-empty string')
    if not re.fullmatch(r'[a-z0-9_]+(?:\.[a-z0-9_]+)+', rule['id']):
        raise ValueError(f'{path}: id must be a dotted lowercase identifier')
    detection = _mapping(rule.get('detection'), DETECTION_FIELDS, path, 'detection')
    if not detection.get('pattern') and not detection.get('conditions'):
        raise ValueError(f'{path}: detection needs a pattern or conditions')
    for field in ('pattern',):
        if field in detection:
            if not isinstance(detection[field], str):
                raise ValueError(f'{path}: detection.{field} must be a string')
            try:
                re.compile(detection[field])
            except re.error as exc:
                raise ValueError(f'{path}: detection.{field}: {exc}') from exc
    conditions = detection.get('conditions', [])
    if not isinstance(conditions, list) or not all(isinstance(c, str) and c.startswith(('WHEN ', 'UNLESS ', 'OBSERVE ')) for c in conditions):
        raise ValueError(f'{path}: detection.conditions must contain WHEN, UNLESS or OBSERVE conditions')
    reporting = _mapping(rule.get('reporting', {}), REPORT_FIELDS, path, 'reporting')
    for field, value in reporting.items():
        if field in {'trace', 'recommendations', 'review_steps'}:
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                raise ValueError(f'{path}: reporting.{field} must be a list of strings')
            if field != 'trace' and any(not v.strip() for v in value):
                raise ValueError(f'{path}: reporting.{field} must contain non-empty steps')
        elif not isinstance(value, str):
            raise ValueError(f'{path}: reporting.{field} must be a string')
    if 'order' in rule and (not isinstance(rule['order'], int) or isinstance(rule['order'], bool)):
        raise ValueError(f'{path}: order must be an integer')
    if 'category' in rule and not isinstance(rule['category'], str):
        raise ValueError(f'{path}: category must be a string')
    config = _mapping(rule.get('scan_config', {}), SCAN_FIELDS, path, 'scan_config')
    for field, value in config.items():
        if field == 'marks':
            if not isinstance(value, list) or not all(isinstance(m, dict) and set(m) <= {'color', 'spec'} and isinstance(m.get('spec'), str) and isinstance(m.get('color', 'red'), str) for m in value):
                raise ValueError(f'{path}: scan_config.marks must contain color/spec mappings')
        elif field in {'context_lines_before', 'context_lines_after', 'context_depth'}:
            try:
                if int(value) < 0:
                    raise ValueError()
            except (ValueError, TypeError):
                raise ValueError(f'{path}: scan_config.{field} must be a non-negative integer')
        elif not isinstance(value, (str, int, bool)):
            raise ValueError(f'{path}: scan_config.{field} must be a scalar')
    source = logic_source(rule)
    if source and validate_logic:
        from core.rdl.compiler import compile_rdl
        document = compile_rdl(source, str(path))
        if not document.valid:
            raise ValueError(f'{path}: invalid detection conditions: ' + '; '.join(d.message for d in document.diagnostics if d.severity.value == 'error'))
    return rule


def catalog_entries(root):
    """Read check metadata without translating or compiling execution baselines."""
    from core.rdl.baseline import slug
    root = Path(root)
    entries, identities = [], set()
    for marker in sorted((root / 'rules/scanning/platform').rglob('_pack.yaml')):
        for filename in sorted(marker.parent.glob('*.yaml')):
            if filename.name == '_pack.yaml':
                continue
            rule = load_rule(filename, validate_logic=False)
            if rule['id'] in identities:
                raise ValueError('Duplicate Pattern Rule identity: ' + rule['id'])
            identities.add(rule['id'])
            ref = reference(rule) if rule['detection'].get('conditions') else ''
            if ref:
                relative = Path(ref).relative_to('logic/rdl/v1')
                scope, stem = relative.parent, relative.stem
            else:
                scope = marker.parent.parent.relative_to(root / 'rules/scanning/platform') / 'core'
                stem = slug(rule['title'])
            path_rule = marker.parent.name == 'filepaths.rules'
            family = slug(rule.get('category') or ('review_surface' if path_rule else 'security'))
            definition = Path('rules/scanning/logic/rdl/v2') / scope / 'baseline' / family / (stem + '.rdl')
            entries.append(dict(rule_id='baseline.' + '.'.join(scope.parts) + '.' + stem,
                                title=rule['title'], category=rule.get('category', 'Review surface'),
                                v1_ref=ref, v2_rule=definition.as_posix(), scope=scope.as_posix(),
                                source_kind='rdl_v1' if ref else 'xml_pattern'))
    return entries


def reference(rule):
    parts = rule['id'].split('.')
    return 'logic/rdl/v1/' + '/'.join(parts[:-1]) + '/' + parts[-1] + '.rdl'


def _guidance(reporting, field, steps_field, heading):
    """Carry original guidance and actionable steps through existing report formats."""
    parts = [reporting[field]] if reporting.get(field) else []
    steps = reporting.get(steps_field, [])
    if steps:
        parts.append(heading + '\n' + '\n'.join(f'{index}. {step}' for index, step in enumerate(steps, 1)))
    return '\n\n'.join(parts)


def rule_element(rule):
    element = ET.Element('rule')
    reporting, detection = rule.get('reporting', {}), rule['detection']
    from core.issue_titles import issue_title
    values = dict(name=issue_title(rule['title']), regex=detection.get('pattern', ''),
                  rdl_ref=reference(rule) if detection.get('conditions') else '',
                  pattern_logic=logic_source(rule), rule_desc=reporting.get('description', ''),
                  description=reporting.get('summary', ''),
                  vuln_desc=reporting.get('impact', ''),
                  developer=_guidance(reporting, 'remediation', 'recommendations', 'Recommended actions:'),
                  reviewer=_guidance(reporting, 'reviewer', 'review_steps', 'Review steps:'))
    for key, value in values.items():
        if value:
            ET.SubElement(element, key).text = value
    if rule.get('scan_config'):
        config = ET.SubElement(element, 'scan_config')
        for key, value in rule['scan_config'].items():
            if key == 'marks' and isinstance(value, list):
                marks = ET.SubElement(config, 'marks')
                for mark in value:
                    ET.SubElement(marks, 'mark', color=mark.get('color', 'red')).text = mark['spec']
                continue
            ET.SubElement(config, key).text = str(value).lower() if isinstance(value, bool) else str(value)
    element.set('pattern_id', rule['id'])
    return element


def load_pack(path):
    """Return the scanner's internal representation; built-ins come from YAML."""
    path = resolve_pack(path)
    if not path.is_dir():
        # Import compatibility for external packs; never preferred over unified rules.
        tree = ET.parse(path).getroot()
        if tree.find('.//exclude') is not None:
            raise ValueError('Legacy per-rule exclude filters are unsupported; review and remove them before importing or scanning')
        return tree
    try:
        metadata = yaml.load((path / '_pack.yaml').read_text(encoding='utf-8'), Loader=_RuleLoader)
    except (yaml.YAMLError, ValueError) as exc:
        raise ValueError(f'{path}: invalid _pack.yaml: {exc}') from exc
    if not isinstance(metadata, dict) or metadata.get('format') != PACK_FORMAT or metadata.get('layout') not in {'flat', 'categories'}:
        raise ValueError(f'{path}: invalid _pack.yaml')
    rules = [(p, load_rule(p)) for p in sorted(path.glob('*.yaml')) if p.name != '_pack.yaml']
    rules.sort(key=lambda item: (item[1].get('order', 0), item[0].name))
    root, categories, seen = ET.Element('root'), {}, set()
    for filename, rule in rules:
        if rule['id'] in seen:
            raise ValueError(f'{filename}: duplicate rule id {rule["id"]}')
        seen.add(rule['id'])
        parent = root
        if metadata['layout'] == 'categories':
            category = rule.get('category', 'Review surface')
            if category not in categories:
                categories[category] = ET.SubElement(root, 'category', name=category)
            parent = categories[category]
        element = rule_element(rule)
        element.set('pattern_file', str(filename))
        parent.append(element)
    return root


def read_logic(root, ref):
    """Resolve a retained rule identity to the authoritative single-file source."""
    root = Path(root)
    sources = _logic_inventory(str(root.resolve()))
    if ref in sources:
        return sources[ref]
    from utils.source_cache import read_source_text
    return read_source_text(root / 'rules/scanning' / ref)


@lru_cache(maxsize=8)
def _logic_inventory(root):
    sources = {}
    for pack in sorted((Path(root) / 'rules/scanning/platform').rglob('_pack.yaml')):
        for filename in sorted(pack.parent.glob('*.yaml')):
            if filename.name == '_pack.yaml':
                continue
            rule = load_rule(filename)
            ref = reference(rule)
            if ref in sources:
                raise ValueError(f'{filename}: duplicate rule identity {rule["id"]}')
            sources[ref] = logic_source(rule)
    return sources


def migrate_xml(path, output=None, logic_root=None):
    """Import a legacy pack once; subsequent edits belong to its YAML rules."""
    from core.rdl.baseline import slug
    path = Path(path)
    output = Path(output) if output else path.with_suffix('.rules')
    if output.exists() and any(output.iterdir()):
        raise ValueError(f'{output}: destination is not empty')
    tree = ET.parse(path).getroot()
    logic_root = Path(logic_root) if logic_root else next((p for p in path.parents if p.name == 'scanning'), path.parent)
    documents = []
    for order, element in enumerate(tree.iter('rule'), 1):
        title = element.findtext('name', '').strip()
        pattern = element.findtext('regex', '').strip()
        ref = element.findtext('rdl_ref', '').strip()
        conditions, reporting = [], {}
        if ref:
            relative = Path(ref).relative_to('logic/rdl/v1')
            identifier = '.'.join(relative.parent.parts) + '.' + relative.stem
            for line in (logic_root / ref).read_text(encoding='utf-8').splitlines():
                line = line.strip()
                if not line or line.startswith(('#', 'VERSION ')):
                    continue
                for prefix, field in [('REPORT AS ', 'type'), ('FAIL_REASON ', 'fail_reason'), ('REASON ', 'reason'), ('TRACE ', 'trace')]:
                    if line.startswith(prefix):
                        value = line[len(prefix):]
                        if field == 'trace':
                            reporting.setdefault(field, []).append(value)
                        else:
                            reporting[field] = value
                        break
                else:
                    conditions.append(line.replace(pattern, '${pattern}') if pattern and line in ('WHEN PRESENT ' + pattern, 'WHEN MISSING ' + pattern) else line)
        else:
            identifier = slug(path.stem) + '.core.' + slug(title)
        detection = {'pattern': pattern}
        if conditions:
            detection['conditions'] = conditions
        for old, field in [('description', 'summary'), ('rule_desc', 'description'), ('vuln_desc', 'impact'), ('developer', 'remediation'), ('reviewer', 'reviewer')]:
            if element.findtext(old):
                reporting[field] = element.findtext(old).strip()
        rule = dict(format=FORMAT, id=identifier, title=title, order=order, detection=detection, reporting=reporting)
        category = next((c.get('name') for c in tree.findall('category') if element in list(c)), None)
        if category:
            rule['category'] = category
        config = element.find('scan_config')
        if config is not None:
            rule['scan_config'] = {c.tag: c.text or '' for c in config}
            if config.find('marks') is not None:
                rule['scan_config']['marks'] = [dict(color=m.get('color', 'red'), spec=(m.text or 'match').strip()) for m in config.find('marks')]
        if element.findtext('exclude'):
            raise ValueError('Legacy per-rule exclude filters are unsupported; remove the filter and review the rule conditions before importing')
        documents.append(rule)
    # Validate every document before creating the destination.
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        for rule in documents:
            test = Path(tmp) / 'rule.yaml'
            test.write_text(yaml.safe_dump(rule, sort_keys=False), encoding='utf-8')
            load_rule(test)
    if len({r['id'] for r in documents}) != len(documents):
        raise ValueError(f'{path}: duplicate rule identities')
    output.mkdir(parents=True, exist_ok=True)
    (output / '_pack.yaml').write_text(yaml.safe_dump(dict(format=PACK_FORMAT, layout='categories' if tree.findall('category') else 'flat'), sort_keys=False), encoding='utf-8')
    for rule in documents:
        (output / (rule['id'].rsplit('.', 1)[-1] + '.yaml')).write_text(yaml.safe_dump(rule, sort_keys=False, allow_unicode=True, width=110), encoding='utf-8')
    return output, len(documents)
