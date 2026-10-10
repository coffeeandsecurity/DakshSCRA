"""Versioned review-workload accounting with explicit, calibratable assumptions."""
import hashlib
import json
import math
import re
from pathlib import Path

import yaml

MODEL_VERSION = '2.0'
DOMAINS = (
    ('authentication', 'Authentication'), ('authorization', 'Authorization'),
    ('taint', 'Taint analysis'), ('input', 'Input handling and injection'),
    ('session', 'Sessions and credentials'), ('crypto', 'Cryptography and transport'),
    ('data', 'Data protection and storage'), ('configuration', 'Configuration and dependencies'),
    ('platform', 'Platform and file handling'), ('business', 'Business logic'),
    ('other', 'Other review areas'),
)
PATTERNS = {
    'authentication': r'authenticat|\blogin\b|\blogout\b|password|biometric|\bmfa\b|\boauth\b',
    'authorization': r'authoriz|access.control|privilege|permission|\brole\b|\bacl\b|\bidor\b',
    'input': r'injection|\bsql\b|\bxss\b|deserial|redirect|\bssrf\b|command|eval|traversal',
    'session': r'session|cookie|credential|secret|token|private.key',
    'crypto': r'crypt|cipher|\btls\b|\bssl\b|certificate|hash|\bhttps\b',
    'data': r'storage|database|logging|sensitive|privacy|clipboard|backup|exposure',
    'configuration': r'config|dependenc|debug|version|manifest|build|header|cors',
    'platform': r'upload|file|webview|intent|ipc|exported|browser|memory|native',
    'business': r'business|workflow|transaction|race|concurren|payment|grade|notification',
}
MODES = ('assisted', 'targeted', 'manual', 'ai')
ASSUMPTION_KEYS = {
    'hours_per_day', 'inspection_loc_per_hour', 'active_minutes', 'suppressed_minutes',
    'unresolved_minutes', 'trace_step_minutes', 'manual_trace_step_minutes',
    'assisted_setup_hours', 'manual_setup_hours', 'manual_file_minutes',
    'domain_exploration_hours', 'report_base_hours', 'report_unit_minutes',
    'confirmed_minutes', 'manual_active_minutes', 'manual_confirmed_minutes',
    'manual_suppressed_minutes', 'manual_unresolved_minutes',
}
LIMITATIONS = [
    'Planning ranges are sensitivity bounds, not confidence intervals or promises of vulnerability detection.',
    'A scan structures review work; a match is not proof of exploitability and a suppression is not proof of safety.',
    'The supplied scan scope, exclusions and unsupported files limit the inventory. Missing evidence is not zero work.',
    'Person-hours exclude remediation, retesting, runtime/backend testing and elapsed scan or model execution time.',
    'Targeted file scope is inferred from retained evidence, not an exhaustive inventory of every implementation of a security control.',
    'No universal automation discount or AI productivity factor is applied.',
    'Effective LOC follows the scanner’s existing comment/blank-line heuristic; calibration must use the same counting convention.',
]


def load_assumptions(path=None):
    path = Path(path) if path else Path(__file__).resolve().parents[1] / 'config/estimate.yaml'
    data = yaml.safe_load(path.read_text(encoding='utf-8')) or {}
    if data.get('model_version') != MODEL_VERSION:
        raise ValueError('Unsupported effort model configuration')
    values = data.get('assumptions')
    if not isinstance(values, dict) or set(values) != ASSUMPTION_KEYS:
        raise ValueError('Global effort configuration must define every supported assumption')
    return validate_assumptions(values, values)


def validate_assumptions(values, defaults=None):
    expected = load_assumptions() if defaults is None else defaults
    if not isinstance(values, dict) or set(values) - set(expected):
        raise ValueError('Unknown effort assumptions')
    result = dict(expected, **values)
    for key, value in result.items():
        if key == 'hours_per_day':
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 < value <= 24:
                raise ValueError('Productive hours per day must be greater than zero and at most 24')
        else:
            if not isinstance(value, (list, tuple)) or len(value) != 2:
                raise ValueError(key + ' requires [low, high]')
            if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or v < 0 or v > 100000 for v in value):
                raise ValueError(key + ' requires finite nonnegative values')
            if value[0] > value[1] or (key == 'inspection_loc_per_hour' and value[0] <= 0):
                raise ValueError(key + ' requires an ordered range and positive inspection rates')
            result[key] = list(value)
    return result


def calibrate(samples, assumptions):
    """Use observed comparable task rates; empirical min/max are not a CI."""
    if not isinstance(samples, (list, tuple)) or len(samples) > 1000:
        raise ValueError('Calibration must contain at most 1000 observed task samples')
    grouped = {}
    for sample in samples:
        key = sample.get('component')
        if key not in assumptions or key == 'hours_per_day':
            raise ValueError('Unknown calibration component')
        units, hours = sample.get('units'), sample.get('hours')
        if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or v <= 0 for v in (units, hours)):
            raise ValueError('Calibration units and hours must be finite and positive')
        rate = units / hours if key == 'inspection_loc_per_hour' else hours / units
        if key.endswith('_minutes'):
            rate *= 60
        grouped.setdefault(key, []).append(rate)
    values, evidence = dict(assumptions), {}
    for key, rates in grouped.items():
        if len(rates) < 5:
            raise ValueError('At least five comparable observations are required per calibrated component')
        values[key] = [min(rates), max(rates)]
        evidence[key] = {'sample_count': len(rates), 'range_method': 'observed minimum/maximum; not a confidence interval'}
    return validate_assumptions(values), evidence


def _number(value):
    try:
        value = float(value)
        return max(0, int(value)) if math.isfinite(value) else 0
    except (TypeError, ValueError, OverflowError):
        return 0


def _read(path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding='utf-8'))


def build_workload(inventory, findings=(), suppressed=(), paths=(), records=(), flows=(),
                   scan_meta=None, recon=None, target='', complete=True, provenance=None):
    """Count review sites, union file scope and preserve every evidence disposition."""
    files = {}
    unlocated = 0
    for item in inventory:
        path = item.get('path', '') if isinstance(item, dict) else item
        if not isinstance(path, str) or not path:
            continue
        path = path.replace('\\', '/').lstrip('/')
        loc = item.get('loc') if isinstance(item, dict) else None
        if loc is not None and (isinstance(loc, bool) or not isinstance(loc, (int, float)) or not math.isfinite(loc) or loc < 0):
            loc = None
        files[path] = {'path': path, 'loc': int(loc) if loc is not None else None}
    target = str(target).replace('\\', '/').rstrip('/')
    aliases = {}

    def canonical(path):
        path = str(path or '').replace('\\', '/')
        original = path.lstrip('/')
        if target and path.startswith(target + '/'):
            path = path[len(target) + 1:]
        path = path.lstrip('/')
        if path in files:
            return path
        if path not in aliases:
            matches = [key for key in files if original.endswith('/' + key) or path.endswith('/' + key)
                       or key.endswith('/' + path)]
            aliases[path] = matches[0] if len(matches) == 1 else path
        return aliases[path]

    units = {}

    def trace_path(step):
        location = step.get('location') or {}
        return step.get('file') or step.get('file_path') or location.get('path') or location.get('file')

    def add(item, disposition, origin, title='', location=None, trace=(), taint=False):
        nonlocal unlocated
        location = location or item.get('location') or item
        path = canonical(location.get('file') or location.get('file_path') or location.get('path'))
        if not path:
            unlocated += 1
            return
        line = _number(location.get('line'))
        text = ' '.join(str(v or '') for v in (title, item.get('title'), item.get('rule_title'), item.get('rule_id'), item.get('kind'), item.get('category'))).replace('_', ' ')
        domains = {key for key, pattern in PATTERNS.items() if re.search(pattern, text, re.I)}
        if taint:
            domains.add('taint')
        if not domains:
            domains.add('other')
        # A review site is one primary concern at a location and disposition;
        # repeated engines/platform inheritance do not create more work units.
        primary = next((key for key, _ in DOMAINS if key in domains and key != 'taint'), 'taint')
        bucket = 'active' if disposition in ('active', 'confirmed') else disposition
        key = (path, line, primary, bucket)
        unit = units.setdefault(key, {'id': hashlib.sha256(json.dumps(key).encode()).hexdigest()[:16],
            'file': path, 'line': line, 'primary_domain': primary, 'domains': [], 'disposition': bucket,
            'confirmed': False, 'reviewer_confirmed': False, 'sources': [], 'checks': [], 'evidence_occurrences': 0,
            'trace_steps': 0, 'files': [path]})
        unit['domains'] = sorted(set(unit['domains']) | domains)
        unit['sources'] = sorted(set(unit['sources']) | {origin})
        identifier = item.get('rule_id') or item.get('rule_title') or title or item.get('title') or item.get('sink') or origin
        unit['checks'] = sorted(set(unit['checks']) | {str(identifier)})
        unit['evidence_occurrences'] += 1
        unit['confirmed'] |= disposition == 'confirmed'
        review = item.get('security_review') or {}
        unit['reviewer_confirmed'] |= item.get('status') == 'confirmed_finding' or (
            isinstance(review, dict) and review.get('status') == 'confirmed' and bool(review.get('reviewer') and review.get('reason')))
        unit['trace_steps'] = max(unit['trace_steps'], len(trace))
        unit['files'] = sorted(set(unit['files']) | {canonical(trace_path(step)) for step in trace
                                                   if isinstance(step, dict) and trace_path(step)})

    for finding in findings:
        for evidence in finding.get('evidence') or []:
            add(finding, 'active', 'source', location=evidence)
    for item in suppressed:
        add(item, 'active' if item.get('status') == 'confirmed_finding' else 'suppressed', 'suppression')
    for item in paths:
        for path in item.get('filepath') or []:
            add(item, 'active', 'path', location={'file': path})
    record_count = 0
    for record in records:
        record_count += 1
        outcome = record.get('v2_outcome')
        context = record.get('context') or {}
        title = record.get('v2_title') or context.get('rule_title') or record.get('v2_rule_id', '')
        disposition = None
        from core.rdl.assessment import classify_record
        assessment = classify_record(record)
        if assessment in ('suppressed', 'mitigated'):
            disposition = 'suppressed'
        elif outcome == 'MATCH':
            path_only = record.get('v2_findings') and all(f.get('path_only') for f in record['v2_findings'])
            disposition = 'active' if path_only else 'confirmed'
        elif outcome in ('INDETERMINATE', 'RULE_ERROR', 'SHADOW_ERROR'):
            disposition = 'unresolved'
        elif outcome == 'NO_MATCH' and (record.get('v2_baseline_outcome') == 'MATCH' or record.get('v1_outcome') == 'MATCH'):
            disposition = 'suppressed'
        if not disposition:
            continue  # Ordinary nonmatching rules are not suppressed findings.
        for item in record.get('v2_findings') or [context]:
            trace = (item.get('trace') or {}).get('steps') or []
            add(dict(item, security_review=record.get('security_review')), disposition, 'rdl', title=title,
                location=item.get('location') or context, trace=trace,
                taint=any(str(step.get('role', '')).lower() == 'source' or step.get('predicate') in ('SOURCE', 'FLOWS TO')
                          or str(step.get('explanation', '')).startswith('input.') for step in trace if isinstance(step, dict)))
    for flow in flows:
        add(flow, 'unresolved' if flow.get('trace_status') == 'partial' or flow.get('flow_kind') == 'partial' else 'active',
            'analyzer', title=flow.get('sink', ''), trace=flow.get('path') or [], taint=True)
    values = sorted(units.values(), key=lambda u: (u['file'], u['line'], u['primary_domain'], u['disposition']))
    detection = (scan_meta or {}).get('detection_summary') or {}
    coverage = {
        'inventory_files': len(files), 'loc_known_files': sum(f['loc'] is not None for f in files.values()),
        'inventory_rows': len(inventory), 'duplicate_inventory_rows': max(0, len(inventory) - len(files)),
        'effective_loc': sum(f['loc'] or 0 for f in files.values()),
        'reported_project_files': _number(detection.get('total_project_files_identified')),
        'reported_scanned_files': _number(detection.get('total_files_scanned')),
        'rdl_records_read': record_count, 'scan_complete': bool(complete),
        'parse_errors': _number((scan_meta or {}).get('live_progress', {}).get('parse_error_count')),
        'unlocated_evidence': unlocated,
    }
    technologies = []
    categories = (recon or {}).get('categories', recon or {})
    for category, entries in categories.items():
        if isinstance(entries, dict):
            technologies.extend(str(name) for name in entries if name != 'meta')
    groups = []
    for key, label in DOMAINS:
        selected = [u for u in values if key in u['domains']]
        related = {f for u in selected for f in u['files']}
        groups.append({'id': key, 'label': label, 'review_units': len(selected),
                       'related_files': len(related), 'related_loc': sum(files[f]['loc'] or 0 for f in related if f in files),
                       **{state: sum(u['disposition'] == state for u in selected) for state in ('active', 'suppressed', 'unresolved')}})
    return {'model_version': MODEL_VERSION, 'target': target, 'files': list(files.values()),
            'review_units': values, 'coverage': coverage, 'domains': groups,
            'technologies': sorted(set(technologies)), 'scan_options': (scan_meta or {}).get('inputs_received') or {},
            'provenance': provenance or {}}


def workload_from_run(data_dir, runtime_dir, target='', complete=True):
    data_dir, runtime_dir = Path(data_dir), Path(runtime_dir)
    from core.rdl.result_store import ResultStore
    inputs = {'inventory': runtime_dir / 'filepaths.json', 'findings': data_dir / 'areas_of_interest.json',
              'suppressed': data_dir / 'suppressed_findings.json', 'paths': data_dir / 'filepaths_aoi.json',
              'scan_meta': runtime_dir / 'scan_summary.json', 'recon': runtime_dir / 'recon_summary.json'}
    values = {name: _read(path, {} if name in ('scan_meta', 'recon') else []) for name, path in inputs.items()}
    if not values['recon']:
        values['recon'] = _read(data_dir / 'recon.json', {})
    analysis = _read(data_dir / 'analysis.json', {})
    flows, analysis_paths = [], set()
    # Only run-owned analysis directories are read, never arbitrary artifact paths.
    for root in (data_dir.parent / 'analysis', runtime_dir / 'analysis'):
        for path in root.glob('*/analysis.json'):
            identity = path.resolve()
            if identity not in analysis_paths:
                payload = _read(path, [])
                flows.extend(payload if isinstance(payload, list) else payload.get('flows') or [])
                analysis_paths.add(identity)
    records_path = runtime_dir / 'rdl_shadow_comparisons.jsonl'
    provenance = {name: {'path': str(path), 'available': path.is_file()} for name, path in inputs.items()}
    rdl_available = records_path.is_file() or records_path.with_suffix('.sqlite3').is_file() or records_path.with_suffix('.findings.jsonl.gz').is_file()
    provenance['rdl'] = {'path': str(records_path), 'available': rdl_available}
    values['scan_meta'].setdefault('analyzer_summary', analysis.get('summary') or {})
    payload = build_workload(**values, records=ResultStore(records_path).iter_records_readonly() if rdl_available else (),
                            flows=flows, target=target, complete=complete, provenance=provenance)
    payload['coverage']['analyzer_failures'] = _number((analysis.get('summary') or {}).get('targets_failed'))
    payload['coverage']['analysis_available'] = bool(analysis.get('summary', {}).get('enabled'))
    payload['coverage']['analyzer_files_read'] = len(analysis_paths)
    payload['coverage']['storage_error'] = records_path.with_suffix('.storage-error').exists()
    return payload


def estimate_workload(workload, mode='assisted', domains=None, assumptions=None, calibration=()):
    if mode not in MODES:
        raise ValueError('Unknown review scenario')
    ids = {key for key, _ in DOMAINS}
    chosen = sorted(ids if domains is None else set(domains))
    if set(chosen) - ids:
        raise ValueError('Unknown review domain')
    defaults = load_assumptions()
    rates = validate_assumptions(assumptions or {}, defaults)
    rates, evidence = calibrate(calibration, rates) if calibration else (rates, {})
    units = [u for u in workload['review_units'] if mode != 'targeted' or set(u['domains']) & set(chosen)]
    related = {path for u in units for path in u['files']}
    files = [f for f in workload['files'] if mode != 'targeted' or f['path'] in related]
    loc = sum(f['loc'] or 0 for f in files)
    counts = {state: sum(u['disposition'] == state for u in units) for state in ('active', 'suppressed', 'unresolved')}
    counts.update(confirmed=sum(u['confirmed'] for u in units), trace_steps=sum(u['trace_steps'] for u in units),
                  cross_file_units=sum(len(u['files']) > 1 for u in units), files=len(files), effective_loc=loc)
    counts['reviewer_confirmed'] = sum(u['disposition'] == 'active' and u.get('reviewer_confirmed', False) for u in units)
    counts['confirmed_review_sites'] = sum(u['disposition'] == 'active' and (u['confirmed'] or u.get('reviewer_confirmed', False)) for u in units)
    counts['areas_of_interest'] = counts['active'] - counts['confirmed_review_sites']
    warnings = []
    coverage = workload['coverage']
    missing_loc = sum(f['loc'] is None for f in files)
    if missing_loc or not files:
        warnings.append('LOC inventory is incomplete or unavailable; the code-inspection component cannot be fully estimated.')
    if not coverage['scan_complete']:
        warnings.append('Scan is incomplete; retained workload is a lower bound.')
    if coverage.get('parse_errors') or coverage.get('analyzer_failures') or coverage.get('storage_error'):
        warnings.append('Scan or analyzer errors leave unmeasured review work.')
    if coverage.get('unlocated_evidence'):
        warnings.append('Some retained evidence has no file location and could not be assigned to a review site.')
    if not coverage.get('analysis_available', True):
        warnings.append('Advanced analysis was not run; taint workload is incomplete.')
    if not workload.get('provenance', {}).get('rdl', {'available': True})['available']:
        warnings.append('RDL review evidence is unavailable; confirmation and unresolved workload may be incomplete.')
    if any(path not in {f['path'] for f in workload['files']} for path in related):
        warnings.append('Some evidence files are outside the retained LOC inventory.')
    if coverage['reported_project_files'] > coverage['inventory_files']:
        warnings.append('The project contains files outside the retained inventory. This estimate covers the supplied scan scope only.')
    if mode == 'targeted':
        warnings.append('Targeted scope includes evidence-related files and explicit exploration time; zero findings does not establish absence of a control or a vulnerability.')
    components = []
    exact_bounds = []

    def add(name, quantity, key, divisor=1, inverse=False):
        low, high = rates[key]
        bounds = [quantity / high, quantity / low] if inverse else [quantity * low / divisor, quantity * high / divisor]
        exact_bounds.append(bounds)
        components.append({'id': key, 'label': name, 'quantity': quantity, 'assumption': key,
                           'hours': [math.ceil(v) for v in bounds], 'formula': 'quantity / rate' if inverse else 'quantity × rate / ' + str(divisor)})

    has_scope = bool(files or units or (mode == 'targeted' and chosen))
    if mode != 'ai' and has_scope:
        add('Orientation and scope planning', 1, 'manual_setup_hours' if mode == 'manual' else 'assisted_setup_hours')
        add('Code inspection', loc, 'inspection_loc_per_hour', inverse=True)
        if mode == 'manual':
            add('Manual file and technology mapping', len(files), 'manual_file_minutes', 60)
        if mode == 'targeted':
            add('Control discovery and domain exploration', len(chosen), 'domain_exploration_hours')
        prefix = 'manual_' if mode == 'manual' else ''
        add('Areas of interest review', counts['areas_of_interest'], prefix + 'active_minutes', 60)
        add('Confirmed or RDL-supported finding review', counts['confirmed_review_sites'], prefix + 'confirmed_minutes', 60)
        add('Suppression decision review', counts['suppressed'], prefix + 'suppressed_minutes', 60)
        add('Unresolved evidence investigation', counts['unresolved'], prefix + 'unresolved_minutes', 60)
        add('Path reconstruction' if mode == 'manual' else 'Trace evidence review', counts['trace_steps'],
            'manual_trace_step_minutes' if mode == 'manual' else 'trace_step_minutes', 60)
        add('Report preparation', 1, 'report_base_hours')
        add('Document reviewed decisions', len(units), 'report_unit_minutes', 60)
    exact_total = [sum(bounds[i] for bounds in exact_bounds) for i in (0, 1)]
    total = [math.ceil(v) for v in exact_total]
    missing = missing_loc or not files
    status = 'not_estimable' if mode == 'ai' else 'evidence_limited' if warnings else 'planning_estimate'
    if mode == 'targeted' and not chosen:
        warnings = []; status = 'no_scope'; total = [0, 0]
    unbounded = mode == 'ai' or (missing and not (mode == 'targeted' and not chosen))
    result = {'schema_version': 2, 'model_version': MODEL_VERSION, 'mode': mode, 'selected_domains': chosen,
        'status': status, 'workload': workload, 'selected_workload': counts, 'assumptions': rates,
        'assumption_basis': 'planning assumptions with observed task calibration' if evidence else 'transparent planning assumptions; not empirically validated for this codebase',
        'calibration': evidence, 'calibration_samples': list(calibration),
        'baseline_defaults': defaults,
        'baseline_overrides': {key: value for key, value in rates.items() if value != defaults[key]},
        'components': components, 'known_work_hours': None if mode == 'ai' else total,
        'total_hours': None if unbounded else total,
        'total_days_min': None if unbounded else math.ceil(exact_total[0] / rates['hours_per_day']),
        'total_days_max': None if unbounded else math.ceil(exact_total[1] / rates['hours_per_day']),
        'rounding': 'Each effort value is rounded up to a whole hour or day. Totals use unrounded task calculations, so rounded rows may not sum to the rounded total.',
        'warnings': warnings, 'limitations': LIMITATIONS,
        'ai_measurements_required': ['Model and version, local hardware or frontier service configuration',
            'Task mix, context size, end-to-end latency including retries and context preparation',
            'Human validation minutes, acceptance rate, missed issues and rework rate',
            'Comparable held-out reviews; model elapsed time and human effort measured separately'] if mode == 'ai' else [],
        'deduplication': 'Review sites are unioned by file, line, primary domain and disposition; active v1/v2 sites merge. Overlapping selected domains share work. Suppressed and unresolved dispositions remain separate.',
        'code_scope': 'all inventoried code' if mode != 'targeted' else 'union of retained evidence-related files',
    }
    result['input_fingerprint'] = hashlib.sha256(json.dumps({'workload': workload, 'mode': mode, 'domains': chosen,
        'assumptions': rates, 'calibration': list(calibration)}, sort_keys=True).encode()).hexdigest()
    return result


def render_estimate(report):
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    root = Path(__file__).resolve().parents[1] / 'resources/templates'
    env = Environment(loader=FileSystemLoader(str(root)), autoescape=select_autoescape(['html']))
    return env.get_template('effort-plan.html').render(report=report)
