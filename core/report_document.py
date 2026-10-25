"""Saved-result documents shared by CLI reports and on-demand web exports."""
from collections import Counter
from hashlib import sha256
from datetime import datetime
from pathlib import Path
import json
import re

from markupsafe import Markup


def _read(path, default):
    path = Path(path)
    return json.loads(path.read_text(encoding='utf-8')) if path.is_file() else default


def cli_document(analysis_path=None):
    import state.runtime_state as state
    runtime = Path(state.scanSummary_Fpath).parent
    data_root = Path(state.outputAoI_JSON).parent
    external = analysis_path and Path(analysis_path).resolve() != Path(state.outputAnalysis_JSON).resolve()
    if external:
        data_root = Path(analysis_path).parent
        runtime = (data_root.parent.parent if data_root.parent.name == 'results' else data_root.parent) / 'runtime'
    from utils.report_audience import current_audience
    return saved_document(data_root, runtime, audience=current_audience())


REPORT_LABELS = {'full': 'Full scan', 'findings': 'Areas of interest',
                 'analysis': 'Advanced analysis', 'suppressed': 'Suppressed findings'}


def saved_document(data_root, runtime, scope='full', scan=None, audience=None):
    """One saved-data contract for CLI generation and web exports."""
    data_root, runtime = Path(data_root), Path(runtime)
    names = {'full': ['summary', 'recon', 'areas_of_interest', 'filepaths_aoi', 'analysis', 'suppressed_findings', 'estimation'],
             'findings': ['areas_of_interest', 'filepaths_aoi'],
             'analysis': ['analysis'], 'suppressed': ['suppressed_findings']}[scope]
    sections = {name: _read(data_root / (name + '.json'), None) for name in names
                if (data_root / (name + '.json')).is_file()}
    if scope in ('full', 'analysis'):
        sections.update(review_sections(runtime))
    if scope in ('full', 'findings'):
        inventory = runtime / 'filepaths.json'
        if not inventory.is_file():
            inventory = data_root / 'filepaths.json'
        if inventory.is_file():
            sections['filepaths'] = _read(inventory, [])
    if not sections:
        raise ValueError('No saved data is available for this report type.')
    summary = _read(data_root / 'summary.json', _read(runtime / 'scan_summary.json', {}))
    if summary:
        sections['summary'] = summary
    inputs = summary.get('inputs_received', {})
    identity = {key: value for key, value in {
        'project': inputs.get('project_name') or inputs.get('project_id') or inputs.get('target_directory'),
        'project_key': inputs.get('project_id'), 'run_uuid': inputs.get('run_id')}.items() if value}
    identity.update(scan or {})
    from utils.report_audience import normalize_audience
    from core.suppression_explanations import explain_suppressions
    explanations = explain_suppressions(sections.get('suppressed_findings') or [], runtime,
        target=inputs.get('target_directory'))
    return {'suppression_explanations': [dict(id=row.get('id'), file=row.get('file'), line=row.get('line'),
                explanation=row['suppression_explanation']) for row in explanations], 'scan': identity, 'report': REPORT_LABELS[scope], 'sections': sections,
            'report_audience': normalize_audience(audience or identity.get('report_audience') or inputs.get('report_audience'))}


def prepare_document(document):
    """Refine guidance on copies, then remove the unselected perspective."""
    from utils.report_audience import filter_guidance, normalize_audience
    from core.review_guidance import audience_guidance
    from core.issue_titles import normalize_record_titles
    def refine(value):
        if isinstance(value, list):
            return [refine(child) for child in value]
        if not isinstance(value, dict):
            return value
        from core.issue_notes import refresh_bundled_notes
        result = refresh_bundled_notes({key: refine(child) for key, child in value.items()})
        dev_key = next((key for key in ('developer_note', 'remediation', 'recommendation') if key in result), None)
        reviewer_key = 'reviewer_note'
        if dev_key or reviewer_key in result:
            developer, reviewer = audience_guidance(result.get('rule_title') or result.get('title') or result.get('kind', ''),
                result.get(dev_key, '') if dev_key else '', result.get(reviewer_key, ''), result.get('category', ''))
            result[dev_key or 'developer_note'], result[reviewer_key] = developer, reviewer
        return normalize_record_titles(result)
    audience = normalize_audience(document.get('report_audience'))
    return filter_guidance(dict(refine(document), report_audience=audience), audience)


def render_json(document, destination):
    from utils.report_audience import filter_guidance
    from core.issue_titles import normalize_document_titles
    document = normalize_document_titles(filter_guidance(document, document.get('report_audience', 'both')))
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(document, ensure_ascii=True, indent=2), encoding='utf-8')
    return destination


def review_sections(runtime):
    from core.rdl.result_store import ResultStore
    from tempfile import TemporaryDirectory
    import shutil
    import sqlite3
    runtime = Path(runtime)
    source = runtime / 'rdl_shadow_comparisons.jsonl'
    sections = {}
    if source.with_suffix('.sqlite3').is_file():
        # Compatibility imports/schema upgrades may write. Perform them only
        # on a consistent private snapshot, never on the retained scan evidence.
        with TemporaryDirectory(prefix='daksh-evidence-') as temporary:
            copied = Path(temporary) / source.name
            with sqlite3.connect(source.with_suffix('.sqlite3').resolve().as_uri() + '?mode=ro', uri=True) as original:
                with sqlite3.connect(str(copied.with_suffix('.sqlite3'))) as snapshot:
                    original.backup(snapshot)
            for journal in (source, source.with_suffix('.findings.jsonl.gz')):
                if journal.is_file():
                    shutil.copy2(journal, Path(temporary) / journal.name)
            sections['rdl_review_evidence'] = list(ResultStore(copied).iter_records(reviewed=True))
    if (runtime / 'rdl_xref.json').is_file():
        from core.rdl.xref import read_index
        try:
            sections['rdl_cross_references'] = read_index(runtime / 'rdl_xref.json') or {}
        except ValueError:
            legacy = _read(runtime / 'rdl_xref.json', {})
            if 'version' in legacy or 'storage_encoding' in legacy:
                raise
            sections['rdl_cross_references'] = legacy
    from core.rdl.advanced import read_inventory_index
    advanced = read_inventory_index(runtime) if (runtime / 'rdl_advanced_review.json').is_file() or sections.get('rdl_cross_references', {}).get('input_inventory') is not None else None
    if advanced and advanced.get('input_inventory') is not None:
        sections['rdl_advanced_analysis'] = dict(provenance=advanced.get('provenance'), created_at=advanced.get('created_at'), **advanced['input_inventory'])
    from core.rdl.program_graphs import read_catalog
    program_graphs = read_catalog(runtime)
    if program_graphs is not None:
        sections['program_graphs'] = program_graphs
    return sections


def safe_snippets(snippets):
    """Legacy snippet text is already escaped; only those fields are trusted."""
    escaped = {'keyword', 'category', 'issue_scope', 'rule_desc', 'issue_desc', 'dev_note',
               'rev_note', 'logic_engine', 'logic_source', 'logic_reason'}
    result = {}
    for platform, items in snippets.items():
        result[platform] = []
        for item in items:
            row = dict(item)
            for key in escaped:
                if key in row:
                    row[key] = Markup(row[key])
            for key in ('logic_trace', 'logic_consulted_files'):
                row[key] = [Markup(text) for text in row.get(key, [])]
            result[platform].append(row)
    return result


def _rows(value):
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def _rank(row):
    return {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}.get(str(row.get('severity', '')).lower(), 5)


def presentation_context(document, platform=None):
    from utils.datetime_utils import presentation_dates
    document = presentation_dates(document)
    from core.recon_presentation import recon_presentation
    from core.rdl.narratives import enrich_analysis, refresh_record
    from core.rdl.assessment import classify_record, CATEGORIES, manual_review_direction
    sections = document.get('sections', {})
    analysis = enrich_analysis(sections.get('analysis') or {})
    results = _rows(analysis.get('results', [])) if isinstance(analysis, dict) else []
    flows, assessments, mitigations, manual, targets = [], [], [], [], []
    for result in results:
        target = str(result.get('platform') or result.get('target') or 'unknown')
        if platform and target.lower() != str(platform).lower():
            continue
        targets.append(result)
        # Framework rows explicitly inherit their parent inventory, not new flows.
        if result.get('engine') == 'platform_inherited':
            continue
        for finding in _rows(result.get('findings', [])):
            flows.append(dict(finding, report_platform=target, anchor=f'flow-{len(flows)+1}'))
    flows.sort(key=_rank)
    assessments.sort(key=_rank)
    vectors, references = [], []
    for flow in flows:
        for item in _rows(flow.get('attack_vectors', [])):
            vectors.append(dict(item, flow_anchor=flow['anchor'], flow_title=flow.get('title', ''),
                                source=flow.get('source', ''), platform=flow['report_platform']))
        for item in _rows(flow.get('xref', [])):
            references.append(dict(item, flow_anchor=flow['anchor']))
    records = [dict(record, v2_findings=[dict(finding) for finding in record.get('v2_findings') or []])
               for record in _rows(sections.get('rdl_review_evidence', []))]
    for record in records:
        refresh_record(record)
    if platform:
        records = [r for r in records if str(r.get('language', '')).lower() == str(platform).lower()]
    rdl_findings, limitations = [], []
    assessment_groups = {category: set() for category in CATEGORIES}
    seen = set()
    from core.rdl.review_views import finding_identity
    for record in records:
        context = record.get('context') or {}
        category = classify_record(record)
        if category in assessment_groups:
            assessment_groups[category].add((record.get('v2_rule_id') or record.get('v2_rule'), context.get('file_path'), record.get('v2_outcome')))
        record_view = dict(title=record.get('v2_title') or record.get('v2_rule_id'),
                           file=context.get('file_path'), status=category,
                           reason=record.get('v2_explanation'), evidence=record.get('v2_evidence') or [],
                           security_review=record.get('security_review'))
        if category == 'manual':
            direction = manual_review_direction(record)
            record_view.update(reason=' '.join(direction[key] for key in ('observed', 'uncertainty', 'investigate')),
                               evidence=direction['evidence'])
        if category == 'mitigated':
            mitigations.append(record_view)
        elif category == 'manual' and record.get('v2_outcome') != 'MATCH':
            manual.append(record_view)
        if record.get('v2_outcome') == 'MATCH':
            for finding in _rows(record.get('v2_findings', [])):
                key = sha256(finding_identity(record, finding).encode()).digest()
                if key in seen:
                    continue
                seen.add(key)
                rdl_findings.append(dict(finding, assessment=category, rule_title=context.get('rule_title') or record.get('v2_rule_id') or record.get('v2_rule'),
                    report_path=context.get('file_path', ''), report_kind=record.get('comparison_kind', ''),
                    report_rule_id=record.get('v2_rule_id') or record.get('v2_rule') or '',
                    report_evidence=finding.get('evidence') or (finding.get('trace') or {}).get('steps') or [],
                    report_explanation=record.get('v2_explanation', '')))
        if record.get('v2_outcome') in ('INDETERMINATE', 'ERROR') or record.get('v2_errors'):
            limitations.append({'rule': context.get('rule_title') or record.get('v2_rule_id'),
                                'file': context.get('file_path', ''), 'outcome': record.get('v2_outcome'),
                                'reason': record.get('v2_explanation') or record.get('v2_errors')})
    # Baseline rules can emit many locations with identical predicate evidence.
    # Keep every location, but print each identical predicate once per rule/file.
    grouped = {}
    compact = []
    for finding in rdl_findings:
        if finding['report_kind'] != 'baseline':
            compact.append(finding)
            continue
        key = (finding.get('report_rule_id') or finding['rule_title'], finding['report_path'])
        if key not in grouped:
            group = dict(finding, report_evidence=[], report_locations=[])
            grouped[key] = (group, set())
            compact.append(group)
        group, evidence_seen = grouped[key]
        group['report_locations'].append({'location': finding.get('location') or {'path': finding['report_path']},
                                           'severity': finding.get('severity'),
                                           'message': finding.get('message') or finding.get('description') or ''})
        if _rank(finding) < _rank(group):
            group['severity'] = finding.get('severity')
        for step in finding['report_evidence']:
            identity = sha256(json.dumps(step, sort_keys=True).encode()).digest()
            if identity not in evidence_seen:
                evidence_seen.add(identity)
                group['report_evidence'].append(step)
    rdl_finding_count = len(rdl_findings)
    rdl_findings = compact
    excerpt_files = {}
    for finding in rdl_findings:
        linked = []
        for step in finding['report_evidence']:
            step = dict(step)
            rows = _rows(step.get('snippet', []))
            if rows:
                path = str((step.get('location') or {}).get('path') or finding['report_path'])
                if path not in excerpt_files:
                    excerpt_files[path] = {'id': 'evidence-file-' + str(len(excerpt_files)+1), 'path': path, 'rows': {}}
                entry = excerpt_files[path]
                for row in rows:
                    key = (row.get('line'), row.get('text', row.get('code', '')))
                    if key not in entry['rows']:
                        entry['rows'][key] = dict(row, text=key[1], anchor=entry['id'] + '-line-' + str(len(entry['rows'])+1))
                    elif row.get('highlight'):
                        entry['rows'][key]['highlight'] = True
                    if row.get('line') == (step.get('location') or {}).get('line'):
                        step['report_excerpt'] = entry['rows'][key]['anchor']
                step.setdefault('report_excerpt', entry['id'])
            linked.append(step)
        finding['report_evidence'] = linked
    evidence_sources = []
    for entry in excerpt_files.values():
        evidence_sources.append(dict(entry, rows=sorted(entry['rows'].values(), key=lambda r: (r.get('line') or 0))))
    xref = sections.get('rdl_cross_references') or {}
    suppressed = []
    companions = {(entry.get('id'), entry.get('file'), entry.get('line')): entry.get('explanation')
                  for entry in document.get('suppression_explanations', [])}
    for row in _rows(sections.get('suppressed_findings', [])):
        row = dict(row)
        if companions.get((row.get('id'), row.get('file'), row.get('line'))):
            row['suppression_explanation'] = companions[(row.get('id'), row.get('file'), row.get('line'))]
        source = str(row.get('suppression_source') or row.get('logic_source') or row.get('rdl_condition') or '')
        engine = str(row.get('suppression_engine') or row.get('logic_engine') or '')
        version = (re.search(r'v?([12])', str(row.get('suppression_version') or row.get('logic_version') or ''))
                   or re.search(r'rdl[ _-]?v?([12])', engine, re.I)
                   or re.search(r'/rdl/v([12])/', source.replace('\\', '/'))
                   or re.search(r'^\s*VERSION\s+([12])\b', row.get('rdl_text', ''), re.M))
        label = 'Pattern Rules' if engine == 'pattern' else 'RDL v' + version[1] if version else (engine or 'Engine not recorded')
        from core.evidence_highlights import highlighted_html
        enabled = str((row.get('scan_config') or {}).get('highlight_enabled', True)).lower() not in {'false', '0', 'no'}
        code_html = Markup(highlighted_html(row.get('code', ''), row.get('highlights', []) if enabled else []))
        suppressed.append(dict(row, report_engine=label, report_source=source, report_code_html=code_html))
    semantic_vectors, semantic_flows, semantic_references = [], [], []
    vector_seen, path_seen, edge_seen = set(), set(), set()
    from core.rdl.review_views import flow_traits
    for index, finding in enumerate(rdl_findings, 1):
        finding['anchor'] = f'rdl-lead-{index}'
        traits = flow_traits(finding)
        if traits['taint'] and traits['path_key'] not in path_seen:
            path_seen.add(traits['path_key'])
            steps = [step for step in finding['report_evidence'] if step.get('matched') is not False
                     and step.get('predicate') in {'SOURCE', 'PROPAGATION', 'SINK'}]
            flow = dict(finding, anchor=f'rdl-flow-{len(semantic_flows)+1}', report_steps=steps,
                        report_complete=traits['complete'], finding_anchor=finding['anchor'])
            semantic_flows.append(flow)
            for previous, step in zip(steps, steps[1:]):
                before, after = previous.get('location') or {}, step.get('location') or {}
                transition = step.get('transition') or ''
                if before.get('path') and after.get('path') and (before['path'] != after['path'] or transition in {'argument-parameter', 'return-call'}):
                    identity = json.dumps([before, after, transition, previous.get('symbol'), step.get('symbol')], sort_keys=True)
                    if identity not in edge_seen:
                        edge_seen.add(identity)
                        semantic_references.append(dict(before=previous, after=step, transition=transition, flow_anchor=flow['anchor']))
        for step in finding['report_evidence']:
            if step.get('predicate') != 'SOURCE' or step.get('matched') is False:
                continue
            identity = json.dumps([step.get('location'), step.get('symbol')], sort_keys=True)
            if identity not in vector_seen:
                vector_seen.add(identity)
                semantic_vectors.append(dict(step, finding_anchor=finding['anchor'], finding_title=finding.get('title') or finding['rule_title']))
    report = document.get('report', 'Full scan')
    severity_names = ['Critical', 'High', 'Medium', 'Low', 'Info', 'Not rated']
    def severity_counts(items):
        counts = Counter(severity_names[_rank(row)] for row in items)
        total = len(items)
        return [dict(label=name, count=counts[name], percent=round(100 * counts[name] / total, 2) if total else 0)
                for name in severity_names]
    for finding in rdl_findings:
        if finding.get('assessment') == 'confirmed':
            loc = finding.get('location') or {}
            assessments.append(dict(finding, file=loc.get('path') or finding.get('report_path'), line=loc.get('line'),
                                    status='confirmed', issue_description=finding.get('description'),
                                    security_impact=finding.get('impact'), recommendation=finding.get('remediation')))
    review_summary = dict(native_severities=severity_counts(assessments),
                          rdl_severities=severity_counts(rdl_findings),
                          native_assessments=len(assessments), rdl_groups=len(rdl_findings),
                          rdl_locations=rdl_finding_count, native_flows=len(flows),
                          semantic_flows=len(semantic_flows), coverage_limits=len(limitations),
                          suppressed=len(suppressed), symbols=len(xref.get('symbols', [])),
                          calls=len(xref.get('calls', [])))
    from core.rdl.program_graphs import report_views, graph_svg
    program_graph_catalog = sections.get('program_graphs') or {}
    program_graph_views = report_views(program_graph_catalog)
    for view in program_graph_views:
        view['svg'] = Markup(graph_svg(view)) if view.get('nodes') else ''
    from utils.report_audience import normalize_audience, filter_guidance
    audience = normalize_audience(document.get('report_audience'))
    return filter_guidance(dict(report_scope=report, report_scan=document.get('scan', {}), analysis_targets=targets,
                report_audience=audience, show_developer_guidance=audience != 'code_review', show_reviewer_guidance=audience != 'developer',
                review_summary=review_summary, rdl_assessment_counts={key: len(value) for key, value in assessment_groups.items()},
                analysis_flows=flows, vulnerabilities=assessments, mitigations=mitigations, manual_reviews=manual,
                attack_vectors=vectors, semantic_vectors=semantic_vectors, semantic_flows=semantic_flows,
                semantic_references=semantic_references, flow_references=references, rdl_findings=rdl_findings, rdl_assessments=[item for item in rdl_findings if item.get('assessment') == 'manual'],
                evidence_sources=evidence_sources, rdl_finding_count=rdl_finding_count, rdl_outcomes=dict(Counter(r.get('v2_outcome', 'Unknown') for r in records)),
                review_limitations=limitations, cross_reference=xref, suppressed=suppressed,
                program_graph_catalog=program_graph_catalog, program_graph_views=program_graph_views,
                recon=sections.get('recon') or {},
                recon_report=recon_presentation(sections.get('recon')),
                extra_sections={k: v for k, v in sections.items() if k not in {
                    'summary', 'areas_of_interest', 'filepaths_aoi', 'filepaths', 'analysis', 'recon',
                    'suppressed_findings', 'rdl_review_evidence', 'rdl_cross_references', 'program_graphs'}},
                show_findings=report not in ('Advanced analysis', 'Suppressed findings'),
                show_analysis=report in ('Full scan', 'Advanced analysis'),
                show_suppressed=report in ('Full scan', 'Suppressed findings')), audience)


def _flow_graph_script():
    asset = Path(__file__).resolve().parent.parent / 'resources' / 'analysis-ui' / 'flow-graph.js'
    return asset.read_text(encoding='utf-8').replace('</script', '<\\/script') if asset.is_file() else ''


def render_document(document, destination, fmt='html', title=None, progress=None):
    document = prepare_document(document)
    from core.report_progress import report_progress
    report_progress(progress, 'building', 'Preparing report sections')
    from core import reports
    destination = Path(destination)
    sections = document.get('sections', {})
    context = reports._build_pdf_report_context(document=document)
    from utils.report_audience import filter_guidance
    context = filter_guidance(context, document['report_audience'])
    if title:
        context['reportTitle'] = title
    if fmt == 'pdf':
        from core.report_pdf import render_pdf
        return render_pdf(context, destination, progress=progress)
    from jinja2 import Environment, FileSystemLoader
    import state.runtime_state as state
    context.update(reportDate=context['report_date'],
                   snippets=safe_snippets(reports.get_areas_of_interest(None, raw=sections.get('areas_of_interest') or [])),
                   filepaths=context['all_filepaths'], filepaths_aoi=context['parsed_paths_aoi'],
                   platform_counts={p['name']: p['count'] for p in context['platform_sections']},
                   total_findings=sum(p['count'] for p in context['platform_sections']))
    script = _flow_graph_script()
    context.update(report_graph_enabled=bool(script), report_graph_script=script)
    env = Environment(loader=FileSystemLoader(state.htmltemplates_dir), autoescape=True)
    from utils.guidance_format import guidance_html
    env.filters['guidance'] = guidance_html
    destination.parent.mkdir(parents=True, exist_ok=True)
    report_progress(progress, 'building', 'Rendering HTML report')
    destination.write_text(env.get_template('report_modern.html').render(**context), encoding='utf-8')
    return destination


def render_html_package(document, destination, page_size=200, progress=None):
    """Render an offline index and bounded detail pages with bidirectional links."""
    original_document = document
    document = prepare_document(document)
    import os
    from core.report_progress import report_progress
    report_progress(progress, 'building', 'Preparing HTML report sections')
    from jinja2 import Environment, FileSystemLoader
    from core import reports
    import state.runtime_state as state
    destination = Path(destination)
    root = destination.parent
    detail = root / (destination.stem + '-files')
    detail.mkdir(parents=True, exist_ok=True)
    context = reports._build_pdf_report_context(document=document)
    from utils.report_audience import filter_guidance
    context = filter_guidance(context, document['report_audience'])
    context.update(reportDate=context['report_date'],
                   snippets=safe_snippets(reports.get_areas_of_interest(None, raw=document.get('sections', {}).get('areas_of_interest') or [])),
                   filepaths=context['all_filepaths'], filepaths_aoi=context['parsed_paths_aoi'])
    env = Environment(loader=FileSystemLoader(state.htmltemplates_dir), autoescape=True)
    from utils.guidance_format import guidance_html
    env.filters['guidance'] = guidance_html
    template = env.get_template('report_modern.html')
    script = _flow_graph_script()
    graph_asset = detail / 'flow-graph.js'
    if script:
        graph_asset.write_text(script, encoding='utf-8')
    context.update(report_graph_enabled=bool(script))
    specs = []
    def add(key, label, fields, enabled=True):
        if not enabled:
            return
        size = max([len(context.get(field, [])) for field in fields] or [0])
        count = max(1, (size + page_size - 1) // page_size)
        paths = [detail / (key + (f'-{i+1}' if i else '') + '.html') for i in range(count)]
        specs.append(dict(key=key, label=label, fields=fields,
                          count=sum(len(context.get(field, [])) for field in fields) if fields else 'Available', paths=paths))
    # Flatten platform groups for bounded finding pages; preserve all evidence per rule.
    aoi = [(platform, row) for platform, rows in context['snippets'].items() for row in rows]
    context['aoi_rows'] = aoi
    add('findings', 'Areas of Interest', ['aoi_rows'], context['show_findings'])
    add('paths-aoi', 'Path Areas of Interest', ['filepaths_aoi'], context['show_findings'])
    add('paths-all', 'File Inventory', ['filepaths'], context['show_findings'])
    add('analysis-overview', 'Analysis Overview', ['analysis_targets'], context['show_analysis'])
    context['rdl_assessments'] = context['rdl_findings']
    add('vulnerabilities', 'Vulnerabilities & Mitigations', ['vulnerabilities', 'mitigations', 'manual_reviews', 'rdl_assessments'], context['show_analysis'])
    add('attack-vectors', 'Attack Vectors', ['attack_vectors', 'semantic_vectors'], context['show_analysis'])
    add('taint-flows', 'Taint & Data Flows', ['analysis_flows', 'semantic_flows'], context['show_analysis'])
    graph = context['cross_reference']
    context['xref_symbols'] = graph.get('symbols', [])
    context['xref_calls'] = graph.get('calls', [])
    add('cross-references', 'Cross References', (['xref_symbols', 'xref_calls'] if graph else ['flow_references']) + ['semantic_references'], context['show_analysis'])
    add('rdl-evidence', 'RDL Review Evidence', ['rdl_findings', 'review_limitations'], context['show_analysis'])
    add('source-evidence', 'Saved Source Evidence', ['evidence_sources'], context['show_analysis'])
    add('program-graphs', 'CFG & DFG', ['program_graph_views'], context['show_analysis'] and bool(context['program_graph_catalog']))
    add('suppressed-findings', 'Suppressed Findings', ['suppressed'], context['show_suppressed'])
    add('reconnaissance', 'Reconnaissance', [], bool(context['recon']))
    extra_pages = {}
    for index, (key, value) in enumerate(context['extra_sections'].items(), 1):
        page_key = f'additional-{index}'
        add(page_key, key.replace('_', ' ').title(), [])
        extra_pages[page_key] = {key: value}
    # Section/record anchors resolve across files, including paginated flows/excerpts.
    anchors = {'overview': destination, 'inputs': destination, 'timeline': destination}
    for spec in specs:
        anchors[spec['key']] = spec['paths'][0]
        for field in spec['fields']:
            for index, row in enumerate(context[field]):
                if not isinstance(row, dict):
                    continue
                path = spec['paths'][index // page_size]
                for key in (('id',) if field == 'evidence_sources' else (() if field == 'rdl_assessments' else ('anchor',))):
                    if row.get(key):
                        anchors[str(row[key])] = path
                for line in row.get('rows', []):
                    if line.get('anchor'):
                        anchors[line['anchor']] = path
    total_pages = 1 + sum(len(spec['paths']) for spec in specs)
    completed_pages = 0
    report_progress(progress, 'building', 'Writing saved results for the HTML package')
    data = detail / 'saved-results.json'
    data.write_text(json.dumps(filter_guidance(original_document, document['report_audience']), ensure_ascii=True), encoding='utf-8')
    def relative(path, current):
        return Path(os.path.relpath(path, current.parent)).as_posix()
    def write(path, key, page_context, pagination=None):
        nonlocal completed_pages
        report_progress(progress, 'building', 'Building ' + page_context['report_page_title'], completed_pages, total_pages, 'pages')
        pages = [dict(label=s['label'], count=s['count'], href=relative(s['paths'][0], path)) for s in specs]
        page_context.update(report_graph_enabled=bool(script) and key in {'taint-flows','cross-references','rdl-evidence','program-graphs'}, report_graph_asset=relative(graph_asset, path) if script else None, report_pages=pages, report_home=relative(destination, path), report_data=relative(data, path),
                            report_pagination=pagination or [], page_sections={key},
                            platform_counts={}, total_findings=len(aoi), extra_sections=extra_pages.get(key, {}),
                            extra_section_id=key)
        html = template.render(**page_context)
        def link(match):
            anchor = match[1]
            target = anchors.get(anchor)
            return 'href="' + ((relative(target, path) if target != path else '') + '#' + anchor if target else '#' + anchor) + '"'
        html = re.sub(r'href="#([^"\s]+)"', link, html)
        path.write_text(html, encoding='utf-8')
        completed_pages += 1
        report_progress(progress, 'building', 'Building HTML detail pages', completed_pages, total_pages, 'pages')
    write(destination, 'overview', dict(context, report_page_title='Summary & Index'))
    outputs = [destination, data] + ([graph_asset] if script else [])
    for spec in specs:
        for index, path in enumerate(spec['paths']):
            current = dict(context, report_page_title=spec['label'])
            for field in spec['fields']:
                current[field] = context[field][index*page_size:(index+1)*page_size]
            if spec['key'] == 'findings':
                current['snippets'] = {}
                for platform, row in current['aoi_rows']:
                    current['snippets'].setdefault(platform, []).append(row)
            if spec['key'] == 'cross-references':
                current['cross_reference'] = dict(graph, symbols=current['xref_symbols'], calls=current['xref_calls']) if graph else {}
            pagination = None
            if len(spec['paths']) > 1:
                pagination = dict(current=index+1, total=len(spec['paths']),
                                  options=[dict(number=i+1, href=relative(p, path)) for i,p in enumerate(spec['paths'])],
                                  previous=relative(spec['paths'][index-1], path) if index else None,
                                  next=relative(spec['paths'][index+1], path) if index+1 < len(spec['paths']) else None,
                                  first=relative(spec['paths'][0], path) if index else None,
                                  last=relative(spec['paths'][-1], path) if index+1 < len(spec['paths']) else None,
                                  total_items=spec['count'], page_items=sum(len(current[field]) for field in spec['fields']),
                                  start=index*page_size+1 if len(spec['fields']) == 1 else None,
                                  end=min((index+1)*page_size, spec['count']) if len(spec['fields']) == 1 else None)
            write(path, spec['key'], current, pagination)
            outputs.append(path)
    return outputs
