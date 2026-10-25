"""Persisted input and bounded flow inventory, independent of rule verdicts."""
import hashlib
import inspect
import re
import time
from dataclasses import asdict, replace
from pathlib import Path

from .cache import AnalysisBudgetExceeded
from .portable_flow import Walker, build_project_flow
from .portable_profiles import EXTENSIONS, SINKS
from .review_views import review_sections


def build_inventory(root, files, max_seconds=30, max_paths=2000):
    root = Path(root).resolve()
    started = time.monotonic()
    profiles, notes, records, contents = {}, [], [], {}
    def priority(item):
        path = item['path'].lower()
        return (0 if '/controllers/' in '/' + path or '/handlers/' in '/' + path else 1, item['path'])
    for item in sorted(files, key=priority):
        path = (root / item['path']).resolve()
        if root not in path.parents:
            notes.append(item['path'] + ': outside source scope')
            continue
        if time.monotonic() - started > max_seconds * 0.6:
            notes.append('Input inventory parse time budget reached; remaining files are not analyzed'); break
        try:
            raw = path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != item['sha256']:
                notes.append(item['path'] + ': source changed during analysis'); continue
            contents[item['path']] = raw.decode('utf-8-sig').splitlines()
            from .mobile_inputs import input_records
            for record in input_records(item['path'], raw.decode('utf-8-sig')):
                if len(records) >= max_paths:
                    notes.append('Input/flow record budget reached; remaining mobile UI inputs are not displayed')
                    break
                records.append(record)
            language = item['language']
            if path.suffix.lower() in {'.jsp', '.erb', '.cshtml', '.aspx', '.asp', '.phtml'}:
                notes.append(item['path'] + ': template flow analysis unavailable'); continue
            if language in EXTENSIONS:
                ir = Walker(path, language, source=raw.decode('utf-8-sig'), max_tokens=100000).parse()
            elif language == 'php':
                from .adapters.tokenized import PHPAdapter
                ir = PHPAdapter().parse_file(path)
            elif language == 'python':
                from .adapters.python import PythonAdapter
                ir = PythonAdapter().parse_file(path)
            else:
                notes.append(item['path'] + ': input flow profile unavailable'); continue
            profiles.setdefault(language, []).append(ir)
        except (OSError, UnicodeError, ValueError, RecursionError, AnalysisBudgetExceeded) as exc:
            notes.append(item['path'] + ': ' + str(exc))
    for language, parts in profiles.items():
        ir = replace(parts[0], entities=tuple(e for p in parts for e in p.entities), edges=tuple(e for p in parts for e in p.edges))
        remaining = max(0, max_seconds - (time.monotonic() - started))
        if remaining <= 0:
            from .flow import DataFlowGraph
            graph = DataFlowGraph({e.entity_id: e for e in ir.entities}, ())
            notes.append('Project flow time budget reached; identified inputs retained without propagation')
        elif language == 'php':
            from .php_flow import PHPDataFlowProvider
            graph = PHPDataFlowProvider().build(root, ir)
        elif language == 'python':
            notes.append('Python input inventory uses intraprocedural flow; cross-file propagation requires rule evidence')
            from .flow import PythonDataFlowProvider
            graph = PythonDataFlowProvider().build(root, ir)
        else:
            if 'max_seconds' in inspect.signature(build_project_flow).parameters:
                graph, limits = build_project_flow(ir, max_seconds=remaining)
            else:
                graph, limits = build_project_flow(ir)
                notes.append('Earlier running scan flow resolver; refresh analysis after scanner reload')
            notes.extend(limits)
        sources = [e for e in graph.entities.values() if 'input.untrusted' in e.concepts]
        sinks = [e for e in graph.entities.values() if bool(e.concepts.intersection(SINKS))]
        terminals = [e for e in graph.entities.values() if e.entity_id not in graph.adjacency and e.attribute('role') != 'coverage']
        for source in sources:
            if len(records) >= max_paths:
                notes.append('Input/flow record budget reached; remaining inputs are not displayed'); break
            paths = []
            try:
                for sink in sinks if time.monotonic() - started <= max_seconds else []:
                    if time.monotonic() - started > max_seconds: raise AnalysisBudgetExceeded('Input/flow time budget reached')
                    path = graph.find_path(source.entity_id, sink.entity_id)
                    if path: paths.append(path)
                    if len(paths) >= 50:
                        notes.append('Destination limit reached for ' + source.name); break
                if not paths and time.monotonic() - started <= max_seconds:
                    # A bounded, balanced recorded prefix is useful even without a sink.
                    candidates = []
                    if len(terminals) > 500: notes.append('Partial path destination budget reached')
                    for target in terminals[:500]:
                        if time.monotonic() - started > max_seconds: raise AnalysisBudgetExceeded('Input/flow time budget reached')
                        path = graph.find_path(source.entity_id, target.entity_id)
                        if path: candidates.append(path)
                    if candidates: paths = [max(candidates, key=lambda p: len(p.entity_ids))]
            except AnalysisBudgetExceeded as exc:
                notes.append(str(exc))
            if not paths:
                if time.monotonic() - started > max_seconds: notes.append('Propagation time budget reached; identified inputs retained as partial paths')
                paths = [None]
            for path in paths:
                steps = []
                ids = path.entity_ids if path else (source.entity_id,)
                for i, entity_id in enumerate(ids):
                    entity = graph.entities[entity_id]
                    location = asdict(entity.location)
                    location['path'] = Path(location['path']).relative_to(root).as_posix()
                    predicate = 'SOURCE' if i == 0 else 'SINK' if bool(entity.concepts.intersection(SINKS)) else 'PROPAGATION'
                    origin = ''
                    if predicate == 'SOURCE':
                        if language in {'java', 'csharp'} and entity.attribute('role') == 'parameter':
                            origin = 'request_parameter' if language == 'csharp' or re.search(r'@(RequestParam|RequestBody|PathVariable|ModelAttribute)\b', contents[location['path']][location['line']-1]) else ''
                        elif language == 'go':
                            name = entity.qualified_name or entity.name
                            origin = 'cookie' if re.search(r'\.Cookies?$', name) else 'body' if '.Body' in name else 'header' if '.Header' in name else 'query' if '.RawQuery' in name or '.FormValue' in name else 'form' if '.Form' in name else ''
                        elif language == 'javascript' and (entity.qualified_name or entity.name) == 'route.params':
                            from .source_review import source_views
                            source_text = '\n'.join(contents[location['path']])
                            comments, code = source_views(location['path'], source_text)
                            if any(code[hit.start():hit.start()+6] == 'import' for hit in re.finditer(r'\bimport\s+[^;]*?\s+from\s*["\'](?:react-native|@react-navigation/[^"\']+)["\']', comments)):
                                origin = 'mobile_navigation'
                    steps.append(dict(predicate=predicate, matched=True, symbol=entity.qualified_name or entity.name,
                                      location=location, transition=path.edge_kinds[i-1] if i and path else '',
                                      snippet=[dict(line=n+1, text=contents[location['path']][n], highlight=n+1 == location['line']) for n in range(max(0, location['line']-3), min(len(contents[location['path']]), location['line']+2))],
                                      input_origin=origin,
                                      concepts=sorted(entity.concepts), explanation='Recorded ' + predicate.lower()))
                finding = dict(title='Recorded input path', location=steps[0]['location'], evidence=steps,
                               trace=dict(steps=steps, review_note='Recorded structural input and propagation evidence; no vulnerability verdict is implied.', protection_note='Validation, sanitization and external reachability require review. A complete path does not establish exploitability.'), severity='INFO', analysis_only=True)
                records.append(dict(v2_rule_id='input-flow-inventory', v2_outcome='RECORDED', analysis_only=True,
                                    comparison_kind='semantic', context=dict(file_path=steps[0]['location']['path']), v2_findings=[finding]))
                if len(records) >= max_paths: break
    # Keep a structural path when the same located UI source was also retained
    # by the bounded fallback; transfer its typed origin without duplicating it.
    def source_key(record):
        loc = record['v2_findings'][0]['location']
        return (str(loc['path']).replace(root.as_posix()+'/', ''), loc.get('line'), loc.get('column'))
    structural = {source_key(record): record for record in records if record.get('v2_rule_id') == 'input-flow-inventory'}
    retained = []
    for record in records:
        other = structural.get(source_key(record)) if record.get('v2_rule_id') == 'mobile-input-inventory' else None
        if other:
            for step in other['v2_findings'][0]['trace']['steps']:
                if step.get('predicate') == 'SOURCE':
                    step['input_origin'] = record['v2_findings'][0]['evidence'][0]['input_origin']
            continue
        retained.append(record)
    records = retained
    notes = sorted(set(str(n).replace(root.as_posix() + '/', '') for n in notes))
    return dict(version=1, records=records, diagnostics=notes[:200], diagnostic_count=len(notes))


def query_inventory(index, section='taint', search='', kind='all', offset=0, limit=50):
    inventory = (index or {}).get('input_inventory')
    index_notes = list((index or {}).get('diagnostics', []))
    if (index or {}).get('truncated'): index_notes.insert(0, 'Source index budget reached; inventory covers indexed files only')
    records = (inventory or {}).get('records', [])
    needle = search.casefold()
    records = [r for r in records if kind in {'all', 'semantic'} and (not needle or needle in str(r).casefold())]
    selected, counts = review_sections(records, section)
    return dict(comparisons=selected[offset:offset+limit], section_counts=counts,
                filtered_total=len(selected), offset=offset, limit=limit, truncated=offset+limit < len(selected),
                query=dict(section=section), summary={}, needs_rebuild=inventory is None,
                diagnostic_count=(inventory or {}).get('diagnostic_count', 0) + len(index_notes),
                provenance=(index or {}).get('provenance'), diagnostics=(index_notes + (inventory or {}).get('diagnostics', []))[:200])


def read_inventory_index(runtime):
    """Prefer an explicit review rebuild while preserving the original scan index."""
    from .xref import read_index, INDEX_NAME
    paths = [Path(runtime)/'rdl_advanced_review.json', Path(runtime)/INDEX_NAME]
    available = [p for p in paths if p.is_file()]
    fallback = None
    for path in available:
        index = read_index(path)
        if index and index.get('input_inventory') is not None: return index
        if fallback is None: fallback = index
    return fallback
