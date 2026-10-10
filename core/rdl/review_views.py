"""Purpose-specific navigation over recorded findings, paths, handoffs and inputs."""
import json


def finding_identity(record, finding):
    return json.dumps([record.get('v2_rule_id') or record.get('v2_rule'),
                      finding.get('location'), finding.get('path') or record.get('context', {}).get('file_path'),
                      finding.get('evidence') or (finding.get('trace') or {}).get('steps', [])], sort_keys=True)


def location_key(location):
    location = location or {}
    return [location.get('path') or '', location.get('line'), location.get('column'),
            location.get('end_line'), location.get('end_column')]


def symbol(step):
    return step.get('symbol') or step.get('explanation') or ''


def flow_traits(finding):
    evidence = finding.get('evidence') or (finding.get('trace') or {}).get('steps') or []
    steps = [item for item in evidence if item.get('matched') is not False
             and item.get('predicate') in {'SOURCE', 'PROPAGATION', 'SINK'}]
    sources = [item for item in steps if item.get('predicate') == 'SOURCE']
    sinks = [item for item in steps if item.get('predicate') == 'SINK']
    edges = []
    if sources:
        for previous, current in zip(steps, steps[1:]):
            before, after = previous.get('location') or {}, current.get('location') or {}
            transition = current.get('transition') or ''
            if not before.get('path') or not after.get('path'):
                continue
            if before['path'] != after['path'] or transition in {'argument-parameter', 'return-call'}:
                edges.append(json.dumps([location_key(before), symbol(previous), location_key(after), symbol(current), transition]))
    return dict(taint=bool(sources), complete=bool(sources and sinks), xref=bool(edges), sources=sources,
                edges=edges, path_key=json.dumps([[step['predicate'], location_key(step.get('location')),
                                                  symbol(step), step.get('transition') or ''] for step in steps]))


def review_sections(records, section='all'):
    """Count distinct entities before paging and select matching findings only."""
    counts = dict(findings=0, taint=0, complete=0, partial=0, xref=0, vectors=0)
    seen, paths, edges, vectors, selected = set(), {}, set(), set(), []
    for record in records:
        findings = []
        for finding in record.get('v2_findings') or []:
            if record.get('v2_outcome') != 'MATCH':
                continue
            identity = finding_identity(record, finding)
            traits = flow_traits(finding)
            if identity not in seen:
                seen.add(identity)
                counts['findings'] += 1
                if traits['taint']:
                    paths[traits['path_key']] = traits['complete']
                edges.update(traits['edges'])
                for source in traits['sources']:
                    vectors.add(json.dumps([location_key(source.get('location')), symbol(source)]))
            if section in {'all', 'findings'} or traits.get('taint' if section == 'vectors' else section):
                findings.append(finding)
        if section == 'all':
            selected.append(record)
        elif findings or (section == 'findings' and record.get('v2_outcome') == 'MATCH'):
            selected.append(dict(record, v2_findings=findings))
    counts.update(taint=len(paths), complete=sum(paths.values()), partial=sum(not value for value in paths.values()),
                  xref=len(edges), vectors=len(vectors))
    return selected, counts
