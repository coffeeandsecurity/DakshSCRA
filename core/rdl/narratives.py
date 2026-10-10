"""Keep issue observations, security consequences, and corrective actions separate."""
import json
from functools import lru_cache
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


@lru_cache(maxsize=8)
def _load(root, signatures):
    root = Path(root)
    semantic = json.loads((root / 'config/rdl_semantic_guidance.json').read_text())['entries']
    by_path, by_id = {}, {}
    for name in ('rdl_baseline.json', 'rdl_additional.json'):
        for entry in json.loads((root / 'config' / name).read_text())['entries']:
            narrative = {field: entry.get(field, '') for field in ('description', 'impact', 'remediation')}
            by_path[entry['v2_rule']] = narrative
            by_id[entry['rule_id']] = narrative
    by_id.update(semantic)
    return by_path, by_id


def catalogs(root=ROOT):
    root = Path(root)
    names = ('rdl_baseline.json', 'rdl_additional.json', 'rdl_semantic_guidance.json')
    signatures = tuple((root / 'config' / name).stat().st_mtime_ns for name in names)
    return _load(str(root), signatures)


def narrative_for(rule_id, rule_path=None, root=ROOT):
    by_path, by_id = catalogs(root)
    return by_path.get(str(rule_path), by_id.get(rule_id, {}))


def refresh_record(record):
    """Update display text on decoded copies; persisted evidence stays untouched."""
    narrative = narrative_for(record.get('v2_rule_id'), record.get('v2_rule'))
    if not narrative:
        return
    for finding in record.get('v2_findings') or []:
        # Source refinements narrow an observation, not its security consequence.
        from .source_review import GUIDANCE
        stem = str(record.get('v2_rule_id', '')).rsplit('.', 1)[-1]
        refinement = GUIDANCE.get(stem)
        if refinement and finding.get('title') != refinement[0]:
            refinement = None
        finding.update({field: value for field, value in narrative.items()
                        if field in {'description', 'impact', 'remediation'} and value})
        if refinement:
            finding['description'] = refinement[1]
            finding['reviewer_note'] = refinement[2]


def enrich_source_findings(items, root=ROOT, path_only=False):
    """Resolve legacy identities by pack and title, never by loose title keywords."""
    by_path, _ = catalogs(root)
    entries = json.loads((Path(root) / 'config/rdl_baseline.json').read_text())['entries']
    index = {}
    for entry in entries:
        if bool(entry['path_rule']) == path_only:
            key = (Path(entry['xml_pack']).stem.casefold(), entry['title'])
            index[key] = by_path[entry['v2_rule']]
    result = []
    for item in items:
        if not isinstance(item, dict):
            result.append(item)
            continue
        copy = dict(item)
        key = ('filepaths' if path_only else str(item.get('platform', '')).casefold(), item.get('rule_title'))
        narrative = index.get(key)
        if narrative:
            if path_only:
                copy.update(brief_desc=narrative['description'], attack_desc=narrative['impact'],
                            developer_note=narrative['remediation'])
            else:
                copy.update(issue_desc=narrative['description'], security_impact=narrative['impact'],
                            developer_note=narrative['remediation'])
        result.append(copy)
    return result


@lru_cache(maxsize=2)
def _analysis_guidance(signature):
    return json.loads((ROOT / 'config/analysis_finding_guidance.json').read_text())['entries']


def enrich_vulnerability(item):
    path = ROOT / 'config/analysis_finding_guidance.json'
    narrative = _analysis_guidance(path.stat().st_mtime_ns).get(item.get('kind'))
    return {**item, **({'issue_description': narrative['description'],
                       'security_impact': narrative['impact'],
                       'recommendation': narrative['remediation']} if narrative else {})}


def enrich_analysis(data):
    if not isinstance(data, dict):
        return data
    result = dict(data)
    if isinstance(data.get('results'), list):
        result['results'] = [enrich_analysis(entry) for entry in data['results']]
    if isinstance(data.get('security_inventory'), dict):
        inventory = dict(data['security_inventory'])
        inventory['vulnerabilities'] = [enrich_vulnerability(item) for item in inventory.get('vulnerabilities', [])]
        result['security_inventory'] = inventory
    return result
