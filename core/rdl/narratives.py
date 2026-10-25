"""Keep issue observations, security consequences, and corrective actions separate."""
import json
import re
from functools import lru_cache
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


from core.issue_titles import issue_title, vulnerability_title, normalize_record_titles


@lru_cache(maxsize=8)
def _load(root, signatures):
    root = Path(root)
    semantic = json.loads((root / 'resources/guidance/rdl/semantic.json').read_text())['entries']
    by_path, by_id = {}, {}
    for name in ('baseline.json', 'additional.json'):
        for entry in json.loads((root / 'rules/scanning/metadata/rdl' / name).read_text())['entries']:
            narrative = {field: entry.get(field, '') for field in ('description', 'impact', 'remediation', 'reviewer')}
            by_path[entry['v2_rule']] = narrative
            by_id[entry['rule_id']] = narrative
    by_id.update(semantic)
    from core.review_guidance import audience_guidance
    for key, narrative in [*by_path.items(), *by_id.items()]:
        narrative['remediation'], narrative['reviewer'] = audience_guidance(
            key, narrative.get('remediation', ''), narrative.get('reviewer', ''))
    return by_path, by_id


def catalogs(root=ROOT):
    root = Path(root)
    paths = ('rules/scanning/metadata/rdl/baseline.json',
             'rules/scanning/metadata/rdl/additional.json',
             'resources/guidance/rdl/semantic.json')
    signatures = tuple((root / path).stat().st_mtime_ns for path in paths)
    return _load(str(root), signatures)


def narrative_for(rule_id, rule_path=None, root=ROOT):
    by_path, by_id = catalogs(root)
    return by_path.get(str(rule_path), by_id.get(rule_id, {}))


def review_guidance(original, refinement=None):
    if not refinement or refinement in (original or ''):
        return original or ''
    return '\n\n'.join(part for part in (original, 'Additional source review: ' + refinement) if part)


def refresh_record(record):
    """Update display text on decoded copies; persisted evidence stays untouched."""
    for key in ('v2_title', 'rule_title'):
        if key in record:
            record[key] = issue_title(record[key])
    if isinstance(record.get('context'), dict) and 'rule_title' in record['context']:
        record['context'] = dict(record['context'], rule_title=issue_title(record['context']['rule_title']))
    for finding in record.get('v2_findings') or []:
        if 'title' in finding:
            finding['title'] = issue_title(finding['title'])
    narrative = narrative_for(record.get('v2_rule_id'), record.get('v2_rule'))
    if not narrative:
        return
    for finding in record.get('v2_findings') or []:
        # Source refinements narrow an observation, not its security consequence.
        from .source_review import GUIDANCE
        stem = str(record.get('v2_rule_id', '')).rsplit('.', 1)[-1]
        refinement = GUIDANCE.get(stem)
        if refinement and issue_title(finding.get('title')) != issue_title(refinement[0]):
            refinement = None
        finding.update({field: value for field, value in narrative.items()
                        if field in {'description', 'impact', 'remediation'} and value})
        if narrative.get('reviewer'):
            finding['reviewer_note'] = narrative['reviewer']
        context_note = finding.get('security_context_note')
        if context_note and context_note not in finding.get('reviewer_note',''):
            finding['reviewer_note'] = '\n\n'.join(value for value in (finding.get('reviewer_note'),context_note) if value)
        if refinement:
            finding['description'] = refinement[1]
            finding['reviewer_note'] = review_guidance(finding.get('reviewer_note'), refinement[2])
        from core.mobile_impact import mobile_impact
        finding['impact'] = mobile_impact(finding.get('impact', ''), record.get('v2_rule_id'))


def enrich_source_findings(items, root=ROOT, path_only=False):
    """Resolve exact source identities first; never infer guidance from a shared title."""
    by_path, _ = catalogs(root)
    entries = json.loads((Path(root) / 'rules/scanning/metadata/rdl/baseline.json').read_text())['entries']
    index, identities = {}, {}
    for entry in entries:
        if bool(entry['path_rule']) == path_only:
            key = (Path(entry['xml_pack']).stem.casefold(), entry['title'])
            narrative = dict(by_path[entry['v2_rule']])
            narrative['mobile_rule_id'] = entry['rule_id']
            index[key] = None if key in index else narrative
            for identity in (entry['rule_id'], entry.get('pattern_file'), entry.get('v1_ref'), entry['v2_rule']):
                if identity:
                    identities[str(identity).replace('\\', '/')] = narrative
    result = []
    for item in items:
        if not isinstance(item, dict):
            result.append(item)
            continue
        from core.issue_notes import refresh_bundled_notes
        copy = refresh_bundled_notes(item)
        if 'rule_title' in copy:
            copy['rule_title'] = issue_title(copy['rule_title'])
        key = ('filepaths' if path_only else str(item.get('platform', '')).casefold(), re.sub(r'^RDL Conditional:\s*', '', item.get('rule_title', '')) if str(item.get('rule_title', '')).startswith('RDL Conditional:') else item.get('rule_title'))
        source = str(item.get('logic_source') or '').replace('\\', '/')
        narrative = identities.get(source) or identities.get(item.get('rule_id')) or index.get(key) or index.get((key[0], issue_title(key[1])))
        if narrative:
            fields = {'brief_desc' if path_only else 'issue_desc': narrative['description'],
                      'attack_desc' if path_only else 'security_impact': narrative['impact'],
                      'developer_note': narrative['remediation'], 'reviewer_note': narrative.get('reviewer', '')}
            # Unified checks already carry their authored guidance. Catalogs enrich
            # legacy records but must not replace a newer saved rule's own notes.
            for field, value in fields.items():
                if value and not copy.get(field):
                    copy[field] = value
            # Preserve custom impact text. Only enrich the known bundled text.
            if not path_only and copy.get('security_impact') == narrative['impact']:
                from core.mobile_impact import mobile_impact
                copy['security_impact'] = mobile_impact(copy['security_impact'], narrative['mobile_rule_id'])
        from core.review_guidance import audience_guidance
        copy['developer_note'], copy['reviewer_note'] = audience_guidance(
            item.get('rule_title', ''), copy.get('developer_note', ''), copy.get('reviewer_note', ''), copy.get('category', ''))
        result.append(copy)
    return result


@lru_cache(maxsize=2)
def _analysis_guidance(signature):
    return json.loads((ROOT / 'resources/guidance/analysis/findings.json').read_text())['entries']


def enrich_vulnerability(item):
    path = ROOT / 'resources/guidance/analysis/findings.json'
    narrative = _analysis_guidance(path.stat().st_mtime_ns).get(item.get('kind'))
    result = {**item, **({'issue_description': narrative['description'],
                       'security_impact': narrative['impact'],
                       'recommendation': narrative['remediation']} if narrative else {})}
    if result.get('title') or result.get('kind'):
        result['title'] = vulnerability_title(result.get('kind'), result.get('title') or result.get('kind'))
    from core.review_guidance import audience_guidance
    result['recommendation'], result['reviewer_note'] = audience_guidance(
        item.get('title') or item.get('kind', ''), result.get('recommendation', ''), result.get('reviewer_note', ''))
    return result


def enrich_analysis(data):
    if not isinstance(data, dict):
        return data
    result = dict(data)
    if isinstance(data.get('results'), list):
        result['results'] = [enrich_analysis(entry) for entry in data['results']]
    if isinstance(data.get('security_inventory'), dict):
        inventory = dict(data['security_inventory'])
        inventory['vulnerabilities'] = [enrich_vulnerability(item) for item in inventory.get('vulnerabilities', [])]
        if 'finding_reviews' in inventory:
            inventory['finding_reviews'] = [normalize_record_titles(item) for item in inventory['finding_reviews']]
        result['security_inventory'] = inventory
    return result
