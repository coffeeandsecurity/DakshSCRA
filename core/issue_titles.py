"""Explicit cross-platform display names, independent of rule identities and evidence."""
import json
import re
from functools import lru_cache
from pathlib import Path

CATALOG = Path(__file__).resolve().parents[1] / 'resources/guidance/issue-titles.json'


@lru_cache(maxsize=1)
def _catalog():
    return json.loads(CATALOG.read_text())


def _aliases():
    return _catalog()['aliases']


def issue_title(value):
    title = str(value or '').strip()
    title = re.sub(r'^RDL(?:\s+v?[12])?(?:\s+(?:conditional|semantic|pattern|rule))?\s*(?::|[-–—])\s*', '', title, flags=re.I).strip()
    return _aliases().get(title, title)


def title_search_aliases(query):
    """Keep canonical title searches useful against older result indexes."""
    query = str(query or '').strip().casefold()
    if len(query) < 8:
        return []
    return sorted({old.casefold() for old, new in _aliases().items()
                   if new.casefold().startswith(query) and query not in old.casefold()})


def vulnerability_title(kind, title):
    if str(title or '').strip() in _aliases():
        return issue_title(title)
    return _catalog().get('kind_titles', {}).get(str(kind), issue_title(title))


def normalize_record_titles(record):
    """Normalize issue headings without touching project names or source text."""
    result = dict(record)
    for key in ('rule_title', 'v2_title'):
        if key in result:
            result[key] = issue_title(result[key])
    if 'title' in result and (any(key in result for key in ('cwe', 'severity', 'confidence', 'issue_description', 'v2_rule_id'))
                              or result.get('kind') in _catalog().get('kind_titles', {})):
        result['title'] = vulnerability_title(result.get('kind'), result['title'])
    return result


def normalize_document_titles(value):
    if isinstance(value, list):
        return [normalize_document_titles(item) for item in value]
    if isinstance(value, dict):
        from core.issue_notes import refresh_bundled_notes
        return normalize_record_titles(refresh_bundled_notes({key: normalize_document_titles(item) for key, item in value.items()}))
    return value


@lru_cache(maxsize=1)
def _rule_title_index():
    index = {}
    for owner, entry in _catalog().get('rule_title_history', {}).items():
        record = (owner, tuple(entry.get('aliases', ())), entry.get('selection_class'))
        for reference in (owner, *entry.get('references', ())):
            index[str(reference).replace('\\', '/').strip()] = record
    return index


def rule_identity(reference):
    """Resolve known aliases to one rule source without grouping by display name."""
    reference = str(reference or '').replace('\\', '/').strip()
    return _rule_title_index().get(reference, (reference, ()))[0]


def rule_title_aliases(reference):
    reference = str(reference or '').replace('\\', '/').strip()
    return _rule_title_index().get(reference, ('', ()))[1]


def rule_selection_class(reference):
    """Keep a display rename from moving a registered check between scan options."""
    reference = str(reference or '').replace('\\', '/').strip()
    return _rule_title_index().get(reference, ('', (), None))[2]
