"""Refresh unchanged bundled notes on decoded records without replacing custom text."""
import json
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def _updates():
    path = Path(__file__).resolve().parents[1] / 'resources/guidance/rule-note-updates.json'
    return json.loads(path.read_text())['entries']


def refresh_bundled_notes(item):
    result = dict(item)
    if not item.get('rule_title'):
        return result
    source = str(item.get('logic_source') or item.get('suppression_source') or '').replace('\\', '/')
    title = str(item.get('rule_title') or '')
    if title.startswith('RDL Conditional: '):
        title = title[len('RDL Conditional: '):]
    for update in _updates():
        same_source = source.endswith(update['source'])
        same_legacy_rule = not source and str(item.get('platform', '')).casefold() == update['platform'] and title == update['authored_title']
        if same_source or same_legacy_rule:
            for field, previous in update['previous'].items():
                if previous and item.get(field) == previous:
                    result[field] = update['current'][field]
            break
    return result
