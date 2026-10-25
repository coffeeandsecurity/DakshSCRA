"""Conditional attack stories, independent of recorded evidence and verdicts."""
import json
from functools import lru_cache
from pathlib import Path

CATALOG = Path(__file__).resolve().parents[1] / 'resources/guidance/mobile-attacks.json'


@lru_cache(maxsize=2)
def _scenarios(signature):
    return json.loads(CATALOG.read_text(encoding='utf-8'))['entries']


def mobile_impact(impact, rule_id):
    """Enrich known bundled rules only; never infer an attack from a shared title."""
    scenario = _scenarios(CATALOG.stat().st_mtime_ns).get(rule_id)
    if not scenario or scenario in (impact or ''):
        return impact or ''
    return '\n\n'.join(part for part in (impact, scenario) if part)
