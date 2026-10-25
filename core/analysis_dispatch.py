from utils.scan_scope import walk_source, allows_file
from pathlib import Path
import os
import json
import hashlib


def observation_digest(finding):
    payload = {key: value for key, value in finding.items()
               if key not in {'id', 'target', 'platform', 'framework', 'review_status'}}
    digest = hashlib.sha256()
    for chunk in json.JSONEncoder(sort_keys=True, ensure_ascii=False).iterencode(payload):
        digest.update(chunk.encode('utf-8'))
    return digest.digest()


def unique_observation_count(results):
    """Count evidence once when framework views inherit platform findings."""
    return len({observation_digest(finding) for result in results
                for finding in result.get('findings', []) if isinstance(finding, dict)})


def project_language_hints(source_root):
    root = Path(source_root)
    counts = {
        "java": 0,
        "kotlin": 0,
        "javascript": 0,
        "dotnet": 0,
    }
    if not root.exists():
        return counts

    languages = {
        ".java": "java", ".kt": "kotlin",
        ".js": "javascript", ".jsx": "javascript",
        ".ts": "javascript", ".tsx": "javascript",
        ".cs": "dotnet", ".vb": "dotnet",
        ".aspx": "dotnet", ".cshtml": "dotnet",
    }
    # Walk once: repeated glob discovery is expensive on mounted source trees.
    # As with rglob, do not descend into directory symlinks.
    for _, _, names in walk_source(root, followlinks=False):
        for name in names:
            language = languages.get(Path(name).suffix)
            if language:
                counts[language] += 1
    return counts


def resolve_analysis_target(platform, alias_map, analyzers, language_hints):
    platform_key = str(platform or "").strip().lower()
    canonical = alias_map.get(platform_key, platform_key)
    runner = analyzers.get(canonical)
    if runner:
        return canonical, runner

    if platform_key == "android":
        kotlin_count = int(language_hints.get("kotlin", 0) or 0)
        java_count = int(language_hints.get("java", 0) or 0)
        if kotlin_count and kotlin_count >= java_count and analyzers.get("kotlin"):
            return "kotlin", analyzers.get("kotlin")
        if java_count and analyzers.get("java"):
            return "java", analyzers.get("java")
        if kotlin_count and analyzers.get("kotlin"):
            return "kotlin", analyzers.get("kotlin")

    return canonical, None


def inherited_analysis_state(parent, has_findings):
    if parent and parent.get('status') == 'failed':
        return {'status': 'failed', 'error': parent.get('error', 'Parent analyzer failed')}
    return {'status': 'completed' if has_findings else 'no_findings'}


def analysis_failure_message(payload):
    """Keep saved partial results, but do not report failed targets as success."""
    failed = [item for item in payload.get('results', []) if item.get('status') == 'failed']
    if failed:
        return 'Analyzer targets failed: ' + '; '.join(
            '{}: {}'.format(item.get('platform', 'unknown'), item.get('error') or 'analysis failed')
            for item in failed)
    count = int(payload.get('summary', {}).get('targets_failed', 0) or 0)
    return '{} analyzer target(s) failed'.format(count) if count else ''


def analyzer_exception_message(error):
    """Blank exception messages must still identify an incomplete analyzer run."""
    message = str(error).strip()
    return '{}: {}'.format(type(error).__name__, message) if message else type(error).__name__
