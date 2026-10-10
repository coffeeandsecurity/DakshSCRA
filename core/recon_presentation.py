"""Readable reconnaissance views derived from saved data, without changing it."""
from collections import Counter
import re


def _count(value):
    try:
        if value is None or isinstance(value, bool):
            return None
        count = int(value)
        return count if count >= 0 else None
    except (ValueError, TypeError, OverflowError):
        return None


def _paths(value):
    return list(dict.fromkeys(str(path) for path in value if isinstance(path, str))) if isinstance(value, list) else []


def _confidence(value):
    value = str(value or '').lower()
    return value if value in ('high', 'medium', 'low') else 'not recorded'


def recon_presentation(saved):
    """Accept current summaries, legacy summaries and raw per-file detections."""
    saved = saved if isinstance(saved, dict) else {}
    meta = saved.get('meta') if isinstance(saved.get('meta'), dict) else {}
    source = saved.get('categories', saved)
    source = source if isinstance(source, dict) else {}
    target = str(meta.get('recon_target_directory') or '')
    root = target.replace('\\', '/').rstrip('/')

    def display_path(path):
        normalized = path.replace('\\', '/')
        if root and normalized == root:
            return '.'
        if root and normalized.startswith(root + '/'):
            return normalized[len(root)+1:]
        return path

    categories, technologies = [], []
    for category, entries in sorted(source.items(), key=lambda item: str(item[0]).casefold()):
        if category == 'meta' or not isinstance(entries, dict):
            continue
        rows = []
        for name, value in entries.items():
            if not isinstance(value, (dict, list)):
                continue
            raw = isinstance(value, list) or (isinstance(value, dict) and 'files' in value)
            data = value if isinstance(value, dict) else {}
            files = _paths(value if isinstance(value, list) else data.get('files', []))
            samples = files if raw else _paths(data.get('sampleFiles', []))
            confidence_map = data.get('confidenceByFile') or {}
            confidence_map = confidence_map if isinstance(confidence_map, dict) else {}
            counts = data.get('confidenceCounts')
            if isinstance(counts, dict):
                counts = {level: _count(counts.get(level)) for level in ('high', 'medium', 'low')}
            elif raw:
                observed = Counter(_confidence(confidence_map.get(path)) for path in files)
                counts = {level: observed[level] for level in ('high', 'medium', 'low')}
            else:
                counts = {level: None for level in ('high', 'medium', 'low')}
            confidence = _confidence(data.get('dominantConfidence'))
            if confidence == 'not recorded' and raw and any(counts.values()):
                confidence = max(('high', 'medium', 'low'), key=lambda level: counts[level] or 0)
            directories = []
            if raw:
                directory_counts = Counter(path.replace('\\', '/').rsplit('/', 1)[0] if '/' in path.replace('\\', '/') else '.' for path in files)
                directory_source = [{'directory': path, 'fileCount': count} for path, count in directory_counts.items()]
            else:
                directory_source = data.get('directories', [])
            if isinstance(directory_source, list):
                for item in directory_source:
                    if isinstance(item, dict) and item.get('directory') is not None:
                        path = str(item['directory'])
                        directories.append(dict(path=path, display=display_path(path), files=_count(item.get('fileCount'))))
            directories.sort(key=lambda item: (-(item['files'] or 0), item['path']))
            row = dict(name=str(name), category=str(category), confidence=confidence,
                       confidence_counts=counts, files=len(files) if raw else _count(data.get('totalFiles')),
                       directory_count=len(directories) if raw else _count(data.get('totalDirectories')),
                       directories=directories, evidence_label='Matched files' if raw else 'Sample files',
                       samples=[dict(path=path, display=display_path(path), confidence=_confidence(confidence_map.get(path))) for path in samples])
            row['directory_count'] = len(directories) if row['directory_count'] is None and directories else row['directory_count']
            rows.append(row)
        rows.sort(key=lambda row: (-(row['files'] or 0), row['name'].casefold()))
        if rows:
            entry = dict(name=str(category), anchor='recon-category-' + str(len(categories)+1), technologies=rows)
            categories.append(entry)
            technologies.extend(rows)
    metadata = []
    order = ['recon_target_directory', 'recon_strict_mode', 'recon_tuning_enabled', 'generated_at']
    for key in sorted(meta, key=lambda key: (order.index(key) if key in order else len(order), str(key))):
        value = meta[key]
        label = {'recon_target_directory': 'Target directory', 'recon_strict_mode': 'Strict filtering',
                 'recon_tuning_enabled': 'Detection tuning', 'generated_at': 'Saved reconnaissance timestamp'}.get(key)
        if not label:
            label = re.sub(r'(?<=[a-z])(?=[A-Z])', ' ', str(key)).replace('_', ' ').capitalize()
        if key in ('recon_strict_mode', 'recon_tuning_enabled'):
            value = {'true': 'Enabled', 'false': 'Disabled'}.get(str(value).lower(), value)
        metadata.append(dict(label=label, value=value))
    return dict(categories=categories, technologies=technologies, metadata=metadata, target=target,
                total_categories=len(categories), total_technologies=len(technologies),
                file_observations=sum(row['files'] or 0 for row in technologies),
                directory_observations=sum(row['directory_count'] or 0 for row in technologies))
