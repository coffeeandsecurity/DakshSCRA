"""Inventory of application-owned storage. Never follows source directories or links."""
import hashlib
import json
import os
import shutil
from pathlib import Path


def owned(path, root):
    path, root = Path(path).absolute(), Path(root).absolute()
    try:
        relative = path.relative_to(root)
    except ValueError:
        return False
    current = root
    if current.is_symlink():
        return False
    for part in relative.parts:
        if part in ('..', '.'):
            return False
        current /= part
        if current.is_symlink():
            return False
    return True


def files(path):
    """Yield regular files only; symlink targets never contribute to cleanup."""
    if path.is_symlink():
        return
    if path.is_file():
        yield path
    elif path.is_dir():
        for parent, directories, names in os.walk(path, followlinks=False):
            directories[:] = sorted(name for name in directories if not (Path(parent) / name).is_symlink())
            for name in sorted(names):
                entry = Path(parent) / name
                if not entry.is_symlink() and entry.is_file():
                    yield entry


def measure(path):
    size = count = 0
    for entry in files(path):
        try:
            size += entry.stat().st_size
            count += 1
        except OSError:
            pass
    return size, count


def units(scan, root, run_root, reports_root):
    result = []
    def add(path, kind, label, removable=False, metadata=None):
        if not owned(path, root) or not path.exists():
            return
        size, count = measure(path)
        result.append(dict(id=hashlib.sha256(str(path.relative_to(root)).encode()).hexdigest()[:24],
                           path=str(path.relative_to(root)), kind=kind, label=label,
                           bytes=size, file_count=count, removable=removable, metadata=metadata or {}, _path=path))
    base = run_root / scan.run_uuid
    if owned(base, root) and base.is_dir():
        for child in sorted(base.iterdir()):
            if child.name == 'exports' and child.is_dir() and not child.is_symlink():
                for job in sorted(child.iterdir()):
                    meta = {}
                    if job.is_dir() and not job.is_symlink():
                        try:
                            saved = json.loads((job / 'job.json').read_text())
                            meta = {key: saved[key] for key in ('format', 'scope', 'status', 'created_at', 'filename') if key in saved}
                        except (OSError, ValueError, TypeError):
                            pass
                    if job.is_dir() and not job.is_symlink():
                        meta['temporary_bytes'] = sum(measure(p)[0] for p in job.glob('scratch-*') if not p.is_symlink())
                    add(job, 'reports', meta.get('filename', job.name), True, meta)
            elif child.name == 'results' and child.is_dir() and not child.is_symlink():
                for entry in sorted(child.iterdir()):
                    add(entry, 'data' if entry.name == 'data' else 'reports', 'Saved results' if entry.name == 'data' else entry.name, entry.name != 'data')
            elif child.name == 'runtime' and child.is_dir() and not child.is_symlink():
                for entry in sorted(child.iterdir()):
                    temporary = entry.name == 'diagnostics'
                    add(entry, 'temporary' if temporary else 'runtime', 'Diagnostic scratch files' if temporary else entry.name, temporary)
            else:
                add(child, 'logs' if child.suffix == '.log' else 'runtime', child.name)
    # Older versions stored results outside the scan working directory.
    for legacy in (reports_root / scan.project_key / scan.run_uuid, reports_root / scan.run_uuid):
        if owned(legacy, root) and legacy.is_dir():
            for entry in sorted(legacy.iterdir()):
                add(entry, 'data' if entry.name == 'data' else 'reports', entry.name, entry.name != 'data')
    log = Path(scan.log_path or '')
    if scan.log_path:
        log = log if log.is_absolute() else root / log
        if owned(log, run_root) and not any(log == item['_path'] or item['_path'] in log.parents for item in result):
            add(log, 'logs', log.name)
    return result


def public_unit(item):
    return {key: value for key, value in item.items() if key != '_path'}


def inventory(scans, projects, root, run_root, reports_root, active_runs):
    groups = {p.project_key: dict(project_key=p.project_key, project_name=p.project_name, scans=[]) for p in projects}
    tracked = []
    for scan in scans:
        group = groups.setdefault(scan.project_key, dict(project_key=scan.project_key, project_name=scan.project_name or scan.project_key, scans=[]))
        items = units(scan, root, run_root, reports_root)
        tracked.extend(item['_path'] for item in items)
        active = scan.status in ('queued', 'running', 'stopping') or scan.run_uuid in active_runs
        group['scans'].append(dict(run_uuid=scan.run_uuid, status=scan.status, created_at=scan.created_at.isoformat() if scan.created_at else None,
                                  active=active, data_removed=scan.data_removed_at is not None, bytes=sum(i['bytes'] for i in items),
                                  units=[dict(public_unit(i), removable=i['removable'] and not active) for i in items]))
    for group in groups.values():
        group['bytes'] = sum(scan['bytes'] for scan in group['scans'])
    # Show storage without a retained project/scan record as read-only, rather
    # than guessing ownership and offering destructive path-based cleanup.
    known_runs = {s.run_uuid for s in scans}
    known_projects = {s.project_key for s in scans}
    other = []
    candidates = []
    if owned(run_root, root) and run_root.exists():
        candidates.extend(p for p in run_root.iterdir() if p.name not in known_runs and not any(p == t for t in tracked))
    if owned(reports_root, root) and reports_root.exists():
        for p in reports_root.iterdir():
            if p.name in known_projects and p.is_dir() and not p.is_symlink():
                candidates.extend(c for c in p.iterdir() if c.name not in known_runs)
            elif p.name not in known_runs:
                candidates.append(p)
    for p in candidates:
        if owned(p, root):
            size, count = measure(p)
            other.append(dict(path=str(p.relative_to(root)), bytes=size, file_count=count, label='Unassigned application files', removable=False))
    usage = shutil.disk_usage(run_root if run_root.exists() else root)
    return dict(projects=sorted(groups.values(), key=lambda g: g['bytes'], reverse=True), unassigned=other,
                managed_bytes=sum(g['bytes'] for g in groups.values()) + sum(i['bytes'] for i in other),
                filesystem=dict(total=usage.total, used=usage.used, free=usage.free),
                note='Sizes are logical file sizes. Filesystem usage also includes other applications. Source directories, account databases and settings are excluded from cleanup. Active report scratch files are released automatically when generation ends.')


def remove_unit(item, root):
    path = item['_path']
    if not item['removable'] or not owned(path, root):
        raise ValueError('This storage item cannot be deleted independently.')
    before, _ = measure(path)
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink(missing_ok=True)
    return before
