"""Allowlisted generated-file cleanup shared by the portal and standalone CLI."""
from contextlib import ExitStack
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import itertools
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import tempfile
import time

from utils.storage_lease import lease

MIN_AGE_SECONDS = 24 * 3600
AREAS = {
    'audit-output': ('Audit and replay outputs', 'exclude/audits', 'Old generated reports, replay data, logs and evidence databases. Scripts, summaries, source copies and referenced fixtures stay.'),
    'restoration-output': ('Report-restoration exports', 'exclude/reviews/report-restoration-20261025', 'Old report exports, intermediate documents and restoration logs. Scripts and summaries stay.'),
    'bytecode': ('Python bytecode caches', 'project code only', 'Regenerable .pyc/.pyo files. Installed dependencies are excluded.'),
    'diagnostics': ('Diagnostic and rotated logs', 'runtime/diagnostics and rotated runtime logs', 'Old diagnostic scratch and numbered/dated rotated logs. Current logs, account databases and scan state stay.'),
    'analyzer-scratch': ('Abandoned analyzer scratch', 'system temporary directory/daksh-analysis-*', 'Old leased analyzer databases whose producing process is no longer running. Active and unrecognized scratch stays.'),
}
SOURCE_NAMES = {'source', 'sources', 'src', 'fixtures', 'fixture', 'legacy', 'source-before', 'before-source', 'before-source-deployed', 'node_modules', 'venv', '.venv', '.git'}
OUTPUT_NAMES = {'runtime', 'results', 'reports', 'exports', 'replay-runtime', 'replay-results'}
GENERATED_SUFFIXES = {'.json', '.jsonl', '.sqlite3', '.sqlite', '.db', '.log', '.txt', '.html', '.pdf', '.docx', '.gz', '.zip', '.png'}
CODE_ROOTS = ('core', 'utils', 'state', 'tools', 'tests', 'webui/api', 'exclude/tests')


def _batches(values):
    values = iter(values)
    while True:
        batch = tuple(itertools.islice(values, 64))
        if not batch:
            return
        yield batch


def _references(path):
    try:
        if path.stat().st_size <= 2 * 1024 * 1024:
            return set(re.findall(r'exclude/audits/([A-Za-z0-9_.-]+)', path.read_text(errors='replace')))
        return set()
    except OSError:
        return {'*'}


def _index_paths(root):
    """Read a checksum-verified ordinary Git index when Git is not installed.

    Split/sparse indexes and other formats require Git; fail closed rather
    than inferring tracked paths from an unsupported representation.
    """
    path = root / '.git/index'
    if not owned(path, root) or path.stat().st_size > 64 * 1024 * 1024:
        raise ValueError('Unavailable Git index')
    data = path.read_bytes()
    if len(data) < 32 or data[:4] != b'DIRC' or hashlib.sha1(data[:-20]).digest() != data[-20:]:
        raise ValueError('Invalid Git index')
    version, count = struct.unpack_from('!II', data, 4)
    if version not in (2, 3):
        raise ValueError('Git is required for this index version')
    paths, position, end = set(), 12, len(data) - 20
    for _ in range(count):
        start = position
        flags = struct.unpack_from('!H', data, position + 60)[0]
        if flags & 0x4000 and version == 2:
            raise ValueError('Invalid index flags')
        name_start = position + 62 + (2 if flags & 0x4000 else 0)
        name_end = data.index(b'\0', name_start, end)
        name = os.fsdecode(data[name_start:name_end])
        if not name or name.endswith('/'):
            raise ValueError('Sparse index requires Git')
        paths.add(name)
        position = start + ((name_end + 1 - start + 7) // 8) * 8
        if position > end:
            raise ValueError('Truncated Git index')
    while position < end:
        signature, length = struct.unpack_from('!4sI', data, position)
        if not b'A' <= signature[:1] <= b'Z':
            raise ValueError('Required index extension needs Git')
        position += 8 + length
        if position > end:
            raise ValueError('Truncated index extension')
    return paths


def owned(path, root):
    path, root = Path(os.path.abspath(path)), Path(os.path.abspath(root))
    try:
        relative = path.relative_to(root)
    except ValueError:
        return False
    if '..' in relative.parts or any(parent.is_symlink() for parent in (root, *root.parents)):
        return False
    # Junctions/reparse points on Windows can redirect without is_symlink().
    if path.resolve() != path:
        return False
    current = root
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            return False
    return True


def walk_files(path, root):
    if not owned(path, root):
        return
    if path.is_file():
        yield path
    elif path.is_dir():
        pending = [path]
        while pending:
            parent = pending.pop()
            try:
                with os.scandir(parent) as scan:
                    entries = sorted(scan, key=lambda entry: entry.name)
                for entry in entries:
                    if entry.is_symlink():
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        pending.append(Path(entry.path))
                    elif entry.is_file(follow_symlinks=False):
                        yield Path(entry.path)
            except OSError:
                continue


def protection(root):
    tracked = set()
    # A checkout must be able to prove a file is untracked. Installed source
    # archives have no index and rely on the narrow generated-file allowlist.
    if (root / '.git').exists():
        try:
            output = subprocess.run(['git', '-c', 'safe.directory=' + str(root), '-C', str(root), 'ls-files', '-z'], check=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            tracked = set(os.fsdecode(output.stdout).split('\0'))
        except (OSError, subprocess.SubprocessError):
            try:
                tracked = _index_paths(root)
            except (OSError, ValueError, struct.error):
                return None, set()
    fixtures = {'pattern-unification-20261012', 'legacy-rule-filter-retirement-20261012', 'mobile-security-coverage-20261012'}
    paths = (path for folder in (*CODE_ROOTS, 'config', 'webui/frontend/src')
             for path in walk_files(root / folder, root)
             if path.suffix in {'.py', '.js', '.jsx', '.ts', '.tsx', '.json', '.yaml', '.yml'})
    with ThreadPoolExecutor(max_workers=8) as pool:
        for batch in _batches(paths):
            for references in pool.map(_references, batch):
                fixtures.update(references)
    return tracked, fixtures


def _snapshot(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError('Not a regular generated file')
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def _measured(candidate):
    try:
        return candidate, _snapshot(candidate[1])
    except (OSError, ValueError):
        return candidate, None


def _measure_candidates(root, temporary_root):
    # Bound both outstanding work and memory; mounted filesystems benefit from
    # overlapping metadata I/O without one task/future per project file.
    with ThreadPoolExecutor(max_workers=8) as pool:
        for batch in _batches(_candidates(root, temporary_root)):
            yield from pool.map(_measured, batch)


def _candidates(root, temporary_root):
    audit = root / 'exclude/audits'
    for path in walk_files(audit, root):
        relative = path.relative_to(audit)
        generated = (path.suffix.lower() in GENERATED_SUFFIXES or path.name.endswith(('.sqlite3-wal', '.sqlite3-shm')))
        source = any(p.casefold() in SOURCE_NAMES for p in relative.parts[:-1])
        summary = any(word in path.stem.lower() for word in ('summary', 'manifest', 'verification'))
        eligible = generated and not source and not summary
        yield 'audit-output', path, root, eligible, relative.parts[0], None
    restoration = root / 'exclude/reviews/report-restoration-20261025'
    for path in walk_files(restoration, root):
        relative = path.relative_to(restoration)
        eligible = path.suffix in GENERATED_SUFFIXES and (relative.parts[0] in {'output', 'saved', 'pdf-parts', 'sample', 'cli-reports'} or relative.parts[0].startswith('word-') or path.suffix == '.log')
        yield 'restoration-output', path, root, eligible, '', None
    for folder in ('__pycache__', *CODE_ROOTS):
        for path in walk_files(root / folder, root):
            if '__pycache__' in path.parts and path.suffix in {'.pyc', '.pyo'}:
                yield 'bytecode', path, root, True, '', None
    for path in walk_files(root / 'runtime/diagnostics', root):
        yield 'diagnostics', path, root, path.suffix in GENERATED_SUFFIXES, '', None
    runtime = root / 'runtime'
    if owned(runtime, root) and runtime.is_dir():
        for path in runtime.iterdir():
            if path.is_file() and not path.is_symlink() and re.fullmatch(r'[\w-]+\.log\.(?:\d+|\d{4}-\d{2}-\d{2})(?:\.gz)?', path.name):
                yield 'diagnostics', path, root, True, '', None
    if owned(temporary_root, temporary_root) and temporary_root.is_dir():
        for folder in sorted(temporary_root.glob('daksh-analysis-*')):
            if folder.is_symlink() or not folder.is_dir():
                continue
            guard = folder / '.cleanup-lease'
            for path in walk_files(folder, temporary_root):
                if path == guard:
                    continue
                yield 'analyzer-scratch', path, temporary_root, path.name in {'findings.sqlite3', 'findings.sqlite3-journal', 'findings.sqlite3-wal', 'findings.sqlite3-shm'}, '', guard


def plan(root, busy=False, local=False, temporary_root=None, now=None):
    root = Path(root).absolute()
    temporary_root = Path(temporary_root or tempfile.gettempdir()).absolute()
    now = time.time() if now is None else now
    tracked, fixtures = protection(root)
    areas = {key: dict(id=key, label=value[0], location=value[1], description=value[2], bytes=0,
                      reclaimable_bytes=0, file_count=0, eligible_files=0, errors=0, samples=[]) for key, value in AREAS.items()}
    candidates = []
    for (key, path, boundary, eligible, fixture, guard), snapshot in _measure_candidates(root, temporary_root):
        area = areas[key]
        try:
            if snapshot is None:
                area['errors'] += 1
                continue
            area['bytes'] += snapshot[2]; area['file_count'] += 1
            relative = path.relative_to(boundary).as_posix()
            if len(area['samples']) < 5:
                area['samples'].append(relative)
            eligible = eligible and now - snapshot[3] / 1e9 >= MIN_AGE_SECONDS
            if key == 'audit-output':
                audit_parts = path.relative_to(root / 'exclude/audits').parts
                eligible = eligible and (any(p in OUTPUT_NAMES for p in audit_parts[:-1])
                    or path.suffix in {'.log', '.jsonl', '.sqlite3'}
                    or path.name.endswith(('.sqlite3-wal', '.sqlite3-shm')) or snapshot[2] >= 1024 * 1024)
            if boundary == root:
                eligible = eligible and tracked is not None and relative not in tracked
            if key == 'audit-output' and (fixture in fixtures or '*' in fixtures):
                eligible = False
            if key == 'diagnostics' and (busy or local):
                eligible = False
            if key in {'audit-output', 'restoration-output'} and busy:
                eligible = False
            if guard:
                try:
                    if not owned(guard, boundary):
                        raise OSError('Unsafe scratch lease')
                    with lease(guard):
                        pass
                except OSError:
                    eligible = False
            if eligible:
                area['reclaimable_bytes'] += snapshot[2]; area['eligible_files'] += 1
                candidates.append(dict(area=key, path=path, root=boundary, snapshot=snapshot, guard=guard))
        except (OSError, ValueError):
            area['errors'] += 1
    return dict(areas=list(areas.values()), reclaimable_bytes=sum(a['reclaimable_bytes'] for a in areas.values()),
                minimum_age_hours=MIN_AGE_SECONDS // 3600, busy=busy,
                ownership_warning='' if tracked is not None else 'Project cleanup is locked because the Git index could not be verified. Run cleanup from a checkout with Git available.',
                note='Only allowlisted generated files at least 24 hours old are eligible. Force skips confirmation only. Source code, referenced fixtures, dependencies, Git, user media, account databases, current logs and saved scan findings are retained. Use scan cleanup separately for saved results.',
                history=history(root), _candidates=candidates)


def public_plan(value):
    return {key: item for key, item in value.items() if not key.startswith('_')}


def cleanup(root, area_ids, **options):
    unknown = set(area_ids) - AREAS.keys()
    if unknown or not area_ids:
        raise ValueError('Select known cleanup areas: ' + ', '.join(AREAS))
    lock = Path(root).absolute() / 'runtime/storage-cleanup.lock'
    if not owned(lock, Path(root).absolute()):
        raise ValueError('Cleanup lock path is linked')
    lock.parent.mkdir(parents=True, exist_ok=True)
    with lease(lock, create=True):
        return _cleanup_locked(root, area_ids, **options)


def _cleanup_locked(root, area_ids, **options):
    current = plan(root, **options)
    removed = removed_files = skipped = 0
    failures = []
    for item in current['_candidates']:
        if item['area'] not in area_ids:
            continue
        path, boundary = item['path'], item['root']
        try:
            with ExitStack() as stack:
                if item['guard']:
                    if not owned(item['guard'], boundary):
                        raise ValueError('Scratch lease changed')
                    stack.enter_context(lease(item['guard']))
                if not owned(path, boundary) or _snapshot(path) != item['snapshot']:
                    skipped += 1
                    continue
                path.unlink()
                removed += item['snapshot'][2]; removed_files += 1
        except FileNotFoundError:
            skipped += 1
        except (OSError, ValueError):
            failures.append(str(path.relative_to(boundary)))
    event = dict(created_at=datetime.now(timezone.utc).isoformat(), areas=list(dict.fromkeys(area_ids)),
                 removed_bytes=removed, removed_files=removed_files, skipped_files=skipped, failed_files=len(failures))
    # History is bounded and separate from account/scan databases. An unwritable
    # history must not misreport already completed deletion as unsuccessful.
    try:
        from utils.json_io import write_json_atomic
        target = Path(root) / 'runtime/storage-cleanup-history.json'
        if not owned(target, Path(root)):
            raise OSError('History path is linked')
        write_json_atomic(target, (history(root, legacy=False) + [event])[-20:])
    except OSError:
        event['history_warning'] = 'Cleanup finished; history could not be saved.'
    return dict(event, failures=failures[:20])


def history(root, legacy=True):
    records = []
    names = ['runtime/storage-cleanup-history.json']
    if legacy:
        names[0:0] = ['exclude/reviews/storage-maintenance-20261025/opal-results-cleanup-20261025.json', 'exclude/reviews/storage-maintenance-20261025/disk-cleanup-20261025.json']
    for name in names:
        path = Path(root) / name
        try:
            if not owned(path, Path(root)) or path.stat().st_size > 1024 * 1024:
                continue
            data = json.loads(path.read_text())
            if isinstance(data, dict) and data.get('status') == 'completed':
                if name.endswith('opal-results-cleanup-20261025.json'):
                    records.append(dict(created_at=data.get('completed_at', '2026-10-25'),
                        removed_bytes=data.get('portal_result_bytes', 0) + sum(row.get('bytes', 0) for row in data.get('private_results_removed', [])),
                        label='Earlier saved scan and audit cleanup'))
                else:
                    records.append(dict(created_at='2026-10-25', removed_bytes=data.get('removed_bytes', 0), removed_files=data.get('removed_targets', len(data.get('removed', []))), label='Earlier audit/report/cache cleanup'))
            elif isinstance(data, list):
                records.extend({k: v for k, v in row.items() if k in {'created_at', 'areas', 'removed_bytes', 'removed_files', 'skipped_files', 'failed_files'}} for row in data[-20:] if isinstance(row, dict))
        except (OSError, ValueError, TypeError):
            continue
    return records
