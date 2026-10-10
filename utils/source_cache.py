"""Scan-local source snapshots with bounded memory and disk-backed reuse."""
import hashlib
import io
import json
import locale
import os
import sqlite3
import tempfile
from collections import OrderedDict
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

_ACTIVE = ContextVar('scan_source_snapshot', default=None)


class SourceSnapshot:
    def __init__(self, roots, max_memory_bytes=32 * 1024 * 1024):
        self.roots = tuple(os.path.abspath(root) for root in roots)
        self.max_memory_bytes = max(0, max_memory_bytes)
        self.memory = OrderedDict()
        self.memory_bytes = 0
        self.entries = {}
        self.spool = tempfile.TemporaryFile()
        self.directory = tempfile.TemporaryDirectory(prefix='scan-cache-')
        self.decisions = sqlite3.connect(str(Path(self.directory.name) / 'decisions.sqlite3'))
        self.decisions.execute('PRAGMA journal_mode=OFF')
        self.decisions.execute('PRAGMA synchronous=OFF')
        self.decisions.execute('PRAGMA cache_size=-2048')
        self.decisions.execute('CREATE TABLE decisions (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
        self.source_reads = self.cache_hits = self.decision_hits = 0

    def key(self, path):
        key = os.path.abspath(path)
        return key if any(key == root or key.startswith(root + os.sep) for root in self.roots) else None

    def read(self, path):
        key = self.key(path)
        if key is None:
            return Path(path).read_bytes()
        if key in self.memory:
            self.cache_hits += 1
            data = self.memory.pop(key)
            self.memory_bytes -= len(data)
        elif key in self.entries:
            self.cache_hits += 1
            offset, size, _ = self.entries[key]
            self.spool.seek(offset)
            data = self.spool.read(size)
            if len(data) != size:
                raise OSError('Incomplete scan source snapshot: ' + key)
        else:
            source = Path(path)
            stat = source.stat()
            data = source.read_bytes()
            after = source.stat()
            if (stat.st_size, stat.st_mtime_ns, stat.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
                raise OSError('Source changed while capturing scan snapshot: ' + key)
            self.spool.seek(0, 2)
            self.entries[key] = (self.spool.tell(), len(data), stat)
            self.spool.write(data)
            self.source_reads += 1
        if len(data) <= self.max_memory_bytes:
            if key not in self.memory:
                self.memory_bytes += len(data)
            self.memory[key] = data
            while self.memory_bytes > self.max_memory_bytes:
                _, removed = self.memory.popitem(last=False)
                self.memory_bytes -= len(removed)
        return data

    def memo(self, parts, compute):
        key = hashlib.sha256(json.dumps(parts, ensure_ascii=True).encode()).hexdigest()
        row = self.decisions.execute('SELECT value FROM decisions WHERE key=?', (key,)).fetchone()
        if row:
            self.decision_hits += 1
            return json.loads(row[0])
        value = compute()
        self.decisions.execute('INSERT OR REPLACE INTO decisions VALUES (?,?)', (key, json.dumps(value)))
        return value

    def close(self):
        self.spool.close()
        self.decisions.close()
        self.directory.cleanup()


def current_snapshot():
    return _ACTIVE.get()


@contextmanager
def source_snapshot(*roots, max_memory_bytes=32 * 1024 * 1024):
    snapshot = SourceSnapshot(roots, max_memory_bytes)
    token = _ACTIVE.set(snapshot)
    try:
        yield snapshot
    finally:
        _ACTIVE.reset(token)
        snapshot.close()


def read_source_bytes(path):
    snapshot = _ACTIVE.get()
    return snapshot.read(path) if snapshot is not None else Path(path).read_bytes()


def read_source_text(path, encoding=None, errors=None):
    # Match Path.read_text's universal-newline behavior exactly.
    return io.StringIO(read_source_bytes(path).decode(encoding or locale.getpreferredencoding(False), errors or 'strict'), newline=None).read()


def source_stat(path):
    snapshot = _ACTIVE.get()
    if snapshot is not None:
        entry = snapshot.entries.get(snapshot.key(path))
        if entry is not None:
            return entry[2]
    return Path(path).stat()
