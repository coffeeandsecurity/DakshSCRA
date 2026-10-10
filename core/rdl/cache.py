"""Bounded content-addressed cache for immutable semantic IR fragments."""

import hashlib
from contextlib import contextmanager
from contextvars import ContextVar
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from utils.scan_scope import glob_source, allows_file
from utils.source_cache import read_source_bytes, source_stat

from .ir import SemanticIR


class AnalysisBudgetExceeded(RuntimeError):
    pass


@dataclass(frozen=True)
class CacheStats:
    hits: int
    misses: int
    evictions: int
    entries: int
    source_bytes: int


class IncrementalIRCache:
    """Caches per-file IR by content and adapter identity with LRU eviction."""

    def __init__(self, max_entries=2048, max_source_bytes=64 * 1024 * 1024,
                 max_file_bytes=4 * 1024 * 1024, max_project_files=20000, max_ir_items=100000, max_project_ir_items=400000):
        self.max_entries = max(1, int(max_entries))
        self.max_source_bytes = max(1, int(max_source_bytes))
        self.max_file_bytes = max(1, int(max_file_bytes))
        self.max_project_files = max(1, int(max_project_files))
        self.max_ir_items = max(1, int(max_ir_items))
        self.max_project_ir_items = max(1, int(max_project_ir_items))
        self._scan_irs = OrderedDict()
        self._ir_items = 0
        self._entries = OrderedDict()
        self._source_bytes = 0
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        self._review_snapshot = ContextVar("rdl_review_snapshot", default=None)

    def _key(self, adapter, path):
        try:
            if source_stat(path).st_size > self.max_file_bytes:
                raise AnalysisBudgetExceeded('source-file byte budget exceeded')
            data = read_source_bytes(path)
        except OSError as exc:
            raise AnalysisBudgetExceeded("source read failed: {0}".format(exc))
        if len(data) > self.max_file_bytes:
            raise AnalysisBudgetExceeded("source-file byte budget exceeded")
        descriptor = adapter.descriptor()
        digest = hashlib.sha256(data).hexdigest()
        return (
            descriptor.language_id, descriptor.adapter_name,
            descriptor.adapter_version, descriptor.ir_schema_version,
            path.resolve().as_posix(), digest,
        ), len(data)

    @contextmanager
    def review_snapshot(self):
        """Reuse immutable IR within one file review, refresh on the next review.

        Each distinct source scope is read and validated on its first use. The
        snapshot is context-local and released even if a rule raises an error.
        """
        token = self._review_snapshot.set({})
        try:
            yield
        finally:
            self._review_snapshot.reset(token)

    def parse(self, adapter, root, source_paths=None):
        from utils.source_cache import current_snapshot
        scan = current_snapshot()
        if source_paths is not None:
            source_paths = tuple(source_paths)
        if scan is not None and source_paths:
            descriptor = adapter.descriptor()
            paths = tuple(source_paths)
            key = (scan, descriptor.language_id, descriptor.adapter_name,
                   descriptor.adapter_version, descriptor.ir_schema_version, paths)
            value = self._scan_irs.pop(key, None)
            if value is not None:
                # This exact immutable scope was validated before insertion.
                self._hits += 1
                self._scan_irs[key] = value
                if isinstance(value, str):
                    raise AnalysisBudgetExceeded(value)
                return value
            if all(scan.key(path) is not None for path in paths):
                try:
                    value = self._parse(adapter, root, paths)
                except AnalysisBudgetExceeded as exc:
                    value = str(exc)
                self._scan_irs[key] = value
                while len(self._scan_irs) > 2:
                    self._scan_irs.popitem(last=False)
                if isinstance(value, str):
                    raise AnalysisBudgetExceeded(value)
                return value
        snapshot = self._review_snapshot.get()
        if snapshot is None:
            return self._parse(adapter, root, source_paths)
        paths = tuple(source_paths) if source_paths is not None else None
        descriptor = adapter.descriptor()
        key = (descriptor.language_id, descriptor.adapter_name, descriptor.adapter_version,
               descriptor.ir_schema_version, str(root), paths)
        if key not in snapshot:
            if len(snapshot) >= self.max_entries:
                snapshot.clear()
            snapshot[key] = self._parse(adapter, root, paths)
        return snapshot[key]

    def _parse(self, adapter, root, source_paths=None):
        root = Path(root)
        files = list(source_paths) if source_paths is not None else [root] if root.is_file() else sorted(
            path for path in glob_source(root, "*") if path.is_file() and adapter.supports(path)
        )
        files = [path for path in files if allows_file(path)]
        if len(files) > self.max_project_files:
            raise AnalysisBudgetExceeded("project-file budget exceeded")
        try:
            project_bytes = sum(source_stat(path).st_size for path in files)
        except OSError as exc:
            raise AnalysisBudgetExceeded("source metadata read failed: {0}".format(exc))
        if project_bytes > self.max_source_bytes:
            raise AnalysisBudgetExceeded("project source-byte budget exceeded")
        parts, items = [], 0
        for path in files:
            part = self._parse_file(adapter, path)
            items += len(part.entities) + len(part.edges)
            if items > self.max_project_ir_items:
                raise AnalysisBudgetExceeded('project IR item budget exceeded')
            parts.append(part)
        if not parts:
            return adapter.parse_project(root)
        return SemanticIR(
            adapter.language_id, adapter.adapter_name, adapter.adapter_version,
            adapter.ir_schema_version,
            tuple(entity for part in parts for entity in part.entities),
            tuple(edge for part in parts for edge in part.edges),
            frozenset().union(*(part.capabilities for part in parts)),
            tuple(message for part in parts for message in part.diagnostics),
        )

    def _parse_file(self, adapter, path):
        key, source_bytes = self._key(adapter, path)
        cached = self._entries.pop(key, None)
        if cached is not None:
            self._entries[key] = cached
            self._hits += 1
            return cached[0]
        self._misses += 1
        identity = key[:-1]
        stale = [item for item in self._entries if item[:-1] == identity]
        for item in stale:
            removed, removed_bytes = self._entries.pop(item)
            self._ir_items -= len(removed.entities) + len(removed.edges)
            self._source_bytes -= removed_bytes
            self._evictions += 1
        value = adapter.parse_file(path)
        self._entries[key] = (value, source_bytes)
        self._source_bytes += source_bytes
        self._ir_items += len(value.entities) + len(value.edges)
        while len(self._entries) > self.max_entries or self._source_bytes > self.max_source_bytes or self._ir_items > self.max_ir_items:
            _, (removed, removed_bytes) = self._entries.popitem(last=False)
            self._ir_items -= len(removed.entities) + len(removed.edges)
            self._source_bytes -= removed_bytes
            self._evictions += 1
        return value

    def clear(self):
        self._scan_irs.clear()
        snapshot = self._review_snapshot.get()
        if snapshot is not None:
            snapshot.clear()
        self._entries.clear()
        self._ir_items = 0
        self._source_bytes = 0

    @property
    def stats(self):
        return CacheStats(
            self._hits, self._misses, self._evictions,
            len(self._entries), self._source_bytes,
        )
