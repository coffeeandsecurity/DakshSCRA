"""Temporary, bounded-memory storage for completed analyzer findings.

The propagation graph remains in memory. Only finished findings and exact
observation identities are spooled while other platform analyzers execute.
The ordinary JSON output remains the durable interface.
"""
import itertools
import json
from pathlib import Path
import sqlite3
import tempfile
import zlib
from collections.abc import Sequence

from core.analysis_dispatch import observation_digest
from utils.json_io import atomic_json_stream
from utils.storage_lease import lease


class FindingRows(Sequence):
    def __init__(self, store, group, count, score_sum):
        self.store, self.group, self.count, self.score_sum = store, group, count, score_sum

    def __len__(self):
        return self.count

    def __iter__(self):
        for payload in self.store.payloads(self.group, self.count):
            yield json.loads(payload)

    def __getitem__(self, index):
        if isinstance(index, slice):
            start, stop, step = index.indices(self.count)
            if step < 0:
                return [self[i] for i in range(start, stop, step)]
            return list(itertools.islice(iter(self), start, stop, step))
        if index < 0:
            index += self.count
        if not 0 <= index < self.count:
            raise IndexError(index)
        row = self.store.db.execute('SELECT payload FROM findings WHERE group_id=? AND position=?',
                                    (self.group, index)).fetchone()
        if row is None:
            raise RuntimeError('Analyzer scratch data is incomplete')
        return json.loads(zlib.decompress(row[0]))


class AnalysisSpool:
    def __init__(self, directory=None):
        self._temporary = tempfile.TemporaryDirectory(prefix='daksh-analysis-', dir=directory)
        self.path = Path(self._temporary.name) / 'findings.sqlite3'
        self.db = None
        self._lease = None
        self._next_group = 0
        try:
            self._lease = lease(self.path.parent / '.cleanup-lease', create=True)
            self._lease.__enter__()
            self.db = sqlite3.connect(str(self.path))
            self.db.execute('PRAGMA journal_mode=DELETE')
            self.db.execute('PRAGMA synchronous=NORMAL')
            self.db.execute('PRAGMA cache_size=-2048')
            self.db.execute('PRAGMA temp_store=FILE')
            self.db.execute('CREATE TABLE findings(group_id INTEGER, position INTEGER, payload BLOB NOT NULL, PRIMARY KEY(group_id,position)) WITHOUT ROWID')
            self.db.execute('CREATE TABLE identities(digest BLOB PRIMARY KEY) WITHOUT ROWID')
        except BaseException:
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def close(self):
        try:
            if self.db is not None:
                self.db.close()
                self.db = None
        finally:
            if self._lease is not None:
                self._lease.__exit__(None, None, None)
                self._lease = None
            self._temporary.cleanup()

    def add(self, findings, score=lambda item: 0):
        group = self._next_group
        self._next_group += 1
        count, score_sum = 0, 0
        # One transaction per target: failed conversion/storage cannot leave
        # phantom observations in the final unique count.
        with self.db:
            for finding in findings:
                payload = json.dumps(finding, ensure_ascii=True, separators=(',', ':')).encode('utf-8')
                self.db.execute('INSERT INTO findings VALUES(?,?,?)',
                                (group, count, zlib.compress(payload, 1)))
                self.db.execute('INSERT OR IGNORE INTO identities VALUES(?)', (observation_digest(finding),))
                score_sum += score(finding)
                count += 1
        return FindingRows(self, group, count, score_sum)

    def payloads(self, group, expected):
        position = -1
        while True:
            cursor = self.db.execute('SELECT position,payload FROM findings WHERE group_id=? AND position>? ORDER BY position LIMIT 16',
                                     (group, position))
            try:
                rows = cursor.fetchall()
            finally:
                cursor.close()
            if not rows:
                if position + 1 != expected:
                    raise RuntimeError('Analyzer scratch data is incomplete')
                return
            for next_position, payload in rows:
                if next_position != position + 1:
                    raise RuntimeError('Analyzer scratch data is incomplete')
                position = next_position
                yield zlib.decompress(payload)

    def unique_count(self):
        return self.db.execute('SELECT COUNT(*) FROM identities').fetchone()[0]

    def write(self, path, summary, results):
        # Payloads were serialized and validated once during ingestion. Reuse
        # those bytes instead of decoding and encoding every finding again.
        with atomic_json_stream(path) as stream:
            stream.write('{"summary":')
            json.dump(summary, stream, indent=2)
            stream.write(',"results":[')
            for index, entry in enumerate(results):
                if index:
                    stream.write(',')
                stream.write('{')
                for field_index, (key, value) in enumerate(entry.items()):
                    if field_index:
                        stream.write(',')
                    json.dump(key, stream)
                    stream.write(':')
                    if isinstance(value, FindingRows):
                        stream.write('[')
                        for row_index, payload in enumerate(self.payloads(value.group, value.count)):
                            if row_index:
                                stream.write(',')
                            stream.write(payload.decode('utf-8'))
                        stream.write(']')
                    else:
                        json.dump(value, stream, indent=2)
                stream.write('}')
            stream.write(']}')
