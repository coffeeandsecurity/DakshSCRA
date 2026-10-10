"""Disk-backed, disposable bookkeeping for a single local scan process."""
import json
import sqlite3
import tempfile
import weakref
from pathlib import Path


def _close(connection, directory):
    connection.close()
    directory.cleanup()


class DiskIndex:
    def __init__(self):
        self._db = None

    def _connection(self):
        if self._db is None:
            directory = tempfile.TemporaryDirectory(prefix='rdl-index-')
            self._db = sqlite3.connect(str(Path(directory.name)/'index.db'))
            # This cache is disposable; durable results use ResultStore separately.
            self._db.execute('PRAGMA journal_mode=OFF')
            self._db.execute('PRAGMA synchronous=OFF')
            self._db.execute('PRAGMA cache_size=-1024')
            self._db.execute('CREATE TABLE entries (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
            weakref.finalize(self, _close, self._db, directory)
        return self._db

    def __contains__(self, key):
        return self.get(key) is not None

    def get(self, key, default=None):
        if self._db is None:
            return default
        row = self._db.execute('SELECT value FROM entries WHERE key=?',(json.dumps(key),)).fetchone()
        return json.loads(row[0]) if row else default

    def __setitem__(self, key, value):
        self._connection().execute('INSERT OR REPLACE INTO entries VALUES (?,?)',(json.dumps(key),json.dumps(value)))

    def add(self, key):
        self[key] = True

    def clear(self):
        if self._db is not None:
            self._db.execute('DELETE FROM entries')

    def __len__(self):
        return self._db.execute('SELECT COUNT(*) FROM entries').fetchone()[0] if self._db else 0
