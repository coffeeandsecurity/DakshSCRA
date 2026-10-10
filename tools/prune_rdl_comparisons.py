"""Remove comparison history from a completed scan without dropping review evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.rdl.result_store import ResultStore, ResultWriter, database_path, dumps
from core.rdl.retention import review_record


def compact(path):
    path = Path(path)
    source = ResultStore(path)
    if path.exists() and path.stat().st_size:
        raise ValueError('Import or clear the legacy journal before compacting a completed scan')
    if path.with_suffix('.findings.jsonl.gz').exists():
        raise ValueError('Remove the legacy compressed journal before compacting')
    original_bytes = source.path.stat().st_size
    with sqlite3.connect(f'file:{source.path}?mode=ro', uri=True) as old:
        if old.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('Source database integrity check failed')
        before_entities = old.execute('SELECT kind,identity FROM entities ORDER BY kind,identity,group_id').fetchall()
        diagnostics = old.execute("SELECT key,value FROM metadata WHERE key='malformed'").fetchall()
        with tempfile.TemporaryDirectory(prefix='rdl-retention-', dir=source.path.parent) as directory:
            target = Path(directory) / 'results.jsonl'
            writer = ResultWriter(target)
            expected = hashlib.sha256()
            kept = removed = 0
            try:
                for (payload,) in old.execute('SELECT payload FROM records ORDER BY id'):
                    manifest = json.loads(payload)
                    # Inspect the small decision fields before expanding evidence.
                    probe = {k: source._get(old, manifest[k]) for k in
                             ('v2_outcome', 'status', 'v2_errors', 'v2_limitations', 'v2_unavailable_capabilities') if k in manifest}
                    if 'v2_findings' in manifest:
                        probe['v2_findings'] = source._get(old, manifest['v2_findings'])
                    if review_record(probe) is None:
                        removed += 1
                        continue
                    record = review_record({k: source._get(old, v) for k, v in manifest.items()})
                    expected.update((dumps(record) + '\n').encode())
                    writer.append(record)
                    kept += 1
            finally:
                writer.close()
            replacement = ResultStore(target)
            with replacement.connect() as new, new:
                new.execute("INSERT OR REPLACE INTO metadata VALUES ('result_retention','review')")
                new.executemany('INSERT OR REPLACE INTO metadata VALUES (?,?)', diagnostics)
                after_entities = new.execute('SELECT kind,identity FROM entities ORDER BY kind,identity,group_id').fetchall()
                if [tuple(r) for r in after_entities] != before_entities:
                    raise ValueError('Finding/flow/cross-reference/attack-vector identities changed')
                if new.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                    raise ValueError('Replacement database integrity check failed')
            actual = hashlib.sha256()
            for record in replacement.iter_records():
                actual.update((dumps(record) + '\n').encode())
            if actual.digest() != expected.digest():
                raise ValueError('Retained evidence did not round-trip exactly')
            # Readers holding the old inode finish safely; subsequent reads see
            # the fully validated replacement. Never use this on a running scan.
            with database_path(target).open('rb') as handle:
                os.fsync(handle.fileno())
            os.replace(database_path(target), source.path)
    return dict(retained=kept, removed=removed, bytes_before=original_bytes,
                bytes_after=source.path.stat().st_size, evidence_verified=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('journal', type=Path, help='Result journal path of a completed scan')
    args = parser.parse_args()
    print(json.dumps(compact(args.journal), indent=2))
