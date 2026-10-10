"""Indexed, lossless local result storage behind the scan result repository API.

Only page payloads are decoded. Large repeated fields and source lines are
content-addressed and compressed; no scan-size quota discards evaluations.
"""
import base64
import gzip
import hashlib
import json
import sqlite3
import time
import zlib
from contextlib import contextmanager
from pathlib import Path

from .review_views import finding_identity, flow_traits, location_key, symbol
from .assessment import CATEGORIES, classify_record, combined_category, manual_review_direction

SCHEMA_VERSION = 4
ASSESSMENT_POLICY_VERSION = 6


def severity_rank(value):
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "INFORMATIONAL": 4, "INFORMATION": 4}.get(str(value or "").strip().upper(), 5)


class ResultStorageError(RuntimeError):
    """A scan must not claim completion when its results could not be saved."""


def database_path(path):
    return Path(path).with_suffix('.sqlite3')


def dumps(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def digest(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


SCHEMA = """
CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS blobs (id TEXT PRIMARY KEY, payload BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS groups (
 id INTEGER PRIMARY KEY, rule TEXT NOT NULL, file TEXT NOT NULL, outcome TEXT NOT NULL,
 kind TEXT NOT NULL, status TEXT NOT NULL, v1_outcome TEXT NOT NULL, search TEXT NOT NULL,
 priority INTEGER NOT NULL, severity_rank INTEGER NOT NULL DEFAULT 6, UNIQUE(rule,file,outcome));
CREATE TABLE IF NOT EXISTS records (
 id INTEGER PRIMARY KEY, group_id INTEGER NOT NULL REFERENCES groups(id),
 status TEXT NOT NULL, kind TEXT NOT NULL, payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS security_reviews (group_id INTEGER PRIMARY KEY REFERENCES groups(id), payload TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS records_group ON records(group_id,id);
CREATE INDEX IF NOT EXISTS groups_page ON groups(priority,id);
CREATE INDEX IF NOT EXISTS groups_outcome ON groups(outcome,priority,id);
CREATE INDEX IF NOT EXISTS groups_status ON groups(status,priority,id);
CREATE INDEX IF NOT EXISTS groups_kind ON groups(kind,priority,id);
CREATE TABLE IF NOT EXISTS entities (
 group_id INTEGER NOT NULL REFERENCES groups(id), kind TEXT NOT NULL, identity TEXT NOT NULL,
 PRIMARY KEY(group_id,kind,identity));
CREATE INDEX IF NOT EXISTS entities_kind ON entities(kind,identity,group_id);
"""


class ResultStore:
    def __init__(self, path):
        self.source = Path(path)
        self.path = database_path(path)

    @contextmanager
    def connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(str(self.path), timeout=30)
        connection.row_factory = sqlite3.Row
        # Keep sorting/index work on disk and avoid WAL on Windows bind mounts.
        connection.execute('PRAGMA foreign_keys=ON')
        connection.execute('PRAGMA cache_size=-4096')
        connection.execute('PRAGMA temp_store=FILE')
        try:
            # Existing databases need no schema writes or writer lock on reads.
            try:
                current = connection.execute("SELECT value FROM metadata WHERE key='schema_version'").fetchone()
            except sqlite3.OperationalError as exc:
                if 'no such table' not in str(exc):
                    raise
                current = None
            policy = connection.execute("SELECT value FROM metadata WHERE key='assessment_policy_version'").fetchone() if current else None
            if current is None or int(current[0]) != SCHEMA_VERSION or not policy or int(policy[0]) != ASSESSMENT_POLICY_VERSION:
                connection.executescript(SCHEMA)
                connection.execute('BEGIN IMMEDIATE')
                row = connection.execute("SELECT value FROM metadata WHERE key='schema_version'").fetchone()
                version = int(row[0]) if row else SCHEMA_VERSION
                if version not in {1, 2, 3, 4, 5}:
                    raise ResultStorageError('Unsupported scan result storage version')
                columns = {item[1] for item in connection.execute('PRAGMA table_info(groups)')}
                if 'severity_rank' not in columns:
                    connection.execute('ALTER TABLE groups ADD COLUMN severity_rank INTEGER NOT NULL DEFAULT 6')
                if 'assessment' not in columns:
                    connection.execute("ALTER TABLE groups ADD COLUMN assessment TEXT NOT NULL DEFAULT 'not_applicable'")
                if 'assessment' not in columns or not policy or int(policy[0]) != ASSESSMENT_POLICY_VERSION:
                    # One-time migration reads evidence, never rewrites original records.
                    for group in connection.execute('SELECT id FROM groups'):
                        categories = []
                        for stored in connection.execute('SELECT payload FROM records WHERE group_id=?', (group['id'],)):
                            manifest = json.loads(stored[0])
                            keys = ('v2_outcome', 'v2_errors', 'v2_unavailable_capabilities', 'v2_evidence', 'v2_findings', 'security_review')
                            record = {key: self._get(connection, manifest[key]) for key in keys if key in manifest}
                            review = connection.execute('SELECT payload FROM security_reviews WHERE group_id=?', (group['id'],)).fetchone()
                            if review: record['security_review'] = json.loads(review[0])
                            categories.append(classify_record(record))
                        connection.execute('UPDATE groups SET assessment=? WHERE id=?', (combined_category(categories), group['id']))
                if version == 1:
                    for record in connection.execute('SELECT group_id,payload FROM records ORDER BY id'):
                        manifest = json.loads(record['payload'])
                        findings = self._get(connection, manifest['v2_findings']) if 'v2_findings' in manifest else []
                        rank = min((severity_rank(item.get('severity')) for item in findings), default=6)
                        if rank < 6:
                            connection.execute('UPDATE groups SET severity_rank=MIN(severity_rank,?) WHERE id=?', (rank,record['group_id']))
                connection.execute('CREATE INDEX IF NOT EXISTS groups_severity_page ON groups(severity_rank,priority,id)')
                connection.execute('CREATE INDEX IF NOT EXISTS groups_assessment_page ON groups(assessment,severity_rank,priority,id)')
                connection.execute("INSERT OR REPLACE INTO metadata VALUES ('schema_version',?)", (str(SCHEMA_VERSION),))
                connection.execute("INSERT OR REPLACE INTO metadata VALUES ('assessment_policy_version',?)", (str(ASSESSMENT_POLICY_VERSION),))
                connection.commit()
            yield connection
        finally:
            connection.close()

    def _put(self, db, value):
        # Long minified source lines are shared even between trace/evidence fields.
        def pack(item):
            if isinstance(item, str) and len(item) > 2048:
                raw = item.encode('utf-8'); key = hashlib.sha256(b'source\0' + raw).hexdigest()
                db.execute('INSERT OR IGNORE INTO blobs VALUES (?,?)', (key, zlib.compress(raw)))
                return ['source', key]
            if isinstance(item, list):
                return ['list', [pack(child) for child in item]]
            if isinstance(item, dict):
                return ['dict', {key: pack(child) for key, child in item.items()}]
            return ['value', item]
        raw = dumps(pack(value)).encode('utf-8')
        key = hashlib.sha256(b'value\0' + raw).hexdigest()
        db.execute('INSERT OR IGNORE INTO blobs VALUES (?,?)', (key, zlib.compress(raw)))
        return key

    def _get(self, db, key):
        row = db.execute('SELECT payload FROM blobs WHERE id=?', (key,)).fetchone()
        if row is None:
            raise ResultStorageError('Scan evidence block is missing: ' + key)
        def unpack(node):
            kind, value = node
            if kind == 'source':
                source = db.execute('SELECT payload FROM blobs WHERE id=?', (value,)).fetchone()
                if source is None:
                    raise ResultStorageError('Scan source block is missing: ' + value)
                return zlib.decompress(source[0]).decode('utf-8')
            if kind == 'dict':
                return {name: unpack(child) for name, child in value.items()}
            if kind == 'list':
                return [unpack(child) for child in value]
            return value
        return unpack(json.loads(zlib.decompress(row[0])))

    def _append(self, db, record):
        if not isinstance(record, dict) or not isinstance(record.get('context') or {}, dict):
            raise ValueError('Invalid evaluation record')
        if record.get('comparison_retained') is False:
            db.execute("INSERT OR IGNORE INTO metadata VALUES ('result_retention','review')")
        context = record.get('context') or {}
        rule = str(record.get('v2_rule_id') or record.get('v2_rule') or 'unknown')
        file = str(context.get('file_path') or '')
        outcome = str(record.get('v2_outcome') or '')
        status = str(record.get('status', 'UNKNOWN'))
        kind = str(record.get('comparison_kind', 'semantic'))
        old = db.execute('SELECT * FROM groups WHERE rule=? AND file=? AND outcome=?', (rule,file,outcome)).fetchone()
        v1 = str(record.get('v1_outcome') or '') if old is None else old['v1_outcome']
        if record.get('v1_outcome') == 'MATCH':
            v1 = 'MATCH'
        group_status = status if old is None else old['status']
        if v1 not in {'NOT_RUN','NOT_APPLICABLE',''} and outcome in {'MATCH','NO_MATCH'}:
            group_status = 'AGREEMENT' if v1 == outcome else 'DISAGREEMENT'
        priority = 0 if group_status == 'DISAGREEMENT' else 1 if outcome == 'MATCH' else 2 if group_status in {'INDETERMINATE','RULE_ERROR','SHADOW_ERROR'} else 3
        if old is None:
            search = ' '.join(str(value or '') for value in (file, record.get('v2_rule_id'), record.get('v2_title'), context.get('rule_title'))).casefold()
            group_id = db.execute('INSERT INTO groups(rule,file,outcome,kind,status,v1_outcome,search,priority) VALUES (?,?,?,?,?,?,?,?)', (rule,file,outcome,kind,group_status,v1,search,priority)).lastrowid
        else:
            group_id = old['id']
            db.execute('UPDATE groups SET status=?,v1_outcome=?,priority=? WHERE id=?', (group_status,v1,priority,group_id))
        review = db.execute('SELECT payload FROM security_reviews WHERE group_id=?', (group_id,)).fetchone()
        category = classify_record(dict(record, security_review=json.loads(review[0]))) if review else classify_record(record)
        if old is not None:
            category = combined_category([old['assessment'], category])
        db.execute('UPDATE groups SET assessment=? WHERE id=?', (category, group_id))
        rank = min((severity_rank(item.get('severity')) for item in record.get('v2_findings') or []), default=6)
        if rank < 6:
            db.execute('UPDATE groups SET severity_rank=MIN(severity_rank,?) WHERE id=?', (rank,group_id))
        manifest = {key: self._put(db, value) for key, value in record.items()}
        db.execute('INSERT INTO records(group_id,status,kind,payload) VALUES (?,?,?,?)', (group_id,status,kind,dumps(manifest)))
        def entity(kind, identity):
            db.execute('INSERT OR IGNORE INTO entities VALUES (?,?,?)', (group_id,kind,digest(identity)))
        for finding in record.get('v2_findings') or []:
            loc = finding.get('location') or {}
            entity('lead', dumps([rule,str(loc.get('path') or file),loc.get('line'),loc.get('column')]))
            if outcome != 'MATCH':
                continue
            entity('findings', finding_identity(record, finding))
            traits = flow_traits(finding)
            if traits['taint']:
                entity('taint', traits['path_key'])
                entity('complete' if traits['complete'] else 'partial', traits['path_key'])
            for edge in traits['edges']:
                entity('xref', edge)
            for source in traits['sources']:
                entity('vectors', json.dumps([location_key(source.get('location')),symbol(source)]))
        return group_id

    def _sync_legacy(self, db):
        # Avoid taking a writer lock when compatibility journals are unchanged.
        pending = False
        for path in (self.source, self.source.with_suffix('.findings.jsonl.gz')):
            if path.exists():
                stat = path.stat()
                saved = db.execute('SELECT value FROM metadata WHERE key=?', ('legacy:' + path.name,)).fetchone()
                state = json.loads(saved[0]) if saved else {}
                if state.get('size') != stat.st_size or state.get('mtime') != stat.st_mtime_ns:
                    pending = True
                    break
        if not pending:
            return
        # Recheck checkpoints under the lock, so concurrent imports cannot duplicate.
        if not db.in_transaction: db.execute('BEGIN IMMEDIATE')
        # Incremental import also supports a still-running older JSONL writer.
        for path, compressed in [(self.source,False),(self.source.with_suffix('.findings.jsonl.gz'),True)]:
            if not path.exists():
                continue
            stat = path.stat()
            key = 'legacy:' + path.name
            saved = db.execute('SELECT value FROM metadata WHERE key=?', (key,)).fetchone()
            state = json.loads(saved[0]) if saved else {'offset':0,'size':0,'mtime':0}
            if state['size'] == stat.st_size and state['mtime'] == stat.st_mtime_ns:
                continue
            if stat.st_size < state['size']:
                raise ResultStorageError('Legacy results changed after import; restore the original journal')
            malformed = 0
            opener = gzip.open if compressed else open
            offset = state['offset']
            try:
                with opener(path, 'rb') as handle:
                    handle.seek(offset)
                    while True:
                        position = handle.tell()
                        line = handle.readline()
                        if not line:
                            break
                        if not line.endswith(b'\n'):
                            # Complete final JSON objects are valid without a newline;
                            # defer genuinely partial writes until their next append.
                            try:
                                json.loads(line)
                            except (ValueError, UnicodeError):
                                break
                        offset = handle.tell()
                        if not line.strip():
                            continue
                        db.execute('SAVEPOINT legacy_record')
                        try:
                            value = json.loads(line)
                            if not isinstance(value, dict) or not isinstance(value.get('context') or {},dict):
                                raise ValueError('invalid record')
                            self._append(db, value)
                        except (ValueError,TypeError,AttributeError,UnicodeError):
                            db.execute('ROLLBACK TO legacy_record')
                            malformed += 1
                        finally:
                            db.execute('RELEASE legacy_record')
            except (EOFError,zlib.error,gzip.BadGzipFile):
                malformed += 1
            state = dict(offset=offset,size=stat.st_size,mtime=stat.st_mtime_ns)
            db.execute('INSERT OR REPLACE INTO metadata VALUES (?,?)', (key,dumps(state)))
            if malformed:
                db.execute("INSERT INTO metadata VALUES ('malformed',?) ON CONFLICT(key) DO UPDATE SET value=CAST(value AS INTEGER)+excluded.value", (str(malformed),))

    def append(self, record):
        try:
            with self.connect() as db, db:
                self._sync_legacy(db)
                if not db.in_transaction:
                    db.execute('BEGIN IMMEDIATE')
                self._append(db, record)
            # Compatibility discovery marker; results live in the adjacent database.
            if not self.source.exists(): self.source.touch()
        except (OSError,sqlite3.Error,ValueError,TypeError,zlib.error) as exc:
            raise ResultStorageError('Cannot persist scan results: ' + str(exc)) from exc

    def _where(self, view, kind, search, section='all'):
        terms, args = [], []
        if view == 'leads': terms.append("g.outcome='MATCH'")
        elif view == 'disagreements': terms.append("g.status='DISAGREEMENT'")
        elif view == 'unresolved': terms.append("g.status IN ('INDETERMINATE','RULE_ERROR','SHADOW_ERROR')")
        if kind != 'all': terms.append('g.kind=?'); args.append(kind)
        if search: terms.append('instr(g.search,?)>0'); args.append(search.casefold())
        if section == 'findings': terms.append("g.outcome='MATCH'")
        elif section in CATEGORIES:
            terms.append('g.assessment=?')
            args.append(section)
        elif section != 'all':
            terms.append("g.assessment!='suppressed'")
            terms.append('EXISTS (SELECT 1 FROM entities e WHERE e.group_id=g.id AND e.kind=?)')
            args.append('taint' if section == 'vectors' else section)
        return (' AND '.join(terms) or '1=1'), args

    def _group(self, db, group):
        result, decisions, findings, seen = None, [], [], {}
        direction = None
        for row in db.execute('SELECT payload FROM records WHERE group_id=? ORDER BY id', (group['id'],)):
            manifest = json.loads(row[0])
            if result is None:
                result = {key:self._get(db,value) for key,value in manifest.items()}
            if group['assessment'] == 'manual' and direction is None:
                candidate = {key: self._get(db, manifest[key]) for key in ('v2_evidence', 'v2_findings') if key in manifest}
                direction = manual_review_direction(candidate)
            context = self._get(db,manifest['context']) if 'context' in manifest else {}
            decisions.append(dict(logic_ref=context.get('logic_ref'),outcome=self._get(db,manifest['v1_outcome']) if 'v1_outcome' in manifest else None,reason=self._get(db,manifest['v1_reason']) if 'v1_reason' in manifest else ''))
            for finding in self._get(db,manifest['v2_findings']) if 'v2_findings' in manifest else []:
                identity = finding_identity(result,finding)
                if identity not in seen:
                    seen[identity] = len(findings); findings.append(finding)
                elif severity_rank(finding.get('severity')) < severity_rank(findings[seen[identity]].get('severity')):
                    findings[seen[identity]] = finding
        review = db.execute('SELECT payload FROM security_reviews WHERE group_id=?', (group['id'],)).fetchone()
        if review: result['security_review'] = json.loads(review[0])
        result['status'] = group['status']
        result['assessment'] = group['assessment']
        if group['assessment'] == 'manual':
            result['manual_review'] = direction
        if result.get('comparison_retained') is not False:
            result.update(v1_outcome=group['v1_outcome'], v1_decisions=decisions)
        if findings or 'v2_findings' in result: result['v2_findings']=findings
        return result

    def read(self, limit=500, offset=0, view='all', search='', kind='all', section='all', after=None):
        from .review_views import review_sections
        with self.connect() as db:
            with db: self._sync_legacy(db)
            # One consistent snapshot for counts and rows while scanning continues.
            db.execute('BEGIN')
            statuses = dict(db.execute('SELECT status,COUNT(*) FROM records GROUP BY status'))
            kinds = dict(db.execute('SELECT kind,COUNT(*) FROM records GROUP BY kind'))
            row = db.execute('SELECT COUNT(*),COUNT(DISTINCT file),COUNT(DISTINCT rule) FROM groups').fetchone()
            bad = db.execute("SELECT value FROM metadata WHERE key='malformed'").fetchone()
            summary = dict(total=sum(statuses.values()),malformed=int(bad[0]) if bad else 0,statuses=statuses,evaluated_files=row[1],evaluated_properties=row[2],property_decisions=row[0],review_leads=db.execute("SELECT COUNT(DISTINCT identity) FROM entities WHERE kind='lead'").fetchone()[0],telemetry_truncated=self.source.with_suffix('.truncated').exists())
            retention = db.execute("SELECT value FROM metadata WHERE key='result_retention'").fetchone()
            summary['comparison_history_retained'] = not (retention and retention[0] == 'review')
            # Counts use the same indexed property/file groups as the paginated lists.
            category_where, category_args = self._where('all',kind,search)
            assessment_counts = dict.fromkeys(CATEGORIES, 0)
            for name, count in db.execute('SELECT g.assessment,COUNT(*) FROM groups g WHERE '+category_where+' GROUP BY g.assessment', category_args):
                if name in assessment_counts:
                    assessment_counts[name] = count
            summary['coverage_limit_groups'] = db.execute("SELECT COUNT(*) FROM groups g WHERE "+category_where+" AND g.assessment='coverage_limit'", category_args).fetchone()[0]
            data_assessments = dict(assessment_counts, total=sum(assessment_counts.values()))
            confirmed_finding_count = db.execute("SELECT COUNT(DISTINCT e.identity) FROM entities e JOIN groups g ON g.id=e.group_id WHERE "+category_where+" AND g.assessment='confirmed' AND e.kind='findings'", category_args).fetchone()[0]
            global_confirmed_finding_count = db.execute("SELECT COUNT(DISTINCT e.identity) FROM entities e JOIN groups g ON g.id=e.group_id WHERE g.assessment='confirmed' AND e.kind='findings'").fetchone()[0]
            base, args = self._where(view,kind,search)
            base += " AND g.assessment!='suppressed'"
            counts = {name:0 for name in ['findings','taint','complete','partial','xref','vectors']}
            for name,count in db.execute('SELECT e.kind,COUNT(DISTINCT e.identity) FROM entities e JOIN groups g ON g.id=e.group_id WHERE '+base+' GROUP BY e.kind',args):
                if name in counts: counts[name]=count
            where, params = self._where(view,kind,search,section)
            total = db.execute('SELECT COUNT(*) FROM groups g WHERE '+where,params).fetchone()[0]
            page_where, page_params = where, list(params)
            use_cursor = False
            if after:
                try:
                    cursor = json.loads(base64.urlsafe_b64decode(after.encode()).decode())
                    if not isinstance(cursor, list) or len(cursor) not in {2,3}: raise ValueError('Invalid result cursor')
                    values = [int(value) for value in cursor]
                    use_cursor = len(values) == 3
                except (ValueError,TypeError,IndexError,UnicodeError) as exc:
                    raise ValueError('Invalid result cursor') from exc
                if use_cursor:
                    rank, priority, group_id = values
                    page_where += ' AND (g.severity_rank,g.priority,g.id) > (?,?,?)'
                    page_params += [rank,priority,group_id]
                # Old two-part cursors use the supplied offset in the new order.
            rows = db.execute('SELECT g.* FROM groups g WHERE '+page_where+' ORDER BY g.severity_rank,g.priority,g.id LIMIT ? OFFSET ?',page_params+[limit+1,0 if use_cursor else offset]).fetchall() if limit else []
            more = len(rows)>limit
            rows = rows[:limit]
            records = [self._group(db,row) for row in rows]
            records, _ = review_sections(records, 'all' if section in CATEGORIES else section)
            cursor = base64.urlsafe_b64encode(dumps([rows[-1]['severity_rank'],rows[-1]['priority'],rows[-1]['id']]).encode()).decode() if more and rows else None
            return dict(summary=summary,comparisons=records,evaluation_kinds=kinds,section_counts=counts,assessment_counts=data_assessments,confirmed_finding_count=confirmed_finding_count,global_confirmed_finding_count=global_confirmed_finding_count,query=dict(view=view,search=search,kind=kind,section=section),filtered_total=total,offset=offset,limit=limit,truncated=more,next_cursor=cursor)

    def record_false_positive_review(self, rule, file, reviewer, reason):
        """Keep review metadata separately from immutable scan records."""
        if not all(isinstance(value, str) and value.strip() for value in (rule, file, reviewer, reason)):
            raise ValueError('A rule, file, reviewer and source-based reason are required')
        review = dict(status='false_positive', reviewer=reviewer, reason=reason)
        with self.connect() as db:
            with db:
                self._sync_legacy(db)
                group = db.execute("SELECT id FROM groups WHERE rule=? AND file=? AND outcome='MATCH'", (rule, file)).fetchone()
                if not group:
                    raise ValueError('No matched rule/file group exists for this review')
                db.execute('INSERT OR REPLACE INTO security_reviews VALUES (?,?)', (group['id'], dumps(review)))
                db.execute("UPDATE groups SET assessment='suppressed' WHERE id=?", (group['id'],))
        return review

    def iter_records(self, reviewed=False):
        with self.connect() as db:
            with db: self._sync_legacy(db)
            for row in db.execute('SELECT group_id,payload FROM records ORDER BY id'):
                record = {key:self._get(db,value) for key,value in json.loads(row['payload']).items()}
                if reviewed:
                    review = db.execute('SELECT payload FROM security_reviews WHERE group_id=?', (row['group_id'],)).fetchone()
                    if review: record['security_review'] = json.loads(review[0])
                yield record

    def iter_records_readonly(self):
        """Read original decisions and reviews without migrations or imports.

        Planning and export consumers must not change retained scan data. Read
        unimported journal tails separately using the saved legacy offsets.
        """
        offsets = {}
        if self.path.is_file():
            connection = sqlite3.connect(self.path.resolve().as_uri() + '?mode=ro', uri=True)
            try:
                connection.execute('PRAGMA query_only=ON')
                connection.execute('BEGIN')
                tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if 'metadata' in tables:
                    for key, value in connection.execute("SELECT key,value FROM metadata WHERE key LIKE 'legacy:%'"):
                        offsets[key[7:]] = json.loads(value).get('offset', 0)
                for group_id, payload in connection.execute('SELECT group_id,payload FROM records ORDER BY id'):
                    record = {key: self._get(connection, value) for key, value in json.loads(payload).items()}
                    if 'security_reviews' in tables:
                        review = connection.execute('SELECT payload FROM security_reviews WHERE group_id=?', (group_id,)).fetchone()
                        if review:
                            record['security_review'] = json.loads(review[0])
                    yield record
            finally:
                connection.close()
        for journal, compressed in ((self.source, False), (self.source.with_suffix('.findings.jsonl.gz'), True)):
            if not journal.is_file():
                continue
            opener = gzip.open if compressed else open
            with opener(journal, 'rb') as handle:
                handle.seek(offsets.get(journal.name, 0))
                for line in handle:
                    if not line.strip():
                        continue
                    record = json.loads(line)
                    if not isinstance(record, dict):
                        raise ResultStorageError('Invalid retained RDL decision')
                    yield record

    def iter_groups(self):
        with self.connect() as db:
            with db: self._sync_legacy(db)
            db.execute('BEGIN')
            for group in db.execute('SELECT * FROM groups ORDER BY severity_rank,priority,id'):
                yield self._group(db,group)


class ResultWriter:
    """Reuse one connection; commit bounded batches without holding idle locks.

    A successful flush is durable. Pending evaluations belong to unfinished work;
    normal exits and exceptions flush them, and failed commits abort the scan.
    SQLite rolls back only the active batch after an abrupt process interruption.
    """
    def __init__(self, path, max_records=50, max_bytes=4 * 1024 * 1024, interval=0.25):
        self.store = ResultStore(path)
        self.max_records = max(1, max_records)
        self.max_bytes = max(1, max_bytes)
        self.interval = max(0, interval)
        self.pending = []
        self.pending_bytes = 0
        self.last_flush = time.monotonic()
        self._context = None
        self._db = None
        self.failed = False

    def append(self, record):
        if self.failed:
            raise ResultStorageError('Result writer has failed')
        # Take ownership of a stable payload; callers may reuse mutable evidence.
        try:
            payload = dumps(record)
        except (ValueError, TypeError) as exc:
            raise ResultStorageError('Cannot serialize scan results: ' + str(exc)) from exc
        size = len(payload.encode('utf-8'))
        if self.pending and self.pending_bytes + size > self.max_bytes:
            self.flush()
        self.pending.append(json.loads(payload))
        self.pending_bytes += size
        if (len(self.pending) >= self.max_records or self.pending_bytes >= self.max_bytes
                or time.monotonic() - self.last_flush >= self.interval):
            self.flush()

    def flush(self):
        if self.failed:
            raise ResultStorageError('Result writer has failed')
        if not self.pending:
            return
        try:
            if self._db is None:
                self._context = self.store.connect()
                self._db = self._context.__enter__()
            with self._db:
                self.store._sync_legacy(self._db)
                if not self._db.in_transaction:
                    self._db.execute('BEGIN IMMEDIATE')
                for record in self.pending:
                    self.store._append(self._db, record)
            if not self.store.source.exists():
                self.store.source.touch()
            self.pending.clear()
            self.pending_bytes = 0
            self.last_flush = time.monotonic()
        except (OSError, sqlite3.Error, ValueError, TypeError, zlib.error) as exc:
            self.failed = True
            raise ResultStorageError('Cannot persist scan results: ' + str(exc)) from exc

    def close(self):
        try:
            if not self.failed:
                self.flush()
        finally:
            if self._db is not None:
                self._context.__exit__(None, None, None)
                self._db = None
