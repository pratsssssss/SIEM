"""Durable health state. One local SQLite file: current state, history, bounded metrics, and an outbox.

Transitions can only be added, and each carries the hash of the one before. Rows past retention may be deleted, and
`chain_base` then records where the chain starts. The rollback journal is kept, not WAL, so that a read-only analyst
connection needs no write access to anything.
"""
import hashlib
import json
import os
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS components (component TEXT PRIMARY KEY, status TEXT NOT NULL, previous TEXT, since_ms INTEGER NOT NULL, pending TEXT, pending_count INTEGER NOT NULL DEFAULT 0, condition TEXT, body TEXT NOT NULL, updated_ms INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS transitions (seq INTEGER PRIMARY KEY AUTOINCREMENT, component TEXT NOT NULL, from_status TEXT, to_status TEXT NOT NULL, at_ms INTEGER NOT NULL, body TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL UNIQUE);
CREATE INDEX IF NOT EXISTS transitions_component ON transitions (component, at_ms);
CREATE TRIGGER IF NOT EXISTS transitions_no_update BEFORE UPDATE ON transitions BEGIN SELECT RAISE(ABORT, 'history is append only'); END;
CREATE TRIGGER IF NOT EXISTS transitions_no_early_delete BEFORE DELETE ON transitions WHEN old.at_ms > (CAST(strftime('%s', 'now') AS INTEGER) - 2592000) * 1000 BEGIN SELECT RAISE(ABORT, 'history younger than 30 days cannot be removed'); END;
CREATE TABLE IF NOT EXISTS episodes (episode_id TEXT PRIMARY KEY, component TEXT NOT NULL, kind TEXT NOT NULL, started_ms INTEGER NOT NULL, ended_ms INTEGER, worst TEXT NOT NULL, first_reason TEXT NOT NULL, last_reason TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS episodes_open ON episodes (component, ended_ms);
CREATE TABLE IF NOT EXISTS samples (minute_ms INTEGER NOT NULL, metric TEXT NOT NULL, value REAL NOT NULL, PRIMARY KEY (minute_ms, metric)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS hourly (hour_ms INTEGER NOT NULL, metric TEXT NOT NULL, samples INTEGER NOT NULL, low REAL NOT NULL, high REAL NOT NULL, mean REAL NOT NULL, last REAL NOT NULL, PRIMARY KEY (hour_ms, metric)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS diagnostics (component TEXT NOT NULL, at_ms INTEGER NOT NULL, body TEXT NOT NULL, PRIMARY KEY (component, at_ms)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS outbox (doc_id TEXT PRIMARY KEY, kind TEXT NOT NULL, doc_index TEXT NOT NULL, body TEXT NOT NULL, added_ms INTEGER NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS marks (name TEXT PRIMARY KEY, value TEXT NOT NULL);
"""
GENESIS = '0' * 64


def digest(previous, body):
    return hashlib.sha256((previous + body).encode()).hexdigest()


class Store:
    def __init__(self, path, read_only=False):
        self.path = path
        if read_only:
            self.db = sqlite3.connect(f'file:{path}?mode=ro', uri=True, timeout=5, isolation_level=None)
            self.db.execute('PRAGMA query_only = ON')
            return
        old = os.umask(0o027)
        try:
            self.db = sqlite3.connect(path, timeout=10, isolation_level=None)
        finally:
            os.umask(old)
        self.db.execute('PRAGMA journal_mode = DELETE')
        self.db.execute('PRAGMA synchronous = FULL')
        self.db.execute('PRAGMA temp_store = MEMORY')
        self.db.execute('PRAGMA cache_size = -1024')
        self.db.executescript(SCHEMA)

    def close(self):
        self.db.close()

    def transaction(self):
        return _Transaction(self.db)

    # Marks.
    def mark(self, name, default=None):
        row = self.db.execute('SELECT value FROM marks WHERE name = ?', (name,)).fetchone()
        return json.loads(row[0]) if row else default

    def set_mark(self, name, value):
        self.db.execute('INSERT INTO marks (name, value) VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET value = excluded.value', (name, json.dumps(value, separators=(',', ':'))))

    # Current state.
    def records(self):
        rows = self.db.execute('SELECT component, status, previous, since_ms, pending, pending_count, condition FROM components').fetchall()
        return {r[0]: {'status': r[1], 'previous': r[2], 'since_ms': r[3], 'pending': r[4], 'pending_count': r[5], 'condition': r[6]} for r in rows}

    def components(self):
        return {r[0]: {**json.loads(r[1]), 'updated_ms': r[2]} for r in self.db.execute('SELECT component, body, updated_ms FROM components ORDER BY component')}

    def component(self, name):
        row = self.db.execute('SELECT body, updated_ms FROM components WHERE component = ?', (name,)).fetchone()
        return {**json.loads(row[0]), 'updated_ms': row[1]} if row else None

    def forget_components(self, keep):
        """Removes current-state rows for components no longer assessed, so a retired one does not linger. History stays."""
        gone = [r[0] for r in self.db.execute('SELECT component FROM components') if r[0] not in keep]
        for name in gone:
            self.db.execute('DELETE FROM components WHERE component = ?', (name,))
        return gone

    def save_component(self, name, record, body, now):
        self.db.execute("""INSERT INTO components (component, status, previous, since_ms, pending, pending_count, condition, body, updated_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(component) DO UPDATE SET status = excluded.status, previous = excluded.previous, since_ms = excluded.since_ms, pending = excluded.pending, pending_count = excluded.pending_count,
            condition = excluded.condition, body = excluded.body, updated_ms = excluded.updated_ms""",
                        (name, record['status'], record['previous'], record['since_ms'], record['pending'], record['pending_count'], record['condition'], json.dumps(body, separators=(',', ':')), now))

    # History.
    def add_transition(self, component, from_status, to_status, at_ms, body):
        text = json.dumps({'component': component, 'from': from_status, 'to': to_status, 'at_ms': at_ms, **body}, sort_keys=True, separators=(',', ':'))
        last = self.db.execute('SELECT hash FROM transitions ORDER BY seq DESC LIMIT 1').fetchone()
        previous = last[0] if last else self.mark('chain_base', GENESIS)
        current = digest(previous, text)
        self.db.execute('INSERT INTO transitions (component, from_status, to_status, at_ms, body, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?)', (component, from_status, to_status, at_ms, text, previous, current))
        return current

    def transitions(self, component=None, since_ms=0, limit=200):
        query = 'SELECT seq, body FROM transitions WHERE at_ms >= ?'
        values = [since_ms]
        if component:
            query += ' AND component = ?'
            values.append(component)
        rows = self.db.execute(query + ' ORDER BY seq DESC LIMIT ?', (*values, limit)).fetchall()
        return [{'seq': r[0], **json.loads(r[1])} for r in rows]

    def recent_transitions(self, component, since_ms):
        return self.db.execute('SELECT COUNT(*) FROM transitions WHERE component = ? AND at_ms >= ?', (component, since_ms)).fetchone()[0]

    def verify_chain(self):
        previous = self.mark('chain_base', GENESIS)
        count = 0
        for seq, body, stored_previous, stored in self.db.execute('SELECT seq, body, prev_hash, hash FROM transitions ORDER BY seq'):
            if stored_previous != previous or digest(previous, body) != stored:
                return {'intact': False, 'rows': count, 'first_broken': seq}
            previous = stored
            count += 1
        return {'intact': True, 'rows': count, 'first_broken': None}

    # Episodes: a stretch of one component being below healthy.
    def open_episode(self, component):
        row = self.db.execute('SELECT episode_id, kind, started_ms, worst FROM episodes WHERE component = ? AND ended_ms IS NULL', (component,)).fetchone()
        return dict(zip(('episode_id', 'kind', 'started_ms', 'worst'), row)) if row else None

    def start_episode(self, component, kind, started_ms, worst, reason):
        episode = hashlib.sha256(f'{component}|{started_ms}'.encode()).hexdigest()[:32]
        self.db.execute('INSERT OR IGNORE INTO episodes (episode_id, component, kind, started_ms, worst, first_reason, last_reason) VALUES (?, ?, ?, ?, ?, ?, ?)', (episode, component, kind, started_ms, worst, reason, reason))
        return episode

    def update_episode(self, episode_id, kind, worst, reason):
        self.db.execute('UPDATE episodes SET kind = ?, worst = ?, last_reason = ? WHERE episode_id = ?', (kind, worst, reason, episode_id))

    def end_episode(self, episode_id, ended_ms, reason):
        self.db.execute('UPDATE episodes SET ended_ms = ?, last_reason = ? WHERE episode_id = ?', (ended_ms, reason, episode_id))

    def episode(self, episode_id):
        row = self.db.execute('SELECT episode_id, component, kind, started_ms, ended_ms, worst, first_reason, last_reason FROM episodes WHERE episode_id = ?', (episode_id,)).fetchone()
        return dict(zip(('episode_id', 'component', 'kind', 'started_ms', 'ended_ms', 'worst', 'first_reason', 'last_reason'), row)) if row else None

    def episodes(self, since_ms=0, only_open=False, limit=100):
        query = 'SELECT episode_id, component, kind, started_ms, ended_ms, worst, first_reason, last_reason FROM episodes WHERE (ended_ms IS NULL OR ended_ms >= ?)'
        if only_open:
            query += ' AND ended_ms IS NULL'
        rows = self.db.execute(query + ' ORDER BY started_ms DESC LIMIT ?', (since_ms, limit)).fetchall()
        return [dict(zip(('episode_id', 'component', 'kind', 'started_ms', 'ended_ms', 'worst', 'first_reason', 'last_reason'), r)) for r in rows]

    # Metrics. The primary key makes a repeated minute a no-op, so a replayed cycle cannot double count.
    def add_samples(self, minute_ms, metrics):
        self.db.executemany('INSERT OR IGNORE INTO samples (minute_ms, metric, value) VALUES (?, ?, ?)', [(minute_ms, k, v) for k, v in sorted(metrics.items())])

    def series(self, metric, since_ms, limit=2880):
        rows = self.db.execute('SELECT minute_ms, value FROM samples WHERE metric = ? AND minute_ms >= ? ORDER BY minute_ms DESC LIMIT ?', (metric, since_ms, limit)).fetchall()
        return list(reversed(rows))

    def latest_samples(self):
        row = self.db.execute('SELECT MAX(minute_ms) FROM samples').fetchone()
        if not row or row[0] is None:
            return None, {}
        since = row[0] - 900000
        found = {}
        for metric, value, minute in self.db.execute('SELECT metric, value, minute_ms FROM samples WHERE minute_ms >= ? ORDER BY minute_ms', (since,)):
            found[metric] = {'value': value, 'at_ms': minute}
        return row[0], found

    def hourly(self, metric, since_ms, limit=720):
        rows = self.db.execute('SELECT hour_ms, samples, low, high, mean, last FROM hourly WHERE metric = ? AND hour_ms >= ? ORDER BY hour_ms LIMIT ?', (metric, since_ms, limit)).fetchall()
        return [dict(zip(('hour_ms', 'samples', 'low', 'high', 'mean', 'last'), r)) for r in rows]

    def roll_up(self, before_ms):
        """Folds whole past hours into aggregates. Repeating it gives the same rows."""
        self.db.execute("""INSERT OR REPLACE INTO hourly (hour_ms, metric, samples, low, high, mean, last)
            SELECT minute_ms / 3600000 * 3600000 AS hour, metric, COUNT(*), MIN(value), MAX(value), AVG(value),
                   (SELECT s.value FROM samples s WHERE s.metric = samples.metric AND s.minute_ms / 3600000 = samples.minute_ms / 3600000 ORDER BY s.minute_ms DESC LIMIT 1)
            FROM samples WHERE minute_ms < ? GROUP BY hour, metric""", (before_ms - before_ms % 3600000,))

    # Diagnostics.
    def add_diagnostic(self, component, at_ms, body):
        self.db.execute('INSERT OR IGNORE INTO diagnostics (component, at_ms, body) VALUES (?, ?, ?)', (component, at_ms, json.dumps(body, separators=(',', ':'))))

    def diagnostics(self, component, limit=20):
        return [{'at_ms': r[0], **json.loads(r[1])} for r in self.db.execute('SELECT at_ms, body FROM diagnostics WHERE component = ? ORDER BY at_ms DESC LIMIT ?', (component, limit))]

    # Outbox. A repeat of a document changes nothing, because the ID is the document's identity.
    def queue(self, doc_id, kind, index, body, now):
        self.db.execute('INSERT OR REPLACE INTO outbox (doc_id, kind, doc_index, body, added_ms) VALUES (?, ?, ?, ?, ?)', (doc_id, kind, index, json.dumps(body, separators=(',', ':')), now))

    def queued(self, limit):
        return self.db.execute('SELECT doc_id, kind, doc_index, body FROM outbox ORDER BY added_ms, doc_id LIMIT ?', (limit,)).fetchall()

    def done(self, doc_ids):
        self.db.executemany('DELETE FROM outbox WHERE doc_id = ?', [(d,) for d in doc_ids])

    def outbox_size(self):
        return self.db.execute('SELECT COUNT(*) FROM outbox').fetchone()[0]

    def trim_outbox(self, limit):
        """Bounds the outbox during a long outage. Metric documents go first. History stays, and is local in any case."""
        over = self.outbox_size() - limit
        if over <= 0:
            return 0
        rows = self.db.execute("SELECT doc_id FROM outbox ORDER BY kind = 'metrics' DESC, kind = 'current' DESC, added_ms LIMIT ?", (over,)).fetchall()
        self.done([r[0] for r in rows])
        return len(rows)

    # Retention.
    def prune(self, now, settings):
        removed = {}
        removed['samples'] = self.db.execute('DELETE FROM samples WHERE minute_ms < ?', (now - settings['samples_hours'] * 3600000,)).rowcount
        removed['hourly'] = self.db.execute('DELETE FROM hourly WHERE hour_ms < ?', (now - settings['hourly_days'] * 86400000,)).rowcount
        removed['diagnostics'] = self.db.execute('DELETE FROM diagnostics WHERE at_ms < ?', (now - settings['diagnostics_days'] * 86400000,)).rowcount
        removed['episodes'] = self.db.execute('DELETE FROM episodes WHERE ended_ms IS NOT NULL AND ended_ms < ?', (now - settings['transitions_days'] * 86400000,)).rowcount
        cutoff = now - settings['transitions_days'] * 86400000
        last = self.db.execute('SELECT hash FROM transitions WHERE at_ms < ? ORDER BY seq DESC LIMIT 1', (cutoff,)).fetchone()
        if last:
            self.set_mark('chain_base', last[0])
            removed['transitions'] = self.db.execute('DELETE FROM transitions WHERE at_ms < ?', (cutoff,)).rowcount
        return removed

    def size(self):
        tables = ('components', 'transitions', 'episodes', 'samples', 'hourly', 'diagnostics', 'outbox')
        return {t: self.db.execute(f'SELECT COUNT(*) FROM {t}').fetchone()[0] for t in tables}


class _Transaction:
    def __init__(self, db):
        self.db = db

    def __enter__(self):
        self.db.execute('BEGIN IMMEDIATE')
        return self

    def __exit__(self, kind, value, trace):
        self.db.execute('COMMIT' if kind is None else 'ROLLBACK')
        return False
