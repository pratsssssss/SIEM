"""Durable state in SQLite. A path's current form can change. Each version, the audit trail and analyst notes are
append-only by trigger, and chained by hash, so a change to what the engine concluded can always be seen.
"""
import hashlib
import json
import sqlite3
import threading

SCHEMA = """
CREATE TABLE IF NOT EXISTS paths (path_id TEXT PRIMARY KEY, seed_kind TEXT NOT NULL, seed_id TEXT NOT NULL, version INTEGER NOT NULL, tier TEXT NOT NULL, fingerprint TEXT NOT NULL, title TEXT NOT NULL, created_ms INTEGER NOT NULL, updated_ms INTEGER NOT NULL, validated_ms INTEGER, body TEXT NOT NULL, dirty INTEGER NOT NULL DEFAULT 1);
CREATE INDEX IF NOT EXISTS paths_updated ON paths (updated_ms);
CREATE TABLE IF NOT EXISTS path_assets (path_id TEXT NOT NULL, asset TEXT NOT NULL, PRIMARY KEY (path_id, asset));
CREATE INDEX IF NOT EXISTS path_assets_asset ON path_assets (asset);
CREATE TABLE IF NOT EXISTS history (seq INTEGER PRIMARY KEY AUTOINCREMENT, path_id TEXT NOT NULL, version INTEGER NOT NULL, at_ms INTEGER NOT NULL, why TEXT NOT NULL, summary TEXT NOT NULL, previous TEXT NOT NULL, hash TEXT NOT NULL, UNIQUE (path_id, version));
CREATE TRIGGER IF NOT EXISTS history_no_update BEFORE UPDATE ON history BEGIN SELECT RAISE(ABORT, 'path history is append-only'); END;
CREATE TRIGGER IF NOT EXISTS history_no_delete BEFORE DELETE ON history BEGIN SELECT RAISE(ABORT, 'path history is append-only'); END;
CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY AUTOINCREMENT, ts_ms INTEGER NOT NULL, path_id TEXT, actor TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL, previous TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
CREATE TABLE IF NOT EXISTS identity_links (id TEXT PRIMARY KEY, a TEXT NOT NULL, b TEXT NOT NULL, actor TEXT NOT NULL, reason TEXT NOT NULL, at_ms INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS queue (seed_kind TEXT NOT NULL, seed_id TEXT NOT NULL, due_ms INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (seed_kind, seed_id));
CREATE TABLE IF NOT EXISTS shipped (kind TEXT NOT NULL, key TEXT NOT NULL, PRIMARY KEY (kind, key));
CREATE TABLE IF NOT EXISTS marks (name TEXT PRIMARY KEY, value TEXT NOT NULL);
"""
GENESIS = '0' * 64
AUDIT_FIELDS = ('seq', 'ts_ms', 'path_id', 'actor', 'action', 'detail', 'previous', 'hash')
HISTORY_FIELDS = ('seq', 'path_id', 'version', 'at_ms', 'why', 'summary', 'previous', 'hash')


def chain(previous, payload):
    return hashlib.sha256((previous + json.dumps(payload, sort_keys=True, separators=(',', ':'))).encode()).hexdigest()


def escape_like(text):
    return text.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')


class Store:
    def __init__(self, path):
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, timeout=30, check_same_thread=False)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('PRAGMA cache_size=-2000')
        self.db.executescript(SCHEMA)

    def close(self):
        self.db.close()

    # Paths.
    def save(self, path, now, why):
        """'new', 'changed' or 'same'. A rebuild with the same meaning changes nothing, so repeats add no history."""
        with self.lock, self.db:
            row = self.db.execute('SELECT version, fingerprint, created_ms FROM paths WHERE path_id = ?', (path['path_id'],)).fetchone()
            if row and row[1] == path['fingerprint']:
                return 'same'
            version = row[0] + 1 if row else 1
            created = row[2] if row else now
            body = {**path, 'version': version, 'created_ms': created, 'updated_ms': now}
            self.db.execute('INSERT OR REPLACE INTO paths (path_id, seed_kind, seed_id, version, tier, fingerprint, title, created_ms, updated_ms, body, dirty) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)',
                            (path['path_id'], path['seed']['kind'], path['seed']['id'], version, path['tier'], path['fingerprint'], path['title'], created, now, json.dumps(body)))
            self.db.execute('DELETE FROM path_assets WHERE path_id = ?', (path['path_id'],))
            for item in path['nodes']:
                if item['type'] == 'asset':
                    self.db.execute('INSERT OR IGNORE INTO path_assets VALUES (?, ?)', (path['path_id'], item.get('asset_id') or item['display']))
            summary = {'tier': path['tier'], 'stages': len(path['stages']), 'edges': len(path['edges']), 'nodes': len(path['nodes']), 'gaps': [g['gap'] for g in path['gaps']], 'contradictions': len(path['contradictions']), 'analyst_status': path['analyst_status']}
            self._history(path['path_id'], version, now, why, summary)
            return 'changed' if row else 'new'

    def _history(self, path_id, version, now, why, summary):
        row = self.db.execute('SELECT hash FROM history ORDER BY seq DESC LIMIT 1').fetchone()
        previous = row[0] if row else GENESIS
        entry = {'path_id': path_id, 'version': version, 'at_ms': now, 'why': why, 'summary': summary}
        self.db.execute('INSERT INTO history (path_id, version, at_ms, why, summary, previous, hash) VALUES (?, ?, ?, ?, ?, ?, ?)', (path_id, version, now, why, json.dumps(summary, sort_keys=True), previous, chain(previous, entry)))

    def update_body(self, path, now):
        """Validation results sit beside the path. They change no version, and are recorded in audit."""
        with self.lock, self.db:
            self.db.execute('UPDATE paths SET body = ?, tier = ?, validated_ms = ?, dirty = 1 WHERE path_id = ?', (json.dumps(path), path['tier'], now, path['path_id']))

    def path(self, path_id):
        with self.lock:
            row = self.db.execute('SELECT body FROM paths WHERE path_id = ?', (path_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def find(self, prefix):
        with self.lock:
            rows = self.db.execute("SELECT path_id FROM paths WHERE path_id LIKE ? || '%' ESCAPE '\\' LIMIT 2", (escape_like(prefix),)).fetchall()
        return rows[0][0] if len(rows) == 1 else None

    def list(self, tier=None, limit=200):
        where, args = (' WHERE tier = ?', (tier,)) if tier else ('', ())
        names = ('path_id', 'seed_kind', 'seed_id', 'version', 'tier', 'title', 'updated_ms')
        with self.lock:
            return [dict(zip(names, r)) for r in self.db.execute(f"SELECT {','.join(names)} FROM paths{where} ORDER BY updated_ms DESC LIMIT ?", (*args, limit))]

    def search(self, text, limit=50):
        pattern = '%' + escape_like(text.lower()) + '%'
        names = ('path_id', 'seed_kind', 'seed_id', 'version', 'tier', 'title', 'updated_ms')
        with self.lock:
            return [dict(zip(names, r)) for r in self.db.execute(f"SELECT DISTINCT {','.join('p.' + n for n in names)} FROM paths p LEFT JOIN path_assets a USING (path_id) WHERE lower(p.title) LIKE ?1 ESCAPE '\\' OR p.seed_id LIKE ?1 ESCAPE '\\' OR lower(a.asset) LIKE ?1 ESCAPE '\\' LIMIT ?2", (pattern, limit))]

    def by_asset(self, asset):
        with self.lock:
            return [r[0] for r in self.db.execute('SELECT path_id FROM path_assets WHERE asset = ? LIMIT 200', (asset,))]

    def by_seed(self, kind, seed_id):
        with self.lock:
            row = self.db.execute('SELECT path_id FROM paths WHERE seed_kind = ? AND seed_id = ?', (kind, seed_id)).fetchone()
        return row[0] if row else None

    def oldest_validated(self, limit):
        with self.lock:
            return [r[0] for r in self.db.execute('SELECT path_id FROM paths ORDER BY COALESCE(validated_ms, 0) LIMIT ?', (limit,))]

    def count(self):
        with self.lock:
            return dict(self.db.execute('SELECT tier, COUNT(*) FROM paths GROUP BY tier').fetchall())

    def history(self, path_id):
        with self.lock:
            rows = self.db.execute(f"SELECT {','.join(HISTORY_FIELDS)} FROM history WHERE path_id = ? ORDER BY seq", (path_id,)).fetchall()
        return [{**dict(zip(HISTORY_FIELDS, r)), 'summary': json.loads(r[5])} for r in rows]

    def verify(self):
        previous, entries = GENESIS, 0
        with self.lock:
            rows = self.db.execute(f"SELECT {','.join(HISTORY_FIELDS)} FROM history ORDER BY seq").fetchall()
        for seq, path_id, version, at_ms, why, summary, before, stored in rows:
            entries += 1
            if before != previous or chain(previous, {'path_id': path_id, 'version': version, 'at_ms': at_ms, 'why': why, 'summary': json.loads(summary)}) != stored:
                return entries, seq
            previous = stored
        return entries, None

    # Queue. A seed appears once, however often it changes.
    def enqueue(self, kind, seed_id, due_ms):
        with self.lock, self.db:
            self.db.execute('INSERT INTO queue (seed_kind, seed_id, due_ms) VALUES (?, ?, ?) ON CONFLICT (seed_kind, seed_id) DO UPDATE SET due_ms = MIN(due_ms, excluded.due_ms), attempts = 0', (kind, seed_id, due_ms))

    def due(self, now, limit):
        with self.lock:
            return self.db.execute('SELECT seed_kind, seed_id, attempts FROM queue WHERE due_ms <= ? ORDER BY due_ms LIMIT ?', (now, limit)).fetchall()

    def done(self, kind, seed_id):
        with self.lock, self.db:
            self.db.execute('DELETE FROM queue WHERE seed_kind = ? AND seed_id = ?', (kind, seed_id))

    def retry(self, kind, seed_id, due_ms):
        with self.lock, self.db:
            self.db.execute('UPDATE queue SET attempts = attempts + 1, due_ms = ? WHERE seed_kind = ? AND seed_id = ?', (due_ms, kind, seed_id))

    def backlog(self):
        with self.lock:
            return self.db.execute('SELECT COUNT(*) FROM queue').fetchone()[0]

    def oldest_due(self, now):
        with self.lock:
            return self.db.execute('SELECT MIN(due_ms) FROM queue WHERE due_ms <= ?', (now,)).fetchone()[0]

    def evidence_state(self):
        """Totals from each path's last check. Expired and altered evidence mean different things, so they stay apart."""
        with self.lock:
            row = self.db.execute("SELECT SUM(json_extract(body, '$.validation.unavailable')), SUM(json_extract(body, '$.validation.changed')) FROM paths").fetchone()
        return {'unavailable': row[0] or 0, 'changed': row[1] or 0}

    # Identity links: only a person makes one.
    def link(self, link_id, a, b, actor, reason, now):
        with self.lock, self.db:
            self.db.execute('INSERT OR REPLACE INTO identity_links VALUES (?, ?, ?, ?, ?, ?)', (link_id, a, b, actor, reason, now))

    def links(self):
        names = ('id', 'a', 'b', 'actor', 'reason', 'at_ms')
        with self.lock:
            return [dict(zip(names, r)) for r in self.db.execute('SELECT id, a, b, actor, reason, at_ms FROM identity_links')]

    # Audit.
    def audit(self, path_id, now, actor, action, detail):
        with self.lock, self.db:
            row = self.db.execute('SELECT hash FROM audit ORDER BY seq DESC LIMIT 1').fetchone()
            previous = row[0] if row else GENESIS
            entry = {'ts_ms': now, 'path_id': path_id, 'actor': actor, 'action': action, 'detail': detail}
            self.db.execute('INSERT INTO audit (ts_ms, path_id, actor, action, detail, previous, hash) VALUES (?, ?, ?, ?, ?, ?, ?)', (now, path_id, actor, action, json.dumps(detail, sort_keys=True), previous, chain(previous, entry)))

    def audit_rows(self, path_id=None, limit=500):
        with self.lock:
            rows = self.db.execute(f"SELECT {','.join(AUDIT_FIELDS)} FROM audit" + (' WHERE path_id = ?' if path_id else '') + ' ORDER BY seq DESC LIMIT ?', (path_id, limit) if path_id else (limit,)).fetchall()
        return [{**dict(zip(AUDIT_FIELDS, r)), 'detail': json.loads(r[5])} for r in reversed(rows)]

    def verify_audit(self):
        previous, entries = GENESIS, 0
        with self.lock:
            rows = self.db.execute(f"SELECT {','.join(AUDIT_FIELDS)} FROM audit ORDER BY seq").fetchall()
        for seq, ts_ms, path_id, actor, action, detail, before, stored in rows:
            entries += 1
            if before != previous or chain(previous, {'ts_ms': ts_ms, 'path_id': path_id, 'actor': actor, 'action': action, 'detail': json.loads(detail)}) != stored:
                return entries, seq
            previous = stored
        return entries, None

    # Output to OpenSearch.
    def dirty(self, limit=25):
        with self.lock:
            return [json.loads(r[0]) for r in self.db.execute('SELECT body FROM paths WHERE dirty = 1 LIMIT ?', (limit,))]

    def clean(self, path_id, updated_ms):
        with self.lock, self.db:
            self.db.execute('UPDATE paths SET dirty = 0 WHERE path_id = ? AND updated_ms = ?', (path_id, updated_ms))

    def unshipped_history(self, limit=100):
        with self.lock:
            rows = self.db.execute(f"SELECT {','.join(HISTORY_FIELDS)} FROM history WHERE CAST(seq AS TEXT) NOT IN (SELECT key FROM shipped WHERE kind = 'history') ORDER BY seq LIMIT ?", (limit,)).fetchall()
        return [{**dict(zip(HISTORY_FIELDS, r)), 'summary': json.loads(r[5])} for r in rows]

    def unshipped_audit(self, limit=100):
        with self.lock:
            rows = self.db.execute(f"SELECT {','.join(AUDIT_FIELDS)} FROM audit WHERE CAST(seq AS TEXT) NOT IN (SELECT key FROM shipped WHERE kind = 'audit') ORDER BY seq LIMIT ?", (limit,)).fetchall()
        return [{**dict(zip(AUDIT_FIELDS, r)), 'detail': json.loads(r[5])} for r in rows]

    def shipped(self, kind, key):
        with self.lock, self.db:
            self.db.execute('INSERT OR IGNORE INTO shipped VALUES (?, ?)', (kind, str(key)))

    def output_backlog(self):
        with self.lock:
            paths = self.db.execute('SELECT COUNT(*) FROM paths WHERE dirty = 1').fetchone()[0]
            history = self.db.execute("SELECT COUNT(*) FROM history WHERE CAST(seq AS TEXT) NOT IN (SELECT key FROM shipped WHERE kind = 'history')").fetchone()[0]
            audit = self.db.execute("SELECT COUNT(*) FROM audit WHERE CAST(seq AS TEXT) NOT IN (SELECT key FROM shipped WHERE kind = 'audit')").fetchone()[0]
        return {'paths': paths, 'history': history, 'audit': audit}

    def mark(self, name, default=None):
        with self.lock:
            row = self.db.execute('SELECT value FROM marks WHERE name = ?', (name,)).fetchone()
        return row[0] if row else default

    def set_mark(self, name, value):
        with self.lock, self.db:
            self.db.execute('INSERT OR REPLACE INTO marks VALUES (?, ?)', (name, str(value)))
