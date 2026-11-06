"""Durable state in SQLite. An alert is committed here before its Kafka offset, and an incident change
commits with its timeline and audit entries, so a crash can repeat work but cannot lose or half-apply it.
"""
import hashlib
import json
import sqlite3
import threading

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
  alert_id TEXT PRIMARY KEY, kind TEXT NOT NULL DEFAULT 'alert', rule_id TEXT NOT NULL, body TEXT NOT NULL, received_ms INTEGER NOT NULL,
  first_ms INTEGER, last_ms INTEGER, status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0, next_ms INTEGER NOT NULL DEFAULT 0,
  context TEXT, enrichment TEXT NOT NULL DEFAULT 'pending', source TEXT NOT NULL DEFAULT 'kafka'
);
CREATE INDEX IF NOT EXISTS alerts_due ON alerts (status, next_ms);
CREATE TABLE IF NOT EXISTS alert_entities (entity TEXT NOT NULL, alert_id TEXT NOT NULL, first_ms INTEGER NOT NULL, PRIMARY KEY (entity, alert_id)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS alert_entities_time ON alert_entities (entity, first_ms);
CREATE TABLE IF NOT EXISTS links (source TEXT NOT NULL, relation TEXT NOT NULL, target TEXT NOT NULL, alert_id TEXT NOT NULL, PRIMARY KEY (source, relation, target, alert_id)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS links_target ON links (target, relation);
CREATE TABLE IF NOT EXISTS quarantine (id INTEGER PRIMARY KEY, received_ms INTEGER NOT NULL, reason TEXT NOT NULL, partition INTEGER, offset INTEGER, sha256 TEXT NOT NULL, size INTEGER NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS quarantine_place ON quarantine (partition, offset);
CREATE TABLE IF NOT EXISTS incidents (
  incident_id TEXT PRIMARY KEY, status TEXT NOT NULL, first_ms INTEGER NOT NULL, last_ms INTEGER NOT NULL, created_ms INTEGER NOT NULL, updated_ms INTEGER NOT NULL,
  severity TEXT NOT NULL, revision INTEGER NOT NULL, body TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS incidents_status ON incidents (status, last_ms);
CREATE TABLE IF NOT EXISTS incident_keys (rule_id TEXT NOT NULL, entity TEXT NOT NULL, incident_id TEXT NOT NULL, PRIMARY KEY (rule_id, entity, incident_id)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS incident_alerts (alert_id TEXT NOT NULL, incident_id TEXT NOT NULL, PRIMARY KEY (alert_id, incident_id)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS incident_alerts_incident ON incident_alerts (incident_id);
CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY, incident_id TEXT, ts_ms INTEGER NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL, prev TEXT NOT NULL, hash TEXT NOT NULL, shipped INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS audit_incident ON audit (incident_id, seq);
CREATE INDEX IF NOT EXISTS audit_unshipped ON audit (shipped, seq);
CREATE TABLE IF NOT EXISTS outbox (incident_id TEXT PRIMARY KEY, revision INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS rule_state (rule_id TEXT PRIMARY KEY, enabled INTEGER NOT NULL, matches INTEGER NOT NULL DEFAULT 0, last_ms INTEGER);
CREATE TABLE IF NOT EXISTS marks (name TEXT PRIMARY KEY, ms INTEGER NOT NULL);
"""


class Store:
    def __init__(self, path):
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, timeout=30, check_same_thread=False)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('PRAGMA cache_size=-4000')
        self.db.executescript(SCHEMA)

    def close(self):
        self.db.close()

    # Intake.
    def inbox(self, alert_id, rule_id, body, now, kind='alert', source='kafka'):
        """Stores once. Returns False for a repeat, so duplicate delivery does nothing."""
        with self.lock, self.db:
            return self.db.execute('INSERT OR IGNORE INTO alerts (alert_id, kind, rule_id, body, received_ms, source) VALUES (?, ?, ?, ?, ?, ?)',
                                   (alert_id, kind, rule_id, json.dumps(body), now, source)).rowcount == 1

    def quarantine(self, now, reason, partition, offset, digest, size):
        with self.lock, self.db:
            self.db.execute('INSERT OR IGNORE INTO quarantine (received_ms, reason, partition, offset, sha256, size) VALUES (?, ?, ?, ?, ?, ?)', (now, reason, partition, offset, digest, size))

    def quarantined(self):
        with self.lock:
            return [dict(zip(('received_ms', 'reason', 'partition', 'offset', 'sha256', 'size'), r)) for r in self.db.execute('SELECT received_ms, reason, partition, offset, sha256, size FROM quarantine ORDER BY id')]

    def due(self, now, limit=100):
        with self.lock:
            return [(r[0], r[1], json.loads(r[2])) for r in self.db.execute("SELECT alert_id, kind, body FROM alerts WHERE status = 'pending' AND next_ms <= ? ORDER BY received_ms, alert_id LIMIT ?", (now, limit))]

    def retry_later(self, alert_id, next_ms):
        with self.lock, self.db:
            self.db.execute('UPDATE alerts SET attempts = attempts + 1, next_ms = ? WHERE alert_id = ?', (next_ms, alert_id))

    def fail(self, alert_id):
        """An alert that cannot be analysed stays stored, and health reports it."""
        with self.lock, self.db:
            self.db.execute("UPDATE alerts SET status = 'failed' WHERE alert_id = ?", (alert_id,))

    def analysed(self, alert_id, first_ms, last_ms, context, entities, links, enrichment):
        """Records what is known of an alert. Runs inside the caller's transaction."""
        self.db.execute("UPDATE alerts SET status = 'done', first_ms = ?, last_ms = ?, context = ?, enrichment = ? WHERE alert_id = ?", (first_ms, last_ms, json.dumps(context), enrichment, alert_id))
        self.db.executemany('INSERT OR IGNORE INTO alert_entities VALUES (?, ?, ?)', ((e, alert_id, first_ms) for e in entities))
        self.db.executemany('INSERT OR IGNORE INTO links VALUES (?, ?, ?, ?)', ((s, r, t, alert_id) for s, r, t in links))

    def context(self, alert_id):
        with self.lock:
            row = self.db.execute('SELECT context FROM alerts WHERE alert_id = ?', (alert_id,)).fetchone()
        return json.loads(row[0]) if row and row[0] else None

    def contexts(self, ids):
        with self.lock:
            marks = ','.join('?' * len(ids))
            return {r[0]: json.loads(r[1]) for r in self.db.execute(f'SELECT alert_id, context FROM alerts WHERE alert_id IN ({marks}) AND context IS NOT NULL', ids)} if ids else {}

    def near(self, entity, start_ms, end_ms, limit=500):
        """Alerts on one entity inside a window, oldest first, with a bound so one noisy entity costs little."""
        with self.lock:
            return [r[0] for r in self.db.execute('SELECT alert_id FROM alert_entities WHERE entity = ? AND first_ms BETWEEN ? AND ? ORDER BY first_ms, alert_id LIMIT ?', (entity, start_ms, end_ms, limit))]

    def children(self, parent):
        with self.lock:
            return [r[0] for r in self.db.execute("SELECT DISTINCT target FROM links WHERE source = ? AND relation = 'spawned'", (parent,))]

    def enrichment_waiting(self, now, older_than_ms, limit=50):
        """Alerts whose enrichment had not arrived, for a later look."""
        with self.lock:
            return [r[0] for r in self.db.execute("SELECT alert_id FROM alerts WHERE status = 'done' AND kind = 'alert' AND enrichment = 'pending' AND received_ms <= ? ORDER BY received_ms LIMIT ?", (now - older_than_ms, limit))]

    def set_enrichment(self, alert_id, state):
        with self.lock, self.db:
            self.db.execute('UPDATE alerts SET enrichment = ? WHERE alert_id = ?', (state, alert_id))

    def counts(self):
        with self.lock:
            return dict(self.db.execute('SELECT status, COUNT(*) FROM alerts GROUP BY status'))

    # Incidents.
    def incident(self, incident_id):
        with self.lock:
            row = self.db.execute('SELECT body FROM incidents WHERE incident_id = ?', (incident_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def save_incident(self, incident):
        """Within the caller's transaction. The outbox entry goes in with it."""
        self.db.execute(
            'INSERT INTO incidents (incident_id, status, first_ms, last_ms, created_ms, updated_ms, severity, revision, body) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) '
            'ON CONFLICT(incident_id) DO UPDATE SET status = excluded.status, first_ms = excluded.first_ms, last_ms = excluded.last_ms, updated_ms = excluded.updated_ms, severity = excluded.severity, revision = excluded.revision, body = excluded.body',
            (incident['incident_id'], incident['status'], incident['first_ms'], incident['last_ms'], incident['created_ms'], incident['updated_ms'], incident['severity'], incident['revision'], json.dumps(incident)))
        self.db.execute('INSERT OR REPLACE INTO outbox VALUES (?, ?)', (incident['incident_id'], incident['revision']))
        self.db.executemany('INSERT OR IGNORE INTO incident_alerts VALUES (?, ?)', ((a, incident['incident_id']) for a in incident['alert_ids'] + incident.get('signal_ids', [])))

    def key_incidents(self, rule_id, entity):
        with self.lock:
            return [r[0] for r in self.db.execute('SELECT incident_id FROM incident_keys WHERE rule_id = ? AND entity = ?', (rule_id, entity))]

    def add_key(self, rule_id, entity, incident_id):
        self.db.execute('INSERT OR IGNORE INTO incident_keys VALUES (?, ?, ?)', (rule_id, entity, incident_id))

    def incidents_of(self, alert_ids):
        with self.lock:
            marks = ','.join('?' * len(alert_ids))
            return [r[0] for r in self.db.execute(f'SELECT DISTINCT incident_id FROM incident_alerts WHERE alert_id IN ({marks})', alert_ids)] if alert_ids else []

    def list_incidents(self, status=None, limit=50):
        where, args = (' WHERE status = ?', [status]) if status else ('', [])
        with self.lock:
            return [json.loads(r[0]) for r in self.db.execute(f'SELECT body FROM incidents{where} ORDER BY last_ms DESC LIMIT ?', [*args, limit])]

    def outbox(self, limit=100):
        with self.lock:
            return [json.loads(r[0]) for r in self.db.execute('SELECT i.body FROM outbox o JOIN incidents i USING (incident_id) ORDER BY i.updated_ms LIMIT ?', (limit,))]

    def shipped(self, incident_id, revision):
        with self.lock, self.db:
            self.db.execute('DELETE FROM outbox WHERE incident_id = ? AND revision = ?', (incident_id, revision))

    def outbox_size(self):
        with self.lock:
            return self.db.execute('SELECT COUNT(*) FROM outbox').fetchone()[0]

    # Audit: a hash chain, so a changed or removed entry shows.
    def audit(self, incident_id, ts_ms, actor, action, detail):
        row = self.db.execute('SELECT hash FROM audit ORDER BY seq DESC LIMIT 1').fetchone()
        previous = row[0] if row else '0' * 64
        text = json.dumps(detail, sort_keys=True)
        digest = hashlib.sha256('|'.join((previous, str(incident_id), str(ts_ms), actor, action, text)).encode()).hexdigest()
        self.db.execute('INSERT INTO audit (incident_id, ts_ms, actor, action, detail, prev, hash) VALUES (?, ?, ?, ?, ?, ?, ?)', (incident_id, ts_ms, actor, action, text, previous, digest))

    def audit_rows(self, incident_id=None, limit=200):
        where, args = (' WHERE incident_id = ?', [incident_id]) if incident_id else ('', [])
        with self.lock:
            rows = self.db.execute(f'SELECT seq, incident_id, ts_ms, actor, action, detail, hash FROM audit{where} ORDER BY seq DESC LIMIT ?', [*args, limit]).fetchall()
        return [dict(zip(('seq', 'incident_id', 'ts_ms', 'actor', 'action', 'detail', 'hash'), (*r[:5], json.loads(r[5]), r[6]))) for r in reversed(rows)]

    def audit_verify(self):
        """Walks the chain. Returns (entries, first broken sequence or None)."""
        previous, count = '0' * 64, 0
        with self.lock:
            for seq, incident_id, ts_ms, actor, action, detail, prev, digest in self.db.execute('SELECT seq, incident_id, ts_ms, actor, action, detail, prev, hash FROM audit ORDER BY seq'):
                count += 1
                if prev != previous or digest != hashlib.sha256('|'.join((previous, str(incident_id), str(ts_ms), actor, action, detail)).encode()).hexdigest():
                    return count, seq
                previous = digest
        return count, None

    def audit_unshipped(self, limit=200):
        with self.lock:
            rows = self.db.execute('SELECT seq, incident_id, ts_ms, actor, action, detail, prev, hash FROM audit WHERE shipped = 0 ORDER BY seq LIMIT ?', (limit,)).fetchall()
        return [dict(zip(('seq', 'incident_id', 'ts_ms', 'actor', 'action', 'detail', 'prev', 'hash'), (*r[:5], json.loads(r[5]), r[6], r[7]))) for r in rows]

    def audit_shipped(self, seq):
        with self.lock, self.db:
            self.db.execute('UPDATE audit SET shipped = 1 WHERE seq = ?', (seq,))

    # Rules and marks.
    def rule_enabled(self, rule_id, default):
        with self.lock:
            row = self.db.execute('SELECT enabled FROM rule_state WHERE rule_id = ?', (rule_id,)).fetchone()
        return bool(row[0]) if row else default

    def set_rule(self, rule_id, enabled):
        self.db.execute('INSERT INTO rule_state (rule_id, enabled) VALUES (?, ?) ON CONFLICT(rule_id) DO UPDATE SET enabled = excluded.enabled', (rule_id, int(enabled)))

    def rule_hit(self, rule_id, now):
        self.db.execute('INSERT INTO rule_state (rule_id, enabled, matches, last_ms) VALUES (?, 1, 1, ?) ON CONFLICT(rule_id) DO UPDATE SET matches = matches + 1, last_ms = excluded.last_ms', (rule_id, now))

    def rule_stats(self):
        with self.lock:
            return {r[0]: {'matches': r[1], 'last_ms': r[2]} for r in self.db.execute('SELECT rule_id, matches, last_ms FROM rule_state')}

    def mark(self, name, default=None):
        with self.lock:
            row = self.db.execute('SELECT ms FROM marks WHERE name = ?', (name,)).fetchone()
        return row[0] if row else default

    def set_mark(self, name, value):
        with self.lock, self.db:
            self.db.execute('INSERT OR REPLACE INTO marks VALUES (?, ?)', (name, value))

    def prune(self, before_ms):
        """Removes the working data of old alerts that no open incident needs. Incidents and audit stay."""
        with self.lock, self.db:
            old = "SELECT alert_id FROM alerts WHERE status = 'done' AND received_ms < ? AND alert_id NOT IN (SELECT ia.alert_id FROM incident_alerts ia JOIN incidents i USING (incident_id) WHERE i.status NOT IN ('resolved', 'closed', 'false_positive'))"
            self.db.execute(f'DELETE FROM alert_entities WHERE alert_id IN ({old})', (before_ms,))
            self.db.execute(f'DELETE FROM links WHERE alert_id IN ({old})', (before_ms,))
            return self.db.execute(f'DELETE FROM alerts WHERE alert_id IN ({old})', (before_ms,)).rowcount
