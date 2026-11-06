"""Durable state in SQLite. Alerts and the watermark commit together, so a crash cannot lose a
detection or skip events: at worst the window runs again, and the same alert IDs are ignored.
"""
import json
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS rule_state (
  rule_id TEXT PRIMARY KEY, watermark_ms INTEGER NOT NULL, last_run_ms INTEGER, next_run_ms INTEGER NOT NULL DEFAULT 0,
  failures INTEGER NOT NULL DEFAULT 0, last_error TEXT, alerts INTEGER NOT NULL DEFAULT 0,
  suppressed INTEGER NOT NULL DEFAULT 0, events INTEGER NOT NULL DEFAULT 0, last_duration_ms INTEGER
);
CREATE TABLE IF NOT EXISTS alerts (
  alert_id TEXT PRIMARY KEY, rule_id TEXT NOT NULL, created_ms INTEGER NOT NULL, full_json TEXT, safe_json TEXT NOT NULL,
  index_done INTEGER NOT NULL DEFAULT 0, kafka_done INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT
);
CREATE INDEX IF NOT EXISTS alerts_pending ON alerts (kafka_done, index_done, created_ms);
"""


class State:
    def __init__(self, path):
        self.db = sqlite3.connect(path, timeout=30)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript(SCHEMA)

    def close(self):
        self.db.close()

    def rule(self, rule_id, now_ms, lookback_ms):
        row = self.db.execute('SELECT watermark_ms, next_run_ms, failures FROM rule_state WHERE rule_id = ?', (rule_id,)).fetchone()
        if row is None:
            with self.db:
                self.db.execute('INSERT INTO rule_state (rule_id, watermark_ms) VALUES (?, ?)', (rule_id, now_ms - lookback_ms))
            return now_ms - lookback_ms, 0, 0
        return row

    def commit_run(self, rule_id, watermark_ms, pairs, now_ms, next_run_ms, events, duration_ms):
        """Adds new alerts and moves the watermark in one transaction. Returns (new, duplicates)."""
        new = 0
        with self.db:
            for alert_id, full, safe in pairs:
                cursor = self.db.execute(
                    'INSERT OR IGNORE INTO alerts (alert_id, rule_id, created_ms, full_json, safe_json) VALUES (?, ?, ?, ?, ?)',
                    (alert_id, rule_id, now_ms, json.dumps(full), json.dumps(safe)))
                new += cursor.rowcount
            self.db.execute(
                'UPDATE rule_state SET watermark_ms = MAX(watermark_ms, ?), last_run_ms = ?, next_run_ms = ?, failures = 0, last_error = NULL, '
                'alerts = alerts + ?, suppressed = suppressed + ?, events = events + ?, last_duration_ms = ? WHERE rule_id = ?',
                (watermark_ms, now_ms, next_run_ms, new, len(pairs) - new, events, duration_ms, rule_id))
        return new, len(pairs) - new

    def record_failure(self, rule_id, error, now_ms, retry_ms):
        with self.db:
            self.db.execute('UPDATE rule_state SET failures = failures + 1, last_error = ?, last_run_ms = ?, next_run_ms = ? WHERE rule_id = ?',
                            (str(error)[:300], now_ms, retry_ms, rule_id))

    def set_watermark(self, rule_id, watermark_ms):
        with self.db:
            self.db.execute('UPDATE rule_state SET watermark_ms = ?, next_run_ms = 0 WHERE rule_id = ?', (watermark_ms, rule_id))

    def pending(self, limit=200):
        return self.db.execute(
            'SELECT alert_id, full_json, safe_json, index_done, kafka_done, attempts FROM alerts '
            'WHERE index_done = 0 OR kafka_done = 0 ORDER BY created_ms, alert_id LIMIT ?', (limit,)).fetchall()

    def mark_index(self, alert_id):
        """The full text is now in OpenSearch, so the local copy is removed."""
        with self.db:
            self.db.execute('UPDATE alerts SET index_done = 1, full_json = NULL, last_error = NULL WHERE alert_id = ?', (alert_id,))

    def mark_kafka(self, alert_id):
        with self.db:
            self.db.execute('UPDATE alerts SET kafka_done = 1, last_error = NULL WHERE alert_id = ?', (alert_id,))

    def mark_attempt(self, alert_id, error=None):
        with self.db:
            self.db.execute('UPDATE alerts SET attempts = attempts + 1, last_error = ? WHERE alert_id = ?', (str(error)[:300] if error else None, alert_id))

    def counts(self):
        pending, oldest = self.db.execute('SELECT COUNT(*), MIN(created_ms) FROM alerts WHERE index_done = 0 OR kafka_done = 0').fetchone()
        total = self.db.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]
        return {'pending': pending, 'oldest_pending_ms': oldest, 'stored': total}

    def rules(self):
        names = ('rule_id', 'watermark_ms', 'last_run_ms', 'failures', 'last_error', 'alerts', 'suppressed', 'events', 'last_duration_ms')
        return [dict(zip(names, row)) for row in self.db.execute(f"SELECT {', '.join(names)} FROM rule_state ORDER BY rule_id")]

    def prune(self, before_ms):
        """Finished alerts must outlive the longest window a rerun could reach."""
        with self.db:
            return self.db.execute('DELETE FROM alerts WHERE created_ms < ? AND index_done = 1 AND kafka_done = 1', (before_ms,)).rowcount
