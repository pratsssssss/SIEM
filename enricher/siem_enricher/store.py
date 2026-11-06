"""Local state in one SQLite file: threat intelligence, lookup cache, quotas, jobs and watermarks.

Everything is on disk with indexes, so a large feed costs storage, not memory.
"""
import ipaddress
import json
import sqlite3
import threading

SCHEMA = """
CREATE TABLE IF NOT EXISTS intel (
  feed TEXT NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL, category TEXT, first_seen TEXT, last_seen TEXT, pull INTEGER NOT NULL,
  PRIMARY KEY (kind, value, feed)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS intel_pull ON intel (feed, pull);
CREATE TABLE IF NOT EXISTS ranges (feed TEXT NOT NULL, start BLOB NOT NULL, end BLOB NOT NULL, category TEXT, pull INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS ranges_start ON ranges (feed, start);
CREATE TABLE IF NOT EXISTS feeds (
  feed TEXT PRIMARY KEY, pull INTEGER NOT NULL DEFAULT 0, rows INTEGER NOT NULL DEFAULT 0, updated_ms INTEGER, checked_ms INTEGER,
  etag TEXT, last_modified TEXT, last_error TEXT
);
CREATE TABLE IF NOT EXISTS cache (
  provider TEXT NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL, stored_ms INTEGER NOT NULL, expires_ms INTEGER NOT NULL, body TEXT NOT NULL, hits INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (provider, kind, value)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS quota (provider TEXT NOT NULL, day TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (provider, day)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS health (
  provider TEXT PRIMARY KEY, ok INTEGER NOT NULL DEFAULT 0, failed INTEGER NOT NULL DEFAULT 0, consecutive INTEGER NOT NULL DEFAULT 0,
  open_until_ms INTEGER NOT NULL DEFAULT 0, last_error TEXT, last_ok_ms INTEGER
);
CREATE TABLE IF NOT EXISTS jobs (
  alert_id TEXT PRIMARY KEY, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_ms INTEGER NOT NULL DEFAULT 0, created_ms INTEGER NOT NULL, updated_ms INTEGER, last_error TEXT
);
CREATE INDEX IF NOT EXISTS jobs_due ON jobs (status, next_ms);
CREATE TABLE IF NOT EXISTS marks (name TEXT PRIMARY KEY, ms INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL DEFAULT 0);
"""


def packed(address):
    """16 bytes that sort in address order, for IPv4 and IPv6 together."""
    ip = ipaddress.ip_address(address)
    return (ipaddress.IPv6Address(int(ip) + (0xffff << 32)) if ip.version == 4 else ip).packed


def bounds(cidr):
    network = ipaddress.ip_network(cidr, strict=False)
    return packed(network[0]), packed(network[-1])


class Store:
    def __init__(self, path):
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, timeout=30, check_same_thread=False)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=NORMAL')
        self.db.execute('PRAGMA cache_size=-8000')
        self.db.executescript(SCHEMA)

    def close(self):
        self.db.close()

    def bump(self, name, by=1):
        with self.lock, self.db:
            self.db.execute('INSERT INTO counters VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET value = value + excluded.value', (name, by))

    def counters(self):
        with self.lock:
            return dict(self.db.execute('SELECT name, value FROM counters'))

    # Threat intelligence.
    def intel(self, kind, value):
        with self.lock:
            return [dict(zip(('feed', 'category', 'first_seen', 'last_seen'), row)) for row in self.db.execute('SELECT feed, category, first_seen, last_seen FROM intel WHERE kind = ? AND value = ?', (kind, value))]

    def in_range(self, feed, address, overlap=8):
        key = packed(address)
        with self.lock:
            rows = self.db.execute('SELECT end, category FROM ranges WHERE feed = ? AND start <= ? ORDER BY start DESC LIMIT ?', (feed, key, overlap)).fetchall()
        return next((category or feed for end, category in rows if end >= key), None)

    def feed_state(self, feed):
        with self.lock:
            row = self.db.execute('SELECT pull, rows, updated_ms, checked_ms, etag, last_modified, last_error FROM feeds WHERE feed = ?', (feed,)).fetchone()
        return dict(zip(('pull', 'rows', 'updated_ms', 'checked_ms', 'etag', 'last_modified', 'last_error'), row)) if row else {'pull': 0, 'rows': 0, 'updated_ms': None, 'checked_ms': None, 'etag': None, 'last_modified': None, 'last_error': None}

    def feed_note(self, feed, now, error=None):
        with self.lock, self.db:
            self.db.execute('INSERT INTO feeds (feed, checked_ms, last_error) VALUES (?, ?, ?) ON CONFLICT(feed) DO UPDATE SET checked_ms = excluded.checked_ms, last_error = excluded.last_error', (feed, now, error))

    def replace_feed_unchanged(self, feed, now):
        """The source says nothing changed, so what is held is still current."""
        with self.lock, self.db:
            self.db.execute('UPDATE feeds SET updated_ms = ?, checked_ms = ?, last_error = NULL WHERE feed = ?', (now, now, feed))

    def replace_feed(self, feed, rows, cidrs, now, etag=None, last_modified=None):
        """Applies a pull in one transaction. Unchanged rows keep their first_seen, and rows gone from
        the feed are removed. A failure leaves the previous data in place."""
        state = self.feed_state(feed)
        pull = state['pull'] + 1
        with self.lock, self.db:
            self.db.executemany(
                'INSERT INTO intel (feed, kind, value, category, first_seen, last_seen, pull) VALUES (?, ?, ?, ?, ?, ?, ?) '
                'ON CONFLICT(kind, value, feed) DO UPDATE SET category = excluded.category, last_seen = excluded.last_seen, pull = excluded.pull',
                ((feed, kind, value, category, first, last, pull) for kind, value, category, first, last in rows))
            self.db.execute('DELETE FROM intel WHERE feed = ? AND pull != ?', (feed, pull))
            self.db.execute('DELETE FROM ranges WHERE feed = ?', (feed,))
            self.db.executemany('INSERT INTO ranges (feed, start, end, category, pull) VALUES (?, ?, ?, ?, ?)',
                                ((feed, *bounds(cidr), category, pull) for cidr, category in cidrs))
            total = self.db.execute('SELECT COUNT(*) FROM intel WHERE feed = ?', (feed,)).fetchone()[0] + len(cidrs)
            self.db.execute(
                'INSERT INTO feeds (feed, pull, rows, updated_ms, checked_ms, etag, last_modified, last_error) VALUES (?, ?, ?, ?, ?, ?, ?, NULL) '
                'ON CONFLICT(feed) DO UPDATE SET pull = excluded.pull, rows = excluded.rows, updated_ms = excluded.updated_ms, checked_ms = excluded.checked_ms, etag = excluded.etag, last_modified = excluded.last_modified, last_error = NULL',
                (feed, pull, total, now, now, etag, last_modified))
        return total

    def purge_feed(self, feed):
        """Removes everything held from one feed."""
        with self.lock, self.db:
            rows = self.db.execute('DELETE FROM intel WHERE feed = ?', (feed,)).rowcount
            rows += self.db.execute('DELETE FROM ranges WHERE feed = ?', (feed,)).rowcount
            self.db.execute('DELETE FROM feeds WHERE feed = ?', (feed,))
        return rows

    # Cache.
    def cached(self, provider, kind, value, now):
        with self.lock:
            row = self.db.execute('SELECT body, expires_ms FROM cache WHERE provider = ? AND kind = ? AND value = ?', (provider, kind, value)).fetchone()
            if row is None or row[1] <= now:
                return None
            with self.db:
                self.db.execute('UPDATE cache SET hits = hits + 1 WHERE provider = ? AND kind = ? AND value = ?', (provider, kind, value))
        return json.loads(row[0])

    def cache_put(self, provider, kind, value, body, now, ttl_seconds):
        with self.lock, self.db:
            self.db.execute('INSERT OR REPLACE INTO cache (provider, kind, value, stored_ms, expires_ms, body, hits) VALUES (?, ?, ?, ?, ?, ?, 0)',
                            (provider, kind, value, now, now + ttl_seconds * 1000, json.dumps(body)))

    def cache_clear(self, provider=None, value=None, expired_before=None):
        clauses, args = [], []
        if provider:
            clauses.append('provider = ?')
            args.append(provider)
        if value:
            clauses.append('value = ?')
            args.append(value)
        if expired_before is not None:
            clauses.append('expires_ms <= ?')
            args.append(expired_before)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ''
        with self.lock, self.db:
            return self.db.execute(f'DELETE FROM cache{where}', args).rowcount

    def cache_stats(self, now):
        with self.lock:
            rows = self.db.execute('SELECT provider, COUNT(*), SUM(expires_ms <= ?), SUM(hits) FROM cache GROUP BY provider', (now,)).fetchall()
        return {p: {'entries': n, 'expired': e, 'hits': h} for p, n, e, h in rows}

    # Provider quota and health.
    def quota_used(self, provider, day):
        with self.lock:
            row = self.db.execute('SELECT used FROM quota WHERE provider = ? AND day = ?', (provider, day)).fetchone()
        return row[0] if row else 0

    def quota_take(self, provider, day, limit):
        """Reserves one request, atomically. Returns False when the day's allowance is spent."""
        with self.lock, self.db:
            self.db.execute('INSERT OR IGNORE INTO quota VALUES (?, ?, 0)', (provider, day))
            done = self.db.execute('UPDATE quota SET used = used + 1 WHERE provider = ? AND day = ? AND used < ?', (provider, day, limit)).rowcount
        return done == 1

    def health_ok(self, provider, now):
        with self.lock, self.db:
            self.db.execute('INSERT INTO health (provider, ok, consecutive, last_ok_ms) VALUES (?, 1, 0, ?) ON CONFLICT(provider) DO UPDATE SET ok = ok + 1, consecutive = 0, open_until_ms = 0, last_ok_ms = excluded.last_ok_ms', (provider, now))

    def health_failed(self, provider, error, now, threshold, cooldown_ms):
        with self.lock, self.db:
            self.db.execute('INSERT OR IGNORE INTO health (provider) VALUES (?)', (provider,))
            self.db.execute('UPDATE health SET failed = failed + 1, consecutive = consecutive + 1, last_error = ? WHERE provider = ?', (str(error)[:200], provider))
            self.db.execute('UPDATE health SET open_until_ms = ? WHERE provider = ? AND consecutive >= ?', (now + cooldown_ms, provider, threshold))

    def provider_open_until(self, provider):
        with self.lock:
            row = self.db.execute('SELECT open_until_ms FROM health WHERE provider = ?', (provider,)).fetchone()
        return row[0] if row else 0

    def provider_health(self):
        with self.lock:
            names = ('provider', 'ok', 'failed', 'consecutive', 'open_until_ms', 'last_error', 'last_ok_ms')
            return [dict(zip(names, row)) for row in self.db.execute(f"SELECT {', '.join(names)} FROM health ORDER BY provider")]

    # Jobs and watermarks.
    def job_add(self, alert_id, now):
        """Returns True if this alert is new, so a repeat sighting makes no second job."""
        with self.lock, self.db:
            return self.db.execute("INSERT OR IGNORE INTO jobs (alert_id, status, created_ms) VALUES (?, 'pending', ?)", (alert_id, now)).rowcount == 1

    def jobs_due(self, now, limit=50):
        with self.lock:
            return [r[0] for r in self.db.execute("SELECT alert_id FROM jobs WHERE status IN ('pending', 'partial') AND next_ms <= ? ORDER BY created_ms LIMIT ?", (now, limit))]

    def job_done(self, alert_id, status, now, retry_ms=None, error=None):
        with self.lock, self.db:
            self.db.execute('UPDATE jobs SET status = ?, attempts = attempts + 1, next_ms = ?, updated_ms = ?, last_error = ? WHERE alert_id = ?', (status, retry_ms or 0, now, str(error)[:200] if error else None, alert_id))

    def job_attempts(self, alert_id):
        with self.lock:
            row = self.db.execute('SELECT attempts FROM jobs WHERE alert_id = ?', (alert_id,)).fetchone()
        return row[0] if row else 0

    def job_counts(self):
        with self.lock:
            return dict(self.db.execute('SELECT status, COUNT(*) FROM jobs GROUP BY status'))

    def mark(self, name, default=None):
        with self.lock:
            row = self.db.execute('SELECT ms FROM marks WHERE name = ?', (name,)).fetchone()
        return row[0] if row else default

    def set_mark(self, name, value):
        with self.lock, self.db:
            self.db.execute('INSERT OR REPLACE INTO marks VALUES (?, ?)', (name, value))
