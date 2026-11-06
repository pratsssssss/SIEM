"""Durable state in SQLite. Change history and audit are append-only by trigger and chained by hash. Asset
records change in place, and every meaningful change is written to history in the same transaction.
Asset records are never deleted.
"""
import hashlib
import json
import secrets
import sqlite3
import threading

from .identity import STRONG

SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
  asset_id TEXT PRIMARY KEY, status TEXT NOT NULL, asset_type TEXT NOT NULL, platform TEXT NOT NULL, hostname TEXT NOT NULL, confidence TEXT NOT NULL, source TEXT NOT NULL,
  first_ms INTEGER, last_ms INTEGER, inventory_ms INTEGER, collection_ms INTEGER, status_ms INTEGER NOT NULL, merged_into TEXT, revision INTEGER NOT NULL DEFAULT 1, dirty INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS identifiers (kind TEXT NOT NULL, value TEXT NOT NULL, asset_id TEXT NOT NULL, source TEXT NOT NULL, first_ms INTEGER NOT NULL, last_ms INTEGER NOT NULL, active INTEGER NOT NULL DEFAULT 1, PRIMARY KEY (kind, value, asset_id));
CREATE INDEX IF NOT EXISTS identifiers_asset ON identifiers (asset_id);
CREATE TABLE IF NOT EXISTS attributes (asset_id TEXT NOT NULL, name TEXT NOT NULL, klass TEXT NOT NULL, value TEXT NOT NULL, source TEXT NOT NULL, observed_ms INTEGER NOT NULL, confidence TEXT NOT NULL, PRIMARY KEY (asset_id, name, klass));
CREATE TABLE IF NOT EXISTS items (
  asset_id TEXT NOT NULL, kind TEXT NOT NULL, key TEXT NOT NULL, body TEXT NOT NULL, klass TEXT NOT NULL, source TEXT NOT NULL, confidence TEXT NOT NULL, first_ms INTEGER NOT NULL, last_ms INTEGER NOT NULL, present INTEGER NOT NULL DEFAULT 1, removed_ms INTEGER,
  PRIMARY KEY (asset_id, kind, key));
CREATE TABLE IF NOT EXISTS leases (asset_id TEXT NOT NULL, ip TEXT NOT NULL, start_ms INTEGER NOT NULL, end_ms INTEGER NOT NULL, source TEXT NOT NULL, PRIMARY KEY (asset_id, ip, start_ms));
CREATE INDEX IF NOT EXISTS leases_ip ON leases (ip, start_ms);
CREATE TABLE IF NOT EXISTS relationships (
  rel_id TEXT PRIMARY KEY, src_type TEXT NOT NULL, src_id TEXT NOT NULL, rel_type TEXT NOT NULL, dst_type TEXT NOT NULL, dst_id TEXT NOT NULL, klass TEXT NOT NULL, confidence TEXT NOT NULL, source TEXT NOT NULL,
  first_ms INTEGER NOT NULL, last_ms INTEGER NOT NULL, count INTEGER NOT NULL DEFAULT 1, dirty INTEGER NOT NULL DEFAULT 1);
CREATE INDEX IF NOT EXISTS relationships_src ON relationships (src_id);
CREATE INDEX IF NOT EXISTS relationships_dst ON relationships (dst_id);
CREATE TABLE IF NOT EXISTS changes (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, at_ms INTEGER NOT NULL, asset_id TEXT NOT NULL, kind TEXT NOT NULL, category TEXT NOT NULL, subject TEXT, before TEXT, after TEXT, klass TEXT NOT NULL, source TEXT NOT NULL, dedupe TEXT UNIQUE, previous TEXT NOT NULL, hash TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS changes_asset ON changes (asset_id, seq);
CREATE TRIGGER IF NOT EXISTS changes_no_update BEFORE UPDATE ON changes BEGIN SELECT RAISE(ABORT, 'asset history is append-only'); END;
CREATE TRIGGER IF NOT EXISTS changes_no_delete BEFORE DELETE ON changes BEGIN SELECT RAISE(ABORT, 'asset history is append-only'); END;
CREATE TABLE IF NOT EXISTS acknowledged (seq INTEGER PRIMARY KEY, actor TEXT NOT NULL, note TEXT, at_ms INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS conflicts (conflict_id TEXT PRIMARY KEY, key TEXT NOT NULL UNIQUE, kind TEXT NOT NULL, state TEXT NOT NULL, assets TEXT NOT NULL, why TEXT NOT NULL, opened_ms INTEGER NOT NULL, closed_ms INTEGER, resolved_by TEXT, resolution TEXT);
CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY AUTOINCREMENT, ts_ms INTEGER NOT NULL, asset_id TEXT, actor TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL, previous TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
CREATE TABLE IF NOT EXISTS sources (source TEXT PRIMARY KEY, collected_ms INTEGER NOT NULL, digest TEXT NOT NULL, ok_ms INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS shipped (kind TEXT NOT NULL, key TEXT NOT NULL, PRIMARY KEY (kind, key));
CREATE TABLE IF NOT EXISTS marks (name TEXT PRIMARY KEY, value TEXT NOT NULL);
"""
GENESIS = '0' * 64
ASSET_FIELDS = ('asset_id', 'status', 'asset_type', 'platform', 'hostname', 'confidence', 'source', 'first_ms', 'last_ms', 'inventory_ms', 'collection_ms', 'status_ms', 'merged_into', 'revision')
CHANGE_FIELDS = ('seq', 'at_ms', 'asset_id', 'kind', 'category', 'subject', 'before', 'after', 'klass', 'source', 'previous', 'hash')
REL_FIELDS = ('rel_id', 'src_type', 'src_id', 'rel_type', 'dst_type', 'dst_id', 'klass', 'confidence', 'source', 'first_ms', 'last_ms', 'count')
ITEM_FIELDS = ('kind', 'key', 'body', 'klass', 'source', 'confidence', 'first_ms', 'last_ms', 'present', 'removed_ms')
AUDIT_FIELDS = ('seq', 'ts_ms', 'asset_id', 'actor', 'action', 'detail', 'previous', 'hash')


def chain(previous, payload):
    return hashlib.sha256((previous + json.dumps(payload, sort_keys=True, separators=(',', ':'))).encode()).hexdigest()


def escape_like(text):
    return text.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')


def _change(row):
    return {**dict(zip(CHANGE_FIELDS, row)), 'before': json.loads(row[6]), 'after': json.loads(row[7])}


class _Tx:
    """One transaction, however deeply nested, so a snapshot is applied whole or not at all."""

    def __init__(self, store):
        self.store = store

    def __enter__(self):
        self.store.lock.acquire()
        self.store.depth += 1
        return self.store

    def __exit__(self, kind, value, trace):
        try:
            self.store.depth -= 1
            if kind:
                self.store.failed = True
            if self.store.depth == 0:
                if self.store.failed:
                    self.store.db.rollback()
                else:
                    self.store.db.commit()
                self.store.failed = False
        finally:
            self.store.lock.release()


class Store:
    def __init__(self, path):
        self.lock = threading.RLock()
        self.depth = 0
        self.failed = False
        self.db = sqlite3.connect(path, timeout=30, check_same_thread=False)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('PRAGMA cache_size=-2000')
        self.db.executescript(SCHEMA)

    def close(self):
        self.db.close()

    def tx(self):
        return _Tx(self)

    # Assets.
    def create_asset(self, status, asset_type, platform, hostname, confidence, source, now, first_ms=None, last_ms=None):
        asset_id = 'ast-' + secrets.token_hex(8)
        with self.tx():
            self.db.execute('INSERT INTO assets (asset_id, status, asset_type, platform, hostname, confidence, source, first_ms, last_ms, status_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', (asset_id, status, asset_type, platform, hostname, confidence, source, first_ms, last_ms, now))
        return asset_id

    def asset(self, asset_id):
        with self.lock:
            row = self.db.execute(f"SELECT {','.join(ASSET_FIELDS)} FROM assets WHERE asset_id = ?", (asset_id,)).fetchone()
        return dict(zip(ASSET_FIELDS, row)) if row else None

    def assets(self, include_merged=False, limit=5000):
        where = '' if include_merged else "WHERE status != 'merged'"
        with self.lock:
            return [dict(zip(ASSET_FIELDS, r)) for r in self.db.execute(f"SELECT {','.join(ASSET_FIELDS)} FROM assets {where} ORDER BY hostname, asset_id LIMIT ?", (limit,))]

    def update_asset(self, asset_id, **fields):
        names = ', '.join(f'{k} = ?' for k in fields)
        with self.tx():
            self.db.execute(f'UPDATE assets SET {names}, revision = revision + 1, dirty = 1 WHERE asset_id = ?', (*fields.values(), asset_id))

    def touch(self, asset_id, first_ms, last_ms):
        """Seen again. Not a new revision: a busy host would otherwise rewrite its record all day."""
        with self.tx():
            self.db.execute('UPDATE assets SET last_ms = MAX(COALESCE(last_ms, 0), ?), first_ms = MIN(COALESCE(first_ms, ?), ?), dirty = 1 WHERE asset_id = ?', (last_ms, first_ms, first_ms, asset_id))

    def find_assets(self, text, limit=50):
        """The text is a value, never a pattern: wildcards in it are matched literally."""
        pattern = '%' + escape_like(text.lower()) + '%'
        with self.lock:
            rows = self.db.execute("""SELECT DISTINCT asset_id FROM (
                SELECT asset_id FROM assets WHERE lower(hostname) LIKE ?1 ESCAPE '\\' OR asset_id LIKE ?1 ESCAPE '\\'
                UNION SELECT asset_id FROM identifiers WHERE kind IN ('hostname', 'mac') AND value LIKE ?1 ESCAPE '\\'
                UNION SELECT asset_id FROM leases WHERE ip LIKE ?1 ESCAPE '\\'
                UNION SELECT asset_id FROM attributes WHERE lower(value) LIKE ?1 ESCAPE '\\'
                UNION SELECT asset_id FROM items WHERE kind IN ('software', 'service') AND lower(key) LIKE ?1 ESCAPE '\\') LIMIT ?2""", (pattern, limit)).fetchall()
        return [r[0] for r in rows]

    def asset_by_prefix(self, text):
        with self.lock:
            rows = self.db.execute("SELECT asset_id FROM assets WHERE asset_id LIKE ? || '%' ESCAPE '\\' LIMIT 2", (escape_like(text),)).fetchall()
        return rows[0][0] if len(rows) == 1 else None

    def count_recent(self, source, since):
        with self.lock:
            return self.db.execute('SELECT COUNT(*) FROM assets WHERE source = ? AND status_ms >= ?', (source, since)).fetchone()[0]

    # Identifiers. The lookups here serve identity.resolve.
    def holders(self, kind, value):
        with self.lock:
            rows = self.db.execute("SELECT i.asset_id FROM identifiers i JOIN assets a USING (asset_id) WHERE i.kind = ? AND i.value = ? AND i.active = 1 AND a.status != 'merged'", (kind, value)).fetchall()
        return {r[0] for r in rows}

    def strong_of(self, asset_id):
        found = {}
        with self.lock:
            for kind, value in self.db.execute(f"SELECT kind, value FROM identifiers WHERE asset_id = ? AND kind IN ({','.join('?' * len(STRONG))})", (asset_id, *STRONG)):
                found.setdefault(kind, set()).add(value)
        return found

    def is_provisional(self, asset_id):
        return not self.strong_of(asset_id)

    def add_identifier(self, kind, value, asset_id, source, now):
        """Keeps `active`: a person who took a name away from an asset is not overruled by its next report."""
        with self.tx():
            self.db.execute('INSERT INTO identifiers (kind, value, asset_id, source, first_ms, last_ms) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (kind, value, asset_id) DO UPDATE SET last_ms = excluded.last_ms', (kind, value, asset_id, source, now, now))

    def set_identifier_active(self, kind, value, asset_id, active):
        with self.tx():
            self.db.execute('UPDATE identifiers SET active = ? WHERE kind = ? AND value = ? AND asset_id = ?', (int(active), kind, value, asset_id))

    def identifiers(self, asset_id):
        names = ('kind', 'value', 'source', 'first_ms', 'last_ms', 'active')
        with self.lock:
            return [dict(zip(names, r)) for r in self.db.execute('SELECT kind, value, source, first_ms, last_ms, active FROM identifiers WHERE asset_id = ? ORDER BY kind, first_ms', (asset_id,))]

    # Attributes: one row per name and class, so an administrator's value never replaces an observed one.
    def set_attribute(self, asset_id, name, klass, value, source, at_ms, confidence):
        """The earlier value, or None."""
        encoded = json.dumps(value, sort_keys=True)
        with self.tx():
            row = self.db.execute('SELECT value FROM attributes WHERE asset_id = ? AND name = ? AND klass = ?', (asset_id, name, klass)).fetchone()
            self.db.execute('INSERT OR REPLACE INTO attributes VALUES (?, ?, ?, ?, ?, ?, ?)', (asset_id, name, klass, encoded, source, at_ms, confidence))
        return json.loads(row[0]) if row else None

    def clear_attribute(self, asset_id, name, klass):
        with self.tx():
            self.db.execute('DELETE FROM attributes WHERE asset_id = ? AND name = ? AND klass = ?', (asset_id, name, klass))

    def attributes(self, asset_id):
        names = ('name', 'klass', 'value', 'source', 'observed_ms', 'confidence')
        with self.lock:
            rows = self.db.execute('SELECT name, klass, value, source, observed_ms, confidence FROM attributes WHERE asset_id = ? ORDER BY name, klass', (asset_id,)).fetchall()
        return [{**dict(zip(names, r)), 'value': json.loads(r[2])} for r in rows]

    def attribute(self, asset_id, name, klass):
        with self.lock:
            row = self.db.execute('SELECT value FROM attributes WHERE asset_id = ? AND name = ? AND klass = ?', (asset_id, name, klass)).fetchone()
        return json.loads(row[0]) if row else None

    # Items: software, services, accounts, interfaces and the like. Absence hides an item, and never deletes it.
    def items(self, asset_id, kind, present_only=True, limit=5000):
        where = ' AND present = 1' if present_only else ''
        with self.lock:
            rows = self.db.execute(f"SELECT {','.join(ITEM_FIELDS)} FROM items WHERE asset_id = ? AND kind = ?{where} ORDER BY key LIMIT ?", (asset_id, kind, limit)).fetchall()
        return [{**dict(zip(ITEM_FIELDS, r)), 'body': json.loads(r[2])} for r in rows]

    def item_map(self, asset_id, kind):
        return {i['key']: i['body'] for i in self.items(asset_id, kind)}

    def put_item(self, asset_id, kind, key, body, klass, source, confidence, first_ms, last_ms=None):
        last_ms = last_ms if last_ms is not None else first_ms
        with self.tx():
            self.db.execute("""INSERT INTO items (asset_id, kind, key, body, klass, source, confidence, first_ms, last_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (asset_id, kind, key) DO UPDATE SET body = excluded.body, source = excluded.source, confidence = excluded.confidence, last_ms = MAX(last_ms, excluded.last_ms), first_ms = MIN(first_ms, excluded.first_ms), present = 1, removed_ms = NULL""",
                            (asset_id, kind, key, json.dumps(body, sort_keys=True), klass, source, confidence, first_ms, last_ms))

    def remove_item(self, asset_id, kind, key, now):
        with self.tx():
            self.db.execute('UPDATE items SET present = 0, removed_ms = ? WHERE asset_id = ? AND kind = ? AND key = ?', (now, asset_id, kind, key))

    def count_items(self, asset_id, kind):
        with self.lock:
            return self.db.execute('SELECT COUNT(*) FROM items WHERE asset_id = ? AND kind = ? AND present = 1', (asset_id, kind)).fetchone()[0]

    # Addresses over time. An address alone never identifies a machine, so one is only ever asked about at a moment.
    def observe_ip(self, asset_id, ip, at_ms, source, gap_ms):
        """Extends the current period, or opens another if the address was away for longer than the gap."""
        with self.tx():
            row = self.db.execute('SELECT start_ms, end_ms FROM leases WHERE asset_id = ? AND ip = ? ORDER BY start_ms DESC LIMIT 1', (asset_id, ip)).fetchone()
            if row and at_ms - row[1] <= gap_ms:
                self.db.execute('UPDATE leases SET end_ms = MAX(end_ms, ?), start_ms = MIN(start_ms, ?) WHERE asset_id = ? AND ip = ? AND start_ms = ?', (at_ms, at_ms, asset_id, ip, row[0]))
                return False
            self.db.execute('INSERT OR IGNORE INTO leases VALUES (?, ?, ?, ?, ?)', (asset_id, ip, at_ms, at_ms, source))
            return row is None

    def leases(self, asset_id):
        names = ('ip', 'start_ms', 'end_ms', 'source')
        with self.lock:
            return [dict(zip(names, r)) for r in self.db.execute('SELECT ip, start_ms, end_ms, source FROM leases WHERE asset_id = ? ORDER BY end_ms DESC, ip', (asset_id,))]

    def holders_of_ip(self, ip, at_ms=None, slack_ms=0):
        where, args = ('', (ip,)) if at_ms is None else (' AND l.start_ms - ? <= ? AND l.end_ms + ? >= ?', (ip, slack_ms, at_ms, slack_ms, at_ms))
        with self.lock:
            return sorted({r[0] for r in self.db.execute(f"SELECT l.asset_id FROM leases l JOIN assets a USING (asset_id) WHERE l.ip = ?{where} AND a.status != 'merged'", args)})

    # Relationships.
    def relate(self, src_type, src_id, rel_type, dst_type, dst_id, klass, confidence, source, first_ms, last_ms=None, count=1):
        last_ms = last_ms if last_ms is not None else first_ms
        rel_id = hashlib.sha256(f'{src_type}|{src_id}|{rel_type}|{dst_type}|{dst_id}'.encode()).hexdigest()[:32]
        with self.tx():
            self.db.execute("""INSERT INTO relationships (rel_id, src_type, src_id, rel_type, dst_type, dst_id, klass, confidence, source, first_ms, last_ms, count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (rel_id) DO UPDATE SET last_ms = MAX(last_ms, excluded.last_ms), first_ms = MIN(first_ms, excluded.first_ms), count = count + excluded.count, dirty = 1""",
                            (rel_id, src_type, src_id, rel_type, dst_type, dst_id, klass, confidence, source, first_ms, last_ms, count))
        return rel_id

    def relationships(self, asset_id, rel_type=None, limit=1000):
        extra, args = (' AND rel_type = ?', (rel_type,)) if rel_type else ('', ())
        with self.lock:
            rows = self.db.execute(f"SELECT {','.join(REL_FIELDS)} FROM relationships WHERE (src_id = ? OR dst_id = ?){extra} ORDER BY last_ms DESC LIMIT ?", (asset_id, asset_id, *args, limit)).fetchall()
        return [dict(zip(REL_FIELDS, r)) for r in rows]

    def count_relationships(self, asset_id):
        with self.lock:
            return self.db.execute('SELECT COUNT(*) FROM relationships WHERE src_id = ?', (asset_id,)).fetchone()[0]

    # History.
    def record_change(self, asset_id, at_ms, kind, category, subject, before, after, klass, source, dedupe=None):
        """False if this was already recorded: an event read twice is one change."""
        entry = {'at_ms': at_ms, 'asset_id': asset_id, 'kind': kind, 'category': category, 'subject': subject, 'before': before, 'after': after, 'klass': klass, 'source': source}
        with self.tx():
            if dedupe and self.db.execute('SELECT 1 FROM changes WHERE dedupe = ?', (dedupe,)).fetchone():
                return False
            row = self.db.execute('SELECT hash FROM changes ORDER BY seq DESC LIMIT 1').fetchone()
            previous = row[0] if row else GENESIS
            self.db.execute('INSERT INTO changes (at_ms, asset_id, kind, category, subject, before, after, klass, source, dedupe, previous, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                            (at_ms, asset_id, kind, category, subject, json.dumps(before), json.dumps(after), klass, source, dedupe, previous, chain(previous, entry)))
        return True

    def changes(self, asset_ids=None, category=None, limit=200):
        where, args = ['1 = 1'], []
        if asset_ids:
            where.append(f"asset_id IN ({','.join('?' * len(asset_ids))})")
            args += list(asset_ids)
        if category:
            where.append('category = ?')
            args.append(category)
        with self.lock:
            return [_change(r) for r in self.db.execute(f"SELECT {','.join(CHANGE_FIELDS)} FROM changes WHERE {' AND '.join(where)} ORDER BY seq DESC LIMIT ?", (*args, limit)).fetchall()]

    def unacknowledged(self, limit=500):
        with self.lock:
            return [_change(r) for r in self.db.execute(f"SELECT {','.join(CHANGE_FIELDS)} FROM changes WHERE category = 'security' AND seq NOT IN (SELECT seq FROM acknowledged) ORDER BY seq DESC LIMIT ?", (limit,)).fetchall()]

    def count_unacknowledged(self):
        with self.lock:
            return self.db.execute("SELECT COUNT(*) FROM changes WHERE category = 'security' AND seq NOT IN (SELECT seq FROM acknowledged)").fetchone()[0]

    def acknowledge(self, seq, actor, note, now):
        with self.tx():
            found = self.db.execute("SELECT 1 FROM changes WHERE seq = ? AND category = 'security'", (seq,)).fetchone()
            if found:
                self.db.execute('INSERT OR IGNORE INTO acknowledged VALUES (?, ?, ?, ?)', (seq, actor, note, now))
        return bool(found)

    def verify_changes(self):
        previous, entries = GENESIS, 0
        with self.lock:
            rows = self.db.execute('SELECT seq, at_ms, asset_id, kind, category, subject, before, after, klass, source, previous, hash FROM changes ORDER BY seq').fetchall()
        for seq, at_ms, asset_id, kind, category, subject, before, after, klass, source, stored_before, stored in rows:
            entries += 1
            entry = {'at_ms': at_ms, 'asset_id': asset_id, 'kind': kind, 'category': category, 'subject': subject, 'before': json.loads(before), 'after': json.loads(after), 'klass': klass, 'source': source}
            if stored_before != previous or chain(previous, entry) != stored:
                return entries, seq
            previous = stored
        return entries, None

    # Conflicts.
    def open_conflict(self, kind, assets, why, now):
        """The id if this is new. A decided conflict stays decided, so a report cannot reopen it."""
        key = hashlib.sha256(f"{kind}|{'|'.join(sorted(assets))}".encode()).hexdigest()[:32]
        with self.tx():
            if self.db.execute('SELECT 1 FROM conflicts WHERE key = ?', (key,)).fetchone():
                return None
            conflict_id = 'cfl-' + key[:12]
            self.db.execute("INSERT INTO conflicts (conflict_id, key, kind, state, assets, why, opened_ms) VALUES (?, ?, ?, 'open', ?, ?, ?)", (conflict_id, key, kind, json.dumps(sorted(assets)), why, now))
        return conflict_id

    def conflicts(self, state='open', asset_id=None):
        names = ('conflict_id', 'kind', 'state', 'assets', 'why', 'opened_ms', 'closed_ms', 'resolved_by', 'resolution')
        where, args = (' WHERE state = ?', (state,)) if state else ('', ())
        with self.lock:
            rows = self.db.execute(f"SELECT {','.join(names)} FROM conflicts{where} ORDER BY opened_ms DESC", args).fetchall()
        found = [{**dict(zip(names, r)), 'assets': json.loads(r[3])} for r in rows]
        return [c for c in found if asset_id in c['assets']] if asset_id else found

    def conflict(self, conflict_id):
        return next((c for c in self.conflicts(None) if c['conflict_id'] == conflict_id), None)

    def close_conflict(self, conflict_id, actor, resolution, now):
        with self.tx():
            self.db.execute("UPDATE conflicts SET state = 'resolved', closed_ms = ?, resolved_by = ?, resolution = ? WHERE conflict_id = ?", (now, actor, resolution, conflict_id))

    def has_open_conflict(self, asset_id):
        return bool(self.conflicts('open', asset_id))

    def merge(self, source, target, now):
        """Everything known about `source` moves to `target`. Its history stays under its own id, and the record stays as a pointer."""
        with self.tx():
            self.db.execute('UPDATE OR IGNORE identifiers SET asset_id = ? WHERE asset_id = ?', (target, source))
            self.db.execute('UPDATE OR IGNORE items SET asset_id = ? WHERE asset_id = ?', (target, source))
            self.db.execute('UPDATE OR IGNORE attributes SET asset_id = ? WHERE asset_id = ?', (target, source))
            self.db.execute('UPDATE OR IGNORE leases SET asset_id = ? WHERE asset_id = ?', (target, source))
            rows = self.db.execute(f"SELECT {','.join(REL_FIELDS)} FROM relationships WHERE src_id = ? OR dst_id = ?", (source, source)).fetchall()
            for row in rows:
                rel = dict(zip(REL_FIELDS, row))
                self.relate(rel['src_type'], target if rel['src_id'] == source else rel['src_id'], rel['rel_type'], rel['dst_type'], target if rel['dst_id'] == source else rel['dst_id'], rel['klass'], rel['confidence'], rel['source'], rel['first_ms'], rel['last_ms'], rel['count'])
                self.db.execute('DELETE FROM relationships WHERE rel_id = ?', (rel['rel_id'],))
            self.db.execute("UPDATE assets SET status = 'merged', merged_into = ?, status_ms = ?, revision = revision + 1, dirty = 1 WHERE asset_id = ?", (target, now, source))

    def merged_from(self, asset_id):
        with self.lock:
            rows = self.db.execute('SELECT asset_id FROM assets WHERE merged_into = ?', (asset_id,)).fetchall()
        found = [r[0] for r in rows]
        return found + [x for a in found for x in self.merged_from(a)]

    # Audit.
    def audit(self, asset_id, now, actor, action, detail):
        with self.tx():
            row = self.db.execute('SELECT hash FROM audit ORDER BY seq DESC LIMIT 1').fetchone()
            previous = row[0] if row else GENESIS
            entry = {'ts_ms': now, 'asset_id': asset_id, 'actor': actor, 'action': action, 'detail': detail}
            self.db.execute('INSERT INTO audit (ts_ms, asset_id, actor, action, detail, previous, hash) VALUES (?, ?, ?, ?, ?, ?, ?)', (now, asset_id, actor, action, json.dumps(detail, sort_keys=True), previous, chain(previous, entry)))

    def audit_rows(self, asset_id=None, limit=500):
        with self.lock:
            rows = self.db.execute(f"SELECT {','.join(AUDIT_FIELDS)} FROM audit" + (' WHERE asset_id = ?' if asset_id else '') + ' ORDER BY seq DESC LIMIT ?', (asset_id, limit) if asset_id else (limit,)).fetchall()
        return [{**dict(zip(AUDIT_FIELDS, r)), 'detail': json.loads(r[5])} for r in reversed(rows)]

    def verify_audit(self):
        previous, entries = GENESIS, 0
        with self.lock:
            rows = self.db.execute('SELECT seq, ts_ms, asset_id, actor, action, detail, previous, hash FROM audit ORDER BY seq').fetchall()
        for seq, ts_ms, asset_id, actor, action, detail, before, stored in rows:
            entries += 1
            entry = {'ts_ms': ts_ms, 'asset_id': asset_id, 'actor': actor, 'action': action, 'detail': json.loads(detail)}
            if before != previous or chain(before, entry) != stored:
                return entries, seq
            previous = stored
        return entries, None

    # Sources: a report older than the last one from that source is a replay.
    def source(self, name):
        with self.lock:
            row = self.db.execute('SELECT collected_ms, digest, ok_ms FROM sources WHERE source = ?', (name,)).fetchone()
        return dict(zip(('collected_ms', 'digest', 'ok_ms'), row)) if row else None

    def sources(self):
        with self.lock:
            return [dict(zip(('source', 'collected_ms', 'digest', 'ok_ms'), r)) for r in self.db.execute('SELECT source, collected_ms, digest, ok_ms FROM sources ORDER BY source')]

    def set_source(self, name, collected_ms, digest, now):
        with self.tx():
            self.db.execute('INSERT OR REPLACE INTO sources VALUES (?, ?, ?, ?)', (name, collected_ms, digest, now))

    # Output to OpenSearch.
    def dirty_assets(self, limit=100):
        with self.lock:
            return [r[0] for r in self.db.execute('SELECT asset_id FROM assets WHERE dirty = 1 LIMIT ?', (limit,))]

    def clean_asset(self, asset_id, revision, last_ms):
        """Only if nothing moved while it was being sent."""
        with self.tx():
            self.db.execute('UPDATE assets SET dirty = 0 WHERE asset_id = ? AND revision = ? AND COALESCE(last_ms, 0) = COALESCE(?, 0)', (asset_id, revision, last_ms))

    def dirty_relationships(self, limit=200):
        with self.lock:
            return [dict(zip(REL_FIELDS, r)) for r in self.db.execute(f"SELECT {','.join(REL_FIELDS)} FROM relationships WHERE dirty = 1 LIMIT ?", (limit,))]

    def clean_relationship(self, rel_id, last_ms, count):
        with self.tx():
            self.db.execute('UPDATE relationships SET dirty = 0 WHERE rel_id = ? AND last_ms = ? AND count = ?', (rel_id, last_ms, count))

    def unshipped_changes(self, limit=200):
        with self.lock:
            return [_change(r) for r in self.db.execute(f"SELECT {','.join(CHANGE_FIELDS)} FROM changes WHERE CAST(seq AS TEXT) NOT IN (SELECT key FROM shipped WHERE kind = 'change') ORDER BY seq LIMIT ?", (limit,)).fetchall()]

    def unshipped_audit(self, limit=200):
        with self.lock:
            rows = self.db.execute(f"SELECT {','.join(AUDIT_FIELDS)} FROM audit WHERE CAST(seq AS TEXT) NOT IN (SELECT key FROM shipped WHERE kind = 'audit') ORDER BY seq LIMIT ?", (limit,)).fetchall()
        return [{**dict(zip(AUDIT_FIELDS, r)), 'detail': json.loads(r[5])} for r in rows]

    def shipped(self, kind, key):
        with self.tx():
            self.db.execute('INSERT OR IGNORE INTO shipped VALUES (?, ?)', (kind, str(key)))

    def backlog(self):
        with self.lock:
            changes = self.db.execute("SELECT COUNT(*) FROM changes WHERE CAST(seq AS TEXT) NOT IN (SELECT key FROM shipped WHERE kind = 'change')").fetchone()[0]
            audit = self.db.execute("SELECT COUNT(*) FROM audit WHERE CAST(seq AS TEXT) NOT IN (SELECT key FROM shipped WHERE kind = 'audit')").fetchone()[0]
            assets = self.db.execute('SELECT COUNT(*) FROM assets WHERE dirty = 1').fetchone()[0]
            relationships = self.db.execute('SELECT COUNT(*) FROM relationships WHERE dirty = 1').fetchone()[0]
        return {'changes': changes, 'audit': audit, 'assets': assets, 'relationships': relationships}

    def mark(self, name, default=None):
        with self.lock:
            row = self.db.execute('SELECT value FROM marks WHERE name = ?', (name,)).fetchone()
        return row[0] if row else default

    def set_mark(self, name, value):
        with self.tx():
            self.db.execute('INSERT OR REPLACE INTO marks VALUES (?, ?)', (name, str(value)))

    def clear_mark(self, name):
        with self.tx():
            self.db.execute('DELETE FROM marks WHERE name = ?', (name,))
