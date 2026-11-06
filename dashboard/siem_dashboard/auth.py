"""The single dashboard administrator: passwords, sessions, throttling and the dashboard's own audit trail.

This account has nothing to do with any operating system account. It is created by root on the machine itself, never over
the network. The identity on a request comes only from the server-side session, so `identity()` is the one place a future
multi-user version would change. Session tokens are stored only as hashes, so reading the database gives no live session.
"""
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS admin (id INTEGER PRIMARY KEY CHECK (id = 1), username TEXT NOT NULL, password TEXT NOT NULL, disabled INTEGER NOT NULL DEFAULT 0, created_ms INTEGER NOT NULL, changed_ms INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, csrf TEXT NOT NULL, created_ms INTEGER NOT NULL, last_ms INTEGER NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS attempts (key TEXT PRIMARY KEY, failures INTEGER NOT NULL, first_ms INTEGER NOT NULL, locked_until_ms INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY AUTOINCREMENT, at_ms INTEGER NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT, outcome TEXT NOT NULL, request_id TEXT, detail TEXT NOT NULL, previous TEXT NOT NULL, hash TEXT NOT NULL UNIQUE);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'audit is append only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'audit is append only'); END;
"""
GENESIS = '0' * 64
# OWASP's memory and work trade-off for scrypt at 32 MiB per check, which keeps a login inside this service's memory limit.
SCRYPT = {'n': 2 ** 15, 'r': 8, 'p': 3}
SCRYPT_MAX_MEMORY = 64 * 1024 * 1024
MIN_PASSWORD = 14
MAX_PASSWORD = 256
REFUSED_NAMES = ('root', 'toor', 'administrator')
FORBIDDEN_DETAIL = ('password', 'token', 'cookie', 'secret', 'csrf')


class AuthError(ValueError):
    pass


def hash_password(password):
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(password.encode('utf-8', 'surrogatepass'), salt=salt, n=SCRYPT['n'], r=SCRYPT['r'], p=SCRYPT['p'], maxmem=SCRYPT_MAX_MEMORY, dklen=32)
    return f"scrypt${SCRYPT['n']}${SCRYPT['r']}${SCRYPT['p']}${salt.hex()}${derived.hex()}"


def verify_password(password, stored):
    try:
        kind, n, r, p, salt, wanted = stored.split('$')
        if kind != 'scrypt':
            return False
        derived = hashlib.scrypt(password.encode('utf-8', 'surrogatepass'), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p), maxmem=SCRYPT_MAX_MEMORY, dklen=32)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(derived.hex(), wanted)


# A failed lookup costs the same as a failed password, so timing does not reveal the name.
DUMMY = None


def dummy_check(password):
    global DUMMY
    if DUMMY is None:
        DUMMY = hash_password(secrets.token_hex(16))
    verify_password(password, DUMMY)


def check_new_password(password):
    if not isinstance(password, str) or not MIN_PASSWORD <= len(password) <= MAX_PASSWORD:
        raise AuthError(f'the password must be {MIN_PASSWORD} to {MAX_PASSWORD} characters')
    if '\x00' in password or len(set(password)) < 5:
        raise AuthError('the password is too simple')


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


class Auth:
    def __init__(self, path, config, clock=None):
        self.path = path
        self.settings = config
        self.clock = clock or (lambda: int(time.time() * 1000))
        old = os.umask(0o077)
        try:
            self.db = sqlite3.connect(path, timeout=10, isolation_level=None, check_same_thread=False)
        finally:
            os.umask(old)
        self.db.execute('PRAGMA journal_mode = DELETE')
        self.db.execute('PRAGMA synchronous = FULL')
        self.db.executescript(SCHEMA)
        import threading
        # Every use of the one connection holds this, reads included. Request threads share the connection, and the sqlite3
        # module reuses one prepared statement for the same SQL, so an unlocked read could be reset, or answered with another
        # thread's row. Re-entrant, so a locked method may call another. Password hashing never runs under it.
        self.lock = threading.RLock()
        self.verifier = threading.BoundedSemaphore(1)

    def close(self):
        self.db.close()

    # Provisioning, reached only by the local root command.
    def admin(self):
        with self.lock:
            row = self.db.execute('SELECT username, password, disabled, created_ms, changed_ms FROM admin').fetchone()
        return dict(zip(('username', 'password', 'disabled', 'created_ms', 'changed_ms'), row)) if row else None

    def create(self, username, password, actor='root-local'):
        if self.admin():
            raise AuthError('an administrator exists. Use reset-password, or remove it first')
        name = (username or '').strip()
        if not name or len(name) > 64 or not name.replace('-', '').replace('_', '').replace('.', '').isalnum():
            raise AuthError('use letters, digits, dots, dashes and underscores')
        if name.lower() in REFUSED_NAMES:
            raise AuthError('this name is reserved. The dashboard account is not an operating system account')
        check_new_password(password)
        now = self.clock()
        with self.lock:
            self.db.execute('INSERT INTO admin (id, username, password, created_ms, changed_ms) VALUES (1, ?, ?, ?, ?)', (name, hash_password(password), now, now))
        self.record(actor, 'admin_created', name, 'ok')

    def set_password(self, password, actor):
        found = self.admin()
        if not found:
            raise AuthError('no administrator exists')
        check_new_password(password)
        now = self.clock()
        with self.lock:
            self.db.execute('UPDATE admin SET password = ?, changed_ms = ? WHERE id = 1', (hash_password(password), now))
            self.db.execute('DELETE FROM sessions')
            self.db.execute('DELETE FROM attempts')
        self.record(actor, 'password_changed', found['username'], 'ok')

    def set_disabled(self, disabled, actor='root-local'):
        with self.lock:
            done = self.db.execute('UPDATE admin SET disabled = ? WHERE id = 1', (1 if disabled else 0,)).rowcount
            self.db.execute('DELETE FROM sessions')
        if not done:
            raise AuthError('no administrator exists')
        self.record(actor, 'login_disabled' if disabled else 'login_enabled', None, 'ok')

    def remove(self, actor='root-local'):
        with self.lock:
            done = self.db.execute('DELETE FROM admin').rowcount
            self.db.execute('DELETE FROM sessions')
            self.db.execute('DELETE FROM attempts')
        if not done:
            raise AuthError('no administrator exists')
        self.record(actor, 'admin_removed', None, 'ok')

    def revoke_all(self, actor='root-local'):
        with self.lock:
            count = self.db.execute('DELETE FROM sessions').rowcount
        self.record(actor, 'sessions_revoked', None, 'ok', detail={'sessions': count})
        return count

    def unlock(self, actor='root-local'):
        with self.lock:
            self.db.execute('DELETE FROM attempts')
        self.record(actor, 'throttle_cleared', None, 'ok')

    def status(self):
        now = self.clock()
        found = self.admin()
        with self.lock:
            live = [r for r in self.db.execute('SELECT created_ms, last_ms FROM sessions').fetchall() if self._alive(r[0], r[1], now)]
            locks = self.db.execute('SELECT COUNT(*) FROM attempts WHERE locked_until_ms > ?', (now,)).fetchone()[0]
        return {'provisioned': bool(found), 'username': found['username'] if found else None, 'login_disabled': bool(found and found['disabled']), 'password_changed_ms': found['changed_ms'] if found else None, 'active_sessions': len(live), 'locked_keys': locks}

    # Throttling. Keyed on the name, and overall, because everything reaches this service from one proxy address.
    def _locked(self, key, now):
        row = self.db.execute('SELECT locked_until_ms FROM attempts WHERE key = ?', (key,)).fetchone()
        return bool(row) and row[0] > now

    def _fail(self, key, limit, now):
        window = self.settings['login']['window_minutes'] * 60000
        row = self.db.execute('SELECT failures, first_ms FROM attempts WHERE key = ?', (key,)).fetchone()
        failures, first = (row[0] + 1, row[1]) if row and now - row[1] <= window else (1, now)
        locked = now + self.settings['login']['lock_minutes'] * 60000 if failures >= limit else 0
        self.db.execute('INSERT OR REPLACE INTO attempts (key, failures, first_ms, locked_until_ms) VALUES (?, ?, ?, ?)', (key, failures, first, locked))

    def login(self, username, password, request_id=None):
        """(token, csrf) for a new session. Every failure reads the same to the caller."""
        now = self.clock()
        name = str(username or '')[:64]
        key = 'name:' + hashlib.sha256(name.lower().encode('utf-8', 'surrogatepass')).hexdigest()[:32]
        settings = self.settings['login']
        with self.lock:
            if self._locked(key, now) or self._locked('global', now):
                refused = True
            else:
                refused = False
        if refused:
            self.record('anonymous', 'login', None, 'throttled', request_id)
            raise AuthError('throttled')
        with self.verifier:
            found = self.admin()
            matches = found is not None and hmac.compare_digest(found['username'].encode('utf-8', 'surrogatepass'), name.encode('utf-8', 'surrogatepass'))
            if matches:
                good = verify_password(str(password or '')[:MAX_PASSWORD], found['password'])
            else:
                dummy_check(str(password or '')[:MAX_PASSWORD])
                good = False
        if not good or found['disabled']:
            with self.lock:
                self._fail(key, settings['failures'], now)
                self._fail('global', settings['global_failures'], now)
            self.record('anonymous', 'login', None, 'refused', request_id)
            raise AuthError('refused')
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with self.lock:
            self.db.execute('DELETE FROM attempts WHERE key IN (?, ?)', (key, 'global'))
            self.db.execute('INSERT INTO sessions (token_hash, csrf, created_ms, last_ms) VALUES (?, ?, ?, ?)', (token_hash(token), csrf, now, now))
        self.record(found['username'], 'login', None, 'ok', request_id)
        return token, csrf

    def _alive(self, created, last, now):
        session = self.settings['session']
        return now - last <= session['idle_minutes'] * 60000 and now - created <= session['absolute_hours'] * 3600000

    def identity(self, token):
        """The session behind a cookie, or None. This is the only source of who is asking."""
        if not token or len(token) > 128:
            return None
        hashed = token_hash(token)
        now = self.clock()
        # One locked block: the session read, the account read and any change to the session, with nothing between them.
        with self.lock:
            row = self.db.execute('SELECT csrf, created_ms, last_ms FROM sessions WHERE token_hash = ?', (hashed,)).fetchone()
            found = self.admin()
            if row is None or found is None or found['disabled'] or not self._alive(row[1], row[2], now):
                if row is not None:
                    self.db.execute('DELETE FROM sessions WHERE token_hash = ?', (hashed,))
                return None
            if now - row[2] > 30000:
                self.db.execute('UPDATE sessions SET last_ms = ? WHERE token_hash = ?', (now, hashed))
        session = self.settings['session']
        return {'username': found['username'], 'role': 'administrator', 'csrf': row[0], 'token_hash': hashed, 'created_ms': row[1],
                'expires_ms': min(now + session['idle_minutes'] * 60000, row[1] + session['absolute_hours'] * 3600000)}

    def logout(self, hashed, actor, request_id=None):
        with self.lock:
            self.db.execute('DELETE FROM sessions WHERE token_hash = ?', (hashed,))
        self.record(actor, 'logout', None, 'ok', request_id)

    def change_password(self, identity, current, new, request_id=None):
        """Needs the current password. Ends every session, and gives this browser a new one."""
        with self.verifier:
            found = self.admin()
            good = verify_password(str(current or '')[:MAX_PASSWORD], found['password'])
        if not good:
            self.record(identity['username'], 'password_change', None, 'refused', request_id)
            raise AuthError('refused')
        check_new_password(new)
        if new == current:
            raise AuthError('the new password is the same as the old one')
        self.set_password(new, identity['username'])
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        now = self.clock()
        with self.lock:
            self.db.execute('INSERT INTO sessions (token_hash, csrf, created_ms, last_ms) VALUES (?, ?, ?, ?)', (token_hash(token), csrf, now, now))
        return token, csrf

    # Audit: authentication, and every state-changing request. Chained, so a removed row shows.
    def record(self, actor, action, target, outcome, request_id=None, detail=None):
        clean = {k: v for k, v in (detail or {}).items() if not any(word in k.lower() for word in FORBIDDEN_DETAIL)}
        at = self.clock()
        text = json.dumps(clean, sort_keys=True, separators=(',', ':'))
        with self.lock:
            last = self.db.execute('SELECT hash FROM audit ORDER BY seq DESC LIMIT 1').fetchone()
            previous = last[0] if last else GENESIS
            body = json.dumps([at, actor, action, target, outcome, request_id, text], separators=(',', ':'))
            current = hashlib.sha256((previous + body).encode()).hexdigest()
            self.db.execute('INSERT INTO audit (at_ms, actor, action, target, outcome, request_id, detail, previous, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', (at, actor, action, target, outcome, request_id, text, previous, current))

    # The two reads share the one connection with every request thread's writes, so they hold the lock as the writes do.
    # Unlocked, a concurrent request could interleave on the cursor.
    def audit_rows(self, limit=100, offset=0):
        with self.lock:
            rows = self.db.execute('SELECT seq, at_ms, actor, action, target, outcome, request_id, detail FROM audit ORDER BY seq DESC LIMIT ? OFFSET ?', (limit, offset)).fetchall()
        return [{**dict(zip(('seq', 'at_ms', 'actor', 'action', 'target', 'outcome', 'request_id'), r)), 'detail': json.loads(r[7])} for r in rows]

    def audit_verify(self):
        previous, count = GENESIS, 0
        with self.lock:
            rows = self.db.execute('SELECT seq, at_ms, actor, action, target, outcome, request_id, detail, previous, hash FROM audit ORDER BY seq').fetchall()
        for seq, at, actor, action, target, outcome, request_id, text, stored_previous, stored in rows:
            body = json.dumps([at, actor, action, target, outcome, request_id, text], separators=(',', ':'))
            if stored_previous != previous or hashlib.sha256((previous + body).encode()).hexdigest() != stored:
                return {'intact': False, 'entries': count, 'first_broken': seq}
            previous, count = stored, count + 1
        return {'intact': True, 'entries': count, 'first_broken': None}
