"""The analyst interface: a local Unix socket, and nothing on the network.

Identity comes from the kernel (SO_PEERCRED), so a client cannot claim to be someone else. Only members of
the siem-analyst group may connect. Root is refused, because an audit entry must name a person.
"""
import grp
import json
import os
import pwd
import socket
import struct
import threading

from .incidents import ActionError, public
from .schema import iso

GROUP = 'siem-analyst'
MAX_REQUEST = 65536


def peer(connection):
    """(pid, uid, gid) of the process at the other end, as the kernel recorded them."""
    return struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))


def authorize(uid, gid, group=GROUP):
    """The person's name, or None. Group membership is read from the system, not from the request."""
    if uid == 0:
        return None
    try:
        name = pwd.getpwuid(uid).pw_name
        wanted = grp.getgrnam(group)
    except KeyError:
        return None
    return name if name in wanted.gr_mem or gid == wanted.gr_gid else None


def summary(incident):
    return {k: incident.get(k) for k in ('incident_id', 'title', 'status', 'severity', 'confidence_level', 'first_seen', 'last_seen', 'hosts', 'users')} | {'alerts': len(incident['alert_ids'])}


class Actions:
    """What an analyst can do. Every change names the person, and goes to the audit trail."""

    def __init__(self, service):
        self.service = service
        self.store = service.store
        self.manager = service.manager

    def list(self, actor, status=None, limit=50):
        return [summary(i) for i in self.store.list_incidents(status, min(int(limit), 500))]

    def show(self, actor, incident_id):
        found = self.store.incident(incident_id)
        if found is None:
            raise ActionError('no such incident')
        return public(found)

    def timeline(self, actor, incident_id):
        found = self.store.incident(incident_id)
        if found is None:
            raise ActionError('no such incident')
        return found['timeline']

    def search(self, actor, host=None, user=None, ip=None, severity=None, limit=50):
        rows = []
        for incident in self.store.list_incidents(None, 5000):
            if host and host.lower() not in [h.lower() for h in incident['hosts']]:
                continue
            if user and not any(user.lower() in u.lower() for u in incident['users']):
                continue
            if ip and ip not in incident['ips']:
                continue
            if severity and incident['severity'] != severity:
                continue
            rows.append(summary(incident))
        return rows[:min(int(limit), 500)]

    def status(self, actor, incident_id, state, note=None):
        return summary(self.manager.transition(incident_id, state, actor, note, self.service.clock()))

    def note(self, actor, incident_id, text):
        return summary(self.manager.add_note(incident_id, actor, text, self.service.clock()))

    def audit(self, actor, incident_id=None, limit=200):
        return [{**row, 'at': iso(row['ts_ms'])} for row in self.store.audit_rows(incident_id, min(int(limit), 1000))]

    def verify(self, actor):
        entries, broken = self.store.audit_verify()
        return {'entries': entries, 'first_broken': broken, 'intact': broken is None}

    def rules(self, actor):
        stats = self.store.rule_stats()
        return [{'id': r.id, 'title': r.title, 'kind': r.kind, 'join': r.join, 'window_seconds': r.window_seconds, 'enabled': self.store.rule_enabled(r.id, r.enabled), **stats.get(r.id, {'matches': 0, 'last_ms': None})} for r in self.service.rules]

    def rule(self, actor, rule_id, enabled):
        if rule_id not in {r.id for r in self.service.rules}:
            raise ActionError('no such rule')
        with self.store.lock, self.store.db:
            self.store.set_rule(rule_id, bool(enabled))
            self.store.audit(None, self.service.clock(), actor, 'rule', {'rule': rule_id, 'enabled': bool(enabled)})
        return {'rule': rule_id, 'enabled': bool(enabled)}

    def replay(self, actor, hours):
        try:
            return self.service.replay(int(hours), actor)
        except ValueError as error:
            raise ActionError(str(error)) from None

    def health(self, actor):
        return self.service.health()

    def quarantine(self, actor):
        return self.store.quarantined()


PUBLIC = ('list', 'show', 'timeline', 'search', 'status', 'note', 'audit', 'verify', 'rules', 'rule', 'replay', 'health', 'quarantine')


def handle(actions, request, actor):
    """Runs one request. Unknown actions and bad arguments are errors, never exceptions on the socket."""
    name = request.get('action') if isinstance(request, dict) else None
    if name not in PUBLIC:
        return {'ok': False, 'error': 'unknown action'}
    arguments = {k: v for k, v in request.items() if k != 'action' and k != 'actor'}
    try:
        return {'ok': True, 'result': getattr(actions, name)(actor, **arguments)}
    except (ActionError, TypeError) as error:
        return {'ok': False, 'error': str(error)}
    except Exception as error:
        return {'ok': False, 'error': type(error).__name__}


class Server:
    def __init__(self, path, actions, group=GROUP, log=print):
        self.path = path
        self.actions = actions
        self.group = group
        self.log = log
        self.socket = None

    def start(self):
        if os.path.exists(self.path):
            os.unlink(self.path)
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.bind(self.path)
        os.chmod(self.path, 0o660)
        try:
            os.chown(self.path, -1, grp.getgrnam(self.group).gr_gid)
        except (KeyError, PermissionError):
            self.log('control socket: group not set')
        self.socket.listen(8)
        threading.Thread(target=self._loop, daemon=True, name='control').start()

    def _loop(self):
        while True:
            try:
                connection, _ = self.socket.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(connection,), daemon=True).start()

    def _serve(self, connection):
        with connection:
            connection.settimeout(10)
            try:
                _, uid, gid = peer(connection)
                actor = authorize(uid, gid, self.group)
                # Read first even when refusing. Closing with unread data resets the connection, and the reason is lost.
                raw = self._read(connection)
                if actor is None:
                    with self.actions.store.lock, self.actions.store.db:
                        self.actions.store.audit(None, self.actions.service.clock(), f'uid:{uid}', 'refused', {'reason': 'not an analyst'})
                    connection.sendall(json.dumps({'ok': False, 'error': f'not a member of {self.group}'}).encode())
                    return
                reply = handle(self.actions, json.loads(raw), actor)
            except (ValueError, OSError):
                reply = {'ok': False, 'error': 'bad request'}
            connection.sendall(json.dumps(reply, default=str).encode())

    @staticmethod
    def _read(connection):
        """The request, up to the limit. The client ends it by shutting down its side."""
        chunks, size = [], 0
        while size <= MAX_REQUEST:
            chunk = connection.recv(MAX_REQUEST)
            if not chunk:
                return b''.join(chunks)
            chunks.append(chunk)
            size += len(chunk)
        raise ValueError('request too large')

    def stop(self):
        if self.socket:
            self.socket.close()


def call(path, request, timeout=60):
    """The client side, used by the siem-incident command."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(timeout)
        client.connect(path)
        client.sendall(json.dumps(request).encode())
        client.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            chunk = client.recv(1048576)
            if not chunk:
                break
            chunks.append(chunk)
    return json.loads(b''.join(chunks))
