"""The analyst interface: a local Unix socket, as in Phases 11, 12 and 14. The kernel names the caller. Members of
siem-analyst read and add notes. Members of siem-path-admin may also rebuild a path or state that two identities
are one, and each is audited. Root is refused, because an audit entry must name a person.

There is no action that changes an incident, an asset or a host. These actions are the dashboard contract.
"""
import grp
import json
import os
import pwd
import socket
import struct
import threading

from . import model
from .evidence import StoreDown
from .model import clean, iso

ANALYST = 'siem-analyst'
ADMIN_GROUP = 'siem-path-admin'
MAX_REQUEST = 65536
MAX_NOTE = 2000
MAX_ROWS = 500


class ActionError(ValueError):
    pass


def peer(connection):
    return struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))


def member(uid, gid, group):
    if uid == 0:
        return None
    try:
        name = pwd.getpwuid(uid).pw_name
        wanted = grp.getgrnam(group)
    except KeyError:
        return None
    return name if name in wanted.gr_mem or gid == wanted.gr_gid else None


def row(item):
    return {**item, 'updated_at': iso(item['updated_ms'])}


class Actions:
    def __init__(self, work):
        self.work = work
        self.store = work.store

    def _path(self, value):
        found = self.store.find(clean(value, 64))
        path = self.store.path(found) if found else None
        if path is None:
            raise ActionError('no such path')
        return path

    def health(self, actor):
        return self.work.health()

    def list(self, actor, tier=None, limit=200):
        if tier is not None and tier not in model.TIERS:
            raise ActionError(f'a tier is one of {model.TIERS}')
        return [row(r) for r in self.store.list(tier, min(int(limit), MAX_ROWS))]

    def show(self, actor, path):
        found = self._path(path)
        return {k: v for k, v in found.items() if k not in ('nodes', 'edges', 'fingerprint')} | {'node_count': len(found['nodes']), 'edge_count': len(found['edges']), 'notes': self._notes(found['path_id'])}

    def search(self, actor, query):
        text = clean(query, 120)
        if not text:
            raise ActionError('nothing to search for')
        return [row(r) for r in self.store.search(text)]

    def graph(self, actor, path):
        found = self._path(path)
        return {'path_id': found['path_id'], 'tier': found['tier'], 'conclusion': found['conclusion'], 'explanation': found['rationale'], 'nodes': found['nodes'], 'edges': [{k: v for k, v in e.items() if k != 'evidence'} | {'evidence_count': len(e['evidence'])} for e in found['edges']]}

    def evidence(self, actor, path, edge=None):
        found = self._path(path)
        rows = [{'edge': e['id'], 'type': e['type'], 'class': e['class'], 'basis': e['basis'], 'tier': e['tier'], 'state': e.get('state', 'not yet validated'), 'reason': e['reason'], 'supporting': e['supporting'], 'contradicting': e['contradicting'], 'evidence': e['evidence']} for e in found['edges'] if edge is None or e['id'].startswith(clean(edge, 32))]
        if edge is not None and not rows:
            raise ActionError('no such edge')
        return rows

    def timeline(self, actor, path):
        found = self._path(path)
        return [{k: s.get(k) for k in ('order', 'at', 'tactic', 'name', 'tier', 'explanation', 'techniques', 'events')} for s in found['stages']]

    def asset(self, actor, asset):
        text = clean(asset, 120)
        ids = self.store.by_asset(text)
        return [row({k: p[k] for k in ('path_id', 'tier', 'title', 'updated_ms')}) for p in (self.store.path(i) for i in ids)]

    def incident(self, actor, incident):
        if not model.valid_id(incident):
            raise ActionError('an incident id is 32 hexadecimal characters')
        found = self.store.by_seed('incident', incident)
        if found is None:
            raise ActionError('no path for that incident')
        return self.show(actor, found)

    def history(self, actor, path):
        return [{**r, 'at': iso(r['at_ms'])} for r in self.store.history(self._path(path)['path_id'])]

    def validate(self, actor, path=None):
        """With a path, reads its evidence again. Without one, checks both hash chains."""
        if path is None:
            entries, broken = self.store.verify()
            audit, audit_broken = self.store.verify_audit()
            return {'history': entries, 'history_first_broken': broken, 'audit': audit, 'audit_first_broken': audit_broken, 'intact': broken is None and audit_broken is None}
        found = self._path(path)
        try:
            counts = self.work.validate(found, actor)
        except StoreDown as error:
            raise ActionError(f'evidence cannot be read now: {error}. The stored result is unchanged') from None
        return {'path_id': found['path_id'], 'counts': counts, 'state': found['evidence_state'], 'tier': found['tier']}

    def explain(self, actor, path):
        found = self._path(path)
        return {'path_id': found['path_id'], 'title': found['title'], 'tier': found['tier'], 'conclusion': found['conclusion'], 'why_this_tier': found['rationale'], 'analyst_status': found['analyst_status'], 'attack_sources': found['attack_sources'], 'affected_assets': found['affected_assets'], 'telemetry_sources': found['telemetry_sources'], 'identities': found['identities'],
                'what_happened': [f"{s.get('at')}: [{s['tactic']}] {s['explanation']} ({s['tier']})" for s in found['stages']], 'doubts': found['contradictions'], 'not_visible': found['gaps'], 'unrelated_events_left_out': found['excluded_unrelated_events'], 'attack_techniques': sorted({t['id'] for s in found['stages'] for t in s['techniques']}), 'evidence_state': found.get('evidence_state', 'not yet validated'), 'next_steps': found['next_steps']}

    def audit(self, actor, path=None):
        found = self._path(path)['path_id'] if path else None
        return [{**r, 'at': iso(r['ts_ms'])} for r in self.store.audit_rows(found)]

    def _notes(self, path_id):
        return [{'at': iso(r['ts_ms']), 'by': r['actor'], 'note': r['detail'].get('note')} for r in self.store.audit_rows(path_id) if r['action'] == 'note']

    def note(self, actor, path, text):
        """An analyst's own conclusion, kept apart from what the engine worked out."""
        found = self._path(path)
        note = clean(text, MAX_NOTE)
        if not note:
            raise ActionError('a note needs text')
        self.store.audit(found['path_id'], self.work.clock(), actor, 'note', {'note': note})
        return {'path_id': found['path_id'], 'by': actor}

    # Administer.
    def rebuild(self, actor, path, reason):
        found = self._path(path)
        why = clean(reason, 300)
        if not why:
            raise ActionError('a reason is required')
        try:
            result = self.work.build(found['seed']['kind'], found['seed']['id'], f'rebuilt by {actor}')
        except StoreDown as error:
            raise ActionError(f'evidence cannot be read now: {error}') from None
        self.store.audit(found['path_id'], self.work.clock(), actor, 'rebuild', {'reason': why, 'result': result})
        return {'path_id': found['path_id'], 'result': result}

    def link_identities(self, actor, a, b, reason):
        """A statement by a person that two accounts are one. Nothing else can make this link."""
        why = clean(reason, 300)
        first, second = clean(a, 200), clean(b, 200)
        if not why or not first.startswith('identity:') or not second.startswith('identity:') or first == second:
            raise ActionError('two different identity ids and a reason are required')
        link_id = model.digest(*sorted((first, second)))
        self.store.link(link_id, first, second, actor, why, self.work.clock())
        self.store.audit(None, self.work.clock(), actor, 'link_identities', {'a': first, 'b': second, 'reason': why})
        return {'link': link_id, 'by': actor, 'note': 'paths holding both identities show this as an analyst statement when next rebuilt'}


READS = ('health', 'list', 'show', 'search', 'graph', 'evidence', 'timeline', 'asset', 'incident', 'history', 'validate', 'explain', 'audit', 'note')
WRITES = ('rebuild', 'link_identities')


def handle(actions, request, identity):
    """`identity` is (analyst name or None, administrator name or None), both from the kernel."""
    name = request.get('action') if isinstance(request, dict) else None
    analyst, admin = identity
    if name not in READS + WRITES:
        return {'ok': False, 'error': 'unknown action'}
    actor = admin if name in WRITES else (analyst or admin)
    if actor is None:
        actions.store.audit(None, actions.work.clock(), analyst or 'unknown', 'refused', {'action': name})
        return {'ok': False, 'error': f'not a member of {ADMIN_GROUP if name in WRITES else ANALYST}'}
    arguments = {k: v for k, v in request.items() if k not in ('action', 'actor')}
    try:
        return {'ok': True, 'result': getattr(actions, name)(actor, **arguments)}
    except (ActionError, TypeError) as error:
        return {'ok': False, 'error': str(error)}
    except Exception as error:
        return {'ok': False, 'error': type(error).__name__}


class Server:
    def __init__(self, path, actions, group=ANALYST, admin_group=ADMIN_GROUP, log=print):
        self.path = path
        self.actions = actions
        self.group = group
        self.admin_group = admin_group
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

    @staticmethod
    def _read(connection):
        chunks, size = [], 0
        while size <= MAX_REQUEST:
            chunk = connection.recv(MAX_REQUEST)
            if not chunk:
                return b''.join(chunks)
            chunks.append(chunk)
            size += len(chunk)
        raise ValueError('request too large')

    def _serve(self, connection):
        with connection:
            connection.settimeout(60)
            try:
                _, uid, gid = peer(connection)
                identity = (member(uid, gid, self.group), member(uid, gid, self.admin_group))
                raw = self._read(connection)
                if identity == (None, None):
                    self.actions.store.audit(None, self.actions.work.clock(), f'uid:{uid}', 'refused', {'reason': 'not an analyst'})
                    connection.sendall(json.dumps({'ok': False, 'error': f'not a member of {self.group}'}).encode())
                    return
                reply = handle(self.actions, json.loads(raw), identity)
            except (ValueError, OSError):
                reply = {'ok': False, 'error': 'bad request'}
            connection.sendall(json.dumps(reply, default=str).encode())

    def stop(self):
        if self.socket:
            self.socket.close()


def call(path, request, timeout=120):
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
