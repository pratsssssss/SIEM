"""The analyst interface: a local Unix socket, as in Phases 11 and 12. The kernel names the caller. Members of
siem-analyst may read. Only members of siem-asset-admin may change ownership, criticality or identity, and every
such change is audited. Root is refused, because an audit entry must name a person.

These actions and their replies are the backend contract for the dashboard. See docs/detection/asset-inventory.md.
"""
import grp
import json
import os
import pwd
import socket
import struct
import threading

from . import changes, schema, views
from .context import Context, NotFound
from .schema import iso

ANALYST = 'siem-analyst'
ADMIN_GROUP = 'siem-asset-admin'
MAX_REQUEST = 65536
MAX_NOTE = 2000
MAX_ROWS = 1000


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


class Actions:
    def __init__(self, work):
        self.work = work
        self.store = work.store
        self.context = Context(work.store, work.opensearch, work.watch)

    def _asset(self, value):
        try:
            return self.context.one(value)
        except NotFound as error:
            raise ActionError(str(error)) from None

    def _note(self, text, required=False):
        note = schema.clean(text, MAX_NOTE)
        if required and not note:
            raise ActionError('a reason is required')
        return note

    # Read.
    def health(self, actor):
        return self.work.health()

    def list(self, actor, status=None, criticality=None, limit=500):
        rows = [views.summary(self.store, a) for a in self.store.assets()]
        rows = [r for r in rows if (status is None or r['status'] == status) and (criticality is None or r.get('criticality') == criticality)]
        return rows[:min(int(limit), MAX_ROWS)]

    def show(self, actor, asset):
        return views.full(self.store, self._asset(asset), self.work.watch)

    def search(self, actor, query, limit=50):
        text = schema.clean(query, 120)
        if not text:
            raise ActionError('nothing to search for')
        return [views.summary(self.store, self.store.asset(a)) for a in self.store.find_assets(text, min(int(limit), 200))]

    def history(self, actor, asset, category=None, limit=200):
        found = self._asset(asset)['asset_id']
        return [views.change_row(c) for c in self.store.changes([found, *self.store.merged_from(found)], category, min(int(limit), MAX_ROWS))]

    def relationships(self, actor, asset):
        return views.relationships(self.store, self._asset(asset)['asset_id'])

    def _items(self, asset, kind, removed=False):
        return [views.item_row(i) for i in self.store.items(self._asset(asset)['asset_id'], kind, not removed)]

    def software(self, actor, asset, removed=False):
        return {'installed': self._items(asset, 'software', removed), 'seen_running': self._items(asset, 'process', removed)}

    def services(self, actor, asset, removed=False):
        return self._items(asset, 'service', removed)

    def users(self, actor, asset):
        found = self._asset(asset)['asset_id']
        owner = self.store.attribute(found, 'owner', schema.ADMIN)
        return {'assigned_owner': owner, 'local_accounts': self._items(asset, 'local_account'), 'observed_users': self._items(asset, 'observed_user'), 'note': 'an observed user was seen on this machine, and that does not make them its owner'}

    def changes(self, actor, category=None, unreviewed=False, limit=200):
        rows = self.store.unacknowledged(min(int(limit), MAX_ROWS)) if unreviewed else self.store.changes(None, category, min(int(limit), MAX_ROWS))
        return [views.change_row(c) for c in rows]

    def stale(self, actor):
        return [views.summary(self.store, a) for a in self.store.assets() if a['status'] == changes.STALE]

    def conflicts(self, actor, all=False):
        return [{**c, 'opened': views.when(c['opened_ms']), 'closed': views.when(c['closed_ms'])} for c in self.store.conflicts(None if all else 'open')]

    def context_of(self, actor, asset=None, incident=None, alert=None, ip=None, at=None):
        try:
            if incident:
                return self.context.for_incident(incident)
            if alert:
                return self.context.for_alert(alert)
            if ip and at:
                return self.context.at_time(ip, at)
            return {'assets': [self.context.view(self.store.asset(a)) for a in self.context.pick(asset or ip)]}
        except NotFound as error:
            raise ActionError(str(error)) from None

    def export(self, actor):
        return views.export_csv(self.store)

    def validate(self, actor):
        entries, broken = self.store.verify_changes()
        audit, audit_broken = self.store.verify_audit()
        return {'history': entries, 'history_first_broken': broken, 'audit': audit, 'audit_first_broken': audit_broken, 'intact': broken is None and audit_broken is None}

    def audit(self, actor, asset=None, limit=200):
        found = self._asset(asset)['asset_id'] if asset else None
        return [{**r, 'at': iso(r['ts_ms'])} for r in self.store.audit_rows(found, min(int(limit), MAX_ROWS))]

    def acknowledge(self, actor, seq, note=None):
        done = self.store.acknowledge(int(seq), actor, self._note(note), self.work.clock())
        if not done:
            raise ActionError('no such security change')
        self.store.audit(None, self.work.clock(), actor, 'acknowledge', {'seq': int(seq), 'note': self._note(note)})
        return {'seq': int(seq), 'by': actor}

    # Administer.
    def metadata(self, actor, asset, name, value=None, clear=False):
        found = self._asset(asset)['asset_id']
        if name not in schema.METADATA:
            raise ActionError(f'metadata is one of {schema.METADATA}')
        if clear:
            self.work.inventory.clear_metadata(found, name, actor)
            return {'asset_id': found, 'cleared': name}
        try:
            if name == 'criticality':
                if value not in schema.CRITICALITY:
                    raise ActionError(f'criticality is one of {schema.CRITICALITY}')
            elif name == 'tags':
                value = sorted({schema.label(t, 40) for t in str(value).split(',') if t.strip()})[:20]
            else:
                value = schema.label(value)
        except schema.Invalid as error:
            raise ActionError(str(error)) from None
        self.work.inventory.set_metadata(found, name, value, actor)
        return {'asset_id': found, name: value}

    def register(self, actor, hostname, asset_type='unknown', platform='unknown'):
        host = schema.hostname(hostname)
        if host is None:
            raise ActionError('the host name is not valid')
        if asset_type not in schema.ASSET_TYPES or platform not in schema.PLATFORMS:
            raise ActionError('unknown asset type or platform')
        if self.store.holders('hostname', host):
            raise ActionError('an asset already holds this name')
        return {'asset_id': self.work.inventory.register(host, asset_type, platform, actor), 'status': changes.DECLARED}

    def retire(self, actor, asset, reason):
        found = self._asset(asset)
        if found['status'] == changes.RETIRED:
            raise ActionError('already retired')
        self.work.inventory.set_status(found['asset_id'], changes.RETIRED, actor, self._note(reason, True))
        return {'asset_id': found['asset_id'], 'status': changes.RETIRED, 'note': 'the record and its history are kept'}

    def reactivate(self, actor, asset, reason):
        found = self._asset(asset)
        if found['status'] not in (changes.RETIRED, changes.REAPPEARED, changes.STALE):
            raise ActionError('only a retired, reappeared or stale asset can be reactivated')
        self.work.inventory.set_status(found['asset_id'], changes.ACTIVE, actor, self._note(reason, True))
        return {'asset_id': found['asset_id'], 'status': changes.ACTIVE}

    def resolve(self, actor, conflict, decision, keep=None, reason=None):
        """`merge`: one machine, and `keep` survives. `separate`: different machines, and `keep`, if named, keeps the
        shared host name. Both are recorded with who decided and why."""
        item = self.store.conflict(conflict)
        if item is None or item['state'] != 'open':
            raise ActionError('no such open conflict')
        reason = self._note(reason, True)
        if decision not in ('merge', 'separate'):
            raise ActionError('a decision is merge or separate')
        if keep is not None and keep not in item['assets']:
            raise ActionError('keep must be one of the assets in this conflict')
        now = self.work.clock()
        others = [a for a in item['assets'] if a != keep]
        with self.store.tx():
            if decision == 'merge':
                if keep is None or len(item['assets']) < 2:
                    raise ActionError('a merge needs two assets, and names the one to keep')
                for other in others:
                    self.store.merge(other, keep, now)
                    self.store.record_change(keep, now, 'assets_merged', changes.NOTABLE, other, other, keep, schema.ADMIN, f'admin:{actor}')
            elif keep:
                shared = {i['value'] for i in self.store.identifiers(keep) if i['kind'] == 'hostname'}
                for other in others:
                    for row in self.store.identifiers(other):
                        if row['kind'] == 'hostname' and row['value'] in shared:
                            self.store.set_identifier_active('hostname', row['value'], other, False)
            self.store.close_conflict(item['conflict_id'], actor, f'{decision}: {reason}', now)
            held = self.store.mark('held_since')
            if held is not None and not self.store.conflicts():
                self.store.set_mark('telemetry', held)
                self.store.clear_mark('held_since')
            self.store.set_mark('incidents', 0)
            for name in item['assets']:
                self.store.update_asset(name, status_ms=self.store.asset(name)['status_ms'])
            self.store.audit(keep, now, actor, 'resolve', {'conflict': item['conflict_id'], 'kind': item['kind'], 'decision': decision, 'keep': keep, 'assets': item['assets'], 'reason': reason})
        return {'conflict': item['conflict_id'], 'decision': decision, 'keep': keep}


READS = ('health', 'list', 'show', 'search', 'history', 'relationships', 'software', 'services', 'users', 'changes', 'stale', 'conflicts', 'context_of', 'export', 'validate', 'audit', 'acknowledge')
WRITES = ('metadata', 'register', 'retire', 'reactivate', 'resolve')


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
            connection.settimeout(30)
            try:
                _, uid, gid = peer(connection)
                identity = (member(uid, gid, self.group), member(uid, gid, self.admin_group))
                # Read first even when refusing. Closing with unread data resets the connection.
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


def call(path, request, timeout=60):
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
