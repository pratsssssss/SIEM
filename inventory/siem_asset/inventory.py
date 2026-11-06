"""Turns reports into asset records. A report is applied whole or not at all, and every meaningful difference
goes to history in the same transaction. Nothing here reaches outside the local store.
"""
from . import changes, identity, schema
from .changes import Change
from .schema import ADMIN, HIGH, INFERRED, LOW, MEDIUM, OBSERVED

GAP_MS = 7 * changes.DAY
RANK = {LOW: 0, MEDIUM: 1, HIGH: 2}
SHRINK = 0.5
SHRINK_FLOOR = 20
FLIP_MS = 86400000
SETS = {'software': changes.software, 'users': changes.users, 'listeners': changes.listeners}
ITEM_KIND = {'software': 'software', 'services': 'service', 'users': 'local_account', 'listeners': 'listener'}
_NOT_PERSON = ('system', 'local service', 'network service', 'anonymous logon')


def account_type(name):
    """An inference from the name's shape, and labelled as one."""
    lowered = name.lower()
    if lowered in _NOT_PERSON or lowered.endswith('$') or lowered.startswith(('dwm-', 'umfd-', 'nt service\\')):
        return 'service_account'
    return 'unknown'


class Inventory:
    def __init__(self, store, clock, watch_services=(), max_new_per_day=25, max_items=1500, log=print):
        self.store = store
        self.clock = clock
        self.watch = frozenset(watch_services)
        self.max_new = max_new_per_day
        self.max_items = max_items
        self.log = log
        self.refused_new = 0

    def _change(self, asset_id, at_ms, change, klass, source, baseline=False, dedupe=None):
        if not baseline:
            self.store.record_change(asset_id, at_ms, change.kind, change.category, change.subject, change.before, change.after, klass, source, dedupe)

    def _seen(self, asset_id, at_ms, source):
        asset = self.store.asset(asset_id)
        moved = changes.seen_again(asset['status'])
        if moved:
            self.store.update_asset(asset_id, status=moved[0], status_ms=self.clock())
            self._change(asset_id, at_ms, moved[1], OBSERVED, source)

    def _open(self, found, now, asset_id=None):
        for item in found:
            members = sorted(set(item['assets']) | ({asset_id} if asset_id else set()))
            if item['kind'] == 'ambiguous_hostname' and any(set(members) <= set(c['assets']) for c in self.store.conflicts()):
                continue
            conflict_id = self.store.open_conflict(item['kind'], members, item['why'], now)
            if conflict_id:
                self.store.audit(None, now, 'system', 'conflict_opened', {'conflict': conflict_id, 'kind': item['kind'], 'assets': members})
                for member in members:
                    self.store.record_change(member, now, 'identity_conflict', changes.SECURITY if item['kind'] != 'ambiguous_hostname' else changes.NOTABLE, conflict_id, None, item['kind'], INFERRED, 'identity')
                    self.store.update_asset(member, status_ms=self.store.asset(member)['status_ms'])

    # Snapshots.
    def apply(self, snap, digest):
        """'applied', 'unchanged' or 'held'. Invalid if this is older than the last report from this machine."""
        seen = identity.Observation.of_snapshot(snap)
        source = f"snapshot:{snap['collector']}"
        key = f"{snap['collector']}:{next(iter(sorted(seen.strong.values())), snap['hostname'])}"
        last = self.store.source(key)
        at_ms, now = snap['collected_ms'], self.clock()
        if last and at_ms < last['collected_ms']:
            raise schema.Invalid('older than the last report from this machine')
        if last and last['digest'] == digest:
            return 'unchanged'
        with self.store.tx():
            found = identity.resolve(seen, self.store)
            if found.outcome == identity.HELD:
                self._open(found.conflicts, now)
                self.store.set_source(key, at_ms, digest, now)
                return 'held'
            asset_id = found.asset_id
            if asset_id is None:
                asset_id = self.store.create_asset(changes.NEW, snap['asset_type'], snap['platform'], snap['hostname'], found.confidence, source, now, at_ms, at_ms)
                self.store.record_change(asset_id, at_ms, 'asset_discovered', changes.NOTABLE, snap['hostname'], None, found.basis, OBSERVED, source)
            elif found.outcome == identity.ADOPTED:
                self.store.record_change(asset_id, at_ms, 'identity_adopted', changes.NOTABLE, snap['hostname'], None, found.basis, INFERRED, 'identity')
            self._open(found.conflicts, now, asset_id)
            self._apply_to(asset_id, snap, seen, found, source, at_ms, now)
            self.store.set_source(key, at_ms, digest, now)
        return 'applied'

    def _apply_to(self, asset_id, snap, seen, found, source, at_ms, now):
        store = self.store
        asset = store.asset(asset_id)
        baseline = asset['inventory_ms'] is None
        self._seen(asset_id, at_ms, source)
        for kind, value in seen.strong.items():
            store.add_identifier(kind, value, asset_id, source, at_ms)
        for name in seen.hostnames:
            store.add_identifier('hostname', name, asset_id, source, at_ms)
        macs_before = {i['value'] for i in store.identifiers(asset_id) if i['kind'] == 'mac' and i['active']}
        for address in seen.macs:
            store.add_identifier('mac', address, asset_id, source, at_ms)
        renamed = asset['hostname'] != snap['hostname']
        if renamed:
            flipping = any(c['kind'] == 'hostname_changed' and c['after'] == asset['hostname'] and c['before'] == snap['hostname'] and at_ms - c['at_ms'] < FLIP_MS for c in store.changes([asset_id], limit=50))
            self._change(asset_id, at_ms, Change('hostname_changed', changes.NOTABLE, None, asset['hostname'], snap['hostname']), OBSERVED, source)
            if flipping:
                self._open([identity.conflict('possible_clone', [asset_id], 'the host name alternates between two values, as when two machines share one identity')], now)
        macs_moved = not baseline and macs_before and seen.macs and not (macs_before & set(seen.macs))
        if macs_moved:
            self._change(asset_id, at_ms, Change('network_identity_changed' if renamed else 'physical_mac_changed', changes.SECURITY if renamed else changes.NOTABLE, None, sorted(macs_before), seen.macs), OBSERVED, source)
        confidence = found.confidence if RANK[found.confidence] >= RANK[asset['confidence']] else asset['confidence']
        store.update_asset(asset_id, hostname=snap['hostname'], asset_type=snap['asset_type'] if snap['asset_type'] != 'unknown' else asset['asset_type'], platform=snap['platform'] if snap['platform'] != 'unknown' else asset['platform'], confidence=confidence, source=source, inventory_ms=at_ms, collection_ms=now)
        for name, value in snap['os'].items():
            before = store.set_attribute(asset_id, f'os.{name}', OBSERVED, value, source, at_ms, HIGH)
            if before is not None and before != value:
                self._change(asset_id, at_ms, changes.os_change(name, before, value), OBSERVED, source)
        for name, value in (('domain_joined', snap['domain_joined']), ('virtual', snap['virtual']), ('vendor', snap['vendor']), ('model', snap['model'])):
            if value not in (None, ''):
                store.set_attribute(asset_id, f'host.{name}', OBSERVED, value, source, at_ms, HIGH)
        for name, value in snap['security'].items():
            before = store.set_attribute(asset_id, f'security.{name}', OBSERVED, value, source, at_ms, HIGH)
            if before is not None and before != value:
                self._change(asset_id, at_ms, changes.security_state(name, before, value), OBSERVED, source)
        for name in ('software', 'services', 'users', 'listeners'):
            if name in snap:
                self._sets(asset_id, name, snap[name], source, at_ms, baseline)
        if 'interfaces' in snap:
            self._network(asset_id, snap['interfaces'], source, at_ms, baseline)
        store.touch(asset_id, at_ms, at_ms)

    def _sets(self, asset_id, name, new, source, at_ms, baseline):
        """A list far shorter than the last one is more likely a failed read than a mass removal, so nothing is
        removed on its word. An attacker hiding things by the same route is caught by the same check."""
        kind = ITEM_KIND[name]
        store = self.store
        old = store.item_map(asset_id, kind)
        cut_short = len(old) >= SHRINK_FLOOR and len(new) < len(old) * SHRINK
        if cut_short:
            self._change(asset_id, at_ms, Change('collection_anomaly', changes.SECURITY, name, len(old), len(new)), OBSERVED, source)
            old = {k: v for k, v in old.items() if k in new}
        found = changes.services(old, new, self.watch) if name == 'services' else SETS[name](old, new)
        for change in found:
            self._change(asset_id, at_ms, change, OBSERVED, source, baseline)
        for key, body in new.items():
            store.put_item(asset_id, kind, key, body, OBSERVED, source, HIGH, at_ms)
        for key in old.keys() - new.keys():
            store.remove_item(asset_id, kind, key, at_ms)

    def _network(self, asset_id, interfaces, source, at_ms, baseline):
        store = self.store
        before = {x['ip'] for x in store.leases(asset_id) if x['end_ms'] >= (store.asset(asset_id)['last_ms'] or 0) and ':' not in x['ip']}
        present, now_ips = set(), set()
        for row in interfaces:
            key = row['name'].lower()
            present.add(key)
            store.put_item(asset_id, 'interface', key, row, OBSERVED, source, HIGH, at_ms)
            store.relate('asset', asset_id, 'has_interface', 'interface', f'{asset_id}/{key}', OBSERVED, HIGH, source, at_ms, count=0)
            for ip in row['ips']:
                if schema.routable(ip):
                    now_ips.add(ip)
                    store.observe_ip(asset_id, ip, at_ms, source, GAP_MS)
                    store.relate('asset', asset_id, 'has_ip', 'ip', ip, OBSERVED, HIGH, source, at_ms, count=0)
            for network in row['segments']:
                store.relate('asset', asset_id, 'in_segment', 'segment', network, INFERRED, MEDIUM, 'interface subnet', at_ms, count=0)
        for key in store.item_map(asset_id, 'interface').keys() - present:
            store.remove_item(asset_id, 'interface', key, at_ms)
        ipv4 = {x for x in now_ips if ':' not in x}
        if before and ipv4 and before != ipv4:
            self._change(asset_id, at_ms, Change('ip_changed', changes.ROUTINE, None, sorted(before), sorted(ipv4)), OBSERVED, source, baseline)

    # Telemetry and metadata.
    def attribute(self, name, first_ms, last_ms, source, create=True):
        """The asset a host name in telemetry belongs to, or None. Creates a provisional record if the name is
        unknown, because an unknown machine is exactly what an analyst wants to hear about."""
        host = schema.hostname(name)
        if host is None:
            return None
        now = self.clock()
        with self.store.tx():
            found = identity.resolve(identity.Observation(hostnames=[host]), self.store)
            self._open(found.conflicts, now)
            if found.outcome == identity.HELD:
                return None
            if found.asset_id:
                self._seen(found.asset_id, last_ms, source)
                self.store.touch(found.asset_id, first_ms, last_ms)
                return found.asset_id
            if not create:
                return None
            if self.store.count_recent(source, now - changes.DAY) >= self.max_new:
                self.refused_new += 1
                return None
            asset_id = self.store.create_asset(changes.NEW, 'unknown', 'unknown', host, LOW, source, now, first_ms, last_ms)
            self.store.add_identifier('hostname', host, asset_id, source, last_ms)
            self.store.record_change(asset_id, last_ms, 'asset_discovered', changes.NOTABLE, host, None, found.basis, OBSERVED, source)
        return asset_id

    def bounded_item(self, asset_id, kind, key, body, klass, source, confidence, first_ms, last_ms):
        """False when the list for this asset is full. A flood of names cannot grow the store without limit."""
        known = key in self.store.item_map(asset_id, kind) if self.store.count_items(asset_id, kind) >= self.max_items else True
        if known:
            self.store.put_item(asset_id, kind, key, body, klass, source, confidence, first_ms, last_ms)
        return known

    def set_metadata(self, asset_id, name, value, actor):
        now = self.clock()
        source = f'admin:{actor}'
        with self.store.tx():
            before = self.store.set_attribute(asset_id, name, ADMIN, value, source, now, HIGH)
            if before != value:
                self._change(asset_id, now, changes.admin_change(name, before, value), ADMIN, source)
            self.store.update_asset(asset_id, status_ms=self.store.asset(asset_id)['status_ms'])
            self.store.audit(asset_id, now, actor, 'metadata', {'name': name, 'before': before, 'after': value})

    def clear_metadata(self, asset_id, name, actor):
        now = self.clock()
        with self.store.tx():
            before = self.store.attribute(asset_id, name, ADMIN)
            self.store.clear_attribute(asset_id, name, ADMIN)
            if before is not None:
                self._change(asset_id, now, changes.admin_change(name, before, None), ADMIN, f'admin:{actor}')
            self.store.update_asset(asset_id, status_ms=self.store.asset(asset_id)['status_ms'])
            self.store.audit(asset_id, now, actor, 'metadata', {'name': name, 'before': before, 'after': None})

    def register(self, hostname, asset_type, platform, actor):
        """An administrator says a machine exists. It stays `declared` until something observes it."""
        now = self.clock()
        source = f'admin:{actor}'
        with self.store.tx():
            asset_id = self.store.create_asset(changes.DECLARED, asset_type, platform, hostname, LOW, source, now)
            self.store.add_identifier('hostname', hostname, asset_id, source, now)
            self.store.record_change(asset_id, now, 'asset_declared', changes.NOTABLE, hostname, None, None, ADMIN, source)
            self.store.audit(asset_id, now, actor, 'register', {'hostname': hostname, 'asset_type': asset_type, 'platform': platform})
        return asset_id

    def set_status(self, asset_id, status, actor, reason):
        now = self.clock()
        with self.store.tx():
            before = self.store.asset(asset_id)['status']
            self.store.update_asset(asset_id, status=status, status_ms=now)
            self._change(asset_id, now, Change('asset_retired' if status == changes.RETIRED else 'asset_reactivated', changes.NOTABLE, None, before, status), ADMIN, f'admin:{actor}')
            self.store.audit(asset_id, now, actor, 'status', {'before': before, 'after': status, 'reason': reason})

    def lifecycle(self, policy):
        """Moves assets on with time. An asset is never removed for going quiet."""
        now = self.clock()
        moved = 0
        for asset in self.store.assets():
            step = policy.tick(asset, now)
            if step:
                with self.store.tx():
                    self.store.update_asset(asset['asset_id'], status=step[0], status_ms=now)
                    self._change(asset['asset_id'], now, step[1], INFERRED, 'lifecycle')
                moved += 1
        return moved
