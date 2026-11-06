"""What the SIEM's own telemetry says about its machines. Read-only, with a fixed set of bounded queries over a
moving window of ingest time, so an event delivered late still counts, and nothing is read twice.

Absence here proves nothing: a program that did not run is not a program that was removed. Telemetry adds to the
inventory, and only a snapshot takes anything away. See docs/detection/asset-inventory.md.
"""
from . import changes, inventory, schema
from .schema import HIGH, INFERRED, MEDIUM, OBSERVED

# (dataset, code): (change, category, field holding its subject).
EVENTS = {
    ('windows.system', '7045'): ('service_installed_event', changes.SECURITY, 'service.name'),
    ('windows.security', '4697'): ('service_installed_event', changes.SECURITY, 'service.name'),
    ('windows.security', '4720'): ('account_created_event', changes.SECURITY, 'user.target.name'),
    ('windows.security', '4726'): ('account_deleted_event', changes.NOTABLE, 'user.target.name'),
    ('windows.security', '4732'): ('group_member_added_event', changes.SECURITY, 'group.name'),
    ('windows.security', '4733'): ('group_member_removed_event', changes.NOTABLE, 'group.name'),
    ('windows.sysmon', '16'): ('sysmon_configuration_changed', changes.SECURITY, None),
}
# (action): (change, category, field holding its subject). Only program-verified events get these names.
LINUX_EVENTS = {
    'user-created': ('account_created_event', changes.SECURITY, 'user.target.name'),
    'user-deleted': ('account_deleted_event', changes.NOTABLE, 'user.target.name'),
    'group-member-added': ('group_member_added_event', changes.SECURITY, 'group.name'),
    'group-member-removed': ('group_member_removed_event', changes.NOTABLE, 'group.name'),
    'crontab-replaced': ('crontab_changed_event', changes.SECURITY, 'user.target.name'),
    'service-failed': ('service_failed_event', changes.NOTABLE, 'service.name'),
}
LINUX_INDEX = 'siem-linux-*'
SUCCESS, FAILURE = 'authenticated_on', 'failed_authentication_on'


def dig(source, path):
    node = source
    for part in path.split('.'):
        node = node.get(part) if isinstance(node, dict) else None
    return node


def _top(bucket, name):
    rows = (bucket.get(name) or {}).get('buckets') or []
    return rows[0]['key'] if rows else ''


class Telemetry:
    def __init__(self, opensearch, inventory_, settings=None, log=print):
        self.opensearch = opensearch
        self.inventory = inventory_
        settings = settings or {}
        self.index = settings.get('index', 'siem-windows-*')
        self.backfill = settings.get('backfill_days', 7) * changes.DAY
        self.window = settings.get('max_window_hours', 24) * changes.HOUR
        self.lag = settings.get('lag_seconds', 60) * 1000
        self.max_hosts = settings.get('max_hosts', 50)
        self.max_users = settings.get('max_users', 100)
        self.max_peers = settings.get('max_peers', 100)
        self.max_processes = settings.get('max_processes', 500)
        self.max_events = settings.get('max_events', 100)
        self.continuous = tuple(settings.get('continuous_sources', ('windows.sysmon', 'windows.security')))
        self.silent = settings.get('silent_source_hours', 6) * changes.HOUR
        self.log = log
        self.truncated = 0
        self.behind = False
        self.unattributed_linux = 0

    def _search(self, size, query, aggregations=None, sort=None):
        body = {'size': size, 'timeout': '15s', 'track_total_hits': False, 'query': query}
        if aggregations:
            body['aggs'] = aggregations
        if sort:
            body['sort'] = sort
        return self.opensearch.search_raw(self.index, body)

    @staticmethod
    def _within(start, end, *terms):
        return {'bool': {'filter': [{'range': {'event.ingested': {'gte': start, 'lt': end, 'format': 'epoch_millis'}}}, *terms]}}

    def _terms(self, field, size, **sub):
        return {'terms': {'field': field, 'size': size}, **({'aggs': sub} if sub else {})}

    def _count_cut(self, aggregation):
        if (aggregation or {}).get('sum_other_doc_count'):
            self.truncated += 1

    def run(self, store, baseline_until):
        """One window. Returns the number of hosts seen. The mark moves only after the whole window has been applied."""
        now = self.inventory.clock()
        end = now - self.lag
        start = int(store.mark('telemetry', now - self.backfill))
        if end <= start:
            return 0
        self.behind = end > start + self.window
        end = min(end, start + self.window)
        self._linux(start, end, baseline_until)
        assets = self._hosts(start, end)
        if assets:
            self._users(start, end, assets)
            self._network(start, end, assets)
            self._processes(start, end, assets)
            self._events(start, end, assets, baseline_until)
        store.set_mark('telemetry', end)
        return len(assets)

    def _linux(self, start, end, baseline_until):
        """Linux events carry a digest of the machine id, the same one a snapshot stores, so they join by
        identity rather than by name. An id no asset holds is counted, and no record is made from it."""
        store = self.inventory.store
        latest = {'max': {'field': '@timestamp'}}
        window = self._within(start, end)
        hosts = {'terms': {'field': 'host.id', 'size': self.max_hosts}, 'aggs': {
            'first': {'min': {'field': '@timestamp'}}, 'last': latest, 'name': self._terms('host.name', 2), 'sources': self._terms('event.dataset', 8, last=latest),
            'people': {'filter': {'terms': {'event.category': ['authentication', 'session']}}, 'aggs': {'users': self._terms('user.name', self.max_users, last=latest, outcome=self._terms('event.outcome', 2, last=latest))}}}}
        buckets = self.opensearch.search_raw(LINUX_INDEX, {'size': 0, 'timeout': '15s', 'track_total_hits': False, 'query': window, 'aggs': {'hosts': hosts}})['aggregations']['hosts']['buckets']
        owners = {}
        for bucket in buckets:
            holders = store.holders('linux_machine_id', schema.clean(bucket['key'], 64))
            names = bucket['name']['buckets']
            host = schema.hostname(names[0]['key']) if len(names) == 1 else None
            if len(holders) != 1 or host is None:
                self.unattributed_linux += bucket['doc_count']
                continue
            asset_id = next(iter(holders))
            owners[bucket['key']] = asset_id
            first_ms, last_ms = int(bucket['first']['value']), int(bucket['last']['value'])
            store.add_identifier('hostname', host, asset_id, 'telemetry:linux', last_ms)
            store.touch(asset_id, min(first_ms, store.asset(asset_id)['first_ms'] or first_ms), last_ms)
            for source in bucket['sources']['buckets']:
                seen = int(source['last']['value'])
                self.inventory.bounded_item(asset_id, 'telemetry_source', schema.clean(source['key'], 60), {'name': schema.clean(source['key'], 60)}, OBSERVED, 'telemetry:linux', HIGH, seen, seen)
            for row in bucket['people']['users']['buckets']:
                name = schema.clean(row['key'], 100)
                if not name:
                    continue
                entity = f'{host}\\{name}'.lower()
                seen = int(row['last']['value'])
                self.inventory.bounded_item(asset_id, 'observed_user', entity, {'name': name, 'domain': host, 'type': inventory.account_type(name), 'type_is': 'inferred from the name'}, OBSERVED, 'telemetry:linux.auth', HIGH, seen, seen)
                for outcome in row['outcome']['buckets']:
                    relation = SUCCESS if outcome['key'] == 'success' else FAILURE
                    store.relate('user', entity, relation, 'asset', asset_id, OBSERVED, HIGH, 'telemetry:linux.auth', int(outcome['last']['value']), count=outcome['doc_count'])
        if not owners:
            return
        hits = self.opensearch.search_raw(LINUX_INDEX, {'size': self.max_events, 'timeout': '15s', 'track_total_hits': False, 'sort': [{'event.ingested': 'asc'}], 'query': self._within(start, end, {'terms': {'event.action': sorted(LINUX_EVENTS)}})})['hits']['hits']
        for hit in hits:
            event = hit['_source']
            rule = LINUX_EVENTS.get(dig(event, 'event.action'))
            asset_id = owners.get(dig(event, 'host.id'))
            ingested = dig(event, 'event.ingested')
            if not rule or not asset_id or (ingested and schema.ms(ingested) <= baseline_until):
                continue
            store.record_change(asset_id, schema.ms(event['@timestamp']), rule[0], rule[1], schema.clean(dig(event, rule[2]), 120) or None, None, None, OBSERVED, f"telemetry:{dig(event, 'event.dataset')}", f"event:{hit['_id']}")

    def _hosts(self, start, end):
        latest = {'max': {'field': '@timestamp'}}
        first = {'min': {'field': '@timestamp'}}
        result = self._search(0, self._within(start, end), {'hosts': self._terms('host.name', self.max_hosts, first=first, last=latest, family=self._terms('host.os.family', 1), sources=self._terms('event.dataset', 12, last=latest))})
        self._count_cut(result['aggregations']['hosts'])
        assets = {}
        for bucket in result['aggregations']['hosts']['buckets']:
            first_ms, last_ms = int(bucket['first']['value']), int(bucket['last']['value'])
            asset_id = self.inventory.attribute(bucket['key'], first_ms, last_ms, 'telemetry:windows')
            if asset_id is None:
                # Cannot be attributed yet. Resolving the conflict replays from here, so nothing is lost.
                if schema.hostname(bucket['key']) and self.inventory.store.mark('held_since') is None:
                    self.inventory.store.set_mark('held_since', start)
                continue
            assets[bucket['key']] = asset_id
            family = _top(bucket, 'family')
            if family in schema.PLATFORMS and self.inventory.store.asset(asset_id)['platform'] == 'unknown':
                self.inventory.store.update_asset(asset_id, platform=family)
            for source in bucket['sources']['buckets']:
                seen = int(source['last']['value'])
                self.inventory.bounded_item(asset_id, 'telemetry_source', schema.clean(source['key'], 60), {'name': schema.clean(source['key'], 60)}, OBSERVED, 'telemetry:windows', HIGH, seen, seen)
        return assets

    def _users(self, start, end, assets):
        latest = {'max': {'field': '@timestamp'}}
        codes = {'terms': {'event.code': ['4624', '4625']}}
        users = self._terms('user.name', self.max_users, last=latest, domain=self._terms('user.domain', 1), code=self._terms('event.code', 2, last=latest))
        result = self._search(0, self._within(start, end, {'term': {'event.dataset': 'windows.security'}}, codes), {'hosts': self._terms('host.name', self.max_hosts, users=users)})
        store = self.inventory.store
        for bucket in result['aggregations']['hosts']['buckets']:
            asset_id = assets.get(bucket['key'])
            self._count_cut(bucket['users'])
            for row in bucket['users']['buckets'] if asset_id else ():
                name, domain = schema.clean(row['key'], 100), schema.clean(_top(row, 'domain'), 80)
                if not name or name == '-':
                    continue
                entity = f'{domain}\\{name}'.lower() if domain else name.lower()
                last_ms = int(row['last']['value'])
                self.inventory.bounded_item(asset_id, 'observed_user', entity, {'name': name, 'domain': domain, 'type': inventory.account_type(name), 'type_is': 'inferred from the name'}, OBSERVED, 'telemetry:windows.security', MEDIUM, last_ms, last_ms)
                for code in row['code']['buckets']:
                    relation = SUCCESS if code['key'] == '4624' else FAILURE
                    store.relate('user', entity, relation, 'asset', asset_id, OBSERVED, MEDIUM, f"telemetry:windows.security/{code['key']}", int(code['last']['value']), count=code['doc_count'])

    def _network(self, start, end, assets):
        latest = {'max': {'field': '@timestamp'}}
        peers = self._terms('destination.ip', self.max_peers, last=latest, port=self._terms('destination.port', 3))
        filters = (self._within(start, end, {'term': {'event.dataset': 'windows.sysmon'}}, {'term': {'event.code': '3'}}, {'term': {'network.direction': 'outbound'}}))
        result = self._search(0, filters, {'hosts': self._terms('host.name', self.max_hosts, peers=peers, own=self._terms('source.ip', 8, last=latest))})
        store = self.inventory.store
        for bucket in result['aggregations']['hosts']['buckets']:
            asset_id = assets.get(bucket['key'])
            if not asset_id:
                continue
            self._count_cut(bucket['peers'])
            for row in bucket['own']['buckets']:
                ip = schema.address(row['key'])
                if ip and schema.routable(ip):
                    store.observe_ip(asset_id, ip, int(row['last']['value']), 'telemetry:windows.sysmon/3', inventory.GAP_MS)
            for row in bucket['peers']['buckets']:
                ip = schema.address(row['key'])
                if not ip or not schema.routable(ip):
                    continue
                last_ms = int(row['last']['value'])
                known = [a for a in store.holders_of_ip(ip, last_ms, inventory.GAP_MS) if a != asset_id]
                # Traffic shows that two addresses spoke, and nothing about trust or ownership.
                target = ('asset', known[0]) if len(known) == 1 else ('ip', ip)
                store.relate('asset', asset_id, 'communicates_with', *target, OBSERVED, MEDIUM, 'telemetry:windows.sysmon/3', last_ms, count=row['doc_count'])

    def _processes(self, start, end, assets):
        latest = {'max': {'field': '@timestamp'}}
        names = self._terms('process.name', self.max_processes, last=latest, product=self._terms('process.pe.product', 1), company=self._terms('process.pe.company', 1), version=self._terms('process.pe.file_version', 1))
        result = self._search(0, self._within(start, end, {'term': {'event.dataset': 'windows.sysmon'}}, {'term': {'event.code': '1'}}), {'hosts': self._terms('host.name', self.max_hosts, names=names)})
        for bucket in result['aggregations']['hosts']['buckets']:
            asset_id = assets.get(bucket['key'])
            self._count_cut(bucket['names'])
            for row in bucket['names']['buckets'] if asset_id else ():
                name = schema.clean(row['key'], 120)
                last_ms = int(row['last']['value'])
                # Ran here. That does not say it is installed, so it is not listed as software.
                self.inventory.bounded_item(asset_id, 'process', name.lower(), {'name': name, 'product': schema.clean(_top(row, 'product'), 120), 'company': schema.clean(_top(row, 'company'), 100), 'version': schema.clean(_top(row, 'version'), 60)}, OBSERVED, 'telemetry:windows.sysmon/1', HIGH, last_ms, last_ms)

    def _events(self, start, end, assets, baseline_until):
        """Whatever reached the SIEM before the inventory first ran is the starting point, not a change."""
        codes = sorted({code for _, code in EVENTS})
        hits = self._search(self.max_events, self._within(start, end, {'terms': {'event.code': codes}}), sort=[{'event.ingested': 'asc'}])['hits']['hits']
        if len(hits) >= self.max_events:
            self.truncated += 1
        for hit in hits:
            event = hit['_source']
            rule = EVENTS.get((dig(event, 'event.dataset'), str(dig(event, 'event.code'))))
            asset_id = assets.get(dig(event, 'host.name'))
            ingested = dig(event, 'event.ingested')
            if not rule or not asset_id or (ingested and schema.ms(ingested) <= baseline_until):
                continue
            kind, category, field = rule
            subject = schema.clean(dig(event, field), 120) if field else None
            at_ms = schema.ms(event['@timestamp'])
            self.inventory.store.record_change(asset_id, at_ms, kind, category, subject, None, None, OBSERVED, f"telemetry:{dig(event, 'event.dataset')}/{dig(event, 'event.code')}", f"event:{hit['_id']}")
            if kind == 'service_installed_event' and subject:
                key = schema.service_key(subject)
                if key not in self.inventory.store.item_map(asset_id, 'service'):
                    self.inventory.store.put_item(asset_id, 'service', key, {'name': key, 'display': '', 'state': '', 'start': '', 'binary': ''}, OBSERVED, f"telemetry:{dig(event, 'event.dataset')}/{dig(event, 'event.code')}", MEDIUM, at_ms)

    def silent_sources(self, asset_id, now):
        """A continuous source that stopped while the host still reports is a lead: an agent or log may be off.
        Only an inference, so it is labelled as one."""
        store = self.inventory.store
        sources = {i['key']: i['last_ms'] for i in store.items(asset_id, 'telemetry_source')}
        newest = max(sources.values(), default=None)
        if newest is None or now - newest > self.silent:
            return
        for name in self.continuous:
            seen = sources.get(name)
            if seen is not None and newest - seen > self.silent:
                store.record_change(asset_id, now, 'security_telemetry_silent', changes.SECURITY, name, seen, newest, INFERRED, 'telemetry gap', f'silent:{asset_id}:{name}:{seen}')
