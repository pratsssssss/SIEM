"""The inventory loop. Each stage is on its own timer, and a failure in one leaves the others running. Nothing
depends on this service: it reads the pipeline's indices, and writes only its own. See ADR-0013, D41.
"""
import base64
import hashlib
import json
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import collect, schema, views
from .changes import Lifecycle
from .inventory import GAP_MS, Inventory
from .schema import MEDIUM, OBSERVED, iso, ms
from .telemetry import Telemetry

CURRENT = 'siem-assets-current'
RELATIONSHIPS = 'siem-asset-relationships'
MAX_BACKOFF = 900000
GRACE_MS = 3600000
CATCH_UP_MS = 15000


class StoreDown(Exception):
    pass


class OpenSearch:
    def __init__(self, url, ca_file, user, password, timeout=20, opener=None):
        self.url = url.rstrip('/')
        self.timeout = timeout
        self.auth = 'Basic ' + base64.b64encode(f'{user}:{password}'.encode()).decode()
        self.opener = opener or urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=ca_file))).open

    def call(self, method, path, body=None, allow=()):
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(self.url + path, data=data, method=method, headers={'Content-Type': 'application/json', 'Authorization': self.auth})
        try:
            return json.load(self.opener(request, timeout=self.timeout))
        except urllib.error.HTTPError as error:
            if error.code in allow:
                return {}
            raise StoreDown(f'HTTP {error.code}') from None
        except (OSError, ValueError) as error:
            raise StoreDown(type(error).__name__) from None

    def ping(self):
        self.call('GET', '/')

    def search_raw(self, index, body):
        result = self.call('POST', f'/{index}/_search?allow_partial_search_results=false&ignore_unavailable=true&allow_no_indices=true', body)
        if result.get('timed_out') or result.get('_shards', {}).get('failed'):
            raise StoreDown('partial result')
        return result

    def search(self, index, body):
        return self.search_raw(index, body)['hits']['hits']


def shipped_change(change):
    row = views.change_row(change)
    return {**{k: v for k, v in row.items() if k != 'source'}, 'provenance': row['source']}


class Timer:
    def __init__(self, every_seconds):
        self.every = every_seconds * 1000
        self.due = 0
        self.wait = 0

    def ready(self, now):
        return now >= self.due

    def ran(self, now):
        self.wait = 0
        self.due = now + self.every

    def failed(self, now):
        """Backs off, so a store that is down is not hammered, and it recovers on its own."""
        self.wait = min(max(self.wait * 2, 30000), MAX_BACKOFF)
        self.due = now + self.wait


class Service:
    def __init__(self, store, opensearch, settings=None, clock=None, local=None, log=print):
        settings = settings or {}
        self.store = store
        self.opensearch = opensearch
        self.clock = clock or (lambda: int(time.time() * 1000))
        self.log = log
        self.watch = dict(settings.get('security_services') or {})
        self.inventory = Inventory(store, self.clock, self.watch, settings.get('max_new_assets_per_day', 25), settings.get('max_items_per_kind', 1500), log)
        self.telemetry = Telemetry(opensearch, self.inventory, settings.get('telemetry'), log)
        self.policy = Lifecycle.load(settings.get('lifecycle'))
        self.drop = settings.get('drop_folder')
        self.local = local or (lambda: collect.linux_snapshot(iso(self.clock())))
        self.collect_local = settings.get('collect_local', True)
        every = settings.get('intervals') or {}
        self.timers = {'drop': Timer(every.get('drop_seconds', 120)), 'local': Timer(every.get('local_seconds', 21600)), 'telemetry': Timer(every.get('telemetry_seconds', 300)), 'incidents': Timer(every.get('incidents_seconds', 300)), 'lifecycle': Timer(every.get('lifecycle_seconds', 3600)), 'flush': Timer(every.get('flush_seconds', 30))}
        self.started = self.clock()
        # This service starts with the stack, and a service still starting is not a service stopped.
        self.timers['local'].due = self.started + every.get('local_delay_seconds', 300) * 1000
        self.state = {'opensearch': 'unknown', 'rejected_reports': 0, 'last_rejection': None, 'unattributed_incident_hosts': 0}

    # Sources.
    def take(self, raw, digest):
        try:
            snap = schema.snapshot(raw, self.clock())
            return self.inventory.apply(snap, digest)
        except schema.Invalid as error:
            self.state['rejected_reports'] += 1
            self.state['last_rejection'] = str(error)[:120]
            self.log(f'report refused: {error}')
            return 'refused'

    def scan_drop(self):
        if not self.drop:
            return
        files, refused = collect.read_drop(self.drop)
        for name, why in refused:
            self.state['rejected_reports'] += 1
            self.state['last_rejection'] = why
            self.log(f'file refused: {why}')
        for name, raw in files:
            digest = hashlib.sha256(raw).hexdigest()
            if self.state.get(f'digest:{name}') == digest:
                continue
            self.state[f'digest:{name}'] = digest
            try:
                self.take(collect.decode(raw), digest)
            except (ValueError, UnicodeDecodeError):
                self.state['rejected_reports'] += 1
                self.state['last_rejection'] = 'not JSON'

    def collect_here(self):
        snap, gaps = self.local()
        if gaps:
            self.log(f"local collection incomplete: {', '.join(gaps)}")
        self.take(snap, hashlib.sha256(json.dumps(snap, sort_keys=True, default=str).encode()).hexdigest())

    def incidents(self):
        """Links assets to incidents. Reads only, and matches on names as the incident recorded them."""
        store = self.store
        after = max(int(store.mark('incidents', 0)) - 300000, 0)
        hits = self.opensearch.search('siem-incidents-*', {'size': 200, 'sort': [{'updated_at': 'asc'}], 'query': {'range': {'updated_at': {'gte': after, 'format': 'epoch_millis'}}}, '_source': ['incident_id', 'hosts', 'ips', 'first_seen', 'last_seen', 'updated_at']})
        newest = None
        for hit in hits:
            source = hit['_source']
            try:
                at_ms = ms(source['last_seen'])
                newest = max(newest or 0, ms(source['updated_at']))
            except (KeyError, ValueError, TypeError):
                continue
            incident_id = schema.clean(source.get('incident_id'), 64)
            found = set()
            for name in source.get('hosts') or ():
                host = schema.hostname(name)
                holders = store.holders('hostname', host) if host else set()
                if len(holders) == 1:
                    found |= holders
                else:
                    self.state['unattributed_incident_hosts'] += 1
            for ip in source.get('ips') or ():
                address = schema.address(ip)
                if address and schema.routable(address):
                    holders = store.holders_of_ip(address, at_ms, GAP_MS)
                    if len(holders) == 1:
                        found |= set(holders)
            for asset_id in found:
                store.relate('asset', asset_id, 'involved_in', 'incident', incident_id, OBSERVED, MEDIUM, 'siem-incidents', at_ms, count=0)
        if newest:
            store.set_mark('incidents', newest)

    def lifecycle(self):
        """Nothing goes stale because the SIEM itself was off, so time is judged only once data has caught up."""
        now = self.clock()
        behind = now - int(self.store.mark('telemetry', 0))
        if now - self.started < GRACE_MS or behind > GRACE_MS:
            return 0
        moved = self.inventory.lifecycle(self.policy)
        for asset in self.store.assets():
            self.telemetry.silent_sources(asset['asset_id'], now)
        return moved

    # Output.
    def flush(self):
        """Runs every 30 seconds, with or without work, so an outage shows in health promptly."""
        self.opensearch.ping()
        now = self.clock()
        for asset_id in self.store.dirty_assets():
            asset = self.store.asset(asset_id)
            self.opensearch.call('PUT', f'/{CURRENT}/_doc/{asset_id}', views.document(self.store, asset, self.watch, now))
            self.store.clean_asset(asset_id, asset['revision'], asset['last_ms'])
        for rel in self.store.dirty_relationships():
            self.opensearch.call('PUT', f"/{RELATIONSHIPS}/_doc/{rel['rel_id']}", {**views.rel_row(rel), 'schema_version': schema.SCHEMA_VERSION})
            self.store.clean_relationship(rel['rel_id'], rel['last_ms'], rel['count'])
        for change in self.store.unshipped_changes():
            index = 'siem-asset-history-' + iso(change['at_ms'])[:7].replace('-', '.')
            self.opensearch.call('PUT', f"/{index}/_create/{change['seq']}-{change['hash'][:16]}", {**shipped_change(change), 'schema_version': schema.SCHEMA_VERSION, 'previous': change['previous'], 'hash': change['hash']}, allow=(409,))
            self.store.shipped('change', change['seq'])
        for row in self.store.unshipped_audit():
            index = 'siem-asset-audit-' + iso(row['ts_ms'])[:7].replace('-', '.')
            self.opensearch.call('PUT', f"/{index}/_create/{row['seq']}-{row['hash'][:16]}", {**row, 'at': iso(row['ts_ms'])}, allow=(409,))
            self.store.shipped('audit', row['seq'])

    def _stage(self, name, action, needs_store):
        timer = self.timers[name]
        now = self.clock()
        if not timer.ready(now):
            return
        try:
            action()
            timer.ran(now)
            if name == 'telemetry' and self.telemetry.behind:
                timer.due = now + CATCH_UP_MS
            if needs_store:
                self.state['opensearch'] = 'ok'
        except StoreDown as error:
            self.state['opensearch'] = str(error)
            timer.failed(now)
        except Exception as error:
            self.state[f'failed:{name}'] = type(error).__name__
            self.log(f'{name} failed: {type(error).__name__}')
            timer.failed(now)
        else:
            self.state.pop(f'failed:{name}', None)

    def _telemetry(self):
        baseline = int(self.store.mark('baseline_until', 0))
        if not baseline:
            baseline = self.clock()
            self.store.set_mark('baseline_until', baseline)
        self.telemetry.run(self.store, baseline)

    def cycle(self):
        self._stage('drop', self.scan_drop, False)
        if self.collect_local:
            self._stage('local', self.collect_here, False)
        self._stage('telemetry', self._telemetry, True)
        self._stage('incidents', self.incidents, True)
        self._stage('lifecycle', self.lifecycle, False)
        self._stage('flush', self.flush, True)

    def health(self):
        reasons = []
        if self.state['opensearch'] not in ('ok', 'unknown'):
            reasons.append(f"OpenSearch: {self.state['opensearch']}")
        reasons += [f'{k[7:]} failed: {v}' for k, v in self.state.items() if k.startswith('failed:')]
        security = self.store.count_unacknowledged()
        conflicts = len(self.store.conflicts())
        if security:
            reasons.append(f'{security} security-relevant changes unreviewed')
        if conflicts:
            reasons.append(f'{conflicts} identity conflicts open')
        assets = self.store.assets()
        counts = {}
        for asset in assets:
            status = views.status_of(self.store, asset)
            counts[status] = counts.get(status, 0) + 1
        return {'status': 'WARN' if reasons else 'OK', 'checked_ms': self.clock(), 'message': '; '.join(reasons) or f"{sum(v for k, v in counts.items() if k != 'retired')} assets in service", 'assets': counts, 'open_conflicts': conflicts, 'security_changes_unreviewed': security, 'backlog': self.store.backlog(), 'telemetry_through': views.when(int(self.store.mark('telemetry', 0))), 'truncated_queries': self.telemetry.truncated, 'unattributed_linux_events': self.telemetry.unattributed_linux, 'refused_new_assets': self.inventory.refused_new,
                'sources': [{'source': s['source'].split(':')[0], 'collected_at': views.when(s['collected_ms']), 'applied_at': views.when(s['ok_ms'])} for s in self.store.sources()], **{k: v for k, v in self.state.items() if not k.startswith(('digest:', 'failed:'))}}

    def write_reports(self, paths):
        report = self.health()
        for path in paths:
            target = Path(path)
            try:
                spare = target.with_suffix('.tmp')
                spare.write_text(json.dumps(report if str(path).startswith('/home/') else {k: report[k] for k in ('status', 'checked_ms', 'message')}, indent=1))
                spare.replace(target)
            except OSError as error:
                self.log(f'could not write {path}: {error}')

    def serve(self, reports, tick=2.0, stopping=lambda: False, sleep=time.sleep):
        last_report = 0
        while not stopping():
            now = self.clock()
            try:
                self.cycle()
            except Exception as error:
                self.log(f'cycle failed: {type(error).__name__}')
            if now - last_report >= 60000:
                self.write_reports(reports)
                last_report = now
            sleep(tick)
