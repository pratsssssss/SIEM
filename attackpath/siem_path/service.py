"""The loop. It watches incidents and high alerts, rebuilds what changed, re-checks stored evidence, and publishes.
It reads the pipeline's indices and writes only its own. It has no way to change an incident, an asset or a host.
"""
import base64
import json
import socket
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import engine, model
from .evidence import Collector, StoreDown, fact_evidence, to_fact
from .model import INSUFFICIENT, PLAUSIBLE, iso, ms

MAX_BACKOFF = 900000
MAX_ATTEMPTS = 5
ASSET_CACHE_MS = 60000
GRAPH = 'siem-attack-path-graph-'


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

    def search(self, index, body):
        result = self.call('POST', f'/{index}/_search?allow_partial_search_results=false&ignore_unavailable=true&allow_no_indices=true', {'timeout': '15s', **body})
        if result.get('timed_out') or result.get('_shards', {}).get('failed'):
            raise StoreDown('partial result')
        return result['hits']['hits']


def asset_socket_lookup(path, timeout=5):
    """Asks Phase 14 who held an address at a moment. Unreachable means unknown, and analysis carries on."""
    def lookup(address, at_ms):
        request = {'action': 'context_of', 'ip': address, 'at': iso(at_ms)}
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(timeout)
                client.connect(path)
                client.sendall(json.dumps(request).encode())
                client.shutdown(socket.SHUT_WR)
                chunks = []
                while True:
                    chunk = client.recv(65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
            reply = json.loads(b''.join(chunks))
        except (OSError, ValueError):
            return None
        return [h['asset_id'] for h in (reply.get('result') or {}).get('holders', [])] if reply.get('ok') else None
    return lookup


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
        self.wait = min(max(self.wait * 2, 30000), MAX_BACKOFF)
        self.due = now + self.wait


class Service:
    def __init__(self, store, opensearch, settings=None, clock=None, ip_lookup=None, log=print):
        settings = settings or {}
        self.store = store
        self.opensearch = opensearch
        self.clock = clock or (lambda: int(time.time() * 1000))
        self.log = log
        self.limits = settings.get('limits') or {}
        self.collector = Collector(opensearch.search, self.limits)
        self.ip_lookup = ip_lookup
        self.per_cycle = settings.get('paths_per_cycle', 5)
        self.backfill = settings.get('backfill_days', 30) * 86400000
        self.alert_levels = settings.get('alert_seed_severities', ['high', 'critical'])
        self.validate_batch = settings.get('validate_batch', 5)
        every = settings.get('intervals') or {}
        self.timers = {'sync': Timer(every.get('sync_seconds', 120)), 'work': Timer(every.get('work_seconds', 10)), 'validate': Timer(every.get('validate_seconds', 3600)), 'flush': Timer(every.get('flush_seconds', 30))}
        self.state = {'opensearch': 'unknown', 'last_build_ms': None, 'gave_up': 0}
        self._assets = (0, None)

    def assets(self):
        """Current records from Phase 14. If they cannot be read, analysis continues with nothing resolved."""
        now = self.clock()
        if self._assets[1] is not None and now - self._assets[0] < ASSET_CACHE_MS:
            return self._assets[1]
        try:
            rows = [h['_source'] for h in self.opensearch.search('siem-assets-current', {'size': 500, '_source': ['asset_id', 'hostname', 'aliases', 'status', 'platform', 'identity_confidence', 'criticality', 'owner', 'merged_into'], 'query': {'match_all': {}}})]
            found = engine.Assets(rows, self.ip_lookup, available=bool(rows))
        except StoreDown:
            found = engine.Assets((), None, available=False)
        self._assets = (now, found)
        return found

    # Finding work.
    def sync(self):
        """New and changed incidents, and high alerts that belong to no incident."""
        now = self.clock()
        since = max(int(self.store.mark('sync', now - self.backfill)) - 300000, 0)
        incidents = self.opensearch.search('siem-incidents-*', {'size': 200, '_source': ['incident_id', 'alert_ids'], 'sort': [{'updated_at': 'asc'}], 'query': {'range': {'updated_at': {'gte': since, 'format': 'epoch_millis'}}}})
        for hit in incidents:
            incident_id = hit['_source'].get('incident_id')
            if model.valid_id(incident_id):
                self.store.enqueue('incident', incident_id, now)
        covered = set()
        for hit in self.opensearch.search('siem-incidents-*', {'size': 500, '_source': ['alert_ids'], 'query': {'range': {'updated_at': {'gte': now - self.backfill, 'format': 'epoch_millis'}}}}):
            ids = hit['_source'].get('alert_ids')
            covered |= set(ids) if isinstance(ids, list) else set()
        alerts = self.opensearch.search('siem-alerts-*', {'size': 200, '_source': ['alert_id'], 'sort': [{'detected_at': 'asc'}], 'query': {'bool': {'filter': [{'terms': {'severity': self.alert_levels}}, {'range': {'detected_at': {'gte': since, 'format': 'epoch_millis'}}}]}}})
        for hit in alerts:
            alert_id = hit['_source'].get('alert_id')
            if model.valid_id(alert_id) and alert_id not in covered:
                self.store.enqueue('alert', alert_id, now)
        if len(incidents) < 200 and len(alerts) < 200:
            self.store.set_mark('sync', now)

    def seed(self, kind, seed_id):
        """Everything one reconstruction needs, or None if the seed no longer exists."""
        collector = self.collector
        if kind == 'incident':
            incident = collector.incident(seed_id)
            if incident is None:
                return None
            ids = incident.get('alert_ids')
            alerts = collector.alerts(ids if isinstance(ids, list) else [])
            seed = engine.Seed('incident', seed_id, incident.get('title') or 'incident', model.clean(incident.get('status'), 20), model.clean(incident.get('severity'), 16), alerts, incident)
        else:
            alerts = collector.alerts([seed_id])
            if not alerts:
                return None
            seed = engine.Seed('alert', seed_id, alerts[0].get('rule_name') or 'alert', 'no_incident', model.clean(alerts[0].get('severity'), 16), alerts)
        refs = [r for a in alerts for r in a.get('raw_event_refs') or []]
        seed.events, seed.missing = collector.events(refs)
        times = [ms(a['timestamp']) for a in alerts if a.get('timestamp')]
        hosts = {model.clean(a.get('host'), 120).lower() for a in alerts if a.get('host')}
        if times:
            seed.context = collector.context(hosts, min(times), max(times))
        seed.intelligence = collector.intelligence([a.get('alert_id') for a in alerts])
        seed.identity_links = self.store.links()
        cited = (seed.incident or {}).get('alert_ids')
        seed.limited = len(seed.context) >= collector.context_events or (isinstance(cited, list) and len(cited) > collector.max_alerts)
        return seed

    def build(self, kind, seed_id, why='new evidence'):
        seed = self.seed(kind, seed_id)
        if seed is None:
            return None
        path = engine.build(seed, self.assets(), self.limits)
        result = self.store.save(path, self.clock(), why)
        self.state['last_build_ms'] = self.clock()
        return result

    def work(self):
        now = self.clock()
        for kind, seed_id, attempts in self.store.due(now, self.per_cycle):
            try:
                self.build(kind, seed_id)
                self.store.done(kind, seed_id)
            except StoreDown:
                if attempts + 1 >= MAX_ATTEMPTS:
                    self.store.retry(kind, seed_id, now + MAX_BACKOFF)
                    self.state['gave_up'] += 1
                else:
                    self.store.retry(kind, seed_id, now + 30000 * 2 ** attempts)
                raise
            except (KeyError, ValueError, TypeError, AttributeError) as error:
                # One bad record must not stall the rest. It is counted, and the seed is dropped.
                self.state['gave_up'] += 1
                self.store.done(kind, seed_id)
                self.store.audit(None, now, 'system', 'build_failed', {'seed': seed_id, 'kind': kind, 'error': type(error).__name__})

    # Checking evidence again.
    def validate(self, path, actor='system'):
        """Reads every cited event and alert again. What is gone or altered stops counting as verified."""
        counts = {'verified': 0, 'unavailable': 0, 'changed': 0, 'not_checked': 0}
        now = self.clock()
        for edge in path['edges']:
            states = []
            for item in edge['evidence']:
                if item['kind'] not in ('event', 'alert'):
                    counts['not_checked'] += 1
                    states.append(item.get('state', 'verified'))
                    continue
                found = self.collector.check(item['kind'], item['index'], item['id'])
                item['state'] = 'verified' if found is not None else 'unavailable'
                if found is not None and item['kind'] == 'event':
                    fact = to_fact(item['index'], item['id'], found)
                    if fact is None or fact_evidence(fact).as_dict()['digest'] != item['digest']:
                        item['state'] = 'changed'
                counts[item['state']] += 1
                states.append(item['state'])
            usable = [s for s in states if s == 'verified']
            if not usable:
                edge['state'] = 'evidence_unavailable'
                edge['tier'] = INSUFFICIENT
            else:
                edge['state'] = 'partly_available' if len(usable) < len(states) else 'verified'
                if edge['state'] == 'partly_available' and model.TIERS.index(edge['tier']) < model.TIERS.index(PLAUSIBLE):
                    edge['tier'] = PLAUSIBLE
        checked = [e for e in path['edges'] if any(i['kind'] in ('event', 'alert') for i in e['evidence'])]
        lost = [e for e in checked if e.get('state') == 'evidence_unavailable']
        weakened = [e for e in checked if e.get('state') != 'verified']
        if weakened:
            path['tier'] = INSUFFICIENT if len(lost) == len(checked) else model.TIERS[max(model.TIERS.index(path['tier']), model.TIERS.index(PLAUSIBLE))]
            path['evidence_state'] = f'{len(weakened)} of {len(checked)} edges have lost evidence, so they no longer count as verified'
        else:
            path['evidence_state'] = 'all cited evidence was found'
        path['validated_at'] = iso(now)
        path['validation'] = counts
        self.store.update_body(path, now)
        self.store.audit(path['path_id'], now, actor, 'validate', counts)
        return counts

    def validate_some(self):
        for path_id in self.store.oldest_validated(self.validate_batch):
            self.validate(self.store.path(path_id))

    # Output.
    def flush(self):
        self.opensearch.ping()
        for path in self.store.dirty():
            month = iso(path['created_ms'])[:7].replace('-', '.')
            at = iso(path['updated_ms'])
            summary = {k: v for k, v in path.items() if k not in ('nodes', 'edges')}
            summary = {**summary, 'path_at': at, 'node_count': len(path['nodes']), 'edge_count': len(path['edges'])}
            self.opensearch.call('PUT', f"/siem-attack-paths-{month}/_doc/{path['path_id']}", summary)
            for node in path['nodes']:
                self.opensearch.call('PUT', f"/{GRAPH}{month}/_doc/{path['path_id']}-{node['id'].replace(':', '-')}", {'doc_type': 'node', 'path_id': path['path_id'], 'schema_version': model.SCHEMA_VERSION, 'at': at, **node})
            for edge in path['edges']:
                self.opensearch.call('PUT', f"/{GRAPH}{month}/_doc/{path['path_id']}-{edge['id']}", {'doc_type': 'edge', 'path_id': path['path_id'], 'schema_version': model.SCHEMA_VERSION, 'at': at, **edge, 'first_seen': iso(edge['first_ms']) if edge['first_ms'] else None, 'last_seen': iso(edge['last_ms']) if edge['last_ms'] else None})
            self.store.clean(path['path_id'], path['updated_ms'])
        for row in self.store.unshipped_history():
            index = 'siem-attack-path-history-' + iso(row['at_ms'])[:7].replace('-', '.')
            self.opensearch.call('PUT', f"/{index}/_create/{row['seq']}-{row['hash'][:16]}", {**row, 'at': iso(row['at_ms'])}, allow=(409,))
            self.store.shipped('history', row['seq'])
        for row in self.store.unshipped_audit():
            index = 'siem-attack-path-audit-' + iso(row['ts_ms'])[:7].replace('-', '.')
            self.opensearch.call('PUT', f"/{index}/_create/{row['seq']}-{row['hash'][:16]}", {**row, 'at': iso(row['ts_ms'])}, allow=(409,))
            self.store.shipped('audit', row['seq'])

    def _stage(self, name, action):
        timer = self.timers[name]
        now = self.clock()
        if not timer.ready(now):
            return
        try:
            action()
            timer.ran(now)
            self.state['opensearch'] = 'ok'
            self.state.pop(f'failed:{name}', None)
        except StoreDown as error:
            self.state['opensearch'] = str(error)
            timer.failed(now)
        except Exception as error:
            self.state[f'failed:{name}'] = type(error).__name__
            self.log(f'{name} failed: {type(error).__name__}')
            timer.failed(now)

    def cycle(self):
        self._stage('sync', self.sync)
        self._stage('work', self.work)
        self._stage('validate', self.validate_some)
        self._stage('flush', self.flush)

    def health(self):
        reasons = []
        if self.state['opensearch'] not in ('ok', 'unknown'):
            reasons.append(f"OpenSearch: {self.state['opensearch']}")
        reasons += [f'{k[7:]} failed: {v}' for k, v in self.state.items() if k.startswith('failed:')]
        counts = self.store.count()
        return {'status': 'WARN' if reasons else 'OK', 'checked_ms': self.clock(), 'message': '; '.join(reasons) or f'{sum(counts.values())} paths', 'paths': counts, 'queue': self.store.backlog(), 'oldest_queued_ms': self.store.oldest_due(self.clock()), 'evidence': self.store.evidence_state(), 'output_backlog': self.store.output_backlog(), **{k: v for k, v in self.state.items() if not k.startswith('failed:')}}

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
