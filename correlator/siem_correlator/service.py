"""The correlation loop: take alerts, gather evidence, evaluate rules, and store incidents.

The order is what makes recovery safe. An alert is stored before its Kafka offset is committed. Evidence
is gathered before anything is changed. An incident change commits as one transaction, and reaches
OpenSearch from an outbox. A failure at any point repeats work, and loses nothing.
"""
import base64
import hashlib
import json
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import entities as ent
from . import schema
from .engine import Engine
from .incidents import Manager, public
from .schema import Invalid, iso, ms

EVENT_FIELDS = ['process.entity_id', 'process.parent.entity_id', 'process.name', 'process.parent.name', 'process.hash.sha256', 'user.name', 'user.domain', 'user.id', 'source.ip', 'destination.ip', 'dns.question.name']
HOSTILE = ('malicious', 'suspicious', 'conflicting')
SLOW_STEP_MS = 30000
SIGNAL_SEVERITY = {'malicious': 'high', 'conflicting': 'medium', 'suspicious': 'medium'}


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

    def search(self, index, body):
        result = self.call('POST', f'/{index}/_search?allow_partial_search_results=false&ignore_unavailable=true&allow_no_indices=true', body)
        if result.get('timed_out') or result.get('_shards', {}).get('failed'):
            raise StoreDown('partial result')
        return result['hits']['hits']


class Kafka:
    """Manual offsets. They are committed only after the alerts are stored."""

    def __init__(self, bootstrap, topic, group='siem-correlator'):
        from confluent_kafka import Consumer, KafkaError, TopicPartition
        self.error_codes = KafkaError
        self.partition = TopicPartition
        self.topic = topic
        self.consumer = Consumer({'bootstrap.servers': bootstrap, 'group.id': group, 'enable.auto.commit': False, 'auto.offset.reset': 'earliest', 'log_level': 3, 'client.id': 'siem-correlator'})
        self.consumer.subscribe([topic])

    def poll(self, limit, timeout):
        """Returns [(partition, offset, value)]. A broker fault raises, and nothing is committed."""
        rows = []
        for message in self.consumer.consume(num_messages=limit, timeout=timeout):
            error = message.error()
            if error is None:
                rows.append((message.partition(), message.offset(), message.value() or b''))
            elif error.code() != self.error_codes._PARTITION_EOF:
                raise StoreDown(f'kafka: {error.name()}')
        return rows

    def commit(self):
        self.consumer.commit(asynchronous=False)

    def lag(self):
        total = 0
        assigned = self.consumer.assignment()
        for item, done in zip(assigned, self.consumer.committed(assigned, timeout=5)):
            _, high = self.consumer.get_watermark_offsets(item, timeout=5)
            total += max(high - max(done.offset, 0), 0)
        return total

    def close(self):
        self.consumer.close()


def enrichment_index_doc(hits):
    return hits[0]['_source'] if hits else None


class Service:
    def __init__(self, store, rules, opensearch, kafka, clock=None, skew_seconds=120, enrichment_wait_seconds=1800, retry_seconds=30, retention_days=30, batch=200, log=print):
        self.store = store
        self.rules = rules
        self.opensearch = opensearch
        self.kafka = kafka
        self.clock = clock or (lambda: int(time.time() * 1000))
        self.skew = skew_seconds * 1000
        self.wait = enrichment_wait_seconds * 1000
        self.retry = retry_seconds * 1000
        self.retention = retention_days * 86400000
        self.batch = batch
        self.log = log
        self.engine = Engine(store, rules, skew_seconds)
        self.manager = Manager(store)
        self.state = {'kafka': 'unknown', 'opensearch': 'unknown', 'lag': None}
        self.last_slow = -SLOW_STEP_MS

    # Intake.
    def take(self, rows):
        """Stores what Kafka gave, then commits. A bad message goes to quarantine with its reason."""
        now = self.clock()
        new = 0
        for partition, offset, value in rows:
            try:
                alert = schema.parse(value)
            except Invalid as error:
                self.store.quarantine(now, str(error), partition, offset, hashlib.sha256(value).hexdigest(), len(value))
                self.log(f'alert quarantined at {partition}:{offset}: {error}')
                continue
            new += self.store.inbox(alert['alert_id'], alert['rule_id'], alert, now)
        return new

    def poll_kafka(self):
        try:
            rows = self.kafka.poll(self.batch, 1.0)
            self.take(rows)
            if rows:
                self.kafka.commit()
            # An empty poll proves nothing about the broker. probe() answers that.
            if rows or self.state['kafka'] == 'unknown':
                self.state['kafka'] = 'ok'
        except StoreDown as error:
            self.state['kafka'] = str(error)
        except Exception as error:
            self.state['kafka'] = type(error).__name__

    # Evidence.
    def _events(self, alert):
        refs = [r.split('/', 1) for r in alert.get('raw_event_refs', [])[:20] if '/' in r]
        ids = [r[1] for r in refs]
        if not ids:
            return []
        return [h['_source'] for h in self.opensearch.search('siem-windows-*', {'size': len(ids), '_source': EVENT_FIELDS, 'query': {'ids': {'values': ids}}})]

    def _enrichment(self, alert_id):
        return enrichment_index_doc(self.opensearch.search('siem-enrichment-*', {'size': 1, '_source': ['status', 'indicators.type', 'indicators.value', 'indicators.verdict', 'indicators.score', 'indicators.field', 'indicators.sources.source'], 'query': {'bool': {'filter': [{'term': {'doc_type': 'alert'}}, {'term': {'alert_id': alert_id}}]}}}))

    def _context(self, alert, events, enrichment):
        first, last, clock_note = schema.times(alert, self.skew)
        hostile = [{k: i.get(k) for k in ('type', 'value', 'verdict', 'score')} for i in (enrichment or {}).get('indicators', []) if i.get('verdict') in HOSTILE]
        conflicting = [i for i in hostile if i['verdict'] == 'conflicting']
        items, links, notes = ent.extract(alert, events, hostile)
        if clock_note:
            notes.append(clock_note)
        if conflicting:
            notes.append('threat intelligence conflicts on at least one indicator')
        fields = (alert.get('evidence') or {}).get('matched_fields') or {}
        host_name = (alert.get('host') or '').lower()

        def ids(name, *more):
            return [e.id for e in (ent.ip(v, host_name) for v in [*more, *fields.get(name, [])] if isinstance(v, (str, int))) if e]
        by_kind = lambda kind: [e for e in items if e.kind == kind]
        own, parents = [], []
        for event in events:
            child = ent.process(host_name, (event.get('process') or {}).get('entity_id'))
            parent = ent.process(host_name, ((event.get('process') or {}).get('parent') or {}).get('entity_id'))
            own += [child.id] if child else []
            parents += [parent.id] if parent else []
        return {
            'alert_id': alert['alert_id'], 'kind': 'alert', 'rule_id': alert['rule_id'], 'rule_name': alert['rule_name'], 'severity': alert['severity'], 'first_ms': first, 'last_ms': last, 'first_iso': iso(first),
            'host': alert.get('host'), 'user': alert.get('user'), 'tactics': (alert.get('mitre') or {}).get('tactics', []), 'facts': (alert.get('evidence') or {}).get('facts', {}),
            'entities': [e.__dict__ for e in items], 'links': links, 'process_ids': own, 'parent_ids': parents, 'parent_name': ent.parent_name(events),
            'process_name': next((p.display for p in by_kind(ent.PROCESS) if p.id in own), (fields.get('process.name') or [None])[0]),
            'source_ips': ids('source.ip', *filter(None, [alert.get('source_ip')])), 'destination_ips': ids('destination.ip'), 'event_ids': alert.get('source_event_ids', []), 'event_refs': alert.get('raw_event_refs', []), 'evidence_ref': alert.get('evidence_ref'),
            'enrichment_ref': None if enrichment is None else f"siem-enrichment/{alert['alert_id']}", 'hostile': hostile, 'enrichment': (enrichment or {}).get('status', 'pending'), 'notes': notes,
            'events_missing': bool(alert.get('raw_event_refs')) and not events,
        }

    def _signal_context(self, body):
        indicator = body['indicator']
        first = ms(body['timestamp'])
        items, links, notes = ent.extract({'alert_id': body['alert_id'], 'rule_id': body['rule_id'], 'rule_name': body['rule_name'], 'host': body.get('host')}, (), [indicator])
        return {'alert_id': body['alert_id'], 'kind': 'signal', 'rule_id': body['rule_id'], 'rule_name': body['rule_name'], 'severity': body['severity'], 'first_ms': first, 'last_ms': first, 'first_iso': iso(first), 'host': body.get('host'), 'user': None,
                'tactics': [], 'facts': {}, 'entities': [e.__dict__ for e in items], 'links': links, 'process_ids': [], 'parent_ids': [], 'parent_name': '', 'process_name': None, 'source_ips': [], 'destination_ips': [],
                'event_ids': [body['event_id']], 'event_refs': [f"{body['event_index']}/{body['event_id']}"], 'evidence_ref': None, 'enrichment_ref': f"siem-enrichment/{body['doc_id']}", 'hostile': [indicator], 'enrichment': 'complete', 'notes': notes, 'events_missing': False}

    @staticmethod
    def _entity_ids(context):
        found = [e['id'] for e in context['entities']]
        found += [f"username:{e['loose']}" for e in context['entities'] if e['kind'] == ent.USER and e.get('loose') and e['quality'] != 'weak']
        return found

    def _commit(self, context, now):
        """One transaction: what is known of the alert, every match, every incident change, and the audit."""
        with self.store.lock, self.store.db:
            self.store.analysed(context['alert_id'], context['first_ms'], context['last_ms'], context, self._entity_ids(context), context['links'], context['enrichment'])
            changed = []
            for match in self.engine.evaluate(context):
                incident_id = self.manager.apply(match, now)
                if incident_id:
                    self.store.rule_hit(match.rule.id, now)
                    changed.append(incident_id)
        return changed

    def process(self, limit=100):
        """Works through waiting alerts. If OpenSearch is down they stay, and are retried."""
        done = 0
        for alert_id, kind, body in self.store.due(self.clock(), limit):
            now = self.clock()
            try:
                context = self._signal_context(body) if kind == 'signal' else self._context(body, self._events(body), self._enrichment(alert_id))
                self._commit(context, now)
                done += 1
                self.state['opensearch'] = 'ok'
            except StoreDown as error:
                self.state['opensearch'] = str(error)
                self.store.retry_later(alert_id, now + self.retry)
            except (Invalid, KeyError, TypeError, ValueError, AttributeError) as error:
                self.log(f'alert {alert_id} cannot be analysed: {type(error).__name__}')
                self.store.fail(alert_id)
        return done

    def recheck_enrichment(self):
        """Enrichment arrives after the alert. When it does, the alert is evaluated again."""
        now = self.clock()
        for alert_id in self.store.enrichment_waiting(now, 60000):
            context = self.store.context(alert_id)
            document = self._enrichment(alert_id)
            if document is None:
                if now - self._received(alert_id) > self.wait:
                    context['enrichment'] = 'missing'
                    self.store.set_enrichment(alert_id, 'missing')
                    self._update_held(context, now)
                continue
            hostile = [{k: i.get(k) for k in ('type', 'value', 'verdict', 'score')} for i in document.get('indicators', []) if i.get('verdict') in HOSTILE]
            context.update(hostile=hostile, enrichment=document.get('status', 'complete'), enrichment_ref=f'siem-enrichment/{alert_id}')
            additions = [ent.indicator(i['type'], i['value'], i['verdict']).__dict__ for i in hostile]
            known = {e['id'] for e in context['entities']}
            context['entities'] += [a for a in additions if a['id'] not in known]
            self._commit(context, now)
            self._update_held(context, now)

    def _received(self, alert_id):
        with self.store.lock:
            row = self.store.db.execute('SELECT received_ms FROM alerts WHERE alert_id = ?', (alert_id,)).fetchone()
        return row[0] if row else 0

    def _update_held(self, context, now):
        """An incident holding this alert picks up the new evidence, and its score changes with it."""
        with self.store.lock, self.store.db:
            self.store.db.execute('UPDATE alerts SET context = ? WHERE alert_id = ?', (json.dumps(context), context['alert_id']))
            for incident_id in self.store.incidents_of([context['alert_id']]):
                incident = self.store.incident(incident_id)
                if context['alert_id'] in incident['_contexts']:
                    incident['_contexts'][context['alert_id']] = context
                    self.manager.refresh(incident, now)
                    self.store.save_incident(incident)
                    self.store.audit(incident_id, now, 'system', 'evidence', {'alert': context['alert_id'], 'enrichment': context['enrichment'], 'severity': incident['severity'], 'confidence': incident['confidence']})

    def poll_signals(self):
        """Intelligence matches on events. These are not alerts: Phase 10 writes them only to OpenSearch."""
        now = self.clock()
        start = self.store.mark('signals', now - 3600000) - 300000
        body = {'size': 200, '_source': ['event_id', 'event_index', 'host', '@timestamp', 'indicators.type', 'indicators.value', 'indicators.verdict', 'indicators.score'],
                'sort': [{'enriched_at': 'asc'}, {'event_id': 'asc'}], 'query': {'bool': {'filter': [{'term': {'doc_type': 'event'}}, {'range': {'enriched_at': {'gte': start, 'format': 'epoch_millis'}}}]}}}
        while True:
            hits = self.opensearch.search('siem-enrichment-*', body)
            for hit in hits:
                source = hit['_source']
                for item in source.get('indicators', []):
                    if item.get('verdict') in HOSTILE:
                        signal = hashlib.sha256(f"signal|{hit['_id']}|{item['type']}|{item['value']}".encode()).hexdigest()[:32]
                        self.store.inbox(signal, f"enrichment:{item['type']}", {
                            'alert_id': signal, 'rule_id': f"enrichment:{item['type']}", 'rule_name': f"Threat intelligence match on a {item['type']}", 'severity': SIGNAL_SEVERITY[item['verdict']], 'timestamp': source.get('@timestamp') or iso(now), 'host': source.get('host'),
                            'indicator': {k: item.get(k) for k in ('type', 'value', 'verdict', 'score')}, 'event_id': source.get('event_id'), 'event_index': source.get('event_index'), 'doc_id': hit['_id']}, now, kind='signal', source='enrichment')
            if len(hits) < 200:
                break
            body['search_after'] = hits[-1]['sort']
        self.store.set_mark('signals', now)

    # Output.
    def flush(self):
        """Sends incidents and audit entries. An older revision can never replace a newer one."""
        for incident in self.store.outbox():
            index = 'siem-incidents-' + iso(incident['created_ms'])[:7].replace('-', '.')
            self.opensearch.call('PUT', f"/{index}/_doc/{incident['incident_id']}?version={incident['revision']}&version_type=external", public(incident), allow=(409,))
            self.store.shipped(incident['incident_id'], incident['revision'])
        for row in self.store.audit_unshipped():
            index = 'siem-incident-audit-' + iso(row['ts_ms'])[:7].replace('-', '.')
            self.opensearch.call('PUT', f"/{index}/_create/{row['seq']}-{row['hash'][:16]}", {**row, 'at': iso(row['ts_ms'])}, allow=(409,))
            self.store.audit_shipped(row['seq'])

    def cycle(self):
        self.poll_kafka()
        self.process()
        now = self.clock()
        steps = [self.flush]
        if now - self.last_slow >= SLOW_STEP_MS:
            self.last_slow = now
            steps = [self.poll_signals, self.recheck_enrichment, self.flush]
        for step in steps:
            try:
                step()
                # Only this step always calls OpenSearch. The others may have nothing to do, which proves nothing.
                if step == self.poll_signals:
                    self.state['opensearch'] = 'ok'
            except StoreDown as error:
                self.state['opensearch'] = str(error)

    def probe(self):
        """Asks the broker directly, for lag and to learn that it answers."""
        try:
            self.state['lag'] = self.kafka.lag()
            self.state['kafka'] = 'ok'
        except Exception as error:
            self.state['lag'] = None
            self.state['kafka'] = type(error).__name__

    def replay(self, hours, actor):
        """Reads alerts from OpenSearch for a bounded window, for a time when Kafka had already expired them.
        Alerts held already are ignored, and those new are processed as usual."""
        if not 1 <= hours <= 720:
            raise ValueError('hours must be from 1 to 720')
        now = self.clock()
        start = now - hours * 3600000
        after, read, new, bad = None, 0, 0, 0
        while True:
            body = {'size': 200, 'sort': [{'detected_at': 'asc'}, {'alert_id': 'asc'}], 'query': {'range': {'detected_at': {'gte': start, 'lt': now, 'format': 'epoch_millis'}}}}
            if after:
                body['search_after'] = after
            hits = self.opensearch.search('siem-alerts-*', body)
            for hit in hits:
                read += 1
                try:
                    alert = schema.check(schema.safe(hit['_source']))
                except Invalid:
                    bad += 1
                    continue
                new += self.store.inbox(alert['alert_id'], alert['rule_id'], alert, now, source='replay')
            if len(hits) < 200:
                break
            after = hits[-1]['sort']
        # Intelligence matches for the window are read again too, on the next slow step.
        self.store.set_mark('signals', start)
        with self.store.lock, self.store.db:
            self.store.audit(None, now, actor, 'replay', {'hours': hours, 'read': read, 'new': new, 'invalid': bad})
        return {'read': read, 'new': new, 'invalid': bad}

    def health(self):
        counts = self.store.counts()
        now = self.clock()
        pending = counts.get('pending', 0)
        reasons = []
        if self.state['kafka'] not in ('ok', 'unknown'):
            reasons.append(f"Kafka: {self.state['kafka']}")
        if self.state['opensearch'] not in ('ok', 'unknown'):
            reasons.append(f"OpenSearch: {self.state['opensearch']}")
        if pending > 500:
            reasons.append(f'{pending} alerts are waiting')
        if counts.get('failed'):
            reasons.append(f"{counts['failed']} alerts could not be analysed")
        quarantined = len(self.store.quarantined())
        return {'status': 'WARN' if reasons else 'OK', 'checked_ms': now, 'message': '; '.join(reasons) or f'{counts.get("done", 0)} alerts held, {pending} waiting, {quarantined} quarantined',
                'alerts': counts, 'quarantined': quarantined, 'outbox': self.store.outbox_size(), **self.state}

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
        last_report = last_lag = last_prune = 0
        while not stopping():
            try:
                self.cycle()
            except Exception as error:
                self.log(f'cycle failed: {type(error).__name__}: {error}')
            now = self.clock()
            if now - last_lag >= 30000:
                self.probe()
                last_lag = now
            if now - last_report >= 60000:
                self.write_reports(reports)
                last_report = now
            if now - last_prune >= 3600000:
                self.store.prune(now - self.retention)
                last_prune = now
            sleep(tick)
