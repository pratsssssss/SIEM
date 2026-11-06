"""The monitoring loop. Nothing in the SIEM depends on it, and it changes nothing in the SIEM."""
import hashlib
import json
import os
import signal
import sys
import threading
import time
from pathlib import Path

from .assess import ALL_UNITS, Assessor, COMPONENTS, DEGRADED, HEALTHY, Memory, UNHEALTHY, UNKNOWN
from .collect import Collector
from .state import RANK, durability, kind_of, rollup, step
from .store import Store

CHECK_AGAINST = (DEGRADED, UNHEALTHY, UNKNOWN)
WALL_SLIP_MS = 30000


class Monitor:
    def __init__(self, config, store, collector=None, wall=None, mono=None, log=None, ship=True):
        self.config = config
        self.store = store
        self.collector = collector or Collector(config)
        self.wall = wall or (lambda: int(time.time() * 1000))
        self.mono = mono or (lambda: int(time.monotonic() * 1000))
        self.log = log or (lambda text: print(text, file=sys.stderr, flush=True))
        self.ship_enabled = ship
        self.memory = Memory(store.mark('memory'))
        self.cycle = store.mark('cycle', 0)
        self.last_mono = None
        self.last_cpu = None
        self.grace_until = store.mark('grace_until', 0)
        self.carry = {}
        self.own = {'cycle_ms': None, 'persist_failed': False, 'failed_collectors': 0}
        self.ship_failures = 0
        self.ship_state = 'not tried'
        self.logged = {}

    # Time. A gap means cycles either side are not consecutive, and silence inside it means nothing.
    def inspect_time(self, now, boot_ms):
        last = self.store.mark('last_cycle_ms')
        interval = self.config['schedule']['cycle_seconds'] * 1000
        gap = None
        if last is not None:
            wall_delta = now - last
            if wall_delta < -WALL_SLIP_MS:
                gap = {'kind': 'clock_went_back', 'seconds': -wall_delta // 1000}
            elif wall_delta > interval * self.config['time']['gap_factor']:
                if self.last_mono is None:
                    kind = 'wsl_restarted' if boot_ms and boot_ms > last else 'monitor_restarted'
                else:
                    slip = wall_delta - (self.mono() - self.last_mono)
                    kind = 'machine_suspended' if slip > WALL_SLIP_MS else 'monitor_stalled'
                gap = {'kind': kind, 'seconds': wall_delta // 1000, 'from_ms': last, 'to_ms': now}
        self.last_mono = self.mono()
        return gap

    # Collection.
    def observe(self, now, due_events, due_slow):
        collector = self.collector
        endpoints = self.config['endpoints']
        obs = {'now_ms': now}
        obs['systemd'] = collector.guarded('systemd', collector.systemd, list(ALL_UNITS))
        obs['host'] = collector.guarded('host', collector.host)
        obs['aggregator'] = collector.guarded('aggregator_metrics', collector.metrics, endpoints['aggregator_metrics'])
        obs['linux_metrics'] = collector.guarded('linux_metrics', collector.metrics, endpoints['linux_agent_metrics'])
        obs['verifier'] = collector.guarded('verifier_metrics', collector.metrics, endpoints['verifier_metrics'])
        obs['kafka'] = collector.guarded('kafka', collector.kafka)
        obs['opensearch'] = collector.guarded('opensearch', collector.opensearch)
        obs['reports'] = {name: collector.guarded(f'report_{name}', collector.report, path) for name, path in self.config['reports'].items()}
        obs['reports']['watchdog'] = collector.guarded('report_watchdog', collector.report, self.config['watchdog_report'])
        # Costlier samples run less often, and each stands until the next, with its own time.
        datasets = [s['dataset'] for s in self.config['sources']]
        if due_events or 'events' not in self.carry:
            got = collector.guarded('events', collector.events, now, datasets)
            self.carry['events'] = {**got, 'observed_ms': now}
            self.carry['analysis'] = collector.guarded('analysis', collector.analysis, now)
        if due_slow or 'retention' not in self.carry:
            self.carry['retention'] = collector.guarded('retention', collector.retention)
        obs.update(self.carry)
        return obs

    # One cycle.
    def run_cycle(self):
        started, now = self.mono(), self.wall()
        self.cycle += 1
        settings = self.config['schedule']
        gap = self.inspect_time(now, distro_started_ms())
        if gap:
            self.memory.forget_windows()
            self.carry = {}
            self.grace_until = now + self.config['time']['resume_grace_seconds'] * 1000
        obs = self.observe(now, self.cycle % settings['events_every_cycles'] == 0, self.cycle % settings['slow_every_cycles'] == 0)
        obs['grace'] = now < self.grace_until
        obs['gap'] = gap
        obs['self'] = self.usage(now)
        assessed, metrics = Assessor(self.config, self.memory).run(obs)
        try:
            self.persist(now, assessed, metrics, gap, obs)
            self.own['persist_failed'] = False
        except Exception as error:  # Disk full or a locked file must not end monitoring.
            self.own['persist_failed'] = True
            self.say('persist', f'could not save a cycle: {type(error).__name__}')
        self.own['cycle_ms'] = self.mono() - started
        self.own['failed_collectors'] = sum(1 for key, value in obs.items() if isinstance(value, dict) and value.get('ok') is False)
        self.write_public_report(now)
        if self.ship_enabled:
            self.ship(now)

    def usage(self, now):
        usage = self.collector.self_usage()
        cpu = None
        if self.last_cpu and now > self.last_cpu[0]:
            cpu = 100 * (usage['cpu_seconds'] - self.last_cpu[1]) * 1000 / (now - self.last_cpu[0])
        self.last_cpu = (now, usage['cpu_seconds'])
        return {**self.own, 'rss': usage['rss'], 'cpu_percent': cpu}

    def say(self, key, text):
        """Logs a thing once until it changes. The journal is never a per-cycle stream."""
        if self.logged.get(key) != text:
            self.logged[key] = text
            self.log(text)

    def persist(self, now, assessed, metrics, gap, obs):
        store, config = self.store, self.config
        with store.transaction():
            records = store.records()
            window = now - config['hysteresis']['flap_window_minutes'] * 60000
            if gap:
                store.add_transition('monitoring', None, UNKNOWN, now, {'kind': 'observation_gap', 'gap': gap['kind'], 'seconds': gap['seconds'], 'reason': self.gap_text(gap)})
                self.queue_gap(gap, now)
            for name, raw in assessed.items():
                record, change = step(records.get(name), raw, now, config, store.recent_transitions(name, window), reset=bool(gap))
                records[name] = record
                body = self.body(name, raw, record, now)
                store.save_component(name, record, body, now)
                if change:
                    self.record_change(name, change, raw, body, now)
                self.track_episode(name, record, raw, now)
                if change or now % 300000 < config['schedule']['cycle_seconds'] * 1000:
                    self.queue_current(name, body, now)
            for name in store.forget_components(set(assessed)):
                records.pop(name, None)
            pipeline = rollup(records, now, config)
            self.pipeline(records, pipeline, now)
            minute = now - now % 60000
            store.add_samples(minute, metrics)
            if self.cycle % config['schedule']['publish_every_cycles'] == 0:
                self.queue_metrics(minute, metrics, pipeline, now)
            if self.cycle % 60 == 1:
                store.roll_up(now)
                store.prune(now, config['retention'])
            trimmed = store.trim_outbox(config['bounds']['outbox_rows'])
            if trimmed:
                store.set_mark('outbox_trimmed', store.mark('outbox_trimmed', 0) + trimmed)
            store.set_mark('last_cycle_ms', now)
            store.set_mark('cycle', self.cycle)
            store.set_mark('grace_until', self.grace_until)
            store.set_mark('memory', self.memory.dump())
            store.set_mark('collectors', self.collector.stats)
            store.set_mark('self', {**self.own, 'rss': obs['self'].get('rss'), 'cpu_percent': obs['self'].get('cpu_percent'), 'last_persist_ms': now, 'ship_state': self.ship_state, 'ship_failures': self.ship_failures, 'interval_seconds': config['schedule']['cycle_seconds']})

    @staticmethod
    def gap_text(gap):
        return {'machine_suspended': 'The machine appears to have been suspended, so nothing was observed in this period',
                'wsl_restarted': 'WSL was not running in this period. Whether Windows was on is not known',
                'monitor_restarted': 'This service was not running in this period, while WSL was',
                'monitor_stalled': 'This service was running but did not complete cycles',
                'clock_went_back': 'The clock moved backwards'}.get(gap['kind'], 'Nothing was observed in this period')

    def body(self, name, raw, record, now):
        kind, platform = kind_of(name)
        evidence = [{**item, 'value': str(item['value'])[:160]} for item in raw['evidence'][:8]]
        held = record['status'] != raw['status']
        reason = f"Held at {record['status']} until the change is confirmed. Latest: {raw['reason']}" if held else raw['reason']
        return {'component': name, 'type': kind, 'platform': platform, 'observed_ms': now, 'status': record['status'], 'previous': record['previous'], 'since_ms': record['since_ms'],
                'latest_assessment': raw['status'], 'pending': record['pending'], 'pending_count': record['pending_count'], 'condition': record['condition'] if held else raw['condition'], 'latest_condition': raw['condition'], 'reason': reason, 'certainty': raw['certainty'],
                'durability': durability(record, now, self.config), 'last_activity_ms': raw['last_activity_ms'], 'last_heartbeat_ms': raw['last_heartbeat_ms'], 'evidence': evidence, 'missing': raw['missing'][:12],
                'freshness': self.freshness(raw, now)}

    def freshness(self, raw, now):
        states = [item['freshness'] for item in raw['evidence']]
        if not states:
            return 'unavailable'
        return 'stale' if 'stale' in states or 'unavailable' in states else 'fresh'

    def record_change(self, name, change, raw, body, now):
        store = self.store
        detail = {'reason': raw['reason'], 'condition': raw['condition'], 'certainty': raw['certainty'], 'first': change['first'], 'missing': raw['missing'][:8]}
        text = store.add_transition(name, change['from'], change['to'], now, detail)
        store.add_diagnostic(name, now, {'evidence': body['evidence'], 'missing': body['missing'], 'reason': raw['reason'], 'condition': raw['condition']})
        self.queue_doc(text[:32], 'transition', self.month('siem-health-transitions', now), {'@timestamp': iso(now), 'component': name, 'type': body['type'], 'platform': body['platform'], 'from': change['from'], 'to': change['to'], **detail, 'schema_version': 1}, now)
        if not change['first'] and name in dict((c[0], c) for c in COMPONENTS):
            self.say(f'change:{name}', f"{name}: {change['from']} to {change['to']}")

    def track_episode(self, name, record, raw, now):
        store = self.store
        current = store.open_episode(name)
        bad = record['status'] in CHECK_AGAINST and not (record['status'] == UNKNOWN and name.startswith('source:'))
        if bad:
            kind = 'observation_gap' if record['status'] == UNKNOWN else 'degradation'
            if current is None:
                episode = store.start_episode(name, kind, record['since_ms'], record['status'], raw['reason'])
                self.queue_episode(episode, now)
            else:
                worst = record['status'] if RANK[record['status']] > RANK[current['worst']] else current['worst']
                if kind == 'degradation':
                    current['kind'] = kind
                store.update_episode(current['episode_id'], current['kind'], worst, raw['reason'])
                if worst != current['worst']:
                    self.queue_episode(current['episode_id'], now)
        elif current is not None:
            store.end_episode(current['episode_id'], now, raw['reason'])
            self.queue_episode(current['episode_id'], now)

    def pipeline(self, records, pipeline, now):
        store = self.store
        previous = store.mark('pipeline')
        status = pipeline['status']
        since = previous['since_ms'] if previous and previous['status'] == status else now
        before = previous['previous'] if previous and previous['status'] == status else (previous or {}).get('status')
        store.set_mark('pipeline', {**pipeline, 'since_ms': since, 'previous': before})
        if previous is None or previous['status'] != status:
            reason = f"Bottleneck {pipeline['bottleneck']}, cause {pipeline['root_cause']}" if pipeline['bottleneck'] else pipeline['coverage_reason']
            text = store.add_transition('pipeline', before, status, now, {'reason': reason, 'condition': 'rollup', 'certainty': 'high', 'first': previous is None, 'missing': []})
            self.queue_doc(text[:32], 'transition', self.month('siem-health-transitions', now), {'@timestamp': iso(now), 'component': 'pipeline', 'type': 'pipeline', 'platform': 'all', 'from': before, 'to': status, 'reason': reason, 'condition': 'rollup', 'schema_version': 1}, now)
            self.say('pipeline', f'pipeline: {before} to {status}')
        record = {'status': status, 'since_ms': since}
        self.track_episode('pipeline', record, {'reason': pipeline['coverage_reason']}, now)

    def queue_doc(self, doc_id, kind, index, body, now):
        self.store.queue(doc_id, kind, index, body, now)

    def queue_gap(self, gap, now):
        doc = hashlib.sha256(f'gap|{now}'.encode()).hexdigest()[:32]
        self.queue_doc(doc, 'transition', self.month('siem-health-transitions', now), {'@timestamp': iso(now), 'component': 'monitoring', 'type': 'gap', 'platform': 'all', 'to': UNKNOWN, 'reason': self.gap_text(gap), 'condition': gap['kind'], 'seconds': gap['seconds'], 'schema_version': 1}, now)

    def queue_episode(self, episode_id, now):
        row = self.store.episode(episode_id)
        if row:
            self.queue_doc(episode_id, 'episode', self.month('siem-health-episodes', row['started_ms']), {'@timestamp': iso(row['started_ms']), 'ended_at': iso(row['ended_ms']) if row['ended_ms'] else None, 'component': row['component'], 'kind': row['kind'], 'worst': row['worst'], 'first_reason': row['first_reason'], 'last_reason': row['last_reason'], 'schema_version': 1}, now)

    def queue_current(self, name, body, now):
        self.queue_doc(f'current-{name}', 'current', 'siem-health-current', {'@timestamp': iso(now), **{k: body[k] for k in ('component', 'type', 'platform', 'status', 'previous', 'condition', 'reason', 'certainty', 'durability', 'freshness')}, 'since': iso(body['since_ms']), 'last_activity': iso(body['last_activity_ms']), 'missing': body['missing'], 'schema_version': 1}, now)

    def queue_metrics(self, minute, metrics, pipeline, now):
        self.queue_doc(f'metrics-{minute}', 'metrics', self.month('siem-health-metrics', minute), {'@timestamp': iso(minute), 'status': pipeline['status'], 'coverage': pipeline['coverage'], 'bottleneck': pipeline['bottleneck'], 'metrics': metrics, 'schema_version': 1}, now)

    @staticmethod
    def month(prefix, ms):
        return f"{prefix}-{time.strftime('%Y.%m', time.gmtime(ms / 1000))}"

    # Output.
    def write_public_report(self, now):
        """A small report outside this service, so that the Windows watcher sees this monitor from the outside."""
        pipeline = self.store.mark('pipeline') or {}
        status = pipeline.get('status')
        word = {HEALTHY: 'OK', UNHEALTHY: 'CRITICAL'}.get(status, 'WARN')
        text = f"Pipeline {status}, coverage {pipeline.get('coverage')}"
        if pipeline.get('bottleneck'):
            text += f", bottleneck {pipeline['bottleneck']}"
        target = Path(self.config['publish_report'])
        try:
            spare = target.with_suffix('.tmp')
            spare.write_text(json.dumps({'status': word, 'checked_ms': now, 'message': text, 'pipeline': status}), encoding='utf-8')
            spare.replace(target)
        except OSError as error:
            self.say('report', f'could not write the report: {type(error).__name__}')

    def ship(self, now):
        """Sends what is waiting. It backs off on failure, and local history is complete either way."""
        rows = self.store.queued(self.config['bounds']['ship_batch'])
        if not rows:
            return
        if self.ship_failures and self.cycle % min(2 ** self.ship_failures, 15):
            return
        lines = []
        for doc_id, _, index, body in rows:
            lines.append(json.dumps({'index': {'_index': index, '_id': doc_id}}))
            lines.append(body)
        try:
            reply = self.collector.fetch(self.config['opensearch']['url'] + '/_bulk', ('\n'.join(lines) + '\n').encode(), {**self.collector._auth(), 'Content-Type': 'application/x-ndjson'},
                                         self.config['timeouts']['opensearch_seconds'], self.collector._ssl())
            result = json.loads(reply)
            if not isinstance(result.get('items'), list):
                raise ValueError('malformed')
            done = [item['index']['_id'] for item in result['items'] if item.get('index', {}).get('status', 500) < 300]
            with self.store.transaction():
                self.store.done(done)
            if len(done) == len(rows):
                self.ship_failures, self.ship_state = 0, 'ok'
            else:
                self.ship_failures, self.ship_state = self.ship_failures + 1, 'partial'
        except Exception as error:
            self.ship_failures += 1
            self.ship_state = Collector.classify(error)
            self.say('ship', f'could not publish: {self.ship_state}')


def distro_started_ms():
    """When this distribution's init started. The kernel's boot time will not do: the WSL virtual machine outlives a
    distribution, so `wsl --terminate` leaves it unchanged."""
    try:
        with open('/proc/stat', encoding='ascii') as handle:
            boot = next(int(line.split()[1]) for line in handle if line.startswith('btime '))
        with open('/proc/1/stat', encoding='ascii') as handle:
            ticks = int(handle.read().rsplit(')', 1)[1].split()[19])
        return (boot + ticks // os.sysconf('SC_CLK_TCK')) * 1000
    except (OSError, ValueError, IndexError, StopIteration):
        return None


def iso(ms):
    if ms is None:
        return None
    return time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(ms / 1000)) + f'.{int(ms) % 1000:03d}Z'


def run(config):
    Path(config['state_file']).parent.mkdir(parents=True, exist_ok=True)
    store = Store(config['state_file'])
    monitor = Monitor(config, store)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    monitor.log('siem-health started')
    interval = config['schedule']['cycle_seconds']
    while not stop.is_set():
        begun = time.monotonic()
        try:
            monitor.run_cycle()
        except Exception as error:  # One bad cycle must not end monitoring.
            monitor.say('cycle', f'cycle failed: {type(error).__name__}: {str(error)[:120]}')
        stop.wait(max(1, interval - (time.monotonic() - begun)))
    store.close()
