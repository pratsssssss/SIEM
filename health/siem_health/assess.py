"""Turns one set of observations into one assessment per component. Pure and deterministic: same input, same output.

The rules that matter:
- A collector error says something about this monitor's view, so it gives UNKNOWN, never UNHEALTHY.
- Silence alone gives UNKNOWN. UNHEALTHY needs positive evidence: systemd says stopped, or a counter shows work waiting
  with no progress.
- A rejected event is a security and quality number. It does not lower health.
"""
import math

from .catalog import CATALOG
from .collect import clean, number, vector_summary, verifier_summary

HEALTHY, DEGRADED, UNHEALTHY, UNKNOWN, NOT_APPLICABLE = 'HEALTHY', 'DEGRADED', 'UNHEALTHY', 'UNKNOWN', 'NOT_APPLICABLE'
CONDITIONS = ('ok', 'quiet', 'service_unavailable', 'not_processing', 'delayed', 'source_unavailable', 'monitoring_unavailable', 'host_offline', 'backlog_increasing', 'backlog_recovering',
              'resource_pressure', 'downstream_unavailable', 'configuration', 'data_loss', 'not_applicable')
INFRASTRUCTURE_REASONS = ('busy', 'read_failed', 'journal_failed', 'downstream_unavailable', 'refusal_limit', 'index_rejected')
NOT_REJECTED = ('accepted', 'replayed', 'replay_conflict') + INFRASTRUCTURE_REASONS

# Component, type, platform. The order is the order of the pipeline.
COMPONENTS = (('windows-agent', 'agent', 'windows'), ('linux-agent', 'agent', 'wsl'), ('kafka', 'broker', 'wsl'), ('verifier', 'service', 'wsl'), ('aggregator', 'service', 'wsl'),
              ('normalization', 'function', 'wsl'), ('opensearch', 'storage', 'wsl'), ('detector', 'service', 'wsl'), ('enricher', 'service', 'wsl'), ('correlator', 'service', 'wsl'),
              ('assets', 'service', 'wsl'), ('attack-paths', 'service', 'wsl'), ('host-wsl', 'host', 'wsl'),
              ('housekeeping', 'timers', 'wsl'), ('health-monitor', 'self', 'wsl'))
SERVICE_UNITS = {'linux-agent': 'siem-linux-agent.service', 'kafka': 'kafka.service', 'verifier': 'seal-verifier.service', 'aggregator': 'vector.service', 'opensearch': 'opensearch.service',
                 'detector': 'siem-detector.service', 'enricher': 'siem-enricher.service', 'correlator': 'siem-correlator.service', 'assets': 'siem-asset.service',
                 'attack-paths': 'siem-path.service'}
TIMER_UNITS = ('siem-disk-guard.timer', 'siem-kafka-expiry-check.timer', 'siem-linux-health.timer')
ALL_UNITS = tuple(SERVICE_UNITS.values()) + TIMER_UNITS


class Memory:
    """What a judgment needs from earlier cycles. Counters and progress survive a restart, windows do not need to."""

    def __init__(self, saved=None):
        saved = saved or {}
        self.counters = saved.get('counters', {})
        self.progress = saved.get('progress', {})
        self.seen = saved.get('seen', {})
        self.series = {}

    def dump(self):
        return {'counters': self.counters, 'progress': self.progress, 'seen': self.seen}

    def forget_windows(self):
        """After a gap, earlier points say nothing about now."""
        self.series = {}
        self.counters = {}

    def rate(self, name, value, now):
        """Per second since the last sample. None for a first sample or a counter reset, because neither is zero."""
        before = self.counters.get(name)
        if value is None:
            return None
        self.counters[name] = [value, now]
        if not before or value < before[0] or now <= before[1]:
            return None
        return (value - before[0]) * 1000 / (now - before[1])

    def window(self, name, value, now, seconds):
        """Rise over the window, or None until two samples exist. A counter that fell has restarted."""
        if value is None:
            return None
        points = self.series.setdefault(name, [])
        if points and value < points[-1][1]:
            points.clear()
        points.append((now, value))
        while len(points) > 2 and points[1][0] <= now - seconds * 1000:
            points.pop(0)
        del points[:-64]
        return points[-1][1] - points[0][1] if len(points) > 1 else None

    def moved(self, name, value, now):
        """When this value last changed. None until a change has been seen."""
        if value is None:
            row = self.progress.get(name)
            return row[1] if row else None
        row = self.progress.get(name)
        if row is None:
            self.progress[name] = [value, None]
            return None
        if row[0] != value:
            row[0], row[1] = value, now
        return row[1]

    def trend(self, name, value):
        """'rising', 'falling' or 'flat', from the last four samples."""
        points = self.series.setdefault(f'trend:{name}', [])
        points.append(value)
        del points[:-4]
        if len(points) < 3:
            return 'flat'
        steps = [b - a for a, b in zip(points, points[1:])]
        if all(step > 0 for step in steps):
            return 'rising'
        if all(step < 0 for step in steps):
            return 'falling'
        return 'flat'


def percentile(values, share):
    if not values:
        return None
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, math.ceil(share * len(ordered)) - 1))]


def result(status, condition, reason, evidence=(), missing=(), activity=None, heartbeat=None, fast=False, certainty='high'):
    return {'status': status, 'condition': condition, 'reason': reason, 'evidence': list(evidence), 'missing': list(missing), 'last_activity_ms': activity, 'last_heartbeat_ms': heartbeat,
            'fast': fast, 'certainty': certainty}


class Assessor:
    def __init__(self, config, memory):
        self.config = config
        self.memory = memory
        self.limits = config['thresholds']
        self.fresh = config['freshness']

    def run(self, obs):
        self.obs = obs
        self.now = obs['now_ms']
        self.metrics = {}
        self.grace = bool(obs.get('grace'))
        self.views = {name: self.view(name, limit) for name, limit in (
            ('detector', 'service_report_seconds'), ('enricher', 'service_report_seconds'), ('correlator', 'service_report_seconds'), ('asset', 'service_report_seconds'),
            ('path', 'service_report_seconds'), ('linux-agent', 'timer_report_seconds'), ('kafka-expiry', 'timer_report_seconds'), ('disk-guard', 'timer_report_seconds'), ('windows-agent', 'windows_report_seconds'))}
        self.aggregator = vector_summary(obs['aggregator']['series']) if obs.get('aggregator', {}).get('ok') else None
        self.linux = vector_summary(obs['linux_metrics']['series']) if obs.get('linux_metrics', {}).get('ok') else None
        self.verifier = verifier_summary(obs['verifier']['series']) if obs.get('verifier', {}).get('ok') else None
        self.search = obs['opensearch'] if obs.get('opensearch', {}).get('ok') else None
        self.brokers = obs['kafka'] if obs.get('kafka', {}).get('ok') else None
        self.events = obs['events'] if obs.get('events', {}).get('ok') else None
        self.search_down = self.down('opensearch', 'opensearch')
        self.kafka_down = self.down('kafka', 'kafka')
        self.verifier_down = self.down('verifier', 'verifier')
        for name, is_down in (('opensearch', self.search_down), ('kafka', self.kafka_down), ('verifier', self.verifier_down), ('aggregator', self.down('aggregator', 'aggregator'))):
            if is_down:
                self.memory.progress[f'down:{name}'] = [1, self.now]
        self.sample_latency()
        found = {}
        for name, method in (('kafka', self.kafka), ('opensearch', self.opensearch), ('verifier', self.check_verifier), ('aggregator', self.check_aggregator), ('normalization', self.normalization),
                             ('windows-agent', self.windows_agent), ('linux-agent', self.linux_agent), ('detector', self.detector), ('enricher', self.enricher), ('correlator', self.correlator),
                             ('assets', self.assets), ('attack-paths', self.paths), ('host-wsl', self.host), ('housekeeping', self.housekeeping), ('health-monitor', self.health_monitor)):
            found[name] = method()
        for source in self.config['sources']:
            found[f"source:{source['dataset']}"] = self.source(source, found)
        return found, self.metrics

    # Helpers.
    def put(self, name, value, digits=3):
        if name in CATALOG and value is not None:
            self.metrics[name] = round(float(value), digits)

    def unit(self, component):
        return self.unit_named(SERVICE_UNITS[component])

    def unit_named(self, name):
        systemd = self.obs.get('systemd', {})
        return systemd.get('units', {}).get(name) if systemd.get('ok') else None

    def down(self, component, key):
        """True only when something positively shows the component is out."""
        unit = self.unit(component)
        if unit and unit['active'] in ('inactive', 'failed'):
            return True
        if self.obs.get(key, {}).get('ok') is False and self.obs[key].get('error') == 'refused':
            return True
        return False

    def lately(self, name):
        """True while the marks of an outage are still in the windows, so that they are blamed on the outage."""
        row = self.memory.progress.get(f'down:{name}')
        return bool(row) and self.now - row[1] <= self.fresh['after_outage_seconds'] * 1000

    def view(self, name, limit_name):
        """A report as this cycle may use it. `state` is fresh, stale, missing, malformed, future or replayed."""
        got = self.obs.get('reports', {}).get(name) or {'ok': False, 'error': 'missing'}
        if not got.get('ok'):
            return {'state': 'missing' if got.get('error') == 'missing' else 'malformed', 'body': None, 'age': None, 'checked': None}
        checked, limit = got['checked_ms'], self.fresh[limit_name]
        age = (self.now - checked) / 1000
        tolerance = self.config['time']['skew_tolerance_seconds']
        if age < -tolerance:
            return {'state': 'future', 'body': None, 'age': age, 'checked': checked}
        last = self.memory.seen.get(name)
        if last is not None and checked < last - 1000:
            return {'state': 'replayed', 'body': None, 'age': age, 'checked': checked}
        self.memory.seen[name] = max(last or 0, checked)
        return {'state': 'stale' if age > limit else 'fresh', 'body': got['body'], 'age': max(age, 0), 'checked': checked}

    def evidence(self, source, value, freshness='fresh', observed=None):
        return {'source': source, 'observed_ms': observed or self.now, 'freshness': freshness, 'value': value}

    def gate(self, component):
        """The unit's state. Returns (assessment or None, evidence, missing)."""
        unit = self.unit(component)
        if unit is None:
            return None, [], ['systemd state']
        evidence = [self.evidence('systemd', f"{unit['active']}/{unit['sub']}, {unit['restarts']} restarts")]
        if unit['active'] in ('inactive', 'failed'):
            return result(UNHEALTHY, 'service_unavailable', f"systemd reports {SERVICE_UNITS[component]} as {unit['active']}", evidence, fast=True), evidence, []
        if unit['active'] != 'active':
            return result(DEGRADED, 'service_unavailable', f"{SERVICE_UNITS[component]} is {unit['active']}", evidence), evidence, []
        minutes = self.limits['restart_loop_minutes']
        rise = self.memory.window(f'restarts:{component}', unit['restarts'], self.now, minutes * 60)
        if rise is not None and rise >= self.limits['restart_loop_count']:
            return result(UNHEALTHY, 'service_unavailable', f'{int(rise)} restarts within {minutes} minutes', evidence), evidence, []
        return None, evidence, []

    def reported(self, component, report):
        """Common start for a service with a report. Returns (assessment or None, view, evidence, missing)."""
        stop, evidence, missing = self.gate(component)
        if stop:
            return stop, None, evidence, missing
        view = self.views[report]
        if view['age'] is not None and view['state'] in ('fresh', 'stale'):
            evidence.append(self.evidence(f'{report} report', f"{int(view['age'])} s old", view['state'], view['checked']))
        heartbeat = view['checked'] if view['state'] in ('fresh', 'stale') else None
        if view['state'] == 'fresh':
            return None, view, evidence, missing
        if view['state'] == 'stale' and self.grace:
            return result(UNKNOWN, 'host_offline', 'The machine has just resumed, so this report may simply not have been written yet', evidence, heartbeat=heartbeat, certainty='low'), view, evidence, missing
        if view['state'] == 'stale' and view['age'] > self.fresh['hang_seconds'] and self.unit(component):
            return result(DEGRADED, 'not_processing', f"Running, but its report is {int(view['age'])} s old", evidence, heartbeat=heartbeat, certainty='medium'), view, evidence, missing
        missing.append(f'{report} report ({view["state"]})')
        return result(UNKNOWN, 'monitoring_unavailable', f"Its report is {view['state']}, so progress cannot be seen", evidence, missing, heartbeat=heartbeat, certainty='low'), view, evidence, missing

    # Transport.
    def kafka(self):
        stop, evidence, missing = self.gate('kafka')
        if stop:
            return stop
        got = self.obs.get('kafka', {})
        if not self.brokers:
            error = got.get('error', 'not collected')
            missing.append(f'broker metadata ({error})')
            if error == 'refused' and self.unit('kafka'):
                return result(DEGRADED, 'not_processing', 'The service is active, but the broker refuses connections', evidence, missing, certainty='medium')
            return result(UNKNOWN, 'monitoring_unavailable', f'Broker metadata could not be read: {error}', evidence, missing, certainty='low')
        evidence.append(self.evidence('kafka metadata', f"{self.brokers['brokers']} broker"))
        ends = self.brokers['end_offsets']
        raw = self.config['kafka']['raw_topic']
        self.put('raw_produced_per_second', self.memory.rate('kafka.raw_end', ends.get(raw), self.now))
        moved = self.memory.moved('kafka.raw_end', ends.get(raw), self.now)
        for group, name in ((self.config['kafka']['raw_group'], 'raw_lag_messages'), (self.config['kafka']['alert_group'], 'alert_lag_messages')):
            row = self.brokers['groups'].get(group, {})
            if row.get('known'):
                self.put(name, row['lag'])
            else:
                missing.append(f'lag of {group} ({row.get("reason", "unknown")})')
        absent = [name for name, row in self.brokers['topics'].items() if not row['exists']]
        leaderless = sum(row['leaderless'] for row in self.brokers['topics'].values())
        if absent:
            return result(UNHEALTHY, 'configuration', f"Topic missing: {', '.join(absent)}", evidence, missing, activity=moved, fast=True)
        if leaderless:
            return result(UNHEALTHY, 'not_processing', f'{leaderless} partitions have no leader', evidence, missing, activity=moved, fast=True)
        expiry = self.views['kafka-expiry']
        if expiry['body'] is not None:
            body = expiry['body']
            age = number(body.get('oldest_unread_age_ms'))
            self.put('oldest_unread_seconds', 0 if age is None else age / 1000)
            evidence.append(self.evidence('kafka expiry report', f"{int(number(body.get('unread')) or 0)} unread", expiry['state'], expiry['checked']))
            if isinstance(body.get('lost_latched'), dict) and body['lost_latched']:
                return result(UNHEALTHY, 'data_loss', 'The expiry check has recorded messages that aged out unread. See the runbook', evidence, missing, activity=moved)
            retention = number(body.get('retention_ms'))
            if retention and age and age > retention * 0.8:
                return result(DEGRADED, 'delayed', 'The oldest unread message is close to retention', evidence, missing, activity=moved)
        else:
            missing.append('kafka expiry report')
        return result(HEALTHY, 'ok', 'Broker answers, every topic has a leader', evidence, missing, activity=moved)

    def check_verifier(self):
        stop, evidence, missing = self.gate('verifier')
        if stop:
            return stop
        if self.verifier is None:
            missing.append(f"verifier metrics ({self.obs.get('verifier', {}).get('error', 'not collected')})")
            return result(UNKNOWN, 'monitoring_unavailable', 'Its counters cannot be read', evidence, missing, certainty='low')
        reasons = self.verifier['reasons']
        accepted = reasons.get('accepted', 0)
        self.put('verified_per_second', self.memory.rate('verifier.accepted', accepted, self.now))
        rejected = sum(v for k, v in reasons.items() if k not in NOT_REJECTED)
        replay = reasons.get('replayed', 0) + reasons.get('replay_conflict', 0)
        faults = sum(reasons.get(k, 0) for k in INFRASTRUCTURE_REASONS)
        self.put('verification_rejected_per_second', self.memory.rate('verifier.rejected', rejected, self.now))
        self.put('replay_rejected_per_second', self.memory.rate('verifier.replay', replay, self.now))
        self.put('verifier_faults_per_second', self.memory.rate('verifier.faults', faults, self.now))
        rise = self.memory.window('verifier.faults', faults, self.now, 300)
        moved = self.memory.moved('verifier.accepted', accepted, self.now)
        evidence.append(self.evidence('verifier metrics', f'{int(accepted)} accepted, {int(rejected)} rejected, {int(replay)} replayed'))
        if rise:
            if self.lately('opensearch'):
                return result(DEGRADED, 'downstream_unavailable', 'Requests failed because of the OpenSearch outage. Vector retries them', evidence, missing, activity=moved)
            if self.lately('aggregator'):
                return result(DEGRADED, 'downstream_unavailable', 'Requests broke off when the aggregator stopped. It resends them', evidence, missing, activity=moved)
            return result(DEGRADED, 'not_processing', f'{int(rise)} requests failed in 5 minutes. Vector retries them', evidence, missing, activity=moved)
        if moved is None or self.now - moved > self.fresh['not_progressing_seconds'] * 1000:
            return result(HEALTHY, 'quiet', 'Running, with no failed requests. Nothing was accepted recently', evidence, missing, activity=moved, certainty='medium')
        return result(HEALTHY, 'ok', 'Accepting events', evidence, missing, activity=moved)

    def check_aggregator(self):
        guard = self.views['disk-guard']['body']
        stop, evidence, missing = self.gate('aggregator')
        if guard and guard.get('ingest_stopped') is True:
            return result(UNHEALTHY, 'resource_pressure', 'The disk guard stopped ingest to protect the disk', evidence, missing, fast=True)
        if stop:
            return stop
        group = (self.brokers or {}).get('groups', {}).get(self.config['kafka']['raw_group'], {})
        lag = group.get('lag') if group.get('known') else None
        if lag is None:
            missing.append('consumer lag')
        moved = self.memory.moved('aggregator.committed', group.get('committed'), self.now)
        trend = self.memory.trend('aggregator.lag', lag) if lag is not None else 'flat'
        expiry = self.views['kafka-expiry']['body'] or {}
        oldest = number(expiry.get('oldest_unread_age_ms'))
        oldest = oldest / 1000 if oldest else 0
        errors = None
        if self.aggregator:
            errors = self.memory.window('aggregator.errors', sum(self.aggregator['errors'].values()), self.now, 300)
            received = sum(v for k, v in self.aggregator['received'].items() if k == 'siem_raw')
            self.put('raw_received_per_second', self.memory.rate('aggregator.raw', received, self.now))
            sinks = sum(v for k, v in self.aggregator['sent'].items() if k.split(':')[0] in ('opensearch_events', 'opensearch_linux'))
            self.put('indexed_per_second', self.memory.rate('aggregator.indexed', sinks, self.now))
            evidence.append(self.evidence('aggregator metrics', f'{int(received)} received, {int(sinks)} indexed'))
        else:
            missing.append(f"aggregator metrics ({self.obs.get('aggregator', {}).get('error', 'not collected')})")
        blocked = 'OpenSearch' if self.search_down else 'the verifier' if self.verifier_down else None
        if lag:
            evidence.append(self.evidence('kafka offsets', f'lag {lag}, {trend}'))
        limit = self.fresh['not_progressing_seconds'] * 1000
        stalled = bool(lag) and moved is not None and self.now - moved > limit
        if stalled and blocked:
            return result(DEGRADED, 'downstream_unavailable', f'Waiting for {blocked}. Events stay safely in Kafka', evidence, missing, activity=moved)
        if stalled:
            return result(UNHEALTHY, 'not_processing', f'Running, {lag} messages waiting, and no progress for {(self.now - moved) // 1000} s', evidence, missing, activity=moved)
        over = (lag or 0) > self.limits['lag_unhealthy_messages'] or oldest > self.limits['oldest_unhealthy_seconds']
        behind = (lag or 0) > self.limits['lag_degraded_messages'] or oldest > self.limits['oldest_degraded_seconds']
        if over or behind:
            condition = 'backlog_increasing' if trend == 'rising' else 'backlog_recovering' if trend == 'falling' else 'delayed'
            if blocked:
                condition = 'downstream_unavailable'
            return result(UNHEALTHY if over and not blocked else DEGRADED, condition, f'{lag} messages waiting, oldest {int(oldest)} s, {trend}', evidence, missing, activity=moved)
        if errors:
            cause = next((n for n in ('opensearch', 'kafka', 'verifier') if self.lately(n)), None)
            if cause:
                return result(DEGRADED, 'downstream_unavailable', f'{int(errors)} component errors in 5 minutes, from the {cause} outage', evidence, missing, activity=moved)
            return result(DEGRADED, 'not_processing', f'{int(errors)} component errors in 5 minutes', evidence, missing, activity=moved)
        if self.aggregator is None and lag is None:
            return result(UNKNOWN, 'monitoring_unavailable', 'Neither its counters nor its lag can be read', evidence, missing, certainty='low')
        if lag == 0:
            return result(HEALTHY, 'ok', 'Nothing is waiting in Kafka', evidence, missing, activity=moved)
        return result(HEALTHY, 'ok', f'{lag} messages in flight, and moving', evidence, missing, activity=moved, certainty='high' if moved else 'medium')

    def normalization(self):
        if self.aggregator is None:
            return result(UNKNOWN, 'monitoring_unavailable', 'Aggregator counters cannot be read, so normalization cannot be judged', missing=['aggregator metrics'], certainty='low')
        sent = self.aggregator['sent']
        taken = sum(self.aggregator['received'].get(k, 0) for k in ('normalize', 'normalize_linux'))
        passed = sum(sent.get(f'{k}:_default', 0) for k in ('normalize', 'normalize_linux'))
        dropped = sum(sent.get(f'{k}:dropped', 0) for k in ('normalize', 'normalize_linux'))
        self.put('normalized_per_second', self.memory.rate('normalize.passed', passed, self.now))
        seen = self.memory.window('normalize.taken', taken, self.now, 300)
        failed = self.memory.window('normalize.dropped', dropped, self.now, 300)
        dead = (self.search or {}).get('groups', {}).get('deadletter', {}).get('docs')
        self.put('deadletter_documents', dead)
        rate = self.memory.rate('deadletter.docs', dead, self.now)
        self.put('deadletter_per_hour', rate * 3600 if rate is not None else None)
        evidence = [self.evidence('aggregator metrics', f'{int(passed)} passed, {int(dropped)} failed since it started')]
        activity = self.memory.moved('normalize.taken', taken, self.now)
        if seen is None or seen < self.limits['normalize_min_events']:
            return result(UNKNOWN, 'quiet', f"Fewer than {self.limits['normalize_min_events']} events in 5 minutes, too few to judge", evidence, activity=activity, certainty='low')
        percent = 100 * (failed or 0) / seen
        self.put('normalize_failed_percent', percent)
        if percent >= self.limits['normalize_unhealthy_percent']:
            return result(UNHEALTHY, 'not_processing', f'{percent:.1f}% of events failed normalization in 5 minutes', evidence, activity=activity)
        if percent >= self.limits['normalize_degraded_percent']:
            return result(DEGRADED, 'delayed', f'{percent:.1f}% of events failed normalization in 5 minutes', evidence, activity=activity)
        return result(HEALTHY, 'ok', f'{int(seen)} events in 5 minutes, {percent:.1f}% failed', evidence, activity=activity)

    # Storage.
    def opensearch(self):
        stop, evidence, missing = self.gate('opensearch')
        if stop:
            return stop
        if not self.search:
            error = self.obs.get('opensearch', {}).get('error', 'not collected')
            missing.append(f'cluster statistics ({error})')
            if error == 'refused':
                return result(UNHEALTHY, 'not_processing', 'The service is active, but it refuses connections', evidence, missing, certainty='medium')
            if error == 'timeout':
                return result(DEGRADED, 'delayed', 'It did not answer within the time limit', evidence, missing, certainty='medium')
            return result(UNKNOWN, 'monitoring_unavailable', f'Statistics could not be read: {error}', evidence, missing, certainty='low')
        found = self.search
        evidence.append(self.evidence('cluster health', f"{found['status']}, {found['active_shards']} shards active"))
        heap = found['heap_percent']
        self.put('opensearch_heap_percent', heap)
        disk = 100 * found['disk_free'] / found['disk_total'] if found['disk_total'] and found['disk_free'] is not None else None
        indexed = found['index_total']
        self.put('opensearch_indexing_per_second', self.memory.rate('opensearch.index_total', indexed, self.now))
        spent, counted = self.memory.window('opensearch.index_ms', found['index_time_ms'], self.now, 60), self.memory.window('opensearch.index_count', indexed, self.now, 60)
        self.put('opensearch_index_ms_per_document', spent / counted if spent is not None and counted else None)
        store = sum((row.get('bytes') or 0) for key, row in found['groups'].items() if key in ('windows', 'linux'))
        self.put('opensearch_store_gib', store / 2 ** 30)
        rejected = self.memory.window('opensearch.rejected', (found['write_rejected'] or 0) + (found['search_rejected'] or 0), self.now, 300)
        failed = self.memory.window('opensearch.failed', found['index_failed'], self.now, 300)
        moved = self.memory.moved('opensearch.index_total', indexed, self.now)
        retention = self.obs.get('retention', {})
        if retention.get('ok') is True:
            evidence.append(self.evidence('retention engine', f"{retention['managed']} indices managed, {retention['failed']} failed"))
        else:
            missing.append('retention state')
        if found['status'] == 'red':
            return result(UNHEALTHY, 'not_processing', 'Cluster status is red: some primary shards are unavailable', evidence, missing, activity=moved, fast=True)
        if found['unassigned']['siem'] or (found['status'] == 'yellow' and not found['unassigned']['other']):
            return result(DEGRADED, 'not_processing', f"{int(found['unassigned']['siem'])} SIEM shards are unassigned", evidence, missing, activity=moved)
        if heap is not None and heap >= self.limits['heap_unhealthy_percent']:
            return result(UNHEALTHY, 'resource_pressure', f'Heap at {heap}%', evidence, missing, activity=moved)
        if disk is not None and disk <= self.limits['opensearch_disk_unhealthy_percent']:
            return result(UNHEALTHY, 'resource_pressure', f'{disk:.0f}% of its disk is free', evidence, missing, activity=moved)
        if rejected:
            return result(DEGRADED, 'resource_pressure', f'{int(rejected)} operations rejected by thread pools in 5 minutes', evidence, missing, activity=moved)
        if failed:
            return result(DEGRADED, 'not_processing', f'{int(failed)} indexing failures in 5 minutes', evidence, missing, activity=moved)
        if heap is not None and heap >= self.limits['heap_degraded_percent']:
            return result(DEGRADED, 'resource_pressure', f'Heap at {heap}%', evidence, missing, activity=moved)
        if disk is not None and disk <= self.limits['opensearch_disk_degraded_percent']:
            return result(DEGRADED, 'resource_pressure', f'{disk:.0f}% of its disk is free', evidence, missing, activity=moved)
        if retention.get('failed'):
            return result(DEGRADED, 'not_processing', f"Retention failed on {retention['failed']} indices", evidence, missing, activity=moved)
        note = 'Green' if found['status'] == 'green' else f"Yellow only for {int(found['unassigned']['other'])} replica of a system index, which one node cannot place"
        return result(HEALTHY, 'ok', f'{note}. Reads and statistics answer', evidence, missing, activity=moved)

    # Collection.
    def windows_newest(self):
        rows = [row for name, row in (self.events or {}).get('sets', {}).items() if name.startswith('windows.')]
        return max((row['ingested_ms'] for row in rows if row['ingested_ms']), default=None)

    def windows_agent(self):
        view = self.views['windows-agent']
        newest = self.windows_newest()
        event_age = (self.now - newest) / 1000 if newest else None
        arriving = event_age is not None and -self.config['time']['skew_tolerance_seconds'] <= event_age <= self.fresh['windows_report_seconds']
        evidence, missing = [], []
        if newest:
            evidence.append(self.evidence('stored events', f'newest Windows event ingested {int(event_age)} s ago', 'fresh' if arriving else 'stale', self.events.get('observed_ms')))
        else:
            missing.append('Windows event timestamps')
        body = view['body'] if view['state'] in ('fresh', 'stale') else None
        heartbeat = view['checked'] if body else None
        if view['state'] == 'fresh':
            service = clean(body.get('service', 'unknown'), 16)
            metrics = body.get('metrics') if isinstance(body.get('metrics'), dict) else {}
            evidence.append(self.evidence('windows report', f'Vector {service}', 'fresh', view['checked']))
            if service != 'Running':
                return result(UNHEALTHY, 'service_unavailable', f'The Windows agent service is {service}', evidence, missing, activity=newest, heartbeat=heartbeat, fast=True)
            received, acked = number(metrics.get('received')), number(metrics.get('acknowledged'))
            buffered = number(metrics.get('buffered'))
            self.put('windows_buffered_events', buffered)
            took = self.memory.moved('windows.received', received, self.now)
            sent = self.memory.moved('windows.acknowledged', acked, self.now)
            errors = self.memory.window('windows.errors', number(metrics.get('errors')), self.now, 1800)
            trend = self.memory.trend('windows.buffered', buffered or 0)
            limit = self.fresh['not_progressing_seconds'] * 1000 + self.fresh['windows_report_seconds'] * 1000
            if received is None:
                missing.append('Windows agent counters')
            elif took and (sent is None or took - sent > limit) and not arriving:
                condition, status = ('downstream_unavailable', DEGRADED) if self.kafka_down else ('not_processing', UNHEALTHY)
                return result(status, condition, 'The agent is collecting, but Kafka has acknowledged nothing', evidence, missing, activity=newest, heartbeat=heartbeat)
            if errors:
                return result(DEGRADED, 'not_processing', f'{int(errors)} agent errors in 30 minutes', evidence, missing, activity=newest, heartbeat=heartbeat)
            if (buffered or 0) > self.limits['lag_degraded_messages']:
                condition = 'backlog_recovering' if trend == 'falling' else 'backlog_increasing' if trend == 'rising' else 'delayed'
                return result(DEGRADED, condition, f'{int(buffered)} events wait in the agent buffer', evidence, missing, activity=newest, heartbeat=heartbeat)
            latency = self.metrics.get('windows_latency_p95_seconds')
            if latency is not None and latency > self.limits['latency_degraded_seconds']:
                return result(DEGRADED, 'delayed', f'Events reach normalization {int(latency)} s after they happened. After an outage this can be retained logs being read, not live collection', evidence, missing, activity=newest, heartbeat=heartbeat)
            if arriving:
                return result(HEALTHY, 'ok', 'Service running, and its events are arriving', evidence, missing, activity=newest, heartbeat=heartbeat)
            if self.events is None:
                return result(UNKNOWN, 'monitoring_unavailable', 'Service running, but delivery cannot be confirmed while events cannot be read', evidence, missing, heartbeat=heartbeat, certainty='low')
            return result(UNKNOWN, 'quiet', 'Service running, with no recent events. A quiet machine and a broken path look the same from here', evidence, missing, activity=newest, heartbeat=heartbeat, certainty='low')
        missing.append(f"Windows report ({view['state']})")
        if arriving:
            return result(HEALTHY, 'ok', 'Events are arriving, so delivery works. The service state itself was not seen', evidence, missing, activity=newest, heartbeat=heartbeat, certainty='medium')
        if self.grace:
            return result(UNKNOWN, 'host_offline', 'The machine has just resumed, so the report and events may simply be late', evidence, missing, activity=newest, heartbeat=heartbeat, certainty='low')
        return result(UNKNOWN, 'monitoring_unavailable', f"The Windows report is {view['state']} and no recent events prove delivery. The watcher task may be stopped, or the agent may be", evidence, missing, activity=newest, heartbeat=heartbeat, certainty='low')

    def linux_agent(self):
        stop, evidence, missing = self.gate('linux-agent')
        if stop:
            return stop
        view = self.views['linux-agent']
        body = view['body'] if view['state'] == 'fresh' else None
        heartbeat = view['checked'] if view['state'] in ('fresh', 'stale') else None
        activity, unread = None, None
        if body:
            unread = number(body.get('unread_journal_entries'))
            evidence.append(self.evidence('linux agent report', f"{int(unread or 0)} journal entries unread", 'fresh', view['checked']))
        else:
            missing.append(f"linux agent report ({view['state']})")
        if self.linux:
            received = self.linux['received'].get('kafka_raw', 0)
            sent = self.linux['sent'].get('kafka_raw:_default', self.linux['sent'].get('kafka_raw', 0))
            buffered = self.linux['buffered'].get('kafka_raw')
            self.put('linux_buffered_events', buffered)
            errors = self.memory.window('linux.errors', sum(self.linux['errors'].values()), self.now, 300)
            took = self.memory.moved('linux.received', received, self.now)
            activity = self.memory.moved('linux.sent', sent, self.now)
            trend = self.memory.trend('linux.buffered', buffered or 0)
            evidence.append(self.evidence('agent metrics', f'{int(received)} queued, {int(sent)} acknowledged by Kafka, {int(buffered or 0)} buffered'))
            limit = self.fresh['not_progressing_seconds'] * 1000
            if buffered and took and (activity is None or took - activity > limit or self.now - activity > limit):
                if self.kafka_down:
                    return result(DEGRADED, 'downstream_unavailable', f'{int(buffered)} events buffered, safe on disk, while Kafka is out', evidence, missing, activity=activity, heartbeat=heartbeat)
                return result(UNHEALTHY, 'not_processing', f'Running, {int(buffered)} events buffered, and Kafka has acknowledged nothing recently', evidence, missing, activity=activity, heartbeat=heartbeat)
            if errors:
                return result(DEGRADED, 'not_processing', f'{int(errors)} component errors in 5 minutes', evidence, missing, activity=activity, heartbeat=heartbeat)
            if (buffered or 0) > self.limits['lag_degraded_messages']:
                condition = 'backlog_recovering' if trend == 'falling' else 'backlog_increasing' if trend == 'rising' else 'delayed'
                return result(DEGRADED, condition, f'{int(buffered)} events wait in the buffer', evidence, missing, activity=activity, heartbeat=heartbeat)
        else:
            missing.append(f"agent metrics ({self.obs.get('linux_metrics', {}).get('error', 'not collected')})")
        oldest = number((body or {}).get('oldest_unread_seconds'))
        if oldest is not None and oldest > self.limits['oldest_degraded_seconds']:
            return result(DEGRADED, 'delayed', f'The oldest unread journal entry is {int(oldest)} s old', evidence, missing, activity=activity, heartbeat=heartbeat)
        recent = activity is not None and self.now - activity <= self.fresh['not_progressing_seconds'] * 1000
        if recent:
            return result(HEALTHY, 'ok', 'Running, and Kafka is acknowledging its events', evidence, missing, activity=activity, heartbeat=heartbeat)
        if unread is not None and unread <= 2 and self.linux:
            return result(HEALTHY, 'quiet', 'Running, and nothing is waiting to be read', evidence, missing, activity=activity, heartbeat=heartbeat, certainty='medium')
        return result(UNKNOWN, 'quiet' if self.linux else 'monitoring_unavailable', 'Running, but delivery cannot be confirmed', evidence, missing, activity=activity, heartbeat=heartbeat, certainty='low')

    def source(self, source, found):
        dataset, quiet = source['dataset'], source.get('quiet_minutes')
        agent = found['windows-agent' if dataset.startswith('windows.') else 'linux-agent']
        observed = (self.events or {}).get('observed_ms')
        row = self.memory.progress.get(f'source:{dataset}')
        current = (self.events or {}).get('sets', {}).get(dataset)
        newest = current.get('newest_ms') if current else None
        ingested = current.get('ingested_ms') if current else None
        if newest and (not row or newest > row[0]):
            self.memory.progress[f'source:{dataset}'] = row = [newest, ingested or newest]
        last = row[0] if row else None
        evidence = [self.evidence('stored events', f'newest {int((self.now - last) / 1000)} s ago', observed=observed)] if last else []
        missing = []
        if self.events is None:
            missing.append('stored events')
            return result(UNKNOWN, 'monitoring_unavailable', 'Stored events cannot be read, so freshness is not known', evidence, missing, activity=last, certainty='low')
        if agent['condition'] == 'service_unavailable':
            return result(UNHEALTHY, 'source_unavailable', 'Its agent is not running, so nothing is being collected', evidence, missing, activity=last)
        age = (self.now - last) / 1000 if last else None
        if age is not None and age < -self.config['time']['skew_tolerance_seconds']:
            return result(UNKNOWN, 'monitoring_unavailable', 'Its newest event is dated in the future, so the clocks disagree', evidence, missing, activity=last, certainty='low')
        if quiet is None:
            if age is not None and age <= 3600:
                return result(HEALTHY, 'ok', 'Events seen in the last hour', evidence, missing, activity=last)
            return result(UNKNOWN, 'quiet', 'This source is often silent, so its silence says nothing', evidence, missing, activity=last, certainty='low')
        if age is not None and age <= quiet * 60:
            return result(HEALTHY, 'ok', f'Newest event {int(age)} s old, within {quiet} minutes', evidence, missing, activity=last)
        if self.grace:
            return result(UNKNOWN, 'host_offline', 'The machine has just resumed, so its events may be on their way', evidence, missing, activity=last, certainty='low')
        text = 'No event seen yet' if age is None else f'No event for {int(age / 60)} minutes, past its usual {quiet}'
        return result(UNKNOWN, 'quiet', f'{text}. Silence alone proves nothing, but coverage cannot be confirmed', evidence, missing, activity=last, certainty='low')

    def sample_latency(self):
        pairs = (self.events or {}).get('latency', {})
        for platform in ('windows', 'linux'):
            values = [v for v in pairs.get(platform, []) if number(v, -86400, 10 ** 8) is not None]
            if values:
                self.put(f'{platform}_latency_p50_seconds', percentile(values, 0.5))
                self.put(f'{platform}_latency_p95_seconds', percentile(values, 0.95))
        delays = self.obs.get('analysis', {})
        for key, name in (('detection_delay', 'alert_delay_seconds'), ('enrichment_delay', 'enrichment_delay_seconds')):
            values = [v for v in delays.get(key, []) if number(v, -86400, 10 ** 8) is not None]
            self.put(name, percentile(values, 0.5))

    # Analysis.
    def detector(self):
        stop, view, evidence, missing = self.reported('detector', 'detector')
        if stop:
            return stop
        body = view['body']
        rules = [r for r in body.get('rules', [])[:500] if isinstance(r, dict)] if isinstance(body.get('rules'), list) else []
        marks = [v for v in (number(r.get('watermark_ms')) for r in rules) if v]
        if not marks:
            return result(UNKNOWN, 'monitoring_unavailable', 'Its report holds no rule watermarks', evidence, missing + ['rule watermarks'], heartbeat=view['checked'], certainty='low')
        newest, oldest = max(marks), min(marks)
        lag = (self.now - newest) / 1000
        self.put('detection_lag_seconds', lag)
        self.put('detection_oldest_watermark_seconds', (self.now - oldest) / 1000)
        moved = self.memory.moved('detector.watermark', newest, self.now)
        failing = sum(1 for r in rules if (number(r.get('failures')) or 0) > 0)
        pending = number(body.get('pending')) or 0
        evidence.append(self.evidence('detector report', f'{len(rules)} rules, {failing} failing, newest watermark {int(lag)} s behind', 'fresh', view['checked']))
        common = {'evidence': evidence, 'missing': missing, 'activity': moved, 'heartbeat': view['checked']}
        if self.search_down:
            return result(DEGRADED, 'downstream_unavailable', 'It cannot query events while OpenSearch is out', **common)
        if failing and self.lately('opensearch'):
            return result(DEGRADED, 'downstream_unavailable', f'{failing} rules are waiting out their retry delay after the OpenSearch outage', **common)
        if rules and failing == len(rules):
            return result(UNHEALTHY, 'not_processing', f'All {failing} rules are failing', **common)
        anchor = moved if moved is not None else None
        if anchor is not None and self.now - anchor > self.fresh['not_progressing_seconds'] * 1000 and lag > self.limits['watermark_degraded_seconds']:
            return result(UNHEALTHY, 'not_processing', f'Running, but no rule has advanced for {(self.now - anchor) // 1000} s', **common)
        if lag > self.limits['watermark_unhealthy_seconds']:
            return result(UNHEALTHY, 'delayed', f'Detection is {int(lag)} s behind', **common)
        if lag > self.limits['watermark_degraded_seconds']:
            return result(DEGRADED, 'delayed', f'Detection is {int(lag)} s behind', **common)
        if failing:
            return result(DEGRADED, 'not_processing', f'{failing} of {len(rules)} rules are failing', **common)
        if pending > self.limits['outbox_degraded']:
            return result(DEGRADED, 'delayed', f'{int(pending)} alerts wait to be published', **common)
        return result(HEALTHY, 'ok', f'{len(rules)} rules advancing, with nothing failing', **common)

    def enricher(self):
        stop, view, evidence, missing = self.reported('enricher', 'enricher')
        if stop:
            return stop
        body = view['body']
        feeds = [f for f in body.get('feeds', [])[:50] if isinstance(f, dict)] if isinstance(body.get('feeds'), list) else []
        enabled = [f for f in feeds if f.get('enabled') is True]
        stale = [clean(f.get('feed'), 32) for f in enabled if f.get('fresh') is not True]
        erred = sum(1 for f in enabled if f.get('last_error'))
        providers = [p for p in body.get('providers', [])[:20] if isinstance(p, dict)] if isinstance(body.get('providers'), list) else []
        paused = sum(1 for p in providers if (number(p.get('open_until_ms')) or 0) > self.now)
        counters = body.get('counters') if isinstance(body.get('counters'), dict) else {}
        moved = self.memory.moved('enricher.lookups', number(counters.get('lookups')), self.now)
        evidence.append(self.evidence('enricher report', f'{len(enabled)} feeds, {len(stale)} stale, {len(providers)} key-based providers, {paused} paused', 'fresh', view['checked']))
        missing.append('pending enrichment count')
        common = {'evidence': evidence, 'missing': missing, 'activity': moved, 'heartbeat': view['checked']}
        if self.search_down:
            return result(DEGRADED, 'downstream_unavailable', 'It cannot read alerts while OpenSearch is out', **common)
        if paused:
            return result(DEGRADED, 'source_unavailable', f'{paused} providers paused by the circuit breaker', **common)
        if stale:
            return result(DEGRADED, 'source_unavailable', f"Intelligence feeds out of date: {', '.join(stale[:4])}", **common)
        if erred:
            return result(DEGRADED, 'source_unavailable', f'{erred} feeds failed their last refresh', **common)
        return result(HEALTHY, 'ok', f'{len(enabled)} feeds fresh', **common)

    def correlator(self):
        stop, view, evidence, missing = self.reported('correlator', 'correlator')
        if stop:
            return stop
        body = view['body']
        alerts = body.get('alerts') if isinstance(body.get('alerts'), dict) else {}
        pending, failed, outbox = number(alerts.get('pending')) or 0, number(alerts.get('failed')) or 0, number(body.get('outbox')) or 0
        self.put('correlation_backlog', pending)
        group = (self.brokers or {}).get('groups', {}).get(self.config['kafka']['alert_group'], {})
        lag = group.get('lag') if group.get('known') else None
        moved = self.memory.moved('correlator.committed', group.get('committed'), self.now)
        trend = self.memory.trend('correlator.lag', (lag or 0) + pending)
        if lag is None:
            missing.append('consumer lag')
        evidence.append(self.evidence('correlator report', f'{int(pending)} waiting, {int(outbox)} unsent, {int(number(body.get("quarantined")) or 0)} quarantined', 'fresh', view['checked']))
        missing.append('audit chain (see validate --chains)')
        common = {'evidence': evidence, 'missing': missing, 'activity': moved, 'heartbeat': view['checked']}
        kafka_state, search_state = body.get('kafka'), body.get('opensearch')
        if self.kafka_down or kafka_state not in ('ok', 'unknown', None):
            return result(DEGRADED, 'downstream_unavailable', 'It cannot read alerts from Kafka', **common)
        if self.search_down or search_state not in ('ok', 'unknown', None):
            return result(DEGRADED, 'downstream_unavailable', f'{int(outbox)} records wait for OpenSearch', **common)
        if lag and moved is not None and self.now - moved > self.fresh['not_progressing_seconds'] * 1000:
            return result(UNHEALTHY, 'not_processing', f'Running, {lag} alerts waiting in Kafka, and no progress', **common)
        if failed:
            return result(DEGRADED, 'not_processing', f'{int(failed)} alerts could not be analysed', **common)
        if pending + (lag or 0) > self.limits['outbox_degraded'] or outbox > self.limits['outbox_degraded']:
            condition = 'backlog_increasing' if trend == 'rising' else 'backlog_recovering' if trend == 'falling' else 'delayed'
            return result(DEGRADED, condition, f'{int(pending + (lag or 0))} alerts waiting, {int(outbox)} unsent', **common)
        return result(HEALTHY, 'ok', 'Nothing is waiting' if not pending and not lag else f'{int(pending + (lag or 0))} alerts in flight', **common)

    def assets(self):
        stop, view, evidence, missing = self.reported('assets', 'asset')
        if stop:
            return stop
        body = view['body']
        backlog = body.get('backlog') if isinstance(body.get('backlog'), dict) else {}
        unsent = sum(number(v) or 0 for v in list(backlog.values())[:10])
        conflicts, rejected = number(body.get('open_conflicts')) or 0, number(body.get('rejected_reports')) or 0
        sources = body.get('sources') if isinstance(body.get('sources'), list) else []
        evidence.append(self.evidence('asset report', f'{len(sources)} sources, {int(conflicts)} identity conflicts, {int(rejected)} rejected reports', 'fresh', view['checked']))
        rise = self.memory.window('assets.rejected', rejected, self.now, 3600)
        common = {'evidence': evidence, 'missing': missing, 'heartbeat': view['checked'], 'activity': view['checked']}
        if self.search_down or body.get('opensearch') not in ('ok', 'unknown', None):
            return result(DEGRADED, 'downstream_unavailable', f'{int(unsent)} records wait for OpenSearch. Lookups still answer from local state', **common)
        if unsent > self.limits['outbox_degraded']:
            return result(DEGRADED, 'delayed', f'{int(unsent)} records wait to be published', **common)
        if rise:
            return result(DEGRADED, 'source_unavailable', f'{int(rise)} inventory reports rejected in an hour', **common)
        # A change awaiting an analyst's review makes this service's own report say WARN. That is work for a person, not a fault.
        return result(HEALTHY, 'ok', f'Reporting, with {int(conflicts)} identity conflicts open', **common)

    def paths(self):
        stop, view, evidence, missing = self.reported('attack-paths', 'path')
        if stop:
            return stop
        body = view['body']
        queue = number(body.get('queue')) or 0
        built = number(body.get('last_build_ms'))
        queued = number(body.get('oldest_queued_ms'))
        oldest = max(0, (self.now - queued) / 1000) if queued else 0
        gave_up = number(body.get('gave_up')) or 0
        backlog = body.get('output_backlog') if isinstance(body.get('output_backlog'), dict) else {}
        unsent = sum(number(v) or 0 for v in list(backlog.values())[:10])
        self.put('path_queue', queue)
        self.put('path_oldest_pending_seconds', oldest)
        self.put('path_delay_seconds', (self.now - built) / 1000 if built else None)
        trend = self.memory.trend('paths.queue', queue)
        failed = self.memory.window('paths.gave_up', gave_up, self.now, 3600)
        evidence_state = body.get('evidence') if isinstance(body.get('evidence'), dict) else {}
        expired, changed = number(evidence_state.get('unavailable')) or 0, number(evidence_state.get('changed')) or 0
        evidence.append(self.evidence('path report', f'{int(queue)} queued, {int(gave_up)} gave up, evidence {int(expired)} expired, {int(changed)} changed', 'fresh', view['checked']))
        if 'evidence' not in body:
            missing.append('evidence state counts')
        common = {'evidence': evidence, 'missing': missing, 'activity': built, 'heartbeat': view['checked']}
        if self.search_down or body.get('opensearch') not in ('ok', 'unknown', None):
            return result(DEGRADED, 'downstream_unavailable', f'{int(queue + unsent)} items wait for OpenSearch. Stored paths can still be read', **common)
        if failed:
            return result(DEGRADED, 'not_processing', f'{int(failed)} paths could not be built in the last hour', **common)
        if changed:
            return result(DEGRADED, 'configuration', f'{int(changed)} evidence references no longer match what was recorded. This is not expiry', **common)
        if queue > self.limits['path_queue_degraded'] or oldest > self.limits['path_oldest_degraded_seconds']:
            condition = 'backlog_increasing' if trend == 'rising' else 'backlog_recovering' if trend == 'falling' else 'delayed'
            return result(DEGRADED, condition, f'{int(queue)} seeds queued, oldest {int(oldest)} s, {trend}', **common)
        # Expired evidence is the designed outcome of 7-day event retention. It is shown, and it is not a fault.
        return result(HEALTHY, 'ok', f'{int(queue)} seeds queued, {int(expired)} evidence references expired by retention', **common)

    # Infrastructure.
    def host(self):
        got = self.obs.get('host', {})
        if not got.get('ok'):
            return result(UNKNOWN, 'monitoring_unavailable', 'Host figures could not be read', missing=['host figures'], certainty='low')
        available = 100 * got['mem_available'] / got['mem_total']
        swap = 100 * got['swap_used'] / got['swap_total'] if got['swap_total'] else 0
        memory = (got['pressure'].get('memory') or {}).get('full')
        cpu = (got['pressure'].get('cpu') or {}).get('some')
        disk = got.get('disk_windows')
        free = disk['free'] / 2 ** 30 if disk else None
        self.put('memory_available_percent', available, 1)
        self.put('swap_used_percent', swap, 1)
        self.put('memory_pressure_full', memory, 2)
        self.put('cpu_pressure_some', cpu, 2)
        self.put('windows_disk_free_gib', free, 1)
        evidence = [self.evidence('kernel', f"{available:.0f}% memory available, {swap:.0f}% swap used, load {got['load1']}")]
        missing = [name for name, value in (('memory pressure', memory), ('CPU pressure', cpu), ('C: free space', free)) if value is None]
        systemd = self.obs.get('systemd', {})
        if not systemd.get('ok'):
            missing.append('systemd state')
        limits = self.limits
        checks = ((free is not None and free < limits['windows_disk_unhealthy_gib'], UNHEALTHY, f'C: has {free} GiB free' if free is None else f'C: has {free:.1f} GiB free'),
                  (available < limits['memory_unhealthy_percent'], UNHEALTHY, f'Only {available:.0f}% of memory is available'),
                  (swap > limits['swap_unhealthy_percent'], UNHEALTHY, f'{swap:.0f}% of swap is in use'),
                  ((memory or 0) > limits['pressure_unhealthy_percent'], UNHEALTHY, f'Tasks stalled on memory {memory}% of the last minute'),
                  (free is not None and free < limits['windows_disk_degraded_gib'], DEGRADED, f'C: has {free} GiB free' if free is None else f'C: has {free:.1f} GiB free'),
                  (available < limits['memory_degraded_percent'], DEGRADED, f'Only {available:.0f}% of memory is available'),
                  (swap > limits['swap_degraded_percent'], DEGRADED, f'{swap:.0f}% of swap is in use'),
                  ((memory or 0) > limits['pressure_degraded_percent'], DEGRADED, f'Tasks stalled on memory {memory}% of the last minute'),
                  ((cpu or 0) > limits['cpu_pressure_degraded_percent'], DEGRADED, f'Tasks waited for a CPU {cpu}% of the last minute'))
        for failing, status, reason in checks:
            if failing:
                return result(status, 'resource_pressure', reason, evidence, missing)
        return result(HEALTHY, 'ok', 'Memory, swap, pressure and C: are within limits', evidence, missing)

    def housekeeping(self):
        evidence, missing = [], []
        stopped = []
        for timer in TIMER_UNITS:
            unit = self.unit_named(timer)
            if unit is None:
                missing.append('timer state')
            elif unit['active'] != 'active':
                stopped.append(timer)
        for report in ('kafka-expiry', 'disk-guard', 'linux-agent'):
            view = self.views[report]
            evidence.append(self.evidence(f'{report} report', view['state'], view['state'] if view['state'] in ('fresh', 'stale') else 'unavailable', view['checked']))
        if stopped:
            return result(DEGRADED, 'service_unavailable', f"Stopped: {', '.join(stopped)}", evidence, missing, fast=True)
        behind = [e['source'] for e in evidence if e['freshness'] != 'fresh']
        if behind:
            if self.grace:
                return result(UNKNOWN, 'host_offline', 'The machine has just resumed, so the timers have not run yet', evidence, missing, certainty='low')
            return result(UNKNOWN, 'monitoring_unavailable', f"Late or unreadable: {', '.join(behind)}", evidence, missing, certainty='low')
        return result(HEALTHY, 'ok', 'Timers active, with reports on time', evidence, missing)

    def health_monitor(self):
        own = self.obs.get('self', {})
        self.put('monitor_cycle_ms', own.get('cycle_ms'), 0)
        self.put('monitor_rss_mib', own['rss'] / 2 ** 20 if own.get('rss') else None, 1)
        self.put('monitor_cpu_percent', own.get('cpu_percent'), 3)
        evidence = [self.evidence('this service', f"last cycle {own.get('cycle_ms')} ms, {own.get('failed_collectors', 0)} collectors failed")]
        missing = []
        watchdog = self.obs.get('reports', {}).get('watchdog') or {}
        if not watchdog.get('ok'):
            missing.append('watchdog report')
        if own.get('persist_failed'):
            return result(DEGRADED, 'not_processing', 'The last cycle could not be saved', evidence, missing, certainty='medium', fast=True)
        if (own.get('cycle_ms') or 0) > self.config['bounds']['cycle_budget_seconds'] * 1000:
            return result(DEGRADED, 'delayed', f"The last cycle took {own['cycle_ms']} ms, past its budget", evidence, missing)
        if own.get('failed_collectors', 0) > 3:
            return result(DEGRADED, 'monitoring_unavailable', f"{own['failed_collectors']} collectors failed in the last cycle", evidence, missing, certainty='medium')
        return result(HEALTHY, 'ok', 'Cycles complete and saved', evidence, missing, activity=self.now, heartbeat=self.now)
