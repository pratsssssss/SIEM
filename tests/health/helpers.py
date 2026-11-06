"""A synthetic SIEM for the real monitor to watch. Everything here is a fixture, and nothing here is a real measurement.

`World` plays the part of the machines. Each `tick` advances the clock one cycle and moves every counter the way a
working pipeline does, then runs a real `Monitor`. A fault is a flag that stops some of that movement.
"""
import json
import socket
import sys
import tempfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'health'))

from siem_health.assess import ALL_UNITS  # noqa: E402
from siem_health.collect import Collector  # noqa: E402
from siem_health.config import build  # noqa: E402
from siem_health.service import Monitor  # noqa: E402
from siem_health.store import Store  # noqa: E402

NOW = 1793440000000
CYCLE = 60000
SOURCES = [{'dataset': 'windows.sysmon', 'quiet_minutes': 15}, {'dataset': 'windows.security', 'quiet_minutes': 30}, {'dataset': 'windows.defender'}, {'dataset': 'linux.system', 'quiet_minutes': 120}, {'dataset': 'linux.package'}]


def timeout():
    raise socket.timeout('timed out')


def refused():
    raise ConnectionRefusedError()


class Fake(Collector):
    def __init__(self, config, world):
        super().__init__(config)
        self.world = world

    def fails(self, name):
        how = self.world.fail.get(name)
        if how == 'timeout':
            timeout()
        if how == 'refused':
            refused()
        if how == 'denied':
            raise PermissionError()
        if how == 'malformed':
            raise ValueError('bad')

    def systemd(self, units):
        self.fails('systemd')
        return {'ok': True, 'units': {u: {'load': 'not-found' if u in self.world.absent else 'loaded', 'active': 'inactive' if u in self.world.absent else self.world.units.get(u, 'active'), 'sub': 'dead' if u in self.world.absent else 'running', 'result': 'success', 'restarts': self.world.restarts.get(u, 0), 'memory': 1000, 'cpu_ns': 1, 'since_mono_us': 1} for u in units}}

    def host(self):
        self.fails('host')
        return self.world.host_figures()

    def metrics(self, url):
        name = 'aggregator' if '9599' in url else 'linux' if '9597' in url else 'verifier'
        self.fails(name)
        return {'ok': True, 'series': self.world.series(name), 'malformed': 0}

    def kafka(self):
        self.fails('kafka')
        return self.world.kafka_view()

    def opensearch(self):
        self.fails('opensearch')
        return self.world.opensearch_view()

    def report(self, path):
        for name, target in self.config['reports'].items():
            if target == path:
                self.fails(f'report:{name}')
                body = self.world.report_body(name)
                if body is None:
                    return {'ok': False, 'error': 'missing'}
                return {'ok': True, 'body': body, 'checked_ms': body['checked_ms']}
        return {'ok': True, 'body': {'checked_ms': self.world.now}, 'checked_ms': self.world.now}

    def events(self, now, datasets):
        self.fails('events')
        sets = {d: {'newest_ms': self.world.newest[d], 'ingested_ms': self.world.newest[d] + 2000, 'count': 5} for d in datasets if d in self.world.newest}
        return {'ok': True, 'sets': sets, 'latency': {'windows': [self.world.latency] * 10, 'linux': [self.world.latency] * 10}, 'sampled': 20}

    def analysis(self, now):
        self.fails('analysis')
        return {'ok': True, 'detection_delay': [120.0], 'enrichment_delay': [40.0]}

    def retention(self):
        self.fails('retention')
        return {'ok': True, 'managed': 10, 'failed': self.world.retention_failed}

    def self_usage(self):
        return {'rss': 30 * 2 ** 20, 'cpu_seconds': self.world.ticks * 0.1}

    def fetch(self, url, body=None, headers=None, timeout=None, context=None):
        self.world.sent.append(url)
        self.fails('ship')
        lines = body.decode().strip().split('\n')
        return json.dumps({'items': [{'index': {'_id': json.loads(l)['index']['_id'], 'status': 201}} for l in lines[::2]]}).encode()

    def _auth(self):
        return {}

    def _ssl(self):
        return None


class World:
    def __init__(self, extra=None, sources=SOURCES):
        self.folder = tempfile.TemporaryDirectory()
        base = Path(self.folder.name)
        settings = {'state_file': str(base / 'health.db'), 'publish_report': str(base / 'health.json'), 'sources': sources}
        settings.update(extra or {})
        self.config = build(settings)
        self.now = NOW
        self.mono = 1000
        self.ticks = 0
        self.sent = []
        self.fail = {}
        self.units = {}
        self.absent = set()
        self.restarts = {}
        self.latency = 2.0
        self.retention_failed = 0
        self.reasons = {'accepted': 0}
        self.counts = dict.fromkeys(('raw', 'normalize', 'normalize_linux', 'dropped', 'sink', 'linux_received', 'linux_sent', 'win_received', 'win_acked'), 0)
        self.frozen = set()
        self.buffered = 0
        self.lag = {'raw': 0, 'alert': 0}
        self.committed = {'raw': 0, 'alert': 0}
        self.rate = 60
        self.memory = {'available': 0.5, 'swap': 0.0, 'pressure': 0.0, 'disk': 60}
        self.search = {'status': 'green', 'heap': 40, 'rejected': 0, 'failed': 0, 'unassigned_siem': 0, 'unassigned_other': 0, 'indexed': 0, 'dead': 0}
        self.reports_override = {}
        self.body_changes = {}
        self.watermark_at = None
        self.newest = {'windows.sysmon': NOW, 'windows.security': NOW, 'windows.defender': NOW - 86400000, 'linux.system': NOW, 'linux.package': NOW - 86400000}
        self.quiet = set()
        self.win_service = 'Running'
        self.store = Store(self.config['state_file'])
        self.monitor = self.new_monitor()
        self.patch = mock.patch('builtins.print')

    def new_monitor(self):
        return Monitor(self.config, self.store, Fake(self.config, self), wall=lambda: self.now, mono=lambda: self.mono, log=lambda text: None)

    def close(self):
        self.store.close()
        self.folder.cleanup()

    # Machines moving.
    def advance(self):
        self.ticks += 1
        self.now += CYCLE
        self.mono += CYCLE
        work = self.rate
        if 'pipeline' not in self.frozen:
            self.counts['raw'] += work
            self.counts['normalize'] += work // 2
            self.counts['normalize_linux'] += work // 2
            self.counts['sink'] += work
            self.reasons['accepted'] += work
            self.search['indexed'] += work
        if 'raw_commit' not in self.frozen:
            self.committed['raw'] += work
        else:
            self.lag['raw'] += work
        if 'alert_commit' not in self.frozen:
            self.committed['alert'] += 1
        else:
            self.lag['alert'] += 50
        if 'linux_delivery' not in self.frozen:
            self.counts['linux_received'] += 10
            self.counts['linux_sent'] += 10
        else:
            self.counts['linux_received'] += 10
            self.buffered += 10
        if 'win_delivery' not in self.frozen:
            self.counts['win_received'] += 50
            self.counts['win_acked'] += 50
        else:
            self.counts['win_received'] += 50
        for name in list(self.newest):
            if name in ('windows.sysmon', 'windows.security', 'linux.system') and name not in self.quiet and not (name.startswith('windows') and self.win_service != 'Running') and not (name.startswith('windows') and 'win_delivery' in self.frozen):
                self.newest[name] = self.now - 5000

    def tick(self, count=1):
        for _ in range(count):
            self.advance()
            self.monitor.run_cycle()
        return self

    def suspend(self, minutes):
        """Wall clock moves, monotonic does not, as when the virtual machine is paused."""
        self.now += minutes * CYCLE

    def stop_monitor(self, minutes):
        self.now += minutes * CYCLE
        self.mono += minutes * CYCLE
        self.monitor = self.new_monitor()

    # Views.
    def status(self, name):
        return self.store.records()[name]['status']

    def condition(self, name):
        return self.store.component(name)['condition']

    def body(self, name):
        return self.store.component(name)

    def pipeline(self):
        return self.store.mark('pipeline')

    # What each source returns.
    def host_figures(self):
        total = 6 * 2 ** 30
        return {'ok': True, 'mem_total': total, 'mem_available': int(total * self.memory['available']), 'swap_total': 4 * 2 ** 30, 'swap_used': int(4 * 2 ** 30 * self.memory['swap']), 'load1': 0.5, 'cpus': 4,
                'pressure': {'memory': {'some': 0.0, 'full': self.memory['pressure']}, 'cpu': {'some': 1.0}, 'io': {'some': 1.0}}, 'disk_root': {'total': 10 ** 12, 'free': 9 * 10 ** 11}, 'disk_windows': {'total': 500 * 2 ** 30, 'free': self.memory['disk'] * 2 ** 30}, 'boot_ms': NOW - 3600000}

    def series(self, name):
        c = self.counts
        if name == 'verifier':
            return [('seal_verifier_events_total', {'result': k}, float(v)) for k, v in self.reasons.items()]
        if name == 'linux':
            return [('vector_component_received_events_total', {'component_id': 'kafka_raw'}, float(c['linux_received'])), ('vector_component_sent_events_total', {'component_id': 'kafka_raw', 'output': '_default'}, float(c['linux_sent'])),
                    ('vector_buffer_size_events', {'component_id': 'kafka_raw'}, float(self.buffered)), ('vector_component_errors_total', {'component_id': 'kafka_raw'}, float(self.fail.get('linux_errors', 0)))]
        return [('vector_component_received_events_total', {'component_id': 'siem_raw'}, float(c['raw'])), ('vector_component_received_events_total', {'component_id': 'normalize'}, float(c['normalize'])),
                ('vector_component_received_events_total', {'component_id': 'normalize_linux'}, float(c['normalize_linux'])), ('vector_component_sent_events_total', {'component_id': 'normalize', 'output': '_default'}, float(c['normalize'] - c['dropped'])),
                ('vector_component_sent_events_total', {'component_id': 'normalize', 'output': 'dropped'}, float(c['dropped'])), ('vector_component_sent_events_total', {'component_id': 'normalize_linux', 'output': '_default'}, float(c['normalize_linux'])),
                ('vector_component_sent_events_total', {'component_id': 'opensearch_events', 'output': '_default'}, float(c['sink'])), ('vector_component_errors_total', {'component_id': 'opensearch_events'}, float(self.fail.get('sink_errors', 0)))]

    def kafka_view(self):
        k = self.config['kafka']
        topics = {k['raw_topic']: {'exists': True, 'partitions': 3, 'leaderless': self.fail.get('leaderless', 0)}, k['alert_topic']: {'exists': True, 'partitions': 1, 'leaderless': 0}, k['incident_topic']: {'exists': 'no_incident_topic' not in self.fail, 'partitions': 1, 'leaderless': 0}}
        return {'ok': True, 'brokers': 1, 'topics': topics, 'end_offsets': {k['raw_topic']: self.committed['raw'] + self.lag['raw'], k['alert_topic']: self.committed['alert'] + self.lag['alert']},
                'groups': {k['raw_group']: {'known': True, 'committed': self.committed['raw'], 'lag': self.lag['raw']}, k['alert_group']: {'known': True, 'committed': self.committed['alert'], 'lag': self.lag['alert']}}}

    def opensearch_view(self):
        s = self.search
        groups = {'windows': {'docs': 1000, 'bytes': 2 ** 30, 'indexed': s['indexed'], 'failed': 0}, 'linux': {'docs': 100, 'bytes': 2 ** 20, 'indexed': 0, 'failed': 0}, 'deadletter': {'docs': s['dead'], 'bytes': 100, 'indexed': 0, 'failed': 0}, 'alerts': {'docs': 10, 'bytes': 100, 'indexed': 0, 'failed': 0}}
        return {'ok': True, 'status': s['status'], 'nodes': 1, 'active_shards': 40, 'unassigned': {'siem': s['unassigned_siem'], 'other': s['unassigned_other']}, 'heap_percent': s['heap'], 'disk_total': 10 ** 12, 'disk_free': 9 * 10 ** 11,
                'index_total': s['indexed'], 'index_time_ms': s['indexed'], 'index_failed': s['failed'], 'write_rejected': s['rejected'], 'search_rejected': 0, 'write_queue': 0, 'groups': groups}

    def report_body(self, name):
        if name in self.reports_override:
            return self.reports_override[name]
        now = self.now
        watermark = self.watermark_at if self.watermark_at is not None else now - 30000
        base = {
            'detector': {'status': 'OK', 'checked_ms': now, 'pending': 0, 'rules_enabled': 2, 'rules': [{'rule_id': 'a', 'watermark_ms': watermark, 'failures': 0}, {'rule_id': 'b', 'watermark_ms': watermark - 1000, 'failures': 0}]},
            'enricher': {'status': 'OK', 'checked_ms': now, 'feeds': [{'feed': 'one', 'enabled': True, 'fresh': True, 'last_error': None}], 'providers': [], 'cache': {}, 'counters': {'lookups': self.ticks}},
            'correlator': {'status': 'OK', 'checked_ms': now, 'alerts': {'done': 5}, 'quarantined': 0, 'outbox': 0, 'kafka': 'ok', 'opensearch': 'ok', 'lag': 0},
            'asset': {'status': 'WARN', 'checked_ms': now, 'open_conflicts': 0, 'backlog': {'changes': 0}, 'sources': [{'source': 'x'}], 'opensearch': 'ok', 'rejected_reports': 0},
            'path': {'status': 'OK', 'checked_ms': now, 'queue': 0, 'oldest_queued_ms': None, 'gave_up': 0, 'output_backlog': {'paths': 0}, 'opensearch': 'ok', 'last_build_ms': now - 60000, 'evidence': {'unavailable': 0, 'changed': 0}},
            'linux-agent': {'status': 'OK', 'checked_ms': now, 'unread_journal_entries': 0, 'oldest_unread_seconds': 0},
            'kafka-expiry': {'checked_ms': now, 'oldest_unread_age_ms': None, 'unread': 0, 'lost_latched': {}, 'retention_ms': 259200000},
            'disk-guard': {'status': 'OK', 'checked_ms': now, 'ingest_stopped': False},
            'windows-agent': {'status': 'OK', 'checked_ms': now, 'service': self.win_service, 'metrics': {'received': self.counts['win_received'], 'acknowledged': self.counts['win_acked'], 'buffered': self.buffered if 'win_delivery' in self.frozen else 0, 'errors': 0}},
        }[name]
        return {**base, **self.body_changes.get(name, {})}


ALL_UNITS_LIST = list(ALL_UNITS)
