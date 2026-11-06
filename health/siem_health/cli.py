"""`siem-health`: read-only views of pipeline health.

The command opens the state file read-only and never talks to the service, so it still answers when the service is
down, and then says so. There is no action here that changes anything, in the SIEM or in this subsystem.
"""
import argparse
import json
import os
import socket
import sqlite3
import subprocess
import sys
import time

from .assess import COMPONENTS
from .catalog import CATALOG, UNAVAILABLE, describe
from .config import ConfigError, load
from .store import Store

DEFAULT_CONFIG = os.environ.get('SIEM_HEALTH_CONFIG', '/home/linux/siem/config/health/health.yaml')
SYSTEMCTL = '/usr/bin/systemctl'
SOCKETS = {'incidents': ('/run/siem-correlator/control.sock', {'action': 'verify'}), 'paths': ('/run/siem-path/control.sock', {'action': 'validate'})}
STATUS_ORDER = ('UNHEALTHY', 'DEGRADED', 'UNKNOWN', 'HEALTHY', 'NOT_APPLICABLE')


def when(ms):
    return time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime(ms / 1000)) if ms else 'never'


def ago(ms, now):
    if not ms:
        return 'never'
    seconds = max(0, (now - ms) // 1000)
    return f'{seconds} s ago' if seconds < 120 else f'{seconds // 60} min ago' if seconds < 7200 else f'{seconds // 3600} h ago'


def service_state():
    """Asked of systemd directly, so this answer does not depend on the service it describes."""
    try:
        done = subprocess.run([SYSTEMCTL, 'show', 'siem-health.service', '--property=ActiveState,SubState,NRestarts'], capture_output=True, text=True, timeout=5, check=False, stdin=subprocess.DEVNULL)
        row = dict(line.split('=', 1) for line in done.stdout.splitlines() if '=' in line)
        return {'active': row.get('ActiveState', 'unknown'), 'sub': row.get('SubState', ''), 'restarts': int(row.get('NRestarts') or 0)}
    except (OSError, ValueError, subprocess.SubprocessError):
        return {'active': 'unknown', 'sub': '', 'restarts': None}


class View:
    def __init__(self, config, clock=None):
        self.config = config
        self.clock = clock or (lambda: int(time.time() * 1000))
        self.store = Store(config['state_file'], read_only=True)
        self.now = self.clock()

    def freshness(self):
        """How far the stored picture can be believed right now."""
        last = self.store.mark('last_cycle_ms')
        interval = self.store.mark('self', {}).get('interval_seconds', self.config['schedule']['cycle_seconds'])
        age = (self.now - last) // 1000 if last else None
        current = last is not None and age <= interval * self.config['time']['gap_factor']
        return {'last_cycle_ms': last, 'age_seconds': age, 'current': current, 'service': service_state()}

    def overview(self):
        fresh = self.freshness()
        pipeline = self.store.mark('pipeline') or {}
        rows = self.store.components()
        groups = {s: sorted(k for k, v in rows.items() if v['status'] == s and not k.startswith('source:')) for s in STATUS_ORDER}
        status = pipeline.get('status', 'UNKNOWN') if fresh['current'] else 'UNKNOWN'
        latest = self.store.latest_samples()[1]
        pressure = [rows['host-wsl']['reason']] if rows.get('host-wsl', {}).get('condition') == 'resource_pressure' else []
        out = {'schema_version': 1, 'observed_ms': fresh['last_cycle_ms'], 'overall': status, 'stored_overall': pipeline.get('status'), 'monitor_current': fresh['current'], 'monitor': fresh, 'since_ms': pipeline.get('since_ms'),
               'previous': pipeline.get('previous'), 'coverage': pipeline.get('coverage', 'unknown') if fresh['current'] else 'unknown', 'coverage_reason': pipeline.get('coverage_reason') if fresh['current'] else 'The monitor is not current, so the last picture may be out of date',
               'bottleneck': pipeline.get('bottleneck'), 'root_cause': pipeline.get('root_cause'), 'critical': groups['UNHEALTHY'], 'degraded': groups['DEGRADED'], 'unknown': groups['UNKNOWN'], 'healthy': groups['HEALTHY'],
               'not_applicable': groups['NOT_APPLICABLE'], 'sources_fresh': pipeline.get('sources_fresh', []), 'sources_quiet': pipeline.get('sources_quiet', []), 'sources_overdue': pipeline.get('sources_overdue', []),
               'resource_pressure': pressure, 'memory_available_percent': latest.get('memory_available_percent', {}).get('value'), 'windows_disk_free_gib': latest.get('windows_disk_free_gib', {}).get('value'), 'stages': pipeline.get('stages', [])}
        return out

    def metrics(self, name=None, hours=2):
        at, latest = self.store.latest_samples()
        if name:
            since = self.now - hours * 3600000
            return {'metric': describe(name), 'unit': CATALOG[name][1]['unit'], 'points': self.store.series(name, since), 'hourly': self.store.hourly(name, since)}
        return {'observed_ms': at, 'metrics': {k: {'value': v['value'], 'unit': CATALOG[k][1]['unit'], 'at_ms': v['at_ms'], 'kind': CATALOG[k][1]['kind']} for k, v in latest.items() if k in CATALOG}}

    def lag(self):
        latest = self.store.latest_samples()[1]
        names = ('raw_lag_messages', 'alert_lag_messages', 'oldest_unread_seconds', 'windows_buffered_events', 'linux_buffered_events', 'correlation_backlog', 'path_queue', 'path_oldest_pending_seconds', 'detection_lag_seconds', 'detection_oldest_watermark_seconds')
        rows = {n: latest.get(n) for n in names}
        return {'observed_ms': self.store.mark('last_cycle_ms'), 'lag': rows, 'not_measured': [n for n, v in rows.items() if v is None]}

    def validate(self, chains=False):
        checks = []
        chain = self.store.verify_chain()
        checks.append({'check': 'transition history is intact', 'ok': chain['intact'], 'detail': chain})
        fresh = self.freshness()
        checks.append({'check': 'the monitor is current', 'ok': fresh['current'], 'detail': {'age_seconds': fresh['age_seconds'], 'service': fresh['service']}})
        rows = self.store.components()
        bad = [k for k, v in rows.items() if not v.get('reason') or 'observed_ms' not in v]
        checks.append({'check': 'every component has a reason and an observation time', 'ok': bool(rows) and not bad, 'detail': {'components': len(rows), 'without': bad}})
        missing = [k for k in self.store.latest_samples()[1] if k not in CATALOG]
        checks.append({'check': 'every stored metric is in the catalogue', 'ok': not missing, 'detail': missing})
        size = self.store.size()
        checks.append({'check': 'the outbox is within its limit', 'ok': size['outbox'] <= self.config['bounds']['outbox_rows'], 'detail': size})
        if chains:
            for name, (path, request) in SOCKETS.items():
                checks.append(self.ask(name, path, request))
        return {'ok': all(c['ok'] for c in checks), 'checks': checks, 'size': size}

    @staticmethod
    def ask(name, path, request):
        """Asks a service to check its own chain, as the person running this command. It changes nothing."""
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as link:
                link.settimeout(10)
                link.connect(path)
                link.sendall(json.dumps(request).encode())
                link.shutdown(socket.SHUT_WR)
                data = b''
                while len(data) < 1000000:
                    part = link.recv(65536)
                    if not part:
                        break
                    data += part
            reply = json.loads(data)
            result = reply.get('result') or {}
            return {'check': f'{name} audit chain', 'ok': bool(reply.get('ok')) and result.get('intact', result.get('ok', False)) is True, 'detail': {k: v for k, v in result.items() if isinstance(v, (int, bool)) or v is None}}
        except (OSError, ValueError) as error:
            return {'check': f'{name} audit chain', 'ok': False, 'detail': f'could not ask: {type(error).__name__}'}

    def resources(self):
        latest = self.store.latest_samples()[1]
        names = ('memory_available_percent', 'swap_used_percent', 'memory_pressure_full', 'cpu_pressure_some', 'windows_disk_free_gib', 'opensearch_heap_percent', 'opensearch_store_gib', 'monitor_rss_mib', 'monitor_cpu_percent', 'monitor_cycle_ms')
        component = self.store.component('host-wsl') or {}
        return {'observed_ms': self.store.mark('last_cycle_ms'), 'status': component.get('status'), 'reason': component.get('reason'), 'figures': {n: latest.get(n, {}).get('value') for n in names}, 'store_rows': self.store.size(), 'self': self.store.mark('self')}

    # History of what is assessed now. A component that is no longer assessed keeps its rows in the store, which is append-only,
    # and they are not listed. Monitoring gaps and the pipeline roll-up are always listed.
    def assessed(self):
        return {c[0] for c in COMPONENTS} | {f"source:{s['dataset']}" for s in self.config['sources']} | {'monitoring', 'pipeline'}

    def history(self, name=None, since_ms=0):
        known = self.assessed()
        return [r for r in self.store.transitions(name, since_ms) if r.get('component') in known]

    def failures(self, since_ms=0):
        known = self.assessed()
        keep = lambda rows: [r for r in rows if r.get('component') in known]
        return {'open': keep(self.store.episodes(only_open=True)), 'recent': keep(self.store.episodes(since_ms))}

    def explain(self, name):
        row = self.store.component(name)
        if row is None:
            return None
        fresh = self.freshness()
        history = self.store.transitions(name, 0, 5)
        note = None if fresh['current'] else f"This monitor last ran {ago(fresh['last_cycle_ms'], self.now)}, so what follows is the last picture it had"
        return {'component': name, 'status': row['status'], 'previous': row['previous'], 'since_ms': row['since_ms'], 'condition': row['condition'], 'reason': row['reason'], 'certainty': row['certainty'], 'durability': row['durability'], 'observed_ms': row['observed_ms'], 'freshness': row['freshness'],
                'latest_assessment': row['latest_assessment'], 'pending': row['pending'], 'evidence': row['evidence'], 'missing': row['missing'], 'last_activity_ms': row['last_activity_ms'], 'last_heartbeat_ms': row['last_heartbeat_ms'], 'recent_transitions': history, 'diagnostics': self.store.diagnostics(name, 3), 'monitor_note': note}


def show_overview(data, now):
    print(f"Pipeline: {data['overall']}   coverage: {data['coverage']}   since {when(data['since_ms'])}")
    print(f"Observed: {when(data['observed_ms'])} ({ago(data['observed_ms'], now)})   monitor service: {data['monitor']['service']['active']}")
    if not data['monitor_current']:
        print(f"WARNING: this monitor is not current. Last stored state was {data['stored_overall']}.")
    print(f"Coverage: {data['coverage_reason']}")
    if data['bottleneck']:
        print(f"Bottleneck: {data['bottleneck']}   root cause: {data['root_cause']}")
    for label, key in (('Critical', 'critical'), ('Degraded', 'degraded'), ('Unknown', 'unknown'), ('Not applicable', 'not_applicable')):
        if data[key]:
            print(f"{label}: {', '.join(data[key])}")
    print(f"Sources: {len(data['sources_fresh'])} fresh, {len(data['sources_quiet'])} quiet" + (f", overdue: {', '.join(data['sources_overdue'])}" if data['sources_overdue'] else ''))
    print(f"Memory available: {data['memory_available_percent']}%   C: free: {data['windows_disk_free_gib']} GiB" + (f"   pressure: {'; '.join(data['resource_pressure'])}" if data['resource_pressure'] else ''))
    print()
    for stage in data['stages']:
        print(f"  {stage['stage']:<14}{stage['status']:<16}{', '.join(stage['components'])}")


def show_components(rows, now):
    print(f"{'COMPONENT':<26}{'STATUS':<16}{'CONDITION':<24}{'ACTIVITY':<14}REASON")
    for name in sorted(rows, key=lambda k: (k.startswith('source:'), STATUS_ORDER.index(rows[k]['status']), k)):
        row = rows[name]
        print(f"{name:<26}{row['status']:<16}{row['condition']:<24}{ago(row['last_activity_ms'], now):<14}{row['reason'][:90]}")


def emit(args, data, text=None):
    if args.json or text is None:
        print(json.dumps(data, indent=1))
    else:
        text()


def main(argv=None):
    parser = argparse.ArgumentParser(prog='siem-health', description='Pipeline health. Every command is read-only.')
    parser.add_argument('--config', default=DEFAULT_CONFIG)
    parser.add_argument('--json', action='store_true', help='machine-readable output')
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('run', help='the service itself')
    commands.add_parser('status')
    commands.add_parser('overview')
    commands.add_parser('components')
    item = commands.add_parser('component')
    item.add_argument('name')
    commands.add_parser('pipeline')
    numbers = commands.add_parser('metrics')
    numbers.add_argument('name', nargs='?')
    numbers.add_argument('--hours', type=int, default=2, choices=range(1, 721), metavar='1-720')
    numbers.add_argument('--catalog', action='store_true')
    history = commands.add_parser('history')
    history.add_argument('name', nargs='?')
    history.add_argument('--days', type=int, default=7, choices=range(1, 366), metavar='1-365')
    failures = commands.add_parser('failures')
    failures.add_argument('--days', type=int, default=7, choices=range(1, 366), metavar='1-365')
    commands.add_parser('lag')
    commands.add_parser('resources')
    checks = commands.add_parser('validate')
    checks.add_argument('--chains', action='store_true', help='also ask the correlator and path services to check their chains')
    why = commands.add_parser('explain')
    why.add_argument('name')
    args = parser.parse_args(argv)
    try:
        config = load(args.config)
    except (ConfigError, OSError) as error:
        print(f'siem-health: {error}', file=sys.stderr)
        return 2
    if args.command == 'run':
        from .service import run
        run(config)
        return 0
    try:
        return dispatch(args, View(config))
    except sqlite3.Error as error:
        print(f'siem-health: the state file cannot be read ({type(error).__name__}). The service state is {service_state()["active"]}.', file=sys.stderr)
        return 3


def dispatch(args, view):
    now = view.now
    command = args.command
    if command == 'status':
        data = view.overview()
        keep = {k: data[k] for k in ('overall', 'coverage', 'bottleneck', 'root_cause', 'observed_ms', 'monitor_current', 'critical', 'degraded', 'unknown')}
        emit(args, keep, lambda: print(f"{keep['overall']}, coverage {keep['coverage']}, observed {ago(keep['observed_ms'], now)}" + (f", bottleneck {keep['bottleneck']}" if keep['bottleneck'] else '')))
    elif command == 'overview':
        data = view.overview()
        emit(args, data, lambda: show_overview(data, now))
    elif command == 'components':
        rows = view.store.components()
        emit(args, rows, lambda: show_components(rows, now))
    elif command == 'component':
        row = view.store.component(args.name)
        if row is None:
            print(f'siem-health: no component named {args.name!r}. See `siem-health components`.', file=sys.stderr)
            return 1
        emit(args, row)
    elif command == 'pipeline':
        emit(args, view.store.mark('pipeline') or {})
    elif command == 'metrics':
        if args.catalog:
            emit(args, {'metrics': [describe(n) for n in CATALOG], 'not_available': UNAVAILABLE})
        elif args.name and args.name not in CATALOG:
            print(f'siem-health: no metric named {args.name!r}. See `siem-health metrics --catalog`.', file=sys.stderr)
            return 1
        else:
            emit(args, view.metrics(args.name, args.hours))
    elif command == 'history':
        emit(args, view.history(args.name, now - args.days * 86400000))
    elif command == 'failures':
        emit(args, view.failures(now - args.days * 86400000))
    elif command == 'lag':
        emit(args, view.lag())
    elif command == 'resources':
        emit(args, view.resources())
    elif command == 'validate':
        data = view.validate(args.chains)
        emit(args, data)
        return 0 if data['ok'] else 1
    elif command == 'explain':
        data = view.explain(args.name)
        if data is None:
            print(f'siem-health: no component named {args.name!r}. See `siem-health components`.', file=sys.stderr)
            return 1
        emit(args, data)
    return 0
