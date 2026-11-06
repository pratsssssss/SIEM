"""Live pipeline health tests, as root in WSL against the running stack. Prints counts and statuses, never event content.

Usage: run_live_health.py real         what it reports, checked against independent sources
       run_live_health.py security     the account, the OpenSearch role, secrets, what is stored
       run_live_health.py faults       real services really stopped, one bounded fault at a time, with recovery
       run_live_health.py resilience   this monitor killed and stopped, with the pipeline watched meanwhile
       run_live_health.py measure      memory, CPU, growth, and ingestion with and without the monitor

`faults` stops real services for a few minutes each. Kafka and the agents' disk buffers hold events meanwhile, and every
fault must recover before the next begins. The Windows agent is not stopped, because that needs elevation. Host pressure
and a suspended machine are not provoked. Those remain fixture tests in test_scenarios.py.
"""
import json
import os
import re
import signal
import socket
import subprocess
import sys
import time
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'health'))
import livelib as t  # noqa: E402
from siem_health.assess import COMPONENTS  # noqa: E402

check, api, wait, systemctl = t.check, t.api, t.wait, t.systemctl
LOGIN = '/home/linux/siem/config/health/opensearch-health.json'
DB = '/home/linux/siem/data/health/health.db'
WINDOWS_REPORT = os.path.join(t.MONITOR, 'windows-agent.json')
CORE = ('opensearch', 'kafka', 'seal-verifier', 'vector', 'siem-detector', 'siem-enricher', 'siem-correlator', 'siem-asset', 'siem-path', 'siem-linux-agent')
KAFKA = '/opt/kafka/bin/kafka-consumer-groups.sh'


def run(*words, timeout=60):
    return subprocess.run(words, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=timeout)


def health(*words):
    done = run('runuser', '-u', 'linux', '--', 'siem-health', '--json', *words)
    return json.loads(done.stdout) if done.stdout.strip().startswith(('{', '[')) else {'_error': done.stderr, '_code': done.returncode}


def as_monitor(*words):
    return run('runuser', '-u', 'siem-health', '--', *words)


def as_service(route, method='GET', body=None):
    t.LOGIN = LOGIN
    return t.as_account(route, method, body)


def component(name):
    return health('component', name)


def restarts():
    return {u: run('systemctl', 'show', u, '--property=NRestarts', '--value').stdout.strip() for u in CORE}


def active(units):
    return all(run('systemctl', 'is-active', u).stdout.strip() == 'active' for u in units)


def vector_received():
    text = urllib.request.urlopen('http://127.0.0.1:9599/metrics', timeout=5).read().decode()
    return sum(float(m[1]) for m in re.finditer(r'^vector_component_received_events_total\{[^}]*component_id="siem_raw"[^}]*\} (\S+)', text, re.M))


def real():
    view = health('overview')
    rows = health('components')
    names = {c[0] for c in COMPONENTS}
    check('every pipeline component is present', names <= set(rows), f'{len(rows)} records')
    now = int(time.time() * 1000)
    check('every record was observed in the last 150 s', all(now - r['observed_ms'] < 150000 for r in rows.values()))
    check('every record has a reason and certainty', all(r['reason'] and r['certainty'] for r in rows.values()))
    check('no component is UNHEALTHY on the idle stack', not view['critical'], str(view['critical']))
    print('INFO overall', view['overall'], 'coverage', view['coverage'], 'degraded', view['degraded'], 'unknown', view['unknown'], 'quiet', view['sources_quiet'])
    units = {'kafka': 'kafka', 'verifier': 'seal-verifier', 'aggregator': 'vector', 'opensearch': 'opensearch', 'detector': 'siem-detector', 'enricher': 'siem-enricher', 'correlator': 'siem-correlator', 'assets': 'siem-asset', 'attack-paths': 'siem-path', 'linux-agent': 'siem-linux-agent'}
    check('every unit it calls up is up by systemctl', all(run('systemctl', 'is-active', u).stdout.strip() == 'active' for k, u in units.items() if rows[k]['status'] == 'HEALTHY'))

    # Independent sources. The administrator account and Kafka's own tools, not this service's reads.
    cluster = api('/_cluster/health')
    check('cluster state agrees with OpenSearch', str(cluster['status']) in rows['opensearch']['evidence'][1]['value'], cluster['status'])
    groups = run(KAFKA, '--bootstrap-server', '127.0.0.1:9092', '--list', timeout=60).stdout.split()
    check('Kafka has exactly the two real groups, and none from this service', sorted(groups) == ['siem-aggregator', 'siem-correlator'], str(groups))
    described = run(KAFKA, '--bootstrap-server', '127.0.0.1:9092', '--group', 'siem-aggregator', '--describe', timeout=60).stdout
    tool_lag = sum(int(line.split()[5]) for line in described.splitlines() if 'siem-raw-logs' in line and line.split()[5].isdigit())
    mine = health('lag')['lag']['raw_lag_messages']['value']
    check('raw lag agrees with the Kafka tool, within what a minute moves', abs(tool_lag - mine) <= 2000, f'tool {tool_lag}, service {mine}')
    metrics = health('metrics')['metrics']
    info = dict(line.split(':', 1) for line in open('/proc/meminfo'))
    available = 100 * int(info['MemAvailable'].split()[0]) / int(info['MemTotal'].split()[0])
    check('memory agrees with the kernel', abs(available - metrics['memory_available_percent']['value']) < 8, f"{available:.1f} and {metrics['memory_available_percent']['value']}")
    free = os.statvfs('/mnt/c')
    check('C: free space agrees', abs(free.f_frsize * free.f_bavail / 2 ** 30 - metrics['windows_disk_free_gib']['value']) < 2)
    newest = api('/siem-windows-*/_search', 'POST', {'size': 1, 'sort': [{'event.ingested': 'desc'}], '_source': ['event.ingested']})['hits']['hits'][0]['_source']['event']['ingested']
    stamp = time.mktime(time.strptime(newest[:19], '%Y-%m-%dT%H:%M:%S')) * 1000 - time.timezone * 0
    check('Windows freshness agrees with the newest stored event', abs(stamp - rows['windows-agent']['last_activity_ms']) < 400000, newest[:19])
    detector = json.load(open('/home/linux/siem/data/detector/detector.json'))
    lag = (detector['checked_ms'] - max(r['watermark_ms'] for r in detector['rules'])) / 1000
    check('detection lag agrees with the detector report', abs(lag - metrics['detection_lag_seconds']['value']) < 200, f"{lag:.0f} and {metrics['detection_lag_seconds']['value']:.0f}")
    points = [v for _, v in health('metrics', 'indexed_per_second', '--hours', '2')['points']]
    check('indexing rate is measured, and above zero', any(v > 0 for v in points), f'{len(points)} samples')
    catalog = health('metrics', '--catalog')
    check('every value shown is in the catalogue', set(metrics) <= {m['name'] for m in catalog['metrics']}, f'{len(metrics)} of {len(catalog["metrics"])}')
    print('INFO not measured right now:', health('lag')['not_measured'])
    print('INFO catalogue entries with no value yet:', sorted({m['name'] for m in catalog['metrics']} - set(metrics)))

    # Footprint in the pipeline itself.
    topics = run('/opt/kafka/bin/kafka-topics.sh', '--bootstrap-server', '127.0.0.1:9092', '--list', timeout=60).stdout.split()
    check('no new Kafka topic', sorted(t for t in topics if not t.startswith('__')) == ['siem-alerts', 'siem-incidents', 'siem-raw-logs'], str(topics))
    listening = run('ss', '-tlnpH').stdout
    check('it listens on nothing', 'siem-health' not in listening and 'siem_health' not in listening)
    lines = run('journalctl', '-u', 'siem-health', '--since', '-1h', '--no-pager', '-q', '-o', 'cat').stdout.splitlines()
    check('its journal is quiet', len(lines) < 200, f'{len(lines)} lines in the last hour')
    # Sessions opened by a person or these tests are real events about that person. Service activity must make none.
    query = {'bool': {'filter': [{'range': {'@timestamp': {'gte': 'now-12m'}}}, {'simple_query_string': {'query': '"siem-health"'}}], 'must_not': [{'term': {'process.name': 'runuser'}}]}}
    found = api('/siem-linux-*/_count', 'POST', {'query': query})
    check('in 12 minutes, covering two watchdog runs, none of its activity entered the event pipeline', found.get('count') == 0, str(found.get('count')))
    check('history is intact, and validate passes', health('validate').get('ok') is True)
    chains = run('runuser', '-u', 'linux', '--', 'siem-health', '--json', 'validate', '--chains')
    data = json.loads(chains.stdout)
    named = {c['check']: c['ok'] for c in data['checks']}
    check('the correlator and path chains answer for an analyst', named.get('incidents audit chain') and named.get('paths audit chain'), str({k: v for k, v in named.items() if 'audit' in k}))
    docs = {name: api(f'/{name}/_count').get('count', 0) for name in ('siem-health-current', 'siem-health-transitions-*', 'siem-health-episodes-*', 'siem-health-metrics-*')}
    check('its indices are published', docs['siem-health-current'] > 0 and docs['siem-health-transitions-*'] > 0, str(docs))
    explained = api('/_plugins/_ism/explain/siem-health-*?size=20')
    check('each dated index has its policy', all(v.get('policy_id') for k, v in explained.items() if k.startswith('siem-health-') and k != 'siem-health-current'), str([k for k in explained if k.startswith('siem-')]))
    print('INFO ingest p95 seconds', {k: metrics.get(k, {}).get('value') for k in ('windows_latency_p50_seconds', 'windows_latency_p95_seconds', 'linux_latency_p50_seconds', 'linux_latency_p95_seconds', 'alert_delay_seconds', 'enrichment_delay_seconds')})


def security():
    shown = run('systemctl', 'show', 'siem-health', '--property=User,NoNewPrivileges,ProtectSystem,CapabilityBoundingSet,MemoryMax,AmbientCapabilities').stdout
    check('it runs as its own account', 'User=siem-health' in shown)
    check('it can gain no privilege', 'NoNewPrivileges=yes' in shown and 'ProtectSystem=strict' in shown)
    check('it holds no capability', 'CapabilityBoundingSet=\n' in shown or 'CapabilityBoundingSet=' in shown and 'cap_' not in shown)
    check('memory limit is 128 MiB', 'MemoryMax=134217728' in shown)
    groups = run('id', '-nG', 'siem-health').stdout.split()
    check('it belongs to no privileged group', set(groups) == {'siem-health', 'linux'}, str(groups))

    files = run('find', '/home/linux/siem', '-xdev', '(', '-iname', '*key*', '-o', '-iname', '*.pem', '-o', '-iname', '*secret*', '-o', '-iname', 'opensearch-*.json', '-o', '-name', '*.curl', '-o', '-name', 'agent.env', ')', '-type', 'f', timeout=120).stdout.split()
    readable = [f for f in files if as_monitor('test', '-r', f).returncode == 0 and not f.endswith(('ca.pem', '/health/opensearch-health.json'))]
    check('no key or other service login is readable', not readable, f'{len(files)} files tried, readable: {readable}')
    for path in ('/home/linux/siem/data/detector/state.db', '/home/linux/siem/data/correlation/correlator.db', '/home/linux/siem/data/enrichment/enricher.db', '/home/linux/siem/data/asset/asset.db', '/home/linux/siem/data/path/path.db', '/home/linux/siem/data/verifier', '/home/linux/siem/data/vector', '/home/linux/siem/data/kafka', '/root/.siem/opensearch-admin.curl'):
        check(f'{path} is closed to it', as_monitor('test', '-r', path).returncode != 0)
    check('it can read service reports', as_monitor('test', '-r', '/home/linux/siem/data/status/detector/detector.json').returncode == 0)
    check('it cannot forge a service report', as_monitor('touch', '/home/linux/siem/data/status/detector/detector.json').returncode != 0)
    check('another service cannot forge one', run('runuser', '-u', 'siem-detector', '--', 'touch', '/home/linux/siem/data/status/correlator/forged').returncode != 0)
    check('another account cannot read one', run('runuser', '-u', 'siem-path', '--', 'test', '-r', '/home/linux/siem/data/status/detector/detector.json').returncode != 0)
    for name in ('siem-correlator', 'siem-asset', 'siem-path'):
        code = ('import socket,sys\ns=socket.socket(socket.AF_UNIX)\ntry:\n s.connect(sys.argv[1]);print("open")\nexcept OSError:\n print("closed")')
        check(f'the {name} socket is closed to it', as_monitor('python3', '-c', code, f'/run/{name}/control.sock').stdout.strip() == 'closed')
    before = run('systemctl', 'show', 'siem-detector', '--property=MainPID', '--value').stdout
    tried = as_monitor('systemctl', 'restart', '--no-ask-password', 'siem-detector')
    check('it cannot restart a service', tried.returncode != 0 and run('systemctl', 'show', 'siem-detector', '--property=MainPID', '--value').stdout == before)

    status, body = as_service('/_cluster/health')
    check('it can read cluster health', status == '200')
    status, body = as_service('/siem-windows-*/_search', 'POST', {'size': 30, 'sort': [{'@timestamp': 'desc'}]})
    hits = json.loads(body)['hits']['hits']
    keys = set()
    for hit in hits:
        for key, value in hit['_source'].items():
            keys |= {f'{key}.{k}' for k in value} if isinstance(value, dict) else {key}
    check('events show it three fields and no more', hits and keys <= {'@timestamp', 'event.ingested', 'event.dataset'}, str(sorted(keys)))
    for field in ('message', 'process.command_line', 'user.name', 'host.name'):
        status, body = as_service('/siem-windows-*/_count', 'POST', {'query': {'exists': {'field': field}}})
        check(f'{field} cannot be matched on either', json.loads(body).get('count') == 0)
    for label, route, method, payload in (
            ('write an alert', '/siem-alerts-2026.11/_doc/healthtest', 'PUT', {'x': 1}), ('write an incident', '/siem-incidents-2026.11/_doc/healthtest', 'PUT', {'x': 1}), ('write an asset', '/siem-assets-current/_doc/healthtest', 'PUT', {'x': 1}),
            ('write a path', '/siem-attack-paths-2026.11/_doc/healthtest', 'PUT', {'x': 1}), ('write an event', '/siem-windows-2026.11.01/_doc/healthtest', 'PUT', {'x': 1}), ('delete an index', '/siem-alerts-2026.11', 'DELETE', None),
            ('read incidents', '/siem-incidents-*/_search', 'POST', {'size': 1}), ('read assets', '/siem-assets-current/_search', 'POST', {'size': 1}), ('read paths', '/siem-attack-paths-*/_search', 'POST', {'size': 1}),
            ('read dead letters', '/siem-deadletter-*/_search', 'POST', {'size': 1}), ('read the audit log', '/security-auditlog-*/_search', 'POST', {'size': 1}), ('change a policy', '/_plugins/_ism/policies/siem-retention', 'DELETE', None),
            ('change cluster settings', '/_cluster/settings', 'PUT', {'persistent': {'action.destructive_requires_name': True}}), ('read the security API', '/_plugins/_security/api/internalusers', 'GET', None), ('change a mapping', '/siem-windows-2026.11.01/_mapping', 'PUT', {'properties': {'x': {'type': 'keyword'}}})):
        status, _ = as_service(route, method, payload)
        check(f'it cannot {label}', status in ('401', '403'), status)

    password = json.load(open(LOGIN))['password']
    blob = open(DB, 'rb').read()
    log = run('journalctl', '-u', 'siem-health', '--no-pager', '-q', '-o', 'cat').stdout
    check('its login is in no state or log', password.encode() not in blob and password not in log)
    check('its login is not in a command line', not [p for p in os.listdir('/proc') if p.isdigit() and os.path.exists(f'/proc/{p}/cmdline') and password.encode() in open(f'/proc/{p}/cmdline', 'rb').read()])
    stat = os.stat(LOGIN)
    check('its login is closed to others', oct(stat.st_mode)[-3:] == '640')
    machine = open('/etc/machine-id').read().strip()
    words = [socket.gethostname(), t.HOST.upper(), t.WINDOWS_USER, machine] + run('hostname', '-I').stdout.split()
    documents = api('/siem-health-*/_search', 'POST', {'size': 500})['hits']['hits']
    text = json.dumps(health('components')) + json.dumps(documents)
    check('no host name, account, machine ID or address in any output or document', not [w for w in words if w and w in text], f'{len(documents)} documents')
    check('no event text in its state', not re.search(rb'CommandLine|command_line|ScriptBlock', blob))


def wait_for(expected, limit, label):
    started = time.time()
    while time.time() - started < limit:
        rows = health('components')
        if isinstance(rows, dict) and '_error' not in rows and all(rows.get(n, {}).get('status') == s and (c is None or rows[n].get('condition') == c) for n, (s, c) in expected.items()):
            return int(time.time() - started)
        time.sleep(8)
    rows = health('components')
    print('INFO unmet', label, {n: (rows.get(n, {}).get('status'), rows.get(n, {}).get('condition')) for n in expected})
    return None


def recovered(names, limit=420):
    return wait_for({n: ('HEALTHY', None) for n in names}, limit, 'recovery')


def fault(label, units, expected, cause, extra=None):
    print(f'--- {label}', flush=True)
    before = restarts()
    run('systemctl', 'stop', *units, timeout=120)
    found = wait_for(expected, 300, label)
    check(f'{label}: seen', found is not None, f'{found} s')
    view = health('overview')
    check(f'{label}: root cause named', view['root_cause'] == cause, f"bottleneck {view['bottleneck']}, cause {view['root_cause']}, overall {view['overall']}, coverage {view['coverage']}")
    check(f'{label}: coverage is not called trusted', view['coverage'] != 'trusted', view['coverage'])
    if extra:
        extra()
    run('systemctl', 'start', *units, timeout=180)
    wait(lambda: active(CORE), 240, 'the units')
    back = recovered(list(expected), 720)
    check(f'{label}: recovery seen', back is not None, f'{back} s')
    check(f'{label}: nothing else restarted', all(restarts()[u] == before[u] for u in CORE if u not in units), '')
    drained = wait(lambda: (health('lag')['lag'].get('raw_lag_messages') or {'value': 99999})['value'] < 5000, 240, 'the raw backlog')
    check(f'{label}: backlog drained', bool(drained))
    # The next fault must start clean, or its blame belongs partly to this one.
    settled = wait(lambda: health('overview')['overall'] == 'HEALTHY', 900, 'overall health')
    check(f'{label}: the whole pipeline is healthy again', bool(settled), health('overview')['overall'])
    return found, back


def faults():
    t0 = time.time()
    # A process alive to systemd, and doing nothing.
    print('--- detector frozen, systemd still says active', flush=True)
    pid = int(run('systemctl', 'show', 'siem-detector', '--property=MainPID', '--value').stdout)
    os.kill(pid, signal.SIGSTOP)
    try:
        unseen = wait_for({'detector': ('UNKNOWN', 'monitoring_unavailable')}, 300, 'frozen, first stage')
        check('frozen detector: first shown as unknown, because its report only stopped', unseen is not None, f'{unseen} s')
        hung = wait_for({'detector': ('DEGRADED', 'not_processing')}, 660, 'frozen, second stage')
        check('frozen detector: then shown as running but not processing, while systemd says active', hung is not None and run('systemctl', 'is-active', 'siem-detector').stdout.strip() == 'active', f'{hung} s more')
    finally:
        os.kill(pid, signal.SIGCONT)
    check('frozen detector: recovers', recovered(['detector']) is not None)

    def still_ingesting():
        first = vector_received()
        time.sleep(90)
        check('ingestion continues with analysis stopped', vector_received() > first, f'{int(vector_received() - first)} events in 90 s')

    fault('analysis services stopped', ['siem-path', 'siem-asset', 'siem-enricher', 'siem-correlator', 'siem-detector'],
          {n: ('UNHEALTHY', 'service_unavailable') for n in ('attack-paths', 'assets', 'enricher', 'correlator', 'detector')}, 'detector', still_ingesting)

    def other_platform():
        check('Linux agent stopped: Windows collection is still healthy', component('windows-agent')['status'] == 'HEALTHY')
    fault('Linux agent stopped', ['siem-linux-agent'], {'linux-agent': ('UNHEALTHY', 'service_unavailable'), 'source:linux.system': ('UNHEALTHY', 'source_unavailable')}, 'linux-agent', other_platform)
    fault('verifier stopped', ['seal-verifier'], {'verifier': ('UNHEALTHY', 'service_unavailable')}, 'verifier')

    def unjudged():
        check('aggregator stopped: normalization is unknown and not failed', wait_for({'normalization': ('UNKNOWN', None)}, 180, 'normalization') is not None)
    fault('aggregator stopped', ['vector'], {'aggregator': ('UNHEALTHY', 'service_unavailable')}, 'aggregator', unjudged)

    def kafka_blame():
        wait_for({'correlator': ('DEGRADED', 'downstream_unavailable')}, 240, 'correlator blames Kafka')
        check('Kafka stopped: correlator blames Kafka and not itself', component('correlator')['condition'] == 'downstream_unavailable')
    fault('Kafka stopped', ['kafka'], {'kafka': ('UNHEALTHY', 'service_unavailable')}, 'kafka', kafka_blame)

    def storage_gone():
        wait_for({'source:windows.sysmon': ('UNKNOWN', 'monitoring_unavailable')}, 300, 'freshness unknown')
        check('OpenSearch stopped: freshness becomes unknown, and is not called stale', component('source:windows.sysmon')['status'] == 'UNKNOWN')
        check('OpenSearch stopped: the command still answers', 'overall' in health('overview'))
        check('OpenSearch stopped: history waits locally', health('resources')['store_rows']['outbox'] > 0)
    fault('OpenSearch stopped', ['opensearch'], {'opensearch': ('UNHEALTHY', 'service_unavailable'), 'detector': ('DEGRADED', 'downstream_unavailable')}, 'opensearch', storage_gone)
    check('published history catches up', bool(wait(lambda: health('resources')['store_rows']['outbox'] == 0 or health('resources')['self']['ship_state'] == 'ok', 600, 'the outbox')))

    print('--- forged and stale Windows reports', flush=True)
    original = open(WINDOWS_REPORT, encoding='utf-8').read()
    forged = json.loads(original)
    try:
        forged.update(service='Stopped', checked_ms=int(time.time() * 1000) + 7200000)
        with open(WINDOWS_REPORT, 'w', encoding='utf-8') as handle:
            json.dump(forged, handle)
        time.sleep(150)
        row = component('windows-agent')
        check('a report dated in the future is not believed', row['status'] == 'HEALTHY' and any('future' in m for m in row['missing']), str(row['missing']))
    finally:
        with open(WINDOWS_REPORT, 'w', encoding='utf-8') as handle:
            handle.write(original)
    check('the whole pipeline returns to healthy', bool(wait(lambda: health('overview')['overall'] == 'HEALTHY', 420, 'overall')), health('overview')['overall'])
    print(f'INFO faults took {int(time.time() - t0)} s')
    episodes = health('failures', '--days', '1')
    print('INFO open episodes', [e['component'] for e in episodes['open']], 'recent', len(episodes['recent']))


def resilience():
    before = restarts()
    first = health('validate')['size']
    pid = run('systemctl', 'show', 'siem-health', '--property=MainPID', '--value').stdout.strip()
    start = vector_received()
    watermark = json.load(open('/home/linux/siem/data/detector/detector.json'))
    os.kill(int(pid), signal.SIGKILL)
    check('it restarts by itself after a crash', bool(wait(lambda: run('systemctl', 'show', 'siem-health', '--property=MainPID', '--value').stdout.strip() not in ('0', pid), 90, 'restart')))
    time.sleep(70)
    check('state survived the crash', health('validate')['size']['transitions'] >= first['transitions'] and health('validate').get('ok') is True)

    run('systemctl', 'stop', 'siem-health')
    run('systemctl', 'start', 'siem-health-watchdog.service', timeout=60)
    report = json.load(open(os.path.join(t.MONITOR, 'health-watchdog.json')))
    check('the watchdog reports a stopped monitor', report['status'] == 'WARN' and 'not being observed' in report['message'], report['message'])
    time.sleep(200)
    view = health('overview')
    check('the command says the picture is not current', view['overall'] == 'UNKNOWN' and view['monitor_current'] is False and view['coverage'] == 'unknown', f"stored {view['stored_overall']}")
    check('validate fails while it is stopped', health('validate').get('_code', 0) == 1 or health('validate').get('ok') is False)
    check('ingestion went on without it', vector_received() > start, f'{int(vector_received() - start)} events')
    later = json.load(open('/home/linux/siem/data/detector/detector.json'))
    check('detection went on without it', max(r['watermark_ms'] for r in later['rules']) > max(r['watermark_ms'] for r in watermark['rules']))
    check('all core services stayed up, and none restarted', active(CORE) and restarts() == before)
    run('systemctl', 'start', 'siem-health')
    time.sleep(130)
    gaps = [g for g in health('history', 'monitoring', '--days', '1') if g.get('gap') == 'monitor_restarted']
    check('the gap is on record', bool(gaps), f"{gaps[0]['seconds']} s" if gaps else '')
    run('systemctl', 'start', 'siem-health-watchdog.service', timeout=60)
    report = json.load(open(os.path.join(t.MONITOR, 'health-watchdog.json')))
    check('the watchdog reports recovery', report['status'] == 'OK', report['message'])
    check('history is intact after all of it', health('validate').get('ok') is True, str(health('validate')['size']))


def counters():
    shown = run('systemctl', 'show', 'siem-health', '--property=CPUUsageNSec,MemoryCurrent,MemoryPeak').stdout
    return dict(line.split('=') for line in shown.split())


def ingest_window(seconds):
    first, began = vector_received(), time.time()
    time.sleep(seconds)
    rate = (vector_received() - first) / (time.time() - began)
    found = api('/siem-windows-*,siem-linux-*/_search', 'POST', {'size': 200, 'sort': [{'event.ingested': 'desc'}], '_source': ['@timestamp', 'event.ingested']})['hits']['hits']
    gaps = []
    for hit in found:
        one, two = hit['_source'].get('@timestamp'), hit['_source'].get('event', {}).get('ingested')
        if one and two:
            gaps.append((time.mktime(time.strptime(two[:19], '%Y-%m-%dT%H:%M:%S')) - time.mktime(time.strptime(one[:19], '%Y-%m-%dT%H:%M:%S'))))
    gaps.sort()
    return round(rate, 2), gaps[len(gaps) // 2], gaps[int(len(gaps) * 0.95)]


def measure():
    print('memory, MiB:', int(counters()['MemoryCurrent']) // 2 ** 20, 'peak', int(counters().get('MemoryPeak', 0) or 0) // 2 ** 20)
    first, began = int(counters()['CPUUsageNSec']), time.time()
    with_monitor = ingest_window(300)
    spent = (int(counters()['CPUUsageNSec']) - first) / 1e9
    print(f'CPU: {spent:.2f} s over {time.time() - began:.0f} s, {100 * spent / (time.time() - began):.3f}% of one core')
    print('with the monitor: events/s, latency p50, p95 s', with_monitor)
    run('systemctl', 'stop', 'siem-health')
    print('without it:       events/s, latency p50, p95 s', ingest_window(300))
    run('systemctl', 'start', 'siem-health')
    print('again with it:    events/s, latency p50, p95 s', ingest_window(180))
    points = [v for _, v in health('metrics', 'monitor_cycle_ms', '--hours', '4')['points']]
    if points:
        print(f'cycle ms: mean {sum(points) / len(points):.0f}, max {max(points):.0f}, over {len(points)} cycles')
    print('state file bytes', os.path.getsize(DB), 'rows', health('resources')['store_rows'])
    for name in ('siem-health-*',):
        print('indices', [(r['index'], r['docs.count'], r['store.size']) for r in api(f'/_cat/indices/{name}?format=json&h=index,docs.count,store.size')])
    print(run('free', '-m').stdout.splitlines()[1])


if __name__ == '__main__':
    stage = sys.argv[1]
    {'real': real, 'security': security, 'faults': faults, 'resilience': resilience, 'measure': measure}[stage]()
    print(f'{stage}: {len(t.failures)} failed' + (f': {t.failures}' if t.failures else ''))
    sys.exit(1 if t.failures else 0)
