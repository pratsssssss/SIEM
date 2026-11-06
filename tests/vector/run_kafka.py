"""Kafka and OpenSearch tests: expiry, delivery metrics, real indexing and outages. Fake events only.

It uses real Kafka and OpenSearch, real Vector, the real agent and aggregator logic and the real
seal verifier. Run it only before the agent ships real events: it resets the consumer group, and
stops OpenSearch and Kafka. The real verifier and aggregator services must be stopped first.

Usage, as root: python3 tests/vector/run_kafka.py <vector> <seal-verifier> <verifier-pki> <out dir>
"""
import base64
import hashlib
import hmac
import json
import pathlib
import re
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
AGENT = yaml.safe_load((ROOT / 'config/windows/vector/vector-agent.yaml').read_text(encoding='utf8'))
AGG = yaml.safe_load((ROOT / 'config/wsl/vector/vector-aggregator.yaml').read_text(encoding='utf8'))
CHECK = ROOT / 'deploy/wsl/siem-kafka-expiry-check.py'
K = '/opt/kafka/bin'
BOOT = '127.0.0.1:9092'
ENV = {'JAVA_HOME': '/usr/lib/jvm/java-17-openjdk-amd64', 'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'KAFKA_HEAP_OPTS': '-Xmx128m'}
failures = []


def check(name, ok, detail=''):
    print(('PASS ' if ok else 'FAIL ') + name + (f' ({detail})' if detail != '' else ''), flush=True)
    if not ok:
        failures.append(name)


def sh(*command, stdin=None, ok=True):
    done = subprocess.run(command, input=stdin, capture_output=True, text=True, env=ENV, timeout=180)
    if ok and done.returncode:
        raise SystemExit(f'{command[0]} exited {done.returncode}: {done.stderr[-300:]}')
    return done.stdout


def topic(name, **config):
    options = [x for k, v in config.items() for x in ('--config', f"{k.replace('_', '.')}={v}")]
    sh(f'{K}/kafka-topics.sh', '--bootstrap-server', BOOT, '--create', '--if-not-exists', '--topic', name, '--partitions', '1', '--replication-factor', '1', *options)


def end_offset(name):
    return sum(int(x) for x in re.findall(r':(\d+)$', sh(f'{K}/kafka-get-offsets.sh', '--bootstrap-server', BOOT, '--topic', name), re.M))


def wait_port(port):
    for _ in range(150):
        try:
            socket.create_connection(('127.0.0.1', port), 1).close()
            return
        except OSError:
            time.sleep(.1)
    raise SystemExit(f'port {port} did not open')


def run_check(name, group, state):
    command = ['python3', str(CHECK), '--topic', name, '--group', group, '--state-dir', str(state)] + PUBLISH
    done = subprocess.run(command, capture_output=True, text=True, env=ENV, timeout=180)
    report = json.loads((state / 'kafka-expiry.json').read_text())
    return done.returncode, report


PUBLISH = []


def expiry(out):
    """Short retention stands in for 72 hours. The broker checks retention every five minutes."""
    name = f'expiry-test-{secrets.token_hex(3)}'
    group = f'expiry-group-{secrets.token_hex(3)}'
    retention = 240000
    topic(name, retention_ms=retention, segment_ms=15000, file_delete_delay_ms=0)
    state = pathlib.Path(tempfile.mkdtemp())
    lines = '\n'.join(f'fake-{i}' for i in range(100)) + '\n'

    # Nothing in the topic.
    code, report = run_check(name, group, state)
    check('expiry: empty topic is OK', code == 0, report['message'])

    sh(f'{K}/kafka-console-producer.sh', '--bootstrap-server', BOOT, '--topic', name, stdin=lines)
    sh(f'{K}/kafka-console-consumer.sh', '--bootstrap-server', BOOT, '--topic', name, '--group', group, '--from-beginning', '--max-messages', '30', '--timeout-ms', '20000', ok=False)
    # The next record rolls the old segment once it is eligible.
    timeline = []
    start = time.time()
    seen = set()
    while time.time() - start < 720:
        code, report = run_check(name, group, state)
        timeline.append((int(time.time() - start), report['status'], report.get('unread'), report.get('oldest_unread_age_ms')))
        seen.add(report['status'])
        print(f"  t={timeline[-1][0]:>4}s {report['status']:<9} {report.get('message')}", flush=True)
        if report['status'] == 'LOST':
            break
        sh(f'{K}/kafka-console-producer.sh', '--bootstrap-server', BOOT, '--topic', name, stdin='tick\n')
        time.sleep(30)
    check('expiry: unread events raise WARN', 'WARN' in seen)
    check('expiry: unread events raise CRITICAL before they expire', 'CRITICAL' in seen)
    check('expiry: expiry is reported as LOST', 'LOST' in seen)
    check('expiry: exit status 3 at LOST', code == 3, code)
    lost = report.get('lost_latched', {})
    total = sum(v['lost'] for v in lost.values())
    check('expiry: the 70 unread events are counted', total >= 70, total)

    # The consumer jumps past the gap, as auto_offset_reset does. The evidence must survive that.
    sh(f'{K}/kafka-console-consumer.sh', '--bootstrap-server', BOOT, '--topic', name, '--group', group, '--from-beginning', '--max-messages', '500', '--timeout-ms', '10000', ok=False)
    code, report = run_check(name, group, state)
    check('expiry: LOST survives the consumer moving on', code == 3 and report['unread'] == 0, report['message'])
    (out / 'expiry-timeline.json').write_text(json.dumps(timeline))

    # A check that cannot run must not look healthy.
    done = subprocess.run(['python3', str(CHECK), '--topic', name, '--group', group, '--state-dir', str(state), '--bootstrap', '127.0.0.1:1'] + PUBLISH,
                          capture_output=True, text=True, env={**ENV, 'KAFKA_OPTS': ''}, timeout=170)
    check('expiry: unreachable broker is CHECK_FAILED, not OK', done.returncode == 4, done.returncode)
    if PUBLISH:
        print('  CHECK_FAILED published', flush=True)
        time.sleep(45)
        calm = f'calm-{secrets.token_hex(3)}'
        topic(calm)
        code, report = run_check(calm, f'{calm}-group', pathlib.Path(tempfile.mkdtemp()))
        check('expiry: healthy state published after the failure', code == 0, report['message'])
        time.sleep(45)


def metrics(port):
    return urllib.request.urlopen(f'http://127.0.0.1:{port}/metrics', timeout=5).read().decode()


def metric(text, name, sink='kafka_raw'):
    pattern = rf'^{name}\{{(.*)\}} (\S+)(?: \d+)?$'
    return sum(float(v) for labels, v in re.findall(pattern, text, re.M) if f'component_id="{sink}"' in labels)


SENT, RECEIVED, BUFFERED = 'vector_component_sent_events_total', 'vector_component_received_events_total', 'vector_buffer_size_events'


def agent_config(work, topic_name, count):
    sink = json.loads(json.dumps(AGENT['sinks']['kafka_raw']))
    sink.update(inputs=['d'], topic=topic_name)
    sink.pop('key_field')
    sink['buffer']['max_size'] = 268435488
    return {'data_dir': str(work), 'sources': {'d': {'type': 'demo_logs', 'format': 'json', 'count': count, 'interval': 0.01},
                                               'm': {'type': 'internal_metrics', 'scrape_interval_secs': 1}},
            'sinks': {'kafka_raw': sink, 'p': {'type': 'prometheus_exporter', 'inputs': ['m'], 'address': '127.0.0.1:19598'}}}


def launch(vector, topic_name, count):
    work = pathlib.Path(tempfile.mkdtemp())
    path = work / 'agent.json'
    path.write_text(json.dumps(agent_config(work, topic_name, count)))
    proc = subprocess.Popen([vector, '--config', str(path), '--quiet'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    wait_port(19598)
    return proc


def stop(proc):
    proc.terminate()
    proc.wait(30)


def drained(count):
    text = ''
    for _ in range(90):
        text = metrics(19598)
        if metric(text, SENT) >= count and metric(text, BUFFERED) == 0:
            break
        time.sleep(1)
    return text


def delivery(vector, out):
    """Real sink settings. Each snapshot also goes to the real Windows check script."""
    # The broker answers, and refuses every message.
    topic('refuse-test', max_message_bytes=10)
    proc = launch(vector, 'refuse-test', 300)
    time.sleep(20)
    text = metrics(19598)
    (out / 'metrics-refused.txt').write_text(text)
    stop(proc)
    sent, received = metric(text, SENT), metric(text, RECEIVED)
    check('delivery: broker refuses, sent stays 0', sent == 0 and received == 300, f'received {received}, sent {sent}')
    check('delivery: broker refuses, errors are counted', metric(text, 'vector_component_errors_total') > 0, metric(text, 'vector_component_errors_total'))
    check('delivery: broker refuses, nothing reached the log', end_offset('refuse-test') == 0, end_offset('refuse-test'))

    # The broker keeps its connections and answers nothing.
    topic('frozen-test')
    main_pid = sh('systemctl', 'show', '-p', 'MainPID', '--value', 'kafka').strip()
    proc = launch(vector, 'frozen-test', 300)
    time.sleep(2)
    subprocess.run(['kill', '-STOP', main_pid], check=True)
    try:
        time.sleep(1)
        before = metric(metrics(19598), SENT)
        time.sleep(15)
        text = metrics(19598)
    finally:
        subprocess.run(['kill', '-CONT', main_pid], check=True)
    (out / 'metrics-frozen.txt').write_text(text)
    check('delivery: frozen broker, sent does not move', metric(text, SENT) == before and metric(text, RECEIVED) == 300, f'{before} then {metric(text, SENT)}')
    text = drained(300)
    stop(proc)
    check('delivery: frozen broker recovers, sent matches Kafka', metric(text, SENT) == 300 and end_offset('frozen-test') >= 300, f"sent {metric(text, SENT)}, Kafka {end_offset('frozen-test')}")

    # The broker is down, then back.
    subprocess.run(['systemctl', 'stop', 'kafka'], check=True)
    proc = launch(vector, 'delivery-test', 500)
    time.sleep(20)
    text = metrics(19598)
    (out / 'metrics-down.txt').write_text(text)
    sent, buffered = metric(text, SENT), metric(text, BUFFERED)
    check('delivery: Kafka down, sent stays 0 and events wait in the buffer', sent == 0 and buffered >= 400, f'sent {sent}, buffered {buffered}')
    subprocess.run(['systemctl', 'start', 'kafka'], check=True)
    topic('delivery-test')
    text = drained(500)
    (out / 'metrics-up.txt').write_text(text)
    sent = metric(text, SENT)
    offset = end_offset('delivery-test')
    stop(proc)
    check('delivery: after recovery sent matches what Kafka holds', sent == 500 and offset >= 500, f'sent {sent}, Kafka {offset}')


class Stack:
    """The real aggregator configuration and real verifier against real Kafka and OpenSearch."""

    def __init__(self, vector, verifier, pki):
        self.vector, self.verifier = vector, verifier
        self.work = pathlib.Path(tempfile.mkdtemp())
        self.keys = {'k1_enc': secrets.token_hex(32), 'k1_mac': secrets.token_hex(32)}
        (self.work / 'keys.json').write_text(json.dumps(self.keys))
        (self.work / 'keys.json').chmod(0o600)
        subprocess.run([pki, '-out', str(self.work / 'tls')], check=True)
        self.tls = str(self.work / 'tls')
        self.proc_verifier = self.proc_vector = None
        self.credentials = json.loads(pathlib.Path('/home/linux/siem/config/vector/opensearch-ingest.json').read_text())
        self.context = ssl.create_default_context(cafile='/etc/opensearch/root-ca.pem')
        self.context.check_hostname = False
        self.admin_curl = '/root/.siem/opensearch-admin.curl'

    def start_verifier(self):
        t = self.tls
        self.proc_verifier = subprocess.Popen([self.verifier, '-keys', str(self.work / 'keys.json'), '-identity-dir', str(self.work / 'journal'), '-server-cert', f'{t}/verifier.crt', '-server-key', f'{t}/verifier.key',
                                               '-client-ca', f'{t}/vector-ca.crt', '-down-cert', f'{t}/verifier.crt', '-down-key', f'{t}/verifier.key', '-down-ca', f'{t}/vector-ca.crt'],
                                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        wait_port(9612)

    def stop_verifier(self):
        self.proc_verifier.terminate()
        self.proc_verifier.wait(10)
        for _ in range(50):
            try:
                socket.create_connection(('127.0.0.1', 9612), .2).close()
                time.sleep(.1)
            except OSError:
                return

    def start_vector(self):
        config = json.loads(json.dumps(AGG))
        config['data_dir'] = str(self.work)
        t = self.tls
        config['sources']['from_verifier']['tls'].update(crt_file=f'{t}/vector.crt', key_file=f'{t}/vector.key', ca_file=f'{t}/verifier-ca.crt')
        config['sinks']['to_verifier']['tls'].update(ca_file=f'{t}/verifier-ca.crt', crt_file=f'{t}/vector.crt', key_file=f'{t}/vector.key')
        for sink in ('opensearch_events', 'opensearch_dead'):
            config['sinks'][sink]['tls']['ca_file'] = '/etc/opensearch/root-ca.pem'
        path = self.work / 'aggregator.json'
        path.write_text(json.dumps(config))
        self.proc_vector = subprocess.Popen([self.vector, '--config', str(path), '--quiet'], stdout=subprocess.DEVNULL, stderr=open(self.work / 'vector.log', 'ab'))
        wait_port(9599)

    def stop_vector(self):
        """Returns the seconds a clean stop took, or None if it had to be killed."""
        self.proc_vector.terminate()
        began = time.time()
        try:
            self.proc_vector.wait(20)
            return round(time.time() - began, 1)
        except subprocess.TimeoutExpired:
            self.proc_vector.kill()
            self.proc_vector.wait(10)
            return None

    def admin(self, path, *extra):
        return sh('curl', '-sS', '--cacert', '/etc/opensearch/root-ca.pem', '-K', self.admin_curl, *extra, f'https://127.0.0.1:9200{path}')

    def count(self, pattern):
        self.admin(f'/{pattern}/_refresh', '-X', 'POST')
        return json.loads(self.admin(f'/{pattern}/_count')).get('count', 0)

    def ingest(self, method, path, body=None):
        request = urllib.request.Request(f'https://127.0.0.1:9200{path}', data=body, method=method, headers={'Content-Type': 'application/json'})
        token = base64.b64encode(f"{self.credentials['user']}:{self.credentials['password']}".encode()).decode()
        request.add_header('Authorization', f'Basic {token}')
        try:
            return urllib.request.urlopen(request, context=self.context, timeout=10).status
        except urllib.error.HTTPError as error:
            return error.code

    def seal(self, events):
        (self.work / 'agent.ndjson').unlink(missing_ok=True)
        names = ('protect', 'protect_failed', 'envelope', 'envelope_failed')
        config = {'data_dir': str(self.work), 'secret': {'field_keys': {'type': 'file', 'path': str(self.work / 'keys.json')}},
                  'sources': {'win_in': {'type': 'stdin', 'decoding': {'codec': 'json'}}},
                  'transforms': {k: AGENT['transforms'][k] for k in names},
                  'sinks': {'out': {'type': 'file', 'inputs': ['envelope', 'envelope_failed'], 'path': str(self.work / 'agent.ndjson'), 'encoding': {'codec': 'json'}}}}
        path = self.work / 'agent.json'
        path.write_text(json.dumps(config))
        subprocess.run([self.vector, '--config', str(path), '--quiet'], input='\n'.join(json.dumps(e) for e in events) + '\n', text=True, check=True, timeout=120, capture_output=True)
        return [json.loads(l) for l in (self.work / 'agent.ndjson').read_text().splitlines()]

    def sign(self, event):
        body = json.dumps(event, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
        mac = hmac.new(bytes.fromhex(self.keys['k1_mac']), f'siem-event-v1|k1|{body}'.encode(), hashlib.sha256).digest()
        return json.dumps({'v': 'siem-event-v1', 'k': 'k1', 'event_uid': event['event_uid'], 'body': body, 'mac': base64.b64encode(mac).decode()})

    def produce(self, lines):
        sh(f'{K}/kafka-console-producer.sh', '--bootstrap-server', BOOT, '--topic', TOPIC, stdin='\n'.join(lines) + '\n')

    def lag(self):
        text = sh(f'{K}/kafka-consumer-groups.sh', '--bootstrap-server', BOOT, '--describe', '--group', 'siem-aggregator', ok=False)
        return sum(int(x) for x in re.findall(rf'{TOPIC}\s+\d+\s+\S+\s+\S+\s+(\d+)', text))

    def settle(self, pattern, target, seconds=120):
        for _ in range(seconds // 2):
            if self.count(pattern) >= target and self.lag() == 0:
                return True
            time.sleep(2)
        return False

    def verifier_metric(self, result):
        text = urllib.request.urlopen('http://127.0.0.1:9612/metrics', timeout=5).read().decode()
        match = re.search(rf'result="{result}"\}} (\d+)', text)
        return int(match[1]) if match else 0

    def block(self, index, value):
        self.admin(f'/{index}/_settings', '-X', 'PUT', '-H', 'Content-Type: application/json', '-d', json.dumps({'index.blocks.write': value}))


TOPIC = 'siem-raw-logs'
SYSMON = 'Microsoft-Windows-Sysmon/Operational'
POWERSHELL = 'Microsoft-Windows-PowerShell/Operational'
WHEN = '2026-10-31T00:00:00.000Z'


def windows_event(channel, event_id, record_id, data, when=WHEN):
    return {'channel': channel, 'event_id': event_id, 'record_id': record_id, 'computer': 'HOST', 'timestamp': when, 'event_data': data}


def real(vector, verifier, pki, out):
    s = Stack(vector, verifier, pki)
    sh(f'{K}/kafka-consumer-groups.sh', '--bootstrap-server', BOOT, '--group', 'siem-aggregator', '--topic', TOPIC, '--reset-offsets', '--to-latest', '--execute', ok=False)
    s.start_verifier()
    s.start_vector()
    base_docs = s.count('siem-windows-*')
    base_dead = s.count('siem-deadletter-*')

    # Real indexing, through all of it.
    events = [windows_event(POWERSHELL, 4104, 100 + i, {'ScriptBlockText': f"$password = 'FakeSecret1'\nGet-Date {i}", 'MessageNumber': 1, 'MessageTotal': 1}) for i in range(200)]
    events += [windows_event(SYSMON, 1, 1000 + i, {'CommandLine': f'tool.exe --password=FakeSecret1 {i}', 'ParentCommandLine': 'cmd.exe', 'Image': 'C:\\t\\tool.exe', 'ProcessId': '4242', 'User': 'HOST\\bob'}) for i in range(50)]
    events += [windows_event('Security', 4624, 2000 + i, {'TargetUserName': 'bob', 'IpAddress': '192.0.2.1'}) for i in range(50)]
    events += [windows_event('Security', 4624, 3000, {'TargetUserName': 'late'}, '2026-10-31T01:00:00+05:30')]
    sealed = s.seal(events)
    bodies = {json.loads(e['body'])['record_id']: json.loads(e['body']) for e in sealed}
    s.produce([json.dumps(e) for e in sealed])
    total = base_docs + 301
    check('real: 301 events reach OpenSearch and lag reaches 0', s.settle('siem-windows-*', total), f"{s.count('siem-windows-*') - base_docs} new docs, lag {s.lag()}")
    indices = s.admin('/_cat/indices/siem-*?h=index&s=index')
    check('real: index name comes from event time in UTC', 'siem-windows-2026.10.31' in indices and 'siem-windows-2026.10.30' in indices, ' '.join(indices.split()))
    uid = bodies[1000]['event_uid']
    doc = json.loads(s.admin(f'/siem-windows-2026.10.31/_doc/{uid}'))
    source = doc.get('_source', {})
    check('real: _id and event.id are event_uid', doc.get('found') is True and source.get('event', {}).get('id') == uid)
    check('real: protected field restored and redacted, as ECS', source.get('process', {}).get('command_line') == 'tool.exe --password=[REDACTED:arg] 0', str(source.get('process', {}).get('command_line')))
    check('real: ECS fields present', source.get('process', {}).get('pid') == 4242 and source.get('user', {}).get('name') == 'bob' and source.get('event', {}).get('dataset') == 'windows.sysmon', str(sorted(source)))
    check('real: no ciphertext or helper fields stored', not {'sealed', 'siem_index', 'siem_id', 'ctx', 'path', 'channel', 'event_data'} & set(source), str(sorted(source)))
    check('real: no canary in any document', 'FakeSecret1' not in s.admin('/siem-windows-*/_search?size=400'))
    found = json.loads(s.admin('/siem-windows-*/_search?size=0&q=process.name:tool.exe'))['hits']['total']['value']
    check('real: ECS fields are searchable', found == 50, found)
    found = json.loads(s.admin('/siem-windows-*/_search?size=0&q=winlog.event_data.User:%22HOST%5C%5Cbob%22'))['hits']['total']['value']
    print(f'INFO flat_object search hits: {found}', flush=True)

    # Dead letters.
    plain = windows_event(POWERSHELL, 4104, 9, {'ScriptBlockText': 'forged'})
    plain['event_uid'] = 'c' * 64
    tampered = dict(sealed[210])
    tampered_body = json.loads(tampered['body'])
    tampered_body['event_data']['Image'] = 'C:\\evil.exe'
    tampered['body'] = json.dumps(tampered_body, sort_keys=True, separators=(',', ':'))
    s.produce([json.dumps(tampered), json.dumps(plain), '{garbage'])
    check('real: three bad messages reach the dead-letter index', s.settle('siem-deadletter-*', base_dead + 3), f"{s.count('siem-deadletter-*') - base_dead} docs, lag {s.lag()}")
    hits = json.loads(s.admin('/siem-deadletter-*/_search?size=40'))['hits']['hits']
    reasons = sorted(h['_source']['dlq']['reason'] for h in hits)
    check('real: dead-letter reasons are right', reasons == ['auth_missing', 'mac_mismatch', 'malformed_json'], str(reasons))
    text = json.dumps(hits)
    check('real: dead letters hold no plaintext or event_data', 'FakeSecret1' not in text and 'evil' not in text and 'forged' not in text and not any('event_data' in h['_source'] for h in hits))
    check('real: failed authentication keeps ciphertext', any('sealed' in h['_source'] for h in hits))
    check('real: good index unchanged by bad input', s.count('siem-windows-*') == total, s.count('siem-windows-*') - total)

    # siem_ingest.
    check('real: siem_ingest can write its own index', s.ingest('POST', '/_bulk', b'{"index":{"_index":"siem-windows-2020.01.01","_id":"probe"}}\n{"a":1}\n') == 200)
    s.admin('/siem-windows-2020.01.01', '-X', 'DELETE')
    for name, method, path, body in (('read', 'GET', '/siem-windows-*/_search', None), ('delete an index', 'DELETE', '/siem-windows-2026.10.31', None),
                                     ('read audit', 'GET', '/security-auditlog-*/_search', None), ('write another index', 'POST', '/other/_doc', b'{"a":1}'),
                                     ('change settings', 'PUT', '/_cluster/settings', b'{"transient":{"cluster.routing.allocation.enable":"all"}}')):
        code = s.ingest(method, path, body)
        check(f'real: siem_ingest cannot {name}', code == 403, code)

    # Redelivery and replay, across a restart.
    lines = [json.dumps(e) for e in sealed[:50]]
    before = s.verifier_metric('replayed')
    version = json.loads(s.admin(f"/siem-windows-2026.10.31/_doc/{bodies[100]['event_uid']}"))['_version']
    s.produce(lines)
    s.settle('siem-windows-*', total)
    time.sleep(5)
    check('real: redelivery adds no documents', s.count('siem-windows-*') == total, s.count('siem-windows-*') - total)
    check('real: redelivery is counted', s.verifier_metric('replayed') - before == 50, s.verifier_metric('replayed') - before)
    check('real: redelivery does not touch the stored document', json.loads(s.admin(f"/siem-windows-2026.10.31/_doc/{bodies[100]['event_uid']}"))['_version'] == version)

    target = bodies[1001]
    url = f"/siem-windows-2026.10.31/_doc/{target['event_uid']}"
    forged = json.loads(json.dumps(target))
    forged['event_data']['Image'] = 'C:\\evil.exe'
    s.stop_verifier()
    s.start_verifier()
    dead_now = s.count('siem-deadletter-*')
    unsigned = json.loads(s.sign(target))
    unsigned['body'] = json.dumps(forged, sort_keys=True, separators=(',', ':'))
    s.produce([json.dumps(unsigned), s.sign(forged)])
    check('replay: after a restart both changed copies dead-letter', s.settle('siem-deadletter-*', dead_now + 2), s.count('siem-deadletter-*') - dead_now)
    stored = json.loads(s.admin(url))
    check('replay: after a restart the stored document is unchanged', stored['_source'].get('process', {}).get('executable') == 'C:\\t\\tool.exe' and stored['_version'] == 1, f"version {stored['_version']}")
    hits = json.loads(s.admin('/siem-deadletter-*/_search?size=0&q=dlq.reason:replay_conflict'))['hits']['total']['value']
    check('replay: the signed change is a replay_conflict', hits == 1, hits)

    # A document OpenSearch refuses: a daily index blocked for writes.
    refused_index = 'siem-windows-2026.10.29'
    good_first = s.seal([windows_event('Security', 4624, 5000, {'TargetUserName': 'seed'}, '2026-10-29T00:00:00.000Z')])
    s.produce([json.dumps(e) for e in good_first])
    s.settle('siem-windows-*', total + 1)
    s.block(refused_index, True)
    dead_now = s.count('siem-deadletter-*')
    poison = s.seal([windows_event('Security', 4624, 5001, {'TargetUserName': 'x'}, '2026-10-29T00:00:01.000Z')])
    after = s.seal([windows_event('Security', 4624, 5002, {'TargetUserName': 'next'})])
    s.produce([json.dumps(poison[0]), json.dumps(after[0])])
    check('poison: a refused document cannot stall ingestion', s.settle('siem-windows-*', total + 2, 90), f"{s.count('siem-windows-*') - total} docs, lag {s.lag()}")
    time.sleep(3)
    check('poison: the refused document is dead-lettered', s.count('siem-deadletter-*') == dead_now + 1, s.count('siem-deadletter-*') - dead_now)
    s.block(refused_index, False)
    total += 2

    # Dead-letter storage failure must hold, never lose.
    dead_index = s.admin('/_cat/indices/siem-deadletter-*?h=index').split()[0]
    s.block(dead_index, True)
    bad = ['{garbage-2']
    s.produce(bad)
    time.sleep(15)
    held = s.lag()
    check('dead-letter failure: the pipeline holds, the offset is not committed', held >= 1, f'lag {held}')
    check('dead-letter failure: aggregator stays up', s.proc_vector.poll() is None)
    s.block(dead_index, False)
    for _ in range(45):
        if s.lag() == 0:
            break
        time.sleep(2)
    check('dead-letter failure: recovers by itself', s.lag() == 0, f'lag {s.lag()}')

    # Outages, with a real backlog.
    base = s.count('siem-windows-*')
    dead_final = s.count('siem-deadletter-*')
    s.stop_verifier()
    batch = s.seal([windows_event('Security', 4624, 6000 + i, {'TargetUserName': 'v'}) for i in range(100)])
    s.produce([json.dumps(e) for e in batch])
    time.sleep(15)
    check('outage: verifier down, nothing indexed and offsets held', s.count('siem-windows-*') == base and s.lag() == 100, f"{s.count('siem-windows-*') - base} docs, lag {s.lag()}")
    s.start_verifier()
    check('outage: verifier back, all delivered', s.settle('siem-windows-*', base + 100), f"{s.count('siem-windows-*') - base} docs, lag {s.lag()}")

    subprocess.run(['systemctl', 'stop', 'opensearch'], check=True)
    batch = s.seal([windows_event('Security', 4624, 7000 + i, {'TargetUserName': 'o'}) for i in range(100)])
    s.produce([json.dumps(e) for e in batch])
    time.sleep(20)
    held = s.lag()
    check('outage: OpenSearch down, offsets held', held == 100, f'lag {held}')
    check('outage: OpenSearch down, aggregator stays up', s.proc_vector.poll() is None)
    subprocess.run(['systemctl', 'start', 'opensearch'], check=True)
    check('outage: OpenSearch back, all delivered exactly once', s.settle('siem-windows-*', base + 200, 200) and s.count('siem-windows-*') == base + 200, f"{s.count('siem-windows-*') - base} docs, lag {s.lag()}")
    check('outage: an outage does not turn good events into dead letters', s.count('siem-deadletter-*') == dead_final, s.count('siem-deadletter-*') - dead_final)

    # Oversized and restart of the aggregator mid-flow.
    s.produce(['x' * 950000])
    s.stop_vector()
    batch = s.seal([windows_event('Security', 4624, 8000 + i, {'TargetUserName': 'a'}) for i in range(100)])
    s.produce([json.dumps(e) for e in batch])
    s.start_vector()
    check('outage: aggregator restart loses nothing', s.settle('siem-windows-*', base + 300, 120), f"{s.count('siem-windows-*') - base} docs, lag {s.lag()}")
    check('real: an oversized message dead-letters', json.loads(s.admin('/siem-deadletter-*/_search?size=0&q=dlq.reason:malformed_json'))['hits']['total']['value'] >= 2)

    print('INFO final verifier counts:', re.sub(r'\s+', ' ', urllib.request.urlopen('http://127.0.0.1:9612/metrics', timeout=5).read().decode()), flush=True)
    s.stop_vector()
    s.stop_verifier()


def main(vector, verifier, pki, out):
    global PUBLISH
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    only = sys.argv[5] if len(sys.argv) > 5 else 'all'
    if len(sys.argv) > 6:
        PUBLISH.extend(['--publish', sys.argv[6]])
    if only in ('all', 'delivery'):
        delivery(vector, out)
    if only in ('all', 'real'):
        real(vector, verifier, pki, out)
    if only in ('all', 'expiry'):
        expiry(out)
    print(f'\n{len(failures)} failed' if failures else '\nall passed', flush=True)
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main(*sys.argv[1:5]))
