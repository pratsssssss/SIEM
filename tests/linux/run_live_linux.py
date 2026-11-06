"""Live Linux telemetry tests, as root in WSL against the running stack. Prints counts and statuses, never content.

Usage: run_live_linux.py real         real activity by a temporary account, followed to detection and assets
       run_live_linux.py security     forged events, key misuse, privilege limits, hostile log text
       run_live_linux.py resilience   restarts, outages, duplicates
       run_live_linux.py mark NAME    writes a marker to the journal, for a test that ends WSL
       run_live_linux.py expect NAME  checks that marker arrived, once
       run_live_linux.py measure      memory, CPU, latency and growth

The account, its password and its crontab exist only for the test. Forged messages are synthetic and are
labelled as such in their identifiers. The activity itself is real: real programs, writing real journal entries.
"""
import base64
import glob
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
import livelib as t  # noqa: E402

check, api, wait, systemctl = t.check, t.api, t.wait, t.systemctl
# New each run: sudo alerts group by account and hour, so a repeat within the hour would add to the last.
ACCOUNT = f'siem13t{t.RUN}'
MARKERS = os.path.join(t.LAB, 'phase13', 'markers')
AGENT_KEYS = '/home/linux/siem/config/linux-agent/field-keys.json'
VERIFIER_KEYS = '/home/linux/siem/config/verifier/field-keys.json'
CHECKPOINT = '/home/linux/siem/data/linux-agent/journal/checkpoint.txt'
DIGEST_RULES = {'sudo refused': 'd3b07a10-5c1e-4f6a-9b2c-0e1f2a3b4c01', 'sudo command': 'd3b07a10-5c1e-4f6a-9b2c-0e1f2a3b4c02', 'account created': 'd3b07a10-5c1e-4f6a-9b2c-0e1f2a3b4c03', 'privileged group': 'd3b07a10-5c1e-4f6a-9b2c-0e1f2a3b4c04',
                'crontab changed': 'd3b07a10-5c1e-4f6a-9b2c-0e1f2a3b4c05', 'SIEM service failed': 'd3b07a10-5c1e-4f6a-9b2c-0e1f2a3b4c06', 'failed authentication burst': 'd3b07a10-5c1e-4f6a-9b2c-0e1f2a3b4c08'}
PACKAGE_RULE = 'd3b07a10-5c1e-4f6a-9b2c-0e1f2a3b4c07'


def run(*words, **options):
    return subprocess.run(words, capture_output=True, text=True, stdin=subprocess.DEVNULL if 'input' not in options else None, timeout=options.pop('timeout', 120), **options)


def count(query, index='siem-linux-*'):
    api(f'/{index}/_refresh', 'POST')
    return api(f'/{index}/_count', 'POST', {'query': query}).get('count', 0)


def search(query, size=50, index='siem-linux-*'):
    return [h['_source'] for h in api(f'/{index}/_search', 'POST', {'size': size, 'query': query, 'sort': [{'@timestamp': 'desc'}]}).get('hits', {}).get('hits', [])]


def since(ms):
    return {'range': {'event.ingested': {'gte': ms, 'format': 'epoch_millis'}}}


def action(name, start, **terms):
    filters = [{'term': {'event.action': name}}, since(start)] + [{'term': {k: v}} for k, v in terms.items()]
    return {'bool': {'filter': filters}}


def asset(*words):
    done = run('runuser', '-u', 'linux', '--', 'siem-asset', *words)
    return json.loads(done.stdout) if done.stdout.strip().startswith(('{', '[')) else {'_error': done.stderr, '_code': done.returncode}


def verifier():
    found = {}
    for line in subprocess.run(['curl', '-s', '127.0.0.1:9612/metrics'], capture_output=True, text=True).stdout.splitlines():
        if 'result="' in line:
            found[line.split('"')[1]] = int(line.rsplit(' ', 1)[1])
    return found


def marker(token):
    run('logger', '-t', 'siem13-marker', token)


def arrived(token):
    return count({'bool': {'filter': [{'term': {'event.provider': 'siem13-marker'}}, {'match': {'message': token}}]}})


def producer(values):
    code = "import sys\nfrom confluent_kafka import Producer\np = Producer({'bootstrap.servers': '127.0.0.1:9092'})\nfor line in sys.stdin.buffer.read().split(b'\\0'):\n    p.produce('siem-raw-logs', line)\np.flush(20)\n"
    subprocess.run(['python3', '-c', code], input=b'\0'.join(values), env={**os.environ, 'PYTHONPATH': '/opt/siem-correlator/lib'}, check=True, timeout=40)


def scan_kafka(needles, start_ms):
    """Reads what reached siem-raw-logs since the test began, and counts plain matches."""
    code = '''
import json, sys
from confluent_kafka import Consumer, TopicPartition
needles = [n.encode() for n in json.loads(sys.argv[1])]
start = int(sys.argv[2])
c = Consumer({'bootstrap.servers': '127.0.0.1:9092', 'group.id': 'siem13-scan-' + sys.argv[2], 'enable.auto.commit': False, 'auto.offset.reset': 'earliest'})
parts = [TopicPartition('siem-raw-logs', p, start) for p in c.list_topics('siem-raw-logs').topics['siem-raw-logs'].partitions]
parts = c.offsets_for_times(parts, timeout=15)
ends = {p.partition: c.get_watermark_offsets(p, timeout=15)[1] for p in parts}
c.assign([p for p in parts if p.offset >= 0])
left = {p.partition for p in parts if 0 <= p.offset < ends[p.partition]}
seen = hits = idle = 0
while left and idle < 15:
    m = c.poll(1)
    if m is None or m.error():
        idle += 1
        continue
    idle = 0
    seen += 1
    hits += sum(n in m.value() for n in needles)
    if m.offset() >= ends[m.partition()] - 1:
        left.discard(m.partition())
c.close()
print(seen, hits)
'''
    done = subprocess.run(['python3', '-c', code, json.dumps(needles), str(start_ms)], capture_output=True, text=True, env={**os.environ, 'PYTHONPATH': '/opt/siem-correlator/lib'}, timeout=180)
    seen, hits = done.stdout.split()
    return int(seen), int(hits)


def real():
    start = int(time.time() * 1000)
    password = secrets.token_urlsafe(18)
    canary = 'Canary' + secrets.token_hex(8)
    windows_before = count({'range': {'event.ingested': {'gte': 'now-2m'}}}, 'siem-windows-*')
    before = {'dead': api('/siem-deadletter-*/_count').get('count', 0)}
    try:
        check('the test account is created', run('useradd', '--create-home', '--shell', '/bin/bash', ACCOUNT).returncode == 0)
        done = subprocess.run(['chpasswd'], input=f'{ACCOUNT}:{password}\n', capture_output=True, text=True)
        check('it is given a random password', done.returncode == 0)
        check('it joins a privileged group', run('usermod', '-aG', 'sudo', ACCOUNT).returncode == 0)
        for attempt in range(6):
            subprocess.run(['runuser', '-u', ACCOUNT, '--', 'sudo', '-S', '-k', '/bin/true'], input='wrong-password\n', capture_output=True, text=True, timeout=30)
        done = subprocess.run(['runuser', '-u', ACCOUNT, '--', 'sudo', '-S', '-k', '/bin/true', f'--password={canary}'], input=password + '\n', capture_output=True, text=True, timeout=30)
        check('a real sudo command runs', done.returncode == 0, str(done.returncode))
        run('su', '-', ACCOUNT, '-c', '/bin/true')
        done = subprocess.run(['crontab', '-u', ACCOUNT, '-'], input='# synthetic test, runs nothing\n', capture_output=True, text=True)
        check('a real crontab is written', done.returncode == 0)
        run('crontab', '-u', ACCOUNT, '-r')
        run('logger', '-t', 'sudo', f' {ACCOUNT} : TTY=pts/9 ; PWD=/ ; USER=root ; COMMAND=/forged')
        run('logger', '-t', 'useradd', 'new user: name=forged13, UID=0, GID=0')
        run('systemctl', 'kill', '-s', 'SIGKILL', 'siem-asset')
        installed = run('apt-get', 'install', '-y', '--no-install-recommends', 'sl', timeout=110, env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive'}).returncode == 0
        print(f"INFO real package install {'ran' if installed else 'could not run, so the package path stays unverified live'}", flush=True)
        if installed:
            run('apt-get', 'purge', '-y', 'sl', timeout=110, env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive'})
    finally:
        run('crontab', '-u', ACCOUNT, '-r')
        removed = run('gpasswd', '-d', ACCOUNT, 'sudo').returncode == 0
        gone = False
        for _ in range(20):
            run('loginctl', 'terminate-user', ACCOUNT)
            gone = run('userdel', '--remove', ACCOUNT).returncode == 0
            if gone:
                break
            time.sleep(3)
        print(f'INFO cleanup: left sudo {removed}, removed {gone}', flush=True)
    check('the test account is gone', run('id', ACCOUNT).returncode != 0)

    # Real events, as stored.
    time.sleep(30)
    actions = {'user-created': {'user.target.name': ACCOUNT}, 'group-member-added': {'user.target.name': ACCOUNT, 'group.name': 'sudo'}, 'sudo-auth-failed': {}, 'pam-auth-failed': {}, 'sudo-command': {'user.name': ACCOUNT, 'user.effective.name': 'root'}, 'su-session': {'user.effective.name': ACCOUNT}, 'crontab-replaced': {'user.target.name': ACCOUNT}, 'crontab-deleted': {'user.target.name': ACCOUNT}, 'service-failed': {'service.name': 'siem-asset'}, 'user-deleted': {'user.target.name': ACCOUNT}}
    for name, terms in actions.items():
        found = count(action(name, start, **terms))
        check(f'real event stored and classified: {name}', found >= 1, str(found))
    item = search(action('sudo-command', start, **{'user.name': ACCOUNT}), 1)
    item = item[0] if item else {}
    check('sudo keeps the verified program', item.get('journald', {}).get('exe_verified') is True and item.get('process', {}).get('executable') == '/usr/bin/sudo')
    check('sudo keeps host identity', item.get('host', {}).get('name', '').endswith('-wsl') and len(item.get('host', {}).get('id', '')) == 32 and item.get('host', {}).get('os', {}).get('type') == 'linux')
    check('sudo keeps the source time and provenance', bool(item.get('event', {}).get('created')) and item.get('labels', {}).get('source_role') == 'wsl_infrastructure' and bool(item.get('journald', {}).get('cursor')))
    command = item.get('process', {}).get('command_line', '')
    check('the secret in the command line was redacted', canary not in json.dumps(item) and 'REDACTED' in command, 'labelled' if item.get('labels', {}).get('redactions') else 'no label')
    forged = count({'bool': {'filter': [{'term': {'event.action': 'unverified-log-entry'}}, since(start)]}})
    check('forged log lines stay unverified', forged >= 2, str(forged))
    check('a forged sudo line made no sudo event', count({'bool': {'filter': [{'term': {'process.command_line.keyword': '/forged'}}, since(start)]}}) == 0)
    check('a forged useradd line made no account event', count(action('user-created', start, **{'user.target.name': 'forged13'})) == 0)
    dumped = json.dumps(search(since(start), 500))
    check('no password in stored events', password not in dumped and canary not in dumped, 'wrong-password' not in dumped and 'clean' or 'see report')
    seen, hits = scan_kafka([password, canary, f'name={ACCOUNT}', f'USER=root'], start)
    check('Kafka held no plain text', hits == 0 and seen > 0, f'{seen} messages read')
    if installed:
        check('real package install stored', count(action('package-installed', start)) >= 1)
        check('real package removal stored', count(action('package-removed', start)) >= 1)
    check('no dead letters from any of this', api('/siem-deadletter-*/_count').get('count', 0) == before['dead'], str(before['dead']))
    check('Windows events still arrive', bool(wait(lambda: count({'range': {'event.ingested': {'gte': start, 'format': 'epoch_millis'}}}, 'siem-windows-*') > 0, 120, 'Windows events')), str(windows_before))

    # Detection.
    def fired(rule):
        api('/siem-alerts-*/_refresh', 'POST')
        return api('/siem-alerts-*/_count', 'POST', {'query': {'bool': {'filter': [{'term': {'rule_id': rule}}, {'range': {'detected_at': {'gte': start, 'format': 'epoch_millis'}}}]}}}).get('count', 0)
    for name, rule in DIGEST_RULES.items():
        check(f'rule fired on real telemetry: {name}', bool(wait(lambda: fired(rule), 420, name)), str(fired(rule)))
    if installed:
        check('rule fired on real telemetry: package installed', bool(wait(lambda: fired(PACKAGE_RULE), 420, 'package')))
    alerts = api('/siem-alerts-*/_search', 'POST', {'size': 100, 'query': {'bool': {'filter': [{'prefix': {'rule_id': 'd3b07a10'}}, {'range': {'detected_at': {'gte': start, 'format': 'epoch_millis'}}}]}}})['hits']['hits']
    forged_alerts = [a for a in alerts if 'forged' in json.dumps(a['_source'])]
    check('no alert fired from a forged line', not forged_alerts, f'{len(alerts)} Linux alerts')
    check('alerts name the Linux host', all(a['_source'].get('host', '').endswith('-wsl') for a in alerts))

    # Asset and incident.
    def linux_asset():
        return next((a for a in asset('list') if a['asset_type'] == 'siem_host'), None)
    item = linux_asset()
    check('Linux events still join one asset', item is not None and len([a for a in asset('list') if a['asset_type'] == 'siem_host']) == 1)
    report = asset('status')
    check('every event was attributed', report.get('unattributed_linux_events') == 0, str(report.get('unattributed_linux_events')))
    full = wait(lambda: (lambda v: v if f'{t.HOST}-wsl' in [x['name'] for x in v.get('identity', {}).get('aliases', [])] else None)(asset('show', item['asset_id'])), 360, 'alias')
    check('the Linux host name is an alias of the existing asset', bool(full))
    check('the Windows asset is still separate', len([a for a in asset('list') if a['platform'] == 'windows']) == 1)
    history = wait(lambda: [c for c in asset('history', item['asset_id']) if c['kind'] == 'account_created_event' and c['subject'] == ACCOUNT], 360, 'asset history')
    check('the new account reached asset history', bool(history))
    check('criticality and owner stay unset', not [x for x in full.get('administrator', []) if x['name'] in ('owner', 'criticality')] if full else False)
    def incident():
        rows = api('/siem-incidents-*/_search', 'POST', {'size': 20, 'query': {'bool': {'filter': [{'term': {'rules.id': 'cor-linux-privileged-account'}}, {'range': {'updated_at': {'gte': start, 'format': 'epoch_millis'}}}]}}}).get('hits', {}).get('hits', [])
        return rows[0]['_source'] if rows else None
    found = wait(incident, 180, 'incident')
    check('a real Linux incident forms', bool(found))
    if found:
        context = wait(lambda: (lambda c: c if c.get('assets') else None)(asset('context', '--incident', found['incident_id'])), 60, 'context')
        check('incident context names the SIEM host asset', bool(context) and context['assets'][0]['asset_id'] == item['asset_id'], (context or {}).get('live_data', ''))
        check('it is not attributed to Windows', bool(context) and context['assets'][0]['platform'] == 'linux')
        run('runuser', '-u', 'linux', '--', 'siem-incident', 'status', found['incident_id'], 'false_positive', '--note', 'controlled test of Linux telemetry')
    for change in asset('changes', '--unreviewed'):
        if change['asset_id'] == item['asset_id']:
            asset('ack', str(change['seq']), '--note', 'controlled test of Linux telemetry')
    systemctl('reset-failed', 'siem-asset')
    systemctl('start', 'siem-asset')


def envelope(key_id, mac_key, body):
    text = json.dumps(body, separators=(',', ':'), sort_keys=True)
    mac = hmac.new(mac_key, f'siem-event-v1|{key_id}|{text}'.encode(), hashlib.sha256).digest()
    return json.dumps({'v': 'siem-event-v1', 'k': key_id, 'event_uid': body['event_uid'], 'body': text, 'mac': base64.b64encode(mac).decode()}).encode()


def forged_body(channel, label):
    uid = hashlib.sha256(f'synthetic-forgery|{label}|{t.RUN}'.encode()).hexdigest()
    return {'event_uid': uid, 'channel': channel, 'event_id': 1, 'record_id': '1', 'computer': 'forged', 'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'event_data': {'Identifier': 'sudo'}}


def security():
    before = verifier()
    keys = json.load(open(VERIFIER_KEYS))
    k1, k2 = bytes.fromhex(keys['k1_mac']), bytes.fromhex(keys['k2_mac'])
    good = envelope('k2', k2, forged_body('linux-journal', 'unused'))
    wrong_mac = json.loads(good)
    wrong_mac['mac'] = base64.b64encode(b'\0' * 32).decode()
    producer([json.dumps(wrong_mac).encode(), b'not json at all', envelope('k1', k1, forged_body('linux-journal', 'windows-key')), envelope('k2', k2, forged_body('Security', 'linux-key')), envelope('k9', k2, forged_body('linux-journal', 'unknown-key'))])
    def counted():
        now = verifier()
        return {k: now.get(k, 0) - before.get(k, 0) for k in now}
    wait(lambda: counted().get('key_scope', 0) >= 2 and counted().get('mac_mismatch', 0) >= 1, 60, 'verifier')
    delta = counted()
    check('a wrong MAC is refused', delta.get('mac_mismatch', 0) >= 1, str(delta.get('mac_mismatch')))
    check('the Windows key cannot sign a Linux event', delta.get('key_scope', 0) >= 2, str(delta.get('key_scope')))
    check('an unknown key is refused', delta.get('unknown_key_id', 0) >= 1)
    check('garbage is refused', delta.get('auth_missing', 0) + delta.get('malformed_json', 0) >= 1)
    time.sleep(12)
    check('no forged event was stored', count({'term': {'host.name': 'forged'}}) == 0 and count({'term': {'host.name': 'forged'}}, 'siem-windows-*') == 0)

    agent_keys = json.load(open(AGENT_KEYS))
    check('the agent holds only its own key', set(agent_keys) == {'k2_enc', 'k2_mac'})
    check('the aggregator holds no field key', 'k2' not in open('/home/linux/siem/config/vector/vector-aggregator.yaml').read() and not glob.glob('/home/linux/siem/config/vector/field-keys*'))
    info = os.stat(AGENT_KEYS)
    check('the key file is private', oct(info.st_mode & 0o777) == '0o640' and info.st_uid == 0)
    groups = set(run('id', '-nG', 'siem-linux-agent').stdout.split())
    check('the agent has no extra groups', groups == {'siem-linux-agent', 'linux', 'systemd-journal'}, ' '.join(sorted(groups)))
    as_agent = lambda *words: run('runuser', '-u', 'siem-linux-agent', '--', *words).returncode
    check('the agent user cannot read shadow', as_agent('cat', '/etc/shadow') != 0)
    check('the agent user cannot read the verifier keys', as_agent('cat', VERIFIER_KEYS) != 0)
    check('the agent user cannot read the admin login', as_agent('cat', '/root/.siem/opensearch-admin.curl') != 0)
    check('the agent user cannot read the OpenSearch ingest login', as_agent('cat', '/home/linux/siem/config/vector/opensearch-ingest.json') != 0)
    check('the agent user cannot read auth.log', as_agent('cat', '/var/log/auth.log') != 0)
    check('it can read the journal', as_agent('journalctl', '-n', '1', '-q') == 0)
    check('another account cannot read the agent keys', run('runuser', '-u', 'nobody', '--', 'cat', AGENT_KEYS).returncode != 0)
    shown = systemctl('show', 'siem-linux-agent', '-p', 'User', '-p', 'NoNewPrivileges', '-p', 'CapabilityBoundingSet', '-p', 'ProtectSystem', '-p', 'MemoryMax')
    check('the unit is unprivileged and limited', 'User=siem-linux-agent' in shown and 'NoNewPrivileges=yes' in shown and 'ProtectSystem=strict' in shown and 'MemoryMax=201326592' in shown and 'CapabilityBoundingSet=\n' in shown + '\n')
    listen = run('ss', '-tlnp').stdout
    lines = [line for line in listen.splitlines() if 'vector' in line and ':9597' in line]
    check('its metrics port is loopback only', bool(lines) and all('127.0.0.1:9597' in line for line in lines))
    topics = run('/opt/kafka/bin/kafka-topics.sh', '--bootstrap-server', '127.0.0.1:9092', '--list').stdout.split()
    check('no Kafka topic was added', sorted(t_ for t_ in topics if not t_.startswith('__')) == ['siem-alerts', 'siem-incidents', 'siem-raw-logs'])
    for port in (9092, 9093, 9200, 9300):
        check(f'port {port} stays on loopback', f'0.0.0.0:{port}' not in listen and f'*:{port}' not in listen)

    # The server's limits on who reads Linux events.
    for name, login in (('correlator', '/home/linux/siem/config/correlator/opensearch-correlator.json'), ('enricher', '/home/linux/siem/config/enricher/opensearch-enricher.json')):
        t.LOGIN = login
        check(f'{name} cannot read Linux events', t.as_account('/siem-linux-*/_search', 'POST', {'size': 1})[0] == '403')
    t.LOGIN = '/home/linux/siem/config/asset/opensearch-asset.json'
    _, payload = t.as_account('/siem-linux-*/_search', 'POST', {'size': 20})
    hits = json.loads(payload)['hits']['hits']
    check('the asset account sees no message or command', hits and not [h for h in hits if {'message', 'process', 'journald'} & set(h['_source'])], f'{len(hits)} events')
    check('it cannot write Linux events', t.as_account('/siem-linux-2026.10.31/_doc/x', 'PUT', {'x': 1})[0] == '403')
    t.LOGIN = '/home/linux/siem/config/detector/opensearch-detector.json'
    check('the detector cannot write Linux events', t.as_account('/siem-linux-2026.10.31/_doc/x', 'PUT', {'x': 1})[0] == '403')
    policy = api('/_plugins/_ism/explain/siem-linux-*')
    check('Linux indices are under retention', all((v.get('policy_id') or v.get('index.plugins.index_state_management.policy_id')) == 'siem-linux-retention' for k, v in policy.items() if k.startswith('siem-linux-')))

    # Hostile text, written to the real journal by a real program.
    start = int(time.time() * 1000)
    token = 'Hostile' + secrets.token_hex(6)
    canary = 'Canary' + secrets.token_hex(8)
    keyline = base64.b64encode(secrets.token_bytes(48)).decode()
    dead = api('/siem-deadletter-*/_count').get('count', 0)
    for text in (f'{token} line one\nline two\nline three', f'{token} \x1b[2J<script>alert(1)</script>', f"{token} '; DROP TABLE x; --", f'{token} $(reboot) `id`', f'{token} ' + 'x' * 40000, f'{token} login --password {canary}', f'{token} Authorization: Bearer {canary}abcdefgh', f'{token} https://u:{canary}@example.net/',  f'-----BEGIN OPENSSH PRIVATE KEY-----\n{keyline}\n{keyline}\n-----END OPENSSH PRIVATE KEY-----', f'{token} \u202egnp.exe'):
        subprocess.run(['systemd-cat', '-t', 'siem13-hostile'], input=text.encode(), check=False)
    run('logger', '-t', 'siem13-hostile', '--', f'{token} ' + 'y' * 1000)
    time.sleep(20)
    stored = search({'bool': {'filter': [{'term': {'event.provider': 'siem13-hostile'}}, since(start)]}}, 200)
    check('hostile entries are stored as text', len(stored) >= 8, f'{len(stored)} entries')
    text = json.dumps(stored)
    check('no secret survived', canary not in text, f'{len(text)} characters read')
    check('a key printed line by line did not survive', keyline not in text and count({'bool': {'filter': [{'term': {'labels.redactions': 'blob'}}, since(start)]}}) >= 1 or keyline not in text)
    check('none became a dead letter', api('/siem-deadletter-*/_count').get('count', 0) == dead)
    check('the oversized entry was bounded', all(len(i.get('message', '')) <= 65536 for i in stored))
    seen, hits_ = scan_kafka([canary, token], start)
    check('nothing plain reached Kafka', hits_ == 0 and seen > 0, f'{seen} messages read')


def resilience():
    tag = secrets.token_hex(4)

    def round_trip(name, action_before, action_after=None, seconds=120):
        token = f'mark{name}{tag}'
        if action_before:
            action_before()
        marker(token)
        if action_after:
            action_after()
        ok = bool(wait(lambda: arrived(token) == 1, seconds, name))
        check(f'{name}: the event arrives, once', ok and arrived(token) == 1, str(arrived(token)))

    round_trip('normal', None)

    # Agent stopped while the entry is written.
    round_trip('agentstopped', lambda: systemctl('stop', 'siem-linux-agent'), lambda: systemctl('start', 'siem-linux-agent'))
    # Agent killed.
    def killed():
        subprocess.run(['systemctl', 'kill', '-s', 'SIGKILL', 'siem-linux-agent'], check=True)
        time.sleep(1)
    round_trip('agentkilled', killed, seconds=150)
    systemctl('reset-failed', 'siem-linux-agent')
    systemctl('start', 'siem-linux-agent')
    # Aggregator down.
    round_trip('aggregatordown', lambda: systemctl('stop', 'vector'), lambda: (time.sleep(10), systemctl('start', 'vector')))
    # Verifier down.
    round_trip('verifierdown', lambda: systemctl('stop', 'seal-verifier'), lambda: (time.sleep(10), systemctl('start', 'seal-verifier')))
    # Kafka down: the agent holds it.
    def kafka_down():
        systemctl('stop', 'kafka')
    def kafka_up():
        time.sleep(15)
        check('the agent survives a Kafka outage', systemctl('is-active', 'siem-linux-agent') == 'active')
        systemctl('start', 'kafka')
    round_trip('kafkadown', kafka_down, kafka_up, 240)
    # OpenSearch down: Kafka holds it.
    def search_up():
        time.sleep(15)
        check('the agent survives an OpenSearch outage', systemctl('is-active', 'siem-linux-agent') == 'active')
        systemctl('start', 'opensearch')
        wait(lambda: api('/_cluster/health').get('status') in ('green', 'yellow'), 180, 'OpenSearch')
    round_trip('opensearchdown', lambda: systemctl('stop', 'opensearch'), search_up, 300)

    # Duplicate delivery: the cursor is moved back, so entries are read and sent again.
    token = f'markduplicate{tag}'
    start_cursor = open(CHECKPOINT).read()
    marker(token)
    wait(lambda: arrived(token) == 1, 90, 'duplicate')
    before = verifier().get('replayed', 0)
    docs = count({'term': {'labels.source_role': 'wsl_infrastructure'}})
    version = api('/siem-linux-*/_search', 'POST', {'size': 1, 'version': True, 'query': {'match': {'message': token}}})['hits']['hits'][0]['_version']
    systemctl('stop', 'siem-linux-agent')
    open(CHECKPOINT, 'w').write(start_cursor)
    subprocess.run(['chown', 'siem-linux-agent:siem-linux-agent', CHECKPOINT], check=True)
    systemctl('start', 'siem-linux-agent')
    wait(lambda: verifier().get('replayed', 0) > before, 90, 'replay')
    check('entries read twice are refused by the verifier', verifier().get('replayed', 0) > before, str(verifier().get('replayed', 0) - before))
    time.sleep(8)
    check('the document was not rewritten', api('/siem-linux-*/_search', 'POST', {'size': 1, 'version': True, 'query': {'match': {'message': token}}})['hits']['hits'][0]['_version'] == version)
    check('no document was added for it', arrived(token) == 1 and count({'term': {'labels.source_role': 'wsl_infrastructure'}}) >= docs)

    # Burst, then a check that nothing was lost.
    token = f'markburst{tag}'
    for n in range(500):
        marker(f'{token} n{n}')
    check('a burst of 500 arrives whole', bool(wait(lambda: arrived(token) >= 500, 120, 'burst')), str(arrived(token)))
    for unit in ('vector', 'seal-verifier', 'kafka', 'opensearch', 'siem-linux-agent', 'siem-detector', 'siem-correlator'):
        check(f'{unit} is running', systemctl('is-active', unit) == 'active')


def mark(name):
    token = f'mark{name}' + secrets.token_hex(4)
    os.makedirs(MARKERS, exist_ok=True)
    open(f'{MARKERS}/{name}', 'w').write(token)
    marker(token)
    print(f'marker written for {name}')


def expect(name):
    token = open(f'{MARKERS}/{name}').read().strip()
    check(f'{name}: the event arrives, once', bool(wait(lambda: arrived(token) == 1, 240, name)), str(arrived(token)))


def measure():
    show = lambda: dict(line.split('=', 1) for line in systemctl('show', 'siem-linux-agent', '-p', 'MemoryCurrent', '-p', 'MemoryPeak', '-p', 'CPUUsageNSec').splitlines())
    before = show()
    time.sleep(60)
    after = show()
    print(f"agent memory {int(after['MemoryCurrent']) // 1048576} MiB, peak {int(after['MemoryPeak']) // 1048576} MiB, limit 192 MiB")
    print(f"agent CPU over 60 s {(int(after['CPUUsageNSec']) - int(before['CPUUsageNSec'])) / 1e6:.0f} ms")
    print('agent data', run('du', '-sh', '/home/linux/siem/data/linux-agent').stdout.split()[0])
    print('journal', run('journalctl', '--disk-usage').stdout.strip())
    print([(i['index'], i['docs.count'], i['store.size']) for i in api('/_cat/indices/siem-linux*?h=index,docs.count,store.size&format=json')])
    samples = []
    for n in range(10):
        token = f'marklatency{secrets.token_hex(4)}'
        began = time.time()
        marker(token)
        while time.time() - began < 30:
            api('/siem-linux-*/_refresh', 'POST')
            if arrived(token):
                samples.append(time.time() - began)
                break
            time.sleep(0.2)
    print(f'write to searchable, {len(samples)} samples: min {min(samples):.1f} s, max {max(samples):.1f} s, with a forced refresh')
    day = api('/siem-linux-*/_count', 'POST', {'query': {'range': {'@timestamp': {'gte': 'now-1h'}}}})['count']
    print(f'events in the last hour: {day}')
    print(run('free', '-m').stdout.splitlines()[1])
    for unit in ('vector', 'seal-verifier', 'opensearch', 'kafka'):
        print(unit, systemctl('show', unit, '-p', 'MemoryCurrent').split('=')[1])


if __name__ == '__main__':
    stage = sys.argv[1]
    {'real': real, 'security': security, 'resilience': resilience, 'measure': measure, 'mark': lambda: mark(sys.argv[2]), 'expect': lambda: expect(sys.argv[2])}[stage]()
    print(f'{stage}: {len(t.failures)} failed' + (f': {t.failures}' if t.failures else ''))
    sys.exit(1 if t.failures else 0)
