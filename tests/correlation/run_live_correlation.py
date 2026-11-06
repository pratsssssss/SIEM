"""Live correlation tests, as root in WSL against the running stack. Prints counts and statuses, never
event content or secrets.

Usage: run_live_correlation.py prepare <info.json>     load synthetic intelligence, for real events
       run_live_correlation.py scenarios <info.json>   what the real events produced
       run_live_correlation.py cleanup                 remove the synthetic intelligence
       run_live_correlation.py resilience              outages, a crash, duplicates, invalid alerts
       run_live_correlation.py security                accounts, the socket, the service
"""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

CURL_ADMIN = '/root/.siem/opensearch-admin.curl'
API = 'https://127.0.0.1:9200'
DB = '/home/linux/siem/data/correlation/correlator.db'
LOGIN = '/home/linux/siem/config/correlator/opensearch-correlator.json'
OWNER = Path('/home/linux/siem/data/enrichment/owner')
SYNTHETIC = OWNER / 'synthetic-phase11.csv'
GROUP = '6a1f0c52-3b7e-4c41-9d21-0e5a7b1c4f05'
SCHTASKS = '6a1f0c52-3b7e-4c41-9d21-0e5a7b1c4f0b'
RUN = hashlib.sha256(str(time.time_ns()).encode()).hexdigest()[:6]
failures = []


def check(name, ok, detail=''):
    print(f"{'PASS' if ok else 'FAIL'} {name}" + (f' ({detail})' if detail != '' else ''), flush=True)
    if not ok:
        failures.append(name)


def api(path, method='GET', body=None):
    command = ['curl', '-sS', '--max-time', '30', '--cacert', '/etc/opensearch/root-ca.pem', '-K', CURL_ADMIN, '-X', method, API + path]
    if body is not None:
        command += ['-H', 'Content-Type: application/json', '-d', json.dumps(body)]
    return json.loads(subprocess.run(command, capture_output=True, text=True).stdout or '{}')


def as_correlator(path, method='GET', body=None):
    """The HTTP status the service's own account gets."""
    login = json.load(open(LOGIN))
    with tempfile.NamedTemporaryFile('w', dir='/root/.siem', suffix='.curl', delete=False) as handle:
        os.fchmod(handle.fileno(), 0o600)
        handle.write(f'user = "{login["user"]}:{login["password"]}"\n')
    try:
        command = ['curl', '-sS', '-w', '\n%{http_code}', '--max-time', '20', '--cacert', '/etc/opensearch/root-ca.pem', '-K', handle.name, '-X', method, API + path]
        if body is not None:
            command += ['-H', 'Content-Type: application/json', '-d', json.dumps(body)]
        text = subprocess.run(command, capture_output=True, text=True).stdout
        payload, _, status = text.rpartition('\n')
        return status, payload
    finally:
        os.unlink(handle.name)


def analyst(*words):
    """The real command, as the analyst account."""
    done = subprocess.run(['su', '-s', '/bin/bash', 'linux', '-c', ' '.join(['siem-incident', *words])], capture_output=True, text=True, timeout=120)
    return json.loads(done.stdout) if done.stdout.strip().startswith(('{', '[')) else {'_text': done.stdout, '_error': done.stderr}


def incidents_rows():
    db = sqlite3.connect(f'file:{DB}?mode=ro', uri=True)
    rows = [json.loads(r[0]) for r in db.execute('SELECT body FROM incidents')]
    db.close()
    return rows


def sql(query, *args):
    db = sqlite3.connect(f'file:{DB}?mode=ro', uri=True)
    rows = db.execute(query, args).fetchall()
    db.close()
    return rows


def wait(probe, seconds, label):
    limit = time.time() + seconds
    while time.time() < limit:
        value = probe()
        if value:
            return value
        time.sleep(5)
    print(f'INFO timed out after {seconds} s waiting for {label}', flush=True)
    return None


def systemctl(*words):
    return subprocess.run(['systemctl', *words], capture_output=True, text=True).stdout.strip()


# Scenarios.
def enricher(*words):
    return subprocess.run(['/usr/local/bin/siem-enricher', *words], capture_output=True, text=True).stdout


def prepare(path):
    info = json.load(open(path, encoding='utf-8-sig'))
    OWNER.mkdir(exist_ok=True)
    SYNTHETIC.write_text('# Synthetic test intelligence. Nothing here is really malicious.\n' + f"ip,{info['ip']},synthetic-c2\n" + ''.join(f'domain,{d},synthetic-c2\n' for d in info['domains']))
    subprocess.run(['chown', 'siem-enricher:siem-enricher', str(SYNTHETIC)], check=True)
    print(enricher('feeds', 'update', '--name', 'owner-synthetic-phase11').strip()[:160])
    subprocess.run(['systemctl', 'restart', 'siem-enricher'], check=True)
    print('enricher restarted with the synthetic file')


def cleanup():
    print(enricher('feeds', 'purge', '--name', 'owner-synthetic-phase11').strip()[:160])
    SYNTHETIC.unlink(missing_ok=True)
    subprocess.run(['systemctl', 'restart', 'siem-enricher'], check=True)
    print('synthetic intelligence removed')


def with_rule(rule, tag=None):
    found = [i for i in incidents_rows() if rule in [r['id'] for r in i['rules']]]
    if tag:
        found = [i for i in found if tag in json.dumps({k: i.get(k) for k in ('users', 'domains', 'indicators', 'correlations')}).lower()]
    return found


def scenarios(path):
    info = json.load(open(path, encoding='utf-8-sig'))
    tag = info['tag'].lower()
    started = info['started']

    def recent(rule):
        return [i for i in with_rule(rule) if i['last_seen'] >= started]

    def report(number, rule, found, expect=True):
        if found:
            item = found[0]
            sequence = len(item['explanation']['sequence'])
            print(f"INFO scenario {number}: {item['incident_id'][:12]} severity {item['severity']} confidence {item['confidence']} alerts {len(item['alert_ids'])} signals {len(item['signal_ids'])} sequence {sequence}", flush=True)
        check(f'scenario {number} on real telemetry: {rule}', bool(found) == expect, f'{len(found)} incidents')

    report(1, 'cor-logon-after-burst', wait(lambda: with_rule('cor-logon-after-burst', tag), 600, 'scenario 1'))
    print('INFO the service and task actions are real. The synthetic intelligence is labelled in the report')
    report(4, 'cor-service-then-process', wait(lambda: recent('cor-service-then-process'), 600, 'scenario 4'))
    report(5, 'cor-task-then-process', wait(lambda: recent('cor-task-then-process'), 600, 'scenario 5'))
    report(6, 'cor-same-indicator', wait(lambda: [i for i in recent('cor-same-indicator') if any(x['value'] == info['ip'] for x in i['indicators'])], 900, 'scenario 6'))
    report(7, 'cor-host-many-domains', wait(lambda: with_rule('cor-host-many-domains', tag), 600, 'scenario 7'))
    for number, rule in ((2, 'cor-password-spray'), (3, 'cor-powershell-child'), (9, 'cor-privilege-then-admin'), (10, 'cor-multi-stage')):
        report(number, rule, with_rule(rule))
    report(8, 'cor-user-many-hosts', with_rule('cor-user-many-hosts'), expect=False)
    print('INFO scenario 8 cannot occur here: the lab has one Windows host, so it stands on fixtures alone')

    separate = [recent(r) for r in ('cor-service-then-process', 'cor-task-then-process', 'cor-host-many-domains')]
    ids = [i[0]['incident_id'] for i in separate if i]
    check('unrelated scenarios on one host stay separate incidents', len(ids) == 3 and len(set(ids)) == 3, f'{len(set(ids))} of 3')
    item = next(iter(with_rule('cor-logon-after-burst', tag)), None)
    if item:
        trace_one(item)


def trace_one(item):
    """Follows one incident back to the stored alerts and events."""
    alert_id = item['alert_ids'][0]
    hit = api('/siem-alerts-*/_search', 'POST', {'size': 1, 'query': {'term': {'alert_id': alert_id}}, '_source': ['raw_event_refs']})['hits']['hits']
    check('an incident alert exists in the alert evidence index', len(hit) == 1)
    if hit:
        index, doc = hit[0]['_source']['raw_event_refs'][0].split('/', 1)
        check('that alert traces to a stored source event', api(f'/{index}/_doc/{doc}?_source=false').get('found') is True)
    stored = api(f"/siem-incidents-*/_search", 'POST', {'size': 1, 'query': {'term': {'incident_id': item['incident_id']}}})['hits']['hits']
    check('the incident reached OpenSearch', len(stored) == 1)
    check('the analyst can read its timeline', isinstance(analyst('timeline', item['incident_id']), list))


# Synthetic alerts, on the real topic, for failures that real events cannot be made to hit on demand.
def fake_alert(rule_id, at_ms, name, user, serial):
    alert_id = hashlib.sha256(f'corrtest|{time.time_ns()}|{serial}'.encode()).hexdigest()[:32]
    stamp = time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime(at_ms / 1000))
    return {'schema_version': 1, 'alert_id': alert_id, 'rule_id': rule_id, 'rule_name': f'corrtest {name}', 'detection_type': 'sigma', 'severity': 'medium', 'confidence': 'medium', 'timestamp': stamp, 'detected_at': stamp, 'description': 'Synthetic correlation test alert',
            'host': 'corrtest-host', 'user': user, 'source_ip': None, 'event_count': 1, 'source_event_ids': [], 'raw_event_refs': [], 'mitre': {'tactics': ['execution'], 'techniques': []}, 'evidence': {'matched_fields': {'user.domain': ['CORRTEST']}, 'first_seen': stamp, 'last_seen': stamp, 'facts': {}}, 'evidence_ref': None}


def publish(*values):
    code = ("import sys, json\nfrom confluent_kafka import Producer\np = Producer({'bootstrap.servers': '127.0.0.1:9092'})\n"
            "for line in sys.stdin.buffer.read().split(b'\\0'):\n    p.produce('siem-alerts', line)\np.flush(20)\n")
    payload = b'\0'.join(v if isinstance(v, bytes) else json.dumps(v).encode() for v in values)
    subprocess.run(['python3', '-c', code], input=payload, env={**os.environ, 'PYTHONPATH': '/opt/siem-correlator/lib'}, check=True, timeout=40)


def fake_pair(user):
    now = int(time.time() * 1000)
    return fake_alert(GROUP, now - 300000, 'first', user, 1), fake_alert(SCHTASKS, now - 60000, 'second', user, 2)


def for_user(user):
    return [i for i in incidents_rows() if any(user in u for u in i['users'])]


def health():
    return analyst('lag')


def close_tests(users):
    for user in users:
        for item in for_user(user):
            if item['status'] == 'new':
                analyst('status', item['incident_id'], 'false_positive', '--note', '"synthetic correlation test"')


def alert_digest():
    """Every stored alert, with its version, so any change shows."""
    digest, after = {}, None
    while True:
        body = {'size': 500, 'seq_no_primary_term': True, 'sort': [{'alert_id': 'asc'}], 'query': {'match_all': {}}}
        if after:
            body['search_after'] = after
        hits = api('/siem-alerts-*/_search', 'POST', body)['hits']['hits']
        for hit in hits:
            digest[hit['_id']] = (hit['_seq_no'], hashlib.sha256(json.dumps(hit['_source'], sort_keys=True).encode()).hexdigest())
        if len(hits) < 500:
            return digest
        after = hits[-1]['sort']


def resilience():
    before = alert_digest()
    print(f'INFO {len(before)} alerts recorded before the tests')

    # Duplicates and invalid alerts.
    first, second = fake_pair(f'corrdup{RUN}')
    sent = time.time()
    publish(first, second)
    limit = sent + 30
    while time.time() < limit and not for_user(f'corrdup{RUN}'):
        time.sleep(0.2)
    print(f'INFO from publishing to a stored incident: {time.time() - sent:.1f} s')
    item = wait(lambda: for_user(f'corrdup{RUN}'), 60, 'the first incident')
    check('a synthetic pair makes an incident through the real topic', bool(item))
    if item:
        revision = item[0]['revision']
        publish(first, second, first)
        time.sleep(15)
        now = for_user(f'corrdup{RUN}')
        check('duplicate delivery changes nothing', len(now) == 1 and now[0]['revision'] == revision, f'revision {revision}')
    held = len(sql('SELECT 1 FROM quarantine'))
    publish(b'private-argument is not an alert', b'{"alert_id": "short"}')
    check('invalid messages are quarantined, not dropped', wait(lambda: len(sql('SELECT 1 FROM quarantine')) == held + 2, 40, 'quarantine') is True)
    check('quarantine keeps no content', 'private-argument' not in json.dumps(analyst('quarantine')))
    check('invalid messages do not stop the service', systemctl('is-active', 'siem-correlator') == 'active')

    # Kafka outage: real alerts made during it, traced one by one.
    started = int(time.time() * 1000)
    systemctl('stop', 'kafka')
    time.sleep(70)
    report = health()
    check('a Kafka outage shows in health', report.get('kafka') != 'ok' and report.get('status') == 'WARN', str(report.get('kafka')))
    check('the service survives a Kafka outage', systemctl('is-active', 'siem-correlator') == 'active')
    late = fake_pair(f'corrkafka{RUN}')
    systemctl('start', 'kafka')
    time.sleep(30)
    publish(*late)
    check('work resumes after the Kafka outage', bool(wait(lambda: for_user(f'corrkafka{RUN}'), 120, 'incident after Kafka')))
    wait(lambda: health().get('kafka') == 'ok', 120, 'kafka state')
    missing = [h['_id'] for h in api('/siem-alerts-*/_search', 'POST', {'size': 500, '_source': False, 'query': {'range': {'detected_at': {'gte': started - 600000, 'format': 'epoch_millis'}}}})['hits']['hits'] if not sql('SELECT 1 FROM alerts WHERE alert_id = ?', h['_id'])]
    time.sleep(60)
    missing = [i for i in missing if not sql('SELECT 1 FROM alerts WHERE alert_id = ?', i)]
    check('every alert detected around the Kafka outage is held', not missing, f'{len(missing)} missing')

    # OpenSearch outage.
    target = for_user(f'corrdup{RUN}')[0]
    systemctl('stop', 'opensearch')
    time.sleep(40)
    outage = fake_pair(f'corropen{RUN}')
    publish(*outage)
    time.sleep(30)
    waiting = sql("SELECT COUNT(*) FROM alerts WHERE alert_id IN (?, ?) AND status = 'pending'", outage[0]['alert_id'], outage[1]['alert_id'])[0][0]
    check('alerts wait, stored, during an OpenSearch outage', waiting == 2, f'{waiting} of 2')
    check('no alert is lost from Kafka during it', len(sql('SELECT 1 FROM alerts WHERE alert_id IN (?, ?)', outage[0]['alert_id'], outage[1]['alert_id'])) == 2)
    noted = analyst('note', target['incident_id'], '"written during the outage"')
    check('an analyst can still work during it', noted.get('incident_id') == target['incident_id'])
    check('the change waits in the outbox', sql('SELECT COUNT(*) FROM outbox')[0][0] >= 1)
    time.sleep(35)
    check('health reports it', health().get('opensearch') != 'ok' and health().get('status') == 'WARN', str(health().get('opensearch')))
    systemctl('start', 'opensearch')
    wait(lambda: api('/_cluster/health').get('status') in ('green', 'yellow'), 180, 'OpenSearch')
    check('held alerts are analysed after recovery', bool(wait(lambda: for_user(f'corropen{RUN}'), 240, 'incident after OpenSearch')))
    check('the outbox drains', wait(lambda: sql('SELECT COUNT(*) FROM outbox')[0][0] == 0, 120, 'outbox') is True)
    stored = wait(lambda: api('/siem-incidents-*/_search', 'POST', {'size': 1, 'query': {'term': {'incident_id': target['incident_id']}}}).get('hits', {}).get('hits'), 60, 'indexed note')
    check('the note made during the outage reached OpenSearch', bool(stored) and 'written during the outage' in json.dumps(stored[0]['_source'].get('notes')))

    # A crash in the middle of a burst.
    burst = []
    now = int(time.time() * 1000)
    for index in range(60):
        user = f'corrcrash{RUN}{index % 10}'
        burst.append(fake_alert(GROUP if index < 10 else SCHTASKS, now - (300000 if index < 10 else 60000), f'crash{index}', user, index))
    publish(*burst)
    time.sleep(1)
    subprocess.run(['systemctl', 'kill', '-s', 'SIGKILL', 'siem-correlator'], check=True)
    print('INFO killed the service during a burst of 60 alerts')
    wait(lambda: systemctl('is-active', 'siem-correlator') == 'active', 90, 'restart')
    ids = [a['alert_id'] for a in burst]
    marks = ','.join('?' * len(ids))
    check('every alert of the burst survives', wait(lambda: sql(f"SELECT COUNT(*) FROM alerts WHERE status = 'done' AND alert_id IN ({marks})", *ids)[0][0] == 60, 120, 'burst') is True)
    built = [i for i in incidents_rows() if any(u.split('\\')[-1].startswith(f'corrcrash{RUN}') for u in i['users'])]
    check('the burst makes ten incidents, one for each account, with no duplicates', len(built) == 10, f'{len(built)} incidents')
    check('every alert is in exactly one of them', sorted(a for i in built for a in i['alert_ids']) == sorted(ids))

    # Replay, and the audit chain.
    replay = analyst('replay', '--hours', '2')
    check('a bounded replay finds nothing lost', replay.get('new') == 0 and 'read' in replay, str(replay))
    check('an unbounded replay is refused', '_text' in analyst('replay', '--hours', '99999'))
    verify = analyst('audit-verify')
    check('the audit chain is intact after all of this', verify.get('intact') is True, f"{verify.get('entries')} entries")
    wait(lambda: sql('SELECT COUNT(*) FROM audit WHERE shipped = 0')[0][0] == 0, 90, 'audit shipping')
    check('the audit trail reached OpenSearch', sql('SELECT COUNT(*) FROM audit WHERE shipped = 0')[0][0] == 0)

    after = alert_digest()
    changed = [k for k, v in before.items() if after.get(k) != v]
    check('no stored alert changed', not changed, f'{len(changed)} of {len(before)}')
    close_tests([f'corrdup{RUN}', f'corrkafka{RUN}', f'corropen{RUN}'] + [f'corrcrash{RUN}{i}' for i in range(10)])
    print(f'INFO health at the end: {health().get("status")}, {health().get("message")}')


def security():
    # The account.
    status, payload = as_correlator('/siem-windows-*/_search', 'POST', {'size': 200, 'query': {'exists': {'field': 'process.name'}}})
    check('the account can search events', status == '200')
    fields = set()
    for hit in json.loads(payload)['hits']['hits']:
        fields |= set(hit['_source']) | {f'{k}.{s}' for k, v in hit['_source'].items() if isinstance(v, dict) for s in v}
    check('field security hides everything but identity fields', not fields & {'message', 'process.command_line', 'winlog', 'powershell', 'event'} and bool(fields), f'{len(fields)} fields visible')
    index = api('/_cat/indices/siem-alerts-*?format=json')[0]['index']
    event_index = api('/_cat/indices/siem-windows-*?format=json')[0]['index']
    enrichment = api('/_cat/indices/siem-enrichment-*?format=json')[0]['index']
    for name, path, method, body in (
            ('write an alert', f'/{index}/_doc/corrtest', 'PUT', {'x': 1}),
            ('write an event', f'/{event_index}/_doc/corrtest', 'PUT', {'x': 1}),
            ('write enrichment', f'/{enrichment}/_doc/corrtest', 'PUT', {'x': 1}),
            ('delete an incident index', '/siem-incidents-2026.10', 'DELETE', None),
            ('delete an audit document', '/siem-incident-audit-2026.10/_doc/1-x', 'DELETE', None),
            ('delete by query on incidents', '/siem-incidents-*/_delete_by_query', 'POST', {'query': {'match_all': {}}}),
            ('update by query on alerts', f'/{index}/_update_by_query', 'POST', {'query': {'match_all': {}}}),
            ('read the security index', '/.opendistro_security/_search', 'POST', {}),
            ('create another index', '/siem-other-test/_doc/1', 'PUT', {'x': 1}),
            ('change cluster settings', '/_cluster/settings', 'PUT', {'persistent': {'action.destructive_requires_name': True}})):
        check(f'the account cannot {name}', as_correlator(path, method, body)[0] == '403')

    # The socket.
    def attempt(user, group=None):
        code = "import sys; sys.path.insert(0, '/opt/siem-correlator/app'); from siem_correlator import control; print(control.call('/run/siem-correlator/control.sock', {'action': 'list'}))"
        command = ['setpriv', f'--reuid={user}', '--clear-groups' if group is None else f'--groups={group}', f"--regid={group or 'nogroup'}", 'python3', '-c', code]
        return subprocess.run(command, capture_output=True, text=True, timeout=20)
    shown = os.stat('/run/siem-correlator/control.sock')
    check('the socket is group-only', oct(shown.st_mode & 0o777) == '0o660', oct(shown.st_mode & 0o777))
    check('a user outside the group cannot open it', attempt('nobody').returncode != 0)
    refused = subprocess.run(['python3', '-c', "import sys; sys.path.insert(0, '/opt/siem-correlator/app'); from siem_correlator import control; print(control.call('/run/siem-correlator/control.sock', {'action': 'list'}))"], capture_output=True, text=True, timeout=20)
    check('root is refused, because an audit entry must name a person', 'not a member' in refused.stdout, refused.stdout[:60])
    entry = analyst('audit')
    check('the refusal is audited', isinstance(entry, list) and any(e['action'] == 'refused' for e in entry))
    item = incidents_rows()[0]
    check('an analyst is accepted', 'incidents' in analyst('list').get('_text', ''))
    check('an illegal move is refused', 'refused' in analyst('status', item['incident_id'], 'nonsense').get('_error', ''))
    subprocess.run(['su', '-s', '/bin/bash', 'linux', '-c', 'siem-incident rule-disable cor-user-many-hosts'], capture_output=True)
    subprocess.run(['su', '-s', '/bin/bash', 'linux', '-c', 'siem-incident rule-enable cor-user-many-hosts'], capture_output=True)
    trail = analyst('audit')
    check('rule changes are audited with the person', sum(1 for e in trail if e['action'] == 'rule' and e['actor'] == 'linux') >= 2)

    # The service.
    show = systemctl('show', 'siem-correlator', '-p', 'User', '-p', 'NoNewPrivileges', '-p', 'ProtectSystem', '-p', 'MemoryMax', '-p', 'CapabilityBoundingSet')
    check('the service is unprivileged and limited', 'User=siem-correlator' in show and 'NoNewPrivileges=yes' in show and 'ProtectSystem=strict' in show and 'MemoryMax=201326592' in show)
    pid = systemctl('show', 'siem-correlator', '-p', 'MainPID', '--value')
    listening = subprocess.run(['ss', '-lntup'], capture_output=True, text=True).stdout
    check('the service listens on no network port', f'pid={pid},' not in listening)
    check('the state file is private', oct(os.stat(DB).st_mode & 0o777) in ('0o600', '0o640', '0o644') and oct(os.stat(os.path.dirname(DB)).st_mode & 0o777) == '0o700')
    check('the login file is not world readable', not os.stat(LOGIN).st_mode & 0o007)
    journal = subprocess.run(['journalctl', '-u', 'siem-correlator', '--no-pager', '-q'], capture_output=True, text=True, errors='replace').stdout
    login = json.load(open(LOGIN))
    check('no secret or quarantined text in the journal', login['password'] not in journal and 'private-argument' not in journal)
    detector = (systemctl('show', 'siem-detector', '-p', 'After', '-p', 'Requires', '-p', 'Wants') + systemctl('show', 'siem-enricher', '-p', 'After', '-p', 'Requires', '-p', 'Wants'))
    check('detection and enrichment do not depend on correlation', 'siem-correlator' not in detector)
    systemctl('stop', 'siem-correlator')
    time.sleep(5)
    check('both keep running with correlation stopped', systemctl('is-active', 'siem-detector') == 'active' and systemctl('is-active', 'siem-enricher') == 'active')
    systemctl('start', 'siem-correlator')
    check('correlation restarts', bool(wait(lambda: systemctl('is-active', 'siem-correlator') == 'active', 30, 'restart')))


if __name__ == '__main__':
    stage = sys.argv[1]
    {'prepare': lambda: prepare(sys.argv[2]), 'scenarios': lambda: scenarios(sys.argv[2]), 'cleanup': cleanup, 'resilience': resilience, 'security': security}[stage]()
    print(f'{stage}: {len(failures)} failed' + (f': {failures}' if failures else ''))
    sys.exit(1 if failures else 0)
