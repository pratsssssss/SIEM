"""Live dashboard tests, as root in WSL against the running stack. Prints counts and statuses, never event content.

Usage: run_live_dashboard.py real        every route on real data, checked against the administrator's own queries
       run_live_dashboard.py leak        real command lines and script text, then a crawl proving none come back
       run_live_dashboard.py security    the account, the role, the network, secrets, and refusals by the real correlator
       run_live_dashboard.py resilience  the dashboard killed and stopped, with the pipeline watched meanwhile
       run_live_dashboard.py measure     memory, CPU and latency under representative use

A temporary administrator is created through the real root command, with a generated password held in memory, and removed
at the end. No production service other than the dashboard is stopped. No record is created or changed: the only incident
actions sent are ones the real correlator must refuse, and the test proves the incident did not change.
"""
import http.client
import json
import os
import secrets
import signal
import ssl
import subprocess
import sys
import time
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
import livelib as t  # noqa: E402

check, api, wait = t.check, t.api, t.wait
USER = 'livetest'
PASSWORD = secrets.token_urlsafe(24)
ADMIN = '/usr/local/sbin/siem-dashboard-admin'
LOGIN = '/home/linux/siem/config/dashboard/opensearch-dashboard.json'
CERT = '/home/linux/siem/config/dashboard/tls/dashboard.crt'
DB = '/home/linux/siem/data/dashboard/dashboard.db'
CORE = ('opensearch', 'kafka', 'seal-verifier', 'vector', 'siem-detector', 'siem-enricher', 'siem-correlator', 'siem-asset', 'siem-path', 'siem-linux-agent', 'siem-health')


def run(*words, timeout=60, stdin=None):
    return subprocess.run(words, capture_output=True, text=True, input=stdin, stdin=None if stdin is not None else subprocess.DEVNULL, timeout=timeout)


class Client:
    def __init__(self):
        self.context = ssl.create_default_context(cafile=CERT)
        self.cookie, self.csrf = None, None
        # Seconds between requests. A long crawl sets it, to stay under the server's own limit of requests per minute.
        self.pace = 0

    def call(self, method, path, body=None):
        if self.pace:
            time.sleep(self.pace)
        link = http.client.HTTPSConnection('127.0.0.1', 8443, context=self.context, timeout=30)
        heads = {}
        if self.cookie:
            heads['Cookie'] = f'__Host-siem_session={self.cookie}'
        data = None
        if body is not None:
            data = json.dumps(body)
            heads['Content-Type'] = 'application/json'
            if self.csrf:
                heads['X-CSRF-Token'] = self.csrf
        link.request(method, f'/api/v1{path}', body=data, headers=heads)
        reply = link.getresponse()
        raw = reply.read()
        link.close()
        cookie = reply.getheader('Set-Cookie')
        if cookie:
            self.cookie = cookie.split(';')[0].split('=', 1)[1] or None
            self.last_cookie = cookie
        parsed = json.loads(raw) if raw else None
        if isinstance(parsed, dict) and isinstance(parsed.get('data'), dict) and parsed['data'].get('csrf'):
            self.csrf = parsed['data']['csrf']
        return reply.status, parsed, raw

    def get(self, path):
        status, body, _ = self.call('GET', path)
        return status, (body or {}).get('data')

    def login(self):
        return self.call('POST', '/auth/login', {'username': USER, 'password': PASSWORD})[0]


def administrator():
    """The name of the account that exists, or None. The server holds one account at most."""
    return json.loads(run(ADMIN, 'status').stdout).get('username')


class Admin:
    """A temporary administrator, made for one block and removed after it. It never touches an account it did not make."""

    def __enter__(self):
        if administrator() is not None:
            raise SystemExit('An administrator already exists. These stages need a server with none, and never touch an existing account.')
        done = run(ADMIN, 'create', USER, '--password-stdin', stdin=PASSWORD + '\n')
        check('the root command creates the administrator from standard input', done.returncode == 0, done.stderr.strip()[:80])
        if done.returncode != 0:
            raise SystemExit('The temporary administrator could not be made, so nothing was changed.')
        self.client = Client()
        return self.client

    def __exit__(self, *rest):
        # Only the account this block made, checked by name again, since remove takes whatever account exists.
        if administrator() == USER:
            print('INFO removing the temporary administrator:', run(ADMIN, 'remove').stdout.strip())
        else:
            print('INFO the temporary administrator is gone already, so nothing was removed')


def real():
    with Admin() as c:
        check('sign-in works over verified TLS', c.login() == 200)
        for path in ('/overview?range=7d', '/events?range=24h&size=10', '/alerts?range=30d&size=10', '/incidents?size=10', '/incidents?include_unverified=true&size=10', '/assets', '/assets/changes?unreviewed=true', '/assets/conflicts', '/attack-paths', '/threat-intelligence', '/health/overview', '/health/components', '/health/lag', '/health/resources', '/health/metrics', '/health/failures', '/health/history', '/health/catalog', '/audit', '/audit/verify', '/search?q=127.0.0.1'):
            check(f'{path} answers', c.get(path)[0] == 200)
        status, view = c.get('/overview?range=30d')
        print('INFO section states', {k: v.get('status') for k, v in view.items() if isinstance(v, dict)})
        check('every overview section has real data', all(v.get('status') == 'ok' for v in view.values() if isinstance(v, dict)))

        # Against independent sources: the administrator account and the service commands.
        count = api('/siem-alerts-*/_count', 'POST', {'query': {'range': {'detected_at': {'gte': 'now-30d'}}}})['count']
        check('alert count agrees with OpenSearch', abs(count - view['security']['data']['alerts_total']) <= 3, f"{count} and {view['security']['data']['alerts_total']}")
        incidents = api('/siem-incidents-*/_search', 'POST', {'size': 200, '_source': ['alert_ids', 'status']})['hits']['hits']
        stored = {h['_source']['alert_id'] for h in api('/siem-alerts-*/_search', 'POST', {'size': 2000, '_source': ['alert_id']})['hits']['hits']}
        verified = sum(1 for h in incidents if set(h['_source'].get('alert_ids', [])) & stored)
        summary = view['incidents']['data']
        check('incident counts agree, with fixtures left out', summary['total'] == verified and summary['excluded_no_stored_alerts'] == len(incidents) - verified, f"{verified} real, {len(incidents) - verified} left out")
        health = json.loads(run('runuser', '-u', 'linux', '--', 'siem-health', '--json', 'overview').stdout)
        shown = c.get('/health/overview')[1]
        check('health is what Phase 16 says', shown['overall'] == health['overall'] and shown['coverage'] == health['coverage'], f"{shown['overall']}, {shown['coverage']}")
        assets = c.get('/assets?size=100')[1]
        check('assets agree with the inventory', assets['total']['value'] == api('/siem-assets-current/_count').get('count'), str(assets['total']['value']))
        serving = [r for r in assets['rows'] if r.get('status') != 'retired']
        check('criticality is not invented', view['assets']['data']['by_criticality'].get('not set', 0) == sum(1 for r in serving if not r.get('criticality')), str(view['assets']['data']['by_criticality']))
        check('retired fixtures are out of the in-service figures', view['assets']['data']['in_service'] == len(serving), f"{len(serving)} of {assets['total']['value']}")
        paths = c.get('/attack-paths?size=100')[1]
        check('paths agree', paths['total']['value'] == api('/siem-attack-paths-*/_count').get('count'), str(paths['total']['value']))

        # The investigation chain, on real records: incident, alert, event, asset, path, evidence.
        rows = c.get('/incidents?size=25')[1]['rows']
        check('there is a real incident to follow', bool(rows), str(len(rows)))
        chain = {'incident': 0, 'alert': 0, 'event': 0, 'event_expired': 0, 'path': 0, 'edge_evidence': 0, 'asset': 0}
        for row in rows[:6]:
            detail = c.get(f"/incidents/{row['incident_id']}")[1]
            chain['incident'] += 1
            for alert in (detail['alerts'].get('data') or [])[:2]:
                a = c.get(f"/alerts/{alert['alert_id']}")[1]
                chain['alert'] += 1
                for ref in [r for r in a['evidence_refs'] if r.get('link')][:1]:
                    status, _ = c.get(f"/events/{ref['index']}/{ref['id']}")
                    chain['event' if status == 200 else 'event_expired'] += 1
            for path in (detail['paths'].get('data') or [])[:1]:
                graph = c.get(f"/attack-paths/{path['path_id']}")[1]
                chain['path'] += 1
                check('a path says it proves nothing', graph['graph']['conclusion'].startswith('none') and 'not proof' in graph['limit_note'])
                for edge in graph['graph']['edges'][:1]:
                    chain['edge_evidence'] += len(c.get(f"/attack-paths/{path['path_id']}/evidence?edge={edge['id']}")[1])
            for asset in (detail['assets'].get('data') or [])[:1]:
                chain['asset'] += c.get(f"/assets/{asset['asset_id']}")[0] == 200
        print('INFO investigation chain', chain)
        check('the chain reached every kind of record', all(chain[k] for k in ('incident', 'alert', 'path', 'edge_evidence', 'asset')) and chain['event'] + chain['event_expired'] > 0, str(chain))
        check('sign-out ends the session', c.call('POST', '/auth/logout', {})[0] == 200 and c.get('/overview')[0] == 401)
    check('no administrator remains', json.loads(run(ADMIN, 'status').stdout)['provisioned'] is False)


def leak():
    secret = set()
    for query, fields in (({'exists': {'field': 'process.command_line'}}, ['process.command_line']), ({'exists': {'field': 'powershell.script_block.text'}}, ['powershell.script_block.text'])):
        found = api('/siem-windows-*/_search', 'POST', {'size': 300, '_source': fields, 'sort': [{'@timestamp': 'desc'}], 'query': query})['hits']['hits']
        for hit in found:
            for value in walk(hit['_source']):
                if isinstance(value, str) and len(value) >= 24:
                    secret.add(value)
    alerts = api('/siem-alerts-*/_search', 'POST', {'size': 300, 'sort': [{'detected_at': 'desc'}], '_source': ['alert_id', 'evidence.matched_fields', 'raw_event_refs']})['hits']['hits']
    for hit in alerts:
        matched = (hit['_source'].get('evidence') or {}).get('matched_fields') or {}
        for name, value in matched.items():
            if any(w in name for w in ('command_line', 'ScriptBlock', 'file.path')):
                secret.update(v for v in walk(value) if isinstance(v, str) and len(v) >= 24)
    check('real restricted values were found to look for', len(secret) > 20, f'{len(secret)} values, not printed')
    with Admin() as c:
        c.login()
        # About 300 requests: paced under the 240 a minute the server allows one session, so none is refused as too many.
        c.pace = 0.3
        blobs = [c.call('GET', p)[2] for p in ('/overview?range=30d', '/events?range=24h&size=100', '/events?range=7d&size=100&dataset=windows.powershell', '/alerts?range=30d&size=100', '/incidents?include_unverified=true&size=100', '/threat-intelligence?size=100', '/attack-paths?size=100', '/audit', '/health/components')]
        crawled = 0
        for hit in alerts[:120]:
            blobs.append(c.call('GET', f"/alerts/{hit['_source']['alert_id']}")[2])
            crawled += 1
            for ref in (hit['_source'].get('raw_event_refs') or [])[:1]:
                index, _, doc = ref.partition('/')
                blobs.append(c.call('GET', f'/events/{index}/{doc}')[2])
                crawled += 1
        rows = c.get('/incidents?include_unverified=true&size=100')[1]['rows']
        for row in rows:
            blobs.append(c.call('GET', f"/incidents/{row['incident_id']}")[2])
            crawled += 1
        for row in c.get('/attack-paths?size=100')[1]['rows'][:40]:
            blobs.append(c.call('GET', f"/attack-paths/{row['path_id']}")[2])
            blobs.append(c.call('GET', f"/attack-paths/{row['path_id']}/evidence")[2])
            crawled += 2
        print('INFO responses crawled', len(blobs), 'bytes', sum(len(b) for b in blobs))
        text = b'\n'.join(blobs).decode('utf-8', 'replace')
        # JSON escapes backslashes and quotes, so both forms are searched.
        hits = sum(1 for value in secret if value in text or json.dumps(value)[1:-1] in text)
        check('no real command line or script text appears in any response', hits == 0, f'{hits} of {len(secret)} found')
        check('a matched_fields key never appears', b'matched_fields"' not in text.encode())


def walk(value):
    if isinstance(value, dict):
        for item in value.values():
            yield from walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from walk(item)
    else:
        yield value


def as_role(route, method='GET', body=None):
    t.LOGIN = LOGIN
    return t.as_account(route, method, body)


def security():
    shown = run('systemctl', 'show', 'siem-dashboard', '--property=User,NoNewPrivileges,ProtectSystem,CapabilityBoundingSet,MemoryMax').stdout
    check('it runs as its own account', 'User=siem-dashboard' in shown)
    check('it can gain no privilege', 'NoNewPrivileges=yes' in shown and 'ProtectSystem=strict' in shown and 'cap_' not in shown)
    groups = run('id', '-nG', 'siem-dashboard').stdout.split()
    check('it holds no administrator or privileged group', set(groups) == {'siem-dashboard', 'linux', 'siem-analyst'}, str(groups))
    listening = [line for line in run('ss', '-tlnH').stdout.splitlines() if ':8443' in line]
    check('it listens on loopback only', len(listening) == 1 and '127.0.0.1:8443' in listening[0])
    others = run('ss', '-tlnH').stdout
    check('Kafka and OpenSearch stay on loopback', all(not any(f'{a}:{p}' in others for a in ('0.0.0.0', '*', '[::]')) for p in (9092, 9093, 9200, 9300)))
    as_it = lambda *w: run('runuser', '-u', 'siem-dashboard', '--', *w)
    files = run('find', '/home/linux/siem/config', '-xdev', '(', '-iname', '*key*', '-o', '-iname', 'opensearch-*.json', '-o', '-name', '*.curl', '-o', '-name', 'agent.env', ')', '-type', 'f', timeout=60).stdout.split()
    readable = [f for f in files if as_it('test', '-r', f).returncode == 0 and not f.startswith('/home/linux/siem/config/dashboard/')]
    check('no other key or login is readable', not readable, f'{len(files)} tried, readable: {readable}')
    for path in ('/home/linux/siem/data/correlation/correlator.db', '/home/linux/siem/data/verifier', '/home/linux/siem/data/kafka', '/home/linux/siem/data/asset/asset.db', '/root/.siem/opensearch-admin.curl', '/etc/shadow'):
        check(f'{path} is closed to it', as_it('test', '-r', path).returncode != 0)
    before = run('systemctl', 'show', 'siem-detector', '--property=MainPID', '--value').stdout
    tried = as_it('systemctl', 'restart', '--no-ask-password', 'siem-detector')
    check('it cannot restart a service', tried.returncode != 0 and run('systemctl', 'show', 'siem-detector', '--property=MainPID', '--value').stdout == before)
    check('the admin command is closed to it', as_it('test', '-x', ADMIN).returncode != 0)
    code = 'import socket,json,sys\ns=socket.socket(socket.AF_UNIX);s.connect(sys.argv[1]);s.sendall(json.dumps({"action":"metadata","asset":"x","name":"owner","value":"y"}).encode());s.shutdown(1);print(s.recv(999).decode())'
    reply = as_it('python3', '-c', code, '/run/siem-asset/control.sock').stdout
    check('the asset service refuses it administrator actions', 'not a member' in reply, reply[:70])

    status, body = as_role('/_cluster/health')
    check('the role cannot read cluster state', status == '403', status)
    status, body = as_role('/siem-windows-*/_search', 'POST', {'size': 50, 'sort': [{'@timestamp': 'desc'}]})
    data = json.loads(body)
    names = set()
    for hit in data['hits']['hits']:
        names |= {k for k in flat(hit['_source'])}
    check('events show only permitted fields', data['hits']['hits'] and not [n for n in names if any(w in n for w in ('command_line', 'script_block', 'message', 'file.', 'event_data', 'host.id'))], f'{len(names)} fields')
    for field in ('process.command_line', 'powershell.script_block.text', 'message'):
        status, body = as_role('/siem-windows-*/_count', 'POST', {'query': {'exists': {'field': field}}})
        check(f'{field} cannot be matched on', json.loads(body).get('count') == 0)
    status, body = as_role('/siem-alerts-*/_search', 'POST', {'size': 20})
    check('alert evidence values are withheld', not [h for h in json.loads(body)['hits']['hits'] if 'matched_fields' in (h['_source'].get('evidence') or {})])
    for label, route, method, payload in (('write an alert', '/siem-alerts-2026.11/_doc/dashtest', 'PUT', {'x': 1}), ('write an incident', '/siem-incidents-2026.11/_doc/dashtest', 'PUT', {'x': 1}), ('write an event', '/siem-windows-2026.11.02/_doc/dashtest', 'PUT', {'x': 1}), ('write a path', '/siem-attack-paths-2026.11/_doc/dashtest', 'PUT', {'x': 1}), ('write to health', '/siem-health-current/_doc/dashtest', 'PUT', {'x': 1}), ('delete an index', '/siem-alerts-2026.11', 'DELETE', None), ('delete by query', '/siem-alerts-*/_delete_by_query', 'POST', {'query': {'match_all': {}}}), ('read dead letters', '/siem-deadletter-*/_search', 'POST', {'size': 1}), ('read the audit log', '/security-auditlog-*/_search', 'POST', {'size': 1}), ('read the security index', '/.opendistro_security/_search', 'POST', {'size': 1}), ('use the security API', '/_plugins/_security/api/internalusers', 'GET', None), ('change settings', '/_cluster/settings', 'PUT', {'persistent': {'action.destructive_requires_name': True}}), ('change retention', '/_plugins/_ism/policies/siem-retention', 'DELETE', None)):
        status, _ = as_role(route, method, payload)
        check(f'the role cannot {label}', status in ('401', '403'), status)

    with Admin() as c:
        for path in ('/overview', '/events', '/alerts', '/incidents', '/assets', '/attack-paths', '/threat-intelligence', '/health/overview', '/audit'):
            check(f'{path} refuses without a session', c.get(path)[0] == 401)
        check('sign-in with the wrong password is refused', c.call('POST', '/auth/login', {'username': USER, 'password': 'wrong-password'})[0] == 401)
        c.login()
        check('the cookie is Secure, HttpOnly, SameSite=Strict and __Host-', all(w in c.last_cookie for w in ('__Host-siem_session=', 'Secure', 'HttpOnly', 'SameSite=Strict')))
        plain = urllib.request.Request('http://127.0.0.1:8443/')
        try:
            urllib.request.urlopen(plain, timeout=4)
            check('plain HTTP is refused', False)
        except Exception:
            check('plain HTTP is refused', True)
        old = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        old.check_hostname, old.verify_mode = False, ssl.CERT_NONE
        old.maximum_version = ssl.TLSVersion.TLSv1_1
        try:
            old.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
            http.client.HTTPSConnection('127.0.0.1', 8443, context=old, timeout=4).request('GET', '/')
            check('TLS below 1.2 is refused', False)
        except Exception:
            check('TLS below 1.2 is refused', True)

        # The real correlator's refusals, on a real incident. Refused means nothing changes.
        rows = c.get('/incidents?status=new&size=5')[1]['rows']
        check('there is a new incident to try', bool(rows))
        target = rows[0]['incident_id']
        before = api('/siem-incidents-*/_search', 'POST', {'size': 1, 'seq_no_primary_term': True, 'query': {'term': {'incident_id': target}}})['hits']['hits'][0]
        status, body, _ = c.call('POST', f'/incidents/{target}/status', {'state': 'closed', 'note': 'test'})
        check('the real correlator refuses an illegal move', status == 409, (body or {}).get('error', {}).get('message'))
        status, body, _ = c.call('POST', f'/incidents/{target}/status', {'state': 'false_positive'})
        check('the real correlator requires its note', status == 409 and 'note' in body['error']['message'], body['error']['message'])
        time.sleep(1)
        after = api('/siem-incidents-*/_search', 'POST', {'size': 1, 'seq_no_primary_term': True, 'query': {'term': {'incident_id': target}}})['hits']['hits'][0]
        check('the incident did not change', before['_seq_no'] == after['_seq_no'] and before['_source']['status'] == after['_source']['status'])
        rows = c.get('/audit')[1]['dashboard']['rows']
        check('the refusals are in the dashboard audit', sum(1 for r in rows if r['action'] == 'incident_status' and r['outcome'] == 'rejected') >= 2)
        check('the audit chain is intact', c.get('/audit/verify')[1]['dashboard']['intact'] is True)
        token = c.cookie
    blob = open(DB, 'rb').read()
    log = run('journalctl', '-u', 'siem-dashboard', '--no-pager', '-q', '-o', 'cat').stdout
    service = json.load(open(LOGIN))['password']
    check('the password is in no state or log', PASSWORD.encode() not in blob and PASSWORD not in log)
    check('the session token is in no state or log', token.encode() not in blob and token not in log)
    check('the OpenSearch login is in no state or log', service.encode() not in blob and service not in log)
    check('no password is in a command line', not [p for p in os.listdir('/proc') if p.isdigit() and os.path.exists(f'/proc/{p}/cmdline') and read_quiet(f'/proc/{p}/cmdline') and any(s.encode() in read_quiet(f'/proc/{p}/cmdline') for s in (service, PASSWORD))])
    check('the frontend holds no credentials', not run('grep', '-rlE', f'{service}|opensearch-dashboard', '/opt/siem-dashboard/static').stdout.strip())
    check('the login file is closed to others', oct(os.stat(LOGIN).st_mode)[-3:] == '640')
    check('the state file is closed to others', oct(os.stat(DB).st_mode)[-3:] == '600')


def read_quiet(path):
    try:
        return open(path, 'rb').read()
    except OSError:
        return b''


def flat(value, prefix=''):
    for key, item in value.items():
        if isinstance(item, dict):
            yield from flat(item, f'{prefix}{key}.')
        else:
            yield f'{prefix}{key}'


def counters():
    text = urllib.request.urlopen('http://127.0.0.1:9599/metrics', timeout=5).read().decode()
    import re
    return sum(float(m[1]) for m in re.finditer(r'^vector_component_received_events_total\{[^}]*component_id="siem_raw"[^}]*\} (\S+)', text, re.M))


def resilience():
    restarts = lambda: {u: run('systemctl', 'show', u, '--property=NRestarts', '--value').stdout.strip() for u in CORE}
    before = restarts()
    with Admin() as c:
        c.login()
        pid = run('systemctl', 'show', 'siem-dashboard', '--property=MainPID', '--value').stdout.strip()
        first = counters()
        os.kill(int(pid), signal.SIGKILL)
        check('it restarts by itself after a crash', bool(wait(lambda: run('systemctl', 'is-active', 'siem-dashboard').stdout.strip() == 'active' and run('systemctl', 'show', 'siem-dashboard', '--property=MainPID', '--value').stdout.strip() != pid, 60, 'restart')))
        check('a session survives the crash', bool(wait(lambda: quiet_status(c) == 200, 30, 'the session')))
        run('systemctl', 'stop', 'siem-dashboard')
        watermark = json.load(open('/home/linux/siem/data/status/detector/detector.json'))
        time.sleep(100)
        check('ingestion goes on with the dashboard stopped', counters() > first, f'{int(counters() - first)} events')
        later = json.load(open('/home/linux/siem/data/status/detector/detector.json'))
        check('detection goes on with the dashboard stopped', max(r['watermark_ms'] for r in later['rules']) > max(r['watermark_ms'] for r in watermark['rules']))
        overall = json.loads(run('runuser', '-u', 'linux', '--', 'siem-health', '--json', 'status').stdout)
        check('health monitoring goes on', overall['monitor_current'] is True, overall['overall'])
        run('systemctl', 'start', 'siem-dashboard')
        check('it comes back', bool(wait(lambda: quiet_status(c) == 200, 30, 'start')))
        check('no core service restarted', restarts() == before)
        check('the audit chain survived', c.get('/audit/verify')[1]['dashboard']['intact'] is True)


def quiet_status(c):
    try:
        return c.get('/incidents?size=1')[0]
    except OSError:
        return 0


def measure():
    usage = lambda: dict(line.split('=') for line in run('systemctl', 'show', 'siem-dashboard', '--property=CPUUsageNSec,MemoryCurrent,MemoryPeak').stdout.split())
    print('idle MiB', int(usage()['MemoryCurrent']) // 2 ** 20)
    first, began = int(usage()['CPUUsageNSec']), time.time()
    time.sleep(60)
    print(f"idle CPU {100 * (int(usage()['CPUUsageNSec']) - first) / 1e9 / (time.time() - began):.3f}% of one core")
    with Admin() as c:
        started = time.perf_counter()
        c.login()
        print(f'sign-in {(time.perf_counter() - started) * 1000:.0f} ms')
        routes = ['/overview?range=24h', '/overview?range=7d', '/events?range=24h&size=50', '/events?range=7d&size=50&dataset=windows.security', '/alerts?range=7d&size=50', '/incidents?size=50', '/assets', '/attack-paths', '/threat-intelligence', '/health/overview', '/health/components', '/audit', '/search?q=127.0.0.1']
        rows = c.get('/incidents?size=3')[1]['rows']
        routes += [f"/incidents/{r['incident_id']}" for r in rows]
        path = c.get('/attack-paths?size=1')[1]['rows'][0]['path_id']
        routes.append(f'/attack-paths/{path}')
        times = {r: [] for r in routes}
        first, began = int(usage()['CPUUsageNSec']), time.time()
        loads = 0
        while time.time() - began < 120:
            for route in routes:
                started = time.perf_counter()
                status = c.get(route)[0]
                times[route].append((time.perf_counter() - started) * 1000)
                loads += 1
                if status != 200:
                    print('INFO status', status, route.split('?')[0])
                time.sleep(0.5)
        spent = time.time() - began
        print(f"under steady use: {loads} requests in {spent:.0f} s, CPU {100 * (int(usage()['CPUUsageNSec']) - first) / 1e9 / spent:.1f}% of one core")
        for route, values in times.items():
            values.sort()
            print(f'{route.split("?")[0][:40]:<42} median {values[len(values) // 2]:.0f} ms, max {values[-1]:.0f} ms')
        print('memory MiB', int(usage()['MemoryCurrent']) // 2 ** 20, 'peak', int(usage().get('MemoryPeak', 0) or 0) // 2 ** 20)
    size = sum(os.path.getsize(os.path.join(d, f)) for d, _, names in os.walk('/opt/siem-dashboard/static') for f in names)
    print('frontend bytes', size, 'state bytes', os.path.getsize(DB))
    print(run('free', '-m').stdout.splitlines()[1])


if __name__ == '__main__':
    stage = sys.argv[1]
    if administrator() is not None:
        sys.exit('An administrator already exists. This suite needs a server with none, and never touches an existing account. Nothing was run.')
    {'real': real, 'leak': leak, 'security': security, 'resilience': resilience, 'measure': measure}[stage]()
    print(f'{stage}: {len(t.failures)} failed' + (f': {t.failures}' if t.failures else ''))
    sys.exit(1 if t.failures else 0)
