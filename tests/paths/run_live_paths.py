"""Live attack path tests, as root in WSL against the running stack. Prints counts and statuses, never content.

Usage: run_live_paths.py real         paths built from stored real evidence, each checked against the source
       run_live_paths.py simulate     a controlled sequence on the Linux host, by a temporary account
       run_live_paths.py security     the account, the socket, hostile input, what is stored
       run_live_paths.py resilience   restart, crash, outages, and the pipeline with this service stopped
       run_live_paths.py measure      memory, CPU, latency and growth

The simulation is safe event generation with real programs. It is not an intrusion, and Kali is not used.
"""
import json
import os
import secrets
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
import livelib as t  # noqa: E402

check, api, wait, systemctl = t.check, t.api, t.wait, t.systemctl
LOGIN = '/home/linux/siem/config/path/opensearch-path.json'
ACCOUNT = f'siem15t{t.RUN}'
TESTER = 'pathtest'


def run(*words, **options):
    return subprocess.run(words, capture_output=True, text=True, stdin=subprocess.DEVNULL if 'input' not in options else None, timeout=options.pop('timeout', 120), **options)


def as_user(user, *words):
    return run('runuser', '-u', user, '--', 'siem-path', *words)


def path(*words):
    done = as_user('linux', *words)
    return json.loads(done.stdout) if done.stdout.strip().startswith(('{', '[')) else {'_error': done.stderr, '_code': done.returncode}


def as_service(route, method='GET', body=None, login=LOGIN):
    t.LOGIN = login
    return t.as_account(route, method, body)


def seq(index):
    return {h['_id']: h['_seq_no'] for h in api(f'/{index}/_search', 'POST', {'size': 1000, 'seq_no_primary_term': True, '_source': False, 'query': {'match_all': {}}})['hits']['hits']}


def settled():
    return bool(wait(lambda: (lambda s: s.get('queue') == 0 and sum(s.get('output_backlog', {'x': 1}).values()) == 0)(path('status')), 300, 'the queue'))


def real():
    incidents, alerts = seq('siem-incidents-*'), seq('siem-alerts-*')
    assets = seq('siem-assets-current')
    check('the queue has drained', settled(), str(path('status').get('paths')))
    rows = path('list')
    stored = api('/siem-incidents-*/_search', 'POST', {'size': 200, '_source': ['incident_id', 'hosts', 'status', 'rules.id'], 'query': {'match_all': {}}})['hits']['hits']
    check('every incident has a path', {h['_source']['incident_id'] for h in stored} <= {r['seed_id'] for r in rows if r['seed_kind'] == 'incident'}, f'{len(rows)} paths, {len(stored)} incidents')
    by_seed = {r['seed_id']: r for r in rows}

    # Each edge, against its source, using the administrator account and not the service's own reads.
    edges = evidence = absent = 0
    untraceable = []
    real_paths = [r for r in rows if r['tier'] != 'insufficient_evidence']
    for row in real_paths:
        for item in path('evidence', row['path_id']):
            edges += 1
            if not item['evidence'] or not item['reason']:
                untraceable.append(item['edge'])
            for record in item['evidence']:
                if record['kind'] == 'event':
                    evidence += 1
                    if api(f"/{record['index']}/_doc/{record['id']}").get('found') is not True:
                        absent += 1
    check('every edge has evidence and a reason', edges > 0 and not untraceable, f'{edges} edges on {len(real_paths)} paths')
    check('every cited event exists in its index', evidence > 0 and absent == 0, f'{evidence} references, {absent} absent')

    synthetic = [h['_source'] for h in stored if h['_source'].get('hosts') and all(str(x).endswith('test-host') for x in h['_source']['hosts'])]
    tiers = {by_seed[i['incident_id']]['tier'] for i in synthetic if i['incident_id'] in by_seed}
    check('test incidents with no stored alerts claim nothing', tiers <= {'insufficient_evidence'}, f'{len(synthetic)} incidents')
    def of(rule, host):
        return [h['_source'] for h in stored if rule in [r['id'] for r in h['_source'].get('rules', [])] and host in h['_source'].get('hosts', [])]

    # Windows: real failed logons, then a success.
    burst = of('cor-logon-after-burst', t.HOST)
    check('a real Windows incident exists for failures then success', bool(burst))
    if burst:
        found = path('explain', by_seed[burst[0]['incident_id']]['path_id'])
        check('T1110 is shown', 'T1110' in found['attack_techniques'])
        check('the asset is the Phase 14 record', found['affected_assets'][0]['resolved'] is True and found['affected_assets'][0]['display'] == t.HOST)
        check('the identity is namespaced', all('\\' in i['display'] for i in found['identities']), str([i['quality'] for i in found['identities']]))
        check('no conclusion is drawn', found['conclusion'].startswith('none'))
        graph = path('graph', by_seed[burst[0]['incident_id']]['path_id'])
        ids = {n['asset_id'] for n in graph['nodes'] if n['type'] == 'asset' and n.get('asset_id')}
        check('the node carries the stable asset id', all(i.startswith('ast-') for i in ids) and bool(ids))

    # Linux: a real privileged group incident.
    linux = of('cor-linux-privileged-account', f'{t.HOST}-wsl')
    check('a real Linux incident exists', bool(linux))
    if linux:
        found = path('explain', by_seed[linux[0]['incident_id']]['path_id'])
        gaps = [g['gap'] for g in found['not_visible']]
        check('Linux process telemetry is stated as missing', 'linux_process_execution' in gaps)
        check('an analyst false positive is shown', found['analyst_status'] == 'false_positive')
        check('and lowers the path', any('false positive' in w for w in found['why_this_tier']), found['tier'])
        check('the asset is the SIEM host', found['affected_assets'][0]['resolved'] is True)
        graph = path('graph', by_seed[linux[0]['incident_id']]['path_id'])
        check('no Linux process edge exists', not [e for e in graph['edges'] if e['type'] in ('spawned', 'executed')])
        check('root joined no other run', len({i['display'] for i in found['identities'] if 'siem13t' in i['display']}) <= 1, f"{len(found['identities'])} identities, {found['unrelated_events_left_out']} events left out")

    # Windows process lineage.
    powershell = of('cor-powershell-child', t.HOST)
    if powershell:
        graph = path('graph', by_seed[powershell[0]['incident_id']]['path_id'])
        spawned = [e for e in graph['edges'] if e['type'] == 'spawned']
        check('real Sysmon lineage is present', bool(spawned), str(len(spawned)))
        check('intelligence is its own class', all(e['class'] == 'threat_intelligence' for e in graph['edges'] if e['type'] == 'associated_with'), str(len([e for e in graph['edges'] if e['type'] == 'associated_with'])))
    multi = [r for r in real_paths if len({a['display'] for a in path('explain', r['path_id'])['affected_assets']}) > 1]
    check('no path spans Windows and Linux, since no reliable link exists', not multi)
    check('no path holds an identity link', not [1 for r in real_paths for e in path('graph', r['path_id'])['edges'] if e['type'] == 'same_identity'])

    # Stored.
    api('/siem-attack-path*/_refresh', 'POST')
    check('paths are in OpenSearch', api('/siem-attack-paths-*/_count')['count'] == len(rows), str(len(rows)))
    check('nodes and edges are in OpenSearch', api('/siem-attack-path-graph-*/_count')['count'] > edges // 2, str(api('/siem-attack-path-graph-*/_count')['count']))
    check('history is in OpenSearch', api('/siem-attack-path-history-*/_count')['count'] >= len(rows))
    policy = api('/_plugins/_ism/explain/siem-attack-path*')
    check('retention is attached', all((v.get('policy_id') or v.get('index.plugins.index_state_management.policy_id')) == 'siem-attack-path-retention' for k, v in policy.items() if k.startswith('siem-attack')), str(len(policy)))
    check('hash chains hold', path('validate').get('intact') is True)
    sample = real_paths[0]['path_id']
    check('validation reads the evidence again', path('validate', sample).get('counts', {}).get('verified', 0) > 0)

    # Nothing it read was touched.
    after = seq('siem-incidents-*')
    check('no incident was changed', all(after.get(k) == v for k, v in incidents.items()), f'{len(incidents)} incidents')
    after = seq('siem-alerts-*')
    check('no alert was changed', all(after.get(k) == v for k, v in alerts.items()), f'{len(alerts)} alerts')
    after = seq('siem-assets-current')
    written = [k for k, v in assets.items() if after.get(k, -1) < v]
    check('no asset was lost', not written, f'{len(assets)} assets')


def simulate():
    """Real programs, a temporary account, and no intrusion. Then the path is read back."""
    start = int(time.time() * 1000)
    password = secrets.token_urlsafe(18)
    try:
        run('useradd', '--create-home', '--shell', '/bin/bash', ACCOUNT)
        subprocess.run(['chpasswd'], input=f'{ACCOUNT}:{password}\n', capture_output=True, text=True)
        run('usermod', '-aG', 'sudo', ACCOUNT)
        done = subprocess.run(['runuser', '-u', ACCOUNT, '--', 'sudo', '-S', '-k', '/bin/true'], input=password + '\n', capture_output=True, text=True, timeout=30)
        check('the account really used sudo', done.returncode == 0)
        subprocess.run(['crontab', '-u', ACCOUNT, '-'], input='# synthetic test, runs nothing\n', capture_output=True, text=True)
        run('crontab', '-u', ACCOUNT, '-r')
        run('logger', '-t', 'sudo', f' {ACCOUNT} : TTY=pts/9 ; PWD=/ ; USER=root ; COMMAND=/forged')
    finally:
        run('crontab', '-u', ACCOUNT, '-r')
        run('gpasswd', '-d', ACCOUNT, 'sudo')
        for _ in range(20):
            run('loginctl', 'terminate-user', ACCOUNT)
            if run('userdel', '--remove', ACCOUNT).returncode == 0:
                break
            time.sleep(3)
    check('the test account is gone', run('id', ACCOUNT).returncode != 0)

    def incident():
        hits = api('/siem-incidents-*/_search', 'POST', {'size': 20, '_source': ['incident_id', 'status'], 'sort': [{'updated_at': 'desc'}], 'query': {'bool': {'filter': [{'term': {'rules.id': 'cor-linux-privileged-account'}}, {'range': {'updated_at': {'gte': start, 'format': 'epoch_millis'}}}]}}})['hits']['hits']
        return hits[0]['_source'] if hits else None
    found = wait(incident, 300, 'incident')
    check('an incident formed from the real activity', bool(found))
    if not found:
        return
    def built():
        reply = path('incident', found['incident_id'])
        names = [i['display'] for i in reply.get('identities', [])] if isinstance(reply, dict) else []
        return reply if any(ACCOUNT in n for n in names) else None
    reply = wait(built, 300, 'path')
    check('a path holds the account', bool(reply))
    if not reply:
        return
    explained = path('explain', reply['path_id'])
    stages = {s['name'] for s in path('timeline', reply['path_id']) if isinstance(s, dict)}
    for name in ('account_created', 'privileged_group_change', 'identity_transition', 'new_account_used'):
        check(f'stage found: {name}', name in stages)
    check('the timeline is in time order', [s['at'] for s in path('timeline', reply['path_id'])] == sorted(s['at'] for s in path('timeline', reply['path_id'])))
    check('the techniques are exact', {'T1136.001', 'T1098', 'T1548.003', 'T1078.003'} <= set(explained['attack_techniques']), str(sorted(explained['attack_techniques'])))
    check('the forged line is in no edge', 'forged' not in json.dumps(path('evidence', reply['path_id'])))
    check('other accounts are left out', not [i for i in explained['identities'] if 'siem13t' in i['display']], f"{explained['unrelated_events_left_out']} left out")
    check('the tier is stated with reasons', bool(explained['why_this_tier']), explained['tier'])
    check('process telemetry is named as missing', 'linux_process_execution' in [g['gap'] for g in explained['not_visible']])
    check('there are next steps', bool(explained['next_steps']))
    check('no password is stored', password not in json.dumps(path('evidence', reply['path_id'])))
    before = path('history', reply['path_id'])
    check('history records versions', len(before) >= 1, str(len(before)))
    run('runuser', '-u', 'linux', '--', 'siem-incident', 'status', found['incident_id'], 'false_positive', '--note', 'controlled test of attack paths')
    def lowered():
        return len(path('history', reply['path_id'])) > len(before)
    check('an analyst decision adds a version', bool(wait(lowered, 200, 'new version')))
    item = path('explain', reply['path_id'])
    check('and lowers the tier, with the reason', item['analyst_status'] == 'false_positive' and any('false positive' in w for w in item['why_this_tier']), item['tier'])


def security():
    deny = lambda route, method='GET', body=None: as_service(route, method, body)[0] == '403'
    for name in ('siem-windows-2026.10.31', 'siem-linux-2026.10.31', 'siem-alerts-2026.10', 'siem-incidents-2026.10', 'siem-enrichment-2026.10', 'siem-assets-current', 'siem-incident-audit-2026.10'):
        check(f'{name}: no writes', deny(f'/{name}/_doc/pathtest', 'PUT', {'x': 1}))
    check('no delete of its own index', deny('/siem-attack-paths-2026.11', 'DELETE'))
    check('no document delete', deny('/siem-attack-paths-2026.11/_doc/x', 'DELETE'))
    check('no cluster settings', deny('/_cluster/settings', 'PUT', {'persistent': {'action.auto_create_index': 'true'}}))
    check('no security configuration', deny('/_plugins/_security/api/roles'))
    check('no audit log', deny('/security-auditlog-*/_search', 'POST', {'size': 0}))
    check('no asset history or audit', deny('/siem-asset-audit-*/_search', 'POST', {'size': 0}))
    check('no direct document read', deny('/siem-windows-2026.10.31/_doc/x'))
    for index, banned in (('siem-windows-*', ('winlog.event_data', 'process.command_line', 'message', 'file.path', 'powershell')), ('siem-linux-*', ('message', 'process.command_line', 'journald.cursor')), ('siem-alerts-*', ('evidence', 'description'))):
        status, payload = as_service(f'/{index}/_search', 'POST', {'size': 100, 'query': {'match_all': {}}})
        text = json.dumps([h['_source'] for h in json.loads(payload)['hits']['hits']])
        check(f'{index}: field security holds', status == '200' and not [b for b in banned if f'"{b.split(".")[-1]}":' in text and b != 'evidence'], f'{len(text)} characters read')
    _, payload = as_service('/siem-windows-*/_count', 'POST', {'query': {'exists': {'field': 'process.command_line'}}})
    check('a command line cannot even be matched', json.loads(payload)['count'] == 0)
    for name in ('detector', 'correlator', 'enricher', 'asset'):
        status, _ = as_service('/siem-attack-paths-*/_search', 'POST', {'size': 1}, f'/home/linux/siem/config/{name}/opensearch-{name}.json')
        check(f'{name} cannot read paths', status == '403')
    t.LOGIN = LOGIN

    info = os.stat(LOGIN)
    check('the login file is private', oct(info.st_mode & 0o777) == '0o640' and info.st_uid == 0)
    check('the state folder is private', oct(os.stat('/home/linux/siem/data/path').st_mode & 0o777) == '0o700')
    check('the socket is limited', oct(os.stat('/run/siem-path/control.sock').st_mode & 0o777) == '0o660')
    secret = json.load(open(LOGIN))['password'].encode()
    hits = sum(1 for base, _, files in os.walk(t.ROOT) for f in files if '.git' not in base and secret in open(os.path.join(base, f), 'rb').read())
    check('the password is in no repository file', hits == 0)
    check('or the journal', secret.decode() not in run('journalctl', '-u', 'siem-path', '--no-pager').stdout)
    shown = systemctl('show', 'siem-path', '-p', 'User', '-p', 'NoNewPrivileges', '-p', 'ProtectSystem', '-p', 'MemoryMax')
    check('the unit is unprivileged and limited', 'User=siem-path' in shown and 'NoNewPrivileges=yes' in shown and 'ProtectSystem=strict' in shown and 'MemoryMax=134217728' in shown)
    groups = set(run('id', '-nG', 'siem-path').stdout.split())
    check('the service has no admin group', groups == {'siem-path', 'linux', 'siem-analyst'}, ' '.join(sorted(groups)))
    pid = systemctl('show', 'siem-path', '-p', 'MainPID', '--value')
    check('it listens on no network port', f'pid={pid},' not in run('ss', '-tlnp').stdout)
    check('it has no Kafka consumer group', 'path' not in run('/opt/kafka/bin/kafka-consumer-groups.sh', '--bootstrap-server', '127.0.0.1:9092', '--list').stdout)
    topics = run('/opt/kafka/bin/kafka-topics.sh', '--bootstrap-server', '127.0.0.1:9092', '--list').stdout.split()
    check('no Kafka topic was added', sorted(x for x in topics if not x.startswith('__')) == ['siem-alerts', 'siem-incidents', 'siem-raw-logs'])
    listen = run('ss', '-tln').stdout
    for port in (9092, 9093, 9200, 9300):
        check(f'port {port} stays on loopback', f'0.0.0.0:{port}' not in listen and f'*:{port}' not in listen)

    rows = path('list')
    sample = next(r['path_id'] for r in rows if r['tier'] != 'insufficient_evidence')
    run('useradd', '--system', '--no-create-home', '--shell', '/usr/sbin/nologin', '--groups', 'siem-analyst', TESTER)
    try:
        check('an analyst can read', as_user(TESTER, 'list').returncode == 0)
        check('an analyst can add a note', as_user(TESTER, 'note', sample, 'controlled security test').returncode == 0)
        done = as_user(TESTER, 'rebuild', sample, '--reason', 'x')
        check('an analyst cannot rebuild', done.returncode == 1 and 'siem-path-admin' in done.stderr)
        done = as_user(TESTER, 'link-identities', 'identity:a', 'identity:b', '--reason', 'x')
        check('an analyst cannot link identities', done.returncode == 1)
        check('the refusals are audited', any(r['action'] == 'refused' and r['actor'] == TESTER for r in path('audit')))
    finally:
        run('userdel', TESTER)
    check('a stranger cannot open the socket', as_user('nobody', 'list').returncode == 2)
    done = run('siem-path', 'list')
    check('root is refused', done.returncode == 1 and 'not a member' in done.stderr)
    check('an administrator can rebuild, and it is audited', 'result' in path('rebuild', sample, '--reason', 'controlled security test') and path('audit', sample)[-1]['action'] == 'rebuild')
    for text in ("'; DROP TABLE paths; --", '$(reboot)', '../../etc/passwd', '%', '_zz_', '{"$ne": 1}', 'a\x1b[2Jb'):
        done = as_user('linux', 'search', text)
        check(f'search is literal: {text[:10]!r}', done.returncode == 0 and json.loads(done.stdout) == [])
    for text in ('../../etc/passwd', "x' OR '1'='1", 'a' * 300):
        check('an incident id is checked first', as_user('linux', 'incident', text).returncode == 1)

    # What is stored.
    docs = api('/siem-attack-path-graph-*/_search', 'POST', {'size': 2000, 'query': {'term': {'doc_type': 'edge'}}})['hits']['hits']
    keys = {k for h in docs for e in h['_source'].get('evidence', []) for k in e.get('fields', {})}
    check('evidence holds named fields only', keys <= {'dataset', 'action', 'kind', 'logon_type', 'source_ip', 'destination_ip', 'service', 'group', 'package', 'attribution', 'rule', 'severity', 'confidence', 'joins', 'verdict', 'type', 'by', 'resolved'}, f'{len(docs)} edges read')
    text = json.dumps([h['_source'] for h in docs])
    check('no command line or message is stored', 'command_line' not in text and '"message"' not in text)
    check('no secret shape is stored', not any(word in text.lower() for word in ('password=', 'passwd=', 'api_key=', 'begin rsa', 'begin openssh')))


def resilience():
    incidents = seq('siem-incidents-*')
    rows = path('list')
    sample = next(r['path_id'] for r in rows if r['tier'] != 'insufficient_evidence')

    # Stopped altogether: the pipeline carries on.
    systemctl('stop', 'siem-path')
    now = int(time.time() * 1000)
    user = f'pathstopped{t.RUN}'
    t.publish(t.fake_alert(t.GROUP, now - 300000, 'first', user, 21), t.fake_alert(t.SCHTASKS, now - 60000, 'second', user, 22))
    check('an incident forms with the service stopped', bool(wait(lambda: t.correlator_has(user), 90, 'incident')))
    for unit in ('siem-detector', 'siem-enricher', 'siem-correlator', 'siem-asset', 'siem-linux-agent', 'vector', 'seal-verifier', 'kafka', 'opensearch'):
        check(f'{unit} stays up', systemctl('is-active', unit) == 'active')
    systemctl('reset-failed', 'siem-path')
    systemctl('start', 'siem-path')
    check('it returns', bool(wait(lambda: 'status' in path('status'), 60, 'socket')))
    check('paths survive', len(path('list')) >= len(rows))
    check('it catches up with what it missed', bool(wait(lambda: any(user in json.dumps(path('explain', r['path_id'])) or r['seed_kind'] == 'incident' and r['seed_id'] in [i['incident_id'] for i in t.correlator_has(user)] for r in path('list')[:10]), 200, 'catch up')))

    # A crash.
    subprocess.run(['systemctl', 'kill', '-s', 'SIGKILL', 'siem-path'], check=True)
    time.sleep(3)
    check('it restarts after a kill', bool(wait(lambda: systemctl('is-active', 'siem-path') == 'active' and 'status' in path('status'), 90, 'restart')))
    check('history is intact', path('validate').get('intact') is True)

    # The asset service is gone.
    systemctl('stop', 'siem-asset')
    check('a path can be rebuilt without the asset service', 'result' in path('rebuild', sample, '--reason', 'controlled outage test'))
    systemctl('reset-failed', 'siem-asset')
    systemctl('start', 'siem-asset')

    # OpenSearch goes away.
    systemctl('stop', 'opensearch')
    report = wait(lambda: (lambda r: r if r.get('status') == 'WARN' and 'OpenSearch' in r.get('message', '') else None)(path('status')), 120, 'WARN')
    check('an outage shows in health', bool(report), str((report or {}).get('opensearch')))
    check('stored paths can still be read', path('show', sample).get('path_id') == sample)
    check('validation refuses rather than guessing', path('validate', sample).get('_code') == 1)
    check('a note can still be added', 'by' in path('note', sample, 'controlled outage test'))
    systemctl('start', 'opensearch')
    wait(lambda: api('/_cluster/health').get('status') in ('green', 'yellow'), 180, 'OpenSearch')
    check('it recovers by itself', bool(wait(lambda: path('status').get('opensearch') == 'ok', 960, 'recovery')))
    check('its output drains', bool(wait(lambda: sum(path('status')['output_backlog'].values()) == 0, 120, 'drain')))
    after = seq('siem-incidents-*')
    check('no earlier incident was changed by this service', all(after.get(k, 0) >= v for k, v in incidents.items()), f'{len(incidents)} incidents')
    for item in t.correlator_has(user):
        run('runuser', '-u', 'linux', '--', 'siem-incident', 'status', item['incident_id'], 'false_positive', '--note', 'synthetic attack path test')


def measure():
    show = lambda: dict(line.split('=', 1) for line in systemctl('show', 'siem-path', '-p', 'MemoryCurrent', '-p', 'MemoryPeak', '-p', 'CPUUsageNSec').splitlines())
    before = show()
    time.sleep(60)
    after = show()
    print(f"memory {int(after['MemoryCurrent']) // 1048576} MiB, peak {int(after['MemoryPeak']) // 1048576} MiB, limit 128 MiB")
    print(f"CPU over 60 s {(int(after['CPUUsageNSec']) - int(before['CPUUsageNSec'])) / 1e6:.0f} ms")
    print('state', run('du', '-sh', '/home/linux/siem/data/path').stdout.split()[0])
    print([(i['index'], i['docs.count'], i['store.size']) for i in api('/_cat/indices/siem-attack*?h=index,docs.count,store.size&format=json')])
    rows = path('list')
    sizes = []
    samples = sorted((r for r in rows if r['tier'] != 'insufficient_evidence'), key=lambda r: r['path_id'])[:8]
    for row in samples:
        started = time.perf_counter()
        reply = path('rebuild', row['path_id'], '--reason', 'measuring')
        spent = time.perf_counter() - started
        graph = path('graph', row['path_id'])
        sizes.append((round(spent, 2), len(graph['nodes']), len(graph['edges'])))
        del reply
    print('rebuild seconds, nodes, edges (whole command):', sizes)
    print('largest graph: nodes', max(s[1] for s in sizes), 'edges', max(s[2] for s in sizes))
    for words in (('list',), ('explain', samples[0]['path_id']), ('evidence', samples[0]['path_id'])):
        started = time.perf_counter()
        path(*words)
        print(f'{words[0]}: {(time.perf_counter() - started) * 1000:.0f} ms for the whole command')
    print(run('free', '-m').stdout.splitlines()[1])


if __name__ == '__main__':
    stage = sys.argv[1]
    {'real': real, 'simulate': simulate, 'security': security, 'resilience': resilience, 'measure': measure}[stage]()
    print(f'{stage}: {len(t.failures)} failed' + (f': {t.failures}' if t.failures else ''))
    sys.exit(1 if t.failures else 0)
