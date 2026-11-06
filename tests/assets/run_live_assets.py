"""Live asset tests, as root in WSL against the running stack. Prints counts and statuses, never event content.

Usage: run_live_assets.py real         the inventory, checked against independent readings of real data
       run_live_assets.py security     the account, the socket, hostile files, on an isolated instance
       run_live_assets.py resilience   outage, crash, restart, and the pipeline with this service stopped
       run_live_assets.py measure      memory, CPU, disk and query cost

Hostile files go to a temporary store, so nothing synthetic enters the real inventory. The one exception is the
registered test asset in `security`, tagged `synthetic-test` and retired at the end of the stage.
"""
import glob
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
import livelib as t  # noqa: E402

sys.path.insert(0, '/opt/siem-asset/app')
from siem_asset import identity, schema  # noqa: E402
from siem_asset.service import OpenSearch, Service  # noqa: E402
from siem_asset.store import Store  # noqa: E402

DB = '/home/linux/siem/data/asset/asset.db'
LOGIN = '/home/linux/siem/config/asset/opensearch-asset.json'
CONFIG = '/home/linux/siem/config/asset/asset.yaml'
DROP = t.site('SIEM_WINDOWS_INVENTORY')
POWERSHELL = '/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'
TESTER = 'assettest'
check, api, wait, systemctl = t.check, t.api, t.wait, t.systemctl


def run_as(user, *words):
    """No shell, so hostile text arrives as one argument."""
    done = subprocess.run(['runuser', '-u', user, '--', 'siem-asset', *words], capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
    return done.returncode, done.stdout, done.stderr


def analyst(*words):
    code, out, err = run_as('linux', *words)
    return json.loads(out) if out.strip().startswith(('{', '[')) else {'_text': out, '_error': err, '_code': code}


def sql(query, *args):
    db = sqlite3.connect(f'file:{DB}?mode=ro', uri=True)
    rows = db.execute(query, args).fetchall()
    db.close()
    return rows


def as_service(path, method='GET', body=None, login=LOGIN):
    t.LOGIN = login
    return t.as_account(path, method, body)


def live_count():
    """Retired synthetic test records stay on file, labelled, as any asset does."""
    return len([a for a in analyst('list') if not a['hostname'].startswith('synthetic-')])


def real_assets():
    rows = analyst('list')
    return next(a for a in rows if a['platform'] == 'windows'), next(a for a in rows if a['platform'] == 'linux')


def powershell(command):
    return subprocess.run([POWERSHELL, '-NoProfile', '-NonInteractive', '-Command', command], capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL).stdout.strip()


def real():
    windows, wsl = real_assets()
    check('two assets, from real sources only', live_count() == 2 and {r[0] for r in sql("SELECT source FROM assets WHERE hostname NOT LIKE 'synthetic-%'")} <= {'snapshot:windows-local', 'snapshot:linux-local'})
    view = analyst('show', windows['asset_id'])
    host_view = analyst('show', wsl['asset_id'])
    facts = {f['name']: f['value'] for f in view['facts']}

    # Windows, read again by a different route.
    caption = powershell('(Get-CimInstance Win32_OperatingSystem).Caption')
    build = powershell('(Get-CimInstance Win32_OperatingSystem).BuildNumber')
    name = powershell('$env:COMPUTERNAME')
    check('Windows operating system matches a direct reading', caption == facts['os.name'] and build == facts['os.build'], build)
    check('Windows host name matches a direct reading', name.lower() == windows['hostname'])
    machine = powershell("(Get-ItemProperty 'HKLM:/SOFTWARE/Microsoft/Cryptography').MachineGuid")
    check('the stored identifier is the digest of the real machine GUID', identity.token('windows_machine_guid', machine) in [i['digest'] for i in view['identity']['machine_identifiers']])
    services = int(powershell('(Get-CimInstance Win32_Service | Measure-Object).Count'))
    current = len([r for r in analyst('services', windows['asset_id']) if r['source'].startswith('snapshot')])
    check('Windows service count is close to a direct reading', abs(services - current) <= 8, f'direct {services}, inventory {current}. Per-user services share one record')
    check('security tools are seen running', {'windefend', 'sysmon64', 'vector'} <= {x['service'] for x in view['security']['tools'] if x['state'] == 'running'}, str(len(view['security']['tools'])))
    check('Defender state is recorded with provenance', any(f['name'] == 'security.defender_realtime' and f['source'] == 'snapshot:windows-local' for f in view['facts']))

    # The SIEM host.
    packages = subprocess.run("dpkg-query -W -f='${db:Status-Status}\\n' | grep -c '^installed$'", shell=True, capture_output=True, text=True).stdout.strip()
    check('package count matches dpkg', int(packages) == host_view['counts']['software'], packages)
    check('the machine id digest matches', identity.token('linux_machine_id', open('/etc/machine-id').read().strip()) in [i['digest'] for i in host_view['identity']['machine_identifiers']])
    open_ports = {x['port'] for x in host_view['security']['exposure']['listeners_beyond_loopback']}
    check('Kafka and OpenSearch are not listed as exposed', not open_ports & {9092, 9093, 9200, 9300}, f'{len(open_ports)} beyond loopback')
    listed = subprocess.run(['ss', '-tlnH'], capture_output=True, text=True).stdout
    check('the kernel agrees that those ports are bound to loopback', all('0.0.0.0:' + str(p) not in listed and '*:' + str(p) not in listed for p in (9092, 9093, 9200, 9300)))

    # Telemetry, against the same indices read by the administrator account.
    query = {'size': 0, 'aggs': {'first': {'min': {'field': '@timestamp'}}, 'last': {'max': {'field': '@timestamp'}}, 'hosts': {'cardinality': {'field': 'host.name'}},
                                 'users': {'filter': {'terms': {'event.code': ['4624', '4625']}}, 'aggs': {'names': {'terms': {'field': 'user.name', 'size': 500}}}},
                                 'processes': {'filter': {'bool': {'filter': [{'term': {'event.dataset': 'windows.sysmon'}}, {'term': {'event.code': '1'}}]}}, 'aggs': {'names': {'terms': {'field': 'process.name', 'size': 1000}}}}}}
    truth = api('/siem-windows-*/_search', 'POST', query)['aggregations']
    check('telemetry names one host, as the inventory does', truth['hosts']['value'] == 1)
    check('first seen matches the earliest event', view['lifecycle']['first_seen'] == truth['first']['value_as_string'], view['lifecycle']['first_seen'])
    check('last seen is recent', time.time() * 1000 - schema.ms(view['lifecycle']['last_seen']) < 3600000 * 2)
    want = {b['key'].lower() for b in truth['users']['names']['buckets']} - {'-'}
    have = {u['name'].lower() for u in analyst('users', windows['asset_id'])['observed_users']}
    check('every authenticating user was found', want <= have, f'{len(have)} of {len(want)}')
    want = {b['key'].lower() for b in truth['processes']['names']['buckets']}
    have = {p['name'].lower() for p in analyst('software', windows['asset_id'])['seen_running']}
    check('processes seen running match', want <= have, f'{len(have)} of {len(want)}')
    owner = analyst('users', windows['asset_id'])
    check('no owner is invented from observed users', owner['assigned_owner'] is None)
    rows = analyst('relationships', windows['asset_id'])
    check('every relationship has provenance, confidence and basis', all(r.get('provenance') and r.get('confidence') and r.get('basis') for r in rows), f'{len(rows)} relationships')

    # Incidents and alerts.
    incidents = api('/siem-incidents-*/_search', 'POST', {'size': 200, '_source': ['incident_id', 'hosts'], 'query': {'term': {'hosts': t.HOST}}})['hits']['hits']
    linked = {r['target']['id'] for r in rows if r['type'] == 'involved_in'}
    check('real incidents link to the Windows asset', {h['_source']['incident_id'] for h in incidents} <= linked, f'{len(linked)} incidents')
    check('none link to the SIEM host', not {h['_source']['incident_id'] for h in incidents} & {r['target']['id'] for r in analyst('relationships', wsl['asset_id']) if r['type'] == 'involved_in'})
    sample = incidents[0]['_source']['incident_id']
    context = analyst('context', '--incident', sample)
    check('context for a real incident names the asset', context['assets'][0]['asset_id'] == windows['asset_id'] and context['live_data'] == 'ok')
    check('it separates facts from inferences', 'confirmed' in context['assets'][0] and 'inferred' in context['assets'][0] and 'stated_by_administrator' in context['assets'][0])
    alert = api('/siem-alerts-*/_search', 'POST', {'size': 1, '_source': ['alert_id'], 'query': {'terms': {'host': [t.HOST.upper(), t.HOST]}}})['hits']['hits'][0]['_source']['alert_id']
    context = analyst('context', '--alert', alert)
    check('context for a real alert names the asset', context['assets'] and context['assets'][0]['asset_id'] == windows['asset_id'])
    ip = next(a['ip'] for a in view['network']['addresses'] if a['current'])
    check('lookup by address finds the asset', analyst('context', '--ip', ip)['assets'][0]['asset_id'] == windows['asset_id'])

    # Stored in OpenSearch.
    api('/siem-asset*/_refresh', 'POST')
    check('current records are stored', api('/siem-assets-current/_count', 'POST', {'query': {'bool': {'must_not': {'prefix': {'hostname': 'synthetic-'}}}}})['count'] == 2)
    check('relationships are stored', api('/siem-asset-relationships/_count')['count'] == sql('SELECT COUNT(*) FROM relationships')[0][0], str(sql('SELECT COUNT(*) FROM relationships')[0][0]))
    check('history is stored', api('/siem-asset-history-*/_count')['count'] == sql('SELECT COUNT(*) FROM changes')[0][0], str(sql('SELECT COUNT(*) FROM changes')[0][0]))
    check('the mapped template applied', api('/siem-assets-current/_mapping')['siem-assets-current']['mappings'].get('dynamic') in (False, 'false'))
    doc = api(f"/siem-assets-current/_doc/{windows['asset_id']}")['_source']
    check('the record lists no programs or accounts', not {'software', 'users', 'services'} & set(doc), str(sorted(doc))[:0])
    check('no vulnerability is claimed', doc['vulnerability_status'] == 'not_assessed')
    policies = api('/_plugins/_ism/policies/siem-asset-retention')
    check('retention is 365 days, for history and audit only', policies['policy']['states'][0]['transitions'][0]['conditions']['min_index_age'] == '365d' and 'siem-assets-current' not in str(policies['policy']['ism_template']))
    check('chains are intact', analyst('validate')['intact'] is True)


def security():
    windows, _ = real_assets()
    deny = lambda path, method='GET', body=None: as_service(path, method, body)[0] == '403'

    # The account.
    event = {'x': 1}
    for name in ('siem-windows-2026.10.31', 'siem-alerts-2026.10', 'siem-incidents-2026.10', 'siem-enrichment-2026.10', 'siem-incident-audit-2026.10'):
        check(f'{name}: no writes', deny(f'/{name}/_doc/assettest', 'PUT', event))
    check('no delete of its own record', deny(f"/siem-assets-current/_doc/{windows['asset_id']}", 'DELETE'))
    check('no delete of its own index', deny('/siem-assets-current', 'DELETE'))
    check('no delete of history', deny('/siem-asset-history-2026.10', 'DELETE'))
    check('no cluster settings', deny('/_cluster/settings', 'PUT', {'persistent': {'action.auto_create_index': 'true'}}), as_service('/_cluster/settings')[0])
    check('no security configuration', deny('/_plugins/_security/api/roles'))
    check('no ISM', deny('/_plugins/_ism/policies'))
    check('no audit log', deny('/security-auditlog-*/_search', 'POST', {'size': 0}))
    check('no dead letters', deny('/siem-deadletter-*/_search', 'POST', {'size': 0}))
    check('no direct document read', deny('/siem-windows-2026.10.31/_doc/x'))
    status, payload = as_service('/siem-windows-*/_search', 'POST', {'size': 50, 'query': {'term': {'event.code': '1'}}})
    fields = set()

    def names(node, path=''):
        for key, value in node.items():
            full = f'{path}.{key}' if path else key
            if isinstance(value, dict):
                names(value, full)
            else:
                fields.add(full)
    for hit in json.loads(payload)['hits']['hits']:
        names(hit['_source'])
    check('field level security returns allowed fields only', status == '200' and fields and not [f for f in fields if f.startswith(('winlog', 'message', 'file.')) or 'command_line' in f], f'{len(fields)} fields')
    _, payload = as_service('/siem-windows-*/_count', 'POST', {'query': {'exists': {'field': 'process.command_line'}}})
    check('a command line cannot even be matched', json.loads(payload)['count'] == 0)
    _, payload = as_service('/siem-windows-*/_search', 'POST', {'size': 1, 'query': {'wildcard': {'winlog.event_data.CommandLine': '*'}}})
    check('nor can raw event data', json.loads(payload)['hits']['hits'] == [])
    check('the reader role is held by nobody', api('/_plugins/_security/api/rolesmapping/siem_asset_reader').get('siem_asset_reader', {}).get('users', []) == [])
    for login in glob.glob('/home/linux/siem/config/*/opensearch-*.json'):
        # siem_path reads current assets on purpose: Phase 14 is its source of asset identity (D51).
        if 'asset' in login or 'opensearch-path' in login:
            continue
        status, _ = as_service('/siem-assets-current/_search', 'POST', {'size': 1}, login)
        check(f"{login.split('/')[-1]}: cannot read the inventory", status == '403')
    t.LOGIN = LOGIN

    # Files and the unit.
    info = lambda path: stat.S_IMODE(os.stat(path).st_mode)
    check('the login file is private', info(LOGIN) == 0o640 and os.stat(LOGIN).st_uid == 0)
    check('the state folder is private', info('/home/linux/siem/data/asset') == 0o700)
    check('the socket is limited to its group', info('/run/siem-asset/control.sock') == 0o660)
    secret = json.load(open(LOGIN))['password'].encode()
    repository = t.ROOT
    hits = sum(1 for base, dirs, files in os.walk(repository) for f in files if '.git' not in base and secret in open(os.path.join(base, f), 'rb').read())
    check('the password is in no file in the repository', hits == 0)
    logged = subprocess.run(['journalctl', '-u', 'siem-asset', '--no-pager'], capture_output=True, text=True).stdout
    check('the password is not in the journal', secret.decode() not in logged)
    shown = systemctl('show', 'siem-asset', '-p', 'User', '-p', 'NoNewPrivileges', '-p', 'CapabilityBoundingSet', '-p', 'ProtectSystem', '-p', 'MemoryMax')
    check('the unit is unprivileged and limited', 'User=siem-asset' in shown and 'NoNewPrivileges=yes' in shown and 'ProtectSystem=strict' in shown and 'MemoryMax=134217728' in shown)
    topics = subprocess.run(['/opt/kafka/bin/kafka-topics.sh', '--bootstrap-server', '127.0.0.1:9092', '--list'], capture_output=True, text=True, timeout=60).stdout
    check('no Kafka topic was added', 'asset' not in topics, f'{len(topics.split())} topics')

    # The socket, with a real analyst who is not an administrator.
    subprocess.run(['useradd', '--system', '--no-create-home', '--shell', '/usr/sbin/nologin', '--groups', 'siem-analyst', TESTER], check=True)
    try:
        code, out, err = run_as(TESTER, 'list')
        check('an analyst can read', code == 0)
        before = sql("SELECT COUNT(*) FROM audit WHERE action = 'refused'")[0][0]
        for words in (('metadata', windows['asset_id'], 'criticality', 'critical'), ('retire', windows['asset_id'], '--reason', 'x'), ('resolve', 'cfl-x', 'merge', '--reason', 'x'), ('register', 'evil-host')):
            code, out, err = run_as(TESTER, *words)
            check(f'an analyst cannot {words[0]}', code == 1 and 'siem-asset-admin' in err)
        check('each refusal is audited with the caller', sql("SELECT COUNT(*) FROM audit WHERE action = 'refused' AND actor = ?", TESTER)[0][0] >= 4 and sql("SELECT COUNT(*) FROM audit WHERE action = 'refused'")[0][0] == before + 4)
        check('criticality was not changed', sql("SELECT COUNT(*) FROM attributes WHERE name = 'criticality' AND asset_id = ?", windows['asset_id'])[0][0] == 0)
    finally:
        subprocess.run(['userdel', TESTER], check=False)
    check('a stranger cannot open the socket', run_as('nobody', 'list')[0] == 2)
    done = subprocess.run(['siem-asset', 'list'], capture_output=True, text=True)
    check('root is refused, because audit must name a person', done.returncode == 1 and 'not a member' in done.stderr)

    # Hostile text, through the real command line, with no shell in between.
    for text in ("'; DROP TABLE assets; --", '$(reboot)', '../../etc/passwd', '%', '_zz_', '{"$ne": 1}', 'a\x1b[2Jb'):
        code, out, err = run_as('linux', 'search', text)
        check(f'search is literal: {text[:12]!r}', code == 0 and json.loads(out) == [])
    for text in ('../../etc/passwd', "x' OR '1'='1", 'a' * 500):
        check('an incident id is checked first', run_as('linux', 'context', '--incident', text)[0] == 1)
    check('assets are still there', live_count() == 2)

    # Administration, on a synthetic record that is labelled and then retired.
    name = f'synthetic-test-{t.RUN}'
    created = analyst('register', name, '--type', 'virtual_machine', '--platform', 'linux')
    asset = created['asset_id']
    check('an administrator can register a machine', created['status'] == 'declared')
    check('and label it', analyst('metadata', asset, 'tags', 'synthetic-test').get('tags') == ['synthetic-test'])
    check('and set criticality', analyst('metadata', asset, 'criticality', 'high').get('criticality') == 'high')
    check('a bad value is refused', analyst('metadata', asset, 'criticality', 'huge').get('_code') == 1)
    check('it is audited with who and what', [r for r in analyst('audit', asset) if r['action'] == 'metadata'][-1]['actor'] == 'linux')
    wait(lambda: api('/siem-asset-audit-*/_refresh', 'POST') and api('/siem-asset-audit-*/_count', 'POST', {'query': {'term': {'asset_id': asset}}})['count'] >= 3, 90, 'audit shipped')
    check('and reaches the audit index', api('/siem-asset-audit-*/_count', 'POST', {'query': {'term': {'asset_id': asset}}})['count'] >= 3)
    check('the criticality change is flagged', any(c['kind'] == 'criticality_changed' and c['category'] == 'security' for c in analyst('history', asset)))
    check('it can be retired with a reason', analyst('retire', asset, '--reason', 'synthetic test record').get('status') == 'retired')
    for change in analyst('changes', '--unreviewed'):
        if change['asset_id'] == asset:
            analyst('ack', str(change['seq']), '--note', 'synthetic test record')
    check('and the record stays', analyst('show', asset)['status'] == 'retired')

    # Hostile files, on a separate instance with its own store.
    folder = tempfile.mkdtemp(dir='/tmp')
    try:
        store = Store(os.path.join(folder, 'asset.db'))
        drop = os.path.join(folder, 'drop')
        os.mkdir(drop)
        login = json.load(open(LOGIN))
        search = OpenSearch('https://127.0.0.1:9200', '/etc/opensearch/root-ca.pem', login['user'], login['password'])
        logs = []
        work = Service(store, search, {'drop_folder': drop, 'collect_local': False, 'security_services': {'windefend': 'Defender'}}, log=logs.append)
        real_file = glob.glob(f'{DROP}/*.json')[0]
        shutil.copy(real_file, os.path.join(drop, 'real.json'))
        work.scan_drop()
        check('a copy of the real snapshot is applied', len(store.assets()) == 1)
        victim = store.assets()[0]['asset_id']
        raw = json.load(open(real_file, encoding='utf-8-sig'))
        forged = {**raw, 'collected_at': schema.iso(int(time.time() * 1000)), 'identifiers': {'windows_machine_guid': 'f0f0f0f0-0000-4000-8000-000000000000'}, 'os': {**raw['os'], 'build': '1'}}
        json.dump(forged, open(os.path.join(drop, 'forged.json'), 'w'))
        work.scan_drop()
        check('a forged machine identifier does not take over the asset', len(store.assets()) == 2 and store.attribute(victim, 'os.build', 'observed') == raw['os']['build'])
        check('it opens a conflict for a person', store.conflicts()[0]['kind'] == 'duplicate_hostname')
        rows = [{'name': text, 'version': text, 'publisher': text} for text in ("'; DROP TABLE items; --", '$(reboot)', '<script>', '\x1b[2J', 'password=hunter2')]
        hostile = {**raw, 'collected_at': schema.iso(int(time.time() * 1000) + 1), 'software': rows, 'services': raw['services'] + [{'name': '`id`', 'state': 'Running', 'start': 'Auto', 'binary': 'C:\\a\\b.exe --token=abc'}]}
        json.dump(hostile, open(os.path.join(drop, 'hostile.json'), 'w'))
        work.scan_drop()
        text = json.dumps([store.items(a['asset_id'], 'software') for a in store.assets()] + [store.items(a['asset_id'], 'service') for a in store.assets()])
        check('hostile names are stored as cleaned text', 'hunter2' not in text and 'token=abc' not in text and '\\u001b' not in text)
        check('tables are intact', store.db.execute('SELECT COUNT(*) FROM items').fetchone()[0] > 0)
        os.symlink('/etc/shadow', os.path.join(drop, 'link.json'))
        open(os.path.join(drop, 'big.json'), 'wb').write(b'x' * (schema.MAX_SNAPSHOT_BYTES + 1))
        open(os.path.join(drop, 'weird;name.json'), 'w').write('{}')
        before = work.state['rejected_reports']
        work.scan_drop()
        check('a link, an oversized file and a bad name are refused', work.state['rejected_reports'] - before == 3, str(work.state['rejected_reports'] - before))
        old = {**raw, 'collected_at': schema.iso(schema.ms(raw['collected_at']) - 86400000)}
        for name_ in ('forged.json', 'hostile.json', 'link.json', 'big.json', 'weird;name.json', 'real.json'):
            os.unlink(os.path.join(drop, name_))
        json.dump(old, open(os.path.join(drop, 'old.json'), 'w'))
        before = work.state['rejected_reports']
        work.scan_drop()
        check('an older report is refused as a replay', work.state['rejected_reports'] == before + 1)
        store.close()
    finally:
        shutil.rmtree(folder, ignore_errors=True)
    check('no hostile file reached the real inventory', live_count() == 2)


def resilience():
    alerts_before = api('/siem-alerts-*/_count')['count']
    seq = lambda index: {h['_id']: h['_seq_no'] for h in api(f'/{index}/_search', 'POST', {'size': 500, 'seq_no_primary_term': True, '_source': False, 'query': {'match_all': {}}})['hits']['hits']}
    incidents = seq('siem-incidents-*')
    alerts = seq('siem-alerts-*')
    changes = sql('SELECT COUNT(*) FROM changes')[0][0]
    windows, _ = real_assets()

    # Stopped altogether: incidents form, including for a machine the inventory has never heard of.
    systemctl('stop', 'siem-asset')
    check('the service stops', systemctl('is-active', 'siem-asset') != 'active')
    now = int(time.time() * 1000)
    user = f'assetstopped{t.RUN}'
    t.publish(t.fake_alert(t.GROUP, now - 300000, 'first', user, 11), t.fake_alert(t.SCHTASKS, now - 60000, 'second', user, 12))
    check('an incident forms with the service stopped, on an unknown host', bool(wait(lambda: t.correlator_has(user), 90, 'incident')))
    for unit in ('siem-detector', 'siem-enricher', 'siem-correlator', 'vector', 'seal-verifier', 'kafka', 'opensearch'):
        check(f'{unit} stays up', systemctl('is-active', unit) == 'active')
    count = lambda: api('/siem-windows-*/_count', 'POST', {'query': {'range': {'event.ingested': {'gte': 'now-3m'}}}})['count']
    check('events keep arriving', bool(wait(count, 120, 'fresh events')), str(count()))
    systemctl('reset-failed', 'siem-asset')
    systemctl('start', 'siem-asset')
    check('the service returns', bool(wait(lambda: 'status' in analyst('status'), 60, 'socket')))
    check('assets survive a restart', live_count() == 2)
    check('history survives a restart', sql('SELECT COUNT(*) FROM changes')[0][0] >= changes and analyst('validate')['intact'] is True)

    # A crash.
    subprocess.run(['systemctl', 'kill', '-s', 'SIGKILL', 'siem-asset'], check=True)
    time.sleep(3)
    check('the service restarts after a kill', bool(wait(lambda: systemctl('is-active', 'siem-asset') == 'active' and 'status' in analyst('status'), 90, 'restart')))
    check('nothing is lost', live_count() == 2 and analyst('validate')['intact'] is True)

    # OpenSearch goes away under it.
    systemctl('stop', 'opensearch')
    report = wait(lambda: (lambda r: r if r.get('status') == 'WARN' and 'OpenSearch' in r.get('message', '') else None)(analyst('status')), 120, 'WARN')
    check('an OpenSearch outage shows in health', bool(report), str((report or {}).get('opensearch')))
    check('the inventory still answers', analyst('show', windows['asset_id']).get('asset_id') == windows['asset_id'])
    check('context says live data is missing', 'unavailable' in analyst('context', '--incident', next(iter(incidents))).get('live_data', ''))
    name = f'synthetic-outage-{t.RUN}'
    created = analyst('register', name)
    check('an administrator can still act', 'asset_id' in created)
    check('the change waits to be sent', wait(lambda: analyst('status')['backlog']['audit'] > 0, 30, 'backlog') is True)
    systemctl('start', 'opensearch')
    wait(lambda: api('/_cluster/health').get('status') in ('green', 'yellow'), 180, 'OpenSearch')
    check('the service recovers by itself', bool(wait(lambda: analyst('status').get('opensearch') == 'ok', 960, 'recovery')))
    check('the backlog drains', bool(wait(lambda: sum(analyst('status')['backlog'].values()) == 0, 120, 'backlog')))
    analyst('retire', created['asset_id'], '--reason', 'synthetic outage test record')
    for change in analyst('changes', '--unreviewed'):
        if change['asset_id'] == created['asset_id']:
            analyst('ack', str(change['seq']), '--note', 'synthetic test record')

    # What it read, it did not touch.
    after = seq('siem-incidents-*')
    check('no incident was changed', all(after.get(k) == v for k, v in incidents.items()), f'{len(incidents)} incidents')
    after = seq('siem-alerts-*')
    check('no alert was changed', all(after.get(k) == v for k, v in alerts.items()), f'{len(alerts)} alerts')
    check('no alert was lost', api('/siem-alerts-*/_count')['count'] >= alerts_before)
    for item in t.correlator_has(user):
        subprocess.run(['runuser', '-u', 'linux', '--', 'siem-incident', 'status', item['incident_id'], 'false_positive', '--note', 'synthetic asset test'], capture_output=True, stdin=subprocess.DEVNULL)


def measure():
    show = lambda: dict(line.split('=', 1) for line in systemctl('show', 'siem-asset', '-p', 'MemoryCurrent', '-p', 'MemoryPeak', '-p', 'CPUUsageNSec').splitlines())
    before = show()
    time.sleep(60)
    after = show()
    print(f"memory {int(after['MemoryCurrent']) // 1048576} MiB, peak {int(after['MemoryPeak']) // 1048576} MiB, limit 128 MiB")
    print(f"CPU over 60 s {(int(after['CPUUsageNSec']) - int(before['CPUUsageNSec'])) / 1e6:.0f} ms")
    print('state', subprocess.run(['du', '-sh', '/home/linux/siem/data/asset'], capture_output=True, text=True).stdout.split()[0])
    print(api('/_cat/indices/siem-asset*?h=index,docs.count,store.size&format=json'))
    windows, _ = real_assets()
    for words in (('list',), ('show', windows['asset_id']), ('search', 'defender'), ('history', windows['asset_id']), ('relationships', windows['asset_id']), ('context', windows['asset_id'])):
        started = time.perf_counter()
        analyst(*words)
        print(f"{words[0]}: {(time.perf_counter() - started) * 1000:.0f} ms for the whole command, including starting it")
    login = json.load(open(LOGIN))
    search = OpenSearch('https://127.0.0.1:9200', '/etc/opensearch/root-ca.pem', login['user'], login['password'])
    folder = tempfile.mkdtemp(dir='/tmp')
    try:
        store = Store(os.path.join(folder, 'asset.db'))
        work = Service(store, search, {'collect_local': False, 'telemetry': {'backfill_days': 1}})
        started = time.perf_counter()
        work.telemetry.run(store, 0)
        print(f'one 24 hour telemetry window on real data: {(time.perf_counter() - started) * 1000:.0f} ms')
        store.close()
    finally:
        shutil.rmtree(folder, ignore_errors=True)
    print(subprocess.run(['free', '-m'], capture_output=True, text=True).stdout.splitlines()[1])


if __name__ == '__main__':
    stage = sys.argv[1]
    {'real': real, 'security': security, 'resilience': resilience, 'measure': measure}[stage]()
    print(f'{stage}: {len(t.failures)} failed' + (f': {t.failures}' if t.failures else ''))
    sys.exit(1 if t.failures else 0)
