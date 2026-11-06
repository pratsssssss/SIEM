"""Live security checks, as root in WSL. Attempts what must be refused. Prints statuses, never secrets.

Usage: run_security.py <token file> <fake secret json>...
"""
import glob
import json
import os
import stat
import subprocess
import sys
import tempfile
import time

import run_e2e as e

API = 'https://127.0.0.1:9200'
CFG = '/home/linux/siem/config'
VECTOR_TLS = f'{CFG}/vector/tls'
VERIFIER_TLS = f'{CFG}/verifier/tls'


def ingest(path, method='GET', body=None):
    """Sends one request as siem_ingest, with the password in a private curl config file."""
    login = json.load(open(f'{CFG}/vector/opensearch-ingest.json'))
    with tempfile.NamedTemporaryFile('w', dir='/root/.siem', suffix='.curl', delete=False) as handle:
        os.fchmod(handle.fileno(), 0o600)
        handle.write(f'user = "{login["user"]}:{login["password"]}"\n')
    try:
        command = ['curl', '-sS', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '20', '--cacert', '/etc/opensearch/root-ca.pem', '-K', handle.name, '-X', method, API + path]
        if body is not None:
            command += ['-H', 'Content-Type: application/json', '-d', json.dumps(body)]
        return subprocess.run(command, capture_output=True, text=True).stdout
    finally:
        os.unlink(handle.name)


def tls(port, path, ca, cert=None, key=None):
    """Posts to a mutual TLS listener. A completed exchange returns an HTTP status."""
    command = ['curl', '-sS', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '10', '--cacert', ca, '-X', 'POST', '--data', '{}', f'https://127.0.0.1:{port}{path}']
    if cert:
        command += ['--cert', cert, '--key', key]
    return subprocess.run(command, capture_output=True, text=True).stdout.strip()


def mode(path):
    info = os.stat(path)
    return f'{stat.S_IMODE(info.st_mode):o} uid={info.st_uid} gid={info.st_gid}'


def main():
    secrets = e.tokens(sys.argv[1])[:2]
    for path in sys.argv[2:]:
        secrets.append(e.load_marker(path)['fake'])

    # OpenSearch ingest account.
    now = time.strftime('%Y.%m.%d', time.gmtime())
    for name, status in (
            ('read events', ingest('/siem-windows-*/_search')),
            ('read one index', ingest(f'/siem-windows-{now}/_search')),
            ('write another index', ingest('/other-index/_doc', 'POST', {'a': 1})),
            ('write the audit log', ingest('/security-auditlog-test/_doc', 'POST', {'a': 1})),
            ('delete an index', ingest(f'/siem-windows-{now}', 'DELETE')),
            ('change a role', ingest('/_plugins/_security/api/roles/siem_ingest', 'PUT', {})),
            ('change cluster settings', ingest('/_cluster/settings', 'PUT', {'persistent': {'action.destructive_requires_name': False}}))):
        e.check(f'siem_ingest cannot {name}', status == '403', status)

    # Mutual TLS. Each side's own certificate must not open the other listener.
    ca_verifier = f'{VECTOR_TLS}/verifier-ca.crt'
    # Controls: the right certificate completes TLS, so a refusal below cannot be a name or CA mistake.
    # An unknown path gets an HTTP answer, and reaches no handler.
    good = tls(9610, '/control', ca_verifier, f'{VECTOR_TLS}/vector.crt', f'{VECTOR_TLS}/vector.key')
    e.check('control: 9610 accepts the Vector certificate', good not in ('000', ''), good)
    good = tls(9611, '/control', f'{VERIFIER_TLS}/vector-ca.crt', f'{VERIFIER_TLS}/verifier.crt', f'{VERIFIER_TLS}/verifier.key')
    e.check('control: 9611 accepts the verifier certificate', good not in ('000', ''), good)
    e.check('9610 refuses no client certificate', tls(9610, '/v1/verify', ca_verifier) in ('000', ''), tls(9610, '/v1/verify', ca_verifier) or 'handshake refused')
    wrong = tls(9610, '/v1/verify', ca_verifier, f'{VERIFIER_TLS}/verifier.crt', f'{VERIFIER_TLS}/verifier.key')
    e.check('9610 refuses the verifier certificate', wrong in ('000', ''), wrong or 'handshake refused')
    plain = tls(9611, '/v1/verified', f'{VERIFIER_TLS}/vector-ca.crt')
    e.check('9611 refuses no client certificate', plain in ('000', ''), plain or 'handshake refused')
    forged = tls(9611, '/v1/verified', f'{VERIFIER_TLS}/vector-ca.crt', f'{VECTOR_TLS}/vector.crt', f'{VECTOR_TLS}/vector.key')
    e.check("9611 refuses Vector's own certificate, so it cannot post verified events", forged in ('000', ''), forged or 'handshake refused')

    # Keys and services.
    print('INFO key file', mode(f'{CFG}/verifier/field-keys.json'))
    info = os.stat(f'{CFG}/verifier/field-keys.json')
    e.check('field keys are 640 and owned by root', stat.S_IMODE(info.st_mode) == 0o640 and info.st_uid == 0)
    print('INFO ingest secret', mode(f'{CFG}/vector/opensearch-ingest.json'))
    print('INFO key sha256', subprocess.run(['sha256sum', f'{CFG}/verifier/field-keys.json'], capture_output=True, text=True).stdout.split()[0])
    for unit, wanted in (('seal-verifier', 'siem-verifier'), ('vector', 'vector')):
        shown = subprocess.run(['systemctl', 'show', unit, '-p', 'User', '-p', 'NoNewPrivileges', '-p', 'ProtectSystem', '-p', 'CapabilityBoundingSet', '--value'], capture_output=True, text=True).stdout.split('\n')
        e.check(f'{unit} runs unprivileged', wanted in shown and 'yes' in shown and 'strict' in shown, ' '.join(s for s in shown if s and len(s) < 20))
    user = subprocess.run(['id', '-nG', 'vector'], capture_output=True, text=True).stdout
    e.check('the aggregator user cannot read field keys', 'siem-verifier' not in user, user.strip())

    # Retention, budget and audit protection.
    settings = e.api('/_cluster/settings?include_defaults=true&flat_settings=true')
    effective = {**settings['defaults'], **settings['persistent'], **settings['transient']}
    e.check('wildcard deletes are refused', effective.get('action.destructive_requires_name') == 'true', effective.get('action.destructive_requires_name'))
    policy = e.api('/_plugins/_ism/policies/siem-retention')['policy']
    print('INFO retention conditions', json.dumps([t.get('conditions') for s in policy['states'] for t in s.get('transitions', [])]))
    e.check('retention is 7 days', '"7d"' in json.dumps(policy))
    explain = e.api('/_plugins/_ism/explain/siem-*?size=200')
    # The current inventory has one record per asset and no age limit, because a quiet asset is never removed (D45).
    indices = [k for k in explain if k.startswith('siem-') and k not in ('siem-assets-current', 'siem-asset-relationships', 'siem-health-current')]
    # Alert evidence outlives the events it cites, under its own 90-day policy (D26).
    wanted = lambda name: 'siem-health-metrics-retention' if name.startswith('siem-health-metrics-') else 'siem-health-retention' if name.startswith('siem-health-') else 'siem-attack-path-retention' if name.startswith('siem-attack-path') else 'siem-linux-retention' if name.startswith('siem-linux-') else 'siem-asset-retention' if name.startswith(('siem-asset-history-', 'siem-asset-audit-')) else 'siem-alert-retention' if name.startswith('siem-alerts-') else 'siem-enrichment-retention' if name.startswith('siem-enrichment-') else 'siem-incident-retention' if name.startswith('siem-incident') else 'siem-retention'
    bad = [k for k in indices if (explain[k].get('policy_id') or explain[k].get('index.plugins.index_state_management.policy_id')) != wanted(k)]
    e.check('every SIEM index is under retention', indices and not bad, f'{len(indices)} indices, {len(bad)} without')
    alert_policy = json.dumps(e.api('/_plugins/_ism/policies/siem-alert-retention')['policy'])
    e.check('alert evidence retention is 90 days', '"90d"' in alert_policy)
    audit = e.api('/_plugins/_ism/explain/security-auditlog-*?size=200')
    names = [k for k in audit if k.startswith('security-auditlog-')]
    print(f'INFO audit indices {len(names)}')
    guarded = [k for k in names if (audit[k].get('policy_id') or audit[k].get('index.plugins.index_state_management.policy_id'))]
    e.check('audit indices are under the protection policy', names and len(guarded) == len(names), f'{len(guarded)} of {len(names)}')
    guard = json.load(open('/home/linux/siem/data/monitor/disk-guard.json'))
    e.check('disk guard reports the real drive, and is healthy', guard.get('status') == 'OK' and guard.get('ingest_stopped') is False, f"free {guard.get('free_gib')} GiB, data {guard.get('data_gib')} GiB, dead {guard.get('dead_gib')} GiB")
    kept = e.api('/_cat/indices/siem-*?format=json&bytes=b&h=store.size')
    print(f"INFO stored bytes {sum(int(r['store.size']) for r in kept)}")

    # Plaintext in logs. Counts only.
    sources = {'journal': subprocess.run(['journalctl', '-u', 'vector', '-u', 'seal-verifier', '-u', 'kafka', '-u', 'opensearch', '--no-pager', '-q'], capture_output=True, text=True, errors='replace').stdout}
    for path in glob.glob('/var/log/kafka/*.log') + glob.glob('/var/log/opensearch/*.log') + glob.glob('/home/linux/siem/data/monitor/*'):
        if os.path.isfile(path):
            sources[path] = open(path, errors='replace').read()
    hits = sum(secret in text for secret in secrets for text in sources.values())
    e.check('no secret token appears in any log', hits == 0, f'{hits} hits across {len(sources)} sources')
    dead_docs = e.search({'match_all': {}}, 1000, pattern='siem-deadletter-*')['hits']['hits']
    allowed = {'channel', 'dlq', 'event_id', 'event_uid', 'kafka', 'record_id', 'sealed', 'source_type', 'timestamp'}
    extra = sorted({k for d in dead_docs for k in d['_source']} - allowed)
    e.check('dead letters hold only routing facts and ciphertext', not extra, extra or len(dead_docs))
    e.check('no secret token appears in a dead letter', not any(secret in json.dumps(d['_source']) for secret in secrets for d in dead_docs))
    print(f'\n{len(e.failures)} failed' if e.failures else '\nall passed')
    return 1 if e.failures else 0


if __name__ == '__main__':
    raise SystemExit(main())
