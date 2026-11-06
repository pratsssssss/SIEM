"""Live security and independence checks, as root in WSL. Prints statuses, never secrets.

Usage: run_enricher_security.py <marker.json> <during.txt>
"""
import json
import os
import stat
import subprocess
import sys
import tempfile
import time

import run_live_enrichment as live
from run_live_enrichment import api, check, failures, hits, search

SECRET = '/home/linux/siem/config/enricher/opensearch-enricher.json'
API = 'https://127.0.0.1:9200'


def enricher(path, method='GET', body=None):
    login = json.load(open(SECRET))
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


def main():
    info = json.load(open(sys.argv[1], encoding='utf-8-sig'))
    during = open(sys.argv[2], encoding='utf-8-sig').read().strip()

    # The alert from the outage: made with the enricher stopped, and enriched only after it returned.
    event = hits(search('siem-windows-*', {'bool': {'filter': [{'term': {'event.code': '106'}}, {'wildcard': {'file.path': f'*{during}*'}}]}}, 1))
    check('the outage event was collected', len(event) == 1)
    alert = hits(search('siem-alerts-*', {'term': {'source_event_ids': event[0]['_id']}}, 1)) if event else []
    check('an alert was created while the enricher was stopped', len(alert) == 1)
    if alert:
        alert_id = alert[0]['_source']['alert_id']
        check('that alert reached Kafka', any(k == alert_id for k, _, _ in live.kafka_rows()))
        document = hits(search('siem-enrichment-*', {'term': {'alert_id': alert_id}}, 1))
        check('it was enriched after the service returned', len(document) == 1)
        if document:
            check('enrichment came after the alert', document[0]['_source']['enriched_at'] > alert[0]['_source']['detected_at'], document[0]['_source']['status'])

    now = time.strftime('%Y.%m.%d', time.gmtime())
    check('siem_enricher can search events', enricher('/siem-windows-*/_search?size=0') == '200')
    check('siem_enricher can search alerts', enricher('/siem-alerts-*/_search?size=0') == '200')
    for name, status in (
            ('write events', enricher(f'/siem-windows-{now}/_doc', 'POST', {'a': 1})),
            ('write alerts', enricher(f'/siem-alerts-{now[:7]}/_doc', 'POST', {'a': 1})),
            ('delete an event index', enricher(f'/siem-windows-{now}', 'DELETE')),
            ('delete alert evidence', enricher(f'/siem-alerts-{now[:7]}', 'DELETE')),
            ('read dead letters', enricher('/siem-deadletter-*/_search')),
            ('read the audit log', enricher('/security-auditlog-*/_search')),
            ('write another index', enricher('/other-index/_doc', 'POST', {'a': 1})),
            ('change a role', enricher('/_plugins/_security/api/roles/siem_enricher', 'PUT', {})),
            ('change cluster settings', enricher('/_cluster/settings', 'PUT', {'persistent': {'action.destructive_requires_name': False}})),
            ('list users', enricher('/_plugins/_security/api/internalusers'))):
        check(f'siem_enricher cannot {name}', status == '403', status)

    info_file = os.stat(SECRET)
    check('its login file is 640 and owned by root', stat.S_IMODE(info_file.st_mode) == 0o640 and info_file.st_uid == 0)
    check('its data folder is private', stat.S_IMODE(os.stat('/home/linux/siem/data/enrichment').st_mode) == 0o700)
    show = subprocess.run(['systemctl', 'show', 'siem-enricher', '-p', 'User', '-p', 'NoNewPrivileges', '-p', 'ProtectSystem', '-p', 'MemoryMax', '--value'], capture_output=True, text=True).stdout.split('\n')
    check('the service is unprivileged', 'siem-enricher' in show and 'yes' in show and 'strict' in show, ' '.join(s for s in show if s and len(s) < 16))
    groups = subprocess.run(['id', '-nG', 'siem-enricher'], capture_output=True, text=True).stdout
    check('it cannot read field keys', 'siem-verifier' not in groups, groups.strip())
    check('no provider key is configured', not os.path.exists('/home/linux/siem/config/enricher/provider-keys.json'))

    pid = subprocess.run(['systemctl', 'show', 'siem-enricher', '-p', 'MainPID', '--value'], capture_output=True, text=True).stdout.strip()
    sockets = [line.split()[4] for line in subprocess.run(['ss', '-tnp'], capture_output=True, text=True).stdout.splitlines() if f'pid={pid},' in line]
    check('with no keys, the service holds no outside connection', not [s for s in sockets if not s.startswith(('127.', '[::ffff:127.'))], f'{len(sockets)} sockets')
    listens = [line for line in subprocess.run(['ss', '-ltnp'], capture_output=True, text=True).stdout.splitlines() if f'pid={pid},' in line]
    check('it opens no listening port', not listens)
    journal = subprocess.run(['journalctl', '-u', 'siem-enricher', '-u', 'siem-enricher-feeds', '--no-pager', '-q'], capture_output=True, text=True, errors='replace').stdout
    check('the test secret is not in its log', info['secret'] not in journal)
    policy = api('/_plugins/_ism/explain/siem-enrichment-*?size=10')
    attached = [k for k, v in policy.items() if k.startswith('siem-enrichment-') and (v.get('policy_id') or v.get('index.plugins.index_state_management.policy_id')) == 'siem-enrichment-retention']
    check('enrichment indices are under retention', bool(attached), attached)
    print(f'{len(failures)} failed' if failures else 'all passed')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
