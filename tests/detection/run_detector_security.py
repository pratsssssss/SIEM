"""Live security checks for the detection engine, as root in WSL. Prints statuses, never secrets.

Usage: run_detector_security.py <token file> <fake secret json>...
"""
import json
import os
import stat
import subprocess
import sys
import tempfile
import time

import detector_probe as probe

API = 'https://127.0.0.1:9200'
SECRET = '/home/linux/siem/config/detector/opensearch-detector.json'
failures = []


def check(name, ok, detail=''):
    print(('PASS ' if ok else 'FAIL ') + name + (f' ({detail})' if detail != '' else ''), flush=True)
    if not ok:
        failures.append(name)


def detector(path, method='GET', body=None):
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


def tokens(paths):
    found = [line.strip() for line in open(paths[0], encoding='utf-8-sig') if line.strip()][:2]
    return found + [json.load(open(p, encoding='utf-8-sig'))['fake'] for p in paths[1:]]


def main():
    now = time.strftime('%Y.%m.%d', time.gmtime())
    check('siem_detector can search events', detector('/siem-windows-*/_search?size=0') == '200')
    for name, status in (
            ('write events', detector(f'/siem-windows-{now}/_doc', 'POST', {'a': 1})),
            ('delete an event index', detector(f'/siem-windows-{now}', 'DELETE')),
            ('read dead letters', detector('/siem-deadletter-*/_search')),
            ('read the audit log', detector('/security-auditlog-*/_search')),
            ('read its own alerts back', detector('/siem-alerts-*/_search')),
            ('delete alert evidence', detector(f"/siem-alerts-{now[:7]}", 'DELETE')),
            ('write another index', detector('/other-index/_doc', 'POST', {'a': 1})),
            ('change a role', detector('/_plugins/_security/api/roles/siem_detector', 'PUT', {})),
            ('change cluster settings', detector('/_cluster/settings', 'PUT', {'persistent': {'action.destructive_requires_name': False}})),
            ('list users', detector('/_plugins/_security/api/internalusers'))):
        check(f'siem_detector cannot {name}', status == '403', status)

    info = os.stat(SECRET)
    check('its login file is 640 and owned by root', stat.S_IMODE(info.st_mode) == 0o640 and info.st_uid == 0)
    info = os.stat('/home/linux/siem/data/detector/state.db')
    folder = os.stat('/home/linux/siem/data/detector')
    check('its state is private to the service', stat.S_IMODE(folder.st_mode) == 0o700, oct(stat.S_IMODE(folder.st_mode)))
    show = subprocess.run(['systemctl', 'show', 'siem-detector', '-p', 'User', '-p', 'NoNewPrivileges', '-p', 'ProtectSystem', '-p', 'CapabilityBoundingSet', '-p', 'MemoryMax', '--value'], capture_output=True, text=True).stdout.split('\n')
    check('the service is unprivileged', 'siem-detector' in show and 'yes' in show and 'strict' in show and '268435456' in show, ' '.join(s for s in show if s and len(s) < 16))
    groups = subprocess.run(['id', '-nG', 'siem-detector'], capture_output=True, text=True).stdout
    check('it cannot read field keys', 'siem-verifier' not in groups, groups.strip())

    pid = subprocess.run(['systemctl', 'show', 'siem-detector', '-p', 'MainPID', '--value'], capture_output=True, text=True).stdout.strip()
    sockets = subprocess.run(['ss', '-tnp'], capture_output=True, text=True).stdout
    mine = [line for line in sockets.splitlines() if f'pid={pid},' in line]
    remote = [line.split()[4] for line in mine if not line.split()[4].startswith(('127.', '[::ffff:127.'))]
    check('every connection it holds is on loopback', not remote, f'{len(mine)} sockets')
    listens = [line for line in subprocess.run(['ss', '-ltnp'], capture_output=True, text=True).stdout.splitlines() if f'pid={pid},' in line]
    check('it opens no listening port', not listens, len(listens))

    rows = [(k, v) for k, _, v in probe.kafka_rows() if len(k) == 32]
    text = '\n'.join(v for _, v in rows)
    print(f'INFO alert messages scanned: {len(rows)}')
    hits = sum(token in text for token in tokens(sys.argv[1:]))
    check('no canary or test secret in siem-alerts', hits == 0, hits)
    plain = sum(name in text for name in ('"process.command_line": ["', '"process.parent.command_line": ["', '"file.path": ["', '"registry.data.strings": ["'))
    check('restricted fields are never plain text in siem-alerts', plain == 0, plain)
    withheld = text.count('"withheld": true')
    check('restricted values are present as digests', withheld > 0, withheld)
    journal = subprocess.run(['journalctl', '-u', 'siem-detector', '--no-pager', '-q'], capture_output=True, text=True, errors='replace').stdout
    check('no canary or test secret in its log', sum(t in journal for t in tokens(sys.argv[1:])) == 0)
    print(f'{len(failures)} failed' if failures else 'all passed')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
