"""Shared helpers for the live suites, run as root in WSL against the running stack. Prints counts and statuses, never event content.

Nothing here imports a service's code: the suites test the running services from outside.
"""
import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def site(name):
    """A site setting, as the installers read it: config/wsl/site.env, then site.local.env. Quotes are removed."""
    value = None
    for file in ('site.env', 'site.local.env'):
        path = os.path.join(ROOT, 'config', 'wsl', file)
        if os.path.isfile(path):
            for line in open(path, encoding='utf-8'):
                key, _, raw = line.strip().partition('=')
                if key == name:
                    value = raw.strip().strip('"\'')
    if not value or '<' in value:
        raise SystemExit(f'Set {name} in config/wsl/site.local.env before running the live suites.')
    return value


MONITOR = site('SIEM_WINDOWS_MONITOR')
# The lab folder on Windows that holds the monitor folder, and the evidence the live suites keep.
LAB = os.path.dirname(MONITOR)
# This machine's name and Windows account, which no output may contain. Both come from the machine, not from this file.
HOST = socket.gethostname().lower()
WINDOWS_USER = MONITOR.split('/Users/', 1)[1].split('/', 1)[0] if '/Users/' in MONITOR else ''
CURL_ADMIN = '/root/.siem/opensearch-admin.curl'
API = 'https://127.0.0.1:9200'
GROUP = '6a1f0c52-3b7e-4c41-9d21-0e5a7b1c4f05'
SCHTASKS = '6a1f0c52-3b7e-4c41-9d21-0e5a7b1c4f0b'
RUN = hashlib.sha256(str(time.time_ns()).encode()).hexdigest()[:6]
# The service login that as_account uses. A suite sets it before each call.
LOGIN = None
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


def as_account(path, method='GET', body=None, login=None):
    """One OpenSearch request as a service account. Returns (status, payload). The password goes through a 0600 file only."""
    login = json.load(open(login or LOGIN))
    with tempfile.NamedTemporaryFile('w', dir='/root/.siem', suffix='.curl', delete=False) as handle:
        os.fchmod(handle.fileno(), 0o600)
        handle.write(f'user = "{login["user"]}:{login["password"]}"\n')
    try:
        command = ['curl', '-sS', '-w', '\n%{http_code}', '--max-time', '20', '--cacert', '/etc/opensearch/root-ca.pem', '-K', handle.name, '-X', method, API + path]
        if body is not None:
            command += ['-H', 'Content-Type: application/json', '-d', json.dumps(body)]
        payload, _, status = subprocess.run(command, capture_output=True, text=True).stdout.rpartition('\n')
        return status, payload
    finally:
        os.unlink(handle.name)


def systemctl(*words):
    return subprocess.run(['systemctl', *words], capture_output=True, text=True).stdout.strip()


def wait(probe, seconds, label):
    limit = time.time() + seconds
    while time.time() < limit:
        value = probe()
        if value:
            return value
        time.sleep(5)
    print(f'INFO timed out after {seconds} s waiting for {label}', flush=True)
    return None


# Synthetic alerts, on a host whose name ends in test-host, which is how stored fixtures are recognised.
def fake_alert(rule_id, at_ms, name, user, serial):
    alert_id = hashlib.sha256(f'fixturetest|{RUN}|{serial}'.encode()).hexdigest()[:32]
    stamp = time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime(at_ms / 1000))
    return {'schema_version': 1, 'alert_id': alert_id, 'rule_id': rule_id, 'rule_name': f'fixturetest {name}', 'detection_type': 'sigma', 'severity': 'high', 'confidence': 'medium', 'timestamp': stamp, 'detected_at': stamp, 'description': 'Synthetic test alert', 'host': 'fixturetest-host', 'user': user, 'source_ip': None, 'event_count': 1,
            'source_event_ids': [], 'raw_event_refs': [], 'mitre': {'tactics': ['execution'], 'techniques': []}, 'evidence': {'matched_fields': {'user.domain': ['FIXTURETEST']}, 'first_seen': stamp, 'last_seen': stamp, 'facts': {}}, 'evidence_ref': None}


def publish(*values):
    code = ("import sys\nfrom confluent_kafka import Producer\np = Producer({'bootstrap.servers': '127.0.0.1:9092'})\nfor line in sys.stdin.buffer.read().split(b'\\0'):\n    p.produce('siem-alerts', line)\np.flush(20)\n")
    subprocess.run(['python3', '-c', code], input=b'\0'.join(json.dumps(v).encode() for v in values), env={**os.environ, 'PYTHONPATH': '/opt/siem-correlator/lib'}, check=True, timeout=40)


def correlator_has(user):
    db = sqlite3.connect('file:/home/linux/siem/data/correlation/correlator.db?mode=ro', uri=True)
    rows = [json.loads(r[0]) for r in db.execute('SELECT body FROM incidents')]
    db.close()
    return [i for i in rows if any(user in u for u in i['users'])]
