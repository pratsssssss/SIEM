"""A private stack for the dashboard: the real server over real TLS, the real correlator behind a real socket, and fixtures for
the rest. Everything here is synthetic and lives in a temporary folder. Run as a member of siem-analyst, not as root,
because the correlator's socket refuses root."""
import http.client
import importlib.util
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'dashboard'))
sys.path.insert(0, str(ROOT / 'health'))

from siem_dashboard import server as web  # noqa: E402
from siem_dashboard.auth import Auth  # noqa: E402
from siem_dashboard.backends import Sockets, Unavailable, incident_rules  # noqa: E402
from siem_dashboard.config import build  # noqa: E402
from siem_dashboard.data import Data  # noqa: E402

spec = importlib.util.spec_from_file_location('correlation_helpers', ROOT / 'tests' / 'correlation' / 'helpers.py')
corr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(corr)
from siem_correlator import control as corr_control  # noqa: E402

PASSWORD = 'a-long-test-passphrase-1'
XSS = '<img src=x onerror=alert(1)><script>alert(2)</script>'
NOW = 1793440000000
CERT = tempfile.TemporaryDirectory()
subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-days', '2', '-keyout', f'{CERT.name}/k.pem', '-out', f'{CERT.name}/c.pem', '-subj', '/CN=test'], check=True, capture_output=True)
ALERT = {'alert_id': 'a' * 32, 'rule_id': 'rule-1', 'rule_name': 'Test rule', 'detection_type': 'sigma', 'severity': 'high', 'confidence': 'medium', 'timestamp': '2026-11-01T10:00:00.000Z', 'detected_at': '2026-11-01T10:01:00.000Z', 'description': XSS, 'host': 'host-a', 'user': 'alice', 'source_ip': None, 'event_count': 1, 'source_event_ids': ['e1'], 'raw_event_refs': ['siem-windows-2026.11.01/doc1'], 'mitre': {'tactics': ['execution'], 'techniques': ['T1059']}, 'evidence': {'rule_fields': ['process.name']}}
EVENT = {'@timestamp': '2026-11-01T10:00:00.000Z', 'event': {'id': 'e1', 'dataset': 'windows.sysmon', 'ingested': '2026-11-01T10:00:02.000Z', 'action': XSS}, 'host': {'name': 'host-a'}, 'user': {'name': XSS}}
ENRICH = {'alert_id': 'a' * 32, 'status': 'complete', 'enriched_at': '2026-11-01T10:02:00.000Z', 'summary': {'highest_verdict': 'unknown', 'by_verdict': {'unknown': 1}}, 'indicators': [{'type': 'ip', 'value': '203.0.113.5', 'verdict': 'no_known_threat', 'score': 0, 'sources_answered': ['one'], 'sources_failed': ['two']}, {'type': 'ip', 'value': '203.0.113.6', 'verdict': 'malicious', 'score': 90, 'sources_answered': ['one'], 'sources_failed': []}]}


class FakeSearch:
    def __init__(self):
        self.down = False
        self.queries = []
        self.incidents = [{'incident_id': 'real', 'title': 'Real', 'status': 'new', 'severity': 'high', 'updated_at': '2026-11-01T10:03:00.000Z', 'alert_ids': ['a' * 32], 'hosts': ['host-a']}, {'incident_id': 'fixture', 'title': 'Fixture', 'status': 'false_positive', 'severity': 'low', 'updated_at': '2026-10-31T10:00:00.000Z', 'alert_ids': ['b' * 32], 'hosts': ['x']}]

    def search(self, index, body):
        self.queries.append((index, body))
        if self.down:
            raise Unavailable('OpenSearch cannot be reached')
        if index.startswith('siem-alerts') and body.get('size') == 0 and 'ids' in body.get('aggs', {}):
            return {'aggregations': {'ids': {'buckets': [{'key': 'a' * 32, 'doc_count': 1}]}}}
        if index.startswith('siem-alerts') and body.get('size') == 0:
            return {'hits': {'total': {'value': 1, 'relation': 'eq'}}, 'aggregations': {'severity': {'buckets': [{'key': 'high', 'doc_count': 1}]}, 'rules': {'buckets': [{'key': 'Test rule', 'doc_count': 1}]}, 'time': {'buckets': [{'key': NOW, 'key_as_string': '2026-11-01T10:00:00.000Z', 'doc_count': 1}]}}}
        table = {'siem-alerts': [ALERT], 'siem-enrichment': [ENRICH], 'siem-incidents': self.incidents, 'siem-attack-paths': [{'path_id': 'p1', 'title': 't', 'tier': 'plausible_inferred', 'gaps': [{'gap': 'x'}], 'validation': {'unavailable': 2}, 'validated_at': '2026-11-01T10:00:00Z', 'path_at': '2026-11-01T10:00:00Z'}]}
        for prefix, rows in table.items():
            if index.startswith(prefix):
                return {'hits': {'total': {'value': len(rows), 'relation': 'eq'}, 'hits': [{'_id': f'd{i}', '_index': 'x', '_source': json.loads(json.dumps(r))} for i, r in enumerate(rows)]}}
        return {'hits': {'total': {'value': 1, 'relation': 'eq'}, 'hits': [{'_id': 'doc1', '_index': 'siem-windows-2026.11.01', '_source': json.loads(json.dumps(EVENT))}]}}


class FakeHealth:
    def __init__(self):
        self.down = False

    def view(self):
        if self.down:
            raise Unavailable('The health monitor state cannot be read')
        return _View(), _Catalog()


class _Rows:
    def components(self):
        return {'kafka': {'component': 'kafka', 'status': 'UNKNOWN', 'reason': XSS}}

    def transitions(self, *args):
        return []

    def episodes(self, *args, **kwargs):
        return []

    def close(self):
        pass


class _View:
    now = NOW
    store = _Rows()

    def overview(self):
        return {'overall': 'DEGRADED', 'coverage': 'limited', 'monitor_current': True, 'stages': []}

    def history(self, *args):
        return []

    def failures(self, *args):
        return {'open': [], 'recent': []}

    def explain(self, name):
        return {'component': name, 'status': 'UNKNOWN', 'evidence': [{'value': '10 feeds'}], 'reason': 'x'} if name in ('kafka', 'enricher') else None

    def lag(self):
        return {'lag': {'raw_lag_messages': None}, 'not_measured': ['raw_lag_messages']}

    def resources(self):
        return {'figures': {}}

    def metrics(self, *args):
        return {'metrics': {}}


class _Catalog:
    CATALOG = {'raw_lag_messages': 1}
    UNAVAILABLE = {}

    @staticmethod
    def describe(name):
        return {'name': name}


class UnixFake:
    """A stand-in for the asset or path service: a real socket that records what it was asked."""

    def __init__(self, path, replies):
        self.replies, self.seen = replies, []
        self.link = socket.socket(socket.AF_UNIX)
        self.link.bind(path)
        self.link.listen(8)
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while True:
            try:
                conn, _ = self.link.accept()
            except OSError:
                return
            with conn:
                data = b''
                while True:
                    part = conn.recv(65536)
                    if not part:
                        break
                    data += part
                request = json.loads(data)
                self.seen.append(request)
                reply = self.replies.get(request['action'], [])
                conn.sendall(json.dumps(reply if isinstance(reply, dict) and 'ok' in reply else {'ok': True, 'result': reply}).encode())

    def close(self):
        self.link.close()


class Stack:
    def __init__(self, test, extra=None, seed=True):
        self.folder = tempfile.TemporaryDirectory()
        test.addCleanup(self.folder.cleanup)
        os.chmod(self.folder.name, 0o755)
        base = Path(self.folder.name)
        settings = {'state_file': str(base / 'd.db'), 'static_dir': str(ROOT / 'dashboard' / 'static'), 'sockets': {'incidents': str(base / 'i.sock'), 'assets': str(base / 'a.sock'), 'paths': str(base / 'p.sock'), 'timeout_seconds': 5}, 'correlator_app': str(ROOT / 'correlator')}
        for key, value in (extra or {}).items():
            settings[key] = value
        self.config = build(settings)
        self.now = [NOW]
        self.clock = lambda: self.now[0]
        self.auth = Auth(self.config['state_file'], self.config, clock=self.clock)
        test.addCleanup(self.auth.close)
        self.search = FakeSearch()
        self.health = FakeHealth()
        self.world = corr.World(test)
        self.real = corr_control.Server(self.config['sockets']['incidents'], corr_control.Actions(self.world.service), group='siem-analyst', log=lambda t: None)
        self.real.start()
        test.addCleanup(self.real.stop)
        asset = {'asset_id': 'ast-1', 'hostname': XSS, 'status': 'active', 'platform': 'windows', 'asset_type': 'host', 'identity_confidence': 'high'}
        self.assets = UnixFake(self.config['sockets']['assets'], {'list': [asset], 'search': [asset], 'show': {**asset, 'identity': {'aliases': []}}, 'conflicts': [], 'changes': [], 'history': [], 'software': {'installed': []}, 'services': [], 'users': {'local_accounts': [], 'observed_users': []}, 'relationships': [], 'acknowledge': {'seq': 1}})
        self.paths = UnixFake(self.config['sockets']['paths'], {'list': [{'path_id': 'p1', 'seed_kind': 'alert', 'seed_id': 'a' * 32, 'tier': 'plausible_inferred', 'title': XSS}], 'graph': {'path_id': 'p1', 'tier': 'plausible_inferred', 'conclusion': 'none', 'nodes': [{'id': 'n1', 'type': 'identity', 'key': 'k', 'display': XSS}], 'edges': []}, 'explain': {'path_id': 'p1'}, 'timeline': [], 'history': [], 'show': {}, 'evidence': [], 'note': {'path_id': 'p1'}, 'asset': []})
        test.addCleanup(self.assets.close)
        test.addCleanup(self.paths.close)
        self.data = Data(self.search, Sockets(self.config['sockets']), self.health, self.config, clock=self.clock)
        self.app = web.App(self.config, self.auth, self.data, incident_rules(self.config['correlator_app']), clock=self.clock)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(f'{CERT.name}/c.pem', f'{CERT.name}/k.pem')
        self.server = web.Server(('127.0.0.1', 0), self.app, context)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        test.addCleanup(self.server.shutdown)
        if seed:
            self.auth.create('analyst', PASSWORD, actor='test')

    def incident(self):
        pair = corr.alert(corr.GROUP, corr.NOW, 'group', severity='high'), corr.alert(corr.SCHTASKS, corr.NOW + 5 * corr.MIN, 'schtasks')
        self.world.feed(*pair)
        return self.world.incidents()[0]['incident_id']

    def client(self):
        return Client(self.port)

    def signed_in(self):
        client = self.client()
        status, _, _ = client.post('/auth/login', {'username': 'analyst', 'password': PASSWORD}, csrf=False)
        assert status == 200, status
        return client


class Client:
    def __init__(self, port):
        self.port = port
        self.cookie = None
        self.csrf = None
        self.context = ssl.create_default_context()
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE

    def raw(self, method, path, body=None, headers=None):
        link = http.client.HTTPSConnection('127.0.0.1', self.port, context=self.context, timeout=15)
        sent = dict(headers or {})
        if self.cookie:
            sent.setdefault('Cookie', f'{web.COOKIE}={self.cookie}')
        link.request(method, path, body=body, headers=sent)
        reply = link.getresponse()
        data = reply.read()
        heads = reply.getheaders()
        link.close()
        return reply.status, data, heads

    def call(self, method, path, body=None, csrf=True, headers=None):
        sent = dict(headers or {})
        payload = None
        if body is not None:
            payload = json.dumps(body)
            sent['Content-Type'] = 'application/json'
        if csrf and self.csrf:
            sent['X-CSRF-Token'] = self.csrf
        status, data, heads = self.raw(method, f'/api/v1{path}', payload, sent)
        for name, value in heads:
            if name.lower() == 'set-cookie':
                self.set_cookie = value
                pair = value.split(';')[0].split('=', 1)
                self.cookie = pair[1] or None
        try:
            parsed = json.loads(data)
        except ValueError:
            parsed = None
        if isinstance(parsed, dict) and isinstance(parsed.get('data'), dict) and parsed['data'].get('csrf'):
            self.csrf = parsed['data']['csrf']
        return status, parsed, dict((k.lower(), v) for k, v in heads)

    def get(self, path):
        return self.call('GET', path)

    def post(self, path, body=None, csrf=True, headers=None):
        return self.call('POST', path, body if body is not None else {}, csrf, headers)
