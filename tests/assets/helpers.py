"""Test doubles and synthetic fixtures. Nothing here is real telemetry, and no test here calls OpenSearch."""
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'inventory'))

from siem_asset import control, schema  # noqa: E402
from siem_asset.service import Service, StoreDown  # noqa: E402
from siem_asset.store import Store  # noqa: E402

NOW = 1793440000000
MIN = 60000
HOUR = 3600000
DAY = 86400000
GUID_A = '1111aaaa-2222-3333-4444-555566667777'
GUID_B = '9999bbbb-2222-3333-4444-555566667777'
UUID_A = 'c0a80001-1234-5678-9abc-def012345678'
UUID_B = 'c0a80002-1234-5678-9abc-def012345678'
MAC_A = '3c:52:82:11:22:33'
MAC_B = '3c:52:82:44:55:66'
WATCH = {'windefend': 'Microsoft Defender', 'sysmon64': 'Sysmon', 'vector': 'Vector agent'}
SERVICES = [{'name': 'WinDefend', 'display': 'Defender', 'state': 'Running', 'start': 'Auto', 'binary': '"C:\\ProgramData\\Microsoft\\MsMpEng.exe"'}, {'name': 'Sysmon64', 'display': 'Sysmon', 'state': 'Running', 'start': 'Auto', 'binary': 'C:\\Windows\\Sysmon64.exe'},
            {'name': 'Spooler', 'display': 'Print', 'state': 'Running', 'start': 'Auto', 'binary': 'C:\\Windows\\spoolsv.exe'}]


def snapshot(host='lab-01', guid=GUID_A, uuid=UUID_A, mac=MAC_A, ip='192.168.1.10', at=NOW, services=None, software=None, users=None, listeners=None, os_build='26200', **extra):
    raw = {'schema': schema.SNAPSHOT, 'collector': 'windows-local', 'collected_at': schema.iso(at), 'host': {'hostname': host, 'platform': 'windows', 'asset_type': 'workstation', 'domain_joined': False, 'virtual': False, 'vendor': 'Acme', 'model': 'One'},
           'identifiers': {k: v for k, v in (('windows_machine_guid', guid), ('hw_uuid', uuid)) if v}, 'os': {'name': 'Windows 11', 'version': '10.0.26200', 'build': os_build, 'arch': '64-bit'},
           'interfaces': [{'name': 'Wi-Fi', 'mac': mac, 'up': True, 'virtual': False, 'ips': [ip], 'cidrs': [f'{ip}/24']}],
           'software': software if software is not None else [{'name': 'Editor', 'version': '1.0', 'publisher': 'Acme'}],
           'services': services if services is not None else SERVICES, 'users': users if users is not None else [{'name': 'alice', 'enabled': True, 'local_admin': True}],
           'listeners': listeners if listeners is not None else [{'proto': 'tcp', 'port': 135, 'scope': 'any', 'process': 'svchost'}, {'proto': 'tcp', 'port': 9000, 'scope': 'loopback', 'process': 'x'}],
           'security': {'defender': {'service': True, 'realtime': True}, 'firewall': {'enabled': 3, 'total': 3}, 'rdp_enabled': False}}
    raw.update(extra)
    return raw


class FakeOpenSearch:
    def __init__(self):
        self.down = False
        self.written = {}
        self.searches = []
        self.responses = {}
        self.incidents = []
        self.alerts = {}
        self.enrichment = {}

    def call(self, method, path, body=None, allow=()):
        if self.down:
            raise StoreDown('ConnectionRefusedError')
        self.written[path] = body
        return {}

    def ping(self):
        if self.down:
            raise StoreDown('ConnectionRefusedError')

    def search_raw(self, index, body):
        if self.down:
            raise StoreDown('ConnectionRefusedError')
        self.searches.append((index, body))
        if index == 'siem-linux-*':
            return self.responses.get('linux_events' if body.get('size') else 'linux', {'aggregations': {'hosts': {'buckets': []}}, 'hits': {'hits': []}})
        text = json.dumps(body)
        for key in ('authenticated', 'peers', 'names', 'sources'):
            if self._marks(key, text):
                return self.responses.get(key, {'aggregations': {'hosts': {'buckets': []}}})
        return self.responses.get('events', {'hits': {'hits': []}})

    @staticmethod
    def _marks(key, text):
        return {'authenticated': '"users"', 'peers': '"peers"', 'names': '"names"', 'sources': '"sources"'}[key] in text

    def search(self, index, body):
        if self.down:
            raise StoreDown('ConnectionRefusedError')
        self.searches.append((index, body))
        if index.startswith('siem-incidents'):
            wanted = (body['query'].get('term') or {}).get('incident_id')
            return [{'_id': i['incident_id'], '_source': i} for i in self.incidents if wanted in (None, i['incident_id'])]
        if index.startswith('siem-alerts'):
            found = self.alerts.get(body['query']['term']['alert_id'])
            return [{'_source': found}] if found else []
        if index.startswith('siem-enrichment'):
            found = self.enrichment.get(body['query']['term']['alert_id'])
            return [{'_source': found}] if found else []
        return []


class World:
    """A service with a settable clock, on a store in a temporary folder."""

    def __init__(self, **settings):
        self.folder = tempfile.TemporaryDirectory()
        self.now = NOW
        self.search = FakeOpenSearch()
        self.logs = []
        self.store = Store(str(Path(self.folder.name) / 'asset.db'))
        self.work = Service(self.store, self.search, {'security_services': WATCH, 'collect_local': False, **settings}, clock=lambda: self.now, log=self.logs.append)
        self.actions = control.Actions(self.work)

    def close(self):
        self.store.close()
        self.folder.cleanup()

    def take(self, raw):
        snap = schema.snapshot(raw, self.now)
        return self.work.inventory.apply(snap, json.dumps(raw, sort_keys=True))

    def only(self):
        rows = self.store.assets()
        assert len(rows) == 1, rows
        return rows[0]

    def kinds(self, asset_id=None):
        return [c['kind'] for c in self.store.changes([asset_id] if asset_id else None, limit=1000)]

    def admin(self, action, /, **arguments):
        return control.handle(self.actions, {'action': action, **arguments}, ('alice', 'alice'))

    def analyst(self, action, /, **arguments):
        return control.handle(self.actions, {'action': action, **arguments}, ('bob', None))


def host_buckets(host='lab-01', first=NOW - HOUR, last=NOW - MIN, sources=None):
    sources = sources or {'windows.sysmon': last, 'windows.security': last}
    return {'aggregations': {'hosts': {'buckets': [{'key': host, 'doc_count': 10, 'first': {'value': first}, 'last': {'value': last}, 'family': {'buckets': [{'key': 'windows'}]}, 'sources': {'buckets': [{'key': k, 'last': {'value': v}} for k, v in sources.items()]}}]}}}


def user_buckets(host='lab-01', name='alice', domain='LAB', last=NOW - MIN, codes=(('4624', 5),)):
    return {'aggregations': {'hosts': {'buckets': [{'key': host, 'users': {'buckets': [{'key': name, 'last': {'value': last}, 'domain': {'buckets': [{'key': domain}]}, 'code': {'buckets': [{'key': c, 'doc_count': n, 'last': {'value': last}} for c, n in codes]}}]}}]}}}


def peer_buckets(host='lab-01', peer='192.168.1.20', own='192.168.1.10', last=NOW - MIN):
    return {'aggregations': {'hosts': {'buckets': [{'key': host, 'own': {'buckets': [{'key': own, 'last': {'value': last}}]}, 'peers': {'buckets': [{'key': peer, 'doc_count': 4, 'last': {'value': last}}]}}]}}}


def name_buckets(host='lab-01', process='tool.exe', last=NOW - MIN):
    return {'aggregations': {'hosts': {'buckets': [{'key': host, 'names': {'buckets': [{'key': process, 'last': {'value': last}, 'product': {'buckets': [{'key': 'Tool'}]}, 'company': {'buckets': []}, 'version': {'buckets': [{'key': '2.0'}]}}]}}]}}}


def event_hit(event_id, dataset, code, host='lab-01', at=NOW - MIN, **fields):
    return {'_id': event_id, '_source': {'@timestamp': schema.iso(at), 'event': {'dataset': dataset, 'code': code, 'ingested': schema.iso(at)}, 'host': {'name': host}, **fields}}
