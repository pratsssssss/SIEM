"""Shared test doubles. No test here needs Kafka, OpenSearch or the network."""
import hashlib
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'correlator'))
RULES = ROOT / 'rules' / 'correlation' / 'rules.yml'

from siem_correlator import rules as rule_lib  # noqa: E402
from siem_correlator.schema import iso  # noqa: E402
from siem_correlator.service import Service, StoreDown  # noqa: E402
from siem_correlator.store import Store  # noqa: E402

NOW = 1793440000000
MIN = 60000
BURST = 'c0a5f1d2-7e41-4c8b-8a10-1f2e3d4c5b01'
SPRAY = 'c0a5f1d2-7e41-4c8b-8a10-1f2e3d4c5b02'
AFTER = 'c0a5f1d2-7e41-4c8b-8a10-1f2e3d4c5b03'
DECODED = 'c0a5f1d2-7e41-4c8b-8a10-1f2e3d4c5b04'
ENCODED = '6a1f0c52-3b7e-4c41-9d21-0e5a7b1c4f02'
PARENT = '6a1f0c52-3b7e-4c41-9d21-0e5a7b1c4f03'
LOLBIN = '6a1f0c52-3b7e-4c41-9d21-0e5a7b1c4f04'
GROUP = '6a1f0c52-3b7e-4c41-9d21-0e5a7b1c4f05'
SERVICE = '6a1f0c52-3b7e-4c41-9d21-0e5a7b1c4f08'
TASK = '6a1f0c52-3b7e-4c41-9d21-0e5a7b1c4f0a'
SCHTASKS = '6a1f0c52-3b7e-4c41-9d21-0e5a7b1c4f0b'
RUNKEY = '6a1f0c52-3b7e-4c41-9d21-0e5a7b1c4f0c'
SCRIPT = '6a1f0c52-3b7e-4c41-9d21-0e5a7b1c4f10'
PORT = '6a1f0c52-3b7e-4c41-9d21-0e5a7b1c4f11'
BAD_IP = '8.8.4.4'
GUID_A = '11111111-1111-1111-1111-111111111111'
GUID_B = '22222222-2222-2222-2222-222222222222'
GUID_C = '33333333-3333-3333-3333-333333333333'
_serial = [0]


def alert(rule_id=TASK, at=NOW, name=None, severity='medium', host='HOST', user='jdoe', domain='WS01', tactics=('execution',), source_ip=None, fields=None, facts=None, last=None, events=1, detected=None):
    _serial[0] += 1
    alert_id = hashlib.sha256(f'alert{_serial[0]}'.encode()).hexdigest()[:32]
    matched = {'user.domain': [domain]} if domain else {}
    matched.update(fields or {})
    event_ids = [f'{alert_id}-e{i}' for i in range(events)]
    return {'schema_version': 1, 'alert_id': alert_id, 'rule_id': rule_id, 'rule_name': name or rule_id[-8:], 'detection_type': 'sigma', 'severity': severity, 'confidence': 'medium', 'timestamp': iso(at), 'detected_at': iso(detected if detected is not None else (last or at) + 60000),
            'description': 'x', 'host': host, 'user': user, 'source_ip': source_ip, 'event_count': max(events, 1), 'source_event_ids': event_ids, 'raw_event_refs': [f'siem-windows-x/{i}' for i in event_ids],
            'mitre': {'tactics': list(tactics), 'techniques': []}, 'evidence': {'matched_fields': matched, 'first_seen': iso(at), 'last_seen': iso(last or at), 'facts': facts or {}}, 'evidence_ref': f'siem-alerts-x/{alert_id}'}


def process_event(entity=GUID_A, parent=None, name='cmd.exe', parent_name=None, user='jdoe', domain='WS01', sha256=None):
    event = {'process': {'entity_id': entity, 'name': name, 'parent': {}}, 'user': {'name': user, 'domain': domain}}
    if parent:
        event['process']['parent'] = {'entity_id': parent, 'name': parent_name or 'parent.exe'}
    elif parent_name:
        event['process']['parent'] = {'name': parent_name}
    if sha256:
        event['process']['hash'] = {'sha256': sha256}
    return event


class FakeOpenSearch:
    def __init__(self):
        self.down = False
        self.events = {}
        self.enrichment = {}
        self.signals = []
        self.alerts = []
        self.written = {}
        self.calls = 0

    def attach(self, alert_doc, *events):
        for event_id, event in zip(alert_doc['source_event_ids'], events):
            self.events[event_id] = event

    def search(self, index, body):
        self.calls += 1
        if self.down:
            raise StoreDown('ConnectionRefusedError')
        query = body['query']
        if index.startswith('siem-windows'):
            return [{'_id': i, '_source': self.events[i]} for i in query['ids']['values'] if i in self.events]
        if index.startswith('siem-alerts'):
            return [{'_source': a, 'sort': [0, a['alert_id']]} for a in self.alerts]
        filters = query['bool']['filter']
        if filters[0]['term']['doc_type'] == 'event':
            return self.signals
        wanted = filters[1]['term']['alert_id']
        return [{'_source': self.enrichment[wanted]}] if wanted in self.enrichment else []

    def call(self, method, path, body=None, allow=()):
        self.calls += 1
        if self.down:
            raise StoreDown('ConnectionRefusedError')
        self.written[path] = body
        return {}


class FakeKafka:
    def __init__(self):
        self.queue = []
        self.position = 0
        self.committed = 0
        self.down = False

    def send(self, *alerts, raw=None):
        for item in alerts:
            self.queue.append(json.dumps(item).encode())
        if raw is not None:
            self.queue.append(raw)

    def poll(self, limit, timeout):
        if self.down:
            raise StoreDown('kafka: _TRANSPORT')
        rows = [(0, i, v) for i, v in enumerate(self.queue) if i >= self.committed][:limit]
        self.position = self.committed + len(rows)
        return rows

    def commit(self):
        self.committed = self.position

    def lag(self):
        if self.down:
            raise OSError('no broker')
        return len(self.queue) - self.committed

    def rewind(self):
        """As after a crash before the commit: everything uncommitted comes again."""
        self.committed = 0


class World:
    def __init__(self, test, rules=None):
        folder = tempfile.TemporaryDirectory()
        test.addCleanup(folder.cleanup)
        self.path = str(Path(folder.name) / 'c.db')
        self.store = Store(self.path)
        test.addCleanup(lambda: self.store.close())
        self.now = [NOW]
        self.opensearch = FakeOpenSearch()
        self.kafka = FakeKafka()
        self.rules = rules or rule_lib.load(RULES)
        self.service = self.make()

    def make(self):
        return Service(self.store, self.rules, self.opensearch, self.kafka, clock=lambda: self.now[0], log=lambda text: None)

    def feed(self, *alerts):
        """Alerts through the whole path, in the order given."""
        self.kafka.send(*alerts)
        self.service.poll_kafka()
        self.service.process()
        return self.incidents()

    def incidents(self):
        return self.store.list_incidents()

    def restart(self):
        self.store.close()
        self.store = Store(self.path)
        self.service = self.make()
