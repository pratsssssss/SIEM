"""Synthetic fixtures, in the shape OpenSearch returns them. Nothing here is real telemetry or a real attack."""
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'attackpath'))

from siem_path import control, model  # noqa: E402
from siem_path.engine import Assets, Seed  # noqa: E402
from siem_path.evidence import StoreDown  # noqa: E402
from siem_path.service import Service  # noqa: E402
from siem_path.store import Store  # noqa: E402

NOW = 1793440000000
MIN = 60000
HOUR = 3600000
WIN = {'asset_id': 'ast-win', 'hostname': 'host-a', 'aliases': ['host-a'], 'status': 'active', 'platform': 'windows', 'identity_confidence': 'high'}
WIN2 = {'asset_id': 'ast-win2', 'hostname': 'host-c', 'aliases': ['host-c'], 'status': 'active', 'platform': 'windows', 'identity_confidence': 'high'}
LIN = {'asset_id': 'ast-lin', 'hostname': 'host-b', 'aliases': ['host-b-wsl'], 'status': 'active', 'platform': 'linux', 'identity_confidence': 'high'}
_serial = [0]


def uid():
    _serial[0] += 1
    return f'{_serial[0]:032x}'


def winevent(code, at=NOW, dataset='windows.security', host='host-a', user='alice', domain='LAB', sid='S-1-5-21-1-2-3-1001', **fields):
    doc = {'@timestamp': model.iso(at), 'event': {'dataset': dataset, 'code': str(code), 'ingested': model.iso(at + 2000)}, 'host': {'name': host}}
    if user:
        doc['user'] = user if isinstance(user, dict) else {'name': user, **({'domain': domain} if domain else {}), **({'id': sid} if sid else {})}
    doc.update(fields)
    return doc


def linuxevent(action, at=NOW, host='host-b-wsl', user='alice', attribution=None, **fields):
    doc = {'@timestamp': model.iso(at), 'event': {'dataset': 'linux.auth', 'action': action, 'ingested': model.iso(at + 2000)}, 'host': {'name': host, 'id': 'cd' * 16}}
    if user:
        doc['user'] = user if isinstance(user, dict) else {'name': user}
    if attribution:
        doc['labels'] = {'attribution': attribution}
    doc.update(fields)
    return doc


def hit(doc, index=None):
    index = index or ('siem-linux-2026.11.01' if doc['event']['dataset'].startswith('linux') else 'siem-windows-2026.11.01')
    return {'_id': uid(), '_index': index, '_source': doc}


def alert(hits, host='host-a', rule='Test rule', severity='high', user=None, techniques=(), tactics=('persistence',), at=NOW, alert_id=None):
    return {'alert_id': alert_id or uid(), 'rule_id': 'rule-1', 'rule_name': rule, 'severity': severity, 'confidence': 'high', 'timestamp': model.iso(at), 'detected_at': model.iso(at + 30000), 'host': host, 'user': user, 'source_ip': None, 'event_count': len(hits),
            'raw_event_refs': [f"{h['_index']}/{h['_id']}" for h in hits], 'source_event_ids': [h['_id'] for h in hits], 'mitre': {'tactics': list(tactics), 'techniques': list(techniques)}}


def seed(cited=(), context=(), alerts=None, status='new', joins=('user',), missing=(), intelligence=(), uncertain=(), links=(), host='host-a', kind='incident', seed_id='e' * 32):
    alerts = alerts if alerts is not None else [alert(cited, host=host)]
    incident = {'incident_id': seed_id, 'title': 'Synthetic', 'status': status, 'rules': [{'id': 'r', 'join': j} for j in joins], 'uncertain': list(uncertain), 'first_seen': model.iso(NOW), 'last_seen': model.iso(NOW), 'updated_at': model.iso(NOW)}
    return Seed(kind, seed_id, 'Synthetic', status, 'high', alerts, incident if kind == 'incident' else None, {(h['_index'], h['_id']): h['_source'] for h in cited}, list(missing), list(context), list(intelligence), list(links))


def assets(*records, ip=None):
    return Assets(records or (WIN, LIN), ip)


def stages(path, name=None):
    return [s for s in path['stages'] if name is None or s['name'] == name]


def edges(path, kind):
    return [e for e in path['edges'] if e['type'] == kind]


class FakeOpenSearch:
    def __init__(self):
        self.down = False
        self.written = {}
        self.searches = []
        self.docs = {'incidents': [], 'alerts': [], 'enrichment': [], 'assets': [WIN, LIN], 'events': {}}

    def ping(self):
        if self.down:
            raise StoreDown('ConnectionRefusedError')

    def call(self, method, path, body=None, allow=()):
        self.ping()
        self.written[path] = body
        return {}

    def add(self, *hits):
        for item in hits:
            self.docs['events'][(item['_index'], item['_id'])] = item['_source']

    def search(self, index, body):
        self.ping()
        self.searches.append((index, body))
        text = json.dumps(body['query'])
        if index == 'siem-assets-current':
            return [{'_source': a} for a in self.docs['assets']]
        if index.startswith('siem-incidents'):
            wanted = (body['query'].get('term') or {}).get('incident_id')
            return [{'_id': i['incident_id'], '_source': i} for i in self.docs['incidents'] if wanted in (None, i['incident_id'])]
        if index.startswith('siem-alerts'):
            ids = (body['query'].get('terms') or {}).get('alert_id') or ([(body['query'].get('term') or {}).get('alert_id')] if 'term' in body['query'] else None)
            return [{'_id': a['alert_id'], '_source': a} for a in self.docs['alerts'] if ids is None or a['alert_id'] in ids]
        if index.startswith('siem-enrichment'):
            return []
        if 'values' in text:
            return [{'_id': i, '_index': index, '_source': self.docs['events'][(index, i)]} for i in body['query']['ids']['values'] if (index, i) in self.docs['events']]
        return []


class World:
    def __init__(self, **settings):
        self.folder = tempfile.TemporaryDirectory()
        self.now = NOW
        self.search = FakeOpenSearch()
        self.store = Store(str(Path(self.folder.name) / 'path.db'))
        self.logs = []
        self.work = Service(self.store, self.search, settings, clock=lambda: self.now, log=self.logs.append)
        self.actions = control.Actions(self.work)

    def close(self):
        self.store.close()
        self.folder.cleanup()

    def analyst(self, action, /, **arguments):
        return control.handle(self.actions, {'action': action, **arguments}, ('bob', None))

    def admin(self, action, /, **arguments):
        return control.handle(self.actions, {'action': action, **arguments}, ('alice', 'alice'))

    def incident(self, cited, incident_id='f' * 32, status='new', title='Synthetic'):
        item = alert(cited)
        self.search.add(*cited)
        self.search.docs['alerts'].append(item)
        self.search.docs['incidents'].append({'incident_id': incident_id, 'title': title, 'severity': 'high', 'status': status, 'rules': [{'id': 'r', 'join': 'user'}], 'alert_ids': [item['alert_id']], 'first_seen': model.iso(NOW), 'last_seen': model.iso(NOW), 'updated_at': model.iso(NOW)})
        return incident_id
