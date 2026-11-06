"""Shared test doubles. No test here needs OpenSearch, Kafka or the network."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'detector'))
RULES = ROOT / 'rules'

from siem_detector.backends import SearchError  # noqa: E402
from siem_detector.dsl_eval import matches  # noqa: E402
from siem_detector.rules import Rule  # noqa: E402

BASE = 1793440000000


def event(uid, ingested, code='1', when=None, **extra):
    doc = {
        '@timestamp': f'2026-10-31T10:00:{uid % 60:02d}.000Z' if when is None else when,
        'event': {'id': f'id{uid}', 'ingested': ingested, 'dataset': 'windows.sysmon', 'code': code},
        'host': {'name': 'HOST'}, 'user': {'name': 'bob'},
    }
    doc.update(extra)
    return doc


def rule(rule_id='rule-1', query=None, **extra):
    settings = dict(
        id=rule_id, title='Test rule', description='A test.', kind='sigma', level='medium', confidence='high', enabled=True,
        interval_seconds=60, tags=['attack.execution', 'attack.t1059'], query=query or {'term': {'event.code': '1'}},
        fields=[], path='test')
    settings.update(extra)
    return Rule(**settings)


class FakeStore:
    """Answers a search the way OpenSearch does: filter, sort, search_after, size."""

    def __init__(self, docs=()):
        self.docs = list(docs)
        self.calls = []
        self.fail_next = 0
        self.indexed = {}
        self.index_failures = 0

    def search(self, index, body):
        self.calls.append(body)
        if self.fail_next:
            self.fail_next -= 1
            raise SearchError('HTTP 503')
        found = [d for d in self.docs if matches(body['query'], d)]
        found.sort(key=lambda d: (d['event']['ingested'], d['event']['id']))
        keys = [(d['event']['ingested'], d['event']['id']) for d in found]
        after = tuple(body.get('search_after', ()))
        chosen = [(k, d) for k, d in zip(keys, found) if not after or k > after][:body['size']]
        return {'hits': {'hits': [{'_id': d['event']['id'], '_index': 'siem-windows-test', '_source': d, 'sort': list(k)} for k, d in chosen]}}

    def index_alert(self, index, alert_id, document):
        if self.index_failures:
            self.index_failures -= 1
            raise SearchError('HTTP 503')
        self.indexed[alert_id] = document


class FakeKafka:
    """A broker that can be down, or can take a message and lose the delivery report."""

    def __init__(self):
        self.topic = []
        self.down = False
        self.lose_reports = False
        self.queued = []

    def send(self, alert_id, payload):
        self.queued.append((alert_id, payload))

    def poll(self, timeout):
        results = {}
        for alert_id, payload in self.queued:
            if self.down:
                results[alert_id] = 'broker down'
                continue
            self.topic.append((alert_id, payload))
            results[alert_id] = 'report lost' if self.lose_reports else None
        self.queued = []
        return results

    def recent_keys(self):
        if self.down:
            raise RuntimeError('broker down')
        return {key for key, _ in self.topic}
