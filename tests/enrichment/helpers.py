"""Shared test doubles. No test here opens a network connection or touches a real service."""
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'enricher'))

from siem_enricher import feeds as feed_lib  # noqa: E402
from siem_enricher.engine import Engine, Limits  # noqa: E402
from siem_enricher.store import Store  # noqa: E402
from siem_enricher.web import WebError  # noqa: E402

NOW = 1793440000000
# Synthetic indicators. 203.0.113.0/24 and example domains are reserved for documentation.
BAD_IP = '8.8.4.4'
OTHER_IP = '1.0.0.1'
BAD_DOMAIN = 'malware-test.example.com'
BAD_URL = 'http://malware-test.example.com/payload'
BAD_HASH = 'a' * 64


class Reply:
    def __init__(self, body=b'', status=200, headers=None):
        self.body = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.status = status
        self.headers = headers or {}


class FakeWeb:
    """Answers from a script. Records each request, so a test can see exactly what left the host."""

    def __init__(self, replies=None):
        self.replies = list(replies or [])
        self.requests = []

    def fetch(self, url, headers=None, data=None, max_bytes=None, method=None):
        self.requests.append({'url': url, 'headers': headers or {}, 'data': data})
        reply = self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]
        if isinstance(reply, Exception):
            raise reply
        return reply.status, reply.headers, reply.body


class Clock:
    def __init__(self, now=NOW):
        self.now = now

    def __call__(self):
        return self.now


class World:
    """A store, feeds and engine in a temporary folder."""

    def __init__(self, test, feeds=(), providers=None, web=None, limits=None):
        folder = tempfile.TemporaryDirectory()
        test.addCleanup(folder.cleanup)
        self.folder = Path(folder.name)
        self.store = Store(str(self.folder / 'e.db'))
        test.addCleanup(self.store.close)
        self.clock = Clock()
        self.web = web or FakeWeb([Reply({})])
        self.slept = []
        self.feeds = feed_lib.Feeds(self.store, list(feeds), self.web, self.clock, log=lambda text: None)
        self.providers = {p.name: p for p in (providers or [])}
        self.engine = Engine(self.store, self.feeds, None, self.providers, self.web, limits or Limits(), self.clock, sleep=self.slept.append, log=lambda text: None)

    def feed_file(self, name, text, **options):
        path = self.folder / f'{name}.txt'
        path.write_text(text)
        values = dict(name=name, format='lines', kind='ip', publisher=name, quality=0.8, confidence=90, category='test', path=str(path))
        values.update(options)
        feed = feed_lib.Feed(**values)
        self.feeds.feeds.append(feed)
        self.feeds.update(feed)
        return feed


class FakeOpenSearch:
    """Holds documents by index family, and answers the two searches the service makes."""

    def __init__(self, alerts=(), events=()):
        self.alerts = list(alerts)
        self.events = list(events)
        self.written = {}
        self.fail = 0

    def search(self, index, body):
        from siem_enricher.service import StoreError
        if self.fail:
            self.fail -= 1
            raise StoreError('HTTP 503')
        query = body['query']
        if index.startswith('siem-alerts'):
            rows = self.alerts
            if 'term' in query:
                rows = [a for a in rows if a['alert_id'] == query['term']['alert_id']]
            return {'hits': {'total': {'value': len(rows)}, 'hits': [{'_id': a['alert_id'], '_index': 'siem-alerts-x', '_source': a, 'sort': [0, a['alert_id']]} for a in rows]}}
        if 'ids' in query:
            wanted = set(query['ids']['values'])
            return {'hits': {'hits': [{'_id': e['event']['id'], '_index': 'siem-windows-x', '_source': e} for e in self.events if e['event']['id'] in wanted]}}
        window = query['bool']['filter'][1]['range']['event.ingested']
        rows = [e for e in self.events if window['gte'] <= e['event']['ingested'] < window['lt']]
        return {'hits': {'hits': [{'_id': e['event']['id'], '_index': 'siem-windows-x', '_source': e, 'sort': [e['event']['ingested'], e['event']['id']]} for e in rows]}}

    def put(self, index, doc_id, document):
        from siem_enricher.service import StoreError
        if self.fail:
            self.fail -= 1
            raise StoreError('HTTP 503')
        self.written[doc_id] = (index, document)


def web_error(status=None, retry_after=None):
    return WebError(f'HTTP {status}', status, retry_after)
