"""Local threat intelligence: public lists downloaded on a schedule, and files the owner provides.

A feed is only data. Its URLs are compared with indicators and never opened. A pull that looks wrong
keeps the previous data, so a broken download can never quietly empty a blocklist.
"""
import gzip
import json
import math
import os
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import indicators as ind
from . import untrusted
from .score import HIT, NO_MATCH, SKIPPED, Observation
from .web import WebError

HOUR_MS = 3600000


class FeedError(Exception):
    pass


@dataclass
class Feed:
    name: str
    format: str
    kind: str
    publisher: str
    stance: str = 'malicious'     # malicious, suspicious or context
    quality: float = 0.5
    confidence: int = 70
    category: str = ''
    url: str = ''
    path: str = ''
    enabled: bool = True
    stale_hours: int = 72
    refresh_hours: int = 24
    max_bytes: int = 52428800
    min_rows: int = 1
    synthetic: bool = False


def _lines(body):
    for raw in body.decode('utf-8', 'replace').splitlines():
        line = raw.strip()
        if line and line[0] not in '#!;':
            yield line.split()[0].split(';')[0]


def parse_lines(feed, body):
    rows, cidrs = [], []
    for text in _lines(body):
        if feed.kind == ind.IP and '/' in text:
            try:
                cidrs.append((text, feed.category))
            except ValueError:
                pass
            continue
        item = ind.parse(feed.kind, text)
        if item:
            rows.append((item.kind, item.value, feed.category, None, None))
    return rows, cidrs


def parse_feodo(feed, body):
    rows = []
    for entry in json.loads(body):
        item = ind.parse(ind.IP, entry.get('ip_address', '')) if isinstance(entry, dict) else None
        if item:
            family = untrusted.label(entry.get('malware')) or feed.category
            rows.append((item.kind, item.value, family, untrusted.timestamp(entry.get('first_seen')), untrusted.timestamp(entry.get('last_online'))))
    return rows, []


def parse_spamhaus(feed, body):
    cidrs = []
    for line in body.decode('utf-8', 'replace').splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict) and 'cidr' in entry:
            cidrs.append((str(entry['cidr']), feed.category))
    return [], cidrs


def parse_aws(feed, body):
    data = json.loads(body)
    found = {str(p['ip_prefix']) for p in data.get('prefixes', []) if 'ip_prefix' in p}
    found |= {str(p['ipv6_prefix']) for p in data.get('ipv6_prefixes', []) if 'ipv6_prefix' in p}
    return [], [(c, feed.category) for c in sorted(found)]


def parse_gcp(feed, body):
    data = json.loads(body)
    found = {str(p.get('ipv4Prefix') or p.get('ipv6Prefix')) for p in data.get('prefixes', []) if p.get('ipv4Prefix') or p.get('ipv6Prefix')}
    return [], [(c, feed.category) for c in sorted(found)]


def parse_indicators(feed, body):
    """An owner-provided file: one `kind,value,category` per line, for intelligence with no public feed."""
    rows, cidrs = [], []
    for line in body.decode('utf-8', 'replace').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = [p.strip() for p in line.split(',')]
        if len(parts) < 2 or parts[0] not in ind.KINDS:
            continue
        category = untrusted.label(parts[2]) if len(parts) > 2 else None
        if parts[0] == ind.IP and '/' in parts[1]:
            cidrs.append((parts[1], category or feed.category))
            continue
        item = ind.parse(parts[0], parts[1])
        if item:
            rows.append((item.kind, item.value, category or feed.category, None, None))
    return rows, cidrs


PARSERS = {'lines': parse_lines, 'feodo-json': parse_feodo, 'spamhaus-jsonl': parse_spamhaus, 'aws-json': parse_aws, 'gcp-json': parse_gcp, 'indicators': parse_indicators}


def owner_files(folder):
    """Each *.csv in the folder is a feed of `kind,value,category` lines, for intelligence with no
    public source. A file named synthetic-*.csv is test data, and says so in every result (D12)."""
    if not folder or not Path(folder).is_dir():
        return []
    found = []
    for path in sorted(Path(folder).glob('*.csv')):
        found.append(Feed(name=f'owner-{path.stem}', format='indicators', kind=ind.HASH, publisher=f'owner-{path.stem}', quality=0.9, confidence=90, category='owner-supplied',
                          path=str(path), stale_hours=87600, refresh_hours=1, max_bytes=52428800, synthetic=path.stem.startswith('synthetic-')))
    return found


def _valid_cidrs(cidrs):
    import ipaddress
    kept = []
    for cidr, category in cidrs:
        try:
            ipaddress.ip_network(cidr, strict=False)
            kept.append((cidr, category))
        except ValueError:
            continue
    return kept


class Feeds:
    def __init__(self, store, feeds, web, clock, log=print):
        self.store = store
        self.feeds = feeds
        self.web = web
        self.clock = clock
        self.log = log

    def due(self):
        now = self.clock()
        return [f for f in self.feeds if f.enabled and (self.store.feed_state(f.name)['checked_ms'] or 0) + f.refresh_hours * HOUR_MS <= now]

    def update(self, feed, force=False):
        """Pulls one feed. Returns a short result. Never raises on a bad pull: the old data stays."""
        now = self.clock()
        state = self.store.feed_state(feed.name)
        try:
            if feed.path:
                body = Path(feed.path).read_bytes()
                etag = last_modified = None
            else:
                headers = {}
                if not force and state['rows']:
                    headers = {k: v for k, v in (('If-None-Match', state['etag']), ('If-Modified-Since', state['last_modified'])) if v}
                status, reply, body = self.web.fetch(feed.url, headers, max_bytes=feed.max_bytes)
                if status == 304:
                    self.store.replace_feed_unchanged(feed.name, now)
                    return 'unchanged'
                if status != 200:
                    raise FeedError(f'HTTP {status}')
                etag, last_modified = reply.get('ETag'), reply.get('Last-Modified')
            if body[:15].lstrip().lower().startswith((b'<!doctype', b'<html')):
                raise FeedError('received a web page, not a feed')
            rows, cidrs = PARSERS[feed.format](feed, body)
            cidrs = _valid_cidrs(cidrs)
            total = len(rows) + len(cidrs)
            if total < feed.min_rows:
                raise FeedError(f'only {total} rows')
            if state['rows'] > 200 and total < state['rows'] / 2:
                raise FeedError(f"{total} rows, down from {state['rows']}")
            kept = self.store.replace_feed(feed.name, rows, cidrs, now, etag, last_modified)
            return f'{kept} rows'
        except (WebError, FeedError, OSError, ValueError, KeyError, TypeError, AttributeError) as error:
            self.store.feed_note(feed.name, now, str(error))
            self.log(f'feed {feed.name} failed: {error}')
            return f'failed: {error}'

    def fresh(self, feed):
        state = self.store.feed_state(feed.name)
        return bool(state['rows']) and (state['updated_ms'] or 0) + feed.stale_hours * HOUR_MS > self.clock()

    def status(self):
        rows = []
        for feed in self.feeds:
            state = self.store.feed_state(feed.name)
            rows.append({'feed': feed.name, 'kind': feed.kind, 'enabled': feed.enabled, 'rows': state['rows'], 'fresh': self.fresh(feed), 'updated_ms': state['updated_ms'], 'last_error': state['last_error']})
        return rows

    def _domains(self, value):
        labels = value.split('.')
        return ['.'.join(labels[i:]) for i in range(len(labels) - 1)]

    def _note(self, feed, category, **extra):
        return Observation(source=feed.name, publisher=feed.publisher, status=HIT, stance=feed.stance, quality=feed.quality, confidence=feed.confidence,
                           categories=[category] if category else [], reputation=feed.stance != 'context', **extra)

    def lookup(self, kind, value):
        """Observations from every usable feed that covers this kind. A stale feed cannot say clean."""
        found = []
        for feed in self.feeds:
            covers = feed.format == 'indicators' or feed.kind == kind or (kind == ind.URL and feed.kind == ind.DOMAIN)
            if not feed.enabled or not covers:
                continue
            if not self.fresh(feed):
                found.append(Observation(source=feed.name, publisher=feed.publisher, status=SKIPPED, detail={'reason': 'stale or empty'}, reputation=feed.stance != 'context'))
                continue
            hit = None
            if kind == ind.IP:
                rows = [r for r in self.store.intel(ind.IP, value) if r['feed'] == feed.name]
                if rows:
                    hit = self._note(feed, rows[0]['category'], first_seen=rows[0]['first_seen'], last_seen=rows[0]['last_seen'])
                else:
                    category = self.store.in_range(feed.name, value)
                    hit = self._note(feed, category) if category else None
            elif feed.kind == ind.DOMAIN or (feed.format == 'indicators' and kind == ind.DOMAIN):
                host = ind.host_of(value) if kind == ind.URL else value
                names = self._domains(host) if host and ind.normalize_domain(host) else []
                for name in names:
                    rows = [r for r in self.store.intel(ind.DOMAIN, name) if r['feed'] == feed.name]
                    if rows:
                        hit = self._note(feed, rows[0]['category'], detail={'matched': name})
                        break
            else:
                rows = [r for r in self.store.intel(kind, value) if r['feed'] == feed.name]
                hit = self._note(feed, rows[0]['category'], first_seen=rows[0]['first_seen'], last_seen=rows[0]['last_seen']) if rows else None
            # An owner file holds what the owner happens to know, so a miss there is not an answer.
            miss = SKIPPED if feed.format == 'indicators' else NO_MATCH
            found.append(hit or Observation(source=feed.name, publisher=feed.publisher, status=miss, reputation=feed.stance != 'context'))
        return found


def entropy(text):
    counts = {c: text.count(c) for c in set(text)}
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def domain_signals(name):
    """Features of the name itself, with no lookup. Weak on purpose: alone, never above unknown."""
    label = max(name.split('.')[:-1] or [name], key=len)
    signals = []
    if 'xn--' in name:
        signals.append('punycode')
    if len(label) >= 30:
        signals.append('long-label')
    if len(label) >= 16 and entropy(label) >= 3.8:
        signals.append('high-entropy-label')
    if name.count('.') >= 5:
        signals.append('many-labels')
    return signals


def heuristics(kind, value):
    signals = domain_signals(value) if kind == ind.DOMAIN else []
    if not signals:
        return []
    return [Observation(source='domain-heuristics', publisher='local-heuristics', status=HIT, stance='suspicious', quality=0.3, confidence=min(30 + 15 * len(signals), 70), categories=signals)]


class Geo:
    """Country, region and ASN from memory-mapped files, so the data is not loaded into process memory."""

    def __init__(self, folder):
        self.folder = Path(folder)
        self.readers = {}

    def _reader(self, name):
        if name not in self.readers:
            path = self.folder / f'{name}.mmdb'
            if not path.exists():
                self.readers[name] = None
            else:
                import maxminddb
                self.readers[name] = maxminddb.open_database(str(path), maxminddb.MODE_MMAP)
        return self.readers[name]

    def close(self):
        for reader in self.readers.values():
            if reader:
                reader.close()
        self.readers = {}

    def lookup(self, address):
        if not ind.is_public_ip(address):
            return {}
        found = {}
        city = self._reader('city')
        if city:
            row = city.get(address) or {}
            found['country'] = (row.get('country') or {}).get('iso_code')
            found['region'] = ((row.get('subdivisions') or [{}])[0].get('names') or {}).get('en')
        asn = self._reader('asn')
        if asn:
            row = asn.get(address) or {}
            found['asn'] = row.get('autonomous_system_number')
            found['organization'] = untrusted.label(row.get('autonomous_system_organization'))
        return {k: v for k, v in found.items() if v is not None}

    def status(self):
        return {name: (self.folder / f'{name}.mmdb').exists() for name in ('city', 'asn')}

    def age_days(self):
        """Days since the oldest file was written. A missing file counts as very old."""
        paths = [self.folder / f'{name}.mmdb' for name in ('city', 'asn')]
        if not all(p.exists() for p in paths):
            return 99999
        return (time.time() - min(p.stat().st_mtime for p in paths)) / 86400


def update_geo(web, folder, name, url_template, clock, max_bytes=157286400, log=print):
    """Downloads one DB-IP Lite file. It is unpacked, opened and checked before it replaces the old one."""
    import maxminddb
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    now = datetime.fromtimestamp(clock() / 1000, timezone.utc)
    months = [now.strftime('%Y-%m'), f'{now.year if now.month > 1 else now.year - 1}-{(now.month - 1) or 12:02d}']
    for month in months:
        status, _, body = web.fetch(url_template.format(month=month), max_bytes=max_bytes)
        if status == 200:
            break
    else:
        raise FeedError(f'no {name} file for {months}')
    handle, spare = tempfile.mkstemp(dir=folder, suffix='.tmp')
    try:
        with os.fdopen(handle, 'wb') as out, gzip.GzipFile(fileobj=__import__('io').BytesIO(body)) as packed:
            shutil.copyfileobj(packed, out, 1048576)
        with maxminddb.open_database(spare, maxminddb.MODE_MMAP) as reader:
            reader.get('8.8.8.8')
        os.chmod(spare, 0o640)
        os.replace(spare, folder / f'{name}.mmdb')
    finally:
        if os.path.exists(spare):
            os.unlink(spare)
    return month
