"""Reads what the SIEM already exposes. Nothing here writes, and nothing here trusts what it reads.

Each collector returns a dictionary with `ok`, or `ok: False` and an `error` class. An error is a fact about
this monitor's view, not about the thing it looked at, so callers must never read it as a failure of that thing.
"""
import base64
import json
import math
import os
import re
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

UNIT_PROPERTIES = ('Id', 'LoadState', 'ActiveState', 'SubState', 'Result', 'NRestarts', 'MemoryCurrent', 'CPUUsageNSec', 'StateChangeTimestampMonotonic')
UNIT_NAME = re.compile(r'^[a-z][a-z0-9-]{0,48}\.(service|timer|target)$')
SYSTEMCTL = '/usr/bin/systemctl'
MAX_NUMBER = 1e18
LINE = re.compile(r'^([a-z_][a-z0-9_]{0,100})(?:\{(.{0,600})\})? (-?[0-9.]+(?:e[+-]?[0-9]+)?)(?: [0-9]{1,16})?$', re.I)
LABEL = re.compile(r'([a-z_][a-z0-9_]{0,40})="([^"\\]{0,120})"', re.I)
PREFIXES = ('vector_component_received_events_total', 'vector_component_sent_events_total', 'vector_component_errors_total', 'vector_component_discarded_events_total',
            'vector_buffer_size_events', 'seal_verifier_')
SAFE_TEXT = re.compile(r'[^A-Za-z0-9 ._:/-]')


def clean(value, limit=80):
    """Text from a report is data. It is cut down to something that cannot steer a terminal or a query."""
    return SAFE_TEXT.sub('', str(value))[:limit]


def number(value, low=0, high=MAX_NUMBER):
    """A finite number inside the bounds, or None. Booleans are not numbers."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value if low <= value <= high else None


def parse_metrics(text, limit):
    """(series, malformed). Series are (name, labels, value). Lines we do not want are skipped before any regex."""
    series, bad = [], 0
    for line in text.split('\n'):
        if not line.startswith(PREFIXES):
            continue
        if len(series) >= limit:
            bad += 1
            break
        match = LINE.match(line)
        if not match:
            bad += 1
            continue
        try:
            value = float(match[3])
        except ValueError:
            bad += 1
            continue
        if number(value) is None:
            bad += 1
            continue
        series.append((match[1], dict(LABEL.findall(match[2] or '')), value))
    return series, bad


def vector_summary(series):
    """Sums Vector series into plain counters, keyed by what a person would ask about."""
    out = {'received': {}, 'sent': {}, 'errors': {}, 'discarded': {}, 'buffered': {}}
    for name, labels, value in series:
        component = clean(labels.get('component_id', ''), 40)
        if not component:
            continue
        if name == 'vector_component_received_events_total':
            out['received'][component] = out['received'].get(component, 0) + value
        elif name == 'vector_component_sent_events_total':
            key = f"{component}:{clean(labels.get('output', '_default'), 24)}"
            out['sent'][key] = out['sent'].get(key, 0) + value
        elif name == 'vector_component_errors_total':
            out['errors'][component] = out['errors'].get(component, 0) + value
        elif name == 'vector_component_discarded_events_total' and labels.get('intentional') != 'true':
            out['discarded'][component] = out['discarded'].get(component, 0) + value
        elif name == 'vector_buffer_size_events':
            out['buffered'][component] = out['buffered'].get(component, 0) + value
    return out


def verifier_summary(series):
    reasons = {}
    for name, labels, value in series:
        if name == 'seal_verifier_events_total':
            reason = clean(labels.get('result', 'other'), 40)
            if reason in reasons or len(reasons) < 40:
                reasons[reason] = reasons.get(reason, 0) + value
    return {'reasons': reasons}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Collector:
    def __init__(self, config, run=subprocess.run, kafka_client=None, opener=None):
        self.config = config
        self.run = run
        self.kafka_client = kafka_client
        self.context = None
        self.header = None
        self.opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        self.stats = {}

    # Bookkeeping for self-monitoring.
    def note(self, name, outcome):
        row = self.stats.setdefault(name, {'ok': 0, 'failed': 0, 'timeouts': 0, 'last_error': None})
        if outcome == 'ok':
            row['ok'] += 1
        else:
            row['failed'] += 1
            row['last_error'] = outcome
            if outcome == 'timeout':
                row['timeouts'] += 1

    def guarded(self, name, function, *args):
        try:
            result = function(*args)
        except Exception as error:  # A collector must never end a cycle.
            result = {'ok': False, 'error': self.classify(error)}
        self.note(name, 'ok' if result.get('ok') else result.get('error', 'failed'))
        return result

    @staticmethod
    def classify(error):
        if isinstance(error, urllib.error.HTTPError):
            return 'denied' if error.code in (401, 403) else 'http_error'
        reason = getattr(error, 'reason', error)
        if isinstance(reason, (socket.timeout, TimeoutError)) or isinstance(error, (socket.timeout, TimeoutError, subprocess.TimeoutExpired)):
            return 'timeout'
        if isinstance(reason, ConnectionRefusedError):
            return 'refused'
        if isinstance(reason, ssl.SSLError):
            return 'tls_error'
        if isinstance(error, PermissionError):
            return 'denied'
        if isinstance(error, (ValueError, KeyError, TypeError, AttributeError, IndexError)):
            return 'malformed'
        return 'unavailable'

    # HTTP, bounded in time and size.
    def fetch(self, url, body=None, headers=None, timeout=None, context=None):
        request = urllib.request.Request(url, data=body, headers=headers or {}, method='POST' if body else 'GET')
        limit = self.config['bounds']['max_response_bytes']
        kwargs = {'context': context} if context else {}
        with self._open(request, timeout or self.config['timeouts']['http_seconds'], kwargs) as reply:
            data = reply.read(limit + 1)
        if len(data) > limit:
            raise ValueError('response too large')
        return data

    def _open(self, request, timeout, kwargs):
        if kwargs:
            handler = urllib.request.HTTPSHandler(context=kwargs['context'])
            return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), handler).open(request, timeout=timeout)
        return self.opener.open(request, timeout=timeout)

    def metrics(self, url):
        text = self.fetch(url).decode('utf-8', 'replace')
        series, bad = parse_metrics(text, self.config['bounds']['max_series'])
        if not series and bad:
            return {'ok': False, 'error': 'malformed'}
        return {'ok': True, 'series': series, 'malformed': bad}

    # Service state through systemd's own read interface. A fixed argument list, with no shell.
    def systemd(self, units):
        for unit in units:
            if not UNIT_NAME.match(unit):
                raise ValueError('bad unit name')
        done = self.run([SYSTEMCTL, 'show', '--no-pager', '--property=' + ','.join(UNIT_PROPERTIES), *units], capture_output=True, text=True,
                        timeout=self.config['timeouts']['systemctl_seconds'], check=False, stdin=subprocess.DEVNULL)
        if done.returncode != 0:
            return {'ok': False, 'error': 'unavailable'}
        found = {}
        for block in done.stdout[:200000].split('\n\n'):
            row = dict(line.split('=', 1) for line in block.splitlines() if '=' in line)
            name = row.get('Id')
            if name not in units:
                continue
            found[name] = {'load': clean(row.get('LoadState', 'loaded'), 24), 'active': clean(row.get('ActiveState', 'unknown'), 24), 'sub': clean(row.get('SubState', ''), 24), 'result': clean(row.get('Result', ''), 24),
                           'restarts': self._int(row.get('NRestarts')), 'memory': self._int(row.get('MemoryCurrent')), 'cpu_ns': self._int(row.get('CPUUsageNSec')),
                           'since_mono_us': self._int(row.get('StateChangeTimestampMonotonic'))}
        if set(found) != set(units):
            return {'ok': False, 'error': 'malformed'}
        return {'ok': True, 'units': found}

    @staticmethod
    def _int(text):
        try:
            value = int(text)
        except (TypeError, ValueError):
            return None
        return value if 0 <= value < 2 ** 63 - 1 else None  # systemd prints the top value for "not known".

    # Service reports. Size and shape are checked, and the age is judged later, by the assessment.
    def report(self, path):
        limit = self.config['bounds']['max_report_bytes']
        target = Path(path)
        try:
            if target.is_symlink():
                return {'ok': False, 'error': 'malformed'}
            with open(target, 'rb') as handle:
                data = handle.read(limit + 1)
        except FileNotFoundError:
            return {'ok': False, 'error': 'missing'}
        if len(data) > limit:
            return {'ok': False, 'error': 'malformed'}
        body = json.loads(data.decode('utf-8'))
        checked = number(body.get('checked_ms')) if isinstance(body, dict) else None
        if checked is None:
            return {'ok': False, 'error': 'malformed'}
        return {'ok': True, 'body': body, 'checked_ms': int(checked)}

    # Kafka, through metadata and offset requests only. This joins no group and reads no message.
    def kafka(self):
        client = (self.kafka_client or self._admin)()
        settings = self.config['kafka']
        timeout = self.config['timeouts']['kafka_seconds']
        meta = client.list_topics(timeout=timeout)
        topics = {}
        for name in (settings['raw_topic'], settings['alert_topic'], settings['incident_topic']):
            topic = meta.topics.get(name)
            if topic is None or topic.error is not None:
                topics[name] = {'exists': False, 'partitions': 0, 'leaderless': 0}
            else:
                topics[name] = {'exists': True, 'partitions': len(topic.partitions), 'leaderless': sum(1 for p in topic.partitions.values() if p.leader < 0 or p.error is not None)}
        ends = self._ends(client, topics, timeout)
        groups = {}
        for group, topic in ((settings['raw_group'], settings['raw_topic']), (settings['alert_group'], settings['alert_topic'])):
            groups[group] = self._group(client, group, topic, ends.get(topic, {}), timeout)
        return {'ok': True, 'brokers': len(meta.brokers), 'topics': topics, 'end_offsets': {k: sum(v.values()) for k, v in ends.items()}, 'groups': groups}

    def _admin(self):
        from confluent_kafka.admin import AdminClient
        return AdminClient({'bootstrap.servers': self.config['endpoints']['kafka'], 'socket.timeout.ms': self.config['timeouts']['kafka_seconds'] * 1000, 'log_level': 0, 'client.id': 'siem-health'})

    @staticmethod
    def _ends(client, topics, timeout):
        from confluent_kafka import TopicPartition
        from confluent_kafka.admin import OffsetSpec
        wanted = {TopicPartition(name, partition): OffsetSpec.latest() for name, row in topics.items() if row['exists'] for partition in range(row['partitions'])}
        ends = {}
        if wanted:
            for partition, future in client.list_offsets(wanted, request_timeout=timeout).items():
                ends.setdefault(partition.topic, {})[partition.partition] = future.result(timeout=timeout).offset
        return ends

    @staticmethod
    def _group(client, group, topic, ends, timeout):
        from confluent_kafka import ConsumerGroupTopicPartitions
        request = [ConsumerGroupTopicPartitions(group)]
        result = client.list_consumer_group_offsets(request, request_timeout=timeout)[group].result(timeout=timeout)
        committed = {p.partition: p.offset for p in result.topic_partitions if p.topic == topic and p.offset >= 0}
        if not committed:
            return {'known': False, 'reason': 'no committed offset'}
        lag = sum(max(0, ends.get(partition, 0) - offset) for partition, offset in committed.items())
        return {'known': True, 'committed': sum(committed.values()), 'lag': lag}

    # OpenSearch. Metadata and statistics only.
    def _ssl(self):
        if self.context is None:
            self.context = ssl.create_default_context(cafile=self.config['opensearch']['ca_file'])
        return self.context

    def _auth(self):
        if self.header is None:
            with open(self.config['opensearch']['login_file'], encoding='utf-8') as handle:
                login = json.load(handle)
            token = base64.b64encode(f"{login['user']}:{login['password']}".encode()).decode()
            self.header = {'Authorization': f'Basic {token}', 'Content-Type': 'application/json'}
        return self.header

    def search_api(self, path, body=None):
        data = self.fetch(self.config['opensearch']['url'] + path, json.dumps(body).encode() if body is not None else None, self._auth(), self.config['timeouts']['opensearch_seconds'], self._ssl())
        return json.loads(data)

    def opensearch(self):
        health = self.search_api('/_cluster/health?level=indices&timeout=2s&filter_path=status,number_of_nodes,active_shards,unassigned_shards,indices.*.status,indices.*.unassigned_shards')
        stats = self.search_api('/_nodes/_local/stats/jvm,fs,indices,thread_pool?filter_path=nodes.*.jvm.mem.heap_used_percent,nodes.*.fs.total,nodes.*.indices.indexing,nodes.*.thread_pool.write,nodes.*.thread_pool.search')
        node = next(iter(stats['nodes'].values()))
        groups = {}
        for name, pattern in (('windows', 'siem-windows-*'), ('linux', 'siem-linux-*'), ('deadletter', 'siem-deadletter-*'), ('alerts', 'siem-alerts-*')):
            found = self.search_api(f'/{pattern}/_stats/docs,store,indexing?filter_path=_all.primaries.docs.count,_all.primaries.store.size_in_bytes,_all.primaries.indexing.index_total,_all.primaries.indexing.index_failed&allow_no_indices=true')
            row = found.get('_all', {}).get('primaries', {})
            groups[name] = {'docs': number(row.get('docs', {}).get('count')), 'bytes': number(row.get('store', {}).get('size_in_bytes')), 'indexed': number(row.get('indexing', {}).get('index_total')), 'failed': number(row.get('indexing', {}).get('index_failed'))}
        unassigned = {'siem': 0, 'other': 0}
        for index, row in health.get('indices', {}).items():
            count = number(row.get('unassigned_shards')) or 0
            unassigned['siem' if str(index).startswith('siem-') else 'other'] += count
        fs = node.get('fs', {}).get('total', {})
        indexing = node.get('indices', {}).get('indexing', {})
        pools = node.get('thread_pool', {})
        status = health.get('status')
        if status not in ('green', 'yellow', 'red'):
            return {'ok': False, 'error': 'malformed'}
        return {'ok': True, 'status': status, 'nodes': number(health.get('number_of_nodes')), 'active_shards': number(health.get('active_shards')), 'unassigned': unassigned,
                'heap_percent': number(node.get('jvm', {}).get('mem', {}).get('heap_used_percent'), 0, 100), 'disk_total': number(fs.get('total_in_bytes')), 'disk_free': number(fs.get('available_in_bytes')),
                'index_total': number(indexing.get('index_total')), 'index_time_ms': number(indexing.get('index_time_in_millis')), 'index_failed': number(indexing.get('index_failed')),
                'write_rejected': number(pools.get('write', {}).get('rejected')), 'search_rejected': number(pools.get('search', {}).get('rejected')), 'write_queue': number(pools.get('write', {}).get('queue')), 'groups': groups}

    def events(self, now_ms, datasets):
        """Newest event per dataset, and a bounded sample of recent events. Only the two newest daily indices of each kind are read."""
        days = [time.strftime('%Y.%m.%d', time.gmtime((now_ms - shift * 86400000) / 1000)) for shift in (0, 1)]
        indices = ','.join(f'siem-{kind}-{day}' for kind in ('windows', 'linux') for day in days)
        query = {'size': 0, 'query': {'bool': {'filter': [{'terms': {'event.dataset': list(datasets)}}]}},
                 'aggs': {'sets': {'terms': {'field': 'event.dataset', 'size': max(1, len(datasets))}, 'aggs': {'newest': {'max': {'field': '@timestamp'}}, 'ingested': {'max': {'field': 'event.ingested'}}}}}}
        found = self.search_api(f'/{indices}/_search?ignore_unavailable=true&allow_no_indices=true&timeout=3s&request_cache=false', query)
        sets = {}
        for bucket in found.get('aggregations', {}).get('sets', {}).get('buckets', []):
            if bucket.get('key') in datasets:
                sets[bucket['key']] = {'newest_ms': number(bucket.get('newest', {}).get('value')), 'ingested_ms': number(bucket.get('ingested', {}).get('value')), 'count': number(bucket.get('doc_count'))}
        window = self.config['freshness']['event_sample_seconds'] * 1000
        sample = {'size': self.config['bounds']['sample_events'], 'sort': [{'event.ingested': 'desc'}], '_source': ['@timestamp', 'event.ingested', 'event.dataset'],
                  'query': {'range': {'event.ingested': {'gte': int(now_ms - window), 'format': 'epoch_millis'}}}}
        recent = self.search_api(f'/{indices}/_search?ignore_unavailable=true&allow_no_indices=true&timeout=3s', sample)
        pairs = {}
        for hit in recent.get('hits', {}).get('hits', []):
            source = hit.get('_source', {})
            event = source.get('event', {}) if isinstance(source.get('event'), dict) else {}
            stamp, ingested = parse_time(source.get('@timestamp')), parse_time(event.get('ingested'))
            if stamp is None or ingested is None:
                continue
            platform = 'windows' if str(event.get('dataset', '')).startswith('windows.') else 'linux'
            pairs.setdefault(platform, []).append((ingested - stamp) / 1000)
        return {'ok': True, 'sets': sets, 'latency': pairs, 'sampled': sum(len(v) for v in pairs.values())}

    def analysis(self, now_ms):
        """Delays that the stored records themselves state. A small sample of the newest, never a scan."""
        size = self.config['bounds']['sample_alerts']
        alerts = self.search_api('/siem-alerts-*/_search?ignore_unavailable=true&allow_no_indices=true&timeout=3s', {'size': size, 'sort': [{'detected_at': 'desc'}], '_source': ['timestamp', 'detected_at']})
        enrichment = self.search_api('/siem-enrichment-*/_search?ignore_unavailable=true&allow_no_indices=true&timeout=3s', {'size': size, 'sort': [{'enriched_at': 'desc'}], '_source': ['@timestamp', 'enriched_at']})
        detection = [diff for diff in (self._gap(h, 'timestamp', 'detected_at') for h in alerts.get('hits', {}).get('hits', [])) if diff is not None]
        enrich = [diff for diff in (self._gap(h, '@timestamp', 'enriched_at') for h in enrichment.get('hits', {}).get('hits', [])) if diff is not None]
        return {'ok': True, 'detection_delay': detection, 'enrichment_delay': enrich}

    @staticmethod
    def _gap(hit, start, end):
        source = hit.get('_source', {})
        first, last = parse_time(source.get(start)), parse_time(source.get(end))
        return (last - first) / 1000 if first is not None and last is not None else None

    def retention(self):
        """How many SIEM indices the retention engine reports as failed. Sampled rarely."""
        found = self.search_api('/_plugins/_ism/explain/siem-*?size=200&show_policy=false')
        total, failed = 0, 0
        for name, row in found.items():
            if isinstance(row, dict) and str(name).startswith('siem-') and row.get('policy_id') or (isinstance(row, dict) and row.get('index.plugins.index_state_management.policy_id')):
                total += 1
                if isinstance(row.get('retry_info'), dict) and row['retry_info'].get('failed') or (isinstance(row.get('info'), dict) and 'cause' in row['info']):
                    failed += 1
        return {'ok': True, 'managed': total, 'failed': failed}

    # The host, from the kernel's own files.
    def host(self):
        info = {}
        with open('/proc/meminfo', encoding='ascii') as handle:
            for line in handle:
                key, _, rest = line.partition(':')
                if key in ('MemTotal', 'MemAvailable', 'SwapTotal', 'SwapFree'):
                    info[key] = int(rest.split()[0]) * 1024
        with open('/proc/loadavg', encoding='ascii') as handle:
            load = float(handle.read().split()[0])
        out = {'ok': True, 'mem_total': info['MemTotal'], 'mem_available': info['MemAvailable'], 'swap_total': info.get('SwapTotal', 0), 'swap_used': info.get('SwapTotal', 0) - info.get('SwapFree', 0),
               'load1': load, 'cpus': os.cpu_count() or 1, 'pressure': {}}
        for name in ('memory', 'cpu', 'io'):
            out['pressure'][name] = self._pressure(name)
        for name, path in (('root', '/'), ('windows', self.config['windows_disk_path'])):
            out[f'disk_{name}'] = self._disk(path)
        with open('/proc/stat', encoding='ascii') as handle:
            for line in handle:
                if line.startswith('btime '):
                    out['boot_ms'] = int(line.split()[1]) * 1000
                    break
        return out

    @staticmethod
    def _pressure(name):
        try:
            with open(f'/proc/pressure/{name}', encoding='ascii') as handle:
                rows = {}
                for line in handle:
                    kind, *pairs = line.split()
                    rows[kind] = float(dict(pair.split('=') for pair in pairs)['avg60'])
                return rows
        except (OSError, ValueError, KeyError):
            return None

    @staticmethod
    def _disk(path):
        try:
            stat = os.statvfs(path)
        except OSError:
            return None
        return {'total': stat.f_frsize * stat.f_blocks, 'free': stat.f_frsize * stat.f_bavail}

    def self_usage(self):
        usage = {'rss': None}
        with open('/proc/self/status', encoding='ascii') as handle:
            for line in handle:
                if line.startswith('VmRSS:'):
                    usage['rss'] = int(line.split()[1]) * 1024
        times = os.times()
        usage['cpu_seconds'] = times.user + times.system
        return usage


def parse_time(text):
    """Milliseconds since the epoch from an ISO 8601 UTC stamp, or None. Anything else is ignored."""
    if not isinstance(text, str) or not 20 <= len(text) <= 35 or not text.endswith('Z'):
        return None
    try:
        whole, _, rest = text[:-1].partition('.')
        base = time.strptime(whole, '%Y-%m-%dT%H:%M:%S')
        fraction = int((rest + '000')[:3]) if rest else 0
    except ValueError:
        return None
    import calendar
    return calendar.timegm(base) * 1000 + fraction
