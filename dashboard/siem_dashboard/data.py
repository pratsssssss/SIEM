"""Everything the screens show. Queries are fixed shapes with bound values, and user input never becomes query syntax.

A section that cannot be read says so. Nothing here substitutes a zero, a guess or a green light for missing data, and
nothing here works out health: Phase 16 does that, and this only passes it on.
"""
import re
import time

from .backends import NotFound, Rejected, Unavailable

ID = re.compile(r'^[A-Za-z0-9_.:\-]{1,128}$')
EVENT_INDEX = re.compile(r'^siem-(windows|linux)-\d{4}\.\d{2}\.\d{2}$')
EVENT_FILTERS = {'host': 'host.name', 'dataset': 'event.dataset', 'category': 'event.category', 'type': 'event.type', 'outcome': 'event.outcome', 'level': 'log.level', 'code': 'event.code', 'action': 'event.action', 'user': 'user.name', 'process': 'process.name', 'source_ip': 'source.ip', 'destination_ip': 'destination.ip', 'event_id': 'event.id'}
EVENT_SORTS = {'time': '@timestamp', 'ingested': 'event.ingested'}
ALERT_FILTERS = {'severity': 'severity', 'rule': 'rule_id', 'host': 'host', 'user': 'user', 'type': 'detection_type', 'alert_id': 'alert_id', 'source_ip': 'source_ip'}
ALERT_SORTS = {'detected': 'detected_at', 'event_time': 'timestamp', 'severity': 'severity'}
SEVERITIES = ('critical', 'high', 'medium', 'low', 'informational')
RANGES = {'1h': 1, '6h': 6, '24h': 24, '7d': 168, '30d': 720}
ALERT_FIELDS = ['alert_id', 'rule_id', 'rule_name', 'detection_type', 'severity', 'confidence', 'timestamp', 'detected_at', 'description', 'host', 'user', 'source_ip', 'event_count', 'source_event_ids', 'raw_event_refs', 'evidence_ref', 'mitre', 'evidence.first_seen', 'evidence.last_seen', 'evidence.rule_fields']
VERDICTS = ('malicious', 'suspicious', 'conflicting', 'unknown', 'no_known_threat', 'lookup_failed')
RESTRICTED_NOTE = 'Command lines, script text, message bodies and file paths are withheld from this account by OpenSearch field level security, so they cannot be shown here.'


def iso(ms):
    return time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(ms / 1000)) + 'Z'


def section(function, *args):
    """One part of a page. Its failure is reported in place, and the rest of the page goes on."""
    try:
        return {'status': 'ok', 'data': function(*args)}
    except Unavailable as error:
        return {'status': 'unavailable', 'reason': error.reason}
    except NotFound:
        return {'status': 'missing', 'reason': 'Not found'}
    except Rejected as error:
        return {'status': 'unavailable', 'reason': error.reason}


def hits(reply):
    return reply.get('hits', {}).get('hits', [])


def total(reply):
    value = reply.get('hits', {}).get('total', 0)
    return value if isinstance(value, dict) else {'value': value, 'relation': 'eq'}


def buckets(reply, name):
    return reply.get('aggregations', {}).get(name, {}).get('buckets', [])


class BadInput(ValueError):
    pass


def identifier(value, what='identifier'):
    if not isinstance(value, str) or not ID.match(value):
        raise BadInput(f'That is not a valid {what}')
    return value


def pick(params, name, allowed, default=None):
    value = params.get(name, default)
    if value is not None and value not in allowed:
        raise BadInput(f'{name} is not one of the allowed values')
    return value


class Data:
    def __init__(self, search, sockets, health, config, clock=None):
        self.search = search
        self.sockets = sockets
        self.health = health
        self.config = config
        self.limits = config['limits']
        self.clock = clock or (lambda: int(time.time() * 1000))
        self.cache = {}

    def cached(self, key, function):
        """A short memory, so several screens cannot turn into many identical searches."""
        now = self.clock()
        row = self.cache.get(key)
        if row and now - row[0] <= self.limits['cache_seconds'] * 1000:
            return row[1]
        value = function()
        if len(self.cache) > 32:
            self.cache.clear()
        self.cache[key] = (now, value)
        return value

    # Paging and time, enforced here whatever the browser sends.
    def paging(self, params):
        try:
            size = int(params.get('size', 25))
            offset = int(params.get('offset', 0))
        except ValueError:
            raise BadInput('size and offset must be numbers') from None
        if not 1 <= size <= self.limits['page_size'] or not 0 <= offset <= self.limits['max_offset']:
            raise BadInput(f"size must be 1 to {self.limits['page_size']}, and offset at most {self.limits['max_offset']}")
        return size, offset

    def window(self, params, default='24h'):
        now = self.clock()
        chosen = params.get('range', default)
        if chosen == 'custom':
            try:
                first, last = int(params['from']), int(params['to'])
            except (KeyError, ValueError):
                raise BadInput('A custom range needs from and to, in milliseconds') from None
            if first >= last or last - first > self.limits['max_days'] * 86400000:
                raise BadInput(f"A custom range must be under {self.limits['max_days']} days")
            return first, last
        if chosen not in RANGES:
            raise BadInput('range is not one of the allowed values')
        return now - RANGES[chosen] * 3600000, now

    @staticmethod
    def term_filters(params, allowed):
        terms = []
        for name, field in allowed.items():
            value = params.get(name)
            if value in (None, ''):
                continue
            if not isinstance(value, str) or len(value) > 256 or any(ord(c) < 32 for c in value):
                raise BadInput(f'{name} is not valid')
            # A term query takes the value as data. There is no query syntax to inject into.
            terms.append({'term': {field: value}})
        return terms

    # Events.
    def event_indices(self, first, last, platform):
        kinds = {'windows': ['windows'], 'linux': ['linux']}.get(platform, ['windows', 'linux'])
        days, moment = [], first - first % 86400000
        while moment <= last and len(days) <= self.limits['max_days']:
            days.append(time.strftime('%Y.%m.%d', time.gmtime(moment / 1000)))
            moment += 86400000
        return ','.join(f'siem-{k}-{d}' for k in kinds for d in days)

    def events(self, params):
        first, last = self.window(params)
        size, offset = self.paging(params)
        platform = pick(params, 'platform', ('windows', 'linux'))
        sort = EVENT_SORTS[pick(params, 'sort', EVENT_SORTS, 'time')]
        order = pick(params, 'order', ('asc', 'desc'), 'desc')
        filters = [{'range': {'@timestamp': {'gte': first, 'lte': last, 'format': 'epoch_millis'}}}] + self.term_filters(params, EVENT_FILTERS)
        body = {'size': size, 'from': offset, 'sort': [{sort: order}], 'track_total_hits': 10000, 'query': {'bool': {'filter': filters}}}
        reply = self.search.search(self.event_indices(first, last, platform), body)
        return {'rows': [self.event_row(h) for h in hits(reply)], 'total': total(reply), 'size': size, 'offset': offset, 'from_ms': first, 'to_ms': last, 'restricted_note': RESTRICTED_NOTE, 'searched': 'Exact match on the chosen fields, over daily indices. Events are kept 7 days'}

    @staticmethod
    def event_row(hit):
        source = hit.get('_source', {})
        event = source.get('event') if isinstance(source.get('event'), dict) else {}
        return {'index': hit.get('_index'), 'id': hit.get('_id'), 'at': source.get('@timestamp'), 'ingested': event.get('ingested'), 'dataset': event.get('dataset'), 'category': event.get('category'), 'type': event.get('type'), 'action': event.get('action'), 'outcome': event.get('outcome'), 'code': event.get('code'),
                'host': (source.get('host') or {}).get('name') if isinstance(source.get('host'), dict) else None, 'user': (source.get('user') or {}).get('name') if isinstance(source.get('user'), dict) else None, 'level': (source.get('log') or {}).get('level') if isinstance(source.get('log'), dict) else None, 'process': (source.get('process') or {}).get('name') if isinstance(source.get('process'), dict) else None}

    def event(self, index, event_id):
        if not EVENT_INDEX.match(index or ''):
            raise BadInput('That is not an event index')
        identifier(event_id, 'event ID')
        reply = self.search.search(index, {'size': 1, 'query': {'ids': {'values': [event_id]}}})
        found = hits(reply)
        if not found:
            raise NotFound('no such event. It may have passed the 7-day retention')
        source = found[0].get('_source', {})
        event = source.get('event') if isinstance(source.get('event'), dict) else {}
        alerts = section(self.alerts_for_event, index, event_id, event.get('id'))
        return {'index': index, 'id': event_id, 'row': self.event_row(found[0]), 'fields': self.flatten(source), 'alerts': alerts, 'assets': section(self.asset_named, self.event_row(found[0])['host']), 'provenance': {'stored_in': index, 'kafka': source.get('siem'), 'ingested': event.get('ingested'), 'sealed': 'Events reach this index only after the verifier accepts their seal'}, 'restricted_note': RESTRICTED_NOTE}

    @staticmethod
    def flatten(value, prefix=''):
        rows = {}
        for key, item in value.items():
            name = f'{prefix}{key}'
            if isinstance(item, dict):
                rows.update(Data.flatten(item, name + '.'))
            else:
                rows[name] = item
        return dict(sorted(rows.items()))

    def alerts_for_event(self, index, doc_id, event_id):
        ids = [doc_id] + ([str(event_id)] if event_id else [])
        reply = self.search.search('siem-alerts-*', {'size': 20, '_source': ALERT_FIELDS, 'query': {'bool': {'should': [{'terms': {'source_event_ids': ids}}, {'term': {'raw_event_refs': f'{index}/{doc_id}'}}], 'minimum_should_match': 1}}})
        return [self.alert_row(h) for h in hits(reply)]

    def asset_named(self, host):
        if not host:
            return []
        # Phase 14's own search decides what matches. Nothing is merged or resolved here.
        return self.sockets.call('assets', 'search', query=str(host)[:128], limit=5)

    # Alerts.
    @staticmethod
    def alert_row(hit):
        source = hit.get('_source', {})
        return {k: source.get(k) for k in ('alert_id', 'rule_id', 'rule_name', 'detection_type', 'severity', 'confidence', 'timestamp', 'detected_at', 'host', 'user', 'source_ip', 'event_count')}

    def alerts(self, params):
        first, last = self.window(params, '7d')
        size, offset = self.paging(params)
        sort = ALERT_SORTS[pick(params, 'sort', ALERT_SORTS, 'detected')]
        order = pick(params, 'order', ('asc', 'desc'), 'desc')
        pick(params, 'severity', SEVERITIES)
        filters = [{'range': {'detected_at': {'gte': first, 'lte': last, 'format': 'epoch_millis'}}}] + self.term_filters(params, ALERT_FILTERS)
        reply = self.search.search('siem-alerts-*', {'size': size, 'from': offset, 'sort': [{sort: order}], 'track_total_hits': 10000, '_source': ALERT_FIELDS, 'query': {'bool': {'filter': filters}}})
        rows = [self.alert_row(h) for h in hits(reply)]
        links = self.cached_verdicts([r['alert_id'] for r in rows])
        for row in rows:
            row['verdict'] = links.get(row['alert_id'])
        return {'rows': rows, 'total': total(reply), 'size': size, 'offset': offset, 'from_ms': first, 'to_ms': last}

    def cached_verdicts(self, ids):
        if not ids:
            return {}
        try:
            reply = self.search.search('siem-enrichment-*', {'size': len(ids), '_source': ['alert_id', 'summary.highest_verdict'], 'query': {'terms': {'alert_id': ids}}})
        except Unavailable:
            return {}
        return {h['_source'].get('alert_id'): (h['_source'].get('summary') or {}).get('highest_verdict') for h in hits(reply)}

    def alert_record(self, alert_id):
        identifier(alert_id, 'alert ID')
        found = hits(self.search.search('siem-alerts-*', {'size': 1, '_source': ALERT_FIELDS, 'query': {'term': {'alert_id': alert_id}}}))
        if not found:
            raise NotFound('no such alert')
        return found[0]['_source']

    def alert(self, alert_id):
        source = self.alert_record(alert_id)
        return {'alert': source, 'evidence_refs': [self.reference(r) for r in (source.get('raw_event_refs') or [])[:50]], 'enrichment': section(self.enrichment_of, alert_id), 'incidents': section(self.incidents_with_alert, alert_id), 'paths': section(self.paths_for_seed, 'alert', alert_id), 'assets': section(self.asset_named, source.get('host')), 'matched_fields_note': 'The values that matched are withheld, because they can hold command lines. The field names the rule used are shown, and the events can be opened.'}

    @staticmethod
    def reference(text):
        """An event reference, broken into a link only if it is a well-formed one."""
        for mark in ('/', ':'):
            index, _, doc = str(text).partition(mark)
            if doc and EVENT_INDEX.match(index) and ID.match(doc):
                return {'index': index, 'id': doc, 'link': True}
        return {'text': str(text)[:200], 'link': False}

    def enrichment_of(self, alert_id):
        found = hits(self.search.search('siem-enrichment-*', {'size': 1, '_source': ['alert_id', 'status', 'enriched_at', 'summary', 'indicators', 'events_available', 'untrusted_notice'], 'query': {'term': {'alert_id': alert_id}}}))
        return found[0]['_source'] if found else None

    def incidents_with_alert(self, alert_id):
        return [{k: h['_source'].get(k) for k in ('incident_id', 'title', 'status', 'severity')} for h in hits(self.search.search('siem-incidents-*', {'size': 10, '_source': ['incident_id', 'title', 'status', 'severity'], 'query': {'term': {'alert_ids': alert_id}}}))]

    def paths_for_seed(self, kind, seed):
        rows = self.sockets.call('paths', 'list', limit=2000)
        return [r for r in rows if r.get('seed_kind') == kind and r.get('seed_id') == seed]

    # Incidents. The service is the record, and OpenSearch is its copy.
    def stored_alert_ids(self, ids):
        """Which alert IDs exist. Incidents with none were made by fixtures, and are kept out of security counts."""
        if not ids:
            return set()
        reply = self.search.search('siem-alerts-*', {'size': 0, 'query': {'terms': {'alert_id': ids[:5000]}}, 'aggs': {'ids': {'terms': {'field': 'alert_id', 'size': min(len(ids), 5000)}}}})
        return {b['key'] for b in buckets(reply, 'ids')}

    def incident_rows(self):
        def build():
            reply = self.search.search('siem-incidents-*', {'size': self.limits['overview_scan'], 'sort': [{'updated_at': 'desc'}], '_source': ['incident_id', 'title', 'status', 'severity', 'confidence_level', 'first_seen', 'last_seen', 'updated_at', 'hosts', 'alert_ids'], 'track_total_hits': True})
            rows = [h['_source'] for h in hits(reply)]
            stored = self.stored_alert_ids(sorted({a for r in rows for a in r.get('alert_ids', [])}))
            for row in rows:
                row['alerts'] = len(row.get('alert_ids', []))
                row['record_class'] = 'verified' if set(row.pop('alert_ids', [])) & stored else 'no_stored_alerts'
            return rows
        return self.cached('incidents', build)

    def incidents(self, params):
        size, offset = self.paging(params)
        status, severity = params.get('status'), pick(params, 'severity', SEVERITIES)
        include_fixture = params.get('include_unverified') == 'true'
        source = 'opensearch'
        try:
            rows = self.incident_rows()
        except Unavailable:
            rows = [{**r, 'record_class': 'not_checked'} for r in self.sockets.call('incidents', 'list', limit=500)]
            source = 'incident service'
        filtered = [r for r in rows if (not status or r.get('status') == status) and (not severity or r.get('severity') == severity) and (include_fixture or r.get('record_class') != 'no_stored_alerts')]
        hidden = sum(1 for r in rows if r.get('record_class') == 'no_stored_alerts')
        return {'rows': filtered[offset:offset + size], 'total': {'value': len(filtered), 'relation': 'eq'}, 'size': size, 'offset': offset, 'source': source, 'unverified_hidden': 0 if include_fixture else hidden}

    def incident(self, incident_id, rules):
        identifier(incident_id, 'incident ID')
        record = self.sockets.call('incidents', 'show', incident_id=incident_id)
        return {'incident': record, 'allowed_moves': (rules or {}).get('moves', {}).get(record.get('status')), 'needs_note': (rules or {}).get('needs_note'), 'rules_available': rules is not None}

    def incident_view(self, incident_id, rules):
        base = self.incident(incident_id, rules)
        record = base['incident']
        ids = (record.get('alert_ids') or [])[:50]
        alerts = section(self.alerts_by_id, ids)
        return {**base, 'alerts': alerts, 'evidence_refs': [self.reference(r) for r in (record.get('raw_event_refs') or [])[:60]], 'enrichment': section(self.enrichment_many, ids), 'paths': section(self.path_of_incident, incident_id), 'audit': section(self.incident_audit, incident_id), 'assets': section(self.assets_of, record.get('hosts') or []), 'record_class': self.record_class(alerts, ids)}

    @staticmethod
    def record_class(alerts, ids):
        if alerts['status'] != 'ok':
            return 'not_checked'
        return 'verified' if alerts['data'] else ('no_stored_alerts' if ids else 'no_alerts')

    def alerts_by_id(self, ids):
        if not ids:
            return []
        return [self.alert_row(h) for h in hits(self.search.search('siem-alerts-*', {'size': len(ids), '_source': ALERT_FIELDS, 'sort': [{'timestamp': 'asc'}], 'query': {'terms': {'alert_id': ids}}}))]

    def enrichment_many(self, ids):
        if not ids:
            return []
        return [h['_source'] for h in hits(self.search.search('siem-enrichment-*', {'size': len(ids), '_source': ['alert_id', 'status', 'enriched_at', 'summary', 'indicators'], 'query': {'terms': {'alert_id': ids}}}))]

    def path_of_incident(self, incident_id):
        return self.paths_for_seed('incident', incident_id)

    def assets_of(self, hosts):
        rows = []
        for host in hosts[:8]:
            rows += self.asset_named(host)
        return list({r['asset_id']: r for r in rows}.values())

    def incident_audit(self, incident_id):
        identifier(incident_id, 'incident ID')
        return self.sockets.call('incidents', 'audit', incident_id=incident_id, limit=300)

    # Assets.
    def assets(self, params):
        size, offset = self.paging(params)
        query = params.get('q')
        if query:
            if len(query) > 128:
                raise BadInput('The search is too long')
            rows = self.sockets.call('assets', 'search', query=query, limit=200)
        else:
            rows = self.sockets.call('assets', 'list', limit=500)
        for name in ('status', 'platform'):
            if params.get(name):
                rows = [r for r in rows if r.get(name) == params[name]]
        return {'rows': rows[offset:offset + size], 'total': {'value': len(rows), 'relation': 'eq'}, 'size': size, 'offset': offset}

    def asset(self, asset_id):
        identifier(asset_id, 'asset ID')
        record = self.sockets.call('assets', 'show', asset=asset_id)
        hostnames = [record.get('hostname')] + [a.get('name') for a in (record.get('identity') or {}).get('aliases', []) if isinstance(a, dict)]
        return {'asset': record, 'alerts': section(self.alerts_on_hosts, [h for h in hostnames if h]), 'incidents': section(self.incidents_on_hosts, [h for h in hostnames if h]), 'paths': section(lambda: self.sockets.call('paths', 'asset', asset=asset_id))}

    def alerts_on_hosts(self, names):
        return [self.alert_row(h) for h in hits(self.search.search('siem-alerts-*', {'size': 25, '_source': ALERT_FIELDS, 'sort': [{'detected_at': 'desc'}], 'query': {'terms': {'host': names[:20]}}}))]

    def incidents_on_hosts(self, names):
        return [{k: h['_source'].get(k) for k in ('incident_id', 'title', 'status', 'severity', 'last_seen')} for h in hits(self.search.search('siem-incidents-*', {'size': 25, '_source': ['incident_id', 'title', 'status', 'severity', 'last_seen'], 'sort': [{'updated_at': 'desc'}], 'query': {'terms': {'hosts': names[:20]}}}))]

    def asset_part(self, asset_id, part, params):
        identifier(asset_id, 'asset ID')
        if part not in ('software', 'services', 'users', 'history', 'relationships'):
            raise NotFound('no such section')
        size, offset = self.paging(params)
        found = self.sockets.call('assets', part, asset=asset_id)
        if part == 'software':
            rows = found.get('installed', [])
        elif part == 'users':
            return found
        else:
            rows = found
        return {'rows': rows[offset:offset + size], 'total': {'value': len(rows), 'relation': 'eq'}, 'size': size, 'offset': offset}

    # Attack paths.
    def path_rows(self):
        def build():
            reply = self.search.search('siem-attack-paths-*', {'size': self.limits['overview_scan'], '_source': ['path_id', 'seed', 'title', 'severity', 'analyst_status', 'tier', 'conclusion', 'gaps', 'validation', 'validated_at', 'updated_ms', 'path_at', 'affected_assets', 'evidence_state'], 'sort': [{'path_at': 'desc'}]})
            return [h['_source'] for h in hits(reply)]
        return self.cached('paths', build)

    def paths(self, params):
        size, offset = self.paging(params)
        tier = params.get('tier')
        rows = self.sockets.call('paths', 'list', **({'tier': identifier(tier, 'tier')} if tier else {}), limit=500)
        return {'rows': rows[offset:offset + size], 'total': {'value': len(rows), 'relation': 'eq'}, 'size': size, 'offset': offset}

    def path(self, path_id):
        identifier(path_id, 'path ID')
        graph = self.sockets.call('paths', 'graph', path=path_id)
        return {'graph': graph, 'explain': section(lambda: self.sockets.call('paths', 'explain', path=path_id)), 'timeline': section(lambda: self.sockets.call('paths', 'timeline', path=path_id)), 'history': section(lambda: self.sockets.call('paths', 'history', path=path_id)), 'record': section(lambda: self.sockets.call('paths', 'show', path=path_id)), 'limit_note': 'A path is a reconstruction of evidence. It is not proof of compromise.'}

    def path_evidence(self, path_id, edge):
        identifier(path_id, 'path ID')
        return self.sockets.call('paths', 'evidence', path=path_id, **({'edge': identifier(edge, 'edge ID')} if edge else {}))

    # Threat intelligence.
    def intelligence_records(self):
        def build():
            reply = self.search.search('siem-enrichment-*', {'size': self.limits['overview_scan'], '_source': ['alert_id', 'status', 'enriched_at', 'summary', 'indicators'], 'sort': [{'enriched_at': 'desc'}], 'track_total_hits': True})
            return {'rows': [h['_source'] for h in hits(reply)], 'total': total(reply)}
        return self.cached('intelligence', build)

    def intelligence(self, params):
        found = self.intelligence_records()
        counts = dict.fromkeys(VERDICTS, 0)
        table = {}
        failures = 0
        for record in found['rows']:
            for item in record.get('indicators') or []:
                failed = bool(item.get('sources_failed'))
                failures += failed
                verdict = item.get('verdict') or 'unknown'
                counts[verdict] = counts.get(verdict, 0) + 1
                key = (item.get('type'), item.get('value'))
                row = table.setdefault(key, {'type': item.get('type'), 'value': item.get('value'), 'verdict': verdict, 'score': item.get('score'), 'independent_sources': item.get('independent_sources'), 'complete': item.get('complete'), 'external_checked': item.get('external_checked'), 'sources_answered': item.get('sources_answered') or [], 'sources_failed': item.get('sources_failed') or [], 'reasons': (item.get('reasons') or [])[:4], 'first_seen': record.get('enriched_at'), 'last_seen': record.get('enriched_at'), 'alert_ids': []})
                row['first_seen'] = min(row['first_seen'] or '', record.get('enriched_at') or '') or row['first_seen']
                row['last_seen'] = max(row['last_seen'] or '', record.get('enriched_at') or '')
                if record.get('alert_id') and len(row['alert_ids']) < 20:
                    row['alert_ids'].append(record['alert_id'])
        rows = sorted(table.values(), key=lambda r: (VERDICTS.index(r['verdict']) if r['verdict'] in VERDICTS else 9, r['last_seen'] or ''), reverse=False)
        verdict = params.get('verdict')
        if verdict:
            rows = [r for r in rows if r['verdict'] == verdict]
        size, offset = self.paging(params)
        return {'rows': rows[offset:offset + size], 'total': {'value': len(rows), 'relation': 'eq'}, 'size': size, 'offset': offset, 'by_verdict': counts, 'lookup_failures': failures, 'records_read': len(found['rows']), 'records_total': found['total'], 'note': 'No known threat means nothing was found in the sources that answered. It does not mean an indicator is safe. Nothing here triggers a lookup.'}

    # Health: Phase 16's view, unchanged.
    def health_overview(self):
        view, _ = self.health.view()
        try:
            return view.overview()
        finally:
            view.store.close()

    def health_call(self, name, *args):
        view, catalog = self.health.view()
        try:
            if name == 'components':
                return view.store.components()
            if name == 'explain':
                found = view.explain(args[0])
                if found is None:
                    raise NotFound('no such component')
                return found
            if name == 'metrics':
                return view.metrics()
            if name == 'series':
                if args[0] not in catalog.CATALOG:
                    raise BadInput('No such metric')
                return view.metrics(args[0], args[1])
            if name == 'catalog':
                return {'metrics': [catalog.describe(n) for n in catalog.CATALOG], 'not_available': catalog.UNAVAILABLE}
            if name == 'history':
                return view.history(None, view.now - 7 * 86400000)
            if name == 'failures':
                return view.failures(view.now - 7 * 86400000)
            if name == 'lag':
                return view.lag()
            if name == 'resources':
                return view.resources()
            raise BadInput('No such view')
        finally:
            view.store.close()

    # The overview.
    def security_summary(self, params):
        first, last = self.window(params)
        span = last - first
        interval = '1h' if span <= 2 * 86400000 else '6h' if span <= 8 * 86400000 else '1d'
        body = {'size': 0, 'track_total_hits': True, 'query': {'range': {'detected_at': {'gte': first, 'lte': last, 'format': 'epoch_millis'}}},
                'aggs': {'severity': {'terms': {'field': 'severity', 'size': 8}}, 'rules': {'terms': {'field': 'rule_name', 'size': 8}}, 'time': {'date_histogram': {'field': 'detected_at', 'fixed_interval': interval, 'min_doc_count': 0, 'extended_bounds': {'min': first, 'max': last}}}}}
        reply = self.search.search('siem-alerts-*', body)
        recent = self.search.search('siem-alerts-*', {'size': 8, '_source': ALERT_FIELDS, 'sort': [{'detected_at': 'desc'}], 'query': {'bool': {'filter': [{'terms': {'severity': ['critical', 'high']}}, {'range': {'detected_at': {'gte': first, 'lte': last, 'format': 'epoch_millis'}}}]}}})
        return {'from_ms': first, 'to_ms': last, 'interval': interval, 'alerts_total': total(reply)['value'], 'by_severity': {b['key']: b['doc_count'] for b in buckets(reply, 'severity')}, 'by_rule': [{'rule': b['key'], 'count': b['doc_count']} for b in buckets(reply, 'rules')], 'over_time': [{'at': b.get('key_as_string'), 'at_ms': b.get('key'), 'count': b['doc_count']} for b in buckets(reply, 'time')], 'recent_high': [self.alert_row(h) for h in hits(recent)]}

    def incident_summary(self):
        rows = self.incident_rows()
        real = [r for r in rows if r['record_class'] == 'verified']
        counts = {}
        for row in real:
            counts[row['status']] = counts.get(row['status'], 0) + 1
        return {'by_status': counts, 'total': len(real), 'excluded_no_stored_alerts': len(rows) - len(real), 'recent': real[:8], 'note': 'Incidents with no stored alert were made by test fixtures, and are left out of these counts.'}

    def asset_summary(self):
        rows = self.sockets.call('assets', 'list', limit=500)
        conflicts = self.sockets.call('assets', 'conflicts')
        changes = self.sockets.call('assets', 'changes', unreviewed=True, limit=200)
        # Retired records include test fixtures, some with a stored criticality. Only assets in service are summarised by it.
        serving = [r for r in rows if r.get('status') != 'retired']

        def tally(name, missing='not set', among=None):
            counts = {}
            for row in (rows if among is None else among):
                key = row.get(name) or missing
                counts[key] = counts.get(key, 0) + 1
            return counts
        return {'total': len(rows), 'in_service': len(serving), 'by_status': tally('status'), 'by_platform': tally('platform', among=serving), 'by_type': tally('asset_type', among=serving), 'by_criticality': tally('criticality', among=serving), 'open_conflicts': len(conflicts), 'unreviewed_changes': len(changes), 'unresolved_identities': sum(1 for r in serving if r.get('identity_confidence') in ('low', 'unresolved', None))}

    def intelligence_summary(self):
        found = self.intelligence({})
        health = None
        try:
            health = self.health_call('explain', 'enricher')
        except (Unavailable, NotFound):
            pass
        return {'by_verdict': found['by_verdict'], 'lookup_failures': found['lookup_failures'], 'records_read': found['records_read'], 'source_freshness': {'status': health['status'], 'evidence': health['evidence'][-1]['value'] if health.get('evidence') else None, 'reason': health['reason']} if health else None, 'note': found['note']}

    def path_summary(self):
        rows = self.path_rows()
        now = self.clock()
        tiers, expired, due, missing = {}, 0, 0, 0
        limit = self.config['evidence_recheck_hours'] * 3600000
        for row in rows:
            tiers[row.get('tier')] = tiers.get(row.get('tier'), 0) + 1
            if (row.get('validation') or {}).get('unavailable'):
                expired += 1
            stamp = row.get('validated_at')
            age = None
            if isinstance(stamp, str):
                try:
                    import calendar
                    age = now - calendar.timegm(time.strptime(stamp[:19], '%Y-%m-%dT%H:%M:%S')) * 1000
                except ValueError:
                    pass
            if age is None or age > limit:
                due += 1
            missing += 1 if row.get('gaps') else 0
        return {'total': len(rows), 'by_tier': tiers, 'with_expired_evidence': expired, 'needing_validation': due, 'with_missing_telemetry': missing, 'recent': [{k: r.get(k) for k in ('path_id', 'title', 'tier', 'path_at')} for r in rows[:6]], 'note': 'A path reconstructs evidence, and proves nothing about compromise. Tiers grade the evidence.'}

    def overview(self, params):
        return {'security': section(self.security_summary, params), 'incidents': section(self.incident_summary), 'health': section(self.health_overview), 'assets': section(self.asset_summary), 'intelligence': section(self.intelligence_summary), 'paths': section(self.path_summary), 'observed_ms': self.clock()}

    # Search across kinds. Each kind is an exact lookup, labelled with where it came from.
    def global_search(self, text):
        text = (text or '').strip()
        if not text or len(text) > 128 or any(ord(c) < 32 for c in text):
            raise BadInput('Enter an ID, host, address or indicator')
        out = {}
        out['alerts'] = section(lambda: [self.alert_row(h) for h in hits(self.search.search('siem-alerts-*', {'size': 10, '_source': ALERT_FIELDS, 'sort': [{'detected_at': 'desc'}], 'query': {'bool': {'should': [{'term': {'alert_id': text}}, {'term': {'rule_id': text}}, {'term': {'rule_name': text}}, {'term': {'host': text}}, {'term': {'source_ip': text}}], 'minimum_should_match': 1}}}))])
        out['incidents'] = section(lambda: [h['_source'] for h in hits(self.search.search('siem-incidents-*', {'size': 10, '_source': ['incident_id', 'title', 'status', 'severity'], 'sort': [{'updated_at': 'desc'}], 'query': {'bool': {'should': [{'term': {'incident_id': text}}, {'term': {'hosts': text}}, {'term': {'ips': text}}, {'term': {'alert_ids': text}}], 'minimum_should_match': 1}}}))])
        out['events'] = section(lambda: [self.event_row(h) for h in hits(self.search.search(self.event_indices(self.clock() - 7 * 86400000, self.clock(), None), {'size': 10, 'sort': [{'@timestamp': 'desc'}], 'query': {'bool': {'should': [{'term': {'event.id': text}}, {'term': {'source.ip': text}}, {'term': {'destination.ip': text}}], 'minimum_should_match': 1}}}))])
        out['assets'] = section(lambda: self.sockets.call('assets', 'search', query=text, limit=10))
        out['attack_paths'] = section(lambda: self.sockets.call('paths', 'search', query=text)[:10])
        out['indicators'] = section(lambda: [r for r in self.intelligence({'size': '100'})['rows'] if r['value'] == text][:10])
        return out
