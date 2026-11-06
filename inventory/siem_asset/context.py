"""Context for an investigation: from an asset, a name, an address, an alert or an incident to what is known about
the machines involved at that moment. Alerts and incidents are read and never changed. If OpenSearch cannot be
reached, what the inventory holds is still returned, and the gap is stated.
"""
import re

from . import changes, schema, views
from .schema import ADMIN, iso, ms
from .service import StoreDown

_DOC_ID = re.compile(r'^[0-9a-f]{32}$')
NEAR_MS = 24 * changes.HOUR
RECENT_USERS = 10
MAX_INCIDENTS = 20


class NotFound(ValueError):
    pass


class Context:
    def __init__(self, store, opensearch, watch):
        self.store = store
        self.opensearch = opensearch
        self.watch = watch

    def pick(self, value):
        """An asset id, a prefix of one, or an exact name or address. Anything else is not an asset."""
        text = str(value or '').strip()[:128]
        found = self.store.asset_by_prefix(text) if text.startswith('ast-') else None
        if found:
            return [found]
        host = schema.hostname(text)
        holders = self.store.holders('hostname', host) if host else set()
        if holders:
            return sorted(holders)
        address = schema.address(text)
        holders = self.store.holders_of_ip(address) if address else []
        if holders:
            return holders
        raise NotFound('no such asset')

    def one(self, value):
        found = self.pick(value)
        if len(found) > 1:
            raise NotFound(f'{len(found)} assets match, so use an asset id: ' + ', '.join(found))
        asset = self.store.asset(found[0])
        return self.store.asset(asset['merged_into']) if asset['merged_into'] else asset

    def view(self, asset, at_ms=None, basis='asset'):
        asset_id = asset['asset_id']
        store = self.store
        family = [asset_id, *store.merged_from(asset_id)]
        attributes = views.by_class(store, asset_id)
        recent = sorted(store.items(asset_id, 'observed_user'), key=lambda u: u['last_ms'], reverse=True)[:RECENT_USERS]
        history = store.changes(family, limit=500)
        important = [c for c in history if c['category'] != changes.ROUTINE]
        near = [views.change_row(c) for c in history if at_ms and abs(c['at_ms'] - at_ms) <= NEAR_MS]
        relations = store.relationships(asset_id)
        return {'asset_id': asset_id, 'hostname': asset['hostname'], 'status': views.status_of(store, asset), 'identity_confidence': asset['confidence'], 'matched_by': basis, 'last_seen': views.when(asset['last_ms']), 'at_time': views.when(at_ms), 'asset_type': asset['asset_type'], 'platform': asset['platform'],
                'confirmed': {'observed_facts': attributes[schema.OBSERVED], 'addresses': [views.lease_row(x, asset) for x in store.leases(asset_id)], 'interfaces': [views.item_row(i) for i in store.items(asset_id, 'interface')], 'security_tools': views.security_tools(store, asset_id, self.watch), 'exposure': views.exposure(store, asset_id), 'recently_observed_users': [views.item_row(u) for u in recent], 'services_of_note': [views.item_row(s) for s in store.items(asset_id, 'service') if s['key'] in self.watch]},
                'stated_by_administrator': attributes[ADMIN], 'inferred': {'attributes': attributes[schema.INFERRED], 'relationships': [views.rel_row(r) for r in relations if r['klass'] == schema.INFERRED]},
                'external_intelligence': attributes[schema.EXTERNAL], 'vulnerabilities': {'status': 'not_assessed'}, 'history': {'important': [views.change_row(c) for c in important[:25]], 'near_this_time': near[:50]},
                'relationships': {'peers': [views.rel_row(r) for r in relations if r['rel_type'] == 'communicates_with'][:25], 'users': [views.rel_row(r) for r in relations if r['rel_type'].endswith('authentication_on') or r['rel_type'] == 'authenticated_on'][:25], 'incidents': [r['dst_id'] for r in relations if r['rel_type'] == 'involved_in'][:MAX_INCIDENTS]}}

    def _matches(self, hosts, ips, at_ms):
        """Each machine named, or a statement that none could be named. A name with no record is reported, not guessed."""
        found, unknown = {}, []
        for name in hosts:
            host = schema.hostname(name)
            holders = self.store.holders('hostname', host) if host else set()
            if len(holders) == 1:
                found.setdefault(next(iter(holders)), 'host name')
            else:
                unknown.append({'kind': 'host', 'value': schema.clean(name, 120), 'why': 'unknown' if not holders else f'{len(holders)} assets hold this name'})
        for value in ips:
            address = schema.address(value)
            if address is None or not schema.routable(address):
                continue
            holders = self.store.holders_of_ip(address, at_ms, 3600000)
            if len(holders) == 1:
                found.setdefault(holders[0], 'address at that time')
            elif holders:
                unknown.append({'kind': 'ip', 'value': address, 'why': f'{len(holders)} assets held this address at that time'})
        return found, unknown

    def _one_doc(self, index, field, value):
        hits = self.opensearch.search(index, {'size': 1, 'query': {'term': {field: value}}})
        return hits[0]['_source'] if hits else None

    def for_incident(self, incident_id):
        if not _DOC_ID.fullmatch(str(incident_id)):
            raise NotFound('an incident id is 32 hexadecimal characters')
        rows = self.store.relationships(incident_id, 'involved_in')
        try:
            incident = self._one_doc('siem-incidents-*', 'incident_id', incident_id)
        except StoreDown as error:
            return {'incident_id': incident_id, 'live_data': f'unavailable: {error}', 'assets': [self.view(self.store.asset(r['src_id']), None, 'stored link') for r in rows], 'unknown': []}
        if incident is None:
            raise NotFound('no such incident')
        at_ms = ms(incident['last_seen'])
        found, unknown = self._matches(incident.get('hosts') or (), incident.get('ips') or (), at_ms)
        return {'incident_id': incident_id, 'title': schema.clean(incident.get('title'), 200), 'severity': incident.get('severity'), 'status': incident.get('status'), 'first_seen': incident.get('first_seen'), 'last_seen': incident.get('last_seen'), 'live_data': 'ok',
                'assets': [{**self.view(self.store.asset(a), at_ms, why), 'other_incidents': [r['dst_id'] for r in self.store.relationships(a, 'involved_in') if r['dst_id'] != incident_id][:MAX_INCIDENTS]} for a, why in found.items()], 'unknown': unknown, 'involves_critical_asset': any(self.store.attribute(a, 'criticality', ADMIN) in ('high', 'critical') for a in found)}

    def for_alert(self, alert_id):
        if not _DOC_ID.fullmatch(str(alert_id)):
            raise NotFound('an alert id is 32 hexadecimal characters')
        try:
            alert = self._one_doc('siem-alerts-*', 'alert_id', alert_id)
            if alert is None:
                raise NotFound('no such alert')
            intelligence = self.opensearch.search('siem-enrichment-*', {'size': 5, 'query': {'term': {'alert_id': alert_id}}})
        except StoreDown as error:
            return {'alert_id': alert_id, 'live_data': f'unavailable: {error}', 'assets': [], 'unknown': []}
        at_ms = ms(alert['timestamp'])
        found, unknown = self._matches([alert['host']] if alert.get('host') else [], [alert['source_ip']] if alert.get('source_ip') else [], at_ms)
        # Enrichment's own findings, read as they stand. Nothing is recomputed here.
        findings = [{'type': i.get('type'), 'value': i.get('value'), 'verdict': i.get('verdict'), 'score': i.get('score'), 'class': schema.EXTERNAL} for hit in intelligence for i in hit['_source'].get('indicators') or ()]
        return {'alert_id': alert_id, 'rule': schema.clean(alert.get('rule_name'), 200), 'severity': alert.get('severity'), 'timestamp': alert.get('timestamp'), 'live_data': 'ok', 'threat_intelligence': findings[:25], 'assets': [self.view(self.store.asset(a), at_ms, why) for a, why in found.items()], 'unknown': unknown}

    def at_time(self, value, text):
        """Who held this address at that moment."""
        address = schema.address(value)
        if address is None:
            raise NotFound('not an address')
        try:
            moment = ms(text)
        except (ValueError, TypeError):
            raise NotFound('not a time') from None
        return {'ip': address, 'at': iso(moment), 'holders': [views.summary(self.store, self.store.asset(a)) for a in self.store.holders_of_ip(address, moment, 3600000)]}
