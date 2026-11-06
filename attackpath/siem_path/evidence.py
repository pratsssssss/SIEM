"""Reads evidence, and turns events into platform-neutral facts. Every query is a fixed shape with bounded size,
and values go in as JSON data. The account's field level security decides what can be returned at all.
"""
from dataclasses import dataclass, field

from . import model
from .model import Evidence, clean, linux_identity, ms, windows_identity

EVENT_FIELDS = ['@timestamp', 'event.id', 'event.dataset', 'event.code', 'event.action', 'event.outcome', 'event.ingested', 'host.name', 'host.id', 'user.name', 'user.domain', 'user.id', 'user.effective.name', 'user.target.name', 'user.target.domain', 'group.name', 'service.name',
                'process.name', 'process.parent.name', 'process.entity_id', 'process.parent.entity_id', 'source.ip', 'destination.ip', 'destination.port', 'winlog.logon.type', 'journald.exe_verified', 'labels.attribution', 'package.name']
ALERT_FIELDS = ['alert_id', 'rule_id', 'rule_name', 'severity', 'confidence', 'timestamp', 'detected_at', 'host', 'user', 'source_ip', 'event_count', 'raw_event_refs', 'source_event_ids', 'mitre.tactics', 'mitre.techniques']
INCIDENT_FIELDS = ['incident_id', 'title', 'severity', 'status', 'revision', 'hosts', 'users', 'ips', 'first_seen', 'last_seen', 'updated_at', 'alert_ids', 'rules.id', 'rules.join', 'uncertain']
EVENT_INDEX = 'siem-windows-*,siem-linux-*'

# What an event is, whichever platform wrote it. Patterns read this and nothing platform-specific.
WINDOWS_KINDS = {('windows.security', '4624'): 'auth_success', ('windows.security', '4625'): 'auth_failure', ('windows.security', '4720'): 'account_created', ('windows.security', '4726'): 'account_deleted', ('windows.security', '4732'): 'group_added', ('windows.security', '4728'): 'group_added', ('windows.security', '4756'): 'group_added',
                 ('windows.security', '4697'): 'service_installed', ('windows.system', '7045'): 'service_installed', ('windows.security', '4698'): 'task_created', ('windows.taskscheduler', '106'): 'task_created', ('windows.security', '4719'): 'audit_policy_changed', ('windows.sysmon', '1'): 'process_start', ('windows.sysmon', '3'): 'network', ('windows.defender', '5001'): 'security_control_changed'}
LINUX_KINDS = {'pam-auth-failed': 'auth_failure', 'ssh-login-failed': 'auth_failure', 'su-failed': 'auth_failure', 'sudo-auth-failed': 'auth_failure', 'sudo-not-permitted': 'privilege_refused', 'ssh-login': 'auth_success', 'su-session': 'privilege_change', 'sudo-command': 'privilege_use', 'user-created': 'account_created', 'user-deleted': 'account_deleted',
               'group-member-added': 'group_added', 'crontab-replaced': 'cron_changed', 'crontab-edited': 'cron_changed', 'service-failed': 'service_failed', 'package-installed': 'package_installed'}
CONTEXT_WINDOWS = sorted(c for _, c in WINDOWS_KINDS if c not in ('1', '3'))


class StoreDown(Exception):
    pass


def dig(source, path):
    node = source
    for part in path.split('.'):
        node = node.get(part) if isinstance(node, dict) else None
    return node


@dataclass
class Fact:
    kind: str
    at_ms: int
    event_id: str
    index: str
    platform: str
    host: str
    dataset: str
    action: str
    ingest: str = None
    actor: object = None
    target: object = None
    source_ip: str = None
    dest_ip: str = None
    dest_port: int = None
    service: str = None
    group: str = None
    package: str = None
    process: dict = field(default_factory=dict)
    logon_type: str = None
    attribution: str = 'verified'


def _ip(value):
    text = clean(value, 64)
    return text if text and text != '-' else None


def to_fact(index, event_id, event):
    """A fact from one stored event, or None. An entry journald does not attribute is no fact about anyone."""
    dataset, code, action = clean(dig(event, 'event.dataset'), 40), clean(dig(event, 'event.code'), 10), clean(dig(event, 'event.action'), 60)
    host = clean(dig(event, 'host.name'), 120).lower()
    try:
        at = ms(event['@timestamp'])
    except (KeyError, ValueError, TypeError):
        return None
    if dataset.startswith('windows.'):
        kind = WINDOWS_KINDS.get((dataset, code))
        if not kind:
            return None
        platform = 'windows'
        actor = windows_identity(dig(event, 'user.name'), dig(event, 'user.domain'), dig(event, 'user.id'))
        target = windows_identity(dig(event, 'user.target.name'), dig(event, 'user.target.domain'))
        attribution = 'verified'
    else:
        kind = LINUX_KINDS.get(action)
        if not kind or dig(event, 'labels.attribution') == 'unverified' or action == 'unverified-log-entry':
            return None
        platform = 'linux'
        actor = linux_identity(dig(event, 'user.name'), host)
        target = linux_identity(dig(event, 'user.target.name') or dig(event, 'user.effective.name'), host)
        attribution = 'process-name' if dig(event, 'labels.attribution') == 'process-name' else 'verified'
    return Fact(kind, at, clean(event_id, 128), clean(index, 64), platform, host, dataset, action, clean(dig(event, 'event.ingested'), 40) or None, actor, target, _ip(dig(event, 'source.ip')), _ip(dig(event, 'destination.ip')), dig(event, 'destination.port') if isinstance(dig(event, 'destination.port'), int) else None,
                clean(dig(event, 'service.name'), 120) or None, clean(dig(event, 'group.name'), 120) or None, clean(dig(event, 'package.name'), 120) or None,
                {'id': clean(dig(event, 'process.entity_id'), 64), 'parent': clean(dig(event, 'process.parent.entity_id'), 64), 'name': clean(dig(event, 'process.name'), 120), 'parent_name': clean(dig(event, 'process.parent.name'), 120)}, clean(dig(event, 'winlog.logon.type'), 4) or None, attribution)


def fact_evidence(fact, asset_id=None):
    """Named fields only. Command lines, message text and raw events are never copied here."""
    fields = {k: v for k, v in (('dataset', fact.dataset), ('action', fact.action), ('kind', fact.kind), ('logon_type', fact.logon_type), ('source_ip', fact.source_ip), ('destination_ip', fact.dest_ip), ('service', fact.service), ('group', fact.group), ('package', fact.package), ('attribution', fact.attribution)) if v}
    return Evidence('event', fact.event_id, fact.index, model.iso(fact.at_ms), fact.ingest, fact.host, asset_id, f'{fact.dataset}@{fact.host}', fields, f'telemetry:{fact.dataset}')


class Collector:
    def __init__(self, search, limits=None):
        limits = limits or {}
        self.search = search
        self.max_alerts = limits.get('max_alerts', 50)
        self.max_events = limits.get('max_events', 200)
        self.context_events = limits.get('context_events', 200)
        self.window_ms = limits.get('window_minutes', 240) * 60000

    def incident(self, incident_id):
        hits = self.search('siem-incidents-*', {'size': 1, '_source': INCIDENT_FIELDS, 'query': {'term': {'incident_id': incident_id}}})
        return hits[0]['_source'] if hits else None

    def alerts(self, ids):
        chosen = [i for i in ids if model.valid_id(i)][:self.max_alerts]
        if not chosen:
            return []
        return [h['_source'] for h in self.search('siem-alerts-*', {'size': len(chosen), '_source': ALERT_FIELDS, 'query': {'terms': {'alert_id': chosen}}})]

    def events(self, refs):
        """Stored events for these references: (found, references no longer there or refused)."""
        by_index, refused = {}, []
        for text in refs:
            parsed = model.event_ref(text)
            if parsed:
                by_index.setdefault(parsed[0], []).append(parsed[1])
            else:
                refused.append(clean(text, 120))
        found = {}
        budget = self.max_events
        for index, ids in sorted(by_index.items()):
            ids = ids[:budget]
            budget -= len(ids)
            if not ids:
                continue
            for hit in self.search(index, {'size': len(ids), '_source': EVENT_FIELDS, 'query': {'ids': {'values': ids}}}):
                found[(index, hit['_id'])] = hit['_source']
        missing = [f'{i}/{e}' for i, ids in by_index.items() for e in ids if (i, e) not in found]
        return found, missing + refused

    def context(self, hosts, start_ms, end_ms):
        """Security-relevant events on these hosts around the seed, for facts the alerts did not cite."""
        if not hosts:
            return []
        query = {'bool': {'filter': [{'terms': {'host.name': sorted(hosts)[:10]}}, {'range': {'@timestamp': {'gte': start_ms - self.window_ms, 'lte': end_ms + self.window_ms, 'format': 'epoch_millis'}}},
                                     {'bool': {'should': [{'terms': {'event.code': CONTEXT_WINDOWS}}, {'terms': {'event.action': sorted(LINUX_KINDS)}}], 'minimum_should_match': 1}}]}}
        return self.search(EVENT_INDEX, {'size': self.context_events, '_source': EVENT_FIELDS, 'sort': [{'@timestamp': 'asc'}], 'query': query})

    def intelligence(self, alert_ids):
        chosen = [i for i in alert_ids if model.valid_id(i)][:self.max_alerts]
        if not chosen:
            return []
        hits = self.search('siem-enrichment-*', {'size': len(chosen), '_source': ['alert_id', 'status', 'indicators.type', 'indicators.value', 'indicators.verdict', 'indicators.score'], 'query': {'bool': {'filter': [{'terms': {'alert_id': chosen}}, {'term': {'doc_type': 'alert'}}]}}})
        return [(h['_id'], h['_index'], h['_source']) for h in hits]

    def check(self, kind, index, ref_id):
        """The stored document behind one reference, for validation, or None."""
        if kind == 'event' and model.event_ref(f'{index}/{ref_id}'):
            hits = self.search(index, {'size': 1, '_source': EVENT_FIELDS, 'query': {'ids': {'values': [ref_id]}}})
            return hits[0]['_source'] if hits else None
        if kind == 'alert' and model.valid_id(ref_id):
            hits = self.search('siem-alerts-*', {'size': 1, '_source': ['alert_id'], 'query': {'term': {'alert_id': ref_id}}})
            return hits[0]['_source'] if hits else None
        return None
