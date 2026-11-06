"""The alert contract: building, validating and making an alert safe for Kafka."""
import hashlib
import json
import re
from datetime import datetime, timezone

from . import ecs

SCHEMA_VERSION = 1
SEVERITIES = ('informational', 'low', 'medium', 'high', 'critical')
CONFIDENCES = ('low', 'medium', 'high')
MAX_REFS = 50
MAX_VALUES = 5
MAX_TEXT = 2000
ALERT_ID = re.compile(r'^[0-9a-f]{32}$')
_TACTICS = {
    'reconnaissance', 'resource_development', 'initial_access', 'execution', 'persistence', 'privilege_escalation',
    'defense_evasion', 'stealth', 'defense_impairment', 'credential_access', 'discovery', 'lateral_movement', 'collection', 'command_and_control',
    'exfiltration', 'impact',
}
REQUIRED = {
    'schema_version': int, 'alert_id': str, 'rule_id': str, 'rule_name': str, 'detection_type': str, 'severity': str,
    'confidence': str, 'timestamp': str, 'detected_at': str, 'description': str, 'host': (str, type(None)),
    'user': (str, type(None)), 'source_ip': (str, type(None)), 'event_count': int, 'source_event_ids': list,
    'raw_event_refs': list, 'mitre': dict, 'evidence': dict, 'evidence_ref': str,
}


def make_id(*parts) -> str:
    """Deterministic, so that the same detection always gets the same ID, on any run."""
    return hashlib.sha256('|'.join(str(p) for p in parts).encode()).hexdigest()[:32]


def iso(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'


def parse_ms(text: str) -> int:
    return int(datetime.fromisoformat(text.replace('Z', '+00:00')).timestamp() * 1000)


def mitre(tags):
    tactics, techniques = [], []
    for tag in tags:
        name = str(tag).lower()
        if not name.startswith('attack.'):
            continue
        name = name[len('attack.'):].replace('-', '_')
        if re.fullmatch(r't\d{4}(\.\d{3})?', name):
            techniques.append(name.upper())
        elif name in _TACTICS:
            tactics.append(name)
    return {'tactics': sorted(set(tactics)), 'techniques': sorted(set(techniques))}


def get(doc, path):
    if path in doc:
        return doc[path]
    value = doc
    for part in path.split('.'):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def _cap(value):
    return value[:MAX_TEXT] + f'...[{len(value)} chars]' if isinstance(value, str) and len(value) > MAX_TEXT else value


def _collect(hits, names):
    """Distinct values per field, from the alert's events."""
    found = {}
    for name in names:
        values = []
        for hit in hits:
            value = get(hit['_source'], name.removesuffix('.keyword'))
            if value in (None, '', []) or isinstance(value, (dict, list)):
                continue
            value = _cap(value)
            if value not in values:
                values.append(value)
            if len(values) == MAX_VALUES:
                break
        if values:
            found[name.removesuffix('.keyword')] = values
    return found


def _first(hits, name):
    for hit in hits:
        value = get(hit['_source'], name)
        if value:
            return str(value)
    return None


def _refs(hits):
    """All references up to the cap, then the first and last with the total in event_count."""
    if len(hits) <= MAX_REFS:
        return hits
    return hits[:MAX_REFS - 1] + hits[-1:]


def build(rule, hits, alert_id, detected_ms, facts=None, severity=None):
    """Makes the full alert. Its evidence can hold restricted text, so it stays in OpenSearch."""
    hits = sorted(hits, key=lambda h: h['_source'].get('@timestamp', ''))
    times = [h['_source']['@timestamp'] for h in hits if h['_source'].get('@timestamp')]
    kept = _refs(hits)
    names = list(dict.fromkeys([*rule.fields, *ecs.CONTEXT_FIELDS]))
    first = parse_ms(times[0]) if times else detected_ms
    return {
        'schema_version': SCHEMA_VERSION,
        'alert_id': alert_id,
        'rule_id': rule.id,
        'rule_name': rule.title,
        'detection_type': rule.kind,
        'severity': severity or rule.level,
        'confidence': rule.confidence,
        'timestamp': iso(first),
        'detected_at': iso(detected_ms),
        'description': rule.description,
        'host': _first(hits, 'host.name'),
        'user': _first(hits, 'user.name'),
        'source_ip': _first(hits, 'source.ip'),
        'event_count': len(hits),
        'source_event_ids': [h['_id'] for h in kept],
        'raw_event_refs': [f"{h['_index']}/{h['_id']}" for h in kept],
        'mitre': mitre(rule.tags),
        'evidence': {
            'matched_fields': _collect(hits, names),
            'rule_fields': [n.removesuffix('.keyword') for n in rule.fields],
            'first_seen': times[0] if times else None,
            'last_seen': times[-1] if times else None,
            'facts': facts or {},
        },
        'evidence_ref': f"{alert_index(first)}/{alert_id}",
    }


def alert_index(ms: int) -> str:
    return 'siem-alerts-' + datetime.fromtimestamp(ms / 1000, timezone.utc).strftime('%Y.%m')


def _withheld(value):
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
    return {'withheld': True, 'sha256': hashlib.sha256(text.encode()).hexdigest(), 'length': len(text)}


def kafka_safe(alert):
    """The Kafka form. Fields not on the allowlist become digests: Kafka has no authentication (D22)."""
    safe = json.loads(json.dumps(alert))
    evidence = safe['evidence']
    evidence['matched_fields'] = {
        name: values if name in ecs.KAFKA_SAFE_FIELDS else [_withheld(v) for v in values]
        for name, values in evidence['matched_fields'].items()
    }
    evidence['facts'] = {k: v if isinstance(v, (int, float, bool)) or v is None else _withheld(v) for k, v in evidence['facts'].items()}
    return safe


def validate(alert):
    """Returns a list of problems. An alert with any problem is never published."""
    problems = [f'{name}: missing or wrong type' for name, kind in REQUIRED.items() if not isinstance(alert.get(name), kind) or (kind is int and isinstance(alert.get(name), bool))]
    if problems:
        return problems
    if not ALERT_ID.fullmatch(alert['alert_id']):
        problems.append('alert_id: not 32 hexadecimal characters')
    if alert['severity'] not in SEVERITIES:
        problems.append('severity: unknown')
    if alert['confidence'] not in CONFIDENCES:
        problems.append('confidence: unknown')
    if alert['detection_type'] not in ('sigma', 'custom'):
        problems.append('detection_type: unknown')
    if alert['schema_version'] != SCHEMA_VERSION:
        problems.append('schema_version: unknown')
    if alert['event_count'] < 1:
        problems.append('event_count: below 1')
    if not alert['source_event_ids'] or len(alert['source_event_ids']) != len(alert['raw_event_refs']):
        problems.append('source_event_ids: empty, or not paired with raw_event_refs')
    for name in ('timestamp', 'detected_at'):
        try:
            parse_ms(alert[name])
        except ValueError:
            problems.append(f'{name}: not a timestamp')
    if set(alert['mitre']) != {'tactics', 'techniques'}:
        problems.append('mitre: needs tactics and techniques')
    if not isinstance(alert['evidence'].get('matched_fields'), dict):
        problems.append('evidence: no matched_fields')
    return problems
