"""Checks an alert before anything uses it. A bad alert is quarantined with its reason, never dropped."""
import json
import re
from datetime import datetime, timezone

SEVERITIES = ('informational', 'low', 'medium', 'high', 'critical')
_ID = re.compile(r'^[0-9a-f]{32}$')
REQUIRED = {'alert_id': str, 'rule_id': str, 'rule_name': str, 'severity': str, 'timestamp': str, 'detected_at': str, 'event_count': int,
            'source_event_ids': list, 'raw_event_refs': list, 'mitre': dict, 'evidence': dict}
# Allowlisted on Kafka by Phase 9. A replay from OpenSearch is cut down to the same fields.
SAFE_FIELDS = frozenset({
    'event.code', 'event.dataset', 'event.action', 'event.category', 'event.outcome', 'host.name', 'user.name', 'user.domain', 'user.id', 'group.name',
    'process.name', 'process.parent.name', 'process.executable', 'process.parent.executable', 'process.pid', 'process.pe.original_file_name',
    'source.ip', 'source.port', 'destination.ip', 'destination.port', 'network.transport', 'network.direction', 'dns.question.name',
    'service.name', 'threat.indicator.name', 'threat.indicator.severity', 'registry.key',
})


class Invalid(ValueError):
    pass


def ms(text):
    """Epoch milliseconds from an ISO timestamp."""
    moment = datetime.fromisoformat(str(text).replace('Z', '+00:00'))
    return int(moment.replace(tzinfo=moment.tzinfo or timezone.utc).timestamp() * 1000)


def iso(value):
    return datetime.fromtimestamp(value / 1000, timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'


def parse(raw):
    """Decoded, validated alert from one Kafka message, or Invalid with the reason."""
    try:
        alert = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as error:
        raise Invalid('not JSON') from error
    if not isinstance(alert, dict):
        raise Invalid('not an object')
    return check(alert)


def check(alert):
    for name, kind in REQUIRED.items():
        if not isinstance(alert.get(name), kind) or (kind is int and isinstance(alert.get(name), bool)):
            raise Invalid(f'{name}: missing or wrong type')
    if alert.get('schema_version') != 1:
        raise Invalid('unknown schema version')
    if not _ID.fullmatch(alert['alert_id']):
        raise Invalid('alert_id is malformed')
    if alert['severity'] not in SEVERITIES:
        raise Invalid('unknown severity')
    if alert['event_count'] < 1:
        raise Invalid('event_count is below 1')
    for name in ('timestamp', 'detected_at'):
        try:
            ms(alert[name])
        except (ValueError, TypeError) as error:
            raise Invalid(f'{name}: not a timestamp') from error
    if not isinstance(alert['evidence'].get('matched_fields', {}), dict):
        raise Invalid('evidence is malformed')
    return alert


def safe(alert):
    """The Kafka-safe form of an alert read from OpenSearch, so that a replay holds no more than Kafka did."""
    copy = dict(alert)
    evidence = dict(alert.get('evidence') or {})
    evidence['matched_fields'] = {k: v for k, v in (evidence.get('matched_fields') or {}).items() if k in SAFE_FIELDS}
    evidence['facts'] = {k: v for k, v in (evidence.get('facts') or {}).items() if isinstance(v, (int, float, bool))}
    copy['evidence'] = evidence
    return copy


def times(alert, skew_ms):
    """(first, last, note). Event time is used unless it is impossible, and then detection time is, with a note."""
    first, detected = ms(alert['timestamp']), ms(alert['detected_at'])
    seen = (alert.get('evidence') or {}).get('last_seen')
    last = first
    if seen:
        try:
            last = ms(seen)
        except (ValueError, TypeError):
            pass
    if first > detected + skew_ms or last > detected + skew_ms:
        return detected, detected, 'event time is later than detection, so the clock is suspect and detection time is used'
    return first, max(first, last), ''
