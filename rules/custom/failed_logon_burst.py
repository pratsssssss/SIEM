"""Many failed logons for one account on one host, inside a sliding window."""
from siem_detector.alerts import get, parse_ms
from siem_detector.custom import CustomRule, Finding

THRESHOLD = 5
WINDOW_MS = 300000


def burst_findings(events, group_key, threshold, window_ms, prefix):
    """Sliding window over events sorted by time. A burst is keyed by its first event, so it is stable."""
    groups = {}
    for event in events:
        groups.setdefault(group_key(event), []).append(event)
    findings = []
    for key, items in groups.items():
        i = 0
        while i + threshold <= len(items):
            first = parse_ms(items[i]['_source']['@timestamp'])
            if parse_ms(items[i + threshold - 1]['_source']['@timestamp']) - first > window_ms:
                i += 1
                continue
            j = i
            while j < len(items) and parse_ms(items[j]['_source']['@timestamp']) - first <= window_ms:
                j += 1
            burst = items[i:j]
            findings.append(Finding(key=f"{prefix}|{key}|{items[i]['_id']}", events=burst, facts={'failed_attempts': len(burst)}))
            i = j
    return findings


class FailedLogonBurst(CustomRule):
    id = 'c0a5f1d2-7e41-4c8b-8a10-1f2e3d4c5b01'
    title = 'Multiple Failed Logons For One Account'
    description = f'At least {THRESHOLD} failed logons for one account on one host within five minutes.'
    level = 'medium'
    tags = ('attack.credential-access', 'attack.t1110.001')
    lookback_seconds = 900
    fields = ('winlog.event_data.TargetUserName', 'winlog.event_data.Status', 'winlog.event_data.SubStatus', 'winlog.event_data.LogonType')

    def query(self):
        return {'bool': {'filter': [{'term': {'event.dataset': 'windows.security'}}, {'term': {'event.code': '4625'}}]}}

    def detect(self, events):
        return burst_findings(events, lambda e: (get(e['_source'], 'host.name'), str(get(e['_source'], 'user.name')).lower()), THRESHOLD, WINDOW_MS, 'logon')
