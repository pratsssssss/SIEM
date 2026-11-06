"""Failed logons followed by a success for the same account. Order matters, which Sigma rules cannot state."""
from siem_detector.alerts import get, parse_ms
from siem_detector.custom import CustomRule, Finding

FAILURES = 3
WINDOW_MS = 600000
# Interactive, network, unlock and remote desktop logons. Service logons are not a password guess.
LOGON_TYPES = {'2', '3', '7', '10'}


class LogonAfterFailures(CustomRule):
    id = 'c0a5f1d2-7e41-4c8b-8a10-1f2e3d4c5b03'
    title = 'Successful Logon After Repeated Failures'
    description = f'At least {FAILURES} failed logons, then a success, for one account on one host within ten minutes.'
    level = 'high'
    tags = ('attack.credential-access', 'attack.t1110', 'attack.initial-access', 'attack.t1078')
    lookback_seconds = 1800
    fields = ('winlog.event_data.LogonType', 'winlog.event_data.TargetUserName')

    def query(self):
        return {'bool': {'filter': [{'term': {'event.dataset': 'windows.security'}}, {'terms': {'event.code': ['4624', '4625']}}]}}

    def detect(self, events):
        accounts = {}
        for event in events:
            accounts.setdefault((get(event['_source'], 'host.name'), str(get(event['_source'], 'user.name')).lower()), []).append(event)
        findings = []
        for key, items in accounts.items():
            failures = []
            for event in items:
                when = parse_ms(event['_source']['@timestamp'])
                failures = [f for f in failures if when - parse_ms(f['_source']['@timestamp']) <= WINDOW_MS]
                if get(event['_source'], 'event.code') == '4625':
                    failures.append(event)
                elif len(failures) >= FAILURES and str(get(event['_source'], 'winlog.event_data.LogonType')) in LOGON_TYPES:
                    findings.append(Finding(key=f"{key}|{event['_id']}", events=[*failures, event], facts={'failed_attempts': len(failures)}))
                    failures = []
        return findings
