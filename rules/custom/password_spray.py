"""One host sees failed logons for many different accounts. Sigma has no sliding distinct count."""
from siem_detector.alerts import get, parse_ms
from siem_detector.custom import CustomRule, Finding

ACCOUNTS = 4
WINDOW_MS = 600000


class PasswordSpray(CustomRule):
    id = 'c0a5f1d2-7e41-4c8b-8a10-1f2e3d4c5b02'
    title = 'Failed Logons Across Many Accounts'
    description = f'Failed logons for at least {ACCOUNTS} different accounts on one host within ten minutes.'
    level = 'high'
    tags = ('attack.credential-access', 'attack.t1110.003')
    lookback_seconds = 1800
    fields = ('winlog.event_data.TargetUserName', 'winlog.event_data.Status')

    def query(self):
        return {'bool': {'filter': [{'term': {'event.dataset': 'windows.security'}}, {'term': {'event.code': '4625'}}]}}

    def detect(self, events):
        hosts = {}
        for event in events:
            hosts.setdefault(get(event['_source'], 'host.name'), []).append(event)
        findings = []
        for host, items in hosts.items():
            i = 0
            while i < len(items):
                first = parse_ms(items[i]['_source']['@timestamp'])
                j, names = i, set()
                while j < len(items) and parse_ms(items[j]['_source']['@timestamp']) - first <= WINDOW_MS:
                    names.add(str(get(items[j]['_source'], 'user.name')).lower())
                    j += 1
                if len(names) >= ACCOUNTS:
                    findings.append(Finding(key=f"{host}|{items[i]['_id']}", events=items[i:j], facts={'accounts': len(names), 'failed_attempts': j - i}))
                    i = j
                else:
                    i += 1
        return findings
