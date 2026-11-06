"""Many failed authentications for one account on the Linux host, whichever program asked."""
from siem_detector.alerts import get, parse_ms
from siem_detector.custom import CustomRule, Finding

THRESHOLD = 5
WINDOW_MS = 300000
ACTIONS = ('pam-auth-failed', 'ssh-login-failed', 'su-failed')


class LinuxAuthBurst(CustomRule):
    id = 'd3b07a10-5c1e-4f6a-9b2c-0e1f2a3b4c08'
    title = 'Multiple Failed Authentications On The Linux Host'
    description = f'At least {THRESHOLD} failed authentications for one account on the Linux host within five minutes.'
    level = 'medium'
    tags = ('attack.credential-access', 'attack.t1110.001')
    lookback_seconds = 900
    fields = ('event.action', 'user.target.name')

    def query(self):
        return {'bool': {'filter': [{'term': {'event.dataset': 'linux.auth'}}, {'terms': {'event.action': list(ACTIONS)}}]}}

    def detect(self, events):
        groups = {}
        for event in events:
            data = event['_source']
            account = get(data, 'user.target.name') or get(data, 'user.name')
            groups.setdefault((get(data, 'host.name'), str(account).lower()), []).append(event)
        findings = []
        for key, items in groups.items():
            i = 0
            while i + THRESHOLD <= len(items):
                first = parse_ms(items[i]['_source']['@timestamp'])
                if parse_ms(items[i + THRESHOLD - 1]['_source']['@timestamp']) - first > WINDOW_MS:
                    i += 1
                    continue
                j = i
                while j < len(items) and parse_ms(items[j]['_source']['@timestamp']) - first <= WINDOW_MS:
                    j += 1
                findings.append(Finding(key=f"linux-auth|{key}|{items[i]['_id']}", events=items[i:j], facts={'failed_attempts': j - i}))
                i = j
        return findings
