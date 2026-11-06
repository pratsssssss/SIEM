"""Regular outbound connections from one process to one address. Timing is beyond a Sigma rule."""
from statistics import mean, pstdev

from siem_detector.alerts import get, parse_ms
from siem_detector.custom import CustomRule, Finding

MIN_CONNECTIONS = 6
MAX_JITTER = 0.1
MIN_GAP_MS = 10000
PRIVATE = ('10.', '127.', '192.168.', '169.254.', '::1', 'fe80:')


def is_private(address):
    if address.startswith('172.'):
        parts = address.split('.')
        return len(parts) > 1 and parts[1].isdigit() and 16 <= int(parts[1]) <= 31
    return address.startswith(PRIVATE)


class NetworkBeacon(CustomRule):
    id = 'c0a5f1d2-7e41-4c8b-8a10-1f2e3d4c5b05'
    title = 'Regular Outbound Connections, Possible Beacon'
    description = f'One process connected to one public address at least {MIN_CONNECTIONS} times, at nearly equal intervals.'
    level = 'medium'
    tags = ('attack.command-and-control', 'attack.t1071', 'attack.t1029')
    lookback_seconds = 7200
    fields = ('destination.port',)

    def query(self):
        return {'bool': {'filter': [{'term': {'event.dataset': 'windows.sysmon'}}, {'term': {'event.code': '3'}}, {'term': {'network.direction': 'egress'}}]}}

    def detect(self, events):
        flows = {}
        for event in events:
            source = event['_source']
            address = str(get(source, 'destination.ip'))
            if is_private(address):
                continue
            flows.setdefault((get(source, 'host.name'), get(source, 'process.executable'), address, get(source, 'destination.port')), []).append(event)
        findings = []
        for key, items in flows.items():
            if len(items) < MIN_CONNECTIONS:
                continue
            times = [parse_ms(e['_source']['@timestamp']) for e in items]
            gaps = [b - a for a, b in zip(times, times[1:])]
            average = mean(gaps)
            if average >= MIN_GAP_MS and pstdev(gaps) / average <= MAX_JITTER:
                findings.append(Finding(key=f"{key}|{items[0]['_id']}", events=items, facts={'connections': len(items), 'mean_gap_seconds': round(average / 1000, 1)}))
        return findings
