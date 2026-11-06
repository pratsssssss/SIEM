"""Decodes PowerShell -EncodedCommand and inspects the content, which Sigma cannot do."""
import base64
import re

from siem_detector.alerts import get
from siem_detector.custom import CustomRule, Finding

FLAG = re.compile(r'\s-(?:e|ec|enc|encodedcommand)\s+"?([A-Za-z0-9+/=]{16,})', re.IGNORECASE)
RISKY = (
    ('network_fetch', re.compile(r'downloadstring|downloaddata|net\.webclient|invoke-webrequest|start-bitstransfer', re.IGNORECASE)),
    ('evaluates_code', re.compile(r'\biex\b|invoke-expression', re.IGNORECASE)),
    ('hidden_window', re.compile(r'-w(?:indowstyle)?\s+hidden', re.IGNORECASE)),
    ('decodes_more', re.compile(r'frombase64string', re.IGNORECASE)),
)


def decoded(line):
    """The UTF-16 text PowerShell would run, or None if the argument is not valid Base64 text."""
    found = FLAG.search(line or '')
    if not found:
        return None
    try:
        return base64.b64decode(found.group(1), validate=True).decode('utf-16-le')
    except ValueError:
        return None


class EncodedCommandContent(CustomRule):
    id = 'c0a5f1d2-7e41-4c8b-8a10-1f2e3d4c5b04'
    title = 'Encoded PowerShell Holds Risky Content'
    description = 'The decoded text of a PowerShell encoded command fetches from the network, evaluates code, or decodes a further layer.'
    level = 'high'
    tags = ('attack.stealth', 'attack.t1027', 'attack.execution', 'attack.t1059.001')
    lookback_seconds = 300

    def query(self):
        return {'bool': {'filter': [
            {'term': {'event.dataset': 'windows.sysmon'}}, {'term': {'event.code': '1'}},
            {'wildcard': {'process.executable': {'value': '*sh*.exe', 'case_insensitive': True}}},
            {'wildcard': {'process.command_line.keyword': {'value': '* -e*', 'case_insensitive': True}}},
        ]}}

    def detect(self, events):
        findings = []
        for event in events:
            text = decoded(get(event['_source'], 'process.command_line'))
            if text is None:
                continue
            hits = [name for name, pattern in RISKY if pattern.search(text)]
            if hits:
                findings.append(Finding(key=event['_id'], events=[event], facts={name: True for name in hits}))
        return findings
