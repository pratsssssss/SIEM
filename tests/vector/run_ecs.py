"""Tests the real ECS normalization transform with fake events. No service and no real events.

Covers each Windows source, missing fields, malformed values and unexpected event IDs.

Usage: python tests/vector/run_ecs.py <vector>
"""
import json
import pathlib
import subprocess
import sys
import tempfile

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
AGG = yaml.safe_load((ROOT / 'config/wsl/vector/vector-aggregator.yaml').read_text(encoding='utf8'))
SYSMON = 'Microsoft-Windows-Sysmon/Operational'
POWERSHELL = 'Microsoft-Windows-PowerShell/Operational'
failures = []


def check(name, ok, detail=''):
    print(('PASS ' if ok else 'FAIL ') + name + (f' ({detail})' if detail != '' else ''))
    if not ok:
        failures.append(name)


def event(channel, event_id, record, data, **extra):
    return {'channel': channel, 'event_id': event_id, 'record_id': record, 'computer': 'HOST.lab', 'timestamp': '2026-10-31T01:02:03.456Z',
            'event_uid': f'{record:064x}', 'provider_name': 'Provider', 'level': 'Information', 'task_name': 'Task', 'opcode_name': 'Info',
            'kafka': {'topic': 'siem-raw-logs', 'partition': 0, 'offset': record}, 'labels': {'protection': 'd22-v1'}, 'event_data': data, **extra}


def get(doc, path):
    value = doc
    for part in path.split('.'):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


CASES = {
    'sysmon process': (event(SYSMON, 1, 1, {'ProcessGuid': '{a}', 'ProcessId': '4242', 'Image': 'C:\\Windows\\System32\\cmd.exe', 'CommandLine': 'cmd /c whoami', 'CurrentDirectory': 'C:\\t\\', 'User': 'HOST\\bob',
                                            'ParentProcessGuid': '{b}', 'ParentProcessId': '100', 'ParentImage': 'C:\\Windows\\explorer.exe', 'ParentCommandLine': 'explorer.exe', 'Hashes': 'SHA256=ABC,MD5=DEF', 'OriginalFileName': 'Cmd.Exe', 'LogonId': '0x3e7'}),
                       {'event.dataset': 'windows.sysmon', 'event.code': '1', 'event.category': ['process'], 'event.type': ['start'], 'process.pid': 4242, 'process.name': 'cmd.exe', 'process.executable': 'C:\\Windows\\System32\\cmd.exe',
                        'process.command_line': 'cmd /c whoami', 'process.parent.pid': 100, 'process.parent.name': 'explorer.exe', 'process.parent.command_line': 'explorer.exe', 'user.name': 'bob', 'user.domain': 'HOST', 'process.hash.sha256': 'ABC', 'process.hash.md5': 'DEF'}),
    'sysmon network': (event(SYSMON, 3, 2, {'ProcessGuid': '{a}', 'ProcessId': '10', 'Image': 'C:\\a.exe', 'User': 'NT AUTHORITY\\SYSTEM', 'Protocol': 'tcp', 'Initiated': 'true', 'SourceIp': '10.0.0.5', 'SourcePort': '50000', 'DestinationIp': '2001:db8::1', 'DestinationPort': '443', 'DestinationHostname': 'x.example'}),
                       {'event.category': ['network'], 'event.type': ['connection'], 'source.ip': '10.0.0.5', 'source.port': 50000, 'destination.ip': '2001:db8::1', 'destination.port': 443, 'network.transport': 'tcp', 'network.direction': 'egress', 'destination.domain': 'x.example', 'user.domain': 'NT AUTHORITY'}),
    'sysmon dns': (event(SYSMON, 22, 3, {'ProcessId': '1', 'Image': 'C:\\a.exe', 'QueryName': 'x.example', 'QueryResults': '1.2.3.4;'}), {'dns.question.name': 'x.example', 'event.category': ['network'], 'event.action': 'dns-query'}),
    'sysmon file': (event(SYSMON, 11, 4, {'ProcessId': '1', 'Image': 'C:\\a.exe', 'TargetFilename': 'C:\\t\\b.txt'}), {'file.path': 'C:\\t\\b.txt', 'file.name': 'b.txt', 'event.category': ['file']}),
    'sysmon registry': (event(SYSMON, 13, 5, {'ProcessId': '1', 'Image': 'C:\\a.exe', 'TargetObject': 'HKLM\\x', 'Details': 'DWORD (1)'}), {'registry.key': 'HKLM\\x', 'registry.data.strings': 'DWORD (1)', 'event.category': ['registry']}),
    'sysmon access': (event(SYSMON, 10, 6, {'SourceProcessId': '5', 'SourceImage': 'C:\\s.exe', 'TargetProcessId': '6', 'TargetImage': 'C:\\t.exe'}), {'process.pid': 5, 'process.target.pid': 6, 'process.name': 's.exe'}),
    'security logon': (event('Security', 4624, 7, {'TargetUserName': 'bob', 'TargetDomainName': 'HOST', 'TargetUserSid': 'S-1-5-21-1', 'IpAddress': '192.0.2.1', 'IpPort': '51000', 'LogonType': '3', 'WorkstationName': 'W', 'ProcessName': '-', 'ProcessId': '0x0'}),
                       {'event.category': ['authentication'], 'event.outcome': 'success', 'user.name': 'bob', 'user.domain': 'HOST', 'source.ip': '192.0.2.1', 'source.port': 51000, 'winlog.logon.type': '3', 'event.action': 'logged-in'}),
    'security failure': (event('Security', 4625, 8, {'TargetUserName': 'bob', 'IpAddress': '-', 'IpPort': '-'}), {'event.outcome': 'failure', 'source.ip': None, 'source.port': None}),
    'security process': (event('Security', 4688, 9, {'SubjectUserName': 'bob', 'NewProcessName': 'C:\\a\\b.exe', 'NewProcessId': '0x1a', 'ProcessId': '0x10', 'ParentProcessName': 'C:\\p.exe'}),
                         {'process.pid': 26, 'process.parent.pid': 16, 'process.name': 'b.exe', 'process.parent.name': 'p.exe', 'event.category': ['process']}),
    'security group': (event('Security', 4732, 10, {'SubjectUserName': 'admin', 'TargetUserName': 'Administrators', 'MemberName': 'CN=bob'}), {'group.name': 'Administrators', 'user.name': 'admin', 'event.category': ['iam']}),
    'powershell': (event(POWERSHELL, 4104, 11, {'ScriptBlockText': 'Get-Date', 'ScriptBlockId': 'id', 'Path': ''}), {'powershell.script_block.text': 'Get-Date', 'powershell.script_block.id': 'id', 'powershell.script_block.path': None, 'event.dataset': 'windows.powershell'}),
    'system service': (event('System', 7045, 12, {'ServiceName': 'svc', 'ImagePath': 'C:\\s.exe'}), {'service.name': 'svc', 'file.path': 'C:\\s.exe', 'event.dataset': 'windows.system'}),
    'defender': (event('Microsoft-Windows-Windows Defender/Operational', 1116, 13, {'Threat Name': 'Test', 'Severity Name': 'Severe', 'Path': 'file:_C:\\x'}), {'threat.indicator.name': 'Test', 'event.category': ['malware'], 'event.dataset': 'windows.defender'}),
    'firewall': (event('Microsoft-Windows-Windows Firewall With Advanced Security/Firewall', 2004, 14, {'RuleName': 'r', 'RuleId': 'i'}), {'rule.name': 'r', 'rule.id': 'i', 'event.dataset': 'windows.firewall'}),
    'task': (event('Microsoft-Windows-TaskScheduler/Operational', 106, 15, {'TaskName': '\\t', 'UserContext': 'bob'}), {'file.path': '\\t', 'event.category': ['configuration']}),
    'unknown id': (event('Security', 9999, 16, {'Anything': 'x'}), {'event.action': 'windows-event-9999', 'event.outcome': 'unknown', 'event.category': ['configuration'], 'event.type': ['info']}),
    'no event data': (event('Security', 4624, 17, None), {'event.code': '4624', 'user.name': None}),
    'event data not an object': (event('Security', 4624, 18, 'text'), {'event.code': '4624', 'user.name': None}),
    'bad numbers': (event(SYSMON, 3, 19, {'ProcessId': 'abc', 'SourcePort': '99999', 'DestinationPort': 'x', 'SourceIp': 'not an ip', 'DestinationIp': '1.2.3.999'}), {'process.pid': None, 'source.port': None, 'destination.port': None, 'source.ip': None, 'destination.ip': None}),
    'unexpected types': (event(SYSMON, 1, 20, {'ProcessId': ['x'], 'Image': 5, 'User': {'a': 1}, 'Hashes': 7}), {'event.code': '1', 'process.name': None}),
    'no domain in user': (event(SYSMON, 1, 21, {'User': 'bob'}), {'user.name': 'bob', 'user.domain': None}),
    'bad timestamp': ({**event('Security', 4624, 22, {}), 'timestamp': 'nope'}, {'event.code': '4624'}),
    'other offset time': ({**event('Security', 4624, 23, {}), 'timestamp': '2026-10-31T01:00:00+05:30'}, {'@timestamp': '2026-10-30T19:30:00.000Z', 'siem_index': '2026.10.30'}),
}


def main(vector):
    with tempfile.TemporaryDirectory() as tmp:
        work = pathlib.Path(tmp)
        config = {'data_dir': str(work), 'sources': {'in': {'type': 'stdin', 'decoding': {'codec': 'json'}}},
                  'transforms': {'normalize': {**AGG['transforms']['normalize'], 'inputs': ['in']},
                                 'normalize_failed': {**AGG['transforms']['normalize_failed'], 'inputs': ['normalize.dropped']}},
                  'sinks': {'good': {'type': 'file', 'inputs': ['normalize'], 'path': str(work / 'good.ndjson').replace('\\', '/'), 'encoding': {'codec': 'json'}},
                            'dead': {'type': 'file', 'inputs': ['normalize_failed'], 'path': str(work / 'dead.ndjson').replace('\\', '/'), 'encoding': {'codec': 'json'}}}}
        path = work / 'ecs.json'
        path.write_text(json.dumps(config), encoding='utf8')
        done = subprocess.run([vector, '--config', str(path), '--quiet'], input='\n'.join(json.dumps(e) for e, _ in CASES.values()) + '\n', capture_output=True, text=True, encoding='utf8', timeout=120)
        check('Vector exits cleanly', done.returncode == 0, done.stderr[-600:] if done.returncode else '')
        docs = [json.loads(l) for l in (work / 'good.ndjson').read_text(encoding='utf8').splitlines()] if (work / 'good.ndjson').exists() else []
        dead = (work / 'dead.ndjson').read_text(encoding='utf8').splitlines() if (work / 'dead.ndjson').exists() else []
        check('every event normalizes, none falls through to dead letters', len(docs) == len(CASES) and not dead, f'{len(docs)} of {len(CASES)}, {len(dead)} dead')
        by = {d['siem_id']: d for d in docs}
        for name, (source, expected) in CASES.items():
            doc = by.get(source['event_uid'], {})
            wrong = {k: get(doc, k) for k, v in expected.items() if get(doc, k) != v}
            check(f'{name}', doc != {} and not wrong, str(wrong) if wrong else '')
        for doc in docs:
            base = ['@timestamp', 'ecs.version', 'host.name', 'host.os.type', 'event.id', 'event.kind', 'event.module', 'event.dataset', 'event.code', 'event.action', 'winlog.channel', 'winlog.event_id', 'winlog.record_id', 'siem_index', 'siem_id']
            missing = [k for k in base if get(doc, k) is None]
            if missing:
                check(f"base fields on {doc.get('siem_id', '')[-4:]}", False, str(missing))
        check('every document has the base ECS fields', True)
        check('original fields are kept for investigation', get(by[CASES['security logon'][0]['event_uid']], 'winlog.event_data.LogonType') == '3')
        check('no raw source fields leak to the top level', not any(k in d for d in docs for k in ('event_data', 'channel', 'event_uid', 'kafka', 'sealed', 'computer')))
    print(f'\n{len(failures)} failed' if failures else '\nall passed')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1]))
