"""What this SIEM really stores: Sigma log sources and field names mapped to the ECS index.

Only event types and fields seen in real telemetry are listed. A field that is not listed makes the
rule fail validation, so a rule can never match nothing because of a mistyped or missing field.
"""

# Rules select their own dataset, so a Windows rule cannot match a Linux event, or the reverse.
EVENT_INDEX = 'siem-windows-*,siem-linux-*'

# Sigma's string matching needs a keyword form. These are the fields that are not plain keywords.
FIELD_TYPES = {
    'destination.ip': 'ip',
    'source.ip': 'ip',
    'destination.port': 'long',
    'source.port': 'long',
    'process.pid': 'long',
    'process.parent.pid': 'long',
}

_PROCESS = {
    'Image': 'process.executable',
    'CommandLine': 'process.command_line.keyword',
    'ParentImage': 'process.parent.executable',
    'ParentCommandLine': 'process.parent.command_line.keyword',
    'OriginalFileName': 'process.pe.original_file_name',
    'IntegrityLevel': 'winlog.event_data.IntegrityLevel',
    'CurrentDirectory': 'winlog.event_data.CurrentDirectory',
    'User': 'winlog.event_data.User',
}
_IMAGE = {'Image': 'process.executable', 'User': 'winlog.event_data.User'}


def _sysmon(code):
    return [{'term': {'event.dataset': 'windows.sysmon'}}, {'term': {'event.code': code}}]


def _dataset(name):
    return [{'term': {'event.dataset': name}}]


# Key: (product, category, service). The filter is what the log source means on this pipeline.
LOGSOURCES = {
    ('windows', 'process_creation', None): {'filter': _sysmon('1'), 'fields': _PROCESS},
    ('windows', 'network_connection', None): {'filter': _sysmon('3'), 'fields': {
        **_IMAGE,
        'DestinationIp': 'destination.ip',
        'DestinationPort': 'destination.port',
        'SourceIp': 'source.ip',
        'SourcePort': 'source.port',
        'DestinationHostname': 'winlog.event_data.DestinationHostname',
        'Initiated': 'winlog.event_data.Initiated',
        'Protocol': 'network.transport',
    }},
    ('windows', 'file_event', None): {'filter': _sysmon('11'), 'fields': {
        **_IMAGE, 'TargetFilename': 'file.path',
    }},
    ('windows', 'registry_set', None): {'filter': _sysmon('13'), 'fields': {
        **_IMAGE, 'TargetObject': 'registry.key', 'Details': 'registry.data.strings',
    }},
    ('windows', 'dns_query', None): {'filter': _sysmon('22'), 'fields': {
        **_IMAGE, 'QueryName': 'dns.question.name',
    }},
    ('windows', 'ps_script', None): {'filter': [{'term': {'event.dataset': 'windows.powershell'}}, {'term': {'event.code': '4104'}}], 'fields': {
        # powershell.script_block.text is analyzed only, so a substring cannot be matched exactly on it.
        'ScriptBlockText': 'winlog.event_data.ScriptBlockText',
        'Path': 'winlog.event_data.Path',
    }},
    ('windows', None, 'security'): {'filter': _dataset('windows.security'), 'fields': {
        'EventID': 'event.code',
        'TargetUserName': 'winlog.event_data.TargetUserName',
        'SubjectUserName': 'winlog.event_data.SubjectUserName',
        'TargetSid': 'winlog.event_data.TargetSid',
        'MemberSid': 'winlog.event_data.MemberSid',
        'MemberName': 'winlog.event_data.MemberName',
        'ServiceName': 'service.name',
        'ServiceFileName': 'file.path',
        'LogonType': 'winlog.event_data.LogonType',
        'PrivilegeList': 'winlog.event_data.PrivilegeList',
    }},
    ('windows', None, 'system'): {'filter': _dataset('windows.system'), 'fields': {
        'EventID': 'event.code',
        'ServiceName': 'service.name',
        'ImagePath': 'file.path',
        'StartType': 'winlog.event_data.StartType',
        'AccountName': 'winlog.event_data.AccountName',
    }},
    ('windows', None, 'windefend'): {'filter': _dataset('windows.defender'), 'fields': {
        'EventID': 'event.code',
        'ThreatName': 'threat.indicator.name',
        'Path': 'file.path',
    }},
    ('windows', None, 'taskscheduler'): {'filter': _dataset('windows.taskscheduler'), 'fields': {
        'EventID': 'event.code',
        'TaskName': 'file.path',
    }},
}

_LINUX = {'Action': 'event.action', 'Outcome': 'event.outcome', 'User': 'user.name', 'TargetUser': 'user.target.name', 'EffectiveUser': 'user.effective.name', 'Group': 'group.name', 'Exe': 'process.executable'}
LOGSOURCES.update({
    ('linux', None, 'auth'): {'filter': _dataset('linux.auth'), 'fields': _LINUX},
    ('linux', None, 'cron'): {'filter': _dataset('linux.cron'), 'fields': _LINUX},
    ('linux', None, 'system'): {'filter': _dataset('linux.system'), 'fields': {**_LINUX, 'Service': 'service.name'}},
    ('linux', None, 'package'): {'filter': _dataset('linux.package'), 'fields': {'Action': 'event.action', 'Package': 'package.name'}},
})

# Fields safe to carry in plain text on Kafka, which has no authentication. Everything else is
# replaced by a digest, so a field added later is withheld until someone decides otherwise (D22).
KAFKA_SAFE_FIELDS = frozenset({
    '@timestamp', 'event.code', 'event.dataset', 'event.id', 'event.action', 'event.category', 'event.outcome',
    'host.name', 'user.name', 'user.domain', 'user.id', 'group.name',
    'process.name', 'process.parent.name', 'process.executable', 'process.parent.executable', 'process.pid',
    'process.pe.original_file_name',
    'source.ip', 'source.port', 'destination.ip', 'destination.port', 'network.transport', 'network.direction',
    'dns.question.name', 'service.name', 'threat.indicator.name', 'threat.indicator.severity',
    'registry.key', 'winlog.channel', 'winlog.record_id', 'user.target.name', 'user.effective.name', 'package.name',
})

# Fields collected for every alert, when an event has them.
CONTEXT_FIELDS = (
    'event.code', 'event.dataset', 'event.action', 'host.name', 'user.name', 'user.domain',
    'process.name', 'process.executable', 'process.command_line', 'process.parent.name', 'process.parent.executable',
    'process.parent.command_line', 'source.ip', 'destination.ip', 'destination.port', 'file.path', 'service.name',
    'registry.key', 'threat.indicator.name',
)
