"""Live check, as root in WSL: did each controlled event produce the expected alert in Kafka?

Reads the siem-alerts topic and the evidence index with the admin account. Prints rule names, counts
and the test's own marker. Usage: run_live_detection.py <marker.json> [elevated marker.json] [wait seconds]
"""
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import helpers
from helpers import RULES
from siem_detector import alerts
from siem_detector.rules import load

K = '/opt/kafka/bin'
ENV = {'JAVA_HOME': '/usr/lib/jvm/java-17-openjdk-amd64', 'PATH': '/usr/bin:/bin', 'KAFKA_HEAP_OPTS': '-Xmx128m', 'KAFKA_JMX_OPTS': ' '}
API = 'https://127.0.0.1:9200'
USER_RULES = {
    'ps_suspicious_script': 'Suspicious PowerShell',
    'proc_encoded_powershell': 'Encoded PowerShell',
    'encoded_command_content': 'Encoded PowerShell, decoded',
    'proc_suspicious_parent_child': 'Parent and child',
    'failed_logon_burst': 'Failed logons',
    'password_spray': 'Failed logons, many accounts',
    'proc_privilege_discovery': 'Privilege indicator',
    'task_registered': 'Scheduled task',
    'proc_schtasks_create': 'Scheduled task, command line',
    'reg_run_key': 'Persistence, registry',
    'file_startup_folder': 'Persistence, Startup folder',
    'net_script_host_outbound': 'Network, public address',
    'net_uncommon_port': 'Network, shell port',
    'network_beacon': 'Network, regular beacon',
}
ELEVATED_RULES = {
    'sec_admin_group_add': 'Privilege escalation',
    'logon_after_failures': 'Logon after failures',
    'sys_new_service': 'New service',
    'sys_service_shell_path': 'New service, shell path',
}
# These events cannot hold the marker: Base64 hides it, and network and group events have no free text.
# They count if they fall inside this run, on a rule that is silent otherwise. Output says which matched so.
BY_TIME = {'proc_encoded_powershell', 'encoded_command_content', 'net_script_host_outbound', 'net_uncommon_port', 'network_beacon', 'sec_admin_group_add'}
RUN_SECONDS = 600
failures = []


def check(name, ok, detail=''):
    print(('PASS ' if ok else 'FAIL ') + name + (f' ({detail})' if detail != '' else ''), flush=True)
    if not ok:
        failures.append(name)


def admin(path, body=None):
    command = ['curl', '-sS', '--max-time', '30', '--cacert', '/etc/opensearch/root-ca.pem', '-K', '/root/.siem/opensearch-admin.curl', f'{API}{path}']
    if body is not None:
        command += ['-H', 'Content-Type: application/json', '-d', json.dumps(body)]
    return json.loads(subprocess.run(command, capture_output=True, text=True, check=True).stdout)


def topic():
    end = subprocess.run([f'{K}/kafka-get-offsets.sh', '--bootstrap-server', '127.0.0.1:9092', '--topic', 'siem-alerts', '--time', '-1'], capture_output=True, text=True, env=ENV).stdout
    total = sum(int(line.rsplit(':', 1)[1]) for line in end.split())
    done = subprocess.run([f'{K}/kafka-console-consumer.sh', '--bootstrap-server', '127.0.0.1:9092', '--topic', 'siem-alerts', '--from-beginning', '--max-messages', str(total), '--timeout-ms', '20000', '--property', 'print.key=true', '--property', 'key.separator=\t'],
                          capture_output=True, text=True, env=ENV, timeout=120)
    rows = []
    for line in done.stdout.splitlines():
        key, _, value = line.partition('\t')
        rows.append((key, value))
    return rows


def expected(marker_info, table, kafka, names):
    """An alert counts if its evidence, in OpenSearch, holds this run's marker, or by time for BY_TIME."""
    timed = {names[stem].id for stem in table if stem in BY_TIME}
    since = alerts.parse_ms(marker_info['started'][:23] + 'Z')
    tokens = [marker_info['marker'], *([marker_info['service']] if 'service' in marker_info else [])]
    found = {}
    for key, value in kafka:
        try:
            alert = json.loads(value)
        except ValueError:
            continue
        if 'evidence_ref' not in alert or alerts.parse_ms(alert['timestamp']) < since - 5000:
            continue
        if alert['rule_id'] in timed and alerts.parse_ms(alert['timestamp']) < since + RUN_SECONDS * 1000:
            found.setdefault(alert['rule_id'], []).append(alert)
            continue
        index, alert_id = alert['evidence_ref'].split('/')
        full = admin(f'/{index}/_doc/{alert_id}')
        if not full.get('found'):
            continue
        refs = full['_source'].get('raw_event_refs', [])
        text = json.dumps(full['_source'])
        held = any(token in text for token in tokens)
        for ref in refs[:5] if not held else []:
            doc_index, doc_id = ref.split('/')
            if any(token in json.dumps(admin(f'/{doc_index}/_doc/{doc_id}').get('_source', {})) for token in tokens):
                held = True
                break
        if held:
            found.setdefault(alert['rule_id'], []).append(alert)
    missing = []
    for stem, label in table.items():
        rule = names[stem]
        hits = found.get(rule.id, [])
        if not hits:
            missing.append(stem)
    return found, missing


def main():
    marker = json.load(open(sys.argv[1], encoding='utf-8-sig'))
    elevated = json.load(open(sys.argv[2], encoding='utf-8-sig')) if len(sys.argv) > 2 and sys.argv[2] != '-' else None
    wait = int(sys.argv[3]) if len(sys.argv) > 3 else 420
    names = {Path(r.path).stem: r for r in load(RULES)}
    deadline = time.time() + wait
    while True:
        kafka = topic()
        found, missing = expected(marker, USER_RULES, kafka, names)
        found2, missing2 = expected(elevated, ELEVATED_RULES, kafka, names) if elevated else ({}, [])
        if (not missing and not missing2) or time.time() > deadline:
            break
        print(f'waiting: {len(missing) + len(missing2)} rules outstanding', flush=True)
        time.sleep(30)

    for stem, label in {**USER_RULES, **(ELEVATED_RULES if elevated else {})}.items():
        rule = names[stem]
        hits = found.get(rule.id, []) + found2.get(rule.id, [])
        check(f'{label}: {rule.title}', bool(hits), f"{len(hits)} alerts, matched by {'time' if stem in BY_TIME else 'marker'}")
        for alert in hits[:1]:
            check(f'{stem}: the alert is valid', not alerts.validate(alert), alerts.validate(alert))
            check(f'{stem}: ATT&CK is present', bool(alert['mitre']['techniques']), alert['mitre']['techniques'])
    every = [value for _, value in kafka]
    keys = [k for k, _ in kafka if k != 'probe']
    check('no alert ID was published twice', len(keys) == len(set(keys)), f'{len(keys)} messages, {len(set(keys))} IDs')
    secrets = 0
    for key, value in kafka:
        secrets += ('notthepassword' in value) + ('private' in value.lower() and 'not-the-password' in value)
    check('no test password in Kafka', secrets == 0, secrets)
    leaked = sum('"process.command_line": ["' in value for value in every)
    check('no command line in plain text in Kafka', leaked == 0, leaked)
    print(f'{len(failures)} failed' if failures else 'all passed')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
