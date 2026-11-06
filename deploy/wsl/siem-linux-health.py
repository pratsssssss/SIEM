#!/usr/bin/env python3
"""Reports whether the Linux agent is keeping up, for the alert watcher and a future dashboard.

Counts and ages only, never journal content. See docs/pipeline/wsl2-linux-telemetry.md.
Exit status: 0 OK, 1 WARN, 4 check failed.
"""
import json
import os
import pathlib
import re
import subprocess
import time
import urllib.request

DATA = pathlib.Path('/home/linux/siem/data/linux-agent')
# The Windows copy goes to the folder its unit names, from config/wsl/site.env. With none set, it is skipped.
MONITOR = os.environ.get('SIEM_WINDOWS_MONITOR', '')
REPORTS = [DATA / 'health.json'] + ([pathlib.Path(MONITOR) / 'linux-agent.json'] if MONITOR else []) + [pathlib.Path('/home/linux/siem/data/status/linux-agent/health.json')]
METRICS = 'http://127.0.0.1:9597/metrics'
JOURNALCTL = '/usr/bin/journalctl'
LAG_WARN_SECONDS = 300
LIMIT = 5000
SKIPPED = ('kafka', 'opensearch', 'vector', 'seal-verifier', 'siem-')
LINE = re.compile(r'^(?P<name>[a-z_]+)(?P<labels>\{.*\})? (?P<value>[0-9.e+-]+)')
RUN = {'capture_output': True, 'text': True, 'timeout': 30, 'check': False, 'stdin': subprocess.DEVNULL}


def metrics():
    found = {}
    with urllib.request.urlopen(METRICS, timeout=5) as reply:
        for line in reply.read().decode().splitlines():
            match = LINE.match(line)
            if match and ('kafka_raw' in (match['labels'] or '') or match['name'].startswith(('vector_component_errors', 'vector_component_discarded'))):
                found[match['name']] = found.get(match['name'], 0) + float(match['value'])
    return found


def counted(entry):
    unit = entry.get('_SYSTEMD_UNIT') or ''
    if unit.startswith(SKIPPED):
        return False
    return not (entry.get('_TRANSPORT') == 'kernel' and int(entry.get('PRIORITY', 7)) > 4)


def unread():
    """(entries the agent has not read yet, age in seconds of the oldest)."""
    marks = list(DATA.glob('journal/checkpoint.txt'))
    if not marks:
        return None, None
    cursor = marks[0].read_text().strip().removeprefix('checkpoint:').strip()
    done = subprocess.run([JOURNALCTL, f'--after-cursor={cursor}', '-o', 'json', '-n', str(LIMIT), '--no-pager', '-q'], **RUN)
    now = time.time()
    entries = []
    for line in done.stdout.splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if counted(entry):
            entries.append(entry)
    age = max((now - int(e['__REALTIME_TIMESTAMP']) / 1e6 for e in entries), default=0)
    return len(entries), int(age)


def main():
    now = int(time.time() * 1000)
    active = subprocess.run(['/usr/bin/systemctl', 'is-active', 'siem-linux-agent'], **RUN).stdout.strip()
    report = {'status': 'OK', 'checked_ms': now, 'message': '', 'source': 'wsl_infrastructure', 'agent': active}
    code = 0
    try:
        count, age = unread()
        numbers = metrics() if active == 'active' else {}
        report.update(unread_journal_entries=count, oldest_unread_seconds=age, buffer_events=numbers.get('vector_buffer_events'), sent_events=numbers.get('vector_component_sent_events_total'), component_errors=numbers.get('vector_component_errors_total', 0), discarded_events=numbers.get('vector_component_discarded_events_total', 0))
        reasons = []
        if active != 'active':
            reasons.append(f'the Linux agent is {active}')
        if age is not None and age > LAG_WARN_SECONDS:
            reasons.append(f'the oldest unread journal entry is {age} s old')
        if count is None:
            reasons.append('no journal checkpoint exists yet')
        if reasons:
            report.update(status='WARN', message='; '.join(reasons))
            code = 1
        else:
            report['message'] = f'{count} journal entries waiting'
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        report.update(status='CHECK_FAILED', message=f'the check could not run: {type(error).__name__}')
        code = 4
    for path in REPORTS:
        try:
            spare = path.with_suffix('.tmp')
            spare.write_text(json.dumps(report if str(path).startswith('/home/') else {k: report[k] for k in ('status', 'checked_ms', 'message')}, indent=1))
            spare.replace(path)
        except OSError:
            pass
    print(f"{report['status']}: {report['message']}", flush=True)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
