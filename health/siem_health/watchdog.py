"""Watches the monitor from outside it. Standard library only, and it shares nothing with the service but the state file.

Run by a timer. It writes one small report, which the service reads as a note and the Windows watcher reads as an alert
source, so that a dead monitor is noticed by something that is not the monitor. It restarts nothing.
"""
import json
import os
import pathlib
import sqlite3
import subprocess
import sys
import time

STATE = '/home/linux/siem/data/health/health.db'
# The Windows copy goes to the folder its unit names, from config/wsl/site.env. With none set, only the local report is written.
MONITOR = os.environ.get('SIEM_WINDOWS_MONITOR', '')
REPORTS = (pathlib.Path('/home/linux/siem/data/status/health-watchdog/watchdog.json'),) + ((pathlib.Path(MONITOR) / 'health-watchdog.json',) if MONITOR else ())
SYSTEMCTL = '/usr/bin/systemctl'
LIMIT_SECONDS = 300


def judge(active, last_cycle_ms, now_ms, limit_seconds=LIMIT_SECONDS):
    """(status, message). Pure, for testing."""
    if active != 'active':
        return 'WARN', f'The health monitor service is {active}, so pipeline health is not being observed'
    if last_cycle_ms is None:
        return 'WARN', 'The health monitor has no completed cycle'
    age = (now_ms - last_cycle_ms) // 1000
    if age > limit_seconds:
        return 'WARN', f'The health monitor is running, but its last cycle was {age} s ago'
    return 'OK', f'The health monitor completed a cycle {max(age, 0)} s ago'


def last_cycle():
    try:
        link = sqlite3.connect(f'file:{STATE}?mode=ro', uri=True, timeout=5)
        try:
            row = link.execute("SELECT value FROM marks WHERE name = 'last_cycle_ms'").fetchone()
        finally:
            link.close()
        return int(row[0]) if row else None
    except (sqlite3.Error, ValueError):
        return None


def main():
    done = subprocess.run([SYSTEMCTL, 'is-active', 'siem-health.service'], capture_output=True, text=True, timeout=10, check=False, stdin=subprocess.DEVNULL)
    now = int(time.time() * 1000)
    status, message = judge(done.stdout.strip() or 'unknown', last_cycle(), now)
    body = json.dumps({'status': status, 'checked_ms': now, 'message': message})
    for target in REPORTS:
        try:
            spare = target.with_suffix('.tmp')
            spare.write_text(body, encoding='utf-8')
            spare.replace(target)
        except OSError as error:
            print(f'could not write {target.name}: {type(error).__name__}', file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
