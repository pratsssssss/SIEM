#!/usr/bin/env python3
"""Protects the real Windows C: drive and the OpenSearch budget by stopping ingestion.

Runs as root from a timer. /mnt/c reports the real C: volume, which OpenSearch's own watermarks
never see, because they watch the WSL disk. Crossing a stop limit stops vector.service and writes a
latch that keeps it stopped, so Kafka holds events and nothing is deleted. It never deletes data:
retention is ISM's job, and audit evidence is never touched.

Exit status: 0 OK, 1 WARN, 2 CRITICAL, 4 check failed. To resume after a stop, fix the cause and
run: rm /home/linux/siem/data/monitor/ingest-stopped && systemctl start vector
"""
import argparse
import json
import os
import pathlib
import subprocess
import sys
import time

GIB = 1024 ** 3
OK, WARN, CRITICAL, FAILED = 0, 1, 2, 4
NAMES = {OK: 'OK', WARN: 'WARN', CRITICAL: 'CRITICAL', FAILED: 'CHECK_FAILED'}
SYSLOG = {OK: 6, WARN: 4, CRITICAL: 2, FAILED: 3}


def tree_size(path):
    total = 0
    for root, _folders, files in os.walk(path):
        for name in files:
            try:
                total += os.lstat(os.path.join(root, name)).st_size
            except OSError:
                pass
    return total


def deadletter_size(args):
    """Returns None if OpenSearch is down, which is not the guard's failure to report."""
    done = subprocess.run(['curl', '-sS', '--max-time', '10', '--cacert', '/etc/opensearch/root-ca.pem', '-K', args.admin,
                           'https://127.0.0.1:9200/_cat/indices/siem-deadletter-*?bytes=b&h=store.size'], capture_output=True, text=True)
    if done.returncode != 0:
        return None
    return sum(int(x) for x in done.stdout.split() if x.isdigit())


def write_state(path, report):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(report, indent=2))
    os.replace(temporary, path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--windows-drive', default='/mnt/c')
    parser.add_argument('--data', default='/home/linux/siem/data/opensearch')
    parser.add_argument('--state-dir', default='/home/linux/siem/data/monitor')
    # The Windows copy goes to the folder its unit names, from config/wsl/site.env. With none set, it is skipped.
    monitor = os.environ.get('SIEM_WINDOWS_MONITOR', '')
    parser.add_argument('--publish', default=f'{monitor}/disk-guard.json' if monitor else '')
    parser.add_argument('--admin', default='/root/.siem/opensearch-admin.curl')
    parser.add_argument('--warn-free-gib', type=float, default=30)
    parser.add_argument('--stop-free-gib', type=float, default=20)
    parser.add_argument('--warn-data-gib', type=float, default=10)
    parser.add_argument('--stop-data-gib', type=float, default=12)
    parser.add_argument('--warn-dead-gib', type=float, default=0.5)
    parser.add_argument('--stop-dead-gib', type=float, default=1)
    parser.add_argument('--simulate-free-gib', type=float)
    parser.add_argument('--simulate-data-gib', type=float)
    parser.add_argument('--simulate-dead-gib', type=float)
    args = parser.parse_args()
    state = pathlib.Path(args.state_dir)
    state.mkdir(parents=True, exist_ok=True)
    latch = state / 'ingest-stopped'
    report = {'checked_ms': int(time.time() * 1000)}
    try:
        stat = os.statvfs(args.windows_drive)
        # Mounted but empty means the real drive is not being read, so the numbers would be wrong.
        if stat.f_blocks == 0:
            raise RuntimeError(f'{args.windows_drive} reports no size')
        free = stat.f_bavail * stat.f_frsize / GIB
        data = tree_size(args.data) / GIB
        dead = deadletter_size(args)
        dead = None if dead is None else dead / GIB
        if args.simulate_free_gib is not None:
            free = args.simulate_free_gib
        if args.simulate_data_gib is not None:
            data = args.simulate_data_gib
        if args.simulate_dead_gib is not None:
            dead = args.simulate_dead_gib

        reasons = []
        status = OK
        for over, stop, warn, text in (
                (free, args.stop_free_gib, args.warn_free_gib, f'C: free {free:.1f} GiB'),
                (-data, -args.stop_data_gib, -args.warn_data_gib, f'OpenSearch data {data:.1f} GiB of {args.stop_data_gib:.0f}'),
                (None if dead is None else -dead, -args.stop_dead_gib, -args.warn_dead_gib, f'dead letters {dead or 0:.2f} GiB')):
            if over is None:
                continue
            if over <= stop:
                status = CRITICAL
                reasons.append(f'STOP: {text}')
            elif over <= warn:
                status = max(status, WARN)
                reasons.append(f'warning: {text}')

        if status == CRITICAL and not latch.exists():
            latch.write_text('; '.join(reasons) + '\n')
            subprocess.run(['systemctl', 'stop', 'vector.service'], check=False, timeout=120)
        if latch.exists():
            status = CRITICAL
            reasons.insert(0, 'ingestion is stopped until the operator clears it: ' + latch.read_text().strip())
        report.update(free_gib=round(free, 2), data_gib=round(data, 3), dead_gib=None if dead is None else round(dead, 3), ingest_stopped=latch.exists())
        message = '; '.join(reasons) or f'C: free {free:.1f} GiB, OpenSearch data {data:.1f} GiB'
    except Exception as error:
        status = FAILED
        message = f'check could not complete: {error}'
    report.update(status=NAMES[status], message=message)
    write_state(state / 'disk-guard.json', report)
    if args.publish:
        try:
            write_state(pathlib.Path(args.publish), report)
        except OSError as error:
            print(f'<3>siem-disk-guard could not publish: {error}', flush=True)
    print(f'<{SYSLOG[status]}>siem-disk-guard {NAMES[status]} {message}', flush=True)
    return status


if __name__ == '__main__':
    sys.exit(main())
