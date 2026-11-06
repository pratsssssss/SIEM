#!/usr/bin/env python3
"""Reports how close unread Kafka events are to expiring, and whether any already have.

The Windows agent moves its checkpoints on once Kafka has an event, so an event that expires
unread is not re-sent. This check is the only thing that shows that happening. It reads offsets
and record times only, never record values.

Exit status: 0 OK, 1 WARN, 2 CRITICAL, 3 LOST, 4 check failed. Each non-zero status fails the
systemd unit, so a failed check is visible instead of looking like a healthy one.

LOST is latched in the state folder, because the consumer's next commit hides the evidence. Delete
kafka-expiry.lost.json only after the loss has been reviewed.

--publish copies the report to a Windows path, where siem-alert-watch.ps1 turns it into a visible
notification. A failed publish goes stale there, and stale reports alert too.
"""
import argparse
import json
import os
import pathlib
import re
import subprocess
import sys
import time

OK, WARN, CRITICAL, LOST, FAILED = 0, 1, 2, 3, 4
NAMES = {OK: 'OK', WARN: 'WARN', CRITICAL: 'CRITICAL', LOST: 'LOST', FAILED: 'CHECK_FAILED'}
SYSLOG = {OK: 6, WARN: 4, CRITICAL: 2, LOST: 1, FAILED: 3}


def kafka(args, tool, *options, check=True):
    command = [f'{args.kafka_bin}/{tool}', '--bootstrap-server', args.bootstrap, *options]
    done = subprocess.run(command, capture_output=True, text=True, timeout=120)
    if check and done.returncode != 0:
        raise RuntimeError(f'{tool} exited {done.returncode}')
    return done.stdout


def retention_ms(args):
    text = kafka(args, 'kafka-configs.sh', '--describe', '--all', '--entity-type', 'topics', '--entity-name', args.topic)
    # Anchored, because delete.retention.ms appears in the same output.
    match = re.search(r'^\s*retention\.ms=(\d+)', text, re.M)
    if not match:
        raise RuntimeError('retention.ms not found')
    return int(match[1])


def offsets(args, when):
    text = kafka(args, 'kafka-get-offsets.sh', '--topic', args.topic, '--time', when)
    return {int(p): int(o) for p, o in re.findall(rf'^{re.escape(args.topic)}:(\d+):(\d+)$', text, re.M)}


def committed(args):
    """Returns partition to offset. A partition with no commit is absent."""
    done = subprocess.run([f'{args.kafka_bin}/kafka-consumer-groups.sh', '--bootstrap-server', args.bootstrap,
                           '--describe', '--group', args.group, '--offsets'], capture_output=True, text=True, timeout=120)
    result = {}
    for line in done.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[1] == args.topic and fields[2].isdigit() and fields[3].isdigit():
            result[int(fields[2])] = int(fields[3])
    return result


def record_time_ms(args, partition, offset):
    text = kafka(args, 'kafka-console-consumer.sh', '--topic', args.topic, '--partition', str(partition), '--offset', str(offset),
                 '--max-messages', '1', '--timeout-ms', '15000', '--formatter-property', 'print.timestamp=true',
                 '--formatter-property', 'print.value=false', check=False)
    match = re.search(r'(?:CreateTime|LogAppendTime):(\d+)', text)
    return int(match[1]) if match else None


def inspect(args, now_ms):
    limit = retention_ms(args)
    earliest, latest = offsets(args, 'earliest'), offsets(args, 'latest')
    done = committed(args)
    partitions = []
    for partition in sorted(latest):
        start, end = earliest.get(partition, 0), latest[partition]
        commit = done.get(partition)
        position = start if commit is None else commit
        lost = max(0, start - commit) if commit is not None else 0
        unread = max(0, end - max(position, start))
        age = None
        if unread:
            stamp = record_time_ms(args, partition, max(position, start))
            if stamp is None:
                raise RuntimeError(f'no record time for partition {partition}')
            age = now_ms - stamp
        partitions.append({'partition': partition, 'log_start': start, 'log_end': end, 'committed': commit,
                           'unread': unread, 'oldest_unread_age_ms': age, 'lost': lost})
    return limit, partitions


def latch(state, topic, partitions):
    """Keeps the highest lost range seen per partition, so a later commit cannot erase it."""
    path = state / 'kafka-expiry.lost.json'
    known = json.loads(path.read_text()) if path.exists() else {}
    for item in partitions:
        key = f"{topic}:{item['partition']}"
        if item['lost'] and item['lost'] > known.get(key, {}).get('lost', 0):
            known[key] = {'lost': item['lost'], 'first_offset': item['committed'], 'last_offset': item['log_start'] - 1, 'recorded_ms': int(time.time() * 1000)}
    if known:
        path.write_text(json.dumps(known, indent=2))
    return known


def write_state(path, report):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(report, indent=2))
    os.replace(temporary, path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--bootstrap', default='127.0.0.1:9092')
    parser.add_argument('--topic', default='siem-raw-logs')
    parser.add_argument('--group', default='siem-aggregator')
    parser.add_argument('--kafka-bin', default='/opt/kafka/bin')
    parser.add_argument('--state-dir', default='/home/linux/siem/data/monitor')
    parser.add_argument('--warn-ratio', type=float, default=1 / 3, help='24 hours of 72')
    parser.add_argument('--critical-ratio', type=float, default=2 / 3, help='48 hours of 72')
    parser.add_argument('--publish', help='also write the report to this path')
    args = parser.parse_args()
    state = pathlib.Path(args.state_dir)
    state.mkdir(parents=True, exist_ok=True)
    now_ms = int(time.time() * 1000)
    report = {'checked_ms': now_ms, 'topic': args.topic, 'group': args.group}
    try:
        limit, partitions = inspect(args, now_ms)
        lost = latch(state, args.topic, partitions)
        ages = [p['oldest_unread_age_ms'] for p in partitions if p['oldest_unread_age_ms'] is not None]
        oldest = max(ages) if ages else None
        status = OK
        if oldest is not None and oldest >= limit * args.critical_ratio:
            status = CRITICAL
        elif oldest is not None and oldest >= limit * args.warn_ratio:
            status = WARN
        if lost:
            status = LOST
        report.update(retention_ms=limit, oldest_unread_age_ms=oldest, unread=sum(p['unread'] for p in partitions),
                      lost_latched=lost, partitions=partitions)
        message = f"unread={report['unread']} oldest_unread_age_s={None if oldest is None else oldest // 1000} retention_s={limit // 1000} lost={sum(v['lost'] for v in lost.values())}"
    except Exception as error:
        status = FAILED
        message = f'check could not complete: {error}'
    report.update(status=NAMES[status], message=message)
    write_state(state / 'kafka-expiry.json', report)
    if args.publish:
        try:
            write_state(pathlib.Path(args.publish), report)
        except OSError as error:
            print(f'<3>siem-kafka-expiry could not publish: {error}', flush=True)
    print(f'<{SYSLOG[status]}>siem-kafka-expiry {NAMES[status]} {message}', flush=True)
    return status


if __name__ == '__main__':
    sys.exit(main())
