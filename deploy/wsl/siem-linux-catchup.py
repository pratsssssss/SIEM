#!/usr/bin/env python3
"""Recovers journal entries from an earlier boot, before the Linux agent starts.

Vector cannot read across boots on systemd 250 to 257, so what was written after the agent stopped, and
before the WSL virtual machine restarted, would never be read. This writes those entries to a spool that
the agent reads and seals like any other. Their cursors are the same as a direct read would give, so
nothing can be counted twice. Failing here never stops the agent, which is why the unit ignores the exit status.
See docs/pipeline/wsl2-linux-telemetry.md.
"""
import json
import os
import pathlib
import re
import subprocess

DATA = pathlib.Path('/home/linux/siem/data/linux-agent')
SPOOL = DATA / 'catchup'
JOURNALCTL = '/usr/bin/journalctl'
MAX_ENTRIES = 200000
MAX_BYTES = 128 * 1024 * 1024
SKIPPED_UNITS = ('kafka', 'opensearch', 'vector', 'seal-verifier', 'siem-')
_BOOT = re.compile(r'(?:^|;)b=([0-9a-f]{32})(?:;|$)')


def checkpoint(root=DATA):
    """The agent's last journal cursor, or None on a first run."""
    for path in sorted(root.glob('journal*/**/checkpoint.txt')) + sorted(root.glob('journald*/**/checkpoint.txt')):
        text = path.read_text().strip()
        if text:
            return text.removeprefix('checkpoint:').strip()
    return None


def boot_of(cursor):
    match = _BOOT.search(cursor)
    return match.group(1) if match else None


def wanted(entry):
    return not (entry.get('_SYSTEMD_UNIT') or '').startswith(SKIPPED_UNITS)


def main():
    cursor = checkpoint()
    if not cursor:
        print('no checkpoint yet, so there is nothing to recover', flush=True)
        return 0
    boot = boot_of(cursor)
    current = pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip().replace('-', '')
    if boot is None or boot == current:
        print('the checkpoint is in this boot, so there is nothing to recover', flush=True)
        return 0
    SPOOL.mkdir(mode=0o700, exist_ok=True)
    target = SPOOL / f'{boot}.ndjson'
    if target.exists():
        print('this boot was already recovered', flush=True)
        return 0
    spare = target.with_suffix('.tmp')
    command = [JOURNALCTL, f'--after-cursor={cursor}', f'--boot={boot}', '-o', 'json', '--no-pager', '-q']
    count = size = 0
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL) as reader, open(os.open(spare, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), 'wb') as out:
        for line in reader.stdout:
            try:
                if not wanted(json.loads(line)):
                    continue
            except ValueError:
                continue
            if count >= MAX_ENTRIES or size + len(line) > MAX_BYTES:
                print(f'stopped at the limit, after {count} entries. The rest of that boot stays in the journal', flush=True)
                reader.kill()
                break
            out.write(line)
            count += 1
            size += len(line)
    spare.replace(target)
    print(f'{count} entries recovered from an earlier boot', flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
