"""The two ways inventory arrives. On the SIEM host this reads the machine's own files, plus two programs with
fixed arguments, and no value from a report ever becomes part of a command. Other machines drop a snapshot in a
folder, and each file there is treated as hostile: no links, no other file types, and bounded in size.
"""
import ipaddress
import json
import os
import pwd
import grp
import re
import socket
import stat
import subprocess
from pathlib import Path

from . import schema

_DROP_NAME = re.compile(r'^[A-Za-z0-9._-]{1,64}\.json$')
MAX_FILES = 16
IP = '/usr/sbin/ip'
SYSTEMCTL = '/usr/bin/systemctl'
_RUN = {'capture_output': True, 'timeout': 20, 'check': False, 'stdin': subprocess.DEVNULL, 'env': {'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C'}}


def read_drop(folder):
    """(name, bytes) for each candidate, and (name, reason) for each refused."""
    good, refused = [], []
    try:
        names = sorted(e.name for e in os.scandir(folder))
    except OSError:
        return good, refused
    for name in names:
        if name.endswith('.tmp'):
            continue
        if not _DROP_NAME.fullmatch(name):
            refused.append((name[:80].encode('ascii', 'replace').decode(), 'file name not allowed'))
            continue
        if len(good) >= MAX_FILES:
            refused.append((name, 'too many files'))
            continue
        try:
            handle = os.open(os.path.join(folder, name), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError:
            refused.append((name, 'not readable as a plain file'))
            continue
        try:
            info = os.fstat(handle)
            if not stat.S_ISREG(info.st_mode):
                refused.append((name, 'not a plain file'))
            elif info.st_size > schema.MAX_SNAPSHOT_BYTES:
                refused.append((name, 'too large'))
            else:
                good.append((name, os.read(handle, schema.MAX_SNAPSHOT_BYTES + 1)))
        finally:
            os.close(handle)
    return good, refused


def decode(raw):
    return json.loads(raw.decode('utf-8-sig'))


def _first_line(path):
    try:
        return Path(path).read_text(encoding='utf8').strip()
    except OSError:
        return ''


def _os_release(path='/etc/os-release'):
    found = {}
    try:
        for line in Path(path).read_text(encoding='utf8').splitlines():
            if '=' in line:
                key, value = line.split('=', 1)
                found[key] = value.strip('"')
    except OSError:
        pass
    return found


def packages(path='/var/lib/dpkg/status'):
    """Read directly, so nothing is run. Installed packages only."""
    found, current = [], {}
    with open(path, encoding='utf8', errors='replace') as handle:
        for line in handle:
            if line == '\n':
                if current.get('Status', '').endswith(' installed') and current.get('Package'):
                    found.append({'name': current['Package'], 'version': current.get('Version', ''), 'publisher': ''})
                current = {}
            elif ': ' in line and line[0] not in ' \t' and line.split(': ', 1)[0] in ('Package', 'Status', 'Version'):
                key, value = line.split(': ', 1)
                current[key] = value.strip()
    return found[:schema.LIMITS['software']]


def _program(arguments):
    result = subprocess.run(arguments, **_RUN)
    if result.returncode != 0:
        raise OSError(f'{arguments[0]} exited {result.returncode}')
    return json.loads(result.stdout)


def interfaces():
    found = []
    for row in _program([IP, '-j', 'addr']):
        addresses = row.get('addr_info') or []
        found.append({'name': row.get('ifname'), 'mac': row.get('address'), 'up': row.get('operstate') == 'UP', 'virtual': True, 'ips': [a.get('local') for a in addresses], 'cidrs': [f"{a.get('local')}/{a.get('prefixlen')}" for a in addresses]})
    return [i for i in found if i['name'] != 'lo']


def services():
    found = []
    for row in _program([SYSTEMCTL, 'list-units', '--type=service', '--all', '--output=json', '--no-pager', '--plain']):
        name = str(row.get('unit', ''))
        if name.endswith('.service') and row.get('load') == 'loaded' and '@' not in name:
            found.append({'name': name[:-8], 'display': row.get('description', ''), 'state': row.get('sub', ''), 'start': '', 'binary': ''})
    return found


def local_users():
    try:
        admins = set(grp.getgrnam('sudo').gr_mem)
    except KeyError:
        admins = set()
    return [{'name': u.pw_name, 'enabled': not u.pw_shell.endswith(('nologin', 'false')), 'local_admin': u.pw_name in admins or u.pw_uid == 0} for u in pwd.getpwall() if u.pw_uid == 0 or 1000 <= u.pw_uid < 60000]


def _decode_address(text):
    if len(text) == 8:
        return ipaddress.ip_address(bytes.fromhex(text)[::-1])
    return ipaddress.ip_address(b''.join(bytes.fromhex(text[n:n + 8])[::-1] for n in range(0, 32, 8)))


def listeners(folder='/proc/net'):
    found = []
    for name in ('tcp', 'tcp6'):
        try:
            lines = Path(folder, name).read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            if parts[3] != '0A':
                continue
            text, port = parts[1].split(':')
            address = _decode_address(text)
            address = getattr(address, 'ipv4_mapped', None) or address
            found.append({'proto': 'tcp', 'port': int(port, 16), 'scope': 'loopback' if address.is_loopback else 'any' if address.is_unspecified else 'specific', 'process': ''})
    return found


def _section(name, reader, gaps):
    try:
        return reader()
    except (OSError, ValueError, subprocess.SubprocessError):
        gaps.append(name)
        return None


def linux_snapshot(now_text):
    """This machine, in the same shape as any other. A section that cannot be read is left out, not left empty."""
    release = _os_release()
    gaps = []
    snap = {'schema': schema.SNAPSHOT, 'collector': 'linux-local', 'collected_at': now_text,
            'host': {'hostname': socket.gethostname().split('.')[0], 'platform': 'linux', 'asset_type': 'siem_host', 'virtual': True},
            'identifiers': {'linux_machine_id': _first_line('/etc/machine-id')},
            'os': {'name': release.get('NAME', ''), 'version': release.get('VERSION_ID', ''), 'build': os.uname().release, 'arch': os.uname().machine}}
    for name, reader in (('interfaces', interfaces), ('software', packages), ('services', services), ('users', local_users), ('listeners', listeners)):
        rows = _section(name, reader, gaps)
        if rows is not None:
            snap[name] = rows
    return snap, gaps
