"""Everything an inventory source reports is untrusted: a host name, a program name or a service name can be
written by an attacker. Nothing here runs, and nothing is passed to a shell. Values are checked, cut to size and
cleaned before they are stored, and anything unknown is dropped.
"""
import ipaddress
import re
from datetime import datetime, timezone

SCHEMA_VERSION = 1
SNAPSHOT = 'siem.asset.snapshot/1'
# How a value is known. Kept apart everywhere, so an inference is never shown as a fact.
OBSERVED, ADMIN, INFERRED, EXTERNAL = 'observed', 'admin', 'inferred', 'external'
HIGH, MEDIUM, LOW = 'high', 'medium', 'low'
ASSET_TYPES = ('workstation', 'server', 'domain_controller', 'virtual_machine', 'siem_host', 'unknown')
PLATFORMS = ('windows', 'linux', 'unknown')
CRITICALITY = ('low', 'medium', 'high', 'critical')
METADATA = ('owner', 'department', 'environment', 'location', 'criticality', 'purpose', 'tags')
LIMITS = {'interfaces': 32, 'ips': 16, 'software': 2000, 'services': 1000, 'users': 200, 'listeners': 300}
MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024

_UNSAFE = re.compile('[\x00-\x1f\x7f-\x9f​-‏‪-‮⁠-⁩﻿]')
_SECRET = re.compile(r'(?i)\b(pass(word|wd|phrase)?|pwd|secret|token|api[_-]?key|credential)\s*[=:]\s*\S+')
_HOST = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,253}[A-Za-z0-9])?$')
_MAC = re.compile(r'^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$')
_LABEL = re.compile(r"^[\w .,'()/+&@-]{1,120}$", re.UNICODE)
_BINARY = re.compile(r'^[\w .()+-]{1,128}$', re.UNICODE)
_ID = re.compile(r'^[A-Za-z0-9{}_-]{8,128}$')
# Per-user Windows services carry a suffix that changes at each logon.
_USER_SERVICE = re.compile(r'^(.+)_[0-9a-f]{4,8}$')
_VIRTUAL_MAC = ('00:15:5d', '08:00:27', '00:0c:29', '00:50:56', '00:05:69', '52:54:00', '00:1c:42', '00:03:ff')


class Invalid(ValueError):
    pass


def ms(text):
    moment = datetime.fromisoformat(str(text).replace('Z', '+00:00'))
    return int(moment.replace(tzinfo=moment.tzinfo or timezone.utc).timestamp() * 1000)


def iso(value):
    return datetime.fromtimestamp(value / 1000, timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'


def clean(value, limit=256):
    """Text fit to store and print: no control or direction characters, no credential shapes, bounded size."""
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return ''
    return _SECRET.sub('[REDACTED]', _UNSAFE.sub('', str(value))).strip()[:limit]


def hostname(value):
    """The lower-case name, or None. A name that fails this is not stored, displayed or matched."""
    text = value.strip() if isinstance(value, str) else ''
    return text.lower() if _HOST.fullmatch(text) and '..' not in text else None


def mac(value):
    text = value.strip().lower().replace('-', ':') if isinstance(value, str) else ''
    return text if _MAC.fullmatch(text) and text != '00:00:00:00:00:00' else None


def mac_is_physical(value):
    """Virtual adapters and locally administered addresses repeat across machines, so they prove nothing."""
    return value is not None and not value.startswith(_VIRTUAL_MAC) and not int(value[:2], 16) & 2


def address(value):
    try:
        return str(ipaddress.ip_address(str(value).strip().split('%')[0]))
    except ValueError:
        return None


def routable(value):
    """Loopback, link-local and multicast addresses say nothing about which machine this is."""
    parsed = ipaddress.ip_address(value)
    return not (parsed.is_loopback or parsed.is_link_local or parsed.is_multicast or parsed.is_unspecified)


def segment(value):
    """The private subnet an interface reports, or None. Public ranges and single addresses say nothing useful."""
    try:
        network = ipaddress.ip_interface(str(value).strip()).network
    except ValueError:
        return None
    usable = network.version == 4 and network.is_private and 8 <= network.prefixlen <= 30 and routable(str(network.network_address))
    return str(network) if usable else None


def label(value, limit=120):
    """A value set by an administrator."""
    text = clean(value, limit)
    if not _LABEL.fullmatch(text):
        raise Invalid('only letters, digits, spaces and . , \' ( ) / + & @ - are allowed')
    return text


def binary_name(value):
    """File name only. The arguments of a service can hold credentials, so a path is never kept."""
    text = clean(value, 1024).strip('"')
    if not text:
        return ''
    if text.lower().find('.exe') > 0:
        text = text[:text.lower().find('.exe') + 4]
    name = re.split(r'[\\/]', text)[-1].split(' -')[0].strip()
    return name if _BINARY.fullmatch(name) else ''


def service_key(name):
    match = _USER_SERVICE.fullmatch(name)
    return (match.group(1) if match else name).lower()


def identifier(value):
    text = value.strip() if isinstance(value, str) else ''
    return text if _ID.fullmatch(text) else None


def _rows(raw, name):
    rows = raw.get(name)
    if rows is None:
        return None
    if not isinstance(rows, list):
        raise Invalid(f'{name}: not a list')
    return [r for r in rows[:LIMITS[name]] if isinstance(r, dict)]


def _flag(value):
    return value if isinstance(value, bool) else None


def _security(raw):
    raw = raw if isinstance(raw, dict) else {}
    defender = raw.get('defender') if isinstance(raw.get('defender'), dict) else {}
    firewall = raw.get('firewall') if isinstance(raw.get('firewall'), dict) else {}
    found = {'defender_service': _flag(defender.get('service')), 'defender_realtime': _flag(defender.get('realtime')), 'rdp_enabled': _flag(raw.get('rdp_enabled'))}
    for name in ('enabled', 'total'):
        value = firewall.get(name)
        found[f'firewall_profiles_{name}'] = value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 8 else None
    return {k: v for k, v in found.items() if v is not None}


def snapshot(raw, now):
    """A clean snapshot, or Invalid with the reason. A section that is absent was not collected, which is
    different from a section that is empty: absence leaves earlier facts standing."""
    if not isinstance(raw, dict) or raw.get('schema') != SNAPSHOT:
        raise Invalid('unknown snapshot schema')
    host = raw.get('host')
    if not isinstance(host, dict):
        raise Invalid('host is missing')
    name = hostname(host.get('hostname'))
    if name is None:
        raise Invalid('the host name is not valid')
    collector = clean(raw.get('collector'), 40)
    if collector not in ('windows-local', 'linux-local'):
        raise Invalid('unknown collector')
    try:
        collected = ms(raw.get('collected_at'))
    except (ValueError, TypeError):
        raise Invalid('collected_at is not a time') from None
    if collected > now + 600000:
        raise Invalid('collected_at is in the future')
    platform = clean(host.get('platform'), 16)
    asset_type = clean(host.get('asset_type'), 24)
    ids = raw.get('identifiers') if isinstance(raw.get('identifiers'), dict) else {}
    out = {'collector': collector, 'collected_ms': collected, 'hostname': name, 'fqdn': hostname(host.get('fqdn')), 'platform': platform if platform in PLATFORMS else 'unknown', 'asset_type': asset_type if asset_type in ASSET_TYPES else 'unknown',
           'domain_joined': _flag(host.get('domain_joined')), 'virtual': _flag(host.get('virtual')), 'vendor': clean(host.get('vendor'), 80), 'model': clean(host.get('model'), 80),
           'identifiers': {k: v for k, v in ((k, identifier(ids.get(k))) for k in ('windows_machine_guid', 'linux_machine_id', 'hw_uuid', 'cloud_instance_id', 'vm_id')) if v}}
    system = raw.get('os') if isinstance(raw.get('os'), dict) else {}
    out['os'] = {k: v for k, v in ((k, clean(system.get(k), 80)) for k in ('name', 'version', 'build', 'arch')) if v}
    out['security'] = _security(raw.get('security'))
    rows = _rows(raw, 'interfaces')
    if rows is not None:
        out['interfaces'] = []
        for row in rows:
            ips = row.get('ips') if isinstance(row.get('ips'), list) else []
            cidrs = row.get('cidrs') if isinstance(row.get('cidrs'), list) else []
            out['interfaces'].append({'name': clean(row.get('name'), 80), 'mac': mac(row.get('mac')), 'up': _flag(row.get('up')), 'virtual': _flag(row.get('virtual')), 'ips': sorted({a for a in (address(i) for i in ips[:LIMITS['ips']]) if a}), 'segments': sorted({s for s in (segment(c) for c in cidrs[:LIMITS['ips']]) if s})})
    rows = _rows(raw, 'software')
    if rows is not None:
        out['software'] = {}
        for row in rows:
            title = clean(row.get('name'), 160)
            if title:
                out['software'][title.lower()] = {'name': title, 'version': clean(row.get('version'), 60), 'publisher': clean(row.get('publisher'), 100)}
    rows = _rows(raw, 'services')
    if rows is not None:
        out['services'] = {}
        for row in rows:
            title = clean(row.get('name'), 120)
            if title:
                key = service_key(title)
                out['services'][key] = {'name': key, 'display': clean(row.get('display'), 160), 'state': clean(row.get('state'), 24).lower(), 'start': clean(row.get('start'), 24).lower(), 'binary': binary_name(row.get('binary'))}
    rows = _rows(raw, 'users')
    if rows is not None:
        out['users'] = {}
        for row in rows:
            title = clean(row.get('name'), 100)
            if title:
                out['users'][title.lower()] = {'name': title, 'enabled': _flag(row.get('enabled')), 'local_admin': _flag(row.get('local_admin'))}
    rows = _rows(raw, 'listeners')
    if rows is not None:
        out['listeners'] = {}
        for row in rows:
            port, proto, scope = row.get('port'), clean(row.get('proto'), 8).lower(), clean(row.get('scope'), 16).lower()
            if isinstance(port, int) and not isinstance(port, bool) and 0 < port < 49152 and proto in ('tcp', 'udp') and scope in ('loopback', 'any', 'specific'):
                out['listeners'][f'{proto}/{port}/{scope}'] = {'proto': proto, 'port': port, 'scope': scope, 'process': binary_name(row.get('process'))}
    return out
