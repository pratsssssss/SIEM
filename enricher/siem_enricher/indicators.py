"""Finds indicators in events and alerts, and makes them safe to compare, store and submit.

An indicator keeps where it came from. Text from a restricted field (D22) can be matched locally, but
is never eligible for an external service, because a command line is the owner's data, not a lookup.
"""
import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

IP, DOMAIN, URL, HASH = 'ip', 'domain', 'url', 'sha256'
KINDS = (IP, DOMAIN, URL, HASH)

# Fields that hold one structured value, so a value here is what the field says it is.
STRUCTURED = {
    'destination.ip': IP, 'source.ip': IP,
    'dns.question.name': DOMAIN,
    'process.hash.sha256': HASH, 'file.hash.sha256': HASH,
}
# Free text. Restricted under D22, or capable of holding a secret. Local matching only.
FREE_TEXT = ('process.command_line', 'process.parent.command_line', 'powershell.script_block.text', 'registry.data.strings', 'file.path')

_URL = re.compile(r'\b(?:https?|ftp)://[^\s"\'<>`|^\\]+', re.IGNORECASE)
_IPV4 = re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')
_LABEL = re.compile(r'^(?!-)[a-z0-9_-]{1,63}(?<!-)$')
_SHA256 = re.compile(r'^[0-9a-fA-F]{64}$')
INTERNAL_SUFFIXES = ('.local', '.localhost', '.internal', '.intranet', '.lan', '.home', '.corp', '.home.arpa', '.in-addr.arpa', '.ip6.arpa', '.test', '.invalid')
MAX_URL = 2048


@dataclass(frozen=True)
class Indicator:
    kind: str
    value: str
    field: str = ''
    restricted: bool = False

    @property
    def key(self):
        return (self.kind, self.value)


def normalize_ip(text):
    """The canonical form, or None. IPv4-mapped IPv6 becomes IPv4, so one host has one key."""
    try:
        address = ipaddress.ip_address(str(text).strip().strip('[]'))
    except ValueError:
        return None
    mapped = getattr(address, 'ipv4_mapped', None)
    return str(mapped or address)


def is_public_ip(text):
    """True only for addresses routable on the internet. Private, loopback, link-local, reserved,
    multicast, documentation and carrier-grade NAT ranges are all excluded by is_global."""
    value = normalize_ip(text)
    if value is None:
        return False
    address = ipaddress.ip_address(value)
    return address.is_global and not address.is_multicast


def normalize_domain(text):
    """Lower case, no trailing dot, IDNA form, or None if it is not a plausible domain."""
    name = str(text).strip().rstrip('.').lower()
    if not name or len(name) > 253 or '.' not in name or normalize_ip(name):
        return None
    try:
        name = name.encode('idna').decode('ascii')
    except UnicodeError:
        return None
    labels = name.split('.')
    if not all(_LABEL.match(label) for label in labels) or labels[-1].isdigit():
        return None
    return name


def is_public_domain(name):
    """False for names that only make sense inside a network, which would leak its structure."""
    return not name.endswith(INTERNAL_SUFFIXES) and name not in ('localhost',)


def normalize_hash(text):
    value = str(text).strip()
    return value.lower() if _SHA256.match(value) else None


def sanitize_url(text):
    """Keeps scheme, host, port and path. Removes credentials, the whole query and the fragment.

    The query is removed, not filtered: a list of sensitive names can never be complete, and a
    session token can sit in any parameter. Returns None if it is not a usable URL.
    """
    raw = str(text).strip().rstrip('.,;:)]}')
    if len(raw) > MAX_URL or any(ord(c) < 33 or ord(c) == 127 for c in raw):
        return None
    try:
        parts = urlsplit(raw)
        host = parts.hostname
        port = parts.port
    except ValueError:
        return None
    if parts.scheme.lower() not in ('http', 'https', 'ftp') or not host:
        return None
    host = normalize_ip(host) or normalize_domain(host)
    if host is None:
        return None
    if ':' in host:
        host = f'[{host}]'
    netloc = f'{host}:{port}' if port and port not in (80, 443, 21) else host
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or '/', '', ''))


def host_of(url):
    host = urlsplit(url).hostname or ''
    return normalize_ip(host) or normalize_domain(host)


def parse(kind, text, field='', restricted=False):
    """Validates one value as one kind. Returns an Indicator, or None."""
    value = {IP: normalize_ip, DOMAIN: normalize_domain, URL: sanitize_url, HASH: normalize_hash}[kind](text)
    return Indicator(kind, value, field, restricted) if value else None


def guess(text):
    """For the manual lookup command."""
    for kind in (HASH, IP, URL, DOMAIN):
        found = parse(kind, text)
        if found:
            return found
    return None


def _get(doc, path):
    if path in doc:
        return doc[path]
    value = doc
    for part in path.split('.'):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def _values(value):
    if value in (None, ''):
        return []
    items = value if isinstance(value, list) else [value]
    return [v for v in items if isinstance(v, (str, int))]


def _from_text(text, field):
    found = []
    for match in _URL.findall(text):
        url = parse(URL, match, field, restricted=True)
        if url:
            found.append(url)
            host = host_of(url.value)
            if host and normalize_domain(host):
                found.append(Indicator(DOMAIN, host, field, True))
            elif host:
                found.append(Indicator(IP, host, field, True))
    for match in _IPV4.findall(_URL.sub(' ', text)):
        address = parse(IP, match, field, restricted=True)
        if address:
            found.append(address)
    return found


def extract(doc):
    """Every indicator in one event document."""
    found = []
    for field, kind in STRUCTURED.items():
        for value in _values(_get(doc, field)):
            item = parse(kind, value, field)
            if item:
                found.append(item)
    # QueryResults holds what Sysmon saw the name resolve to: resolution context, with no new DNS query.
    for value in _values(_get(doc, 'dns.answers.data')):
        found += [i for i in (parse(IP, match, 'dns.answers.data') for match in _IPV4.findall(str(value))) if i]
    for field in FREE_TEXT:
        for value in _values(_get(doc, field)):
            found += _from_text(str(value), field)
    return merge(found)


def extract_alert(alert):
    """Indicators in a full alert's matched fields, which are ECS names mapped to lists of values."""
    fields = (alert.get('evidence') or {}).get('matched_fields') or {}
    found = []
    for field, values in fields.items():
        kind = STRUCTURED.get(field)
        for value in _values(values):
            if kind:
                item = parse(kind, value, field)
                found += [item] if item else []
            elif field in FREE_TEXT:
                found += _from_text(str(value), field)
    return merge(found)


def merge(items):
    """One entry per indicator. A value also seen in a structured field is not restricted."""
    best = {}
    for item in items:
        held = best.get(item.key)
        if held is None or (held.restricted and not item.restricted):
            best[item.key] = item
    return list(best.values())


def external_allowed(indicator, allow_urls=False):
    """The single gate for anything leaving this host. Refuses unless it is plainly permitted."""
    if indicator.restricted:
        return False
    if indicator.kind == IP:
        return is_public_ip(indicator.value)
    if indicator.kind == DOMAIN:
        return is_public_domain(indicator.value)
    if indicator.kind == HASH:
        return normalize_hash(indicator.value) is not None
    if indicator.kind == URL:
        return allow_urls and sanitize_url(indicator.value) == indicator.value and is_public_domain(host_of(indicator.value) or 'localhost')
    return False
