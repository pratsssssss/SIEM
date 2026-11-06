"""Turns alerts into entities with stable identifiers.

An identifier says exactly what is known, and no more. Two names that look alike are different entities
unless the evidence says otherwise, so `ASUS\\bob` and `bob` stay apart, and a rule that links them must
accept the uncertainty and say so.
"""
import ipaddress
import re
from dataclasses import dataclass

HOST, USER, IP, DOMAIN, PROCESS, HASH, RULE, ALERT, INDICATOR = 'host', 'user', 'ip', 'domain', 'process', 'hash', 'rule', 'alert', 'indicator'

# Accounts that exist on every machine and do not identify a person. They never link anything.
SERVICE_ACCOUNTS = {'system', 'local service', 'network service', 'anonymous logon', 'nt authority\\system', 'nt authority\\local service', 'nt authority\\network service', '-', ''}
# SIDs that say nothing about who it was: null, anonymous, system, local and network service.
EMPTY_SIDS = {'S-1-0-0', 'S-1-5-7', 'S-1-5-18', 'S-1-5-19', 'S-1-5-20'}
_SID = re.compile(r'^S-1-\d+(-\d+)+$')
_GUID = re.compile(r'^\{?[0-9a-fA-F-]{36}\}?$')
_SHA256 = re.compile(r'^[0-9a-fA-F]{64}$')


@dataclass(frozen=True)
class Entity:
    kind: str
    id: str
    display: str
    # strong identifies one thing. weak is real but links nothing. ambiguous links only where a rule accepts it.
    quality: str = 'strong'
    note: str = ''
    loose: str = ''  # for users: the bare name, used only by rules that accept uncertainty


def host(name):
    text = str(name or '').strip().lower()
    return Entity(HOST, f'host:{text}', text) if text else None


def user(name, domain=None, sid=None):
    """A SID identifies an account. A domain and name are next best. A bare name is ambiguous."""
    bare = str(name or '').strip()
    if '\\' in bare and not domain:
        domain, bare = bare.split('\\', 1)
    low, realm = bare.lower(), str(domain or '').strip().lower()
    if not low:
        return None
    if low in SERVICE_ACCOUNTS or f'{realm}\\{low}' in SERVICE_ACCOUNTS or realm in ('nt authority', 'nt service', 'window manager', 'font driver host') or low.endswith('$'):
        return Entity(USER, f'user:service:{low}', bare, 'weak', 'a service or machine account, which identifies no person')
    if sid and _SID.match(str(sid)) and str(sid) not in EMPTY_SIDS:
        return Entity(USER, f'user:sid:{sid}', f'{realm}\\{low}' if realm else low, loose=low)
    if realm and realm not in ('-', '.'):
        return Entity(USER, f'user:name:{realm}\\{low}', f'{realm}\\{low}', loose=low)
    return Entity(USER, f'user:unqualified:{low}', low, 'ambiguous', 'no domain or SID, so this name could be more than one account', loose=low)


def ip(address, host_name=None):
    """Private and loopback addresses mean different things on different hosts, so they are scoped."""
    try:
        parsed = ipaddress.ip_address(str(address).strip())
    except ValueError:
        return None
    text = str(getattr(parsed, 'ipv4_mapped', None) or parsed)
    parsed = ipaddress.ip_address(text)
    if parsed.is_global:
        return Entity(IP, f'ip:{text}', text)
    scope = str(host_name or 'unknown').lower()
    quality = 'weak' if parsed.is_loopback or parsed.is_link_local or parsed.is_unspecified else 'ambiguous'
    return Entity(IP, f'ip:{scope}:{text}', text, quality, 'a local address, meaningful only on this host')


def domain(name):
    text = str(name or '').strip().rstrip('.').lower()
    return Entity(DOMAIN, f'domain:{text}', text) if text and '.' in text else None


def process(host_name, guid, name=None):
    """Sysmon's process GUID is unique per process start. A PID is reused, so it is never an identity."""
    text = str(guid or '').strip().strip('{}').lower()
    if not _GUID.match(text) or not host_name:
        return None
    return Entity(PROCESS, f'process:{str(host_name).lower()}:{text}', str(name or text))


def sha256(value):
    text = str(value or '').strip().lower()
    return Entity(HASH, f'sha256:{text}', text) if _SHA256.match(text) else None


def indicator(kind, value, verdict):
    return Entity(INDICATOR, f'indicator:{kind}:{value}', str(value), note=str(verdict))


def rule(rule_id, title=''):
    return Entity(RULE, f'rule:{rule_id}', str(title or rule_id))


def alert(alert_id):
    return Entity(ALERT, f'alert:{alert_id}', str(alert_id))


def _first(alert_doc, name):
    values = ((alert_doc.get('evidence') or {}).get('matched_fields') or {}).get(name) or []
    for value in values:
        if isinstance(value, (str, int)):
            return value
    return None


def _get(doc, path):
    value = doc
    for part in path.split('.'):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def extract(alert_doc, events=(), hostile=()):
    """Entities and relationships for one alert. Returns (entities, links, notes)."""
    found, links, notes = {}, [], []

    def add(entity):
        if entity:
            found[entity.id] = entity
        return entity

    this = add(alert(alert_doc['alert_id']))
    add(rule(alert_doc['rule_id'], alert_doc.get('rule_name')))
    machine = add(host(alert_doc.get('host')))
    if machine is None:
        notes.append('the alert names no host')
    name = machine.display if machine else None

    # The alert's own fields, then each source event, which adds identifiers the alert does not carry.
    add(user(alert_doc.get('user') or _first(alert_doc, 'user.name'), _first(alert_doc, 'user.domain')))
    for field, value in (('source.ip', alert_doc.get('source_ip') or _first(alert_doc, 'source.ip')), ('destination.ip', _first(alert_doc, 'destination.ip'))):
        add(ip(value, name) if value else None)
    add(domain(_first(alert_doc, 'dns.question.name')))
    users = set()
    for event in events:
        person = add(user(_get(event, 'user.name'), _get(event, 'user.domain'), _get(event, 'user.id')))
        if person and person.quality != 'weak':
            users.add(person.id)
        for path in ('source.ip', 'destination.ip'):
            add(ip(_get(event, path), name) if _get(event, path) else None)
        add(domain(_get(event, 'dns.question.name')))
        add(sha256(_get(event, 'process.hash.sha256')))
        child = add(process(name, _get(event, 'process.entity_id'), _get(event, 'process.name')))
        parent = add(process(name, _get(event, 'process.parent.entity_id'), _get(event, 'process.parent.name')))
        if child and parent:
            links.append((parent.id, 'spawned', child.id))
    if len(users) > 1:
        notes.append(f'source events name {len(users)} different accounts')
    if not events and alert_doc.get('raw_event_refs'):
        notes.append('source events are no longer available')
    for item in hostile:
        entity = add(indicator(item['type'], item['value'], item['verdict']))
        links.append((this.id, 'involves', entity.id))
    for entity in found.values():
        if entity.kind not in (ALERT,):
            links.append((this.id, 'observed', entity.id))
    return list(found.values()), links, notes


def parent_name(events):
    """The parent image name, lower case, from the first event that has one."""
    for event in events:
        value = _get(event, 'process.parent.name')
        if value:
            return str(value).lower()
    return ''
