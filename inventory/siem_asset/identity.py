"""Which machine is this? A pure decision, so every case can be tested. See ADR-0013, D42.

An operating system identifier or hardware UUID says who a machine is. A host name, MAC or IP address only
suggests it. Two records are never joined on a suggestion: a contradiction opens a conflict for a person,
and the evidence stays on its own record until they decide.
"""
import hashlib
from dataclasses import dataclass, field

from . import schema

STRONG = ('windows_machine_guid', 'linux_machine_id', 'hw_uuid', 'cloud_instance_id', 'vm_id')
# Firmware often ships these placeholders, so they identify nothing.
_JUNK = {'00000000-0000-0000-0000-000000000000', 'ffffffff-ffff-ffff-ffff-ffffffffffff', '03000200-0400-0500-0006-000700080009', '00020003-0004-0005-0006-000700080009', 'to-be-filled-by-o.e.m.', 'not-settable', 'default-string'}
MATCHED, ADOPTED, NEW, NEW_CONFLICTED, HELD = 'matched', 'adopted', 'new', 'new_conflicted', 'held'


def token(kind, value):
    """Identity needs equality only, so a machine identifier is stored as a digest."""
    return hashlib.sha256(f'{kind}:{value.lower()}'.encode()).hexdigest()[:32]


def strong_tokens(identifiers):
    return {k: token(k, v) for k, v in identifiers.items() if k in STRONG and v.lower() not in _JUNK}


@dataclass
class Observation:
    strong: dict = field(default_factory=dict)
    hostnames: list = field(default_factory=list)
    macs: list = field(default_factory=list)

    @classmethod
    def of_snapshot(cls, snap):
        names = [snap['hostname']] + ([snap['fqdn']] if snap.get('fqdn') else [])
        macs = sorted({i['mac'] for i in snap.get('interfaces', ()) if schema.mac_is_physical(i['mac']) and i.get('virtual') is not True})
        return cls(strong_tokens(snap['identifiers']), names, macs)


@dataclass
class Resolution:
    outcome: str
    asset_id: str = None
    confidence: str = schema.LOW
    basis: str = ''
    conflicts: list = field(default_factory=list)


def conflict(kind, assets, why):
    return {'kind': kind, 'assets': sorted(set(assets)), 'why': why}


def resolve(seen, lookup):
    """`lookup` offers holders(kind, value), strong_of(asset) and is_provisional(asset)."""
    if seen.strong:
        return _with_strong(seen, lookup)
    if seen.macs:
        return _by_name_and_mac(seen, lookup)
    return _by_name(seen, lookup)


def _named(seen, lookup):
    found = set()
    for name in seen.hostnames:
        found |= lookup.holders('hostname', name)
    return found


def _contradicts(reported, stored):
    return any(stored.get(k) and v not in stored[k] for k, v in reported.items())


def _with_strong(seen, lookup):
    hits = set()
    for kind, value in seen.strong.items():
        hits |= lookup.holders(kind, value)
    if hits:
        agree = [a for a in hits if not _contradicts(seen.strong, lookup.strong_of(a))]
        if len(agree) == 1:
            return Resolution(MATCHED, agree[0], schema.HIGH, 'machine identifier')
        if agree:
            return Resolution(HELD, None, schema.LOW, 'machine identifier', [conflict('split_identity', agree, 'one machine identifier is held by several assets')])
        return Resolution(NEW_CONFLICTED, None, schema.MEDIUM, 'new record: identifiers disagree', [conflict('clone_or_reinstall', hits, 'some machine identifiers match and others differ: a cloned machine, or a reinstall')])
    named = _named(seen, lookup)
    provisional = [a for a in named if lookup.is_provisional(a)]
    settled = named - set(provisional)
    if settled:
        return Resolution(NEW_CONFLICTED, None, schema.MEDIUM, 'new record: name already in use', [conflict('duplicate_hostname', settled, 'a different machine reports a host name already held')])
    if len(provisional) == 1:
        return Resolution(ADOPTED, provisional[0], schema.MEDIUM, 'an unidentified record with this name took the machine identifier')
    if provisional:
        return Resolution(NEW_CONFLICTED, None, schema.MEDIUM, 'new record: several unidentified records hold this name', [conflict('ambiguous_hostname', provisional, 'several unidentified records share this name')])
    shared = set()
    for address in seen.macs:
        shared |= lookup.holders('mac', address)
    if shared:
        return Resolution(NEW_CONFLICTED, None, schema.MEDIUM, 'new record: a physical MAC is already held', [conflict('shared_mac', shared, 'a different machine reports a physical MAC already held')])
    return Resolution(NEW, None, schema.HIGH, 'new machine identifier')


def _by_name_and_mac(seen, lookup):
    named = _named(seen, lookup)
    by_mac = set()
    for address in seen.macs:
        by_mac |= lookup.holders('mac', address)
    both = named & by_mac
    if len(both) == 1:
        return Resolution(MATCHED, next(iter(both)), schema.MEDIUM, 'host name and physical MAC agree')
    if by_mac or len(named) > 1 or (named and not all(lookup.is_provisional(a) for a in named)):
        return Resolution(NEW_CONFLICTED, None, schema.LOW, 'new record: partial match', [conflict('partial_match', named | by_mac, 'a host name or MAC matches, and no machine identifier confirms it')])
    if named:
        return Resolution(ADOPTED, next(iter(named)), schema.LOW, 'host name only')
    return Resolution(NEW, None, schema.LOW, 'no machine identifier was reported')


def _by_name(seen, lookup):
    """Telemetry carries a name and nothing else, so it can attribute an event, and it can never join records."""
    named = _named(seen, lookup)
    if len(named) == 1:
        return Resolution(MATCHED, next(iter(named)), schema.MEDIUM, 'host name')
    if named:
        return Resolution(HELD, None, schema.LOW, 'host name', [conflict('ambiguous_hostname', named, 'several assets hold this name, so telemetry cannot be attributed')])
    return Resolution(NEW, None, schema.LOW, 'host name only')
