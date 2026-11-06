"""The graph model: what a node, an edge and a piece of evidence are. See docs/detection/attack-paths.md.

Everything read from events is untrusted, so it is checked, cut to size and cleaned here. No value becomes a
query string, a file path or a command. Node and edge IDs are digests of what they mean, so rebuilding a path
gives the same graph.
"""
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

SCHEMA_VERSION = 1

# How an edge is known. Kept apart everywhere, so an interpretation is never shown as an observation.
OBSERVED, DETECTION, CORRELATION, ASSET, INTEL, ANALYST, INFERRED = 'observed', 'detection', 'correlation', 'asset', 'threat_intelligence', 'analyst', 'inferred'
# Evidence tiers, strongest first. These describe evidence, and none of them means compromise.
CONFIRMED, STRONG, PLAUSIBLE, WEAK, INSUFFICIENT = 'confirmed_observation', 'strongly_supported', 'plausible_inferred', 'weak_hypothesis', 'insufficient_evidence'
TIERS = (CONFIRMED, STRONG, PLAUSIBLE, WEAK, INSUFFICIENT)

NODE_TYPES = ('asset', 'identity', 'process', 'service', 'ip', 'domain', 'alert', 'incident', 'group', 'package', 'indicator', 'task')
EDGE_TYPES = ('authenticated_to', 'failed_authentication_to', 'access_attempt_from', 'remote_access_from', 'executed', 'spawned', 'communicated_with', 'escalated_privileges', 'created', 'added_to_group', 'installed', 'scheduled',
              'failed_on', 'detected_on', 'triggered', 'correlated_with', 'associated_with', 'same_identity')

_EVENT_REF = re.compile(r'^(siem-(?:windows|linux)-\d{4}\.\d{2}\.\d{2})/([A-Za-z0-9_-]{8,128})$')
_ALERT_ID = re.compile(r'^[0-9a-f]{32}$')
_UNSAFE = re.compile('[\x00-\x1f\x7f-\x9f​-‏‪-‮⁠-⁩﻿]')
_SID = re.compile(r'^S-1-\d+(-\d+)+$')
_SECRET = re.compile(r'(?i)\b(pass(word|wd|phrase)?|pwd|secret|token|api[_-]?key|credential)\s*[=:]\s*\S+')
EMPTY_SIDS = {'S-1-0-0', 'S-1-5-7', 'S-1-5-18', 'S-1-5-19', 'S-1-5-20'}
SERVICE_NAMES = {'system', 'local service', 'network service', 'anonymous logon', '-', ''}
SERVICE_REALMS = {'nt authority', 'nt service', 'window manager', 'font driver host'}


def ms(text):
    moment = datetime.fromisoformat(str(text).replace('Z', '+00:00'))
    return int(moment.replace(tzinfo=moment.tzinfo or timezone.utc).timestamp() * 1000)


def iso(value):
    return datetime.fromtimestamp(value / 1000, timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'


def clean(value, limit=200):
    """Text fit to store and print. A value is data here, and nothing reads it as an instruction."""
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return ''
    return _SECRET.sub('[REDACTED]', _UNSAFE.sub('', str(value))).strip()[:limit]


def digest(*parts):
    return hashlib.sha256('|'.join(str(p) for p in parts).encode()).hexdigest()[:32]


def event_ref(text):
    """(index, id), or None. A reference can point at event indices only, so a forged one reads nothing else."""
    match = _EVENT_REF.fullmatch(str(text))
    return (match.group(1), match.group(2)) if match else None


def valid_id(text):
    return bool(_ALERT_ID.fullmatch(str(text)))


@dataclass(frozen=True)
class Identity:
    """An account in its own namespace. The same name on two platforms is two identities, unless a person says otherwise."""
    id: str
    display: str
    # strong: names one account. local: one account on one host. ambiguous: a bare name.
    # shared and weak link nothing: root is every administrator, and a service account is nobody.
    quality: str
    sid: str = ''

    @property
    def links(self):
        return self.quality not in ('weak', 'shared')


def windows_identity(name, realm=None, sid=None):
    bare = clean(name, 120)
    realm = clean(realm, 80)
    if '\\' in bare and not realm:
        realm, bare = bare.split('\\', 1)
    low, area = bare.lower(), realm.lower()
    if not low:
        return None
    if low in SERVICE_NAMES or area in SERVICE_REALMS or low.endswith('$') or (sid and str(sid) in EMPTY_SIDS and sid != 'S-1-0-0'):
        return Identity(f'identity:windows:service:{low}', bare, 'weak')
    usable = str(sid) if sid and _SID.fullmatch(str(sid)) and str(sid) not in EMPTY_SIDS else ''
    if area and area not in ('-', '.'):
        return Identity(f'identity:windows:{area}\\{low}', f'{area}\\{low}', 'strong', usable)
    return Identity(f'identity:windows:unqualified:{low}', low, 'ambiguous', usable)


def linux_identity(name, host):
    """A Linux account means something only on its own host."""
    bare, machine = clean(name, 100), clean(host, 120).lower()
    if not bare or bare == '-':
        return None
    return Identity(f'identity:linux:{machine}:{bare.lower()}', f'{machine}\\{bare}', 'shared' if bare.lower() == 'root' else 'local')


@dataclass
class Evidence:
    kind: str  # event, alert, enrichment, incident, asset
    ref_id: str
    index: str
    source_time: str
    ingest_time: str = None
    host: str = None
    asset_id: str = None
    sensor: str = None
    fields: dict = field(default_factory=dict)
    provenance: str = ''
    state: str = 'verified'

    def as_dict(self):
        body = json.dumps(self.fields, sort_keys=True)
        return {'kind': self.kind, 'id': self.ref_id, 'index': self.index, 'source_time': self.source_time, 'ingest_time': self.ingest_time, 'host': self.host, 'asset_id': self.asset_id, 'sensor': self.sensor, 'fields': self.fields, 'provenance': self.provenance, 'state': self.state, 'digest': hashlib.sha256(body.encode()).hexdigest()[:32]}


class Graph:
    """One path's nodes and edges, with hard limits. Past a limit nothing is added, and the path says so."""

    def __init__(self, max_nodes=200, max_edges=400):
        self.nodes, self.edges = {}, {}
        self.max_nodes, self.max_edges = max_nodes, max_edges
        self.cut = 0

    def node(self, kind, key, display=None, **attributes):
        node_id = f'{kind}:{digest(kind, key)}'
        if node_id not in self.nodes:
            if len(self.nodes) >= self.max_nodes:
                self.cut += 1
                return None
            self.nodes[node_id] = {'id': node_id, 'type': kind, 'key': clean(key, 256), 'display': clean(display if display is not None else key, 200), **attributes}
        else:
            self.nodes[node_id].update({k: v for k, v in attributes.items() if v not in (None, '', [])})
        return node_id

    def edge(self, source, kind, target, klass, basis, tier, evidence, reason, supporting=(), contradicting=()):
        """Refuses an edge with nothing behind it: that is the rule the whole model rests on."""
        if source is None or target is None:
            return None
        records = [e for e in evidence if e]
        if not records:
            return None
        edge_id = digest(source, kind, target)
        times = [ms(e.source_time) for e in records if e.source_time]
        if edge_id in self.edges:
            found = self.edges[edge_id]
            seen = {e['id'] for e in found['evidence']}
            found['evidence'] += [e.as_dict() for e in records if e.ref_id not in seen]
            if times:
                found['first_ms'] = min(found['first_ms'], min(times))
                found['last_ms'] = max(found['last_ms'], max(times))
            if TIERS.index(tier) > TIERS.index(found['tier']):
                found['tier'] = tier
            found['contradicting'] = sorted({*found['contradicting'], *contradicting})
            return edge_id
        if len(self.edges) >= self.max_edges:
            self.cut += 1
            return None
        first, last = (min(times), max(times)) if times else (0, 0)
        self.edges[edge_id] = {'id': edge_id, 'source': source, 'type': kind, 'target': target, 'first_ms': first, 'last_ms': last, 'class': klass, 'basis': basis, 'tier': tier, 'reason': clean(reason, 300), 'supporting': sorted(set(supporting)), 'contradicting': sorted(set(contradicting)), 'evidence': [e.as_dict() for e in records]}
        return edge_id
