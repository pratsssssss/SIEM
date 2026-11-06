"""Stable status from raw assessments, and the pipeline view. Pure, so every path can be tested with a plain clock."""
from .assess import COMPONENTS, DEGRADED, HEALTHY, NOT_APPLICABLE, UNHEALTHY, UNKNOWN

RANK = {HEALTHY: 0, NOT_APPLICABLE: 0, UNKNOWN: 1, DEGRADED: 2, UNHEALTHY: 3}
# In pipeline order. A supporting stage can lower the overall state to DEGRADED, and no further.
STAGES = (('collection', ('windows-agent', 'linux-agent'), True), ('transport', ('kafka',), True), ('verification', ('verifier',), True), ('processing', ('aggregator', 'normalization'), True),
          ('storage', ('opensearch',), True), ('detection', ('detector',), True), ('correlation', ('correlator',), True), ('enrichment', ('enricher',), False), ('assets', ('assets',), False),
          ('attack paths', ('attack-paths',), False), ('host', ('host-wsl', 'housekeeping'), False))
KINDS = {name: (kind, platform) for name, kind, platform in COMPONENTS}


def kind_of(name):
    if name.startswith('source:'):
        return ('source', 'windows' if name.startswith('source:windows.') else 'wsl')
    return KINDS.get(name, ('other', 'wsl'))


def step(record, raw, now, config, recent_transitions=0, reset=False):
    """One cycle of hysteresis. Returns (new record, transition or None).

    Going worse needs fewer cycles than getting better, so a failure shows fast and a recovery must hold. Direct proof
    (`fast`) moves at once. `reset` follows a gap, because cycles either side of it are not consecutive.
    """
    settings = config['hysteresis']
    if record is None:
        fresh = {'status': raw['status'], 'previous': None, 'since_ms': now, 'pending': None, 'pending_count': 0, 'condition': raw['condition']}
        return fresh, {'from': None, 'to': raw['status'], 'first': True}
    record = dict(record)
    if reset:
        record['pending'], record['pending_count'] = None, 0
    if raw['status'] == record['status']:
        record['pending'], record['pending_count'] = None, 0
        record['condition'] = raw['condition']
        return record, None
    if raw['status'] != record['pending']:
        record['pending'], record['pending_count'] = raw['status'], 0
    record['pending_count'] += 1
    worse = RANK[raw['status']] > RANK[record['status']]
    needed = settings['worsen_cycles'] if worse else settings['improve_cycles']
    if not worse and recent_transitions >= settings['flap_transitions']:
        needed *= settings['flap_factor']
    if raw.get('fast') and worse:
        needed = 1
    if record['pending_count'] < needed:
        return record, None
    change = {'from': record['status'], 'to': raw['status'], 'first': False}
    record.update(previous=record['status'], status=raw['status'], since_ms=now, pending=None, pending_count=0, condition=raw['condition'])
    return record, change


def durability(record, now, config):
    """`transient` while a change is unconfirmed or young, and `persistent` after."""
    if record['pending'] or now - record['since_ms'] < config['hysteresis']['persist_after_seconds'] * 1000:
        return 'transient'
    return 'persistent'


def rollup(records, now, config, sampled_at=None):
    """The whole pipeline from stable records."""
    def status(name):
        row = records.get(name)
        return row['status'] if row else UNKNOWN

    stages, worst = [], HEALTHY
    bottleneck, cause = None, None
    for stage, members, core in STAGES:
        ranked = max((status(m) for m in members), key=lambda s: RANK[s])
        shown = ranked if any(status(m) != NOT_APPLICABLE for m in members) else NOT_APPLICABLE
        stages.append({'stage': stage, 'status': shown, 'components': list(members), 'core': core})
        effect = shown if core or shown not in (UNHEALTHY,) else DEGRADED
        if RANK[effect] > RANK[worst]:
            worst = effect
        for member in members:
            row = records.get(member)
            if row and row['status'] in (DEGRADED, UNHEALTHY):
                if bottleneck is None:
                    bottleneck = member
                if cause is None and row.get('condition') != 'downstream_unavailable':
                    cause = member
    cause = cause or bottleneck
    sources = {k: v for k, v in records.items() if k.startswith('source:')}
    fresh = sorted(k[7:] for k, v in sources.items() if v['status'] == HEALTHY)
    silent = sorted(k[7:] for k, v in sources.items() if v['status'] == UNKNOWN)
    broken = sorted(k[7:] for k, v in sources.items() if v['status'] in (DEGRADED, UNHEALTHY))
    overdue = sorted(k[7:] for k in silent for s in config['sources'] if s['dataset'] == k and s.get('quiet_minutes') is not None)
    chain = ('windows-agent', 'linux-agent', 'kafka', 'verifier', 'aggregator', 'normalization', 'opensearch', 'detector', 'correlator')
    gaps = [m for m in chain if status(m) in (DEGRADED, UNHEALTHY)]
    blind = [m for m in chain if status(m) == UNKNOWN]
    if gaps or broken:
        coverage, why = 'limited', 'Part of the path from collection to detection is degraded or down: ' + ', '.join(gaps + broken)
    elif overdue:
        coverage, why = 'limited', 'These usually busy sources have gone quiet, which cannot be told from a loss: ' + ', '.join(overdue)
    elif blind:
        coverage, why = 'unknown', 'These cannot be judged at present: ' + ', '.join(blind)
    else:
        coverage, why = 'trusted', 'Collection to detection is working and busy sources are fresh. Coverage is still limited to what the sources record'
    return {'status': worst, 'stages': stages, 'bottleneck': bottleneck, 'root_cause': cause, 'coverage': coverage, 'coverage_reason': why, 'sources_fresh': fresh, 'sources_quiet': silent,
            'sources_overdue': overdue, 'sources_unavailable': broken, 'observed_ms': now}
