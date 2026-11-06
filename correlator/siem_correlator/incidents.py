"""Incidents: creation, growth, scoring, lifecycle and the record of each change.

Evidence is only ever added. The system opens incidents. Only a person moves one to contained, resolved,
closed or false positive, and no action is taken on any host.
"""
import hashlib
from . import rules as rule_lib
from .schema import SEVERITIES, iso

NEW, OPEN, INVESTIGATING, CONTAINED, RESOLVED, CLOSED, FALSE_POSITIVE = 'new', 'open', 'investigating', 'contained', 'resolved', 'closed', 'false_positive'
STATES = (NEW, OPEN, INVESTIGATING, CONTAINED, RESOLVED, CLOSED, FALSE_POSITIVE)
FINISHED = (RESOLVED, CLOSED, FALSE_POSITIVE)
MOVES = {
    NEW: (OPEN, INVESTIGATING, FALSE_POSITIVE),
    OPEN: (INVESTIGATING, CONTAINED, RESOLVED, FALSE_POSITIVE),
    INVESTIGATING: (CONTAINED, RESOLVED, FALSE_POSITIVE, OPEN),
    CONTAINED: (RESOLVED, INVESTIGATING),
    RESOLVED: (CLOSED, OPEN),
    CLOSED: (OPEN,),
    FALSE_POSITIVE: (OPEN,),
}
NEEDS_NOTE = (FALSE_POSITIVE, CLOSED, RESOLVED)
MAX_NOTE = 2000
TIMELINE_LIMIT = 500
CORRELATION_LIMIT = 100
CONTEXTS_PER_RULE = 25
CONFIDENCE_BANDS = ((70, 'high'), (40, 'medium'), (0, 'low'))
LINK_POINTS = {3: 45, 2: 30, 1: 15}
LINK_WORDS = {3: 'recorded process lineage', 2: 'a shared identity or indicator', 1: 'a shared host or name, and timing alone'}


class ActionError(ValueError):
    pass


def independent_rules(contexts):
    """How many groups of rules saw different things. Repeats of one rule, and rules that fired on one
    event, are copies of one observation and count once."""
    groups = []
    for rule_id in {c['rule_id'] for c in contexts}:
        events = {e for c in contexts if c['rule_id'] == rule_id for e in c.get('event_ids', [])}
        overlapping = [g for g in groups if g & events]
        groups = [g for g in groups if not g & events] + [events.union(*overlapping) | {f'rule:{rule_id}'}]
    return len(groups)


def score(incident, contexts):
    """Severity and confidence, with each step named. Repeats of one rule count once."""
    rules_seen = range(independent_rules(contexts))
    levels = [SEVERITIES.index(c['severity']) for c in contexts]
    base = max(levels)
    reasons = [f'Severity starts at {SEVERITIES[base]}, the highest of the alerts held']
    # The weakest link decides. One proven parent and child says nothing about the rest of the incident.
    strengths = [rule_lib.LINK_STRENGTH[j] for j in incident['_joins']]
    link = min(strengths)
    hostile = [v for c in contexts for v in c.get('hostile', [])]
    malicious = [i for i in hostile if i['verdict'] == 'malicious']
    conflicting = [i for i in hostile if i['verdict'] == 'conflicting']
    level = base
    if len(rules_seen) >= 3 and link >= 2:
        level += 1
        reasons.append(f'Raised one step: {len(rules_seen)} independent rules joined by {LINK_WORDS[link]}')
    if malicious and link >= 2 and level == base:
        level += 1
        reasons.append(f'Raised one step: {len(malicious)} indicators have a malicious verdict')
    level = min(level, len(SEVERITIES) - 1)
    if link == 1:
        level = min(level, max(base, SEVERITIES.index('medium')))

    confidence = LINK_POINTS[link]
    parts = [f'{LINK_POINTS[link]} for {LINK_WORDS[link]}']
    if max(strengths) > link:
        confidence += 5
        parts.append(f'5 because part of it has {LINK_WORDS[max(strengths)]}')
    extra = min((len(rules_seen) - 1) * 10, 20)
    if extra:
        confidence += extra
        parts.append(f'{extra} for {len(rules_seen)} independent rules')
    if len(contexts) > len(rules_seen):
        parts.append(f'0 for {len(contexts) - len(rules_seen)} repeats of the same rules, which are not independent')
    if malicious:
        confidence += 15
        parts.append('15 for a malicious indicator')
    uncertain = list(incident['uncertain'])
    for condition, points, text in (
            (conflicting, 15, 'threat intelligence conflicts'),
            (any(c.get('events_missing') for c in contexts), 10, 'some source events are gone'),
            (any(c.get('enrichment') not in ('complete', 'no_indicators') for c in contexts if c.get('kind') == 'alert'), 5, 'enrichment is incomplete'),
            (any('order is not proven' in u for u in uncertain), 10, 'the order is not proven'),
            # A name link already scored as weak. Deducting again would count one doubt twice.
            (link > 1 and any('name only' in u for u in uncertain), 10, 'identity is uncertain')):
        if condition:
            confidence -= points
            parts.append(f'minus {points}: {text}')
    confidence = max(min(confidence, 95), 5)
    band = next(name for floor, name in CONFIDENCE_BANDS if confidence >= floor)
    return SEVERITIES[level], confidence, band, reasons, parts


def _sorted_unique(values):
    return sorted({v for v in values if v})


class Manager:
    def __init__(self, store, merge_window_seconds=3600, clock=None):
        self.store = store
        self.merge = merge_window_seconds * 1000
        self.clock = clock

    def _find(self, match):
        """An incident this match belongs to, or None. Finished incidents are left alone."""
        ids = [m['alert_id'] for m in match.alerts]
        for incident_id in self.store.incidents_of(ids):
            found = self.store.incident(incident_id)
            if found['status'] not in FINISHED:
                return found
        for incident_id in self.store.key_incidents(match.rule.id, match.entity):
            found = self.store.incident(incident_id)
            # Alerts can arrive in any order, so the gap is measured in both directions of time.
            gap = max(min(m['first_ms'] for m in match.alerts) - found['last_ms'], found['first_ms'] - max(m['last_ms'] for m in match.alerts))
            if found['status'] not in FINISHED and gap <= self.merge:
                return found
        return None

    def _covered(self, match):
        """True if a finished incident already holds every alert here, so a replay cannot reopen it."""
        ids = {m['alert_id'] for m in match.alerts}
        for incident_id in self.store.incidents_of(sorted(ids)):
            found = self.store.incident(incident_id)
            if found['status'] in FINISHED and ids <= set(found['alert_ids'] + found.get('signal_ids', [])):
                return True
        return False

    def _held(self, match):
        held = set()
        for incident_id in self.store.incidents_of(sorted(m['alert_id'] for m in match.alerts)):
            found = self.store.incident(incident_id)
            held |= set(found['alert_ids'] + found.get('signal_ids', []))
        return held

    def apply(self, match, now):
        """Creates or grows an incident, inside the caller's transaction. Returns its ID, or None if nothing changed."""
        incident = self._find(match)
        if incident is None:
            if self._covered(match):
                return None
            first = min(match.alerts, key=lambda m: (m['first_ms'], m['alert_id']))
            held = self._held(match)
            newest = [m for m in match.alerts if m['alert_id'] not in held]
            seed = min(newest or match.alerts, key=lambda m: (m['first_ms'], m['alert_id']))
            incident_id = hashlib.sha256(f"{match.rule.id}|{match.entity}|{seed['alert_id']}".encode()).hexdigest()[:32]
            # A finished incident is evidence. Whatever happens next, it is never replaced.
            if self.store.incident(incident_id) is not None:
                return None
            incident = {
                'schema_version': 1, 'incident_id': incident_id, 'title': match.rule.title, 'description': match.rule.description, 'status': NEW, 'revision': 0,
                'created_ms': now, 'updated_ms': now, 'first_ms': first['first_ms'], 'last_ms': first['last_ms'], 'alert_ids': [], 'signal_ids': [], 'rules': [], 'timeline': [], 'notes': [],
                'correlations': [], 'uncertain': [], '_joins': [], '_contexts': {},
            }
            self.store.audit(incident_id, now, 'system', 'created', {'rule': match.rule.id, 'entity': match.entity})
        before = set(incident['alert_ids'] + incident['signal_ids'])
        fresh = [m for m in match.alerts if m['alert_id'] not in before]
        known_rule = match.rule.id in [r['id'] for r in incident['rules']]
        if not fresh and known_rule:
            return None
        if not known_rule:
            incident['rules'].append({'id': match.rule.id, 'title': match.rule.title, 'join': match.rule.join})
            incident['_joins'].append(match.rule.join)
        # Every alert stays listed. Past the limits, the count says how many steps are not spelled out.
        if len(incident['correlations']) < CORRELATION_LIMIT:
            incident['correlations'].append({'rule': match.rule.id, 'join': match.rule.join, 'entity': match.entity, 'reason': match.reason, 'sequence': match.sequence, 'at': iso(now)})
        else:
            incident['correlations_omitted'] = incident.get('correlations_omitted', 0) + 1
        for member in fresh:
            (incident['signal_ids'] if member.get('kind') == 'signal' else incident['alert_ids']).append(member['alert_id'])
            # Repeats of one rule add nothing to the score, so memory stops growing with them.
            if sum(c['rule_id'] == member['rule_id'] for c in incident['_contexts'].values()) < CONTEXTS_PER_RULE:
                incident['_contexts'][member['alert_id']] = member
            if len(incident['timeline']) < TIMELINE_LIMIT:
                incident['timeline'].append({'at': member['first_iso'], 'ms': member['first_ms'], 'alert_id': member['alert_id'], 'rule': member['rule_name'], 'severity': member['severity'], 'host': member.get('host'), 'user': member.get('user')})
            else:
                incident['timeline_omitted'] = incident.get('timeline_omitted', 0) + 1
        incident['timeline'].sort(key=lambda t: (t['ms'], t['alert_id']))
        incident['uncertain'] = _sorted_unique([*incident['uncertain'], *match.uncertain, *(n for m in fresh for n in m.get('notes', []))])
        self.refresh(incident, now)
        self.store.add_key(match.rule.id, match.entity, incident['incident_id'])
        self.store.save_incident(incident)
        self.store.audit(incident['incident_id'], now, 'system', 'updated', {'revision': incident['revision'], 'rule': match.rule.id, 'alerts_added': [m['alert_id'] for m in fresh], 'severity': incident['severity'], 'confidence': incident['confidence']})
        return incident['incident_id']

    def refresh(self, incident, now):
        """Recomputes everything derived, from the contexts held. Nothing is removed."""
        contexts = list(incident['_contexts'].values())
        incident['first_ms'] = min(c['first_ms'] for c in contexts)
        incident['last_ms'] = max(c['last_ms'] for c in contexts)
        incident['first_seen'], incident['last_seen'] = iso(incident['first_ms']), iso(incident['last_ms'])
        incident['created_at'], incident['updated_at'] = iso(incident['created_ms']), iso(now)
        incident['updated_ms'] = now
        incident['revision'] += 1

        def values(kind, field='display'):
            return _sorted_unique(e[field] for c in contexts for e in c['entities'] if e['kind'] == kind)
        incident['hosts'], incident['users'], incident['ips'], incident['domains'] = values('host'), values('user'), values('ip'), values('domain')
        incident['processes'] = _sorted_unique(c.get('process_name') for c in contexts)
        incident['file_hashes'] = values('hash')
        incident['entity_ids'] = _sorted_unique(e['id'] for c in contexts for e in c['entities'] if e['kind'] not in ('alert', 'rule'))
        incident['source_event_ids'] = _sorted_unique(i for c in contexts for i in c.get('event_ids', []))
        incident['raw_event_refs'] = _sorted_unique(i for c in contexts for i in c.get('event_refs', []))
        incident['alert_refs'] = _sorted_unique(c.get('evidence_ref') for c in contexts)
        incident['enrichment_refs'] = _sorted_unique(c.get('enrichment_ref') for c in contexts)
        incident['indicators'] = [dict(i) for i in {(i['type'], i['value']): i for c in contexts for i in c.get('hostile', [])}.values()]
        severity, confidence, band, severity_reasons, confidence_parts = score(incident, contexts)
        incident['severity'], incident['confidence'], incident['confidence_level'] = severity, confidence, band
        incident['explanation'] = {
            'why_grouped': [c['reason'] for c in incident['correlations']],
            'connected_by': sorted({c['entity'] for c in incident['correlations']}),
            'rules_matched': [r['title'] for r in incident['rules']],
            'sequence': next((c['sequence'] for c in reversed(incident['correlations']) if c['sequence']), []),
            'evidence': f"{len(incident['alert_ids'])} alerts, {len(incident['signal_ids'])} intelligence matches, {len(incident['raw_event_refs'])} source events",
            'uncertain': incident['uncertain'], 'severity_reasons': severity_reasons, 'confidence_reasons': confidence_parts,
        }

    def transition(self, incident_id, target, actor, note, now):
        # Read and write under one lock: the correlation loop may be growing this incident now.
        with self.store.lock, self.store.db:
            incident = self._get(incident_id)
            if target not in STATES:
                raise ActionError(f'unknown state {target}')
            if target not in MOVES[incident['status']]:
                raise ActionError(f"{incident['status']} cannot move to {target}")
            if target in NEEDS_NOTE and not (note or '').strip():
                raise ActionError(f'{target} needs a note saying why')
            before = incident['status']
            incident['status'] = target
            self._note(incident, actor, note, now)
            incident['updated_ms'], incident['updated_at'] = now, iso(now)
            incident['revision'] += 1
            self.store.save_incident(incident)
            self.store.audit(incident_id, now, actor, 'status', {'from': before, 'to': target, 'note': note or ''})
        return incident

    def add_note(self, incident_id, actor, note, now):
        with self.store.lock, self.store.db:
            incident = self._get(incident_id)
            if not (note or '').strip():
                raise ActionError('the note is empty')
            self._note(incident, actor, note, now)
            incident['updated_ms'], incident['updated_at'] = now, iso(now)
            incident['revision'] += 1
            self.store.save_incident(incident)
            self.store.audit(incident_id, now, actor, 'note', {'note': note})
        return incident

    def _note(self, incident, actor, note, now):
        if note and note.strip():
            if len(note) > MAX_NOTE:
                raise ActionError(f'the note is over {MAX_NOTE} characters')
            incident['notes'].append({'at': iso(now), 'by': actor, 'text': note})

    def _get(self, incident_id):
        incident = self.store.incident(incident_id)
        if incident is None:
            raise ActionError('no such incident')
        return incident


def public(incident):
    """The stored form, without working data."""
    return {k: v for k, v in incident.items() if not k.startswith('_') and k not in ('first_ms', 'last_ms', 'created_ms', 'updated_ms')}
