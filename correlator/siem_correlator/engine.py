"""Evaluates rules. Each new alert is tested against what is stored on its entities, in both directions
of time, so an alert that arrives late still completes a sequence that began before or after it.
"""
from dataclasses import dataclass, field

from . import rules as rule_lib


@dataclass
class Match:
    rule: rule_lib.Rule
    entity: str
    alerts: list
    reason: str
    sequence: list = field(default_factory=list)
    uncertain: list = field(default_factory=list)


def _span(rule, context):
    margin = rule.window_seconds * 1000
    return context['first_ms'] - margin, context['last_ms'] + margin


class Engine:
    def __init__(self, store, rules, skew_seconds=120):
        self.store = store
        self.rules = rules
        self.skew = skew_seconds * 1000

    def evaluate(self, context):
        """All matches that involve this alert."""
        found = []
        for rule in self.rules:
            if not self.store.rule_enabled(rule.id, rule.enabled):
                continue
            if rule.join == 'lineage':
                found += self._lineage(rule, context)
                continue
            for entity in rule_lib.join_entities(rule, context):
                found += self._on_entity(rule, entity, context)
        return found

    def _candidates(self, rule, entity, context):
        start, end = _span(rule, context)
        ids = self.store.near(entity, start, end)
        contexts = self.store.contexts(ids)
        return [contexts[i] for i in ids if i in contexts]

    def _user_note(self, rule, members):
        if rule.join != 'user_name':
            return []
        ids = {e['id'] for m in members for e in m['entities'] if e['kind'] == 'user' and e['quality'] != 'weak'}
        return [f'the accounts match by name only, across {len(ids)} forms of identity, so they may not be one account'] if len(ids) > 1 else []

    def _on_entity(self, rule, entity, context):
        members = self._candidates(rule, entity, context)
        return getattr(self, f'_{rule.kind}')(rule, entity, context, members)

    def _ordered(self, rule, earlier, later):
        """(in order, within window, uncertain). Timestamps inside the skew cannot prove which came first."""
        gap = later['first_ms'] - earlier['last_ms']
        if later['first_ms'] > earlier['first_ms'] + rule.window_seconds * 1000:
            return False, False
        if gap < -self.skew:
            return False, False
        # One host has one clock, so skew only makes the order doubtful between hosts. On one clock an
        # alert may span the alert before it, as a logon after failures spans the failures, and still end later.
        same_clock = bool(earlier.get('host')) and str(earlier.get('host')).lower() == str(later.get('host')).lower()
        return True, gap < 0 and later['last_ms'] <= earlier['last_ms'] if same_clock else gap < self.skew

    def _sequence(self, rule, entity, context, members):
        stages = [[m for m in members if s.matches(m)] for s in rule.selectors]
        if not all(stages) or not any(context['alert_id'] == m['alert_id'] for stage in stages for m in stage):
            return []
        found = []
        # Latest first: the nearest earlier stage is the better pairing, and it avoids reaching back into old activity.
        for first in reversed(stages[0]):
            chain, uncertain, current = [first], [], first
            for stage in stages[1:]:
                options = []
                for item in stage:
                    if item['alert_id'] == current['alert_id']:
                        continue
                    ordered, close = self._ordered(rule, current, item)
                    if ordered:
                        options.append((item['first_ms'], item['alert_id'], item, close))
                if not options:
                    chain = None
                    break
                # The alert being evaluated goes first, so a later repeat joins the incident too.
                _, _, chosen, close = min(options, key=lambda o: (o[2]['alert_id'] != context['alert_id'], *o[:2]))
                if close:
                    uncertain.append(f"{current['rule_name']} and {chosen['rule_name']} are within the clock skew allowance, so their order is not proven")
                chain.append(chosen)
                current = chosen
            if chain and any(m['alert_id'] == context['alert_id'] for m in chain):
                uncertain += self._user_note(rule, chain)
                steps = [f"{m['rule_name']} at {m['first_iso']}" for m in chain]
                # The last stage may have repeats that arrived before the first stage did. They belong here too.
                held = {m['alert_id'] for m in chain}
                repeats = [m for m in stages[-1] if m['alert_id'] not in held and self._ordered(rule, chain[-2], m)[0]]
                found.append(Match(rule, entity, chain + repeats, f"Sequence on {entity}: {' then '.join(steps)}", sequence=steps, uncertain=uncertain))
        return found[:1]

    def _threshold(self, rule, entity, context, members):
        chosen = [m for m in members if any(s.matches(m) for s in rule.selectors)]
        names = {m['rule_id'] for m in chosen}
        if len(chosen) < rule.min_alerts or len(names) < rule.min_distinct_rules or not any(m['alert_id'] == context['alert_id'] for m in chosen):
            return []
        return [Match(rule, entity, chosen, f'{len(chosen)} alerts from {len(names)} rules share {entity}, within {rule.window_seconds} s', uncertain=self._user_note(rule, chosen))]

    def _distinct(self, rule, entity, context, members):
        def counted(member):
            found = {e['id'] for e in member['entities'] if e['kind'] == rule.count and e['quality'] == 'strong' and (rule.count != 'indicator' or e.get('note') in ('malicious', 'suspicious', 'conflicting'))}
            return {v for v in found if v.startswith('indicator:domain:')} if rule.count == 'indicator' else found
        # Only alerts that add a counted value belong. On a host join, the rest are merely on the same machine.
        chosen = [m for m in members if any(s.matches(m) for s in rule.selectors) and counted(m)]
        values = {v for m in chosen for v in counted(m)}
        if len(values) < rule.min_count or not any(m['alert_id'] == context['alert_id'] for m in chosen):
            return []
        return [Match(rule, entity, chosen, f'{len(values)} different {rule.count} values on {entity}, within {rule.window_seconds} s', uncertain=self._user_note(rule, chosen))]

    def _chain(self, rule, entity, context, members):
        chosen = sorted((m for m in members if any(s.matches(m) for s in rule.selectors)), key=lambda m: (m['first_ms'], m['alert_id']))
        tactics, kept, seen = [], [], set()
        for member in chosen:
            new = [t for t in member['tactics'] if t not in tactics]
            events = set(member.get('event_ids', []))
            # Two rules on one event are one observation, not two stages.
            if new and not events & seen:
                tactics += new
                kept.append(member)
                seen |= events
        names = {m['rule_id'] for m in kept}
        if len(tactics) < rule.min_tactics or len(names) < rule.min_tactics or not any(m['alert_id'] == context['alert_id'] for m in chosen):
            return []
        steps = [f"{m['rule_name']} at {m['first_iso']}" for m in kept]
        return [Match(rule, entity, chosen, f"{len(tactics)} ATT&CK tactics from {len(names)} rules on {entity}: {', '.join(tactics)}", sequence=steps, uncertain=self._user_note(rule, chosen))]

    def _single(self, rule, entity, context, members):
        if not rule.selectors[0].matches(context):
            return []
        return [Match(rule, entity, [context], f"{context['rule_name']} on {entity} is significant alone")]

    def _lineage(self, rule, context):
        """An alert on a process, then an alert on a process it started. This is recorded fact, not timing."""
        found = []
        first, second = rule.selectors[0], rule.selectors[1]
        parents = context.get('parent_ids', [])
        own = context.get('process_ids', [])
        pairs = []
        if second.matches(context):
            for parent in parents:
                pairs += [(self._alerts_on(rule, parent, context), context, parent)]
        if first.matches(context):
            for process in own:
                for child in self.store.children(process):
                    pairs += [([context], self._alerts_on(rule, child, context), process)]
        for earlier, later, process in pairs:
            earlier = [earlier] if isinstance(earlier, dict) else earlier
            later = [later] if isinstance(later, dict) else later
            for a in earlier:
                for b in later:
                    if a['alert_id'] != b['alert_id'] and first.matches(a) and second.matches(b):
                        found.append(Match(rule, process, [a, b], f"{a['rule_name']} on a process that started the process in {b['rule_name']}. Sysmon recorded the parent and child identifiers",
                                           sequence=[f"{a['rule_name']} at {a['first_iso']}", f"{b['rule_name']} at {b['first_iso']}"]))
        return found[:1]

    def _alerts_on(self, rule, process, context):
        start, end = _span(rule, context)
        ids = self.store.near(process, start, end)
        contexts = self.store.contexts(ids)
        return [contexts[i] for i in ids if i in contexts]
