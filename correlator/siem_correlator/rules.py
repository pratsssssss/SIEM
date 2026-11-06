"""Correlation rules, from rules/correlation/rules.yml. Only what a rule states links alerts.

A shared host alone never makes a sequence causal: a rule states which link it relies on, and that link
sets how much the incident can claim. See docs/detection/correlation-rules.md.
"""
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from . import entities as ent

KINDS = ('sequence', 'threshold', 'distinct', 'chain', 'single')
JOINS = ('host', 'user', 'user_name', 'source_ip', 'destination_ip', 'indicator', 'lineage')
# How much a link says about alerts being related. Lineage is proof. A host is only coincidence in time.
LINK_STRENGTH = {'lineage': 3, 'user': 2, 'indicator': 2, 'source_ip': 2, 'destination_ip': 2, 'user_name': 1, 'host': 1}


class RuleError(ValueError):
    pass


@dataclass
class Selector:
    rules: tuple = ()
    any_process: bool = False
    parent_names: tuple = ()
    min_facts: dict = field(default_factory=dict)
    signals: bool = False

    def matches(self, context):
        if context.get('kind') == 'signal' and not self.signals:
            return False
        if self.rules and context['rule_id'] not in self.rules:
            return False
        if self.any_process and not context.get('process_ids'):
            return False
        if self.parent_names and context.get('parent_name') not in self.parent_names:
            return False
        facts = context.get('facts') or {}
        return all(isinstance(facts.get(k), (int, float)) and facts[k] >= v for k, v in self.min_facts.items())


@dataclass
class Rule:
    id: str
    title: str
    description: str
    kind: str
    join: str
    window_seconds: int
    enabled: bool = True
    selectors: list = field(default_factory=list)
    min_alerts: int = 2
    min_distinct_rules: int = 1
    count: str = ''
    min_count: int = 2
    min_tactics: int = 3
    scenario: int = 0


def _selector(raw):
    return Selector(rules=tuple(raw.get('rules', ())), any_process=bool(raw.get('any_process')), parent_names=tuple(n.lower() for n in raw.get('parent_names', ())), min_facts=dict(raw.get('min_facts', {})), signals=bool(raw.get('signals')))


def load(path):
    data = yaml.safe_load(Path(path).read_text(encoding='utf8'))
    rules, seen = [], set()
    for raw in data['rules']:
        if raw['id'] in seen:
            raise RuleError(f"{raw['id']}: listed twice")
        seen.add(raw['id'])
        if raw['kind'] not in KINDS:
            raise RuleError(f"{raw['id']}: unknown kind {raw['kind']}")
        if raw['join'] not in JOINS:
            raise RuleError(f"{raw['id']}: unknown join {raw['join']}")
        if not 60 <= int(raw['window_seconds']) <= 86400:
            raise RuleError(f"{raw['id']}: window_seconds must be from 60 to 86400")
        stages = [_selector(s) for s in raw.get('stages', [raw.get('select', {})])]
        if raw['kind'] == 'sequence' and len(stages) < 2:
            raise RuleError(f"{raw['id']}: a sequence needs two stages")
        rules.append(Rule(id=raw['id'], title=raw['title'], description=raw['description'], kind=raw['kind'], join=raw['join'], window_seconds=int(raw['window_seconds']), enabled=bool(raw.get('enabled', True)),
                          selectors=stages, min_alerts=int(raw.get('min_alerts', 2)), min_distinct_rules=int(raw.get('min_distinct_rules', 1)), count=raw.get('count', ''), min_count=int(raw.get('min_count', 2)),
                          min_tactics=int(raw.get('min_tactics', 3)), scenario=int(raw.get('scenario', 0))))
    return rules


def join_entities(rule, context):
    """The entity IDs this rule may join on, for one alert. Weak entities never link anything."""
    items = context['entities']
    usable = [e for e in items if e['quality'] != 'weak']
    if rule.join == 'host':
        return [e['id'] for e in usable if e['kind'] == ent.HOST]
    if rule.join == 'user':
        return [e['id'] for e in usable if e['kind'] == ent.USER and e['quality'] == 'strong']
    if rule.join == 'user_name':
        return [f"username:{e['loose']}" for e in usable if e['kind'] == ent.USER and e.get('loose')]
    if rule.join in ('source_ip', 'destination_ip'):
        return [e['id'] for e in items if e['kind'] == ent.IP and e['id'] in context.get(rule.join + 's', [])]
    if rule.join == 'indicator':
        return [e['id'] for e in usable if e['kind'] == ent.INDICATOR and e.get('note') in ('malicious', 'suspicious', 'conflicting')]
    return []
