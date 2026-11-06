"""Reconstruction. Given a seed and its evidence, builds one graph and one explanation. Pure code: it reads no
store, so each rule can be tested, and two runs on the same evidence give the same path. See ADR-0015.

Three rules hold throughout:
  An edge needs evidence, and an event can link to a path only through the same identity on the same asset.
  Time alone never joins anything: it can only order what identity has already joined.
  A tier describes evidence. No tier means compromise, and the engine never concludes that.
"""
import ipaddress
import re
from dataclasses import dataclass, field

from . import model
from .evidence import fact_evidence, to_fact
from .model import ANALYST, CONFIRMED, CORRELATION, DETECTION, INFERRED, INSUFFICIENT, INTEL, OBSERVED, PLAUSIBLE, STRONG, TIERS, WEAK, Evidence, Graph, clean, iso, ms

# Exact identifiers, and only for what the evidence itself shows. A technique an alert names comes from the alert.
TECHNIQUES = {'T1110': 'Brute Force', 'T1136.001': 'Create Account: Local Account', 'T1078.003': 'Valid Accounts: Local Accounts', 'T1098': 'Account Manipulation', 'T1548.003': 'Abuse Elevation Control Mechanism: Sudo and Sudo Caching', 'T1543.003': 'Create or Modify System Process: Windows Service',
              'T1053.005': 'Scheduled Task/Job: Scheduled Task', 'T1053.003': 'Scheduled Task/Job: Cron', 'T1562.001': 'Impair Defenses: Disable or Modify Tools', 'T1562.002': 'Impair Defenses: Disable Windows Event Logging', 'T1021.001': 'Remote Services: Remote Desktop Protocol', 'T1021.004': 'Remote Services: SSH'}
_TECHNIQUE = re.compile(r'^T\d{4}(\.\d{3})?$')
PRIVILEGED_GROUPS = {'sudo', 'adm', 'root', 'shadow', 'disk', 'administrators', 'remote desktop users', 'siem-asset-admin', 'siem-analyst'}
FAILURES_BEFORE_SUCCESS = 3
NETWORK_LOGONS = {'3', '10'}
GAPS = {'linux_process_execution': 'Linux process execution is not collected (D15, deferred), so nothing shows what ran on this host beyond sudo, cron and services, and no Linux parent and child process link can exist',
        'linux_ssh': 'No SSH server is installed on the Linux host, so remote logon to it cannot be observed',
        'linux_firewall': 'No firewall telemetry exists on the Linux host',
        'linux_network': 'Linux network connections are not collected, so traffic from this host cannot be followed',
        'source_not_observed': 'The activity reached a monitored host from an address with no telemetry, so what happened at the source is unknown',
        'asset_unknown': 'A host in this path has no record in the asset inventory',
        'asset_context_unavailable': 'The asset inventory could not be reached, so addresses were left unresolved',
        'evidence_missing': 'Some source events are no longer stored, or their references were refused',
        'graph_truncated': 'A size limit was reached, so this path is incomplete',
        'query_limited': 'A query limit was reached, so some alerts or nearby events were not read'}


@dataclass
class Seed:
    kind: str  # incident or alert
    id: str
    title: str
    status: str = 'new'
    severity: str = ''
    alerts: list = field(default_factory=list)
    incident: dict = None
    events: dict = field(default_factory=dict)
    missing: list = field(default_factory=list)
    context: list = field(default_factory=list)
    intelligence: list = field(default_factory=list)
    identity_links: list = field(default_factory=list)
    limited: bool = False


class Assets:
    """Answers from Phase 14 only. A name is resolved by the inventory's own aliases, and never guessed here."""

    def __init__(self, records=(), ip_lookup=None, available=True):
        self.records = {r['asset_id']: r for r in records}
        self.ip_lookup = ip_lookup
        self.available = available

    def by_host(self, name):
        held = [r for r in self.records.values() if name in (r.get('aliases') or []) and r.get('status') != 'merged']
        return held[0] if len(held) == 1 else None, len(held)

    def by_ip(self, address, at_ms):
        if not self.ip_lookup:
            return None
        held = self.ip_lookup(address, at_ms)
        return self.records.get(held[0]) if held and len(held) == 1 else None


def worse(a, b):
    return TIERS[max(TIERS.index(a), TIERS.index(b))]


def lower(tier):
    return TIERS[min(TIERS.index(tier) + 1, len(TIERS) - 1)]


class Builder:
    def __init__(self, seed, assets, limits=None):
        limits = limits or {}
        self.seed = seed
        self.assets = assets
        self.graph = Graph(limits.get('max_nodes', 200), limits.get('max_edges', 400))
        self.max_hops = limits.get('max_hops', 3)
        self.sequence_ms = limits.get('sequence_minutes', 30) * 60000
        self.stages, self.contradictions, self.excluded = [], [], 0
        self.gaps, self.sources, self.affected, self.sensors, self.identities = set(), {}, {}, set(), {}
        self.asset_nodes = {}

    # Nodes.
    def asset_node(self, host):
        if host in self.asset_nodes:
            return self.asset_nodes[host]
        record, holders = self.assets.by_host(host)
        if record:
            node = self.graph.node('asset', record['asset_id'], record.get('hostname'), asset_id=record['asset_id'], resolved=True, platform=record.get('platform'), identity_confidence=record.get('identity_confidence'), status=record.get('status'), criticality=record.get('criticality'), owner=record.get('owner'))
            if record.get('status') in ('conflicted', 'retired', 'reappeared'):
                self.contradiction('major', f"The asset {record.get('hostname')} has status {record.get('status')}, so its identity or service is in doubt")
        else:
            node = self.graph.node('asset', f'unresolved:{host}', host, resolved=False, ambiguous=holders > 1)
            self.gaps.add('asset_unknown' if self.assets.available else 'asset_context_unavailable')
            if holders > 1:
                self.contradiction('major', f'{holders} assets hold the name {host}, so it is left unresolved')
        self.asset_nodes[host] = node
        if node:
            self.affected[node] = host
        return node

    def asset_resolved(self, host):
        node = self.asset_nodes.get(host) or self.asset_node(host)
        return bool(node and self.graph.nodes[node].get('resolved'))

    def identity_node(self, person):
        if person is None:
            return None
        node = self.graph.node('identity', person.id, person.display, quality=person.quality, sid=person.sid)
        if node:
            self.identities[node] = person.display
        return node

    def ip_node(self, address, fact):
        node = self.graph.node('ip', f'{fact.host}:{address}' if self._local(address) else address, address, scope=fact.host if self._local(address) else 'global', role='attack_source')
        return node

    @staticmethod
    def _local(address):
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            return True
        return not parsed.is_global

    # Tiers.
    def observed_tier(self, fact, person):
        """How strongly an event shows what its edge claims. Starts at the top, and each doubt names itself."""
        tier = CONFIRMED
        if fact.attribution != 'verified':
            tier = worse(tier, STRONG)
        if not self.asset_resolved(fact.host):
            tier = worse(tier, STRONG)
        if person is not None and person.quality == 'ambiguous':
            tier = worse(tier, STRONG)
        return tier

    def contradiction(self, weight, text):
        if text not in [c['text'] for c in self.contradictions]:
            self.contradictions.append({'weight': weight, 'text': clean(text, 300)})

    def stage(self, tactic, name, facts, edges, explanation, technique=None, source='rule'):
        edges = [e for e in edges if e]
        if not edges:
            return
        tiers = [self.graph.edges[e]['tier'] for e in edges]
        at = min(self.graph.edges[e]['first_ms'] for e in edges)
        techniques = []
        if technique:
            techniques.append({'id': technique, 'name': TECHNIQUES[technique], 'source': source})
        self.stages.append({'tactic': tactic, 'name': name, 'at_ms': at, 'at': iso(at) if at else None, 'edges': edges, 'tier': max(tiers, key=TIERS.index), 'explanation': clean(explanation, 400), 'techniques': techniques, 'events': len(facts)})

    # Selecting facts.
    def facts(self):
        """Facts cited by alerts, then context facts that reach them through identity on one asset, and nothing else."""
        cited = []
        for (index, event_id), event in sorted(self.seed.events.items()):
            fact = to_fact(index, event_id, event)
            if fact:
                cited.append(fact)
        anchors = {(f.host, p.id) for f in cited for p in (f.actor, f.target) if p and p.links}
        for alert in self.seed.alerts:
            person = self._alert_identity(alert)
            if person and person.links:
                anchors.add((clean(alert.get('host'), 120).lower(), person.id))
        seen = {(f.index, f.event_id) for f in cited}
        pool = []
        for hit in self.seed.context:
            key = (hit.get('_index'), hit.get('_id'))
            if key in seen:
                continue
            seen.add(key)
            fact = to_fact(hit.get('_index'), hit.get('_id'), hit.get('_source') or {})
            if fact:
                pool.append(fact)
        kept = list(cited)
        for _ in range(self.max_hops):
            added, reached = [], set()
            for fact in pool:
                people = {(fact.host, p.id) for p in (fact.actor, fact.target) if p and p.links}
                if people & anchors:
                    added.append(fact)
                    reached |= people
            if not added:
                break
            anchors |= reached
            kept += added
            pool = [f for f in pool if f not in added]
        self.excluded = len(pool)
        return sorted(kept, key=lambda f: (f.at_ms, f.event_id))

    def _alert_identity(self, alert):
        host = clean(alert.get('host'), 120).lower()
        name = alert.get('user')
        if not name:
            return None
        return model.linux_identity(name, host) if host.endswith('-wsl') or self._platform_of(host) == 'linux' else model.windows_identity(name)

    def _platform_of(self, host):
        record, _ = self.assets.by_host(host)
        return (record or {}).get('platform')

    # Patterns. Each reads facts, whichever platform wrote them.
    def authentication(self, facts):
        groups = {}
        for fact in facts:
            if fact.kind in ('auth_failure', 'auth_success'):
                person = fact.target or fact.actor
                if person and person.links:
                    groups.setdefault((fact.host, person.id), []).append(fact)
        for (host, _), items in groups.items():
            items.sort(key=lambda f: f.at_ms)
            asset = self.asset_node(host)
            failures = [f for f in items if f.kind == 'auth_failure']
            successes = [f for f in items if f.kind == 'auth_success']
            person = items[0].target or items[0].actor
            node = self.identity_node(person)
            used = []
            for fact in items:
                who = fact.target or fact.actor
                evidence = [fact_evidence(fact, self.graph.nodes.get(asset, {}).get('asset_id'))]
                kind = 'authenticated_to' if fact.kind == 'auth_success' else 'failed_authentication_to'
                used.append(self.graph.edge(node, kind, asset, OBSERVED, 'observed', self.observed_tier(fact, who), evidence, f'{fact.dataset} recorded this on the host'))
                self.sensors.add(f'{fact.dataset}@{fact.host}')
                if fact.source_ip and fact.source_ip not in ('127.0.0.1', '::1'):
                    self._source(fact, asset, evidence)
            for success in successes:
                before = [f for f in failures if 0 <= success.at_ms - f.at_ms <= self.sequence_ms]
                if len(before) >= FAILURES_BEFORE_SUCCESS:
                    addresses = {f.source_ip for f in before if f.source_ip}
                    if success.source_ip and addresses and success.source_ip not in addresses:
                        self.contradiction('major', f'The failures came from {len(addresses)} other addresses, and the success from a different one, so these may be separate activity')
                    self.stage('credential-access', 'failures_then_success', before + [success], used, f'{len(before)} failed authentications, then a success, for one identity on one asset, within {self.sequence_ms // 60000} minutes', 'T1110', 'pattern')
                    self.stage('initial-access', 'account_access_after_failures', [success], [used[-1]] if used else [], 'An authentication succeeded after those failures. This shows access was granted, and not who was using the account')
                    break
            else:
                if failures and successes:
                    if all(s.at_ms < failures[0].at_ms for s in successes):
                        self.contradiction('minor', 'Every success came before the failures, so failures did not lead to access')
                self.stage('credential-access', 'failed_authentication', failures or successes, used, f'{len(failures)} failed and {len(successes)} successful authentications. Too few, or in the wrong order, to show guessing')

    def _source(self, fact, asset, evidence):
        """An address reported by the target. What sent it, and from where, is not known."""
        peer = self.assets.by_ip(fact.source_ip, fact.at_ms)
        if not peer:
            self.gaps.add('source_not_observed')
        if peer and peer.get('asset_id') != self.graph.nodes.get(asset, {}).get('asset_id'):
            other = self.graph.node('asset', peer['asset_id'], peer.get('hostname'), asset_id=peer['asset_id'], resolved=True, platform=peer.get('platform'), identity_confidence=peer.get('identity_confidence'))
            lateral = fact.logon_type in NETWORK_LOGONS or fact.action == 'ssh-login'
            if lateral and fact.kind == 'auth_success':
                record = Evidence('asset', peer['asset_id'], 'siem-assets-current', iso(fact.at_ms), host=peer.get('hostname'), asset_id=peer['asset_id'], fields={'resolved': 'address held at that time'}, provenance='asset inventory')
                edge = self.graph.edge(other, 'remote_access_from', asset, INFERRED, 'inferred', PLAUSIBLE, [*evidence, record], 'The target reported this address, and the inventory held it for that asset at that time. Addresses can be spoofed or shared', supporting=['address held at that time'])
                technique = 'T1021.001' if fact.logon_type == '10' else 'T1021.004' if fact.action == 'ssh-login' else None
                self.stage('lateral-movement', 'remote_access_between_assets', [fact], [edge], 'A network logon on one asset came from an address another asset held at that moment', technique, 'pattern')
                self.sources[other] = peer.get('hostname')
                return
        node = self.ip_node(fact.source_ip, fact)
        self.graph.edge(node, 'access_attempt_from', asset, OBSERVED, 'observed', STRONG, evidence, 'The target reported this source address. It was not observed at the source')
        self.sources[node] = fact.source_ip

    def privilege(self, facts):
        for fact in facts:
            if fact.kind in ('privilege_use', 'privilege_change'):
                actor, target = fact.actor, fact.target
                if not actor or not target or actor.id == target.id:
                    continue
                edge = self.graph.edge(self.identity_node(actor), 'escalated_privileges', self.identity_node(target), OBSERVED, 'observed', self.observed_tier(fact, actor), [fact_evidence(fact)], f'{fact.action}: this account acted as that one')
                self.sensors.add(f'{fact.dataset}@{fact.host}')
                self.asset_node(fact.host)
                self.stage('privilege-escalation', 'identity_transition', [fact], [edge], 'One account ran as another. Whether that was allowed use is for a person to judge', 'T1548.003' if fact.action == 'sudo-command' else None, 'pattern')
            if fact.kind == 'privilege_refused' and fact.actor:
                self.asset_node(fact.host)
                edge = self.graph.edge(self.identity_node(fact.actor), 'failed_authentication_to', self.asset_node(fact.host), OBSERVED, 'observed', self.observed_tier(fact, fact.actor), [fact_evidence(fact)], 'sudo refused this account')
                self.stage('privilege-escalation', 'privilege_refused', [fact], [edge], 'A privilege request was refused')
            if fact.kind == 'group_added':
                asset = self.asset_node(fact.host)
                group = self.graph.node('group', f'{fact.host}:{(fact.group or "").lower()}', fact.group) if fact.group else None
                member = fact.target or fact.actor
                edge = self.graph.edge(self.identity_node(member) or asset, 'added_to_group', group, OBSERVED, 'observed', self.observed_tier(fact, member), [fact_evidence(fact)], 'The host recorded this group change')
                privileged = (fact.group or '').lower() in PRIVILEGED_GROUPS
                self.sensors.add(f'{fact.dataset}@{fact.host}')
                self.stage('persistence' if privileged else 'discovery', 'privileged_group_change' if privileged else 'group_change', [fact], [edge], 'An account joined a group that grants administration' if privileged else 'An account joined a group', 'T1098' if privileged else None, 'pattern')

    def accounts(self, facts):
        created = {}
        for fact in facts:
            if fact.kind == 'account_created' and fact.target:
                asset = self.asset_node(fact.host)
                node = self.identity_node(fact.target)
                source = self.identity_node(fact.actor) if fact.actor else asset
                edge = self.graph.edge(source, 'created', node, OBSERVED, 'observed', self.observed_tier(fact, fact.target), [fact_evidence(fact)], 'The host recorded this account being created')
                self.sensors.add(f'{fact.dataset}@{fact.host}')
                self.stage('persistence', 'account_created', [fact], [edge], 'A local account was created', 'T1136.001', 'pattern')
                created[(fact.host, fact.target.id)] = fact
        for (host, person), made in created.items():
            uses = [f for f in facts if f.host == host and f.at_ms >= made.at_ms and f.kind in ('auth_success', 'privilege_use', 'privilege_change') and ((f.actor and f.actor.id == person) or (f.kind == 'auth_success' and f.target and f.target.id == person))]
            if uses:
                use = uses[0]
                who = use.actor if use.actor and use.actor.id == person else use.target
                edge = self.graph.edge(self.identity_node(who), 'authenticated_to', self.asset_node(host), OBSERVED, 'observed', self.observed_tier(use, who), [fact_evidence(use)], 'The new account was used on this host')
                self.stage('persistence', 'new_account_used', [use], [edge], 'An account created in this path was then used, on the same asset', 'T1078.003', 'pattern')

    def persistence(self, facts):
        for fact in facts:
            if fact.kind in ('service_installed', 'task_created', 'cron_changed', 'package_installed'):
                asset = self.asset_node(fact.host)
                actor = self.identity_node(fact.actor) if fact.actor and fact.actor.links else asset
                self.sensors.add(f'{fact.dataset}@{fact.host}')
                if fact.kind == 'service_installed' and fact.service:
                    node = self.graph.node('service', f'{fact.host}:{fact.service.lower()}', fact.service)
                    edge = self.graph.edge(actor, 'installed', node, OBSERVED, 'observed', self.observed_tier(fact, fact.actor), [fact_evidence(fact)], 'The host recorded this service being installed')
                    self.stage('persistence', 'service_installed', [fact], [edge], 'A Windows service was installed', 'T1543.003', 'pattern')
                elif fact.kind == 'task_created':
                    node = self.graph.node('task', f'{fact.host}:{fact.event_id}', 'scheduled task')
                    edge = self.graph.edge(actor, 'scheduled', node, OBSERVED, 'observed', self.observed_tier(fact, fact.actor), [fact_evidence(fact)], 'The host recorded this scheduled task')
                    self.stage('persistence', 'task_created', [fact], [edge], 'A Windows scheduled task was registered', 'T1053.005', 'pattern')
                elif fact.kind == 'cron_changed':
                    target = self.identity_node(fact.target) if fact.target else None
                    node = self.graph.node('task', f'{fact.host}:crontab:{fact.target.id if fact.target else "unknown"}', 'user crontab')
                    edge = self.graph.edge(actor, 'scheduled', node, OBSERVED, 'observed', self.observed_tier(fact, fact.actor), [fact_evidence(fact)], 'The host recorded this crontab change', supporting=[target] if target else ())
                    self.stage('persistence', 'cron_changed', [fact], [edge], 'A user crontab changed. Its contents are not known', 'T1053.003', 'pattern')
                elif fact.package:
                    node = self.graph.node('package', f'{fact.host}:{fact.package}', fact.package)
                    edge = self.graph.edge(asset, 'installed', node, OBSERVED, 'observed', self.observed_tier(fact, None), [fact_evidence(fact)], 'dpkg recorded this. It does not say who asked for it')
                    self.stage('persistence', 'package_installed', [fact], [edge], 'A package was installed. Who asked for it is not recorded')
            if fact.kind in ('service_failed', 'security_control_changed', 'audit_policy_changed'):
                asset = self.asset_node(fact.host)
                self.sensors.add(f'{fact.dataset}@{fact.host}')
                node = self.graph.node('service', f'{fact.host}:{(fact.service or fact.action).lower()}', fact.service or fact.action)
                edge = self.graph.edge(node, 'failed_on', asset, OBSERVED, 'observed', self.observed_tier(fact, None) if fact.kind != 'service_failed' else worse(self.observed_tier(fact, None), STRONG), [fact_evidence(fact)], 'The host recorded this. It does not say why')
                technique = 'T1562.002' if fact.kind == 'audit_policy_changed' else 'T1562.001' if fact.kind == 'security_control_changed' else None
                self.stage('defense-evasion', fact.kind, [fact], [edge], 'A security component failed or changed. A fault looks the same as an attack here', technique, 'pattern')

    def processes(self, facts):
        for fact in facts:
            if fact.kind == 'process_start' and fact.process['id']:
                node = self.graph.node('process', f"{fact.host}:{fact.process['id']}", fact.process['name'])
                asset = self.asset_node(fact.host)
                edges = [self.graph.edge(self.identity_node(fact.actor) if fact.actor and fact.actor.links else asset, 'executed', node, OBSERVED, 'observed', self.observed_tier(fact, fact.actor), [fact_evidence(fact)], 'Sysmon recorded this process start')]
                if fact.process['parent']:
                    parent = self.graph.node('process', f"{fact.host}:{fact.process['parent']}", fact.process['parent_name'])
                    edges.append(self.graph.edge(parent, 'spawned', node, OBSERVED, 'observed', self.observed_tier(fact, fact.actor), [fact_evidence(fact)], 'Sysmon recorded the parent and child by process GUID'))
                self.sensors.add(f'{fact.dataset}@{fact.host}')
                self.stage('execution', 'process_lineage', [fact], edges, 'A process started, and its parent is recorded')
            if fact.kind == 'network' and fact.dest_ip and fact.process['id']:
                node = self.graph.node('process', f"{fact.host}:{fact.process['id']}", fact.process['name'])
                peer = self.ip_node(fact.dest_ip, fact)
                self.graph.nodes[peer]['role'] = 'network_peer'
                self.graph.edge(node, 'communicated_with', peer, OBSERVED, 'observed', self.observed_tier(fact, fact.actor), [fact_evidence(fact)], 'Sysmon recorded this connection. It says nothing about trust')

    def detections(self):
        for alert in self.seed.alerts:
            alert_id = clean(alert.get('alert_id'), 32)
            host = clean(alert.get('host'), 120).lower()
            if not alert_id or not host:
                continue
            asset = self.asset_node(host)
            node = self.graph.node('alert', alert_id, alert.get('rule_name'), severity=clean(alert.get('severity'), 16), rule_id=clean(alert.get('rule_id'), 64))
            when = alert.get('timestamp')
            mitre = alert.get('mitre') or {}
            record = Evidence('alert', alert_id, 'siem-alerts-*', when, alert.get('detected_at'), host, self.graph.nodes.get(asset, {}).get('asset_id'), 'detection engine', {'rule': clean(alert.get('rule_name'), 120), 'severity': clean(alert.get('severity'), 16), 'confidence': clean(alert.get('confidence'), 16)}, 'detection')
            backed = any(model.event_ref(r) and tuple(model.event_ref(r)) in self.seed.events for r in alert.get('raw_event_refs') or [])
            edge = self.graph.edge(node, 'detected_on', asset, DETECTION, 'observed', STRONG if backed else PLAUSIBLE, [record], 'A rule fired here. That is an interpretation, and its events are the observation' if backed else 'A rule fired here, and its source events are not available')
            techniques = [{'id': clean(t, 16), 'name': TECHNIQUES.get(clean(t, 16), ''), 'source': 'alert'} for t in (mitre.get('techniques') or [])[:6] if _TECHNIQUE.fullmatch(str(t))]
            self.stages.append({'tactic': clean((mitre.get('tactics') or ['detection'])[0], 40).replace('_', '-'), 'name': 'detection', 'at_ms': ms(when) if when else 0, 'at': when, 'edges': [edge] if edge else [], 'tier': STRONG if backed else PLAUSIBLE, 'explanation': clean(f"Rule: {alert.get('rule_name')}", 300), 'techniques': techniques, 'events': int(alert.get('event_count') or 0) if isinstance(alert.get('event_count'), int) else 0})
            incident = self.seed.incident
            if incident:
                join = sorted({clean(r.get('join'), 20) for r in incident.get('rules') or [] if isinstance(r, dict)})
                strong = not (set(join) & {'host', 'user_name'}) and bool(join)
                inode = self.graph.node('incident', incident['incident_id'], incident.get('title'), status=clean(incident.get('status'), 20))
                self.graph.edge(node, 'correlated_with', inode, CORRELATION, 'inferred', STRONG if strong else PLAUSIBLE, [Evidence('incident', incident['incident_id'], 'siem-incidents-*', incident.get('last_seen'), incident.get('updated_at'), host, None, 'correlator', {'joins': ','.join(join)}, 'correlation')], f"Correlation joined these by {', '.join(join) or 'an unstated link'}")

    def intelligence(self):
        for doc_id, index, doc in self.seed.intelligence:
            alert_id = clean(doc.get('alert_id'), 32)
            alert = self.graph.nodes.get(f"alert:{model.digest('alert', alert_id)}")
            if not alert:
                continue
            for item in (doc.get('indicators') or [])[:25]:
                verdict = clean(item.get('verdict'), 20)
                if verdict not in ('malicious', 'suspicious', 'conflicting'):
                    continue
                node = self.graph.node('indicator', f"{clean(item.get('type'), 12)}:{clean(item.get('value'), 200)}", item.get('value'), verdict=verdict)
                self.graph.edge(alert['id'], 'associated_with', node, INTEL, 'inferred', PLAUSIBLE, [Evidence('enrichment', clean(doc_id, 128), clean(index, 64), self._alert_time(alert_id), None, None, None, 'enrichment', {'verdict': verdict, 'type': clean(item.get('type'), 12)}, 'threat intelligence')], 'Threat intelligence says something about this indicator. That is no proof about this host')
                if verdict == 'conflicting':
                    self.contradiction('minor', 'Threat intelligence sources disagree on an indicator')

    def _alert_time(self, alert_id):
        return next((a.get('timestamp') for a in self.seed.alerts if a.get('alert_id') == alert_id), None)

    def identity_links(self, facts):
        """Only a person can say two accounts are one. Shared names never do it."""
        present = {p.id for f in facts for p in (f.actor, f.target) if p}
        for link in self.seed.identity_links:
            if link['a'] in present and link['b'] in present:
                people = {p.id: p for f in facts for p in (f.actor, f.target) if p}
                record = Evidence('analyst', link['id'], 'analyst statement', iso(link['at_ms']), fields={'by': clean(link['actor'], 60)}, provenance=f"analyst:{clean(link['actor'], 60)}")
                self.graph.edge(self.identity_node(people[link['a']]), 'same_identity', self.identity_node(people[link['b']]), ANALYST, 'inferred', STRONG, [record], clean(link['reason'], 300))

    def review(self, facts):
        if self.seed.missing:
            self.gaps.add('evidence_missing')
            self.contradiction('minor', f'{len(self.seed.missing)} cited events are no longer available, or their references were refused')
        linux = [n for n in self.graph.nodes.values() if n['type'] == 'asset' and n.get('platform') == 'linux']
        if linux or any(f.platform == 'linux' for f in facts):
            self.gaps |= {'linux_process_execution', 'linux_network'}
            if any(f.kind in ('auth_success', 'auth_failure') for f in facts if f.platform == 'linux'):
                self.gaps |= {'linux_ssh', 'linux_firewall'}
        if self.seed.status == 'false_positive':
            self.contradiction('major', 'An analyst closed this incident as a false positive')
        for text in (self.seed.incident or {}).get('uncertain') or []:
            self.contradiction('minor', f'Correlation noted: {clean(text, 200)}')
        if self.graph.cut:
            self.gaps.add('graph_truncated')
        if self.seed.limited:
            self.gaps.add('query_limited')

    def tier(self):
        """The weakest stage sets the tier. A strong edge cannot lift a weak one, and each step is written down."""
        rationale = []
        observed = [s for s in self.stages if s['name'] != 'detection']
        if not observed:
            tier = PLAUSIBLE if self.stages else INSUFFICIENT
            rationale.append('No observed event supports a stage, so this rests on detections alone' if self.stages else 'No stage could be built')
        else:
            tier = max((s['tier'] for s in observed), key=TIERS.index)
            rationale.append(f'{len(observed)} observed stages, and the weakest is {tier}')
        if any(not n.get('resolved') for n in self.graph.nodes.values() if n['type'] == 'asset') and TIERS.index(tier) < TIERS.index(STRONG):
            tier = STRONG
            rationale.append('Capped at strongly_supported: an asset is unresolved')
        major = [c for c in self.contradictions if c['weight'] == 'major']
        for item in major:
            tier = lower(tier)
            rationale.append(f"Lowered one tier: {item['text']}")
        minor = [c for c in self.contradictions if c['weight'] == 'minor']
        if minor:
            rationale.append(f'{len(minor)} lesser doubts are listed, and do not change the tier')
        if 'evidence_missing' in self.gaps and TIERS.index(tier) < TIERS.index(PLAUSIBLE):
            tier = PLAUSIBLE
            rationale.append('Capped at plausible_inferred: evidence is missing')
        if 'graph_truncated' in self.gaps and TIERS.index(tier) < TIERS.index(WEAK):
            tier = WEAK
            rationale.append('Capped at weak_hypothesis: the graph is incomplete')
        rationale.append('No tier means compromise. A person decides that')
        return tier, rationale

    def next_steps(self):
        steps = []
        kinds = {s['name'] for s in self.stages}
        if 'failures_then_success' in kinds:
            steps.append('Ask the account holder whether they made the logon that succeeded')
        if 'account_created' in kinds or 'new_account_used' in kinds:
            steps.append('Check who requested the new account, and whether a change record exists')
        if 'privileged_group_change' in kinds:
            steps.append('Confirm the group change was approved')
        if {'service_installed', 'task_created', 'cron_changed'} & kinds:
            steps.append('Read what the new service, task or crontab runs, on the host')
        if 'identity_transition' in kinds:
            steps.append('Review the sudo commands in the event evidence')
        if 'remote_access_between_assets' in kinds:
            steps.append('Check the source asset for what started the connection')
        if 'source_not_observed' in self.gaps:
            steps.append('Find out who owns the source address')
        if 'linux_process_execution' in self.gaps:
            steps.append('Inspect the Linux host directly, since its process activity is not recorded')
        if 'evidence_missing' in self.gaps:
            steps.append('Look for the missing events in the host logs before relying on this path')
        return steps or ['Review the detection and its events']


def build(seed, assets, limits=None):
    worker = Builder(seed, assets, limits)
    facts = worker.facts()
    worker.detections()
    worker.authentication(facts)
    worker.accounts(facts)
    worker.privilege(facts)
    worker.persistence(facts)
    worker.processes(facts)
    worker.intelligence()
    worker.identity_links(facts)
    worker.review(facts)
    stages = sorted(worker.stages, key=lambda s: (s['at_ms'], s['name']))
    for number, stage in enumerate(stages, 1):
        stage['order'] = number
    tier, rationale = worker.tier()
    edges = sorted(worker.graph.edges.values(), key=lambda e: e['id'])
    nodes = sorted(worker.graph.nodes.values(), key=lambda n: n['id'])
    fingerprint = model.digest(tier, [e['id'] for e in edges], [len(e['evidence']) for e in edges], [s['name'] for s in stages], sorted(worker.gaps), [c['text'] for c in worker.contradictions], seed.status)
    return {'schema_version': model.SCHEMA_VERSION, 'path_id': model.digest('path', seed.kind, seed.id), 'seed': {'kind': seed.kind, 'id': seed.id}, 'title': clean(seed.title, 200), 'severity': seed.severity, 'analyst_status': seed.status, 'tier': tier, 'conclusion': 'none: this is evidence for a person to judge, and not a finding of compromise', 'rationale': rationale,
            'attack_sources': [{'node': k, 'display': v} for k, v in sorted(worker.sources.items())], 'affected_assets': [{'node': k, 'display': v, 'resolved': bool(worker.graph.nodes[k].get('resolved'))} for k, v in sorted(worker.affected.items()) if k in worker.graph.nodes], 'telemetry_sources': sorted(worker.sensors), 'identities': [{'node': k, 'display': v, 'quality': worker.graph.nodes[k].get('quality')} for k, v in sorted(worker.identities.items())],
            'stages': stages, 'nodes': nodes, 'edges': edges, 'contradictions': worker.contradictions, 'gaps': [{'gap': g, 'meaning': GAPS[g]} for g in sorted(worker.gaps)], 'excluded_unrelated_events': worker.excluded, 'next_steps': worker.next_steps(), 'fingerprint': fingerprint}
