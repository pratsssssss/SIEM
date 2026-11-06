// The overview: security, operations, assets, intelligence and paths. Every number comes from the API, or reads as unavailable.
import { get } from './api.js';
import { ago, badge, bars, card, h, link, note, part, stat, table, when, filterBar, none } from './ui.js';

const SEVERITY = ['critical', 'high', 'medium', 'low', 'informational'];
export const alertColumns = [
  { title: 'Detected', render: (r) => when(r.detected_at) }, { title: 'Severity', render: (r) => badge(r.severity) }, { title: 'Rule', render: (r) => link(`#/alerts/${r.alert_id}`, r.rule_name) }, { title: 'Host', key: 'host' },
];

function security(section, range) {
  return card(`Security, last ${range}`, part(section, (d) => [
    h('div', { class: 'stats' }, stat(d.alerts_total, 'alerts'), SEVERITY.map((s) => (d.by_severity[s] ? stat(d.by_severity[s], s) : null))),
    d.alerts_total ? bars(d.over_time) : note('No alerts in this period. This says nothing was detected, not that nothing happened.'),
    h('h3', null, 'Most active rules'), table([{ title: 'Rule', key: 'rule' }, { title: 'Alerts', key: 'count' }], d.by_rule),
    h('h3', null, 'Recent high and critical'), table(alertColumns, d.recent_high),
  ]));
}

function incidents(section) {
  return card('Incidents', part(section, (d) => [
    h('div', { class: 'stats' }, ['new', 'open', 'investigating', 'contained', 'resolved', 'closed', 'false_positive'].map((s) => stat(d.by_status[s] || 0, s.replace('_', ' ')))),
    d.excluded_no_stored_alerts ? note(`${d.excluded_no_stored_alerts} incidents with no stored alert are left out, as test fixtures.`) : null,
    h('h3', null, 'Recent'), table([{ title: 'Incident', render: (r) => link(`#/incidents/${r.incident_id}`, r.title) }, { title: 'Status', render: (r) => badge(r.status) }, { title: 'Severity', render: (r) => badge(r.severity) }], d.recent),
  ]));
}

function operations(section) {
  return card('Operations', part(section, (d) => [
    h('div', { class: 'stats' }, h('div', { class: 'stat' }, badge(d.overall), h('span', null, ' pipeline')), h('div', { class: 'stat' }, badge(d.coverage === 'trusted' ? 'HEALTHY' : d.coverage === 'limited' ? 'DEGRADED' : 'UNKNOWN', 'Coverage, as Phase 16 states it'), h('span', null, ` coverage ${d.coverage}`))),
    d.monitor_current ? null : note(`The health monitor is not current. The last stored state was ${d.stored_overall}.`, 'warn'),
    h('p', { class: 'dim' }, d.coverage_reason),
    d.bottleneck ? note(`Bottleneck: ${d.bottleneck}. Root cause: ${d.root_cause}.`, 'warn') : null,
    table([{ title: 'Stage', key: 'stage' }, { title: 'Status', render: (r) => badge(r.status) }, { title: 'Components', render: (r) => r.components.map((c, i) => [i ? ', ' : '', link(`#/health/${c}`, c)]) }], d.stages),
    h('p', { class: 'dim' }, 'Last observed: ', when(d.observed_ms), ' · ', ago(d.observed_ms)),
  ]));
}

function tally(values) {
  return Object.entries(values || {}).map(([k, v]) => stat(v, k.replaceAll('_', ' ')));
}

function assets(section) {
  return card('Assets', part(section, (d) => [
    h('div', { class: 'stats' }, stat(d.in_service, 'in service'), stat(d.total - d.in_service, 'retired'), stat(d.open_conflicts, 'identity conflicts'), stat(d.unreviewed_changes, 'changes to review'), stat(d.unresolved_identities, 'low confidence identities')),
    h('h3', null, 'In service, by platform'), h('div', { class: 'stats' }, tally(d.by_platform)),
    h('h3', null, 'In service, by criticality'), h('div', { class: 'stats' }, tally(d.by_criticality)),
  ]));
}

function intelligence(section) {
  return card('Threat intelligence', part(section, (d) => [
    h('div', { class: 'stats' }, tally(d.by_verdict), stat(d.lookup_failures, 'lookups with a failed source')),
    h('p', { class: 'dim' }, d.note),
    h('p', null, 'Sources: ', d.source_freshness ? [badge(d.source_freshness.status), ' ', d.source_freshness.reason] : none('freshness unknown')),
  ]));
}

function paths(section) {
  return card('Attack paths', part(section, (d) => [
    h('div', { class: 'stats' }, stat(d.total, 'paths'), stat(d.with_expired_evidence, 'with expired evidence'), stat(d.needing_validation, 'due for checking'), stat(d.with_missing_telemetry, 'with missing telemetry')),
    h('h3', null, 'By tier'), h('div', { class: 'stats' }, tally(d.by_tier)),
    h('p', { class: 'dim' }, d.note),
    table([{ title: 'Path', render: (r) => link(`#/paths/${r.path_id}`, r.title) }, { title: 'Tier', render: (r) => badge(r.tier) }, { title: 'Built', render: (r) => ago(r.path_at) }], d.recent),
  ]));
}

export async function page({ params, go, setRefresh, redraw }) {
  const range = params.range || '24h';
  const d = await get('/overview', { range });
  setRefresh(redraw, 60);
  return h('div', null, h('h1', null, 'Overview'), h('p', { class: 'lead' }, 'Observed ', when(d.observed_ms), '. Refreshes each minute while this tab is open.'),
    filterBar([{ key: 'range', title: 'Time range', options: ['1h', '6h', '24h', '7d', '30d'], default: '24h' }], { range }, (v) => go('overview', v)),
    h('div', { class: 'grid' }, security(d.security, range), operations(d.health)), h('div', { class: 'grid' }, incidents(d.incidents), paths(d.paths)), h('div', { class: 'grid' }, assets(d.assets), intelligence(d.intelligence)));
}
