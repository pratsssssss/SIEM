// Threat intelligence, pipeline health, audit, settings and search. Health states come from Phase 16 unchanged:
// nothing on this page works one out, and a metric with no value reads as unavailable, never as zero.
import { changePassword, get, session } from './api.js';
import { ago, badge, card, empty, filterBar, h, kv, link, none, note, pager, part, stat, table, when } from './ui.js';

export async function intelligence({ params, go }) {
  const data = await get('/threat-intelligence', { size: 50, ...params });
  return h('div', null, h('h1', null, 'Threat Intelligence'), note(data.note),
    card('Verdicts', h('div', { class: 'stats' }, Object.entries(data.by_verdict).map(([k, v]) => stat(v, k.replaceAll('_', ' '))), stat(data.lookup_failures, 'lookups with a failed source')), h('p', { class: 'dim' }, `From the newest ${data.records_read} of ${data.records_total.value} enrichment records.`)),
    filterBar([{ key: 'verdict', title: 'Verdict', options: ['', 'malicious', 'suspicious', 'conflicting', 'unknown', 'no_known_threat', 'lookup_failed'] }], params, (v) => go('intelligence', v)),
    card(null, table([{ title: 'Indicator', render: (r) => h('span', { class: 'mono' }, r.value) }, { title: 'Type', key: 'type' }, { title: 'Verdict', render: (r) => badge(r.verdict) }, { title: 'Score', key: 'score' }, { title: 'Sources', render: (r) => (r.sources_answered || []).join(', ') }, { title: 'Failed', render: (r) => (r.sources_failed || []).join(', ') }, { title: 'Complete', render: (r) => String(r.complete) }, { title: 'First seen', render: (r) => when(r.first_seen) }, { title: 'Last seen', render: (r) => when(r.last_seen) }, { title: 'Alerts', render: (r) => (r.alert_ids || []).filter(Boolean).slice(0, 3).map((a, i) => [i ? ', ' : '', link(`#/alerts/${encodeURIComponent(a)}`, String(a).slice(0, 8))]) }], data.rows), pager(data, (offset) => go('intelligence', { ...params, offset }))));
}

const value = (metric) => (metric && metric.value !== undefined && metric.value !== null ? metric.value : none('unavailable'));

export async function health({ setRefresh, redraw }) {
  const [overview, components, lag, resources, failures, history] = await Promise.all(['overview', 'components', 'lag', 'resources', 'failures', 'history'].map((n) => get(`/health/${n}`).catch((e) => ({ unavailable: e.message }))));
  setRefresh(redraw, 60);
  if (overview.unavailable) return h('div', null, h('h1', null, 'Pipeline Health'), note(`The health monitor state cannot be read: ${overview.unavailable}. That says nothing about the pipeline itself.`, 'warn'));
  const rows = Object.values(components.unavailable ? {} : components);
  const fresh = (r) => ago(r.observed_ms);
  const figures = resources.figures || {};
  return h('div', null, h('h1', null, 'Pipeline Health'), h('p', { class: 'lead' }, 'States are Phase 16’s, unchanged. Last cycle ', when(overview.observed_ms), ', ', ago(overview.observed_ms), '.'),
    overview.monitor_current ? null : note(`This monitor is not current. Last stored state: ${overview.stored_overall}. Do not read the rows below as live.`, 'bad'),
    card('Pipeline', h('div', { class: 'stats' }, h('div', { class: 'stat' }, badge(overview.overall), h('span', null, ' overall')), h('div', { class: 'stat' }, h('b', null, overview.coverage), h('span', null, 'coverage'))), h('p', { class: 'dim' }, overview.coverage_reason), overview.bottleneck ? note(`Bottleneck: ${overview.bottleneck}. Root cause: ${overview.root_cause}.`, 'warn') : null,
      table([{ title: 'Stage', key: 'stage' }, { title: 'Status', render: (r) => badge(r.status) }, { title: 'Components', render: (r) => r.components.join(', ') }], overview.stages)),
    h('div', { class: 'grid' }, card('Backlog and lag', kv(Object.entries(lag.lag || {}).map(([k, v]) => [k.replaceAll('_', ' '), value(v)]))),
      card('Resources', kv([['Memory available, %', figures.memory_available_percent ?? none('unavailable')], ['Swap used, %', figures.swap_used_percent ?? none('unavailable')], ['Memory pressure', figures.memory_pressure_full ?? none('unavailable')], ['CPU pressure', figures.cpu_pressure_some ?? none('unavailable')], ['C: free, GiB', figures.windows_disk_free_gib ?? none('unavailable')], ['OpenSearch heap, %', figures.opensearch_heap_percent ?? none('unavailable')]]))),
    card('Components', table([{ title: 'Component', render: (r) => link(`#/health/${r.component}`, r.component) }, { title: 'Status', render: (r) => badge(r.status) }, { title: 'Condition', key: 'condition' }, { title: 'Certainty', key: 'certainty' }, { title: 'Observed', render: fresh }, { title: 'Last activity', render: (r) => ago(r.last_activity_ms) }, { title: 'Reason', key: 'reason' }], rows.sort((a, b) => a.component.startsWith('source:') - b.component.startsWith('source:')))),
    h('div', { class: 'grid' }, card('Open episodes', failures.open?.length ? table([{ title: 'Component', key: 'component' }, { title: 'Worst', render: (r) => badge(r.worst) }, { title: 'Started', render: (r) => when(r.started_ms) }, { title: 'Reason', key: 'last_reason' }], failures.open) : empty('No open episode.')),
      card('Recent changes, 7 days', table([{ title: 'When', render: (r) => when(r.at_ms) }, { title: 'Component', key: 'component' }, { title: 'From', render: (r) => badge(r.from) }, { title: 'To', render: (r) => badge(r.to) }, { title: 'Reason', key: 'reason' }], Array.isArray(history) ? history.slice(0, 40) : []))));
}

export async function component({ args }) {
  const d = await get(`/health/components/${encodeURIComponent(args[0])}`);
  return h('div', null, h('h1', null, d.component), h('p', { class: 'lead' }, badge(d.status), ' ', d.condition, ', certainty ', d.certainty, ', ', d.durability), h('p', null, d.reason), d.monitor_note ? note(d.monitor_note, 'warn') : null,
    card('Evidence', table([{ title: 'Source', key: 'source' }, { title: 'Value', key: 'value' }, { title: 'Freshness', render: (r) => badge(r.freshness) }, { title: 'Observed', render: (r) => when(r.observed_ms) }], d.evidence)),
    d.missing?.length ? card('Could not be observed', h('ul', { class: 'plain' }, d.missing.map((m) => h('li', null, m)))) : null,
    card('Recent changes', table([{ title: 'When', render: (r) => when(r.at_ms) }, { title: 'From', render: (r) => badge(r.from) }, { title: 'To', render: (r) => badge(r.to) }, { title: 'Reason', key: 'reason' }], d.recent_transitions)));
}

export async function audit({ params, go }) {
  const [data, verify] = await Promise.all([get('/audit', { size: 50, ...params }), get('/audit/verify')]);
  const rows = (d) => table([{ title: 'When', render: (r) => when(r.at) }, { title: 'Actor', key: 'actor' }, { title: 'Action', key: 'action' }, { title: 'Target', render: (r) => r.incident_id || r.path_id || r.asset_id || r.target }], d.slice(0, 100));
  return h('div', null, h('h1', null, 'Audit History'), h('p', { class: 'lead' }, 'Sign-ins and every change made here, then each service’s own trail. Changes made through the dashboard appear in those trails under the service account siem-dashboard.'),
    card('Chains', kv([['Dashboard', verify.dashboard.intact ? `Intact, ${verify.dashboard.entries} entries` : `Broken at ${verify.dashboard.first_broken}`], ['Incidents', part(verify.incidents, (v) => (v.intact ? `Intact, ${v.entries} entries` : `Broken at ${v.first_broken}`))]])),
    card('Dashboard', table([{ title: 'When', render: (r) => when(r.at_ms) }, { title: 'Actor', key: 'actor' }, { title: 'Action', key: 'action' }, { title: 'Target', key: 'target' }, { title: 'Outcome', render: (r) => badge(r.outcome === 'ok' ? 'ok' : 'stale', r.outcome, r.outcome) }, { title: 'Request', render: (r) => h('span', { class: 'mono' }, r.request_id) }], data.dashboard.rows), pager({ ...data.dashboard, total: { value: data.dashboard.offset + data.dashboard.rows.length + (data.dashboard.rows.length === data.dashboard.size ? 1 : 0) } }, (offset) => go('audit', { ...params, offset }))),
    h('div', { class: 'grid' }, card('Incidents', part(data.incidents, rows)), card('Attack paths', part(data.paths, rows)), card('Assets', part(data.assets, rows))));
}

export async function settings() {
  const current = h('input', { type: 'password', autocomplete: 'current-password', maxlength: 256, required: true });
  const next = h('input', { type: 'password', autocomplete: 'new-password', minlength: 14, maxlength: 256, required: true });
  const message = h('p', { role: 'status' });
  return h('div', null, h('h1', null, 'Settings'), card('Account', kv([['Name', session.user], ['Session ends', when(session.expires)]]), h('p', { class: 'dim' }, 'This is the dashboard administrator account. It has no connection to any operating system account. Sign-in is managed on the server with siem-dashboard-admin.')),
    card('Change password', h('form', { class: 'filters', on: { submit: async (e) => { e.preventDefault(); message.textContent = ''; try { await changePassword(current.value, next.value); message.textContent = 'Changed. Every other session has ended.'; } catch (failure) { message.textContent = failure.message; } current.value = ''; next.value = ''; } } }, h('label', null, 'Current password', current), h('label', null, 'New password, 14 characters or more', next), h('button', { class: 'btn primary', type: 'submit' }, 'Change')), message));
}

export async function search({ params }) {
  const d = await get('/search', { q: params.q });
  const block = (title, result, columns) => card(title, part(result, (rows) => table(columns, rows)));
  return h('div', null, h('h1', null, 'Search'), h('p', { class: 'lead' }, 'Exact lookups on IDs, hosts and addresses. Each result says where it came from.'),
    h('div', { class: 'grid' }, block('Alerts: stored alerts', d.alerts, [{ title: 'Rule', render: (r) => link(`#/alerts/${r.alert_id}`, r.rule_name) }, { title: 'Severity', render: (r) => badge(r.severity) }]), block('Incidents: incident records', d.incidents, [{ title: 'Incident', render: (r) => link(`#/incidents/${r.incident_id}`, r.title) }, { title: 'Status', render: (r) => badge(r.status) }]),
      block('Events: last 7 days', d.events, [{ title: 'Time', render: (r) => link(`#/events/${r.index}/${encodeURIComponent(r.id)}`, when(r.at)) }, { title: 'Source', key: 'dataset' }]), block('Assets: inventory', d.assets, [{ title: 'Asset', render: (r) => link(`#/assets/${r.asset_id}`, r.hostname) }, { title: 'Status', render: (r) => badge(r.status) }]),
      block('Attack paths', d.attack_paths, [{ title: 'Path', render: (r) => link(`#/paths/${r.path_id}`, r.title) }, { title: 'Tier', render: (r) => badge(r.tier) }]), block('Indicators: enrichment records', d.indicators, [{ title: 'Indicator', key: 'value' }, { title: 'Verdict', render: (r) => badge(r.verdict) }])));
}
