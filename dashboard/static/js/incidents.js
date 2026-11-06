// Incidents and the investigation workspace. Moves offered here come from the correlator's own table, and the correlator
// still validates each one: this page holds no incident state of its own.
import { get, post } from './api.js';
import { refs, indicators } from './explore.js';
import { ago, badge, card, confirmDialog, empty, filterBar, h, kv, link, none, note, pager, part, table, when } from './ui.js';

const CONSEQUENTIAL = { false_positive: 'This records the incident as a false positive.', resolved: 'This records the incident as resolved.', closed: 'This closes the incident.', contained: 'This records that containment happened. The SIEM takes no action on any host.' };
const CLASS = { verified: 'Backed by stored alerts', no_stored_alerts: 'No stored alert: a test fixture, or expired', not_checked: 'Not checked: OpenSearch is unavailable', no_alerts: 'No alerts listed' };
const columns = [{ title: 'Incident', render: (r) => link(`#/incidents/${r.incident_id}`, r.title) }, { title: 'Status', render: (r) => badge(r.status) }, { title: 'Severity', render: (r) => badge(r.severity) }, { title: 'Confidence', key: 'confidence_level' }, { title: 'First seen', render: (r) => when(r.first_seen) }, { title: 'Last seen', render: (r) => when(r.last_seen) }, { title: 'Hosts', render: (r) => (r.hosts || []).join(', ') }, { title: 'Alerts', key: 'alerts' }, { title: 'Record', render: (r) => (r.record_class ? CLASS[r.record_class] : null) }];

export async function list({ params, go }) {
  const data = await get('/incidents', { size: 50, ...params });
  return h('div', null, h('h1', null, 'Incidents'), h('p', { class: 'lead' }, 'Read from ', data.source, '.'),
    data.source !== 'opensearch' ? note('OpenSearch is unavailable, so this list comes from the incident service, and records are not checked against stored alerts.', 'warn') : null,
    data.unverified_hidden ? note(`${data.unverified_hidden} incidents with no stored alert are hidden as test fixtures.`) : null,
    filterBar([{ key: 'status', title: 'Status', options: ['', 'new', 'open', 'investigating', 'contained', 'resolved', 'closed', 'false_positive'] }, { key: 'severity', title: 'Severity', options: ['', 'critical', 'high', 'medium', 'low'] }, { key: 'include_unverified', title: 'Fixtures', options: [['', 'Hide'], ['true', 'Show']] }], params, (v) => go('incidents', v)),
    card(null, table(columns, data.rows), pager(data, (offset) => go('incidents', { ...params, offset }))));
}

export async function investigations() {
  const data = await get('/incidents', { size: 50 });
  const active = data.rows.filter((r) => ['new', 'open', 'investigating', 'contained'].includes(r.status));
  return h('div', null, h('h1', null, 'Investigations'), h('p', { class: 'lead' }, 'Incidents still in progress. Open one to work through its alerts, events, assets, paths and evidence.'), card(null, active.length ? table(columns, active) : empty('No incident is in progress.')));
}

function actions(d, id, redraw) {
  const record = d.incident;
  const text = h('textarea', { maxlength: 2000, 'aria-label': 'Note' });
  const error = h('p', { class: 'err', role: 'alert' });
  const move = (state) => async () => {
    const run = async () => { await post(`/incidents/${encodeURIComponent(id)}/status`, { state, note: text.value || undefined }); redraw(); };
    if (CONSEQUENTIAL[state]) confirmDialog(`Move to ${state.replace('_', ' ')}?`, CONSEQUENTIAL[state], 'Confirm', run);
    else { try { await run(); } catch (e) { error.textContent = e.message; } }
  };
  const moves = d.allowed_moves;
  return card('Actions', h('p', { class: 'dim' }, 'The incident service validates every move, and records it.', d.rules_available ? '' : ' Its table could not be read, so no moves are offered.'), text, error,
    h('div', { class: 'pager' }, h('button', { class: 'btn', type: 'button', on: { click: async () => { try { await post(`/incidents/${encodeURIComponent(id)}/notes`, { text: text.value }); redraw(); } catch (e) { error.textContent = e.message; } } } }, 'Add note'),
      (moves || []).map((state) => h('button', { class: 'btn', type: 'button', title: (d.needs_note || []).includes(state) ? 'Needs a note' : undefined, on: { click: move(state) } }, state.replace('_', ' ')))), record.status ? h('p', { class: 'dim' }, `Now ${record.status.replace('_', ' ')}.`) : null);
}

function timeline(record) {
  const rows = [...(record.timeline || [])].sort((a, b) => (a.ms || 0) - (b.ms || 0));
  return table([{ title: 'When', render: (r) => when(r.at) }, { title: 'What', render: (r) => (r.alert_id ? link(`#/alerts/${r.alert_id}`, r.rule || r.alert_id) : r.rule || r.event || r.kind) }, { title: 'Severity', render: (r) => (r.severity ? badge(r.severity) : null) }, { title: 'Host', key: 'host' }, { title: 'Basis', render: () => 'Correlated' }], rows.slice(0, 200));
}

export async function detail({ args, redraw }) {
  const id = args[0];
  const d = await get(`/incidents/${encodeURIComponent(id)}`);
  const r = d.incident;
  return h('div', null, h('h1', null, r.title), h('p', { class: 'lead' }, badge(r.status), ' ', badge(r.severity), ' ', CLASS[d.record_class] || ''), r.description ? h('p', null, r.description) : null,
    d.record_class === 'no_stored_alerts' ? note('None of this incident’s alerts are stored, so it is treated as a test fixture and left out of security counts.', 'warn') : null,
    h('div', { class: 'grid' }, card('Summary', kv([['Incident ID', h('span', { class: 'mono' }, r.incident_id)], ['Confidence', r.confidence !== undefined ? `${r.confidence} (${r.confidence_level})` : r.confidence_level], ['First seen', when(r.first_seen)], ['Last seen', when(r.last_seen)], ['Updated', when(r.updated_at)], ['Hosts', (r.hosts || []).join(', ')], ['Users', (r.users || []).join(', ')], ['Addresses', (r.ips || []).join(', ')], ['Processes', (r.processes || []).join(', ')], ['Revision', r.revision]])), actions(d, id, redraw)),
    (r.uncertain || []).length ? card('What is uncertain', h('ul', { class: 'plain' }, r.uncertain.map((u) => h('li', null, u)))) : null,
    h('div', { class: 'grid' }, card('Timeline', timeline(r)), card('Why these belong together', table([{ title: 'Rule', key: 'rule' }, { title: 'Joined on', key: 'join' }, { title: 'Reason', key: 'reason' }, { title: 'Basis', render: () => 'Correlated, not observed' }], (r.correlations || []).slice(0, 40)))),
    h('div', { class: 'grid' }, card('Alerts', part(d.alerts, (rows) => table([{ title: 'Rule', render: (a) => link(`#/alerts/${a.alert_id}`, a.rule_name) }, { title: 'Severity', render: (a) => badge(a.severity) }, { title: 'Event time', render: (a) => when(a.timestamp) }], rows))), card('Evidence', refs(d.evidence_refs))),
    h('div', { class: 'grid' }, card('Threat intelligence', part(d.enrichment, (rows) => (rows.length ? indicators(rows.flatMap((e) => e.indicators || [])) : empty('No enrichment recorded.')))), card('Attack paths', h('p', { class: 'dim' }, 'A path is a reconstruction, not proof of compromise.'), part(d.paths, (rows) => table([{ title: 'Path', render: (p) => link(`#/paths/${p.path_id}`, p.title) }, { title: 'Tier', render: (p) => badge(p.tier) }, { title: 'Built', render: (p) => ago(p.updated_at) }], rows))), card('Possible assets', h('p', { class: 'dim' }, 'Phase 14 search on the host names. A name alone does not prove identity.'), part(d.assets, (rows) => table([{ title: 'Asset', render: (a) => link(`#/assets/${a.asset_id}`, a.hostname) }, { title: 'Status', render: (a) => badge(a.status) }], rows)))),
    h('div', { class: 'grid' }, card('Analyst notes', (r.notes || []).length ? table([{ title: 'When', render: (n) => when(n.at) }, { title: 'By', key: 'by' }, { title: 'Note', key: 'text' }], r.notes) : empty('No notes.')), card('Audit history', part(d.audit, (rows) => table([{ title: 'When', render: (a) => when(a.at) }, { title: 'Actor', key: 'actor' }, { title: 'Action', key: 'action' }, { title: 'Hash', render: (a) => h('span', { class: 'mono' }, String(a.hash || '').slice(0, 12)) }], rows.slice(0, 100)))), h('div', null, none(''))));
}
