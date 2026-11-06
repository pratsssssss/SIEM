// Events and alerts.
import { get } from './api.js';
import { badge, card, empty, filterBar, h, kv, link, note, none, pager, part, table, when } from './ui.js';

const RANGES = ['1h', '6h', '24h', '7d', '30d'];

function listState(params, go, path, defaults) {
  const sort = params.sort || defaults.sort;
  const order = params.order || 'desc';
  return { sort: { key: sort, order }, onSort: (key) => go(path, { ...params, sort: key, order: sort === key && order === 'desc' ? 'asc' : 'desc', offset: '' }) };
}

export async function events({ params, go }) {
  const data = await get('/events', { size: 50, ...params, range: params.range || '24h' });
  const state = listState(params, go, 'events', { sort: 'time' });
  return h('div', null, h('h1', null, 'Events'), h('p', { class: 'lead' }, data.searched), note(data.restricted_note),
    filterBar([{ key: 'range', title: 'Time range', options: RANGES, default: '24h' }, { key: 'platform', title: 'Platform', options: ['', 'windows', 'linux'] }, { key: 'host', title: 'Host' }, { key: 'dataset', title: 'Source', placeholder: 'windows.security' }, { key: 'category', title: 'Category' }, { key: 'type', title: 'Type' }, { key: 'outcome', title: 'Outcome', options: ['', 'success', 'failure', 'unknown'] }, { key: 'level', title: 'Severity level', options: ['', 'Critical', 'Error', 'Warning', 'Information', 'Verbose'] }, { key: 'user', title: 'User' }, { key: 'process', title: 'Process' }, { key: 'source_ip', title: 'Source address' }, { key: 'event_id', title: 'Event ID' }], params, (v) => go('events', v)),
    card(null, table([{ title: 'Time', sort: 'time', render: (r) => link(`#/events/${r.index}/${encodeURIComponent(r.id)}`, when(r.at)) }, { title: 'Source', key: 'dataset' }, { title: 'Action', key: 'action' }, { title: 'Outcome', render: (r) => (r.outcome ? badge(r.outcome === 'failure' ? 'bad' : r.outcome === 'success' ? 'ok' : 'unknown', r.outcome, r.outcome) : null) }, { title: 'Host', render: (r) => (r.host ? link(`#/assets?q=${encodeURIComponent(r.host)}`, r.host) : null) }, { title: 'User', key: 'user' }, { title: 'Process', key: 'process' }, { title: 'Code', key: 'code' }], data.rows, state), pager(data, (offset) => go('events', { ...params, offset }))));
}

export async function event({ args }) {
  const [index, id] = args;
  const d = await get(`/events/${index}/${encodeURIComponent(id)}`);
  return h('div', null, h('h1', null, 'Event'), note(d.restricted_note),
    h('div', { class: 'grid' }, card('Summary', kv([['Time', when(d.row.at)], ['Ingested', when(d.row.ingested)], ['Source', d.row.dataset], ['Host', d.row.host], ['User', d.row.user], ['Action', d.row.action], ['Outcome', d.row.outcome]])),
      card('Provenance', kv([['Stored in', h('span', { class: 'mono' }, d.provenance.stored_in)], ['Document', h('span', { class: 'mono' }, d.id)], ['Kafka', d.provenance.kafka ? `${d.provenance.kafka.kafka?.topic ?? ''} partition ${d.provenance.kafka.kafka?.partition ?? '?'} offset ${d.provenance.kafka.kafka?.offset ?? '?'}` : null]]), h('p', { class: 'dim' }, d.provenance.sealed))),
    h('div', { class: 'grid' }, card('Related alerts', part(d.alerts, (rows) => table([{ title: 'Rule', render: (r) => link(`#/alerts/${r.alert_id}`, r.rule_name) }, { title: 'Severity', render: (r) => badge(r.severity) }], rows))), card('Possible assets', h('p', { class: 'dim' }, 'Found by Phase 14 search on the host name. A name alone does not prove identity.'), part(d.assets, (rows) => table([{ title: 'Asset', render: (r) => link(`#/assets/${r.asset_id}`, r.hostname) }, { title: 'Status', render: (r) => badge(r.status) }], rows)))),
    card('Permitted fields', table([{ title: 'Field', render: (r) => h('span', { class: 'mono' }, r[0]) }, { title: 'Value', render: (r) => (typeof r[1] === 'object' ? JSON.stringify(r[1]) : String(r[1])) }], Object.entries(d.fields))));
}

const VERDICT = (r) => (r.verdict ? badge(r.verdict) : none('no enrichment'));

export async function alerts({ params, go }) {
  const data = await get('/alerts', { size: 50, ...params, range: params.range || '7d' });
  const state = listState(params, go, 'alerts', { sort: 'detected' });
  return h('div', null, h('h1', null, 'Alerts'), h('p', { class: 'lead' }, 'Alerts are stored as detected. Nothing here changes them.'),
    filterBar([{ key: 'range', title: 'Time range', options: RANGES, default: '7d' }, { key: 'severity', title: 'Severity', options: ['', 'critical', 'high', 'medium', 'low', 'informational'] }, { key: 'host', title: 'Host' }, { key: 'user', title: 'User' }, { key: 'type', title: 'Category' }, { key: 'rule', title: 'Rule ID' }, { key: 'alert_id', title: 'Alert ID' }], params, (v) => go('alerts', v)),
    card(null, table([{ title: 'Detected', sort: 'detected', render: (r) => link(`#/alerts/${r.alert_id}`, when(r.detected_at)) }, { title: 'Event time', sort: 'event_time', render: (r) => when(r.timestamp) }, { title: 'Severity', sort: 'severity', render: (r) => badge(r.severity) }, { title: 'Rule', key: 'rule_name' }, { title: 'Category', key: 'detection_type' }, { title: 'Host', key: 'host' }, { title: 'User', key: 'user' }, { title: 'Intelligence', render: VERDICT }], data.rows, state), pager(data, (offset) => go('alerts', { ...params, offset }))));
}

export const refs = (rows) => (rows.length ? table([{ title: 'Stored evidence', render: (r) => (r.link ? link(`#/events/${r.index}/${encodeURIComponent(r.id)}`, `${r.index} / ${r.id.slice(0, 16)}`) : `${r.text} (not a link)`) }], rows) : empty('No evidence references.'));

export function indicators(rows) {
  return table([{ title: 'Indicator', render: (r) => h('span', { class: 'mono' }, r.value) }, { title: 'Type', key: 'type' }, { title: 'Verdict', render: (r) => badge(r.verdict) }, { title: 'Score', key: 'score' }, { title: 'Sources failed', render: (r) => (r.sources_failed || []).join(', ') }], rows);
}

export async function alert({ args }) {
  const d = await get(`/alerts/${encodeURIComponent(args[0])}`);
  const a = d.alert;
  return h('div', null, h('h1', null, a.rule_name), h('p', { class: 'lead' }, badge(a.severity), ' ', a.description),
    h('div', { class: 'grid' }, card('Alert', kv([['Alert ID', h('span', { class: 'mono' }, a.alert_id)], ['Rule ID', h('span', { class: 'mono' }, a.rule_id)], ['Category', a.detection_type], ['Confidence', a.confidence], ['Event time', when(a.timestamp)], ['Detected', when(a.detected_at)], ['Host', a.host], ['User', a.user], ['Source address', a.source_ip], ['Events', a.event_count], ['ATT&CK', [...(a.mitre?.tactics || []), ...(a.mitre?.techniques || [])].join(', ')]])),
      card('Why it fired', note(d.matched_fields_note), kv([['Fields the rule used', (a.evidence?.rule_fields || []).join(', ')], ['First seen', when(a.evidence?.first_seen)], ['Last seen', when(a.evidence?.last_seen)]]))),
    h('div', { class: 'grid' }, card('Evidence', refs(d.evidence_refs)),
      card('Threat intelligence', part(d.enrichment, (e) => (e ? [h('p', { class: 'dim' }, e.untrusted_notice), kv([['Highest verdict', badge(e.summary?.highest_verdict)], ['Enriched', when(e.enriched_at)]]), indicators(e.indicators || [])] : empty('Not enriched.'))))),
    h('div', { class: 'grid' }, card('Incidents', part(d.incidents, (rows) => table([{ title: 'Incident', render: (r) => link(`#/incidents/${r.incident_id}`, r.title) }, { title: 'Status', render: (r) => badge(r.status) }], rows))), card('Attack paths', part(d.paths, (rows) => table([{ title: 'Path', render: (r) => link(`#/paths/${r.path_id}`, r.title) }, { title: 'Tier', render: (r) => badge(r.tier) }], rows))),
      card('Possible assets', part(d.assets, (rows) => table([{ title: 'Asset', render: (r) => link(`#/assets/${r.asset_id}`, r.hostname) }, { title: 'Status', render: (r) => badge(r.status) }], rows)))));
}
