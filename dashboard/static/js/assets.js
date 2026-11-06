// Assets, from Phase 14. Nothing here merges an asset or resolves a conflict: those stay with the administrator's command.
import { get, post } from './api.js';
import { badge, card, confirmDialog, empty, filterBar, h, kv, link, none, note, pager, part, table, unavailable, when } from './ui.js';

const PARTS = { software: 'Software', services: 'Services', users: 'Identities', history: 'History', relationships: 'Relationships' };

function acknowledge(row, redraw) {
  return h('button', { class: 'btn', type: 'button', on: { click: () => confirmDialog('Mark as reviewed?', `You are recording that you reviewed this change: ${row.kind}.`, 'Mark reviewed', async () => { await post(`/assets/changes/${row.seq}/acknowledge`, {}); redraw(); }) } }, 'Mark reviewed');
}

export async function list({ params, go, redraw }) {
  const data = await get('/assets', { size: 50, ...params });
  const [changes, conflicts] = await Promise.allSettled([get('/assets/changes', { unreviewed: 'true' }), get('/assets/conflicts')]);
  return h('div', null, h('h1', null, 'Assets'), h('p', { class: 'lead' }, 'From the Phase 14 inventory. Assets are never joined here on a name, address or account.'),
    filterBar([{ key: 'q', title: 'Search' }, { key: 'status', title: 'Status', options: ['', 'active', 'new', 'stale', 'retired'] }, { key: 'platform', title: 'Platform', options: ['', 'windows', 'linux', 'unknown'] }], params, (v) => go('assets', v)),
    card(null, table([{ title: 'Asset', render: (r) => link(`#/assets/${r.asset_id}`, r.hostname) }, { title: 'Status', render: (r) => badge(r.status) }, { title: 'Platform', key: 'platform' }, { title: 'Type', key: 'asset_type' }, { title: 'Identity confidence', key: 'identity_confidence' }, { title: 'Criticality', render: (r) => r.criticality || none('not set') }, { title: 'Last seen', render: (r) => when(r.last_seen) }], data.rows), pager(data, (offset) => go('assets', { ...params, offset }))),
    h('div', { class: 'grid' },
      card('Changes to review', changes.status === 'fulfilled' ? table([{ title: 'When', render: (r) => when(r.at) }, { title: 'Change', key: 'kind' }, { title: 'Subject', key: 'subject' }, { title: 'Asset', render: (r) => link(`#/assets/${r.asset_id}`, 'Open') }, { title: '', render: (r) => acknowledge(r, redraw) }], changes.value) : unavailable(changes.reason.message)),
      card('Identity conflicts', h('p', { class: 'dim' }, 'Shown for review. They are resolved only by the administrator command, never here or automatically.'), conflicts.status === 'fulfilled' ? (conflicts.value.length ? table([{ title: 'Opened', key: 'opened' }, { title: 'Kind', key: 'kind' }, { title: 'Status', key: 'status' }], conflicts.value) : empty('No open conflict.')) : unavailable(conflicts.reason.message))));
}

async function loadPart(id, name, slot, offset = 0) {
  slot.replaceChildren(h('p', { class: 'empty' }, 'Loading…'));
  try {
    const d = await get(`/assets/${encodeURIComponent(id)}/${name}`, { size: 50, offset });
    const move = (next) => loadPart(id, name, slot, next);
    const seen = [{ title: 'First seen', render: (r) => when(r.first_seen) }, { title: 'Last seen', render: (r) => when(r.last_seen) }, { title: 'Source', key: 'source' }, { title: 'Confidence', key: 'confidence' }];
    if (name === 'users') return slot.replaceChildren(kv([['Assigned owner', d.assigned_owner || none('not set')]]), h('p', { class: 'dim' }, d.note), h('h3', null, 'Local accounts'), table([{ title: 'Name', key: 'name' }, { title: 'Local admin', render: (r) => String(r.local_admin) }, ...seen], d.local_accounts), h('h3', null, 'Observed users'), table([{ title: 'Name', key: 'name' }, { title: 'Domain', key: 'domain' }, { title: 'Type', key: 'type' }, ...seen], d.observed_users));
    const columns = { software: [{ title: 'Name', key: 'name' }, { title: 'Version', key: 'version' }, { title: 'Publisher', key: 'publisher' }, ...seen], services: [{ title: 'Name', key: 'name' }, { title: 'Display', key: 'display' }, { title: 'State', key: 'state' }, { title: 'Start', key: 'start' }, ...seen], history: [{ title: 'When', render: (r) => when(r.at) }, { title: 'Change', key: 'kind' }, { title: 'Category', key: 'category' }, { title: 'Subject', key: 'subject' }, { title: 'Before', key: 'before' }, { title: 'After', key: 'after' }, { title: 'Source', key: 'source' }], relationships: [{ title: 'From', render: (r) => r.source?.id }, { title: 'Type', key: 'type' }, { title: 'To', render: (r) => r.target?.id }, { title: 'Basis', key: 'basis' }, { title: 'Confidence', key: 'confidence' }, { title: 'Provenance', key: 'provenance' }, { title: 'Last seen', render: (r) => when(r.last_seen) }] }[name];
    return slot.replaceChildren(table(columns, d.rows), pager(d, move));
  } catch (e) {
    return slot.replaceChildren(unavailable(e.message));
  }
}

export async function detail({ args }) {
  const id = args[0];
  const d = await get(`/assets/${encodeURIComponent(id)}`);
  const a = d.asset;
  const slot = h('div');
  const tabs = h('div', { class: 'tabs', role: 'tablist' }, Object.entries(PARTS).map(([name, title]) => h('button', { type: 'button', role: 'tab', on: { click: (e) => { for (const b of tabs.children) b.classList.remove('on'); e.target.classList.add('on'); loadPart(id, name, slot); } } }, title)));
  const aliases = a.identity?.aliases || [];
  return h('div', null, h('h1', null, a.hostname), h('p', { class: 'lead' }, badge(a.status), ' ', a.platform, ' ', a.asset_type),
    a.merged_into ? note(`Merged into ${a.merged_into}.`, 'warn') : null,
    h('div', { class: 'grid' }, card('Asset', kv([['Asset ID', h('span', { class: 'mono' }, a.asset_id)], ['Operating system', [a.os_name, a.os_version].filter(Boolean).join(' ')], ['Identity confidence', a.identity_confidence], ['Owner', a.owner || none('not set')], ['Criticality', a.criticality || none('not set')], ['First seen', when(a.lifecycle?.first_seen)], ['Last seen', when(a.last_seen)], ['Last inventory', when(a.last_inventory_update)], ['Discovered by', a.lifecycle?.source_of_discovery]])),
      card('Names', table([{ title: 'Name', key: 'name' }, { title: 'Active', render: (r) => String(r.active) }, { title: 'Source', key: 'source' }, { title: 'First seen', render: (r) => when(r.first_seen) }, { title: 'Last seen', render: (r) => when(r.last_seen) }], aliases)),
      card('Addresses', table([{ title: 'Address', render: (r) => r.address || r.ip || r.value }, { title: 'From', render: (r) => when(r.first_seen || r.from) }, { title: 'To', render: (r) => (r.last_seen || r.to ? when(r.last_seen || r.to) : 'still held') }, { title: 'Source', key: 'source' }], a.network?.addresses || a.addresses || a.leases || []))),
    h('div', { class: 'grid' }, card('Alerts', part(d.alerts, (rows) => table([{ title: 'Rule', render: (r) => link(`#/alerts/${r.alert_id}`, r.rule_name) }, { title: 'Severity', render: (r) => badge(r.severity) }, { title: 'Detected', render: (r) => when(r.detected_at) }], rows))), card('Incidents', part(d.incidents, (rows) => table([{ title: 'Incident', render: (r) => link(`#/incidents/${r.incident_id}`, r.title) }, { title: 'Status', render: (r) => badge(r.status) }], rows))), card('Attack paths', part(d.paths, (rows) => table([{ title: 'Path', render: (r) => link(`#/paths/${r.path_id}`, r.title) }, { title: 'Tier', render: (r) => badge(r.tier) }], rows)))),
    card('Details', tabs, slot));
}
