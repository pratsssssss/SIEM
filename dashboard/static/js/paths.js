// Attack paths: a readable graph, with a table and timeline for the same data. No tier means compromise, and the page says so.
import { get, post } from './api.js';
import { ago, badge, card, empty, filterBar, h, kv, link, note, pager, part, table, unavailable, when } from './ui.js';

const TIERS = ['', 'confirmed_observation', 'strongly_supported', 'plausible_inferred', 'weak_hypothesis', 'insufficient_evidence'];
const MAX_DRAWN = 250;

export async function list({ params, go }) {
  const data = await get('/attack-paths', { size: 50, ...params });
  return h('div', null, h('h1', null, 'Attack Paths'), note('A path reconstructs what the evidence shows. A tier grades the evidence. It does not state that a host was compromised.'),
    filterBar([{ key: 'tier', title: 'Tier', options: TIERS }], params, (v) => go('paths', v)),
    card(null, table([{ title: 'Path', render: (r) => link(`#/paths/${r.path_id}`, r.title) }, { title: 'Tier', render: (r) => badge(r.tier) }, { title: 'From', key: 'seed_kind' }, { title: 'Version', key: 'version' }, { title: 'Updated', render: (r) => ago(r.updated_at) }], data.rows), pager(data, (offset) => go('paths', { ...params, offset }))));
}

// Columns by the first time each node was seen in an edge, so left to right reads as earlier to later.
function layout(nodes, edges) {
  const first = new Map();
  for (const e of edges) for (const id of [e.source, e.target]) if (e.first_ms && (!first.has(id) || e.first_ms < first.get(id))) first.set(id, e.first_ms);
  const order = [...new Set([...first.values()])].sort((a, b) => a - b);
  const groups = order.length > 7 ? 7 : Math.max(order.length, 1);
  const column = (id) => (first.has(id) ? Math.min(groups - 1, Math.floor(order.indexOf(first.get(id)) * groups / order.length)) : 0);
  const rows = new Map();
  const place = new Map();
  for (const node of nodes) {
    const c = column(node.id);
    const r = rows.get(c) || 0;
    rows.set(c, r + 1);
    place.set(node.id, { x: 20 + c * 190, y: 20 + r * 58 });
  }
  return { place, width: 20 + groups * 190, height: 40 + Math.max(...rows.values(), 1) * 58 };
}

const edgeClass = (e) => (e.basis === 'observed' || e.class === 'observed' ? 'observed' : e.class === 'inferred' || e.basis === 'inferred' ? 'inferred' : 'interpretation');

function graphView(graph, inspect, filters) {
  const nodes = graph.nodes.filter((n) => !filters.nodes.has(n.type));
  const shown = new Set(nodes.map((n) => n.id));
  const edges = graph.edges.filter((e) => !filters.edges.has(e.type) && shown.has(e.source) && shown.has(e.target));
  if (nodes.length > MAX_DRAWN) return note(`${nodes.length} nodes is too many to draw clearly. Use the table below, or filter by type.`, 'warn');
  if (!nodes.length) return empty('Every node is filtered out.');
  const { place, width, height } = layout(nodes, edges);
  const items = [];
  const select = (el, value, kind) => { for (const s of el.ownerSVGElement.querySelectorAll('.sel')) s.classList.remove('sel'); el.classList.add('sel'); inspect(kind, value); };
  for (const edge of edges) {
    const a = place.get(edge.source); const b = place.get(edge.target);
    const line = h('path', { svg: true, class: `edge ${edgeClass(edge)}`, d: `M${a.x + 150},${a.y + 19} C${a.x + 180},${a.y + 19} ${b.x - 30},${b.y + 19} ${b.x},${b.y + 19}`, tabindex: 0, role: 'button', 'aria-label': `${edge.type}, ${edge.basis}`, on: { click: (e) => select(e.currentTarget, edge, 'edge'), keydown: (e) => { if (e.key === 'Enter') select(e.currentTarget, edge, 'edge'); } } }, h('title', { svg: true }, `${edge.type} (${edge.tier})`));
    items.push(line);
  }
  for (const node of nodes) {
    const p = place.get(node.id);
    const label = String(node.display || node.key || node.id);
    items.push(h('g', { svg: true, class: 'node', transform: `translate(${p.x},${p.y})`, tabindex: 0, role: 'button', 'aria-label': `${node.type}: ${label}`, on: { click: (e) => select(e.currentTarget, node, 'node'), keydown: (e) => { if (e.key === 'Enter') select(e.currentTarget, node, 'node'); } } },
      h('rect', { svg: true, width: 150, height: 38, rx: 5 }), h('text', { svg: true, class: 't', x: 7, y: 13 }, node.type), h('text', { svg: true, x: 7, y: 29 }, label.length > 24 ? `${label.slice(0, 23)}…` : label), h('title', { svg: true }, label)));
  }
  return h('div', { class: 'graph-scroll' }, h('svg', { svg: true, class: 'graph', width, height, viewBox: `0 0 ${width} ${height}`, role: 'group', 'aria-label': 'Attack path graph. The same data is in the tables below.' }, items));
}

const nodeLink = (n) => {
  if (n.type === 'alert') return link(`#/alerts/${String(n.key).replace(/^alert:/, '')}`, 'Open alert');
  if (n.type === 'incident') return link(`#/incidents/${String(n.key).replace(/^incident:/, '')}`, 'Open incident');
  if (n.type === 'asset' && !String(n.key).startsWith('unresolved')) return link(`#/assets/${String(n.key).replace(/^asset:/, '')}`, 'Open asset');
  return null;
};

async function inspector(id, panel, kind, value) {
  if (kind === 'node') {
    panel.replaceChildren(h('h2', null, 'Node'), kv([['Type', value.type], ['Name', value.display], ['Key', h('span', { class: 'mono' }, value.key)], ['Resolved', value.resolved === undefined ? null : String(value.resolved)], ['Ambiguous', value.ambiguous === undefined ? null : String(value.ambiguous)]]), nodeLink(value));
    return;
  }
  panel.replaceChildren(h('h2', null, `Edge: ${value.type}`), kv([['Basis', badge(value.basis)], ['Class', value.class], ['Tier', badge(value.tier)], ['First seen', when(value.first_ms)], ['Last seen', when(value.last_ms)], ['State', value.state]]), h('p', null, value.reason), h('p', { class: 'dim' }, 'Loading evidence…'));
  try {
    const rows = await get(`/attack-paths/${encodeURIComponent(id)}/evidence`, { edge: value.id });
    const items = rows.flatMap((r) => r.evidence || []);
    panel.lastChild.replaceWith(h('div', null, h('h3', null, 'Evidence'), items.length ? table([{ title: 'Kind', key: 'kind' }, { title: 'State', render: (e) => badge(e.state === 'verified' ? 'ok' : e.state === 'changed' ? 'bad' : 'stale', e.state, e.state) }, { title: 'Source', render: (e) => (e.kind === 'event' ? link(`#/events/${e.index}/${encodeURIComponent(e.id)}`, when(e.source_time)) : e.kind === 'alert' ? link(`#/alerts/${e.id}`, when(e.source_time)) : when(e.source_time)) }, { title: 'Provenance', key: 'provenance' }], items) : empty('No evidence listed.'),
      (value.contradicting || []).length ? h('div', null, h('h3', null, 'Contradicting'), h('ul', { class: 'plain' }, value.contradicting.map((c) => h('li', null, typeof c === 'string' ? c : JSON.stringify(c))))) : null));
  } catch (e) {
    panel.lastChild.replaceWith(unavailable(e.message));
  }
}

function checks(title, values, filter, redraw) {
  return h('fieldset', { class: 'card' }, h('legend', null, title), values.map((v) => h('label', null, h('input', { type: 'checkbox', checked: !filter.has(v), on: { change: (e) => { if (e.target.checked) filter.delete(v); else filter.add(v); redraw(); } } }), ` ${v}  `)));
}

export async function detail({ args, redraw }) {
  const id = args[0];
  const d = await get(`/attack-paths/${encodeURIComponent(id)}`);
  const graph = d.graph;
  const panel = h('section', { class: 'card', 'aria-live': 'polite' }, h('p', { class: 'dim' }, 'Select a node or edge. Solid lines were observed. Dashed were inferred. Dotted are a rule’s or analyst’s interpretation.'));
  const filters = { nodes: new Set(), edges: new Set() };
  const slot = h('div');
  const draw = () => slot.replaceChildren(graphView(graph, (kind, value) => inspector(id, panel, kind, value), filters));
  draw();
  const text = h('textarea', { maxlength: 2000, 'aria-label': 'Note' });
  const error = h('p', { class: 'err', role: 'alert' });
  return h('div', null, h('h1', null, 'Attack path'), note(`${d.limit_note} Conclusion stored by the engine: ${graph.conclusion}.`, 'warn'), h('p', { class: 'lead' }, badge(graph.tier)),
    part(d.explain, (x) => h('div', { class: 'grid' }, card('Why this tier', h('ul', { class: 'plain' }, (x.why_this_tier || []).map((w) => h('li', null, w))), h('p', { class: 'dim' }, x.evidence_state)), card('What cannot be seen', (x.not_visible || []).length ? h('ul', { class: 'plain' }, x.not_visible.map((g) => h('li', null, g.meaning))) : empty('No gap recorded.')), card('Doubts', (x.doubts || []).length ? h('ul', { class: 'plain' }, x.doubts.map((c) => h('li', null, `${c.text} (${c.weight})`))) : empty('No contradiction recorded.')), card('ATT&CK and next steps', h('p', null, (x.attack_techniques || []).join(', ') || 'No technique justified by the evidence.'), h('ul', { class: 'plain' }, (x.next_steps || []).map((s) => h('li', null, s)))))),
    h('div', { class: 'grid' }, checks('Node types', [...new Set(graph.nodes.map((n) => n.type))], filters.nodes, draw), checks('Edge types', [...new Set(graph.edges.map((e) => e.type))], filters.edges, draw)),
    h('div', { class: 'graph-wrap' }, slot, panel),
    card('Timeline', part(d.timeline, (rows) => table([{ title: '#', key: 'order' }, { title: 'When', render: (r) => when(r.at) }, { title: 'Stage', key: 'name' }, { title: 'Tactic', key: 'tactic' }, { title: 'Tier', render: (r) => badge(r.tier) }, { title: 'Explanation', key: 'explanation' }, { title: 'Techniques', render: (r) => (r.techniques || []).map((t) => `${t.id} (${t.source})`).join(', ') }], rows))),
    card('Edges, as a table', table([{ title: 'From', render: (e) => graph.nodes.find((n) => n.id === e.source)?.display }, { title: 'Edge', key: 'type' }, { title: 'To', render: (e) => graph.nodes.find((n) => n.id === e.target)?.display }, { title: 'Basis', render: (e) => badge(e.basis) }, { title: 'Tier', render: (e) => badge(e.tier) }, { title: 'First seen', render: (e) => when(e.first_ms) }, { title: 'State', key: 'state' }, { title: 'Evidence', key: 'evidence_count' }], graph.edges)),
    card('Your note', h('p', { class: 'dim' }, 'Kept apart from what the engine worked out.'), text, error, h('button', { class: 'btn', type: 'button', on: { click: async () => { try { await post(`/attack-paths/${encodeURIComponent(id)}/notes`, { text: text.value }); redraw(); } catch (e) { error.textContent = e.message; } } } }, 'Add note')),
    card('Versions', part(d.history, (rows) => table([{ title: 'Version', key: 'version' }, { title: 'When', render: (r) => when(r.at || r.at_ms) }, { title: 'Tier', render: (r) => badge(r.tier) }, { title: 'Why', key: 'reason' }], rows.slice(0, 30)))));
}
