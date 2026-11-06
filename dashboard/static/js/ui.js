// Building blocks. Every value reaches the page as text, through h(): nothing here parses a string as markup, so an
// event, alert or graph label can never become HTML.
const SVG = 'http://www.w3.org/2000/svg';

export function h(tag, attrs, ...children) {
  const svg = attrs && attrs.svg;
  const node = svg ? document.createElementNS(SVG, tag) : document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (key === 'svg' || value === undefined || value === null || value === false) continue;
    if (key === 'on') for (const [name, fn] of Object.entries(value)) node.addEventListener(name, fn);
    else if (key === 'class') node.setAttribute('class', value);
    else if (key === 'href') node.setAttribute('href', safeHref(value));
    else if (key.startsWith('on')) throw new Error('use the on map');
    else if (key === 'value') node.value = value;
    else if (value === true) node.setAttribute(key, '');
    else node.setAttribute(key, String(value));
  }
  append(node, children);
  return node;
}

function append(node, children) {
  for (const child of children.flat(3)) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
}

// Links are built by this application. Anything else is refused, so a value from an event cannot become a javascript: URL.
export function safeHref(value) {
  return typeof value === 'string' && value.startsWith('#/') ? value : '#/';
}

export const link = (route, text) => h('a', { href: route }, text ?? route);
export const none = (text = 'not recorded') => h('span', { class: 'dim' }, text);
export const shown = (value, text) => (value === null || value === undefined || value === '' ? none(text) : value);

const clsName = (value) => 's-' + String(value).replace(/[^A-Za-z0-9_]/g, '_');
export const badge = (value, title, label) => (value === null || value === undefined || value === '' ? none() : h('span', { class: `badge ${clsName(value)}`, title }, String(label ?? value).replaceAll('_', ' ')));

let zone = 'UTC';
try { zone = localStorage.getItem('zone') === 'local' ? 'local' : 'UTC'; } catch { zone = 'UTC'; }
export const timeZone = () => zone;
export function setZone(next) {
  zone = next;
  try { localStorage.setItem('zone', next); } catch { /* A preference only. */ }
}

export function when(value) {
  if (value === null || value === undefined || value === '') return none();
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  const text = zone === 'UTC' ? date.toISOString().slice(0, 19).replace('T', ' ') + ' UTC' : date.toLocaleString();
  return h('span', { title: date.toISOString() }, text);
}

export function ago(value) {
  if (!value) return none('never');
  const seconds = Math.round((Date.now() - new Date(value).getTime()) / 1000);
  if (!Number.isFinite(seconds)) return String(value);
  if (seconds < 0) return h('span', { class: 's-stale', title: 'Dated in the future, so the clocks disagree' }, 'in the future');
  if (seconds < 120) return `${seconds} s ago`;
  if (seconds < 7200) return `${Math.round(seconds / 60)} min ago`;
  if (seconds < 172800) return `${Math.round(seconds / 3600)} h ago`;
  return `${Math.round(seconds / 86400)} days ago`;
}

export const kv = (rows) => h('dl', { class: 'kv' }, rows.filter(Boolean).map(([key, value]) => [h('dt', null, key), h('dd', null, value === null || value === undefined || value === '' ? none() : value)]));
export const card = (title, ...body) => h('section', { class: 'card' }, title ? h('h2', null, title) : null, ...body);
export const stat = (value, label) => h('div', { class: 'stat' }, h('b', null, value === null || value === undefined ? '—' : value), h('span', null, label));
export const note = (text, kind = '') => h('p', { class: `note ${kind}` }, text);
export const empty = (text = 'Nothing to show.') => h('p', { class: 'empty' }, text);
export const unavailable = (text) => h('p', { class: 'unavailable' }, `Unavailable: ${text}. This is not the same as none.`);
export const loading = () => h('p', { class: 'empty', role: 'status' }, 'Loading…');
export const errorBlock = (error) => h('p', { class: 'err', role: 'alert' }, error.message || 'Something went wrong', error.requestId ? h('span', { class: 'dim mono' }, `  (request ${error.requestId})`) : null);

// A section from the API: it either holds data, or says why it does not.
export function part(result, render) {
  if (!result) return unavailable('not returned');
  if (result.status === 'ok') return render(result.data);
  if (result.status === 'missing') return empty('None found.');
  return unavailable(result.reason || 'not available');
}

export function table(columns, rows, { onRow, sort, onSort } = {}) {
  if (!rows || !rows.length) return empty();
  const head = h('tr', null, columns.map((c) => h('th', { scope: 'col', 'aria-sort': sort && sort.key === c.sort ? (sort.order === 'asc' ? 'ascending' : 'descending') : undefined },
    c.sort && onSort ? h('button', { type: 'button', on: { click: () => onSort(c.sort) } }, c.title, sort && sort.key === c.sort ? (sort.order === 'asc' ? ' ▲' : ' ▼') : '') : c.title)));
  const body = rows.map((row) => {
    const cells = columns.map((c) => { const value = c.render ? c.render(row) : row[c.key]; return h('td', null, value === null || value === undefined || value === '' ? none('—') : value); });
    const attrs = onRow ? { class: 'click', tabindex: 0, on: { click: (e) => { if (e.target.tagName !== 'A') onRow(row); }, keydown: (e) => { if (e.key === 'Enter') onRow(row); } } } : null;
    return h('tr', attrs, cells);
  });
  return h('div', { class: 'scroll' }, h('table', null, h('thead', null, head), h('tbody', null, body)));
}

export function pager(result, onMove) {
  const total = result.total?.value ?? 0;
  const capped = result.total?.relation === 'gte';
  const first = total ? result.offset + 1 : 0;
  const last = Math.min(result.offset + result.size, total);
  return h('div', { class: 'pager' }, h('button', { class: 'btn', type: 'button', disabled: result.offset <= 0, on: { click: () => onMove(Math.max(0, result.offset - result.size)) } }, 'Previous'),
    h('span', null, `${first}–${last} of ${total}${capped ? '+' : ''}`),
    h('button', { class: 'btn', type: 'button', disabled: last >= total, on: { click: () => onMove(result.offset + result.size) } }, 'Next'));
}

export function filterBar(fields, values, onApply) {
  const inputs = {};
  const form = h('form', { class: 'filters', on: { submit: (e) => { e.preventDefault(); const next = {}; for (const [k, el] of Object.entries(inputs)) if (el.value) next[k] = el.value; onApply(next); } } },
    fields.map((f) => {
      const input = f.options
        ? h('select', { name: f.key }, f.options.map((o) => { const [v, t] = Array.isArray(o) ? o : [o, o || 'Any']; return h('option', { value: v }, t); }))
        : h('input', { name: f.key, maxlength: 256, placeholder: f.placeholder || '', size: f.size || 16 });
      input.value = values[f.key] ?? f.default ?? '';
      inputs[f.key] = input;
      return h('label', null, f.title, input);
    }), h('button', { class: 'btn primary', type: 'submit' }, 'Apply'));
  return form;
}

export function confirmDialog(title, body, action, run) {
  const error = h('p', { class: 'err' });
  const dialog = h('dialog', null, h('h2', null, title), h('p', null, body), error, h('div', { class: 'pager' },
    h('button', { class: 'btn', type: 'button', on: { click: () => { dialog.close(); dialog.remove(); } } }, 'Cancel'),
    h('button', { class: 'btn primary', type: 'button', on: { click: async () => { try { await run(); dialog.close(); dialog.remove(); } catch (e) { error.textContent = e.message; } } } }, action)));
  document.body.append(dialog);
  dialog.showModal();
}

export function bars(points) {
  const width = Math.max(points.length * 8, 120);
  const top = Math.max(1, ...points.map((p) => p.count));
  const rects = points.map((p, i) => h('rect', { svg: true, x: i * 8, y: 90 - (p.count / top) * 86, width: 6, height: Math.max((p.count / top) * 86, p.count ? 2 : 0) }, h('title', { svg: true }, `${p.at}: ${p.count}`)));
  return h('svg', { svg: true, class: 'bars', viewBox: `0 0 ${width} 90`, preserveAspectRatio: 'none', role: 'img', 'aria-label': 'Alerts over time' }, rects);
}
