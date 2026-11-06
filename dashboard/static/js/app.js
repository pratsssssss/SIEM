// The shell: sign-in, navigation, routing. State lives in the address, so refresh and Back keep an investigation in place.
import { loadSession, login, logout, session, whenExpired } from './api.js';
import { errorBlock, h, link, loading, setZone, timeZone } from './ui.js';
import * as overview from './overview.js';
import * as explore from './explore.js';
import * as incidents from './incidents.js';
import * as paths from './paths.js';
import * as assets from './assets.js';
import * as system from './system.js';

const NAV = [['Overview', '#/overview'], ['Events', '#/events'], ['Alerts', '#/alerts'], ['Incidents', '#/incidents'], ['Investigations', '#/investigations'], ['Attack Paths', '#/paths'], ['Assets', '#/assets'], ['Threat Intelligence', '#/intelligence'], ['Pipeline Health', '#/health'], ['Audit History', '#/audit'], ['Settings', '#/settings']];
const ROUTES = [
  [/^overview$/, overview.page], [/^events$/, explore.events], [/^events\/([^/]+)\/([^/]+)$/, explore.event], [/^alerts$/, explore.alerts], [/^alerts\/([^/]+)$/, explore.alert],
  [/^incidents$/, incidents.list], [/^incidents\/([^/]+)$/, incidents.detail], [/^investigations$/, incidents.investigations],
  [/^paths$/, paths.list], [/^paths\/([^/]+)$/, paths.detail], [/^assets$/, assets.list], [/^assets\/([^/]+)$/, assets.detail],
  [/^intelligence$/, system.intelligence], [/^health$/, system.health], [/^health\/([^/]+)$/, system.component], [/^audit$/, system.audit], [/^settings$/, system.settings], [/^search$/, system.search],
];
const root = document.getElementById('root');
let content = null;
let refresh = null;
let current = 0;

export function route() {
  const raw = location.hash.replace(/^#\//, '') || 'overview';
  const [path, query] = raw.split('?');
  return { path, params: Object.fromEntries(new URLSearchParams(query || '')) };
}

export function go(path, params) {
  const query = new URLSearchParams(Object.entries(params || {}).filter(([, v]) => v !== '' && v !== undefined)).toString();
  location.hash = `#/${path}${query ? `?${query}` : ''}`;
}

// Where this investigation has been, kept for this tab only.
function trail(path) {
  let steps = [];
  try { steps = JSON.parse(sessionStorage.getItem('trail') || '[]'); } catch { steps = []; }
  if (/^(incidents|alerts|events|assets|paths)\/.+/.test(path)) {
    const at = steps.indexOf(path);
    steps = at >= 0 ? steps.slice(0, at + 1) : [...steps, path].slice(-6);
    try { sessionStorage.setItem('trail', JSON.stringify(steps)); } catch { /* Only a convenience. */ }
  }
  return steps;
}

function trailBar(path) {
  const steps = trail(path);
  if (!steps.length) return null;
  const kinds = { incidents: 'Incident', alerts: 'Alert', events: 'Event', assets: 'Asset', paths: 'Path' };
  return h('div', { class: 'trail', 'aria-label': 'Investigation trail' }, 'Trail:', steps.map((s, i) => [i ? h('span', { class: 'sep' }, '›') : null, link(`#/${s}`, `${kinds[s.split('/')[0]]} ${s.split('/').pop().slice(0, 10)}`)]));
}

async function render() {
  const mine = ++current;
  if (refresh) { clearInterval(refresh); refresh = null; }
  const { path, params } = route();
  for (const a of document.querySelectorAll('nav.side a')) a.classList.toggle('on', path.split('/')[0] === a.getAttribute('href').slice(2).split('?')[0]);
  const match = ROUTES.map(([pattern, page]) => [path.match(pattern), page]).find(([m]) => m);
  content.replaceChildren(loading());
  if (!match) { content.replaceChildren(h('p', { class: 'empty' }, 'No such page.')); return; }
  const [found, page] = match;
  try {
    const args = found.slice(1).map(decodeURIComponent);
    const node = await page({ params, args, go, setRefresh: (fn, seconds) => { refresh = setInterval(() => { if (!document.hidden) fn(); }, seconds * 1000); }, redraw: render });
    if (mine === current) content.replaceChildren(trailBar(path) || '', node);
  } catch (error) {
    if (mine === current) content.replaceChildren(errorBlock(error));
  }
}

function shell() {
  const box = h('input', { type: 'search', name: 'q', maxlength: 128, placeholder: 'ID, host, address or indicator', 'aria-label': 'Search' });
  const zone = h('button', { class: 'btn', type: 'button', title: 'Show times in UTC or this browser’s zone', on: { click: () => { setZone(timeZone() === 'UTC' ? 'local' : 'UTC'); zone.textContent = timeZone() === 'UTC' ? 'UTC' : 'Local'; render(); } } }, timeZone() === 'UTC' ? 'UTC' : 'Local');
  content = h('main', { id: 'main' });
  root.replaceChildren(h('div', { class: 'shell' },
    h('nav', { class: 'side', 'aria-label': 'Main' }, h('div', { class: 'brand' }, 'SIEM Analyst'), NAV.map(([title, href]) => h('a', { href }, title))),
    h('div', null,
      h('div', { class: 'top' }, h('form', { role: 'search', on: { submit: (e) => { e.preventDefault(); if (box.value.trim()) go('search', { q: box.value.trim() }); } } }, box, h('button', { class: 'btn', type: 'submit' }, 'Search')),
        h('div', { class: 'who' }, zone, h('span', null, session.user), h('button', { class: 'btn', type: 'button', on: { click: async () => { try { await logout(); } finally { signIn(); } } } }, 'Sign out'))),
      content)));
  render();
}

function signIn(message) {
  sessionStorage.removeItem('trail');
  if (refresh) { clearInterval(refresh); refresh = null; }
  const user = h('input', { name: 'username', autocomplete: 'username', required: true, maxlength: 64 });
  const pass = h('input', { name: 'password', type: 'password', autocomplete: 'current-password', required: true, maxlength: 256 });
  const error = h('p', { class: 'err', role: 'alert' }, message || '');
  const button = h('button', { class: 'btn primary', type: 'submit' }, 'Sign in');
  root.replaceChildren(h('form', { class: 'login', on: { submit: async (e) => {
    e.preventDefault();
    error.textContent = '';
    button.disabled = true;
    try { await login(user.value, pass.value); pass.value = ''; shell(); } catch (failure) { error.textContent = failure.message; pass.value = ''; button.disabled = false; }
  } } }, h('h1', null, 'SIEM Analyst Dashboard'), h('p', { class: 'dim' }, 'Sign in with the dashboard administrator account. This is not an operating system account.'),
  h('label', null, 'Name', user), h('label', null, 'Password', pass), error, button));
  user.focus();
}

whenExpired(() => signIn('Your session has ended. Sign in to continue.'));
window.addEventListener('hashchange', () => { if (content) render(); });
loadSession().then((state) => (state.authenticated ? shell() : signIn())).catch((failure) => { root.replaceChildren(errorBlock(failure)); });
