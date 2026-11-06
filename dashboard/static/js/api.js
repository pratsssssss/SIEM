// The one path to the server. The session cookie is HttpOnly, so no script can read it. The CSRF value lives only in memory.
export const session = { user: null, csrf: null, expires: 0 };
let onExpired = () => {};
export const whenExpired = (fn) => { onExpired = fn; };

export class ApiError extends Error {
  constructor(message, status, requestId) { super(message); this.status = status; this.requestId = requestId; }
}

async function send(path, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 20000);
  let reply;
  try {
    reply = await fetch(`/api/v1${path}`, { credentials: 'same-origin', ...options, signal: controller.signal });
  } catch {
    throw new ApiError('The dashboard server cannot be reached', 0);
  } finally {
    clearTimeout(timer);
  }
  let body = null;
  try { body = await reply.json(); } catch { body = null; }
  if (!reply.ok) {
    if (reply.status === 401 && !path.startsWith('/auth/')) onExpired();
    throw new ApiError(body?.error?.message || 'The request failed', reply.status, body?.error?.request_id);
  }
  return body?.data;
}

export const get = (path, params) => {
  const query = new URLSearchParams(Object.entries(params || {}).filter(([, v]) => v !== '' && v !== undefined && v !== null)).toString();
  return send(query ? `${path}?${query}` : path);
};

export const post = (path, body) => send(path, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrf || '' }, body: JSON.stringify(body || {}) });

function remember(data) {
  session.user = data.authenticated ? data.username : null;
  session.csrf = data.authenticated ? data.csrf : null;
  session.expires = data.expires_ms || 0;
  return data;
}

export const loadSession = async () => remember(await get('/auth/session'));
export const login = async (username, password) => remember(await post('/auth/login', { username, password }));
export const logout = async () => remember(await post('/auth/logout'));
export const changePassword = async (current, next) => remember(await post('/auth/password', { current, new: next }));
