"""The HTTPS server and the API. Standard library only, so this adds no package to the host.

Order on every request: size, rate, session, CSRF, validation, then the work. The identity on a request comes from the
session and nothing else: a name, role or actor in a body or header is ignored, and no route reads one.
"""
import hmac
import ipaddress
import json
import mimetypes
import re
import secrets
import signal
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlsplit

from .auth import Auth, AuthError
from .backends import Health, NotFound, OpenSearch, Rejected, Sockets, Unavailable, incident_rules
from .config import load
from .data import BadInput, Data, identifier, section

API = '/api/v1'
COOKIE = '__Host-siem_session'
HEADERS = {
    'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'geolocation=(), camera=(), microphone=()', 'Cross-Origin-Opener-Policy': 'same-origin', 'Cross-Origin-Resource-Policy': 'same-origin',
}
TOKEN = re.compile(r'^[A-Za-z0-9_\-]{20,128}$')
NOTE_LIMIT = 2000


class Problem(Exception):
    def __init__(self, status, message, code=None):
        super().__init__(message)
        self.status, self.message, self.code = status, message, code


class Limiter:
    """A fixed one-minute count per key, bounded in size."""

    def __init__(self, clock):
        self.clock = clock
        self.rows = {}
        self.lock = threading.Lock()

    def allow(self, key, limit):
        minute = self.clock() // 60000
        with self.lock:
            if len(self.rows) > 1000:
                self.rows.clear()
            row = self.rows.get(key)
            if not row or row[0] != minute:
                self.rows[key] = [minute, 1]
                return True
            row[1] += 1
            return row[1] <= limit


class App:
    def __init__(self, config, auth, data, rules=None, clock=None):
        self.config = config
        self.auth = auth
        self.data = data
        self.rules = rules
        self.clock = clock or (lambda: int(time.time() * 1000))
        self.limiter = Limiter(self.clock)
        self.strict_transport = not ipaddress.ip_address(config['listen']['host']).is_loopback
        self.static = {}
        root = Path(config['static_dir'])
        if root.is_dir():
            for path in root.rglob('*'):
                if path.is_file() and not path.is_symlink():
                    self.static['/' + path.relative_to(root).as_posix()] = path
        self.static['/'] = root / 'index.html'
        self.routes = [
            ('GET', r'/overview', self.overview), ('GET', r'/search', self.search),
            ('GET', r'/events', lambda r: self.data.events(r.params)), ('GET', r'/events/([^/]+)/([^/]+)', lambda r, i, e: self.data.event(i, e)),
            ('GET', r'/alerts', lambda r: self.data.alerts(r.params)), ('GET', r'/alerts/([^/]+)', lambda r, a: self.data.alert(a)),
            ('GET', r'/incidents', lambda r: self.data.incidents(r.params)), ('GET', r'/incidents/([^/]+)', lambda r, i: self.data.incident_view(i, self.rules)), ('GET', r'/incidents/([^/]+)/audit', lambda r, i: self.data.incident_audit(i)),
            ('POST', r'/incidents/([^/]+)/status', self.incident_status), ('POST', r'/incidents/([^/]+)/notes', self.incident_note),
            ('GET', r'/investigations/alert/([^/]+)', lambda r, a: self.data.alert(a)),
            ('GET', r'/assets', lambda r: self.data.assets(r.params)), ('GET', r'/assets/changes', lambda r: self.data.sockets.call('assets', 'changes', unreviewed=r.params.get('unreviewed') == 'true', limit=200)), ('GET', r'/assets/conflicts', lambda r: self.data.sockets.call('assets', 'conflicts')),
            ('POST', r'/assets/changes/(\d{1,12})/acknowledge', self.asset_acknowledge),
            ('GET', r'/assets/([^/]+)', lambda r, a: self.data.asset(a)), ('GET', r'/assets/([^/]+)/([a-z]+)', lambda r, a, p: self.data.asset_part(a, p, r.params)),
            ('GET', r'/attack-paths', lambda r: self.data.paths(r.params)), ('GET', r'/attack-paths/([^/]+)', lambda r, p: self.data.path(p)), ('GET', r'/attack-paths/([^/]+)/evidence', lambda r, p: self.data.path_evidence(p, r.params.get('edge'))),
            ('POST', r'/attack-paths/([^/]+)/notes', self.path_note),
            ('GET', r'/threat-intelligence', lambda r: self.data.intelligence(r.params)),
            ('GET', r'/health/overview', lambda r: self.data.health_overview()), ('GET', r'/health/components', lambda r: self.data.health_call('components')), ('GET', r'/health/components/([a-z0-9:._\-]+)', lambda r, c: self.data.health_call('explain', c)),
            ('GET', r'/health/metrics', lambda r: self.data.health_call('metrics')), ('GET', r'/health/catalog', lambda r: self.data.health_call('catalog')), ('GET', r'/health/metrics/([a-z0-9_]+)', lambda r, m: self.data.health_call('series', m, self.hours(r))),
            ('GET', r'/health/history', lambda r: self.data.health_call('history')), ('GET', r'/health/failures', lambda r: self.data.health_call('failures')), ('GET', r'/health/lag', lambda r: self.data.health_call('lag')), ('GET', r'/health/resources', lambda r: self.data.health_call('resources')),
            ('GET', r'/audit', self.audit), ('GET', r'/audit/verify', self.audit_verify),
        ]
        self.routes = [(m, re.compile(f'^{p}$'), f) for m, p, f in self.routes]

    def session_body(self, identity, csrf):
        return {'authenticated': True, 'username': identity['username'], 'role': identity['role'], 'csrf': csrf, 'expires_ms': identity['expires_ms']}

    @staticmethod
    def hours(request):
        try:
            hours = int(request.params.get('hours', 2))
        except ValueError:
            raise BadInput('hours must be a number') from None
        if not 1 <= hours <= 720:
            raise BadInput('hours must be 1 to 720')
        return hours

    def overview(self, request):
        key = f"overview:{request.params.get('range', '24h')}"
        self.data.window(request.params)
        return self.data.cached(key, lambda: self.data.overview(request.params))

    def search(self, request):
        return self.data.global_search(request.params.get('q'))

    # Changes. Each is validated by the service that owns the record, then recorded here under the session's identity.
    @staticmethod
    def text(body, name, required=True):
        value = body.get(name)
        if value is None and not required:
            return None
        if not isinstance(value, str) or len(value) > NOTE_LIMIT or (required and not value.strip()):
            raise BadInput(f'{name} is required, and at most {NOTE_LIMIT} characters')
        return value

    def changed(self, request, action, target, function, detail):
        try:
            result = function()
        except (Rejected, NotFound) as error:
            self.auth.record(request.identity['username'], action, target, 'rejected', request.id, {**detail, 'reason': str(error.args[0])[:200]})
            raise
        except Unavailable as error:
            self.auth.record(request.identity['username'], action, target, 'unavailable', request.id, detail)
            raise error
        self.auth.record(request.identity['username'], action, target, 'ok', request.id, detail)
        return result

    def incident_status(self, request, incident_id):
        identifier(incident_id, 'incident ID')
        state = request.body.get('state')
        if not isinstance(state, str) or not re.fullmatch(r'[a-z_]{1,32}', state):
            raise BadInput('state is not valid')
        note = self.text(request.body, 'note', required=False)
        return self.changed(request, 'incident_status', incident_id, lambda: self.data.sockets.call('incidents', 'status', incident_id=incident_id, state=state, note=note), {'state': state, 'with_note': bool(note)})

    def incident_note(self, request, incident_id):
        identifier(incident_id, 'incident ID')
        text = self.text(request.body, 'text')
        return self.changed(request, 'incident_note', incident_id, lambda: self.data.sockets.call('incidents', 'note', incident_id=incident_id, text=text), {'length': len(text)})

    def path_note(self, request, path_id):
        identifier(path_id, 'path ID')
        text = self.text(request.body, 'text')
        return self.changed(request, 'path_note', path_id, lambda: self.data.sockets.call('paths', 'note', path=path_id, text=text), {'length': len(text)})

    def asset_acknowledge(self, request, seq):
        note = self.text(request.body, 'note', required=False)
        return self.changed(request, 'asset_acknowledge', seq, lambda: self.data.sockets.call('assets', 'acknowledge', seq=int(seq), note=note), {'with_note': bool(note)})

    def audit(self, request):
        size, offset = self.data.paging(request.params)
        return {'dashboard': {'rows': self.auth.audit_rows(size, offset), 'size': size, 'offset': offset}, 'incidents': section(self.data.sockets.call, 'incidents', 'audit'), 'paths': section(self.data.sockets.call, 'paths', 'audit'), 'assets': section(self.data.sockets.call, 'assets', 'audit')}

    def audit_verify(self, request):
        return {'dashboard': self.auth.audit_verify(), 'incidents': section(self.data.sockets.call, 'incidents', 'verify')}


class Request:
    def __init__(self, params, body, identity, request_id):
        self.params, self.body, self.identity, self.id = params, body, identity, request_id


class Handler(BaseHTTPRequestHandler):
    server_version = 'siem'
    sys_version = ''
    protocol_version = 'HTTP/1.1'
    timeout = 30

    def log_message(self, *args):
        """Nothing per request: URLs can hold search terms, and the journal feeds the pipeline."""

    def setup(self):
        super().setup()
        self.request_id = secrets.token_hex(8)
        self.extra_cookie = None

    @property
    def app(self):
        return self.server.app

    def body_left(self):
        """True if a request body has not been read. It would be taken for the next request on this connection."""
        return self.command == 'POST' and not self.body_done and self.headers.get('Content-Length', '0') not in ('0', '')

    def reply(self, status, body, content_type='application/json', cache='no-store'):
        unread = self.body_left()
        if unread:
            self.close_connection = True
        self.send_response(status)
        if unread:
            self.send_header('Connection', 'close')
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', cache)
        self.send_header('X-Request-Id', self.request_id)
        for name, value in HEADERS.items():
            self.send_header(name, value)
        # HSTS binds a whole host name on every port. On localhost it would force HTTPS on unrelated local services.
        if self.app.strict_transport:
            self.send_header('Strict-Transport-Security', 'max-age=31536000')
        if self.extra_cookie:
            self.send_header('Set-Cookie', self.extra_cookie)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def send_json(self, status, value):
        self.reply(status, json.dumps(value, default=str, separators=(',', ':')).encode())

    def problem(self, status, message, code=None):
        self.send_json(status, {'error': {'message': message, 'code': code or status, 'request_id': self.request_id}})

    def cookie_value(self):
        for part in self.headers.get('Cookie', '').split(';'):
            name, _, value = part.strip().partition('=')
            if name == COOKIE and TOKEN.match(value):
                return value
        return None

    def set_cookie(self, token, expires=False):
        flags = 'Path=/; Secure; HttpOnly; SameSite=Strict'
        self.extra_cookie = f'{COOKIE}=; Max-Age=0; {flags}' if expires else f'{COOKIE}={token}; {flags}'

    def read_body(self):
        limit = self.app.config['limits']['max_body_bytes']
        try:
            length = int(self.headers.get('Content-Length', 0))
        except ValueError:
            raise Problem(400, 'Bad request') from None
        if length > limit or length < 0:
            self.close_connection = True
            raise Problem(413, 'The request is too large')
        if 'chunked' in self.headers.get('Transfer-Encoding', '').lower():
            self.close_connection = True
            raise Problem(411, 'A length is required')
        if not length:
            return {}
        if self.headers.get('Content-Type', '').split(';')[0].strip() != 'application/json':
            raise Problem(415, 'Send JSON')
        try:
            data = self.rfile.read(length)
            self.body_done = True
            body = json.loads(data)
        except (ValueError, UnicodeDecodeError):
            raise Problem(400, 'The body is not valid JSON') from None
        if not isinstance(body, dict):
            raise Problem(400, 'The body must be an object')
        return body

    def same_origin(self):
        """A changing request must come from this page. Browsers set these headers, and a page elsewhere cannot forge them."""
        fetch_site = self.headers.get('Sec-Fetch-Site')
        if fetch_site and fetch_site not in ('same-origin', 'none'):
            return False
        origin = self.headers.get('Origin')
        if origin:
            return urlsplit(origin).netloc == self.headers.get('Host', '')
        return True

    def dispatch(self):
        self.body_done = False
        parts = urlsplit(self.path)
        try:
            path = unquote(parts.path, errors='strict')
        except UnicodeDecodeError:
            return self.problem(400, 'Bad request')
        if not path.startswith(API + '/'):
            return self.serve_static(path) if self.command in ('GET', 'HEAD') else self.problem(405, 'Not allowed')
        try:
            self.handle_api(path[len(API):], parts.query)
        except Problem as problem:
            self.problem(problem.status, problem.message, problem.code)
        except BadInput as error:
            self.problem(400, str(error))
        except NotFound:
            self.problem(404, 'Not found')
        except Rejected as error:
            self.problem(409, error.reason, 'rejected')
        except Unavailable as error:
            self.problem(503, error.reason, 'unavailable')
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            self.close_connection = True
        except Exception as error:  # Nothing internal reaches a browser.
            print(f'request failed: {type(error).__name__}, request {self.request_id}', file=sys.stderr, flush=True)
            self.problem(500, 'Something went wrong')

    def handle_api(self, path, query):
        app = self.app
        limits = app.config['limits']
        if self.command == 'POST' and not self.same_origin():
            raise Problem(403, 'Refused', 'origin')
        if path.startswith('/auth/'):
            return self.handle_auth(path, query)
        token = self.cookie_value()
        identity = app.auth.identity(token) if token else None
        if identity is None:
            if not app.limiter.allow('anonymous', limits['anonymous_per_minute']):
                raise Problem(429, 'Too many requests')
            raise Problem(401, 'Sign in to continue', 'session')
        if not app.limiter.allow(identity['token_hash'], limits['requests_per_minute']):
            raise Problem(429, 'Too many requests')
        body = {}
        if self.command == 'POST':
            self.require_csrf(identity)
            body = self.read_body()
        try:
            params = dict(parse_qsl(query, keep_blank_values=False, strict_parsing=False, max_num_fields=32))
        except ValueError:
            raise Problem(400, 'Too many parameters') from None
        request = Request(params, body, identity, self.request_id)
        allowed = False
        for method, pattern, function in app.routes:
            match = pattern.match(path)
            if match:
                allowed = True
                if method == self.command:
                    return self.send_json(200, {'data': function(request, *match.groups()), 'meta': {'request_id': self.request_id, 'observed_ms': app.clock()}})
        raise Problem(405 if allowed else 404, 'Not allowed' if allowed else 'Not found')

    def require_csrf(self, identity):
        sent = self.headers.get('X-CSRF-Token', '')
        if not hmac.compare_digest(sent.encode(), identity['csrf'].encode()):
            raise Problem(403, 'Refused', 'csrf')

    def handle_auth(self, path, query):
        app = self.app
        auth = app.auth
        if path == '/auth/session' and self.command == 'GET':
            token = self.cookie_value()
            identity = auth.identity(token) if token else None
            if identity is None:
                # Whether an account exists is not told to an anonymous caller.
                return self.send_json(200, {'data': {'authenticated': False}, 'meta': {'request_id': self.request_id}})
            return self.send_json(200, {'data': app.session_body(identity, identity['csrf']), 'meta': {'request_id': self.request_id}})
        if self.command != 'POST':
            raise Problem(405, 'Not allowed')
        if path == '/auth/login':
            if not app.limiter.allow('login', app.config['limits']['anonymous_per_minute']):
                raise Problem(429, 'Too many requests')
            body = self.read_body()
            try:
                # Whatever cookie arrived is ignored. A session is only ever created here, with a new token.
                token, csrf = auth.login(body.get('username'), body.get('password'), self.request_id)
            except AuthError:
                raise Problem(401, 'Those details were not accepted, or sign-in is paused. Try again later', 'login') from None
            old = self.cookie_value()
            if old:
                previous = auth.identity(old)
                if previous:
                    auth.logout(previous['token_hash'], previous['username'], self.request_id)
            self.set_cookie(token)
            identity = auth.identity(token)
            return self.send_json(200, {'data': app.session_body(identity, csrf), 'meta': {'request_id': self.request_id}})
        token = self.cookie_value()
        identity = auth.identity(token) if token else None
        if identity is None:
            raise Problem(401, 'Sign in to continue', 'session')
        self.require_csrf(identity)
        if path == '/auth/logout':
            auth.logout(identity['token_hash'], identity['username'], self.request_id)
            self.set_cookie('', expires=True)
            return self.send_json(200, {'data': {'authenticated': False}, 'meta': {'request_id': self.request_id}})
        if path == '/auth/password':
            body = self.read_body()
            try:
                token, csrf = auth.change_password(identity, body.get('current'), body.get('new'), self.request_id)
            except AuthError as error:
                text = str(error)
                raise Problem(400, 'The current password was not accepted' if text == 'refused' else text) from None
            self.set_cookie(token)
            fresh = auth.identity(token)
            return self.send_json(200, {'data': app.session_body(fresh, csrf), 'meta': {'request_id': self.request_id}})
        raise Problem(404, 'Not found')

    def serve_static(self, path):
        target = self.app.static.get(path)
        if target is None or not target.is_file():
            return self.problem(404, 'Not found')
        kind = mimetypes.guess_type(target.name)[0] or 'application/octet-stream'
        if kind == 'text/html' or kind == 'text/css' or kind.endswith('javascript'):
            kind += '; charset=utf-8'
        self.reply(200, target.read_bytes(), kind, 'no-cache')

    def do_GET(self):
        self.dispatch()

    def do_HEAD(self):
        self.dispatch()

    def do_POST(self):
        self.dispatch()

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (ConnectionResetError, BrokenPipeError, ssl.SSLError, TimeoutError):
            self.close_connection = True

    def send_error(self, code, message=None, explain=None):
        """The standard error page names the server and echoes input. This does neither."""
        self.close_connection = True
        try:
            self.problem(code if code < 600 else 400, 'Not allowed' if code in (405, 501) else 'Bad request')
        except OSError:
            pass


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 32

    def __init__(self, address, app, context=None):
        super().__init__(address, Handler)
        self.app = app
        self.context = context
        self.slots = threading.BoundedSemaphore(app.config['limits']['max_connections'])

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(30)
        return connection, address

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            if self.context:
                request = self.context.wrap_socket(request, server_side=True)
            super().process_request_thread(request, client_address)
        except (OSError, ssl.SSLError):
            pass
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        """Quiet: a dropped connection is not news, and its address has no place in the journal."""


def tls_context(config):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(config['tls']['certificate'], config['tls']['key'])
    return context


def build_app(config):
    auth = Auth(config['state_file'], config)
    data = Data(OpenSearch(config['opensearch']), Sockets(config['sockets']), Health(config['health']), config)
    return App(config, auth, data, incident_rules(config['correlator_app']))


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(prog='siem-dashboard')
    parser.add_argument('--config', default='/home/linux/siem/config/dashboard/dashboard.yaml')
    args = parser.parse_args(argv)
    config = load(args.config)
    app = build_app(config)
    server = Server((config['listen']['host'], config['listen']['port']), app, tls_context(config))
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print('siem-dashboard started', file=sys.stderr, flush=True)
    stop.wait()
    server.shutdown()
    return 0
