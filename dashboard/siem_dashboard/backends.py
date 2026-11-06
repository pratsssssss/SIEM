"""The ways out of this service: OpenSearch with a read-only login, and three local sockets.

Every socket call goes through a fixed allow-list. The operating system group that opens those sockets would allow more,
including rule changes and identity merges, so this list is what keeps the dashboard to analyst work. Nothing here runs a
program, and no error text from a backend reaches a browser.
"""
import base64
import json
import socket
import ssl
import sys
import urllib.error
import urllib.request

ALLOWED = {
    'incidents': {'list', 'show', 'timeline', 'status', 'note', 'audit', 'verify', 'health'},
    'assets': {'health', 'list', 'show', 'search', 'history', 'relationships', 'software', 'services', 'users', 'changes', 'conflicts', 'stale', 'context_of', 'acknowledge', 'audit'},
    'paths': {'health', 'list', 'show', 'search', 'graph', 'evidence', 'timeline', 'asset', 'incident', 'history', 'explain', 'audit', 'note'},
}
MAX_REPLY = 16 * 1024 * 1024


class Unavailable(Exception):
    """A backend could not answer. `reason` is safe to show."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


class Rejected(Exception):
    """A backend answered and refused. Its own validation is the authority."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


class NotFound(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class OpenSearch:
    def __init__(self, settings):
        self.settings = settings
        self.opener = None
        self.header = None

    def _ready(self):
        if self.opener is None:
            context = ssl.create_default_context(cafile=self.settings['ca_file'])
            self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=context))
            with open(self.settings['login_file'], encoding='utf-8') as handle:
                login = json.load(handle)
            token = base64.b64encode(f"{login['user']}:{login['password']}".encode()).decode()
            self.header = {'Authorization': f'Basic {token}', 'Content-Type': 'application/json'}

    def search(self, index, body):
        """A bounded search with a server-side time limit. Partial results are refused, not shown as complete."""
        try:
            self._ready()
            path = f"{self.settings['url']}/{index}/_search?ignore_unavailable=true&allow_no_indices=true&allow_partial_search_results=false&timeout={self.settings['query_timeout']}"
            request = urllib.request.Request(path, data=json.dumps(body).encode(), headers=self.header, method='POST')
            with self.opener.open(request, timeout=self.settings['timeout_seconds']) as reply:
                data = reply.read(MAX_REPLY + 1)
        except urllib.error.HTTPError as error:
            raise Unavailable('The search was refused' if error.code in (401, 403) else 'The search failed') from None
        except (OSError, ValueError):
            raise Unavailable('OpenSearch cannot be reached') from None
        if len(data) > MAX_REPLY:
            raise Unavailable('The reply was too large')
        try:
            return json.loads(data)
        except ValueError:
            raise Unavailable('The reply was unreadable') from None


class Sockets:
    def __init__(self, settings):
        self.settings = settings

    def call(self, service, action, **arguments):
        if action not in ALLOWED[service]:
            raise Rejected('This action is not available from the dashboard')
        names = {'incidents': 'Incident service', 'assets': 'Asset service', 'paths': 'Attack path service'}
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as link:
                link.settimeout(self.settings['timeout_seconds'])
                link.connect(self.settings[service])
                link.sendall(json.dumps({'action': action, **arguments}).encode())
                link.shutdown(socket.SHUT_WR)
                chunks, size = [], 0
                while True:
                    chunk = link.recv(1 << 20)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > MAX_REPLY:
                        raise Unavailable(f'{names[service]} sent too much')
                    chunks.append(chunk)
            reply = json.loads(b''.join(chunks))
        except (OSError, ValueError):
            raise Unavailable(f'{names[service]} cannot be reached') from None
        if not isinstance(reply, dict):
            raise Unavailable(f'{names[service]} sent an unreadable reply')
        if not reply.get('ok'):
            text = str(reply.get('error', 'refused'))[:200]
            if text.startswith('no such'):
                raise NotFound(text)
            raise Rejected(text)
        return reply.get('result')


class Health:
    """Phase 16's own read-only views, in process. Nothing about health is worked out here."""

    def __init__(self, settings):
        self.settings = settings
        self.loaded = None

    def view(self):
        try:
            if self.loaded is None:
                if self.settings['app'] not in sys.path:
                    sys.path.append(self.settings['app'])
                from siem_health import cli as health_cli
                from siem_health import catalog
                from siem_health.config import load
                self.loaded = (health_cli, catalog, load(self.settings['config']))
            cli, catalog, config = self.loaded
            return cli.View(config), catalog
        except Exception:  # A missing or damaged monitor must not take the dashboard with it.
            self.loaded = None
            raise Unavailable('The health monitor state cannot be read') from None


def incident_rules(app):
    """The correlator's own transition table, so the screen can never disagree with it. None if it cannot be read."""
    try:
        if app not in sys.path:
            sys.path.append(app)
        from siem_correlator.incidents import MOVES, NEEDS_NOTE, STATES
        return {'states': list(STATES), 'moves': {k: list(v) for k, v in MOVES.items()}, 'needs_note': list(NEEDS_NOTE)}
    except Exception:
        return None
