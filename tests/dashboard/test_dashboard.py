"""Authentication, authorization, API, workflows, security and resilience, on fixtures with the real correlator's validation."""
import json
import re
import sqlite3
import unittest
from pathlib import Path

from helpers import NOW, PASSWORD, ROOT, Stack, XSS, web
from siem_dashboard import backends, config as settings
from siem_dashboard.auth import Auth, AuthError, hash_password, verify_password
from siem_dashboard.backends import ALLOWED, Rejected, Sockets
from siem_dashboard.data import BadInput

STATIC = ROOT / 'dashboard' / 'static'
CODE = '\n'.join(p.read_text(encoding='utf-8') for p in (ROOT / 'dashboard' / 'siem_dashboard').glob('*.py'))
JS = {p.name: p.read_text(encoding='utf-8') for p in (STATIC / 'js').glob('*.js')}
READ_ROUTES = ['/overview', '/search?q=x', '/events', '/events/siem-windows-2026.11.01/doc1', '/alerts', '/alerts/' + 'a' * 32, '/incidents', '/incidents/x', '/incidents/x/audit', '/assets', '/assets/ast-1', '/assets/ast-1/history', '/assets/changes', '/assets/conflicts', '/attack-paths', '/attack-paths/p1', '/attack-paths/p1/evidence', '/threat-intelligence', '/health/overview', '/health/components', '/health/lag', '/health/resources', '/audit', '/audit/verify']
WRITE_ROUTES = ['/incidents/x/status', '/incidents/x/notes', '/attack-paths/p1/notes', '/assets/changes/1/acknowledge', '/auth/password', '/auth/logout']
# The whole Version 1 surface. A route, menu entry or page that is not listed here fails the tests until it is added on purpose.
VERSION_1_ROUTES = [
    ('GET', '/overview'), ('GET', '/search'), ('GET', '/events'), ('GET', r'/events/([^/]+)/([^/]+)'), ('GET', '/alerts'), ('GET', r'/alerts/([^/]+)'),
    ('GET', '/incidents'), ('GET', r'/incidents/([^/]+)'), ('GET', r'/incidents/([^/]+)/audit'), ('POST', r'/incidents/([^/]+)/status'), ('POST', r'/incidents/([^/]+)/notes'),
    ('GET', r'/investigations/alert/([^/]+)'), ('GET', '/assets'), ('GET', '/assets/changes'), ('GET', '/assets/conflicts'), ('POST', r'/assets/changes/(\d{1,12})/acknowledge'),
    ('GET', r'/assets/([^/]+)'), ('GET', r'/assets/([^/]+)/([a-z]+)'), ('GET', '/attack-paths'), ('GET', r'/attack-paths/([^/]+)'), ('GET', r'/attack-paths/([^/]+)/evidence'),
    ('POST', r'/attack-paths/([^/]+)/notes'), ('GET', '/threat-intelligence'), ('GET', '/health/overview'), ('GET', '/health/components'), ('GET', r'/health/components/([a-z0-9:._\-]+)'),
    ('GET', '/health/metrics'), ('GET', '/health/catalog'), ('GET', r'/health/metrics/([a-z0-9_]+)'), ('GET', '/health/history'), ('GET', '/health/failures'), ('GET', '/health/lag'),
    ('GET', '/health/resources'), ('GET', '/audit'), ('GET', '/audit/verify')]
VERSION_1_MENU = [('Overview', 'overview'), ('Events', 'events'), ('Alerts', 'alerts'), ('Incidents', 'incidents'), ('Investigations', 'investigations'), ('Attack Paths', 'paths'), ('Assets', 'assets'),
                  ('Threat Intelligence', 'intelligence'), ('Pipeline Health', 'health'), ('Audit History', 'audit'), ('Settings', 'settings')]
VERSION_1_PAGES = ['alerts', 'assets', 'audit', 'events', 'health', 'incidents', 'intelligence', 'investigations', 'overview', 'paths', 'search', 'settings']


class Base(unittest.TestCase):
    def stack(self, **kwargs):
        return Stack(self, **kwargs)


class Provisioning(Base):
    def test_with_no_administrator_nothing_opens(self):
        s = self.stack(seed=False)
        client = s.client()
        self.assertEqual(client.get('/auth/session')[1]['data'], {'authenticated': False})
        self.assertEqual(client.post('/auth/login', {'username': 'analyst', 'password': PASSWORD}, csrf=False)[0], 401)
        self.assertEqual(client.get('/overview')[0], 401)

    def test_no_setup_or_registration_route_exists(self):
        s = self.stack(seed=False)
        client = s.client()
        for path in ('/auth/register', '/auth/setup', '/auth/create', '/setup', '/admin', '/users'):
            self.assertIn(client.post(path, {'username': 'x', 'password': PASSWORD}, csrf=False)[0], (401, 404), path)
        self.assertFalse(s.auth.admin())

    def test_passwords_are_scrypt_and_never_stored_plainly(self):
        s = self.stack()
        stored = s.auth.admin()['password']
        self.assertTrue(stored.startswith('scrypt$32768$8$3$'))
        self.assertTrue(verify_password(PASSWORD, stored))
        self.assertFalse(verify_password(PASSWORD + 'x', stored))
        self.assertNotIn(PASSWORD.encode(), Path(s.config['state_file']).read_bytes())

    def test_two_hashes_of_one_password_differ(self):
        self.assertNotEqual(hash_password(PASSWORD), hash_password(PASSWORD))

    def test_weak_passwords_and_reserved_names_are_refused(self):
        s = self.stack(seed=False)
        for name, password in (('root', PASSWORD), ('ROOT', PASSWORD), ('analyst', 'short'), ('analyst', 'a' * 20), ('bad name!', PASSWORD), ('', PASSWORD)):
            with self.assertRaises(AuthError):
                s.auth.create(name, password)

    def test_only_one_administrator(self):
        s = self.stack()
        with self.assertRaises(AuthError):
            s.auth.create('second', PASSWORD)
        with self.assertRaises(sqlite3.IntegrityError):
            s.auth.db.execute("INSERT INTO admin VALUES (2, 'b', 'c', 0, 0, 0)")

    def test_the_command_takes_no_password_argument(self):
        source = (ROOT / 'dashboard' / 'siem_dashboard' / 'admin.py').read_text(encoding='utf-8')
        self.assertIn('getpass', source)
        self.assertNotRegex(source, r"add_argument\('--password'[,)]")
        self.assertIn("os.geteuid() != 0", source)

    def test_disable_and_remove(self):
        s = self.stack()
        client = s.signed_in()
        s.auth.set_disabled(True)
        self.assertEqual(client.get('/overview')[0], 401)
        self.assertEqual(s.client().post('/auth/login', {'username': 'analyst', 'password': PASSWORD}, csrf=False)[0], 401)
        s.auth.set_disabled(False)
        s.signed_in()
        s.auth.remove()
        self.assertIsNone(s.auth.admin())
        self.assertTrue(s.auth.audit_verify()['intact'])


class Sessions(Base):
    def test_right_and_wrong_credentials(self):
        s = self.stack()
        self.assertEqual(s.signed_in().get('/overview')[0], 200)
        status, body, _ = s.client().post('/auth/login', {'username': 'analyst', 'password': 'wrong'}, csrf=False)
        self.assertEqual(status, 401)
        unknown = s.client().post('/auth/login', {'username': 'nobody', 'password': 'wrong'}, csrf=False)
        self.assertEqual(body['error']['message'], unknown[1]['error']['message'], 'a wrong name and a wrong password read the same')

    def test_root_is_just_an_unknown_name(self):
        s = self.stack()
        self.assertEqual(s.client().post('/auth/login', {'username': 'root', 'password': PASSWORD}, csrf=False)[0], 401)
        self.assertNotIn('pam', CODE.lower().replace('spam', ''))
        self.assertNotIn('/etc/shadow', CODE)

    def test_cookie_flags(self):
        s = self.stack()
        client = s.signed_in()
        cookie = client.set_cookie
        self.assertTrue(cookie.startswith('__Host-siem_session='))
        for flag in ('Secure', 'HttpOnly', 'SameSite=Strict', 'Path=/'):
            self.assertIn(flag, cookie)
        self.assertNotIn('Domain', cookie)

    def test_login_reply_holds_no_token_or_hash(self):
        s = self.stack()
        client = s.client()
        status, body, _ = client.post('/auth/login', {'username': 'analyst', 'password': PASSWORD}, csrf=False)
        text = json.dumps(body)
        self.assertNotIn(client.cookie, text)
        self.assertNotIn('scrypt', text)
        self.assertNotIn('password', text)

    def test_tokens_are_stored_only_as_hashes(self):
        s = self.stack()
        client = s.signed_in()
        self.assertNotIn(client.cookie.encode(), Path(s.config['state_file']).read_bytes())

    def test_logout_ends_the_session_on_the_server(self):
        s = self.stack()
        client = s.signed_in()
        old = client.cookie
        self.assertEqual(client.post('/auth/logout')[0], 200)
        client.cookie = old
        self.assertEqual(client.get('/overview')[0], 401)

    def test_idle_and_absolute_expiry(self):
        s = self.stack()
        client = s.signed_in()
        s.now[0] += 31 * 60000
        self.assertEqual(client.get('/overview')[0], 401)
        client = s.signed_in()
        for _ in range(17):
            s.now[0] += 29 * 60000
            status = client.get('/incidents')[0]
        self.assertEqual(status, 401, 'activity cannot extend a session past its absolute limit')

    def test_login_makes_a_new_session_whatever_cookie_arrives(self):
        s = self.stack()
        client = s.client()
        client.cookie = 'A' * 43
        client.post('/auth/login', {'username': 'analyst', 'password': PASSWORD}, csrf=False)
        self.assertNotEqual(client.cookie, 'A' * 43)
        other = s.client()
        other.cookie = 'A' * 43
        self.assertEqual(other.get('/overview')[0], 401, 'a fixed session value gets nobody in')

    def test_a_second_login_replaces_the_first_on_one_browser(self):
        s = self.stack()
        client = s.signed_in()
        first = client.cookie
        client.post('/auth/login', {'username': 'analyst', 'password': PASSWORD}, csrf=False)
        self.assertNotEqual(client.cookie, first)
        other = s.client()
        other.cookie = first
        self.assertEqual(other.get('/overview')[0], 401)

    def test_changing_the_password_rotates_and_ends_other_sessions(self):
        s = self.stack()
        one, two = s.signed_in(), s.signed_in()
        first = one.cookie
        new = 'another-long-passphrase-2'
        self.assertEqual(one.post('/auth/password', {'current': PASSWORD, 'new': new})[0], 200)
        self.assertNotEqual(one.cookie, first)
        self.assertEqual(one.get('/overview')[0], 200)
        self.assertEqual(two.get('/overview')[0], 401)
        self.assertEqual(s.client().post('/auth/login', {'username': 'analyst', 'password': PASSWORD}, csrf=False)[0], 401)

    def test_changing_the_password_needs_the_current_one(self):
        s = self.stack()
        client = s.signed_in()
        self.assertEqual(client.post('/auth/password', {'current': 'wrong', 'new': 'another-long-passphrase-2'})[0], 400)
        self.assertEqual(client.post('/auth/password', {'current': PASSWORD, 'new': 'short'})[0], 400)
        self.assertTrue(verify_password(PASSWORD, s.auth.admin()['password']))

    def test_root_reset_ends_sessions(self):
        s = self.stack()
        client = s.signed_in()
        s.auth.set_password('reset-long-passphrase-3', 'root-local')
        self.assertEqual(client.get('/overview')[0], 401)

    def test_throttling_stops_guessing_even_with_the_right_password(self):
        s = self.stack()
        for _ in range(5):
            s.client().post('/auth/login', {'username': 'analyst', 'password': 'wrong'}, csrf=False)
        self.assertEqual(s.client().post('/auth/login', {'username': 'analyst', 'password': PASSWORD}, csrf=False)[0], 401)
        self.assertTrue(any(r['outcome'] == 'throttled' for r in s.auth.audit_rows(20)))
        s.now[0] += 16 * 60000
        self.assertEqual(s.client().post('/auth/login', {'username': 'analyst', 'password': PASSWORD}, csrf=False)[0], 200)

    def test_guessing_names_trips_the_overall_limit(self):
        s = self.stack()
        for index in range(20):
            s.client().post('/auth/login', {'username': f'name{index}', 'password': 'wrong'}, csrf=False)
        self.assertEqual(s.client().post('/auth/login', {'username': 'analyst', 'password': PASSWORD}, csrf=False)[0], 401)
        s.auth.unlock()
        self.assertEqual(s.client().post('/auth/login', {'username': 'analyst', 'password': PASSWORD}, csrf=False)[0], 200)

    def test_a_login_flood_is_rate_limited(self):
        s = self.stack(extra={'limits': {**settings.DEFAULTS['limits'], 'anonymous_per_minute': 10}})
        statuses = [s.client().post('/auth/login', {}, csrf=False)[0] for _ in range(14)]
        self.assertIn(429, statuses)

    def test_a_session_survives_a_backend_restart(self):
        s = self.stack()
        client = s.signed_in()
        again = web.App(s.config, Auth(s.config['state_file'], s.config, clock=s.clock), s.data, None, clock=s.clock)
        self.assertIsNotNone(again.auth.identity(client.cookie))
        again.auth.close()


class Connections(Base):
    def test_a_body_left_unread_cannot_become_the_next_request(self):
        import http.client
        s = self.stack()
        probe = s.client()
        link = http.client.HTTPSConnection('127.0.0.1', s.port, context=probe.context, timeout=10)
        # Refused before its body is read. The body here is shaped like a request, as an attacker would shape it.
        smuggled = 'GET /api/v1/auth/session HTTP/1.1\r\nHost: x\r\n\r\n'
        link.request('POST', '/api/v1/overview', body=smuggled, headers={'Content-Type': 'application/json'})
        first = link.getresponse()
        first.read()
        self.assertEqual(first.status, 401)
        self.assertEqual(first.getheader('Connection'), 'close')
        link.close()

    def test_sign_out_then_a_new_request_on_the_same_connection(self):
        import http.client
        s = self.stack()
        client = s.signed_in()
        link = http.client.HTTPSConnection('127.0.0.1', s.port, context=client.context, timeout=10)
        heads = {'Cookie': f'{web.COOKIE}={client.cookie}', 'X-CSRF-Token': client.csrf, 'Content-Type': 'application/json'}
        link.request('POST', '/api/v1/auth/logout', body='{}', headers=heads)
        reply = link.getresponse()
        reply.read()
        self.assertEqual(reply.status, 200)
        link.close()
        link = http.client.HTTPSConnection('127.0.0.1', s.port, context=client.context, timeout=10)
        link.request('GET', '/')
        self.assertEqual(link.getresponse().status, 200)
        link.close()

    def test_a_read_body_keeps_the_connection_usable(self):
        import http.client
        s = self.stack()
        client = s.signed_in()
        link = http.client.HTTPSConnection('127.0.0.1', s.port, context=client.context, timeout=10)
        heads = {'Cookie': f'{web.COOKIE}={client.cookie}', 'X-CSRF-Token': client.csrf, 'Content-Type': 'application/json'}
        link.request('POST', '/api/v1/attack-paths/p1/notes', body='{"text": "x"}', headers=heads)
        reply = link.getresponse()
        reply.read()
        self.assertEqual(reply.status, 200)
        link.request('GET', '/')
        self.assertEqual(link.getresponse().status, 200)
        link.close()


class Csrf(Base):
    def test_a_change_needs_the_token(self):
        s = self.stack()
        client = s.signed_in()
        self.assertEqual(client.post('/incidents/x/notes', {'text': 'hi'}, csrf=False)[0], 403)
        client.csrf = 'wrong-value-wrong-value'
        self.assertEqual(client.post('/incidents/x/notes', {'text': 'hi'})[0], 403)

    def test_another_origin_is_refused_even_with_the_token(self):
        s = self.stack()
        client = s.signed_in()
        self.assertEqual(client.post('/incidents/x/notes', {'text': 'hi'}, headers={'Origin': 'https://evil.example', 'Host': f'127.0.0.1:{s.port}'})[0], 403)
        self.assertEqual(client.post('/incidents/x/notes', {'text': 'hi'}, headers={'Sec-Fetch-Site': 'cross-site'})[0], 403)

    def test_login_from_another_origin_is_refused(self):
        s = self.stack()
        self.assertEqual(s.client().post('/auth/login', {'username': 'analyst', 'password': PASSWORD}, csrf=False, headers={'Sec-Fetch-Site': 'cross-site'})[0], 403)

    def test_a_get_changes_nothing(self):
        s = self.stack()
        client = s.signed_in()
        for path in WRITE_ROUTES:
            self.assertIn(client.get(path)[0], (404, 405), path)

    def test_a_form_post_is_not_accepted(self):
        s = self.stack()
        client = s.signed_in()
        status = client.raw('POST', '/api/v1/incidents/x/notes', 'text=hi', {'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRF-Token': client.csrf})[0]
        self.assertEqual(status, 415)


class Authorization(Base):
    def test_every_read_route_refuses_without_a_session(self):
        s = self.stack()
        for path in READ_ROUTES:
            self.assertEqual(s.client().get(path)[0], 401, path)

    def test_every_change_refuses_without_a_session(self):
        s = self.stack()
        for path in WRITE_ROUTES:
            self.assertEqual(s.client().post(path, {'text': 'x'}, csrf=False)[0], 401, path)

    def test_a_forged_cookie_is_refused(self):
        s = self.stack()
        client = s.client()
        client.cookie = 'forged-forged-forged-forged-forged'
        self.assertEqual(client.get('/overview')[0], 401)

    def test_a_named_identity_in_a_request_changes_nothing(self):
        s = self.stack()
        incident = s.incident()
        client = s.signed_in()
        status, body, _ = client.post(f'/incidents/{incident}/notes', {'text': 'hello', 'actor': 'mallory', 'username': 'mallory', 'role': 'root'}, headers={'X-User': 'mallory', 'X-Role': 'root', 'X-Forwarded-User': 'mallory'})
        self.assertEqual(status, 200)
        row = s.auth.audit_rows(5)[0]
        self.assertEqual((row['actor'], row['action'], row['outcome']), ('analyst', 'incident_note', 'ok'))
        notes = s.world.store.incident(incident)['notes']
        self.assertNotEqual(notes[-1]['by'], 'mallory')

    def test_no_route_reads_identity_from_a_request(self):
        for word in ("headers.get('X-User", "body.get('actor", "body.get('role", "params.get('actor", "params.get('role"):
            self.assertNotIn(word, CODE)

    def test_the_dashboard_cannot_reach_administrator_actions(self):
        for service, action in (('incidents', 'rule'), ('incidents', 'replay'), ('assets', 'metadata'), ('assets', 'resolve'), ('assets', 'retire'), ('assets', 'register'), ('assets', 'reactivate'), ('paths', 'rebuild'), ('paths', 'link_identities'), ('paths', 'validate')):
            with self.assertRaises(Rejected):
                Sockets({'incidents': '/nonexistent', 'assets': '/nonexistent', 'paths': '/nonexistent', 'timeout_seconds': 1}).call(service, action)

    def test_the_sockets_offered_are_exactly_these(self):
        self.assertEqual(sorted(ALLOWED), ['assets', 'incidents', 'paths'])


class Api(Base):
    def test_paging_is_bounded(self):
        s = self.stack()
        client = s.signed_in()
        for path in ('/events?size=101', '/events?size=0', '/events?offset=901', '/events?size=x', '/alerts?offset=-1', '/incidents?size=9999'):
            self.assertEqual(client.get(path)[0], 400, path)

    def test_time_windows_are_bounded(self):
        s = self.stack()
        client = s.signed_in()
        for path in ('/events?range=99y', '/events?range=custom', f'/events?range=custom&from=0&to={NOW}', f'/events?range=custom&from={NOW}&to={NOW - 1}'):
            self.assertEqual(client.get(path)[0], 400, path)

    def test_a_search_touches_only_daily_indices_in_range(self):
        s = self.stack()
        client = s.signed_in()
        client.get('/events?range=1h')
        index, body = s.search.queries[-1]
        self.assertNotIn('*', index)
        self.assertLessEqual(len(index.split(',')), 4)
        self.assertLessEqual(body['size'], 100)
        self.assertLessEqual(body['track_total_hits'], 10000)

    def test_sort_is_a_closed_list(self):
        s = self.stack()
        client = s.signed_in()
        self.assertEqual(client.get('/events?sort=_script')[0], 400)
        self.assertEqual(client.get('/alerts?order=sideways')[0], 400)
        self.assertEqual(client.get('/alerts?severity=everything')[0], 400)

    def test_malformed_requests(self):
        s = self.stack()
        client = s.signed_in()
        self.assertEqual(client.raw('POST', '/api/v1/incidents/x/notes', '{bad', {'Content-Type': 'application/json', 'X-CSRF-Token': client.csrf})[0], 400)
        self.assertEqual(client.raw('POST', '/api/v1/incidents/x/notes', '[1]', {'Content-Type': 'application/json', 'X-CSRF-Token': client.csrf})[0], 400)
        self.assertEqual(client.post('/incidents/x/notes', {'text': 5})[0], 400)
        self.assertEqual(client.post('/incidents/x/notes', {'text': 'x' * 2001})[0], 400)
        self.assertEqual(client.post('/incidents/x/status', {'state': 'x y'})[0], 400)

    def test_a_large_body_is_refused(self):
        s = self.stack()
        client = s.signed_in()
        self.assertEqual(client.raw('POST', '/api/v1/incidents/x/notes', 'x' * 20000, {'Content-Type': 'application/json', 'X-CSRF-Token': client.csrf})[0], 413)

    def test_rate_limit(self):
        s = self.stack(extra={'limits': {**settings.DEFAULTS['limits'], 'requests_per_minute': 30}})
        client = s.signed_in()
        self.assertIn(429, [client.get('/alerts')[0] for _ in range(35)])

    def test_errors_carry_a_request_id_and_no_internals(self):
        s = self.stack()
        client = s.signed_in()
        status, body, heads = client.get('/nope')
        self.assertEqual(status, 404)
        self.assertEqual(body['error']['request_id'], heads['x-request-id'])
        s.search.down = True
        status, body, _ = client.get('/events')
        self.assertEqual(status, 503)
        self.assertNotRegex(json.dumps(body), r'Traceback|/home/|9200|opensearch-dashboard')

    def test_an_unexpected_fault_reveals_nothing(self):
        s = self.stack()
        client = s.signed_in()
        s.data.events = lambda params: 1 / 0
        status, body, _ = client.get('/events')
        self.assertEqual(status, 500)
        self.assertNotIn('ZeroDivision', json.dumps(body))

    def test_method_not_allowed(self):
        s = self.stack()
        client = s.signed_in()
        self.assertEqual(client.post('/overview')[0], 405)
        self.assertIn(client.raw('DELETE', '/api/v1/incidents/x')[0], (400, 405, 501))

    def test_settings_refuse_exposure(self):
        for bad in ({'listen': {'host': '0.0.0.0', 'port': 8443}}, {'listen': {'host': '10.0.0.5', 'port': 8443}}, {'opensearch': {**settings.DEFAULTS['opensearch'], 'url': 'https://example.com:9200'}}, {'session': {'idle_minutes': 9999, 'absolute_hours': 8}}):
            with self.assertRaises(settings.ConfigError):
                settings.build(bad)

    def test_a_wildcard_listener_is_refused_even_when_exposure_is_chosen(self):
        with self.assertRaises(settings.ConfigError):
            settings.build({'require_loopback': False, 'listen': {'host': '0.0.0.0', 'port': 8443}})
        self.assertTrue(settings.build({'require_loopback': False, 'listen': {'host': '10.0.0.5', 'port': 8443}}))


class Injection(Base):
    def test_query_syntax_stays_a_literal_value(self):
        s = self.stack()
        client = s.signed_in()
        for payload in ('*', 'a OR 1=1', '"; DROP', '{"match_all":{}}', '_exists_:message'):
            from urllib.parse import quote
            client.get(f'/events?host={quote(payload)}')
            filters = s.search.queries[-1][1]['query']['bool']['filter']
            self.assertIn({'term': {'host.name': payload}}, filters)

    def test_no_free_form_query_exists_anywhere(self):
        for word in ('query_string', 'simple_query_string', "'script'", "'wildcard'", "'regexp'", '_delete_by_query', '_update_by_query'):
            self.assertNotIn(word, CODE, word)

    def test_the_client_only_searches(self):
        self.assertEqual(re.findall(r"method='([A-Z]+)'", (ROOT / 'dashboard' / 'siem_dashboard' / 'backends.py').read_text(encoding='utf-8')), ['POST'])
        self.assertEqual(re.findall(r"/_(\w+)\?", (ROOT / 'dashboard' / 'siem_dashboard' / 'backends.py').read_text(encoding='utf-8')), ['search'])

    def test_ids_are_checked_before_any_lookup(self):
        s = self.stack()
        client = s.signed_in()
        for path in ('/alerts/%27%20OR%201', '/incidents/a%20b', '/attack-paths/%3Cx%3E', '/assets/a%20b'):
            self.assertEqual(client.get(path)[0], 400, path)

    def test_an_event_index_must_be_an_event_index(self):
        s = self.stack()
        client = s.signed_in()
        before = len(s.search.queries)
        for index in ('.opendistro_security', 'siem-alerts-2026.11', 'security-auditlog-2026.11.01', 'siem-windows-*', '_all'):
            self.assertEqual(client.get(f'/events/{index}/doc1')[0], 400, index)
        self.assertEqual(len(s.search.queries), before)

    def test_sqlite_input_is_bound(self):
        s = self.stack()
        s.client().post('/auth/login', {'username': "' OR '1'='1", 'password': "' OR '1'='1"}, csrf=False)
        self.assertIsNotNone(s.auth.admin())
        self.assertNotRegex(CODE, r"execute\(f'")

    def test_strange_text_cannot_break_login(self):
        s = self.stack()
        for name in ('\ud800', 'é' * 200, None, 5, ['x']):
            self.assertEqual(s.client().post('/auth/login', {'username': name, 'password': name}, csrf=False)[0], 401, repr(name))


class StaticFiles(Base):
    def test_traversal_finds_nothing(self):
        s = self.stack()
        client = s.client()
        for path in ('/../dashboard.db', '/..%2f..%2fetc/passwd', '/js/../../siem_dashboard/auth.py', '//etc/passwd', '/%2e%2e/%2e%2e/etc/passwd', '/js/%2e%2e/%2e%2e/siem_dashboard/auth.py'):
            self.assertIn(client.raw('GET', path)[0], (400, 404), path)

    def test_the_page_and_its_headers(self):
        s = self.stack()
        status, body, heads = s.client().raw('GET', '/')
        heads = {k.lower(): v for k, v in heads}
        self.assertEqual(status, 200)
        policy = heads['content-security-policy']
        self.assertIn("script-src 'self'", policy)
        self.assertIn("default-src 'none'", policy)
        self.assertIn("frame-ancestors 'none'", policy)
        self.assertNotIn('unsafe', policy)
        self.assertNotIn('strict-transport-security', heads, 'on loopback it would bind every port on localhost')
        self.assertEqual(heads['x-content-type-options'], 'nosniff')
        self.assertEqual(heads['x-frame-options'], 'DENY')
        self.assertNotIn(b'<script>', body.replace(b'<script type="module" src="/js/app.js"></script>', b''))

    def test_a_real_server_name_gets_strict_transport(self):
        s = self.stack(extra={'require_loopback': False, 'listen': {'host': '10.0.0.5', 'port': 8443}})
        status, _, heads = s.client().raw('GET', '/')
        self.assertIn('max-age', dict((k.lower(), v) for k, v in heads)['strict-transport-security'])

    def test_api_replies_are_never_cached_or_sniffed(self):
        s = self.stack()
        client = s.signed_in()
        _, _, heads = client.get('/overview')
        self.assertEqual(heads['cache-control'], 'no-store')
        self.assertTrue(heads['content-type'].startswith('application/json'))

    def test_the_server_does_not_name_itself(self):
        s = self.stack()
        _, _, heads = s.client().raw('GET', '/')
        server = dict((k.lower(), v) for k, v in heads).get('server', '')
        self.assertNotRegex(server, r'Python|\d\.\d')

    def test_no_secret_or_internal_address_in_the_frontend(self):
        text = '\n'.join(JS.values())
        self.assertNotRegex(text, r'9200|9092|password\s*[:=]\s*[\'"][^\'"]|Authorization|Basic ')

    def test_no_markup_is_ever_built_from_data(self):
        for name, text in JS.items():
            for word in ('innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval(', 'new Function', 'srcdoc'):
                self.assertNotIn(word, text, f'{name}: {word}')

    def test_no_external_resource(self):
        for path in list(STATIC.rglob('*')):
            if path.is_file():
                self.assertNotRegex(path.read_text(encoding='utf-8'), r'https?://(?!www\.w3\.org/2000/svg)', path.name)

    def test_links_from_data_cannot_be_script(self):
        self.assertIn("value.startsWith('#/')", JS['ui.js'])


class Workflows(Base):
    def test_overview_keeps_fixtures_out_of_counts(self):
        s = self.stack()
        data = s.signed_in().get('/overview?range=24h')[1]['data']
        counts = data['incidents']['data']
        self.assertEqual(counts['total'], 1)
        self.assertEqual(counts['excluded_no_stored_alerts'], 1)
        self.assertEqual(data['security']['data']['alerts_total'], 1)
        self.assertEqual(data['health']['data']['overall'], 'DEGRADED', 'health is passed on, not worked out')
        self.assertEqual(data['paths']['data']['with_expired_evidence'], 1)
        self.assertEqual(data['assets']['data']['by_criticality'], {'not set': 1}, 'unset is not filled in')

    def test_an_enrichment_record_with_no_alert_does_not_add_a_null_link(self):
        s = self.stack()
        s.search.search_original = s.search.search
        def without(index, body):
            reply = s.search.search_original(index, body)
            if index.startswith('siem-enrichment'):
                reply['hits']['hits'][0]['_source'].pop('alert_id', None)
            return reply
        s.data.search.search = without
        rows = s.signed_in().get('/threat-intelligence')[1]['data']['rows']
        self.assertEqual(rows[0]['alert_ids'], [])

    def test_unknown_verdicts_are_not_called_benign(self):
        s = self.stack()
        data = s.signed_in().get('/threat-intelligence')[1]['data']
        self.assertEqual(data['by_verdict']['no_known_threat'], 1)
        self.assertEqual(data['lookup_failures'], 1)
        self.assertNotIn('benign', json.dumps(data['by_verdict']))
        self.assertIn('does not mean', data['note'])

    def test_event_list_and_detail(self):
        s = self.stack()
        client = s.signed_in()
        rows = client.get('/events?range=24h&host=host-a')[1]['data']['rows']
        self.assertEqual(rows[0]['dataset'], 'windows.sysmon')
        detail = client.get('/events/siem-windows-2026.11.01/doc1')[1]['data']
        self.assertEqual(detail['fields']['event.dataset'], 'windows.sysmon')
        self.assertEqual(detail['alerts']['data'][0]['alert_id'], 'a' * 32)
        self.assertIn('withheld', detail['restricted_note'])

    def test_alert_detail_links_everything_it_can(self):
        s = self.stack()
        d = s.signed_in().get('/alerts/' + 'a' * 32)[1]['data']
        self.assertEqual(d['evidence_refs'], [{'index': 'siem-windows-2026.11.01', 'id': 'doc1', 'link': True}])
        self.assertEqual(d['incidents']['data'][0]['incident_id'], 'real')
        self.assertEqual(d['paths']['data'][0]['path_id'], 'p1')

    def test_incident_list_hides_fixtures_unless_asked(self):
        s = self.stack()
        client = s.signed_in()
        self.assertEqual([r['incident_id'] for r in client.get('/incidents')[1]['data']['rows']], ['real'])
        self.assertEqual(len(client.get('/incidents?include_unverified=true')[1]['data']['rows']), 2)

    def test_the_real_correlator_decides_every_move(self):
        s = self.stack()
        incident = s.incident()
        client = s.signed_in()
        view = client.get(f'/incidents/{incident}')[1]['data']
        self.assertEqual(view['incident']['status'], 'new')
        self.assertEqual(view['allowed_moves'], ['open', 'investigating', 'false_positive'])
        self.assertEqual(client.post(f'/incidents/{incident}/status', {'state': 'closed', 'note': 'x'})[0], 409, 'new cannot go straight to closed')
        self.assertEqual(s.world.store.incident(incident)['status'], 'new')
        status, body, _ = client.post(f'/incidents/{incident}/status', {'state': 'false_positive'})
        self.assertEqual(status, 409)
        self.assertIn('note', body['error']['message'], 'the mandatory note is the correlator rule')
        self.assertEqual(client.post(f'/incidents/{incident}/status', {'state': 'open'})[0], 200)
        self.assertEqual(client.post(f'/incidents/{incident}/status', {'state': 'investigating'})[0], 200)
        self.assertEqual(client.post(f'/incidents/{incident}/status', {'state': 'resolved', 'note': 'done'})[0], 200)
        self.assertEqual(client.post(f'/incidents/{incident}/status', {'state': 'closed', 'note': 'done'})[0], 200)
        self.assertEqual(s.world.store.incident(incident)['status'], 'closed')
        self.assertEqual(client.post(f'/incidents/{incident}/status', {'state': 'invented'})[0], 409)

    def test_each_change_is_in_both_audit_trails(self):
        s = self.stack()
        incident = s.incident()
        client = s.signed_in()
        _, _, heads = client.post(f'/incidents/{incident}/status', {'state': 'open'})
        rows = client.get(f'/incidents/{incident}/audit')[1]['data']
        self.assertTrue([r for r in rows if r['action'] in ('status', 'transition', 'state')] or len(rows) >= 2)
        mine = s.auth.audit_rows(5)[0]
        self.assertEqual((mine['actor'], mine['action'], mine['target'], mine['outcome'], mine['request_id']), ('analyst', 'incident_status', incident, 'ok', heads['x-request-id']))
        self.assertTrue(s.world.store.audit_verify()[1] is None)

    def test_a_refused_change_is_recorded_too(self):
        s = self.stack()
        incident = s.incident()
        client = s.signed_in()
        client.post(f'/incidents/{incident}/status', {'state': 'closed', 'note': 'x'})
        row = s.auth.audit_rows(5)[0]
        self.assertEqual((row['action'], row['outcome']), ('incident_status', 'rejected'))

    def test_no_deletion_of_an_incident_exists(self):
        self.assertNotIn('delete', ALLOWED['incidents'])
        s = self.stack()
        self.assertFalse([p for m, p, _ in s.app.routes if m not in ('GET', 'POST')])

    def test_notes_are_not_altered_or_put_in_the_audit(self):
        s = self.stack()
        incident = s.incident()
        client = s.signed_in()
        client.post(f'/incidents/{incident}/notes', {'text': 'private conclusion'})
        self.assertEqual(s.world.store.incident(incident)['notes'][-1]['text'], 'private conclusion')
        self.assertNotIn('private conclusion', json.dumps(s.auth.audit_rows(5)))

    def test_asset_views_and_acknowledge_use_the_service(self):
        s = self.stack()
        client = s.signed_in()
        self.assertEqual(client.get('/assets')[1]['data']['total']['value'], 1)
        self.assertEqual(client.get('/assets/ast-1')[1]['data']['asset']['asset_id'], 'ast-1')
        self.assertEqual(client.get('/assets/ast-1/nothing')[0], 404)
        self.assertEqual(client.post('/assets/changes/7/acknowledge', {})[0], 200)
        self.assertEqual(s.assets.seen[-1]['action'], 'acknowledge')
        self.assertEqual(s.assets.seen[-1]['seq'], 7)

    def test_attack_path_says_it_is_no_proof(self):
        s = self.stack()
        d = s.signed_in().get('/attack-paths/p1')[1]['data']
        self.assertEqual(d['graph']['conclusion'], 'none')
        self.assertIn('not proof of compromise', d['limit_note'])

    def test_parallel_audit_reads_and_session_writes_never_fail(self):
        import concurrent.futures
        s = self.stack()
        c = s.signed_in()
        cookie = c.cookie
        def one(path):
            client = s.client()
            client.cookie = cookie
            return client.get(path)[0]
        with concurrent.futures.ThreadPoolExecutor(12) as pool:
            codes = list(pool.map(one, ['/audit/verify', '/audit', '/auth/session'] * 20))
        self.assertEqual(set(codes), {200}, codes)

    def test_the_api_is_exactly_the_version_1_routes(self):
        s = self.stack()
        found = sorted((m, p.pattern) for m, p, _ in s.app.routes)
        self.assertEqual(found, sorted((m, f'^{p}$') for m, p in VERSION_1_ROUTES))

    def test_an_unknown_path_reads_nothing(self):
        s = self.stack()
        c = s.signed_in()
        before = len(s.search.queries)
        status, body, _ = c.get('/no-such-route')
        self.assertEqual(status, 404)
        self.assertEqual(len(s.search.queries), before)

    def test_the_session_reply_carries_only_identity(self):
        s = self.stack()
        c = s.signed_in()
        self.assertEqual(sorted(c.get('/auth/session')[1]['data']), ['authenticated', 'csrf', 'expires_ms', 'role', 'username'])

    def test_the_menu_and_pages_are_exactly_the_version_1_set(self):
        app = JS['app.js']
        nav = re.findall(r"\['([^']+)', '#/([a-z]+)'\]", app.split('const ROUTES')[0])
        self.assertEqual(nav, VERSION_1_MENU)
        pages = re.findall(r"\[/\^([a-z]+)", app.split('const ROUTES')[1].split('];')[0])
        self.assertEqual(sorted(set(pages)), sorted(VERSION_1_PAGES))

    def test_the_browser_asks_only_for_version_1_routes(self):
        asked = set()
        for code in JS.values():
            asked.update(re.findall(r"(?:get|post)\(`?'?(/[a-z][a-z-]*)", code))
        served = {p.split('/')[1] for _, p in VERSION_1_ROUTES}
        self.assertTrue(asked, 'no request found')
        self.assertFalse({a for a in asked if a.split('/')[1] not in served | {'auth'}}, asked)

    def test_the_audit_page_and_its_chain(self):
        s = self.stack()
        client = s.signed_in()
        self.assertEqual(client.get('/audit')[1]['data']['dashboard']['rows'][0]['action'], 'login')
        self.assertTrue(client.get('/audit/verify')[1]['data']['dashboard']['intact'])

    def test_the_audit_cannot_be_edited_and_tampering_shows(self):
        s = self.stack()
        with self.assertRaises(sqlite3.DatabaseError):
            s.auth.db.execute("UPDATE audit SET actor = 'x'")
        with self.assertRaises(sqlite3.DatabaseError):
            s.auth.db.execute('DELETE FROM audit')
        s.auth.db.execute('DROP TRIGGER audit_no_update')
        s.auth.db.execute("UPDATE audit SET actor = 'x' WHERE seq = 1")
        self.assertFalse(s.auth.audit_verify()['intact'])

    def test_the_audit_refuses_secret_shaped_detail(self):
        s = self.stack()
        s.auth.record('a', 'b', None, 'ok', detail={'password': 'x', 'session_token': 'y', 'cookie': 'z', 'kept': 1})
        self.assertEqual(s.auth.audit_rows(1)[0]['detail'], {'kept': 1})

    def test_global_search_labels_each_kind(self):
        s = self.stack()
        d = s.signed_in().get('/search?q=203.0.113.6')[1]['data']
        self.assertEqual(set(d), {'alerts', 'incidents', 'events', 'assets', 'attack_paths', 'indicators'})
        self.assertEqual(d['indicators']['data'][0]['verdict'], 'malicious')
        self.assertEqual(s.signed_in().get('/search?q=')[0], 400)


class HostileContent(Base):
    def test_hostile_text_comes_back_as_inert_json(self):
        s = self.stack()
        client = s.signed_in()
        status, data, heads = client.raw('GET', '/api/v1/alerts/' + 'a' * 32)
        heads = dict((k.lower(), v) for k, v in heads)
        self.assertTrue(heads['content-type'].startswith('application/json'))
        self.assertEqual(json.loads(data)['data']['alert']['description'], XSS)

    def test_graph_labels_only_reach_text_nodes(self):
        self.assertIn('createElementNS', JS['ui.js'])
        self.assertIn('createTextNode', JS['ui.js'])
        self.assertIn("throw new Error('use the on map')", JS['ui.js'])

    def test_the_graph_is_bounded(self):
        self.assertIn('MAX_DRAWN', JS['paths.js'])


class Resilience(Base):
    def test_opensearch_down_leaves_a_working_page(self):
        s = self.stack()
        client = s.signed_in()
        s.search.down = True
        s.data.cache.clear()
        s.app.data.cache.clear()
        status, body, _ = client.get('/overview?range=6h')
        data = body['data']
        self.assertEqual(status, 200)
        self.assertEqual(data['security']['status'], 'unavailable')
        self.assertEqual(data['health']['status'], 'ok')
        self.assertEqual(data['assets']['status'], 'ok')

    def test_incidents_fall_back_to_the_service_and_say_so(self):
        s = self.stack()
        s.incident()
        client = s.signed_in()
        s.search.down = True
        s.data.cache.clear()
        data = client.get('/incidents')[1]['data']
        self.assertEqual(data['source'], 'incident service')
        self.assertEqual(data['rows'][0]['record_class'], 'not_checked')

    def test_each_service_down_is_reported_and_is_not_zero(self):
        s = self.stack()
        client = s.signed_in()
        s.health.down = True
        s.config['sockets']['assets'] = '/nonexistent/a'
        s.config['sockets']['paths'] = '/nonexistent/p'
        s.config['sockets']['incidents'] = '/nonexistent/i'
        s.data.cache.clear()
        data = client.get('/overview?range=1h')[1]['data']
        self.assertEqual(data['health']['status'], 'unavailable')
        self.assertEqual(data['assets']['status'], 'unavailable')
        self.assertEqual(data['security']['status'], 'ok')
        self.assertEqual(client.get('/assets')[0], 503)
        self.assertEqual(client.get('/attack-paths')[0], 503)
        self.assertEqual(client.get('/health/overview')[0], 503)

    def test_a_change_during_an_outage_is_recorded_as_not_done(self):
        s = self.stack()
        client = s.signed_in()
        s.config['sockets']['incidents'] = '/nonexistent/i'
        self.assertEqual(client.post('/incidents/x/notes', {'text': 'hi'})[0], 503)
        row = s.auth.audit_rows(1)[0]
        self.assertEqual((row['action'], row['outcome']), ('incident_note', 'unavailable'))

    def test_missing_fields_do_not_break_lists(self):
        s = self.stack()
        s.search.incidents = [{'incident_id': 'bare', 'status': 'new', 'alert_ids': []}]
        client = s.signed_in()
        self.assertEqual(client.get('/incidents?include_unverified=true')[0], 200)
        s.data.search.search = lambda index, body: {'hits': {'hits': [{'_id': 'x'}]}}
        self.assertEqual(client.get('/events')[0], 200)

    def test_a_section_with_an_unreadable_reply_stays_contained(self):
        s = self.stack()
        s.assets.replies['list'] = {'ok': False, 'error': 'stack trace at /home/secret'}
        client = s.signed_in()
        data = client.get('/overview?range=7d')[1]['data']
        self.assertEqual(data['assets']['status'], 'unavailable')


class Isolation(Base):
    def test_no_program_is_ever_started(self):
        for word in ('subprocess', 'os.system', 'os.popen', 'pty.', 'shell=True', 'exec(', 'eval('):
            self.assertNotIn(word, CODE, word)

    def test_no_kafka(self):
        self.assertNotIn('confluent', CODE)
        self.assertNotIn('9092', CODE)

    def test_no_unit_depends_on_the_dashboard(self):
        for path in (ROOT / 'deploy' / 'systemd').rglob('*'):
            if path.is_dir() or path.name in ('siem-dashboard.service', 'siem.target'):
                continue
            self.assertNotRegex(path.read_text(encoding='utf-8'), r'(Requires|Wants|BindsTo|After|Before)=.*siem-dashboard', path.name)

    def test_no_core_code_refers_to_it(self):
        for folder in ('detector', 'enricher', 'correlator', 'attackpath', 'inventory', 'health', 'services'):
            for path in (ROOT / folder).rglob('*'):
                if path.suffix in ('.py', '.go'):
                    self.assertNotIn('siem_dashboard', path.read_text(encoding='utf-8', errors='replace'), path)

    def test_the_role_holds_no_write_or_administration(self):
        role = (ROOT / 'deploy' / 'opensearch' / 'create-dashboard-user.sh').read_text(encoding='utf-8')
        block = role[role.index('"cluster_permissions"'):role.index("}' >/dev/null")]
        self.assertEqual(set(re.findall(r'"allowed_actions": \[([^\]]*)\]', block)), {'"indices:data/read/search*"'})
        self.assertIn('"cluster_permissions": ["cluster:monitor/main"]', block)
        self.assertNotRegex(block, r'command_line|powershell|"message"|file\.path|script_block|matched_fields|host\.id')

    def test_every_read_is_under_field_level_security(self):
        role = (ROOT / 'deploy' / 'opensearch' / 'create-dashboard-user.sh').read_text(encoding='utf-8')
        self.assertEqual(role.count('"index_patterns"'), role.count('"fls"'))

    def test_the_unit_is_confined(self):
        unit = (ROOT / 'deploy' / 'systemd' / 'siem-dashboard.service').read_text(encoding='utf-8')
        for line in ('User=siem-dashboard', 'NoNewPrivileges=true', 'ProtectSystem=strict', 'CapabilityBoundingSet=', 'MemoryMax=192M', 'ReadWritePaths=/home/linux/siem/data/dashboard'):
            self.assertIn(line, unit)
        self.assertNotIn('siem-asset-admin', unit)
        self.assertNotIn('siem-path-admin', unit)

    def test_paths_are_settings_not_wsl_assumptions(self):
        self.assertNotIn('/mnt/c', CODE)


class ModuleGuards(unittest.TestCase):
    def test_backends_module_shape(self):
        self.assertTrue(callable(backends.incident_rules))
        self.assertIs(BadInput.__mro__[1], ValueError)


if __name__ == '__main__':
    unittest.main()
