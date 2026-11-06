"""Drives the real dashboard in a real headless Edge, on Windows. Standard library only, and uses one short-lived browser.

The password is generated here, passed to the root command on standard input, and held only in memory. The account is removed
at the end. Screenshots go to the folder named on the command line. Reports text sizes, never page content.
"""
import base64
import json
import os
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request

EDGE = r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
WSL = ['wsl.exe', '-d', 'Ubuntu-24.04', '-u', 'root', '--', '/usr/local/sbin/siem-dashboard-admin']
PORT = 9333
USER = 'browsertest'
PASSWORD = secrets.token_urlsafe(24)
failures = []


def check(name, ok, detail=''):
    print(f"{'PASS' if ok else 'FAIL'} {name}" + (f' ({detail})' if detail != '' else ''), flush=True)
    if not ok:
        failures.append(name)


class Socket:
    """Just enough WebSocket for the DevTools protocol."""

    def __init__(self, url):
        host, _, path = url.removeprefix('ws://').partition('/')
        name, _, port = host.partition(':')
        self.link = socket.create_connection((name, int(port)), timeout=30)
        key = base64.b64encode(os.urandom(16)).decode()
        self.link.sendall(f'GET /{path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n'.encode())
        data = b''
        while b'\r\n\r\n' not in data:
            data += self.link.recv(4096)
        self.buffer = data.split(b'\r\n\r\n', 1)[1]

    def exact(self, size):
        while len(self.buffer) < size:
            chunk = self.link.recv(1 << 20)
            if not chunk:
                raise ConnectionError('closed')
            self.buffer += chunk
        out, self.buffer = self.buffer[:size], self.buffer[size:]
        return out

    def send(self, text):
        body = text.encode()
        mask = os.urandom(4)
        size = len(body)
        head = b'\x81' + (bytes([0x80 | size]) if size < 126 else bytes([0x80 | 126]) + struct.pack('>H', size) if size < 65536 else bytes([0x80 | 127]) + struct.pack('>Q', size))
        self.link.sendall(head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(body)))

    def receive(self):
        out = b''
        while True:
            first, second = self.exact(2)
            size = second & 0x7f
            if size == 126:
                size = struct.unpack('>H', self.exact(2))[0]
            elif size == 127:
                size = struct.unpack('>Q', self.exact(8))[0]
            out += self.exact(size)
            if first & 0x80:
                return out.decode('utf-8', 'replace')


class Page:
    def __init__(self, url):
        self.socket = Socket(url)
        self.next = 0
        self.problems = []
        self.responses = []
        for domain in ('Page', 'Runtime', 'Log', 'Network'):
            self.call(f'{domain}.enable')

    def note(self, message):
        method = message.get('method')
        params = message.get('params', {})
        if method == 'Runtime.exceptionThrown':
            self.problems.append('exception: ' + str(params['exceptionDetails'].get('text'))[:120] + ' ' + str(params['exceptionDetails'].get('exception', {}).get('description'))[:160])
        elif method == 'Log.entryAdded' and params['entry'].get('level') == 'error':
            self.problems.append('log: ' + params['entry'].get('text', '')[:160])
        elif method == 'Runtime.consoleAPICalled' and params.get('type') == 'error':
            self.problems.append('console error')
        elif method == 'Network.responseReceived':
            self.responses.append((params['response'].get('status'), params['response'].get('url', '').split('8443')[-1][:80]))

    def call(self, method, **params):
        self.next += 1
        wanted = self.next
        self.socket.send(json.dumps({'id': wanted, 'method': method, 'params': params}))
        while True:
            message = json.loads(self.socket.receive())
            if message.get('id') == wanted:
                return message.get('result', {})
            self.note(message)

    def run(self, expression, wait=True):
        result = self.call('Runtime.evaluate', expression=expression, awaitPromise=wait, returnByValue=True)
        if 'exceptionDetails' in result:
            raise RuntimeError(str(result['exceptionDetails'])[:200])
        return result.get('result', {}).get('value')

    def settle(self, seconds=15):
        limit = time.time() + seconds
        while time.time() < limit:
            if not self.run("!!document.querySelector('main') && document.querySelector('main').innerText.trim() !== 'Loading…'"):
                time.sleep(0.2)
                continue
            return True
        return False

    def text(self):
        return self.run("document.querySelector('main') ? document.querySelector('main').innerText : document.body.innerText") or ''

    def shot(self, folder, name):
        data = self.call('Page.captureScreenshot', format='png')['data']
        with open(os.path.join(folder, f'{name}.png'), 'wb') as handle:
            handle.write(base64.b64decode(data))


def administrator():
    """The name of the account that exists, or None."""
    return json.loads(subprocess.run([*WSL, 'status'], capture_output=True, text=True).stdout).get('username')


PAGES = ('overview', 'events', 'alerts', 'incidents', 'investigations', 'paths', 'assets', 'intelligence', 'health', 'audit', 'settings', 'search')
PROBES = [sys.argv[i + 1] for i, a in enumerate(sys.argv[:-1]) if a == '--probe']


def main():
    folder = sys.argv[1]
    os.makedirs(folder, exist_ok=True)
    # One account at most exists, and remove takes whichever it is. So this never starts while another account exists,
    # and removes only the account it made, checked by name.
    if administrator() is not None:
        print('An administrator already exists. This test needs a server with none, and never touches an existing account. Nothing was run.')
        return 2
    made = subprocess.run([*WSL, 'create', USER, '--password-stdin'], input=PASSWORD + '\n', capture_output=True, text=True)
    check('a temporary administrator is created', made.returncode == 0, made.stderr.strip()[:80])
    if made.returncode != 0:
        return 1
    profile = tempfile.mkdtemp(prefix='siem-edge-')
    browser = subprocess.Popen([EDGE, '--headless=new', '--disable-gpu', f'--remote-debugging-port={PORT}', f'--user-data-dir={profile}', '--ignore-certificate-errors', '--no-first-run', '--window-size=1500,1000', '--disable-extensions', 'about:blank'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        target = None
        for _ in range(60):
            try:
                pages = json.load(urllib.request.urlopen(f'http://127.0.0.1:{PORT}/json', timeout=2))
                target = next(p for p in pages if p['type'] == 'page')
                break
            except (OSError, StopIteration, ValueError):
                time.sleep(0.5)
        page = Page(target['webSocketDebuggerUrl'])
        page.call('Page.navigate', url='https://localhost:8443/')
        time.sleep(2)
        check('the sign-in page appears over HTTPS from Windows', page.run("!!document.querySelector('form.login')"))
        check('the session cookie is out of reach of scripts', 'siem_session' not in (page.run('document.cookie') or ''))
        page.shot(folder, '00-signin')
        page.run("""(() => { const set = (n, v) => { const e = document.querySelector(`input[name=${n}]`); e.value = v; }; set('username', 'nobody'); set('password', 'wrong-password-here'); document.querySelector('form.login').requestSubmit(); })()""")
        limit = time.time() + 8
        while time.time() < limit and 'not accepted' not in page.run("document.querySelector('form.login').innerText"):
            time.sleep(0.2)
        check('a wrong password shows an error, and no page', 'not accepted' in page.run("document.querySelector('form.login').innerText"))
        page.run(f"""(() => {{ const set = (n, v) => {{ const e = document.querySelector(`input[name=${{n}}]`); e.value = v; }}; set('username', {json.dumps(USER)}); set('password', {json.dumps(PASSWORD)}); document.querySelector('form.login').requestSubmit(); }})()""")
        time.sleep(2)
        check('sign-in reaches the overview', page.settle() and 'Overview' in page.text())
        check('after sign-in the cookie is still hidden', 'siem_session' not in (page.run('document.cookie') or ''))
        nav = page.run("[...document.querySelectorAll('nav.side a')].map(a => a.textContent).join('|')") or ''
        menu = 'Overview|Events|Alerts|Incidents|Investigations|Attack Paths|Assets|Threat Intelligence|Pipeline Health|Audit History|Settings'
        check('the menu is exactly the Version 1 set', nav == menu, nav)
        routes = [('overview', 'Security'), ('events', 'Events'), ('alerts', 'Alerts'), ('incidents', 'Incidents'), ('investigations', 'Investigations'), ('paths', 'Attack Paths'), ('assets', 'Assets'), ('intelligence', 'Threat Intelligence'), ('health', 'Pipeline Health'), ('audit', 'Audit History'), ('settings', 'Change password')]
        for index, (route, word) in enumerate(routes):
            page.run(f"location.hash = '#/{route}'")
            time.sleep(0.6)
            ready = page.settle()
            text = page.text()
            check(f'{route} renders', ready and word in text and 'Something went wrong' not in text, f'{len(text)} characters')
            page.shot(folder, f'{index + 1:02d}-{route}')
            links = page.run("[...document.querySelectorAll('a[href^=\"#/\"]')].map(a => a.getAttribute('href').split('?')[0].split('/')[1]).join('|')") or ''
            stray = sorted({l for l in links.split('|') if l and l not in PAGES})
            check(f'{route}: every link goes to a Version 1 page', not stray, ', '.join(stray))

        # Pages named on the command line with --probe must not exist: each shows the not-found page, and asks the API nothing.
        for name in PROBES:
            before = len(page.responses)
            page.run(f"location.hash = '#/{name}'")
            time.sleep(0.8)
            page.settle()
            asked = [u for _, u in page.responses[before:] if f'/api/v1/{name}' in u]
            check(f'probe {name}: no such page, and no API request', 'No such page.' in page.text() and not asked, f'{len(asked)} requests')
            page.shot(folder, f'probe-{name}')

        # The investigation chain, by following the links on the screen.
        click = lambda selector: page.run(f"(() => {{ const e = document.querySelector({json.dumps(selector)}); if (!e) return false; e.click(); return true; }})()")
        page.run("location.hash = '#/incidents'")
        time.sleep(0.8)
        page.settle()
        check('an incident can be opened from the list', click("main td a[href^='#/incidents/']"))
        time.sleep(1)
        page.settle()
        incident_url = page.run('location.hash')
        check('the workspace shows evidence, audit and paths together', all(w in page.text() for w in ('Evidence', 'Audit history', 'Attack paths', 'Analyst notes', 'Timeline')))
        page.shot(folder, '20-incident')
        page.call('Page.reload')
        time.sleep(2)
        page.settle()
        check('a refresh stays on the incident, still signed in', page.run('location.hash') == incident_url and 'Audit history' in page.text())
        check('an alert can be opened from the incident', click("main td a[href^='#/alerts/']"))
        time.sleep(1)
        page.settle()
        check('the alert says its matched values are withheld', 'withheld' in page.text())
        page.shot(folder, '21-alert')
        check('the trail remembers the way back', page.run("!!document.querySelector('.trail a[href^=\"#/incidents/\"]')"))
        page.run("history.back()")
        time.sleep(1)
        page.settle()
        check('Back returns to the incident', page.run('location.hash') == incident_url)

        # The graph, by real clicks on real data.
        page.run("location.hash = '#/paths?tier=confirmed_observation'")
        time.sleep(1)
        page.settle()
        check('a path can be opened', click("main td a[href^='#/paths/']"))
        time.sleep(1.5)
        page.settle()
        check('the path says it proves nothing', 'not proof of compromise' in page.text())
        check('a graph is drawn', page.run("document.querySelectorAll('svg.graph .node').length") > 0, f"{page.run(chr(34).join(['document.querySelectorAll(', 'svg.graph .node', ').length']).replace(chr(34) + 'svg', chr(39) + 'svg').replace('node' + chr(34), 'node' + chr(39)))} nodes")
        page.shot(folder, '22-path')
        page.run("document.querySelector('svg.graph .node').dispatchEvent(new MouseEvent('click', {bubbles: true}))")
        time.sleep(0.5)
        check('a node can be inspected', 'Node' in page.run("document.querySelector('.graph-wrap section').innerText"))
        had_edge = page.run("(() => { const e = document.querySelector('svg.graph path.edge'); if (!e) return false; e.dispatchEvent(new MouseEvent('click', {bubbles: true})); return true; })()")
        time.sleep(1.5)
        if had_edge:
            check('an edge shows its evidence', 'Evidence' in page.run("document.querySelector('.graph-wrap section').innerText"))
            page.shot(folder, '23-edge')

        # Hostile text, through the real page.
        payload = '<img src=x onerror=window.__xss=1><script>window.__xss=1</script>'
        page.run(f"location.hash = '#/events?host=' + encodeURIComponent({json.dumps(payload)})")
        time.sleep(1.2)
        page.settle()
        page.run(f"location.hash = '#/search?q=' + encodeURIComponent({json.dumps(payload)})")
        time.sleep(1.2)
        page.settle()
        check('script in the address does not run', page.run('window.__xss === undefined'))
        check('no image was injected', page.run("document.querySelectorAll('main img').length") == 0)
        blocked = page.run("(() => { try { const s = document.createElement('script'); s.textContent = 'window.__inline = 1'; document.head.append(s); return window.__inline === undefined; } catch { return true; } })()")
        check('the content security policy blocks inline script', blocked)
        page.problems = [p for p in page.problems if 'Content Security Policy' not in p and 'inline script' not in p]

        # Sign-out, and a dead session.
        page.run("location.hash = '#/overview'")
        time.sleep(1)
        page.settle()
        page.run("[...document.querySelectorAll('button')].find((b) => b.textContent === 'Sign out').click()")
        time.sleep(1.5)
        check('sign-out returns to sign-in', page.run("!!document.querySelector('form.login')"))
        page.call('Page.reload')
        time.sleep(1.5)
        check('a refresh after sign-out stays signed out', page.run("!!document.querySelector('form.login')"))
        wanted = [p for p in page.problems if '401' not in p]
        check('no script error or policy violation on any page', not wanted, '; '.join(wanted[:4]))
        bad = sorted({f'{s} {u}' for s, u in page.responses if s and s >= 500})
        check('no server error on any page', not bad, '; '.join(bad[:4]))
    finally:
        browser.terminate()
        try:
            browser.wait(10)
        except subprocess.TimeoutExpired:
            browser.kill()
        shutil.rmtree(profile, ignore_errors=True)
        if administrator() == USER:
            removed = subprocess.run([*WSL, 'remove'], capture_output=True, text=True)
            print('INFO', removed.stdout.strip())
        else:
            print('INFO the temporary administrator is gone already, so nothing was removed')
    print(f'browser: {len(failures)} failed' + (f': {failures}' if failures else ''))
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
