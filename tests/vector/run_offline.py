"""Offline D22 tests. No service, no Kafka, no real events. All secrets are fake.

Chains the real agent transforms into the real aggregator, through the real seal verifier over
mutual TLS, then attacks them with tampered, malformed and fuzzed input. Only Kafka is simulated.
Exit 0 means every check passed.

Usage: python tests/vector/run_offline.py <vector> <seal-verifier> <verifier-pki>
"""
import base64
import hashlib
import hmac
import json
import pathlib
import random
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

import yaml

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from corpus import keep, sec  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
AGENT = yaml.safe_load((ROOT / 'config/windows/vector/vector-agent.yaml').read_text(encoding='utf8'))
AGG = yaml.safe_load((ROOT / 'config/wsl/vector/vector-aggregator.yaml').read_text(encoding='utf8'))
SYSMON = 'Microsoft-Windows-Sysmon/Operational'
POWERSHELL = 'Microsoft-Windows-PowerShell/Operational'
CANARY = 'FakeSecret1'
failures = []


def check(name, ok, detail=''):
    print(('PASS ' if ok else 'FAIL ') + name + (f' ({detail})' if detail else ''))
    if not ok:
        failures.append(name)


def run(vector, cfg, work, name, stdin):
    path = work / f'{name}.json'
    path.write_text(json.dumps(cfg), encoding='utf8')
    r = subprocess.run([vector, '--config', str(path), '--quiet'], input=stdin, capture_output=True, text=True, encoding='utf8', timeout=180)
    return r


def file_sink(work, name, inputs):
    return {'type': 'file', 'inputs': inputs, 'path': (work / f'{name}.ndjson').as_posix(), 'encoding': {'codec': 'json'}, 'buffer': {'type': 'memory', 'max_events': 100000, 'when_full': 'block'}}


def read(work, name):
    p = work / f'{name}.ndjson'
    return [json.loads(l) for l in p.read_text(encoding='utf8').split(chr(10)) if l.strip()] if p.exists() else []


def finished(work, name):
    """Counts lines without parsing, because Vector may still be writing the file."""
    p = work / f'{name}.ndjson'
    return p.read_bytes().count(b'\n') if p.exists() else 0


def secret_for(work):
    return {'field_keys': {'type': 'file', 'path': (work / 'keys.json').as_posix()}}


def agent_cfg(work):
    return {'data_dir': (work / 'data').as_posix(), 'secret': secret_for(work),
            'sources': {'win_in': {'type': 'stdin', 'decoding': {'codec': 'json'}}},
            'transforms': {k: AGENT['transforms'][k] for k in ('protect', 'protect_failed', 'envelope', 'envelope_failed')},
            'sinks': {'out': file_sink(work, 'agent', ['envelope', 'envelope_failed'])}}


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def wait_port(port):
    for _ in range(100):
        try:
            socket.create_connection(('127.0.0.1', port), 1).close()
            return
        except OSError:
            time.sleep(.1)
    raise SystemExit(f'port {port} did not open')


class Chain:
    """The real aggregator configuration and real verifier. Only Kafka and the sinks differ."""

    def __init__(self, vector, verifier, work):
        self.vector, self.verifier, self.work = vector, verifier, work
        self.tls = (work / 'tls').as_posix()
        self.verify_port, self.source_port, self.metrics_port = free_port(), free_port(), free_port()
        self.proc = None
        self.runs = 0

    def start_verifier(self, journal=None):
        t = self.tls
        self.runs += 1
        self.journal = journal or str(self.work / f'journal-{self.runs}')
        self.proc = subprocess.Popen([self.verifier, '-identity-dir', self.journal, '-listen', f'127.0.0.1:{self.verify_port}', '-metrics', f'127.0.0.1:{self.metrics_port}',
                                      '-downstream', f'https://127.0.0.1:{self.source_port}/v1/verified', '-keys', str(self.work / 'keys.json'),
                                      '-server-cert', f'{t}/verifier.crt', '-server-key', f'{t}/verifier.key', '-client-ca', f'{t}/vector-ca.crt',
                                      '-down-cert', f'{t}/verifier.crt', '-down-key', f'{t}/verifier.key', '-down-ca', f'{t}/vector-ca.crt'],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        wait_port(self.metrics_port)

    def stop_verifier(self):
        self.proc.terminate()
        self.proc.wait(10)

    def config(self):
        t = json.loads(json.dumps({k: AGG['transforms'][k] for k in ('ingest', 'ingest_failed', 'from_verifier_clean', 'sort_events')}))
        t['ingest']['inputs'] = ['kafka_sim']
        t['kafka_sim'] = {'type': 'remap', 'inputs': ['raw_in'], 'source': '.topic = "siem-raw-logs"\n.partition = 0\n.offset = 1'}
        source = json.loads(json.dumps(AGG['sources']['from_verifier']))
        source['address'] = f'127.0.0.1:{self.source_port}'
        source['tls'].update(crt_file=f'{self.tls}/vector.crt', key_file=f'{self.tls}/vector.key', ca_file=f'{self.tls}/verifier-ca.crt')
        sink = json.loads(json.dumps(AGG['sinks']['to_verifier']))
        sink['uri'] = f'https://127.0.0.1:{self.verify_port}/v1/verify'
        sink['tls'].update(ca_file=f'{self.tls}/verifier-ca.crt', crt_file=f'{self.tls}/vector.crt', key_file=f'{self.tls}/vector.key')
        return {'data_dir': (self.work / 'data').as_posix(),
                'sources': {'raw_in': {'type': 'stdin', 'decoding': {'codec': 'bytes'}, 'max_length': 4000000}, 'from_verifier': source},
                'transforms': t,
                'sinks': {'to_verifier': sink, 'good': file_sink(self.work, 'good', ['sort_events.good']), 'dead': file_sink(self.work, 'dead', ['sort_events.dead'])}}

    def launch(self, name):
        for f in ('good', 'dead'):
            (self.work / f'{f}.ndjson').unlink(missing_ok=True)
        path = self.work / f'{name}.json'
        path.write_text(json.dumps(self.config()), encoding='utf8')
        proc = subprocess.Popen([self.vector, '--config', str(path), '--quiet'], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        wait_port(self.source_port)
        return proc

    def result(self, name):
        text = urllib.request.urlopen(f'http://127.0.0.1:{self.metrics_port}/metrics', timeout=5).read().decode()
        for line in text.splitlines():
            if f'result="{name}"' in line:
                return int(line.split()[-1])
        return 0

    def run(self, name, lines, timeout=120, journal=None):
        """Feeds lines and waits for every one to come out. The source never ends by itself."""
        self.stop_verifier()
        self.start_verifier(journal)
        proc = self.launch(name)
        proc.stdin.write(('\n'.join(lines) + '\n').encode('utf8', 'surrogateescape'))
        proc.stdin.close()
        deadline = time.time() + timeout
        while time.time() < deadline and proc.poll() is None:
            if finished(self.work, 'good') + finished(self.work, 'dead') + self.result('replayed') >= len(lines):
                break
            time.sleep(.25)
        code = proc.poll()
        time.sleep(.5)
        proc.terminate()
        stderr = proc.stderr.read().decode('utf8', 'replace')
        proc.wait(20)
        return code, stderr


def event(channel, event_id, record_id, data, **extra):
    return {'channel': channel, 'event_id': event_id, 'record_id': record_id, 'computer': 'HOST', 'timestamp': '2026-10-31T00:00:00.000Z', 'event_data': data, 'message': 'Event', **extra}


def monitor_unit_checks():
    """A monitor that pulled in the service it watches would start it, and hide the outage."""
    root = ROOT / 'deploy' / 'systemd'
    for name in ('siem-kafka-expiry-check', 'siem-disk-guard'):
        text = (root / f'{name}.service').read_text()
        pulled = [line for line in text.splitlines() if line.startswith(('Requires=', 'Wants=', 'BindsTo='))]
        check(f'{name} does not start what it watches', not pulled, pulled)


def route_checks():
    """Proves from the real configuration that no route avoids the verifier."""
    parts = {**AGG['sources'], **AGG['transforms'], **AGG['sinks']}

    def ancestors(name, seen=None):
        seen = set() if seen is None else seen
        base = name.split('.')[0]
        if base in seen:
            return seen
        seen.add(base)
        for parent in parts.get(base, {}).get('inputs', []):
            ancestors(parent, seen)
        return seen

    outputs = [n for n, s in AGG['sinks'].items() if s['type'] in ('opensearch', 'elasticsearch')]
    check('route: all OpenSearch outputs exist', sorted(outputs) == ['opensearch_dead', 'opensearch_events', 'opensearch_linux'], str(outputs))
    for name in outputs:
        reached = ancestors(name)
        check(f'route: {name} comes only from the verifier', 'from_verifier' in reached and not reached & {'siem_raw', 'ingest', 'ingest_failed'}, str(sorted(reached)))
    consumers = sorted(n for n, p in parts.items() if any(i.split('.')[0] in ('ingest', 'ingest_failed', 'siem_raw') for i in p.get('inputs', [])) and n not in ('ingest', 'ingest_failed'))
    check('route: the verifier hop is the only way out of ingest', consumers == ['to_verifier'], str(consumers))
    check('route: no blackhole sink', not [n for n, s in AGG['sinks'].items() if s['type'] == 'blackhole'])
    text = (ROOT / 'config/wsl/vector/vector-aggregator.yaml').read_text(encoding='utf8')
    check('route: no field keys or decrypt in the aggregator', 'field_keys' not in text and 'decrypt(' not in text and 'hmac(' not in text)
    tls = AGG['sources']['from_verifier']['tls']
    check('route: the trusted source requires a client certificate', tls.get('enabled') is True and tls.get('verify_certificate') is True and 'verifier-ca' in tls.get('ca_file', ''))


def main(vector, verifier, pki):
    route_checks()
    monitor_unit_checks()
    tmp = tempfile.TemporaryDirectory(prefix='d22-')
    work = pathlib.Path(tmp.name)
    (work / 'data').mkdir()
    keys = {'k1_enc': secrets.token_hex(32), 'k1_mac': secrets.token_hex(32)}
    (work / 'keys.json').write_text(json.dumps(keys))
    (work / 'keys.json').chmod(0o600)

    def sign(event):
        """Builds what a key holder would send, so a test can reach the checks after authentication."""
        body = json.dumps(event, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
        mac = hmac.new(bytes.fromhex(keys['k1_mac']), f'siem-event-v1|k1|{body}'.encode(), hashlib.sha256).digest()
        return json.dumps({'v': 'siem-event-v1', 'k': 'k1', 'event_uid': event.get('event_uid'), 'body': body, 'mac': base64.b64encode(mac).decode()})

    subprocess.run([pki, '-out', str(work / 'tls')], check=True)
    chain = Chain(vector, verifier, work)
    chain.start_verifier()

    secret_cmd = f'tool.exe --password={CANARY} --keep me'
    cases = [
        event(SYSMON, 1, 100, {'CommandLine': secret_cmd, 'ParentCommandLine': f'net user bob {CANARY} /add', 'Image': 'C:\\t\\tool.exe', 'User': 'HOST\\bob'}),
        event(SYSMON, 1, 101, {'CommandLine': secret_cmd, 'ParentCommandLine': '', 'Image': 'C:\\t\\tool.exe'}),
        event(SYSMON, 1, 195, {'CommandLine': 'mangled', 'Image': 'mangled'}, xml=f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System/><EventData><Data Name="CommandLine">cmd /c a &amp;&amp; b &gt; c --password={CANARY} &lt;in  2&gt;&amp;1</Data><Data Name="Image">C:\\t &amp; u\\x.exe</Data><Data Name="User"></Data></EventData></Event>'),
        event(SYSMON, 1, 196, {'CommandLine': f'tool --password={CANARY}', 'Image': 'C:\\y.exe'}, xml=f'<Event><unclosed>{CANARY}'),
        event(POWERSHELL, 4104, 197, {'ScriptBlockText': 'mangled'}, xml=f"<Event><EventData><Data Name='ScriptBlockText'>$a = 1 &amp;&amp; 2\r\n$password = '{CANARY}'\r\nGet-Date</Data></EventData></Event>"),
        event('System', 7040, 402, {'param1': 'mangled'}, xml='<Event><EventData><Data Name="param1">A &amp; B</Data></EventData></Event>'),
        event(SYSMON, 13, 102, {'Details': f'cmd /c tool --token {CANARY}', 'TargetObject': 'HKLM\\x'}),
        event(SYSMON, 19, 103, {'Query': f'select x where y = "--pass {CANARY}"', 'Name': 'q'}),
        event(SYSMON, 20, 104, {'Destination': f'cmd /c tool --secret {CANARY}', 'Name': 'd'}),
        event(POWERSHELL, 4104, 200, {'ScriptBlockText': f"$password = '{CANARY}'\nGet-Date", 'ScriptBlockId': 'abc', 'MessageNumber': 1, 'MessageTotal': 1, 'Path': ''}),
        event(POWERSHELL, 4100, 201, {'ContextInfo': f'--password {CANARY}', 'Payload': f'--password {CANARY}', 'UserData': f'--password {CANARY}'}),
        event('Security', 4688, 300, {'CommandLine': '', 'NewProcessName': 'C:\\x.exe'}, xml='<Event>copy</Event>'),
        event('Security', 4697, 301, {'ServiceFileName': f'svc.exe --password {CANARY}', 'ServiceName': 's'}, xml=f'<Event>{CANARY}</Event>'),
        event('System', 7045, 400, {'ImagePath': f'svc.exe --password {CANARY}', 'ServiceName': 's'}, xml=f'<Event>{CANARY}</Event>'),
        event('Security', 1102, 302, {}, xml='<Event>keep</Event>'),
        event('System', 104, 401, {}, xml='<Event>keep</Event>'),
        event('Security', 4624, 303, {'TargetUserName': 'bob'}, xml='<Event>drop</Event>'),
        event(SYSMON, 1, 105, {'CommandLine': 'A' * 200000, 'ParentCommandLine': 'p', 'Image': 'i'}),
        event(SYSMON, 3, 106, {'Image': 'i'}, string_inserts=[f'--password {CANARY}']),
        event(SYSMON, 22, 107, 'not-an-object'),
    ]
    stdin = '\n'.join(json.dumps(c) for c in cases) + '\n'
    r = run(vector, agent_cfg(work), work, 'agent', stdin)
    check('agent run exits cleanly', r.returncode == 0, f'exit {r.returncode} {r.stderr[-300:] if r.returncode else ""}')
    out = read(work, 'agent')
    check('every agent event survives', len(out) == len(cases), f'{len(out)} of {len(cases)}')
    text = json.dumps(out)
    envelopes = out
    check('every event is an envelope of exactly five fields', all(sorted(e) == ['body', 'event_uid', 'k', 'mac', 'v'] for e in envelopes))
    out = [json.loads(e['body']) for e in envelopes]
    check('the body is canonical, with sorted keys and no spaces', all(e['body'] == json.dumps(json.loads(e['body']), sort_keys=True, separators=(',', ':'), ensure_ascii=False) for e in envelopes))
    check('the envelope MAC covers the exact body', all(base64.b64decode(e['mac']) == hmac.new(bytes.fromhex(keys['k1_mac']), f"siem-event-v1|k1|{e['body']}".encode(), hashlib.sha256).digest() for e in envelopes))
    check('envelope identity matches the body', all(e['event_uid'] == json.loads(e['body'])['event_uid'] for e in envelopes))
    check('canary absent from all agent output', CANARY not in text)
    check('no restricted plaintext in agent output', 'tool.exe --' not in text and 'Get-Date' not in text)
    by = {str(e.get('record_id')): e for e in out}
    check('message removed', not any('message' in e for e in out))
    check('xml kept only on 1102 and 104', {str(e['record_id']) for e in out if 'xml' in e} == {'302', '401'})
    check('Sysmon 1 fields sealed', set(by['100']['sealed']) == {'CommandLine', 'ParentCommandLine'})
    check('empty field not sealed', set(by['101']['sealed']) == {'CommandLine'})
    check('plain fields stay plain', by['100']['event_data']['Image'] == 'C:\\t\\tool.exe')
    check('XML entities are restored in plain fields', by['195']['event_data']['Image'] == 'C:\\t & u\\x.exe')
    check('a single XML field is restored', by['402']['event_data']['param1'] == 'A & B')
    check('rebuilt fields are redacted and sealed', 'CommandLine' not in by['195']['event_data'] and 'CommandLine' in by['195']['sealed'])
    check('unparsable XML keeps event_data, labelled', by['196']['event_data']['Image'] == 'C:\\y.exe' and by['196']['labels'].get('xml_fallback') is True)
    check('unparsable XML is still sealed', 'CommandLine' in by['196']['sealed'] and CANARY not in json.dumps(by['196']))
    check('redaction rules recorded', sorted(by['100']['labels']['redactions']) == ['arg', 'net'])
    check('oversized field truncated with its length', by['105']['labels']['truncated'] == {'CommandLine': 200000})
    check('string_inserts sealed', '_string_inserts' in by['106']['sealed'] and 'string_inserts' not in by['106'])
    failed = [e for e in out if e.get('labels', {}).get('seal_failed')]
    check('runtime failure fails closed', len(failed) == 1 and 'event_data' not in failed[0] and 'not-an-object' not in json.dumps(failed[0]))

    # Round trip through the real aggregator logic.
    code, stderr = chain.run('agg1', [json.dumps(e) for e in envelopes])
    check('aggregator round trip keeps running', code is None, f'exit {code} {stderr[-300:]}')
    good = {str(e.get('record_id')): e for e in read(work, 'good')}
    dead = read(work, 'dead')
    check('all protected events verify', len(good) == len(out), f'{len(good)} good, {len(dead)} dead {[d["dlq"]["reason"] for d in dead]}')
    check('fields restored, secret redacted', good.get('100', {}).get('event_data', {}).get('CommandLine') == 'tool.exe --password=[REDACTED:arg] --keep me')
    check('script restored', good.get('200', {}).get('event_data', {}).get('ScriptBlockText') == "$password = [REDACTED:assign]\nGet-Date")
    check('line endings survive the XML rebuild', good.get('197', {}).get('event_data', {}).get('ScriptBlockText') == "$a = 1 && 2\r\n$password = [REDACTED:assign]\r\nGet-Date", repr(good.get('197', {}).get('event_data', {}).get('ScriptBlockText')))
    check('rebuilt command line is exact', good.get('195', {}).get('event_data', {}).get('CommandLine') == 'cmd /c a && b > c --password=[REDACTED:arg] <in  2>&1')
    check('all 4100 fields restored', len([k for k in ('ContextInfo', 'Payload', 'UserData') if k in good.get('201', {}).get('event_data', {})]) == 3)
    check('canary absent after decrypt', CANARY not in json.dumps(list(good.values())))
    check('sealed removed from good events', not any('sealed' in e for e in good.values()))
    check('source event time survives the hop', good.get('100', {}).get('timestamp', '').startswith('2026-10-31T00:00:00'), good.get('100', {}).get('timestamp'))
    check('hop adds no request path', not any('path' in e for e in good.values()))
    check('source_type survives the hop', good.get('100', {}).get('source_type') == by['100'].get('source_type'), str(good.get('100', {}).get('source_type')))

    restored = good

    # Redaction corpus, through the real agent and aggregator logic.
    corpus = [event(POWERSHELL, 4104, 5000 + i, {'ScriptBlockText': v, 'MessageNumber': 1, 'MessageTotal': 1}) for i, v in enumerate(sec + keep)]
    (work / 'agent.ndjson').unlink()
    run(vector, agent_cfg(work), work, 'agent', '\n'.join(json.dumps(c) for c in corpus) + '\n')
    chain.run('agg-corpus', (work / 'agent.ndjson').read_text(encoding='utf8').splitlines())
    result = {str(e['record_id']): e['event_data']['ScriptBlockText'] for e in read(work, 'good')}
    check('corpus: every event round trips', len(result) == len(corpus), f'{len(result)} of {len(corpus)}')
    bad = ('FakeSecret1', 'AKIAABC', 'aaaaaaaa', 'bbbbbbbb', 'eyJhbG', 'MIIEfake')
    missed = [result.get(str(5000 + i)) for i in range(len(sec)) if any(b in result.get(str(5000 + i), '') for b in bad)]
    check('corpus: all fake secrets redacted', not missed, f'{len(sec) - len(missed)} of {len(sec)} {missed}')
    altered = [(v, result.get(str(5000 + len(sec) + i))) for i, v in enumerate(keep) if result.get(str(5000 + len(sec) + i)) != v]
    check('corpus: detection-relevant commands byte-identical', not altered, f'{len(keep) - len(altered)} of {len(keep)} {altered}')
    check('corpus: no replacement artefacts', not [r for r in result.values() if '{1}' in r or '{3}' in r])
    expected = {0: 'mysql.exe -u root -p[REDACTED:arg] -h db', 1: 'tool.exe --password=[REDACTED:arg]', 8: 'net user bob [REDACTED:net] /add', 12: 'git clone https://bob:[REDACTED:url]@git.example/r.git'}
    wrong = {k: result.get(str(5000 + k)) for k, v in expected.items() if result.get(str(5000 + k)) != v}
    check('corpus: argument names and context kept', not wrong, str(wrong) if wrong else '')

    # IV uniqueness.
    many = [event(POWERSHELL, 4104, 1000 + i, {'ScriptBlockText': 'same text', 'MessageNumber': 1, 'MessageTotal': 1}) for i in range(5000)]
    (work / 'agent.ndjson').unlink()
    run(vector, agent_cfg(work), work, 'agent', '\n'.join(json.dumps(c) for c in many) + '\n')
    sealed = [json.loads(e['body'])['sealed']['ScriptBlockText'] for e in read(work, 'agent')]
    check('5,000 encryptions, 5,000 unique IVs', len({s['iv'] for s in sealed}) == 5000 and len(sealed) == 5000)
    check('identical text gives unique ciphertext', len({s['ct'] for s in sealed}) == 5000)

    # Attacks on the aggregator.
    base = by['100']
    other = by['200']

    def mutated(fn):
        e = json.loads(json.dumps(base))
        fn(e)
        return sign(e)

    def flip(s):
        b = bytearray(base64.b64decode(s))
        b[0] ^= 1
        return base64.b64encode(bytes(b)).decode()

    def setv(path, value):
        return lambda e: e['sealed']['CommandLine'].__setitem__(path, value)

    attacks = {
        'mac_mismatch ct': mutated(lambda e: setv('ct', flip(e['sealed']['CommandLine']['ct']))(e)),
        'mac_mismatch iv': mutated(lambda e: setv('iv', flip(e['sealed']['CommandLine']['iv']))(e)),
        'mac_mismatch mac': mutated(lambda e: setv('mac', flip(e['sealed']['CommandLine']['mac']))(e)),
        'mac_mismatch swapped field': mutated(lambda e: e['sealed'].update({'CommandLine': e['sealed']['ParentCommandLine']})),
        'mac_mismatch other event': mutated(lambda e: e.__setitem__('record_id', 999)),
        'mac_mismatch other uid': mutated(lambda e: e.__setitem__('event_uid', 'a' * 64)),
        'unknown_key_id': mutated(lambda e: setv('k', 'k9')(e)),
        'bad_length short iv': mutated(lambda e: setv('iv', base64.b64encode(b'short').decode())(e)),
        'bad_length short mac': mutated(lambda e: setv('mac', base64.b64encode(b'short').decode())(e)),
        'bad_length huge ct': mutated(lambda e: setv('ct', base64.b64encode(b'x' * 200000).decode())(e)),
        'bad_encoding': mutated(lambda e: setv('ct', '!!!not base64!!!')(e)),
        'sealed_shape': mutated(lambda e: e['sealed'].__setitem__('CommandLine', 'text')),
        'sealed_field_not_allowed': mutated(lambda e: e['sealed'].__setitem__('Image', e['sealed']['CommandLine'])),
        'sealed_too_many': mutated(lambda e: e['sealed'].update({f'x{i}': {} for i in range(9)})),
        'schema_sealed': mutated(lambda e: e.__setitem__('sealed', 'text')),
        'schema_identity': mutated(lambda e: e.__setitem__('event_uid', 'nope')),
        'schema_channel': mutated(lambda e: e.__setitem__('channel', 'Other')),
        'schema_ids': mutated(lambda e: e.__setitem__('record_id', 'x')),
        'schema_timestamp': mutated(lambda e: e.__setitem__('timestamp', 'not a time')),
        'schema_event_data': mutated(lambda e: e.__setitem__('event_data', 'text')),
        'schema_unknown_field': mutated(lambda e: e.__setitem__('5ealed', e.pop('sealed'))),
        'unsealed_restricted': mutated(lambda e: e['event_data'].__setitem__('CommandLine', f'forged {CANARY}')),
        'seal_missing': mutated(lambda e: (e.pop('sealed'))),
        'malformed_json garbage': '{"not json',
        'malformed_json array': '[1,2,3]',
        'malformed_json deep': '[' * 500,
        'size': 'x' * 1500000,
    }
    code, stderr = chain.run('agg2', list(attacks.values()))
    check('attacks: aggregator did not crash', code is None, f'exit {code} {stderr[-300:]}')
    dead = read(work, 'dead')
    good = read(work, 'good')
    check('attacks: none accepted', len(good) == 0, f'{len(good)} accepted')
    check('attacks: all dead-lettered', len(dead) == len(attacks), f'{len(dead)} of {len(attacks)}')
    reasons = [d['dlq']['reason'] for d in dead]
    for (name, _), reason in zip(attacks.items(), reasons):
        check(f'attack {name}', reason == name.split(' ')[0], reason)
    text = json.dumps(dead)
    check('dead-letter holds no plaintext or event_data', CANARY not in text and not any('event_data' in d for d in dead) and 'xxxxxxxx' not in text)
    check('dead-letter keeps ciphertext for failed seals', any('sealed' in d for d in dead))

    # Authentication failures on the MAC itself: each must be rejected for the expected reason.
    mac = base64.b64decode(base['sealed']['CommandLine']['mac'])
    b64 = lambda b: base64.b64encode(b).decode()

    def at(position):
        b = bytearray(mac)
        b[position] ^= 0x80
        return b64(bytes(b))

    auth = {f'mac_mismatch byte {i}': mutated(lambda e, i=i: setv('mac', at(i))(e)) for i in range(32)}
    auth.update({
        'mac_mismatch all zero': mutated(lambda e: setv('mac', b64(bytes(32)))(e)),
        'mac_mismatch all ones': mutated(lambda e: setv('mac', b64(b'\xff' * 32))(e)),
        'mac_mismatch from other event': mutated(lambda e: setv('mac', other['sealed'][next(iter(other['sealed']))]['mac'])(e)),
        'sealed_field_not_allowed other channel': mutated(lambda e: e.__setitem__('channel', 'Microsoft-Windows-PowerShell/Operational')),
        'sealed_field_not_allowed other event id': mutated(lambda e: e.__setitem__('event_id', 13)),
        'mac_mismatch moved to security 4688': mutated(lambda e: (e.update({'channel': 'Security', 'event_id': 4688}), e['sealed'].pop('ParentCommandLine'))),
        'bad_length empty mac': mutated(lambda e: setv('mac', '')(e)),
        'bad_length mac 31': mutated(lambda e: setv('mac', b64(mac[:31]))(e)),
        'bad_length mac 33': mutated(lambda e: setv('mac', b64(mac + b'x'))(e)),
        'bad_length mac 64': mutated(lambda e: setv('mac', b64(mac + mac))(e)),
        'sealed_shape null mac': mutated(lambda e: setv('mac', None)(e)),
        'sealed_shape number mac': mutated(lambda e: setv('mac', 12345)(e)),
        'sealed_shape array mac': mutated(lambda e: setv('mac', [1, 2])(e)),
        'sealed_shape object mac': mutated(lambda e: setv('mac', {'a': 1})(e)),
        'sealed_shape missing mac': mutated(lambda e: e['sealed']['CommandLine'].pop('mac')),
        'bad_encoding invalid mac': mutated(lambda e: setv('mac', '!' * 44)(e)),
        'unknown_key_id null': mutated(lambda e: setv('k', None)(e)),
        'unknown_key_id missing': mutated(lambda e: e['sealed']['CommandLine'].pop('k')),
    })
    # A bad second field must reject the whole event, with no partial plaintext.
    auth['mac_mismatch second field'] = mutated(lambda e: e['sealed']['ParentCommandLine'].__setitem__('mac', b64(bytes(32))))
    code, stderr = chain.run('agg4', list(auth.values()))
    good, dead = read(work, 'good'), read(work, 'dead')
    check('auth failures: aggregator did not crash', code is None, f'exit {code} {stderr[-300:]}')
    check('auth failures: none accepted', len(good) == 0, f'{len(good)} accepted')
    check('auth failures: all dead-lettered', len(dead) == len(auth), f'{len(dead)} of {len(auth)}')
    for (name, _), record in zip(auth.items(), dead):
        check(f'auth {name}', record['dlq']['reason'] == name.split(' ')[0], record['dlq']['reason'])
    check('auth failures: no plaintext in dead-letter', CANARY not in json.dumps(dead) and not any('event_data' in d for d in dead))

    # Whole-event authentication: the same changes with no key must all fail at the envelope.
    def forged(fn):
        e = json.loads(json.dumps(base))
        fn(e)
        envelope = json.loads(sign(base))
        envelope['body'] = json.dumps(e, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
        return json.dumps(envelope)

    changes = {
        'unsealed field': lambda e: e['event_data'].__setitem__('Image', 'C:\\evil.exe'),
        'user': lambda e: e['event_data'].__setitem__('User', 'HOST\\admin'),
        'timestamp': lambda e: e.__setitem__('timestamp', '2020-01-01T00:00:00.000Z'),
        'computer': lambda e: e.__setitem__('computer', 'OTHER'),
        'labels': lambda e: e['labels'].__setitem__('seal_failed', True),
        'identity': lambda e: e.__setitem__('event_uid', 'd' * 64),
        'seal removed': lambda e: e.pop('sealed'),
        'added field': lambda e: e.__setitem__('extra', 1),
    }
    code, stderr = chain.run('agg5', [forged(fn) for fn in changes.values()] + [json.dumps(base), '{"v":"siem-event-v1","failed":true}'])
    dead = read(work, 'dead')
    check('forgery: no change to an event passes without the key', len(read(work, 'good')) == 0 and code is None, f"{len(read(work, 'good'))} accepted")
    reasons = [d['dlq']['reason'] for d in dead]
    check('forgery: every changed event fails at the envelope MAC', reasons[:len(changes)] == ['mac_mismatch'] * len(changes), str(reasons))
    check('forgery: a bare event, the old format, has no authentication', reasons[-2:] == ['auth_missing', 'auth_missing'], str(reasons[-2:]))
    check('forgery: dead letters hold no event content', 'evil' not in json.dumps(dead) and not any('event_data' in d for d in dead))

    # Replay survives a verifier restart, because the journal is on disk.
    journal = str(work / 'journal-durable')
    first = json.dumps(envelopes[0])
    chain.run('replay1', [first], journal=journal)
    check('replay: first delivery indexed', len(read(work, 'good')) == 1)
    chain.run('replay2', [first], journal=journal)
    check('replay: redelivery after a restart forwards nothing', len(read(work, 'good')) == 0 and chain.result('replayed') == 1, str(chain.result('replayed')))
    changed = json.loads(envelopes[0]['body'])
    changed['event_data']['Image'] = 'C:\\evil.exe'
    chain.run('replay3', [sign(changed)], journal=journal)
    dead = read(work, 'dead')
    check('replay: a signed change to a stored identity is refused after a restart', len(dead) == 1 and dead[0]['dlq']['reason'] == 'replay_conflict', str([d['dlq']['reason'] for d in dead]))

    # Fuzz: random corruption of valid messages.
    rng = random.Random(7)
    lines = []
    seeds = [json.dumps(next(n for n in envelopes if json.loads(n['body'])['record_id'] == e['record_id'])) for e in (base, other, by['201'])]
    for i in range(3000):
        s = bytearray(rng.choice(seeds).encode())
        for _ in range(rng.randint(1, 12)):
            s[rng.randrange(len(s))] = rng.randrange(32, 127)
        lines.append(s.decode('latin1').replace('\n', ' '))
    code, stderr = chain.run('agg3', lines)
    good, dead = read(work, 'good'), read(work, 'dead')
    check('fuzz: 3,000 messages, no crash', code is None, f'exit {code} {stderr[-300:]}')
    check('fuzz: every message accounted for', len(good) + len(dead) + chain.result('replayed') == 3000, f"{len(good)} good, {len(dead)} dead, {chain.result('replayed')} repeats")
    want = {str(e['record_id']): {k: restored[str(e['record_id'])]['event_data'][k] for k in e['sealed']} for e in (base, other, by['201'])}
    tampered_good = [g for g in good if {k: g['event_data'].get(k) for k in want.get(str(g.get('record_id')), {'missing': 1})} != want.get(str(g.get('record_id')))]
    check('fuzz: no event accepted with altered protected data', not tampered_good, f'{len(tampered_good)} of {len(good)} accepted')
    check('fuzz: no canary anywhere', CANARY not in json.dumps(good + dead))

    # Bypass: nothing may post to Vector's trusted source without the verifier's certificate.
    def attempt(cert=None):
        context = ssl.create_default_context(cafile=str(work / 'tls/vector-ca.crt'))
        context.check_hostname = False
        if cert:
            context.load_cert_chain(*cert)
        forged = json.dumps({'channel': SYSMON, 'event_id': 1, 'record_id': 9, 'event_uid': 'f' * 64, 'event_data': {'CommandLine': 'forged'}}).encode()
        request = urllib.request.Request(f'https://127.0.0.1:{chain.source_port}/v1/verified', data=forged, method='POST')
        try:
            return urllib.request.urlopen(request, context=context, timeout=5).status
        except urllib.error.HTTPError as e:
            return e.code
        except (OSError, ssl.SSLError):
            return 'refused'

    chain.stop_verifier()
    chain.start_verifier()
    proc = chain.launch('bypass')
    tls = work / 'tls'
    result = attempt()
    check('bypass: no client certificate refused', result == 'refused', str(result))
    result = attempt((tls / 'vector.crt', tls / 'vector.key'))
    check("bypass: Vector's own certificate refused", result == 'refused', str(result))
    result = attempt((tls / 'verifier.crt', tls / 'verifier.key'))
    check('bypass: control, the verifier certificate is accepted', result == 200, str(result))
    time.sleep(1)
    proc.terminate()
    proc.wait(20)
    check('bypass: only the control event arrived', len(read(work, 'good')) == 1, str(len(read(work, 'good'))))

    # Service outage: nothing is lost or falsely accepted while the verifier is down.
    chain.stop_verifier()
    proc = chain.launch('outage')
    proc.stdin.write((json.dumps(envelopes[1]) + '\n').encode())
    proc.stdin.close()
    time.sleep(5)
    check('outage: nothing delivered while the verifier is down', not read(work, 'good') and not read(work, 'dead'))
    chain.start_verifier()
    deadline = time.time() + 60
    while time.time() < deadline and not finished(work, 'good'):
        time.sleep(.25)
    proc.terminate()
    proc.wait(20)
    check('outage: event delivered after recovery', len(read(work, 'good')) == 1, str(len(read(work, 'good'))))
    chain.stop_verifier()

    tmp.cleanup()
    print(f'\n{len(failures)} failed' if failures else '\nall passed')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main(*sys.argv[1:4]))
