"""The agent's protect and envelope transforms, through the real Vector binary, on synthetic journal entries.
Checks the real output: MACs by recomputing them, sealed text by decrypting it with openssl.
"""
import base64
import hashlib
import hmac
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml
from helpers import AGENT, ENC, MAC, MACHINE, ROOT, STAMP, agent_transforms, run_transforms

KEYS = {'k2_enc': ENC, 'k2_mac': MAC}
CANARY = 'CanaryValue7731'


def entry(message, command=None, **fields):
    base = {'__CURSOR': f's=1;i={abs(hash(str(message))) % 9999};b=' + 'ee' * 16, '__REALTIME_TIMESTAMP': '1793500000000000', '_MACHINE_ID': MACHINE, 'SYSLOG_IDENTIFIER': 'tool', '_COMM': 'tool', '_EXE': '/usr/bin/tool', '_PID': '10', '_UID': '1000', '_GID': '1000', '_TRANSPORT': 'syslog',
            '_BOOT_ID': 'ee' * 16, 'PRIORITY': '6', 'SYSLOG_FACILITY': '4', 'timestamp': STAMP, 'message': message}
    if command is not None:
        base['_CMDLINE'] = command
    base.update(fields)
    return base


def decrypt(item):
    key, iv = ENC, base64.b64decode(item['iv']).hex()
    done = subprocess.run(['openssl', 'enc', '-d', '-aes-256-ctr', '-K', key, '-iv', iv], input=base64.b64decode(item['ct']), capture_output=True, check=True)
    return done.stdout.decode()


class Protect(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inputs = {
            'plain': entry('session opened'),
            'secret': entry(f'tool --password {CANARY} run', f'tool --token={CANARY}x'),
            'pem': entry('-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----'),
            'shadow': entry('hash $6$saltsalt$abcdefghijklmnopqrstuvwxyz0123456789'),
            'url': entry(f'clone https://bob:{CANARY}@example.net/x'),
            'bearer': entry(f'Authorization: Bearer {CANARY}abcdefgh'),
            'mysql': entry(f'mysql -u root -p{CANARY} db'),
            'sshpass': entry(f'sshpass -p {CANARY} ssh host'),
            'export': entry(f'export API_TOKEN={CANARY}'),
            'identified': entry(f"CREATE USER x IDENTIFIED BY {CANARY}"),
            'keyline': entry('b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUxOQ'),
            'big': entry('x' * 70000),
            'binary': entry([104, 105, 0, 255]),
            'extra': entry('with extra', PASSWORD_FIELD=CANARY, OTHER=CANARY),
            'empty': entry(''),
            'none': entry(None),
        }
        cls.out = {}
        results = run_transforms(agent_transforms(), ['envelope'], list(cls.inputs.values()), KEYS, parse_time=True)
        cls.raw = results
        for item in results:
            body = json.loads(item['body'])
            cls.out[body['event_data'].get('Cursor')] = (item, body)
        cls.by_name = {name: cls.out.get(e['__CURSOR']) for name, e in cls.inputs.items()}

    def test_every_entry_comes_out(self):
        self.assertEqual(len(self.raw), len(self.inputs))
        self.assertTrue(all(self.by_name.values()))

    def test_envelope_shape_and_mac(self):
        for name, (item, body) in self.by_name.items():
            self.assertEqual(set(item), {'v', 'k', 'event_uid', 'body', 'mac'}, name)
            self.assertEqual((item['v'], item['k']), ('siem-event-v1', 'k2'))
            want = hmac.new(bytes.fromhex(MAC), f"siem-event-v1|k2|{item['body']}".encode(), hashlib.sha256).digest()
            self.assertEqual(base64.b64decode(item['mac']), want, name)

    def test_field_macs_match_the_verifier_format(self):
        _, body = self.by_name['plain']
        field = body['sealed']['Message']
        aad = json.dumps(['siem-d22-v1', 'k2', body['event_uid'], body['channel'], str(body['event_id']), str(body['record_id']), 'Message', field['iv'], field['ct']], separators=(',', ':')).encode()
        self.assertEqual(base64.b64decode(field['mac']), hmac.new(bytes.fromhex(MAC), aad, hashlib.sha256).digest())

    def test_no_message_text_is_in_the_clear(self):
        for name, (item, body) in self.by_name.items():
            self.assertNotIn('Message', body['event_data'], name)
            self.assertNotIn('CommandLine', body['event_data'], name)
            self.assertNotIn(CANARY, json.dumps(item), name)
        self.assertNotIn('session opened', json.dumps(self.raw))

    def test_only_named_fields_leave(self):
        _, body = self.by_name['extra']
        self.assertNotIn('PASSWORD_FIELD', json.dumps(body))
        self.assertLessEqual(set(body), {'event_uid', 'channel', 'event_id', 'record_id', 'computer', 'provider_name', 'timestamp', 'level', 'event_data', 'labels', 'sealed'})

    def test_identity_is_stable_and_from_the_cursor(self):
        _, body = self.by_name['plain']
        cursor = self.inputs['plain']['__CURSOR']
        self.assertEqual(body['event_uid'], hashlib.sha256(f'linux-journal|{MACHINE}|{cursor}'.encode()).hexdigest())
        self.assertEqual(body['record_id'], '1793500000000000')
        self.assertEqual(body['event_id'], 1)

    def test_host_identity_is_the_asset_digest(self):
        _, body = self.by_name['plain']
        self.assertEqual(body['event_data']['HostId'], hashlib.sha256(f'linux_machine_id:{MACHINE}'.encode()).hexdigest()[:32])
        self.assertEqual(body['computer'], 'testhost-wsl')
        self.assertNotIn(MACHINE, json.dumps(body))

    def test_secrets_are_redacted_before_sealing(self):
        for name in ('secret', 'url', 'bearer', 'mysql', 'sshpass', 'export', 'identified'):
            _, body = self.by_name[name]
            text = decrypt(body['sealed']['Message'])
            self.assertNotIn(CANARY, text, name)
            self.assertIn('[REDACTED:', text, name)
            self.assertTrue(body['labels'].get('redactions'), name)
        self.assertNotIn(CANARY, decrypt(self.by_name['secret'][1]['sealed']['CommandLine']))

    def test_private_key_and_password_hash(self):
        self.assertEqual(decrypt(self.by_name['pem'][1]['sealed']['Message']), '[REDACTED:pem]')
        self.assertNotIn('abcdefghijkl', decrypt(self.by_name['shadow'][1]['sealed']['Message']))

    def test_one_line_of_a_printed_key(self):
        self.assertEqual(decrypt(self.by_name['keyline'][1]['sealed']['Message']), '[REDACTED:blob]')

    def test_ordinary_text_survives(self):
        self.assertEqual(decrypt(self.by_name['plain'][1]['sealed']['Message']), 'session opened')

    def test_oversized_text_is_cut_and_says_so(self):
        _, body = self.by_name['big']
        self.assertEqual(len(decrypt(body['sealed']['Message'])), 65536)
        self.assertEqual(body['labels']['truncated']['Message'], 70000)

    def test_binary_message_is_kept_as_text(self):
        self.assertTrue(self.by_name['binary'][1]['sealed']['Message'])

    def test_empty_messages_seal_nothing(self):
        for name in ('empty', 'none'):
            self.assertNotIn('sealed', self.by_name[name][1], name)

    def test_a_failure_keeps_the_fact_and_no_content(self):
        broken = entry(f'secret {CANARY}')
        del broken['_MACHINE_ID']
        out = run_transforms(agent_transforms(), ['envelope'], [broken], KEYS, parse_time=True)
        body = json.loads(out[0]['body'])
        self.assertTrue(body['labels']['seal_failed'])
        self.assertEqual(body['labels']['event_id_basis'], 'agent_generated')
        self.assertNotIn(CANARY, json.dumps(out))


class Package(unittest.TestCase):
    def test_package_line(self):
        line = '2026-11-01 10:00:00 install sl:amd64 <none> 5.02-1'
        out = run_transforms(agent_transforms(), ['envelope'], [{'message': line, 'timestamp': STAMP, 'file': '/var/log/dpkg.log'}], KEYS, parse_time=True)
        body = json.loads(out[0]['body'])
        self.assertEqual(body['channel'], 'linux-package')
        self.assertEqual(body['event_uid'], hashlib.sha256(f'linux-package|{MACHINE}|{line}'.encode()).hexdigest())
        self.assertTrue(body['timestamp'].startswith('2026-11-01T10:00:00'))
        self.assertEqual(body['record_id'], '1793527200')

    def test_a_reread_line_has_the_same_identity(self):
        line = '2026-11-01 10:00:00 remove sl:amd64 5.02-1 <none>'
        first = run_transforms(agent_transforms(), ['envelope'], [{'message': line, 'timestamp': STAMP}], KEYS, parse_time=True)
        second = run_transforms(agent_transforms(), ['envelope'], [{'message': line, 'timestamp': '2026-11-02T10:00:00.000000Z'}], KEYS, parse_time=True)
        self.assertEqual(first[0]['event_uid'], second[0]['event_uid'])


class Configuration(unittest.TestCase):
    def setUp(self):
        self.config = yaml.safe_load(AGENT.read_text())

    def test_the_sink_has_only_the_envelope_as_input(self):
        self.assertEqual(self.config['sinks']['kafka_raw']['inputs'], ['envelope', 'envelope_failed'])

    def test_a_disk_buffer_that_blocks_and_never_gives_up(self):
        sink = self.config['sinks']['kafka_raw']
        self.assertEqual(sink['buffer']['type'], 'disk')
        self.assertEqual(sink['buffer']['when_full'], 'block')
        self.assertEqual(sink['message_timeout_ms'], 0)
        self.assertTrue(sink['acknowledgements']['enabled'])

    def test_entries_carry_their_cursor(self):
        self.assertTrue(self.config['sources']['journal']['emit_cursor'])

    def test_no_new_topic(self):
        self.assertEqual(self.config['sinks']['kafka_raw']['topic'], 'siem-raw-logs')

    def test_own_key_not_the_windows_key(self):
        text = AGENT.read_text()
        self.assertNotIn('k1_', text)
        self.assertNotIn('"k1"', text)

    def test_metrics_stay_on_loopback(self):
        self.assertTrue(self.config['sinks']['metrics']['address'].startswith('127.0.0.1:'))

    def test_the_siem_does_not_read_its_own_logs(self):
        excluded = self.config['sources']['journal']['exclude_units']
        for unit in ('vector.service', 'kafka.service', 'opensearch.service', 'seal-verifier.service', 'siem-linux-agent.service'):
            self.assertIn(unit, excluded)

    def test_the_redaction_rules_are_the_windows_rules(self):
        windows = (ROOT / 'config/windows/vector/vector-agent.yaml').read_text()
        rules = [line.strip() for line in windows.splitlines() if line.strip().startswith('n = replace_with(')]
        self.assertGreaterEqual(len(rules), 14)
        for rule in rules:
            self.assertIn(rule, AGENT.read_text())


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / 'deploy' / 'wsl' / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Catchup(unittest.TestCase):
    def setUp(self):
        self.module = load('siem-linux-catchup')
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)

    def test_boot_comes_from_the_cursor(self):
        self.assertEqual(self.module.boot_of('s=a;i=1;b=' + 'ab' * 16 + ';m=2;t=3;x=4'), 'ab' * 16)
        self.assertIsNone(self.module.boot_of('nonsense'))

    def test_reads_the_real_checkpoint_location(self):
        (self.root / 'journal').mkdir()
        (self.root / 'journal' / 'checkpoint.txt').write_text('checkpoint:s=a;b=c\n')
        self.assertEqual(self.module.checkpoint(self.root), 's=a;b=c')

    def test_no_checkpoint_is_a_first_run(self):
        self.assertIsNone(self.module.checkpoint(self.root))

    def test_the_siem_units_are_left_out(self):
        self.assertFalse(self.module.wanted({'_SYSTEMD_UNIT': 'siem-asset.service'}))
        self.assertFalse(self.module.wanted({'_SYSTEMD_UNIT': 'kafka.service'}))
        self.assertTrue(self.module.wanted({'_SYSTEMD_UNIT': 'cron.service'}))
        self.assertTrue(self.module.wanted({}))

    def test_catchup_lines_become_journal_entries(self):
        config = yaml.safe_load(AGENT.read_text())
        transforms = {'catchup_parsed': {**config['transforms']['catchup_parsed'], 'inputs': ['decode']}}
        line = json.dumps({'__CURSOR': 'c', 'MESSAGE': 'hello', '__REALTIME_TIMESTAMP': '1793500000000000', '_MACHINE_ID': 'x'})
        out = run_transforms(transforms, ['catchup_parsed'], [{'message': line}])
        self.assertEqual((out[0]['message'], out[0]['__CURSOR']), ('hello', 'c'))
        self.assertTrue(out[0]['timestamp'].startswith('2026-11-01T'))


class Health(unittest.TestCase):
    def setUp(self):
        self.module = load('siem-linux-health')

    def test_metric_lines(self):
        match = self.module.LINE.match('vector_buffer_events{component_id="kafka_raw",x="y z"} 12 1793500000000')
        self.assertEqual((match['name'], match['value']), ('vector_buffer_events', '12'))

    def test_excluded_and_quiet_entries_do_not_count(self):
        self.assertFalse(self.module.counted({'_SYSTEMD_UNIT': 'siem-detector.service'}))
        self.assertFalse(self.module.counted({'_TRANSPORT': 'kernel', 'PRIORITY': '6'}))
        self.assertTrue(self.module.counted({'_TRANSPORT': 'kernel', 'PRIORITY': '3'}))
        self.assertTrue(self.module.counted({'_TRANSPORT': 'syslog'}))


if __name__ == '__main__':
    unittest.main()
