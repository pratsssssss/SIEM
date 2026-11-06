"""The rule catalog, every rule's fixtures, and custom rule behaviour at their limits."""
import contextlib
import io
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import helpers
import yaml
from helpers import RULES, ROOT
from siem_detector import alerts, cli
from siem_detector.rules import CatalogError, load


def custom(name):
    return next(r for r in load(RULES) if Path(r.path).stem == name).custom


def failed(second, user='bob', uid=None, host='H'):
    return {'_id': f'e{second}-{user}', '_index': 'i', '_source': {
        '@timestamp': alerts.iso(1793440000000 + second * 1000), 'event': {'code': '4625'}, 'host': {'name': host}, 'user': {'name': user}}}


class Catalog(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'rules'
        shutil.copytree(RULES, self.root)
        self.catalog = yaml.safe_load((self.root / 'rules.yml').read_text())

    def save(self):
        (self.root / 'rules.yml').write_text(yaml.safe_dump(self.catalog))

    def first(self):
        return self.catalog['rules'][0]

    def test_real_catalog_loads(self):
        rules = load(RULES)
        self.assertEqual(len(rules), 30)
        self.assertEqual(sum(r.kind == 'sigma' for r in rules), 24)
        self.assertEqual(sum(r.kind == 'custom' for r in rules), 6)
        self.assertTrue(all(r.enabled for r in rules))

    def test_linux_and_windows_rules_cannot_see_each_others_events(self):
        for made in load(RULES):
            text = str(made.query)
            if 'linux_' in Path(made.path).stem or '/linux/' in made.path.replace('\\', '/'):
                self.assertIn('linux.', text, made.title)
                self.assertNotIn('windows.', text, made.title)
            else:
                self.assertNotIn('linux.', text, made.title)

    def test_every_rule_carries_attack_tags(self):
        for made in load(RULES):
            found = alerts.mitre(made.tags)
            self.assertTrue(found['tactics'] and found['techniques'], made.title)

    def test_disabled_rule_is_not_loaded_to_run(self):
        self.first()['enabled'] = False
        self.save()
        self.assertEqual(len(load(self.root, include_disabled=False)), 29)
        self.assertEqual(len(load(self.root)), 30)

    def test_severity_and_interval_can_be_overridden(self):
        self.first().update(severity='critical', interval_seconds=45)
        self.save()
        made = next(r for r in load(self.root) if r.id == self.first()['id'])
        self.assertEqual((made.level, made.interval_seconds), ('critical', 45))

    def test_unlisted_rule_file_is_refused(self):
        del self.catalog['rules'][0]
        self.save()
        with self.assertRaisesRegex(CatalogError, 'not listed'):
            load(self.root)

    def test_entry_without_a_file_is_refused(self):
        self.catalog['rules'].append({'id': '99999999-0000-4000-8000-000000000000'})
        self.save()
        with self.assertRaisesRegex(CatalogError, 'no rule file'):
            load(self.root)

    def test_listed_twice_is_refused(self):
        self.catalog['rules'].append(dict(self.first()))
        self.save()
        with self.assertRaisesRegex(CatalogError, 'twice'):
            load(self.root)

    def test_bad_values_are_refused(self):
        for change, says in (({'severity': 'urgent'}, 'severity'), ({'confidence': 'sure'}, 'confidence'), ({'interval_seconds': 5}, 'interval')):
            original = dict(self.first())
            self.first().update(change)
            self.save()
            with self.assertRaisesRegex(CatalogError, says):
                load(self.root)
            self.catalog['rules'][0] = original

    def test_grouping_on_restricted_text_is_refused(self):
        self.first()['group_by'] = ['process.command_line']
        self.save()
        with self.assertRaisesRegex(CatalogError, 'safe field'):
            load(self.root)

    def test_one_invalid_rule_fails_the_whole_validation(self):
        (self.root / 'sigma' / 'windows' / 'bad.yml').write_text('title: bad\n')
        with self.assertRaises(CatalogError):
            load(self.root)

    def test_custom_file_must_define_one_rule(self):
        (self.root / 'custom' / 'empty.py').write_text('X = 1\n')
        with self.assertRaisesRegex(CatalogError, 'exactly one'):
            load(self.root)


class Fixtures(unittest.TestCase):
    def test_every_rule_passes_its_fixtures(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = cli.cmd_test(SimpleNamespace(rules=str(RULES), fixtures=str(ROOT / 'tests' / 'detection' / 'fixtures.yml')))
        self.assertEqual(code, 0, output.getvalue())

    def test_every_rule_has_both_kinds_of_fixture(self):
        fixtures = yaml.safe_load((ROOT / 'tests' / 'detection' / 'fixtures.yml').read_text(encoding='utf8'))
        for made in load(RULES):
            entry = fixtures.get(Path(made.path).stem, {})
            self.assertTrue(entry.get('match') and entry.get('no_match'), made.path)

    def test_a_fixture_that_should_not_pass_is_caught(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'wrong.yml'
            fixtures = yaml.safe_load((ROOT / 'tests' / 'detection' / 'fixtures.yml').read_text(encoding='utf8'))
            fixtures['sys_new_service']['match'], fixtures['sys_new_service']['no_match'] = fixtures['sys_new_service']['no_match'], fixtures['sys_new_service']['match']
            path.write_text(yaml.safe_dump(fixtures))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(cli.cmd_test(SimpleNamespace(rules=str(RULES), fixtures=str(path))), 1)


class FailedLogons(unittest.TestCase):
    def setUp(self):
        self.rule = custom('failed_logon_burst')

    def test_threshold_at_the_limit(self):
        self.assertEqual(len(self.rule.detect([failed(i) for i in range(4)])), 0)
        self.assertEqual(len(self.rule.detect([failed(i) for i in range(5)])), 1)

    def test_window_at_the_limit(self):
        inside = [failed(s) for s in (0, 1, 2, 3, 300)]
        outside = [failed(s) for s in (0, 1, 2, 3, 301)]
        self.assertEqual(len(self.rule.detect(inside)), 1)
        self.assertEqual(len(self.rule.detect(outside)), 0)

    def test_sliding_window_finds_a_burst_that_straddles_a_boundary(self):
        self.assertEqual(len(self.rule.detect([failed(s) for s in (0, 400, 401, 402, 403, 404)])), 1)

    def test_accounts_are_separate(self):
        self.assertEqual(len(self.rule.detect([failed(i, user=f'u{i}') for i in range(5)])), 0)

    def test_hosts_are_separate(self):
        self.assertEqual(len(self.rule.detect([failed(i, host=f'h{i}') for i in range(5)])), 0)

    def test_key_is_stable_when_the_same_burst_is_seen_again_with_more_events(self):
        first = self.rule.detect([failed(i) for i in range(5)])[0]
        again = self.rule.detect([failed(i) for i in range(7)])[0]
        self.assertEqual(first.key, again.key)

    def test_a_long_attack_gives_one_alert_per_window(self):
        # 100 failures, 10 s apart. Each window takes 31 of them.
        self.assertEqual(len(self.rule.detect([failed(s * 10) for s in range(100)])), 4)


class Sequence(unittest.TestCase):
    def test_success_before_the_failures_does_not_count(self):
        made = custom('logon_after_failures')
        good = {'_id': 'g', '_index': 'i', '_source': {'@timestamp': alerts.iso(1793440000000 + 500000), 'event': {'code': '4624'}, 'host': {'name': 'H'}, 'user': {'name': 'bob'}, 'winlog': {'event_data': {'LogonType': '3'}}}}
        self.assertEqual(len(made.detect([failed(0), failed(1), failed(2), good])), 1)
        self.assertEqual(len(made.detect([good, *[failed(600 + i) for i in range(3)]])), 0)

    def test_failures_older_than_the_window_do_not_count(self):
        made = custom('logon_after_failures')
        good = {'_id': 'g', '_index': 'i', '_source': {'@timestamp': alerts.iso(1793440000000 + 700000), 'event': {'code': '4624'}, 'host': {'name': 'H'}, 'user': {'name': 'bob'}, 'winlog': {'event_data': {'LogonType': '3'}}}}
        self.assertEqual(len(made.detect([failed(0), failed(1), failed(2), good])), 0)


class Encoded(unittest.TestCase):
    def test_decoding(self):
        spec = __import__('importlib.util').util.spec_from_file_location('enc', RULES / 'custom' / 'encoded_command_content.py')
        module = __import__('importlib.util').util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(module.decoded('powershell -enc RwBlAHQALQBEAGEAdABlAA=='), 'Get-Date')
        self.assertEqual(module.decoded('powershell -ENCODEDCOMMAND RwBlAHQALQBEAGEAdABlAA=='), 'Get-Date')
        self.assertIsNone(module.decoded('powershell -File a.ps1'))
        self.assertIsNone(module.decoded(None))


if __name__ == '__main__':
    unittest.main()
