"""The parts: configuration, parsing, hostile input, storage, the command line, and isolation by inspection."""
import contextlib
import io
import json
import re
import socket
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from helpers import NOW, ROOT, World
from siem_health import catalog, cli, watchdog
from siem_health.assess import ALL_UNITS, Assessor, Memory, percentile
from siem_health.collect import Collector, clean, number, parse_metrics, parse_time, vector_summary
from siem_health.config import ConfigError, build, load
from siem_health.store import Store


class Configuration(unittest.TestCase):
    def test_the_real_file_is_valid(self):
        config = load(ROOT / 'config' / 'wsl' / 'health' / 'health.yaml')
        self.assertEqual(config['schedule']['cycle_seconds'], 60)
        self.assertEqual(len(config['sources']), 12)

    def test_out_of_bounds_is_refused(self):
        for bad in ({'schedule': {'cycle_seconds': 5}}, {'hysteresis': {'worsen_cycles': 0}}, {'timeouts': {'http_seconds': 99}}, {'retention': {'transitions_days': 5}}):
            with self.assertRaises(ConfigError):
                build(bad)

    def test_unknown_settings_are_refused(self):
        with self.assertRaises(ConfigError):
            build({'schedule': {'cycle_second': 60}})

    def test_thresholds_must_make_sense_together(self):
        with self.assertRaises(ConfigError):
            build({'thresholds': {'lag_degraded_messages': 999999999}})
        with self.assertRaises(ConfigError):
            build({'thresholds': {'memory_unhealthy_percent': 50}})

    def test_a_boolean_is_not_a_number(self):
        with self.assertRaises(ConfigError):
            build({'schedule': {'cycle_seconds': True}})

    def test_nothing_may_point_off_this_machine(self):
        for bad in ({'endpoints': {'aggregator_metrics': 'http://example.com/metrics'}}, {'opensearch': {'url': 'https://10.0.0.1:9200'}}, {'endpoints': {'kafka': 'broker.example.com:9092'}}):
            with self.assertRaises(ConfigError):
                build(bad)

    def test_a_bad_source_is_refused(self):
        for bad in ([{'dataset': 'x; rm -rf /'}], [{'dataset': 'windows.a', 'quiet_minutes': 0}], [{'dataset': 'windows.a'}, {'dataset': 'windows.a'}]):
            with self.assertRaises(ConfigError):
                build({'sources': bad})


class Parsing(unittest.TestCase):
    def test_prometheus_lines_with_timestamps(self):
        series, bad = parse_metrics('vector_component_errors_total{component_id="a",host="x"} 5 1793554526885\n', 10)
        self.assertEqual(series, [('vector_component_errors_total', {'component_id': 'a', 'host': 'x'}, 5.0)])
        self.assertEqual(bad, 0)

    def test_irrelevant_lines_are_skipped_unread(self):
        series, bad = parse_metrics('vector_something_bucket{le="+Inf"} NaN\n# HELP x\n', 10)
        self.assertEqual((series, bad), ([], 0))

    def test_hostile_and_impossible_values_are_dropped(self):
        text = '\n'.join(['vector_component_errors_total{component_id="a"} NaN', 'vector_component_errors_total{component_id="a"} 1e999', 'vector_component_errors_total{component_id="a"} -5', 'vector_component_errors_total{component_id="a"} 99e30', 'vector_component_errors_total not a number'])
        series, bad = parse_metrics(text, 10)
        self.assertEqual(series, [])
        self.assertEqual(bad, 5)

    def test_the_series_count_is_bounded(self):
        text = '\n'.join(f'vector_component_errors_total{{component_id="c{i}"}} 1' for i in range(100))
        series, bad = parse_metrics(text, 10)
        self.assertEqual(len(series), 10)
        self.assertEqual(bad, 1)

    def test_hostile_labels_are_cleaned(self):
        out = vector_summary([('vector_component_errors_total', {'component_id': "a'; DROP\x1b[31m"}, 1.0)])
        self.assertEqual(list(out['errors']), ['a DROP31m'])

    def test_intentional_discards_are_not_faults(self):
        out = vector_summary([('vector_component_discarded_events_total', {'component_id': 'keep', 'intentional': 'true'}, 454.0), ('vector_component_discarded_events_total', {'component_id': 'sink', 'intentional': 'false'}, 3.0)])
        self.assertEqual(out['discarded'], {'sink': 3.0})

    def test_numbers(self):
        for bad in (True, None, 'x', float('nan'), float('inf'), -1, 1e19):
            self.assertIsNone(number(bad))
        self.assertEqual(number(5), 5)

    def test_times(self):
        self.assertEqual(parse_time('2026-11-01T17:35:40.485Z') % 1000, 485)
        for bad in (None, 5, 'yesterday', '2026-13-01T00:00:00.000Z', "2026-11-01'; DROP"):
            self.assertIsNone(parse_time(bad))

    def test_percentile_nearest_rank(self):
        self.assertEqual(percentile([1, 2, 3, 4], 0.5), 2)
        self.assertEqual(percentile(list(range(1, 101)), 0.95), 95)
        self.assertIsNone(percentile([], 0.5))

    def test_clean_removes_terminal_control(self):
        self.assertEqual(clean('ok\x1b[2J$(reboot)`x`'), 'ok2Jrebootx')


class Reports(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.base = Path(self.folder.name)
        self.collector = Collector(build({'bounds': {'max_report_bytes': 4096, 'max_response_bytes': 2000000, 'max_series': 6000, 'sample_events': 200, 'sample_alerts': 20, 'ship_batch': 200, 'outbox_rows': 5000, 'cycle_budget_seconds': 30}}))

    def read(self, text, name='r.json'):
        target = self.base / name
        target.write_text(text, encoding='utf-8')
        return self.collector.guarded('r', self.collector.report, str(target))

    def test_good(self):
        self.assertTrue(self.read(json.dumps({'checked_ms': NOW}))['ok'])

    def test_missing_is_missing(self):
        self.assertEqual(self.collector.guarded('r', self.collector.report, str(self.base / 'no.json'))['error'], 'missing')

    def test_each_malformation_is_refused(self):
        for text in ('not json', '[]', '{}', '{"checked_ms": "soon"}', '{"checked_ms": -5}', '{"checked_ms": true}', '{"checked_ms": 1e400}'):
            self.assertFalse(self.read(text)['ok'], text)

    def test_oversized_is_refused(self):
        self.assertEqual(self.read(json.dumps({'checked_ms': NOW, 'x': 'a' * 5000}))['error'], 'malformed')

    def test_a_symbolic_link_is_not_followed(self):
        real = self.base / 'real.json'
        real.write_text(json.dumps({'checked_ms': NOW}), encoding='utf-8')
        link = self.base / 'link.json'
        link.symlink_to(real)
        self.assertFalse(self.collector.guarded('r', self.collector.report, str(link))['ok'])

    def test_a_report_with_wrong_inner_types_cannot_crash_an_assessment(self):
        world = World()
        self.addCleanup(world.close)
        world.tick(4)
        hostile = {'checked_ms': None, 'rules': 'x', 'feeds': 5, 'providers': {'a': 1}, 'alerts': [1], 'outbox': 'x', 'backlog': 'x', 'sources': 'x', 'output_backlog': 3, 'evidence': 'x', 'queue': {'a': 1}, 'metrics': 'x', 'service': {'a': 1}, 'unread_journal_entries': 'x', 'lost_latched': 'x'}
        for name in ('detector', 'enricher', 'correlator', 'asset', 'path', 'linux-agent', 'kafka-expiry', 'disk-guard', 'windows-agent'):
            world.body_changes[name] = {k: v for k, v in hostile.items() if k != 'checked_ms'}
        world.tick(3)
        self.assertEqual(world.status('kafka'), 'HEALTHY')
        self.assertTrue(world.store.verify_chain()['intact'])


class Fetching(unittest.TestCase):
    def test_a_response_past_the_limit_is_refused(self):
        collector = Collector(build())
        reply = mock.MagicMock()
        reply.__enter__.return_value.read.return_value = b'x' * 2000001
        collector.opener = mock.Mock(open=mock.Mock(return_value=reply))
        self.assertEqual(collector.guarded('m', collector.metrics, 'http://127.0.0.1:1/metrics')['error'], 'malformed')

    def test_errors_are_classified(self):
        self.assertEqual(Collector.classify(socket.timeout()), 'timeout')
        self.assertEqual(Collector.classify(ConnectionRefusedError()), 'refused')
        self.assertEqual(Collector.classify(PermissionError()), 'denied')
        self.assertEqual(Collector.classify(ValueError()), 'malformed')
        self.assertEqual(Collector.classify(subprocess.TimeoutExpired('x', 1)), 'timeout')

    def test_systemctl_gets_a_fixed_list_and_no_shell(self):
        run = mock.Mock(return_value=mock.Mock(returncode=0, stdout='Id=a.service\nActiveState=active\nSubState=running\nResult=success\nNRestarts=0\nMemoryCurrent=[not set]\nCPUUsageNSec=1\n'))
        collector = Collector(build(), run=run)
        found = collector.systemd(['a.service'])
        self.assertTrue(found['ok'])
        self.assertIsNone(found['units']['a.service']['memory'])
        self.assertNotIn('shell', run.call_args.kwargs)
        self.assertEqual(run.call_args.args[0][1], 'show')

    def test_load_state_tells_not_installed_from_stopped(self):
        block = 'Id={}\nLoadState={}\nActiveState=inactive\nSubState=dead\nResult=success\nNRestarts=0\nMemoryCurrent=[not set]\nCPUUsageNSec=[not set]\n'
        out = block.format('a.service', 'not-found') + '\n' + block.format('b.service', 'loaded')
        collector = Collector(build(), run=mock.Mock(return_value=mock.Mock(returncode=0, stdout=out)))
        units = collector.systemd(['a.service', 'b.service'])['units']
        self.assertEqual((units['a.service']['load'], units['b.service']['load']), ('not-found', 'loaded'))
        self.assertIn('--property=Id,LoadState,', collector.run.call_args.args[0][3])

    def test_the_components_are_exactly_the_version_1_set(self):
        from siem_health.assess import COMPONENTS, SERVICE_UNITS
        self.assertEqual([c[0] for c in COMPONENTS], ['windows-agent', 'linux-agent', 'kafka', 'verifier', 'aggregator', 'normalization', 'opensearch', 'detector', 'enricher', 'correlator',
                                                     'assets', 'attack-paths', 'host-wsl', 'housekeeping', 'health-monitor'])
        self.assertEqual(sorted(SERVICE_UNITS), ['aggregator', 'assets', 'attack-paths', 'correlator', 'detector', 'enricher', 'kafka', 'linux-agent', 'opensearch', 'verifier'])

    def test_a_hostile_unit_name_never_reaches_systemctl(self):
        run = mock.Mock()
        collector = Collector(build(), run=run)
        self.assertFalse(collector.guarded('s', collector.systemd, ['x.service; reboot'])['ok'])
        run.assert_not_called()

    def test_opensearch_paths_hold_no_user_text(self):
        source = (ROOT / 'health' / 'siem_health' / 'collect.py').read_text(encoding='utf-8')
        self.assertNotIn('"_source": true', source)
        self.assertNotRegex(source, r"process\.command_line|powershell\.script|'message'")


class Rates(unittest.TestCase):
    def test_first_sample_and_reset_are_not_zero(self):
        memory = Memory()
        self.assertIsNone(memory.rate('a', 10, 1000))
        self.assertEqual(memory.rate('a', 70, 61000), 1.0)
        self.assertIsNone(memory.rate('a', 5, 121000), 'a restarted counter is not negative traffic')
        self.assertEqual(memory.rate('a', 65, 181000), 1.0)

    def test_memory_survives_as_json(self):
        memory = Memory()
        memory.rate('a', 1, 1)
        memory.moved('b', 1, 1)
        again = Memory(json.loads(json.dumps(memory.dump())))
        self.assertEqual(again.rate('a', 61, 60001), 1.0)

    def test_moved_needs_a_real_change(self):
        memory = Memory()
        self.assertIsNone(memory.moved('a', 1, 100))
        self.assertIsNone(memory.moved('a', 1, 200))
        self.assertEqual(memory.moved('a', 2, 300), 300)

    def test_a_window_forgets_a_reset(self):
        memory = Memory()
        memory.window('a', 10, 0, 300)
        self.assertEqual(memory.window('a', 15, 60000, 300), 5)
        self.assertIsNone(memory.window('a', 2, 120000, 300))


class StoreRules(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.path = str(Path(self.folder.name) / 'h.db')
        self.store = Store(self.path)
        self.addCleanup(self.store.close)

    def test_history_cannot_be_changed(self):
        self.store.add_transition('a', None, 'HEALTHY', 1793440000000, {'reason': 'x'})
        with self.assertRaises(sqlite3.DatabaseError):
            self.store.db.execute("UPDATE transitions SET to_status = 'x'")

    def test_recent_history_cannot_be_deleted(self):
        import time
        self.store.add_transition('a', None, 'HEALTHY', int(time.time() * 1000), {'reason': 'x'})
        with self.assertRaises(sqlite3.DatabaseError):
            self.store.db.execute('DELETE FROM transitions')

    def test_tampering_breaks_the_chain(self):
        self.store.add_transition('a', None, 'HEALTHY', 1, {'reason': 'x'})
        self.store.add_transition('a', 'HEALTHY', 'UNHEALTHY', 2, {'reason': 'y'})
        self.store.db.execute('DROP TRIGGER transitions_no_update')
        self.store.db.execute("UPDATE transitions SET body = '{}' WHERE seq = 1")
        self.assertEqual(self.store.verify_chain(), {'intact': False, 'rows': 0, 'first_broken': 1})

    def test_retention_keeps_the_chain_checkable(self):
        day = 86400000
        now = 1793440000000
        self.store.db.execute('DROP TRIGGER transitions_no_early_delete')
        for at in (now - 100 * day, now - 95 * day, now - 10 * day):
            self.store.add_transition('a', None, 'HEALTHY', at, {'reason': 'x'})
        removed = self.store.prune(now, {'samples_hours': 48, 'hourly_days': 30, 'transitions_days': 90, 'diagnostics_days': 7})
        self.assertEqual(removed['transitions'], 2)
        self.assertTrue(self.store.verify_chain()['intact'])
        self.store.add_transition('a', None, 'UNKNOWN', now, {'reason': 'x'})
        self.assertEqual(self.store.verify_chain()['rows'], 2)

    def test_metrics_roll_up_and_old_samples_go(self):
        hour = 3600000
        base = 1793440000000 - 1793440000000 % hour
        for offset, value in ((0, 1.0), (60000, 3.0)):
            self.store.add_samples(base + offset, {'m': value})
        self.store.roll_up(base + hour + 1)
        self.store.roll_up(base + hour + 1)
        rows = self.store.hourly('m', 0)
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]['samples'], rows[0]['low'], rows[0]['high'], rows[0]['mean'], rows[0]['last']), (2, 1.0, 3.0, 2.0, 3.0))
        self.store.prune(base + 3 * 86400000, {'samples_hours': 48, 'hourly_days': 30, 'transitions_days': 90, 'diagnostics_days': 7})
        self.assertEqual(self.store.size()['samples'], 0)
        self.assertEqual(self.store.size()['hourly'], 1)

    def test_a_read_only_connection_cannot_write(self):
        self.store.set_mark('a', 1)
        reader = Store(self.path, read_only=True)
        self.addCleanup(reader.close)
        self.assertEqual(reader.mark('a'), 1)
        with self.assertRaises(sqlite3.OperationalError):
            reader.set_mark('a', 2)

    def test_an_episode_key_is_stable(self):
        one = self.store.start_episode('a', 'degradation', 5, 'DEGRADED', 'x')
        two = self.store.start_episode('a', 'degradation', 5, 'DEGRADED', 'x')
        self.assertEqual(one, two)
        self.assertEqual(len(self.store.episodes()), 1)


class Catalogue(unittest.TestCase):
    def test_every_entry_is_complete(self):
        for name in catalog.CATALOG:
            row = catalog.describe(name)
            for key in ('definition', 'source', 'method', 'unit', 'interval', 'window', 'kind'):
                self.assertTrue(row[key], (name, key))
            self.assertIn(row['kind'], ('direct', 'sampled', 'estimate'))

    def test_only_catalogued_metrics_exist(self):
        world = World()
        self.addCleanup(world.close)
        world.tick(6)
        for name in world.store.latest_samples()[1]:
            self.assertIn(name, catalog.CATALOG)

    def test_unavailable_metrics_are_explained(self):
        self.assertTrue(all(len(reason) > 20 for reason in catalog.UNAVAILABLE.values()))


class CommandLine(unittest.TestCase):
    def setUp(self):
        self.world = World()
        self.addCleanup(self.world.close)
        self.world.tick(6)
        self.file = Path(self.world.folder.name) / 'health.yaml'
        self.file.write_text(json.dumps({'state_file': self.world.config['state_file'], 'publish_report': self.world.config['publish_report'], 'sources': self.world.config['sources']}), encoding='utf-8')
        self.service = mock.patch.object(cli, 'service_state', return_value={'active': 'active', 'sub': 'running', 'restarts': 0})
        self.service.start()
        self.addCleanup(self.service.stop)
        self.clock = mock.patch('time.time', return_value=self.world.now / 1000)
        self.clock.start()
        self.addCleanup(self.clock.stop)

    def run_command(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(['--config', str(self.file), *args])
        return code, out.getvalue(), err.getvalue()

    def test_every_read_command_runs(self):
        for args in (['status'], ['overview'], ['components'], ['component', 'kafka'], ['pipeline'], ['metrics'], ['metrics', '--catalog'], ['metrics', 'raw_lag_messages'], ['history'], ['history', 'kafka'], ['failures'], ['lag'], ['resources'], ['validate'], ['explain', 'detector']):
            code, out, err = self.run_command(*args)
            self.assertEqual(code, 0, (args, err))
            self.assertTrue(out, args)
            code, out, err = self.run_command('--json', *args)
            self.assertEqual(code, 0, (args, err))
            json.loads(out)

    def test_commands_change_nothing(self):
        before = Path(self.world.config['state_file']).read_bytes()
        for args in (['overview'], ['components'], ['failures'], ['validate'], ['explain', 'kafka']):
            self.run_command(*args)
        self.assertEqual(Path(self.world.config['state_file']).read_bytes(), before)

    def test_unknown_names_are_refused_plainly(self):
        for args in (['component', "x' OR 1=1"], ['explain', '../../etc/passwd'], ['metrics', 'nope']):
            code, _, err = self.run_command(*args)
            self.assertEqual(code, 1)
            self.assertIn('no ', err)

    def test_a_stopped_monitor_is_told_apart_from_a_healthy_pipeline(self):
        self.clock.stop()
        self.clock = mock.patch('time.time', return_value=self.world.now / 1000 + 3600)
        self.clock.start()
        code, out, _ = self.run_command('--json', 'overview')
        data = json.loads(out)
        self.assertEqual(data['overall'], 'UNKNOWN')
        self.assertEqual(data['stored_overall'], 'HEALTHY')
        self.assertFalse(data['monitor_current'])
        self.assertEqual(data['coverage'], 'unknown')
        code, out, _ = self.run_command('--json', 'validate')
        self.assertEqual(code, 1)

    def test_no_state_file_gets_a_plain_answer(self):
        self.file.write_text(json.dumps({'state_file': str(Path(self.world.folder.name) / 'none.db'), 'sources': []}), encoding='utf-8')
        code, _, err = self.run_command('overview')
        self.assertEqual(code, 3)
        self.assertIn('cannot be read', err)

    def test_the_overview_names_the_bottleneck(self):
        self.world.units['kafka.service'] = 'failed'
        self.world.fail['kafka'] = 'refused'
        self.world.tick()
        self.clock.stop()
        self.clock = mock.patch('time.time', return_value=self.world.now / 1000)
        self.clock.start()
        _, out, _ = self.run_command('overview')
        self.assertIn('Pipeline: UNHEALTHY', out)
        self.assertIn('Bottleneck: kafka', out)

    def test_no_command_can_change_anything(self):
        source = (ROOT / 'health' / 'siem_health' / 'cli.py').read_text(encoding='utf-8')
        self.assertNotRegex(source, r"\b(restart|stop|start|kill|disable|enable|acknowledge|resolve|close|delete)\b(?=['\"])")
        self.assertNotIn('set_mark', source)


class Watchdog(unittest.TestCase):
    def test_judgments(self):
        now = 10 ** 12
        self.assertEqual(watchdog.judge('active', now - 60000, now)[0], 'OK')
        self.assertEqual(watchdog.judge('inactive', now, now)[0], 'WARN')
        self.assertEqual(watchdog.judge('active', None, now)[0], 'WARN')
        self.assertEqual(watchdog.judge('active', now - 900000, now)[0], 'WARN')

    def test_it_imports_nothing_from_the_service(self):
        source = (ROOT / 'health' / 'siem_health' / 'watchdog.py').read_text(encoding='utf-8')
        self.assertNotRegex(source, r'from \.|import siem_health|yaml|confluent')
        self.assertNotRegex(source, r"'(restart|start|stop)'")


class Isolation(unittest.TestCase):
    code = '\n'.join(path.read_text(encoding='utf-8') for path in (ROOT / 'health' / 'siem_health').glob('*.py'))

    def test_no_unit_depends_on_this_service(self):
        for path in (ROOT / 'deploy' / 'systemd').rglob('*'):
            if path.is_dir() or path.name.startswith('siem-health') or path.name == 'siem.target':
                continue
            text = path.read_text(encoding='utf-8')
            self.assertNotRegex(text, r'(Requires|Wants|BindsTo|After|Before|Requisite)=.*siem-health', path.name)

    def test_the_target_only_wants_it(self):
        target = (ROOT / 'deploy' / 'systemd' / 'siem.target').read_text(encoding='utf-8')
        self.assertIn('siem-health.service', re.search(r'^Wants=.*$', target, re.M)[0])
        self.assertNotRegex(target, r'Requires=.*siem-health')

    def test_no_core_code_refers_to_it(self):
        for folder in ('detector', 'enricher', 'correlator', 'attackpath', 'services'):
            for path in (ROOT / folder).rglob('*'):
                if path.suffix in ('.py', '.go'):
                    self.assertNotIn('siem-health', path.read_text(encoding='utf-8', errors='replace'), path)
                    self.assertNotIn('siem_health', path.read_text(encoding='utf-8', errors='replace'), path)

    def test_no_kafka_consumer_or_producer(self):
        self.assertNotRegex(self.code, r'\b(Consumer|Producer)\(|\.subscribe\(|\.poll\(|\.produce\(')

    def test_no_remediation_verb_is_issued(self):
        self.assertEqual(sorted(set(re.findall(r"SYSTEMCTL, '([a-z-]+)'", self.code))), ['is-active', 'show'])
        self.assertNotRegex(self.code, r'shell=True|os\.system|os\.popen|eval\(|exec\(')

    def test_only_its_own_indices_are_written(self):
        self.assertEqual(set(re.findall(r"'(siem-[a-z-]+)'", (ROOT / 'health' / 'siem_health' / 'service.py').read_text(encoding='utf-8'))), {'siem-health-transitions', 'siem-health-episodes', 'siem-health-metrics', 'siem-health-current'})

    def test_no_external_address_in_the_code(self):
        self.assertFalse([u for u in re.findall(r'https?://([^/\'"\s{]+)', self.code) if not u.startswith('127.0.0.1')])

    def test_units_are_watched_by_exact_name(self):
        self.assertTrue(all(re.fullmatch(r'[a-z-]+\.(service|timer)', unit) for unit in ALL_UNITS))
        self.assertEqual(Assessor.__module__, 'siem_health.assess')

    def test_the_role_cannot_read_content_or_write_elsewhere(self):
        role = (ROOT / 'deploy' / 'opensearch' / 'create-health-user.sh').read_text(encoding='utf-8')
        self.assertNotIn('cluster_all', role)
        self.assertNotRegex(role, r'"indices_all"|"indices:\*"|"\*"')
        blocks = re.findall(r'\{"index_patterns": \[([^\]]*)\], "allowed_actions": \[([^\]]*)\](?:, "fls": \[([^\]]*)\])?\}', role)
        for patterns, actions, fls in blocks:
            if 'indices:data/read' in actions:
                self.assertTrue(fls, patterns)
                self.assertNotRegex(fls, 'message|command|script|user|host')
            if 'write' in actions:
                self.assertEqual(patterns, '"siem-health-*"')


if __name__ == '__main__':
    unittest.main()
