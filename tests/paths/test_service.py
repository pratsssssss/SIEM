"""The service, the analyst interface, storage and failure handling, on synthetic fixtures."""
import json
import os
import tempfile
import unittest
from pathlib import Path

from helpers import MIN, NOW, World, alert, hit, winevent
from siem_path import control, evidence, model
from siem_path.evidence import Collector, StoreDown
from siem_path.service import OpenSearch, Timer, asset_socket_lookup
from siem_path.store import Store


class Base(unittest.TestCase):
    def setUp(self):
        self.world = World()
        self.addCleanup(self.world.close)
        self.cited = [hit(winevent(4625, NOW + n * MIN)) for n in range(4)] + [hit(winevent(4624, NOW + 5 * MIN))]
        self.incident = self.world.incident(self.cited)

    def build(self):
        self.assertEqual(self.world.work.build('incident', self.incident), 'new')
        return self.world.store.list()[0]['path_id']


class Storage(Base):
    def test_a_rebuild_with_the_same_meaning_adds_nothing(self):
        path = self.build()
        self.assertEqual(self.world.work.build('incident', self.incident), 'same')
        self.assertEqual(len(self.world.store.history(path)), 1)

    def test_new_evidence_makes_a_new_version_and_keeps_the_old(self):
        path = self.build()
        extra = hit(winevent(4698, NOW + 6 * MIN))
        self.world.search.add(extra)
        self.world.search.docs['alerts'][0]['raw_event_refs'].append(f"{extra['_index']}/{extra['_id']}")
        self.assertEqual(self.world.work.build('incident', self.incident), 'changed')
        rows = self.world.store.history(path)
        self.assertEqual([r['version'] for r in rows], [1, 2])
        self.assertEqual(self.world.store.path(path)['version'], 2)

    def test_an_analyst_decision_makes_a_new_version(self):
        path = self.build()
        before = self.world.store.path(path)['tier']
        self.world.search.docs['incidents'][0]['status'] = 'false_positive'
        self.world.work.build('incident', self.incident)
        self.assertNotEqual(self.world.store.path(path)['tier'], before)

    def test_history_and_audit_are_append_only_and_chained(self):
        self.build()
        self.world.store.audit(None, NOW, 'a', 'b', {})
        for sql in ('UPDATE history SET why = 1', 'DELETE FROM history', 'UPDATE audit SET actor = 1', 'DELETE FROM audit'):
            with self.assertRaises(Exception):
                self.world.store.db.execute(sql)
        self.assertTrue(self.world.analyst('validate')['result']['intact'])

    def test_tampering_with_history_is_detected(self):
        self.build()
        store = self.world.store
        store.db.execute('DROP TRIGGER history_no_update')
        store.db.execute("UPDATE history SET why = 'altered'")
        store.db.commit()
        self.assertEqual(self.world.analyst('validate')['result']['history_first_broken'], 1)

    def test_a_restart_keeps_everything(self):
        path = self.build()
        again = Store(self.world.store.db.execute('PRAGMA database_list').fetchone()[2])
        self.addCleanup(again.close)
        self.assertEqual(again.path(path)['version'], 1)
        self.assertEqual(again.verify()[1], None)

    def test_flush_writes_only_its_own_indices_and_history_uses_create(self):
        self.build()
        self.world.work.flush()
        for path in self.world.search.written:
            self.assertRegex(path, r'^/siem-attack-(paths|path-graph|path-history|path-audit)-\d{4}\.\d{2}/')
        self.assertTrue([p for p in self.world.search.written if 'history' in p and '/_create/' in p])

    def test_the_path_document_is_a_summary_and_the_graph_is_separate(self):
        self.build()
        self.world.work.flush()
        doc = next(v for k, v in self.world.search.written.items() if k.startswith('/siem-attack-paths-'))
        self.assertNotIn('edges', doc)
        self.assertGreater(doc['edge_count'], 0)
        self.assertTrue([v for k, v in self.world.search.written.items() if '-graph-' in k and v['doc_type'] == 'edge'])

    def test_flush_is_incremental(self):
        self.build()
        self.world.work.flush()
        self.world.search.written.clear()
        self.world.work.flush()
        self.assertEqual(self.world.search.written, {})

    def test_an_outage_holds_output_and_it_drains(self):
        self.build()
        self.world.search.down = True
        with self.assertRaises(StoreDown):
            self.world.work.flush()
        self.assertGreater(sum(self.world.work.health()['output_backlog'].values()), 0)
        self.world.search.down = False
        self.world.work.flush()
        self.assertEqual(sum(self.world.work.health()['output_backlog'].values()), 0)


class Queue(Base):
    def test_sync_queues_incidents_once(self):
        self.world.work.sync()
        self.world.work.sync()
        self.assertEqual(self.world.store.backlog(), 1)

    def test_a_high_alert_in_no_incident_is_a_seed(self):
        lone = alert([hit(winevent(4698))], severity='high')
        self.world.search.docs['alerts'].append(lone)
        self.world.work.sync()
        self.assertIn(('alert', lone['alert_id'], 0), self.world.store.due(NOW, 10))

    def test_work_is_bounded_per_cycle(self):
        world = World(paths_per_cycle=2)
        self.addCleanup(world.close)
        for n in range(5):
            world.incident([hit(winevent(4624, NOW + n))], incident_id=f'{n:032x}')
        world.work.sync()
        world.work.work()
        self.assertEqual(world.store.backlog(), 3)

    def test_an_outage_keeps_the_seed_and_it_is_retried_later(self):
        self.world.work.sync()
        self.world.search.down = True
        with self.assertRaises(StoreDown):
            self.world.work.work()
        self.assertEqual(self.world.store.backlog(), 1)
        self.assertEqual(self.world.store.due(NOW, 10), [])
        self.world.search.down = False
        self.world.now += 31000
        self.world.work.work()
        self.assertEqual(self.world.store.backlog(), 0)

    def test_one_bad_record_does_not_stall_the_rest(self):
        self.world.search.docs['incidents'].append({'incident_id': 'a' * 32, 'updated_at': model.iso(NOW), 'alert_ids': 7})
        self.world.work.sync()
        self.world.work.work()
        self.assertEqual(self.world.store.backlog(), 0)
        self.assertEqual(len(self.world.store.list()), 2)

    def test_a_query_limit_is_stated_on_the_path(self):
        world = World(limits={'max_alerts': 1})
        self.addCleanup(world.close)
        incident = world.incident([hit(winevent(4624))])
        world.search.docs['incidents'][0]['alert_ids'].append('a' * 32)
        world.work.build('incident', incident)
        path = world.store.path(world.store.list()[0]['path_id'])
        self.assertIn('query_limited', [g['gap'] for g in path['gaps']])

    def test_a_seed_that_vanished_is_dropped(self):
        self.assertIsNone(self.world.work.build('incident', 'b' * 32))


class Validation(Base):
    def test_all_present_is_verified(self):
        path = self.build()
        reply = self.world.analyst('validate', path=path)['result']
        self.assertEqual(reply['counts']['unavailable'], 0)
        self.assertEqual(reply['tier'], self.world.store.path(path)['tier'])

    def test_a_vanished_event_is_no_longer_verified(self):
        path = self.build()
        before = self.world.store.path(path)['tier']
        self.world.search.docs['events'].clear()
        self.world.search.docs['alerts'].clear()
        reply = self.world.analyst('validate', path=path)['result']
        self.assertEqual(reply['tier'], model.INSUFFICIENT)
        self.assertNotEqual(reply['tier'], before)
        self.assertIn('lost evidence', reply['state'])

    def test_some_lost_lowers_the_path_and_says_so(self):
        path = self.build()
        key = next(iter(self.world.search.docs['events']))
        del self.world.search.docs['events'][key]
        self.world.analyst('validate', path=path)
        found = self.world.store.path(path)
        self.assertEqual(found['tier'], model.PLAUSIBLE)
        self.assertEqual(found['validation']['unavailable'], 1)
        states = [e.get('state') for e in found['edges']]
        self.assertIn('partly_available', states)

    def test_an_altered_event_is_caught(self):
        path = self.build()
        for doc in self.world.search.docs['events'].values():
            doc['event']['code'] = '4720'
        self.world.analyst('validate', path=path)
        self.assertGreater(self.world.store.path(path)['validation']['changed'], 0)

    def test_validating_during_an_outage_changes_nothing(self):
        path = self.build()
        before = self.world.store.path(path)
        self.world.search.down = True
        reply = self.world.analyst('validate', path=path)
        self.assertFalse(reply['ok'])
        self.assertEqual(self.world.store.path(path)['tier'], before['tier'])

    def test_validation_keeps_the_version(self):
        path = self.build()
        self.world.analyst('validate', path=path)
        self.assertEqual(self.world.store.path(path)['version'], 1)
        self.assertEqual(self.world.store.audit_rows(path)[-1]['action'], 'validate')


class Evidence(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.collector = Collector(lambda index, body: self.calls.append((index, body)) or [])

    def test_a_forged_reference_is_refused_and_never_queried(self):
        found, refused = self.collector.events(['.opendistro_security/abcdefgh12', 'siem-incidents-2026.10/abcdefgh12', '../x/abcdefgh12'])
        self.assertEqual(found, {})
        self.assertEqual(len(refused), 3)
        self.assertEqual(self.calls, [])

    def test_a_missing_event_is_reported(self):
        _, missing = self.collector.events(['siem-windows-2026.11.01/abcdefgh12'])
        self.assertEqual(missing, ['siem-windows-2026.11.01/abcdefgh12'])

    def test_events_are_bounded(self):
        collector = Collector(lambda index, body: self.calls.append(len(body['query']['ids']['values'])) or [], {'max_events': 3})
        collector.events([f'siem-windows-2026.11.01/abcdefgh{n:02}' for n in range(9)])
        self.assertEqual(self.calls, [3])

    def test_no_query_asks_for_text(self):
        for field in evidence.EVENT_FIELDS + evidence.ALERT_FIELDS + evidence.INCIDENT_FIELDS:
            self.assertNotIn('command_line', field)
            self.assertNotIn('message', field)
            self.assertNotIn('event_data', field)
            self.assertNotEqual(field, 'evidence')

    def test_bad_alert_ids_are_not_queried(self):
        self.assertEqual(self.collector.alerts(["x' OR 1=1", '../y']), [])
        self.assertEqual(self.calls, [])

    def test_check_refuses_other_indices(self):
        self.assertIsNone(self.collector.check('event', '.opendistro_security', 'abcdefgh12'))
        self.assertIsNone(self.collector.check('incident', 'siem-incidents-2026.10', 'abcdefgh12'))
        self.assertEqual(self.calls, [])


class Access(Base):
    def test_an_analyst_cannot_rebuild_or_link(self):
        path = self.build()
        for name, arguments in (('rebuild', {'path': path, 'reason': 'x'}), ('link_identities', {'a': 'identity:a', 'b': 'identity:b', 'reason': 'x'})):
            self.assertEqual(self.world.analyst(name, **arguments), {'ok': False, 'error': 'not a member of siem-path-admin'})
        self.assertEqual(len([r for r in self.world.store.audit_rows() if r['action'] == 'refused']), 2)

    def test_a_stranger_can_do_nothing(self):
        self.assertFalse(control.handle(self.world.actions, {'action': 'list'}, (None, None))['ok'])

    def test_root_is_refused(self):
        self.assertIsNone(control.member(0, 0, 'root'))

    def test_the_caller_cannot_claim_a_name(self):
        path = self.build()
        reply = control.handle(self.world.actions, {'action': 'rebuild', 'actor': 'alice', 'path': path, 'reason': 'x'}, ('bob', None))
        self.assertFalse(reply['ok'])

    def test_a_rebuild_needs_a_reason_and_is_audited(self):
        path = self.build()
        self.assertFalse(self.world.admin('rebuild', path=path, reason=' ')['ok'])
        self.assertTrue(self.world.admin('rebuild', path=path, reason='new rule')['ok'])
        row = self.world.store.audit_rows(path)[-1]
        self.assertEqual((row['action'], row['actor'], row['detail']['reason']), ('rebuild', 'alice', 'new rule'))

    def test_identity_links_are_validated_and_audited(self):
        self.assertFalse(self.world.admin('link_identities', a='x', b='y', reason='r')['ok'])
        self.assertFalse(self.world.admin('link_identities', a='identity:a', b='identity:a', reason='r')['ok'])
        self.assertFalse(self.world.admin('link_identities', a='identity:a', b='identity:b', reason='')['ok'])
        self.assertTrue(self.world.admin('link_identities', a='identity:a', b='identity:b', reason='one person')['ok'])
        self.assertEqual(self.world.store.audit_rows()[-1]['actor'], 'alice')

    def test_a_note_is_the_analyst_s_own_and_changes_nothing_else(self):
        path = self.build()
        before = self.world.store.path(path)
        self.assertTrue(self.world.analyst('note', path=path, text='looks like a test')['ok'])
        self.assertEqual(self.world.store.path(path), before)
        self.assertEqual(self.world.analyst('show', path=path)['result']['notes'][0]['by'], 'bob')

    def test_no_action_can_touch_an_incident_or_host(self):
        for name in control.READS + control.WRITES:
            self.assertFalse(any(word in name for word in ('close', 'contain', 'isolate', 'block', 'disable', 'remediate', 'status')) and name != 'status', name)

    def test_nothing_in_the_package_runs_a_program(self):
        import siem_path
        for path in Path(siem_path.__file__).parent.glob('*.py'):
            text = path.read_text(encoding='utf8')
            for word in ('subprocess', 'os.system', 'eval(', 'exec(', 'Popen', 'pickle', 'shell=True'):
                self.assertNotIn(word, text, path.name)

    def test_writes_go_nowhere_but_its_own_indices(self):
        import siem_path
        text = (Path(siem_path.__file__).parent / 'service.py').read_text(encoding='utf8')
        for word in ("'PUT', f'/siem-incidents", "'PUT', f'/siem-alerts", "'POST', f'/siem-incidents"):
            self.assertNotIn(word, text)


class Interface(Base):
    def test_explain_gives_reasons_and_says_no_conclusion(self):
        path = self.build()
        reply = self.world.analyst('explain', path=path)['result']
        for key in ('why_this_tier', 'what_happened', 'doubts', 'not_visible', 'next_steps', 'attack_techniques', 'telemetry_sources', 'attack_sources', 'affected_assets'):
            self.assertIn(key, reply)
        self.assertIn('T1110', reply['attack_techniques'])
        self.assertTrue(reply['conclusion'].startswith('none'))

    def test_every_edge_shows_its_evidence(self):
        path = self.build()
        rows = self.world.analyst('evidence', path=path)['result']
        self.assertTrue(rows and all(r['evidence'] and r['reason'] for r in rows))

    def test_the_graph_comes_with_an_explanation(self):
        reply = self.world.analyst('graph', path=self.build())['result']
        self.assertTrue(reply['explanation'])
        self.assertTrue(reply['nodes'] and reply['edges'])

    def test_lookups(self):
        path = self.build()
        self.assertEqual(self.world.analyst('asset', asset='ast-win')['result'][0]['path_id'], path)
        self.assertEqual(self.world.analyst('incident', incident=self.incident)['result']['path_id'], path)
        self.assertEqual(self.world.analyst('search', query='Synthetic')['result'][0]['path_id'], path)
        self.assertTrue(self.world.analyst('timeline', path=path)['result'])
        self.assertEqual(self.world.analyst('history', path=path)['result'][0]['version'], 1)

    def test_hostile_input_is_a_plain_miss(self):
        self.build()
        for text in ("' OR 1=1 --", '%', '_zz_', '../../etc/passwd', '{"$ne": 1}', '\x1b[2J'):
            self.assertEqual(self.world.analyst('search', query=text)['result'] if self.world.analyst('search', query=text)['ok'] else [], [], text)
            self.assertFalse(self.world.analyst('show', path=text + 'zz')['ok'], text)
            self.assertFalse(self.world.analyst('incident', incident=text)['ok'], text)

    def test_unknown_action_and_arguments(self):
        self.assertFalse(self.world.analyst('drop')['ok'])
        self.assertFalse(self.world.analyst('show', nonsense=1)['ok'])
        self.assertFalse(self.world.analyst('list', tier='compromised')['ok'])


class Resilience(unittest.TestCase):
    def test_timer_backs_off(self):
        timer = Timer(60)
        timer.failed(0)
        self.assertEqual(timer.due, 30000)
        for _ in range(12):
            timer.failed(0)
        self.assertEqual(timer.due, 900000)
        timer.ran(0)
        self.assertEqual(timer.wait, 0)

    def test_an_outage_is_visible_and_other_stages_still_run(self):
        world = World()
        self.addCleanup(world.close)
        world.search.down = True
        world.work.cycle()
        self.assertEqual(world.work.health()['status'], 'WARN')
        world.search.down = False
        world.now += 31000
        world.work.cycle()
        self.assertEqual(world.work.health()['opensearch'], 'ok')

    def test_a_bug_in_one_stage_does_not_stop_the_others(self):
        world = World()
        self.addCleanup(world.close)
        world.work._stage('sync', lambda: 1 / 0)
        world.work._stage('flush', world.work.flush)
        self.assertIn('sync failed', world.work.health()['message'])
        self.assertEqual(world.work.state['opensearch'], 'ok')

    def test_no_asset_inventory_still_gives_a_path(self):
        world = World()
        self.addCleanup(world.close)
        world.search.docs['assets'] = []
        incident = world.incident([hit(winevent(4624))])
        world.work.build('incident', incident)
        path = world.store.list()[0]
        self.assertIn('asset_context_unavailable', [g['gap'] for g in world.store.path(path['path_id'])['gaps']])

    def test_an_unreachable_asset_socket_means_unknown(self):
        self.assertIsNone(asset_socket_lookup('/nonexistent/socket')('192.0.2.1', NOW))

    def test_windows_report_holds_no_detail(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        world = World()
        self.addCleanup(world.close)
        target = Path(folder.name) / 'path.json'
        world.work.write_reports([str(target)])
        self.assertEqual(set(json.loads(target.read_text())), {'status', 'checked_ms', 'message'})

    def test_client_turns_failure_into_store_down(self):
        def broken(request, timeout):
            raise OSError('refused')
        with self.assertRaises(StoreDown):
            OpenSearch('https://127.0.0.1:9200', None, 'u', 'p', opener=broken).ping()


@unittest.skipUnless(os.name == 'posix', 'needs a Unix socket')
class Socket(unittest.TestCase):
    def test_socket_permissions_and_refusal(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        world = World()
        self.addCleanup(world.close)
        path = str(Path(folder.name) / 's.sock')
        server = control.Server(path, world.actions, group='no-such-group', admin_group='no-such-either', log=lambda _: None)
        server.start()
        self.addCleanup(server.stop)
        self.assertFalse(control.call(path, {'action': 'list'})['ok'])
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), '0o660')
        self.assertEqual(world.store.audit_rows()[-1]['action'], 'refused')


if __name__ == '__main__':
    unittest.main()
