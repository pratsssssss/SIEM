"""Normalization, schema, provenance, history, lifecycle, relationships and telemetry. All data here is synthetic."""
import json
import os
import tempfile
import unittest
from pathlib import Path

from helpers import DAY, HOUR, MIN, NOW, SERVICES, World, event_hit, host_buckets, name_buckets, peer_buckets, snapshot, user_buckets
from siem_asset import collect, identity, inventory, schema, views
from siem_asset.changes import Lifecycle


class Normalize(unittest.TestCase):
    def test_clean_removes_controls_and_direction_marks(self):
        self.assertEqual(schema.clean('ab\x1b[31mc\n\u202ed\u200b'), 'ab[31mcd')

    def test_clean_removes_credential_shapes(self):
        self.assertNotIn('hunter2', schema.clean('app password=hunter2 now'))
        self.assertNotIn('abc', schema.clean('x token: abc'))

    def test_clean_bounds_size_and_refuses_structures(self):
        self.assertEqual(len(schema.clean('x' * 999, 50)), 50)
        self.assertEqual(schema.clean({'a': 1}), '')
        self.assertEqual(schema.clean(True), '')

    def test_hostname_rules(self):
        self.assertEqual(schema.hostname(' LAB-01 '), 'lab-01')
        for bad in ('a b', 'a;b', '$(x)', '`x`', '../etc', 'a/b', 'a\\b', '', 'x' * 300, '-a', 'a\nb', None, 5, "a'b", '"a"', '<a>', 'a|b', '%00'):
            self.assertIsNone(schema.hostname(bad), bad)

    def test_mac_forms(self):
        self.assertEqual(schema.mac('AA-BB-CC-00-11-22'), 'aa:bb:cc:00:11:22')
        self.assertIsNone(schema.mac('00:00:00:00:00:00'))
        self.assertIsNone(schema.mac('zz:bb:cc:00:11:22'))

    def test_address_forms(self):
        self.assertEqual(schema.address('fe80::1%12'), 'fe80::1')
        self.assertIsNone(schema.address('1.2.3'))
        self.assertFalse(schema.routable('127.0.0.1'))
        self.assertFalse(schema.routable('169.254.1.1'))
        self.assertFalse(schema.routable('224.0.0.1'))
        self.assertTrue(schema.routable('192.168.1.1'))

    def test_segment_is_private_ipv4_only(self):
        self.assertEqual(schema.segment('192.168.1.10/24'), '192.168.1.0/24')
        self.assertIsNone(schema.segment('8.8.8.8/24'))
        self.assertIsNone(schema.segment('192.168.1.10/32'))
        self.assertIsNone(schema.segment('nonsense'))

    def test_binary_name_drops_path_and_arguments(self):
        self.assertEqual(schema.binary_name('"C:\\Program Files\\App\\app.exe" --password=x'), 'app.exe')
        self.assertEqual(schema.binary_name('C:\\Windows\\system32\\svchost.exe -k netsvcs'), 'svchost.exe')
        self.assertEqual(schema.binary_name('/usr/bin/thing -a'), 'thing')

    def test_per_user_service_suffix_is_removed(self):
        self.assertEqual(schema.service_key('CDPUserSvc_4fd12'), 'cdpusersvc')
        self.assertEqual(schema.service_key('Spooler'), 'spooler')

    def test_label_refuses_markup(self):
        for bad in ('<script>', 'a;b', '$(x)', 'a|b', '`b`', ''):
            with self.assertRaises(schema.Invalid):
                schema.label(bad)


class SnapshotSchema(unittest.TestCase):
    def test_good(self):
        out = schema.snapshot(snapshot(), NOW)
        self.assertEqual(out['hostname'], 'lab-01')
        self.assertEqual(out['services']['windefend']['binary'], 'MsMpEng.exe')

    def test_refusals(self):
        for change, reason in (({'schema': 'x'}, 'schema'), ({'collector': 'nope'}, 'collector'), ({'collected_at': 'never'}, 'time'), ({'collected_at': schema.iso(NOW + DAY)}, 'future'), ({'host': {'hostname': 'a;b'}}, 'name'), ({'host': 5}, 'host'), ({'software': 'x'}, 'list')):
            raw = {**snapshot(), **change}
            with self.assertRaises(schema.Invalid, msg=reason):
                schema.snapshot(raw, NOW)
        with self.assertRaises(schema.Invalid):
            schema.snapshot([], NOW)

    def test_unknown_fields_are_dropped(self):
        out = schema.snapshot(snapshot(extra='hidden', environment={'SECRET': 'x'}), NOW)
        self.assertNotIn('hidden', json.dumps(out))
        self.assertNotIn('SECRET', json.dumps(out))

    def test_lists_are_bounded(self):
        raw = snapshot(software=[{'name': f'p{n}'} for n in range(9000)])
        self.assertEqual(len(schema.snapshot(raw, NOW)['software']), schema.LIMITS['software'])

    def test_absent_section_is_not_empty(self):
        raw = snapshot()
        del raw['software']
        self.assertNotIn('software', schema.snapshot(raw, NOW))

    def test_bad_values_become_absent_not_defaults(self):
        raw = snapshot()
        raw['security'] = {'defender': {'realtime': 'yes'}, 'firewall': {'enabled': 99}}
        self.assertEqual(schema.snapshot(raw, NOW)['security'], {})

    def test_ephemeral_listeners_are_left_out(self):
        out = schema.snapshot(snapshot(listeners=[{'proto': 'tcp', 'port': 50000, 'scope': 'any'}, {'proto': 'tcp', 'port': 'x', 'scope': 'any'}]), NOW)
        self.assertEqual(out['listeners'], {})


class Provenance(unittest.TestCase):
    def setUp(self):
        self.world = World()
        self.addCleanup(self.world.close)
        self.world.take(snapshot())
        self.asset = self.world.only()['asset_id']

    def test_every_attribute_has_source_time_class_and_confidence(self):
        rows = self.world.store.attributes(self.asset)
        self.assertTrue(rows)
        for row in rows:
            self.assertEqual(row['klass'], 'observed')
            self.assertTrue(row['source'].startswith('snapshot:'))
            self.assertEqual(row['observed_ms'], NOW)
            self.assertIn(row['confidence'], ('high', 'medium', 'low'))

    def test_admin_value_sits_beside_observed_and_replaces_nothing(self):
        self.world.admin('metadata', asset=self.asset, name='owner', value='Blue Team')
        view = self.world.analyst('show', asset=self.asset)['result']
        self.assertEqual([x['value'] for x in view['administrator']], ['Blue Team'])
        self.assertTrue(view['facts'])
        self.assertTrue(all(x['source'].startswith('snapshot:') for x in view['facts']))

    def test_unknown_fields_are_absent(self):
        doc = views.document(self.world.store, self.world.store.asset(self.asset), {}, NOW)
        for name in ('owner', 'criticality', 'department', 'location', 'tags', 'environment', 'purpose'):
            self.assertNotIn(name, doc)

    def test_vulnerabilities_are_never_claimed(self):
        view = self.world.analyst('show', asset=self.asset)['result']
        self.assertEqual(view['security']['vulnerabilities']['status'], 'not_assessed')

    def test_observed_user_is_kept_apart_from_owner(self):
        self.world.search.responses['authenticated'] = user_buckets()
        self.world.work.telemetry._users(NOW - HOUR, NOW, {'lab-01': self.asset})
        view = self.world.analyst('users', asset=self.asset)['result']
        self.assertIsNone(view['assigned_owner'])
        self.assertEqual(view['observed_users'][0]['name'], 'alice')
        self.assertEqual(self.world.store.attribute(self.asset, 'owner', 'admin'), None)

    def test_account_type_is_labelled_as_inference(self):
        self.assertEqual(inventory.account_type('SYSTEM'), 'service_account')
        self.assertEqual(inventory.account_type('HOST$'), 'service_account')
        self.assertEqual(inventory.account_type('alice'), 'unknown')
        self.world.search.responses['authenticated'] = user_buckets(name='SYSTEM')
        self.world.work.telemetry._users(NOW - HOUR, NOW, {'lab-01': self.asset})
        row = self.world.store.items(self.asset, 'observed_user')[0]['body']
        self.assertEqual(row['type_is'], 'inferred from the name')


class History(unittest.TestCase):
    def setUp(self):
        self.world = World()
        self.addCleanup(self.world.close)
        self.world.take(snapshot(at=NOW - DAY))
        self.asset = self.world.only()['asset_id']

    def later(self, **values):
        self.world.take(snapshot(at=NOW, **values))
        return {c['kind']: c for c in self.world.store.changes(limit=1000)}

    def test_baseline_records_discovery_only(self):
        self.assertEqual(self.world.kinds(), ['asset_discovered'])

    def test_os_upgrade(self):
        change = self.later(os_build='26300')['os_changed']
        self.assertEqual((change['before'], change['after'], change['category']), ('26200', '26300', 'notable'))

    def test_software_install_remove_and_update(self):
        found = self.later(software=[{'name': 'Editor', 'version': '2.0'}, {'name': 'New Tool', 'version': '1'}])
        self.assertEqual(found['software_version_changed']['category'], 'routine')
        self.assertEqual(found['software_installed']['category'], 'notable')
        found = self.world.take(snapshot(at=NOW + MIN, software=[{'name': 'Editor', 'version': '2.0'}]))
        self.assertIn('software_removed', self.world.kinds())
        removed = self.world.analyst('software', asset=self.asset, removed=True)['result']['installed']
        self.assertEqual({r['name']: r['present'] for r in removed}['New Tool'], False)

    def test_new_autostart_service_is_security_relevant(self):
        found = self.later(services=SERVICES + [{'name': 'Odd', 'state': 'Running', 'start': 'Auto', 'binary': 'C:\\x\\odd.exe'}])
        self.assertEqual(found['service_added']['category'], 'security')

    def test_new_manual_service_is_notable(self):
        found = self.later(services=SERVICES + [{'name': 'Odd', 'state': 'Stopped', 'start': 'Manual', 'binary': 'odd.exe'}])
        self.assertEqual(found['service_added']['category'], 'notable')

    def test_service_binary_change(self):
        services = [dict(s) for s in SERVICES]
        services[2]['binary'] = 'C:\\Temp\\spoolsv2.exe'
        self.assertEqual(self.later(services=services)['service_binary_changed']['category'], 'security')

    def test_security_software_disappearing(self):
        found = self.later(services=SERVICES[1:])
        self.assertEqual(found['service_removed']['category'], 'security')
        self.assertEqual(found['service_removed']['subject'], 'windefend')

    def test_security_service_stopped(self):
        services = [dict(s) for s in SERVICES]
        services[0]['state'] = 'Stopped'
        self.assertEqual(self.later(services=services)['security_service_stopped']['category'], 'security')

    def test_ordinary_service_stopping_records_nothing(self):
        services = [dict(s) for s in SERVICES]
        services[2]['state'] = 'Stopped'
        self.later(services=services)
        self.assertEqual(self.world.kinds(), ['asset_discovered'])

    def test_per_user_service_suffix_change_records_nothing(self):
        base = SERVICES + [{'name': 'CDPUserSvc_4fd12', 'state': 'Running', 'start': 'Auto'}]
        self.world.take(snapshot(at=NOW - HOUR, services=base))
        self.world.take(snapshot(at=NOW, services=SERVICES + [{'name': 'CDPUserSvc_99aa1', 'state': 'Running', 'start': 'Auto'}]))
        self.assertEqual([k for k in self.world.kinds() if k.startswith('service_') and k != 'service_added'], [])
        self.assertEqual(self.world.kinds().count('service_added'), 1)

    def test_new_local_admin(self):
        found = self.later(users=[{'name': 'alice', 'enabled': True, 'local_admin': True}, {'name': 'mallory', 'enabled': True, 'local_admin': True}])
        self.assertEqual(found['local_account_added']['category'], 'security')

    def test_admin_rights_granted(self):
        self.world.take(snapshot(at=NOW - HOUR, users=[{'name': 'alice', 'enabled': True, 'local_admin': False}]))
        self.world.take(snapshot(at=NOW))
        self.assertIn('local_admin_granted', {c['kind'] for c in self.world.store.changes()})

    def test_listener_beyond_loopback_is_security_and_loopback_is_routine(self):
        found = self.later(listeners=[{'proto': 'tcp', 'port': 135, 'scope': 'any'}, {'proto': 'tcp', 'port': 9000, 'scope': 'loopback'}, {'proto': 'tcp', 'port': 4444, 'scope': 'any', 'process': 'nc'}, {'proto': 'tcp', 'port': 9001, 'scope': 'loopback'}])
        added = [c for c in self.world.store.changes() if c['kind'] == 'listener_opened']
        self.assertEqual({c['subject']: c['category'] for c in added}, {'tcp/4444/any': 'security', 'tcp/9001/loopback': 'routine'})
        del found

    def test_defender_off_is_security(self):
        raw = snapshot(at=NOW)
        raw['security']['defender']['realtime'] = False
        self.world.take(raw)
        change = next(c for c in self.world.store.changes() if c['subject'] == 'defender_realtime')
        self.assertEqual((change['kind'], change['category']), ('security_control_weakened', 'security'))

    def test_defender_on_again_is_not_alarming(self):
        self.test_defender_off_is_security()
        self.world.take(snapshot(at=NOW + MIN))
        self.assertEqual(self.world.store.changes(limit=1)[0]['category'], 'routine')

    def test_owner_and_criticality_changes(self):
        self.world.admin('metadata', asset=self.asset, name='owner', value='Alice')
        self.world.admin('metadata', asset=self.asset, name='criticality', value='high')
        found = {c['kind']: c for c in self.world.store.changes()}
        self.assertEqual(found['owner_changed']['category'], 'notable')
        self.assertEqual(found['criticality_changed']['category'], 'security')
        self.assertEqual(found['criticality_changed']['klass'], 'admin')

    def test_setting_the_same_value_records_nothing(self):
        self.world.admin('metadata', asset=self.asset, name='owner', value='Alice')
        count = len(self.world.kinds())
        self.world.admin('metadata', asset=self.asset, name='owner', value='Alice')
        self.assertEqual(len(self.world.kinds()), count)

    def test_routine_only_changes_raise_nothing(self):
        self.later(ip='192.168.1.99')
        self.assertEqual(self.world.work.health()['security_changes_unreviewed'], 0)

    def test_security_change_raises_health_until_acknowledged(self):
        self.later(services=SERVICES[1:])
        health = self.world.work.health()
        self.assertEqual((health['status'], health['security_changes_unreviewed']), ('WARN', 1))
        seq = self.world.analyst('changes', unreviewed=True)['result'][0]['seq']
        self.assertTrue(self.world.analyst('acknowledge', seq=seq, note='planned')['ok'])
        self.assertEqual(self.world.work.health()['security_changes_unreviewed'], 0)
        self.assertEqual(len(self.world.store.changes(category='security')), 1)

    def test_a_much_shorter_list_removes_nothing_and_is_flagged(self):
        many = [{'name': f'p{n}', 'version': '1'} for n in range(40)]
        self.world.take(snapshot(at=NOW - HOUR, software=many))
        self.world.take(snapshot(at=NOW, software=many[:3]))
        self.assertEqual(self.world.store.count_items(self.asset, 'software'), 41 - 1)
        change = next(c for c in self.world.store.changes() if c['kind'] == 'collection_anomaly')
        self.assertEqual(change['category'], 'security')

    def test_absent_section_removes_nothing(self):
        raw = snapshot(at=NOW)
        del raw['services']
        self.world.take(raw)
        self.assertEqual(self.world.store.count_items(self.asset, 'service'), 3)

    def test_history_is_append_only_and_chained(self):
        self.later(os_build='26300')
        for sql in ('UPDATE changes SET kind = 1', 'DELETE FROM changes', 'UPDATE audit SET actor = 1', 'DELETE FROM audit'):
            self.world.store.audit(None, NOW, 'a', 'b', {})
            with self.assertRaises(Exception):
                self.world.store.db.execute(sql)
        self.assertEqual(self.world.store.verify_changes()[1], None)
        self.assertEqual(self.world.store.verify_audit()[1], None)

    def test_a_tampered_chain_is_detected(self):
        self.later(os_build='26300')
        store = self.world.store
        store.db.execute('DROP TRIGGER changes_no_update')
        store.db.execute("UPDATE changes SET after = '\"9\"' WHERE seq = 2")
        store.db.commit()
        self.assertEqual(self.world.analyst('validate')['result']['history_first_broken'], 2)

    def test_a_failed_snapshot_leaves_nothing_half_applied(self):
        store = self.world.store
        real = store.set_source
        store.set_source = lambda *a: (_ for _ in ()).throw(RuntimeError('crash'))
        with self.assertRaises(RuntimeError):
            self.world.take(snapshot(at=NOW, os_build='26300'))
        store.set_source = real
        self.assertEqual(store.attribute(self.asset, 'os.build', 'observed'), '26200')
        self.assertEqual(self.world.kinds(), ['asset_discovered'])


class Life(unittest.TestCase):
    def setUp(self):
        self.world = World()
        self.addCleanup(self.world.close)
        self.world.take(snapshot())
        self.asset = self.world.only()['asset_id']
        self.policy = Lifecycle(new_hours=72, stale_days=14)

    def age(self, days):
        self.world.now = NOW + days * DAY
        return self.world.work.inventory.lifecycle(self.policy)

    def test_new_then_active_then_stale(self):
        self.assertEqual(self.world.only()['status'], 'new')
        self.world.store.touch(self.asset, NOW, NOW + 4 * DAY)
        self.age(4)
        self.assertEqual(self.world.only()['status'], 'active')
        self.age(19)
        self.assertEqual(self.world.only()['status'], 'stale')

    def test_stale_is_never_deleted(self):
        self.age(400)
        self.assertEqual(self.world.only()['status'], 'stale')
        self.age(800)
        self.assertEqual(len(self.world.store.assets()), 1)

    def test_thresholds_are_configurable(self):
        self.world.now = NOW + 2 * DAY
        self.world.work.inventory.lifecycle(Lifecycle(stale_days=1))
        self.assertEqual(self.world.only()['status'], 'stale')

    def test_stale_returns_to_active(self):
        self.age(20)
        self.world.take(snapshot(at=self.world.now))
        self.assertEqual(self.world.only()['status'], 'active')
        self.assertIn('asset_returned', self.world.kinds())

    def test_retired_is_kept_and_stays_retired_with_time(self):
        self.assertTrue(self.world.admin('retire', asset=self.asset, reason='sold')['ok'])
        self.age(100)
        self.assertEqual(self.world.only()['status'], 'retired')

    def test_retired_machine_seen_again_is_security_relevant(self):
        self.world.admin('retire', asset=self.asset, reason='sold')
        self.world.now = NOW + HOUR
        self.world.take(snapshot(at=NOW + HOUR, os_build='9'))
        self.assertEqual(self.world.only()['status'], 'reappeared')
        change = next(c for c in self.world.store.changes() if c['kind'] == 'retired_asset_seen')
        self.assertEqual(change['category'], 'security')
        self.assertTrue(self.world.admin('reactivate', asset=self.asset, reason='returned')['ok'])
        self.assertEqual(self.world.only()['status'], 'active')

    def test_telemetry_from_a_retired_host_also_counts(self):
        self.world.admin('retire', asset=self.asset, reason='sold')
        self.world.work.inventory.attribute('lab-01', NOW + 1, NOW + 2, 'telemetry:windows')
        self.assertEqual(self.world.only()['status'], 'reappeared')

    def test_declared_machine_waits_to_be_seen(self):
        reply = self.world.admin('register', hostname='kali-lab', asset_type='virtual_machine', platform='linux')
        asset = self.world.store.asset(reply['result']['asset_id'])
        self.assertEqual(asset['status'], 'declared')
        self.age(90)
        self.assertEqual(self.world.store.asset(asset['asset_id'])['status'], 'declared')
        self.world.work.inventory.attribute('kali-lab', self.world.now, self.world.now, 'telemetry:windows')
        self.assertEqual(self.world.store.asset(asset['asset_id'])['status'], 'new')

    def test_no_asset_goes_stale_while_the_siem_itself_is_catching_up(self):
        work = self.world.work
        self.world.now = NOW + 30 * DAY
        work.started = NOW
        self.world.store.set_mark('telemetry', NOW)
        self.assertEqual(work.lifecycle(), 0)
        self.assertEqual(self.world.only()['status'], 'new')
        self.world.store.set_mark('telemetry', self.world.now)
        self.assertEqual(work.lifecycle(), 1)

    def test_no_asset_goes_stale_just_after_a_restart(self):
        work = self.world.work
        self.world.now = NOW + 30 * DAY
        work.started = self.world.now
        self.world.store.set_mark('telemetry', self.world.now)
        self.assertEqual(work.lifecycle(), 0)


class Relationships(unittest.TestCase):
    def setUp(self):
        self.world = World()
        self.addCleanup(self.world.close)
        self.world.take(snapshot())
        self.asset = self.world.only()['asset_id']

    def rows(self):
        return self.world.analyst('relationships', asset=self.asset)['result']

    def test_every_row_has_the_required_fields(self):
        rows = self.rows()
        self.assertTrue(rows)
        for row in rows:
            for key in ('source', 'type', 'target', 'last_seen', 'provenance', 'confidence', 'basis'):
                self.assertTrue(row.get(key), (key, row))

    def test_types_from_a_snapshot(self):
        self.assertTrue({'has_interface', 'has_ip', 'has_software', 'runs_service', 'in_segment'} <= {r['type'] for r in self.rows()})

    def test_segment_is_inferred_and_others_observed(self):
        kinds = {r['type']: r['basis'] for r in self.rows()}
        self.assertEqual(kinds['in_segment'], 'inferred')
        self.assertEqual(kinds['has_ip'], 'directly observed')

    def test_owner_link_exists_only_when_assigned(self):
        self.assertNotIn('assigned_to', {r['type'] for r in self.rows()})
        self.world.admin('metadata', asset=self.asset, name='owner', value='Alice')
        self.assertIn('assigned_to', {r['type'] for r in self.rows()})

    def test_authentication_links_user_to_host_and_separates_failures(self):
        self.world.search.responses['authenticated'] = user_buckets(codes=(('4624', 5), ('4625', 2)))
        self.world.work.telemetry._users(NOW - HOUR, NOW, {'lab-01': self.asset})
        found = {r['type']: r for r in self.rows()}
        self.assertEqual(found['authenticated_on']['count'], 5)
        self.assertEqual(found['failed_authentication_on']['count'], 2)
        self.assertEqual(found['authenticated_on']['source']['id'], 'lab\\alice')

    def test_traffic_links_to_an_address_and_claims_no_trust(self):
        self.world.search.responses['peers'] = peer_buckets()
        self.world.work.telemetry._network(NOW - HOUR, NOW, {'lab-01': self.asset})
        link = next(r for r in self.rows() if r['type'] == 'communicates_with')
        self.assertEqual(link['target'], {'type': 'ip', 'id': '192.168.1.20'})
        self.assertEqual(self.world.analyst('show', asset=self.asset)['result']['inferred'], [])

    def test_traffic_to_a_known_machine_links_to_that_asset(self):
        self.world.take(snapshot(host='lab-02', guid='7777aaaa-2222-3333-4444-555566667777', uuid=None, mac='3c:52:82:77:77:77', ip='192.168.1.20'))
        other = next(a['asset_id'] for a in self.world.store.assets() if a['hostname'] == 'lab-02')
        self.world.search.responses['peers'] = peer_buckets()
        self.world.work.telemetry._network(NOW - HOUR, NOW, {'lab-01': self.asset})
        link = next(r for r in self.rows() if r['type'] == 'communicates_with')
        self.assertEqual(link['target'], {'type': 'asset', 'id': other})

    def test_repeat_observation_counts_and_does_not_duplicate(self):
        self.world.search.responses['peers'] = peer_buckets()
        self.world.work.telemetry._network(NOW - HOUR, NOW, {'lab-01': self.asset})
        self.world.work.telemetry._network(NOW - HOUR, NOW, {'lab-01': self.asset})
        rows = [r for r in self.rows() if r['type'] == 'communicates_with']
        self.assertEqual((len(rows), rows[0]['count']), (1, 8))


class Telemetry(unittest.TestCase):
    def setUp(self):
        self.world = World()
        self.addCleanup(self.world.close)

    def fill(self):
        search = self.world.search
        search.responses.update(sources=host_buckets(), authenticated=user_buckets(), peers=peer_buckets(), names=name_buckets())

    def test_a_run_builds_a_low_confidence_record_from_a_name(self):
        self.fill()
        self.assertEqual(self.world.work.telemetry.run(self.world.store, 0), 1)
        asset = self.world.only()
        self.assertEqual((asset['hostname'], asset['confidence'], asset['platform'], asset['source']), ('lab-01', 'low', 'windows', 'telemetry:windows'))

    def test_a_process_seen_running_is_not_listed_as_installed_software(self):
        self.fill()
        self.world.work.telemetry.run(self.world.store, 0)
        asset = self.world.only()['asset_id']
        found = self.world.analyst('software', asset=asset)['result']
        self.assertEqual(found['installed'], [])
        self.assertEqual(found['seen_running'][0]['name'], 'tool.exe')

    def test_the_window_uses_ingest_time_and_is_bounded(self):
        self.fill()
        self.world.work.telemetry.run(self.world.store, 0)
        body = self.world.search.searches[0][1]
        window = body['query']['bool']['filter'][0]['range']['event.ingested']
        self.assertLessEqual(window['lt'] - window['gte'], 24 * HOUR)
        self.assertEqual(body['timeout'], '15s')

    def test_only_allowed_fields_are_queried(self):
        self.fill()
        self.world.work.telemetry.run(self.world.store, 0)
        text = json.dumps([b for _, b in self.world.search.searches])
        for field in ('command_line', 'script_block', 'winlog.event_data', 'file.path', 'winlog.xml'):
            self.assertNotIn(field, text)

    def test_the_mark_moves_only_after_success(self):
        self.fill()
        self.world.search.responses['names'] = {}
        with self.assertRaises(KeyError):
            self.world.work.telemetry.run(self.world.store, 0)
        self.assertIsNone(self.world.store.mark('telemetry'))

    def test_backfill_catches_up_one_window_at_a_time(self):
        self.fill()
        for _ in range(7):
            self.world.work.telemetry.run(self.world.store, 0)
        self.assertEqual(int(self.world.store.mark('telemetry')), NOW - 60000)

    def test_a_hostile_host_name_is_ignored(self):
        self.world.search.responses['sources'] = host_buckets(host='x;rm -rf /')
        self.world.work.telemetry.run(self.world.store, 0)
        self.assertEqual(self.world.store.assets(), [])

    def test_new_records_per_day_are_capped(self):
        world = World(max_new_assets_per_day=2)
        self.addCleanup(world.close)
        for n in range(5):
            world.work.inventory.attribute(f'host-{n}', NOW, NOW, 'telemetry:windows')
        self.assertEqual(len(world.store.assets()), 2)
        self.assertEqual(world.work.health()['refused_new_assets'], 3)

    def test_items_per_kind_are_capped(self):
        world = World(max_items_per_kind=3)
        self.addCleanup(world.close)
        world.take(snapshot())
        asset = world.only()['asset_id']
        results = [world.work.inventory.bounded_item(asset, 'process', f'p{n}', {}, 'observed', 's', 'high', NOW, NOW) for n in range(5)]
        self.assertEqual(results, [True, True, True, False, False])

    def event(self, *hits, baseline=0):
        self.fill()
        self.world.search.responses['events'] = {'hits': {'hits': list(hits)}}
        self.world.work.telemetry.run(self.world.store, baseline)

    def test_service_install_event_is_a_security_change_with_provenance(self):
        self.event(event_hit('e1', 'windows.system', '7045', service={'name': 'Odd'}))
        change = next(c for c in self.world.store.changes() if c['kind'] == 'service_installed_event')
        self.assertEqual((change['category'], change['subject'], change['source']), ('security', 'Odd', 'telemetry:windows.system/7045'))

    def test_an_event_read_twice_is_one_change(self):
        hit = event_hit('e1', 'windows.system', '7045', service={'name': 'Odd'})
        self.event(hit)
        self.world.store.set_mark('telemetry', NOW - 7 * DAY)
        self.event(hit)
        self.assertEqual(self.world.kinds().count('service_installed_event'), 1)

    def test_history_before_the_baseline_raises_nothing(self):
        self.event(event_hit('e1', 'windows.system', '7045', service={'name': 'Odd'}), baseline=NOW)
        self.assertNotIn('service_installed_event', self.world.kinds())

    def test_the_baseline_goes_by_ingest_time_within_a_window_that_straddles_it(self):
        old = event_hit('e1', 'windows.system', '7045', at=NOW - 2 * DAY, service={'name': 'Old'})
        old['_source']['event']['ingested'] = schema.iso(NOW - 3 * HOUR)
        new = event_hit('e2', 'windows.system', '7045', at=NOW - MIN, service={'name': 'New'})
        self.event(old, new, baseline=NOW - HOUR)
        self.assertEqual([c['subject'] for c in self.world.store.changes() if c['kind'] == 'service_installed_event'], ['New'])

    def test_silent_security_source_is_inferred_and_labelled(self):
        self.world.take(snapshot())
        asset = self.world.only()['asset_id']
        store = self.world.store
        store.put_item(asset, 'telemetry_source', 'windows.sysmon', {}, 'observed', 't', 'high', NOW - 9 * HOUR, NOW - 9 * HOUR)
        store.put_item(asset, 'telemetry_source', 'windows.system', {}, 'observed', 't', 'high', NOW - MIN, NOW - MIN)
        self.world.work.telemetry.silent_sources(asset, NOW)
        self.world.work.telemetry.silent_sources(asset, NOW)
        rows = [c for c in store.changes() if c['kind'] == 'security_telemetry_silent']
        self.assertEqual((len(rows), rows[0]['klass']), (1, 'inferred'))

    def test_a_quiet_host_is_not_called_silent(self):
        self.world.take(snapshot())
        asset = self.world.only()['asset_id']
        self.world.store.put_item(asset, 'telemetry_source', 'windows.sysmon', {}, 'observed', 't', 'high', NOW - 20 * HOUR, NOW - 20 * HOUR)
        self.world.work.telemetry.silent_sources(asset, NOW)
        self.assertNotIn('security_telemetry_silent', self.world.kinds())


class LinuxTelemetry(unittest.TestCase):
    """Synthetic buckets, in the shape the Linux index returns."""

    def setUp(self):
        self.world = World()
        self.addCleanup(self.world.close)
        raw = snapshot(host='lab-linux', guid=None, uuid=None, mac=None, ip='172.20.0.2')
        raw['collector'] = 'linux-local'
        raw['host']['platform'] = 'linux'
        raw['host']['asset_type'] = 'siem_host'
        raw['identifiers'] = {'linux_machine_id': 'ab' * 16}
        self.world.take(raw)
        self.asset = self.world.only()['asset_id']
        self.digest = identity.token('linux_machine_id', 'ab' * 16)

    def buckets(self, digest=None, names=('lab-linux-wsl',), users=(('alice', 'success', 3),)):
        last = NOW - MIN
        rows = [{'key': n, 'last': {'value': last}, 'outcome': {'buckets': [{'key': o, 'doc_count': c, 'last': {'value': last}}]}} for n, o, c in users]
        return {'aggregations': {'hosts': {'buckets': [{'key': digest or self.digest, 'doc_count': 10, 'first': {'value': NOW - HOUR}, 'last': {'value': last}, 'name': {'buckets': [{'key': n} for n in names]},
                                                        'sources': {'buckets': [{'key': 'linux.auth', 'last': {'value': last}}]}, 'people': {'users': {'buckets': rows}}}]}}}

    def run_stage(self, baseline=0):
        self.world.work.telemetry._linux(NOW - HOUR, NOW, baseline)

    def test_events_join_the_asset_by_identity_not_by_name(self):
        self.world.search.responses['linux'] = self.buckets()
        self.run_stage()
        self.assertEqual(len(self.world.store.assets()), 1)
        self.assertEqual(self.world.only()['last_ms'], NOW)
        self.assertEqual(self.world.store.holders('hostname', 'lab-linux-wsl'), {self.asset})
        self.assertEqual(self.world.store.items(self.asset, 'telemetry_source')[0]['key'], 'linux.auth')

    def test_an_unknown_machine_id_creates_nothing_and_is_counted(self):
        self.world.search.responses['linux'] = self.buckets(digest='ff' * 16)
        self.run_stage()
        self.assertEqual(len(self.world.store.assets()), 1)
        self.assertEqual(self.world.only()['last_ms'], NOW)
        self.assertEqual(self.world.store.holders('hostname', 'lab-linux-wsl'), set())
        self.assertEqual(self.world.work.health()['unattributed_linux_events'], 10)

    def test_two_names_on_one_id_are_not_trusted(self):
        self.world.search.responses['linux'] = self.buckets(names=('a-wsl', 'b-wsl'))
        self.run_stage()
        self.assertEqual(self.world.store.holders('hostname', 'a-wsl'), set())

    def test_a_hostile_name_is_ignored(self):
        self.world.search.responses['linux'] = self.buckets(names=('x;rm -rf /',))
        self.run_stage()
        self.assertEqual(self.world.store.items(self.asset, 'telemetry_source'), [])

    def test_a_linux_user_is_never_the_same_entity_as_a_windows_user(self):
        self.world.search.responses['linux'] = self.buckets()
        self.run_stage()
        link = self.world.store.relationships(self.asset, 'authenticated_on')[0]
        self.assertEqual(link['src_id'], 'lab-linux-wsl\\alice')

    def test_observed_user_does_not_become_owner(self):
        self.world.search.responses['linux'] = self.buckets()
        self.run_stage()
        self.assertIsNone(self.world.store.attribute(self.asset, 'owner', 'admin'))
        self.assertIsNone(self.world.store.attribute(self.asset, 'criticality', 'admin'))

    def test_failures_link_apart(self):
        self.world.search.responses['linux'] = self.buckets(users=(('alice', 'failure', 4),))
        self.run_stage()
        self.assertEqual(self.world.store.relationships(self.asset, 'failed_authentication_on')[0]['count'], 4)

    def event(self, action, **fields):
        return {'_id': 'e1', '_source': {'@timestamp': schema.iso(NOW - MIN), 'host': {'id': self.digest}, 'event': {'dataset': 'linux.auth', 'action': action, 'ingested': schema.iso(NOW - MIN)}, **fields}}

    def test_a_new_account_is_a_security_change_once(self):
        self.world.search.responses['linux'] = self.buckets()
        self.world.search.responses['linux_events'] = {'hits': {'hits': [self.event('user-created', user={'target': {'name': 'mallory'}})]}}
        self.run_stage()
        self.run_stage()
        rows = [c for c in self.world.store.changes() if c['kind'] == 'account_created_event']
        self.assertEqual((len(rows), rows[0]['subject'], rows[0]['category']), (1, 'mallory', 'security'))

    def test_history_before_the_baseline_raises_nothing(self):
        self.world.search.responses['linux'] = self.buckets()
        self.world.search.responses['linux_events'] = {'hits': {'hits': [self.event('user-created')]}}
        self.run_stage(baseline=NOW)
        self.assertNotIn('account_created_event', self.world.kinds())

    def test_the_linux_query_asks_for_no_text(self):
        self.world.search.responses['linux'] = self.buckets()
        self.run_stage()
        text = json.dumps([b for _, b in self.world.search.searches])
        for field in ('message', 'command_line', 'journald'):
            self.assertNotIn(field, text)


class Collect(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name)

    def test_only_plain_named_json_files_are_taken(self):
        (self.path / 'good.json').write_text('{}')
        (self.path / 'bad name;x.json').write_text('{}')
        (self.path / 'note.txt').write_text('x')
        (self.path / 'partial.tmp').write_text('{')
        good, refused = collect.read_drop(str(self.path))
        self.assertEqual([n for n, _ in good], ['good.json'])
        self.assertEqual(len(refused), 2)

    @unittest.skipUnless(hasattr(os, 'O_NOFOLLOW') and os.name == 'posix', 'needs links')
    def test_a_link_is_refused(self):
        secret = self.path / 'outside'
        secret.write_text('{"x": 1}')
        drop = self.path / 'drop'
        drop.mkdir()
        (drop / 'link.json').symlink_to(secret)
        good, refused = collect.read_drop(str(drop))
        self.assertEqual(good, [])
        self.assertEqual(refused[0][1], 'not readable as a plain file')

    def test_an_oversized_file_is_refused(self):
        (self.path / 'big.json').write_bytes(b'x' * (schema.MAX_SNAPSHOT_BYTES + 1))
        good, refused = collect.read_drop(str(self.path))
        self.assertEqual((good, refused), ([], [('big.json', 'too large')]))

    def test_a_missing_folder_is_not_an_error(self):
        self.assertEqual(collect.read_drop(str(self.path / 'absent')), ([], []))

    def test_too_many_files_are_bounded(self):
        for n in range(collect.MAX_FILES + 3):
            (self.path / f'f{n}.json').write_text('{}')
        good, refused = collect.read_drop(str(self.path))
        self.assertEqual((len(good), len(refused)), (collect.MAX_FILES, 3))

    def test_bom_is_accepted(self):
        self.assertEqual(collect.decode(b'\xef\xbb\xbf{"a": 1}'), {'a': 1})

    def test_package_list_keeps_only_installed(self):
        path = self.path / 'status'
        path.write_text('Package: a\nStatus: install ok installed\nVersion: 1\n\nPackage: b\nStatus: deinstall ok config-files\nVersion: 2\n\n')
        self.assertEqual([p['name'] for p in collect.packages(str(path))], ['a'])

    def test_listener_parsing(self):
        (self.path / 'tcp').write_text('  sl  local_address rem_address   st\n 0: 0100007F:23F0 00000000:0000 0A x\n 1: 00000000:0016 00000000:0000 0A x\n 2: 0100007F:1234 0100007F:0016 01 x\n')
        rows = collect.listeners(str(self.path))
        self.assertEqual([(r['port'], r['scope']) for r in rows], [(9200, 'loopback'), (22, 'any')])

    def test_a_mapped_loopback_address_is_loopback(self):
        (self.path / 'tcp6').write_text('  sl  local_address rem_address   st\n 0: 0000000000000000FFFF00000100007F:23F0 00000000000000000000000000000000:0000 0A x\n')
        self.assertEqual([(r['port'], r['scope']) for r in collect.listeners(str(self.path))], [(9200, 'loopback')])

    def test_the_only_programs_run_have_fixed_arguments(self):
        source = (Path(collect.__file__)).read_text(encoding='utf8')
        self.assertEqual(source.count('subprocess.run('), 1)
        self.assertNotIn('shell=True', source)
        self.assertEqual(source.count('_program(['), 2)

    def test_no_module_runs_a_program_or_evaluates_text(self):
        folder = Path(collect.__file__).parent
        for path in folder.glob('*.py'):
            text = path.read_text(encoding='utf8')
            for word in ('os.system', 'eval(', 'exec(', 'shell=True', 'pickle', 'Popen'):
                self.assertNotIn(word, text, path.name)
            if path.name != 'collect.py':
                self.assertNotIn('subprocess', text, path.name)



if __name__ == '__main__':
    unittest.main()
