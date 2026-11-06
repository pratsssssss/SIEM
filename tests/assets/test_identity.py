"""Identity: every case in ADR-0013, D42. All data here is synthetic."""
import unittest


from helpers import DAY, GUID_A, GUID_B, HOUR, MAC_A, MAC_B, NOW, UUID_A, UUID_B, World, host_buckets, snapshot
from siem_asset import identity, schema
from siem_asset.identity import Observation, resolve


class Lookup:
    def __init__(self):
        self.ids = {}

    def add(self, asset, kind, value):
        self.ids.setdefault((kind, value), set()).add(asset)

    def holders(self, kind, value):
        return set(self.ids.get((kind, value), ()))

    def strong_of(self, asset):
        found = {}
        for (kind, value), holders in self.ids.items():
            if asset in holders and kind in identity.STRONG:
                found.setdefault(kind, set()).add(value)
        return found

    def is_provisional(self, asset):
        return not self.strong_of(asset)


class Pure(unittest.TestCase):
    def setUp(self):
        self.look = Lookup()

    def test_new_machine(self):
        self.assertEqual(resolve(Observation({'windows_machine_guid': 'g'}, ['a']), self.look).outcome, identity.NEW)

    def test_strong_match_is_high_confidence(self):
        self.look.add('A', 'windows_machine_guid', 'g')
        found = resolve(Observation({'windows_machine_guid': 'g'}, ['renamed']), self.look)
        self.assertEqual((found.outcome, found.asset_id, found.confidence), (identity.MATCHED, 'A', schema.HIGH))

    def test_contradicting_strong_ids_do_not_match(self):
        self.look.add('A', 'windows_machine_guid', 'g1')
        self.look.add('A', 'hw_uuid', 'u1')
        found = resolve(Observation({'windows_machine_guid': 'g1', 'hw_uuid': 'u2'}, ['a']), self.look)
        self.assertEqual(found.outcome, identity.NEW_CONFLICTED)
        self.assertEqual(found.conflicts[0]['kind'], 'clone_or_reinstall')

    def test_a_shared_identifier_with_an_exact_holder_goes_to_that_holder(self):
        self.look.add('A', 'windows_machine_guid', 'g1')
        self.look.add('A', 'hw_uuid', 'u1')
        self.look.add('B', 'windows_machine_guid', 'g2')
        self.look.add('B', 'hw_uuid', 'u1')
        found = resolve(Observation({'windows_machine_guid': 'g2', 'hw_uuid': 'u1'}, ['b']), self.look)
        self.assertEqual((found.outcome, found.asset_id), (identity.MATCHED, 'B'))

    def test_one_identifier_on_two_assets_is_held(self):
        self.look.add('A', 'hw_uuid', 'u1')
        self.look.add('B', 'hw_uuid', 'u1')
        found = resolve(Observation({'hw_uuid': 'u1'}, ['x']), self.look)
        self.assertEqual(found.outcome, identity.HELD)
        self.assertEqual(found.conflicts[0]['kind'], 'split_identity')

    def test_name_alone_never_joins_two_identified_machines(self):
        self.look.add('A', 'windows_machine_guid', 'g1')
        self.look.add('A', 'hostname', 'same')
        found = resolve(Observation({'windows_machine_guid': 'g2'}, ['same']), self.look)
        self.assertEqual(found.outcome, identity.NEW_CONFLICTED)
        self.assertIsNone(found.asset_id)
        self.assertEqual(found.conflicts[0]['kind'], 'duplicate_hostname')

    def test_provisional_record_is_adopted_with_medium_confidence(self):
        self.look.add('P', 'hostname', 'same')
        found = resolve(Observation({'windows_machine_guid': 'g'}, ['same']), self.look)
        self.assertEqual((found.outcome, found.asset_id, found.confidence), (identity.ADOPTED, 'P', schema.MEDIUM))

    def test_two_provisional_records_are_not_guessed_between(self):
        self.look.add('P', 'hostname', 'same')
        self.look.add('Q', 'hostname', 'same')
        self.assertEqual(resolve(Observation({'windows_machine_guid': 'g'}, ['same']), self.look).outcome, identity.NEW_CONFLICTED)

    def test_physical_mac_on_another_machine_conflicts(self):
        self.look.add('A', 'windows_machine_guid', 'g1')
        self.look.add('A', 'mac', 'm')
        found = resolve(Observation({'windows_machine_guid': 'g2'}, ['other'], ['m']), self.look)
        self.assertEqual(found.conflicts[0]['kind'], 'shared_mac')

    def test_telemetry_name_attributes_with_medium_confidence(self):
        self.look.add('A', 'hostname', 'a')
        found = resolve(Observation(hostnames=['a']), self.look)
        self.assertEqual((found.outcome, found.asset_id, found.confidence), (identity.MATCHED, 'A', schema.MEDIUM))

    def test_telemetry_name_held_twice_is_not_attributed(self):
        self.look.add('A', 'hostname', 'a')
        self.look.add('B', 'hostname', 'a')
        found = resolve(Observation(hostnames=['a']), self.look)
        self.assertEqual((found.outcome, found.asset_id), (identity.HELD, None))

    def test_unknown_telemetry_name_is_low_confidence(self):
        self.assertEqual(resolve(Observation(hostnames=['z']), self.look).confidence, schema.LOW)

    def test_name_and_mac_without_strong_id(self):
        self.look.add('A', 'hostname', 'a')
        self.look.add('A', 'mac', 'm')
        self.assertEqual(resolve(Observation({}, ['a'], ['m']), self.look).asset_id, 'A')

    def test_mac_without_name_is_only_a_partial_match(self):
        self.look.add('A', 'hostname', 'a')
        self.look.add('A', 'mac', 'm')
        found = resolve(Observation({}, ['other'], ['m']), self.look)
        self.assertEqual(found.conflicts[0]['kind'], 'partial_match')

    def test_junk_firmware_uuids_are_ignored(self):
        self.assertEqual(identity.strong_tokens({'hw_uuid': '00000000-0000-0000-0000-000000000000', 'windows_machine_guid': GUID_A}).keys(), {'windows_machine_guid'})
        self.assertEqual(identity.strong_tokens({'hw_uuid': 'FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF'}), {})

    def test_identifier_is_stored_as_a_digest(self):
        self.assertNotIn(GUID_A, identity.token('windows_machine_guid', GUID_A))

    def test_virtual_macs_are_not_evidence(self):
        for value in ('00:15:5d:00:00:01', '08:00:27:00:00:01', '02:00:00:00:00:01', '52:54:00:00:00:01'):
            self.assertFalse(schema.mac_is_physical(value), value)
        self.assertTrue(schema.mac_is_physical(MAC_A))


class Applied(unittest.TestCase):
    def setUp(self):
        self.world = World()
        self.addCleanup(self.world.close)

    def test_dhcp_change_keeps_one_asset_and_is_routine(self):
        self.world.take(snapshot(ip='192.168.1.10', at=NOW - DAY))
        self.world.take(snapshot(ip='192.168.1.77', at=NOW))
        asset = self.world.only()
        self.assertEqual({x['ip'] for x in self.world.store.leases(asset['asset_id'])}, {'192.168.1.10', '192.168.1.77'})
        change = next(c for c in self.world.store.changes() if c['kind'] == 'ip_changed')
        self.assertEqual(change['category'], 'routine')

    def test_multiple_interfaces(self):
        raw = snapshot()
        raw['interfaces'].append({'name': 'Ethernet', 'mac': MAC_B, 'up': False, 'virtual': False, 'ips': ['10.0.0.5']})
        self.world.take(raw)
        asset = self.world.only()
        self.assertEqual(len(self.world.store.items(asset['asset_id'], 'interface')), 2)
        self.assertEqual(len([i for i in self.world.store.identifiers(asset['asset_id']) if i['kind'] == 'mac']), 2)

    def test_hostname_change_keeps_the_asset_and_the_old_name(self):
        self.world.take(snapshot(host='old-name', at=NOW - DAY))
        self.world.take(snapshot(host='new-name', at=NOW))
        asset = self.world.only()
        self.assertEqual(asset['hostname'], 'new-name')
        self.assertEqual(self.world.store.holders('hostname', 'old-name'), {asset['asset_id']})
        self.assertIn('hostname_changed', self.world.kinds())

    def test_hostname_and_mac_change_together_is_security_relevant(self):
        self.world.take(snapshot(at=NOW - DAY))
        self.world.take(snapshot(host='elsewhere', mac=MAC_B, at=NOW))
        change = next(c for c in self.world.store.changes() if c['kind'] == 'network_identity_changed')
        self.assertEqual(change['category'], 'security')

    def test_reinstall_opens_a_conflict_and_keeps_two_records(self):
        self.world.take(snapshot(at=NOW - DAY))
        self.world.take(snapshot(guid=GUID_B, at=NOW))
        self.assertEqual(len(self.world.store.assets()), 2)
        self.assertEqual(self.world.store.conflicts()[0]['kind'], 'clone_or_reinstall')

    def test_cloned_vm_with_new_hardware_id_is_a_conflict(self):
        self.world.take(snapshot(host='vm', uuid=UUID_A, at=NOW - DAY))
        self.world.take(snapshot(host='vm-copy', uuid=UUID_B, at=NOW))
        self.assertEqual(len(self.world.store.assets()), 2)
        self.assertEqual(len(self.world.store.conflicts()), 1)

    def test_exact_clone_shows_itself_by_alternating_names(self):
        self.world.take(snapshot(host='one', at=NOW - 3 * HOUR))
        self.world.take(snapshot(host='two', at=NOW - 2 * HOUR))
        self.world.take(snapshot(host='one', at=NOW - HOUR))
        self.assertEqual(self.world.store.conflicts()[0]['kind'], 'possible_clone')

    def test_asset_with_no_identifiers_stays_provisional(self):
        self.world.take(snapshot(guid=None, uuid=None, mac=None))
        asset = self.world.only()
        self.assertEqual(asset['confidence'], schema.LOW)
        self.assertTrue(self.world.store.is_provisional(asset['asset_id']))

    def test_telemetry_then_snapshot_adopts_and_keeps_one_record(self):
        self.world.search.responses['sources'] = host_buckets()
        self.world.work.telemetry.run(self.world.store, 0)
        self.assertEqual(self.world.only()['confidence'], schema.LOW)
        self.world.take(snapshot())
        asset = self.world.only()
        self.assertEqual(asset['confidence'], schema.MEDIUM)
        self.assertIn('identity_adopted', self.world.kinds())

    def test_conflict_then_merge_then_stays_merged(self):
        self.world.take(snapshot(at=NOW - DAY))
        self.world.take(snapshot(guid=GUID_B, at=NOW - HOUR))
        conflict = self.world.store.conflicts()[0]
        keep, other = conflict['assets']
        reply = self.world.admin('resolve', conflict=conflict['conflict_id'], decision='merge', keep=keep, reason='reinstalled, confirmed by the owner')
        self.assertTrue(reply['ok'], reply)
        self.assertEqual(self.world.store.asset(other)['status'], 'merged')
        self.assertEqual(self.world.only()['asset_id'], keep)
        self.assertEqual(self.world.store.conflicts(), [])
        self.world.take(snapshot(guid=GUID_B, at=NOW))
        self.assertEqual(self.world.only()['asset_id'], keep)
        self.assertEqual(self.world.store.conflicts(), [])

    def test_separate_with_keep_gives_the_name_to_one_and_ends_ambiguity(self):
        self.world.take(snapshot(at=NOW - DAY))
        self.world.take(snapshot(guid=GUID_B, uuid=UUID_B, mac=MAC_B, at=NOW - HOUR))
        conflict = self.world.store.conflicts()[0]
        keep = conflict['assets'][0]
        self.assertTrue(self.world.admin('resolve', conflict=conflict['conflict_id'], decision='separate', keep=keep, reason='two machines')['ok'])
        self.assertEqual(self.world.store.holders('hostname', 'lab-01'), {keep})
        self.assertEqual(len(self.world.store.assets()), 2)

    def test_a_later_report_does_not_undo_a_decided_name(self):
        self.test_separate_with_keep_gives_the_name_to_one_and_ends_ambiguity()
        self.world.take(snapshot(guid=GUID_B, uuid=UUID_B, mac=MAC_B, at=NOW, ip='192.168.1.200'))
        self.assertEqual(len(self.world.store.holders('hostname', 'lab-01')), 1)
        self.assertEqual(self.world.store.conflicts(), [])

    def test_ambiguous_name_in_telemetry_attributes_nothing(self):
        self.world.take(snapshot(at=NOW - DAY))
        self.world.take(snapshot(guid=GUID_B, uuid=UUID_B, mac=MAC_B, at=NOW - HOUR))
        before = {a['asset_id']: a['last_ms'] for a in self.world.store.assets()}
        self.assertIsNone(self.world.work.inventory.attribute('lab-01', NOW, NOW, 'telemetry:windows'))
        self.assertEqual({a['asset_id']: a['last_ms'] for a in self.world.store.assets()}, before)

    def test_telemetry_held_by_a_conflict_is_replayed_after_it_is_resolved(self):
        self.world.take(snapshot(at=NOW - DAY))
        self.world.take(snapshot(guid=GUID_B, uuid=UUID_B, mac=MAC_B, at=NOW - HOUR))
        self.world.search.responses['sources'] = host_buckets()
        self.world.work.telemetry.run(self.world.store, 0)
        passed = int(self.world.store.mark('telemetry'))
        conflict = self.world.store.conflicts()[0]
        keep = conflict['assets'][0]
        self.world.admin('resolve', conflict=conflict['conflict_id'], decision='separate', keep=keep, reason='two machines')
        self.assertLess(int(self.world.store.mark('telemetry')), passed)
        self.assertIsNone(self.world.store.mark('held_since'))
        self.world.work.telemetry.run(self.world.store, 0)
        self.assertEqual(self.world.store.count_items(keep, 'telemetry_source'), 2)

    def test_held_report_changes_no_asset(self):
        self.world.take(snapshot(at=NOW - DAY))
        self.world.take(snapshot(guid=GUID_B, at=NOW - HOUR))
        count = len(self.world.store.assets())
        self.assertEqual(self.world.take(snapshot(guid=None, uuid=UUID_A, at=NOW, mac=None)), 'held')
        self.assertEqual(len(self.world.store.assets()), count)

    def test_conflicted_is_shown_as_the_status_while_open(self):
        self.world.take(snapshot(at=NOW - DAY))
        self.world.take(snapshot(guid=GUID_B, at=NOW))
        rows = self.world.analyst('list')['result']
        self.assertEqual({r['status'] for r in rows}, {'conflicted'})

    def test_forged_snapshot_cannot_take_over_an_identified_asset_by_name(self):
        self.world.take(snapshot(at=NOW - DAY))
        original = self.world.only()['asset_id']
        self.world.take(snapshot(guid='badbad00-0000-4000-8000-000000000000', uuid=None, mac=None, os_build='1', at=NOW))
        self.assertEqual(len(self.world.store.assets()), 2)
        self.assertEqual(self.world.store.attribute(original, 'os.build', 'observed'), '26200')

    def test_replayed_older_snapshot_is_refused(self):
        self.world.take(snapshot(at=NOW))
        with self.assertRaises(schema.Invalid):
            self.world.take(snapshot(at=NOW - HOUR, os_build='1'))
        self.assertEqual(self.world.store.attribute(self.world.only()['asset_id'], 'os.build', 'observed'), '26200')

    def test_duplicate_snapshot_is_applied_once(self):
        raw = snapshot()
        self.assertEqual(self.world.take(raw), 'applied')
        self.assertEqual(self.world.take(raw), 'unchanged')
        self.assertEqual(len(self.world.store.assets()), 1)



if __name__ == '__main__':
    unittest.main()
