"""Entity identity, and alert validation."""
import json
import unittest

import helpers  # noqa: F401
from helpers import GUID_A, alert, process_event
from siem_correlator import entities as ent
from siem_correlator import schema
from siem_correlator.schema import Invalid


class Users(unittest.TestCase):
    def test_a_sid_is_the_strongest_identity(self):
        item = ent.user('bob', 'CORP', 'S-1-5-21-1-2-3-1001')
        self.assertEqual(item.id, 'user:sid:S-1-5-21-1-2-3-1001')
        self.assertEqual(item.quality, 'strong')

    def test_domain_and_name(self):
        self.assertEqual(ent.user('Bob', 'CORP').id, 'user:name:corp\\bob')

    def test_a_combined_name_is_split(self):
        self.assertEqual(ent.user('CORP\\bob').id, 'user:name:corp\\bob')

    def test_case_does_not_make_a_different_account(self):
        self.assertEqual(ent.user('BOB', 'corp').id, ent.user('bob', 'CORP').id)

    def test_a_bare_name_is_ambiguous_and_stays_apart(self):
        bare = ent.user('bob')
        self.assertEqual(bare.quality, 'ambiguous')
        self.assertNotEqual(bare.id, ent.user('bob', 'CORP').id)

    def test_same_name_in_two_domains_is_two_accounts(self):
        self.assertNotEqual(ent.user('admin', 'HOST1').id, ent.user('admin', 'HOST2').id)

    def test_similar_names_are_not_merged(self):
        self.assertNotEqual(ent.user('bob', 'C').id, ent.user('bob1', 'C').id)
        self.assertNotEqual(ent.user('b.ob', 'C').id, ent.user('bob', 'C').id)

    def test_null_and_system_sids_are_not_identity(self):
        self.assertEqual(ent.user('bob', 'CORP', 'S-1-0-0').id, 'user:name:corp\\bob')
        self.assertEqual(ent.user('bob', 'CORP', 'garbage').id, 'user:name:corp\\bob')

    def test_service_accounts_are_weak(self):
        for name, domain in (('SYSTEM', 'NT AUTHORITY'), ('LOCAL SERVICE', 'NT AUTHORITY'), ('NETWORK SERVICE', None), ('ASUS$', 'WORKGROUP'), ('ANONYMOUS LOGON', None), ('DWM-1', 'Window Manager'), ('UMFD-0', 'Font Driver Host')):
            self.assertEqual(ent.user(name, domain).quality, 'weak', name)

    def test_empty_is_nothing(self):
        self.assertIsNone(ent.user('', 'CORP'))
        self.assertIsNone(ent.user(None))


class Others(unittest.TestCase):
    def test_public_ip_is_global(self):
        self.assertEqual(ent.ip('8.8.8.8', 'H').id, 'ip:8.8.8.8')

    def test_the_same_private_ip_on_two_hosts_is_two_entities(self):
        self.assertNotEqual(ent.ip('10.0.0.5', 'a').id, ent.ip('10.0.0.5', 'b').id)

    def test_loopback_is_weak(self):
        self.assertEqual(ent.ip('::1', 'H').quality, 'weak')
        self.assertEqual(ent.ip('127.0.0.1', 'H').quality, 'weak')

    def test_mapped_ipv6_is_the_same_host(self):
        self.assertEqual(ent.ip('::ffff:8.8.8.8').id, 'ip:8.8.8.8')

    def test_bad_ip(self):
        self.assertIsNone(ent.ip('not-an-ip'))

    def test_process_identity_is_the_guid_on_a_host(self):
        self.assertEqual(ent.process('HOST', '{' + GUID_A.upper() + '}').id, f'process:host:{GUID_A}')

    def test_same_guid_on_two_hosts_differs(self):
        self.assertNotEqual(ent.process('a', GUID_A).id, ent.process('b', GUID_A).id)

    def test_a_pid_is_not_a_process_identity(self):
        self.assertIsNone(ent.process('HOST', '4242'))

    def test_hash_and_domain(self):
        self.assertEqual(ent.sha256('AB' * 32).id, 'sha256:' + 'ab' * 32)
        self.assertIsNone(ent.sha256('short'))
        self.assertEqual(ent.domain('Evil.Example.COM.').id, 'domain:evil.example.com')
        self.assertIsNone(ent.domain('localhost'))

    def test_host_is_case_insensitive(self):
        self.assertEqual(ent.host('ASUS').id, ent.host('asus').id)
        self.assertIsNone(ent.host(''))


class Extraction(unittest.TestCase):
    def test_alert_and_rule_are_entities(self):
        doc = alert()
        items, _, _ = ent.extract(doc)
        self.assertIn(f"alert:{doc['alert_id']}", [e.id for e in items])
        self.assertIn(f"rule:{doc['rule_id']}", [e.id for e in items])

    def test_process_lineage_becomes_a_link(self):
        items, links, _ = ent.extract(alert(), [process_event(GUID_A, helpers.GUID_B, 'cmd.exe', 'powershell.exe')])
        self.assertIn((f'process:host:{helpers.GUID_B}', 'spawned', f'process:host:{GUID_A}'), links)

    def test_event_user_with_sid_is_kept_apart_from_alert_user_name(self):
        event = {'user': {'name': 'jdoe', 'domain': 'WS01', 'id': 'S-1-5-21-1-2-3-1001'}}
        ids = {e.id for e in ent.extract(alert(), [event])[0] if e.kind == 'user'}
        self.assertEqual(ids, {'user:name:ws01\\jdoe', 'user:sid:S-1-5-21-1-2-3-1001'})

    def test_events_naming_two_accounts_are_noted(self):
        _, _, notes = ent.extract(alert(), [{'user': {'name': 'a', 'domain': 'X'}}, {'user': {'name': 'b', 'domain': 'X'}}])
        self.assertTrue(any('different accounts' in n for n in notes))

    def test_missing_events_are_noted(self):
        self.assertTrue(any('no longer available' in n for n in ent.extract(alert())[2]))

    def test_no_host_is_noted(self):
        self.assertTrue(any('no host' in n for n in ent.extract(alert(host=None))[2]))

    def test_hostile_indicators_link_to_the_alert(self):
        items, links, _ = ent.extract(alert(), (), [{'type': 'ip', 'value': '8.8.4.4', 'verdict': 'malicious'}])
        self.assertTrue(any(e.id == 'indicator:ip:8.8.4.4' and e.note == 'malicious' for e in items))
        self.assertTrue(any(r == 'involves' for _, r, _ in links))

    def test_withheld_values_are_not_read_as_identity(self):
        doc = alert(fields={'user.domain': [{'withheld': True, 'sha256': 'x', 'length': 3}]}, domain=None)
        self.assertEqual([e.quality for e in ent.extract(doc)[0] if e.kind == 'user'], ['ambiguous'])


class Validation(unittest.TestCase):
    def test_a_good_alert_passes(self):
        doc = alert()
        self.assertEqual(schema.parse(json.dumps(doc).encode())['alert_id'], doc['alert_id'])

    def test_bad_messages_say_why(self):
        for raw, says in ((b'not json', 'not JSON'), (b'[1]', 'not an object'), (b'{}', 'missing'), (b'\xff\xfe', 'not JSON')):
            with self.assertRaisesRegex(Invalid, says):
                schema.parse(raw)

    def test_each_required_field(self):
        for name in schema.REQUIRED:
            doc = alert()
            del doc[name]
            with self.assertRaises(Invalid, msg=name):
                schema.check(doc)

    def test_bad_values(self):
        for name, value in (('severity', 'urgent'), ('alert_id', 'short'), ('timestamp', 'never'), ('event_count', 0), ('schema_version', 9), ('event_count', True), ('detected_at', 7)):
            doc = alert()
            doc[name] = value
            with self.assertRaises(Invalid, msg=name):
                schema.check(doc)

    def test_a_replayed_alert_is_cut_down_to_what_kafka_holds(self):
        doc = alert(fields={'process.command_line': ['secret text'], 'process.name': ['cmd.exe'], 'brand.new': ['x']}, facts={'note': 'text', 'count': 3})
        safe = schema.safe(doc)
        self.assertNotIn('secret text', json.dumps(safe))
        self.assertEqual(safe['evidence']['matched_fields']['process.name'], ['cmd.exe'])
        self.assertEqual(safe['evidence']['facts'], {'count': 3})


class Time(unittest.TestCase):
    def test_event_time_is_used_when_it_is_believable(self):
        self.assertEqual(schema.times(alert(at=helpers.NOW), 120000)[:2], (helpers.NOW, helpers.NOW))

    def test_a_late_alert_keeps_its_event_time(self):
        first, _, note = schema.times(alert(at=helpers.NOW, detected=helpers.NOW + 86400000), 120000)
        self.assertEqual(first, helpers.NOW)
        self.assertEqual(note, '')

    def test_a_future_event_is_not_believed(self):
        first, _, note = schema.times(alert(at=helpers.NOW + 3600000, detected=helpers.NOW), 120000)
        self.assertEqual(first, helpers.NOW)
        self.assertIn('clock is suspect', note)

    def test_small_skew_is_allowed(self):
        self.assertEqual(schema.times(alert(at=helpers.NOW + 60000, detected=helpers.NOW), 120000)[2], '')

    def test_range(self):
        self.assertEqual(schema.times(alert(at=helpers.NOW, last=helpers.NOW + 5000), 120000)[1], helpers.NOW + 5000)


if __name__ == '__main__':
    unittest.main()
