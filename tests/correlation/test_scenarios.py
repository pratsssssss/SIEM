"""The ten scenarios on synthetic fixtures, and cases that must stay separate (D9)."""
import unittest

import helpers
from helpers import (AFTER, BAD_IP, BURST, DECODED, ENCODED, GROUP, GUID_A, GUID_B, GUID_C, LOLBIN, MIN, NOW, PARENT, PORT, RUNKEY, SCHTASKS, SCRIPT, SERVICE, SPRAY, TASK, World, alert, process_event)


def only(items, rule):
    return [i for i in items if rule in [r['id'] for r in i['rules']]]


def hostile(value, kind='ip', verdict='malicious'):
    return {'status': 'complete', 'indicators': [{'type': kind, 'value': value, 'verdict': verdict, 'score': 90}]}


def signal(doc_id, domain, at=NOW, host='HOST'):
    return {'_id': doc_id, '_source': {'event_id': f'e{doc_id}', 'event_index': 'siem-windows-x', 'host': host, '@timestamp': helpers.iso(at), 'indicators': [{'type': 'domain', 'value': domain, 'verdict': 'malicious', 'score': 90}]}}


class Scenarios(unittest.TestCase):
    def setUp(self):
        self.w = World(self)

    def test_1_failed_logons_then_success(self):
        items = self.w.feed(alert(BURST, NOW, 'burst', user='victim', domain=None), alert(AFTER, NOW + MIN, 'after', user='victim', domain='ASUS', severity='high'))
        found = only(items, 'cor-logon-after-burst')
        self.assertEqual(len(found), 1)
        self.assertTrue(any('name only' in u for u in found[0]['uncertain']))

    def test_1_order_matters(self):
        self.assertEqual(only(self.w.feed(alert(AFTER, NOW, user='victim'), alert(BURST, NOW + 30 * MIN, user='victim')), 'cor-logon-after-burst'), [])

    def test_1_different_accounts_stay_apart(self):
        self.assertEqual(only(self.w.feed(alert(BURST, NOW, user='a'), alert(AFTER, NOW + MIN, user='b')), 'cor-logon-after-burst'), [])

    def test_2_password_spray_from_one_address(self):
        items = self.w.feed(alert(SPRAY, NOW, 'spray', severity='high', source_ip='203.0.114.9', fields={'source.ip': ['8.8.8.8']}, facts={'accounts': 6}))
        self.assertEqual(len(only(items, 'cor-password-spray')), 1)

    def test_2_too_few_accounts(self):
        self.assertEqual(only(self.w.feed(alert(SPRAY, NOW, fields={'source.ip': ['8.8.8.8']}, facts={'accounts': 2})), 'cor-password-spray'), [])

    def lineage(self, parent_rule, child_rule, parent=GUID_A, child_parent=GUID_A):
        first, second = alert(parent_rule, NOW, 'first'), alert(child_rule, NOW + MIN, 'second')
        self.w.opensearch.attach(first, process_event(parent, name='powershell.exe'))
        self.w.opensearch.attach(second, process_event(GUID_B, child_parent, 'bitsadmin.exe', 'powershell.exe'))
        return first, second

    def test_3_powershell_then_child(self):
        items = self.w.feed(*self.lineage(ENCODED, LOLBIN))
        found = only(items, 'cor-powershell-child')
        self.assertEqual(len(found), 1)
        self.assertIn('recorded process lineage', ' '.join(found[0]['explanation']['confidence_reasons']))

    def test_3_child_arriving_first_still_matches(self):
        first, second = self.lineage(DECODED, LOLBIN)
        self.assertEqual(len(only(self.w.feed(second, first), 'cor-powershell-child')), 1)

    def test_3_unrelated_processes_do_not_match(self):
        self.assertEqual(only(self.w.feed(*self.lineage(ENCODED, LOLBIN, GUID_A, GUID_C)), 'cor-powershell-child'), [])

    def test_4_service_then_process(self):
        second = alert(LOLBIN, NOW + MIN, 'lolbin')
        self.w.opensearch.attach(second, process_event(GUID_B, GUID_C, 'bitsadmin.exe', 'services.exe'))
        items = self.w.feed(alert(SERVICE, NOW, 'service', user=None), second)
        found = only(items, 'cor-service-then-process')
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['confidence_level'], 'low')

    def test_4_a_process_from_another_parent_is_not_linked(self):
        second = alert(LOLBIN, NOW + MIN)
        self.w.opensearch.attach(second, process_event(GUID_B, GUID_C, 'bitsadmin.exe', 'explorer.exe'))
        self.assertEqual(only(self.w.feed(alert(SERVICE, NOW, user=None), second), 'cor-service-then-process'), [])

    def test_5_task_then_process(self):
        second = alert(LOLBIN, NOW + MIN)
        self.w.opensearch.attach(second, process_event(GUID_B, GUID_C, 'bitsadmin.exe', 'svchost.exe'))
        self.assertEqual(len(only(self.w.feed(alert(TASK, NOW), second), 'cor-task-then-process')), 1)

    def test_6_same_malicious_ip(self):
        first, second = alert(SCRIPT, NOW, 'script'), alert(PORT, NOW + MIN, 'port')
        self.w.opensearch.enrichment[first['alert_id']] = hostile(BAD_IP)
        self.w.opensearch.enrichment[second['alert_id']] = hostile(BAD_IP)
        found = only(self.w.feed(first, second), 'cor-same-indicator')
        self.assertEqual(len(found), 1)
        self.assertEqual(len(found[0]['alert_ids']), 2)
        self.assertEqual(found[0]['indicators'][0]['value'], BAD_IP)

    def test_6_clean_indicators_do_not_link(self):
        first, second = alert(SCRIPT, NOW), alert(PORT, NOW + MIN)
        self.w.opensearch.enrichment[first['alert_id']] = hostile(BAD_IP, verdict='no_known_threat')
        self.w.opensearch.enrichment[second['alert_id']] = hostile(BAD_IP, verdict='no_known_threat')
        self.assertEqual(only(self.w.feed(first, second), 'cor-same-indicator'), [])

    def test_7_one_host_many_domains(self):
        self.w.opensearch.signals = [signal('a', 'one.example.com'), signal('b', 'two.example.com')]
        self.w.service.poll_signals()
        self.w.service.process()
        found = only(self.w.incidents(), 'cor-host-many-domains')
        self.assertEqual(len(found), 1)
        self.assertEqual(len(found[0]['signal_ids']), 2)

    def test_7_other_alerts_on_the_host_are_not_swept_in(self):
        self.w.feed(alert(TASK, NOW, 'unrelated'))
        self.w.opensearch.signals = [signal('a', 'one.example.com'), signal('b', 'two.example.com'), {'_id': 'c', '_source': {**signal('c', 'x')['_source'], 'indicators': [{'type': 'ip', 'value': BAD_IP, 'verdict': 'malicious', 'score': 90}]}}]
        self.w.service.poll_signals()
        self.w.service.process()
        found = only(self.w.incidents(), 'cor-host-many-domains')[0]
        self.assertEqual((found['alert_ids'], len(found['signal_ids'])), ([], 2))

    def test_7_every_hostile_indicator_of_one_event_is_kept(self):
        both = {'_id': 'a', '_source': {**signal('a', 'one.example.com')['_source'], 'indicators': [{'type': 'domain', 'value': d, 'verdict': 'malicious', 'score': 90} for d in ('one.example.com', 'two.example.com')]}}
        self.w.opensearch.signals = [both]
        self.w.service.poll_signals()
        self.assertEqual(self.w.store.counts()['pending'], 2)

    def test_7_one_domain_twice_is_not_many(self):
        self.w.opensearch.signals = [signal('a', 'one.example.com'), signal('b', 'one.example.com')]
        self.w.service.poll_signals()
        self.w.service.process()
        self.assertEqual(only(self.w.incidents(), 'cor-host-many-domains'), [])

    def test_7_two_hosts_are_not_one_host(self):
        self.w.opensearch.signals = [signal('a', 'one.example.com', host='A'), signal('b', 'two.example.com', host='B')]
        self.w.service.poll_signals()
        self.w.service.process()
        self.assertEqual(only(self.w.incidents(), 'cor-host-many-domains'), [])

    def test_8_one_domain_account_on_two_hosts(self):
        found = only(self.w.feed(alert(TASK, NOW, host='ONE', user='admin', domain='CORP'), alert(RUNKEY, NOW + MIN, host='TWO', user='admin', domain='CORP')), 'cor-user-many-hosts')
        self.assertEqual(len(found), 1)
        self.assertEqual(sorted(found[0]['hosts']), ['one', 'two'])

    def test_8_local_accounts_with_one_name_are_different_people(self):
        self.assertEqual(only(self.w.feed(alert(TASK, NOW, host='ONE', user='admin', domain='ONE'), alert(RUNKEY, NOW + MIN, host='TWO', user='admin', domain='TWO')), 'cor-user-many-hosts'), [])

    def test_8_a_bare_name_cannot_link_hosts(self):
        self.assertEqual(only(self.w.feed(alert(TASK, NOW, host='ONE', user='admin', domain=None), alert(RUNKEY, NOW + MIN, host='TWO', user='admin', domain=None)), 'cor-user-many-hosts'), [])

    def test_8_system_cannot_link_hosts(self):
        self.assertEqual(only(self.w.feed(alert(TASK, NOW, host='ONE', user='SYSTEM', domain='NT AUTHORITY'), alert(RUNKEY, NOW + MIN, host='TWO', user='SYSTEM', domain='NT AUTHORITY')), 'cor-user-many-hosts'), [])

    def test_9_privilege_then_administrative_activity(self):
        self.assertEqual(len(only(self.w.feed(alert(GROUP, NOW, 'group', severity='high'), alert(SCHTASKS, NOW + 5 * MIN, 'schtasks')), 'cor-privilege-then-admin')), 1)

    def test_9_another_account_is_not_linked(self):
        self.assertEqual(only(self.w.feed(alert(GROUP, NOW), alert(SCHTASKS, NOW + MIN, user='other')), 'cor-privilege-then-admin'), [])

    def test_9_outside_the_window(self):
        self.assertEqual(only(self.w.feed(alert(GROUP, NOW), alert(SCHTASKS, NOW + 61 * MIN)), 'cor-privilege-then-admin'), [])

    def test_10_multi_stage(self):
        found = only(self.w.feed(alert(ENCODED, NOW, 'a', tactics=('execution',)), alert(RUNKEY, NOW + MIN, 'b', tactics=('persistence',)), alert(SCRIPT, NOW + 2 * MIN, 'c', tactics=('command_and_control',))), 'cor-multi-stage')
        self.assertEqual(len(found), 1)
        self.assertEqual(len(found[0]['explanation']['sequence']), 3)

    def test_10_repeats_of_one_rule_are_not_stages(self):
        self.assertEqual(only(self.w.feed(alert(RUNKEY, NOW, tactics=('persistence', 'execution', 'stealth')), alert(RUNKEY, NOW + MIN, tactics=('persistence', 'execution', 'stealth'))), 'cor-multi-stage'), [])

    def test_10_rules_on_one_event_are_not_stages(self):
        a, b = alert(ENCODED, NOW, tactics=('execution',)), alert(RUNKEY, NOW + MIN, tactics=('persistence',))
        c = alert(SCRIPT, NOW + 2 * MIN, tactics=('command_and_control',))
        c['source_event_ids'] = list(b['source_event_ids'])
        self.assertEqual(only(self.w.feed(a, b, c), 'cor-multi-stage'), [])

    def test_10_two_tactics_are_not_enough(self):
        self.assertEqual(only(self.w.feed(alert(ENCODED, NOW, tactics=('execution',)), alert(RUNKEY, NOW + MIN, tactics=('persistence',))), 'cor-multi-stage'), [])


class StaySeparate(unittest.TestCase):
    """D9 warns that unrelated activity on a shared entity can merge. This lab is one host, so it matters."""

    def setUp(self):
        self.w = World(self)

    def test_unrelated_alerts_on_one_host_make_no_incident(self):
        self.assertEqual(self.w.feed(alert(TASK, NOW, user='a'), alert(SCRIPT, NOW + MIN, user='b')), [])

    def test_two_users_keep_two_incidents(self):
        items = self.w.feed(alert(GROUP, NOW, user='a'), alert(SCHTASKS, NOW + MIN, user='a'), alert(GROUP, NOW + 2 * MIN, user='b'), alert(SCHTASKS, NOW + 3 * MIN, user='b'))
        self.assertEqual(len(only(items, 'cor-privilege-then-admin')), 2)

    def test_two_activities_far_apart_stay_separate(self):
        items = self.w.feed(alert(GROUP, NOW), alert(SCHTASKS, NOW + MIN), alert(GROUP, NOW + 300 * MIN), alert(SCHTASKS, NOW + 301 * MIN))
        self.assertEqual(len(only(items, 'cor-privilege-then-admin')), 2)

    def test_a_shared_host_alone_never_builds_a_chain(self):
        items = self.w.feed(alert(ENCODED, NOW, user='a', tactics=('execution',)), alert(RUNKEY, NOW + MIN, user='b', tactics=('persistence',)), alert(SCRIPT, NOW + 2 * MIN, user='c', tactics=('command_and_control',)))
        self.assertEqual(only(items, 'cor-multi-stage'), [])


class Time(unittest.TestCase):
    def setUp(self):
        self.w = World(self)

    def test_out_of_order_arrival_still_matches(self):
        late, early = alert(SCHTASKS, NOW + 5 * MIN), alert(GROUP, NOW)
        self.assertEqual(len(only(self.w.feed(late, early), 'cor-privilege-then-admin')), 1)

    def test_a_much_later_arrival_still_matches(self):
        self.w.feed(alert(GROUP, NOW))
        self.w.now[0] += 2 * 3600000
        self.assertEqual(len(only(self.w.feed(alert(SCHTASKS, NOW + 5 * MIN, detected=NOW + 2 * 3600000)), 'cor-privilege-then-admin')), 1)

    def test_one_host_has_one_clock_so_its_order_is_known(self):
        items = only(self.w.feed(alert(GROUP, NOW), alert(SCHTASKS, NOW + 30000)), 'cor-privilege-then-admin')
        self.assertFalse(any('order is not proven' in u for u in items[0]['uncertain']))

    def test_an_alert_spanning_the_earlier_one_but_ending_later_has_a_known_order(self):
        items = only(self.w.feed(alert(GROUP, NOW, last=NOW + MIN), alert(SCHTASKS, NOW, last=NOW + 2 * MIN)), 'cor-privilege-then-admin')
        self.assertFalse(any('order is not proven' in u for u in items[0]['uncertain']))

    def test_within_clock_skew_between_hosts_the_order_is_uncertain(self):
        items = only(self.w.feed(alert(GROUP, NOW, host='ONE'), alert(SCHTASKS, NOW + 30000, host='TWO')), 'cor-privilege-then-admin')
        self.assertEqual(len(items), 1)
        self.assertTrue(any('order is not proven' in u for u in items[0]['uncertain']))
        self.assertTrue(any('order is not proven' in r for r in items[0]['explanation']['confidence_reasons']))

    def test_slightly_reversed_inside_the_skew_still_matches_as_uncertain(self):
        items = only(self.w.feed(alert(GROUP, NOW), alert(SCHTASKS, NOW - 60000)), 'cor-privilege-then-admin')
        self.assertEqual(len(items), 1)
        self.assertTrue(any('order is not proven' in u for u in items[0]['uncertain']))

    def test_clearly_reversed_order_is_no_match(self):
        self.assertEqual(only(self.w.feed(alert(GROUP, NOW), alert(SCHTASKS, NOW - 10 * MIN)), 'cor-privilege-then-admin'), [])

    def test_an_impossible_timestamp_is_flagged(self):
        items = only(self.w.feed(alert(GROUP, NOW + 3600000, detected=NOW), alert(SCHTASKS, NOW + MIN)), 'cor-privilege-then-admin')
        self.assertTrue(items and any('clock is suspect' in u for u in items[0]['uncertain']))

    def test_timestamps_establishing_the_order_are_kept(self):
        found = only(self.w.feed(alert(GROUP, NOW, 'first'), alert(SCHTASKS, NOW + 5 * MIN, 'second')), 'cor-privilege-then-admin')[0]
        self.assertEqual(found['explanation']['sequence'], [f'first at {helpers.iso(NOW)}', f'second at {helpers.iso(NOW + 5 * MIN)}'])


LINUX_BURST = 'd3b07a10-5c1e-4f6a-9b2c-0e1f2a3b4c08'
LINUX_SUDO = 'd3b07a10-5c1e-4f6a-9b2c-0e1f2a3b4c02'
LINUX_GROUP = 'd3b07a10-5c1e-4f6a-9b2c-0e1f2a3b4c04'


class LinuxHost(unittest.TestCase):
    def setUp(self):
        self.w = World(self)

    def test_privileged_group_is_an_incident_on_its_own(self):
        found = only(self.w.feed(alert(LINUX_GROUP, NOW, 'group', severity='high', host='host-wsl', user=None, domain=None)), 'cor-linux-privileged-account')
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['hosts'], ['host-wsl'])

    def test_burst_then_sudo_links_by_name_only(self):
        found = only(self.w.feed(alert(LINUX_BURST, NOW, 'burst', host='host-wsl', user='alice', domain=None), alert(LINUX_SUDO, NOW + MIN, 'sudo', host='host-wsl', user='alice', domain=None, severity='low')), 'cor-linux-auth-burst-then-sudo')
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['rules'][0]['join'], 'user_name')

    def test_sudo_before_the_burst_is_not_a_sequence(self):
        found = only(self.w.feed(alert(LINUX_SUDO, NOW, 'sudo', host='host-wsl', user='alice', domain=None, severity='low'), alert(LINUX_BURST, NOW + 20 * MIN, 'burst', host='host-wsl', user='alice', domain=None)), 'cor-linux-auth-burst-then-sudo')
        self.assertEqual(found, [])

    def test_a_shared_name_across_windows_and_linux_links_nothing(self):
        items = self.w.feed(alert(BURST, NOW, 'windows burst', host='ASUS', user='alice', domain=None), alert(LINUX_SUDO, NOW + MIN, 'linux sudo', host='asus-wsl', user='alice', domain=None, severity='low'))
        self.assertEqual(only(items, 'cor-linux-auth-burst-then-sudo'), [])
        self.assertEqual(only(items, 'cor-logon-after-burst'), [])


if __name__ == '__main__':
    unittest.main()
