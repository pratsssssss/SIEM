"""Reconstruction on synthetic fixtures. The ten validation scenarios are named in the class Scenarios."""
import json
import unittest

from helpers import HOUR, LIN, MIN, NOW, WIN, WIN2, alert, assets, edges, hit, linuxevent, seed, stages, winevent
from siem_path import engine, model
from siem_path.engine import Assets, build
from siem_path.evidence import fact_evidence, to_fact
from siem_path.model import CONFIRMED, INSUFFICIENT, PLAUSIBLE, STRONG, TIERS, Evidence, Graph


def failures(n=4, start=NOW, **fields):
    return [hit(winevent(4625, start + i * MIN, **fields)) for i in range(n)]


class Model(unittest.TestCase):
    def test_an_edge_needs_evidence(self):
        graph = Graph()
        a, b = graph.node('asset', 'a'), graph.node('asset', 'b')
        self.assertIsNone(graph.edge(a, 'triggered', b, 'observed', 'observed', CONFIRMED, [], 'nothing behind it'))
        self.assertIsNone(graph.edge(None, 'triggered', b, 'observed', 'observed', CONFIRMED, [Evidence('event', 'x', 'i', model.iso(NOW))], 'r'))
        self.assertEqual(graph.edges, {})

    def test_ids_are_stable(self):
        one, two = Graph(), Graph()
        self.assertEqual(one.node('asset', 'a'), two.node('asset', 'a'))
        self.assertNotEqual(one.node('asset', 'a'), one.node('identity', 'a'))

    def test_repeat_evidence_merges_into_one_edge(self):
        graph = Graph()
        a, b = graph.node('asset', 'a'), graph.node('asset', 'b')
        for at, ref in ((NOW, 'one'), (NOW + MIN, 'two'), (NOW, 'one')):
            graph.edge(a, 'triggered', b, 'observed', 'observed', CONFIRMED, [Evidence('event', ref, 'i', model.iso(at))], 'r')
        edge = next(iter(graph.edges.values()))
        self.assertEqual((len(graph.edges), len(edge['evidence'])), (1, 2))
        self.assertEqual((edge['first_ms'], edge['last_ms']), (NOW, NOW + MIN))

    def test_merged_edge_keeps_the_weaker_tier(self):
        graph = Graph()
        a, b = graph.node('asset', 'a'), graph.node('asset', 'b')
        graph.edge(a, 'triggered', b, 'observed', 'observed', CONFIRMED, [Evidence('event', '1', 'i', model.iso(NOW))], 'r')
        graph.edge(a, 'triggered', b, 'observed', 'observed', PLAUSIBLE, [Evidence('event', '2', 'i', model.iso(NOW))], 'r')
        self.assertEqual(next(iter(graph.edges.values()))['tier'], PLAUSIBLE)

    def test_limits_stop_growth_and_are_counted(self):
        graph = Graph(max_nodes=2, max_edges=1)
        nodes = [graph.node('asset', str(n)) for n in range(4)]
        self.assertEqual(nodes[2:], [None, None])
        graph.edge(nodes[0], 'triggered', nodes[1], 'o', 'o', CONFIRMED, [Evidence('event', '1', 'i', model.iso(NOW))], 'r')
        self.assertIsNone(graph.edge(nodes[1], 'triggered', nodes[0], 'o', 'o', CONFIRMED, [Evidence('event', '2', 'i', model.iso(NOW))], 'r'))
        self.assertEqual(graph.cut, 3)

    def test_event_references_reach_event_indices_only(self):
        self.assertEqual(model.event_ref('siem-windows-2026.10.31/abcdefgh12'), ('siem-windows-2026.10.31', 'abcdefgh12'))
        self.assertEqual(model.event_ref('siem-linux-2026.10.31/abcdefgh12')[0], 'siem-linux-2026.10.31')
        for bad in ('.opendistro_security/abcdefgh12', 'siem-incidents-2026.10/abcdefgh12', 'siem-windows-*/abcdefgh12', '../_cluster/settings', 'siem-windows-2026.10.31/a b', 'siem-windows-2026.10.31/x?y=1', 'siem-windows-2026.10.31,siem-alerts-2026.10/abcdefgh12', '', None, 5):
            self.assertIsNone(model.event_ref(bad), bad)

    def test_clean_removes_controls_and_credentials(self):
        self.assertEqual(model.clean('a\x1b[2J‮b'), 'a[2Jb')
        self.assertNotIn('hunter2', model.clean('x password=hunter2'))
        self.assertEqual(model.clean({'a': 1}), '')


class Identities(unittest.TestCase):
    def test_a_windows_account_has_a_domain(self):
        self.assertEqual(model.windows_identity('Alice', 'LAB').id, 'identity:windows:lab\\alice')
        self.assertEqual(model.windows_identity('LAB\\alice').id, 'identity:windows:lab\\alice')

    def test_a_bare_name_is_ambiguous(self):
        self.assertEqual(model.windows_identity('alice').quality, 'ambiguous')

    def test_service_accounts_link_nothing(self):
        for name, realm in (('SYSTEM', 'NT AUTHORITY'), ('HOST$', 'LAB'), ('LOCAL SERVICE', None), ('-', None), ('DWM-1', 'Window Manager')):
            self.assertFalse(model.windows_identity(name, realm).links, name)

    def test_the_null_sid_of_a_failed_logon_is_not_a_service_account(self):
        self.assertTrue(model.windows_identity('alice', 'LAB', 'S-1-0-0').links)

    def test_a_linux_account_belongs_to_its_host(self):
        self.assertNotEqual(model.linux_identity('root', 'a-wsl').id, model.linux_identity('root', 'b-wsl').id)

    def test_the_same_name_on_two_platforms_is_two_identities(self):
        self.assertNotEqual(model.windows_identity('alice', 'LAB').id, model.linux_identity('alice', 'host').id)


class Facts(unittest.TestCase):
    def test_platforms_reach_the_same_kinds(self):
        self.assertEqual(to_fact('i', 'e', winevent(4624)).kind, 'auth_success')
        self.assertEqual(to_fact('i', 'e', linuxevent('ssh-login')).kind, 'auth_success')
        self.assertEqual(to_fact('i', 'e', winevent(4720)).kind, to_fact('i', 'e', linuxevent('user-created')).kind)

    def test_unverified_linux_entries_are_no_facts(self):
        self.assertIsNone(to_fact('i', 'e', linuxevent('sudo-command', attribution='unverified')))
        self.assertIsNone(to_fact('i', 'e', linuxevent('unverified-log-entry')))

    def test_process_name_attribution_is_kept(self):
        self.assertEqual(to_fact('i', 'e', linuxevent('crontab-replaced', attribution='process-name')).attribution, 'process-name')

    def test_a_malformed_event_is_no_fact(self):
        self.assertIsNone(to_fact('i', 'e', {'event': {'dataset': 'windows.security', 'code': '4624'}}))
        self.assertIsNone(to_fact('i', 'e', {**winevent(4624), '@timestamp': 'never'}))
        self.assertIsNone(to_fact('i', 'e', winevent(9999)))

    def test_evidence_copies_named_fields_only(self):
        doc = winevent(4624, source={'ip': '192.0.2.1'}, message='secret text', process={'command_line': 'tool --password x'})
        record = fact_evidence(to_fact('siem-windows-2026.11.01', 'e', doc)).as_dict()
        text = json.dumps(record)
        self.assertNotIn('secret text', text)
        self.assertNotIn('command_line', text)
        for key in ('id', 'index', 'source_time', 'ingest_time', 'host', 'sensor', 'provenance', 'kind', 'digest'):
            self.assertIn(key, record)


class Scenarios(unittest.TestCase):
    def test_1_failures_then_success(self):
        cited = failures() + [hit(winevent(4624, NOW + 5 * MIN))]
        path = build(seed(cited), assets())
        stage = stages(path, 'failures_then_success')[0]
        self.assertEqual(stage['techniques'][0]['id'], 'T1110')
        self.assertEqual(stage['tier'], CONFIRMED)
        self.assertEqual(path['tier'], CONFIRMED)
        self.assertIn('compromise', path['conclusion'])
        self.assertTrue(path['conclusion'].startswith('none'))

    def test_1_the_same_rule_works_on_linux(self):
        cited = [hit(linuxevent('ssh-login-failed', NOW + i * MIN, source={'ip': '192.0.2.7'})) for i in range(4)] + [hit(linuxevent('ssh-login', NOW + 5 * MIN, source={'ip': '192.0.2.7'}))]
        path = build(seed(cited, host='host-b-wsl'), assets())
        self.assertEqual(len(stages(path, 'failures_then_success')), 1)
        self.assertEqual(path['attack_sources'][0]['display'], '192.0.2.7')
        self.assertEqual(edges(path, 'access_attempt_from')[0]['tier'], STRONG)

    def test_1_too_few_failures_is_no_guessing(self):
        path = build(seed(failures(2) + [hit(winevent(4624, NOW + 3 * MIN))]), assets())
        self.assertEqual(stages(path, 'failures_then_success'), [])

    def test_1_success_before_failures_is_not_a_sequence(self):
        path = build(seed([hit(winevent(4624, NOW))] + failures(4, NOW + MIN)), assets())
        self.assertEqual(stages(path, 'failures_then_success'), [])
        self.assertTrue(any('before the failures' in c['text'] for c in path['contradictions']))

    def test_1_failures_too_long_before_are_not_joined(self):
        path = build(seed(failures(4) + [hit(winevent(4624, NOW + 2 * HOUR))]), assets())
        self.assertEqual(stages(path, 'failures_then_success'), [])

    def test_2_privilege_change_then_activity(self):
        cited = [hit(linuxevent('sudo-command', NOW, user={'name': 'alice', 'effective': {'name': 'root'}})), hit(linuxevent('crontab-replaced', NOW + MIN, user='root', attribution='process-name'))]
        path = build(seed(cited, host='host-b-wsl'), assets())
        stage = stages(path, 'identity_transition')[0]
        self.assertEqual(stage['techniques'][0]['id'], 'T1548.003')
        self.assertEqual(edges(path, 'escalated_privileges')[0]['basis'], 'observed')
        self.assertEqual(stages(path, 'cron_changed')[0]['tier'], STRONG)
        self.assertEqual(path['tier'], STRONG)

    def test_3_new_account_then_used(self):
        cited = [hit(winevent(4720, NOW, user={'name': 'admin', 'domain': 'LAB', 'target': {'name': 'mallory', 'domain': 'LAB'}})), hit(winevent(4624, NOW + MIN, user='mallory'))]
        path = build(seed(cited), assets())
        self.assertEqual(stages(path, 'account_created')[0]['techniques'][0]['id'], 'T1136.001')
        self.assertEqual(stages(path, 'new_account_used')[0]['techniques'][0]['id'], 'T1078.003')

    def test_3_a_new_account_with_the_name_on_another_asset_is_not_use(self):
        cited = [hit(winevent(4720, NOW, user={'name': 'admin', 'domain': 'LAB', 'target': {'name': 'mallory', 'domain': 'LAB'}})), hit(winevent(4624, NOW + MIN, host='host-c', user='mallory'))]
        path = build(seed(cited), assets(WIN, WIN2))
        self.assertEqual(stages(path, 'new_account_used'), [])

    def test_4_service_and_task_changes(self):
        cited = [hit(winevent(7045, NOW, dataset='windows.system', user=None, service={'name': 'Odd'})), hit(winevent(4698, NOW + MIN))]
        path = build(seed(cited), assets())
        self.assertEqual(stages(path, 'service_installed')[0]['techniques'][0]['id'], 'T1543.003')
        self.assertEqual(stages(path, 'task_created')[0]['techniques'][0]['id'], 'T1053.005')
        self.assertEqual(path['attack_sources'], [])

    def test_5_linux_sudo_and_group(self):
        cited = [hit(linuxevent('group-member-added', NOW, user={'target': {'name': 'bob'}}, group={'name': 'sudo'}))]
        path = build(seed(cited, host='host-b-wsl'), assets())
        self.assertEqual(stages(path, 'privileged_group_change')[0]['techniques'][0]['id'], 'T1098')
        self.assertEqual(edges(path, 'added_to_group')[0]['basis'], 'observed')

    def test_6_windows_process_lineage_is_recorded_by_guid(self):
        cited = [hit(winevent(1, dataset='windows.sysmon', process={'entity_id': '{a}', 'name': 'cmd.exe', 'parent': {'entity_id': '{b}', 'name': 'x.exe'}}))]
        path = build(seed(cited), assets())
        self.assertEqual(len(edges(path, 'spawned')), 1)
        self.assertEqual(len(edges(path, 'executed')), 1)

    def test_7_same_name_across_platforms_links_nothing(self):
        windows = [hit(winevent(4624, NOW, user='alice'))]
        path = build(seed(windows, context=[hit(linuxevent('sudo-command', NOW + MIN, host='host-a', user='alice'))]), assets())
        self.assertEqual([e for e in path['edges'] if 'host-b' in json.dumps(e)], [])
        self.assertEqual(path['excluded_unrelated_events'], 1)
        self.assertEqual(edges(path, 'same_identity'), [])

    def test_7_a_person_can_state_a_cross_platform_link(self):
        windows = hit(winevent(4624, NOW, user='alice'))
        linux = hit(linuxevent('sudo-command', NOW + MIN, user={'name': 'alice', 'effective': {'name': 'root'}}))
        a, b = model.windows_identity('alice', 'LAB').id, model.linux_identity('alice', 'host-b-wsl').id
        link = {'id': 'l', 'a': a, 'b': b, 'actor': 'carol', 'reason': 'one person, per HR', 'at_ms': NOW}
        path = build(seed([windows, linux], links=[link]), assets())
        edge = edges(path, 'same_identity')[0]
        self.assertEqual((edge['class'], edge['basis']), ('analyst', 'inferred'))
        self.assertEqual(edge['evidence'][0]['provenance'], 'analyst:carol')

    def test_7_lateral_movement_needs_the_address_held_by_an_asset_then(self):
        event = hit(winevent(4624, NOW, host='host-a', source={'ip': '10.0.0.5'}, winlog={'logon': {'type': '3'}}))
        path = build(seed([event]), Assets((WIN, WIN2), lambda ip, at: ['ast-win2']))
        edge = edges(path, 'remote_access_from')[0]
        self.assertEqual((edge['basis'], edge['tier']), ('inferred', PLAUSIBLE))
        self.assertEqual(path['attack_sources'][0]['display'], 'host-c')
        self.assertEqual(stages(path, 'remote_access_between_assets')[0]['techniques'], [])

    def test_7_rdp_gets_its_technique_and_a_console_logon_is_not_lateral(self):
        rdp = hit(winevent(4624, NOW, source={'ip': '10.0.0.5'}, winlog={'logon': {'type': '10'}}))
        path = build(seed([rdp]), Assets((WIN, WIN2), lambda ip, at: ['ast-win2']))
        self.assertEqual(stages(path, 'remote_access_between_assets')[0]['techniques'][0]['id'], 'T1021.001')
        console = hit(winevent(4624, NOW, source={'ip': '10.0.0.5'}, winlog={'logon': {'type': '2'}}))
        path = build(seed([console]), Assets((WIN, WIN2), lambda ip, at: ['ast-win2']))
        self.assertEqual(edges(path, 'remote_access_from'), [])

    def test_7_an_address_shared_over_time_resolves_to_nobody(self):
        event = hit(winevent(4624, NOW, source={'ip': '10.0.0.5'}, winlog={'logon': {'type': '3'}}))
        path = build(seed([event]), Assets((WIN, WIN2), lambda ip, at: ['ast-win2', 'ast-win']))
        self.assertEqual(edges(path, 'remote_access_from'), [])
        self.assertIn('source_not_observed', [g['gap'] for g in path['gaps']])

    def test_8_linux_paths_state_what_cannot_be_seen(self):
        path = build(seed([hit(linuxevent('sudo-command', user={'name': 'a', 'effective': {'name': 'root'}}))], host='host-b-wsl'), assets())
        gaps = [g['gap'] for g in path['gaps']]
        self.assertIn('linux_process_execution', gaps)
        self.assertIn('linux_network', gaps)
        self.assertEqual(edges(path, 'spawned'), [])
        self.assertEqual(edges(path, 'executed'), [])
        self.assertTrue(any('Inspect the Linux host' in s for s in path['next_steps']))

    def test_8_a_host_with_no_record_stays_unresolved(self):
        path = build(seed([hit(winevent(4624, host='unknown-host'))], host='unknown-host'), assets())
        self.assertFalse(path['affected_assets'][0]['resolved'])
        self.assertIn('asset_unknown', [g['gap'] for g in path['gaps']])
        self.assertEqual(path['tier'], STRONG)

    def test_8_missing_events_lower_the_path(self):
        path = build(seed([hit(winevent(4624))], missing=['siem-windows-2026.10.20/abcdefghij']), assets())
        self.assertIn('evidence_missing', [g['gap'] for g in path['gaps']])
        self.assertEqual(path['tier'], PLAUSIBLE)

    def test_8_a_detection_with_no_events_is_not_an_observation(self):
        item = alert([], host='host-a')
        path = build(seed([], alerts=[item], missing=['siem-windows-2026.10.20/abcdefghij']), assets())
        self.assertEqual(path['tier'], PLAUSIBLE)
        self.assertEqual(edges(path, 'detected_on')[0]['tier'], PLAUSIBLE)

    def test_8_nothing_at_all_is_insufficient(self):
        self.assertEqual(build(seed([], alerts=[]), assets())['tier'], INSUFFICIENT)

    def test_9_analyst_false_positive_lowers_the_path(self):
        cited = [hit(winevent(4624))]
        self.assertEqual(TIERS.index(build(seed(cited, status='false_positive'), assets())['tier']), TIERS.index(build(seed(cited), assets())['tier']) + 1)

    def test_9_failures_and_success_from_different_addresses_lower_the_path(self):
        cited = failures(4, source={'ip': '192.0.2.1'}) + [hit(winevent(4624, NOW + 5 * MIN, source={'ip': '198.51.100.9'}))]
        path = build(seed(cited), assets())
        self.assertTrue(any('different one' in c['text'] for c in path['contradictions']))
        self.assertEqual(path['tier'], STRONG)

    def test_9_conflicting_intelligence_is_noted_and_proves_nothing(self):
        item_hit = hit(winevent(4624))
        item = alert([item_hit])
        doc = ('d', 'siem-enrichment-2026.11', {'alert_id': item['alert_id'], 'indicators': [{'type': 'ip', 'value': '192.0.2.1', 'verdict': 'conflicting', 'score': 50}, {'type': 'ip', 'value': '192.0.2.2', 'verdict': 'clean', 'score': 0}]})
        path = build(seed([item_hit], alerts=[item], intelligence=[doc]), assets())
        edge = edges(path, 'associated_with')[0]
        self.assertEqual((edge['class'], edge['tier'], len(edges(path, 'associated_with'))), ('threat_intelligence', PLAUSIBLE, 1))
        self.assertEqual(path['tier'], CONFIRMED)

    def test_9_a_retired_asset_lowers_the_path(self):
        retired = {**WIN, 'status': 'retired'}
        self.assertEqual(build(seed([hit(winevent(4624))]), assets(retired))['tier'], STRONG)

    def test_9_two_assets_with_one_name_are_left_unresolved(self):
        twin = {**WIN2, 'aliases': ['host-a']}
        path = build(seed([hit(winevent(4624))]), assets(WIN, twin))
        self.assertTrue(any('hold the name' in c['text'] for c in path['contradictions']))
        self.assertFalse(path['affected_assets'][0]['resolved'])

    def test_10_activity_by_another_account_is_left_out(self):
        cited = [hit(winevent(4624, user='alice'))]
        context = [hit(winevent(4720, NOW + MIN, user={'name': 'carol', 'domain': 'LAB', 'target': {'name': 'dave', 'domain': 'LAB'}})), hit(winevent(7045, NOW + MIN, dataset='windows.system', user=None, service={'name': 'Unrelated'}))]
        path = build(seed(cited, context=context), assets())
        self.assertEqual(stages(path, 'account_created'), [])
        self.assertEqual(stages(path, 'service_installed'), [])
        self.assertEqual(path['excluded_unrelated_events'], 2)

    def test_10_time_alone_joins_nothing_however_close(self):
        cited = [hit(winevent(4624, NOW, user='alice'))]
        context = [hit(winevent(4624, NOW + 1, user='carol'))]
        path = build(seed(cited, context=context), assets())
        self.assertEqual(len(path['identities']), 1)

    def test_10_a_service_account_links_nothing(self):
        cited = [hit(winevent(4624, NOW, user='SYSTEM', domain='NT AUTHORITY', sid='S-1-5-18'))]
        context = [hit(winevent(4698, NOW + MIN, user='SYSTEM', domain='NT AUTHORITY', sid='S-1-5-18'))]
        path = build(seed(cited, context=context), assets())
        self.assertEqual(stages(path, 'task_created'), [])

    def test_10_root_joins_nothing_because_it_is_every_administrator(self):
        ran = hit(linuxevent('sudo-command', NOW, user={'name': 'alice', 'effective': {'name': 'root'}}))
        other = hit(linuxevent('sudo-command', NOW + MIN, user={'name': 'bob', 'effective': {'name': 'root'}}))
        path = build(seed([ran], context=[other], host='host-b-wsl'), assets())
        self.assertEqual(path['excluded_unrelated_events'], 1)
        self.assertEqual(len(edges(path, 'escalated_privileges')), 1)

    def test_10_a_same_identity_event_on_another_host_is_left_out(self):
        cited = [hit(winevent(4624, host='host-a'))]
        path = build(seed(cited, context=[hit(winevent(4624, NOW + MIN, host='host-c'))]), assets(WIN, WIN2))
        self.assertEqual(path['excluded_unrelated_events'], 1)


class Tiers(unittest.TestCase):
    def test_a_service_account_links_nothing_and_its_event_is_still_an_observation(self):
        path = build(seed([hit(winevent(1, dataset='windows.sysmon', user='SYSTEM', domain='NT AUTHORITY', sid='S-1-5-18', process={'entity_id': '{a}', 'name': 'x.exe', 'parent': {'entity_id': '{b}', 'name': 'y.exe'}}))]), assets())
        self.assertEqual(edges(path, 'spawned')[0]['tier'], CONFIRMED)

    def test_a_service_install_names_no_actor_and_is_still_an_observation(self):
        path = build(seed([hit(winevent(7045, dataset='windows.system', user=None, service={'name': 'x'}))]), assets())
        self.assertEqual(edges(path, 'installed')[0]['tier'], CONFIRMED)

    def test_rationale_names_only_what_changed_the_tier(self):
        path = build(seed([], alerts=[alert([], host='unknown')], missing=['siem-windows-2026.10.20/abcdefghij'], host='unknown'), assets())
        self.assertEqual(path['tier'], PLAUSIBLE)
        self.assertFalse([r for r in path['rationale'] if r.startswith('Capped')])

    def test_an_ambiguous_account_is_not_confirmed(self):
        path = build(seed([hit(winevent(4625, domain=None, sid=None))]), assets())
        self.assertEqual(edges(path, 'failed_authentication_to')[0]['tier'], STRONG)

    def test_tactic_names_are_one_form(self):
        item_hit = hit(winevent(4624))
        path = build(seed([item_hit], alerts=[alert([item_hit], tactics=['credential_access'])]), assets())
        self.assertEqual(stages(path, 'detection')[0]['tactic'], 'credential-access')


class Behaviour(unittest.TestCase):
    def test_the_same_evidence_gives_the_same_path(self):
        cited = failures() + [hit(winevent(4624, NOW + 5 * MIN))]
        item = alert(cited)
        first, second = build(seed(cited, alerts=[item]), assets()), build(seed(cited, alerts=[item]), assets())
        self.assertEqual(first['fingerprint'], second['fingerprint'])
        self.assertEqual(first['edges'], second['edges'])

    def test_source_affected_and_sensor_stay_three_things(self):
        cited = failures(4, source={'ip': '192.0.2.1'}) + [hit(winevent(4624, NOW + 5 * MIN, source={'ip': '192.0.2.1'}))]
        path = build(seed(cited), assets())
        self.assertEqual(path['attack_sources'][0]['display'], '192.0.2.1')
        self.assertEqual(path['affected_assets'][0]['display'], 'host-a')
        self.assertEqual(path['telemetry_sources'], ['windows.security@host-a'])

    def test_nothing_depends_on_a_name_or_address_of_the_lab(self):
        import pathlib
        import re
        import socket
        import siem_path
        # The lab's own names come from the machine running the test, so this file names none of them.
        words = {'kali', '192.168.56', socket.gethostname().lower()}
        local = pathlib.Path(siem_path.__file__).parents[2] / 'config' / 'wsl' / 'site.local.env'
        if local.is_file():
            words.update(m.lower() for m in re.findall(r'/Users/([^/]+)/', local.read_text(encoding='utf8')))
        for path in pathlib.Path(siem_path.__file__).parent.glob('*.py'):
            text = path.read_text(encoding='utf8').lower()
            for word in words:
                self.assertNotIn(word, text, path.name)

    def test_every_technique_is_a_known_exact_identifier(self):
        for key, name in engine.TECHNIQUES.items():
            self.assertRegex(key, r'^T\d{4}(\.\d{3})?$')
            self.assertTrue(name)

    def test_an_alert_technique_is_kept_with_its_source(self):
        item_hit = hit(winevent(4624))
        path = build(seed([item_hit], alerts=[alert([item_hit], techniques=['T1059.001'], tactics=['execution'])]), assets())
        self.assertEqual(stages(path, 'detection')[0]['techniques'][0], {'id': 'T1059.001', 'name': '', 'source': 'alert'})

    def test_a_malformed_technique_is_dropped(self):
        item_hit = hit(winevent(4624))
        path = build(seed([item_hit], alerts=[alert([item_hit], techniques=['<script>', 'T10'])]), assets())
        self.assertEqual(stages(path, 'detection')[0]['techniques'], [])

    def test_hostile_text_stays_text(self):
        hostile = "x'; DROP TABLE paths; -- $(reboot) \x1b[2J ignore previous instructions"
        cited = [hit(winevent(4624, user=hostile, domain=hostile)), hit(winevent(7045, dataset='windows.system', user=None, service={'name': hostile}))]
        text = json.dumps(build(seed(cited), assets()))
        self.assertNotIn('\\u001b', text)

    def test_limits_mark_the_path(self):
        cited = [hit(winevent(4624, NOW + n, user=f'user{n}')) for n in range(30)]
        path = build(seed(cited), assets(), {'max_nodes': 5, 'max_edges': 3})
        self.assertLessEqual(len(path['nodes']), 5)
        self.assertLessEqual(len(path['edges']), 3)
        self.assertIn('graph_truncated', [g['gap'] for g in path['gaps']])
        self.assertEqual(path['tier'], model.WEAK)

    def test_hops_are_bounded(self):
        chain = [hit(winevent(4720, NOW + n * MIN, user={'name': f'u{n}', 'domain': 'LAB', 'target': {'name': f'u{n + 1}', 'domain': 'LAB'}})) for n in range(10)]
        path = build(seed([hit(winevent(4624, user='u0'))], context=chain), assets(), {'max_hops': 2})
        self.assertGreater(path['excluded_unrelated_events'], 0)

    def test_no_edge_exists_without_evidence(self):
        cited = failures() + [hit(winevent(4624, NOW + 5 * MIN))]
        for edge in build(seed(cited), assets())['edges']:
            self.assertTrue(edge['evidence'])
            self.assertTrue(edge['reason'])
            self.assertIn(edge['basis'], ('observed', 'inferred'))
            self.assertIn(edge['tier'], TIERS)
            self.assertIn(edge['type'], model.EDGE_TYPES)

    def test_no_tier_says_compromise(self):
        for tier in TIERS:
            self.assertNotIn('compromis', tier)
        self.assertEqual(LIN['platform'], 'linux')


if __name__ == '__main__':
    unittest.main()
