"""Incidents, scoring, lifecycle, audit, recovery and the analyst interface."""
import json
import os
import socket
import tempfile
import threading
import unittest
from pathlib import Path

import helpers
from helpers import BAD_IP, ENCODED, GROUP, GUID_A, GUID_B, LOLBIN, MIN, NOW, PORT, RUNKEY, SCHTASKS, SCRIPT, TASK, World, alert, process_event
from siem_correlator import control, incidents, rules as rule_lib
from siem_correlator.incidents import ActionError
from siem_correlator.schema import SEVERITIES
from siem_correlator.service import StoreDown


def pair(**extra):
    return alert(GROUP, NOW, 'group', severity='high', **extra), alert(SCHTASKS, NOW + 5 * MIN, 'schtasks', **extra)


class Incidents(unittest.TestCase):
    def setUp(self):
        self.w = World(self)

    def test_every_required_field_is_present(self):
        incident = self.w.feed(*pair())[0]
        self.w.opensearch.written.clear()
        public = incidents.public(incident)
        for name in ('incident_id', 'title', 'description', 'severity', 'confidence', 'status', 'first_seen', 'last_seen', 'hosts', 'users', 'ips', 'domains', 'processes', 'file_hashes', 'alert_ids', 'source_event_ids', 'enrichment_refs', 'rules', 'timeline', 'created_at', 'updated_at', 'explanation'):
            self.assertIn(name, public)
        self.assertEqual(public['status'], 'new')
        self.assertFalse([k for k in public if k.startswith('_')])

    def test_trace_back_to_alerts_and_events(self):
        first, second = pair()
        incident = self.w.feed(first, second)[0]
        self.assertEqual(set(incident['alert_ids']), {first['alert_id'], second['alert_id']})
        self.assertIn(first['evidence_ref'], incident['alert_refs'])
        self.assertIn(first['raw_event_refs'][0], incident['raw_event_refs'])
        self.assertIn(first['source_event_ids'][0], incident['source_event_ids'])

    def test_explanation_answers_each_question(self):
        explain = self.w.feed(*pair())[0]['explanation']
        for name in ('why_grouped', 'connected_by', 'rules_matched', 'sequence', 'evidence', 'uncertain', 'severity_reasons', 'confidence_reasons'):
            self.assertIn(name, explain)
        self.assertTrue(explain['why_grouped'] and explain['connected_by'] and explain['sequence'])

    def test_duplicate_delivery_changes_nothing(self):
        first, second = pair()
        self.w.feed(first, second)
        revision = self.w.incidents()[0]['revision']
        self.w.feed(first, second, first)
        self.assertEqual(len(self.w.incidents()), 1)
        self.assertEqual(self.w.incidents()[0]['revision'], revision)

    def test_a_new_alert_grows_the_incident_and_keeps_history(self):
        first, second = pair()
        self.w.feed(first, second)
        third = alert(RUNKEY, NOW + 6 * MIN, 'runkey')
        incident = self.w.feed(third)[0]
        self.assertEqual(len(incident['alert_ids']), 3)
        self.assertEqual(len(incident['timeline']), 3)
        self.assertEqual(len(incident['correlations']), 2)
        self.assertEqual(len(self.w.store.audit_rows(incident['incident_id'])), 3)

    def test_several_rules_on_shared_alerts_make_one_incident(self):
        a = alert(ENCODED, NOW, 'encoded', tactics=('execution',))
        b = alert(GROUP, NOW + MIN, 'group', tactics=('privilege_escalation',))
        c = alert(SCHTASKS, NOW + 2 * MIN, 'schtasks', tactics=('persistence',))
        items = self.w.feed(a, b, c)
        self.assertEqual(len(items), 1)
        self.assertEqual({r['id'] for r in items[0]['rules']}, {'cor-privilege-then-admin', 'cor-multi-stage'})

    def test_repeats_that_arrive_before_the_first_stage_are_all_kept(self):
        repeats = [alert(SCHTASKS, NOW + 5 * MIN) for _ in range(4)]
        self.w.feed(*repeats)
        items = self.w.feed(alert(GROUP, NOW))
        self.assertEqual(len(items), 1)
        self.assertEqual(len(items[0]['alert_ids']), 5)

    def test_finished_incident_is_not_reopened_by_a_repeat(self):
        first, second = pair()
        incident = self.w.feed(first, second)[0]
        self.w.service.manager.transition(incident['incident_id'], 'false_positive', 'analyst', 'expected', NOW)
        self.w.store.db.execute("UPDATE alerts SET status = 'pending'")
        self.w.service.process()
        self.assertEqual(len(self.w.incidents()), 1)
        self.assertEqual(self.w.incidents()[0]['status'], 'false_positive')

    def test_new_activity_after_closure_is_a_new_incident(self):
        first, second = pair()
        incident = self.w.feed(first, second)[0]
        self.w.service.manager.transition(incident['incident_id'], 'false_positive', 'analyst', 'expected', NOW)
        self.assertEqual(len(self.w.feed(alert(GROUP, NOW + 10 * MIN), alert(SCHTASKS, NOW + 11 * MIN))), 2)
        kept = self.w.store.incident(incident['incident_id'])
        self.assertEqual((kept['status'], len(kept['alert_ids']), len(kept['notes'])), ('false_positive', 2, 1))

    def test_a_late_repeat_cannot_overwrite_a_closed_incident(self):
        first, second = pair()
        incident = self.w.feed(first, second)[0]
        self.w.service.manager.transition(incident['incident_id'], 'false_positive', 'analyst', 'expected', NOW)
        self.w.feed(alert(SCHTASKS, NOW + 6 * MIN))
        kept = self.w.store.incident(incident['incident_id'])
        self.assertEqual((kept['status'], len(kept['alert_ids'])), ('false_positive', 2))

    def test_incident_ids_are_stable_on_a_rebuild(self):
        first, second = pair()
        one = self.w.feed(first, second)[0]['incident_id']
        other = World(self)
        self.assertEqual(other.feed(first, second)[0]['incident_id'], one)

    def test_memory_per_incident_is_bounded(self):
        first, second = pair()
        self.w.feed(first, second)
        self.w.feed(*[alert(SCHTASKS, NOW + 6 * MIN + i * 1000, 'schtasks') for i in range(60)])
        incident = self.w.incidents()[0]
        self.assertEqual(len(incident['alert_ids']), 62)
        self.assertLessEqual(len(incident['_contexts']), 26)

    def test_a_long_incident_says_what_it_does_not_spell_out(self):
        first, second = pair()
        self.w.feed(first, second)
        self.w.feed(*[alert(SCHTASKS, NOW + 6 * MIN + i * 1000, 'schtasks') for i in range(120)])
        self.w.service.process()
        incident = self.w.incidents()[0]
        self.assertEqual(len(incident['correlations']), incidents.CORRELATION_LIMIT)
        self.assertEqual(incident['correlations_omitted'], 21)
        self.assertEqual(len(incident['alert_ids']), 122)


class Scoring(unittest.TestCase):
    def setUp(self):
        self.w = World(self)

    def test_severity_is_the_highest_alert_not_a_sum(self):
        items = self.w.feed(alert(GROUP, NOW, severity='low'), alert(SCHTASKS, NOW + 5 * MIN, severity='medium'))
        self.assertEqual(items[0]['severity'], 'medium')

    def test_many_copies_of_one_rule_do_not_raise_severity(self):
        first = alert(GROUP, NOW, severity='medium')
        copies = [alert(SCHTASKS, NOW + 3 * MIN + i * 1000, severity='medium') for i in range(10)]
        incident = self.w.feed(first, *copies)[0]
        self.assertEqual(incident['severity'], 'medium')
        self.assertTrue(any('repeats' in r for r in incident['explanation']['confidence_reasons']))

    def test_three_independent_rules_with_a_real_link_raise_one_step(self):
        items = self.w.feed(alert(ENCODED, NOW, tactics=('execution',), severity='medium'), alert(GROUP, NOW + MIN, tactics=('privilege_escalation',), severity='medium'), alert(SCHTASKS, NOW + 2 * MIN, tactics=('persistence',), severity='medium'))
        self.assertEqual(items[0]['severity'], 'high')

    def test_one_proven_pair_does_not_lend_its_strength_to_the_rest(self):
        contexts = [{'rule_id': str(i), 'severity': 'medium', 'hostile': [], 'kind': 'alert', 'enrichment': 'complete'} for i in range(4)]
        mixed = incidents.score({'_joins': ['user', 'lineage'], 'uncertain': []}, contexts)
        self.assertLess(mixed[1], incidents.score({'_joins': ['lineage'], 'uncertain': []}, contexts)[1])
        self.assertFalse(any('lineage' in r for r in mixed[3]))

    def test_rules_on_one_event_are_one_observation(self):
        same = [{'rule_id': r, 'event_ids': ['e1']} for r in 'abc']
        self.assertEqual(incidents.independent_rules(same), 1)
        self.assertEqual(incidents.independent_rules([{'rule_id': 'a', 'event_ids': ['e1']}, {'rule_id': 'b', 'event_ids': ['e2']}]), 2)
        self.assertEqual(incidents.independent_rules([{'rule_id': 'a', 'event_ids': ['e1', 'e2']}, {'rule_id': 'b', 'event_ids': ['e2']}, {'rule_id': 'c', 'event_ids': ['e3']}]), 2)

    def test_never_more_than_critical(self):
        contexts = [{'rule_id': str(i), 'severity': 'critical', 'hostile': [], 'kind': 'alert', 'enrichment': 'complete'} for i in range(5)]
        self.assertEqual(incidents.score({'_joins': ['lineage'], 'uncertain': []}, contexts)[0], 'critical')

    def test_a_host_link_cannot_escalate(self):
        contexts = [{'rule_id': str(i), 'severity': 'medium', 'hostile': [], 'kind': 'alert', 'enrichment': 'complete'} for i in range(5)]
        severity, confidence, band, _, _ = incidents.score({'_joins': ['host'], 'uncertain': []}, contexts)
        self.assertEqual(severity, 'medium')
        self.assertLess(confidence, 70)

    def test_lineage_is_worth_more_than_a_host(self):
        contexts = [{'rule_id': 'a', 'severity': 'medium', 'hostile': [], 'kind': 'alert', 'enrichment': 'complete'}]
        self.assertGreater(incidents.score({'_joins': ['lineage'], 'uncertain': []}, contexts)[1], incidents.score({'_joins': ['host'], 'uncertain': []}, contexts)[1])

    def contexts(self, **extra):
        return [{'rule_id': 'a', 'severity': 'high', 'hostile': [], 'kind': 'alert', 'enrichment': 'complete', **extra}]

    def test_uncertainty_lowers_confidence(self):
        base = incidents.score({'_joins': ['user'], 'uncertain': []}, self.contexts())[1]
        for case in ({'contexts': self.contexts(events_missing=True), 'uncertain': []},
                     {'contexts': self.contexts(hostile=[{'verdict': 'conflicting', 'value': 'x', 'type': 'ip'}]), 'uncertain': []},
                     {'contexts': self.contexts(enrichment='failed'), 'uncertain': []},
                     {'contexts': self.contexts(), 'uncertain': ['order is not proven']},
                     {'contexts': self.contexts(), 'uncertain': ['match by name only']}):
            self.assertLess(incidents.score({'_joins': ['user'], 'uncertain': case['uncertain']}, case['contexts'])[1], base, case)

    def test_a_name_link_is_not_penalized_twice(self):
        self.assertEqual(incidents.score({'_joins': ['user_name'], 'uncertain': ['match by name only']}, self.contexts())[1], incidents.score({'_joins': ['user_name'], 'uncertain': []}, self.contexts())[1])

    def test_a_malicious_indicator_raises_confidence_and_one_step(self):
        hostile = [{'verdict': 'malicious', 'value': 'x', 'type': 'ip'}]
        contexts = [{'rule_id': 'a', 'severity': 'medium', 'hostile': hostile, 'kind': 'alert', 'enrichment': 'complete'}]
        severity, confidence, *_ = incidents.score({'_joins': ['indicator'], 'uncertain': []}, contexts)
        self.assertEqual(severity, 'high')
        self.assertGreaterEqual(confidence, 45)

    def test_scoring_is_deterministic(self):
        contexts = self.contexts()
        self.assertEqual(incidents.score({'_joins': ['user'], 'uncertain': []}, contexts), incidents.score({'_joins': ['user'], 'uncertain': []}, contexts))

    def test_every_score_explains_itself(self):
        explain = self.w.feed(*pair())[0]['explanation']
        self.assertTrue(explain['severity_reasons'] and explain['confidence_reasons'])


class Lifecycle(unittest.TestCase):
    def setUp(self):
        self.w = World(self)
        self.id = self.w.feed(*pair())[0]['incident_id']
        self.m = self.w.service.manager

    def test_the_normal_path(self):
        for state, note in (('open', None), ('investigating', None), ('contained', None), ('resolved', 'fixed'), ('closed', 'done')):
            self.assertEqual(self.m.transition(self.id, state, 'analyst', note, NOW)['status'], state)

    def test_all_seven_states_exist(self):
        self.assertEqual(set(incidents.STATES), {'new', 'open', 'investigating', 'contained', 'resolved', 'closed', 'false_positive'})

    def test_illegal_moves_are_refused(self):
        for state in ('contained', 'resolved', 'closed'):
            with self.assertRaises(ActionError):
                self.m.transition(self.id, state, 'analyst', 'x', NOW)

    def test_unknown_state(self):
        with self.assertRaises(ActionError):
            self.m.transition(self.id, 'deleted', 'analyst', 'x', NOW)

    def test_closing_needs_a_reason(self):
        with self.assertRaisesRegex(ActionError, 'needs a note'):
            self.m.transition(self.id, 'false_positive', 'analyst', '', NOW)

    def test_reopening_works(self):
        self.m.transition(self.id, 'false_positive', 'analyst', 'x', NOW)
        self.assertEqual(self.m.transition(self.id, 'open', 'analyst', None, NOW)['status'], 'open')

    def test_the_system_never_contains_or_resolves(self):
        first, second = pair()
        self.w.feed(first, second)
        self.assertTrue(all(i['status'] == 'new' for i in self.w.incidents()))

    def test_no_code_path_runs_a_response_action(self):
        for path in (helpers.ROOT / 'correlator' / 'siem_correlator').glob('*.py'):
            text = path.read_text(encoding='utf8')
            for word in ('subprocess', 'os.system', 'Popen', 'taskkill', 'netsh', 'Stop-'):
                self.assertNotIn(word, text, path)

    def test_status_change_is_audited_with_who_and_why(self):
        self.m.transition(self.id, 'false_positive', 'alice', 'known job', NOW)
        last = self.w.store.audit_rows(self.id)[-1]
        self.assertEqual((last['actor'], last['action'], last['detail']['from'], last['detail']['to'], last['detail']['note']), ('alice', 'status', 'new', 'false_positive', 'known job'))

    def test_notes_are_kept_and_audited(self):
        self.m.add_note(self.id, 'alice', 'looked at this', NOW)
        self.assertEqual(self.w.store.incident(self.id)['notes'][0]['by'], 'alice')
        self.assertEqual(self.w.store.audit_rows(self.id)[-1]['action'], 'note')

    def test_an_empty_or_huge_note_is_refused(self):
        with self.assertRaises(ActionError):
            self.m.add_note(self.id, 'a', ' ', NOW)
        with self.assertRaises(ActionError):
            self.m.add_note(self.id, 'a', 'x' * 3000, NOW)

    def test_an_update_keeps_the_status_set_by_an_analyst(self):
        self.m.transition(self.id, 'investigating', 'alice', None, NOW)
        self.w.feed(alert(RUNKEY, NOW + 6 * MIN))
        self.assertEqual(self.w.store.incident(self.id)['status'], 'investigating')

    def test_unknown_incident(self):
        with self.assertRaises(ActionError):
            self.m.transition('nope', 'open', 'a', None, NOW)


class Audit(unittest.TestCase):
    def setUp(self):
        self.w = World(self)
        self.id = self.w.feed(*pair())[0]['incident_id']

    def test_the_chain_verifies(self):
        self.assertIsNone(self.w.store.audit_verify()[1])

    def test_an_altered_entry_is_detected(self):
        self.w.store.db.execute("UPDATE audit SET actor = 'mallory' WHERE seq = 1")
        self.assertEqual(self.w.store.audit_verify()[1], 1)

    def test_a_removed_entry_is_detected(self):
        self.w.store.db.execute('DELETE FROM audit WHERE seq = 1')
        self.assertIsNotNone(self.w.store.audit_verify()[1])


class Recovery(unittest.TestCase):
    def setUp(self):
        self.w = World(self)

    def cycle(self):
        self.w.service.cycle()

    def test_alert_is_stored_before_its_offset_is_committed(self):
        first, second = pair()
        self.w.kafka.send(first, second)
        original = self.w.store.inbox

        def crash(*args, **kwargs):
            raise SystemExit('power cut')
        self.w.store.inbox = crash
        with self.assertRaises(SystemExit):
            self.w.service.poll_kafka()
        self.w.store.inbox = original
        self.assertEqual(self.w.kafka.committed, 0)
        self.cycle()
        self.assertEqual(len(self.w.incidents()), 1)

    def test_crash_after_storing_and_before_commit_does_not_duplicate(self):
        first, second = pair()
        self.w.feed(first, second)
        self.w.kafka.rewind()
        self.w.restart()
        self.cycle()
        self.assertEqual(len(self.w.incidents()), 1)
        self.assertEqual(len(self.w.incidents()[0]['alert_ids']), 2)

    def test_crash_during_analysis_repeats_the_alert(self):
        first, second = pair()
        self.w.kafka.send(first, second)
        self.w.service.poll_kafka()
        original = self.w.service.manager.apply

        def crash(*args):
            raise SystemExit('power cut')
        self.w.service.manager.apply = crash
        with self.assertRaises(SystemExit):
            self.w.service.process()
        self.w.restart()
        self.assertEqual(len(self.w.store.due(NOW)), 1, 'the transaction rolled back, so the second alert waits')
        self.w.service.process()
        self.assertEqual(len(self.w.incidents()), 1)
        self.assertTrue(original)

    def test_kafka_outage_loses_nothing_and_resumes(self):
        first, second = pair()
        self.w.kafka.send(first)
        self.cycle()
        self.w.kafka.down = True
        self.w.kafka.send(second)
        self.cycle()
        self.assertIn('kafka', self.w.service.state['kafka'])
        self.assertEqual(self.w.service.health()['status'], 'WARN')
        self.w.kafka.down = False
        self.cycle()
        self.assertEqual(len(self.w.incidents()), 1)

    def test_a_quiet_kafka_outage_shows_in_health(self):
        self.cycle()
        self.w.kafka.down = True
        self.w.kafka.poll = lambda limit, timeout: []
        self.cycle()
        self.w.service.probe()
        self.assertEqual(self.w.service.health()['status'], 'WARN')

    def test_a_quiet_opensearch_outage_stays_in_health(self):
        self.cycle()
        self.w.opensearch.down = True
        self.w.service.last_slow = -60000
        self.cycle()
        self.cycle()
        self.assertEqual(self.w.service.health()['status'], 'WARN')
        self.w.opensearch.down = False
        self.w.service.last_slow = -60000
        self.cycle()
        self.assertEqual(self.w.service.health()['status'], 'OK')

    def test_opensearch_outage_keeps_alerts_waiting(self):
        first, second = pair()
        self.w.opensearch.down = True
        self.w.kafka.send(first, second)
        self.cycle()
        self.assertEqual(self.w.kafka.committed, 2, 'they are stored, so the offset can move')
        self.assertEqual(self.w.store.counts().get('pending'), 2)
        self.assertEqual(self.w.incidents(), [])
        self.w.opensearch.down = False
        self.w.now[0] += 60000
        self.cycle()
        self.assertEqual(len(self.w.incidents()), 1)

    def test_incident_waits_in_the_outbox_during_an_outage(self):
        first, second = pair()
        self.w.feed(first, second)
        self.w.opensearch.down = True
        self.cycle()
        self.assertEqual(self.w.store.outbox_size(), 1)
        self.w.opensearch.down = False
        self.cycle()
        self.assertEqual(self.w.store.outbox_size(), 0)
        self.assertTrue(any('siem-incidents-' in p and 'version_type=external' in p for p in self.w.opensearch.written))

    def test_outbox_survives_a_restart(self):
        first, second = pair()
        self.w.opensearch.down = True
        self.w.feed(first, second)
        self.w.opensearch.down = False
        self.w.service.process()
        self.w.now[0] += 60000
        self.w.service.process()
        self.w.opensearch.down = True
        self.w.restart()
        self.w.opensearch.down = False
        self.w.service.flush()
        self.assertEqual(self.w.store.outbox_size(), 0)

    def test_audit_is_shipped_with_create_only(self):
        self.w.feed(*pair())
        self.w.service.flush()
        self.assertTrue(any('siem-incident-audit-' in p and '/_create/' in p for p in self.w.opensearch.written))

    def test_invalid_alert_is_quarantined_and_does_not_block_others(self):
        first, second = pair()
        self.w.kafka.send(first, raw=b'{"not": "an alert"}')
        self.w.kafka.send(raw=b'garbage')
        self.w.kafka.send(second)
        self.cycle()
        self.assertEqual(len(self.w.incidents()), 1)
        rows = self.w.store.quarantined()
        self.assertEqual(len(rows), 2)
        self.assertTrue(rows[0]['reason'] and rows[0]['sha256'])
        self.assertEqual(self.w.kafka.committed, 4)

    def test_quarantine_keeps_no_content(self):
        self.w.kafka.send(raw=b'{"secret": "private-argument"}')
        self.cycle()
        self.assertNotIn('private-argument', json.dumps(self.w.store.quarantined()))

    def test_quarantine_shows_in_health(self):
        self.w.kafka.send(raw=b'garbage')
        self.cycle()
        self.assertEqual(self.w.service.health()['quarantined'], 1)

    def test_replay_finds_alerts_kafka_lost_and_ignores_known_ones(self):
        first, second = pair()
        self.w.feed(first)
        self.w.opensearch.alerts = [first, second]
        result = self.w.service.replay(24, 'alice')
        self.assertEqual((result['read'], result['new']), (2, 1))
        self.w.service.process()
        self.assertEqual(len(self.w.incidents()), 1)
        self.assertEqual(self.w.store.audit_rows()[-1]['actor'], 'system')

    def test_replay_is_bounded(self):
        for hours in (0, 10000):
            with self.assertRaises(ValueError):
                self.w.service.replay(hours, 'a')

    def test_replay_holds_no_restricted_text(self):
        doc = alert(GROUP, NOW, fields={'process.command_line': ['private-argument']})
        self.w.opensearch.alerts = [doc]
        self.w.service.replay(24, 'a')
        self.assertNotIn('private-argument', json.dumps(self.w.store.due(NOW + 1)))

    def test_prune_keeps_what_an_open_incident_needs(self):
        first, second = pair()
        self.w.feed(first, second, alert(TASK, NOW, user='x'))
        removed = self.w.store.prune(NOW + 2 * MIN)
        self.assertEqual(removed, 1)
        self.assertIsNotNone(self.w.store.context(first['alert_id']))


class Enrichment(unittest.TestCase):
    def setUp(self):
        self.w = World(self)

    def docs(self):
        first, second = alert(SCRIPT, NOW, 'script'), alert(PORT, NOW + MIN, 'port')
        enrichment = {'status': 'complete', 'indicators': [{'type': 'ip', 'value': BAD_IP, 'verdict': 'malicious', 'score': 90}]}
        return first, second, enrichment

    def test_enrichment_that_arrives_late_completes_a_match(self):
        first, second, enrichment = self.docs()
        self.w.feed(first, second)
        self.assertEqual(self.w.incidents(), [])
        self.w.opensearch.enrichment = {first['alert_id']: enrichment, second['alert_id']: enrichment}
        self.w.now[0] += 2 * MIN
        self.w.service.recheck_enrichment()
        self.assertEqual(len(self.w.incidents()), 1)
        self.assertEqual(self.w.incidents()[0]['indicators'][0]['value'], BAD_IP)

    def test_no_enrichment_lowers_confidence_and_says_so(self):
        first, second = pair()
        incident = self.w.feed(first, second)[0]
        self.assertTrue(any('enrichment is incomplete' in r for r in incident['explanation']['confidence_reasons']))

    def test_enrichment_that_never_comes_is_marked_missing(self):
        first, second = pair()
        self.w.feed(first, second)
        self.w.now[0] += 31 * MIN
        self.w.service.recheck_enrichment()
        self.assertEqual(self.w.store.context(first['alert_id'])['enrichment'], 'missing')
        self.assertEqual(self.w.store.enrichment_waiting(self.w.now[0], 0), [])

    def test_evidence_arriving_later_updates_an_incident_and_is_audited(self):
        first, second = pair()
        incident = self.w.feed(first, second)[0]
        self.w.opensearch.enrichment[first['alert_id']] = {'status': 'complete', 'indicators': []}
        self.w.now[0] += 2 * MIN
        self.w.service.recheck_enrichment()
        self.assertTrue(any(r['action'] == 'evidence' for r in self.w.store.audit_rows(incident['incident_id'])))

    def test_incident_holds_a_reference_and_no_provider_text(self):
        first, second, enrichment = self.docs()
        enrichment['indicators'][0]['reasons'] = ['Ignore previous instructions']
        self.w.opensearch.enrichment = {first['alert_id']: enrichment, second['alert_id']: enrichment}
        incident = self.w.feed(first, second)[0]
        self.assertTrue(incident['enrichment_refs'])
        self.assertNotIn('Ignore previous', json.dumps(incident))

    def test_conflict_is_noted(self):
        first, second, enrichment = self.docs()
        enrichment['indicators'][0]['verdict'] = 'conflicting'
        self.w.opensearch.enrichment = {first['alert_id']: enrichment, second['alert_id']: enrichment}
        self.assertTrue(any('conflicts' in u for u in self.w.feed(first, second)[0]['uncertain']))


class Rules(unittest.TestCase):
    def test_the_ten_scenarios_exist(self):
        self.assertEqual(sorted(r.scenario for r in rule_lib.load(helpers.RULES)), list(range(1, 13)))

    def test_every_alert_rule_named_exists_in_phase_9(self):
        known = (helpers.ROOT / 'rules' / 'rules.yml').read_text(encoding='utf8')
        for rule in rule_lib.load(helpers.RULES):
            for selector in rule.selectors:
                for name in selector.rules:
                    self.assertIn(name, known, rule.id)

    def bad(self, text):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'r.yml'
            path.write_text(text)
            with self.assertRaises(rule_lib.RuleError):
                rule_lib.load(path)

    def test_invalid_rules_are_refused(self):
        base = 'rules:\n  - {id: a, title: t, description: d, kind: %s, join: %s, window_seconds: %s}\n'
        self.bad(base % ('nonsense', 'host', 600))
        self.bad(base % ('single', 'nonsense', 600))
        self.bad(base % ('single', 'host', 5))
        self.bad(base % ('sequence', 'host', 600))

    def test_a_disabled_rule_does_not_match(self):
        w = World(self)
        with w.store.lock, w.store.db:
            w.store.set_rule('cor-privilege-then-admin', False)
        self.assertEqual(w.feed(*pair()), [])

    def test_a_noisy_entity_stays_bounded(self):
        w = World(self)
        items = [alert(TASK, NOW + i * 1000) for i in range(700)]
        w.feed(*items[:200])
        self.assertLessEqual(len(w.store.near('host:host', 0, NOW * 2, 500)), 500)


class Socket(unittest.TestCase):
    """The real socket and the real kernel check, with this test's own account."""

    def setUp(self):
        self.w = World(self)
        self.id = self.w.feed(*pair())[0]['incident_id']
        self.actions = control.Actions(self.w.service)
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)

    def test_root_is_refused(self):
        self.assertIsNone(control.authorize(0, 0))

    def test_an_unknown_uid_is_refused(self):
        self.assertIsNone(control.authorize(54321, 54321))

    def test_a_non_member_is_refused(self):
        self.assertIsNone(control.authorize(1, 1, 'root'))

    def test_a_missing_group_is_refused(self):
        self.assertIsNone(control.authorize(1000, 1000, 'no-such-group'))

    def test_the_actor_comes_from_the_kernel_not_the_request(self):
        reply = control.handle(self.actions, {'action': 'note', 'incident_id': self.id, 'text': 'hello', 'actor': 'somebody-else'}, 'alice')
        self.assertTrue(reply['ok'])
        self.assertEqual(self.w.store.audit_rows(self.id)[-1]['actor'], 'alice')

    def test_unknown_action(self):
        self.assertFalse(control.handle(self.actions, {'action': 'store'}, 'a')['ok'])
        self.assertFalse(control.handle(self.actions, 'nonsense', 'a')['ok'])
        self.assertFalse(control.handle(self.actions, {'action': '__init__'}, 'a')['ok'])

    def test_bad_arguments_are_an_error_not_a_crash(self):
        self.assertFalse(control.handle(self.actions, {'action': 'status', 'incident_id': self.id, 'state': 'open', 'surprise': 1}, 'a')['ok'])

    def test_the_interface_covers_every_operation(self):
        self.assertEqual(set(control.PUBLIC), {'list', 'show', 'timeline', 'search', 'status', 'note', 'audit', 'verify', 'rules', 'rule', 'replay', 'health', 'quarantine'})

    def test_read_operations(self):
        for request in ({'action': 'list'}, {'action': 'show', 'incident_id': self.id}, {'action': 'timeline', 'incident_id': self.id}, {'action': 'audit', 'incident_id': self.id}, {'action': 'verify'}, {'action': 'rules'}, {'action': 'health'}, {'action': 'quarantine'}):
            self.assertTrue(control.handle(self.actions, request, 'a')['ok'], request)

    def test_search_by_each_field(self):
        for request, found in (({'host': 'host'}, 1), ({'user': 'jdoe'}, 1), ({'severity': 'high'}, 1), ({'host': 'other'}, 0), ({'ip': '1.2.3.4'}, 0), ({'user': 'nobody'}, 0)):
            self.assertEqual(len(control.handle(self.actions, {'action': 'search', **request}, 'a')['result']), found, request)

    def test_rule_switch_is_audited(self):
        control.handle(self.actions, {'action': 'rule', 'rule_id': 'cor-multi-stage', 'enabled': False}, 'alice')
        self.assertEqual(self.w.store.audit_rows()[-1]['actor'], 'alice')
        self.assertFalse(next(r for r in control.handle(self.actions, {'action': 'rules'}, 'a')['result'] if r['id'] == 'cor-multi-stage')['enabled'])

    def test_a_refused_client_is_audited_and_given_nothing(self):
        path = os.path.join(self.folder.name, 'c.sock')
        server = control.Server(path, self.actions, group='no-such-group', log=lambda t: None)
        server.start()
        self.addCleanup(server.stop)
        reply = control.call(path, {'action': 'list'})
        self.assertFalse(reply['ok'])
        self.assertIn('not a member', reply['error'])
        self.assertEqual(self.w.store.audit_rows()[-1]['action'], 'refused')

    def test_socket_permissions(self):
        path = os.path.join(self.folder.name, 'c.sock')
        server = control.Server(path, self.actions, log=lambda t: None)
        server.start()
        self.addCleanup(server.stop)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o660)

    def test_there_is_no_network_listener(self):
        for path in (helpers.ROOT / 'correlator' / 'siem_correlator').glob('*.py'):
            text = path.read_text(encoding='utf8')
            self.assertNotIn('AF_INET', text, path)
            self.assertNotIn('http.server', text, path)


class Independence(unittest.TestCase):
    def test_detection_and_enrichment_do_not_know_about_correlation(self):
        for folder in ('detector', 'enricher'):
            for path in (helpers.ROOT / folder).rglob('*.py'):
                self.assertNotIn('siem_correlator', path.read_text(encoding='utf8'), path)

    def test_the_correlator_writes_only_its_own_indices(self):
        w = World(self)
        w.feed(*pair())
        w.service.flush()
        self.assertTrue(all('/siem-incident' in p for p in w.opensearch.written))


if __name__ == '__main__':
    unittest.main()
