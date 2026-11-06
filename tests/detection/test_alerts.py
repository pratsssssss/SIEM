"""The alert contract, publishing and recovery, and the OpenSearch client's failure handling."""
import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path

import helpers
from helpers import BASE, FakeKafka, FakeStore, event, rule
from siem_detector import alerts, runner
from siem_detector.backends import OpenSearch, Outbox, SearchError
from siem_detector.state import State

SECRET_LINE = 'tool.exe --password=[REDACTED:arg] private-argument'


def hit(uid=1, **extra):
    return {'_id': f'id{uid}', '_index': 'siem-windows-2026.10.31', '_source': event(uid, BASE, **extra)}


class Schema(unittest.TestCase):
    def build(self, hits=None, **kwargs):
        return alerts.build(rule(), hits or [hit()], alerts.make_id('a'), BASE, **kwargs)

    def test_valid_alert_has_every_required_field(self):
        alert = self.build()
        self.assertEqual(alerts.validate(alert), [])
        for name in ('alert_id', 'rule_id', 'rule_name', 'severity', 'confidence', 'timestamp', 'source_event_ids', 'host', 'user', 'description', 'evidence', 'mitre'):
            self.assertIn(name, alert)
        self.assertEqual(alert['host'], 'HOST')
        self.assertEqual(alert['user'], 'bob')
        self.assertEqual(alert['source_event_ids'], ['id1'])
        self.assertEqual(alert['raw_event_refs'], ['siem-windows-2026.10.31/id1'])

    def test_mitre_comes_from_tags(self):
        self.assertEqual(alerts.mitre(['attack.execution', 'attack.t1059.001', 'attack.command-and-control', 'attack.stealth', 'car.2016-04-005']),
                         {'tactics': ['command_and_control', 'execution', 'stealth'], 'techniques': ['T1059.001']})

    def test_ids_are_deterministic_and_differ_by_input(self):
        self.assertEqual(alerts.make_id('a', 1), alerts.make_id('a', 1))
        self.assertNotEqual(alerts.make_id('a', 1), alerts.make_id('a', 2))

    def test_validation_rejects_broken_alerts(self):
        for name, value in (('severity', 'urgent'), ('confidence', 'sure'), ('alert_id', 'short'), ('timestamp', 'yesterday'), ('event_count', 0), ('detection_type', 'ml'), ('source_event_ids', []), ('schema_version', 2), ('mitre', {}), ('event_count', True)):
            alert = self.build()
            alert[name] = value
            self.assertTrue(alerts.validate(alert), name)

    def test_validation_rejects_a_missing_field(self):
        alert = self.build()
        del alert['rule_id']
        self.assertEqual(alerts.validate(alert), ['rule_id: missing or wrong type'])

    def test_many_events_keep_first_last_and_the_true_count(self):
        hits = [hit(i, when=f'2026-10-31T{i // 60:02d}:{i % 60:02d}:00.000Z') for i in range(1, 121)]
        alert = self.build(hits)
        self.assertEqual(alert['event_count'], 120)
        self.assertEqual(len(alert['source_event_ids']), alerts.MAX_REFS)
        self.assertEqual(alert['source_event_ids'][0], 'id1')
        self.assertEqual(alert['source_event_ids'][-1], 'id120')

    def test_time_range_covers_every_event(self):
        alert = self.build([hit(2, when='2026-10-31T10:00:02.000Z'), hit(1, when='2026-10-31T10:00:01.000Z')])
        self.assertEqual(alert['evidence']['first_seen'], '2026-10-31T10:00:01.000Z')
        self.assertEqual(alert['evidence']['last_seen'], '2026-10-31T10:00:02.000Z')
        self.assertEqual(alert['timestamp'], '2026-10-31T10:00:01.000Z')

    def test_long_evidence_is_capped_and_says_so(self):
        alert = self.build([hit(1, process={'command_line': 'x' * 5000, 'name': 'a.exe'})])
        value = alert['evidence']['matched_fields']['process.command_line'][0]
        self.assertTrue(value.endswith('[5000 chars]'))
        self.assertLess(len(value), 2100)


class KafkaSafety(unittest.TestCase):
    """D22: nothing restricted may reach Kafka. The check is the absence of the text itself."""

    def alert(self):
        h = hit(1, process={'command_line': SECRET_LINE, 'parent': {'command_line': 'parent private-argument'}, 'name': 'tool.exe', 'executable': 'C:\\tool.exe'},
                file={'path': 'C:\\private-argument\\a'}, powershell={'script_block': {'text': 'private-argument'}})
        made = rule(fields=['process.command_line.keyword', 'powershell.script_block.text', 'winlog.event_data.ScriptBlockText'])
        return alerts.build(made, [h], alerts.make_id('a'), BASE, facts={'note': 'private-argument', 'count': 3})

    def test_restricted_values_do_not_appear(self):
        safe = alerts.kafka_safe(self.alert())
        self.assertNotIn('private-argument', json.dumps(safe))

    def test_full_alert_keeps_the_evidence(self):
        self.assertIn('private-argument', json.dumps(self.alert()))

    def test_withheld_values_keep_a_digest_to_match_later(self):
        safe = alerts.kafka_safe(self.alert())
        entry = safe['evidence']['matched_fields']['process.command_line'][0]
        self.assertTrue(entry['withheld'])
        self.assertEqual(len(entry['sha256']), 64)
        self.assertEqual(entry['length'], len(SECRET_LINE))

    def test_safe_fields_stay_readable(self):
        safe = alerts.kafka_safe(self.alert())
        self.assertEqual(safe['evidence']['matched_fields']['process.name'], ['tool.exe'])
        self.assertEqual(safe['evidence']['facts']['count'], 3)

    def test_a_new_field_is_withheld_by_default(self):
        full = self.alert()
        full['evidence']['matched_fields']['brand.new.field'] = ['private-argument']
        self.assertNotIn('private-argument', json.dumps(alerts.kafka_safe(full)))

    def test_the_safe_form_is_a_valid_alert_that_points_at_the_evidence(self):
        safe = alerts.kafka_safe(self.alert())
        self.assertEqual(alerts.validate(safe), [])
        self.assertTrue(safe['evidence_ref'].startswith('siem-alerts-'))


class Outboxes(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / 'state.db')
        self.state = State(self.path)
        self.addCleanup(lambda: self.state.close())
        self.store = FakeStore()
        self.kafka = FakeKafka()
        self.outbox = Outbox(self.state, self.store, self.kafka, log=lambda text: None)

    def add(self, count=1):
        ids = []
        for i in range(count):
            alert_id = alerts.make_id('x', i)
            full = alerts.build(rule(), [hit(i + 1)], alert_id, BASE)
            self.state.rule('rule-1', BASE, 0)
            self.state.commit_run('rule-1', BASE, [(alert_id, full, alerts.kafka_safe(full))], BASE, BASE, 1, 1)
            ids.append(alert_id)
        return ids

    def test_alert_reaches_both_stores_once(self):
        ids = self.add()
        self.outbox.cycle()
        self.assertEqual([k for k, _ in self.kafka.topic], ids)
        self.assertIn(ids[0], self.store.indexed)
        self.assertEqual(self.state.counts()['pending'], 0)

    def test_message_key_is_the_alert_id_and_value_is_valid_json(self):
        ids = self.add()
        self.outbox.cycle()
        key, value = self.kafka.topic[0]
        self.assertEqual(key, ids[0])
        self.assertEqual(json.loads(value)['alert_id'], ids[0])

    def test_kafka_outage_keeps_every_alert_until_it_returns(self):
        ids = self.add(3)
        self.kafka.down = True
        for _ in range(4):
            self.outbox.cycle()
        self.assertEqual(self.kafka.topic, [])
        self.assertEqual(self.state.counts()['pending'], 3)
        self.kafka.down = False
        self.outbox.cycle()
        self.assertEqual(sorted(k for k, _ in self.kafka.topic), sorted(ids))
        self.assertEqual(self.state.counts()['pending'], 0)

    def test_lost_delivery_report_does_not_duplicate(self):
        self.add()
        self.kafka.lose_reports = True
        self.outbox.cycle()
        self.assertEqual(len(self.kafka.topic), 1)
        self.assertEqual(self.state.counts()['pending'], 1)
        self.kafka.lose_reports = False
        self.outbox.cycle()
        self.assertEqual(len(self.kafka.topic), 1)
        self.assertEqual(self.state.counts()['pending'], 0)

    def test_crash_after_send_does_not_duplicate_after_restart(self):
        ids = self.add()
        self.kafka.topic.append((ids[0], '{}'))
        self.state.mark_attempt(ids[0])
        self.state.close()
        self.state = State(self.path)
        Outbox(self.state, self.store, self.kafka, log=lambda text: None).cycle()
        self.assertEqual(len(self.kafka.topic), 1)
        self.assertEqual(self.state.counts()['pending'], 0)

    def test_kafka_audit_failure_holds_rather_than_guesses(self):
        ids = self.add()
        self.state.mark_attempt(ids[0])
        self.kafka.down = True
        self.outbox.cycle()
        self.assertEqual(self.kafka.queued, [])
        self.assertEqual(self.state.counts()['pending'], 1)

    def test_evidence_failure_is_retried_without_blocking_kafka(self):
        ids = self.add()
        self.store.index_failures = 1
        self.outbox.cycle()
        self.assertEqual(self.state.counts()['pending'], 1)
        self.assertEqual(len(self.kafka.topic), 1)
        self.outbox.cycle()
        self.assertIn(ids[0], self.store.indexed)
        self.assertEqual(self.state.counts()['pending'], 0)
        self.assertEqual(len(self.kafka.topic), 1)

    def test_local_full_text_is_removed_once_indexed(self):
        ids = self.add()
        self.outbox.cycle()
        row = self.state.db.execute('SELECT full_json FROM alerts WHERE alert_id = ?', ids).fetchone()
        self.assertIsNone(row[0])

    def test_outbox_survives_a_restart_during_an_outage(self):
        ids = self.add(2)
        self.kafka.down = True
        self.outbox.cycle()
        self.state.close()
        self.state = State(self.path)
        self.kafka.down = False
        Outbox(self.state, self.store, self.kafka, log=lambda text: None).cycle()
        self.assertEqual(sorted(k for k, _ in self.kafka.topic), sorted(ids))

    def test_kafka_form_never_holds_restricted_text(self):
        alert_id = alerts.make_id('s')
        h = hit(1, process={'command_line': 'private-argument'})
        full = alerts.build(rule(), [h], alert_id, BASE)
        self.state.rule('rule-1', BASE, 0)
        self.state.commit_run('rule-1', BASE, [(alert_id, full, alerts.kafka_safe(full))], BASE, BASE, 1, 1)
        self.outbox.cycle()
        self.assertNotIn('private-argument', self.kafka.topic[0][1])
        self.assertIn('private-argument', json.dumps(self.store.indexed[alert_id]))


def response(body):
    return io.BytesIO(json.dumps(body).encode())


def http_error(code):
    return urllib.error.HTTPError('https://x', code, 'error', {}, io.BytesIO(b'{}'))


class Client(unittest.TestCase):
    def client(self, replies):
        self.requests = []
        items = list(replies)

        def opener(request, timeout):
            self.requests.append(request)
            item = items.pop(0)
            if isinstance(item, Exception):
                raise item
            return response(item)
        return OpenSearch('https://127.0.0.1:9200', None, 'siem_detector', 'pw', opener=opener, sleep=lambda s: None)

    GOOD = {'timed_out': False, '_shards': {'failed': 0}, 'hits': {'hits': []}}

    def test_success(self):
        self.assertEqual(self.client([self.GOOD]).search('i', {})['hits'], {'hits': []})
        self.assertTrue(self.requests[0].get_header('Authorization').startswith('Basic '))

    def test_partial_results_are_refused_by_the_server_too(self):
        self.client([self.GOOD]).search('i', {})
        self.assertIn('allow_partial_search_results=false', self.requests[0].full_url)

    def test_transient_errors_are_retried(self):
        self.assertTrue(self.client([http_error(503), OSError('reset'), self.GOOD]).search('i', {}))
        self.assertEqual(len(self.requests), 3)

    def test_rate_limit_is_retried(self):
        self.assertTrue(self.client([http_error(429), self.GOOD]).search('i', {}))

    def test_a_bad_query_is_not_retried(self):
        with self.assertRaises(SearchError):
            self.client([http_error(400), self.GOOD]).search('i', {})
        self.assertEqual(len(self.requests), 1)

    def test_timed_out_query_is_a_failure(self):
        with self.assertRaises(SearchError):
            self.client([dict(self.GOOD, timed_out=True)] * 3).search('i', {})

    def test_failed_shards_are_a_failure(self):
        with self.assertRaises(SearchError):
            self.client([dict(self.GOOD, _shards={'failed': 1})] * 3).search('i', {})

    def test_garbage_response_is_a_failure(self):
        client = OpenSearch('https://x', None, 'u', 'p', opener=lambda r, timeout: io.BytesIO(b'not json'), sleep=lambda s: None)
        with self.assertRaises(SearchError):
            client.search('i', {})

    def test_gives_up_after_the_retries(self):
        with self.assertRaises(SearchError):
            self.client([http_error(503)] * 3).search('i', {})
        self.assertEqual(len(self.requests), 3)

    def test_second_write_of_an_alert_counts_as_done(self):
        self.client([http_error(409)]).index_alert('i', 'a', {})

    def test_evidence_write_uses_create_so_it_cannot_overwrite(self):
        self.client([{}]).index_alert('i', 'a', {})
        self.assertIn('/_create/a', self.requests[0].full_url)


if __name__ == '__main__':
    unittest.main()
