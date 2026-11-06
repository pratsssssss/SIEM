"""Windows, checkpoints, pagination, failures and duplicate suppression."""
import tempfile
import unittest
from pathlib import Path

import helpers
from helpers import BASE, FakeStore, event, rule
from siem_detector import runner
from siem_detector.custom import CustomRule, Finding
from siem_detector.state import State

MIN = 60000


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / 'state.db')
        self.state = State(self.path)
        self.addCleanup(lambda: self.state.close())
        self.now = BASE
        self.store = FakeStore()
        self.logs = []

    def engine(self, rules=None, **settings):
        values = dict(overlap_seconds=300, settle_seconds=30, initial_lookback_seconds=3600, page_size=10)
        values.update(settings)
        return runner.Engine(rules or [rule()], self.store, self.state, runner.Settings(**values), clock=lambda: self.now, log=self.logs.append)

    def alerts(self):
        return self.state.db.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]

    def watermark(self, rule_id='rule-1'):
        return self.state.db.execute('SELECT watermark_ms FROM rule_state WHERE rule_id = ?', (rule_id,)).fetchone()[0]


class Windows(Base):
    def test_first_run_reads_only_the_initial_lookback(self):
        self.store.docs = [event(1, BASE - 2 * 3600000), event(2, BASE - 1800000)]
        self.engine().run_rule(rule())
        self.assertEqual(self.alerts(), 1)

    def test_recent_events_wait_for_the_settle_time(self):
        self.store.docs = [event(1, BASE - 10000)]
        self.engine().run_rule(rule())
        self.assertEqual(self.alerts(), 0)
        self.now += MIN
        self.engine().run_rule(rule())
        self.assertEqual(self.alerts(), 1)

    def test_event_exactly_on_the_end_boundary_is_taken_next_run(self):
        self.store.docs = [event(1, BASE - 30000)]
        self.engine().run_rule(rule())
        self.assertEqual(self.alerts(), 0, 'the end of the window is exclusive')
        self.now += MIN
        self.engine().run_rule(rule())
        self.assertEqual(self.alerts(), 1)

    def test_event_exactly_on_the_watermark_is_not_missed(self):
        engine = self.engine()
        engine.run_rule(rule())
        mark = self.watermark()
        self.store.docs = [event(1, mark)]
        self.now += MIN
        engine.run_rule(rule())
        self.assertEqual(self.alerts(), 1)

    def test_late_visible_event_inside_the_overlap_is_found(self):
        engine = self.engine()
        engine.run_rule(rule())
        self.now += MIN
        # Indexed two minutes ago, but only searchable now, behind the watermark.
        self.store.docs = [event(1, self.watermark() - 2 * MIN)]
        engine.run_rule(rule())
        self.assertEqual(self.alerts(), 1)

    def test_event_older_than_the_overlap_is_not_reread(self):
        engine = self.engine()
        engine.run_rule(rule())
        self.now += MIN
        self.store.docs = [event(1, self.watermark() - 6 * MIN)]
        engine.run_rule(rule())
        self.assertEqual(self.alerts(), 0)

    def test_old_event_time_is_still_seen_because_ingestion_time_drives_the_window(self):
        engine = self.engine()
        engine.run_rule(rule())
        self.now += 2 * MIN
        self.store.docs = [event(1, self.now - MIN, when='2026-10-20T00:00:00.000Z')]
        engine.run_rule(rule())
        self.assertEqual(self.alerts(), 1)

    def test_query_bounds_are_bound_to_the_window(self):
        self.engine().run_rule(rule())
        bounds = self.store.calls[0]['query']['bool']['filter'][1]['range']['event.ingested']
        self.assertEqual(bounds['lt'], BASE - 30000)
        self.assertEqual(bounds['gte'], BASE - 3600000 - 300000)

    def test_no_run_before_the_interval(self):
        engine = self.engine()
        engine.run_due()
        calls = len(self.store.calls)
        self.now += 59000
        engine.run_due()
        self.assertEqual(len(self.store.calls), calls)
        self.now += 2000
        engine.run_due()
        self.assertGreater(len(self.store.calls), calls)

    def test_disabled_rule_never_runs(self):
        self.engine([rule(enabled=False)]).run_due()
        self.assertEqual(self.store.calls, [])


class Pagination(Base):
    def test_all_pages_are_read_with_search_after(self):
        self.store.docs = [event(i, BASE - 100000 - i) for i in range(35)]
        self.engine().run_rule(rule())
        self.assertEqual(self.alerts(), 35)
        self.assertEqual(len(self.store.calls), 4)
        self.assertIn('search_after', self.store.calls[1])

    def test_equal_timestamps_do_not_lose_events_across_pages(self):
        self.store.docs = [event(i, BASE - 100000) for i in range(25)]
        self.engine().run_rule(rule())
        self.assertEqual(self.alerts(), 25)

    def test_cap_resumes_where_it_stopped(self):
        self.store.docs = [event(i, BASE - 200000 + i * 1000) for i in range(35)]
        engine = self.engine(max_events_per_run=10, overlap_seconds=0)
        self.now += 0
        engine.run_rule(rule())
        self.assertEqual(self.alerts(), 10)
        self.assertLess(self.watermark(), BASE - 30000)
        for _ in range(6):
            engine.run_rule(rule())
        self.assertEqual(self.alerts(), 35)

    def test_overlap_fuller_than_the_cap_still_advances(self):
        self.store.docs = [event(i, BASE - 100000) for i in range(25)]
        engine = self.engine(max_events_per_run=5)
        engine.run_rule(rule())
        first = self.watermark()
        engine.run_rule(rule())
        self.assertEqual(self.alerts(), 25)
        self.assertGreater(self.watermark(), first)


class Failures(Base):
    def test_query_failure_keeps_the_watermark_and_loses_nothing(self):
        engine = self.engine()
        engine.run_rule(rule())
        mark = self.watermark()
        self.store.docs = [event(1, mark + 5000)]
        self.now += MIN
        self.store.fail_next = 1
        engine.run_rule(rule())
        self.assertEqual(self.watermark(), mark)
        self.assertEqual(self.alerts(), 0)
        self.now += MIN
        engine.run_rule(rule())
        self.assertEqual(self.alerts(), 1)

    def test_failure_on_a_later_page_keeps_the_watermark(self):
        self.store.docs = [event(i, BASE - 100000 + i) for i in range(15)]
        engine = self.engine()
        original = self.store.search

        def fail_second(index, body):
            if 'search_after' in body:
                raise helpers.SearchError('HTTP 503')
            return original(index, body)
        self.store.search = fail_second
        engine.run_rule(rule())
        self.assertEqual(self.alerts(), 0, 'a partial window must not produce alerts or move on')
        self.store.search = original
        self.now += 10 * MIN
        engine.run_rule(rule())
        self.assertEqual(self.alerts(), 15)

    def test_failures_back_off_and_are_reported(self):
        engine = self.engine()
        self.store.fail_next = 5
        engine.run_rule(rule())
        first = self.state.db.execute('SELECT next_run_ms, failures FROM rule_state').fetchone()
        self.assertEqual(first, (BASE + 60000, 1))
        self.now += 60000
        engine.run_rule(rule())
        second = self.state.db.execute('SELECT next_run_ms, failures FROM rule_state').fetchone()
        self.assertEqual(second, (self.now + 120000, 2))
        self.assertEqual(engine.health()['status'], 'WARN')

    def test_success_clears_the_failure_count(self):
        engine = self.engine()
        self.store.fail_next = 1
        engine.run_rule(rule())
        engine.run_rule(rule())
        self.assertEqual(self.state.db.execute('SELECT failures FROM rule_state').fetchone()[0], 0)

    def test_one_failing_rule_does_not_stop_the_others(self):
        good = rule('good')
        bad = rule('bad')
        self.store.docs = [event(1, BASE - 100000)]
        original = self.store.search
        seen = []

        def search(index, body):
            seen.append(1)
            if len(seen) == 1:
                raise helpers.SearchError('HTTP 400')
            return original(index, body)
        self.store.search = search
        self.engine([bad, good]).run_due()
        self.assertEqual(self.alerts(), 1)

    def test_broken_custom_rule_is_contained(self):
        class Broken(CustomRule):
            id, title, description, level = 'broken', 'B', 'B', 'low'

            def query(self):
                return {'match_all': {}}

            def detect(self, events):
                raise KeyError('a bug in the rule')
        self.store.docs = [event(1, BASE - 100000)]
        custom = Broken()
        made = rule('broken', kind='custom', custom=custom, query=custom.query(), lookback_seconds=0)
        engine = self.engine([made])
        engine.run_rule(made)
        self.assertEqual(self.state.db.execute('SELECT failures FROM rule_state').fetchone()[0], 1)


class Duplicates(Base):
    def test_repeated_runs_over_the_overlap_make_one_alert(self):
        self.store.docs = [event(1, BASE - 100000)]
        engine = self.engine()
        for _ in range(5):
            engine.run_rule(rule())
            self.now += MIN
        self.assertEqual(self.alerts(), 1)

    def test_restart_resumes_from_the_checkpoint(self):
        self.store.docs = [event(1, BASE - 100000)]
        self.engine().run_rule(rule())
        mark = self.watermark()
        self.state.close()
        self.state = State(self.path)
        self.now += MIN
        self.engine().run_rule(rule())
        self.assertEqual(self.alerts(), 1)
        self.assertGreater(self.watermark(), mark)

    def test_crash_before_commit_repeats_the_window_with_the_same_ids(self):
        self.store.docs = [event(1, BASE - 100000)]
        engine = self.engine()
        original = self.state.commit_run

        def crash(*args, **kwargs):
            raise SystemExit('power cut')
        self.state.commit_run = crash
        with self.assertRaises(SystemExit):
            engine.run_rule(rule())
        self.state.commit_run = original
        self.assertEqual(self.alerts(), 0)
        engine.run_rule(rule())
        self.assertEqual(self.alerts(), 1)

    def test_alert_and_watermark_commit_together(self):
        self.store.docs = [event(1, BASE - 100000)]
        engine = self.engine()
        engine.run_rule(rule())
        self.state.db.execute('DROP TABLE alerts')
        self.state.db.executescript('CREATE TABLE alerts (x)')
        self.store.docs = [event(2, BASE + 1000)]
        self.now += 2 * MIN
        mark = self.watermark()
        with self.assertRaises(Exception):
            engine.run_rule(rule())
        self.assertEqual(self.watermark(), mark)

    def test_grouping_makes_one_alert_per_group_and_window(self):
        grouped = rule(group_by=['host.name'], group_window_seconds=3600)
        self.store.docs = [event(i, BASE - 100000 + i) for i in range(20)]
        self.engine([grouped]).run_rule(grouped)
        self.assertEqual(self.alerts(), 1)
        self.assertEqual(self.state.rules()[0]['events'], 20)

    def test_grouped_alert_is_not_repeated_by_a_later_event_in_the_window(self):
        grouped = rule(group_by=['host.name'], group_window_seconds=3600)
        self.store.docs = [event(1, BASE - 100000)]
        engine = self.engine([grouped])
        engine.run_rule(grouped)
        self.now += MIN
        self.store.docs.append(event(2, BASE + 1000))
        engine.run_rule(grouped)
        self.assertEqual(self.alerts(), 1)
        self.assertEqual(self.state.rules()[0]['suppressed'], 1)

    def test_custom_finding_repeats_are_ignored(self):
        class Always(CustomRule):
            id, title, description, level = 'always', 'A', 'A', 'low'
            lookback_seconds = 3600

            def query(self):
                return {'match_all': {}}

            def detect(self, events):
                return [Finding(key=events[0]['_id'], events=events[:1], facts={'n': 1})] if events else []
        self.store.docs = [event(1, BASE - 100000)]
        custom = Always()
        made = rule('always', kind='custom', custom=custom, query=custom.query(), lookback_seconds=3600)
        engine = self.engine([made])
        for _ in range(3):
            engine.run_rule(made)
            self.now += MIN
        self.assertEqual(self.alerts(), 1)

    def test_prune_keeps_unfinished_alerts(self):
        self.store.docs = [event(1, BASE - 100000)]
        self.engine().run_rule(rule())
        self.assertEqual(self.state.prune(BASE + 1), 0)
        alert_id = self.state.pending()[0][0]
        self.state.mark_index(alert_id)
        self.state.mark_kafka(alert_id)
        self.assertEqual(self.state.prune(BASE + 1), 1)


class Health(Base):
    def test_old_unpublished_alerts_are_critical(self):
        self.store.docs = [event(1, BASE - 100000)]
        engine = self.engine()
        engine.run_rule(rule())
        self.now += 11 * MIN
        self.assertEqual(engine.health()['status'], 'CRITICAL')

    def test_healthy(self):
        engine = self.engine()
        engine.run_rule(rule())
        self.assertEqual(engine.health()['status'], 'OK')

    def test_report_is_written_atomically(self):
        target = Path(self.tmp.name) / 'detector.json'
        runner.write_report({'status': 'OK'}, [target])
        self.assertIn('OK', target.read_text())
        self.assertFalse(target.with_suffix('.tmp').exists())


if __name__ == '__main__':
    unittest.main()
