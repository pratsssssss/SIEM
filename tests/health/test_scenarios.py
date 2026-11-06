"""The failure and recovery scenarios, on fixtures, through the real monitor. Numbers follow the phase brief."""
import json
import unittest
import unittest.mock

from helpers import CYCLE, NOW, World
from siem_health.assess import DEGRADED, HEALTHY, NOT_APPLICABLE, UNHEALTHY, UNKNOWN

CORE_UNITS = ('kafka.service', 'seal-verifier.service', 'vector.service', 'opensearch.service', 'siem-detector.service')


class Base(unittest.TestCase):
    def world(self, *args, warm=8, **kwargs):
        world = World(*args, **kwargs)
        self.addCleanup(world.close)
        world.tick(warm)
        return world


class Normal(Base):
    def test_01_a_working_pipeline_is_healthy_and_trusted(self):
        w = self.world()
        pipeline = w.pipeline()
        self.assertEqual(pipeline['status'], HEALTHY)
        self.assertEqual(pipeline['coverage'], 'trusted')
        self.assertIsNone(pipeline['bottleneck'])
        for name in ('windows-agent', 'linux-agent', 'kafka', 'verifier', 'aggregator', 'normalization', 'opensearch', 'detector', 'enricher', 'correlator', 'assets', 'attack-paths', 'host-wsl', 'housekeeping', 'health-monitor'):
            self.assertEqual(w.status(name), HEALTHY, (name, w.body(name)['reason']))

    def test_every_assessment_has_time_evidence_freshness_and_reason(self):
        w = self.world()
        for name, row in w.store.components().items():
            self.assertTrue(row['reason'], name)
            self.assertEqual(row['observed_ms'], w.now)
            self.assertIn(row['freshness'], ('fresh', 'stale', 'unavailable'))
            self.assertIn(row['certainty'], ('high', 'medium', 'low'))
            for item in row['evidence']:
                self.assertTrue({'source', 'observed_ms', 'freshness', 'value'} <= set(item))

    def test_all_the_pipeline_rates_are_populated_from_counters(self):
        w = self.world()
        _, metrics = w.store.latest_samples()
        for name in ('raw_received_per_second', 'verified_per_second', 'normalized_per_second', 'indexed_per_second', 'raw_produced_per_second'):
            self.assertAlmostEqual(metrics[name]['value'], 1.0, places=2, msg=name)
        self.assertEqual(metrics['raw_lag_messages']['value'], 0)
        self.assertEqual(metrics['windows_latency_p95_seconds']['value'], 2.0)


class CollectionFaults(Base):
    def test_02_windows_agent_stopped(self):
        w = self.world()
        w.win_service = 'Stopped'
        w.tick()
        self.assertEqual(w.status('windows-agent'), UNHEALTHY)
        self.assertEqual(w.condition('windows-agent'), 'service_unavailable')
        w.tick()
        self.assertEqual(w.status('source:windows.sysmon'), UNHEALTHY)
        self.assertEqual(w.status('linux-agent'), HEALTHY)
        self.assertEqual(w.status('source:linux.system'), HEALTHY)
        self.assertEqual(w.pipeline()['status'], UNHEALTHY)
        self.assertEqual(w.pipeline()['bottleneck'], 'windows-agent')

    def test_02b_windows_recovers_and_says_so(self):
        w = self.world()
        w.win_service = 'Stopped'
        w.tick(3)
        w.win_service = 'Running'
        w.tick(4)
        self.assertEqual(w.status('windows-agent'), HEALTHY)
        self.assertEqual(w.pipeline()['status'], HEALTHY)
        self.assertFalse([e for e in w.store.episodes(only_open=True) if e['component'] == 'windows-agent'])

    def test_a_replay_of_retained_windows_logs_is_named_as_delay_not_called_live(self):
        w = self.world()
        w.latency = 2000.0
        w.tick(5)
        self.assertEqual(w.status('windows-agent'), DEGRADED)
        self.assertEqual(w.condition('windows-agent'), 'delayed')
        self.assertIn('retained logs', w.body('windows-agent')['reason'])

    def test_a_running_agent_with_no_delivery_is_told_apart(self):
        w = self.world()
        w.frozen.add('win_delivery')
        w.tick(32)
        self.assertEqual(w.status('windows-agent'), UNHEALTHY)
        self.assertEqual(w.condition('windows-agent'), 'not_processing')

    def test_03_linux_agent_stopped(self):
        w = self.world()
        w.units['siem-linux-agent.service'] = 'inactive'
        w.tick()
        self.assertEqual(w.status('linux-agent'), UNHEALTHY)
        self.assertEqual(w.status('windows-agent'), HEALTHY)
        w.tick()
        self.assertEqual(w.status('source:linux.system'), UNHEALTHY)
        self.assertEqual(w.status('source:windows.sysmon'), HEALTHY)

    def test_a_running_linux_agent_kafka_will_not_acknowledge(self):
        w = self.world()
        w.frozen.add('linux_delivery')
        w.tick(13)
        self.assertEqual(w.status('linux-agent'), UNHEALTHY)
        self.assertEqual(w.condition('linux-agent'), 'not_processing')

    def test_23_a_late_windows_report_with_events_arriving_stays_healthy_and_says_what_is_missing(self):
        w = self.world()
        w.body_changes['windows-agent'] = {'checked_ms': NOW}
        w.tick(20)
        self.assertEqual(w.status('windows-agent'), HEALTHY)
        self.assertEqual(w.body('windows-agent')['certainty'], 'medium')
        self.assertTrue([m for m in w.body('windows-agent')['missing'] if 'Windows report' in m])

    def test_23b_a_late_report_with_no_events_either_is_unknown_never_unhealthy(self):
        w = self.world()
        w.body_changes['windows-agent'] = {'checked_ms': NOW}
        w.quiet |= {'windows.sysmon', 'windows.security'}
        w.tick(40)
        self.assertEqual(w.status('windows-agent'), UNKNOWN)
        self.assertEqual(w.condition('windows-agent'), 'monitoring_unavailable')


class TransportFaults(Base):
    def test_04_kafka_unavailable(self):
        w = self.world()
        w.units['kafka.service'] = 'failed'
        w.fail['kafka'] = 'refused'
        w.tick()
        self.assertEqual(w.status('kafka'), UNHEALTHY)
        self.assertEqual(w.condition('kafka'), 'service_unavailable')
        self.assertEqual(w.pipeline()['root_cause'], 'kafka')

    def test_04b_consumers_blame_kafka_rather_than_themselves(self):
        w = self.world()
        w.units['kafka.service'] = 'failed'
        w.fail['kafka'] = 'refused'
        w.frozen.add('linux_delivery')
        w.tick(14)
        self.assertEqual(w.condition('linux-agent'), 'downstream_unavailable')
        self.assertEqual(w.status('linux-agent'), DEGRADED)
        self.assertEqual(w.status('correlator'), DEGRADED)
        self.assertEqual(w.pipeline()['root_cause'], 'kafka')

    def test_05_a_rising_backlog_is_seen_rising_then_recovering(self):
        w = self.world()
        w.rate = 2000
        w.frozen.add('raw_commit')
        w.lag['raw'] = 6000
        w.tick(1)
        w.frozen.discard('raw_commit')
        w.body_changes['kafka-expiry'] = {}
        w.tick(0)
        # Lag rises while commits still move, so this is delay and not a stall.
        for lag in (7000, 9000, 12000, 15000):
            w.lag['raw'] = lag
            w.tick()
        self.assertEqual(w.status('aggregator'), DEGRADED)
        self.assertEqual(w.condition('aggregator'), 'backlog_increasing')
        for lag in (13000, 11000, 9000, 7000):
            w.lag['raw'] = lag
            w.tick()
        self.assertEqual(w.condition('aggregator'), 'backlog_recovering')
        w.lag['raw'] = 0
        w.tick(4)
        self.assertEqual(w.status('aggregator'), HEALTHY)

    def test_kafka_lag_is_not_claimed_without_a_committed_offset(self):
        w = self.world()
        original = w.kafka_view

        def view():
            data = original()
            data['groups']['siem-aggregator'] = {'known': False, 'reason': 'no committed offset'}
            return data
        w.kafka_view = view
        w.tick(3)
        self.assertIn('consumer lag', w.body('aggregator')['missing'])
        self.assertEqual(w.store.series('raw_lag_messages', w.now - 2 * CYCLE), [], 'no number is better than a made-up one')

    def test_expired_messages_are_data_loss(self):
        w = self.world()
        w.body_changes['kafka-expiry'] = {'lost_latched': {'0': 5}}
        w.tick(3)
        self.assertEqual(w.status('kafka'), UNHEALTHY)
        self.assertEqual(w.condition('kafka'), 'data_loss')

    def test_a_missing_topic_is_found(self):
        w = self.world()
        w.fail['no_incident_topic'] = True
        w.tick()
        self.assertEqual(w.status('kafka'), UNHEALTHY)
        self.assertEqual(w.condition('kafka'), 'configuration')


class VerifierAndNormalization(Base):
    def test_06_verifier_unavailable(self):
        w = self.world()
        w.units['seal-verifier.service'] = 'inactive'
        w.fail['verifier'] = 'refused'
        w.frozen |= {'raw_commit', 'pipeline'}
        w.tick(13)
        self.assertEqual(w.status('verifier'), UNHEALTHY)
        self.assertEqual(w.status('aggregator'), DEGRADED)
        self.assertEqual(w.condition('aggregator'), 'downstream_unavailable')
        self.assertEqual(w.pipeline()['root_cause'], 'verifier')

    def test_07_aggregator_unavailable(self):
        w = self.world()
        w.units['vector.service'] = 'failed'
        w.fail['aggregator'] = 'refused'
        w.tick(2)
        self.assertEqual(w.status('aggregator'), UNHEALTHY)
        self.assertEqual(w.status('normalization'), UNKNOWN, 'cannot be judged, which is not the same as failing')

    def test_07b_a_request_cut_off_by_the_aggregator_stopping_is_not_the_verifiers_fault(self):
        w = self.world()
        w.units['vector.service'] = 'inactive'
        w.fail['aggregator'] = 'refused'
        w.reasons['read_failed'] = 1
        w.tick(1)
        w.tick(3)
        self.assertEqual(w.condition('verifier'), 'downstream_unavailable')
        self.assertEqual(w.pipeline()['root_cause'], 'aggregator')

    def test_08_normalization_failure(self):
        w = self.world()
        for _ in range(8):
            w.counts['dropped'] += 20
            w.tick()
        self.assertEqual(w.status('normalization'), UNHEALTHY)

    def test_08b_a_small_failure_rate_is_degraded(self):
        w = self.world()
        for _ in range(8):
            w.counts['dropped'] += 2
            w.tick()
        self.assertEqual(w.status('normalization'), DEGRADED)

    def test_a_forged_event_is_a_number_and_not_a_fault(self):
        w = self.world()
        w.reasons['bad_seal'] = 0
        for _ in range(6):
            w.reasons['bad_seal'] += 10
            w.tick()
        self.assertEqual(w.status('verifier'), HEALTHY)
        self.assertEqual(w.pipeline()['status'], HEALTHY)
        self.assertGreater(w.store.latest_samples()[1]['verification_rejected_per_second']['value'], 0)

    def test_27_duplicates_are_counted_apart_from_rejections(self):
        w = self.world()
        w.reasons['replayed'] = 0
        for _ in range(4):
            w.reasons['replayed'] += 60
            w.tick()
        metrics = w.store.latest_samples()[1]
        self.assertEqual(metrics['replay_rejected_per_second']['value'], 1.0)
        self.assertEqual(metrics['verification_rejected_per_second']['value'], 0)
        self.assertEqual(w.status('verifier'), HEALTHY)

    def test_verifier_infrastructure_faults_do_lower_health(self):
        w = self.world()
        w.reasons['journal_failed'] = 0
        for _ in range(4):
            w.reasons['journal_failed'] += 3
            w.tick()
        self.assertEqual(w.status('verifier'), DEGRADED)

    def test_dead_letters_are_shown_without_failing_anything(self):
        w = self.world()
        for _ in range(4):
            w.search['dead'] += 5
            w.tick()
        self.assertEqual(w.status('normalization'), HEALTHY)
        self.assertEqual(w.store.latest_samples()[1]['deadletter_documents']['value'], 20)


class StorageFaults(Base):
    def test_09_opensearch_unavailable(self):
        w = self.world()
        w.units['opensearch.service'] = 'failed'
        w.fail.update(opensearch='refused', events='refused', analysis='refused', ship='refused')
        w.tick(4)
        self.assertEqual(w.status('opensearch'), UNHEALTHY)
        self.assertEqual(w.status('detector'), DEGRADED)
        self.assertEqual(w.condition('detector'), 'downstream_unavailable')
        self.assertEqual(w.status('source:windows.sysmon'), UNKNOWN, 'freshness cannot be read, so it is not known')
        self.assertEqual(w.pipeline()['root_cause'], 'opensearch')
        self.assertGreater(w.store.outbox_size(), 0, 'history waits locally')

    def test_09b_a_refused_connection_with_the_unit_active(self):
        w = self.world()
        w.fail['opensearch'] = 'refused'
        w.tick(3)
        self.assertEqual(w.status('opensearch'), UNHEALTHY)

    def test_10_opensearch_write_rejection(self):
        w = self.world()
        for _ in range(4):
            w.search['rejected'] += 5
            w.tick()
        self.assertEqual(w.status('opensearch'), DEGRADED)
        self.assertEqual(w.condition('opensearch'), 'resource_pressure')

    def test_a_red_cluster_is_unhealthy_at_once(self):
        w = self.world()
        w.search['status'] = 'red'
        w.tick()
        self.assertEqual(w.status('opensearch'), UNHEALTHY)

    def test_yellow_for_a_system_replica_on_one_node_is_healthy_and_says_so(self):
        w = self.world()
        w.search.update(status='yellow', unassigned_other=1)
        w.tick(5)
        self.assertEqual(w.status('opensearch'), HEALTHY)
        self.assertIn('replica', w.body('opensearch')['reason'])

    def test_an_unassigned_siem_shard_is_degraded(self):
        w = self.world()
        w.search.update(status='yellow', unassigned_siem=1)
        w.tick(3)
        self.assertEqual(w.status('opensearch'), DEGRADED)

    def test_retention_failure_is_seen(self):
        w = self.world(warm=14)
        w.retention_failed = 2
        w.tick(16)
        self.assertEqual(w.status('opensearch'), DEGRADED)


class AfterAnOutage(Base):
    def outage(self, w, unit='opensearch.service', key='opensearch', cycles=2):
        w.units[unit] = 'failed'
        w.fail[key] = 'refused'
        w.tick(cycles)
        del w.units[unit], w.fail[key]

    def test_errors_left_by_kafka_are_blamed_on_kafka(self):
        w = self.world()
        self.outage(w, 'kafka.service', 'kafka')
        w.fail['sink_errors'] = 14
        w.tick(3)
        self.assertEqual(w.condition('aggregator'), 'downstream_unavailable')
        self.assertIn('kafka outage', w.body('aggregator')['reason'])

    def test_rules_retrying_after_opensearch_are_named_and_not_called_broken(self):
        w = self.world()
        self.outage(w)
        far = w.now + 10 ** 8
        w.body_changes['detector'] = {'rules': [{'rule_id': 'a', 'watermark_ms': far, 'failures': 3}, {'rule_id': 'b', 'watermark_ms': far, 'failures': 3}]}
        w.tick(3)
        self.assertEqual(w.status('detector'), DEGRADED)
        self.assertEqual(w.condition('detector'), 'downstream_unavailable')
        self.assertIn('retry delay', w.body('detector')['reason'])

    def test_the_excuse_runs_out(self):
        w = self.world()
        self.outage(w)
        w.tick(11)
        w.body_changes['detector'] = {'rules': [{'rule_id': 'a', 'watermark_ms': w.now + 10 ** 8, 'failures': 3}]}
        w.tick(3)
        self.assertEqual(w.status('detector'), UNHEALTHY, 'an old outage cannot explain a failure forever')

    def test_with_only_downstream_blame_a_cause_is_still_named(self):
        w = self.world()
        self.outage(w, cycles=1)
        far = w.now + 10 ** 8
        w.body_changes['detector'] = {'rules': [{'rule_id': 'a', 'watermark_ms': far, 'failures': 3}]}
        w.tick(3)
        self.assertEqual(w.pipeline()['root_cause'], 'detector')

    def test_an_episode_closes_when_a_source_returns_to_quiet(self):
        w = self.world()
        w.units['siem-linux-agent.service'] = 'inactive'
        w.tick(3)
        self.assertTrue(w.store.open_episode('source:linux.package'))
        w.units.clear()
        w.tick(6)
        self.assertEqual(w.status('source:linux.package'), UNKNOWN)
        self.assertIsNone(w.store.open_episode('source:linux.package'))


class AnalysisFaults(Base):
    def test_11_detector_stopped(self):
        w = self.world()
        w.units['siem-detector.service'] = 'inactive'
        w.tick()
        self.assertEqual(w.status('detector'), UNHEALTHY)
        self.assertEqual(w.pipeline()['status'], UNHEALTHY)

    def test_12_watermark_not_progressing(self):
        w = self.world()
        w.watermark_at = w.now
        w.tick(13)
        self.assertEqual(w.status('detector'), UNHEALTHY)
        self.assertEqual(w.condition('detector'), 'not_processing')
        self.assertIn('no rule has advanced', w.body('detector')['reason'])

    def test_12b_a_detector_that_is_behind_but_moving_is_delayed(self):
        w = self.world()
        for _ in range(4):
            w.body_changes['detector'] = {'rules': [{'rule_id': 'a', 'watermark_ms': w.now + CYCLE - 900000 + w.ticks, 'failures': 0}]}
            w.tick()
        self.assertEqual(w.status('detector'), DEGRADED)
        self.assertEqual(w.condition('detector'), 'delayed')

    def test_some_rules_failing_is_degraded_and_all_is_unhealthy(self):
        w = self.world()
        w.body_changes['detector'] = {'rules': [{'rule_id': 'a', 'watermark_ms': NOW + 10 ** 7, 'failures': 2}, {'rule_id': 'b', 'watermark_ms': NOW + 10 ** 7, 'failures': 0}]}
        w.tick(3)
        self.assertEqual(w.status('detector'), DEGRADED)
        w.body_changes['detector'] = {'rules': [{'rule_id': 'a', 'watermark_ms': NOW + 10 ** 7, 'failures': 2}]}
        w.tick(3)
        self.assertEqual(w.status('detector'), UNHEALTHY)

    def test_13_enrichment_unavailable(self):
        w = self.world()
        w.units['siem-enricher.service'] = 'failed'
        w.tick()
        self.assertEqual(w.status('enricher'), UNHEALTHY)
        self.assertEqual(w.pipeline()['status'], DEGRADED, 'enrichment supports detection and does not carry it')

    def test_13b_stale_feeds_and_open_breakers(self):
        w = self.world()
        w.body_changes['enricher'] = {'feeds': [{'feed': 'one', 'enabled': True, 'fresh': False, 'last_error': None}]}
        w.tick(3)
        self.assertEqual(w.condition('enricher'), 'source_unavailable')
        w.body_changes['enricher'] = {'providers': [{'provider': 'x', 'open_until_ms': w.now + 10 ** 7}]}
        w.tick(3)
        self.assertIn('circuit breaker', w.body('enricher')['reason'])

    def test_14_correlator_stopped(self):
        w = self.world()
        w.units['siem-correlator.service'] = 'inactive'
        w.tick()
        self.assertEqual(w.status('correlator'), UNHEALTHY)

    def test_15_correlation_backlog(self):
        w = self.world()
        w.body_changes['correlator'] = {'alerts': {'pending': 600}}
        w.tick(3)
        self.assertEqual(w.status('correlator'), DEGRADED)
        self.assertEqual(w.store.latest_samples()[1]['correlation_backlog']['value'], 600)

    def test_15b_a_stalled_correlator_is_running_but_not_processing(self):
        w = self.world()
        w.frozen.add('alert_commit')
        w.tick(13)
        self.assertEqual(w.status('correlator'), UNHEALTHY)
        self.assertEqual(w.condition('correlator'), 'not_processing')

    def test_16_asset_service_unavailable(self):
        w = self.world()
        w.units['siem-asset.service'] = 'inactive'
        w.tick()
        self.assertEqual(w.status('assets'), UNHEALTHY)
        self.assertEqual(w.pipeline()['status'], DEGRADED)

    def test_a_review_backlog_is_not_a_fault(self):
        w = self.world()
        w.body_changes['asset'] = {'status': 'WARN', 'security_changes_unreviewed': 9}
        w.tick(3)
        self.assertEqual(w.status('assets'), HEALTHY)

    def test_17_attack_path_service_unavailable(self):
        w = self.world()
        w.units['siem-path.service'] = 'failed'
        w.tick()
        self.assertEqual(w.status('attack-paths'), UNHEALTHY)
        self.assertEqual(w.status('detector'), HEALTHY)

    def test_18_attack_path_backlog(self):
        w = self.world()
        for size in (300, 400, 500, 600):
            w.body_changes['path'] = {'queue': size, 'oldest_queued_ms': w.now - 2000000}
            w.tick()
        self.assertEqual(w.status('attack-paths'), DEGRADED)
        self.assertEqual(w.condition('attack-paths'), 'backlog_increasing')

    def test_expired_evidence_is_not_a_fault_and_altered_evidence_is(self):
        w = self.world()
        w.body_changes['path'] = {'evidence': {'unavailable': 400, 'changed': 0}}
        w.tick(4)
        self.assertEqual(w.status('attack-paths'), HEALTHY)
        self.assertIn('expired by retention', w.body('attack-paths')['reason'])
        w.body_changes['path'] = {'evidence': {'unavailable': 400, 'changed': 2}}
        w.tick(3)
        self.assertEqual(w.status('attack-paths'), DEGRADED)
        self.assertIn('not expiry', w.body('attack-paths')['reason'])


class Components(Base):
    """What is assessed is exactly the Version 1 set, a missing core unit is a fault, and a retired component does not linger."""

    def test_a_core_unit_that_is_not_found_is_a_fault(self):
        w = self.world(warm=0)
        w.absent.add('siem-asset.service')
        w.tick(8)
        self.assertEqual(w.status('assets'), UNHEALTHY)
        self.assertNotEqual(w.pipeline()['status'], HEALTHY)

    def test_a_stored_row_for_a_retired_component_is_removed(self):
        w = self.world()
        record, body = w.store.records()['kafka'], w.store.component('kafka')
        with w.store.transaction():
            w.store.save_component('retired-component', record, body, w.now)
        self.assertIn('retired-component', w.store.components())
        w.tick(1)
        self.assertNotIn('retired-component', w.store.components())
        self.assertNotIn('retired-component', w.store.records())
        self.assertEqual(w.pipeline()['status'], HEALTHY)

    def test_views_list_history_only_for_what_is_assessed(self):
        from siem_health.cli import View
        w = self.world()
        with w.store.transaction():
            w.store.add_transition('retired-component', 'HEALTHY', 'UNKNOWN', w.now, {'reason': 'x'})
        self.assertIn('retired-component', [r['component'] for r in w.store.transitions(None, 0)])
        view = View(w.config, clock=lambda: w.now)
        self.addCleanup(view.store.close)
        shown = {r['component'] for r in view.history(None, 0)}
        self.assertNotIn('retired-component', shown)
        self.assertIn('kafka', {c for c in view.assessed()})
        failures = view.failures(0)
        self.assertFalse([r for r in failures['open'] + failures['recent'] if r['component'] == 'retired-component'])

    def test_history_is_kept_when_a_row_is_removed(self):
        w = self.world()
        before = len(w.store.transitions(None, 0))
        record, body = w.store.records()['kafka'], w.store.component('kafka')
        with w.store.transaction():
            w.store.save_component('retired-component', record, body, w.now)
        w.tick(1)
        self.assertGreaterEqual(len(w.store.transitions(None, 0)), before)


class HostFaults(Base):
    def test_19_disk_pressure(self):
        w = self.world()
        w.memory['disk'] = 25
        w.tick(3)
        self.assertEqual(w.status('host-wsl'), DEGRADED)
        w.memory['disk'] = 15
        w.tick(3)
        self.assertEqual(w.status('host-wsl'), UNHEALTHY)
        self.assertEqual(w.condition('host-wsl'), 'resource_pressure')

    def test_19b_the_disk_guard_stopping_ingest_is_named(self):
        w = self.world()
        w.units['vector.service'] = 'inactive'
        w.body_changes['disk-guard'] = {'ingest_stopped': True}
        w.tick()
        self.assertEqual(w.condition('aggregator'), 'resource_pressure')
        self.assertIn('disk guard', w.body('aggregator')['reason'])

    def test_20_memory_pressure(self):
        w = self.world()
        w.memory['available'] = 0.08
        w.tick(3)
        self.assertEqual(w.status('host-wsl'), DEGRADED)
        w.memory.update(available=0.04)
        w.tick(3)
        self.assertEqual(w.status('host-wsl'), UNHEALTHY)
        w.memory.update(available=0.5, pressure=30.0)
        w.tick(5)
        self.assertEqual(w.status('host-wsl'), UNHEALTHY)
        self.assertIn('stalled on memory', w.body('host-wsl')['reason'])

    def test_a_restart_loop_is_found(self):
        w = self.world()
        for count in range(1, 5):
            w.restarts['siem-detector.service'] = count
            w.tick()
        self.assertEqual(w.status('detector'), UNHEALTHY)
        self.assertIn('restarts', w.body('detector')['reason'])

    def test_a_stopped_timer(self):
        w = self.world()
        w.units['siem-disk-guard.timer'] = 'inactive'
        w.tick()
        self.assertEqual(w.status('housekeeping'), DEGRADED)


class TimeAndGaps(Base):
    def test_21_suspension_is_a_gap_and_no_failure_is_invented(self):
        w = self.world()
        w.suspend(180)
        w.tick()
        marks = [t for t in w.store.transitions('monitoring') if t.get('gap') == 'machine_suspended']
        self.assertEqual(len(marks), 1)
        self.assertEqual(marks[0]['seconds'], 10860)
        self.assertEqual(w.status('detector'), HEALTHY)
        self.assertNotEqual(w.pipeline()['status'], UNHEALTHY)

    def test_21b_on_resume_stale_reports_give_unknown_inside_the_grace_period(self):
        w = self.world()
        stale = w.now
        for name in ('detector', 'correlator', 'windows-agent'):
            w.body_changes[name] = {'checked_ms': stale}
        w.quiet |= {'windows.sysmon', 'windows.security'}
        w.suspend(180)
        w.tick(1)
        w.tick(1)
        self.assertEqual(w.body('detector')['condition'], 'host_offline')
        self.assertEqual(w.status('detector'), UNKNOWN)
        self.assertEqual(w.body('windows-agent')['condition'], 'host_offline')
        w.body_changes.clear()
        w.quiet.clear()
        w.tick(4)
        self.assertEqual(w.status('detector'), HEALTHY)

    def test_21c_a_real_outage_after_resume_still_shows(self):
        w = self.world()
        w.suspend(180)
        w.units['siem-detector.service'] = 'failed'
        w.tick()
        self.assertEqual(w.status('detector'), UNHEALTHY, 'systemd saying stopped is proof, whatever the clock did')

    def test_22_host_shutdown_is_recorded_as_a_period_nothing_was_seen(self):
        w = self.world()
        w.stop_monitor(600)
        with unittest.mock.patch.object(w.monitor, 'inspect_time', wraps=w.monitor.inspect_time):
            w.tick()
        gaps = w.store.transitions('monitoring')
        self.assertEqual(len(gaps), 1)
        self.assertIn(gaps[0]['gap'], ('monitor_restarted', 'wsl_restarted'))
        self.assertNotEqual(w.pipeline()['status'], UNHEALTHY)

    def test_22b_a_distribution_that_restarted_is_told_from_a_service_that_did(self):
        w = self.world()
        w.stop_monitor(30)
        with unittest.mock.patch('siem_health.service.distro_started_ms', return_value=w.now - 60000):
            w.tick()
        self.assertEqual(w.store.transitions('monitoring')[0]['gap'], 'wsl_restarted')

    def test_22c_the_start_time_of_this_distribution_can_be_read(self):
        from siem_health.service import distro_started_ms
        import time
        started = distro_started_ms()
        self.assertTrue(started and started <= time.time() * 1000)

    def test_24_clock_skew_a_future_report_is_not_believed(self):
        w = self.world()
        w.body_changes['windows-agent'] = {'checked_ms': w.now + 10 ** 7}
        w.tick(3)
        self.assertIn('future', ' '.join(w.body('windows-agent')['missing']))

    def test_24b_a_future_event_is_not_taken_as_fresh(self):
        w = self.world(warm=3)
        w.newest['linux.package'] = w.now + 10 ** 8
        w.tick(6)
        self.assertEqual(w.status('source:linux.package'), UNKNOWN)
        self.assertIn('future', w.body('source:linux.package')['reason'])

    def test_24c_small_skew_is_tolerated(self):
        w = self.world()
        w.body_changes['detector'] = {}
        original = w.report_body

        def ahead(name):
            body = original(name)
            return {**body, 'checked_ms': body['checked_ms'] + 30000} if name == 'detector' else body
        w.report_body = ahead
        w.tick(3)
        self.assertEqual(w.status('detector'), HEALTHY)

    def test_clock_going_back_is_a_gap_and_writes_cleanly(self):
        w = self.world()
        w.now -= 600000
        w.tick()
        self.assertTrue([t for t in w.store.transitions('monitoring') if t.get('gap') == 'clock_went_back'])

    def test_32_a_quiet_period_is_not_a_failure(self):
        w = self.world()
        w.rate = 0
        w.quiet |= set(w.newest)
        w.counts['win_received'] = w.counts['win_received']
        w.tick(50)
        pipeline = w.pipeline()
        self.assertNotEqual(pipeline['status'], UNHEALTHY)
        for name in ('source:windows.sysmon', 'source:windows.security'):
            self.assertEqual(w.status(name), UNKNOWN)
        for name in ('kafka', 'verifier', 'aggregator', 'opensearch', 'detector', 'correlator', 'linux-agent'):
            self.assertIn(w.status(name), (HEALTHY, UNKNOWN), name)
            self.assertNotEqual(w.status(name), UNHEALTHY)
        self.assertIn(pipeline['coverage'], ('limited', 'unknown'), 'it must not claim coverage it cannot show')

    def test_32b_sparse_sources_are_unknown_and_do_not_limit_coverage(self):
        w = self.world()
        self.assertEqual(w.status('source:linux.package'), UNKNOWN)
        self.assertEqual(w.pipeline()['coverage'], 'trusted')
        self.assertIn('linux.package', w.pipeline()['sources_quiet'])


class Hysteresis(Base):
    def test_one_bad_cycle_changes_nothing(self):
        w = self.world()
        w.memory['available'] = 0.08
        w.tick()
        self.assertEqual(w.status('host-wsl'), HEALTHY)
        self.assertEqual(w.body('host-wsl')['pending'], DEGRADED)
        self.assertEqual(w.body('host-wsl')['durability'], 'transient')
        w.memory['available'] = 0.5
        w.tick()
        self.assertEqual(w.status('host-wsl'), HEALTHY)
        self.assertEqual(len(w.store.transitions('host-wsl')), 1, 'only the first observation')

    def test_flapping_input_produces_few_transitions(self):
        w = self.world()
        for turn in range(60):
            w.memory['available'] = 0.08 if turn % 2 else 0.5
            w.tick()
        self.assertLessEqual(len(w.store.transitions('host-wsl')), 2)

    def test_slow_flapping_is_damped_after_repeats(self):
        w = self.world()
        count = 0
        for _ in range(12):
            w.memory['available'] = 0.08
            w.tick(3)
            w.memory['available'] = 0.5
            w.tick(4)
            count += 1
        since = w.now - 30 * CYCLE
        self.assertLessEqual(w.store.recent_transitions('host-wsl', since), 8)

    def test_recovery_needs_more_cycles_than_failure(self):
        w = self.world()
        w.memory['available'] = 0.08
        w.tick(2)
        self.assertEqual(w.status('host-wsl'), DEGRADED)
        w.memory['available'] = 0.5
        w.tick(2)
        self.assertEqual(w.status('host-wsl'), DEGRADED)
        w.tick(1)
        self.assertEqual(w.status('host-wsl'), HEALTHY)

    def test_direct_proof_is_not_delayed(self):
        w = self.world()
        w.units['siem-detector.service'] = 'failed'
        w.tick(1)
        self.assertEqual(w.status('detector'), UNHEALTHY)

    def test_a_transition_records_all_it_should(self):
        w = self.world()
        w.units['siem-detector.service'] = 'failed'
        w.tick(1)
        row = w.store.transitions('detector', limit=1)[0]
        self.assertEqual((row['from'], row['to']), (HEALTHY, UNHEALTHY))
        self.assertEqual(row['at_ms'], w.now)
        self.assertTrue(row['reason'])
        body = w.body('detector')
        self.assertEqual(body['previous'], HEALTHY)
        self.assertEqual(body['since_ms'], w.now)

    def test_same_input_gives_same_output(self):
        a, b = self.world(), self.world()
        for w in (a, b):
            w.units['kafka.service'] = 'failed'
            w.fail['kafka'] = 'refused'
            w.tick(3)
        self.assertEqual(json.dumps(a.store.components(), sort_keys=True), json.dumps(b.store.components(), sort_keys=True))


class Persistence(Base):
    def test_25_crash_and_restart_keeps_state_and_counters(self):
        w = self.world()
        w.units['siem-detector.service'] = 'failed'
        w.tick()
        before = w.body('detector')['since_ms']
        w.stop_monitor(1)
        w.tick()
        self.assertEqual(w.status('detector'), UNHEALTHY)
        self.assertEqual(w.body('detector')['since_ms'], before, 'a restart is not a new failure')
        self.assertEqual(len([t for t in w.store.transitions('detector') if t['to'] == UNHEALTHY]), 1)

    def test_26_history_survives_and_chains(self):
        w = self.world()
        w.units['siem-asset.service'] = 'failed'
        w.tick(2)
        w.units.clear()
        w.tick(4)
        path = w.config['state_file']
        w.store.close()
        from siem_health.store import Store
        w.store = Store(path)
        rows = w.store.transitions('assets')
        self.assertEqual([r['to'] for r in reversed(rows)], [HEALTHY, UNHEALTHY, HEALTHY])
        self.assertTrue(w.store.verify_chain()['intact'])
        closed = [e for e in w.store.episodes() if e['component'] == 'assets']
        self.assertEqual(len(closed), 1)
        self.assertIsNotNone(closed[0]['ended_ms'])
        self.assertEqual(closed[0]['worst'], UNHEALTHY)

    def test_27b_a_repeated_cycle_adds_nothing(self):
        w = self.world()
        before = w.store.size()['samples']
        minute = w.now - w.now % 60000
        w.store.add_samples(minute, dict.fromkeys(('monitor_cycle_ms', 'raw_lag_messages'), 999.0))
        self.assertEqual(w.store.size()['samples'], before)
        self.assertNotEqual(dict(w.store.series('monitor_cycle_ms', minute)).get(minute), 999.0)

    def test_27c_a_replayed_report_is_refused(self):
        w = self.world()
        old = w.report_body('detector')
        w.tick(2)
        w.reports_override['detector'] = {**old, 'checked_ms': w.now - 3 * CYCLE, 'pending': 9999}
        w.tick(3)
        self.assertEqual(w.status('detector'), UNKNOWN)
        self.assertIn('replayed', ' '.join(w.body('detector')['missing']))

    def test_an_outage_of_the_store_does_not_end_the_cycle(self):
        w = self.world()
        real = w.store.save_component
        w.store.save_component = lambda *a: (_ for _ in ()).throw(OSError('disk full'))
        w.tick()
        w.store.save_component = real
        self.assertTrue(w.monitor.own['persist_failed'])
        w.tick()
        self.assertFalse(w.monitor.own['persist_failed'])

    def test_a_failed_cycle_leaves_nothing_half_written(self):
        w = self.world()
        count = w.store.size()['transitions']
        real = w.store.set_mark
        w.units['siem-detector.service'] = 'failed'

        def broken(name, value):
            if name == 'cycle':
                raise OSError('disk full')
            real(name, value)
        w.store.set_mark = broken
        w.tick()
        w.store.set_mark = real
        self.assertEqual(w.store.size()['transitions'], count)


class MonitorFaults(Base):
    def test_28_a_query_timeout_is_unknown_not_unhealthy(self):
        w = self.world()
        w.fail.update(kafka='timeout', aggregator='timeout', verifier='timeout', linux='timeout')
        w.tick(4)
        self.assertEqual(w.status('kafka'), UNKNOWN)
        self.assertEqual(w.status('verifier'), UNKNOWN)
        stats = w.store.mark('collectors')
        self.assertGreater(stats['kafka']['timeouts'], 0)

    def test_28b_an_opensearch_timeout_is_degraded_with_medium_certainty(self):
        w = self.world()
        w.fail['opensearch'] = 'timeout'
        w.tick(4)
        self.assertEqual(w.status('opensearch'), DEGRADED)
        self.assertEqual(w.body('opensearch')['certainty'], 'medium')

    def test_29_malformed_responses_are_unknown(self):
        w = self.world()
        w.fail.update(kafka='malformed', opensearch='malformed', verifier='malformed', aggregator='malformed', linux='malformed', events='malformed')
        w.tick(4)
        for name in ('kafka', 'opensearch', 'verifier', 'normalization'):
            self.assertEqual(w.status(name), UNKNOWN, name)

    def test_30_permission_denied_is_unknown(self):
        w = self.world()
        w.fail.update(opensearch='denied', events='denied')
        w.tick(4)
        self.assertEqual(w.status('opensearch'), UNKNOWN)
        self.assertEqual(w.condition('opensearch'), 'monitoring_unavailable')
        self.assertEqual(w.status('source:windows.sysmon'), UNKNOWN)

    def test_30b_systemd_unreadable_does_not_become_a_failure(self):
        w = self.world()
        w.fail['systemd'] = 'denied'
        w.tick(4)
        self.assertEqual(w.status('detector'), HEALTHY)
        self.assertIn('systemd state', w.body('detector')['missing'])

    def test_31_self_monitoring_failure_is_visible(self):
        w = self.world()
        real = w.store.save_component
        w.store.save_component = lambda *a: (_ for _ in ()).throw(OSError('disk full'))
        w.tick(2)
        w.store.save_component = real
        w.tick(3)
        self.assertEqual(w.status('health-monitor'), DEGRADED)
        self.assertIn('could not be saved', w.store.transitions('health-monitor', limit=1)[0]['reason'])
        self.assertIn('Held at DEGRADED', w.body('health-monitor')['reason'], 'a held state must not read as recovered')

    def test_many_failing_collectors_are_reported_about_itself(self):
        w = self.world()
        w.fail.update(kafka='timeout', opensearch='timeout', aggregator='timeout', linux='timeout', verifier='timeout')
        w.tick(5)
        self.assertEqual(w.status('health-monitor'), DEGRADED)

    def test_publishing_failure_leaves_a_complete_local_record(self):
        w = self.world()
        w.fail['ship'] = 'refused'
        w.units['siem-asset.service'] = 'failed'
        w.tick(3)
        self.assertEqual(w.monitor.ship_state, 'refused')
        self.assertTrue([t for t in w.store.transitions('assets') if t['to'] == UNHEALTHY])
        del w.fail['ship']
        for _ in range(20):
            w.tick()
        self.assertEqual(w.monitor.ship_state, 'ok')
        self.assertEqual(w.store.outbox_size(), 0)

    def test_the_outbox_is_bounded_and_metrics_go_first(self):
        w = self.world(extra={'bounds': {'outbox_rows': 500, 'max_response_bytes': 2000000, 'max_report_bytes': 65536, 'max_series': 6000, 'sample_events': 200, 'sample_alerts': 20, 'ship_batch': 200, 'cycle_budget_seconds': 30}})
        for number in range(600):
            w.store.queue(f'm{number}', 'metrics', 'siem-health-metrics-2026.11', {}, w.now)
        w.store.queue('t1', 'transition', 'siem-health-transitions-2026.11', {}, w.now)
        w.store.trim_outbox(500)
        self.assertEqual(w.store.outbox_size(), 500)
        self.assertIn('t1', [row[0] for row in w.store.db.execute('SELECT doc_id, 1, 2, 3 FROM outbox')])


if __name__ == '__main__':
    unittest.main()
