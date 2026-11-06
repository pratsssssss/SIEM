"""The metric catalogue. A metric that is not described here is not published, and tests hold that to be true.

`kind` is `direct` (counted by the component), `sampled` (computed from a bounded sample), or `estimate` (a stand-in,
named as such). Rates need two samples: the first cycle after any restart shows nothing rather than zero.
"""

CYCLE = '60 s'
EVENTS = 'Every 3 cycles'
SLOW = 'Every 15 cycles'


def row(unit, source, method, interval, window, kind, limits):
    return {'unit': unit, 'source': source, 'method': method, 'interval': interval, 'window': window, 'kind': kind, 'limits': limits}


CATALOG = {
    'raw_received_per_second': ('Events the aggregator took from Kafka', row('events/s', 'Vector aggregator', '`siem_raw` received counter, per second', CYCLE, '1 cycle', 'direct', 'Counts Kafka records, and one record is one event here')),
    'verified_per_second': ('Events the verifier accepted', row('events/s', 'Seal verifier', '`accepted` counter, per second', CYCLE, '1 cycle', 'direct', 'Resets when the verifier restarts')),
    'normalized_per_second': ('Events normalization passed on', row('events/s', 'Vector aggregator', 'Default output of both normalize transforms', CYCLE, '1 cycle', 'direct', 'Excludes events sent to the dead letter route')),
    'indexed_per_second': ('Events OpenSearch acknowledged', row('events/s', 'Vector aggregator', 'Sent counters of both event sinks', CYCLE, '1 cycle', 'direct', 'A batch counts when acknowledged')),
    'opensearch_indexing_per_second': ('Documents indexed by the node', row('documents/s', 'OpenSearch', 'Node `index_total`, per second', CYCLE, '1 cycle', 'direct', 'Includes every index on the node, also this monitor\'s and the audit log')),
    'opensearch_index_ms_per_document': ('Mean time to index one document', row('ms', 'OpenSearch', 'Change in `index_time_in_millis` over change in `index_total`', CYCLE, '1 cycle', 'direct', 'A node-wide mean. It is not an end-to-end latency')),
    'windows_latency_p50_seconds': ('Median time from a Windows event to normalization', row('s', 'Stored events', '`event.ingested` minus `@timestamp`, on a sample', EVENTS, '10 minutes, newest 200 events', 'sampled', 'Ends at normalization: no timestamp records the moment of indexing. A replay of old logs raises it')),
    'windows_latency_p95_seconds': ('95th percentile of the same', row('s', 'Stored events', 'As above', EVENTS, '10 minutes, newest 200 events', 'sampled', 'As above')),
    'linux_latency_p50_seconds': ('Median time from a Linux event to normalization', row('s', 'Stored events', '`event.ingested` minus `@timestamp`, on a sample', EVENTS, '10 minutes, newest 200 events', 'sampled', 'As for Windows')),
    'linux_latency_p95_seconds': ('95th percentile of the same', row('s', 'Stored events', 'As above', EVENTS, '10 minutes, newest 200 events', 'sampled', 'As above')),
    'raw_lag_messages': ('Raw messages not yet committed by the aggregator', row('messages', 'Kafka', 'End offsets minus committed offsets, group `siem-aggregator`', CYCLE, 'Instant', 'direct', 'Commits follow batches, so a few hundred is normal under load')),
    'alert_lag_messages': ('Alert messages not yet committed by the correlator', row('messages', 'Kafka', 'End offset minus committed offset, group `siem-correlator`', CYCLE, 'Instant', 'direct', 'No lag exists for the detector or enricher, which poll OpenSearch')),
    'raw_produced_per_second': ('Messages entering the raw topic', row('messages/s', 'Kafka', 'Change in end offsets, per second', CYCLE, '1 cycle', 'direct', 'Both agents together. Kafka cannot separate them without reading messages')),
    'oldest_unread_seconds': ('Age of the oldest unread raw message', row('s', 'Kafka expiry check', 'Its report, which reads one record timestamp', 'Every 5 minutes', 'Instant', 'sampled', 'As old as the check, so up to 5 minutes behind')),
    'windows_buffered_events': ('Events in the Windows agent disk buffer', row('events', 'Windows agent metrics', 'Via the alert watcher report', 'Every 5 minutes', 'Instant', 'sampled', 'Absent when the report is stale')),
    'linux_buffered_events': ('Events in the Linux agent disk buffer', row('events', 'Linux agent metrics', '`kafka_raw` buffer gauge', CYCLE, 'Instant', 'direct', '')),
    'verification_rejected_per_second': ('Events refused for a security or quality reason', row('events/s', 'Seal verifier', 'All reasons except accepted, replay, and infrastructure faults', CYCLE, '1 cycle', 'direct', 'A forged event raises this. It does not mean the pipeline failed')),
    'replay_rejected_per_second': ('Duplicates refused', row('events/s', 'Seal verifier', '`replayed` plus `replay_conflict`', CYCLE, '1 cycle', 'direct', 'A redelivery after a restart raises this too')),
    'verifier_faults_per_second': ('Requests refused by a fault', row('requests/s', 'Seal verifier', '`busy`, `read_failed`, `journal_failed`, `downstream_unavailable`', CYCLE, '1 cycle', 'direct', 'Vector retries these, so nothing is lost by them')),
    'normalize_failed_percent': ('Share of events normalization could not pass on', row('%', 'Vector aggregator', 'Dropped output over input, both transforms', CYCLE, '5 minutes', 'direct', 'Needs 20 events in the window. Fewer gives no value')),
    'deadletter_documents': ('Documents in the dead letter indices', row('documents', 'OpenSearch', 'Index statistics', CYCLE, 'Instant', 'direct', 'Falls when retention removes an index')),
    'deadletter_per_hour': ('Growth of the same', row('documents/h', 'OpenSearch', 'Positive change, per hour', CYCLE, '1 cycle', 'direct', 'Age of the oldest is not collected')),
    'detection_lag_seconds': ('Now minus the newest rule watermark', row('s', 'Detector report', 'Its per-rule watermarks', CYCLE, 'Instant', 'direct', 'Rules run on their own schedule, so the value moves in steps')),
    'detection_oldest_watermark_seconds': ('Now minus the oldest rule watermark', row('s', 'Detector report', 'As above', CYCLE, 'Instant', 'direct', 'Shows one rule falling behind')),
    'alert_delay_seconds': ('Median time from the triggering event to the alert', row('s', 'Stored alerts', '`detected_at` minus `timestamp`, newest 20 alerts', EVENTS, 'Newest alerts, of any age', 'sampled', 'Depends on rule windows, and is only as recent as the last alert')),
    'enrichment_delay_seconds': ('Median time from alert to enrichment', row('s', 'Stored enrichment', '`enriched_at` minus `@timestamp`, newest 20', EVENTS, 'Newest records, of any age', 'sampled', 'Only as recent as the last alert')),
    'correlation_backlog': ('Alerts held but not analysed', row('alerts', 'Correlator report', '`pending` count', CYCLE, 'Instant', 'direct', 'A delay in seconds is not recorded anywhere, so this and the alert lag stand in for it')),
    'path_queue': ('Seeds awaiting a path', row('seeds', 'Path report', '`queue`', CYCLE, 'Instant', 'direct', '')),
    'path_oldest_pending_seconds': ('Age of the oldest due seed', row('s', 'Path report', '`oldest_queued_ms`', CYCLE, 'Instant', 'direct', 'A retry resets the due time')),
    'path_delay_seconds': ('Time since the last path was built', row('s', 'Path report', '`last_build_ms`', CYCLE, 'Instant', 'direct', 'Grows in a quiet period, so it is shown and never judged alone')),
    'memory_available_percent': ('Memory available in WSL', row('%', 'Kernel', '`/proc/meminfo`', CYCLE, 'Instant', 'direct', '')),
    'swap_used_percent': ('Swap in use', row('%', 'Kernel', '`/proc/meminfo`', CYCLE, 'Instant', 'direct', '')),
    'memory_pressure_full': ('Time all tasks stalled on memory', row('%', 'Kernel', '`/proc/pressure/memory`, `full avg60`', CYCLE, '60 s', 'direct', '')),
    'cpu_pressure_some': ('Time some task waited for a CPU', row('%', 'Kernel', '`/proc/pressure/cpu`, `some avg60`', CYCLE, '60 s', 'direct', '')),
    'windows_disk_free_gib': ('Free space on C:, which holds the WSL disk', row('GiB', 'Kernel', '`statvfs` on `/mnt/c`', CYCLE, 'Instant', 'direct', 'The virtual disk reports its own far larger limit, so C: is what matters')),
    'opensearch_heap_percent': ('Java heap in use', row('%', 'OpenSearch', 'Node statistics', CYCLE, 'Instant', 'direct', 'A sawtooth is normal')),
    'opensearch_store_gib': ('Size of event indices', row('GiB', 'OpenSearch', 'Index statistics', CYCLE, 'Instant', 'direct', 'Primaries only')),
    'monitor_cycle_ms': ('Length of a monitoring cycle', row('ms', 'This service', 'Measured by itself', CYCLE, 'Instant', 'direct', '')),
    'monitor_rss_mib': ('Memory of this service', row('MiB', 'This service', '`/proc/self/status`', CYCLE, 'Instant', 'direct', '')),
    'monitor_cpu_percent': ('CPU of this service', row('%', 'This service', '`os.times`', CYCLE, '1 cycle', 'direct', '')),
}

UNAVAILABLE = {
    'Correlation delay in seconds': 'No record states when the correlator took an alert. `correlation_backlog` and `alert_lag_messages` stand in',
    'Time from event to index': '`event.ingested` is set at normalization, before indexing. The Vector sink acknowledgement has no per-event time',
    'End-to-end event loss': 'Counts differ for filtering, rejection, routing, retention and duplicates, so a difference between them is not loss, and none is computed',
    'Windows agent errors between watcher runs': 'Metrics stay on Windows loopback, unreachable from WSL under NAT networking. They are read every 5 minutes by the watcher',
    'Oldest age in the dead letter indices': 'Would need a search over dead letter content. Growth is shown instead',
    'Enrichment pending count': 'The enricher reports completed jobs, not those waiting',
    'Correlator audit chain': 'Needs the analyst socket, which this service must not join. `siem-health validate --chains` asks as the analyst running it',
    'Producer errors at the broker': 'The agents count their own send errors, and the broker has no per-client error counter here',
}


def describe(name):
    meaning, details = CATALOG[name]
    return {'name': name, 'definition': meaning, **details}
