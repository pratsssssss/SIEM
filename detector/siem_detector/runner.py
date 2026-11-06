"""Runs each rule over the events indexed since its watermark (D5).

Windows use event.ingested, not event time, so events delayed by an outage are still seen. Each run
re-reads an overlap, and stops short of now, because a document is searchable only after a refresh.
Repeats are harmless: alert IDs are deterministic, and the store ignores an ID it already holds.
"""
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from . import alerts, ecs
from .backends import SearchError

BASE_FIELDS = ('@timestamp', 'event.id', 'event.ingested', 'winlog.channel', 'winlog.record_id', *ecs.CONTEXT_FIELDS)
SORT = [{'event.ingested': 'asc'}, {'event.id': 'asc'}]


@dataclass
class Settings:
    overlap_seconds: int = 300
    settle_seconds: int = 30
    initial_lookback_seconds: int = 3600
    page_size: int = 500
    max_events_per_run: int = 20000
    retention_days: int = 16
    max_retry_seconds: int = 3600


def now_ms():
    return int(time.time() * 1000)


class Engine:
    def __init__(self, rules, store, state, settings=None, clock=now_ms, log=None):
        self.rules = rules
        self.store = store
        self.state = state
        self.settings = settings or Settings()
        self.clock = clock
        self.log = log or (lambda text: print(text, flush=True))

    def _body(self, rule, start, end, after=None):
        names = sorted({*BASE_FIELDS, *(n.removesuffix('.keyword') for n in rule.fields)})
        body = {
            'size': self.settings.page_size, 'track_total_hits': False, 'sort': SORT, '_source': names,
            'query': {'bool': {'filter': [rule.query, {'range': {'event.ingested': {'gte': start, 'lt': end, 'format': 'epoch_millis'}}}]}},
        }
        if after:
            body['search_after'] = after
        return body

    def fetch(self, rule, start, end, watermark):
        """Pages through a window. Returns (hits, resume point, or None when complete).

        The cap only stops a run past the watermark, or a window fuller than the cap could never advance.
        """
        hits, after, last = [], None, None
        while True:
            page = self.store.search(ecs.EVENT_INDEX, self._body(rule, start, end, after))['hits']['hits']
            hits.extend(page)
            if len(page) < self.settings.page_size:
                return hits, None
            after = page[-1]['sort']
            last = after[0]
            if len(hits) >= self.settings.max_events_per_run and last > watermark:
                # The next run resumes here. The tie at this exact millisecond is re-read, and deduplicated.
                return hits, last

    def _grouped(self, rule, hits):
        groups = {}
        for hit in hits:
            when = alerts.parse_ms(hit['_source']['@timestamp'])
            bucket = when // (rule.group_window_seconds * 1000)
            key = (*[alerts.get(hit['_source'], name) for name in rule.group_by], bucket)
            groups.setdefault(key, []).append(hit)
        return [(alerts.make_id(rule.id, *key), group) for key, group in groups.items()]

    def _detections(self, rule, hits, now):
        """Returns (alert_id, hits, facts, severity) for each detection."""
        if rule.custom:
            ordered = sorted(hits, key=lambda h: (h['_source'].get('@timestamp', ''), h['_id']))
            return [(alerts.make_id(rule.id, f.key), f.events, f.facts, f.severity) for f in rule.custom.detect(ordered)]
        if rule.group_by:
            return [(alert_id, group, {}, None) for alert_id, group in self._grouped(rule, hits)]
        return [(alerts.make_id(rule.id, hit['_id']), [hit], {}, None) for hit in hits]

    def run_rule(self, rule):
        s = self.settings
        now = self.clock()
        watermark, _, failures = self.state.rule(rule.id, now, s.initial_lookback_seconds * 1000)
        end = now - s.settle_seconds * 1000
        if end <= watermark:
            return 0
        start = watermark - max(s.overlap_seconds, rule.lookback_seconds) * 1000
        began = time.monotonic()
        try:
            hits, resumed = self.fetch(rule, start, end, watermark)
            pairs = []
            for alert_id, events, facts, severity in self._detections(rule, hits, now):
                full = alerts.build(rule, events, alert_id, now, facts, severity)
                problems = alerts.validate(full)
                if problems:
                    raise ValueError(f'invalid alert: {problems}')
                pairs.append((alert_id, full, alerts.kafka_safe(full)))
        except (SearchError, ValueError, KeyError, TypeError) as error:
            # The watermark stays, so this window runs again.
            delay = min(rule.interval_seconds * 2 ** failures, s.max_retry_seconds)
            self.state.record_failure(rule.id, error, now, now + delay * 1000)
            self.log(f'rule {rule.id} failed: {error}. Retrying in {delay} s')
            return 0
        watermark_to = resumed if resumed is not None else end
        next_run = now if resumed is not None else now + rule.interval_seconds * 1000
        new, repeats = self.state.commit_run(rule.id, watermark_to, pairs, now, next_run, len(hits), int((time.monotonic() - began) * 1000))
        if new or repeats:
            self.log(f'rule {rule.id}: {len(hits)} events, {new} new alerts, {repeats} repeats ignored')
        return new

    def run_due(self):
        for rule in self.rules:
            if not rule.enabled:
                continue
            _, next_run, _ = self.state.rule(rule.id, self.clock(), self.settings.initial_lookback_seconds * 1000)
            if next_run <= self.clock():
                self.run_rule(rule)

    def health(self):
        counts = self.state.counts()
        rows = self.state.rules()
        enabled = {r.id for r in self.rules if r.enabled}
        failing = [r for r in rows if r['failures'] and r['rule_id'] in enabled]
        now = self.clock()
        behind = [r for r in rows if r['rule_id'] in enabled and now - r['watermark_ms'] > 3600000]
        age = (now - counts['oldest_pending_ms']) / 1000 if counts['oldest_pending_ms'] else 0
        status = 'OK'
        reasons = []
        if failing:
            status = 'WARN'
            reasons.append(f'{len(failing)} rules are failing')
        if behind:
            status = 'WARN'
            reasons.append(f'{len(behind)} rules are over an hour behind')
        if age > 600:
            status = 'CRITICAL'
            reasons.append(f"{counts['pending']} alerts unpublished for {int(age)} s")
        return {'status': status, 'checked_ms': now, 'message': '; '.join(reasons) or f"{len(enabled)} rules enabled, {counts['stored']} alerts held", 'rules_enabled': len(enabled), **counts, 'rules': rows}


def write_report(report, paths):
    """Atomic, so that a reader never sees half a report."""
    text = json.dumps(report, indent=1)
    # Rule errors can quote a query, so the Windows copy gets the summary only.
    short = json.dumps({k: v for k, v in report.items() if k != 'rules'}, indent=1)
    for path in paths:
        target = Path(path)
        try:
            spare = target.with_suffix('.tmp')
            spare.write_text(text if str(path).startswith('/home/') else short)
            spare.replace(target)
        except OSError as error:
            print(f'could not write {path}: {error}', file=sys.stderr, flush=True)


def serve(engine, outbox, settings, report_paths, tick=5.0, stopping=lambda: False, sleep=time.sleep):
    last_report = 0
    last_prune = 0
    while not stopping():
        try:
            engine.run_due()
            outbox.cycle(poll_seconds=min(tick, 2.0))
        except Exception as error:
            # One bad cycle must not end detection. The health report shows it.
            engine.log(f'cycle failed: {type(error).__name__}: {error}')
        now = engine.clock()
        if now - last_report >= 60000:
            write_report(engine.health(), report_paths)
            last_report = now
        if now - last_prune >= 3600000:
            engine.state.prune(now - settings.retention_days * 86400000)
            last_prune = now
        sleep(tick)
