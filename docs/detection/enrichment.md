# Enrichment

**Status:** Deployed. Results are in the Phase 10 acceptance report. Decisions: D8, [D28 to D30](../adr/0010-threat-enrichment.md). Sources, scoring and privacy are in [Threat intelligence](threat-intelligence.md).

## Data flow

```text
siem-alerts-*     new alerts, every 20 s        -> indicators -> local data + external providers
siem-windows-*    Sysmon 1, 3 and 22, local only -> indicators -> local data
                                                                    |
                                                  scoring, one verdict per indicator
                                                                    |
                                                  siem-enrichment-YYYY.MM
```

Nothing is written back to events or alerts, and nothing reaches Kafka. If this service stops, ingestion and detection continue, and it catches up from a watermark.

## Parts

| File, under `enricher/siem_enricher/` | Job |
|---|---|
| `indicators.py` | Extraction, validation, URL sanitizing, and `external_allowed`, the only gate on what leaves |
| `feeds.py` | Feed download and parsing, GeoIP, name signals |
| `providers.py` | One adapter per external provider |
| `engine.py` | Lookup path: cache, limits, retries, circuit breaker, bounded workers |
| `score.py` | Verdicts and reasons |
| `store.py` | SQLite: intelligence, cache, quotas, jobs, watermarks |
| `service.py` | Reads alerts and events, writes results |
| `untrusted.py` | Filters everything a provider says |
| `web.py` | The only outside connection |
| `cli.py` | Commands |

## Results

### Alert document

The document's ID is the `alert_id`, so a repeat replaces it, and never duplicates it.

| Field | Meaning |
|---|---|
| `doc_type` | `alert` |
| `alert_id`, `alert_ref` | The alert, and where it is stored |
| `rule_id`, `rule_name`, `alert_severity` | Copied from the alert. Severity is recorded, and not changed |
| `source_event_ids`, `raw_event_refs` | Copied from the alert |
| `status` | `complete`, `partial`, `failed` or `no_indicators` |
| `events_available` | How many source events still existed |
| `summary` | `highest_verdict`, `indicator_count`, `by_verdict`, `max_score` |
| `threat.enrichments` | ECS: hostile indicators, as `indicator` and `matched` |
| `indicators` | Every indicator, with its verdict, reasons and sources |

### Event document

Written only when an event's indicator is `malicious`, `suspicious` or `conflicting`. It has `doc_type: event`, with `event_id` and `event_index` linking to the event.

### Indicator

| Field | Meaning |
|---|---|
| `type`, `value`, `field` | `ip`, `domain`, `url` or `sha256`, its normal form, and where it was found |
| `from_restricted_text` | True if it came from free text, so it was not eligible for external lookup |
| `external_checked` | Whether an external provider was asked |
| `verdict`, `score`, `reasons` | See [scoring](threat-intelligence.md#scoring) |
| `independent_sources` | Publishers with a hostile answer |
| `complete`, `sources_answered`, `sources_failed` | Whether every source answered |
| `context` | Country, region, ASN, organization, and tags such as `tor-exits` |
| `sources` | Each source's answer, except plain no-match |

## Failure behaviour

| Failure | Behaviour |
|---|---|
| Provider down or slow | Retries with backoff, then marks it failed. After 5 failures in a row it is paused for 15 minutes |
| Provider rate limit | Paused for its `Retry-After`. Local limits also apply, by the minute and by the day |
| Bad key | Paused for an hour, with no retries |
| Malformed answer | A failure, not clean |
| Some lookups failed | `status: partial`, retried up to 5 times with growing gaps. The document stays visible as partial |
| OpenSearch down | The job waits. Watermarks do not move |
| Feed fails, or shrinks by half | The previous data stays. `feeds list` shows the error |
| Feed stale | It stops answering, so it cannot make anything look clean |
| Enricher stopped | Alerts and events flow as normal |

## Commands

As the service account, in WSL: `sudo -u siem-enricher siem-enricher <command>`.

| Task | Command |
|---|---|
| Status | `status` |
| Provider health | `providers` |
| List feeds | `feeds list` |
| Update feeds that are due | `feeds update` |
| Force all feeds | `feeds update --force` |
| One feed | `feeds update --name openphish` |
| Remove a feed's data | `feeds purge --name <feed>` |
| Cache statistics | `cache stats` |
| Clear expired entries | `cache expire` |
| Invalidate | `cache clear --provider virustotal`, or `--value 8.8.8.8`, or both, or neither for all |
| Look up, locally | `lookup 8.8.8.8` |
| Look up, with providers | `lookup example.com --external` |
| Enrich one alert again | `enrich-alert <alert id>` |
| Preview a backfill | `backfill both --hours 168 --dry-run` |
| Run a backfill | `backfill both --hours 168` |

| Service | Command |
|---|---|
| Start and stop with the stack | `deploy\windows\siem-up.ps1`, `siem-down.ps1` |
| Alone | `sudo systemctl start siem-enricher`, `sudo systemctl stop siem-enricher` |
| Logs | `journalctl -u siem-enricher` |
| Feed timer | `systemctl status siem-enricher-feeds.timer` |

A backfill is local only for events. For alerts it uses the same rules as live, and a job that already exists is not repeated. A dry run reads and counts, and sends and writes nothing. A backfill does not move the live watermark. After adding a file to the owner folder, restart the service.

**Tests:** from `tests/enrichment`, with the wheels on `PYTHONPATH`: `python3 -m unittest test_indicators test_providers test_engine`.

## Install

As root in WSL, from the repository root, with OpenSearch up:

```text
bash deploy/opensearch/create-enricher-user.sh
bash deploy/opensearch/apply-index-policy.sh
bash deploy/wsl/install-enricher.sh <folder holding the wheels in enricher/requirements.lock>
sudo -u siem-enricher siem-enricher feeds update --force
```

## Monitoring

The service writes `enricher.json` every minute, and the Windows task `SIEM alert watch` reads a summary. `WARN` means a feed is stale or a provider is paused. A failing enrichment does not raise an alert status, because it does not affect detection, but it shows in `status`.

_Internal test reports and planning records mentioned here are not published with Version 1._
