# Detection Engine

**Status:** Deployed. Results are in the Phase 9 acceptance report. Decisions: D5, D7, [D6, D25 and D26](../adr/0009-detection-engine.md). Rule authors should read [Writing rules](writing-rules.md).

## Data flow

```text
siem-windows-*  (ECS events, in OpenSearch)
   |  read by siem_detector, one bounded window per rule
   v
Rules: 17 Sigma, compiled to Query DSL, and 5 custom Python
   |  deterministic alert IDs
   v
SQLite state: alerts and the watermark commit in one transaction
   |  outbox, retried until delivered
   +--> OpenSearch siem-alerts-YYYY.MM   full evidence, 90 days
   +--> Kafka siem-alerts                allowlisted fields, restricted values as digests
```

## Parts

| File, under `detector/siem_detector/` | Job |
|---|---|
| `ecs.py` | What this SIEM stores: log sources, field mapping, the Kafka allowlist |
| `sigma_compile.py` | pySigma parses and validates. A custom backend writes Query DSL |
| `custom.py` | The interface for Python rules |
| `rules.py` | Loads the catalog, and refuses anything inconsistent |
| `runner.py` | Windows, paging, retries, grouping, health |
| `state.py` | Watermarks, alert store and outbox, in SQLite |
| `alerts.py` | The alert contract and the Kafka-safe form |
| `backends.py` | OpenSearch client, Kafka producer, outbox delivery |
| `dsl_eval.py` | Evaluates a query offline, for tests |
| `cli.py` | Commands |

Rules know nothing about infrastructure or publishing. `backends.py` is the only file that talks to OpenSearch or Kafka.

## How a run works

1. The window is from the watermark, less a 5-minute overlap, to 30 seconds before now. The window uses `event.ingested`, so events delayed by an outage are still seen, even when their event time is old.
2. Results are paged with `search_after`, sorted by `event.ingested` then `event.id`. A partial or timed-out response is a failure.
3. Alert IDs are hashes of the rule and the event or finding, so a repeat of the overlap makes the same ID, and the store ignores it.
4. New alerts and the new watermark commit in one SQLite transaction. A crash repeats the window, and cannot skip events or lose a detection.
5. If a rule fails, its watermark stays, and it retries with backoff, up to an hour. Other rules continue.

A run stops after 20,000 events, resumes at once, and always moves past the old watermark.

## Publishing

| Step | Behaviour |
|---|---|
| Evidence | Created in OpenSearch with `_create`, so a repeat is harmless and cannot overwrite |
| Kafka | Idempotent producer, `acks=all`, keyed by alert ID |
| Lost delivery report | The end of the topic is read first, and alerts already there are marked sent, not resent |
| Kafka or OpenSearch down | Alerts stay in the outbox and retry. Evidence and Kafka retry separately |
| Local full text | Removed from SQLite once OpenSearch holds it |

## Alert

| Field | Meaning |
|---|---|
| `alert_id` | Deterministic, 32 hexadecimal characters |
| `rule_id`, `rule_name`, `detection_type` | The rule, and `sigma` or `custom` |
| `severity`, `confidence` | `informational` to `critical`, and `low` to `high` |
| `timestamp`, `detected_at` | First event, and when the detector made the alert |
| `host`, `user`, `source_ip` | When the events have them |
| `description` | The rule's own text |
| `event_count`, `source_event_ids`, `raw_event_refs` | True count, and up to 50 references. Beyond that, the first 49 and the last |
| `mitre` | `tactics` and `techniques`, from the rule's tags |
| `evidence` | Matched field values, time range and rule-specific facts |
| `evidence_ref` | Where the full alert is in OpenSearch |

### What Kafka gets

Kafka has no authentication, and Phase 8 proved it holds no restricted plaintext ([D22](../adr/0006-sensitive-telemetry-handling.md)). So fields on an allowlist stay readable, and any other value becomes `{"withheld": true, "sha256": ..., "length": ...}`. A new field is withheld until someone adds it to `ecs.KAFKA_SAFE_FIELDS`. Investigators read the full alert through `evidence_ref`.

Alert evidence keeps its own copy of the matched values for 90 days, because the events themselves expire after 7.

## Commands

In WSL, as `siem-detector`: `sudo -u siem-detector siem-detector <command>`.

| Command | Does |
|---|---|
| `validate` | Compiles every rule and checks the catalog |
| `validate --attack` | Also checks ATT&CK tags. **Downloads MITRE data** |
| `list` | Every rule, with state, severity and interval |
| `show <rule>` | The compiled query |
| `test` | Runs rule fixtures, with no services. Needs `tests/detection/fixtures.yml` |
| `status` | Health, watermarks and counts |
| `once` | One pass, then publishes |
| `rewind <rule or all> --hours N` | Re-reads history. Existing alert IDs are ignored, so it cannot duplicate |
| `run` | The service |

## Start and stop

| Action | Command |
|---|---|
| Whole stack, including the detector | `deploy\windows\siem-up.ps1` |
| Whole stack | `deploy\windows\siem-down.ps1` |
| Detector only | `sudo systemctl start siem-detector` and `sudo systemctl stop siem-detector` |
| Logs | `journalctl -u siem-detector` |

The detector needs OpenSearch and Kafka. If either is down, it keeps running and retries.

## Install

As root in WSL, from the repository root, with OpenSearch up:

```text
bash deploy/opensearch/create-detector-user.sh
bash deploy/opensearch/apply-index-policy.sh
bash deploy/wsl/install-detector.sh <folder holding the wheels in detector/requirements.lock>
```

To fetch the wheels, on any host:

```text
python -m pip download -d <folder> --platform manylinux2014_x86_64 --platform manylinux_2_28_x86_64 --python-version 3.12 --only-binary=:all: pysigma confluent-kafka
```

The installer checks each wheel's SHA-256 against the lock file, and unpacks it without running it.

## Enrichment

The engine knows nothing about enrichment, and alerts do not wait for it. [Enrichment](enrichment.md) reads `siem-alerts-*`, and writes verdicts to its own index, linked by `alert_id`.

## Monitoring

The service writes `detector.json` every minute. The Windows task `SIEM alert watch` reads a summary copy, and notifies on `WARN`, `CRITICAL` or a stale report.

| Status | Meaning |
|---|---|
| `WARN` | A rule is failing, or is over an hour behind |
| `CRITICAL` | Alerts have been unpublished for over 10 minutes |
| `CHECK_FAILED` | The report is missing or old |

## Security

| Control | Detail |
|---|---|
| OpenSearch account | `siem_detector` searches `siem-windows-*` and writes `siem-alerts-*`, and nothing else |
| Service | Unprivileged, no capabilities, `ProtectSystem=strict`, 256 MiB limit, 50 % of a core |
| Network | Loopback only. pySigma's ATT&CK download is off in the service |
| State file | Owner only, because pending alerts hold restricted text |

_Internal test reports and planning records mentioned here are not published with Version 1._
