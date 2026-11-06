# Phase 8 Final Architecture

**Status:** as built, and accepted on 2026-10-31. Decisions: [D22](../adr/0006-sensitive-telemetry-handling.md), [D23](../adr/0007-seal-verifier.md), [D24](../adr/0008-whole-event-authentication.md). Results: acceptance report.

## Data path

```text
Windows Event Logs
  -> Vector agent, LocalSystem service
       protect: rebuild fields from the raw XML, redact, cap, seal restricted fields with AES-256-CTR and a field MAC
       envelope: canonical body, whole-event HMAC-SHA-256
       disk buffer, 1 GiB, blocks when full
  -> Kafka siem-raw-logs, 127.0.0.1:9092, 72 hours
  -> Vector aggregator
       ingest: size check only
  -> seal verifier, 127.0.0.1:9610, mutual TLS 1.3
       envelope MAC, schema, field MACs, decrypt, identity journal
  -> Vector aggregator, 127.0.0.1:9611, mutual TLS 1.2
       normalize: ECS
  -> OpenSearch, 127.0.0.1:9200
       siem-windows-YYYY.MM.DD        by event time, 7 days
       siem-deadletter-YYYY.MM.DD     ciphertext and routing facts, 7 days
  -> Detection engine, on a schedule. See docs/detection/detection-engine.md
       siem-alerts-YYYY.MM            full evidence, 90 days
       Kafka siem-alerts              allowlisted fields, restricted values as digests
  -> Enrichment, read-only on the above. See docs/detection/enrichment.md
       siem-enrichment-YYYY.MM        verdicts linked by alert_id and event.id, 90 days
  -> Correlation, reading the above and Kafka. See docs/detection/incident-management.md
       siem-incidents-YYYY.MM, siem-incident-audit-YYYY.MM     incidents and their audit trail
  -> Asset inventory, reading the above and local snapshots. Nothing depends on it. See docs/detection/asset-inventory.md
       siem-assets-current, siem-asset-relationships, siem-asset-history-YYYY.MM, siem-asset-audit-YYYY.MM
```

## Trust boundaries

| Boundary | Control |
|---|---|
| Windows user to agent files | ACLs: `SYSTEM` and Administrators only, owned by Administrators |
| Agent to the network | Windows Firewall rule A: `vector.exe` may reach only `127.0.0.1` |
| Agent to Kafka | Loopback, no authentication. **The envelope MAC is what protects the content**. Kafka JMX is off |
| Kafka to aggregator | Nothing in a message is trusted until the verifier passes it |
| Aggregator to verifier | Mutual TLS. The aggregator holds no field keys |
| Verifier to aggregator | Mutual TLS, with a separate CA, so Vector's own certificate cannot post events |
| Aggregator to OpenSearch | TLS to the private CA. `siem_ingest` can only write two index families |
| Detector to OpenSearch | TLS to the private CA. `siem_detector` can search events and write alert evidence, nothing else |
| Detector to Kafka | Loopback, no authentication, so restricted values never go there |
| Enricher to OpenSearch | TLS to the private CA. `siem_enricher` can read events and alerts, and write only its own index |
| Correlator to OpenSearch | TLS to the private CA. `siem_correlator` reads identity fields of events under field level security, reads alerts and enrichment, and writes only its own indices |
| Asset service to OpenSearch | TLS to the private CA. `siem_asset` reads named fields of events, alerts, enrichment and incidents under field level security, and writes only its own indices |
| WSL2 Linux agent | A second Vector process with its own key, `k2`, which the verifier accepts on Linux channels only. Same seal, MAC, disk buffer and Kafka topic as Windows. Events go to `siem-linux-*`. See docs/pipeline/wsl2-linux-telemetry.md |
| Attack path service | `siem_path` reads named fields of events, alerts, enrichment and incidents under field level security, reads current assets, and writes only its own indices. See docs/detection/attack-paths.md |
| Pipeline health service | `siem_health` reads cluster statistics and three named event fields under field level security, and writes only `siem-health-*`. It holds no socket access and no Kafka group. Each service writes one status report to a folder only it can write and only this service can read. Nothing depends on it. See [Pipeline Health](../operations/pipeline-health.md) |
| Analyst dashboard | `siem-dashboard` serves HTTPS on loopback. `siem_dashboard` searches named fields under field level security and cannot write. Changes go only through the correlator, asset and path sockets, by a fixed list of actions. Nothing depends on it. See [the dashboard guide](../operations/dashboard.md) |
| Enricher to the internet | HTTPS to listed hosts only, enforced in the application (D29). Only permitted indicators leave |

## Components

| Component | Runs as | Limit | Failure effect |
|---|---|---|---|
| Vector agent | `LocalSystem`, automatic | Disk buffer 1 GiB | Windows logs hold events until it returns |
| Kafka 4.4.0 | `kafka` | 1 GiB per partition, 72 hours | Agent buffers |
| Seal verifier | `siem-verifier` | 512 MiB | Aggregator retries. Offsets stay uncommitted |
| Vector aggregator | `vector` | 1 GiB | Kafka holds events |
| OpenSearch 3.9.0 | `opensearch` | 12 GB budget, enforced by the disk guard | Aggregator retries. Offsets stay uncommitted |

## Protections

| Risk | Control |
|---|---|
| Secrets in logs | Redaction on the agent, then sealing, before the disk buffer |
| Forged or altered events | Whole-event MAC with `crypto/subtle.ConstantTimeCompare` |
| Replay or changed identity | Durable journal, in force across restarts |
| One bad event stalling ingestion | The refused event is isolated and dead-lettered |
| Storage failure destroying events | Verifier holds, so offsets are not committed |
| `C:` filling up | Disk guard stops ingestion at 20 GiB free |
| Budget overrun | Disk guard stops ingestion at 12 GiB of OpenSearch data |
| Dead-letter flood | 7-day retention, and the guard stops at 1 GiB |
| Unread events expiring | Expiry check, with alerts at 24 and 48 hours |
| Lost command-line characters | Fields rebuilt from raw XML on the agent |
| A monitor hiding an outage | Monitor units never start the services they watch |
| Deleted audit evidence | No delete policy, read-only after 2 days, wildcard deletes refused |

## Monitoring

| Report | Written by | Seen through |
|---|---|---|
| `kafka-expiry.json` | WSL timer, 15 minutes | Windows notification, `alerts.log`, journald, failed unit |
| `disk-guard.json` | WSL timer, 5 minutes | Same |
| Delivery status | `check-vector-delivery.ps1`, on demand | Output and exit status |

The Windows task `SIEM alert watch` reads the reports every five minutes while the operator is logged on. It has a logon trigger and a timed trigger, because the logon trigger alone repeats only from the next logon.

## Differences from the original design

| Original | As built | Why |
|---|---|---|
| Aggregator decrypts in VRL | Separate Go verifier | VRL has no constant-time compare |
| Field MACs only | Field MACs and whole-event MAC | Unsealed fields could be altered |
| In-memory replay cache | Durable journal | A restart reopened the window |
| Rules A, B and C | Rule A only | Windows Firewall does not filter loopback, so B and C did nothing |
| `AES-256-CTR` in VRL | `AES-256-CTR-BE` | The first is a deprecated non-standard counter |
| `event_data` used as parsed | Rebuilt from raw XML on the agent | Vector loses `&`, `<` and `>` |

_Internal test reports and planning records mentioned here are not published with Version 1._
