# Vector Aggregator and Seal Verifier Deployment

**Status:** Deployed. Decisions: [D22](../adr/0006-sensitive-telemetry-handling.md), [D23](../adr/0007-seal-verifier.md) and [D24](../adr/0008-whole-event-authentication.md). Day-to-day use is in the [runbook](phase8-operations-runbook.md).

## Layout

| Use | Location | Access |
|---|---|---|
| Verifier binary | `/opt/seal-verifier/seal-verifier` | `root`, 755 |
| Field keys | `/home/linux/siem/config/verifier/field-keys.json` | `root:siem-verifier`, 640 |
| Verifier certificates | `/home/linux/siem/config/verifier/tls/` | Keys 640 to `siem-verifier` |
| Vector certificates and OpenSearch CA | `/home/linux/siem/config/vector/tls/` | Keys 640 to `vector` |
| OpenSearch password | `/home/linux/siem/config/vector/opensearch-ingest.json` | `root:vector`, 640 |
| Expiry check state | `/home/linux/siem/data/monitor/` | `linux` |

Vector cannot read the field keys.

## Ports, loopback only

| Port | Use |
|---|---|
| 9610 | Verifier, mutual TLS |
| 9611 | Vector `from_verifier`, mutual TLS |
| 9612 | Verifier metrics, counts only |
| 9599 | Aggregator metrics, counts only |

The verifier refuses a non-loopback address at start.

## Build

Go is not part of the runtime. Build on any host with the pinned toolchain, with no dependencies:

```text
cd services/seal-verifier
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o seal-verifier .
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o verifier-pki ./cmd/verifier-pki
```

Tested with Go 1.27.3. Record the binary's SHA-256 when it is built for deployment.

## Install

Run as root in WSL, from the repository root, with the stack's OpenSearch up:

```text
bash deploy/wsl/install-aggregator.sh <folder with seal-verifier and verifier-pki> <Vector tarball>
bash deploy/opensearch/apply-index-policy.sh
```

The first script checks the tarball's pinned SHA-256, and installs the verifier, Vector, certificates, configuration, monitors and units. The second applies templates, retention and audit protection. Both are safe to re-run. Field keys come from `deploy/windows/install-vector-agent.ps1`. Then run `register-siem-alert-task.ps1` on Windows, and start with `siem-up.ps1`.

## Throughput

`opensearch_events` flushes at 200 events, matching the verifier's batch. A larger size holds every batch for the sink's 2-second timeout, and each verifier request waits for that, which capped ingestion at 91 events per second. It is now 526.

## Failure behaviour

| Failure | Behaviour |
|---|---|
| Verifier down | Vector retries. Kafka lag grows, and nothing is committed. Delivery resumes alone |
| Vector source down | Verifier answers 503, with the same result |
| Downstream hang | Bounded by a 90 s timeout |
| Too many requests | 503, retried |
| OpenSearch refuses one document | That event dead-letters as `index_rejected`, and the rest continue |
| Dead-letter write refused, or over 20 refusals a minute | Verifier holds with 503. Lag grows and the expiry alert fires |
| Bad MAC, bad shape, replay conflict | Dead-letter record |
| Oversized line | That record dead-letters, and the rest of the batch continues |
| Panic in processing | That event dead-letters, rather than stalling the partition |

The verifier never answers 4xx for anything Vector sends, because 4xx is final for Vector.

## Delivery and expiry monitoring

The expiry check must never `Requires=` Kafka. It once did, and its timer restarted a stopped Kafka, which hid the outage. `run_offline.py` now fails if either monitor unit pulls in another service.

`deploy/windows/siem-alert-watch.ps1` turns the expiry report into a Windows notification for `WARN`, `CRITICAL`, `LOST` and `CHECK_FAILED`, and announces when they clear. `register-siem-alert-task.ps1` runs it every five minutes in the operator's session. Limits are in the blocker review.

| Check | Where | Shows |
|---|---|---|
| `check-vector-delivery.ps1` | Windows | What Kafka has acknowledged. Only the sink's sent count is delivery |
| `siem-kafka-expiry-check` | WSL timer, every 15 minutes | Age of the oldest unread event, and any event already lost |

| Delivery status | Meaning |
|---|---|
| `ACKNOWLEDGED` | Every event received was acknowledged by Kafka |
| `PENDING` | Some acknowledged, the rest are waiting |
| `NOT_DELIVERING` | None acknowledged. Kafka is down or not answering |
| `LOST` | Events left the buffer without an acknowledgement |
| `NO_EVENTS` | Nothing has been received, which is not a success |
| `CHECK_FAILED` | The check could not read metrics |

| Expiry status | At 72-hour retention |
|---|---|
| `OK` | Nothing unread is older than 24 hours |
| `WARN` | Oldest unread event is over 24 hours old |
| `CRITICAL` | Over 48 hours old. Start the aggregator, or stop the agent |
| `LOST` | Events expired unread. Latched until reviewed |
| `CHECK_FAILED` | The check could not complete |

Every status other than `OK` exits non-zero, so the unit shows as failed and journald holds the message. While WSL is stopped, the check does not run, but Kafka is not deleting anything either. The first run after boot reports the true age.

**Recovering from LOST:** expired events cannot be re-read from Kafka, and the agent's checkpoints have moved on. The Windows logs may still hold them, up to their own limits. Delete `kafka-expiry.lost.json` only after the loss has been reviewed.

## Restore note

The backup `ubuntu-24.04-pre-vector-20261031.tar` predates `siem_ingest`. After restoring it, run `deploy/opensearch/create-ingest-user.sh`.

## Rollback

```text
systemctl disable --now seal-verifier siem-kafka-expiry-check.timer
rm -rf /opt/seal-verifier /etc/systemd/system/seal-verifier.service
rm -rf /home/linux/siem/config/verifier /home/linux/siem/config/vector/tls
systemctl daemon-reload
```

This deletes the WSL copy of the keys. The Windows copy remains.

_Internal test reports and planning records mentioned here are not published with Version 1._
