# Ingestion Pipeline

**Status:** Original design, now deployed. What was built is in the [Phase 8 final architecture](../architecture/phase8-final-architecture.md), which takes priority where they differ. This keeps the principles of D3, D4 and D5, applied to the new platform.

## Paths

```text
Windows Event Logs
    -> Native Vector Windows agent
    -> Kafka siem-raw-logs (WSL2)
    -> Vector aggregator
    -> VRL normalization and ECS mapping
    -> OpenSearch

WSL2 Linux telemetry
    -> Vector Linux source
    -> Kafka siem-raw-logs
    -> Vector aggregator -> ECS -> OpenSearch

Kali attack ledger (D21, batch)
    -> Vector file source in WSL2
    -> Kafka siem-raw-logs
    -> Vector aggregator -> separate attack index
```

The Sigma runner and ML detector read normalized events from OpenSearch.

## Principles

- **Kafka is the transport and replay buffer.** It is not the archive.
- **OpenSearch is the primary storage and search layer.**
- **Normalized events go directly to OpenSearch.** There is no `siem-normalized` topic.
- **Agents never write directly to OpenSearch** (D4).
- **Unparsed events go to a dead-letter destination**, never the main index.

## Kafka topics

| Topic | Producer | Consumer |
|---|---|---|
| `siem-raw-logs` | Vector agents | Vector aggregator |
| `siem-alerts` | Sigma runner, ML detector | Alert enricher, correlator |
| `siem-incidents` | Created, and unused: the correlator writes incidents to OpenSearch | None |

`siem-reports` remains an OpenSearch index. Kafka is single-node with replication factor 1, so it does not protect against disk loss.

## Event identity

The rule from Phase 0 is unchanged: the agent assigns a stable `event.id` once, it travels unchanged, the aggregator never recalculates it, and OpenSearch uses it as `_id`. A content-only hash is never the identity.

| Priority | Source | Identity from | `labels.event_id_basis` |
|---|---|---|---|
| 1 | Windows Event Log | Computer, channel, `EventRecordID`, event time | `source_record` |
| 1 | journald, if used | Host and `__CURSOR` | `source_record` |
| 2 | Tailed files with a validated generation | Host, path, file generation, byte offset, raw-line hash | `file_occurrence` |
| 3 | No reliable source identity | Random identifier generated once by the agent | `agent_generated` |

File generation rules and the fallback's limits are in section 10 of the technical assessment.

**Windows behaviour to validate:**

| Scenario | Expected |
|---|---|
| Two identical events | Different `EventRecordID`, so two events |
| Vector restarts from its bookmark | Same identity, no duplicate document |
| Kafka redelivery or replay | Same identity, document updated in place |
| Log cleared and numbering restarts | Event time keeps the identity distinct |

## Idempotency and replay

Delivery is at-least-once, so duplicates are normal.

- Redelivery of the same `event.id` updates one document.
- Replaying `siem-raw-logs` through a new parser updates documents, and does not duplicate them.
- Replay is only possible within Kafka retention.
- Downstream services reference `event.id`.

## Reconciliation

Offsets, delivered events, unique identities and indexed unique events are measured separately. They have no one-to-one relationship. The model in section 13 of the technical assessment applies unchanged.

**Windows addition:** record numbers are per channel, so they are compared per channel. Gaps are expected if a filter drops events or a log wraps.

## Buffering

| Layer | Purpose |
|---|---|
| Windows Event Log | Holds events until they wrap |
| Vector bookmark | Records the read position |
| Vector disk buffer on Windows | Holds events while Kafka is unreachable, only with `message_timeout_ms: 0`, as Phase 8 testing showed |
| Kafka retention | Allows replay |

## Time

Windows and Sysmon events are read in UTC where the source provides it. `@timestamp` is the event time and `event.ingested` is the ingestion time, so the gap between them shows pipeline lag, including WSL outages. Watermarks (D5) must allow for that lag.

## Untested assumptions

- The beta source is reliable over long runs. Open issues are listed in [Vector compatibility](windows-vector-compatibility.md).
- Vector's Kafka path works from Windows. Real Kafka traffic has passed with librdkafka, the library Vector uses, but not with Vector itself.

_Internal test reports and planning records mentioned here are not published with Version 1._
