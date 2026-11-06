# ADR-0013: Asset Inventory and Context

| Field | Value |
|---|---|
| **Status** | Implemented on 2026-10-31, under the owner's asset inventory brief. Subject to owner review |
| **Decisions** | D41, D42, D43, D44, D45 |
| **Evidence** | Acceptance report, [operations and contracts](../detection/asset-inventory.md) |

**Phase number:** the brief asked for the next number from the roadmap. Phase 13 is held by WSL2 Linux sources, and the roadmap schedules asset data separately, with no number. So this is **Phase 14**, the first unused number, and nothing else is renumbered.

**Relation to D8:** D8 places asset lookups in the aggregator, with asset data as CSV. The brief says asset context must never become a dependency of ingestion, so nothing was added to the aggregator. D8 is not changed. `siem-asset export` produces the CSV, so that lookup can still be built if the owner wants it. See D41.

## D41: Inventory is a separate service that nothing depends on

**Decision:** `siem-asset` reads named fields of `siem-windows-*`, `siem-alerts-*`, `siem-enrichment-*` and `siem-incidents-*`, and writes only `siem-assets-current`, `siem-asset-relationships`, `siem-asset-history-YYYY.MM` and `siem-asset-audit-YYYY.MM`. No other service knows about it. It adds no Kafka topic and uses no Kafka client.

**Why:** an unknown machine must still produce events, detections and incidents. The surest way is for the pipeline to have no connection to this service.

**Consequence:** context is joined when someone asks for it, rather than written into alerts. No alert or incident holds asset data, so a rule cannot use asset fields until the owner decides to build that. Field level security and a role with no write access to pipeline indices enforce the boundary on the server.

| Alternative | Why not |
|---|---|
| Enrich events in the aggregator | Makes ingestion depend on asset data, which the brief forbids |
| Add asset fields to incidents | Rewrites incident records, which the brief forbids |
| A Kafka topic for inventory | Nothing needs a stream. A folder and bounded queries carry this volume |

## D42: Identity rests on machine identifiers, and a contradiction goes to a person

**Decision:** a Windows machine GUID, a Linux machine id, a hardware UUID, or a cloud or VM id says who a machine is. A host name, physical MAC or IP address only suggests it.

| Case | Outcome |
|---|---|
| A machine identifier matches, with no contradiction | Same asset, high confidence. A new name, address or interface is added to it |
| Some identifiers match and others differ (clone, reinstall) | New record, plus a conflict |
| One identifier is held by several assets | Report held, plus a conflict |
| A name already held by a different identified machine | New record, plus a conflict |
| A name held by an unidentified record | That record takes the identifier, at medium confidence, and history says so |
| Telemetry, which carries only a name | Attributed if one asset holds the name. Never merges anything. Held if several do |
| The name alternates between two values within a day | Conflict: an exact clone has no other sign |

An address is stored with its period, and is asked about only at a moment. Placeholder firmware UUIDs, virtual MACs and locally administered MACs are not evidence. An identifier is stored as a SHA-256 digest, since identity needs only equality.

**A conflict is resolved by a person:** `merge` keeps one record and leaves the other as a pointer, with both histories reachable. `separate` records that they differ, and can give the shared name to one. A decided conflict does not reopen.

**Why not merge on agreement of name and address?** A forged report could then take over a real asset's record. Here it can only create a conflict.

**Found in use:** WSL inherits the Windows computer name, so the SIEM host and the endpoint both report `asus`. The conflict opened as designed. It was resolved with `separate`, and the name went to Windows, because telemetry named `asus` comes from Windows.

## D43: Every value says how it is known, and unknown stays absent

**Decision:** values carry a class: `observed`, `admin`, `inferred` or `external`, with a source, a time and a confidence. An administrator's value sits beside an observed one, and replaces nothing. A value that is not known is left out, never defaulted. Views show facts and inferences in separate sections.

Specific consequences:

- A user seen logging on is an **observed user**, and never an owner. Only an administrator assigns an owner.
- A process seen running is listed as seen running, and not as installed software.
- Traffic between two hosts is recorded as traffic, and claims no shared owner or trust boundary.
- A shared subnet is `inferred`.
- `service_account` is an inference from the shape of a name, and is labelled as one.
- Vulnerabilities are reported as `not_assessed`, because no reliable source is connected.

## D44: Inventory comes from telemetry and read-only local collection

**Decision:** three sources feed the inventory. No agent is added, and nothing scans a network.

| Source | How |
|---|---|
| Windows endpoint | `siem-asset-collect.ps1`, unelevated and read-only, writes a snapshot file to a folder |
| SIEM host | The service reads its own files, and runs `ip` and `systemctl` with fixed arguments |
| Existing telemetry | Bounded aggregations over a moving window of ingest time |

A snapshot is a contract, not a Windows detail, so a future host can use the same folder. Every file in it is treated as hostile.

**Telemetry only adds.** Absence from telemetry proves nothing, so only a snapshot removes an item. A much shorter list than last time removes nothing, and is flagged, because it is more likely a failed read or an attempt to hide something.

**Limit:** a process running as the Windows user can write to the folder. A forged report cannot take over an identified asset, but it can open conflicts, or report false values under a real machine identifier if it copies one. Snapshots are not signed.

## D45: History is append-only, and a suspicious change is a lead

**Decision:** changes are classed `routine`, `notable` or `security`, by fixed rules. History and audit are append-only by trigger and chained by hash. An unreviewed security change raises this service's health to WARN until a person acknowledges it. It creates no alert, and touches no incident.

The first run records a baseline. Whatever reached the SIEM before it is the starting point, not a change.

**Retention:** history and audit are deleted after 365 days, matching incidents (D33). The current record and relationships have no age limit, and an asset is never removed for going quiet.

**Why not raise alerts?** Detection is a separate, tested stage, and these rules have no measured false positive rate. A rule can be written once they do.

## Roles

| Actor | Can |
|---|---|
| `siem-analyst` member | Read everything through the socket, and acknowledge a change |
| `siem-asset-admin` member | Also set metadata, register, retire, reactivate and resolve conflicts |
| Root | Nothing through the socket, because audit must name a person |
| OpenSearch `siem_asset_reader` | Read-only role for future readers. Held by nobody |

Metadata and identity decisions are separated from reading because they change what analysts trust.

_Internal test reports and planning records mentioned here are not published with Version 1._
