# ADR-0016: Pipeline Health

| Field | Value |
|---|---|
| **Status** | Implemented on 2026-11-01, under the owner's pipeline visibility brief. Subject to owner review |
| **Decisions** | D55, D56, D57, D58, D59, and the implementation of D13 |
| **Evidence** | Acceptance report, [operations and contracts](../operations/pipeline-health.md) |

**Phase number:** the roadmap had pipeline visibility unscheduled. Phase 15 was taken and the numbered list resumes at 17, so 16 was the first unused number. Nothing was renumbered.

## D13: Pipeline metrics implementation

D13 recommended Vector internal metrics and a small Kafka lag check, and left the metrics store open. The roadmap row also named Grafana.

**This phase implements D13 without a metrics store of its own and without Grafana.** The brief rules out a heavyweight monitoring stack and a new time-series database unless proven necessary, and neither was needed: bounded SQLite and the existing OpenSearch hold what is required. The minimum signals are the [component list](../operations/pipeline-health.md#components). Prometheus and Grafana stay possible, since Vector and the verifier already export the format.

## D55: A separate observer that nothing depends on

**Decision:** `siem-health` is a separate unprivileged service. No unit requires it, it adds no dependency to any core service, and core code does not know it exists. It has no network listener and no control socket. It uses Kafka metadata and offset requests only, so it joins no group and adds no topic.

**Why:** a monitor that can hurt what it monitors is worse than none. The brief makes this the first principle.

**It has no action on the world.** Nothing here restarts, remediates, acknowledges or changes anything. This is enforced by accounts and roles, and not merely by the code.

## D56: Unknown is a state, and silence is not evidence

**Decision:** five statuses. A monitoring error gives `UNKNOWN`. Silence alone gives `UNKNOWN`. `UNHEALTHY` needs positive evidence. A rejected event never lowers health.

**Why:** the two expensive mistakes are a false alarm from a quiet machine and a green screen from a blind monitor. Both come from treating absence as evidence.

**Cost:** a usually busy source going silent is only `UNKNOWN`, even if the cause is tampering. Coverage then becomes `limited`, so it is not hidden.

## D57: Services publish one report, and the monitor enters no private directory

**Decision:** each service writes one extra copy of its existing report to a folder only it can write and only `siem-health` can read. This needed configuration and unit lines, and no new code path in those services. The one code change is two read-only fields in the attack path report: oldest queued item, and evidence state.

**Why not sockets:** every control socket answers `siem-analyst`, which can also change things. Phase 15 had to accept that for address lookups, and the brief forbids it here.

**Why not reading databases:** directory access would expose state that holds event-derived content.

**Why not the existing Windows-side reports:** those carry only status, time and message, by design.

**Cost:** seven units and six configuration files changed, and those services had to restart once.

## D58: Hysteresis that cannot hide proof

**Decision:** going worse takes 2 cycles and recovering takes 3, doubled for a component that keeps changing. Direct proof, such as systemd saying stopped, moves at once. A held state says it is held.

**Why:** flapping trains people to ignore a monitor, but a delay must never cover a fact.

## D59: Bounded, separated history

**Decision:** one-minute samples for 48 hours, hourly aggregates for 30 days, transitions and episodes for 90 days, and diagnostics for 7 days locally. In OpenSearch, transitions and episodes for at least 90 days, and 5-minute snapshots for at least 30. Transitions are append-only and hash-chained.

**Retention is new, not changed.** Every existing policy stays as approved. Because indices are monthly, the policies are 120 and 62 days from creation, so nothing leaves before its minimum.

**Why:** the question three months later is what broke and for how long, not the value of a counter on a given minute.

## Phase 15 open items

| Item | Position |
|---|---|
| Asset socket permissions | Unchanged, and still open. This service avoids the same issue by joining no analyst group |
| Evidence expiry and path retention | Health keeps expired and altered evidence apart: expiry is normal, and alteration degrades. Retention is unchanged |
| Dashboard read-only identity | Still the owner's decision. Contracts are documented, and no reader role was created |
| Unverified multi-host behaviour | Still unverified. This monitor is built for the hosts that exist |

## Options left to the owner

- **How a dashboard identifies its user.** Contracts here are the CLI and indices, and a reader role should wait for this.
- **Agent metrics from Windows.** Binding the Windows exporter to a WSL-reachable address, or moving to mirrored networking, would give per-minute Windows figures. Either changes network exposure, so neither was done.
- **Whether `health.json` should notify on `DEGRADED`.** It does at present, as `WARN`.

**Later change, 2026-11-07:** the collector also reads each unit's `LoadState`, so a unit that is not installed is told apart from one that is stopped. Stored current-state rows for components that are no longer assessed are removed each cycle, so a retired component does not linger. History is kept.

_Internal test reports and planning records mentioned here are not published with Version 1._
