# ADR-0015: Attack Path Validation

| Field | Value |
|---|---|
| **Status** | Implemented on 2026-11-01, under the owner's attack path brief. Subject to owner review |
| **Decisions** | D50, D51, D52, D53, D54, plus the owner's rulings on D15 and D21 |
| **Evidence** | Acceptance report, [operations and contracts](../detection/attack-paths.md) |

**Phase number:** the roadmap had attack path validation unnumbered, and 15 and 16 unused, so this is Phase 15. Nothing was renumbered.

## The owner's rulings

**D21, Kali collection: decided by the owner in this brief.** Kali is a controlled attacker and test machine. It is not a production asset category and not a required telemetry source. No Kali collection path is built. It may generate controlled test activity, and that activity is observed through the monitored target and existing sensors. The ledger design in `docs/pipeline/kali-attacker-telemetry.md` is therefore not required, and stays as a record of the options.

**D15, Linux process execution: deferred by the owner.** auditd and broad Linux process auditing stay off. The cost is stated on every affected path. See D54.

**This engine uses no language model and no external service.** It is deterministic.

## D50: A separate, deterministic service that nothing depends on

**Decision:** `siem-path` reads named fields of events, alerts, enrichment and incidents, and reads current asset records. It writes only `siem-attack-paths-*` and `siem-attack-path-*`. It adds no Kafka topic or consumer. There is no model, and no randomness: the same evidence gives the same graph, with the same IDs.

**Why:** an analyst has to be able to rerun a reconstruction and get the same answer, and the pipeline must not notice if this service stops.

**It has no action on the world.** It starts no program, and has no path to change an incident, alert, asset or host. An incident's seed record is read only.

## D51: An edge needs evidence, and identity is what joins events

**Decision:** the graph refuses an edge with no evidence record. An event joins a path only through the same identity on the same asset, reachable from what the alerts cited, within a bounded number of hops. Time orders events that identity has already joined, and never joins anything by itself.

| Identity | Links? |
|---|---|
| Windows, domain and name | Yes |
| Linux, host and name | Yes, on that host only |
| Bare name | Weakly, and the edge says so |
| Service account, machine account | No. Its events are still observed |
| Linux `root` | No: it is every administrator |

**Found on real data:** `root` began as an ordinary local account, and joined three separate test runs into one 43 stage path through `sudo`. That is why it links nothing.

**Namespaces never merge by name.** `alice` on Windows and `alice` on Linux are two identities. Only a person can state that two accounts are one (`link-identities`), which needs an administrator and a reason, is audited, and shows as an `analyst` edge.

**Asset identity is Phase 14's.** A host resolves only through that inventory's aliases, which it maintains from machine identifiers. Two holders of a name leave it unresolved. An address resolves only through Phase 14's time-aware lookup, and only if one asset held it at that moment.

## D52: Confidence is an ordered tier, set by the weakest stage

**Decision:** five named tiers, and no percentages.

| Tier | Means |
|---|---|
| `confirmed_observation` | A verified event on a resolved asset, with an unambiguous identity, directly shows this |
| `strongly_supported` | Direct evidence with one named doubt, or a detection with its events |
| `plausible_inferred` | An inference, a correlation by name or host, or a detection with no events |
| `weak_hypothesis` | The graph was cut by a limit |
| `insufficient_evidence` | Nothing supports it, or its evidence has gone |

A path takes the tier of its weakest observed stage, a stronger edge cannot lift a weaker one, and each major contradiction lowers it one step. Every step is written into `rationale`.

**Why not a score?** A number invites a threshold, and the brief forbids treating a threshold as proof. Numbers would also need weights that nothing here could justify. Ordering and a stated reason need no invented weights. The correlator's numeric score is a different thing, and stays as it is.

**No tier means compromise.** Every path carries `conclusion: none`. `confirmed_observation` says an event happened, and says nothing about intent. An analyst's false positive is itself evidence, of class `analyst`, and lowers the path.

## D53: Evidence is referenced, and checked again

**Decision:** edges hold references and named fields: the event or alert ID, index, source and ingest times, host, asset, sensor and provenance, plus a digest. Raw events, command lines and message text are never copied. A reference must match the event index pattern, or it is refused unread.

`validate` reads every reference again. Evidence that is gone becomes `unavailable`, and altered evidence becomes `changed`. Those edges stop counting as verified, and the path's tier falls. Windows and Linux events are kept 7 days and paths 365, so **this will happen to every path**: a path outlives its events, and says so, rather than presenting old claims as verified.

**History** is append-only and hash chained. A rebuild with the same meaning adds nothing, and one that changes meaning adds a version.

## D54: What cannot be seen is part of the result

**Decision:** each path lists its gaps, and no edge is made that needs evidence the system lacks.

| Gap | Effect |
|---|---|
| Linux process execution (D15) | No Linux `executed` or `spawned` edges exist, or can |
| Linux network connections | No traffic can be followed from a Linux host |
| SSH, firewall | Remote logon to the Linux host cannot be observed |
| Source not observed | An address reported by a target is only that. What happened at the source is unknown |

**Source, affected asset and sensor stay three things:** `attack_sources`, `affected_assets` and `telemetry_sources`. They can differ, and nothing here depends on any particular source. No name, address or user of this lab appears in the code, and a test asserts that.

## Alternatives

| Alternative | Why not |
|---|---|
| A graph database | Too heavy for this host, and bounded per-seed graphs do not need one |
| A global graph of all entities | Every traversal would risk joining unrelated activity, which is the failure this exists to prevent |
| Numeric confidence | See D52 |
| A model to narrate paths | D10 and the brief: this must be deterministic |
| Writing paths into incidents | Incident history must not change |

## Revisit when

- D15 changes, because Linux process edges become possible.
- A second monitored endpoint exists. Lateral movement has fixtures only until then.
- Analysts have used this enough to judge the tiers.

_Internal test reports and planning records mentioned here are not published with Version 1._
