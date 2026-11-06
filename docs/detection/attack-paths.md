# Attack Paths

`siem-path` reconstructs what the evidence shows about an incident: who, on which machines, in what order, and how sure it is. It is deterministic, and it uses no model. **It reaches no conclusion about compromise.** That stays with a person. Decisions are in [ADR-0015](../adr/0015-attack-path-validation.md), and results are in the acceptance report.

## How it works

```
incidents, high alerts in no incident
  -> seed -> alerts -> cited events -> identity-linked context events -> threat intelligence
  -> facts (the same kinds on Windows and Linux)
  -> graph: nodes and edges, each edge with evidence
  -> stages, tier, doubts, gaps, next steps
  -> local history -> OpenSearch -> analyst socket and CLI
```

| Step | Limit |
|---|---|
| Alerts per seed | 50 |
| Cited events | 200 |
| Context events | 200, within 4 hours of the alerts |
| Identity hops from the cited events | 3 |
| Sequence window | 30 minutes |
| Nodes, edges | 200, 400. Past this, the path is capped at `weak_hypothesis` and says so |
| Paths built per cycle | 5, every 10 s |

Reaching the alert or context limit adds the gap `query_limited`, so a path never hides that it read only part of the evidence.

## Graph

Schema version 1. IDs are digests of meaning, so a rebuild gives the same graph.

| Node type | Key | Source |
|---|---|---|
| `asset` | Phase 14 `asset_id`, or `unresolved:<name>` | Asset inventory |
| `identity` | `identity:windows:<domain>\<name>`, `identity:linux:<host>:<name>` | Events |
| `process` | Host and Sysmon process GUID. Windows only | Sysmon |
| `service`, `task`, `group`, `package` | Host and name | Events |
| `ip` | Address, scoped to its host if private | Events |
| `alert`, `incident` | Their IDs | Detection, correlation |
| `indicator` | Type and value | Enrichment |

`domain`, and files as nodes, are not built: no pattern needs them yet.

| Edge | From, to | Class | Basis |
|---|---|---|---|
| `authenticated_to`, `failed_authentication_to` | Identity, asset | `observed` | Observed |
| `access_attempt_from` | Address, asset | `observed` | Observed by the target, and capped at `strongly_supported` |
| `remote_access_from` | Asset, asset | `inferred` | Inferred from an address held at that moment |
| `executed`, `spawned` | Identity or asset, process. Process, process | `observed` | Sysmon, Windows only |
| `communicated_with` | Process, address | `observed` | Sysmon. Says nothing about trust |
| `escalated_privileges` | Identity, identity | `observed` | sudo or su |
| `created`, `added_to_group` | Identity, identity or group | `observed` | Host records |
| `installed`, `scheduled` | Identity or asset, service, task or package | `observed` | Host records |
| `failed_on` | Service, asset | `observed` | Host records. Does not say why |
| `detected_on` | Alert, asset | `detection` | A rule's interpretation |
| `correlated_with` | Alert, incident | `correlation` | Names the join |
| `associated_with` | Alert, indicator | `threat_intelligence` | `malicious`, `suspicious` and `conflicting` only. No proof about a host |
| `same_identity` | Identity, identity | `analyst` | A person's statement |

Each edge has `id`, `source`, `type`, `target`, `first_ms`, `last_ms`, `class`, `basis`, `tier`, `reason`, `supporting`, `contradicting` and `evidence`.

## Evidence

Each record has `kind`, `id`, `index`, `source_time`, `ingest_time`, `host`, `asset_id`, `sensor`, `fields`, `provenance`, `state` and `digest`.

`fields` holds named facts only: dataset, action, kind, logon type, addresses, service, group, package and attribution. It never holds a command line, message text or a raw event, and the account cannot read them anyway.

| `state` | Meaning |
|---|---|
| `verified` | Found when last checked |
| `unavailable` | Gone, usually by retention |
| `changed` | Found, and different from what was recorded |

Windows and Linux events are kept 7 days, and paths 365 days, so **old paths lose their events.** They then show that, and their tier falls. Run `siem-path validate <path>` to check one. The service rechecks five a time, hourly.

## Confidence

See [ADR-0015, D52](../adr/0015-attack-path-validation.md#d52-confidence-is-an-ordered-tier-set-by-the-weakest-stage). Tiers, strongest first: `confirmed_observation`, `strongly_supported`, `plausible_inferred`, `weak_hypothesis`, `insufficient_evidence`.

| What moves it | Effect |
|---|---|
| Identity is a bare name | Edge at most `strongly_supported` |
| Attribution is `process-name` | Edge at most `strongly_supported` |
| Asset unresolved | Edge and path at most `strongly_supported` |
| No observed stage | Path at most `plausible_inferred` |
| Evidence missing | Path at most `plausible_inferred` |
| Graph cut by a limit | Path at most `weak_hypothesis` |
| Each major contradiction | Path one tier lower |
| A stronger edge elsewhere | Nothing. The weakest stage decides |

**Major contradictions:** an analyst's false positive, failures and success from different addresses, an asset that is retired or in conflict, and a name held by two assets. **Lesser doubts** are listed, and do not move the tier: intelligence conflicts, success before failures, missing events (which cap the tier instead), and the correlator's own notes.

## ATT&CK

Only exact identifiers, and only where the evidence itself shows the behaviour.

| Technique | Requires |
|---|---|
| T1110 Brute Force | 3 or more failures, then a success, for one identity on one asset, within 30 minutes |
| T1136.001 Local Account | An account created event |
| T1078.003 Local Accounts | That account then used, on the same asset |
| T1098 Account Manipulation | Added to a privileged group |
| T1548.003 Sudo and Sudo Caching | A real sudo command |
| T1543.003 Windows Service | A service installed |
| T1053.005 Scheduled Task | A task registered |
| T1053.003 Cron | A user crontab changed |
| T1562.001, T1562.002 | Defender disabled, audit policy changed |
| T1021.001, T1021.004 | A logon of that type from an address another asset held |

Techniques on an alert are carried with `source: alert`. They are the detection rule's claim, and not this engine's. Discovery patterns and SIEM service failures have no technique here, because a fault looks the same.

## Cross-platform

Facts use the same kinds on every platform, so a pattern runs unchanged on Windows and Linux. No rule joins them by name or time. A cross-host link needs one of:

- The target reports a source address, and Phase 14 says one asset held it at that moment. This gives an `inferred` edge at `plausible_inferred`.
- A person states that two identities are one.

**Today no path crosses platforms,** because no reliable link exists: the Windows host and the SIEM host share no account or observed logon.

Kali is an ordinary unknown source here. Nothing in the code knows about it.

## Commands

As `linux` in `wsl -d Ubuntu-24.04 -u linux`. Root is refused. Output is JSON.

| Command | Needs | Does |
|---|---|---|
| `siem-path status` | Analyst | Health |
| `siem-path list [--tier t]` | Analyst | Paths |
| `siem-path explain <path>` | Analyst | **Start here.** What happened, why this tier, doubts, what cannot be seen, next steps |
| `siem-path show <path>` | Analyst | The full record, without the graph |
| `siem-path graph <path>` | Analyst | Nodes and edges, with the explanation |
| `siem-path evidence <path> [--edge id]` | Analyst | Evidence behind each edge |
| `siem-path timeline <path>` | Analyst | Stages in order |
| `siem-path search <text>` | Analyst | Literal search of titles, IDs and assets |
| `siem-path asset <asset>` | Analyst | Paths involving an asset, by asset ID |
| `siem-path incident <id>` | Analyst | The path for an incident |
| `siem-path history <path>` | Analyst | Versions |
| `siem-path validate [<path>]` | Analyst | With a path, reads its evidence again. Without, checks the hash chains |
| `siem-path note <path> <text>` | Analyst | Your own conclusion, kept apart from the engine's |
| `siem-path audit [<path>]` | Analyst | The audit trail |
| `siem-path rebuild <path> --reason r` | Administrator | Rebuild now |
| `siem-path link-identities <a> <b> --reason r` | Administrator | State that two accounts are one |

Administrators are members of `siem-path-admin`. Add one with `usermod -aG siem-path-admin <name>`, as root.

Incident decisions stay with `siem-incident`. There is deliberately no command here that changes one.

## Dashboard contract

Schema version 1. A change to these shapes changes `schema_version`.

**Socket:** `/run/siem-path/control.sock`, the same protocol as the [asset service](asset-inventory.md#dashboard-contract). Send a JSON object, shut down the write side, and read `{"ok": true, "result": ...}` or `{"ok": false, "error": "..."}`.

| Action | Arguments |
|---|---|
| `health` | |
| `list` | `tier`, `limit` |
| `show`, `graph`, `timeline`, `history`, `explain` | `path` |
| `evidence` | `path`, `edge` |
| `search` | `query` |
| `asset` | `asset` |
| `incident` | `incident` |
| `validate`, `audit` | `path`, optional |
| `note` | `path`, `text` |
| `rebuild` | `path`, `reason` |
| `link_identities` | `a`, `b`, `reason` |

**Indices,** which no reader role holds yet:

| Index | One document per | Notes |
|---|---|---|
| `siem-attack-paths-YYYY.MM` | Path | Summary, stages, doubts, gaps. Month of creation |
| `siem-attack-path-graph-YYYY.MM` | Node or edge | `doc_type` says which. Query by `path_id` |
| `siem-attack-path-history-YYYY.MM` | Version | |
| `siem-attack-path-audit-YYYY.MM` | Action | |

A viewer should show `explain` beside any graph, and should show `class`, `basis`, `tier` and `state` on each edge. It should never show a tier as a verdict.

## Configuration

`/home/linux/siem/config/path/path.yaml`, from `config/wsl/path/path.yaml`.

| Setting | Default |
|---|---|
| `backfill_days` | 30 |
| `alert_seed_severities` | `high`, `critical` |
| `paths_per_cycle`, `validate_batch` | 5, 5 |
| `intervals.*` | See file |
| `limits.*` | See the table above |

## Security

Threats, and what stops each:

| Threat | Control |
|---|---|
| A hostile name or message | Treated as data. Names are cleaned and bounded, values reach queries as JSON, and nothing is ever run |
| Instructions in an event | Nothing reads text as an instruction. There is no model, and the service reads no message text |
| Query injection | Fixed query shapes. Search binds parameters and treats wildcards literally. IDs are checked first |
| A forged event reference | A reference must match the event index pattern, or it is refused unread |
| A forged Linux log line | Unverified entries are not facts, so they make no edge |
| Identity spoofing | Names never merge. An account with the same name elsewhere joins nothing |
| Graph exhaustion | Hard limits, bounded hops, one graph per seed |
| Unauthorized access | Socket group, kernel-named caller, root refused. Other services' accounts cannot read paths |
| Unauthorized change | Administrator group for rebuild and identity links, all audited |
| Field exposure | Field level security on all sources |
| Lost evidence shown as verified | `validate` lowers the path |
| Tampered history | Append-only triggers and hash chains. Root in WSL could rebuild a chain, and OpenSearch has no create-only permission |

## Failure and recovery

| Failure | Effect | Recovery |
|---|---|---|
| OpenSearch down | Health WARN within a minute. Stored paths can be read, and notes added. Validation refuses | Backs off to 15 minutes, resumes by itself, and drains |
| Service stopped | The pipeline is unaffected | It catches up from its mark on start |
| Crash | A seed stays queued until built, and paths are stored whole | Automatic |
| Asset service down | Addresses stay unresolved, and the gap is stated | Rebuild |
| A bad record | Counted as `gave_up`, and the rest carry on | |

## Backup

The state file is `/home/linux/siem/data/path/path.db`. Copy it with the service stopped. Paths can be rebuilt from stored evidence while it lasts, but not after the events expire, and history and identity links cannot be rebuilt.

## Known limits

See the acceptance report.

_Internal test reports and planning records mentioned here are not published with Version 1._
