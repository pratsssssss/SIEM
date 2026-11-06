# Asset Inventory and Context

`siem-asset` tells the SIEM which machines it is looking at: what they run, who has been seen on them, what changed, and which incidents involve them. Nothing depends on it. If it stops, events, detections and incidents carry on. Decisions are in [ADR-0013](../adr/0013-asset-inventory.md), and results are in the acceptance report.

## Architecture

```
Windows endpoint -> siem-asset-collect.ps1 -> snapshot file ---\
SIEM host        -> local files, ip, systemctl -----------------> validate -> identity -> asset records
siem-windows-*   -> bounded queries, by ingest time ------------/                         history, relationships, audit
siem-incidents-* -> links to assets ---------------------------/                                 |
                                                                                                  v
                                 analyst socket and CLI <- context on request -> OpenSearch: siem-assets-current,
                                 (alerts, incidents, threat intelligence read live)      relationships, history, audit
```

State lives in `/home/linux/siem/data/asset/asset.db`. OpenSearch holds a copy for readers. A failure in one stage leaves the others running.

## Discovery sources

| Source | Gives | Class | Interval |
|---|---|---|---|
| Windows snapshot | OS, identifiers, interfaces, programs, services, local accounts, listeners, Defender, firewall and RDP state | observed | 6 hours and at logon, **once the task is registered** |
| SIEM host | OS, machine id, interfaces, packages, services, accounts, listeners | observed | 6 hours |
| Security 4624, 4625 | Users seen on a host, failures apart | observed | 5 minutes |
| Sysmon 1 | Processes seen running, with product and version | observed | 5 minutes |
| Sysmon 3 | Own addresses, and peers | observed | 5 minutes |
| System 7045, Security 4697 | Service installed | observed | 5 minutes |
| Security 4720, 4726, 4732, 4733 | Accounts and group changes | observed | 5 minutes |
| Sysmon 16 | Sysmon configuration changed | observed | 5 minutes |
| Which datasets a host sends | Telemetry sources, and silence | observed, silence inferred | 5 minutes |
| `siem-asset metadata` | Owner, criticality and so on | admin | When set |

Service arguments and command lines are never collected, because they can hold credentials. The account cannot read them in any case.

### Registering the Windows task

Run this once in a normal PowerShell, from `deploy\windows`. It needs no elevation:

```powershell
.\register-siem-asset-task.ps1
```

This was done on 2026-10-31, and the task ran successfully that day. Without it, the Windows record refreshes only when `.\siem-asset-collect.ps1` is run by hand. Telemetry-derived facts keep updating regardless. Reports reach Windows notifications through `asset.json`, read by the alert watcher.

## Asset schema

Version 1. A field that is not known is absent.

| Group | Fields | Class |
|---|---|---|
| Identity | `asset_id` (`ast-` and 16 hex), `hostname`, aliases, machine identifier digests, `asset_type`, `platform`, `identity_confidence` | observed |
| Operating system | `os.name`, `os.version`, `os.build`, `os.arch` | observed |
| Network | Interfaces, addresses with periods, physical MACs, `in_segment` | observed, segment inferred |
| Ownership | `owner`, `department`, `environment`, `location`, `criticality`, `purpose`, `tags` | admin |
| Security | Tools from `security_services`, listeners beyond loopback, Defender, firewall, RDP, `vulnerabilities: not_assessed` | observed |
| Lifecycle | `first_seen`, `last_seen`, `last_inventory_update`, `last_successful_collection`, status, `source_of_discovery` | observed |

`asset_type` is one of `workstation`, `server`, `domain_controller`, `virtual_machine`, `siem_host`, `unknown`. `criticality` is one of `low`, `medium`, `high`, `critical`.

A snapshot uses schema `siem.asset.snapshot/1`. Its fields are enforced by `inventory/siem_asset/schema.py`, and anything else is dropped. A section that is absent was not collected, which is different from an empty one.

## Identity

The rules are in [ADR-0013, D42](../adr/0013-asset-inventory.md#d42-identity-rests-on-machine-identifiers-and-a-contradiction-goes-to-a-person).

| Situation | What happens |
|---|---|
| DHCP change | Same asset. The old address keeps its period. A routine change |
| Several interfaces | All held on one asset |
| Host name change | Same asset. The old name stays an alias |
| Reinstall, new machine GUID on the same hardware | Conflict. `merge` if it is the same machine |
| Cloned VM with new hardware id | Conflict. `separate` |
| Exact clone | Shows as a name alternating within a day, then a conflict |
| Incomplete identifiers | A record at low confidence |
| Name and address shared | Never joined |

```bash
siem-asset conflicts
siem-asset resolve <conflict> merge --keep <asset> --reason "reinstalled, confirmed by the owner"
siem-asset resolve <conflict> separate --keep <asset> --reason "two machines. This one keeps the name"
```

While a name is held by two assets, telemetry for that name cannot be attributed, and is counted. Resolving the conflict replays the held telemetry and incidents.

## Lifecycle

| Status | Meaning | Moves to |
|---|---|---|
| `declared` | An administrator said it exists, and nothing has observed it | `new` when seen |
| `new` | First seen within `new_hours` (72) | `active`, `stale` |
| `active` | In service | `stale` |
| `stale` | Quiet for `stale_days` (14). A notable change | `active` when seen |
| `retired` | An administrator retired it | `reappeared` when seen, which is a security change |
| `reappeared` | Retired and seen again | `active` by `reactivate` |
| `conflicted` | Shown over any status while a conflict is open | The stored status when resolved |
| `merged` | A pointer to the record that absorbed it | None |

Nothing is ever deleted for going quiet. Nothing goes stale in the first hour after a start, or while telemetry is more than an hour behind, so a stopped SIEM does not age its assets.

## Changes

| Class | Examples |
|---|---|
| `security` | New auto-start service, service binary changed, tool in `security_services` removed or stopped, new local account or admin, listener opened beyond loopback, Defender or firewall weakened, RDP enabled, criticality changed, a retired asset seen, name and MAC changed together, a much shorter list than last time, a continuous source gone silent, an identity conflict |
| `notable` | OS upgrade, software installed or removed, host name change, owner change, new manual service, stale or returned |
| `routine` | IP change, software version, listener on loopback, service start type for ordinary services |

An ordinary service stopping records nothing. Security changes raise health to WARN until acknowledged with `siem-asset ack <seq> --note "why"`. They create no alert. The list is in `inventory/siem_asset/changes.py` and `telemetry.py`.

## Relationships

Each row has a source, target, type, first and last seen, provenance, confidence, a count, and a `basis` of `directly observed`, `inferred` or `stated by an administrator`.

| Type | From, to | Basis |
|---|---|---|
| `has_interface`, `has_ip` | asset, interface or address | observed |
| `has_software`, `runs_service` | asset, item | observed |
| `in_segment` | asset, private subnet | inferred |
| `authenticated_on`, `failed_authentication_on` | user, asset | observed |
| `communicates_with` | asset, asset or address | observed |
| `involved_in` | asset, incident | observed, medium confidence, since it rests on a name in the incident |
| `assigned_to` | asset, owner | administrator |

`communicates_with` says two addresses exchanged traffic, and nothing about trust.

**For attack path validation:** the graph is reachable with `siem-asset relationships <asset>`, or from `siem-asset-relationships`. Listeners, accounts, local admins and peers are the inputs a path engine would need. No engine is built, and the graph has never been tested as one.

## Commands

Run as `linux` in `wsl -d Ubuntu-24.04 -u linux`. Root is refused. All output is JSON.

| Command | Needs | Does |
|---|---|---|
| `siem-asset status` | Analyst | Health |
| `siem-asset list [--status s] [--criticality c]` | Analyst | Assets |
| `siem-asset show <asset>` | Analyst | The full record |
| `siem-asset search <text>` | Analyst | Literal search of names, addresses, MACs, programs and services |
| `siem-asset history <asset> [--category c]` | Analyst | Changes |
| `siem-asset relationships <asset>` | Analyst | Links |
| `siem-asset software <asset> [--removed]` | Analyst | Installed, and seen running |
| `siem-asset services <asset> [--removed]` | Analyst | Services |
| `siem-asset users <asset>` | Analyst | Owner, local accounts and observed users, kept apart |
| `siem-asset changes [--category c] [--unreviewed]` | Analyst | All changes |
| `siem-asset stale` | Analyst | Quiet assets |
| `siem-asset conflicts [--all]` | Analyst | Identity conflicts |
| `siem-asset context <asset>` | Analyst | Context, by id, name or address |
| `siem-asset context --incident <id>` | Analyst | Context for an incident, at its time |
| `siem-asset context --alert <id>` | Analyst | Context for an alert, with threat intelligence |
| `siem-asset context --ip <ip> --at <time>` | Analyst | Who held an address then |
| `siem-asset ack <seq> [--note n]` | Analyst | Acknowledge a security change |
| `siem-asset export` | Analyst | CSV, for D8. Formula cells are neutralised |
| `siem-asset validate` | Analyst | Check both hash chains |
| `siem-asset audit [<asset>]` | Analyst | The audit trail |
| `siem-asset metadata <asset> <name> [value] [--clear]` | Administrator | Set or clear metadata |
| `siem-asset register <hostname> [--type t] [--platform p]` | Administrator | Declare a machine |
| `siem-asset retire <asset> --reason r` | Administrator | Retire. The record stays |
| `siem-asset reactivate <asset> --reason r` | Administrator | Back in service |
| `siem-asset resolve <conflict> merge\|separate [--keep a] --reason r` | Administrator | Decide a conflict |

Add a person with `usermod -aG siem-analyst <name>` or `usermod -aG siem-asset-admin <name>`, as root. The service reads `/etc/group`, so this takes effect at once. **Criticality and owner are unset on the real assets.** Set them with `siem-asset metadata`.

## Dashboard contract

Schema version 1. A change to any shape below changes `schema_version`.

**Socket.** `/run/siem-asset/control.sock`, Unix stream. Send one JSON object and shut down the write side, then read one JSON object: `{"ok": true, "result": ...}` or `{"ok": false, "error": "..."}`. The kernel identifies the caller. A web backend would need its own decision on how to pass on the identity of the person using it, since the service would see only the backend's account.

| Action | Arguments | Result |
|---|---|---|
| `health` | | Status, counts, backlog, sources |
| `list` | `status`, `criticality`, `limit` | Summaries |
| `show` | `asset` | Full record |
| `search` | `query`, `limit` | Summaries |
| `history` | `asset`, `category`, `limit` | Change rows |
| `relationships` | `asset` | Relationship rows |
| `software`, `services` | `asset`, `removed` | Item rows |
| `users` | `asset` | `assigned_owner`, `local_accounts`, `observed_users` |
| `changes` | `category`, `unreviewed`, `limit` | Change rows |
| `stale`, `conflicts`, `validate`, `export`, `audit` | See commands | As named |
| `context_of` | `asset`, `incident`, `alert`, `ip`, `at` | Context |
| `acknowledge` | `seq`, `note` | Confirmation |
| `metadata`, `register`, `retire`, `reactivate`, `resolve` | See commands | Confirmation |

**Rows.**

| Row | Fields |
|---|---|
| Summary | `asset_id`, `hostname`, `status`, `asset_type`, `platform`, `identity_confidence`, `last_seen`, `last_inventory_update`, and when known `criticality`, `os_name`, `os_version` |
| Change | `seq`, `at`, `asset_id`, `kind`, `category`, `subject`, `before`, `after`, `class`, `source` |
| Item | The item's own fields, plus `class`, `source`, `confidence`, `first_seen`, `last_seen`, `present`, `removed_at` |
| Relationship | `id`, `source`, `type`, `target`, `first_seen`, `last_seen`, `provenance`, `confidence`, `basis`, `count` |
| Context | `confirmed`, `stated_by_administrator`, `inferred`, `external_intelligence`, `vulnerabilities`, `history`, `relationships` |

**Indices,** for reads through the `siem_asset_reader` role, which nobody holds yet:

| Index | One document per | Notes |
|---|---|---|
| `siem-assets-current` | Asset, by `asset_id` | A small summary. No lists of programs or accounts |
| `siem-asset-relationships` | Relationship | Excludes software and services, which stay behind the socket |
| `siem-asset-history-YYYY.MM` | Change | Field `provenance` carries the row's `source` |
| `siem-asset-audit-YYYY.MM` | Administrative action | Not readable by that role |

**Future detection rules** can join `host.name` to `hostname` or `aliases` in `siem-assets-current`, and read `criticality`, `asset_type`, `environment`, `status` and `security_tools`. No rule does so today, and no rule's meaning has changed. A rule must treat a missing record as normal.

## Security

- **Account:** `siem_asset` has field level security on all four sources, and no write to any of them. See `deploy/opensearch/create-asset-user.sh`.
- **Hostile input:** names are checked against strict patterns, control and direction characters are removed, credential shapes are redacted, and sizes are bounded. Queries use parameters, and text search treats wildcards literally. Incident and alert ids are checked before any query.
- **No execution:** two programs run, with fixed arguments and no shell. No value from a report reaches one.
- **Drop folder:** plain files only, with no links. Names are restricted, files are capped at 4 MiB, and there are at most 16.
- **Replay:** a report older than the last from that machine is refused.
- **Stored data:** machine identifiers are digests. Accounts and programs stay behind the socket.
- **Limits:** see [Known limits](#known-limits).

## Configuration

`/home/linux/siem/config/asset/asset.yaml`, from `config/wsl/asset/asset.yaml`.

| Setting | Default | Meaning |
|---|---|---|
| `drop_folder` | `...\SIEM-Lab\inventory` | Snapshot folder |
| `intervals.*` | See file | Stage timers |
| `lifecycle.new_hours`, `stale_days` | 72, 14 | Thresholds |
| `telemetry.backfill_days` | 7 | History read on the first run |
| `telemetry.max_window_hours` | 24 | Largest window in one read |
| `telemetry.max_hosts`, `max_users`, `max_peers`, `max_processes`, `max_events` | 50, 100, 100, 500, 100 | Query bounds. Results cut by a bound are counted as `truncated_queries` |
| `telemetry.silent_source_hours` | 6 | Silence before a lead |
| `max_new_assets_per_day`, `max_items_per_kind` | 25, 1500 | Growth limits |
| `security_services` | See file | Service names that matter |

## Failure and recovery

| Failure | Effect | Recovery |
|---|---|---|
| OpenSearch down | Health WARN within a minute. Local reads and administration work. Context says live data is missing | Backs off, up to 15 minutes, and drains by itself |
| Service crash | Restarts after 30 s. A report applies whole or not at all | Automatic |
| Service stopped | The pipeline is unaffected | `systemctl start siem-asset` |
| Snapshot missing | The record ages, and telemetry still updates `last_seen` | Run the collector, or register the task |
| Bad snapshot | Refused and counted in `rejected_reports`. Earlier facts stand | Fix the file |
| Name held by two assets | Telemetry is held, and an incident links to neither | Resolve the conflict, which replays it |
| State file lost | Records are gone, and the OpenSearch copy remains. No rebuild tool exists | Restore from backup. See below |

## Backup

The state file is `/home/linux/siem/data/asset/asset.db`. Copy it with the service stopped. If it is lost, the OpenSearch copy remains, but no tool rebuilds state from it, and metadata and conflict decisions would have to be re-entered from `siem-asset-audit-*`.

## Known limits

See the acceptance report.

_Internal test reports and planning records mentioned here are not published with Version 1._
