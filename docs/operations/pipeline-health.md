# Pipeline Health

`siem-health` watches the SIEM from collection to analysis and says whether an analyst can trust the current coverage. It reads what components already expose, and it changes nothing. **No part of the SIEM depends on it.** If it stops, ingestion and detection carry on, and something outside it notices. Decisions are in [ADR-0016](../adr/0016-pipeline-health.md), and results are in the acceptance report.

## How it works

```
systemd, kernel, Vector and verifier counters, Kafka offsets, OpenSearch statistics,
a bounded sample of event timestamps, one status report from each service
  -> collect, each with a time and size limit
  -> assess: one result per component, with reason, evidence and what is missing
  -> hysteresis: a stable status, with transitions and episodes
  -> pipeline view: stages, bottleneck, root cause, coverage
  -> local SQLite -> own OpenSearch indices, and a small report for the Windows watcher
```

A cycle takes under a second every 60 s. Event freshness and delays are sampled every 3 cycles, and retention state every 15.

**What it adds to Kafka: nothing.** It uses metadata and offset requests only, joins no group, and reads no message. It adds no topic.

**How it sees private state.** Each service writes one extra copy of its existing status report to `/home/linux/siem/data/status/<service>/`, a folder that service alone can write and only `siem-health` can read. The monitor never enters a service's private directory, and it needs no socket, so it cannot act on anything.

**Windows.** Agent metrics are on Windows loopback, which WSL cannot reach under NAT networking. The alert watcher, every five minutes and without elevation, writes `windows-agent.json` with the service state and delivery counters. Anything running as the Windows user can write that file, so the monitor treats it as the weakest source, and stored events have to corroborate it.

## Components

| Component | Type | Platform | Main evidence |
|---|---|---|---|
| `windows-agent` | Agent | Windows | Windows report, newest stored Windows event, delivery counters |
| `linux-agent` | Agent | WSL | systemd, agent metrics, Linux health report |
| `source:<dataset>` | Source | Either | Newest stored event, its agent's state |
| `kafka` | Broker | WSL | systemd, metadata, end offsets, expiry report |
| `verifier` | Service | WSL | systemd, counters by reason |
| `aggregator` | Service | WSL | systemd, Vector metrics, consumer lag, disk guard |
| `normalization` | Function | WSL | Vector transform counters, dead letter size |
| `opensearch` | Storage | WSL | systemd, cluster and node statistics, retention state |
| `detector` | Service | WSL | systemd, rule watermarks, failures, outbox |
| `enricher` | Service | WSL | systemd, feeds, providers, breakers |
| `correlator` | Service | WSL | systemd, consumer lag, report |
| `assets` | Service | WSL | systemd, report |
| `attack-paths` | Service | WSL | systemd, queue, oldest item, evidence state |
| `host-wsl` | Host | WSL | `/proc`, `statvfs` on `/mnt/c` |
| `housekeeping` | Timers | WSL | Timer state, report ages |
| `health-monitor` | Self | WSL | Its own cycle, plus the watchdog |

## Status

| Status | Means |
|---|---|
| `HEALTHY` | Evidence shows it working |
| `DEGRADED` | Working, but delayed, partly failing, or blocked by something else |
| `UNHEALTHY` | Positive evidence that it is not doing its job |
| `UNKNOWN` | Not enough evidence either way. **This is not a mild failure.** |
| `NOT_APPLICABLE` | Not meant to be active |

**Three rules decide most cases.**

1. **A monitoring error is `UNKNOWN`.** A timeout, a refused permission or a malformed reply says something about this monitor's view. The exceptions are a refused connection while systemd says the service is active, and a timed-out OpenSearch, which are evidence of the service itself, at medium certainty.
2. **Silence alone is `UNKNOWN`.** `UNHEALTHY` needs proof: systemd says stopped, or work is waiting with no progress.
3. **A rejected event is a number.** A forged or malformed event raises `verification_rejected_per_second` and changes no status. Faults in the verifier itself (`busy`, `read_failed`, `journal_failed`, `downstream_unavailable`, `index_rejected`, `refusal_limit`) do lower it.

| Condition | Means |
|---|---|
| `ok`, `quiet` | Working, or nothing to do |
| `service_unavailable` | Stopped, failed or restarting |
| `not_processing` | Running, and not doing its job |
| `delayed` | Doing its job late |
| `source_unavailable` | A source or feed it depends on is out |
| `monitoring_unavailable` | The evidence cannot be read |
| `host_offline` | The machine has just resumed, so silence means nothing yet |
| `backlog_increasing`, `backlog_recovering` | Behind, getting worse or better |
| `resource_pressure` | Short of memory, disk or threads |
| `downstream_unavailable` | Blocked by another component, which is named as the root cause |
| `configuration` | Set up differently from what was decided |
| `data_loss` | The expiry check has recorded unread messages lost |

`certainty` is `high`, `medium` or `low`, from how direct the evidence is. `durability` is `transient` until a change is confirmed and 5 minutes old, then `persistent`.

### Pipeline view

Stages run in pipeline order. The **bottleneck** is the first stage below healthy. The **root cause** is the first that is not merely `downstream_unavailable`.

Enrichment, assets, attack paths and the host are supporting stages, so they lower the overall state to `DEGRADED` at most. A real host problem also shows on the components it hurts.


**Coverage** answers whether an analyst can trust what they see:

| Coverage | Means |
|---|---|
| `trusted` | Collection to detection works, and busy sources are fresh. It still covers only what the sources record: for example, no Linux process execution (D15) |
| `limited` | Part of that path is degraded, or a usually busy source has gone quiet |
| `unknown` | Something on that path cannot be judged, or this monitor is not current |

## Thresholds

All are in `health.yaml`, with bounds in `config.py`. A value out of bounds stops this service at start, and nothing else. Every threshold is a first estimate from one lab on a few days of data.

| Setting | Default | Why |
|---|---|---|
| `worsen_cycles`, `improve_cycles` | 2, 3 | One bad sample is often nothing. A recovery must hold, and flapping is the noisier error |
| Direct proof, such as systemd stopped | 1 cycle | Hysteresis must not hide a fact |
| `flap_transitions`, `flap_factor` | 6 in 30 min, ×2 | A component that keeps changing must hold longer before it counts as recovered |
| `service_report_seconds` | 180 | Services report every 30 to 60 s, so this is three misses |
| `timer_report_seconds`, `windows_report_seconds` | 900 | Timers and the watcher run every 5 minutes, so this is three misses |
| `hang_seconds`, `not_progressing_seconds` | 600 | Long enough for the slowest rule interval, and short enough to matter |
| `after_outage_seconds` | 600 | Errors in a 5-minute window, and rules in retry delay, are blamed on an outage for this long, and not after |
| `watermark_degraded_seconds`, `_unhealthy_` | 600, 1800 | Rules run within a few minutes. Half an hour behind means detection is not current |
| `lag_degraded_messages`, `_unhealthy_` | 5,000, 100,000 | Measured bursts are far below 5,000. 100,000 is a large part of a day here |
| `oldest_degraded_seconds`, `_unhealthy_` | 300, 3600 | Against 72-hour Kafka retention, an hour is safe but plainly behind |
| `latency_degraded_seconds` | 300 | Measured p95 is under 5 s |
| `normalize_*_percent`, `normalize_min_events` | 1%, 20%, 20 events | Normal failure is 0. Below 20 events a percentage says nothing |
| `memory_*_percent` | 10, 5 | Page cache is what OpenSearch and Kafka rely on |
| `swap_*_percent` | 50, 90 | Measured swap in use is 0 |
| `pressure_*_percent`, `cpu_pressure_degraded_percent` | 5, 25, 50 | Measured values stay near 0 |
| `windows_disk_*_gib` | 30, 20 | Follows the [resource budget](resource-budget.md). The disk guard acts on its own |
| `heap_*_percent` | 85, 95 | Heap saws upward normally |
| `restart_loop_count`, `_minutes` | 3 in 30 | The service limits are 6 in 10 minutes, so this warns first |
| `resume_grace_seconds` | 300 | Timers and reports need one 5-minute round |

**Source quiet limits** are set above the longest silence measured on 2026-11-01. That covers only 48 hours and about 16 hours of uptime.

| Source | Usual silence | Longest measured |
|---|---|---|
| `windows.sysmon`, `windows.security` | 15, 30 min | Under 10 min |
| `windows.powershell`, `linux.system` | 60, 30 min | Under 10 min |
| `linux.auth`, `linux.cron`, `windows.taskscheduler` | 90, 120, 120 min | 40, 20, 30 min |
| `windows.system` | 240 min | 130 min |
| `windows.firewall`, `windows.defender`, `linux.kernel`, `linux.package` | Not set: often silent | 400, 660, 30, 60 min |

## Time and missing data

Internally everything is UTC milliseconds.

| Situation | Handling |
|---|---|
| A cycle far later than expected | Recorded as a gap, kind `machine_suspended`, `wsl_restarted`, `monitor_restarted` or `monitor_stalled`. Rates and hysteresis restart, and for 5 minutes stale evidence gives `UNKNOWN` |
| During that grace period, systemd says stopped | Still `UNHEALTHY`. Proof is proof |
| WSL restarted | Whether Windows was on is not known, and the record says so |
| A report dated more than 120 s ahead | Not believed, and listed under `missing` |
| A report older than the last one seen | Refused as replayed |
| An event dated in the future | `UNKNOWN`, and never fresh |
| Clock moved backwards | Recorded as a gap. Repeated minutes change nothing, because the key is the minute |
| Counter fell | The component restarted. That window has no rate, rather than a negative one |
| First sample after a restart | No value, rather than zero |
| Windows host off | WSL is off too, so the monitor is not running, and the period appears as a gap afterwards |

**After an outage, Windows can read retained event logs.** A recovered agent therefore does not prove continuous collection. High latency in that period is shown with that warning.

## Metrics

`siem-health metrics --catalog` prints the full catalogue, and it is the reference: definition, source, method, unit, sampling, window, limits, and whether a value is `direct`, `sampled` or an `estimate`.

**What is deliberately not computed:**

| Not available | Why |
|---|---|
| End-to-end event loss | Counts differ for filtering, rejection, routing, retention and duplicates. A difference between them is not loss |
| Time from event to index | `event.ingested` is set at normalization. Latency here ends there |
| Correlation delay in seconds | No record states when the correlator took an alert. Lag and backlog stand in |
| Enrichment pending count | The enricher reports finished jobs only |
| Windows errors between watcher runs | Metrics stay on Windows loopback |
| Oldest dead letter age | It would need a search of dead letter content |
| Producer errors at the broker | Agents count their own, and the broker has none per client |
| Correlator audit chain, in the service | It needs the analyst socket, which this service must not join. `siem-health validate --chains` asks as the analyst |

## Commands

As `linux` in `wsl -d Ubuntu-24.04 -u linux`. **Every command is read-only.** They open the state file directly and never talk to the service, so they still answer when it is down. Add `--json` for machine-readable output.

| Command | Shows |
|---|---|
| `siem-health status` | One line |
| `siem-health overview` | **Start here.** Overall, coverage, bottleneck, stages, sources, resources |
| `siem-health components` | Every component |
| `siem-health component <name>` | The full record |
| `siem-health explain <name>` | Why it has this status: evidence, what is missing, recent changes |
| `siem-health pipeline` | The stored pipeline view |
| `siem-health metrics [<name>] [--hours n]` | Current values, or one series |
| `siem-health metrics --catalog` | Every metric, and what is unavailable |
| `siem-health history [<name>] [--days n]` | Status changes. `monitoring` holds gaps |
| `siem-health failures [--days n]` | Open and recent episodes |
| `siem-health lag` | Every backlog and lag |
| `siem-health resources` | Host figures and this service's own use |
| `siem-health validate [--chains]` | Checks history, currency and bounds. Exit status 1 if any fail |

Exit status: 0 done, 1 not found or validation failed, 2 bad configuration, 3 state unreadable.

### Examples

**Healthy, real output:**

```
Pipeline: HEALTHY   coverage: trusted   since 2026-11-01 18:06:04Z
Observed: 2026-11-01 18:06:04Z (55 s ago)   monitor service: active
Sources: 10 fresh, 2 quiet
Memory available: 38.9%   C: free: 56.4 GiB
```

**Degraded, fixture:** enrichment stopped, and detection unaffected. Enrichment is a supporting stage.

```
Pipeline: DEGRADED   coverage: trusted
Bottleneck: enricher   root cause: enricher
Critical: enricher
```

**Unhealthy, fixture:** Kafka stopped, and the correlator blames it rather than itself.

```
Pipeline: UNHEALTHY   coverage: limited
Coverage: Part of the path from collection to detection is degraded or down: kafka, correlator
Bottleneck: kafka   root cause: kafka
Critical: kafka
Degraded: correlator, linux-agent
```

**Unknown, fixture:** permission refused to OpenSearch. Nothing is claimed about OpenSearch itself.

```
opensearch  UNKNOWN  monitoring_unavailable  Statistics could not be read: denied
```

**Recovering, fixture:**

```
aggregator  DEGRADED  backlog_recovering  7000 messages waiting, oldest 0 s, falling
```

**Held, fixture:** a recovery not yet confirmed never reads as recovered.

```
health-monitor  DEGRADED  Held at DEGRADED until the change is confirmed. Latest: Cycles complete and saved
```

**Monitor failure, fixture:** the stored state said healthy, and the command refuses to repeat it.

```
Pipeline: UNKNOWN   coverage: unknown
Observed: 2026-11-01 18:06:04Z (61 min ago)   monitor service: inactive
WARNING: this monitor is not current. Last stored state was HEALTHY.
```

## Self-monitoring

| Layer | Sees |
|---|---|
| `health-monitor` component | Cycle length, collector failures, save failures. Query timeouts are in `resources` |
| `siem-health` command | Asks systemd directly and compares the last cycle's age |
| `siem-health-watchdog.timer` | Standard library only, every 5 minutes. Reports `health-watchdog.json`. It restarts nothing |
| Windows alert watcher | Treats `health.json` and `health-watchdog.json` like any report. Silence past 45 minutes is `CHECK_FAILED` |

The watcher's notifications are operational, and they raise no security alert. Nothing about this monitor can create an alert or incident.

## Dashboard contract

Schema version 1. A change to these shapes changes `schema_version`. No web server is built, and **no reader role exists**: how a web backend passes on who is using it is still the owner's decision.

**Command:** every command with `--json`. `overview` is the single best call, and it carries `monitor_current`, which a viewer must show.

| Need | Source |
|---|---|
| Overall health | `overview`: `overall`, `coverage`, `coverage_reason`, `bottleneck`, `root_cause` |
| Component health | `components`, or `siem-health-current`, one document per component |
| Pipeline stages | `overview.stages` |
| Time series | `metrics <name>`, or `siem-health-metrics-YYYY.MM` |
| Backlog and lag | `lag` |
| History | `history`, or `siem-health-transitions-YYYY.MM` |
| Episodes | `failures`, or `siem-health-episodes-YYYY.MM` |
| Resources | `resources` |
| Last processing time | `last_activity_ms`, `last_heartbeat_ms` on each component |
| Evidence and explanation | `explain <name>` |

**Component record:** `component`, `type`, `platform`, `observed_ms`, `status`, `previous`, `since_ms`, `latest_assessment`, `pending`, `pending_count`, `condition`, `latest_condition`, `reason`, `certainty`, `durability`, `last_activity_ms`, `last_heartbeat_ms`, `evidence[]` (`source`, `observed_ms`, `freshness`, `value`), `missing[]`, `freshness`.

**Indices:**

| Index | One document per | Identity |
|---|---|---|
| `siem-health-current` | Component | `current-<component>`. Refreshed on change, and otherwise about every 5 minutes |
| `siem-health-transitions-YYYY.MM` | Status change or gap | Its chain hash, so a resend changes nothing |
| `siem-health-episodes-YYYY.MM` | Episode | Component and start, so updates replace |
| `siem-health-metrics-YYYY.MM` | 5 minutes | `metrics-<minute>`. `metrics.<name>` holds catalogue values |

A viewer should show `UNKNOWN` as a state of its own, never as a shade of failure. It should show `observed_ms` beside every status, and show `monitor_current: false` above everything else.

## Security

| Threat | Control |
|---|---|
| Reading event content | Field level security allows three fields on events and two on alerts and enrichment. No command line, message, user or host name can be read or matched |
| Reading keys | Its own account, in no privileged group. Tests try every key and login file |
| Changing anything | `siem_health` writes only `siem-health-*`. No socket access, and systemd refuses it |
| Remediation | None exists. The code issues `systemctl show` and `is-active`, and nothing else |
| Command injection | No shell. Fixed argument lists, and unit names checked against an exact pattern |
| Query injection | Fixed query shapes. Nothing from a report reaches a query |
| Path manipulation | Report paths come from configuration, and a symbolic link is refused |
| A malformed or huge response | Size and time limits, parsers that refuse rather than guess, numbers bounded and finite |
| A forged status report | Each folder has one writer. The Windows report is the exception, and it cannot alone prove health |
| A stale or replayed report | Age, future-date and replay checks |
| Resource exhaustion | 128 MiB, 15% CPU, bounded rows, samples, series and outbox |
| A network exposure | No listener. Every address is checked to be on loopback, or the service will not start |
| Sensitive output | Only counts, ages and states are copied. Tests search all output for real host names and accounts |
| A feedback loop | No Kafka use, a quiet journal, the units excluded from the Linux agent, and systemd's lifecycle lines for the timer job suppressed |

Permissions: `siem-health` reads the status folders and `/home/linux/siem/data/monitor`, and writes `/home/linux/siem/data/health`, whose group is `siem-analyst` so analysts can read it. Its only other membership is `linux`, for passing through `/home/linux`, as with every service here.

## Retention

| Data | Local | OpenSearch |
|---|---|---|
| Current state | One row per component | `siem-health-current`, one document per component, no expiry needed |
| Transitions, episodes | 90 days | 120 days after index creation. Indices are monthly, so at least 90 days |
| One-minute samples | 48 hours | Not sent |
| Five-minute metric snapshots | Not kept | 62 days after index creation, so at least 30 days |
| Hourly aggregates | 30 days | Not sent |
| Detailed diagnostics | 7 days | Not sent |

Local transitions younger than 30 days cannot be deleted at all: a trigger refuses it. Pruning records where the chain starts, so the rest stays checkable. Existing retention policies are unchanged.

## Failure and recovery

| Failure | Effect on the SIEM | What to do |
|---|---|---|
| Service stopped or crashed | None | systemd restarts a crash. Otherwise `systemctl start siem-health`. The gap is recorded, and state resumes |
| Bad configuration | None | The service will not start. Fix `health.yaml` |
| OpenSearch down | None from this. History waits locally, and the command still works | It resumes and drains by itself |
| State file lost | Current state and history are gone. The SIEM is unaffected | Stop, move the file aside, start. Published history remains in OpenSearch |
| Outbox past its limit | Oldest metric documents go first. Local history stays | Nothing |

To stop only monitoring: `systemctl stop siem-health siem-health-watchdog.timer`, as root. Both are part of `siem-up.ps1` and `siem-down.ps1`.

To back up, copy `/home/linux/siem/data/health/health.db` with the service stopped.

## Installation

As root in WSL, from the repository, with OpenSearch up:

```bash
bash deploy/wsl/install-health.sh
bash deploy/opensearch/create-health-user.sh
bash deploy/opensearch/apply-index-policy.sh
systemctl start siem-health siem-health-watchdog.timer
```

The status report paths are in each service's configuration and unit. The install script creates the folders, and a service still starts if its folder is missing.

## Known limits

See the acceptance report.

_Internal test reports and planning records mentioned here are not published with Version 1._
