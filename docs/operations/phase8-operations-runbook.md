# Phase 8 Operations Runbook

Deployment detail is in [Vector agent deployment](vector-agent-deployment.md) and [Vector aggregator deployment](vector-aggregator-deployment.md).

## Start and stop

| Action | Command, from `deploy\windows` |
|---|---|
| Start the stack | `.\siem-up.ps1` |
| Stop the stack | `.\siem-down.ps1` |

`siem-up.ps1` needs no elevation, and starts OpenSearch, Kafka, the verifier, the aggregator, the [detection engine](../detection/detection-engine.md), [enrichment](../detection/enrichment.md) and the timers, then holds WSL open. `siem-down.ps1` stops them in reverse order, checks each one, then ends WSL.

The Windows agent is a separate automatic service. It keeps collecting while WSL is off, up to its 1 GiB buffer, then blocks and falls back on the Windows logs.

| Agent action, elevated | Command |
|---|---|
| Status | `Get-Service Vector` |
| Stop | `Stop-Service Vector` |
| Start | `Start-Service Vector` |

**Do not leave the stack stopped for days with the agent running**, because events wait in the buffer and old log records can roll off Windows first.

## Daily health check

| Question | Command |
|---|---|
| Is the agent delivering? | `.\check-vector-delivery.ps1`, which must show `ACKNOWLEDGED`. It needs the agent running. A brief `PENDING` with `pending` at 0 is normal |
| Are events reaching OpenSearch? | `python3 tests/vector/run_e2e.py state`, as root in WSL. `ACKNOWLEDGED` means Kafka holds the event, not that it is searchable, so also check that lag stays small |
| Any alerts? | `Get-Content $env:USERPROFILE\SIEM-Lab\monitor\alerts.log -Tail 20` |
| WSL services? | `wsl -d Ubuntu-24.04 -u root systemctl is-active opensearch kafka seal-verifier vector siem-detector siem-enricher` |
| Failed units? | `wsl -d Ubuntu-24.04 -u root systemctl --failed` |

## Responding to alerts

| Alert | Meaning | Action |
|---|---|---|
| Kafka `WARN` | An unread event is over 24 hours old | Check the aggregator and verifier |
| Kafka `CRITICAL` | Over 48 hours old | Fix ingestion now. Expiry starts at 72 hours |
| Kafka `LOST` | Events expired unread | Review `kafka-expiry.lost.json`, which lists the ranges, then delete it. Check the Windows logs for what remains |
| Disk `WARN` | `C:` under 30 GiB, data over 10 GiB, or dead letters over 0.5 GiB | Free space or review |
| Disk `CRITICAL` | Ingestion stopped by the guard | Fix the cause, then clear the latch |
| Enricher `WARN` | A threat feed is stale, or a provider is paused. Detection is not affected | `sudo -u siem-enricher siem-enricher status`, and `feeds list` |
| Correlator `WARN` | Kafka or OpenSearch is unreachable, alerts are waiting, or an alert could not be analysed. Detection and enrichment are unaffected. See [Incident Management](../detection/incident-management.md) |
| Asset `WARN` | OpenSearch is unreachable, a stage failed, a security-relevant change awaits review, or an identity conflict is open. Nothing before it is affected. `siem-asset status`, `changes --unreviewed` and `conflicts`. See [Asset Inventory](../detection/asset-inventory.md) |
| Linux agent `WARN` | The Linux agent is down, or journal entries are waiting. Windows collection is unaffected. See [WSL2 Linux Telemetry](../pipeline/wsl2-linux-telemetry.md#troubleshooting) |
| Attack path `WARN` | OpenSearch is unreachable, or a stage failed. Nothing depends on this service. See [Attack Paths](../detection/attack-paths.md#failure-and-recovery) |
| `health` `WARN` or `CRITICAL` | The pipeline is degraded or unhealthy. Run `siem-health overview`, then `siem-health explain <component>`. See [Pipeline Health](pipeline-health.md) |
| `health-watchdog` `WARN` | The monitor itself is down or stalled. The pipeline is not affected by that. `systemctl status siem-health` |
| Dashboard will not open | Nothing in the SIEM depends on it. `systemctl status siem-dashboard`, then see [the dashboard guide](dashboard.md#failure-and-recovery) |
| Detector `WARN` or `CRITICAL` | Rules are failing or behind, or alerts are unpublished | `sudo -u siem-detector siem-detector status`, and `journalctl -u siem-detector` |
| `CHECK_FAILED` | A check cannot run, or its report is over 45 minutes old. A stopped Kafka shows as this: the check never starts Kafka | Find out why. Treat it as blind, not as healthy |

**Clearing the disk guard:**

```text
wsl -d Ubuntu-24.04 -u root rm /home/linux/siem/data/monitor/ingest-stopped
wsl -d Ubuntu-24.04 -u root systemctl start vector
```

Kafka holds events during the stop, and the aggregator catches up by itself.

## Threat feeds

Feeds update by timer. A failed or shrunken pull keeps the old data. A stale feed stops answering, so an indicator shows `unknown`, not clean. See [Threat intelligence](../detection/threat-intelligence.md).

## Dead letters

Dead letters hold routing facts and ciphertext. Search `siem-deadletter-*` by `dlq.reason`.

| Reason | Meaning |
|---|---|
| `mac_mismatch`, `auth_missing`, `auth_version`, `unknown_key_id`, `bad_length`, `bad_encoding` | Failed authentication. Treat as tampering or a local process writing to Kafka |
| `malformed_json`, `size`, `verifier_malformed` | Not an event |
| `replay_conflict` | A signed event tried to change a stored identity. Treat as key compromise until explained |
| `stale_event` | Older than 14 days |
| `index_rejected` | OpenSearch refused the document |
| `schema_*`, `unsealed_restricted`, `seal_missing`, `sealed_*` | A signed event of the wrong shape. Suspect an agent fault |
| `normalize_error` | The ECS step failed |

## Searching command lines

| Point | Detail |
|---|---|
| Exact text | Use `process.command_line.keyword` with a wildcard, for example `*2>&1*`. The analyzed field splits on punctuation |
| `%` | Sysmon writes each `%` as `%%` before Vector reads it, so search for `%%PATH%%` |
| Security 4688 | Holds no command line, by the owner's decision. Use Sysmon event 1 |
| Events indexed before 2026-10-31 13:35 IST | Lost `&`, `<` and `>` to the Vector defect. They age out by 2026-11-07, and cannot be reprocessed, because their identities are already in the journal |

## Backup

| Item | Method |
|---|---|
| WSL | `siem-down.ps1`, then `wsl --export Ubuntu-24.04 <path>`, then record the SHA-256 |
| Windows field keys | `C:\ProgramData\Vector\secrets\field-keys.json`. WSL holds a copy |
| Configuration | In this repository |

**Exports from now on hold the field keys, TLS keys, OpenSearch credentials and the identity journal.** Treat them as sensitive.

## Recovery

| Failure | Recovery |
|---|---|
| Verifier or aggregator down | systemd restarts it. Offsets were not committed, so nothing is lost |
| Kafka or OpenSearch down | Start it. Everything resumes |
| Agent killed | Windows restarts it after 60 s |
| WSL terminated | Run `siem-up.ps1`. The agent holds events meanwhile, and the stack recovers by itself |
| Identity journal lost | The verifier starts empty. Delivered events can be delivered again, and overwrite with identical content. The replay protection for older events is lost until they age out |
| Field keys lost on WSL | Copy from Windows with the installer, which compares hashes |
| Both copies of the keys lost | See [Field keys](vector-agent-deployment.md#field-keys) |
| WSL restored from an export | Run `deploy/opensearch/create-ingest-user.sh` if the export predates `siem_ingest`, then `deploy/wsl/install-aggregator.sh` |

## Rebuilding the verifier

Requires Go 1.27.3. See [Build](vector-aggregator-deployment.md#build).

## Rollback of Phase 8

| Part | Steps |
|---|---|
| Agent | [Rollback](vector-agent-deployment.md#rollback) |
| Aggregator and verifier | [Rollback](vector-aggregator-deployment.md#rollback) |
| Classic log ACL | `deploy\windows\restrict-classic-powershell-log.ps1 -Rollback`, elevated |
| Alert task | `Unregister-ScheduledTask -TaskName 'SIEM alert watch'` |
