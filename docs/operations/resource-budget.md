# Resource Budget

**Status:** Planning budget. OpenSearch and Kafka are measured, on short synthetic tests. Other services are estimates. This replaces the earlier estimates in the [technical architecture](../architecture/technical-architecture-windows-wsl2.md).

## Host capacity

| Resource | Measured |
|---|---|
| RAM | 15.82 GB |
| RAM free | 7.93 GB, with Brave using about 3 GB |
| CPU | AMD Ryzen 7 7435HS, 8 cores, 16 threads |
| `C:` free | 62.27 GB after Phase 6 |

## RAM

| Consumer | Allocation | Basis |
|---|---|---|
| Windows host | About 8 GB | Observed use |
| WSL2 cap | 5.8 GiB + 4 GiB swap | Effective limit |
| Kali, only when needed | 2 GB | Configured |
| **Total with everything running** | **About 15.8 GB** | Effectively all RAM |

Close Brave and game launchers before running Kali alongside the stack.

### Inside WSL2

| Component | Budget | Basis |
|---|---|---|
| Ubuntu | 0.6 GB | **Measured** 519 MiB idle |
| OpenSearch | 2.5 GB | **Measured** 1.68 GiB idle, 1.82 GiB peak with 1 GiB heap in Phase 6. 1.8 to 2.5 GiB with real data in Phase 8, including page cache |
| Kafka | 0.9 GB | **Measured** 0.41 GiB idle, 0.48 GiB peak with 512 MiB heap in Phase 6. Up to 0.9 GiB with real data in Phase 8, including page cache |
| Vector aggregator | 0.3 GB | **Measured** 45 MiB idle, 150 to 180 MiB live, 301 MiB draining a backlog at 526 events/s |
| Seal verifier | 0.05 GB | **Measured** 13 MiB idle, 22 to 32 MiB live. Service limit 512 MiB |
| Detection engine | 0.1 GB | **Measured** 31 MiB in service, 63 MB scanning a week of data. Service limit 256 MiB |
| **Core total** | **4.8 GB** | |
| Dashboards, on demand | 0.5 GB | Estimate |
| Enrichment service | 0.1 GB | **Measured** 18 MiB in service, 68 MiB peak. Service limit 192 MiB |
| Asset service | 0.05 GB | **Measured** 16 to 22 MiB in service, 28 MiB peak. Service limit 128 MiB |
| Linux agent | 0.1 GB | **Measured** 53 MiB in service, 61 MiB peak. Service limit 192 MiB |
| Attack path service | 0.05 GB | **Measured** 16 to 22 MiB in service. Service limit 128 MiB |
| Pipeline health service | 0.05 GB | **Measured** 20 to 39 MiB in service, 41 MiB peak seen. Service limit 128 MiB |
| Dashboard service | 0.05 GB | **Measured** 19 MiB idle, 52 MiB peak at sign-in. Service limit 192 MiB |
| Correlation service | 0.1 GB | **Measured** 21 MiB in service, 90 MiB peak in a 5,000 alert test. Service limit 192 MiB |
| Grafana, from Phase 11 | 0.2 GB | Estimate |
| ML scoring, scheduled | 0.15 GB | Estimate |
| **All components** | **5.85 GB** | |
| Margin for page cache and bursts | None left once every planned part runs. Page cache is reclaimable, so the OpenSearch and Kafka figures overstate need. Re-measure in Phase 11 | |

Do not allocate all WSL memory to services, because OpenSearch and Kafka both rely on page cache.

**Measured with both running:** WSL used 2,611 MiB idle and 2,843 MiB at peak of 5,928 MiB. At least 3,084 MiB stayed available, and no swap was used. That available figure includes reclaimable page cache.

### OpenSearch heap

- OpenSearch recommends heap at half of system RAM, and its default is 1 GB. Half of this WSL cap would be about 2.9 GB, which would crowd Kafka and page cache.
- **Start at `-Xms1g -Xmx1g`**, with both values equal.
- Raise to 1.5 GB only if heap pressure appears and memory is spare. Phase 6 showed none: sampled heap use stayed below 45% with no old-generation GC, on a short test. Real event volume may differ.

### Swap

- 4 GiB of swap stays as a safety margin for bursts.
- OpenSearch advises against swapping. `bootstrap.memory_lock=true` with `LimitMEMLOCK=infinity` is active, and `vm.swappiness` is now 10. Phase 6 used no swap.
- Sustained swap use is a warning that the stack is too large for this host.

## CPU

| Consumer | Allocation |
|---|---|
| WSL2 | 4 of 16 threads |
| Kali | 2 of 16 threads |
| Windows | The rest |

No per-service CPU limits are set. OpenSearch measured 1.4 to 2.0% of one core idle and 230% during a short indexing run. Kafka measured 3.4% idle and 60.8% while receiving 10,000 records per second. Limits are not needed yet. Use systemd `CPUWeight` if contention appears. ML training and detection runs should avoid overlapping.

## Disk

| Use | Budget |
|---|---|
| OpenSearch indices | 12 GB |
| Kafka | 4 GB |
| WSL OS and packages | 5 GB |
| Logs and enrichment data | 2 GB. Enrichment uses 156 MB, measured |
| WSL exports | 6 GB |
| **SIEM total** | **29 GB** |
| WSL swap, worst case | 4 GB |

This is lower than the earlier 36 GB estimate, because that estimate left too little room on `C:`. Phase 6 raised two lines from measurements: the VHDX is 4.6 GiB with OpenSearch and Kafka installed, and the three exports total 5.74 GiB. The exports line reflects what exists, not a target.

### Capacity check

Measured after Phase 6. 10.34 GiB of the budget is already used, so about 19 GiB remains, plus swap.

| Scenario | `C:` free after |
|---|---|
| Today | 62.27 GB |
| SIEM at full budget, with swap | About 40 GB |
| Then Kali grows to its full 82,015 MB capacity (about 34 GB more) | **About 6 GB** |
| SIEM at full budget, Kali limited to 10 GB of growth | About 30 GB |

The target is to keep at least 25 GB free, so **Kali's growth is the main disk risk**. No disk has been changed.

**Recommendations**

1. Treat 10 GB as a working limit on Kali's growth, and check its size before each test session.
2. Review Docker Desktop's 19.14 GB `docker_data.vhdx`. This is an owner decision, because D18 no longer needs it. It has not been inspected or deleted.
3. Keep only two WSL exports. Three exist. Removing the two older ones would free 2.56 GiB, but that is an owner decision and none have been deleted.

| `C:` free | Action |
|---|---|
| Below 30 GB | Warning: review retention and reduce what's stored |
| Below 20 GB | Stop ingestion and free space before continuing |

## Retention

Real event volume is still unknown. Phase 7 [estimates](windows-telemetry-preparation.md#event-volume-estimate) 18 to 540 MB of raw JSON per day, and it must be measured now that the Windows changes are applied. This is the sizing formula:

```text
GB per day = events per second × 86,400 × average document bytes ÷ 1,000,000,000
```

**Assumed example:** 10 events per second at 1.5 KB each is about 1.3 GB per day, so 12 GB holds about 9 days.

| Store | Starting policy |
|---|---|
| OpenSearch | One primary shard, no replicas, daily indices. ISM delete at 7 days. Total size is held by the scheduled disk check, because ISM conditions apply per index |
| `siem-raw-logs` | 3 partitions, `retention.bytes` 1 GB each, 72-hour retention |
| `siem-alerts`, `siem-incidents` | 1 partition each, 256 MB each |
| Vector buffer on Windows | Disk buffer, 1 GiB, blocks when full |
| Logs | systemd journal limited, plus rotated service logs |
| Health history | Local: samples 48 hours, hourly 30 days, transitions 90 days, diagnostics 7 days. OpenSearch: transitions and episodes at least 90 days, metrics at least 30 days. See [Pipeline Health](pipeline-health.md#retention) |
| Windows event logs | Security 128 MiB, Sysmon 128 MiB, PowerShell 64 MiB, Task Scheduler 32 MiB, about 320 MiB more on `C:` at most |

Kafka's `retention.bytes` applies per partition, so the totals above come to about 3.5 GB.

## OpenSearch disk watermarks will not protect `C:`

ext4 in WSL reports about 1 TB, while the VHDX actually lives on `C:` with 67 GB free. Phase 6 confirmed that the OpenSearch node itself reports a total of 1.08 TB, so its percentage-based watermarks would not trigger before `C:` runs out.

If `C:` fills, VHDX writes can fail, which risks corruption. So:

- Rely on ISM age-based deletion and a total-size check, not watermarks.
- Check `C:` free space from a scheduled job, using `df /mnt/c`. This job has to be built.
- Treat the thresholds above as hard operational limits.

## Assumptions and limits

- OpenSearch figures are measured on a short synthetic test. Other service figures are still estimates.
- Phase 6's synthetic documents compress unusually well, so they say nothing about real document size.
- Windows use varies, and 8 GB is only one observation.
- The VHDX grows but does not shrink automatically, so deleted data does not return space to `C:`.
- Volume, document size and compression are unknown.
