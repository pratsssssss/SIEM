# Migration Rationale and Limitations

**Date:** 2026-10-30. **Decision:** [ADR-0002, D17](../adr/0002-windows-wsl2-kali-platform.md).

## Why the platform changed

The VirtualBox Ubuntu Server VM could not run a SIEM reliably.

| Observation | Result |
|---|---|
| Execution engine | Every observed session used NEM, reporting `AMD-V is not available` |
| Historical guest lockups | Up to 488 s, across 2 GB, 4 GB and 8 GB RAM configurations |
| Reproduced on VirtualBox 7.2.4 (6 GB, 4 vCPUs) | Stalls up to 338 s under CPU load alone, and 110 s under a single-threaded memory walk |
| I/O-only load | Clean, with a 0.43 s maximum gap |
| Host memory during those tests | Not exhausted |
| VirtualBox 7.2.22 with 2 vCPUs | A 771 s stall during boot left the root disk driver unloaded. A paced 1 GiB memory test then stalled for 10.9 s |
| Linux workaround `nox2apic rcupdate.rcu_normal=1` | Not applied. The guest had no x2APIC flag, and the stall did not match the reported issue |

The cause was never proven, because no session ran without NEM. The evidence pointed at VirtualBox's NEM execution path rather than the guest.

## Why WSL2

WSL2 runs on the Windows hypervisor directly and does not use VirtualBox's NEM path.

| WSL2 test | Result |
|---|---|
| Load | 3 CPU workers plus a 1.5 GiB memory walk |
| Duration | 120 s |
| Maximum gap | 0.25 s |
| Kernel stall messages | 0 |

Windows also becomes a real monitored endpoint, which gives the project richer telemetry than the old VM.

## Limitations

- **The WSL2 result is encouraging, not proof.** It was one bounded test, not a long-term production run, and it did not use Kafka or OpenSearch.
- **Shared host.** Windows, the SIEM and Kali share one laptop, so a host failure stops everything. A compromised Windows endpoint also threatens the SIEM.
- **Kali still uses VirtualBox.** It may still be affected by NEM stalls, which is untested on 7.2.22.
- **WSL lifecycle.** WSL can stop when idle (D19). Windows telemetry must be buffered when WSL is down.
- **Memory.** WSL2, Kali and Windows together nearly fill the 16 GB host.
- **Storage.** Everything is on one SSD, and the WSL backup does not protect against disk failure.
- **Linux telemetry was lost.** auditd, UFW and SSH data from the old VM no longer exist.

## Evidence retention

The VM, its backup and the Phase 1 and 1B evidence folders were deleted with the owner's authorization. The figures above come from the reports of those phases. A partial copy of the Phase 1 evidence remains in a temporary folder and is not a durable record.
