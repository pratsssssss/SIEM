# ADR-0002: Windows, WSL2 and Kali Platform Migration

| | |
|---|---|
| **ADR status** | Accepted for D17. D18 to D21 are Pending approval |
| **Date** | 2026-10-30 |
| **Supersedes** | D1 in ADR-0001. It also closes D2 |
| **Status table** | [Decision status](decision-status.md) |
| **Later changes** | D18, D19 and D20 were resolved in [ADR-0003](0003-service-runtime.md), [ADR-0004](0004-wsl-lifecycle-service-management.md) and [ADR-0005](0005-kafka-listener-design.md). Their text below is preserved as first written |
| **Rationale** | [Migration rationale and limitations](../architecture/migration-rationale-and-limitations.md) |

## Context

ADR-0001 placed the SIEM and the monitored workload on one VirtualBox Ubuntu Server VM. That VM showed repeated execution stalls, and the project owner selected a new platform. The VM has been retired and deleted.

ADR-0001 is preserved as written, as a historical record. Where the two differ on platform, this ADR takes precedence.

Status meanings are the same as in ADR-0001.

## Decision summary

| ID | Decision | Status | Needed by |
|---|---|---|---|
| D17 | Windows 11 endpoint, WSL2 SIEM host, Kali attacker | **Approved** | Now |
| D18 | Service runtime: native or containers | **Pending approval** | Before Phase 5 |
| D19 | WSL service lifecycle and keep-alive | **Pending approval** | Before Phase 8 |
| D20 | Kafka bind address for Windows access | **Pending approval** | Phase 6 test |
| D21 | Kali telemetry collection path | **Pending approval** | Before Phase 10 |

## D17: Windows endpoint, WSL2 SIEM host, Kali attacker

**Decision:**

- **Windows 11 is the monitored endpoint.** It produces real operating-system telemetry.
- **WSL2 Ubuntu 24.04 is the SIEM infrastructure host.** It runs Kafka, the Vector aggregator, OpenSearch and the analysis services.
- **Kali is the controlled attacker VM** on VirtualBox.
- **The VirtualBox Ubuntu Server VM is retired.** It is not part of the current platform.
- **WSL2 is not the source of Windows telemetry.** Windows telemetry is collected from the actual Windows operating system, by a native Windows agent.

**Why:**

- Repeated VirtualBox NEM execution stalls affected the Ubuntu Server VM.
- VirtualBox 7.2.22 and reducing Ubuntu to 2 vCPUs did not resolve those stalls.
- WSL2 passed a bounded 120-second test with 3 CPU workers and a 1.5 GiB memory walk. The maximum observed gap was 0.25 seconds, with no kernel stall messages.

This is encouraging evidence, not proof of long-term production stability.

**Trade-offs:**

- A real Windows endpoint gives rich, genuine telemetry. In exchange, the SIEM and the monitored endpoint share one physical laptop, so a host failure stops both.
- WSL2 avoids the VirtualBox NEM path for the SIEM. In exchange, WSL has its own lifecycle, and it can stop when idle unless that is managed (D19).
- Kali still runs on VirtualBox under the same active hypervisor, so it may still be exposed to NEM stalls. This is untested on 7.2.22.
- Attacks target a real personal machine, not a disposable VM. Test scope must stay controlled.

**Consequences:**

- Linux auditd, UFW and SSH telemetry from the retired VM no longer exist. Linux coverage is reclassified in the detection coverage review.
- The endpoint agent moves from Linux to Windows. The ingestion principles in D4 still apply.
- The Windows hypervisor must stay enabled, because WSL2 depends on it.
- Kafka and OpenSearch must not be exposed to the LAN or the host-only network.

**Revisit if:** WSL2 shows sustained stalls under the real stack, or the host cannot run the stack alongside normal Windows use.

## D18: Service runtime

**Status:** Pending approval. Nothing may assume Docker is required.

| Factor | Native services under systemd | Containers (Docker Engine or Podman in WSL2) |
|---|---|---|
| Memory overhead | Lowest | Some added overhead |
| Upgrade and rollback | Package or tarball management | Image tags are simple to pin and roll back |
| Learning value | Direct view of each service | Closer to common SIEM deployments |
| Lifecycle | Plain systemd units | An extra daemon, plus systemd or Compose |
| Kafka listeners | One listener can be enough | A second internal listener is likely needed |
| Data paths | Direct paths under `/home/linux/siem/data` | Bind mounts to the same paths |

**To resolve:** compare install steps, memory use and upgrade path for OpenSearch and Kafka, then record the choice before Phase 5.

## D19: WSL service lifecycle

**Status:** Pending approval. No keep-alive is configured.

Microsoft documents `instanceIdleTimeout` (default 15,000 ms, with `-1` disabling automatic shutdown) and `vmIdleTimeout` (default 60,000 ms). Whether running systemd services count as activity on this host is untested.

| Option | Benefit | Cost |
|---|---|---|
| Start WSL manually | Simple, and memory is only used when wanted | Telemetry buffers on Windows while WSL is down |
| Disable idle shutdown | Services stay up once started | Up to the WSL memory cap stays in use |
| Windows logon task | Stack is available after logon | Adds a startup dependency |

**To resolve:** test idle behaviour with a real service, then choose.

## D20: Kafka bind address

**Status:** Pending approval, awaiting a test.

Microsoft documents that ports bound to wildcard or localhost in WSL2 should be reachable from the host through `localhost:port`. The only test on this host used a listener bound to `0.0.0.0`. It did not prove that Kafka bound only to `127.0.0.1` is reachable from Windows.

**To resolve:** test both bind addresses in Phase 6, as set out in the [networking design](../architecture/windows-wsl2-networking.md). Prefer `127.0.0.1` if it works.

## D21: Kali telemetry collection path

**Status:** Pending approval.

**Recommendation:** an operator-run attack ledger, copied in batches and ingested through a controlled path. Kali gets no network route to Kafka. Details and trade-offs are in the [Kali design](../pipeline/kali-attacker-telemetry.md).

## Effect on ADR-0001

- **D1:** superseded by D17.
- **D2:** closed. The diagnosis finished, and the affected VM is retired. The restriction on disabling the hypervisor remains, and WSL2 now requires it.
- **All other decisions:** see the [decision status table](decision-status.md). No Pending decision is approved by this ADR.

_Internal test reports and planning records mentioned here are not published with Version 1._
