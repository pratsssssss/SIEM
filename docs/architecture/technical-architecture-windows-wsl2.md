# Technical Architecture: Windows, WSL2 and Kali

| | |
|---|---|
| **Date** | 2026-10-30 |
| **Status** | Current architecture. OpenSearch and Kafka are deployed, see [OpenSearch deployment](../operations/opensearch-deployment.md) and [Kafka deployment](../operations/kafka-deployment.md). Other SIEM services are not deployed yet |
| **Decisions** | [Decision status](../adr/decision-status.md) is the authoritative status view |
| **History** | The technical assessment is kept as the Phase 0 baseline |

The detection and correlation designs from the assessment are preserved. This document changes where they run and where telemetry comes from.

**Version 1:** the pipeline below is what is built and released. ML detection, generated reports and delivery are not built.

## Platform roles

| Host | Role | Runs |
|---|---|---|
| **Windows 11** | Monitored endpoint | Sysmon, Windows Event Logs, native Vector agent |
| **WSL2 Ubuntu 24.04** | SIEM infrastructure host | Kafka, Vector aggregator, OpenSearch, detection, enrichment, correlation, assets, attack paths, health, SOC dashboard |
| **Kali VM** | Controlled attacker | Attack tools and the attack ledger |

The VirtualBox Ubuntu Server VM is retired and is not part of this architecture.

## Architecture

This is the intended eventual design, not the initial deployment. The [deployment roadmap](../operations/deployment-roadmap.md) adds components one at a time.

```text
 KALI VM (VirtualBox)          WINDOWS 11 (monitored endpoint)
 controlled attacker           ┌─────────────────────────────────────────┐
        │ host-only            │ Sysmon, Security, System, Application,  │
        └─────────────────────>│ PowerShell, Defender, firewall log      │
          192.168.56.1         │                  │                      │
                               │          Vector agent (native)          │
                               │                  │ 127.0.0.1:9092       │
                               │ ┌────────────────▼─────────────────┐    │
                               │ │ WSL2 UBUNTU (SIEM host)          │    │
                               │ │ Kafka (KRaft): siem-raw-logs     │    │
                               │ │        │                         │    │
                               │ │ Vector aggregator                │    │
                               │ │  VRL, ECS, GeoIP, asset CSV      │    │
                               │ │        │             │           │    │
                               │ │        ▼             ▼           │    │
                               │ │ OpenSearch    dead-letter route  │    │
                               │ │        │                         │    │
                               │ │ Sigma + custom rule detector     │    │
                               │ │        │ siem-alerts             │    │
                               │ │ Enricher (feeds, GeoIP)          │    │
                               │ │        │                         │    │
                               │ │ Correlator                       │    │
                               │ │        │ siem-incidents          │    │
                               │ │ Asset inventory, attack paths    │    │
                               │ │ Pipeline health                  │    │
                               │ │ SOC dashboard (loopback HTTPS)   │    │
                               │ └──────────────────────────────────┘    │
                               └─────────────────────────────────────────┘
```

## Telemetry categories

| Category | Source | Design |
|---|---|---|
| Windows | The real Windows OS | [Windows telemetry](../pipeline/windows-telemetry.md) |
| WSL2 Linux | The SIEM host | [WSL2 Linux telemetry](../pipeline/wsl2-linux-telemetry.md) |
| Kali | Attack records | [Kali telemetry and isolation](../pipeline/kali-attacker-telemetry.md) |

The categories stay separate. `labels.source_role` is `windows_endpoint`, `wsl_infrastructure` or `kali_attacker`.

## Preserved design

| Area | Status |
|---|---|
| Kafka KRaft broker, with no RabbitMQ | Preserved |
| Single ingestion path, no agent dual-write | Preserved |
| No `siem-normalized` topic | Preserved |
| Scheduled Sigma queries with watermarks | Preserved |
| Custom Python detection runner | Preserved |
| Entity-based correlation | Preserved |
| systemd timers first, Prefect only if justified | Preserved |
| Kubernetes as an optional stretch goal | Preserved |

Pipeline detail is in [ingestion pipeline](../pipeline/ingestion-pipeline.md), and connectivity is in [networking design](windows-wsl2-networking.md).

## Resource architecture

The host has 16 GB RAM. WSL2 is capped at about 5.8 GiB with 4 GiB swap and 4 CPUs. Figures below are the Phase 4 planning estimates. The current budget is in the [resource budget](../operations/resource-budget.md), which replaces this section and the disk budget below where they differ.

| Component | Estimate | Runs |
|---|---|---|
| OpenSearch (about 1 GB heap) | 2 GB | Always |
| Kafka (about 512 MB heap) | 0.7 GB | Always |
| Ubuntu | 0.3 GB | Always |
| Vector aggregator | 0.1 GB | Always |
| Python detection | 0.25 GB | Always, once deployed |
| **Core subtotal** | **About 3.35 GB** | |
| Dashboards | 0.5 GB | On demand |
| Grafana | 0.2 GB | From Phase 11 |
| ML scoring and correlation | 0.25 GB | Scheduled |
| **All components** | **About 4.3 GB** | |

**Should everything run at once?** It fits on paper, with about 1.5 GB to spare, but this is unproven. Priorities:

1. OpenSearch and Kafka always come first.
2. Run Dashboards only when needed.
3. Add Grafana only when health dashboards are built.
4. Run ML training separately from attack tests, because its memory burst is unmeasured.

Vector and Sysmon on Windows use Windows memory, not the WSL allowance. Sysmon is installed and measured about 31 MiB in a short test. Vector is not installed yet. See [Vector compatibility](../pipeline/windows-vector-compatibility.md) and [Sysmon deployment](../operations/sysmon-deployment.md).

With Kali running, Windows has about 8 GB left, which is about what it has been using. Close heavy applications first.

## Disk and retention

`C:` had about 72 GB free at the last check. Data sits inside the WSL VHDX on `C:`, and the VHDX does not shrink automatically.

| Use | Proposed budget |
|---|---|
| OpenSearch indices | 20 GB |
| Kafka | 4 GB total across all partitions |
| WSL OS and packages | 5 GB |
| Logs and enrichment data | 2 GB |
| WSL exports on Windows | 5 GB |
| **Total SIEM budget** | **About 36 GB** |
| Kept free on `C:` | At least 25 GB |

These are proposals until real Windows event volume is measured in Phase 7.

- **OpenSearch:** one primary shard, no replicas, daily indices, ISM deletion at about 14 days. Tune this from measured volume.
- **Kafka:** `retention.bytes` applies per partition, so the limit must be calculated across partitions.
- **Kali:** its dynamic disk can still grow by about 33 GB, which competes with this budget.
- **Backups:** old WSL exports must be rotated. They also consume `C:`.

## Security

- Kafka and OpenSearch stay on loopback, and are never exposed to the LAN or Kali.
- Log content is untrusted input to every stage that reads it.
- Windows command lines and scripts can contain secrets, so they are masked before storage and display.
- The SIEM shares a host with its monitored endpoint. A Windows compromise is a SIEM compromise, and this is an accepted lab risk.
- Attacks target a real machine, so the safety rules in the Kali design apply.

## Open decisions

Kali collection (D21) is Pending, along with D6, D11, D12, D13 and D15. Runtime (D18), WSL lifecycle (D19) and the Kafka listener (D20) are decided in [ADR-0003](../adr/0003-service-runtime.md), [ADR-0004](../adr/0004-wsl-lifecycle-service-management.md) and [ADR-0005](../adr/0005-kafka-listener-design.md), D20 passed its Phase 6 test with real Kafka, and its check from Kali is still open. See [decision status](../adr/decision-status.md). Service management is in [runtime and service management](runtime-and-service-management.md).

_Internal test reports and planning records mentioned here are not published with Version 1._
