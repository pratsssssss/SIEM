# ADR-0003: Service Runtime

| | |
|---|---|
| **ADR status** | Approved under the Phase 5 delegation, subject to owner review |
| **Date** | 2026-10-30 |
| **Decision** | D18 |
| **Depends on** | [ADR-0002](0002-windows-wsl2-kali-platform.md), D17 |
| **Design** | [Runtime and service management](../architecture/runtime-and-service-management.md) |

## Context

ADR-0002 left the runtime open, and Docker was not to be assumed. The host has 16 GB RAM, and WSL2 is capped at about 5.8 GiB. The priority is a stable, reproducible deployment that does not overwhelm the host.

## Decision

**Run OpenSearch, Kafka and Vector natively inside WSL2 Ubuntu, as systemd services.**

| Component | Install method | Candidate version |
|---|---|---|
| OpenSearch | Official apt repository or `.deb`, version pinned | 3.9.0 |
| Kafka | Official signed tarball under `/opt`, with a project systemd unit | 4.4.0, published by Apache |
| Java for Kafka | Ubuntu `openjdk-17-jre-headless` | 17.0.20 |
| Vector | Official package, version pinned | 0.61.0 |

Candidate versions must be reconfirmed at deployment. OpenSearch uses its bundled JDK. Package upgrades for these services are held, and they happen only deliberately.

## Options compared

| Factor | A. Native in WSL2 | B. Docker Engine in WSL2 | C. Docker Desktop |
|---|---|---|---|
| RAM and CPU overhead | Lowest: no daemon | `dockerd` and `containerd` add some memory (unmeasured) | Highest: desktop app, backend and a separate `docker-desktop` distro |
| Disk | Packages only | Images plus layers | Already holds a 19.14 GB `docker_data.vhdx` on this host |
| Ubuntu 24.04 and WSL2 | OpenSearch tests Ubuntu 24.04. Kafka and Vector are Linux native | Ubuntu 24.04 is supported. Docker's Ubuntu page does not mention WSL, and Docker Desktop's docs advise against having both installed, which applies here | Supported on WSL2. Runs in its own distro, not Ubuntu |
| systemd integration | Direct | `docker.service` plus Compose, which is one layer removed | Outside Ubuntu's systemd |
| Startup and shutdown | Plain unit ordering, and reverse order on stop | Compose or per-container units | Depends on the Windows app being running |
| Version pinning | Apt holds and tarballs | Excellent: image tags and digests | Excellent for images, but the app itself also updates |
| Data persistence | Direct paths under `/home/linux/siem/data` | Bind mounts to the same paths | Bind mounts cross a distro boundary, or use its VHDX |
| Operational complexity | Lowest moving-part count. More manual install work | One more daemon and network layer | Most layers |
| Networking | Bind directly to `127.0.0.1` | Adds Docker's `iptables` rules, and `iptables` is not installed today. Published ports bypass firewall rules | Extra forwarding path |
| Kafka listeners | One listener serves both client types | Second listener likely | Second listener likely |
| 16 GB host fit | Best | Reasonable | Poorest |

## Why

- **Stability on this host matters most.** Fewer layers mean fewer failure modes. The D20 tests show native binds behave well.
- **Memory is the tight resource.** Every daemon competes with OpenSearch and Kafka inside a 5.8 GiB cap.
- **Lifecycle fits directly.** D19 depends on ordered systemd stops, because WSL gives services only about 9 s when it ends.
- **Official packages exist for each service.** Containers are not needed for compatibility.

Options B and C were not rejected for lack of capability. Their overhead was not measured, so this relies on architecture rather than a benchmark.

## Trade-offs

- **Reproducibility:** containers rebuild more easily. Native services need scripted installs in `deploy/` and pinned versions to compensate.
- **Upgrades:** rollback is more manual than changing an image tag. WSL exports before upgrades offset this.
- **Isolation:** services share one OS, so a dependency conflict is possible. Dedicated service users limit the impact.

## Consequences

- Docker Engine and Docker Desktop are not used by the SIEM.
- Docker Desktop should stay stopped during SIEM use, because it shares the WSL memory cap.
- Installs must be scripted and repeatable, and they are kept in `deploy/`.
- Service users need access to `/home/linux/siem/data`, because `/home/linux` is mode 750. See the design document.
- Kafka's default 1 GB heap must be overridden explicitly.

## Revisit if

Native installs prove unreliable, or dependency conflicts appear.
