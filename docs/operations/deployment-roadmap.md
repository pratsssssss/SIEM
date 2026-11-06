# Deployment Roadmap

**Status:** Current roadmap for the Windows, WSL2 and Kali platform. It replaces the phase plan in section 12 of the technical assessment, which is kept as history.

Each phase ends with a recorded result in `docs/verification/`. Services are added one at a time.

## Completed

| Phase | Result |
|---|---|
| 0 | Repository foundation and accepted documentation baseline |
| 1, 1B | Lab diagnosis; stalls reproduced and not resolved on VirtualBox |
| 2 | Migration: Ubuntu VM retired, WSL2 Ubuntu 24.04 installed |
| 3 | WSL foundation: directories, limits and first backup |
| 4 | Architecture migration documentation |
| 5 | Runtime and infrastructure foundation: D18, D19 and D20 decided, lifecycle and forwarding tested |
| 6 | Core services: OpenSearch and Kafka deployed and validated, with the open items listed below |
| 8 | Vector and ingestion pipeline: Windows agent, Go verifier, aggregator, ECS, templates, ISM, dead letters, disk guard and alerts. Accepted on 2026-10-31 |
| 9 | Detection engine: Sigma and custom rules, runner, alerts to `siem-alerts`. Accepted on 2026-10-31 |
| 10 | Threat intelligence and enrichment: feeds, GeoIP, provider adapters, scoring. Accepted on 2026-10-31 |
| 11 | Event correlation and incident management. See the acceptance report |
| 12 | Reserved for Version 2. Not part of this release |
| 13 | WSL2 Linux telemetry: a second agent with its own key, through the Phase 8 path, ECS, Linux rules and asset identity. See the acceptance report. SSH, auditd and firewall sources do not exist on this host |
| 15 | Attack path validation: a deterministic, evidence-backed graph per incident, with tiers, doubts, gaps and history. See the acceptance report. Kali is not required (D21), and Linux process execution stays deferred (D15) |
| 16 | Pipeline health: `siem-health`, a separate read-only observer from collection to analysis, with unknown kept apart from unhealthy. See the acceptance report and [operations](pipeline-health.md). D13 is implemented without Grafana or a metrics store |
| 17 | SOC analyst dashboard: a self-hosted workspace over every subsystem, with a single root-provisioned administrator and no privileged control over the SIEM. See the acceptance report and [operations](dashboard.md) |
| 14 | Asset inventory and context: identity, provenance, history, lifecycle, relationships and investigation context. See the acceptance report. The Windows snapshot task is registered |

Phase 5 changed scope: it became a decision and test phase, and it deployed nothing. OpenSearch moved to Phase 6, and later phase numbers are unchanged.

Phase 9 changed scope: the owner made the detection engine Phase 9, so it swapped places with WSL2 Linux sources, now Phase 13. See [ADR-0009](../adr/0009-detection-engine.md).

Phase 10 changed scope: the owner made threat enrichment Phase 10. This took in the old Phase 12 GeoIP work and the old Phase 15, so attack path validation moved to Phase 12. See [ADR-0010](../adr/0010-threat-enrichment.md).

Phase 11 changed scope: the owner made correlation Phase 11, and reserved Phase 12 for Version 2 work. Attack path validation and asset data are scheduled separately, so their numbers below are not a sequence. Pipeline visibility no longer has a phase number. See [ADR-0011](../adr/0011-correlation-and-incidents.md).

Phase 17 is the SOC analyst dashboard, as the owner's brief named it. That number held report generation, which is Version 2 work, so it became unscheduled. No completed phase was renumbered.

Phase 16 is pipeline health. It was unscheduled. Phase 15 was taken and the numbered list resumes at 17, so 16 was the first unused number, and nothing was renumbered.

Phase 14 is asset data. The brief asked for the next number, Phase 13 was held by WSL2 Linux sources, and 14 was the first unused number, so nothing was renumbered. Phase 13 followed it. It replaces the old scope of an asset CSV with a full subsystem, and the aggregator lookup in D8 was not built. See [ADR-0013](../adr/0013-asset-inventory.md).

## Remaining

| Phase | Work | Needs first | Exit criteria |
|---|---|---|---|
| **7. Windows endpoint telemetry** | **Configured and validated, volume not yet measured.** Done: inventory, [source matrix](../pipeline/windows-telemetry-source-matrix.md), [configuration](windows-telemetry-preparation.md), [Sysmon](sysmon-deployment.md), [Vector review](../pipeline/windows-vector-compatibility.md) and configuration record. Restart check passed on 2026-10-31. Remaining: 24 to 48 hours of normal use to measure volume | None | Each source produces real events (**met**), and volume is measured (**open**) |
| **Isolation check, unscheduled** | Confirm from Kali that ports 9092, 9093, 9200 and 9300 are unreachable. The old D20 check, kept apart from attack paths | Kali running | Those ports are unreachable from Kali |
| **18. Delivery** | PDF, Slack, JIRA | Generated reports, Version 2 | Channel failure does not lose reports |
| **19. Feedback** | TP and FP capture | Phase 18 | Labels stored |
| **20. ML** | Windows baseline, statistical baseline, Isolation Forest | Weeks of real data | Compared with baseline on known attacks |
| **21. Hardening** | TLS, authentication, restore tests, load tests | All above | Security checklist passed |

## Phase 6 exit criteria

Decisions: [D18](../adr/0003-service-runtime.md), [D19](../adr/0004-wsl-lifecycle-service-management.md) and [D20](../adr/0005-kafka-listener-design.md). Designs: [runtime](../architecture/runtime-and-service-management.md), [Kafka networking](../architecture/kafka-networking-design.md) and [resource budget](resource-budget.md).

**Step A exit criteria (OpenSearch): all met on 2026-10-30.**

- Bound to localhost, with health green and no replicas.
- Document round trip works, and data survives a restart.
- Heap fixed at 1 GB, and real memory measured.
- Stall check passes under the running service.
- Real stop time measured against the 120 s proposal.

Index templates and ISM moved to Phase 9, because they depend on the ECS mappings built there.

**Step B exit criteria (Kafka): met on 2026-10-30, except the check moved below.**

- Bound to loopback only as a plain IPv4 socket, confirmed with `ss -tln`, and held by `wslrelay` on Windows.
- Produce and consume work from Windows and WSL2 with a real client.
- Replay works, and data survives a restart.
- Heap fixed at 512 MB, and real memory measured.

**Both steps together: met on 2026-10-30.**

- `siem-up.ps1` and `siem-down.ps1` work, and services stop in reverse order.
- `siem-down.ps1` returns only after every service is inactive.
- Budgets are updated from measurements.

**Open items carried forward.** These were earlier exit criteria or tasks that Phase 6 did not meet. They are recorded here, not dropped:

| Item | Why open | Now due |
|---|---|---|
| D20 checks from Kali | Kali stayed powered off | Phase 10 |
| Unclean stop recovers within documented limits | Crash tests were excluded | **Closed.** Passed in Phase 8 |
| WSL termination with a live client | Not run | **Closed.** Passed in Phase 8 |

The OpenSearch admin password item is closed: the owner reported a successful rotation on 2026-10-30. The hold session item is closed: it passed on 2026-10-31.

## Notes

**Network telemetry (D15):** this attaches to Phases 7 and 13 once decided. Sysmon network events and firewall logging are the current candidates.

**Orchestration (D14):** systemd timers are added as each job appears.

## Dependencies to watch

- **D20** passed with real Kafka, and its Kali check is open.
- **Sysmon** must exist before Vector starts, because a single-channel source exits if its channel is missing.
- **Sustained ingestion** should wait for ISM and the `C:` disk check, which the plan places before any indexing.
- **`C:` space:** Kali's growth, WSL exports and the 19.14 GB Docker data file affect the disk budget.
- **Windows changes** need elevation, plus the owner's approval. Phase 7's are applied, and rollback is documented.
- **Secrets in logs:** 4104 and Sysmon 1 can hold secrets, and Kafka has no authentication or encryption until Phase 21. [D22](../adr/0006-sensitive-telemetry-handling.md) protects the listed fields, and does not authenticate Kafka events.
- **A real baseline** needs normal Windows use, so collection should start as soon as Phase 9 is stable.
- **Kali** must be confirmed stable by Phase 10.

## Stability checks

Each service phase repeats a bounded stall check while the new service runs. WSL2's single 120-second test is not enough evidence on its own. Any sustained stall stops the roadmap for review.

_Internal test reports and planning records mentioned here are not published with Version 1._
