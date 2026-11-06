# Architecture Decision Status

Last reviewed: 2026-10-31, at the close of Phase 15.

This table is the current status view. Decision text lives in ADR-0001, [ADR-0002](0002-windows-wsl2-kali-platform.md), [ADR-0003](0003-service-runtime.md), [ADR-0004](0004-wsl-lifecycle-service-management.md), [ADR-0005](0005-kafka-listener-design.md) and [ADR-0006](0006-sensitive-telemetry-handling.md). Neither approval nor history is changed by this table.

**Approval** is the owner's decision. **Review result** is whether the decision still fits the new platform.

| ID | Decision | Approval | Review result | Note |
|---|---|---|---|---|
| D1 | Single Ubuntu VM hosts SIEM and monitored asset | Approved (historical) | **Superseded** | Replaced by D17 |
| D2 | Diagnose VirtualBox/Hyper-V before further workload | Approved (historical) | **Superseded** | Diagnosis closed and the VM retired. Disabling the hypervisor stays unapproved, and WSL2 requires it |
| D3 | Kafka using KRaft | Approved | Still valid | Single-node KRaft in WSL2. The version is pinned at deployment. Listener detail depends on D20 |
| D4 | Single ingestion path, no agent dual-write | Approved | **Needs revision** | The principle holds. The agent is now Windows Vector, and event identity gains a Windows source record path |
| D5 | Scheduled Sigma queries with watermarks | Approved | Still valid | Platform independent. Timestamps from Windows need checking at ingestion |
| D6 | PPL versus Lucene backend | Decided in Phase 9 | **Tested**, see [ADR-0009](0009-detection-engine.md) | Neither: a project Query DSL backend passed 17 of 17, Lucene 8 and PPL 7. Subject to owner review |
| D7 | Custom Python detection runner | Approved | Still valid | Runs in WSL2 |
| D8 | Local enrichment at event time, external TI at alert time | Approved | Still valid | Runs in the aggregator and a Python service. Asset data now describes the Windows host. The aggregator lookup is not built: see ADR-0013 |
| D9 | Entity-based alert correlation | Approved | Still valid, refined by D32 | Entity mapping gains Windows fields: `host.name`, `user.name`, `source.ip`, `process.entity_id`. A shared host alone never makes activity causal |
| D11 | Medium-severity incident handling | Pending | **Pending further testing** | Unchanged |
| D12 | Mock threat intelligence strategy | Partly decided in Phase 10, see [ADR-0010](0010-threat-enrichment.md) | **Labelled, temporary file tested** | Still needed, because Kali uses a private address |
| D13 | Pipeline metrics implementation | **Implemented in Phase 16**, subject to owner review | Current | No separate metrics store and no Grafana. See ADR-0016 |
| D14 | systemd timers first, Prefect later if justified | Approved | Still valid | Applies inside WSL2 and depends on D19. Windows Vector runs as a Windows service |
| D15 | Network telemetry expansion | Pending; Linux process auditing **deferred by the owner in the Phase 15 brief** | **Needs revision** | The auditd and Zeek plan was Linux based. Windows options are Sysmon Event ID 3 and firewall logs. Remains Pending. auditd stays off, so Linux process execution is not collected. See ADR-0015 |
| D16 | Kubernetes is an optional stretch goal | Approved | Still valid | Unchanged |
| D17 | Windows endpoint, WSL2 SIEM host, Kali attacker | Approved | Current | Supersedes D1 |
| D18 | Service runtime: native services in WSL2 under systemd | Approved (Phase 5 delegation) | Current | ADR-0003. Depends on D17. Docker is not used. Overhead of the alternatives was not measured |
| D19 | Manual start, bounded hold session, ordered stop before WSL ends | Approved (Phase 5 delegation) | Current | ADR-0004. Depends on D17 and D18. WSL ends after about 16 s even with a service running, and gives about 9 s after SIGTERM |
| D20 | Kafka binds and advertises `127.0.0.1:9092` for both client types | Approved (Phase 5 delegation) | Still valid, Kali check open. The Phase 8 outbound firewall rule on `vector.exe` does not affect it | ADR-0005. Depends on D3, D17 and D18. Kafka's JVM must use `preferIPv4Stack=true`. Real Kafka passed metadata, advertised-listener, produce and consume tests from Windows and WSL2 in Phase 6. The check from Kali moves to Phase 10 |
| D21 | Kali telemetry collection path | **Decided by the owner in the Phase 15 brief** | Current | Kali is a controlled test machine, not a production asset or required source. No Kali collection path is built. Activity is observed through the target and existing sensors. See ADR-0015 |
| D22 | Redact and seal restricted fields on the Windows agent | Approved | Current | ADR-0006, approved 2026-10-31. Depends on D4, D17 and D20. Changes the meaning of "raw" in `siem-raw-logs`. It does not authenticate Kafka events. Its constant-time requirement is met by D23 |
| D23 | A Go seal verifier does all MAC checks and decryption, and Vector holds no field keys | Approved | Deployed | ADR-0007, approved 2026-10-31. `crypto/subtle` is not on the audit's review list |
| D24 | The agent authenticates the whole event, and a durable journal enforces identity | Approved | Deployed | ADR-0008, approved 2026-10-31. It does not add Kafka authentication |
| D31 | Correlation is a separate service, with a transactional inbox and outbox | Implemented, subject to owner review | Current | ADR-0011 |
| D32 | A rule names its link, and the weakest link limits the claim | Implemented, subject to owner review | Current | ADR-0011 |
| D33 | Incidents and incident audit go to their own indices, kept 365 days | Implemented, subject to owner review | Current | ADR-0011 |
| D34 | Analysts connect through a local socket, identified by the kernel | Implemented, subject to owner review | Current | ADR-0011 |
| D35 | Field level security keeps sensitive event text from the correlator | Implemented, subject to owner review | Current | ADR-0011 |
| D41 | Inventory is a separate service that nothing depends on. No Kafka topic | Implemented, subject to owner review | Current | ADR-0013 |
| D42 | Identity rests on machine identifiers, and a contradiction goes to a person | Implemented, subject to owner review | Current | ADR-0013 |
| D43 | Every value says how it is known, and unknown stays absent | Implemented, subject to owner review | Current | ADR-0013 |
| D44 | Inventory comes from telemetry and read-only local collection. No scanning, no new agent | Implemented, subject to owner review | Current | ADR-0013 |
| D45 | History is append-only, and a suspicious change is a lead, not an alert | Implemented, subject to owner review | Current | ADR-0013 |
| D46 | Linux is a second agent with its own key, which the verifier binds to Linux channels | Implemented, subject to owner review | Current | ADR-0014 |
| D47 | Text is sealed, and only journald's kernel-recorded fields classify an event | Implemented, subject to owner review | Current | ADR-0014 |
| D48 | Linux events have their own index family and sink. No Kafka topic | Implemented, subject to owner review | Current | ADR-0014 |
| D49 | The journal and dpkg log are the sources. A catch-up step covers earlier boots | Implemented, subject to owner review | Current | ADR-0014 |
| D50 | Attack paths are a separate, deterministic service that nothing depends on | Implemented, subject to owner review | Current | ADR-0015 |
| D51 | An edge needs evidence, and identity on one asset is what joins events. Time never does | Implemented, subject to owner review | Current | ADR-0015 |
| D52 | Confidence is an ordered tier set by the weakest stage, and no tier means compromise | Implemented, subject to owner review | Current | ADR-0015 |
| D53 | Evidence is referenced, not copied, and checked again | Implemented, subject to owner review | Current | ADR-0015 |
| D54 | What cannot be seen is part of the result | Implemented, subject to owner review | Current | ADR-0015 |
| D55 | Pipeline health is a separate observer that nothing depends on | Implemented, subject to owner review | Current | ADR-0016 |
| D56 | Unknown is a state, and silence is not evidence | Implemented, subject to owner review | Current | ADR-0016 |
| D57 | Services publish one report, and the monitor enters no private directory | Implemented, subject to owner review | Current | ADR-0016 |
| D58 | Hysteresis that cannot hide proof | Implemented, subject to owner review | Current | ADR-0016 |
| D59 | Bounded, separated health history | Implemented, subject to owner review | Current | ADR-0016 |
| D60 | One administrator, provisioned by root on the server, and unrelated to any operating system account | Decided by the owner in the Phase 17 brief | Current | ADR-0017 |
| D61 | No new dependency: standard library backend, plain modules in the browser, no build step | Implemented, subject to owner review | Current | ADR-0017 |
| D62 | Reads through a field-limited role, and changes only through each service's own validated interface | Implemented, subject to owner review | Current | ADR-0017 |
| D63 | A fixed list of allowed socket actions, because the socket group allows more | Implemented, subject to owner review | Current | ADR-0017 |
| D64 | Direct TLS on loopback, with no reverse proxy in the lab | Implemented, subject to owner review | Current | ADR-0017 |

**Totals**

| Approval | Decisions |
|---|---|
| Approved and current | D3, D4, D5, D7, D8, D9, D14, D16, D17 |
| Approved under the Phase 5 delegation, subject to owner review | D18, D19, D20 |
| Approved, historical and superseded | D1, D2 |
| Pending | D11, D12, D15 |
| Approved in Phase 8 | D22, D23, D24 |
| Implemented in Phase 9, subject to owner review | D6 result, D25, D26, D27 |
| Implemented in Phase 10, subject to owner review | D12 result, D28, D29, D30 |
| Implemented in Phase 11, subject to owner review | D31, D32, D33, D34, D35 |
| Implemented in Phase 14, subject to owner review | D41, D42, D43, D44, D45 |
| Implemented in Phase 13, subject to owner review | D46, D47, D48, D49 |
| Implemented in Phase 15, subject to owner review | D50, D51, D52, D53, D54 |
| Implemented in Phase 16, subject to owner review | D13, D55, D56, D57, D58, D59 |
| Implemented in Phase 17, subject to owner review | D61, D62, D63, D64 |
| Decided by the owner in the Phase 17 brief | D60 |
| Decided by the owner in the Phase 15 brief | D21 |
| Deferred | None |

D10, D36 to D40, D65 and D66 cover work outside Version 1, and are not listed here.

D4 stays Approved. Its revision adds Windows detail, and does not reopen the decision.

D18 to D20 were resolved because the Phase 5 assignment asked for them to be decided and recorded. The owner can still overturn them. D20 passed its Phase 6 test with real Kafka, and its check from Kali is still open.

_Internal test reports and planning records mentioned here are not published with Version 1._
