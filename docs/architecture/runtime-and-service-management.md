# Runtime and Service Management

**Status:** Implemented for OpenSearch and Kafka in Phase 6. Vector and detection parts are still design. Decisions: [D18](../adr/0003-service-runtime.md) and [D19](../adr/0004-wsl-lifecycle-service-management.md). Measurements: Phase 5 test results, OpenSearch validation and Kafka validation.

## Selected runtime

SIEM services run natively in WSL2 Ubuntu under systemd. Docker is not used.

| Service | Runs as | Config | Data |
|---|---|---|---|
| OpenSearch | `opensearch` user from the package | `/etc/opensearch` | `/home/linux/siem/data/opensearch` |
| Kafka | Dedicated `kafka` user | `/home/linux/siem/config/kafka` | `/home/linux/siem/data/kafka` |
| Vector aggregator | `vector` user from the package | `/home/linux/siem/config/vector` | Vector data directory |
| Detection services | `linux`, later a dedicated user | `/home/linux/siem/config` | OpenSearch |

**Directory access:** `/home/linux` and `siem/data` are mode 750 and owned by `linux`, so service users cannot enter them by default. Add each service user to the `linux` group for traversal, and give each service ownership of its own data directory. Do not loosen `/home/linux` to world-readable.

## Service dependencies

```text
siem.target
├── opensearch.service        (first)
├── kafka.service             After=opensearch.service
├── vector.service            After=kafka.service
└── siem-detection.target     After=vector.service
```

These are ordering rules, not hard dependencies. Kafka can run while OpenSearch is down, which Phase 6 confirmed, and it holds events meanwhile. Systemd reverses the order on stop.

## Lifecycle

### Windows login

Nothing starts. WSL stays stopped until needed, and no memory is used. The Windows Vector service runs independently once it is deployed.

### Startup

1. The operator runs `siem-up.ps1`.
2. The script opens the hold session, so idle shutdown cannot interrupt the start.
3. WSL boots the distro if needed, and systemd reaches its normal state.
4. The script runs `systemctl start siem.target`.
5. Services start in order. `After=` alone only waits for a process to start, so each unit also needs an `ExecStartPost` that polls its health check.
6. The script reports status.

### Health checks

| Service | Check | Healthy means |
|---|---|---|
| OpenSearch | Startup gate: TLS request to `127.0.0.1:9200`. Operator check: `/_cluster/health` | Gate gets 200 or 401. Health is green with no replicas |
| Kafka | `kafka-broker-api-versions.sh --bootstrap-server 127.0.0.1:9092` | Broker answers |
| Vector | Local health endpoint | Returns OK |
| Detection | Last timer run | Succeeded within its interval |

### Graceful shutdown

1. The operator runs `siem-down.ps1`.
2. `systemctl stop` runs with every service named, in reverse order, and waits. Stopping `siem.target` alone would return at once, while services were still stopping.
3. Detection stops first, so no new queries start.
4. The aggregator flushes its buffers.
5. Kafka closes its logs.
6. OpenSearch flushes and closes.
7. The script confirms the service processes and ports are gone. If not, it stops and leaves WSL running.
8. The script stops `siem.target`, then runs `wsl --terminate Ubuntu-24.04`, which also ends the hold session.

| Stop timeout | Value |
|---|---|
| Vector | 60 s |
| Kafka | 120 s |
| OpenSearch | 120 s |

In Phase 6, OpenSearch stopped in 0.5 to 0.8 s and Kafka in 1.4 to 1.7 s, on light workloads. The 120 s limits stay as a margin for heavier use. The Vector value is still a proposal.

### Why stopping first matters

| Stop path | Service grace before kill |
|---|---|
| `systemctl stop` naming services, with WSL staying up | Unit `TimeoutStopSec` |
| `systemctl poweroff` | About 24 s |
| `wsl --terminate` or `wsl --shutdown` | About 9 s |

Do not rely on either service finishing in 9 s under real load, even though both were faster on light workloads.

## Idle shutdown

WSL ends about 16 s after the last session, even with systemd services running. The hold session prevents this while the stack is up.

## Recovery

| Event | Effect | Recovery |
|---|---|---|
| Hold session dies | WSL stops after about 16 s, and services get a short grace period | Run `siem-up.ps1`, then check logs |
| Unexpected WSL termination | Services killed without a clean flush | Kafka runs log recovery, and OpenSearch replays its translog. Duplicates are safe because `event.id` is the `_id` |
| `wsl --shutdown` by mistake | Same | Same |
| Windows reboot or update | WSL ends with unknown grace | Run `siem-up.ps1`, then verify health. Stop the stack first whenever possible |
| Service crash | Stack partly up | `Restart=on-failure`, with limits so a failure cannot loop forever |
| Host out of memory | WSL or a service is killed | Stop optional services, then see the [resource budget](../operations/resource-budget.md) |
| VHDX corruption | Distro lost | Restore from `%USERPROFILE%\SIEM-Lab\backups\wsl\` |

**After any unclean stop:**

1. Start normally, because Kafka and OpenSearch recover by design.
2. Check OpenSearch health and Kafka under-replicated and offline partitions.
3. Confirm the aggregator's consumer lag falls.
4. Reconcile the affected window.
5. Record a gap if a Windows channel wrapped.

Windows Vector is designed to retry and to hold its position with bookmarks, so event flow should resume. This is untested until Phase 8.

## Deployed files

These files are in the repository and were tested in Phase 6 with OpenSearch and Kafka running together. Vector entries are added when it is deployed.

| Repository file | Installed to | Purpose |
|---|---|---|
| `deploy/systemd/siem.target` | `/etc/systemd/system/siem.target` | Groups the stack. Never enabled at boot |
| `deploy/opensearch/opensearch-siem.conf` | `/etc/systemd/system/opensearch.service.d/siem.conf` | Limits, timeouts, restart and health gate |
| `deploy/opensearch/wait-opensearch.sh` | `/usr/local/lib/siem/wait-opensearch.sh` | Startup health gate |
| `deploy/kafka/kafka.service` | `/etc/systemd/system/kafka.service` | Kafka unit, JVM settings and health gate |
| `deploy/kafka/wait-kafka.sh` | `/usr/local/lib/siem/wait-kafka.sh` | Startup health gate |
| `deploy/kafka/siem-kafka-tmpfiles.conf` | `/etc/tmpfiles.d/siem-kafka.conf` | Removes rolled logs after 7 days |
| `deploy/wsl/siem-hold.sh` | `/home/linux/siem/scripts/siem-hold.sh` | Bounded hold session |
| `deploy/windows/siem-up.ps1` | Run from the repository | Starts the stack |
| `deploy/windows/siem-down.ps1` | Run from the repository | Stops services by name, confirms, then ends WSL |

Rules for adding a service:

- Add it to `Wants=` and `After=` in `siem.target`. `After=` makes the target active only once its services have started. It does not make stopping the target wait.
- Add `PartOf=siem.target`, plus `After=` the previous service.
- Add it to the front of `$Services` in `siem-down.ps1`, add its user to `$ServiceUsers`, and add its ports to `$PortPattern`.
- Add it to the `reset-failed` line in `siem-up.ps1`.
- Any Java service that Windows must reach needs `-Djava.net.preferIPv4Stack=true`.
- Set `StartLimitBurst` high enough for normal use, because deliberate starts count towards it.
- Never enable a service in `multi-user.target`.
- Detection units must be named individually, because `siem-detection.target` would also return early.
- In `siem-down.ps1`, avoid `bash -c` with inner quotes, because Windows PowerShell 5.1 strips them.

A later logon task, if adopted, would be a per-user Task Scheduler entry that runs `siem-up.ps1` at logon. It needs no elevation, and it has not been created.

## Unverified

- Hidden hold session surviving an interactive terminal closing. It survived `siem-up.ps1`'s own process exiting.
- `Restart=on-failure` after a real crash.
- OpenSearch and Kafka stop times under sustained load.
- Behaviour during a Windows reboot or sleep.
- Whether idle shutdown's grace matches `wsl --terminate`.

_Internal test reports and planning records mentioned here are not published with Version 1._
