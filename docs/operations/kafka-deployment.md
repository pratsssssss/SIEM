# Kafka Deployment

**Status:** Deployed in Phase 6 Step B and validated. Results are in the Kafka validation. Unclean stop and WSL termination passed in the Phase 8 acceptance report. Decisions: D3, [D18](../adr/0003-service-runtime.md), [D19](../adr/0004-wsl-lifecycle-service-management.md) and [D20](../adr/0005-kafka-listener-design.md).

## Version

| Item | Value |
|---|---|
| Kafka | 4.4.0, Scala 2.13 build, the newest Apache release on 2026-10-30 |
| Java | Ubuntu OpenJDK 17.0.20.1, package `17.0.20.1+1-1~24.04` |
| Java support | Apache fully supports Java 17, 21 and 25, and recommends the latest LTS |
| Operating system | Linux. Apache publishes no Ubuntu-specific support list |
| Mode | KRaft, combined broker and controller. There is no ZooKeeper |

Kafka uses `/usr/lib/jvm/java-17-openjdk-amd64`, set in its unit. OpenSearch keeps its bundled Java 25, and both were confirmed from the running processes. The Java package is pinned at install but not held, so Ubuntu security updates still apply. Kafka itself only changes when it is deliberately reinstalled.

## Install procedure

`deploy/kafka/install-kafka.sh` stops unless both checks pass:

| Check | Source | Result |
|---|---|---|
| GPG signature | `.asc` from `downloads.apache.org`, against Apache's `KEYS` file | Good, key `1817905E3B2708B11A24B88E9AFA6F66CC8C3534` |
| SHA-512 | `.sha512` from `downloads.apache.org` | Matches |

The archive came from `dlcdn.apache.org`, Apache's CDN, because `downloads.apache.org` was too slow. Its signature and checksum still came from `downloads.apache.org`. `KEYS` has no separately published fingerprint, so trust rests on Apache's HTTPS site.

1. Put these in an empty download directory outside the VHDX: `kafka_2.13-4.4.0.tgz`, its `.asc` and `.sha512`, and `KEYS`.
2. Run as root in Ubuntu: `bash deploy/kafka/install-kafka.sh verify <dir>`
3. Run as root in Ubuntu: `bash deploy/kafka/install-kafka.sh install <dir>`
4. Start the stack with `deploy/windows/siem-up.ps1`.
5. Run `deploy/kafka/create-topics.sh` as root. It is safe to repeat.

## Layout

| Use | Location | Owner and mode |
|---|---|---|
| Program | `/opt/kafka_2.13-4.4.0`, linked from `/opt/kafka` | `root` |
| Configuration | `/home/linux/siem/config/kafka/server.properties` | `root:kafka`, 640 |
| Cluster ID | `/home/linux/siem/config/kafka/cluster.id` | `root:kafka`, 640 |
| Data and KRaft metadata | `/home/linux/siem/data/kafka` | `kafka:kafka`, 750 |
| Logs | `/var/log/kafka` | `kafka:kafka`, 750 |

The `kafka` system user has no login shell. It is in the `linux` group so it can pass through `/home/linux`.

## Configuration

| Setting | Value | Why |
|---|---|---|
| `process.roles` | `broker,controller` | Single node |
| `listeners` | `CLIENT://127.0.0.1:9092,CONTROLLER://127.0.0.1:9093` | Loopback only |
| `advertised.listeners` | The same two addresses | Windows and WSL2 clients both reach `127.0.0.1:9092` |
| `auto.create.topics.enable` | `false` | Topics are explicit |
| `log.retention.hours` | `72` | Resource budget |
| `log.segment.bytes` | `104857600` | `retention.bytes` cannot remove the active segment |
| Heap | `-Xms512m -Xmx512m` | Resource budget |
| `KAFKA_OPTS` | `-Djava.net.preferIPv4Stack=true` | **Required.** Without it WSL does not forward the port to Windows |

Two Kafka defaults would have caused disk growth, so the deployment replaces them:

- The GC log can reach 1 GB by default. `KAFKA_GC_LOG_OPTS` limits it to 3 files of 10 MB.
- Service logs roll hourly and are never deleted. `/etc/tmpfiles.d/siem-kafka.conf` removes files older than 7 days, when `systemd-tmpfiles-clean` runs.

## Topics

| Topic | Partitions | `retention.bytes` per partition | `segment.bytes` |
|---|---|---|---|
| `siem-raw-logs` | 3 | 1 GiB | 100 MiB |
| `siem-alerts` | 1 | 256 MiB | 64 MiB. Written by the [detection engine](../detection/detection-engine.md). Holds no restricted values |
| `siem-incidents` | 1 | 256 MiB | 64 MiB |

All use replication factor 1 and 72-hour retention. Topics exist but carry no real events yet.

## KRaft cluster identity

Storage was formatted once with `kafka-storage.sh format --standalone`, using a cluster ID from `kafka-storage.sh random-uuid`. The installer refuses to format if `meta.properties` exists, or if the directory has unknown content.

**Recovery implications:**

- The cluster ID is in `meta.properties` and in `cluster.id`. Kafka refuses to start if they disagree with the configuration or if the storage belongs to another cluster.
- Never delete `meta.properties` or re-run `format` to fix a start problem. It discards the cluster identity and can lose topic metadata.
- A restored WSL export keeps its matching ID and data, so it starts normally.

## Service management

- `kafka.service` is **disabled at boot**, and nothing starts at Windows login.
- `siem.target` starts OpenSearch, then Kafka, in order.
- Startup waits on `wait-kafka.sh`, which calls `kafka-broker-api-versions.sh` and clears the broker's heap and GC settings first.
- `siem-down.ps1` stops Kafka, then OpenSearch, by name and waits for both. It then confirms users, processes and ports are clear before ending WSL.
- `StartLimitBurst=6` in 10 minutes. `siem-up.ps1` resets the counter.

Admin tools need a writable log location. Run them with `LOG_DIR=/tmp`, for example:

```bash
LOG_DIR=/tmp /opt/kafka/bin/kafka-topics.sh --bootstrap-server 127.0.0.1:9092 --list
```

## Networking

| Client | Address |
|---|---|
| Windows | `127.0.0.1:9092`, through `wslrelay` |
| WSL2 services | `127.0.0.1:9092` |

Detail is in the [Kafka networking design](../architecture/kafka-networking-design.md).

## Security limitations

**Kafka has no authentication, authorization or encryption here. Localhost binding is not application-level authentication.**

- Any Windows or WSL2 process that can reach `127.0.0.1:9092` can read, write, create and delete topics. That includes malware on the monitored endpoint.
- Traffic is plaintext.
- The controller port `9093` is also forwarded to Windows `127.0.0.1`, because it is an IPv4 loopback socket. Any local Windows process can connect to it too.
- JMX is off. `kafka-run-class.sh` otherwise opens an unauthenticated connector on `0.0.0.0` at a random port, which WSL forwards to Windows `127.0.0.1`. The units set `KAFKA_JMX_OPTS` to a single space. Phase 6 missed this, and Phase 8 found and closed it. `tests/vector/run_e2e.py listeners` checks it.
- This is an accepted lab risk until hardening in Phase 21. Do not treat events in Kafka as tamper-proof.
- **Phase 8 update:** that acceptance predates sensitive telemetry. Without protection, a non-admin process could read Sysmon and PowerShell text from Kafka after being denied the same channels, so [D22](../adr/0006-sensitive-telemetry-handling.md) protects restricted fields before they reach Kafka. It does not authenticate Kafka events. Forgery, topic deletion and retention changes stay open until Phase 21. See the Phase 8 review.

## Delivery semantics

Delivery is at-least-once. The broker does not deduplicate, and Phase 6 showed a redelivered `event.id` stored as a new record. Exactly-once end-to-end processing is not claimed. OpenSearch's `_id` handles duplicates downstream.

Replay works by moving a consumer group's offsets:

```bash
LOG_DIR=/tmp /opt/kafka/bin/kafka-consumer-groups.sh --bootstrap-server 127.0.0.1:9092 \
  --group <group> --topic <topic> --reset-offsets --to-earliest --execute
```

Replay only reaches data still inside retention. The group must be inactive first.

## Recovery

| Event | Action |
|---|---|
| Service will not start | `journalctl -u kafka`, `/var/log/kafka/server.log`, then `systemctl reset-failed kafka.service` |
| Cluster ID mismatch | Stop. Compare `cluster.id` and `meta.properties`. Do not format |
| WSL ended without a clean stop | Run `siem-up.ps1`. Kafka should run log recovery. This was not tested, because the phase excluded crash tests |
| Windows client cannot connect | Confirm `ss -tln` shows `127.0.0.1:9092`, not `[::ffff:127.0.0.1]:9092`, and that `wslrelay` holds the port |
| Disk filling | Check topic limits and `C:` free space. Do not delete files under `data/kafka` by hand |
| Distro lost | Import `ubuntu-24.04-pre-kafka-20261030.tar`, then repeat this install |

The pre-Kafka export contains OpenSearch's certificates, private keys and admin credential. Treat it as sensitive.

## Expected log messages

| Message | Meaning |
|---|---|
| `WARN ... Attempting to close NetworkClient that has already been closed` | Appears once at each shutdown |
| `ERROR ... CONTROLLER_REGISTRATION ... NotControllerException` | Seen once in 6 starts, within about 15 ms of the controller taking over. The broker became healthy. Investigate if it repeats or the broker does not start |
| `Disconnected` or `Connect ... failed` in clients | Normal while the broker is down |

## Known limits

- Consumer lag monitoring does not exist yet (D13).
- Kafka is single-node with replication factor 1, so it gives no protection against disk loss.
- Sustained throughput through `wslrelay` is unmeasured. Windows tests used small messages.

_Internal test reports and planning records mentioned here are not published with Version 1._
