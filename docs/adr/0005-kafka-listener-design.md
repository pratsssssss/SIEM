# ADR-0005: Kafka Listener Design

| | |
|---|---|
| **ADR status** | Approved under the Phase 5 delegation, subject to owner review and the Phase 6 integration test |
| **Date** | 2026-10-30 |
| **Decision** | D20 |
| **Depends on** | D3, D17, D18 |
| **Evidence** | Phase 5 test results |
| **Design** | [Kafka networking design](../architecture/kafka-networking-design.md) |
| **Later changes** | The decision stands, with one added requirement from Phase 6. A Java socket bound to `127.0.0.1` is IPv4-mapped by default, and WSL does not forward it to Windows. Kafka's JVM must run with `-Djava.net.preferIPv4Stack=true`. Real Kafka passed the Windows tests with this setting. The checks from Kali remain open and move to Phase 10. The text below is preserved as first written |

## Context

Two client types need Kafka: the native Windows Vector agent, and services inside WSL2. ADR-0002 left open whether Kafka bound only to `127.0.0.1` is reachable from Windows.

## Decision

**Bind the Kafka client listener to `127.0.0.1:9092`, and advertise `127.0.0.1:9092`. Both client types share this one listener.**

- The KRaft controller listener binds to `127.0.0.1:9093`.
- Do not bind to `0.0.0.0`.
- Do not advertise the WSL `172.30.x.x` address.
- NAT mode and localhost forwarding stay as they are.
- No Windows Firewall rule is added.

## Why

A TCP round trip through Windows `127.0.0.1` worked for a service bound to `127.0.0.1` in WSL2. On this host that bind was unreachable through the host-only, Wi-Fi and WSL addresses.

A `0.0.0.0` bind also answered on the WSL address, so it has more exposure for no gain.

One listener is enough because both client types reach the broker at the same address. Windows clients arrive through `wslrelay`, and WSL clients arrive directly. A second listener is only needed if clients see different addresses, as containers would (D18 rejected those).

## Trade-offs

- **Simplicity against flexibility:** a single listener cannot give the two client types different security settings. A second listener can be added later.
- **Any local Windows process can connect.** The listener uses PLAINTEXT with no authentication, so malware on the endpoint could read or forge events. This is an accepted lab risk until hardening.

## Consequences

- Windows Vector uses `127.0.0.1:9092`, never a hostname that could resolve elsewhere.
- Kafka is unreachable from Windows whenever WSL is down, so the agent needs a disk buffer.
- No security depends on a firewall rule, but this needs checking from Kali.

## Requires a Phase 6 test

This decision rests on a generic TCP test. Real Kafka must still prove:

- Producing and consuming from Windows through the advertised address.
- The KRaft controller listener on loopback.
- Exposure checks from Kali.

If these fail, this ADR is revisited before any workaround is applied.

_Internal test reports and planning records mentioned here are not published with Version 1._
