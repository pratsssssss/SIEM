# Windows-to-WSL2 Networking Design

**Status:** Design only. No firewall rules or service listeners have been created. Kafka listener detail is now in the [Kafka networking design](kafka-networking-design.md) and [ADR-0005](../adr/0005-kafka-listener-design.md).

## Topology

```text
Windows 11 host
├── Vector agent ──> 127.0.0.1:9092 ──(WSL localhost forwarding)──┐
├── Host-only adapter 192.168.56.1 <── Kali attacker               │
└── WSL2 VM (NAT mode)                                             │
    ├── Kafka :9092 <──────────────────────────────────────────────┘
    ├── Vector aggregator ──> Kafka and OpenSearch over localhost
    ├── OpenSearch :9200 (localhost only)
    └── Detection, enrichment, correlation, assets, attack paths, health and the dashboard over localhost
```

## Current facts

| Item | Value |
|---|---|
| WSL networking mode | NAT, with `localhostForwarding=true` |
| WSL eth0 address | `172.30.x.x`, which can change. It must never be used in configuration |
| Forwarding test | Listeners in WSL bound to `127.0.0.1` and `0.0.0.0` were both reachable from Windows at `127.0.0.1` |
| Windows side of that test | `wslrelay`, bound to `127.0.0.1` only |
| Kali-facing address | The ports were not reachable at `192.168.56.1` from Windows |
| Inbound Windows listeners today | 135, 445, 7680 and dynamic RPC ports |
| Stopped services | WinRM and Remote Desktop |

## Kafka listeners

Kafka clients first contact a bootstrap address, then connect to the address the broker advertises. A wrong advertised address breaks clients even when the first connection succeeds.

- **Windows clients** use `127.0.0.1:9092`.
- **Internal WSL2 clients** also use `127.0.0.1:9092`, so one listener serves both (D20).
- **Never advertise** the WSL `172.30.x.x` address, because it can change. Kafka also rejects advertising `0.0.0.0`.

The proposed configuration is in the [Kafka networking design](kafka-networking-design.md).

## Implementation test (D20)

Phase 5 tested a generic TCP service bound to `127.0.0.1` in WSL2, and it was reachable from Windows. Real Kafka still has to prove this in Phase 6, using the validation plan in the Kafka networking design. Results are in Phase 5 test results.

## Exposure rules

- Kafka, OpenSearch and Dashboards must not be reachable from the LAN or from Kali.
- NAT mode stays. Mirrored mode would change what is exposed, so it needs a new decision.
- No Windows Firewall rules are added for these services.
- OpenSearch binds to localhost, and authentication and TLS have been on since Phase 6.
- OpenSearch's Java socket is IPv4-mapped, which WSL does not forward, so port 9200 is not reachable from Windows. Kafka uses the IPv4 stack so that it is forwarded, and real Windows clients have passed. Its controller port 9093 is forwarded too.
- Plaintext Kafka is acceptable only because it stays on loopback.

## Kali isolation

Kali's host-only adapter reaches Windows at `192.168.56.1`, which is how controlled attacks are delivered. Kali has no route to WSL2's NAT network by design.

**Must be validated later, from Kali:**

- Which Windows ports Kali can actually reach through the host's firewall.
- That WSL-forwarded ports are unreachable.
- Which firewall profile applies to the host-only adapter. This is unconfirmed.
- That Kali's NAT adapter is not used to attack anything outside the lab.

## Failure behaviour

| Failure | Effect | Design response |
|---|---|---|
| WSL stopped | Windows Vector cannot reach Kafka | Disk buffer on the agent, retries, and Event Log bookmarks |
| WSL IP changes | None, because no configuration uses it | Keep using localhost |
| Forwarding unavailable | Same as WSL stopped | Alert from Windows Vector metrics (D13) |
| Windows event log wraps during a long outage | Older events are lost | Size channels appropriately and limit outage time |

_Internal test reports and planning records mentioned here are not published with Version 1._
