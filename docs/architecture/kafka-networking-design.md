# Kafka Networking Design

**Status:** Implemented and tested with real Kafka in Phase 6. Decision: [D20](../adr/0005-kafka-listener-design.md). Deployment is in [Kafka deployment](../operations/kafka-deployment.md), results in the Kafka validation. Wider connectivity is in [Windows-to-WSL2 networking](windows-wsl2-networking.md).

## How Kafka clients connect

Clients use a bootstrap address only for the first contact. The broker then returns its advertised address, and the client connects there for all real traffic. A client can pass bootstrap and still fail if the advertised address is wrong for it.

| Setting | Meaning | Confirmed from Apache source |
|---|---|---|
| `listeners` | Addresses the broker binds to. `0.0.0.0` binds all interfaces | Yes |
| `advertised.listeners` | Addresses given to clients and other brokers | Yes |
| Advertising `0.0.0.0` | Not valid | Yes |
| Named listeners | Need `listener.security.protocol.map` | Yes |
| Default heap | `-Xmx1G -Xms1G` unless `KAFKA_HEAP_OPTS` is set | Yes |

## Client connectivity

| Client | Connects to | Path |
|---|---|---|
| Windows Vector agent | `127.0.0.1:9092` | Windows loopback, `wslrelay`, WSL2 loopback |
| Vector aggregator | `127.0.0.1:9092` | WSL2 loopback |
| Detection and other WSL2 services | `127.0.0.1:9092` | WSL2 loopback |

Both client types resolve the advertised `127.0.0.1:9092` correctly from where they sit. That is why one listener is enough.

## Deployed configuration

```properties
process.roles=broker,controller
node.id=1
controller.quorum.bootstrap.servers=127.0.0.1:9093

listeners=CLIENT://127.0.0.1:9092,CONTROLLER://127.0.0.1:9093
advertised.listeners=CLIENT://127.0.0.1:9092,CONTROLLER://127.0.0.1:9093
listener.security.protocol.map=CLIENT:PLAINTEXT,CONTROLLER:PLAINTEXT
inter.broker.listener.name=CLIENT
controller.listener.names=CONTROLLER
```

This follows Apache's 4.4.0 KRaft sample `server.properties`, with loopback addresses and named listeners. The full file is `deploy/kafka/server.properties`.

**Required JVM setting:** `KAFKA_OPTS=-Djava.net.preferIPv4Stack=true`.

| JVM setting | Socket in WSL | From Windows `127.0.0.1` |
|---|---|---|
| Default | `[::ffff:127.0.0.1]` | No connection, because WSL does not forward it |
| `preferIPv4Stack=true` | `127.0.0.1` | Connected |

The default row was measured with plain Java sockets on the bundled JDK. Real Kafka with this setting bound `127.0.0.1:9092` and `127.0.0.1:9093`, and `wslrelay` forwarded both.

## Bind address comparison

| Bind | From Windows `127.0.0.1` | From host-only IP | From Wi-Fi IP | From WSL IP |
|---|---|---|---|---|
| `127.0.0.1` (selected) | Works | No connection | No connection | No connection |
| `0.0.0.0` | Works | No connection | No connection | **Works** |

All connections were made from Windows itself, and the test does not separate rejected from timed out. Real Kafka on the selected bind gave the same results for ports 9092 and 9093. From inside WSL, the WSL IP was also closed.

## Exposure risks

| Risk | Assessment |
|---|---|
| `0.0.0.0` bind | Reachable on the WSL `eth0` address. Avoided |
| LAN access | Windows listens only on `127.0.0.1`, forwarding is off and there is no `portproxy`. Not tested from another device |
| Kali access | No listener on `192.168.56.1` from Windows' view. Kali has not tested this |
| Local Windows processes | Any process can connect to 9092 and 9093, without authentication, and can read, write or delete topics. Localhost binding is not authentication. Accepted lab risk |
| Controller port on Windows | `wslrelay` forwards 9093 as well as 9092. No Windows client needs it, but WSL forwards every loopback IPv4 socket |
| WSL mode change | Mirrored mode would change exposure, so it needs a new decision |
| Added `portproxy` or firewall rule | Could expose the port. Do not add one |

**Is a firewall rule needed?** No, based on current evidence, because the port is not listening on any external interface. This assumption must be confirmed from Kali.

## Evidence status

**Confirmed on this host**

- A TCP round trip works from Windows to a `127.0.0.1` bind in WSL2.
- `wslrelay` holds forwarded ports on Windows `127.0.0.1` only.
- A `127.0.0.1` bind gives no connection via host-only, Wi-Fi and WSL addresses, tested from Windows.
- Java needs `preferIPv4Stack=true` for WSL to forward a loopback socket to Windows.
- Windows IP forwarding is off, and no `portproxy` entries exist.
- Real Kafka metadata, produce and consume work from Windows with librdkafka.
- The Windows client connects to broker 1 at the advertised address after metadata.
- The KRaft controller runs on a loopback listener.
- The same Windows producer reconnects after a broker restart.

**Requires a later integration test**

- Long-lived connections through `wslrelay`, and sustained throughput.
- Client recovery after WSL itself restarts.
- The Windows Vector Kafka sink, which is still unconfirmed.

**Unverified security assumptions**

- Kali cannot reach Kafka. Kali has not been booted for this test.
- Other LAN devices cannot reach Kafka.
- The firewall profile applied to the host-only adapter.
- Hyper-V firewall behaviour for WSL traffic.

## Validation plan

| Step | Status |
|---|---|
| 1. `ss -tln` shows `127.0.0.1:9092`, and `wslrelay` holds port 9092 | **Passed** |
| 2. WSL2 test topic, produce and consume | **Passed** |
| 3. Windows produce and consume with a real Kafka client | **Passed** |
| 4. Client used the advertised address | **Passed** |
| 5. Restart Kafka, and the client recovers | **Passed** |
| 6. Terminate WSL, and a live client retries without crashing | Not tested. Moves to the Phase 8 outage test |
| 7. From Kali, confirm `192.168.56.1:9092` and `:9093` are unreachable | Not tested. Moves to Phase 10 |
| 8. `nmap` from Kali against the same ports, with approval | Not tested. Moves to Phase 10 |
| 9. Record results | Kafka validation |

If a later step fails, do not add firewall rules or change WSL networking as a workaround. Revisit D20.

_Internal test reports and planning records mentioned here are not published with Version 1._
