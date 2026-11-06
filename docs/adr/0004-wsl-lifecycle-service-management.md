# ADR-0004: WSL Lifecycle and Service Management

| | |
|---|---|
| **ADR status** | Approved under the Phase 5 delegation, subject to owner review |
| **Date** | 2026-10-30 |
| **Decision** | D19 |
| **Depends on** | D17, D18 |
| **Evidence** | Phase 5 test results |
| **Design** | [Runtime and service management](../architecture/runtime-and-service-management.md) |

## Context

Phase 5 tests changed this decision:

- WSL shuts down about 16 s after the last session ends, **even with a systemd service running**.
- A held `wsl.exe` session keeps the distro and its services up.
- `wsl --terminate` and `wsl --shutdown` give services about 9 s after SIGTERM before killing them.
- `systemctl poweroff` gives about 24 s.
- `TimeoutStopSec` does not extend those limits.
- `systemctl stop` on a target returns at once, while its services are still stopping.
- `systemctl stop` naming the services waits for them, and keeps the reverse order.

So systemd alone cannot keep the SIEM running, ending WSL is not a safe way to stop it, and stopping the target is not enough before WSL ends.

## Decision

1. **Start the stack deliberately**, with a Windows script. It is not started at Windows logon for now.
2. **Do not enable SIEM services at distro boot.** They belong to a `siem.target`, which is started explicitly. A casual `wsl` command must not load the whole stack.
3. **Use a bounded hold session.** The start script opens one hidden `wsl.exe` session that exits on its own when `siem.target` stops. It lives only as long as the stack.
4. **Always stop services first, by name.** The stop script names every service in `systemctl stop`, which waits for them. Only then is WSL terminated.
5. **Order services with systemd**, so stopping reverses startup.

| Order | Startup | Shutdown |
|---|---|---|
| 1 | OpenSearch | Detection scheduler and services |
| 2 | Kafka | Vector aggregator |
| 3 | Vector aggregator | Kafka |
| 4 | Detection scheduler and services | OpenSearch |

## Options compared

| Option | Benefit | Cost | Result |
|---|---|---|---|
| Manual startup | Memory used only when wanted. Simple to reason about | Telemetry waits while the stack is down | **Selected now** |
| Windows Task Scheduler at logon | Stack ready after logon, without elevation | Always costs up to 5.8 GiB, and it masks failures | Later option |
| Login-triggered startup (Run key or Startup folder) | Simple | Same cost, with no retry or status | Rejected |
| Permanent keepalive | Always on | Holds memory even when the stack is off | Rejected |
| Bounded hold session | Solves idle shutdown, ends with the stack | One hidden process while running | **Selected** |
| `instanceIdleTimeout=-1` | One setting, documented by Microsoft | Global, affects every distro, and needs a `.wslconfig` change | Fallback |

## Why

- The stack costs real memory, so it should not run whenever the laptop is on.
- Windows Vector is designed to buffer while WSL is down, so an always-on stack should not be required yet. This is untested until Phase 8.
- A hold tied to `siem.target` meets the rule against a permanent keepalive without justification.

## Trade-offs

- **Telemetry gaps:** events wait in Windows logs and the agent's buffer while the stack is down. A long outage could lose events if a channel wraps.
- **Human step:** someone must start the stack. A forgotten start delays detection, which is acceptable in a lab.
- **Hold session risk:** if it dies, WSL stops about 16 s later and services get only a short grace period.

## Consequences

- Scripts and units are proposed in the design document. **None have been created on the host.**
- No scheduled task, Run key or `.wslconfig` change was made.
- D14 timers run inside WSL only while the stack is up, so daily jobs must tolerate missed runs (`Persistent=true`).
- Never use `wsl --shutdown` while services run. Windows reboots should follow a clean stop.

## Revisit if

Continuous detection becomes a requirement, which is likely from Phase 13. A logon task would then be the first option. Also revisit if Phase 6 shows the hold session does not survive an interactive terminal closing. It did survive a tool shell exiting.

_Internal test reports and planning records mentioned here are not published with Version 1._
