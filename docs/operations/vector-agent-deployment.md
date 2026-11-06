# Vector Agent Deployment

**Status:** Installed. Decisions: [D22](../adr/0006-sensitive-telemetry-handling.md), [D23](../adr/0007-seal-verifier.md) and [D24](../adr/0008-whole-event-authentication.md). Results: acceptance report.

## Layout

| Use | Location | Access |
|---|---|---|
| Program | `C:\Program Files\Vector\bin\vector.exe` | `SYSTEM` and Administrators only |
| Configuration | `C:\Program Files\Vector\config\vector-agent.yaml` | Same |
| Disk buffer and checkpoints | `C:\ProgramData\Vector\data` | Same |
| Field keys | `C:\ProgramData\Vector\secrets\field-keys.json` | Same |

`deploy/windows/install-vector-agent.ps1` removes inherited permissions before any content arrives, sets Administrators as owner, and checks owner and permissions on every path before keys are created or delivered. A folder must block inheritance. A file inherits from its locked folder, so it is judged by its effective rules.

## Service

| Item | Value |
|---|---|
| Account | `LocalSystem`, needed to read the Security, Sysmon and PowerShell channels |
| Start | Manual after `-NoStart`, so a reboot cannot begin collection. Automatic after the final run, when it keeps collecting while WSL is off |
| Recovery | Restart after 60 s, 60 s, then 300 s |
| Binary trust | Pinned SHA-256 against the official release. `vector.exe` is not signed |

## Network

- The only configured endpoint is Kafka at `127.0.0.1:9092`.
- **Rule A** blocks `vector.exe` from every address except `127.0.0.1`, in all profiles. Tested while active: Kafka works, and `example.com` is blocked, while an unprotected control copy reaches both.
- **Rules B and C were tested and automatically removed.** With each active, the protected binary still reached loopback listeners, because Windows Firewall does not filter loopback here. Loopback destinations are limited only by the ACL-protected configuration.
- There is no allow rule: outbound defaults to Allow, and Block beats Allow.
- `deploy/windows/test-vector-firewall.ps1` tests them with real connections. `vector validate --no-environment` skips healthchecks, so it proves nothing about connectivity.
- These rules contain a bad configuration, not a compromise. A `LocalSystem` process can change the firewall, and DNS lookups run in another service.
- Metrics are on `127.0.0.1:9598`, and hold counts only.
- The API is off, and nothing listens on a wildcard address.

This outbound rule limits Vector only. It does not change [D20](../adr/0005-kafka-listener-design.md), whose rule against adding a firewall rule concerns Kafka's exposure.

## Field keys

| Topic | Procedure |
|---|---|
| **Generation** | The installer takes 32 bytes from the operating system's generator, then derives the encryption and MAC keys separately with HKDF-SHA-256, under the labels `siem-d22-k1-enc` and `siem-d22-k1-mac`. The input key is never stored |
| **Distribution** | The installer writes the exact bytes to WSL over stdin, and compares SHA-256 on both sides, so keys never appear on a command line. They never enter the repository or logs |
| **Permissions** | Windows: `SYSTEM` and Administrators. WSL2: `/home/linux/siem/config/verifier/field-keys.json`, `root:siem-verifier`, 640 |
| **Use** | The agent reads them through Vector's `file` secret backend. On WSL only the seal verifier reads them |
| **Rotation** | 1. Add `k2` to both key files, and restart the seal verifier. 2. Switch the agent's key ID to `k2` and restart it. 3. Keep `k1` until the agent buffer has drained and Kafka's 72-hour retention has passed. 4. Remove `k1` from both |
| **Compromise** | Rotate at once, and treat restricted fields in Kafka and the agent buffer as exposed |
| **Loss of the Windows copy** | Copy it back from WSL, because the agent cannot recreate it |
| **Loss of both copies** | Restore from a WSL export, which holds the keys. Otherwise generate new keys. Unread events then go to dead-letter, still sealed, and cannot be recovered from Kafka. The Windows logs remain the source |
| **Backups** | WSL exports from this phase onward contain the keys and must be treated as sensitive |

## Exact event text

Vector 0.61.0 loses `&`, `<` and `>` from `event_data`, so `include_xml` is on for every source, and `protect` rebuilds named fields from the raw XML before redaction. It then removes the XML, except on events 1102 and 104. If an event's XML cannot be parsed, it keeps Vector's copy, and sets `labels.xml_fallback`. See the [compatibility review](../pipeline/windows-vector-compatibility.md).

## What D22 does not do

D22 protects the listed fields. **It does not authenticate Kafka events.** An event with no protected fields can still be forged by anything that can reach port 9092, until Kafka gains authentication and authorization in Phase 21. Labels and unprotected fields are not covered by the MAC. Removing the sealed fields from an event is detected only for Sysmon 1, 4104 and 4100, where sealing is required.

## Rollback

```powershell
Stop-Service Vector
sc.exe delete Vector
Get-NetFirewallRule -DisplayName 'SIEM Vector agent, block *' | Remove-NetFirewallRule
Remove-Item 'C:\Program Files\Vector', 'C:\ProgramData\Vector' -Recurse -Force
```

This deletes the buffer and checkpoints. Windows logging is not affected.

_Internal test reports and planning records mentioned here are not published with Version 1._
