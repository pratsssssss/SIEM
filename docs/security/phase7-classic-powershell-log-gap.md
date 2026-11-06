# Phase 7 Gap: Classic PowerShell Log Access

**Status:** closed on 2026-10-31. The ACL below was applied with owner approval, and all four live checks passed. D22 was never bypassed, because Vector does not collect this log.

Phase 7 recorded this gap in [Windows telemetry preparation](../operations/windows-telemetry-preparation.md). The Stage 8.4 pre-review proved it with evidence. An earlier report called it a new finding, which was wrong.

## Finding

Phase 7 restricted PowerShell Operational. The classic `Windows PowerShell` log kept its default permissions, and **an unelevated session can read it**. Its events 400, 403 and 600 record `HostApplication`, the full command line, so a secret passed to `powershell -Command` is readable there.

| Check | Result |
|---|---|
| Read from an unelevated session | Succeeded |
| Two fake canaries planted through `powershell -Command` | Both found in 8 events, before the log overwrote them |
| Same read of PowerShell Operational and Sysmon | Refused |
| Size | 15 MB, circular |

## Exact change

Applied with `wevtutil sl "Windows PowerShell" /ca:<SDDL>`, the Phase 7 method. It changes **only four entries**, each from `0x3` (read and write) to `0x2` (write only).

**Current:**

```text
O:BAG:SYD:(A;;0x2;;;S-1-15-2-1)(A;;0x2;;;S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x7;;;SO)(A;;0x3;;;IU)(A;;0x3;;;SU)(A;;0x3;;;S-1-5-3)(A;;0x3;;;S-1-5-33)(A;;0x1;;;S-1-5-32-573)
```

**Proposed:**

```text
O:BAG:SYD:(A;;0x2;;;S-1-15-2-1)(A;;0x2;;;S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x7;;;SO)(A;;0x2;;;IU)(A;;0x2;;;SU)(A;;0x2;;;S-1-5-3)(A;;0x2;;;S-1-5-33)(A;;0x1;;;S-1-5-32-573)
```

| Account | SDDL | Before | After |
|---|---|---|---|
| SYSTEM | `SY` | Full, `0xf0007` | Unchanged |
| Administrators | `BA` | Read, write, clear, `0x7` | Unchanged |
| Server Operators | `SO` | `0x7` | Unchanged. Not used on this host |
| Interactive users | `IU` | Read, write | **Write only** |
| Service logons | `SU` | Read, write | **Write only** |
| Batch logons | `S-1-5-3` | Read, write | **Write only** |
| Local account logons | `S-1-5-33` | Read, write | **Write only** |
| Event Log Readers | `S-1-5-32-573` | Read | Unchanged. The group has no members |
| AppContainer entries | `S-1-15-...` | Write | Unchanged |

**Why write stays:** PowerShell writes this log under the caller's own account. Removing write would stop ordinary sessions being logged, and lose telemetry.

**Elevated sessions:** they match `BA`, so they keep read. A process in Event Log Readers also keeps read, which is that group's purpose.

## Commands

All run from `deploy/windows/`. Nothing here clears the log.

| Action | Command |
|---|---|
| Show current and proposed, unelevated | `.\restrict-classic-powershell-log.ps1` |
| Apply, elevated. Saves the current value first | `.\restrict-classic-powershell-log.ps1 -Apply` |
| Roll back, elevated | `.\restrict-classic-powershell-log.ps1 -Rollback` |

**Rollback by hand:** `wevtutil sl "Windows PowerShell" /ca:<Current SDDL above>`. The saved copy is `%USERPROFILE%\SIEM-Lab\phase8\classic-log-access-before.txt`.

The change takes effect without a restart of the log service in the Phase 7 method, but that is not proven for a classic log. The live test below shows whether it did.

## Tests

| Stage | Test | Status |
|---|---|---|
| Offline | `tests/windows/test-classic-log-acl.ps1` against the real current ACL: SYSTEM and Administrators unchanged, four accounts lose read and keep write, only those entries change, applying twice changes nothing, Event Log Readers is empty | **24 of 24 pass** |
| Live, after `-Apply` | `test-classic-log-acl.ps1 -Live`, elevated. An unelevated token is denied. SYSTEM reads. Administrators read. An ordinary session still writes | **4 of 4 pass** |

The offline test proves what the ACL says, not what Windows enforces. Only the live test proves that. If any live check fails, roll back.

## Risks

- A classic log's access may be stored differently from a modern channel's, so the first `-Apply` is itself a test. The script confirms the value changed, and fails if it did not.
- A tool that reads this log as an ordinary user will lose access. None is known here.
