# Windows Telemetry Source Matrix

**Status:** Collection plan. Windows logging is [configured](../operations/windows-telemetry-preparation.md), and the Vector agent collects all seven sources. Measured facts are in the Phase 7 inventory. Earlier background is in [Windows telemetry](windows-telemetry.md).

Volumes here are **estimates** unless marked measured. The assumptions are in [windows-telemetry-preparation](../operations/windows-telemetry-preparation.md#event-volume-estimate).

## Sources

| # | Source and channel | Purpose | Permissions to read | Admin change needed | Events per day (estimate) | Priority |
|---|---|---|---|---|---|---|
| 1 | Windows Security, `Security` | Logons, accounts, processes, tasks, audit changes | Administrator, `LocalSystem` or `Event Log Readers` | Done, audit policy. 4688 command line stays off | 5,000 to 40,000 | **Essential** |
| 2 | Sysmon, `Microsoft-Windows-Sysmon/Operational` | Process, network, persistence, tampering | Administrator or `LocalSystem`. Unelevated read denied (measured) | Done, installed | 8,000 to 60,000 | **Essential** |
| 3 | PowerShell, `Microsoft-Windows-PowerShell/Operational` | Script content | Administrator or `LocalSystem`. Unelevated read denied (measured), restricted on purpose | Done, script block logging | 200 to 36,000 | **Essential** |
| 4 | Defender, `Microsoft-Windows-Windows Defender/Operational` | Detections, protection tampering | Readable unelevated (measured) | No | About 12 after filtering | **Essential** |
| 5 | Firewall, `.../Firewall` | Rule and setting changes | Readable unelevated (measured) | No | About 50 after filtering | Useful |
| 6 | System, `System` | Service installs, log clears, restarts | Readable unelevated (measured) | No | About 30 after filtering | **Essential** |
| 7 | Tasks, `Microsoft-Windows-TaskScheduler/Operational` | Task registration detail | Readable unelevated | Done, enabled | Under 50 after filtering | Useful |
| 8 | Application, `Application` | Crashes | Readable unelevated (measured) | No | About 140 unfiltered (measured) | Optional, not collected at first |
| 9 | Firewall connection logging, `pfirewall.log` or 5156/5157 | Allowed and blocked connections | Administrator | **Yes** | Very high | Optional, **not recommended** |

## Duplication

| Activity | Sources | Decision |
|---|---|---|
| Process creation | Sysmon 1 and Security 4688 | Keep both at first. Sysmon has hashes and parent detail, and 4688 still works if Sysmon is stopped. Review after volume is measured |
| Service install | Sysmon 13 on `ImagePath`, Security 4697, System 7045 | Keep 7045 and 4697. Their sources fail independently |
| Scheduled task | TaskScheduler 106, 140, 141, Sysmon 11 on the Tasks folder. Security 4698 to 4702 are not generated, because Other Object Access Events is not audited | TaskScheduler is primary, with Sysmon 11 as tamper-resistance |
| Firewall rule change | Security 4946 to 4948 and Firewall channel | Keep both at low volume |
| Log clear | Security 1102 and System 104 | Keep both. Each covers a different log |
| PowerShell script | 4104 and classic 400, 403, 600 | Collect 4104 and 4100 only. Classic events are high volume and carry little |

The aggregator must not merge these. Correlation works on entities, and each source keeps its own `event.id`.

## Event ID shortlist

All IDs were checked against provider metadata or real events on this host. **An ID being listed does not mean it is being generated.** "Needs audit" means the audit policy must be enabled first.

### Authentication

| ID | Provider | Meaning | Needs audit |
|---|---|---|---|
| 4624 | Security-Auditing | Logon succeeded | Likely default |
| 4625 | Security-Auditing | Logon failed | Likely default |
| 4634, 4647 | Security-Auditing | Logoff | Likely default |
| 4648 | Security-Auditing | Logon with explicit credentials | Likely default |
| 4672 | Security-Auditing | Special privileges assigned | Likely default |
| 4776 | Security-Auditing | Credential validation | **Yes** |
| 4740 | Security-Auditing | Account locked out | Likely default |

### Accounts and privileges

| ID | Meaning | Needs audit |
|---|---|---|
| 4720, 4722, 4723, 4724, 4725, 4726 | Account created, enabled, password change, reset, disabled, deleted | Likely default for success |
| 4738 | Account changed | Likely default for success |
| 4728, 4729, 4732, 4733, 4756, 4757 | Group membership changed | **Yes** |
| 4798, 4799 | Group or user membership enumerated | **Yes** |

### Processes and PowerShell

| ID | Provider | Meaning | Needs |
|---|---|---|---|
| 4688 | Security-Auditing | Process created. No command line, by the owner's decision, so use Sysmon 1 for arguments | **Audit** |
| 1 | Sysmon | Process created | **Sysmon** |
| 4104 | PowerShell | Script block text | **Script block logging** for full coverage |
| 4100 | PowerShell | Engine error | None |

### Services and scheduled tasks

| ID | Provider | Meaning | Needs |
|---|---|---|---|
| 7045 | Service Control Manager | Service installed | None |
| 7040 | Service Control Manager | Service start type changed | None |
| 7034 | Service Control Manager | Service crashed | None |
| 4697 | Security-Auditing | Service installed | **Audit** |
| 4698, 4699, 4700, 4701, 4702 | Security-Auditing | Task created, deleted, enabled, disabled, updated. **Not generated:** its subcategory was not approved | **Audit, not enabled** |
| 106, 140, 141 | TaskScheduler | Task registered, updated, deleted | **Enable channel** |

TaskScheduler 200 and 201 are excluded because they fire on every task run.

### Defender

| ID | Meaning |
|---|---|
| 1006, 1116 | Malware detected |
| 1007, 1117 | Action taken |
| 1008, 1118, 1119 | Action failed |
| 1009 | Item restored from quarantine |
| 1015 | Suspicious behaviour detected |
| 2001, 2003 | Definition or engine update failed |
| 3002 | Real-time protection failed |
| 5001 | Real-time protection disabled |
| 5004, 5007 | Configuration changed |
| 5008 | Engine failed |
| 5010, 5012 | Scanning disabled |
| 5013 | Tamper protection blocked a change |

5007 is noisy, at 332 events in 30 days (measured), but it is the signal for exclusions being added. The aggregator can filter on the setting changed.

### Firewall

| ID | Meaning |
|---|---|
| 2004, 2071, 2097 | Rule added. The ID varies by origin and build, and 2097 is the one observed here |
| 2005, 2099 | Rule modified |
| 2006, 2052 | Rule deleted |
| 2002, 2003, 2082, 2083 | Setting changed |
| 4946, 4947, 4948 | Security-Auditing rule change, **needs audit** |
| 5024, 5025 | Firewall service started or stopped |

2084 (duplicate rule) is excluded. It was the top ID measured, at 638 of 1,303 records.

### Log clearing and audit tampering

| ID | Provider | Meaning | Needs |
|---|---|---|---|
| 1102 | **Eventlog**, in Security | Security log cleared | None |
| 104 | **Eventlog**, in System | A log was cleared | None |
| 4719 | Security-Auditing | Audit policy changed | Likely default |

1102 and 104 keep their fields in `UserData`, which Vector does not parse into a field. See [Vector compatibility](windows-vector-compatibility.md).

### Sysmon

| ID | Meaning | Proposed |
|---|---|---|
| 1 | Process create | All, minus 3 noise rules |
| 2 | File time changed | User-path executables |
| 3 | Network connection | Tools, user paths, admin ports |
| 5 | Process terminate | Off |
| 6 | Driver load | Except valid Microsoft signatures |
| 7 | Image load | Selective |
| 8 | Remote thread | Except 2 core processes |
| 9 | Raw disk read | Except Defender |
| 10 | Process access | LSASS credential-access masks only |
| 11 | File create | Persistence and drops |
| 12, 13, 14 | Registry | Persistence and security keys |
| 15 | Stream created | Downloads |
| 17, 18 | Pipes | Known remote-execution names |
| 19, 20, 21 | WMI persistence | All |
| 22 | DNS query | Tools and user paths |
| 23, 24, 26 | File delete, clipboard, delete detected | Off |
| 25 | Process tampering | All |
| 27, 28 | File block | Off |
| 29 | Executable written | Downloads and temp folders |

## Explicitly not collected

| Source | Why |
|---|---|
| `WMI-Activity/Operational` | Measured about 1,760 events per hour, mostly 5858 client errors |
| `CodeIntegrity/Operational` | 1,259 events in a day (measured), low value without tuning |
| Windows PowerShell classic log | Measured about 1,460 events per hour under automation, duplicates 4104 |
| Security 5156, 5157, 5152 | Connection logging is very high volume. Sysmon 3 is selective instead |
| Security 4663, 4656 | Object access needs SACLs and is very noisy |
| Security 4689, Sysmon 5 | Process end adds volume without detection value. 4689 is audited on the host at the owner's request, so it stays in the Security log. Whether to ship it is a Phase 8 choice |
| TaskScheduler 200, 201 | Fire on every task run |
| Analytic and debug channels | Vector cannot subscribe to them (issue #25600) |

_Internal test reports and planning records mentioned here are not published with Version 1._
