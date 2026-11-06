# Windows Telemetry Configuration

**Status:** Applied on 2026-10-30 with the owner's approval. Results are in the Phase 7 configuration record, and the starting state is in the Phase 7 inventory. What to collect is in the [source matrix](../pipeline/windows-telemetry-source-matrix.md). Vector is not installed, so nothing leaves the host yet.

## Applied configuration

`deploy/windows/apply-windows-telemetry.ps1` applies everything below except Sysmon. Run it elevated. It backs up first, is safe to run again, and stops at the first failed check.

### Audit policy

| Subcategory | Before | Now |
|---|---|---|
| Process Creation | No Auditing | Success |
| Process Termination | No Auditing | Success |
| Credential Validation | No Auditing | Success and Failure |
| Group Membership | No Auditing | Success |
| Security System Extension | No Auditing | Success and Failure |
| Special Logon | Success | Success and Failure |
| Logon | Success and Failure | Unchanged |
| Logoff | Success | Unchanged |
| Account Lockout | Success | Unchanged |

The Logon/Logoff rows follow Microsoft's client recommendations. Other subcategories were left alone, and the script proves that by comparing all 60 before and after.

**Group Membership is not group changes.** It logs a user's groups at logon (4627). Group changes come from Security Group Management, which was already on.

### PowerShell

`EnableScriptBlockLogging` is 1 and `EnableScriptBlockInvocationLogging` is 0, under `HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`. Invocation logging would add 4105 and 4106 for every block.

### Event logs

| Channel | Before | Now |
|---|---|---|
| Security | 20 MiB | 128 MiB |
| PowerShell Operational | 15 MiB | 64 MiB |
| Task Scheduler Operational | Disabled, 10 MiB | Enabled, 32 MiB |
| Sysmon Operational | Did not exist | 128 MiB |

All are circular. Together they can use about 320 MiB more on `C:`.

### PowerShell log access

Script block logs can hold secrets, and this channel was readable by every interactive user. Read rights were removed from `IU`, `SU`, `S-1-5-3` and `S-1-5-33`, which keep write rights so that non-admin PowerShell can still log. `SYSTEM`, Administrators and `Event Log Readers` can still read.

**Effect:** an unelevated session can no longer read this log. Vector will run as `LocalSystem`, so it should be unaffected.

## Deliberately not enabled

| Setting | Why |
|---|---|
| 4688 command line, `ProcessCreationIncludeCmdLine_Enabled` | Owner's decision. It would write every command line to the Security log |
| Module logging, transcription | Owner's decision |
| `SCENoApplyLegacyAuditPolicy` | Not approved. Nothing applies legacy audit policy on this host today, but a future one could override the settings above |
| Other Object Access Events | Not approved, so **4698 to 4702 are not generated**. Task evidence comes from Task Scheduler Operational and Sysmon 11 |
| Protected Event Logging | Needs certificates and a decryption step. Consider at hardening |
| Defender, firewall, BitLocker, hypervisor, WSL | Out of scope and confirmed unchanged |
| PowerShell 2.0 engine | Not changed. The feature query returns nothing, and `powershell.exe -Version 2` runs 5.1 instead |

## Residual risks

| Risk | Detail |
|---|---|
| **Secrets in 4104** | Script block logging stores script text as written. Any password placed in a script or typed into PowerShell can be stored in clear text. Administrators, `SYSTEM` and `Event Log Readers` can read it, and Vector will carry it to Kafka and OpenSearch from Phase 8 |
| **Secrets in Sysmon 1** | Sysmon always records `CommandLine` and `ParentCommandLine`, even though 4688 does not. The owner chose to keep this on 2026-10-30. The channel is restricted to administrators. See [Sysmon deployment](sysmon-deployment.md#sensitive-data) |
| Classic PowerShell log | `Windows PowerShell` events 400 and 600 can show host command lines, and this channel was not restricted |
| Task Scheduler log | Still readable by interactive users. Task names and paths are visible |
| PowerShell 2.0 | The engine does not produce script block logs. On 2026-10-31 `powershell.exe -Version 2` reported it deprecated and ran 5.1, so that downgrade route is closed |

**Do not type passwords into PowerShell commands on this host.** Use prompts that do not echo, such as the OpenSearch rotation script.

## Backup

Each run writes a timestamped folder under `%USERPROFILE%\SIEM-Lab\phase7-config\`. **The first run, `20261030-233347`, holds the original state, so keep it.** Later runs back up whatever was current then.

| File in `backup\` | Contents |
|---|---|
| `auditpol.csv`, `auditpol.txt` | Complete audit policy, for restoring and for reading |
| `Security.txt`, `Microsoft-Windows-PowerShell-Operational.txt`, `Microsoft-Windows-TaskScheduler-Operational.txt` | Size, retention and channel access |
| `powershell-policy.txt` | PowerShell policy keys, which did not exist before |
| `untouched-settings.txt` | Defender, firewall, hypervisor, BitLocker and WSL state |

## Rollback

**Rollback has not been tested.** Run it elevated, and remove Sysmon first if it is also being rolled back ([steps](sysmon-deployment.md#rollback)).

```powershell
$Backup = "$env:USERPROFILE\SIEM-Lab\phase7-config\20261030-233347\backup"

auditpol /restore /file:"$Backup\auditpol.csv"
Remove-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' -Recurse

$Ps = 'Microsoft-Windows-PowerShell/Operational'
$Access = ((Get-Content "$Backup\Microsoft-Windows-PowerShell-Operational.txt" | Select-String '^channelAccess: (.+)$').Matches[0].Groups[1].Value).Trim()
wevtutil sl $Ps /ca:$Access /ms:15728640
wevtutil sl Security /ms:20971520
wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:false /ms:10485760
```

A smaller size may not shrink a log that is already larger until the log is cleared. **Do not clear a log just to finish a rollback** unless the owner decides to, because that destroys evidence.

Reverting audit policy and script block logging stops new events. Events already written stay until they wrap.

## Validation

Re-run `apply-windows-telemetry.ps1`, which proves each item with real events, including from a real non-admin process. Sysmon has `deploy/windows/verify-sysmon.ps1`.

**Older 4688 events are not proof.** 4688 appeared on this host with Process Creation set to No Auditing, so only an event for a process started after the change counts. The script matches on process ID.

## Next steps

1. Run normally for **24 to 48 hours**, without automation-heavy work, then measure real volume by channel and event ID.
2. Tune Sysmon, and update the estimates below with measured figures.
3. Begin Phase 8.

## Event volume estimate

**These are estimates, not measurements.** Real volume is still to be measured. The estimate came before the final configuration. It includes no 4689, which is now audited, and Security's measured 5379 at about 2,800 a day is included in its range.

Assumptions: one user, normal daily use, about 16 powered-on hours. JSON event size is 700 bytes measured from Vector output on small channels, and assumed to be 1.2 KB for Security and Sysmon, which have more fields. PowerShell 4104 averages 11.6 KB, measured from this session's scripts.

| Tier | Source | Low events/day | Typical | High |
|---|---|---|---|---|
| Essential | Security, filtered | 5,000 | 15,000 | 40,000 |
| Essential | Sysmon, proposed configuration | 8,000 | 25,000 | 60,000 |
| Essential | PowerShell 4104 and 4100 | 200 | 1,000 | 36,000 |
| Essential | Defender, System, filtered | 40 | 50 | 200 |
| Useful | Firewall, Tasks, filtered | 50 | 100 | 300 |
| **Total** | | **About 13,000** | **About 41,000** | **About 136,000** |
| **Raw JSON per day** | | **About 18 MB** | **About 60 MB** | **About 540 MB** |

The high column assumes a day of heavy PowerShell automation. PowerShell alone is then about 420 MB, because each event is so large.

**Likely to be excessive if not controlled:** PowerShell 4104 during automation, Sysmon 3 and 22 from user-path applications, Sysmon 1 and 4688 during builds, and Sysmon 11 and 13 during software updates.

### Retention against current limits

| Store | Limit | At 60 MB/day | At 540 MB/day |
|---|---|---|---|
| `siem-raw-logs` | 3 GiB across partitions, 72 hours | 72 hours applies | 72 hours applies, about 1.6 GB |
| OpenSearch, 12 GB, assuming 1.5 times raw size on disk | 7-day ISM planned | About 0.6 GB for 7 days | About 5.7 GB for 7 days |
| Security log, 128 MiB | Circular | Days, unverified | Unverified |
| PowerShell log, 64 MiB | Circular | Days | About 4 hours under automation |

Neither limit is exceeded at the high estimate, but the 1.5 factor is unmeasured. No retention setting was changed in this phase. ISM and the `C:` disk check are still due in Phase 9, so **sustained ingestion should not start before they exist**.

_Internal test reports and planning records mentioned here are not published with Version 1._
