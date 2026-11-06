# Windows Telemetry Design

**Status:** Background design. Phase 7 added the [source matrix](windows-telemetry-source-matrix.md), the measured inventory, the [Vector compatibility review](windows-vector-compatibility.md) and the [applied configuration](../operations/windows-telemetry-preparation.md). Where they differ from this document, they take priority.

Windows is the monitored endpoint. All telemetry in this document comes from the real Windows operating system, not from WSL2. Synthetic logs must not stand in for it.

## Sources

| Source | Channel | Provides | Limitations | State on 2026-10-30 |
|---|---|---|---|---|
| Sysmon | `Microsoft-Windows-Sysmon/Operational` | Process creation with hashes, network connections, file, registry, DNS and driver activity | Needs a tuned configuration or it is noisy. Network events are off by default and carry no byte counts | Installed, 128 MiB |
| Security | `Security` | Logons, failures, account and group changes, privilege use | Depends on audit policy. Reading it needs elevated rights | Enabled, 128 MiB |
| System | `System` | Services, drivers, boot and shutdown | Little direct attack detail | Enabled, 20 MB |
| Application | `Application` | Application errors and crashes | Noisy and inconsistent | Enabled, 20 MB |
| PowerShell | `Microsoft-Windows-PowerShell/Operational` | Engine and script activity | Attackers can use other shells. Reading it now needs elevated rights | Enabled, 64 MiB, script block logging on |
| Defender | `Microsoft-Windows-Windows Defender/Operational` | Detections, remediation and protection changes | Shows only what Defender saw | Enabled, 16 MB |
| Windows Firewall | `pfirewall.log`, plus the firewall event channel | Allowed and dropped connections in the log file. The channel records firewall changes | Log file logging is off. It is a file, not an event channel | File logging off on all profiles |

Additional sources need a specific justification. TaskScheduler Operational is now enabled, at 32 MiB, and WMI-Activity remains a candidate.

## Configuration

| Item | Why | State |
|---|---|---|
| Install Sysmon with a tuned configuration | Core endpoint visibility | Done |
| Review audit policy with `auditpol` | Logon and account events depend on it | Done. `auditpol` works on Windows Home |
| Enable process creation auditing (4688) | Backup process visibility | Done, **without command lines**, by the owner's decision |
| Enable PowerShell script block logging (4104) | Records script content | Done. Scripts can contain secrets, so read access is restricted |
| Enable firewall logging | Dropped-connection data for scan detection | Not enabled. Revisit under D15 |
| Review channel sizes | Small logs wrap during WSL outages | Done |

**Sensitive data:** command lines and scripts can contain credentials. Those fields are treated as sensitive: masked at ingestion, and withheld from readers by field level security.

## Sysmon event selection

| Priority | Event IDs | Reason |
|---|---|---|
| Start with | 1, 3, 11, 13, 22 | Process, network, file, registry and DNS |
| Add with filters | 7, 10 | High volume. Microsoft warns both can generate significant logging |
| Add when needed | 2, 6, 8, 9, 12, 14, 15, 17, 18, 19, 20, 21, 25 | Specific techniques |
| Avoid at first | 23, 24 | 23 archives deleted files and can consume disk. 24 touches clipboard content |

## Collection with Vector

Vector runs natively on Windows as a service, using the `windows_event_log` source.

| Finding | Effect on design |
|---|---|
| Source added in v0.55.0, and v0.61.0 is the latest release | Pin a version at deployment |
| The documentation labels it **beta** | Treat it as unproven and test it in Phase 8 |
| v0.56.0 fixed a freeze after idle periods | Use a version with that fix |
| `read_existing_events=false` can subscribe and never deliver | Test this setting explicitly |
| `read_existing_events=true` reads the backlog once per channel | Plan for a first-run burst |
| One source per channel | Do not list a channel twice |
| `only_event_ids` fails above about 23 IDs | Confirmed in Phase 7, and `vector validate` does not detect it. Use a grouped `event_query` |
| Acknowledgements off means a crash can lose checkpointed data | Enable end-to-end acknowledgements |
| Security channel access | The service account needs read access, which is untested |
| Kafka sink in the Windows build | Confirmed in Phase 7 with `vector list` and a live healthcheck |

The firewall log needs Vector's `file` source, and it follows the file generation rules in [ingestion pipeline](ingestion-pipeline.md).

## Event identity

`event.id` is derived from the computer, channel, `EventRecordID` and event creation time. Vector's documentation does not list `record_id`, but the source code at v0.61.0 emits it (`src/sources/windows_event_log/parser.rs`, commit `17e017e3c07bca3f2048f7cc4ec618a23d9289c5`). Phase 7 confirmed it on real events from the Windows binary.

Creation time is included because record numbering could restart if a log is cleared. `labels.event_id_basis` is `source_record`.

## ECS mapping

| Windows field | ECS field |
|---|---|
| `channel` | `winlog.channel` |
| `provider_name` | `winlog.provider_name` |
| `event_id` | `winlog.event_id`, `event.code` |
| `record_id` | `winlog.record_id` |
| `computer` | `host.name` |
| Sysmon `Image` | `process.executable` |
| Sysmon `CommandLine` | `process.command_line` |
| Sysmon `ProcessGuid` | `process.entity_id` |
| Sysmon `Hashes` | `process.hash.*` |
| Logon `TargetUserName` | `user.name` |
| Logon `IpAddress` | `source.ip` |

Final mappings are confirmed against real events in Phase 9.

_Internal test reports and planning records mentioned here are not published with Version 1._
