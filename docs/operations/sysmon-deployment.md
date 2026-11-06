# Sysmon Deployment

**Status:** Installed on 2026-10-30 with the owner's approval, after the owner accepted the Sysinternals licence. Results are in the Phase 7 configuration record. It runs a boot-start kernel driver and a persistent service.

## Version and source

| Item | Value |
|---|---|
| Product | Microsoft Sysinternals Sysmon, standalone |
| Version | 15.22, page dated 2026-09-10 |
| Schema | 4.91, binary version 18, read from the binary with `-s` |
| Source | `https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon` |
| Download | `https://download.sysinternals.com/files/Sysmon.zip` |
| `Sysmon.zip` SHA-256 | `00ecf1b46aec99299d3ae0bca79dc621458bd014b20b509d7c5c8e8c8611aa54` |
| `Sysmon64.exe` SHA-256 | `83d31f2478dc6716cfdbf69e5c384bf043072b5f0d8d7b2eea365f709fda4352` |
| Signature | Valid, Authenticode, Microsoft Corporation |

**Pinning:** the download URL has no version in it, so Microsoft can replace the file. The hashes above are the pin, and `install-sysmon.ps1` refuses anything else. Microsoft publishes no checksum, so the hashes were recorded from this download after its signature was verified.

## Standalone or built-in

Windows 11 now includes Sysmon as an optional feature, off by default. Its packages are staged on this host. Microsoft states the two **cannot coexist**.

| | Standalone 15.22 | Built-in |
|---|---|---|
| Version control | Pinned by hash | Follows Windows Update |
| Verification | Hash and signature | Part of Windows servicing |
| Schema | 4.91, known | Unknown until enabled. Microsoft's example shows 4.90 |
| Enable | `Sysmon64.exe -i` | `Enable-WindowsOptionalFeature`, then `sysmon -i` |

**Decision: standalone**, because this project pins versions and it can be verified before anything runs. Changing to built-in later means uninstalling standalone first. Check the configuration's schema version if that happens.

## Configuration

`config/windows/sysmon/sysmon-config.xml`, with 22 rule types and 77 rule conditions. Sysmon's own parser accepted it at install.

| Setting | Value | Why |
|---|---|---|
| Hashes | SHA256, IMPHASH | Threat-intel matching and malware family grouping |
| `DnsLookup` | False | No delay or extra traffic from reverse lookups |
| `CheckRevocation` | False | No certificate network calls |

The per-event plan is in the [source matrix](../pipeline/windows-telemetry-source-matrix.md#sysmon).

### Exclusions and their blind spots

| Exclusion | Blind spot |
|---|---|
| Search workers launched by `SearchIndexer.exe` | Abuse of those exact path and parent pairs |
| `conhost.exe` with `0xffffffff -ForceV1` | A forged command line on that exact binary |
| Microsoft-signed valid drivers (6) | A vulnerable Microsoft-signed driver |
| `csrss` and `wininit` (8, 10) | Code already injected into those processes |
| `\MsMpEng.exe` (9, 10) | **Matches by name ending.** A fake binary of that name in another folder would be hidden |
| PowerShell loading its own engine (7) | None significant |

### Selective rules and what they miss

| Rule | Not seen |
|---|---|
| Network (3), DNS (22) | Traffic from `Program Files` applications not on the tool list, unless the destination port is listed. Malware injected into a browser is not seen by these events |
| Image load (7) | All other DLLs, so most DLL side-loading |
| Process access (10) | Access to anything but LSASS, and other access masks |
| File create (11) | Other file types and locations |
| Registry (12 to 14) | Persistence through keys not listed |
| Pipes (17, 18) | Any tool using a different pipe name |

`%USERPROFILE%\.local\bin\claude.exe` and similar tools will match the user-path rule. They stay visible on purpose. Tune after measuring.

**Off deliberately:** 23 archives deleted files and could fill `C:`. 24 stores clipboard contents, including passwords. 27 and 28 block activity, and Sysmon is only observing here.

## Deployment procedure

This is how it was installed, and how to install it again on a rebuilt host. Apply the [logging configuration](windows-telemetry-preparation.md) first.

1. Read the licence in `Eula.txt`. Accepting it is the owner's decision.
2. Download `Sysmon.zip` from the official URL.
3. Verify without changing anything:

   ```powershell
   .\config\windows\sysmon\install-sysmon.ps1 -ZipPath C:\path\to\Sysmon.zip
   ```

4. Install from an elevated PowerShell:

   ```powershell
   .\config\windows\sysmon\install-sysmon.ps1 -ZipPath C:\path\to\Sysmon.zip -Apply -AcceptEula
   ```

The script checks both hashes, the signature, the version and the XML. It refuses if built-in Sysmon or a different Sysmon binary is present. It then installs with the configuration and sets the channel to 128 MiB. If this pinned version is already installed, it re-applies the configuration instead.

If `Sysmon.zip` no longer matches, Microsoft has released a new version. Review it and update the pin. Do not bypass the check.

## Validation

`deploy/windows/verify-sysmon.ps1` runs these checks elevated, and all passed on 2026-10-30 and again after a restart on 2026-10-31. It creates and removes one `.ps1` file, and makes one HTTPS request to `example.com`.

| Check | Expected |
|---|---|
| `Sysmon64` service | Running, automatic |
| `SysmonDrv` | Running in the service manager, and listed by `fltmc filters`. `Win32_SystemDriver` does not list it on this host |
| Installed binary | Pinned hash, valid signature |
| `Microsoft-Windows-Sysmon/Operational` | Enabled, 128 MiB, circular |
| Event 16 | Configuration change recorded |
| Test process | Event 1 with SHA256 and IMPHASH |
| Test HTTPS request from PowerShell | Events 3 and 22 |
| Test `.ps1` in Downloads, then deleted | Event 11 |
| Event 255 | None |
| Security 4697, System 7045 | Sysmon service recorded |

Next, run for 24 to 48 hours, and record events per day by ID before tuning.

**Check for stalls.** This host had severe stalls under VirtualBox and Hyper-V. A kernel driver is a new variable. The check passed with the stack running, but only for minutes and without Kali. After a restart on 2026-10-31 the driver was running with no crash or unexpected shutdown, but the stack was not started.

**The driver is boot-start.** If the host has trouble at boot after this change, suspect it first. Run the rollback below from Safe Mode if needed. This has not been tested.

## Change configuration

```powershell
Sysmon64.exe -c config\windows\sysmon\sysmon-config.xml
```

The change applies immediately, with no restart. Event 16 records it. Sysmon's own service stop, or a change here, is itself a detection signal.

## Rollback

```powershell
Sysmon64.exe -u
```

This removes the service and the driver, which takes effect at once. If that fails, `Sysmon64.exe -u force`. The event channel may remain and is harmless. Existing events stay until they wrap.

Rollback has not been tested. Afterwards, confirm with `Get-Service Sysmon*` and `fltmc filters`, and remove the Sysmon sources from the Vector configuration, because a missing channel stops a single-channel source.

## Sensitive data

Sysmon records full command lines in `CommandLine` and `ParentCommandLine`, which can contain passwords, and file paths that can reveal personal data. This applies even though 4688 command-line capture is deliberately off, and Sysmon has no setting to remove these fields. `FieldSizes` can only truncate them.

**Owner's decision, 2026-10-30:** keep the configuration as prepared, because argument-based detection depends on these fields. The rule against command-line capture applies to 4688.

The channel allows read for `SYSTEM`, Administrators, Backup Operators, Server Operators and `Event Log Readers`, and an unelevated read was denied. From Phase 8 these fields will reach Kafka and OpenSearch, which is a separate exposure. If this decision changes, `FieldSizes` is the option to test.

_Internal test reports and planning records mentioned here are not published with Version 1._
