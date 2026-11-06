# Kali Attacker Telemetry and Isolation Design

**Status:** Not built. **The owner decided D21 in the Phase 15 brief:** Kali is a controlled test machine, not a production asset or required source, and no collection path is built. Controlled activity is observed through the target and existing sensors. See [ADR-0015](../adr/0015-attack-path-validation.md). This page stays as the record of the options considered.

Kali's logs record what the attacker did. They are ground truth for testing, not detections, and they do not become Windows telemetry. A detection is only proven when the matching event appears independently from Windows.

## Attacker activity categories

| Category | Example | Attack-side record | Expected Windows evidence |
|---|---|---|---|
| Reconnaissance | Host discovery | Tool, target, time | Possibly none |
| Network scanning | Port scan of `192.168.56.1` | Ports and timing | Firewall drops, if logging is enabled |
| Authentication testing | Failed SMB logons against a test account | Account, attempts, timing | Security 4625, then 4624 on success |
| Controlled exploitation | Approved technique against a test target | Technique ID and result | Sysmon, Security and Defender events |

Expected evidence is a planning assumption until it is tested. Windows Home has no Remote Desktop host, and WinRM is stopped, so the real attack surface is limited. SMB is currently listening.

## Attack ledger

Each run records:

| Field | Purpose |
|---|---|
| `run_id` | Links all steps in one exercise |
| `technique` | MITRE ATT&CK ID |
| `tool` and `command` | What was run, with no secrets |
| `start_time`, `end_time` | UTC window for matching |
| `source_ip`, `target` | Must be lab addresses only |
| `expected_signals` | The events that should appear |

## Collection options (D21)

| Option | Benefit | Cost |
|---|---|---|
| **A. Operator ledger copied in batches (recommended)** | No network route to the SIEM. Simple, and Kali stays isolated | Manual, and not real time |
| B. Vector on Kali sending to Kafka | Automatic | Exposes Kafka to the host-only network, which breaks the isolation rule |
| C. Shared folder to Windows | Simple transfer | Adds a VirtualBox channel between attacker and host |

With option A, the file is copied to WSL2 and ingested by a dedicated Vector file source through `siem-raw-logs`. Kali logs are never collected automatically.

## Labelling and separation

| Field | Value |
|---|---|
| `labels.source_role` | `kali_attacker` |
| `event.dataset` | `kali.ledger` |
| `labels.run_id` | Matches the ledger |

Ledger events go to a separate index, proposed as `siem-lab-attack-*`. The Sigma runner and ML detector must exclude it, so attacker records can never raise alerts or train models.

## Correlating attacker and Windows events

Validation joins ledger windows to Windows events by time, `source.ip` and target. It answers two questions: did the expected event appear, and did a detection fire? This happens in test tooling, not in production correlation (D9). Clock differences between Kali and Windows must be measured first.

## Isolation

| Control | Current state | Required |
|---|---|---|
| Attacks use the host-only network | Host-only adapter present | Target only `192.168.56.1` |
| No route to WSL2 services | By design under NAT | Validate from Kali |
| Kafka and OpenSearch unreachable | Not deployed | Validate after deployment |
| Kali NAT adapter | Present | Do not attack through it. Consider disconnecting it during tests |
| Clipboard and drag-and-drop | Bidirectional | Review. This is a host-to-attacker channel |
| Disk location | Inside OneDrive | Review separately |

## Safety rules

- Attack only this lab host, and only with the owner's approval for each technique.
- Use a dedicated test account. Never use real credentials.
- Do not disable Defender, the firewall or other protections to make a test succeed, without separate approval.
- Windows is a real personal machine, so destructive techniques are out of scope.
- Do not weaken the host to create an attack surface without a recorded decision.

## Risks

Kali still runs on VirtualBox under NEM and may stall, which is untested on 7.2.22. Its 2 GB and 2 vCPU allocation is also untested.
