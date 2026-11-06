# ADR-0014: WSL2 Linux Telemetry

| Field | Value |
|---|---|
| **Status** | Implemented on 2026-11-01, under the owner's Phase 13 brief. Subject to owner review |
| **Decisions** | D46, D47, D48, D49 |
| **Evidence** | Acceptance report, [operations and contracts](../pipeline/wsl2-linux-telemetry.md) |

**What this does not decide.** **D21 stays Pending.** Read from the repository, D21 is the Kali telemetry collection path, with an operator ledger recommended. It has nothing to do with WSL2, and this phase neither needs it nor touches Kali. **D15 stays Pending:** it holds the auditd question, so auditd was not installed. See [D49](#d49-the-journal-and-the-package-log-are-the-sources).

## D46: Linux is a second agent, with its own key

**Decision:** a separate Vector process, `siem-linux-agent`, reads this host, and applies the same stages as the Windows agent: redact, seal, whole-event MAC, disk buffer, `siem-raw-logs`. It holds its own key, `k2`. The verifier accepts `k2` on Linux channels only, and refuses any other key there, with `key_scope`.

**Why:** ADR-0008 says a second agent needs its own key, because a shared key would let one host forge another's events. A separate key is not enough alone: the verifier must also bind it to a source, which is the only change to its logic.

| Alternative | Why not |
|---|---|
| Add a source to the aggregator | The aggregator must hold no field keys (D23), and events must not bypass the verifier |
| Reuse `k1` | ADR-0008 forbids it |
| A plain path for "trusted" local logs | A parallel path around Phase 8 controls, which the brief forbids |

**Verifier changes:** two channels (`linux-journal`, `linux-package`), `Message` and `CommandLine` restricted on them, and the key binding. Windows channels, fields and order of checks are unchanged, and a test proves it with `k2` loaded.

**This does not change D23 or D24.** It is the case ADR-0008 reserved under "Revisit when".

## D47: Text is sealed, and only the kernel's word classifies an event

**Decision:** all message text and command lines are sealed, after redaction. Only named fields leave the agent. An event is treated as coming from a program only if journald's `_EXE` is that program. Otherwise it is stored as `unverified-log-entry`, labelled `attribution: unverified`, with no user or target fields.

**Why:** Linux logs differ from Windows ones in a way that matters. Any local process can write `SYSLOG_IDENTIFIER=sudo` with any text. `_EXE`, `_UID` and `_COMM` are added by journald, and cannot be set by the writer.

**Cost:** `_EXE` needs the process to be alive when journald reads it. A tool that exits at once can lose it, and its event becomes unverified. That fails safe: a true event is not called proven, and a false one is not believed.

**One exception, from real data:** `crontab` exits so quickly that it never has `_EXE`, so every real crontab change would have been unverified. For that tool alone, a matching kernel process name is accepted, labelled `attribution: process-name`, with `exe_verified` false. A process can rename itself, so this is weaker. A forger can raise a false alert this way, and cannot hide a real one.

## D48: Linux events have their own index family

**Decision:** `siem-linux-YYYY.MM.DD`, a separate template, retention of 7 days to match Windows events, and a separate sink. The aggregator's `normalize` transform and Windows sink are unchanged. The route for Windows events gained one condition, to exclude Linux channels. No Kafka topic is added.

**Who can read:** the detector, all fields, as on Windows. The asset service, named fields under field level security, with no message, command or journal fields. The correlator and enricher cannot read this index, so a Linux alert reaches them with its alert fields only. That is deliberate for now, and is listed in the limits.

**Host identity:** the agent sets `host.name` to `asus-wsl`, because WSL takes the Windows computer name, and `host.id` to the digest of the machine id, which is the digest the Phase 14 asset already stores. So events join the asset by identity, and a name cannot attach them to the wrong record.

**Detection:** `EVENT_INDEX` now names both families. Every rule filters on its own `event.dataset`, so a Windows rule cannot match a Linux event, or the reverse, and a test asserts this for every rule.

## D49: The journal and the package log are the sources

**Decision:** collect the systemd journal and `/var/log/dpkg.log`. Do not collect `auth.log` or `syslog`, which rsyslog copies from the journal, because that would duplicate every event. Leave out the SIEM's own service logs, which would feed back into this pipeline. systemd's own records about those services stay.

**Boots:** Vector refuses to read across boots on systemd 250 to 257, and this host has 255. So `siem-linux-catchup.py` runs before the agent starts. If the saved cursor belongs to an earlier boot, it exports what was unread to a spool, which the agent seals like any other entry, with the same cursors. Without it, entries written after the agent stopped, and before a VM restart, would never be read.

**Process execution is a known gap.** Nothing records every process here. That needs auditd or an eBPF tool, and auditd sits under D15, which is Pending. The kernel supports audit, and `systemd-journald-audit.socket` is off. What is recorded is every sudo command, cron command and service start, each with its command line where the source gives one.

### Decision needed from the owner

**Should process execution be collected on the SIEM host?** This is part of D15. If yes, auditd's rules would need limiting, because the stack's own processes are busy, and its volume and memory would need measuring here first.

_Internal test reports and planning records mentioned here are not published with Version 1._
