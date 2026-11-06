# WSL2 Linux Telemetry

**Status:** Deployed in Phase 13. Decisions are in [ADR-0014](../adr/0014-wsl2-linux-telemetry.md), and results are in the acceptance report.

This telemetry describes the WSL2 Ubuntu host that runs the SIEM. It says nothing about what happens elsewhere.

| Activity | Seen here? |
|---|---|
| Linux userspace in WSL2 | **Yes**, through the journal and dpkg |
| The WSL2 kernel | Warnings and worse only |
| The Windows host | **No.** That comes from the Windows agent, under `host.name` `ASUS`, in `siem-windows-*` |
| Inside the Kali VM | **No.** Kali is D21, which is Pending |

## Path

```text
journald, dpkg.log
  -> siem-linux-agent (Vector): named fields only, redact, seal, whole-event MAC, disk buffer
  -> Kafka siem-raw-logs            the same topic. Kafka sees sealed envelopes
  -> aggregator -> seal verifier    k2 is accepted on Linux channels only
  -> aggregator normalize_linux     ECS
  -> OpenSearch siem-linux-YYYY.MM.DD
  -> detection, then correlation, asset inventory
```

## Sources

Checked on this host on 2026-11-01. Volumes are real, from the 24 hours before collection began, so they include test activity.

| Source | Enabled here | Real events | Collected by | Needs | Volume |
|---|---|---|---|---|---|
| systemd journal | Yes, persistent, in `/var/log/journal` | Yes | Vector `journald` | Group `systemd-journal` | About 30,600 entries a day in all, and far fewer after the exclusions below |
| Authentication, through PAM | Yes | `su`, `login`, `runuser`. `sudo` when used | Journal | As above | Hundreds a day, mostly test harnesses |
| sudo | Installed | None until the test here, because no one used it | Journal | As above | Follows use |
| Users and groups | Yes | `useradd`, `userdel`, `usermod`, `groupadd`, `gpasswd` | Journal | As above | Follows use |
| cron, crontab | `cron` active | Yes | Journal | As above | About 18 a day |
| systemd timers and services | Yes | Yes | Journal, with structured `UNIT`, `JOB_*` and `UNIT_RESULT` | As above | About 2,900 a day |
| Packages | Yes | Yes | Vector `file`, `/var/log/dpkg.log`, world-readable | None | Follows use. Unattended upgrades run about daily |
| Kernel | Yes | About 2,500 lines a day, mostly boot and driver noise | Journal, priority warning or worse | As above | A few |
| SSH | **Not installed** | **None** | Parser ready. Tested on fixtures only | | None |
| auditd | **Not installed.** Under D15 | **None** | Not collected | Owner decision | |
| UFW, nftables | **Not installed** | **None** | Not collected | | |
| AppArmor | Inactive | **None** | Not collected | | |
| `auth.log`, `syslog` | Yes, from rsyslog | Copies of the journal | **Deliberately not read:** they would duplicate events | | |

**Left out on purpose:** the logs of Kafka, OpenSearch, Vector, the verifier and the `siem-*` services. Reading them would feed the pipeline's own traffic back into itself, and Kafka alone writes about 19,500 lines a day. systemd's records about those services stay, which is what shows a service failing.

## WSL2 behaviour

| Item | Finding |
|---|---|
| systemd | Available, version 255. `boot.systemd=true` in `/etc/wsl.conf` |
| Journal | Persistent. 413 MB at the start of this phase, with journald's default limits |
| Boot ID | **Survives `wsl --terminate`.** It changes only when the virtual machine restarts: `wsl --shutdown`, idle shutdown of the VM, or a Windows restart |
| Reading across boots | Vector refuses it on systemd 250 to 257. `siem-linux-catchup.py` covers the gap |
| Audit | Kernel support present, nothing configured, `systemd-journald-audit.socket` off |
| Host name | WSL takes the Windows computer name, so the agent reports `<name>-wsl` |
| Time zone | UTC, which `dpkg.log` timestamps rely on |
| Network | NAT. The WSL address changes at boot. Listening services are recorded by Phase 14 snapshots, not here |

## Collection

`config/wsl/vector/vector-linux-agent.yaml`, installed to `/home/linux/siem/config/linux-agent/`.

| Setting | Value | Why |
|---|---|---|
| Cursor | `emit_cursor: true`, saved in `journal/checkpoint.txt` | Without it, entries have no identity |
| First start | `since_now: true` | Does not import the old journal |
| Kernel | Priority 4 or lower | Keeps warnings, drops driver noise |
| dpkg | `install`, `upgrade`, `remove`, `purge` lines | Status lines repeat these |
| Buffer | 256 MiB on disk, blocks when full | Past that, the journal itself holds what follows |
| Delivery | `acks: all`, `message_timeout_ms: 0` | A send never times out into a loss |
| Metrics | `127.0.0.1:9597` | Counts only, loopback |

## Event identity

| Field | Value |
|---|---|
| `event_uid` | SHA-256 of `linux-journal`, machine id and cursor. For packages: `linux-package`, machine id and the line |
| `record_id` | Journal time in microseconds, or the dpkg line's time |
| `event_id` | Always 1. The verifier needs a number, and classification happens later |

A reread gives the same identity, so the verifier refuses it as a replay, and the document is not touched.

## Security

- **Fields:** only the named list leaves the agent. Anything else a program adds to its entry stays behind.
- **Text:** `Message` and `CommandLine` are redacted and sealed. The verifier refuses them in the clear on any Linux event.
- **Redaction:** all 14 Windows rules, unchanged and checked by a test, plus `IDENTIFIED BY`, `sshpass -p`, `chpasswd` and password hashes.
- **Failure:** a transform error keeps the fact that an entry was written, and no content, with `labels.seal_failed`.
- **Forgery:** see [ADR-0014, D47](../adr/0014-wsl2-linux-telemetry.md#d47-text-is-sealed-and-only-the-kernels-word-classifies-an-event).
- **Privilege:** the agent's user has `systemd-journal` and no other privilege. It cannot read `auth.log`, shadow, or any other key.

**After the verifier, text is in plain form in OpenSearch,** as Windows command lines are. Field level security keeps it from the asset service. Only the detector, and administrators, can read it.

## ECS fields

| Field | Source | Notes |
|---|---|---|
| `@timestamp`, `event.created` | The source's own time | A bad time on one event falls back to arrival time |
| `event.ingested` | The aggregator | Detection windows use this |
| `event.kind`, `event.module` | `event`, `linux` | |
| `event.dataset` | `linux.auth`, `linux.cron`, `linux.system`, `linux.kernel`, `linux.package` | |
| `event.category`, `type`, `action`, `outcome` | Parsed, see below | `log-entry` and `unknown` when nothing is claimed |
| `event.provider` | `SYSLOG_IDENTIFIER` | Written by the program, so not proof |
| `host.name`, `host.hostname` | Set by the agent | `asus-wsl` |
| `host.id` | Digest of the machine id | Matches the Phase 14 asset |
| `host.os.type`, `family`, `name`, `version` | `/etc/os-release` | |
| `user.name` | Parsed | Who acted. Absent if the source does not say |
| `user.id` | Parsed | The number the source reports |
| `user.effective.name` | Parsed | Who it ran as |
| `user.target.name`, `group.name` | Parsed | |
| `process.pid`, `executable`, `name`, `user.id` | `_PID`, `_EXE`, `_COMM`, `_UID` | The program that wrote the entry |
| `process.command_line` | sudo or cron command, else `_CMDLINE` | Sealed in transit, restricted at rest |
| `source.ip`, `source.port` | Parsed | Only valid addresses |
| `service.name` | `UNIT` | |
| `package.name`, `version`, `previous_version` | dpkg | |
| `log.level`, `log.syslog.facility.code` | `PRIORITY`, `SYSLOG_FACILITY` | Absent when the entry has none |
| `message` | `MESSAGE` | Redacted, up to 64 KiB |
| `journald.transport`, `cursor`, `boot_id`, `unit`, `exe_verified` | Journal | |
| `labels.source_role`, `protection`, `event_id_basis`, `redactions`, `truncated`, `attribution` | Agent and aggregator | |

`process.parent.pid` and `destination.ip` are never set: this source does not give them.

| `event.action` | From |
|---|---|
| `sudo-command`, `sudo-auth-failed`, `sudo-not-permitted` | sudo |
| `su-session`, `su-failed` | su |
| `session-opened`, `session-closed`, `pam-auth-failed` | pam_unix, within any verified program, and logind |
| `ssh-login`, `ssh-login-failed` | sshd. **Fixtures only** |
| `user-created`, `user-deleted`, `group-created`, `group-deleted`, `group-member-added`, `group-member-removed`, `password-changed` | Shadow tools |
| `scheduled-task-run`, `crontab-replaced`, `crontab-edited`, `crontab-deleted`, `crontab-listed` | cron |
| `service-started`, `service-stopped`, `service-restarted`, `service-failed`, `service-event` | systemd, PID 1's structured fields |
| `package-installed`, `package-upgraded`, `package-removed` | dpkg |
| `unverified-log-entry` | A known name, from a program journald does not confirm |
| `log-entry` | Anything else |

## Asset link

Events join the existing SIEM host asset through `host.id`. The first event adds `asus-wsl` as an alias of that asset, so an alert or incident naming that host finds it. An id that no asset holds is counted in `unattributed_linux_events`, and no record is made from it. Telemetry never changes owner or criticality. Users are recorded as `asus-wsl\name`, so a Linux account and a Windows account with one name stay two entities.

## Detection

| Rule | Source | Level | On real telemetry |
|---|---|---|---|
| Sudo refused | Sigma, `linux.auth` | Medium | Fired |
| Command run with sudo | Sigma, grouped per account and hour | Low | Fired |
| Local account created | Sigma | Medium | Fired |
| Account added to a privileged group | Sigma | High | Fired |
| User crontab changed | Sigma, `linux.cron` | Medium | Fired |
| SIEM service failed | Sigma, `linux.system` | High | Fired |
| Package installed | Sigma, `linux.package` | Low | Fired |
| Failed authentication burst | Custom, 5 in 5 minutes | Medium | Fired |

**Considered and not built:**

| Scenario | Why not |
|---|---|
| Repeated SSH failures, as its own rule | No SSH server. The burst rule covers `ssh-login-failed` when one exists |
| Unexpected service creation | Nothing logs a new unit file. Phase 14 snapshots record it, every 6 hours |
| Unusual process execution | No process telemetry |
| Security service stopped | A planned stop looks the same, so only failure is alerted |

Correlation adds `cor-linux-privileged-account` and `cor-linux-auth-burst-then-sudo`, which joins by account name.

**Cross-platform:** no rule joins Windows and Linux, on purpose. A shared user name across the two proves nothing, and a test confirms that it links nothing. What a later phase can use: `host.id`, `user.name`, `source.ip` and the asset relationships. Time alone must never be enough.

## Dashboard contract

| Need | Where |
|---|---|
| Events | `siem-linux-*`, with the fields above. Windows events keep their own schema, so a timeline merges on `@timestamp`, `host.name`, `event.action`, `event.outcome`, `user.name` |
| Source health | `/home/linux/siem/data/linux-agent/health.json`, every 5 minutes: `status`, `checked_ms`, `message`, `source`, `agent`, `unread_journal_entries`, `oldest_unread_seconds`, `buffer_events`, `sent_events`, `component_errors`, `discarded_events` |
| Source health, Windows side | `SIEM-Lab\monitor\linux-agent.json`: `status`, `checked_ms`, `message` only |
| Which datasets a host sends | `siem-asset show`, as `telemetry_source` items |
| Host | [Asset contract](../detection/asset-inventory.md#dashboard-contract), through `host.id` |

`status` is `OK`, `WARN` or `CHECK_FAILED`. The rule schema version stays with `ecs.version`, and new fields are added, never renamed.

## Operating

```bash
# As root in WSL, from the repository.
bash deploy/opensearch/create-ingest-user.sh && bash deploy/opensearch/create-detector-user.sh && bash deploy/opensearch/create-asset-user.sh
bash deploy/opensearch/apply-index-policy.sh
bash deploy/wsl/install-linux-agent.sh
systemctl restart seal-verifier vector
systemctl start siem-linux-agent siem-linux-health.timer
```

It starts and stops with `siem-up.ps1` and `siem-down.ps1`.

| Question | Command |
|---|---|
| Is it running? | `systemctl status siem-linux-agent` |
| Is it keeping up? | `cat /home/linux/siem/data/linux-agent/health.json`, as root |
| Refusals? | `curl -s 127.0.0.1:9612/metrics \| grep result=`, and look for `key_scope` |

## Troubleshooting

| Symptom | Meaning | Action |
|---|---|---|
| `Linux agent WARN`, unread entries old | The agent cannot deliver | Check Kafka. The disk buffer holds 256 MiB, and the journal holds more |
| Many events with `labels.seal_failed` | The protect transform is failing | They hold no content. `journalctl -u siem-linux-agent`, then fix the cause. Those entries are not recoverable unless the cursor is moved back |
| `key_scope` in the verifier's counts | A wrong key signed an event | Treat it as an attempted forgery, unless a key was just rotated |
| `unverified-log-entry` from a real tool | The program exited before journald read its details | The event is kept, and raises no alert |
| Agent will not start after a Windows restart | The catch-up step failed | It cannot stop the agent. Check `journalctl -u siem-linux-agent` |

**Rotating `k2`:** add a new pair, such as `k3`, to both key files, name it in the verifier's `-linux-keys` flag, and restart the verifier, then the agent. Keep the old pair until nothing signed with it is left in Kafka.

**Backup:** the agent's checkpoint and buffer are in `/home/linux/siem/data/linux-agent`. Key files are in `/home/linux/siem/config/linux-agent/`, and must not go in a repository.

_Internal test reports and planning records mentioned here are not published with Version 1._
