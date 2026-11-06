# Windows Vector Compatibility

**Status:** Reviewed against the real Windows binary on 2026-10-30, before Vector was installed. Current state is in [Vector agent deployment](../operations/vector-agent-deployment.md). The binary was extracted to a temporary folder and run briefly in the foreground, with console output or a Kafka healthcheck only. No service was created, and nothing was written to Kafka.

**Recommendation: Vector 0.61.0, x86_64, for Phase 8, pinned by SHA-256.** Native Windows-to-Kafka collection is feasible, with the conditions below.

**Correction, 2026-10-31:** the Phase 8 review found that the delivery notes and configuration plan below were wrong in places. They are corrected here.

## Binary

| Item | Result |
|---|---|
| Release | v0.61.0, 2026-10-29, the newest release |
| Artifact | `vector-0.61.0-x86_64-pc-windows-msvc.zip`, from GitHub Releases |
| Also published | `vector-0.61.0-x64.msi` |
| SHA-256 | `6a04e833f9a91f874688e8087d768f5cb35d40e3271c87df6258e271915d0f49`, matches `vector-0.61.0-SHA256SUMS` |
| Version output | `vector 0.61.0 (x86_64-pc-windows-msvc 17e017e 2026-10-29)` |
| Size | 147.9 MB executable |
| **Authenticode** | **`vector.exe` is not signed** |
| GitHub attestation | None found |

Trust rests on the checksum, fetched from the same GitHub release. A compromised release would not be detected. The MSI was not inspected.

`packages.timber.io` returned 404 for this zip, so use GitHub Releases.

## Confirmed by the binary

| Question | Result | How |
|---|---|---|
| `windows_event_log` source | **Present** | `vector list` |
| Kafka sink | **Present** | `vector list` |
| Kafka connection from Windows | **Works** | `vector validate` healthcheck against the live broker passed, and failed correctly on a wrong port |
| Architecture | x86_64, matching this host | Version string |
| `record_id` | **Present on every event** | 2,029 and 727 events captured, no duplicates per channel |
| Other fields | `event_id`, `channel`, `computer`, `provider_name`, `timestamp`, `level`, `user_id`, `message` | Captured events |
| `event_data` | **Parsed into named fields** on EventData channels | System 7045, Defender 1116, Firewall 2097, PowerShell 4104 |
| Checkpoints | `windows_event_log_checkpoints.json` in `data_dir`. A restart delivered 0 repeated events | Restart test |
| Grouped `event_query` | The exact draft Security query was accepted | Run on System, because Security needs elevation |

Security and Sysmon field parsing were not tested. Security is denied without elevation, and Sysmon is not installed. Both use `EventData` in their schemas, so they should behave like the channels above.

## Earlier risks, resolved

| Risk | Result |
|---|---|
| Kafka sink missing from the Windows build | **Closed.** Present and connects |
| Silent subscription failure | **Confirmed, in two forms.** See below |
| Event ID filter limit | **Confirmed.** See below |

## Behaviour to design around

### Skipped channels

| Test | Result |
|---|---|
| One channel, access denied (`Security`, unelevated) | Vector **exits** with an error |
| One channel, does not exist | Vector **exits** with an error |
| Good channel, plus missing and denied channels in one source | **Keeps running.** Only a `WARN` per skipped channel |
| `vector validate` on all of these | **Passes.** It does not check channels |

A multi-channel source can lose Security with only a warning. **Use one source per channel**, so a failure is loud.

### `read_existing_events`

Official docs and issue #26117 report that the default `false` can subscribe successfully, then deliver nothing, with no error and no checkpoint. **Use `true`**, plus `max_event_age_secs` to limit the first backlog. With `false`, the test delivered 0 events in 8 s, but that channel had no new events, so this proves nothing.

### Event ID limits

| Test | Result |
|---|---|
| `only_event_ids` with 5 IDs | Works |
| `only_event_ids` with 40 IDs | **`vector validate` passes, then Vector exits at runtime** |

The cause is an XPath limit in Windows: 23 flat terms per query. The code's limit of 1,000 IDs does not help. **Keep lists to 23 or fewer, or use a grouped `event_query`.** A channel cannot be split across two sources.

### `event_data` loses XML-special characters

Found live in Stage 8.8, and missed by this review. Vector 0.61.0 drops `&`, `<` and `>` from `event_data`, with the spaces beside them. Windows recorded a task named `A & B`, and `event_data` held `AB`. The `xml` field and VRL `parse_xml` both returned the exact text.

The agent therefore enables `include_xml` on every source, and `protect` rebuilds named fields from the XML before redaction, then removes it. Re-check this before upgrading Vector.

### `UserData` is not parsed

Events that use `UserData` XML produced no `event_data` or `user_data` field across 727 `LocalSessionManager` events. The `message` field is rendered, and `include_xml: true` keeps the data.

**Log-clear events 104 and 1102 use `UserData`.** The draft enables `include_xml` on Security and System, so the aggregator must parse the XML for those IDs. 1102 itself has not been observed through Vector.

## Delivery and state

| Topic | Finding | Source |
|---|---|---|
| Delivery | At-least-once, end-to-end acknowledgements supported | Official docs |
| Component maturity | **Beta** | Official docs |
| Checkpoint timing | With a disk buffer, checkpoints follow the **write to the buffer**, not Kafka's confirmation | Source code, corrected in Phase 8 |
| Checkpoint write | Atomic, temp file plus rename, `sync_all` | Source code |
| Position | Windows bookmark per channel | Source code |
| Bad bookmark | Falls back to no bookmark, with a warning. Can redeliver | Source code |
| Disk buffer | Supported on sinks. Vector enforces a minimum size, and the draft's 1 GiB passes `vector validate` | Source code and validate |
| Retry | Kafka client retries until `message_timeout_ms`, then the event is **lost**, because the buffer removes it whatever the outcome. `message_timeout_ms: 0` avoids this | Source and Phase 8 test, corrected |
| Permissions | Runs as `LocalSystem` as a service, so `Event Log Readers` is not needed. Security, Sysmon and PowerShell Operational all deny unelevated read, so a foreground test needs elevation | Unverified until Phase 8 |

`event.id` duplicates are safe downstream, because OpenSearch uses it as `_id`.

## Open upstream issues

All are open against this source at the time of review. None is known to be fixed in 0.61.0.

| Issue | Problem | Effect here |
|---|---|---|
| [#26888](https://github.com/vectordotdev/vector/issues/26888) | Never re-subscribes after a channel goes missing, until restart | Reinstalling Sysmon could stop collection. Restart Vector after any Sysmon change |
| [#26115](https://github.com/vectordotdev/vector/issues/26115) | No re-subscribe after a stale query when a high-volume log rolls over | Reported on a domain controller. Security on a workstation is lower risk, but watch for it |
| [#26120](https://github.com/vectordotdev/vector/issues/26120) | Re-subscribe can drop records, with `read_existing_events=false` | Reported on a domain-joined server. Avoided by using `true` |
| [#26117](https://github.com/vectordotdev/vector/issues/26117) | Delivers nothing with `read_existing_events=false` | Avoided by using `true` |
| [#26525](https://github.com/vectordotdev/vector/issues/26525) | Process crash reading `Hyper-V-VmSwitch-Operational` | Do not collect that channel. Hyper-V is active on this host |
| [#25600](https://github.com/vectordotdev/vector/issues/25600) | Analytic and debug channels cannot be subscribed | Not used |

Source code for 0.61.0 contains a `resubscribe_channel` function, so some recovery exists. It was not tested here.

## Why 0.61.0

- It is the version actually tested here.
- The `windows_event_log` source has had no commits since 2026-10-16, so 0.60.0 and 0.61.0 contain the same source. By commit title, the changes between 0.59.0 and that date are lint, schema and UTF-8 value handling.
- No older release is known to avoid the issues above.
- **It is one day old.** Its other changes, including any to the Kafka sink, were not fully reviewed, because GitHub's comparison stops at 300 files.

If 0.61.0 misbehaves, fall back to 0.60.0, which has the same source. Earlier notes record 0.56.0 as the first with the idle-freeze fix.

## Phase 8 configuration plan

Configuration: `config/windows/vector/vector-agent.yaml`, which replaced the Phase 7 draft in Stage 8.3. See [Vector agent deployment](../operations/vector-agent-deployment.md).

| Decision | Value | Why |
|---|---|---|
| Sources | One per channel | Failure is loud |
| Start position | `read_existing_events: true`, `max_event_age_secs: 604800` | Avoids #26117. The age limit applies on every read, so a short one could filter a backlog |
| Filtering | At the source, within the 23-term limit | Saves volume before Kafka |
| Security | Grouped `event_query`, `include_xml: true` | Limit and `UserData` |
| Identity | SHA-256 of computer, channel, record ID and time | Matches the design |
| Sink | `127.0.0.1:9092`, topic `siem-raw-logs`, `acks=all` | D20 |
| Acknowledgements | Enabled | Checkpoint only after the event is durable in the disk buffer |
| Buffer | Disk, 1 GiB, `when_full: block`, with `message_timeout_ms: 0` and a bounded producer queue | Survives WSL being stopped. Without the timeout change it does not |
| Compression | LZ4 | Low CPU |

**Order of work:** Vector must start after Sysmon exists, because a single-channel source exits if its channel is missing.

### Phase 8 tests

| Test | Why |
|---|---|
| Vector service reads Security as `LocalSystem` | Unverified |
| Real 4688 and Sysmon 1 fields | Not captured yet |
| Real 1102 and 104, from a disposable test | `UserData` handling |
| Every source reports events, using internal metrics | Detects silent loss |
| WSL stopped, then restarted, with a live agent | Roadmap open item |
| Log rollover under load | #26115 |
| Vector memory and CPU on Windows | Unmeasured |
| Restart with a large backlog | Duplicates and rate |

Do not treat a clean `vector validate` as proof the channels work.

_Internal test reports and planning records mentioned here are not published with Version 1._
