# Incident Management

`siem-correlator` turns alerts into incidents. It never modifies events, alerts or enrichment documents, never takes an action on a host, and never marks an incident contained or resolved. Decisions are in [ADR-0011](../adr/0011-correlation-and-incidents.md), and rules and scoring in [Correlation Rules](correlation-rules.md).

## How it works

```
Kafka siem-alerts ──> inbox (SQLite) ──> analysis ──> rules ──> incident + audit + outbox (one transaction)
                        │  bad message: quarantine      │                       │
OpenSearch ─────────────┴─ identity fields, enrichment ─┘                       └──> siem-incidents-*, siem-incident-audit-*
```

| Step | Failure | What happens |
|---|---|---|
| Kafka to inbox | Crash before the commit | Kafka delivers again, and the inbox ignores repeats |
| Bad message | Not an alert | Stored in quarantine, with the reason, digest and size, and never its content |
| Analysis | OpenSearch down | The alert stays waiting, and is retried every 30 s |
| Analysis | Unexpected data | Marked failed, kept, and health reports it |
| Rules and incident | Crash mid-transaction | Rolled back, and the alert is analysed again |
| Outbox | OpenSearch down | Waits. External versions stop an old revision replacing a new one |
| Enrichment | Late | Rechecked for 30 minutes. A match can then form, or the incident score updates |
| Enrichment | Never arrives | Marked missing, and confidence says so |

Intelligence matches on events are not alerts, so Phase 10 writes them only to OpenSearch. The service polls them as "signals", which scenario 7 uses.

## Incident record

| Field | Meaning |
|---|---|
| `incident_id` | A digest of the rule, entity and earliest alert of the first match. Fixed once created. A rebuild gives the same ID only if alerts arrive in the same order |
| `title`, `description` | From the first rule that matched |
| `status` | One of the states below |
| `severity`, `confidence`, `confidence_level` | See [scoring](correlation-rules.md#scoring) |
| `first_seen`, `last_seen` | Event time |
| `created_at`, `updated_at`, `revision` | When recorded |
| `hosts`, `users`, `ips`, `domains`, `processes`, `file_hashes` | Entities, by display name |
| `entity_ids` | Stable entity IDs |
| `alert_ids`, `signal_ids`, `source_event_ids` | All contributors |
| `alert_refs`, `raw_event_refs`, `enrichment_refs` | Index and document references |
| `rules` | Correlation rules, each with its join |
| `indicators` | Hostile indicators: type, value, verdict and score. No provider text |
| `correlations` | Each match, with its reason. The first 100 are spelled out, and `correlations_omitted` counts the rest |
| `timeline` | Alerts by event time. The first 500, and `timeline_omitted` counts the rest |
| `uncertain` | What is missing or in doubt |
| `explanation` | Why grouped, connected by, rules, sequence, evidence, uncertainty, severity and confidence reasons |
| `notes` | Analyst notes |

`alert_ids` and the audit trail stay complete. Scoring holds up to 25 alerts per rule, because more repeats change nothing, so an incident's entity lists come from those.

## Lifecycle

| From | Can move to |
|---|---|
| New | Open, Investigating, False positive |
| Open | Investigating, Contained, Resolved, False positive |
| Investigating | Contained, Resolved, False positive, Open |
| Contained | Resolved, Investigating |
| Resolved | Closed, Open |
| Closed | Open |
| False positive | Open |

State names in commands are `new`, `open`, `investigating`, `contained`, `resolved`, `closed` and `false_positive`. Resolved, closed and false positive need a note. New activity never reopens a finished incident: it starts a new one, and the finished one is left unchanged.

## Operations

Commands run in WSL as a member of `siem-analyst`. The `linux` user is one. Root is refused.

```bash
wsl -d Ubuntu-24.04 -u linux
siem-incident list [--status new] [--limit 50]
siem-incident show <id>                  # the short ID from list works
siem-incident timeline <id>
siem-incident search --host H --user U --ip A --severity high
siem-incident status <id> investigating
siem-incident status <id> false_positive --note "why"
siem-incident note <id> "text"
siem-incident rules
siem-incident rule-disable <rule-id>
siem-incident rule-enable <rule-id>
siem-incident replay --hours 6           # 1 to 720
siem-incident lag                        # health, Kafka lag, waiting alerts
siem-incident quarantine
siem-incident audit [<id>]
siem-incident audit-verify
```

Start and stop, as root: `systemctl start siem-correlator`, `systemctl stop siem-correlator`, `journalctl -u siem-correlator`. It also starts and stops with `siem-up.ps1` and `siem-down.ps1`. The Alert task shows a warning from `correlator.json`.

Add an analyst, as root: `usermod -aG siem-analyst <name>`.

## Troubleshooting

| Sign | Meaning | Do |
|---|---|---|
| `lag` shows `kafka` not ok | Broker unreachable | Fix Kafka. Nothing is lost while the alert is on the topic, up to 72 h |
| `lag` shows `opensearch` not ok, and alerts waiting | No evidence available | Fix OpenSearch. They resume |
| `outbox` above 0 for long | Writes refused | Check OpenSearch and the role |
| Alerts in `failed` | Data the code cannot read | Read the journal. The alert is stored |
| Service was off for over 72 h | Kafka expired alerts | `siem-incident replay --hours N` reads the alert index, for up to 30 days |
| `audit-verify` not intact | The state file changed outside the service | Treat as an integrity incident. The OpenSearch copy holds what had shipped |

## Backup and recovery

The state file is `/home/linux/siem/data/correlation/correlator.db`. Copy it with the service stopped. If it is lost, incidents can be rebuilt with `replay`. The same alerts are grouped by the same rules, though an ID can differ if arrival order does. Analyst status, notes and the audit chain are held only in that file and in OpenSearch, and a rebuild does not restore them, so back it up after analyst work.

## Security

- The account reads identity fields of events, and alerts and enrichment. It writes only `siem-incidents-*` and `siem-incident-audit-*`.
- The service runs unprivileged with a 192 MiB limit, a read-only system, and no network listener.
- Incidents hold no command lines, script text or provider text. Replay cuts alerts to the fields Kafka carries.
- Limits are listed in [ADR-0011](../adr/0011-correlation-and-incidents.md): the account can overwrite its own audit documents, and root in WSL can alter state.
