# Writing Rules

Use Sigma where you can. Write a custom rule only for what Sigma cannot state: order, sliding counts, timing, or decoding.

## Add a Sigma rule

1. Create `rules/sigma/windows/<name>.yml`, with a new `id` from `uuidgen`.
2. Add the `id` to `rules/rules.yml`.
3. Add at least one `match` and one `no_match` to `tests/detection/fixtures.yml`, under `<name>`. A near miss makes the best `no_match`.
4. Validate and test.
5. Deploy.

### Log sources

| `logsource` | Event | Fields |
|---|---|---|
| `category: process_creation` | Sysmon 1 | `Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `OriginalFileName`, `IntegrityLevel`, `CurrentDirectory`, `User` |
| `category: network_connection` | Sysmon 3 | `Image`, `User`, `DestinationIp`, `DestinationPort`, `SourceIp`, `SourcePort`, `DestinationHostname`, `Initiated`, `Protocol` |
| `category: file_event` | Sysmon 11 | `Image`, `User`, `TargetFilename` |
| `category: registry_set` | Sysmon 13 | `Image`, `User`, `TargetObject`, `Details` |
| `category: dns_query` | Sysmon 22 | `Image`, `User`, `QueryName` |
| `category: ps_script` | PowerShell 4104 | `ScriptBlockText`, `Path` |
| `service: security` | Security log | `EventID`, `TargetUserName`, `SubjectUserName`, `TargetSid`, `MemberSid`, `MemberName`, `ServiceName`, `ServiceFileName`, `LogonType`, `PrivilegeList` |
| `service: system` | System log | `EventID`, `ServiceName`, `ImagePath`, `StartType`, `AccountName` |
| `service: windefend` | Defender | `EventID`, `ThreatName`, `Path` |
| `service: taskscheduler` | Task Scheduler | `EventID`, `TaskName` |

All use `product: windows`. To add a field, add it to `ecs.py`, after confirming that real events hold it. Only collected event IDs exist: see `config/windows/vector/vector-agent.yaml`.

### What is refused

The compiler refuses these, because each would silently change or empty the rule:

| Construct | Why | Instead |
|---|---|---|
| `re` modifier | OpenSearch regular expressions are anchored, and are not PCRE | Wildcards, or a custom rule |
| `fieldref` | A query cannot compare two fields | Custom rule |
| Keywords, a value with no field | No search-everything field exists | Name the field |
| Correlation rules | No exact query form | Custom rule |
| A field not in the table | It would match nothing | Add it to `ecs.py`, if it exists |
| A log source not in the table | Not collected | None |
| A wildcard on an IP field | `ip` fields have no text form | `cidr` modifier |
| Text on a numeric field | Not expressible | Compare the number |
| `null` or `exists` on `winlog.event_data` fields | Not proven on this field type | An ECS field, or custom |
| Timestamp modifiers | Not implemented | Custom rule |

Matching is case-insensitive, as Sigma specifies. The `cased` modifier makes it case-sensitive.

### Things to watch

| Point | Detail |
|---|---|
| `%` | Sysmon writes it as `%%`, so `%TEMP%` needs `%%TEMP%%` |
| Security 4688 | Holds no command line, by the owner's decision. Use Sysmon 1 |
| Security 4698 | This host does not produce it. Use Task Scheduler 106 |
| Sysmon 3 | Logged only for shells, script hosts, some tools and user-writable paths, plus admin ports. A connection by another program does not exist in the data |
| Text over 8,191 characters | Not indexed for matching, so a longer `CommandLine` cannot match |
| Events before 2026-10-31 13:35 IST | Lost `&`, `<` and `>` to a Vector defect, and age out by 2026-11-07 |
| ATT&CK names | The current data has `stealth` and `defense-impairment`, not `defense-evasion`. `validate --attack` checks them |

## Add a custom rule

Create `rules/custom/<name>.py`, with exactly one class:

```python
from siem_detector.alerts import get
from siem_detector.custom import CustomRule, Finding


class RareThing(CustomRule):
    id = 'a new UUID'
    title = 'What Happened'
    description = 'One sentence, fixed text. Never put event values here.'
    level = 'medium'
    tags = ('attack.execution', 'attack.t1059')
    lookback_seconds = 900                    # how far before the watermark to fetch
    fields = ('winlog.event_data.Something',) # fields beyond the standard context

    def query(self):
        return {'bool': {'filter': [{'term': {'event.code': '1'}}]}}

    def detect(self, events):
        return [Finding(key=e['_id'], events=[e], facts={'count': 1}) for e in events if self.interesting(e)]

    def interesting(self, event):
        return get(event['_source'], 'process.name') == 'x.exe'
```

| Rule | Requirement |
|---|---|
| `query` | A filter for candidates. Keep it narrow. The time range is added for you |
| `detect` | Takes events sorted by `@timestamp`. Must be deterministic, and hold no state |
| `Finding.key` | Must be the same on every run for the same detection. Build it from the first event's ID. Not the count, or the last event |
| `Finding.facts` | Numbers and booleans reach Kafka. Strings become digests |

A rule must not query, publish or read files. If `detect` raises an error, the run fails, the watermark stays, and the health report shows it.

The examples are `failed_logon_burst.py` for a sliding count, `password_spray.py` for a sliding distinct count, `logon_after_failures.py` for order, `encoded_command_content.py` for decoding, and `network_beacon.py` for timing.

For custom rules, fixtures are scenarios, each a list of events judged together.

## Change a rule

| Change | Where |
|---|---|
| Enable or disable | `enabled` in `rules/rules.yml` |
| Severity | `severity` in `rules/rules.yml`, or the rule's `level` |
| Confidence | `confidence` in `rules/rules.yml` |
| How often it runs | `interval_seconds`, 30 at least |
| Many events to one alert | `group_by` and `group_window_seconds`. Only fields that are safe for Kafka |

Changing a rule's logic does not reissue old alerts: IDs do not depend on the rule's text. To search again, use `rewind`.

## Validate and test

From the repository root, with no services running:

```text
export PYTHONPATH=<detector libraries>:detector SIEM_RULES=rules
python3 -m siem_detector validate
python3 -m siem_detector validate --attack
python3 -m siem_detector test
python3 -m siem_detector show <rule name>
cd tests/detection && python3 -m unittest test_sigma test_runner test_alerts test_rules
```

With OpenSearch up, `tests/detection/run_live_parity.py` proves that the rules behave the same on real OpenSearch as offline.

## Deploy

```text
bash deploy/wsl/install-detector.sh <wheel folder>
sudo systemctl restart siem-detector
sudo -u siem-detector siem-detector rewind <rule id> --hours 24
```

The installer compiles every rule, and stops if any is invalid. The running service keeps its old rules until it restarts. `rewind` is optional, and applies a new rule to recent history.
