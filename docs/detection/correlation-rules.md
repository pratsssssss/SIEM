# Correlation Rules

Rules live in `rules/correlation/rules.yml`, and install to `/home/linux/siem/config/correlator/rules.yml`. A bad file stops the service at start, and says which rule is wrong. Decisions are in [ADR-0011](../adr/0011-correlation-and-incidents.md).

## The ten rules

| Scenario | Rule | Kind | Join | Window | What it needs |
|---|---|---|---|---|---|
| 1 | `cor-logon-after-burst` | sequence | user name | 30 min | Failed logon burst, then a success after failures |
| 2 | `cor-password-spray` | single | source IP | 30 min | Spray detection covering at least 4 accounts |
| 3 | `cor-powershell-child` | sequence | lineage | 60 min | Encoded PowerShell alert, then an alert on a process it started |
| 4 | `cor-service-then-process` | sequence | host | 30 min | New service, then a flagged process started by `services.exe` |
| 5 | `cor-task-then-process` | sequence | host | 30 min | Task registered, then a flagged process from the task service |
| 6 | `cor-same-indicator` | threshold | indicator | 24 h | Two alerts with one hostile indicator |
| 7 | `cor-host-many-domains` | distinct | host | 60 min | Two hostile domains in intelligence matches on one host |
| 8 | `cor-user-many-hosts` | distinct | user | 2 h | One qualified account flagged on two hosts |
| 9 | `cor-privilege-then-admin` | sequence | user | 60 min | Group or UAC alert, then a persistent change by that account |
| 10 | `cor-multi-stage` | chain | user | 2 h | Three ATT&CK tactics from three rules on different events |

## Kinds

- **sequence:** each stage in order. The nearest earlier first stage is paired, and the alert being evaluated joins whichever stage it fits.
- **threshold:** at least `min_alerts` selected alerts on one entity.
- **distinct:** at least `min_count` different values of `count` on one entity.
- **chain:** at least `min_tactics` tactics, from as many rules, on different events.
- **single:** one alert is enough, because the detection already counted what matters.

## Joins

| Join | Meaning | Strength |
|---|---|---|
| `lineage` | Sysmon recorded the parent and child | Proof |
| `user` | One account, by SID or domain and name | Shared identity |
| `indicator` | One indicator with a hostile verdict | Shared identity |
| `source_ip`, `destination_ip` | One address | Shared identity |
| `user_name` | The same bare name, which may be two accounts | Timing, and the doubt is recorded |
| `host` | One machine | Timing only |

## What is deliberately not linked

- **Script block alerts in a lineage chain.** Event 4104 carries no process identity, so scenario 3 starts at encoded command alerts.
- **A service or task to the process it starts.** Windows records no link. Scenarios 4 and 5 require the right parent process and say they are associations. A wrong parent is not matched.
- **Weak identities.** `SYSTEM`, service accounts and machine accounts link nothing. Loopback addresses are weak too, but the spray rule still reports on one, because it joins no other alert. The confidence stays low.
- **Accounts with one name on different hosts.** A local `admin` on one host is a different account from `admin` on another.

## Changing a rule

1. Edit `rules/correlation/rules.yml`, and name alert rules by their Phase 9 IDs.
2. Add a positive and a negative case to `tests/correlation/test_scenarios.py`.
3. Run the unit suites, then `deploy/wsl/install-correlator.sh`, then restart the service.

A rule is switched off without an edit by `siem-incident rule-disable <id>`. That is audited, and survives a restart.

## Scoring

**Severity** starts at the highest alert severity. It rises one step for three independent rules, or a malicious indicator, and one step only, and never with a link no stronger than a host or a bare name. Severities are never added.

**Confidence** is out of 95:

| Item | Points |
|---|---|
| Weakest link: lineage / identity / host or name | 45 / 30 / 15 |
| Part of the incident has a stronger link | +5 |
| Each independent rule after the first, to 20 | +10 |
| A malicious indicator | +15 |
| Intelligence conflicts | −15 |
| Some source events are gone | −10 |
| The order is not proven | −10 |
| Identity is uncertain | −10 |
| Enrichment is incomplete | −5 |

Bands: 70 and above is high, 40 and above is medium, and below that is low. Each incident lists these reasons in `explanation`.
