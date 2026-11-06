# ADR-0011: Correlation And Incident Management

| Field | Value |
|---|---|
| **Status** | Implemented on 2026-10-31, under the owner's Phase 11 brief. Subject to owner review |
| **Decisions** | D31, D32, D33, D34, D35, and a refinement of D9 |
| **Evidence** | Acceptance report, [rules](../detection/correlation-rules.md), [operations](../detection/incident-management.md) |

D9 stands, with one refinement, recorded under D32.

## D31: Correlation is a separate service that nothing depends on

**Decision:** `siem-correlator` consumes Kafka `siem-alerts` and writes only its own index families. Detection and enrichment neither import it nor order themselves after it. Stopping it costs nothing but incidents, which it catches up on when it returns.

State lives in one SQLite file. An alert is stored before its Kafka offset is committed. An incident change, its audit entries and its outbox entry commit as one transaction. OpenSearch receives incidents from that outbox with external versions, so a retry can never put an older revision over a newer one.

**Why:** Kafka keeps alerts for 72 hours and OpenSearch may be away, so neither can be the record of work in progress. Writing an incident directly would need a two-phase commit, which this does not need.

**Cost:** a single-writer file, so this runs on one host. That matches the rest of the lab.

## D32: A rule names its link, and the link limits the claim

**Refinement of D9.** D9 groups alerts that share entities. It warned that broad correlation could merge unrelated activity. This lab has one Windows host and one everyday account, so a shared host alone would link everything.

**Decision:** each rule states one join: `lineage`, `user`, `indicator`, `source_ip`, `destination_ip`, `user_name` or `host`. Nothing else links alerts. A shared host or a shared bare name is called timing, and never causal. Weak identities, such as `SYSTEM` or a machine account, link nothing. A user with no domain or SID is held apart from a qualified user, and a rule may match it only through `user_name`, which records the doubt.

Scoring uses the **weakest** link in the incident. Running this on real alerts proved why. Using the strongest let one proven parent and child lend its strength to thirteen unrelated rules, and the incident then claimed all of them were joined by recorded lineage. That claim was false, and was removed.

The real test events showed a second case. The domain rule counted values on a host join, and it took every alert on that host as a member, so four unrelated activities became one incident. A member must now add a counted value.

Repeats of a rule, and different rules that fired on one event, count as one observation. Between hosts, timestamps within the skew allowance of 120 seconds do not prove which came first, and the incident says so. One host has one clock, so there only overlapping times leave the order in doubt.

## D33: Incidents go to two index families, kept 365 days

**Decision:** `siem-incidents-YYYY.MM` holds the current revision of each incident, and `siem-incident-audit-YYYY.MM` holds audit entries. Both are retained for 365 days. Source events (7 days) and alert evidence (90 days) expire first, so an old incident keeps its references, and its summary, after what they point to has gone.

**Not published to Kafka.** The `siem-incidents` topic stays unused. Nothing consumes it, and Phase 12 can read incidents from OpenSearch. If it needs a stream, that is one new consumer of the outbox.

**Limit:** OpenSearch cannot express "create, never update" as a permission, so the account can overwrite its own audit documents. The hash chain in SQLite detects a change to the local copy, and `_create` is what the service uses, but the account's rights do not prevent it.

## D34: Analysts connect through a local socket, and the kernel says who they are

**Decision:** the analyst interface is a Unix socket, mode 0660, group `siem-analyst`. The service reads the caller's identity with `SO_PEERCRED`, then checks the group in the system database. Anything the request says about identity is ignored. Root is refused, because an audit entry must name a person. There is no network listener.

**Why:** the brief forbids an unauthenticated interface, and a web interface would add login, sessions and TLS for one person. Peer credentials cannot be forged by a client.

**Limit:** anyone with root in WSL can read or alter the state file. The hash chain shows a careless change, but root can rebuild the chain. The real boundary is the Windows account, which is true of the whole SIEM host.

## D35: The server, not only the code, keeps sensitive text from this service

**Decision:** the `siem_correlator` role reads events through field level security, limited to identity fields. Command lines and script text are not visible to the account, so a fault in this service cannot leak them into an incident. Alerts have no such limit, because their fields vary by rule, so replay cuts each alert to the fields Kafka carries (D25) in code.

## Not chosen

- **A graph database.** Bounded windows over an indexed table answer every rule here, within 192 MiB.
- **Publishing to `siem-incidents`.** See D33.
- **A web interface.** See D34. Phase 12 or later can add one in front of this socket.
- **Automatic merging of incidents that share a host.** See D32.

## Revisit when

- A second Windows host arrives. Scenario 8 can then be tested on real telemetry, and the host join needs review.
- Alerts exceed about ten a second. One writer and synchronous commits are the limit.
- Several analysts work at once. Notes and status changes are serialized, but nobody is told that someone else is on an incident.

_Internal test reports and planning records mentioned here are not published with Version 1._
