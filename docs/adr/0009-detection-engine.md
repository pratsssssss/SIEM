# ADR-0009: Detection Engine Decisions

| Field | Value |
|---|---|
| **Status** | Implemented on 2026-10-31, under the owner's Phase 9 brief. Subject to owner review |
| **Decisions** | D6 result, D25, D26, D27 |
| **Evidence** | D6 results, acceptance report |

D5 and D7 stand unchanged, and this builds on them.

## D6 result: Query DSL, written by a project backend

**Decision:** convert Sigma rules to OpenSearch Query DSL with a small backend built on pySigma. Correlations, which Sigma states as correlation rules, are custom Python rules.

**Why:** this is D6's decision rule 4, and only this option passed gate G1.

| Option | Rules correct on real OpenSearch, of 17 |
|---|---|
| Project DSL backend | **17** |
| Released Lucene, `pysigma-backend-opensearch` 2.0.3 | 8 |
| Released PPL, same package | 7 |

The cause is structural. Sigma matching is case-insensitive, and a Lucene string on a keyword field is not. The same search on real data returned 16 documents as a Lucene string, and 3,291 with `case_insensitive`. A rule would silently miss most of its matches, which the owner's brief forbids. PPL cannot see `.keyword` subfields or `flat_object` fields.

**Trade-off:** 200 lines of backend to maintain, and it refuses more than a released backend does. A refused rule is visible, and a wrong rule is not.

**pySigma is still the parser and validator.** Only the output stage is project code.

## D25: Alert evidence lives in OpenSearch, and Kafka gets an allowlisted form

**Decision:** full alerts go to a new index family, `siem-alerts-YYYY.MM`. The `siem-alerts` topic gets the same alert, with every field outside an allowlist replaced by a digest.

**Why:** the brief asks for evidence in alerts and for alerts on Kafka. Kafka has no authentication, and D22 requires that restricted fields never reach it in plaintext. Phase 8 verified this across 109,728 envelopes. Copying command lines to `siem-alerts` would have undone that.

**Consequences:**

- Investigating an alert needs OpenSearch, through `evidence_ref`. Kafka alone gives the rule, host, user, times, process names and digests.
- A new field is withheld by default.
- Phase 10 and later consumers must not expect restricted values on the topic.
- Any later consumer must read evidence from OpenSearch, and D22 must be reviewed before any text leaves the host.

## D26: Alert evidence is kept for 90 days

**Decision:** a new ISM policy deletes `siem-alerts-*` at 90 days. Events stay at 7.

**Why:** evidence must outlive the events it cites. D6's evidence design already expects this: "ISM can delete referenced documents, so alerts keep the key field values".

**Consequence:** restricted text can now live 90 days, not 7, but only the fields of events that matched a rule, redacted as before, and capped at 2,000 characters. At the measured rate this is well under 1 MB a month. This extends D22's exposure, so **the owner should confirm it**. Changing it needs only a new policy.

## D27: A separate account and service for detection

**Decision:** `siem_detector` searches `siem-windows-*`, writes `siem-alerts-*`, and does nothing else. It runs as the `siem-detector` system service, with no capabilities, and up to 256 MiB.

**Why:** the detector reads restricted text, so it must not share the admin account. It has to write somewhere, and its write access stops at its own index.

**Trade-off:** `siem_detector` can read every event. That is its job.

## Roadmap

The owner's brief makes the detection engine Phase 9. The earlier plan had it as Phase 13, with WSL2 Linux sources as Phase 9. The two swapped places, and nothing was dropped.

## Not chosen

| Option | Why not |
|---|---|
| Released Lucene backend | Fails G1, on case |
| PPL | Fails G1 |
| OpenSearch Security Analytics | Excluded by D7 |
| Restricted text in Kafka | Breaks D22 |
| Read `process.command_line` | Analyzed text cannot match a substring exactly, so `.keyword` is used |
| In-memory duplicate cache | A restart would repeat alerts |

## Revisit when

- Kafka gains authentication (Phase 21): the allowlist can widen.
- OpenSearch gains a keyword subfield for script text: `winlog.event_data` stops being needed.
- Volume grows: 90 days of evidence may need a size limit.

_Internal test reports and planning records mentioned here are not published with Version 1._
