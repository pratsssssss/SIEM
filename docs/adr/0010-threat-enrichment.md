# ADR-0010: Threat Enrichment

| Field | Value |
|---|---|
| **Status** | Implemented on 2026-10-31, under the owner's Phase 10 brief. Subject to owner review |
| **Decisions** | D28, D29, D30, and the D12 result |
| **Evidence** | Acceptance report, [sources](../detection/threat-intelligence.md) |

D8 stands, and this implements it: local lookups for events, and external intelligence at alert time. One difference: D8 placed local lookups in the aggregator. They run in the enrichment service instead, because VRL cannot read a large on-disk database, and placing them there would have put enrichment on the ingestion path, which the brief forbids. This does not change what D8 protects.

## D28: Enrichment is a separate service that nothing depends on

**Decision:** `siem-enricher` reads events and alerts from OpenSearch, and writes results to its own index family, `siem-enrichment-YYYY.MM`. It is linked to alerts by `alert_id` and to events by `event.id`. It has no Kafka client, and the detector has no reference to it.

**Why:** the brief requires that a failure cannot stop alert creation or delivery, and that original evidence stays unchanged. The surest way is for no path to exist. Enrichment does not modify events or alerts, and its role has no write access to them.

**Consequences:**

- Enrichment lags alerts by up to a minute or so.
- A later consumer joins alerts to enrichment by `alert_id`.
- No enrichment data is added to Kafka, so the D25 allowlist is unchanged.

## D29: The SIEM host makes outbound internet requests, for listed hosts only

**Decision:** this is new. Until now the stack was loopback only. The enrichment code may reach listed HTTPS hosts only: the feeds in configuration, and active providers. All outside access is in `web.py`.

**Why:** public feeds are how this can work with no paid service.

**Limits:** HTTPS only, listed hosts only, including on redirects, no credentials in URLs, a size cap, and timeouts. Inbound exposure is unchanged. The check is in the application, not the network. There is no firewall rule behind it, so compromised code could ignore it.

## D30: Enrichment results are kept for 90 days

Same as alert evidence (D26), and for the same reason. Results can hold sanitized URLs and domains found in restricted text. Credentials, queries and fragments are removed before storage.

## D12 result: synthetic intelligence is a named, temporary file

**Decision:** test intelligence lives in `data/enrichment/owner/synthetic-*.csv`, appears under that name in every result, and is purged after each test. This answers D12's labelling and isolation questions. Results from a test stay in the index, labelled, as evidence. D12 otherwise stays open on replaying sanitized public-IP samples, which is not needed now.

## Roadmap

The owner's brief makes this Phase 10. The earlier plan split it across Phase 12, local enrichment, and Phase 15, alert enrichment, with attack path validation as Phase 10. Attack path validation is now Phase 12, and Phase 15 is closed as done here.

## Not chosen

| Option | Why not |
|---|---|
| Enrich inside the aggregator | Puts enrichment on the ingestion path |
| Add fields to events or alerts | Changes evidence |
| Enrich inside the detector | An enrichment fault could then affect alerts |
| External lookups per event | Cannot fit free tiers (D8), and would send far more out |
| Kafka topic for results | Nothing consumes it yet, and it adds a surface |
| Active DNS, WHOIS | Exposes the investigation |
| Averaging provider scores | A clean answer from a source with no data would hide a finding |
| Trust a feed with a shrunken pull | A broken download would quietly empty a blocklist |

## Revisit when

- Provider keys are added: review the privacy table first.
- Correlation is built: it may want enrichment on an event stream.
- A network firewall is added in Phase 21: D29's limit should move there.

_Internal test reports and planning records mentioned here are not published with Version 1._
