# ADR-0007: Seal Verifier

| | |
|---|---|
| **ADR status** | **Approved by the owner on 2026-10-31.** Deployed |
| **Date** | 2026-10-31 |
| **Decision** | D23 |
| **Depends on** | D22 |
| **Evidence** | Stage 8.4 pre-review, corrections record |

## Context

D22 requires constant-time MAC verification. VRL's `!=` is an ordinary byte comparison, and double HMAC does not change that. The owner rejected double HMAC as a substitute and chose a small Go service.

## Decision

**A separate process does all MAC verification and decryption, using only the Go standard library. The Vector aggregator holds no field keys.**

```text
Kafka -> Vector ingest (size only) -> seal verifier -> Vector normalize -> OpenSearch
```

[D24](0008-whole-event-authentication.md) later moved all schema checks into the verifier, after authentication.

| Item | Decision |
|---|---|
| Final comparison | `crypto/subtle.ConstantTimeCompare`, on two 32-byte values, in one place only |
| Order | Validate every field, authenticate every field, then decrypt |
| Decryption | `crypto/aes` and `crypto/cipher` standard CTR |
| Transport | Mutual TLS on loopback, in both directions, with separate CAs |
| Keys | Read at start from a file refused if other users can access it |
| Failures | Dead-letter record, with ciphertext and routing facts only |
| Outage | 503, so Vector retries and the Kafka offset stays uncommitted |
| Refused document | Split the batch, dead-letter that event as `index_rejected`, and continue. Hold if the dead-letter write also fails, or above 20 refusals a minute |

The approved architecture is otherwise unchanged: no Docker, no second Kafka topic, and the aggregator still writes directly to OpenSearch.

## Audit coverage

**This is not a fully audited path, and must not be described as one.** The Trail of Bits review of Go's cryptography, March 2025, reported one low and five informational issues. Its manual review list includes `crypto/aes`, `crypto/cipher`, `crypto/hmac`, `crypto/rand` and `crypto/sha256`. **`crypto/subtle`, which holds the final comparison, is not on that list.** Go 1.27.3 is later than the audited code.

## Agent change

The agent moves from VRL's `AES-256-CTR` to `AES-256-CTR-BE`. The former is a deprecated little-endian 64-bit counter, which standard CTR cannot read: Go decrypted the first 16 bytes correctly and the rest as garbage. This is still AES-256-CTR with a unique IV, as D22 requires. The agent's counter wraps at 2^64 in the IV's low half and Go's carries, so a field crossing that point dead-letters as `counter_wrap`, with odds near 2^-50 per field.

## Bypass

- `from_verifier` is the only input to the routed output.
- It requires a client certificate from the verifier's CA. Vector's own certificate is refused, because the two directions use different CAs.
- `verifier-pki` keeps CA keys in memory only, so no further certificate can be issued.
- The verifier rejects any client whose certificate name is not `siem-vector`.

A process running as root, or as either service account, can defeat this. It is a boundary against other local users and processes.

## Replay

**Superseded by [D24](0008-whole-event-authentication.md), which replaced the in-memory cache with a durable journal.** The text below records the original design.

Kafka delivers at least once, so a repeat cannot simply be refused. The verifier hashed the opened event, and held 200,000 identities in memory:

| Case | Result |
|---|---|
| Same identity, same content | Forwarded and counted. `_id` makes it an overwrite with identical data |
| The agent re-reads an event, with a new IV | Same as above, because the hash covers plaintext |
| Same identity, different content | **Dead-lettered as `replay_conflict`** |

**Limits:** the cache is lost on restart and is bounded, so an old identity can be replayed once it has been evicted. The first version seen wins. The MAC does not cover unsealed fields. **This overwrite was demonstrated after a restart.** Implications and options are in the blocker review, and await an owner decision.

## TLS 1.2

Vector 0.61.0's TLS listener does not negotiate 1.3. The hop from the verifier to Vector uses TLS 1.2, limited to `ECDHE-ECDSA` with AES-256-GCM or ChaCha20-Poly1305, with mutual authentication. Vector to the verifier uses 1.3. Revisit when Vector's listener supports 1.3.

## Consequences

- One more service to run, patch and monitor, with `Go` as a build dependency.
- Plaintext crosses loopback inside mutual TLS between the verifier and Vector.
- The verifier is a dependency of ingestion. Stopping it stops delivery, with no loss.
- `siem-raw-logs` format is otherwise unchanged.

## Revisit when

- VRL gains a constant-time compare, or `decrypt` stops panicking on AEAD failures.
- Vector's listener supports TLS 1.3.
- Kafka gains authentication in Phase 21.

_Internal test reports and planning records mentioned here are not published with Version 1._
