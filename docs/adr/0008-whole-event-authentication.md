# ADR-0008: Whole-Event Authentication

| | |
|---|---|
| **ADR status** | **Approved by the owner on 2026-10-31** |
| **Date** | 2026-10-31 |
| **Decision** | D24 |
| **Depends on** | D22, D23 |
| **Evidence** | Phase 8 acceptance report |

## Context

D22 authenticated sealed fields only. A demonstration showed that a replayed sealed event with an altered unsealed field could overwrite a stored document after a verifier restart. The owner required every field to be authenticated, and replay protection that survives a restart.

## Decision

**The agent authenticates the whole event. The verifier checks that before reading anything in it.**

### Envelope

```json
{"v": "siem-event-v1", "k": "k1", "event_uid": "...", "body": "<canonical JSON>", "mac": "<base64>"}
```

| Item | Decision |
|---|---|
| `body` | The whole event after redaction and sealing. `encode_json` sorts keys, so it is canonical |
| MAC input | `siem-event-v1|<key ID>|<body>`, using the exact body bytes |
| Why exact bytes | The verifier never re-serializes, so there is nothing to disagree about |
| Label | Separates this MAC from field MACs, whose input is a JSON array |
| Key | The D22 MAC key |
| Field MACs | Kept. Both must pass before decryption |

The agent's `envelope` transform is the last step before the disk buffer, and the only input to the Kafka sink.

### Verification order

1. Size check in Vector, which parses nothing.
2. Exactly five string fields, known version and key, base64, 32-byte MAC.
3. `crypto/subtle.ConstantTimeCompare` over the envelope MAC.
4. Parse the body. Check schema, channel, IDs, event age and restricted fields.
5. Validate and verify every field MAC.
6. Decrypt.
7. Check identity against the journal.

Schema checks moved from Vector to the verifier, so nothing unauthenticated is parsed as an event.

### Identity and replay

| Case | Result |
|---|---|
| New event | Forwarded. Recorded only after Vector acknowledges |
| Identical redelivery | Acknowledged and **not forwarded**. The stored document is not touched |
| Agent re-read with a new IV | Same, because the hash covers the opened event |
| Same `event_uid`, different content | `replay_conflict` dead letter |
| Unsigned change | `mac_mismatch` dead letter |
| Older than 14 days | `stale_event` dead letter |

**Journal:** a fsynced daily file in `/home/linux/siem/data/verifier`, kept for 16 days and read at start. Each 36-byte record holds a hash of the identity, an HMAC of the opened event and a CRC, so it reveals no content. The service will not start without it.

**Why 14 and 16 days:** the journal outlives the oldest accepted event, so nothing old enough to be forgotten can be accepted again.

**Crash window:** an event delivered just before a crash, and not yet recorded, is delivered again. The document ID is the same, so this overwrites it with identical content.

## Security properties

| Attacker | Result |
|---|---|
| Local process on Kafka, no key | Cannot forge, alter or reorder content into an accepted event. **Can** fill Kafka with junk, delete nothing, and cause dead letters |
| Replay of a captured event | No effect |
| Key holder | Can forge new identities. Cannot change a stored identity through the pipeline |

**This does not add Kafka authentication.** Any local process can still write to or read from `siem-raw-logs`. Reading yields redacted, sealed events. That stays for Phase 21.

## Consequences

- `siem-raw-logs` holds envelopes, so consumers other than the verifier cannot read events as JSON without unwrapping them.
- Whole-event MAC adds about 44 bytes per event, and JSON escaping of the body adds size.
- D22's statement that unsealed events are forgeable no longer applies to anyone without the key.

## Revisit when

- Kafka gains authentication in Phase 21.
- A second agent is added, because a shared key would let one host forge another's events. Each host would need its own key.

_Internal test reports and planning records mentioned here are not published with Version 1._
