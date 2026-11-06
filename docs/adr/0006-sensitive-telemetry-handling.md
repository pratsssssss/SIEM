# ADR-0006: Sensitive Telemetry Handling

| | |
|---|---|
| **ADR status** | **Approved by the owner on 2026-10-31**, with the additions below |
| **Date** | 2026-10-31 |
| **Decision** | D22 |
| **Depends on** | D4, D17, D20 |
| **Evidence** | Phase 8 architecture and security review |

## Context

Sysmon 1 and PowerShell 4104 can hold passwords in clear text. Phase 7 restricted those channels so that non-admin processes cannot read them. Kafka has no authentication until Phase 21, so any local process can read `siem-raw-logs`. Vector's disk buffer would hold a second copy on `C:`.

Dropping these events would remove the main evidence for command-line and script detection, so that is not acceptable.

## Decision

**Protect restricted fields on the agent, before the disk buffer. The pipeline must not widen who can read them.**

### Restricted fields

| Channel | Event | Fields |
|---|---|---|
| Sysmon | 1 | `CommandLine`, `ParentCommandLine` |
| Sysmon | 13 | `Details` |
| Sysmon | 20 | `Destination` |
| PowerShell | 4104 | `ScriptBlockText` |
| PowerShell | 4100 | `ContextInfo`, `Payload`, `UserData` |
| Security | 4688 | `CommandLine`, empty by policy, kept as a guard |
| Security | 4697 | `ServiceFileName` |
| System | 7045 | `ImagePath` |

If `string_inserts` ever appears on the Sysmon or PowerShell channels, it is sealed too.

### Agent steps

1. Assign `event_uid`, as designed.
2. Remove `message`, and remove `xml` except on Security 1102 and System 104.
3. **Redact** each restricted field with the shared rules. A match keeps the argument name, for example `--password=[REDACTED:arg]`, and records the rule in `labels.redactions`.
4. Cap each field at 128 KiB. A longer value keeps its start, and sets `labels.truncated`, with the original length recorded.
5. **Seal** each field: AES-256-CTR, in the standard big-endian form, with a random 16-byte IV, then HMAC-SHA-256 over a version label, key ID, `event_uid`, channel, event ID, record ID, field name, IV and ciphertext. Store them in `.sealed.<field>` with key ID `k1`, and delete the plaintext.
6. **Fail closed:** if a step fails, the event ships with the restricted field removed and `labels.seal_failed: true`. Plaintext is never forwarded.

### Aggregator steps

1. Verify the MAC first, and decrypt only if it matches.
2. On failure, write the event to dead-letter, still sealed.
3. Send an event to dead-letter if its channel and ID require sealing and it has no `sealed` field or `seal_failed` label.
4. Normalize and write to OpenSearch. Sealed values are not stored in the main index.

### Algorithm

Authenticated ciphers (`CHACHA20-POLY1305`, `XCHACHA20-POLY1305`) are rejected. In Vector 0.61.0 their `decrypt` **panics the process** on a wrong key or bad data, which VRL cannot catch, and Kafka accepts input from anyone. AES-256-CTR does not panic, and the MAC is checked before it runs.

### Keys

| Item | Decision |
|---|---|
| Keys | Two 256-bit keys, one for encryption and one for the MAC, derived separately with HKDF-SHA-256 from 32 random bytes |
| Windows | `C:\ProgramData\Vector\secrets\field-keys.json`, readable only by `SYSTEM` and Administrators |
| WSL2 | `/home/linux/siem/config/verifier/field-keys.json`, `root:siem-verifier`, 640. Changed by D23, so Vector no longer holds keys |
| Delivery | Read through Vector's `file` secret backend. Never on a command line, in the repository, or in logs |
| Rotation | New key ID on the agent. The aggregator keeps the old key until Kafka retention and the agent buffer have passed |
| Backups | WSL exports then contain the key, and are already treated as sensitive |
| Loss | Retained Kafka events go to dead-letter. The Windows logs remain the source |

Windows and the aggregator hold the same key. That is acceptable, because anyone able to read the Windows key can already read the event logs.

### Access to other stores

- Agent data folder: `SYSTEM` and Administrators only, because it holds the disk buffer and checkpoints.
- OpenSearch: a dedicated `siem_ingest` user that can only write to `siem-*` indices. Its password is held the same way as the keys, on the aggregator.
- Any later stage that sends data off the host must mask it first, because OpenSearch holds redacted plaintext.

## Additions at approval

- Verification order: strict validation of shape and length, then the MAC, then decryption.
- HMAC verification must be constant-time. VRL has no constant-time compare, so double HMAC was tried and rejected by the owner. [D23](0007-seal-verifier.md) moves verification and decryption to a Go service using `crypto/subtle.ConstantTimeCompare`. Not yet deployed.
- Top-level fields are checked against an allowlist.
- Dead-letter records hold ciphertext and routing facts only, never `event_data` or the raw message.
- **D22 does not authenticate Kafka events.** Events with no protected fields stay forgeable until Kafka has authentication and authorization. [D24](0008-whole-event-authentication.md) later added whole-event authentication, so this now applies only to a holder of the key.
- Key procedures are in [Vector agent deployment](../operations/vector-agent-deployment.md#field-keys).

## Options considered

| Option | Result |
|---|---|
| Ship in the clear, relying on loopback | **Rejected.** Undoes the Phase 7 channel restriction |
| Exclude Sysmon 1 and 4104 | **Rejected.** Loses core detection |
| Truncate with Sysmon `FieldSizes` | **Rejected.** Destroys evidence, and still leaks the kept part |
| Redact only | **Rejected.** Unknown formats would be readable in Kafka |
| Seal only | **Rejected.** A secret would reach OpenSearch whenever a pattern could have stopped it |
| Hash the fields | **Rejected.** Detection needs the text, and short values can be guessed |
| Redact on the aggregator | **Rejected.** Secrets would already be in the buffer and Kafka |
| Enable Kafka authentication now | Not proposed. It belongs to Phase 21, changes approved scope, and does not protect the disk buffer |
| **Redact and seal on the agent** | **Proposed** |

## Consequences

- `siem-raw-logs` holds redacted, sealed events, so "raw" no longer means byte-identical to the source. Replay works only while the key is held, and cannot recover redacted values.
- Sealed fields add about 33% and no longer compress.
- The agent runs more VRL. It measured 12,963 events per second at 11.6 KB, on synthetic text.
- Redaction rules become security-critical code, with tests in the repository. Adding a rule changes only new events.
- Forgery of unsealed events and Kafka tampering remain open until Phase 21.

## Revisit when

- Kafka gains authentication and encryption.
- Vector fixes the panic, which would allow an authenticated cipher.
- A real secret is found in OpenSearch, which means the rules need review.

_Internal test reports and planning records mentioned here are not published with Version 1._
