# Lock Server Mapping to the GovOps TRACE Collector API

This document maps Janssen Lock Server to the vendor-neutral [GovOps TRACE Collector API](govops-trace-collector-api.md) (the "standard"). It records where the existing designs conflict, which Lock behavior already conforms, and what Lock must change. The standard itself does not mention Lock.

Section references of the form `§n` without a document name refer to the standard. `MVP` means `Lock-Server-TRACE-MVP-Design.md`; `design.md`, `jans-trace-core` (`jans-trace-core-mvp-design.md`), and `govops-trace-profile.md` are the repository documents of those names.

## 1. Sources and what is implemented

| Source | What it establishes |
|---|---|
| `research/lock-code.txt` (Lock source dump) | **Implemented:** `POST /api/v1/audit/{health,log,telemetry}` and their `/bulk` variants. Scopes `https://jans.io/oauth/lock/{health,log,telemetry}.write`. Bulk endpoints return `200`. Errors use `LockApiError {code, message, description}`. Discovery at `/.well-known/lock-server-configuration` returns `version`, `issuer`, `audit.{health,log,telemetry}_endpoint`, and `config.{policy,sse}_endpoint`. **No TRACE endpoint exists in the code dump.** |
| `Lock-Server-TRACE-MVP-Design.md`, `design.md` | **Designed, not implemented:** `POST /api/v1/audit/trace`, `POST /api/v1/audit/trace/bulk`, scope `https://jans.io/oauth/lock/trace.write`, retrieval endpoints, error handling, idempotency, producer keys, receipt chain. |
| `jans-trace-core-mvp-design.md` | Strict JSON, JCS, Ed25519, `content_digest`, receipt hash, and a library error-code set. |
| `govops-trace-profile.md` | The vendor-neutral record profile (`tag:govops.owasp.org,2026:trace-v1`). |
| `research/lock-server-design-context.txt` | Known tension points, including the receipt-commit protocol forced by `jans-orm`. |

"Status" below refers to the designed behavior unless it says "implemented".

## 2. Inconsistencies found in the existing designs

| # | Topic | What the documents say | Resolution in the standard |
|---|---|---|---|
| 1 | Profile identifier | MVP §7 fixes `tag:jans.io,2026:trace-v1`. `govops-trace-profile.md` §2 fixes `tag:govops.owasp.org,2026:trace-v1`. The context notes record a third spelling (`govops`) in the upstream working-group dump. | `trace_profiles` lists every accepted tag. Lock lists both of its tags while it migrates. The standard's vectors use the GovOps tag. |
| 2 | Discovery document | Lock serves `/.well-known/lock-server-configuration`. The Cedarling documentation cites `.well-known/lock-master-configuration`. Neither describes TRACE endpoints. | New `/.well-known/govops-trace-configuration` (§11). Producers such as Cedarling use it for `CEDARLING_TRACE_ENDPOINT` discovery. |
| 3 | Ingestion scope name | MVP §11 hardcodes `https://jans.io/oauth/lock/trace.write`. | The standard requires publishing `ingestion_scope` (§4.3). Lock publishes its URI. |
| 4 | Bulk status code | MVP §11.2: `207` "or `200` per a consistently-chosen contract". Implemented Lock bulk endpoints return `200`. | `200` whenever the envelope was processed; per-record results carry the outcome. `207` is not used, which also matches the implemented bulk endpoints (§8.3). |
| 4a | Acceptance status | MVP §11.1 and `design.md` Component 1 return `202 Accepted` after verification and persistence. `202` conventionally means processing is incomplete. | `201 Created` for first durable acceptance, `200 OK` for an idempotent replay (§6.2). `202` is not used. |
| 5 | Storage failure | MVP §11.1 and §12: `500`, or `503` if the deployment exposes a retryable condition, "chosen consistently". `design.md` uses `500` for a storage outage and `503` for ledger divergence. | `503 COLLECTOR_UNAVAILABLE` for a retryable outage, `503 COLLECTOR_INTEGRITY_HOLD` for the integrity hold, `500 INTERNAL_ERROR` for the unexpected (§10.2). |
| 6 | Oversize input | `design.md` Operational Limits: oversize body `400`. MVP §14: oversize batch `400`. | `413` for bytes, `400` for counts and array limits (§5.8, §10.2). |
| 7 | Rejected vs quarantined records | MVP §12: "Reject or quarantine; do not index". `design.md`: `400`, or quarantine per configuration. It is not stated what the client sees when a record is quarantined. | Quarantine is internal. The response is always a rejection with no receipt (§7.1 rule 1). |
| 8 | Missing execution context | MVP §7.1 and §12: reject. `design.md` Error Handling: `202` with `unattributed_flag`. | Profile choice, published as `execution_correlation_required` (§7.5). Lock MVP: `true`. |
| 9 | Error body | Implemented Lock: `LockApiError {code, message, description}`. MVP §11.2 bulk example: `error: {code, message}`. | RFC 9457 Problem Details with `code` and `retryable` (§10.1). |
| 10 | Receipt contents | MVP §11.1 response has `receipt_sequence` but no `received_at`, although `received_at` is a hashed receipt member (MVP §9). `design.md` Component 1 puts `current_settlement` in the `202`, but the MVP has no settlement. | `receipt_id` and `received_at` are REQUIRED. `receipt_sequence` and settlement data are optional extensions (§6.3). |
| 11 | Meaning of flags on replay | MVP §8: `coverage_gap_flag` clears itself when the predecessor arrives. MVP §12: replay returns "the original acceptance result". It is unclear whether replay shows the original or the current flags. | Flags are as of original acceptance and identical on replay (§7.4, §9). Current state is a retrieval concern. |
| 12 | Order of replay and verification | MVP §5 verifies the signature (step 5) before idempotency (step 7). MVP §6 and §10 say later revocation never rewrites recorded results. Following the §5 order, a replay after revocation would fail. | Replay is detected before key-validity checks (§4.6 step 10, §9 item 3). |
| 13 | Atomic record and receipt | MVP §5 step 8, §9, §12 and acceptance criterion 12 assume atomic record plus receipt. The implementation must use a `PENDING/COMMITTED/VOID` protocol because `jans-orm` has no multi-entry transaction. | The standard requires only durable commit before acknowledgement and no visible partial state (§7.2). A `COMMITTED`-before-acknowledge rule satisfies it. |
| 14 | `record_id` form | MVP §7.1: "UUID or ULID". Examples in MVP §7 (`R-token-issued-001`) and the GovOps examples are neither. No case rule, so one UUID could appear under two identities. | Canonical lowercase UUID or uppercase ULID, exact string comparison (§5.6). |
| 15 | Batch producer uniformity | MVP §11.2: one producer per batch, mixed batches rejected. Aggregating intermediaries (OpenTelemetry Collector, Kafka adapters) carry many producers. | One producer per batch remains the default. `bulk_mixed_producers_supported` is an advertised capability (§8.1). |
| 16 | Unknown/unauthorized producer | `design.md`: `400` "unresolvable producer". The MVP distinguishes unknown key, wrong producer, wrong event kind (`producer_authorized_for_claim`). | Distinct codes `KEY_UNKNOWN`, `KEY_NOT_VALID`, `EVENT_KIND_NOT_AUTHORIZED`, with permitted collapse for registry privacy (§10.2). |
| 17 | Submitter vs producer permission | MVP §4.2 allows a forwarding client only by configuration, but the processing order (§5) never places that check before key lookup. | Explicit step 7 and `403 SUBMITTER_NOT_AUTHORIZED` (§4.5, §4.6). |
| 18 | Retrieval ambiguity status | `design.md`: `300`, or `409` when `Accept` demands one body. | Retrieval is out of scope for the standard. Note for a future retrieval specification. |
| 19 | Receipt-chain details | The receipt profile differs between documents (seven members in the MVP, an extra `receipt_profile` in the GovOps profile and `jans-trace-core`). | Not standardized. The receipt chain is a Collector-internal detail (§1.2). |
| 20 | Where the cryptographic suite lives | MVP §6 and `jans-trace-core` §6 fix Ed25519, JCS and SHA-256 for Lock, and defer algorithm agility. `govops-trace-profile.md` §1 fixes Ed25519 for the GovOps MVP. The suite is therefore specified in three places and tied to Lock. | The standard defers all of it to the record profile and advertises it per profile (§5.3, §11.2.1). A future profile (for example hardware-backed ECDSA) needs no new API version. |
| 21 | Chain admission, integrity and completeness | MVP §8 lets an already-registered key open a chain by submitting its first record (first sight) and treats pre-registration as a stronger option, but says nothing about a Collector that requires registration. `design.md` Component 3 offers pre-registration and first-sight anchoring and calls the resulting kind `genesis_kind`, a classification. The same document also says a genesis for an "unregistered, unanchored" chain "does not confer chain-start status", which conflicts with first-sight anchoring. For a sentinel on a non-genesis record, the Authenticated Chain Genesis text says both "rejected" and "fails `predecessor_linked`" (a flagged break). MVP §8 and §12 accept and flag gaps and link failures. | Three separate concerns (§7.4). Admission is the only chain-related rejection, decided by the registration modes: first-sight anchoring admits an unregistered chain, a pre-registered-only Collector rejects it with `CHAIN_NOT_REGISTERED`. Integrity and completeness findings are flags and never rejections. A sentinel on a non-genesis position is flagged as `chain_link_failure_flag`. |

## 3. Mapping by section

Status values: **Conforms** (design already satisfies the requirement), **Change** (design must change), **Add** (new capability), **Verify** (cannot be determined from the repository).

| Standard | Requirement | Lock | Status | Required change |
|---|---|---|---|---|
| §3 | `POST /api/v1/audit/trace`, `POST /api/v1/audit/trace/bulk` | Same paths in MVP §11. Not implemented. | Conforms (design) | Implement. |
| §3, §11 | `GET /.well-known/govops-trace-configuration` | Only `lock-server-configuration` exists. | Add | New servlet beside `LockServerConfigurationService`; do not remove the existing one. |
| §4.1 | TLS 1.2+, no cleartext, no redirect | Deployment configuration. | Verify | Confirm the existing endpoints and any proxy refuse cleartext. |
| §4.2 | Token validation, `401` | Existing `AuthorizationProcessingFilter` and `CedarlingAuthorizationProcessingFilter`. | Conforms (implemented for audit endpoints) | Return Problem Details for TRACE endpoints. Verify sender-constrained token support. |
| §4.3 | One ingestion scope, published | `trace.write`, separate `trace.readonly` and `trace.producers.manage`. | Conforms | Publish as `ingestion_scope`. Add the Cedarling policy-store entries `lock_audit_trace_write` and `lock_audit_trace_bulk_write`, following `lock_audit_*_write`. |
| §4.4 | Domain from authenticated client; unbound rejected; body domain ignored | `design.md` Component 1 and Evidence Domain and Isolation. | Conforms (design) | Define the status for an unbound client: `403 EVIDENCE_DOMAIN_NOT_BOUND`. |
| §4.5 | Submitter-to-producer permission before key lookup | MVP §4.2 (forwarding by configuration). | Change | Add the explicit check as step 7. Confirm the configuration can bind a client to a producer set. |
| §4.6 | Processing order | MVP §5 differs (inconsistency 12). | Change | Reorder: replay detection after structural checks and before key-validity checks. Conflict only after signature verification. |
| §5.1 | JSON only; optional gzip | JSON. Gzip unspecified. | Conforms | Gzip is optional. If enabled, enforce decoded-size limits during decompression. |
| §5.2 | Strict JSON | `jans-trace-core` §6.2 rejects duplicate members, bad UTF-8, trailing data, non-objects. | Conforms | Map library codes (section 4 below). |
| §5.3 to §5.5 | Algorithms, signature input, canonicalization and digest come from the profile; no independent negotiation | `jans-trace-core` §6 implements Ed25519, JCS, SHA-256 and fixes them, with no algorithm agility. | Conforms for the current profiles | None now. To support another profile, add a per-profile suite selection keyed by `trace.eat_profile` in `jans-trace-core`, and never select the algorithm from request data. |
| §5.6 | Canonical `record_id` forms | MVP §7.1 says UUID or ULID only. | Change | Enforce lowercase UUID / uppercase ULID. Fix non-conforming examples in MVP §7 and `govops-trace-profile.md`. |
| §5.7 | Preserve assertion and raw bytes | `design.md` Component 1. | Conforms | None. |
| §5.8 | Published limits, minimums, `413` | `design.md` Operational Limits: 256 KiB, arrays; batch limits unspecified. | Change | Fix defaults (record 262,144 bytes; batch bytes; batch records; depth). Return `413` for byte limits. Lock's API limit must not exceed the `jans-trace-core` limit. |
| §6.2 | `201` for first durable acceptance, `200` for replay | MVP §11.1 and `design.md` Component 1 return `202` for both. | Change | Return `201` on first acceptance and `200` on replay; distinguish them with `idempotent_replay`. Acknowledge only after the durable commit (see §7.2 row). |
| §6.3 | Receipt contents | MVP §11.1 lacks `received_at` and `receipt_id`. | Change | Add `received_at` (already stored, MVP §9). Add `receipt_id` (decimal string of `receipt_sequence`). Keep `receipt_sequence` as an extension. Exclude `current_settlement` from the MVP. |
| §7.2 | Durable commit before acknowledgement | `PENDING/COMMITTED/VOID` receipt protocol (context notes). | Verify | Prove that a record is acknowledged only after `COMMITTED`, that `PENDING` and `VOID` entries are invisible to retrieval and replay, and that tests C-23 and C-33 pass. |
| §7.4 | Admission, integrity, completeness | MVP §8, §10, §12. | Conforms with clarifications | Snapshot the flags at acceptance and return the snapshot on replay (inconsistency 11). Separate the three concerns in MVP §8. |
| §7.4.1 | Admission by registration mode | MVP §8: a registered key opens a chain at first sight (`first_observed_genesis`); pre-registration is optional and stronger. `design.md` Component 3 supports both mechanisms. | Conforms | Lock is variant M3 (both modes): unregistered chains are admitted, registered chains are classified as pre-registered. State in MVP §8 that Lock admits unregistered chains from an authorized key. A registered-only policy (and `CHAIN_NOT_REGISTERED`) is not required of Lock. |
| §7.4.1 | `chain_admission` in the receipt | `genesis_kind` is Lock-assigned and stored (`design.md` Authenticated Chain Genesis). | Add | Return `genesis_kind` as `chain_admission`. For a first-observed chain whose genesis has not arrived, return `first_observed_genesis`. |
| §7.4.2 | Sentinel on a non-genesis position, or a non-sentinel at position 1 | `design.md` (Record structure table) says the record is "rejected"; the Authenticated Chain Genesis bullets say it "fails `predecessor_linked`". | Change | Accept and set `chain_link_failure_flag` regardless of whether a predecessor is held. Fix the "rejected" wording in `design.md`. |
| §7.4.3 | Missing predecessor | MVP §8: accept, `coverage_gap_flag`. `design.md`: coverage gap at an unanchored origin. | Conforms | None. |
| §7.5 | Correlation context | MVP rejects missing context. | Conforms (MVP) | Publish `execution_correlation_required: true`. The full design later sets `false` and adds `unattributed_flag`. |
| §8.1 | Array body, one producer per batch | MVP §11.2. | Conforms | Return `BATCH_MIXED_PRODUCERS`. Publish `bulk_mixed_producers_supported: false`. |
| §8.2 | Independent per-record processing, array-order identity decisions | MVP §11.2. | Conforms | Add the in-array duplicate rule `[R, R']`. |
| §8.3 | `200` and `results[]` with `index`, Problem `error` | MVP §11.2 leaves `207` vs `200` open and uses `error: {code, message}`. | Change | Fix `200`; add `index`; use Problem Details. |
| §9 | Idempotency, conflict, atomicity | MVP §12, `design.md` Error Handling. | Conforms | Add the concurrency tests C-27. Make replay return the original receipt including `received_at`. |
| §10 | Problem Details, code table | `LockApiError`. | Change | Use RFC 9457 on TRACE endpoints. Existing `/audit/{log,health,telemetry}` endpoints keep `LockApiError`. |
| §11 | Metadata members | New. | Add | Source each member from configuration (section 5). |
| §12.1 FW-* | Forwarder rules | Not a Lock component. | n/a | Applies to forwarders deployed with Lock. |
| §12.2 CO-1..4 | Treat forwarded records as direct; domain from the forwarder's credential; unchanged assertion; no early receipt | MVP §4.2, §5. | Conforms (design) | Store the submitting client as ingestion metadata, outside the assertion (MVP §10 `ingestion`). |
| §14 | Privacy | `design.md` retention, token claims. | Conforms | Document retention versus erasure for signed assertions. |

## 4. Error-code mapping

| Standard code | Lock design source | `jans-trace-core` code |
|---|---|---|
| `UNAUTHENTICATED`, `INSUFFICIENT_SCOPE` | OAuth filter (`401`, `403`) | n/a |
| `EVIDENCE_DOMAIN_NOT_BOUND` | `design.md` Component 1 ("rejected rather than defaulted") | n/a |
| `SUBMITTER_NOT_AUTHORIZED` | MVP §4.2 forwarding rule | n/a |
| `MALFORMED_JSON` | `design.md` Error Handling | `INVALID_JSON`, `DUPLICATE_MEMBER`, `NON_CANONICALIZABLE_JSON` |
| `SCHEMA_INVALID` | "Event-kind schema mismatch", "Array-size limit exceeded", "Missing mandatory identifier" | `INVALID_ASSERTION_SHAPE` |
| `UNSUPPORTED_PROFILE` | MVP §7.1 (`eat_profile` fixed) | n/a (Lock schema validation) |
| `MISSING_EXECUTION_CONTEXT` | MVP §12 "Missing required execution scope" | n/a |
| `PRODUCER_IDENTITY_MISMATCH` | MVP §12 (`producer` differs from `producer_chain.producer_id`) | `PRODUCER_MISMATCH` |
| `SIGNATURE_MALFORMED` | n/a | `INVALID_SIGNATURE_ENCODING`, `MISSING_SIGNATURE` |
| `CHAIN_NOT_REGISTERED` | n/a. Lock admits unregistered chains from an authorized key. Needed only if a registered-only policy is added. | n/a |
| `KEY_UNKNOWN` | "Unknown or untrusted producer" | `KID_MISMATCH` |
| `KEY_NOT_VALID` | MVP §6 validity window and revocation | n/a (registry check) |
| `EVENT_KIND_NOT_AUTHORIZED` | MVP §6, §12 (`authorized_event_kinds`) | n/a (registry check) |
| `UNSUPPORTED_ALGORITHM` | n/a (the MVP has one algorithm) | `INVALID_PUBLIC_KEY` when a registered key's type does not match the profile's algorithm |
| `SIGNATURE_INVALID` | "Signature verification failure" | `SIGNATURE_INVALID` |
| `RECORD_ID_CONFLICT` | "Content conflict" (`409`) | n/a |
| `REQUEST_TOO_LARGE`, `RECORD_TOO_LARGE` | Operational Limits | `SIZE_LIMIT_EXCEEDED` |
| `COLLECTOR_UNAVAILABLE` | "Storage failure" | n/a |
| `COLLECTOR_INTEGRITY_HOLD` | "Receipt-ledger divergence detected on failover recovery" | n/a |
| `INTERNAL_ERROR` | MVP §11.1 | `INTERNAL_ERROR`, `SIGNER_FAILURE` |

## 5. Metadata values for Lock

| Member | Source |
|---|---|
| `issuer` | Existing `getBaseEndpoint()` host. |
| `trace_ingestion_endpoint`, `trace_bulk_ingestion_endpoint` | `getBaseEndpoint()` + `/audit/trace`, `/audit/trace/bulk`. |
| `trace_profiles[].profile` | `tag:govops.owasp.org,2026:trace-v1` and `tag:jans.io,2026:trace-v1` during migration, each with the same suite. |
| `trace_profiles[].event_kinds_supported` | MVP §7.2: `AUTHORIZATION_DECISION`, `CAPABILITY_INVOKED`, `RUNTIME_EFFECT`. |
| `trace_profiles[].signature_algorithms_supported`, `.canonicalization`, `.content_digest_algorithm` | For each listed profile: `["Ed25519"]`, `"RFC8785"`, `"sha256"` (`jans-trace-core` §6.1). |
| `authorization_servers`, `ingestion_scope` | Lock's trusted OAuth issuers; `https://jans.io/oauth/lock/trace.write`. |
| `max_record_bytes`, `max_batch_bytes`, `max_batch_records`, `max_nesting_depth` | New Lock configuration properties, bounded by the `jans-trace-core` limits (§11 of that document). |
| `execution_correlation_required` | `true` for the MVP. |
| `producer_chain_registration_modes_supported` | `first_observed_genesis`, `pre_registered_genesis` (MVP §8). Add `linked_restart_genesis` only when Lock validates the signed `chain_link` (MVP §8 defers that validation). With both modes listed, unregistered chains are admitted (§7.4.1). |
| `acceptance_durability` | Per deployment (`replicated_durable` only if the persistence layer replicates before commit). |

## 6. Required implementation changes

Ordered by dependency.

1. **Receipt and commit.** Return `201` (first acceptance) or `200` (replay) instead of `202`; return `received_at` and `receipt_id`; snapshot flags at acceptance; acknowledge only after the `COMMITTED` state; ensure replays return the stored snapshot (§6.3, §7.2, §9).
2. **Processing order.** Implement §4.6: submitter-to-producer check before key lookup, replay before key validity, conflict after signature verification.
3. **Errors.** Add an RFC 9457 error writer for the TRACE endpoints and the code table (§10). Keep `LockApiError` on the existing audit endpoints.
4. **Bulk.** `200`, `index`, per-element Problem errors, array-order identity semantics, `BATCH_*` envelope errors (§8).
5. **Limits.** Configuration properties and defaults; `413` for bytes; enforce before verification (§5.8).
6. **Record identity.** Enforce canonical `record_id` forms (§5.6).
7. **Profiles.** Accept both profile tags and publish each as a `trace_profiles` entry with its suite. Key the cryptographic suite by `trace.eat_profile` inside `jans-trace-core` so later profiles can add algorithms without an API change.
8. **Discovery.** Implement `/.well-known/govops-trace-configuration` (§11). Update Cedarling's endpoint discovery to use it, and correct the `lock-master-configuration` reference.
9. **Authorization.** Add the Cedarling policies for the two TRACE endpoints and the forwarder-to-producer binding.
10. **Chain admission.** State Lock's admission policy in MVP §8 and `design.md` Component 3 (open admission for an authorized key, pre-registration as the stronger classification). Flag, do not reject, a sentinel on a non-genesis position. Return `chain_admission`. Optionally add a registered-only policy that returns `CHAIN_NOT_REGISTERED`.
11. **Conformance.** Run the standard's test suite (§15, Appendix C) in Lock's CI. Provide the `(hook)` facilities: fault injection at the commit point, record-store inspection, key revocation.

## 7. Updates to repository documents

| Document | Change |
|---|---|
| `Lock-Server-TRACE-MVP-Design.md` | §11.1/11.2: add `received_at`, `receipt_id`, replace `202` with `201`/`200`, fix bulk to `200`, Problem Details, `index`. §12: reference the standard's error table and `503` choice. §14: `413`. §7.1: `record_id` forms. §5: processing order. |
| `design.md` | Component 1 and Error Handling: replace `LockApiError` for TRACE endpoints, align statuses, reference the standard. |
| `cedarling-trace-design-MVP.md` | §6: `CEDARLING_TRACE_ENDPOINT` discovery via the new well-known document. |
| `govops-trace-profile.md` | Fix example identifiers to canonical `record_id` forms. |
| `README.md` | Link the standard and this mapping. |

## 8. Open questions

- Should Lock keep `tag:jans.io,2026:trace-v1` indefinitely, or deprecate it after producers migrate?
- Does the existing Lock client configuration support binding a client to a set of permitted producers (§4.5), or does that need a new configuration entity?
- Can `jans-orm` provide the `replicated_durable` guarantee on every supported backend, or should Lock omit `acceptance_durability` by default?
- Does any Lock deployment need a registered-only chain policy (variant M2)? If not, `CHAIN_NOT_REGISTERED` stays unused and the corresponding tests are marked not applicable.
- Should retrieval receive its own interface specification, including the `300` versus `409` ambiguity response?
