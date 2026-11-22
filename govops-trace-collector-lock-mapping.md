# Lock Server Mapping to the GovOps TRACE Collector API

This document maps Janssen Lock Server to the vendor-neutral [GovOps TRACE Collector API](govops-trace-collector-api.md) (the "standard"). It records which Lock behavior conforms, where the implemented Lock differs, and what is left as a decision. The standard itself does not mention Lock.

Section references of the form `§n` without a document name refer to the standard. `MVP` means `Lock-Server-TRACE-MVP-Design.md`. `design.md`, `jans-trace-core` (`jans-trace-core-mvp-design.md`), `cedarling-trace-design-MVP.md` and `govops-trace-profile.md` are the repository documents of those names.

## 1. Sources and what they describe

The MVP documents describe the **implemented** Lock TRACE behavior. `design.md` is the full target design, a superset of the MVP, and keeps behavior that the MVP defers (for example `unattributed_flag`, settlement, lineage coverage). Where the two differ, this document compares the standard with the MVP and notes `design.md` separately.

| Source | What it establishes |
|---|---|
| `Lock-Server-TRACE-MVP-Design.md` | Implemented endpoints `POST /api/v1/audit/trace` and `/trace/bulk`, scope `https://jans.io/oauth/lock/trace.write`, retrieval, admin API (`/api/v1/audit/trace/admin/...`, scope `trace.admin`), gRPC `TraceService`, discovery through `/.well-known/lock-server-configuration`, error body `{error, error_description, reason}`, `chainRegistrationMode`, batch-ingest mode. |
| `jans-trace-core-mvp-design.md` | Strict JSON, JCS, Ed25519, `content_digest`, receipt hash, library error codes, input limits (256 KiB record, depth 32). |
| `cedarling-trace-design-MVP.md` | The main producer. Runs `FIRST_OBSERVED` genesis only, discovers `trace_bulk_endpoint`, retries on `5xx`, `429`, `408`, and per-record `5xx` inside a `207`. |
| `design.md` | Full design. `202` for every acceptance, `503` for the integrity hold, retention, lineage coverage, settlement. |
| `govops-trace-profile.md` | The vendor-neutral record profile (`tag:govops.owasp.org,2026:trace-v1`), including the cryptographic suite and record limits (§15). |
| `trace-mvp-post-mvp.md` | Items deferred beyond the MVP. |

## 2. Where Lock differs from the standard

Each row names the Lock behavior, the standard's requirement, and a proposed resolution. "Lock" means Lock would change. "Standard" means the standard would change. "Decision" means the owners must choose. The standard is not changed for any row without that decision.

| # | Topic | Lock (MVP) | Standard | Proposed resolution |
|---|---|---|---|---|
| D1 | Acceptance status | `202` for every accepted record, including replay (MVP §11.1, `design.md` Error Handling). | `201` first acceptance, `200` replay (§6.2). | Lock. Update Cedarling's response handling (MVP §11.1 contract) and `design.md` Error Handling at the same time. |
| D2 | Bulk status | `207` whenever the batch was processed (MVP §11.2). Cedarling's retry logic reads the `207` body. | `200` with `results[]` (§8.3). | Lock. Cedarling must accept `200` and keep reading per-record `5xx`. |
| D3 | Error body | `{error, error_description, reason}`; `reason` toggled by `errorReasonEnabled` (MVP §12). | RFC 9457 Problem Details with `code` and `retryable` (§10.1). | Lock on the TRACE endpoints. See section 4 for the id mapping. |
| D4 | Storage failure | `500 storage_failure`, `500 crypto_unavailable` (MVP §12). `design.md`: `503` for the integrity hold. | `503 COLLECTOR_UNAVAILABLE` for a retryable outage, `500 INTERNAL_ERROR` otherwise (§10.2). | Lock. A producer cannot tell a retryable outage from a bug today. |
| D5 | Oversize bulk | `400` (MVP §14, `design.md` Operational Limits). | `413` for bytes, `400` for counts (§5.8). | Lock. |
| D6 | Receipt contents | `receipt_sequence`, `received_at`, flags, plus `policy_mismatch_flag`, `reserved_member_flag`, `reserved_members`. No `receipt_id`. | `receipt_id` and `received_at` REQUIRED (§6.3); other members optional extensions. | Lock adds `receipt_id` (decimal string of `receipt_sequence`). The two Lock flags stay as extensions. |
| D7 | Flags on replay | A replay reports the **stored** flags, which neighbor flag maintenance may have changed since acceptance (MVP §8, §12). | Flags are as of original acceptance and identical on replay (§7.4, §9). | Decision. Either Lock stores an acceptance snapshot in the `ingestion` block, or the standard relaxes the rule to "current flags". The snapshot is cheap and keeps replay byte-stable. |
| D8 | Replay versus key validity | The key window and event-kind checks run before the idempotency check (MVP §5). A replay after revocation fails. | Replay is detected before key checks (§4.6, §9 item 3). | Lock. Move the idempotency lookup before step 11 for records that match a stored identity and digest. |
| D9 | Chain admission | `PRE_REGISTERED` (default) rejects an unregistered chain with `400 chain_not_registered`. `FIRST_OBSERVED` registers a chain only from its genesis record, and rejects a non-genesis record on an unregistered chain with `400 chain_not_registered` (MVP §8). | Admission is by registration mode (§7.4.1): a first-sight Collector admits any authorized chain, with a gap flag for a non-genesis first record. A pre-registered-only Collector rejects with `CHAIN_NOT_REGISTERED`. | `PRE_REGISTERED` is the standard's pre-registered-only variant and conforms. `FIRST_OBSERVED` is a third variant (admit only from genesis). Decision: add it to the standard as `first_observed_genesis_only`, or have Lock admit non-genesis records with the gap flag. Cedarling needs `FIRST_OBSERVED`. |
| D10 | Sentinel and position mismatch | A sentinel on a non-genesis position, or a non-sentinel at position 1, is `400 invalid_genesis` (MVP §8). | Accept and set `chain_link_failure_flag` (§7.4.2; tests G-08, V-23). | Decision. The standard keeps integrity findings as flags so that evidence is never lost. Lock rejects them, which loses the record. Prefer Lock change. |
| D11 | Future `signed_at` | Rejects a record whose `signed_at` is more than the skew (300 s) ahead (`signed_at_in_future`, MVP §7.1). | `signed_at` is a claim, never an ordering authority (§4.5.1); the standard defines no rejection. | Decision. Either add an optional, published `max_future_skew_seconds` to the standard, or Lock stops rejecting and flags. |
| D12 | `producer` format | 1 to 255 characters, starts with a letter or digit, then letters, digits and `. _ : / -`. Space and other characters are rejected (MVP §7.1). | The standard treats `producer_id` as an opaque string and its vector V-26 uses `pdp/fleet 1`. | Decision. Either the profile adopts the Lock character rule (and vector V-26, tests C-49, C-57 and L-12 change), or Lock widens its rule. Adopting the stricter rule is simpler for URL paths. |
| D13 | Array limits | MVP defaults 256 elements per array (`jans-trace-core`: 1024). `design.md` Operational Limits already uses the profile values (32, 32, 128, 64, 64), so the MVP is the outlier. Fields `trace_execution_id` and `execution_authority` at most 255 characters. | Profile §15 maximums: `tokens[]` 32, `token_claims[]` 32, `decisions[]` and `invocations[]` 128, `operation_ids[]` 64, `parent_record_ids[]` 64. | Decision. Either Lock lowers its defaults to the profile values, or the profile states them as minimums that every Collector accepts. Collectors differ in practice, so minimums are the safer reading. |
| D14 | Submitter identity | "Authenticated submitting client" plus a configured binding. The issuer is not part of the key (MVP §4.1, §4.2). | `(issuer, client_id)` (§4.2.2). | Lock. Key bindings and `allowedProducerIds` by the pair. |
| D15 | Replay retention | No published value. | `idempotency_retention_seconds` (§9.1). | Lock publishes the shortest per-domain retention (default 400 days, 34,560,000 s) in discovery. |
| D16 | Discovery | `/.well-known/lock-server-configuration` with `trace_endpoint`, `trace_bulk_endpoint`, `trace_record_endpoint`, `trace_execution_endpoint` (MVP §11.7). | `/.well-known/govops-trace-configuration` (§11). | Lock adds the new document and keeps the old one. Cedarling's `discovered` mode keeps working against the old document until it is migrated. |
| D17 | Profile tag | `tag:jans.io,2026:trace-v1` only. | The vectors use `tag:govops.owasp.org,2026:trace-v1`; `trace_profiles` lists every accepted tag. | Lock lists both tags while it migrates. |
| D18 | Receipt lookup | Not designed. Retrieval (MVP §11.3) returns the whole record under `trace.readonly`. | Optional `GET /api/v1/audit/trace/receipts/{producer_id}/{record_id}` (§7.3.1). | Optional. Add for OTLP and Kafka reconciliation. |
| D19 | Atomic record and receipt | `PENDING/COMMITTED/VOID`. A race can leave a record stored with its identity blocked by a `VOID` entry (MVP §9). | A record is acknowledged only after a durable commit, and no partial state is visible (§7.2; DUR-005). | Verify. Confirm a blocked identity is retryable (a resubmission gets a new receipt), or the standard's DUR tests fail. |
| D20 | Missing execution context | Rejected (MVP §7.1). `design.md` accepts it with `unattributed_flag`. | Published `execution_correlation_required` (§7.5). | Conforms. Publish `true` for the MVP. |

### 2.1 Findings specific to `design.md`

`design.md` is the full design. These rows are in addition to D1 to D20. `design.md` has been updated to the standard for every row except E7 and E10, which need no change.

| # | Location | What it says | Standard | Resolution |
|---|---|---|---|---|
| E1 | Authenticated Chain Genesis | First-sight anchoring admits an unregistered chain, but the same list says a genesis for an "unregistered, unanchored" chain is flagged and "does not confer chain-start status". A non-genesis record on a chain whose genesis was never seen is a coverage gap at an unanchored origin. | §7.4.1: admission is by mode. First-sight admits, a gap is a flag. | The gap rule matches the standard's first-sight variant. Remove or reword the "does not confer chain-start status" bullet so it does not read as a rejection. This also shows the MVP's `FIRST_OBSERVED` (D9) is stricter than `design.md`. |
| E2 | Producer chain table versus Authenticated Chain Genesis | The `prev_record_hash` row says a non-genesis record presenting the sentinel is "rejected". The genesis section says it "fails `predecessor_linked`", a flagged break. | §7.4.2: flag it. | Fix the "rejected" wording. The MVP's `invalid_genesis` (D10) follows the "rejected" reading. |
| E3 | Error Handling: signature failure, content conflict | "`400`, or quarantined per configuration"; a conflict is "`409`, or quarantined". The response a producer sees when a record is quarantined is not stated. | §7.1: quarantine is internal and the response is always a rejection with no receipt. | State that quarantine never changes the response. |
| E4 | Error Handling: unknown producer | `400` "unresolvable producer", with no distinction for an unknown key, a revoked key or a wrong event kind. | Distinct codes `KEY_UNKNOWN`, `KEY_NOT_VALID`, `EVENT_KIND_NOT_AUTHORIZED` (§10.2). | Adopt the MVP split (`unknown_producer_key`, `key_not_valid`). |
| E5 | Error Handling: bulk | "Accepted for processing", with a per-record result array and no status code. | `200` with `results[]` (§8.3). | State `200` (the MVP says `207`, D2). |
| E6 | Component 1 and Error Handling: unattributed evidence | A record without `trace_execution_id` is stored with `unattributed_flag`. | §7.5: published `execution_correlation_required`. | Publish `false` for a deployment that follows `design.md`. The MVP publishes `true` (D20). |
| E7 | Component 1 | The `202` body carries `current_settlement`. The MVP has no settlement. | §6.3: settlement data is an optional extension. | Conforms as an extension. |
| E8 | Error Handling: integrity hold | `503` for ledger divergence, and `500` for a plain storage outage. | `503 COLLECTOR_INTEGRITY_HOLD` and `503 COLLECTOR_UNAVAILABLE` (§10.2). | The integrity hold conforms. The storage outage should be `503` (D4). |
| E9 | Operational Limits: retention | Default 400 days per evidence domain, and a shorter period for enriched token claims. The body size limit is `400`. | §9.1 publishes the shortest retention. §5.8 uses `413` for bytes. | Publish the shortest domain retention (D15). Use `413` for bytes (D5). A resubmission after pruning is a new acceptance (§9.3), which `design.md` does not state. |
| E10 | Error Handling: ambiguous lookup | `300`, or `409` when `Accept` demands one body. | Retrieval is out of scope. | Nothing to do. Open question below. |

Items that conform without change: strict JSON and duplicate-member rejection, `record_id` canonical forms (MVP §7.1: UUID or ULID, verify the case rule), one producer per bulk request, per-record bulk processing in array order, equivocation stored and flagged, `409 record_conflict` on a different digest, evidence-domain derivation from the authenticated client with a body-supplied `evidence_domain_id` ignored (and `reserved_member_flag`), key validity decided on Lock's clock (MVP §6; verify no code path uses `signed_at`), and the cryptographic suite (Ed25519, JCS, SHA-256).

## 3. Mapping by section

Status values: **Conforms**, **Change** (Lock must change; see section 2), **Add** (new capability), **Decision** (section 2 decision row), **Verify** (cannot be determined from the repository).

| Standard | Requirement | Lock | Status |
|---|---|---|---|
| §3 | `POST /api/v1/audit/trace`, `/trace/bulk` | Same paths (MVP §11.1, §11.2). | Conforms |
| §3, §11 | `GET /.well-known/govops-trace-configuration` | Not present (D16). | Add |
| §4.1 | TLS 1.2+, no cleartext | Deployment configuration. | Verify |
| §4.2, §4.2.1 | Token validation, minimum mechanisms | Existing OAuth filters. Accepted token format and `cnf` handling are not described. | Verify |
| §4.2.2 | Submitter identity `(issuer, client_id)` | D14. | Change |
| §4.2.3 | Audience check, dependency failure | Not specified. | Add |
| §4.3 | One published ingestion scope | `trace.write`. | Conforms (publish) |
| §4.4 | Domain from authenticated client, body value ignored | MVP §4.1. Unbound client is `403 client_not_bound`. | Conforms |
| §4.5 | Submitter-to-producer permission before key lookup | MVP §5 step order: the check precedes key lookup (`403 producer_not_allowed`). | Conforms |
| §4.5.1 | Key validity at the Collector's clock | MVP §6, §10. | Conforms (verify) |
| §4.6 | Processing order | D8. | Change |
| §5.2 | Strict JSON | `jans-trace-core` §6.2. | Conforms |
| §5.3 to §5.5 | Suite from the profile | Fixed Ed25519, JCS, SHA-256. | Conforms |
| §5.6 | `record_id` forms | UUID or ULID. | Verify case rule |
| §5.8 | Published limits, `413` | D5, D13. | Change, Decision |
| §6.2 | `201` and `200` | D1. | Change |
| §6.3 | Receipt contents | D6. | Change |
| §7.2 | Durable commit before acknowledgement | D19. | Verify |
| §7.3.1 | Receipt lookup | D18. | Add (optional) |
| §7.4.1 | Admission by registration mode | D9. | Decision |
| §7.4.2 | Sentinel misuse is a flag | D10. | Decision |
| §7.4.3 | Missing predecessor is a flag | MVP §8: `coverage_gap_flag`. | Conforms |
| §7.4.5 | Optional flags, `synchronous_integrity_flags` | Lock assesses synchronously and returns all flags. | Conforms (publish `true`) |
| §7.5 | Correlation context | D20. | Conforms |
| §8.1 | Array body, one producer per batch | MVP §11.2. | Conforms |
| §8.2 | Per-record processing in array order | MVP §9.1, §11.2. | Conforms |
| §8.3 | `200` with `results[]` and `index` | D2. | Change |
| §9.1 | Replay retention published | D15. | Add |
| §9.2 | Rules that do not apply to a replay | D8, D7. | Change |
| §9.3 | Resubmission after expiry | Not specified. | Add |
| §10 | Problem Details, code table | D3, D4. | Change |
| §11 | Metadata members | New (section 5). | Add |
| §12.1, §12.2 | Forwarder rules | Lock treats a forwarded record as direct (MVP §4.2). | Conforms (design) |
| §14 | Privacy | `design.md` retention, token claims. | Conforms |

## 4. Error-code mapping

| Standard code | Lock error id (MVP §12) | Lock status | `jans-trace-core` code |
|---|---|---|---|
| `UNAUTHENTICATED`, `INSUFFICIENT_SCOPE` | OAuth filter | 401, 403 | n/a |
| `EVIDENCE_DOMAIN_NOT_BOUND` | `client_not_bound` | 403 | n/a |
| `SUBMITTER_NOT_AUTHORIZED` | `producer_not_allowed` | 403 | n/a |
| `MALFORMED_JSON` | `invalid_request` | 400 | `INVALID_JSON`, `DUPLICATE_MEMBER`, `NON_CANONICALIZABLE_JSON` |
| `BATCH_NOT_ARRAY`, `BATCH_MIXED_PRODUCERS` | `invalid_request` | 400 | n/a |
| `SCHEMA_INVALID` | `invalid_assertion` | 400 | `INVALID_ASSERTION_SHAPE` |
| `UNSUPPORTED_PROFILE` | `unsupported_profile` | 400 | n/a |
| `MISSING_EXECUTION_CONTEXT` | `invalid_assertion` (reason names the missing pair) | 400 | n/a |
| `PRODUCER_IDENTITY_MISMATCH` | `producer_mismatch` | 400 | `INVALID_ASSERTION_SHAPE` (the core's `PRODUCER_MISMATCH` is a different check, signed producer against the caller's expected producer) |
| `SIGNATURE_MALFORMED` | `invalid_assertion` | 400 | `INVALID_SIGNATURE_ENCODING`, `MISSING_SIGNATURE` |
| `CHAIN_NOT_REGISTERED` | `chain_not_registered` | 400 | n/a |
| `KEY_UNKNOWN` | `unknown_producer_key` | 400 | `KID_MISMATCH` |
| `KEY_NOT_VALID` | `key_not_valid` | 400 | n/a |
| `EVENT_KIND_NOT_AUTHORIZED` | `unknown_producer_key` (collapse permitted, §10.2) | 400 | n/a |
| `SIGNATURE_INVALID` | `invalid_signature` | 400 | `SIGNATURE_INVALID` |
| `RECORD_ID_CONFLICT` | `record_conflict` | 409 | n/a |
| `REQUEST_TOO_LARGE`, `RECORD_TOO_LARGE` | `invalid_request` | 400 (D5) | `SIZE_LIMIT_EXCEEDED` |
| `COLLECTOR_UNAVAILABLE` | `storage_failure` | 500 (D4) | n/a |
| `INTERNAL_ERROR` | `crypto_unavailable` | 500 | `INTERNAL_ERROR`, `SIGNER_FAILURE` |
| `COLLECTOR_INTEGRITY_HOLD` | `design.md` ledger divergence | 503 | n/a |
| `UNSUPPORTED_ALGORITHM` | n/a (one suite) | n/a | `INVALID_PUBLIC_KEY` on key type mismatch |
| `RECEIPT_NOT_FOUND`, `RECEIPT_ACCESS_DENIED` | New (D18) | n/a | n/a |
| (no standard code) | `invalid_genesis` | 400 | D10 |

## 5. Metadata values for Lock

| Member | Source |
|---|---|
| `issuer` | Existing `getBaseEndpoint()` host. |
| `trace_ingestion_endpoint`, `trace_bulk_ingestion_endpoint` | `getBaseEndpoint()` + `/audit/trace`, `/audit/trace/bulk`. |
| `trace_profiles[].profile` | `tag:jans.io,2026:trace-v1` today; add `tag:govops.owasp.org,2026:trace-v1` during migration, each with the same suite. |
| `trace_profiles[].event_kinds_supported` | MVP §7.2: `AUTHORIZATION_DECISION`, `CAPABILITY_INVOKED`, `RUNTIME_EFFECT`. |
| `trace_profiles[].signature_algorithms_supported`, `.canonicalization`, `.content_digest_algorithm` | For each listed profile: `["Ed25519"]`, `"RFC8785"`, `"sha256"` (`jans-trace-core` §6.1). |
| `authorization_servers[]` | One entry per trusted OAuth issuer from Lock's trusted-issuer configuration, with `token_format` (`jwt` or `introspection`) and, where the issuer does not use `client_id`, `client_id_claim`. |
| `ingestion_scope` | `https://jans.io/oauth/lock/trace.write`. |
| `sender_constrained_tokens_supported` | Per Lock's DPoP and certificate-binding support (to be confirmed). |
| `max_record_bytes`, `max_batch_bytes`, `max_batch_records`, `max_nesting_depth` | Existing properties: 262,144 bytes, `maxBulkRequestBytes` (4 MiB), `maxBulkRecords` (100), depth 32 (MVP §11, §14). |
| `execution_correlation_required` | `true` for the MVP. |
| `producer_chain_registration_modes_supported` | Per `chainRegistrationMode` (MVP §8): `PRE_REGISTERED` publishes the pre-registered-only mode. `FIRST_OBSERVED` has no standard value yet (D9). |
| `synchronous_integrity_flags` | `true` (MVP §11.1 and `design.md` Property 17 assess synchronously). |
| `trace_receipt_endpoint`, `receipt_scope` | Present only if Lock implements receipt lookup: `.../audit/trace/receipts/{producer_id}/{record_id}` and the receipt scope above. |
| `idempotency_retention_seconds`, `trace_profiles_replay_only` | The shortest per-domain record retention across Lock's evidence domains (default 400 days = 34,560,000 s). Replay-only list is empty unless a profile tag is withdrawn. |
| `acceptance_durability` | Per deployment (`replicated_durable` only if the persistence layer replicates before commit). |

## 6. Required implementation changes

Ordered by dependency. Items marked "after decision" wait on a row of section 2.

1. **Status codes and receipt.** Return `201`/`200` for single, `200` for bulk; add `receipt_id`; snapshot flags at acceptance (D1, D2, D6, D7).
2. **Processing order.** Detect replay before key validity checks (D8).
3. **Errors.** Add a Problem Details writer for the TRACE endpoints; split `storage_failure` into `503`/`500`; `413` for byte limits (D3, D4, D5). Keep the existing envelope on the other audit endpoints.
4. **Submitter identity.** Key client bindings and `allowedProducerIds` by `(issuer, client_id)`; add the audience and `cnf` checks (D14).
5. **Discovery and metadata.** Serve `/.well-known/govops-trace-configuration` beside the existing document and publish `idempotency_retention_seconds` (D15, D16, section 5).
6. **Profiles.** List both tags and key the suite by `trace.eat_profile` inside `jans-trace-core` (D17).
7. **Chain admission, sentinel, clock, producer format, limits.** After decision: D9, D10, D11, D12, D13.
8. **Commit protocol.** Prove a `VOID`-blocked identity is retryable (D19).
9. **Receipt lookup (optional).** D18.
10. **Conformance.** Run `conformance/` against Lock in CI. Lock needs the hooks the tests name: controllable clock, fault injection at the commit point, record-store inspection, key and chain registration, and submitter and limit configuration. Without a hook, the dependent tests are reported as unverified.

## 7. Updates to repository documents

The MVP documents describe the implementation. They are not rewritten to the standard here. They change when Lock changes, or when a decision above is made.

| Document | Change when |
|---|---|
| `Lock-Server-TRACE-MVP-Design.md` | §11, §12, §14: D1 to D5, D8; §5: D8; §8: D9, D10; §7.1: D11, D12. |
| `design.md` | Updated to the standard: rows E1 to E6, E8, E9 and D1 to D5, D7, D15 (statuses, Problem Details, `413`/`503`, quarantine, genesis wording, retention). Not changed: D9 to D13, which are decisions (the MVP, not `design.md`, differs on D9, D10 and D13). |
| `cedarling-trace-design-MVP.md`, `cedarling-trace-design.md`, `fido-trace-design.md`, `auth-server-trace-design.md` | Updated: retry per standard §10.3 and §8.5, `200`/`207` bulk handling, discovery through the standard's metadata document, lowercase canonical `record_id`, acceptance statuses. The Cedarling MVP has no durable outbox (standard §10.3 SHOULD), recorded as a known deviation. The `FIRST_OBSERVED` requirement depends on D9. |
| `jans-trace-core-mvp-design.md` | §11 limits against profile §15 (D13); suite keyed by `eat_profile` (D17). |
| `auth-server-trace-design-MVP.md`, `fido-trace-design-MVP.md` | None. Neither signs records in the MVP. |
| `govops-trace-profile.md` | D12, D13 if the profile is changed. |
| `README.md` | Link the standard and this mapping. |

## 8. Open questions

- Decisions D7 and D9 to D13 in section 2.
- Should Lock keep `tag:jans.io,2026:trace-v1` indefinitely, or deprecate it after producers migrate?
- Can `jans-orm` provide the `replicated_durable` guarantee on every supported backend, or should Lock omit `acceptance_durability`?
- Does the existing Lock client configuration bind a client to a set of permitted producers by `(issuer, client_id)`? The MVP has `allowedProducerIds` per client, which suggests yes.
- Should retrieval receive its own interface specification, including the `300` versus `409` ambiguity response in `design.md`?
