# GovOps TRACE Collector API

**Status:** Draft 1 (proposed interoperable specification)
**Applies to:** TRACE record profile `tag:govops.owasp.org,2026:trace-v1` (`govops-trace-profile.md`)

## Contents

1. Introduction and scope
2. Conventions and terminology
3. Overview
4. Authentication and authorization
5. Wire format
6. Single-record submission
7. Acceptance semantics
8. Bulk submission
9. Idempotency and conflicts
10. Errors
11. Discovery
12. Intermediaries
13. Security considerations
14. Privacy considerations
15. Conformance
16. IANA considerations
17. References

Appendices: A (examples), B (OpenAPI 3.1 definition), C (conformance test vectors), D (informative OTLP and Kafka bindings).

---

## 1. Introduction and scope

TRACE producers (policy decision points, enforcement points, identity systems, effect observers) sign evidence records. A **Collector** receives those records, verifies them, durably accepts them, and returns a receipt. This document specifies the REST interface by which a Collector receives signed TRACE records, and the metadata by which a client discovers that interface.

The goal is that any TRACE producer can submit to any conforming Collector without adopting any particular Collector architecture.

### 1.1 In scope

- Single-record and batch submission endpoints.
- Collector discovery metadata.
- Transport security, OAuth 2.0 access control, and the separation between submission authorization and producer verification.
- Request and response formats, size limits, and signature preservation.
- When a Collector may acknowledge a record as accepted.
- Idempotency, conflict, and error behavior.
- Requirements on intermediaries (forwarders, OpenTelemetry Collectors, Kafka-backed adapters).
- Conformance requirements and test vectors.

### 1.2 Out of scope

This document does not specify, and a conforming Collector is free to choose:

- storage engine, database schema, replication, or deployment architecture;
- the internal receipt chain, checkpoints, or external anchoring (a Collector MAY expose one, see §6.3);
- correlation, graph, analytics, or retrieval APIs;
- settlement, completeness, trust-tier, capability-resolution, or any other derived assessment;
- the mechanism by which producer keys and evidence domains are provisioned (configuration file, admin API, or other);
- the TRACE record schema itself, which is defined by the TRACE record profile and is referenced, not duplicated, here.

If this document and a TRACE record profile disagree about the content of a record, the profile governs. If they disagree about API behavior, this document governs.

### 1.3 Design constraints

1. The evidence format is transport-independent. REST is the canonical Collector submission interface, but a producer MAY carry a signed record through an intermediary (OTLP, Kafka, or another broker). The signed bytes, not the transport, are the evidence (§12).
2. Receiving a record, verifying it, accepting it, and assessing it are different things, and this document keeps them separate (§7).
3. Nothing a client or intermediary sends outside the signed assertion can select the evidence domain, raise trust, or substitute for a producer signature.

---

## 2. Conventions and terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown here.

JSON is as defined by RFC 8259. "Strict JSON" is defined in §5.2.

| Term | Meaning |
|---|---|
| **Record** | A producer-signed TRACE assertion: the complete top-level JSON object, including `signature`. |
| **Producer** | The component that creates and signs a record. Identified by the signed `producer` member. |
| **Submitter** | The authenticated OAuth client that sends the HTTP request. It is often, but not always, the producer. |
| **Forwarder** | A submitter that relays records signed by other producers (§12). |
| **Collector** | A server implementing this API. |
| **Evidence domain** | The Collector's isolation partition for authorization, storage, and identity. Derived by the Collector from the authenticated submitter, never from the record (§4.4). |
| **Producer key registry** | The Collector's administratively provisioned mapping from `(evidence domain, producer_id, kid)` to a public key and the event kinds that key may sign. |
| **Record identity** | `(evidence domain, producer_id, record_id)`. |
| **`content_digest`** | `"sha256:"` plus lowercase hexadecimal SHA-256 of the RFC 8785 (JCS) canonical form of the complete record, including `signature` (§5.5). |
| **Acceptance receipt** | The Collector's response stating that it verified and durably accepted a record (§6.3, §7). |
| **Execution correlation pair** | `(execution_authority, trace_execution_id)`: the namespace in which an execution ID was allocated, and the ID of one execution within it. A profile may require both on every record. |
| **Terminal rejection** | A rejection that retrying the same bytes cannot cure. |

---

## 3. Overview

```text
 Producer --signed record--> [ optional forwarder / OTLP / Kafka ] --> Collector
                                                                         |
   POST /api/v1/audit/trace                 +----------------------------+--------------+
   POST /api/v1/audit/trace/bulk            | 1. authenticate, authorize                |
   GET  /.well-known/govops-trace-          | 2. verify (key, signature)                |
        configuration                       | 3. durably accept, return receipt         |
                                            +----------------------------+--------------+
                                                                         |
                                                                         v
                                          later, asynchronously: assessment (out of scope)
```

| Method | Endpoint | Purpose | Authentication |
|---|---|---|---|
| POST | `/api/v1/audit/trace` | Submit one record | OAuth 2.0 access token with the ingestion scope |
| POST | `/api/v1/audit/trace/bulk` | Submit a batch of records | OAuth 2.0 access token with the ingestion scope |
| GET | `/.well-known/govops-trace-configuration` | Collector metadata | None |

The paths above are canonical for API version `v1`. A Collector MAY be deployed under a path prefix; the endpoints it serves are then the URLs published in its metadata (§11), and clients MUST use those URLs instead of constructing them.

---

## 4. Authentication and authorization

### 4.1 Transport security

- Every request to the ingestion endpoints MUST use TLS. A Collector MUST NOT serve them over cleartext HTTP and MUST NOT redirect a cleartext request to HTTPS for an ingestion endpoint (the access token would already have been exposed).
- A Collector MUST support TLS 1.2 or later and SHOULD support TLS 1.3 (RFC 8446). It MUST NOT negotiate SSL 3.0, TLS 1.0, or TLS 1.1.
- Clients MUST validate the Collector's certificate chain and host name.

### 4.2 OAuth 2.0 access tokens

- A request to an ingestion endpoint MUST carry an OAuth 2.0 access token (RFC 6750 `Authorization: Bearer`, or a sender-constrained scheme such as DPoP, RFC 9449, or mutual-TLS-bound tokens, RFC 8705).
- Sender-constrained tokens are RECOMMENDED, and are especially RECOMMENDED for forwarders, which hold credentials that can submit for many producers.
- The Collector MUST validate the token's signature or introspection result, expiry, issuer, and audience before processing the body. Accepted issuers are those listed in the Collector's `authorization_servers` metadata (§11).
- The Collector SHOULD require that the token's audience identifies the Collector (RFC 8707).
- Access tokens MUST NOT be accepted in a URI query parameter.
- A missing, expired, malformed, or otherwise invalid token yields `401` with `WWW-Authenticate` (RFC 6750 §3) and problem code `UNAUTHENTICATED`.

### 4.3 Scopes

- The Collector MUST define one ingestion scope and MUST publish its name as `ingestion_scope` in its metadata. A token without that scope yields `403` with `INSUFFICIENT_SCOPE`.
- The RECOMMENDED scope name is `trace.write`. Deployments MAY use a namespaced value, such as a URI. Clients MUST read the name from metadata.
- The ingestion scope MUST NOT also authorize producer-key administration, evidence retrieval, or any other function. Retrieval and administration use separate scopes and are not defined here.

### 4.4 Evidence-domain isolation

- The Collector MUST derive the evidence domain from the authenticated submitter (the OAuth client identity as validated in §4.2) and the Collector's own configuration.
- A submitter with no evidence-domain binding MUST be rejected with `403` and `EVIDENCE_DOMAIN_NOT_BOUND`. The Collector MUST NOT apply a default domain to an unbound submitter in a multi-domain deployment. (A deployment with exactly one domain MAY treat it as an implicit configured value, but the rules in this section still apply.)
- The evidence domain MUST NOT be read from the request path, query, headers, or record body. If a record contains a member named `evidence_domain_id` (or an equivalent partition field), the Collector MUST ignore it for every purpose, and SHOULD flag it for operators. The member remains part of the signed assertion and is preserved unchanged.
- The evidence domain MUST be determined before any producer-key lookup, identity lookup, or content-based routing.
- Every read and write in the Collector MUST be scoped to that domain. A record identity, key, or receipt in another domain MUST NOT be observable through any response, error detail, timing-dependent behavior the Collector controls, or idempotency result. In particular, a submission in domain D2 MUST NOT conflict with, replay, or reveal an identical record identity in domain D1.
- A producer that legitimately submits to several domains needs a separately provisioned key registration and a separately bound submitter credential in each.

### 4.5 Submission authorization is not producer verification

Two independent checks apply to every record. Neither substitutes for the other.

| | Submission authorization | Producer verification |
|---|---|---|
| Question | May this authenticated client send records to this Collector, for this producer? | Did the registered producer sign exactly these bytes, and may that key sign this event kind? |
| Evidence | OAuth token, scope, submitter-to-evidence-domain binding, submitter-to-producer permission | Producer key registry entry, `kid`, Ed25519 signature |
| Failure | `401`, `403` | `400` with a key or signature code |
| Granted by | The Collector's access-control configuration | The producer key registry, provisioned administratively |

Rules:

1. **Submitter-to-producer permission.** The Collector MUST maintain which submitters may submit records for which `producer_id` values. By default a submitter may submit only for the producer it represents. A submitter MAY submit for other producers only if the Collector's configuration explicitly permits that submitter to forward for those producers (§12). A submitter that is not permitted MUST be rejected with `403` and `SUBMITTER_NOT_AUTHORIZED`, before key resolution or signature verification.
2. **No self-authenticating keys.** The Collector MUST NOT accept a public key from a request. Keys come only from the producer key registry, provisioned by an administrative path separate from the ingestion scope.
3. **Producer identity comes from the signed record.** The Collector MUST NOT accept a producer identity, `kid`, or evidence domain from an unsigned header, query, or transport attribute in place of the values in the signed assertion.
4. **Registry authority.** The index `(evidence domain, producer_id, kid)` locates a candidate key. Authority to sign comes from the administrative registration of that key: it exists, is within its validity window, is not revoked, is registered for this `producer_id`, and lists the record's `trace.event_kind` as permitted.
5. **A valid OAuth token never makes an invalid signature acceptable**, and a valid signature never overrides a missing submission permission.

The minimum content of a producer key registration is informative:

```json
{
  "producer_id": "pdp-fleet-1",
  "kid": "key-2026-01",
  "public_key_jwk": { "kty": "OKP", "crv": "Ed25519", "x": "..." },
  "authorized_event_kinds": ["AUTHORIZATION_DECISION"],
  "valid_from": "2026-01-01T00:00:00Z",
  "valid_until": null,
  "revoked_at": null
}
```

### 4.6 Processing order

A Collector MUST produce results as if it evaluated the following steps in order for each request, and MUST report the first failing step. Steps 1 to 6 apply to the request; steps 7 to 16 apply to each record. This order ensures that authorization precedes content processing, that cheap limit checks precede cryptography, and that replay is recognized before key-validity checks.

| # | Step | Failure |
|---|---|---|
| 1 | TLS | connection refused |
| 2 | Authenticate token | `401 UNAUTHENTICATED` |
| 3 | Check ingestion scope | `403 INSUFFICIENT_SCOPE` |
| 4 | Derive evidence domain | `403 EVIDENCE_DOMAIN_NOT_BOUND` |
| 5 | Check `Content-Type`, `Content-Encoding`, body byte limit (`max_record_bytes` for a single-record request, `max_batch_bytes` for a batch), rate limit | `415`, `413 RECORD_TOO_LARGE` or `413 REQUEST_TOO_LARGE`, `429` |
| 6 | Strict-parse the body; check batch envelope (array, non-empty, count limit, producer uniformity) | `400` envelope codes (§8.1) |
| 7 | Read each record's `producer` and check submitter-to-producer permission | `403 SUBMITTER_NOT_AUTHORIZED` |
| 8 | Check per-record size limit | `413 RECORD_TOO_LARGE` |
| 9 | Validate record structure: required members, supported profile, `record_id` form, `producer` equals `producer_chain.producer_id`, event-kind schema, required correlation context | `400 SCHEMA_INVALID`, `UNSUPPORTED_PROFILE`, `PRODUCER_IDENTITY_MISMATCH`, `MISSING_EXECUTION_CONTEXT` |
| 10 | Compute `content_digest`; look up the record identity; if an accepted record has the same digest, return its original receipt (replay) | none: replay |
| 11 | Resolve the key by `(evidence domain, producer_id, kid)`; check validity window and revocation; check `event_kind` permission | `400 KEY_UNKNOWN`, `KEY_NOT_VALID`, `EVENT_KIND_NOT_AUTHORIZED` |
| 12 | Check signature encoding and verify the Ed25519 signature | `400 SIGNATURE_MALFORMED`, `SIGNATURE_INVALID` |
| 13 | If the identity exists with a different digest | `409 RECORD_ID_CONFLICT` |
| 14 | Evaluate producer-chain position and set integrity flags | none: flags |
| 15 | Atomically and durably commit the record and its receipt | `503 COLLECTOR_UNAVAILABLE`, `500 INTERNAL_ERROR` |
| 16 | Return the receipt | none |

---

## 5. Wire format

### 5.1 Content types and encoding

- Requests: `Content-Type: application/json`. The body is UTF-8. A Collector MUST reject any other media type with `415` and `UNSUPPORTED_MEDIA_TYPE`.
- A Collector MAY accept `Content-Encoding: gzip` and, if so, MUST list it in `content_encodings_supported`. A client MUST NOT send a content encoding the Collector has not advertised. Every size and nesting limit applies to the decoded body, and the Collector MUST enforce a decoded-size limit while decoding (not after) to resist decompression bombs.
- Successful responses: `application/json`. Error responses: `application/problem+json` (RFC 9457).
- A Collector MUST ignore request headers that purport to carry producer identity, `kid`, evidence domain, or correlation values (for example `Audit-Trace-ID`); these are correlation hints, never evidence.

### 5.2 Strict JSON

The request body, and every record, MUST be strict JSON. A Collector MUST reject with `400 MALFORMED_JSON`:

- invalid UTF-8, or invalid Unicode scalar values in strings;
- a duplicate member name at any depth (a parser that silently keeps the first or last duplicate is not acceptable for signed input);
- `NaN`, `Infinity`, `-Infinity`, or numbers the RFC 8785 number model cannot represent;
- trailing non-whitespace content after the JSON value;
- a record that is not a JSON object;
- nesting deeper than `max_nesting_depth`.

### 5.3 Record structure

The record's members, event kinds, and schemas are defined by the TRACE record profile named in `trace.eat_profile`. This document does not restate them. The Collector reads these top-level members for routing, identity, and verification:

| Member | Use by the Collector |
|---|---|
| `producer` | Stable logical producer identifier. MUST equal `producer_chain.producer_id` byte for byte. |
| `kid` | Selects the registered key. Inside the signed scope. |
| `record_id` | Producer-generated identity within the producer's namespace. |
| `trace.eat_profile` | MUST be in the Collector's `trace_profiles_supported`. |
| `trace.event_kind` | MUST be permitted for the key. |
| `trace.signed_at` | Producer time (NumericDate). A claim, never an ordering authority. |
| `producer_chain.*` | Chain position and predecessor hash (§7.4). |
| `signature` | Unpadded base64url Ed25519 signature. |

Unknown members MUST be preserved and are covered by the signature. A Collector MUST NOT remove, rename, reorder for storage semantics, or add members to the signed assertion.

### 5.4 Signature

- Algorithm: Ed25519 (RFC 8032). Algorithm agility is not provided by `v1`; the only value in `signature_algorithms_supported` defined by this version is `Ed25519`.
- Signature input: the RFC 8785 canonical form of the complete top-level record with only the top-level `signature` member omitted. Every other member, including unknown members, is signed.
- Signature encoding: unpadded base64url (RFC 4648 §5) of the 64-byte signature. A Collector MUST reject padding, the standard base64 alphabet, a wrong decoded length, and a non-string value with `SIGNATURE_MALFORMED`.
- The Collector MUST verify with the key selected by the signed `kid`. It MUST NOT guess a key from a timestamp.

### 5.5 Content digest

```text
content_digest = "sha256:" + lowercase_hex( SHA-256( JCS( complete record including signature ) ) )
```

`content_digest` fingerprints the entire signed record. It is Collector-computed and is never a signature-verification result, a record identifier, or a producer-supplied value. A producer-supplied `content_digest` member, if present, has no effect.

### 5.6 Record identity

- `record_id` is produced by the producer inside the signed body. It MUST be a UUID in lowercase canonical text form (RFC 9562, `8-4-4-4-12` lowercase hexadecimal) or a ULID in uppercase Crockford base32 (26 characters). A Collector MUST reject other forms with `SCHEMA_INVALID`.
- A Collector MUST compare `record_id` as an exact string. Because forms are fixed, one UUID cannot appear under two identities by changing letter case.
- The record identity is `(evidence domain, producer_id, record_id)`. Two producers MAY use the same `record_id` without collision.

### 5.7 Signature and byte preservation

- A Collector MUST store the assertion so that its JCS form, and therefore its signature and `content_digest`, can be reproduced exactly at any later time. A Collector MUST NOT insert resolved claims, status, trust, corrections, or receipt data into the assertion.
- A Collector SHOULD also retain the exact received bytes, because some later anchoring formats commit to the as-transmitted serialization, which JCS cannot reconstruct.
- Idempotency and conflict decisions use `content_digest`, so a semantically identical resubmission with different whitespace, member order, or number spelling is the same record.

### 5.8 Limits

A Collector MUST enforce, and MUST publish in metadata (§11), at least these limits:

| Limit | Metadata field | Minimum a Collector MUST support | Failure |
|---|---|---|---|
| Bytes in one record (decoded) | `max_record_bytes` | 65,536 | `413 RECORD_TOO_LARGE` |
| Bytes in one bulk request body (decoded) | `max_batch_bytes` | 1,048,576 | `413 REQUEST_TOO_LARGE` |
| Records in one batch | `max_batch_records` | 100 | `400 BATCH_TOO_MANY_RECORDS` |
| JSON nesting depth | `max_nesting_depth` | 16 | `400 MALFORMED_JSON` |

Recommended defaults: 262,144 bytes per record, 8 MiB per request, 500 records per batch, depth 32. Array-length limits inside a record (for example `tokens[]`) are defined by the TRACE record profile and are reported as `SCHEMA_INVALID`; a Collector MUST NOT silently truncate a signed array.

A Collector MUST apply all limits before expensive cryptographic processing. A client MUST NOT send more than the advertised limits.

---

## 6. Single-record submission

### 6.1 Request

```http
POST /api/v1/audit/trace HTTP/1.1
Host: collector.example.org
Authorization: Bearer <access-token>
Content-Type: application/json

{ ...the complete signed record... }
```

The body is exactly one record. No wrapper object is used.

### 6.2 Responses

| Status | When | Body |
|---|---|---|
| `201 Created` | First durable acceptance: the record was verified and durably accepted by this request | Acceptance receipt, `idempotent_replay` false |
| `200 OK` | Idempotent replay: an identical record had already been accepted | The original acceptance receipt, `idempotent_replay` true |
| `400` | Malformed JSON, invalid record, unverifiable signature or key | Problem Details |
| `401`, `403` | Authentication or authorization failure | Problem Details |
| `409` | The record identity is bound to different content | Problem Details |
| `413`, `415`, `429` | Limit, media type, rate | Problem Details |
| `500`, `503` | Nothing was accepted; retry is safe | Problem Details |

`201` and `200` are used, and `202 Accepted` is not, because `202` conventionally means that processing has not completed. This API acknowledges only after verification and durable storage (§7.2). A `201` means the record was durably accepted by this request. A `200` means an earlier request already accepted it. A client MUST treat both as acceptance and MUST use `idempotent_replay`, not the status, to tell them apart. A `201` response MAY include a `Location` header if the Collector offers a retrieval URL for the record; clients MUST NOT depend on it.

### 6.3 Acceptance receipt

```json
{
  "accepted": true,
  "producer_id": "pdp-fleet-1",
  "record_id": "0191f3a0-7b1e-7c2a-9d41-3a2f7b0c9d41",
  "content_digest": "sha256:c849281f3c5ef69a204c28cf8a3036092b159ffa782b2bee11d3513fd4455226",
  "receipt_id": "108422",
  "received_at": "2026-06-11T00:42:23.456Z",
  "idempotent_replay": false,
  "coverage_gap_flag": false,
  "chain_link_failure_flag": false,
  "equivocation_flag": false,
  "late_flag": false
}
```

| Member | Required | Meaning |
|---|---|---|
| `accepted` | REQUIRED | `true`. |
| `producer_id`, `record_id` | REQUIRED | Echo of the record identity. |
| `content_digest` | REQUIRED | The Collector-computed digest (§5.5). A producer SHOULD compare it with its own computation. |
| `receipt_id` | REQUIRED | Opaque string, unique within the evidence domain, assigned once per accepted record, and identical on every replay. |
| `received_at` | REQUIRED | RFC 3339 UTC timestamp with exactly millisecond precision and a `Z` suffix, assigned by the Collector at acceptance and identical on every replay. |
| `idempotent_replay` | REQUIRED | `false` on first acceptance; `true` when the response repeats an earlier acceptance. |
| `coverage_gap_flag`, `chain_link_failure_flag`, `equivocation_flag`, `late_flag` | REQUIRED | Integrity flags as of the moment of original acceptance (§7.4). |
| `unattributed_flag` | CONDITIONAL | REQUIRED if the Collector accepts records without correlation context (§7.5). |
| `receipt_sequence` | OPTIONAL | Position in a Collector-internal receipt chain, if the Collector exposes one. Clients MUST NOT depend on its presence. |

A Collector MAY add members. A client MUST ignore members it does not recognize. This document does not standardize the Collector's internal receipt chain, commitment profile, checkpoints, or settlement status; a Collector exposing them does so through extension members.

---

## 7. Acceptance semantics

### 7.1 Three different things

| Stage | What it establishes | When | Where reported |
|---|---|---|---|
| **Cryptographic verification** | The producer key was registered, valid, and authorized for the event kind, and the Ed25519 signature is valid over the JCS bytes. | Before acceptance (steps 11 and 12). | A failure is an error response. Success is implied by a receipt. |
| **Acceptance** | The Collector durably holds the assertion and a receipt for it, bound to the evidence domain, and will return the same receipt for any identical resubmission. | At the `201` or `200` (or an accepted bulk element). | The acceptance receipt. |
| **Evidence assessment** | Derived findings such as settlement, completeness, trust tier, capability resolution, lineage coverage. | Later, asynchronously, any number of times. | Outside this API. |

Rules that follow:

1. A Collector MUST NOT report `accepted: true` for a record that has not passed verification. A Collector MAY retain a record that failed verification in separately access-controlled quarantine, but it MUST respond as for a rejection, MUST NOT return a receipt, and MUST NOT make the quarantined record visible to any evidence retrieval or correlation.
2. Acceptance does not imply that the record is true, complete, authorized, correlated, settled, or independently observed. A valid signature proves that the registered producer key signed those bytes.
3. A Collector MUST NOT label accepted records as `settled`, `complete`, or externally anchored on the basis of acceptance.
4. Assessments MUST NOT modify the accepted assertion. They are stored and reported separately.

### 7.2 When a Collector may acknowledge

A Collector MUST NOT return a receipt (a `201` or `200` from the single-record endpoint, or an accepted element in a bulk response) until **all** of the following hold:

1. Steps 2 to 14 of §4.6 succeeded for the record.
2. The assertion (as defined in §5.7) and its receipt data (`receipt_id`, `received_at`, `content_digest`, and the integrity flags) have been written to durable storage. Durable means the write survives a process crash and a restart of the Collector, and, if the Collector advertises `acceptance_durability: "replicated_durable"`, the loss of a single storage node.
3. The write is committed. A record whose commit is pending, in doubt, or later voided MUST NOT have been acknowledged.
4. The receipt returned is the receipt persisted. A later identical submission MUST return identical `receipt_id` and `received_at`.

Consequences:

- The Collector MUST NOT acknowledge from an in-memory buffer, an unflushed write-ahead queue, or a message accepted onto an internal broker whose delivery to storage is not yet confirmed.
- Asynchronous indexing, correlation, and assessment after the acknowledgement are permitted, provided the persisted evidence and receipt are sufficient to rebuild them.
- If the Collector cannot complete the commit, it MUST return `503 COLLECTOR_UNAVAILABLE` (or `500 INTERNAL_ERROR`). It MUST NOT leave a visible record, receipt, or index entry for an unacknowledged submission. If the outcome is unknown to the client (timeout, connection loss), the client resubmits the same bytes. The Collector then returns either a first acceptance or a replay; it never returns two receipts.

### 7.3 Receipt scope

A receipt establishes only: "This Collector, within this evidence domain, verified these bytes against a registered key and durably accepted them at `received_at`." It is not a signature by the Collector. A Collector that wants to provide a signed or anchored receipt does so through an extension and separate specification.

### 7.4 Producer-chain flags

Producers sequence their records in chains (`producer_chain`). Records may arrive out of order. The Collector evaluates position by `sequence_number`, never by arrival order, and sets these flags in the receipt. Flags describe the state at the moment of acceptance and are reproduced unchanged on replay. Current state is available through retrieval interfaces outside this document.

| Flag | Set when | Rejection? |
|---|---|---|
| `coverage_gap_flag` | The record at `sequence_number − 1` on the same `(producer_id, producer_instance_id, producer_chain_id)` is not held. | No. The record is accepted. |
| `chain_link_failure_flag` | The record at `sequence_number − 1` is held, but its `content_digest` differs from this record's `prev_record_hash`. | No. The record is accepted. |
| `equivocation_flag` | A different record, with a different `record_id` and a valid signature, is already held at the same `(producer_id, producer_instance_id, producer_chain_id, sequence_number)`. | No. Both records are retained and flagged. The Collector MUST NOT silently select one. |
| `late_flag` | The Collector's receipt time is later than `signed_at` by more than a configured lateness policy. | No. Lateness alone is never a reason to reject. |

The genesis record uses `sequence_number: 1` and the predecessor sentinel `sha256:` followed by 64 zeros. A Collector accepts a first record of a chain from any registered key (`first_observed_genesis`), and MAY additionally support chains whose genesis was registered in advance (`pre_registered_genesis`). The modes it supports are published as `producer_chain_registration_modes_supported`. Supporting a mode determines how the Collector assesses lineage later; it does not change what this API returns.

A same-`record_id` resubmission with different content is a **conflict** (§9), not an equivocation.

### 7.5 Missing correlation context

If the Collector's metadata states `execution_correlation_required: true`, a record whose `trace` lacks `trace_execution_id` or `execution_authority` MUST be rejected with `MISSING_EXECUTION_CONTEXT`. Either field alone is missing context, because the two always travel together.

If `execution_correlation_required` is `false`, the Collector MAY accept such records, and MUST then return `unattributed_flag: true` in the receipt. How the Collector later correlates them is outside this document.

---

## 8. Bulk submission

### 8.1 Request

```http
POST /api/v1/audit/trace/bulk HTTP/1.1
Authorization: Bearer <access-token>
Content-Type: application/json

[ { ...record... }, { ...record... } ]
```

- The body is a JSON array of records. The array MUST contain between 1 and `max_batch_records` elements, and the decoded body MUST NOT exceed `max_batch_bytes`.
- Unless the Collector advertises `bulk_mixed_producers_supported: true`, every record in a batch MUST have the same `producer`. A batch that mixes producers is rejected as a whole with `400 BATCH_MIXED_PRODUCERS`.
- A batch always belongs to exactly one evidence domain, the one derived from the authenticated submitter. There is no way to address more than one domain in a request.
- A Collector that does not implement bulk submission omits `trace_bulk_ingestion_endpoint` from its metadata.

Envelope failures reject the whole request and process nothing:

| Condition | Status | Code |
|---|---|---|
| Body is not a JSON array, or is not strict JSON | `400` | `MALFORMED_JSON` |
| Empty array | `400` | `BATCH_EMPTY` |
| More than `max_batch_records` elements | `400` | `BATCH_TOO_MANY_RECORDS` |
| Decoded body larger than `max_batch_bytes` | `413` | `REQUEST_TOO_LARGE` |
| Mixed producers without support | `400` | `BATCH_MIXED_PRODUCERS` |
| Submitter not permitted for the batch's single producer | `403` | `SUBMITTER_NOT_AUTHORIZED` |
| Authentication, scope, domain, media type, rate | `401`, `403`, `415`, `429` | as in §10 |

When mixed producers are supported, `SUBMITTER_NOT_AUTHORIZED` is reported per element.

### 8.2 Processing semantics

- Each record is processed independently, exactly as a single submission. A batch is N single-record ingestions that share one HTTP request. It is not a transaction.
- A failure on one record (bad signature, unknown key, conflict, size, storage failure) MUST NOT reject, delay the acknowledgement of, or alter the result of any other record.
- Each accepted record is committed atomically and durably under §7.2 before its element reports `accepted: true`. The Collector MUST NOT report any element accepted before that element's own commit.
- A non-object element, or an element that is not a valid record, is rejected on its own with a per-element error. It does not reject the batch.
- Identity decisions among records in the same batch MUST be made as if the records were processed one at a time in array order. Therefore `[R, R]` yields a first acceptance and then a replay of the same receipt. `[R, R′]`, where `R′` reuses the identity of `R` with different content, yields an acceptance and then a conflict, not the reverse. A Collector MAY process elements concurrently if it preserves this result.

### 8.3 Response

When the envelope was valid and the Collector processed the batch, the status is `200 OK`, even if every element was rejected. `207 Multi-Status` is not used. The body is:

```json
{
  "results": [
    { "index": 0, "accepted": true, "producer_id": "...", "record_id": "...", "content_digest": "sha256:...",
      "receipt_id": "...", "received_at": "...", "idempotent_replay": false,
      "coverage_gap_flag": false, "chain_link_failure_flag": false, "equivocation_flag": false, "late_flag": false },
    { "index": 1, "accepted": false, "producer_id": "...", "record_id": "...",
      "error": { "type": "...", "title": "...", "status": 400, "code": "SIGNATURE_INVALID", "retryable": false } }
  ]
}
```

- `results` MUST contain exactly one element per request element, in request order, each with the zero-based `index` of the request element.
- An accepted element is an acceptance receipt (§6.3) plus `index`.
- A rejected element carries `accepted: false`, `index`, and `error`, a Problem Details object (§10.1) whose `status` is the status the same record would have received on the single-record endpoint. `producer_id` and `record_id` are present when they could be read from the element.
- If the Collector could not process the batch at all, it MUST respond with a request-level `503` (or `500`, `429`) and no `results`, and MUST NOT have accepted any element. It SHOULD use a request-level error when every element would fail with the same retryable condition.

### 8.4 Ordering

- Producers SHOULD place records of the same chain in ascending `sequence_number` order, and a Collector SHOULD process them in that order, but neither is required for correctness.
- A Collector MUST NOT reject, or give a different outcome to, a record because it arrived before its predecessor (§7.4). Chain position is assessed by `sequence_number`.
- No ordering is guaranteed or implied between records of different chains, producers, or batches. Receipt order is the Collector's order of acceptance, not a global event order.

### 8.5 Retry

After a `200` bulk response, a producer or forwarder MUST:

1. treat each element with `accepted: true` as complete, including elements with `idempotent_replay: true`;
2. treat each element whose error has `retryable: false` as a terminal rejection: not retry it unchanged, and surface it to an operator;
3. resubmit each element whose error has `retryable: true`, unchanged, after a backoff (§10.3). The producer MAY resubmit only those elements, or the entire batch. Resubmitting the entire batch is safe because already-accepted elements return their original receipts.

After a request-level `429`, `500`, `503`, a timeout, or a connection failure, the client MUST resubmit the same bytes, because it cannot know whether any element was accepted. Idempotency (§9) makes this safe.

---

## 9. Idempotency and conflicts

Idempotency is keyed on record identity and `content_digest`, not on the received byte sequence and not on an `Idempotency-Key` header. No such header is defined or used.

| Condition | Required behavior |
|---|---|
| Same record identity, same `content_digest` as an accepted record | Return the **original acceptance receipt** with `idempotent_replay: true` and status `200` (the first acceptance returned `201`). Do not create a second receipt, a second chain entry, or new flags. |
| Same record identity, different `content_digest`, record verifies | Return `409` with `RECORD_ID_CONFLICT`. The first-accepted record is authoritative and MUST NOT be overwritten, amended, or replaced. |
| Same chain position, different `record_id`, both verify | Not a conflict. Accept the new record with `equivocation_flag: true` (§7.4). |
| Same `record_id`, different `producer_id` | Different identity. Accept normally. |
| Same identity bytes in a different evidence domain | Different identity. Accept normally, with an independent receipt. |

Detail:

1. **The original receipt.** A replay returns the same `receipt_id`, `received_at`, `content_digest`, and integrity flags as the first acceptance, with only `idempotent_replay` changed to `true`.
2. **Semantically identical bytes.** A resubmission that differs only in whitespace, member order, or equivalent number spelling has the same `content_digest` and is a replay. A re-serializing intermediary therefore cannot cause a false conflict.
3. **Replay survives key changes.** After a record is accepted, later key rotation, revocation, or validity-window changes MUST NOT turn a replay into a rejection or change the recorded result. This is why replay detection (step 10) precedes key-validity checks (step 11). A new, different record signed by a since-revoked key is still rejected.
4. **Authorization still applies.** A replay is returned only to a submitter permitted to submit for that producer in that evidence domain (step 7). A Collector MUST NOT confirm the existence of a record identity to any other caller.
5. **Conflict only after verification.** A record is judged a conflict only after it passes key and signature verification (step 13 follows step 12), so unverified content cannot probe or provoke conflicts on an identity.
6. **Atomicity.** Under concurrent submissions the Collector MUST serialize per record identity. Two concurrent identical submissions yield exactly one first acceptance and one replay. Two concurrent submissions with the same identity and different content yield exactly one acceptance and one `409`.
7. **Conflict response.** The Problem Details object SHOULD include `producer_id`, `record_id`, `existing_content_digest`, and `submitted_content_digest`. A Collector MAY quarantine the conflicting record for investigation, but MUST NOT admit it to evidence retrieval or correlation under the contested identity.
8. **Retention.** A Collector SHOULD preserve identity and receipt data for as long as it retains the record. If retention removes a record, resubmitting it is a new first acceptance.

---

## 10. Errors

### 10.1 Problem Details

Every error response from an ingestion endpoint, and every per-element `error` in a bulk response, is an RFC 9457 Problem Details object. Request-level errors use `Content-Type: application/problem+json`.

| Member | Required | Content |
|---|---|---|
| `type` | REQUIRED | `https://govops.owasp.org/trace/errors/` followed by the lowercase, hyphenated error code (for example `.../signature-invalid`). |
| `title` | REQUIRED | Short, stable, human-readable summary. |
| `status` | REQUIRED | The HTTP status. |
| `code` | REQUIRED | One of the codes in §10.2. |
| `retryable` | REQUIRED | `true` if retrying the identical bytes later, without operator action, can succeed. |
| `detail` | OPTIONAL | Human-readable explanation for this occurrence. |
| `instance` | OPTIONAL | A URI identifying this occurrence. |
| `producer_id`, `record_id` | OPTIONAL | Where applicable. |
| `existing_content_digest`, `submitted_content_digest` | OPTIONAL | On `RECORD_ID_CONFLICT`. |

An error body MUST NOT contain a bearer token, signed record content, a signature, or any information about another evidence domain. `detail` MUST NOT reveal whether a record identity exists to a caller not permitted to know (§9).

### 10.2 Error codes

| Code | HTTP | Retryable | Condition | Client action |
|---|---|---|---|---|
| `UNAUTHENTICATED` | 401 | no | Missing, expired, or invalid access token | Obtain a new token, then resubmit (once per failure) |
| `INSUFFICIENT_SCOPE` | 403 | no | Token lacks the ingestion scope | Fix client registration |
| `EVIDENCE_DOMAIN_NOT_BOUND` | 403 | no | Submitter has no evidence-domain binding | Operator action |
| `SUBMITTER_NOT_AUTHORIZED` | 403 | no | Submitter may not submit for this `producer_id` | Operator action |
| `UNSUPPORTED_MEDIA_TYPE` | 415 | no | `Content-Type` or `Content-Encoding` not supported | Fix request |
| `REQUEST_TOO_LARGE` | 413 | no | Decoded body exceeds `max_batch_bytes` | Split the batch |
| `RECORD_TOO_LARGE` | 413 | no | A record exceeds `max_record_bytes` | Terminal for that record |
| `BATCH_TOO_MANY_RECORDS` | 400 | no | More than `max_batch_records` elements | Split the batch |
| `BATCH_EMPTY` | 400 | no | Empty batch | Fix request |
| `BATCH_MIXED_PRODUCERS` | 400 | no | Mixed producers and mixing is not supported | Split by producer |
| `MALFORMED_JSON` | 400 | no | Not strict JSON, not an object/array as required, duplicate member, or too deep | Terminal for that record |
| `SCHEMA_INVALID` | 400 | no | Record violates the profile schema, event-kind schema, array limits, or the `record_id` form | Terminal for that record |
| `UNSUPPORTED_PROFILE` | 400 | no | `trace.eat_profile` not in `trace_profiles_supported` | Terminal for that record |
| `MISSING_EXECUTION_CONTEXT` | 400 | no | Correlation pair required and absent or incomplete | Terminal for that record |
| `PRODUCER_IDENTITY_MISMATCH` | 400 | no | `producer` differs from `producer_chain.producer_id` | Terminal for that record |
| `SIGNATURE_MALFORMED` | 400 | no | Signature is not unpadded base64url of 64 bytes | Terminal for that record |
| `KEY_UNKNOWN` | 400 | no | No key registered for `(domain, producer_id, kid)` | Operator registers key |
| `KEY_NOT_VALID` | 400 | no | Key outside its validity window or revoked | Operator action |
| `EVENT_KIND_NOT_AUTHORIZED` | 400 | no | Key may not sign this `event_kind` | Operator action |
| `SIGNATURE_INVALID` | 400 | no | Signature does not verify | Terminal for that record |
| `RECORD_ID_CONFLICT` | 409 | no | Identity already bound to different content | Terminal; investigate |
| `RATE_LIMITED` | 429 | yes | Rate limit | Wait `Retry-After`, then retry |
| `COLLECTOR_UNAVAILABLE` | 503 | yes | Storage or a required dependency unavailable; nothing accepted | Back off, retry |
| `COLLECTOR_INTEGRITY_HOLD` | 503 | yes | Collector refuses submissions until an operator resolves an integrity condition; nothing accepted | Back off for a long interval, retry |
| `INTERNAL_ERROR` | 500 | yes | Unexpected failure; nothing accepted | Back off, retry a bounded number of times |

Additional rules:

- Statuses in this table are normative. In particular, a Collector MUST use `503`, not `500`, when it deliberately reports a retryable storage or dependency outage, and MUST use `413`, not `400`, for oversized bodies and records.
- A Collector MAY return a more specific problem `type` for a code, but the `code` and `status` MUST NOT change.
- A Collector MAY collapse `KEY_UNKNOWN`, `KEY_NOT_VALID`, and `EVENT_KIND_NOT_AUTHORIZED` into `KEY_UNKNOWN` to avoid disclosing registry contents to a submitter not entitled to see them. It MUST NOT use a code that falsely implies the key was authorized.
- A Collector MUST NOT reveal through the code or status that a record identity exists in another evidence domain.
- Errors that are not listed use the closest HTTP status with Problem Details and one of the codes above; a Collector MUST NOT invent a new `code` within `v1`.

### 10.3 Retry behavior

- A client MUST NOT retry a response whose `retryable` is `false` unchanged. It MAY retry after an operator has acted (for example, registered a key).
- A client MUST retry `retryable: true` outcomes, timeouts, and connection failures with the **same bytes** (or a JCS-equivalent serialization), using exponential backoff with jitter. It MUST honor `Retry-After` (RFC 9110 §10.2.3) when present. RECOMMENDED: initial delay 1 s, factor 2, cap 5 min, full jitter.
- A client that depends on evidence delivery SHOULD keep unacknowledged records in durable local storage until it receives a receipt or a terminal rejection. Dropping a record after a bounded number of retries is a client policy decision and is evidence loss.
- A client MUST NOT change a record's content and resubmit it under the same `record_id`. A corrected record is a new record with a new `record_id` and a new chain position.

---

## 11. Discovery

### 11.1 Location

```http
GET /.well-known/govops-trace-configuration HTTP/1.1
Host: collector.example.org
```

- The document is served over HTTPS, without authentication, as `application/json`, with status `200`.
- It MUST contain no per-tenant, per-client, or secret information.
- A Collector served under a path prefix publishes the document at the well-known location for its origin and MAY additionally serve it under the prefix. In every case, `issuer` identifies the Collector.
- A Collector SHOULD send `Cache-Control` with a `max-age`. A client SHOULD cache for that period (default one hour if absent), and MUST re-fetch after a `404`, `410`, or repeated `UNSUPPORTED_PROFILE` or limit errors.
- A client MUST ignore members it does not recognize.

### 11.2 Members

| Member | Type | Required | Meaning |
|---|---|---|---|
| `issuer` | string (HTTPS URL) | REQUIRED | Identifier of the Collector. MUST equal the origin (and path prefix, if any) from which this document was retrieved. A client MUST reject the document otherwise. |
| `api_versions_supported` | array of string | REQUIRED | Supported API versions, such as `["v1"]`. |
| `trace_ingestion_endpoint` | string (URL) | REQUIRED | Single-record submission URL. |
| `trace_bulk_ingestion_endpoint` | string (URL) | CONDITIONAL | Bulk submission URL. Present if and only if bulk is supported. |
| `trace_profiles_supported` | array of string | REQUIRED | Accepted `trace.eat_profile` values. |
| `event_kinds_supported` | array of string | RECOMMENDED | Event kinds the Collector accepts. |
| `signature_algorithms_supported` | array of string | REQUIRED | For `v1`, `["Ed25519"]`. |
| `canonicalization_methods_supported` | array of string | RECOMMENDED | For `v1`, `["RFC8785"]`. |
| `authorization_servers` | array of string (issuer URLs) | REQUIRED | OAuth 2.0 authorization servers whose tokens the Collector accepts. A client obtains each server's metadata by RFC 8414 or OpenID Connect Discovery at its issuer identifier. This member has the meaning defined for OAuth protected resource metadata in RFC 9728. |
| `ingestion_scope` | string | REQUIRED | The scope required by both ingestion endpoints. |
| `scopes_supported` | array of string | OPTIONAL | Other scopes the Collector defines. |
| `max_record_bytes` | integer | REQUIRED | Maximum decoded bytes in one record (§5.8). |
| `max_batch_bytes` | integer | CONDITIONAL | Maximum decoded bytes in a bulk request body. Present if bulk is supported. |
| `max_batch_records` | integer | CONDITIONAL | Maximum records in a batch. Present if bulk is supported. |
| `max_nesting_depth` | integer | RECOMMENDED | Maximum JSON nesting depth. |
| `bulk_mixed_producers_supported` | boolean | OPTIONAL | Default `false`. |
| `execution_correlation_required` | boolean | RECOMMENDED | Whether records without the full correlation pair are rejected (§7.5). Default `true` when absent. |
| `producer_chain_registration_modes_supported` | array of string | REQUIRED | Any of `first_observed_genesis`, `pre_registered_genesis`, `linked_restart_genesis`. A Collector MUST support `first_observed_genesis` or `pre_registered_genesis` and MUST list every mode it supports. |
| `acceptance_durability` | string | OPTIONAL | `local_durable` or `replicated_durable` (§7.2). A Collector that omits it makes no replication claim. |
| `content_encodings_supported` | array of string | OPTIONAL | For example `["gzip"]`. Absent means none. |

The limits MUST be values that every authorized submitter can rely on. A Collector MAY grant a particular submitter higher limits, but MUST NOT enforce lower ones than it publishes.

### 11.3 Example

```json
{
  "issuer": "https://collector.example.org",
  "api_versions_supported": ["v1"],
  "trace_ingestion_endpoint": "https://collector.example.org/api/v1/audit/trace",
  "trace_bulk_ingestion_endpoint": "https://collector.example.org/api/v1/audit/trace/bulk",
  "trace_profiles_supported": ["tag:govops.owasp.org,2026:trace-v1"],
  "event_kinds_supported": ["AUTHORIZATION_DECISION", "CAPABILITY_INVOKED", "RUNTIME_EFFECT"],
  "signature_algorithms_supported": ["Ed25519"],
  "canonicalization_methods_supported": ["RFC8785"],
  "authorization_servers": ["https://auth.example.org"],
  "ingestion_scope": "trace.write",
  "scopes_supported": ["trace.write"],
  "max_record_bytes": 262144,
  "max_batch_bytes": 8388608,
  "max_batch_records": 500,
  "max_nesting_depth": 32,
  "bulk_mixed_producers_supported": false,
  "execution_correlation_required": true,
  "producer_chain_registration_modes_supported": ["first_observed_genesis", "pre_registered_genesis"],
  "acceptance_durability": "replicated_durable",
  "content_encodings_supported": ["gzip"]
}
```

---

## 12. Intermediaries

Producers MAY reach a Collector through intermediaries. This section applies to every component that receives a signed record from a producer (or another intermediary) and later submits it to a Collector, including:

- an authenticated HTTP forwarder or gateway;
- an OpenTelemetry Collector that receives OTLP and exports to this API;
- a Kafka-backed (or other broker-backed) ingestion adapter: a producer writes to a topic and a consumer submits to the Collector.

The evidence is the signed record. An intermediary is a courier. It has no authority to alter, vouch for, or complete the record.

### 12.1 Requirements on forwarders

A forwarder is conforming only if it satisfies all of the following.

**Authentication and evidence domain**

- **FW-1** A forwarder MUST authenticate to the Collector with its own OAuth 2.0 client credentials. It MUST NOT strip authentication, share one credential across evidence domains, or present a producer's token as proof of its own authority.
- **FW-2** A forwarder serving records for more than one evidence domain MUST keep a separate credential and a separate durable queue (or topic) per evidence domain, and MUST NOT combine records from different domains into one request or one queue. It MUST NOT choose the domain from record content, because the Collector derives the domain from the credential.

**Preservation of signed assertions**

- **FW-3** A forwarder MUST deliver each record so that the JCS form of the delivered record is identical to the JCS form of the record the producer signed. It MUST NOT add, remove, rename, truncate, normalize, or re-encode any signed member, MUST NOT re-sign, and MUST NOT wrap the record in a way the Collector would store as the assertion.
- **FW-4** A forwarder SHOULD forward the original bytes unchanged. If it parses and re-serializes, it MUST use a strict JSON implementation (rejecting rather than collapsing duplicate member names), MUST preserve string content and number values exactly, and MUST NOT pass records through a lossy intermediate data model (for example, converting integers to floating point, or splitting a record into typed attributes and re-assembling it). The RECOMMENDED carriage is as opaque text or bytes (Appendix D).
- **FW-5** A forwarder MUST NOT infer, set, or replace any evidence field (producer identity, `kid`, correlation values, evidence domain, trust claims) from unsigned transport metadata such as OTLP attributes, resource attributes, Kafka headers, topic names, or HTTP headers. Such metadata is a routing and correlation hint only.

**Producer authorization**

- **FW-6** A forwarder MUST submit only for producers that the Collector's configuration permits it to forward for (§4.5). Its permission is necessary and never sufficient: the Collector verifies each record's signature and key authority regardless of who forwarded it.
- **FW-7** A forwarder MAY pre-verify signatures to discard obviously corrupt input or to raise an operator alarm. It MUST NOT silently drop, repair, or "fix up" a record, and MUST NOT treat its own verification as a substitute for the Collector's.

**Durable acknowledgement**

- **FW-8** Only a Collector receipt (a `201` or `200` from the single-record endpoint, or an element with `accepted: true`) means a record was accepted. A forwarder MUST NOT report to its upstream that a record was accepted by the Collector until it holds that receipt for that record.
- **FW-9** A forwarder MAY durably queue a record and acknowledge custody to its upstream before the Collector responds, but the acknowledgement MUST be distinguishable from Collector acceptance (for example, by status name or protocol semantics). The upstream MUST NOT be led to believe the evidence is held by the Collector. For example, an OTLP `Export` success means only that the OpenTelemetry Collector received the data.
- **FW-10** A forwarder that acknowledges custody MUST persist the record durably before doing so, and MUST retain it, across restarts, until the Collector returns an acceptance or a terminal rejection for it.
- **FW-11** A forwarder MUST provide at-least-once delivery and rely on Collector idempotency (§9) to absorb duplicates. It MUST NOT drop a record because of a `retryable: true` error, a timeout, or a connection failure.
- **FW-12** A forwarder MUST NOT retry a terminal rejection (`retryable: false`) unchanged. It MUST surface it, including the Problem Details `code` and `record_id`, to an operator or a dead-letter destination. It MUST NOT silently discard it.
- **FW-13** A forwarder that consumes from a broker MUST NOT advance or commit its consumption position for a record until that record has an acceptance or a terminal rejection that has been surfaced.

**Operation**

- **FW-14** A forwarder MUST follow §10.3 for retries and honor `Retry-After`.
- **FW-15** A forwarder MUST respect the limits and capabilities in Collector metadata (record and batch size, `bulk_mixed_producers_supported`), and MUST re-read metadata after limit-related errors.
- **FW-16** A forwarder MUST NOT depend on ordering. It MAY preserve or reorder records.
- **FW-17** A forwarder MUST NOT log bearer tokens, and SHOULD NOT log record content; logging `producer_id`, `record_id`, `content_digest`, and result codes is sufficient.

### 12.2 Requirements on Collectors with respect to intermediaries

- **CO-1** A Collector MUST treat a forwarded record exactly as a directly submitted record: authorization, key resolution, signature verification, event-kind permission, identity, idempotency, and flags are identical.
- **CO-2** A Collector MUST bind the evidence domain to the forwarder's credential, never to anything in the record or transport metadata.
- **CO-3** A Collector MUST store the signed assertion unchanged. It MUST NOT record the forwarder as the producer. It MAY record the submitter's identity as ingestion metadata outside the assertion.
- **CO-4** A Collector MUST NOT return a receipt for a record before durable acceptance (§7.2), even if the forwarder is highly trusted. Forwarders rely on this to implement FW-8.

### 12.3 Informative transport bindings

OTLP and Kafka bindings are described in Appendix D. They are informative. The normative requirements are those above.

---

## 13. Security considerations

**Threat model.** An attacker may be: an unauthenticated network party; an authenticated client acting outside its permission; a malicious or compromised producer; a malicious or compromised intermediary; or a malicious tenant of a multi-domain Collector. The Collector's operator is trusted to run the Collector faithfully; this API does not protect against an operator that rewrites its own storage (see the receipt-scope limitation in §7.3).

**Replay.**
- Resubmitting a captured record cannot create a second record: identity and digest make it a replay (§9). A replay returns only the original receipt and reveals nothing new, and only to a submitter permitted for the producer.
- A replayed record cannot move into another evidence domain unless that domain independently registers the producer key and binds the submitter. Registering a key in two domains is an explicit operator decision.
- Access tokens are bearer credentials. Sender-constrained tokens (RFC 9449, RFC 8705) limit replay of the request itself. TLS protects tokens in transit.
- Producer timestamps are claims. A Collector MUST NOT use `signed_at` to reject a record as a replay, and MUST use its own `received_at` for receipt order.

**Unauthorized submission.**
- Authorization precedes content processing (§4.6). A submitter not permitted for a producer learns nothing about keys or records (§4.5, step 7).
- Submitter-to-producer permission should follow least privilege. A forwarder holding permission for many producers is a high-value credential; use sender-constrained tokens, narrow `ingestion_scope`, and separate credentials per evidence domain.

**Signature verification.**
- Use constant-time, reviewed Ed25519 implementations. Reject non-canonical signature encodings and duplicate JSON members, so one signed value cannot have two interpretations.
- Verify against the key selected by the signed `kid`; never guess from time, and never accept a key from the request.
- Strict JSON (§5.2) is part of verification. A parser that keeps the last duplicate member lets an attacker present different content to the Collector and to an auditor.
- A valid signature is necessary but not sufficient. It does not establish truth, completeness, independent observation, or successful enforcement. Collectors and consumers MUST NOT present accepted evidence as more than the record kind establishes.

**Resource exhaustion.**
- Enforce byte, count, depth, and rate limits before cryptographic work (§4.6, §5.8). Enforce decoded-size limits during decompression.
- Bound per-request work: a batch with many invalid signatures costs one verification each, so apply rate limits per client and consider per-client limits on failed records.
- Ed25519 verification is cheap but not free. Reject malformed encodings and unauthorized submitters before verifying.
- Return `429` with `Retry-After` rather than queuing without bound. Never acknowledge from an unbounded queue (§7.2).

**Tenant isolation.**
- Derive the evidence domain only from the authenticated credential (§4.4). Scope every key lookup, identity lookup, receipt, and error message to it.
- Do not let error text, status codes, or response timing that the Collector controls distinguish "exists in another domain" from "does not exist".
- Registry entries are per domain. Possession of a signing key never grants cross-domain access.

**Sensitive evidence.** See §14.

**Compromised intermediaries.** A compromised forwarder, OpenTelemetry Collector, or broker can drop, delay, duplicate, reorder, or replay records, and can submit any signed record it has seen. It cannot forge a record for a registered key. Effects and mitigations:
- *Dropping or delaying* is not preventable by the Collector. It is detectable as producer-chain coverage gaps (`coverage_gap_flag`) and by `late_flag`. Producers that need stronger assurance use direct submission, or keep a local durable copy until receipt.
- *Substitution or alteration* fails signature verification. The Collector therefore rejects the altered record, and the original remains valid for resubmission.
- *Duplication and replay* are absorbed by idempotency.
- *Cross-domain misdirection*: a forwarder with credentials for several domains could place a record in the wrong domain. FW-2 requires separate credentials and queues, and Collectors SHOULD limit each credential to one domain.
- *Over-broad permission*: a compromised forwarder can submit signed records it holds for any producer it may forward for. Limit the producer set per forwarder.
- *False acknowledgement upstream*: a faulty forwarder might report acceptance it did not obtain. FW-8 and FW-9 require distinguishing custody from acceptance. A producer that needs proof compares the receipt's `content_digest` with its own computation, obtained by direct submission or from retrieval.

**Key compromise.** Revoking a registry key stops new records from that key. It does not rewrite earlier acceptance results (§9). Records signed with a compromised key before revocation remain accepted and are an assessment concern.

**Error and log hygiene.** Do not echo record content or tokens in errors or logs. Treat `detail` strings that quote attacker-controlled values as untrusted when rendering.

**Downgrade.** `v1` has a single signature algorithm and canonicalization. A future version adds algorithms under a new profile identifier and an explicit verifier policy, not through a record-selected algorithm.

---

## 14. Privacy considerations

- TRACE records can contain identifiers of workloads, instances, human sponsors, token issuers and `jti` values, action names, resource types, and timestamps. Together they describe who did what and when. They are sensitive operational and personal data.
- Records MUST NOT contain raw bearer tokens or other credentials. Token references use issuer plus `jti` or a fingerprint.
- Producers SHOULD minimize personal data in signed fields and prefer pseudonymous or workload identifiers, because an accepted assertion cannot be edited. Erasure requests cannot be met by changing a signed assertion; a Collector that must support erasure needs a retention and deletion policy applied to whole records, with the tamper-evidence consequences documented to its users.
- A Collector MUST isolate evidence by domain, MUST protect stored evidence with access control and encryption at rest appropriate to its sensitivity, and SHOULD apply a documented retention period.
- A Collector MUST NOT expose evidence through this API's responses beyond the receipt. Retrieval is a separate, separately authorized interface.
- Discovery metadata is public and MUST NOT reveal tenants, clients, producers, or registry contents.
- Intermediaries see full record content. An intermediary under different administrative control from the producer is a processor of that data. Use TLS on every hop and apply FW-17.
- Error responses, logs, and metrics MUST NOT include record content or tokens.

---

## 15. Conformance

### 15.1 Classes

| Class | Applies to | Must satisfy |
|---|---|---|
| **Collector** | A server offering the single-record endpoint and metadata | §3, §4, §5, §6, §7, §9, §10, §11, §12.2, and tests C-*, D-*, X-* |
| **Collector-Bulk** | A Collector that also offers the bulk endpoint | the Collector class, §8, and tests B-* |
| **Producer** | A component that signs records and submits them directly or through an intermediary | §5.3 to §5.6, §10.3, and tests P-* |
| **Forwarder** | A component that relays records from producers to a Collector | §12.1 and tests F-* |

A claim of conformance MUST name the class, the API version (`v1`), and the profile identifiers tested. A Collector that passes the tests but advertises limits or capabilities it does not enforce is not conforming.

Each test is independent and observable from outside the Collector's storage. Tests marked **(hook)** need an operator-supplied test hook, such as fault injection or read access to an evidence domain. A Collector that cannot supply a hook MUST say so in its conformance claim; the corresponding requirement is then unverified, not passed.

### 15.2 Reference fixture

Unless a test says otherwise, it starts from an empty record store and this configuration.

| Item | Value |
|---|---|
| Evidence domains | `D1`, `D2` |
| Client `c-pdp` | bound to `D1`; ingestion scope; may submit for producer `pdp-fleet-1` |
| Client `c-pep` | bound to `D1`; ingestion scope; may submit for producer `payments-gateway-pep` |
| Client `c-fwd` | bound to `D1`; ingestion scope; may submit for both producers |
| Client `c-ro` | bound to `D1`; a token without the ingestion scope |
| Client `c-nodom` | ingestion scope; no evidence-domain binding |
| Client `c-d2` | bound to `D2`; ingestion scope; may submit for `pdp-fleet-1`; no keys registered in `D2` |
| Registry `D1` | `pdp-fleet-1` / `key-2026-01` authorizing `AUTHORIZATION_DECISION`; `payments-gateway-pep` / `pep-key-2026-01` authorizing `CAPABILITY_INVOKED`. Public keys are in Appendix C.1. |
| Metadata | `execution_correlation_required: true`, `bulk_mixed_producers_supported: false`, `first_observed_genesis` supported, `trace_profiles_supported` contains `tag:govops.owasp.org,2026:trace-v1` |
| Limits | The Collector's published limits. Tests that exceed a limit read it from metadata. |

Vector identifiers (`V-nn`) refer to Appendix C.

### 15.3 Collector tests

| ID | Requirements | Procedure | Expected |
|---|---|---|---|
| C-01 | §6, §7.2 | `c-pdp` submits V-01. | `201`; receipt with every REQUIRED member; `idempotent_replay` false; all four flags false; `content_digest` equals the value in Appendix C.3. |
| C-02 | §9 | Submit V-01, then V-01 again. | First `201`, second `200`. The second has the same `receipt_id`, `received_at`, `content_digest`; `idempotent_replay` true. No second receipt exists **(hook)**. |
| C-03 | §5.7, §9 | Submit V-01, then V-06 (V-01 re-serialized). | `200` replay with the original receipt. |
| C-04 | §9 | Submit V-01, then V-20. | Second: `409`, `RECORD_ID_CONFLICT`, `retryable` false. The stored record is still V-01 **(hook)**. |
| C-05 | §4.5, §7.1 | Submit V-10 on an empty store, and again after V-01 is accepted. | Both: `400 SIGNATURE_INVALID`. No receipt. Nothing retrievable **(hook)**. |
| C-06 | §4.5 | Submit V-11. | `400 KEY_UNKNOWN`. |
| C-07 | §4.5 | Submit V-12. | `400 EVENT_KIND_NOT_AUTHORIZED` (or `KEY_UNKNOWN` if the Collector collapses codes, §10.2). Never accepted. |
| C-08 | §5.3 | Submit V-13. | `400 PRODUCER_IDENTITY_MISMATCH`. |
| C-09 | §7.5 | Submit V-14. | `400 MISSING_EXECUTION_CONTEXT`. |
| C-10 | §5.3 | Submit V-15. | `400 UNSUPPORTED_PROFILE`. |
| C-11 | §5.4 | Submit V-16. | `400 SIGNATURE_MALFORMED`. |
| C-12 | §5.6 | Submit V-17. | `400 SCHEMA_INVALID`. |
| C-13 | §5.2 | Submit V-18 as the raw body. | `400 MALFORMED_JSON`. No record is accepted. |
| C-14 | §7.4 | Submit V-02, then V-01. | V-02: `201`, `coverage_gap_flag` true. V-01: `201`, all flags false. Neither is rejected for arrival order. |
| C-15 | §7.4 | Submit V-01, then V-22. | V-22: `201`, `chain_link_failure_flag` true. |
| C-16 | §7.4 | Submit V-01, then V-21. | V-21: `201`, `equivocation_flag` true. Both records are retained **(hook)**. |
| C-17 | §4.2 | Submit V-01 with no token, then with an expired token. | `401 UNAUTHENTICATED`, with `WWW-Authenticate`. |
| C-18 | §4.3 | `c-ro` submits V-01. | `403 INSUFFICIENT_SCOPE`. |
| C-19 | §4.4 | `c-nodom` submits V-01. | `403 EVIDENCE_DOMAIN_NOT_BOUND`. |
| C-20 | §4.5, §4.6 | `c-pep` submits V-01 and then V-10. | Both `403 SUBMITTER_NOT_AUTHORIZED`. The tampered record yields the same error as the valid one, showing authorization precedes verification. |
| C-21 | §4.4 | `c-d2` submits V-01. Register `pdp-fleet-1` / `key-2026-01` in `D2` and resubmit. | First: `400 KEY_UNKNOWN`. Second: `201` with a first acceptance (`idempotent_replay` false) and a receipt independent of any `D1` receipt. No `D1` record, receipt, or identity is observable in either response. |
| C-22 | §12.2 CO-1 | `c-fwd` submits V-01 and V-03 (single-record endpoint). | Both `201`. Outcomes equal those for direct submission. |
| C-23 | §7.2 **(hook)** | Fail the durable write during V-01. | `503 COLLECTOR_UNAVAILABLE` (or `500`), `retryable` true. No receipt, record, or index entry visible. After recovery, resubmission yields `201` with `idempotent_replay` false. If the write is made to succeed but the response is lost, resubmission yields `200` with `idempotent_replay` true. |
| C-24 | §5.8 | Submit a signed record larger than `max_record_bytes` (generated by padding a signed member). | `413 RECORD_TOO_LARGE`. The Collector does not verify the signature first **(hook)**. A record of exactly `max_record_bytes` is accepted. |
| C-25 | §5.1 | Submit V-01 with `Content-Type: text/plain`, then with an unadvertised `Content-Encoding`. | `415 UNSUPPORTED_MEDIA_TYPE`. |
| C-26 | §4.4 | `c-pdp` submits V-05 (signed body names `evidence_domain_id: "D2"`). | `201`. The record is held in `D1` only; `D2` holds nothing **(hook)**. The body member is preserved in the stored assertion. |
| C-27 | §9, item 6 | Send V-01 twice concurrently; separately, V-01 and V-20 concurrently. | First pair: one `201` (`idempotent_replay` false), one `200` (true), same receipt. Second pair: one `201`, one `409`. |
| C-28 | §9, item 3 **(hook)** | Accept V-01. Revoke `key-2026-01`. Resubmit V-01. Submit V-02. | V-01: `200` replay, original receipt. V-02: `400 KEY_NOT_VALID`. |
| C-29 | §10.1 | Inspect every error produced by C-04 to C-28. | `application/problem+json`; `type`, `title`, `status`, `code`, `retryable` present; no token, record content, or other-domain data. |
| C-30 | §6.3 | Inspect `received_at` and `receipt_id` from C-01. | `received_at` matches `YYYY-MM-DDThh:mm:ss.sssZ`. `receipt_id` is a non-empty string. |
| C-31 | §4.1 | Attempt a cleartext HTTP submission with a token. | Connection refused, or no request processing; no redirect carrying the token. |
| C-32 | §7.1 | Submit a record that fails verification on a Collector that quarantines **(hook)**. | Response is a rejection with no receipt. The record is absent from retrieval and correlation. |
| C-33 | §7.2 **(hook)** | Kill the Collector between accepting a request and the durable commit. | No receipt was returned. After restart, resubmission is a first acceptance. |
| C-34 | §12.2 CO-3 | `c-fwd` submits V-01 and V-03. Retrieve the stored assertions. | JCS of each stored assertion equals JCS of the submitted record. The forwarder is not recorded as the producer. |

### 15.4 Bulk tests

| ID | Requirements | Procedure | Expected |
|---|---|---|---|
| B-01 | §8.2, §8.3 | `c-pdp` submits `[V-01, V-10, V-02]`. | `200`. `results[0]` accepted, `results[1]` `SIGNATURE_INVALID` (status 400), `results[2]` accepted. `index` values are 0, 1, 2. V-02's `coverage_gap_flag` is false because V-01 precedes it. |
| B-02 | §8.1 | `c-fwd` submits `[V-01, V-03]`. | `400 BATCH_MIXED_PRODUCERS`. Nothing accepted **(hook)**. |
| B-03 | §8.1 | Submit `[]`. | `400 BATCH_EMPTY`. |
| B-04 | §8.1 | Submit `max_batch_records + 1` records. | `400 BATCH_TOO_MANY_RECORDS`. Nothing accepted. |
| B-05 | §8.1 | Submit a body larger than `max_batch_bytes`. | `413 REQUEST_TOO_LARGE`. |
| B-06 | §8.5, §9 | Repeat B-01. | `200`. `results[0]` and `results[2]` are `idempotent_replay` true with original receipts. `results[1]` is rejected again. |
| B-07 | §8.2 | Submit `[V-01, V-01]`, then (fresh store) `[V-01, V-20]`. | First: accepted, then replay of the same receipt. Second: accepted, then `409 RECORD_ID_CONFLICT` as that element's error. |
| B-08 | §8.4 | Submit `[V-02, V-01]`. | `200`. Both accepted. V-02 `coverage_gap_flag` true. Arrival order does not cause rejection. |
| B-09 | §8.2 | Submit `[V-01, <oversized record>, V-02]`. | `200`. The oversized element is `RECORD_TOO_LARGE`. The others are accepted. |
| B-10 | §8.2 | Submit `[V-01, 42]`. | `200`. `results[1]` is `MALFORMED_JSON`. `results[0]` is accepted. |
| B-11 | §8.1 | `c-pep` submits `[V-01]`. | `403 SUBMITTER_NOT_AUTHORIZED`, request level. |
| B-12 | §8.3 **(hook)** | Fail the durable write for one element only. | `200`. That element is `COLLECTOR_UNAVAILABLE`, `retryable` true. Other elements are accepted. |
| B-13 | §8.3 | Submit a batch where all elements are valid. | `200` (not `201`, `202`, or `207`). |
| B-14 | §8.2 | Submit `[V-01, V-02]`. Record the order of acceptance **(hook)**. | `results` is in request order regardless of internal processing order. |

### 15.5 Discovery tests

| ID | Requirements | Procedure | Expected |
|---|---|---|---|
| D-01 | §11.1 | `GET /.well-known/govops-trace-configuration` without credentials. | `200`, `application/json`, all REQUIRED members for the class. |
| D-02 | §11.2 | Compare `issuer` with the retrieval origin. | Equal. |
| D-03 | §11.2 | Call each advertised endpoint. | Each is served. `trace_bulk_ingestion_endpoint` is absent if bulk is unsupported. |
| D-04 | §5.8, §11.2 | For each advertised limit, submit a request at the limit and one beyond it. | At the limit: processed. Beyond: the specified rejection. |
| D-05 | §11.2 | Submit V-15 (profile not listed). Submit V-01 (profile listed). | `UNSUPPORTED_PROFILE`; accepted. |
| D-06 | §4.2, §11.2 | Use a valid token from a listed authorization server, then one from an unlisted issuer. | Accepted; `401 UNAUTHENTICATED`. |
| D-07 | §11.2 | Inspect the document. | No tenant, client, producer, or key information. |
| D-08 | §11.2 | Inspect `producer_chain_registration_modes_supported`. | Contains `first_observed_genesis` or `pre_registered_genesis`, and only modes the Collector supports. |

### 15.6 Producer tests

| ID | Requirements | Procedure | Expected |
|---|---|---|---|
| P-01 | §5.4 | Verify a producer's output for V-01's content class with the public key. | Ed25519 signature verifies over JCS minus `signature`; `kid` is inside the signed scope; signature is unpadded base64url. |
| P-02 | §5.6 | Generate 10,000 records. | Every `record_id` is a lowercase UUID or an uppercase ULID, and is unique for the producer. |
| P-03 | §5.5 | Compare the producer's own `content_digest` with the receipt's. | Equal, or the producer reports a mismatch as an error. |
| P-04 | §10.3 | Stub returns `503` twice, then `201`. | The producer resubmits identical bytes, with increasing delays, and records success only after the `201`. |
| P-05 | §10.3 | Stub returns `429` with `Retry-After: 2`. | The producer waits at least 2 s. |
| P-06 | §10.3 | Stub returns a terminal `400`. | The producer does not resubmit unchanged and surfaces the `code`. |
| P-07 | §10.3 | Stub drops the connection after reading the request. | The producer resubmits the same bytes. |
| P-08 | §10.3 | Producer restarts with unacknowledged records. | Records are resubmitted from durable storage, or the producer's documentation states that it does not buffer durably. |
| P-09 | §5.8, §8.1 | Metadata states small limits and no mixed producers. | The producer's requests respect them. |
| P-10 | §10.3 | Producer needs to fix a rejected record. | The corrected record has a new `record_id`; the producer never resubmits changed content under the old one. |
| P-11 | §14 | Inspect produced records. | No raw bearer tokens or credentials. |
| P-12 | §7.5 | Producer has no correlation pair for an event while the Collector requires it. | The producer does not submit, or reports the condition. It does not invent values. |

### 15.7 Forwarder tests

| ID | Requirements | Procedure | Expected |
|---|---|---|---|
| F-01 | FW-3, FW-4 | Pass V-01, V-03, V-04, V-06 through the forwarder. | The JCS form, and therefore `content_digest`, of each delivered record equals the source's. V-04 (non-ASCII values) is not altered by re-encoding. |
| F-02 | FW-3, FW-7 | Pass V-10 through the forwarder. | It is delivered unchanged (or surfaced), never repaired. The Collector returns `SIGNATURE_INVALID`. |
| F-03 | FW-2 | Feed records for `D1` and `D2` through a forwarder with a credential per domain. | Each request uses the matching credential. No request contains records from both domains. |
| F-04 | FW-8, FW-9 | The Collector stub delays its response. | Before the receipt, the forwarder reports at most custody to the upstream. After it, acceptance. |
| F-05 | FW-10, FW-11 | Kill the forwarder after it acknowledged custody, then restart; the Collector stub fails twice before accepting. | Every record is delivered; the Collector shows exactly one receipt per record (replays absorb duplicates). |
| F-06 | FW-12 | The Collector returns a terminal `400` for one record. | Not retried. Surfaced with `code` and `record_id`. |
| F-07 | FW-14 | The Collector returns `429` with `Retry-After` and `503`. | Backoff and `Retry-After` honored. |
| F-08 | FW-5 | Set conflicting producer identity and domain in transport metadata (OTLP attributes or Kafka headers). | No effect on the submitted record, credential choice for the producer identity, or Collector decisions. |
| F-09 | FW-15, FW-1 | Metadata states limits and no mixed producers. | Batches respect limits and producer uniformity. The forwarder authenticates with its own credential. |
| F-10 | FW-13 | Broker-backed forwarder; Collector unavailable. | The consumer position does not advance. After recovery, delivery completes. |
| F-11 | FW-17 | Inspect forwarder logs. | No tokens; no record content. |

---

## 16. IANA considerations

### 16.1 Well-known URI

This document uses the well-known URI suffix `govops-trace-configuration` (RFC 8615). Registration is requested with the following values.

- URI suffix: `govops-trace-configuration`
- Change controller: GovOps working group
- Specification document: this document, §11
- Status: provisional
- Related information: none

### 16.2 Other

No media types or link relations are registered. Problem `type` URIs under `https://govops.owasp.org/trace/errors/` are identifiers and MUST NOT be assumed to resolve.

---

## 17. References

### 17.1 Normative

- RFC 2119, RFC 8174: requirement keywords
- RFC 3339: timestamps
- RFC 4648: base64url encoding
- RFC 6749, RFC 6750: OAuth 2.0 and bearer tokens
- RFC 8032: Ed25519
- RFC 8259: JSON
- RFC 8414: OAuth 2.0 Authorization Server Metadata
- RFC 8446: TLS 1.3
- RFC 8615: Well-known URIs
- RFC 8785: JSON Canonicalization Scheme
- RFC 9110: HTTP Semantics
- RFC 9457: Problem Details for HTTP APIs
- RFC 9562: UUIDs
- TRACE record profile `tag:govops.owasp.org,2026:trace-v1` (`govops-trace-profile.md`)

### 17.2 Informative

- RFC 7493: I-JSON
- RFC 8705: OAuth mutual-TLS client authentication and certificate-bound tokens
- RFC 8707: Resource Indicators for OAuth 2.0
- RFC 9449: OAuth 2.0 Demonstrating Proof of Possession (DPoP)
- RFC 9728: OAuth 2.0 Protected Resource Metadata
- OpenTelemetry Protocol (OTLP) specification
- OpenAPI Specification 3.1

---

## Appendix A. Examples (informative)

Digests and signatures are those of the vectors in Appendix C.

### A.1 Discovery

```http
GET /.well-known/govops-trace-configuration HTTP/1.1
Host: collector.example.org

HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: max-age=3600
```

The body is the document in §11.3.

### A.2 First acceptance (vector V-01)

```http
POST /api/v1/audit/trace HTTP/1.1
Host: collector.example.org
Authorization: Bearer eyJ...
Content-Type: application/json

{"producer":"pdp-fleet-1","kid":"key-2026-01","record_id":"0191f3a0-7b1e-7c2a-9d41-3a2f7b0c9d41","trace":{"eat_profile":"tag:govops.owasp.org,2026:trace-v1","event_kind":"AUTHORIZATION_DECISION","signed_at":1781138542,"trace_execution_id":"exec-123","execution_authority":"payments-gateway","subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"event":{"decision":{"action":"Acme::Action::\"ApprovePayment\"","resource_type":"Acme::Payment","outcome":"ALLOW"},"tokens":[{"issuer":"https://accounts.example.org","token_type":"access_token","jti":"9c9f2e77-9a3e-4b62-9a2a-2f6e6e2a9f3e"}]},"policy":{"policy_store_id":"https://example.org/policy-stores/payments","policy_store_version":"1.2.3","policy_language":"cedar","policy_language_version":"4.4.0","bundle_hash":"sha256:6cd416d52176b7d2fb8132025f55a42443910cc8d9f2b3f1d19b98b090c2d928"},"runtime":{"pdp_id":"pdp-001"}},"producer_chain":{"producer_id":"pdp-fleet-1","producer_instance_id":"pdp-001","producer_chain_id":"chain-pdp-001-a","sequence_number":1,"prev_record_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"parent_record_ids":[],"signature":"NCteOEnLP7tcVEuDJ95lgP_DFIaz3--j2nlcRQm-2nvOnsTTHdg-WVps3e-H4PD8qC5YEjMxi805YUTJ-sB6Bw"}

HTTP/1.1 201 Created
Content-Type: application/json

{"accepted":true,"producer_id":"pdp-fleet-1","record_id":"0191f3a0-7b1e-7c2a-9d41-3a2f7b0c9d41","content_digest":"sha256:c849281f3c5ef69a204c28cf8a3036092b159ffa782b2bee11d3513fd4455226","receipt_id":"108422","received_at":"2026-06-11T00:42:23.456Z","idempotent_replay":false,"coverage_gap_flag":false,"chain_link_failure_flag":false,"equivocation_flag":false,"late_flag":false}
```

### A.3 Replay

Resubmitting V-01 (in any JSON formatting):

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"accepted":true,"producer_id":"pdp-fleet-1","record_id":"0191f3a0-7b1e-7c2a-9d41-3a2f7b0c9d41","content_digest":"sha256:c849281f3c5ef69a204c28cf8a3036092b159ffa782b2bee11d3513fd4455226","receipt_id":"108422","received_at":"2026-06-11T00:42:23.456Z","idempotent_replay":true,"coverage_gap_flag":false,"chain_link_failure_flag":false,"equivocation_flag":false,"late_flag":false}
```

Only `idempotent_replay` differs from A.2.

### A.4 Conflict (vector V-20 after V-01)

```http
HTTP/1.1 409 Conflict
Content-Type: application/problem+json

{"type":"https://govops.owasp.org/trace/errors/record-id-conflict","title":"Record identity already used with different content","status":409,"code":"RECORD_ID_CONFLICT","retryable":false,"producer_id":"pdp-fleet-1","record_id":"0191f3a0-7b1e-7c2a-9d41-3a2f7b0c9d41","existing_content_digest":"sha256:c849281f3c5ef69a204c28cf8a3036092b159ffa782b2bee11d3513fd4455226","submitted_content_digest":"sha256:2c92043b1d3c70516d452af46d7987c22701fb4b81133e8f92b4c6e83aa92e99"}
```

### A.5 Signature failure (vector V-10)

```http
HTTP/1.1 400 Bad Request
Content-Type: application/problem+json

{"type":"https://govops.owasp.org/trace/errors/signature-invalid","title":"Signature verification failed","status":400,"code":"SIGNATURE_INVALID","retryable":false}
```

### A.6 Out-of-order chain (vector V-02 first)

```http
HTTP/1.1 201 Created
Content-Type: application/json

{"accepted":true,"producer_id":"pdp-fleet-1","record_id":"0191f3a0-7b1f-7d3b-8e52-4b3a8c1d0e52","content_digest":"sha256:ad48f69db6bf6f789871edf3dfe48f340174d9a30217cd2789f8a0e043c0ea00","receipt_id":"108423","received_at":"2026-06-11T00:42:24.101Z","idempotent_replay":false,"coverage_gap_flag":true,"chain_link_failure_flag":false,"equivocation_flag":false,"late_flag":false}
```

The record is accepted (`201`) with `coverage_gap_flag: true`. It is not rejected. When V-01 later arrives it is accepted normally.

### A.7 Mixed batch (vectors V-01, V-10, V-02)

```http
POST /api/v1/audit/trace/bulk HTTP/1.1
Authorization: Bearer eyJ...
Content-Type: application/json

[ V-01, V-10, V-02 ]

HTTP/1.1 200 OK
Content-Type: application/json

{"results":[
 {"index":0,"accepted":true,"producer_id":"pdp-fleet-1","record_id":"0191f3a0-7b1e-7c2a-9d41-3a2f7b0c9d41","content_digest":"sha256:c849281f3c5ef69a204c28cf8a3036092b159ffa782b2bee11d3513fd4455226","receipt_id":"108422","received_at":"2026-06-11T00:42:23.456Z","idempotent_replay":false,"coverage_gap_flag":false,"chain_link_failure_flag":false,"equivocation_flag":false,"late_flag":false},
 {"index":1,"accepted":false,"producer_id":"pdp-fleet-1","record_id":"0191f3a0-7b1e-7c2a-9d41-3a2f7b0c9d41","error":{"type":"https://govops.owasp.org/trace/errors/signature-invalid","title":"Signature verification failed","status":400,"code":"SIGNATURE_INVALID","retryable":false}},
 {"index":2,"accepted":true,"producer_id":"pdp-fleet-1","record_id":"0191f3a0-7b1f-7d3b-8e52-4b3a8c1d0e52","content_digest":"sha256:ad48f69db6bf6f789871edf3dfe48f340174d9a30217cd2789f8a0e043c0ea00","receipt_id":"108423","received_at":"2026-06-11T00:42:23.457Z","idempotent_replay":false,"coverage_gap_flag":false,"chain_link_failure_flag":false,"equivocation_flag":false,"late_flag":false}
]}
```

### A.8 Rate limited

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 2
Content-Type: application/problem+json

{"type":"https://govops.owasp.org/trace/errors/rate-limited","title":"Rate limit exceeded","status":429,"code":"RATE_LIMITED","retryable":true}
```

### A.9 Storage unavailable

```http
HTTP/1.1 503 Service Unavailable
Retry-After: 10
Content-Type: application/problem+json

{"type":"https://govops.owasp.org/trace/errors/collector-unavailable","title":"Durable storage unavailable; nothing was accepted","status":503,"code":"COLLECTOR_UNAVAILABLE","retryable":true}
```

---

## Appendix B. OpenAPI 3.1 definition (normative companion)

The definition below is validated as OpenAPI 3.1, and every example in it is validated against its schemas. If it conflicts with the text of this document, the text governs.

```yaml
openapi: 3.1.0
info:
  title: GovOps TRACE Collector API
  version: 1.0.0-draft.1
  summary: Submission and discovery interface for signed TRACE evidence records.
  description: |
    Normative companion to `govops-trace-collector-api.md`. If this definition and the
    Markdown specification disagree, the Markdown specification governs.
    The structure of a TRACE record is defined by the TRACE record profile, not by this file;
    `SignedTraceRecord` below constrains only the members a Collector needs to route, identify,
    and verify a record.
  license:
    name: Apache-2.0
    identifier: Apache-2.0
servers:
  - url: https://collector.example.org
    description: Example Collector. Real deployments publish their own base URL.
tags:
  - name: Ingestion
  - name: Discovery
paths:
  /api/v1/audit/trace:
    post:
      tags: [Ingestion]
      operationId: submitTraceRecord
      summary: Submit one signed TRACE record
      description: |
        Returns 201 only after the record is verified and durably accepted (specification section 7).
        An identical resubmission returns 200 with the original receipt and `idempotent_replay: true`.
        202 is intentionally not used.
      security:
        - oauth2: [trace.write]
        - bearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/SignedTraceRecord'
            examples:
              decision:
                summary: PDP AUTHORIZATION_DECISION (vector R1)
                value: {"producer":"pdp-fleet-1","kid":"key-2026-01","record_id":"0191f3a0-7b1e-7c2a-9d41-3a2f7b0c9d41","trace":{"eat_profile":"tag:govops.owasp.org,2026:trace-v1","event_kind":"AUTHORIZATION_DECISION","signed_at":1781138542,"trace_execution_id":"exec-123","execution_authority":"payments-gateway","subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"event":{"decision":{"action":"Acme::Action::\"ApprovePayment\"","resource_type":"Acme::Payment","outcome":"ALLOW"},"tokens":[{"issuer":"https://accounts.example.org","token_type":"access_token","jti":"9c9f2e77-9a3e-4b62-9a2a-2f6e6e2a9f3e"}]},"policy":{"policy_store_id":"https://example.org/policy-stores/payments","policy_store_version":"1.2.3","policy_language":"cedar","policy_language_version":"4.4.0","bundle_hash":"sha256:6cd416d52176b7d2fb8132025f55a42443910cc8d9f2b3f1d19b98b090c2d928"},"runtime":{"pdp_id":"pdp-001"}},"producer_chain":{"producer_id":"pdp-fleet-1","producer_instance_id":"pdp-001","producer_chain_id":"chain-pdp-001-a","sequence_number":1,"prev_record_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"parent_record_ids":[],"signature":"NCteOEnLP7tcVEuDJ95lgP_DFIaz3--j2nlcRQm-2nvOnsTTHdg-WVps3e-H4PD8qC5YEjMxi805YUTJ-sB6Bw"}
      responses:
        '201':
          description: First durable acceptance.
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/AcceptanceReceipt'
              examples:
                accepted:
                  value:
                    accepted: true
                    producer_id: pdp-fleet-1
                    record_id: 0191f3a0-7b1e-7c2a-9d41-3a2f7b0c9d41
                    content_digest: sha256:c849281f3c5ef69a204c28cf8a3036092b159ffa782b2bee11d3513fd4455226
                    receipt_id: '108422'
                    received_at: '2026-06-11T00:42:23.456Z'
                    idempotent_replay: false
                    coverage_gap_flag: false
                    chain_link_failure_flag: false
                    equivocation_flag: false
                    late_flag: false
        '200':
          description: Idempotent replay. The original receipt is returned unchanged except for `idempotent_replay`.
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/AcceptanceReceipt'
              examples:
                replay:
                  value:
                    accepted: true
                    producer_id: pdp-fleet-1
                    record_id: 0191f3a0-7b1e-7c2a-9d41-3a2f7b0c9d41
                    content_digest: sha256:c849281f3c5ef69a204c28cf8a3036092b159ffa782b2bee11d3513fd4455226
                    receipt_id: '108422'
                    received_at: '2026-06-11T00:42:23.456Z'
                    idempotent_replay: true
                    coverage_gap_flag: false
                    chain_link_failure_flag: false
                    equivocation_flag: false
                    late_flag: false
        '400': {$ref: '#/components/responses/BadRequest'}
        '401': {$ref: '#/components/responses/Unauthorized'}
        '403': {$ref: '#/components/responses/Forbidden'}
        '409': {$ref: '#/components/responses/Conflict'}
        '413': {$ref: '#/components/responses/TooLarge'}
        '415': {$ref: '#/components/responses/UnsupportedMediaType'}
        '429': {$ref: '#/components/responses/TooManyRequests'}
        '500': {$ref: '#/components/responses/InternalError'}
        '503': {$ref: '#/components/responses/Unavailable'}
  /api/v1/audit/trace/bulk:
    post:
      tags: [Ingestion]
      operationId: submitTraceRecordBatch
      summary: Submit a batch of signed TRACE records
      description: |
        Each record is processed independently (specification section 8). The response is 200 whenever
        the batch envelope was valid and the Collector could process it, even if every record was rejected.
      security:
        - oauth2: [trace.write]
        - bearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: array
              minItems: 1
              items:
                $ref: '#/components/schemas/SignedTraceRecord'
            examples:
              mixed:
                summary: One valid record and one record altered after signing (vectors V-01 and V-10)
                value: [{"producer":"pdp-fleet-1","kid":"key-2026-01","record_id":"0191f3a0-7b1e-7c2a-9d41-3a2f7b0c9d41","trace":{"eat_profile":"tag:govops.owasp.org,2026:trace-v1","event_kind":"AUTHORIZATION_DECISION","signed_at":1781138542,"trace_execution_id":"exec-123","execution_authority":"payments-gateway","subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"event":{"decision":{"action":"Acme::Action::\"ApprovePayment\"","resource_type":"Acme::Payment","outcome":"ALLOW"},"tokens":[{"issuer":"https://accounts.example.org","token_type":"access_token","jti":"9c9f2e77-9a3e-4b62-9a2a-2f6e6e2a9f3e"}]},"policy":{"policy_store_id":"https://example.org/policy-stores/payments","policy_store_version":"1.2.3","policy_language":"cedar","policy_language_version":"4.4.0","bundle_hash":"sha256:6cd416d52176b7d2fb8132025f55a42443910cc8d9f2b3f1d19b98b090c2d928"},"runtime":{"pdp_id":"pdp-001"}},"producer_chain":{"producer_id":"pdp-fleet-1","producer_instance_id":"pdp-001","producer_chain_id":"chain-pdp-001-a","sequence_number":1,"prev_record_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"parent_record_ids":[],"signature":"NCteOEnLP7tcVEuDJ95lgP_DFIaz3--j2nlcRQm-2nvOnsTTHdg-WVps3e-H4PD8qC5YEjMxi805YUTJ-sB6Bw"}, {"producer":"pdp-fleet-1","kid":"key-2026-01","record_id":"0191f3a0-7b1e-7c2a-9d41-3a2f7b0c9d41","trace":{"eat_profile":"tag:govops.owasp.org,2026:trace-v1","event_kind":"AUTHORIZATION_DECISION","signed_at":1781138542,"trace_execution_id":"exec-123","execution_authority":"payments-gateway","subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"event":{"decision":{"action":"Acme::Action::\"ApprovePayment\"","resource_type":"Acme::Payment","outcome":"DENY"},"tokens":[{"issuer":"https://accounts.example.org","token_type":"access_token","jti":"9c9f2e77-9a3e-4b62-9a2a-2f6e6e2a9f3e"}]},"policy":{"policy_store_id":"https://example.org/policy-stores/payments","policy_store_version":"1.2.3","policy_language":"cedar","policy_language_version":"4.4.0","bundle_hash":"sha256:6cd416d52176b7d2fb8132025f55a42443910cc8d9f2b3f1d19b98b090c2d928"},"runtime":{"pdp_id":"pdp-001"}},"producer_chain":{"producer_id":"pdp-fleet-1","producer_instance_id":"pdp-001","producer_chain_id":"chain-pdp-001-a","sequence_number":1,"prev_record_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"parent_record_ids":[],"signature":"NCteOEnLP7tcVEuDJ95lgP_DFIaz3--j2nlcRQm-2nvOnsTTHdg-WVps3e-H4PD8qC5YEjMxi805YUTJ-sB6Bw"}]
      responses:
        '200':
          description: Batch processed. Each element of `results` corresponds to the request element at `index`.
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/BulkResponse'
              examples:
                mixed:
                  value:
                    results:
                      - index: 0
                        accepted: true
                        producer_id: pdp-fleet-1
                        record_id: 0191f3a0-7b1e-7c2a-9d41-3a2f7b0c9d41
                        content_digest: sha256:c849281f3c5ef69a204c28cf8a3036092b159ffa782b2bee11d3513fd4455226
                        receipt_id: '108422'
                        received_at: '2026-06-11T00:42:23.456Z'
                        idempotent_replay: false
                        coverage_gap_flag: false
                        chain_link_failure_flag: false
                        equivocation_flag: false
                        late_flag: false
                      - index: 1
                        accepted: false
                        producer_id: pdp-fleet-1
                        record_id: 0191f3a0-7b1e-7c2a-9d41-3a2f7b0c9d41
                        error:
                          type: https://govops.owasp.org/trace/errors/signature-invalid
                          title: Signature verification failed
                          status: 400
                          code: SIGNATURE_INVALID
                          retryable: false
        '400': {$ref: '#/components/responses/BadRequest'}
        '401': {$ref: '#/components/responses/Unauthorized'}
        '403': {$ref: '#/components/responses/Forbidden'}
        '413': {$ref: '#/components/responses/TooLarge'}
        '415': {$ref: '#/components/responses/UnsupportedMediaType'}
        '429': {$ref: '#/components/responses/TooManyRequests'}
        '500': {$ref: '#/components/responses/InternalError'}
        '503': {$ref: '#/components/responses/Unavailable'}
  /.well-known/govops-trace-configuration:
    get:
      tags: [Discovery]
      operationId: getCollectorConfiguration
      summary: Retrieve Collector metadata
      description: Unauthenticated. Contains no per-tenant information.
      security: []
      responses:
        '200':
          description: Collector metadata.
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/CollectorConfiguration'
              examples:
                example:
                  value:
                    issuer: https://collector.example.org
                    api_versions_supported: [v1]
                    trace_ingestion_endpoint: https://collector.example.org/api/v1/audit/trace
                    trace_bulk_ingestion_endpoint: https://collector.example.org/api/v1/audit/trace/bulk
                    trace_profiles_supported:
                      - tag:govops.owasp.org,2026:trace-v1
                    event_kinds_supported: [AUTHORIZATION_DECISION, CAPABILITY_INVOKED, RUNTIME_EFFECT]
                    signature_algorithms_supported: [Ed25519]
                    canonicalization_methods_supported: [RFC8785]
                    authorization_servers: [https://auth.example.org]
                    ingestion_scope: trace.write
                    scopes_supported: [trace.write]
                    max_record_bytes: 262144
                    max_batch_bytes: 8388608
                    max_batch_records: 500
                    max_nesting_depth: 32
                    bulk_mixed_producers_supported: false
                    execution_correlation_required: true
                    producer_chain_registration_modes_supported: [first_observed_genesis, pre_registered_genesis]
                    acceptance_durability: replicated_durable
                    content_encodings_supported: [gzip]
        '429': {$ref: '#/components/responses/TooManyRequests'}
        '503': {$ref: '#/components/responses/Unavailable'}
components:
  securitySchemes:
    oauth2:
      type: oauth2
      description: OAuth 2.0 client credentials. The scope name is advertised as `ingestion_scope` in Collector metadata.
      flows:
        clientCredentials:
          tokenUrl: https://auth.example.org/token
          scopes:
            trace.write: Submit TRACE records.
    bearerAuth:
      type: http
      scheme: bearer
      description: OAuth 2.0 access token (RFC 6750). Sender-constrained tokens (RFC 9449, RFC 8705) are RECOMMENDED.
  headers:
    RetryAfter:
      description: Seconds to wait before retrying, or an HTTP-date.
      schema:
        type: string
  responses:
    BadRequest:
      description: Malformed or unverifiable request, or an envelope-level violation.
      content:
        application/problem+json:
          schema: {$ref: '#/components/schemas/Problem'}
          examples:
            malformed:
              value:
                type: https://govops.owasp.org/trace/errors/malformed-json
                title: Request body is not valid strict JSON
                status: 400
                code: MALFORMED_JSON
                retryable: false
                detail: Duplicate member name "record_id" at $.
    Unauthorized:
      description: Missing, expired, or invalid access token.
      headers:
        WWW-Authenticate:
          schema: {type: string}
      content:
        application/problem+json:
          schema: {$ref: '#/components/schemas/Problem'}
    Forbidden:
      description: Token lacks the ingestion scope, the client has no evidence-domain binding, or the client may not submit for the record's producer.
      content:
        application/problem+json:
          schema: {$ref: '#/components/schemas/Problem'}
    Conflict:
      description: The record identity is already bound to different content.
      content:
        application/problem+json:
          schema: {$ref: '#/components/schemas/Problem'}
          examples:
            conflict:
              value:
                type: https://govops.owasp.org/trace/errors/record-id-conflict
                title: Record identity already used with different content
                status: 409
                code: RECORD_ID_CONFLICT
                retryable: false
                producer_id: pdp-fleet-1
                record_id: 0191f3a0-7b1e-7c2a-9d41-3a2f7b0c9d41
                existing_content_digest: sha256:c849281f3c5ef69a204c28cf8a3036092b159ffa782b2bee11d3513fd4455226
                submitted_content_digest: sha256:2c92043b1d3c70516d452af46d7987c22701fb4b81133e8f92b4c6e83aa92e99
    TooLarge:
      description: Request body or record exceeds an advertised limit.
      content:
        application/problem+json:
          schema: {$ref: '#/components/schemas/Problem'}
    UnsupportedMediaType:
      description: Content-Type or Content-Encoding not supported.
      content:
        application/problem+json:
          schema: {$ref: '#/components/schemas/Problem'}
    TooManyRequests:
      description: Rate limit exceeded. Retry after the interval in Retry-After.
      headers:
        Retry-After: {$ref: '#/components/headers/RetryAfter'}
      content:
        application/problem+json:
          schema: {$ref: '#/components/schemas/Problem'}
    InternalError:
      description: Unexpected failure. Nothing was accepted. Retrying the same bytes is safe.
      content:
        application/problem+json:
          schema: {$ref: '#/components/schemas/Problem'}
    Unavailable:
      description: Storage or a required dependency is unavailable, or the Collector is in an integrity hold. Nothing was accepted.
      headers:
        Retry-After: {$ref: '#/components/headers/RetryAfter'}
      content:
        application/problem+json:
          schema: {$ref: '#/components/schemas/Problem'}
  schemas:
    SignedTraceRecord:
      type: object
      description: |
        A producer-signed TRACE record as defined by the TRACE record profile. Only the members a
        Collector must read to route, identify, and verify the record are constrained here. Unknown members
        are permitted and are covered by the signature.
      required: [producer, kid, record_id, trace, producer_chain, signature]
      properties:
        producer:
          type: string
          minLength: 1
        kid:
          type: string
          minLength: 1
        record_id:
          type: string
          description: Producer-generated UUID (lowercase canonical text) or ULID (uppercase Crockford base32).
          oneOf:
            - pattern: '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
            - pattern: '^[0-9A-HJKMNP-TV-Z]{26}$'
        trace:
          type: object
          required: [eat_profile, event_kind, signed_at]
          properties:
            eat_profile: {type: string}
            event_kind: {type: string}
            signed_at: {type: integer}
            trace_execution_id: {type: string}
            execution_authority: {type: string}
          additionalProperties: true
        producer_chain:
          type: object
          required: [producer_id, producer_instance_id, producer_chain_id, sequence_number, prev_record_hash]
          properties:
            producer_id: {type: string}
            producer_instance_id: {type: string}
            producer_chain_id: {type: string}
            sequence_number: {type: integer, minimum: 1}
            prev_record_hash:
              type: string
              pattern: '^sha256:[0-9a-f]{64}$'
          additionalProperties: true
        parent_record_ids:
          type: array
          items: {type: object}
        signature:
          type: string
          description: Unpadded base64url encoding of the 64-byte Ed25519 signature.
          pattern: '^[A-Za-z0-9_-]{86}$'
      additionalProperties: true
    AcceptanceReceipt:
      type: object
      description: |
        Evidence that the Collector verified and durably accepted the record. It is not a statement that
        the record is true, complete, or settled.
      required:
        - accepted
        - producer_id
        - record_id
        - content_digest
        - receipt_id
        - received_at
        - idempotent_replay
        - coverage_gap_flag
        - chain_link_failure_flag
        - equivocation_flag
        - late_flag
      properties:
        accepted: {const: true}
        producer_id: {type: string}
        record_id: {type: string}
        content_digest:
          type: string
          pattern: '^sha256:[0-9a-f]{64}$'
        receipt_id:
          type: string
          description: Opaque identifier, unique within the evidence domain, stable across replays.
        received_at:
          type: string
          format: date-time
          description: RFC 3339 UTC timestamp with millisecond precision, assigned by the Collector.
          pattern: '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$'
        idempotent_replay: {type: boolean}
        coverage_gap_flag: {type: boolean}
        chain_link_failure_flag: {type: boolean}
        equivocation_flag: {type: boolean}
        late_flag: {type: boolean}
        unattributed_flag: {type: boolean}
        receipt_sequence:
          type: integer
          description: OPTIONAL. Position in a Collector-internal receipt chain, if one is exposed.
      additionalProperties: true
    BulkAccepted:
      allOf:
        - $ref: '#/components/schemas/AcceptanceReceipt'
        - type: object
          required: [index]
          properties:
            index: {type: integer, minimum: 0}
    BulkRejected:
      type: object
      required: [index, accepted, error]
      properties:
        index: {type: integer, minimum: 0}
        accepted: {const: false}
        producer_id:
          type: string
          description: Present when determinable from the submitted element.
        record_id:
          type: string
          description: Present when determinable from the submitted element.
        error: {$ref: '#/components/schemas/Problem'}
      additionalProperties: false
    BulkResponse:
      type: object
      required: [results]
      properties:
        results:
          type: array
          description: One element per request element, in request order.
          items:
            oneOf:
              - $ref: '#/components/schemas/BulkAccepted'
              - $ref: '#/components/schemas/BulkRejected'
      additionalProperties: false
    ErrorCode:
      type: string
      enum:
        - UNAUTHENTICATED
        - INSUFFICIENT_SCOPE
        - EVIDENCE_DOMAIN_NOT_BOUND
        - SUBMITTER_NOT_AUTHORIZED
        - UNSUPPORTED_MEDIA_TYPE
        - REQUEST_TOO_LARGE
        - RECORD_TOO_LARGE
        - BATCH_TOO_MANY_RECORDS
        - BATCH_EMPTY
        - BATCH_MIXED_PRODUCERS
        - MALFORMED_JSON
        - SCHEMA_INVALID
        - UNSUPPORTED_PROFILE
        - MISSING_EXECUTION_CONTEXT
        - PRODUCER_IDENTITY_MISMATCH
        - SIGNATURE_MALFORMED
        - KEY_UNKNOWN
        - KEY_NOT_VALID
        - EVENT_KIND_NOT_AUTHORIZED
        - SIGNATURE_INVALID
        - RECORD_ID_CONFLICT
        - RATE_LIMITED
        - COLLECTOR_UNAVAILABLE
        - COLLECTOR_INTEGRITY_HOLD
        - INTERNAL_ERROR
    Problem:
      type: object
      description: RFC 9457 Problem Details with the members this specification adds.
      required: [type, title, status, code, retryable]
      properties:
        type: {type: string, format: uri}
        title: {type: string}
        status: {type: integer, minimum: 100, maximum: 599}
        detail: {type: string}
        instance: {type: string}
        code: {$ref: '#/components/schemas/ErrorCode'}
        retryable: {type: boolean}
        producer_id: {type: string}
        record_id: {type: string}
        existing_content_digest: {type: string}
        submitted_content_digest: {type: string}
      additionalProperties: true
    CollectorConfiguration:
      type: object
      required:
        - issuer
        - api_versions_supported
        - trace_ingestion_endpoint
        - trace_profiles_supported
        - signature_algorithms_supported
        - authorization_servers
        - ingestion_scope
        - max_record_bytes
        - producer_chain_registration_modes_supported
      properties:
        issuer:
          type: string
          format: uri
          description: HTTPS URL identifying the Collector. MUST equal the origin and path prefix used to retrieve this document.
        api_versions_supported:
          type: array
          minItems: 1
          items: {type: string, pattern: '^v[0-9]+$'}
        trace_ingestion_endpoint: {type: string, format: uri}
        trace_bulk_ingestion_endpoint:
          type: string
          format: uri
          description: Absent if the Collector does not implement bulk submission.
        trace_profiles_supported:
          type: array
          minItems: 1
          items: {type: string}
        event_kinds_supported:
          type: array
          items: {type: string}
        signature_algorithms_supported:
          type: array
          minItems: 1
          items: {type: string}
        canonicalization_methods_supported:
          type: array
          items: {type: string}
        authorization_servers:
          type: array
          minItems: 1
          description: Issuer identifiers. Their metadata is discoverable per RFC 8414 or OpenID Connect Discovery.
          items: {type: string, format: uri}
        ingestion_scope: {type: string}
        scopes_supported:
          type: array
          items: {type: string}
        max_record_bytes: {type: integer, minimum: 1}
        max_batch_bytes: {type: integer, minimum: 1}
        max_batch_records: {type: integer, minimum: 1}
        max_nesting_depth: {type: integer, minimum: 1}
        bulk_mixed_producers_supported: {type: boolean, default: false}
        execution_correlation_required: {type: boolean}
        producer_chain_registration_modes_supported:
          type: array
          minItems: 1
          items:
            type: string
            enum: [first_observed_genesis, pre_registered_genesis, linked_restart_genesis]
        acceptance_durability:
          type: string
          enum: [local_durable, replicated_durable]
        content_encodings_supported:
          type: array
          items: {type: string}
      additionalProperties: true
```

---

## Appendix C. Conformance test vectors

The vectors are normative inputs and expected results for the tests in §15. All signatures were produced with the **non-production test keys below**; their seeds are published on purpose so that implementations can regenerate and extend the vectors. Never register these keys outside a test deployment.

### C.1 Test keys

| Producer | `kid` | Authorized event kinds | Ed25519 seed (hex) | Public key (JWK `x`) |
|---|---|---|---|---|
| `pdp-fleet-1` | `key-2026-01` | `AUTHORIZATION_DECISION` | `ccb2538fd1c9bbc2a2d034662c4a220387c7a4eb62d3cfd3582a0e0aa183adcc` | `osMws01rURBEOGoaCDB5eFcNt7qw6sgH4y-ty1_WZ5A` |
| `payments-gateway-pep` | `pep-key-2026-01` | `CAPABILITY_INVOKED` | `b26864e6c1d517b2527e68873aad0c2ab04507b8022c6df52b19ee342055b3d7` | `hQZQSp0mtUu3bMyZ_DEH5rJ_rPLyOtpOAniT2swqaD8` |

Each seed is the SHA-256 of an ASCII label, `govops-trace-collector-test/<producer_id>/<kid>`. The public key JWK is `{"kty":"OKP","crv":"Ed25519","x":"<value>"}`.

### C.2 How the vectors were produced

Each signed record is a JSON object whose signature input is `JCS(record without "signature")`. The signature is Ed25519 over those UTF-8 bytes, encoded as unpadded base64url. The `content_digest` is `sha256:` and the lowercase hex SHA-256 of `JCS(record including "signature")`. For these vectors, which contain only ASCII member names and string, integer, and null values, JCS output equals compact JSON with members sorted by name.

### C.3 Worked computation for V-01

Signing input (`JCS` of V-01 without `signature`):

```text
{"kid":"key-2026-01","parent_record_ids":[],"producer":"pdp-fleet-1","producer_chain":{"prev_record_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000","producer_chain_id":"chain-pdp-001-a","producer_id":"pdp-fleet-1","producer_instance_id":"pdp-001","sequence_number":1},"record_id":"0191f3a0-7b1e-7c2a-9d41-3a2f7b0c9d41","trace":{"eat_profile":"tag:govops.owasp.org,2026:trace-v1","event":{"decision":{"action":"Acme::Action::\"ApprovePayment\"","outcome":"ALLOW","resource_type":"Acme::Payment"},"tokens":[{"issuer":"https://accounts.example.org","jti":"9c9f2e77-9a3e-4b62-9a2a-2f6e6e2a9f3e","token_type":"access_token"}]},"event_kind":"AUTHORIZATION_DECISION","execution_authority":"payments-gateway","policy":{"bundle_hash":"sha256:6cd416d52176b7d2fb8132025f55a42443910cc8d9f2b3f1d19b98b090c2d928","policy_language":"cedar","policy_language_version":"4.4.0","policy_store_id":"https://example.org/policy-stores/payments","policy_store_version":"1.2.3"},"runtime":{"pdp_id":"pdp-001"},"signed_at":1781138542,"subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"trace_execution_id":"exec-123"}}
```

Signature (unpadded base64url, 86 characters):

```text
NCteOEnLP7tcVEuDJ95lgP_DFIaz3--j2nlcRQm-2nvOnsTTHdg-WVps3e-H4PD8qC5YEjMxi805YUTJ-sB6Bw
```

Digests of the positive vectors:

| Vector | `content_digest` |
|---|---|
| V-01 | `sha256:c849281f3c5ef69a204c28cf8a3036092b159ffa782b2bee11d3513fd4455226` |
| V-02 | `sha256:ad48f69db6bf6f789871edf3dfe48f340174d9a30217cd2789f8a0e043c0ea00` (its `prev_record_hash` is V-01's digest) |
| V-03 | `sha256:524391ac77a07ec35546d909f6c409c719fb25e52645c5cccb0332001a830259` |
| V-04 | `sha256:08c257582502a1aaf4ebe4998f0825d7e1cebf4719df025f7eca524ee96ec3f8` |
| V-05 | `sha256:9b551c0889228cc656dc1c06774109db1280a2d00cc504b678ac9aeaafdb3703` |

V-06 has the same digest as V-01.

### C.4 Vectors

Preconditions use the fixture in §15.2. "Used by" lists the tests in §15 that use the vector.

#### V-01

- **Purpose:** Valid `AUTHORIZATION_DECISION`, genesis of chain `chain-pdp-001-a`, execution `exec-123`.
- **Precondition:** empty store
- **Submitter:** `c-pdp`
- **Expected:** `201`; all flags false; `content_digest` = `sha256:c849281f3c5ef69a204c28cf8a3036092b159ffa782b2bee11d3513fd4455226`.
- **Used by:** C-01, C-02, C-03, C-04, C-05, C-15, C-16, C-21, C-22, C-27, C-28, C-30, B-01, B-06, B-07

```json
{
  "producer": "pdp-fleet-1",
  "kid": "key-2026-01",
  "record_id": "0191f3a0-7b1e-7c2a-9d41-3a2f7b0c9d41",
  "trace": {
    "eat_profile": "tag:govops.owasp.org,2026:trace-v1",
    "event_kind": "AUTHORIZATION_DECISION",
    "signed_at": 1781138542,
    "trace_execution_id": "exec-123",
    "execution_authority": "payments-gateway",
    "subject": {
      "workload_id": "spiffe://example.org/service/payments-gateway"
    },
    "event": {
      "decision": {
        "action": "Acme::Action::\"ApprovePayment\"",
        "resource_type": "Acme::Payment",
        "outcome": "ALLOW"
      },
      "tokens": [
        {
          "issuer": "https://accounts.example.org",
          "token_type": "access_token",
          "jti": "9c9f2e77-9a3e-4b62-9a2a-2f6e6e2a9f3e"
        }
      ]
    },
    "policy": {
      "policy_store_id": "https://example.org/policy-stores/payments",
      "policy_store_version": "1.2.3",
      "policy_language": "cedar",
      "policy_language_version": "4.4.0",
      "bundle_hash": "sha256:6cd416d52176b7d2fb8132025f55a42443910cc8d9f2b3f1d19b98b090c2d928"
    },
    "runtime": {
      "pdp_id": "pdp-001"
    }
  },
  "producer_chain": {
    "producer_id": "pdp-fleet-1",
    "producer_instance_id": "pdp-001",
    "producer_chain_id": "chain-pdp-001-a",
    "sequence_number": 1,
    "prev_record_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
  },
  "parent_record_ids": [],
  "signature": "NCteOEnLP7tcVEuDJ95lgP_DFIaz3--j2nlcRQm-2nvOnsTTHdg-WVps3e-H4PD8qC5YEjMxi805YUTJ-sB6Bw"
}
```

#### V-02

- **Purpose:** Valid `AUTHORIZATION_DECISION`, chain position 2 (`prev_record_hash` = digest of V-01), `DENY`, execution `exec-124`.
- **Precondition:** empty store, or V-01 accepted
- **Submitter:** `c-pdp`
- **Expected:** Empty store: `201`, `coverage_gap_flag` true. After V-01: `201`, all flags false.
- **Used by:** C-14, C-28, B-01, B-08

```json
{"producer":"pdp-fleet-1","kid":"key-2026-01","record_id":"0191f3a0-7b1f-7d3b-8e52-4b3a8c1d0e52","trace":{"eat_profile":"tag:govops.owasp.org,2026:trace-v1","event_kind":"AUTHORIZATION_DECISION","signed_at":1781138600,"trace_execution_id":"exec-124","execution_authority":"payments-gateway","subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"event":{"decision":{"action":"Acme::Action::\"ApprovePayment\"","resource_type":"Acme::Payment","outcome":"DENY"},"tokens":[{"issuer":"https://accounts.example.org","token_type":"access_token","jti":"9c9f2e77-9a3e-4b62-9a2a-2f6e6e2a9f3e"}]},"policy":{"policy_store_id":"https://example.org/policy-stores/payments","policy_store_version":"1.2.3","policy_language":"cedar","policy_language_version":"4.4.0","bundle_hash":"sha256:6cd416d52176b7d2fb8132025f55a42443910cc8d9f2b3f1d19b98b090c2d928"},"runtime":{"pdp_id":"pdp-001"}},"producer_chain":{"producer_id":"pdp-fleet-1","producer_instance_id":"pdp-001","producer_chain_id":"chain-pdp-001-a","sequence_number":2,"prev_record_hash":"sha256:c849281f3c5ef69a204c28cf8a3036092b159ffa782b2bee11d3513fd4455226"},"parent_record_ids":[],"signature":"Hc-B-e4FnlHykEQQrVUAdRh2GGjcsFsuyGdYpoP_FD4rZAH28wmh_k0lUBo9l5NCt0QX6IhBfRtU-ZHC7U3CCg"}
```

#### V-03

- **Purpose:** Valid `CAPABILITY_INVOKED` from a different producer and key, with an `authorized` parent edge to V-01.
- **Precondition:** any
- **Submitter:** `c-pep` or `c-fwd`
- **Expected:** `201`; all flags false.
- **Used by:** C-22, C-34, B-02

```json
{"producer":"payments-gateway-pep","kid":"pep-key-2026-01","record_id":"0191f3a0-7b20-7e4c-9f63-5c4b9d2e1f63","trace":{"eat_profile":"tag:govops.owasp.org,2026:trace-v1","event_kind":"CAPABILITY_INVOKED","signed_at":1781138543,"trace_execution_id":"exec-123","execution_authority":"payments-gateway","subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"event":{"invocation":{"action":"Acme::Action::\"ApprovePayment\"","resource_type":"Acme::Payment","outcome":"SUCCESS"},"enforcement_point_id":"payments-gateway-01"}},"producer_chain":{"producer_id":"payments-gateway-pep","producer_instance_id":"payments-gateway-01","producer_chain_id":"chain-pep-01","sequence_number":1,"prev_record_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"parent_record_ids":[{"producer_id":"pdp-fleet-1","record_id":"0191f3a0-7b1e-7c2a-9d41-3a2f7b0c9d41","relationship_type":"authorized"}],"signature":"q9dnOcAHXqAJ4pdTfvLghlvqgCWZlJD0vzuostJ702mogKd6xBC5Oml68FzV1otp85MXoa6VmlFLf0KnfkYQAw"}
```

#### V-04

- **Purpose:** Valid record whose `issuer` value contains non-ASCII characters (`é` and U+1F512, a surrogate pair in UTF-16). Chain `chain-pdp-001-u`.
- **Precondition:** any
- **Submitter:** `c-pdp`
- **Expected:** `201`. The delivered JCS form must equal the source (FW-4).
- **Used by:** F-01

```json
{"producer":"pdp-fleet-1","kid":"key-2026-01","record_id":"0191f3a0-7b2a-72e6-93ad-06e5d9c2b3ad","trace":{"eat_profile":"tag:govops.owasp.org,2026:trace-v1","event_kind":"AUTHORIZATION_DECISION","signed_at":1781138542,"trace_execution_id":"exec-123","execution_authority":"payments-gateway","subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"event":{"decision":{"action":"Acme::Action::\"ApprovePayment\"","resource_type":"Acme::Payment","outcome":"ALLOW"},"tokens":[{"issuer":"https://accounts.example.org/café/🔒","token_type":"access_token","jti":"9c9f2e77-9a3e-4b62-9a2a-2f6e6e2a9f3e"}]},"policy":{"policy_store_id":"https://example.org/policy-stores/payments","policy_store_version":"1.2.3","policy_language":"cedar","policy_language_version":"4.4.0","bundle_hash":"sha256:6cd416d52176b7d2fb8132025f55a42443910cc8d9f2b3f1d19b98b090c2d928"},"runtime":{"pdp_id":"pdp-001"}},"producer_chain":{"producer_id":"pdp-fleet-1","producer_instance_id":"pdp-001","producer_chain_id":"chain-pdp-001-u","sequence_number":1,"prev_record_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"parent_record_ids":[],"signature":"IK-jMuQaJKkbYLbrrPxPUm8Oc9zZtaAx10PNzSvVr-YOK_8_nHYrzA5rjJIAaaizJcjkUBvCZ4zBDUB5xpx0Bw"}
```

#### V-05

- **Purpose:** Valid record that carries a signed top-level `evidence_domain_id: "D2"`. Chain `chain-pdp-001-d`.
- **Precondition:** any
- **Submitter:** `c-pdp` (bound to `D1`)
- **Expected:** `201`. Held in `D1`. The body member is ignored for partitioning and preserved.
- **Used by:** C-26

```json
{"producer":"pdp-fleet-1","kid":"key-2026-01","record_id":"0191f3a0-7b2b-73f7-84be-17f6ead3c4be","trace":{"eat_profile":"tag:govops.owasp.org,2026:trace-v1","event_kind":"AUTHORIZATION_DECISION","signed_at":1781138542,"trace_execution_id":"exec-123","execution_authority":"payments-gateway","subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"event":{"decision":{"action":"Acme::Action::\"ApprovePayment\"","resource_type":"Acme::Payment","outcome":"ALLOW"},"tokens":[{"issuer":"https://accounts.example.org","token_type":"access_token","jti":"9c9f2e77-9a3e-4b62-9a2a-2f6e6e2a9f3e"}]},"policy":{"policy_store_id":"https://example.org/policy-stores/payments","policy_store_version":"1.2.3","policy_language":"cedar","policy_language_version":"4.4.0","bundle_hash":"sha256:6cd416d52176b7d2fb8132025f55a42443910cc8d9f2b3f1d19b98b090c2d928"},"runtime":{"pdp_id":"pdp-001"}},"producer_chain":{"producer_id":"pdp-fleet-1","producer_instance_id":"pdp-001","producer_chain_id":"chain-pdp-001-d","sequence_number":1,"prev_record_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"parent_record_ids":[],"evidence_domain_id":"D2","signature":"ie6m4ml8UN9b4WfMOI0_e4g0mU0V0GlsuPR3O4DmMr87GLBfRMFXd95F2WROsVC6R7NLQD7aquHlz5Xg2AieBw"}
```

#### V-06

- **Purpose:** V-01 re-serialized: top-level members in reverse order, 4-space indentation. Semantically identical.
- **Precondition:** V-01 accepted
- **Submitter:** `c-pdp`
- **Expected:** `200` replay: original receipt, `idempotent_replay` true.
- **Used by:** C-03, F-01

```json
{
    "signature": "NCteOEnLP7tcVEuDJ95lgP_DFIaz3--j2nlcRQm-2nvOnsTTHdg-WVps3e-H4PD8qC5YEjMxi805YUTJ-sB6Bw",
    "parent_record_ids": [],
    "producer_chain": {
        "producer_id": "pdp-fleet-1",
        "producer_instance_id": "pdp-001",
        "producer_chain_id": "chain-pdp-001-a",
        "sequence_number": 1,
        "prev_record_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    },
    "trace": {
        "eat_profile": "tag:govops.owasp.org,2026:trace-v1",
        "event_kind": "AUTHORIZATION_DECISION",
        "signed_at": 1781138542,
        "trace_execution_id": "exec-123",
        "execution_authority": "payments-gateway",
        "subject": {
            "workload_id": "spiffe://example.org/service/payments-gateway"
        },
        "event": {
            "decision": {
                "action": "Acme::Action::\"ApprovePayment\"",
                "resource_type": "Acme::Payment",
                "outcome": "ALLOW"
            },
            "tokens": [
                {
                    "issuer": "https://accounts.example.org",
                    "token_type": "access_token",
                    "jti": "9c9f2e77-9a3e-4b62-9a2a-2f6e6e2a9f3e"
                }
            ]
        },
        "policy": {
            "policy_store_id": "https://example.org/policy-stores/payments",
            "policy_store_version": "1.2.3",
            "policy_language": "cedar",
            "policy_language_version": "4.4.0",
            "bundle_hash": "sha256:6cd416d52176b7d2fb8132025f55a42443910cc8d9f2b3f1d19b98b090c2d928"
        },
        "runtime": {
            "pdp_id": "pdp-001"
        }
    },
    "record_id": "0191f3a0-7b1e-7c2a-9d41-3a2f7b0c9d41",
    "kid": "key-2026-01",
    "producer": "pdp-fleet-1"
}
```

#### V-10

- **Purpose:** V-01 with `decision.outcome` changed from `ALLOW` to `DENY` after signing; signature unchanged.
- **Precondition:** empty store or V-01 accepted
- **Submitter:** `c-pdp`
- **Expected:** `400 SIGNATURE_INVALID`. No receipt. With `c-pep`: `403 SUBMITTER_NOT_AUTHORIZED`.
- **Used by:** C-05, C-20, B-01, F-02

```json
{"producer":"pdp-fleet-1","kid":"key-2026-01","record_id":"0191f3a0-7b1e-7c2a-9d41-3a2f7b0c9d41","trace":{"eat_profile":"tag:govops.owasp.org,2026:trace-v1","event_kind":"AUTHORIZATION_DECISION","signed_at":1781138542,"trace_execution_id":"exec-123","execution_authority":"payments-gateway","subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"event":{"decision":{"action":"Acme::Action::\"ApprovePayment\"","resource_type":"Acme::Payment","outcome":"DENY"},"tokens":[{"issuer":"https://accounts.example.org","token_type":"access_token","jti":"9c9f2e77-9a3e-4b62-9a2a-2f6e6e2a9f3e"}]},"policy":{"policy_store_id":"https://example.org/policy-stores/payments","policy_store_version":"1.2.3","policy_language":"cedar","policy_language_version":"4.4.0","bundle_hash":"sha256:6cd416d52176b7d2fb8132025f55a42443910cc8d9f2b3f1d19b98b090c2d928"},"runtime":{"pdp_id":"pdp-001"}},"producer_chain":{"producer_id":"pdp-fleet-1","producer_instance_id":"pdp-001","producer_chain_id":"chain-pdp-001-a","sequence_number":1,"prev_record_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"parent_record_ids":[],"signature":"NCteOEnLP7tcVEuDJ95lgP_DFIaz3--j2nlcRQm-2nvOnsTTHdg-WVps3e-H4PD8qC5YEjMxi805YUTJ-sB6Bw"}
```

#### V-11

- **Purpose:** Correctly signed, but `kid` is `key-unknown`, which is not registered.
- **Precondition:** fixture
- **Submitter:** `c-pdp`
- **Expected:** `400 KEY_UNKNOWN`.
- **Used by:** C-06

```json
{"producer":"pdp-fleet-1","kid":"key-unknown","record_id":"0191f3a0-7b23-7b7f-8c96-8f7ec25b4c96","trace":{"eat_profile":"tag:govops.owasp.org,2026:trace-v1","event_kind":"AUTHORIZATION_DECISION","signed_at":1781138542,"trace_execution_id":"exec-123","execution_authority":"payments-gateway","subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"event":{"decision":{"action":"Acme::Action::\"ApprovePayment\"","resource_type":"Acme::Payment","outcome":"ALLOW"},"tokens":[{"issuer":"https://accounts.example.org","token_type":"access_token","jti":"9c9f2e77-9a3e-4b62-9a2a-2f6e6e2a9f3e"}]},"policy":{"policy_store_id":"https://example.org/policy-stores/payments","policy_store_version":"1.2.3","policy_language":"cedar","policy_language_version":"4.4.0","bundle_hash":"sha256:6cd416d52176b7d2fb8132025f55a42443910cc8d9f2b3f1d19b98b090c2d928"},"runtime":{"pdp_id":"pdp-001"}},"producer_chain":{"producer_id":"pdp-fleet-1","producer_instance_id":"pdp-001","producer_chain_id":"chain-pdp-001-a","sequence_number":1,"prev_record_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"parent_record_ids":[],"signature":"k5HalDC95uWVrZWsnFS4UoXftCn6HsJX80scg8KJmbgM60BFPkD4qAlYhqgnoeF0VNUfB7RdGyFBj9VfFcbuDQ"}
```

#### V-12

- **Purpose:** `CAPABILITY_INVOKED` signed by the key authorized only for `AUTHORIZATION_DECISION`.
- **Precondition:** fixture
- **Submitter:** `c-pdp`
- **Expected:** `400 EVENT_KIND_NOT_AUTHORIZED` (or `KEY_UNKNOWN` if collapsed).
- **Used by:** C-07

```json
{"producer":"pdp-fleet-1","kid":"key-2026-01","record_id":"0191f3a0-7b24-7c80-9da7-a08fd36c5da7","trace":{"eat_profile":"tag:govops.owasp.org,2026:trace-v1","event_kind":"CAPABILITY_INVOKED","signed_at":1781138542,"trace_execution_id":"exec-123","execution_authority":"payments-gateway","subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"event":{"invocation":{"action":"Acme::Action::\"ApprovePayment\"","resource_type":"Acme::Payment","outcome":"SUCCESS"},"enforcement_point_id":"payments-gateway-01"}},"producer_chain":{"producer_id":"pdp-fleet-1","producer_instance_id":"pdp-001","producer_chain_id":"chain-pdp-001-a","sequence_number":1,"prev_record_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"parent_record_ids":[],"signature":"yzUFvKyF8UB-SCEht9Bs74o9o3rDPK44ki3a9ycSbjL6PhOx8aK1FarK2axdVxRuX68S4V4ex5NtSFBere7QCA"}
```

#### V-13

- **Purpose:** Correctly signed, but `producer` is `pdp-fleet-2` while `producer_chain.producer_id` is `pdp-fleet-1`.
- **Precondition:** fixture
- **Submitter:** `c-pdp`
- **Expected:** `400 PRODUCER_IDENTITY_MISMATCH`.
- **Used by:** C-08

```json
{"producer":"pdp-fleet-2","kid":"key-2026-01","record_id":"0191f3a0-7b25-7d91-8eb8-b190e47d6eb8","trace":{"eat_profile":"tag:govops.owasp.org,2026:trace-v1","event_kind":"AUTHORIZATION_DECISION","signed_at":1781138542,"trace_execution_id":"exec-123","execution_authority":"payments-gateway","subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"event":{"decision":{"action":"Acme::Action::\"ApprovePayment\"","resource_type":"Acme::Payment","outcome":"ALLOW"},"tokens":[{"issuer":"https://accounts.example.org","token_type":"access_token","jti":"9c9f2e77-9a3e-4b62-9a2a-2f6e6e2a9f3e"}]},"policy":{"policy_store_id":"https://example.org/policy-stores/payments","policy_store_version":"1.2.3","policy_language":"cedar","policy_language_version":"4.4.0","bundle_hash":"sha256:6cd416d52176b7d2fb8132025f55a42443910cc8d9f2b3f1d19b98b090c2d928"},"runtime":{"pdp_id":"pdp-001"}},"producer_chain":{"producer_id":"pdp-fleet-1","producer_instance_id":"pdp-001","producer_chain_id":"chain-pdp-001-a","sequence_number":1,"prev_record_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"parent_record_ids":[],"signature":"LK7wACQiOCiPGyJ9SIJvljZzwJCwCe0RutFzZ3mRocG6F3uayAlSL5XTV0VZGxWfsEbZ7p9csvI2Uf5VwHb4CQ"}
```

#### V-14

- **Purpose:** Correctly signed `AUTHORIZATION_DECISION` without `trace.execution_authority`. `trace_execution_id` is present.
- **Precondition:** `execution_correlation_required: true`
- **Submitter:** `c-pdp`
- **Expected:** `400 MISSING_EXECUTION_CONTEXT`.
- **Used by:** C-09

```json
{"producer":"pdp-fleet-1","kid":"key-2026-01","record_id":"0191f3a0-7b26-7ea2-9fc9-c2a1f58e7fc9","trace":{"eat_profile":"tag:govops.owasp.org,2026:trace-v1","event_kind":"AUTHORIZATION_DECISION","signed_at":1781138542,"trace_execution_id":"exec-123","subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"event":{"decision":{"action":"Acme::Action::\"ApprovePayment\"","resource_type":"Acme::Payment","outcome":"ALLOW"},"tokens":[{"issuer":"https://accounts.example.org","token_type":"access_token","jti":"9c9f2e77-9a3e-4b62-9a2a-2f6e6e2a9f3e"}]},"policy":{"policy_store_id":"https://example.org/policy-stores/payments","policy_store_version":"1.2.3","policy_language":"cedar","policy_language_version":"4.4.0","bundle_hash":"sha256:6cd416d52176b7d2fb8132025f55a42443910cc8d9f2b3f1d19b98b090c2d928"},"runtime":{"pdp_id":"pdp-001"}},"producer_chain":{"producer_id":"pdp-fleet-1","producer_instance_id":"pdp-001","producer_chain_id":"chain-pdp-001-a","sequence_number":1,"prev_record_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"parent_record_ids":[],"signature":"wan8V-vehv0pTrWTML4QUpWxrDXLmwbs1Ci8ejD6TKLwKnRuSj3QIgvCBpEARWFmKK2d81_p9Cb5UY0oNW3fBg"}
```

#### V-15

- **Purpose:** Correctly signed, but `trace.eat_profile` is `tag:example.com,2026:other-v1`, which the Collector does not list.
- **Precondition:** fixture
- **Submitter:** `c-pdp`
- **Expected:** `400 UNSUPPORTED_PROFILE`.
- **Used by:** C-10, D-05

```json
{"producer":"pdp-fleet-1","kid":"key-2026-01","record_id":"0191f3a0-7b27-7fb3-80da-d3b2a69f80da","trace":{"eat_profile":"tag:example.com,2026:other-v1","event_kind":"AUTHORIZATION_DECISION","signed_at":1781138542,"trace_execution_id":"exec-123","execution_authority":"payments-gateway","subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"event":{"decision":{"action":"Acme::Action::\"ApprovePayment\"","resource_type":"Acme::Payment","outcome":"ALLOW"},"tokens":[{"issuer":"https://accounts.example.org","token_type":"access_token","jti":"9c9f2e77-9a3e-4b62-9a2a-2f6e6e2a9f3e"}]},"policy":{"policy_store_id":"https://example.org/policy-stores/payments","policy_store_version":"1.2.3","policy_language":"cedar","policy_language_version":"4.4.0","bundle_hash":"sha256:6cd416d52176b7d2fb8132025f55a42443910cc8d9f2b3f1d19b98b090c2d928"},"runtime":{"pdp_id":"pdp-001"}},"producer_chain":{"producer_id":"pdp-fleet-1","producer_instance_id":"pdp-001","producer_chain_id":"chain-pdp-001-a","sequence_number":1,"prev_record_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"parent_record_ids":[],"signature":"AgxaodM3BzpGI81G5XRugRqM88t6GFJclk-tccCGymQCyjxG3tKZBQrhKmkVKCUgSx0I2EiioqvPZsvp-dWmAw"}
```

#### V-16

- **Purpose:** V-01 with `==` appended to `signature` (padded base64url).
- **Precondition:** fixture
- **Submitter:** `c-pdp`
- **Expected:** `400 SIGNATURE_MALFORMED`.
- **Used by:** C-11

```json
{"producer":"pdp-fleet-1","kid":"key-2026-01","record_id":"0191f3a0-7b1e-7c2a-9d41-3a2f7b0c9d41","trace":{"eat_profile":"tag:govops.owasp.org,2026:trace-v1","event_kind":"AUTHORIZATION_DECISION","signed_at":1781138542,"trace_execution_id":"exec-123","execution_authority":"payments-gateway","subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"event":{"decision":{"action":"Acme::Action::\"ApprovePayment\"","resource_type":"Acme::Payment","outcome":"ALLOW"},"tokens":[{"issuer":"https://accounts.example.org","token_type":"access_token","jti":"9c9f2e77-9a3e-4b62-9a2a-2f6e6e2a9f3e"}]},"policy":{"policy_store_id":"https://example.org/policy-stores/payments","policy_store_version":"1.2.3","policy_language":"cedar","policy_language_version":"4.4.0","bundle_hash":"sha256:6cd416d52176b7d2fb8132025f55a42443910cc8d9f2b3f1d19b98b090c2d928"},"runtime":{"pdp_id":"pdp-001"}},"producer_chain":{"producer_id":"pdp-fleet-1","producer_instance_id":"pdp-001","producer_chain_id":"chain-pdp-001-a","sequence_number":1,"prev_record_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"parent_record_ids":[],"signature":"NCteOEnLP7tcVEuDJ95lgP_DFIaz3--j2nlcRQm-2nvOnsTTHdg-WVps3e-H4PD8qC5YEjMxi805YUTJ-sB6Bw=="}
```

#### V-17

- **Purpose:** Correctly signed, but `record_id` is `payment-42` (not a UUID or ULID).
- **Precondition:** fixture
- **Submitter:** `c-pdp`
- **Expected:** `400 SCHEMA_INVALID`.
- **Used by:** C-12

```json
{"producer":"pdp-fleet-1","kid":"key-2026-01","record_id":"payment-42","trace":{"eat_profile":"tag:govops.owasp.org,2026:trace-v1","event_kind":"AUTHORIZATION_DECISION","signed_at":1781138542,"trace_execution_id":"exec-123","execution_authority":"payments-gateway","subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"event":{"decision":{"action":"Acme::Action::\"ApprovePayment\"","resource_type":"Acme::Payment","outcome":"ALLOW"},"tokens":[{"issuer":"https://accounts.example.org","token_type":"access_token","jti":"9c9f2e77-9a3e-4b62-9a2a-2f6e6e2a9f3e"}]},"policy":{"policy_store_id":"https://example.org/policy-stores/payments","policy_store_version":"1.2.3","policy_language":"cedar","policy_language_version":"4.4.0","bundle_hash":"sha256:6cd416d52176b7d2fb8132025f55a42443910cc8d9f2b3f1d19b98b090c2d928"},"runtime":{"pdp_id":"pdp-001"}},"producer_chain":{"producer_id":"pdp-fleet-1","producer_instance_id":"pdp-001","producer_chain_id":"chain-pdp-001-a","sequence_number":1,"prev_record_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"parent_record_ids":[],"signature":"yskjUWBEiA6JUq6a2IOJTXyG0xPSIZTGaYb3DeNtedxL9Vr_uz8GRLEhBSCTpKYqsS1B1ThA16fjPZyVjesXBg"}
```

#### V-18

- **Purpose:** Raw text of V-01 with an extra leading `record_id` member (duplicate member name). Not parseable as strict JSON.
- **Precondition:** fixture
- **Submitter:** `c-pdp`
- **Expected:** `400 MALFORMED_JSON`. Nothing accepted.
- **Used by:** C-13

```text
{"record_id":"0191f3a0-7b28-70c4-91eb-e4c3b7a091eb","kid":"key-2026-01","parent_record_ids":[],"producer":"pdp-fleet-1","producer_chain":{"prev_record_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000","producer_chain_id":"chain-pdp-001-a","producer_id":"pdp-fleet-1","producer_instance_id":"pdp-001","sequence_number":1},"record_id":"0191f3a0-7b1e-7c2a-9d41-3a2f7b0c9d41","signature":"NCteOEnLP7tcVEuDJ95lgP_DFIaz3--j2nlcRQm-2nvOnsTTHdg-WVps3e-H4PD8qC5YEjMxi805YUTJ-sB6Bw","trace":{"eat_profile":"tag:govops.owasp.org,2026:trace-v1","event":{"decision":{"action":"Acme::Action::\"ApprovePayment\"","outcome":"ALLOW","resource_type":"Acme::Payment"},"tokens":[{"issuer":"https://accounts.example.org","jti":"9c9f2e77-9a3e-4b62-9a2a-2f6e6e2a9f3e","token_type":"access_token"}]},"event_kind":"AUTHORIZATION_DECISION","execution_authority":"payments-gateway","policy":{"bundle_hash":"sha256:6cd416d52176b7d2fb8132025f55a42443910cc8d9f2b3f1d19b98b090c2d928","policy_language":"cedar","policy_language_version":"4.4.0","policy_store_id":"https://example.org/policy-stores/payments","policy_store_version":"1.2.3"},"runtime":{"pdp_id":"pdp-001"},"signed_at":1781138542,"subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"trace_execution_id":"exec-123"}}
```

#### V-20

- **Purpose:** Same record identity as V-01 (`pdp-fleet-1`, same `record_id`), different `signed_at`, correctly re-signed.
- **Precondition:** V-01 accepted
- **Submitter:** `c-pdp`
- **Expected:** `409 RECORD_ID_CONFLICT`; `existing_content_digest` = `sha256:c849281f3c5ef69a204c28cf8a3036092b159ffa782b2bee11d3513fd4455226`; `submitted_content_digest` = `sha256:2c92043b1d3c70516d452af46d7987c22701fb4b81133e8f92b4c6e83aa92e99`.
- **Used by:** C-04, C-27, B-07

```json
{"producer":"pdp-fleet-1","kid":"key-2026-01","record_id":"0191f3a0-7b1e-7c2a-9d41-3a2f7b0c9d41","trace":{"eat_profile":"tag:govops.owasp.org,2026:trace-v1","event_kind":"AUTHORIZATION_DECISION","signed_at":1781138999,"trace_execution_id":"exec-123","execution_authority":"payments-gateway","subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"event":{"decision":{"action":"Acme::Action::\"ApprovePayment\"","resource_type":"Acme::Payment","outcome":"ALLOW"},"tokens":[{"issuer":"https://accounts.example.org","token_type":"access_token","jti":"9c9f2e77-9a3e-4b62-9a2a-2f6e6e2a9f3e"}]},"policy":{"policy_store_id":"https://example.org/policy-stores/payments","policy_store_version":"1.2.3","policy_language":"cedar","policy_language_version":"4.4.0","bundle_hash":"sha256:6cd416d52176b7d2fb8132025f55a42443910cc8d9f2b3f1d19b98b090c2d928"},"runtime":{"pdp_id":"pdp-001"}},"producer_chain":{"producer_id":"pdp-fleet-1","producer_instance_id":"pdp-001","producer_chain_id":"chain-pdp-001-a","sequence_number":1,"prev_record_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"parent_record_ids":[],"signature":"Ij2gOeVkH_zlI2MPO1AkTkZ52JqGB4gpI6WpYsFueb3u2mKRahIqSZrAPpyypQkTBz78J28AQOSFlHdLGVvIAQ"}
```

#### V-21

- **Purpose:** Different `record_id`, same chain position as V-01 (`chain-pdp-001-a`, `sequence_number` 1), `DENY`, correctly signed.
- **Precondition:** V-01 accepted
- **Submitter:** `c-pdp`
- **Expected:** `201`, `equivocation_flag` true. Both records retained.
- **Used by:** C-16

```json
{"producer":"pdp-fleet-1","kid":"key-2026-01","record_id":"0191f3a0-7b21-7f5d-8a74-6d5ca03f2a74","trace":{"eat_profile":"tag:govops.owasp.org,2026:trace-v1","event_kind":"AUTHORIZATION_DECISION","signed_at":1781138542,"trace_execution_id":"exec-123","execution_authority":"payments-gateway","subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"event":{"decision":{"action":"Acme::Action::\"ApprovePayment\"","resource_type":"Acme::Payment","outcome":"DENY"},"tokens":[{"issuer":"https://accounts.example.org","token_type":"access_token","jti":"9c9f2e77-9a3e-4b62-9a2a-2f6e6e2a9f3e"}]},"policy":{"policy_store_id":"https://example.org/policy-stores/payments","policy_store_version":"1.2.3","policy_language":"cedar","policy_language_version":"4.4.0","bundle_hash":"sha256:6cd416d52176b7d2fb8132025f55a42443910cc8d9f2b3f1d19b98b090c2d928"},"runtime":{"pdp_id":"pdp-001"}},"producer_chain":{"producer_id":"pdp-fleet-1","producer_instance_id":"pdp-001","producer_chain_id":"chain-pdp-001-a","sequence_number":1,"prev_record_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"parent_record_ids":[],"signature":"2kT-JgZ7Gr9yu-X79ZG-noGZ49ZqtiFwvk_8sZbco4oAKsoG5d36oukQar5n7jYbQWPk_Wr6ITmnFop_2H2WCA"}
```

#### V-22

- **Purpose:** Chain position 2 on `chain-pdp-001-a`, but `prev_record_hash` is `sha256:` + 64 `a`; correctly signed.
- **Precondition:** V-01 accepted
- **Submitter:** `c-pdp`
- **Expected:** `201`, `chain_link_failure_flag` true.
- **Used by:** C-15

```json
{"producer":"pdp-fleet-1","kid":"key-2026-01","record_id":"0191f3a0-7b22-7a6e-9b85-7e6db14a3b85","trace":{"eat_profile":"tag:govops.owasp.org,2026:trace-v1","event_kind":"AUTHORIZATION_DECISION","signed_at":1781138542,"trace_execution_id":"exec-123","execution_authority":"payments-gateway","subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"event":{"decision":{"action":"Acme::Action::\"ApprovePayment\"","resource_type":"Acme::Payment","outcome":"ALLOW"},"tokens":[{"issuer":"https://accounts.example.org","token_type":"access_token","jti":"9c9f2e77-9a3e-4b62-9a2a-2f6e6e2a9f3e"}]},"policy":{"policy_store_id":"https://example.org/policy-stores/payments","policy_store_version":"1.2.3","policy_language":"cedar","policy_language_version":"4.4.0","bundle_hash":"sha256:6cd416d52176b7d2fb8132025f55a42443910cc8d9f2b3f1d19b98b090c2d928"},"runtime":{"pdp_id":"pdp-001"}},"producer_chain":{"producer_id":"pdp-fleet-1","producer_instance_id":"pdp-001","producer_chain_id":"chain-pdp-001-a","sequence_number":2,"prev_record_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"parent_record_ids":[],"signature":"IgZ05ki7o51YxBc0KUS3o_NkRqeOFGSt-P9Hl1pcHtkFgajFD9vnjEYCY9B6DJnIHrYNB45HZxVCoT5KIM1TBg"}
```


---

## Appendix D. Informative transport bindings

These bindings show how to satisfy §12 for common intermediaries. The governing rule is that the signed record travels as opaque text. Nothing in the intermediary may convert it into a different data model and back.

### D.1 OTLP and the OpenTelemetry Collector

- **Carriage.** Put the exact JSON text of the record in an OTLP `LogRecord` as a `string` body (`AnyValue.string_value`). Do not use `kvlist_value`, which would split the record into typed attributes and break duplicate-member detection and number fidelity. Do not use `int_value` or `double_value` for any part of the record.
- **Attributes.** Attributes such as `govops.trace.content_type = application/json` and a routing key are hints. They never carry producer identity, domain, or correlation values that the Collector relies on (FW-5).
- **Processors.** No processor in the pipeline may modify, truncate, redact, sample, or split the body of these log records. Use routing or filtering on hints only. Batch processors may group log records but MUST NOT reorder or merge bodies.
- **Exporter.** The exporter that submits to a Collector MUST be a purpose-built exporter (or equivalent) that: authenticates with its own OAuth client (FW-1); posts the unchanged body text to the single or bulk endpoint; interprets per-element results; applies §10.3; and uses a persistent queue. It MUST NOT treat OTLP-level success as Collector acceptance.
- **Acknowledgement.** An OTLP `Export` success response means only that the receiving OpenTelemetry Collector took custody (FW-9). A producer that needs acceptance evidence obtains it by direct submission, or by an out-of-band reconciliation against receipts.
- **Persistent queue.** To satisfy FW-10, enable a file-backed or equivalent durable sending queue and size it for the maximum outage the deployment tolerates. An in-memory queue does not satisfy FW-10.

### D.2 Kafka and other message brokers

- **Carriage.** The message value is the exact record bytes (UTF-8 JSON). The message key SHOULD be `producer_id` and `producer_chain_id`, which keeps a chain's records in one partition and in order. Order is not required for correctness (§8.4).
- **Domains.** Use a separate topic (or cluster) per evidence domain, consumed by a separate adapter instance holding the credential for that domain (FW-2). Topic names are routing, not evidence.
- **Producer to broker.** Use acknowledgements from all in-sync replicas and idempotent production, so custody by the broker is durable. This is custody, not acceptance (FW-9).
- **Consumer adapter.** Read, batch into a single-producer batch (or mixed batches if the Collector advertises support), submit, and commit the consumer offset only after every record in the batch has an acceptance or a terminal rejection that has been written to a dead-letter destination (FW-13).
- **Dead letter.** Write each terminally rejected record, with its Problem Details `code`, `record_id`, and `content_digest`, to a dead-letter topic with restricted access (FW-12). Do not drop it. Records for `retryable: true` outcomes stay in the main flow with backoff.
- **Retention.** Set topic retention longer than the longest tolerated Collector outage, so an outage cannot discard unacknowledged evidence.
