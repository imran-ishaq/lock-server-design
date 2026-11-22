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

Appendices: A (examples), B (OpenAPI 3.1 definition), C (test vectors), D (informative OTLP and Kafka bindings), E (requirement register).

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
- the internal receipt chain, checkpoints, or external anchoring (a Collector MAY expose one, see §6.3); [SCP-001]
- correlation, graph, analytics, or retrieval APIs;
- settlement, completeness, trust-tier, capability-resolution, or any other derived assessment;
- the mechanism by which producer keys and evidence domains are provisioned (configuration file, admin API, or other);
- the TRACE record schema, and the cryptographic suite that protects a record (signature algorithms, signature input construction, canonicalization, and content-digest computation). Both belong to the TRACE record profile and are referenced, not duplicated, here (§5.3).

If this document and a TRACE record profile disagree about the content of a record or its cryptographic protection, the profile governs. If they disagree about API behavior, this document governs.

### 1.3 Design constraints

1. The evidence format is transport-independent. REST is the canonical Collector submission interface, but a producer MAY carry a signed record through an intermediary (OTLP, Kafka, or another broker). [SCP-002] The signed bytes, not the transport, are the evidence (§12).
2. Receiving a record, verifying it, accepting it, and assessing it are different things, and this document keeps them separate (§7).
3. Nothing a client or intermediary sends outside the signed assertion can select the evidence domain, raise trust, or substitute for a producer signature.
4. The API is independent of the cryptographic suite. The record profile defines the suite, the Collector advertises it per profile, and a new profile (for example one using hardware-backed ECDSA signatures) needs no new API version (§5.3, §11).

---

## 2. Conventions and terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown here.

Normative statements in sections 1 to 14 carry a stable identifier in square brackets after the statement, for example the identifier AUT-004 for a statement about access tokens. Identifiers are described in §15.2, and are listed with their level, role, and tests in Appendix E.

JSON is as defined by RFC 8259. "Strict JSON" is defined in §5.2.

| Term | Meaning |
|---|---|
| **Record** | A producer-signed TRACE assertion: the complete top-level JSON object, including `signature`. |
| **TRACE record profile** ("profile") | The specification, identified by `trace.eat_profile`, that defines a record's members, event kinds, and cryptographic protection (§5.3). |
| **Producer** | The component that creates and signs a record. Identified by the signed `producer` member. |
| **Submitter** | The authenticated OAuth client that sends the HTTP request, identified by `(issuer, client_id)` (§4.2.2). It is often, but not always, the producer. |
| **Authorization server** | An OAuth 2.0 server that issues the access tokens the Collector accepts. The Collector trusts a configured set of them. |
| **Forwarder** | A submitter that relays records signed by other producers (§12). |
| **Collector** | A server implementing this API. |
| **Evidence domain** | The Collector's isolation partition for authorization, storage, and identity. Derived by the Collector from the authenticated submitter, never from the record (§4.4). |
| **Producer key registry** | The Collector's administratively provisioned mapping from `(evidence domain, producer_id, kid)` to a public key and the event kinds that key may sign. |
| **Record identity** | `(evidence domain, producer_id, record_id)`. |
| **`content_digest`** | A Collector-computed fingerprint of the complete record, including `signature`, constructed as the record's profile defines and written `<algorithm>:<value>` (§5.5). |
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
| GET | `/api/v1/audit/trace/receipts/{producer_id}/{record_id}` | Receipt lookup (optional, §7.3.1) | OAuth 2.0 access token with the receipt scope |

The paths above are canonical for API version `v1`. A Collector MAY be deployed under a path prefix; the endpoints it serves are then the URLs published in its metadata (§11), and clients MUST use those URLs instead of constructing them. [OVR-001]

---

## 4. Authentication and authorization

### 4.1 Transport security

- Every request to the ingestion endpoints MUST use TLS. [TRN-001] A Collector MUST NOT serve them over cleartext HTTP and MUST NOT redirect a cleartext request to HTTPS for an ingestion endpoint (the access token would already have been exposed). [TRN-002]
- A Collector MUST support TLS 1.2 or later and SHOULD support TLS 1.3 (RFC 8446). [TRN-003] It MUST NOT negotiate SSL 3.0, TLS 1.0, or TLS 1.1. [TRN-004]
- Clients MUST validate the Collector's certificate chain and host name. [TRN-005]

### 4.2 OAuth 2.0 access tokens and submitter identity

#### 4.2.1 Presenting tokens and minimum mechanisms

A request to an ingestion endpoint MUST carry an OAuth 2.0 access token. [AUT-001] Tokens MUST NOT be accepted in a URI query parameter or in the request body. [AUT-002]

**A conforming Collector MUST support, at a minimum:** [AUT-003]

1. Bearer tokens in the `Authorization` request header (RFC 6750 §2.1). [AUT-M1]
2. Access tokens issued to a client acting on its own behalf (the client credentials grant, RFC 6749 §4.4), as JWT access tokens (RFC 9068). The Collector validates the signature with the keys of the issuing authorization server (published at the `jwks_uri` in its RFC 8414 metadata), and checks `iss`, `aud` (§4.2.3), `exp`, `nbf` when present, the client identifier claim (§4.2.2), and `scope` (§4.3). [AUT-M2] The Collector MUST reject a token whose `alg` is `none` or a symmetric algorithm, and MUST NOT fetch keys from a `jku`, `x5u`, or `jwk` header parameter. [AUT-004]
3. Rejection of a sender-constrained token whose proof it cannot verify (§4.2.4). [AUT-M3] A token that carries a confirmation (`cnf`) claim MUST NOT be accepted as a plain bearer token. [AUT-005]

**A Collector MAY also support:** opaque access tokens validated by token introspection (RFC 7662) (and MUST, if it lists an authorization server with `token_format: "introspection"`); DPoP-bound tokens (RFC 9449); and certificate-bound tokens (RFC 8705). [AUT-006]

**How the submitter authenticates to the authorization server** (for example `client_secret_basic`, `private_key_jwt`, or mutual TLS) is a matter between the submitter and its authorization server and is outside this API. The Collector sees only the resulting token. For forwarders, which hold credentials that can submit for many producers, asymmetric client authentication (`private_key_jwt`, RFC 7523, or `tls_client_auth`, RFC 8705) is RECOMMENDED over a shared secret. [AUT-007]

#### 4.2.2 Submitter identity

A **submitter identity** is the ordered pair **(issuer, client_id)**:

- `issuer` is the identifier of the authorization server that issued the token, and
- `client_id` is the OAuth client identifier within that authorization server.

A client identifier is unique only within its authorization server. A Collector may trust several authorization servers, so:

1. A submitter identity MUST be scoped to its issuing authorization server. [IDN-001] `client_id` alone MUST NOT identify a submitter, bind an evidence domain, or grant any permission. [IDN-002]
2. Two identities are equal only if both components are equal. [IDN-R1] Each is compared as an exact string (simple string comparison, RFC 3986 §6.2.1), with no normalization and no case folding. A client `c-pdp` at one authorization server is a different submitter from `c-pdp` at another.
3. A Collector MUST NOT concatenate the pair into one string unless the encoding is unambiguous (for example a JSON array, or length-prefixed components). [IDN-003]

**Derivation.** The Collector MUST derive the submitter identity from the validated claims of the access token, or from an authenticated introspection response, according to the documented token profile of the authorization server that issued it. [IDN-004] The Collector records that profile for each trusted authorization server and publishes it in its metadata (§11.2, `authorization_servers`).

| Token format | `issuer` | `client_id` |
|---|---|---|
| JWT access token (`token_format: "jwt"`) | The validated `iss` claim. It MUST be exactly one of the Collector's configured issuers. | The claim named by the server's `client_id_claim` (default `client_id`, RFC 9068 §2.2). [IDN-005] |
| Opaque token with introspection (`token_format: "introspection"`) | The issuer of the authorization server whose introspection endpoint returned `active: true`. If the response contains `iss`, it MUST equal that issuer. | The response member named by the server's `client_id_claim` (default `client_id`, RFC 7662 §2.2). [IDN-006] |

Rules:

- If the client identifier is absent, empty, or not a string, the request is rejected with `401 UNAUTHENTICATED`. The Collector MUST NOT fall back to `sub`, `azp`, a certificate subject, or any other value, unless the server's token profile names that claim as `client_id_claim`. [IDN-007]
- The identity MUST NOT be taken from a request header, query parameter, request body, record content, an unvalidated token, or the subject of a TLS client certificate. [IDN-008] (A certificate can bind a token under RFC 8705. It does not supply the identity.)
- A token's `iss` selects the keys or introspection endpoint of that authorization server and no other. The Collector checks `iss` against its configured issuers before choosing any key. A token validated for one authorization server can never produce an identity with another server's issuer. This prevents issuer mix-up and key confusion.
- When the token represents a resource owner acting through a client, the identity is still the client's `(issuer, client_id)`. The user's `sub` plays no role in this API.
- The Collector MAY retain the identity as ingestion metadata outside the signed assertion. [IDN-009]

The submitter identity is the only identity this document uses for evidence-domain binding (§4.4) and submitter-to-producer permission (§4.5). Both bindings are configured against `(issuer, client_id)` pairs.

#### 4.2.3 Token validation and failures

- The Collector MUST validate the token before processing the body: signature or introspection result, expiry, `nbf` when present, issuer, and audience. [TOK-001]
- **Audience.** A JWT access token's `aud` MUST contain the Collector's `issuer` identifier from its metadata, which serves as the Collector's resource identifier (RFC 8707, RFC 9728). [TOK-002] An introspection response that contains `aud` MUST contain it as well. [TOK-003]
- A missing, expired, malformed, or otherwise invalid token, an issuer that is not configured, an unusable client identifier, or an inactive introspection result yields `401` with `WWW-Authenticate` (RFC 6750 §3) and problem code `UNAUTHENTICATED`.
- If the Collector cannot obtain the keys or the introspection result it needs and has no valid cached result, it MUST respond `503 COLLECTOR_UNAVAILABLE` (with `Retry-After`) and MUST NOT accept the request. [TOK-004] Key sets MAY be cached as HTTP caching permits. [TOK-005] An introspection result MUST NOT be cached beyond the token's `exp` or a configured maximum (RECOMMENDED: 5 minutes at most). [TOK-006]
- A Collector SHOULD reject a JWT access token whose lifetime (`exp` minus `iat`) exceeds a configured maximum. [TOK-007]

#### 4.2.4 Sender-constrained tokens

- Sender-constrained tokens are RECOMMENDED, and especially for forwarders. [SCT-001]
- If a token carries a confirmation claim (`cnf`, in the JWT or in the introspection response), the Collector MUST verify the corresponding proof (RFC 9449 for `jkt`, RFC 8705 for `x5t#S256`) and MUST reject the request with `401 UNAUTHENTICATED` if it cannot. [SCT-002] It MUST NOT treat a constrained token as a bearer token. [SCT-003]
- A Collector that supports either mechanism lists it in `sender_constrained_tokens_supported` (§11.2).

### 4.3 Scopes

- The Collector MUST define one ingestion scope and MUST publish its name as `ingestion_scope` in its metadata. [SCO-001] A token without that scope yields `403` with `INSUFFICIENT_SCOPE`.
- The RECOMMENDED scope name is `trace.write`. [SCO-002] Deployments MAY use a namespaced value, such as a URI. [SCO-003] Clients MUST read the name from metadata. [SCO-004]
- The ingestion scope MUST NOT also authorize producer-key administration, evidence retrieval, receipt lookup, or any other function. [SCO-005] Retrieval and administration use separate scopes and are not defined here.
- A Collector that offers receipt lookup (§7.3.1) defines a separate **receipt scope** and publishes its name as `receipt_scope`. It MUST differ from the ingestion scope. [SCO-006] A token with only the ingestion scope cannot look up receipts, and a token with only the receipt scope cannot submit records.

### 4.4 Evidence-domain isolation

- The Collector MUST derive the evidence domain from the authenticated submitter identity `(issuer, client_id)` (§4.2.2) and the Collector's own configuration. [DOM-001] The binding is configured against the pair, never against `client_id` alone.
- A submitter identity with no evidence-domain binding MUST be rejected with `403` and `EVIDENCE_DOMAIN_NOT_BOUND`. [DOM-002] A client that has the same `client_id` as a bound client, but is issued by a different authorization server, is a different identity and is unbound unless configured. The Collector MUST NOT apply a default domain to an unbound submitter in a multi-domain deployment. [DOM-003] (A deployment with exactly one domain MAY treat it as an implicit configured value, but the rules in this section still apply.) [DOM-004]
- The evidence domain MUST NOT be read from the request path, query, headers, or record body. [DOM-005] If a record contains a member named `evidence_domain_id` (or an equivalent partition field), the Collector MUST ignore it for every purpose, and SHOULD flag it for operators. [DOM-006] The member remains part of the signed assertion and is preserved unchanged.
- The evidence domain MUST be determined before any producer-key lookup, identity lookup, or content-based routing. [DOM-007]
- Every read and write in the Collector MUST be scoped to that domain. [DOM-008] A record identity, key, or receipt in another domain MUST NOT be observable through any response, error detail, timing-dependent behavior the Collector controls, or idempotency result. [DOM-009] In particular, a submission in domain D2 MUST NOT conflict with, replay, or reveal an identical record identity in domain D1. [DOM-010]
- A producer that legitimately submits to several domains needs a separately provisioned key registration and a separately bound submitter credential in each.

### 4.5 Submission authorization is not producer verification

Two independent checks apply to every record. Neither substitutes for the other.

| | Submission authorization | Producer verification |
|---|---|---|
| Question | May this authenticated submitter, identified by `(issuer, client_id)`, send records to this Collector, for this producer? | Did the registered producer sign exactly these bytes, and may that key sign this event kind? |
| Evidence | OAuth token, scope, submitter-to-evidence-domain binding, submitter-to-producer permission | Producer key registry entry, `kid`, signature verified as the record's profile defines |
| Failure | `401`, `403` | `400` with a key or signature code |
| Granted by | The Collector's access-control configuration | The producer key registry, provisioned administratively |

Rules:

1. **Submitter-to-producer permission.** The Collector MUST maintain which submitter identities `(issuer, client_id)` may submit records for which `producer_id` values. [PRM-001] By default a submitter may submit only for the producer it represents. A submitter MAY submit for other producers only if the Collector's configuration explicitly permits that submitter to forward for those producers (§12). [PRM-002] A submitter that is not permitted MUST be rejected with `403` and `SUBMITTER_NOT_AUTHORIZED`, before key resolution or signature verification. [PRM-003]
2. **No self-authenticating keys.** The Collector MUST NOT accept a public key from a request. [PRM-004] Keys come only from the producer key registry, provisioned by an administrative path separate from the ingestion scope.
3. **Producer identity comes from the signed record.** The Collector MUST NOT accept a producer identity, `kid`, or evidence domain from an unsigned header, query, or transport attribute in place of the values in the signed assertion. [PRM-005]
4. **Registry authority.** The index `(evidence domain, producer_id, kid)` locates a candidate key. Authority to sign comes from the administrative registration of that key: it exists, is within its validity window and not revoked **at the evaluation time defined in §4.5.1**, is registered for this `producer_id`, and lists the record's `trace.event_kind` as permitted.
5. **A valid OAuth token never makes an invalid signature acceptable**, and a valid signature never overrides a missing submission permission.

The minimum content of a producer key registration is informative. The key representation and algorithm are defined by the profile. The example is for a profile that uses Ed25519:

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

#### 4.5.1 Time used for key validity checks

The validity window (`valid_from`, `valid_until`) and `revoked_at` of a key are compared with a single time. This version defines it.

**Evaluation time.** For a record the Collector has not accepted before, the evaluation time is **the Collector's own clock reading when it performs step 11 of §4.6, for that record**. [KEY-R0] The Collector MUST NOT use any time supplied by the client or the record for this purpose. [KEY-001] In particular it MUST NOT use `trace.signed_at`, an HTTP `Date` header, a request header or parameter, a transport timestamp, or a message timestamp from an intermediary. [KEY-002]

**Rule.** Given the evaluation time `T`, a key is valid if and only if all of the following hold: [KEY-R1]

- `valid_from` is absent or `valid_from ≤ T`;
- `valid_until` is absent or `T < valid_until`; and
- `revoked_at` is absent or `T < revoked_at`.

A key that is not valid at `T` yields `KEY_NOT_VALID`. A key that is not registered at all yields `KEY_UNKNOWN`.

**Consistency.**
- Each record has one evaluation time. [KEY-R2] A Collector MAY use one time for all elements of a bulk request, or a separate time for each element, but MUST be consistent within a request. [KEY-003]
- For an accepted record, the evaluation time MUST NOT be later than that record's `received_at`. [KEY-004]
- The Collector MUST retain, for every accepted record, the identity of the key that verified it (for example its thumbprint) and the evaluation time. [KEY-005] A Collector MAY expose them through its retrieval interfaces, which are outside this document. [KEY-006]

**Idempotent replay.** A replay (step 10) is answered before key validity is evaluated, and the verification decision made at the original acceptance is preserved. The Collector MUST NOT re-evaluate the key for a record it has already accepted, and MUST NOT change the retained evaluation time, key identity, or receipt. [KEY-007] Later expiry, rotation, or revocation of the key has no effect on a replay (§9).

**Why acceptance time.** `signed_at` is asserted by the producer. If it were used, anyone holding an expired or revoked key could backdate a record into the key's validity window. The Collector's clock is the only time source that the producer cannot choose. A trusted external timestamp, which would let a Collector evaluate validity as of an independently attested signing time, is not defined in this version. A later version or profile MAY define it. [KEY-008]

**Consequence: delayed delivery.** A record that was legitimately signed while its key was valid can reach the Collector after the key has expired or been revoked. This happens when delivery is delayed by an outage, by a Collector or network failure, or by a queue that holds records for a long time (for example a Kafka topic or an OpenTelemetry persistent queue). Under this rule the Collector rejects such a record with `KEY_NOT_VALID`. This is intended behavior for `v1`, and it affects honest producers as well as attackers. Deployments SHOULD plan for it:

- Operators SHOULD keep a rotated-out key valid for verification for at least the longest delivery delay they tolerate after the producer last signed with it. [KEY-009] A registry SHOULD distinguish the time a key stops being used for signing from the time it stops being accepted for verification. [KEY-010]
- Operators SHOULD NOT revoke a key as routine rotation. [KEY-011] Revocation means that records first presented after `revoked_at` are rejected, whenever they were signed.
- Operators SHOULD set `valid_from` earlier than the first use of a key by at least the clock skew between producer and Collector, and Collectors SHOULD keep their clocks synchronized to a trusted source. [KEY-012]
- A rejection with `KEY_NOT_VALID` is recoverable: after an operator extends the key's validity (or re-registers it) so that the Collector's current time falls within it, the same bytes can be resubmitted and accepted. Intermediaries SHOULD keep such records rather than discard them (FW-12, Appendix D). [KEY-013]

### 4.6 Processing order

A Collector MUST produce results as if it evaluated the following steps in order for each request, and MUST report the first failing step. [ORD-001] Steps 10a to 14 apply only to a record that is not a replay (§9.2). [ORD-R2] Steps 1 to 6b apply to the request; steps 7 to 16 apply to each record. This order ensures that authorization precedes content processing, that cheap limit checks precede cryptography, and that replay is recognized before key-validity checks.

| # | Step | Failure |
|---|---|---|
| 1 | TLS | connection refused [ORD-S01] |
| 2 | Authenticate the token and derive the submitter identity `(issuer, client_id)` (§4.2) | `401 UNAUTHENTICATED`; `503 COLLECTOR_UNAVAILABLE` if keys or introspection are unavailable [ORD-S02] |
| 3 | Check ingestion scope | `403 INSUFFICIENT_SCOPE` [ORD-S03] |
| 4 | Derive evidence domain | `403 EVIDENCE_DOMAIN_NOT_BOUND` [ORD-S04] |
| 5 | Check `Content-Type`, `Content-Encoding`, body byte limit (`max_record_bytes` for a single-record request, `max_batch_bytes` for a batch), rate limit | `415`, `413 RECORD_TOO_LARGE` or `413 REQUEST_TOO_LARGE`, `429` [ORD-S05] |
| 6a | Strict-parse the whole body as one JSON document (§5.2) | `400 MALFORMED_JSON`: whole request rejected [ORD-S06A] |
| 6b | Check the envelope. Single-record request: the top-level value is a JSON object. Batch: the top-level value is an array, it is non-empty, within the count limit, and (unless mixing is supported) all elements that have a string `producer` have the same one | `400 SCHEMA_INVALID` (single), `400 BATCH_NOT_ARRAY`, `BATCH_EMPTY`, `BATCH_TOO_MANY_RECORDS`, `BATCH_MIXED_PRODUCERS`: whole request rejected [ORD-S06B] |
| 7 | For each record that is a JSON object with a string `producer`, check submitter-to-producer permission. Elements that are not such objects skip this step and fail at step 9 | `403 SUBMITTER_NOT_AUTHORIZED` [ORD-S07] |
| 8 | Check per-record size limit | `413 RECORD_TOO_LARGE` [ORD-S08] |
| 9 | Identify the record: the element is a JSON object, `producer`, `record_id`, and `trace.eat_profile` are strings, and the Collector can canonicalize records of that profile (including a profile kept for replay only, §9.2) | `400 SCHEMA_INVALID`, `UNSUPPORTED_PROFILE` [ORD-S09] |
| 10 | Compute `content_digest`; look up the record identity; if an accepted record with the same digest exists and its replay data is retained (§9.1), return its original receipt. Steps 10a to 14 are skipped | none: replay [ORD-S10] |
| 10a | Validate the record as a new record under the **current** rules: the profile is currently accepted for new records, required members, `record_id` form, `producer` equals `producer_chain.producer_id`, event-kind schema, array limits, required correlation context | `400 SCHEMA_INVALID`, `UNSUPPORTED_PROFILE`, `PRODUCER_IDENTITY_MISMATCH`, `MISSING_EXECUTION_CONTEXT` [ORD-S10A] |
| 11 | Resolve the key by `(evidence domain, producer_id, kid)`; check validity window and revocation at the evaluation time (§4.5.1, the Collector's clock, never `signed_at`); check `event_kind` permission | `400 KEY_UNKNOWN`, `KEY_NOT_VALID`, `EVENT_KIND_NOT_AUTHORIZED` [ORD-S11] |
| 12 | Check the signature encoding and algorithm, and verify the signature, all as the record's profile defines | `400 SIGNATURE_MALFORMED`, `UNSUPPORTED_ALGORITHM`, `SIGNATURE_INVALID` [ORD-S12] |
| 13 | If the identity exists with a different digest | `409 RECORD_ID_CONFLICT` [ORD-S13] |
| 14 | Check chain admission (§7.4.1). If admitted, evaluate integrity and completeness and set the flags (§7.4.2, §7.4.3). The evaluation is REQUIRED here only if the Collector advertises `synchronous_integrity_flags`. Otherwise it MAY be deferred until after acceptance (§7.4.5). | `400 CHAIN_NOT_REGISTERED`; otherwise none: flags [ORD-S14] |
| 15 | Atomically and durably commit the record and its receipt | `503 COLLECTOR_UNAVAILABLE`, `500 INTERNAL_ERROR` [ORD-S15] |
| 16 | Return the receipt | none [ORD-S16] |

#### Scope of each failure

A failure rejects either the whole request or one element. The scope depends on whether the failure is in the request or in one record.

| Validation failure | Scope | Result |
|---|---|---|
| The body is not a valid strict JSON document: syntax error, invalid UTF-8, duplicate member name anywhere, excessive nesting, an unrepresentable value (§5.2) | **Entire request** | `400 MALFORMED_JSON`. Nothing is processed, including elements that appear valid. [VAL-01] |
| The batch envelope is invalid: top-level value is not an array, empty, too many elements, body too large, mixed producers without support | **Entire request** | `400` or `413` with an envelope code. Nothing is processed. [VAL-02] |
| Single-record request whose body is valid JSON but not an object | **Entire request** (the body is the record) | `400 SCHEMA_INVALID`. [VAL-03] |
| Valid JSON element in a batch that is not an object, or that violates the record schema, profile, event-kind schema, `record_id` form, or correlation requirement | **Individual element** | Element rejected with `SCHEMA_INVALID` (or the specific code, such as `UNSUPPORTED_PROFILE`). Other elements are processed. [VAL-04] |
| Record too large (batch element) | **Individual element** | `RECORD_TOO_LARGE`. [VAL-05] |
| Submitter not permitted for the element's producer in a mixed batch | **Individual element** | `SUBMITTER_NOT_AUTHORIZED`. [VAL-06] |
| Key unknown, not valid, or not authorized for the event kind; signature malformed, unsupported algorithm, or invalid | **Individual element** | The specific code of §10.2. [VAL-07] |
| Chain not registered; identity conflict | **Individual element** | `CHAIN_NOT_REGISTERED`; `RECORD_ID_CONFLICT`. [VAL-08] |
| Durable write fails for one element | **Individual element** | `COLLECTOR_UNAVAILABLE`. [VAL-09] |

The reason for the first row is that a document that is not valid JSON has no trustworthy element boundaries, and a duplicate member name has two possible meanings. The Collector therefore cannot say which element is affected, and it rejects the request without processing any part of it. In contrast, a valid JSON document whose element has the wrong type or shape has a well-defined element, which can be rejected without affecting the others. On the single-record endpoint the two scopes coincide, because the request contains one record.

---

## 5. Wire format

### 5.1 Content types and encoding

- Requests: `Content-Type: application/json`. The body is UTF-8. A Collector MUST reject any other media type with `415` and `UNSUPPORTED_MEDIA_TYPE`. [WIR-001]
- A Collector MAY accept `Content-Encoding: gzip` and, if so, MUST list it in `content_encodings_supported`. [WIR-002] A client MUST NOT send a content encoding the Collector has not advertised. [WIR-003] Every size and nesting limit applies to the decoded body, and the Collector MUST enforce a decoded-size limit while decoding (not after) to resist decompression bombs. [WIR-004]
- Successful responses: `application/json`. Error responses: `application/problem+json` (RFC 9457).
- A Collector MUST ignore request headers that purport to carry producer identity, `kid`, evidence domain, or correlation values (for example `Audit-Trace-ID`); these are correlation hints, never evidence. [WIR-005]

### 5.2 Strict JSON

The request body MUST be strict JSON, parsed as one document before any element of it is processed. [JSN-001] A Collector MUST reject the **entire request** with `400 MALFORMED_JSON` if the body contains any of the following, and MUST NOT process any part of it:

- invalid UTF-8, or invalid Unicode scalar values in strings; [JSN-L1]
- a duplicate member name at any depth (a parser that silently keeps the first or last duplicate is not acceptable for signed input); [JSN-L2]
- `NaN`, `Infinity`, `-Infinity`, or values the profile's canonicalization cannot represent unambiguously (the profile MAY add stricter rules); [JSN-002]
- trailing non-whitespace content after the JSON value; [JSN-L3]
- nesting deeper than `max_nesting_depth`. [JSN-L4]

These are failures of the JSON document. A valid JSON value of the wrong type or shape is not malformed JSON. A single-record body that is valid JSON but not an object is rejected with `400 SCHEMA_INVALID`. [JSN-R1] A batch element that is valid JSON but not an object is rejected individually with `SCHEMA_INVALID` (§8.2). The scope of every failure is in the table in §4.6.

### 5.3 Record structure and the profile contract

The TRACE record profile named in the record's `trace.eat_profile` defines the record. This document does not restate it and does not define any cryptographic algorithm.

**Profile-defined.** The profile, not this API, defines:

1. the signature algorithms and the public-key representation;
2. the signature input construction;
3. the signature encoding;
4. canonicalization of the record;
5. the content-digest algorithm, its construction, and its textual form;
6. the predecessor sentinel for the first record of a chain;
7. the event kinds and their schemas; and
8. any strictness beyond §5.2, such as a number model.

**Conformance rule.** Signature algorithms, signature input construction, canonicalization, and content-digest computation MUST conform to the TRACE record profile identified by the record's `trace.eat_profile` and advertised by the Collector in its metadata (§11). [PRF-001] A Collector MUST NOT negotiate, select, or accept an algorithm independently of the applicable profile, and MUST NOT apply the cryptographic rules of one profile to a record of another. [PRF-002] A Collector MUST NOT accept an algorithm named in the request, in a header, or in transport metadata. [PRF-003]

**Why this matters.** The API depends on a profile only through the contract in this section. A future profile, for example one that requires hardware-backed ECDSA signatures, is supported by listing it in the Collector's metadata. It does not require a new API version.

**What a profile must provide to be used with this API.**

- The members in the table below, under these names.
- A canonicalization that is a deterministic function of the record, such that two records have the same canonical form if and only if they are semantically identical.
- A content digest that is a deterministic, collision-resistant function of the complete record including its signature, written `<algorithm>:<value>` with exactly one textual form for a given digest, so that digests can be compared as strings.
- A signed scope that includes `producer`, `kid`, `record_id`, `trace`, and `producer_chain`, and every other member except the signature itself.
- A key registration model in which a key states its algorithm.

**Members the Collector reads** for routing, identity, and verification:

| Member | Use by the Collector |
|---|---|
| `producer` | Stable logical producer identifier. MUST equal `producer_chain.producer_id` byte for byte. [PRF-004] |
| `kid` | Selects the registered key. Inside the signed scope. |
| `record_id` | Producer-generated identity within the producer's namespace. |
| `trace.eat_profile` | MUST be one of the profiles in the Collector's `trace_profiles` metadata. [PRF-005] |
| `trace.event_kind` | MUST be permitted for the key. [PRF-006] |
| `trace.signed_at` | Producer time (NumericDate). A claim, never an ordering authority, and never used for key validity (§4.5.1). |
| `producer_chain.*` | Chain position and predecessor hash (§7.4). |
| `signature` | The signature value, encoded as the profile specifies. |

Unknown members MUST be preserved and are covered by the signature. [PRF-007] A Collector MUST NOT remove, rename, reorder for storage semantics, or add members to the signed assertion. [PRF-008]

*Example (informative).* Profile `tag:govops.owasp.org,2026:trace-v1` defines Ed25519 (RFC 8032) signatures; a signature input that is the RFC 8785 (JCS) canonical form of the record without its top-level `signature`; an unpadded base64url signature encoding (RFC 4648 §5); a content digest that is SHA-256 of the JCS form of the complete record, written `sha256:` plus lowercase hexadecimal; and the predecessor sentinel `sha256:` plus 64 zeros. The vectors in Appendix C belong to that profile.

### 5.4 Signature

- Verification MUST use the algorithm, signature input construction, and signature encoding that the record's profile defines (§5.3). [SIG-001] A Collector MUST reject a malformed signature encoding with `SIGNATURE_MALFORMED`. [SIG-002]
- The algorithm needed to verify a record MUST be one the Collector lists for that profile in `trace_profiles` (§11.2) and MUST match the algorithm of the registered key. [SIG-003] Otherwise the Collector MUST reject the record with `UNSUPPORTED_ALGORITHM`. [SIG-004]
- The Collector MUST verify with the key selected by the signed `kid`. [SIG-005] It MUST NOT guess a key from a timestamp, and MUST NOT take a key or an algorithm from the request. [SIG-006]

### 5.5 Content digest

`content_digest` fingerprints the entire signed record, including its signature. It is computed as the record's profile defines, and is written `<algorithm>:<value>` (for example `sha256:` followed by lowercase hexadecimal). Two records have the same `content_digest` only if they have the same canonical form. [DIG-R3]

`content_digest` is Collector-computed. It is never a signature-verification result, a record identifier, or a producer-supplied value. A producer-supplied `content_digest` member, if present, has no effect. [DIG-R1] Digests are compared as exact strings. [DIG-R2]

### 5.6 Record identity

- `record_id` is produced by the producer inside the signed body. It MUST be a UUID in lowercase canonical text form (RFC 9562, `8-4-4-4-12` lowercase hexadecimal) or a ULID in uppercase Crockford base32 (26 characters). [RID-001] A Collector MUST reject other forms with `SCHEMA_INVALID`. [RID-002]
- A Collector MUST compare `record_id` as an exact string. [RID-003] Because forms are fixed, one UUID cannot appear under two identities by changing letter case.
- The record identity is `(evidence domain, producer_id, record_id)`. [RID-R1] Two producers MAY use the same `record_id` without collision. [RID-004]

### 5.7 Signature and byte preservation

- A Collector MUST store the assertion so that its canonical form (as the profile defines it), and therefore its signature input and `content_digest`, can be reproduced exactly at any later time. [PRS-001] A Collector MUST NOT insert resolved claims, status, trust, corrections, or receipt data into the assertion. [PRS-002]
- A Collector SHOULD also retain the exact received bytes, because some later anchoring formats commit to the as-transmitted serialization, which canonicalization cannot reconstruct. [PRS-003]
- Idempotency and conflict decisions use `content_digest`, so a semantically identical resubmission with different whitespace, member order, or number spelling is the same record. [PRS-R1]

### 5.8 Limits

A Collector MUST enforce, and MUST publish in metadata (§11), at least these limits:

| Limit | Metadata field | Minimum a Collector MUST support | Failure |
|---|---|---|---|
| Bytes in one record (decoded) | `max_record_bytes` | 65,536 | `413 RECORD_TOO_LARGE` [LIM-RECORD] |
| Bytes in one bulk request body (decoded) | `max_batch_bytes` | 1,048,576 | `413 REQUEST_TOO_LARGE` [LIM-BATCHBYTES] |
| Records in one batch | `max_batch_records` | 100 | `400 BATCH_TOO_MANY_RECORDS` [LIM-BATCHRECORDS] |
| JSON nesting depth | `max_nesting_depth` | 16 | `400 MALFORMED_JSON` [LIM-DEPTH] |

Recommended defaults: 262,144 bytes per record, 8 MiB per request, 500 records per batch, depth 32. Array-length limits inside a record (for example `tokens[]`) are defined by the TRACE record profile and are reported as `SCHEMA_INVALID`; a Collector MUST NOT silently truncate a signed array. [LIM-001]

A Collector MUST apply all limits before expensive cryptographic processing. [LIM-002] A client MUST NOT send more than the advertised limits. [LIM-003]

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
| `201 Created` | First durable acceptance: the record was verified and durably accepted by this request | Acceptance receipt, `idempotent_replay` false [SUB-S1] |
| `200 OK` | Idempotent replay: an identical record had already been accepted | The original acceptance receipt, `idempotent_replay` true [SUB-S2] |
| `400` | Malformed JSON, invalid record, unverifiable signature or key | Problem Details [SUB-S3] |
| `401`, `403` | Authentication or authorization failure | Problem Details [SUB-S4] |
| `409` | The record identity is bound to different content | Problem Details [SUB-S5] |
| `413`, `415`, `429` | Limit, media type, rate | Problem Details [SUB-S6] |
| `500`, `503` | Nothing was accepted; retry is safe | Problem Details [SUB-S7] |

`201` and `200` are used, and `202 Accepted` is not, because `202` conventionally means that processing has not completed. This API acknowledges only after verification and durable storage (§7.2). A `201` means the record was durably accepted by this request. A `200` means an earlier request already accepted it. A client MUST treat both as acceptance and MUST use `idempotent_replay`, not the status, to tell them apart. [SUB-001] A `201` response MAY include a `Location` header if the Collector offers a retrieval URL for the record; clients MUST NOT depend on it. [SUB-002]

### 6.3 Acceptance receipt

The example below is from a Collector that advertises `synchronous_integrity_flags: true`. A Collector that does not omits the four flag members (§7.4.5, Appendix A.2).

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
| `accepted` | REQUIRED | `true`. [RCP-001] |
| `producer_id`, `record_id` | REQUIRED | Echo of the record identity. [RCP-002] |
| `content_digest` | REQUIRED | The Collector-computed digest (§5.5). A producer SHOULD compare it with its own computation. [RCP-003] |
| `receipt_id` | REQUIRED | Opaque string, unique within the evidence domain, assigned once per accepted record, and identical on every replay. [RCP-004] |
| `received_at` | REQUIRED | RFC 3339 UTC timestamp with exactly millisecond precision and a `Z` suffix, assigned by the Collector at acceptance and identical on every replay. [RCP-005] |
| `idempotent_replay` | REQUIRED | `false` on first acceptance; `true` when the response repeats an earlier acceptance. [RCP-006] |
| `coverage_gap_flag`, `chain_link_failure_flag`, `equivocation_flag`, `late_flag` | CONDITIONAL | REQUIRED, all four, if the Collector advertises `synchronous_integrity_flags: true` (§11.2). Otherwise the Collector MUST omit all four (§7.4.5). Values are as of the moment of original acceptance (§7.4). [RCP-007] |
| `unattributed_flag` | CONDITIONAL | REQUIRED if the Collector accepts records without correlation context (§7.5). [RCP-008] |
| `chain_admission` | OPTIONAL | How the record's chain was admitted: `pre_registered_genesis`, `first_observed_genesis`, or `linked_restart_genesis` (§7.4.1). RECOMMENDED when the Collector lists more than one mode. [RCP-009] |
| `receipt_sequence` | OPTIONAL | Position in a Collector-internal receipt chain, if the Collector exposes one. Clients MUST NOT depend on its presence. [RCP-010] |

A Collector MAY add members. [RCP-011] A client MUST ignore members it does not recognize. [RCP-012] This document does not standardize the Collector's internal receipt chain, commitment profile, checkpoints, or settlement status; a Collector exposing them does so through extension members.

---

## 7. Acceptance semantics

### 7.1 Three different things

| Stage | What it establishes | When | Where reported |
|---|---|---|---|
| **Cryptographic verification** | The producer key was registered, valid, and authorized for the event kind, and the signature is valid as the record's profile defines. | Before acceptance (steps 11 and 12). | A failure is an error response. Success is implied by a receipt. |
| **Acceptance** | The Collector durably holds the assertion and a receipt for it, bound to the evidence domain, and will return the same receipt for any identical resubmission. | At the `201` or `200` (or an accepted bulk element). | The acceptance receipt. |
| **Evidence assessment** | Derived findings such as settlement, completeness, trust tier, capability resolution, lineage coverage, and (if the Collector defers it) producer-chain integrity and completeness (§7.4.5). | Later, asynchronously, any number of times. | Outside this API. |

Rules that follow:

1. A Collector MUST NOT report `accepted: true` for a record that has not passed verification. [ACC-001] A Collector MAY retain a record that failed verification in separately access-controlled quarantine, but it MUST respond as for a rejection, MUST NOT return a receipt, and MUST NOT make the quarantined record visible to any evidence retrieval or correlation. [ACC-002]
2. Acceptance does not imply that the record is true, complete, authorized, correlated, settled, or independently observed. A valid signature proves that the registered producer key signed those bytes.
3. A Collector MUST NOT label accepted records as `settled`, `complete`, or externally anchored on the basis of acceptance. [ACC-003]
4. Assessments MUST NOT modify the accepted assertion. [ACC-004] They are stored and reported separately.
5. Acceptance establishes successful verification and durable storage, independently of chain assessment. A Collector MAY evaluate producer-chain integrity and completeness asynchronously (§7.4.5). [ACC-005]

### 7.2 When a Collector may acknowledge

A Collector MUST NOT return a receipt (a `201` or `200` from the single-record endpoint, or an accepted element in a bulk response) until **all** of the following hold:

1. Steps 2 to 14 of §4.6 succeeded for the record (for a replay, steps 2 to 10). [DUR-C1]
2. The assertion (as defined in §5.7) and its receipt data (`receipt_id`, `received_at`, `content_digest`, and the integrity flags if the Collector returns them) have been written to durable storage. [DUR-C2] Durable means the write survives a process crash and a restart of the Collector, and, if the Collector advertises `acceptance_durability: "replicated_durable"`, the loss of a single storage node.
3. The write is committed. [DUR-C3] A record whose commit is pending, in doubt, or later voided MUST NOT have been acknowledged. [DUR-001]
4. The receipt returned is the receipt persisted. A later identical submission MUST return identical `receipt_id` and `received_at`. [DUR-002]

Consequences:

- The Collector MUST NOT acknowledge from an in-memory buffer, an unflushed write-ahead queue, or a message accepted onto an internal broker whose delivery to storage is not yet confirmed. [DUR-003]
- Asynchronous indexing, correlation, and assessment after the acknowledgement are permitted, provided the persisted evidence and receipt are sufficient to rebuild them.
- If the Collector cannot complete the commit, it MUST return `503 COLLECTOR_UNAVAILABLE` (or `500 INTERNAL_ERROR`). [DUR-004] It MUST NOT leave a visible record, receipt, or index entry for an unacknowledged submission. [DUR-005] If the outcome is unknown to the client (timeout, connection loss), the client resubmits the same bytes. The Collector then returns either a first acceptance or a replay; it never returns two receipts.

### 7.3 Receipt scope

A receipt establishes only: "This Collector, within this evidence domain, verified these bytes against a registered key and durably accepted them at `received_at`." It is not a signature by the Collector. A Collector that wants to provide a signed or anchored receipt does so through an extension and separate specification.

#### 7.3.1 Receipt lookup (optional)

A producer that submits through OTLP, Kafka, or another intermediary does not necessarily receive the Collector's acceptance receipt (§12). A Collector MAY offer a receipt lookup endpoint so that such a producer can reconcile locally generated evidence against Collector acceptance, without a broader evidence retrieval API. [LKP-001]

```http
GET /api/v1/audit/trace/receipts/{producer_id}/{record_id} HTTP/1.1
Authorization: Bearer <access-token>
```

**Availability.** The endpoint is optional. A Collector that offers it publishes `trace_receipt_endpoint` and `receipt_scope` in its metadata (§11.2), and a client uses the URL template from the metadata. A Collector that does not offer it omits both members.

**Parameters.** `producer_id` and `record_id` are both REQUIRED path segments, each percent-encoded as RFC 3986 requires. [LKP-002] There are no query parameters. The two together are the record identity (§5.6) within the caller's evidence domain, so a lookup is never ambiguous. The Collector MUST support `GET` and MAY support `HEAD`. [LKP-003]

**Authorization.** The following checks apply in order. Each is required:

1. A valid access token (§4.2). Failure: `401 UNAUTHENTICATED`. [LKP-A1]
2. The receipt scope (§4.3). Failure: `403 INSUFFICIENT_SCOPE`. [LKP-A2]
3. An evidence domain derived from the submitter identity as in §4.4. [LKP-A3] Failure: `403 EVIDENCE_DOMAIN_NOT_BOUND`. The lookup is confined to that evidence domain, and a receipt in any other domain is not observable.
4. **Receipt-read permission.** The submitter identity `(issuer, client_id)` MUST be permitted to read receipts for `producer_id` in that evidence domain. [LKP-004] This permission is configured separately from submission permission (§4.5). The default is no permission. A Collector MAY grant it to a producer's own identity and to forwarders. [LKP-005] Failure: `403 RECEIPT_ACCESS_DENIED`, returned in the same way whether or not a receipt exists, so that a caller without permission learns nothing about the record.

**Response.** `200 OK` with the receipt stored at acceptance:

```json
{
  "accepted": true,
  "producer_id": "pdp-fleet-1",
  "record_id": "0191f3a0-7b1e-7c2a-9d41-3a2f7b0c9d41",
  "content_digest": "sha256:c849281f3c5ef69a204c28cf8a3036092b159ffa782b2bee11d3513fd4455226",
  "receipt_id": "108422",
  "received_at": "2026-06-11T00:42:23.456Z"
}
```

- The members are those of the acceptance receipt (§6.3). [LKP-R1] `receipt_id`, `received_at`, `content_digest`, and, where the Collector returns them, the integrity flags and `chain_admission` are exactly the values the first acceptance returned, and so equal those of any replay (§9). The flags are the snapshot taken at acceptance (§7.4.4). The current assessment of the chain is not available here.
- `idempotent_replay` is omitted. [LKP-R2] A lookup is not a submission.
- The response contains no part of the assertion, no verification detail, and no token information.
- A receipt is not a signature by the Collector. A lookup response has the same trust as the response to the original submission: a statement by the Collector, authenticated by TLS (§7.3).

**Not found.** `404 Not Found` with `RECEIPT_NOT_FOUND` means that the Collector holds no receipt for that identity in the caller's evidence domain. [LKP-N1] The record may not have arrived yet, may be in transit, may have been rejected or quarantined (which leave no receipt), or may have been removed after its replay retention. The Collector does not distinguish these cases and a `404` is **not** evidence of rejection. Because the Collector retains replay data for at least `idempotency_retention_seconds` from `received_at` (§9.1), a `404` for a record that was first submitted less than that period ago means that the record has **not been accepted yet**. After that period the answer is inconclusive.

**Comparing digests.** A caller compares the returned `content_digest` with the digest it computed for the record it sent. If they differ, the Collector holds different content under that record identity. [LKP-D1] The caller MUST NOT treat its own record as accepted and SHOULD raise an alert, because this is the situation that a conflict (§9) reports on submission. [LKP-006]

**Other requirements.**
- The endpoint has no side effects, is not a submission, and creates no chain state.
- A `200` response is immutable and MAY be cached privately (`Cache-Control: private`). [LKP-007] A `404` MUST NOT be cached. [LKP-008]
- A Collector SHOULD rate-limit lookups per submitter identity and respond `429` with `Retry-After`, because a lookup can be used to probe for record identities. [LKP-009]
- Errors use Problem Details (§10).

### 7.4 Producer chains: admission, integrity, completeness

Producers sequence their records in chains. A chain is identified by `(producer_id, producer_instance_id, producer_chain_id)`, and a record's position in it by `sequence_number`. Records may arrive in any order.

Three different questions are asked about a chain. They have different answers, are evaluated independently, and have different effects on the response.

| Concern | Question | Possible outcome |
|---|---|---|
| **Admission** | Is this producer authorized to establish or extend this chain on this Collector? | Admitted, or **rejected** with `CHAIN_NOT_REGISTERED`. The only chain-related ground for rejection. [CHN-ADMISSION] |
| **Integrity** | Does the record link correctly: consecutive position, matching predecessor hash, one record per position? | Always accepted. Reported by `chain_link_failure_flag` and `equivocation_flag` when assessed synchronously, otherwise by the Collector's assessment interface (§7.4.5). [CHN-INTEGRITY] |
| **Completeness** | Are the earlier records of the chain held? | Always accepted. Reported by `coverage_gap_flag` when assessed synchronously, otherwise by the Collector's assessment interface (§7.4.5). [CHN-COMPLETENESS] |

Rules:

1. Admission does not depend on integrity or completeness. [CHN-R1] A record is not rejected because its predecessor is missing, and it is not admitted because its predecessor is present. Whether a chain is admitted depends only on the Collector's registration modes (§7.4.1) and the chain's registration.
2. Integrity and completeness findings never cause rejection, and never depend on arrival order. [CHN-R2] Chain position is evaluated by `sequence_number`.
3. A record that fails key or signature verification MUST NOT create, anchor, or alter any chain state. [CHN-001] Admission is evaluated only for a verified record (§4.6 step 14).
4. Admission is a property of the chain, not of the key. [CHN-R4] A key authorized for an event kind (§4.5) does not by itself make a chain registered.

#### 7.4.1 Chain admission and registration modes

A **registration mode** states how a Collector establishes the beginning of a chain. The Collector publishes the modes it supports as `producer_chain_registration_modes_supported` (§11.2).

| Mode | Meaning |
|---|---|
| `pre_registered_genesis` | An administrator registers the chain before the Collector sees its records (for example by `producer_id` and `producer_chain_id`, and optionally `producer_instance_id` and the expected genesis `record_id`). The mechanism is out of scope. |
| `first_observed_genesis` | The Collector anchors a chain the first time it sees a verified record of it, with no prior registration. The anchor fixes what the Collector saw. It does not show that the producer had no earlier chain. |
| `linked_restart_genesis` | The Collector admits a new chain whose genesis carries a signed link, defined by the profile, to the head of a chain of the same producer that the Collector has already admitted. |

A Collector MUST list at least one of `first_observed_genesis` and `pre_registered_genesis`. [ADM-001] The modes it lists decide what happens to a record of a chain that is **not registered** (the Collector has no registration for it and has not previously admitted it):

| Modes listed | Record of a registered chain | Record of an unregistered chain |
|---|---|---|
| `first_observed_genesis` only | not applicable (no registration is offered) | **Admitted.** The chain is anchored at first sight. [ADM-M1] |
| `pre_registered_genesis` only | **Admitted**, in any arrival order, including before the genesis record | **Rejected:** `400 CHAIN_NOT_REGISTERED`, whether the record is a genesis or not. Nothing is stored and no chain is created. [ADM-M2] |
| both | **Admitted.** The chain is classified as pre-registered. | **Admitted.** The chain is anchored at first sight. [ADM-M3] |

`linked_restart_genesis` may be listed in addition. It adds one case: a record that is the genesis of a chain carrying a valid link (see "A link is valid" in this subsection) is admitted whichever of the rows above applies. A record of an unregistered chain without such a link is treated by the row above.

Further rules:

- **Admission is remembered.** Once a chain is admitted, later records of it are admitted without re-evaluating registration. [ADM-R1] Removing a registration later does not unadmit a chain or its accepted records.
- **First-sight anchoring is not authentication of history.** Under `first_observed_genesis`, a record of an unknown chain that is not at `sequence_number` 1 is admitted, the chain is anchored at that first observed record, and `coverage_gap_flag` is true. [ADM-R2] If the genesis record arrives later, it is accepted and is not rejected for arriving late. Whether such a chain counts as having an authenticated start is an assessment outside this API.
- **A rejected record leaves no trace.** A `CHAIN_NOT_REGISTERED` rejection is terminal for that chain until an administrator registers it. [ADM-R3] After registration, the same bytes can be resubmitted and are accepted as a first acceptance.
- **Registration does not weaken verification.** A record of a registered chain still has to pass steps 9 to 14 of §4.6, including 10a.
- **A link is valid** for `linked_restart_genesis` when the record's profile-defined link names a chain of the same `producer_id`, in the same evidence domain, that the Collector has admitted. Further validation of the link is profile-defined.
- **Reporting.** A receipt MAY carry `chain_admission` with one of the mode identifiers, stating how this record's chain was admitted. [ADM-002] A Collector that lists more than one mode SHOULD include it. [ADM-003]

#### 7.4.2 Integrity flags

| Flag | Set when |
|---|---|
| `chain_link_failure_flag` | (a) The record at `sequence_number − 1` is held, but its `content_digest` differs from this record's `prev_record_hash`; or (b) the record is at `sequence_number` 1 and does not carry the profile's genesis sentinel, or is at a later position and does carry it (a forged origin). Case (b) applies whether or not the predecessor is held. [FLG-CHAIN_LINK_FAILURE] |
| `equivocation_flag` | A different record, with a different `record_id` and a valid signature, is already held at the same `(producer_id, producer_instance_id, producer_chain_id, sequence_number)`. Both records are retained and flagged, and the Collector MUST NOT silently select one. [FLG-EQUIVOCATION] |

An integrity flag does not clear itself when more records arrive, because the conflicting data is already present. The genesis sentinel is defined by the record's profile (for the GovOps v1 profile, `sha256:` followed by 64 zeros).

A same-`record_id` resubmission with different content is a **conflict** (§9), not an equivocation.

#### 7.4.3 Completeness flag

| Flag | Set when |
|---|---|
| `coverage_gap_flag` | The record at `sequence_number − 1` on the same chain is not held, and this record is not at `sequence_number` 1. [FLG-COVERAGE_GAP] |

A gap is a statement about what the Collector holds at the moment of acceptance, not an error. When the missing record later arrives it is accepted and links correctly. The flag in an earlier receipt is not changed (§9). A deployment that needs to know whether a chain is complete asks the Collector's retrieval and assessment interfaces, which are outside this document.

#### 7.4.4 Other flag and snapshot semantics

| Flag | Set when |
|---|---|
| `late_flag` | The Collector's receipt time is later than `signed_at` by more than a configured lateness policy. Lateness alone is never a reason to reject. [FLG-LATE] |

Each flag a Collector returns describes the state at the moment of original acceptance and is reproduced unchanged on replay.

#### 7.4.5 Synchronous and asynchronous assessment

Synchronous chain analysis needs stateful lookups on every record. A high-throughput Collector can defer it. The API allows both.

- A Collector MAY evaluate producer-chain integrity and completeness (and `late_flag`) asynchronously, after durable acceptance. [ASY-001] Acceptance establishes successful verification and durable storage, independently of chain assessment.
- A Collector that does so MUST omit `coverage_gap_flag`, `chain_link_failure_flag`, `equivocation_flag`, and `late_flag` from every receipt (single and bulk, first acceptance and replay), and MUST NOT advertise `synchronous_integrity_flags: true`. [ASY-002] Omission is deliberate: an absent flag means "not assessed at acceptance", never "no finding". A client MUST NOT read an absent flag as `false`. [ASY-003]
- A Collector that returns the four flags in every receipt MUST advertise `synchronous_integrity_flags: true` in its metadata (§11.2). [ASY-004] It then MUST return all four in every receipt, and the values MUST be the findings at the moment of acceptance. [ASY-005]
- Chain **admission** (§7.4.1) is always evaluated before acceptance, because it can reject a record. A deferred assessment covers integrity and completeness only.
- A Collector that defers assessment SHOULD complete it and SHOULD make the findings available through its retrieval or assessment interfaces. [ASY-006] Those interfaces are outside this document. The findings, once made, are the same as those a synchronous Collector would have reported for the same arrival sequence, except that they MAY reflect records that arrived after the one being assessed. [ASY-007]
- A Collector MUST NOT present a chain as intact, complete, or free of findings while its assessment is pending or has not been performed, and MUST NOT present deferred assessment as a property of acceptance. [ASY-008]

### 7.5 Missing correlation context

If the Collector's metadata states `execution_correlation_required: true`, a record whose `trace` lacks `trace_execution_id` or `execution_authority` MUST be rejected with `MISSING_EXECUTION_CONTEXT`. [COR-001] Either field alone is missing context, because the two always travel together.

If `execution_correlation_required` is `false`, the Collector MAY accept such records, and MUST then return `unattributed_flag: true` in the receipt. [COR-002] How the Collector later correlates them is outside this document.

---

## 8. Bulk submission

### 8.1 Request

```http
POST /api/v1/audit/trace/bulk HTTP/1.1
Authorization: Bearer <access-token>
Content-Type: application/json

[ { ...record... }, { ...record... } ]
```

- The body is a JSON array of records. The array MUST contain between 1 and `max_batch_records` elements, and the decoded body MUST NOT exceed `max_batch_bytes`. [BLK-001]
- Unless the Collector advertises `bulk_mixed_producers_supported: true`, every record in a batch MUST have the same `producer`. [BLK-002] A batch that mixes producers is rejected as a whole with `400 BATCH_MIXED_PRODUCERS`. Elements that are not JSON objects with a string `producer` do not take part in this check. They are rejected individually with `SCHEMA_INVALID`.
- A batch always belongs to exactly one evidence domain, the one derived from the authenticated submitter. There is no way to address more than one domain in a request.
- A Collector that does not implement bulk submission omits `trace_bulk_ingestion_endpoint` from its metadata.

Envelope failures reject the whole request and process nothing:

| Condition | Status | Code |
|---|---|---|
| Body is not a strict JSON document (syntax, UTF-8, duplicate member, depth) | `400` | `MALFORMED_JSON` [BLK-E1] |
| Body is valid JSON but the top-level value is not an array | `400` | `BATCH_NOT_ARRAY` [BLK-E2] |
| Empty array | `400` | `BATCH_EMPTY` [BLK-E3] |
| More than `max_batch_records` elements | `400` | `BATCH_TOO_MANY_RECORDS` [BLK-E4] |
| Decoded body larger than `max_batch_bytes` | `413` | `REQUEST_TOO_LARGE` [BLK-E5] |
| Mixed producers without support | `400` | `BATCH_MIXED_PRODUCERS` [BLK-E6] |
| Submitter not permitted for the batch's single producer | `403` | `SUBMITTER_NOT_AUTHORIZED` [BLK-E7] |
| Authentication, scope, domain, media type, rate | `401`, `403`, `415`, `429` | as in §10 [BLK-E8] |

When mixed producers are supported, `SUBMITTER_NOT_AUTHORIZED` is reported per element.

### 8.2 Processing semantics

- Each record is processed independently, exactly as a single submission. [BLP-R1] A batch is N single-record ingestions that share one HTTP request. It is not a transaction.
- A failure on one record (bad signature, unknown key, conflict, size, storage failure) MUST NOT reject, delay the acknowledgement of, or alter the result of any other record. [BLP-001]
- Each accepted record is committed atomically and durably under §7.2 before its element reports `accepted: true`. The Collector MUST NOT report any element accepted before that element's own commit. [BLP-002]
- An element that is valid JSON but is not a JSON object, or is not a valid record, is rejected on its own with `SCHEMA_INVALID` (or the more specific code). [BLP-R2] It does not reject the batch.
- The contrary case is a failure of the JSON document itself: a syntax error, invalid UTF-8, a duplicate member name, or excessive nesting anywhere in the body. [BLP-R3] That rejects the whole request with `MALFORMED_JSON`, because the Collector cannot trust the element boundaries or the meaning of the affected member. No element is processed. See §4.6 for the scope of every failure.
- Identity decisions among records in the same batch MUST be made as if the records were processed one at a time in array order. [BLP-003] Therefore `[R, R]` yields a first acceptance and then a replay of the same receipt. `[R, R′]`, where `R′` reuses the identity of `R` with different content, yields an acceptance and then a conflict, not the reverse. A Collector MAY process elements concurrently if it preserves this result. [BLP-004]

### 8.3 Response

When the envelope was valid and the Collector processed the batch, the status is `200 OK`, even if every element was rejected. `207 Multi-Status` is not used. The body is:

```json
{
  "results": [
    { "index": 0, "accepted": true, "producer_id": "...", "record_id": "...", "content_digest": "sha256:...",
      "receipt_id": "...", "received_at": "...", "idempotent_replay": false,
      "coverage_gap_flag": false, "chain_link_failure_flag": false, "equivocation_flag": false, "late_flag": false }
    { "index": 1, "accepted": false, "producer_id": "...", "record_id": "...",
      "error": { "type": "...", "title": "...", "status": 400, "code": "SIGNATURE_INVALID", "retryable": false } }
  ]
}
```

- `results` MUST contain exactly one element per request element, in request order, each with the zero-based `index` of the request element. [BLR-001]
- An accepted element is an acceptance receipt (§6.3) plus `index`. The four flag members in the example appear only if the Collector advertises `synchronous_integrity_flags: true` (§7.4.5).
- A rejected element carries `accepted: false`, `index`, and `error`, a Problem Details object (§10.1) whose `status` is the status the same record would have received on the single-record endpoint. `producer_id` and `record_id` are present when they could be read from the element.
- If the Collector could not process the batch at all, it MUST respond with a request-level `503` (or `500`, `429`) and no `results`, and MUST NOT have accepted any element. [BLR-002] It SHOULD use a request-level error when every element would fail with the same retryable condition. [BLR-003]

### 8.4 Ordering

- Producers SHOULD place records of the same chain in ascending `sequence_number` order, and a Collector SHOULD process them in that order, but neither is required for correctness. [BLO-001]
- A Collector MUST NOT reject, or give a different outcome to, a record because its predecessor has not arrived. [BLO-002] That is a completeness finding (`coverage_gap_flag`, §7.4.3). Chain position is assessed by `sequence_number`.
- Chain admission (§7.4.1) is separate and does not depend on order. Where only `pre_registered_genesis` is listed, a record of a registered chain is admitted whatever its position, and a record of an unregistered chain is rejected with `CHAIN_NOT_REGISTERED` whatever its position, including when it is the genesis record.
- No ordering is guaranteed or implied between records of different chains, producers, or batches. Receipt order is the Collector's order of acceptance, not a global event order.

### 8.5 Retry

After a `200` bulk response, a producer or forwarder MUST:

1. treat each element with `accepted: true` as complete, including elements with `idempotent_replay: true`; [BLT-M1]
2. treat each element whose error has `retryable: false` as a terminal rejection: not retry it unchanged, and surface it to an operator; [BLT-M2]
3. resubmit each element whose error has `retryable: true`, unchanged, after a backoff (§10.3). [BLT-M3] The producer MAY resubmit only those elements, or the entire batch. [BLT-001] Resubmitting the entire batch is safe because already-accepted elements return their original receipts.

After a request-level `429`, `500`, `503`, a timeout, or a connection failure, the client MUST resubmit the same bytes, because it cannot know whether any element was accepted. [BLT-002] Idempotency (§9) makes this safe.

---

## 9. Idempotency and conflicts

Idempotency is keyed on record identity and `content_digest`, not on the received byte sequence and not on an `Idempotency-Key` header. No such header is defined or used.

| Condition | Required behavior |
|---|---|
| Same record identity, same `content_digest` as an accepted record whose replay data is retained (§9.1) | Return the **original acceptance receipt** with `idempotent_replay: true` and status `200` (the first acceptance returned `201`). Do not create a second receipt, a second chain entry, or new flags. [IDP-T1] |
| Same record identity, different `content_digest`, record verifies | Return `409` with `RECORD_ID_CONFLICT`. The first-accepted record is authoritative and MUST NOT be overwritten, amended, or replaced. [IDP-001] |
| Same chain position, different `record_id`, both verify | Not a conflict. Accept the new record. Equivocation is reported by `equivocation_flag: true` if the Collector assesses synchronously, and otherwise by its assessment interface (§7.4.5). [IDP-T3] |
| Same `record_id`, different `producer_id` | Different identity. Accept normally. [IDP-T4] |
| Same identity bytes in a different evidence domain | Different identity. Accept normally, with an independent receipt. [IDP-T5] |

Detail:

1. **The original receipt.** A replay returns the same `receipt_id`, `received_at`, `content_digest`, and (when the Collector returns them) integrity flags as the first acceptance, with only `idempotent_replay` changed to `true`. [IDP-R1]
2. **Semantically identical bytes.** A resubmission that differs only in whitespace, member order, or equivalent number spelling has the same `content_digest` and is a replay. [IDP-R2] A re-serializing intermediary therefore cannot cause a false conflict.
3. **Replay survives key changes.** After a record is accepted, later key rotation, revocation, or validity-window changes MUST NOT turn a replay into a rejection or change the recorded result. [IDP-002] This is why replay detection (step 10) precedes key-validity checks (step 11). A new, different record signed by a since-revoked or since-expired key is still rejected, because key validity is evaluated at the Collector's acceptance time, not at `signed_at` (§4.5.1). The verification decision made at the original acceptance is preserved: the key identity and evaluation time retained for the record do not change on replay.
4. **Authorization still applies.** A replay is returned only to a submitter permitted to submit for that producer in that evidence domain (step 7). A Collector MUST NOT confirm the existence of a record identity to any other caller. [IDP-003]
5. **Conflict only after verification.** A record is judged a conflict only after it passes key and signature verification (step 13 follows step 12), so unverified content cannot probe or provoke conflicts on an identity. [IDP-R5]
6. **Atomicity.** Under concurrent submissions the Collector MUST serialize per record identity. [IDP-004] Two concurrent identical submissions yield exactly one first acceptance and one replay. Two concurrent submissions with the same identity and different content yield exactly one acceptance and one `409`.
7. **Conflict response.** The Problem Details object SHOULD include `producer_id`, `record_id`, `existing_content_digest`, and `submitted_content_digest`. [IDP-005] A Collector MAY quarantine the conflicting record for investigation, but MUST NOT admit it to evidence retrieval or correlation under the contested identity. [IDP-006]

### 9.1 Replay data and its retention

**Replay data** for an accepted record is its record identity, its `content_digest`, and its acceptance receipt (`receipt_id`, `received_at`, and, if the Collector returns them, the integrity flags and `chain_admission`). The Collector needs it to answer a resubmission with the original receipt and to detect a conflict.

- **Minimum period.** A Collector MUST retain the replay data of an accepted record for at least `idempotency_retention_seconds` after the record's `received_at`. [RET-001] The Collector publishes the value in its metadata (§11.2). The value MUST be at least 86,400 (one day). [RET-002] A value of at least 604,800 (seven days) is RECOMMENDED. [RET-003]
- **Tied to the record.** A Collector MUST NOT remove the replay data of an accepted record while it still holds the record itself. [RET-004] Replay data therefore lasts at least as long as the record, and never less than the minimum period. A Collector MAY retain it longer. [RET-005]
- **Public value.** The published value MUST be a period that every submitter can rely on. [RET-006] If retention differs by evidence domain, the Collector publishes the shortest value.
- **Deletion obligations.** A Collector MAY delete a record and its replay data earlier only to comply with a legal or contractual deletion obligation. [RET-007] It SHOULD document that it does so. [RET-008]
- **Choosing the value.** The period SHOULD exceed the longest time a producer or forwarder may hold and retry a record. [RET-009] For broker-backed delivery, that is the broker's retention, plus the longest tolerated outage, plus the maximum retry backoff (§9.4).

### 9.2 Rules applied to a resubmission of an accepted record

A **replay** is a submission whose record identity and `content_digest` match an accepted record whose replay data is retained. A Collector changes its configuration over time: it adds and withdraws profiles, tightens schema rules, changes limits, expires keys, and changes access. The guarantee for a replay is:

> Within the replay retention period, a submission that satisfies the **current request admission rules** and whose record has the same identity and `content_digest` as an accepted record MUST be answered with the original receipt (`200`, `idempotent_replay: true`), regardless of any change since acceptance to the **record-content rules**. [RPR-001]

The two classes of rule are:

| Rule | Applies to a replay? | Notes |
|---|---|---|
| Authentication, scope, evidence-domain binding, submitter-to-producer permission (§4.2 to §4.5; steps 2 to 4, 7) | **Yes, current rules.** | A replay is answered only to a submitter who is currently authorized. If a binding or permission has been removed, the result is the corresponding `401` or `403`. If the binding now points to another evidence domain, the submission is evaluated in that domain and is not a replay of the other domain's record. [RPR-T1] |
| Media type, encoding, rate limit, strict JSON, batch envelope (steps 5, 6a, 6b) | **Yes, current rules.** | [RPR-T2] |
| Body size and per-record size limits (steps 5, 8) | **Yes, current values.** | These protect the Collector before it can identify the record. See the note below. [RPR-T3] |
| Record identification and canonicalization (step 9) | **Yes**, but a withdrawn profile is kept available for replay. | See below. [RPR-T4] |
| Profile currently accepted for new records, required members, `record_id` form, event-kind schema, array limits, correlation requirement (step 10a) | **No.** | These are record-content rules. They apply only to a record being accepted for the first time. A tightened schema rule or a changed `execution_correlation_required` has no effect on a replay. [RPR-T5] |
| Key validity, event-kind authorization, signature (steps 11 and 12) | **No.** | §4.5.1 and §9, item 3. The verification made at acceptance is preserved. [RPR-T6] |
| Chain admission, integrity and completeness (step 14) | **No.** | The flags are those of the original receipt. A changed registration or registration mode does not affect a replay. [RPR-T7] |

**Withdrawn profiles.** The profile's identifier fixes its canonicalization and digest construction (§5.3). A change to either is a new profile identifier. If a Collector stops accepting new records under a profile, it MUST keep the ability to canonicalize and digest records of that profile, for replay only, until every accepted record of that profile has passed its replay retention period. [RPR-002] During that time the Collector lists the profile in `trace_profiles_replay_only` (§11.2) and not in `trace_profiles`. A submission under a replay-only profile that matches an accepted record is answered as a replay. Any other submission under it is rejected with `UNSUPPORTED_PROFILE` at step 10a.

**Size limits.** Size limits are applied before the Collector can tell whether a record is a replay, because identifying it requires parsing it. A Collector SHOULD NOT reduce `max_record_bytes` or `max_batch_bytes` while it holds replay data for records that the lower value would exclude. [RPR-003] If it does, a resubmission of such a record is rejected with the size error. The earlier acceptance stands. It is neither revoked nor changed, and the producer should treat the error as a rejection of the resubmission, not of the evidence.

**Unchanged rules for new records.** A record that is not a replay is validated under all current rules. In particular, a record with an accepted record's identity and a different `content_digest` is validated first, and is a conflict only if it passes (§9, item 5).

### 9.3 Submission after the replay data has expired

When the replay data of an accepted record has expired, which under §9.1 happens only after the record itself was deleted, the Collector has no basis to recognize the submission. It MUST evaluate it as a new record under all current rules:

- If every current rule passes, the Collector accepts it as a first acceptance: `201`, `idempotent_replay: false`, with a **new** `receipt_id`, a **new** `received_at`, and flags evaluated afresh (`late_flag` may be set if the Collector assesses synchronously). [EXP-M1] It MUST NOT return the original receipt's values, and MUST NOT report `idempotent_replay: true`. [EXP-001]
- If a current rule fails (for example the signing key has since expired, or the profile has been withdrawn), the Collector rejects it with the corresponding error. [EXP-M2] It does not report that the record was accepted earlier.
- If the submission has the same identity as an expired record but different content, it is accepted as a new record. [EXP-M3] Conflict protection ends with the replay data.

The Collector does not return a special "receipt expired" error. It cannot reliably distinguish an expired receipt from a record it has never seen, and a Collector that does retain such knowledge simply keeps the replay data longer. A producer or forwarder that needs deduplication across a longer period than `idempotency_retention_seconds` MUST NOT rely on the Collector for it. [EXP-002] After expiry, the same bytes may be accepted again as new evidence. Consumers of evidence MUST treat two accepted records with the same record identity and `content_digest` as the same record. [EXP-003]

### 9.4 Broker-backed delivery

Records that travel through a broker (Kafka, a persistent OpenTelemetry queue, or similar) can be delivered more than once and long after they were first submitted. To keep deduplication reliable:

- The maximum time a record can remain in the pipeline (broker retention, plus the longest outage the deployment tolerates, plus the maximum retry backoff) SHOULD be shorter than `idempotency_retention_seconds`. [BRK-001] A forwarder or producer MUST NOT assume that a resubmission later than that is a replay. [BRK-002]
- A forwarder that receives a `200` replay, or an accepted element with `idempotent_replay: true`, treats the record as complete (§8.5). A replay cannot be rejected because a record-content rule changed (§9.2). The only rules that can reject it are the request admission rules, including size limits.
- A rejection with `403` or `401` for a record that was accepted earlier means that the forwarder's access has changed. It is not a verdict on the evidence, and the forwarder SHOULD retain the record until the access problem is resolved. [BRK-003]
- A record whose replay data has expired and that is resubmitted by a pipeline is accepted as new (§9.3). The forwarder and the Collector's operator SHOULD treat this as a sign that the pipeline holds records too long. [BRK-004]
- Compare the receipt's `content_digest` and `received_at` with the forwarder's record of the earlier receipt, if any, to detect that a record was accepted again.


---

## 10. Errors

### 10.1 Problem Details

Every error response from an ingestion endpoint, and every per-element `error` in a bulk response, is an RFC 9457 Problem Details object. Request-level errors use `Content-Type: application/problem+json`.

| Member | Required | Content |
|---|---|---|
| `type` | REQUIRED | `https://govops.owasp.org/trace/errors/` followed by the lowercase, hyphenated error code (for example `.../signature-invalid`). [PRB-001] |
| `title` | REQUIRED | Short, stable, human-readable summary. [PRB-002] |
| `status` | REQUIRED | The HTTP status. [PRB-003] |
| `code` | REQUIRED | One of the codes in §10.2. [PRB-004] |
| `retryable` | REQUIRED | `true` if retrying the identical bytes later, without operator action, can succeed. [PRB-005] |
| `detail` | OPTIONAL | Human-readable explanation for this occurrence. [PRB-006] |
| `instance` | OPTIONAL | A URI identifying this occurrence. [PRB-007] |
| `producer_id`, `record_id` | OPTIONAL | Where applicable. [PRB-008] |
| `existing_content_digest`, `submitted_content_digest` | OPTIONAL | On `RECORD_ID_CONFLICT`. [PRB-009] |

An error body MUST NOT contain a bearer token, signed record content, a signature, or any information about another evidence domain. [PRB-010] `detail` MUST NOT reveal whether a record identity exists to a caller not permitted to know (§9). [PRB-011]

### 10.2 Error codes

| Code | HTTP | Retryable | Condition | Client action |
|---|---|---|---|---|
| `UNAUTHENTICATED` | 401 | no | Missing, expired, or invalid access token | Obtain a new token, then resubmit (once per failure) [ERR-UNAUTHENTICATED] |
| `INSUFFICIENT_SCOPE` | 403 | no | Token lacks the ingestion scope | Fix client registration [ERR-INSUFFICIENT_SCOPE] |
| `EVIDENCE_DOMAIN_NOT_BOUND` | 403 | no | Submitter has no evidence-domain binding | Operator action [ERR-EVIDENCE_DOMAIN_NOT_BOUND] |
| `SUBMITTER_NOT_AUTHORIZED` | 403 | no | Submitter may not submit for this `producer_id` | Operator action [ERR-SUBMITTER_NOT_AUTHORIZED] |
| `UNSUPPORTED_MEDIA_TYPE` | 415 | no | `Content-Type` or `Content-Encoding` not supported | Fix request [ERR-UNSUPPORTED_MEDIA_TYPE] |
| `REQUEST_TOO_LARGE` | 413 | no | Decoded body exceeds `max_batch_bytes` | Split the batch [ERR-REQUEST_TOO_LARGE] |
| `RECORD_TOO_LARGE` | 413 | no | A record exceeds `max_record_bytes` | Terminal for that record [ERR-RECORD_TOO_LARGE] |
| `BATCH_TOO_MANY_RECORDS` | 400 | no | More than `max_batch_records` elements | Split the batch [ERR-BATCH_TOO_MANY_RECORDS] |
| `BATCH_NOT_ARRAY` | 400 | no | A bulk request body is valid JSON but not an array | Fix request [ERR-BATCH_NOT_ARRAY] |
| `BATCH_EMPTY` | 400 | no | Empty batch | Fix request [ERR-BATCH_EMPTY] |
| `BATCH_MIXED_PRODUCERS` | 400 | no | Mixed producers and mixing is not supported | Split by producer [ERR-BATCH_MIXED_PRODUCERS] |
| `MALFORMED_JSON` | 400 | no | The body is not a strict JSON document: syntax error, invalid UTF-8, duplicate member name, unrepresentable value, or excessive nesting. Always rejects the whole request | Fix and resend [ERR-MALFORMED_JSON] |
| `SCHEMA_INVALID` | 400 | no | Valid JSON that is not a valid record: not an object (a bulk element, or a single-record body), missing or mistyped members, event-kind schema, array limits, or the `record_id` form | Terminal for that record [ERR-SCHEMA_INVALID] |
| `UNSUPPORTED_PROFILE` | 400 | no | `trace.eat_profile` is not the `profile` of any entry in `trace_profiles` | Terminal for that record [ERR-UNSUPPORTED_PROFILE] |
| `MISSING_EXECUTION_CONTEXT` | 400 | no | Correlation pair required and absent or incomplete | Terminal for that record [ERR-MISSING_EXECUTION_CONTEXT] |
| `PRODUCER_IDENTITY_MISMATCH` | 400 | no | `producer` differs from `producer_chain.producer_id` | Terminal for that record [ERR-PRODUCER_IDENTITY_MISMATCH] |
| `SIGNATURE_MALFORMED` | 400 | no | The signature encoding is invalid under the record's profile | Terminal for that record [ERR-SIGNATURE_MALFORMED] |
| `UNSUPPORTED_ALGORITHM` | 400 | no | The algorithm needed to verify the record is not supported for its profile, or does not match the registered key's algorithm | Terminal for that record [ERR-UNSUPPORTED_ALGORITHM] |
| `CHAIN_NOT_REGISTERED` | 400 | no | The record's chain is not registered and the Collector does not admit chains at first sight (§7.4.1) | Operator registers the chain, then resubmit [ERR-CHAIN_NOT_REGISTERED] |
| `RECEIPT_NOT_FOUND` | 404 | yes | Receipt lookup only: no receipt is retained for the identity in the caller's evidence domain (§7.3.1). It does not mean the record was rejected | Retry later within the reconciliation window [ERR-RECEIPT_NOT_FOUND] |
| `RECEIPT_ACCESS_DENIED` | 403 | no | Receipt lookup only: the submitter identity may not read receipts for this `producer_id` | Operator action [ERR-RECEIPT_ACCESS_DENIED] |
| `KEY_UNKNOWN` | 400 | no | No key registered for `(domain, producer_id, kid)` | Operator registers key [ERR-KEY_UNKNOWN] |
| `KEY_NOT_VALID` | 400 | no | The key is outside its validity window or revoked at the Collector's evaluation time (§4.5.1). This includes a legitimately signed record that arrives after its key expired | Operator extends the key's validity, then resubmit the same bytes [ERR-KEY_NOT_VALID] |
| `EVENT_KIND_NOT_AUTHORIZED` | 400 | no | Key may not sign this `event_kind` | Operator action [ERR-EVENT_KIND_NOT_AUTHORIZED] |
| `SIGNATURE_INVALID` | 400 | no | Signature does not verify | Terminal for that record [ERR-SIGNATURE_INVALID] |
| `RECORD_ID_CONFLICT` | 409 | no | Identity already bound to different content | Terminal; investigate [ERR-RECORD_ID_CONFLICT] |
| `RATE_LIMITED` | 429 | yes | Rate limit | Wait `Retry-After`, then retry [ERR-RATE_LIMITED] |
| `COLLECTOR_UNAVAILABLE` | 503 | yes | Storage or a required dependency unavailable; nothing accepted | Back off, retry [ERR-COLLECTOR_UNAVAILABLE] |
| `COLLECTOR_INTEGRITY_HOLD` | 503 | yes | Collector refuses submissions until an operator resolves an integrity condition; nothing accepted | Back off for a long interval, retry [ERR-COLLECTOR_INTEGRITY_HOLD] |
| `INTERNAL_ERROR` | 500 | yes | Unexpected failure; nothing accepted | Back off, retry a bounded number of times [ERR-INTERNAL_ERROR] |

Additional rules:

- Statuses in this table are normative. In particular, a Collector MUST use `503`, not `500`, when it deliberately reports a retryable storage or dependency outage, and MUST use `413`, not `400`, for oversized bodies and records. [ERR-001]
- A Collector MAY return a more specific problem `type` for a code, but the `code` and `status` MUST NOT change. [ERR-002]
- A Collector MAY collapse `KEY_UNKNOWN`, `KEY_NOT_VALID`, and `EVENT_KIND_NOT_AUTHORIZED` into `KEY_UNKNOWN` to avoid disclosing registry contents to a submitter not entitled to see them. [ERR-003] It MUST NOT use a code that falsely implies the key was authorized. [ERR-004]
- A Collector MUST NOT reveal through the code or status that a record identity exists in another evidence domain. [ERR-005]
- Errors that are not listed use the closest HTTP status with Problem Details and one of the codes above; a Collector MUST NOT invent a new `code` within `v1`. [ERR-006]

### 10.3 Retry behavior

- A client MUST NOT retry a response whose `retryable` is `false` unchanged. [RTY-001] It MAY retry after an operator has acted (for example, registered a key). [RTY-002]
- A client MUST retry `retryable: true` outcomes, timeouts, and connection failures with the **same bytes** (or a serialization with the same canonical form under the record's profile), using exponential backoff with jitter. [RTY-003] It MUST honor `Retry-After` (RFC 9110 §10.2.3) when present. [RTY-004] RECOMMENDED: initial delay 1 s, factor 2, cap 5 min, full jitter. [RTY-005]
- A client that depends on evidence delivery SHOULD keep unacknowledged records in durable local storage until it receives a receipt or a terminal rejection. [RTY-006] Dropping a record after a bounded number of retries is a client policy decision and is evidence loss.
- A client MUST NOT change a record's content and resubmit it under the same `record_id`. [RTY-007] A corrected record is a new record with a new `record_id` and a new chain position.

---

## 11. Discovery

### 11.1 Location

```http
GET /.well-known/govops-trace-configuration HTTP/1.1
Host: collector.example.org
```

- The document is served over HTTPS, without authentication, as `application/json`, with status `200`. [DSC-R1]
- It MUST contain no per-tenant, per-client, or secret information. [DSC-001]
- A Collector served under a path prefix publishes the document at the well-known location for its origin and MAY additionally serve it under the prefix. [DSC-002] In every case, `issuer` identifies the Collector.
- A Collector SHOULD send `Cache-Control` with a `max-age`. [DSC-003] A client SHOULD cache for that period (default one hour if absent), and MUST re-fetch after a `404`, `410`, or repeated `UNSUPPORTED_PROFILE` or limit errors. [DSC-004]
- A client MUST ignore members it does not recognize. [DSC-005]

### 11.2 Members

| Member | Type | Required | Meaning |
|---|---|---|---|
| `issuer` | string (HTTPS URL) | REQUIRED | Identifier of the Collector. MUST equal the origin (and path prefix, if any) from which this document was retrieved. A client MUST reject the document otherwise. [DSM-001] |
| `api_versions_supported` | array of string | REQUIRED | Supported API versions, such as `["v1"]`. [DSM-002] |
| `trace_ingestion_endpoint` | string (URL) | REQUIRED | Single-record submission URL. [DSM-003] |
| `trace_bulk_ingestion_endpoint` | string (URL) | CONDITIONAL | Bulk submission URL. Present if and only if bulk is supported. |
| `trace_profiles` | array of object | REQUIRED | One entry for each supported TRACE record profile, with that profile's cryptographic capabilities. See §11.2.1. [DSM-004] |
| `authorization_servers` | array of object | REQUIRED | The OAuth 2.0 authorization servers whose tokens the Collector accepts, each with its token profile (§11.2.2). A client obtains each server's metadata by RFC 8414 or OpenID Connect Discovery at its `issuer`. [DSM-005] |
| `sender_constrained_tokens_supported` | array of string | OPTIONAL | Any of `dpop` (RFC 9449) and `mtls` (RFC 8705). Absent means none (§4.2.4). [DSM-006] |
| `ingestion_scope` | string | REQUIRED | The scope required by both ingestion endpoints. [DSM-007] |
| `scopes_supported` | array of string | OPTIONAL | Other scopes the Collector defines. [DSM-008] |
| `max_record_bytes` | integer | REQUIRED | Maximum decoded bytes in one record (§5.8). [DSM-009] |
| `max_batch_bytes` | integer | CONDITIONAL | Maximum decoded bytes in a bulk request body. Present if bulk is supported. |
| `max_batch_records` | integer | CONDITIONAL | Maximum records in a batch. Present if bulk is supported. |
| `max_nesting_depth` | integer | RECOMMENDED | Maximum JSON nesting depth. [DSM-010] |
| `bulk_mixed_producers_supported` | boolean | OPTIONAL | Default `false`. [DSM-011] |
| `execution_correlation_required` | boolean | RECOMMENDED | Whether records without the full correlation pair are rejected (§7.5). Default `true` when absent. [DSM-012] |
| `producer_chain_registration_modes_supported` | array of string | REQUIRED | Any of `first_observed_genesis`, `pre_registered_genesis`, `linked_restart_genesis`. MUST contain `first_observed_genesis` or `pre_registered_genesis`, and MUST list every mode the Collector supports. The set decides how unregistered chains are treated (§7.4.1): if it contains `first_observed_genesis`, a record of an unregistered chain is admitted; if it contains only `pre_registered_genesis`, such a record is rejected with `CHAIN_NOT_REGISTERED`. [DSM-013] |
| `synchronous_integrity_flags` | boolean | OPTIONAL | Default `false`. `true` if every receipt carries `coverage_gap_flag`, `chain_link_failure_flag`, `equivocation_flag`, and `late_flag` as evaluated at acceptance (§7.4.5). If `false` or absent, receipts omit all four. [DSM-014] |
| `trace_receipt_endpoint` | string (URI Template) | OPTIONAL | Receipt lookup URL template with the variables `producer_id` and `record_id` (RFC 6570), for example `https://collector.example.org/api/v1/audit/trace/receipts/{producer_id}/{record_id}`. Present if and only if the Collector offers receipt lookup (§7.3.1). [DSM-015] |
| `receipt_scope` | string | CONDITIONAL | The scope required by receipt lookup. REQUIRED if `trace_receipt_endpoint` is present. MUST differ from `ingestion_scope`. [DSM-016] |
| `idempotency_retention_seconds` | integer | REQUIRED | The minimum period, in seconds from a record's `received_at`, for which the Collector guarantees to retain replay data and so to answer an identical resubmission with the original receipt (§9.1). At least 86,400. [DSM-017] |
| `trace_profiles_replay_only` | array of string | OPTIONAL | Profiles the Collector no longer accepts for new records but still canonicalizes for replay (§9.2). A profile is in `trace_profiles` or in this list, never both. [DSM-018] |
| `acceptance_durability` | string | OPTIONAL | `local_durable` or `replicated_durable` (§7.2). A Collector that omits it makes no replication claim. [DSM-019] |
| `content_encodings_supported` | array of string | OPTIONAL | For example `["gzip"]`. Absent means none. [DSM-020] |

The limits MUST be values that every authorized submitter can rely on. [DSM-021] A Collector MAY grant a particular submitter higher limits, but MUST NOT enforce lower ones than it publishes. [DSM-022]

#### 11.2.1 Profile entries

Each element of `trace_profiles` describes one profile and the cryptographic capabilities the Collector provides for it. A client chooses a profile from this list, and signs and digests its records as that profile defines.

| Member | Type | Required | Meaning |
|---|---|---|---|
| `profile` | string | REQUIRED | The `trace.eat_profile` value. [DSP-001] |
| `signature_algorithms_supported` | array of string | REQUIRED | Signature algorithms the Collector verifies for records of this profile. Identifiers are those the profile defines. [DSP-002] |
| `canonicalization` | string | REQUIRED | The profile's canonicalization method, as the profile identifies it. [DSP-003] |
| `content_digest_algorithm` | string | REQUIRED | The profile's content-digest algorithm, as the profile identifies it. This is the `<algorithm>` prefix of `content_digest` values. [DSP-004] |
| `event_kinds_supported` | array of string | RECOMMENDED | Event kinds the Collector accepts under this profile. [DSP-005] |

Rules:

- The identifiers in an entry are defined by the profile. This API treats them as opaque strings and does not define a registry of them.
- A Collector MUST list only values it implements and enforces. [DSP-006] It MUST verify a record using only the values in the entry for the record's `trace.eat_profile`. [DSP-007]
- A Collector MUST NOT negotiate an algorithm with a client. [DSP-008] A client that cannot produce records using a listed profile and algorithm cannot submit to that Collector.
- Different profiles MAY list different suites. [DSP-009] A record is never verified with another profile's entry.
- Adding a profile, or an algorithm to a profile's entry, does not change `api_versions_supported`.


#### 11.2.2 Authorization server entries

Each element of `authorization_servers` declares one trusted authorization server and the token profile the Collector uses to derive a submitter identity (§4.2.2).

| Member | Type | Required | Meaning |
|---|---|---|---|
| `issuer` | string (URL) | REQUIRED | The authorization server's issuer identifier. Compared as an exact string with the `iss` of a token. This is the `issuer` component of a submitter identity. [DSA-001] |
| `token_format` | string | REQUIRED | `jwt` (JWT access tokens, RFC 9068) or `introspection` (opaque tokens, RFC 7662). [DSA-002] |
| `client_id_claim` | string | OPTIONAL | The token claim, or introspection response member, that carries the OAuth client identifier. Default `client_id`. [DSA-003] |
| `scope_claim` | string | OPTIONAL | The claim that carries the granted scopes. Default `scope` (a space-separated string). [DSA-004] |

The entry states the authorization server's documented token profile. It does not publish any client or tenant. A Collector MUST NOT list an authorization server whose tokens it cannot validate by the stated profile. [DSA-005]

### 11.3 Example

The values inside each `trace_profiles` entry come from that profile's definition.

```json
{
  "issuer": "https://collector.example.org",
  "api_versions_supported": ["v1"],
  "trace_ingestion_endpoint": "https://collector.example.org/api/v1/audit/trace",
  "trace_bulk_ingestion_endpoint": "https://collector.example.org/api/v1/audit/trace/bulk",
  "trace_profiles": [
    {
      "profile": "tag:govops.owasp.org,2026:trace-v1",
      "signature_algorithms_supported": ["Ed25519"],
      "canonicalization": "RFC8785",
      "content_digest_algorithm": "sha256",
      "event_kinds_supported": ["AUTHORIZATION_DECISION", "CAPABILITY_INVOKED", "RUNTIME_EFFECT"]
    }
  ],
  "authorization_servers": [
    { "issuer": "https://auth.example.org", "token_format": "jwt" },
    { "issuer": "https://auth2.example.org", "token_format": "introspection", "client_id_claim": "client_id" }
  ],
  "sender_constrained_tokens_supported": ["dpop"],
  "ingestion_scope": "trace.write",
  "scopes_supported": ["trace.write", "trace.receipt.read"],
  "max_record_bytes": 262144,
  "max_batch_bytes": 8388608,
  "max_batch_records": 500,
  "max_nesting_depth": 32,
  "bulk_mixed_producers_supported": false,
  "execution_correlation_required": true,
  "producer_chain_registration_modes_supported": ["first_observed_genesis", "pre_registered_genesis"],
  "trace_receipt_endpoint": "https://collector.example.org/api/v1/audit/trace/receipts/{producer_id}/{record_id}",
  "receipt_scope": "trace.receipt.read",
  "idempotency_retention_seconds": 2592000,
  "synchronous_integrity_flags": true,
  "acceptance_durability": "replicated_durable",
  "content_encodings_supported": ["gzip"]
}
```

A Collector that adds a profile with a different suite adds another entry. For illustration only, a hypothetical hardware-backed ECDSA profile would appear as:

```json
{
  "profile": "tag:example.com,2026:trace-ecdsa-v1",
  "signature_algorithms_supported": ["ES256"],
  "canonicalization": "RFC8785",
  "content_digest_algorithm": "sha256"
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

- **FW-3** A forwarder MUST deliver each record so that the canonical form (as the record's profile defines it) of the delivered record is identical to that of the record the producer signed. It MUST NOT add, remove, rename, truncate, normalize, or re-encode any signed member, MUST NOT re-sign, and MUST NOT wrap the record in a way the Collector would store as the assertion.
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
- **FW-18** A forwarder SHOULD limit the time it holds a record (queue or broker retention, plus outage, plus retry backoff) to less than the Collector's `idempotency_retention_seconds`, and SHOULD alert when a record approaches that age. A resubmission after the replay data has expired is accepted as new evidence (§9.3). A forwarder MUST NOT treat an authentication or authorization rejection of an already-accepted record as a verdict on the evidence (§9.4).

### 12.2 Requirements on Collectors with respect to intermediaries

- **CO-1** A Collector MUST treat a forwarded record exactly as a directly submitted record: authorization, key resolution, signature verification, event-kind permission, identity, idempotency, and findings are identical.
- **CO-2** A Collector MUST bind the evidence domain to the forwarder's submitter identity `(issuer, client_id)` (§4.2.2), never to anything in the record or transport metadata.
- **CO-3** A Collector MUST store the signed assertion unchanged. It MUST NOT record the forwarder as the producer. It MAY record the submitter's identity as ingestion metadata outside the assertion.
- **CO-4** A Collector MUST NOT return a receipt for a record before durable acceptance (§7.2), even if the forwarder is highly trusted. Forwarders rely on this to implement FW-8.

### 12.3 Informative transport bindings

OTLP and Kafka bindings are described in Appendix D. They are informative. The normative requirements are those above.

### 12.4 Reconciling evidence submitted through an intermediary

A producer that submits through an intermediary may never see a receipt (FW-9). It can reconcile its locally generated evidence against Collector acceptance by receipt lookup (§7.3.1), if the Collector offers it. For each record it has produced, the producer keeps `producer_id`, `record_id`, its own `content_digest`, and the time of first submission. It then queries the receipt endpoint and acts on the result:

| Lookup result | Meaning | Producer action |
|---|---|---|
| `200`, `content_digest` equal to its own | The Collector accepted this record at `received_at`. | Mark the record accepted. Stop retrying. [RCN-T1] |
| `200`, `content_digest` different | The Collector holds different content under this identity. | Do not mark accepted. Raise an alert. Do not resubmit changed content under the same `record_id` (§10.3). [RCN-T2] |
| `404`, first submission younger than `idempotency_retention_seconds` | Not accepted (yet). | Keep the record. Retry the lookup later. If the record is no longer held by the pipeline, resubmit it (identical bytes). [RCN-T3] |
| `404`, first submission older than `idempotency_retention_seconds` | Inconclusive: not accepted, rejected, or expired. | Do not infer rejection. Resubmitting is permitted. It is accepted as a new record if no longer held (§9.3). [RCN-T4] |
| `403` or `401` | No access, or access changed. | Resolve access. Do not treat as a verdict on the evidence. [RCN-T5] |
| `429`, `503` | Rate limit or outage. | Back off (§10.3). [RCN-T6] |

A `404` never proves that a record was rejected. A producer that needs the reason for a rejection uses direct submission, whose response carries the error. A producer SHOULD poll with backoff and SHOULD NOT look up a record before an intermediary has had time to deliver it. [RCN-001] If the Collector does not offer receipt lookup, reconciliation is not possible through this API, and the producer relies on direct submission or on its intermediary's records.

- **FW-19** A forwarder that receives Collector receipts SHOULD retain, for each record, `producer_id`, `record_id`, `content_digest`, `receipt_id`, and `received_at`, at least until the upstream producer can reconcile, so it can answer an upstream question without a second submission.

---

## 13. Security considerations

**Threat model.** An attacker may be: an unauthenticated network party; an authenticated client acting outside its permission; a malicious or compromised producer; a malicious or compromised intermediary; or a malicious tenant of a multi-domain Collector. The Collector's operator is trusted to run the Collector faithfully; this API does not protect against an operator that rewrites its own storage (see the receipt-scope limitation in §7.3).

**Replay.**
- Resubmitting a captured record cannot create a second record: identity and digest make it a replay (§9). A replay returns only the original receipt and reveals nothing new, and only to a submitter permitted for the producer.
- A replayed record cannot move into another evidence domain unless that domain independently registers the producer key and binds the submitter. Registering a key in two domains is an explicit operator decision.
- Access tokens are bearer credentials. Sender-constrained tokens (RFC 9449, RFC 8705) limit replay of the request itself. TLS protects tokens in transit.
- Producer timestamps are claims. A Collector MUST NOT use `signed_at` to reject a record as a replay, MUST NOT use it to decide key validity (§4.5.1), and MUST use its own `received_at` for receipt order. [SEC-001]
- The Collector's clock is a security input. An attacker who can move it can make an expired or revoked key look valid. Synchronize it to a trusted source and alert on large corrections.

**Receipt lookup as an oracle.** Receipt lookup tells a caller whether an identity has an accepted record. Guard it with a separate scope and a separate per-producer permission (§7.3.1). Return `RECEIPT_ACCESS_DENIED` identically whether or not a record exists, and confine every lookup to the caller's evidence domain. Rate-limit lookups per submitter identity. Return only the receipt, never the assertion.

**Unauthorized submission.**
- Authorization precedes content processing (§4.6).
- **Submitter identity confusion.** Client identifiers are unique only within their authorization server. A Collector that trusts several servers and binds permissions by `client_id` alone would let a client at one server act as a same-named client at another. Bind by `(issuer, client_id)` (§4.2.2), select validating keys only by the token's configured `iss`, never fetch keys from token header parameters, and never take identity from headers or certificates.
- **Token replay and constraint stripping.** Refuse any token carrying `cnf` unless its proof verifies (§4.2.4), so a constrained token cannot be replayed as a bearer token. A submitter not permitted for a producer learns nothing about keys or records (§4.5, step 7).
- Submitter-to-producer permission should follow least privilege. A forwarder holding permission for many producers is a high-value credential; use sender-constrained tokens, narrow `ingestion_scope`, and separate credentials per evidence domain.

**Signature verification.**
- Use constant-time, reviewed implementations of the algorithms the profile requires. Reject non-canonical signature encodings and duplicate JSON members, so one signed value cannot have two interpretations.
- Verify against the key selected by the signed `kid`; never guess from time, and never accept a key from the request.
- Strict JSON (§5.2) is part of verification. A parser that keeps the last duplicate member lets an attacker present different content to the Collector and to an auditor.
- A valid signature is necessary but not sufficient. It does not establish truth, completeness, independent observation, or successful enforcement. Collectors and consumers MUST NOT present accepted evidence as more than the record kind establishes. [SEC-002]

**Resource exhaustion.**
- Enforce byte, count, depth, and rate limits before cryptographic work (§4.6, §5.8). Enforce decoded-size limits during decompression.
- Bound per-request work: a batch with many invalid signatures costs one verification each, so apply rate limits per client and consider per-client limits on failed records.
- Signature verification is not free, and its cost depends on the profile's algorithm. Reject malformed encodings and unauthorized submitters before verifying.
- Return `429` with `Retry-After` rather than queuing without bound. Never acknowledge from an unbounded queue (§7.2).

**Tenant isolation.**
- Derive the evidence domain only from the authenticated credential (§4.4). Scope every key lookup, identity lookup, receipt, and error message to it.
- Do not let error text, status codes, or response timing that the Collector controls distinguish "exists in another domain" from "does not exist".
- Registry entries are per domain. Possession of a signing key never grants cross-domain access.

**Sensitive evidence.** See §14.

**Compromised intermediaries.** A compromised forwarder, OpenTelemetry Collector, or broker can drop, delay, duplicate, reorder, or replay records, and can submit any signed record it has seen. It cannot forge a record for a registered key. Effects and mitigations:
- *Dropping or delaying* is not preventable by the Collector. It is detectable as producer-chain coverage gaps (reported by `coverage_gap_flag` or by the Collector's assessment) and as late arrival. Producers that need stronger assurance use direct submission, or keep a local durable copy until receipt.
- *Substitution or alteration* fails signature verification. The Collector therefore rejects the altered record, and the original remains valid for resubmission.
- *Duplication and replay* are absorbed by idempotency.
- *Cross-domain misdirection*: a forwarder with credentials for several domains could place a record in the wrong domain. FW-2 requires separate credentials and queues, and Collectors SHOULD limit each credential to one domain. [SEC-003]
- *Over-broad permission*: a compromised forwarder can submit signed records it holds for any producer it may forward for. Limit the producer set per forwarder.
- *False acknowledgement upstream*: a faulty forwarder might report acceptance it did not obtain. FW-8 and FW-9 require distinguishing custody from acceptance. A producer that needs proof compares the receipt's `content_digest` with its own computation, obtained by direct submission or from retrieval.

**Key compromise.** Revoking a registry key stops new records from that key, evaluated at the Collector's acceptance time (§4.5.1). It does not rewrite earlier acceptance results (§9). Records accepted before revocation remain accepted and are an assessment concern. Records signed before revocation but first presented after it are rejected, whether the producer or an attacker presents them. Because `signed_at` is not used, an attacker holding a compromised key cannot backdate a record to before the revocation.

**Backdating and delayed delivery.** Using the Collector's time rather than `signed_at` closes backdating. Its cost is that honest producers whose delivery was delayed past key expiry also see rejections. The operational controls are in §4.5.1.

**Error and log hygiene.** Do not echo record content or tokens in errors or logs. Treat `detail` strings that quote attacker-controlled values as untrusted when rendering.

**Downgrade.** The record's profile fixes the cryptographic suite, and the Collector MUST NOT negotiate an algorithm independently of it (§5.3). [SEC-004] A new algorithm arrives only as a new profile identifier (or a profile revision) listed in the Collector's metadata, with an explicit verifier policy. An attacker cannot select a weaker algorithm by naming it in a request, a header, or a record member, because none of those is consulted.

---

## 14. Privacy considerations

- TRACE records can contain identifiers of workloads, instances, human sponsors, token issuers and `jti` values, action names, resource types, and timestamps. Together they describe who did what and when. They are sensitive operational and personal data.
- Records MUST NOT contain raw bearer tokens or other credentials. [PRV-001] Token references use issuer plus `jti` or a fingerprint.
- Producers SHOULD minimize personal data in signed fields and prefer pseudonymous or workload identifiers, because an accepted assertion cannot be edited. [PRV-002] Erasure requests cannot be met by changing a signed assertion; a Collector that must support erasure needs a retention and deletion policy applied to whole records, with the tamper-evidence consequences documented to its users.
- A Collector MUST isolate evidence by domain, MUST protect stored evidence with access control and encryption at rest appropriate to its sensitivity, and SHOULD apply a documented retention period. [PRV-003]
- A Collector MUST NOT expose evidence through this API's responses beyond the receipt. [PRV-004] Retrieval is a separate, separately authorized interface.
- Discovery metadata is public and MUST NOT reveal tenants, clients, producers, or registry contents. [PRV-005]
- Intermediaries see full record content. An intermediary under different administrative control from the producer is a processor of that data. Use TLS on every hop and apply FW-17.
- Error responses, logs, and metrics MUST NOT include record content or tokens. [PRV-006]

---

## 15. Conformance

This section defines what a conformance claim states, how requirements are identified, how tests are tied to them, and how a certification suite obtains deterministic inputs and expected results. The tests, vectors, fixtures, and requirement register are published as separate machine-readable artifacts (§15.4). The tables in this section are generated from those artifacts, so they cannot differ from them.

### 15.1 Classes and claims

| Class | Applies to | Must satisfy |
|---|---|---|
| **Collector** | A server offering the single-record endpoint and metadata | Every mandatory requirement whose role is `collector` and whose capability, if any, the Collector has |
| **Collector-Bulk** | A Collector that also offers the bulk endpoint | The Collector class, and the requirements of capability `bulk` |
| **Producer** | A component that signs records and submits them, directly or through an intermediary | The requirements whose role is `producer` or `client` |
| **Forwarder** | A component that relays records from producers to a Collector | The requirements of §12.1 and those whose role is `forwarder` or `client` |

A claim of conformance states the class, the API version (`v1`), the profile identifiers tested, the capabilities the implementation has (§15.3), and the registration-mode variant (§15.5). A Collector that passes the tests but advertises limits or capabilities that it does not enforce is not conforming.

### 15.2 Requirement identifiers

Every normative statement in sections 1 to 14 has a stable identifier. It appears in square brackets after the statement, and in the requirement register (`requirements.json`, Appendix E).

- **Form.** `<AREA>-<NNN>` for a requirement stated with a keyword of RFC 2119 (for example `ADM-001`). `<AREA>-<letter><n>` for a requirement that the text states without a keyword, such as a table row, a list item, or a rule in a table (for example `ORD-S07`, `ERR-SIGNATURE_INVALID`, `RPR-T5`). The identifiers `FW-n` and `CO-n` of §12 are kept.
- **Stability.** An identifier is never reused and never renumbered. A requirement that is removed stays in the register as withdrawn. A new requirement gets a new identifier, even if it sits between two existing ones. Section numbers may change. Identifiers do not.
- **Granularity.** One identifier covers one sentence, one table row, or one list item. Where a sentence states several obligations, a test that covers the sentence covers all of them.
- **Attributes.** Each requirement in the register has a **level** (`mandatory` for MUST, MUST NOT, SHALL, REQUIRED, and normative table rows and list items; `recommended` for SHOULD and RECOMMENDED; `optional` for MAY and OPTIONAL), a **role** (`collector`, `producer`, `forwarder`, `client`, `operator`, `consumer`), an optional **capability** (§15.3), and a **verification** method: `test` (an API test against a Collector), `behavior` (a behavioral test of a producer or forwarder), `inspection` (documentation, configuration, or code review), or `advisory` (guidance, not verified).
- **Drift check.** Each register entry stores a verbatim snippet of the text that carries the identifier. The suite tool fails if a snippet or its identifier tag is missing from this document.
- **Coverage rule.** Every mandatory requirement that a test can verify is mapped to at least one test, or is listed as a documented exception with a reason (§15.8). The suite tool fails otherwise.

### 15.3 Mandatory tests and tests of optional capabilities

Each test is either **mandatory** or **conditional**.

- A **mandatory** test applies to every implementation of its class. A failure is a non-conformance. A mandatory test may need a **hook** (for example a controllable clock). A Collector that cannot supply a hook leaves the test **unverified**, which is reported separately from a pass and cannot support a claim for the requirements the test covers.
- A **conditional** test applies only if the implementation has the stated **capability**, and it is not run otherwise. A test of an optional capability never counts against an implementation that lacks the capability. If the implementation has the capability, the test is mandatory for it.
- A test has a **strength**, `MUST` or `SHOULD`. A failed `SHOULD` test is reported as a warning and is not a non-conformance.
- Where a test expects flag values in a receipt, it applies to a Collector with `synchronous_integrity_flags` true. For other Collectors the receipt must carry no flag (an implicit check in every test), and the test's findings are checked through the Collector's assessment interface where a test says so.

The capabilities are:

| Capability | Applies when the Collector | Tests |
|---|---|---|
| `async_flags` | `synchronous_integrity_flags` false or absent | C-35, C-36, D-13 |
| `bulk` | Collector-Bulk (bulk endpoint offered) | R-13, B-01, B-02, B-03, B-04, B-05, B-06, B-07, B-08, B-09, B-10, B-11, B-12, B-13, B-14, B-15, B-16, B-17, B-18, B-19, B-20, B-21, B-22, D-03, B-25 |
| `bulk_absent` | bulk endpoint not offered | B-24 |
| `chain_mode:both` | both modes listed (variant M3) | G-06 |
| `chain_mode:first_observed` | modes are `first_observed_genesis` only (variant M1) | G-01, G-02, G-07 |
| `chain_mode:pre_registered` | modes are `pre_registered_genesis` only (variant M2) | G-03, G-04, G-05, G-09 |
| `configurable_client_id_claim` | a configurable client identifier claim | A-08 |
| `gzip` | `gzip` content encoding advertised | C-51, C-52 |
| `integrity_hold` | an integrity-hold state exists | C-59 |
| `introspection` | an authorization server with `token_format` `introspection` | A-11, A-12, A-18 |
| `mixed_producers` | `bulk_mixed_producers_supported` true | B-23 |
| `multi_as` | two or more authorization servers trusted | A-02, A-03, A-04 |
| `multiple_profiles` | more than one profile listed | D-10 |
| `profile_withdrawal` | a profile can be withdrawn to replay-only | R-08, R-09 |
| `rate_limiting` | rate limiting applied | C-58 |
| `receipt_lookup` | receipt lookup offered | L-01, L-02, L-03, L-04, L-05, L-06, L-07, L-08, L-09, L-10, L-11, L-12, L-13, L-14, L-15, P-13 |
| `sender_constrained` | DPoP or mTLS supported | A-16 |
| `sync_flags` | `synchronous_integrity_flags` true | C-14, C-15, C-16, R-15, C-56 |
| `unattributed` | `execution_correlation_required` false | C-55 |

### 15.4 Conformance artifacts

The following files are published with this specification in the `conformance/` directory. They are the authoritative form of the tests. They use only JSON and are independent of any programming language.

| File | Content |
|---|---|
| `requirements.json` | The register: every requirement with its identifier, section, level, role, capability, verification, statement, and anchor text, and the coverage exceptions. |
| `vectors.json` | Test keys, and every test vector with its content, `content_digest`, and signature validity. |
| `fixtures.json` | The deterministic initial state: clock, Collector configuration, authorization servers, submitters, producer key registry, registration-mode variants, and the generators of derived bodies. |
| `tests.json` | Every test: identifier, class, applicability, capability, strength, required hooks, mapped requirement identifiers, and for API tests the steps with their expected responses. |
| `reference_model.py` | An executable model of the processing order of §4.6 and the rules of sections 4 to 11. |
| `run_suite.py` | Validates the artifacts, runs every API test against the model, checks coverage and drift, and renders the tables of this section. |

**The reference model is a consistency checker.** It is not a Collector. Every expected response in `tests.json` is one that the model produces. If a test expects something that the normative order forbids, for example a verification error for a record whose submitter is not authorized for its producer, the run fails. The model also refuses limits below the minimums of §5.8. A certification suite uses `tests.json` and `vectors.json` against the Collector under test, and uses the model only to keep the artifacts consistent.

**Step grammar.** An API test is a list of steps. A step is `submit`, `bulk`, `lookup`, `metadata`, `parallel`, `hook`, or `inspect`. A request step names the submitter (`as`), the body (a vector identifier, raw text, a JSON value, a list of these for a batch, or a generated body), optional token overrides and request headers, and the expected response. An expected response states the status, the problem `code`, and the members of the receipt or the per-element results that must match. A value of the form `$name:argument` is a matcher: `$clock` (the fixture clock), `$nonempty`, `$ms_ts` (millisecond timestamp), `$digest:V-01`, `$rid:V-01`, `$producer:V-01`, `$same:label.member` and `$ne:label.member` (equal to, or different from, a value saved by an earlier step), `$opt:value` (equal if the member is present), `$not:value`, `$present`, `$absent`, and `$any`.

**Implicit checks.** In every test the runner also checks that each error is a well-formed Problem Details object whose status and `retryable` agree with the error table of §10.2, that a `401` carries a `WWW-Authenticate` header, that no error body contains token or signature material, that every receipt has the required members, that the four flags are present in every receipt of a synchronous Collector and absent from every receipt of any other, and that a lookup response has no `idempotent_replay` member.

### 15.5 Deterministic fixtures

A test starts from the fixture state, applies its own `fixture` overrides, and then runs its steps. Nothing depends on wall-clock time or on the state left by another test. A Collector under test is put into the fixture state before each test.

**Clock.** The fixture clock is frozen at `2026-06-11T01:00:00.000Z`. It changes only through the `set_clock` and `advance_clock` hooks. Every `received_at`, every `verified_at`, and every key-validity decision uses it, so receipts and decisions are reproducible.

**Collector configuration.** Issuer `https://collector.example.org`; ingestion scope `trace.write`; receipt scope `trace.receipt.read`; limits max_record_bytes 262144, max_batch_bytes 8388608, max_batch_records 500, max_nesting_depth 32; `execution_correlation_required` true; `synchronous_integrity_flags` true; `idempotency_retention_seconds` 2592000; record retention 34560000 seconds; lateness policy 86400 seconds; one profile `tag:govops.owasp.org,2026:trace-v1`.

**Authorization servers.**

| Name | Issuer | Token format |
|---|---|---|
| AS-1 | `https://auth.example.org` | `jwt` |
| AS-2 | `https://auth2.example.org` | `introspection` |

**Submitters.** A submitter is `(issuer, client_id)`; tests name it by the first column.

| Name | Server | Scopes | Evidence domain | May submit for | May read receipts for |
|---|---|---|---|---|---|
| `c-pdp` | AS-1 | `trace.write` | D1 | `pdp-fleet-1`, `pdp-fleet-2`, `pdp/fleet 1` | none |
| `c-pep` | AS-1 | `trace.write` | D1 | `payments-gateway-pep` | none |
| `c-fwd` | AS-1 | `trace.write` | D1 | `pdp-fleet-1`, `payments-gateway-pep` | none |
| `c-ro` | AS-1 | none | D1 | `pdp-fleet-1` | none |
| `c-nodom` | AS-1 | `trace.write` | none | `pdp-fleet-1` | none |
| `c-d2` | AS-1 | `trace.write` | D2 | `pdp-fleet-1` | none |
| `c-recon` | AS-1 | `trace.receipt.read` | D1 | none | `pdp-fleet-1`, `pdp/fleet 1` |
| `as2-c-pdp` | AS-2 | `trace.write` | none | none | none |

**Producer key registry.** Both keys have `valid_from` 2026-01-01T00:00:00Z, no `valid_until`, and no revocation. The public keys are in `vectors.json`.

| Domain | Producer | `kid` | Authorized event kinds |
|---|---|---|---|
| D1 | `pdp-fleet-1` | `key-2026-01` | AUTHORIZATION_DECISION |
| D1 | `payments-gateway-pep` | `pep-key-2026-01` | CAPABILITY_INVOKED |
| D1 | `pdp/fleet 1` | `key-sl-01` | AUTHORIZATION_DECISION |
| D2 | none | | |

**Registration-mode variants.**

| Variant | Modes | Registered chains |
|---|---|---|
| M1 (default) | `first_observed_genesis` | none |
| M2 | `pre_registered_genesis` | `chain-pdp-001-a` |
| M3 | `first_observed_genesis`, `pre_registered_genesis` | `chain-pdp-001-a` |

**Hooks.** A test names the hooks it needs. A Collector that cannot supply a hook leaves that test unverified, never passed.

| Hook | Meaning |
|---|---|
| `set_clock` | set the Collector clock |
| `advance_clock` | advance the Collector clock |
| `set_key` | change a registered key's window |
| `register_key` | register a key in an evidence domain |
| `register_chain` | register a producer chain |
| `unregister_chain` | remove a chain registration |
| `set_limit` | set a limit (not below the specification's minimum) |
| `set_collector` | set a Collector configuration value |
| `add_schema_rule` | add a record-content rule |
| `set_profile_state` | withdraw a profile to replay-only |
| `set_submitter` | change a submitter's binding, scopes, or permissions |
| `set_rate_limit` | apply a request rate limit |
| `fail_commit` | make the next durable commit fail |
| `set_modes` | change the chain registration modes |
| `set_as` | change an authorization server's token profile |

Inspection hooks used by tests: `stored` (is the record held; its key identity, `verified_at`, `received_at`, and digest), `count` (records held in a domain), `assessment` (current chain findings of a record), `chain_known` (is a chain admitted).

**Determinism rules.**
- The clock is frozen, so a test can state exactly which `received_at` and which key-validity decision to expect. A Collector that has no controllable clock leaves the clock-dependent tests unverified.
- Receipt identifiers are opaque. Tests compare them only for equality with, or difference from, another receipt, never against a literal.
- Generated bodies are defined in `fixtures.json` and re-signed with the published test keys, so a size or depth test is reproducible.
- Variants M1, M2, and M3 select the registration modes (§7.4.1). A Collector is tested in the variant it advertises.

### 15.6 Test catalogue

The identifiers in the third column are requirement identifiers (§15.2). A step labelled "(hook)" uses a hook of §15.5. An expected value of "all four flags false" applies to a synchronous Collector (§15.3).

#### Collector: submission, verification, acceptance, key validity (C-*)

| ID | Applies | Requirements | Procedure | Expected |
|---|---|---|---|---|
| C-01 | Mandatory | SUB-S1, RCP-001, RCP-002, RCP-003, RCP-004, RCP-005, RCP-006, ORD-S15, ORD-S16, DUR-C1, DUR-C2, DUR-C3, ACC-001, PRV-004 | 1. `c-pdp` submits V-01. | 1. `201`, receipt: idempotent_replay false, all four flags false. |
| C-02 | Mandatory | IDP-T1, IDP-R1, SUB-S2, DUR-002, RCP-006, ORD-S10 | 1. `c-pdp` submits V-01. 2. `c-pdp` submits V-01. | 1. `201`, receipt: idempotent_replay false, all four flags false. 2. `200`, receipt: idempotent_replay true, received_at same as step 1, receipt_id same as step 1, all four flags false. |
| C-03 | Mandatory | IDP-T1, IDP-R2, PRS-R1, DIG-R2, DIG-R3 | 1. `c-pdp` submits V-01. 2. `c-pdp` submits V-06. | 1. `201`, receipt: idempotent_replay false, all four flags false. 2. `200`, receipt: idempotent_replay true, received_at same as step 1, receipt_id same as step 1. |
| C-04 | Mandatory | IDP-001, IDP-005, ORD-S13, ERR-RECORD_ID_CONFLICT, SUB-S5 | 1. `c-pdp` submits V-01. 2. `c-pdp` submits V-20. 3. inspect stored of V-01. | 1. `201`, receipt: idempotent_replay false, all four flags false. 2. `409` `RECORD_ID_CONFLICT`, retryable false, existing_content_digest = digest of V-01, submitted_content_digest = digest of V-20. 3. present true, digest = digest of V-01. |
| C-05 | Mandatory | ERR-SIGNATURE_INVALID, ORD-S12, SIG-001, ACC-001, IDP-R5, CHN-001, SUB-S3 | 1. `c-pdp` submits V-10. 2. inspect stored of V-01. 3. `c-pdp` submits V-01. 4. `c-pdp` submits V-10. | 1. `400` `SIGNATURE_INVALID`, retryable false. 2. present false. 3. `201`, receipt: idempotent_replay false, all four flags false. 4. `400` `SIGNATURE_INVALID`. |
| C-06 | Mandatory | ERR-KEY_UNKNOWN, ORD-S11, SIG-005, PRM-004 | 1. `c-pdp` submits V-11. | 1. `400` `KEY_UNKNOWN`, retryable false. |
| C-07 | Mandatory | ERR-EVENT_KIND_NOT_AUTHORIZED, ORD-S11, PRF-006, ERR-004 | 1. `c-pdp` submits V-12. 2. inspect stored of V-12. | 1. `400`, one of `EVENT_KIND_NOT_AUTHORIZED`, `KEY_UNKNOWN`. 2. present false. *ERR-003 allows a Collector to collapse key-related codes into KEY_UNKNOWN.* |
| C-08 | Mandatory | ERR-PRODUCER_IDENTITY_MISMATCH, PRF-004, ORD-S10A, ORD-S07, PRM-003, PRM-005 | 1. `c-pdp` submits V-13. 2. `c-fwd` submits V-13. | 1. `400` `PRODUCER_IDENTITY_MISMATCH`, retryable false. 2. `403` `SUBMITTER_NOT_AUTHORIZED`. *c-pdp may submit for pdp-fleet-2, so step 7 passes and step 10a reports the mismatch. c-fwd may not, so step 7 reports 403 first.* |
| C-09 | Mandatory | COR-001, ERR-MISSING_EXECUTION_CONTEXT | 1. `c-pdp` submits V-14. | 1. `400` `MISSING_EXECUTION_CONTEXT`, retryable false. |
| C-10 | Mandatory | PRF-005, ERR-UNSUPPORTED_PROFILE, ORD-S09 | 1. `c-pdp` submits V-15. | 1. `400` `UNSUPPORTED_PROFILE`, retryable false. |
| C-11 | Mandatory | SIG-002, ERR-SIGNATURE_MALFORMED | 1. `c-pdp` submits V-16. | 1. `400` `SIGNATURE_MALFORMED`, retryable false. |
| C-12 | Mandatory | RID-001, RID-002, ERR-SCHEMA_INVALID, ORD-S10A | 1. `c-pdp` submits V-17. | 1. `400` `SCHEMA_INVALID`, retryable false. |
| C-13 | Mandatory | JSN-001, JSN-L2, ERR-MALFORMED_JSON, ORD-S06A, VAL-01 | 1. `c-pdp` submits V-18. 2. inspect stored of V-01. | 1. `400` `MALFORMED_JSON`, retryable false. 2. present false. |
| C-14 | If `synchronous_integrity_flags` true | FLG-COVERAGE_GAP, CHN-COMPLETENESS, CHN-R2, RCP-007 | 1. `c-pdp` submits V-02. 2. `c-pdp` submits V-01. | 1. `201`, receipt: idempotent_replay false, flags: coverage_gap true (others false). 2. `201`, receipt: idempotent_replay false, all four flags false. |
| C-15 | If `synchronous_integrity_flags` true | FLG-CHAIN_LINK_FAILURE, CHN-INTEGRITY | 1. `c-pdp` submits V-01. 2. `c-pdp` submits V-22. | 1. `201`, receipt: idempotent_replay false, all four flags false. 2. `201`, receipt: idempotent_replay false, flags: chain_link_failure true (others false). |
| C-16 | If `synchronous_integrity_flags` true | FLG-EQUIVOCATION, IDP-T3, CHN-INTEGRITY | 1. `c-pdp` submits V-01. 2. `c-pdp` submits V-21. 3. inspect stored of V-01. 4. inspect stored of V-21. | 1. `201`, receipt: idempotent_replay false, all four flags false. 2. `201`, receipt: idempotent_replay false, flags: equivocation true (others false). 3. present true. 4. present true. |
| C-17 | Mandatory | AUT-001, ERR-UNAUTHENTICATED, ORD-S02, TOK-001, SUB-S4 | 1. no token submits V-01. 2. `c-pdp` submits V-01 (token `{"exp":"expired"}`). | 1. `401` `UNAUTHENTICATED`, headers: WWW-Authenticate present. 2. `401` `UNAUTHENTICATED`, headers: WWW-Authenticate present. |
| C-18 | Mandatory | SCO-001, ERR-INSUFFICIENT_SCOPE, ORD-S03 | 1. `c-ro` submits V-01. | 1. `403` `INSUFFICIENT_SCOPE`. |
| C-19 | Mandatory | DOM-002, DOM-003, ERR-EVIDENCE_DOMAIN_NOT_BOUND, ORD-S04 | 1. `c-nodom` submits V-01. | 1. `403` `EVIDENCE_DOMAIN_NOT_BOUND`. |
| C-20 | Mandatory | PRM-001, PRM-003, ERR-SUBMITTER_NOT_AUTHORIZED, ORD-S07, ORD-001 | 1. `c-pep` submits V-01. 2. `c-pep` submits V-10. | 1. `403` `SUBMITTER_NOT_AUTHORIZED`. 2. `403` `SUBMITTER_NOT_AUTHORIZED`. |
| C-21 | Mandatory | DOM-001, DOM-008, DOM-009, DOM-010, IDP-T5, ERR-005 | 1. `c-d2` submits V-01. 2. (hook) register a key in an evidence domain: domain "D2", key_from "pdp-fleet-1/key-2026-01". 3. `c-d2` submits V-01. 4. `c-pdp` submits V-01. | 1. `400` `KEY_UNKNOWN`. 3. `201`, receipt: idempotent_replay false, all four flags false. 4. `201`, receipt: idempotent_replay false, all four flags false. |
| C-22 | Mandatory | CO-1, PRM-002, ORD-S07, CO-2 | 1. `c-fwd` submits V-01. 2. `c-fwd` submits V-03. | 1. `201`, receipt: idempotent_replay false, all four flags false. 2. `201`, receipt: idempotent_replay false, all four flags false. |
| C-23 | Mandatory; hooks: fault injection at the commit point | DUR-004, DUR-005, ERR-COLLECTOR_UNAVAILABLE, ORD-S15, ERR-001, SUB-S7, CO-4 | 1. (hook) make the next durable commit fail: count 1. 2. `c-pdp` submits V-01. 3. inspect count. 4. `c-pdp` submits V-01. | 2. `503` `COLLECTOR_UNAVAILABLE`, retryable true. 3. count 0. 4. `201`, receipt: idempotent_replay false, all four flags false. |
| C-24 | Mandatory | LIM-RECORD, ERR-RECORD_TOO_LARGE, LIM-002, DSM-009, SUB-S6 | 1. `c-pdp` submits a generated copy of V-01 that is max_record_bytes + 1 bytes. 2. `c-pdp` submits a generated copy of V-01 that is max_record_bytes bytes. | 1. `413` `RECORD_TOO_LARGE`, retryable false. 2. `201`. |
| C-25 | Mandatory | WIR-001, WIR-003, ERR-UNSUPPORTED_MEDIA_TYPE, ORD-S05, SUB-S6 | 1. `c-pdp` submits V-01 (content type `text/plain`). 2. `c-pdp` submits V-01 (content encoding `gzip`). | 1. `415` `UNSUPPORTED_MEDIA_TYPE`. 2. `415` `UNSUPPORTED_MEDIA_TYPE`. |
| C-26 | Mandatory | DOM-005, DOM-006, PRF-007 | 1. `c-pdp` submits V-05. 2. inspect stored of V-05. 3. inspect count in D2. | 1. `201`, receipt: idempotent_replay false, all four flags false. 2. present true. 3. count 0. |
| C-27 | Mandatory | IDP-004, IDP-T1 | 1. concurrently: `c-pdp` submits V-01 and `c-pdp` submits V-01. | 1. statuses `200`, `201`, one receipt. *The reference model runs the requests in turn. A real Collector runs them concurrently and must return the same outcome set.* |
| C-28 | Mandatory; hooks: registry (revoke key) | KEY-007, IDP-002, ERR-KEY_NOT_VALID, KEY-R1 | 1. `c-pdp` submits V-01. 2. (hook) change a registered key's window: producer_id "pdp-fleet-1", kid "key-2026-01", revoked_at "2026-06-11T01:00:00.000Z". 3. `c-pdp` submits V-01. 4. `c-pdp` submits V-02. | 1. `201`, receipt: idempotent_replay false, all four flags false. 3. `200`, receipt: idempotent_replay true, received_at same as step 1, receipt_id same as step 1. 4. `400` `KEY_NOT_VALID`. |
| C-29 | Mandatory | PRB-001, PRB-002, PRB-003, PRB-004, PRB-005, PRB-010, ERR-006, ERR-002, PRV-006 | 1. `c-pdp` submits V-10. 2. `c-pdp` submits V-11. 3. `c-ro` submits V-01. 4. `c-pdp` submits the text `{`. | 1. `400` `SIGNATURE_INVALID`. 2. `400` `KEY_UNKNOWN`. 3. `403` `INSUFFICIENT_SCOPE`. 4. `400` `MALFORMED_JSON`. *The runner checks type, title, status, code, retryable, the status and retryable values of the error table, and the absence of tokens and signatures in every error body.* |
| C-30 | Mandatory | RCP-004, RCP-005, RCP-011, RCP-012 | 1. `c-pdp` submits V-01. | 1. `201`, receipt present. |
| C-31 | Mandatory | TRN-001, TRN-002, ORD-S01 | 1. `c-pdp` submits V-01 (scheme `http`). | 1. refused. *The model returns the status 'refused' for any non-TLS request.* |
| C-32 | Mandatory; inspection; hooks: quarantine inspection | ACC-001, ACC-002, IDP-006 | On a Collector that quarantines, submit V-10. Inspect retrieval, correlation, and the receipt store. | The response is a rejection with no receipt. The record is absent from retrieval and correlation. |
| C-33 | Mandatory; inspection; hooks: process kill at the commit point | DUR-001, DUR-003, ORD-S15 | Kill the Collector between receiving V-01 and the durable commit. Restart. Resubmit V-01. | No receipt was returned before the kill. After restart, resubmission is a first acceptance (201, idempotent_replay false). |
| C-34 | Mandatory | CO-3, PRS-001, PRS-002, PRF-008, ACC-004 | 1. `c-fwd` submits V-01. 2. `c-fwd` submits V-03. 3. inspect stored of V-01. 4. inspect stored of V-03. | 1. `201`, receipt: idempotent_replay false, all four flags false. 2. `201`, receipt: idempotent_replay false, all four flags false. 3. present true, digest = digest of V-01. 4. present true, digest = digest of V-03. |
| C-35 | If `synchronous_integrity_flags` false or absent; hooks: assessment interface | ASY-002, ASY-008, ASY-003, RCP-007 | 1. `c-pdp` submits V-02. 2. inspect assessment of V-02. | 1. `201`, receipt: idempotent_replay false. 2. present true, coverage_gap_flag true. |
| C-36 | If `synchronous_integrity_flags` false or absent; hooks: assessment interface | ASY-002, ASY-006, ASY-007, CHN-R2 | 1. `c-pdp` submits V-01. 2. `c-pdp` submits V-22. 3. `c-pdp` submits V-21. 4. inspect assessment of V-22. 5. inspect assessment of V-21. 6. inspect assessment of V-01. | 1. `201`, receipt: idempotent_replay false. 2. `201`. 3. `201`. 4. chain_link_failure_flag true. 5. equivocation_flag true. 6. equivocation_flag true. |
| C-37 | Mandatory | JSN-R1, VAL-03, VAL-01, ORD-S06B, ORD-S06A | 1. `c-pdp` submits the text `42`. 2. `c-pdp` submits [V-01]. 3. `c-pdp` submits the text `{`. | 1. `400` `SCHEMA_INVALID`. 2. `400` `SCHEMA_INVALID`. 3. `400` `MALFORMED_JSON`. |
| C-38 | Mandatory | ORD-001, DOM-007, ORD-S02, ORD-S03, ORD-S04, ORD-S06A | 1. no token submits the text `{`. 2. `c-ro` submits the text `{`. 3. `c-nodom` submits the text `{`. | 1. `401` `UNAUTHENTICATED`. 2. `403` `INSUFFICIENT_SCOPE`. 3. `403` `EVIDENCE_DOMAIN_NOT_BOUND`. |
| C-39 | Mandatory; hooks: Collector clock, registry | KEY-R0, KEY-001, KEY-002, KEY-R1, KEY-004, SEC-001, SIG-006 | 1. (hook) change a registered key's window: producer_id "pdp-fleet-1", kid "key-2026-01", valid_from "2026-06-12T00:00:00.000Z". 2. (hook) set the Collector clock: value "2026-06-12T00:00:01.000Z". 3. `c-pdp` submits V-01. | 3. `201`, receipt: idempotent_replay false, all four flags false. |
| C-40 | Mandatory; hooks: Collector clock, registry | ERR-KEY_NOT_VALID, KEY-R1, KEY-R0 | 1. (hook) change a registered key's window: producer_id "pdp-fleet-1", kid "key-2026-01", valid_until "2026-06-11T00:00:00.000Z". 2. `c-pdp` submits V-01. 3. (hook) change a registered key's window: producer_id "pdp-fleet-1", kid "key-2026-01", valid_until "2026-06-13T00:00:00.000Z". 4. `c-pdp` submits V-01. | 2. `400` `KEY_NOT_VALID`, retryable false. 4. `201`, receipt: idempotent_replay false, all four flags false. |
| C-41 | Mandatory; hooks: Collector clock, registry | KEY-R1, ERR-KEY_NOT_VALID | 1. (hook) change a registered key's window: producer_id "pdp-fleet-1", kid "key-2026-01", valid_from "2026-06-11T01:00:00.000Z". 2. `c-pdp` submits V-01. 3. (hook) change a registered key's window: producer_id "pdp-fleet-1", kid "key-2026-01", valid_until "2026-06-11T01:00:00.000Z". 4. `c-pdp` submits V-02. | 2. `201`, receipt: idempotent_replay false, all four flags false. 4. `400` `KEY_NOT_VALID`. |
| C-42 | Mandatory; hooks: Collector clock, registry | KEY-007, KEY-005, KEY-004, IDP-002, KEY-R2 | 1. `c-pdp` submits V-01. 2. (hook) change a registered key's window: producer_id "pdp-fleet-1", kid "key-2026-01", valid_until "2026-06-11T01:00:01.000Z". 3. (hook) advance the Collector clock: seconds 2. 4. `c-pdp` submits V-01. 5. `c-pdp` submits V-02. 6. inspect stored of V-01. | 1. `201`, receipt: idempotent_replay false, all four flags false. 4. `200`, receipt: idempotent_replay true, received_at same as step 1, receipt_id same as step 1. 5. `400` `KEY_NOT_VALID`. 6. present true, key ['pdp-fleet-1', 'key-2026-01'], verified_at "2026-06-11T01:00:00.000Z", received_at "2026-06-11T01:00:00.000Z". |
| C-43 | Mandatory; hooks: Collector clock, registry | KEY-001, KEY-002, WIR-005 | 1. (hook) change a registered key's window: producer_id "pdp-fleet-1", kid "key-2026-01", valid_until "2026-06-11T00:00:00.000Z". 2. `c-pdp` submits V-01 (request headers `{"Date":"Thu, 11 Jun 2026 00:30:00 GMT","X-Audit-Time":"2026-06-11T00:30:00Z"}`). | 2. `400` `KEY_NOT_VALID`. |
| C-44 | Mandatory; hooks: Collector clock, registry | KEY-R1, ERR-KEY_NOT_VALID, KEY-001 | 1. (hook) change a registered key's window: producer_id "pdp-fleet-1", kid "key-2026-01", revoked_at "2026-06-11T01:00:00.000Z". 2. `c-pdp` submits V-01. | 2. `400` `KEY_NOT_VALID`. |
| C-45 | Mandatory | IDP-004, IDP-001 | 1. concurrently: `c-pdp` submits V-01 and `c-pdp` submits V-20. | 1. statuses `201`, `409`. |
| C-46 | Mandatory; hooks: registry (register key) | SIG-003, SIG-004, ERR-UNSUPPORTED_ALGORITHM, PRF-001, PRF-002, PRF-003, DSP-007, DSP-008, SEC-004, SIG-001 | 1. (hook) register a key in an evidence domain: domain "D1", key_from "pdp-fleet-1/key-2026-01", patch {"kid": "key-es-01", "algorithm": "ES256"}. 2. `c-pdp` submits a generated, re-signed copy of V-01 with kid = "key-es-01". | 2. `400` `UNSUPPORTED_ALGORITHM`. |
| C-47 | Mandatory | LIM-DEPTH, ERR-MALFORMED_JSON, JSN-L4, LIM-002 | 1. `c-pdp` submits a generated copy of V-01 nested 40 levels deep. | 1. `400` `MALFORMED_JSON`. |
| C-48 | Mandatory | JSN-L1, VAL-01, ERR-MALFORMED_JSON | 1. `c-pdp` submits V-01 with an invalid UTF-8 byte. | 1. `400` `MALFORMED_JSON`. |
| C-49 | Mandatory | RID-R1, PRM-001 | 1. `c-pdp` submits V-26. | 1. `201`, receipt: idempotent_replay false, all four flags false. |
| C-50 | Mandatory | ERR-SCHEMA_INVALID, ORD-S10A, PRF-004 | 1. `c-pdp` submits V-25. | 1. `400` `SCHEMA_INVALID`. |
| C-51 | If `gzip` content encoding advertised | WIR-002, DSM-020 | 1. read the metadata. 2. `c-pdp` submits V-01 (content encoding `gzip`). | 1. `200`, content_encodings_supported ["gzip"]. 2. `201`, receipt: idempotent_replay false, all four flags false. *A real harness gzips the body. The model does not decode it.* |
| C-52 | If `gzip` content encoding advertised; inspection | WIR-004 | Send a gzip body that decodes to more than max_record_bytes (a decompression bomb). | The Collector stops decoding at the limit and returns 413 without allocating the decoded size. |
| C-53 | Mandatory | PRM-004, SIG-006 | 1. `c-pdp` submits a generated, re-signed copy of V-01 with kid = "key-inline", trace.x_public_key_jwk = {"kty": "OKP", "crv": "Ed25519", "x": "A. | 1. `400` `KEY_UNKNOWN`. |
| C-54 | Mandatory | LIM-001, ERR-SCHEMA_INVALID | 1. `c-pdp` submits a generated, re-signed copy of V-01 with trace.event.tokens = [{"issuer": "https://a.example", "token_. | 1. `400` `SCHEMA_INVALID`. |
| C-55 | If `execution_correlation_required` false | COR-002, RCP-008 | 1. read the metadata. 2. `c-pdp` submits V-14. | 1. `200`, execution_correlation_required false. 2. `201`, receipt: idempotent_replay false, unattributed_flag true. |
| C-56 | If `synchronous_integrity_flags` true; hooks: Collector clock | FLG-LATE, RCP-007, SEC-001 | 1. (hook) set the Collector clock: value "2026-06-13T00:00:00.000Z". 2. `c-pdp` submits V-01. | 2. `201`, receipt: idempotent_replay false, flags: late true (others false). |
| C-57 | Mandatory | IDP-T4, RID-004, RID-R1 | 1. `c-pdp` submits V-01. 2. `c-pdp` submits a generated, re-signed copy of V-01 with producer = "pdp/fleet 1", kid = "key-sl-01", producer_chain.producer_id = "pdp/fleet 1", producer_chain.producer_chain_id = "chain-sl-02". | 1. `201`, receipt: idempotent_replay false, all four flags false. 2. `201`. |
| C-58 | If rate limiting applied; hooks: rate limit | ERR-RATE_LIMITED, SUB-S6 | 1. (hook) apply a request rate limit: max_requests 1. 2. `c-pdp` submits V-01. 3. `c-pdp` submits V-02. | 2. `201`. 3. `429` `RATE_LIMITED`, retryable true, headers: Retry-After present. |
| C-59 | If an integrity-hold state exists; inspection; hooks: integrity hold | ERR-COLLECTOR_INTEGRITY_HOLD | Put the Collector in its integrity-hold state and submit V-01. | 503 COLLECTOR_INTEGRITY_HOLD, retryable true, Retry-After present, nothing accepted. |
| C-60 | Mandatory; inspection; hooks: fault injection | ERR-INTERNAL_ERROR | Cause an unexpected internal failure while processing V-01. | 500 INTERNAL_ERROR, retryable true, no receipt, record, or index entry. A retry of the same bytes is a first acceptance. |
| C-61 | Mandatory | JSN-L3, VAL-01 | 1. `c-pdp` submits the text `{} x`. | 1. `400` `MALFORMED_JSON`. |
| C-62 | Mandatory | DIG-R1, DIG-R3 | 1. `c-pdp` submits a generated, re-signed copy of V-01 with content_digest = "sha256:00000000000000000000000000000000. | 1. `201`, receipt: content_digest is not sha256:0000000.... |

#### Authentication and submitter identity (A-*)

| ID | Applies | Requirements | Procedure | Expected |
|---|---|---|---|---|
| A-01 | Mandatory | AUT-M1, AUT-M2, AUT-001, IDN-005, TOK-001, AUT-003 | 1. `c-pdp` submits V-01. | 1. `201`, receipt: idempotent_replay false, all four flags false. |
| A-02 | If two or more authorization servers trusted | IDN-001, IDN-002, DOM-002, IDN-R1 | 1. `as2-c-pdp` submits V-01. | 1. `403` `EVIDENCE_DOMAIN_NOT_BOUND`. |
| A-03 | If two or more authorization servers trusted; hooks: submitter bindings, registry (register key) | IDN-001, IDN-002, DOM-001, DOM-010, IDP-T5 | 1. (hook) change a submitter's binding, scopes, or permissions: name "as2-c-pdp", patch {"domain": "D2", "submit_for": ["pdp-fleet-1"]}. 2. (hook) register a key in an evidence domain: domain "D2", key_from "pdp-fleet-1/key-2026-01". 3. `as2-c-pdp` submits V-01. 4. `c-pdp` submits V-01. | 3. `201`, receipt: idempotent_replay false, all four flags false. 4. `201`, receipt: idempotent_replay false, all four flags false. |
| A-04 | If two or more authorization servers trusted; hooks: submitter bindings | IDN-002, PRM-001, PRM-003 | 1. (hook) change a submitter's binding, scopes, or permissions: name "as2-c-pdp", patch {"domain": "D1", "submit_for": []}. 2. `as2-c-pdp` submits V-01. | 2. `403` `SUBMITTER_NOT_AUTHORIZED`. |
| A-05 | Mandatory | IDN-005, ERR-UNAUTHENTICATED | 1. `c-pdp` submits V-01 (token `{"iss":"https://evil.example","signer":"https://evil.example"}`). | 1. `401` `UNAUTHENTICATED`. |
| A-06 | Mandatory | AUT-004, IDN-005, TOK-001, AUT-M2 | 1. `c-pdp` submits V-01 (token `{"signer":"https://auth2.example.org"}`). 2. `c-pdp` submits V-01 (token `{"alg":"none"}`). 3. `c-pdp` submits V-01 (token `{"alg":"HS256"}`). 4. `c-pdp` submits V-01 (token `{"header_params":["jku"]}`). | 1. `401` `UNAUTHENTICATED`. 2. `401` `UNAUTHENTICATED`. 3. `401` `UNAUTHENTICATED`. 4. `401` `UNAUTHENTICATED`. |
| A-07 | Mandatory | IDN-007, IDN-004 | 1. `c-pdp` submits V-01 (token `{"claims":{"client_id":null,"sub":"c-pdp"}}`). | 1. `401` `UNAUTHENTICATED`. |
| A-08 | If a configurable client identifier claim; hooks: authorization server profile | IDN-004, IDN-005, DSA-003 | 1. (hook) change an authorization server's token profile: as "AS-1", patch {"client_id_claim": "azp"}. 2. `c-pdp` submits V-01 (token `{"claims":{"azp":"c-unknown"}}`). | 2. `403` `EVIDENCE_DOMAIN_NOT_BOUND`. |
| A-09 | Mandatory | IDN-008, WIR-005 | 1. `c-nodom` submits V-01 (request headers `{"X-Client-Id":"c-pdp","X-Forwarded-Client":"c-pdp"}`). | 1. `403` `EVIDENCE_DOMAIN_NOT_BOUND`. |
| A-10 | Mandatory | TOK-001, TOK-002, ERR-UNAUTHENTICATED | 1. `c-pdp` submits V-01 (token `{"exp":"expired"}`). 2. `c-pdp` submits V-01 (token `{"nbf":"future"}`). 3. `c-pdp` submits V-01 (token `{"aud":["https://other.example"]}`). | 1. `401` `UNAUTHENTICATED`, headers: WWW-Authenticate invalid_token. 2. `401` `UNAUTHENTICATED`. 3. `401` `UNAUTHENTICATED`. |
| A-11 | If an authorization server with `token_format` `introspection`; hooks: submitter bindings | TOK-003, TOK-004, IDN-006, ERR-COLLECTOR_UNAVAILABLE, AUT-006 | 1. (hook) change a submitter's binding, scopes, or permissions: name "as2-c-pdp", patch {"domain": "D1", "submit_for": ["pdp-fleet-1"]}. 2. `as2-c-pdp` submits V-01 (token `{"introspection":{"active":false}}`). 3. `as2-c-pdp` submits V-01. 4. `as2-c-pdp` submits V-01 (token `{"introspection":"unavailable"}`). | 2. `401` `UNAUTHENTICATED`. 3. `201`, receipt: idempotent_replay false, all four flags false. 4. `503` `COLLECTOR_UNAVAILABLE`, headers: Retry-After present. |
| A-12 | If an authorization server with `token_format` `introspection` | IDN-006 | 1. `as2-c-pdp` submits V-01 (token `{"introspection":{"iss":"https://auth.example.org"}}`). | 1. `401` `UNAUTHENTICATED`. |
| A-13 | Mandatory | AUT-005, AUT-M3, SCT-002, SCT-003 | 1. `c-pdp` submits V-01 (token `{"cnf":"dpop","cnf_proof":false}`). 2. `c-pdp` submits V-01 (token `{"cnf":"dpop","cnf_proof":true}`). | 1. `401` `UNAUTHENTICATED`. 2. `401` `UNAUTHENTICATED`. *The fixture Collector supports no sender-constrained mechanism, so even a token with a proof is rejected.* |
| A-14 | Mandatory | AUT-002 | 1. `c-pdp` submits V-01 (token `{"location":"query"}`). 2. `c-pdp` submits V-01 (token `{"location":"body"}`). | 1. `401` `UNAUTHENTICATED`. 2. `401` `UNAUTHENTICATED`. |
| A-15 | Mandatory | IDN-004, IDN-007 | 1. `c-pdp` submits V-01 (token `{"claims":{"sub":"c-pep"}}`). | 1. `201`, receipt: idempotent_replay false, all four flags false. |
| A-16 | If DPoP or mTLS supported | SCT-002, DSM-006 | 1. `c-pdp` submits V-01 (token `{"cnf":"dpop","cnf_proof":true}`). 2. `c-pdp` submits V-02 (token `{"cnf":"dpop","cnf_proof":false}`). | 1. `201`, receipt: idempotent_replay false, all four flags false. 2. `401` `UNAUTHENTICATED`. |
| A-17 | Mandatory; inspection; hooks: Collector configuration review | IDN-003 | Inspect the Collector's binding and permission configuration for AS-1 and AS-2 clients that share a client_id. | Bindings and permissions are keyed by the pair, or by an unambiguous encoding of it, and never by client_id alone. |
| A-18 | If an authorization server with `token_format` `introspection`; inspection; hooks: introspection stub | TOK-006 | Return active:true with a short exp, then active:false for the same token after exp, and resubmit. | The second submission is rejected with 401. The first result was not reused after exp. |

#### Chain admission, integrity, completeness (G-*)

| ID | Applies | Requirements | Procedure | Expected |
|---|---|---|---|---|
| G-01 | If modes are `first_observed_genesis` only (variant M1) | ADM-M1, ADM-001, CHN-ADMISSION, DSM-013 | 1. `c-pdp` submits V-01. 2. `c-pdp` submits V-04. | 1. `201`, receipt: idempotent_replay false, chain_admission = first_observed_genesis if present, all four flags false. 2. `201`, receipt: idempotent_replay false, all four flags false. |
| G-02 | If modes are `first_observed_genesis` only (variant M1) | ADM-R2, FLG-COVERAGE_GAP | 1. `c-pdp` submits V-24. | 1. `201`, receipt: idempotent_replay false, flags: coverage_gap true (others false). |
| G-03 | If modes are `pre_registered_genesis` only (variant M2) | ADM-M2, ERR-CHAIN_NOT_REGISTERED, ORD-S14, CHN-ADMISSION, CHN-R4 | 1. `c-pdp` submits V-01. 2. `c-pdp` submits V-04. 3. `c-pdp` submits V-24. 4. inspect count. | 1. `201`, receipt: idempotent_replay false, all four flags false. 2. `400` `CHAIN_NOT_REGISTERED`, retryable false. 3. `400` `CHAIN_NOT_REGISTERED`. 4. count 1. |
| G-04 | If modes are `pre_registered_genesis` only (variant M2) | ADM-M2, CHN-R1, CHN-R2 | 1. `c-pdp` submits V-02. 2. `c-pdp` submits V-01. | 1. `201`, receipt: idempotent_replay false, flags: coverage_gap true (others false). 2. `201`, receipt: idempotent_replay false, all four flags false. |
| G-05 | If modes are `pre_registered_genesis` only (variant M2); hooks: chain registration | ADM-R3, ERR-CHAIN_NOT_REGISTERED | 1. `c-pdp` submits V-05. 2. (hook) register a producer chain: producer_id "pdp-fleet-1", producer_instance_id "pdp-001", producer_chain_id "chain-pdp-001-d". 3. `c-pdp` submits V-05. | 1. `400` `CHAIN_NOT_REGISTERED`. 3. `201`, receipt: idempotent_replay false, all four flags false. |
| G-06 | If both modes listed (variant M3) | ADM-M3, ADM-002, ADM-003 | 1. `c-pdp` submits V-01. 2. `c-pdp` submits V-04. | 1. `201`, receipt: idempotent_replay false, chain_admission = pre_registered_genesis if present. 2. `201`, receipt: idempotent_replay false, chain_admission = first_observed_genesis if present. |
| G-07 | If modes are `first_observed_genesis` only (variant M1) | CHN-001, ADM-R3 | 1. `c-pdp` submits V-10. 2. inspect chain_known. 3. `c-pdp` submits V-01. | 1. `400` `SIGNATURE_INVALID`. 2. known false. 3. `201`, receipt: idempotent_replay false, all four flags false. |
| G-08 | Mandatory | FLG-CHAIN_LINK_FAILURE, FLG-COVERAGE_GAP, CHN-INTEGRITY | In each variant M1, M2, M3: 1. `c-pdp` submits V-23. | 1. `201`, receipt: idempotent_replay false, flags: coverage_gap true, chain_link_failure true (others false). |
| G-09 | If modes are `pre_registered_genesis` only (variant M2); hooks: chain registration | ADM-R1 | 1. `c-pdp` submits V-01. 2. (hook) remove a chain registration: producer_chain_id "chain-pdp-001-a". 3. `c-pdp` submits V-02. | 1. `201`, receipt: idempotent_replay false, all four flags false. 3. `201`, receipt: idempotent_replay false, all four flags false. |
| G-10 | Mandatory | CHN-R1, CHN-R2, CHN-ADMISSION | In each variant M1, M2, M3: 1. `c-pdp` submits V-01. 2. `c-pdp` submits V-02. | 1. `201`, receipt: idempotent_replay false, all four flags false. 2. `201`, receipt: idempotent_replay false, all four flags false. |

#### Replay, retention, and configuration changes (R-*)

| ID | Applies | Requirements | Procedure | Expected |
|---|---|---|---|---|
| R-01 | Mandatory | RET-002, DSM-017, RET-006 | 1. read the metadata. | 1. `200`, present: idempotency_retention_seconds, idempotency_retention_seconds at least 86400. |
| R-02 | Mandatory; hooks: Collector clock | RET-001, IDP-T1 | 1. `c-pdp` submits V-01. 2. (hook) advance the Collector clock: seconds 2591999. 3. `c-pdp` submits V-01. | 1. `201`, receipt: idempotent_replay false, all four flags false. 3. `200`, receipt: idempotent_replay true, received_at same as step 1, receipt_id same as step 1. |
| R-03 | Mandatory; hooks: Collector clock | RET-004, RET-001 | 1. `c-pdp` submits V-01. 2. (hook) advance the Collector clock: seconds 8640000. 3. `c-pdp` submits V-01. | 1. `201`, receipt: idempotent_replay false, all four flags false. 3. `200`, receipt: idempotent_replay true, received_at same as step 1, receipt_id same as step 1. |
| R-04 | Mandatory; hooks: Collector clock | EXP-M1, EXP-001, ORD-S10 | 1. `c-pdp` submits V-01. 2. (hook) advance the Collector clock: seconds 34646400. 3. `c-pdp` submits V-01. | 1. `201`, receipt: idempotent_replay false, all four flags false. 3. `201`, receipt: idempotent_replay false, receipt_id differs from step 1. |
| R-05 | Mandatory; hooks: Collector clock | EXP-M3 | 1. `c-pdp` submits V-01. 2. (hook) advance the Collector clock: seconds 34646400. 3. `c-pdp` submits V-20. | 1. `201`, receipt: idempotent_replay false, all four flags false. 3. `201`, receipt: idempotent_replay false. |
| R-06 | Mandatory; hooks: Collector clock, registry | EXP-M2, ERR-KEY_NOT_VALID | 1. `c-pdp` submits V-01. 2. (hook) advance the Collector clock: seconds 34646400. 3. (hook) change a registered key's window: producer_id "pdp-fleet-1", kid "key-2026-01", valid_until "2026-12-31T00:00:00.000Z". 4. `c-pdp` submits V-01. | 1. `201`, receipt: idempotent_replay false, all four flags false. 4. `400` `KEY_NOT_VALID`. |
| R-07 | Mandatory; hooks: schema rules | RPR-001, RPR-T5, RPR-T6, ORD-R2 | 1. `c-pdp` submits V-01. 2. (hook) add a record-content rule: rule {"require_member": "trace.policy.policy_store_owner"}. 3. `c-pdp` submits V-01. 4. `c-pdp` submits V-02. | 1. `201`, receipt: idempotent_replay false, all four flags false. 3. `200`, receipt: idempotent_replay true, received_at same as step 1, receipt_id same as step 1. 4. `400` `SCHEMA_INVALID`. |
| R-08 | If a profile can be withdrawn to replay-only; hooks: profile list | RPR-002, DSM-018, RPR-T4, ERR-UNSUPPORTED_PROFILE | 1. `c-pdp` submits V-01. 2. (hook) withdraw a profile to replay-only: profile "tag:govops.owasp.org,2026:trace-v1", state "replay_only". 3. read the metadata. 4. `c-pdp` submits V-01. 5. `c-pdp` submits V-02. | 1. `201`, receipt: idempotent_replay false, all four flags false. 3. `200`, present: trace_profiles_replay_only, trace_profiles_replay_only ["tag:govops.owasp.org,2026:trace-v1"]. 4. `200`, receipt: idempotent_replay true, received_at same as step 1, receipt_id same as step 1. 5. `400` `UNSUPPORTED_PROFILE`. |
| R-09 | If a profile can be withdrawn to replay-only; inspection; hooks: profile list, Collector clock | RPR-002, DSM-018 | Withdraw the profile of V-01 (replay-only). Check the metadata. Advance the clock past received_at plus idempotency_retention_seconds for every accepted record of that profile. | Until that point the profile is in trace_profiles_replay_only and V-01 is still a replay. Only afterwards may it leave the list. |
| R-10 | Mandatory; hooks: limits | RPR-T3, RPR-003, ERR-RECORD_TOO_LARGE | 1. `c-pdp` submits a generated copy of V-01 of 100000 bytes. 2. (hook) set a limit (not below the specification's minimum): name "max_record_bytes", value 65536. 3. `c-pdp` submits a generated copy of V-01 of 100000 bytes. 4. (hook) set a limit (not below the specification's minimum): name "max_record_bytes", value 262144. 5. `c-pdp` submits a generated copy of V-01 of 100000 bytes. | 1. `201`. 3. `413` `RECORD_TOO_LARGE`. 5. `200`. |
| R-11 | Mandatory; hooks: submitter permissions | RPR-T1, IDP-003, PRM-003 | 1. `c-pdp` submits V-01. 2. (hook) change a submitter's binding, scopes, or permissions: name "c-pdp", patch {"submit_for": []}. 3. `c-pdp` submits V-01. | 1. `201`, receipt: idempotent_replay false, all four flags false. 3. `403` `SUBMITTER_NOT_AUTHORIZED`. |
| R-12 | Mandatory; hooks: registration mode | RPR-T7, ADM-R1 | 1. `c-pdp` submits V-01. 2. (hook) change the chain registration modes: modes ["pre_registered_genesis"]. 3. `c-pdp` submits V-01. 4. `c-pdp` submits V-04. | 1. `201`, receipt: idempotent_replay false, all four flags false. 3. `200`, receipt: idempotent_replay true, received_at same as step 1, receipt_id same as step 1. 4. `400` `CHAIN_NOT_REGISTERED`. |
| R-13 | If Collector-Bulk (bulk endpoint offered) | BLP-003, IDP-T1, BLR-001 | 1. `c-pdp` submits V-01. 2. `c-pdp` submits a batch [V-01, V-02, V-01]. | 1. `201`, receipt: idempotent_replay false, all four flags false. 2. `200`, results [0] accepted, replay; [1] accepted; [2] accepted, replay. |
| R-14 | Mandatory; hooks: submitter bindings, registry (register key) | RPR-T1, DOM-001, IDP-T5 | 1. `c-pdp` submits V-01. 2. (hook) change a submitter's binding, scopes, or permissions: name "c-pdp", patch {"domain": "D2"}. 3. `c-pdp` submits V-01. 4. (hook) register a key in an evidence domain: domain "D2", key_from "pdp-fleet-1/key-2026-01". 5. `c-pdp` submits V-01. | 1. `201`, receipt: idempotent_replay false, all four flags false. 3. `400` `KEY_UNKNOWN`. 5. `201`, receipt: idempotent_replay false, all four flags false. |
| R-15 | If `synchronous_integrity_flags` true | IDP-R1, RCP-007, ASY-005 | 1. `c-pdp` submits V-02. 2. `c-pdp` submits V-01. 3. `c-pdp` submits V-02. | 1. `201`, receipt: idempotent_replay false, flags: coverage_gap true (others false). 2. `201`, receipt: idempotent_replay false, all four flags false. 3. `200`, receipt: idempotent_replay true, received_at same as step 1, receipt_id same as step 1, flags: coverage_gap true (others false). *V-01 arrives later and closes the gap, but the replay of V-02 still reports the flags as of its acceptance.* |
| R-16 | Mandatory | RPR-T2, RPR-T1 | 1. `c-pdp` submits V-01. 2. `c-pdp` submits V-01 (content type `text/plain`). 3. `c-pdp` submits the text `{`. | 1. `201`, receipt: idempotent_replay false, all four flags false. 2. `415` `UNSUPPORTED_MEDIA_TYPE`. 3. `400` `MALFORMED_JSON`. |

#### Receipt lookup (L-*)

| ID | Applies | Requirements | Procedure | Expected |
|---|---|---|---|---|
| L-01 | If receipt lookup offered | DSM-015, DSM-016, SCO-006 | 1. read the metadata. | 1. `200`, template with both variables; scope differs from the ingestion scope. |
| L-02 | If receipt lookup offered | LKP-R1, LKP-R2, LKP-002, LKP-A1, LKP-A2, LKP-A3, DUR-002, PRV-004, LKP-003 | 1. `c-pdp` submits V-01. 2. `c-recon` looks up `pdp-fleet-1` / V-01. | 1. `201`, receipt: idempotent_replay false, all four flags false. 2. `200`, receipt: receipt_id same as step 1, received_at same as step 1, all four flags false. |
| L-03 | If receipt lookup offered | LKP-R1, IDP-R1 | 1. `c-pdp` submits V-01. 2. `c-pdp` submits V-01. 3. `c-recon` looks up `pdp-fleet-1` / V-01. | 1. `201`, receipt: idempotent_replay false, all four flags false. 2. `200`. 3. `200`, receipt: receipt_id same as step 1, received_at same as step 1, all four flags false. |
| L-04 | If receipt lookup offered | LKP-N1, ERR-RECEIPT_NOT_FOUND | 1. `c-recon` looks up `pdp-fleet-1` / V-02. | 1. `404` `RECEIPT_NOT_FOUND`, retryable true. |
| L-05 | If receipt lookup offered | LKP-N1, ACC-001 | 1. `c-pdp` submits V-10. 2. `c-recon` looks up `pdp-fleet-1` / V-10. | 1. `400` `SIGNATURE_INVALID`. 2. `404` `RECEIPT_NOT_FOUND`. |
| L-06 | If receipt lookup offered | SCO-005, LKP-A2, SCO-006 | 1. `c-pdp` looks up `pdp-fleet-1` / V-01. 2. `c-recon` submits V-01. | 1. `403` `INSUFFICIENT_SCOPE`. 2. `403` `INSUFFICIENT_SCOPE`. |
| L-07 | If receipt lookup offered | LKP-004, ERR-RECEIPT_ACCESS_DENIED, PRB-011, IDP-003 | 1. `c-pep` submits V-03. 2. `c-recon` looks up `payments-gateway-pep` / V-03. 3. `c-recon` looks up `payments-gateway-pep` / V-02. | 1. `201`, receipt: idempotent_replay false, all four flags false. 2. `403` `RECEIPT_ACCESS_DENIED`, retryable false. 3. `403` `RECEIPT_ACCESS_DENIED`, retryable false. |
| L-08 | If receipt lookup offered; hooks: submitter bindings | DOM-009, LKP-A3, DOM-008 | 1. `c-pdp` submits V-01. 2. (hook) change a submitter's binding, scopes, or permissions: name "c-d2", patch {"scopes": ["trace.receipt.read"], "receipt_for": ["pdp-flee. 3. `c-d2` looks up `pdp-fleet-1` / V-01. | 1. `201`, receipt: idempotent_replay false, all four flags false. 3. `404` `RECEIPT_NOT_FOUND`. |
| L-09 | If receipt lookup offered; hooks: submitter bindings | LKP-A1, LKP-A3, ERR-EVIDENCE_DOMAIN_NOT_BOUND | 1. no token looks up `pdp-fleet-1` / V-01. 2. `c-recon` looks up `pdp-fleet-1` / V-01 (token `{"exp":"expired"}`). 3. (hook) change a submitter's binding, scopes, or permissions: name "c-nodom", patch {"scopes": ["trace.receipt.read"], "receipt_for": ["pdp-flee. 4. `c-nodom` looks up `pdp-fleet-1` / V-01. | 1. `401` `UNAUTHENTICATED`. 2. `401` `UNAUTHENTICATED`. 4. `403` `EVIDENCE_DOMAIN_NOT_BOUND`. |
| L-10 | If receipt lookup offered | LKP-D1, IDP-001, LKP-R1 | 1. `c-pdp` submits V-01. 2. `c-pdp` submits V-20. 3. `c-recon` looks up `pdp-fleet-1` / V-01. | 1. `201`, receipt: idempotent_replay false, all four flags false. 2. `409` `RECORD_ID_CONFLICT`. 3. `200`, receipt: receipt_id same as step 1, received_at same as step 1, all four flags false. |
| L-11 | If receipt lookup offered; hooks: Collector clock | LKP-N1, EXP-001 | 1. `c-pdp` submits V-01. 2. (hook) advance the Collector clock: seconds 34646400. 3. `c-recon` looks up `pdp-fleet-1` / V-01. | 1. `201`, receipt: idempotent_replay false, all four flags false. 3. `404` `RECEIPT_NOT_FOUND`. |
| L-12 | If receipt lookup offered | LKP-002, RID-R1 | 1. `c-pdp` submits V-26. 2. `c-recon` looks up `pdp%2Ffleet%201` / V-26. | 1. `201`, receipt: idempotent_replay false, all four flags false. 2. `200`, receipt present. |
| L-13 | If receipt lookup offered | LKP-008, LKP-007 | 1. `c-recon` looks up `pdp-fleet-1` / V-01. 2. `c-pdp` submits V-01. 3. `c-recon` looks up `pdp-fleet-1` / V-01. | 1. `404`, headers: Cache-Control no-store. 2. `201`, receipt: idempotent_replay false, all four flags false. 3. `200`, headers: Cache-Control private. |
| L-14 | If receipt lookup offered (SHOULD); hooks: rate limit | LKP-009 | 1. (hook) apply a request rate limit: max_requests 2. 2. `c-recon` looks up `pdp-fleet-1` / V-01. 3. `c-recon` looks up `pdp-fleet-1` / V-01. 4. `c-recon` looks up `pdp-fleet-1` / V-01. | 2. `404`. 3. `404`. 4. `429` `RATE_LIMITED`, retryable true, headers: Retry-After present. |
| L-15 | If receipt lookup offered | LKP-001, CO-1 | 1. `c-fwd` submits V-01. 2. `c-recon` looks up `pdp-fleet-1` / V-01. | 1. `201`, receipt: idempotent_replay false, all four flags false. 2. `200`, receipt: receipt_id same as step 1, received_at same as step 1, all four flags false. |

#### Bulk submission (B-*)

| ID | Applies | Requirements | Procedure | Expected |
|---|---|---|---|---|
| B-01 | If Collector-Bulk (bulk endpoint offered) | BLR-001, BLP-001, BLP-R1, BLP-003, VAL-07, ERR-SIGNATURE_INVALID, BLK-001 | 1. `c-pdp` submits a batch [V-01, V-10, V-02]. | 1. `200`, results [0] accepted; [1] SIGNATURE_INVALID (400); [2] accepted. |
| B-02 | If Collector-Bulk (bulk endpoint offered) | BLK-002, BLK-E6, ERR-BATCH_MIXED_PRODUCERS | 1. `c-fwd` submits a batch [V-01, V-03]. 2. inspect count. | 1. `400` `BATCH_MIXED_PRODUCERS`. 2. count 0. |
| B-03 | If Collector-Bulk (bulk endpoint offered) | BLK-E3, ERR-BATCH_EMPTY, BLK-001 | 1. `c-pdp` submits a batch []. | 1. `400` `BATCH_EMPTY`. |
| B-04 | If Collector-Bulk (bulk endpoint offered) | BLK-001, BLK-E4, LIM-BATCHRECORDS, ERR-BATCH_TOO_MANY_RECORDS, DSM-021 | 1. `c-pdp` submits a batch an array of max_batch_records + 1 elements. 2. inspect count. | 1. `400` `BATCH_TOO_MANY_RECORDS`. 2. count 0. |
| B-05 | If Collector-Bulk (bulk endpoint offered) | BLK-E5, LIM-BATCHBYTES, ERR-REQUEST_TOO_LARGE | 1. `c-pdp` submits a batch an array padded to max_batch_bytes + 1 bytes. 2. inspect count. | 1. `413` `REQUEST_TOO_LARGE`. 2. count 0. |
| B-06 | If Collector-Bulk (bulk endpoint offered) | BLT-M1, BLT-M2, IDP-T1, BLT-002 | 1. `c-pdp` submits a batch [V-01, V-10, V-02]. 2. `c-pdp` submits a batch [V-01, V-10, V-02]. | 1. `200`, results [0] accepted; [1] SIGNATURE_INVALID; [2] accepted. 2. `200`, results [0] accepted, replay; [1] SIGNATURE_INVALID; [2] accepted, replay. |
| B-07 | If Collector-Bulk (bulk endpoint offered) | BLP-003, IDP-T1 | 1. `c-pdp` submits a batch [V-01, V-01]. | 1. `200`, results [0] accepted; [1] accepted, replay. |
| B-08 | If Collector-Bulk (bulk endpoint offered) | BLP-003, IDP-001, VAL-08 | 1. `c-pdp` submits a batch [V-01, V-20]. | 1. `200`, results [0] accepted; [1] RECORD_ID_CONFLICT (409). |
| B-09 | If Collector-Bulk (bulk endpoint offered) | BLO-002, CHN-R2, FLG-COVERAGE_GAP | 1. `c-pdp` submits a batch [V-02, V-01]. | 1. `200`, results [0] accepted, gap flag set; [1] accepted. |
| B-10 | If Collector-Bulk (bulk endpoint offered) | BLP-001, VAL-05, ERR-RECORD_TOO_LARGE, ORD-S08 | 1. `c-pdp` submits a batch [V-01, a generated copy of V-01 that is max_record_bytes + 1 bytes, V-02]. | 1. `200`, results [0] accepted; [1] RECORD_TOO_LARGE (413); [2] accepted. |
| B-11 | If Collector-Bulk (bulk endpoint offered) | BLP-R2, VAL-04, ERR-SCHEMA_INVALID | 1. `c-pdp` submits a batch [V-01, the JSON value `42`]. | 1. `200`, results [0] accepted; [1] SCHEMA_INVALID (400). |
| B-12 | If Collector-Bulk (bulk endpoint offered) | BLK-E7, ERR-SUBMITTER_NOT_AUTHORIZED | 1. `c-pep` submits a batch [V-01]. | 1. `403` `SUBMITTER_NOT_AUTHORIZED`. |
| B-13 | If Collector-Bulk (bulk endpoint offered); hooks: fault injection at the commit point | BLP-001, BLP-002, VAL-09, ERR-COLLECTOR_UNAVAILABLE | 1. (hook) make the next durable commit fail: count 1. 2. `c-pdp` submits a batch [V-01, V-02]. | 2. `200`, results [0] COLLECTOR_UNAVAILABLE (503); [1] accepted, gap flag set. |
| B-14 | If Collector-Bulk (bulk endpoint offered) | BLR-001, BLK-E8 | 1. `c-pdp` submits a batch [V-01, V-02]. | 1. `200`, results [0] accepted; [1] accepted. |
| B-15 | If Collector-Bulk (bulk endpoint offered) | BLR-001 | 1. `c-pdp` submits a batch [V-02, V-01]. | 1. `200`, results [0] accepted, gap flag set; [1] accepted. |
| B-16 | If Collector-Bulk (bulk endpoint offered) | BLP-R3, VAL-01, BLK-E1, ORD-S06A, JSN-002, JSN-L2 | 1. `c-pdp` submits a batch [V-02, V-18]. 2. inspect count. | 1. `400` `MALFORMED_JSON`. 2. count 0. |
| B-17 | If Collector-Bulk (bulk endpoint offered) | VAL-01, BLK-E1, JSN-001 | 1. `c-pdp` submits a batch V-01 cut after 40 characters. 2. inspect count. | 1. `400` `MALFORMED_JSON`. 2. count 0. |
| B-18 | If Collector-Bulk (bulk endpoint offered) | BLK-E2, ERR-BATCH_NOT_ARRAY, VAL-02 | 1. `c-pdp` submits a batch V-01. | 1. `400` `BATCH_NOT_ARRAY`. |
| B-19 | If Collector-Bulk (bulk endpoint offered) | JSN-L1, VAL-01, BLP-R3 | 1. `c-pdp` submits a batch [V-01, V-02 with an invalid UTF-8 byte]. 2. inspect count. | 1. `400` `MALFORMED_JSON`. 2. count 0. |
| B-20 | If Collector-Bulk (bulk endpoint offered) | JSN-L4, LIM-DEPTH, VAL-01 | 1. `c-pdp` submits a batch [V-01, a generated copy of V-02 nested 40 levels deep]. 2. inspect count. | 1. `400` `MALFORMED_JSON`. 2. count 0. |
| B-21 | If Collector-Bulk (bulk endpoint offered) | BLK-002, VAL-04 | 1. `c-fwd` submits a batch [V-01, the JSON value `42`, V-03]. 2. `c-fwd` submits a batch [V-01, the JSON value `42`, V-02]. | 1. `400` `BATCH_MIXED_PRODUCERS`. 2. `200`, results [0] accepted; [1] SCHEMA_INVALID; [2] accepted. |
| B-22 | If Collector-Bulk (bulk endpoint offered) | VAL-04, VAL-07, BLP-001 | 1. `c-pdp` submits a batch [V-01, V-25, V-10, V-02]. | 1. `200`, results [0] accepted; [1] SCHEMA_INVALID; [2] SIGNATURE_INVALID; [3] accepted. |
| B-23 | If `bulk_mixed_producers_supported` true | DSM-011, BLK-002, VAL-06, BLP-001 | 1. `c-fwd` submits a batch [V-01, V-03, V-13]. | 1. `200`, results [0] accepted; [1] accepted; [2] SUBMITTER_NOT_AUTHORIZED (403). |
| B-24 | If bulk endpoint not offered | OVR-001, DSM-021 | 1. read the metadata. | 1. `200`, absent: trace_bulk_ingestion_endpoint, max_batch_bytes, max_batch_records. |
| B-25 | If Collector-Bulk (bulk endpoint offered); hooks: fault injection (storage down) | BLR-002, BLR-003 | 1. (hook) set a Collector configuration value: name "storage_down", value true. 2. `c-pdp` submits a batch [V-01, V-02]. 3. inspect count. | 2. `503` `COLLECTOR_UNAVAILABLE`, retryable true, headers: Retry-After present. 3. count 0. |

#### Discovery (D-*)

| ID | Applies | Requirements | Procedure | Expected |
|---|---|---|---|---|
| D-01 | Mandatory | DSC-R1, DSM-001, DSM-002, DSM-003, DSM-004, DSM-005, DSM-007, DSM-009, DSM-013, DSM-017 | 1. read the metadata. | 1. `200`, present: issuer, api_versions_supported, trace_ingestion_endpoint, trace_profiles, authorization_servers, ingestion_scope, max_record_bytes, idempotency_retention_seconds, producer_chain_registration_modes_supported. |
| D-02 | Mandatory | DSM-001 | 1. read the metadata. | 1. `200`, issuer = the Collector's issuer. |
| D-03 | If Collector-Bulk (bulk endpoint offered) | DSM-003, DSC-R1 | 1. read the metadata. | 1. `200`, present: trace_bulk_ingestion_endpoint, max_batch_bytes, max_batch_records. |
| D-05 | Mandatory | DSP-001, PRF-005, ERR-UNSUPPORTED_PROFILE | 1. read the metadata. 2. `c-pdp` submits V-15. 3. `c-pdp` submits V-01. | 1. `200`, present: trace_profiles. 2. `400` `UNSUPPORTED_PROFILE`. 3. `201`, receipt: idempotent_replay false, all four flags false. |
| D-06 | Mandatory | DSA-001, DSA-002, DSM-005, DSA-005 | 1. read the metadata. | 1. `200`, each authorization server entry has issuer and token_format. |
| D-07 | Mandatory | PRV-005, DSC-001 | 1. read the metadata. | 1. `200`, no tenant, client, producer, or key names. |
| D-08 | Mandatory | ADM-001, DSM-013, ADM-M1, ADM-M2, ADM-M3 | In each variant M1, M2, M3: 1. read the metadata. | 1. `200`, present: producer_chain_registration_modes_supported. *Run with the G-* tests for the variant that the metadata describes.* |
| D-09 | Mandatory | DSP-001, DSP-002, DSP-003, DSP-004, DSM-004, DSP-006 | 1. read the metadata. | 1. `200`, each profile entry has its cryptographic members. |
| D-10 | If more than one profile listed; inspection; hooks: second profile | DSP-009 | Configure a second profile with a different suite. Submit one valid record for each. | Each record is verified only with its own profile's entry. Neither profile's algorithms are used for the other. |
| D-11 | Mandatory | ASY-004, ASY-005, ASY-002, DSM-014, RCP-007 | 1. read the metadata. 2. `c-pdp` submits V-01. 3. `c-pdp` submits V-01. | 1. `200`, synchronous_integrity_flags true. 2. `201`, receipt: idempotent_replay false, all four flags false. 3. `200`. |
| D-12 | Mandatory | RET-002, RET-006, DSM-017, DSM-018 | 1. read the metadata. | 1. `200`, idempotency_retention_seconds at least 86400, the two profile lists do not overlap. |
| D-13 | If `synchronous_integrity_flags` false or absent | ASY-002, DSM-014 | 1. read the metadata. 2. `c-pdp` submits V-01. 3. `c-pdp` submits V-01. | 1. `200`, synchronous_integrity_flags false. 2. `201`. 3. `200`. |
| D-14 | Mandatory | DSM-009, DSM-021, LIM-RECORD, DSM-022 | 1. read the metadata. 2. `c-pdp` submits a generated copy of V-01 that is max_record_bytes + 1 bytes. | 1. `200`, max_record_bytes 262144. 2. `413` `RECORD_TOO_LARGE`. |

#### Producer behavior (P-*)

| ID | Applies | Requirements | Procedure | Expected |
|---|---|---|---|---|
| P-01 | Mandatory | SIG-001, PRF-001 | Verify a producer's output with the public key, using the producer's profile. | The signature verifies as the profile defines; kid is inside the signed scope; the encoding is the profile's. |
| P-02 | Mandatory | RID-001, RID-003 | Generate 10,000 records. | Every record_id is a lowercase UUID or an uppercase ULID, and is unique for the producer. |
| P-03 | Mandatory (SHOULD) | RCP-003, DIG-R2 | Compare the producer's own content_digest with the receipt's. | Equal, or the producer reports a mismatch. |
| P-04 | Mandatory | RTY-003, SUB-001, BLT-002 | A stub returns 503 twice, then 201. | The producer resubmits identical bytes with increasing delays and records success only after the 201. |
| P-05 | Mandatory | RTY-004 | A stub returns 429 with Retry-After: 2. | The producer waits at least 2 seconds. |
| P-06 | Mandatory | RTY-001, BLT-M2 | A stub returns a terminal 400. | The producer does not resubmit unchanged and surfaces the code. |
| P-07 | Mandatory | RTY-003, BLT-002 | A stub drops the connection after reading the request. | The producer resubmits the same bytes. |
| P-08 | Mandatory (SHOULD) | RTY-006 | Restart the producer with unacknowledged records. | The records are resubmitted from durable storage, or the producer's documentation states that it does not buffer durably. |
| P-09 | Mandatory | LIM-003, BLK-002, WIR-003 | Metadata states small limits and no mixed producers. | The producer's requests respect them. |
| P-10 | Mandatory | RTY-007 | Fix a rejected record. | The corrected record has a new record_id. Changed content is never resubmitted under the old one. |
| P-11 | Mandatory | PRV-001 | Inspect produced records. | No raw bearer tokens or credentials. |
| P-12 | Mandatory | COR-001 | The producer has no correlation pair for an event while the Collector requires it. | The producer does not submit, or reports the condition. It does not invent values. |
| P-13 | If receipt lookup offered | RCN-T1, RCN-T2, RCN-T3, RCN-T4, RCN-T5, RCN-T6, LKP-D1, LKP-006, RCN-001 | A stub receipt endpoint returns: 200 with the producer's digest; 200 with a different digest; 404 within the retention period; 404 after it; 403. | The producer marks the first accepted and stops retrying; alerts on the second and does not mark it accepted; keeps the record and retries the lookup for the third; infers nothing for the fourth; treats the fifth as an access problem. |
| P-14 | Mandatory | SCO-004, DSC-005, DSC-004, RCP-012, RCP-010 | Metadata names a scope, adds an unknown member, and sets a cache lifetime. | The producer reads the scope from metadata, ignores unknown members, and re-reads after the cache lifetime. |
| P-15 | Mandatory | ASY-003 | Receive a receipt without the four flags. | The producer does not treat the absence as no finding. |
| P-16 | Mandatory | TRN-005 | Present a certificate for another host name, then one from an untrusted chain. | The client refuses both and sends no token. |
| P-17 | Mandatory | EXP-002, BRK-002 | Hold a record for longer than idempotency_retention_seconds, then resubmit. | The producer does not treat the resubmission as a replay and does not depend on the Collector for deduplication. |

#### Forwarder behavior (F-*)

| ID | Applies | Requirements | Procedure | Expected |
|---|---|---|---|---|
| F-01 | Mandatory | FW-3, FW-4 | Pass V-01, V-03, V-04, V-06 through the forwarder. | The canonical form, and therefore the content_digest, of each delivered record equals the source's. V-04 is not altered by re-encoding. |
| F-02 | Mandatory | FW-3, FW-7 | Pass V-10 through the forwarder. | It is delivered unchanged or surfaced, never repaired. The Collector returns SIGNATURE_INVALID. |
| F-03 | Mandatory | FW-2, FW-1 | Feed records for D1 and D2 through a forwarder with a credential per domain. | Each request uses the matching credential. No request mixes domains. |
| F-04 | Mandatory | FW-8, FW-9 | The Collector stub delays its response. | Before the receipt the forwarder reports at most custody upstream. After it, acceptance. |
| F-05 | Mandatory | FW-10, FW-11 | Kill the forwarder after it acknowledged custody, restart; the Collector stub fails twice before accepting. | Every record is delivered, and the Collector shows one receipt per record. |
| F-06 | Mandatory | FW-12, BLT-M2, KEY-013 | The Collector returns a terminal 400 for one record. | Not retried. Surfaced with code and record_id. A KEY_NOT_VALID rejection is kept for resubmission. |
| F-07 | Mandatory | FW-14, RTY-004, BLT-M3 | The Collector returns 429 with Retry-After and 503. | Backoff and Retry-After honored. |
| F-08 | Mandatory | FW-5 | Set conflicting producer identity and domain in transport metadata. | No effect on the submitted record, the credential used, or the Collector's decisions. |
| F-09 | Mandatory | FW-15, FW-1 | Metadata states limits and no mixed producers. | Batches respect them. The forwarder authenticates with its own credential. |
| F-10 | Mandatory | FW-13 | A broker-backed forwarder; the Collector is unavailable. | The consumer position does not advance. After recovery, delivery completes. |
| F-11 | Mandatory | FW-17 | Inspect forwarder logs. | No tokens, no record content. |
| F-12 | Mandatory (SHOULD) | FW-19 | Pass records through and ask the forwarder what it holds per record. | For each record: producer_id, record_id, content_digest, receipt_id, received_at. |
| F-13 | Mandatory | FW-6 | Offer the forwarder a record from a producer it is not permitted to forward for. | The forwarder does not submit it. |
| F-14 | Mandatory | FW-16 | Deliver a producer's chain to the forwarder in reverse order. | Delivery completes, in any order. |
| F-15 | Mandatory (SHOULD) | FW-18, BRK-002, BRK-003 | Hold records near idempotency_retention_seconds. | The forwarder alerts, and does not treat a later resubmission as a replay. |
| F-16 | Mandatory | FW-7 | Enable pre-verification and feed it a record with a bad signature. | It raises an alarm or discards visibly. It does not repair the record. |


### 15.7 Reporting

A report for a Collector lists, for each test, one of: `passed`, `failed`, `unverified` (a hook is missing), or `not applicable` (a capability is missing). It lists the capabilities and the variant. A claim of conformance requires that no mandatory test failed and states which mandatory tests were unverified.

### 15.8 Requirement coverage

The register holds 434 requirements: 359 mandatory, 34 recommended, 41 optional. By verification method: 351 by API test, 54 by behavioral test, 18 by inspection, 11 advisory.
Of the 349 mandatory requirements that a test can verify, 346 are mapped to at least one test and 3 are documented exceptions. The suite has 192 tests (117 mandatory, 75 conditional on a capability).

Coverage exceptions:

| Requirement | Reason |
|---|---|
| KEY-003 | inspection: a Collector may use one evaluation time or one per element. The difference shows only if a key expires during a batch, which an API test cannot arrange without a clock that advances inside one request. |
| SUB-002 | advisory: Location is optional. The binding sentence is a prohibition on clients depending on it. |
| ACC-003 | inspection: whether a Collector labels accepted records as settled or complete is a matter of its status vocabulary, not of an API response. |


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
- RFC 6749, RFC 6750: OAuth 2.0 and bearer tokens
- RFC 8259: JSON
- RFC 8414: OAuth 2.0 Authorization Server Metadata
- RFC 8446: TLS 1.3
- RFC 8615: Well-known URIs
- RFC 9110: HTTP Semantics
- RFC 9457: Problem Details for HTTP APIs
- RFC 9562: UUIDs
- TRACE record profile `tag:govops.owasp.org,2026:trace-v1` (`govops-trace-profile.md`)

### 17.2 Informative

- RFC 4648, RFC 8032, RFC 8785: base64url, Ed25519, and JSON Canonicalization Scheme. They are used by the GovOps v1 profile. This API does not require them.
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

Asynchronous Collector (`synchronous_integrity_flags` false or absent). The four flag members are omitted, and an absent flag does not mean "no finding":

```http
HTTP/1.1 201 Created
Content-Type: application/json

{"accepted":true,"producer_id":"pdp-fleet-1","record_id":"0191f3a0-7b1e-7c2a-9d41-3a2f7b0c9d41","content_digest":"sha256:c849281f3c5ef69a204c28cf8a3036092b159ffa782b2bee11d3513fd4455226","receipt_id":"108422","received_at":"2026-06-11T00:42:23.456Z","idempotent_replay":false}
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

### A.9 Unregistered chain under a registered-only Collector (vector V-04)

```http
HTTP/1.1 400 Bad Request
Content-Type: application/problem+json

{"type":"https://govops.owasp.org/trace/errors/chain-not-registered","title":"The record's producer chain is not registered","status":400,"code":"CHAIN_NOT_REGISTERED","retryable":false,"producer_id":"pdp-fleet-1","record_id":"0191f3a0-7b2a-72e6-93ad-06e5d9c2b3ad"}
```

The Collector lists only `pre_registered_genesis`. After an administrator registers `chain-pdp-001-u`, the same bytes are accepted with `201`.

### A.10 Storage unavailable

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
    and verify a record. Signature algorithms, canonicalization, and content-digest construction are
    defined by the record's profile and advertised per profile in Collector metadata.
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
                asynchronous:
                  summary: Collector that does not assess chains at acceptance. The four flags are omitted.
                  value:
                    accepted: true
                    producer_id: pdp-fleet-1
                    record_id: 0191f3a0-7b1e-7c2a-9d41-3a2f7b0c9d41
                    content_digest: sha256:c849281f3c5ef69a204c28cf8a3036092b159ffa782b2bee11d3513fd4455226
                    receipt_id: '108422'
                    received_at: '2026-06-11T00:42:23.456Z'
                    idempotent_replay: false
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
  /api/v1/audit/trace/receipts/{producer_id}/{record_id}:
    get:
      tags: [Ingestion]
      operationId: getAcceptanceReceipt
      summary: Look up an acceptance receipt (optional)
      description: |
        Optional. Returns the receipt stored when the record was accepted, so a producer that submitted
        through an intermediary can reconcile. Requires the receipt scope and a per-producer receipt-read
        permission (specification section 7.3.1). A 404 does not mean the record was rejected.
      security:
        - oauth2: [trace.receipt.read]
        - bearerAuth: []
      parameters:
        - name: producer_id
          in: path
          required: true
          description: The signed producer identifier, percent-encoded.
          schema: {type: string, minLength: 1}
        - name: record_id
          in: path
          required: true
          description: The producer-generated record identifier (lowercase UUID or uppercase ULID).
          schema:
            type: string
            oneOf:
              - pattern: '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
              - pattern: '^[0-9A-HJKMNP-TV-Z]{26}$'
      responses:
        '200':
          description: The stored receipt. `idempotent_replay` is omitted because a lookup is not a submission.
          headers:
            Cache-Control:
              schema: {type: string}
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/StoredReceipt'
              examples:
                stored:
                  value:
                    accepted: true
                    producer_id: pdp-fleet-1
                    record_id: 0191f3a0-7b1e-7c2a-9d41-3a2f7b0c9d41
                    content_digest: sha256:c849281f3c5ef69a204c28cf8a3036092b159ffa782b2bee11d3513fd4455226
                    receipt_id: '108422'
                    received_at: '2026-06-11T00:42:23.456Z'
        '401': {$ref: '#/components/responses/Unauthorized'}
        '403': {$ref: '#/components/responses/Forbidden'}
        '404':
          description: No receipt is retained for the identity in the caller's evidence domain. Not evidence of rejection.
          headers:
            Cache-Control:
              schema: {type: string}
          content:
            application/problem+json:
              schema: {$ref: '#/components/schemas/Problem'}
              examples:
                notfound:
                  value:
                    type: https://govops.owasp.org/trace/errors/receipt-not-found
                    title: No receipt is retained for this record
                    status: 404
                    code: RECEIPT_NOT_FOUND
                    retryable: true
        '429': {$ref: '#/components/responses/TooManyRequests'}
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
                    trace_profiles:
                      - profile: tag:govops.owasp.org,2026:trace-v1
                        signature_algorithms_supported: [Ed25519]
                        canonicalization: RFC8785
                        content_digest_algorithm: sha256
                        event_kinds_supported: [AUTHORIZATION_DECISION, CAPABILITY_INVOKED, RUNTIME_EFFECT]
                    authorization_servers:
                      - issuer: https://auth.example.org
                        token_format: jwt
                      - issuer: https://auth2.example.org
                        token_format: introspection
                        client_id_claim: client_id
                    sender_constrained_tokens_supported: [dpop]
                    ingestion_scope: trace.write
                    scopes_supported: [trace.write, trace.receipt.read]
                    trace_receipt_endpoint: https://collector.example.org/api/v1/audit/trace/receipts/{producer_id}/{record_id}
                    receipt_scope: trace.receipt.read
                    max_record_bytes: 262144
                    max_batch_bytes: 8388608
                    max_batch_records: 500
                    max_nesting_depth: 32
                    bulk_mixed_producers_supported: false
                    execution_correlation_required: true
                    producer_chain_registration_modes_supported: [first_observed_genesis, pre_registered_genesis]
                    idempotency_retention_seconds: 2592000
                    synchronous_integrity_flags: true
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
            trace.receipt.read: Look up acceptance receipts.
    bearerAuth:
      type: http
      scheme: bearer
      description: |
        OAuth 2.0 access token (RFC 6750). A conforming Collector must accept JWT access tokens (RFC 9068) as
        bearer tokens. The submitter identity is derived as (issuer, client_id) (specification section 4.2.2).
        Tokens with a cnf claim must not be accepted as plain bearer tokens. Sender-constrained tokens
        (RFC 9449, RFC 8705) are RECOMMENDED.
  headers:
    RetryAfter:
      description: Seconds to wait before retrying, or an HTTP-date.
      schema:
        type: string
  responses:
    BadRequest:
      description: Request-level failure. The body is not a valid JSON document, or the single-record body is not an object, or the batch envelope is invalid. Nothing was processed. (Element-level failures in a batch appear in the 200 response instead.)
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
              description: Predecessor digest, or the sentinel the record's profile defines for the first record of a chain.
              minLength: 1
          additionalProperties: true
        parent_record_ids:
          type: array
          items: {type: object}
        signature:
          type: string
          description: Signature value. Algorithm, input, and encoding are defined by the record's profile, not by this API.
          minLength: 1
      additionalProperties: true
    ReceiptCore:
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
      properties:
        accepted: {const: true}
        producer_id: {type: string}
        record_id: {type: string}
        content_digest:
          type: string
          pattern: '^[a-z0-9][a-z0-9-]*:[A-Za-z0-9_+/=.-]+$'
          description: "`<algorithm>:<value>`, constructed as the record's profile defines."
        receipt_id:
          type: string
          description: Opaque identifier, unique within the evidence domain, stable across replays.
        received_at:
          type: string
          format: date-time
          description: RFC 3339 UTC timestamp with millisecond precision, assigned by the Collector.
          pattern: '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$'
        idempotent_replay: {type: boolean}
        coverage_gap_flag:
          type: boolean
          description: |
            The record's predecessor was not held at acceptance. Present, with the other three flags, only if the Collector advertises
            synchronous_integrity_flags true. Absence means not assessed at acceptance, not false.
        chain_link_failure_flag:
          type: boolean
          description: |
            The predecessor's digest did not match, or the genesis sentinel was misused. Present, with the other three flags, only if the Collector advertises
            synchronous_integrity_flags true. Absence means not assessed at acceptance, not false.
        equivocation_flag:
          type: boolean
          description: |
            A different record already held the same chain position. Present, with the other three flags, only if the Collector advertises
            synchronous_integrity_flags true. Absence means not assessed at acceptance, not false.
        late_flag:
          type: boolean
          description: |
            The record arrived later than the Collector's lateness policy allows. Present, with the other three flags, only if the Collector advertises
            synchronous_integrity_flags true. Absence means not assessed at acceptance, not false.
        unattributed_flag: {type: boolean}
        chain_admission:
          type: string
          enum: [pre_registered_genesis, first_observed_genesis, linked_restart_genesis]
          description: OPTIONAL. How the record's producer chain was admitted (specification section 7.4.1).
        receipt_sequence:
          type: integer
          description: OPTIONAL. Position in a Collector-internal receipt chain, if one is exposed.
      additionalProperties: true
    AcceptanceReceipt:
      description: Receipt returned by a submission. It is the receipt core plus `idempotent_replay`.
      allOf:
        - $ref: '#/components/schemas/ReceiptCore'
        - type: object
          required: [idempotent_replay]
    StoredReceipt:
      description: Receipt returned by a lookup. It is the receipt core without `idempotent_replay`.
      allOf:
        - $ref: '#/components/schemas/ReceiptCore'
        - type: object
          properties:
            idempotent_replay: false
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
        - BATCH_NOT_ARRAY
        - BATCH_EMPTY
        - BATCH_MIXED_PRODUCERS
        - MALFORMED_JSON
        - SCHEMA_INVALID
        - UNSUPPORTED_PROFILE
        - MISSING_EXECUTION_CONTEXT
        - PRODUCER_IDENTITY_MISMATCH
        - SIGNATURE_MALFORMED
        - UNSUPPORTED_ALGORITHM
        - CHAIN_NOT_REGISTERED
        - KEY_UNKNOWN
        - KEY_NOT_VALID
        - EVENT_KIND_NOT_AUTHORIZED
        - SIGNATURE_INVALID
        - RECORD_ID_CONFLICT
        - RECEIPT_NOT_FOUND
        - RECEIPT_ACCESS_DENIED
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
        - trace_profiles
        - authorization_servers
        - ingestion_scope
        - max_record_bytes
        - idempotency_retention_seconds
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
        trace_receipt_endpoint:
          type: string
          description: URI Template (RFC 6570) with variables producer_id and record_id. Present only if receipt lookup is offered.
        receipt_scope:
          type: string
          description: Scope required by receipt lookup. Required if trace_receipt_endpoint is present. Differs from ingestion_scope.
        trace_bulk_ingestion_endpoint:
          type: string
          format: uri
          description: Absent if the Collector does not implement bulk submission.
        trace_profiles:
          type: array
          minItems: 1
          description: One entry per supported TRACE record profile, with that profile's cryptographic capabilities.
          items:
            type: object
            required: [profile, signature_algorithms_supported, canonicalization, content_digest_algorithm]
            properties:
              profile:
                type: string
                description: The `trace.eat_profile` value.
              signature_algorithms_supported:
                type: array
                minItems: 1
                items: {type: string}
              canonicalization:
                type: string
              content_digest_algorithm:
                type: string
              event_kinds_supported:
                type: array
                items: {type: string}
            additionalProperties: true
        authorization_servers:
          type: array
          minItems: 1
          description: |
            Trusted OAuth 2.0 authorization servers and their token profiles. A submitter identity is the pair
            (issuer, client_id) and is scoped to the issuing server (specification section 4.2.2).
          items:
            type: object
            required: [issuer, token_format]
            properties:
              issuer:
                type: string
                format: uri
                description: Issuer identifier. Metadata is discoverable per RFC 8414 or OpenID Connect Discovery.
              token_format:
                type: string
                enum: [jwt, introspection]
              client_id_claim:
                type: string
                default: client_id
                description: Claim or introspection member carrying the OAuth client identifier.
              scope_claim:
                type: string
                default: scope
            additionalProperties: true
        sender_constrained_tokens_supported:
          type: array
          items:
            type: string
            enum: [dpop, mtls]
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
          description: |
            Must contain first_observed_genesis or pre_registered_genesis. If first_observed_genesis is listed,
            records of unregistered chains are admitted. If only pre_registered_genesis is listed, they are
            rejected with CHAIN_NOT_REGISTERED (specification section 7.4.1).
          items:
            type: string
            enum: [first_observed_genesis, pre_registered_genesis, linked_restart_genesis]
        idempotency_retention_seconds:
          type: integer
          minimum: 86400
          description: Minimum period, in seconds from a record's received_at, for which replay data is retained (specification section 9.1).
        trace_profiles_replay_only:
          type: array
          items: {type: string}
          description: Profiles no longer accepted for new records but still answered for replay (specification section 9.2).
        synchronous_integrity_flags:
          type: boolean
          default: false
          description: True if every receipt carries the four integrity flags as evaluated at acceptance.
        acceptance_durability:
          type: string
          enum: [local_durable, replicated_durable]
        content_encodings_supported:
          type: array
          items: {type: string}
      additionalProperties: true
```

---

## Appendix C. Test vectors

The vectors are the inputs of the tests in §15.6. They belong to the profile `tag:govops.owasp.org,2026:trace-v1`, whose cryptographic suite is Ed25519 signatures, RFC 8785 (JCS) canonicalization, and SHA-256 content digests. The suite is the profile's, not the API's. The API behavior under test is independent of it, and a Collector that lists another profile needs equivalent vectors from that profile. The expected result for each vector is in the tests that use it (`tests.json`), because it depends on the submitter, the fixture, and the registration-mode variant. `vectors.json` is the authoritative form of this appendix.

### C.1 Test keys

All signatures were produced with the **non-production test keys below**. Their seeds are published on purpose so that implementations can regenerate and extend the vectors. Never register these keys outside a test deployment.

| Producer | `kid` | Ed25519 seed (hex) | Public key (JWK `x`) |
|---|---|---|---|
| `pdp-fleet-1` | `key-2026-01` | `ccb2538fd1c9bbc2a2d034662c4a220387c7a4eb62d3cfd3582a0e0aa183adcc` | `osMws01rURBEOGoaCDB5eFcNt7qw6sgH4y-ty1_WZ5A` |
| `payments-gateway-pep` | `pep-key-2026-01` | `b26864e6c1d517b2527e68873aad0c2ab04507b8022c6df52b19ee342055b3d7` | `hQZQSp0mtUu3bMyZ_DEH5rJ_rPLyOtpOAniT2swqaD8` |
| `pdp/fleet 1` | `key-sl-01` | `b906e232bcf65ca1ccefc4ef55a1ac936b9b7ed488537b6049a8d3395b606440` | `_X0MOS5dRVOYHCbzljFrtsZ7YprvnIcRz0tuHkHVwYs` |

Each seed is the SHA-256 of an ASCII label, `govops-trace-collector-test/<producer_id>/<kid>`. The public key JWK is `{"kty":"OKP","crv":"Ed25519","x":"<value>"}`. The registered event kinds of each key are in the fixture (§15.5).

### C.2 How the vectors were produced

A signed record is a JSON object whose signature input is `JCS(record without "signature")`. The signature is Ed25519 over those UTF-8 bytes, encoded as unpadded base64url. The `content_digest` is `sha256:` and the lowercase hex SHA-256 of `JCS(record including "signature")`. For these vectors, which contain only ASCII member names and string, integer, and null values, JCS output equals compact JSON with members sorted by name.

### C.3 Worked computation for V-01

Signing input (`JCS` of V-01 without `signature`):

```text
{"kid":"key-2026-01","parent_record_ids":[],"producer":"pdp-fleet-1","producer_chain":{"prev_record_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000","producer_chain_id":"chain-pdp-001-a","producer_id":"pdp-fleet-1","producer_instance_id":"pdp-001","sequence_number":1},"record_id":"0191f3a0-7b1e-7c2a-9d41-3a2f7b0c9d41","trace":{"eat_profile":"tag:govops.owasp.org,2026:trace-v1","event":{"decision":{"action":"Acme::Action::\"ApprovePayment\"","outcome":"ALLOW","resource_type":"Acme::Payment"},"tokens":[{"issuer":"https://accounts.example.org","jti":"9c9f2e77-9a3e-4b62-9a2a-2f6e6e2a9f3e","token_type":"access_token"}]},"event_kind":"AUTHORIZATION_DECISION","execution_authority":"payments-gateway","policy":{"bundle_hash":"sha256:6cd416d52176b7d2fb8132025f55a42443910cc8d9f2b3f1d19b98b090c2d928","policy_language":"cedar","policy_language_version":"4.4.0","policy_store_id":"https://example.org/policy-stores/payments","policy_store_version":"1.2.3"},"runtime":{"pdp_id":"pdp-001"},"signed_at":1781138542,"subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"trace_execution_id":"exec-123"}}
```

Signature (unpadded base64url, 86 characters):

```text
NCteOEnLP7tcVEuDJ95lgP_DFIaz3--j2nlcRQm-2nvOnsTTHdg-WVps3e-H4PD8qC5YEjMxi805YUTJ-sB6Bw
```

### C.4 Catalogue

| Vector | Description | `content_digest` | Signature | Used by |
|---|---|---|---|---|
| V-01 | Valid AUTHORIZATION_DECISION, genesis of chain chain-pdp-001-a, execution exec-123. | `sha256:c849281f3c5ef69a204c28cf8a3036092b159ffa782b2bee11d3513fd4455226` | valid | C-01, C-02, C-03, C-04, C-05, C-13, C-14, C-15, C-16, C-17, C-18, C-19, C-20, C-21, C-22, C-23, C-24, C-25, C-27, C-28, C-29, C-30, C-31, C-34, C-36, C-37, C-39, C-40, C-41, C-42, C-43, C-44, C-45, C-46, C-47, C-48, A-01, A-02, A-03, A-04, A-05, A-06, A-07, A-08, A-09, A-10, A-11, A-12, A-13, A-14, A-15, A-16, G-01, G-03, G-04, G-06, G-07, G-09, G-10, R-02, R-03, R-04, R-05, R-06, R-07, R-08, R-10, R-11, R-12, R-13, R-14, R-15, L-02, L-03, L-06, L-08, L-09, L-10, L-11, L-13, L-14, L-15, B-01, B-02, B-06, B-07, B-08, B-09, B-10, B-11, B-12, B-13, B-14, B-15, B-17, B-18, B-19, B-20, B-21, B-22, B-23, D-05, D-11, D-13, D-14, C-51, C-53, C-54, C-56, C-57, C-58, C-62, R-16, B-25 |
| V-02 | Valid AUTHORIZATION_DECISION, chain position 2 (prev_record_hash is V-01's digest), DENY, execution exec-124. | `sha256:ad48f69db6bf6f789871edf3dfe48f340174d9a30217cd2789f8a0e043c0ea00` | valid | C-14, C-28, C-35, C-41, C-42, A-16, G-04, G-09, G-10, R-07, R-08, R-13, R-15, L-04, L-07, B-01, B-06, B-09, B-10, B-13, B-14, B-15, B-16, B-19, B-20, B-21, B-22, C-58, B-25 |
| V-03 | Valid CAPABILITY_INVOKED from payments-gateway-pep, with an authorized parent edge to V-01. | `sha256:524391ac77a07ec35546d909f6c409c719fb25e52645c5cccb0332001a830259` | valid | C-22, C-34, L-07, B-02, B-21, B-23 |
| V-04 | Valid record whose token issuer contains non-ASCII characters. Genesis of unregistered chain chain-pdp-001-u. | `sha256:08c257582502a1aaf4ebe4998f0825d7e1cebf4719df025f7eca524ee96ec3f8` | valid | G-01, G-03, G-06, R-12 |
| V-05 | Valid record with a signed top-level evidence_domain_id of D2. Chain chain-pdp-001-d. | `sha256:9b551c0889228cc656dc1c06774109db1280a2d00cc504b678ac9aeaafdb3703` | valid | C-26, G-05 |
| V-06 | V-01 re-serialized: top-level members reversed, 4-space indent. Same content_digest as V-01. | `sha256:c849281f3c5ef69a204c28cf8a3036092b159ffa782b2bee11d3513fd4455226` | valid | C-03 |
| V-10 | V-01 with decision.outcome changed after signing. | `sha256:18d3299c8687ec745d31e2d623fccdeaa4943a14324040e010a4877a41daccdc` | invalid | C-05, C-20, C-29, G-07, L-05, B-01, B-06, B-22 |
| V-11 | Correctly signed; kid key-unknown is not registered. | `sha256:43fa6feb87e21d6fae0995203e66c9da95e2db97376e201c99d7222effae36ff` | valid | C-06, C-29 |
| V-12 | CAPABILITY_INVOKED signed by the key authorized only for AUTHORIZATION_DECISION. | `sha256:2ca30e9dfb43324e0b05bc400928f3e8a867cad7fbfa76e06e2992b15a21a5d1` | valid | C-07 |
| V-13 | Correctly signed; producer is pdp-fleet-2 while producer_chain.producer_id is pdp-fleet-1. | `sha256:6af9f01925b9393370ca355dad6e77eb51b0ebd35b17bf3c4f1df002a895c6dc` | valid | C-08, B-23 |
| V-14 | Correctly signed AUTHORIZATION_DECISION without trace.execution_authority. | `sha256:6af35ff77ffe05568317668070f0cee36b97acb7524a1fdaad8f66a1e3ceccc5` | valid | C-09, C-55 |
| V-15 | Correctly signed; trace.eat_profile is not a listed profile. | `sha256:af480fa986d20ef421743345cb98a3931d69636a90b683ef7ac790a17e1de77a` | valid | C-10, D-05 |
| V-16 | V-01 with == appended to signature. | `sha256:7d389becea1c9c863b895307d0eca3b70c9adacc3192f0230fbea283771e1155` | invalid | C-11 |
| V-17 | Correctly signed; record_id is payment-42. | `sha256:3e46557e098e0d8c0e6e391bd8bc3dacf039e1584187baf951d6df18a90514f4` | valid | C-12 |
| V-18 | Raw text of V-01 with an extra leading record_id member (duplicate member name). | none (not strict JSON) | not applicable | C-13, B-16 |
| V-20 | Same identity as V-01, different signed_at, correctly re-signed. | `sha256:2c92043b1d3c70516d452af46d7987c22701fb4b81133e8f92b4c6e83aa92e99` | valid | C-04, C-45, R-05, L-10, B-08 |
| V-21 | Different record_id, same chain position as V-01, DENY, correctly signed. | `sha256:e634e8fbca1417a231b2d0db0f6fd963912624bf820bab5d38f54041ffdaeb88` | valid | C-16, C-36 |
| V-22 | Chain chain-pdp-001-a position 2, prev_record_hash is sha256 of 64 a, correctly signed. | `sha256:b766ca6d5cffc7bd574dbe41c27d980e375349038bde7ae338261877f2b24be6` | valid | C-15, C-36 |
| V-23 | Chain chain-pdp-001-a position 2 carrying the genesis sentinel, correctly signed. | `sha256:7ff0a3bfed8237ab450492bda7f6015e63372f963e32729fe82e4f2add60826b` | valid | G-08 |
| V-24 | Unregistered chain chain-pdp-001-x position 3, correctly signed. | `sha256:ea21a940266e5ba7db4909276fd5b6e9ed1dd5d0adebdb18d2ba689d68636c08` | valid | G-02, G-03 |
| V-25 | Correctly signed record that has no trace member. Chain chain-pdp-001-n. | `sha256:0daef1c498d31f720654cecf260a178dadd026f2b21ea425c97f55fc1f2e840a` | valid | C-50, B-22 |
| V-26 | Valid record from producer 'pdp/fleet 1' (reserved characters in producer_id), key key-sl-01. | `sha256:896a49db43047eae11ff5a408faf10d7267ce83407a15d8e76ac417a386ae88c` | valid | C-49, L-12 |

### C.5 Content

#### V-01

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

```json
{"producer":"pdp-fleet-1","kid":"key-2026-01","record_id":"0191f3a0-7b1f-7d3b-8e52-4b3a8c1d0e52","trace":{"eat_profile":"tag:govops.owasp.org,2026:trace-v1","event_kind":"AUTHORIZATION_DECISION","signed_at":1781138600,"trace_execution_id":"exec-124","execution_authority":"payments-gateway","subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"event":{"decision":{"action":"Acme::Action::\"ApprovePayment\"","resource_type":"Acme::Payment","outcome":"DENY"},"tokens":[{"issuer":"https://accounts.example.org","token_type":"access_token","jti":"9c9f2e77-9a3e-4b62-9a2a-2f6e6e2a9f3e"}]},"policy":{"policy_store_id":"https://example.org/policy-stores/payments","policy_store_version":"1.2.3","policy_language":"cedar","policy_language_version":"4.4.0","bundle_hash":"sha256:6cd416d52176b7d2fb8132025f55a42443910cc8d9f2b3f1d19b98b090c2d928"},"runtime":{"pdp_id":"pdp-001"}},"producer_chain":{"producer_id":"pdp-fleet-1","producer_instance_id":"pdp-001","producer_chain_id":"chain-pdp-001-a","sequence_number":2,"prev_record_hash":"sha256:c849281f3c5ef69a204c28cf8a3036092b159ffa782b2bee11d3513fd4455226"},"parent_record_ids":[],"signature":"Hc-B-e4FnlHykEQQrVUAdRh2GGjcsFsuyGdYpoP_FD4rZAH28wmh_k0lUBo9l5NCt0QX6IhBfRtU-ZHC7U3CCg"}
```

#### V-03

```json
{"producer":"payments-gateway-pep","kid":"pep-key-2026-01","record_id":"0191f3a0-7b20-7e4c-9f63-5c4b9d2e1f63","trace":{"eat_profile":"tag:govops.owasp.org,2026:trace-v1","event_kind":"CAPABILITY_INVOKED","signed_at":1781138543,"trace_execution_id":"exec-123","execution_authority":"payments-gateway","subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"event":{"invocation":{"action":"Acme::Action::\"ApprovePayment\"","resource_type":"Acme::Payment","outcome":"SUCCESS"},"enforcement_point_id":"payments-gateway-01"}},"producer_chain":{"producer_id":"payments-gateway-pep","producer_instance_id":"payments-gateway-01","producer_chain_id":"chain-pep-01","sequence_number":1,"prev_record_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"parent_record_ids":[{"producer_id":"pdp-fleet-1","record_id":"0191f3a0-7b1e-7c2a-9d41-3a2f7b0c9d41","relationship_type":"authorized"}],"signature":"q9dnOcAHXqAJ4pdTfvLghlvqgCWZlJD0vzuostJ702mogKd6xBC5Oml68FzV1otp85MXoa6VmlFLf0KnfkYQAw"}
```

#### V-04

```json
{"producer":"pdp-fleet-1","kid":"key-2026-01","record_id":"0191f3a0-7b2a-72e6-93ad-06e5d9c2b3ad","trace":{"eat_profile":"tag:govops.owasp.org,2026:trace-v1","event_kind":"AUTHORIZATION_DECISION","signed_at":1781138542,"trace_execution_id":"exec-123","execution_authority":"payments-gateway","subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"event":{"decision":{"action":"Acme::Action::\"ApprovePayment\"","resource_type":"Acme::Payment","outcome":"ALLOW"},"tokens":[{"issuer":"https://accounts.example.org/café/🔒","token_type":"access_token","jti":"9c9f2e77-9a3e-4b62-9a2a-2f6e6e2a9f3e"}]},"policy":{"policy_store_id":"https://example.org/policy-stores/payments","policy_store_version":"1.2.3","policy_language":"cedar","policy_language_version":"4.4.0","bundle_hash":"sha256:6cd416d52176b7d2fb8132025f55a42443910cc8d9f2b3f1d19b98b090c2d928"},"runtime":{"pdp_id":"pdp-001"}},"producer_chain":{"producer_id":"pdp-fleet-1","producer_instance_id":"pdp-001","producer_chain_id":"chain-pdp-001-u","sequence_number":1,"prev_record_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"parent_record_ids":[],"signature":"IK-jMuQaJKkbYLbrrPxPUm8Oc9zZtaAx10PNzSvVr-YOK_8_nHYrzA5rjJIAaaizJcjkUBvCZ4zBDUB5xpx0Bw"}
```

#### V-05

```json
{"producer":"pdp-fleet-1","kid":"key-2026-01","record_id":"0191f3a0-7b2b-73f7-84be-17f6ead3c4be","trace":{"eat_profile":"tag:govops.owasp.org,2026:trace-v1","event_kind":"AUTHORIZATION_DECISION","signed_at":1781138542,"trace_execution_id":"exec-123","execution_authority":"payments-gateway","subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"event":{"decision":{"action":"Acme::Action::\"ApprovePayment\"","resource_type":"Acme::Payment","outcome":"ALLOW"},"tokens":[{"issuer":"https://accounts.example.org","token_type":"access_token","jti":"9c9f2e77-9a3e-4b62-9a2a-2f6e6e2a9f3e"}]},"policy":{"policy_store_id":"https://example.org/policy-stores/payments","policy_store_version":"1.2.3","policy_language":"cedar","policy_language_version":"4.4.0","bundle_hash":"sha256:6cd416d52176b7d2fb8132025f55a42443910cc8d9f2b3f1d19b98b090c2d928"},"runtime":{"pdp_id":"pdp-001"}},"producer_chain":{"producer_id":"pdp-fleet-1","producer_instance_id":"pdp-001","producer_chain_id":"chain-pdp-001-d","sequence_number":1,"prev_record_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"parent_record_ids":[],"evidence_domain_id":"D2","signature":"ie6m4ml8UN9b4WfMOI0_e4g0mU0V0GlsuPR3O4DmMr87GLBfRMFXd95F2WROsVC6R7NLQD7aquHlz5Xg2AieBw"}
```

#### V-06

```text
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

```json
{"producer":"pdp-fleet-1","kid":"key-2026-01","record_id":"0191f3a0-7b1e-7c2a-9d41-3a2f7b0c9d41","trace":{"eat_profile":"tag:govops.owasp.org,2026:trace-v1","event_kind":"AUTHORIZATION_DECISION","signed_at":1781138542,"trace_execution_id":"exec-123","execution_authority":"payments-gateway","subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"event":{"decision":{"action":"Acme::Action::\"ApprovePayment\"","resource_type":"Acme::Payment","outcome":"DENY"},"tokens":[{"issuer":"https://accounts.example.org","token_type":"access_token","jti":"9c9f2e77-9a3e-4b62-9a2a-2f6e6e2a9f3e"}]},"policy":{"policy_store_id":"https://example.org/policy-stores/payments","policy_store_version":"1.2.3","policy_language":"cedar","policy_language_version":"4.4.0","bundle_hash":"sha256:6cd416d52176b7d2fb8132025f55a42443910cc8d9f2b3f1d19b98b090c2d928"},"runtime":{"pdp_id":"pdp-001"}},"producer_chain":{"producer_id":"pdp-fleet-1","producer_instance_id":"pdp-001","producer_chain_id":"chain-pdp-001-a","sequence_number":1,"prev_record_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"parent_record_ids":[],"signature":"NCteOEnLP7tcVEuDJ95lgP_DFIaz3--j2nlcRQm-2nvOnsTTHdg-WVps3e-H4PD8qC5YEjMxi805YUTJ-sB6Bw"}
```

#### V-11

```json
{"producer":"pdp-fleet-1","kid":"key-unknown","record_id":"0191f3a0-7b23-7b7f-8c96-8f7ec25b4c96","trace":{"eat_profile":"tag:govops.owasp.org,2026:trace-v1","event_kind":"AUTHORIZATION_DECISION","signed_at":1781138542,"trace_execution_id":"exec-123","execution_authority":"payments-gateway","subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"event":{"decision":{"action":"Acme::Action::\"ApprovePayment\"","resource_type":"Acme::Payment","outcome":"ALLOW"},"tokens":[{"issuer":"https://accounts.example.org","token_type":"access_token","jti":"9c9f2e77-9a3e-4b62-9a2a-2f6e6e2a9f3e"}]},"policy":{"policy_store_id":"https://example.org/policy-stores/payments","policy_store_version":"1.2.3","policy_language":"cedar","policy_language_version":"4.4.0","bundle_hash":"sha256:6cd416d52176b7d2fb8132025f55a42443910cc8d9f2b3f1d19b98b090c2d928"},"runtime":{"pdp_id":"pdp-001"}},"producer_chain":{"producer_id":"pdp-fleet-1","producer_instance_id":"pdp-001","producer_chain_id":"chain-pdp-001-a","sequence_number":1,"prev_record_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"parent_record_ids":[],"signature":"k5HalDC95uWVrZWsnFS4UoXftCn6HsJX80scg8KJmbgM60BFPkD4qAlYhqgnoeF0VNUfB7RdGyFBj9VfFcbuDQ"}
```

#### V-12

```json
{"producer":"pdp-fleet-1","kid":"key-2026-01","record_id":"0191f3a0-7b24-7c80-9da7-a08fd36c5da7","trace":{"eat_profile":"tag:govops.owasp.org,2026:trace-v1","event_kind":"CAPABILITY_INVOKED","signed_at":1781138542,"trace_execution_id":"exec-123","execution_authority":"payments-gateway","subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"event":{"invocation":{"action":"Acme::Action::\"ApprovePayment\"","resource_type":"Acme::Payment","outcome":"SUCCESS"},"enforcement_point_id":"payments-gateway-01"}},"producer_chain":{"producer_id":"pdp-fleet-1","producer_instance_id":"pdp-001","producer_chain_id":"chain-pdp-001-a","sequence_number":1,"prev_record_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"parent_record_ids":[],"signature":"yzUFvKyF8UB-SCEht9Bs74o9o3rDPK44ki3a9ycSbjL6PhOx8aK1FarK2axdVxRuX68S4V4ex5NtSFBere7QCA"}
```

#### V-13

```json
{"producer":"pdp-fleet-2","kid":"key-2026-01","record_id":"0191f3a0-7b25-7d91-8eb8-b190e47d6eb8","trace":{"eat_profile":"tag:govops.owasp.org,2026:trace-v1","event_kind":"AUTHORIZATION_DECISION","signed_at":1781138542,"trace_execution_id":"exec-123","execution_authority":"payments-gateway","subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"event":{"decision":{"action":"Acme::Action::\"ApprovePayment\"","resource_type":"Acme::Payment","outcome":"ALLOW"},"tokens":[{"issuer":"https://accounts.example.org","token_type":"access_token","jti":"9c9f2e77-9a3e-4b62-9a2a-2f6e6e2a9f3e"}]},"policy":{"policy_store_id":"https://example.org/policy-stores/payments","policy_store_version":"1.2.3","policy_language":"cedar","policy_language_version":"4.4.0","bundle_hash":"sha256:6cd416d52176b7d2fb8132025f55a42443910cc8d9f2b3f1d19b98b090c2d928"},"runtime":{"pdp_id":"pdp-001"}},"producer_chain":{"producer_id":"pdp-fleet-1","producer_instance_id":"pdp-001","producer_chain_id":"chain-pdp-001-a","sequence_number":1,"prev_record_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"parent_record_ids":[],"signature":"LK7wACQiOCiPGyJ9SIJvljZzwJCwCe0RutFzZ3mRocG6F3uayAlSL5XTV0VZGxWfsEbZ7p9csvI2Uf5VwHb4CQ"}
```

#### V-14

```json
{"producer":"pdp-fleet-1","kid":"key-2026-01","record_id":"0191f3a0-7b26-7ea2-9fc9-c2a1f58e7fc9","trace":{"eat_profile":"tag:govops.owasp.org,2026:trace-v1","event_kind":"AUTHORIZATION_DECISION","signed_at":1781138542,"trace_execution_id":"exec-123","subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"event":{"decision":{"action":"Acme::Action::\"ApprovePayment\"","resource_type":"Acme::Payment","outcome":"ALLOW"},"tokens":[{"issuer":"https://accounts.example.org","token_type":"access_token","jti":"9c9f2e77-9a3e-4b62-9a2a-2f6e6e2a9f3e"}]},"policy":{"policy_store_id":"https://example.org/policy-stores/payments","policy_store_version":"1.2.3","policy_language":"cedar","policy_language_version":"4.4.0","bundle_hash":"sha256:6cd416d52176b7d2fb8132025f55a42443910cc8d9f2b3f1d19b98b090c2d928"},"runtime":{"pdp_id":"pdp-001"}},"producer_chain":{"producer_id":"pdp-fleet-1","producer_instance_id":"pdp-001","producer_chain_id":"chain-pdp-001-a","sequence_number":1,"prev_record_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"parent_record_ids":[],"signature":"wan8V-vehv0pTrWTML4QUpWxrDXLmwbs1Ci8ejD6TKLwKnRuSj3QIgvCBpEARWFmKK2d81_p9Cb5UY0oNW3fBg"}
```

#### V-15

```json
{"producer":"pdp-fleet-1","kid":"key-2026-01","record_id":"0191f3a0-7b27-7fb3-80da-d3b2a69f80da","trace":{"eat_profile":"tag:example.com,2026:other-v1","event_kind":"AUTHORIZATION_DECISION","signed_at":1781138542,"trace_execution_id":"exec-123","execution_authority":"payments-gateway","subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"event":{"decision":{"action":"Acme::Action::\"ApprovePayment\"","resource_type":"Acme::Payment","outcome":"ALLOW"},"tokens":[{"issuer":"https://accounts.example.org","token_type":"access_token","jti":"9c9f2e77-9a3e-4b62-9a2a-2f6e6e2a9f3e"}]},"policy":{"policy_store_id":"https://example.org/policy-stores/payments","policy_store_version":"1.2.3","policy_language":"cedar","policy_language_version":"4.4.0","bundle_hash":"sha256:6cd416d52176b7d2fb8132025f55a42443910cc8d9f2b3f1d19b98b090c2d928"},"runtime":{"pdp_id":"pdp-001"}},"producer_chain":{"producer_id":"pdp-fleet-1","producer_instance_id":"pdp-001","producer_chain_id":"chain-pdp-001-a","sequence_number":1,"prev_record_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"parent_record_ids":[],"signature":"AgxaodM3BzpGI81G5XRugRqM88t6GFJclk-tccCGymQCyjxG3tKZBQrhKmkVKCUgSx0I2EiioqvPZsvp-dWmAw"}
```

#### V-16

```json
{"producer":"pdp-fleet-1","kid":"key-2026-01","record_id":"0191f3a0-7b1e-7c2a-9d41-3a2f7b0c9d41","trace":{"eat_profile":"tag:govops.owasp.org,2026:trace-v1","event_kind":"AUTHORIZATION_DECISION","signed_at":1781138542,"trace_execution_id":"exec-123","execution_authority":"payments-gateway","subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"event":{"decision":{"action":"Acme::Action::\"ApprovePayment\"","resource_type":"Acme::Payment","outcome":"ALLOW"},"tokens":[{"issuer":"https://accounts.example.org","token_type":"access_token","jti":"9c9f2e77-9a3e-4b62-9a2a-2f6e6e2a9f3e"}]},"policy":{"policy_store_id":"https://example.org/policy-stores/payments","policy_store_version":"1.2.3","policy_language":"cedar","policy_language_version":"4.4.0","bundle_hash":"sha256:6cd416d52176b7d2fb8132025f55a42443910cc8d9f2b3f1d19b98b090c2d928"},"runtime":{"pdp_id":"pdp-001"}},"producer_chain":{"producer_id":"pdp-fleet-1","producer_instance_id":"pdp-001","producer_chain_id":"chain-pdp-001-a","sequence_number":1,"prev_record_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"parent_record_ids":[],"signature":"NCteOEnLP7tcVEuDJ95lgP_DFIaz3--j2nlcRQm-2nvOnsTTHdg-WVps3e-H4PD8qC5YEjMxi805YUTJ-sB6Bw=="}
```

#### V-17

```json
{"producer":"pdp-fleet-1","kid":"key-2026-01","record_id":"payment-42","trace":{"eat_profile":"tag:govops.owasp.org,2026:trace-v1","event_kind":"AUTHORIZATION_DECISION","signed_at":1781138542,"trace_execution_id":"exec-123","execution_authority":"payments-gateway","subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"event":{"decision":{"action":"Acme::Action::\"ApprovePayment\"","resource_type":"Acme::Payment","outcome":"ALLOW"},"tokens":[{"issuer":"https://accounts.example.org","token_type":"access_token","jti":"9c9f2e77-9a3e-4b62-9a2a-2f6e6e2a9f3e"}]},"policy":{"policy_store_id":"https://example.org/policy-stores/payments","policy_store_version":"1.2.3","policy_language":"cedar","policy_language_version":"4.4.0","bundle_hash":"sha256:6cd416d52176b7d2fb8132025f55a42443910cc8d9f2b3f1d19b98b090c2d928"},"runtime":{"pdp_id":"pdp-001"}},"producer_chain":{"producer_id":"pdp-fleet-1","producer_instance_id":"pdp-001","producer_chain_id":"chain-pdp-001-a","sequence_number":1,"prev_record_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"parent_record_ids":[],"signature":"yskjUWBEiA6JUq6a2IOJTXyG0xPSIZTGaYb3DeNtedxL9Vr_uz8GRLEhBSCTpKYqsS1B1ThA16fjPZyVjesXBg"}
```

#### V-18

```text
{"record_id":"0191f3a0-7b28-70c4-91eb-e4c3b7a091eb","kid":"key-2026-01","parent_record_ids":[],"producer":"pdp-fleet-1","producer_chain":{"prev_record_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000","producer_chain_id":"chain-pdp-001-a","producer_id":"pdp-fleet-1","producer_instance_id":"pdp-001","sequence_number":1},"record_id":"0191f3a0-7b1e-7c2a-9d41-3a2f7b0c9d41","signature":"NCteOEnLP7tcVEuDJ95lgP_DFIaz3--j2nlcRQm-2nvOnsTTHdg-WVps3e-H4PD8qC5YEjMxi805YUTJ-sB6Bw","trace":{"eat_profile":"tag:govops.owasp.org,2026:trace-v1","event":{"decision":{"action":"Acme::Action::\"ApprovePayment\"","outcome":"ALLOW","resource_type":"Acme::Payment"},"tokens":[{"issuer":"https://accounts.example.org","jti":"9c9f2e77-9a3e-4b62-9a2a-2f6e6e2a9f3e","token_type":"access_token"}]},"event_kind":"AUTHORIZATION_DECISION","execution_authority":"payments-gateway","policy":{"bundle_hash":"sha256:6cd416d52176b7d2fb8132025f55a42443910cc8d9f2b3f1d19b98b090c2d928","policy_language":"cedar","policy_language_version":"4.4.0","policy_store_id":"https://example.org/policy-stores/payments","policy_store_version":"1.2.3"},"runtime":{"pdp_id":"pdp-001"},"signed_at":1781138542,"subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"trace_execution_id":"exec-123"}}
```

#### V-20

```json
{"producer":"pdp-fleet-1","kid":"key-2026-01","record_id":"0191f3a0-7b1e-7c2a-9d41-3a2f7b0c9d41","trace":{"eat_profile":"tag:govops.owasp.org,2026:trace-v1","event_kind":"AUTHORIZATION_DECISION","signed_at":1781138999,"trace_execution_id":"exec-123","execution_authority":"payments-gateway","subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"event":{"decision":{"action":"Acme::Action::\"ApprovePayment\"","resource_type":"Acme::Payment","outcome":"ALLOW"},"tokens":[{"issuer":"https://accounts.example.org","token_type":"access_token","jti":"9c9f2e77-9a3e-4b62-9a2a-2f6e6e2a9f3e"}]},"policy":{"policy_store_id":"https://example.org/policy-stores/payments","policy_store_version":"1.2.3","policy_language":"cedar","policy_language_version":"4.4.0","bundle_hash":"sha256:6cd416d52176b7d2fb8132025f55a42443910cc8d9f2b3f1d19b98b090c2d928"},"runtime":{"pdp_id":"pdp-001"}},"producer_chain":{"producer_id":"pdp-fleet-1","producer_instance_id":"pdp-001","producer_chain_id":"chain-pdp-001-a","sequence_number":1,"prev_record_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"parent_record_ids":[],"signature":"Ij2gOeVkH_zlI2MPO1AkTkZ52JqGB4gpI6WpYsFueb3u2mKRahIqSZrAPpyypQkTBz78J28AQOSFlHdLGVvIAQ"}
```

#### V-21

```json
{"producer":"pdp-fleet-1","kid":"key-2026-01","record_id":"0191f3a0-7b21-7f5d-8a74-6d5ca03f2a74","trace":{"eat_profile":"tag:govops.owasp.org,2026:trace-v1","event_kind":"AUTHORIZATION_DECISION","signed_at":1781138542,"trace_execution_id":"exec-123","execution_authority":"payments-gateway","subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"event":{"decision":{"action":"Acme::Action::\"ApprovePayment\"","resource_type":"Acme::Payment","outcome":"DENY"},"tokens":[{"issuer":"https://accounts.example.org","token_type":"access_token","jti":"9c9f2e77-9a3e-4b62-9a2a-2f6e6e2a9f3e"}]},"policy":{"policy_store_id":"https://example.org/policy-stores/payments","policy_store_version":"1.2.3","policy_language":"cedar","policy_language_version":"4.4.0","bundle_hash":"sha256:6cd416d52176b7d2fb8132025f55a42443910cc8d9f2b3f1d19b98b090c2d928"},"runtime":{"pdp_id":"pdp-001"}},"producer_chain":{"producer_id":"pdp-fleet-1","producer_instance_id":"pdp-001","producer_chain_id":"chain-pdp-001-a","sequence_number":1,"prev_record_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"parent_record_ids":[],"signature":"2kT-JgZ7Gr9yu-X79ZG-noGZ49ZqtiFwvk_8sZbco4oAKsoG5d36oukQar5n7jYbQWPk_Wr6ITmnFop_2H2WCA"}
```

#### V-22

```json
{"producer":"pdp-fleet-1","kid":"key-2026-01","record_id":"0191f3a0-7b22-7a6e-9b85-7e6db14a3b85","trace":{"eat_profile":"tag:govops.owasp.org,2026:trace-v1","event_kind":"AUTHORIZATION_DECISION","signed_at":1781138542,"trace_execution_id":"exec-123","execution_authority":"payments-gateway","subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"event":{"decision":{"action":"Acme::Action::\"ApprovePayment\"","resource_type":"Acme::Payment","outcome":"ALLOW"},"tokens":[{"issuer":"https://accounts.example.org","token_type":"access_token","jti":"9c9f2e77-9a3e-4b62-9a2a-2f6e6e2a9f3e"}]},"policy":{"policy_store_id":"https://example.org/policy-stores/payments","policy_store_version":"1.2.3","policy_language":"cedar","policy_language_version":"4.4.0","bundle_hash":"sha256:6cd416d52176b7d2fb8132025f55a42443910cc8d9f2b3f1d19b98b090c2d928"},"runtime":{"pdp_id":"pdp-001"}},"producer_chain":{"producer_id":"pdp-fleet-1","producer_instance_id":"pdp-001","producer_chain_id":"chain-pdp-001-a","sequence_number":2,"prev_record_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"parent_record_ids":[],"signature":"IgZ05ki7o51YxBc0KUS3o_NkRqeOFGSt-P9Hl1pcHtkFgajFD9vnjEYCY9B6DJnIHrYNB45HZxVCoT5KIM1TBg"}
```

#### V-23

```json
{"producer":"pdp-fleet-1","kid":"key-2026-01","record_id":"0191f3a0-7b2c-74a8-95cf-28a7fbe4d5cf","trace":{"eat_profile":"tag:govops.owasp.org,2026:trace-v1","event_kind":"AUTHORIZATION_DECISION","signed_at":1781138542,"trace_execution_id":"exec-123","execution_authority":"payments-gateway","subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"event":{"decision":{"action":"Acme::Action::\"ApprovePayment\"","resource_type":"Acme::Payment","outcome":"ALLOW"},"tokens":[{"issuer":"https://accounts.example.org","token_type":"access_token","jti":"9c9f2e77-9a3e-4b62-9a2a-2f6e6e2a9f3e"}]},"policy":{"policy_store_id":"https://example.org/policy-stores/payments","policy_store_version":"1.2.3","policy_language":"cedar","policy_language_version":"4.4.0","bundle_hash":"sha256:6cd416d52176b7d2fb8132025f55a42443910cc8d9f2b3f1d19b98b090c2d928"},"runtime":{"pdp_id":"pdp-001"}},"producer_chain":{"producer_id":"pdp-fleet-1","producer_instance_id":"pdp-001","producer_chain_id":"chain-pdp-001-a","sequence_number":2,"prev_record_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"parent_record_ids":[],"signature":"ovtdvERIBlDQtiP0goIzMQ_5Sp86hz1w-RKnj6dUO917w4N2_hfNzyTtRO48yb98K4HP08KSDQP-Sbz6xvXGBw"}
```

#### V-24

```json
{"producer":"pdp-fleet-1","kid":"key-2026-01","record_id":"0191f3a0-7b2d-75b9-86d0-39b80cf5e6d0","trace":{"eat_profile":"tag:govops.owasp.org,2026:trace-v1","event_kind":"AUTHORIZATION_DECISION","signed_at":1781138542,"trace_execution_id":"exec-123","execution_authority":"payments-gateway","subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"event":{"decision":{"action":"Acme::Action::\"ApprovePayment\"","resource_type":"Acme::Payment","outcome":"ALLOW"},"tokens":[{"issuer":"https://accounts.example.org","token_type":"access_token","jti":"9c9f2e77-9a3e-4b62-9a2a-2f6e6e2a9f3e"}]},"policy":{"policy_store_id":"https://example.org/policy-stores/payments","policy_store_version":"1.2.3","policy_language":"cedar","policy_language_version":"4.4.0","bundle_hash":"sha256:6cd416d52176b7d2fb8132025f55a42443910cc8d9f2b3f1d19b98b090c2d928"},"runtime":{"pdp_id":"pdp-001"}},"producer_chain":{"producer_id":"pdp-fleet-1","producer_instance_id":"pdp-001","producer_chain_id":"chain-pdp-001-x","sequence_number":3,"prev_record_hash":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"parent_record_ids":[],"signature":"DbCk-MzMZGTau2rwmFxczgh7jIwFDL5w0aFaCsiNxLnZNpveKTa1JiqGMNfFo_VWNWn5TVgUVCX2TEnWnpGOCQ"}
```

#### V-25

```json
{"producer":"pdp-fleet-1","kid":"key-2026-01","record_id":"0191f3a0-7b2e-76ca-97e1-4ac91d06f7e1","producer_chain":{"producer_id":"pdp-fleet-1","producer_instance_id":"pdp-001","producer_chain_id":"chain-pdp-001-n","sequence_number":1,"prev_record_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"parent_record_ids":[],"signature":"Bz2v9QBKqeomJg92Gp0n56p-lEtH5-DyNdyNabLOR6Hu0zHBUsYO4VgB_2VZTVLvYOaaPKX5KLmab8fYz4BTBA"}
```

#### V-26

```json
{"producer":"pdp/fleet 1","kid":"key-sl-01","record_id":"0191f3a0-7b2f-77db-88f2-5bda2e1708f2","trace":{"eat_profile":"tag:govops.owasp.org,2026:trace-v1","event_kind":"AUTHORIZATION_DECISION","signed_at":1781138542,"trace_execution_id":"exec-123","execution_authority":"payments-gateway","subject":{"workload_id":"spiffe://example.org/service/payments-gateway"},"event":{"decision":{"action":"Acme::Action::\"ApprovePayment\"","resource_type":"Acme::Payment","outcome":"ALLOW"},"tokens":[{"issuer":"https://accounts.example.org","token_type":"access_token","jti":"9c9f2e77-9a3e-4b62-9a2a-2f6e6e2a9f3e"}]},"policy":{"policy_store_id":"https://example.org/policy-stores/payments","policy_store_version":"1.2.3","policy_language":"cedar","policy_language_version":"4.4.0","bundle_hash":"sha256:6cd416d52176b7d2fb8132025f55a42443910cc8d9f2b3f1d19b98b090c2d928"},"runtime":{"pdp_id":"pdp-001"}},"producer_chain":{"producer_id":"pdp/fleet 1","producer_instance_id":"pdp-001","producer_chain_id":"chain-sl-01","sequence_number":1,"prev_record_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"parent_record_ids":[],"signature":"HxFMsIlLwXmyihK9FwcWpwgAEBeaRCxHtMKm6vphr6KXK7wovpKz99q2kxaW9Cf2kKkh9YX4VsfzVi4J5HvYCA"}
```


---

## Appendix D. Informative transport bindings

These bindings show how to satisfy §12 for common intermediaries. The governing rule is that the signed record travels as opaque text. Nothing in the intermediary may convert it into a different data model and back.

### D.1 OTLP and the OpenTelemetry Collector

- **Carriage.** Put the exact JSON text of the record in an OTLP `LogRecord` as a `string` body (`AnyValue.string_value`). Do not use `kvlist_value`, which would split the record into typed attributes and break duplicate-member detection and number fidelity. Do not use `int_value` or `double_value` for any part of the record.
- **Attributes.** Attributes such as `govops.trace.content_type = application/json` and a routing key are hints. They never carry producer identity, domain, or correlation values that the Collector relies on (FW-5).
- **Processors.** No processor in the pipeline may modify, truncate, redact, sample, or split the body of these log records. Use routing or filtering on hints only. Batch processors may group log records but MUST NOT reorder or merge bodies.
- **Exporter.** The exporter that submits to a Collector MUST be a purpose-built exporter (or equivalent) that: authenticates with its own OAuth client (FW-1); posts the unchanged body text to the single or bulk endpoint; interprets per-element results; applies §10.3; and uses a persistent queue. It MUST NOT treat OTLP-level success as Collector acceptance.
- **Acknowledgement.** An OTLP `Export` success response means only that the receiving OpenTelemetry Collector took custody (FW-9). A producer that needs acceptance evidence obtains it by direct submission, or by reconciling with the Collector's receipt lookup (§7.3.1, §12.4) using the record's `producer_id`, `record_id`, and its own digest.
- **Delayed delivery and key expiry.** A persistent queue can hold records past the signing key's `valid_until`. The Collector rejects them with `KEY_NOT_VALID` (§4.5.1). Keep rotated-out keys valid for verification for longer than the queue can hold records, and keep rejected records for resubmission.
- **Persistent queue.** To satisfy FW-10, enable a file-backed or equivalent durable sending queue and size it for the maximum outage the deployment tolerates. An in-memory queue does not satisfy FW-10.

### D.2 Kafka and other message brokers

- **Carriage.** The message value is the exact record bytes (UTF-8 JSON). The message key SHOULD be `producer_id` and `producer_chain_id`, which keeps a chain's records in one partition and in order. Order is not required for correctness (§8.4).
- **Domains.** Use a separate topic (or cluster) per evidence domain, consumed by a separate adapter instance holding the credential for that domain (FW-2). Topic names are routing, not evidence.
- **Producer to broker.** Use acknowledgements from all in-sync replicas and idempotent production, so custody by the broker is durable. This is custody, not acceptance (FW-9).
- **Reconciliation.** The adapter records each Collector receipt (FW-19). A producer that wrote to the topic reconciles by receipt lookup (§12.4) with an identity that holds the receipt scope and receipt-read permission for its `producer_id`. A `404` within the replay retention period means not yet accepted, and the record stays in the topic until it is accepted or its retention ends.
- **Consumer adapter.** Read, batch into a single-producer batch (or mixed batches if the Collector advertises support), submit, and commit the consumer offset only after every record in the batch has an acceptance or a terminal rejection that has been written to a dead-letter destination (FW-13).
- **Dead letter.** Write each terminally rejected record, with its Problem Details `code`, `record_id`, and `content_digest`, to a dead-letter topic with restricted access (FW-12). Do not drop it. Records for `retryable: true` outcomes stay in the main flow with backoff.
- **Retention.** Set topic retention longer than the longest tolerated Collector outage, so an outage cannot discard unacknowledged evidence.
- **Delayed delivery and key expiry.** The Collector evaluates key validity at its own acceptance time (§4.5.1), not at `signed_at`. A record that sat in a topic while its key expired, or was revoked, is rejected with `KEY_NOT_VALID`. To avoid losing evidence, keep rotated-out keys valid for verification for longer than the longest backlog the pipeline can hold, and extend validity before draining a backlog if needed. Route `KEY_NOT_VALID` rejections to the dead-letter destination (FW-12), not to a discard path, so they can be resubmitted after an operator extends validity.

---

## Appendix E. Requirement register

The register lists every requirement identifier of sections 1 to 14 and §12. `requirements.json` holds the full statement and anchor text. "Tests" lists the tests that map to the requirement (§15.6). "exception" refers to §15.8.

| ID | § | Level | Applies to | Capability | Verified by | Tests |
|---|---|---|---|---|---|---|
| SCP-001 | 1.2 | optional | collector |  | test |  |
| SCP-002 | 1.3 | optional | collector |  | test |  |
| OVR-001 | 3 | mandatory | collector |  | test | B-24 |
| TRN-001 | 4.1 | mandatory | collector |  | test | C-31 |
| TRN-002 | 4.1 | mandatory | collector |  | test | C-31 |
| TRN-003 | 4.1 | mandatory | collector |  | inspection |  |
| TRN-004 | 4.1 | mandatory | collector |  | inspection |  |
| TRN-005 | 4.1 | mandatory | producer, forwarder |  | behavior | P-16 |
| AUT-001 | 4.2.1 | mandatory | collector |  | test | C-17, A-01 |
| AUT-002 | 4.2.1 | mandatory | collector |  | test | A-14 |
| AUT-003 | 4.2.1 | mandatory | collector |  | test | A-01 |
| AUT-004 | 4.2.1 | mandatory | collector |  | test | A-06 |
| AUT-005 | 4.2.1 | mandatory | collector |  | test | A-13 |
| AUT-006 | 4.2.1 | mandatory | collector | introspection | test | A-11 |
| AUT-007 | 4.2.1 | recommended | operator |  | advisory |  |
| IDN-001 | 4.2.2 | mandatory | collector |  | test | A-02, A-03 |
| IDN-002 | 4.2.2 | mandatory | collector |  | test | A-02, A-03, A-04 |
| IDN-003 | 4.2.2 | mandatory | collector |  | inspection | A-17 |
| IDN-004 | 4.2.2 | mandatory | collector |  | test | A-07, A-08, A-15 |
| IDN-005 | 4.2.2 | mandatory | collector |  | test | A-01, A-05, A-06, A-08 |
| IDN-006 | 4.2.2 | mandatory | collector | introspection | test | A-11, A-12 |
| IDN-007 | 4.2.2 | mandatory | collector |  | test | A-07, A-15 |
| IDN-008 | 4.2.2 | mandatory | collector |  | test | A-09 |
| IDN-009 | 4.2.2 | optional | collector |  | inspection |  |
| TOK-001 | 4.2.3 | mandatory | collector |  | test | C-17, A-01, A-06, A-10 |
| TOK-002 | 4.2.3 | mandatory | collector |  | test | A-10 |
| TOK-003 | 4.2.3 | mandatory | collector | introspection | test | A-11 |
| TOK-004 | 4.2.3 | mandatory | collector |  | test | A-11 |
| TOK-005 | 4.2.3 | optional | collector | introspection | test |  |
| TOK-006 | 4.2.3 | mandatory | collector | introspection | test | A-18 |
| TOK-007 | 4.2.3 | recommended | collector |  | test |  |
| SCT-001 | 4.2.4 | recommended | operator |  | advisory |  |
| SCT-002 | 4.2.4 | mandatory | collector |  | test | A-13, A-16 |
| SCT-003 | 4.2.4 | mandatory | collector |  | test | A-13 |
| SCO-001 | 4.3 | mandatory | collector |  | test | C-18 |
| SCO-002 | 4.3 | recommended | collector |  | test |  |
| SCO-003 | 4.3 | optional | collector |  | test |  |
| SCO-004 | 4.3 | mandatory | producer, forwarder |  | behavior | P-14 |
| SCO-005 | 4.3 | mandatory | collector |  | test | L-06 |
| SCO-006 | 4.3 | mandatory | collector | receipt_lookup | test | L-01, L-06 |
| DOM-001 | 4.4 | mandatory | collector |  | test | C-21, A-03, R-14 |
| DOM-002 | 4.4 | mandatory | collector |  | test | C-19, A-02 |
| DOM-003 | 4.4 | mandatory | collector |  | test | C-19 |
| DOM-004 | 4.4 | optional | collector |  | inspection |  |
| DOM-005 | 4.4 | mandatory | collector |  | test | C-26 |
| DOM-006 | 4.4 | mandatory | collector |  | test | C-26 |
| DOM-007 | 4.4 | mandatory | collector |  | test | C-38 |
| DOM-008 | 4.4 | mandatory | collector |  | test | C-21, L-08 |
| DOM-009 | 4.4 | mandatory | collector |  | test | C-21, L-08 |
| DOM-010 | 4.4 | mandatory | collector |  | test | C-21, A-03 |
| PRM-001 | 4.5 | mandatory | collector |  | test | C-20, C-49, A-04 |
| PRM-002 | 4.5 | optional | collector |  | test | C-22 |
| PRM-003 | 4.5 | mandatory | collector |  | test | C-08, C-20, A-04, R-11 |
| PRM-004 | 4.5 | mandatory | collector |  | test | C-06, C-53 |
| PRM-005 | 4.5 | mandatory | collector |  | test | C-08 |
| KEY-001 | 4.5.1 | mandatory | collector |  | test | C-39, C-43, C-44 |
| KEY-002 | 4.5.1 | mandatory | collector |  | test | C-39, C-43 |
| KEY-003 | 4.5.1 | mandatory | collector |  | test | exception |
| KEY-004 | 4.5.1 | mandatory | collector |  | test | C-39, C-42 |
| KEY-005 | 4.5.1 | mandatory | collector |  | inspection | C-42 |
| KEY-006 | 4.5.1 | optional | collector |  | inspection |  |
| KEY-007 | 4.5.1 | mandatory | collector |  | test | C-28, C-42 |
| KEY-008 | 4.5.1 | optional | collector |  | test |  |
| KEY-009 | 4.5.1 | recommended | operator |  | advisory |  |
| KEY-010 | 4.5.1 | recommended | operator |  | advisory |  |
| KEY-011 | 4.5.1 | recommended | operator |  | advisory |  |
| KEY-012 | 4.5.1 | recommended | operator |  | advisory |  |
| KEY-013 | 4.5.1 | recommended | forwarder |  | behavior | F-06 |
| ORD-001 | 4.6 | mandatory | collector |  | test | C-20, C-38 |
| ORD-S14 | 4.6 | mandatory | collector |  | test | G-03 |
| WIR-001 | 5.1 | mandatory | collector |  | test | C-25 |
| WIR-002 | 5.1 | mandatory | collector | gzip | test | C-51 |
| WIR-003 | 5.1 | mandatory | producer, forwarder |  | behavior | C-25, P-09 |
| WIR-004 | 5.1 | mandatory | collector | gzip | test | C-52 |
| WIR-005 | 5.1 | mandatory | collector |  | test | C-43, A-09 |
| JSN-001 | 5.2 | mandatory | collector |  | test | C-13, B-17 |
| JSN-002 | 5.2 | optional | collector |  | test | B-16 |
| PRF-001 | 5.3 | mandatory | collector |  | test | C-46, P-01 |
| PRF-002 | 5.3 | mandatory | collector |  | test | C-46 |
| PRF-003 | 5.3 | mandatory | collector |  | test | C-46 |
| PRF-004 | 5.3 | mandatory | collector |  | test | C-08, C-50 |
| PRF-005 | 5.3 | mandatory | collector |  | test | C-10, D-05 |
| PRF-006 | 5.3 | mandatory | collector |  | test | C-07 |
| PRF-007 | 5.3 | mandatory | collector |  | test | C-26 |
| PRF-008 | 5.3 | mandatory | collector |  | test | C-34 |
| SIG-001 | 5.4 | mandatory | collector |  | test | C-05, C-46, P-01 |
| SIG-002 | 5.4 | mandatory | collector |  | test | C-11 |
| SIG-003 | 5.4 | mandatory | collector |  | test | C-46 |
| SIG-004 | 5.4 | mandatory | collector |  | test | C-46 |
| SIG-005 | 5.4 | mandatory | collector |  | test | C-06 |
| SIG-006 | 5.4 | mandatory | collector |  | test | C-39, C-53 |
| RID-001 | 5.6 | mandatory | collector |  | test | C-12, P-02 |
| RID-002 | 5.6 | mandatory | collector |  | test | C-12 |
| RID-003 | 5.6 | mandatory | collector |  | test | P-02 |
| RID-004 | 5.6 | optional | collector |  | test | C-57 |
| PRS-001 | 5.7 | mandatory | collector |  | test | C-34 |
| PRS-002 | 5.7 | mandatory | collector |  | test | C-34 |
| PRS-003 | 5.7 | recommended | collector |  | inspection |  |
| LIM-001 | 5.8 | mandatory | collector |  | test | C-54 |
| LIM-002 | 5.8 | mandatory | collector |  | test | C-24, C-47 |
| LIM-003 | 5.8 | mandatory | producer, forwarder |  | behavior | P-09 |
| SUB-001 | 6.2 | mandatory | producer, forwarder |  | behavior | P-04 |
| SUB-002 | 6.2 | mandatory | collector |  | test | exception |
| RCP-001 | 6.3 | mandatory | collector |  | test | C-01 |
| RCP-002 | 6.3 | mandatory | collector |  | test | C-01 |
| RCP-003 | 6.3 | mandatory | collector |  | test | C-01, P-03 |
| RCP-004 | 6.3 | mandatory | collector |  | test | C-01, C-30 |
| RCP-005 | 6.3 | mandatory | collector |  | test | C-01, C-30 |
| RCP-006 | 6.3 | mandatory | collector |  | test | C-01, C-02 |
| RCP-007 | 6.3 | mandatory | collector | sync_flags | test | C-14, C-35, R-15, D-11, C-56 |
| RCP-008 | 6.3 | mandatory | collector |  | test | C-55 |
| RCP-009 | 6.3 | recommended | collector |  | test |  |
| RCP-010 | 6.3 | mandatory | collector |  | test | P-14 |
| RCP-011 | 6.3 | optional | collector |  | test | C-30 |
| RCP-012 | 6.3 | mandatory | producer, forwarder |  | behavior | C-30, P-14 |
| ACC-001 | 7.1 | mandatory | collector |  | test | C-01, C-05, C-32, L-05 |
| ACC-002 | 7.1 | mandatory | collector |  | test | C-32 |
| ACC-003 | 7.1 | mandatory | collector |  | test | exception |
| ACC-004 | 7.1 | mandatory | collector |  | test | C-34 |
| ACC-005 | 7.1 | optional | collector |  | test |  |
| DUR-001 | 7.2 | mandatory | collector |  | test | C-33 |
| DUR-002 | 7.2 | mandatory | collector |  | test | C-02, L-02 |
| DUR-003 | 7.2 | mandatory | collector |  | inspection | C-33 |
| DUR-004 | 7.2 | mandatory | collector |  | test | C-23 |
| DUR-005 | 7.2 | mandatory | collector |  | test | C-23 |
| LKP-001 | 7.3.1 | optional | collector | receipt_lookup | test | L-15 |
| LKP-002 | 7.3.1 | mandatory | collector | receipt_lookup | test | L-02, L-12 |
| LKP-003 | 7.3.1 | mandatory | collector | receipt_lookup | test | L-02 |
| LKP-004 | 7.3.1 | mandatory | collector | receipt_lookup | test | L-07 |
| LKP-005 | 7.3.1 | optional | collector | receipt_lookup | test |  |
| LKP-006 | 7.3.1 | mandatory | producer | receipt_lookup | behavior | P-13 |
| LKP-007 | 7.3.1 | optional | collector | receipt_lookup | test | L-13 |
| LKP-008 | 7.3.1 | mandatory | collector | receipt_lookup | test | L-13 |
| LKP-009 | 7.3.1 | recommended | collector | receipt_lookup | test | L-14 |
| CHN-001 | 7.4 | mandatory | collector |  | test | C-05, G-07 |
| ADM-001 | 7.4.1 | mandatory | collector |  | test | G-01, D-08 |
| ADM-002 | 7.4.1 | optional | collector |  | test | G-06 |
| ADM-003 | 7.4.1 | recommended | collector |  | test | G-06 |
| FLG-EQUIVOCATION | 7.4.2 | mandatory | collector | sync_flags | test | C-16 |
| ASY-001 | 7.4.5 | optional | collector | async_flags | test |  |
| ASY-002 | 7.4.5 | mandatory | collector | async_flags | test | C-35, C-36, D-11, D-13 |
| ASY-003 | 7.4.5 | mandatory | producer, forwarder |  | behavior | C-35, P-15 |
| ASY-004 | 7.4.5 | mandatory | collector | sync_flags | test | D-11 |
| ASY-005 | 7.4.5 | mandatory | collector | sync_flags | test | R-15, D-11 |
| ASY-006 | 7.4.5 | recommended | collector | async_flags | test | C-36 |
| ASY-007 | 7.4.5 | optional | collector | async_flags | test | C-36 |
| ASY-008 | 7.4.5 | mandatory | collector | async_flags | test | C-35 |
| COR-001 | 7.5 | mandatory | collector |  | test | C-09, P-12 |
| COR-002 | 7.5 | mandatory | collector | unattributed | test | C-55 |
| BLK-001 | 8.1 | mandatory | collector | bulk | test | B-01, B-03, B-04 |
| BLK-002 | 8.1 | mandatory | collector | bulk | test | B-02, B-21, B-23, P-09 |
| BLP-001 | 8.2 | mandatory | collector | bulk | test | B-01, B-10, B-13, B-22, B-23 |
| BLP-002 | 8.2 | mandatory | collector | bulk | test | B-13 |
| BLP-003 | 8.2 | mandatory | collector | bulk | test | R-13, B-01, B-07, B-08 |
| BLP-004 | 8.2 | optional | collector | bulk | test |  |
| BLR-001 | 8.3 | mandatory | collector | bulk | test | R-13, B-01, B-14, B-15 |
| BLR-002 | 8.3 | mandatory | collector | bulk | test | B-25 |
| BLR-003 | 8.3 | recommended | collector | bulk | test | B-25 |
| BLO-001 | 8.4 | recommended | producer | bulk | behavior |  |
| BLO-002 | 8.4 | mandatory | collector | bulk | test | B-09 |
| BLT-001 | 8.5 | optional | producer, forwarder | bulk | behavior |  |
| BLT-002 | 8.5 | mandatory | producer, forwarder | bulk | behavior | B-06, P-04, P-07 |
| IDP-001 | 9 | mandatory | collector |  | test | C-04, C-45, L-10, B-08 |
| IDP-002 | 9 | mandatory | collector |  | test | C-28, C-42 |
| IDP-003 | 9 | mandatory | collector |  | test | R-11, L-07 |
| IDP-004 | 9 | mandatory | collector |  | test | C-27, C-45 |
| IDP-005 | 9 | recommended | collector |  | test | C-04 |
| IDP-006 | 9 | mandatory | collector |  | test | C-32 |
| RET-001 | 9.1 | mandatory | collector |  | test | R-02, R-03 |
| RET-002 | 9.1 | mandatory | collector |  | test | R-01, D-12 |
| RET-003 | 9.1 | recommended | operator |  | advisory |  |
| RET-004 | 9.1 | mandatory | collector |  | test | R-03 |
| RET-005 | 9.1 | optional | collector |  | test |  |
| RET-006 | 9.1 | mandatory | collector |  | test | R-01, D-12 |
| RET-007 | 9.1 | optional | collector |  | inspection |  |
| RET-008 | 9.1 | recommended | collector |  | inspection |  |
| RET-009 | 9.1 | recommended | operator |  | advisory |  |
| RPR-001 | 9.2 | mandatory | collector |  | test | R-07 |
| RPR-002 | 9.2 | mandatory | collector | profile_withdrawal | test | R-08, R-09 |
| RPR-003 | 9.2 | recommended | collector | bulk | test | R-10 |
| EXP-001 | 9.3 | mandatory | collector |  | test | R-04, L-11 |
| EXP-002 | 9.3 | mandatory | producer, forwarder |  | behavior | P-17 |
| EXP-003 | 9.3 | mandatory | consumer |  | advisory |  |
| BRK-001 | 9.4 | recommended | operator |  | advisory |  |
| BRK-002 | 9.4 | mandatory | producer, forwarder |  | behavior | F-15, P-17 |
| BRK-003 | 9.4 | recommended | forwarder |  | behavior | F-15 |
| BRK-004 | 9.4 | recommended | operator |  | advisory |  |
| PRB-001 | 10.1 | mandatory | collector |  | test | C-29 |
| PRB-002 | 10.1 | mandatory | collector |  | test | C-29 |
| PRB-003 | 10.1 | mandatory | collector |  | test | C-29 |
| PRB-004 | 10.1 | mandatory | collector |  | test | C-29 |
| PRB-005 | 10.1 | mandatory | collector |  | test | C-29 |
| PRB-006 | 10.1 | optional | collector |  | test |  |
| PRB-007 | 10.1 | optional | collector |  | test |  |
| PRB-008 | 10.1 | optional | collector |  | test |  |
| PRB-009 | 10.1 | optional | collector |  | test |  |
| PRB-010 | 10.1 | mandatory | collector |  | test | C-29 |
| PRB-011 | 10.1 | mandatory | collector |  | test | L-07 |
| ERR-001 | 10.2 | mandatory | collector |  | test | C-23 |
| ERR-002 | 10.2 | mandatory | collector |  | test | C-29 |
| ERR-003 | 10.2 | optional | collector |  | test |  |
| ERR-004 | 10.2 | mandatory | collector |  | test | C-07 |
| ERR-005 | 10.2 | mandatory | collector |  | test | C-21 |
| ERR-006 | 10.2 | mandatory | collector |  | test | C-29 |
| RTY-001 | 10.3 | mandatory | producer, forwarder |  | behavior | P-06 |
| RTY-002 | 10.3 | optional | producer, forwarder |  | behavior |  |
| RTY-003 | 10.3 | mandatory | producer, forwarder |  | behavior | P-04, P-07 |
| RTY-004 | 10.3 | mandatory | producer, forwarder |  | behavior | P-05, F-07 |
| RTY-005 | 10.3 | recommended | producer, forwarder |  | behavior |  |
| RTY-006 | 10.3 | recommended | producer, forwarder |  | behavior | P-08 |
| RTY-007 | 10.3 | mandatory | producer, forwarder |  | behavior | P-10 |
| DSC-001 | 11.1 | mandatory | collector |  | test | D-07 |
| DSC-002 | 11.1 | optional | collector |  | inspection |  |
| DSC-003 | 11.1 | recommended | collector |  | test |  |
| DSC-004 | 11.1 | mandatory | producer, forwarder |  | behavior | P-14 |
| DSC-005 | 11.1 | mandatory | producer, forwarder |  | behavior | P-14 |
| DSM-001 | 11.2 | mandatory | collector |  | test | D-01, D-02 |
| DSM-002 | 11.2 | mandatory | collector |  | test | D-01 |
| DSM-003 | 11.2 | mandatory | collector |  | test | D-01, D-03 |
| DSM-004 | 11.2 | mandatory | collector |  | test | D-01, D-09 |
| DSM-005 | 11.2 | mandatory | collector |  | test | D-01, D-06 |
| DSM-006 | 11.2 | optional | collector | sender_constrained | test | A-16 |
| DSM-007 | 11.2 | mandatory | collector |  | test | D-01 |
| DSM-008 | 11.2 | optional | collector |  | test |  |
| DSM-009 | 11.2 | mandatory | collector |  | test | C-24, D-01, D-14 |
| DSM-010 | 11.2 | recommended | collector |  | test |  |
| DSM-011 | 11.2 | optional | collector | mixed_producers | test | B-23 |
| DSM-012 | 11.2 | recommended | collector |  | test |  |
| DSM-013 | 11.2 | mandatory | collector |  | test | G-01, D-01, D-08 |
| DSM-014 | 11.2 | optional | collector |  | test | D-11, D-13 |
| DSM-015 | 11.2 | optional | collector | receipt_lookup | test | L-01 |
| DSM-016 | 11.2 | mandatory | collector | receipt_lookup | test | L-01 |
| DSM-017 | 11.2 | mandatory | collector |  | test | R-01, D-01, D-12 |
| DSM-018 | 11.2 | optional | collector | profile_withdrawal | test | R-08, R-09, D-12 |
| DSM-019 | 11.2 | optional | collector | durability_claim | test |  |
| DSM-020 | 11.2 | optional | collector | gzip | test | C-51 |
| DSM-021 | 11.2 | mandatory | collector |  | test | B-04, B-24, D-14 |
| DSM-022 | 11.2 | mandatory | collector |  | test | D-14 |
| DSP-001 | 11.2.1 | mandatory | collector |  | test | D-05, D-09 |
| DSP-002 | 11.2.1 | mandatory | collector |  | test | D-09 |
| DSP-003 | 11.2.1 | mandatory | collector |  | test | D-09 |
| DSP-004 | 11.2.1 | mandatory | collector |  | test | D-09 |
| DSP-005 | 11.2.1 | recommended | collector |  | test |  |
| DSP-006 | 11.2.1 | mandatory | collector |  | test | D-09 |
| DSP-007 | 11.2.1 | mandatory | collector |  | test | C-46 |
| DSP-008 | 11.2.1 | mandatory | collector |  | test | C-46 |
| DSP-009 | 11.2.1 | optional | collector | multiple_profiles | test | D-10 |
| DSA-001 | 11.2.2 | mandatory | collector |  | test | D-06 |
| DSA-002 | 11.2.2 | mandatory | collector |  | test | D-06 |
| DSA-003 | 11.2.2 | optional | collector |  | test | A-08 |
| DSA-004 | 11.2.2 | optional | collector |  | test |  |
| DSA-005 | 11.2.2 | mandatory | collector |  | test | D-06 |
| FW-1 | 12.1 | mandatory | forwarder |  | behavior | F-03, F-09 |
| FW-2 | 12.1 | mandatory | forwarder |  | behavior | F-03 |
| FW-3 | 12.1 | mandatory | forwarder |  | behavior | F-01, F-02 |
| FW-4 | 12.1 | mandatory | forwarder |  | behavior | F-01 |
| FW-5 | 12.1 | mandatory | forwarder |  | behavior | F-08 |
| FW-6 | 12.1 | mandatory | forwarder |  | behavior | F-13 |
| FW-7 | 12.1 | mandatory | forwarder |  | behavior | F-02, F-16 |
| FW-8 | 12.1 | mandatory | forwarder |  | behavior | F-04 |
| FW-9 | 12.1 | mandatory | forwarder |  | behavior | F-04 |
| FW-10 | 12.1 | mandatory | forwarder |  | behavior | F-05 |
| FW-11 | 12.1 | mandatory | forwarder |  | behavior | F-05 |
| FW-12 | 12.1 | mandatory | forwarder |  | behavior | F-06 |
| FW-13 | 12.1 | mandatory | forwarder |  | behavior | F-10 |
| FW-14 | 12.1 | mandatory | forwarder |  | behavior | F-07 |
| FW-15 | 12.1 | mandatory | forwarder |  | behavior | F-09 |
| FW-16 | 12.1 | mandatory | forwarder |  | behavior | F-14 |
| FW-17 | 12.1 | mandatory | forwarder |  | behavior | F-11 |
| FW-18 | 12.1 | mandatory | forwarder |  | behavior | F-15 |
| CO-1 | 12.2 | mandatory | collector |  | test | C-22, L-15 |
| CO-2 | 12.2 | mandatory | collector |  | test | C-22 |
| CO-3 | 12.2 | mandatory | collector |  | test | C-34 |
| CO-4 | 12.2 | mandatory | collector |  | test | C-23 |
| RCN-001 | 12.4 | recommended | producer | receipt_lookup | behavior | P-13 |
| FW-19 | 12.4 | recommended | forwarder |  | behavior | F-12 |
| SEC-001 | 13 | mandatory | collector |  | test | C-39, C-56 |
| SEC-002 | 13 | mandatory | collector |  | inspection |  |
| SEC-003 | 13 | recommended | collector |  | inspection |  |
| SEC-004 | 13 | mandatory | collector |  | inspection | C-46 |
| PRV-001 | 14 | mandatory | producer |  | inspection | P-11 |
| PRV-002 | 14 | recommended | producer |  | inspection |  |
| PRV-003 | 14 | mandatory | collector |  | inspection |  |
| PRV-004 | 14 | mandatory | collector |  | test | C-01, L-02 |
| PRV-005 | 14 | mandatory | collector |  | test | D-07 |
| PRV-006 | 14 | mandatory | collector |  | test | C-29 |
| ORD-S01 | 4.6 | mandatory | collector |  | test | C-31 |
| ORD-S02 | 4.6 | mandatory | collector |  | test | C-17, C-38 |
| ORD-S03 | 4.6 | mandatory | collector |  | test | C-18, C-38 |
| ORD-S04 | 4.6 | mandatory | collector |  | test | C-19, C-38 |
| ORD-S05 | 4.6 | mandatory | collector | bulk | test | C-25 |
| ORD-S06A | 4.6 | mandatory | collector |  | test | C-13, C-37, C-38, B-16 |
| ORD-S06B | 4.6 | mandatory | collector |  | test | C-37 |
| ORD-S07 | 4.6 | mandatory | collector |  | test | C-08, C-20, C-22 |
| ORD-S08 | 4.6 | mandatory | collector |  | test | B-10 |
| ORD-S09 | 4.6 | mandatory | collector |  | test | C-10 |
| ORD-S10 | 4.6 | mandatory | collector |  | test | C-02, R-04 |
| ORD-S10A | 4.6 | mandatory | collector |  | test | C-08, C-12, C-50 |
| ORD-S11 | 4.6 | mandatory | collector |  | test | C-06, C-07 |
| ORD-S12 | 4.6 | mandatory | collector |  | test | C-05 |
| ORD-S13 | 4.6 | mandatory | collector |  | test | C-04 |
| ORD-S15 | 4.6 | mandatory | collector |  | test | C-01, C-23, C-33 |
| ORD-S16 | 4.6 | mandatory | collector |  | test | C-01 |
| VAL-01 | 4.6 | mandatory | collector |  | test | C-13, C-37, C-48, B-16, B-17, B-19, B-20, C-61 |
| VAL-02 | 4.6 | mandatory | collector |  | test | B-18 |
| VAL-03 | 4.6 | mandatory | collector |  | test | C-37 |
| VAL-04 | 4.6 | mandatory | collector |  | test | B-11, B-21, B-22 |
| VAL-05 | 4.6 | mandatory | collector |  | test | B-10 |
| VAL-06 | 4.6 | mandatory | collector |  | test | B-23 |
| VAL-07 | 4.6 | mandatory | collector |  | test | B-01, B-22 |
| VAL-08 | 4.6 | mandatory | collector |  | test | B-08 |
| VAL-09 | 4.6 | mandatory | collector |  | test | B-13 |
| LIM-RECORD | 5.8 | mandatory | collector |  | test | C-24, D-14 |
| LIM-BATCHBYTES | 5.8 | mandatory | collector | bulk | test | B-05 |
| LIM-BATCHRECORDS | 5.8 | mandatory | collector | bulk | test | B-04 |
| LIM-DEPTH | 5.8 | mandatory | collector |  | test | C-47, B-20 |
| SUB-S1 | 6.2 | mandatory | collector |  | test | C-01 |
| SUB-S2 | 6.2 | mandatory | collector |  | test | C-02 |
| SUB-S3 | 6.2 | mandatory | collector |  | test | C-05 |
| SUB-S4 | 6.2 | mandatory | collector |  | test | C-17 |
| SUB-S5 | 6.2 | mandatory | collector |  | test | C-04 |
| SUB-S6 | 6.2 | mandatory | collector |  | test | C-24, C-25, C-58 |
| SUB-S7 | 6.2 | mandatory | collector |  | test | C-23 |
| CHN-ADMISSION | 7.4 | mandatory | collector |  | test | G-01, G-03, G-10 |
| CHN-INTEGRITY | 7.4 | mandatory | collector |  | test | C-15, C-16, G-08 |
| CHN-COMPLETENESS | 7.4 | mandatory | collector |  | test | C-14 |
| ADM-M1 | 7.4.1 | mandatory | collector | chain_mode:first_observed | test | G-01, D-08 |
| ADM-M2 | 7.4.1 | mandatory | collector | chain_mode:pre_registered | test | G-03, G-04, D-08 |
| ADM-M3 | 7.4.1 | mandatory | collector | chain_mode:both | test | G-06, D-08 |
| FLG-CHAIN_LINK_FAILURE | 7.4.2 | mandatory | collector | sync_flags | test | C-15, G-08 |
| FLG-COVERAGE_GAP | 7.4.3 | mandatory | collector | sync_flags | test | C-14, G-02, G-08, B-09 |
| FLG-LATE | 7.4.4 | mandatory | collector | sync_flags | test | C-56 |
| BLK-E1 | 8.1 | mandatory | collector | bulk | test | B-16, B-17 |
| BLK-E2 | 8.1 | mandatory | collector | bulk | test | B-18 |
| BLK-E3 | 8.1 | mandatory | collector | bulk | test | B-03 |
| BLK-E4 | 8.1 | mandatory | collector | bulk | test | B-04 |
| BLK-E5 | 8.1 | mandatory | collector | bulk | test | B-05 |
| BLK-E6 | 8.1 | mandatory | collector | bulk | test | B-02 |
| BLK-E7 | 8.1 | mandatory | collector | bulk | test | B-12 |
| BLK-E8 | 8.1 | mandatory | collector | bulk | test | B-14 |
| IDP-T1 | 9 | mandatory | collector |  | test | C-02, C-03, C-27, R-02, R-13, B-06, B-07 |
| IDP-T3 | 9 | mandatory | collector |  | test | C-16 |
| IDP-T4 | 9 | mandatory | collector |  | test | C-57 |
| IDP-T5 | 9 | mandatory | collector |  | test | C-21, A-03, R-14 |
| RPR-T1 | 9.2 | mandatory | collector |  | test | R-11, R-14, R-16 |
| RPR-T2 | 9.2 | mandatory | collector |  | test | R-16 |
| RPR-T3 | 9.2 | mandatory | collector |  | test | R-10 |
| RPR-T4 | 9.2 | mandatory | collector |  | test | R-08 |
| RPR-T5 | 9.2 | mandatory | collector |  | test | R-07 |
| RPR-T6 | 9.2 | mandatory | collector |  | test | R-07 |
| RPR-T7 | 9.2 | mandatory | collector |  | test | R-12 |
| ERR-UNAUTHENTICATED | 10.2 | mandatory | collector |  | test | C-17, A-05, A-10 |
| ERR-INSUFFICIENT_SCOPE | 10.2 | mandatory | collector |  | test | C-18 |
| ERR-EVIDENCE_DOMAIN_NOT_BOUND | 10.2 | mandatory | collector |  | test | C-19, L-09 |
| ERR-SUBMITTER_NOT_AUTHORIZED | 10.2 | mandatory | collector |  | test | C-20, B-12 |
| ERR-UNSUPPORTED_MEDIA_TYPE | 10.2 | mandatory | collector |  | test | C-25 |
| ERR-REQUEST_TOO_LARGE | 10.2 | mandatory | collector | bulk | test | B-05 |
| ERR-RECORD_TOO_LARGE | 10.2 | mandatory | collector |  | test | C-24, R-10, B-10 |
| ERR-BATCH_TOO_MANY_RECORDS | 10.2 | mandatory | collector | bulk | test | B-04 |
| ERR-BATCH_NOT_ARRAY | 10.2 | mandatory | collector | bulk | test | B-18 |
| ERR-BATCH_EMPTY | 10.2 | mandatory | collector | bulk | test | B-03 |
| ERR-BATCH_MIXED_PRODUCERS | 10.2 | mandatory | collector | bulk | test | B-02 |
| ERR-MALFORMED_JSON | 10.2 | mandatory | collector |  | test | C-13, C-47, C-48 |
| ERR-SCHEMA_INVALID | 10.2 | mandatory | collector |  | test | C-12, C-50, B-11, C-54 |
| ERR-UNSUPPORTED_PROFILE | 10.2 | mandatory | collector |  | test | C-10, R-08, D-05 |
| ERR-MISSING_EXECUTION_CONTEXT | 10.2 | mandatory | collector |  | test | C-09 |
| ERR-PRODUCER_IDENTITY_MISMATCH | 10.2 | mandatory | collector |  | test | C-08 |
| ERR-SIGNATURE_MALFORMED | 10.2 | mandatory | collector |  | test | C-11 |
| ERR-UNSUPPORTED_ALGORITHM | 10.2 | mandatory | collector |  | test | C-46 |
| ERR-CHAIN_NOT_REGISTERED | 10.2 | mandatory | collector |  | test | G-03, G-05 |
| ERR-RECEIPT_NOT_FOUND | 10.2 | mandatory | collector | receipt_lookup | test | L-04 |
| ERR-RECEIPT_ACCESS_DENIED | 10.2 | mandatory | collector | receipt_lookup | test | L-07 |
| ERR-KEY_UNKNOWN | 10.2 | mandatory | collector |  | test | C-06 |
| ERR-KEY_NOT_VALID | 10.2 | mandatory | collector |  | test | C-28, C-40, C-41, C-44, R-06 |
| ERR-EVENT_KIND_NOT_AUTHORIZED | 10.2 | mandatory | collector |  | test | C-07 |
| ERR-SIGNATURE_INVALID | 10.2 | mandatory | collector |  | test | C-05, B-01 |
| ERR-RECORD_ID_CONFLICT | 10.2 | mandatory | collector |  | test | C-04 |
| ERR-RATE_LIMITED | 10.2 | mandatory | collector |  | test | C-58 |
| ERR-COLLECTOR_UNAVAILABLE | 10.2 | mandatory | collector |  | test | C-23, A-11, B-13 |
| ERR-COLLECTOR_INTEGRITY_HOLD | 10.2 | mandatory | collector |  | test | C-59 |
| ERR-INTERNAL_ERROR | 10.2 | mandatory | collector |  | test | C-60 |
| RCN-T1 | 12.4 | mandatory | producer | receipt_lookup | behavior | P-13 |
| RCN-T2 | 12.4 | mandatory | producer | receipt_lookup | behavior | P-13 |
| RCN-T3 | 12.4 | mandatory | producer | receipt_lookup | behavior | P-13 |
| RCN-T4 | 12.4 | mandatory | producer | receipt_lookup | behavior | P-13 |
| RCN-T5 | 12.4 | mandatory | producer | receipt_lookup | behavior | P-13 |
| RCN-T6 | 12.4 | mandatory | producer | receipt_lookup | behavior | P-13 |
| AUT-M1 | 4.2.1 | mandatory | collector |  | test | A-01 |
| AUT-M2 | 4.2.1 | mandatory | collector |  | test | A-01, A-06 |
| AUT-M3 | 4.2.1 | mandatory | collector |  | test | A-13 |
| IDN-R1 | 4.2.2 | mandatory | collector |  | test | A-02 |
| KEY-R0 | 4.5.1 | mandatory | collector |  | test | C-39, C-40 |
| KEY-R1 | 4.5.1 | mandatory | collector |  | test | C-28, C-39, C-40, C-41, C-44 |
| KEY-R2 | 4.5.1 | mandatory | collector |  | test | C-42 |
| ORD-R2 | 4.6 | mandatory | collector |  | test | R-07 |
| JSN-R1 | 5.2 | mandatory | collector |  | test | C-37 |
| DUR-C1 | 7.2 | mandatory | collector |  | test | C-01 |
| DUR-C2 | 7.2 | mandatory | collector |  | test | C-01 |
| DUR-C3 | 7.2 | mandatory | collector |  | test | C-01 |
| CHN-R1 | 7.4 | mandatory | collector |  | test | G-04, G-10 |
| CHN-R2 | 7.4 | mandatory | collector |  | test | C-14, C-36, G-04, G-10, B-09 |
| CHN-R4 | 7.4 | mandatory | collector |  | test | G-03 |
| ADM-R1 | 7.4.1 | mandatory | collector |  | test | G-09, R-12 |
| ADM-R2 | 7.4.1 | mandatory | collector | chain_mode:first_observed | test | G-02 |
| ADM-R3 | 7.4.1 | mandatory | collector | chain_mode:pre_registered | test | G-05, G-07 |
| BLP-R1 | 8.2 | mandatory | collector | bulk | test | B-01 |
| BLP-R2 | 8.2 | mandatory | collector | bulk | test | B-11 |
| BLP-R3 | 8.2 | mandatory | collector | bulk | test | B-16, B-19 |
| BLT-M1 | 8.5 | mandatory | producer, forwarder | bulk | behavior | B-06 |
| BLT-M2 | 8.5 | mandatory | producer, forwarder | bulk | behavior | B-06, P-06, F-06 |
| BLT-M3 | 8.5 | mandatory | producer, forwarder | bulk | behavior | F-07 |
| EXP-M1 | 9.3 | mandatory | collector |  | test | R-04 |
| EXP-M2 | 9.3 | mandatory | collector |  | test | R-06 |
| EXP-M3 | 9.3 | mandatory | collector |  | test | R-05 |
| LKP-A1 | 7.3.1 | mandatory | collector | receipt_lookup | test | L-02, L-09 |
| LKP-A2 | 7.3.1 | mandatory | collector | receipt_lookup | test | L-02, L-06 |
| LKP-A3 | 7.3.1 | mandatory | collector | receipt_lookup | test | L-02, L-08, L-09 |
| LKP-R1 | 7.3.1 | mandatory | collector | receipt_lookup | test | L-02, L-03, L-10 |
| LKP-R2 | 7.3.1 | mandatory | collector | receipt_lookup | test | L-02 |
| LKP-N1 | 7.3.1 | mandatory | collector | receipt_lookup | test | L-04, L-05, L-11 |
| LKP-D1 | 7.3.1 | mandatory | producer | receipt_lookup | behavior | L-10, P-13 |
| DSC-R1 | 11.1 | mandatory | collector |  | test | D-01, D-03 |
| IDP-R1 | 9 | mandatory | collector |  | test | C-02, R-15, L-03 |
| IDP-R2 | 9 | mandatory | collector |  | test | C-03 |
| IDP-R5 | 9 | mandatory | collector |  | test | C-05 |
| PRS-R1 | 5.7 | mandatory | collector |  | test | C-03 |
| DIG-R1 | 5.5 | mandatory | collector |  | test | C-62 |
| DIG-R2 | 5.5 | mandatory | collector |  | test | C-03, P-03 |
| DIG-R3 | 5.5 | mandatory | collector |  | test | C-03, C-62 |
| JSN-L1 | 5.2 | mandatory | collector |  | test | C-48, B-19 |
| JSN-L2 | 5.2 | mandatory | collector |  | test | C-13, B-16 |
| JSN-L3 | 5.2 | mandatory | collector |  | test | C-61 |
| JSN-L4 | 5.2 | mandatory | collector |  | test | C-47, B-20 |
| RID-R1 | 5.6 | mandatory | collector |  | test | C-49, L-12, C-57 |
