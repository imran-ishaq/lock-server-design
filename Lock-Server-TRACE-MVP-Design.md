# Lock Server TRACE — MVP Design

## 1. Purpose

This document defines the smallest useful implementation of TRACE evidence support in Janssen Lock Server. It is an implementation profile of the full TRACE design, not a replacement for it.

The MVP answers four practical questions about a governed agent action:

1. What capability was authorized?
2. What enforcement point attempted or performed the invocation?
3. What did each evidence producer sign?
4. Which records belong to the same governed execution?

The MVP provides attributable, tamper-evident records and basic correlation. It does **not** claim that an execution's evidence is complete, that a producer reported every event, or that a recorded action caused a claimed real-world effect.

## 2. MVP outcome

At the end of Phase 1, Lock Server can:

- accept a signed TRACE record from an authenticated producer;
- derive the record's evidence-domain partition from the submitting OAuth client;
- verify the producer identity, key, signature, and required schema;
- preserve the producer-signed assertion without modification;
- detect replay, record-ID conflict, producer-chain coverage gaps, chain-link failures, equivocation, and late arrival, flagging each rather than silently dropping or rejecting it;
- assign a Lock receipt sequence and append the record to Lock's receipt chain;
- correlate records by governed execution, capability, producer, and token reference; and
- retrieve either one record or the direct records for one execution.

This is sufficient to demonstrate the core evidence path:

`authorization decision → capability invocation → optional runtime effect`

The authorization decision and capability invocation should come from different control points. Cedarling records what was authorized. The PEP, agent gateway, or tool gateway that mediates the action records `CAPABILITY_INVOKED`. An agent's own statement that it invoked a capability is not equivalent to enforcement-point evidence.

## 3. Scope

### Required in the MVP

- OAuth-protected single-record ingestion.
- OAuth-protected bulk ingestion (`POST /api/v1/audit/trace/bulk`), one producer per batch, with per-record accept/reject — required because a high-throughput producer such as Cedarling cannot scale with one request per record (see §11.2).
- An optional batch-ingest write mode (`batchIngestEnabled`, off by default) that writes the receipt entries and records of one request in one database transaction where the store supports it, with the same per-record results as the default path (§9.1).
- Per-evidence-domain producer-key registration through an admin API under a separate scope (`trace.admin`), never implicitly from a submitted record.
- Producer-chain registration, either through the admin API (`pre_registered_genesis`) or from a chain's genesis record (`first_observed_genesis`), selected by Lock configuration (§8).
- Ed25519 signatures selected by signed `kid`.
- RFC 8785 JSON Canonicalization Scheme (JCS).
- Immutable storage of accepted producer assertions.
- Lock-derived verification and ingestion metadata.
- Execution correlation using `(evidence_domain_id, execution_authority, trace_execution_id)`.
- Record identity using `(evidence_domain_id, producer_id, record_id)`.
- Producer-local sequence and predecessor-hash checking.
- A Lock receipt hash chain.
- Multiple token references per record, identified by issuer plus `jti`, or by fingerprint when `jti` is absent.
- Retrieval by record, by execution, and by policy store release.
- Coverage-gap, chain-link-failure, equivocation, and late-arrival flagging, plus two Lock-specific findings: `policy_mismatch_flag` (the record names a policy store release Lock did not serve) and `reserved_member_flag` (the producer signed a member Lock derives itself, §10).
- The same API over gRPC, next to REST (§11.6).
- Structured errors and idempotent replay.

### Explicitly deferred

The MVP does not implement:

- settlement assessments or Lock-signed settlement receipts;
- execution completeness or assurance profiles, including the AIMS evidence-completeness profile;
- lineage checkpoints or claims of complete producer history;
- delegation non-expansion analysis;
- authorization-transition reconstruction;
- user-intent and approval records, including `USER_CONFIRMATION_RECORDED` and the `APPROVAL_GRANTED` authorization-grant binding (confirmation-vs-authorization distinction);
- operation-binding commitments, including proof-of-possession binding (`pop_binding` — WPT/HTTP-Message-Signature proof binding);
- token-claim enrichment or current-state resolution, and token-exchange / transaction-token lineage (including the forwarded-access-token anti-pattern finding);
- RATS-based attestation assessment or trust tiers;
- cross-domain correlation or import;
- privacy-preserving trust-boundary profiles;
- signed receipt checkpoints or external transparency anchoring;
- Evidence Packet export;
- Lock emitting TRACE records for access to **its own** endpoints (Lock-as-PEP self-emission — Lock embeds Cedarling, so it *could* be a producer, but self-reference/recursion and settlement-key-vs-producer-key hygiene must be resolved first; see `design.md`: Lock as a TRACE producer for its own endpoints); or
- graph traversal beyond direct execution membership;
- a quarantine store for rejected records (rejected records are not stored); or
- an administrative operation that gives a record whose receipt entry is `VOID` a new receipt position (§9).

The MVP also defers the AIMS/WIMSE identity and lifecycle features the full design specifies:

- the WIMSE Agent Identifier profile (requiring `workload_id` to be a WIMSE URI) — the MVP accepts any stable `workload_id`, and defers `credential_type`/`audience`/`expiration`/`cnf_key_thumbprint`/`credential_id` on `tokens[]` (the MVP records only issuer/type/jti/fingerprint) and the `workload_authentication` record of how the workload authenticated (transport vs. application, mtls/wpt/http_message_signature);
- credential-provisioning evidence (`CREDENTIAL_PROVISIONED`) and its posture/assessment references; and
- security-signal and remediation evidence (`SECURITY_SIGNAL_RECEIVED` / `REMEDIATION_APPLIED`, the SSF/CAEP/RISC signal-and-remediation causal pair).

## 4. Security and responsibility boundaries

TRACE involves several parties with different responsibilities:

- A **policy decision point (PDP)**, such as Cedarling, decides whether a governed capability is allowed and produces an `AUTHORIZATION_DECISION` record.
- An **enforcement point**, such as a PEP, agent gateway, or tool gateway, mediates the action and produces a `CAPABILITY_INVOKED` record.
- An **evidence producer** signs the record it creates. A PDP or enforcement point is therefore a producer for its own records.
- A **submitting client** sends a signed record to Lock. It is usually the producer, but an approved forwarder may submit on a producer's behalf.
- **Lock Server** verifies, stores, correlates, and returns evidence. Lock does not decide whether the governed capability should run.

There are three independent security checks. They must not be confused:

| Check | Question answered | Mechanism |
|---|---|---|
| Capability authorization | May the agent exercise this action on this resource? | Cedarling or another PDP; the result is evidence recorded by TRACE. |
| TRACE API access control | May this client submit or read evidence through Lock's API? | OAuth access token, TRACE API scope, and Lock endpoint policy. |
| Record verification | Who signed this record, and have the signed fields changed? | Producer key lookup and Ed25519 signature verification. |

Lock performs the second and third checks. The first happened at the PDP and is what an `AUTHORIZATION_DECISION` record describes. 

### 4.1 Evidence-domain isolation

One Lock deployment may collect evidence for several organizations, environments, or other administrative partitions. Records from those partitions must not collide or become visible to one another. `evidence_domain_id` is the opaque Lock-local identifier for that isolation boundary.

Lock determines the domain from the authenticated submitting client and that client's configured domain binding. The producer does not choose the domain by placing a value in the record. Otherwise, a producer could claim another domain's identifier and attempt to write into its namespace.

Lock MUST NOT derive `evidence_domain_id` from the submitted assertion. If the body contains that field, Lock must either reject the request or ignore the field and flag the attempt; it must never use the submitted value for routing or storage.

Within Lock, the derived domain scopes producer-key lookup, record identity, execution correlation, indexes, and retrieval. A producer key registered in one evidence domain grants no authority in another. A producer serving several domains must have an explicit registration in each one.

A single-domain deployment may configure one implicit domain. It should still retain the internal partition so a later move to multiple domains does not change record identities or weaken isolation.

### 4.2 Submitting client and record producer

Before doing record-dependent work, Lock MUST validate that the OAuth client may use the TRACE ingestion endpoint—for example, by checking the access token and `trace.write` scope. This is ordinary API access control for Lock as an OAuth resource server. It is not a decision about whether the agent may exercise the capability described in the record.

After the API caller is accepted, Lock verifies the signed `producer` and `kid` against a producer key registered in the derived evidence domain. This establishes record authorship independently of the transport credential.

Normally the submitting OAuth client and signed producer represent the same component. Lock does not compare the two: a client may submit a record only when its domain binding lists the signed `producer` (or `"*"`) in `allowedProducerIds`, whether it submits its own records or forwards another producer's; otherwise the request fails with `403 producer_not_allowed`. A client without its own binding falls back to `defaultEvidenceDomainId` and to `defaultAllowedProducerIds`, which is empty by default, so with Lock's defaults such a client cannot submit until an operator lists its producer. A forwarding client cannot replace the producer signature or select a different evidence domain in the record body.

## 5. Minimal architecture

The MVP has five logical components:

| Component | Responsibility |
|---|---|
| TRACE API | Validate API access, derive `evidence_domain_id`, and parse requests. It does not decide whether the governed capability is allowed. |
| Verification service | Validate schema, resolve `(evidence_domain_id, producer_id, kid)`, canonicalize, and verify the signature. |
| Producer key registry | Store trusted Ed25519 public keys and validity/revocation metadata per evidence domain. |
| Correlation service | Validate producer-chain position and create direct execution, capability, producer, and token indexes. |
| TRACE store | Persist the assertion, verification metadata, and ingestion metadata, and write the receipt-chain entry: claimed and settled per record (§9), or inserted in one transaction with the records in batch-ingest mode (§9.1). |

Processing order is fixed:

1. Validate the OAuth client and its permission to use the TRACE endpoint.
2. Derive `evidence_domain_id`.
3. Validate the JSON structure and limits.
4. Check that the client may submit for the signed `producer` (§4.2).
5. Resolve the signed producer and `kid` within that domain: the key's validity window, then its `authorized_event_kinds`.
6. Verify the Ed25519 signature over the JCS form of every assertion field except `signature`.
7. Compute `content_digest` over the JCS form of the complete assertion, including `signature`.
8. Apply idempotency, conflict, chain-registration (§8), chain-gap, and equivocation checks.
9. Write the record and its Lock receipt entry. On the per-record path, claim a receipt position, store the record, then settle the receipt entry (§9). In batch-ingest mode, reserve a contiguous range of receipt positions and insert the receipt entries and records of the request in one transaction (§9.1).
10. Return the acceptance result.

In batch-ingest mode, steps 3–7 run for every element of the request first, without holding any lock. Steps 8–9 then run for the verified elements in array order, and each element is planned as if the earlier valid elements of the same request were already stored. Each element gets the result it would get as a separate submission made in array order.

Unverified records MUST NOT enter the normal TRACE store or any retrieval index. An implementation may place them in a separately access-controlled quarantine.

## 6. Producer key registration

Each key is identified by:

`(evidence_domain_id, producer_id, kid)`

The minimum key record is:

```json
{
  "producer_id": "cedarling-fleet-1",
  "kid": "key-2026-01",
  "public_key_jwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "..."
  },
  "authorized_event_kinds": ["AUTHORIZATION_DECISION"],
  "valid_from": "2026-01-01T00:00:00Z",
  "valid_until": null,
  "revoked_at": null
}
```

`producer_id` is the **stable logical producer** (`cedarling-fleet-1`), not a `name/semver` string — software version is separate signed metadata (see §7.1), so a software upgrade does not force a new producer identity, key, or chain. `authorized_event_kinds` scopes which event kinds this key may sign; a record whose `event_kind` is outside the key's authorized set is **rejected**, exactly like an unknown key (the full design elaborates this as the `producer_authorized_for_claim` check). The full design additionally scopes a key by `authorized_measurement_points` (which collection points the key may claim); the MVP defers that finer scoping and enforces only `authorized_event_kinds`.

**Keys are provisioned administratively, never implicitly.** Lock registers producer keys only through an **administrative API protected by a separate scope**, `https://jans.io/oauth/lock/trace.admin`, distinct from `trace.write`. Lock MUST NOT accept a public key merely because it accompanied the first record — that would make the signature self-authenticating. Possession of a signing key must not let the holder define its own producer identity or claim scope; those come only from the administrative registration. Authorization rests on that independently provisioned registration, **not** on the mere fact that a key was found at the lookup index `(evidence_domain_id, producer_id, kid)` — the index locates a candidate key; the administrative registration is what grants authority. (The full design expresses this registration as a portable, administratively-signed **Producer-Key Authorization Statement** that binds the key by thumbprint for offline verification; the MVP relies on Lock's live registry and defers that artifact along with Evidence Packets — see §3.)

The assertion MUST carry `kid` inside the signed scope. Lock selects the key by `kid`; it must not guess the key from the record timestamp. Key rotation may leave old keys available for historical verification. Revoking a key later must not rewrite a verification result recorded before the revocation.

The admin API (scope `trace.admin`; `producer_id` travels in request bodies and query parameters, never in path segments, because it may contain `/`):

| Operation | Endpoint | Notes |
|---|---|---|
| Register a key | `POST /api/v1/audit/trace/admin/producer-keys` | Body as above. `authorized_event_kinds` is required, non-empty, and immutable. Keys are create-only: a duplicate `(producer_id, kid)` is `409 key_already_exists`; rotate by registering a new `kid`. |
| List keys | `GET /api/v1/audit/trace/admin/producer-keys?producer_id=...` | The filter is optional. |
| Revoke a key | `POST /api/v1/audit/trace/admin/producer-keys/revoke` | Body `{producer_id, kid}`. Idempotent. |
| Register a chain | `POST /api/v1/audit/trace/admin/producer-chains` | Body `{producer_id, producer_instance_id, producer_chain_id}`; the chain gets `genesis_kind: pre_registered_genesis` (§8). |
| List chains | `GET /api/v1/audit/trace/admin/producer-chains` | Each entry carries `registered_by` and `genesis_kind`. |

A record whose `event_kind` is outside the key's `authorized_event_kinds` is rejected with the same error as an unknown key (`unknown_producer_key`, reason `event_kind_not_authorized`), before any signature work.

## 7. Minimal TRACE assertion

The following is the MVP wire shape. Fields shown as `null` may be omitted unless an event-kind rule requires them.

```json
{
  "producer": "cedarling-fleet-1",
  "kid": "key-2026-01",
  "record_id": "9f3e9e2a-6b0e-4b2c-9f6e-3a2f7b0c9d41",
  "trace": {
    "eat_profile": "tag:jans.io,2026:trace-v1",
    "event_kind": "AUTHORIZATION_DECISION",
    "signed_at": 1781138542,
    "trace_execution_id": "exec-01JABCXYZQK8P5N9F2C7R3T4V6",
    "execution_authority": "spiffe://example.org/agent/planner",
    "subject": {
      "workload_id": "spiffe://example.org/agent/planner",
      "workload_instance_id": "04bbe9ef-a853-417c-a2b8-5328b62936e2"
    },
    "event": {
      "decision": {
        "action": "Acme::Action::\"Pay\"",
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
      "bundle_hash": "sha256:..."
    },
    "runtime": {
      "pdp_id": "cedarling-001"
    }
  },
  "producer_chain": {
    "producer_id": "cedarling-fleet-1",
    "producer_instance_id": "cedarling-001",
    "producer_chain_id": "chain-01JABC9Z0K",
    "sequence_number": 4821,
    "prev_record_hash": "sha256:..."
  },
  "parent_record_ids": [
    {
      "producer_id": "jans-auth-server",
      "record_id": "R-token-issued-001",
      "relationship_type": "issued_token"
    }
  ],
  "signature": "base64url(...)"
}
```

### 7.1 Required common fields

| Field | MVP rule |
|---|---|
| `producer` | Required. **Stable logical producer identifier** (e.g. `cedarling-fleet-1`), not a `name/semver` string: 1 to 255 characters, a letter or digit followed by letters, digits, and `. _ : / -`, compared byte for byte and never normalized. Must equal `producer_chain.producer_id` byte-for-byte. Software version/build/runtime, when carried, travel as separate signed metadata, never folded into `producer_id`. |
| `producer_version` | Optional top-level string of 1 to 255 characters. A build label: signed and stored unchanged, never interpreted by Lock. The record format is versioned by `trace.eat_profile`, not by this member. |
| `kid` | Required and signed. Selects the registered verification key. |
| `record_id` | Required and producer-generated UUID or ULID. |
| `trace.eat_profile` | Required and fixed to the supported TRACE profile version. |
| `trace.event_kind` | Required and limited to the MVP event catalog below. |
| `trace.signed_at` | Required NumericDate. Producer time; not treated as receipt time. A value more than a configurable skew (default 300 s) ahead of Lock's clock is rejected; a past value never is (lateness only sets `late_flag`). |
| `trace.trace_execution_id` | Required for the MVP; at most 255 characters. |
| `trace.execution_authority` | Required; at most 255 characters. Scopes the execution ID. Distinct from `subject.workload_id` (see below): the authority scopes the execution identifier, the workload is the subject participating in it. |
| `trace.subject.workload_id` | **Event-specific.** Required (non-empty, at most 255 characters) for `AUTHORIZATION_DECISION` and `CAPABILITY_INVOKED` (these records identify the workload requesting or exercising the capability); not required for event kinds where no workload is known or relevant. |
| `trace.subject.workload_instance_id` | Optional. Some deployments cannot reliably identify a particular process, pod, or runtime instance. |
| `trace.event` | Required; shape depends on `event_kind`. |
| `producer_chain` | Required. Identifies the producer-local chain and position. |
| `parent_record_ids` | Optional array of typed causal references. Empty array is valid. |
| `signature` | Required base64url Ed25519 signature. |

Requiring the execution ID at ingestion deliberately avoids correlation-backfill behavior in Phase 1.

The **execution initiator** — whichever component creates the governed unit of work — creates the `(execution_authority, trace_execution_id)` pair and propagates it to the PDP, enforcement point, and effect observer. There is no single Jans component that always plays this role: it may be an agent runtime or workflow engine, an agent/API/tool gateway, a PEP receiving the first governed request, an application host embedding Cedarling, or a scheduler starting an autonomous job. `trace_execution_id` and `execution_authority` always travel together. Cedarling and Lock do **not** generate these identifiers — Cedarling consumes the normalized context and Lock correlates the resulting evidence. Lock does not mint the identifier or authorize the execution; it uses the signed pair to correlate evidence. If a producer cannot obtain that context, it cannot submit the record under the MVP profile and must wait for the later correlation-backfill feature.

Note that `execution_authority` and `workload_id` are **different concepts**: the authority scopes the execution identifier, while the workload is the subject participating in the execution. They are identical in the §7 example above, but they do not have to be.

#### Canonical propagation wire profile

To keep nominally-conforming producers correlatable, the MVP fixes one canonical mapping for the base correlation fields. A host, sidecar, PEP, or gateway translates the applicable carrier into the producer's (and Cedarling's) input model.

| TRACE field | HTTP header | OTel baggage key | Token claim |
|---|---|---|---|
| `trace_execution_id` | `Audit-Trace-ID` | `audit.trace_id` | `https://jans.io/trace/execution_id` |
| `execution_authority` | `Audit-Execution-Authority` | `audit.execution_authority` | `https://jans.io/trace/execution_authority` |
| `workload_id` | `Audit-Workload-ID` | `audit.workload_id` | `https://jans.io/trace/workload_id` |
| `workload_instance_id` | `Audit-Workload-Instance-ID` | `audit.workload_instance_id` | `https://jans.io/trace/workload_instance_id` |

Rules accompanying the mapping:

- `trace_execution_id` and `execution_authority` MUST travel together.
- Cedarling receives normalized values through its authorization API. It does not parse headers, tokens, or OTel baggage.
- The host, sidecar, PEP, or gateway translates the applicable carrier into Cedarling's input model.
- Unsigned headers and baggage are correlation hints, not authoritative claims.
- A trusted ingress component SHOULD validate or replace externally-supplied values rather than forwarding them blindly.
- Signed token claims provide stronger binding, but their issuer and signature MUST still be validated.
- When several carriers disagree, precedence is validated token claim, then trusted ingress/host input, then unsigned header, then OTel baggage; the conflict MUST be recorded rather than silently resolved.

Every `parent_record_ids` reference is resolved inside the same Lock-derived `evidence_domain_id`. Cross-domain causal edges are not supported by the MVP.

### 7.2 MVP event catalog

The MVP recognizes only the three event kinds needed for the capability-evidence path:

| Event kind | Producer | Minimum event data |
|---|---|---|
| `AUTHORIZATION_DECISION` | Cedarling or another PDP | a singular `decision` `{action, resource_type, outcome}` (the signed Cedar action and resource type, no resource id) — or, for an atomic batch evaluation, `decisions[]` with a per-entry `decision_id` and `outcome` and no record-level `outcome`; complete `trace.policy` block; and `trace.runtime.pdp_id`. |
| `CAPABILITY_INVOKED` | PEP, agent gateway, or tool gateway | a singular `invocation` `{action, resource_type, outcome}` (or `invocations[]` with per-entry `invocation_id`/`outcome` for an atomic batch) and `enforcement_point_id`. |
| `RUNTIME_EFFECT` | Target system or trusted observer | Two fields are required (matching the full design): `effect_status`, which says what happened to the effect and is one of `planned`, `dispatched`, `confirmed`, `failed`, or `reverted`; and `outcome`, which is required for every status except `planned`. One extra rule applies to a `confirmed` effect: it MUST also carry a `result_digest` over the observed result. (Lock enforces this "confirmed means a result was actually observed" rule from the record's bytes alone, even in the MVP.) A `RUNTIME_EFFECT` also normally links back to the invocation it followed, via a `produced_effect` parent edge, and SHOULD carry a result/target identifier or `result_digest` so it is useful evidence rather than a bare outcome. |

`AUTHORIZATION_DECISION` and `CAPABILITY_INVOKED` are required for the primary capability-governance flow. `RUNTIME_EFFECT` is optional. Authentication, FIDO, lifecycle, correlation-backfill, delegation, intent, approval, and transition events are deferred to later phases.

These requirements intentionally match the corresponding event-kind schemas in the full design. The MVP narrows the catalog; it does not define weaker versions of the retained event kinds. **Producers sign the capability *facts*, not the governance label.** An `AUTHORIZATION_DECISION` signs a singular `decision` (`{action, resource_type, outcome}`) and a `CAPABILITY_INVOKED` signs a singular `invocation` (`{action, resource_type, outcome}`) — the concrete Cedar action and resource *type* (never a resource id), one record per call. An atomic batch evaluation MAY instead carry `decisions[]`/`invocations[]`, each entry bearing its own `decision_id`/`invocation_id` and `outcome` with no record-level `outcome`. The governance label **`capability_id` is Lock-derived in the full design** (resolved from the signed `(action, resource_type)` plus `policy_store_id`/`policy_store_version` against a versioned mapping in the policy store, stored as `capability_resolution` outside the signed assertion — see `design.md`: Capability Resolution). The **MVP defers that resolution and the capability index** (see §13): the MVP records the signed facts so they are forward-compatible, but does not require Lock to resolve `capability_id` or to serve capability-keyed retrieval. `RUNTIME_EFFECT` carries neither a `decision`/`decisions[]` nor an `invocation`/`invocations[]`; its causal link to the invocation is expressed by `parent_record_ids`.

Lock MUST validate the schema for the declared `event_kind` and reject fields that contradict that kind. The fact rules Lock applies:

- `action` and `resource_type` are non-empty strings of at most 512 characters; a `resource_id` inside a fact is rejected.
- A decision `outcome` is `ALLOW` or `DENY`; an invocation `outcome` is `SUCCESS` or `FAILURE`. The vocabularies are distinct.
- The plural form carries a unique `decision_id`/`invocation_id` (at most 256 characters) per entry. A decision or invocation record with both the singular and the plural member, or with a record-level `trace.event.outcome`, is rejected.
- A signed `capability_ids` is a Lock-derived member: ignored and flagged with `reserved_member_flag` (§10), never used. Lock records evidence; it does not infer that an authorization caused an invocation merely because their timestamps are close. Producers express causal relationships with `parent_record_ids`.

#### What each record establishes (and does not)

Each record kind establishes a **narrow, specific claim** and nothing stronger. This boundary is normative: Lock, and any system consuming Lock's MVP evidence, MUST NOT promote a record into a claim it does not make — a lower-level piece of evidence is never silently elevated into proof of authorization, correctness, or occurrence it does not carry.

| Record | Establishes | Does **not** establish |
|---|---|---|
| `AUTHORIZATION_DECISION` | The PDP signed that it returned this decision under the referenced policy. | That the action occurred or was appropriate. |
| `CAPABILITY_INVOKED` | The enforcement point asserts it mediated the invocation. | That the target produced the claimed effect. |
| `RUNTIME_EFFECT` | The observer asserts that it observed the effect. | That the effect was authorized. |
| Lock receipt | Lock accepted these bytes at this position in its receipt chain. | That the producer's assertion is true or complete. |

This mirrors the full design's per-record-kind claim boundaries, narrowed to the MVP's three event kinds and its receipt chain. It is the MVP expression of the §14 rule that a valid signature is not equated with truth, completeness, independent observation, or successful enforcement.

### 7.3 Token references

`tokens[]` is an array because one decision or action may use several tokens. Each entry MUST contain:

- canonical `issuer`: an `https` URI, an `http` URI whose host is `localhost`, or, for a credential whose issuer has no URI (such as a non-JWT token handled by a custom processor), the URN `urn:jans:cedarling:custom-issuer:<name>`;
- `token_type` (the token's role; a producer-defined type such as a Cedar entity type is allowed); and
- either `jti` or `fingerprint`. Cedarling and `jans-trace-core` derive `fingerprint` as `sha256:` plus lowercase hex SHA-256 of the token exactly as received; Lock also accepts an opaque base64url value of 16–128 characters.

The external token identity is `(evidence_domain_id, issuer, jti)`, never bare `jti`. When no `jti` exists, Lock uses `(evidence_domain_id, issuer, fingerprint)`. Raw bearer tokens MUST NOT be stored: Lock rejects a token reference whose values look like a compact JWS or JWE.

Token claims, decision-time validation details, revocation freshness, token lineage, and later Lock enrichment are deferred. Their omission must be reported as “not captured,” never as “valid.”

## 8. Producer chain

Each producer instance maintains one or more chains. Lock does not impose a global order across producers, and does not impose a single chain per instance.

- `producer_chain_id` identifies one chain instance.
- A producer instance MAY own **more than one chain concurrently**: the model is `producer_id → producer_instance_id → one or more producer_chain_id values`. Each record belongs to exactly one chain and each chain stays strictly linear, but a busy instance (e.g. an embedded Cedarling handling many concurrent `authorize_*` calls) MAY allocate chains by worker, partition, thread, or execution lane so concurrent writers do not contend on one serialized sequence allocator. TRACE does not claim a total order within an instance; cross-chain ordering comes from causal links and `trace_execution_id`.
- `sequence_number` increases by one within one chain.
- `prev_record_hash` is the prior position's `content_digest`.
- The genesis record uses `sequence_number: 1` and the configured all-zero predecessor sentinel.

**Genesis authentication.** The signing **key** is always administratively registered first (§6); genesis authentication is a separate question about the *chain*. For deployments needing stronger lineage assurance, a chain genesis is **pre-registered** with Lock (`pre_registered_genesis`). Otherwise, when Lock runs in `FIRST_OBSERVED` mode (below), an already-registered key MAY open a new chain simply by submitting its first signed record, which Lock anchors at first sight as `first_observed_genesis`. A first-observed chain establishes tamper-evident history from the moment Lock sees it, but cannot establish complete producer history before that point.

Lock selects the genesis rule with one setting, `chainRegistrationMode`:

| Mode | Behavior |
|---|---|
| `PRE_REGISTERED` (Lock default) | A chain exists only after an administrator registers it (§6). A record on an unregistered chain is rejected with `400 chain_not_registered`, at every sequence position. |
| `FIRST_OBSERVED` | A genesis record (`sequence_number: 1` with the all-zero sentinel) on an unregistered chain registers the chain, after the key, event-kind, and signature checks succeed. Admin-registered chains keep working. |

In both modes a **non-genesis record on an unregistered chain is rejected** with `400 chain_not_registered`: Lock never registers a chain from a later position. A producer that opens a new chain at every start (such as Cedarling in the MVP, `cedarling-trace-design-MVP.md` §4) therefore needs `FIRST_OBSERVED`, and must get its genesis record accepted before the rest of that chain. Each chain records how it came to exist in `genesis_kind` (`pre_registered_genesis` or `first_observed_genesis`).

**Restart does not automatically mean a new chain.** A producer that has **durably retained** its `producer_chain_id`, last `sequence_number`, and previous record hash SHOULD **continue its existing chain** across a restart. A new chain is necessary only when that state is unavailable, when a new independently-sequenced writer is created, or when the producer deliberately rotates to another chain. Where a new chain is unavoidable, its genesis SHOULD reference the previous chain head where known (the full design specifies the signed `chain_link`; the MVP records the reference and defers full link validation). Lock accepts `producer_chain.chain_link` only on a genesis record (`400 invalid_genesis` with reason `chain_link_on_non_genesis` otherwise), checks only its shape, and keeps it unchanged.

**Cedarling deployment patterns.** The MVP recognizes that the producer's longevity and key custody vary by deployment: **embedded/server Cedarling** — the host supplies the key and durable chain state; **sidecar Cedarling** — the sidecar owns the key and one or more chain writers; **ephemeral pod** — uses a fleet or workload-provisioned key and opens a `first_observed_genesis` chain for that pod/writer; **WASM Cedarling** — preferably returns the assertion to a trusted host for signing, since a browser-held key provides weaker producer assurance and is classified accordingly. The rule throughout: keys identify trusted producers, chains identify independently-sequenced record streams, and versions describe software — they are not the same identifier.

Within a registered chain, records may arrive out of order. A missing predecessor does not cause rejection: Lock accepts the record with `coverage_gap_flag: true` and clears that derived condition when the missing position arrives and links correctly. A present but nonmatching predecessor is a different case: Lock accepts the record with `chain_link_failure_flag: true`, a genuine chain-link break rather than a pending gap. Unlike a coverage gap, this flag is **not** self-clearing — the conflicting predecessor is already present, so later arrival cannot resolve it — and it remains visible as an integrity finding. When several records hold the predecessor position (equivocation), one whose `content_digest` matches `prev_record_hash` is enough. Lock checks a record when it arrives and again each time a record arrives at its predecessor position, against all records present there at that time; once set, the flag stays, so a matching predecessor that arrives after a nonmatching one does not clear it.

**Flag maintenance.** Lock computes a new record's flags from the chain as it was before the record was written, then updates the derived flags of neighboring records. Each neighbor update is a compare-and-swap on that record, retried up to `correlationRetryLimit` times on a version conflict; it is best-effort and never fails the request. After the write Lock reads the predecessor, own, and successor positions once more, so a neighbor that another request or node stored at the same time is not missed: Lock corrects the new record's own `coverage_gap_flag` (only clearing it) and `chain_link_failure_flag` (only setting it), and corrects a successor that arrived meanwhile. The acceptance response reports the flags the record was stored with, on both write paths (§9), so a reader can see a flag change shortly after acceptance. In batch-ingest mode these updates can run after the response, on a bounded pool (`postCommitCorrelationThreads`, §9.1); updates still queued when Lock stops are lost, and nothing repairs them later.

If independently valid records with different `record_id` values claim the same `(evidence_domain_id, producer_id, producer_instance_id, producer_chain_id, sequence_number)`, Lock stores and flags both records as equivocation. It never silently selects a winner. This differs from reuse of the same `record_id`, which is a content conflict and cannot create two records under one primary key.

Producer order, Lock receipt order, and causal relationships are separate:

- producer order says what one producer signed in sequence;
- receipt order says when Lock accepted records; and
- `parent_record_ids` says which causal relationship a producer asserted.

None is a global event clock.

## 9. Lock receipt chain

For every accepted record, Lock assigns:

- `receipt_sequence`: monotonically increasing within the evidence domain's Lock receipt chain;
- `received_at`: Lock's receipt timestamp — an RFC 3339 UTC timestamp normalized to `Z` with **millisecond precision** (e.g. `2026-06-11T00:41:02.123Z`), matching the receipt-commitment profile (`jans-trace-core` §7.1). Because `received_at` is part of the receipt-hash input, a value stored or displayed without millisecond precision would not reproduce the receipt hash; the stored value and any example MUST carry milliseconds; and
- `prev_receipt_hash`: hash of the preceding receipt entry.

The receipt-entry hash MUST bind at least:

`evidence_domain_id`, `receipt_sequence`, `received_at`, `producer_id`, `record_id`, `content_digest`, and `prev_receipt_hash`.

The list is closed for the receipt profile `tag:jans.io,2026:lock-trace-receipt-v1`: the hash is `sha256:` plus lowercase hex SHA-256 of the JCS form of exactly these members and `receipt_profile`, nothing else.

**Two write paths.** The storage layer (the Jans ORM) offers per-entry compare-and-swap and unique inserts on every backend, and an atomic insert of several entries in one transaction on the SQL backend (PostgreSQL, MySQL) only. It has no general multi-entry transaction and no sequence allocator. Lock therefore writes a record and its receipt entry in one of two ways, into the same receipt chain:

- **Per-record path (default).** Lock claims a receipt position as a `PENDING` entry, stores the record, and settles the entry as `COMMITTED`; a failed request settles it `VOID`, and a repair timer settles entries left `PENDING` by a stopped node. The record and its receipt entry are separate writes. A failed request leaves no stored record and no index entry, but may leave a `VOID` receipt entry. In one rare race (a worker that stalls past its deadline) a record is stored under a `VOID` entry; Lock keeps the record, fails the request, and its identity stays blocked until an operator acts.
- **Batch path (`batchIngestEnabled`, §9.1).** Lock reserves a contiguous range of positions and inserts the receipt entries, already `COMMITTED`, together with the records, in one transaction. A batch never leaves a `PENDING` or `VOID` entry: a failed transaction stores nothing, and its records fall back to the per-record path.

The entry state is not part of the receipt hash, so a `VOID` entry keeps the chain dense and verifiable: it is a position Lock allocated and abandoned, not a gap.

Both paths allocate positions the same way. A node reads the highest receipt entry of the domain, in any state, proposes the next position or positions, and inserts under the unique key `(evidence_domain_id, receipt_sequence)`; a node that loses the race re-reads and retries. There is no separate chain-head row. Because the unique position is the only arbiter, nodes on either path can write the same evidence domain at the same time. The derived indexes (§13) are attributes of the record entry, so they are written with the record.

This chain makes local insertion, deletion, and rewriting detectable during verification. Without signed checkpoints or an independent external anchor, it does not prove integrity against a Lock operator able to rewrite the entire chain. The API and documentation must not overstate that guarantee.

### 9.1 Batch ingest

Batch ingest is an opt-in write mode for both transports: over REST for `POST /api/v1/audit/trace/bulk` and `POST /api/v1/audit/trace`, and over gRPC for `TraceService/SubmitBulkRecords` and `TraceService/SubmitRecord` (§11.6). The gRPC methods hand the exact signed bytes to the same ingestion code as REST, so the setting, the write path, and the results are the same on both. It changes how Lock writes, not what Lock accepts: request and response shapes, status codes, error ids and reasons, receipt fields, flags, and stored rows are the same as on the per-record path. Lock uses it only when `batchIngestEnabled` is on, the store supports atomic batch inserts, and the configured crypto provider is available; otherwise every request takes the per-record path.

For one request Lock:

1. **Verifies** every element (§5 steps 3–7) without holding any lock, optionally in parallel (`batchVerifyThreads`). A failing element is rejected on its own. A producer key is read from the store once per request and reused for later elements that name the same `(producer, kid)`; its validity window and revocation are still judged for every element, only a key that verified an element is reused, and nothing is kept after the request, so a key revoked during one request is seen by the next.
2. **Plans** the verified elements in array order. An element whose identity is already stored, or planned earlier in the request, is classified as an idempotent replay or a `409` conflict. The others get their chain position and flags (§8) as if the earlier elements of the request were already stored, so a chain of many records in one request gets the same flags as when the records arrive one by one.
3. **Commits** the N new records: Lock reserves the next N receipt positions of the evidence domain and inserts the N receipt entries and the N records in one transaction. The new records get consecutive receipt sequences in array order. A replay keeps its original sequence, and a rejected element gets none.
4. **Correlates** after the commit: the neighbor-flag updates of §8, in array order, on the request thread or on a bounded pool (`postCommitCorrelationThreads`).

A single submission made while batch ingest is on goes through the same steps as a batch of one: one transaction instead of the three commits (claim, insert, settle) of the per-record path.

**Contention.** Compare-and-swap on the unique receipt position stays the multi-node protocol. If another writer took one of the positions first, the transaction rolls back and nothing is stored; Lock waits a random backoff and retries the range from a fresh head, up to `rangeAllocationRetryLimit` attempts. An identity that another request stored meanwhile with the same content becomes a replay and is dropped from the retry; if it was stored with different content, later plans of the request may depend on it, so the request falls back to the per-record path, which reports that element as `record_conflict`. Inside one node a per-domain lock serializes range reservation and the transaction; it is released during the backoff.

**Fallback and fail-closed.** If the transaction fails for any other reason, or the range attempts run out, Lock processes the unfinished elements one by one on the per-record path, so one failing row never fails its neighbors and each element gets the per-record result. If the request thread is interrupted during a backoff (for example while Lock stops), Lock stores nothing more for that request and fails the unfinished elements with `500 storage_failure`, reason `receipt_allocation_interrupted`, without the fallback. On both paths a record is reported accepted only after its rows are committed, and a receipt position is never reused.

**Limits.** The ORM accepts at most 1000 entries in one atomic batch and every element needs two (its receipt entry and its record), so `maxBulkRecords` should stay at 500 or below while batch ingest is on. A larger request is not written as one transaction: Lock logs `batch_too_large` and falls back to the per-record path.

**Rollout.** Lock reads the setting on every request and picks up a changed dynamic configuration within about 30 seconds, without a restart. Rows written by the batch path are ordinary `COMMITTED` receipt entries and records: turning the mode off needs no cleanup, and a replay is answered the same way on both paths.

| Setting (`traceConfiguration`) | Default | Meaning |
|---|---|---|
| `batchIngestEnabled` | `false` | Use the batch path for bulk and single submissions. |
| `batchVerifyThreads` | `0` | Threads that verify the elements of one request in parallel; `0` uses the request thread. At most 64. |
| `postCommitCorrelationThreads` | `0` | Threads for the post-commit flag updates; with a pool the response does not wait for them (§8). At most 64. |
| `rangeAllocationRetryLimit` | `32` | Range attempts, the first included, before the fallback. |
| `rangeAllocationBackoffMs`, `rangeAllocationMaxBackoffMs` | `5`, `250` | Before retry k Lock waits a uniformly random time up to `min(base × 2^(k−1), cap)` ms; a base of `0` disables the wait. |

`receiptAllocationRetryLimit` (default 8) still bounds the per-record path. On one 8-vCPU test VM with PostgreSQL, bulk requests of 100 records reached about 6,000–7,200 records/s per evidence domain and Lock node with batch ingest, against about 370 records/s on the per-record path, which waits for about three database commits per record. These are test measurements, not guarantees. The Jans documentation (`docs/janssen-server/lock/trace.md`, "Batch ingest") holds the operator guidance and the measured sizing; open scaling questions are in `trace-mvp-post-mvp.md` §3.2.

## 10. Stored envelope

Lock stores three clearly separated parts:

```json
{
  "assertion": {
    "...": "the complete producer-signed record, unchanged"
  },
  "content_digest": "sha256:...",
  "verification": {
    "signature_valid": true,
    "key_id": "key-2026-01",
    "key_thumbprint": "sha256:...",
    "verified_at": "2026-06-11T00:41:02.123Z",
    "algorithm": "Ed25519",
    "key_authorized": true
  },
  "ingestion": {
    "receipt_sequence": 108422,
    "received_at": "2026-06-11T00:41:02.123Z",
    "prev_receipt_hash": "sha256:...",
    "receipt_hash": "sha256:...",
    "coverage_gap_flag": false,
    "chain_link_failure_flag": false,
    "equivocation_flag": false,
    "late_flag": false,
    "policy_mismatch_flag": false,
    "reserved_member_flag": false,
    "reserved_members": [],
    "receipt_state": "COMMITTED"
  }
}
```

Lock also keeps the exact accepted request text as `assertion_raw` and returns it on retrieval next to the parsed `assertion`; when the two differ, `assertion_raw` decides. `receipt_hash` is the hash of the record's receipt entry (§9). `receipt_state` is not stored with the record: Lock reads it from the receipt entry when it builds a response. It is `COMMITTED`, `PENDING` for the short time before the per-record path settles the entry, or `VOID` only for a record stored by the late-insert race of §9. Two flags extend the MVP set:

- `policy_mismatch_flag`: the record's `trace.policy` names a policy store that Lock serves, with a `bundle_hash` (SHA-256 of the archive bytes Lock serves) that no Lock node served at the time the record is judged, within a grace window; or a matching release whose known `policy_store_version` differs from the record's. Lock still accepts the record; a store Lock does not serve is never compared.
- `reserved_member_flag`: the producer signed a member Lock derives itself (such as `evidence_domain_id`, `capability_ids`, or a flag). Lock ignores it, uses its own value, and lists the paths in `reserved_members`.

`assertion` is byte-immutable after acceptance. Lock MUST NOT insert resolved claims, status, trust, corrections, or receipt data into it. Future assessments must be stored beside the assertion as new Lock-authored artifacts.

`content_digest` is a top-level Lock-computed envelope value used for replay and conflict detection; it is not a signature-verification result. The producer signature is verified over JCS canonical bytes of every assertion field except `signature`. `content_digest` is SHA-256 over JCS canonical bytes of the full assertion including `signature`. These scopes are intentionally different.

The `verification` block records the admission decision Lock made at `verified_at`, so it is not reconstructed later from mutable registry state: `signature_valid`, the verifying `key_id` and its `key_thumbprint` (the thumbprint pins the exact key independently of the non-unique `kid` selector), and `key_authorized` — a single boolean capturing that the key existed, was within its validity window, was not revoked, was registered for this `producer_id`, and was authorized for the record's `event_kind` (the admission checks of §6). A later re-scoping, revocation, or validity change of the key never rewrites these recorded results for an already-stored record. The MVP keeps `key_authorized` as one boolean; the full design decomposes it into separately-recorded `key_resolved`/`key_temporally_valid`/`key_not_revoked`/`key_authorized_for_producer`/`producer_authorized_for_claim` results and binds them to a signed Producer-Key Authorization Statement for offline verification — both deferred here. (The MVP records no `trust_tier`; trust tiers are deferred per §3.)

## 11. API

### 11.1 Submit one record

```http
POST /api/v1/audit/trace
Authorization: Bearer <access-token>
Content-Type: application/json
```

Required scope:

`https://jans.io/oauth/lock/trace.write`

The same operation is served over gRPC as `TraceService/SubmitRecord` (§11.6), with the same scope, validation, receipt, and results.

Success response:

```json
{
  "accepted": true,
  "producer_id": "cedarling-fleet-1",
  "record_id": "9f3e9e2a-6b0e-4b2c-9f6e-3a2f7b0c9d41",
  "content_digest": "sha256:...",
  "receipt_sequence": 108422,
  "received_at": "2026-06-11T00:41:02.123Z",
  "idempotent_replay": false,
  "coverage_gap_flag": false,
  "chain_link_failure_flag": false,
  "equivocation_flag": false,
  "late_flag": false,
  "policy_mismatch_flag": false,
  "reserved_member_flag": false,
  "reserved_members": []
}
```

Return `202 Accepted` only after verification and persistence succeed. Use `400` for malformed or invalid signed content, `401`/`403` for OAuth failures, `409` for reuse of the same record identity with different content, and `500` when durable storage cannot complete. Lock uses `500` (not `503`) for storage failures and for an unavailable crypto provider.

**OAuth failures** follow RFC 6750: an expired, inactive, or invalid token is `401` with `WWW-Authenticate: Bearer error="invalid_token"`; a token without the required scope is `403` with `error="insufficient_scope"`. A producer can therefore renew its token on `401` and treat `403` as final.

**Error body.** Every TRACE error uses `{"error": "<id>", "error_description": "<text>", "reason": "<detail>"}`. `reason` names the offending field or check (for example `missing:trace.policy`, `event_kind_not_authorized`, `signed_at_in_future`) and is present only when Lock's `errorReasonEnabled` is on (off by default). The ids:

| Error id | HTTP | When |
|---|---|---|
| `invalid_request` | 400 | Malformed JSON, a limit exceeded, a bulk envelope problem, or TRACE disabled (`trace_disabled`). |
| `invalid_assertion` | 400 | A schema violation; `reason` names the field. |
| `unsupported_profile` | 400 | `trace.eat_profile` is not `tag:jans.io,2026:trace-v1`. |
| `producer_mismatch` | 400 | `producer` differs from `producer_chain.producer_id`, or does not match the `producer` format (§7.1, reason `producer_format`). |
| `unknown_producer_key` | 400 | No key for `(evidence_domain_id, producer, kid)`, or `event_kind` outside its `authorized_event_kinds`. |
| `key_not_valid` | 400 | The key is outside its validity window or revoked. |
| `invalid_signature` | 400 | Ed25519 verification failed, or the signature is not valid unpadded base64url. |
| `chain_not_registered` | 400 | The record's chain is not registered (§8). |
| `invalid_genesis` | 400 | The genesis position and `prev_record_hash` disagree, or `chain_link` on a non-genesis record. |
| `client_not_bound` | 403 | The client resolves to no evidence domain. |
| `producer_not_allowed` | 403 | The client may not submit for the signed producer. |
| `record_not_found`, `execution_not_found` | 404 | Retrieval found nothing in the domain. |
| `record_conflict` | 409 | Same record identity, different `content_digest`. |
| `ambiguous_identifier` | 409 | An unscoped lookup matches several producers or authorities. |
| `key_already_exists`, `chain_already_exists`, `invalid_key` | 409 / 409 / 400 | Admin API (§6). |
| `storage_failure` | 500 | Persistence or receipt allocation failed (§9); `reason` names the case: `receipt_allocation_exhausted` (no position or range within the retry limits; on the batch path only when the per-record fallback also runs out), `receipt_allocation_interrupted` (batch path, interrupted during a range backoff, §9.1), `batch_verification_abandoned` (Lock stopped while the element waited on the verification pool), `receipt_claim_expired`, `race_record_missing`, or `receipt_void_after_insert` (per-record path, §9). Only `receipt_void_after_insert` leaves a stored record. |
| `crypto_unavailable` | 500 | The configured crypto implementation is unavailable (§14); Lock fails closed. |

### 11.2 Submit a batch of records

```http
POST /api/v1/audit/trace/bulk
Authorization: Bearer <access-token>
Content-Type: application/json
```

Required scope:

`https://jans.io/oauth/lock/trace.write`

The same operation is served over gRPC as `TraceService/SubmitBulkRecords` (§11.6). Its request carries the exact bytes of the JSON array, and Lock applies the same envelope checks, per-record processing, write path (§9, §9.1), and per-record results as over REST.

Bulk ingestion is **in the MVP** because a high-throughput producer such as Cedarling can make thousands of decisions per second, and one HTTP request per record (§11.1) does not scale to that. The batch amortizes transport and lets a producer reuse its existing buffered, periodic shipping channel. The batch body is an array of signed TRACE records, **one producer per batch** (every record shares the same signed `producer`/`producer_chain.producer_id`; a batch mixing producers is rejected). A configurable maximum batch size applies: `maxBulkRecords` (default 100) and `maxBulkRequestBytes` (default 4 MiB, never above 16 MiB); each record is still bounded by the single-record limit (see §14). With batch ingest on, keep `maxBulkRecords` at 500 or below (§9.1). An element without a readable `producer` is not counted by the one-producer check and fails on its own.

**Per-record results, not all-or-nothing.** Lock verifies, correlates, persists, and applies the ingestion-integrity flags (coverage-gap, chain-link-failure, equivocation, late-arrival) to **each record on its own merits**: each record gets the result it would get as a single §11.1 submission made in array order, and a later record sees the earlier valid records of the request as already stored. A failure on one record (bad signature, unknown/unauthorized key, `409` identity conflict, storage failure) does **not** reject the other, independently-valid records; admission has no cross-record coupling. How the records are written depends on the write path (§9). On the per-record path each record is stored with its own receipt claim, three commits per record. With batch ingest (§9.1) the new records of the request and their receipt entries are written in one database transaction; if that transaction fails, the records fall back to the per-record path, so one failing row still does not fail its neighbors. (The MVP runs no settlement — settlement assessments and receipts are a later phase, see §3 and §16 — so there is no settlement pass, per-record or batch-level, to run here.)

Success response is a per-record result array in submission order:

```json
{
  "results": [
    { "index": 0, "accepted": true,  "producer_id": "cedarling-fleet-1", "record_id": "9f3e9e2a-...", "content_digest": "sha256:...", "receipt_sequence": 108422, "received_at": "2026-06-11T00:41:02.123Z", "idempotent_replay": false, "coverage_gap_flag": false, "chain_link_failure_flag": false, "equivocation_flag": false, "late_flag": false, "policy_mismatch_flag": false, "reserved_member_flag": false, "reserved_members": [] },
    { "index": 1, "accepted": false, "producer_id": "cedarling-fleet-1", "record_id": "1b2c3d4e-...", "error": { "error": "invalid_signature", "error_description": "...", "reason": "signature_mismatch" } }
  ]
}
```

Lock returns `207 Multi-Status` whenever the batch was processed, whatever the per-record results; `index` is the position in the submitted array, and a per-record `error` uses the §11.1 error body. For the batch as a whole, `400 invalid_request` is returned only when TRACE is disabled (`trace_disabled`, §11.7) or the **batch envelope** itself is malformed, with a `reason`: not JSON, not an array (`not_array`), empty (`empty_bulk_records`), too many records (`max_bulk_records_exceeded`), too large (`bulk_body_too_large`), or mixed producers (`bulk_mixed_producers`); `401`/`403` for OAuth failures, `403 client_not_bound` when the client resolves to no evidence domain, and `500` only when Lock could not process the batch at all. Each accepted record's receipt is assigned exactly as in §11.1, and replay/`409`/gap/equivocation semantics are per-record and identical to the single-record path. Receipt sequences follow array order but need not be contiguous: a rejected record claims none. With batch ingest, the new records stored by one successful transaction get consecutive sequences; after a fallback to the per-record path, other writers can take positions between them. Resubmitting a whole array is safe: records already committed replay idempotently. Records within one batch MAY advance the producer chain across several `producer_chain_id` lanes (see §8), so batching never forces one serialized sequence allocator.


### 11.3 Retrieve one record

```http
GET /api/v1/audit/trace/records/{record_id}?producer_id={producer_id}
```

Required scope:

`https://jans.io/oauth/lock/trace.readonly`

`producer_id` SHOULD be supplied. If omitted, Lock may return the record only when the bare ID resolves to exactly one producer within the authenticated evidence domain; otherwise it returns an ambiguity error.

### 11.4 Retrieve one execution

```http
GET /api/v1/audit/trace/executions/{trace_execution_id}?execution_authority={execution_authority}
```

The MVP response contains the execution identity and its directly associated records, ordered by Lock receipt sequence. It does not claim global event order, traverse child executions, or compute completeness.

`execution_authority` SHOULD be supplied. If omitted, Lock may return the execution only when the bare ID resolves uniquely within the authenticated evidence domain.

A record response carries `assertion_raw` (the exact accepted text), `assertion` (the same text parsed), `content_digest`, `verification`, and `ingestion` (§10). An execution response carries `"ordering": "receipt_sequence"` and `"completeness": "not_assessed"`, and pages with `start` (default 0) and `count` (default 100, at most 1000).

### 11.5 Search by policy store release

```http
GET /api/v1/audit/trace/records?policy_store_id=...&policy_store_version=...&bundle_hash=...&received_from=...&received_to=...
```

Required scope: `https://jans.io/oauth/lock/trace.readonly`. Returns, in receipt order, the records of the caller's domain whose `trace.policy` matches; at least one of `policy_store_id` or `bundle_hash` is required. It answers "which decisions were made with release X".

### 11.6 gRPC transport

The same operations are served over gRPC by `io.jans.lock.trace.TraceService` (`SubmitRecord`, `SubmitBulkRecords`, `GetRecord`, `SearchRecords`, `GetExecution`) and `io.jans.lock.trace.TraceAdminService` (the §6 admin operations). They run the same code as REST, with the same scopes, evidence domains, receipts, and error ids. Assertions travel as the exact signed bytes, never re-serialized. A REST status maps to the matching gRPC status (`400` → `INVALID_ARGUMENT`, `401` → `UNAUTHENTICATED`, `403` → `PERMISSION_DENIED`, `404` → `NOT_FOUND`, `409` → `ALREADY_EXISTS`, `500` → `INTERNAL`; `ambiguous_identifier` → `FAILED_PRECONDITION`), with the §11.1 error body as the status description. Single and bulk submissions over gRPC use the per-record or batch write path exactly as REST does (§9.1). Lock accepts inbound gRPC messages of up to `maxBulkRequestBytes` plus 64 KiB of envelope (at least 10 MiB in the servlet `bridge` mode); a bulk body over `maxBulkRequestBytes` but inside that limit fails with `INVALID_ARGUMENT`, and a larger message is rejected by gRPC itself with `RESOURCE_EXHAUSTED`.

### 11.7 Discovery

When TRACE is enabled, Lock's configuration document (`/.well-known/lock-server-configuration`) publishes `trace_endpoint`, `trace_bulk_endpoint`, `trace_record_endpoint`, and `trace_execution_endpoint`. When TRACE is disabled, they are absent and every TRACE endpoint returns `400 invalid_request` with reason `trace_disabled`.

## 12. Idempotency and errors

| Condition | Required behavior |
|---|---|
| Same composite record identity and same `content_digest` | Return the original acceptance result with `idempotent_replay: true`; do not append a second receipt. |
| Same composite record identity and different `content_digest` | Return `409`; never overwrite the first record. |
| Unknown producer or `kid` | Reject (`unknown_producer_key`); nothing is stored or indexed. The MVP has no quarantine store. |
| `event_kind` outside the key's `authorized_event_kinds` | Reject; a key authorized for one event kind cannot sign another. |
| Invalid signature | Reject (`invalid_signature`); nothing is stored or indexed. |
| `producer` differs from `producer_chain.producer_id` | Reject. |
| Missing required execution scope | Reject in the MVP. |
| Missing predecessor in a registered chain | Accept and flag a coverage gap. |
| Non-genesis record on an unregistered chain | Reject (`chain_not_registered`, §8). |
| Client not allowed to submit for the signed producer | Reject (`403 producer_not_allowed`). |
| `signed_at` too far ahead of Lock's clock | Reject (`invalid_assertion`, reason `signed_at_in_future`). |
| Signed member that Lock derives itself | Accept; ignore the member and set `reserved_member_flag`. |
| Present predecessor with wrong digest | Accept and flag the chain-link failure; never report the chain as intact. |
| Same chain position, different `record_id`, and valid signatures | Store and flag both records as equivocation; never select one silently. |
| Record received substantially later than `signed_at` | Accept and set `late_flag: true` under a configurable lateness policy; lateness alone is not a rejection reason. |
| Storage or receipt append failure | Fail the request with `500 storage_failure`; no record or index entry may remain visible, except in the rare race described in §9. On the per-record path an allocated receipt position is settled `VOID` and stays in the receipt chain (§9). A failed batch transaction stores nothing and allocates nothing; its records fall back to the per-record path (§9.1). |

## 13. Minimum storage keys and indexes

The implementation needs only these keys and indexes:

- primary record key: `(evidence_domain_id, producer_id, record_id)`;
- execution index: `(evidence_domain_id, execution_authority, trace_execution_id)`;
- producer-chain position: `(evidence_domain_id, producer_id, producer_instance_id, producer_chain_id, sequence_number)`;
- token index: `(evidence_domain_id, issuer, jti-or-fingerprint)`; and
- receipt-chain position: `(evidence_domain_id, receipt_sequence)`; and
- policy store release: `(evidence_domain_id, policy_store_id, policy_store_version, bundle_hash)` for §11.5.

Capability resolution and the capability index (`(evidence_domain_id, capability_id)`), and session, workload, transaction, assessment, checkpoint, and graph-traversal indexes, may be added in later phases. The signed `(action, resource_type)` facts the MVP records make the capability index addable later without re-emitting records.

## 14. Security requirements

- Enforce TLS and OAuth on every TRACE endpoint.
- Derive the evidence domain before any key lookup or content-based routing.
- Apply maximum request size, nesting depth, string length, array length, and object member count before expensive cryptographic processing. Lock defaults: 256 KiB per record, depth 32, strings of 8192 characters, 256 array elements, 256 object members.
- Apply a maximum **batch size** (record count) and a maximum batch body size to `POST /api/v1/audit/trace/bulk` before cryptographic processing; a batch exceeding either is rejected with `400` at the envelope level, never partially processed past the limit.
- Acknowledge a record only after its rows are committed, on both write paths (§9). Never reuse a receipt position. A batch that cannot commit falls back to the per-record path, or fails closed when interrupted; it never drops or duplicates evidence (§9.1).
- Use constant-time cryptographic implementations and approved Ed25519 libraries. Lock has two interchangeable implementations, selected by `cryptoProvider`: `JAVA` (BouncyCastle, the default) and `NATIVE` (`jans-trace-core` through its `jans-trace-java` binding, `jans-trace-core-mvp-design.md` §9). Both produce the same `content_digest`, key thumbprint, and receipt hash. The selected one must load and pass its self-test; otherwise every submission fails with `500 crypto_unavailable`, with no fallback to the other.
- Never log raw bearer tokens or sensitive token claims.
- Preserve the original assertion and the exact verifying `kid` for historical verification.
- Treat producer timestamps as claims. Use `received_at` for Lock receipt order.
- Authorize reads within the same evidence domain as writes; never perform cross-domain fallback searches.
- Do not equate a valid signature with truth, completeness, independent observation, or successful enforcement.
- Do not label the MVP evidence as `settled`, `complete`, or externally anchored.

## 15. MVP acceptance criteria

The MVP is complete when all of the following tests pass:

1. A valid record from a client permitted to use the TRACE API is verified, stored unchanged, indexed, and assigned exactly one receipt sequence.
2. An invalid signature, unknown key, or mismatched producer identity never appears in normal retrieval.
3. Replaying identical content returns the original receipt without creating another entry.
4. Reusing a record identity with changed content cannot overwrite the accepted record.
5. Two producers may use the same `record_id` without collision because `producer_id` scopes identity.
6. Two issuers may use the same `jti` without collision because `issuer` scopes token identity.
7. A record may reference multiple tokens and all references are indexed.
8. A producer-chain gap is visible, and out-of-order arrival within a registered chain can resolve the gap without rewriting assertions.
9. Equivocation at one producer-chain position is visible and no conflicting record is silently preferred.
10. Execution retrieval never crosses an evidence domain and never silently guesses among ambiguous authorities.
11. The authorization decision and enforcement-point invocation can be retrieved under the same execution.
12. A failed write leaves neither a visible record nor an index entry (except the rare race in §9); on the per-record path a receipt position it allocated is settled `VOID` and the receipt chain still verifies, and a failed batch transaction leaves no receipt entry at all.
13. A record lookup never returns a matching identifier from another evidence domain.
14. An unscoped record or execution lookup with several in-domain matches returns an ambiguity error rather than selecting one.
15. A record signed by a key not authorized for its `producer_id`, or whose `event_kind` is outside the key's `authorized_event_kinds`, is rejected and never appears in normal retrieval — exactly as an unknown key is.
16. A stored record's recorded admission decision (`signature_valid`, `key_thumbprint`, `key_authorized`) is fixed at `verified_at`: later re-scoping, revocation, or validity-window changes to the key never rewrite it for an already-stored record.
17. A `POST /api/v1/audit/trace/bulk` batch with a mix of valid and invalid records accepts every valid record and rejects every invalid one on its own merits, each with its own per-record result and receipt; one record's failure never rejects an independently-valid record in the same batch, and a batch mixing producers is rejected at the envelope level.
18. With batch ingest on (§9.1), single and bulk submissions give the same per-record results, flags, and stored records as the per-record path; the new records of one successful batch transaction hold consecutive receipt sequences; and a failed batch transaction stores nothing and leaves every element to the per-record path, or fails it closed when interrupted.

## 16. Later phases

The concrete items the Jans MVP implementation deferred, with the condition for returning to each, are listed in `trace-mvp-post-mvp.md`, including scaling one evidence domain beyond one Lock node.

Phase 2 can add signed settlement assessments, receipt checkpoints, richer retrieval, token claims captured at decision time, and operation-binding commitments (including proof-of-possession binding). Phase 3 can add completeness and assurance profiles, delegation and authorization-state analysis, lineage validation, external transparency, and Evidence Packets for offline verification.

The AIMS/WIMSE identity and lifecycle features layer onto these phases without altering the MVP's accepted assertions: the WIMSE Agent Identifier profile and the AIMS-recognized credential metadata on `tokens[]`; the `workload_authentication` record of how a workload authenticated; credential-provisioning/posture evidence (`CREDENTIAL_PROVISIONED`); user-confirmation-vs-authorization evidence (`USER_CONFIRMATION_RECORDED` with the `APPROVAL_GRANTED` authorization-grant binding); token-exchange/transaction-token lineage and the forwarded-access-token anti-pattern finding; security-signal and remediation evidence (`SECURITY_SIGNAL_RECEIVED` / `REMEDIATION_APPLIED`); and the AIMS evidence-completeness profile that checks an execution against the AIMS audit minimum. Each is an additive `event_kind`, optional field, or Lock-derived assessment.

All later features should remain additive: they may assess, correlate, checkpoint, or package an accepted assertion, but must never rewrite it.
