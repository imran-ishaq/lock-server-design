# Lock Server TRACE — Design

Design documents for adding **TRACE evidence collection** to the Janssen **Lock Server**.

TRACE records are signed, immutable statements about security-relevant events — authentication, authorization decisions, capability invocations, delegation, trust-boundary crossings, and observed runtime effects. Lock Server verifies these records, preserves each producer's original signed assertion unchanged, and correlates them into a verifiable **evidence graph** organized around a governed execution (`trace_execution_id`).

The goal is evidence that can be checked by someone **outside the producer's trust boundary**: attributable (who signed it), tamper-evident (the bytes have not changed), correlatable (which records belong to the same execution), and honest about what is *not* established (what is missing, what was not verified, which trust assumptions remain). A valid signature is necessary but is never treated as proof that a policy ran, an action occurred, or an effect was authorized.

This repository is **design documentation only**. It holds no Lock, Cedarling, or other product implementation. The `conformance/` directory holds machine-readable test artifacts and a small reference model that checks them for consistency; the model is not a Collector.

## Where to start

- **New to the project?** Read the [full design](design.md) overview, then the [MVP design](Lock-Server-TRACE-MVP-Design.md).
- **Implementing the first release?** Start from the [MVP design](Lock-Server-TRACE-MVP-Design.md) and the [phased implementation plan](phased-implementation-plan.md); Phase 1 *is* the MVP.
- **Integrating a producer** (Cedarling, Auth Server, FIDO Server)? Read that producer's companion doc below, then the [Collector API](govops-trace-collector-api.md) for the submission rules (retry, status codes, discovery).
- **Building or testing a Collector, or a client of one?** Read the vendor-neutral [GovOps TRACE Collector API](govops-trace-collector-api.md), the [record profile](govops-trace-profile.md), and the [conformance artifacts](conformance/README.md). The [Lock mapping](govops-trace-collector-lock-mapping.md) lists where Lock differs from the standard.
- **Looking for the product scope?** Read the [Gluu Ledger PRD](Gluu-Ledger-PRD.md).

## Core design

| Document | What it covers |
|---|---|
| [design.md](design.md) | **The full TRACE design.** The authoritative record model, verification/settlement pipeline, evidence graph, correlation, trust tiers and the per-dimension verification vector, capability resolution, evidence-domain isolation, lineage/anchoring, correctness properties, and alignment with the TRACE standard (v0.2). |
| [Lock-Server-TRACE-MVP-Design.md](Lock-Server-TRACE-MVP-Design.md) | **The MVP profile** — the smallest useful implementation (a strict subset of the full design): signed single/bulk ingestion over REST and gRPC (with an optional one-transaction batch-ingest mode), evidence-domain isolation, producer-key registration, the receipt hash chain, correlation, and ingestion-time integrity flagging. |
| [phased-implementation-plan.md](phased-implementation-plan.md) | How the full design is delivered incrementally. Phase 1 = the MVP; later phases add settlement, completeness/context, and full cross-domain assurance. |
| [govops-trace-profile.md](govops-trace-profile.md) | The **GovOps record profile** (`tag:govops.owasp.org,2026:trace-v1`) — the record-schema delta over the base TRACE v0.2 Trust Record (the nested `trace` envelope, the `event_kind` catalog, producer-chain and causal-edge fields, signed capability facts), what is deliberately *not* a signed-schema change (Collector-derived fields), and the cryptographic suite, genesis sentinel, identifier forms and array limits that the Collector API delegates to the profile (§15). |
| [govops-trace-collector-api.md](govops-trace-collector-api.md) | The **GovOps TRACE Collector API** — a vendor-neutral standard for submitting signed records: endpoints, OAuth submitter identity, processing order, idempotency and replay, bulk semantics, errors, discovery (`/.well-known/govops-trace-configuration`), intermediaries, and conformance (requirement IDs, classes, and tests). It does not name Lock. |
| [govops-trace-collector-lock-mapping.md](govops-trace-collector-lock-mapping.md) | How Lock maps to the standard: the deviations of the implemented Lock (D1 to D20), findings specific to `design.md`, the error-code mapping, the metadata values, and the open decisions. |
| [conformance/](conformance/README.md) | Machine-readable conformance artifacts for the standard (requirements, signed vectors, fixtures, tests, a JSON schema) and a reference model with a runner that checks them for consistency. |
| [jans-trace-core-mvp-design.md](jans-trace-core-mvp-design.md) | The reusable **`jans-trace-core`** Rust library for the deterministic cryptographic operations (JCS canonicalization, Ed25519 signing/verification, content-digest, receipt-chain hashing) shared by producers, Lock, and independent verifiers. |
| [trace-mvp-post-mvp.md](trace-mvp-post-mvp.md) | What the Jans MVP implementation (Lock, Cedarling, `jans-trace-core`) deferred, why, and when to return to each item. |

## Producer integrations

Each TRACE producer signs its own records with its own key. These companion docs map each Jans component onto the record model, with a full-design version and an MVP-scoped version.

| Producer | Produces | Full design | MVP scope |
|---|---|---|---|
| **Cedarling** (PDP) | `AUTHORIZATION_DECISION` | [cedarling-trace-design.md](cedarling-trace-design.md) | [cedarling-trace-design-MVP.md](cedarling-trace-design-MVP.md) |
| **Jans Auth Server** (OP) | `AUTHENTICATION_EVENT`, execution bootstrap | [auth-server-trace-design.md](auth-server-trace-design.md) | [auth-server-trace-design-MVP.md](auth-server-trace-design-MVP.md) |
| **Jans FIDO Server** | `FIDO_CEREMONY` | [fido-trace-design.md](fido-trace-design.md) | [fido-trace-design-MVP.md](fido-trace-design-MVP.md) |

**Producer roles in the MVP, at a glance:** Cedarling is a first-class MVP producer (it signs one of the three MVP event kinds). The Auth Server has only a thin MVP role — stamping the execution-correlation pair into issued token claims — since authentication events are deferred. The FIDO Server has no MVP role (its `FIDO_CEREMONY` is deferred). The three MVP companion docs explain each case.

## Related designs

| Document | What it covers |
|---|---|
| [Gluu-Ledger-PRD.md](Gluu-Ledger-PRD.md) | Product requirements for Gluu Ledger, the commercial product built on Lock, with release gates that include Collector API conformance. |
| [hardware-anchored-identity.md](hardware-anchored-identity.md) | Hardware-anchored agent identity (attested keys, JWT-SVID issuance) in the Auth Server, and the TRACE evidence it emits. [Implementation appendix](hardware-anchored-identity-implementation.md) and [review history](hardware-anchored-identity-review-history.md). |

## Key concepts

- **Producer vs. Lock.** Producers sign *facts they observed*; Lock derives *interpretations* (trust tier, settlement, completeness, capability resolution) and stores them **outside** the immutable signed assertion.
- **Execution, not session.** Evidence is organized around `trace_execution_id` (a governed unit of work), with human sessions as one optional dimension.
- **Enforcement separation.** `CAPABILITY_INVOKED` is signed by the enforcement point's own key, never the PDP's — even when Cedarling is embedded in the enforcing application (two producers, two keys, one process).
- **Standard alignment.** Lock emits a distinct Jans profile (`tag:jans.io,2026:trace-v1`) that extends the TRACE standard (tracked at **v0.2**); see *Alignment with TRACE v0.2* in [design.md](design.md). The vendor-neutral GovOps profile (`tag:govops.owasp.org,2026:trace-v1`) shares its cryptographic suite, and Lock lists both tags while producers migrate.
- **Interface versus implementation.** The Collector API defines what any Collector does at its boundary. The MVP documents describe what Lock implements today, and [the mapping](govops-trace-collector-lock-mapping.md) records the difference. `design.md` is the target design and follows the standard.

## Repository layout

```
design.md                          Full TRACE design (authoritative)
Lock-Server-TRACE-MVP-Design.md    MVP profile (Phase 1)
phased-implementation-plan.md      Phased delivery plan
govops-trace-profile.md            GovOps record profile (delta from TRACE v0.2, cryptographic suite, limits)
jans-trace-core-mvp-design.md      Shared Rust crypto library design
trace-mvp-post-mvp.md              Post-MVP backlog from the implementation
cedarling-trace-design*.md         Cedarling producer (full + MVP)
auth-server-trace-design*.md       Auth Server producer (full + MVP)
fido-trace-design*.md              FIDO Server producer (full + MVP)
govops-trace-collector-api.md      GovOps TRACE Collector API standard (vendor-neutral)
govops-trace-collector-lock-mapping.md   Lock Server mapping and required changes for that standard
conformance/                       Machine-readable conformance artifacts for the standard
Gluu-Ledger-PRD.md                 Product requirements for Gluu Ledger
hardware-anchored-identity*.md     Hardware-anchored agent identity design, implementation appendix, review history
```

The `research/` directory holds background source material (the TRACE spec, Jans component docs, and code references) used while writing these designs; it is not part of the design deliverable. The `conformance/` directory holds JSON artifacts (requirements, vectors, fixtures, tests) and a small reference model that checks them for consistency. The model is not a Collector implementation.
