# GovOps TRACE Collector conformance artifacts

Machine-readable conformance material for the [GovOps TRACE Collector API](../govops-trace-collector-api.md). Section 15 and Appendices C and E of the specification are generated from these files, so the specification and the artifacts cannot differ.

| File | Content |
|---|---|
| `requirements.json` | The requirement register: every normative statement with a stable identifier, level, role, capability, verification method, statement text, and the anchor text that ties it to the specification. Also the documented coverage exceptions. |
| `vectors.json` | Test keys (published seeds, test use only) and the test vectors: record content, `content_digest`, and signature validity. |
| `fixtures.json` | The deterministic initial state of every test: frozen clock, Collector configuration, authorization servers, submitters, producer key registry, registration-mode variants, and the definitions of generated bodies. |
| `tests.json` | The tests. Each maps to requirement identifiers and is mandatory or conditional on a capability. API tests carry their steps and expected responses. |
| `schema.json` | JSON Schema for `tests.json` and `requirements.json`. |
| `reference_model.py` | Executable model of the processing order (specification section 4.6) and the rules of sections 4 to 11. |
| `run_suite.py` | Validates the artifacts, runs the API tests against the model, checks coverage, and renders the tables. |

## What the reference model is, and is not

It is a **consistency checker**. Every expected response in `tests.json` must be one that the model produces. If a test contradicts the normative order, the run fails. For example, a test that submits a record whose `producer` the submitter may not use, and expects a verification error, fails: submitter authorization (step 7) comes first and returns `403`. The model also refuses limits below the minimums of section 5.8.

It is **not a Collector** and is not meant to be deployed. It models tokens abstractly, keeps state in memory, and has no network code. A certification suite sends the same steps to the Collector under test and compares the same expectations.

## Running

```sh
python3 -m pip install cryptography jsonschema      # jsonschema is optional
python3 run_suite.py                                 # validate, run, check coverage
python3 run_suite.py --spec ../govops-trace-collector-api.md   # also check requirement tags in the specification
python3 run_suite.py --render                        # print the test catalogue as Markdown
```

The exit status is 0 only if every API test passes against the model, the artifacts validate, every mandatory test-verifiable requirement is mapped to a test or to a documented exception, and (with `--spec`) every requirement still carries its identifier in the specification.

## Requirements

An identifier is `<AREA>-<NNN>` (a sentence with an RFC 2119 keyword) or `<AREA>-<letter><n>` (a table row or list item without one). `FW-n` and `CO-n` keep their original names. An identifier is never reused or renumbered. Each requirement has:

- `level`: `mandatory`, `recommended`, or `optional`;
- `role`: `collector`, `producer`, `forwarder`, `client`, `operator`, or `consumer`;
- `capability`: when the requirement applies only with an optional capability, otherwise `null`;
- `verification`: `test`, `behavior`, `inspection`, or `advisory`.

## Tests

- `applicability` is `mandatory` or `conditional`. A conditional test names a `capability` (see the table in section 15.3). It is not run, and does not count against an implementation, when the capability is absent.
- `strength` is `MUST` or `SHOULD`. A failed `SHOULD` test is a warning.
- `hooks_required` lists the hooks a test needs. A missing hook leaves the test `unverified`. It is never a pass.
- `kind` is `api` (steps with expected responses), `behavior` (a procedure for a producer or forwarder), or `manual` (an inspection or an unmodeled fault).
- `variants` runs a test in each registration-mode variant. `fixture` overrides the initial state for one test.

### Steps

| `op` | Fields |
|---|---|
| `submit` | `as` (submitter), `body`, optional `token` (overrides), `headers` (request headers), `content_type`, `content_encoding`, `scheme`, `no_token`, `label`, `expect` |
| `bulk` | as `submit`, with `body` a list |
| `lookup` | `as`, `producer` (percent-encoded), `record` (a vector identifier), `expect` |
| `metadata` | `expect.metadata` with `present`, `absent`, `equals`, `min`, `absent_strings`, and structure flags |
| `parallel` | `requests`, `expect.statuses` |
| `hook` | `action` and its arguments (see section 15.5 for the hook list) |
| `inspect` | `what` (`stored`, `count`, `assessment`, `chain_known`), `record` or `producer`/`chain`, `domain`, `expect` |

A `body` is a vector identifier, `{"raw": text}`, `{"json": value}`, `{"gen": {...}}`, or a list of these (a batch). Generators are `oversized_record`, `sized_record`, `deep_nesting`, `invalid_utf8`, `truncate`, `variant` (set members and re-sign), `padded_array`, and `count_array`. They are defined in `fixtures.json` and use the published test keys.

### Matchers

Expected values may be literals or matchers: `$clock`, `$nonempty`, `$ms_ts`, `$digest:V-01`, `$rid:V-01`, `$producer:V-01`, `$same:label[.member]`, `$ne:label[.member]`, `$opt:value` (equal if present), `$not:value`, `$present`, `$absent`, `$any`, `$issuer`.

### Implicit checks

Applied to every step: well-formed Problem Details whose status and `retryable` agree with the error table; `WWW-Authenticate` on every `401`; no token or signature material in an error body; required receipt members; the four integrity flags present in every receipt of a synchronous Collector and absent from every receipt of any other; no `idempotent_replay` in a lookup response.

## Determinism

The clock is frozen at the value in `fixtures.json` and moves only through the `set_clock` and `advance_clock` hooks, so `received_at` and every key-validity decision are reproducible. Receipt identifiers are opaque and are compared only with other receipts. A test never depends on the state another test left behind.

## Using the artifacts in a certification suite

1. Read the Collector's metadata. Derive its capabilities and its registration-mode variant.
2. For each test: skip it if its capability is absent. Otherwise put the Collector into the fixture state, apply the test's `fixture` overrides, and run the steps over HTTP. Report `unverified` if a required hook is missing.
3. Compare each response with the step's `expect`, including the implicit checks.
4. Report passed, failed, unverified, and not applicable per test, and the requirement identifiers each test covers.
5. Use `requirements.json` to list the mandatory requirements that no passed test covers.
