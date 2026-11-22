#!/usr/bin/env python3
"""Run the GovOps TRACE Collector conformance artifacts against the reference model.

  python3 run_suite.py                  validate artifacts, run every runnable test, report coverage
  python3 run_suite.py --render         print the Markdown tables for section 15
  python3 run_suite.py --spec FILE      also check requirement anchors against the specification text

Exit status is 0 only if all checks pass.
"""
import copy, json, os, re, sys
from reference_model import Model, ERRORS, Resp, jcs, digest_of, fmt_time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import base64, hashlib

HERE = os.path.dirname(os.path.abspath(__file__))
load = lambda n: json.load(open(os.path.join(HERE, n)))
FX, VEC, TESTS, REQS = load("fixtures.json"), load("vectors.json"), load("tests.json"), load("requirements.json")
REQ = {r["id"]: r for r in REQS["requirements"]}
b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()


# ------------------------------------------------------------------ bodies
def vtext(vid):
    v = VEC["vectors"][vid]
    return v["content"] if v["kind"] == "raw_text" else json.dumps(v["content"], separators=(",", ":"), ensure_ascii=False)


def sign_record(rec, key_name):
    k = VEC["keys"][key_name]
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(k["seed_hex"]))
    r = {m: v for m, v in rec.items() if m != "signature"}
    r["signature"] = b64u(sk.sign(jcs(r).encode("utf-8")))
    return r


def gen(spec, model):
    (name, a), = spec.items()
    if name == "oversized_record":
        base = copy.deepcopy(VEC["vectors"][a["base"]]["content"])
        limit = model.col["limits"][a["limit"]]; target = limit + a.get("delta", 0)
        base["record_id"] = "0191f3a0-7c00-7000-8000-%012x" % (target % (16 ** 12))
        pk = base["producer"] + "/" + base["kid"]
        base["trace"]["x_pad"] = ""
        size0 = len(json.dumps(sign_record(base, pk), separators=(",", ":"), ensure_ascii=False).encode())
        base["trace"]["x_pad"] = "a" * (target - size0)
        rec = sign_record(base, pk)
        size = len(json.dumps(rec, separators=(",", ":"), ensure_ascii=False).encode())
        assert size == target, (size, target)
        return json.dumps(rec, separators=(",", ":"), ensure_ascii=False).encode()
    if name == "sized_record":
        a = dict(a, limit="max_record_bytes", delta=0); target = a.pop("bytes")
        model = type("M", (), {"col": {"limits": {"max_record_bytes": target}}})()
        return gen({"oversized_record": a}, model)
    if name == "padded_array":
        n = model.col["limits"][a["limit"]] + a.get("delta", 0)
        return b'["' + b"a" * (n - 4) + b'"]'
    if name == "count_array":
        n = model.col["limits"][a["limit"]] + a.get("delta", 0)
        return b"[" + b",".join([b"0"] * n) + b"]"
    if name == "deep_nesting":
        base = copy.deepcopy(VEC["vectors"][a["base"]]["content"]); node = base["trace"]["x_deep"] = {}
        for _ in range(a["depth"]): node["n"] = {}; node = node["n"]
        return json.dumps(sign_record(base, base["producer"] + "/" + base["kid"]), separators=(",", ":")).encode()
    if name == "invalid_utf8":
        t = vtext(a["base"]).encode(); i = t.index(b"payments-gateway")
        return t[:i] + b"\xc3\x28" + t[i + 1:]
    if name == "truncate":
        return vtext(a["base"]).encode()[: a["keep"]]
    if name == "variant":
        rec = copy.deepcopy(VEC["vectors"][a["base"]]["content"])
        for path, val in a["set"].items():
            node = rec; parts = path.split(".")
            for p in parts[:-1]: node = node[p]
            node[parts[-1]] = val
        return json.dumps(sign_record(rec, a["sign_with"]), separators=(",", ":"), ensure_ascii=False).encode()
    raise ValueError(name)


def item(x, model):
    if isinstance(x, str): return vtext(x).encode()
    if "raw" in x: return x["raw"].encode()
    if "json" in x: return json.dumps(x["json"]).encode()
    if "gen" in x: return gen(x["gen"], model)
    raise ValueError(x)


def body_of(spec, model):
    if spec is None: return b""
    if isinstance(spec, list): return b"[" + b",".join(item(x, model) for x in spec) + b"]"
    return item(spec, model)


# ------------------------------------------------------------------ expectations
class Ctx:
    def __init__(self, model): self.m = model; self.labels = {}; self.fails = []

    def fail(self, msg): self.fails.append(msg)

    def match(self, want, got, where):
        if isinstance(want, str) and want.startswith("$"):
            tag, _, arg = want[1:].partition(":")
            if tag == "any": return
            if tag == "clock": return self.eq(fmt_time(self.m.clock), got, where)
            if tag == "nonempty":
                if not (isinstance(got, str) and got): self.fail(f"{where}: expected non-empty string, got {got!r}")
                return
            if tag == "ms_ts":
                if not (isinstance(got, str) and re.match(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$", got)): self.fail(f"{where}: not a ms timestamp: {got!r}")
                return
            if tag == "not":
                if got == arg: self.fail(f"{where}: must not equal {arg!r}")
                return
            if tag == "digest": return self.eq(VEC["vectors"][arg]["content_digest"], got, where)
            if tag == "rid": return self.eq(VEC["vectors"][arg]["content"]["record_id"], got, where)
            if tag == "producer": return self.eq(VEC["vectors"][arg]["content"]["producer"], got, where)
            if tag in ("same", "ne"):
                lab, _, field = arg.partition(".")
                ref = self.labels[lab]
                for part in (field or where.split(".")[-1]).split("."): ref = ref[part]
                if tag == "same": return self.eq(ref, got, where)
                if ref == got: self.fail(f"{where}: expected a value different from {ref!r}")
                return
            if tag == "issuer": return self.eq(self.m.col["issuer"], got, where)
            raise ValueError(want)
        if isinstance(want, dict):
            if not isinstance(got, dict): return self.fail(f"{where}: expected object, got {got!r}")
            for k, v in want.items():
                if isinstance(v, str) and v.startswith("$opt:"):
                    if k in got: self.eq(v[5:], got[k], f"{where}.{k}")
                elif v == "$absent":
                    if k in got: self.fail(f"{where}.{k}: expected absent")
                elif k not in got: self.fail(f"{where}.{k}: missing")
                else: self.match(v, got[k], f"{where}.{k}")
            return
        self.eq(want, got, where)

    def eq(self, want, got, where):
        if want != got: self.fail(f"{where}: expected {want!r}, got {got!r}")

    FLAGS = {"coverage_gap": "coverage_gap_flag", "chain_link_failure": "chain_link_failure_flag", "equivocation": "equivocation_flag", "late": "late_flag"}

    def receipt(self, rc, want, where, replay_lookup=False):
        sync = self.m.col["synchronous_integrity_flags"]
        for f in self.FLAGS.values():
            if sync and f not in rc: self.fail(f"{where}: flag {f} missing on a synchronous Collector")
            if not sync and f in rc: self.fail(f"{where}: flag {f} present on an asynchronous Collector")
        for need in ("accepted", "producer_id", "record_id", "content_digest", "receipt_id", "received_at"):
            if need not in rc: self.fail(f"{where}: receipt member {need} missing")
        if replay_lookup and "idempotent_replay" in rc: self.fail(f"{where}: idempotent_replay present in a lookup response")
        if not replay_lookup and "idempotent_replay" not in rc: self.fail(f"{where}: idempotent_replay missing")
        want = dict(want or {})
        fl = want.pop("flags", None)
        if fl is not None and sync:
            fl = {k: False for k in self.FLAGS} if fl == "none" else fl
            for k, v in fl.items(): self.eq(v, rc.get(self.FLAGS[k]), f"{where}.{self.FLAGS[k]}")
        self.match(want, rc, where)

    def problem(self, p, where):
        for k in ("type", "title", "status", "code", "retryable"):
            if k not in p: self.fail(f"{where}: Problem Details member {k} missing")
        if p.get("code") in ERRORS:
            st, rt = ERRORS[p["code"]]
            if (p["status"], p["retryable"]) != (st, rt): self.fail(f"{where}: status/retryable do not match the error table for {p['code']}")
        else:
            self.fail(f"{where}: unknown code {p.get('code')}")
        if not str(p.get("type", "")).startswith("https://govops.owasp.org/trace/errors/"): self.fail(f"{where}: bad problem type")
        blob = json.dumps(p)
        if "eyJ" in blob or "signature" in p: self.fail(f"{where}: problem leaks token or signature material")

    def response(self, r, ex, where):
        if ex.get("status") == "refused":
            return self.eq("refused", r.status, where + ".status")
        if "status" in ex: self.eq(ex["status"], r.status, where + ".status")
        is_problem = isinstance(r.body, dict) and "code" in r.body and "accepted" not in r.body
        if is_problem:
            self.problem(r.body, where)
            if r.status == 401 and "WWW-Authenticate" not in r.headers: self.fail(f"{where}: 401 without WWW-Authenticate")
        if "code" in ex:
            self.eq(ex["code"], r.body.get("code") if is_problem else None, where + ".code")
        if "code_in" in ex and not (is_problem and r.body.get("code") in ex["code_in"]): self.fail(f"{where}: code {r.body.get('code') if is_problem else None} not in {ex['code_in']}")
        if "retryable" in ex and is_problem: self.eq(ex["retryable"], r.body["retryable"], where + ".retryable")
        if "problem" in ex: self.match(ex["problem"], r.body, where + ".problem")
        if "receipt" in ex or "flags" in ex:
            rc = r.body
            if not isinstance(rc, dict) or rc.get("accepted") is not True: return self.fail(f"{where}: expected a receipt, got {rc!r}")
            w = dict(ex.get("receipt", {}))
            if "flags" in ex: w["flags"] = ex["flags"]
            self.receipt(rc, w, where + ".receipt", replay_lookup=ex.get("lookup", False))
        if "headers" in ex:
            for h, v in ex["headers"].items():
                got = r.headers.get(h)
                if v == "$absent":
                    if got is not None: self.fail(f"{where}: header {h} unexpectedly present")
                elif v == "$present":
                    if got is None: self.fail(f"{where}: header {h} missing")
                elif got is None or not re.search(v, got): self.fail(f"{where}: header {h}={got!r} does not match {v!r}")
        if "results" in ex:
            res = (r.body or {}).get("results")
            if res is None or len(res) != len(ex["results"]): return self.fail(f"{where}: expected {len(ex['results'])} results, got {None if res is None else len(res)}")
            for i, (w, g) in enumerate(zip(ex["results"], res)):
                wh = f"{where}.results[{i}]"
                self.eq(i, g.get("index"), wh + ".index")
                self.eq(w["accepted"], g.get("accepted"), wh + ".accepted")
                if w["accepted"]:
                    ww = dict(w.get("receipt", {}))
                    if "flags" in w: ww["flags"] = w["flags"]
                    self.receipt({k: v for k, v in g.items() if k != "index"}, ww, wh)
                    if "label" in w: self.labels[w["label"]] = g
                else:
                    self.problem(g["error"], wh + ".error")
                    if "code" in w: self.eq(w["code"], g["error"]["code"], wh + ".error.code")
                    if "status" in w: self.eq(w["status"], g["error"]["status"], wh + ".error.status")
        if "metadata" in ex: self.metadata(r.body, ex["metadata"], where)
        if "body" in ex: self.match(ex["body"], r.body, where + ".body")

    def metadata(self, m, ex, where):
        for k in ex.get("present", []):
            if k not in m: self.fail(f"{where}: metadata member {k} missing")
        for k in ex.get("absent", []):
            if k in m: self.fail(f"{where}: metadata member {k} unexpectedly present")
        for k, v in ex.get("equals", {}).items(): self.match(v, m.get(k), f"{where}.{k}")
        for s in ex.get("absent_strings", []):
            if s in json.dumps(m): self.fail(f"{where}: metadata discloses {s!r}")
        if ex.get("profile_entries"):
            for p in m["trace_profiles"]:
                for k in ("profile", "signature_algorithms_supported", "canonicalization", "content_digest_algorithm"):
                    if k not in p: self.fail(f"{where}: profile entry lacks {k}")
        if ex.get("authorization_server_entries"):
            for a in m["authorization_servers"]:
                for k in ("issuer", "token_format"):
                    if k not in a: self.fail(f"{where}: authorization server entry lacks {k}")
        if "min" in ex:
            for k, v in ex["min"].items():
                if not m.get(k, 0) >= v: self.fail(f"{where}: {k} < {v}")
        if ex.get("disjoint"):
            a, b = ex["disjoint"]
            if set(m.get(a, [])) & set(x["profile"] if isinstance(x, dict) else x for x in m.get(b, [])) or set(x["profile"] for x in m.get(b, []) if isinstance(x, dict)) & set(m.get(a, [])):
                self.fail(f"{where}: {a} and {b} overlap")
        if ex.get("receipt_template"):
            t = m.get("trace_receipt_endpoint", "")
            if "{producer_id}" not in t or "{record_id}" not in t: self.fail(f"{where}: receipt endpoint is not a template with both variables")
            if m.get("receipt_scope") in (None, m.get("ingestion_scope")): self.fail(f"{where}: receipt_scope missing or equal to ingestion_scope")


# ------------------------------------------------------------------ running
def run_steps(test, model, cx):
    for n, st in enumerate(test["steps"], 1):
        op = st["op"]; where = f"{test['id']} step {n} ({op})"
        if op == "hook":
            a = {k: v for k, v in st.items() if k not in ("op", "action")}
            if st["action"] == "register_key":
                src = a.pop("key_from"); key = copy.deepcopy(next(k for k in FX["registry"]["D1"]["keys"] if k["producer_id"] + "/" + k["kid"] == src))
                key.update(a.pop("patch", {})); model.hook("register_key", domain=a["domain"], key=key)
            elif st["action"] == "set_as":
                for a2 in model.as_by_issuer.values():
                    if a2["name"] == a["as"]: a2.update(a["patch"])
            elif st["action"] == "set_modes": model.modes = list(a["modes"])
            else: model.hook(st["action"], **a)
            continue
        if op == "inspect":
            r = model.inspect(st["what"], st.get("domain", "D1"), VEC["vectors"][st["record"]]["content"]["producer"] if "record" in st and st["what"] != "chain_known" else st.get("producer"),
                              VEC["vectors"][st["record"]]["content"]["record_id"] if "record" in st and st["what"] != "chain_known" else st.get("chain"))
            if st["what"] == "stored" and r["present"]:
                e = model.records[(st.get("domain", "D1"), VEC["vectors"][st["record"]]["content"]["producer"], VEC["vectors"][st["record"]]["content"]["record_id"])]
                r["digest"] = e["digest"]
            cx.match(st.get("expect", {}), r, where); continue
        if op in ("submit", "bulk", "lookup", "metadata", "parallel"):
            tok = model.token_for(st["as"], st.get("token")) if "as" in st else None
            if "no_token" in st: tok = None
            ex = st.get("expect", {})
            if op == "metadata": r = model.metadata()
            elif op == "submit":
                r = model.submit(tok, body_of(st.get("body"), model), scheme=st.get("scheme", "https"), content_type=st.get("content_type", "application/json"), content_encoding=st.get("content_encoding"), headers=st.get("headers"))
            elif op == "bulk":
                r = model.bulk(tok, body_of(st.get("body"), model), content_type=st.get("content_type", "application/json"))
            elif op == "lookup":
                rid = VEC["vectors"][st["record"]]["content"]["record_id"] if st["record"].startswith("V-") else st["record"]
                r = model.lookup(tok, st["producer"], rid)
            else:
                rs = [model.submit(model.token_for(p["as"]), body_of(p["body"], model)) for p in st["requests"]]
                got = sorted(x.status for x in rs)
                if got != sorted(ex["statuses"]): cx.fail(f"{where}: statuses {got} != {sorted(ex['statuses'])}")
                rcs = {x.body.get("receipt_id") for x in rs if isinstance(x.body, dict) and "receipt_id" in x.body}
                if ex.get("one_receipt") and len(rcs) != 1: cx.fail(f"{where}: expected exactly one receipt_id, got {rcs}")
                continue
            cx.response(r, ex, where)
            if "label" in st and isinstance(r.body, dict): cx.labels[st["label"]] = r.body
            continue
        raise ValueError(op)


def run_test(test, variants_default="M1"):
    out = []
    if test.get("kind") in ("behavior", "manual"):
        return [("n/a", None)]
    for variant in test.get("variants") or [test.get("fixture", {}).get("variant", variants_default)]:
        ov = copy.deepcopy(test.get("fixture", {})); ov["variant"] = variant
        for hn, vv in (ov.pop("authorization_servers", {}) or {}).items(): ov.setdefault("_as", {})[hn] = vv
        model = Model(FX, VEC, ov)
        for hn, patch in (ov.get("_as") or {}).items():
            for a in model.as_by_issuer.values():
                if a["name"] == hn: a.update(patch)
            model.fx["authorization_servers"][hn].update(patch)
        cx = Ctx(model)
        try:
            run_steps(test, model, cx)
        except Exception as e:  # a model or authoring error
            cx.fail(f"exception {type(e).__name__}: {e}")
        out.append((variant, cx.fails))
    return out


# ------------------------------------------------------------------ checks
def check_artifacts():
    errs = []
    ids = [t["id"] for t in TESTS["tests"]]
    for i in set(ids):
        if ids.count(i) > 1: errs.append(f"duplicate test id {i}")
    for t in TESTS["tests"]:
        for r in t["requirements"]:
            if r not in REQ: errs.append(f"{t['id']}: unknown requirement {r}")
        if not t["requirements"]: errs.append(f"{t['id']}: maps to no requirement")
        for st in t.get("steps", []):
            for x in ([st.get("body")] if not isinstance(st.get("body"), list) else st["body"]):
                for v in ([x] if isinstance(x, str) else []):
                    if v.startswith("V-") and v not in VEC["vectors"]: errs.append(f"{t['id']}: unknown vector {v}")
        if t.get("applicability") == "conditional" and not t.get("capability"): errs.append(f"{t['id']}: conditional test without capability")
        if t.get("applicability") == "mandatory" and t.get("capability"): errs.append(f"{t['id']}: mandatory test with capability")
    try:
        import jsonschema
        sch = load("schema.json")
        for name, doc, key in (("tests", TESTS, "tests"), ("requirements", REQS, "requirements")):
            for e in jsonschema.Draft202012Validator({**sch["$defs"][name], "$defs": sch["$defs"]}).iter_errors(doc):
                errs.append(f"schema {name}: {list(e.path)[:3]} {e.message[:100]}")
    except ImportError:
        pass
    return errs


def coverage():
    covered = {}
    for t in TESTS["tests"]:
        for r in t["requirements"]: covered.setdefault(r, []).append(t["id"])
    miss = []
    for r in REQS["requirements"]:
        if r["level"] == "mandatory" and r["verification"] in ("test", "behavior") and r["id"] not in covered and r["id"] not in REQS["coverage_exceptions"]:
            miss.append(r["id"])
    return covered, miss


def main():
    errs = check_artifacts()
    bad = 0
    for t in TESTS["tests"]:
        for variant, fails in run_test(t):
            if fails:
                bad += 1; print(f"FAIL {t['id']} [{variant}] {t['title']}")
                for f in fails[:6]: print("     ", f)
    covered, miss = coverage()
    print(f"tests: {len(TESTS['tests'])}, failing: {bad}")
    print(f"artifact errors: {len(errs)}"); [print("  ", e) for e in errs[:30]]
    print(f"mandatory test-verifiable requirements without a test: {len(miss)}"); [print("  ", m) for m in miss]
    if "--spec" in sys.argv:
        spec = open(sys.argv[sys.argv.index("--spec") + 1]).read().split("\n"); drift = []
        for r in REQS["requirements"]:
            tag = "[" + r["id"] + "]"
            lines = [l for l in spec if tag in l]
            key = r["anchor"].strip().rstrip("| ")[:40] if r["anchor"] else ""
            if r["id"].startswith(("FW-", "CO-")): ok = any(("**" + r["id"] + "**") in l for l in spec)
            else: ok = len(lines) == 1 and key in lines[0]
            if not ok: drift.append(r["id"])
        print("requirements whose text drifted or lost their identifier tag:", len(drift), drift[:20])
        bad += len(drift)
    return 0 if not (bad or errs or miss) else 1



# ------------------------------------------------------------------ rendering (section 15 and appendices)
CAPS = {"bulk": "Collector-Bulk (bulk endpoint offered)", "receipt_lookup": "receipt lookup offered", "sync_flags": "`synchronous_integrity_flags` true",
        "async_flags": "`synchronous_integrity_flags` false or absent", "multi_as": "two or more authorization servers trusted", "introspection": "an authorization server with `token_format` `introspection`",
        "sender_constrained": "DPoP or mTLS supported", "configurable_client_id_claim": "a configurable client identifier claim", "gzip": "`gzip` content encoding advertised",
        "unattributed": "`execution_correlation_required` false", "mixed_producers": "`bulk_mixed_producers_supported` true", "profile_withdrawal": "a profile can be withdrawn to replay-only",
        "multiple_profiles": "more than one profile listed", "rate_limiting": "rate limiting applied", "integrity_hold": "an integrity-hold state exists", "bulk_absent": "bulk endpoint not offered",
        "chain_mode:first_observed": "modes are `first_observed_genesis` only (variant M1)", "chain_mode:pre_registered": "modes are `pre_registered_genesis` only (variant M2)",
        "chain_mode:both": "both modes listed (variant M3)", "durability_claim": "`acceptance_durability` advertised"}
GROUPS = [("C", "Collector: submission, verification, acceptance, key validity"), ("A", "Authentication and submitter identity"), ("G", "Chain admission, integrity, completeness"),
          ("R", "Replay, retention, and configuration changes"), ("L", "Receipt lookup"), ("B", "Bulk submission"), ("D", "Discovery"), ("P", "Producer behavior"), ("F", "Forwarder behavior")]
HOOKS = {"set_clock": "set the Collector clock", "advance_clock": "advance the Collector clock", "set_key": "change a registered key's window", "register_key": "register a key in an evidence domain",
         "register_chain": "register a producer chain", "unregister_chain": "remove a chain registration", "set_limit": "set a limit (not below the specification's minimum)",
         "set_collector": "set a Collector configuration value", "add_schema_rule": "add a record-content rule", "set_profile_state": "withdraw a profile to replay-only",
         "set_submitter": "change a submitter's binding, scopes, or permissions", "set_rate_limit": "apply a request rate limit", "fail_commit": "make the next durable commit fail",
         "set_modes": "change the chain registration modes", "set_as": "change an authorization server's token profile"}


def q(x): return "`" + str(x) + "`"


def dbody(b, labels=None):
    if b is None: return "an empty body"
    if isinstance(b, str): return b
    if isinstance(b, list): return "[" + ", ".join(dbody(x) for x in b) + "]"
    if "raw" in b: return "the text " + q(b["raw"])
    if "json" in b: return "the JSON value " + q(json.dumps(b["json"]))
    g = list(b["gen"].items())[0]; n, a = g
    return {"oversized_record": lambda: f"a generated copy of {a['base']} that is {a['limit']} {'+ %d' % a['delta'] if a.get('delta') else ''} bytes".replace("  ", " "),
            "sized_record": lambda: f"a generated copy of {a['base']} of {a['bytes']} bytes", "deep_nesting": lambda: f"a generated copy of {a['base']} nested {a['depth']} levels deep",
            "invalid_utf8": lambda: f"{a['base']} with an invalid UTF-8 byte", "truncate": lambda: f"{a['base']} cut after {a['keep']} characters",
            "variant": lambda: f"a generated, re-signed copy of {a['base']} with {', '.join(k + ' = ' + json.dumps(v)[:40] for k, v in a['set'].items())}",
            "padded_array": lambda: f"an array padded to {a['limit']} + {a.get('delta', 0)} bytes", "count_array": lambda: f"an array of {a['limit']} + {a.get('delta', 0)} elements"}[n]()


def dstep(st, num):
    op = st["op"]
    if op == "hook":
        a = {k: v for k, v in st.items() if k not in ("op", "action")}
        det = ", ".join(f"{k} {json.dumps(v)}" if not isinstance(v, dict) else f"{k} {json.dumps(v)[:60]}" for k, v in a.items())
        return f"(hook) {HOOKS.get(st['action'], st['action'])}: {det}"
    if op == "inspect": return f"inspect {st['what']}" + (f" of {st['record']}" if "record" in st else "") + (f" in {st['domain']}" if st.get("domain", "D1") != "D1" else "")
    if op == "metadata": return "read the metadata"
    who = "no token" if st.get("no_token") else q(st.get("as", "?"))
    extra = []
    if st.get("token"): extra.append("token " + q(json.dumps(st["token"], separators=(",", ":"))))
    for k in ("content_type", "content_encoding", "scheme"):
        if st.get(k): extra.append(f"{k.replace('_', ' ')} {q(st[k])}")
    if st.get("headers"): extra.append("request headers " + q(json.dumps(st["headers"], separators=(",", ":"))))
    ex = (" (" + "; ".join(extra) + ")") if extra else ""
    if op == "submit": return f"{who} submits {dbody(st.get('body'))}{ex}"
    if op == "bulk": return f"{who} submits a batch {dbody(st.get('body'))}{ex}"
    if op == "lookup": return f"{who} looks up {q(st['producer'])} / {st['record']}{ex}"
    if op == "parallel": return "concurrently: " + " and ".join(f"{q(r['as'])} submits {dbody(r['body'])}" for r in st["requests"])


def dmatch(k, v, lab):
    if isinstance(v, str) and v.startswith("$"):
        t, _, a = v[1:].partition(":")
        return {"clock": f"{k} = the clock", "nonempty": f"{k} present", "ms_ts": f"{k} has millisecond form", "digest": f"{k} = digest of {a}", "rid": f"{k} = record_id of {a}", "producer": f"{k} = producer of {a}",
                "same": f"{k} same as step {lab.get(a.split('.')[0], '?')}", "ne": f"{k} differs from step {lab.get(a.split('.')[0], '?')}", "opt": f"{k} = {a} if present", "not": f"{k} is not {a[:14]}...", "absent": f"{k} absent", "present": f"{k} present", "any": f"{k} any", "issuer": f"{k} = the Collector's issuer"}[t]
    if isinstance(v, bool): return f"{k} {str(v).lower()}"
    return f"{k} {json.dumps(v)}"


def dexpect(ex, lab):
    p = []
    if "status" in ex: p.append("refused" if ex["status"] == "refused" else q(ex["status"]) + (" " + q(ex["code"]) if "code" in ex else ""))
    elif "code" in ex: p.append(q(ex["code"]))
    if "code_in" in ex: p.append("one of " + ", ".join(q(c) for c in ex["code_in"]))
    if "retryable" in ex: p.append(f"retryable {str(ex['retryable']).lower()}")
    if "problem" in ex: p.append(", ".join(dmatch(k, v, lab) for k, v in ex["problem"].items()))
    if "receipt" in ex:
        keys = ("idempotent_replay", "chain_admission", "unattributed_flag")
        r = ex["receipt"]; sel = [dmatch(k, r[k], lab) for k in r if k in keys or isinstance(r[k], str) and r[k].startswith(("$same", "$ne", "$not"))]
        if sel: p.append("receipt: " + ", ".join(sel))
        elif r: p.append("receipt present")
    if "flags" in ex:
        f = ex["flags"]; p.append("all four flags false" if f == "none" else "flags: " + ", ".join(f"{k} {str(v).lower()}" for k, v in f.items() if v) + " (others false)")
    if "headers" in ex: p.append("headers: " + ", ".join(f"{h} {'present' if v == '$present' else v}" for h, v in ex["headers"].items()))
    if "results" in ex:
        out = []
        for i, w in enumerate(ex["results"]):
            if w["accepted"]:
                r = w.get("receipt", {}); out.append(f"[{i}] accepted" + (", replay" if r.get("idempotent_replay") is True else "") + (", " + ("gap flag set" if isinstance(w.get("flags"), dict) and w["flags"].get("coverage_gap") else "") if isinstance(w.get("flags"), dict) and w["flags"].get("coverage_gap") else ""))
            else: out.append(f"[{i}] {w.get('code')}" + (f" ({w['status']})" if w.get("status") else ""))
        p.append("results " + "; ".join(out))
    if "metadata" in ex:
        m = ex["metadata"]
        for k in ("present", "absent"):
            if k in m: p.append(f"{k}: " + ", ".join(m[k]))
        if "equals" in m: p.append(", ".join(dmatch(k, v, lab) for k, v in m["equals"].items()))
        if "min" in m: p.append(", ".join(f"{k} at least {v}" for k, v in m["min"].items()))
        if m.get("absent_strings"): p.append("no tenant, client, producer, or key names")
        if m.get("profile_entries"): p.append("each profile entry has its cryptographic members")
        if m.get("authorization_server_entries"): p.append("each authorization server entry has issuer and token_format")
        if m.get("receipt_template"): p.append("template with both variables; scope differs from the ingestion scope")
        if m.get("disjoint"): p.append("the two profile lists do not overlap")
    for k in ("present", "digest", "count", "known", "coverage_gap_flag", "chain_link_failure_flag", "equivocation_flag", "key", "verified_at", "received_at"):
        if k in ex: p.append(dmatch(k, ex[k], lab) if not isinstance(ex[k], list) else f"{k} {ex[k]}")
    if "statuses" in ex: p.append("statuses " + ", ".join(q(s) for s in ex["statuses"]) + (", one receipt" if ex.get("one_receipt") else ""))
    return ", ".join(x for x in p if x)


def render_test(t):
    if t.get("kind") in ("behavior", "manual"):
        proc, exp = t["procedure"], t["expected"]
    else:
        lab = {}
        for i, st in enumerate(t["steps"], 1):
            if st.get("label"): lab[st["label"]] = i
            for j, w in enumerate((st.get("expect") or {}).get("results", [])):
                if w.get("label"): lab[w["label"]] = i
        proc = " ".join(f"{i}. {dstep(st, i)}." for i, st in enumerate(t["steps"], 1) if st["op"] in ("hook", "inspect", "metadata", "submit", "bulk", "lookup", "parallel"))
        exp = " ".join(f"{i}. {e}." for i, st in enumerate(t["steps"], 1) for e in [dexpect(st.get("expect") or {}, lab)] if e and st["op"] not in ("hook",))
        if t.get("variants"): proc = f"In each variant {', '.join(t['variants'])}: " + proc
    cond = "Mandatory" if t["applicability"] == "mandatory" else "If " + CAPS.get(t["capability"], t["capability"])
    if t["strength"] != "MUST": cond += f" ({t['strength']})"
    if t.get("kind") == "manual": cond += "; inspection"
    if t.get("hooks_required"): cond += "; hooks: " + ", ".join(t["hooks_required"])
    note = f" *{t['note']}*" if t.get("note") else ""
    esc = lambda s: s.replace("|", "\\|")
    return f"| {t['id']} | {esc(cond)} | {', '.join(t['requirements'])} | {esc(proc)} | {esc(exp)}{note} |"


def render_catalogue():
    out = []
    for letter, title in GROUPS:
        ts = [t for t in TESTS["tests"] if t["id"].startswith(letter + "-")]
        if not ts: continue
        out.append(f"#### {title} ({letter}-*)\n\n| ID | Applies | Requirements | Procedure | Expected |\n|---|---|---|---|---|")
        out += [render_test(t) for t in ts]; out.append("")
    return "\n".join(out)


def render_fixtures():
    c = FX["collector"]; L = []
    L.append("**Clock.** The fixture clock is frozen at `%s`. It changes only through the `set_clock` and `advance_clock` hooks. Every `received_at`, every `verified_at`, and every key-validity decision uses it, so receipts and decisions are reproducible.\n" % FX["clock"]["now"])
    L.append("**Collector configuration.** Issuer `%s`; ingestion scope `%s`; receipt scope `%s`; limits %s; `execution_correlation_required` %s; `synchronous_integrity_flags` %s; `idempotency_retention_seconds` %d; record retention %d seconds; lateness policy %d seconds; one profile `%s`.\n" % (
        c["issuer"], c["ingestion_scope"], c["receipt_scope"], ", ".join(f"{k} {v}" for k, v in c["limits"].items()), str(c["execution_correlation_required"]).lower(), str(c["synchronous_integrity_flags"]).lower(),
        c["idempotency_retention_seconds"], c["record_retention_seconds"], c["lateness_seconds"], c["profiles"][0]["profile"]))
    L.append("**Authorization servers.**\n\n| Name | Issuer | Token format |\n|---|---|---|")
    L += [f"| {n} | `{a['issuer']}` | `{a['token_format']}` |" for n, a in FX["authorization_servers"].items()]
    L.append("\n**Submitters.** A submitter is `(issuer, client_id)`; tests name it by the first column.\n\n| Name | Server | Scopes | Evidence domain | May submit for | May read receipts for |\n|---|---|---|---|---|---|")
    for n, s in FX["submitters"].items():
        L.append(f"| `{n}` | {s['as']} | {', '.join(q(x) for x in s['scopes']) or 'none'} | {s['domain'] or 'none'} | {', '.join(q(x) for x in s['submit_for']) or 'none'} | {', '.join(q(x) for x in s['receipt_for']) or 'none'} |")
    L.append("\n**Producer key registry.** Both keys have `valid_from` 2026-01-01T00:00:00Z, no `valid_until`, and no revocation. The public keys are in `vectors.json`.\n\n| Domain | Producer | `kid` | Authorized event kinds |\n|---|---|---|---|")
    for d, r in FX["registry"].items():
        for k in r["keys"]: L.append(f"| {d} | `{k['producer_id']}` | `{k['kid']}` | {', '.join(k['authorized_event_kinds'])} |")
        if not r["keys"]: L.append(f"| {d} | none | | |")
    L.append("\n**Registration-mode variants.**\n\n| Variant | Modes | Registered chains |\n|---|---|---|")
    for n, v in FX["variants"].items():
        L.append(f"| {n}{' (default)' if n == FX['default_variant'] else ''} | {', '.join(q(m) for m in v['modes'])} | {', '.join(q(c['producer_chain_id']) for c in v['registered_chains']) or 'none'} |")
    L.append("\n**Hooks.** A test names the hooks it needs. A Collector that cannot supply a hook leaves that test unverified, never passed.\n\n| Hook | Meaning |\n|---|---|")
    L += [f"| `{k}` | {v} |" for k, v in HOOKS.items()]
    L.append("\nInspection hooks used by tests: `stored` (is the record held; its key identity, `verified_at`, `received_at`, and digest), `count` (records held in a domain), `assessment` (current chain findings of a record), `chain_known` (is a chain admitted).")
    return "\n".join(L)


def render_capabilities():
    caps = sorted({t["capability"] for t in TESTS["tests"] if t.get("capability")})
    L = ["| Capability | Applies when the Collector | Tests |\n|---|---|---|"]
    for c in caps: L.append(f"| `{c}` | {CAPS.get(c, c)} | {', '.join(t['id'] for t in TESTS['tests'] if t.get('capability') == c)} |")
    return "\n".join(L)


def render_register():
    cov, _ = coverage()
    L = ["| ID | § | Level | Applies to | Capability | Verified by | Tests |\n|---|---|---|---|---|---|---|"]
    for r in REQS["requirements"]:
        t = ", ".join(cov.get(r["id"], [])) or ("exception" if r["id"] in REQS["coverage_exceptions"] else "")
        L.append(f"| {r['id']} | {r['section']} | {r['level']} | {', '.join(r['role'])} | {r['capability'] or ''} | {r['verification']} | {t} |")
    return "\n".join(L)


def render_coverage():
    cov, _ = coverage(); R = REQS["requirements"]
    from collections import Counter
    lv = Counter(r["level"] for r in R); vf = Counter(r["verification"] for r in R)
    must = [r for r in R if r["level"] == "mandatory" and r["verification"] in ("test", "behavior")]
    covered = [r for r in must if r["id"] in cov]
    ex = REQS["coverage_exceptions"]
    L = [f"The register holds {len(R)} requirements: {lv['mandatory']} mandatory, {lv['recommended']} recommended, {lv['optional']} optional. By verification method: {vf['test']} by API test, {vf['behavior']} by behavioral test, {vf['inspection']} by inspection, {vf['advisory']} advisory.",
         f"Of the {len(must)} mandatory requirements that a test can verify, {len(covered)} are mapped to at least one test and {len(must) - len(covered)} are documented exceptions. The suite has {len(TESTS['tests'])} tests ({sum(1 for t in TESTS['tests'] if t['applicability'] == 'mandatory')} mandatory, {sum(1 for t in TESTS['tests'] if t['applicability'] == 'conditional')} conditional on a capability)."]
    if ex:
        L.append("\nCoverage exceptions:\n\n| Requirement | Reason |\n|---|---|")
        L += [f"| {k} | {v} |" for k, v in ex.items()]
    return "\n".join(L)


if __name__ == "__main__":
    if "--render" in sys.argv:
        print(render_catalogue()); sys.exit(0)
    sys.exit(main())
