#!/usr/bin/env python3
"""Reference model of the GovOps TRACE Collector API.

Purpose: check the conformance suite for internal consistency. It encodes the normative processing
order (specification section 4.6) and the rules of sections 4 to 11 as an executable model. Every
expected result in tests.json must be one that this model produces. It is NOT a Collector
implementation. It uses an abstract token model, a frozen clock, and in-memory state.

Requires: Python 3.9+ and the `cryptography` package (Ed25519 verification).
"""
import base64, copy, datetime as dt, hashlib, json, re
from urllib.parse import unquote
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey

UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
ULID = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")
SENTINEL = "sha256:" + "0" * 64
ERRORS = {  # code -> (status, retryable)
    "UNAUTHENTICATED": (401, False), "INSUFFICIENT_SCOPE": (403, False), "EVIDENCE_DOMAIN_NOT_BOUND": (403, False),
    "SUBMITTER_NOT_AUTHORIZED": (403, False), "UNSUPPORTED_MEDIA_TYPE": (415, False), "REQUEST_TOO_LARGE": (413, False),
    "RECORD_TOO_LARGE": (413, False), "BATCH_TOO_MANY_RECORDS": (400, False), "BATCH_NOT_ARRAY": (400, False),
    "BATCH_EMPTY": (400, False), "BATCH_MIXED_PRODUCERS": (400, False), "MALFORMED_JSON": (400, False),
    "SCHEMA_INVALID": (400, False), "UNSUPPORTED_PROFILE": (400, False), "MISSING_EXECUTION_CONTEXT": (400, False),
    "PRODUCER_IDENTITY_MISMATCH": (400, False), "SIGNATURE_MALFORMED": (400, False), "UNSUPPORTED_ALGORITHM": (400, False),
    "CHAIN_NOT_REGISTERED": (400, False), "KEY_UNKNOWN": (400, False), "KEY_NOT_VALID": (400, False),
    "EVENT_KIND_NOT_AUTHORIZED": (400, False), "SIGNATURE_INVALID": (400, False), "RECORD_ID_CONFLICT": (409, False),
    "RECEIPT_NOT_FOUND": (404, True), "RECEIPT_ACCESS_DENIED": (403, False), "RATE_LIMITED": (429, True),
    "COLLECTOR_UNAVAILABLE": (503, True), "COLLECTOR_INTEGRITY_HOLD": (503, True), "INTERNAL_ERROR": (500, True)}


def jcs(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest_of(rec):
    return "sha256:" + hashlib.sha256(jcs(rec).encode("utf-8")).hexdigest()


def b64u_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def parse_time(s):
    return dt.datetime.strptime(s.replace("Z", ""), "%Y-%m-%dT%H:%M:%S.%f" if "." in s else "%Y-%m-%dT%H:%M:%S").replace(tzinfo=dt.timezone.utc)


def fmt_time(t):
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (t.microsecond // 1000)


class Resp:
    def __init__(self, status, body=None, headers=None):
        self.status, self.body, self.headers = status, body, headers or {}


def problem(code, detail=None, **extra):
    st, rt = ERRORS[code]
    b = {"type": "https://govops.owasp.org/trace/errors/" + code.lower().replace("_", "-"), "title": code, "status": st, "code": code, "retryable": rt}
    if detail:
        b["detail"] = detail
    b.update(extra)
    return b


def err(code, headers=None, **extra):
    p = problem(code, **extra)
    return Resp(p["status"], p, headers)


class DupKey(Exception):
    pass


def strict_parse(raw, max_depth):
    """Return (value, None) or (None, reason). Strict JSON: UTF-8, no duplicate members, no NaN, bounded depth."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None, "invalid UTF-8"

    def hook(pairs):
        d = {}
        for k, v in pairs:
            if k in d:
                raise DupKey(k)
            d[k] = v
        return d

    def bad(c):
        raise ValueError("constant " + c)
    try:
        v = json.loads(text, object_pairs_hook=hook, parse_constant=bad)
    except DupKey as e:
        return None, "duplicate member " + str(e)
    except (ValueError, RecursionError) as e:
        return None, "syntax: " + str(e)

    def depth(x):
        if isinstance(x, dict):
            return 1 + max([depth(y) for y in x.values()] or [0])
        if isinstance(x, list):
            return 1 + max([depth(y) for y in x] or [0])
        return 0
    if depth(v) > max_depth:
        return None, "nesting"
    return v, None


class Model:
    def __init__(self, fixtures, vectors, overrides=None):
        fx = copy.deepcopy(fixtures)
        overrides = overrides or {}
        self.fx = fx
        self.vectors = vectors
        self.keys = vectors["keys"]
        variant = overrides.get("variant", fx["default_variant"])
        self.variant = variant
        v = fx["variants"][variant]
        self.modes = list(v["modes"])
        self.registered = [dict(c) for c in v["registered_chains"]]
        self.col = fx["collector"]
        for k, val in (overrides.get("collector") or {}).items():
            if isinstance(val, dict) and isinstance(self.col.get(k), dict):
                self.col[k].update(val)
            else:
                self.col[k] = val
        self.clock = parse_time(overrides.get("clock", fx["clock"]["now"]))
        self.submitters = fx["submitters"]
        for name, patch in (overrides.get("submitters") or {}).items():
            self.submitters.setdefault(name, {}).update(patch)
        self.registry = fx["registry"]
        self.records = {}      # (domain, producer, record_id) -> entry
        self.chains = {}       # (domain, producer, instance, chain) -> {"admission":..., "positions":{seq:[(rid,digest)]}}
        self.counter = {}
        self.requests = {}
        self.as_by_issuer = {a["issuer"]: dict(a, name=n) for n, a in fx["authorization_servers"].items()}

    # ---------------------------------------------------------------- hooks
    def hook(self, action, **a):
        c = self.col
        if action == "set_clock": self.clock = parse_time(a["value"])
        elif action == "advance_clock": self.clock += dt.timedelta(seconds=a["seconds"])
        elif action == "set_key":
            for k in self.registry[a.get("domain", "D1")]["keys"]:
                if k["producer_id"] == a["producer_id"] and k["kid"] == a["kid"]:
                    for f in ("valid_from", "valid_until", "revoked_at"):
                        if f in a: k[f] = a[f]
        elif action == "register_key":
            self.registry.setdefault(a["domain"], {"keys": []})["keys"].append(a["key"])
        elif action == "register_chain": self.registered.append({"domain": a.get("domain", "D1"), "producer_id": a["producer_id"], "producer_instance_id": a.get("producer_instance_id"), "producer_chain_id": a["producer_chain_id"]})
        elif action == "unregister_chain": self.registered = [r for r in self.registered if r["producer_chain_id"] != a["producer_chain_id"]]
        elif action == "set_limit":
            floors = {"max_record_bytes": 65536, "max_batch_bytes": 1048576, "max_batch_records": 100, "max_nesting_depth": 16}
            if a["value"] < floors[a["name"]]:
                raise ValueError(f"{a['name']}={a['value']} is below the specification's minimum of {floors[a['name']]}: a conforming Collector cannot be configured this way")
            c["limits"][a["name"]] = a["value"]
        elif action == "set_collector": c[a["name"]] = a["value"]
        elif action == "add_schema_rule": c["schema_rules"].append(a["rule"])
        elif action == "set_profile_state":
            for p in c["profiles"]:
                if p["profile"] == a["profile"]: p["state"] = a["state"]
        elif action == "set_submitter":
            self.submitters[a["name"]].update(a["patch"])
        elif action == "set_rate_limit": c["rate_limit"] = a["max_requests"]
        elif action == "fail_commit": c["commit_failures"] = a.get("count", 1)
        else: raise ValueError("unknown hook " + action)

    # ---------------------------------------------------------------- tokens
    def token_for(self, name, over=None):
        s = self.submitters[name]
        a = self.fx["authorization_servers"][s["as"]]
        cid = s["client_id"]
        t = {"format": "jwt" if a["token_format"] == "jwt" else "opaque", "iss": a["issuer"], "signer": a["issuer"], "alg": "EdDSA",
             "claims": {"client_id": cid, "sub": cid, "azp": cid}, "scope": list(s["scopes"]), "aud": [self.col["issuer"]],
             "exp": "valid", "nbf": "ok", "header_params": [], "cnf": None, "cnf_proof": False, "location": "header",
             "introspection": ({"active": True, "client_id": cid, "iss": a["issuer"], "aud": [self.col["issuer"]]} if a["token_format"] != "jwt" else None)}
        for k, v in (over or {}).items():
            if isinstance(v, dict) and isinstance(t.get(k), dict):
                for kk, vv in v.items():
                    if vv is None: t[k].pop(kk, None)
                    else: t[k][kk] = vv
            else:
                t[k] = v
        return t

    def authenticate(self, t):
        if t is None or t.get("location") in ("query", "body"):
            return None, err("UNAUTHENTICATED", headers={"WWW-Authenticate": 'Bearer error="invalid_token"'})
        a = self.as_by_issuer.get(t["iss"])
        if a is None:
            return None, err("UNAUTHENTICATED", headers={"WWW-Authenticate": 'Bearer error="invalid_token"'})
        bad = err("UNAUTHENTICATED", headers={"WWW-Authenticate": 'Bearer error="invalid_token"'})
        if a["token_format"] == "jwt":
            if t["format"] != "jwt" or t["alg"] in ("none", "HS256") or t.get("header_params") or t["signer"] != a["issuer"]: return None, bad
            if t["exp"] != "valid" or t["nbf"] != "ok" or self.col["issuer"] not in t.get("aud", []): return None, bad
            cid = t["claims"].get(a["client_id_claim"])
        else:
            intro = t.get("introspection")
            if intro == "unavailable": return None, err("COLLECTOR_UNAVAILABLE", headers={"Retry-After": "5"})
            if not intro or not intro.get("active"): return None, bad
            if intro.get("iss") not in (None, a["issuer"]): return None, bad
            if "aud" in intro and self.col["issuer"] not in intro["aud"]: return None, bad
            cid = intro.get(a["client_id_claim"])
        if not isinstance(cid, str) or not cid: return None, bad
        if t.get("cnf"):
            kind = t["cnf"]
            if not (t.get("cnf_proof") and kind in self.col["sender_constrained_tokens_supported"]): return None, bad
        return (a["issuer"], cid), None

    def submitter(self, ident):
        for n, s in self.submitters.items():
            if self.fx["authorization_servers"][s["as"]]["issuer"] == ident[0] and s["client_id"] == ident[1]:
                return s
        return None

    def purge(self):
        keep = int(self.col["record_retention_seconds"])
        for k in [k for k, e in self.records.items() if self.clock >= parse_time(e["receipt"]["received_at"]) + dt.timedelta(seconds=keep)]:
            del self.records[k]

    # ---------------------------------------------------------------- front (steps 1-5)
    def front(self, endpoint, token, scheme, content_type, content_encoding, body_len):
        if scheme != "https": return None, None, Resp("refused")
        ident, e = self.authenticate(token)
        if e: return None, None, e
        s = self.submitter(ident)
        need = self.col["receipt_scope"] if endpoint == "lookup" else self.col["ingestion_scope"]
        if need not in token["scope"]: return None, None, err("INSUFFICIENT_SCOPE")
        if not s or not s.get("domain"): return None, None, err("EVIDENCE_DOMAIN_NOT_BOUND")
        rl = self.col.get("rate_limit")
        if rl is not None:
            self.requests[ident] = self.requests.get(ident, 0) + 1
            if self.requests[ident] > rl: return None, None, err("RATE_LIMITED", headers={"Retry-After": "2"})
        if endpoint in ("single", "bulk"):
            if content_type != "application/json" or (content_encoding and content_encoding not in self.col["content_encodings_supported"]):
                return None, None, err("UNSUPPORTED_MEDIA_TYPE")
            lim = self.col["limits"]
            if endpoint == "single" and body_len > lim["max_record_bytes"]: return None, None, err("RECORD_TOO_LARGE")
            if endpoint == "bulk" and body_len > lim["max_batch_bytes"]: return None, None, err("REQUEST_TOO_LARGE")
        return ident, s, None

    # ---------------------------------------------------------------- submission
    def submit(self, token, body, scheme="https", content_type="application/json", content_encoding=None, headers=None):
        self.purge()
        ident, s, e = self.front("single", token, scheme, content_type, content_encoding, len(body))
        if e: return e
        if self.col.get("storage_down"): return err("COLLECTOR_UNAVAILABLE", headers={"Retry-After": "5"})
        v, why = strict_parse(body, self.col["limits"]["max_nesting_depth"])
        if why: return err("MALFORMED_JSON", detail=why)
        if not isinstance(v, dict): return err("SCHEMA_INVALID", detail="body is not a JSON object")
        if isinstance(v.get("producer"), str) and v["producer"] not in s["submit_for"]:
            return err("SUBMITTER_NOT_AUTHORIZED")
        r = self.process(s, v, check_permission=False)
        return self.single_resp(r)

    def single_resp(self, r):
        if r["accepted"]:
            return Resp(200 if r["receipt"]["idempotent_replay"] else 201, self.render(r["receipt"]))
        return err(r["code"], **r.get("extra", {}))

    def render(self, rc):
        out = {k: v for k, v in rc.items() if not k.startswith("_")}
        if not self.col["synchronous_integrity_flags"]:
            for f in ("coverage_gap_flag", "chain_link_failure_flag", "equivocation_flag", "late_flag"): out.pop(f, None)
        return out

    def bulk(self, token, body, scheme="https", content_type="application/json", content_encoding=None, headers=None):
        self.purge()
        ident, s, e = self.front("bulk", token, scheme, content_type, content_encoding, len(body))
        if e: return e
        if self.col.get("storage_down"): return err("COLLECTOR_UNAVAILABLE", headers={"Retry-After": "5"})
        lim = self.col["limits"]
        v, why = strict_parse(body, lim["max_nesting_depth"])
        if why: return err("MALFORMED_JSON", detail=why)
        if not isinstance(v, list): return err("BATCH_NOT_ARRAY")
        if not v: return err("BATCH_EMPTY")
        if len(v) > lim["max_batch_records"]: return err("BATCH_TOO_MANY_RECORDS")
        prods = [x["producer"] for x in v if isinstance(x, dict) and isinstance(x.get("producer"), str)]
        mixed = self.col["bulk_mixed_producers_supported"]
        if not mixed and len(set(prods)) > 1: return err("BATCH_MIXED_PRODUCERS")
        if not mixed and prods and prods[0] not in s["submit_for"]: return err("SUBMITTER_NOT_AUTHORIZED")
        results = []
        for i, el in enumerate(v):
            r = self.process(s, el, check_permission=mixed, element=True)
            if r["accepted"]:
                d = self.render(r["receipt"]); d["index"] = i; results.append(d)
            else:
                p = problem(r["code"], **r.get("extra", {}))
                d = {"index": i, "accepted": False, "error": p}
                if isinstance(el, dict):
                    if isinstance(el.get("producer"), str): d["producer_id"] = el["producer"]
                    if isinstance(el.get("record_id"), str): d["record_id"] = el["record_id"]
                results.append(d)
        return Resp(200, {"results": results})

    def fail(self, code, **extra):
        return {"accepted": False, "code": code, "extra": extra}

    def profile(self, name):
        for p in self.col["profiles"]:
            if p["profile"] == name: return p
        return None

    def process(self, s, el, check_permission, element=False):
        domain = s["domain"]; col = self.col
        if check_permission and isinstance(el, dict) and isinstance(el.get("producer"), str) and el["producer"] not in s["submit_for"]:
            return self.fail("SUBMITTER_NOT_AUTHORIZED")                                   # step 7
        if element:
            size = len(jcs(el).encode("utf-8")) if not isinstance(el, (int, float, str, type(None), bool)) else 0
            if size > col["limits"]["max_record_bytes"]: return self.fail("RECORD_TOO_LARGE")   # step 8
        if not isinstance(el, dict): return self.fail("SCHEMA_INVALID")                     # step 9
        prof = (el.get("trace") or {}).get("eat_profile") if isinstance(el.get("trace"), dict) else None
        if not (isinstance(el.get("producer"), str) and isinstance(el.get("record_id"), str) and isinstance(prof, str)): return self.fail("SCHEMA_INVALID")
        pe = self.profile(prof)
        if pe is None or pe["state"] not in ("accepted", "replay_only"): return self.fail("UNSUPPORTED_PROFILE")
        dg = digest_of(el)                                                                   # step 10
        key = (domain, el["producer"], el["record_id"])
        ent = self.records.get(key)
        if ent and ent["digest"] == dg:
            rc = dict(ent["receipt"]); rc["idempotent_replay"] = True
            return {"accepted": True, "receipt": rc}
        if pe["state"] != "accepted": return self.fail("UNSUPPORTED_PROFILE")                # step 10a
        for m in ("producer", "kid", "record_id", "trace", "producer_chain", "signature"):
            if m not in el: return self.fail("SCHEMA_INVALID")
        tr, pc = el["trace"], el["producer_chain"]
        if not (isinstance(tr, dict) and isinstance(pc, dict) and isinstance(el["kid"], str) and isinstance(el["signature"], str)): return self.fail("SCHEMA_INVALID")
        if not all(k in tr for k in ("event_kind", "signed_at")) or not all(k in pc for k in ("producer_id", "producer_instance_id", "producer_chain_id", "sequence_number", "prev_record_hash")): return self.fail("SCHEMA_INVALID")
        if not (UUID.match(el["record_id"]) or ULID.match(el["record_id"])): return self.fail("SCHEMA_INVALID")
        if el["producer"] != pc["producer_id"]: return self.fail("PRODUCER_IDENTITY_MISMATCH")
        if tr["event_kind"] not in pe["event_kinds_supported"]: return self.fail("SCHEMA_INVALID")
        for rule in col["schema_rules"]:
            node = el
            for part in rule["require_member"].split("."):
                node = node.get(part) if isinstance(node, dict) else None
            if node is None: return self.fail("SCHEMA_INVALID")
        unattributed = not (tr.get("trace_execution_id") and tr.get("execution_authority"))
        if col["execution_correlation_required"] and unattributed: return self.fail("MISSING_EXECUTION_CONTEXT")
        tk = (tr.get("event") or {}).get("tokens")
        if isinstance(tk, list) and len(tk) > 32: return self.fail("SCHEMA_INVALID")
        k = next((k for k in self.registry.get(domain, {"keys": []})["keys"] if k["producer_id"] == el["producer"] and k["kid"] == el["kid"]), None)   # step 11
        if k is None: return self.fail("KEY_UNKNOWN")
        t = self.clock
        vf, vu, rv = k["valid_from"], k["valid_until"], k["revoked_at"]
        if (vf and t < parse_time(vf)) or (vu and t >= parse_time(vu)) or (rv and t >= parse_time(rv)): return self.fail("KEY_NOT_VALID")
        if tr["event_kind"] not in k["authorized_event_kinds"]: return self.fail("EVENT_KIND_NOT_AUTHORIZED")
        sig = el["signature"]                                                                 # step 12
        if not re.match(r"^[A-Za-z0-9_-]{86}$", sig): return self.fail("SIGNATURE_MALFORMED")
        if k["algorithm"] not in pe["signature_algorithms_supported"]: return self.fail("UNSUPPORTED_ALGORITHM")
        try:
            pub = Ed25519PublicKey.from_public_bytes(b64u_decode(k["public_jwk"]["x"]))
            pub.verify(b64u_decode(sig), jcs({m: x for m, x in el.items() if m != "signature"}).encode("utf-8"))
        except Exception:
            return self.fail("SIGNATURE_INVALID")
        if ent and ent["digest"] != dg: return self.fail("RECORD_ID_CONFLICT", producer_id=el["producer"], record_id=el["record_id"], existing_content_digest=ent["digest"], submitted_content_digest=dg)   # step 13
        ck = (domain, pc["producer_id"], pc["producer_instance_id"], pc["producer_chain_id"])      # step 14
        chain = self.chains.get(ck)
        if chain is None:
            reg = any(r["domain"] == domain and r["producer_id"] == pc["producer_id"] and r["producer_chain_id"] == pc["producer_chain_id"] and r.get("producer_instance_id") in (None, pc["producer_instance_id"]) for r in self.registered)
            if reg and "pre_registered_genesis" in self.modes: adm = "pre_registered_genesis"
            elif "first_observed_genesis" in self.modes: adm = "first_observed_genesis"
            else: return self.fail("CHAIN_NOT_REGISTERED", producer_id=el["producer"], record_id=el["record_id"])
            chain = {"admission": adm, "positions": {}}
        flags = self.flags(chain, pc["sequence_number"], pc["prev_record_hash"], el["record_id"], dg, tr["signed_at"])
        if col["commit_failures"] > 0:                                                         # step 15
            col["commit_failures"] -= 1
            return self.fail("COLLECTOR_UNAVAILABLE")
        self.chains[ck] = chain
        chain["positions"].setdefault(pc["sequence_number"], []).append((el["record_id"], dg))
        self.counter[domain] = self.counter.get(domain, 0) + 1
        rc = {"accepted": True, "producer_id": el["producer"], "record_id": el["record_id"], "content_digest": dg,
              "receipt_id": str(self.counter[domain]), "received_at": fmt_time(self.clock), "idempotent_replay": False,
              "chain_admission": chain["admission"]}
        if not col["execution_correlation_required"]: rc["unattributed_flag"] = unattributed
        rc.update(flags)
        self.records[key] = {"record": el, "digest": dg, "receipt": rc, "key": (k["producer_id"], k["kid"]), "verified_at": fmt_time(self.clock), "chain": ck}
        out = dict(rc)
        return {"accepted": True, "receipt": out}

    def flags(self, chain, seq, prev, rid, dg, signed_at, now=None):
        pos = chain["positions"]
        pred = pos.get(seq - 1, [])
        link = (bool(pred) and all(d != prev for _, d in pred)) or (seq == 1 and prev != SENTINEL) or (seq > 1 and prev == SENTINEL)
        eq = any(r != rid for r, _ in pos.get(seq, []))
        now = now or self.clock
        late = (now - dt.datetime.fromtimestamp(signed_at, dt.timezone.utc)).total_seconds() > self.col["lateness_seconds"]
        return {"coverage_gap_flag": seq > 1 and not pred, "chain_link_failure_flag": link, "equivocation_flag": eq, "late_flag": late}

    # ---------------------------------------------------------------- lookup
    def lookup(self, token, producer, record_id, scheme="https"):
        self.purge()
        ident, s, e = self.front("lookup", token, scheme, None, None, 0)
        if e: return e
        producer = unquote(producer)
        if producer not in s["receipt_for"]: return err("RECEIPT_ACCESS_DENIED")
        ent = self.records.get((s["domain"], producer, record_id))
        if ent is None: return err("RECEIPT_NOT_FOUND", headers={"Cache-Control": "no-store"})
        rc = {k: v for k, v in ent["receipt"].items() if k != "idempotent_replay"}
        return Resp(200, self.render(rc), {"Cache-Control": "private"})

    # ---------------------------------------------------------------- metadata and inspection
    def metadata(self):
        c = self.col
        m = {"issuer": c["issuer"], "api_versions_supported": ["v1"],
             "trace_ingestion_endpoint": c["issuer"] + "/api/v1/audit/trace",
             "trace_profiles": [{k: v for k, v in p.items() if k != "state"} for p in c["profiles"] if p["state"] == "accepted"],
             "authorization_servers": [{k: v for k, v in a.items() if k != "name"} for a in self.as_by_issuer.values()],
             "ingestion_scope": c["ingestion_scope"], "max_record_bytes": c["limits"]["max_record_bytes"],
             "idempotency_retention_seconds": c["idempotency_retention_seconds"],
             "producer_chain_registration_modes_supported": self.modes,
             "synchronous_integrity_flags": c["synchronous_integrity_flags"],
             "execution_correlation_required": c["execution_correlation_required"],
             "max_nesting_depth": c["limits"]["max_nesting_depth"], "scopes_supported": [c["ingestion_scope"]]}
        if c["offers_bulk"]:
            m.update(trace_bulk_ingestion_endpoint=c["issuer"] + "/api/v1/audit/trace/bulk", max_batch_bytes=c["limits"]["max_batch_bytes"],
                     max_batch_records=c["limits"]["max_batch_records"], bulk_mixed_producers_supported=c["bulk_mixed_producers_supported"])
        if c["offers_receipt_lookup"]:
            m.update(trace_receipt_endpoint=c["issuer"] + "/api/v1/audit/trace/receipts/{producer_id}/{record_id}", receipt_scope=c["receipt_scope"])
            m["scopes_supported"].append(c["receipt_scope"])
        rep = [p["profile"] for p in c["profiles"] if p["state"] == "replay_only"]
        if rep: m["trace_profiles_replay_only"] = rep
        if c["content_encodings_supported"]: m["content_encodings_supported"] = c["content_encodings_supported"]
        if c["sender_constrained_tokens_supported"]: m["sender_constrained_tokens_supported"] = c["sender_constrained_tokens_supported"]
        return Resp(200, m, {"Cache-Control": "max-age=3600"})

    def inspect(self, what, domain, producer=None, record_id=None):
        e = self.records.get((domain, producer, record_id))
        if what == "stored": return {"present": e is not None, **({"key": list(e["key"]), "verified_at": e["verified_at"], "received_at": e["receipt"]["received_at"]} if e else {})}
        if what == "assessment":
            if not e: return {"present": False}
            ck = e["chain"]; ch = self.chains[ck]; pc = e["record"]["producer_chain"]
            f = self.flags(ch, pc["sequence_number"], pc["prev_record_hash"], e["record"]["record_id"], e["digest"], e["record"]["trace"]["signed_at"], now=parse_time(e["receipt"]["received_at"]))
            return {"present": True, **f}
        if what == "chain_known":
            return {"known": any(k[0] == domain and k[1] == producer and k[3] == record_id for k in self.chains)}
        if what == "count":
            return {"count": sum(1 for k in self.records if k[0] == domain)}
        raise ValueError(what)
