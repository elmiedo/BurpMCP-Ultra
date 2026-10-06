#!/usr/bin/env python3
"""
Thin integrity validator for an identity-matrix registry.

Checks what JSON Schema cannot express:
  - id uniqueness (within each collection and across the whole registry)
  - cross-references resolve:
        identity.credentials[]        -> credentials
        identity.precedence[]         -> that identity's own credentials  (precedence subset)
        binding.identity / identities -> identities
        session.from_credential       -> credentials
        session.identity              -> identities
        credential.renewal_ref        -> renewal_policies
  - (soft) credential.renewal_ref points at a policy; inline renewal needs no ref

Optionally runs structural JSON-Schema validation first when the schema file is
present and `jsonschema` is importable (pip install jsonschema).

Usage:
    validate_registry.py registry.json [--schema identity-matrix.schema.json] [--no-schema]

Exit code: 0 = clean, 1 = problems found, 2 = bad input.
A registry is either the envelope object
    {"credentials":[...], "identities":[...], "bindings":[...], "sessions":[...], "renewal_policies":[...]}
or a flat list of records (bucketed here by their `kind`).
"""

import argparse
import json
import os
import sys

KIND_TO_COLLECTION = {
    "credential": "credentials",
    "identity": "identities",
    "binding": "bindings",
    "session": "sessions",
    "renewal-policy": "renewal_policies",
}
KIND_TO_DEF = {
    "credential": "credential",
    "identity": "identity",
    "binding": "binding",
    "session": "session",
    "renewal-policy": "renewalPolicy",
}
COLLECTIONS = ["credentials", "identities", "bindings", "sessions", "renewal_policies"]


def load_registry(path):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    reg = {c: [] for c in COLLECTIONS}
    if isinstance(data, dict) and any(k in data for k in COLLECTIONS):
        for c in COLLECTIONS:
            reg[c] = data.get(c, []) or []
    elif isinstance(data, list):
        for rec in data:
            col = KIND_TO_COLLECTION.get(rec.get("kind") if isinstance(rec, dict) else None)
            if col:
                reg[col].append(rec)
            else:
                reg.setdefault("_unknown", []).append(rec)
    else:
        raise ValueError("registry must be the envelope object or a flat list of records")
    return reg


def schema_validate(reg, schema_path):
    """Structural validation of each record against its $def. Returns (errors, fmt_note).
    Returns None if jsonschema is unavailable."""
    try:
        from jsonschema import Draft202012Validator, FormatChecker
    except ImportError:
        return None  # jsonschema not available -> skip, signalled by None
    with open(schema_path, encoding="utf-8") as fh:
        schema = json.load(fh)
    Draft202012Validator.check_schema(schema)
    defs = schema["$defs"]
    # Make `format` assertive (default draft 2020-12 treats it as annotation only).
    fc = FormatChecker()
    active = "date-time" in fc.checkers
    schema_validate.fmt_note = ("date-time/uri asserted" if active
                                else "format NOT asserted (pip install jsonschema[format])")
    validators = {
        col: Draft202012Validator({"$defs": defs, "$ref": f"#/$defs/{KIND_TO_DEF[kind]}"},
                                  format_checker=fc)
        for kind, col in KIND_TO_COLLECTION.items()
    }
    errs = []
    for col in COLLECTIONS:
        for i, rec in enumerate(reg.get(col, [])):
            for e in sorted(validators[col].iter_errors(rec), key=lambda e: list(e.path)):
                loc = "/".join(str(p) for p in e.path) or "(root)"
                rid = rec.get("id", f"[{i}]") if isinstance(rec, dict) else f"[{i}]"
                errs.append(f"schema  {col}:{rid} @ {loc}: {e.message}")
    return errs


def _id(rec, i):
    return rec.get("id", f"[{i}]") if isinstance(rec, dict) else f"[{i}]"


_STATEFUL = {"session-cookie", "signed-cookie", "oauth2", "digest"}
_STATELESS = {"api-key", "basic", "tls-client-cert", "hmac-signature", "totp-seed"}


def cred_statefulness(cred):
    """stateful = carries server-side session state that a parallel fan-out would
    clobber. bearer/jwt depend on transport: a cookie-borne token is stateful."""
    t = cred.get("type")
    if t in _STATEFUL:
        return "stateful"
    if t in ("bearer", "jwt"):
        inj = (cred.get("application") or {}).get("inject")
        return "stateful" if inj == "cookie" else "stateless"
    return "stateless"


def integrity_check(reg):
    errs = []

    # ---- id uniqueness ----
    global_seen = {}
    ids = {c: set() for c in COLLECTIONS}
    for col in COLLECTIONS:
        local = {}
        for i, rec in enumerate(reg[col]):
            rid = rec.get("id") if isinstance(rec, dict) else None
            if rid is None:
                if col != "bindings":  # bindings legitimately have no id
                    errs.append(f"idcheck {col}[{i}]: record has no id")
                continue
            if rid in local:
                errs.append(f"idcheck {col}: duplicate id {rid!r} (also at index {local[rid]})")
            else:
                local[rid] = i
                ids[col].add(rid)
            if rid in global_seen and global_seen[rid] != col:
                errs.append(f"idcheck id {rid!r} reused across collections ({global_seen[rid]} and {col})")
            else:
                global_seen[rid] = col

    cred_ids = ids["credentials"]
    identity_ids = ids["identities"]
    policy_ids = ids["renewal_policies"]
    cred_by_id = {c["id"]: c for c in reg["credentials"] if isinstance(c, dict) and "id" in c}
    idn_by_id = {d["id"]: d for d in reg["identities"] if isinstance(d, dict) and "id" in d}

    # ---- identity.credentials / precedence ----
    for i, idn in enumerate(reg["identities"]):
        rid = _id(idn, i)
        creds = idn.get("credentials", []) or []
        credset = set(creds)
        for c in creds:
            if c not in cred_ids:
                errs.append(f"xref    identity {rid}: credentials -> missing credential {c!r}")
        for c in idn.get("precedence", []) or []:
            if c not in credset:
                errs.append(f"subset  identity {rid}: precedence entry {c!r} not in this identity's credentials")

    # ---- bindings ----
    for i, b in enumerate(reg["bindings"]):
        label = f"binding[{i}]"
        mode = b.get("mode")
        if mode == "dedicated":
            tgt = b.get("identity")
            if tgt not in identity_ids:
                errs.append(f"xref    {label} (dedicated): identity -> missing {tgt!r}")
        elif mode == "shared":
            for tgt in b.get("identities", []) or []:
                if tgt not in identity_ids:
                    errs.append(f"xref    {label} (pool {b.get('pool')!r}): identities -> missing {tgt!r}")
            # invariant: burp-native serialises on a global egress lock, so any
            # requested concurrency is meaningless (and fan-out is contradictory).
            if b.get("execution") == "burp-native":
                if b.get("max_concurrent_per_identity", 1) > 1:
                    errs.append(
                        f"invariant {label} (pool {b.get('pool')!r}): execution='burp-native' with "
                        f"max_concurrent_per_identity={b['max_concurrent_per_identity']} is meaningless "
                        f"— the global Burp upstream serialises regardless (use 'parallel' for real concurrency)")
                if b.get("stateless_fanout"):
                    errs.append(
                        f"invariant {label} (pool {b.get('pool')!r}): execution='burp-native' contradicts "
                        f"stateless_fanout=true — fan-out implies parallel egress, which burp-native cannot do")
            # invariant: stateless_fanout must not reference any stateful credential
            if b.get("stateless_fanout"):
                for idn_id in b.get("identities", []) or []:
                    idn = idn_by_id.get(idn_id)
                    if not idn:
                        continue
                    for cid in idn.get("credentials", []) or []:
                        c = cred_by_id.get(cid)
                        if c and cred_statefulness(c) == "stateful":
                            errs.append(
                                f"invariant {label} (pool {b.get('pool')!r}): stateless_fanout=true "
                                f"but identity {idn_id} uses stateful credential {cid} "
                                f"(type {c.get('type')!r}) — lease-free fan-out will clobber its session")

    # ---- sessions ----
    for i, s in enumerate(reg["sessions"]):
        rid = _id(s, i)
        fc = s.get("from_credential")
        if fc not in cred_ids:
            errs.append(f"xref    session {rid}: from_credential -> missing {fc!r}")
        sid = s.get("identity")
        if sid is not None and sid not in identity_ids:
            errs.append(f"xref    session {rid}: identity -> missing {sid!r}")

    # ---- credential.renewal_ref ----
    for i, c in enumerate(reg["credentials"]):
        rid = _id(c, i)
        rr = c.get("renewal_ref")
        if rr is not None and rr not in policy_ids:
            errs.append(f"xref    credential {rid}: renewal_ref -> missing renewal policy {rr!r}")

    return errs


def main():
    ap = argparse.ArgumentParser(description="Integrity validator for an identity-matrix registry.")
    ap.add_argument("registry")
    ap.add_argument("--schema", default=None, help="Path to identity-matrix.schema.json (default: sibling of this script)")
    ap.add_argument("--no-schema", action="store_true", help="Skip structural JSON-Schema validation")
    args = ap.parse_args()

    try:
        reg = load_registry(args.registry)
    except Exception as e:
        print(f"ERROR: cannot read registry: {e}", file=sys.stderr)
        return 2

    if reg.get("_unknown"):
        print(f"ERROR: {len(reg['_unknown'])} record(s) with unknown/missing kind", file=sys.stderr)
        return 2

    counts = ", ".join(f"{c}={len(reg[c])}" for c in COLLECTIONS)
    print(f"registry: {counts}")

    all_errs = []

    # structural schema pass (optional)
    if not args.no_schema:
        schema_path = args.schema or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "identity-matrix.schema.json"
        )
        if os.path.exists(schema_path):
            sres = schema_validate(reg, schema_path)
            if sres is None:
                print("schema:   skipped (jsonschema not installed)")
            else:
                note = getattr(schema_validate, "fmt_note", "")
                print(f"schema:   {'OK' if not sres else str(len(sres)) + ' error(s)'}  [{note}]")
                all_errs += sres
        else:
            print(f"schema:   skipped (schema file not found at {schema_path})")

    # integrity pass (always)
    ires = integrity_check(reg)
    print(f"integrity:{'OK' if not ires else ' ' + str(len(ires)) + ' error(s)'}")
    all_errs += ires

    if all_errs:
        print("\n".join("  - " + e for e in all_errs))
        print(f"\nFAIL: {len(all_errs)} problem(s)")
        return 1
    print("\nPASS: registry is structurally valid and referentially consistent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
