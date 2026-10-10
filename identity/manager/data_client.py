#!/usr/bin/env python3
"""Identity data-plane: per-identity HTTP client (manager side).

Why this exists alongside Burp: Montoya's upstream proxy is GLOBAL — Burp
cannot route per-request through identity-specific egress. This client owns
the parallel execution mode: each identity's traffic goes out through its own
egress (presentation.egress_ref → concrete proxy), with credentials applied
exactly like the Burp-side IdentityApplier (same registry, same precedence,
replace-never-merge layers).

The wire format it produces matches what the MCP side sends, so a target sees
identical requests whichever path executed them.

Egress resolution: egress_ref strings map to concrete proxy URLs via the
`egresses` dict supplied by the operator (manager owns all egress knowledge;
the registry only carries opaque refs). Identities without an egress_ref go
direct.

Usage:
    plane = IdentityPlane.from_registry_file("registry.json",
                                             secrets={"cred:web1": "..."},
                                             egresses={"egress:dc-1": "socks5://127.0.0.1:9050"})
    resp = await plane.request("id:persona-1", "GET", "https://app.example.com/status")
"""

from __future__ import annotations

import fnmatch
import json
from typing import Optional, Union

import httpx


def _host_matches(pattern: str, host: str) -> bool:
    host = host.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return host.endswith(suffix) and len(host) > len(suffix)
    return host == pattern


def _scope_allows(scope: dict, host: str, path: str = "/") -> bool:
    if not any(_host_matches(p, host) for p in scope.get("hosts", [])):
        return False
    paths = scope.get("paths")
    if paths:
        return any(fnmatch.fnmatch(path, p) for p in paths)
    return True


class IdentityError(RuntimeError):
    pass


class IdentityPlane:
    """One httpx.AsyncClient per identity: pinned egress, own cookie jar."""

    def __init__(self, registry: dict, secrets: dict[str, str],
                 egresses: Optional[dict[str, str]] = None,
                 timeout: float = 30.0):
        self.credentials = {c["id"]: c for c in registry.get("credentials", [])}
        self.identities = {i["id"]: i for i in registry.get("identities", [])}
        self.secrets = secrets
        self.egresses = egresses or {}
        self.timeout = timeout
        self._clients: dict[str, httpx.AsyncClient] = {}

    @classmethod
    def from_registry_file(cls, path: str, secrets: dict[str, str], **kw) -> "IdentityPlane":
        with open(path, encoding="utf-8") as f:
            return cls(json.load(f), secrets, **kw)

    # ── lifecycle ────────────────────────────────────────────────────────────

    async def close(self) -> None:
        for c in self._clients.values():
            await c.aclose()
        self._clients.clear()

    async def __aenter__(self) -> "IdentityPlane":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()

    def _client_for(self, identity_id: str) -> httpx.AsyncClient:
        if identity_id in self._clients:
            return self._clients[identity_id]
        ident = self.identities[identity_id]
        egress_ref = ident.get("presentation", {}).get("egress_ref")
        proxy = self.egresses.get(egress_ref) if egress_ref else None
        if egress_ref and proxy is None:
            raise IdentityError(f"egress {egress_ref!r} of {identity_id} has no concrete proxy "
                                f"in the manager's egress map")
        client = httpx.AsyncClient(proxy=proxy, timeout=self.timeout,
                                   follow_redirects=False, trust_env=False)
        self._clients[identity_id] = client
        return client

    # ── identity application (mirrors bridge/IdentityApplier.kt) ────────────

    def resolve_injections(self, identity_id: str) -> list[dict]:
        ident = self.identities.get(identity_id)
        if ident is None:
            raise IdentityError(f"unknown identity {identity_id!r}")
        plan = []
        for cred_id in ident.get("precedence", []):
            cred = self.credentials.get(cred_id)
            if cred is None:
                raise IdentityError(
                    f"precedence entry {cred_id!r} of {identity_id} is not in its credentials")
            secret = self.secrets.get(cred_id)
            if secret is None:
                raise IdentityError(f"no secret for {cred_id} — refusing to send "
                                    f"half-authenticated (atomic contract)")
            app = cred.get("application", {})
            inject = app.get("inject")
            name = app.get("name") or ("Authorization" if inject == "bearer" else None)
            if inject in ("cookie", "header", "authorization", "bearer", "query") and name:
                plan.append({"credential": cred_id, "inject": inject,
                             "name": name, "value": secret,
                             "scope": cred.get("scope", {})})
        return plan

    def _apply(self, plan: list[dict], url: str,
               headers: dict, params: dict, cookies: dict) -> list[str]:
        applied = []
        host = httpx.URL(url).host
        path = httpx.URL(url).path or "/"
        for inj in plan:
            if not _scope_allows(inj["scope"], host, path):
                # Same contract as the Burp side: out-of-scope injection is an
                # error, not a skip — the caller asked for this identity.
                raise IdentityError(
                    f"{inj['credential']} not scoped for {host}{path} — refusing to inject")
            kind, name, value = inj["inject"], inj["name"], inj["value"]
            if kind == "cookie":
                cookies[name] = value
            elif kind == "bearer":
                headers[name] = f"Bearer {value}"
            elif kind in ("header", "authorization"):
                headers[name] = value
            elif kind == "query":
                params[name] = value
            applied.append(f"{kind}:{name}<-{inj['credential']}")
        return applied

    # ── request ──────────────────────────────────────────────────────────────

    async def request(self, identity_id: str, method: str, url: str, *,
                      headers: Optional[dict] = None, body: Union[str, bytes, None] = None,
                      params: Optional[dict] = None) -> httpx.Response:
        plan = self.resolve_injections(identity_id)
        headers = dict(headers or {})
        params = dict(params or {})
        cookies: dict = {}
        self._apply(plan, url, headers, params, cookies)
        client = self._client_for(identity_id)
        return await client.request(method, url, headers=headers, params=params,
                                    cookies=cookies, content=body)


# ── CLI smoke: python3 data_client.py <registry.json> <identity> <url> ──────
# Secrets come from KEY=VALUE env vars (credential id -> secret):
#   cred:web1=s3cr3t python3 data_client.py registry.json id:persona-1 https://...

async def _cli() -> None:
    import asyncio, sys
    path, identity, url = sys.argv[1], sys.argv[2], sys.argv[3]
    kv = dict(a.split("=", 1) for a in sys.argv[4:] if "=" in a)
    secrets = {k: v for k, v in kv.items() if k.startswith("cred:")}
    egresses = {k: v for k, v in kv.items() if k.startswith("egress:")}
    async with IdentityPlane.from_registry_file(path, secrets, egresses) as plane:
        for inj in plane.resolve_injections(identity):
            print("plan:", inj["inject"], inj["name"], "<-", inj["credential"])
        r = await plane.request(identity, "GET", url)
        print(r.status_code, r.http_version, r.request.url)

if __name__ == "__main__":
    import asyncio
    asyncio.run(_cli())
