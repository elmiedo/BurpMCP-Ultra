<div align="center">

# BurpMCP-Ultra

**The most powerful MCP server for Burp Suite Professional.**

Drop a single JAR into Burp, connect Claude Code (or any MCP client), and drive every
part of Burp Suite programmatically through AI agents.

[![Latest release](https://img.shields.io/github/v/release/elmiedo/BurpMCP-Ultra?color=1f6feb&label=release)](https://github.com/elmiedo/BurpMCP-Ultra/releases/latest)
[![Build](https://img.shields.io/github/workflow/status/elmiedo/BurpMCP-Ultra/build/Build)](https://github.com/elmiedo/BurpMCP-Ultra/actions/workflows/build.yml)
[![License](https://img.shields.io/badge/license-MIT-3fb950)](#license)
[![Burp Suite](https://img.shields.io/badge/Burp%20Suite-Professional-ff6633)](https://portswigger.net/burp)
[![Kotlin](https://img.shields.io/badge/Kotlin-2.1.20-7F52FF?logo=kotlin&logoColor=white)](https://kotlinlang.org)
[![MCP tools](https://img.shields.io/badge/MCP%20tools-154-8957e5)](#tools)
[![Stars](https://img.shields.io/github/stars/elmiedo/BurpMCP-Ultra?style=flat&color=e3b341)](https://github.com/elmiedo/BurpMCP-Ultra/stargazers)
[![Telegram](https://img.shields.io/badge/Telegram-%40D4RK__V0RT3X-2CA5E0?logo=telegram&logoColor=white)](https://t.me/D4RK_V0RT3X)

**154 Tools** &bull; **8 Resources** &bull; **17 Event Types** &bull; Real-time Dashboard &bull; Hardened Localhost Security

[Architecture](#architecture) &bull;
[Tools](#tools) &bull;
[Quick Start](#quick-start) &bull;
[Tool Classes](#tool-classes) &bull;
[Use Cases](#use-cases) &bull;
[Security](#security-model)

</div>

---

BurpMCP-Ultra is a native **Kotlin** Burp Suite extension with an embedded **MCP (Model
Context Protocol)** server. It exposes Burp's Montoya API as 154 structured tools over a
token-secured local SSE transport, so an AI agent can run proxy history analysis, active
scans, fuzzing, race conditions, OOB testing, custom scan checks, and guided exploitation
— all from natural language.

## Architecture

![BurpMCP-Ultra architecture](docs/architecture.png)

Reading order — top to bottom, left to right: the MCP client talks JSON-RPC over
SSE to the extension's transport; the `ToolRegistry` fans tool calls out to the
bridge layer, which drives Burp's Montoya API (Proxy, Scanner, Intruder,
Repeater, Collaborator). The Identity Matrix (right) resolves imported
identities and applies credentials atomically to outgoing requests; the manager
side (bottom right) resolves vault secrets and serializes egress grants to
Burp's global upstream. Editable source: [docs/architecture.drawio](docs/architecture.drawio).

## Why BurpMCP-Ultra?

Compared at the level of capability classes, not single tools. Counts are of
Ultra's tool classes; the same table per tool is in [Tools](#tools).

| Capability class | BurpMCP-Ultra | burp-ai-agent | PortSwigger Official |
|---|:---:|:---:|:---:|
| **HTTP traffic & request crafting** — structured/raw send, chains, fuzzing, races, raw bytes | 13 tools | partial | partial |
| **Proxy triage** — history, regex search, traffic stats, intercept, per-item rules | 14 tools | partial | – |
| **Scanning & crawling** — crawl, audit, tasks, issues, reports, BCheck import | 13 tools | partial | – |
| **Custom scan checks** — BCheck DSL + scripted passive/active checks | 10 tools | – | – |
| **Access control & IDOR** — sweep, auth diff, canary-confirmed horizontal hunt | 3 tools | – | – |
| **Injection & JWT offense** — oracle-confirmed SQLi/SSTI/LFI, alg:none / RS→HS / crack | 2 tools | – | – |
| **Recon & fingerprinting** — JS endpoints, content discovery, param mining, CORS, WAF | 5 tools | – | – |
| **Passive intel extraction** — 30+ secret/infra patterns, entropy de-noised, MIME-scoped | 1 tool | – | – |
| **WebSocket testing** — full lifecycle + intercept rules | 7 tools | – | – |
| **Collaborator OOB** — create / poll / correlate / restore | 7 tools | partial | partial |
| **Identity Matrix** — registry import, atomic credential application, per-identity egress | 3 tools + `identity/` module | – | – |
| **Agent working memory** — deduplicated findings store surviving reloads | 2 tools | – | – |
| **Events, persistence & platform control** — event bus, storage, config, task engine, handoffs | 41 tools | partial | partial |
| **Utilities** — encode/decode/hash/compress/random/smart-decode | 12 tools | partial | – |
| **Real-time web dashboard** | yes | – | – |
| **Hardened localhost security** — host/origin allowlist, token, scope gate, audit log | yes | partial | partial |

> Competitor marks are indicative, based on each project's public tool list.

## Tools

**154 MCP tools across 38 classes.** Names are stable; the authoritative count is
`server.tools.size`, surfaced in the Server tab. Full per-tool reference (parameters,
returns, the exact wording the server advertises to the agent): **[docs/tools.md](docs/tools.md)** —
regenerate it with `python3 scripts/gen_tool_docs.py` after changing tool schemas.

| Class | Tools |
|---|---|
| **Proxy** (14) | `proxy_history` `proxy_history_search` `proxy_traffic_stats` `proxy_websocket_history` `proxy_websocket_history_search` `proxy_intercept_enable` `proxy_intercept_disable` `proxy_intercept_status` `proxy_annotate` `proxy_set_request_rule` `proxy_set_response_rule` `proxy_list_rules` `proxy_remove_rule` `proxy_auto_auth` |
| **HTTP** (13) | `http_send_request` `http_send_requests_parallel` `http_send_request_chain` `http_send_raw_bytes` `http_fuzz` `http_race` `http_cookie_jar_get` `http_cookie_jar_set` `http_analyze_keywords` `http_analyze_variations` `http_set_traffic_rule` `http_list_traffic_rules` `http_remove_traffic_rule` |
| **Scanner** (13) | `scanner_start_crawl` `scanner_start_audit` `scanner_task_status` `scanner_task_list` `scanner_task_delete` `scanner_task_add_request` `scanner_task_issues` `scanner_get_all_issues` `scanner_generate_report` `scanner_create_issue` `scanner_import_bcheck` `scanner_register_check` `scanner_unregister_check` |
| **Collaborator** (7) | `collaborator_create_client` `collaborator_restore_client` `collaborator_generate_payload` `collaborator_poll` `collaborator_server_info` `collaborator_get_secret` `collaborator_default_payload` |
| **Intruder & Repeater** (4) | `intruder_send` `intruder_send_with_positions` `intruder_register_payload_processor` `repeater_send` |
| **WebSocket** (7) | `websocket_create` `websocket_send_text` `websocket_send_binary` `websocket_close` `websocket_list` `websocket_get_messages` `websocket_set_intercept_rule` |
| **Analysis** (7) | `analyze_request` `analyze_response` `analyze_find_reflected` `analyze_extract_params` `analyze_insertion_points` `analyze_diff` `analyze_response_body_search` |
| **Utilities** (12) | `util_url_encode` `util_url_decode` `util_base64_encode` `util_base64_decode` `util_html_encode` `util_hash` `util_compress` `util_decompress` `util_random_string` `util_random_bytes` `util_jwt_decode` `util_decode_smart` |
| **BCheck** (5) | `bcheck_create` `bcheck_import` `bcheck_templates` `bcheck_list` `bcheck_remove` |
| **Scan Checks — script** (5) | `scancheck_create_passive` `scancheck_create_active` `scancheck_templates` `scancheck_list` `scancheck_remove` |
| **Burp Suite** (9) | `burp_version` `burp_export_project_config` `burp_import_project_config` `burp_export_user_config` `burp_import_user_config` `burp_task_engine_state` `burp_task_engine_set` `burp_command_line_args` `burp_shutdown` |
| **Config** (7) | `config_proxy_listeners_list` `config_proxy_listener_add` `config_proxy_listener_remove` `config_match_replace_add` `config_match_replace_list` `config_match_replace_remove` `config_upstream_proxy_set` |
| **Events** (5) | `events_get` `events_get_by_type` `events_subscribe` `events_unsubscribe` `events_clear` |
| **Persistence & Preferences** (6) | `persistence_store` `persistence_get` `persistence_delete` `persistence_list` `preference_store` `preference_get` |
| **Session Handling** (3) | `session_create_token_rule` `session_list_rules` `session_remove_rule` |
| **Recon** (3) | `recon_js_endpoints` `recon_content_discovery` `recon_param_mine` |
| **Identity Matrix** (3) | `identity_import` `identity_list` `identity_status` |
| **Findings** (2) | `findings_add` `findings_list` |
| **Burp AI** (2) | `ai_status` `ai_prompt` |
| **Logging** (2) | `log_message` `log_event` |
| **Organizer** (2) | `organizer_send` `organizer_get_items` |
| **Web Probe** (2) | `cors_probe` `recon_fingerprint` |
| **JWT** (1) | `jwt_attack` |
| **GraphQL** (1) | `graphql_probe` |
| **Passive Intel** (1) | `passive_intel` |
| **Auth Diff** (1) | `auth_diff` |
| **API Import** (1) | `api_import_openapi` |
| **Access Control** (1) | `access_control_sweep` |
| **Injection Probe** (1) | `injection_probe` |
| **IDOR Hunt** (1) | `idor_hunt` |
| **Bambda** (1) | `bambda_import` |
| **Project** (1) | `project_info` |
| **Extension** (1) | `extension_info` |
| **Comparer** (1) | `comparer_send` |
| **Decoder** (1) | `decoder_send` |
| **Scope** (4) | `scope_check` `scope_include` `scope_exclude` `scope_get_config` |
| **Sitemap** (4) | `sitemap_query` `sitemap_get_issues` `sitemap_add_request` `sitemap_add_issue` |

**Resources** (8, read-only, no tool call needed): `burp://proxy/history` ·
`burp://proxy/websocket/history` · `burp://scanner/issues` · `burp://sitemap` ·
`burp://scope` · `burp://config/project` · `burp://config/user` · `burp://organizer/items`

> Offensive tools that issue live requests are **scope-gated** (see [Security Model](#security-model)).

## Quick Start

### 1. Build

```bash
git clone https://github.com/elmiedo/BurpMCP-Ultra.git
cd BurpMCP-Ultra
./gradlew shadowJar
```

Output: `build/libs/burpmcp-ultra-2.5.0-alpha.2.jar` (~13 MB). A **JDK 17–21** must be installed —
see [Building from Source](#building-from-source). Pre-built JARs are on the
[Releases](https://github.com/elmiedo/BurpMCP-Ultra/releases) page.

### 2. Load into Burp

1. Burp Suite Pro → **Extensions** → **Add**
2. Select the JAR
3. The **BurpMCP-Ultra** tab appears with a green "Running" status and your connection token

### 3. Connect Claude Code

```json
{
  "mcpServers": {
    "burp": {
      "type": "sse",
      "url": "http://127.0.0.1:9876/",
      "headers": {
        "Authorization": "Bearer PASTE_TOKEN_FROM_SERVER_TAB"
      }
    }
  }
}
```

Add to `~/.claude.json` or your project's `.mcp.json`.

> ⚠️ **The token is required, and the endpoint is the root path `/` — not `/sse`.**
> Copy the token from the **Server** tab of the BurpMCP-Ultra panel in Burp. Without it the
> server returns `401`, and clients like Claude Code then fall back to OAuth discovery and
> fail with `SDK auth failed: HTTP 404: Invalid OAuth error response`.

> 💡 **MCP client can't set headers?** Use the token-in-path URL — no `headers` block needed
> (GitHub issue #11). Copy it with **"Copy No-Headers Config"** on the Server tab:
>
> ```json
> { "mcpServers": { "burp": { "type": "sse", "url": "http://127.0.0.1:9876/PASTE_TOKEN_FROM_SERVER_TAB/" } } }
> ```
>
> **Keep the trailing slash** — it is what makes the token survive onto the SSE back-channel.
> A `?token=…` query does **not** work for MCP: the SDK advertises its POST endpoint as the
> relative reference `?sessionId=…`, which per RFC 3986 §5.3 replaces the query (so the token is
> dropped and every message `401`s) while preserving the path. Note the token becomes part of the
> URL, so prefer the header form when your client supports it.

### 4. Open Dashboard

Browse to **http://127.0.0.1:9878** for the real-time web dashboard.

## Tool Classes

What you hand each class and what comes back, one line per class. Full parameter-level
detail lives in [docs/tools.md](docs/tools.md); worked examples for the agent in
[Use Cases](#use-cases).

- **Proxy** — give filters (host/method/status/MIME/scope), get filtered history rows, aggregate triage stats, or set intercept/rules. [`docs`](docs/tools.md#proxy)
- **HTTP** — give a structured or raw request, get the full response with timing; give a `FUZZ`-marked request + payloads, get all fuzz responses; give N identical requests, get race analysis. `http_send_request`/`http_fuzz` accept an `identity` for atomic auth application. [`docs`](docs/tools.md#http)
- **Scanner** — give seed URLs or a request + audit config, get task ids; poll status, collect issues, generate reports. [`docs`](docs/tools.md#scanner)
- **Collaborator** — get a client + payloads, later poll DNS/HTTP/SMTP interactions; restore a client from its secret across sessions. [`docs`](docs/tools.md#collaborator)
- **Intruder & Repeater** — give a request, get an Intruder attack or a Repeater tab (native HTTP/2 via `http2=true`). [`docs`](docs/tools.md#intruder)
- **WebSocket** — give a URL, get a live connection id; send text/binary frames, read filtered history, set intercept rules. [`docs`](docs/tools.md#websocket)
- **Analysis** — give a raw message or two, get parsed structure, extracted params, insertion points, reflection surface, diffs, or a body search across history. [`docs`](docs/tools.md#analysis)
- **Utilities** — give a value, get it encoded/decoded/hashed/compressed/randomized; `util_decode_smart` peels multi-layer encodings. [`docs`](docs/tools.md#utilities)
- **BCheck / Scan Checks** — give a pattern or a multi-step payload chain, get a deployed custom scan check (passive or active) running inside Burp's scanner. [`docs`](docs/tools.md#bcheck)
- **Burp Suite / Config** — get version, configs, task-engine state, command line; set listeners, match-replace rules, upstream proxy (used by the Identity egress contract). [`docs`](docs/tools.md#burp-suite)
- **Events** — subscribe to 17 event types; give filters, get the event log. Powers the dashboard and agent push notifications. [`docs`](docs/tools.md#events)
- **Persistence & Preferences** — key-value storage in project scope or global preferences; survives reloads. [`docs`](docs/tools.md#persistence--preferences)
- **Session Handling** — give an extract+inject rule, get automatic session token rotation on matched requests. [`docs`](docs/tools.md#session-handling)
- **Recon / Web Probe** — give a host, get JS-harvested endpoints, discovered paths, mined params, CORS misconfigs, tech/WAF fingerprints. [`docs`](docs/tools.md#recon)
- **Identity Matrix** — give a registry (+ secrets from the manager), get validated identities; pass `identity=` to HTTP tools or `registry_id=` to AC tools for atomic, layer-replacing auth. [`docs`](docs/tools.md#identity-matrix)
- **Findings** — give type+url (+detail/evidence/CVSS/steps), get a deduplicated finding id; list with filters. The agent's working memory for reporting. [`docs`](docs/tools.md#findings)
- **Offense: Injection / JWT / GraphQL / IDOR / Auth Diff / Access Control** — give a request + target info, get confirmed verdicts (oracle-checked SQLi/SSTI/LFI, JWT forgeries, GraphQL introspection, canary-confirmed cross-user reads, privesc flags). [`docs`](docs/tools.md#injection-probe)
- **Passive Intel** — give nothing (optional filters), get secrets/tokens/internal IPs/leaks found across captured traffic, entropy- and MIME-de-noised. [`docs`](docs/tools.md#passive-intel)
- **API Import** — give an OpenAPI/Swagger spec, get generated (optionally sent) requests and a populated sitemap. [`docs`](docs/tools.md#api-import)
- **Platform bits** — Comparer/Decoder/Organizer handoffs, logging, project/extension info, Burp AI, Bambda import. [`docs`](docs/tools.md#comparer)

## Identity Matrix (2.5.0-alpha.2)

Multi-account, anti-correlation operations need every server-correlatable signal —
cookies, tokens, IP, headers, fingerprints — to rotate **together**. The
[`identity/`](identity/) module defines the four-layer model:

| Layer | What it is | Mutability |
|---|---|---|
| **credential** | typed secret material (oauth2 / jwt / session-cookie / hmac-signature / mTLS / …) + scope + injection + lifecycle | immutable seed |
| **identity** | persona: credential bundle (by reference) + presentation (egress, locale, JA3/JA4) | stable |
| **binding** | agent×identity matrix: dedicated or pooled (sticky/round-robin, leases, back-pressure) | policy |
| **session** | live state: cookie jar, tokens, CSRF, timing clocks, bound egress | mutable, never written back |

Key properties: secrets only via `vault://` refs (plaintext is schema-rejected);
idle (sliding) and absolute expiry are **different clocks** — keepalive attacks
one, refresh/reauth the other; unknown idle timeouts self-calibrate from observed
deaths; scope-gated injection refuses to place a live token on an off-scope host.

**Execution contract** (machine-checked): Montoya's upstream proxy is global, so
per-identity egress inside Burp is impossible for parallel active traffic.
Bindings therefore declare `execution: parallel` (manager's own httpx+socks
client, N identities concurrent, per-identity egress) or `execution: burp-native`
(Burp Scanner/Intruder/Repeater via the global upstream under an exclusive egress
lock — one identity at a time). Contradictory combinations
(burp-native + max_concurrent>1, burp-native + stateless_fanout) are rejected by
the validator.

Artifacts: [`identity-matrix.schema.json`](identity/identity-matrix.schema.json)
(draft 2020-12, format-assertive) · [`validate_registry.py`](identity/validate_registry.py)
(schema + integrity gate, CI-ready) · [`session_manager.py`](identity/session_manager.py)
(live cycle + deterministic demos A–F) · [module README](identity/README.md).
MCP integration is live: `identity_import` / `identity_list` / `identity_status`,
the `identity` parameter on `http_send_request` / `http_fuzz`, and `registry_id`
on `idor_hunt` / `access_control_sweep` / `auth_diff` identity entries.

## Use Cases

What to hand an LLM agent first, and what it can confirm on its own.

### Guided Injection Probe
```
injection_probe(
  request: "GET /item?id=FUZZ HTTP/1.1\r\nHost: shop.com\r\n\r\n",
  host: "shop.com", port: 443,
  classes: ["sqli", "ssti", "lfi"]      # optional; default all
)
```
Marks the injection point with `FUZZ`, then **confirms** vulnerabilities with deterministic
oracles — SQL error fingerprints, time-delay analysis, template math-evaluation
(`1337*1337 → 1787569`), and file-content markers — returning only confirmed findings with
the triggering payload. For blind/OOB classes, pair `collaborator_*` with `http_fuzz`.

### JWT Attacks
```
jwt_attack(token: "eyJ...", mode: "crack", wordlist: ["secret", "changeme", ...])
```
`alg:none` forgery, **RS→HS** algorithm-confusion forging, weak-secret dictionary cracking,
and full structural analysis.

### Access-Control Sweep
```
auth_diff / access_control_sweep
  request: "GET /api/users/1 HTTP/1.1\r\nHost: api.com\r\n\r\n",
  auth_levels: [
    {"name": "admin", "header_name": "Authorization", "header_value": "Bearer admin"},
    {"name": "user",  "header_name": "Authorization", "header_value": "Bearer user"},
    {"name": "none"}
  ]
```
Replays the same request(s) across identities, diffs the responses, and flags **IDOR**,
privilege escalation, and missing authorization. With an imported registry, replace the
header pairs with `{"name": "user", "registry_id": "id:user-1", "object_id": …, "canary": …}`.

### Race Condition Testing
```
http_race(request: "POST /api/transfer HTTP/1.1\r\nHost: bank.com\r\n\r\n{\"amount\":100}",
          host: "bank.com", port: 443, count: 20)
```
Fires 20 identical requests simultaneously via Burp's parallel engine and analyzes
status/length distributions to detect TOCTOU, double-spend, and limit-bypass bugs.

### Inline Fuzzer (3 modes)
```
# FUZZ keyword
http_fuzz(request: "GET /api?id=FUZZ HTTP/1.1\r\nHost: api.com\r\n\r\n", host: "api.com",
          port: 443, payloads: ["1", "admin", "../../etc/passwd"])
# §section§ markers (like Intruder)   |   # byte offsets: positions: [[12, 15]]
# built-in payload libraries via:     payload_library: "xss" | "sqli" | "lfi" | ...
```

### Custom Scan Checks
```
# BCheck DSL
bcheck_create(name: "AWS Key Leak", type: "passive_response",
              match_pattern: "AKIA[0-9A-Z]{16}", severity: "high", confidence: "firm")
# Script mode — multi-step active check
scancheck_create_active(name: "SSTI", steps: [
  {"payload": "{{7*7}}", "response_conditions": [
    {"location": "response_body", "pattern": "49", "condition_type": "contains"}]}])
```

### API Schema Import
```
api_import_openapi(spec_json: "<swagger/openapi JSON>", auth_header: "Authorization",
                   auth_value: "Bearer …", send_requests: true, add_to_sitemap: true)
```
Parses OpenAPI 3.x / Swagger 2.0 (resolving `$ref`), generates real requests with sample
parameters/bodies for every endpoint, and optionally sends them — populating proxy history
and sitemap. Out-of-scope sends are skipped and reported.

### Passive Intelligence Extraction
```
passive_intel(max_items: 2000, in_scope_only: true)
```
Scans captured traffic for 30+ patterns with entropy de-noising and MIME scoping to cut
false positives:
- **Cloud credentials** — AWS keys, Google/Slack/Stripe/GitHub tokens
- **Tokens & secrets** — JWTs, Bearer/Basic auth, private keys
- **Personal data** — emails, internal IPs, phone numbers
- **Cloud resources** — S3/Azure/GCS buckets
- **Infrastructure** — internal URLs, GraphQL endpoints, API paths
- **Errors & fingerprints** — stack traces, SQL errors, server/framework versions
- **Sensitive paths** — `/admin`, `/.env`, `/.git`, `/debug`, `/actuator`

---

## Security Model

BurpMCP-Ultra runs three local servers (SSE `9876`/`9877`, dashboard `9878`). Binding to
`127.0.0.1` is **not** a trust boundary, so the transport is hardened and offensive tools are
governed by **operator-only** controls the agent cannot change.

> **Port already in use?** PortSwigger's own **MCP Server** extension also defaults to **9876**, so
> running both at once clashes. Move this extension with the `mcp_sse_port` / `mcp_http_port` /
> `mcp_dashboard_port` preferences (or `-Dburpmcp.ssePort=…`), then reload. On a clash the
> extension now says so explicitly in the Errors tab — it is *not* the JDK-version problem.

**Transport hardening**
- **Host-header allowlist** — defeats DNS rebinding.
- **Origin lockdown** — rejects cross-origin browser requests; CORS only advertises loopback.
- **Per-session token** — required on every request (`Authorization: Bearer`, `mcp_token`
  cookie, `?token=`, or the first URL **path** segment `/<token>/` for header-less MCP clients).
  The dashboard uses an `HttpOnly` cookie, so the token never lives in a URL there. A back-channel
  `POST ?sessionId=…` may instead present a live session id — a 122-bit capability the server
  discloses only over an already-authenticated stream, never a bypass.

**Operator governance** (configured in Burp, not via MCP)
- `mcp_scope_mode` — `off` / `warn` / `enforce`. Every live-request tool passes through a
  central **scope gate** (`http_*`, `auth_diff`, `api_import_openapi`, `recon_*`, `graphql_probe`,
  `cors_probe`, `access_control_sweep`, `injection_probe`).
- `mcp_allow_destructive` — default **false**; blocks `burp_shutdown` and config import.
- **Append-only audit log** of security-relevant tool calls (`~/.burpmcp-ultra-audit.jsonl`).

Additional defenses: ReDoS-safe regex, CRLF header validation, and response/WebSocket size caps.

---

## Web Dashboard

Open **http://127.0.0.1:9878** for the real-time dashboard:

- **Live Activity Stream** with noise filtering (auto-hides Google/Apple/Microsoft connectivity checks)
- **Attack Vector Detection** — badges for AUTH, API, PARAMS, UPLOAD, ADMIN, DATA endpoints
- **Request Detail Panel** — click any item for full request info + send-to-tool actions
- **Stats Bar** — live counters for events, in-scope hosts, and attack-vector categories
- **Filter Controls** — type filters, URL search, noise toggle
- **Active Rules** — view all proxy, traffic, and session rules
- **Connection Info** — transport URLs and a ready-to-paste MCP client config

---

## Setup Guides

<details>
<summary><strong>Claude Code (Direct SSE)</strong></summary>

```json
{
  "mcpServers": {
    "burp": {
      "type": "sse",
      "url": "http://127.0.0.1:9876/",
      "headers": { "Authorization": "Bearer PASTE_TOKEN_FROM_SERVER_TAB" }
    }
  }
}
```
The token comes from the **Server** tab. The endpoint is the root path `/` (not `/sse`). If your
client cannot set headers, drop the `headers` block and put the token in the path instead —
`"url": "http://127.0.0.1:9876/<token>/"` (keep the trailing slash). Config locations:
`~/.claude.json` (global) or `.mcp.json` (per-project).

</details>

<details>
<summary><strong>Claude Code via Caddy (recommended for stability)</strong></summary>

Caddy prevents SSE timeout disconnections and provides reliable buffering.

```bash
sudo apt install caddy
```
`/etc/caddy/Caddyfile`:
```
:9900 {
    reverse_proxy 127.0.0.1:9876 {
        transport http { read_timeout 0  write_timeout 0  response_header_timeout 0 }
        flush_interval -1
        header_up Connection {>Connection}
        header_up Upgrade {>Upgrade}
    }
}
```
```bash
sudo systemctl restart caddy
```
Then point your config at port 9900:
```json
{
  "mcpServers": {
    "burp": {
      "type": "sse",
      "url": "http://127.0.0.1:9900/",
      "headers": { "Authorization": "Bearer PASTE_TOKEN_FROM_SERVER_TAB" }
    }
  }
}
```
Pre-built Caddyfile: [`configs/Caddyfile`](configs/Caddyfile)

</details>

<details>
<summary><strong>Claude Desktop (stdio via proxy)</strong></summary>

Claude Desktop only supports stdio transport. Bridge it with supergateway:
```json
{
  "mcpServers": {
    "burp": {
      "command": "npx",
      "args": ["-y", "supergateway", "--sse", "http://127.0.0.1:9876/", "--header", "Authorization: Bearer PASTE_TOKEN_FROM_SERVER_TAB"]
    }
  }
}
```

</details>

<details>
<summary><strong>Automated setup script</strong></summary>

```bash
chmod +x configs/setup.sh
./configs/setup.sh
```
Builds the JAR, optionally configures Caddy, and prints the MCP config to add.

</details>

---

## Tech Stack

| Component | Version |
|-----------|---------|
| Kotlin | 2.1.20 |
| JVM Target | 17 |
| Montoya API | 2026.2 |
| MCP Kotlin SDK | 0.8.3 |
| Ktor CIO | 3.2.3 |
| kotlinx.serialization | 1.8.1 |
| Shadow JAR | 8.1.1 |

## Requirements

**To run (inside Burp):**
- Burp Suite Professional 2025.x or later
- Java 17+ — provided by Burp's bundled JRE (nothing to install)

**To build from source:**
- A **JDK 17–21** (LTS) installed. Building under Java 22+ (including Burp's bundled Java 25)
  is incompatible with the Kotlin 2.1.20 / Ktor 3.2.3 / MCP SDK toolchain and yields a JAR
  whose MCP SSE ports silently fail to bind. You do **not** need JDK 17 as your default,
  though: the build pins both compilation and the Gradle daemon to a JDK 17 toolchain
  (`gradle/gradle-daemon-jvm.properties`), so `./gradlew` auto-runs under JDK 17 as long as
  one is installed and discoverable.
- Gradle 8.x — included via the committed wrapper (`./gradlew` / `gradlew.bat`).

## Building from Source

The Gradle wrapper is committed, so no separate Gradle install is needed.

**Linux / macOS**
```bash
git clone https://github.com/elmiedo/BurpMCP-Ultra.git
cd BurpMCP-Ultra
# Gradle auto-selects an installed JDK 17 for the build daemon, so this works even if your
# default `java` is Burp's Java 25. If no JDK 17 is discoverable, install one (or set JAVA_HOME).
./gradlew shadowJar
# Output: build/libs/burpmcp-ultra-2.5.0-alpha.2.jar
```

**Windows (PowerShell / cmd)**
```bat
git clone https://github.com/elmiedo/BurpMCP-Ultra.git
cd BurpMCP-Ultra
:: Gradle auto-selects an installed JDK 17 for the build daemon, so this works even if your
:: default `java` is Burp's Java 25. If no JDK 17 is discoverable, install one (or set JAVA_HOME).
gradlew.bat shadowJar
:: Output: build\libs\burpmcp-ultra-2.5.0-alpha.2.jar
```

> If no JDK 17 is found, Gradle fails with a clear "no compatible daemon JVM" error instead of
> silently producing a broken JAR. Kotlin 2.1.20 cannot even *compile* the Gradle build scripts
> under Java 22+, which is why the daemon is pinned to JDK 17.

## Project Structure

```
BurpMCP-Ultra/
├── build.gradle.kts              # Build configuration
├── gradle/                       # Wrapper + daemon-JVM pin (JDK 17)
├── configs/                      # Ready-to-use config files (Caddyfile, MCP JSON, setup.sh)
├── scripts/gen_tool_docs.py      # Regenerates docs/tools.md from source
├── src/main/kotlin/com/burpmcp/ultra/
│   ├── core/                     # Extension entry point + helpers
│   ├── bridge/                   # Montoya API bridges
│   ├── tools/                    # 38 tool class modules (154 tools)
│   ├── safety/                   # Scope gate, action policy, ReDoS-safe regex
│   ├── transport/                # MCP server + dashboard + security
│   ├── events/                   # Unified event bus
│   ├── state/                    # State management
│   └── ui/                       # Swing UI tab
├── identity/                     # Identity Matrix module: schema, validator, session manager
├── src/test/                     # 451 unit tests
└── docs/                         # Tool reference (tools.md), architecture, capability review
```

---

## Contact & Support

- 🐛 **Bugs & feature requests:** [GitHub Issues](https://github.com/elmiedo/BurpMCP-Ultra/issues)
- 📦 **Releases & changelog:** [GitHub Releases](https://github.com/elmiedo/BurpMCP-Ultra/releases)
- 💬 **Quick reach:** Telegram [**@D4RK_V0RT3X**](https://t.me/D4RK_V0RT3X)

## License

[MIT](LICENSE)

---

<div align="center">
Built for bug-bounty hunters and pentesters who want AI-powered Burp Suite automation.
</div>
