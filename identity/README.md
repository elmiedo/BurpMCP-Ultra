# Identity Matrix — credential/identity/binding/session model + session manager

Four-layer identity model for multi-account agent operations against rate-limiting
and identity-correlating targets. Layers:

1. **credential** — immutable typed secret material (basic/bearer/api-key/oauth2/jwt/
   session-cookie/signed-cookie/tls-client-cert/hmac-signature/digest/totp-seed),
   scope (suffix-match host globs, dot boundary), application (inject: header|cookie|
   query|tls|signer), lifecycle with auto-quarantine, renewal policy (keepalive
   attacks IDLE timeout, refresh/reauth attack ABSOLUTE expiry).
2. **identity** — persona: credential bundle by reference + presentation
   (egress/UA-locale/fingerprints). Everything a server can correlate, rotated together.
3. **binding** — the agent×identity matrix: dedicated or shared pool with strategies
   (sticky/round_robin/...), leases, max_concurrent back-pressure, stateless_fanout.
4. **session** — mutable runtime state (cookie jar, live tokens, CSRF, timing clocks);
   never written back into the credential.

## Execution contract (Burp Suite Pro MCP)

Montoya's upstream proxy is **global** — there is no per-request egress. Therefore:

- **passive** ops (site map, proxy history, passive checks) — Burp-native, egress-agnostic;
- **parallel** (`execution: "parallel"`, default) — active ops through the manager's own
  HTTP client (httpx+socks), honoring per-identity egress, N identities concurrent;
- **burp-native** (`execution: "burp-native"`) — Scanner/Intruder/Repeater run via the
  global upstream under an exclusive egress lock: exactly one identity/egress at a time,
  others queue FIFO.

Enforced invariants (see validate_registry.py): burp-native + max_concurrent>1 is
meaningless (rejected); burp-native + stateless_fanout is contradictory (rejected);
stateless_fanout must not reference stateful credentials (session-cookie/signed-cookie/
oauth2/digest, or cookie-borne bearer/jwt); sticky needs affinity_key; secrets only via
vault:// refs; inline renewal XOR renewal_ref.

## Files

- `identity-matrix.schema.json` — JSON Schema draft 2020-12 (format-assertive); root
  validates a single record by `kind`, `#/$defs/registry` validates a whole file.
- `validate_registry.py` — schema pass (with FormatChecker) + referential integrity.
  Exit 0/1/2 (clean/problems/bad input). `pip install jsonschema[format]` recommended.
- `session_manager.py` — the live cycle: minting, keepalive vs refresh, idle
  self-calibration from observed deaths, leases, EgressLock. Deterministic VirtualClock
  demos (scenarios A–F) run in milliseconds: `python3 session_manager.py`.
  Single-threaded by design — see CONCURRENCY note before driving from parallel MCP calls.
- `examples/registry.example.json` — small valid registry.
