#!/usr/bin/env python3
"""
Session manager skeleton for a fleet of web+API agents.

Pairs with identity-matrix.schema.json: it consumes credentials (+ renewal
policy) and produces/keeps Layer-4 sessions alive. It implements the behaviour
the schema cannot express — the live cycle:

  * mint a session from a credential (login / token exchange)
  * keepalive loop that attacks the server's IDLE (sliding) timeout
  * refresh/reauth that attacks the ABSOLUTE expiry
  * self-calibration of an unknown idle_timeout from observed deaths
  * leases for shared pools (sticky affinity + max_concurrent back-pressure)

Design: everything is event-driven on a Scheduler against an injectable Clock.
The demo runs on a VirtualClock (deterministic, instant) so 15-minute timeouts
prove out in milliseconds. In production you swap two seams:
    Clock      -> wall-clock time
    Scheduler  -> asyncio (loop.call_later) or your job runner
and swap the Vault/Authenticator/target I/O stubs for real ones. Nothing else
in the core changes.

In the Burp-MCP setting this is a PRODUCTION component, not a throwaway skeleton:
the identity-layer HTTP client (httpx+socks) lives here and owns per-identity
egress, because Montoya's upstream proxy is global and cannot do per-request
egress. Active Burp tools (Repeater/Scanner/Intruder) will NOT honor egress_ref;
only this client does. Burp receives such traffic as a passive mirror only.

CONCURRENCY: this skeleton is single-threaded/deterministic. LeasePool and the
session map are NOT thread/async-safe as written — wrap checkout/checkin and the
session dict in a lock (or run the manager on one event loop) before driving it
from parallel MCP calls, or max_concurrent and the lease invariants will leak.
"""

from __future__ import annotations
import heapq
import itertools
from dataclasses import dataclass, field
from typing import Callable, Optional


# ─────────────────────────────── helpers / seams ───────────────────────────────

def parse_duration(s: str) -> float:
    """'30m' -> 1800.0 seconds. Matches the schema's duration pattern."""
    unit = {"s": 1, "m": 60, "h": 3600, "d": 86400}[s[-1]]
    return int(s[:-1]) * unit


def fmt(t: float) -> str:
    return f"{int(t)//60:02d}:{int(t)%60:02d}"


def host_matches(pattern: str, host: str) -> bool:
    """Suffix-match with a dot boundary (see scope.hosts in the schema).
    '*.acme.example' matches a.acme.example, x.y.acme.example; NOT acme.example,
    NOT notacme.example. A bare host matches only itself."""
    host = host.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        suffix = pattern[1:]                       # ".acme.example"
        return host.endswith(suffix) and len(host) > len(suffix)
    return host == pattern


def scope_allows(scope: dict, host: str, path: str = "/") -> bool:
    import fnmatch
    if not any(host_matches(p, host) for p in scope.get("hosts", [])):
        return False
    paths = scope.get("paths")
    if paths:
        return any(fnmatch.fnmatch(path, p) for p in paths)
    return True


class Clock:
    def now(self) -> float: raise NotImplementedError


class VirtualClock(Clock):
    def __init__(self): self.t = 0.0
    def now(self) -> float: return self.t


class WallClock(Clock):  # prod seam
    def now(self) -> float:
        import time
        return time.time()


class Scheduler:
    """Min-heap of timed callbacks with lazy cancellation.
    Prod: replace with asyncio call_later handles or a job queue."""
    def __init__(self, clock: VirtualClock):
        self.clock = clock
        self._heap: list = []
        self._seq = itertools.count()
        self._cancelled: set[int] = set()

    def at(self, when: float, cb: Callable[[], None]) -> int:
        sid = next(self._seq)
        heapq.heappush(self._heap, (when, sid, cb))
        return sid

    def after(self, delay: float, cb: Callable[[], None]) -> int:
        return self.at(self.clock.now() + delay, cb)

    def cancel(self, sid: Optional[int]) -> None:
        if sid is not None:
            self._cancelled.add(sid)

    def run_until(self, horizon: float) -> None:
        while self._heap and self._heap[0][0] <= horizon:
            when, sid, cb = heapq.heappop(self._heap)
            if sid in self._cancelled:
                self._cancelled.discard(sid); continue
            self.clock.t = max(self.clock.t, when)
            cb()
        self.clock.t = max(self.clock.t, horizon)


class Vault:  # prod seam: real KMS/secret store
    def get(self, ref: str) -> str:
        return f"<secret for {ref}>"


# ─────────────────────── simulated target (demo only) ───────────────────────

class SimulatedServer:
    """A 'stupid site' that drops a session after idle_limit seconds without
    activity, and hard-expires it after abs_limit. The manager does NOT know
    idle_limit up front — that's what calibration discovers."""
    def __init__(self, clock: Clock, idle_limit: float, abs_limit: float):
        self.clock = clock
        self.idle_limit = idle_limit
        self.abs_limit = abs_limit
        self._born: dict[str, float] = {}
        self._seen: dict[str, float] = {}
        self._n = itertools.count()

    def create(self) -> str:
        sid = f"srv-{next(self._n)}"
        now = self.clock.now()
        self._born[sid] = now; self._seen[sid] = now
        return sid

    def request(self, sid: str) -> bool:
        """True if the session was still alive and is now refreshed."""
        now = self.clock.now()
        if sid not in self._seen:
            return False
        if now - self._seen[sid] > self.idle_limit:      # died of idle
            del self._seen[sid]; return False
        if now - self._born[sid] > self.abs_limit:       # hard expiry
            del self._seen[sid]; return False
        self._seen[sid] = now                            # activity slides idle
        return True


class Authenticator:
    """Stub. Prod: dispatch by credential['type'] — login for session-cookie,
    token exchange for oauth2, signer for hmac, etc. Here everything routes
    through the simulated server."""
    def __init__(self, server: SimulatedServer, vault: Vault):
        self.server, self.vault = server, vault

    def mint(self, cred: dict) -> str:
        _ = self.vault.get(cred["secret_ref"])
        return self.server.create()

    def contact(self, server_sid: str) -> bool:   # keepalive ping or real request
        return self.server.request(server_sid)

    def refresh(self, server_sid: str) -> Optional[str]:
        # token refresh keeps same server session alive in this stub
        return server_sid if self.server.request(server_sid) else None


# ─────────────────────────────── calibration ───────────────────────────────

class IdleCalibrator:
    """Learns a *safe* idle_timeout. A death observed at probe time means the
    true timeout is somewhere in (last_activity, probe]; probe-last_activity is
    an upper bound. We tighten below it and converge from above until deaths
    stop. (Prod refinement: also use successful-idle intervals as lower bounds
    and bisect; here we keep the conservative one-sided rule.)"""
    def __init__(self, initial: float, source: str):
        self.est = initial
        self.source = source
        self.history: list[float] = []

    def observe_death(self, idle_at_death: float) -> None:
        self.history.append(idle_at_death)
        self.est = min(self.est, idle_at_death * 0.9)
        self.source = "observed"


# ───────────────────────────────── session ─────────────────────────────────

@dataclass
class Session:
    id: str
    from_credential: str
    owner: Optional[str]
    server_sid: str
    acquired_at: float
    expires_at: Optional[float]           # absolute ceiling
    last_activity: float
    state: str = "live"                    # live|dead
    bound_egress: Optional[str] = None
    _ka: Optional[int] = None              # scheduled keepalive handle
    _rf: Optional[int] = None              # scheduled refresh handle


# ───────────────────────────── session manager ─────────────────────────────

class SessionManager:
    def __init__(self, clock: Clock, sched: Scheduler, auth: Authenticator,
                 log: Callable[[str], None]):
        self.clock, self.sched, self.auth, self.log = clock, sched, auth, log
        self._sid = itertools.count()
        self.sessions: dict[str, Session] = {}
        self.calib: dict[str, IdleCalibrator] = {}     # per credential id
        self.churn = 0                                  # unexpected re-mints

    # ---- policy access ----
    @staticmethod
    def _policy(cred: dict) -> dict:
        return cred.get("renewal", {}) or {}

    def _idle_est(self, cred: dict) -> float:
        pol = self._policy(cred)
        cid = cred["id"]
        if cid not in self.calib:
            if "idle_timeout" in pol:
                self.calib[cid] = IdleCalibrator(parse_duration(pol["idle_timeout"]),
                                                 pol.get("idle_timeout_source", "declared"))
            else:
                self.calib[cid] = IdleCalibrator(1800.0, "default")   # blind guess
        return self.calib[cid].est

    def _margin(self, cred: dict) -> float:
        ka = self._policy(cred).get("keepalive", {})
        return parse_duration(ka.get("margin", "60s"))

    def _methods(self, cred: dict) -> list[str]:
        return self._policy(cred).get("methods", ["none"])

    # ---- lifecycle ----
    def mint(self, cred: dict, owner: Optional[str], reason: str) -> Session:
        now = self.clock.now()
        srv = self.auth.mint(cred)
        pol = self._policy(cred)
        abs_ttl = parse_duration(pol["absolute_ttl"]) if "absolute_ttl" in pol else None
        s = Session(id=f"sess:{next(self._sid)}", from_credential=cred["id"], owner=owner,
                    server_sid=srv, acquired_at=now,
                    expires_at=(now + abs_ttl) if abs_ttl else None,
                    last_activity=now,
                    bound_egress=(cred.get("_egress")))
        self.sessions[s.id] = s
        self.log(f"{fmt(now)}  MINT    {s.id} from {cred['id']} ({reason})")
        self._schedule(cred, s)
        return s

    def _cred_of(self, s: Session, creds: dict) -> dict:
        return creds[s.from_credential]

    def _schedule(self, cred: dict, s: Session) -> None:
        self.sched.cancel(s._ka); self.sched.cancel(s._rf)
        s._ka = s._rf = None
        if s.state != "live":
            return
        methods = self._methods(cred)
        now = self.clock.now()

        if "keepalive" in methods:
            idle = self._idle_est(cred)
            due = s.last_activity + idle - self._margin(cred)
            s._ka = self.sched.at(max(due, now), lambda: self._on_keepalive(cred, s))

        if s.expires_at and ({"refresh", "reauth"} & set(methods)):
            grace = parse_duration(self._policy(cred).get("refresh", {}).get("grace", "60s"))
            s._rf = self.sched.at(max(s.expires_at - grace, now),
                                  lambda: self._on_refresh(cred, s))

    def _on_keepalive(self, cred: dict, s: Session) -> None:
        if s.state != "live":
            return
        now = self.clock.now()
        if self.auth.contact(s.server_sid):
            s.last_activity = now
            self.log(f"{fmt(now)}  KA ok   {s.id}  (next in "
                     f"{int(self._idle_est(cred)-self._margin(cred))}s)")
            self._schedule(cred, s)
        else:
            idle_at_death = now - s.last_activity
            self.calib.setdefault(cred["id"], IdleCalibrator(1800.0, "default"))
            self.calib[cred["id"]].observe_death(idle_at_death)
            self.log(f"{fmt(now)}  KA DEAD {s.id}  idle<= {int(idle_at_death)}s  "
                     f"-> idle_est now {int(self.calib[cred['id']].est)}s (observed)")
            self._kill(s)
            self.churn += 1
            self.mint(cred, s.owner, "re-mint after idle death")

    def _on_refresh(self, cred: dict, s: Session) -> None:
        if s.state != "live":
            return
        now = self.clock.now()
        new_srv = self.auth.refresh(s.server_sid)
        if new_srv:
            s.server_sid = new_srv
            abs_ttl = parse_duration(self._policy(cred)["absolute_ttl"])
            s.expires_at = now + abs_ttl
            s.last_activity = now
            self.log(f"{fmt(now)}  REFRESH {s.id}  absolute extended to {fmt(s.expires_at)}")
            self._schedule(cred, s)
        else:
            self.log(f"{fmt(now)}  REFRESH failed {s.id} -> reauth")
            self._kill(s); self.churn += 1
            self.mint(cred, s.owner, "reauth after refresh failure")

    def _kill(self, s: Session) -> None:
        s.state = "dead"
        self.sched.cancel(s._ka); self.sched.cancel(s._rf)

    # ---- task-facing ----
    def live_session(self, cred: dict, owner: Optional[str]) -> Session:
        for s in self.sessions.values():
            if s.from_credential == cred["id"] and s.owner == owner and s.state == "live":
                return s
        return self.mint(cred, owner, "first use")

    def use(self, cred: dict, owner: Optional[str], label: str,
            target_host: str, target_path: str = "/") -> Optional[Session]:
        """A real task request. Gated by scope so a credential is never injected
        toward a host/path it isn't scoped for (in Burp, Repeater/Scanner can
        easily steer a request off-host — this stops a live token leaking there).
        Counts as activity; re-mints if the session silently died."""
        if not scope_allows(cred.get("scope", {}), target_host, target_path):
            now = self.clock.now()
            self.log(f"{fmt(now)}  SCOPE DENY {label}: {cred['id']} not scoped for "
                     f"{target_host}{target_path} — refusing to inject")
            return None
        s = self.live_session(cred, owner)
        now = self.clock.now()
        if self.auth.contact(s.server_sid):
            s.last_activity = now
            self.log(f"{fmt(now)}  TASK ok {label} on {s.id}")
            self._schedule(cred, s)
            return s
        self.log(f"{fmt(now)}  TASK DEAD session for {label} -> relogin (churn)")
        self._kill(s); self.churn += 1
        s2 = self.mint(cred, owner, "re-mint for task")
        self.auth.contact(s2.server_sid); s2.last_activity = now
        return s2


# ───────────────────────────── leases (shared pool) ─────────────────────────

@dataclass
class Lease:
    agent: str
    identity: str
    expires_at: float


class LeasePool:
    """Pool binding: sticky affinity by agent + max_concurrent back-pressure.
    NOT thread/async-safe: guard checkout/checkin with a lock under concurrent
    MCP calls, or max_concurrent leaks."""
    def __init__(self, clock: Clock, binding: dict):
        self.clock = clock
        self.identities: list[str] = binding["identities"]
        self.strategy = binding["strategy"]
        self.affinity_key = binding.get("affinity_key")
        self.ttl = parse_duration(binding.get("lease_ttl", "30m"))
        self.max_per = binding.get("max_concurrent_per_identity", 1)
        self._active: dict[str, list[Lease]] = {i: [] for i in self.identities}
        self._sticky: dict[str, str] = {}
        self._rr = 0

    def _free(self) -> None:
        now = self.clock.now()
        for i in self._active:
            self._active[i] = [l for l in self._active[i] if l.expires_at > now]

    def checkout(self, agent: str) -> Optional[Lease]:
        self._free()
        # idempotent: an agent already holding a live lease gets it back (TTL
        # renewed) instead of consuming a second slot.
        for i in self.identities:
            for l in self._active[i]:
                if l.agent == agent:
                    l.expires_at = self.clock.now() + self.ttl
                    return l
        if self.strategy == "sticky" and agent in self._sticky:
            cand = [self._sticky[agent]]
        elif self.strategy == "round_robin":
            k = self._rr % len(self.identities)
            cand = self.identities[k:] + self.identities[:k]
            self._rr += 1
        else:  # sticky(new agent)/lru/weighted/random -> least-loaded
            cand = sorted(self.identities, key=lambda i: len(self._active[i]))
        for i in cand:
            if len(self._active[i]) < self.max_per:
                lease = Lease(agent, i, self.clock.now() + self.ttl)
                self._active[i].append(lease)
                if self.strategy == "sticky":
                    self._sticky[agent] = i
                return lease
        return None   # fully leased -> back-pressure

    def checkin(self, lease: Lease) -> None:
        self._active[lease.identity] = [l for l in self._active[lease.identity] if l is not lease]


class EgressLock:
    """Burp-wide exclusive lock for execution='burp-native' operations.

    Because Montoya's upstream proxy is global, a burp-native op must (1) hold
    this lock, (2) flip the GLOBAL upstream to its identity's egress, (3) run,
    (4) release. Only one identity/egress is active at a time; others queue FIFO.
    execution='parallel' ops never touch this lock — they run through the
    manager's own client with their own egress, concurrently.

    Composes with LeasePool: a burp-native pool still leases an identity, but the
    lease is then gated by this global lock, collapsing concurrency to one. NOT
    thread/async-safe as written — guard with a real mutex in production."""
    def __init__(self, set_global_upstream: Callable[[str], None]):
        self._set_global = set_global_upstream
        self._owner: Optional[str] = None
        self._global_egress: Optional[str] = None
        self._waiters: list = []     # FIFO of (identity, egress, on_grant)

    def acquire(self, identity: str, egress: str, on_grant: Callable[[], None]) -> bool:
        if self._owner is None:
            self._grant(identity, egress, on_grant)
            return True
        self._waiters.append((identity, egress, on_grant))
        return False

    def _grant(self, identity: str, egress: str, on_grant: Callable[[], None]) -> None:
        self._owner = identity
        if egress != self._global_egress:        # flip Burp's global upstream only on change
            self._global_egress = egress
            self._set_global(egress)
        on_grant()

    def release(self) -> None:
        self._owner = None
        if self._waiters:
            identity, egress, cb = self._waiters.pop(0)
            self._grant(identity, egress, cb)


# ──────────────────────────────────── demo ─────────────────────────────────

def run_keepalive_demo():
    IDLE, ABS = parse_duration("15m"), parse_duration("60m")   # server truth
    TASKS = [1800, 3600]                                        # every 30 min

    def scenario(name, policy, horizon):
        print(f"\n===== {name} =====")
        clock = VirtualClock(); sched = Scheduler(clock)
        server = SimulatedServer(clock, idle_limit=IDLE, abs_limit=ABS)
        mgr = SessionManager(clock, sched, Authenticator(server, Vault()), print)
        cred = {"id": "cred:web1", "type": "session-cookie",
                "secret_ref": "vault://kv/web1", "_egress": "203.0.113.9",
                "scope": {"hosts": ["*.slow.example"]}, "renewal": policy}
        mgr.mint(cred, owner="agent-001", reason="startup")
        for t in TASKS:
            sched.at(t, lambda: mgr.use(cred, "agent-001", f"check@{fmt(clock.now())}",
                                        target_host="app.slow.example", target_path="/status"))
        sched.run_until(horizon)
        print(f"  --> relogins due to churn: {mgr.churn}")
        return mgr.churn

    a = scenario("A  no keepalive (idle death every cycle)",
                 {"methods": ["reauth"], "idle_timeout": "15m"}, 3700)
    b = scenario("B  keepalive + refresh (idle known = 15m)",
                 {"methods": ["keepalive", "refresh"], "idle_timeout": "15m",
                  "idle_timeout_source": "declared", "absolute_ttl": "60m",
                  "keepalive": {"request": {"method": "GET", "path": "/ping"}, "margin": "3m"},
                  "refresh": {"endpoint": "https://idp/token", "grace": "60s"}}, 3700)

    print("\n===== C  self-calibration (idle UNKNOWN, true = 15m) =====")
    clock = VirtualClock(); sched = Scheduler(clock)
    server = SimulatedServer(clock, idle_limit=IDLE, abs_limit=ABS)
    mgr = SessionManager(clock, sched, Authenticator(server, Vault()), print)
    cred = {"id": "cred:web2", "type": "session-cookie", "secret_ref": "vault://kv/web2",
            "renewal": {"methods": ["keepalive"],
                        "keepalive": {"request": {"method": "GET", "path": "/ping"}, "margin": "3m"}}}
    mgr.mint(cred, owner="agent-002", reason="startup (no idle_timeout -> guess 1800s)")
    sched.run_until(6000)
    print(f"  --> deaths while learning: {mgr.churn}; "
          f"final idle_est = {int(mgr.calib['cred:web2'].est)}s "
          f"(source={mgr.calib['cred:web2'].source}); deaths stop once est is safe")
    return a, b


def run_scope_demo():
    print("\n===== E  scope gate (host suffix-match, dot boundary) =====")
    clock = VirtualClock(); sched = Scheduler(clock)
    server = SimulatedServer(clock, idle_limit=900, abs_limit=3600)
    mgr = SessionManager(clock, sched, Authenticator(server, Vault()), print)
    cred = {"id": "cred:web1", "type": "session-cookie", "secret_ref": "vault://kv/web1",
            "scope": {"hosts": ["*.slow.example"]}, "renewal": {"methods": ["none"]}}
    for host in ["app.slow.example", "slow.example", "notslow.example", "evil.com"]:
        ok = scope_allows(cred["scope"], host)
        print(f"  {host:20s} -> {'ALLOW' if ok else 'deny '}")
    print("  (bare apex and look-alike correctly denied; only real subdomains pass)")
    mgr.use(cred, "agent-001", "offhost-attempt", target_host="evil.com")


def run_execution_demo():
    print("\n===== F  hybrid execution: parallel vs burp-native (global egress lock) =====")
    lock = EgressLock(set_global_upstream=lambda e: print(f"      [Burp] global upstream -> {e}"))

    def op(name, identity, egress, execution):
        if execution == "burp-native":
            got = lock.acquire(identity, egress,
                               lambda: print(f"  {name:10s} RUN   burp-native on {identity} via {egress}"))
            if not got:
                print(f"  {name:10s} QUEUE burp-native (egress lock held by other identity)")
        else:
            print(f"  {name:10s} RUN   parallel    on {identity} via {egress}  (no lock)")

    op("scan-A", "id:p1", "egress:A", "burp-native")    # takes the lock, flips upstream
    op("fuzz-par", "id:p3", "egress:C", "parallel")     # unaffected, runs now
    op("scan-B", "id:p2", "egress:B", "burp-native")    # blocked -> queued
    print("  scan-A done -> release")
    lock.release()                                      # scan-B granted, upstream flips


def run_lease_demo():
    print("\n===== D  shared pool: sticky affinity + max_concurrent back-pressure =====")
    clock = VirtualClock()
    binding = {"kind": "binding", "mode": "shared", "pool": "pool-A",
               "identities": ["id:p1", "id:p2"], "strategy": "sticky",
               "affinity_key": "agent_id", "lease_ttl": "30m",
               "max_concurrent_per_identity": 1}
    pool = LeasePool(clock, binding)
    la = pool.checkout("agentA"); print(f"  agentA -> {la.identity}")
    lb = pool.checkout("agentB"); print(f"  agentB -> {lb.identity}")
    la2 = pool.checkout("agentA"); print(f"  agentA again -> {la2.identity}  (sticky: same as before = {la2.identity == la.identity})")
    lc = pool.checkout("agentC"); print(f"  agentC -> {lc}  (both identities at max_concurrent=1 -> back-pressure)")
    pool.checkin(lb); print("  agentB checks in id:p2")
    lc = pool.checkout("agentC"); print(f"  agentC retry -> {lc.identity if lc else None}  (slot freed)")


if __name__ == "__main__":
    a, b = run_keepalive_demo()
    run_scope_demo()
    run_execution_demo()
    run_lease_demo()
    print(f"\nSUMMARY: no-keepalive caused {a} relogins; keepalive caused {b}. "
          f"Same workload, same egress — keepalive removes the churn.")
