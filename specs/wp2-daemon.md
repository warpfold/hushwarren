# WP2 — `hush-daemon`: DNS engine, upstream ladder, list pipeline

Implements: `docs/architecture.md` §3 (component map), §5 (DNS engine), §6 (list
pipeline, runtime side). Binding standards: `specs/standards.md`. Builds on WP1's
`hush-core` — if core's API is missing something, flag it in the run summary and
add the minimal extension to core (with tests) rather than duplicating logic.

**P0 scope:** the resolver works and blocks when system DNS is pointed at it
manually. NOT in scope: Sentinel takeover/restore, captive portal, VPN, platform
DNS writing (P1); control API + CLI (WP3); sqlite query-log rollup (P1 — ring
buffer only). The `sentinel` module exists as a typed skeleton (state enum +
snooze wiring) so WP3/P1 have a stable seam.

Dependencies: `tokio` (rt-multi-thread, macros, signal, net, time, sync),
`hickory-server`, `hickory-resolver` (DoH via rustls feature — check the resolved
version's feature names on docs.rs; avoid webpki-roots per standards §4, prefer
native roots), `reqwest` (default-features = false, rustls + native roots, gzip),
`arc-swap`, `serde`, `toml`, `thiserror`, `tracing`, `tracing-subscriber`
(EnvFilter), `clap` (derive, for the small arg surface), `hush-core`.
Dev-deps: `tempfile`, `hickory-client` or use `hickory-resolver` as test client.

---

## 1. Process layout (`main.rs` + `app.rs`)

```
hushd run [--config <path>] [--state-dir <path>]   # default subcommand
hushd self-test [--config <path>]                  # resolve canaries through own engine, exit 0/1
hushd print-config                                 # effective config incl. defaults, TOML to stdout
```

- Config resolution: `--config` > `<state-dir>/hushwarren.toml` > built-in default.
  State dir: `--state-dir` > `HUSH_STATE_DIR` env > platform default
  (`/Library/Application Support/hushwarren`, `/var/lib/hushwarren`,
  `%PROGRAMDATA%\hushwarren`) > `./.hushwarren-state` (dev fallback, warn).
  Create it (and subdirs `lists/`, `compiled/`) on boot.
- `app::App` owns: `DecisionEngine` (core), `QueryRing` (cap 10_000), upstream
  resolvers, compiled-rules state, task handles. Constructed by
  `App::start(config) -> Result<RunningApp>` where `RunningApp` exposes
  **actual bound addresses** (`udp_addrs()`, etc. — tests bind port 0) and
  `shutdown()` (graceful: stop accepting, drain in-flight with 5s deadline).
  Integration tests use `App::start` in-process; `main` is a thin wrapper —
  keep `main.rs` under ~80 lines.
- Shutdown on SIGTERM/SIGINT (unix) / ctrl_c (all platforms).
- Panic belt: `std::panic::set_hook` logging at error + process exit nonzero —
  the service manager restarts us; a silently-wedged daemon violates P1
  (zero-touch-ux.md §2 layer 1 assumes crashes are LOUD).

## 2. Module `dns` — listener + request handler

- `hickory-server` `ServerFuture` with UDP + TCP listeners on every configured
  addr. Implement `RequestHandler`:

```
qname --Domain::parse--> fail? => respond per §2.3
  -> engine.decide(domain, now)
  Block        => §2.2 sinkhole answer
  Forward      => upstream ladder (§3)
  ForwardLocal => local resolver (config.do53_fallback; empty => treat as Forward, count it)
push QueryRecord (always, including errors; upstream_ms only on forwards)
```

### 2.2 Sinkhole responses (block action)
- `null_ip` (default): A ⇒ `0.0.0.0`, AAAA ⇒ `::`, both TTL `config.block.ttl_secs`,
  NOERROR, RA flag set, AA clear. **Any other qtype (TXT, MX, SVCB/HTTPS=64/65,
  SRV, …) ⇒ NODATA** (NOERROR, empty answer section). HTTPS-qtype NODATA matters:
  answering only A while browsers race HTTPS(65) re-leaks via some resolvers'
  fallback behavior — return NODATA so the browser settles on the sinkholed A.
- `nxdomain`: NXDOMAIN for all qtypes.
- PTR/ANY for blocked names: NODATA (don't fabricate reverse records).

### 2.3 Protocol hygiene (the "infallible boundary", standards §2)
- Unparseable/garbage packet: hickory surfaces this — respond FORMERR where a
  response is possible, else drop; count `malformed_total`; never crash (test).
- qname that fails `Domain::parse` (e.g. non-ASCII garbage): forward it upstream
  UNTOUCHED (Forward verdict, reason NoMatch) — we filter ads, we are not a
  validator; breaking weird-but-real names violates P1. Count it.
- Always copy the request ID/flags correctly (hickory's ResponseBuilder does);
  set RD/RA sensibly (we are a recursive forwarder: RA = true).
- EDNS: accept; advertise 1232-byte UDP payload; truncate + TC bit ⇒ client
  retries TCP (hickory handles; verify with the >512B test below).

## 3. Module `upstream` — the ladder

Two-tier P0 ladder (architecture §5's "health-checked hysteresis" lands with the
Sentinel; P0 = working failover, structured for that future):

```rust
pub struct UpstreamLadder {
    doh: Vec<DohResolver>,        // one TokioAsyncResolver per DoH endpoint,
                                  // constructed with NameServerConfig{ip=bootstrap, tls_dns_name=host}
    do53_fallback: Option<TokioAsyncResolver>,
    rung: AtomicUsize,            // current preferred rung
}
impl UpstreamLadder {
    /// Try current rung; on error/timeout (2s per rung) advance and retry once
    /// on the next; after last rung -> ServFail to client. A success on a lower
    /// rung schedules a probe of rung 0 after 30s (simple recovery, no flapping:
    /// only move UP on successful probe, not per-query).
    pub async fn resolve(&self, name, rtype) -> Result<Lookup, UpstreamError>;
}
```

- **Loop hazard (architecture §5) is a hard requirement:** the resolvers are
  configured ONLY from `bootstrap_ips` — assert in construction that no system
  resolver / `/etc/resolv.conf` path is consulted (hickory: build
  `ResolverConfig` from explicit `NameServerConfig`s, never `from_system_conf`).
- Caching: enable hickory-resolver's cache on each resolver (positive+negative).
  TTL clamping: min 5s, max 86400s.
- Map upstream outcomes to client responses: NXDOMAIN/NODATA pass through
  faithfully; timeout/transport-error after ladder exhaustion ⇒ SERVFAIL.
- CNAME chains: hickory resolves through them; ensure the FINAL answer set is
  what we return, and (P0 simplification, document it) blocklist evaluation
  applies to the ORIGINAL qname only — CNAME-cloaking defense is a P1 item
  (evaluating every CNAME target against the rules) — leave a `// P1:` marker.

## 4. Module `lists` — fetch → compile → swap

Boot sequence (order matters — architecture §6):
1. Try `CompiledRules::load(state/compiled)` ⇒ swap in, log counts.
2. Corrupt/missing ⇒ try compiling from cached raw sources in `state/lists/`.
3. Nothing cached ⇒ `CompiledRules::empty()` (resolver works, blocks nothing) +
   immediate fetch. **Never block listener startup on a fetch.**

Refresh task (tokio): every `refresh_hours` ± uniform jitter `jitter_minutes`;
also one immediate fetch 10s after boot if lists are empty/stale > 2×interval.
Per source: GET with `If-None-Match`/`If-Modified-Since` from stored validators;
304 ⇒ keep cached; 200 ⇒ atomic-replace raw file. ANY source failing ⇒ use its
cached copy; ALL failing ⇒ keep current compile, `warn`, exponential backoff
(30s→1h cap) for retry. After any raw change: parse all sources (core),
build, `save()` artifact, `engine.swap_rules()`. Compile on
`tokio::task::spawn_blocking` (fst build of 1M domains is CPU work).
Reject any source response > 256 MB (poisoned-source guard, count + warn).

`lists::Status { per_source: Vec<SourceStatus>, compiled_meta, last_swap } `
exposed for WP3's API.

## 5. Module `sentinel` — P0 skeleton only

```rust
pub enum GuardState { Filtering, Snoozed { until_unix_ms: u64 }, StandingBy { why: StandbyReason }, Attention { why: String } }
pub struct Sentinel { state: watch::Sender<GuardState>, engine: Arc<DecisionEngine> }
impl Sentinel {
    pub fn snooze(&self, duration: Duration);   // sets engine snooze + state
    pub fn resume(&self);
    pub fn state(&self) -> watch::Receiver<GuardState>;
}
```
No takeover/portal/VPN logic yet — but ALL state transitions go through here so
P1 slots in without rewiring WP3's API.

## 6. Observability

- `tracing_subscriber` EnvFilter (`HUSH_LOG`, default `info`).
- Counters (AtomicU64 in a `Metrics` struct, exposed for WP3): queries_total,
  blocked_total, forwarded_total, local_total, servfail_total, malformed_total,
  upstream_rung_current, cache-ish stats if hickory exposes them cheaply (else skip).
- Per-query `debug!` with qname/verdict/reason/ms.

## 7. Mandatory tests

**Unit:** sinkhole response construction per qtype/action (A, AAAA, TXT, HTTPS65,
PTR × null_ip/nxdomain); TTL from config; ladder rung advance/recovery logic
(mock the resolver trait — extract `trait Resolve` for testability); state-dir
resolution precedence; config file > env > default; jitter bounds.

**Integration (`crates/daemon/tests/`)** — in-process `App::start` with port-0
config; an in-process **mock upstream**: a tiny hickory-server authority (or
hand-rolled UDP responder — simpler is fine) serving a fixed zone
(`good.test A 192.0.2.10`, `slow.test` = 3s delayed answer, plus a query
counter). Upstream config for tests: `do53` pointing at the mock (the DoH code
path is identical above the transport; real-DoH coverage is the live test).
Helper: `wait_ready` = retry status query against the bound port with 5s
deadline — no sleeps (standards §5).

Cases:
1. blocked A ⇒ 0.0.0.0, TTL = configured, NOERROR
2. blocked AAAA ⇒ `::`; blocked HTTPS(65) ⇒ NODATA; nxdomain action ⇒ NXDOMAIN
3. allowed name ⇒ real answer from mock (192.0.2.10)
4. allow-over-block via user allow at runtime (engine.set_user_allow, no restart)
5. snooze ⇒ blocked name resolves; resume ⇒ blocked again (via Sentinel)
6. cache: same query twice ⇒ mock's query counter increments once
7. ladder: primary mock down (closed port) ⇒ answer still arrives via fallback
   rung; servfail when ALL rungs down
8. list reload: write new raw list file, trigger refresh ⇒ newly-listed domain
   blocks without restart (swap observed via decide, poll w/ deadline)
9. garbage UDP datagram (raw socket send of random bytes) ⇒ daemon survives,
   subsequent queries fine
10. 500-query concurrent burst (mix blocked/allowed) ⇒ all answered < 5s total,
    counters add up
11. TCP transport: blocked + forwarded query over TCP work
12. shutdown: `RunningApp::shutdown()` returns < 5s with in-flight queries,
    socket released (rebind same port succeeds)
13. boot with corrupt `compiled/block.fst` ⇒ daemon starts, recompiles from
    cached raw, blocks correctly
14. boot with empty state dir + unreachable list sources ⇒ daemon starts,
    resolves (blocks nothing), no crash-loop

**E2E:** one smoke in `crates/daemon/tests/e2e_binary.rs`: spawn the real
`hushd` binary (`CARGO_BIN_EXE_hushd`) with temp state + port-0… port-0
discovery via stdout line `LISTENING udp=<addr>` printed at info — make `run`
emit it exactly once for this purpose; then one blocked + one forwarded query
against it; SIGTERM; assert clean exit code.

**Live (`#[ignore]`):** `live_doh_cloudflare`: real config, resolve
`cloudflare.com` A through the DoH rung; assert non-empty + log latency.

## 8. Deliverable shape

Module files under `crates/daemon/src/`: `main.rs` (thin), `app.rs`, `dns.rs`,
`upstream.rs`, `lists.rs`, `sentinel.rs`, `metrics.rs`, `state_dir.rs`,
`platform/mod.rs` (empty placeholder for P1). Gate green per standards §1; run
summary per standards §7 with the 14 integration cases checklisted.
