# WP5 — Sentinel: takeover transaction, crash safety, macOS PlatformDns

Implements `docs/zero-touch-ux.md` §1–§6 (the Sentinel spec — READ IT FIRST, it is
the design; this file adds only implementation decisions) and the macOS column of
`docs/os-integration.md` §1–§2. Binding: `specs/standards.md`.

**P1 scope:** macOS only. `platform/linux.rs` / `windows.rs` stay empty stubs that
return `Unsupported`. The state machine + transaction are platform-agnostic and
fully tested against a mock platform; macOS code is thin.

## 1. `platform/` — the trait (daemon)

```rust
pub trait PlatformDns: Send + Sync + 'static {
    /// Current DNS per network service. Distinguishes Dhcp vs Static(Vec<IpAddr>).
    fn snapshot(&self) -> Result<DnsSnapshot, PlatformError>;
    fn point_at_self(&self, services: &[String]) -> Result<(), PlatformError>; // set 127.0.0.1 (+ ::1)
    fn restore(&self, snap: &DnsSnapshot) -> Result<(), PlatformError>;        // idempotent
    fn current_setting(&self, service: &str) -> Result<DnsSetting, PlatformError>; // drift poll
}
pub struct DnsSnapshot { pub taken_unix_ms: u64, pub services: Vec<ServiceDns> }
pub struct ServiceDns { pub service: String, pub setting: DnsSetting }
pub enum DnsSetting { Dhcp, Static(Vec<IpAddr>) }   // "pointing at us" == Static([127.0.0.1, ::1])
```

`DnsSnapshot` serde-JSON, persisted to `state_dir/dns-snapshot.json` (atomic +
fsync) BEFORE any COMMIT. Schema versioned (`"v":1`).

### macOS impl (`platform/macos.rs`)
Shell out to `/usr/sbin/networksetup` (std::process::Command; no new deps):
- enumerate: `-listallnetworkservices`, skip lines starting `*` (disabled) and the
  header line; query each with `-getdnsservers <svc>` — output "There aren't any
  DNS Servers set" ⇒ `Dhcp`, else parse IP lines ⇒ `Static`.
- set: `-setdnsservers <svc> 127.0.0.1 ::1`; restore Dhcp: `-setdnsservers <svc> Empty`.
- Treat per-service command failure as per-service error; restore() continues
  through ALL services and aggregates errors (never abort half-restored).
- Needs root for set-operations → fine: the LaunchDaemon runs as root (WP6).
  Non-root run of takeover ⇒ clean `PlatformError::NeedsRoot` mapped to a
  friendly CLI message.

## 2. Takeover transaction (`sentinel/takeover.rs`)

Exactly the 7 steps of zero-touch-ux §1, as a function over `&dyn PlatformDns` +
`&App` so it is fully testable with a mock:

- PREPARE: listeners must already be bound on 127.0.0.1:53/[::1]:53 (the daemon
  binds them at start when `listen` config says 53; in installed mode it does).
  Port conflict ⇒ abort with diagnosis (who owns it via `lsof -nP -i :53` output
  captured in the error, best-effort).
- SELF-TEST: through OUR OWN listener (raw hickory client to 127.0.0.1:53):
  `hushwarren-selftest-blocked.invalid` must sinkhole (it is a COMPILED-IN always-
  block rule — add to DecisionEngine as a builtin, reason ListBlocked), and a
  configurable allowed canary (`canary_domain`, default `example.com`) must return
  ≥1 A record via upstream.
- SNAPSHOT → persist → COMMIT (`point_at_self`) → VERIFY: resolve the allowed
  canary through the SYSTEM path (`std::net::ToSocketAddrs` on "<canary>:443" —
  uses the OS resolver, which now points at us) with 5s deadline.
- Any failure after COMMIT ⇒ `restore(snapshot)` then return the original error.
- `restore` path must stay dependency-light: `hushd restore` subcommand reads
  the snapshot JSON and calls PlatformDns::restore directly — no tokio runtime
  beyond a current-thread one, no App construction.

New subcommands: `hushd takeover` (runs against the RUNNING daemon's state dir;
refuses if no daemon healthy — checks api.addr + /v0/status), `hushd restore`
(works with NO daemon — the escape hatch). Mirror as API `POST /v0/takeover`,
`POST /v0/restore` and CLI verbs `hush takeover` / `hush restore`.

## 3. Crash safety (`sentinel/breaker.rs`) — zero-touch-ux §2

- Breadcrumb file `state_dir/run-state.json`: `{ "clean_shutdown": bool,
  "abnormal_restarts": [unix_ms…] }`. On boot: if previous run NOT clean AND
  system DNS currently points at us (snapshot exists): count it; 3 abnormal
  within 5 min ⇒ BREAKER: restore snapshot, set `GuardState::Attention`,
  KEEP RUNNING (resolver up, DNS not pointed at us) — do not exit (launchd
  would just restart us; idling disarmed is the design).
- Clean shutdown hook writes `clean_shutdown: true`; SIGTERM path included.
- `hushd run --pre-start-check` mode used by the launchd wrapper script
  (WP6): if breadcrumb dirty AND daemon won't be able to serve, restore first.
  Implement as: always run the check inline at daemon start (no separate
  process needed for P1) — document the deviation from §2's "service wrapper"
  wording.

## 4. Watcher loop (`sentinel/watch.rs`) — §3–§6 simplified for P1

One tokio task, tick every 5s (config `sentinel.poll_secs`, default 5):

1. **Wake detection**: monotonic-vs-wall clock gap > 30s since last tick ⇒ treat
   as wake ⇒ full re-verify cycle.
2. **Drift check** (only when state == Filtering): `current_setting` for each
   snapshot service; classify per zero-touch-ux §6:
   - all point at us ⇒ ok.
   - any reverted to Dhcp/empty ⇒ silent re-arm (`point_at_self` those services;
     count `drift_repairs`).
   - changed to a third-party static set AND a `utun*`/`ppp*` interface appeared
     since takeover (check `getifaddrs` via `std::process::Command("ifconfig",
    ["-l"])` diff) ⇒ VPN: `GuardState::StandingBy(Vpn)`, do NOT fight; when the
     iface disappears ⇒ re-run takeover.
   - changed to third-party static, no VPN iface ⇒ user-set: restore-respect →
     `StandingBy(UserDns)` + ONE notification (P1: log at warn + state change;
     real notifications are P2 tray work — document).
3. **Captive portal probe** (when Filtering AND a drift/wake/network event just
   happened, not every tick): GET `http://captive.apple.com/hotspot-detect.html`
   with the DHCP resolver from the snapshot (reqwest `resolve()` override using
   snapshot DHCP IPs; 3s timeout). Body != Apple's `<HTML><HEAD><TITLE>Success...`
   ⇒ portal: `StandingBy(Portal)` + engine pass-through-all (snooze mechanism with
   reason PortalMode — reuse snooze plumbing but distinct state); re-probe every
   5s; clean ⇒ SELF-TEST ⇒ re-arm. 15-min timebox ⇒ stay transparent, warn.
4. State transitions ALL go through `Sentinel` (watch::Sender<GuardState> from
   WP2) — API /v0/status reflects them (`standing_by` reasons in the JSON).

## 5. Tests (mandatory)

**Unit:** snapshot JSON round-trip + versioning; networksetup OUTPUT PARSERS
(feed captured real outputs as fixtures: dhcp case, static case, disabled-service
`*` case, "aren't any DNS Servers" case); transaction step ordering + rollback on
each failure point (mock PlatformDns recording calls); breaker window math (3-in-5min,
boundary); wake-gap detection; drift classification table (us/dhcp/static×vpn-iface).

**Integration (MockPlatform — in-memory `DnsSetting` map, injectable failures):**
matrix scenarios as logic tests — (a) takeover happy path: self-test→snapshot→
commit→verify ordering observed; (b) VERIFY fails ⇒ restored, error returned, mock
back to initial; (c) breaker fires on 3rd dirty boot ⇒ restore called, state
Attention; (d) drift-to-dhcp ⇒ re-arm call; (e) drift-to-static+vpn ⇒ StandingBy,
no set-calls; (f) vpn gone ⇒ takeover re-runs; (g) portal probe mismatch ⇒
pass-through state, probe-clean ⇒ re-armed (mock the HTTP probe via a local
hyper/axum server returning portal-ish then Success bodies).

**E2E (#[ignore], macOS, root-gated):** `live_macos_takeover_restore`: REAL
networksetup — snapshot, takeover on the active service, dig through system path,
restore, assert `networksetup -getdnsservers` output identical to snapshot. Skip
cleanly (eprintln + return) when not root. These run in the live proof session.

## 6. Out of scope (P1)

SCDynamicStore push notifications (polling suffices; leave `// P2:`), real macOS
user notifications (tray, P2), Linux/Windows impls, NRPT, IPv6 service-specific
`-setv6dnsservers` handling beyond what `-setdnsservers` covers (investigate and
document what macOS actually does with v6 when only v4 list set — put findings in
the run summary).

Gate per standards §1 + run summary per §7.
