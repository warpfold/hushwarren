# hushwarren — System Architecture

Status: **draft v0.2** (P0 engine shipped; Sentinel next)
License: GPL-3.0-or-later for our code; all deps permissive, enforced by `cargo deny`.

---

## 1. Vision & principles

hushwarren is a DNS sinkhole that blocks ads/trackers for the device (default) or the
whole network (opt-in), with a hard product rule:

> **P0 — Zero-touch.** After installation the user never configures anything.
> Every design decision is evaluated against this first.

Supporting principles:

- **P1 — Never break the internet.** A DNS interceptor that fails closed takes the
  user offline. Every takeover is transactional with verified rollback; every failure
  mode degrades to "ads come back," never to "internet gone."
- **P2 — Single static binary per OS.** No runtimes, no Docker, no bash installers.
- **P3 — Local-first, private by default.** Query logs never leave the machine.
  No telemetry. The control API binds to localhost only.
- **P4 — Copyleft out, permissive in.** Our code is GPL-3.0-or-later (free use —
  commercial included — but distributed modifications must be published: improvements
  stay free). The *dependency* tree stays strictly permissive (MIT/Apache/BSD-class,
  allow-listed in `deny.toml`) so hushwarren's own license is the only copyleft in
  the build. (Blocklists are runtime-fetched *data*, not linked code — their
  licenses require attribution in the UI, not relicensing.)
- **P5 — The dashboard is a bonus, not a requirement.** A user who never opens the
  UI gets the full product.

## 2. Operating modes

### Local Guard (default — the zero-touch mode)
The resolver listens on `127.0.0.1:53` / `[::1]:53` and the installer points *this
machine's* DNS at it. Protection travels with the laptop to every Wi-Fi network. No
router, no static IP, no second device. This is the mode that makes Windows/macOS
laptop users — whom Pi-hole structurally ignores — the primary audience.

### Network Guard (opt-in, advanced)
Same daemon, additionally listening on the LAN interface, advertised to other devices
via the router's DHCP DNS setting (which the user configures — the one deliberate
exception to zero-touch, clearly labeled "advanced"). Future: optional DHCP server to
remove even that step. Network Guard is P3 in phasing; nothing in the core may assume
local-only.

## 3. Component map

```
┌────────────────────────────── user session ───────────────────────────────┐
│  hush-tray (menu bar / system tray)        hush (CLI, optional)        │
│   status · counter · snooze · open dashboard                               │
└───────────────┬────────────────────────────────────┬───────────────────────┘
                │ localhost HTTP + token              │
┌───────────────▼────────────────────────────────────▼───────────────────────┐
│  hushd (system service: launchd / systemd / Windows SCM)                  │
│                                                                             │
│   ┌─────────────┐   ┌──────────────┐   ┌─────────────────────────────┐      │
│   │ DNS engine  │──▶│ Decision     │──▶│ Upstream forwarder           │      │
│   │ hickory     │   │ engine       │   │ DoH (rustls) w/ bootstrap    │      │
│   │ udp/tcp :53 │   │ fst blocklist│   │ IPs + Do53 fallback + cache  │      │
│   └─────────────┘   └──────────────┘   └─────────────────────────────┘      │
│   ┌─────────────┐   ┌──────────────┐   ┌─────────────────────────────┐      │
│   │ List        │   │ Query log    │   │ Control API (axum,          │      │
│   │ pipeline    │   │ ring buf +   │   │ 127.0.0.1, token-auth)      │      │
│   │ fetch→fst   │   │ sqlite roll  │   │ serves dashboard SPA        │      │
│   └─────────────┘   └──────────────┘   └─────────────────────────────┘      │
│   ┌──────────────────────────────────────────────────────────────────┐      │
│   │ Sentinel: DNS configurator · network watcher · captive-portal    │      │
│   │ probe · VPN detector · health self-test · takeover transactions  │      │
│   └──────────────────────────────────────────────────────────────────┘      │
└──────────────────────────────────────────────────────────────────────────────┘
```

One daemon process, multiple tokio tasks. The **Sentinel** is what distinguishes
hushwarren from "hickory + a blocklist" — it owns the zero-touch guarantees and is
specified in [`zero-touch-ux.md`](zero-touch-ux.md).

## 4. Crate layout (cargo workspace)

| Crate | Kind | Responsibility | Key deps |
|---|---|---|---|
| `hush-core` | lib | Pure logic, no I/O policy: decision engine, blocklist compile/lookup (fst), list-format parsers (hosts, AdBlock domain syntax, plain domains), config model, query-log types | `fst`, `serde` |
| `hush-daemon` | bin (`hushd`) | DNS server (hickory), upstream DoH/Do53, Sentinel, control API, query log persistence, service entrypoints | `hickory-server`, `hickory-resolver`, `tokio`, `axum`, `rustls`, `rusqlite` |
| `hush-cli` | bin (`hush`) | status / snooze / allow / logs / takeover & restore (advanced); talks to control API | `clap`, `reqwest` (rustls) |
| `hush-tray` | bin | Menu-bar/tray UI: status dot, blocked counter, snooze, open dashboard. Runs in user session, auto-started | `tray-icon`, `muda` |
| `dist/` | — | Per-OS installer recipes: `.pkg` (macOS), `.msi` (WiX), `.deb`/`.rpm` + curl script (Linux) | — |

Dependency rule: `hush-core` is std-only + `fst`/`serde` — it must stay trivially
testable and portable. All OS-specific code lives behind the Sentinel's
`platform::` modules in `hush-daemon` (cfg-gated, one module per OS, one shared
trait).

```rust
/// Implemented per-OS; everything else is platform-agnostic.
trait PlatformDns {
    fn snapshot(&self) -> DnsSnapshot;                    // current per-interface DNS
    fn point_at_self(&self, snap: &DnsSnapshot) -> Result<()>;
    fn restore(&self, snap: &DnsSnapshot) -> Result<()>;
    fn watch_changes(&self) -> impl Stream<Item = NetEvent>; // iface up/down, VPN, sleep/wake
}
```

## 5. DNS engine

### Listener
`hickory-server` on UDP+TCP `127.0.0.1:53` and `[::1]:53` (Local Guard). IPv6 is
**mandatory**, not optional — if `::1` isn't set alongside `127.0.0.1`, dual-stack
OSes will prefer the router's IPv6 resolver and every query leaks around us.

### Decision engine (hush-core)
Per query, in order:

1. **Snooze / pause check** — global pass-through flag (atomic read).
2. **Allowlist** — exact + suffix; user overrides always win.
3. **Blocklist** — compiled `fst::Set` over **reversed-label keys**
   (`com.doubleclick` …); subdomain matching = exact `contains` per ancestor
   suffix (≤ ~10 lookups), which makes partial-label false matches impossible by
   construction. Millions of domains ≈ tens of MB resident, microsecond lookups,
   zero per-query allocation.
4. **Local names** — single-label and `.local`/`.lan`/RFC-6762-adjacent names are
   never blocked and forwarded to the *DHCP-provided* resolver (printers, NAS,
   router admin pages must keep working — a classic Pi-hole papercut).

Block action (configurable, default first): respond `0.0.0.0` + `::` with short TTL.
Default chosen over NXDOMAIN because some apps hard-retry on NXDOMAIN but accept an
unroutable address quietly. TTL 10s so un-blocking takes effect fast.

### Upstream forwarder
- **Default: DoH** (`hickory-resolver` + rustls) to a small rotation
  (Cloudflare, Quad9) — encrypted upstream out of the box, something Pi-hole needs a
  sidecar for.
- **Loop hazard (critical):** once system DNS = us, resolving `cloudflare-dns.com`
  via the system resolver would recurse into ourselves. DoH endpoints are configured
  with **bootstrap IPs** baked into config; the upstream path never consults the
  system resolver.
- **Fallback ladder:** DoH primary → DoH secondary → plain Do53 to the DHCP-provided
  resolver (captured in the takeover snapshot). Health-checked with hysteresis;
  ladder position surfaces in the tray as a subtle status, never as an error dialog.
- **Cache:** hickory's TTL-respecting cache in front of the ladder. Negative caching
  per RFC 2308.

### Performance envelope
A laptop's own DNS load is trivial (tens of qps burst). Design target is the
Network Guard ceiling: 5k qps sustained on a Pi-class arm64 box, p99 < 5ms for
cached/blocked answers. Rust + fst makes this boring to hit.

## 6. Blocklist pipeline

```
sources.toml ──▶ fetcher (etag-aware, jittered daily) ──▶ parsers ──▶ canonicalize
                                                                        │
            atomic swap (ArcSwap) ◀── fst::Set builder ◀── dedupe + allowlist subtraction
```

- **Default source set** (curated for zero false positives — this *is* the product;
  a list that breaks a bank's login violates P0): OISD small/big tier as default
  baseline (its stated philosophy is "blocks ads without breaking sites" — exactly
  our contract), evaluated against Hagezi tiers during P1. Attribution shown in
  dashboard; lists are fetched data, never bundled into the binary.
- Compile to fst off-thread; swap via `arc_swap::ArcSwap<CompiledRules>` — the hot
  path never takes a lock.
- Persist compiled artifact + raw sources to the state dir so a reboot with no
  network still blocks (cold-start from disk, refresh later).
- First run: installer ships a pre-fetched snapshot inside the package so blocking
  works **immediately**, even if first boot is offline.
- Failure mode: fetch fails → keep serving the previous compile, retry with backoff,
  surface "lists 3 days stale" in dashboard only. Never block startup on a fetch.

## 7. Query log & stats

- In-memory ring buffer (last ~10k queries) for the live dashboard view.
- SQLite (rusqlite, WAL) for rolling 7-day history, batched inserts, auto-vacuumed
  size cap (default 100 MB). Privacy default: log **domains**, not client IPs, in
  Local Guard (there's only one client); Network Guard adds per-client opt-in.
- Powers the killer UX feature: **"recently blocked"** list in the dashboard with
  one-click allow — the answer to "this site just broke."

## 8. Control plane

- axum HTTP server on `127.0.0.1:<port>` (fixed default, fallback-scan if taken),
  serving both the JSON API and the embedded dashboard SPA (static assets compiled
  into the binary via `include_dir` — single-binary rule).
- **Auth:** random token minted at install, written `0600` to a state file readable
  by the admin/user group; tray, CLI, and browser (via one-time URL the tray opens)
  present it. No listener on non-loopback interfaces, ever (Network Guard dashboards
  still require an SSH tunnel or explicit config — P3 problem).
- API surface (v0): `GET /status`, `GET /queries/recent`, `GET /stats/summary`,
  `POST /snooze {secs}`, `POST /allow {domain}`, `POST /unallow`, `GET /lists`,
  `POST /lists/refresh`, `POST /takeover`, `POST /restore` (the last two power
  install/uninstall and the CLI's advanced verbs).

## 9. Security posture

- DNS cache-poisoning hardening comes from hickory (source-port & TXID
  randomization); DoH upstream removes the off-path spoofing surface entirely.
- Daemon privilege: lowest viable per OS — see
  [`os-integration.md`](os-integration.md) (Linux: dedicated user +
  `CAP_NET_BIND_SERVICE`; macOS: root LaunchDaemon, drops to nobody after bind
  where feasible; Windows: LocalService with the SCM granting the bind).
- Control API: localhost + token, CSRF-safe (token header, not cookie), no CORS.
- Supply chain: `cargo deny` (licenses + advisories) and `cargo audit` in CI;
  lockfile committed; release binaries signed/notarized per OS (P2).

## 10. Phasing

| Phase | Deliverable | Exit criterion |
|---|---|---|
| **P0 — Engine** ✅ | `hushd` resolves + blocks on macOS & Linux dev boxes; fst pipeline; DoH upstream; CLI `status/snooze/allow`; manual DNS pointing | Dogfoodable daily driver for us — **met, live-proven** |
| **P1 — Sentinel** ✅ (macOS) | Transactional takeover/restore, network watcher, captive-portal + VPN handling, crash safety — full [`zero-touch-ux.md`](zero-touch-ux.md) spec on macOS + Linux | macOS: 12/12 live scenarios pass on a real machine. Linux platform implemented; live roaming proof pending a Linux box |
| **P2 — Ship** ✅ (code) | Windows port (WP11, **live-proven on Win11** + native Windows CI gate); tray app (WP10 — macOS functional; Windows tray code present but its event loop is not yet wired; Linux tray deferred, headless-first audience); dashboard SPA (WP9); installers .pkg built unsigned + .deb/.rpm/.msi CI recipes (WP12); uninstallers; pre-fetched Hagezi snapshot | Signing needs certs (env-hook ready); Windows/Linux package smoke-installs pending CI runners; Windows tray event loop unimplemented |
| **P3 — Network Guard** ✅ (code) | LAN listening, per-client stats, router guidance UI — WP13, opt-in, default off | Mechanism shipped + tested; multi-device LAN live proof pending |
| **P4 — Nice** | DoT/DoQ inbound (WP14 §1 — shipped), passive mDNS insight (WP14 §3 — shipped), multi-profile with hot-reload (WP14 §2 — shipped). **DHCP server DEFERRED**: a competing DHCP server on a LAN with an existing one can bring the network down — direct P1 ("never break the internet") violation with no safe default. Revisit only on concrete demand as its own spec. | DoT/DoQ/profiles/mDNS shipped; DHCP deferred |

## 11. Open questions (tracked, not blocking P0)

1. Tray stack: `tray-icon`+`muda` (lean, used by Tauri) vs full Tauri for tray AND
   dashboard shell. Lean first; revisit if dashboard-in-webview beats browser-tab UX.
2. Block-page option (serve a tiny "blocked by hushwarren" page on 80/443 for
   sinkholed HTTP)? Pi-hole dropped theirs; default no — silent `0.0.0.0` is calmer.
3. OISD vs Hagezi as the default list — needs a false-positive bake-off during P1
   dogfood (track allow-clicks as the metric).
4. Windows ARM64 (Surface) in P2 scope? Rust targets it fine; CI cost question.
5. Name collision check for `hushwarren` on crates.io/brew/winget before P2 ship
   (binary names `hushd`/`hush` likely fine; package id may need `hushwarren-dns`).
