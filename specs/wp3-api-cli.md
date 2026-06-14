# WP3 — Control API (`hush-daemon::api`) + `hush` CLI

Implements: `docs/architecture.md` §8 (control plane), the API-facing slice of
`docs/zero-touch-ux.md` §7 (snooze / allow). Binding: `specs/standards.md`.
Builds on WP1+WP2; extend (don't fork) `App`/`Sentinel`/`Metrics` seams.

**P0 scope:** JSON API + token auth + CLI. NOT in scope: dashboard SPA (P2 —
but the API shapes below are what it will consume, so they're contractual),
takeover/restore endpoints (P1), Network Guard anything.

New deps — daemon: `axum`, `serde_json`, `rand` (token), `subtle`
(constant-time compare), `tokio-util` (if needed for shutdown). CLI: `clap`
(derive), `reqwest` (default-features off, rustls, json), `serde`,
`serde_json`, `anyhow` (CLI binary MAY use anyhow; libraries may not),
`tokio` (rt, macros). Dev: `assert_cmd`, `predicates`, `tempfile`,
`tower` (for oneshot handler tests).

---

## 1. Token auth

- On boot, daemon ensures `state_dir/api.token`: 32 bytes from `rand::rngs::OsRng`,
  hex-encoded, written `0600` (unix; on Windows default ACLs are acceptable P0,
  leave `// P2: tighten ACL` marker), atomic write. Reused if present and
  well-formed; regenerated if malformed.
- Every request must carry `Authorization: Bearer <token>`; compare constant-time
  (`subtle::ConstantTimeEq`). Failure ⇒ 401 `{"error":"unauthorized"}`. No
  exemptions (status included — an unauthenticated localhost oracle leaks
  browsing history via stats).
- Bind STRICTLY to the configured loopback addr from `config.api.listen`;
  refuse (config validation error) any non-loopback IP in P0.
- Also write `state_dir/api.addr` containing the ACTUAL bound address (port 0
  support) — this file + token file are how CLI/tray discover the daemon.

## 2. API surface (all JSON; version prefix `/v0`)

| Method/Path | Req | Resp (200) |
|---|---|---|
| `GET /v0/status` | — | `{state: "filtering"\|"snoozed"\|"standing_by"\|"attention", snoozed_until_unix_ms: u64\|null, version, uptime_secs, rules: {block_count, allow_count, built_unix_ms, sources: [name]}, counters: {queries_total, blocked_total, forwarded_total, local_total, servfail_total}}` |
| `GET /v0/queries/recent?n=100&blocked_only=true` | — | `{queries: [QueryRecord-shaped]}` newest-first, n clamped to [1, 1000] |
| `GET /v0/stats/summary` | — | `{since_unix_ms, queries_total, blocked_total, block_rate: f32}` |
| `POST /v0/snooze` | `{secs: u64}` (1..=86400) | `{snoozed_until_unix_ms}` |
| `POST /v0/resume` | — | `{state}` |
| `POST /v0/allow` | `{domain: string}` | `{allowed: [string]}` (full list after) |
| `POST /v0/unallow` | `{domain: string}` | `{allowed: [string]}` |
| `GET /v0/allowlist` | — | `{allowed: [string]}` |
| `GET /v0/lists` | — | `lists::Status` from WP2 §4 |
| `POST /v0/lists/refresh` | — | 202 `{started: true}` (kicks the refresh task; non-blocking) |

Error contract: 400 invalid body/domain (`{"error", "detail"}`), 401 auth, 404
unknown path, 422 valid JSON failing domain parse (surface `DomainError` text).
Handlers never panic; axum fallback handler returns the 404 shape.

## 3. Allowlist persistence

- `POST /allow`: `Domain::parse` → add to `UserAllowSet` (dedup; reject if
  already-covered by an existing user-allow suffix with 200-and-no-op semantics)
  → `engine.set_user_allow` → persist `state_dir/allowlist.txt` (one domain per
  line, atomic tmp+rename) BEFORE responding. Boot (WP2 `App::start`): load the
  file if present; unparseable lines are skipped + warned, never fatal.
- `unallow` removes the exact entry only (not covered subdomains).

## 4. `hush` CLI

Discovery: `--state-dir` flag > `HUSH_STATE_DIR` > platform default —
read `api.addr` + `api.token`. Daemon unreachable ⇒ exit 2 with
`hushwarren isn't running (looked at <addr>). Is the service installed?`
(human messages on stderr; data on stdout).

```
hush status                # human summary: state dot word, rules count, blocked today
hush status --json         # raw /v0/status (every verb gets --json passthrough)
hush snooze [5m|30m|2h|off]   # duration parser: Nm/Nh/Ns; "off" -> /resume
hush allow <domain> / hush unallow <domain> / hush allowlist
hush log [-n 50] [--blocked]  # recent queries, aligned columns: time qname verdict reason ms
hush lists [--refresh]
```

Exit codes: 0 ok; 1 API-level error (4xx/5xx, message shown); 2 cannot connect.
Output discipline: stable, parseable lines; `--json` is the script contract.

## 5. Mandatory tests

**Unit (daemon::api):** token compare (right/wrong/empty/timing-shape — just
assert constant-time helper is used by construction); n-clamping; snooze secs
bounds; domain validation surface (422 path); allowlist add/remove/no-op
semantics; addr-file content.

**Integration (tower oneshot, no sockets):** every endpoint happy path + 401
(missing AND wrong token) + 400/422 cases; allow → engine actually flips a
decide() outcome (wire a real DecisionEngine into the test router); persistence
file contents after allow/unallow; snooze→status reflects snoozed state +
resume reverts.

**E2E (`crates/cli/tests/e2e_cli.rs`)** — spawn REAL `hushd` (temp state,
port-0 listen + api), then drive the REAL `hush` binary via `assert_cmd`:
1. `hush status` ⇒ exit 0, shows "filtering", rules count matches fixture list
2. full flow: query a blocked fixture domain (DNS client straight to the bound
   port) ⇒ 0.0.0.0 → `hush allow <it>` ⇒ exit 0 → same query ⇒ real answer
   from mock upstream → `hush unallow` ⇒ blocked again → restart daemon with
   same state dir ⇒ allowlist empty-of-it persisted correctly
3. `hush snooze 5m` ⇒ status snoozed + blocked domain passes; `snooze off` ⇒
   re-armed
4. `hush log --blocked -n 5` contains the test queries, newest first
5. wrong token in `api.token` (corrupt the file after daemon start) ⇒ exit 1
   with the API error surfaced; missing state dir ⇒ exit 2 with the
   isn't-running message
6. `hush status --json` parses as JSON and matches /v0/status schema keys

**Live:** none needed (no external network in this WP).

## 6. Deliverable shape

- `crates/daemon/src/api/{mod,routes,auth,types}.rs`; wire into `App::start`
  (API task starts after DNS listeners are ready, included in `RunningApp`
  readiness + `shutdown()`).
- `crates/cli/src/{main,client,output}.rs` replacing the stub.
- Gate green per standards §1 (now includes the e2e layer); run summary per
  standards §7. After this WP the P0 exit criterion from `docs/architecture.md`
  §10 is met: dogfoodable by pointing system DNS at 127.0.0.1 manually.
