# WP9 — SQLite query-log rollup + embedded dashboard SPA

P2 deliverable (architecture §7, §8; roadmap §1.3 retention, §3 privacy-insight
row). Binding: `specs/standards.md`. The dashboard is a bonus, not a
requirement (P5): nothing may regress for users who never open it.

## 1. Config additions (`hush-core::config`)

```toml
[privacy]
retain_days = 7                # sqlite history retention (roadmap §1.3)

[dashboard]
enabled = true                 # serve the SPA on the existing loopback API port
```

`retain_days` range 1..=90 (validate). Query-log mode interplay (binding):
`full` ⇒ sqlite rows carry qnames; `anonymous` ⇒ rows carry verdict/reason
with `qname = "<redacted>"`; `off` ⇒ **no sqlite writes at all**. Mode changes
do not retro-purge (document), but `off` at startup also skips opening the DB.

## 2. SQLite rollup (`hush-daemon`, new module `rollup.rs`)

- Dep: `rusqlite` (bundled feature; MIT — verify `cargo deny`). Core stays
  sqlite-free: rollup consumes the existing `QueryRecord` types from core.
- WAL mode, single writer task fed by a bounded channel off the existing
  query-log write path (hot path never blocks: on full channel, drop + count
  a `rollup_dropped` metric). Batched inserts (flush every 2 s or 256 rows).
- Schema v1: `queries(ts_ms, qname, qtype, verdict, reason, detail)` +
  `meta(schema_version)`. Index on ts_ms. (`client_ip` column is WP13 —
  leave it out; WP13 migrates schema to v2.)
- Retention: hourly job deletes rows older than `retain_days` and enforces a
  100 MB cap (incremental vacuum; oldest-first deletes).
- DB path: `state_dir/querylog.sqlite`, 0600. Corruption ⇒ rename aside +
  recreate + warn (never crash, never block DNS).

## 3. Stats/history API (additive)

- `GET /v0/stats/history?hours=24&bucket=3600` → time-bucketed totals
  {ts, total, blocked} from sqlite (404-style empty result when log off).
- `GET /v0/stats/top?n=20&hours=168` → top blocked + top allowed domains
  (redacted mode ⇒ empty lists + `log_mode` field — same honesty contract as
  /v0/queries/recent). This powers privacy-insight ("your TV phoned home
  4,112×" — roadmap §3 row flips to Tier 1 when this ships).

## 4. Dashboard SPA (`hush-daemon`, embedded assets)

- NO JS build toolchain: hand-written static `index.html` + one CSS + one JS
  file under `crates/daemon/assets/dashboard/`, embedded with `include_dir`
  (or `include_str!` — pick the lighter; any new dep through `cargo deny`).
  Served at `/dashboard/` from the EXISTING loopback axum server.
- Auth: static assets are served without auth (they contain no secrets).
  All data fetches send the existing bearer token header. Token delivery:
  `hush dashboard` (new CLI verb) prints/opens
  `http://127.0.0.1:<port>/dashboard/#token=<token>` — fragment, never query
  string (fragments don't reach server logs); the JS moves it to
  sessionStorage and strips the fragment. No cookies, no CORS (same-origin
  only), CSRF-safe by construction (header token).
- Views (one page, tabs; keep it boring): **Status** (guard state, counters,
  upstream ladder incl. doh3/doh labels, privacy flags); **Recently blocked**
  with one-click Allow (existing POST /v0/allow) — the killer papercut fix;
  **Insights** (top blocked over retain window, total per day) honoring log
  mode; **Lists** (per-source name/category/license/**attribution** — this is
  the license obligation surface, roadmap §1.1); **Privacy** (read-only
  toggles + the Private-Relay trade-off explanation text from roadmap §2.2,
  and the §5 "what DNS cannot do" honesty block).
- `dashboard.enabled = false` ⇒ 404 on /dashboard/, API unchanged.

## 5. CLI

`hush dashboard [--print-url]` — discovers addr+token (existing discovery),
default opens the browser (`open`/`xdg-open`/`start` shell-out, no new dep),
`--print-url` only prints.

## 6. Mandatory tests

**Unit (daemon):** rollup batching/flush; retention delete math; cap
enforcement; mode interplay (off ⇒ zero writes; anonymous ⇒ redacted rows);
corruption recovery path (feed a garbage file).
**Integration:** insert via real queries against mock upstream ⇒
/v0/stats/history and /top return correct buckets/counts; log off ⇒ empty +
mode field; dashboard route serves index.html with correct content-type;
unauthenticated /v0/* still 401 while /dashboard/ assets 200; disabled ⇒ 404.
**E2E (cli):** `hush dashboard --print-url` prints a URL containing
`#token=` and the live port.

## 7. Deliverable

`rollup.rs`, `assets/dashboard/*`, API routes, CLI verb. Gate per standards
§1 (deny: rusqlite, include_dir). Run summary per standards §7.
