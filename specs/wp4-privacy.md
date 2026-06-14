# WP4 — Privacy Tier 1 (default-on) + Tier 2 toggles (gated)

Implements `docs/privacy-roadmap.md` §1–§2. Binding: `specs/standards.md`.
Builds on the verified P0 stack; extend seams, don't fork. **Do not implement any
Tier 3 item** (no ODoH, no padding, no sharding).

## 1. Config additions (`hush-core::config`)

```toml
[lists]
preset = "balanced"              # "minimal" | "balanced" | "strict" | "aggressive" | "custom"
extra_categories = []            # catalog keys, see §2
sources = []                     # when preset="custom" (or to ADD to a preset — see merge rule)

[privacy]
browser_doh_canary = true        # Tier 1.2
cname_inspection = true          # Tier 1.4
query_log = "full"               # "full" | "anonymous" | "off"   (Tier 1.3)
block_doh_bypass = false         # Tier 2.1 (gated)
block_private_relay = false      # Tier 2.2 (gated)
```

Merge rule (fixes the §config trap found in live testing, where declaring any
`[[lists.sources]]` silently replaced the defaults): effective sources =
`preset_sources(preset) ∪ catalog(extra_categories) ∪ sources`. `preset="custom"`
⇒ preset contributes nothing. `validate()` problems: unknown preset, unknown
category key, `custom` with empty union. Defaults unchanged for everything else;
config stays round-trip stable.

## 2. Source catalog (`hush-core::catalog`, new module)

Compiled-in, data-only (names/URLs/licenses/format notes — actual lists still
runtime-fetched). Entries (URLs verified 2026-06-12, roadmap §7):

- Presets — minimal: hagezi-light (`https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/light.txt`);
  balanced: oisd-small (`https://small.oisd.nl/domainswild2`) + hagezi-normal
  (`.../domains/multi.txt` — the Normal tier's real filename); strict: oisd-big
  (`https://big.oisd.nl/domainswild2`) + hagezi-pro (`.../domains/pro.txt`).
- Categories — `telemetry-windows` (hagezi `domains/native.winoffice.txt` +
  WindowsSpyBlocker `https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt`),
  `telemetry-samsung|xiaomi|apple|amazon|huawei` (hagezi `domains/native.<vendor>.txt`),
  `threat-intel` (hagezi `adblock/tif.medium.txt` — adblock format, parser handles),
  `doh-bypass` (hagezi `adblock/doh-vpn-proxy-bypass.txt`; auto-included when
  `privacy.block_doh_bypass = true`, also selectable explicitly), `nsfw`
  (`https://nsfw.oisd.nl/domainswild2`).
- Each catalog entry: `key, name, url, license: Option<&str>, attribution: &str`.
  Public `Catalog::resolve(preset, &categories) -> Result<Vec<SourceConfig>, _>` +
  `Catalog::all()` for the API/dashboard.

## 3. Behavior changes (`hush-daemon`)

### 3.1 Browser-DoH canary (dns.rs, before decide())
qname == `use-application-dns.net` (case-insensitive, any qtype) and flag on ⇒
**NXDOMAIN**, reason `BrowserDohCanary` (new `Reason` variant), counted in metrics,
logged at debug. Flag off ⇒ normal pipeline.

### 3.2 Private Relay gate (dns.rs, same site)
Flag ON: `mask.icloud.com` / `mask-h2.icloud.com` (and subdomains) ⇒ **NODATA**
(Apple-documented response; NOT null-IP, NOT a timeout), reason `PrivateRelayBlocked`.
Flag OFF (default): these domains are FORCE-ALLOWED — i.e. even if a blocklist
contains them, they forward (reason `PrivateRelayProtected`). Rationale: a list
must not silently disable a user's privacy feature; only the explicit toggle may.

### 3.3 CNAME-chain inspection (upstream response path)
After upstream resolve, before answering: walk every CNAME target in the response
chain (hickory `Lookup` records). For each hop: run the SAME decision ladder
(user-allow → list-allow → list-block; skip snooze/local — snooze already returned
early, locals don't reach upstream). Any hop Blocked ⇒ respond as if the original
qname were blocked (sinkhole per configured action; reason `CnameCloaked { hop }` —
record the offending hop in the query log detail). Allow at any hop only protects
that hop, not the chain. Depth cap 10 hops (count + forward uninspected beyond cap,
warn once per qname). Flag off ⇒ skip entirely. Document: inspection is
response-side (AdGuard model), so cache hits inherit the original verdict — note
why that's sound (cache stores the sinkhole, not the chain).

### 3.4 Query-log modes (querylog wiring)
`full` = today. `anonymous` ⇒ QueryRecord stored with `qname = "<redacted>"`
(counters/verdict/reason intact; CnameCloaked hop also redacted). `off` ⇒ ring
never written (stats counters still increment). API `/v0/queries/recent` in
`anonymous|off` returns 200 with `{queries: [...redacted...]}` / empty + a
`"log_mode"` field; CLI `hush log` prints the mode notice. Mode is config-time
(no runtime toggle in this WP — dashboard lands later).

## 4. Surface updates

- API: `GET /v0/status` gains `privacy: {browser_doh_canary, cname_inspection, query_log, block_doh_bypass, block_private_relay}`
  and `GET /v0/lists` gains `preset` + per-source `category`/`license`/`attribution`.
  Additive only — existing keys unchanged (CLI types tolerate unknown fields; add
  the new fields to CLI types too).
- CLI: `hush status` prints a `privacy` line (compact: `canary✓ cname✓ log=full`);
  `hush lists` shows attribution string per source.
- `hushd print-config` reflects all new defaults.

## 5. Mandatory tests

**Unit (core):** preset→sources resolution incl. custom/empty problems; merge rule
(preset ∪ categories ∪ explicit, dedup by URL); catalog URL well-formedness (parse
as `reqwest::Url` shape via plain checks — no reqwest dep in core); config
round-trip with new sections; unknown preset/category ⇒ collected problems;
query_log mode parsing.

**Unit (daemon):** canary NXDOMAIN any-qtype + flag-off passthrough; Private Relay
NODATA when on / force-allow-beats-blocklist when off; CNAME walker: chain with
blocked-mid-hop ⇒ Block(CnameCloaked), allow-at-hop ⇒ pass, depth-cap, no-CNAME
fast path untouched; redaction in anonymous mode; ring untouched in off mode.

**Integration (daemon tests/, extend mock upstream to serve CNAME chains):**
(1) canary e2e: query `use-application-dns.net` ⇒ NXDOMAIN; (2) cloaked tracker:
mock zone `shop.example.test CNAME track.evil.test`, `track.evil.test A …`, only
`evil.test` blocklisted ⇒ query for `shop.example.test` sinkholed; flag off ⇒ real
answer; (3) user-allow `evil.test` ⇒ passes with inspection on; (4) private-relay
toggle on ⇒ NODATA for `mask.icloud.com`, off ⇒ forwards even when blocklisted
(seed the list); (5) preset=minimal boots and compiles from a local mock list
server mapped to the catalog (override catalog URLs via test-only injection —
add `Catalog::resolve_with_overrides` or accept a base-URL rewrite hook; do NOT
hit the real internet); (6) query_log=off ⇒ /v0/queries/recent empty + counters
advance.

**E2E (cli):** `hush status` shows the privacy line; `hush log` in off-mode
prints the notice (daemon started with the flag).

**Live (#[ignore]):** `live_privacy_lists_fetch`: resolve the real catalog —
fetch hagezi-light + hagezi `multi.txt` + tif.medium HEAD/GET, assert 200 and
non-trivial size (catches URL rot; do NOT assert counts).

## 6. Deliverable

New core module `catalog.rs`; daemon changes in dns.rs/upstream.rs/querylog
wiring/api; CLI additive fields. Gate per standards §1 (incl. `cargo deny` — no
new deps expected; if you need one, justify). Run summary per standards §7 with
this §5 checklist.
