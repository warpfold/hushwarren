# Privacy Roadmap — basics on by default, advanced behind gates

Status: **v0.2, research-grounded** (web research 2026-06-12, refreshed same day
for the WP8 round; sources in §7).
Product rule unchanged: zero-touch. Privacy basics must work with NO configuration;
advanced features are config-gated because each carries a breakage or ethics cost.

## 0. Positioning

hushwarren is privacy-*focused*, not privacy-*absolutist*: we maximize privacy by
default **without breaking anything and without disabling other privacy tools**.
Two consequences that differ from competitors:

- We do NOT block iCloud Private Relay by default (Pi-hole does — see §2.4).
- We never log off-device; query logs are RAM-first and the on-disk story is opt-in.

## 1. TIER 1 — enabled by default (the "easy and basic" set)

### 1.1 Category list presets
One config knob, sane default, curated catalog baked into the binary (URLs only —
lists are still runtime-fetched data):

```toml
[lists]
preset = "balanced"            # minimal | balanced | strict | aggressive
extra_categories = []          # "telemetry-windows", "telemetry-samsung", ... "threat-intel"
```

| Preset | Sources (catalog) | Rationale |
|---|---|---|
| minimal | Hagezi Light | ads only, near-zero FP risk |
| **balanced** (default) | OISD small + Hagezi Normal (`multi.txt` — NB: not `normal.txt`) | ads + trackers, "don't break" philosophy |
| strict | OISD big + Hagezi Pro | + telemetry/aggressive tracking |

`extra_categories` map to Hagezi native-vendor lists (Samsung/Xiaomi/Apple/Windows-
Office/Amazon/Huawei…, MIT-licensed), WindowsSpyBlocker (actively maintained,
v4.39.0 2026-04), and Hagezi TIF-medium for threat-intel. License note: Hagezi =
MIT (verified); **OISD has no stated license** — acceptable as runtime-fetched data
with attribution, NOT bundleable; the packaged first-run snapshot (P2) must
therefore be built from Hagezi only.

### 1.2 Browser-DoH coherence (Firefox canary)
Answer `use-application-dns.net` with NXDOMAIN (NODATA also valid per Mozilla; we
use NXDOMAIN). Effect: Firefox's *default-on* DoH steps aside so the system path —
us — handles DNS; users who explicitly enabled Firefox DoH are not overridden
(canary doesn't apply to them, by Mozilla's design — we honor that).
`privacy.browser_doh_canary = true` (default).

### 1.3 Query-log privacy modes
P0 already logs to RAM only (ring buffer). Make the policy explicit:

```toml
[privacy]
query_log = "full"     # full | anonymous | off
```
- `full` (default): qname+verdict in RAM ring, nothing on disk (status quo).
- `anonymous`: counters and verdict/reason only — no qnames stored anywhere.
- `off`: counters only, ring disabled, `hush log` returns an explanatory notice.
When sqlite rollup lands (P1+), retention knobs attach here (`retain_days`, default 7).

### 1.4 CNAME-cloaking inspection — default ON
First-party-looking trackers hide behind CNAMEs (verified-active operators:
Eulerian, AT Internet/Piano, Criteo, Adobe Experience Cloud, Commanders Act,
Pardot, Eloqua, Webtrekk, LiveIntent, TraceDock, Wizaly). Industry baseline is
default-on (Pi-hole `CNAMEdeepInspect=true`, AdGuard Home always-on, ControlD on;
only NextDNS gates it). Mechanism: evaluate **every CNAME target in the upstream
response chain** against the same rules + allowlist; any blocked hop ⇒ sinkhole the
original query. FP safety = identical to Pi-hole's: an intermediate blocks only if
it is independently blocklisted; user allowlist wins at every hop.
`privacy.cname_inspection = true` (default), kill-switch documented.

> Classified "basic" despite implementation depth: invisible to users, industry-
> default, and the FP profile is the same as ordinary blocking.

## 2. TIER 2 — implemented but GATED (off by default)

### 2.1 DoH-bypass blocking (`privacy.block_doh_bypass = false`)
Block resolution of known public DoH endpoints (Hagezi doh-vpn-proxy-bypass,
~17k entries, MIT; dibdot/DoH-IP-blocklists for reference) so apps with built-in
DoH fall back to system DNS. Gated because it intentionally breaks a user-chosen
configuration in OTHER software — that's an admin decision, not a default.

### 2.2 iCloud Private Relay handling (`privacy.block_private_relay = false`)
When enabled: answer `mask.icloud.com` / `mask-h2.icloud.com` with NODATA — Apple's
documented mechanism; the device shows the user a clear notice and offers a choice.
**Default OFF on ethics**: Private Relay IS a privacy feature; silently disabling
it to preserve our own filtering trades the user's privacy for our coverage
(Pi-hole defaults to blocking; AdGuard's lists don't include it; we side with
AdGuard). The dashboard explains the trade-off where the toggle lives.

### 2.3 NSFW / family filtering (`lists.extra_categories = ["nsfw"]`)
OISD NSFW. Gated: content policy is a household decision, never a default.

### 2.4 Candidate: fingerprinting categories (not yet in catalog)
Hagezi `native.tiktok.txt` (TikTok SDK fingerprinting endpoints) and the
Pro++ "fingerprinter" tier block the *reporting* of fingerprint data — real
value, but Hagezi labels Pro++ "may contain false positives." Add as gated
`extra_categories` keys only after an FP bake-off; never a default.

## 3. TIER 3 — specced, future (gated when they land)

| Feature | Ground truth blocking it today | Plan |
|---|---|---|
| EDNS padding (RFC 7830/8467) | hickory still has none — issue #504 open since 2018, no 2026 movement. ~~blocks us~~ **It doesn't block us**: we control the bytes on the ODoH rung today and can own the DoH bytes too | **Implemented (WP8)** — 128-octet block padding on DoH-h2 (hand-rolled `PaddedDohRung`; hickory 0.26 exposes no EDNS-option hook, verified) and ODoH rungs; never on Do53. v1 honesty note: hickory-native **h3 rungs are unpadded** (no seam) — documented in upstream.rs |
| DoH3 / DoQ upstream | hickory-resolver 0.26 ships `h3-ring`/`quic-ring`; Quad9 serves DoQ+DoH3 globally since 2026-03-31, Cloudflare serves DoH3 | **Implemented (WP8)** — `upstream.h3 = true` (default) inserts h3 rungs before h2 rungs for verified providers (Cloudflare ✓, Quad9 ✓; Mullvad verified NOT serving DoH3 2026-06-12); existing ladder = the fallback; live h3 proven against both. QUIC hides transport metadata TCP+TLS leaks; confidentiality is equal — don't overclaim |
| DNS rebind protection | Not a standards gap — just unbuilt. NextDNS/Pi-hole gate it; we can default-on because Local Guard has one client | **Implemented (WP8)** — `privacy.rebind_protection = true` (default): private/loopback/link-local/ULA answers for public names ⇒ NODATA + `RebindBlocked{addr}`; CGNAT 100.64/10 allowed (Tailscale), `plex.direct` built-in exempt, `privacy.rebind_allow` for split-horizon |
| HTTPS/SVCB (ECH) integrity | ECH ships in major browsers and rides on type-65 RRs; middleboxes have started stripping them (Palo Alto, 2026-02) | **Implemented (WP8)** — asserted by test: type-65 RDATA byte-intact for allowed names (mock ech blob), sinkholed with zero upstream contact for blocked ones; live ECH proof against crypto.cloudflare.com. Rebind inspection ignores ipv4/ipv6 hints |
| DNSSEC validation | hickory 0.26 has `dnssec-ring`, but global INVALID rate ≈0.1% and the 2026-05-05 `.de` signature incident broke millions of domains on validating resolvers for ~3 h — a P1 ("never break the internet") violation as a default | Tier 3, gated `privacy.dnssec_validate = false` when specced; revisit if INVALID rate drops below ~0.01%. Integrity, not privacy — DoH already removes the in-path forgery surface |
| QNAME minimization | hickory implements it only in the *recursor*; our stub/forwarder path can't | Honest doc: meaningful only if we grow a recursive mode; upstreams that minimize (Mullvad, verified) inherit it for us |
| ECS | ~~As a stub forwarder we don't attach ECS at all today~~ | **Asserted by test** (`ecs_never_sent`) — hickory does NOT inject ECS; confirmed WP7. |
| Oblivious DoH rung | ~~odoh-rs v1.0.4 (BSD-2, alive, Cloudflare) = crypto primitives only; relay ecosystem small, Cloudflare-centric~~ Relay update 2026-06: two public non-Cloudflare relays exist (Fastly/F. Denis, Hetzner/Numa) — relay-mode is genuinely two-party now; the *target* is still Cloudflare-only. Watch for a Mullvad/Quad9 target | **Implemented, experimental** — `privacy.odoh = true` inserts ODoH rung at rung-0; `odoh-rs` v1.0.4 (BSD-2, deny-verified); direct-to-target mode + relay-mode via RFC 9230 query params; 1 h config cache; retry-on-decrypt; WP7 shipped. |
| Anonymized DNSCrypt rung | healthy relay ecosystem (~450 relays) but **no permissive Rust client library exists** (gap) | Larger build; revisit after ODoH; could be a contribution opportunity |
| Query sharding across resolvers | no blocker, design needed (cache interaction, per-domain stickiness) | Behind `privacy.shard_upstreams`; needs care: naive sharding can worsen fingerprinting |
| Privacy-insight dashboard ("your TV phoned home 4,112×") | ~~needs sqlite rollup (P1+)~~ | **Implemented (WP9)** — sqlite rollup (retain_days, anonymous-mode redaction verified on the durable surface) + Insights tab (`/v0/stats/top`, `/v0/stats/history`); Tier 1 |

## 4. Upstream choices (informed by verified policies)

- Cloudflare: truncated-IP logs deleted ≤25h, audited (KPMG FY2025 signed
  2026-02). Quad9: no IP retention at all; **dropped HTTP/1.1 DoH 2025-12-15**
  (~~verify in CI live test~~ **done** — `live_doh_quad9` proves the h2 path);
  DoQ + DoH3 live globally since 2026-03-31 (→ WP8). Mullvad DoH: free,
  QNAME-min, no-log (Assured-audited), Swedish jurisdiction.
- ~~Action: ship Mullvad as a selectable third preset upstream~~ **Shipped**
  (`[upstream] preset = "mullvad"` → Mullvad→Cloudflare→Quad9; unfiltered
  `dns.mullvad.net` since we do our own blocking; `live_doh_mullvad` covers it).
  Default ladder stays Cloudflare→Quad9; dashboard policy text still pending
  the dashboard (P2).
- Evaluated and NOT added (2026-06): **DNS4EU** (EU-sovereign but retains IPs
  ~3–6 months for troubleshooting/threat research — disqualified as a no-log
  preset; reconsider only as an explicitly-disclosed EU option), **Hagezi
  resolver** (no-log, EU, but single operator, three servers, no anycast, and
  it filters with its own lists upstream of ours — double-blocking), and
  **dns0.eu** (shut down 2025-10).

## 5. What DNS cannot do (kept honest, shown in docs/dashboard)

No URL-parameter stripping, no cookie/fingerprint defense, no content inspection,
no protection against hardcoded-IP DoH (firewall territory). Claims beyond DNS
scope are how privacy products lose trust.

## 6. Implementation order

1. ~~**WP4: Tier 1 complete + Tier 2 toggles**~~ Shipped (incl. the §4 API/CLI
   surface and the `block_doh_bypass` auto-include, both landed 2026-06-12).
2. ~~P1 Sentinel work proceeds in parallel~~ Shipped on macOS (live-proven);
   Linux platform implemented, live proof pending.
3. ~~ODoH first among Tier 3~~ Shipped experimental (WP7, with ECS assertion).
4. ~~**WP8: transport privacy**~~ Shipped 2026-06-12 (DoH3 rungs, EDNS padding
   on h2+ODoH, rebind protection, HTTPS/SVCB integrity — all default-on; spec
   `specs/wp8-transport-privacy.md`).
5. Remaining Tier 3 items (DNSSEC gated, sharding, DNSCrypt, h3-rung padding
   once hickory grows an EDNS seam) each get their own spec when scheduled.

## 7. Source notes

Hagezi repo (MIT, tier URLs incl. `multi.txt` naming), OISD downloads page (no
license stated), Mozilla canary-domain support doc (NXDOMAIN *or* NODATA),
Apple "Prepare your network for iCloud Private Relay" (NODATA/NXDOMAIN, no drops),
Pi-hole FTL config docs (`CNAMEdeepInspect` default true), AdGuard cname-trackers
repo, NextDNS cname-cloaking-blocklist, hickory issues #504 (padding, open) and
#3676 (QNAME-min RFC 9156, open), odoh-rs v1.0.4 BSD-2, DNSCrypt v3 relay list
(~450), Cloudflare/Quad9/Mullvad privacy pages.

WP8 round (2026-06-12): Quad9 DoQ/DoH3 GA announcement (2026-03-31),
hickory-resolver 0.26 docs.rs feature flags (`h3-ring`/`quic-ring`,
`dnssec-ring`), RFC 8467 + edns0-padding.org implementation matrix (hickory
absent), Mullvad DoH/DoT help page (endpoint + Assured audit), DNSCrypt v3
odoh-relays list (2 public relays: Fastly, Hetzner/Numa), Tailscale & Plex
rebinding-FP threads, NextDNS rebind help, Palo Alto 2026-02 release notes
(HTTPS-RR blocking to defeat ECH), RFC 9460, technologychecker.io DNSSEC
adoption stats (≈0.1% INVALID), DENIC `.de` signature incident write-ups
(2026-05-05), DNS4EU launch + Timelex retention analysis, dns0.eu shutdown
coverage (2025-10), Hagezi dns-servers repo.
