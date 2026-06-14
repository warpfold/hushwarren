# WP8 — Transport privacy: DoH3, EDNS padding, rebind protection, ECH integrity

Implements the four WP8-scheduled rows of the `docs/privacy-roadmap.md` §3
table (2026-06-12 research round). All four are Tier-1-grade: default-on once
shipped. Binding: `specs/standards.md`. Builds on the
verified P0/WP4/WP7 stack; extend seams, don't fork. All four items are
Tier 1 (default-on, kill-switch documented). **Do not implement**: DNSSEC
validation (Tier 3, gated, see roadmap), DoQ upstream (revisit only if h3 is
blocked), inbound DoT/DoQ (P4), query sharding.

## 1. Config additions (`hush-core::config`)

```toml
[upstream]
h3 = true                      # prefer DoH3 rungs where the provider supports it

[privacy]
doh_padding = true             # RFC 8467 block padding on encrypted upstream queries
rebind_protection = true       # reject private addresses in public-name answers
rebind_allow = []              # extra domain suffixes exempt from rebind protection
```

Defaults ON (zero-touch: better privacy with silent fallback / negligible FP
risk). `validate()`: `rebind_allow` entries must parse as domain suffixes
(reuse the allowlist syntax). Round-trip stable; defaults unchanged elsewhere.

## 2. DoH3 upstream rungs (`hush-daemon::upstream`)

- Add hickory-resolver feature `h3-ring` (same ring/rustls family we already
  use; run `cargo deny` — quinn et al. must stay permissive; a violation is a
  stop-and-report, not a deny.toml edit).
- Ladder construction: for each DoH endpoint whose provider is **verified to
  serve DoH3** (Cloudflare and Quad9 confirmed live 2026-03-31; verify Mullvad
  at implementation time — only verified providers get an h3 rung), insert an
  h3 rung immediately BEFORE that provider's h2 rung, same URL + bootstrap
  IPs. The existing rung-failover machinery (health checks + hysteresis) IS
  the h2 fallback — no new fallback logic. `upstream.h3 = false` ⇒ ladder
  unchanged from today.
- QUIC blocked (UDP-443-filtered networks) must degrade silently to the h2
  rung within the existing rung timeout — assert in tests that an unreachable
  h3 rung does not add user-visible latency beyond one rung step.
- Surface: rung names in `/v0/status` upstream section distinguish `doh3://`
  vs `doh://` (additive string change only).

## 3. EDNS padding, RFC 8467 (`hush-daemon::upstream`, `odoh.rs`)

Behavior: every DNS query sent over an **encrypted** rung (DoH h2, DoH3,
ODoH) carries an EDNS(0) Padding option (code 12) bringing the serialized
query to a multiple of 128 octets. Never pad Do53 rungs (RFC 7830 §6 —
padding on cleartext is a tracking vector, not a defense).

Seam reality (verify against hickory 0.26 docs.rs, not memory):
- ODoH rung (`odoh.rs`) hand-rolls message bytes — pad there directly.
  Mandatory.
- The hickory-resolver DoH path owns serialization internally. Candidate
  seams, in preference order: (a) a hickory API that lets us attach EDNS
  options to outgoing queries (check `ResolverOpts`/connection-provider
  hooks in 0.26); (b) if none exists, hand-roll the DoH rung: build the
  query via `hickory_proto::op::Message` + POST `application/dns-message`
  over our existing reqwest (h2) client — we then own the bytes. (b) is a
  bigger change: keep the hickory rung as the implementation for
  `doh_padding = false` and only route through the hand-rolled rung when
  padding is on, OR migrate fully if parity is provable — implementer
  decides, documents, and reports per standards §7.
- If (a) and (b) both turn out blocked, STOP and report — do not ship a
  partial "padding" claim (roadmap §5 honesty rule).

## 4. Rebind protection (`hush-core::decision` + response path)

After upstream resolve + CNAME-chain inspection, before caching/answering:
if the original qname is NOT a local name (locals never reach upstream) and
any A/AAAA record in the answer is in the reject set, treat the response as
blocked: answer **NODATA**, reason `RebindBlocked { addr }` (new variant;
offending address in the query-log detail), counted in metrics.

- Reject set: RFC1918 (10/8, 172.16/12, 192.168/16), loopback (127/8, ::1),
  link-local (169.254/16, fe80::/10), ULA (fc00::/7), unspecified (0.0.0.0,
  ::). **Explicitly allowed**: CGNAT 100.64/10 (Tailscale/MagicDNS lives
  there).
- Exemptions, checked before rejection: user allowlist (existing — allow
  always wins), `privacy.rebind_allow` suffixes, and a compiled-in exemption
  for `plex.direct` (documented Plex LAN-playback pattern; keep the built-in
  list to exactly this until evidence demands more).
- Known FP class to document where the toggle lives: corporate split-horizon
  DNS reached through the Do53-to-DHCP fallback rung. Mitigation is the
  kill-switch + `rebind_allow`; do NOT auto-disable on VPN detect in this WP
  (Sentinel coupling is a separate decision — note it as future).
- Cache stores the NODATA verdict (same rationale as CNAME inspection: the
  cache holds the sinkhole, not the chain).

## 5. HTTPS/SVCB (type-65) integrity (tests + one behavior check)

ECH depends on HTTPS RRs; a filter that mangles them silently downgrades
browser privacy. Two binding behaviors, mostly assertions of what should
already be true:

- Allowed qname, qtype HTTPS ⇒ the upstream RDATA (SvcParams, ech blob)
  reaches the client byte-intact. Fix any normalization that breaks this.
- Blocked qname, qtype HTTPS ⇒ sinkhole semantics consistent with A/AAAA
  (NODATA per current non-address-qtype block behavior — verify; the query
  must NOT reach upstream, and must not leak the real ech config).
- Rebind protection (§4) inspects A/AAAA only — ipv4hint/ipv6hint SvcParams
  are hints, not answers; do not reject on them (document).

## 6. Surface updates (additive only)

- `/v0/status` privacy object gains `doh_padding`, `rebind_protection`;
  upstream section distinguishes doh3 rungs (§2).
- CLI `hush status` privacy line gains compact markers: `pad✓ rebind✓`
  (✗ when off), keeping the existing order/format.
- `hushd print-config` reflects the new defaults.

## 7. Mandatory tests

**Unit (core):** reject-set membership table (every range above, v4+v6,
boundary addresses); exemption precedence (allowlist > rebind_allow >
built-in > reject); config round-trip + validate() problems for bad
`rebind_allow` entries.

**Unit (daemon):** padding: serialized query length % 128 == 0 across qname
lengths 1..=253 (table-driven sample), Do53 rung NOT padded; rebind: response
walker flags offending record incl. behind a CNAME chain, CGNAT passes,
plex.direct passes; ladder: h3-rung insertion order per provider flag matrix.

**Integration (daemon tests/, extend mock upstream):** (1) mock upstream
returns 192.168.1.1 for a public name ⇒ NODATA, reason RebindBlocked, metric
incremented; flag off ⇒ answer passes; (2) rebind_allow suffix ⇒ passes;
(3) type-65 RDATA round-trips byte-intact through the daemon for an allowed
name (mock zone with SvcParams incl. a dummy ech blob); (4) blocked name
type-65 ⇒ sinkholed, zero upstream contacts (assert on mock hit counter);
(5) padding asserted on the wire against a byte-capturing mock (reuse the
ecs_test harness pattern); (6) h3 rung unreachable ⇒ h2 rung answers within
one rung timeout.

**E2E (cli):** `hush status` shows the extended privacy line.

**Live (#[ignore]):** `live_doh3_quad9` + `live_doh3_cloudflare` (proves real
h3 negotiation); `live_https_rr_ech`: query an HTTPS RR for a domain known to
publish ech through the daemon, assert ≥1 type-65 answer with non-empty
SvcParams (do NOT hard-assert the ech key — CDN behavior drifts); re-run
`live_doh_*` h2 suite (regression).

## 8. Deliverable

Config additions in core; ladder + padding in upstream.rs/odoh.rs; rebind
walker in core decision + daemon response path; tests per §7. Gate per
standards §1 incl. `cargo deny` (h3 pulls quinn — verify licenses). Run
summary per standards §7 with this §7 checklist; padding-seam decision (§3)
documented explicitly.
