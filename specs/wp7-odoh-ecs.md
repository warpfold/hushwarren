# WP7 — ODoH experimental rung + ECS-never-sent assertion

Implements `docs/privacy-roadmap.md` §3 rows "Oblivious DoH rung" and "ECS".
Binding: `specs/standards.md`. Scope: `crates/daemon/src/upstream.rs` + the
`[upstream]`/`[privacy]` config surface + tests. Root Cargo.toml dep additions
are YOURS (no other agent owns it right now).

## 1. ECS-never-sent (Tier 1 truth-claim — cheap, do it first)

Claim: hushwarren never attaches an EDNS Client Subnet option upstream.
Prove it, don't assume it:

- Integration test `ecs_never_sent`: extend the mock Do53 upstream in
  `crates/daemon/tests/` to CAPTURE raw query bytes; drive 3 query shapes
  (cold lookup, cache-bypass second name, TCP retry via truncation if cheap —
  else skip TCP, note it); parse each captured query's OPT record (hickory-proto
  `Message::from_vec`) and assert NO option code 8 (ECS) present.
- If the assertion FAILS (hickory silently adds ECS): do NOT hack around it —
  report in the run summary with the hickory API that controls it; fixing
  becomes a follow-up decision.
- Document the claim in `docs/privacy-roadmap.md` §3 table (flip the ECS row to
  "asserted by test" — one-line edit).

## 2. ODoH rung (`privacy.odoh`, default OFF, experimental)

RFC 9230 via `odoh-rs` (BSD-2-Clause, v1.0.4 — verify license in cargo deny).
odoh-rs provides ONLY the crypto encapsulation; you build the transport:

```toml
[upstream.odoh]                 # presence + privacy.odoh=true enables the rung
target = "https://odoh.cloudflare-dns.com/dns-query"
relay = ""                      # "" = DIRECT-TO-TARGET (testing mode, see below)
bootstrap_ips = ["1.1.1.1"]     # for resolving the target/relay hostnames
[privacy]
odoh = false                    # gate (roadmap Tier 3): experimental
```

Mechanics:
1. Fetch the target's ODoH config: GET `<target-origin>/.well-known/odohconfigs`
   (Cloudflare serves it; via reqwest with bootstrap-IP `resolve()` override —
   the loop hazard rule applies here too). Parse with odoh-rs
   (`ObliviousDoHConfigs::deserialize`-equivalent — CHECK the v1.0.4 docs.rs API,
   do not code from memory). Cache for 1h; refresh on decrypt failure.
2. Per query: build the DNS message bytes → `encapsulate` with a fresh client
   secret per query (odoh-rs API) → POST `application/oblivious-dns-message` to
   `relay` if set (with `targethost`/`targetpath` query params per RFC 9230 §7)
   else directly to the target → `decapsulate` response → hand the Message up
   as a normal lookup result.
3. Rung position: when enabled, ODoH becomes rung 0; existing DoH rungs follow
   as fallback (ladder semantics unchanged). Timeout 4s.
4. **Honesty requirement** (this text, nearly verbatim, in the config docs and
   the roadmap table): *direct-to-target ODoH still hides client IP↔query
   linkage from cache/transport observers but the target sees your IP exactly
   like DoH; unlinkability requires a relay run by a different party. Public
   relay ecosystem is small — relay mode is configured but we ship no default
   relay.* Status: experimental.
5. New deps: `odoh-rs` (+ whatever it needs that isn't already in-tree). Run
   `cargo deny check` — BSD-2 is allowlisted. If odoh-rs drags in something
   non-permissive, STOP and report.

## 3. Tests

**Unit:** odoh config-cache expiry/refresh-on-failure logic (mock the fetch);
rung-0 insertion when enabled; flag off ⇒ ladder identical to before (assert
constructor output shape).

**Integration:** mock ODoH TARGET in-process: axum server that (a) serves
generated `odohconfigs` (use odoh-rs server-side API to mint a config+keypair in
the test), (b) accepts oblivious-dns-message POSTs, decapsulates with the test
keypair, answers a fixed A record, encapsulates the response. Tests: happy path
end-to-end through `UpstreamLadder`; decrypt-failure ⇒ config refetch then rung
failover (next rung serves); flag off ⇒ target never contacted.

**Live (#[ignore]):** `live_odoh_cloudflare`: real config fetch from
`odoh.cloudflare-dns.com` + resolve `cloudflare.com` A direct-to-target; assert
NOERROR + ≥1 answer; print latency. (This is goal-clause-3's live proof.)

Gate per standards §1; run summary per §7. Do not touch sentinel/platform files —
another agent owns them concurrently. Shared files you may touch: root Cargo.toml
(you own it this round), `crates/core/src/config.rs` (upstream+privacy sections
only — the other agent adds a `[sentinel]` section; keep your edits scoped to
your structs so a textual merge is trivial), `docs/privacy-roadmap.md` (the two
table-row edits).
