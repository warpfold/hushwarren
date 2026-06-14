# WP14 — P4: inbound encrypted DNS, profiles, mDNS insight

P4 deliverable (architecture §10 P4: "DoT/DoQ inbound, DHCP server, local
mDNS insight, multi-profile"). Binding: `specs/standards.md`. P4 has no
exit criterion — scope is bounded by THIS spec; each feature is gated and
default-off. One item is formally re-scoped:

> **DHCP server — DEFERRED with rationale.** A competing DHCP server on a
> LAN that already has one (every router) can take the network down — a
> direct P1 ("never break the internet") violation with no safe default.
> The supported path stays router-DHCP-DNS (WP13 guidance). Revisit only on
> concrete demand, as its own spec. Record this in architecture §10 P4 row
> and the run summary; implement nothing for it.

## 1. Inbound DoT + DoQ (`[inbound_tls]`, default off)

```toml
[inbound_tls]
enabled = false
bind = []                  # explicit IPs (same rules as network_guard.bind;
                           # loopback ALLOWED here — local testing is legit)
cert_path = ""             # PEM chain; empty + enabled ⇒ self-signed (below)
key_path = ""
doq = false                # DoQ listener on 853/udp additionally to DoT 853/tcp
```

- Server side: verify hickory-server 0.26 feature names on docs.rs for TLS
  and QUIC listeners (ring family, consistent with existing features); wire
  the SAME request handler — zero pipeline forks.
- Self-signed path: when enabled with empty cert/key, generate once into
  `state_dir/inbound-tls/` (rcgen if its license passes cargo deny — verify;
  if not permissive, require user-provided PEM and report) with the bind IPs
  + hostname as SANs, 0600 keys, regenerate on SAN change. Document the
  client-trust reality honestly (Android Private DNS wants a hostname +
  trusted cert; self-signed = manual trust; this feature mainly serves
  LAN/power users — docs/network-guard.md section).
- validate(): enabled+empty bind ⇒ problem; cert without key ⇒ problem; doq
  without enabled ⇒ problem.

## 2. Multi-profile (`hush profile`, hot-reload subset)

- Profiles are full config files in `state_dir/profiles/<name>.toml`.
  `hush profile list|show <name>|switch <name>` (new CLI verbs).
- New API `POST /v0/config/reload {profile}`: daemon re-reads the profile
  and applies ONLY the hot-reloadable subset — lists (preset/categories/
  sources ⇒ refetch+recompile via the existing pipeline), privacy toggles
  (canary, cname, rebind, padding flag consumed at next rung build — if a
  flag is genuinely bind-time, REPORT it and exclude it), upstream preset/
  endpoints (rebuild the ladder atomically — ArcSwap precedent). Explicitly
  NOT reloadable (restart required, API says so in the response):
  listen addrs, network_guard, inbound_tls, api, state_dir, dashboard.
  Response lists `applied: [...]` + `requires_restart: [...]` — honest, not
  silent.
- The active profile name persists (`state_dir/active-profile`) and is
  loaded at startup; absent ⇒ the normal config path (status quo). `hush
  status` shows the active profile when one is set.
- This is the architecture's "multi-profile (work/home)" — document the
  intended use in the CLI help.

## 3. mDNS insight (passive, `[network_guard] mdns_insight = false`)

- Purpose: name the per-client IPs in the WP13 Clients view ("Living-room
  TV" instead of 192.168.1.23). Passive ONLY: join 224.0.0.251:5353 /
  [ff02::fb]:5353 multicast, parse announcements with hickory-proto (NO new
  dep), maintain an ip→hostname map (A/AAAA + PTR from responses; TTL-aged;
  cap 1024 entries). Never transmit a single packet (assert in tests: the
  socket is never written).
- Gated under network_guard (insight without clients is pointless);
  /v0/clients gains `name` field when known; dashboard shows it.
- Failure to join multicast (permissions, iface) ⇒ warn once, feature off,
  nothing else degrades.

## 4. Mandatory tests

Unit: config validate() matrix for all three features; mDNS response parsing
(A/PTR/AAAA, malformed-packet fuzz sample — counted, never panic; reuse the
infallibility discipline of standards §2); reload-subset partition (every
config field classified applied/requires_restart — table test that FAILS
when a new config field is added unclassified: forces future WPs to decide).
Integration: DoT — rustls client connects to the inbound listener on an
ephemeral port with the self-signed cert and resolves a blocked name ⇒
sinkholed (proves pipeline identity); DoQ behind its flag if the hickory
server feature proves usable — if it does not, implement DoT only and
REPORT DoQ as blocked-by-upstream with evidence (do not fake it); profile
switch e2e: boot with balanced, switch to a strict-preset profile via CLI,
assert lists status reflects it without restart + response lists
requires_restart for a listener change; mDNS: feed a canned announcement
packet through the parser path (loopback multicast in CI is flaky — unit-
level parse + map-update coverage is acceptable; say so).

## 5. Deliverable

inbound_tls module, profile verbs + reload endpoint, mdns module, docs
additions. Architecture §10 P4 row updated (DHCP deferred note). Gate per
standards §1 (deny for any new dep: hickory tls/quic features, rcgen). Run
summary per standards §7.
