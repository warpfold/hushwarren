# WP13 — Network Guard (P3): opt-in LAN protection

P3 deliverable (architecture §2 Network Guard, §10 P3). Binding:
`specs/standards.md`. This is the ONE deliberate exception to zero-touch
(the user configures their router's DHCP DNS) — everything here is opt-in,
default off, and must not change Local Guard behavior by a single byte when
disabled.

## 1. Config (`hush-core::config`)

```toml
[network_guard]
enabled = false
bind = []                 # explicit LAN IPs to ALSO listen on, e.g. ["192.168.1.10"]
log_clients = false       # per-client stats opt-in (architecture §7)
```

validate(): enabled with empty bind ⇒ problem; bind entries must parse as
IpAddr and must NOT be unspecified (0.0.0.0/:: refused — explicit addresses
only, a wildcard listener is never zero-touch-safe) and not loopback
(pointless). Disabled ⇒ bind/log_clients ignored (but still validated).

## 2. Listeners (`hush-daemon`)

- When enabled: additional UDP+TCP listeners on each bind:53 join the
  existing loopback set, feeding the SAME pipeline (decision, privacy,
  rebind — nothing forks). Bind failure on a LAN addr (iface down) ⇒ warn +
  retry with backoff, never fatal (the laptop case: iface comes and goes).
- The control API stays loopback-only FOREVER (architecture §8): assert in
  code and test that network_guard never affects the API bind.

## 3. Per-client stats (`log_clients = true` only)

- QueryRecord gains `client: Option<IpAddr>` (core type, serde additive).
  Populated ONLY when the query arrived on a network_guard listener AND
  log_clients is on; loopback queries always None (don't pretend Local Guard
  has clients). Query-log modes apply unchanged; `anonymous` redacts qnames
  but MAY keep client IPs (counters per device are the point) — document
  this explicitly in the config rustdoc; `off` stores nothing, as ever.
- WP9 sqlite: schema migrates v1→v2 adding nullable `client` column
  (migration test mandatory). New API `GET /v0/clients?hours=24` → per-client
  totals/blocked (empty + explanatory field when log_clients off).
- Dashboard: a Clients tab appearing only when the API reports the feature
  on; shows per-client counts. Router-guidance page (static text per
  os-integration knowledge: "point your router's DHCP DNS at <this
  machine's LAN IPs>"), listing the configured bind addrs.

## 4. Docs

`docs/network-guard.md`: how to enable (config), router DHCP DNS pointers,
static-IP/DHCP-reservation advice, the trade-offs (laptop sleep = LAN DNS
outage — recommend an always-on box), and the privacy note (per-client
logging is off by default and what turning it on means for housemates).

## 5. Mandatory tests

Unit: validate() matrix (wildcard refused, loopback refused, enabled+empty
refused); QueryRecord client-field serde round-trip incl. absent field
(old records). Integration: daemon with network_guard bound to a second
loopback-reachable addr (use 127.0.0.1:0-style ephemeral on a DIFFERENT
loopback address where the platform allows, else a second ephemeral port
documented as the closest sandbox-safe approximation — be explicit about
what is and isn't proven); queries through the guard listener get answered
+ blocked identically to loopback; client recorded only when log_clients on;
sqlite v1→v2 migration preserves rows; /v0/clients shapes; API never binds
non-loopback even with network_guard on (assert bind addr).
E2E: `hush status` unchanged when disabled.

## 6. Exit criterion honesty

Architecture P3 says "replaces a Pi-hole." This WP delivers the mechanism
(LAN DNS + per-client stats + guidance); a multi-device live proof needs a
real LAN and is PENDING — say so in the run summary and leave a
`proof/network-guard-live.md` checklist for it.

## 7. Deliverable

Config + listeners + client stats + clients API + dashboard tab + docs.
Run summary per standards §7.
