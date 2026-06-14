# hushwarren — User Guide

**What it is:** network-level ad and tracker blocking for the machine it runs
on. A DNS sinkhole in pure Rust — like Pi-hole, minus the Pi, minus the Linux
requirement, minus the configuration. You install it once; it answers every
DNS query your machine makes, blocks the ones that belong to ad/tracker
domains, and encrypts the rest on their way to the upstream resolver.

**The one rule:** after installation you do *nothing*. No router settings, no
DNS numbers, no YAML. If you ever HAVE to configure something for the basics
to work, that's a bug.

---

## 1. What it does (out of the box, zero config)

| Area | Behavior |
|---|---|
| **Blocking** | Sinkholes ad/tracker domains using curated lists (OISD + Hagezi "balanced" preset, ~400k domains), refreshed daily. CNAME-cloaked trackers (first-party-looking domains hiding a tracker behind a CNAME) are caught by chain inspection. A packaged Hagezi snapshot means blocking works on first boot even with no network. |
| **Encrypted upstream** | Your DNS queries leave the machine encrypted: DoH3 (HTTP/3) to Cloudflare/Quad9 when reachable, DoH (HTTP/2) otherwise, plain DNS to your router only as last resort. Queries are padded (RFC 8467) to resist size-correlation snooping. |
| **Privacy hygiene** | Query logs live in RAM by default and a local SQLite file (7-day retention) — nothing ever leaves the machine. No telemetry, ever. DNS-rebinding protection rejects malicious answers that point public names at your private network (Tailscale and Plex are exempted). Firefox's built-in DoH steps aside automatically (canary) so the system path — hushwarren — does the filtering. |
| **Self-defense (the Sentinel)** | Transactional DNS takeover with verified rollback: if anything fails, your DNS is restored exactly as found. Detects captive portals (hotel Wi-Fi) and steps aside until you're through. Yields to VPNs that own DNS, resumes when they drop. A crash-loop breaker restores your DNS rather than leave you offline. Survives sleep/wake and network roaming. |
| **Honesty** | If a privacy feature can't deliver, it says so instead of pretending (e.g. iCloud Private Relay is *protected* by default — a blocklist is never allowed to silently disable Apple's privacy feature; only your explicit toggle can). |

## 2. How to install (macOS — the proven platform)

Either:

```bash
# Option A — the installer package (builds unsigned locally for now)
bash dist/macos/build-pkg.sh           # produces dist/_pkg/hushwarren-installer.pkg
open dist/_pkg/hushwarren-installer.pkg  # one admin prompt, then done

# Option B — the script
sudo bash dist/macos/install.sh
```

Both install the daemon (LaunchDaemon, auto-restarts, survives reboots), the
menu-bar tray, take over DNS transactionally, and verify blocking works
before declaring success. **Uninstall:** `sudo bash dist/macos/uninstall.sh`
— restores DNS exactly as found and removes every trace.

Linux (`dist/linux/` — .deb/.rpm via nfpm + systemd) and Windows
(`dist/windows/` — .msi via WiX + SCM service) are implemented and reviewed
but await their first live run on real machines; treat them as beta recipes.

## 3. Daily use

**Nothing.** That's the product. When you want to interact anyway:

- **Tray icon** (menu bar): green = filtering, amber = snoozed, grey =
  standing by (VPN/portal), red = needs attention. Menu: snooze 5 min/1 hour,
  resume, open dashboard.
- **Dashboard** (`hush dashboard` or the tray menu): status, **recently
  blocked with one-click Allow** (the answer to "this site just broke"),
  insights ("this device asked for doubleclick.net 4,112× this week"),
  list sources with attribution, privacy toggles explained.
- **CLI** (`hush`):

```text
hush status            state, rules count, blocked today, privacy line, active profile
hush snooze 5m         pause filtering (everything passes through), auto-resumes
hush snooze --resume   resume now
hush allow example.com permanent allowlist (one-click equivalent)
hush log               recent queries (respects your privacy mode)
hush lists             blocklist sources, freshness, attribution
hush dashboard         open the web UI (tokened URL, localhost only)
hush profile switch X  hot-swap config profile (work/home/strict)
hush takeover/restore  manual DNS point/restore (root; normally automatic)
```

## 4. Configuration (all optional)

Config lives at `<state-dir>/hushwarren.toml` (macOS:
`/Library/Application Support/hushwarren`). Everything has a working default.
The knobs that matter:

```toml
[lists]
preset = "balanced"        # minimal | balanced | strict | aggressive
extra_categories = []      # "telemetry-windows", "telemetry-samsung", "nsfw", ...
```

**List presets**, lightest to heaviest — heavier blocks more but is likelier to
break a site, so `balanced` is the default:

| Preset | Sources | Use it when |
|---|---|---|
| `minimal` | Hagezi Light | You want only the most certain ad/tracker hits, nothing borderline. |
| `balanced` *(default)* | OISD Small + Hagezi Multi | Ads gone, basically nothing breaks. The right choice for almost everyone. |
| `strict` | OISD Big + Hagezi Pro | More trackers/telemetry blocked; rare breakage. |
| `aggressive` | OISD Big + Hagezi Pro++ | Maximum coverage (incl. crash/error analytics like Bugsnag/Sentry, `adservice.google.com`, `ad.doubleclick.net`). Blocks ~everything on the d3ward ad-test, at a higher false-positive rate — expect to allowlist the occasional site. |

For full manual control set `preset = "custom"` and list your own
`[[lists.sources]]` (name + url) — e.g. Hagezi `ultimate` for a 100% d3ward
score. The chosen lists are fetched and recompiled on a daily refresh.

```toml
[privacy]
query_log = "full"         # full | anonymous (no domain names stored) | off
retain_days = 7            # local history window
cname_inspection = true    # catch cloaked trackers
rebind_protection = true   # block private-IP answers for public names
doh_padding = true         # RFC 8467 query padding
block_doh_bypass = false   # gated: force apps with built-in DoH back to system DNS
block_private_relay = false # gated: disable iCloud Private Relay (ethics: off)

[upstream]
preset = "default"         # default (Cloudflare→Quad9) | mullvad
h3 = true                  # DoH3 first, h2 fallback

[network_guard]            # opt-in: protect the whole LAN (Pi-hole mode)
enabled = false
bind = []                  # e.g. ["192.168.1.10"] — then point your router's
                           # DHCP DNS here (see docs/network-guard.md)
log_clients = false        # per-device stats (household decision)
mdns_insight = false       # name devices ("Living-room TV") in the dashboard

[inbound_tls]              # opt-in: serve DoT/DoQ to other devices
enabled = false
```

Profiles: drop full config files in `<state-dir>/profiles/<name>.toml` and
`hush profile switch <name>` — lists/privacy changes apply live; the response
tells you honestly which settings need a restart.

## 5. What it deliberately does NOT do

DNS-scope honesty (claims beyond DNS are how privacy products lose trust):
no URL-parameter stripping, no cookie/fingerprint defense, no content
inspection, no defense against apps with hardcoded-IP DoH (that's firewall
territory), no DHCP server (a competing DHCP server can take a LAN down —
deferred by design, use your router's DHCP-DNS setting instead).

## 6. Status (2026-06-12)

All planned phases (P0–P4) and the full privacy roadmap (Tiers 1–2 + ODoH,
DoH3, padding, rebind protection, ECH integrity) are code-complete,
Opus-reviewed, and gate-verified (809 tests). Live-proven on macOS: all 12
zero-touch scenarios on a real machine, plus real-internet proofs of every
upstream rung and the dashboard. Pending real-world verification: Linux and
Windows live runs, package smoke-installs in CI, and code signing
(certificates required). Until packages are signed, macOS Gatekeeper will
warn on the unsigned .pkg.
