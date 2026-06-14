<p align="center">
  <img src="icon.svg" alt="hushwarren logo" width="160" height="160" />
</p>

# hushwarren

**Network-level ad & tracker blocking that you install and then forget exists.**

A cross-platform DNS sinkhole in pure Rust. Like Pi-hole, minus the Pi, minus the Linux requirement, minus the configuration. One installer, zero setup.

---

## The one rule

> The user does **nothing** after installation. No router settings, no DNS numbers, no terminal, no YAML. Install → ads gone. Anything that violates this rule is a bug.

---

## What happens at each moment

| Moment | You | hushwarren |
|---|---|---|
| **Install** | Run the installer, approve one admin prompt | Installs a system service, starts the resolver, verifies it works, switches the machine's DNS to itself — transactionally, with rollback |
| **Daily use** | Nothing | Resolves all DNS locally, sinkholes ad/tracker domains, auto-updates blocklists daily, survives reboots |
| **Hotel / café Wi-Fi** | Join the network as usual | Detects the captive portal, steps aside, steps back in when the portal clears |
| **VPN turns on** | Nothing | Detects the VPN owns DNS, yields gracefully, resumes when the VPN drops |
| **Something breaks** | Click the tray icon → "Snooze 5 min" | Passes everything through, re-arms automatically |
| **Uninstall** | Run the uninstaller | Restores DNS exactly as found, removes every trace |

---

## Why not Pi-hole or AdGuard Home?

| | Pi-hole | AdGuard Home | **hushwarren** |
|---|---|---|---|
| Language | C / PHP | Go | Pure Rust |
| Requires dedicated box | ✅ yes | ❌ no | ❌ no |
| Requires Linux | ✅ yes | ❌ | ❌ |
| Protects laptops on any network | ❌ | ❌ | ✅ |
| Zero configuration | ❌ | ❌ | ✅ |
| Single static binary | ❌ | ❌ | ✅ |
| Encrypted upstream out of the box | ❌ (sidecar) | ✅ | ✅ |
| CNAME-cloaking inspection | optional | ✅ | ✅ |
| LAN / network-wide mode | ✅ | ✅ | ✅ opt-in |

The key difference: hushwarren's default mode protects *the machine it's installed on*, so laptops are first-class citizens and the protection travels with you to every network.

---

## Features

### Blocking
- **~400k domains blocked** out of the box — OISD Small + Hagezi `balanced` preset, refreshed daily
- **CNAME-cloaking inspection** — first-party-looking tracker domains that hide a real tracker behind a CNAME chain are caught and sinkholed
- **Four presets** (`minimal` → `balanced` → `strict` → `aggressive`) and a `custom` mode for full list control
- **Bundled first-run snapshot** so blocking works immediately, even offline

### Privacy
- **Encrypted upstream by default** — DoH3 (HTTP/3) to Cloudflare/Quad9 with HTTP/2 fallback; plain DNS used only as a last resort
- **Query padding** (RFC 8467) to resist size-correlation snooping
- **DNS-rebinding protection** — rejects malicious answers that point public names at your private network
- **RAM-first query log** — history lives in memory and a local SQLite file (7-day rolling window, configurable); nothing ever leaves the machine
- **No telemetry, ever**
- **Firefox DoH canary** — Firefox's built-in DoH steps aside automatically so the system path does the filtering

### Zero-touch guarantees (the Sentinel)
- **Transactional DNS takeover** — if anything fails during install, your DNS is restored exactly as found
- **Captive portal detection** — hotel/café Wi-Fi works; hushwarren steps aside until you're past the portal
- **VPN awareness** — yields when a VPN owns DNS, resumes when it drops
- **Drift re-arm** — monitors for DNS settings being changed by other software; silently re-arms on passive drift, gracefully yields (with one notification) if you've deliberately set a different resolver
- **Crash-loop breaker** — restores your DNS rather than leave you offline

### Controls (all optional — the product works without touching any of them)
- **Tray icon** — green (filtering) / amber (snoozed) / grey (yielded to VPN/portal) / red (needs attention)
- **Dashboard** — recently blocked with one-click Allow, privacy insights, blocklist attribution, per-toggle explanations
- **CLI** (`hush`) — `status`, `snooze`, `allow`, `log`, `lists`, `profile switch`, `dashboard`

### Advanced (opt-in)
- **Network Guard** — listen on the LAN interface to protect the whole household; per-client stats in the dashboard
- **DoT / DoQ inbound** — serve encrypted DNS to other devices
- **Multi-profile hot reload** — `work`, `home`, `strict` profiles swap live; most changes don't need a restart
- **Passive mDNS insight** — name devices ("Living-room TV") in the Network Guard dashboard

---

## Platform status

| Platform | Status |
|---|---|
| **macOS** | ✅ Live-proven — all 12 zero-touch scenarios pass on a real machine; unsigned `.pkg` installer builds and installs locally |
| **Windows 11** | ✅ Live-proven — full zero-touch flow (SCM service → transactional DNS takeover → sinkhole → crash-restart → drift re-arm → uninstall bit-clean) passes on a fresh machine |
| **Linux** | 🔶 Implemented, not yet live-proven on a real machine — treat as beta |

**Blocking effectiveness** (Windows 11, headless Edge, [d3ward ad-block test](https://d3ward.github.io/toolz/adblock)):

| List | Domains reached (lower = better) | Blocked |
|---|---|---|
| No blocking (baseline) | 124 / 131 | — |
| `balanced` (default) | **9 / 131** | 93% |
| Hagezi `ultimate` | **0 / 131** | 100% |

---

## Install

### macOS

```bash
# Option A — installer package (recommended)
bash dist/macos/build-pkg.sh
open dist/_pkg/hushwarren-installer.pkg   # one admin prompt, then done

# Option B — shell script
sudo bash dist/macos/install.sh
```

**Uninstall:** `sudo bash dist/macos/uninstall.sh` — restores your DNS exactly as found and removes every trace.

### Windows

```powershell
# MSI installer (WiX — build locally for now)
cargo build --release
# See dist/windows/ for the WiX recipe
```

### Linux

```bash
# .deb / .rpm via nfpm + systemd — build locally for now
sudo bash dist/linux/install.sh   # see dist/linux/ for recipes
```

> **Note:** Packages are not yet signed. macOS Gatekeeper will warn on the unsigned `.pkg`. Code signing is the next milestone before a public release.

---

## Building from source

```bash
# Prerequisites: Rust stable toolchain
cargo build --workspace --release
```

The workspace produces four binaries:

| Binary | Crate | Role |
|---|---|---|
| `hushd` | `daemon` | DNS server + Sentinel + control API |
| `hush` | `cli` | CLI control tool |
| `hush-tray` | `tray` | System tray / menu-bar app |
| *(library)* | `core` | Pure logic — decision engine, blocklist, config |

Quality gate (must pass before a PR):

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test --workspace   # 809 tests
cargo deny check licenses
```

---

## Daily use

**Nothing.** That's the product. When you want to interact anyway:

### Tray menu
Click the icon in your menu bar / system tray:
- **Snooze 5 min / 1 hour** — temporarily pass everything through (re-arms automatically)
- **Resume** — re-arm immediately
- **Open dashboard** — browser tab, localhost only, token-authenticated

### Dashboard
- **Recently blocked** with one-click Allow — the answer to "this site just broke"
- **Privacy insights** — "this device asked for `doubleclick.net` 4,112× this week"
- **Blocklist sources** with attribution and freshness
- **Privacy toggles** with plain-language explanations

### CLI

```
hush status              state, rule count, blocked today, active profile
hush snooze 5m           pause filtering; auto-resumes after 5 minutes
hush snooze --resume     re-arm immediately
hush allow example.com   permanent allowlist entry (equivalent to one-click Allow)
hush log                 recent queries (respects your privacy mode)
hush lists               blocklist sources, freshness, and attribution
hush dashboard           open the web UI
hush profile switch X    hot-swap a config profile (work / home / strict)
```

---

## Configuration

Config lives at `<state-dir>/hushwarren.toml`:
- macOS: `/Library/Application Support/hushwarren/hushwarren.toml`
- Windows: `C:\ProgramData\hushwarren\hushwarren.toml`
- Linux: `/var/lib/hushwarren/hushwarren.toml`

Everything has a working default. The knobs that matter:

```toml
[lists]
preset = "balanced"       # minimal | balanced | strict | aggressive | custom
extra_categories = []     # "telemetry-windows", "telemetry-samsung", "nsfw", "threat-intel", ...

[privacy]
query_log = "full"        # full | anonymous (no domain names stored) | off
retain_days = 7
cname_inspection = true
rebind_protection = true
doh_padding = true

[upstream]
preset = "default"        # default (Cloudflare → Quad9) | mullvad
h3 = true                 # DoH3 first, HTTP/2 fallback

[network_guard]           # opt-in: protect the whole LAN
enabled = false
bind = []                 # e.g. ["192.168.1.10"] — then point your router's DHCP DNS here
```

**Profiles:** drop full config files into `<state-dir>/profiles/<name>.toml` and switch live with `hush profile switch <name>`.

---

## Architecture

```
┌──────────────── user session ─────────────────┐
│  hush-tray (menu bar)    hush (CLI)            │
└──────────┬───────────────────────┬────────────┘
           │  localhost HTTP/token  │
┌──────────▼───────────────────────▼────────────┐
│  hushd (launchd / systemd / Windows SCM)       │
│                                                │
│  DNS engine (hickory)                          │
│    → Decision engine (fst blocklist)           │
│    → Upstream forwarder (DoH3 → DoH → Do53)    │
│                                                │
│  List pipeline  ·  Query log  ·  Control API   │
│                                                │
│  Sentinel                                      │
│    DNS configurator · network watcher          │
│    captive-portal probe · VPN detector         │
│    health self-test · takeover transactions    │
└────────────────────────────────────────────────┘
```

- The **decision engine** (`hush-core`) uses a compiled `fst::Set` over reversed-label domain keys — millions of domains in tens of MB, microsecond lookups, zero per-query allocation.
- The **Sentinel** is what distinguishes hushwarren from "hickory + a blocklist." It owns all zero-touch guarantees.
- The **control API** (axum, `127.0.0.1` only, token-authenticated) serves both the JSON API and the embedded dashboard SPA as a single binary — no separate web server.

---

## Contributing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) before opening a PR. Two things matter:

1. **The CLA** — include `I agree to the hushwarren CLA as stated in CONTRIBUTING.md.` in every PR description. PRs without it cannot be merged (it's what keeps the dual-license model legally sound for everyone).
2. **The engineering bar** — `cargo fmt --check && cargo clippy -D warnings && cargo test --workspace` must pass. The zero-touch product rule applies to every change: if a user has to configure something for the basics to work, it's a bug.

---

## License

**GPL-3.0-or-later.** Free to use anywhere, commercially included — but if you distribute a modified version, your changes must be published under the same terms. Improvements stay free for everyone; closed forks are not possible.

All *dependencies* are strictly permissive (MIT/Apache/BSD-class, enforced by `cargo deny` in CI), so hushwarren's own code is the only copyleft in the build.

The project is dual-licensed: the maintainer may offer hushwarren's code under separate commercial license terms. This is what the CLA enables. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
