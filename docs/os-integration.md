# OS Integration — DNS takeover, services, installers

Status: **draft v0.1**

All OS-specific behavior lives in `hush-daemon`'s `platform::{macos,linux,windows}`
modules behind the `PlatformDns` trait (architecture §4). This doc is the ground
truth for what each implementation does and why.

---

## 1. Capability matrix

| Concern | macOS | Linux | Windows |
|---|---|---|---|
| Service manager | LaunchDaemon (`/Library/LaunchDaemons/io.hushwarren.daemon.plist`), `KeepAlive` | systemd unit, `Restart=always`, `WatchdogSec` + `sd_notify` | Windows service via `windows-service` crate, SCM recovery actions |
| Bind :53 privilege | None needed ≥ 10.14 (unprivileged low-port bind allowed); run as root LaunchDaemon anyway for DNS-write rights | Dedicated `hushwarren` user + `AmbientCapabilities=CAP_NET_BIND_SERVICE` — **no root** | LocalSystem (needed for `SetInterfaceDnsSettings`); SCM handles bind |
| Read current DNS | `SCDynamicStore` (system-configuration crate) — distinguishes DHCP vs manual | resolver regime detection (§3) | `GetAdaptersAddresses` + per-interface registry `NameServer` (empty ⇒ DHCP) |
| Write DNS | `networksetup -setdnsservers <service> 127.0.0.1` per network service; restore with `Empty` (= back to DHCP) or prior manual list | per-regime (§3) | `Set-DnsClientServerAddress`-equivalent via netioapi/registry per interface; empty list restores DHCP |
| Network-change events | `SCNetworkReachability` / SCDynamicStore notifications (sleep/wake via IOKit power notes) | netlink (`rtnetlink`) for iface/route; D-Bus signals from NetworkManager/resolved when present | `NotifyIpInterfaceChange` + `NotifyNetworkConnectivityHint` |
| VPN signature | new `utun*` iface + DNS keys claimed by another process in SCDynamicStore | `wg*`/`tun*` iface or resolved per-link DNS owned by VPN | new TAP/Wintun iface w/ DNS, often w/ NRPT rules |
| Tray | menu-bar extra (`tray-icon`), LaunchAgent login item | `StatusNotifierItem` (KDE/GNOME w/ extension; degrade: headless + dashboard) | system tray (first-class), Run-key login item |
| Installer | `.pkg` (productbuild), signed + notarized; preinstall snapshot, postinstall takeover | `.deb`/`.rpm` (cargo-dist) + `curl \| sh` fallback; postinst takeover | `.msi` (WiX via cargo-wix), signed; custom action takeover |
| Uninstaller | uninstall `.pkg`/script: restore → unload → remove | `prerm`: restore → disable | MSI uninstall custom action: restore → SCM remove |
| State dir | `/Library/Application Support/hushwarren/` | `/var/lib/hushwarren/` | `C:\ProgramData\hushwarren\` |

## 2. macOS specifics

- `networksetup` operates on **network services** (Wi-Fi, Ethernet, …), not raw
  interfaces — enumerate via `-listallnetworkservices`, apply to all enabled ones,
  and re-apply when services appear (new Wi-Fi networks don't create services, but
  adapters do).
- Restore semantics: `networksetup -setdnsservers "Wi-Fi" Empty` returns the
  service to DHCP. The snapshot must record per-service either `DHCP` or the
  explicit prior list — the two restore paths differ.
- The takeover-verify step must tolerate mDNSResponder quirks: macOS caches
  aggressively; canary checks use unique random subdomains of a test zone to dodge
  caches.
- Notarization + hardened runtime are mandatory for distribution (P2); the .pkg
  postinstall runs the takeover transaction as root and must be idempotent (pkg
  re-installs happen).

## 3. Linux — the resolver-regime problem

Linux has no single "the DNS setting." Detection ladder at startup and on every
network change, then act per regime:

| Regime | Detect | Takeover | Restore |
|---|---|---|---|
| **systemd-resolved** (Ubuntu/Fedora default) | `/etc/resolv.conf` symlinks to `../run/systemd/resolve/stub-resolv.conf` (stub 127.0.0.53) | Drop-in `/etc/systemd/resolved.conf.d/hushwarren.conf`: `DNS=127.0.0.1`, `Domains=~.`; leave the stub in place (apps → stub → us). No fight over resolv.conf | remove drop-in, `systemctl restart systemd-resolved` |
| **NetworkManager, no resolved** | NM running, resolv.conf NM-managed | NM conf.d drop-in `dns=none` + write resolv.conf `nameserver 127.0.0.1` | remove drop-in, let NM regenerate |
| **Plain resolv.conf** | neither of the above | atomic-replace resolv.conf (keep original at `resolv.conf.hushwarren-prev`); set immutable bit only as opt-in (some tools rewrite it) | move prev back |
| **resolvconf/openresolv** | `resolvconf` binary owns the file | register as a resolvconf provider with top priority | deregister |

- Port-53 conflicts: detect `systemd-resolved`'s stub (127.0.0.53 — fine, different
  IP), `dnsmasq` (NM dns=dnsmasq mode), and docker's embedded resolver. We bind
  127.0.0.1 specifically, so conflicts are rarer than "is something on
  0.0.0.0:53" — the PREPARE step checks our exact addresses.
- Headless servers are a real Linux audience: tray optional, `hush` CLI +
  dashboard are the full interface. (This is also the Network Guard host shape.)

## 4. Windows specifics

- DNS is **per-interface**. Set on all connected interfaces (v4: `127.0.0.1`,
  v6: `::1`) and on interface-arrival events. Empty server list restores DHCP;
  snapshot records prior static lists where present.
- **Port-53 squatters** (the famous Windows papercut): Internet Connection Sharing
  (ICS) service, Hyper-V/WSL2 NAT (`HNS`), Docker Desktop. PREPARE enumerates the
  owner via `GetExtendedUdpTable`; the installer offers the documented remedy for
  ICS (stop+disable, it's almost never used) and otherwise binds loopback only —
  HNS binds specific vEthernet IPs, so loopback usually coexists. Test-matrix #12
  covers this.
- Smart-App-Control / Defender reputation: unsigned new binaries that rewrite DNS
  look like malware (because malware does exactly this). EV/OV code-signing from
  day one of public distribution; this is a ship blocker, not polish.
- NRPT (Name Resolution Policy Table) rules from corporate VPNs override interface
  DNS — the VPN detector must read NRPT and yield (zero-touch-ux §4) rather than
  conclude "drift."

## 5. Shipping pipeline (P2)

- `cargo-dist` for the build matrix (mac universal2, linux x86_64/aarch64
  musl-static, windows x86_64), per-OS packaging on top (productbuild / WiX /
  nfpm-style deb+rpm).
- Release artifacts: installer per OS + standalone static binaries (the
  homelab/server crowd installs those directly).
- Update channel (P2.5): tray checks a static JSON over HTTPS, offers download —
  never auto-applies (a self-updating DNS daemon is a trust problem until we've
  earned it; revisit with signed deltas later).
- Package-manager presence when stable: Homebrew cask, winget, AUR — each must
  drive the same install/uninstall contracts (takeover in post-install hooks).
