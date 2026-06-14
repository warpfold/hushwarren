# Zero-Touch UX — the Sentinel specification

Status: **draft v0.1**

"User does nothing after install" is not a UI document — it is a **reliability
engineering** document. The UI's job is to be ignorable; the Sentinel's job is to
make that safe. This spec defines every situation where a naive DNS interceptor
would demand user action, and what hushwarren does instead.

The prime directive inherits from architecture P1:

> **Failure degrades to "ads come back," never to "internet gone."**

---

## 1. The takeover transaction

Pointing a machine's DNS at a resolver that isn't ready — or that later dies — is
how you take a user offline. DNS takeover is therefore **transactional**:

```
PREPARE   bind 127.0.0.1:53 + [::1]:53 (port-53 conflict check first)
          load blocklist (packaged snapshot if first run)
SELF-TEST resolve canaries THROUGH OUR OWN LISTENER:
            allowed name  → must return real records (proves upstream path)
            blocked name  → must return 0.0.0.0  (proves decision engine)
SNAPSHOT  record current per-interface DNS (incl. "DHCP-provided" as a distinct
          state vs "manually set to X" — restore must reproduce either exactly)
COMMIT    rewrite DNS on every active interface (v4 AND v6)
VERIFY    resolve canaries through the SYSTEM path (i.e., as apps will)
ROLLBACK  any step fails → restore snapshot, log, surface one tray notification
          ("hushwarren couldn't start — your internet is untouched")
```

The snapshot is persisted to the state dir **before** COMMIT, fsynced, so even a
power cut mid-takeover is recoverable at next boot. `restore` is idempotent and is
the first thing both the uninstaller and the crash-recovery path call.

The same transaction runs at: install, boot, wake-from-sleep verification, and
re-arm after snooze/VPN/portal — it is *the* primitive, written once, tested hard.

## 2. Crash safety — the dead-man's switch

If `hushd` dies while system DNS points at 127.0.0.1, the machine has no DNS.
Layered defense, in order of engagement:

1. **Service-manager restart** (first line): launchd `KeepAlive`, systemd
   `Restart=always` + `WatchdogSec` (daemon pets via `sd_notify`), Windows SCM
   recovery actions. Covers crashes in < 2 s; user never notices.
2. **Crash-loop breaker** (second line): the daemon counts its own abnormal
   restarts (state-dir breadcrumb). On the 3rd abnormal restart within 5 minutes it
   **restores the DNS snapshot, disarms, and idles** — internet works, ads return,
   tray shows one notification ("protection paused after a problem — click to
   re-arm"). It does *not* keep flapping.
3. **Wedge guard** (third line): the breadcrumb protocol distinguishes "crashed"
   from "cleanly stopped," so a daemon that is killed-9, OOM-killed, or disabled by
   the service manager still gets DNS restored at the next boot by the service
   wrapper's pre-start check — and the OS keeps a non-loopback fallback long enough
   to fetch updates.

Design consequence: **restore-DNS must work without the daemon being healthy** — it
lives in a small, dependency-light code path callable by: daemon shutdown hook,
pre-start check, uninstaller, and `hush restore` (CLI escape hatch).

## 3. Captive portals (hotel / café / airport Wi-Fi)

The single most common way local DNS interception "breaks the laptop." Portals
hijack DNS to redirect you to a login page; if we answer DNS honestly, the user
sees timeouts instead of a login page and blames us.

**Detection.** The Sentinel watches for the portal signature on every network
change: probe the OS's own connectivity-check endpoints
(`captive.apple.com`, `connectivitycheck.gstatic.com/generate_204`,
`msftconnecttest.com/connecttest.txt`) *via the DHCP-provided resolver*. A 302 / 
unexpected body / NXDOMAIN-for-known-good ⇒ portal in front of us.

**Response — step aside, then step back:**

1. Enter **portal mode**: pass-through ALL queries to the DHCP resolver unfiltered
   (do NOT restore system DNS — flapping settings while the OS's own portal
   detector is also probing causes races; we stay in the path but become
   transparent).
2. The OS's native captive-portal sheet pops as normal; user logs in like always
   (this is "user does nothing *extra*" — the portal itself is unavoidable).
3. Re-probe every 5 s; when probes come back clean, run SELF-TEST and re-arm
   filtering. Tray dot: grey → green. No notification needed.
4. Timebox: if a portal signature persists > 15 min with user traffic flowing,
   assume a portal-like-but-broken network and stay transparent (P1 over purity).

## 4. VPN coexistence

VPN clients rewrite DNS to their own resolvers (corporate split-horizon names only
resolve there). Fighting them breaks work laptops; that's a uninstall-grade sin.

- **Detect:** interface watcher sees utun/wg/tap interfaces or a DNS change we
  didn't write (settings drift, §6) where the new server is on a VPN interface.
- **Yield:** enter transparent pass-through; do NOT rewrite settings back. Tray
  shows grey "standing by (VPN active)". Filtering of the VPN's DNS is off —
  correctness over coverage for corporate names.
- **Resume:** VPN interface goes away → takeover transaction re-runs → green dot.
- Future (P4, opt-in only): filter-in-front-of-VPN for personal VPNs, since it
  risks split-horizon breakage it will never be default.

## 5. Sleep / wake / network roaming

Every wake and every SSID change re-runs, in order: port-53 sanity → portal probe →
VPN check → VERIFY (canaries through system path) → repair if drifted. This loop is
the Sentinel's heartbeat; it is rate-limited and silent. The DHCP-resolver entry in
the snapshot is refreshed per-network (it's our Do53 fallback and portal probe path).

## 6. Settings drift

Other software (VPN installers, "network repair" tools, IT scripts, the user
poking System Settings) will overwrite DNS. Policy: **repair quietly, but respect
intent.**

- Drift to a VPN resolver → §4 (yield).
- Drift to DHCP/empty (typical "reset by other software") → silently re-arm.
- Drift to an explicit third-party resolver (someone deliberately set 8.8.8.8) →
  respect it, go grey, one notification with "re-enable" action. Guessing wrong
  here in either direction is a support ticket; the explicit-set case is rare and
  deliberate enough to warrant the single prompt.

## 7. Snooze & "a site broke"

The escape valve that prevents uninstalls. Reachable in ≤ 2 clicks, never asks for
config:

- **Tray → Snooze** (5 min / 30 min / until I resume): decision engine passes
  through; resolver keeps resolving (stopping it would violate P1). Auto re-arm;
  tray dot amber while snoozed.
- **Tray → Open dashboard → Recently blocked**: reverse-chronological blocked
  domains with one-click **Allow**. The flow for "checkout button does nothing" is:
  snooze → finish checkout → open recently-blocked → allow the one domain → done.
  No log-diving, no syntax.
- Allow rules are suffix-scoped (`allow example-cdn.com` covers subdomains) and
  win over every blocklist (architecture §5).

## 8. The visible surface (deliberately tiny)

**Tray/menu-bar icon** — the entire ambient UI:

| Dot | Meaning |
|---|---|
| 🟢 | Filtering; tooltip shows "12,403 blocked this week" |
| 🟡 | Snoozed (auto re-arms) |
| ⚪ | Standing by: VPN / portal / explicit user DNS |
| 🔴 | Needs attention (crash-loop breaker fired) — the ONLY state that ever notifies more than once |

Menu: Snooze ▸ · Open dashboard · Pause protection · Quit (quits tray only; the
service keeps running — protection ≠ the icon. "Pause protection" is the verb that
actually disarms, wired through `POST /snooze`).

**Dashboard** (browser tab on localhost, token-auth): counters + sparkline ·
recently blocked w/ Allow · allowlist management · list sources + freshness +
attribution · query log (toggle) · an Advanced page (upstream choice, block action,
Network Guard) that 95% of users never open — and never need to.

**Notifications budget:** zero in steady state. One per: failed takeover,
crash-loop disarm, explicit-DNS yield. Anything chattier erodes the trust that
lets users forget we exist.

## 9. Install & uninstall contracts

**Install** (one admin prompt, per-OS mechanics in
[`os-integration.md`](os-integration.md)):
service registered + started → takeover transaction → tray registered as login
item → menu bar shows green within seconds of the installer closing. First
blocklist is the packaged snapshot — blocking works offline, immediately; freshen
happens in background.

**Uninstall** is a first-class feature, not an afterthought (trust: "easy to fully
remove" is why people accept "runs as a system service"): stop tray → `restore`
(the dependency-light path, §2) → verify resolution via system path → unregister
service → remove binaries + state (offer to keep allowlist for reinstall). Leaves
the machine bit-for-bit as found w.r.t. DNS.

## 10. Sentinel test matrix (P1 exit gate)

Automatable on CI runners/VMs where possible; the rest scripted-manual per OS:

| # | Scenario | Pass condition |
|---|---|---|
| 1 | Install on clean VM | green dot, ads blocked, no prompts beyond installer |
| 2 | `kill -9 hushd` ×1 | restart < 2 s, no user-visible gap |
| 3 | `kill -9` ×3 in 5 min (poisoned config) | breaker: DNS restored, internet OK, single notification |
| 4 | Reboot during takeover COMMIT | boot-time pre-start check restores or completes; never offline |
| 5 | Hotel-portal simulation (NXDOMAIN-hijack + 302) | portal sheet appears, login works, auto re-arm ≤ 10 s after clear |
| 6 | WireGuard + corp-style split DNS up/down | grey while up, internal names resolve, green ≤ 5 s after down |
| 7 | Third-party app rewrites DNS to DHCP | silent re-arm ≤ 5 s |
| 8 | User sets 8.8.8.8 manually | grey + exactly one notification; no fight |
| 9 | Sleep 24 h → wake on new SSID | correct state ≤ 5 s, zero notifications |
| 10 | Uninstall | DNS bit-identical to pre-install snapshot; no files left |
| 11 | Offline first boot | packaged lists active; blocking works with no network |
| 12 | Port 53 squatted (mDNSResponder edge / ICS / docker-proxy) | installer detects, resolves or aborts cleanly pre-COMMIT with internet untouched |
