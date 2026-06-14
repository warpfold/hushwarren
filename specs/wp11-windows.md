# WP11 — Windows platform (Sentinel port)

P2 deliverable (architecture §10 P2 "Windows port"; os-integration.md §1, §4
Windows column). Binding: `specs/standards.md`. Mirrors the Linux pattern
(WP-Linux, `platform/linux.rs`): pure logic host-testable, side effects
cfg-gated. Live-proven on a real Windows 11 machine (see §4 and
`proof/zero-touch-evidence-windows.md`).

## 1. DNS takeover (`platform/windows.rs`, new)

- Mechanism: per-interface registry values
  `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}\NameServer`
  (comma-separated static list; empty string ⇒ DHCP) and the Tcpip6 analog
  for IPv6, then `ipconfig /flushdns`. Shell out to `reg query`/`reg add`
  (locale-stable keys/values — do NOT parse localized `netsh` output; this
  is the localization hazard, document it) and enumerate interfaces +
  friendly names via
  `powershell -NoProfile -Command "Get-NetAdapter | ConvertTo-Json"` or
  `Get-DnsClientServerAddress … | ConvertTo-Json` (JSON = locale-stable).
  Parse JSON with serde_json (already in tree? verify; it's permissive).
  NO new windows-API crates for the DNS path — shell-out keeps the pattern
  identical to macos.rs/linux.rs.
- Snapshot maps to the existing `DnsSnapshot`/`ServiceDns` model: service =
  interface friendly name + GUID; setting = Dhcp | Static{servers}. Reuse
  the `linux_regime`-style additive-field precedent ONLY if something extra
  is genuinely needed (GUID can ride in the service string — prefer that).
- `point_at_self` = set NameServer to `127.0.0.1` (v4) and `::1` (v6 key) on
  all active adapters; `restore` = exact inverse from snapshot; root check ⇒
  Administrator check (`net session` succeeds or whoami /groups contains
  S-1-5-32-544 — pick one, document); NeedsRoot before any side effect.
- **Live-proof correction (Windows 11):** *reading* current DNS via `reg query`
  is fine, but *writing* DNS via `reg add` is NOT — it updates the stored
  registry value (so `Get-DnsClientServerAddress` reports the new server) yet
  does **not** notify the running TCP/IP stack, so the live resolver keeps using
  the old (DHCP) server and the sinkhole is silently bypassed. `apply_setting`
  therefore writes via `Set-DnsClientServerAddress -InterfaceIndex …`
  (`-ServerAddresses`/`-ResetServerAddresses`), which writes the same registry
  values **and** notifies the stack. Its parameters are locale-invariant, so the
  localization hazard above is unchanged. See
  `proof/zero-touch-evidence-windows.md` and `raw-windows/diag2.txt`.

## 2. Service (SCM)

- Dep (cfg windows only): `windows-service` (architecture names it; verify
  license via cargo deny — it's in the lockfile graph even on mac).
- `hushd` gains a cfg(windows) service entry point (`--service` dispatch,
  SCM control handler mapping stop/shutdown to the existing
  CancellationToken path) + `hushd service install/uninstall` verbs writing
  the SCM registration (auto-start, recovery: restart). Keep
  the non-Windows build byte-identical.
- **Live-proof corrections (Windows 11):**
  - Account is **LocalSystem** (`account_name: None`), NOT LocalService. The
    Sentinel must continuously rewrite `HKLM\…\Tcpip{,6}\…\NameServer` (drift
    re-arm), whose default ACL grants write only to Administrators/SYSTEM;
    LocalService cannot, so autonomous re-arm silently failed. LocalSystem
    matches the macOS/Linux daemon (root). Proven by S7.
  - `recovery: restart` is implemented via `update_failure_actions` (escalating
    1 s/2 s/5 s, reset 1 day). The service must be created with
    `SERVICE_CHANGE_CONFIG | SERVICE_START` — a restart action lets the SCM
    *start* the service, so the START right is required or the call fails with a
    winapi error. Proven by S2 and `raw-windows/02-sc-qfailure.txt`.

## 3. Watcher bits

`sentinel/watch.rs`: cfg(windows) interface scan via the same
Get-NetAdapter JSON (prefixes: `wintun`, `tap`, `tun`, plus
InterfaceDescription matching "WireGuard|OpenVPN|Tailscale" — keep the
shared prefix matcher; extend it only additively).

## 4. Constraints & verification

- Pure functions (JSON parsing → adapter list, registry-output parsing,
  snapshot mapping, restore-plan derivation) compile and unit-test on ALL
  hosts (this dev box is macOS) — same discipline as linux.rs.
- Cross-target: `cargo clippy -p hush-daemon --lib --target x86_64-pc-windows-msvc -- -D warnings`
  (expect ring/aws-lc build-script failure like the Linux cross-check — if C
  toolchain blocks it, fall back to `cargo check` variants and report
  exactly what could and could not be proven).
- Live proof on real Windows: **DONE** (Windows 11, `DESKTOP-8F22VJI`). Runner:
  `proof/win-live-proof.ps1` (self-restoring); evidence:
  `proof/zero-touch-evidence-windows.md`. `PASS: S1 S2 S7 S10`. The original
  `proof/run-zero-touch-proof.ps1` skeleton is superseded by `win-live-proof.ps1`.

## 5. Mandatory tests

Unit: adapter-JSON parsing (incl. localized-name adapters, disabled
adapters filtered); reg-query output parsing (NameServer present/empty);
snapshot round-trip incl. GUID-bearing service names; restore-plan per
setting; admin-check string parsing. Integration: existing MockPlatform
sentinel suite must pass unchanged (transaction logic untouched).

## 6. Deliverable

`platform/windows.rs` + mod.rs wiring (`native()` returns WindowsDns on
windows), service entry, watch.rs branch, proof skeleton. Run summary per
standards §7 with an honest "verified vs pending" table.
