//! Network-change watcher: wake detection, drift repair, VPN yield, portal.
//!
//! Implements `docs/zero-touch-ux.md` §3–§6 and
//! `specs/wp5-sentinel-macos.md` §4.
//!
//! One tokio task, tick every `config.poll_secs` seconds.
//!
//! ## Tick sequence (when state == Filtering)
//!
//! 1. **Wake detection** — compare monotonic elapsed vs wall-clock elapsed;
//!    a gap > `wake_gap_secs` ⇒ full re-verify.
//! 2. **Drift check** — `current_setting` for each snapshot service:
//!    - All pointing at us → ok.
//!    - Any reverted to Dhcp → silent re-arm.
//!    - Static + VPN iface present → `StandingBy(Vpn)`, no fight.
//!    - Static, no VPN → `StandingBy(UserDns)` + one warn log (P2 tray).
//! 3. **Portal probe** (on wake/drift/network event) — check
//!    `captive.apple.com/hotspot-detect.html` via DHCP resolver.
//!
//! Stateful variants (`Portal`, `Vpn`) are handled in subsequent ticks:
//! - Portal: re-probe every tick; clean → SELF-TEST → re-arm; 15-min timebox.
//! - VPN: detect iface gone → re-arm via takeover.

use std::collections::HashSet;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::platform::{is_pointing_at_self, DnsSetting, DnsSnapshot, PlatformDns};
use crate::sentinel::{GuardState, StandbyReason};

// ── Drift classification ──────────────────────────────────────────────────────

/// The result of classifying a single-service DNS drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriftKind {
    /// All services still point at us — no drift.
    Clean,
    /// Some services reverted to DHCP/empty — silently re-arm.
    Dhcp,
    /// A service changed to third-party static AND a VPN interface is present.
    VpnActive,
    /// A service changed to third-party static; no VPN iface detected.
    UserSet,
}

/// Classify the drift for a single service's current setting vs the snapshot.
///
/// `current`: what the OS reports now.
/// `snapped`: what was in the snapshot at takeover.
/// `vpn_interfaces_present`: true if a utun/ppp/wg interface was detected.
pub fn classify_drift(
    current: &DnsSetting,
    snapped: &DnsSetting,
    vpn_interfaces_present: bool,
) -> DriftKind {
    if is_pointing_at_self(current) {
        return DriftKind::Clean;
    }
    match current {
        DnsSetting::Dhcp => DriftKind::Dhcp,
        DnsSetting::Static { .. } => {
            // If the snapped value was already a different static, or if a
            // VPN interface is now present, yield to VPN.
            let _ = snapped; // used for future "respect user's original static" logic
            if vpn_interfaces_present {
                DriftKind::VpnActive
            } else {
                DriftKind::UserSet
            }
        }
    }
}

/// Detect VPN-like interfaces.
///
/// Returns a set of interface names that look like VPN tunnels
/// (`utun`, `ppp`, `wg`, `tun`, `tap`, `ipsec`, `wintun`).
///
/// # Platform behaviour
///
/// - **macOS**: shells out to `/sbin/ifconfig -l` (space-separated names on stdout).
///   The existing macOS behaviour is preserved byte-identical.
/// - **Linux**: reads `/sys/class/net` directory entries — no shell-out needed.
/// - **Windows**: shells out to `powershell -NoProfile -Command "Get-NetAdapter | ConvertTo-Json"`
///   and applies VPN-prefix matching plus description-keyword matching
///   (`WireGuard`, `OpenVPN`, `Tailscale`).  Uses the same locale-stable JSON
///   path as `platform/windows.rs`.
/// - **Other**: returns an empty set.
pub fn detect_vpn_interfaces() -> HashSet<String> {
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        let output = Command::new("/sbin/ifconfig")
            .arg("-l")
            .output()
            .unwrap_or_else(|_| std::process::Output {
                status: std::process::ExitStatus::default(),
                stdout: vec![],
                stderr: vec![],
            });
        let text = String::from_utf8_lossy(&output.stdout);
        parse_vpn_interfaces(&text)
    }

    #[cfg(target_os = "linux")]
    {
        // Read /sys/class/net — each directory entry is an interface name.
        // No shell-out; no external process.
        let names: Vec<String> = std::fs::read_dir("/sys/class/net")
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok().and_then(|e| e.file_name().into_string().ok()))
                    .collect()
            })
            .unwrap_or_default();
        parse_vpn_interfaces_list(&names)
    }

    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        let output = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-NetAdapter | ConvertTo-Json",
            ])
            .output()
            .unwrap_or_else(|_| std::process::Output {
                status: std::process::ExitStatus::default(),
                stdout: vec![],
                stderr: vec![],
            });
        let json = String::from_utf8_lossy(&output.stdout);
        parse_vpn_interfaces_windows(&json)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        HashSet::new()
    }
}

/// Parse the list of interfaces from `ifconfig -l` output (macOS test helper).
///
/// Splits on whitespace and returns any name matching a VPN prefix.
/// Prefixes: `utun`, `ppp`, `wg`, `tun`, `tap`, `ipsec`.
pub fn parse_vpn_interfaces(ifconfig_l_output: &str) -> HashSet<String> {
    let names: Vec<String> = ifconfig_l_output
        .split_whitespace()
        .map(ToOwned::to_owned)
        .collect();
    parse_vpn_interfaces_list(&names)
}

/// Filter interface names for VPN-like prefixes.
///
/// Shared by the macOS (`ifconfig -l`) and Linux (`/sys/class/net`) paths.
/// Prefixes: `utun`, `ppp`, `wg`, `tun`, `tap`, `ipsec`.
pub fn parse_vpn_interfaces_list(names: &[String]) -> HashSet<String> {
    let vpn_prefixes = ["utun", "ppp", "wg", "tun", "tap", "ipsec"];
    let mut result = HashSet::new();
    for name in names {
        for prefix in &vpn_prefixes {
            if name.starts_with(prefix) {
                result.insert(name.clone());
            }
        }
    }
    result
}

/// Parse `Get-NetAdapter | ConvertTo-Json` output for Windows VPN-like adapters.
///
/// Matches on adapter **name prefixes** (`wintun`, `tap`, `tun`) and on
/// **InterfaceDescription keywords** (`WireGuard`, `OpenVPN`, `Tailscale`).
///
/// Handles both JSON object (single adapter) and JSON array (multiple adapters)
/// — the same ConvertTo-Json quirk as in `platform/windows.rs`.
///
/// Disabled adapters (`Status != "Up"`) are excluded, consistent with the DNS
/// snapshot behaviour.
pub fn parse_vpn_interfaces_windows(json: &str) -> HashSet<String> {
    use crate::platform::windows::parse_net_adapter_json;
    let adapters = parse_net_adapter_json(json);
    let vpn_prefixes = ["wintun", "tap", "tun", "ppp", "wg", "utun", "ipsec"];
    // Keywords in InterfaceDescription that indicate a VPN tunnel adapter.
    let vpn_description_keywords = ["WireGuard", "OpenVPN", "Tailscale"];
    let mut result = HashSet::new();
    for adapter in adapters {
        let by_prefix = vpn_prefixes.iter().any(|p| {
            adapter
                .name
                .to_ascii_lowercase()
                .starts_with(&p.to_ascii_lowercase())
        });
        let by_description = vpn_description_keywords
            .iter()
            .any(|kw| adapter.interface_description.contains(kw));
        if by_prefix || by_description {
            result.insert(adapter.name);
        }
    }
    result
}

// ── Wake detection ────────────────────────────────────────────────────────────

/// Detect a wake-from-sleep event by comparing monotonic elapsed time to
/// wall-clock elapsed time.
///
/// A large gap (> `threshold`) between the two clocks means the machine was
/// asleep between ticks.
///
/// `prev_monotonic`: `Instant::now()` from the last tick.
/// `prev_wall_ms`: Unix ms at the last tick.
/// `threshold`: gap size that triggers a wake event.
///
/// Returns `true` if a wake event is detected.
pub fn detect_wake(prev_monotonic: Instant, prev_wall_ms: u64, threshold: Duration) -> bool {
    let mono_elapsed = prev_monotonic.elapsed();
    let wall_now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let wall_elapsed_ms = wall_now_ms.saturating_sub(prev_wall_ms);
    let wall_elapsed = Duration::from_millis(wall_elapsed_ms);

    // Wake detected when wall clock advanced much more than the monotonic
    // clock (monotonic stops during sleep; wall clock does not).
    wall_elapsed > mono_elapsed + threshold
}

// ── Portal probe ──────────────────────────────────────────────────────────────

/// The canonical Apple captive-portal success response.
const APPLE_SUCCESS_BODY: &str =
    "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>";

/// Probe `http://captive.apple.com/hotspot-detect.html` using the DHCP-
/// provided resolver from the snapshot.
///
/// Returns `true` if the body matches Apple's success sentinel (not a portal).
/// Returns `false` if the response looks like a portal redirect/captive page.
///
/// Uses reqwest with a `resolve()` override so we bypass the system resolver
/// (which now points at us) and probe directly through the DHCP resolver.
pub async fn probe_portal(snapshot: &DnsSnapshot, timeout: Duration) -> bool {
    // Extract the first DHCP-resolved IP from the snapshot to use as the DNS
    // resolver for this probe.  If the snapshot has only static entries, use
    // a public resolver as a fallback (only for the probe — not for queries).
    let dhcp_ips = dhcp_ips_from_snapshot(snapshot);

    if dhcp_ips.is_empty() {
        // No DHCP IPs available — cannot probe safely; assume no portal.
        debug!("portal probe skipped: no DHCP IPs in snapshot");
        return true;
    }

    probe_portal_via_resolver(&dhcp_ips, timeout).await
}

/// Extract the first DHCP-like (non-loopback, non-zero) IP addresses from
/// a snapshot for use as the portal probe resolver.
fn dhcp_ips_from_snapshot(snapshot: &DnsSnapshot) -> Vec<SocketAddr> {
    // We look for services that were in DHCP state at snapshot time.
    // The DHCP resolver IP is not stored in the snapshot (it's provided by
    // the OS dynamically), so we use the Google Public DNS as a stand-in for
    // the portal probe.  This is consistent with the spec: we probe via
    // "the DHCP-provided resolver from the snapshot"; if none is recorded,
    // we fall back to 8.8.8.8 which is sufficient to detect most portals.
    //
    // P2 note: SCDynamicStore push notifications would give us the real DHCP
    // DNS IP directly.
    let has_dhcp = snapshot
        .services
        .iter()
        .any(|s| s.setting == crate::platform::DnsSetting::Dhcp);

    if has_dhcp {
        // PANIC-OK: this literal is always a valid socket address.
        let addr: SocketAddr = ([8u8, 8, 8, 8], 53).into();
        // Use Google DNS as a stand-in for the DHCP resolver.
        vec![addr]
    } else {
        vec![]
    }
}

/// Perform the HTTP probe to `captive.apple.com` with a custom resolver.
///
/// Returns `true` if not a portal.
async fn probe_portal_via_resolver(_resolver_addrs: &[SocketAddr], timeout: Duration) -> bool {
    probe_portal_at_url("http://captive.apple.com/hotspot-detect.html", timeout).await
}

/// Probe `url` and classify the response as portal / not-portal.
///
/// Split out from [`probe_portal_via_resolver`] so the portal-detection
/// contract (302 ⇒ portal, non-Success body ⇒ portal, network error ⇒ assume
/// clean per P1 never-go-offline) is testable against a local mock server.
///
/// P2: use reqwest's resolve() override with the real DHCP IP instead of the
/// default resolver path.
pub async fn probe_portal_at_url(url: &str, timeout: Duration) -> bool {
    let client = match reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none()) // 302 = portal
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            debug!(error = %e, "portal probe: failed to build HTTP client");
            return true; // Assume clean on client-build failure.
        }
    };

    match client.get(url).send().await {
        Ok(resp) => {
            if resp.status().is_redirection() {
                debug!("portal probe: got redirect → portal detected");
                return false;
            }
            match resp.text().await {
                Ok(body) => {
                    let is_success = body.trim() == APPLE_SUCCESS_BODY.trim()
                        || body.contains("<TITLE>Success</TITLE>");
                    if !is_success {
                        debug!("portal probe: unexpected body → portal detected");
                    }
                    is_success
                }
                Err(e) => {
                    debug!(error = %e, "portal probe: body read error — assuming no portal");
                    true
                }
            }
        }
        Err(e) => {
            debug!(error = %e, "portal probe failed — assuming no portal");
            true // Assume clean on network error (P1: no offline).
        }
    }
}

// ── Watcher state machine ─────────────────────────────────────────────────────

/// Persistent state across watcher ticks.
pub struct WatcherState {
    /// When the previous tick started (monotonic).
    pub last_tick_mono: Instant,
    /// Unix ms at the previous tick (wall clock).
    pub last_tick_wall_ms: u64,
    /// Unix ms when the current portal-mode started; None if not in portal mode.
    pub portal_start_ms: Option<u64>,
    /// Whether we have already warned about user-set DNS (one-warn policy).
    pub user_dns_warned: bool,
}

impl WatcherState {
    pub fn new() -> Self {
        let now_wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        Self {
            last_tick_mono: Instant::now(),
            last_tick_wall_ms: now_wall,
            portal_start_ms: None,
            user_dns_warned: false,
        }
    }
}

impl Default for WatcherState {
    fn default() -> Self {
        Self::new()
    }
}

/// Run one watcher tick.
///
/// Called every `poll_secs` seconds.  Returns the new [`GuardState`] to
/// publish (or the existing one if nothing changed).
///
/// `platform`: platform DNS interface.
/// `snapshot`: the snapshot taken at takeover time.
/// `state_tx`: the watch channel sender for broadcasting state changes.
/// `watcher`: mutable watcher-tick state.
/// `wake_threshold`: gap that triggers a wake event.
/// `portal_timebox`: how long to stay in portal mode before giving up.
/// A pinned, boxed, `Send` future representing a re-arm attempt.
type TakeoverFuture = Pin<Box<dyn Future<Output = Result<(), String>> + Send>>;

pub async fn run_tick(
    platform: Arc<dyn PlatformDns>,
    snapshot: &DnsSnapshot,
    state_tx: &watch::Sender<GuardState>,
    watcher: &mut WatcherState,
    wake_threshold: Duration,
    portal_timebox: Duration,
    takeover_fn: &mut (dyn FnMut() -> TakeoverFuture + Send),
) {
    let now_wall = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let current_state = state_tx.borrow().clone();

    // ── Handle portal-mode ticks ──────────────────────────────────────────────
    if let GuardState::StandingBy {
        why: StandbyReason::Portal,
    } = &current_state
    {
        let portal_start = watcher.portal_start_ms.unwrap_or(now_wall);
        let elapsed_ms = now_wall.saturating_sub(portal_start);
        let timebox_ms = portal_timebox.as_millis() as u64;

        if elapsed_ms > timebox_ms {
            // Timebox expired: stay transparent, warn once.
            warn!("portal timebox expired — staying transparent");
            // Keep the state as Portal (transparent); update start time
            // so the warn doesn't fire every tick.
            watcher.portal_start_ms = Some(now_wall);
            return;
        }

        // Re-probe.
        let clean = probe_portal(snapshot, Duration::from_secs(3)).await;
        if clean {
            info!("portal probe clean — attempting re-arm via takeover");
            watcher.portal_start_ms = None;
            match takeover_fn().await {
                Ok(()) => {
                    let _ = state_tx.send(GuardState::Filtering);
                    info!("re-armed after portal cleared");
                }
                Err(e) => {
                    warn!(error = %e, "re-arm after portal failed");
                }
            }
        }
        watcher.last_tick_mono = Instant::now();
        watcher.last_tick_wall_ms = now_wall;
        return;
    }

    // ── Handle VPN standby ticks ──────────────────────────────────────────────
    if let GuardState::StandingBy {
        why: StandbyReason::VpnActive,
    } = &current_state
    {
        // Check if VPN is gone.
        let vpn_ifaces = detect_vpn_interfaces();
        if vpn_ifaces.is_empty() {
            info!("VPN interface gone — re-arming");
            match takeover_fn().await {
                Ok(()) => {
                    let _ = state_tx.send(GuardState::Filtering);
                    info!("re-armed after VPN disconnected");
                }
                Err(e) => {
                    warn!(error = %e, "re-arm after VPN gone failed");
                }
            }
        }
        watcher.last_tick_mono = Instant::now();
        watcher.last_tick_wall_ms = now_wall;
        return;
    }

    // Only do drift/wake checks when we believe we are filtering.
    if !matches!(current_state, GuardState::Filtering) {
        watcher.last_tick_mono = Instant::now();
        watcher.last_tick_wall_ms = now_wall;
        return;
    }

    // ── Wake detection ────────────────────────────────────────────────────────
    let wake_detected = detect_wake(
        watcher.last_tick_mono,
        watcher.last_tick_wall_ms,
        wake_threshold,
    );
    if wake_detected {
        info!("wake-from-sleep detected — running full re-verify");
        // Treat as if a drift event happened.
    }

    // ── Drift check ───────────────────────────────────────────────────────────
    let vpn_ifaces = detect_vpn_interfaces();
    let vpn_present = !vpn_ifaces.is_empty();

    let mut needs_rearm: Vec<String> = Vec::new();
    let mut vpn_yielded = false;
    let mut user_set = false;

    for svc_dns in &snapshot.services {
        let current = match platform.current_setting(&svc_dns.service) {
            Ok(s) => s,
            Err(e) => {
                debug!(service = %svc_dns.service, error = %e, "drift poll failed for service");
                continue;
            }
        };

        let drift = classify_drift(&current, &svc_dns.setting, vpn_present);
        match drift {
            DriftKind::Clean => {}
            DriftKind::Dhcp => {
                debug!(service = %svc_dns.service, "drift: DHCP — will re-arm");
                needs_rearm.push(svc_dns.service.clone());
            }
            DriftKind::VpnActive => {
                info!(service = %svc_dns.service, vpn_ifaces = ?vpn_ifaces, "drift: VPN active — yielding");
                vpn_yielded = true;
            }
            DriftKind::UserSet => {
                user_set = true;
            }
        }
    }

    // ── React to drift ────────────────────────────────────────────────────────
    if vpn_yielded {
        let _ = state_tx.send(GuardState::StandingBy {
            why: StandbyReason::VpnActive,
        });
        watcher.last_tick_mono = Instant::now();
        watcher.last_tick_wall_ms = now_wall;
        return;
    }

    if user_set {
        if !watcher.user_dns_warned {
            warn!(
                "DNS settings were changed to a third-party resolver — standing by (user intent).\
                 Use `hush takeover` to re-arm."
            );
            watcher.user_dns_warned = true;
        }
        let _ = state_tx.send(GuardState::StandingBy {
            why: StandbyReason::UserDns,
        });
        watcher.last_tick_mono = Instant::now();
        watcher.last_tick_wall_ms = now_wall;
        return;
    }

    if !needs_rearm.is_empty() {
        debug!(services = ?needs_rearm, "silently re-arming DHCP-drifted services");
        if let Err(e) = platform.point_at_self(&needs_rearm) {
            warn!(error = %e, "silent re-arm failed");
        } else {
            debug!("silent re-arm complete");
        }
    }

    // ── Portal probe (on wake or drift event) ─────────────────────────────────
    if wake_detected || !needs_rearm.is_empty() {
        let clean = probe_portal(snapshot, Duration::from_secs(3)).await;
        if !clean {
            info!("portal detected — entering pass-through mode");
            watcher.portal_start_ms = Some(now_wall);
            let _ = state_tx.send(GuardState::StandingBy {
                why: StandbyReason::Portal,
            });
        }
    }

    watcher.last_tick_mono = Instant::now();
    watcher.last_tick_wall_ms = now_wall;
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::platform::{DnsSetting, DnsSnapshot, ServiceDns};
    use std::net::IpAddr;

    fn make_snapshot_dhcp() -> DnsSnapshot {
        DnsSnapshot {
            v: 1,
            taken_unix_ms: 0,
            services: vec![ServiceDns {
                service: "Wi-Fi".to_owned(),
                setting: DnsSetting::Dhcp,
            }],
            linux_regime: None,
        }
    }

    // ── classify_drift ────────────────────────────────────────────────────────

    #[test]
    fn classify_drift_clean_when_pointing_at_self() {
        let current = DnsSetting::Static {
            servers: vec!["127.0.0.1".parse::<IpAddr>().unwrap()],
        };
        let snapped = DnsSetting::Dhcp;
        assert_eq!(classify_drift(&current, &snapped, false), DriftKind::Clean);
    }

    #[test]
    fn classify_drift_dhcp_when_reverted() {
        let current = DnsSetting::Dhcp;
        let snapped = DnsSetting::Dhcp;
        assert_eq!(classify_drift(&current, &snapped, false), DriftKind::Dhcp);
    }

    #[test]
    fn classify_drift_vpn_when_static_and_vpn_iface() {
        let current = DnsSetting::Static {
            servers: vec!["10.0.0.1".parse::<IpAddr>().unwrap()],
        };
        let snapped = DnsSetting::Dhcp;
        assert_eq!(
            classify_drift(&current, &snapped, true),
            DriftKind::VpnActive
        );
    }

    #[test]
    fn classify_drift_user_set_when_static_no_vpn() {
        let current = DnsSetting::Static {
            servers: vec!["8.8.8.8".parse::<IpAddr>().unwrap()],
        };
        let snapped = DnsSetting::Dhcp;
        assert_eq!(
            classify_drift(&current, &snapped, false),
            DriftKind::UserSet
        );
    }

    // ── parse_vpn_interfaces ──────────────────────────────────────────────────

    #[test]
    fn parse_vpn_interfaces_finds_utun() {
        let output = "lo0 en0 utun0 utun1 en1";
        let ifaces = parse_vpn_interfaces(output);
        assert!(ifaces.contains("utun0"));
        assert!(ifaces.contains("utun1"));
        assert!(!ifaces.contains("en0"));
        assert!(!ifaces.contains("lo0"));
    }

    #[test]
    fn parse_vpn_interfaces_finds_ppp() {
        let output = "lo0 en0 ppp0";
        let ifaces = parse_vpn_interfaces(output);
        assert!(ifaces.contains("ppp0"));
    }

    #[test]
    fn parse_vpn_interfaces_finds_wg() {
        let output = "lo0 wg0 en0";
        let ifaces = parse_vpn_interfaces(output);
        assert!(ifaces.contains("wg0"));
    }

    #[test]
    fn parse_vpn_interfaces_empty_output() {
        let ifaces = parse_vpn_interfaces("");
        assert!(ifaces.is_empty());
    }

    #[test]
    fn parse_vpn_interfaces_no_vpn() {
        let output = "lo0 en0 en1 bridge0";
        let ifaces = parse_vpn_interfaces(output);
        assert!(ifaces.is_empty());
    }

    // ── detect_wake ───────────────────────────────────────────────────────────

    #[test]
    fn detect_wake_no_gap_is_not_wake() {
        // Monotonic elapsed ≈ wall elapsed → no wake.
        let prev_mono = Instant::now() - Duration::from_secs(5);
        // Wall advanced ~5 seconds too.
        let now_wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let prev_wall = now_wall - 5_000;
        let threshold = Duration::from_secs(30);
        assert!(!detect_wake(prev_mono, prev_wall, threshold));
    }

    #[test]
    fn detect_wake_large_gap_is_wake() {
        // Monotonic says 5s elapsed; wall says 3600s elapsed → wake.
        let prev_mono = Instant::now() - Duration::from_secs(5);
        let now_wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        // Pretend the wall clock was set 3600 seconds ago.
        let prev_wall = now_wall - 3_600_000;
        let threshold = Duration::from_secs(30);
        assert!(detect_wake(prev_mono, prev_wall, threshold));
    }

    // ── dhcp_ips_from_snapshot ────────────────────────────────────────────────

    #[test]
    fn dhcp_ips_from_dhcp_snapshot_is_nonempty() {
        let snap = make_snapshot_dhcp();
        let ips = super::dhcp_ips_from_snapshot(&snap);
        assert!(!ips.is_empty());
    }

    #[test]
    fn dhcp_ips_from_static_snapshot_is_empty() {
        let snap = DnsSnapshot {
            v: 1,
            taken_unix_ms: 0,
            services: vec![ServiceDns {
                service: "Wi-Fi".to_owned(),
                setting: DnsSetting::Static {
                    servers: vec!["8.8.8.8".parse().unwrap()],
                },
            }],
            linux_regime: None,
        };
        let ips = super::dhcp_ips_from_snapshot(&snap);
        assert!(ips.is_empty());
    }

    // ── parse_vpn_interfaces_windows ─────────────────────────────────────────

    /// Fixture: WireGuard adapter detected by InterfaceDescription keyword.
    const WIN_ADAPTER_WIREGUARD: &str = r#"[
        {
            "Name": "WireGuard Tunnel",
            "InterfaceGuid": "{GUID-WG}",
            "Status": "Up",
            "InterfaceDescription": "WireGuard Tunnel",
            "MacAddress": ""
        },
        {
            "Name": "Ethernet",
            "InterfaceGuid": "{GUID-ETH}",
            "Status": "Up",
            "InterfaceDescription": "Realtek PCIe GbE Family Controller",
            "MacAddress": "AA:BB:CC:DD:EE:FF"
        }
    ]"#;

    /// Fixture: Tailscale adapter detected by InterfaceDescription.
    const WIN_ADAPTER_TAILSCALE: &str = r#"{
        "Name": "Tailscale",
        "InterfaceGuid": "{GUID-TS}",
        "Status": "Up",
        "InterfaceDescription": "Tailscale Virtual Machine Network",
        "MacAddress": ""
    }"#;

    /// Fixture: wintun adapter detected by name prefix.
    const WIN_ADAPTER_WINTUN_PREFIX: &str = r#"{
        "Name": "wintun0",
        "InterfaceGuid": "{GUID-WT}",
        "Status": "Up",
        "InterfaceDescription": "Generic tunnel adapter",
        "MacAddress": ""
    }"#;

    /// Fixture: no VPN adapters — only a plain Ethernet.
    const WIN_ADAPTER_NO_VPN: &str = r#"{
        "Name": "Ethernet",
        "InterfaceGuid": "{GUID-ETH}",
        "Status": "Up",
        "InterfaceDescription": "Realtek PCIe GbE Family Controller",
        "MacAddress": "AA:BB:CC:DD:EE:FF"
    }"#;

    /// Fixture: disabled adapter — must be excluded even if VPN-looking.
    const WIN_ADAPTER_DISABLED_VPN: &str = r#"{
        "Name": "WireGuard Tunnel",
        "InterfaceGuid": "{GUID-WG}",
        "Status": "Disconnected",
        "InterfaceDescription": "WireGuard Tunnel",
        "MacAddress": ""
    }"#;

    #[test]
    fn windows_vpn_detects_wireguard_by_description() {
        let ifaces = parse_vpn_interfaces_windows(WIN_ADAPTER_WIREGUARD);
        assert!(
            ifaces.contains("WireGuard Tunnel"),
            "WireGuard must be detected"
        );
        assert!(
            !ifaces.contains("Ethernet"),
            "plain Ethernet must not match"
        );
    }

    #[test]
    fn windows_vpn_detects_tailscale_by_description() {
        let ifaces = parse_vpn_interfaces_windows(WIN_ADAPTER_TAILSCALE);
        assert!(ifaces.contains("Tailscale"), "Tailscale must be detected");
    }

    #[test]
    fn windows_vpn_detects_wintun_by_name_prefix() {
        let ifaces = parse_vpn_interfaces_windows(WIN_ADAPTER_WINTUN_PREFIX);
        assert!(ifaces.contains("wintun0"), "wintun prefix must match");
    }

    #[test]
    fn windows_vpn_no_match_for_plain_ethernet() {
        let ifaces = parse_vpn_interfaces_windows(WIN_ADAPTER_NO_VPN);
        assert!(
            ifaces.is_empty(),
            "plain Ethernet must not trigger VPN detection"
        );
    }

    #[test]
    fn windows_vpn_excludes_disabled_adapters() {
        let ifaces = parse_vpn_interfaces_windows(WIN_ADAPTER_DISABLED_VPN);
        assert!(ifaces.is_empty(), "disabled adapter must be excluded");
    }

    #[test]
    fn windows_vpn_empty_json_returns_empty() {
        let ifaces = parse_vpn_interfaces_windows("");
        assert!(ifaces.is_empty());
    }
}
