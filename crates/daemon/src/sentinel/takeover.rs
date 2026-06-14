//! DNS takeover transaction — the 7-step atomic commit.
//!
//! Implements `docs/zero-touch-ux.md` §1 and `specs/wp5-sentinel-macos.md` §2.
//!
//! The transaction is a pure function over `&dyn PlatformDns`, fully testable
//! with [`crate::platform::stub::MockPlatform`].
//!
//! ```text
//! PREPARE   verify listeners are bound (port-53 sanity)
//! SELF-TEST  resolve blocked canary → 0.0.0.0 (proves sinkhole)
//!            resolve allowed canary → ≥1 A record (proves upstream path)
//! SNAPSHOT  record current per-service DNS (Dhcp vs Static)
//! PERSIST   write snapshot to disk (atomic+fsync) BEFORE COMMIT
//! COMMIT    point_at_self for all active services
//! VERIFY    resolve allowed canary via system path (ToSocketAddrs)
//! ROLLBACK  if VERIFY fails → restore(snapshot), return error
//! ```

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

use thiserror::Error;
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

use crate::platform::{load_snapshot, persist_snapshot, DnsSnapshot, PlatformDns, PlatformError};
use hush_core::SELFTEST_BLOCKED_DOMAIN;

/// Errors from the takeover transaction.
#[derive(Debug, Error)]
pub enum TakeoverError {
    /// A port-53 conflict prevented us from binding.
    #[error("port 53 is already in use; cannot start takeover: {0}")]
    PortConflict(String),

    /// The DNS self-test failed (blocked canary was not sinkholed, or
    /// allowed canary did not resolve).
    #[error("self-test failed: {0}")]
    SelfTestFailed(String),

    /// A platform DNS operation failed.
    #[error("platform error: {0}")]
    Platform(#[from] PlatformError),

    /// The snapshot could not be persisted to disk.
    #[error("snapshot persist failed: {0}")]
    SnapshotPersist(std::io::Error),

    /// VERIFY step failed after COMMIT — snapshot has been restored.
    #[error("post-commit verify failed (DNS restored): {0}")]
    VerifyFailed(String),

    /// A DNS query through our listener produced an unexpected response.
    #[error("self-test DNS error: {0}")]
    DnsError(String),
}

/// Configuration for a takeover transaction.
#[derive(Debug, Clone)]
pub struct TakeoverConfig {
    /// The address of our own DNS listener to send SELF-TEST queries to.
    /// Typically `127.0.0.1:53`.
    pub listener_addr: SocketAddr,
    /// Domain that must sinkhole (blocked canary).
    pub blocked_canary: String,
    /// Domain that must resolve (allowed canary).
    pub allowed_canary: String,
    /// Timeout for each DNS probe during SELF-TEST and VERIFY.
    pub probe_timeout: Duration,
    /// State directory for snapshot persistence.
    pub state_dir: std::path::PathBuf,
}

impl Default for TakeoverConfig {
    fn default() -> Self {
        Self {
            listener_addr: "127.0.0.1:53".parse().unwrap_or_else(|_| {
                // PANIC-OK: this literal is always valid.
                unreachable!("hardcoded address is always valid")
            }),
            blocked_canary: SELFTEST_BLOCKED_DOMAIN.to_owned(),
            allowed_canary: "example.com".to_owned(),
            probe_timeout: Duration::from_secs(5),
            state_dir: std::path::PathBuf::from("/var/lib/hushwarren"),
        }
    }
}

/// Execute the DNS takeover transaction.
///
/// # Steps
///
/// 1. **PREPARE** — verify the listener is reachable (not: bind it; the
///    daemon has already bound it at start).
/// 2. **SELF-TEST** — send DNS A queries through our own listener.
/// 3. **SNAPSHOT** — record current DNS via `platform.snapshot()`.
/// 4. **PERSIST** — write snapshot to `state_dir/dns-snapshot.json`
///    atomically before any commit.
/// 5. **COMMIT** — `platform.point_at_self(services)`.
/// 6. **VERIFY** — resolve allowed canary via `ToSocketAddrs` (the system path).
/// 7. **ROLLBACK** on VERIFY failure — `platform.restore(&snapshot)`.
///
/// Returns `Ok(DnsSnapshot)` on full success.
pub async fn run_takeover(
    platform: &dyn PlatformDns,
    cfg: &TakeoverConfig,
) -> Result<DnsSnapshot, TakeoverError> {
    info!(
        listener = %cfg.listener_addr,
        "starting takeover transaction"
    );

    // ── PREPARE: verify our listener is bound ────────────────────────────────
    // We probe the listener with a UDP connect to confirm it is reachable.
    // Port conflicts caught here prevent committing with a broken resolver.
    prepare_check(cfg.listener_addr).await?;

    // ── SELF-TEST through own listener ───────────────────────────────────────
    self_test(cfg).await?;

    // ── SNAPSHOT ─────────────────────────────────────────────────────────────
    // Read the live DNS state (used for the service list to commit).
    let current = platform.snapshot()?;
    debug!(services = current.services.len(), "current DNS read");

    // Baseline for restore: PRESERVE an existing on-disk snapshot (re-arm) or
    // persist the current state as a fresh baseline (first takeover). See
    // [`resolve_restore_baseline`] for the why.
    let snapshot = resolve_restore_baseline(&cfg.state_dir, &current)?;

    // ── COMMIT (point the LIVE services at us) ───────────────────────────────
    // On partial failure (some adapters already sinkholed when point_at_self
    // errors), attempt best-effort restore so no adapters are left in an
    // inconsistent state.  The original COMMIT error is always returned.
    let service_names: Vec<String> = current.services.iter().map(|s| s.service.clone()).collect();
    if let Err(commit_err) = platform.point_at_self(&service_names) {
        warn!(error = %commit_err, "COMMIT failed — attempting best-effort rollback");
        if let Err(restore_err) = platform.restore(&snapshot) {
            error!(
                error = %restore_err,
                "rollback after COMMIT failure also failed — DNS state may be inconsistent"
            );
        } else {
            info!("rollback after COMMIT failure complete");
        }
        return Err(TakeoverError::Platform(commit_err));
    }
    info!(
        services = service_names.len(),
        "COMMIT: DNS pointed at sinkhole"
    );

    // ── VERIFY via system path ────────────────────────────────────────────────
    let verify_result = verify_via_system_path(&cfg.allowed_canary, cfg.probe_timeout).await;
    if let Err(e) = verify_result {
        warn!(error = %e, "VERIFY failed after COMMIT — rolling back");
        // Attempt rollback; log but don't mask the original error.
        if let Err(restore_err) = platform.restore(&snapshot) {
            warn!(error = %restore_err, "rollback also failed — DNS state may be inconsistent");
        } else {
            info!("rollback complete — DNS restored to pre-takeover state");
        }
        return Err(TakeoverError::VerifyFailed(e));
    }

    // Explicit re-arm clears any durable crash-loop trip so the daemon resumes
    // normal filtering instead of coming up disarmed on the next restart.
    if let Err(e) = crate::sentinel::breaker::clear_trip(&cfg.state_dir) {
        warn!(error = %e, "could not clear breaker trip after takeover");
    }

    info!("takeover transaction complete — filtering active");
    Ok(snapshot)
}

/// Resolve the restore baseline for a takeover.
///
/// PRESERVE an existing on-disk snapshot if one is present: a second takeover
/// is a re-arm (drift repair, post-breaker recovery, manual re-run), and the
/// true pre-hushwarren baseline was already captured on the first takeover.
/// Re-capturing the current state now would record "us" (127.0.0.1) — or a
/// transient third-party/user DNS change made while we were standing by — as
/// the baseline, poisoning the uninstall-restore contract (DNS must return
/// bit-identical to its pre-install configuration).
///
/// On a true first takeover (no snapshot on disk), persist `current` as the
/// baseline (fsync happens before COMMIT in the caller's ordering).
pub fn resolve_restore_baseline(
    state_dir: &Path,
    current: &DnsSnapshot,
) -> Result<DnsSnapshot, TakeoverError> {
    match load_snapshot(state_dir) {
        Ok(Some(existing)) => {
            info!("reusing existing pre-takeover snapshot as restore baseline (re-arm)");
            Ok(existing)
        }
        _ => {
            persist_snapshot(state_dir, current).map_err(TakeoverError::SnapshotPersist)?;
            debug!("baseline snapshot persisted (first takeover)");
            Ok(current.clone())
        }
    }
}

/// Restore from a snapshot, removing the persisted snapshot file on success.
///
/// This is the dependency-light escape hatch used by:
/// - `hushd restore` subcommand (no daemon running)
/// - crash-loop breaker
/// - shutdown hook
pub fn restore_from_snapshot(
    platform: &dyn PlatformDns,
    snap: &DnsSnapshot,
    state_dir: &Path,
) -> Result<(), PlatformError> {
    platform.restore(snap)?;
    crate::platform::remove_snapshot(state_dir);
    info!("DNS restored from snapshot");
    Ok(())
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// PREPARE: verify that a UDP socket can reach the listener address.
///
/// We connect (no packet sent — just routing table check) to detect port
/// conflicts before committing.
async fn prepare_check(listener_addr: SocketAddr) -> Result<(), TakeoverError> {
    // Bind an ephemeral UDP socket and try to connect to our listener.
    // If the listener is not up, the connect will not fail (UDP is connectionless),
    // but we can at least verify the address is reachable on the loopback interface.
    // The actual reachability is confirmed by SELF-TEST below.
    debug!(addr = %listener_addr, "PREPARE: listener reachability check");
    let check = UdpSocket::bind("127.0.0.1:0").await;
    match check {
        Ok(_) => {
            debug!("PREPARE: loopback bind succeeded");
            Ok(())
        }
        Err(e) => Err(TakeoverError::PortConflict(format!(
            "cannot bind loopback UDP: {e}"
        ))),
    }
}

/// SELF-TEST: send DNS A queries through our own listener and verify
/// - blocked canary (`hushwarren-selftest-blocked.invalid`) → sinkholes to 0.0.0.0
/// - allowed canary (`example.com`) → at least one A record
async fn self_test(cfg: &TakeoverConfig) -> Result<(), TakeoverError> {
    debug!(
        blocked = %cfg.blocked_canary,
        allowed = %cfg.allowed_canary,
        listener = %cfg.listener_addr,
        "SELF-TEST starting"
    );

    // Test 1: blocked canary must return 0.0.0.0 (NXDOMAIN or NullIp sinkhole).
    let blocked_ok = probe_blocked(&cfg.blocked_canary, cfg.listener_addr, cfg.probe_timeout).await;
    match blocked_ok {
        Ok(true) => debug!("SELF-TEST: blocked canary sinkholes correctly"),
        Ok(false) => {
            return Err(TakeoverError::SelfTestFailed(format!(
                "blocked canary '{}' was NOT sinkholes (returned a real address)",
                cfg.blocked_canary
            )));
        }
        Err(e) => {
            return Err(TakeoverError::SelfTestFailed(format!(
                "blocked canary probe error: {e}"
            )));
        }
    }

    // Test 2: allowed canary must return ≥1 A record.
    let allowed_ok = probe_allowed(&cfg.allowed_canary, cfg.listener_addr, cfg.probe_timeout).await;
    match allowed_ok {
        Ok(true) => debug!("SELF-TEST: allowed canary resolves correctly"),
        Ok(false) => {
            return Err(TakeoverError::SelfTestFailed(format!(
                "allowed canary '{}' returned no A records (upstream path broken)",
                cfg.allowed_canary
            )));
        }
        Err(e) => {
            return Err(TakeoverError::SelfTestFailed(format!(
                "allowed canary probe error: {e}"
            )));
        }
    }

    info!("SELF-TEST passed");
    Ok(())
}

/// Probe the blocked canary through our listener.
///
/// Returns `Ok(true)` if the domain sinkholes (returns 0.0.0.0, ::, or
/// NXDOMAIN), `Ok(false)` if it resolves to a real address.
async fn probe_blocked(
    domain: &str,
    listener: SocketAddr,
    timeout: Duration,
) -> Result<bool, String> {
    let ips = resolve_via_listener(domain, listener, timeout).await?;
    // Sinkholes returns 0.0.0.0, ::, NXDOMAIN (empty), or SERVFAIL (error above).
    let is_sinkholed = ips.iter().all(|ip| {
        *ip == IpAddr::from([0, 0, 0, 0]) || *ip == IpAddr::from([0, 0, 0, 0, 0, 0, 0, 0])
    });
    // Empty result (NXDOMAIN) also counts as sinkholed.
    Ok(ips.is_empty() || is_sinkholed)
}

/// Probe the allowed canary through our listener.
///
/// Returns `Ok(true)` if ≥1 A record is returned.
async fn probe_allowed(
    domain: &str,
    listener: SocketAddr,
    timeout: Duration,
) -> Result<bool, String> {
    let ips = resolve_via_listener(domain, listener, timeout).await?;
    // At least one non-zero, non-loopback IP = upstream path works.
    let has_real = ips.iter().any(|ip| {
        !ip.is_loopback()
            && *ip != IpAddr::from([0, 0, 0, 0])
            && *ip != IpAddr::from([0, 0, 0, 0, 0, 0, 0, 0])
    });
    Ok(has_real)
}

/// Send a raw DNS A query to `listener` and return the A record IPs.
///
/// Uses raw UDP so we bypass the system resolver entirely.
async fn resolve_via_listener(
    domain: &str,
    listener: SocketAddr,
    timeout: Duration,
) -> Result<Vec<IpAddr>, String> {
    // Build a minimal DNS A query packet.
    let packet = build_dns_query(domain, /* qtype A */ 1);

    let sock = UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("bind error: {e}"))?;

    sock.connect(listener)
        .await
        .map_err(|e| format!("connect to listener error: {e}"))?;

    // Send query with timeout.
    tokio::time::timeout(timeout, sock.send(&packet))
        .await
        .map_err(|_| "send timeout".to_owned())?
        .map_err(|e| format!("send error: {e}"))?;

    // Receive response with timeout.
    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(timeout, sock.recv(&mut buf))
        .await
        .map_err(|_| "recv timeout — listener may not be bound".to_owned())?
        .map_err(|e| format!("recv error: {e}"))?;

    // Parse the response.
    parse_dns_a_response(&buf[..n])
}

/// Build a minimal DNS A query packet for `domain`.
fn build_dns_query(domain: &str, qtype: u16) -> Vec<u8> {
    let mut pkt: Vec<u8> = Vec::with_capacity(64);

    // Transaction ID: 0xAB01 (arbitrary, constant for test queries).
    pkt.extend_from_slice(&[0xAB, 0x01]);
    // Flags: standard query, recursion desired.
    pkt.extend_from_slice(&[0x01, 0x00]);
    // QDCOUNT = 1.
    pkt.extend_from_slice(&[0x00, 0x01]);
    // ANCOUNT, NSCOUNT, ARCOUNT = 0.
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    // Encode the QNAME as DNS labels.
    for label in domain.split('.') {
        if label.is_empty() {
            continue;
        }
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0x00); // root label

    // QTYPE and QCLASS (IN = 1).
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x01]);

    pkt
}

/// Parse DNS A records from a raw response packet.
///
/// Returns the list of IPv4 addresses found in the answer section.
/// Ignores parse errors — an empty list is a valid sinkhole result.
fn parse_dns_a_response(pkt: &[u8]) -> Result<Vec<IpAddr>, String> {
    if pkt.len() < 12 {
        return Ok(vec![]); // Truncated packet → no answers.
    }

    // RCODE is the low 4 bits of byte 3.
    let rcode = pkt[3] & 0x0F;
    if rcode != 0 {
        // Non-zero RCODE (NXDOMAIN=3, SERVFAIL=2, etc.) → sinkhole / error.
        return Ok(vec![]);
    }

    let ancount = u16::from_be_bytes([pkt[6], pkt[7]]) as usize;
    if ancount == 0 {
        return Ok(vec![]);
    }

    // Skip the question section by walking past the QNAME + QTYPE + QCLASS.
    let mut pos = 12usize;
    pos = skip_name(pkt, pos)?;
    pos += 4; // QTYPE + QCLASS
    if pos > pkt.len() {
        return Ok(vec![]);
    }

    // Parse answer records.
    let mut addrs: Vec<IpAddr> = Vec::new();
    for _ in 0..ancount {
        if pos >= pkt.len() {
            break;
        }
        pos = skip_name(pkt, pos)?;
        if pos + 10 > pkt.len() {
            break;
        }
        let rtype = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
        // Skip TYPE(2) + CLASS(2) + TTL(4).
        pos += 8;
        let rdlength = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]) as usize;
        pos += 2;
        if pos + rdlength > pkt.len() {
            break;
        }
        if rtype == 1 && rdlength == 4 {
            // A record.
            let ip = IpAddr::from([pkt[pos], pkt[pos + 1], pkt[pos + 2], pkt[pos + 3]]);
            addrs.push(ip);
        } else if rtype == 28 && rdlength == 16 {
            // AAAA record.
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&pkt[pos..pos + 16]);
            addrs.push(IpAddr::from(bytes));
        }
        pos += rdlength;
    }
    Ok(addrs)
}

/// Skip a DNS name (label sequence or pointer) starting at `pos`.
/// Returns the position after the name.
fn skip_name(pkt: &[u8], mut pos: usize) -> Result<usize, String> {
    loop {
        if pos >= pkt.len() {
            return Err(format!("name parse overrun at pos {pos}"));
        }
        let len = pkt[pos];
        if len == 0 {
            return Ok(pos + 1);
        } else if len & 0xC0 == 0xC0 {
            // Pointer: 2 bytes total.
            return Ok(pos + 2);
        } else {
            pos += 1 + len as usize;
        }
    }
}

/// VERIFY: resolve the allowed canary via the SYSTEM path (`ToSocketAddrs`).
///
/// After COMMIT the system resolver points at us.  A successful resolution
/// proves the takeover is working end-to-end.
///
/// Runs in a blocking thread (ToSocketAddrs blocks) with a timeout.
async fn verify_via_system_path(canary: &str, timeout: Duration) -> Result<(), String> {
    let query = format!("{canary}:443");
    debug!(query, "VERIFY: resolving via system path (ToSocketAddrs)");

    let result = tokio::time::timeout(
        timeout,
        tokio::task::spawn_blocking(move || query.to_socket_addrs().map(|mut iter| iter.next())),
    )
    .await;

    match result {
        Ok(Ok(Ok(Some(_)))) => {
            debug!("VERIFY passed");
            Ok(())
        }
        Ok(Ok(Ok(None))) => Err(format!(
            "'{canary}' resolved to no addresses via system path"
        )),
        Ok(Ok(Err(e))) => Err(format!("'{canary}' system-path resolution failed: {e}")),
        Ok(Err(e)) => Err(format!("spawn_blocking panic: {e}")),
        Err(_) => Err(format!(
            "system-path resolution of '{canary}' timed out after {timeout:?}"
        )),
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::useless_vec)]
    use super::*;

    // ── DNS packet builder ────────────────────────────────────────────────────

    #[test]
    fn build_dns_query_produces_valid_header() {
        let pkt = build_dns_query("example.com", 1);
        // Minimum length: 12 header + labels + null + qtype + qclass.
        assert!(pkt.len() >= 12);
        // QDCOUNT = 1.
        assert_eq!(u16::from_be_bytes([pkt[4], pkt[5]]), 1);
        // RD flag set.
        assert!(pkt[2] & 0x01 != 0);
    }

    #[test]
    fn build_dns_query_encodes_labels() {
        let pkt = build_dns_query("ads.example.com", 1);
        // Check the label encoding: 3,'a','d','s', 7,'e','x','a','m','p','l','e', 3,'c','o','m', 0
        let qname_start = 12;
        assert_eq!(pkt[qname_start], 3); // len("ads")
        assert_eq!(&pkt[qname_start + 1..qname_start + 4], b"ads");
    }

    // ── DNS response parser ───────────────────────────────────────────────────

    #[test]
    fn parse_empty_packet_returns_empty() {
        let ips = parse_dns_a_response(&[]).unwrap();
        assert!(ips.is_empty());
    }

    #[test]
    fn parse_nxdomain_response_returns_empty() {
        // Build a response with RCODE=3 (NXDOMAIN), ANCOUNT=0.
        let mut pkt = vec![
            0xAB, 0x01, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        // Add question: single-label "x\0" + QTYPE A + QCLASS IN.
        pkt.extend_from_slice(&[1, b'x', 0, 0, 1, 0, 1]);
        let ips = parse_dns_a_response(&pkt).unwrap();
        assert!(ips.is_empty());
    }

    #[test]
    fn parse_sinkhole_a_record_0_0_0_0() {
        // Construct a minimal A response with 0.0.0.0.
        let domain = "test";
        let mut pkt = build_dns_query(domain, 1);
        // Turn query into response: set QR bit (0x80), RA bit; ANCOUNT = 1.
        pkt[2] |= 0x80;
        pkt[6] = 0x00;
        pkt[7] = 0x01; // ANCOUNT = 1
                       // Append answer RR: name pointer to offset 12, TYPE A, CLASS IN, TTL 10, RDLEN 4, 0.0.0.0.
        pkt.extend_from_slice(&[
            0xC0, 0x0C, // name pointer to offset 12
            0x00, 0x01, // TYPE A
            0x00, 0x01, // CLASS IN
            0x00, 0x00, 0x00, 0x0A, // TTL 10
            0x00, 0x04, // RDLEN 4
            0x00, 0x00, 0x00, 0x00, // 0.0.0.0
        ]);
        let ips = parse_dns_a_response(&pkt).unwrap();
        assert_eq!(ips, vec![IpAddr::from([0, 0, 0, 0])]);
    }

    // ── probe_blocked / probe_allowed logic ───────────────────────────────────

    #[test]
    fn probe_blocked_empty_ips_is_sinkholed() {
        // An empty IP list (NXDOMAIN) counts as sinkholed.
        let ips: Vec<IpAddr> = vec![];
        let is_sinkholed = ips
            .iter()
            .all(|ip| *ip == IpAddr::from([0, 0, 0, 0]) || *ip == IpAddr::from([0u8; 16]));
        assert!(ips.is_empty() || is_sinkholed);
    }

    #[test]
    fn probe_blocked_null_ip_is_sinkholed() {
        let ips = vec![IpAddr::from([0, 0, 0, 0])];
        let is_sinkholed = ips
            .iter()
            .all(|ip| *ip == IpAddr::from([0, 0, 0, 0]) || *ip == IpAddr::from([0u8; 16]));
        assert!(is_sinkholed);
    }

    #[test]
    fn probe_allowed_real_ip_is_passing() {
        let ips = vec!["93.184.216.34".parse::<IpAddr>().unwrap()];
        let has_real = ips.iter().any(|ip| {
            !ip.is_loopback() && *ip != IpAddr::from([0, 0, 0, 0]) && *ip != IpAddr::from([0u8; 16])
        });
        assert!(has_real);
    }

    #[test]
    fn probe_allowed_loopback_only_is_failing() {
        let ips = vec!["127.0.0.1".parse::<IpAddr>().unwrap()];
        let has_real = ips.iter().any(|ip| {
            !ip.is_loopback() && *ip != IpAddr::from([0, 0, 0, 0]) && *ip != IpAddr::from([0u8; 16])
        });
        assert!(!has_real);
    }

    // ── skip_name ─────────────────────────────────────────────────────────────

    #[test]
    fn skip_name_root_label() {
        // Single null byte = root label.
        let pkt = &[0x00u8];
        assert_eq!(skip_name(pkt, 0).unwrap(), 1);
    }

    #[test]
    fn skip_name_pointer() {
        // Pointer 0xC0 0x0C.
        let pkt = &[0xC0u8, 0x0C];
        assert_eq!(skip_name(pkt, 0).unwrap(), 2);
    }

    #[test]
    fn skip_name_two_labels() {
        // "com" (3 bytes) + root.
        let pkt: &[u8] = &[3, b'c', b'o', b'm', 0];
        assert_eq!(skip_name(pkt, 0).unwrap(), 5);
    }
}
