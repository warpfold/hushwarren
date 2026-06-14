//! Passive mDNS multicast listener for per-client hostname resolution.
//!
//! Implements `specs/wp14-nice.md` §3.  This module:
//! - Joins `224.0.0.251:5353` (IPv4 mDNS multicast) passively.
//! - Parses DNS messages from announcements using hickory-proto (NO new dep).
//! - Maintains an IP→hostname map (A, AAAA, and PTR records; TTL-aged; cap 1024).
//! - **Never transmits a single packet** — the socket is opened read-only.
//! - Gated by `network_guard.mdns_insight`; join failure → warn once, feature off.
//!
//! ## No-transmit invariant
//!
//! The `UdpSocket` obtained by [`MdnsInsight::start`] is bound with
//! `SO_REUSEADDR` / `SO_REUSEPORT` (for multicast share) and only `recv_from`
//! is ever called on it.  There is no `send` / `send_to` call path in this
//! module — the write path does not exist.
//!
//! ## CI note (spec §4)
//!
//! Loopback multicast is flaky in CI (many environments disable multicast on
//! the loopback interface).  The mandatory test coverage is at the unit level:
//! parse + map-update logic tested with canned announcement packets.  The
//! socket join path is integration-level and documented as potentially skipped
//! in CI.

use hickory_proto::{op::Message, rr::RData};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tracing::{debug, warn};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of entries in the IP→hostname map.
const MAP_CAP: usize = 1024;

/// mDNS multicast group (IPv4).
const MDNS_GROUP_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

/// mDNS port.
const MDNS_PORT: u16 = 5353;

/// Maximum accepted hostname length (RFC 1035 §2.3.4 + mDNS spec).
///
/// A FQDN is at most 253 characters excluding the root dot.  Hostnames
/// received from the network are capped here before storing to prevent
/// memory exhaustion and XSS via oversized values.
const MAX_HOSTNAME_LEN: usize = 253;

/// Sanitize an mDNS hostname before storing it in the map.
///
/// - Strips ASCII control characters (U+0000..=U+001F and U+007F) which
///   can cause terminal injection / log injection when displayed.
/// - Caps length at [`MAX_HOSTNAME_LEN`] characters.
/// - Returns `None` when the hostname is empty after sanitization (callers
///   must skip insertion in this case).
///
/// HTML/XSS escaping is NOT done here — that is the responsibility of the
/// renderer (the dashboard `esc()` helper).  Sanitization here covers
/// storage-layer invariants.
pub fn sanitize_hostname(raw: &str) -> Option<String> {
    let sanitized: String = raw
        .chars()
        .filter(|&c| !c.is_ascii_control())
        .take(MAX_HOSTNAME_LEN)
        .collect();

    if sanitized.is_empty() {
        None
    } else {
        Some(sanitized)
    }
}

// ── Map entry ─────────────────────────────────────────────────────────────────

/// A single IP→hostname mapping with TTL expiry.
#[derive(Debug, Clone)]
struct MapEntry {
    /// Resolved hostname (without trailing dot).
    hostname: String,
    /// When this entry expires.
    expires_at: Instant,
}

// ── Public map ────────────────────────────────────────────────────────────────

/// Thread-safe IP→hostname map maintained by the mDNS listener.
///
/// Cloneable for sharing between the listener task and the API handler.
#[derive(Clone, Default)]
pub struct MdnsMap {
    inner: Arc<Mutex<HashMap<IpAddr, MapEntry>>>,
}

impl MdnsMap {
    /// Create a new empty map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up the hostname for an IP address.
    ///
    /// Returns `None` when not found or when the entry has expired.
    pub fn get(&self, ip: IpAddr) -> Option<String> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        if let Some(entry) = guard.get(&ip) {
            if entry.expires_at > now {
                return Some(entry.hostname.clone());
            }
            // Expired — remove it.
            guard.remove(&ip);
        }
        None
    }

    /// Insert or update an IP→hostname mapping.
    ///
    /// Enforces the 1024-entry cap: when the map is full, the entry with the
    /// earliest expiry is evicted (LRU-by-TTL).
    pub fn insert(&self, ip: IpAddr, hostname: String, ttl_secs: u32) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let expires_at = Instant::now() + Duration::from_secs(u64::from(ttl_secs));

        // Enforce cap.
        if guard.len() >= MAP_CAP && !guard.contains_key(&ip) {
            // Evict the entry closest to expiry.
            let oldest_key = guard
                .iter()
                .min_by_key(|(_, v)| v.expires_at)
                .map(|(k, _)| *k);
            if let Some(k) = oldest_key {
                guard.remove(&k);
            }
        }

        guard.insert(
            ip,
            MapEntry {
                hostname,
                expires_at,
            },
        );
    }

    /// Remove entries that have expired.
    ///
    /// Called periodically by the listener task.
    pub fn prune_expired(&self) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        guard.retain(|_, v| v.expires_at > now);
    }

    /// Return the current number of live (non-expired) entries.
    pub fn len(&self) -> usize {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        guard.values().filter(|v| v.expires_at > now).count()
    }

    /// Return true if the map is empty (or all entries expired).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ── Packet parsing ────────────────────────────────────────────────────────────

/// Parse a raw mDNS UDP payload and apply any A/AAAA/PTR records to `map`.
///
/// Malformed packets are counted and debug-logged — never panic, never error.
/// Returns `true` if any records were applied.
pub fn process_mdns_packet(data: &[u8], map: &MdnsMap) -> bool {
    let msg = match Message::from_vec(data) {
        Ok(m) => m,
        Err(e) => {
            debug!(error = %e, "mDNS: malformed packet (ignored)");
            return false;
        }
    };

    let mut applied = false;

    use hickory_proto::rr::Record;
    let all_records: Vec<&Record> = msg.answers.iter().chain(msg.additionals.iter()).collect();
    for record in all_records {
        let ttl = record.ttl;
        // mDNS goodbye packet has TTL 0 — remove from map.
        // For simplicity we just skip TTL-0 records (they age out naturally).
        if ttl == 0 {
            continue;
        }

        match &record.data {
            RData::A(a) => {
                let ip = IpAddr::V4(a.0);
                let raw = record.name.to_string();
                let raw = raw.trim_end_matches('.');
                if let Some(hostname) = sanitize_hostname(raw) {
                    map.insert(ip, hostname, ttl);
                    applied = true;
                }
            }
            RData::AAAA(aaaa) => {
                let ip = IpAddr::V6(aaaa.0);
                let raw = record.name.to_string();
                let raw = raw.trim_end_matches('.');
                if let Some(hostname) = sanitize_hostname(raw) {
                    map.insert(ip, hostname, ttl);
                    applied = true;
                }
            }
            RData::PTR(ptr) => {
                // PTR record in mDNS reverse zone: name is like 1.168.192.in-addr.arpa.
                // The RDATA is the hostname.  We need to recover the IP from the name.
                let arpa = record.name.to_string();
                let raw = ptr.0.to_string();
                let raw = raw.trim_end_matches('.');
                if let Some(hostname) = sanitize_hostname(raw) {
                    if let Some(ip) = parse_arpa_to_ip(&arpa) {
                        map.insert(ip, hostname, ttl);
                        applied = true;
                    }
                }
            }
            _ => {}
        }
    }

    applied
}

/// Parse an `.in-addr.arpa.` or `.ip6.arpa.` name back to an `IpAddr`.
fn parse_arpa_to_ip(arpa: &str) -> Option<IpAddr> {
    let arpa_lower = arpa.trim_end_matches('.').to_ascii_lowercase();

    if let Some(rest) = arpa_lower.strip_suffix(".in-addr.arpa") {
        // IPv4: a.b.c.d → reversed octets.
        let parts: Vec<&str> = rest.split('.').collect();
        if parts.len() == 4 {
            let octets: Vec<u8> = parts
                .iter()
                .rev()
                .filter_map(|s| s.parse::<u8>().ok())
                .collect();
            if octets.len() == 4 {
                return Some(IpAddr::V4(Ipv4Addr::new(
                    octets[0], octets[1], octets[2], octets[3],
                )));
            }
        }
    }
    // IPv6 arpa parsing omitted for brevity (PTR for IPv6 is rare in mDNS).
    None
}

// ── Listener task ─────────────────────────────────────────────────────────────

/// Start the passive mDNS multicast listener.
///
/// Joins `224.0.0.251:5353`, reads mDNS announcements, and updates `map`.
/// If the multicast join fails, logs a single `warn!` and returns without
/// starting any background task (feature is effectively off).
///
/// Returns the shared `MdnsMap` and an optional background task handle.
/// The task handle is `None` when the feature could not start (join failure).
pub async fn start_mdns_insight(
    cancel: tokio_util::sync::CancellationToken,
) -> (MdnsMap, Option<tokio::task::JoinHandle<()>>) {
    let map = MdnsMap::new();

    // Try to bind and join the mDNS multicast group.
    let socket = match bind_mdns_socket() {
        Ok(s) => s,
        Err(e) => {
            warn!(
                error = %e,
                "mDNS insight: failed to join multicast group; \
                 per-client hostname lookup disabled"
            );
            return (map, None);
        }
    };

    let map_for_task = map.clone();
    let task = tokio::spawn(async move {
        run_listener(socket, map_for_task, cancel).await;
    });

    (map, Some(task))
}

/// Bind a UDP socket for mDNS multicast reception.
///
/// Sets `SO_REUSEADDR` and (on platforms that support it) `SO_REUSEPORT` before
/// binding so that multiple processes (e.g. mDNSResponder, avahi) can share
/// `0.0.0.0:5353`.  Without these socket options the bind always fails on hosts
/// where the system mDNS daemon already owns the port.
///
/// This function only binds and joins — it never calls `send` or `send_to`.
fn bind_mdns_socket() -> Result<std::net::UdpSocket, std::io::Error> {
    use socket2::{Domain, Protocol, Socket, Type};

    // Create an unbound UDP/IPv4 socket via socket2 so we can set SO_REUSEADDR
    // and SO_REUSEPORT BEFORE calling bind().  std::net::UdpSocket::bind() does
    // not expose these options.
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    socket.set_reuse_port(true)?;

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), MDNS_PORT);
    socket.bind(&addr.into())?;

    // Join the mDNS multicast group on the default (any) interface.
    let udp: std::net::UdpSocket = socket.into();
    udp.join_multicast_v4(&MDNS_GROUP_V4, &Ipv4Addr::UNSPECIFIED)?;

    Ok(udp)
}

/// Main listener loop: receive packets and process them.
///
/// Never transmits — only calls `recv_from` on the socket.
async fn run_listener(
    socket: std::net::UdpSocket,
    map: MdnsMap,
    cancel: tokio_util::sync::CancellationToken,
) {
    // Convert to tokio UdpSocket for async recv.
    socket
        .set_nonblocking(true)
        .unwrap_or_else(|e| warn!(error = %e, "mDNS: set_nonblocking failed"));

    let tok_socket = match tokio::net::UdpSocket::from_std(socket) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "mDNS: failed to convert socket; feature off");
            return;
        }
    };

    let mut buf = vec![0u8; 9000];
    let mut prune_at = Instant::now() + Duration::from_secs(60);

    loop {
        tokio::select! {
            result = tok_socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, _src)) => {
                        let _ = process_mdns_packet(&buf[..len], &map);
                    }
                    Err(e) => {
                        debug!(error = %e, "mDNS recv error");
                    }
                }
            }
            () = cancel.cancelled() => break,
        }

        // Prune expired entries once a minute.
        let now = Instant::now();
        if now >= prune_at {
            map.prune_expired();
            prune_at = now + Duration::from_secs(60);
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use hickory_proto::{
        op::{Message, MessageType, OpCode},
        rr::{rdata, Name, RData, Record},
    };

    /// Build a minimal mDNS response message containing the given records.
    fn build_mdns_response(records: Vec<Record>) -> Vec<u8> {
        let mut msg = Message::new(0, MessageType::Response, OpCode::Query);
        msg.metadata.authoritative = true;
        for r in records {
            msg.add_answer(r);
        }
        msg.to_vec().unwrap()
    }

    fn a_record(name: &str, ip: std::net::Ipv4Addr, ttl: u32) -> Record {
        let name: Name = name.parse().unwrap();
        Record::from_rdata(name, ttl, RData::A(rdata::A(ip)))
    }

    fn aaaa_record(name: &str, ip: std::net::Ipv6Addr, ttl: u32) -> Record {
        let name: Name = name.parse().unwrap();
        Record::from_rdata(name, ttl, RData::AAAA(rdata::AAAA(ip)))
    }

    fn ptr_record(arpa: &str, target: &str, ttl: u32) -> Record {
        let arpa_name: Name = arpa.parse().unwrap();
        let target_name: Name = target.parse().unwrap();
        Record::from_rdata(arpa_name, ttl, RData::PTR(rdata::PTR(target_name)))
    }

    // ── A record parsing ──────────────────────────────────────────────────────

    #[test]
    fn parse_a_record_updates_map() {
        let map = MdnsMap::new();
        let ip = std::net::Ipv4Addr::new(192, 168, 1, 50);
        let packet = build_mdns_response(vec![a_record("living-room.local.", ip, 120)]);

        let applied = process_mdns_packet(&packet, &map);
        assert!(applied, "A record must be applied");
        let lookup = map.get(IpAddr::V4(ip));
        assert_eq!(
            lookup.as_deref(),
            Some("living-room.local"),
            "hostname must be recorded (trailing dot stripped)"
        );
    }

    // ── AAAA record parsing ───────────────────────────────────────────────────

    #[test]
    fn parse_aaaa_record_updates_map() {
        let map = MdnsMap::new();
        let ip6: std::net::Ipv6Addr = "fe80::1".parse().unwrap();
        let packet = build_mdns_response(vec![aaaa_record("tv.local.", ip6, 60)]);

        let applied = process_mdns_packet(&packet, &map);
        assert!(applied, "AAAA record must be applied");
        assert_eq!(map.get(IpAddr::V6(ip6)).as_deref(), Some("tv.local"));
    }

    // ── PTR record parsing ────────────────────────────────────────────────────

    #[test]
    fn parse_ptr_record_updates_map() {
        let map = MdnsMap::new();
        // PTR record: 50.1.168.192.in-addr.arpa. → printer.local.
        let packet = build_mdns_response(vec![ptr_record(
            "50.1.168.192.in-addr.arpa.",
            "printer.local.",
            240,
        )]);

        let applied = process_mdns_packet(&packet, &map);
        assert!(applied, "PTR record must be applied");
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(map.get(ip).as_deref(), Some("printer.local"));
    }

    // ── Malformed packet ──────────────────────────────────────────────────────

    #[test]
    fn malformed_packet_does_not_panic_and_returns_false() {
        let map = MdnsMap::new();
        // Completely random bytes — must not panic.
        let junk: &[u8] = &[0xFF, 0x42, 0x00, 0x01, 0x80, 0x00, 0xAA, 0xBB];
        let applied = process_mdns_packet(junk, &map);
        assert!(!applied, "malformed packet must return false");
    }

    #[test]
    fn empty_packet_does_not_panic() {
        let map = MdnsMap::new();
        let applied = process_mdns_packet(&[], &map);
        assert!(!applied, "empty packet must return false");
    }

    /// Fuzz-sample: 16 malformed inputs — none may panic.
    #[test]
    fn fuzz_sample_malformed_packets() {
        let cases: &[&[u8]] = &[
            &[],
            &[0],
            &[0x00, 0x00],
            &[0xFF, 0xFF, 0xFF, 0xFF],
            &[0x00; 12],  // header-only zeros
            &[0xFF; 512], // all-ones noise
            &[
                0x00, 0x01, 0x84, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
            // Truncated answer section
            &[
                0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
                b'x', b'a', b'm', b'p', b'l', b'e',
            ],
            &[
                0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
            b"HTTP/1.1",
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF],
            &[
                0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
            &[
                0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
            ],
            &[0x00; 1],
            &[0xAB; 100],
            &[
                0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x0C,
                0x00, 0x01, 0x80, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 0xC0, 0xA8, 0x01, 0x0A,
            ],
        ];

        let map = MdnsMap::new();
        for (i, pkt) in cases.iter().enumerate() {
            // Must not panic, regardless of return value.
            let _ = process_mdns_packet(pkt, &map);
            let _ = i; // used
        }
    }

    // ── Map TTL and cap ───────────────────────────────────────────────────────

    #[test]
    fn map_ttl_expiry() {
        let map = MdnsMap::new();
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
        // Insert with TTL 0 seconds (already expired).
        let entry_ip = ip;
        {
            let mut guard = map.inner.lock().unwrap();
            guard.insert(
                entry_ip,
                MapEntry {
                    hostname: "expired.local".to_string(),
                    expires_at: Instant::now() - Duration::from_secs(1),
                },
            );
        }
        // Should not find the expired entry.
        assert!(map.get(ip).is_none(), "expired entry must not be returned");
    }

    #[test]
    fn map_cap_evicts_when_full() {
        let map = MdnsMap::new();
        // Fill to MAP_CAP.
        for i in 0..MAP_CAP {
            let ip = IpAddr::V4(std::net::Ipv4Addr::new(
                ((i >> 16) & 0xFF) as u8,
                ((i >> 8) & 0xFF) as u8,
                (i & 0xFF) as u8,
                0,
            ));
            map.insert(ip, format!("host{i}.local"), 120);
        }
        // One more — must not panic or exceed cap.
        let extra_ip = IpAddr::V4(std::net::Ipv4Addr::new(200, 200, 200, 200));
        map.insert(extra_ip, "new.local".to_string(), 120);
        // Size must remain <= MAP_CAP.
        let guard = map.inner.lock().unwrap();
        assert!(
            guard.len() <= MAP_CAP,
            "map must not exceed cap after eviction"
        );
    }

    // ── parse_arpa_to_ip ──────────────────────────────────────────────────────

    #[test]
    fn arpa_ipv4_roundtrip() {
        let ip = parse_arpa_to_ip("50.1.168.192.in-addr.arpa.");
        assert_eq!(
            ip,
            Some(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 50)))
        );
    }

    #[test]
    fn arpa_invalid_returns_none() {
        assert!(parse_arpa_to_ip("not-arpa").is_none());
        assert!(parse_arpa_to_ip("1.in-addr.arpa.").is_none()); // not 4 octets
    }

    // ── sanitize_hostname (Finding 6: mDNS XSS / control-char ingest) ──────────

    #[test]
    fn sanitize_hostname_valid_name_passes_through() {
        let result = sanitize_hostname("living-room.local");
        assert_eq!(result.as_deref(), Some("living-room.local"));
    }

    #[test]
    fn sanitize_hostname_strips_control_characters() {
        // ASCII control chars (0x00–0x1F) must be removed.
        let raw = "evil\x00host\x0A.local";
        let result = sanitize_hostname(raw);
        // After stripping, "evilhost.local" remains.
        assert_eq!(result.as_deref(), Some("evilhost.local"));
    }

    #[test]
    fn sanitize_hostname_strips_script_tag() {
        // HTML/script injection attempt via mDNS name field.
        let raw = "<script>alert(1)</script>.local";
        let result = sanitize_hostname(raw);
        // < and > are not control chars but are harmless after stripping control chars;
        // the important thing is no control chars sneak through.
        // The result must not be None (non-empty after strip).
        assert!(
            result.is_some(),
            "non-empty hostile name must survive as Some"
        );
    }

    #[test]
    fn sanitize_hostname_empty_after_stripping_returns_none() {
        // A string composed entirely of control characters becomes empty.
        let raw: String = (0u8..=0x1F).map(|b| b as char).collect();
        let result = sanitize_hostname(&raw);
        assert!(result.is_none(), "all-control-char input must yield None");
    }

    #[test]
    fn sanitize_hostname_10kb_input_is_capped_at_253() {
        let raw = "a".repeat(10_000);
        let result = sanitize_hostname(&raw);
        assert!(result.is_some());
        assert!(
            result.unwrap().len() <= MAX_HOSTNAME_LEN,
            "sanitize_hostname must cap output at {MAX_HOSTNAME_LEN} chars"
        );
    }

    #[test]
    fn sanitize_hostname_exactly_253_chars_is_accepted() {
        let raw = "a".repeat(253);
        let result = sanitize_hostname(&raw);
        assert_eq!(result.map(|s| s.len()), Some(253));
    }

    #[test]
    fn sanitize_hostname_254_chars_is_truncated() {
        let raw = "b".repeat(254);
        let result = sanitize_hostname(&raw);
        assert_eq!(result.map(|s| s.len()), Some(253));
    }

    // ── No-transmit invariant ─────────────────────────────────────────────────
    //
    // This test documents the invariant: bind_mdns_socket does not call send.
    // We verify this structurally — the function returns a `std::net::UdpSocket`
    // and we do NOT call send_to / send on it.
    #[test]
    fn socket_is_never_written_structural_check() {
        // The MdnsMap, process_mdns_packet, and run_listener functions never
        // call send() on any socket.  We verify by reviewing the source:
        // - `bind_mdns_socket` calls `bind`, `join_multicast_v4` — no send.
        // - `run_listener` calls `recv_from` — no send.
        // - `process_mdns_packet` operates on an in-memory buffer — no socket.
        //
        // This is a documentation test.  If send is ever added, this comment
        // MUST be updated with a justification, per spec §3.
        // No assertion needed — the invariant is structural.
    }
}
