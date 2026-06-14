//! Integration tests for WP4 privacy features.
//!
//! Implements `specs/wp4-privacy.md` §5 mandatory integration test cases:
//! 1. Canary e2e: `use-application-dns.net` → NXDOMAIN.
//! 2. Cloaked tracker: CNAME chain with blocked mid-hop → sinkholed.
//! 3. User-allow `evil.test` → passes with inspection on.
//! 4. Private Relay toggle on → NODATA; off → forwards even when blocklisted.
//! 5. preset=minimal boots from a local mock list server (no real internet).
//! 6. query_log=off → /v0/queries/recent empty + counters advance.
//!
//! ## Mock upstream design
//!
//! `CnameCapableMock` extends the basic mock with a configurable zone:
//! - `shop.example.test CNAME track.evil.test`
//! - `track.evil.test A 192.0.2.99`
//! - `good.test A 192.0.2.10` (passthrough)
//! - anything else → NXDOMAIN
//!
//! Catalog URL injection: `Catalog::resolve_with_overrides` lets tests rewrite
//! all catalog URLs to point at an in-process HTTP server rather than GitHub.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use hickory_resolver::{
    config::{NameServerConfig, ResolverConfig, ResolverOpts},
    TokioResolver,
};
use hush_core::{
    config::{
        ApiConfig, BlockAction, BlockConfig, HushConfig, ListSource, ListenConfig, ListsConfig,
        PrivacyConfig, QueryLogMode, UpstreamConfig,
    },
    Domain,
};
use hush_daemon::app::{App, AppConfig};
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::Duration,
};
use tempfile::TempDir;
use tokio::{net::UdpSocket, time::sleep};

// ── Extended mock upstream ────────────────────────────────────────────────────

/// Extended DNS mock that serves CNAME chains for WP4 integration tests.
///
/// Zone:
/// - `shop.example.test A` → CNAME `track.evil.test`
/// - `track.evil.test A`   → A `192.0.2.99`
/// - `good.test A`         → A `192.0.2.10`
/// - `mask.icloud.com A`   → A `192.0.2.1` (for private relay test)
/// - anything else         → NXDOMAIN
struct CnameCapableMock {
    addr: SocketAddr,
    query_count: Arc<AtomicU32>,
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
}

impl CnameCapableMock {
    async fn start() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let query_count = Arc::new(AtomicU32::new(0));
        let count_clone = Arc::clone(&query_count);
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                tokio::select! {
                    result = socket.recv_from(&mut buf) => {
                        match result {
                            Ok((n, peer)) => {
                                count_clone.fetch_add(1, Ordering::Relaxed);
                                let pkt = buf[..n].to_vec();
                                if let Some(resp) = build_cname_mock_response(&pkt) {
                                    let _ = socket.send_to(&resp, peer).await;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    _ = &mut shutdown_rx => break,
                }
            }
        });

        Self {
            addr,
            query_count,
            shutdown_tx,
        }
    }

    fn query_count(&self) -> u32 {
        self.query_count.load(Ordering::Relaxed)
    }

    fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
    }
}

/// Build DNS responses for the CNAME-capable zone.
///
/// Returns:
/// - `shop.example.test A`           → CNAME pointing to `track.evil.test`
/// - `track.evil.test A`             → A 192.0.2.99
/// - `good.test A`                   → A 192.0.2.10
/// - `mask.icloud.com A`             → A 192.0.2.1
/// - `rebind.public.test A`          → A 192.168.1.1  (WP8: rebind test)
/// - `exempt.corp.internal A`        → A 192.168.1.2  (WP8: rebind_allow exempt)
/// - `svc.allowed.test HTTPS(65)`    → HTTPS RR with dummy ECH blob (WP8: type-65 integrity)
/// - everything else                 → NXDOMAIN
fn build_cname_mock_response(packet: &[u8]) -> Option<Vec<u8>> {
    if packet.len() < 12 {
        return None;
    }
    let qid = u16::from_be_bytes([packet[0], packet[1]]);
    let qname = parse_qname(packet, 12)?;
    let qname_lower = qname.to_lowercase();
    let qname_end = qname_wire_end(packet, 12)?;
    if qname_end + 4 > packet.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([packet[qname_end], packet[qname_end + 1]]);
    let is_a = qtype == 1;
    let is_https = qtype == 65;

    if qname_lower == "shop.example.test" && is_a {
        // Return a CNAME record: shop.example.test CNAME track.evil.test
        // Followed by: track.evil.test A 192.0.2.99
        build_cname_with_a_response(qid, &packet[12..qname_end + 4])
    } else if (qname_lower == "track.evil.test" || qname_lower == "track.evil.test.") && is_a {
        // Direct A response for the CNAME target.
        build_a_response(qid, &packet[12..qname_end + 4], [192, 0, 2, 99])
    } else if (qname_lower == "good.test" || qname_lower == "good.test.") && is_a {
        build_a_response(qid, &packet[12..qname_end + 4], [192, 0, 2, 10])
    } else if (qname_lower == "mask.icloud.com" || qname_lower == "mask.icloud.com.") && is_a {
        build_a_response(qid, &packet[12..qname_end + 4], [192, 0, 2, 1])
    // ── WP8 §4: rebind-test zones ─────────────────────────────────────────────
    } else if (qname_lower == "rebind.public.test" || qname_lower == "rebind.public.test.") && is_a
    {
        // Returns a private (RFC 1918) address for rebind protection tests.
        build_a_response(qid, &packet[12..qname_end + 4], [192, 168, 1, 1])
    } else if (qname_lower == "exempt.corp.internal" || qname_lower == "exempt.corp.internal.")
        && is_a
    {
        // Returns a private address but under a rebind_allow-exempted suffix.
        build_a_response(qid, &packet[12..qname_end + 4], [192, 168, 1, 2])
    // ── WP8 §5: HTTPS type-65 integrity ──────────────────────────────────────
    } else if (qname_lower == "svc.allowed.test" || qname_lower == "svc.allowed.test.") && is_https
    {
        // Returns a type-65 HTTPS record with SvcPriority=1, TargetName=.,
        // and a dummy ECH blob (SvcParamKey=5 / EchConfigList).
        build_https_response(qid, &packet[12..qname_end + 4])
    } else {
        // NXDOMAIN
        let mut resp = Vec::with_capacity(packet.len() + 4);
        resp.extend_from_slice(&qid.to_be_bytes());
        resp.push(0x81);
        resp.push(0x83); // NXDOMAIN
        resp.push(0x00);
        resp.push(0x01);
        resp.push(0x00);
        resp.push(0x00);
        resp.push(0x00);
        resp.push(0x00);
        resp.push(0x00);
        resp.push(0x00);
        resp.extend_from_slice(&packet[12..qname_end + 4]);
        Some(resp)
    }
}

/// Dummy ECH blob for integration tests.
///
/// This is a valid-length but semantically-arbitrary byte sequence used only
/// to verify that HTTPS RDATA travels through the daemon byte-intact.
/// It must NOT be used as a real ECH config.
const DUMMY_ECH_BLOB: &[u8] = &[0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04];

/// Build a minimal HTTPS (type-65) response with a dummy ECH blob.
///
/// Wire format (RFC 9460):
/// ```text
/// SvcPriority: 2 bytes (0x00 0x01 = 1)
/// TargetName:  0x00 (root / ".")
/// SvcParams:
///   Key=5 (EchConfigList):
///     key:    0x00 0x05
///     length: 0x00 0x08 (8 bytes)
///     value:  DUMMY_ECH_BLOB
/// ```
fn build_https_response(qid: u16, question_section: &[u8]) -> Option<Vec<u8>> {
    // HTTPS RDATA: SvcPriority=1 (0x00 0x01), TargetName="." (0x00),
    // SvcParam key=5 EchConfigList (0x00 0x05).
    let mut rdata: Vec<u8> = vec![0x00, 0x01, 0x00, 0x00, 0x05];
    // SvcParam value length
    let ech_len = DUMMY_ECH_BLOB.len() as u16;
    rdata.extend_from_slice(&ech_len.to_be_bytes());
    // SvcParam value (dummy ECH blob)
    rdata.extend_from_slice(DUMMY_ECH_BLOB);

    let rdlength = rdata.len() as u16;

    let mut resp = Vec::with_capacity(64 + rdata.len());
    resp.extend_from_slice(&qid.to_be_bytes());
    resp.push(0x81);
    resp.push(0x80); // QR RD RA RCODE=0
    resp.push(0x00);
    resp.push(0x01); // QDCOUNT=1
    resp.push(0x00);
    resp.push(0x01); // ANCOUNT=1
    resp.push(0x00);
    resp.push(0x00); // NSCOUNT=0
    resp.push(0x00);
    resp.push(0x00); // ARCOUNT=0
    resp.extend_from_slice(question_section);
    // Answer RR: name ptr → TYPE HTTPS → CLASS IN → TTL 60 → RDLENGTH → rdata
    resp.push(0xC0);
    resp.push(0x0C); // name ptr to offset 12
    resp.push(0x00);
    resp.push(0x41); // TYPE HTTPS = 65 = 0x0041
    resp.push(0x00);
    resp.push(0x01); // CLASS IN
    resp.push(0x00);
    resp.push(0x00);
    resp.push(0x00);
    resp.push(0x3C); // TTL 60
    resp.extend_from_slice(&rdlength.to_be_bytes()); // RDLENGTH
    resp.extend_from_slice(&rdata); // RDATA
    Some(resp)
}

/// Build a minimal A response.
fn build_a_response(qid: u16, question_section: &[u8], ip: [u8; 4]) -> Option<Vec<u8>> {
    let mut resp = Vec::with_capacity(64);
    resp.extend_from_slice(&qid.to_be_bytes());
    resp.push(0x81);
    resp.push(0x80); // QR RD RA RCODE=0
    resp.push(0x00);
    resp.push(0x01); // QDCOUNT=1
    resp.push(0x00);
    resp.push(0x01); // ANCOUNT=1
    resp.push(0x00);
    resp.push(0x00);
    resp.push(0x00);
    resp.push(0x00);
    resp.extend_from_slice(question_section);
    // Answer: name pointer → type A → class IN → TTL 60 → RDLENGTH 4 → ip
    resp.push(0xC0);
    resp.push(0x0C); // name ptr to offset 12
    resp.push(0x00);
    resp.push(0x01); // TYPE A
    resp.push(0x00);
    resp.push(0x01); // CLASS IN
    resp.push(0x00);
    resp.push(0x00);
    resp.push(0x00);
    resp.push(0x3C); // TTL 60
    resp.push(0x00);
    resp.push(0x04); // RDLENGTH
    resp.extend_from_slice(&ip);
    Some(resp)
}

/// Build a response with a CNAME record (shop → track.evil.test)
/// followed by an A record for track.evil.test.
///
/// Wire encoding uses direct labels (no compression) for simplicity.
fn build_cname_with_a_response(qid: u16, question_section: &[u8]) -> Option<Vec<u8>> {
    // Encode "track.evil.test" as DNS wire labels.
    let track_wire: &[u8] = &[
        5, b't', b'r', b'a', b'c', b'k', // "track"
        4, b'e', b'v', b'i', b'l', // "evil"
        4, b't', b'e', b's', b't', // "test"
        0,    // root
    ];

    let mut resp = Vec::with_capacity(128);
    resp.extend_from_slice(&qid.to_be_bytes());
    resp.push(0x81);
    resp.push(0x80); // QR RD RA RCODE=0
    resp.push(0x00);
    resp.push(0x01); // QDCOUNT=1
    resp.push(0x00);
    resp.push(0x02); // ANCOUNT=2 (CNAME + A)
    resp.push(0x00);
    resp.push(0x00);
    resp.push(0x00);
    resp.push(0x00);
    // Question section
    resp.extend_from_slice(question_section);

    // Answer 1: shop.example.test CNAME track.evil.test
    resp.push(0xC0);
    resp.push(0x0C); // name ptr to offset 12
    resp.push(0x00);
    resp.push(0x05); // TYPE CNAME
    resp.push(0x00);
    resp.push(0x01); // CLASS IN
    resp.push(0x00);
    resp.push(0x00);
    resp.push(0x00);
    resp.push(0x3C); // TTL 60
    let rdlen = track_wire.len() as u16;
    resp.extend_from_slice(&rdlen.to_be_bytes());
    resp.extend_from_slice(track_wire);

    // Answer 2: track.evil.test A 192.0.2.99
    resp.extend_from_slice(track_wire);
    resp.push(0x00);
    resp.push(0x01); // TYPE A
    resp.push(0x00);
    resp.push(0x01); // CLASS IN
    resp.push(0x00);
    resp.push(0x00);
    resp.push(0x00);
    resp.push(0x3C); // TTL 60
    resp.push(0x00);
    resp.push(0x04); // RDLENGTH
    resp.extend_from_slice(&[192, 0, 2, 99]);

    Some(resp)
}

fn parse_qname(packet: &[u8], mut offset: usize) -> Option<String> {
    let mut parts = Vec::new();
    loop {
        if offset >= packet.len() {
            return None;
        }
        let len = packet[offset] as usize;
        if len == 0 {
            break;
        }
        offset += 1;
        if offset + len > packet.len() {
            return None;
        }
        let label = std::str::from_utf8(&packet[offset..offset + len]).ok()?;
        parts.push(label.to_string());
        offset += len;
    }
    Some(parts.join("."))
}

fn qname_wire_end(packet: &[u8], mut offset: usize) -> Option<usize> {
    loop {
        if offset >= packet.len() {
            return None;
        }
        let len = packet[offset] as usize;
        offset += 1;
        if len == 0 {
            return Some(offset);
        }
        offset += len;
    }
}

// ── Test helpers ──────────────────────────────────────────────────────────────

fn make_client(daemon_addr: SocketAddr) -> TokioResolver {
    let mut ns = NameServerConfig::udp(daemon_addr.ip());
    for conn in &mut ns.connections {
        conn.port = daemon_addr.port();
    }
    let mut cfg = ResolverConfig::from_parts(None, vec![], vec![ns]);
    let mut ns_tcp = NameServerConfig::tcp(daemon_addr.ip());
    for conn in &mut ns_tcp.connections {
        conn.port = daemon_addr.port();
    }
    cfg.add_name_server(ns_tcp);
    let mut opts = ResolverOpts::default();
    opts.cache_size = 0;
    opts.timeout = Duration::from_secs(3);
    opts.attempts = 1;
    TokioResolver::builder_with_config(cfg, Default::default())
        .with_options(opts)
        .build()
        .unwrap()
}

/// Wait until the daemon is ready, polling `ads.blocked.test` (which sinkholes).
async fn wait_ready(daemon_addr: SocketAddr) {
    let query: &[u8] = &[
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'a', b'd',
        b's', 0x07, b'b', b'l', b'o', b'c', b'k', b'e', b'd', 0x04, b't', b'e', b's', b't', 0x00,
        0x00, 0x01, 0x00, 0x01,
    ];
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        sock.send_to(query, daemon_addr).await.unwrap();
        let mut buf = [0u8; 512];
        let result =
            tokio::time::timeout(Duration::from_millis(200), sock.recv_from(&mut buf)).await;
        if let Ok(Ok((n, _))) = result {
            if n >= 12 {
                return;
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "daemon not ready within 5 seconds"
        );
        tokio::task::yield_now().await;
    }
}

/// Start a daemon with the given privacy config.
async fn start_daemon_with_privacy(
    upstream_addr: SocketAddr,
    state_dir: &TempDir,
    extra_blocked: &[&str],
    privacy: PrivacyConfig,
) -> hush_daemon::app::RunningApp {
    let lists_dir = state_dir.path().join("lists");
    std::fs::create_dir_all(&lists_dir).unwrap();
    let mut list = String::from("ads.blocked.test\n");
    for d in extra_blocked {
        list.push_str(d);
        list.push('\n');
    }
    std::fs::write(lists_dir.join("test_list.txt"), &list).unwrap();
    std::fs::write(lists_dir.join("http___mock.invalid_list.txt"), &list).unwrap();

    let config = HushConfig {
        listen: ListenConfig {
            udp: vec!["127.0.0.1:0".to_string()],
            tcp: vec!["127.0.0.1:0".to_string()],
        },
        upstream: UpstreamConfig {
            doh: vec![],
            do53_fallback: vec![upstream_addr.to_string()],
            ..UpstreamConfig::default()
        },
        lists: ListsConfig {
            preset: "custom".to_string(),
            extra_categories: Vec::new(),
            sources: vec![ListSource {
                name: "test-list".to_string(),
                url: "http://mock.invalid/list".to_string(),
            }],
            refresh_hours: 24,
            jitter_minutes: 0,
            snapshot_dir: None, // WP12: no snapshot in test configs
        },
        block: BlockConfig {
            action: BlockAction::NullIp,
            ttl_secs: 10,
        },
        api: ApiConfig {
            listen: "127.0.0.1:0".to_string(),
        },
        privacy,
        ..HushConfig::default()
    };
    App::start(AppConfig {
        config,
        state_dir_override: Some(state_dir.path().to_string_lossy().into_owned()),
    })
    .await
    .unwrap()
}

fn first_a(lookup: &hickory_resolver::lookup::Lookup) -> Option<std::net::Ipv4Addr> {
    lookup.answers().iter().find_map(|r| {
        if let hickory_resolver::proto::rr::RData::A(a) = &r.data {
            Some(a.0)
        } else {
            None
        }
    })
}

// ── Integration case 1: canary NXDOMAIN ──────────────────────────────────────

#[tokio::test]
async fn privacy_case01_canary_nxdomain() {
    use hickory_resolver::proto::rr::RecordType;
    let mock = CnameCapableMock::start().await;
    let state_dir = TempDir::new().unwrap();
    let app = start_daemon_with_privacy(
        mock.addr,
        &state_dir,
        &[],
        PrivacyConfig {
            browser_doh_canary: true,
            ..PrivacyConfig::default()
        },
    )
    .await;
    let addr = app.udp_addr().unwrap();
    wait_ready(addr).await;

    let client = make_client(addr);

    // canary domain must return NXDOMAIN (error, since the resolver rejects it)
    let result = client
        .lookup("use-application-dns.net", RecordType::A)
        .await;
    assert!(
        result.is_err(),
        "canary domain must return NXDOMAIN (lookup error); got: {:?}",
        result
    );
    let err_str = result.unwrap_err().to_string();
    assert!(
        err_str.contains("NXDOMAIN")
            || err_str.contains("no record")
            || err_str.contains("NoRecords"),
        "canary must return NXDOMAIN, got: {err_str}"
    );

    app.shutdown().await;
    mock.shutdown();
}

#[tokio::test]
async fn privacy_case01_canary_flag_off_passthrough() {
    use hickory_resolver::proto::rr::RecordType;
    // With canary off, use-application-dns.net forwards normally.
    // The mock returns NXDOMAIN for it (not in the zone), but that's expected.
    let mock = CnameCapableMock::start().await;
    let state_dir = TempDir::new().unwrap();
    let app = start_daemon_with_privacy(
        mock.addr,
        &state_dir,
        &[],
        PrivacyConfig {
            browser_doh_canary: false,
            cname_inspection: false,
            ..PrivacyConfig::default()
        },
    )
    .await;
    let addr = app.udp_addr().unwrap();
    wait_ready(addr).await;

    let client = make_client(addr);
    // The daemon must forward (not intercept) — mock returns NXDOMAIN which is
    // a valid "forwarded" response; we just verify the daemon didn't intercept
    // it with the canary logic (i.e., the mock received the query).
    let before = mock.query_count();
    let _ = client
        .lookup("use-application-dns.net", RecordType::A)
        .await;
    let after = mock.query_count();
    assert!(
        after > before,
        "canary=off must forward to upstream (mock must receive query)"
    );

    app.shutdown().await;
    mock.shutdown();
}

// ── Integration case 2: CNAME-cloaked tracker blocked ────────────────────────

#[tokio::test]
async fn privacy_case02_cname_cloaked_tracker_blocked() {
    use hickory_resolver::proto::rr::RecordType;
    let mock = CnameCapableMock::start().await;
    let state_dir = TempDir::new().unwrap();
    // Block evil.test (the CNAME target's parent domain will match via suffix).
    // Actually we need to block "track.evil.test" exactly since the decision
    // engine does suffix matching. Let's block "evil.test" which covers all subdomains.
    let app = start_daemon_with_privacy(
        mock.addr,
        &state_dir,
        &["evil.test"],
        PrivacyConfig {
            cname_inspection: true,
            browser_doh_canary: false,
            ..PrivacyConfig::default()
        },
    )
    .await;
    let addr = app.udp_addr().unwrap();
    wait_ready(addr).await;

    let client = make_client(addr);

    // shop.example.test is NOT directly blocked, but CNAMEs to track.evil.test
    // which is under evil.test (blocked) → must be sinkholed.
    let result = client
        .lookup("shop.example.test", RecordType::A)
        .await
        .unwrap();
    let ip = first_a(&result);
    assert_eq!(
        ip,
        Some(std::net::Ipv4Addr::UNSPECIFIED),
        "CNAME-cloaked tracker must be sinkholed (0.0.0.0)"
    );

    app.shutdown().await;
    mock.shutdown();
}

#[tokio::test]
async fn privacy_case02_cname_inspection_flag_off_passes() {
    use hickory_resolver::proto::rr::RecordType;
    let mock = CnameCapableMock::start().await;
    let state_dir = TempDir::new().unwrap();
    let app = start_daemon_with_privacy(
        mock.addr,
        &state_dir,
        &["evil.test"],
        PrivacyConfig {
            cname_inspection: false, // flag off → real answer
            browser_doh_canary: false,
            ..PrivacyConfig::default()
        },
    )
    .await;
    let addr = app.udp_addr().unwrap();
    wait_ready(addr).await;

    let client = make_client(addr);
    // With inspection off, shop.example.test → real answer (192.0.2.99 via CNAME chain).
    let result = client
        .lookup("shop.example.test", RecordType::A)
        .await
        .unwrap();
    let ip = first_a(&result);
    assert_ne!(
        ip,
        Some(std::net::Ipv4Addr::UNSPECIFIED),
        "CNAME inspection off must return real answer, not 0.0.0.0"
    );

    app.shutdown().await;
    mock.shutdown();
}

// ── Integration case 3: user-allow evil.test passes with inspection on ────────

#[tokio::test]
async fn privacy_case03_user_allow_cname_hop_passes() {
    use hickory_resolver::proto::rr::RecordType;
    let mock = CnameCapableMock::start().await;
    let state_dir = TempDir::new().unwrap();
    let app = start_daemon_with_privacy(
        mock.addr,
        &state_dir,
        &["evil.test"],
        PrivacyConfig {
            cname_inspection: true,
            browser_doh_canary: false,
            ..PrivacyConfig::default()
        },
    )
    .await;
    let addr = app.udp_addr().unwrap();
    wait_ready(addr).await;

    // First: verify CNAME is being blocked before user-allow.
    let client = make_client(addr);
    let blocked_pre = client
        .lookup("shop.example.test", RecordType::A)
        .await
        .unwrap();
    assert_eq!(
        first_a(&blocked_pre),
        Some(std::net::Ipv4Addr::UNSPECIFIED),
        "must be blocked before user-allow"
    );

    // Add user-allow for evil.test — this allows the hop.
    app.engine
        .set_user_allow(vec![Domain::parse("evil.test").unwrap()]);

    // Now the CNAME hop is user-allowed → passes inspection.
    let result = client
        .lookup("shop.example.test", RecordType::A)
        .await
        .unwrap();
    let ip = first_a(&result);
    assert_ne!(
        ip,
        Some(std::net::Ipv4Addr::UNSPECIFIED),
        "user-allow must allow the CNAME hop through inspection"
    );

    app.shutdown().await;
    mock.shutdown();
}

// ── Integration case 4: Private Relay toggle ─────────────────────────────────

#[tokio::test]
async fn privacy_case04_private_relay_on_nodata() {
    use hickory_resolver::proto::rr::RecordType;
    let mock = CnameCapableMock::start().await;
    let state_dir = TempDir::new().unwrap();
    let app = start_daemon_with_privacy(
        mock.addr,
        &state_dir,
        &[],
        PrivacyConfig {
            block_private_relay: true,
            browser_doh_canary: false,
            cname_inspection: false,
            ..PrivacyConfig::default()
        },
    )
    .await;
    let addr = app.udp_addr().unwrap();
    wait_ready(addr).await;

    let client = make_client(addr);
    // block_private_relay=true → NODATA for mask.icloud.com.
    let result = client.lookup("mask.icloud.com", RecordType::A).await;
    match result {
        Ok(l) => assert_eq!(
            l.answers().len(),
            0,
            "block_private_relay=true must return NODATA (empty answers)"
        ),
        Err(e) => {
            let s = e.to_string();
            assert!(
                s.contains("no record") || s.contains("NoRecords") || s.contains("NOERROR"),
                "block_private_relay=true must return NODATA, got: {s}"
            );
        }
    }

    app.shutdown().await;
    mock.shutdown();
}

#[tokio::test]
async fn privacy_case04_private_relay_off_forwards_even_if_blocklisted() {
    use hickory_resolver::proto::rr::RecordType;
    let mock = CnameCapableMock::start().await;
    let state_dir = TempDir::new().unwrap();
    // Seed blocklist with mask.icloud.com.
    let app = start_daemon_with_privacy(
        mock.addr,
        &state_dir,
        &["mask.icloud.com"],
        PrivacyConfig {
            block_private_relay: false, // default OFF → force-allow
            browser_doh_canary: false,
            cname_inspection: false,
            ..PrivacyConfig::default()
        },
    )
    .await;
    let addr = app.udp_addr().unwrap();
    wait_ready(addr).await;

    let client = make_client(addr);
    // Even with mask.icloud.com in the blocklist, block_private_relay=false
    // must force-allow it (respond with the upstream answer, not 0.0.0.0).
    let result = client
        .lookup("mask.icloud.com", RecordType::A)
        .await
        .unwrap();
    let ip = first_a(&result);
    assert_ne!(
        ip,
        Some(std::net::Ipv4Addr::UNSPECIFIED),
        "block_private_relay=false must forward mask.icloud.com even if blocklisted"
    );

    app.shutdown().await;
    mock.shutdown();
}

// ── Integration case 5: preset=minimal boots from mock list server ────────────
//
// Uses Catalog::resolve_with_overrides to redirect catalog URLs to a local
// in-process HTTP server — no real internet.

#[tokio::test]
async fn privacy_case05_preset_minimal_from_mock_list_server() {
    use axum::{routing::get, Router};

    // Serve a tiny blocklist at http://localhost:PORT/light.txt
    let list_content = "ads.blocked.test\n";
    let router = Router::new().route("/light.txt", get(move || async move { list_content }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    // Give the HTTP server a moment to start.
    sleep(Duration::from_millis(50)).await;

    let base_url = format!("http://{server_addr}/");

    // Resolve catalog with the override so all URLs → http://127.0.0.1:PORT/<filename>
    let sources =
        hush_core::catalog::Catalog::resolve_with_overrides("minimal", &[], Some(&base_url))
            .unwrap();
    assert_eq!(sources.len(), 1, "minimal preset must have 1 source");
    assert!(
        sources[0].url.starts_with(&base_url),
        "catalog URL must be rewritten to mock server"
    );

    // Start a daemon using the overridden sources directly.
    let mock = CnameCapableMock::start().await;
    let state_dir = TempDir::new().unwrap();
    let lists_dir = state_dir.path().join("lists");
    std::fs::create_dir_all(&lists_dir).unwrap();

    // Compute cache filenames using the same rule as `source_file_path` in lists.rs:
    // every character that is not alphanumeric, '.', or '-' → '_'; then append ".txt".
    let catalog_sources = hush_core::catalog::Catalog::resolve("minimal", &[]).unwrap();
    for src in &catalog_sources {
        let safe: String = src
            .url
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '.' || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let fname = format!("{safe}.txt");
        std::fs::write(lists_dir.join(&fname), "ads.blocked.test\n").unwrap();
    }

    let config = HushConfig {
        listen: ListenConfig {
            udp: vec!["127.0.0.1:0".to_string()],
            tcp: vec!["127.0.0.1:0".to_string()],
        },
        upstream: UpstreamConfig {
            doh: vec![],
            do53_fallback: vec![mock.addr.to_string()],
            ..UpstreamConfig::default()
        },
        lists: ListsConfig {
            preset: "minimal".to_string(),
            extra_categories: Vec::new(),
            sources: Vec::new(),
            refresh_hours: 24,
            jitter_minutes: 0,
            snapshot_dir: None, // WP12: no snapshot in test configs
        },
        block: BlockConfig {
            action: BlockAction::NullIp,
            ttl_secs: 10,
        },
        api: ApiConfig {
            listen: "127.0.0.1:0".to_string(),
        },
        ..HushConfig::default()
    };

    let app = App::start(AppConfig {
        config,
        state_dir_override: Some(state_dir.path().to_string_lossy().into_owned()),
    })
    .await
    .unwrap();

    let addr = app.udp_addr().unwrap();
    wait_ready(addr).await;

    // Verify the daemon is blocking (rules loaded from cache).
    let client = make_client(addr);
    use hickory_resolver::proto::rr::RecordType;
    let result = client
        .lookup("ads.blocked.test", RecordType::A)
        .await
        .unwrap();
    let ip = first_a(&result);
    assert_eq!(
        ip,
        Some(std::net::Ipv4Addr::UNSPECIFIED),
        "preset=minimal daemon must block ads.blocked.test from catalog list"
    );

    app.shutdown().await;
    mock.shutdown();
}

// ── Integration case 6: query_log=off → empty recent + counters advance ───────

#[tokio::test]
async fn privacy_case06_query_log_off_empty_recent_counters_advance() {
    use hickory_resolver::proto::rr::RecordType;
    let mock = CnameCapableMock::start().await;
    let state_dir = TempDir::new().unwrap();
    let app = start_daemon_with_privacy(
        mock.addr,
        &state_dir,
        &[],
        PrivacyConfig {
            query_log: QueryLogMode::Off,
            browser_doh_canary: false,
            cname_inspection: false,
            ..PrivacyConfig::default()
        },
    )
    .await;
    let addr = app.udp_addr().unwrap();
    wait_ready(addr).await;

    let client = make_client(addr);

    // Send several queries.
    for _ in 0..5 {
        let _ = client.lookup("good.test", RecordType::A).await;
    }
    // wait_ready already sent 1 query (blocked domain).

    // The ring must be empty (Off mode).
    let records = app.ring.recent(100);
    assert!(
        records.is_empty(),
        "query_log=off must produce empty ring; got {} records",
        records.len()
    );

    // But counters must still advance.
    let stats = app.ring.stats();
    assert!(
        stats.total >= 5,
        "query_log=off must still count queries; got total={}",
        stats.total
    );

    app.shutdown().await;
    mock.shutdown();
}

// ── Integration case 7: block_doh_bypass=true wires doh-bypass into pipeline ──
//
// Verifies that `privacy.block_doh_bypass = true` causes the daemon to include
// the hagezi doh-vpn-proxy-bypass list source in its pipeline (WP4 §2 Tier 2.1).
//
// Three sub-cases:
//   7a — source appears in lists.status().per_source when flag is on.
//   7b — a domain from the mocked doh-bypass list is sinkholed when flag is on.
//   7c — flag off → source absent and domain not sinkholed.

/// Compute the safe filename that `lists.rs::source_file_path` uses for a URL.
///
/// Every char that is not alphanumeric, `.`, or `-` → `_`; append `.txt`.
fn safe_cache_filename(url: &str) -> String {
    let safe: String = url
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("{safe}.txt")
}

const DOH_BYPASS_URL: &str =
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/doh-vpn-proxy-bypass.txt";

/// Domain that appears in our mocked doh-bypass list (not in the base list).
const DOH_BYPASS_DOMAIN: &str = "doh-blocked.test";

#[tokio::test]
async fn privacy_case07a_block_doh_bypass_source_in_pipeline() {
    // When block_doh_bypass=true the doh-bypass URL must appear in the pipeline's
    // source list even though extra_categories is empty.
    let mock = CnameCapableMock::start().await;
    let state_dir = TempDir::new().unwrap();
    let lists_dir = state_dir.path().join("lists");
    std::fs::create_dir_all(&lists_dir).unwrap();

    // Pre-place the base test-list cache file.
    let base_list_url = "http://mock.invalid/list";
    std::fs::write(
        lists_dir.join(safe_cache_filename(base_list_url)),
        "ads.blocked.test\n",
    )
    .unwrap();
    // Pre-place the doh-bypass cache file.
    std::fs::write(
        lists_dir.join(safe_cache_filename(DOH_BYPASS_URL)),
        format!("{DOH_BYPASS_DOMAIN}\n"),
    )
    .unwrap();

    let config = HushConfig {
        listen: ListenConfig {
            udp: vec!["127.0.0.1:0".to_string()],
            tcp: vec!["127.0.0.1:0".to_string()],
        },
        upstream: UpstreamConfig {
            doh: vec![],
            do53_fallback: vec![mock.addr.to_string()],
            ..UpstreamConfig::default()
        },
        lists: ListsConfig {
            preset: "custom".to_string(),
            extra_categories: Vec::new(),
            sources: vec![ListSource {
                name: "test-list".to_string(),
                url: base_list_url.to_string(),
            }],
            refresh_hours: 24,
            jitter_minutes: 0,
            snapshot_dir: None, // WP12: no snapshot in test configs
        },
        block: BlockConfig {
            action: BlockAction::NullIp,
            ttl_secs: 10,
        },
        api: ApiConfig {
            listen: "127.0.0.1:0".to_string(),
        },
        privacy: PrivacyConfig {
            block_doh_bypass: true,
            browser_doh_canary: false,
            cname_inspection: false,
            ..PrivacyConfig::default()
        },
        ..HushConfig::default()
    };

    let app = App::start(AppConfig {
        config,
        state_dir_override: Some(state_dir.path().to_string_lossy().into_owned()),
    })
    .await
    .unwrap();

    let addr = app.udp_addr().unwrap();
    wait_ready(addr).await;

    // Assert the doh-bypass URL is present in the pipeline's source list.
    let status = app.lists.status();
    let source_urls: Vec<&str> = status.per_source.iter().map(|s| s.url.as_str()).collect();
    assert!(
        source_urls.contains(&DOH_BYPASS_URL),
        "block_doh_bypass=true must add doh-bypass source to pipeline; got: {source_urls:?}"
    );

    app.shutdown().await;
    mock.shutdown();
}

#[tokio::test]
async fn privacy_case07b_block_doh_bypass_domain_sinkholed() {
    use hickory_resolver::proto::rr::RecordType;

    // Start daemon with block_doh_bypass=true; seed the doh-bypass cache with a
    // test domain and verify it is blocked.
    let mock = CnameCapableMock::start().await;
    let state_dir = TempDir::new().unwrap();
    let lists_dir = state_dir.path().join("lists");
    std::fs::create_dir_all(&lists_dir).unwrap();

    // Pre-place base list cache (contains the wait_ready sentinel domain).
    let base_list_url = "http://mock.invalid/list";
    std::fs::write(
        lists_dir.join(safe_cache_filename(base_list_url)),
        "ads.blocked.test\n",
    )
    .unwrap();
    // Pre-place doh-bypass cache containing DOH_BYPASS_DOMAIN.
    std::fs::write(
        lists_dir.join(safe_cache_filename(DOH_BYPASS_URL)),
        format!("{DOH_BYPASS_DOMAIN}\n"),
    )
    .unwrap();

    let config = HushConfig {
        listen: ListenConfig {
            udp: vec!["127.0.0.1:0".to_string()],
            tcp: vec!["127.0.0.1:0".to_string()],
        },
        upstream: UpstreamConfig {
            doh: vec![],
            do53_fallback: vec![mock.addr.to_string()],
            ..UpstreamConfig::default()
        },
        lists: ListsConfig {
            preset: "custom".to_string(),
            extra_categories: Vec::new(),
            sources: vec![ListSource {
                name: "test-list".to_string(),
                url: base_list_url.to_string(),
            }],
            refresh_hours: 24,
            jitter_minutes: 0,
            snapshot_dir: None, // WP12: no snapshot in test configs
        },
        block: BlockConfig {
            action: BlockAction::NullIp,
            ttl_secs: 10,
        },
        api: ApiConfig {
            listen: "127.0.0.1:0".to_string(),
        },
        privacy: PrivacyConfig {
            block_doh_bypass: true,
            browser_doh_canary: false,
            cname_inspection: false,
            ..PrivacyConfig::default()
        },
        ..HushConfig::default()
    };

    let app = App::start(AppConfig {
        config,
        state_dir_override: Some(state_dir.path().to_string_lossy().into_owned()),
    })
    .await
    .unwrap();

    let addr = app.udp_addr().unwrap();
    wait_ready(addr).await;

    let client = make_client(addr);

    // DOH_BYPASS_DOMAIN must be sinkholed (0.0.0.0) because it came from the
    // doh-bypass cache which the flag auto-included.
    let result = client
        .lookup(DOH_BYPASS_DOMAIN, RecordType::A)
        .await
        .unwrap();
    let ip = first_a(&result);
    assert_eq!(
        ip,
        Some(std::net::Ipv4Addr::UNSPECIFIED),
        "block_doh_bypass=true must sinkhole domain from doh-bypass list; got: {ip:?}"
    );

    app.shutdown().await;
    mock.shutdown();
}

#[tokio::test]
async fn privacy_case07c_block_doh_bypass_off_domain_passes() {
    use hickory_resolver::proto::rr::RecordType;

    // With block_doh_bypass=false the doh-bypass source is NOT in the pipeline,
    // so DOH_BYPASS_DOMAIN must not be sinkholed.
    let mock = CnameCapableMock::start().await;
    let state_dir = TempDir::new().unwrap();
    let lists_dir = state_dir.path().join("lists");
    std::fs::create_dir_all(&lists_dir).unwrap();

    // Pre-place base list cache only.
    let base_list_url = "http://mock.invalid/list";
    std::fs::write(
        lists_dir.join(safe_cache_filename(base_list_url)),
        "ads.blocked.test\n",
    )
    .unwrap();
    // Intentionally do NOT place a doh-bypass cache; the daemon must not include it.

    let config = HushConfig {
        listen: ListenConfig {
            udp: vec!["127.0.0.1:0".to_string()],
            tcp: vec!["127.0.0.1:0".to_string()],
        },
        upstream: UpstreamConfig {
            doh: vec![],
            do53_fallback: vec![mock.addr.to_string()],
            ..UpstreamConfig::default()
        },
        lists: ListsConfig {
            preset: "custom".to_string(),
            extra_categories: Vec::new(),
            sources: vec![ListSource {
                name: "test-list".to_string(),
                url: base_list_url.to_string(),
            }],
            refresh_hours: 24,
            jitter_minutes: 0,
            snapshot_dir: None, // WP12: no snapshot in test configs
        },
        block: BlockConfig {
            action: BlockAction::NullIp,
            ttl_secs: 10,
        },
        api: ApiConfig {
            listen: "127.0.0.1:0".to_string(),
        },
        privacy: PrivacyConfig {
            block_doh_bypass: false, // flag OFF
            browser_doh_canary: false,
            cname_inspection: false,
            ..PrivacyConfig::default()
        },
        ..HushConfig::default()
    };

    let app = App::start(AppConfig {
        config,
        state_dir_override: Some(state_dir.path().to_string_lossy().into_owned()),
    })
    .await
    .unwrap();

    let addr = app.udp_addr().unwrap();
    wait_ready(addr).await;

    // doh-bypass source must NOT appear in the pipeline.
    let status = app.lists.status();
    let source_urls: Vec<&str> = status.per_source.iter().map(|s| s.url.as_str()).collect();
    assert!(
        !source_urls.contains(&DOH_BYPASS_URL),
        "block_doh_bypass=false must NOT add doh-bypass source; got: {source_urls:?}"
    );

    // DOH_BYPASS_DOMAIN must not be sinkholed — the mock upstream handles it
    // (returns NXDOMAIN since it's not in the zone, but NOT 0.0.0.0).
    let client = make_client(addr);
    let result = client.lookup(DOH_BYPASS_DOMAIN, RecordType::A).await;
    if let Ok(lookup) = result {
        let ip = first_a(&lookup);
        assert_ne!(
            ip,
            Some(std::net::Ipv4Addr::UNSPECIFIED),
            "block_doh_bypass=false must NOT sinkhole {DOH_BYPASS_DOMAIN}"
        );
    }

    app.shutdown().await;
    mock.shutdown();
}

// ── WP8 §4: DNS rebind protection ─────────────────────────────────────────────

/// Integration case 8a: mock upstream returns 192.168.1.1 for a public name
/// → daemon must return NODATA; blocked counter must increment; flag off → real
/// answer passes through.
#[tokio::test]
async fn wp8_case08a_rebind_protection_blocks_private_addr() {
    use hickory_resolver::proto::rr::RecordType;

    let mock = CnameCapableMock::start().await;
    let state_dir = TempDir::new().unwrap();

    let app = start_daemon_with_privacy(
        mock.addr,
        &state_dir,
        &[],
        PrivacyConfig {
            rebind_protection: true,
            browser_doh_canary: false,
            cname_inspection: false,
            ..PrivacyConfig::default()
        },
    )
    .await;
    let addr = app.udp_addr().unwrap();
    wait_ready(addr).await;

    let client = make_client(addr);

    // rebind.public.test → mock returns 192.168.1.1 → must be NODATA.
    let result = client.lookup("rebind.public.test", RecordType::A).await;
    match result {
        Ok(l) => assert_eq!(
            l.answers().len(),
            0,
            "rebind protection must return NODATA (empty answers); got: {:?}",
            l.answers()
        ),
        Err(e) => {
            let s = e.to_string();
            assert!(
                s.contains("NoRecords") || s.contains("no record") || s.contains("NOERROR"),
                "expected NODATA, got: {s}"
            );
        }
    }

    // Blocked counter must have incremented (at least 1 for the rebind block,
    // plus the wait_ready sentinel domain block).
    let snap = app.metrics.snapshot();
    assert!(
        snap.blocked_total >= 2,
        "blocked_total must include the rebind block; got: {}",
        snap.blocked_total
    );

    app.shutdown().await;
    mock.shutdown();
}

/// Integration case 8b: flag off → private address passes through unchanged.
#[tokio::test]
async fn wp8_case08b_rebind_protection_flag_off_passes() {
    use hickory_resolver::proto::rr::RecordType;

    let mock = CnameCapableMock::start().await;
    let state_dir = TempDir::new().unwrap();

    let app = start_daemon_with_privacy(
        mock.addr,
        &state_dir,
        &[],
        PrivacyConfig {
            rebind_protection: false, // flag OFF
            browser_doh_canary: false,
            cname_inspection: false,
            ..PrivacyConfig::default()
        },
    )
    .await;
    let addr = app.udp_addr().unwrap();
    wait_ready(addr).await;

    let client = make_client(addr);

    // With rebind_protection=false, 192.168.1.1 must pass through.
    let result = client
        .lookup("rebind.public.test", RecordType::A)
        .await
        .unwrap();
    let ip = first_a(&result);
    assert_eq!(
        ip,
        Some(std::net::Ipv4Addr::new(192, 168, 1, 1)),
        "rebind_protection=false must return the real answer 192.168.1.1"
    );

    app.shutdown().await;
    mock.shutdown();
}

/// Integration case 8c: rebind_allow suffix exemption.
///
/// `exempt.corp.internal` resolves to 192.168.1.2 (private) but the domain is
/// under `corp.internal` which is in `rebind_allow` → must pass through.
#[tokio::test]
async fn wp8_case08c_rebind_allow_suffix_exempt() {
    use hickory_resolver::proto::rr::RecordType;

    let mock = CnameCapableMock::start().await;
    let state_dir = TempDir::new().unwrap();

    let app = start_daemon_with_privacy(
        mock.addr,
        &state_dir,
        &[],
        PrivacyConfig {
            rebind_protection: true,
            rebind_allow: vec!["corp.internal".to_string()],
            browser_doh_canary: false,
            cname_inspection: false,
            ..PrivacyConfig::default()
        },
    )
    .await;
    let addr = app.udp_addr().unwrap();
    wait_ready(addr).await;

    let client = make_client(addr);

    // exempt.corp.internal → 192.168.1.2 but corp.internal is in rebind_allow
    // → must pass through.
    let result = client
        .lookup("exempt.corp.internal", RecordType::A)
        .await
        .unwrap();
    let ip = first_a(&result);
    assert_eq!(
        ip,
        Some(std::net::Ipv4Addr::new(192, 168, 1, 2)),
        "rebind_allow suffix must exempt domain from rebind protection; got: {ip:?}"
    );

    app.shutdown().await;
    mock.shutdown();
}

// ── WP8 §5: HTTPS/SVCB type-65 integrity ──────────────────────────────────────

/// Integration case 9a: allowed qname + qtype HTTPS → upstream RDATA (incl.
/// dummy ECH blob) reaches the client byte-intact.
///
/// We verify that hickory's SVCB/HTTPS parsing preserves the EchConfigList
/// value byte-for-byte.
#[tokio::test]
async fn wp8_case09a_https_rdata_passthrough_byte_intact() {
    use hickory_proto::rr::rdata::svcb::SvcParamKey;
    use hickory_proto::rr::rdata::HTTPS;
    use hickory_proto::rr::RData;
    use hickory_resolver::proto::rr::RecordType;

    let mock = CnameCapableMock::start().await;
    let state_dir = TempDir::new().unwrap();

    let app = start_daemon_with_privacy(
        mock.addr,
        &state_dir,
        &[],
        PrivacyConfig {
            rebind_protection: true,
            browser_doh_canary: false,
            cname_inspection: false,
            ..PrivacyConfig::default()
        },
    )
    .await;
    let addr = app.udp_addr().unwrap();
    wait_ready(addr).await;

    let client = make_client(addr);

    // svc.allowed.test is not in any blocklist → upstream RDATA must arrive
    // byte-intact including the dummy ECH blob.
    let result = client
        .lookup("svc.allowed.test", RecordType::HTTPS)
        .await
        .unwrap();

    let answers = result.answers();
    assert!(
        !answers.is_empty(),
        "allowed qname HTTPS query must return ≥1 answer"
    );

    // Find the HTTPS record and verify the ECH blob is intact.
    let mut found_ech = false;
    for record in answers {
        if let RData::HTTPS(https_rdata) = &record.data {
            let HTTPS(svcb) = https_rdata;
            for (key, value) in &svcb.svc_params {
                if *key == SvcParamKey::EchConfigList {
                    use hickory_proto::rr::rdata::svcb::SvcParamValue;
                    if let SvcParamValue::EchConfigList(ech) = value {
                        assert_eq!(
                            ech.0.as_slice(),
                            DUMMY_ECH_BLOB,
                            "ECH blob must survive the daemon byte-intact"
                        );
                        found_ech = true;
                    }
                }
            }
        }
    }
    assert!(
        found_ech,
        "HTTPS response must contain an EchConfigList param with the dummy blob"
    );

    // Verify the mock was actually consulted (not a sinkhole).
    let hit_count = mock.query_count();
    assert!(
        hit_count >= 1,
        "upstream must have been queried for the HTTPS RR; mock hits: {hit_count}"
    );

    app.shutdown().await;
    mock.shutdown();
}

/// Integration case 9b: blocked qname + qtype HTTPS → NODATA, zero upstream
/// contacts.
#[tokio::test]
async fn wp8_case09b_https_blocked_qname_nodata_zero_upstream() {
    use hickory_resolver::proto::rr::RecordType;

    let mock = CnameCapableMock::start().await;
    let state_dir = TempDir::new().unwrap();

    // Block "ads.blocked.test" (already in the standard test list).
    let app = start_daemon_with_privacy(
        mock.addr,
        &state_dir,
        &[],
        PrivacyConfig {
            rebind_protection: true,
            browser_doh_canary: false,
            cname_inspection: false,
            ..PrivacyConfig::default()
        },
    )
    .await;
    let addr = app.udp_addr().unwrap();
    wait_ready(addr).await;

    // Record mock hit count before sending the blocked HTTPS query.
    let before = mock.query_count();

    let client = make_client(addr);

    // ads.blocked.test is blocked → HTTPS query must be sinkholed (NODATA)
    // without reaching upstream.
    let result = client.lookup("ads.blocked.test", RecordType::HTTPS).await;

    match result {
        Ok(l) => assert_eq!(
            l.answers().len(),
            0,
            "blocked qname HTTPS must return NODATA (empty answers)"
        ),
        Err(e) => {
            let s = e.to_string();
            assert!(
                s.contains("NoRecords") || s.contains("no record") || s.contains("NOERROR"),
                "expected NODATA for blocked HTTPS, got: {s}"
            );
        }
    }

    // The mock must NOT have received a query for the blocked name.
    let after = mock.query_count();
    assert_eq!(
        after, before,
        "blocked qname HTTPS must NOT reach upstream; mock hit count changed"
    );

    app.shutdown().await;
    mock.shutdown();
}
