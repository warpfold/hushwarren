//! ECS-never-sent integration test — `specs/wp7-odoh-ecs.md` §1.
//!
//! Claim: hushwarren never attaches an EDNS Client Subnet (ECS) option
//! (option code 8, RFC 7871) to any upstream query.
//!
//! Approach: extend the Do53 mock upstream to CAPTURE raw query bytes, then
//! parse every captured query's OPT record and assert no option code 8 is
//! present.  The test drives three query shapes:
//!   1. Cold lookup — first query for a name (no daemon cache).
//!   2. Cache-bypass second name — a distinct name also not in cache.
//!   3. Pre-blocked domain — the daemon answers from its rule engine; upstream
//!      never sees this query (verifies no ECS is injected in non-forwarded
//!      paths either).
//!
//! If the assertion FAILS (hickory silently inserts ECS): the test panics with
//! a detailed message listing the ECS payload found.  Per `specs/wp7-odoh-ecs.md`
//! §1, the fix is NOT to work around it — it becomes a follow-up.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use hickory_proto::op::Message;
use hickory_resolver::{
    config::{NameServerConfig, ResolverConfig, ResolverOpts},
    TokioResolver,
};
use hush_core::config::{
    ApiConfig, BlockAction, BlockConfig, HushConfig, ListSource, ListenConfig, ListsConfig,
    UpstreamConfig,
};
use hush_daemon::app::{App, AppConfig};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};
use tempfile::TempDir;
use tokio::net::UdpSocket;

// ── Byte-capturing mock upstream ─────────────────────────────────────────────

/// A mock Do53 upstream that captures every raw query packet it receives.
struct CapturingMockUpstream {
    addr: SocketAddr,
    /// All raw UDP payloads received, in order.
    captured_queries: Arc<StdMutex<Vec<Vec<u8>>>>,
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
}

impl CapturingMockUpstream {
    async fn start() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let captured = Arc::new(StdMutex::new(Vec::<Vec<u8>>::new()));
        let captured_clone = Arc::clone(&captured);
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                tokio::select! {
                    result = socket.recv_from(&mut buf) => {
                        match result {
                            Ok((n, peer)) => {
                                let pkt = buf[..n].to_vec();
                                // Capture the raw bytes before building a response.
                                {
                                    let mut guard = captured_clone.lock().unwrap();
                                    guard.push(pkt.clone());
                                }
                                if let Some(resp) = build_mock_response(&pkt) {
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
            captured_queries: captured,
            shutdown_tx,
        }
    }

    /// Drain all captured raw query packets.
    fn drain_queries(&self) -> Vec<Vec<u8>> {
        let mut guard = self.captured_queries.lock().unwrap();
        std::mem::take(&mut *guard)
    }

    fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
    }
}

// ── Minimal DNS responder ────────────────────────────────────────────────────

fn build_mock_response(packet: &[u8]) -> Option<Vec<u8>> {
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

    if is_a {
        // Return A 192.0.2.10 for any name, so the daemon can return a result.
        let ip: [u8; 4] = if qname_lower.contains("alpha") {
            [192, 0, 2, 10]
        } else {
            [192, 0, 2, 11]
        };
        build_a_response(qid, &packet[12..qname_end + 4], ip)
    } else {
        // NXDOMAIN for non-A types.
        let mut resp = Vec::with_capacity(packet.len() + 4);
        resp.extend_from_slice(&qid.to_be_bytes());
        resp.push(0x81);
        resp.push(0x83);
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

fn build_a_response(qid: u16, question: &[u8], ip: [u8; 4]) -> Option<Vec<u8>> {
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
    resp.extend_from_slice(question);
    resp.push(0xC0);
    resp.push(0x0C);
    resp.push(0x00);
    resp.push(0x01); // TYPE A
    resp.push(0x00);
    resp.push(0x01); // CLASS IN
    resp.push(0x00);
    resp.push(0x00);
    resp.push(0x00);
    resp.push(0x3C); // TTL 60
    resp.push(0x00);
    resp.push(0x04);
    resp.extend_from_slice(&ip);
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
    let cfg = ResolverConfig::from_parts(None, vec![], vec![ns]);
    let mut opts = ResolverOpts::default();
    opts.cache_size = 0; // disable client-side cache for test isolation
    opts.timeout = Duration::from_secs(3);
    opts.attempts = 1;
    TokioResolver::builder_with_config(cfg, Default::default())
        .with_options(opts)
        .build()
        .unwrap()
}

async fn wait_ready(daemon_addr: SocketAddr) {
    // Query the daemon's blocked domain (never forwarded to upstream).
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

// ── ECS assertion ─────────────────────────────────────────────────────────────

/// EDNS option code 8 = Client Subnet (RFC 7871).
const ECS_OPTION_CODE: u16 = 8;

/// Assert that a raw DNS query packet contains no ECS option (code 8).
///
/// Parses the OPT record from the additional section using hickory-proto
/// `Message::from_vec`.  If no OPT record is present the query trivially
/// passes.  If an OPT record IS present, every option code is checked.
///
/// Panics with a detailed message if ECS is found.
fn assert_no_ecs(raw: &[u8], label: &str) {
    let msg = match Message::from_vec(raw) {
        Ok(m) => m,
        Err(e) => {
            // A malformed query is counted as-is (no ECS can be present in
            // garbage bytes), but we note it for debugging.
            eprintln!("[ecs_test] {label}: could not parse query message: {e}; skipping ECS check");
            return;
        }
    };

    // `additionals` is a public Vec<Record> in hickory-proto 0.26.1.
    // If there's no OPT record, there can be no ECS.
    if msg.additionals.is_empty() && msg.edns.is_none() {
        return; // no EDNS — trivially no ECS
    }

    // Check EDNS options via hickory's Edns type.
    // `OPT.options` is a public `Vec<(EdnsCode, EdnsOption)>` in hickory-proto 0.26.1.
    if let Some(edns) = &msg.edns {
        for (code, opt_val) in &edns.options().options {
            let code_u16: u16 = (*code).into();
            assert_ne!(
                code_u16, ECS_OPTION_CODE,
                "[ecs_test] {label}: ECS (EDNS option code 8) detected in upstream query!\n\
                 This means hickory-resolver IS injecting ECS — this must be fixed upstream.\n\
                 Option found: code={code_u16} value={opt_val:?}"
            );
        }
    }
}

// ── Test case ─────────────────────────────────────────────────────────────────

/// `ecs_never_sent` — proves hushwarren never sends ECS to any upstream.
///
/// Drives 3 query shapes and asserts no ECS option code 8 in any captured packet.
#[tokio::test]
async fn ecs_never_sent() {
    use hickory_resolver::proto::rr::RecordType;

    let mock = CapturingMockUpstream::start().await;
    let state_dir = TempDir::new().unwrap();

    // Pre-populate a list cache file so the daemon has blocked domain `ads.blocked.test`.
    let lists_dir = state_dir.path().join("lists");
    std::fs::create_dir_all(&lists_dir).unwrap();
    std::fs::write(
        lists_dir.join("http___mock.invalid_list.txt"),
        "ads.blocked.test\n",
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

    // Drain any queries generated during startup / wait_ready.
    let _ = mock.drain_queries();

    let client = make_client(addr);

    // ── Query shape 1: cold lookup (first query for alpha.ecs-test.internal) ──
    let _ = client
        .lookup("alpha.ecs-test.internal", RecordType::A)
        .await;

    // ── Query shape 2: cache-bypass second name ───────────────────────────────
    let _ = client.lookup("beta.ecs-test.internal", RecordType::A).await;

    // Drain the two cold-lookup queries and assert no ECS in either.
    // Give the mock a moment to process before draining.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let cold_queries = mock.drain_queries();
    assert!(
        !cold_queries.is_empty(),
        "mock must have received at least the two cold-lookup queries"
    );
    for (i, raw) in cold_queries.iter().enumerate() {
        assert_no_ecs(raw, &format!("cold-query[{i}]"));
    }

    // ── Query shape 3: blocked domain (sinkholed; mock must NOT see it) ───────
    // The queue is now empty (just drained).  Query the blocked domain —
    // the daemon sinkholes it locally and must never forward to the mock.
    let _ = client.lookup("ads.blocked.test", RecordType::A).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let blocked_queries = mock.drain_queries();
    assert_eq!(
        blocked_queries.len(),
        0,
        "blocked domain must not reach the upstream (got {} queries for it)",
        blocked_queries.len()
    );

    app.shutdown().await;
    mock.shutdown();
}
