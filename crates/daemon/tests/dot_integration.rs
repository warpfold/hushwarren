//! DoT (DNS-over-TLS) integration test — WP14 §1 mandatory test.
//!
//! Boots a SinkholeHandler pipeline against an in-process decision engine,
//! wraps it in an inbound DoT listener on an ephemeral port, performs a TLS
//! handshake trusting the daemon's self-signed certificate, sends a blocked
//! query, and asserts the answer is sinkholed (0.0.0.0).
//!
//! This proves the DoT pipeline identity: TLS framing → SinkholeHandler →
//! BlockAction::Sinkhole → 0.0.0.0 reply.
//!
//! # No sleeps
//!
//! `wait_ready_dot` polls with a 5-second deadline.
//!
//! # Port 853 / root
//!
//! `bind_inbound_tls` accepts a `dot_port` argument; we pass `0` so the OS
//! assigns an ephemeral port — no root required.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{net::SocketAddr, sync::Arc, time::Duration};

use hush_core::{
    config::{BlockAction, InboundTlsConfig, PrivacyConfig, QueryLogMode},
    rules::RuleSink as _,
    DecisionEngine, Domain, RulesBuilder,
};
use hush_daemon::{
    dns::{HandlerState, SinkholeHandler},
    inbound_tls::{bind_inbound_tls, ensure_self_signed_cert},
    metrics::Metrics,
    rollup,
    upstream::UpstreamLadder,
};
use rustls::{
    pki_types::{CertificateDer, ServerName},
    ClientConfig, RootCertStore,
};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use tokio_rustls::TlsConnector;

// ── Wire helpers ──────────────────────────────────────────────────────────────

/// Minimal A-query for `ads.blocked.test` (will be blocked before forwarding).
fn blocked_query_wire() -> Vec<u8> {
    vec![
        0x12, 0x34, // ID
        0x01, 0x00, // flags: RD=1
        0x00, 0x01, // QDCOUNT=1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ANC/NSC/ARC = 0
        // QNAME: ads.blocked.test.
        0x03, b'a', b'd', b's', 0x07, b'b', b'l', b'o', b'c', b'k', b'e', b'd', 0x04, b't', b'e',
        b's', b't', 0x00, 0x00, 0x01, // QTYPE A
        0x00, 0x01, // QCLASS IN
    ]
}

/// Build a rustls ClientConfig that trusts only the self-signed cert in `tls_dir`.
fn make_test_client_config(tls_dir: &std::path::Path) -> Arc<ClientConfig> {
    let cert_pem = std::fs::read(tls_dir.join("cert.pem")).expect("cert.pem");
    let cert_ders: Vec<CertificateDer<'static>> =
        rustls::pki_types::pem::PemObject::pem_slice_iter(&cert_pem)
            .collect::<Result<Vec<_>, _>>()
            .expect("parse PEM");
    let mut roots = RootCertStore::empty();
    for c in cert_ders {
        roots.add(c).expect("add cert");
    }
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// Poll the DoT listener until it responds.  5-second deadline.
async fn wait_ready_dot(dot_addr: SocketAddr, client_cfg: Arc<ClientConfig>) {
    let connector = TlsConnector::from(Arc::clone(&client_cfg));
    let sni = ServerName::try_from("127.0.0.1").unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let query = blocked_query_wire();
    let mut framed = (query.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&query);

    loop {
        if let Ok(tcp) = TcpStream::connect(dot_addr).await {
            if let Ok(mut tls) = connector.connect(sni.clone(), tcp).await {
                let _ = tls.write_all(&framed).await;
                let mut lb = [0u8; 2];
                if timeout(Duration::from_millis(500), tls.read_exact(&mut lb))
                    .await
                    .is_ok()
                {
                    return;
                }
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "DoT listener not ready within 5 s"
        );
        tokio::task::yield_now().await;
    }
}

// ── Test ──────────────────────────────────────────────────────────────────────

/// Boot a DoT listener on an ephemeral port, send a blocked query, assert sinkholed.
///
/// Mandatory pipeline identity test (`specs/wp14-nice.md` §4).
#[tokio::test]
async fn dot_blocked_name_is_sinkholed() {
    // Install the ring crypto provider (required by rustls when multiple
    // features are in the build graph; harmless if already installed).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let state_dir = TempDir::new().unwrap();
    let cancel = tokio_util::sync::CancellationToken::new();

    // ── Decision engine with one blocked domain ───────────────────────────────
    let engine = Arc::new(DecisionEngine::new());
    {
        let mut builder = RulesBuilder::new();
        builder.add_source_name("test");
        builder.block(Domain::parse("ads.blocked.test").unwrap());
        let compiled = builder.build().unwrap();
        engine.swap_rules(Arc::new(compiled));
    }

    // ── Upstream ladder (empty — blocked names never reach it) ────────────────
    let ladder = {
        use hush_core::config::UpstreamConfig;
        let empty = UpstreamConfig {
            doh: vec![],
            do53_fallback: vec![],
            ..UpstreamConfig::default()
        };
        UpstreamLadder::from_config(&empty, &PrivacyConfig::default()).unwrap()
    };
    let ladder = Arc::new(ladder);

    // ── Shared infra (ring, metrics, rollup) ──────────────────────────────────
    let ring = Arc::new(hush_core::QueryRing::new(256));
    let metrics = Arc::new(Metrics::new());
    let rollup = rollup::start_rollup(
        state_dir.path().to_path_buf(),
        QueryLogMode::Off,
        7,
        cancel.clone(),
    );

    // ── SinkholeHandler ───────────────────────────────────────────────────────
    let privacy_arc = Arc::new(arc_swap::ArcSwap::from_pointee(PrivacyConfig::default()));
    let handler_state = Arc::new(HandlerState {
        engine,
        ladder,
        ring,
        rollup,
        metrics,
        block_action: BlockAction::NullIp,
        block_ttl_secs: 42,
        privacy: privacy_arc,
        log_clients: false,
    });
    let handler = SinkholeHandler::new(handler_state);

    // ── Self-signed cert (generate before bind so we can load it for trust) ───
    let tls_cfg = InboundTlsConfig {
        enabled: true,
        bind: vec!["127.0.0.1".to_string()],
        cert_path: String::new(),
        key_path: String::new(),
        doq: false,
    };
    ensure_self_signed_cert(&tls_cfg, state_dir.path()).unwrap();

    // ── Bind DoT on port 0 (ephemeral) ────────────────────────────────────────
    let (bound, _task) = bind_inbound_tls(
        &tls_cfg,
        handler,
        state_dir.path(),
        cancel.clone(),
        0, // 0 = OS-assigned ephemeral port
    )
    .await
    .expect("bind DoT");
    let dot_addr = bound.dot_addrs[0];

    // ── Trust store from the generated cert ───────────────────────────────────
    let tls_dir = state_dir.path().join("inbound-tls");
    let client_cfg = make_test_client_config(&tls_dir);

    // ── Wait for listener ─────────────────────────────────────────────────────
    wait_ready_dot(dot_addr, Arc::clone(&client_cfg)).await;

    // ── Send a DoT query (RFC 7858: 2-byte length prefix + DNS wire) ──────────
    let connector = TlsConnector::from(Arc::clone(&client_cfg));
    let sni = ServerName::try_from("127.0.0.1").unwrap();
    let tcp = TcpStream::connect(dot_addr).await.unwrap();
    let mut tls = connector.connect(sni, tcp).await.unwrap();

    let query = blocked_query_wire();
    let len_prefix = (query.len() as u16).to_be_bytes();
    tls.write_all(&len_prefix).await.unwrap();
    tls.write_all(&query).await.unwrap();

    // ── Read the 2-byte length prefix ─────────────────────────────────────────
    let mut lb = [0u8; 2];
    timeout(Duration::from_secs(3), tls.read_exact(&mut lb))
        .await
        .expect("read length (timeout)")
        .expect("read length (I/O)");
    let resp_len = u16::from_be_bytes(lb) as usize;
    assert!(resp_len >= 12, "response too short: {resp_len} bytes");

    // ── Read the DNS response ─────────────────────────────────────────────────
    let mut resp = vec![0u8; resp_len];
    timeout(Duration::from_secs(3), tls.read_exact(&mut resp))
        .await
        .expect("read response (timeout)")
        .expect("read response (I/O)");

    // ── Assert ANCOUNT ≥ 1 ───────────────────────────────────────────────────
    let ancount = u16::from_be_bytes([resp[6], resp[7]]);
    assert!(
        ancount >= 1,
        "expected ≥1 sinkhole answer, got ANCOUNT={ancount}"
    );

    // ── Assert answer contains 0.0.0.0 ───────────────────────────────────────
    // The sinkhole RDATA for an A record is 4 zero bytes.
    let sinkholed = resp.windows(4).any(|w| w == [0, 0, 0, 0]);
    assert!(
        sinkholed,
        "expected 0.0.0.0 sinkhole in answer section, got: {resp:02x?}"
    );

    cancel.cancel();
}
