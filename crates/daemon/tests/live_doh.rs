//! Live DoH integration test — gated by `#[ignore]`.
//!
//! Requires real network access to the live DoH resolvers.
//! Run with: `cargo test -p hush-daemon --test live_doh -- --ignored --nocapture`
//!
//! Tests in this file:
//! - `live_doh_cloudflare` — Cloudflare (default ladder rung 0)
//! - `live_doh_quad9` — Quad9 (default ladder rung 1).  Quad9 dropped HTTP/1.1
//!   DoH on 2025-12-15; hickory's DoH client is h2-only — this test passing
//!   proves the h2 path against the second rung of the default ladder.
//! - `live_doh_mullvad` — Mullvad (mullvad preset, rung 0; unfiltered endpoint).
//!
//! Per `specs/standards.md` §5 (live tests are the ONLY layer allowed to touch
//! the real internet, gated `#[ignore]`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use hush_core::config::{
    ApiConfig, BlockConfig, DohEndpoint, HushConfig, ListSource, ListenConfig, ListsConfig,
    UpstreamConfig,
};
use hush_daemon::app::{App, AppConfig};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::net::UdpSocket;

// Wire encoding of "cloudflare.com" A query
const CLOUDFLARE_COM: &[u8] = &[
    0x0A, b'c', b'l', b'o', b'u', b'd', b'f', b'l', b'a', b'r', b'e', 0x03, b'c', b'o', b'm', 0x00,
];

// Wire encoding of "example.com" A query (neutral, IANA-reserved domain)
const EXAMPLE_COM: &[u8] = &[
    0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
];

fn build_a_query(id: u16, qname_wire: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(12 + qname_wire.len() + 4);
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.push(0x01);
    pkt.push(0x00);
    pkt.push(0x00);
    pkt.push(0x01);
    pkt.push(0x00);
    pkt.push(0x00);
    pkt.push(0x00);
    pkt.push(0x00);
    pkt.push(0x00);
    pkt.push(0x00);
    pkt.extend_from_slice(qname_wire);
    pkt.push(0x00);
    pkt.push(0x01);
    pkt.push(0x00);
    pkt.push(0x01);
    pkt
}

/// Live test: resolve `cloudflare.com` A through the DoH rung.
///
/// Asserts non-empty answer + logs latency.
#[tokio::test]
#[ignore = "requires real network; run with --ignored"]
async fn live_doh_cloudflare() {
    let state_dir = TempDir::new().unwrap();
    let lists_dir = state_dir.path().join("lists");
    std::fs::create_dir_all(&lists_dir).unwrap();

    let config = HushConfig {
        listen: ListenConfig {
            udp: vec!["127.0.0.1:0".to_string()],
            tcp: vec!["127.0.0.1:0".to_string()],
        },
        upstream: UpstreamConfig {
            doh: vec![DohEndpoint {
                url: "https://cloudflare-dns.com/dns-query".to_string(),
                bootstrap_ips: vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()],
            }],
            do53_fallback: vec![],
            ..UpstreamConfig::default()
        },
        lists: ListsConfig {
            preset: "custom".to_string(),
            extra_categories: Vec::new(),
            sources: vec![ListSource {
                name: "empty".to_string(),
                url: "http://127.0.0.1:1/list".to_string(),
            }],
            refresh_hours: 24,
            jitter_minutes: 0,
            snapshot_dir: None, // WP12: no snapshot in test configs
        },
        block: BlockConfig::default(),
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

    let daemon_addr = app.udp_addr().unwrap();

    // Send a raw A query for cloudflare.com and measure latency.
    let query = build_a_query(0xCF01, CLOUDFLARE_COM);
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let t0 = Instant::now();
    sock.send_to(&query, daemon_addr).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let result = tokio::time::timeout(Duration::from_secs(10), sock.recv_from(&mut buf))
        .await
        .expect("timeout waiting for DoH response")
        .expect("recv_from error");
    let latency = t0.elapsed();

    let (n, _) = result;
    let resp = &buf[..n];
    println!("live_doh_cloudflare: latency={latency:?} response_bytes={n}");

    assert!(n >= 12, "response too short");
    let rcode = resp[3] & 0x0F;
    assert_eq!(rcode, 0, "must return NOERROR, got RCODE={rcode}");
    let ancount = u16::from_be_bytes([resp[6], resp[7]]);
    assert!(
        ancount > 0,
        "cloudflare.com must have at least one A record"
    );

    app.shutdown().await;
}

/// Live test: resolve `example.com` A through Quad9's DoH rung.
///
/// WHY this test exists: Quad9 dropped HTTP/1.1 DoH support on 2025-12-15;
/// only HTTP/2 is now accepted.  hickory-resolver's DoH client is h2-only,
/// so this test passing proves the h2 path works against the second rung of
/// the default ladder.  It is a CI live-test regression guard for that change.
/// Per `docs/privacy-roadmap.md` §4.
#[tokio::test]
#[ignore = "requires real network; run with --ignored"]
async fn live_doh_quad9() {
    let state_dir = TempDir::new().unwrap();
    let lists_dir = state_dir.path().join("lists");
    std::fs::create_dir_all(&lists_dir).unwrap();

    let config = HushConfig {
        listen: ListenConfig {
            udp: vec!["127.0.0.1:0".to_string()],
            tcp: vec!["127.0.0.1:0".to_string()],
        },
        upstream: UpstreamConfig {
            doh: vec![DohEndpoint {
                url: "https://dns.quad9.net/dns-query".to_string(),
                bootstrap_ips: vec!["9.9.9.9".to_string(), "149.112.112.112".to_string()],
            }],
            do53_fallback: vec![],
            ..UpstreamConfig::default()
        },
        lists: ListsConfig {
            preset: "custom".to_string(),
            extra_categories: Vec::new(),
            sources: vec![ListSource {
                name: "empty".to_string(),
                url: "http://127.0.0.1:1/list".to_string(),
            }],
            refresh_hours: 24,
            jitter_minutes: 0,
            snapshot_dir: None, // WP12: no snapshot in test configs
        },
        block: BlockConfig::default(),
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

    let daemon_addr = app.udp_addr().unwrap();

    // Send a raw A query for example.com and measure latency.
    let query = build_a_query(0xD901, EXAMPLE_COM);
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let t0 = Instant::now();
    sock.send_to(&query, daemon_addr).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let result = tokio::time::timeout(Duration::from_secs(10), sock.recv_from(&mut buf))
        .await
        .expect("timeout waiting for DoH response")
        .expect("recv_from error");
    let latency = t0.elapsed();

    let (n, _) = result;
    let resp = &buf[..n];
    println!("live_doh_quad9: latency={latency:?} response_bytes={n}");

    assert!(n >= 12, "response too short");
    let rcode = resp[3] & 0x0F;
    assert_eq!(rcode, 0, "must return NOERROR, got RCODE={rcode}");
    let ancount = u16::from_be_bytes([resp[6], resp[7]]);
    assert!(ancount > 0, "example.com must have at least one A record");

    app.shutdown().await;
}

/// Live test: resolve `example.com` A through Mullvad's DoH rung.
///
/// Uses the unfiltered Mullvad endpoint (`dns.mullvad.net/dns-query`, anycast
/// `194.242.2.2`) — the same endpoint the `"mullvad"` upstream preset selects.
/// Our blocking happens locally; the unfiltered profile ensures Mullvad itself
/// does not double-filter.  Per `docs/privacy-roadmap.md` §4.
#[tokio::test]
#[ignore = "requires real network; run with --ignored"]
async fn live_doh_mullvad() {
    let state_dir = TempDir::new().unwrap();
    let lists_dir = state_dir.path().join("lists");
    std::fs::create_dir_all(&lists_dir).unwrap();

    let config = HushConfig {
        listen: ListenConfig {
            udp: vec!["127.0.0.1:0".to_string()],
            tcp: vec!["127.0.0.1:0".to_string()],
        },
        upstream: UpstreamConfig {
            doh: vec![DohEndpoint {
                // Verified 2026-06-12: https://mullvad.net/en/help/dns-over-https-and-dns-over-tls
                // Unfiltered endpoint; anycast IPv4 194.242.2.2.
                url: "https://dns.mullvad.net/dns-query".to_string(),
                bootstrap_ips: vec!["194.242.2.2".to_string()],
            }],
            do53_fallback: vec![],
            ..UpstreamConfig::default()
        },
        lists: ListsConfig {
            preset: "custom".to_string(),
            extra_categories: Vec::new(),
            sources: vec![ListSource {
                name: "empty".to_string(),
                url: "http://127.0.0.1:1/list".to_string(),
            }],
            refresh_hours: 24,
            jitter_minutes: 0,
            snapshot_dir: None, // WP12: no snapshot in test configs
        },
        block: BlockConfig::default(),
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

    let daemon_addr = app.udp_addr().unwrap();

    // Send a raw A query for example.com and measure latency.
    let query = build_a_query(0xDA02, EXAMPLE_COM);
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let t0 = Instant::now();
    sock.send_to(&query, daemon_addr).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let result = tokio::time::timeout(Duration::from_secs(10), sock.recv_from(&mut buf))
        .await
        .expect("timeout waiting for DoH response")
        .expect("recv_from error");
    let latency = t0.elapsed();

    let (n, _) = result;
    let resp = &buf[..n];
    println!("live_doh_mullvad: latency={latency:?} response_bytes={n}");

    assert!(n >= 12, "response too short");
    let rcode = resp[3] & 0x0F;
    assert_eq!(rcode, 0, "must return NOERROR, got RCODE={rcode}");
    let ancount = u16::from_be_bytes([resp[6], resp[7]]);
    assert!(ancount > 0, "example.com must have at least one A record");

    app.shutdown().await;
}

// ── WP8 §2 — live DoH3 tests ──────────────────────────────────────────────────

/// Live DoH3 test against Cloudflare's public DoH3 endpoint.
///
/// Proves real h3 (HTTP/3 over QUIC) negotiation through the daemon's h3-ring
/// rung.  If QUIC/UDP-443 is blocked on this network, the h3 rung will time out
/// and the test will report the failure clearly.
///
/// Run with: `cargo test -p hush-daemon --test live_doh -- --ignored --nocapture`
#[tokio::test]
#[ignore = "requires real network + unblocked UDP/443; run with --ignored"]
async fn live_doh3_cloudflare() {
    let state_dir = tempfile::TempDir::new().unwrap();
    let lists_dir = state_dir.path().join("lists");
    std::fs::create_dir_all(&lists_dir).unwrap();

    let config = hush_core::config::HushConfig {
        listen: ListenConfig {
            udp: vec!["127.0.0.1:0".to_string()],
            tcp: vec!["127.0.0.1:0".to_string()],
        },
        upstream: UpstreamConfig {
            preset: "default".to_string(),
            h3: true, // enable DoH3 rungs
            doh: vec![DohEndpoint {
                url: "https://cloudflare-dns.com/dns-query".to_string(),
                bootstrap_ips: vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()],
            }],
            do53_fallback: vec![],
            ..UpstreamConfig::default()
        },
        lists: ListsConfig {
            preset: "custom".to_string(),
            extra_categories: Vec::new(),
            sources: vec![ListSource {
                name: "empty".to_string(),
                url: "http://127.0.0.1:1/list".to_string(),
            }],
            refresh_hours: 24,
            jitter_minutes: 0,
            snapshot_dir: None, // WP12: no snapshot in test configs
        },
        block: BlockConfig::default(),
        api: ApiConfig {
            listen: "127.0.0.1:0".to_string(),
        },
        ..hush_core::config::HushConfig::default()
    };

    let app = App::start(AppConfig {
        config,
        state_dir_override: Some(state_dir.path().to_string_lossy().into_owned()),
    })
    .await
    .unwrap();

    let daemon_addr = app.udp_addr().unwrap();

    let query = build_a_query(0xCF03, CLOUDFLARE_COM);
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let t0 = Instant::now();
    sock.send_to(&query, daemon_addr).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let result = tokio::time::timeout(Duration::from_secs(10), sock.recv_from(&mut buf))
        .await
        .expect("timeout waiting for DoH3 response")
        .expect("recv_from error");
    let latency = t0.elapsed();

    let (n, _) = result;
    let resp = &buf[..n];
    println!("live_doh3_cloudflare: latency={latency:?} response_bytes={n}");

    assert!(n >= 12, "response too short");
    let rcode = resp[3] & 0x0F;
    assert_eq!(rcode, 0, "must return NOERROR, got RCODE={rcode}");
    let ancount = u16::from_be_bytes([resp[6], resp[7]]);
    assert!(
        ancount > 0,
        "cloudflare.com must have at least one A record (DoH3)"
    );

    app.shutdown().await;
}

/// Live DoH3 test against Quad9's public DoH3 endpoint.
///
/// Quad9 announced DoH3 GA on 2026-03-31.  This test proves real h3
/// negotiation through the daemon's Quad9 h3-ring rung.
///
/// Run with: `cargo test -p hush-daemon --test live_doh -- --ignored --nocapture`
#[tokio::test]
#[ignore = "requires real network + unblocked UDP/443; run with --ignored"]
async fn live_doh3_quad9() {
    let state_dir = tempfile::TempDir::new().unwrap();
    let lists_dir = state_dir.path().join("lists");
    std::fs::create_dir_all(&lists_dir).unwrap();

    let config = hush_core::config::HushConfig {
        listen: ListenConfig {
            udp: vec!["127.0.0.1:0".to_string()],
            tcp: vec!["127.0.0.1:0".to_string()],
        },
        upstream: UpstreamConfig {
            preset: "default".to_string(),
            h3: true, // enable DoH3 rungs
            doh: vec![DohEndpoint {
                url: "https://dns.quad9.net/dns-query".to_string(),
                bootstrap_ips: vec!["9.9.9.9".to_string(), "149.112.112.112".to_string()],
            }],
            do53_fallback: vec![],
            ..UpstreamConfig::default()
        },
        lists: ListsConfig {
            preset: "custom".to_string(),
            extra_categories: Vec::new(),
            sources: vec![ListSource {
                name: "empty".to_string(),
                url: "http://127.0.0.1:1/list".to_string(),
            }],
            refresh_hours: 24,
            jitter_minutes: 0,
            snapshot_dir: None, // WP12: no snapshot in test configs
        },
        block: BlockConfig::default(),
        api: ApiConfig {
            listen: "127.0.0.1:0".to_string(),
        },
        ..hush_core::config::HushConfig::default()
    };

    let app = App::start(AppConfig {
        config,
        state_dir_override: Some(state_dir.path().to_string_lossy().into_owned()),
    })
    .await
    .unwrap();

    let daemon_addr = app.udp_addr().unwrap();

    let query = build_a_query(0xD903, EXAMPLE_COM);
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let t0 = Instant::now();
    sock.send_to(&query, daemon_addr).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let result = tokio::time::timeout(Duration::from_secs(10), sock.recv_from(&mut buf))
        .await
        .expect("timeout waiting for DoH3 response")
        .expect("recv_from error");
    let latency = t0.elapsed();

    let (n, _) = result;
    let resp = &buf[..n];
    println!("live_doh3_quad9: latency={latency:?} response_bytes={n}");

    assert!(n >= 12, "response too short");
    let rcode = resp[3] & 0x0F;
    assert_eq!(rcode, 0, "must return NOERROR, got RCODE={rcode}");
    let ancount = u16::from_be_bytes([resp[6], resp[7]]);
    assert!(
        ancount > 0,
        "example.com must have at least one A record (DoH3 via Quad9)"
    );

    app.shutdown().await;
}
