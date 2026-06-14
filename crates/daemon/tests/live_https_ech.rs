//! Live test: HTTPS RR with ECH SvcParams.
//!
//! Implements `specs/wp8-transport-privacy.md` §7 live test `live_https_rr_ech`.
//!
//! Queries an HTTPS RR through the daemon for a domain known to publish ECH,
//! and asserts ≥1 type-65 answer with non-empty SvcParams.  The exact ECH key
//! is NOT hard-asserted (CDN deployments drift).
//!
//! Run with:
//! ```sh
//! cargo test -p hush-daemon --test live_https_ech -- --ignored --nocapture
//! ```
//!
//! Requires internet access.  Skipped by default.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use hickory_resolver::{
    config::{NameServerConfig, ResolverConfig, ResolverOpts},
    TokioResolver,
};
use hush_core::config::{
    ApiConfig, BlockAction, BlockConfig, HushConfig, ListSource, ListenConfig, ListsConfig,
    PrivacyConfig, UpstreamConfig,
};
use hush_daemon::app::{App, AppConfig};
use std::{net::SocketAddr, time::Duration};
use tempfile::TempDir;
use tokio::net::UdpSocket;

fn make_client(daemon_addr: SocketAddr) -> TokioResolver {
    let mut ns = NameServerConfig::udp(daemon_addr.ip());
    for conn in &mut ns.connections {
        conn.port = daemon_addr.port();
    }
    let cfg = ResolverConfig::from_parts(None, vec![], vec![ns]);
    let mut opts = ResolverOpts::default();
    opts.cache_size = 0;
    opts.timeout = Duration::from_secs(5);
    opts.attempts = 2;
    TokioResolver::builder_with_config(cfg, Default::default())
        .with_options(opts)
        .build()
        .unwrap()
}

/// Wait until the daemon is ready by polling its sinkhole response.
async fn wait_ready(daemon_addr: SocketAddr) {
    let query: &[u8] = &[
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'a', b'd',
        b's', 0x07, b'b', b'l', b'o', b'c', b'k', b'e', b'd', 0x04, b't', b'e', b's', b't', 0x00,
        0x00, 0x01, 0x00, 0x01,
    ];
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        sock.send_to(query, daemon_addr).await.unwrap();
        let mut buf = [0u8; 512];
        let result =
            tokio::time::timeout(Duration::from_millis(300), sock.recv_from(&mut buf)).await;
        if let Ok(Ok((n, _))) = result {
            if n >= 12 {
                return;
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "daemon not ready within 10 seconds"
        );
        tokio::task::yield_now().await;
    }
}

/// Start a minimal daemon forwarding to real DoH upstreams (no blocklist).
async fn start_live_daemon() -> (hush_daemon::app::RunningApp, TempDir) {
    let state_dir = TempDir::new().unwrap();
    let lists_dir = state_dir.path().join("lists");
    std::fs::create_dir_all(&lists_dir).unwrap();

    // Write an empty blocklist (the test needs no blocks, only forwarding).
    let base_url = "http://mock.invalid/empty";
    std::fs::write(
        lists_dir.join(
            base_url
                .chars()
                .map(|c| {
                    if c.is_alphanumeric() || c == '.' || c == '-' {
                        c
                    } else {
                        '_'
                    }
                })
                .collect::<String>()
                + ".txt",
        ),
        "",
    )
    .unwrap();

    let config = HushConfig {
        listen: ListenConfig {
            udp: vec!["127.0.0.1:0".to_string()],
            tcp: vec!["127.0.0.1:0".to_string()],
        },
        // Use Cloudflare DoH for live tests.
        upstream: UpstreamConfig::default(),
        lists: ListsConfig {
            preset: "custom".to_string(),
            extra_categories: vec![],
            sources: vec![ListSource {
                name: "empty".to_string(),
                url: base_url.to_string(),
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
            browser_doh_canary: false,
            cname_inspection: false,
            rebind_protection: false, // don't interfere with the live ECH query
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

    (app, state_dir)
}

/// Live test: query an HTTPS RR for a domain known to publish ECH through the
/// daemon and assert ≥1 type-65 answer with non-empty SvcParams.
///
/// Tries `crypto.cloudflare.com` first (Cloudflare ECH demo), then falls back
/// to `cloudflare.com`.  Does NOT hard-assert the ECH key bytes — CDN
/// deployments drift.
///
/// Run with: `cargo test -p hush-daemon --test live_https_ech -- --ignored --nocapture`
#[tokio::test]
#[ignore]
async fn live_https_rr_ech() {
    use hickory_proto::rr::RData;
    use hickory_resolver::proto::rr::RecordType;

    let (app, _state_dir) = start_live_daemon().await;
    let addr = app.udp_addr().unwrap();
    wait_ready(addr).await;

    let client = make_client(addr);

    // Try the Cloudflare ECH demo domain first.
    let candidates = ["crypto.cloudflare.com", "cloudflare.com"];

    let mut found_svc_params = false;
    let mut last_error = String::new();

    for domain in &candidates {
        let result = client.lookup(*domain, RecordType::HTTPS).await;
        match result {
            Ok(lookup) => {
                let answers = lookup.answers();
                if answers.is_empty() {
                    last_error = format!("{domain}: no answers");
                    continue;
                }
                for record in answers {
                    if let RData::HTTPS(https_rdata) = &record.data {
                        let hickory_proto::rr::rdata::HTTPS(svcb) = https_rdata;
                        if svcb.svc_priority > 0 && !svcb.svc_params.is_empty() {
                            println!(
                                "live_https_rr_ech: {domain} → priority={}, {} SvcParams",
                                svcb.svc_priority,
                                svcb.svc_params.len()
                            );
                            for (key, _val) in &svcb.svc_params {
                                println!("  SvcParam key={key:?}");
                            }
                            found_svc_params = true;
                            break;
                        }
                    }
                }
                if found_svc_params {
                    break;
                }
                last_error = format!("{domain}: answers present but no non-empty SvcParams");
            }
            Err(e) => {
                last_error = format!("{domain}: lookup error: {e}");
            }
        }
    }

    assert!(
        found_svc_params,
        "live_https_rr_ech: no HTTPS RR with non-empty SvcParams found for any candidate; \
         last error: {last_error}"
    );

    app.shutdown().await;
}
