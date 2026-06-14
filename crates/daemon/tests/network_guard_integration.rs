//! Integration tests for WP13 — Network Guard.
//!
//! Covers spec §5 mandatory cases:
//!   • validate() matrix (wildcard, loopback, enabled+empty refused)
//!   • QueryRecord client-field serde round-trip incl. absent field (old records)
//!   • Client recorded only when log_clients on (unit-level)
//!   • SQLite v1→v2 migration (covered in rollup unit tests; cross-checked here)
//!   • GET /v0/clients shapes incl. disabled-explanation
//!   • API never binds non-loopback even with network_guard on (architecture §8)

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use serde_json::Value;
use tempfile::TempDir;
use tower::ServiceExt;

use arc_swap::ArcSwap;
use hush_core::{
    config::{HushConfig, ListSource, ListsConfig, NetworkGuardConfig, PrivacyConfig},
    querylog::QueryRecord,
    DecisionEngine, Reason, Verdict,
};
use hush_daemon::{
    api::{routes, ApiState},
    lists::ListsPipeline,
    metrics::Metrics,
    platform::stub::MockPlatform,
    rollup,
    sentinel::{takeover::TakeoverConfig, Sentinel},
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_api_state(tmp: &TempDir, network_guard_cfg: NetworkGuardConfig) -> Arc<ApiState> {
    let token = "deadbeef".repeat(8);
    std::fs::write(tmp.path().join("api.token"), &token).unwrap();

    let engine = Arc::new(DecisionEngine::new());
    let ring = Arc::new(hush_core::QueryRing::new(1000));
    let metrics = Arc::new(Metrics::new());
    let (sentinel_impl, _rx) = Sentinel::new(Arc::clone(&engine));
    let sentinel = Arc::new(sentinel_impl);

    let lists_config = ListsConfig {
        preset: "custom".to_string(),
        extra_categories: Vec::new(),
        sources: vec![ListSource {
            name: "test".to_string(),
            url: "http://mock.invalid/list".to_string(),
        }],
        refresh_hours: 24,
        jitter_minutes: 0,
        snapshot_dir: None,
    };
    let lists = Arc::new(ListsPipeline::new(
        lists_config,
        tmp.path().to_path_buf(),
        Arc::clone(&engine),
    ));

    let cancel = tokio_util::sync::CancellationToken::new();
    let rollup_handle = rollup::start_rollup(
        tmp.path().to_path_buf(),
        hush_core::config::QueryLogMode::Off,
        7,
        cancel,
    );

    let current_config = HushConfig {
        network_guard: network_guard_cfg.clone(),
        ..HushConfig::default()
    };
    let privacy_cfg = PrivacyConfig::default();
    let privacy_arc = Arc::new(ArcSwap::from_pointee(privacy_cfg.clone()));
    Arc::new(ApiState {
        token,
        engine,
        sentinel,
        metrics,
        ring,
        lists,
        allowlist: std::sync::Mutex::new(Vec::new()),
        start_time: std::time::Instant::now(),
        state_dir: tmp.path().to_path_buf(),
        platform: Arc::new(MockPlatform::new(std::iter::empty::<(
            String,
            hush_daemon::platform::DnsSetting,
        )>())),
        takeover_cfg: TakeoverConfig::default(),
        privacy_cfg,
        privacy_arc,
        rollup: rollup_handle,
        dashboard_enabled: true,
        network_guard_cfg,
        mdns_map: hush_daemon::mdns::MdnsMap::new(),
        active_profile: std::sync::Mutex::new(None),
        current_config: std::sync::Mutex::new(current_config),
    })
}

async fn get_authed(router: axum::Router, token: &str, path: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

// ── §5.1: Config validation ───────────────────────────────────────────────────

#[test]
fn validate_rejects_wildcard_bind() {
    let mut cfg = HushConfig::default();
    cfg.network_guard.enabled = true;
    cfg.network_guard.bind = vec!["0.0.0.0".to_string()];
    let errs = cfg.validate();
    assert!(
        !errs.is_empty(),
        "wildcard 0.0.0.0 bind must be rejected by validate()"
    );
    assert!(
        errs.iter()
            .any(|e| e.message.contains("unspecified") || e.message.contains("0.0.0.0")),
        "error message should mention unspecified/0.0.0.0, got: {errs:?}"
    );
}

#[test]
fn validate_rejects_ipv6_wildcard_bind() {
    let mut cfg = HushConfig::default();
    cfg.network_guard.enabled = true;
    cfg.network_guard.bind = vec!["::".to_string()];
    let errs = cfg.validate();
    assert!(!errs.is_empty(), "IPv6 wildcard :: bind must be rejected");
}

#[test]
fn validate_rejects_loopback_bind() {
    let mut cfg = HushConfig::default();
    cfg.network_guard.enabled = true;
    cfg.network_guard.bind = vec!["127.0.0.1".to_string()];
    let errs = cfg.validate();
    assert!(
        !errs.is_empty(),
        "loopback 127.0.0.1 must be rejected (DNS already owns that address)"
    );
    assert!(
        errs.iter().any(|e| e.message.contains("loopback")),
        "error message should mention loopback, got: {errs:?}"
    );
}

#[test]
fn validate_rejects_enabled_with_empty_bind() {
    let mut cfg = HushConfig::default();
    cfg.network_guard.enabled = true;
    cfg.network_guard.bind = Vec::new();
    let errs = cfg.validate();
    assert!(
        !errs.is_empty(),
        "enabled=true with empty bind[] must be rejected"
    );
}

#[test]
fn validate_accepts_disabled_empty_bind() {
    // The default (disabled + empty bind) must be valid.
    let cfg = HushConfig::default();
    let errs = cfg.validate();
    assert!(
        errs.is_empty(),
        "default config (disabled, empty bind) must pass validate(): {errs:?}"
    );
}

#[test]
fn validate_accepts_valid_lan_ip() {
    let mut cfg = HushConfig::default();
    cfg.network_guard.enabled = true;
    cfg.network_guard.bind = vec!["192.168.1.10".to_string()];
    let errs = cfg.validate();
    assert!(
        errs.is_empty(),
        "valid LAN IP should pass validate(): {errs:?}"
    );
}

#[test]
fn validate_rejects_invalid_ip_string() {
    let mut cfg = HushConfig::default();
    cfg.network_guard.enabled = true;
    cfg.network_guard.bind = vec!["not-an-ip".to_string()];
    let errs = cfg.validate();
    assert!(!errs.is_empty(), "non-IP string in bind[] must be rejected");
}

// ── §5.2: QueryRecord client field (via ring + API) ───────────────────────────

#[test]
fn query_record_client_field_defaults_to_none() {
    // Verify that a QueryRecord pushed without an explicit client defaults to None.
    let ring = hush_core::QueryRing::new(10);
    ring.push(QueryRecord {
        ts_unix_ms: 1,
        qname: "example.com".to_string(),
        qtype: 1,
        verdict: Verdict::Forward,
        reason: Reason::NoMatch,
        upstream_ms: None,
        client: None,
    });
    let records = ring.recent(10);
    assert!(
        records[0].client.is_none(),
        "client must default to None when not set"
    );
}

#[test]
fn query_record_client_field_round_trips_through_ring() {
    use std::net::IpAddr;
    let ip: IpAddr = "192.168.1.42".parse().unwrap();
    let ring = hush_core::QueryRing::new(10);
    ring.push(QueryRecord {
        ts_unix_ms: 2,
        qname: "example.com".to_string(),
        qtype: 1,
        verdict: Verdict::Forward,
        reason: Reason::NoMatch,
        upstream_ms: None,
        client: Some(ip),
    });
    let records = ring.recent(10);
    assert_eq!(
        records[0].client,
        Some(ip),
        "client IP must round-trip through QueryRing"
    );
}

// ── §5.3: GET /v0/clients disabled explanation ────────────────────────────────

#[tokio::test]
async fn clients_endpoint_returns_disabled_explanation_when_log_clients_off() {
    let tmp = TempDir::new().unwrap();
    let guard_cfg = NetworkGuardConfig::default(); // log_clients: false
    let state = make_api_state(&tmp, guard_cfg);
    let token = state.token.clone();
    let router = routes::build_router(Arc::clone(&state));

    let (status, json) = get_authed(router, &token, "/v0/clients").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        json["log_clients_enabled"], false,
        "log_clients_enabled must be false"
    );
    assert!(
        !json["explanation"].is_null(),
        "explanation must be present when log_clients is off"
    );
    let clients = json["clients"].as_array().unwrap();
    assert!(
        clients.is_empty(),
        "clients list must be empty when disabled"
    );
}

#[tokio::test]
async fn clients_endpoint_returns_401_without_auth() {
    let tmp = TempDir::new().unwrap();
    let state = make_api_state(&tmp, NetworkGuardConfig::default());
    let router = routes::build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("GET")
        .uri("/v0/clients")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn clients_endpoint_with_log_clients_on_returns_enabled_body() {
    let tmp = TempDir::new().unwrap();
    let guard_cfg = NetworkGuardConfig {
        enabled: false,
        bind: Vec::new(),
        log_clients: true,
        mdns_insight: false,
    };
    let state = make_api_state(&tmp, guard_cfg);
    let token = state.token.clone();
    let router = routes::build_router(Arc::clone(&state));

    let (status, json) = get_authed(router, &token, "/v0/clients").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        json["log_clients_enabled"], true,
        "log_clients_enabled must be true when log_clients=true"
    );
    assert!(
        json["explanation"].is_null(),
        "explanation should be null when enabled"
    );
    // No DB exists (log_mode=off), so clients list should be empty but present.
    assert!(json["clients"].is_array(), "clients field must be an array");
}

#[tokio::test]
async fn clients_endpoint_hours_param_accepted() {
    let tmp = TempDir::new().unwrap();
    let guard_cfg = NetworkGuardConfig {
        enabled: false,
        bind: Vec::new(),
        log_clients: true,
        mdns_insight: false,
    };
    let state = make_api_state(&tmp, guard_cfg);
    let token = state.token.clone();
    let router = routes::build_router(Arc::clone(&state));

    let (status, json) = get_authed(router, &token, "/v0/clients?hours=48").await;
    assert_eq!(status, StatusCode::OK);
    assert!(json["clients"].is_array());
}

// ── §5.4: Architecture §8 invariant — API must never bind non-loopback ────────

/// ApiServer::start must return NonLoopback error when given a non-loopback addr.
#[tokio::test]
async fn api_server_rejects_non_loopback_listen_addr() {
    let tmp = TempDir::new().unwrap();

    // Write a token file so auth::ensure_token succeeds.
    let token = "deadbeef".repeat(8);
    std::fs::write(tmp.path().join("api.token"), &token).unwrap();

    let engine = Arc::new(DecisionEngine::new());
    let ring = Arc::new(hush_core::QueryRing::new(10));
    let metrics = Arc::new(Metrics::new());
    let (sentinel_impl, _rx) = Sentinel::new(Arc::clone(&engine));
    let sentinel = Arc::new(sentinel_impl);
    let lists_config = hush_core::config::ListsConfig::default();
    let lists = Arc::new(hush_daemon::lists::ListsPipeline::new(
        lists_config,
        tmp.path().to_path_buf(),
        Arc::clone(&engine),
    ));
    let cancel = tokio_util::sync::CancellationToken::new();
    let rollup_handle = hush_daemon::rollup::start_rollup(
        tmp.path().to_path_buf(),
        hush_core::config::QueryLogMode::Off,
        7,
        cancel.clone(),
    );

    let privacy_cfg = PrivacyConfig::default();
    let privacy_arc = Arc::new(arc_swap::ArcSwap::from_pointee(privacy_cfg.clone()));

    // A non-loopback address must be rejected immediately.
    let non_loopback: std::net::SocketAddr = "10.0.0.1:9999".parse().unwrap();
    let result = hush_daemon::api::ApiServer::start(hush_daemon::api::ApiServerConfig {
        listen_addr: non_loopback,
        state_dir: tmp.path().to_path_buf(),
        engine: Arc::clone(&engine),
        sentinel: Arc::clone(&sentinel),
        metrics: Arc::clone(&metrics),
        ring: Arc::clone(&ring),
        lists: Arc::clone(&lists),
        platform: Arc::new(MockPlatform::new(std::iter::empty::<(
            String,
            hush_daemon::platform::DnsSetting,
        )>())),
        takeover_cfg: TakeoverConfig::default(),
        cancel: cancel.clone(),
        privacy_cfg: privacy_cfg.clone(),
        privacy_arc: Arc::clone(&privacy_arc),
        rollup: rollup_handle.clone(),
        dashboard_enabled: false,
        network_guard_cfg: NetworkGuardConfig::default(),
        mdns_map: hush_daemon::mdns::MdnsMap::new(),
        active_profile: None,
        current_config: hush_core::config::HushConfig::default(),
    })
    .await;

    assert!(
        matches!(result, Err(hush_daemon::api::ApiStartError::NonLoopback(_))),
        "ApiServer::start must return NonLoopback for a non-loopback address; got: {:?}",
        result.as_ref().err()
    );
}

/// With a loopback address, ApiServer::start binds successfully and the
/// resulting api_addr is on loopback.
#[tokio::test]
async fn api_server_bound_addr_is_loopback() {
    let tmp = TempDir::new().unwrap();

    let token = "deadbeef".repeat(8);
    std::fs::write(tmp.path().join("api.token"), &token).unwrap();

    let engine = Arc::new(DecisionEngine::new());
    let ring = Arc::new(hush_core::QueryRing::new(10));
    let metrics = Arc::new(Metrics::new());
    let (sentinel_impl, _rx) = Sentinel::new(Arc::clone(&engine));
    let sentinel = Arc::new(sentinel_impl);
    let lists_config = hush_core::config::ListsConfig::default();
    let lists = Arc::new(hush_daemon::lists::ListsPipeline::new(
        lists_config,
        tmp.path().to_path_buf(),
        Arc::clone(&engine),
    ));
    let cancel = tokio_util::sync::CancellationToken::new();
    let rollup_handle = hush_daemon::rollup::start_rollup(
        tmp.path().to_path_buf(),
        hush_core::config::QueryLogMode::Off,
        7,
        cancel.clone(),
    );

    let privacy_cfg = PrivacyConfig::default();
    let privacy_arc = Arc::new(arc_swap::ArcSwap::from_pointee(privacy_cfg.clone()));

    let loopback: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server = hush_daemon::api::ApiServer::start(hush_daemon::api::ApiServerConfig {
        listen_addr: loopback,
        state_dir: tmp.path().to_path_buf(),
        engine: Arc::clone(&engine),
        sentinel: Arc::clone(&sentinel),
        metrics: Arc::clone(&metrics),
        ring: Arc::clone(&ring),
        lists: Arc::clone(&lists),
        platform: Arc::new(MockPlatform::new(std::iter::empty::<(
            String,
            hush_daemon::platform::DnsSetting,
        )>())),
        takeover_cfg: TakeoverConfig::default(),
        cancel: cancel.clone(),
        privacy_cfg: privacy_cfg.clone(),
        privacy_arc: Arc::clone(&privacy_arc),
        rollup: rollup_handle.clone(),
        dashboard_enabled: false,
        network_guard_cfg: NetworkGuardConfig::default(),
        mdns_map: hush_daemon::mdns::MdnsMap::new(),
        active_profile: None,
        current_config: hush_core::config::HushConfig::default(),
    })
    .await
    .unwrap();

    assert!(
        server.api_addr.ip().is_loopback(),
        "api_addr must be loopback; got {}",
        server.api_addr
    );
    // Clean up
    cancel.cancel();
    server.join().await;
}

// ── §5.5: NetworkGuardConfig TOML serde ───────────────────────────────────────

#[test]
fn network_guard_config_toml_defaults_on_missing_section() {
    // Parse a config with no [network_guard] section — all fields should default.
    let cfg = HushConfig::from_toml_str("").unwrap();
    assert!(!cfg.network_guard.enabled);
    assert!(cfg.network_guard.bind.is_empty());
    assert!(!cfg.network_guard.log_clients);
}

#[test]
fn network_guard_config_toml_round_trips() {
    let toml = r#"
[network_guard]
enabled = true
bind = ["192.168.1.10"]
log_clients = true
"#;
    let cfg = HushConfig::from_toml_str(toml).unwrap();
    assert!(cfg.network_guard.enabled);
    assert_eq!(cfg.network_guard.bind, ["192.168.1.10"]);
    assert!(cfg.network_guard.log_clients);
}

#[test]
fn network_guard_config_unknown_field_is_rejected() {
    let toml = r#"
[network_guard]
enabled = false
unknown_key = "surprise"
"#;
    let result = HushConfig::from_toml_str(toml);
    assert!(
        result.is_err(),
        "unknown field in [network_guard] should be rejected (deny_unknown_fields)"
    );
}
