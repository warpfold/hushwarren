//! Integration tests for the control API (`hush-daemon::api`).
//!
//! Uses `tower::ServiceExt::oneshot` for in-process routing — no real TCP sockets.
//! Wires REAL `DecisionEngine` / `Sentinel` / `QueryRing` instances into a
//! fresh router per test.
//!
//! All mandatory cases from `specs/wp3-api-cli.md` §5 (integration layer) are
//! covered here.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use serde_json::Value;
use tempfile::TempDir;
use tower::ServiceExt; // for .oneshot()

use hush_core::{
    config::{ListSource, ListsConfig, PrivacyConfig},
    querylog::QueryRecord,
    DecisionEngine, Domain, Reason, Verdict,
};
use hush_daemon::{
    api::{routes, ApiState},
    lists::ListsPipeline,
    metrics::Metrics,
    platform::stub::MockPlatform,
    rollup,
    sentinel::{takeover::TakeoverConfig, Sentinel},
};

// ── Test helpers ──────────────────────────────────────────────────────────────

struct TestRouter {
    router: axum::Router,
    token: String,
    state: Arc<ApiState>,
    state_dir: TempDir,
}

impl TestRouter {
    fn new() -> Self {
        let tmp = TempDir::new().unwrap();

        // Write a token file (64 lowercase hex chars).
        let token = "cafebabe".repeat(8); // 64 hex chars
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
                name: "test-list".to_string(),
                url: "http://mock.invalid/list".to_string(),
            }],
            refresh_hours: 24,
            jitter_minutes: 0,
            snapshot_dir: None, // WP12: no snapshot in test configs
        };
        let lists = Arc::new(ListsPipeline::new(
            lists_config,
            tmp.path().to_path_buf(),
            Arc::clone(&engine),
        ));

        let cancel = tokio_util::sync::CancellationToken::new();
        let rollup_handle = rollup::start_rollup(
            tmp.path().to_path_buf(),
            hush_core::config::QueryLogMode::Off, // no DB in integration tests
            7,
            cancel,
        );

        let privacy_cfg = PrivacyConfig::default();
        let privacy_arc = Arc::new(arc_swap::ArcSwap::from_pointee(privacy_cfg.clone()));
        let api_state = Arc::new(ApiState {
            token: token.clone(),
            engine: Arc::clone(&engine),
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
            network_guard_cfg: hush_core::config::NetworkGuardConfig::default(),
            mdns_map: hush_daemon::mdns::MdnsMap::new(),
            active_profile: std::sync::Mutex::new(None),
            current_config: std::sync::Mutex::new(hush_core::config::HushConfig::default()),
        });

        let router = routes::build_router(Arc::clone(&api_state));

        Self {
            router,
            token,
            state: api_state,
            state_dir: tmp,
        }
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.token)
    }

    async fn get(&self, path: &str) -> (StatusCode, Value) {
        self.get_with_auth(path, &self.auth_header()).await
    }

    async fn get_with_auth(&self, path: &str, auth: &str) -> (StatusCode, Value) {
        let req = Request::builder()
            .method("GET")
            .uri(path)
            .header(header::AUTHORIZATION, auth)
            .body(Body::empty())
            .unwrap();
        let resp = self.router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, json)
    }

    async fn post_json(&self, path: &str, body: Value) -> (StatusCode, Value) {
        self.post_json_with_auth(path, body, &self.auth_header())
            .await
    }

    async fn post_json_with_auth(
        &self,
        path: &str,
        body: Value,
        auth: &str,
    ) -> (StatusCode, Value) {
        let req = Request::builder()
            .method("POST")
            .uri(path)
            .header(header::AUTHORIZATION, auth)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = self.router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, json)
    }

    /// POST with an empty body (no JSON content-type).
    async fn post_empty(&self, path: &str) -> (StatusCode, Value) {
        let req = Request::builder()
            .method("POST")
            .uri(path)
            .header(header::AUTHORIZATION, self.auth_header())
            .header(header::CONTENT_LENGTH, "0")
            .body(Body::empty())
            .unwrap();
        let resp = self.router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, json)
    }
}

// ── 401 — missing / wrong token ───────────────────────────────────────────────

#[tokio::test]
async fn auth_missing_header_returns_401() {
    let tr = TestRouter::new();
    let req = Request::builder()
        .method("GET")
        .uri("/v0/status")
        .body(Body::empty())
        .unwrap();
    let resp = tr.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["error"], "unauthorized");
}

#[tokio::test]
async fn auth_wrong_token_returns_401() {
    let tr = TestRouter::new();
    // Wrong token — same length as the real one but different value.
    let wrong = "deadbeef".repeat(8);
    let (status, json) = tr
        .get_with_auth("/v0/status", &format!("Bearer {wrong}"))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["error"], "unauthorized");
}

// ── GET /v0/status ────────────────────────────────────────────────────────────

#[tokio::test]
async fn status_happy_path() {
    let tr = TestRouter::new();
    let (status, json) = tr.get("/v0/status").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["state"], "filtering");
    assert!(json["snoozed_until_unix_ms"].is_null());
    assert!(json["version"].is_string());
    assert!(json["uptime_secs"].is_number());
    assert!(json["rules"]["block_count"].is_number());
    assert!(json["counters"]["queries_total"].is_number());
}

// ── GET /v0/queries/recent ────────────────────────────────────────────────────

#[tokio::test]
async fn queries_recent_empty() {
    let tr = TestRouter::new();
    let (status, json) = tr.get("/v0/queries/recent?n=10").await;
    assert_eq!(status, StatusCode::OK);
    assert!(json["queries"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn queries_recent_returns_records_newest_first() {
    let tr = TestRouter::new();

    // Push 3 records into the ring.
    let ring = &tr.state.ring;
    ring.push(QueryRecord {
        ts_unix_ms: 100,
        qname: "a.test".to_string(),
        qtype: 1,
        verdict: Verdict::Forward,
        reason: Reason::NoMatch,
        upstream_ms: None,
        client: None,
    });
    ring.push(QueryRecord {
        ts_unix_ms: 200,
        qname: "b.test".to_string(),
        qtype: 1,
        verdict: Verdict::Block,
        reason: Reason::ListBlocked,
        upstream_ms: None,
        client: None,
    });
    ring.push(QueryRecord {
        ts_unix_ms: 300,
        qname: "c.test".to_string(),
        qtype: 1,
        verdict: Verdict::Forward,
        reason: Reason::NoMatch,
        upstream_ms: Some(5),
        client: None,
    });

    let (status, json) = tr.get("/v0/queries/recent?n=10").await;
    assert_eq!(status, StatusCode::OK);
    let queries = json["queries"].as_array().unwrap();
    assert_eq!(queries.len(), 3);
    // Newest first.
    assert_eq!(queries[0]["ts_unix_ms"], 300);
    assert_eq!(queries[1]["ts_unix_ms"], 200);
    assert_eq!(queries[2]["ts_unix_ms"], 100);
    // queries[0] is the ts=300 record with upstream_ms=Some(5).
    assert_eq!(queries[0]["upstream_ms"], 5);
    // queries[1] is the ts=200 blocked record.
    assert_eq!(queries[1]["verdict"], "block");
    // queries[2] is the ts=100 record with no upstream_ms.
    assert!(queries[2]["upstream_ms"].is_null());
}

#[tokio::test]
async fn queries_recent_blocked_only_filter() {
    let tr = TestRouter::new();
    let ring = &tr.state.ring;
    ring.push(QueryRecord {
        ts_unix_ms: 100,
        qname: "good.test".to_string(),
        qtype: 1,
        verdict: Verdict::Forward,
        reason: Reason::NoMatch,
        upstream_ms: None,
        client: None,
    });
    ring.push(QueryRecord {
        ts_unix_ms: 200,
        qname: "bad.test".to_string(),
        qtype: 1,
        verdict: Verdict::Block,
        reason: Reason::ListBlocked,
        upstream_ms: None,
        client: None,
    });

    let (status, json) = tr.get("/v0/queries/recent?n=10&blocked_only=true").await;
    assert_eq!(status, StatusCode::OK);
    let queries = json["queries"].as_array().unwrap();
    assert_eq!(queries.len(), 1);
    assert_eq!(queries[0]["qname"], "bad.test");
}

#[tokio::test]
async fn queries_recent_n_clamped() {
    let tr = TestRouter::new();
    // n=0 is valid; clamped to 1 internally.
    let (status, _) = tr.get("/v0/queries/recent?n=0").await;
    assert_eq!(status, StatusCode::OK);
}

// ── GET /v0/stats/summary ─────────────────────────────────────────────────────

#[tokio::test]
async fn stats_summary_happy_path() {
    let tr = TestRouter::new();
    let (status, json) = tr.get("/v0/stats/summary").await;
    assert_eq!(status, StatusCode::OK);
    assert!(json["since_unix_ms"].is_number());
    assert!(json["queries_total"].is_number());
    assert!(json["blocked_total"].is_number());
    assert!(json["block_rate"].is_number());
}

// ── POST /v0/snooze ───────────────────────────────────────────────────────────

#[tokio::test]
async fn snooze_valid_secs_returns_200() {
    let tr = TestRouter::new();
    let (status, json) = tr
        .post_json("/v0/snooze", serde_json::json!({"secs": 300}))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(json["snoozed_until_unix_ms"].is_number());

    // Status must now reflect snoozed.
    let (_, status_json) = tr.get("/v0/status").await;
    assert_eq!(status_json["state"], "snoozed");
}

#[tokio::test]
async fn snooze_secs_0_returns_400() {
    let tr = TestRouter::new();
    let (status, json) = tr
        .post_json("/v0/snooze", serde_json::json!({"secs": 0}))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"], "invalid_body");
}

#[tokio::test]
async fn snooze_secs_86401_returns_400() {
    let tr = TestRouter::new();
    let (status, json) = tr
        .post_json("/v0/snooze", serde_json::json!({"secs": 86401}))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"], "invalid_body");
}

#[tokio::test]
async fn snooze_secs_1_boundary_valid() {
    let tr = TestRouter::new();
    let (status, _) = tr
        .post_json("/v0/snooze", serde_json::json!({"secs": 1}))
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn snooze_secs_86400_boundary_valid() {
    let tr = TestRouter::new();
    let (status, _) = tr
        .post_json("/v0/snooze", serde_json::json!({"secs": 86400}))
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn snooze_invalid_json_returns_400() {
    let tr = TestRouter::new();
    let req = Request::builder()
        .method("POST")
        .uri("/v0/snooze")
        .header(header::AUTHORIZATION, tr.auth_header())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("not valid json"))
        .unwrap();
    let resp = tr.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── POST /v0/resume ───────────────────────────────────────────────────────────

#[tokio::test]
async fn resume_clears_snooze() {
    let tr = TestRouter::new();

    // Snooze first.
    tr.post_json("/v0/snooze", serde_json::json!({"secs": 300}))
        .await;
    let (_, s) = tr.get("/v0/status").await;
    assert_eq!(s["state"], "snoozed");

    // Resume.
    let (status, json) = tr.post_empty("/v0/resume").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["state"], "filtering");

    // Confirm status is back to filtering.
    let (_, s2) = tr.get("/v0/status").await;
    assert_eq!(s2["state"], "filtering");
}

// ── POST /v0/allow ────────────────────────────────────────────────────────────

#[tokio::test]
async fn allow_adds_domain_to_list() {
    let tr = TestRouter::new();
    let (status, json) = tr
        .post_json("/v0/allow", serde_json::json!({"domain": "example.com"}))
        .await;
    assert_eq!(status, StatusCode::OK);
    let allowed = json["allowed"].as_array().unwrap();
    assert!(
        allowed.iter().any(|v| v == "example.com"),
        "example.com must be in the returned list"
    );
}

#[tokio::test]
async fn allow_deduplicates_domain() {
    let tr = TestRouter::new();
    tr.post_json("/v0/allow", serde_json::json!({"domain": "example.com"}))
        .await;
    let (status, json) = tr
        .post_json("/v0/allow", serde_json::json!({"domain": "example.com"}))
        .await;
    assert_eq!(status, StatusCode::OK);
    let allowed = json["allowed"].as_array().unwrap();
    let count = allowed.iter().filter(|v| *v == "example.com").count();
    assert_eq!(count, 1, "duplicate allow must not double-add");
}

#[tokio::test]
async fn allow_flips_engine_decide_outcome() {
    let tr = TestRouter::new();

    // Seed the engine with a block rule.
    use hush_core::rules::{RuleSink, RulesBuilder};
    let mut builder = RulesBuilder::new();
    builder.block(Domain::parse("blocked.test").unwrap());
    let rules = builder.build().unwrap();
    tr.state.engine.swap_rules(Arc::new(rules));

    // Verify blocked (ts=0 means no snooze).
    let d = Domain::parse("blocked.test").unwrap();
    let (verdict_before, _) = tr.state.engine.decide(&d, 0);
    assert_eq!(
        verdict_before,
        Verdict::Block,
        "must be blocked before allow"
    );

    // Allow the domain via the API.
    let (status, _) = tr
        .post_json("/v0/allow", serde_json::json!({"domain": "blocked.test"}))
        .await;
    assert_eq!(status, StatusCode::OK);

    // Now decide must return (Forward, UserAllowed).
    let (verdict_after, reason_after) = tr.state.engine.decide(&d, 0);
    assert_eq!(
        verdict_after,
        Verdict::Forward,
        "after allow, engine must forward"
    );
    assert_eq!(reason_after, Reason::UserAllowed);
}

#[tokio::test]
async fn allow_invalid_domain_returns_422() {
    let tr = TestRouter::new();
    let (status, json) = tr
        .post_json("/v0/allow", serde_json::json!({"domain": "!!invalid!!"}))
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(json["error"], "invalid_domain");
}

#[tokio::test]
async fn allow_persists_to_file() {
    let tr = TestRouter::new();
    tr.post_json("/v0/allow", serde_json::json!({"domain": "persisted.com"}))
        .await;
    let content = std::fs::read_to_string(tr.state_dir.path().join("allowlist.txt")).unwrap();
    assert!(
        content.contains("persisted.com"),
        "domain must be in the persistence file"
    );
}

// ── POST /v0/unallow ──────────────────────────────────────────────────────────

#[tokio::test]
async fn unallow_removes_domain() {
    let tr = TestRouter::new();

    // Add first.
    tr.post_json("/v0/allow", serde_json::json!({"domain": "example.com"}))
        .await;

    // Remove.
    let (status, json) = tr
        .post_json("/v0/unallow", serde_json::json!({"domain": "example.com"}))
        .await;
    assert_eq!(status, StatusCode::OK);
    let allowed = json["allowed"].as_array().unwrap();
    assert!(
        !allowed.iter().any(|v| v == "example.com"),
        "example.com must be gone after unallow"
    );
}

#[tokio::test]
async fn unallow_noop_when_absent() {
    let tr = TestRouter::new();
    // Unallow something that was never allowed — must succeed (no-op).
    let (status, json) = tr
        .post_json("/v0/unallow", serde_json::json!({"domain": "nothere.com"}))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(json["allowed"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn unallow_persists_to_file() {
    let tr = TestRouter::new();
    tr.post_json("/v0/allow", serde_json::json!({"domain": "temp.com"}))
        .await;
    tr.post_json("/v0/unallow", serde_json::json!({"domain": "temp.com"}))
        .await;
    // File may be absent (empty list) or present but not contain the domain.
    let content =
        std::fs::read_to_string(tr.state_dir.path().join("allowlist.txt")).unwrap_or_default();
    assert!(
        !content.contains("temp.com"),
        "removed domain must not be in the persistence file"
    );
}

#[tokio::test]
async fn unallow_does_not_remove_subdomains() {
    let tr = TestRouter::new();

    // Allow parent and subdomain.
    tr.post_json("/v0/allow", serde_json::json!({"domain": "example.com"}))
        .await;
    tr.post_json(
        "/v0/allow",
        serde_json::json!({"domain": "sub.example.com"}),
    )
    .await;

    // Unallow only the parent.
    let (_, json) = tr
        .post_json("/v0/unallow", serde_json::json!({"domain": "example.com"}))
        .await;
    let allowed = json["allowed"].as_array().unwrap();

    assert!(!allowed.iter().any(|v| v == "example.com"));
    assert!(
        allowed.iter().any(|v| v == "sub.example.com"),
        "subdomain must remain after parent unallow"
    );
}

#[tokio::test]
async fn unallow_invalid_domain_returns_422() {
    let tr = TestRouter::new();
    let (status, json) = tr
        .post_json("/v0/unallow", serde_json::json!({"domain": "   "}))
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(json["error"], "invalid_domain");
}

// ── GET /v0/allowlist ─────────────────────────────────────────────────────────

#[tokio::test]
async fn allowlist_empty_initially() {
    let tr = TestRouter::new();
    let (status, json) = tr.get("/v0/allowlist").await;
    assert_eq!(status, StatusCode::OK);
    assert!(json["allowed"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn allowlist_reflects_added_domains() {
    let tr = TestRouter::new();
    tr.post_json("/v0/allow", serde_json::json!({"domain": "a.com"}))
        .await;
    tr.post_json("/v0/allow", serde_json::json!({"domain": "b.com"}))
        .await;
    let (_, json) = tr.get("/v0/allowlist").await;
    let allowed = json["allowed"].as_array().unwrap();
    assert_eq!(allowed.len(), 2);
}

// ── GET /v0/lists ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn lists_happy_path() {
    let tr = TestRouter::new();
    let (status, json) = tr.get("/v0/lists").await;
    assert_eq!(status, StatusCode::OK);
    let sources = json["sources"].as_array().unwrap();
    assert!(!sources.is_empty());
    assert_eq!(sources[0]["name"], "test-list");
    assert_eq!(sources[0]["enabled"], true);
    // Without any fetch the tracking fields start as null.
    assert!(sources[0]["last_fetched_unix_ms"].is_null());
    assert!(sources[0]["last_error"].is_null());
}

/// After `record_source_ok` + `record_swap` the API must return real timestamps
/// and rule counts.
#[tokio::test]
async fn lists_reports_real_tracking_after_fetch() {
    let tr = TestRouter::new();

    // Simulate a successful fetch by calling the private helpers via the
    // pipeline's public tracking seam.
    let lists = Arc::clone(&tr.state.lists);

    // Write a raw cache file so compile_from_raw_cache succeeds.
    let lists_dir = tr.state_dir.path().join("lists");
    std::fs::create_dir_all(&lists_dir).unwrap();
    let url = "http://mock.invalid/list";
    // File name derived by the same source_file_path logic.
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
    std::fs::write(
        lists_dir.join(format!("{safe}.txt")),
        "ads.example.com\ntracker.bad.com\n",
    )
    .unwrap();

    // Trigger a reload (calls compile_from_raw_cache which updates rule counts
    // and engine, then we manually record_swap).
    lists.reload_from_cache().await.unwrap();

    let (status, json) = tr.get("/v0/lists").await;
    assert_eq!(status, StatusCode::OK);
    let sources = json["sources"].as_array().unwrap();
    assert_eq!(sources.len(), 1);

    // rule_count must be populated after compile.
    let rule_count = sources[0]["rule_count"].as_u64();
    assert!(
        rule_count.is_some() && rule_count.unwrap() > 0,
        "rule_count must be > 0 after reload, got {:?}",
        rule_count,
    );
}

// ── POST /v0/lists/refresh ────────────────────────────────────────────────────

#[tokio::test]
async fn lists_refresh_returns_202() {
    let tr = TestRouter::new();
    let req = Request::builder()
        .method("POST")
        .uri("/v0/lists/refresh")
        .header(header::AUTHORIZATION, tr.auth_header())
        .header(header::CONTENT_LENGTH, "0")
        .body(Body::empty())
        .unwrap();
    let resp = tr.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["started"], true);
}

// ── 404 fallback ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn unknown_path_returns_404() {
    let tr = TestRouter::new();
    let (status, json) = tr.get("/v0/no_such_endpoint").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(json["error"], "not_found");
}

// ── WP4 §4 — GET /v0/status privacy object ───────────────────────────────────

/// The status response must include a `privacy` object with all seven boolean/string fields.
/// Defaults: canary=true, cname=true, log=full, doh_bypass=false, relay=false,
/// doh_padding=true, rebind_protection=true.
#[tokio::test]
async fn status_contains_privacy_object_with_defaults() {
    let tr = TestRouter::new();
    let (status, json) = tr.get("/v0/status").await;
    assert_eq!(status, StatusCode::OK);

    let privacy = &json["privacy"];
    assert!(
        privacy.is_object(),
        "status must contain a 'privacy' object; got: {privacy}"
    );
    assert_eq!(
        privacy["browser_doh_canary"], true,
        "default browser_doh_canary must be true"
    );
    assert_eq!(
        privacy["cname_inspection"], true,
        "default cname_inspection must be true"
    );
    assert_eq!(
        privacy["query_log"], "full",
        "default query_log must be 'full'"
    );
    assert_eq!(
        privacy["block_doh_bypass"], false,
        "default block_doh_bypass must be false"
    );
    assert_eq!(
        privacy["block_private_relay"], false,
        "default block_private_relay must be false"
    );
    // WP8 §6: new fields with defaults true.
    assert_eq!(
        privacy["doh_padding"], true,
        "default doh_padding must be true (WP8 §1)"
    );
    assert_eq!(
        privacy["rebind_protection"], true,
        "default rebind_protection must be true (WP8 §1)"
    );
}

// ── WP4 §4 — GET /v0/lists preset + catalog attribution ──────────────────────

/// The lists response must include top-level `preset` and per-source catalog metadata.
/// For a catalog URL (oisd-small), `category`, `license`, `attribution` must be present.
#[tokio::test]
async fn lists_contains_preset_and_catalog_attribution() {
    // Build a TestRouter using oisd-small (a catalog source) as the list URL.
    let tmp = tempfile::TempDir::new().unwrap();
    let token = "cafebabe".repeat(8);
    std::fs::write(tmp.path().join("api.token"), &token).unwrap();

    let engine = Arc::new(hush_core::DecisionEngine::new());
    let ring = Arc::new(hush_core::QueryRing::new(1000));
    let metrics = Arc::new(hush_daemon::metrics::Metrics::new());
    let (sentinel_impl, _rx) = hush_daemon::sentinel::Sentinel::new(Arc::clone(&engine));
    let sentinel = Arc::new(sentinel_impl);

    // Use balanced preset so oisd-small is included.
    let lists_config = ListsConfig {
        preset: "balanced".to_string(),
        extra_categories: Vec::new(),
        sources: Vec::new(),
        refresh_hours: 24,
        jitter_minutes: 0,
        snapshot_dir: None, // WP12: no snapshot in test configs
    };
    let lists = Arc::new(hush_daemon::lists::ListsPipeline::new(
        lists_config,
        tmp.path().to_path_buf(),
        Arc::clone(&engine),
    ));

    let cancel2 = tokio_util::sync::CancellationToken::new();
    let rollup2 = rollup::start_rollup(
        tmp.path().to_path_buf(),
        hush_core::config::QueryLogMode::Off,
        7,
        cancel2,
    );
    let privacy_cfg2 = PrivacyConfig::default();
    let privacy_arc2 = Arc::new(arc_swap::ArcSwap::from_pointee(privacy_cfg2.clone()));
    let api_state = Arc::new(ApiState {
        token: token.clone(),
        engine,
        sentinel,
        metrics,
        ring,
        lists,
        allowlist: std::sync::Mutex::new(Vec::new()),
        start_time: std::time::Instant::now(),
        state_dir: tmp.path().to_path_buf(),
        platform: Arc::new(hush_daemon::platform::stub::MockPlatform::new(
            std::iter::empty::<(String, hush_daemon::platform::DnsSetting)>(),
        )),
        takeover_cfg: hush_daemon::sentinel::takeover::TakeoverConfig::default(),
        privacy_cfg: privacy_cfg2,
        privacy_arc: privacy_arc2,
        rollup: rollup2,
        dashboard_enabled: true,
        network_guard_cfg: hush_core::config::NetworkGuardConfig::default(),
        mdns_map: hush_daemon::mdns::MdnsMap::new(),
        active_profile: std::sync::Mutex::new(None),
        current_config: std::sync::Mutex::new(hush_core::config::HushConfig::default()),
    });

    let router = hush_daemon::api::routes::build_router(Arc::clone(&api_state));
    let auth = format!("Bearer {token}");

    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/v0/lists")
        .header(axum::http::header::AUTHORIZATION, &auth)
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(status, StatusCode::OK);

    // preset must be "balanced".
    assert_eq!(
        json["preset"], "balanced",
        "preset field must be 'balanced'"
    );

    // All sources should be non-empty.
    let sources = json["sources"].as_array().unwrap();
    assert!(!sources.is_empty(), "balanced preset must have sources");

    // Find oisd-small (URL contains "small.oisd.nl").
    let oisd = sources
        .iter()
        .find(|s| s["name"].as_str().unwrap_or("").contains("OISD Small"))
        .expect("balanced preset must include OISD Small");

    // category must be "oisd-small".
    assert_eq!(
        oisd["category"], "oisd-small",
        "oisd-small must have category key"
    );
    // attribution must be a non-empty string.
    assert!(
        oisd["attribution"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false),
        "oisd-small must have attribution"
    );
    // license is null for OISD (no stated license).
    assert!(
        oisd["license"].is_null(),
        "oisd-small has no stated license; must be null"
    );
}

// ── WP4 §3.4 — GET /v0/queries/recent log_mode field ────────────────────────

/// The queries/recent response must always include a `log_mode` field.
/// With the default config (full), it must be "full".
#[tokio::test]
async fn queries_recent_contains_log_mode_full_by_default() {
    let tr = TestRouter::new();
    let (status, json) = tr.get("/v0/queries/recent?n=10").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        json["log_mode"], "full",
        "default log_mode must be 'full'; got: {}",
        json["log_mode"]
    );
}

/// When privacy_cfg has query_log=Off, the ring is empty and log_mode is "off".
#[tokio::test]
async fn queries_recent_log_mode_off_returns_empty_and_mode_off() {
    let tmp = tempfile::TempDir::new().unwrap();
    let token = "cafebabe".repeat(8);
    std::fs::write(tmp.path().join("api.token"), &token).unwrap();

    let engine = Arc::new(hush_core::DecisionEngine::new());
    // Ring built with Off mode — writes are suppressed in the query path.
    // For this API test we simply verify the log_mode field and that queries is empty.
    let ring = Arc::new(hush_core::QueryRing::new(1000));
    let metrics = Arc::new(hush_daemon::metrics::Metrics::new());
    let (sentinel_impl, _rx) = hush_daemon::sentinel::Sentinel::new(Arc::clone(&engine));
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
        snapshot_dir: None, // WP12: no snapshot in test configs
    };
    let lists = Arc::new(hush_daemon::lists::ListsPipeline::new(
        lists_config,
        tmp.path().to_path_buf(),
        Arc::clone(&engine),
    ));

    let privacy_cfg_off = PrivacyConfig {
        query_log: hush_core::config::QueryLogMode::Off,
        ..PrivacyConfig::default()
    };

    let cancel3 = tokio_util::sync::CancellationToken::new();
    let rollup3 = rollup::start_rollup(
        tmp.path().to_path_buf(),
        hush_core::config::QueryLogMode::Off,
        7,
        cancel3,
    );
    let privacy_arc3 = Arc::new(arc_swap::ArcSwap::from_pointee(privacy_cfg_off.clone()));
    let api_state = Arc::new(ApiState {
        token: token.clone(),
        engine,
        sentinel,
        metrics,
        ring,
        lists,
        allowlist: std::sync::Mutex::new(Vec::new()),
        start_time: std::time::Instant::now(),
        state_dir: tmp.path().to_path_buf(),
        platform: Arc::new(hush_daemon::platform::stub::MockPlatform::new(
            std::iter::empty::<(String, hush_daemon::platform::DnsSetting)>(),
        )),
        takeover_cfg: hush_daemon::sentinel::takeover::TakeoverConfig::default(),
        privacy_cfg: privacy_cfg_off,
        privacy_arc: privacy_arc3,
        rollup: rollup3,
        dashboard_enabled: true,
        network_guard_cfg: hush_core::config::NetworkGuardConfig::default(),
        mdns_map: hush_daemon::mdns::MdnsMap::new(),
        active_profile: std::sync::Mutex::new(None),
        current_config: std::sync::Mutex::new(hush_core::config::HushConfig::default()),
    });

    let router = hush_daemon::api::routes::build_router(Arc::clone(&api_state));
    let auth = format!("Bearer {token}");

    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/v0/queries/recent?n=10")
        .header(axum::http::header::AUTHORIZATION, &auth)
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        json["log_mode"], "off",
        "log_mode must be 'off' when privacy_cfg.query_log=Off"
    );
    // Ring is empty (we didn't push anything) — queries must be empty.
    assert!(
        json["queries"].as_array().unwrap().is_empty(),
        "queries must be empty when ring was never written"
    );
}

// ── WP9 §6 — Dashboard routes ─────────────────────────────────────────────────

/// GET /dashboard/ must return 200 with text/html when dashboard is enabled.
#[tokio::test]
async fn dashboard_index_returns_200_html() {
    let tr = TestRouter::new();
    let req = Request::builder()
        .method("GET")
        .uri("/dashboard/")
        // No auth header — static assets bypass auth.
        .body(Body::empty())
        .unwrap();
    let resp = tr.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.contains("text/html"),
        "content-type must be text/html; got: {ct}"
    );
}

/// /v0/* must still require auth while /dashboard/ does not.
#[tokio::test]
async fn v0_requires_auth_dashboard_does_not() {
    let tr = TestRouter::new();

    // Unauthenticated /v0/status → 401.
    let req_api = Request::builder()
        .method("GET")
        .uri("/v0/status")
        .body(Body::empty())
        .unwrap();
    let resp_api = tr.router.clone().oneshot(req_api).await.unwrap();
    assert_eq!(resp_api.status(), StatusCode::UNAUTHORIZED);

    // Unauthenticated /dashboard/ → 200 (no auth needed).
    let req_dash = Request::builder()
        .method("GET")
        .uri("/dashboard/")
        .body(Body::empty())
        .unwrap();
    let resp_dash = tr.router.clone().oneshot(req_dash).await.unwrap();
    assert_eq!(resp_dash.status(), StatusCode::OK);
}

/// When dashboard_enabled=false, /dashboard/ must return 404.
#[tokio::test]
async fn dashboard_disabled_returns_404() {
    let tmp = tempfile::TempDir::new().unwrap();
    let token = "cafebabe".repeat(8);
    std::fs::write(tmp.path().join("api.token"), &token).unwrap();

    let engine = Arc::new(hush_core::DecisionEngine::new());
    let ring = Arc::new(hush_core::QueryRing::new(1000));
    let metrics = Arc::new(hush_daemon::metrics::Metrics::new());
    let (sentinel_impl, _rx) = hush_daemon::sentinel::Sentinel::new(Arc::clone(&engine));
    let sentinel = Arc::new(sentinel_impl);
    let lists_config = ListsConfig {
        preset: "custom".to_string(),
        extra_categories: Vec::new(),
        sources: Vec::new(),
        refresh_hours: 24,
        jitter_minutes: 0,
        snapshot_dir: None, // WP12: no snapshot in test configs
    };
    let lists = Arc::new(hush_daemon::lists::ListsPipeline::new(
        lists_config,
        tmp.path().to_path_buf(),
        Arc::clone(&engine),
    ));
    let cancel_d = tokio_util::sync::CancellationToken::new();
    let rollup_d = rollup::start_rollup(
        tmp.path().to_path_buf(),
        hush_core::config::QueryLogMode::Off,
        7,
        cancel_d,
    );
    let privacy_cfg_d = PrivacyConfig::default();
    let privacy_arc_d = Arc::new(arc_swap::ArcSwap::from_pointee(privacy_cfg_d.clone()));
    let api_state = Arc::new(ApiState {
        token: token.clone(),
        engine,
        sentinel,
        metrics,
        ring,
        lists,
        allowlist: std::sync::Mutex::new(Vec::new()),
        start_time: std::time::Instant::now(),
        state_dir: tmp.path().to_path_buf(),
        platform: Arc::new(hush_daemon::platform::stub::MockPlatform::new(
            std::iter::empty::<(String, hush_daemon::platform::DnsSetting)>(),
        )),
        takeover_cfg: hush_daemon::sentinel::takeover::TakeoverConfig::default(),
        privacy_cfg: privacy_cfg_d,
        privacy_arc: privacy_arc_d,
        rollup: rollup_d,
        dashboard_enabled: false, // disabled
        network_guard_cfg: hush_core::config::NetworkGuardConfig::default(),
        mdns_map: hush_daemon::mdns::MdnsMap::new(),
        active_profile: std::sync::Mutex::new(None),
        current_config: std::sync::Mutex::new(hush_core::config::HushConfig::default()),
    });
    let router = hush_daemon::api::routes::build_router(Arc::clone(&api_state));

    let req = Request::builder()
        .method("GET")
        .uri("/dashboard/")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// GET /v0/stats/history returns empty buckets + log_mode="off" when query_log=Off.
#[tokio::test]
async fn stats_history_log_off_returns_empty() {
    let tmp = tempfile::TempDir::new().unwrap();
    let token = "cafebabe".repeat(8);
    std::fs::write(tmp.path().join("api.token"), &token).unwrap();

    let engine = Arc::new(hush_core::DecisionEngine::new());
    let ring = Arc::new(hush_core::QueryRing::new(1000));
    let metrics = Arc::new(hush_daemon::metrics::Metrics::new());
    let (sentinel_impl, _rx) = hush_daemon::sentinel::Sentinel::new(Arc::clone(&engine));
    let sentinel = Arc::new(sentinel_impl);
    let lists_config = ListsConfig {
        preset: "custom".to_string(),
        extra_categories: Vec::new(),
        sources: Vec::new(),
        refresh_hours: 24,
        jitter_minutes: 0,
        snapshot_dir: None, // WP12: no snapshot in test configs
    };
    let lists = Arc::new(hush_daemon::lists::ListsPipeline::new(
        lists_config,
        tmp.path().to_path_buf(),
        Arc::clone(&engine),
    ));
    let cancel_h = tokio_util::sync::CancellationToken::new();
    let rollup_h = rollup::start_rollup(
        tmp.path().to_path_buf(),
        hush_core::config::QueryLogMode::Off,
        7,
        cancel_h,
    );
    let privacy_off = PrivacyConfig {
        query_log: hush_core::config::QueryLogMode::Off,
        ..PrivacyConfig::default()
    };
    let privacy_arc_h = Arc::new(arc_swap::ArcSwap::from_pointee(privacy_off.clone()));
    let api_state = Arc::new(ApiState {
        token: token.clone(),
        engine,
        sentinel,
        metrics,
        ring,
        lists,
        allowlist: std::sync::Mutex::new(Vec::new()),
        start_time: std::time::Instant::now(),
        state_dir: tmp.path().to_path_buf(),
        platform: Arc::new(hush_daemon::platform::stub::MockPlatform::new(
            std::iter::empty::<(String, hush_daemon::platform::DnsSetting)>(),
        )),
        takeover_cfg: hush_daemon::sentinel::takeover::TakeoverConfig::default(),
        privacy_cfg: privacy_off,
        privacy_arc: privacy_arc_h,
        rollup: rollup_h,
        dashboard_enabled: true,
        network_guard_cfg: hush_core::config::NetworkGuardConfig::default(),
        mdns_map: hush_daemon::mdns::MdnsMap::new(),
        active_profile: std::sync::Mutex::new(None),
        current_config: std::sync::Mutex::new(hush_core::config::HushConfig::default()),
    });
    let router = hush_daemon::api::routes::build_router(Arc::clone(&api_state));
    let auth = format!("Bearer {token}");

    let req = Request::builder()
        .method("GET")
        .uri("/v0/stats/history?hours=24&bucket=3600")
        .header(header::AUTHORIZATION, &auth)
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["log_mode"], "off");
    assert!(
        json["buckets"].as_array().unwrap().is_empty(),
        "buckets must be empty when log is off"
    );
}

/// GET /v0/stats/top returns empty lists + log_mode="off" when query_log=Off.
#[tokio::test]
async fn stats_top_log_off_returns_empty() {
    let tmp = tempfile::TempDir::new().unwrap();
    let token = "cafebabe".repeat(8);
    std::fs::write(tmp.path().join("api.token"), &token).unwrap();

    let engine = Arc::new(hush_core::DecisionEngine::new());
    let ring = Arc::new(hush_core::QueryRing::new(1000));
    let metrics = Arc::new(hush_daemon::metrics::Metrics::new());
    let (sentinel_impl, _rx) = hush_daemon::sentinel::Sentinel::new(Arc::clone(&engine));
    let sentinel = Arc::new(sentinel_impl);
    let lists_config = ListsConfig {
        preset: "custom".to_string(),
        extra_categories: Vec::new(),
        sources: Vec::new(),
        refresh_hours: 24,
        jitter_minutes: 0,
        snapshot_dir: None, // WP12: no snapshot in test configs
    };
    let lists = Arc::new(hush_daemon::lists::ListsPipeline::new(
        lists_config,
        tmp.path().to_path_buf(),
        Arc::clone(&engine),
    ));
    let cancel_t = tokio_util::sync::CancellationToken::new();
    let rollup_t = rollup::start_rollup(
        tmp.path().to_path_buf(),
        hush_core::config::QueryLogMode::Off,
        7,
        cancel_t,
    );
    let privacy_off = PrivacyConfig {
        query_log: hush_core::config::QueryLogMode::Off,
        ..PrivacyConfig::default()
    };
    let privacy_arc_t = Arc::new(arc_swap::ArcSwap::from_pointee(privacy_off.clone()));
    let api_state = Arc::new(ApiState {
        token: token.clone(),
        engine,
        sentinel,
        metrics,
        ring,
        lists,
        allowlist: std::sync::Mutex::new(Vec::new()),
        start_time: std::time::Instant::now(),
        state_dir: tmp.path().to_path_buf(),
        platform: Arc::new(hush_daemon::platform::stub::MockPlatform::new(
            std::iter::empty::<(String, hush_daemon::platform::DnsSetting)>(),
        )),
        takeover_cfg: hush_daemon::sentinel::takeover::TakeoverConfig::default(),
        privacy_cfg: privacy_off,
        privacy_arc: privacy_arc_t,
        rollup: rollup_t,
        dashboard_enabled: true,
        network_guard_cfg: hush_core::config::NetworkGuardConfig::default(),
        mdns_map: hush_daemon::mdns::MdnsMap::new(),
        active_profile: std::sync::Mutex::new(None),
        current_config: std::sync::Mutex::new(hush_core::config::HushConfig::default()),
    });
    let router = hush_daemon::api::routes::build_router(Arc::clone(&api_state));
    let auth = format!("Bearer {token}");

    let req = Request::builder()
        .method("GET")
        .uri("/v0/stats/top?n=10&hours=24")
        .header(header::AUTHORIZATION, &auth)
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["log_mode"], "off");
    assert!(
        json["blocked"].as_array().unwrap().is_empty(),
        "blocked must be empty when log is off"
    );
    assert!(
        json["allowed"].as_array().unwrap().is_empty(),
        "allowed must be empty when log is off"
    );
}

// ── Finding 2: Path traversal via profile name returns 400 ───────────────────

/// POST /v0/config/reload with a traversal profile name must return 400.
#[tokio::test]
async fn config_reload_path_traversal_returns_400() {
    let tr = TestRouter::new();

    // Set an active profile so the handler reaches name validation.
    {
        let mut active = tr
            .state
            .active_profile
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *active = Some("../../etc/passwd".to_string());
    }

    // The traversal name is in active_profile; reload should reject with 400.
    let (status, json) = tr
        .post_json(
            "/v0/config/reload",
            serde_json::json!({"profile": "../../etc/passwd"}),
        )
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "traversal profile name must return 400; body: {json}"
    );
    assert_eq!(
        json["error"], "invalid_profile_name",
        "error key must be 'invalid_profile_name'"
    );
}

/// GET /v0/profiles/:name with an invalid name (dots, special chars) must return 400.
#[tokio::test]
async fn profile_show_invalid_name_returns_400() {
    let tr = TestRouter::new();
    // A name with a dot is invalid (only [A-Za-z0-9_-] allowed).
    let (status, json) = tr.get("/v0/profiles/bad.name").await;
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "invalid profile name must return 400; body: {json}"
    );
    assert_eq!(json["error"], "invalid_profile_name");
}

// ── Finding 7: query_log=off makes /v0/clients return disabled explanation ────

/// When privacy.query_log=Off, GET /v0/clients must return log_clients_enabled=false
/// with an explanatory message, regardless of network_guard.log_clients.
#[tokio::test]
async fn clients_query_log_off_returns_disabled_explanation() {
    let tmp = tempfile::TempDir::new().unwrap();
    let token = "cafebabe".repeat(8);
    std::fs::write(tmp.path().join("api.token"), &token).unwrap();

    let engine = Arc::new(hush_core::DecisionEngine::new());
    let ring = Arc::new(hush_core::QueryRing::new(1000));
    let metrics = Arc::new(hush_daemon::metrics::Metrics::new());
    let (sentinel_impl, _rx) = hush_daemon::sentinel::Sentinel::new(Arc::clone(&engine));
    let sentinel = Arc::new(sentinel_impl);
    let lists = Arc::new(hush_daemon::lists::ListsPipeline::new(
        ListsConfig {
            preset: "custom".to_string(),
            extra_categories: Vec::new(),
            sources: Vec::new(),
            refresh_hours: 24,
            jitter_minutes: 0,
            snapshot_dir: None,
        },
        tmp.path().to_path_buf(),
        Arc::clone(&engine),
    ));
    let cancel_c = tokio_util::sync::CancellationToken::new();
    let rollup_c = rollup::start_rollup(
        tmp.path().to_path_buf(),
        hush_core::config::QueryLogMode::Off,
        7,
        cancel_c,
    );
    // log_clients=true but query_log=Off — the query_log check takes precedence.
    let privacy_off = PrivacyConfig {
        query_log: hush_core::config::QueryLogMode::Off,
        ..PrivacyConfig::default()
    };
    let privacy_arc_c = Arc::new(arc_swap::ArcSwap::from_pointee(privacy_off.clone()));
    let api_state = Arc::new(hush_daemon::api::ApiState {
        token: token.clone(),
        engine,
        sentinel,
        metrics,
        ring,
        lists,
        allowlist: std::sync::Mutex::new(Vec::new()),
        start_time: std::time::Instant::now(),
        state_dir: tmp.path().to_path_buf(),
        platform: Arc::new(hush_daemon::platform::stub::MockPlatform::new(
            std::iter::empty::<(String, hush_daemon::platform::DnsSetting)>(),
        )),
        takeover_cfg: hush_daemon::sentinel::takeover::TakeoverConfig::default(),
        privacy_cfg: privacy_off,
        privacy_arc: privacy_arc_c,
        rollup: rollup_c,
        dashboard_enabled: true,
        network_guard_cfg: hush_core::config::NetworkGuardConfig {
            enabled: false,
            bind: Vec::new(),
            log_clients: true, // enabled, but query_log=off overrides
            mdns_insight: false,
        },
        mdns_map: hush_daemon::mdns::MdnsMap::new(),
        active_profile: std::sync::Mutex::new(None),
        current_config: std::sync::Mutex::new(hush_core::config::HushConfig::default()),
    });
    let router = hush_daemon::api::routes::build_router(Arc::clone(&api_state));
    let auth = format!("Bearer {token}");

    let req = Request::builder()
        .method("GET")
        .uri("/v0/clients")
        .header(header::AUTHORIZATION, &auth)
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        json["log_clients_enabled"], false,
        "query_log=off must disable clients regardless of log_clients flag"
    );
    assert!(
        !json["explanation"].is_null(),
        "explanation must be present when query_log=off"
    );
    let explanation = json["explanation"].as_str().unwrap_or("");
    assert!(
        explanation.contains("query_log"),
        "explanation must mention query_log; got: {explanation}"
    );
}

// ── Snooze → status snoozed, resume reverts (full flow) ───────────────────────

#[tokio::test]
async fn snooze_then_resume_full_flow() {
    let tr = TestRouter::new();

    // Initially filtering.
    let (s1, j1) = tr.get("/v0/status").await;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(j1["state"], "filtering");
    assert!(j1["snoozed_until_unix_ms"].is_null());

    // Snooze.
    let (s2, j2) = tr
        .post_json("/v0/snooze", serde_json::json!({"secs": 60}))
        .await;
    assert_eq!(s2, StatusCode::OK);
    assert!(j2["snoozed_until_unix_ms"].as_u64().unwrap() > 0);

    // Status must show snoozed + until > 0.
    let (_, js) = tr.get("/v0/status").await;
    assert_eq!(js["state"], "snoozed");
    assert!(js["snoozed_until_unix_ms"].as_u64().unwrap() > 0);

    // Resume.
    let (s3, j3) = tr.post_empty("/v0/resume").await;
    assert_eq!(s3, StatusCode::OK);
    assert_eq!(j3["state"], "filtering");

    // Status must show filtering again; until is null.
    let (_, jf) = tr.get("/v0/status").await;
    assert_eq!(jf["state"], "filtering");
    assert!(jf["snoozed_until_unix_ms"].is_null());
}
