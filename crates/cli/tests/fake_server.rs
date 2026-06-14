//! Shared fake-API-server helpers used by integration tests.
//!
//! Spins up an in-process axum server on an ephemeral port implementing the
//! `/v0` contract from `specs/wp3-api-cli.md` §2.  The server is intentionally
//! minimal — it covers happy paths and the explicit error scenarios mandated by
//! the spec.
//!
//! Usage pattern:
//! ```no_run
//! let (addr, token, _guard) = fake_server::start_filtering().await;
//! // The guard's Drop stops the server.
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{get, post},
    Router,
};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// Token the fake server expects.
pub const VALID_TOKEN: &str = "cafebabe0000111122223333444455556666777788889999aaaabbbbccccddd";

/// Guard that shuts down the fake server when dropped.
pub struct ServerGuard {
    shutdown: Option<oneshot::Sender<()>>,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

// ── Server state ──────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    /// Expected bearer token.
    token: String,
    /// Current daemon state string.
    daemon_state: String,
}

// ── Auth helper ───────────────────────────────────────────────────────────────

fn check_auth(state: &AppState, headers: &HeaderMap) -> Result<(), (StatusCode, Json<Value>)> {
    let expected = format!("Bearer {}", state.token);
    let got = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if got != expected {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "unauthorized"})),
        ));
    }
    Ok(())
}

// ── Routes ────────────────────────────────────────────────────────────────────

async fn get_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    check_auth(&state, &headers)?;
    Ok(Json(json!({
        "state": state.daemon_state,
        "snoozed_until_unix_ms": null,
        "version": "0.0.1-test",
        "uptime_secs": 42,
        "rules": {
            "block_count": 12345,
            "allow_count": 3,
            "built_unix_ms": 1700000000000u64,
            "sources": ["oisd-small"]
        },
        "counters": {
            "queries_total": 500,
            "blocked_total": 100,
            "forwarded_total": 390,
            "local_total": 10,
            "servfail_total": 0
        },
        "privacy": {
            "browser_doh_canary": true,
            "cname_inspection": true,
            "query_log": "full",
            "block_doh_bypass": false,
            "block_private_relay": false,
            "doh_padding": true,
            "rebind_protection": true
        }
    })))
}

#[derive(serde::Deserialize)]
struct RecentQueryParams {
    n: Option<u32>,
    blocked_only: Option<bool>,
}

async fn get_queries_recent(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<RecentQueryParams>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    check_auth(&state, &headers)?;
    let n = params.n.unwrap_or(50).clamp(1, 1000);
    let blocked_only = params.blocked_only.unwrap_or(false);

    let mut queries = vec![
        json!({
            "ts_unix_ms": 1700000002000u64,
            "qname": "ads.evil.com",
            "qtype": 1,
            "verdict": "block",
            "reason": "list_blocked",
            "upstream_ms": null
        }),
        json!({
            "ts_unix_ms": 1700000001000u64,
            "qname": "good.example.com",
            "qtype": 1,
            "verdict": "forward",
            "reason": "no_match",
            "upstream_ms": 15
        }),
    ];

    if blocked_only {
        queries.retain(|q| q["verdict"] == "block");
    }
    queries.truncate(n as usize);

    Ok(Json(json!({ "queries": queries, "log_mode": "full" })))
}

async fn get_stats_summary(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    check_auth(&state, &headers)?;
    Ok(Json(json!({
        "since_unix_ms": 1700000000000u64,
        "queries_total": 500,
        "blocked_total": 100,
        "block_rate": 0.2
    })))
}

async fn post_snooze(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Json(body): axum::extract::Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    check_auth(&state, &headers)?;
    let secs = body.get("secs").and_then(|v| v.as_u64()).unwrap_or(0);
    if !(1..=86400).contains(&secs) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_body", "detail": "secs must be in [1, 86400]"})),
        ));
    }
    let until_ms = 9_000_000_000_000u64;
    Ok(Json(json!({ "snoozed_until_unix_ms": until_ms })))
}

async fn post_resume(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    check_auth(&state, &headers)?;
    Ok(Json(json!({ "state": "filtering" })))
}

async fn post_allow(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Json(body): axum::extract::Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    check_auth(&state, &headers)?;
    let domain = match body.get("domain").and_then(|v| v.as_str()) {
        Some(d) => d.to_owned(),
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid_body", "detail": "domain is required"})),
            ))
        }
    };
    Ok(Json(json!({ "allowed": [domain] })))
}

async fn post_unallow(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Json(body): axum::extract::Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    check_auth(&state, &headers)?;
    let _domain = match body.get("domain").and_then(|v| v.as_str()) {
        Some(d) => d.to_owned(),
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid_body", "detail": "domain is required"})),
            ))
        }
    };
    Ok(Json(json!({ "allowed": [] })))
}

async fn get_allowlist(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    check_auth(&state, &headers)?;
    Ok(Json(json!({ "allowed": ["example.com", "good.org"] })))
}

async fn get_lists(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    check_auth(&state, &headers)?;
    Ok(Json(json!({
        "preset": "balanced",
        "sources": [
            {
                "name": "oisd-small",
                "enabled": true,
                "rule_count": 50000,
                "last_fetched_unix_ms": 1700000000000u64,
                "last_http_status": 200,
                "last_error": null,
                "category": "oisd-small",
                "license": null,
                "attribution": "OISD (https://oisd.nl) — runtime-fetched; not bundled"
            }
        ]
    })))
}

async fn post_lists_refresh(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    check_auth(&state, &headers)?;
    Ok((StatusCode::ACCEPTED, Json(json!({ "started": true }))))
}

// ── Server constructor ────────────────────────────────────────────────────────

/// Start a fake API server returning "filtering" state with `VALID_TOKEN`.
///
/// Returns `(addr, token, guard)`.  The server runs until `guard` is dropped.
pub async fn start_filtering() -> (SocketAddr, String, ServerGuard) {
    start_with_state("filtering", VALID_TOKEN).await
}

/// Start a fake API server with a custom daemon state and token.
pub async fn start_with_state(
    daemon_state: &str,
    token: &str,
) -> (SocketAddr, String, ServerGuard) {
    let app_state = Arc::new(AppState {
        token: token.to_owned(),
        daemon_state: daemon_state.to_owned(),
    });

    let router = Router::new()
        .route("/v0/status", get(get_status))
        .route("/v0/queries/recent", get(get_queries_recent))
        .route("/v0/stats/summary", get(get_stats_summary))
        .route("/v0/snooze", post(post_snooze))
        .route("/v0/resume", post(post_resume))
        .route("/v0/allow", post(post_allow))
        .route("/v0/unallow", post(post_unallow))
        .route("/v0/allowlist", get(get_allowlist))
        .route("/v0/lists", get(get_lists))
        .route("/v0/lists/refresh", post(post_lists_refresh))
        .with_state(app_state);

    // Bind to port 0 → OS assigns an ephemeral port.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind ephemeral port");
    let addr = listener.local_addr().expect("failed to get local addr");

    let (tx, rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await
            .expect("server error");
    });

    let guard = ServerGuard { shutdown: Some(tx) };
    (addr, token.to_owned(), guard)
}

/// Write the `api.addr` and `api.token` files that the CLI reads.
pub fn write_state_files(dir: &std::path::Path, addr: SocketAddr, token: &str) {
    std::fs::write(dir.join("api.addr"), addr.to_string()).expect("write api.addr");
    std::fs::write(dir.join("api.token"), token).expect("write api.token");
}
