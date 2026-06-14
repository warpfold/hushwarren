//! Axum route handlers for the `/v0` control API and `/dashboard/` SPA.
//!
//! Implements `specs/wp3-api-cli.md` §2 endpoints and
//! `specs/wp9-dashboard-rollup.md` §3–§4.
//!
//! Every `/v0/*` handler:
//! 1. Calls `require_auth` → returns 401 on failure.
//! 2. Performs its operation.
//! 3. Returns JSON with the correct status code.
//!
//! `/dashboard/*` assets are served without authentication (they contain no
//! secrets).  When `dashboard.enabled = false`, `/dashboard/*` returns 404.
//! Handlers never panic; the axum fallback returns the spec 404 shape.

use std::{net::IpAddr, sync::Arc, time::Duration};

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use tracing::{debug, info, warn};

use crate::{
    api::{
        auth::check_bearer,
        types::{
            AllowlistBody, ApiErrorBody, ClientEntry, ClientsBody, ClientsParams, ConfigReloadBody,
            ConfigReloadReq, Counters, DomainReq, HistoryBody, HistoryBucket, HistoryParams,
            ListSourceStatus, ListsBody, ListsRefreshBody, PrivacyStatus, ProfileBody,
            ProfileEntry, ProfilesBody, QueriesBody, QueryRecord, RecentQueryParams, RestoreBody,
            ResumeBody, RulesStatus, SnoozeBody, SnoozeReq, StatsSummaryBody, StatusBody,
            TakeoverBody, TopBody, TopEntry, TopParams,
        },
        ApiState,
    },
    sentinel::{takeover, GuardState},
};
use hush_core::{catalog::Catalog, config::QueryLogMode, Domain};

// ── Embedded dashboard assets ─────────────────────────────────────────────────

/// `index.html` — embedded at compile time.
const DASHBOARD_INDEX: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/dashboard/index.html"
));

/// `style.css` — embedded at compile time.
const DASHBOARD_CSS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/dashboard/style.css"
));

/// `app.js` — embedded at compile time.
const DASHBOARD_JS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/dashboard/app.js"
));

// ── Auth helper ───────────────────────────────────────────────────────────────

/// Extract the `Authorization` header and compare constant-time.
///
/// Returns `Ok(())` on success or an axum `Response` (401) on failure.
///
/// The `Response` is boxed to keep the `Err` variant size small (clippy lint).
fn require_auth(state: &ApiState, headers: &HeaderMap) -> Result<(), Box<Response>> {
    let header_val = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    if check_bearer(header_val, &state.token) {
        Ok(())
    } else {
        Err(Box::new(
            (
                StatusCode::UNAUTHORIZED,
                Json(ApiErrorBody::simple("unauthorized")),
            )
                .into_response(),
        ))
    }
}

// ── Route table ───────────────────────────────────────────────────────────────

/// Build the complete router: `/v0` API + `/dashboard/` SPA.
pub fn build_router(state: Arc<ApiState>) -> Router {
    Router::new()
        // V0 API routes (all require Bearer auth).
        .route("/v0/status", get(handle_status))
        .route("/v0/queries/recent", get(handle_queries_recent))
        .route("/v0/stats/summary", get(handle_stats_summary))
        .route("/v0/stats/history", get(handle_stats_history))
        .route("/v0/stats/top", get(handle_stats_top))
        .route("/v0/snooze", post(handle_snooze))
        .route("/v0/resume", post(handle_resume))
        .route("/v0/allow", post(handle_allow))
        .route("/v0/unallow", post(handle_unallow))
        .route("/v0/allowlist", get(handle_allowlist))
        .route("/v0/lists", get(handle_lists))
        .route("/v0/lists/refresh", post(handle_lists_refresh))
        .route("/v0/takeover", post(handle_takeover))
        .route("/v0/restore", post(handle_restore))
        .route("/v0/clients", get(handle_clients))
        .route("/v0/config/reload", post(handle_config_reload))
        .route("/v0/profiles", get(handle_profiles_list))
        .route("/v0/profiles/{name}", get(handle_profile_show))
        // Dashboard SPA routes (no auth — assets contain no secrets).
        .route("/dashboard/", get(handle_dashboard_index))
        .route("/dashboard/index.html", get(handle_dashboard_index))
        .route("/dashboard/style.css", get(handle_dashboard_css))
        .route("/dashboard/app.js", get(handle_dashboard_js))
        .fallback(handle_not_found)
        .with_state(state)
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// `GET /v0/status` — daemon health and counters.
async fn handle_status(State(state): State<Arc<ApiState>>, headers: HeaderMap) -> Response {
    if let Err(r) = require_auth(&state, &headers) {
        return *r;
    }

    let (state_str, standing_by_reason) = state.sentinel.state_api();
    let snoozed_until = match state.sentinel.current_state() {
        GuardState::Snoozed { until_unix_ms } => Some(until_unix_ms),
        _ => None,
    };

    let rules = state.engine.current_rules();
    let rules_body = RulesStatus {
        block_count: rules.meta.block_count,
        allow_count: rules.meta.allow_count,
        built_unix_ms: rules.meta.built_unix_ms,
        sources: rules.meta.source_names.clone(),
    };
    drop(rules);

    let snap = state.metrics.snapshot();
    let counters = Counters {
        queries_total: snap.queries_total,
        blocked_total: snap.blocked_total,
        forwarded_total: snap.forwarded_total,
        local_total: snap.local_total,
        servfail_total: snap.servfail_total,
    };

    let uptime_secs = state.start_time.elapsed().as_secs();

    let privacy = PrivacyStatus {
        browser_doh_canary: state.privacy_cfg.browser_doh_canary,
        cname_inspection: state.privacy_cfg.cname_inspection,
        query_log: query_log_mode_to_str(state.privacy_cfg.query_log).to_owned(),
        block_doh_bypass: state.privacy_cfg.block_doh_bypass,
        block_private_relay: state.privacy_cfg.block_private_relay,
        doh_padding: state.privacy_cfg.doh_padding,
        rebind_protection: state.privacy_cfg.rebind_protection,
    };

    let active_profile = state
        .active_profile
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();

    let body = StatusBody {
        state: state_str,
        snoozed_until_unix_ms: snoozed_until,
        standing_by_reason,
        version: env!("CARGO_PKG_VERSION").to_owned(),
        uptime_secs,
        rules: rules_body,
        counters,
        privacy,
        active_profile,
    };

    Json(body).into_response()
}

/// `GET /v0/queries/recent?n=100&blocked_only=true`
async fn handle_queries_recent(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Query(params): Query<RecentQueryParams>,
) -> Response {
    if let Err(r) = require_auth(&state, &headers) {
        return *r;
    }

    let n = params.n.unwrap_or(100).clamp(1, 1000) as usize;
    let blocked_only = params.blocked_only.unwrap_or(false);

    let records: Vec<_> = if blocked_only {
        state.ring.recent_blocked(n)
    } else {
        state.ring.recent(n)
    };

    let queries = records
        .into_iter()
        .map(|r| QueryRecord {
            ts_unix_ms: r.ts_unix_ms,
            qname: r.qname,
            qtype: r.qtype,
            verdict: verdict_to_string(r.verdict),
            reason: reason_to_string(r.reason),
            upstream_ms: r.upstream_ms,
        })
        .collect();

    let log_mode = query_log_mode_to_str(state.privacy_cfg.query_log).to_owned();

    Json(QueriesBody { queries, log_mode }).into_response()
}

/// `GET /v0/stats/summary`
async fn handle_stats_summary(State(state): State<Arc<ApiState>>, headers: HeaderMap) -> Response {
    if let Err(r) = require_auth(&state, &headers) {
        return *r;
    }

    let ring_stats = state.ring.stats();
    let queries_total = ring_stats.total;
    let blocked_total = ring_stats.blocked;
    let block_rate = if queries_total > 0 {
        blocked_total as f32 / queries_total as f32
    } else {
        0.0
    };

    let body = StatsSummaryBody {
        since_unix_ms: ring_stats.since_unix_ms,
        queries_total,
        blocked_total,
        block_rate,
    };

    Json(body).into_response()
}

/// `POST /v0/snooze` — `{secs: u64}`, secs must be in `1..=86400`.
async fn handle_snooze(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    body: Result<Json<SnoozeReq>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if let Err(r) = require_auth(&state, &headers) {
        return *r;
    }

    let req = match body {
        Ok(Json(req)) => req,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiErrorBody::with_detail("invalid_body", e.to_string())),
            )
                .into_response()
        }
    };

    if !(1..=86400).contains(&req.secs) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiErrorBody::with_detail(
                "invalid_body",
                "secs must be in [1, 86400]",
            )),
        )
            .into_response();
    }

    state.sentinel.snooze(Duration::from_secs(req.secs));

    // Compute the until_ms from the sentinel state (authoritative).
    let until_unix_ms = match state.sentinel.current_state() {
        GuardState::Snoozed { until_unix_ms } => until_unix_ms,
        _ => {
            // Snooze was set synchronously, so this path should not be reached.
            // Fallback: compute from now.
            unix_ms_now() + req.secs * 1000
        }
    };

    debug!(secs = req.secs, until_unix_ms, "snooze set");
    Json(SnoozeBody {
        snoozed_until_unix_ms: until_unix_ms,
    })
    .into_response()
}

/// `POST /v0/resume` — clear any active snooze.
async fn handle_resume(State(state): State<Arc<ApiState>>, headers: HeaderMap) -> Response {
    if let Err(r) = require_auth(&state, &headers) {
        return *r;
    }

    state.sentinel.resume();
    debug!("snooze cleared via resume");

    let guard_state = state.sentinel.current_state();
    Json(ResumeBody {
        state: guard_state_to_string(&guard_state),
    })
    .into_response()
}

/// `POST /v0/allow` — add a domain to the user allowlist.
///
/// Spec §3: `Domain::parse` → dedup → `engine.set_user_allow` → persist BEFORE responding.
async fn handle_allow(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    body: Result<Json<DomainReq>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if let Err(r) = require_auth(&state, &headers) {
        return *r;
    }

    let req = match body {
        Ok(Json(req)) => req,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiErrorBody::with_detail("invalid_body", e.to_string())),
            )
                .into_response()
        }
    };

    let domain = match Domain::parse(&req.domain) {
        Ok(d) => d,
        Err(e) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(ApiErrorBody::with_detail("invalid_domain", e.to_string())),
            )
                .into_response()
        }
    };

    // Load the current allow set, add the domain (dedup), persist, then update the engine.
    let mut domains = {
        let lock = state.allowlist.lock().unwrap_or_else(|e| e.into_inner());
        lock.clone()
    };

    let domain_str = domain.as_str().to_owned();
    if !domains.contains(&domain_str) {
        domains.push(domain_str);
    }

    // Persist BEFORE updating the engine (spec §3 ordering).
    let persist_path = state.state_dir.join("allowlist.txt");
    if let Err(e) = persist_allowlist(&persist_path, &domains) {
        tracing::warn!(error = %e, "failed to persist allowlist");
    }

    // Update the engine.
    let parsed_domains: Vec<Domain> = domains
        .iter()
        .filter_map(|s| Domain::parse(s).ok())
        .collect();
    state.engine.set_user_allow(parsed_domains);

    // Update the in-memory set.
    {
        let mut lock = state.allowlist.lock().unwrap_or_else(|e| e.into_inner());
        *lock = domains.clone();
    }

    info!(domain = domain.as_str(), "domain added to allowlist");
    Json(AllowlistBody { allowed: domains }).into_response()
}

/// `POST /v0/unallow` — remove a domain from the user allowlist.
async fn handle_unallow(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    body: Result<Json<DomainReq>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if let Err(r) = require_auth(&state, &headers) {
        return *r;
    }

    let req = match body {
        Ok(Json(req)) => req,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiErrorBody::with_detail("invalid_body", e.to_string())),
            )
                .into_response()
        }
    };

    let domain = match Domain::parse(&req.domain) {
        Ok(d) => d,
        Err(e) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(ApiErrorBody::with_detail("invalid_domain", e.to_string())),
            )
                .into_response()
        }
    };

    let domain_str = domain.as_str().to_owned();

    let mut domains = {
        let lock = state.allowlist.lock().unwrap_or_else(|e| e.into_inner());
        lock.clone()
    };

    // Spec §3: remove the exact entry only.
    domains.retain(|d| d != &domain_str);

    // Persist BEFORE updating the engine.
    let persist_path = state.state_dir.join("allowlist.txt");
    if let Err(e) = persist_allowlist(&persist_path, &domains) {
        tracing::warn!(error = %e, "failed to persist allowlist");
    }

    let parsed_domains: Vec<Domain> = domains
        .iter()
        .filter_map(|s| Domain::parse(s).ok())
        .collect();
    state.engine.set_user_allow(parsed_domains);

    {
        let mut lock = state.allowlist.lock().unwrap_or_else(|e| e.into_inner());
        *lock = domains.clone();
    }

    info!(domain = domain.as_str(), "domain removed from allowlist");
    Json(AllowlistBody { allowed: domains }).into_response()
}

/// `GET /v0/allowlist` — return the full current allowlist.
async fn handle_allowlist(State(state): State<Arc<ApiState>>, headers: HeaderMap) -> Response {
    if let Err(r) = require_auth(&state, &headers) {
        return *r;
    }

    let domains = {
        let lock = state.allowlist.lock().unwrap_or_else(|e| e.into_inner());
        lock.clone()
    };

    Json(AllowlistBody { allowed: domains }).into_response()
}

/// `GET /v0/lists` — list pipeline status.
///
/// WP4 §4: adds `preset` at the top level and per-source `category`, `license`,
/// `attribution` by looking up each source URL in the compiled-in catalog.
/// Sources not found in the catalog (user-custom) get `None` for all three.
async fn handle_lists(State(state): State<Arc<ApiState>>, headers: HeaderMap) -> Response {
    if let Err(r) = require_auth(&state, &headers) {
        return *r;
    }

    let list_status = state.lists.status();
    let preset = state.lists.preset();

    let sources = list_status
        .per_source
        .into_iter()
        .map(|s| {
            // Look up the source URL in the catalog to get metadata.
            let catalog_entry = Catalog::find_by_url(&s.url);
            ListSourceStatus {
                name: s.name,
                enabled: true,
                rule_count: s.last_rule_count,
                last_fetched_unix_ms: s.last_ok_unix_ms,
                last_http_status: None,
                last_error: s.last_error,
                category: catalog_entry.map(|e| e.key.to_owned()),
                license: catalog_entry.and_then(|e| e.license).map(str::to_owned),
                attribution: catalog_entry.map(|e| e.attribution.to_owned()),
            }
        })
        .collect();

    Json(ListsBody { preset, sources }).into_response()
}

/// `POST /v0/lists/refresh` — kick the refresh task (non-blocking, returns 202).
async fn handle_lists_refresh(State(state): State<Arc<ApiState>>, headers: HeaderMap) -> Response {
    if let Err(r) = require_auth(&state, &headers) {
        return *r;
    }

    // Kick the real fetch+compile pipeline non-blocking.
    let lists = Arc::clone(&state.lists);
    tokio::spawn(async move {
        if let Err(e) = lists.force_refresh().await {
            tracing::warn!(error = %e, "background list refresh failed");
        }
    });

    info!("list refresh triggered");
    (
        StatusCode::ACCEPTED,
        Json(ListsRefreshBody { started: true }),
    )
        .into_response()
}

/// `POST /v0/takeover` — execute the DNS takeover transaction.
///
/// Requires root on macOS. Returns 200 on success or 500 on failure.
async fn handle_takeover(State(state): State<Arc<ApiState>>, headers: HeaderMap) -> Response {
    if let Err(r) = require_auth(&state, &headers) {
        return *r;
    }

    let platform = Arc::clone(&state.platform);
    let cfg = state.takeover_cfg.clone();

    let result = takeover::run_takeover(platform.as_ref(), &cfg).await;
    match result {
        Ok(_snapshot) => {
            info!("DNS takeover succeeded");
            Json(TakeoverBody {
                success: true,
                error: None,
            })
            .into_response()
        }
        Err(e) => {
            warn!(error = %e, "DNS takeover failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(TakeoverBody {
                    success: false,
                    error: Some(e.to_string()),
                }),
            )
                .into_response()
        }
    }
}

/// `POST /v0/restore` — restore DNS settings from snapshot.
///
/// Requires root on macOS. Returns 200 on success or 500 on failure.
async fn handle_restore(State(state): State<Arc<ApiState>>, headers: HeaderMap) -> Response {
    if let Err(r) = require_auth(&state, &headers) {
        return *r;
    }

    let platform = Arc::clone(&state.platform);
    let state_dir = state.state_dir.clone();

    // Load the persisted snapshot; if none is found, return 409 Conflict.
    let snap = match crate::platform::load_snapshot(&state_dir) {
        Ok(Some(s)) => s,
        Ok(None) => {
            return (
                StatusCode::CONFLICT,
                Json(RestoreBody {
                    success: false,
                    error: Some("no DNS snapshot found; takeover may not have been run".to_owned()),
                }),
            )
                .into_response();
        }
        Err(e) => {
            warn!(error = %e, "failed to load DNS snapshot for restore");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(RestoreBody {
                    success: false,
                    error: Some(format!("failed to read snapshot: {e}")),
                }),
            )
                .into_response();
        }
    };

    let result = tokio::task::spawn_blocking(move || {
        takeover::restore_from_snapshot(&*platform, &snap, &state_dir)
    })
    .await;

    match result {
        Ok(Ok(())) => {
            info!("DNS restore succeeded");
            Json(RestoreBody {
                success: true,
                error: None,
            })
            .into_response()
        }
        Ok(Err(e)) => {
            warn!(error = %e, "DNS restore failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(RestoreBody {
                    success: false,
                    error: Some(e.to_string()),
                }),
            )
                .into_response()
        }
        Err(join_err) => {
            warn!(error = %join_err, "DNS restore task panicked");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(RestoreBody {
                    success: false,
                    error: Some("internal error: restore task failed".to_owned()),
                }),
            )
                .into_response()
        }
    }
}

/// `GET /v0/stats/history?hours=24&bucket=3600` — time-bucketed totals from SQLite.
///
/// Returns 200 with an empty bucket list (and `log_mode` field) when query log
/// is off.  `hours` defaults to 24; `bucket` defaults to 3600.
async fn handle_stats_history(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Query(params): Query<HistoryParams>,
) -> Response {
    if let Err(r) = require_auth(&state, &headers) {
        return *r;
    }

    let log_mode = query_log_mode_to_str(state.privacy_cfg.query_log).to_owned();

    if state.privacy_cfg.query_log == QueryLogMode::Off {
        return Json(HistoryBody {
            buckets: Vec::new(),
            log_mode,
        })
        .into_response();
    }

    let hours = params.hours.unwrap_or(24).clamp(1, 8760);
    let bucket = params.bucket.unwrap_or(3600).clamp(60, 86400);
    let db_path = state.state_dir.join("querylog.sqlite");

    let buckets = match crate::rollup::query_history(&db_path, hours, bucket) {
        Ok(rows) => rows
            .into_iter()
            .map(|b| HistoryBucket {
                ts: b.ts,
                total: b.total,
                blocked: b.blocked,
            })
            .collect(),
        Err(e) => {
            warn!(error = %e, "stats/history: DB query failed");
            Vec::new()
        }
    };

    Json(HistoryBody { buckets, log_mode }).into_response()
}

/// `GET /v0/stats/top?n=20&hours=168` — top blocked + allowed domains.
///
/// When `log_mode` is `"anonymous"` or `"off"`, returns empty lists with the
/// `log_mode` field set correctly.
async fn handle_stats_top(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Query(params): Query<TopParams>,
) -> Response {
    if let Err(r) = require_auth(&state, &headers) {
        return *r;
    }

    let log_mode = query_log_mode_to_str(state.privacy_cfg.query_log).to_owned();
    let n = params.n.unwrap_or(20).clamp(1, 100);
    let hours = params.hours.unwrap_or(168).clamp(1, 8760);
    let db_path = state.state_dir.join("querylog.sqlite");

    let (blocked, allowed) =
        match crate::rollup::query_top(&db_path, n, hours, state.privacy_cfg.query_log) {
            Ok(pair) => pair,
            Err(e) => {
                warn!(error = %e, "stats/top: DB query failed");
                (Vec::new(), Vec::new())
            }
        };

    let to_entries = |v: Vec<crate::rollup::TopEntry>| -> Vec<TopEntry> {
        v.into_iter()
            .map(|e| TopEntry {
                qname: e.qname,
                count: e.count,
            })
            .collect()
    };

    Json(TopBody {
        blocked: to_entries(blocked),
        allowed: to_entries(allowed),
        log_mode,
    })
    .into_response()
}

/// `GET /v0/clients?hours=24` — per-client query totals (WP13).
///
/// Returns an empty `clients` list with `log_clients_enabled = false` and an
/// explanatory field when `network_guard.log_clients` is off.  When on,
/// returns per-device totals from the SQLite rollup DB.
async fn handle_clients(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Query(params): Query<ClientsParams>,
) -> Response {
    if let Err(r) = require_auth(&state, &headers) {
        return *r;
    }

    // When query_log=off, no data is written to the DB — return an explanatory
    // response consistent with /v0/stats/* behaviour.
    if state.privacy_cfg.query_log == QueryLogMode::Off {
        return Json(ClientsBody {
            log_clients_enabled: false,
            explanation: Some("privacy.query_log is off; no client data is recorded".to_owned()),
            clients: Vec::new(),
        })
        .into_response();
    }

    if !state.network_guard_cfg.log_clients {
        return Json(ClientsBody {
            log_clients_enabled: false,
            explanation: Some(
                "network_guard.log_clients is off; set it to true to enable per-client stats"
                    .to_owned(),
            ),
            clients: Vec::new(),
        })
        .into_response();
    }

    let hours = params.hours.unwrap_or(24).clamp(1, 8760);
    let db_path = state.state_dir.join("querylog.sqlite");

    let entries = match crate::rollup::query_clients(&db_path, hours) {
        Ok(rows) => rows
            .into_iter()
            .map(|e| {
                // Attempt mDNS hostname lookup for the client IP (WP14 §3).
                let name = e
                    .client
                    .parse::<IpAddr>()
                    .ok()
                    .and_then(|ip| state.mdns_map.get(ip));
                ClientEntry {
                    client: e.client,
                    name,
                    total: e.total,
                    blocked: e.blocked,
                }
            })
            .collect(),
        Err(e) => {
            warn!(error = %e, "clients: DB query failed");
            Vec::new()
        }
    };

    Json(ClientsBody {
        log_clients_enabled: true,
        explanation: None,
        clients: entries,
    })
    .into_response()
}

// ── WP14 §2: config reload + profile handlers ─────────────────────────────────

/// `POST /v0/config/reload {profile?: string}` — hot-reload the config subset.
///
/// Loads the named profile (or re-reads the current active profile when absent),
/// applies the hot-reloadable fields (lists, upstream, privacy), and reports
/// what requires restart.
async fn handle_config_reload(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    body: Result<Json<ConfigReloadReq>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if let Err(r) = require_auth(&state, &headers) {
        return *r;
    }

    let req = match body {
        Ok(Json(r)) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiErrorBody::with_detail("invalid_body", e.to_string())),
            )
                .into_response();
        }
    };

    // Determine which profile to reload.
    let profile_name = {
        let req_profile = req.profile.clone();
        let active = state
            .active_profile
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        req_profile.or(active)
    };

    let Some(ref name) = profile_name else {
        // No profile active and none requested — nothing to reload.
        return Json(ConfigReloadBody {
            applied: Vec::new(),
            requires_restart: Vec::new(),
        })
        .into_response();
    };

    // Validate profile name at the API boundary (400 before any FS access).
    if let Err(e) = crate::profiles::validate_profile_name(name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiErrorBody::with_detail(
                "invalid_profile_name",
                e.to_string(),
            )),
        )
            .into_response();
    }

    // Load the profile.
    let new_cfg = match crate::profiles::load_profile(&state.state_dir, name) {
        Ok(c) => c,
        Err(crate::profiles::ProfileError::NotFound(_)) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ApiErrorBody::with_detail(
                    "profile_not_found",
                    format!("profile '{name}' not found"),
                )),
            )
                .into_response();
        }
        Err(crate::profiles::ProfileError::InvalidName(_)) => {
            // This should have been caught above; guard here for defence-in-depth.
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiErrorBody::with_detail(
                    "invalid_profile_name",
                    format!("profile name '{name}' is invalid"),
                )),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(ApiErrorBody::with_detail("profile_invalid", e.to_string())),
            )
                .into_response();
        }
    };

    // Classify changes relative to the current running config.
    let old_cfg = state
        .current_config
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let reload_result = crate::profiles::classify_reload(&old_cfg, &new_cfg);

    // Apply hot-reloadable sections.
    let applied = reload_result.applied.clone();
    let requires_restart = reload_result.requires_restart.clone();

    if applied.contains(&"lists".to_owned()) {
        // Hot-apply: swap the pipeline's config so force_refresh picks up the
        // new preset/categories/sources, then trigger the refresh.
        let lists = Arc::clone(&state.lists);
        let new_lists_cfg = new_cfg.effective_lists_config();
        lists.update_config(new_lists_cfg);
        tokio::spawn(async move {
            if let Err(e) = lists.force_refresh().await {
                warn!(error = %e, "lists reload failed during profile switch");
            }
        });
        info!(profile = %name, "lists config swapped and refresh triggered");
    }

    if applied.contains(&"privacy".to_owned()) {
        // Hot-apply: store the new PrivacyConfig into the shared ArcSwap so all
        // DNS handler workers see it on their next request (lock-free load).
        state.privacy_arc.store(Arc::new(new_cfg.privacy.clone()));
        info!(profile = %name, "privacy config hot-swapped into DNS handlers");
    }

    // Persist active profile name.
    if let Err(e) = crate::profiles::save_active_profile(&state.state_dir, name) {
        warn!(error = %e, profile = %name, "failed to persist active-profile file");
    }

    // Update in-memory state.
    {
        let mut active = state
            .active_profile
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *active = Some(name.clone());
    }
    {
        let mut current = state
            .current_config
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Only update the hot-reloadable parts of the stored config.
        if applied.contains(&"lists".to_owned()) {
            current.lists = new_cfg.lists.clone();
        }
        if applied.contains(&"privacy".to_owned()) {
            current.privacy = new_cfg.privacy.clone();
        }
        // upstream is now in requires_restart — do NOT update current.upstream here.
    }

    info!(
        profile = %name,
        applied = ?applied,
        requires_restart = ?requires_restart,
        "config reload complete"
    );

    Json(ConfigReloadBody {
        applied,
        requires_restart,
    })
    .into_response()
}

/// `GET /v0/profiles` — list available profiles.
async fn handle_profiles_list(State(state): State<Arc<ApiState>>, headers: HeaderMap) -> Response {
    if let Err(r) = require_auth(&state, &headers) {
        return *r;
    }

    let active = state
        .active_profile
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();

    let names = crate::profiles::list_profiles(&state.state_dir);
    let profiles = names
        .iter()
        .map(|name| ProfileEntry {
            name: name.clone(),
            active: active.as_deref() == Some(name.as_str()),
        })
        .collect();

    Json(ProfilesBody { profiles, active }).into_response()
}

/// `GET /v0/profiles/:name` — show a profile's TOML content.
async fn handle_profile_show(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    if let Err(r) = require_auth(&state, &headers) {
        return *r;
    }

    // Validate profile name at the API boundary (400 before any FS access).
    if let Err(e) = crate::profiles::validate_profile_name(&name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiErrorBody::with_detail(
                "invalid_profile_name",
                e.to_string(),
            )),
        )
            .into_response();
    }

    match crate::profiles::read_profile_content(&state.state_dir, &name) {
        Ok(content) => Json(ProfileBody { name, content }).into_response(),
        Err(crate::profiles::ProfileError::NotFound(_)) => (
            StatusCode::NOT_FOUND,
            Json(ApiErrorBody::with_detail(
                "profile_not_found",
                format!("profile '{name}' not found"),
            )),
        )
            .into_response(),
        Err(crate::profiles::ProfileError::InvalidName(_)) => (
            StatusCode::BAD_REQUEST,
            Json(ApiErrorBody::with_detail(
                "invalid_profile_name",
                format!("profile name '{name}' is invalid"),
            )),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorBody::with_detail("internal_error", e.to_string())),
        )
            .into_response(),
    }
}

// ── Dashboard SPA handlers (no auth required) ─────────────────────────────────

/// Serve `index.html` at `/dashboard/`.
///
/// Returns 404 when `dashboard.enabled = false`.
async fn handle_dashboard_index(State(state): State<Arc<ApiState>>) -> Response {
    if !state.dashboard_enabled {
        return (
            StatusCode::NOT_FOUND,
            Json(ApiErrorBody::simple("not_found")),
        )
            .into_response();
    }
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        DASHBOARD_INDEX,
    )
        .into_response()
}

/// Serve `style.css` at `/dashboard/style.css`.
async fn handle_dashboard_css(State(state): State<Arc<ApiState>>) -> Response {
    if !state.dashboard_enabled {
        return (
            StatusCode::NOT_FOUND,
            Json(ApiErrorBody::simple("not_found")),
        )
            .into_response();
    }
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        DASHBOARD_CSS,
    )
        .into_response()
}

/// Serve `app.js` at `/dashboard/app.js`.
async fn handle_dashboard_js(State(state): State<Arc<ApiState>>) -> Response {
    if !state.dashboard_enabled {
        return (
            StatusCode::NOT_FOUND,
            Json(ApiErrorBody::simple("not_found")),
        )
            .into_response();
    }
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        DASHBOARD_JS,
    )
        .into_response()
}

/// Axum fallback — returns the spec 404 shape for any unknown path.
async fn handle_not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ApiErrorBody::simple("not_found")),
    )
        .into_response()
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Map [`GuardState`] to the string used in the API spec.
fn guard_state_to_string(state: &GuardState) -> String {
    match state {
        GuardState::Filtering => "filtering".to_owned(),
        GuardState::Snoozed { .. } => "snoozed".to_owned(),
        GuardState::StandingBy { .. } => "standing_by".to_owned(),
        GuardState::Attention { .. } => "attention".to_owned(),
    }
}

/// Map a core [`Verdict`] to the API string.
fn verdict_to_string(v: hush_core::decision::Verdict) -> String {
    use hush_core::decision::Verdict;
    match v {
        Verdict::Block => "block",
        Verdict::Forward => "forward",
        Verdict::ForwardLocal => "forward_local",
    }
    .to_owned()
}

/// Map a core [`Reason`] to the API string.
///
/// WP4 additions: `BrowserDohCanary`, `PrivateRelayBlocked`,
/// `PrivateRelayProtected`, `CnameCloaked` are new variants.
/// WP8 addition: `RebindBlocked` is a new variant.
fn reason_to_string(r: hush_core::decision::Reason) -> String {
    use hush_core::decision::Reason;
    match r {
        Reason::Snoozed => "snoozed".to_owned(),
        Reason::LocalName => "local_name".to_owned(),
        Reason::UserAllowed => "user_allowed".to_owned(),
        Reason::ListAllowed => "list_allowed".to_owned(),
        Reason::ListBlocked => "list_blocked".to_owned(),
        Reason::NoMatch => "no_match".to_owned(),
        // WP4 new variants.
        Reason::BrowserDohCanary => "browser_doh_canary".to_owned(),
        Reason::PrivateRelayBlocked => "private_relay_blocked".to_owned(),
        Reason::PrivateRelayProtected => "private_relay_protected".to_owned(),
        Reason::CnameCloaked { hop } => format!("cname_cloaked:{hop}"),
        // WP8 §4 new variant.
        Reason::RebindBlocked { addr } => format!("rebind_blocked:{addr}"),
    }
}

/// Map a [`QueryLogMode`] to its canonical string representation.
///
/// These strings are the public API contract — they match the config TOML values
/// and the spec §3.4 `log_mode` field.
fn query_log_mode_to_str(mode: QueryLogMode) -> &'static str {
    match mode {
        QueryLogMode::Full => "full",
        QueryLogMode::Anonymous => "anonymous",
        QueryLogMode::Off => "off",
    }
}

/// Atomically write the allowlist to disk (tmp + rename).
///
/// Each domain is written on its own line.
fn persist_allowlist(path: &std::path::Path, domains: &[String]) -> Result<(), std::io::Error> {
    let parent = path.parent().unwrap_or(std::path::Path::new("."));
    let tmp = parent.join(".allowlist.txt.tmp");
    let content = domains.join("\n");
    std::fs::write(&tmp, content)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Current Unix time in milliseconds.
fn unix_ms_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
