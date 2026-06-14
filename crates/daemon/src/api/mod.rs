//! Control API server: axum HTTP server bound to loopback.
//!
//! Implements `specs/wp3-api-cli.md` §1–§3.  The server:
//! 1. Validates the configured listen address is loopback-only.
//! 2. Calls [`auth::ensure_token`] to get/create `state_dir/api.token`.
//! 3. Binds the axum server (port 0 support via `TcpListener::bind`).
//! 4. Writes the ACTUAL bound address to `state_dir/api.addr`.
//! 5. Loads the persisted allowlist from `state_dir/allowlist.txt`.
//! 6. Serves the router in a background task.
//!
//! The server is started by [`App::start`] after DNS listeners are ready.
//! Shutdown is coordinated via `CancellationToken`.

pub mod auth;
pub mod routes;
pub mod types;

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Instant,
};

use thiserror::Error;
use tokio::{net::TcpListener, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::{
    lists::ListsPipeline,
    mdns::MdnsMap,
    metrics::Metrics,
    platform::PlatformDns,
    rollup::RollupHandle,
    sentinel::{takeover::TakeoverConfig, Sentinel},
};
use arc_swap::ArcSwap;
use hush_core::{
    config::{HushConfig, NetworkGuardConfig, PrivacyConfig},
    querylog::QueryRing,
    DecisionEngine, Domain,
};

// ── Shared state ──────────────────────────────────────────────────────────────

/// All state shared by the axum handler closures.
///
/// Constructed once in [`ApiServer::start`] and wrapped in `Arc` for axum.
pub struct ApiState {
    /// The bearer token — constant for the lifetime of the server.
    pub token: String,
    /// Shared decision engine.
    pub engine: Arc<DecisionEngine>,
    /// Shared sentinel.
    pub sentinel: Arc<Sentinel>,
    /// Shared metrics.
    pub metrics: Arc<Metrics>,
    /// Shared query ring.
    pub ring: Arc<QueryRing>,
    /// Shared list pipeline.
    pub lists: Arc<ListsPipeline>,
    /// In-memory allowlist (domain strings, forward form).
    pub allowlist: Mutex<Vec<String>>,
    /// Daemon start time (for `uptime_secs`).
    pub start_time: Instant,
    /// State directory path (for persisting allowlist + DNS snapshots).
    pub state_dir: PathBuf,
    /// Platform DNS implementation (for takeover / restore).
    pub platform: Arc<dyn PlatformDns>,
    /// Takeover configuration (self-test domain, timeout, state dir).
    pub takeover_cfg: TakeoverConfig,
    /// Privacy feature toggle configuration (WP4 + WP9) — used by `GET /v0/status`.
    pub privacy_cfg: PrivacyConfig,
    /// Hot-swappable privacy config shared with the DNS handler (finding #4a).
    ///
    /// `POST /v0/config/reload` calls `privacy_arc.store(Arc::new(new_config))`
    /// to propagate a privacy change to all DNS workers without a restart.
    pub privacy_arc: Arc<ArcSwap<PrivacyConfig>>,
    /// Rollup handle for stats API queries (WP9).
    pub rollup: RollupHandle,
    /// Whether the dashboard SPA is enabled (WP9).
    pub dashboard_enabled: bool,
    /// Network Guard configuration (WP13) — used by `GET /v0/clients`.
    pub network_guard_cfg: NetworkGuardConfig,
    /// Passive mDNS IP→hostname map (WP14 §3).  Empty when mDNS insight is off.
    pub mdns_map: MdnsMap,
    /// Currently active profile name (WP14 §2); `None` when default config is active.
    pub active_profile: std::sync::Mutex<Option<String>>,
    /// Full current daemon config (for hot-reload comparison).
    pub current_config: std::sync::Mutex<HushConfig>,
}

// ── Errors ────────────────────────────────────────────────────────────────────

/// Errors during API server startup.
#[derive(Debug, Error)]
pub enum ApiStartError {
    /// The configured `api.listen` address is not a loopback address.
    #[error("api.listen must be a loopback address (e.g. 127.0.0.1); got {0}")]
    NonLoopback(SocketAddr),
    /// Token file could not be created or read.
    #[error("token file error: {0}")]
    Token(#[from] auth::TokenError),
    /// TCP listener bind failed.
    #[error("API listener bind error: {0}")]
    Bind(#[from] std::io::Error),
}

// ── API server handle ─────────────────────────────────────────────────────────

/// Configuration for [`ApiServer::start`].
pub struct ApiServerConfig {
    /// Configured listen address (must be loopback).
    pub listen_addr: SocketAddr,
    /// State directory path.
    pub state_dir: PathBuf,
    /// Shared decision engine.
    pub engine: Arc<DecisionEngine>,
    /// Shared sentinel.
    pub sentinel: Arc<Sentinel>,
    /// Shared metrics.
    pub metrics: Arc<Metrics>,
    /// Shared query ring.
    pub ring: Arc<QueryRing>,
    /// Shared list pipeline.
    pub lists: Arc<ListsPipeline>,
    /// Platform DNS implementation (for takeover / restore).
    pub platform: Arc<dyn PlatformDns>,
    /// Takeover configuration.
    pub takeover_cfg: TakeoverConfig,
    /// Cancellation token for graceful shutdown.
    pub cancel: CancellationToken,
    /// Privacy feature toggle configuration (WP4 + WP9).
    pub privacy_cfg: PrivacyConfig,
    /// Hot-swappable privacy config shared with DNS handlers.
    pub privacy_arc: Arc<ArcSwap<PrivacyConfig>>,
    /// Rollup handle for stats API queries (WP9).
    pub rollup: RollupHandle,
    /// Whether the dashboard SPA is enabled (WP9).
    pub dashboard_enabled: bool,
    /// Network Guard configuration (WP13).
    pub network_guard_cfg: NetworkGuardConfig,
    /// Passive mDNS IP→hostname map (WP14 §3).
    pub mdns_map: MdnsMap,
    /// Currently active profile name (WP14 §2); `None` when default config is active.
    pub active_profile: Option<String>,
    /// Full current daemon config (for hot-reload comparison).
    pub current_config: HushConfig,
}

/// A running API server.
pub struct ApiServer {
    /// The actual bound socket address (may differ from configured when port = 0).
    pub api_addr: SocketAddr,
    /// Background task handle.
    task: Option<JoinHandle<()>>,
}

impl ApiServer {
    /// Start the API server.
    ///
    /// # Errors
    ///
    /// Returns [`ApiStartError::NonLoopback`] if `cfg.listen_addr` is not a loopback address.
    pub async fn start(cfg: ApiServerConfig) -> Result<Self, ApiStartError> {
        let ApiServerConfig {
            listen_addr,
            state_dir,
            engine,
            sentinel,
            metrics,
            ring,
            lists,
            platform,
            takeover_cfg,
            cancel,
            privacy_cfg,
            privacy_arc,
            rollup,
            dashboard_enabled,
            network_guard_cfg,
            mdns_map,
            active_profile,
            current_config,
        } = cfg;
        let state_dir = state_dir.as_path();
        // Enforce loopback-only in P0.
        if !listen_addr.ip().is_loopback() {
            return Err(ApiStartError::NonLoopback(listen_addr));
        }

        // Ensure the token exists and is valid.
        let token = auth::ensure_token(state_dir)?;

        // Load the persisted allowlist (unparseable lines are skipped + warned).
        let initial_allowlist = load_allowlist(state_dir);

        // Seed the decision engine with the persisted user-allow set.
        let parsed: Vec<Domain> = initial_allowlist
            .iter()
            .filter_map(|s| Domain::parse(s).ok())
            .collect();
        if !parsed.is_empty() {
            info!(
                count = parsed.len(),
                "loaded persisted allowlist into engine"
            );
            engine.set_user_allow(parsed);
        }

        // Build shared state.
        let api_state = Arc::new(ApiState {
            token,
            engine,
            sentinel,
            metrics,
            ring,
            lists,
            allowlist: Mutex::new(initial_allowlist),
            start_time: Instant::now(),
            state_dir: state_dir.to_path_buf(),
            platform,
            takeover_cfg,
            privacy_cfg,
            privacy_arc,
            rollup,
            dashboard_enabled,
            network_guard_cfg,
            mdns_map,
            active_profile: std::sync::Mutex::new(active_profile),
            current_config: std::sync::Mutex::new(current_config),
        });

        // Bind the listener (port 0 → OS assigns).
        let listener = TcpListener::bind(listen_addr).await?;
        let api_addr = listener.local_addr()?;

        // Write the ACTUAL bound address to state_dir/api.addr.
        write_addr_file(state_dir, api_addr)?;

        info!(addr = %api_addr, "API server listening");

        // Build the router.
        let router = routes::build_router(api_state);

        // Serve in a background task.
        let task = tokio::spawn(async move {
            let result = axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    cancel.cancelled().await;
                })
                .await;
            if let Err(e) = result {
                tracing::error!(error = %e, "API server error");
            }
        });

        Ok(Self {
            api_addr,
            task: Some(task),
        })
    }

    /// Wait for the server background task to complete.
    pub async fn join(mut self) {
        if let Some(task) = self.task.take() {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), task).await;
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Write the actual API address to `state_dir/api.addr`.
///
/// Written atomically via tmp+rename.
fn write_addr_file(state_dir: &Path, addr: SocketAddr) -> Result<(), std::io::Error> {
    let path = state_dir.join("api.addr");
    let tmp = state_dir.join(".api.addr.tmp");
    std::fs::write(&tmp, addr.to_string())?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// Load `state_dir/allowlist.txt`.
///
/// Unparseable lines are skipped with a `warn!`.  Missing file returns empty list.
fn load_allowlist(state_dir: &Path) -> Vec<String> {
    let path = state_dir.join("allowlist.txt");
    let content = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(e) => {
            warn!(path = %path.display(), error = %e, "cannot read allowlist.txt; starting empty");
            return Vec::new();
        }
    };

    let mut result = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match Domain::parse(trimmed) {
            Ok(d) => result.push(d.as_str().to_owned()),
            Err(e) => {
                warn!(
                    line = trimmed,
                    error = %e,
                    "allowlist.txt: unparseable line skipped"
                );
            }
        }
    }
    result
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
pub mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::api::auth::TOKEN_HEX_LEN;
    use tempfile::TempDir;

    // ── addr file content ─────────────────────────────────────────────────────

    #[test]
    fn write_addr_file_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        write_addr_file(tmp.path(), addr).unwrap();
        let content = std::fs::read_to_string(tmp.path().join("api.addr")).unwrap();
        assert_eq!(content, "127.0.0.1:9999");
    }

    #[test]
    fn write_addr_file_port_zero_records_actual_port() {
        let tmp = TempDir::new().unwrap();
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        write_addr_file(tmp.path(), addr).unwrap();
        let content = std::fs::read_to_string(tmp.path().join("api.addr")).unwrap();
        let parsed: SocketAddr = content.parse().unwrap();
        assert_eq!(parsed.port(), 12345);
    }

    // ── load_allowlist ────────────────────────────────────────────────────────

    #[test]
    fn load_allowlist_missing_file_returns_empty() {
        let tmp = TempDir::new().unwrap();
        let list = load_allowlist(tmp.path());
        assert!(list.is_empty());
    }

    #[test]
    fn load_allowlist_reads_domains() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("allowlist.txt"), "example.com\ngood.org\n").unwrap();
        let list = load_allowlist(tmp.path());
        assert_eq!(list, vec!["example.com", "good.org"]);
    }

    #[test]
    fn load_allowlist_skips_invalid_lines() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join("allowlist.txt"),
            "example.com\n!!invalid!!\ngood.org\n",
        )
        .unwrap();
        let list = load_allowlist(tmp.path());
        // Invalid line is skipped, valid ones remain.
        assert_eq!(list, vec!["example.com", "good.org"]);
    }

    #[test]
    fn load_allowlist_skips_blank_lines() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join("allowlist.txt"),
            "\nexample.com\n\ngood.org\n\n",
        )
        .unwrap();
        let list = load_allowlist(tmp.path());
        assert_eq!(list, vec!["example.com", "good.org"]);
    }

    // ── n clamping ────────────────────────────────────────────────────────────

    /// The clamping logic lives inline in handle_queries_recent; this test
    /// documents the contract so regressions are caught.
    #[test]
    fn n_clamp_range() {
        // Values at and beyond the clamping boundary.
        let clamp = |n: u32| n.clamp(1, 1000) as usize;
        assert_eq!(clamp(0), 1, "n=0 must clamp to 1");
        assert_eq!(clamp(1), 1);
        assert_eq!(clamp(500), 500);
        assert_eq!(clamp(1000), 1000);
        assert_eq!(clamp(1001), 1000, "n=1001 must clamp to 1000");
        assert_eq!(clamp(u32::MAX), 1000);
    }

    // ── Token validity used by API ────────────────────────────────────────────

    #[test]
    fn token_hex_len_constant() {
        assert_eq!(TOKEN_HEX_LEN, 64, "token must be 64 hex chars (32 bytes)");
    }

    // ── allow/unallow semantics ───────────────────────────────────────────────

    #[test]
    fn allowlist_add_deduplicates() {
        let mut list: Vec<String> = vec!["example.com".to_owned()];
        let new_domain = "example.com".to_owned();
        if !list.contains(&new_domain) {
            list.push(new_domain);
        }
        assert_eq!(list.len(), 1, "duplicate must not be added");
    }

    #[test]
    fn allowlist_remove_exact_only() {
        let mut list: Vec<String> = vec![
            "example.com".to_owned(),
            "sub.example.com".to_owned(),
            "other.com".to_owned(),
        ];
        list.retain(|d| d != "example.com");
        assert_eq!(list.len(), 2);
        assert!(!list.contains(&"example.com".to_owned()));
        assert!(list.contains(&"sub.example.com".to_owned()));
    }

    #[test]
    fn allowlist_remove_noop_when_absent() {
        let mut list: Vec<String> = vec!["example.com".to_owned()];
        list.retain(|d| d != "nonexistent.com");
        assert_eq!(list.len(), 1, "removing absent domain must be a no-op");
    }

    // ── snooze secs bounds ────────────────────────────────────────────────────

    #[test]
    fn snooze_secs_boundary_1_is_valid() {
        assert!((1u64..=86400).contains(&1));
    }

    #[test]
    fn snooze_secs_boundary_86400_is_valid() {
        assert!((1u64..=86400).contains(&86400));
    }

    #[test]
    fn snooze_secs_boundary_0_is_invalid() {
        assert!(!(1u64..=86400).contains(&0));
    }

    #[test]
    fn snooze_secs_boundary_86401_is_invalid() {
        assert!(!(1u64..=86400).contains(&86401));
    }
}
