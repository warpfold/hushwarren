//! App lifecycle: `App::start` → `RunningApp` → `RunningApp::shutdown`.
//!
//! Implements `specs/wp2-daemon.md` §1 + `specs/wp3-api-cli.md` §1–§3.
//! `App::start` is the canonical entry point used by both `main.rs` and
//! integration tests.  It:
//! 1. Resolves and initialises the state directory.
//! 2. Builds all shared state (engine, ring, metrics, ladder, sentinel).
//! 3. Starts the list pipeline (loads rules or starts empty).
//! 4. Binds DNS listeners via `dns::bind_listeners`.
//! 5. Prints exactly one `LISTENING udp=<addr>` line (e2e contract).
//! 6. Starts the control API server (token, addr file, axum task).
//! 7. Drives the server in a background task.
//! 8. Returns `RunningApp` with actual bound addresses + shutdown handle.
//!
//! `RunningApp::shutdown` cancels all tasks and waits up to 5 s.

use crate::{
    api::{ApiServer, ApiStartError},
    dns::{bind_listeners, HandlerState, SinkholeHandler},
    inbound_tls,
    lists::ListsPipeline,
    mdns::MdnsMap,
    metrics::Metrics,
    platform::{self, load_snapshot},
    profiles, rollup,
    sentinel::{
        breaker::{self, BreakerConfig, BreakerOutcome},
        takeover::{self, TakeoverConfig},
        watch::{run_tick, WatcherState},
        Sentinel,
    },
    state_dir,
};
use arc_swap::ArcSwap;
use hush_core::{
    config::{HushConfig, PrivacyConfig, UpstreamConfig},
    querylog::QueryRing,
    DecisionEngine,
};
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use thiserror::Error;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

/// Errors during daemon startup.
#[derive(Debug, Error)]
pub enum StartError {
    /// Could not create the state directory.
    #[error("state directory error: {0}")]
    StateDir(#[from] state_dir::StateDirError),
    /// DNS listener bind failed.
    #[error("DNS bind error: {0}")]
    Bind(#[from] std::io::Error),
    /// Configuration is invalid.
    #[error("invalid configuration: {0}")]
    Config(String),
    /// Upstream ladder construction failed.
    #[error("upstream init error: {0}")]
    Upstream(String),
    /// API server startup failed.
    #[error("API start error: {0}")]
    Api(#[from] ApiStartError),
    /// Inbound TLS listener setup failed.
    #[error("inbound TLS error: {0}")]
    InboundTls(#[from] inbound_tls::InboundTlsError),
}

/// Configuration for `App::start`.
pub struct AppConfig {
    /// Full daemon configuration.
    pub config: HushConfig,
    /// Explicit state-dir override (from CLI `--state-dir`).
    pub state_dir_override: Option<String>,
}

/// A running daemon instance.
// WP3-seam: all public fields/methods are consumed by the control API + integration tests.
#[allow(dead_code)]
pub struct RunningApp {
    /// Actual bound UDP addresses.
    udp_addrs: Vec<SocketAddr>,
    /// Actual bound TCP addresses.
    tcp_addrs: Vec<SocketAddr>,
    /// WP13: Actual bound Network Guard UDP addresses (empty when disabled).
    pub guard_udp_addrs: Vec<SocketAddr>,
    /// WP13: Actual bound Network Guard TCP addresses (empty when disabled).
    pub guard_tcp_addrs: Vec<SocketAddr>,
    /// Shared engine (for test access to `set_user_allow` etc.).
    pub engine: Arc<DecisionEngine>,
    /// Shared sentinel (for test access to `snooze` / `resume`).
    pub sentinel: Arc<Sentinel>,
    /// Shared metrics.
    pub metrics: Arc<Metrics>,
    /// Query ring buffer (for test access in WP4 integration tests).
    pub ring: Arc<QueryRing>,
    /// List pipeline (for test access to `force_refresh` etc.).
    pub lists: Arc<ListsPipeline>,
    /// The actual API server address (bound after DNS listeners are ready).
    pub api_addr: SocketAddr,
    /// Cancellation token for graceful shutdown.
    cancel: CancellationToken,
    /// Handle for the DNS server background task.
    server_task: Option<JoinHandle<()>>,
    /// WP13: Handle for the Network Guard DNS server background task (None when disabled).
    guard_server_task: Option<JoinHandle<()>>,
    /// WP14: Bound DoT listener addresses (empty when inbound TLS is disabled).
    pub dot_addrs: Vec<SocketAddr>,
    /// WP14: Handle for the inbound TLS (DoT/DoQ) server background task (None when disabled).
    inbound_tls_task: Option<JoinHandle<()>>,
    /// WP14: Handle for the mDNS insight listener task (None when disabled or join failed).
    mdns_task: Option<JoinHandle<()>>,
    /// Control API server handle.
    api_server: Option<ApiServer>,
    /// State directory path (for clean-shutdown breadcrumb).
    state_dir: PathBuf,
}

// WP3-seam: address accessors consumed by integration tests and the control API.
#[allow(dead_code)]
impl RunningApp {
    /// The actual UDP socket addresses the daemon bound to.
    pub fn udp_addrs(&self) -> &[SocketAddr] {
        &self.udp_addrs
    }

    /// The actual TCP socket addresses the daemon bound to.
    pub fn tcp_addrs(&self) -> &[SocketAddr] {
        &self.tcp_addrs
    }

    /// The first UDP address (convenience for tests with a single listener).
    pub fn udp_addr(&self) -> Option<SocketAddr> {
        self.udp_addrs.first().copied()
    }

    /// The actual bound API address.
    pub fn api_addr(&self) -> SocketAddr {
        self.api_addr
    }

    /// Graceful shutdown: cancel all tasks, wait up to 5 seconds.
    pub async fn shutdown(mut self) {
        self.cancel.cancel();
        if let Some(task) = self.server_task.take() {
            let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
        }
        if let Some(task) = self.guard_server_task.take() {
            let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
        }
        if let Some(task) = self.inbound_tls_task.take() {
            let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
        }
        if let Some(task) = self.mdns_task.take() {
            let _ = tokio::time::timeout(Duration::from_secs(1), task).await;
        }
        if let Some(api) = self.api_server.take() {
            api.join().await;
        }
        // WP5: Mark this shutdown as clean so the crash-loop breaker does not
        // count the next boot as an abnormal restart.
        if let Err(e) = breaker::mark_clean(&self.state_dir) {
            warn!(error = %e, "could not mark clean shutdown in run-state.json");
        }
    }
}

/// The application builder/starter.
pub struct App;

impl App {
    /// Start the daemon and return a `RunningApp` on success.
    ///
    /// All heavy initialisation happens here; `main.rs` is a thin wrapper.
    pub async fn start(cfg: AppConfig) -> Result<RunningApp, StartError> {
        // Validate config.
        let problems = cfg.config.validate();
        if !problems.is_empty() {
            return Err(StartError::Config(
                problems
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join("; "),
            ));
        }

        // Resolve and initialise state directory.
        let state_dir = state_dir::resolve(cfg.state_dir_override.as_deref());
        state_dir::init(&state_dir)?;

        // WP14 §2: Load active profile at startup (overrides the passed config
        // for the hot-reloadable fields).
        let (effective_config, active_profile_name) =
            profiles::load_active_profile_at_startup(&state_dir, &cfg.config);

        // WP5: Build the platform DNS handle early so the crash-breaker can
        // call restore if needed (before listeners are bound).
        let platform_dns: Arc<dyn crate::platform::PlatformDns> = Arc::from(platform::native());

        // WP5: Crash-loop breaker — mark dirty + check before doing anything
        // else.  The breaker is a no-op when no snapshot exists (first run).
        let sentinel_cfg = &cfg.config.sentinel;
        let breaker_cfg = BreakerConfig {
            threshold: sentinel_cfg.breaker_threshold,
            window_secs: sentinel_cfg.breaker_window_secs,
        };
        // Load snapshot now so the breaker restore_fn can use it.
        // `load_snapshot` returns Ok(Some(snap)) when armed, Ok(None)/Err when not.
        let boot_snapshot = load_snapshot(&state_dir).ok().flatten();
        let snapshot_exists = boot_snapshot.is_some();
        let platform_for_breaker = Arc::clone(&platform_dns);
        let state_dir_for_breaker = state_dir.clone();
        let breaker_outcome = match breaker::check_breaker(
            &state_dir,
            &breaker_cfg,
            crate::sentinel::unix_ms_now(),
            snapshot_exists,
            move || {
                if let Some(snap) = boot_snapshot {
                    takeover::restore_from_snapshot(
                        platform_for_breaker.as_ref(),
                        &snap,
                        &state_dir_for_breaker,
                    )
                    .map_err(|e| e.to_string())
                } else {
                    Ok(())
                }
            },
        ) {
            Ok(outcome) => outcome,
            Err(e) => {
                warn!(error = %e, "breaker check failed; proceeding as Nominal");
                BreakerOutcome::Nominal
            }
        };
        // `check_breaker` writes mark_dirty inside; proceed.

        // Build shared state.
        let engine = Arc::new(DecisionEngine::new());
        // WP4: use the configured query-log mode so Off/Anonymous modes are respected.
        // WP14: effective_config may have been overridden by the active profile.
        let ring = Arc::new(QueryRing::with_mode(
            10_000,
            effective_config.privacy.query_log,
        ));
        let metrics = Arc::new(Metrics::new());

        // Create the shared cancellation token early so the rollup writer and
        // the DNS server task both use the same token.
        let cancel = CancellationToken::new();

        // WP9: start the rollup writer (no-op when query_log=Off).
        let rollup_handle = rollup::start_rollup(
            state_dir.clone(),
            effective_config.privacy.query_log,
            effective_config.privacy.retain_days,
            cancel.clone(),
        );

        // Build upstream ladder (ODoH rung prepended when privacy.odoh=true).
        // WP14: use effective_config (profile may override upstream).
        let upstream_cfg = effective_config.upstream.clone();
        let privacy_cfg = effective_config.privacy.clone();
        let ladder = build_ladder(upstream_cfg, &privacy_cfg)?;
        let ladder = Arc::new(ladder);

        // Build sentinel.
        let (sentinel_impl, _sentinel_rx) = Sentinel::new(Arc::clone(&engine));
        let sentinel = Arc::new(sentinel_impl);

        // WP5: If the crash-loop breaker fired, enter Attention state.
        if let BreakerOutcome::Fired { reason } = &breaker_outcome {
            warn!(reason = %reason, "crash-loop breaker fired; running disarmed in Attention state");
            sentinel.set_attention(reason.clone());
        }

        // Build and start the list pipeline.
        // Use `effective_lists_config()` so that privacy.block_doh_bypass=true
        // auto-injects the doh-bypass catalog category (WP4 §2 Tier 2.1).
        // WP14: effective_config (profile override) used for lists preset.
        let lists = Arc::new(ListsPipeline::new(
            effective_config.effective_lists_config(),
            state_dir.clone(),
            Arc::clone(&engine),
        ));
        Arc::clone(&lists).start().await;

        // Build the shared privacy ArcSwap.  All handler instances (loopback,
        // DoT, guard) share this pointer so `POST /v0/config/reload` can hot-swap
        // the privacy config with a single `store()` call that is immediately
        // visible to all DNS workers without a restart.
        let privacy_arc: Arc<ArcSwap<PrivacyConfig>> =
            Arc::new(ArcSwap::from_pointee(effective_config.privacy.clone()));

        // Build the DNS request handler (loopback path: log_clients always false).
        let handler_state = Arc::new(HandlerState {
            engine: Arc::clone(&engine),
            ladder: Arc::clone(&ladder),
            ring: Arc::clone(&ring),
            rollup: rollup_handle.clone(),
            metrics: Arc::clone(&metrics),
            block_action: cfg.config.block.action,
            block_ttl_secs: cfg.config.block.ttl_secs,
            privacy: Arc::clone(&privacy_arc),
            log_clients: false, // loopback path — client is always None
        });
        let handler = SinkholeHandler::new(handler_state);

        // Bind DNS listeners.
        let udp_addrs = cfg.config.listen.udp.clone();
        let tcp_addrs = cfg.config.listen.tcp.clone();
        let (mut server, bound) = bind_listeners(&udp_addrs, &tcp_addrs, handler).await?;

        // Emit the LISTENING line (e2e contract — exactly once).
        for addr in &bound.udp {
            info!(target: "hushd::listening", "LISTENING udp={addr}");
            // Also print to stdout for the e2e binary test to parse.
            println!("LISTENING udp={addr}");
        }

        // Drive server in a background task.
        let cancel2 = cancel.clone();
        let server_task = tokio::spawn(async move {
            tokio::select! {
                result = server.block_until_done() => {
                    if let Err(e) = result {
                        error!(error = %e, "DNS server error");
                    }
                }
                () = cancel2.cancelled() => {
                    if let Err(e) = server.shutdown_gracefully().await {
                        error!(error = %e, "DNS server shutdown error");
                    }
                }
            }
        });

        // Update metrics with current rung.
        metrics
            .upstream_rung_current
            .store(ladder.current_rung(), std::sync::atomic::Ordering::Relaxed);

        // Start the control API server (after DNS listeners are ready — spec §6).
        let api_listen: std::net::SocketAddr = cfg
            .config
            .api
            .listen
            .parse()
            .map_err(|e: std::net::AddrParseError| StartError::Config(e.to_string()))?;

        // WP5: Build TakeoverConfig from the first bound UDP listener.
        let takeover_cfg = TakeoverConfig {
            listener_addr: bound.udp.first().copied().unwrap_or(api_listen),
            allowed_canary: sentinel_cfg.canary_domain.clone(),
            state_dir: state_dir.clone(),
            ..TakeoverConfig::default()
        };

        // WP14 §3: Start passive mDNS insight listener when enabled.
        // Join failure → warn once, feature off, nothing else degrades.
        let (mdns_map, mdns_task) = if cfg.config.network_guard.mdns_insight {
            let (map, task) = crate::mdns::start_mdns_insight(cancel.clone()).await;
            (map, task)
        } else {
            (MdnsMap::new(), None)
        };

        // WP14 §1: Bind inbound DoT/DoQ listeners when enabled.
        // Bind failure IS fatal (explicitly configured, user expects it to work).
        let (dot_addrs, inbound_tls_task) = if cfg.config.inbound_tls.enabled {
            let dot_handler_state = Arc::new(HandlerState {
                engine: Arc::clone(&engine),
                ladder: Arc::clone(&ladder),
                ring: Arc::clone(&ring),
                rollup: rollup_handle.clone(),
                metrics: Arc::clone(&metrics),
                block_action: cfg.config.block.action,
                block_ttl_secs: cfg.config.block.ttl_secs,
                privacy: Arc::clone(&privacy_arc),
                log_clients: false,
            });
            let dot_handler = SinkholeHandler::new(dot_handler_state);
            let (bound_tls, tls_task) = inbound_tls::bind_inbound_tls(
                &cfg.config.inbound_tls,
                dot_handler,
                &state_dir,
                cancel.clone(),
                853,
            )
            .await?;
            info!(
                dot = ?bound_tls.dot_addrs,
                doq = ?bound_tls.doq_addrs,
                "inbound TLS listeners bound"
            );
            (bound_tls.dot_addrs, Some(tls_task))
        } else {
            (Vec::new(), None)
        };

        let api_server = ApiServer::start(crate::api::ApiServerConfig {
            listen_addr: api_listen,
            state_dir: state_dir.clone(),
            engine: Arc::clone(&engine),
            sentinel: Arc::clone(&sentinel),
            metrics: Arc::clone(&metrics),
            ring: Arc::clone(&ring),
            lists: Arc::clone(&lists),
            platform: Arc::clone(&platform_dns),
            takeover_cfg: takeover_cfg.clone(),
            cancel: cancel.clone(),
            privacy_cfg: effective_config.privacy.clone(),
            privacy_arc: Arc::clone(&privacy_arc),
            rollup: rollup_handle.clone(),
            dashboard_enabled: cfg.config.dashboard.enabled,
            network_guard_cfg: cfg.config.network_guard.clone(),
            mdns_map,
            active_profile: active_profile_name,
            current_config: effective_config,
        })
        .await?;

        let api_addr = api_server.api_addr;

        // WP5: Spawn the network watcher task (poll_secs interval).
        // Only active when we have a snapshot (i.e. takeover has been done).
        let watcher_args = WatcherArgs {
            platform: Arc::clone(&platform_dns),
            sentinel: Arc::clone(&sentinel),
            takeover_cfg: takeover_cfg.clone(),
            state_dir: state_dir.clone(),
            poll_secs: sentinel_cfg.poll_secs,
            wake_threshold: Duration::from_secs(sentinel_cfg.wake_gap_secs),
            portal_timebox: Duration::from_secs(sentinel_cfg.portal_timebox_secs),
            cancel: cancel.clone(),
        };
        let _watcher_task = tokio::spawn(run_watcher_loop(watcher_args));

        // WP13: Bind Network Guard listeners when enabled.
        // Bind failures on LAN addresses are non-fatal (warn + retry later) —
        // the laptop use case: interface comes and goes.
        // The guard handler sets log_clients=true when configured.
        let (guard_udp_addrs, guard_tcp_addrs, guard_server_task) =
            if cfg.config.network_guard.enabled {
                // BUG-FIX (finding #3): use `effective_config.privacy` (which
                // incorporates the active profile) rather than `cfg.config.privacy`
                // (the raw base config before profile overlay).  Loopback and DoT
                // handlers already use `effective_config.privacy`; the guard handler
                // must match so all listeners share the same privacy posture.
                let guard_handler_state = Arc::new(HandlerState {
                    engine: Arc::clone(&engine),
                    ladder: Arc::clone(&ladder),
                    ring: Arc::clone(&ring),
                    rollup: rollup_handle.clone(),
                    metrics: Arc::clone(&metrics),
                    block_action: cfg.config.block.action,
                    block_ttl_secs: cfg.config.block.ttl_secs,
                    privacy: Arc::clone(&privacy_arc),
                    log_clients: cfg.config.network_guard.log_clients,
                });
                let guard_handler = SinkholeHandler::new(guard_handler_state);

                match crate::dns::bind_guard_listeners(
                    &cfg.config.network_guard.bind,
                    guard_handler,
                    cancel.clone(),
                )
                .await
                {
                    Ok((guard_udp, guard_tcp, guard_task)) => {
                        info!(
                            udp = ?guard_udp,
                            tcp = ?guard_tcp,
                            "Network Guard listeners bound"
                        );
                        (guard_udp, guard_tcp, Some(guard_task))
                    }
                    Err(e) => {
                        // Non-fatal: warn and continue without guard listeners.
                        warn!(
                            error = %e,
                            "Network Guard: failed to bind listeners; continuing without guard"
                        );
                        (Vec::new(), Vec::new(), None)
                    }
                }
            } else {
                (Vec::new(), Vec::new(), None)
            };

        Ok(RunningApp {
            udp_addrs: bound.udp,
            tcp_addrs: bound.tcp,
            guard_udp_addrs,
            guard_tcp_addrs,
            dot_addrs,
            engine,
            sentinel,
            metrics,
            ring,
            lists,
            api_addr,
            cancel,
            server_task: Some(server_task),
            guard_server_task,
            inbound_tls_task,
            mdns_task,
            api_server: Some(api_server),
            state_dir,
        })
    }
}

// ── Ladder construction ───────────────────────────────────────────────────────

fn build_ladder(
    cfg: UpstreamConfig,
    privacy: &hush_core::config::PrivacyConfig,
) -> Result<crate::upstream::UpstreamLadder, StartError> {
    crate::upstream::UpstreamLadder::from_config(&cfg, privacy)
        .map_err(|e| StartError::Upstream(e.to_string()))
}

// ── WP5 watcher loop ──────────────────────────────────────────────────────────

/// Arguments for the sentinel watcher task (avoids closure lifetime issues).
struct WatcherArgs {
    platform: Arc<dyn crate::platform::PlatformDns>,
    sentinel: Arc<Sentinel>,
    takeover_cfg: TakeoverConfig,
    state_dir: PathBuf,
    poll_secs: u64,
    wake_threshold: Duration,
    portal_timebox: Duration,
    cancel: CancellationToken,
}

/// Network-change watcher loop.
///
/// Runs in a dedicated tokio task.  Ticks every `poll_secs`; skips ticks when
/// no DNS snapshot is present (daemon not yet armed via takeover).
async fn run_watcher_loop(args: WatcherArgs) {
    let WatcherArgs {
        platform,
        sentinel,
        takeover_cfg,
        state_dir,
        poll_secs,
        wake_threshold,
        portal_timebox,
        cancel,
    } = args;

    let mut watcher_state = WatcherState::new();

    loop {
        tokio::select! {
            () = tokio::time::sleep(Duration::from_secs(poll_secs)) => {}
            () = cancel.cancelled() => break,
        }

        // Only run the watcher when a snapshot exists (i.e. daemon is armed).
        let snapshot = match load_snapshot(&state_dir) {
            Ok(Some(s)) => s,
            Ok(None) => continue, // Not yet armed — skip.
            Err(e) => {
                tracing::debug!(error = %e, "watcher: snapshot read error — skipping tick");
                continue;
            }
        };

        let platform_clone = Arc::clone(&platform);
        let cfg_clone = takeover_cfg.clone();

        run_tick(
            Arc::clone(&platform),
            &snapshot,
            &sentinel.state_tx,
            &mut watcher_state,
            wake_threshold,
            portal_timebox,
            &mut || {
                let p = Arc::clone(&platform_clone);
                let c = cfg_clone.clone();
                Box::pin(async move {
                    takeover::run_takeover(p.as_ref(), &c)
                        .await
                        .map(|_| ())
                        .map_err(|e| e.to_string())
                })
            },
        )
        .await;
    }
}

// ── Test helpers ──────────────────────────────────────────────────────────────

/// Build a minimal `AppConfig` suitable for integration tests.
///
/// - Port 0 (OS assigns ephemeral port).
/// - No DoH (avoids real network); Do53 fallback to `upstream_addr`.
/// - Empty state dir in `state_dir`.
/// - Single blocked domain: `"ads.blocked.test"`.
// WP3-seam: consumed by the integration test suite in crates/daemon/tests/.
#[allow(dead_code)]
pub fn test_config(
    upstream_addr: SocketAddr,
    state_dir: PathBuf,
    extra_blocked: &[&str],
) -> AppConfig {
    use hush_core::config::{BlockConfig, ListSource, ListenConfig, ListsConfig, UpstreamConfig};

    // Build a raw list file so the list pipeline can load something.
    let lists_dir = state_dir.join("lists");
    let _ = std::fs::create_dir_all(&lists_dir);
    let mut list_content = String::from("ads.blocked.test\n");
    for d in extra_blocked {
        list_content.push_str(d);
        list_content.push('\n');
    }
    let list_path = lists_dir.join("test_list.txt");
    let _ = std::fs::write(&list_path, list_content);

    // Config with port-0 listeners.
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
                url: "file://test_list".to_string(), // dummy URL
            }],
            refresh_hours: 24,
            jitter_minutes: 0,
            snapshot_dir: None, // WP12: no snapshot in test configs
        },
        block: BlockConfig::default(),
        api: hush_core::config::ApiConfig {
            listen: "127.0.0.1:0".to_string(),
        },
        ..HushConfig::default()
    };

    AppConfig {
        config,
        state_dir_override: Some(state_dir.to_string_lossy().into_owned()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use hush_core::config::HushConfig;

    // ── Config validation gates startup ──────────────────────────────────────

    #[tokio::test]
    async fn bad_config_returns_error() {
        let mut config = HushConfig::default();
        config.listen.udp = vec!["not-a-socket".to_string()];
        let result = App::start(AppConfig {
            config,
            state_dir_override: None,
        })
        .await;
        assert!(
            matches!(result, Err(StartError::Config(_))),
            "bad config must fail at start"
        );
    }
}
