//! # hushd — the hushwarren daemon
//!
//! Entry point for the `hushd` binary.  Kept thin (~80 lines per spec).
//!
//! Subcommands:
//! - `run` (default) — bind listeners, serve forever.
//! - `self-test` — resolve canaries through own engine, exit 0/1.
//! - `print-config` — print effective config as TOML to stdout.
//! - `takeover` — execute DNS takeover transaction (requires root, no daemon needed).
//! - `restore` — restore DNS from snapshot (requires root, no daemon needed).
//! - `service install` — register hushd as a Windows SCM service (Windows only).
//! - `service uninstall` — remove the Windows SCM service registration (Windows only).
//!
//! ## Windows SCM integration (`specs/wp11-windows.md` §2)
//!
//! On Windows, `hushd --service` is called by the SCM when the service starts.
//! The service handler maps Stop/Shutdown SCM controls to the existing
//! `CancellationToken` shutdown path, keeping the non-Windows build byte-identical.
//!
//! See `docs/architecture.md` §3 and `specs/wp2-daemon.md` §1.

use clap::{Parser, Subcommand};
use hush_core::config::HushConfig;
use hush_daemon::{
    app::{App, AppConfig},
    platform,
    sentinel::takeover::{self, TakeoverConfig},
    state_dir,
};
use tracing::error;

#[derive(Debug, Parser)]
#[command(name = "hushd", about = "hushwarren DNS sinkhole daemon")]
struct Cli {
    /// Path to the configuration file.
    #[arg(long)]
    config: Option<String>,

    /// Path to the state directory.
    #[arg(long)]
    state_dir: Option<String>,

    /// Run as a Windows SCM service (called by the Service Control Manager;
    /// not for direct user invocation).
    #[cfg(target_os = "windows")]
    #[arg(long, hide = true)]
    service: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start the DNS resolver (default).
    Run,
    /// Resolve canary domains through the running engine; exit 0 on success.
    SelfTest,
    /// Print the effective configuration (TOML) and exit.
    PrintConfig,
    /// Execute the DNS takeover transaction (requires Administrator on Windows).
    ///
    /// Points all active network adapters at 127.0.0.1/::1 after snapshotting
    /// the previous state.  Can be run without a running daemon for emergency
    /// use; normally called via `hush takeover`.
    Takeover,
    /// Restore DNS settings from the pre-takeover snapshot (requires Administrator on Windows).
    ///
    /// Reads `state_dir/dns-snapshot.json` and applies the previous settings.
    /// Can be run without a running daemon as a recovery escape hatch.
    Restore,
    /// Windows SCM service management (Windows only).
    ///
    /// `service install` — register hushd in the Service Control Manager
    /// (LocalSystem account, auto-start, restart-on-failure recovery policy).
    ///
    /// `service uninstall` — remove the SCM registration.
    #[cfg(target_os = "windows")]
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
}

/// Sub-actions for the `service` command (Windows only).
#[cfg(target_os = "windows")]
#[derive(Debug, Subcommand)]
enum ServiceAction {
    /// Register hushd as a Windows SCM service.
    Install,
    /// Remove the Windows SCM service registration.
    Uninstall,
}

fn main() {
    // Install a panic hook that logs at error and exits non-zero.
    // A silent-wedged daemon violates P1 (zero-touch-ux.md §2).
    std::panic::set_hook(Box::new(|info| {
        eprintln!("hushd PANIC: {info}");
        std::process::exit(1);
    }));

    // On Windows, if `--service` is passed the SCM called us — hand off to
    // the service entry point BEFORE full CLI parsing so the SCM control
    // handler is installed as early as possible.
    #[cfg(target_os = "windows")]
    if std::env::args().any(|a| a == "--service") {
        windows_service_main();
        return;
    }

    let cli = Cli::parse();

    // Initialise tracing with HUSH_LOG / default `info`.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("HUSH_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| {
            eprintln!("hushd: failed to build tokio runtime: {e}");
            std::process::exit(1);
        });

    let exit_code = rt.block_on(async move { run(cli).await });
    std::process::exit(exit_code);
}

// ── Windows SCM service integration (specs/wp11-windows.md §2) ───────────────
//
// `define_windows_service!` generates an `extern "system"` function and MUST
// be called at module scope (not inside a fn body).  All SCM entry-point code
// therefore lives here at the top level, gated by `cfg(target_os = "windows")`.
//
// The non-Windows build does not compile any of this, keeping the
// cross-platform binary byte-identical.

#[cfg(target_os = "windows")]
mod win_service {
    //! Windows SCM service entry point and runner.
    //!
    //! Separated from `main()` because `define_windows_service!` generates
    //! `extern "system"` linkage and must appear at module scope.

    use super::{App, AppConfig};
    use tracing::error;
    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };

    pub(super) const SERVICE_NAME: &str = "hushwarren";
    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

    // Bring load_config_inner into scope for the SCM path.
    use super::load_config_inner;

    // Generate the low-level `extern "system"` SCM entry function.
    // This calls `handle_service_main` on a background thread.
    define_windows_service!(ffi_service_main, handle_service_main);

    /// Called by the SCM on a background thread.
    fn handle_service_main(_args: Vec<std::ffi::OsString>) {
        // Use a CancellationToken so the SCM Stop/Shutdown control can
        // integrate cleanly with the existing tokio-util shutdown path.
        let token = tokio_util::sync::CancellationToken::new();
        let token_clone = token.clone();

        let status_handle =
            service_control_handler::register(SERVICE_NAME, move |control| match control {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    token_clone.cancel();
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            });

        let handle = match status_handle {
            Ok(h) => h,
            Err(e) => {
                eprintln!("hushd: SCM register failed: {e}");
                return;
            }
        };

        // Report "Running" to the SCM.
        if let Err(e) = handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::default(),
            process_id: None,
        }) {
            eprintln!("hushd: set service status Running failed: {e}");
            return;
        }

        // Build the tokio runtime and run the daemon until the token fires.
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(r) => r,
            Err(e) => {
                eprintln!("hushd: failed to build tokio runtime: {e}");
                return;
            }
        };

        // Resolve the config the same way the foreground path does so that
        // HUSH_SNAPSHOT_DIR and any on-disk hushwarren.toml are honoured when
        // running as a Windows SCM service (fix for missing apply_env_overrides).
        let config = load_config_inner(None, None);
        let app_cfg = AppConfig {
            config,
            state_dir_override: None,
        };

        rt.block_on(async move {
            match App::start(app_cfg).await {
                Ok(running) => {
                    token.cancelled().await;
                    running.shutdown().await;
                }
                Err(e) => {
                    error!(error = %e, "hushd (service) failed to start");
                }
            }
        });

        // Report "Stopped" before returning so the SCM does not report us as
        // hung.
        let _ = handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::default(),
            process_id: None,
        });
    }

    /// Start the service dispatcher.  Blocks until the service is stopped.
    pub(super) fn run() {
        if let Err(e) = service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
            eprintln!("hushd: service_dispatcher::start failed: {e}");
            std::process::exit(1);
        }
    }
}

/// Entry point used when the SCM calls `hushd --service`.
#[cfg(target_os = "windows")]
fn windows_service_main() {
    win_service::run();
}

async fn run(cli: Cli) -> i32 {
    // Load config.
    let config = load_config(&cli);

    match cli.command.unwrap_or(Command::Run) {
        Command::Run | Command::SelfTest => {
            let app_cfg = AppConfig {
                config,
                state_dir_override: cli.state_dir.clone(),
            };
            match App::start(app_cfg).await {
                Ok(running) => {
                    // Wait for SIGTERM / SIGINT.
                    wait_for_signal().await;
                    running.shutdown().await;
                    0
                }
                Err(e) => {
                    error!(error = %e, "hushd failed to start");
                    1
                }
            }
        }
        Command::PrintConfig => match config.to_toml_string() {
            Ok(toml) => {
                println!("{toml}");
                0
            }
            Err(e) => {
                eprintln!("print-config error: {e}");
                1
            }
        },

        Command::Takeover => {
            let state_dir = state_dir::resolve(cli.state_dir.as_deref());
            let platform_dns = platform::native();
            let cfg = TakeoverConfig {
                state_dir: state_dir.clone(),
                allowed_canary: config.sentinel.canary_domain.clone(),
                ..TakeoverConfig::default()
            };
            match takeover::run_takeover(&*platform_dns, &cfg).await {
                Ok(_snap) => {
                    println!("takeover: DNS is now pointing at the local sinkhole");
                    0
                }
                Err(e) => {
                    eprintln!("takeover failed: {e}");
                    1
                }
            }
        }

        Command::Restore => {
            let state_dir = state_dir::resolve(cli.state_dir.as_deref());
            let platform_dns = platform::native();
            let snap = match hush_daemon::platform::load_snapshot(&state_dir) {
                Ok(Some(s)) => s,
                Ok(None) => {
                    eprintln!("restore: no DNS snapshot found — has takeover been run?");
                    return 1;
                }
                Err(e) => {
                    eprintln!("restore: failed to read snapshot: {e}");
                    return 1;
                }
            };
            match takeover::restore_from_snapshot(&*platform_dns, &snap, &state_dir) {
                Ok(()) => {
                    println!("restore: DNS settings have been restored");
                    0
                }
                Err(e) => {
                    eprintln!("restore failed: {e}");
                    1
                }
            }
        }

        #[cfg(target_os = "windows")]
        Command::Service { action } => windows_service_manage(action),
    }
}

/// Install or uninstall the hushd Windows SCM service.
///
/// `install` — registers the service as LocalService with auto-start and
/// restart-on-failure recovery policy.
/// `uninstall` — removes the SCM registration.
#[cfg(target_os = "windows")]
fn windows_service_manage(action: ServiceAction) -> i32 {
    use std::time::Duration;

    use windows_service::{
        service::{
            ServiceAccess, ServiceAction as ScmAction, ServiceActionType, ServiceErrorControl,
            ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType,
            ServiceType,
        },
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    const SERVICE_DISPLAY_NAME: &str = "hushwarren DNS Sinkhole";
    let service_name = win_service::SERVICE_NAME;

    let manager = match ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CREATE_SERVICE | ServiceManagerAccess::CONNECT,
    ) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("service: failed to open SCM: {e}");
            return 1;
        }
    };

    match action {
        ServiceAction::Install => {
            // Resolve the path of this binary to register as the service executable.
            let exe_path = match std::env::current_exe() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("service install: cannot resolve executable path: {e}");
                    return 1;
                }
            };
            let service_info = ServiceInfo {
                name: service_name.into(),
                display_name: SERVICE_DISPLAY_NAME.into(),
                service_type: ServiceType::OWN_PROCESS,
                start_type: ServiceStartType::AutoStart,
                error_control: ServiceErrorControl::Normal,
                executable_path: exe_path,
                // `--service` tells hushd to hand off to the SCM entry point.
                launch_arguments: vec!["--service".into()],
                dependencies: vec![],
                // LocalSystem (account_name: None ⇒ LocalSystem) is required:
                // the Sentinel must continuously rewrite system DNS in
                // HKLM\SYSTEM\CurrentControlSet\Services\Tcpip{,6}\Parameters\
                // Interfaces\{GUID}\NameServer, whose default ACL grants write
                // only to Administrators and SYSTEM. LocalService cannot write
                // those keys, so autonomous re-arm (drift recovery, the core
                // zero-touch promise) would silently fail under it. This mirrors
                // the macOS daemon (root via LaunchDaemon) and the Linux daemon
                // (root via systemd). Binding :53 also needs the privilege.
                account_name: None,
                account_password: None,
            };
            // CHANGE_CONFIG to write the registration; START is additionally
            // required to attach a *restart* failure action (the SCM must be
            // permitted to start the service on crash) — without it,
            // `update_failure_actions` fails with a winapi error.
            match manager.create_service(
                &service_info,
                ServiceAccess::CHANGE_CONFIG | ServiceAccess::START,
            ) {
                Ok(service) => {
                    // Configure SCM failure-recovery so a crashed daemon is
                    // automatically restarted (spec wp11 §38: "recovery:
                    // restart"). This is the Windows analog of the macOS
                    // LaunchDaemon `KeepAlive` — without it, a `kill -9` leaves
                    // the machine with DNS pointed at a dead resolver until the
                    // Sentinel breaker or a reboot intervenes. Escalating
                    // delays (1s → 2s → 5s) avoid a tight crash-restart spin;
                    // the daemon's own crash-loop breaker (3 kills in 5 min →
                    // restore DNS + disarm) remains the backstop for a genuinely
                    // wedged binary. The reset period (1 day) clears the failure
                    // count after a long healthy run.
                    let recovery = ServiceFailureActions {
                        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
                        reboot_msg: None,
                        command: None,
                        actions: Some(vec![
                            ScmAction {
                                action_type: ServiceActionType::Restart,
                                delay: Duration::from_secs(1),
                            },
                            ScmAction {
                                action_type: ServiceActionType::Restart,
                                delay: Duration::from_secs(2),
                            },
                            ScmAction {
                                action_type: ServiceActionType::Restart,
                                delay: Duration::from_secs(5),
                            },
                        ]),
                    };
                    if let Err(e) = service.update_failure_actions(recovery) {
                        // Non-fatal: the service is registered and will run; it
                        // just won't auto-restart on crash. Surface it loudly so
                        // the gap is visible rather than silent.
                        eprintln!("service install: WARNING — could not set recovery actions: {e}");
                    }
                    println!("service install: hushwarren service registered");
                    0
                }
                Err(e) => {
                    eprintln!("service install failed: {e}");
                    1
                }
            }
        }
        ServiceAction::Uninstall => {
            let service = match manager.open_service(service_name, ServiceAccess::DELETE) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("service uninstall: cannot open service: {e}");
                    return 1;
                }
            };
            match service.delete() {
                Ok(()) => {
                    println!("service uninstall: hushwarren service removed");
                    0
                }
                Err(e) => {
                    eprintln!("service uninstall failed: {e}");
                    1
                }
            }
        }
    }
}

fn load_config(cli: &Cli) -> HushConfig {
    load_config_inner(cli.config.as_deref(), cli.state_dir.as_deref())
}

/// Resolve and load the effective [`HushConfig`].
///
/// Precedence: explicit `config_path` > `<state_dir>/hushwarren.toml` > built-in default.
/// Environment overrides (e.g. `HUSH_SNAPSHOT_DIR`) are always applied last.
///
/// Extracted from [`load_config`] so the Windows SCM path (`handle_service_main`)
/// can call the same resolution logic without a parsed [`Cli`] struct.
/// Non-Windows builds are byte-identical — this function compiles on all targets.
fn load_config_inner(config_path: Option<&str>, state_dir_override: Option<&str>) -> HushConfig {
    if let Some(path) = config_path {
        match std::fs::read_to_string(path) {
            Ok(s) => match HushConfig::from_toml_str(&s) {
                Ok(cfg) => return apply_env_overrides(cfg),
                Err(e) => {
                    eprintln!("hushd: config parse error in {path}: {e}");
                    std::process::exit(1);
                }
            },
            Err(e) => {
                eprintln!("hushd: cannot read config {path}: {e}");
                std::process::exit(1);
            }
        }
    }

    // Try <state-dir>/hushwarren.toml.
    let state_dir = state_dir::resolve(state_dir_override);
    let candidate = state_dir.join("hushwarren.toml");
    if candidate.exists() {
        if let Ok(s) = std::fs::read_to_string(&candidate) {
            if let Ok(cfg) = HushConfig::from_toml_str(&s) {
                return apply_env_overrides(cfg);
            }
        }
    }

    // Fall through to the built-in default.
    apply_env_overrides(HushConfig::default())
}

/// Apply environment overrides that installers set via service env vars.
///
/// `HUSH_SNAPSHOT_DIR` (set by the macOS LaunchDaemon plist, WP12 §1) supplies
/// the packaged first-run snapshot location when the config file does not set
/// `lists.snapshot_dir` explicitly — an explicit config value always wins.
fn apply_env_overrides(mut cfg: HushConfig) -> HushConfig {
    if cfg.lists.snapshot_dir.is_none() {
        if let Ok(dir) = std::env::var("HUSH_SNAPSHOT_DIR") {
            if !dir.trim().is_empty() {
                cfg.lists.snapshot_dir = Some(dir);
            }
        }
    }
    cfg
}

/// Wait for SIGTERM or SIGINT (ctrl_c on all platforms).
async fn wait_for_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate())
            .unwrap_or_else(|_| panic!("PANIC-OK: SIGTERM handler setup is infallible on unix"));
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
