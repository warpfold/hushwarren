//! # hush-tray — the ambient UI
//!
//! One icon, four states (`docs/zero-touch-ux.md §8`):
//!
//! | Dot   | Meaning |
//! |-------|---------|
//! | green | Filtering |
//! | amber | Snoozed (auto re-arms) |
//! | grey  | Standing by: VPN / portal / user-DNS / daemon unreachable |
//! | red   | Attention (crash-loop breaker fired) |
//!
//! Menu: Snooze ▸ (5 min / 1 hour) · Resume · Open dashboard ·
//!       Quit hush-tray (protection keeps running).
//!
//! Quitting or crashing the tray never affects filtering — the daemon is the
//! product, the tray is only the ambient indicator.
//!
//! ## `--once` flag
//!
//! When `--once` is passed the binary resolves credentials, polls
//! `GET /v0/status`, prints the dot-state string, and exits 0.  No UI is
//! initialised.  This is the hook for E2E tests (`specs/wp10-tray.md §5`).
//!
//! ## Event-loop choice
//!
//! `tao` owns the main thread (macOS requirement for menu-bar UI).  HTTP
//! polling runs in a background `std::thread` using `reqwest::blocking` (avoids
//! a tokio runtime on the main thread, matches the workspace's existing reqwest
//! config).  State changes are signalled via a `std::sync::Mutex<TrayState>`
//! that the event loop reads on `MainEventsCleared`.

mod client;
mod discovery;
mod icon;
mod state;

use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use clap::Parser;
use tracing::warn;

use crate::{
    client::TrayClient,
    discovery::{load_credentials, resolve_state_dir},
    icon::icon_for_state,
    state::{status_to_tray, unreachable_state, DotState, TrayState},
};

// ── CLI ───────────────────────────────────────────────────────────────────────

/// hush-tray — hushwarren menu-bar indicator.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Poll the daemon once, print the state string, and exit.
    ///
    /// Used by E2E tests (`specs/wp10-tray.md §5`).  Does not initialise the
    /// tray UI or the event loop — safe to run headlessly.
    #[arg(long)]
    once: bool,
}

// ── Poll interval ─────────────────────────────────────────────────────────────

/// How often the background thread polls `/v0/status`.
const POLL_INTERVAL: Duration = Duration::from_secs(5);

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    if cli.once {
        run_once();
    } else {
        #[cfg(target_os = "macos")]
        run_tray();

        #[cfg(not(target_os = "macos"))]
        {
            eprintln!(
                "hush-tray: tray UI is only supported on macOS in this build. \
                 Use --once for headless state queries."
            );
            std::process::exit(1);
        }
    }
}

// ── --once mode (E2E-testable, no UI) ─────────────────────────────────────────

/// Resolve credentials, poll `/v0/status` once, print the dot-state, exit 0.
///
/// Prints one of: `filtering`, `snoozed`, `standing_by`, `attention`.
/// On any error (daemon not running, bad credentials) prints `standing_by` and
/// exits 0 — the tray treats unreachability as grey, not fatal.
fn run_once() {
    let state_dir = resolve_state_dir();
    let tray_state = match load_credentials(&state_dir) {
        Err(e) => {
            warn!(error = %e, "cannot load credentials (daemon not running?)");
            unreachable_state()
        }
        Ok(creds) => match TrayClient::new(creds.base_url, creds.token) {
            Err(e) => {
                warn!(error = %e, "cannot build HTTP client");
                unreachable_state()
            }
            Ok(client) => match client.get_status() {
                Ok(status) => status_to_tray(&status),
                Err(e) => {
                    warn!(error = %e, "GET /v0/status failed");
                    unreachable_state()
                }
            },
        },
    };

    println!("{}", tray_state.dot.as_str());
}

// ── Tray UI (macOS main thread) ───────────────────────────────────────────────

/// Build and run the menu-bar tray.  Never returns normally (event loop owns
/// the thread); exits when the user clicks "Quit hush-tray".
#[cfg(target_os = "macos")]
fn run_tray() {
    use muda::{Menu, MenuItem, PredefinedMenuItem, Submenu};
    use tao::{
        event::{Event, StartCause},
        event_loop::{ControlFlow, EventLoopBuilder},
    };
    use tray_icon::TrayIconBuilder;

    // Shared state between background poll thread and main event loop.
    let shared: Arc<Mutex<TrayState>> = Arc::new(Mutex::new(unreachable_state()));

    // ── Build menu ────────────────────────────────────────────────────────────

    // Disabled counter line (updated on each poll).
    let counter_item = MenuItem::new("0 blocked today", false, None);

    // Snooze submenu.
    let snooze_5m = MenuItem::new("Snooze 5 min", true, None);
    let snooze_1h = MenuItem::new("Snooze 1 hour", true, None);
    let snooze_sub = Submenu::new("Snooze", true);
    // Ignoring append errors: in-process Menu construction cannot fail on valid items.
    let _ = snooze_sub.append(&snooze_5m);
    let _ = snooze_sub.append(&snooze_1h);

    // Resume item.
    let resume_item = MenuItem::new("Resume", true, None);

    // Dashboard item.
    let dashboard_item = MenuItem::new("Open dashboard", true, None);

    // Quit item — per §8 wording: protection keeps running.
    let quit_item = MenuItem::new("Quit hush-tray (protection keeps running)", true, None);

    let menu = Menu::new();
    let _ = menu.append(&counter_item);
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&snooze_sub);
    let _ = menu.append(&resume_item);
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&dashboard_item);
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&quit_item);

    // Capture menu item IDs for event matching.
    let snooze_5m_id = snooze_5m.id().clone();
    let snooze_1h_id = snooze_1h.id().clone();
    let resume_id = resume_item.id().clone();
    let dashboard_id = dashboard_item.id().clone();
    let quit_id = quit_item.id().clone();

    // ── Background poll thread ────────────────────────────────────────────────

    let poll_shared = Arc::clone(&shared);
    std::thread::spawn(move || poll_loop(poll_shared));

    // ── Event loop ────────────────────────────────────────────────────────────

    let event_loop = EventLoopBuilder::new().build();

    // TrayIcon is initialised inside StartCause::Init to avoid a macOS
    // timing issue where the icon doesn't appear if created before the run
    // loop is running.
    let mut tray_icon: Option<tray_icon::TrayIcon> = None;
    let mut last_dot: Option<DotState> = None;

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;

        match event {
            Event::NewEvents(StartCause::Init) => {
                // Build the initial icon and attach the menu.
                let initial_icon = icon_for_state(DotState::StandingBy)
                    .unwrap_or_else(|e| panic!("PANIC-OK: icon creation failed at startup: {e}"));

                match TrayIconBuilder::new()
                    .with_menu(Box::new(menu.clone()))
                    .with_tooltip("hushwarren — starting")
                    .with_icon(initial_icon)
                    .build()
                {
                    Ok(icon) => {
                        tray_icon = Some(icon);
                        last_dot = Some(DotState::StandingBy);
                    }
                    Err(e) => {
                        warn!(error = %e, "failed to create tray icon");
                    }
                }
            }

            Event::MainEventsCleared => {
                // Apply any state update from the poll thread.
                let current = { shared.lock().unwrap_or_else(|p| p.into_inner()).clone() };

                if Some(current.dot) != last_dot {
                    last_dot = Some(current.dot);
                    if let Some(ti) = tray_icon.as_ref() {
                        match icon_for_state(current.dot) {
                            Ok(new_icon) => {
                                let _ = ti.set_icon(Some(new_icon));
                            }
                            Err(e) => {
                                warn!(error = %e, "failed to update tray icon");
                            }
                        }
                        let _ = ti.set_tooltip(Some(current.tooltip.as_str()));
                    }

                    // Update counter menu item.
                    counter_item.set_text(format!("{} blocked today", current.blocked_total));
                }

                // ── Handle menu events ────────────────────────────────────────

                let state_dir = resolve_state_dir();
                while let Ok(menu_event) = muda::MenuEvent::receiver().try_recv() {
                    if menu_event.id == quit_id {
                        *control_flow = ControlFlow::Exit;
                        return;
                    }

                    // For snooze/resume/dashboard we need a client; load credentials lazily.
                    if menu_event.id == snooze_5m_id
                        || menu_event.id == snooze_1h_id
                        || menu_event.id == resume_id
                        || menu_event.id == dashboard_id
                    {
                        match load_credentials(&state_dir) {
                            Err(e) => {
                                warn!(error = %e, "cannot load credentials for menu action");
                            }
                            Ok(creds) => {
                                let base_url = creds.base_url.clone();
                                let token = creds.token.clone();

                                if menu_event.id == snooze_5m_id {
                                    if let Ok(c) = TrayClient::new(base_url, token) {
                                        if let Err(e) = c.snooze(5 * 60) {
                                            warn!(error = %e, "snooze 5m failed");
                                        }
                                    }
                                } else if menu_event.id == snooze_1h_id {
                                    if let Ok(c) = TrayClient::new(base_url, token) {
                                        if let Err(e) = c.snooze(60 * 60) {
                                            warn!(error = %e, "snooze 1h failed");
                                        }
                                    }
                                } else if menu_event.id == resume_id {
                                    if let Ok(c) = TrayClient::new(base_url, token) {
                                        if let Err(e) = c.resume() {
                                            warn!(error = %e, "resume failed");
                                        }
                                    }
                                } else if menu_event.id == dashboard_id {
                                    open_dashboard(&creds.base_url, &creds.token);
                                }
                            }
                        }
                    }
                }
            }

            _ => {}
        }
    });
}

/// Poll `/v0/status` every [`POLL_INTERVAL`] and write the result to `shared`.
///
/// Runs forever in a background thread.  Any error (unreachable daemon, bad
/// credentials) resolves to the grey `unreachable_state()` — never panics.
fn poll_loop(shared: Arc<Mutex<TrayState>>) {
    loop {
        let state_dir = resolve_state_dir();
        let new_state = match load_credentials(&state_dir) {
            Err(e) => {
                warn!(error = %e, "discovery failed in poll loop");
                unreachable_state()
            }
            Ok(creds) => match TrayClient::new(creds.base_url, creds.token) {
                Err(e) => {
                    warn!(error = %e, "client build failed in poll loop");
                    unreachable_state()
                }
                Ok(client) => match client.get_status() {
                    Ok(status) => status_to_tray(&status),
                    Err(e) => {
                        warn!(error = %e, "GET /v0/status failed in poll loop");
                        unreachable_state()
                    }
                },
            },
        };

        {
            let mut guard = shared.lock().unwrap_or_else(|p| p.into_inner());
            *guard = new_state;
        }

        // Sleep in small increments so a future "request shutdown" signal can
        // be added without restructuring this loop.
        let deadline = Instant::now() + POLL_INTERVAL;
        while Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(250));
        }
    }
}

/// Build the dashboard URL from base URL and auth token.
///
/// Format: `{base_url}/dashboard/#token={token}` — must match
/// `crates/cli/src/main.rs` `cmd_dashboard` exactly.
/// The fragment is never sent to the server; the SPA reads it from
/// `location.hash` and moves the token to sessionStorage.
pub(crate) fn dashboard_url(base_url: &str, token: &str) -> String {
    format!("{base_url}/dashboard/#token={token}")
}

/// Open the hushwarren dashboard in the default browser.
///
/// Builds the `http://<addr>/dashboard/#token=<token>` URL exactly as
/// `hush dashboard` does (`crates/cli/src/main.rs` cmd_dashboard), then
/// shells out to `open` (macOS).
fn open_dashboard(base_url: &str, token: &str) {
    let url = dashboard_url(base_url, token);
    #[cfg(target_os = "macos")]
    {
        if let Err(e) = std::process::Command::new("open").arg(&url).status() {
            warn!(error = %e, url, "failed to open dashboard");
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Err(e) = std::process::Command::new("xdg-open").arg(&url).status() {
            warn!(error = %e, url, "failed to open dashboard");
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Err(e) = std::process::Command::new("cmd")
            .args(["/C", "start", &url])
            .status()
        {
            warn!(error = %e, url, "failed to open dashboard");
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        warn!(url, "open_dashboard: unsupported platform");
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    /// The dashboard URL must contain "/dashboard/#token=" — matching
    /// `crates/cli/src/main.rs` `cmd_dashboard` exactly.
    #[test]
    fn dashboard_url_contains_dashboard_path_and_token() {
        let url = dashboard_url("http://127.0.0.1:5380", "abc123");
        assert!(
            url.contains("/dashboard/#token="),
            "URL must contain /dashboard/#token=, got: {url}"
        );
        assert!(
            url.ends_with("abc123"),
            "URL must end with the token, got: {url}"
        );
        assert_eq!(url, "http://127.0.0.1:5380/dashboard/#token=abc123");
    }
}
