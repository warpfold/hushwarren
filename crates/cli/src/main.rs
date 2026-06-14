//! # hush — control CLI for hushwarren
//!
//! Thin client over hushd's localhost control API (`specs/wp3-api-cli.md` §4).
//! Discovery: `--state-dir` flag > `HUSH_STATE_DIR` env > platform default.
//! Exit codes: 0 ok / 1 API error / 2 cannot connect.
//!
//! ## Verbs
//! - `hush status [--json]`
//! - `hush snooze [5m|30m|2h|off] [--json]`
//! - `hush allow <domain> [--json]`
//! - `hush unallow <domain> [--json]`
//! - `hush allowlist [--json]`
//! - `hush log [-n N] [--blocked] [--json]`
//! - `hush lists [--refresh] [--json]`

use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand};

mod client;
mod discovery;
mod duration;
mod output;
mod types;

use client::{ApiClient, ClientError};
use discovery::{load_credentials, resolve_state_dir};
use duration::{parse_duration, SnoozeDuration};

// ── CLI definition ─────────────────────────────────────────────────────────────

/// hush — hushwarren control CLI
#[derive(Debug, Parser)]
#[command(name = "hush", about = "Control the hushwarren DNS sinkhole daemon")]
struct Cli {
    /// Override the hushwarren state directory (reads api.addr + api.token from here).
    #[arg(long, global = true, value_name = "DIR")]
    state_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Show daemon status (state, rules count, blocked today).
    Status {
        /// Print raw JSON from the API instead of human-readable output.
        #[arg(long)]
        json: bool,
    },

    /// Snooze or resume filtering.
    ///
    /// DURATION: 5m / 30m / 2h / Ns / Nm / Nh, or "off" to resume immediately.
    Snooze {
        /// Duration: 5m, 30m, 2h, 90s, etc., or "off" to resume.
        duration: Option<String>,

        /// Print raw JSON from the API instead of human-readable output.
        #[arg(long)]
        json: bool,
    },

    /// Add a domain to the permanent allowlist.
    Allow {
        /// The domain to allow (e.g. example.com).
        domain: String,

        /// Print raw JSON from the API instead of human-readable output.
        #[arg(long)]
        json: bool,
    },

    /// Remove a domain from the permanent allowlist.
    Unallow {
        /// The domain to remove from the allowlist.
        domain: String,

        /// Print raw JSON from the API instead of human-readable output.
        #[arg(long)]
        json: bool,
    },

    /// Show the current allowlist.
    Allowlist {
        /// Print raw JSON from the API instead of human-readable output.
        #[arg(long)]
        json: bool,
    },

    /// Show recent DNS query log.
    Log {
        /// Number of records to show (default 50, max 1000).
        #[arg(short = 'n', default_value = "50")]
        count: u32,

        /// Show only blocked queries.
        #[arg(long)]
        blocked: bool,

        /// Print raw JSON from the API instead of human-readable output.
        #[arg(long)]
        json: bool,
    },

    /// Show blocklist source status.
    Lists {
        /// Kick off an immediate background refresh.
        #[arg(long)]
        refresh: bool,

        /// Print raw JSON from the API instead of human-readable output.
        #[arg(long)]
        json: bool,
    },

    /// Point system DNS at the local sinkhole (requires root on macOS).
    Takeover {
        /// Print raw JSON from the API instead of human-readable output.
        #[arg(long)]
        json: bool,
    },

    /// Restore system DNS from the pre-takeover snapshot (requires root on macOS).
    Restore {
        /// Print raw JSON from the API instead of human-readable output.
        #[arg(long)]
        json: bool,
    },

    /// Open the hushwarren dashboard in the default browser.
    ///
    /// Constructs the URL `http://<addr>/dashboard/#token=<token>` from the
    /// live daemon credentials and opens it in the system browser.
    /// The `--print-url` flag prints the URL instead of opening it.
    Dashboard {
        /// Print the URL only; do not open the browser.
        #[arg(long)]
        print_url: bool,
    },

    /// Manage config profiles (work/home/strict presets, etc.).
    ///
    /// Profiles are full config files stored in `state_dir/profiles/<name>.toml`.
    /// Switching a profile hot-reloads the list/privacy/upstream settings without
    /// restarting the daemon; listen, API, and inbound_tls changes require restart
    /// (the response tells you which).
    #[command(subcommand)]
    Profile(ProfileCommand),
}

/// Profile sub-commands.
#[derive(Debug, Subcommand)]
pub enum ProfileCommand {
    /// List available profiles.
    List {
        /// Print raw JSON.
        #[arg(long)]
        json: bool,
    },

    /// Show the TOML content of a named profile.
    Show {
        /// Profile name.
        name: String,

        /// Print raw JSON.
        #[arg(long)]
        json: bool,
    },

    /// Switch to a named profile (hot-reloads applicable settings).
    Switch {
        /// Profile name to activate.
        name: String,

        /// Print raw JSON.
        #[arg(long)]
        json: bool,
    },
}

// ── Exit codes ────────────────────────────────────────────────────────────────

/// Exit with 0 (success).
const EXIT_OK: i32 = 0;
/// Exit with 1: API-level error (4xx/5xx, malformed response).
const EXIT_API_ERROR: i32 = 1;
/// Exit with 2: daemon unreachable (connection refused, etc.).
const EXIT_UNREACHABLE: i32 = 2;

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Resolve the state directory using the precedence chain.
    let state_dir = resolve_state_dir(cli.state_dir.as_deref());

    // Load API credentials from the state directory.
    let creds = match load_credentials(&state_dir) {
        Ok(c) => c,
        Err(e) => {
            // Credentials not found → treat as "daemon not running".
            // We don't have an addr yet, so synthesize a helpful message.
            let addr_guess = format!("{}", state_dir.join("api.addr").display());
            eprintln!(
                "hushwarren isn't running (looked at {addr_guess}). Is the service installed?"
            );
            tracing::debug!("credential load error: {e:#}");
            process::exit(EXIT_UNREACHABLE);
        }
    };

    let addr = creds.base_url.trim_start_matches("http://").to_owned();

    // Build the HTTP client.
    let client = match ApiClient::new(creds.base_url.clone(), creds.token.clone()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to build HTTP client: {e}");
            process::exit(EXIT_API_ERROR);
        }
    };

    let exit_code = run_command(cli.command, &client, &addr, &creds.token).await;
    process::exit(exit_code);
}

// ── Command dispatch ──────────────────────────────────────────────────────────

async fn run_command(cmd: Command, client: &ApiClient, addr: &str, token: &str) -> i32 {
    match cmd {
        Command::Status { json } => cmd_status(client, addr, json).await,
        Command::Snooze { duration, json } => cmd_snooze(client, addr, duration, json).await,
        Command::Allow { domain, json } => cmd_allow(client, addr, &domain, json).await,
        Command::Unallow { domain, json } => cmd_unallow(client, addr, &domain, json).await,
        Command::Allowlist { json } => cmd_allowlist(client, addr, json).await,
        Command::Log {
            count,
            blocked,
            json,
        } => cmd_log(client, addr, count, blocked, json).await,
        Command::Lists { refresh, json } => cmd_lists(client, addr, refresh, json).await,
        Command::Takeover { json } => cmd_takeover(client, addr, json).await,
        Command::Restore { json } => cmd_restore(client, addr, json).await,
        Command::Dashboard { print_url } => cmd_dashboard(addr, token, print_url),
        Command::Profile(sub) => cmd_profile(client, addr, sub).await,
    }
}

// ── Individual command handlers ───────────────────────────────────────────────

async fn cmd_status(client: &ApiClient, addr: &str, json: bool) -> i32 {
    match client.status().await {
        Ok(resp) => {
            if json {
                print_json(&resp);
            } else {
                output::print_status(&resp);
            }
            EXIT_OK
        }
        Err(e) => handle_error(e, addr),
    }
}

async fn cmd_snooze(
    client: &ApiClient,
    addr: &str,
    duration_str: Option<String>,
    json: bool,
) -> i32 {
    // Default to "5m" if no duration given (spec lists 5m as first example).
    let raw = duration_str.unwrap_or_else(|| "5m".to_owned());
    let dur = match parse_duration(&raw) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("hush: {e}");
            return EXIT_API_ERROR;
        }
    };

    match dur {
        SnoozeDuration::Off => {
            // Resume filtering.
            match client.resume().await {
                Ok(resp) => {
                    if json {
                        print_json(&resp);
                    } else {
                        output::print_resumed(&resp.state);
                    }
                    EXIT_OK
                }
                Err(e) => handle_error(e, addr),
            }
        }
        SnoozeDuration::Secs(secs) => match client.snooze(secs).await {
            Ok(resp) => {
                if json {
                    print_json(&resp);
                } else {
                    output::print_snoozed(resp.snoozed_until_unix_ms);
                }
                EXIT_OK
            }
            Err(e) => handle_error(e, addr),
        },
    }
}

async fn cmd_allow(client: &ApiClient, addr: &str, domain: &str, json: bool) -> i32 {
    match client.allow(domain).await {
        Ok(resp) => {
            if json {
                print_json(&resp);
            } else {
                output::print_allow_result(&resp, true);
            }
            EXIT_OK
        }
        Err(e) => handle_error(e, addr),
    }
}

async fn cmd_unallow(client: &ApiClient, addr: &str, domain: &str, json: bool) -> i32 {
    match client.unallow(domain).await {
        Ok(resp) => {
            if json {
                print_json(&resp);
            } else {
                output::print_allow_result(&resp, false);
            }
            EXIT_OK
        }
        Err(e) => handle_error(e, addr),
    }
}

async fn cmd_allowlist(client: &ApiClient, addr: &str, json: bool) -> i32 {
    match client.allowlist().await {
        Ok(resp) => {
            if json {
                print_json(&resp);
            } else {
                output::print_allowlist(&resp);
            }
            EXIT_OK
        }
        Err(e) => handle_error(e, addr),
    }
}

async fn cmd_log(client: &ApiClient, addr: &str, count: u32, blocked: bool, json: bool) -> i32 {
    match client.queries_recent(count, blocked).await {
        Ok(resp) => {
            if json {
                print_json(&resp);
            } else {
                output::print_queries(&resp);
            }
            EXIT_OK
        }
        Err(e) => handle_error(e, addr),
    }
}

async fn cmd_lists(client: &ApiClient, addr: &str, refresh: bool, json: bool) -> i32 {
    if refresh {
        match client.lists_refresh().await {
            Ok(resp) => {
                if json {
                    print_json(&resp);
                } else {
                    output::print_lists_refresh_started();
                }
                // After kicking off refresh, fall through to print status.
                if json {
                    return EXIT_OK;
                }
            }
            Err(e) => return handle_error(e, addr),
        }
    }
    match client.lists().await {
        Ok(resp) => {
            if json {
                print_json(&resp);
            } else {
                output::print_lists(&resp);
            }
            EXIT_OK
        }
        Err(e) => handle_error(e, addr),
    }
}

async fn cmd_takeover(client: &ApiClient, addr: &str, json: bool) -> i32 {
    match client.takeover().await {
        Ok(resp) => {
            if json {
                print_json(&resp);
            } else if resp.success {
                println!("takeover: DNS is now pointing at the local sinkhole");
            } else {
                eprintln!(
                    "hush: takeover failed: {}",
                    resp.error.as_deref().unwrap_or("unknown error")
                );
                return EXIT_API_ERROR;
            }
            EXIT_OK
        }
        Err(e) => handle_error(e, addr),
    }
}

async fn cmd_restore(client: &ApiClient, addr: &str, json: bool) -> i32 {
    match client.restore().await {
        Ok(resp) => {
            if json {
                print_json(&resp);
            } else if resp.success {
                println!("restore: DNS settings have been restored to pre-takeover state");
            } else {
                eprintln!(
                    "hush: restore failed: {}",
                    resp.error.as_deref().unwrap_or("unknown error")
                );
                return EXIT_API_ERROR;
            }
            EXIT_OK
        }
        Err(e) => handle_error(e, addr),
    }
}

fn cmd_dashboard(addr: &str, token: &str, print_url: bool) -> i32 {
    // Fragment never reaches server logs — the JS moves it to sessionStorage.
    let url = format!("http://{addr}/dashboard/#token={token}");
    if print_url {
        println!("{url}");
        return EXIT_OK;
    }
    if let Err(e) = open_browser(&url) {
        eprintln!("hush: could not open browser: {e}");
        // Print the URL as fallback.
        println!("{url}");
    }
    EXIT_OK
}

/// Open `url` in the system default browser.
///
/// Uses platform-appropriate shell-out:
/// - macOS: `open <url>`
/// - Linux: `xdg-open <url>`
/// - Windows: `cmd /c start <url>`
///
/// No new dependency — only standard-library `std::process::Command`.
fn open_browser(url: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    let spawn = std::process::Command::new("open")
        .arg(url)
        .spawn()
        .map_err(|e| e.to_string());

    #[cfg(target_os = "linux")]
    let spawn = std::process::Command::new("xdg-open")
        .arg(url)
        .spawn()
        .map_err(|e| e.to_string());

    #[cfg(target_os = "windows")]
    let spawn = std::process::Command::new("cmd")
        .args(["/c", "start", url])
        .spawn()
        .map_err(|e| e.to_string());

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    let spawn: Result<_, String> = Err("browser open not supported on this platform".to_owned());

    spawn.map(|_| ())
}

async fn cmd_profile(client: &ApiClient, addr: &str, sub: ProfileCommand) -> i32 {
    match sub {
        ProfileCommand::List { json } => match client.profiles_list().await {
            Ok(resp) => {
                if json {
                    print_json(&resp);
                } else {
                    if resp.profiles.is_empty() {
                        println!("No profiles found (place .toml files in state_dir/profiles/)");
                    } else {
                        for p in &resp.profiles {
                            let marker = if p.active { " (active)" } else { "" };
                            println!("  {}{}", p.name, marker);
                        }
                    }
                }
                EXIT_OK
            }
            Err(e) => handle_error(e, addr),
        },
        ProfileCommand::Show { name, json } => match client.profile_show(&name).await {
            Ok(resp) => {
                if json {
                    print_json(&resp);
                } else {
                    println!("{}", resp.content);
                }
                EXIT_OK
            }
            Err(e) => handle_error(e, addr),
        },
        ProfileCommand::Switch { name, json } => match client.config_reload(Some(&name)).await {
            Ok(resp) => {
                if json {
                    print_json(&resp);
                } else {
                    if !resp.applied.is_empty() {
                        println!("profile '{}' applied: {}", name, resp.applied.join(", "));
                    }
                    if !resp.requires_restart.is_empty() {
                        println!(
                            "  requires restart for: {}",
                            resp.requires_restart.join(", ")
                        );
                    }
                    if resp.applied.is_empty() && resp.requires_restart.is_empty() {
                        println!("profile '{}' active (no changes)", name);
                    }
                }
                EXIT_OK
            }
            Err(e) => handle_error(e, addr),
        },
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Serialize `v` as pretty JSON and print to stdout.
fn print_json<T: serde::Serialize>(v: &T) {
    // If serialization fails, we treat it as an unexpected error (exit 1).
    match serde_json::to_string_pretty(v) {
        Ok(s) => println!("{s}"),
        Err(e) => {
            eprintln!("hush: failed to serialize response as JSON: {e}");
            process::exit(EXIT_API_ERROR);
        }
    }
}

/// Map a [`ClientError`] to the correct exit code, printing the appropriate
/// message to stderr.
///
/// - [`ClientError::Unreachable`] → print "isn't running" message + exit 2
/// - Everything else → print error message + exit 1
fn handle_error(e: ClientError, addr: &str) -> i32 {
    match e {
        ClientError::Unreachable { .. } => {
            eprintln!("hushwarren isn't running (looked at {addr}). Is the service installed?");
            EXIT_UNREACHABLE
        }
        ClientError::ApiError { message } => {
            eprintln!("hush: API error: {message}");
            EXIT_API_ERROR
        }
        ClientError::Other(inner) => {
            eprintln!("hush: {inner:#}");
            EXIT_API_ERROR
        }
    }
}
