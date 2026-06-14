//! State-directory discovery and API credential loading for hush-tray.
//!
//! # Duplication note
//!
//! This module is a deliberate ~30-line copy of `crates/cli/src/discovery.rs`.
//! The spec (`specs/wp10-tray.md` §2) requires mirroring the CLI's discovery
//! logic rather than creating a shared crate, to keep crate boundaries minimal
//! and avoid coupling an ambient UI process to the CLI's dependency graph.
//! If the discovery contract changes, BOTH copies must be updated.
//!
//! State-dir resolution matches the daemon's (`crates/daemon/src/state_dir.rs`):
//!   `HUSH_STATE_DIR` env var > platform default.
//! Precedence chain per `specs/wp3-api-cli.md` §4:
//!   `HUSH_STATE_DIR` env var > platform default.

use std::path::{Path, PathBuf};

use thiserror::Error;

/// Resolved API credentials ready for use by [`crate::client::TrayClient`].
#[derive(Debug, Clone)]
pub struct ApiCredentials {
    /// Base URL of the hushd control API, e.g. `http://127.0.0.1:5380`.
    pub base_url: String,
    /// Bearer token to send in every `Authorization` header.
    pub token: String,
}

/// Errors from credential loading.
#[derive(Debug, Error)]
pub enum DiscoveryError {
    /// A required state-dir file could not be read.
    #[error("cannot read {path}: {source}")]
    Io {
        /// Path that could not be read.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

/// Resolve the state directory using the precedence chain.
///
/// Precedence: `HUSH_STATE_DIR` env var > platform default.
/// (The tray has no `--state-dir` CLI flag; env is the override.)
pub fn resolve_state_dir() -> PathBuf {
    if let Ok(env) = std::env::var("HUSH_STATE_DIR") {
        if !env.is_empty() {
            return PathBuf::from(env);
        }
    }
    platform_default_state_dir()
}

/// Load `api.addr` and `api.token` from `state_dir`.
///
/// Returns an error if either file is missing or cannot be read.
pub fn load_credentials(state_dir: &Path) -> Result<ApiCredentials, DiscoveryError> {
    let addr_path = state_dir.join("api.addr");
    let token_path = state_dir.join("api.token");

    let addr_raw = std::fs::read_to_string(&addr_path).map_err(|source| DiscoveryError::Io {
        path: addr_path.clone(),
        source,
    })?;
    let addr = addr_raw.trim().to_owned();

    let token_raw = std::fs::read_to_string(&token_path).map_err(|source| DiscoveryError::Io {
        path: token_path.clone(),
        source,
    })?;
    let token = token_raw.trim().to_owned();

    let base_url = format!("http://{addr}");
    Ok(ApiCredentials { base_url, token })
}

// ── Platform defaults ─────────────────────────────────────────────────────────
//
// Daemon runs as root → `/Library/Application Support/hushwarren` on macOS.
// The tray runs as the user but reads files written by root, so the path must
// match the daemon's platform_default exactly (`crates/daemon/src/state_dir.rs`).

/// Returns the platform-appropriate default state directory for hushwarren.
///
/// - macOS: `/Library/Application Support/hushwarren` (system daemon path)
/// - Linux: `/var/lib/hushwarren`
/// - Windows: `%PROGRAMDATA%\hushwarren`
fn platform_default_state_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/hushwarren")
    }

    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/var/lib/hushwarren")
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(pd) = std::env::var("PROGRAMDATA") {
            return PathBuf::from(pd).join("hushwarren");
        }
        PathBuf::from(r"C:\ProgramData\hushwarren")
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        PathBuf::from("/var/lib/hushwarren")
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    // ── HUSH_STATE_DIR env beats platform default ─────────────────────────────

    #[test]
    fn env_beats_platform_default() {
        let tmp = TempDir::new().unwrap();
        let path_str = tmp.path().to_str().unwrap().to_owned();
        std::env::set_var("HUSH_STATE_DIR", &path_str);
        let result = resolve_state_dir();
        std::env::remove_var("HUSH_STATE_DIR");
        assert_eq!(result, tmp.path());
    }

    // ── Empty env falls through to platform default ───────────────────────────

    #[test]
    fn empty_env_falls_through_to_default() {
        std::env::set_var("HUSH_STATE_DIR", "");
        let result = resolve_state_dir();
        std::env::remove_var("HUSH_STATE_DIR");
        assert!(!result.as_os_str().is_empty());
    }

    // ── load_credentials happy path ───────────────────────────────────────────

    #[test]
    fn load_credentials_happy_path() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("api.addr"), "127.0.0.1:9999\n").unwrap();
        fs::write(tmp.path().join("api.token"), "deadbeef1234\n").unwrap();

        let creds = load_credentials(tmp.path()).unwrap();
        assert_eq!(creds.base_url, "http://127.0.0.1:9999");
        assert_eq!(creds.token, "deadbeef1234");
    }

    // ── load_credentials strips whitespace ───────────────────────────────────

    #[test]
    fn load_credentials_strips_whitespace() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("api.addr"), "  127.0.0.1:8080  ").unwrap();
        fs::write(tmp.path().join("api.token"), "\ttoken123\t").unwrap();

        let creds = load_credentials(tmp.path()).unwrap();
        assert_eq!(creds.base_url, "http://127.0.0.1:8080");
        assert_eq!(creds.token, "token123");
    }

    // ── Missing api.addr errors with path in message ──────────────────────────

    #[test]
    fn load_credentials_missing_addr_errors() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("api.token"), "sometoken").unwrap();
        let result = load_credentials(tmp.path());
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("api.addr"), "error must name the missing file");
    }

    // ── Missing api.token errors with path in message ─────────────────────────

    #[test]
    fn load_credentials_missing_token_errors() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("api.addr"), "127.0.0.1:5380").unwrap();
        let result = load_credentials(tmp.path());
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("api.token"),
            "error must name the missing file"
        );
    }

    // ── Platform default is non-empty ─────────────────────────────────────────

    #[test]
    fn platform_default_is_non_empty() {
        let p = platform_default_state_dir();
        assert!(!p.as_os_str().is_empty());
    }
}
