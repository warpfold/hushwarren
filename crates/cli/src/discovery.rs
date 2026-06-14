//! State-directory discovery and API credential loading.
//!
//! Implements the precedence chain from `specs/wp3-api-cli.md` §4:
//!   `--state-dir` flag > `HUSH_STATE_DIR` env var > platform default.
//!
//! Once a state directory is resolved the module reads two files written by the
//! daemon at boot:
//!   - `api.addr`  — the actual bound address, e.g. `127.0.0.1:5380`
//!   - `api.token` — 64-char hex bearer token

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Resolved API credentials ready for use by [`crate::client::ApiClient`].
#[derive(Debug, Clone)]
pub struct ApiCredentials {
    /// Base URL of the hushd control API, e.g. `http://127.0.0.1:5380`.
    pub base_url: String,
    /// Bearer token to send in every `Authorization` header.
    pub token: String,
}

/// Resolve the state directory using the precedence chain.
///
/// Precedence: `explicit_flag` > `HUSH_STATE_DIR` env var > platform default.
pub fn resolve_state_dir(explicit_flag: Option<&Path>) -> PathBuf {
    if let Some(p) = explicit_flag {
        return p.to_owned();
    }
    if let Ok(env) = std::env::var("HUSH_STATE_DIR") {
        if !env.is_empty() {
            return PathBuf::from(env);
        }
    }
    platform_default_state_dir()
}

/// Load `api.addr` and `api.token` from `state_dir`.
///
/// Returns an error if either file is missing or unparseable.
pub fn load_credentials(state_dir: &Path) -> Result<ApiCredentials> {
    let addr_path = state_dir.join("api.addr");
    let token_path = state_dir.join("api.token");

    let addr_raw = std::fs::read_to_string(&addr_path)
        .with_context(|| format!("cannot read {}", addr_path.display()))?;
    let addr = addr_raw.trim().to_owned();

    let token_raw = std::fs::read_to_string(&token_path)
        .with_context(|| format!("cannot read {}", token_path.display()))?;
    let token = token_raw.trim().to_owned();

    let base_url = format!("http://{addr}");
    Ok(ApiCredentials { base_url, token })
}

// ── Platform defaults ─────────────────────────────────────────────────────────

/// Returns the platform-appropriate default state directory for hushwarren.
///
/// - macOS: `/Library/Application Support/hushwarren` (system-wide; matches the
///   daemon's default in `crates/daemon/src/state_dir.rs` and the LaunchDaemon
///   plist).  Note: the previous per-user path (`$HOME/Library/…`) was a CLI
///   bug surfaced by review — the daemon always uses the system-wide path.
/// - Linux: `/var/lib/hushwarren` (system daemon convention)
/// - Windows: `%PROGRAMDATA%\hushwarren` (or fallback to `C:\ProgramData\hushwarren`)
///
/// The function never fails; it returns a best-effort path even when env vars
/// are absent.
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
        // Fallback for unsupported platforms.
        PathBuf::from("/var/lib/hushwarren")
    }
}

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    // ── Precedence: explicit flag beats env ───────────────────────────────────

    #[test]
    fn explicit_flag_beats_env() {
        let tmp = TempDir::new().unwrap();
        // Set env to something different.
        std::env::set_var("HUSH_STATE_DIR", "/should/not/be/used");
        let result = resolve_state_dir(Some(tmp.path()));
        // Restore: do it regardless of result.
        std::env::remove_var("HUSH_STATE_DIR");
        assert_eq!(result, tmp.path());
    }

    // ── Precedence: env beats platform default ────────────────────────────────

    #[test]
    fn env_beats_platform_default() {
        let tmp = TempDir::new().unwrap();
        let path_str = tmp.path().to_str().unwrap().to_owned();
        std::env::set_var("HUSH_STATE_DIR", &path_str);
        let result = resolve_state_dir(None);
        std::env::remove_var("HUSH_STATE_DIR");
        assert_eq!(result, tmp.path());
    }

    // ── Precedence: empty env falls through to default ────────────────────────

    #[test]
    fn empty_env_falls_through_to_default() {
        std::env::set_var("HUSH_STATE_DIR", "");
        let result = resolve_state_dir(None);
        std::env::remove_var("HUSH_STATE_DIR");
        // We can't check the exact default (platform-dependent), but it must
        // not be an empty path.
        assert!(!result.as_os_str().is_empty());
    }

    // ── Precedence: no flag, no env → platform default ────────────────────────

    #[test]
    fn no_flag_no_env_returns_platform_default() {
        std::env::remove_var("HUSH_STATE_DIR");
        let result = resolve_state_dir(None);
        assert!(!result.as_os_str().is_empty());
    }

    /// On macOS the CLI default must match the daemon's system-wide path so
    /// `hush status` finds the daemon's state dir without HUSH_STATE_DIR.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_default_matches_daemon_state_dir() {
        std::env::remove_var("HUSH_STATE_DIR");
        let result = resolve_state_dir(None);
        assert_eq!(
            result,
            std::path::PathBuf::from("/Library/Application Support/hushwarren"),
            "macOS CLI default must be /Library/Application Support/hushwarren \
             (system-wide, matching the daemon)"
        );
    }

    // ── load_credentials reads addr + token ──────────────────────────────────

    #[test]
    fn load_credentials_happy_path() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("api.addr"), "127.0.0.1:9999\n").unwrap();
        fs::write(tmp.path().join("api.token"), "deadbeef1234\n").unwrap();

        let creds = load_credentials(tmp.path()).unwrap();
        assert_eq!(creds.base_url, "http://127.0.0.1:9999");
        assert_eq!(creds.token, "deadbeef1234");
    }

    #[test]
    fn load_credentials_strips_whitespace() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("api.addr"), "  127.0.0.1:8080  ").unwrap();
        fs::write(tmp.path().join("api.token"), "\ttoken123\t").unwrap();

        let creds = load_credentials(tmp.path()).unwrap();
        assert_eq!(creds.base_url, "http://127.0.0.1:8080");
        assert_eq!(creds.token, "token123");
    }

    #[test]
    fn load_credentials_missing_addr_file_errors() {
        let tmp = TempDir::new().unwrap();
        // Only write the token file; addr is missing.
        fs::write(tmp.path().join("api.token"), "sometoken").unwrap();
        let result = load_credentials(tmp.path());
        assert!(result.is_err());
        let msg = format!("{:#}", result.unwrap_err());
        assert!(
            msg.contains("api.addr"),
            "error message must name the missing file"
        );
    }

    #[test]
    fn load_credentials_missing_token_file_errors() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("api.addr"), "127.0.0.1:5380").unwrap();
        let result = load_credentials(tmp.path());
        assert!(result.is_err());
        let msg = format!("{:#}", result.unwrap_err());
        assert!(
            msg.contains("api.token"),
            "error message must name the missing file"
        );
    }
}
