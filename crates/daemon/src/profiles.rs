//! Multi-profile support: load/save/switch config profiles (WP14 §2).
//!
//! Profiles are full `HushConfig` TOML files stored at
//! `state_dir/profiles/<name>.toml`.  The active profile name is persisted to
//! `state_dir/active-profile` and loaded at startup.
//!
//! ## Hot-reload subset
//!
//! `POST /v0/config/reload` applies only the hot-reloadable subset and reports
//! what requires restart.  The exact classification is documented below and
//! tested by `config::reload_subset_partition_table_complete`.
//!
//! Hot-reloadable (applied without restart):
//!   - `lists` — re-feed into the existing list pipeline
//!   - `privacy` — update in-memory privacy config
//!   - `upstream` — rebuild the upstream ladder atomically
//!
//! Requires restart (not applied, reported to caller):
//!   - `listen`, `block`, `api`, `runtime`, `sentinel`, `dashboard`,
//!     `network_guard`, `inbound_tls`

use hush_core::config::HushConfig;
use std::{
    fs,
    path::{Path, PathBuf},
};
use tracing::{info, warn};

/// Validate that `name` is a safe profile identifier.
///
/// Returns `Ok(())` when valid, `Err(ProfileError::InvalidName)` otherwise.
/// Called at BOTH the API boundary and inside `profile_path` (defence in depth).
pub fn validate_profile_name(name: &str) -> Result<(), ProfileError> {
    // Manual check without regex dep: only allow [A-Za-z0-9_-]{1,64}.
    if name.is_empty() || name.len() > 64 {
        return Err(ProfileError::InvalidName(name.to_owned()));
    }
    if name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        Ok(())
    } else {
        Err(ProfileError::InvalidName(name.to_owned()))
    }
}

/// Name of the file that persists the currently active profile.
const ACTIVE_PROFILE_FILE: &str = "active-profile";

/// Subdirectory within the state dir that contains profile TOML files.
const PROFILES_DIR: &str = "profiles";

// ── Public API ─────────────────────────────────────────────────────────────────

/// Errors from profile operations.
#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    /// Profile file not found.
    #[error("profile not found: {0}")]
    NotFound(String),
    /// Profile name failed validation (path traversal prevention).
    ///
    /// Valid names match `[A-Za-z0-9_-]{1,64}`.
    #[error("invalid profile name '{0}' (must match [A-Za-z0-9_-]{{1,64}})")]
    InvalidName(String),
    /// TOML parse error.
    #[error("TOML parse error in profile {name}: {error}")]
    Parse { name: String, error: String },
    /// Validation error.
    #[error("profile {name} validation error: {error}")]
    Validation { name: String, error: String },
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// List all available profile names (TOML files in `state_dir/profiles/`).
///
/// Returns an empty list when the directory does not exist.
pub fn list_profiles(state_dir: &Path) -> Vec<String> {
    let dir = state_dir.join(PROFILES_DIR);
    match fs::read_dir(&dir) {
        Ok(entries) => {
            let mut names: Vec<String> = entries
                .filter_map(|e| e.ok())
                .filter_map(|e| {
                    let path = e.path();
                    if path.extension().is_some_and(|ext| ext == "toml") {
                        path.file_stem().and_then(|s| s.to_str()).map(str::to_owned)
                    } else {
                        None
                    }
                })
                .collect();
            names.sort();
            names
        }
        Err(_) => Vec::new(),
    }
}

/// Load a named profile from `state_dir/profiles/<name>.toml`.
pub fn load_profile(state_dir: &Path, name: &str) -> Result<HushConfig, ProfileError> {
    // API boundary validation — reject traversal attempts before touching the FS.
    validate_profile_name(name)?;
    let path = profile_path(state_dir, name);
    let content = fs::read_to_string(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ProfileError::NotFound(name.to_owned())
        } else {
            ProfileError::Io(e)
        }
    })?;

    let cfg: HushConfig = toml::from_str(&content).map_err(|e| ProfileError::Parse {
        name: name.to_owned(),
        error: e.to_string(),
    })?;

    let problems = cfg.validate();
    if !problems.is_empty() {
        return Err(ProfileError::Validation {
            name: name.to_owned(),
            error: problems
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join("; "),
        });
    }

    Ok(cfg)
}

/// Return the raw TOML content of a named profile.
pub fn read_profile_content(state_dir: &Path, name: &str) -> Result<String, ProfileError> {
    // API boundary validation — reject traversal attempts before touching the FS.
    validate_profile_name(name)?;
    let path = profile_path(state_dir, name);
    fs::read_to_string(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ProfileError::NotFound(name.to_owned())
        } else {
            ProfileError::Io(e)
        }
    })
}

/// Persist the name of the active profile to `state_dir/active-profile`.
pub fn save_active_profile(state_dir: &Path, name: &str) -> Result<(), std::io::Error> {
    let path = state_dir.join(ACTIVE_PROFILE_FILE);
    fs::write(&path, name)
}

/// Load the active profile name from `state_dir/active-profile`.
///
/// Returns `None` when the file does not exist (normal first-run / no profile
/// selected).
pub fn load_active_profile_name(state_dir: &Path) -> Option<String> {
    let path = state_dir.join(ACTIVE_PROFILE_FILE);
    match fs::read_to_string(&path) {
        Ok(s) => {
            let name = s.trim().to_owned();
            if name.is_empty() {
                None
            } else {
                Some(name)
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            warn!(error = %e, "could not read active-profile file; using default config");
            None
        }
    }
}

/// Load the active profile at daemon startup.
///
/// Returns `(config, active_name)` where `active_name` is `None` when no profile
/// is active.  Falls back to `base_config` when the profile file is missing or
/// invalid.
pub fn load_active_profile_at_startup(
    state_dir: &Path,
    base_config: &HushConfig,
) -> (HushConfig, Option<String>) {
    let Some(name) = load_active_profile_name(state_dir) else {
        return (base_config.clone(), None);
    };

    match load_profile(state_dir, &name) {
        Ok(cfg) => {
            info!(profile = %name, "loaded active profile at startup");
            (cfg, Some(name))
        }
        Err(e) => {
            warn!(
                profile = %name,
                error = %e,
                "active profile failed to load; falling back to default config"
            );
            (base_config.clone(), None)
        }
    }
}

/// Profile-switch result — what happened and what still needs restart.
pub struct ReloadResult {
    /// Config sections applied immediately.
    pub applied: Vec<String>,
    /// Config sections that require restart.
    pub requires_restart: Vec<String>,
}

/// Classify which sections differ and which require restart.
///
/// The caller is responsible for actually applying the hot-reloadable sections.
pub fn classify_reload(old: &HushConfig, new: &HushConfig) -> ReloadResult {
    let mut applied = Vec::new();
    let mut requires_restart = Vec::new();

    // Hot-reloadable sections (applied without restart).
    if old.lists != new.lists {
        applied.push("lists".to_owned());
    }
    if old.privacy != new.privacy {
        applied.push("privacy".to_owned());
    }

    // Requires-restart sections (NOT applied; reported to caller).
    //
    // `upstream`: the ladder is constructed at startup by binding DoH transports,
    // probing ODoH targets, and setting up rustls clients.  That bind-time
    // initialisation cannot be hot-swapped without restarting the resolver task.
    // The spec §7 escape hatch: "report bind-time things honestly."
    if old.upstream != new.upstream {
        requires_restart.push("upstream".to_owned());
    }
    if old.listen != new.listen {
        requires_restart.push("listen".to_owned());
    }
    if old.block != new.block {
        requires_restart.push("block".to_owned());
    }
    if old.api != new.api {
        requires_restart.push("api".to_owned());
    }
    if old.runtime != new.runtime {
        requires_restart.push("runtime".to_owned());
    }
    if old.sentinel != new.sentinel {
        requires_restart.push("sentinel".to_owned());
    }
    if old.dashboard != new.dashboard {
        requires_restart.push("dashboard".to_owned());
    }
    if old.network_guard != new.network_guard {
        requires_restart.push("network_guard".to_owned());
    }
    if old.inbound_tls != new.inbound_tls {
        requires_restart.push("inbound_tls".to_owned());
    }

    ReloadResult {
        applied,
        requires_restart,
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Build the filesystem path for a named profile.
///
/// # Invariant
///
/// `name` MUST already have been validated by [`validate_profile_name`] before
/// this function is called.  The assertion here is a defence-in-depth backstop:
/// any caller that bypasses the public API will panic loudly in development
/// rather than silently creating a path outside the profiles directory.
fn profile_path(state_dir: &Path, name: &str) -> PathBuf {
    // PANIC-OK: validate_profile_name is called by every public entry point;
    // a failure here means an internal caller bypassed the public API validation.
    assert!(
        validate_profile_name(name).is_ok(),
        "profile_path called with unvalidated name: {name:?}"
    );
    state_dir.join(PROFILES_DIR).join(format!("{name}.toml"))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use hush_core::config::HushConfig;
    use tempfile::TempDir;

    fn write_profile(state_dir: &Path, name: &str, content: &str) {
        let dir = state_dir.join("profiles");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{name}.toml")), content).unwrap();
    }

    // ── list_profiles ─────────────────────────────────────────────────────────

    #[test]
    fn list_profiles_empty_when_no_dir() {
        let tmp = TempDir::new().unwrap();
        let names = list_profiles(tmp.path());
        assert!(names.is_empty());
    }

    #[test]
    fn list_profiles_returns_sorted_names() {
        let tmp = TempDir::new().unwrap();
        let min_toml = toml::to_string(&HushConfig::default()).unwrap();
        write_profile(tmp.path(), "work", &min_toml);
        write_profile(tmp.path(), "home", &min_toml);
        write_profile(tmp.path(), "strict", &min_toml);

        let names = list_profiles(tmp.path());
        assert_eq!(names, vec!["home", "strict", "work"]);
    }

    // ── load_profile ──────────────────────────────────────────────────────────

    #[test]
    fn load_profile_not_found_returns_error() {
        let tmp = TempDir::new().unwrap();
        let result = load_profile(tmp.path(), "missing");
        assert!(matches!(result, Err(ProfileError::NotFound(_))));
    }

    #[test]
    fn load_profile_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let cfg = HushConfig::default();
        let toml_str = toml::to_string(&cfg).unwrap();
        write_profile(tmp.path(), "default-rt", &toml_str);

        let loaded = load_profile(tmp.path(), "default-rt").unwrap();
        assert_eq!(loaded.listen, cfg.listen);
    }

    // ── active profile persistence ────────────────────────────────────────────

    #[test]
    fn active_profile_roundtrip() {
        let tmp = TempDir::new().unwrap();
        assert!(load_active_profile_name(tmp.path()).is_none());

        save_active_profile(tmp.path(), "work").unwrap();
        assert_eq!(
            load_active_profile_name(tmp.path()).as_deref(),
            Some("work")
        );
    }

    // ── classify_reload ───────────────────────────────────────────────────────

    #[test]
    fn classify_reload_no_changes_empty_result() {
        let cfg = HushConfig::default();
        let result = classify_reload(&cfg, &cfg);
        assert!(result.applied.is_empty());
        assert!(result.requires_restart.is_empty());
    }

    #[test]
    fn classify_reload_lists_change_goes_to_applied() {
        let old = HushConfig::default();
        let mut new = old.clone();
        new.lists.preset = "strict".to_owned();
        let result = classify_reload(&old, &new);
        assert!(result.applied.contains(&"lists".to_owned()));
        assert!(!result.requires_restart.contains(&"lists".to_owned()));
    }

    #[test]
    fn classify_reload_listen_change_goes_to_requires_restart() {
        let old = HushConfig::default();
        let mut new = old.clone();
        new.listen.udp = vec!["0.0.0.0:5353".to_owned()];
        let result = classify_reload(&old, &new);
        assert!(result.requires_restart.contains(&"listen".to_owned()));
        assert!(!result.applied.contains(&"listen".to_owned()));
    }

    #[test]
    fn classify_reload_inbound_tls_change_goes_to_requires_restart() {
        let old = HushConfig::default();
        let mut new = old.clone();
        new.inbound_tls.enabled = true;
        let result = classify_reload(&old, &new);
        assert!(result.requires_restart.contains(&"inbound_tls".to_owned()));
    }
}
