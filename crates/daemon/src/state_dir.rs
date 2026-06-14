//! State directory resolution and initialisation.
//!
//! Implements `specs/wp2-daemon.md` §1 state-dir precedence:
//! 1. Explicit `--state-dir` CLI argument.
//! 2. `HUSH_STATE_DIR` environment variable.
//! 3. Platform default (`/Library/Application Support/hushwarren`, etc.).
//! 4. `./.hushwarren-state` dev fallback (logged as a warning).
//!
//! Creates `<state-dir>/lists/` and `<state-dir>/compiled/` on first use.

use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::warn;

/// Errors from state-dir initialisation.
#[derive(Debug, Error)]
pub enum StateDirError {
    /// Could not create the state directory or one of its required subdirs.
    #[error("failed to create state directory {path}: {source}")]
    Create {
        /// The path that could not be created.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

/// Subdirectories that `init` always creates under the state root.
const SUBDIRS: &[&str] = &["lists", "compiled"];

/// Platform default state directory.
///
/// The daemon runs as root/system service; these are system-wide paths.
#[cfg(target_os = "macos")]
fn platform_default() -> PathBuf {
    PathBuf::from("/Library/Application Support/hushwarren")
}

#[cfg(target_os = "linux")]
fn platform_default() -> PathBuf {
    PathBuf::from("/var/lib/hushwarren")
}

#[cfg(target_os = "windows")]
fn platform_default() -> PathBuf {
    // %PROGRAMDATA% defaults to C:\ProgramData when not set.
    let base = std::env::var("PROGRAMDATA").unwrap_or_else(|_| r"C:\ProgramData".to_string());
    PathBuf::from(base).join("hushwarren")
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn platform_default() -> PathBuf {
    PathBuf::from("/var/lib/hushwarren")
}

/// Resolve the state directory from the given sources and return the path.
///
/// Precedence (highest first):
/// 1. `explicit` — from `--state-dir` CLI argument.
/// 2. `HUSH_STATE_DIR` environment variable.
/// 3. Platform default.
/// 4. `./.hushwarren-state` (dev fallback, a `warn!` is emitted).
///
/// The returned path is NOT yet created — call [`init`] to create it.
pub fn resolve(explicit: Option<&str>) -> PathBuf {
    if let Some(p) = explicit {
        return PathBuf::from(p);
    }
    if let Ok(env) = std::env::var("HUSH_STATE_DIR") {
        if !env.is_empty() {
            return PathBuf::from(env);
        }
    }
    let default = platform_default();
    // If we cannot determine whether the platform default exists, use it
    // unconditionally and let `init` surface errors later.  Fall through to
    // the dev fallback only when running from a user-writable CWD and the
    // platform path is unreachable (detected by a failed permission check).
    //
    // For P0 simplicity: always return the platform default here; the dev
    // fallback fires only if the daemon can't create it (warn there).
    let _ = default; // used above
    warn_dev_fallback_if_needed(&platform_default())
}

/// Returns the path; emits `warn!` and falls back to `./.hushwarren-state`
/// when the platform path is both non-existent AND non-creatable (checked by
/// a tentative create).  For P0 the check is a best-effort heuristic: we
/// attempt to create the directory and, on permission denied specifically,
/// fall back.
fn warn_dev_fallback_if_needed(path: &Path) -> PathBuf {
    // If it already exists (common for re-runs), return immediately.
    if path.exists() {
        return path.to_path_buf();
    }
    // Try to create it — if we succeed, return it; if EPERM, fall back.
    match std::fs::create_dir_all(path) {
        Ok(()) => path.to_path_buf(),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            let fallback = PathBuf::from(".hushwarren-state");
            warn!(
                platform_path = %path.display(),
                fallback = %fallback.display(),
                "cannot create platform state dir (permission denied); \
                 using dev fallback — set HUSH_STATE_DIR for a stable location"
            );
            fallback
        }
        Err(_) => path.to_path_buf(), // let init surface other errors
    }
}

/// Create the state directory and its required subdirectories.
///
/// Safe to call repeatedly — `create_dir_all` is idempotent.
pub fn init(root: &Path) -> Result<(), StateDirError> {
    std::fs::create_dir_all(root).map_err(|source| StateDirError::Create {
        path: root.to_path_buf(),
        source,
    })?;

    for sub in SUBDIRS {
        let dir = root.join(sub);
        std::fs::create_dir_all(&dir).map_err(|source| StateDirError::Create {
            path: dir.clone(),
            source,
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use tempfile::TempDir;

    /// Process env is global; cargo runs tests in parallel threads. Every test
    /// that touches HUSH_STATE_DIR must hold this lock or the set/remove
    /// pairs race (caught live on the CI runner's 2-thread timing).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_env_var(value: Option<&str>, f: impl FnOnce() -> PathBuf) -> PathBuf {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        match value {
            Some(v) => std::env::set_var("HUSH_STATE_DIR", v),
            None => std::env::remove_var("HUSH_STATE_DIR"),
        }
        let result = f();
        std::env::remove_var("HUSH_STATE_DIR");
        result
    }

    // ── resolve: explicit wins ────────────────────────────────────────────────

    #[test]
    fn explicit_wins_over_env() {
        let result = with_env_var(Some("/env/path"), || resolve(Some("/explicit/path")));
        assert_eq!(result, PathBuf::from("/explicit/path"));
    }

    // ── resolve: env wins over default ────────────────────────────────────────

    #[test]
    fn env_wins_over_platform_default() {
        let result = with_env_var(Some("/env/state"), || resolve(None));
        assert_eq!(result, PathBuf::from("/env/state"));
    }

    // ── resolve: empty env falls through ─────────────────────────────────────

    #[test]
    fn empty_env_falls_through_to_default() {
        let result = with_env_var(Some(""), || resolve(None));
        // Must NOT be an empty path.
        assert!(!result.as_os_str().is_empty());
    }

    // ── init: creates subdirs ─────────────────────────────────────────────────

    #[test]
    fn init_creates_subdirs() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("state");
        init(&root).unwrap();
        for sub in SUBDIRS {
            assert!(
                root.join(sub).is_dir(),
                "subdir {sub} must exist after init"
            );
        }
    }

    // ── init: idempotent ──────────────────────────────────────────────────────

    #[test]
    fn init_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("state");
        init(&root).unwrap();
        init(&root).unwrap(); // second call must not error
    }
}
