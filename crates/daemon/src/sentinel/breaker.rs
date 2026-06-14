//! Crash-loop breaker — `docs/zero-touch-ux.md` §2.
//!
//! Implements `specs/wp5-sentinel-macos.md` §3.
//!
//! ## Protocol
//!
//! A breadcrumb file `state_dir/run-state.json` records whether the previous
//! daemon run ended cleanly and a rolling list of abnormal-restart timestamps
//! (Unix ms).  On every boot:
//!
//! 1. If the previous run was **clean** (`clean_shutdown: true`) → nothing to
//!    do; reset the restart counter.
//! 2. If the previous run was **not clean** (crash, kill-9, OOM) **and** the
//!    system DNS currently points at us (snapshot exists) → count an abnormal
//!    restart.
//! 3. If ≥ `threshold` abnormal restarts occurred within `window_secs` →
//!    **BREAKER fires**: restore the DNS snapshot, set
//!    [`GuardState::Attention`], and keep running disarmed.
//!
//! ## Deviation from zero-touch-ux §2 wording
//!
//! The spec mentions a "pre-start check" as a separate process mode invoked by
//! the service wrapper.  For P1 the check is run inline at daemon start (inside
//! `App::start`) — no separate process is needed.  The escape hatch
//! (`hushd restore`) remains independent.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, warn};

// ── Types ─────────────────────────────────────────────────────────────────────

/// The persistent breadcrumb file written to `state_dir/run-state.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunState {
    /// Was the last shutdown clean (graceful SIGTERM / API stop)?
    pub clean_shutdown: bool,
    /// Timestamps (Unix ms) of each abnormal restart observed.
    /// Entries outside the breaker window are pruned on each write.
    pub abnormal_restarts: Vec<u64>,
    /// When the breaker last fired (Unix ms), if it is still tripped.
    ///
    /// DURABILITY: the breaker's disarmed/Attention state must survive process
    /// restarts. The daemon keeps running after a fire, but `KeepAlive` plus
    /// transient `:53` bind races during a crash storm can still recycle the
    /// process; without this flag a fresh boot would come up in the default
    /// `filtering` state and silently re-arm — exactly the loop the breaker
    /// exists to stop. While this is set, every boot stays disarmed. It is
    /// cleared by a clean shutdown or an explicit re-arm (takeover).
    #[serde(default)]
    pub tripped_unix_ms: Option<u64>,
}

impl Default for RunState {
    fn default() -> Self {
        Self {
            clean_shutdown: true,
            abnormal_restarts: Vec::new(),
            tripped_unix_ms: None,
        }
    }
}

/// Outcome of [`BreakerState::check`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BreakerOutcome {
    /// Everything is fine; proceed normally.
    Nominal,
    /// Breaker fired: DNS has been restored and the daemon should run disarmed.
    Fired {
        /// Human-readable reason surfaced in the API status.
        reason: String,
    },
}

/// Configuration for the crash-loop breaker.
#[derive(Debug, Clone)]
pub struct BreakerConfig {
    /// Number of abnormal restarts within `window_secs` that trips the breaker.
    pub threshold: u32,
    /// Sliding-window length in seconds.
    pub window_secs: u64,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        Self {
            threshold: 3,
            window_secs: 300,
        }
    }
}

/// Errors from the breaker module.
#[derive(Debug, Error)]
pub enum BreakerError {
    /// The `run-state.json` file could not be read.
    #[error("run-state.json read error: {0}")]
    Read(std::io::Error),
    /// The `run-state.json` file could not be written.
    #[error("run-state.json write error: {0}")]
    Write(std::io::Error),
    /// The `run-state.json` file contains invalid JSON.
    #[error("run-state.json parse error: {0}")]
    Parse(String),
}

// ── State file I/O ────────────────────────────────────────────────────────────

/// Load `state_dir/run-state.json`.
///
/// Returns `RunState::default()` if the file does not exist.
pub fn load_run_state(state_dir: &Path) -> Result<RunState, BreakerError> {
    let path = run_state_path(state_dir);
    match std::fs::read_to_string(&path) {
        Ok(s) => serde_json::from_str(&s).map_err(|e| BreakerError::Parse(e.to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(RunState::default()),
        Err(e) => Err(BreakerError::Read(e)),
    }
}

/// Write `state_dir/run-state.json` atomically (tmp + rename).
pub fn save_run_state(state_dir: &Path, state: &RunState) -> Result<(), BreakerError> {
    let path = run_state_path(state_dir);
    let tmp = state_dir.join(".run-state.json.tmp");
    let json = serde_json::to_string_pretty(state)
        .unwrap_or_else(|_| r#"{"clean_shutdown":true,"abnormal_restarts":[]}"#.to_owned());
    std::fs::write(&tmp, &json).map_err(BreakerError::Write)?;
    std::fs::rename(&tmp, &path).map_err(BreakerError::Write)?;
    Ok(())
}

/// Mark the current run as dirty (called at daemon boot before any action).
///
/// Sets `clean_shutdown = false` so a subsequent crash is detected.
pub fn mark_dirty(state_dir: &Path) -> Result<(), BreakerError> {
    let mut state = load_run_state(state_dir).unwrap_or_default();
    state.clean_shutdown = false;
    save_run_state(state_dir, &state)
}

/// Mark the current run as clean (called in the shutdown hook).
///
/// Sets `clean_shutdown = true` and clears the durable trip and restart
/// history so the next boot starts fresh (a clean shutdown means the operator
/// or service manager stopped us deliberately).
pub fn mark_clean(state_dir: &Path) -> Result<(), BreakerError> {
    let mut state = load_run_state(state_dir).unwrap_or_default();
    state.clean_shutdown = true;
    state.tripped_unix_ms = None;
    state.abnormal_restarts.clear();
    save_run_state(state_dir, &state)
}

/// Clear a durable breaker trip — called on an explicit re-arm (takeover).
///
/// After the operator re-arms (`hushd takeover` / `POST /v0/takeover`), the
/// daemon should resume normal filtering and stop coming up disarmed.
pub fn clear_trip(state_dir: &Path) -> Result<(), BreakerError> {
    let mut state = load_run_state(state_dir).unwrap_or_default();
    state.tripped_unix_ms = None;
    state.abnormal_restarts.clear();
    save_run_state(state_dir, &state)
}

/// Path to the breadcrumb file.
pub fn run_state_path(state_dir: &Path) -> PathBuf {
    state_dir.join("run-state.json")
}

// ── Breaker logic ─────────────────────────────────────────────────────────────

/// Check for a crash loop and optionally fire the breaker.
///
/// Called at daemon boot, after marking dirty.
///
/// ## Logic
///
/// 1. If the previous run ended cleanly → reset abnormal restart list, return
///    [`BreakerOutcome::Nominal`].
/// 2. If not clean **and** a snapshot exists (DNS was pointing at us when we
///    crashed) → record this abnormal restart timestamp.
/// 3. If the sliding-window count reaches the threshold → fire:
///    - Call `restore_fn` to restore the DNS snapshot.
///    - Update the breadcrumb to reflect the state.
///    - Return [`BreakerOutcome::Fired`].
pub fn check_breaker(
    state_dir: &Path,
    cfg: &BreakerConfig,
    now_unix_ms: u64,
    snapshot_exists: bool,
    restore_fn: impl FnOnce() -> Result<(), String>,
) -> Result<BreakerOutcome, BreakerError> {
    let mut state = load_run_state(state_dir)?;

    // DURABLE TRIP: if a prior boot already fired the breaker and it has not
    // been cleared (clean shutdown / re-arm), stay disarmed across this restart
    // regardless of snapshot/clean state. Without this, the post-fire restart
    // storm re-arms in the default filtering state.
    if let Some(tripped) = state.tripped_unix_ms {
        let still_tripped = now_unix_ms.saturating_sub(tripped) <= cfg.window_secs * 1_000;
        if still_tripped {
            warn!("breaker still tripped from a recent fire; staying disarmed");
            state.clean_shutdown = false;
            save_run_state(state_dir, &state)?;
            return Ok(BreakerOutcome::Fired {
                reason: "crash-loop breaker tripped (recovering)".to_owned(),
            });
        }
        // Trip aged out → clear and proceed normally.
        state.tripped_unix_ms = None;
    }

    if state.clean_shutdown {
        // Clean exit last time → clear the restart history and proceed.
        debug!("previous shutdown was clean; resetting abnormal restart counter");
        state.abnormal_restarts.clear();
        state.clean_shutdown = false; // mark as dirty for THIS run
        save_run_state(state_dir, &state)?;
        return Ok(BreakerOutcome::Nominal);
    }

    // Previous run was not clean.
    if snapshot_exists {
        // DNS was pointed at us when we crashed → count this restart.
        state.abnormal_restarts.push(now_unix_ms);
        debug!(
            total = state.abnormal_restarts.len(),
            "abnormal restart counted (DNS was pointing at us)"
        );
    } else {
        debug!("abnormal restart but no DNS snapshot; no action needed");
        state.clean_shutdown = false;
        save_run_state(state_dir, &state)?;
        return Ok(BreakerOutcome::Nominal);
    }

    // Prune entries outside the window.
    let window_start = now_unix_ms.saturating_sub(cfg.window_secs * 1_000);
    state.abnormal_restarts.retain(|&ts| ts >= window_start);

    let count = state.abnormal_restarts.len() as u32;
    debug!(
        count,
        threshold = cfg.threshold,
        window_secs = cfg.window_secs,
        "breaker window check"
    );

    if count >= cfg.threshold {
        // BREAKER FIRES.
        warn!(
            count,
            threshold = cfg.threshold,
            "crash-loop breaker fired — restoring DNS and running disarmed"
        );

        let restore_result = restore_fn();
        if let Err(e) = restore_result {
            warn!(error = %e, "restore during breaker fire failed; DNS state may be inconsistent");
        }

        // Clear the history so we don't re-count, and set the DURABLE trip so
        // every subsequent restart stays disarmed until a clean shutdown or
        // an explicit re-arm clears it.
        state.abnormal_restarts.clear();
        state.clean_shutdown = false;
        state.tripped_unix_ms = Some(now_unix_ms);
        save_run_state(state_dir, &state)?;

        let reason = format!(
            "{count} abnormal restarts within {} seconds",
            cfg.window_secs
        );
        info!("breaker fired: {reason}");
        return Ok(BreakerOutcome::Fired { reason });
    }

    // Not yet at threshold.
    state.clean_shutdown = false;
    save_run_state(state_dir, &state)?;
    Ok(BreakerOutcome::Nominal)
}

/// Count the abnormal restarts within the given window, for testing.
pub fn count_in_window(timestamps: &[u64], now_unix_ms: u64, window_secs: u64) -> usize {
    let window_start = now_unix_ms.saturating_sub(window_secs * 1_000);
    timestamps.iter().filter(|&&ts| ts >= window_start).count()
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use tempfile::TempDir;

    fn ms(secs: u64) -> u64 {
        secs * 1_000
    }

    // ── RunState round-trip ───────────────────────────────────────────────────

    #[test]
    fn run_state_round_trip() {
        let dir = TempDir::new().unwrap();
        let state = RunState {
            clean_shutdown: false,
            abnormal_restarts: vec![ms(100), ms(200)],
            tripped_unix_ms: None,
        };
        save_run_state(dir.path(), &state).unwrap();
        let loaded = load_run_state(dir.path()).unwrap();
        assert_eq!(state, loaded);
    }

    #[test]
    fn load_run_state_missing_returns_default() {
        let dir = TempDir::new().unwrap();
        let state = load_run_state(dir.path()).unwrap();
        assert!(state.clean_shutdown);
        assert!(state.abnormal_restarts.is_empty());
    }

    #[test]
    fn mark_dirty_sets_clean_shutdown_false() {
        let dir = TempDir::new().unwrap();
        mark_dirty(dir.path()).unwrap();
        let state = load_run_state(dir.path()).unwrap();
        assert!(!state.clean_shutdown);
    }

    #[test]
    fn durable_trip_survives_restarts_until_rearm() {
        let dir = TempDir::new().unwrap();
        let cfg = BreakerConfig {
            threshold: 3,
            window_secs: 300,
        };
        let mut restores = 0;
        // Three dirty restarts with a snapshot → fire on the 3rd.
        for i in 0..3 {
            let mut s = load_run_state(dir.path()).unwrap();
            s.clean_shutdown = false;
            save_run_state(dir.path(), &s).unwrap();
            let out = check_breaker(dir.path(), &cfg, ms(100) + i * 1000, true, || {
                restores += 1;
                Ok(())
            })
            .unwrap();
            if i < 2 {
                assert_eq!(out, BreakerOutcome::Nominal);
            } else {
                assert!(matches!(out, BreakerOutcome::Fired { .. }), "3rd fires");
            }
        }
        assert_eq!(restores, 1, "restore called exactly once on fire");
        // The trip is now durable: a SUBSEQUENT restart (e.g. launchd churn +
        // :53 bind race) must STAY disarmed even though the snapshot was removed
        // and history cleared — without re-restoring.
        let out = check_breaker(dir.path(), &cfg, ms(110), false, || {
            restores += 1;
            Ok(())
        })
        .unwrap();
        assert!(
            matches!(out, BreakerOutcome::Fired { .. }),
            "stays disarmed"
        );
        assert_eq!(restores, 1, "no extra restore while already tripped");

        // An explicit re-arm clears the trip → next boot is Nominal again.
        clear_trip(dir.path()).unwrap();
        let mut s = load_run_state(dir.path()).unwrap();
        s.clean_shutdown = false;
        save_run_state(dir.path(), &s).unwrap();
        let out = check_breaker(dir.path(), &cfg, ms(120), true, || Ok(())).unwrap();
        assert_eq!(out, BreakerOutcome::Nominal, "re-arm clears the trip");
    }

    #[test]
    fn mark_clean_sets_clean_shutdown_true() {
        let dir = TempDir::new().unwrap();
        mark_dirty(dir.path()).unwrap();
        mark_clean(dir.path()).unwrap();
        let state = load_run_state(dir.path()).unwrap();
        assert!(state.clean_shutdown);
    }

    // ── Breaker window math ───────────────────────────────────────────────────

    #[test]
    fn count_in_window_basic() {
        let timestamps = vec![ms(0), ms(100), ms(200), ms(400)];
        let now = ms(500);
        // Window: 300s = 300,000ms → window_start = ms(200) → includes ms(200) and ms(400) only.
        let count = count_in_window(&timestamps, now, 300);
        assert_eq!(count, 2);
    }

    #[test]
    fn count_in_window_none_in_window() {
        let timestamps = vec![ms(0), ms(100)];
        let now = ms(1000);
        // Window 100s → window_start = ms(900); nothing qualifies.
        let count = count_in_window(&timestamps, now, 100);
        assert_eq!(count, 0);
    }

    #[test]
    fn count_in_window_all_in_window() {
        let timestamps = vec![ms(100), ms(200), ms(300)];
        let now = ms(400);
        let count = count_in_window(&timestamps, now, 400);
        assert_eq!(count, 3);
    }

    #[test]
    fn count_in_window_boundary_inclusive() {
        // now = 500s, window = 500s → window_start = 0s → ms(0) is included.
        let timestamps = vec![ms(0)];
        let count = count_in_window(&timestamps, ms(500), 500);
        assert_eq!(count, 1);
    }

    #[test]
    fn count_in_window_boundary_exclusive() {
        // now = 500s, window = 499s → window_start = 1s (1000ms) → ms(0) is excluded.
        let timestamps = vec![ms(0)];
        let count = count_in_window(&timestamps, ms(500), 499);
        assert_eq!(count, 0);
    }

    // ── Breaker: clean previous shutdown ──────────────────────────────────────

    #[test]
    fn breaker_clean_previous_shutdown_is_nominal() {
        let dir = TempDir::new().unwrap();
        // Write a clean-shutdown state.
        save_run_state(
            dir.path(),
            &RunState {
                clean_shutdown: true,
                abnormal_restarts: vec![ms(1), ms(2), ms(3)],
                tripped_unix_ms: None,
            },
        )
        .unwrap();

        let cfg = BreakerConfig {
            threshold: 3,
            window_secs: 300,
        };
        let mut restore_called = false;
        let outcome = check_breaker(dir.path(), &cfg, ms(300), true, || {
            restore_called = true;
            Ok(())
        })
        .unwrap();

        assert_eq!(outcome, BreakerOutcome::Nominal);
        assert!(!restore_called, "restore must not be called on clean boot");
        // Abnormal restart list must be cleared.
        let state = load_run_state(dir.path()).unwrap();
        assert!(state.abnormal_restarts.is_empty());
    }

    // ── Breaker: 2 restarts in window → Nominal ───────────────────────────────

    #[test]
    fn breaker_two_restarts_below_threshold() {
        let dir = TempDir::new().unwrap();
        // Simulate 2 previous abnormal restarts within the window.
        // check_breaker will add the current restart → 3 total.
        // threshold=4 → still below → Nominal.
        save_run_state(
            dir.path(),
            &RunState {
                clean_shutdown: false,
                abnormal_restarts: vec![ms(100), ms(200)],
                tripped_unix_ms: None,
            },
        )
        .unwrap();

        let cfg = BreakerConfig {
            threshold: 4,
            window_secs: 300,
        };
        let mut restore_called = false;
        let outcome = check_breaker(
            dir.path(),
            &cfg,
            ms(250),
            true, // snapshot exists
            || {
                restore_called = true;
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(outcome, BreakerOutcome::Nominal);
        assert!(!restore_called);
    }

    // ── Breaker: 3rd restart in window → Fired ────────────────────────────────

    #[test]
    fn breaker_fires_on_third_restart() {
        let dir = TempDir::new().unwrap();
        // 2 previous abnormal restarts within the window.
        save_run_state(
            dir.path(),
            &RunState {
                clean_shutdown: false,
                abnormal_restarts: vec![ms(100), ms(200)],
                tripped_unix_ms: None,
            },
        )
        .unwrap();

        let cfg = BreakerConfig {
            threshold: 3,
            window_secs: 300,
        };
        let mut restore_called = false;
        let outcome = check_breaker(
            dir.path(),
            &cfg,
            ms(250), // now = 250s, all 3 in the 300s window
            true,
            || {
                restore_called = true;
                Ok(())
            },
        )
        .unwrap();

        assert!(matches!(outcome, BreakerOutcome::Fired { .. }));
        assert!(restore_called, "restore must be called when breaker fires");
    }

    // ── Breaker: old restarts outside window → Nominal ────────────────────────

    #[test]
    fn breaker_old_restarts_outside_window_are_pruned() {
        let dir = TempDir::new().unwrap();
        // 2 restarts, but far outside the 5-min window.
        save_run_state(
            dir.path(),
            &RunState {
                clean_shutdown: false,
                abnormal_restarts: vec![ms(1), ms(2)],
                tripped_unix_ms: None,
            },
        )
        .unwrap();

        let cfg = BreakerConfig {
            threshold: 3,
            window_secs: 300,
        };
        let mut restore_called = false;
        // now = 1000s → window_start = 700s → both old entries pruned.
        let outcome = check_breaker(dir.path(), &cfg, ms(1000), true, || {
            restore_called = true;
            Ok(())
        })
        .unwrap();

        assert_eq!(outcome, BreakerOutcome::Nominal);
        assert!(!restore_called);
    }

    // ── Breaker: no snapshot → Nominal even if dirty ──────────────────────────

    #[test]
    fn breaker_no_snapshot_skips_count() {
        let dir = TempDir::new().unwrap();
        save_run_state(
            dir.path(),
            &RunState {
                clean_shutdown: false,
                abnormal_restarts: vec![ms(100), ms(200)],
                tripped_unix_ms: None,
            },
        )
        .unwrap();

        let cfg = BreakerConfig {
            threshold: 3,
            window_secs: 300,
        };
        let mut restore_called = false;
        let outcome = check_breaker(
            dir.path(),
            &cfg,
            ms(250),
            false, // no snapshot → DNS was not pointing at us → no count
            || {
                restore_called = true;
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(outcome, BreakerOutcome::Nominal);
        assert!(!restore_called);
    }

    // ── Breaker: fires on exactly threshold ───────────────────────────────────

    #[test]
    fn breaker_fires_at_exact_threshold() {
        let dir = TempDir::new().unwrap();
        // threshold=2; one previous restart in window.
        save_run_state(
            dir.path(),
            &RunState {
                clean_shutdown: false,
                abnormal_restarts: vec![ms(100)],
                tripped_unix_ms: None,
            },
        )
        .unwrap();

        let cfg = BreakerConfig {
            threshold: 2,
            window_secs: 300,
        };
        let mut fired = false;
        let outcome = check_breaker(dir.path(), &cfg, ms(200), true, || {
            fired = true;
            Ok(())
        })
        .unwrap();

        assert!(matches!(outcome, BreakerOutcome::Fired { .. }));
        assert!(fired);
    }
}
