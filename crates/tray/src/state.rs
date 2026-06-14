//! State mapping: `/v0/status` JSON → [`DotState`].
//!
//! Implements `specs/wp10-tray.md` §2 dot-state logic and
//! `docs/zero-touch-ux.md` §8 tray table.
//!
//! This module is pure: no I/O, no filesystem, no network.  All mapping
//! is a deterministic function of the JSON fields — unit-testable headlessly.

use serde::Deserialize;

// ── Status response shape ─────────────────────────────────────────────────────
//
// Mirrors the subset of `GET /v0/status` that the tray cares about.
// Uses `#[serde(default)]` on optional fields so the tray tolerates future
// daemon versions that add new fields without breaking deserialization.

/// Subset of `GET /v0/status` needed to derive the dot state.
///
/// Full schema lives in `crates/cli/src/types.rs`; the tray duplicates only
/// the fields it needs rather than importing across crates.
#[derive(Debug, Clone, Deserialize)]
pub struct StatusResponse {
    /// Guard state: `"filtering"`, `"snoozed"`, `"standing_by"`, `"attention"`.
    pub state: String,
    /// Non-null while snoozed (expiry in Unix ms).
    ///
    /// Retained in the struct so callers can display time-until-resume in
    /// tooltips in the future; the tray currently uses the `state` field to
    /// derive the dot colour.
    #[serde(default)]
    #[allow(dead_code)] // used in tests; retained for future tooltip enrichment
    pub snoozed_until_unix_ms: Option<u64>,
    /// Cumulative counters.
    pub counters: Counters,
}

/// Counters sub-object from `/v0/status`.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Counters {
    /// Total queries answered since daemon start.
    ///
    /// Retained for future use (query-rate display in tooltip); the tray
    /// currently derives tooltip text from `blocked_total` only.
    #[allow(dead_code)] // retained for future tooltip enrichment
    pub queries_total: u64,
    /// Queries sinkholed since daemon start.
    pub blocked_total: u64,
}

// ── DotState ─────────────────────────────────────────────────────────────────

/// The four visible tray states from `docs/zero-touch-ux.md §8`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DotState {
    /// Green — actively filtering.
    Filtering,
    /// Amber — snoozed (auto re-arms).
    Snoozed,
    /// Grey — standing by: VPN / portal / user-set DNS / daemon unreachable.
    StandingBy,
    /// Red — attention: crash-loop breaker fired.
    Attention,
}

impl DotState {
    /// Human-readable state name for `--once` output and tooltip.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Filtering => "filtering",
            Self::Snoozed => "snoozed",
            Self::StandingBy => "standing_by",
            Self::Attention => "attention",
        }
    }
}

// ── TrayState ────────────────────────────────────────────────────────────────

/// Full tray display state: dot + tooltip text + blocked counter for the menu.
#[derive(Debug, Clone)]
pub struct TrayState {
    /// Which coloured dot to show.
    pub dot: DotState,
    /// Tooltip string (e.g. "hushwarren — 1 234 blocked today").
    ///
    /// Read by the macOS tray UI; the headless `--once` path reads only `dot`.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub tooltip: String,
    /// Blocked counter for the disabled menu line.
    ///
    /// Read by the macOS tray UI; the headless `--once` path reads only `dot`.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub blocked_total: u64,
}

// ── Mapping ───────────────────────────────────────────────────────────────────

/// Map a live `/v0/status` response to [`TrayState`].
///
/// Guard-state strings are the exact strings emitted by `routes.rs`
/// `guard_state_to_string`:
///   - `"filtering"` → green
///   - `"snoozed"`   → amber
///   - `"standing_by"` → grey
///   - `"attention"` → red (breaker fired)
///   - anything else → grey (defensive; future states degrade gracefully)
pub fn status_to_tray(status: &StatusResponse) -> TrayState {
    let dot = match status.state.as_str() {
        "filtering" => DotState::Filtering,
        "snoozed" => DotState::Snoozed,
        "standing_by" => DotState::StandingBy,
        "attention" => DotState::Attention,
        // Unknown future states degrade to StandingBy (grey) — conservative.
        _ => DotState::StandingBy,
    };

    let blocked = status.counters.blocked_total;
    let tooltip = format!("hushwarren — {} blocked today", blocked);

    TrayState {
        dot,
        tooltip,
        blocked_total: blocked,
    }
}

/// Produce a [`TrayState`] for the "daemon unreachable" case (grey dot).
///
/// Used when `GET /v0/status` fails (connection refused, timeout, etc.).
pub fn unreachable_state() -> TrayState {
    TrayState {
        dot: DotState::StandingBy,
        tooltip: "hushwarren — starting / not running".to_owned(),
        blocked_total: 0,
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    fn make_status(state: &str, blocked: u64) -> StatusResponse {
        StatusResponse {
            state: state.to_owned(),
            snoozed_until_unix_ms: None,
            counters: Counters {
                queries_total: blocked + 100,
                blocked_total: blocked,
            },
        }
    }

    fn make_status_snoozed(blocked: u64) -> StatusResponse {
        StatusResponse {
            state: "snoozed".to_owned(),
            snoozed_until_unix_ms: Some(9_999_999_999_000),
            counters: Counters {
                queries_total: blocked + 50,
                blocked_total: blocked,
            },
        }
    }

    // ── Filtering → green ─────────────────────────────────────────────────────

    #[test]
    fn filtering_maps_to_green() {
        let s = make_status("filtering", 42);
        let t = status_to_tray(&s);
        assert_eq!(t.dot, DotState::Filtering);
        assert_eq!(t.blocked_total, 42);
        assert!(t.tooltip.contains("42"));
    }

    // ── Snoozed → amber ───────────────────────────────────────────────────────

    #[test]
    fn snoozed_maps_to_amber() {
        let s = make_status_snoozed(7);
        let t = status_to_tray(&s);
        assert_eq!(t.dot, DotState::Snoozed);
        assert_eq!(t.blocked_total, 7);
    }

    // ── Standing-by → grey ────────────────────────────────────────────────────

    #[test]
    fn standing_by_maps_to_grey() {
        let s = make_status("standing_by", 0);
        let t = status_to_tray(&s);
        assert_eq!(t.dot, DotState::StandingBy);
    }

    // ── Attention → red ───────────────────────────────────────────────────────

    #[test]
    fn attention_maps_to_red() {
        let s = make_status("attention", 0);
        let t = status_to_tray(&s);
        assert_eq!(t.dot, DotState::Attention);
    }

    // ── Unknown state → grey (defensive) ────────────────────────────────────

    #[test]
    fn unknown_state_degrades_to_grey() {
        let s = make_status("some_future_state", 0);
        let t = status_to_tray(&s);
        assert_eq!(t.dot, DotState::StandingBy);
    }

    // ── Unreachable → grey with specific message ──────────────────────────────

    #[test]
    fn unreachable_is_grey_and_not_running_tooltip() {
        let t = unreachable_state();
        assert_eq!(t.dot, DotState::StandingBy);
        assert!(
            t.tooltip.contains("not running") || t.tooltip.contains("starting"),
            "tooltip must indicate daemon is not running; got: {}",
            t.tooltip
        );
        assert_eq!(t.blocked_total, 0);
    }

    // ── DotState::as_str roundtrip ────────────────────────────────────────────

    #[test]
    fn dot_state_as_str_roundtrip() {
        assert_eq!(DotState::Filtering.as_str(), "filtering");
        assert_eq!(DotState::Snoozed.as_str(), "snoozed");
        assert_eq!(DotState::StandingBy.as_str(), "standing_by");
        assert_eq!(DotState::Attention.as_str(), "attention");
    }

    // ── Tooltip contains blocked count ───────────────────────────────────────

    #[test]
    fn tooltip_contains_blocked_count() {
        let s = make_status("filtering", 1234);
        let t = status_to_tray(&s);
        assert!(
            t.tooltip.contains("1234"),
            "tooltip must contain blocked count; got: {}",
            t.tooltip
        );
    }

    // ── Zero blocked counter ──────────────────────────────────────────────────

    #[test]
    fn zero_blocked_total() {
        let s = make_status("filtering", 0);
        let t = status_to_tray(&s);
        assert_eq!(t.blocked_total, 0);
        assert!(t.tooltip.contains("0"));
    }

    // ── Snoozed state carries the expiry timestamp ────────────────────────────

    #[test]
    fn snoozed_carries_expiry_in_status() {
        let s = make_status_snoozed(10);
        assert_eq!(s.snoozed_until_unix_ms, Some(9_999_999_999_000));
    }
}
