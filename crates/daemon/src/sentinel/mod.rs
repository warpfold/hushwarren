//! Sentinel: guard-state machine, DNS takeover, crash safety, network watcher.
//!
//! Implements `docs/zero-touch-ux.md` §1–§6 and
//! `specs/wp5-sentinel-macos.md`.
//!
//! ## Module structure
//!
//! - [`breaker`] — crash-loop breaker (breadcrumb + restart counting).
//! - [`takeover`] — DNS takeover transaction (7-step atomic commit).
//! - [`watch`] — network-change watcher (wake, drift, VPN, portal).
//!
//! ## State model
//!
//! All state transitions go through [`Sentinel::state_tx`].  API `/v0/status`
//! reads the current state via [`Sentinel::current_state`].
//!
//! ## Deviations from spec
//!
//! - The crash-loop "pre-start check" runs inline at `App::start` rather than
//!   in a separate service-wrapper process.  The escape hatch (`hushd
//!   restore`) remains a fully independent code path.
//! - P2 tray notifications are not implemented; user-DNS yield is logged at
//!   `warn!` only.

pub mod breaker;
pub mod takeover;
pub mod watch;

use hush_core::DecisionEngine;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::watch as tokio_watch;

// ── Public re-exports used by the rest of the daemon ─────────────────────────

pub use breaker::{BreakerConfig, BreakerOutcome};
pub use takeover::{TakeoverConfig, TakeoverError};
pub use watch::WatcherState;

// ── GuardState + StandbyReason ────────────────────────────────────────────────

/// Why the sentinel is standing by (not filtering).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StandbyReason {
    /// Waiting for the initial list compile to complete.
    Initialising,
    /// All upstream resolvers are unreachable (degraded to pass-through).
    AllUpstreamsDown,
    /// A captive portal has been detected; pass-through until cleared.
    Portal,
    /// A VPN has taken over DNS; yielding until it disconnects.
    VpnActive,
    /// The user (or another app) explicitly set a third-party DNS resolver.
    UserDns,
}

/// The observable state of the Sentinel.
///
/// All state transitions go through [`Sentinel`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardState {
    /// Normal operation: blocklist active, upstreams healthy.
    Filtering,
    /// Temporary user-initiated pass-through.
    Snoozed {
        /// Unix time (ms) when snooze expires and `Filtering` resumes.
        until_unix_ms: u64,
    },
    /// Not filtering, for the given reason — not a user choice.
    StandingBy {
        /// Why we are standing by.
        why: StandbyReason,
    },
    /// Anomaly requiring user attention (crash-loop breaker fired).
    Attention {
        /// Human-readable description of the anomaly.
        why: String,
    },
}

/// Errors produced by the Sentinel.
#[derive(Debug, Error)]
pub enum SentinelError {
    /// The watch channel was closed (caller dropped the receiver).
    #[error("sentinel state channel closed")]
    ChannelClosed,
}

// ── Sentinel ──────────────────────────────────────────────────────────────────

/// The Sentinel manages the guard state and wires snooze into the decision
/// engine.
///
/// All state transitions go through here.  Wrap in `Arc` to share across tasks.
pub struct Sentinel {
    pub(crate) state_tx: tokio_watch::Sender<GuardState>,
    /// Internal receiver that keeps the channel alive.
    _self_rx: tokio_watch::Receiver<GuardState>,
    engine: Arc<DecisionEngine>,
}

impl Sentinel {
    /// Construct a new Sentinel in [`GuardState::Filtering`] state.
    pub fn new(engine: Arc<DecisionEngine>) -> (Self, tokio_watch::Receiver<GuardState>) {
        let (tx, rx) = tokio_watch::channel(GuardState::Filtering);
        let self_rx = tx.subscribe();
        let external_rx = rx;
        (
            Self {
                state_tx: tx,
                _self_rx: self_rx,
                engine,
            },
            external_rx,
        )
    }

    /// Snooze filtering for `duration`.
    pub fn snooze(&self, duration: Duration) {
        let now_ms = unix_ms_now();
        let until_ms = now_ms.saturating_add(duration.as_millis() as u64);
        self.engine.snooze_until(until_ms);
        let _ = self.state_tx.send(GuardState::Snoozed {
            until_unix_ms: until_ms,
        });
    }

    /// Resume filtering immediately (cancel any active snooze).
    pub fn resume(&self) {
        self.engine.snooze_until(0);
        let _ = self.state_tx.send(GuardState::Filtering);
    }

    /// Set the guard state to [`GuardState::StandingBy`].
    pub fn set_standing_by(&self, why: StandbyReason) {
        let _ = self.state_tx.send(GuardState::StandingBy { why });
    }

    /// Set the guard state to [`GuardState::Filtering`].
    pub fn set_filtering(&self) {
        let _ = self.state_tx.send(GuardState::Filtering);
    }

    /// Set the guard state to [`GuardState::Attention`].
    pub fn set_attention(&self, why: impl Into<String>) {
        let _ = self
            .state_tx
            .send(GuardState::Attention { why: why.into() });
    }

    /// Return a cloned receiver for the current guard state.
    pub fn state(&self) -> tokio_watch::Receiver<GuardState> {
        self.state_tx.subscribe()
    }

    /// Read the current guard state without subscribing.
    pub fn current_state(&self) -> GuardState {
        self.state_tx.borrow().clone()
    }

    /// Map the current state to the API string.
    ///
    /// Returns a `(state, standby_reason)` tuple for embedding in `/v0/status`.
    pub fn state_api(&self) -> (String, Option<String>) {
        match self.current_state() {
            GuardState::Filtering => ("filtering".to_owned(), None),
            GuardState::Snoozed { .. } => ("snoozed".to_owned(), None),
            GuardState::StandingBy { why } => (
                "standing_by".to_owned(),
                Some(standby_reason_to_string(&why)),
            ),
            GuardState::Attention { .. } => ("attention".to_owned(), None),
        }
    }
}

/// Map a [`StandbyReason`] to a user-facing string.
fn standby_reason_to_string(why: &StandbyReason) -> String {
    match why {
        StandbyReason::Initialising => "initialising".to_owned(),
        StandbyReason::AllUpstreamsDown => "all_upstreams_down".to_owned(),
        StandbyReason::Portal => "portal".to_owned(),
        StandbyReason::VpnActive => "vpn".to_owned(),
        StandbyReason::UserDns => "user_dns".to_owned(),
    }
}

/// Best-effort current Unix time in milliseconds.
pub fn unix_ms_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use hush_core::DecisionEngine;

    fn make_sentinel() -> (Sentinel, tokio_watch::Receiver<GuardState>) {
        let engine = Arc::new(DecisionEngine::new());
        Sentinel::new(engine)
    }

    // ── Initial state ─────────────────────────────────────────────────────────

    #[test]
    fn initial_state_is_filtering() {
        let (s, rx) = make_sentinel();
        assert_eq!(*rx.borrow(), GuardState::Filtering);
        assert_eq!(s.current_state(), GuardState::Filtering);
    }

    // ── Snooze ────────────────────────────────────────────────────────────────

    #[test]
    fn snooze_transitions_to_snoozed() {
        let (s, _rx) = make_sentinel();
        s.snooze(Duration::from_secs(60));
        match s.current_state() {
            GuardState::Snoozed { until_unix_ms } => {
                assert!(until_unix_ms > 0);
            }
            other => panic!("expected Snoozed, got {other:?}"),
        }
    }

    #[test]
    fn snooze_arms_engine() {
        let engine = Arc::new(DecisionEngine::new());
        let (s, _rx) = Sentinel::new(Arc::clone(&engine));
        s.snooze(Duration::from_secs(3600));
        assert!(engine.snoozed(unix_ms_now()));
    }

    // ── Resume ────────────────────────────────────────────────────────────────

    #[test]
    fn resume_transitions_to_filtering() {
        let engine = Arc::new(DecisionEngine::new());
        let (s, rx) = Sentinel::new(Arc::clone(&engine));
        s.snooze(Duration::from_secs(60));
        s.resume();
        assert_eq!(*rx.borrow(), GuardState::Filtering);
        assert!(!engine.snoozed(unix_ms_now()));
    }

    // ── StandingBy ────────────────────────────────────────────────────────────

    #[test]
    fn set_standing_by() {
        let (s, _rx) = make_sentinel();
        s.set_standing_by(StandbyReason::AllUpstreamsDown);
        match s.current_state() {
            GuardState::StandingBy { why } => {
                assert_eq!(why, StandbyReason::AllUpstreamsDown);
            }
            other => panic!("expected StandingBy, got {other:?}"),
        }
    }

    #[test]
    fn set_filtering_after_standing_by() {
        let (s, rx) = make_sentinel();
        s.set_standing_by(StandbyReason::Initialising);
        s.set_filtering();
        assert_eq!(*rx.borrow(), GuardState::Filtering);
    }

    // ── Attention ─────────────────────────────────────────────────────────────

    #[test]
    fn set_attention() {
        let (s, _rx) = make_sentinel();
        s.set_attention("crash loop");
        match s.current_state() {
            GuardState::Attention { why } => assert_eq!(why, "crash loop"),
            other => panic!("expected Attention, got {other:?}"),
        }
    }

    // ── state_api ─────────────────────────────────────────────────────────────

    #[test]
    fn state_api_filtering() {
        let (s, _) = make_sentinel();
        let (state, reason) = s.state_api();
        assert_eq!(state, "filtering");
        assert_eq!(reason, None);
    }

    #[test]
    fn state_api_standing_by_vpn() {
        let (s, _) = make_sentinel();
        s.set_standing_by(StandbyReason::VpnActive);
        let (state, reason) = s.state_api();
        assert_eq!(state, "standing_by");
        assert_eq!(reason, Some("vpn".to_owned()));
    }

    #[test]
    fn state_api_standing_by_portal() {
        let (s, _) = make_sentinel();
        s.set_standing_by(StandbyReason::Portal);
        let (state, reason) = s.state_api();
        assert_eq!(state, "standing_by");
        assert_eq!(reason, Some("portal".to_owned()));
    }

    #[test]
    fn state_api_standing_by_user_dns() {
        let (s, _) = make_sentinel();
        s.set_standing_by(StandbyReason::UserDns);
        let (state, reason) = s.state_api();
        assert_eq!(state, "standing_by");
        assert_eq!(reason, Some("user_dns".to_owned()));
    }
}
