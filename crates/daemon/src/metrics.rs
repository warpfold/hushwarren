//! Daemon-wide counters exposed via the control API (WP3).
//!
//! Implements `specs/wp2-daemon.md` §6 observability counters.  All counters
//! are `AtomicU64`; incrementing is lock-free and cheap on the hot path.
//! The struct is wrapped in `Arc` and shared across tasks.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// All daemon-wide counters.
///
/// Exposed read-only to WP3's control API.  Writable only through the
/// increment helpers below, which enforce the Relaxed-ordering contract:
/// counters are advisory/diagnostic, not synchronisation primitives.
// WP3-seam: `local_total`, `snapshot()`, and `MetricsSnapshot` are consumed
// by the control API; `inc_local` is called from the ForwardLocal DNS path
// (WP3 wires that verdict).
#[allow(dead_code)]
pub struct Metrics {
    /// Total DNS queries received (all outcomes).
    pub queries_total: AtomicU64,
    /// Queries answered with a sinkhole response.
    pub blocked_total: AtomicU64,
    /// Queries forwarded to the upstream ladder (DoH / Do53).
    pub forwarded_total: AtomicU64,
    /// Queries forwarded to the local/DHCP resolver (`ForwardLocal` verdict).
    pub local_total: AtomicU64,
    /// Queries that ended with SERVFAIL (all upstreams exhausted or transport
    /// error — distinct from upstream SERVFAIL pass-through).
    pub servfail_total: AtomicU64,
    /// Malformed UDP datagrams received (garbage, truncated, etc.).
    pub malformed_total: AtomicU64,
    /// Current active ladder rung (0 = primary DoH; increases on failover).
    pub upstream_rung_current: AtomicUsize,
}

// WP3-seam: all methods are either called on the hot DNS path or by the
// control API.  `inc_local` / `snapshot` are consumed in WP3.
#[allow(dead_code)]
impl Metrics {
    /// Construct a zero-initialised metrics set.
    pub fn new() -> Self {
        Self {
            queries_total: AtomicU64::new(0),
            blocked_total: AtomicU64::new(0),
            forwarded_total: AtomicU64::new(0),
            local_total: AtomicU64::new(0),
            servfail_total: AtomicU64::new(0),
            malformed_total: AtomicU64::new(0),
            upstream_rung_current: AtomicUsize::new(0),
        }
    }

    /// Increment `queries_total` by one.
    #[inline]
    pub fn inc_queries(&self) {
        self.queries_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment `blocked_total` by one.
    #[inline]
    pub fn inc_blocked(&self) {
        self.blocked_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment `forwarded_total` by one.
    #[inline]
    pub fn inc_forwarded(&self) {
        self.forwarded_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment `local_total` by one.
    #[inline]
    pub fn inc_local(&self) {
        self.local_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment `servfail_total` by one.
    #[inline]
    pub fn inc_servfail(&self) {
        self.servfail_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment `malformed_total` by one.
    #[inline]
    pub fn inc_malformed(&self) {
        self.malformed_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Return a point-in-time snapshot of every counter.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            queries_total: self.queries_total.load(Ordering::Relaxed),
            blocked_total: self.blocked_total.load(Ordering::Relaxed),
            forwarded_total: self.forwarded_total.load(Ordering::Relaxed),
            local_total: self.local_total.load(Ordering::Relaxed),
            servfail_total: self.servfail_total.load(Ordering::Relaxed),
            malformed_total: self.malformed_total.load(Ordering::Relaxed),
            upstream_rung_current: self.upstream_rung_current.load(Ordering::Relaxed),
        }
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Point-in-time snapshot of [`Metrics`], suitable for serialisation.
// WP3-seam: serialised and returned by the control API `GET /metrics`.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricsSnapshot {
    /// See [`Metrics::queries_total`].
    pub queries_total: u64,
    /// See [`Metrics::blocked_total`].
    pub blocked_total: u64,
    /// See [`Metrics::forwarded_total`].
    pub forwarded_total: u64,
    /// See [`Metrics::local_total`].
    pub local_total: u64,
    /// See [`Metrics::servfail_total`].
    pub servfail_total: u64,
    /// See [`Metrics::malformed_total`].
    pub malformed_total: u64,
    /// See [`Metrics::upstream_rung_current`].
    pub upstream_rung_current: usize,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn zero_on_construction() {
        let m = Metrics::new();
        let s = m.snapshot();
        assert_eq!(s.queries_total, 0);
        assert_eq!(s.blocked_total, 0);
        assert_eq!(s.forwarded_total, 0);
        assert_eq!(s.local_total, 0);
        assert_eq!(s.servfail_total, 0);
        assert_eq!(s.malformed_total, 0);
        assert_eq!(s.upstream_rung_current, 0);
    }

    #[test]
    fn increments_independent() {
        let m = Metrics::new();
        m.inc_queries();
        m.inc_queries();
        m.inc_blocked();
        m.inc_forwarded();
        m.inc_local();
        m.inc_servfail();
        m.inc_malformed();

        let s = m.snapshot();
        assert_eq!(s.queries_total, 2);
        assert_eq!(s.blocked_total, 1);
        assert_eq!(s.forwarded_total, 1);
        assert_eq!(s.local_total, 1);
        assert_eq!(s.servfail_total, 1);
        assert_eq!(s.malformed_total, 1);
    }
}
