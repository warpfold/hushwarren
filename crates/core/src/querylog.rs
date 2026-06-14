//! Query log types and in-memory ring buffer.
//!
//! Implements `specs/wp1-core.md` §6 and `specs/wp4-privacy.md` §3.4.
//! The [`QueryRing`] is the in-process store for the live dashboard view;
//! the daemon's SQLite rolling log is built on top of these types in WP2.
//!
//! ## WP4: query-log privacy modes
//!
//! `QueryRing` is constructed with a `QueryLogMode`:
//! - `Full` (default): qname + verdict + reason stored as-is.
//! - `Anonymous`: `qname` is replaced with `"<redacted>"` before storing.
//!   Counters and verdict/reason are still incremented.
//! - `Off`: counters increment; the ring buffer is never written.
//!
//! ## WP13: `client` field
//!
//! [`QueryRecord`] gains `client: Option<IpAddr>` (additive serde — absent in
//! old serialised records, deserialises as `None`).  The field is populated
//! **only** when:
//! 1. The query arrived on a Network Guard listener (not the loopback path), AND
//! 2. `network_guard.log_clients = true`.
//!
//! Loopback queries always produce `client = None` — there is only one client
//! in Local Guard mode.
//!
//! **Privacy interaction with `anonymous` mode:** `anonymous` redacts qnames
//! but deliberately preserves `client` — per-device counters are the point of
//! `log_clients`.  Turning on `log_clients` with `anonymous` gives you
//! per-device counts without recording what each device browsed.
//! `off` mode stores nothing, as always.
//!
//! # Threading contract
//!
//! [`QueryRing::push`] is called from the DNS hot path (many tokio workers).
//! We use a `std::sync::Mutex` — not a tokio mutex — because:
//!   - The critical section is a handful of `Vec` / counter operations: O(1),
//!     nanoseconds in practice.
//!   - No `.await` occurs inside the lock, so there is no risk of holding a
//!     mutex guard across a suspension point (which would block the executor).
//!   - `tokio::sync::Mutex` adds overhead and is only necessary when a lock
//!     *must* be held across `.await`.
//!
//! This choice is documented here as the authoritative rationale.

use crate::config::QueryLogMode;
use crate::decision::{Reason, Verdict};
use std::net::IpAddr;
use std::sync::Mutex;

/// Redaction placeholder used in [`QueryLogMode::Anonymous`] mode.
///
/// Both the in-memory ring and the SQLite rollup writer MUST use this constant
/// so the string is consistent across all storage layers.
pub const REDACTED_QNAME: &str = "<redacted>";

/// A single resolved DNS query and its disposition.
#[derive(Debug, Clone)]
pub struct QueryRecord {
    /// Unix timestamp of the query in milliseconds.
    pub ts_unix_ms: u64,
    /// The queried domain name (forward form, no trailing dot).
    pub qname: String,
    /// DNS query type (e.g., 1 = A, 28 = AAAA, 5 = CNAME).
    pub qtype: u16,
    /// Decision engine verdict.
    pub verdict: Verdict,
    /// Why the verdict was produced.
    pub reason: Reason,
    /// How long the upstream round-trip took in milliseconds.
    /// `None` for blocked queries (no upstream consulted).
    pub upstream_ms: Option<u32>,
    /// Source IP of the DNS client.
    ///
    /// Populated **only** when all three conditions are met:
    /// 1. The query arrived on a Network Guard listener (LAN, not loopback).
    /// 2. `network_guard.log_clients = true`.
    /// 3. `privacy.query_log` is not `off` (nothing stored in off mode).
    ///
    /// Loopback (Local Guard) queries always produce `None`.
    /// `anonymous` mode preserves client IPs — see module-level doc for the
    /// privacy interaction.
    pub client: Option<IpAddr>,
}

/// Aggregate statistics from a [`QueryRing`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingStats {
    /// Total queries pushed since the ring was created (saturating).
    pub total: u64,
    /// Queries with `Verdict::Block` since the ring was created (saturating).
    pub blocked: u64,
    /// Unix timestamp (ms) of the oldest record currently in the ring.
    /// `0` if the ring is empty.
    pub since_unix_ms: u64,
}

/// Ring-buffer inner state, protected by a `Mutex`.
struct RingInner {
    /// Fixed-capacity circular buffer.
    buf: Vec<QueryRecord>,
    /// Write-head index (next slot to overwrite).
    head: usize,
    /// True once the buffer has wrapped around at least once.
    full: bool,
    /// Saturating total-query counter.
    total: u64,
    /// Saturating blocked-query counter.
    blocked: u64,
}

/// Fixed-capacity overwrite-oldest ring buffer for query records.
///
/// Push from the DNS path is O(1) and never blocks queries.
/// See module-level doc for the threading rationale and WP4 mode semantics.
pub struct QueryRing {
    inner: Mutex<RingInner>,
    capacity: usize,
    /// Controls how records are stored (see `specs/wp4-privacy.md` §3.4).
    mode: QueryLogMode,
}

impl QueryRing {
    /// Create a new ring with the given `capacity` and `Full` log mode.
    ///
    /// # Panics
    ///
    /// Panics if `capacity == 0`.  In production the daemon always passes a
    /// positive value derived from validated config.
    pub fn new(capacity: usize) -> Self {
        Self::with_mode(capacity, QueryLogMode::Full)
    }

    /// Create a new ring with the given `capacity` and log `mode`.
    ///
    /// # Panics
    ///
    /// Panics if `capacity == 0`.
    pub fn with_mode(capacity: usize, mode: QueryLogMode) -> Self {
        assert!(capacity > 0, "QueryRing capacity must be > 0");
        Self {
            inner: Mutex::new(RingInner {
                buf: Vec::with_capacity(capacity),
                head: 0,
                full: false,
                total: 0,
                blocked: 0,
            }),
            capacity,
            mode,
        }
    }

    /// The current log mode.
    pub fn mode(&self) -> QueryLogMode {
        self.mode
    }

    /// Push a record into the ring, applying the configured log mode.
    ///
    /// - `Full`: stored verbatim.
    /// - `Anonymous`: `qname` replaced with `"<redacted>"` before storing.
    /// - `Off`: counters are incremented; the record is NOT stored in the ring.
    ///
    /// O(1).  Acquires the inner mutex for the duration of the write only.
    pub fn push(&self, r: QueryRecord) {
        // Mutex poison: if a previous thread panicked while holding the lock,
        // we recover and continue — a poisoned ring is better than a crash.
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        inner.total = inner.total.saturating_add(1);
        if r.verdict == Verdict::Block {
            inner.blocked = inner.blocked.saturating_add(1);
        }

        // `Off` mode: count only, do not store.
        if self.mode == QueryLogMode::Off {
            return;
        }

        // `Anonymous` mode: redact the qname before storing.
        let r = if self.mode == QueryLogMode::Anonymous {
            QueryRecord {
                qname: REDACTED_QNAME.to_owned(),
                ..r
            }
        } else {
            r
        };

        if inner.buf.len() < self.capacity {
            inner.buf.push(r);
        } else {
            let head = inner.head;
            inner.buf[head] = r;
        }
        inner.head = (inner.head + 1) % self.capacity;
        if inner.head == 0 {
            inner.full = true;
        }
    }

    /// Return up to `n` most-recent records, newest first.
    pub fn recent(&self, n: usize) -> Vec<QueryRecord> {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        self.drain_newest(&inner, n, |_| true)
    }

    /// Return up to `n` most-recent blocked records, newest first.
    pub fn recent_blocked(&self, n: usize) -> Vec<QueryRecord> {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        self.drain_newest(&inner, n, |r: &QueryRecord| r.verdict == Verdict::Block)
    }

    /// Return aggregate statistics.
    pub fn stats(&self) -> RingStats {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        let since_unix_ms = if inner.buf.is_empty() {
            0
        } else {
            // The oldest record is at `head` when full, or at index 0 otherwise.
            let oldest_idx = if inner.full { inner.head } else { 0 };
            inner.buf[oldest_idx].ts_unix_ms
        };

        RingStats {
            total: inner.total,
            blocked: inner.blocked,
            since_unix_ms,
        }
    }

    /// Internal helper: collect up to `n` records matching `predicate`,
    /// walking from the newest toward the oldest.
    fn drain_newest(
        &self,
        inner: &RingInner,
        n: usize,
        predicate: impl Fn(&QueryRecord) -> bool,
    ) -> Vec<QueryRecord> {
        if inner.buf.is_empty() || n == 0 {
            return Vec::new();
        }

        let len = inner.buf.len();
        // Walk backward from the slot just before `head`.
        // When not full, the last-inserted is at `head - 1` (or `len - 1`).
        // When full, same formula but wraps.
        let mut result = Vec::with_capacity(n.min(len));
        let mut i = 0usize;
        while i < len && result.len() < n {
            // newest slot is (head + len - 1) % len, then decreasing
            let idx = (inner.head + len - 1 - i) % len;
            let rec = &inner.buf[idx];
            if predicate(rec) {
                result.push(rec.clone());
            }
            i += 1;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use std::sync::Arc;
    use std::thread;

    fn make_record(ts: u64, verdict: Verdict) -> QueryRecord {
        QueryRecord {
            ts_unix_ms: ts,
            qname: "test.example.com".to_string(),
            qtype: 1,
            verdict,
            reason: Reason::NoMatch,
            upstream_ms: None,
            client: None,
        }
    }

    // ── Wraparound at capacity ────────────────────────────────────────────────

    #[test]
    fn wraparound_overwrites_oldest() {
        let ring = QueryRing::new(3);
        ring.push(make_record(1, Verdict::Forward));
        ring.push(make_record(2, Verdict::Forward));
        ring.push(make_record(3, Verdict::Forward));
        ring.push(make_record(4, Verdict::Forward)); // overwrites ts=1

        let recent = ring.recent(10);
        assert_eq!(recent.len(), 3, "ring holds exactly capacity records");

        // Newest first: 4, 3, 2.
        assert_eq!(recent[0].ts_unix_ms, 4);
        assert_eq!(recent[1].ts_unix_ms, 3);
        assert_eq!(recent[2].ts_unix_ms, 2);
    }

    // ── recent(n) ordering ────────────────────────────────────────────────────

    #[test]
    fn recent_ordering_newest_first() {
        let ring = QueryRing::new(10);
        for ts in 1..=5 {
            ring.push(make_record(ts, Verdict::Forward));
        }
        let recent = ring.recent(3);
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].ts_unix_ms, 5);
        assert_eq!(recent[1].ts_unix_ms, 4);
        assert_eq!(recent[2].ts_unix_ms, 3);
    }

    #[test]
    fn recent_blocked_filters_correctly() {
        let ring = QueryRing::new(10);
        ring.push(make_record(1, Verdict::Forward));
        ring.push(make_record(2, Verdict::Block));
        ring.push(make_record(3, Verdict::Forward));
        ring.push(make_record(4, Verdict::Block));

        let blocked = ring.recent_blocked(10);
        assert_eq!(blocked.len(), 2);
        assert!(blocked.iter().all(|r| r.verdict == Verdict::Block));
        // Newest first.
        assert_eq!(blocked[0].ts_unix_ms, 4);
        assert_eq!(blocked[1].ts_unix_ms, 2);
    }

    // ── Stats counters ────────────────────────────────────────────────────────

    #[test]
    fn stats_counters() {
        let ring = QueryRing::new(100);
        ring.push(make_record(10, Verdict::Forward));
        ring.push(make_record(20, Verdict::Block));
        ring.push(make_record(30, Verdict::Block));

        let stats = ring.stats();
        assert_eq!(stats.total, 3);
        assert_eq!(stats.blocked, 2);
        assert_eq!(stats.since_unix_ms, 10, "oldest = first pushed");
    }

    #[test]
    fn stats_since_tracks_oldest_after_wraparound() {
        let ring = QueryRing::new(3);
        ring.push(make_record(10, Verdict::Forward));
        ring.push(make_record(20, Verdict::Forward));
        ring.push(make_record(30, Verdict::Forward));
        // Push ts=40 overwrites ts=10 (oldest slot).
        ring.push(make_record(40, Verdict::Forward));

        let stats = ring.stats();
        assert_eq!(stats.total, 4);
        assert_eq!(stats.since_unix_ms, 20, "oldest after wrap = ts=20");
    }

    #[test]
    fn stats_empty_ring() {
        let ring = QueryRing::new(10);
        let stats = ring.stats();
        assert_eq!(stats.total, 0);
        assert_eq!(stats.blocked, 0);
        assert_eq!(stats.since_unix_ms, 0);
    }

    // ── Push-from-8-threads smoke ─────────────────────────────────────────────

    #[test]
    fn push_from_8_threads_no_data_race() {
        let ring = Arc::new(QueryRing::new(1024));
        let handles: Vec<_> = (0..8)
            .map(|t| {
                let r = Arc::clone(&ring);
                thread::spawn(move || {
                    for i in 0u64..200 {
                        r.push(make_record(t * 200 + i, Verdict::Forward));
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let stats = ring.stats();
        // 8 threads × 200 pushes = 1600 total.
        assert_eq!(stats.total, 1600, "all pushes must be counted");
        // Ring holds at most capacity entries.
        assert!(ring.recent(10000).len() <= 1024);
    }

    // ── WP4: query_log mode = Anonymous ──────────────────────────────────────

    #[test]
    fn anonymous_mode_redacts_qname() {
        use crate::config::QueryLogMode;
        let ring = QueryRing::with_mode(10, QueryLogMode::Anonymous);
        ring.push(QueryRecord {
            ts_unix_ms: 1,
            qname: "secret.example.com".to_string(),
            qtype: 1,
            verdict: Verdict::Forward,
            reason: Reason::NoMatch,
            upstream_ms: None,
            client: None,
        });
        let records = ring.recent(10);
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].qname, "<redacted>",
            "anonymous mode must redact qname"
        );
        // Counters still increment.
        assert_eq!(ring.stats().total, 1);
    }

    #[test]
    fn anonymous_mode_preserves_verdict_and_reason() {
        use crate::config::QueryLogMode;
        let ring = QueryRing::with_mode(10, QueryLogMode::Anonymous);
        ring.push(QueryRecord {
            ts_unix_ms: 2,
            qname: "ads.evil.com".to_string(),
            qtype: 1,
            verdict: Verdict::Block,
            reason: Reason::ListBlocked,
            upstream_ms: None,
            client: None,
        });
        let records = ring.recent(10);
        assert_eq!(records[0].verdict, Verdict::Block);
        assert_eq!(records[0].reason, Reason::ListBlocked);
    }

    // ── WP4: query_log mode = Off ─────────────────────────────────────────────

    #[test]
    fn off_mode_ring_stays_empty() {
        use crate::config::QueryLogMode;
        let ring = QueryRing::with_mode(10, QueryLogMode::Off);
        ring.push(make_record(1, Verdict::Forward));
        ring.push(make_record(2, Verdict::Block));
        ring.push(make_record(3, Verdict::Forward));

        let records = ring.recent(10);
        assert!(
            records.is_empty(),
            "off mode must not write records to ring"
        );
    }

    #[test]
    fn off_mode_counters_still_advance() {
        use crate::config::QueryLogMode;
        let ring = QueryRing::with_mode(100, QueryLogMode::Off);
        ring.push(make_record(1, Verdict::Forward));
        ring.push(make_record(2, Verdict::Block));
        ring.push(make_record(3, Verdict::Block));

        let stats = ring.stats();
        assert_eq!(stats.total, 3, "off mode must still count total queries");
        assert_eq!(
            stats.blocked, 2,
            "off mode must still count blocked queries"
        );
    }

    // ── WP4: CnameCloaked reason survives ring push/read cycle ────────────────

    #[test]
    fn cname_cloaked_reason_roundtrip() {
        let ring = QueryRing::new(10);
        ring.push(QueryRecord {
            ts_unix_ms: 5,
            qname: "shop.example.com".to_string(),
            qtype: 1,
            verdict: Verdict::Block,
            reason: Reason::CnameCloaked {
                hop: "track.evil.test".to_string(),
            },
            upstream_ms: None,
            client: None,
        });
        let records = ring.recent(10);
        assert_eq!(records.len(), 1);
        match &records[0].reason {
            Reason::CnameCloaked { hop } => {
                assert_eq!(hop, "track.evil.test");
            }
            r => panic!("expected CnameCloaked, got: {r:?}"),
        }
    }

    #[test]
    fn anonymous_mode_redacts_cname_cloaked_hop() {
        use crate::config::QueryLogMode;
        let ring = QueryRing::with_mode(10, QueryLogMode::Anonymous);
        ring.push(QueryRecord {
            ts_unix_ms: 6,
            qname: "shop.example.com".to_string(),
            qtype: 1,
            verdict: Verdict::Block,
            reason: Reason::CnameCloaked {
                hop: "track.evil.test".to_string(),
            },
            upstream_ms: None,
            client: None,
        });
        let records = ring.recent(10);
        assert_eq!(records[0].qname, "<redacted>", "qname must be redacted");
        // Reason itself is not redacted (verdict/reason are retained for stats).
        // The hop name is NOT a user-private datum (it's from the blocklist) —
        // only the queried qname is private.
    }

    // ── WP13: client field serde round-trip ───────────────────────────────────

    #[test]
    fn client_field_none_by_default() {
        let ring = QueryRing::new(10);
        ring.push(make_record(1, Verdict::Forward));
        let records = ring.recent(10);
        assert_eq!(records[0].client, None, "client must default to None");
    }

    #[test]
    fn client_field_some_lan_ip_preserved() {
        let lan_ip: IpAddr = "192.168.1.42".parse().unwrap();
        let ring = QueryRing::new(10);
        ring.push(QueryRecord {
            ts_unix_ms: 1,
            qname: "example.com".to_string(),
            qtype: 1,
            verdict: Verdict::Forward,
            reason: Reason::NoMatch,
            upstream_ms: None,
            client: Some(lan_ip),
        });
        let records = ring.recent(10);
        assert_eq!(
            records[0].client,
            Some(lan_ip),
            "client IP must be preserved in the ring"
        );
    }

    #[test]
    fn anonymous_mode_preserves_client_ip() {
        // anonymous redacts qnames but KEEPS client IPs (per-device counters
        // are the point of log_clients — see module-level doc).
        use crate::config::QueryLogMode;
        let lan_ip: IpAddr = "10.0.0.5".parse().unwrap();
        let ring = QueryRing::with_mode(10, QueryLogMode::Anonymous);
        ring.push(QueryRecord {
            ts_unix_ms: 1,
            qname: "secret.corp.example.com".to_string(),
            qtype: 1,
            verdict: Verdict::Block,
            reason: Reason::ListBlocked,
            upstream_ms: None,
            client: Some(lan_ip),
        });
        let records = ring.recent(10);
        assert_eq!(
            records[0].qname, "<redacted>",
            "anonymous mode must redact qname"
        );
        assert_eq!(
            records[0].client,
            Some(lan_ip),
            "anonymous mode must preserve client IP"
        );
    }
}
