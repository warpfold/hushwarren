//! Per-query verdict engine.
//!
//! Implements `docs/architecture.md` §5 decision ladder and
//! `specs/wp1-core.md` §4.  This is the hot path: `decide` is called
//! concurrently from many tokio workers.  It takes `&self`, never blocks,
//! and sees rule swaps atomically via `ArcSwap::load`.
//!
//! Precedence ladder (exactly this order — it is the product contract):
//! 1. Snooze → `(Forward, Snoozed)`
//! 2. Local name → `(ForwardLocal, LocalName)`
//! 3. User allow → `(Forward, UserAllowed)`
//! 4. List allow → `(Forward, ListAllowed)`; list block → `(Block, ListBlocked)`
//! 5. No match → `(Forward, NoMatch)`

use crate::domain::Domain;
use crate::rules::{CompiledRules, RuleMatch};
use arc_swap::ArcSwap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// The verdict produced for one DNS query.
///
/// Returned by [`DecisionEngine::decide`]; the daemon maps it to wire
/// responses (see `docs/architecture.md` §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Sinkhole: answer `0.0.0.0` / `::` with a short TTL.
    Block,
    /// Forward to the upstream DoH/Do53 ladder.
    Forward,
    /// Forward to the DHCP-provided resolver only (local names: single-label
    /// or suffix in the local-TLD set — printers, NAS, etc. must keep working).
    ForwardLocal,
}

/// Why the decision engine produced a particular [`Verdict`].
///
/// ## WP4 additions
///
/// `BrowserDohCanary`, `PrivateRelayBlocked`, `PrivateRelayProtected`, and
/// `CnameCloaked` are new in WP4.  These are produced by protocol-level checks
/// in `dns.rs` **before** the decision ladder — they are not list logic.
///
/// When adding a new variant here, also update:
/// - `daemon/src/api/routes.rs` → `reason_to_string`
/// - `cli/src/types.rs` (no change needed — CLI treats reason as `String`)
/// - All exhaustive `match` arms in daemon code
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// Global snooze is active (time-limited pass-through).
    Snoozed,
    /// Domain is a local name (single label or local TLD) — never blocked.
    LocalName,
    /// User one-click allow matched the domain.
    UserAllowed,
    /// List allow (exception) rule matched.
    ListAllowed,
    /// List block rule matched.
    ListBlocked,
    /// No rule matched; passed through to upstream.
    NoMatch,
    /// **WP4 §3.1** — Firefox browser-DoH canary domain (`use-application-dns.net`)
    /// was answered with NXDOMAIN to suppress Firefox's built-in DoH.
    BrowserDohCanary,
    /// **WP4 §3.2** — `block_private_relay=true`: responded NODATA to disable
    /// iCloud Private Relay per Apple's documented mechanism.
    PrivateRelayBlocked,
    /// **WP4 §3.2** — `block_private_relay=false` (default): Private Relay
    /// domains were force-allowed even though a blocklist would have matched.
    PrivateRelayProtected,
    /// **WP4 §3.3** — CNAME-cloaking inspection found a blocked intermediate
    /// CNAME hop.  `hop` records the offending target name.
    CnameCloaked {
        /// The CNAME target that matched a block rule.
        hop: String,
    },
    /// **WP8 §4** — DNS rebinding protection blocked an answer that contained
    /// a private/loopback/link-local address for a public query name.
    /// `addr` records the offending address (redacted in anonymous query-log
    /// mode, just like `CnameCloaked::hop`).
    RebindBlocked {
        /// The private address that triggered the block.
        addr: String,
    },
}

// Manually derive Copy for non-CnameCloaked variants is not possible since
// CnameCloaked contains String.  The type is Clone only.
// All code that previously used Copy semantics on Reason must instead use
// .clone() or match by reference.  The decision hot-path uses `&Domain`
// already so this has no performance impact.

/// The compiled-in domain that the Sentinel's SELF-TEST resolves to verify that
/// the decision engine is blocking.
///
/// This domain is **always** sinkholes regardless of user allows or list state.
/// It must be queried through the daemon's own listener during the takeover
/// SELF-TEST step and return `0.0.0.0`; if it resolves to anything else the
/// SELF-TEST fails and the takeover is aborted.
///
/// See `specs/wp5-sentinel-macos.md` §2 and `docs/zero-touch-ux.md` §1.
pub const SELFTEST_BLOCKED_DOMAIN: &str = "hushwarren-selftest-blocked.invalid";

/// Local TLDs whose names must always be forwarded to the DHCP resolver, never
/// blocked.  Single-label names are also local regardless of this list.
///
/// Invariant: checked BEFORE user-allow and list rules so that blocking `.lan`
/// entries that sometimes appear in third-party lists never takes down printers.
static LOCAL_TLDS: &[&str] = &[
    "local",
    "localdomain",
    "lan",
    "home",
    "internal",
    "home.arpa",
    "arpa",
];

/// The set of domains the user has one-click-allowed.
///
/// Sorted `Vec<String>` of reversed-label keys; suffix matching via binary
/// search.  User-allowed sets are small (≤ hundreds of entries), so a linear
/// structure with binary search is adequate — no fst overhead.
#[derive(Debug, Default, Clone)]
pub struct UserAllowSet {
    /// Reversed-label keys, sorted for binary-search suffix lookup.
    keys: Vec<String>,
}

impl UserAllowSet {
    /// Build from a list of domains.  The set deduplicates and sorts
    /// automatically.
    pub fn from_domains(domains: Vec<Domain>) -> Self {
        let mut keys: Vec<String> = domains.iter().map(|d| d.reversed()).collect();
        keys.sort_unstable();
        keys.dedup();
        Self { keys }
    }

    /// Returns `true` if `d` or any of its ancestors is in this set.
    pub fn contains(&self, d: &Domain) -> bool {
        let mut buf = String::with_capacity(d.as_str().len());
        for ancestor in d.self_and_ancestors() {
            reverse_into(ancestor, &mut buf);
            if self.keys.binary_search(&buf).is_ok() {
                return true;
            }
        }
        false
    }

    /// Serialize to a newline-delimited list of domain strings (forward form,
    /// not reversed).  The daemon persists this as a plain text file (WP3).
    pub fn to_lines(&self) -> String {
        // Convert reversed keys back to forward form for human-readable storage.
        self.keys
            .iter()
            .map(|rev| {
                let mut labels: Vec<&str> = rev.split('.').collect();
                labels.reverse();
                labels.join(".")
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Number of entries in the set.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Returns `true` if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// The central decision engine.
///
/// Thread-safe by construction: all mutable state is either `AtomicU64` or
/// behind `ArcSwap`.  `decide` takes `&self` and never holds a lock across
/// any suspension point.
pub struct DecisionEngine {
    /// List-sourced compiled rules; swapped atomically on list refresh.
    rules: ArcSwap<CompiledRules>,
    /// One-click user allows; small, swapped atomically.
    user_allow: ArcSwap<UserAllowSet>,
    /// Unix timestamp (ms) until which snooze is active; 0 = not snoozed.
    snooze_until_unix_ms: AtomicU64,
}

impl DecisionEngine {
    /// Create a new engine with empty rules and no snooze.
    pub fn new() -> Self {
        Self {
            rules: ArcSwap::from_pointee(CompiledRules::empty()),
            user_allow: ArcSwap::from_pointee(UserAllowSet::default()),
            snooze_until_unix_ms: AtomicU64::new(0),
        }
    }

    /// Produce a verdict for a single DNS query.
    ///
    /// # Precedence ladder
    ///
    /// 1. **Snooze** — global pause; all queries forwarded.
    /// 2. **Local name** — single-label or suffix in [`LOCAL_TLDS`]; forward
    ///    to DHCP resolver.  Checked before allow/block so that blocklisted
    ///    `.lan` garbage never breaks printers.
    /// 3. **User allow** — suffix-scoped, like rules; explicit user override.
    /// 4. **List rules** — `CompiledRules::match_domain`; allow beats block.
    /// 5. **No match** — forward to upstream.
    pub fn decide(&self, d: &Domain, now_unix_ms: u64) -> (Verdict, Reason) {
        // 0. Built-in always-block: Sentinel SELF-TEST domain.
        //    This rule is unconditional — it fires even while snoozed so that
        //    the SELF-TEST can verify the decision engine is reachable.
        if d.as_str() == SELFTEST_BLOCKED_DOMAIN {
            return (Verdict::Block, Reason::ListBlocked);
        }

        // 1. Snooze
        if self.snoozed(now_unix_ms) {
            return (Verdict::Forward, Reason::Snoozed);
        }

        // 2. Local name
        if is_local_name(d) {
            return (Verdict::ForwardLocal, Reason::LocalName);
        }

        // 3. User allow
        let ua = self.user_allow.load();
        if ua.contains(d) {
            return (Verdict::Forward, Reason::UserAllowed);
        }

        // 4. List rules
        let rules = self.rules.load();
        match rules.match_domain(d) {
            RuleMatch::Allowed => (Verdict::Forward, Reason::ListAllowed),
            RuleMatch::Blocked => (Verdict::Block, Reason::ListBlocked),
            RuleMatch::None => (Verdict::Forward, Reason::NoMatch),
        }
    }

    /// Atomically replace the active compiled rules.
    ///
    /// The swap is instantly visible to all in-flight `decide` calls (ArcSwap
    /// guarantee: load after a store sees the new value on the next load).
    pub fn swap_rules(&self, r: Arc<CompiledRules>) {
        self.rules.store(r);
    }

    /// Replace the user-allow set atomically.
    pub fn set_user_allow(&self, domains: Vec<Domain>) {
        self.user_allow
            .store(Arc::new(UserAllowSet::from_domains(domains)));
    }

    /// Set the snooze expiry.  Pass `0` to clear.
    pub fn snooze_until(&self, unix_ms: u64) {
        self.snooze_until_unix_ms.store(unix_ms, Ordering::Relaxed);
    }

    /// Returns `true` if snooze is currently active.
    pub fn snoozed(&self, now_unix_ms: u64) -> bool {
        let until = self.snooze_until_unix_ms.load(Ordering::Relaxed);
        until != 0 && now_unix_ms < until
    }

    /// Load the current compiled rules without modification.
    ///
    /// Returns an `arc_swap::Guard` that holds a shared reference to the
    /// active [`CompiledRules`]; the guard must be dropped before any code
    /// stores a new rule set.  Primarily used by the list pipeline to inspect
    /// the current rule-set metadata (e.g. to detect empty rules on boot).
    ///
    /// **Core extension added for WP2** — flagged in run summary.
    pub fn current_rules(&self) -> arc_swap::Guard<Arc<CompiledRules>> {
        self.rules.load()
    }
}

impl Default for DecisionEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Returns `true` if `d` is a local name that must never be blocked.
fn is_local_name(d: &Domain) -> bool {
    let s = d.as_str();
    // Single-label names (no dot) are always local.
    if !s.contains('.') {
        return true;
    }
    // Check exact match against local TLDs and pseudo-TLDs.
    if LOCAL_TLDS.contains(&s) {
        return true;
    }
    // Check suffix: any domain whose TLD or eTLD is in LOCAL_TLDS.
    for ancestor in d.self_and_ancestors() {
        if LOCAL_TLDS.contains(&ancestor) {
            return true;
        }
    }
    false
}

/// Reverse a raw domain string into `buf` (reuses allocation across calls).
fn reverse_into(domain: &str, buf: &mut String) {
    buf.clear();
    let mut labels: Vec<&str> = domain.split('.').collect();
    labels.reverse();
    for (i, label) in labels.iter().enumerate() {
        if i > 0 {
            buf.push('.');
        }
        buf.push_str(label);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::rules::{RuleSink, RulesBuilder};
    use std::sync::Arc;

    fn engine_with_rules(blocks: &[&str], allows: &[&str]) -> DecisionEngine {
        let engine = DecisionEngine::new();
        let mut builder = RulesBuilder::new();
        for b in blocks {
            builder.block(Domain::parse(b).unwrap());
        }
        for a in allows {
            builder.allow(Domain::parse(a).unwrap());
        }
        let rules = builder.build().unwrap();
        engine.swap_rules(Arc::new(rules));
        engine
    }

    // ── Precedence ladder — one test per rung proving it beats all lower rungs.

    #[test]
    fn snooze_beats_list_block() {
        let engine = engine_with_rules(&["ads.evil.com"], &[]);
        engine.snooze_until(u64::MAX);
        let d = Domain::parse("ads.evil.com").unwrap();
        let (verdict, reason) = engine.decide(&d, 0);
        assert_eq!(verdict, Verdict::Forward, "snooze must override block");
        assert_eq!(reason, Reason::Snoozed);
    }

    #[test]
    fn local_name_beats_list_block() {
        // Even if a blocklist contains a .lan entry, local names must be forwarded.
        let engine = engine_with_rules(&["printer.lan"], &[]);
        let d = Domain::parse("printer.lan").unwrap();
        let (verdict, reason) = engine.decide(&d, 0);
        assert_eq!(verdict, Verdict::ForwardLocal);
        assert_eq!(reason, Reason::LocalName);
    }

    #[test]
    fn single_label_is_local() {
        let engine = engine_with_rules(&["localhost"], &[]);
        let d = Domain::parse("localhost").unwrap();
        let (verdict, reason) = engine.decide(&d, 0);
        assert_eq!(verdict, Verdict::ForwardLocal);
        assert_eq!(reason, Reason::LocalName);
    }

    #[test]
    fn user_allow_beats_list_block() {
        let engine = engine_with_rules(&["example.com"], &[]);
        engine.set_user_allow(vec![Domain::parse("cdn.example.com").unwrap()]);
        let d = Domain::parse("cdn.example.com").unwrap();
        let (verdict, reason) = engine.decide(&d, 0);
        assert_eq!(verdict, Verdict::Forward);
        assert_eq!(reason, Reason::UserAllowed);
    }

    #[test]
    fn list_allow_beats_list_block() {
        let engine = engine_with_rules(&["example.com"], &["cdn.example.com"]);
        let d = Domain::parse("x.cdn.example.com").unwrap();
        let (verdict, reason) = engine.decide(&d, 0);
        assert_eq!(verdict, Verdict::Forward);
        assert_eq!(reason, Reason::ListAllowed);
    }

    #[test]
    fn list_block_fires() {
        let engine = engine_with_rules(&["ads.example.com"], &[]);
        let d = Domain::parse("ads.example.com").unwrap();
        let (verdict, reason) = engine.decide(&d, 0);
        assert_eq!(verdict, Verdict::Block);
        assert_eq!(reason, Reason::ListBlocked);
    }

    #[test]
    fn no_match_forwards() {
        let engine = engine_with_rules(&[], &[]);
        let d = Domain::parse("clean.example.com").unwrap();
        let (verdict, reason) = engine.decide(&d, 0);
        assert_eq!(verdict, Verdict::Forward);
        assert_eq!(reason, Reason::NoMatch);
    }

    // ── Snooze boundary tests ─────────────────────────────────────────────────

    #[test]
    fn snooze_exact_boundary_expired() {
        // snooze_until = 1000 ms, now = 1000 ms → NOT snoozed (now >= until).
        let engine = DecisionEngine::new();
        engine.snooze_until(1000);
        assert!(
            !engine.snoozed(1000),
            "snooze expires AT the boundary (not <)"
        );
    }

    #[test]
    fn snooze_active_just_before_boundary() {
        let engine = DecisionEngine::new();
        engine.snooze_until(1000);
        assert!(engine.snoozed(999), "snooze is active 1ms before expiry");
    }

    #[test]
    fn snooze_cleared_by_zero() {
        let engine = DecisionEngine::new();
        engine.snooze_until(u64::MAX);
        assert!(engine.snoozed(0));
        engine.snooze_until(0);
        assert!(!engine.snoozed(0), "snooze_until(0) must clear snooze");
    }

    // ── Concurrent decide-during-swap_rules smoke ─────────────────────────────
    //
    // ArcSwap guarantees no torn reads — this test documents that contract by
    // spawning threads that read while another thread swaps rules.

    #[test]
    fn concurrent_decide_during_swap_rules() {
        use std::thread;
        let engine = Arc::new(engine_with_rules(&["ads.example.com"], &[]));
        let d = Domain::parse("ads.example.com").unwrap();

        // Spawn 8 reader threads.
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let eng = Arc::clone(&engine);
                let domain = d.clone();
                thread::spawn(move || {
                    for _ in 0..1000 {
                        let (verdict, _) = eng.decide(&domain, 0);
                        // No torn reads: verdict must always be one of the
                        // defined variants (Block from old rules, or Forward
                        // from swapped-in empty rules).
                        assert!(
                            verdict == Verdict::Block || verdict == Verdict::Forward,
                            "torn read produced an invalid verdict"
                        );
                    }
                })
            })
            .collect();

        // Swap rules mid-flight.
        for _ in 0..100 {
            let mut b = RulesBuilder::new();
            b.block(Domain::parse("ads.example.com").unwrap());
            let r = b.build().unwrap();
            engine.swap_rules(Arc::new(r));
            engine.swap_rules(Arc::new(CompiledRules::empty()));
        }

        for h in handles {
            h.join().unwrap();
        }
    }
}
