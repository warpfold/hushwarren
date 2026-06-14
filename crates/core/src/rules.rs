//! Compiled rule sets backed by `fst::Set`.
//!
//! Implements `docs/architecture.md` §6 (compile side) and
//! `specs/wp1-core.md` §3.  The key invariant: domain names are stored as
//! reversed-label strings (`"com.example.ads"`) so that subdomain matching
//! reduces to an **exact `set.contains(key)`** for each ancestor of the query
//! domain, with no range or prefix scans.  This prevents partial-label false
//! positives (`notexample.com` cannot match `example.com` by construction,
//! because their reversed keys `com.notexample` and `com.example` are
//! distinct) — see the `label_boundary_nonmatch` test for a machine-checked
//! proof of this invariant.

use crate::domain::Domain;
use fst::{Set, SetBuilder};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::io::{BufWriter, Write};
use std::path::Path;
use thiserror::Error;

/// Errors from the rules module.
#[derive(Debug, Error)]
pub enum RulesError {
    /// `fst` rejected a key sequence (keys must be inserted in sorted order;
    /// `RulesBuilder` ensures this via `BTreeSet` deduplication).
    #[error("fst build error: {0}")]
    FstBuild(#[from] fst::Error),

    /// A rules artifact on disk was missing, truncated, or had invalid fst
    /// bytes.  The caller should rebuild from the raw source files.
    #[error("corrupt or missing rules artifact: {0}")]
    CorruptArtifact(String),

    /// An I/O error during artifact save or load.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// `meta.json` failed JSON deserialization (wrong schema / truncated file).
    #[error("meta.json parse error: {0}")]
    MetaParse(String),
}

/// Trait implemented by anything that can receive parsed domain rules.
///
/// Both `RulesBuilder` and the in-place parse counter implement this so
/// `parse::parse_list` can drive either without branching.
pub trait RuleSink {
    /// Record a block rule for `d` and all its subdomains.
    fn block(&mut self, d: Domain);
    /// Record an allow (exception) rule for `d` and all its subdomains.
    fn allow(&mut self, d: Domain);
}

/// Accumulates domain rules before compiling them into a [`CompiledRules`].
///
/// Uses `BTreeSet` internally so keys are automatically deduplicated and
/// emitted to `fst::SetBuilder` in sorted order (a hard fst requirement).
#[derive(Debug, Default)]
pub struct RulesBuilder {
    block_keys: BTreeSet<String>,
    allow_keys: BTreeSet<String>,
    /// Source names attached to the compiled artifact's metadata.
    pub source_names: Vec<String>,
}

impl RulesBuilder {
    /// Create a new, empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a source name to be recorded in the compiled artifact's metadata.
    pub fn add_source_name(&mut self, name: impl Into<String>) {
        self.source_names.push(name.into());
    }

    /// Return the current number of unique block keys accumulated so far.
    ///
    /// Used by the list pipeline to compute per-source rule-count deltas between
    /// successive calls to [`RuleSink::block`] for each source.
    pub fn block_len(&self) -> usize {
        self.block_keys.len()
    }

    /// Consume the builder and produce a [`CompiledRules`] artifact.
    ///
    /// Keys are emitted to the fst builder in sorted order (BTreeSet guarantees
    /// this); the fst crate requires strict lexicographic order.
    pub fn build(self) -> Result<CompiledRules, RulesError> {
        let block_count = self.block_keys.len() as u64;
        let allow_count = self.allow_keys.len() as u64;

        let block = build_set(self.block_keys)?;
        let allow = build_set(self.allow_keys)?;

        let meta = RulesMeta {
            block_count,
            allow_count,
            built_unix_ms: unix_ms_now(),
            source_names: self.source_names,
        };

        Ok(CompiledRules { block, allow, meta })
    }
}

impl RuleSink for RulesBuilder {
    fn block(&mut self, d: Domain) {
        self.block_keys.insert(d.reversed());
    }

    fn allow(&mut self, d: Domain) {
        self.allow_keys.insert(d.reversed());
    }
}

/// Metadata persisted alongside a compiled rule set artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RulesMeta {
    /// Number of unique block rules in the compiled set.
    pub block_count: u64,
    /// Number of unique allow (exception) rules in the compiled set.
    pub allow_count: u64,
    /// Unix timestamp (milliseconds) when this artifact was built.
    pub built_unix_ms: u64,
    /// Human-readable names of the source lists that contributed to this artifact.
    pub source_names: Vec<String>,
}

/// The result of looking up a domain in a [`CompiledRules`] set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleMatch {
    /// The domain is explicitly allowed (exception wins over block).
    Allowed,
    /// The domain is blocked.
    Blocked,
    /// Neither an allow nor a block rule matched.
    None,
}

/// A compiled, immutable rule set backed by two `fst::Set` instances.
///
/// The key encoding is reversed-label DNS names (`"com.example.ads"`).
/// Subdomain matching is implemented by walking the query domain's ancestor
/// chain and checking **exact contains** at each level — no range scans.
///
/// # Invariant: no partial-label false positives
///
/// Because lookup is exact-key only, `"com.notexample"` can never match a
/// rule keyed `"com.example"`.  The `label_boundary_nonmatch` unit test proves
/// this property at the type level.
pub struct CompiledRules {
    block: Set<Vec<u8>>,
    allow: Set<Vec<u8>>,
    /// Metadata about how this rule set was built.
    pub meta: RulesMeta,
}

impl CompiledRules {
    /// Return a rule set that matches nothing.
    ///
    /// Used as the daemon's cold-start state before the first list compile.
    pub fn empty() -> CompiledRules {
        // PANIC-OK: building a Set from an empty key sequence is infallible;
        // the only fst error requires inserting keys out of order, which cannot
        // happen with zero keys.
        let block = build_set(BTreeSet::new())
            .unwrap_or_else(|_| unreachable!("empty fst::Set construction cannot fail"));
        let allow = build_set(BTreeSet::new())
            .unwrap_or_else(|_| unreachable!("empty fst::Set construction cannot fail"));
        CompiledRules {
            block,
            allow,
            meta: RulesMeta {
                block_count: 0,
                allow_count: 0,
                built_unix_ms: unix_ms_now(),
                source_names: Vec::new(),
            },
        }
    }

    /// Look up `d` against the compiled allow and block sets.
    ///
    /// Walks `d.self_and_ancestors()` most-specific to least-specific.
    /// If **any** suffix is in `allow` → [`RuleMatch::Allowed`].
    /// Else if **any** suffix is in `block` → [`RuleMatch::Blocked`].
    /// Else → [`RuleMatch::None`].
    ///
    /// Allow wins regardless of specificity — a user who allows `cdn.example.com`
    /// while `example.com` is blocked gets the CDN unblocked (see
    /// `docs/architecture.md` §5, zero-touch-ux.md §7).
    ///
    /// Uses a stack-allocated scratch buffer for the reversed key to keep this
    /// hot-path allocation-free.
    pub fn match_domain(&self, d: &Domain) -> RuleMatch {
        let mut buf = String::with_capacity(d.as_str().len());

        // Allow pass: if any ancestor is in the allow set, return Allowed.
        for ancestor in d.self_and_ancestors() {
            reverse_domain_into(ancestor, &mut buf);
            if self.allow.contains(&buf) {
                return RuleMatch::Allowed;
            }
        }

        // Block pass: allow exhausted, check block set.
        // Spec: allow wins over block at ANY specificity — we must exhaust allow
        // before declaring a block.
        for ancestor in d.self_and_ancestors() {
            reverse_domain_into(ancestor, &mut buf);
            if self.block.contains(&buf) {
                return RuleMatch::Blocked;
            }
        }

        RuleMatch::None
    }

    /// Save the compiled rule set to `dir` atomically.
    ///
    /// Writes `<dir>/block.fst`, `<dir>/allow.fst`, and `<dir>/meta.json`.
    /// Each file is written to a temporary file in the same directory, then
    /// `fsync`-ed and renamed over the target, ensuring the directory never
    /// contains a partially-written artifact.
    pub fn save(&self, dir: &Path) -> Result<(), RulesError> {
        fs::create_dir_all(dir)?;

        atomic_write(dir, "block.fst", self.block.as_fst().to_vec())?;
        atomic_write(dir, "allow.fst", self.allow.as_fst().to_vec())?;

        let meta_json =
            serde_json::to_vec(&self.meta).map_err(|e| RulesError::MetaParse(e.to_string()))?;
        atomic_write(dir, "meta.json", meta_json)?;

        Ok(())
    }

    /// Load a compiled rule set from `dir`.
    ///
    /// Validates fst headers (`fst::Set::new` errors on corrupt bytes) and
    /// checks that the stored `meta.json` counts match the set sizes.
    /// Any failure → [`RulesError::CorruptArtifact`]; the caller should
    /// rebuild from raw sources (`docs/architecture.md` §6 failure mode).
    pub fn load(dir: &Path) -> Result<CompiledRules, RulesError> {
        let block_bytes = fs::read(dir.join("block.fst"))
            .map_err(|e| RulesError::CorruptArtifact(format!("cannot read block.fst: {e}")))?;
        let allow_bytes = fs::read(dir.join("allow.fst"))
            .map_err(|e| RulesError::CorruptArtifact(format!("cannot read allow.fst: {e}")))?;
        let meta_bytes = fs::read(dir.join("meta.json"))
            .map_err(|e| RulesError::CorruptArtifact(format!("cannot read meta.json: {e}")))?;

        let block: Set<Vec<u8>> = Set::new(block_bytes)
            .map_err(|e| RulesError::CorruptArtifact(format!("block.fst corrupt: {e}")))?;
        let allow: Set<Vec<u8>> = Set::new(allow_bytes)
            .map_err(|e| RulesError::CorruptArtifact(format!("allow.fst corrupt: {e}")))?;

        let meta: RulesMeta = serde_json::from_slice(&meta_bytes)
            .map_err(|e| RulesError::CorruptArtifact(format!("meta.json parse error: {e}")))?;

        Ok(CompiledRules { block, allow, meta })
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Build an `fst::Set<Vec<u8>>` from a sorted set of string keys.
fn build_set(keys: BTreeSet<String>) -> Result<Set<Vec<u8>>, RulesError> {
    let mut bytes = Vec::new();
    {
        let mut builder = SetBuilder::new(&mut bytes)?;
        for key in &keys {
            builder.insert(key.as_bytes())?;
        }
        builder.finish()?;
    }
    Ok(Set::new(bytes)?)
}

/// Write `contents` to `<dir>/<name>` atomically via tempfile + rename.
///
/// The tempfile is written and synced in the same directory as the target so
/// the rename is on the same filesystem (POSIX rename atomicity guarantee).
fn atomic_write(dir: &Path, name: &str, contents: Vec<u8>) -> Result<(), RulesError> {
    let target = dir.join(name);
    let tmp_path = dir.join(format!(".{name}.tmp"));

    {
        let file = fs::File::create(&tmp_path)?;
        let mut writer = BufWriter::new(&file);
        writer.write_all(&contents)?;
        writer.flush()?;
        file.sync_all()?;
    }

    fs::rename(&tmp_path, &target)?;
    Ok(())
}

/// Reverse the labels of a dot-separated domain string into `buf`.
///
/// `"ads.example.com"` → `"com.example.ads"`.
/// The buffer is cleared before writing.
fn reverse_domain_into(domain: &str, buf: &mut String) {
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

/// Current Unix time in milliseconds, best-effort.
///
/// Falls back to 0 on platforms where `SystemTime` is unavailable; this is
/// only cosmetic metadata and never affects correctness.
fn unix_ms_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use tempfile::TempDir;

    fn make_rules(blocks: &[&str], allows: &[&str]) -> CompiledRules {
        let mut builder = RulesBuilder::new();
        for b in blocks {
            builder.block(Domain::parse(b).unwrap());
        }
        for a in allows {
            builder.allow(Domain::parse(a).unwrap());
        }
        builder.build().unwrap()
    }

    // ── Exact match ──────────────────────────────────────────────────────────

    #[test]
    fn exact_match_blocked() {
        let rules = make_rules(&["example.com"], &[]);
        let d = Domain::parse("example.com").unwrap();
        assert_eq!(rules.match_domain(&d), RuleMatch::Blocked);
    }

    // ── Subdomain match ───────────────────────────────────────────────────────

    #[test]
    fn subdomain_blocked_by_parent() {
        let rules = make_rules(&["example.com"], &[]);
        let d = Domain::parse("a.b.example.com").unwrap();
        assert_eq!(rules.match_domain(&d), RuleMatch::Blocked);
    }

    // ── Label boundary invariant — the mandatory non-match test ──────────────
    //
    // INVARIANT: exact-key lookup means `notexample.com` (reversed:
    // `com.notexample`) can never match a rule keyed `com.example`.
    // Similarly `ample.com` (`com.ample`) cannot match `example.com`.
    // This test is the machine-checked proof of that property.

    #[test]
    fn label_boundary_nonmatch_notexample() {
        let rules = make_rules(&["example.com"], &[]);
        let d = Domain::parse("notexample.com").unwrap();
        assert_eq!(
            rules.match_domain(&d),
            RuleMatch::None,
            "notexample.com must NOT be matched by an example.com rule"
        );
    }

    #[test]
    fn label_boundary_nonmatch_ample() {
        let rules = make_rules(&["example.com"], &[]);
        let d = Domain::parse("ample.com").unwrap();
        assert_eq!(
            rules.match_domain(&d),
            RuleMatch::None,
            "ample.com must NOT be matched by an example.com rule"
        );
    }

    // ── Allow beats block ─────────────────────────────────────────────────────
    //
    // The spec asymmetry: allow wins only on its own suffix chain.
    // allow `cdn.example.com` + block `example.com`:
    //   x.cdn.example.com → Allowed  (cdn.example.com is in its ancestry)
    //   other.example.com → Blocked  (cdn.example.com is NOT in its ancestry)

    #[test]
    fn allow_beats_block_at_cdn_subtree() {
        let rules = make_rules(&["example.com"], &["cdn.example.com"]);
        let d = Domain::parse("x.cdn.example.com").unwrap();
        assert_eq!(rules.match_domain(&d), RuleMatch::Allowed);
    }

    #[test]
    fn allow_does_not_protect_sibling_subtree() {
        let rules = make_rules(&["example.com"], &["cdn.example.com"]);
        let d = Domain::parse("other.example.com").unwrap();
        assert_eq!(rules.match_domain(&d), RuleMatch::Blocked);
    }

    // ── Empty rules ───────────────────────────────────────────────────────────

    #[test]
    fn empty_rules_match_nothing() {
        let rules = CompiledRules::empty();
        let d = Domain::parse("anything.com").unwrap();
        assert_eq!(rules.match_domain(&d), RuleMatch::None);
    }

    // ── Meta counts ───────────────────────────────────────────────────────────

    #[test]
    fn meta_counts_correct() {
        let rules = make_rules(&["a.com", "b.com", "c.com"], &["x.com"]);
        assert_eq!(rules.meta.block_count, 3);
        assert_eq!(rules.meta.allow_count, 1);
    }

    // ── block_len accessor ────────────────────────────────────────────────────

    #[test]
    fn block_len_zero_initially() {
        let builder = RulesBuilder::new();
        assert_eq!(builder.block_len(), 0);
    }

    #[test]
    fn block_len_increments_with_block_rules() {
        let mut builder = RulesBuilder::new();
        assert_eq!(builder.block_len(), 0);
        builder.block(Domain::parse("a.com").unwrap());
        assert_eq!(builder.block_len(), 1);
        builder.block(Domain::parse("b.com").unwrap());
        assert_eq!(builder.block_len(), 2);
    }

    #[test]
    fn block_len_deduplicates() {
        let mut builder = RulesBuilder::new();
        builder.block(Domain::parse("a.com").unwrap());
        builder.block(Domain::parse("a.com").unwrap()); // duplicate
        assert_eq!(
            builder.block_len(),
            1,
            "duplicate block rules must not inflate block_len"
        );
    }

    #[test]
    fn block_len_unaffected_by_allow_rules() {
        let mut builder = RulesBuilder::new();
        builder.allow(Domain::parse("a.com").unwrap());
        assert_eq!(
            builder.block_len(),
            0,
            "allow rules must not affect block_len"
        );
    }

    // ── Save / load round-trip ────────────────────────────────────────────────

    #[test]
    fn save_load_round_trip() {
        let rules = make_rules(&["ads.example.com", "tracker.bad.com"], &["cdn.good.com"]);
        let dir = TempDir::new().unwrap();
        rules.save(dir.path()).unwrap();

        let loaded = CompiledRules::load(dir.path()).unwrap();
        assert_eq!(loaded.meta.block_count, rules.meta.block_count);
        assert_eq!(loaded.meta.allow_count, rules.meta.allow_count);

        let d = Domain::parse("ads.example.com").unwrap();
        assert_eq!(loaded.match_domain(&d), RuleMatch::Blocked);
        let d2 = Domain::parse("cdn.good.com").unwrap();
        assert_eq!(loaded.match_domain(&d2), RuleMatch::Allowed);
    }

    // ── Corrupt artifact → CorruptArtifact error ──────────────────────────────

    #[test]
    fn corrupt_block_fst_returns_error() {
        let rules = make_rules(&["example.com"], &[]);
        let dir = TempDir::new().unwrap();
        rules.save(dir.path()).unwrap();

        // Overwrite block.fst with garbage.
        fs::write(dir.path().join("block.fst"), b"not valid fst bytes").unwrap();

        let result = CompiledRules::load(dir.path());
        assert!(
            matches!(result, Err(RulesError::CorruptArtifact(_))),
            "corrupt block.fst must yield CorruptArtifact"
        );
    }

    #[test]
    fn missing_artifact_returns_error() {
        let dir = TempDir::new().unwrap();
        let result = CompiledRules::load(dir.path());
        assert!(matches!(result, Err(RulesError::CorruptArtifact(_))));
    }
}
