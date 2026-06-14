//! # hush-core
//!
//! Pure logic for hushwarren: everything that can be unit-tested without a
//! network, a privileged port, or an OS API. See `docs/architecture.md` §4–§6.
//!
//! ## Modules
//!
//! - [`domain`] — canonical DNS name type; construction is the only validation
//!   point; reversed-label encoding for fst keys.
//! - [`parse`] — unified blocklist line parser (hosts, AdBlock, plain domains).
//! - [`rules`] — compiled fst-backed rule sets; atomic artifact save/load.
//! - [`decision`] — per-query verdict engine; precedence ladder; ArcSwap hot path.
//! - [`config`] — serde+toml config model; collect-all validation.
//! - [`querylog`] — query record types and fixed-capacity overwrite ring buffer.
//! - [`catalog`] — compiled-in source catalog (WP4); maps preset/category keys to URLs.

pub mod catalog;
pub mod config;
pub mod decision;
pub mod domain;
pub mod parse;
pub mod querylog;
pub mod rebind;
pub mod rules;

// Re-export the most-used public types at the crate root for convenience.
pub use config::{HushConfig, SentinelConfig};
pub use decision::{DecisionEngine, Reason, Verdict, SELFTEST_BLOCKED_DOMAIN};
pub use domain::{Domain, DomainError};
pub use querylog::{QueryRecord, QueryRing, RingStats};
pub use rules::{CompiledRules, RuleMatch, RulesBuilder, RulesMeta};
