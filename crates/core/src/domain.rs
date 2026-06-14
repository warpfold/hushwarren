//! Canonical DNS name type (`Domain`).
//!
//! Implements `docs/architecture.md` §5 canonicalization rules and the
//! reversed-label encoding used as `fst::Set` keys in the `rules` module.
//! Construction is the ONLY way to obtain a `Domain`; all invariants are
//! checked at parse time so the rest of the codebase can assume them.

use std::net::Ipv4Addr;
use thiserror::Error;

/// A canonicalized DNS name: lowercase ASCII, no trailing dot, no empty labels.
///
/// The inner `String` satisfies the invariants checked by `parse()` — callers
/// MUST NOT construct `Domain` through any other path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Domain(String);

/// Errors produced by [`Domain::parse`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DomainError {
    /// Input was empty (after trimming whitespace and a trailing dot).
    #[error("domain name is empty")]
    Empty,

    /// Total encoded length exceeds the 253-byte DNS wire limit.
    #[error("domain name exceeds 253 characters")]
    TooLong,

    /// A label is empty, longer than 63 chars, or contains characters outside
    /// `[a-z0-9_-]` (after lowercasing).  The bad label text is included for
    /// diagnostics.
    #[error("domain label is invalid: {0:?}")]
    BadLabel(String),

    /// The input contains non-ASCII bytes.  IDNA / punycode conversion is out of
    /// P0 scope; already-punycoded `xn--` labels pass through.
    #[error("domain name contains non-ASCII characters")]
    NotAscii,

    /// The input parsed as an IPv4 address (e.g. `1.2.3.4`).  Blocking IPs is
    /// not DNS's job; hosts-file lines sometimes carry bare IPs that we must
    /// ignore rather than treat as domain names.
    #[error("input is an IPv4 address, not a domain name")]
    IsIpAddress,
}

impl Domain {
    /// Parse and canonicalize a DNS name.
    ///
    /// Canonicalization order (matches spec §1):
    /// 1. Trim ASCII whitespace; strip one trailing `.` if present.
    /// 2. Reject non-ASCII.
    /// 3. Lowercase.
    /// 4. Validate length and label characters.
    /// 5. Reject bare IPv4 addresses.
    pub fn parse(input: &str) -> Result<Domain, DomainError> {
        // Step 1: trim, strip single trailing dot.
        let trimmed = input.trim();
        let without_dot = trimmed.strip_suffix('.').unwrap_or(trimmed);

        if without_dot.is_empty() {
            return Err(DomainError::Empty);
        }

        // Step 2: reject non-ASCII before any further processing.
        if !without_dot.is_ascii() {
            return Err(DomainError::NotAscii);
        }

        // Step 3: lowercase.
        let lower = without_dot.to_ascii_lowercase();

        // Step 4a: total length.
        if lower.len() > 253 {
            return Err(DomainError::TooLong);
        }

        // Step 4b: validate each label.
        for label in lower.split('.') {
            if label.is_empty() {
                // Empty label = two consecutive dots or leading/trailing dot
                // after stripping the one allowed trailing dot.
                return Err(DomainError::BadLabel(String::new()));
            }
            if label.len() > 63 {
                return Err(DomainError::BadLabel(label.to_string()));
            }
            // Allowed: [a-z0-9_-]
            // Note: labels starting/ending with '-' are accepted (seen in the
            // wild on blocklists; we are a filter, not a registrar).
            for ch in label.chars() {
                if !matches!(ch, 'a'..='z' | '0'..='9' | '_' | '-') {
                    return Err(DomainError::BadLabel(label.to_string()));
                }
            }
        }

        // Step 5: reject bare IPv4 addresses.
        // A domain that is also a valid Ipv4Addr (e.g. "1.2.3.4") is an IP,
        // not a domain name.  Hosts-file lines sometimes place bare IPs in the
        // hostname column; blocking IPs is not DNS's job.
        if lower.parse::<Ipv4Addr>().is_ok() {
            return Err(DomainError::IsIpAddress);
        }

        Ok(Domain(lower))
    }

    /// Returns the canonical string form (lowercase, no trailing dot).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Labels in reversed order joined with `.`.
    ///
    /// `"ads.example.com"` → `"com.example.ads"`
    ///
    /// This is the fst key encoding: exact `set.contains(key)` for each suffix
    /// of the query domain implements subdomain matching without range scans
    /// (see `rules` module).
    pub fn reversed(&self) -> String {
        let mut buf = String::with_capacity(self.0.len());
        self.reversed_into(&mut buf);
        buf
    }

    /// Like [`reversed`](Domain::reversed) but writes into a caller-supplied
    /// buffer, allowing the hot path to reuse a stack/thread-local allocation.
    ///
    /// The buffer is **cleared** before writing.
    pub fn reversed_into(&self, buf: &mut String) {
        buf.clear();
        let mut labels: Vec<&str> = self.0.split('.').collect();
        labels.reverse();
        for (i, label) in labels.iter().enumerate() {
            if i > 0 {
                buf.push('.');
            }
            buf.push_str(label);
        }
    }

    /// Iterator over this domain and each parent, from most specific to least.
    ///
    /// `"a.b.com"` → `["a.b.com", "b.com", "com"]`
    ///
    /// Used by the rules engine to implement suffix matching by walking the
    /// ancestry chain and checking exact `fst::Set::contains` at each level.
    pub fn self_and_ancestors(&self) -> impl Iterator<Item = &str> {
        SelfAndAncestors {
            s: &self.0,
            offset: 0,
        }
    }
}

/// Iterator state for [`Domain::self_and_ancestors`].
struct SelfAndAncestors<'a> {
    s: &'a str,
    /// Byte offset of the current slice into `s`; starts at 0 (full domain).
    offset: usize,
}

impl<'a> Iterator for SelfAndAncestors<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset > self.s.len() {
            return None;
        }
        let current = &self.s[self.offset..];
        if current.is_empty() {
            return None;
        }
        // Advance offset to the character after the next '.' (or past the end).
        self.offset = match current.find('.') {
            Some(dot_pos) => self.offset + dot_pos + 1,
            None => self.s.len() + 1, // signal exhaustion on next call
        };
        Some(current)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    // --- happy-path canonicalization ---

    #[test]
    fn trailing_dot_stripped() {
        let d = Domain::parse("example.com.").unwrap();
        assert_eq!(d.as_str(), "example.com");
    }

    #[test]
    fn uppercase_lowercased() {
        let d = Domain::parse("ADS.Example.COM").unwrap();
        assert_eq!(d.as_str(), "ads.example.com");
    }

    #[test]
    fn single_label_valid() {
        let d = Domain::parse("localhost").unwrap();
        assert_eq!(d.as_str(), "localhost");
    }

    #[test]
    fn underscore_label_ok() {
        let d = Domain::parse("_dmarc.example.com").unwrap();
        assert_eq!(d.as_str(), "_dmarc.example.com");
    }

    #[test]
    fn xn_punycode_passes_through() {
        let d = Domain::parse("xn--nxasmq6b.com").unwrap();
        assert_eq!(d.as_str(), "xn--nxasmq6b.com");
    }

    #[test]
    fn leading_trailing_dash_label_accepted() {
        // Registrar-invalid but seen in real blocklists; we are a filter, not a registrar.
        let d = Domain::parse("-bad-label-.example.com").unwrap();
        assert_eq!(d.as_str(), "-bad-label-.example.com");
    }

    // --- length boundary tests ---

    #[test]
    fn exactly_253_chars_ok() {
        // 63 + '.' + 63 + '.' + 63 + '.' + 61 = 253
        let label63 = "a".repeat(63);
        let label61 = "a".repeat(61);
        let s = format!("{label63}.{label63}.{label63}.{label61}");
        assert_eq!(s.len(), 253);
        assert!(Domain::parse(&s).is_ok());
    }

    #[test]
    fn exactly_254_chars_rejected() {
        let label63 = "a".repeat(63);
        let label62 = "a".repeat(62);
        let s = format!("{label63}.{label63}.{label63}.{label62}");
        assert_eq!(s.len(), 254);
        assert_eq!(Domain::parse(&s), Err(DomainError::TooLong));
    }

    #[test]
    fn label_exactly_63_ok() {
        let label = "a".repeat(63);
        let s = format!("{label}.com");
        assert!(Domain::parse(&s).is_ok());
    }

    #[test]
    fn label_64_rejected() {
        let label = "a".repeat(64);
        let s = format!("{label}.com");
        assert!(matches!(Domain::parse(&s), Err(DomainError::BadLabel(_))));
    }

    // --- error cases ---

    #[test]
    fn empty_string_rejected() {
        assert_eq!(Domain::parse(""), Err(DomainError::Empty));
        assert_eq!(Domain::parse("   "), Err(DomainError::Empty));
        assert_eq!(Domain::parse("."), Err(DomainError::Empty));
    }

    #[test]
    fn empty_label_rejected() {
        assert!(matches!(
            Domain::parse("a..b"),
            Err(DomainError::BadLabel(_))
        ));
    }

    #[test]
    fn non_ascii_rejected() {
        assert_eq!(Domain::parse("bücher.de"), Err(DomainError::NotAscii));
    }

    #[test]
    fn bare_ipv4_rejected() {
        assert_eq!(Domain::parse("1.2.3.4"), Err(DomainError::IsIpAddress));
        assert_eq!(Domain::parse("0.0.0.0"), Err(DomainError::IsIpAddress));
        assert_eq!(Domain::parse("127.0.0.1"), Err(DomainError::IsIpAddress));
    }

    #[test]
    fn bad_char_rejected() {
        assert!(matches!(
            Domain::parse("ex@mple.com"),
            Err(DomainError::BadLabel(_))
        ));
    }

    // --- reversed() ---

    #[test]
    fn reversed_correctness() {
        let d = Domain::parse("ads.example.com").unwrap();
        assert_eq!(d.reversed(), "com.example.ads");
    }

    #[test]
    fn reversed_single_label() {
        let d = Domain::parse("localhost").unwrap();
        assert_eq!(d.reversed(), "localhost");
    }

    // --- self_and_ancestors ---

    #[test]
    fn self_and_ancestors_order_and_count() {
        let d = Domain::parse("a.b.com").unwrap();
        let v: Vec<&str> = d.self_and_ancestors().collect();
        assert_eq!(v, vec!["a.b.com", "b.com", "com"]);
    }

    #[test]
    fn self_and_ancestors_single_label() {
        let d = Domain::parse("localhost").unwrap();
        let v: Vec<&str> = d.self_and_ancestors().collect();
        assert_eq!(v, vec!["localhost"]);
    }

    #[test]
    fn self_and_ancestors_two_labels() {
        let d = Domain::parse("example.com").unwrap();
        let v: Vec<&str> = d.self_and_ancestors().collect();
        assert_eq!(v, vec!["example.com", "com"]);
    }
}
