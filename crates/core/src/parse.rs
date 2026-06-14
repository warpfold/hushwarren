//! Blocklist line parser — unified handling of hosts, AdBlock domain syntax,
//! and plain domain lists.
//!
//! Implements `docs/architecture.md` §6 (parse side) and `specs/wp1-core.md` §2.
//! One parser handles all three real-world formats so callers need no per-file
//! format detection; mixed-format files (they exist in the wild) work correctly.

use crate::domain::Domain;
use crate::rules::RuleSink;

/// The result of parsing one line of a blocklist.
#[derive(Debug, PartialEq, Eq)]
pub enum Line {
    /// The domain (and all its subdomains) should be blocked.
    Block(Domain),
    /// AdBlock exception (`@@||domain^`): the domain is explicitly allowed.
    Allow(Domain),
    /// Line carries no actionable rule (comment, empty, unsupported syntax, etc.).
    Skip(SkipReason),
}

/// Why a line was skipped rather than producing a `Block` or `Allow` rule.
#[derive(Debug, PartialEq, Eq)]
pub enum SkipReason {
    /// Line was empty or entirely comment.
    Empty,
    /// Hosts-file entry for a well-known localhost alias — not a block target.
    LocalhostEntry,
    /// Hosts-file entry with a non-sinkhole IP (real DNS mapping, e.g. `192.168.1.5 nas`).
    NonBlockingHostsEntry,
    /// AdBlock cosmetic rule, regex pattern, or other syntax we cannot represent.
    UnsupportedSyntax,
    /// Domain token failed `Domain::parse` (invalid label, IP address, etc.).
    BadDomain,
}

/// Aggregate counts from parsing a multi-line list.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ParseSummary {
    /// Number of `Block` entries emitted.
    pub blocked: u64,
    /// Number of `Allow` (exception) entries emitted.
    pub allowed: u64,
    /// Number of lines skipped for any reason.
    pub skipped: u64,
}

/// Hostnames appearing in common blocklist headers that are localhost aliases.
///
/// Hosts-file lines whose second column is in this set are always skipped;
/// blocking them would take down local resolution entirely.
static LOCALHOST_NAMES: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-allnodes",
    "ip6-allrouters",
];

/// IP tokens that indicate a sinkhole / null-route hosts-file line.
///
/// Any other IP token means the line is a real DNS mapping that should not be
/// turned into a block rule.
static SINKHOLE_IPS: &[&str] = &["0.0.0.0", "127.0.0.1", "::", "::1", "0"];

/// Parse one line of a blocklist and return the resulting [`Line`].
///
/// This function never returns an error: all problems are encoded as
/// `Skip(reason)` so callers can count and log them without branching.
pub fn parse_line(line: &str) -> Line {
    // ── Pre-check: AdBlock cosmetic markers that start with '#' ──────────────
    // These must be tested on the raw (un-comment-stripped) line because
    // `strip_comment` treats a leading '#' as a comment opener and would turn
    // `##.ad-banner` into an empty string → Skip(Empty) instead of
    // Skip(UnsupportedSyntax).
    //
    // Only `##` and `#@#` need special-casing; all other AdBlock patterns
    // (`@@||`, `||`, regex) are handled correctly after comment stripping.
    let raw_trimmed = line.trim();
    if raw_trimmed.starts_with("##") || raw_trimmed.starts_with("#@#") {
        return Line::Skip(SkipReason::UnsupportedSyntax);
    }

    // ── Step 1: strip comments and trim ──────────────────────────────────────
    // Comments start with `#` or `!` when at the start of the line OR
    // preceded by ASCII whitespace.  We do NOT split `domain#fragment` style
    // garbage — the whole line will fail domain parse and become Skip(BadDomain).
    let stripped = strip_comment(line);
    let trimmed = stripped.trim();
    if trimmed.is_empty() {
        return Line::Skip(SkipReason::Empty);
    }

    // ── Step 2: AdBlock exception @@||domain^ ────────────────────────────────
    if let Some(rest) = trimmed.strip_prefix("@@||") {
        let domain_part = strip_adblock_options(rest);
        return match Domain::parse(domain_part) {
            Ok(d) => Line::Allow(d),
            Err(_) => Line::Skip(SkipReason::BadDomain),
        };
    }

    // ── Step 3: AdBlock block ||domain^ ──────────────────────────────────────
    if let Some(rest) = trimmed.strip_prefix("||") {
        let domain_part = strip_adblock_options(rest);
        return match Domain::parse(domain_part) {
            Ok(d) => Line::Block(d),
            Err(_) => Line::Skip(SkipReason::BadDomain),
        };
    }

    // ── Step 3b: Unsupported AdBlock syntax (remaining cases) ────────────────
    // Regex patterns — anything else that looks like AdBlock but without `||`.
    if trimmed.starts_with('/') && trimmed.ends_with('/') {
        return Line::Skip(SkipReason::UnsupportedSyntax);
    }

    // ── Step 4: Hosts file format ─────────────────────────────────────────────
    // "ip  host1  host2  ..." — the first token must parse as an IP address.
    // We recognise IPv4 and bare IPv6 (:: / ::1) and decimal zero.
    let mut tokens = trimmed.split_ascii_whitespace();
    if let Some(first) = tokens.next() {
        if is_ip_token(first) {
            let is_sinkhole = SINKHOLE_IPS.contains(&first);
            // Collect remaining tokens as candidate hostnames.
            let hosts: Vec<&str> = tokens.collect();
            if hosts.is_empty() {
                // Lone IP address line — nothing useful.
                return Line::Skip(SkipReason::Empty);
            }
            if !is_sinkhole {
                return Line::Skip(SkipReason::NonBlockingHostsEntry);
            }
            // Sinkhole hosts line: yield the first parseable, non-localhost host.
            // parse_list drives this via the multi-host helper; for single-line
            // calls we return the first actionable result.
            for host in &hosts {
                if LOCALHOST_NAMES.contains(host) {
                    // Keep looking for a real entry (hosts lines can mix).
                    continue;
                }
                return match Domain::parse(host) {
                    Ok(d) => Line::Block(d),
                    Err(_) => Line::Skip(SkipReason::BadDomain),
                };
            }
            // All tokens were localhost aliases.
            return Line::Skip(SkipReason::LocalhostEntry);
        }
    }

    // ── Step 5: plain domain ─────────────────────────────────────────────────
    match Domain::parse(trimmed) {
        Ok(d) => Line::Block(d),
        Err(_) => Line::Skip(SkipReason::BadDomain),
    }
}

/// Strip the AdBlock `^` suffix and optional `$options` portion from a domain token.
///
/// `"example.com^"` → `"example.com"`
/// `"example.com^$third-party"` → `"example.com"`
fn strip_adblock_options(s: &str) -> &str {
    // Strip everything from '^' onward, then any trailing whitespace.
    let cut = s.find('^').map_or(s, |pos| &s[..pos]);
    cut.trim()
}

/// Strip the comment portion of a line.
///
/// The comment marker (`#` or `!`) is recognised only at start-of-line or when
/// preceded by ASCII whitespace, so `domain#fragment` garbage is NOT split.
fn strip_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if (b == b'#' || b == b'!') && (i == 0 || bytes[i - 1].is_ascii_whitespace()) {
            return &line[..i];
        }
    }
    line
}

/// Returns `true` if `token` is an IP address (v4 or IPv6 subset we care about).
fn is_ip_token(token: &str) -> bool {
    // Fast path: known IPv6 sinkhole tokens.
    if token == "::" || token == "::1" {
        return true;
    }
    // Single digit zero (seen in some hosts files).
    if token == "0" {
        return true;
    }
    // Try IPv4 parse — this also handles `0.0.0.0`, `127.0.0.1`, and ANY other
    // valid IPv4.
    token.parse::<std::net::Ipv4Addr>().is_ok() || token.parse::<std::net::Ipv6Addr>().is_ok()
}

/// Parse an entire list (potentially millions of lines) feeding results into
/// `sink`.  Returns aggregate [`ParseSummary`] counts.
///
/// Hosts-file lines that carry multiple hostnames are expanded: each hostname
/// is fed to the sink separately so block-counts stay accurate.
///
/// This function never errors; all problems are counted as skipped.
pub fn parse_list(text: &str, sink: &mut impl RuleSink) -> ParseSummary {
    let mut summary = ParseSummary::default();

    for raw_line in text.lines() {
        // Pre-check: AdBlock cosmetic markers that start with '#'.
        // strip_comment would convert `##.ad` to "" → Skip(Empty); we want
        // Skip(UnsupportedSyntax) so these are caught before comment stripping.
        let raw_trimmed = raw_line.trim();
        if raw_trimmed.starts_with("##") || raw_trimmed.starts_with("#@#") {
            summary.skipped += 1;
            continue;
        }

        let stripped = strip_comment(raw_line);
        let trimmed = stripped.trim();

        if trimmed.is_empty() {
            summary.skipped += 1;
            continue;
        }

        // AdBlock exception
        if let Some(rest) = trimmed.strip_prefix("@@||") {
            let domain_part = strip_adblock_options(rest);
            match Domain::parse(domain_part) {
                Ok(d) => {
                    sink.allow(d);
                    summary.allowed += 1;
                }
                Err(_) => summary.skipped += 1,
            }
            continue;
        }

        // AdBlock block
        if let Some(rest) = trimmed.strip_prefix("||") {
            let domain_part = strip_adblock_options(rest);
            match Domain::parse(domain_part) {
                Ok(d) => {
                    sink.block(d);
                    summary.blocked += 1;
                }
                Err(_) => summary.skipped += 1,
            }
            continue;
        }

        // Unsupported AdBlock syntax
        if trimmed.starts_with("##")
            || trimmed.starts_with("#@#")
            || trimmed.starts_with("@@")
            || (trimmed.starts_with('/') && trimmed.ends_with('/'))
            || trimmed.contains("##")
            || trimmed.contains("#@#")
        {
            summary.skipped += 1;
            continue;
        }

        // Hosts file multi-host expansion
        let mut tokens = trimmed.split_ascii_whitespace();
        if let Some(first) = tokens.next() {
            if is_ip_token(first) {
                let is_sinkhole = SINKHOLE_IPS.contains(&first);
                let hosts: Vec<&str> = tokens.collect();
                if hosts.is_empty() {
                    summary.skipped += 1;
                    continue;
                }
                if !is_sinkhole {
                    summary.skipped += 1;
                    continue;
                }
                // Expand each hostname on this sinkhole line.
                let mut any_block = false;
                for host in &hosts {
                    if LOCALHOST_NAMES.contains(host) {
                        summary.skipped += 1;
                        continue;
                    }
                    match Domain::parse(host) {
                        Ok(d) => {
                            sink.block(d);
                            summary.blocked += 1;
                            any_block = true;
                        }
                        Err(_) => {
                            summary.skipped += 1;
                        }
                    }
                }
                if !any_block && !hosts.is_empty() {
                    // All tokens were localhost aliases — already counted above.
                }
                continue;
            }
        }

        // Plain domain
        match Domain::parse(trimmed) {
            Ok(d) => {
                sink.block(d);
                summary.blocked += 1;
            }
            Err(_) => summary.skipped += 1,
        }
    }

    summary
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::rules::RulesBuilder;

    // ── Happy-path format tests ───────────────────────────────────────────────

    #[test]
    fn plain_domain_line() {
        assert_eq!(
            parse_line("example.com"),
            Line::Block(Domain::parse("example.com").unwrap())
        );
    }

    #[test]
    fn adblock_block_basic() {
        assert_eq!(
            parse_line("||ads.example.com^"),
            Line::Block(Domain::parse("ads.example.com").unwrap())
        );
    }

    #[test]
    fn adblock_allow_exception() {
        assert_eq!(
            parse_line("@@||cdn.example.com^"),
            Line::Allow(Domain::parse("cdn.example.com").unwrap())
        );
    }

    #[test]
    fn adblock_block_with_options_ignored() {
        // `$third-party` option must be ignored; the domain rule applies.
        assert_eq!(
            parse_line("||ads.example.com^$third-party"),
            Line::Block(Domain::parse("ads.example.com").unwrap())
        );
    }

    #[test]
    fn adblock_cosmetic_skipped() {
        assert_eq!(
            parse_line("##.ad-banner"),
            Line::Skip(SkipReason::UnsupportedSyntax)
        );
    }

    #[test]
    fn hosts_line_single() {
        assert_eq!(
            parse_line("0.0.0.0 ads.example.com"),
            Line::Block(Domain::parse("ads.example.com").unwrap())
        );
    }

    #[test]
    fn hosts_line_127_variant() {
        assert_eq!(
            parse_line("127.0.0.1 tracker.bad.com"),
            Line::Block(Domain::parse("tracker.bad.com").unwrap())
        );
    }

    #[test]
    fn hosts_line_localhost_skipped() {
        assert_eq!(
            parse_line("127.0.0.1 localhost"),
            Line::Skip(SkipReason::LocalhostEntry)
        );
    }

    #[test]
    fn hosts_line_non_blocking_skipped() {
        assert_eq!(
            parse_line("192.168.1.5 nas"),
            Line::Skip(SkipReason::NonBlockingHostsEntry)
        );
    }

    // ── Comment stripping ─────────────────────────────────────────────────────

    #[test]
    fn hash_comment_at_start() {
        assert_eq!(
            parse_line("# this is a comment"),
            Line::Skip(SkipReason::Empty)
        );
    }

    #[test]
    fn bang_comment() {
        assert_eq!(
            parse_line("! Adblock Plus filter"),
            Line::Skip(SkipReason::Empty)
        );
    }

    #[test]
    fn inline_hash_comment_stripped() {
        // "ads.example.com # comment" → Block(ads.example.com)
        assert_eq!(
            parse_line("ads.example.com # inline comment"),
            Line::Block(Domain::parse("ads.example.com").unwrap())
        );
    }

    // ── Whitespace and edge cases ─────────────────────────────────────────────

    #[test]
    fn whitespace_only() {
        assert_eq!(parse_line("   \t  "), Line::Skip(SkipReason::Empty));
    }

    #[test]
    fn crlf_line_ending() {
        // str::lines() handles CRLF; verify via parse_list on CRLF text.
        let text = "ads.example.com\r\nother.com\r\n";
        let mut builder = RulesBuilder::new();
        let summary = parse_list(text, &mut builder);
        assert_eq!(summary.blocked, 2);
    }

    // ── Multi-host hosts line ─────────────────────────────────────────────────

    #[test]
    fn hosts_line_three_hostnames() {
        let text = "0.0.0.0 a.example.com b.example.com c.example.com\n";
        let mut builder = RulesBuilder::new();
        let summary = parse_list(text, &mut builder);
        assert_eq!(
            summary.blocked, 3,
            "each hostname on a hosts line yields a Block"
        );
    }

    // ── Robustness: no panics on pathological inputs ──────────────────────────

    #[test]
    fn empty_input_no_panic() {
        let mut builder = RulesBuilder::new();
        let summary = parse_list("", &mut builder);
        assert_eq!(summary.blocked, 0);
        assert_eq!(summary.allowed, 0);
    }

    #[test]
    fn large_garbage_no_panic() {
        // 10 MB of garbage — must not panic or OOM.
        let garbage = "x!@#$%^&*()\n".repeat(900_000);
        let mut builder = RulesBuilder::new();
        let summary = parse_list(&garbage, &mut builder);
        // We only care it doesn't panic; counts can be all-skipped.
        let _ = summary;
    }
}
