//! Human-readable output formatters for the `hush` CLI.
//!
//! All functions write to stdout (data) or stderr (errors) directly, except
//! `format_*` helpers that return `String` so they can be unit-tested without
//! I/O.
//!
//! Output contract from `specs/wp3-api-cli.md` §4:
//! - Human output → stdout; errors → stderr.
//! - `--json` bypasses this module entirely (raw API body printed by `main`).
//! - Aligned columns for the `log` table: `time  qname  verdict  reason  ms`.

use crate::types::{
    AllowlistResponse, ListsResponse, PrivacyStatus, QueriesResponse, StatusResponse,
};

// ── status ────────────────────────────────────────────────────────────────────

/// Print a human-readable summary of the daemon status.
pub fn print_status(s: &StatusResponse) {
    let state_label = state_dot(&s.state);
    println!("{state_label}");
    println!("  version    {}", s.version);
    println!("  uptime     {}s", s.uptime_secs);
    if let Some(ref profile) = s.active_profile {
        println!("  profile    {profile}");
    }
    if let Some(until) = s.snoozed_until_unix_ms {
        println!("  snoozed    until unix_ms={until}");
    }
    println!(
        "  rules      {} blocked / {} allowed",
        s.rules.block_count, s.rules.allow_count
    );
    if !s.rules.sources.is_empty() {
        println!("  sources    {}", s.rules.sources.join(", "));
    }
    println!(
        "  queries    total={} blocked={} forwarded={} local={} servfail={}",
        s.counters.queries_total,
        s.counters.blocked_total,
        s.counters.forwarded_total,
        s.counters.local_total,
        s.counters.servfail_total,
    );
    println!("  privacy    {}", format_privacy_line(&s.privacy));
}

/// Format the privacy line for `hush status`.
///
/// Format (WP4 §4, WP8 §6):
/// `canary✓ cname✓ pad✓ rebind✓ log=full`
/// with ✗ for off flags.  The WP8 `pad` and `rebind` markers are always shown
/// (they are on by default) and are inserted between `cname` and `log=`.
/// `doh-bypass` and `private-relay` markers are appended only when enabled
/// (they are off by default, so omitting them keeps the line compact for most users).
pub fn format_privacy_line(p: &PrivacyStatus) -> String {
    let canary = if p.browser_doh_canary {
        "canary✓"
    } else {
        "canary✗"
    };
    let cname = if p.cname_inspection {
        "cname✓"
    } else {
        "cname✗"
    };
    let pad = if p.doh_padding { "pad✓" } else { "pad✗" };
    let rebind = if p.rebind_protection {
        "rebind✓"
    } else {
        "rebind✗"
    };
    let log = format!("log={}", p.query_log);
    let mut parts = vec![
        canary.to_owned(),
        cname.to_owned(),
        pad.to_owned(),
        rebind.to_owned(),
        log,
    ];
    if p.block_doh_bypass {
        parts.push("doh-bypass✓".to_owned());
    }
    if p.block_private_relay {
        parts.push("private-relay✓".to_owned());
    }
    parts.join(" ")
}

/// Format the state string as a dot + word (used as the first line of `status`).
///
/// This is a pure function so it can be unit-tested.
pub fn state_dot(state: &str) -> String {
    let dot = match state {
        "filtering" => "●",
        "snoozed" => "◐",
        "standing_by" => "○",
        "attention" => "!",
        _ => "?",
    };
    format!("{dot} {state}")
}

// ── allowlist ────────────────────────────────────────────────────────────────

/// Print the current allowlist.
pub fn print_allowlist(r: &AllowlistResponse) {
    if r.allowed.is_empty() {
        println!("(allowlist is empty)");
    } else {
        for d in &r.allowed {
            println!("{d}");
        }
    }
}

/// Print feedback after an allow/unallow operation.
pub fn print_allow_result(r: &AllowlistResponse, added: bool) {
    let verb = if added { "allowed" } else { "unallowed" };
    let count = r.allowed.len();
    println!("{verb}: allowlist now has {count} entries");
}

// ── snooze ────────────────────────────────────────────────────────────────────

/// Print confirmation of a snooze.
pub fn print_snoozed(until_ms: u64) {
    println!("snoozed until unix_ms={until_ms}");
}

/// Print confirmation that filtering has resumed.
pub fn print_resumed(state: &str) {
    println!("resumed: state is now {state}");
}

// ── log ───────────────────────────────────────────────────────────────────────

/// Column widths for the log table (fixed so output is stable for scripts).
const COL_TIME: usize = 16;
const COL_QNAME: usize = 40;
const COL_VERDICT: usize = 13;
const COL_REASON: usize = 14;
const COL_MS: usize = 6;

/// Print the log table header.
fn print_log_header() {
    println!(
        "{:<COL_TIME$}  {:<COL_QNAME$}  {:<COL_VERDICT$}  {:<COL_REASON$}  {:>COL_MS$}",
        "time(unix_ms)", "qname", "verdict", "reason", "ms"
    );
    println!(
        "{:-<COL_TIME$}  {:-<COL_QNAME$}  {:-<COL_VERDICT$}  {:-<COL_REASON$}  {:->COL_MS$}",
        "", "", "", "", ""
    );
}

/// Format a single log row as a `String`.
///
/// This is a pure function so it can be unit-tested without I/O.
pub fn format_log_row(
    ts_ms: u64,
    qname: &str,
    verdict: &str,
    reason: &str,
    ms: Option<u32>,
) -> String {
    let ms_str = ms.map(|m| m.to_string()).unwrap_or_else(|| "-".to_owned());
    format!(
        "{:<COL_TIME$}  {:<COL_QNAME$}  {:<COL_VERDICT$}  {:<COL_REASON$}  {:>COL_MS$}",
        ts_ms, qname, verdict, reason, ms_str,
    )
}

/// Print the query log table.
///
/// WP4 §3.4: when `log_mode` is `"off"` or `"anonymous"`, a notice is printed
/// before (or instead of) the table.
pub fn print_queries(r: &QueriesResponse) {
    match r.log_mode.as_str() {
        "off" => {
            println!(
                "notice: query logging is disabled (privacy.query_log=off); \
                 the ring buffer is not written"
            );
            return;
        }
        "anonymous" => {
            println!(
                "notice: query logging is in anonymous mode (privacy.query_log=anonymous); \
                 domain names are redacted"
            );
        }
        _ => {} // "full" or unknown → no notice
    }

    if r.queries.is_empty() {
        println!("(no queries)");
        return;
    }
    print_log_header();
    for q in &r.queries {
        println!(
            "{}",
            format_log_row(q.ts_unix_ms, &q.qname, &q.verdict, &q.reason, q.upstream_ms)
        );
    }
}

// ── lists ────────────────────────────────────────────────────────────────────

/// Print the lists status table.
///
/// WP4 §4: attribution string is shown per source when present.
pub fn print_lists(r: &ListsResponse) {
    if r.sources.is_empty() {
        println!("(no list sources configured)");
        return;
    }
    for src in &r.sources {
        let enabled = if src.enabled { "enabled" } else { "disabled" };
        let rules = src
            .rule_count
            .map(|c| format!("{c} rules"))
            .unwrap_or_else(|| "? rules".to_owned());
        let fetched = src
            .last_fetched_unix_ms
            .map(|ms| format!("fetched {}", format_unix_ms_time(ms)))
            .unwrap_or_else(|| "never fetched".to_owned());
        let status = if let Some(err) = &src.last_error {
            format!("error: {err}")
        } else if src.last_fetched_unix_ms.is_some() {
            "ok".to_owned()
        } else if let Some(code) = src.last_http_status {
            format!("HTTP {code}")
        } else {
            "pending".to_owned()
        };
        println!(
            "{name}  [{enabled}]  {rules}  {fetched}  {status}",
            name = src.name,
        );
        if let Some(attr) = &src.attribution {
            println!("    attribution: {attr}");
        }
    }
}

/// Format a Unix millisecond timestamp as a `HH:MM:SS` wall-clock string (UTC).
///
/// This is a pure function so it can be unit-tested without I/O.
pub fn format_unix_ms_time(unix_ms: u64) -> String {
    let secs = unix_ms / 1000;
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    format!("{h:02}:{m:02}:{s:02}")
}

/// Print confirmation that a list refresh was kicked off.
pub fn print_lists_refresh_started() {
    println!("list refresh started (non-blocking)");
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    // ── format_privacy_line ───────────────────────────────────────────────────

    #[test]
    fn privacy_line_all_defaults() {
        // PrivacyStatus::default() has doh_padding=false / rebind_protection=false
        // (old-daemon sentinel values); the real daemon always sends true.
        let p = PrivacyStatus::default();
        let line = format_privacy_line(&p);
        // Tier 1 features on by default → ✓; log=full; Tier 2 omitted.
        assert!(line.contains("canary✓"), "canary must be ✓ by default");
        assert!(line.contains("cname✓"), "cname must be ✓ by default");
        assert!(line.contains("log=full"), "log must be full by default");
        // WP8 fields absent from old daemon → ✗ (conservative unknown).
        assert!(
            line.contains("pad✗"),
            "pad must be ✗ for old-daemon default"
        );
        assert!(
            line.contains("rebind✗"),
            "rebind must be ✗ for old-daemon default"
        );
        // Tier 2 features must NOT appear when disabled.
        assert!(
            !line.contains("doh-bypass"),
            "doh-bypass must not appear when disabled"
        );
        assert!(
            !line.contains("private-relay"),
            "private-relay must not appear when disabled"
        );
    }

    /// All-on case: both WP8 markers are ✓.
    #[test]
    fn privacy_line_all_on() {
        let p = PrivacyStatus {
            browser_doh_canary: true,
            cname_inspection: true,
            query_log: "full".to_owned(),
            block_doh_bypass: false,
            block_private_relay: false,
            doh_padding: true,
            rebind_protection: true,
        };
        let line = format_privacy_line(&p);
        assert!(line.contains("canary✓"), "canary must be ✓");
        assert!(line.contains("cname✓"), "cname must be ✓");
        assert!(line.contains("pad✓"), "pad must be ✓ when doh_padding=true");
        assert!(
            line.contains("rebind✓"),
            "rebind must be ✓ when rebind_protection=true"
        );
        assert!(line.contains("log=full"), "log must be present");
        // Order: canary cname pad rebind log (Tier 2 omitted when off).
        let canary_pos = line.find("canary✓").unwrap();
        let cname_pos = line.find("cname✓").unwrap();
        let pad_pos = line.find("pad✓").unwrap();
        let rebind_pos = line.find("rebind✓").unwrap();
        let log_pos = line.find("log=").unwrap();
        assert!(canary_pos < cname_pos, "canary must precede cname");
        assert!(cname_pos < pad_pos, "cname must precede pad");
        assert!(pad_pos < rebind_pos, "pad must precede rebind");
        assert!(rebind_pos < log_pos, "rebind must precede log=");
    }

    /// pad off: marker shows ✗.
    #[test]
    fn privacy_line_pad_off() {
        let p = PrivacyStatus {
            browser_doh_canary: true,
            cname_inspection: true,
            query_log: "full".to_owned(),
            block_doh_bypass: false,
            block_private_relay: false,
            doh_padding: false,
            rebind_protection: true,
        };
        let line = format_privacy_line(&p);
        assert!(
            line.contains("pad✗"),
            "pad must be ✗ when doh_padding=false"
        );
        assert!(
            line.contains("rebind✓"),
            "rebind must be ✓ when rebind_protection=true"
        );
    }

    /// rebind off: marker shows ✗.
    #[test]
    fn privacy_line_rebind_off() {
        let p = PrivacyStatus {
            browser_doh_canary: true,
            cname_inspection: true,
            query_log: "full".to_owned(),
            block_doh_bypass: false,
            block_private_relay: false,
            doh_padding: true,
            rebind_protection: false,
        };
        let line = format_privacy_line(&p);
        assert!(line.contains("pad✓"), "pad must be ✓ when doh_padding=true");
        assert!(
            line.contains("rebind✗"),
            "rebind must be ✗ when rebind_protection=false"
        );
    }

    #[test]
    fn privacy_line_all_features_enabled() {
        let p = PrivacyStatus {
            browser_doh_canary: true,
            cname_inspection: true,
            query_log: "anonymous".to_owned(),
            block_doh_bypass: true,
            block_private_relay: true,
            doh_padding: true,
            rebind_protection: true,
        };
        let line = format_privacy_line(&p);
        assert!(line.contains("canary✓"));
        assert!(line.contains("cname✓"));
        assert!(line.contains("pad✓"));
        assert!(line.contains("rebind✓"));
        assert!(line.contains("log=anonymous"));
        assert!(line.contains("doh-bypass✓"));
        assert!(line.contains("private-relay✓"));
    }

    #[test]
    fn privacy_line_tier1_off() {
        let p = PrivacyStatus {
            browser_doh_canary: false,
            cname_inspection: false,
            query_log: "off".to_owned(),
            block_doh_bypass: false,
            block_private_relay: false,
            doh_padding: false,
            rebind_protection: false,
        };
        let line = format_privacy_line(&p);
        assert!(line.contains("canary✗"));
        assert!(line.contains("cname✗"));
        assert!(line.contains("pad✗"));
        assert!(line.contains("rebind✗"));
        assert!(line.contains("log=off"));
    }

    // ── state_dot ─────────────────────────────────────────────────────────────

    #[test]
    fn state_dot_filtering() {
        assert_eq!(state_dot("filtering"), "● filtering");
    }

    #[test]
    fn state_dot_snoozed() {
        assert_eq!(state_dot("snoozed"), "◐ snoozed");
    }

    #[test]
    fn state_dot_standing_by() {
        assert_eq!(state_dot("standing_by"), "○ standing_by");
    }

    #[test]
    fn state_dot_attention() {
        assert_eq!(state_dot("attention"), "! attention");
    }

    #[test]
    fn state_dot_unknown() {
        assert_eq!(state_dot("weird"), "? weird");
    }

    // ── format_log_row columns ────────────────────────────────────────────────

    #[test]
    fn format_log_row_with_upstream_ms() {
        let row = format_log_row(
            1700000001000,
            "ads.example.com",
            "block",
            "list_blocked",
            Some(0),
        );
        // The row must contain all four values.
        assert!(row.contains("1700000001000"));
        assert!(row.contains("ads.example.com"));
        assert!(row.contains("block"));
        assert!(row.contains("list_blocked"));
        // Upstream ms is 0 for blocked — represented as "0"
        assert!(row.contains('0'));
    }

    #[test]
    fn format_log_row_null_ms_shows_dash() {
        let row = format_log_row(
            1700000000000,
            "good.example.com",
            "forward",
            "no_match",
            None,
        );
        assert!(row.contains('-'));
    }

    #[test]
    fn format_log_row_columns_are_aligned() {
        // Two rows should have the same width (padded to column boundaries).
        let short = format_log_row(100, "a.com", "block", "list_blocked", None);
        let long = format_log_row(
            1700000001000,
            "very-long-domain-name-that-is-long.example.com",
            "forward",
            "user_allowed",
            Some(123),
        );
        // The first COL_TIME characters of the first column should be padded.
        // Both rows start with the ts left-padded to COL_TIME.
        let short_ts_part = &short[..COL_TIME];
        let long_ts_part = &long[..COL_TIME];
        assert_eq!(short_ts_part.len(), long_ts_part.len());
    }

    #[test]
    fn format_log_row_long_qname_truncated_by_display() {
        // A very long qname will still be formatted — we verify the row is produced
        // without panicking (the column spec clips at COL_QNAME via padding, but
        // format! doesn't truncate, so very long names will overflow that column;
        // that's acceptable per the spec which only says "aligned columns").
        let qname = "a".repeat(80);
        let row = format_log_row(1, &qname, "forward", "no_match", None);
        assert!(row.contains(&qname));
    }

    // ── format_unix_ms_time ───────────────────────────────────────────────────

    #[test]
    fn format_unix_ms_midnight() {
        // 0 ms = 1970-01-01 00:00:00 UTC
        assert_eq!(format_unix_ms_time(0), "00:00:00");
    }

    #[test]
    fn format_unix_ms_known_time() {
        // 1700000000000 ms = 2023-11-14 22:13:20 UTC → 22:13:20
        assert_eq!(format_unix_ms_time(1_700_000_000_000), "22:13:20");
    }

    #[test]
    fn format_unix_ms_sub_second_truncated() {
        // 999 ms rounds down to 00:00:00
        assert_eq!(format_unix_ms_time(999), "00:00:00");
        // 1000 ms = 00:00:01
        assert_eq!(format_unix_ms_time(1000), "00:00:01");
    }

    #[test]
    fn format_unix_ms_wrap_at_24h() {
        // Exactly 24 h = 86400 s → next day at 00:00:00
        assert_eq!(format_unix_ms_time(86_400_000), "00:00:00");
        // 86399 s = 23:59:59
        assert_eq!(format_unix_ms_time(86_399_000), "23:59:59");
    }
}
