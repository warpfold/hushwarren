//! Duration string parser for the `hush snooze` subcommand.
//!
//! Accepted formats per `specs/wp3-api-cli.md` §4:
//! - `"off"` — clear snooze (maps to `SnoozeDuration::Off`)
//! - `Nm`    — N minutes (e.g. `5m`, `30m`)
//! - `Nh`    — N hours   (e.g. `2h`)
//! - `Ns`    — N seconds (e.g. `90s`)
//!
//! The value is clamped server-side to [1, 86400] seconds; the client sends
//! whatever value is parsed without further bounds checks (error will come from
//! the API with exit 1, which is correct behaviour).

use std::fmt;

/// The result of parsing a snooze duration string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnoozeDuration {
    /// Clear the current snooze (call `POST /v0/resume`).
    Off,
    /// Snooze for exactly `secs` seconds.
    Secs(u64),
}

/// Parse error for duration strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseDurationError {
    pub input: String,
}

impl fmt::Display for ParseDurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid duration {:?}; expected 'off', or a number followed by s/m/h (e.g. 5m, 2h, 90s)",
            self.input
        )
    }
}

/// Parse a snooze duration string.
///
/// Returns `Ok(SnoozeDuration::Off)` for `"off"`.
/// Returns `Ok(SnoozeDuration::Secs(n))` for `"Nm"`, `"Nh"`, `"Ns"`.
/// Returns `Err` for anything else.
pub fn parse_duration(input: &str) -> Result<SnoozeDuration, ParseDurationError> {
    let s = input.trim();
    if s.eq_ignore_ascii_case("off") {
        return Ok(SnoozeDuration::Off);
    }

    // Must end with a unit suffix.
    let (num_str, multiplier) = if let Some(prefix) = s.strip_suffix('m') {
        (prefix, 60u64)
    } else if let Some(prefix) = s.strip_suffix('h') {
        (prefix, 3600u64)
    } else if let Some(prefix) = s.strip_suffix('s') {
        (prefix, 1u64)
    } else {
        return Err(ParseDurationError {
            input: input.to_owned(),
        });
    };

    let n: u64 = num_str.parse().map_err(|_| ParseDurationError {
        input: input.to_owned(),
    })?;

    let secs = n
        .checked_mul(multiplier)
        .ok_or_else(|| ParseDurationError {
            input: input.to_owned(),
        })?;

    Ok(SnoozeDuration::Secs(secs))
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    // ── Happy paths ───────────────────────────────────────────────────────────

    #[test]
    fn off_lowercase() {
        assert_eq!(parse_duration("off"), Ok(SnoozeDuration::Off));
    }

    #[test]
    fn off_uppercase() {
        assert_eq!(parse_duration("OFF"), Ok(SnoozeDuration::Off));
    }

    #[test]
    fn off_mixed_case() {
        assert_eq!(parse_duration("Off"), Ok(SnoozeDuration::Off));
    }

    #[test]
    fn five_minutes() {
        assert_eq!(parse_duration("5m"), Ok(SnoozeDuration::Secs(300)));
    }

    #[test]
    fn thirty_minutes() {
        assert_eq!(parse_duration("30m"), Ok(SnoozeDuration::Secs(1800)));
    }

    #[test]
    fn two_hours() {
        assert_eq!(parse_duration("2h"), Ok(SnoozeDuration::Secs(7200)));
    }

    #[test]
    fn ninety_seconds() {
        assert_eq!(parse_duration("90s"), Ok(SnoozeDuration::Secs(90)));
    }

    #[test]
    fn one_second() {
        assert_eq!(parse_duration("1s"), Ok(SnoozeDuration::Secs(1)));
    }

    #[test]
    fn one_minute() {
        assert_eq!(parse_duration("1m"), Ok(SnoozeDuration::Secs(60)));
    }

    #[test]
    fn one_hour() {
        assert_eq!(parse_duration("1h"), Ok(SnoozeDuration::Secs(3600)));
    }

    #[test]
    fn whitespace_trimmed() {
        assert_eq!(parse_duration(" 5m "), Ok(SnoozeDuration::Secs(300)));
    }

    // ── Error paths ──────────────────────────────────────────────────────────

    #[test]
    fn garbage_string_errors() {
        assert!(parse_duration("garbage").is_err());
    }

    #[test]
    fn bare_number_errors() {
        assert!(parse_duration("300").is_err());
    }

    #[test]
    fn empty_string_errors() {
        assert!(parse_duration("").is_err());
    }

    #[test]
    fn negative_not_accepted() {
        // "-5m" → strip_suffix('m') → "-5" → parse::<u64>() fails
        assert!(parse_duration("-5m").is_err());
    }

    #[test]
    fn non_integer_errors() {
        assert!(parse_duration("1.5h").is_err());
    }

    #[test]
    fn zero_seconds_is_accepted_as_zero_secs() {
        // 0 is valid to parse; server will reject it with 400 (out of [1,86400]).
        assert_eq!(parse_duration("0s"), Ok(SnoozeDuration::Secs(0)));
    }

    #[test]
    fn error_message_contains_input() {
        let err = parse_duration("garbage").unwrap_err();
        assert!(err.to_string().contains("garbage"));
    }

    // ── spec-listed canonical inputs ─────────────────────────────────────────

    #[test]
    fn spec_canonical_5m() {
        assert_eq!(parse_duration("5m"), Ok(SnoozeDuration::Secs(300)));
    }

    #[test]
    fn spec_canonical_30m() {
        assert_eq!(parse_duration("30m"), Ok(SnoozeDuration::Secs(1800)));
    }

    #[test]
    fn spec_canonical_2h() {
        assert_eq!(parse_duration("2h"), Ok(SnoozeDuration::Secs(7200)));
    }
}
