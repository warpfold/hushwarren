//! Blocking HTTP client for the hushd control API (tray subset).
//!
//! Implements `specs/wp10-tray.md` §2 polling + snooze/resume actions.
//!
//! # Why `reqwest::blocking`?
//!
//! The tray's macOS event loop (`tao`) must own the main thread.  Polling runs
//! in a background `std::thread` (spawned by `main.rs`) that calls the daemon
//! every 5 s.  Using `reqwest::blocking` keeps that thread free of an async
//! runtime, avoids the multi-runtime pitfall (`reqwest::blocking` panics if
//! called from inside a tokio context), and matches the workspace's existing
//! reqwest config (`default-features = false`, `rustls-tls-native-roots`).
//!
//! Bearer-token header scheme mirrors `crates/cli/src/client.rs`.

use reqwest::{blocking::Client, header};
use thiserror::Error;

use crate::state::StatusResponse;

/// Errors from the tray HTTP client.
#[derive(Debug, Error)]
pub enum ClientError {
    /// The daemon could not be reached (connection refused, timeout, etc.).
    /// Maps to the "grey / not running" dot state.
    #[error("cannot reach daemon at {addr}: {cause}")]
    Unreachable {
        /// The address that was tried.
        addr: String,
        /// Underlying error description.
        cause: String,
    },
    /// The daemon returned a non-success status code.
    #[error("API error {status}: {message}")]
    ApiError {
        /// HTTP status.
        status: u16,
        /// Error body or raw text.
        message: String,
    },
    /// Unexpected error (malformed JSON, TLS, etc.).
    #[error("unexpected error: {0}")]
    Other(String),
}

/// Blocking HTTP client for the `/v0` control API (tray-specific subset).
pub struct TrayClient {
    inner: Client,
    base_url: String,
    token: String,
}

impl TrayClient {
    /// Construct a new client.
    ///
    /// `base_url` must NOT have a trailing slash (e.g. `http://127.0.0.1:5380`).
    pub fn new(base_url: String, token: String) -> Result<Self, ClientError> {
        let inner = Client::builder()
            .timeout(std::time::Duration::from_secs(4))
            .build()
            .map_err(|e| ClientError::Other(format!("failed to build HTTP client: {e}")))?;
        Ok(Self {
            inner,
            base_url,
            token,
        })
    }

    /// `GET /v0/status` — returns the parsed response or a [`ClientError`].
    ///
    /// Connection failures produce [`ClientError::Unreachable`] so the caller
    /// can render the grey "not running" dot without treating it as a fatal error.
    pub fn get_status(&self) -> Result<StatusResponse, ClientError> {
        let url = format!("{}/v0/status", self.base_url);
        let resp = self
            .inner
            .get(&url)
            .header(header::AUTHORIZATION, format!("Bearer {}", self.token))
            .send()
            .map_err(|e| self.map_reqwest_error(e))?;

        let status = resp.status();
        let body = resp
            .text()
            .map_err(|e| ClientError::Other(format!("failed to read body: {e}")))?;

        if status.is_success() {
            serde_json::from_str::<StatusResponse>(&body)
                .map_err(|e| ClientError::Other(format!("malformed JSON from daemon: {e}")))
        } else {
            Err(ClientError::ApiError {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// `POST /v0/snooze` with `{"secs": secs}`.
    ///
    /// `secs` must be in `[1, 86400]` (daemon enforces; we pass through).
    ///
    /// Called from the macOS tray menu; the headless `--once` path never snoozes.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fn snooze(&self, secs: u64) -> Result<(), ClientError> {
        let url = format!("{}/v0/snooze", self.base_url);
        let body = format!("{{\"secs\":{secs}}}");
        let resp = self
            .inner
            .post(&url)
            .header(header::AUTHORIZATION, format!("Bearer {}", self.token))
            .header(header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .map_err(|e| self.map_reqwest_error(e))?;

        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status().as_u16();
            let message = resp.text().unwrap_or_default();
            Err(ClientError::ApiError { status, message })
        }
    }

    /// `POST /v0/resume` — clear the active snooze.
    ///
    /// The daemon's unsnooze contract (verified in `routes.rs`): `POST /v0/resume`
    /// calls `sentinel.resume()` and returns the new state.  Secs=0 is NOT the
    /// unsnooze path — `/v0/resume` is the correct endpoint.
    ///
    /// Called from the macOS tray menu; the headless `--once` path never resumes.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fn resume(&self) -> Result<(), ClientError> {
        let url = format!("{}/v0/resume", self.base_url);
        let resp = self
            .inner
            .post(&url)
            .header(header::AUTHORIZATION, format!("Bearer {}", self.token))
            .header(header::CONTENT_LENGTH, "0")
            .send()
            .map_err(|e| self.map_reqwest_error(e))?;

        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status().as_u16();
            let message = resp.text().unwrap_or_default();
            Err(ClientError::ApiError { status, message })
        }
    }

    // ── Error mapping ─────────────────────────────────────────────────────────

    fn map_reqwest_error(&self, e: reqwest::Error) -> ClientError {
        if e.is_connect() || e.is_timeout() {
            ClientError::Unreachable {
                addr: self
                    .base_url
                    .trim_start_matches("http://")
                    .trim_start_matches("https://")
                    .to_owned(),
                cause: e.to_string(),
            }
        } else {
            ClientError::Other(e.to_string())
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn client_constructs_without_error() {
        let c = TrayClient::new("http://127.0.0.1:9999".to_owned(), "tok".to_owned());
        assert!(c.is_ok());
    }

    // ── Verify StatusResponse deserialization for all guard states ────────────

    #[test]
    fn deserialize_filtering_status() {
        let json = r#"{
            "state": "filtering",
            "snoozed_until_unix_ms": null,
            "counters": {"queries_total": 500, "blocked_total": 100}
        }"#;
        let r: StatusResponse = serde_json::from_str(json).unwrap();
        assert_eq!(r.state, "filtering");
        assert_eq!(r.counters.blocked_total, 100);
    }

    #[test]
    fn deserialize_snoozed_status() {
        let json = r#"{
            "state": "snoozed",
            "snoozed_until_unix_ms": 9999999999000,
            "counters": {"queries_total": 0, "blocked_total": 0}
        }"#;
        let r: StatusResponse = serde_json::from_str(json).unwrap();
        assert_eq!(r.state, "snoozed");
        assert_eq!(r.snoozed_until_unix_ms, Some(9_999_999_999_000));
    }

    #[test]
    fn deserialize_standing_by_status() {
        let json = r#"{
            "state": "standing_by",
            "snoozed_until_unix_ms": null,
            "counters": {"queries_total": 0, "blocked_total": 0}
        }"#;
        let r: StatusResponse = serde_json::from_str(json).unwrap();
        assert_eq!(r.state, "standing_by");
    }

    #[test]
    fn deserialize_attention_status() {
        let json = r#"{
            "state": "attention",
            "snoozed_until_unix_ms": null,
            "counters": {"queries_total": 0, "blocked_total": 0}
        }"#;
        let r: StatusResponse = serde_json::from_str(json).unwrap();
        assert_eq!(r.state, "attention");
    }

    // ── Extra fields in the JSON are tolerated ────────────────────────────────

    #[test]
    fn extra_fields_are_tolerated() {
        let json = r#"{
            "state": "filtering",
            "snoozed_until_unix_ms": null,
            "standing_by_reason": null,
            "version": "0.0.1",
            "uptime_secs": 999,
            "rules": {"block_count": 0, "allow_count": 0, "built_unix_ms": 0, "sources": []},
            "counters": {"queries_total": 10, "blocked_total": 2,
                         "forwarded_total": 8, "local_total": 0, "servfail_total": 0},
            "privacy": {}
        }"#;
        // serde should ignore unknown fields (no deny_unknown_fields on this type)
        let r: StatusResponse = serde_json::from_str(json).unwrap();
        assert_eq!(r.state, "filtering");
        assert_eq!(r.counters.blocked_total, 2);
    }
}
