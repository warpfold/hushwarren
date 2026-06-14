//! HTTP client for the hushd control API.
//!
//! Wraps `reqwest` with bearer-token auth, typed endpoints, and translates
//! HTTP-level errors into the two exit-code categories defined in
//! `specs/wp3-api-cli.md` §4:
//!
//! - [`ClientError::ApiError`]  → exit 1 (server returned 4xx/5xx with a body)
//! - [`ClientError::Unreachable`] → exit 2 (connection refused / timeout)

use reqwest::{header, Client};
use serde::de::DeserializeOwned;
use thiserror::Error;

use crate::types::{
    AllowlistResponse, ApiErrorBody, ConfigReloadResponse, ListsRefreshResponse, ListsResponse,
    ProfileResponse, ProfilesResponse, QueriesResponse, RestoreResponse, ResumeResponse,
    SnoozeResponse, StatusResponse, TakeoverResponse,
};

/// Errors returned by [`ApiClient`] methods.
#[derive(Debug, Error)]
pub enum ClientError {
    /// The daemon returned a 4xx or 5xx status code.
    /// The `message` field is the `error` (and optional `detail`) from the JSON body.
    #[error("API error: {message}")]
    ApiError { message: String },

    /// The daemon could not be reached (connection refused, host unreachable, etc.).
    /// The `addr` is what was looked at — used in the user-facing "isn't running" message.
    #[error("cannot connect to {addr}: {cause}")]
    Unreachable { addr: String, cause: String },

    /// Unexpected error (malformed JSON, I/O, etc.) — maps to exit 1.
    #[error("unexpected error: {0}")]
    Other(#[from] anyhow::Error),
}

/// Typed client for the hushd `/v0` control API.
///
/// Constructed once per CLI invocation; all methods are `async` and borrow
/// `&self`.
pub struct ApiClient {
    inner: Client,
    base_url: String,
    token: String,
}

impl ApiClient {
    /// Create a new client.
    ///
    /// `base_url` must NOT have a trailing slash (e.g. `http://127.0.0.1:5380`).
    pub fn new(base_url: String, token: String) -> Result<Self, ClientError> {
        let inner = Client::builder()
            .build()
            .map_err(|e| ClientError::Other(anyhow::anyhow!("failed to build HTTP client: {e}")))?;
        Ok(Self {
            inner,
            base_url,
            token,
        })
    }

    // ── GET helpers ───────────────────────────────────────────────────────────

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, ClientError> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .inner
            .get(&url)
            .header(header::AUTHORIZATION, format!("Bearer {}", self.token))
            .send()
            .await
            .map_err(|e| self.map_reqwest_error(e))?;

        self.parse_response(resp).await
    }

    // ── POST helpers ──────────────────────────────────────────────────────────

    async fn post_json<B: serde::Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, ClientError> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .inner
            .post(&url)
            .header(header::AUTHORIZATION, format!("Bearer {}", self.token))
            .json(body)
            .send()
            .await
            .map_err(|e| self.map_reqwest_error(e))?;

        self.parse_response(resp).await
    }

    async fn post_empty<T: DeserializeOwned>(&self, path: &str) -> Result<T, ClientError> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .inner
            .post(&url)
            .header(header::AUTHORIZATION, format!("Bearer {}", self.token))
            .header(header::CONTENT_LENGTH, "0")
            .send()
            .await
            .map_err(|e| self.map_reqwest_error(e))?;

        self.parse_response(resp).await
    }

    // ── Response parsing ──────────────────────────────────────────────────────

    async fn parse_response<T: DeserializeOwned>(
        &self,
        resp: reqwest::Response,
    ) -> Result<T, ClientError> {
        let status = resp.status();
        let body_bytes = resp.bytes().await.map_err(|e| {
            ClientError::Other(anyhow::anyhow!("failed to read response body: {e}"))
        })?;

        if status.is_success() {
            serde_json::from_slice::<T>(&body_bytes).map_err(|e| {
                ClientError::Other(anyhow::anyhow!(
                    "malformed JSON from server (status {status}): {e}"
                ))
            })
        } else {
            // Try to extract the error body; fall back to raw text.
            let message = if let Ok(err_body) = serde_json::from_slice::<ApiErrorBody>(&body_bytes)
            {
                match err_body.detail {
                    Some(d) => format!("{}: {d}", err_body.error),
                    None => err_body.error,
                }
            } else {
                format!(
                    "HTTP {status}: {}",
                    String::from_utf8_lossy(&body_bytes).trim()
                )
            };
            Err(ClientError::ApiError { message })
        }
    }

    // ── Error mapping ─────────────────────────────────────────────────────────

    fn map_reqwest_error(&self, e: reqwest::Error) -> ClientError {
        // reqwest surfaces connection-refused as an "error sending request"
        // that contains a hyper source.  We treat any connect-level failure as
        // Unreachable (exit 2).
        let is_connect = e.is_connect() || e.is_timeout();
        if is_connect {
            ClientError::Unreachable {
                addr: self
                    .base_url
                    .trim_start_matches("http://")
                    .trim_start_matches("https://")
                    .to_owned(),
                cause: e.to_string(),
            }
        } else {
            ClientError::Other(anyhow::anyhow!("{e}"))
        }
    }

    // ── Typed endpoint methods ────────────────────────────────────────────────

    /// `GET /v0/status`
    pub async fn status(&self) -> Result<StatusResponse, ClientError> {
        self.get("/v0/status").await
    }

    /// `GET /v0/queries/recent?n=<n>&blocked_only=<blocked_only>`
    pub async fn queries_recent(
        &self,
        n: u32,
        blocked_only: bool,
    ) -> Result<QueriesResponse, ClientError> {
        let path = format!("/v0/queries/recent?n={n}&blocked_only={blocked_only}");
        self.get(&path).await
    }

    /// `POST /v0/snooze` with `{secs: u64}`
    pub async fn snooze(&self, secs: u64) -> Result<SnoozeResponse, ClientError> {
        #[derive(serde::Serialize)]
        struct Body {
            secs: u64,
        }
        self.post_json("/v0/snooze", &Body { secs }).await
    }

    /// `POST /v0/resume`
    pub async fn resume(&self) -> Result<ResumeResponse, ClientError> {
        self.post_empty("/v0/resume").await
    }

    /// `POST /v0/allow` with `{domain: string}`
    pub async fn allow(&self, domain: &str) -> Result<AllowlistResponse, ClientError> {
        #[derive(serde::Serialize)]
        struct Body<'a> {
            domain: &'a str,
        }
        self.post_json("/v0/allow", &Body { domain }).await
    }

    /// `POST /v0/unallow` with `{domain: string}`
    pub async fn unallow(&self, domain: &str) -> Result<AllowlistResponse, ClientError> {
        #[derive(serde::Serialize)]
        struct Body<'a> {
            domain: &'a str,
        }
        self.post_json("/v0/unallow", &Body { domain }).await
    }

    /// `GET /v0/allowlist`
    pub async fn allowlist(&self) -> Result<AllowlistResponse, ClientError> {
        self.get("/v0/allowlist").await
    }

    /// `GET /v0/lists`
    pub async fn lists(&self) -> Result<ListsResponse, ClientError> {
        self.get("/v0/lists").await
    }

    /// `POST /v0/lists/refresh`
    pub async fn lists_refresh(&self) -> Result<ListsRefreshResponse, ClientError> {
        self.post_empty("/v0/lists/refresh").await
    }

    /// `POST /v0/takeover` — execute the DNS takeover transaction.
    pub async fn takeover(&self) -> Result<TakeoverResponse, ClientError> {
        self.post_empty("/v0/takeover").await
    }

    /// `POST /v0/restore` — restore DNS settings from snapshot.
    pub async fn restore(&self) -> Result<RestoreResponse, ClientError> {
        self.post_empty("/v0/restore").await
    }

    /// `POST /v0/config/reload` — hot-reload a named profile (WP14 §2).
    pub async fn config_reload(
        &self,
        profile: Option<&str>,
    ) -> Result<ConfigReloadResponse, ClientError> {
        #[derive(serde::Serialize)]
        struct Body<'a> {
            #[serde(skip_serializing_if = "Option::is_none")]
            profile: Option<&'a str>,
        }
        self.post_json("/v0/config/reload", &Body { profile }).await
    }

    /// `GET /v0/profiles` — list available profiles (WP14 §2).
    pub async fn profiles_list(&self) -> Result<ProfilesResponse, ClientError> {
        self.get("/v0/profiles").await
    }

    /// `GET /v0/profiles/:name` — show profile TOML content (WP14 §2).
    pub async fn profile_show(&self, name: &str) -> Result<ProfileResponse, ClientError> {
        self.get(&format!("/v0/profiles/{name}")).await
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::types::StatsSummaryResponse;

    #[test]
    fn client_constructs_without_error() {
        // Just verifies that building the reqwest Client doesn't panic / error
        // on the target platform.
        let c = ApiClient::new("http://127.0.0.1:9999".to_owned(), "tok".to_owned());
        assert!(c.is_ok());
    }

    // ── Response deserialization tests ────────────────────────────────────────

    #[test]
    fn deserialize_status_response() {
        let json = r#"{
            "state": "filtering",
            "snoozed_until_unix_ms": null,
            "version": "0.0.1",
            "uptime_secs": 42,
            "rules": {
                "block_count": 100,
                "allow_count": 5,
                "built_unix_ms": 1700000000000,
                "sources": ["oisd-small"]
            },
            "counters": {
                "queries_total": 200,
                "blocked_total": 50,
                "forwarded_total": 145,
                "local_total": 5,
                "servfail_total": 0
            }
        }"#;
        let r: StatusResponse = serde_json::from_str(json).unwrap();
        assert_eq!(r.state, "filtering");
        assert_eq!(r.snoozed_until_unix_ms, None);
        assert_eq!(r.rules.block_count, 100);
        assert_eq!(r.counters.blocked_total, 50);
    }

    #[test]
    fn deserialize_status_snoozed() {
        let json = r#"{
            "state": "snoozed",
            "snoozed_until_unix_ms": 9999999999000,
            "version": "0.0.1",
            "uptime_secs": 10,
            "rules": {"block_count":0,"allow_count":0,"built_unix_ms":0,"sources":[]},
            "counters": {"queries_total":0,"blocked_total":0,"forwarded_total":0,"local_total":0,"servfail_total":0}
        }"#;
        let r: StatusResponse = serde_json::from_str(json).unwrap();
        assert_eq!(r.state, "snoozed");
        assert_eq!(r.snoozed_until_unix_ms, Some(9999999999000));
    }

    #[test]
    fn deserialize_queries_response() {
        let json = r#"{
            "queries": [
                {
                    "ts_unix_ms": 1700000001000,
                    "qname": "ads.example.com",
                    "qtype": 1,
                    "verdict": "block",
                    "reason": "list_blocked",
                    "upstream_ms": null
                },
                {
                    "ts_unix_ms": 1700000000000,
                    "qname": "good.example.com",
                    "qtype": 28,
                    "verdict": "forward",
                    "reason": "no_match",
                    "upstream_ms": 12
                }
            ]
        }"#;
        let r: QueriesResponse = serde_json::from_str(json).unwrap();
        assert_eq!(r.queries.len(), 2);
        assert_eq!(r.queries[0].qname, "ads.example.com");
        assert_eq!(r.queries[0].upstream_ms, None);
        assert_eq!(r.queries[1].upstream_ms, Some(12));
    }

    #[test]
    fn deserialize_stats_summary_response() {
        let json = r#"{
            "since_unix_ms": 1700000000000,
            "queries_total": 1000,
            "blocked_total": 300,
            "block_rate": 0.3
        }"#;
        let r: StatsSummaryResponse = serde_json::from_str(json).unwrap();
        assert_eq!(r.queries_total, 1000);
        assert!((r.block_rate - 0.3).abs() < 0.001);
    }

    #[test]
    fn deserialize_snooze_response() {
        let json = r#"{"snoozed_until_unix_ms": 9999999999000}"#;
        let r: SnoozeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(r.snoozed_until_unix_ms, 9999999999000);
    }

    #[test]
    fn deserialize_resume_response() {
        let json = r#"{"state": "filtering"}"#;
        let r: ResumeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(r.state, "filtering");
    }

    #[test]
    fn deserialize_allowlist_response() {
        let json = r#"{"allowed": ["example.com", "good.org"]}"#;
        let r: AllowlistResponse = serde_json::from_str(json).unwrap();
        assert_eq!(r.allowed, vec!["example.com", "good.org"]);
    }

    #[test]
    fn deserialize_lists_response() {
        let json = r#"{
            "sources": [
                {
                    "name": "oisd-small",
                    "enabled": true,
                    "rule_count": 50000,
                    "last_fetched_unix_ms": 1700000000000,
                    "last_http_status": 200,
                    "last_error": null
                }
            ]
        }"#;
        let r: ListsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(r.sources.len(), 1);
        assert_eq!(r.sources[0].name, "oisd-small");
        assert_eq!(r.sources[0].rule_count, Some(50000));
    }

    #[test]
    fn deserialize_lists_refresh_response() {
        let json = r#"{"started": true}"#;
        let r: ListsRefreshResponse = serde_json::from_str(json).unwrap();
        assert!(r.started);
    }

    #[test]
    fn deserialize_api_error_body_no_detail() {
        let json = r#"{"error": "unauthorized"}"#;
        let r: ApiErrorBody = serde_json::from_str(json).unwrap();
        assert_eq!(r.error, "unauthorized");
        assert_eq!(r.detail, None);
    }

    #[test]
    fn deserialize_api_error_body_with_detail() {
        let json = r#"{"error": "invalid_body", "detail": "domain is required"}"#;
        let r: ApiErrorBody = serde_json::from_str(json).unwrap();
        assert_eq!(r.error, "invalid_body");
        assert_eq!(r.detail, Some("domain is required".to_owned()));
    }

    // ── ClientError is_connect detection ─────────────────────────────────────

    #[test]
    fn status_code_success_range() {
        use reqwest::StatusCode;
        assert!(StatusCode::OK.is_success());
        assert!(StatusCode::ACCEPTED.is_success());
        assert!(!StatusCode::BAD_REQUEST.is_success());
        assert!(!StatusCode::UNAUTHORIZED.is_success());
    }
}
