//! Response types for the hushd control API (`/v0` prefix).
//!
//! These structs mirror the JSON contract from `specs/wp3-api-cli.md` §2 and
//! `specs/wp4-privacy.md` §4.  They are the CLI's own deserialization targets
//! — `hush-core` has no dependency on this crate.
//!
//! New WP4 fields use `#[serde(default)]` so the CLI tolerates old daemons
//! that do not yet emit them.

use serde::{Deserialize, Serialize};

// ── /v0/status ────────────────────────────────────────────────────────────────

/// Rule-set statistics embedded in `StatusResponse`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RulesStatus {
    /// Number of blocked domains in the active rule set.
    pub block_count: u64,
    /// Number of allow-exception domains in the active rule set.
    pub allow_count: u64,
    /// Unix timestamp (ms) when the rules were built.
    pub built_unix_ms: u64,
    /// Names of the contributing list sources.
    pub sources: Vec<String>,
}

/// Per-query counters embedded in `StatusResponse`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Counters {
    /// Total queries handled since daemon start.
    pub queries_total: u64,
    /// Queries answered with the sinkhole response.
    pub blocked_total: u64,
    /// Queries forwarded to upstream DoH/Do53.
    pub forwarded_total: u64,
    /// Queries forwarded to the local (DHCP) resolver.
    pub local_total: u64,
    /// Queries that resulted in SERVFAIL.
    pub servfail_total: u64,
}

/// Privacy feature toggles from `GET /v0/status` (WP4 §4, WP8 §6).
///
/// All fields default to their configured defaults so the CLI works against old
/// daemons that do not yet emit the newer fields.  WP8 fields (`doh_padding`,
/// `rebind_protection`) use `#[serde(default)]` which maps to `false` when the
/// field is absent — this is intentionally conservative: an old daemon that does
/// not report these fields renders `✗`, signalling to the user that the feature
/// status is unknown rather than silently showing `✓`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PrivacyStatus {
    /// Whether the browser-DoH canary is active.
    #[serde(default = "bool_true")]
    pub browser_doh_canary: bool,
    /// Whether CNAME-chain inspection is active.
    #[serde(default = "bool_true")]
    pub cname_inspection: bool,
    /// Query-log privacy mode: `"full"`, `"anonymous"`, or `"off"`.
    #[serde(default = "default_full")]
    pub query_log: String,
    /// Whether the DoH-bypass blocklist is active.
    #[serde(default)]
    pub block_doh_bypass: bool,
    /// Whether Private Relay blocking is active.
    #[serde(default)]
    pub block_private_relay: bool,
    /// Whether RFC 8467 EDNS padding is active on encrypted upstream queries
    /// (`specs/wp8-transport-privacy.md` §3).  Defaults to `false` when absent
    /// (old daemon) — renders as `pad✗` to signal unknown status.
    #[serde(default)]
    pub doh_padding: bool,
    /// Whether DNS rebinding protection is active
    /// (`specs/wp8-transport-privacy.md` §4).  Defaults to `false` when absent
    /// (old daemon) — renders as `rebind✗` to signal unknown status.
    #[serde(default)]
    pub rebind_protection: bool,
}

fn bool_true() -> bool {
    true
}

fn default_full() -> String {
    "full".to_owned()
}

impl Default for PrivacyStatus {
    fn default() -> Self {
        Self {
            browser_doh_canary: true,
            cname_inspection: true,
            query_log: "full".to_owned(),
            block_doh_bypass: false,
            block_private_relay: false,
            doh_padding: false,
            rebind_protection: false,
        }
    }
}

/// Response body for `GET /v0/status`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StatusResponse {
    /// Daemon state: one of `"filtering"`, `"snoozed"`, `"standing_by"`, `"attention"`.
    pub state: String,
    /// Unix timestamp (ms) when the current snooze expires; `null` if not snoozed.
    pub snoozed_until_unix_ms: Option<u64>,
    /// Why we are standing by (e.g. `"vpn"`, `"portal"`, `"user_dns"`);
    /// `null` when not in `standing_by` state.
    pub standing_by_reason: Option<String>,
    /// Daemon build / release version string.
    pub version: String,
    /// Seconds since daemon start.
    pub uptime_secs: u64,
    /// Rule-set statistics.
    pub rules: RulesStatus,
    /// Cumulative query counters.
    pub counters: Counters,
    /// Privacy feature toggle status (WP4).  Defaults to WP4 defaults when
    /// the field is absent (old daemon).
    #[serde(default)]
    pub privacy: PrivacyStatus,
    /// Active profile name (WP14 §2); `None` when default config is active.
    #[serde(default)]
    pub active_profile: Option<String>,
}

// ── /v0/queries/recent ────────────────────────────────────────────────────────

/// A single DNS query record returned by `GET /v0/queries/recent`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct QueryRecord {
    /// Unix timestamp of the query in milliseconds.
    pub ts_unix_ms: u64,
    /// The queried domain name (forward form, no trailing dot).
    pub qname: String,
    /// DNS query type (e.g. 1 = A, 28 = AAAA).
    pub qtype: u16,
    /// Decision engine verdict: `"block"`, `"forward"`, or `"forward_local"`.
    pub verdict: String,
    /// Why the verdict was produced (e.g. `"list_blocked"`, `"user_allowed"`).
    pub reason: String,
    /// Upstream round-trip in milliseconds; `null` for blocked queries.
    pub upstream_ms: Option<u32>,
}

/// Response body for `GET /v0/queries/recent`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct QueriesResponse {
    /// Records, newest first, at most `n` (clamped to [1, 1000] server-side).
    pub queries: Vec<QueryRecord>,
    /// Query-log privacy mode: `"full"`, `"anonymous"`, or `"off"` (WP4 §3.4).
    /// Defaults to `"full"` when absent (old daemon).
    #[serde(default = "default_full")]
    pub log_mode: String,
}

// ── /v0/stats/summary ─────────────────────────────────────────────────────────

/// Response body for `GET /v0/stats/summary`.
///
/// Not yet surfaced as a CLI verb; defined here for completeness of the API
/// contract (`specs/wp3-api-cli.md` §2) and tested via deserialization below.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[allow(dead_code)]
pub struct StatsSummaryResponse {
    /// Start of the measurement window (Unix ms).
    pub since_unix_ms: u64,
    /// Total queries in the window.
    pub queries_total: u64,
    /// Blocked queries in the window.
    pub blocked_total: u64,
    /// Fraction of queries blocked (0.0–1.0).
    pub block_rate: f32,
}

// ── /v0/snooze ────────────────────────────────────────────────────────────────

/// Response body for `POST /v0/snooze`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SnoozeResponse {
    /// Unix timestamp (ms) when the snooze expires.
    pub snoozed_until_unix_ms: u64,
}

// ── /v0/resume ────────────────────────────────────────────────────────────────

/// Response body for `POST /v0/resume`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResumeResponse {
    /// New daemon state after resuming (should be `"filtering"`).
    pub state: String,
}

// ── /v0/allow, /v0/unallow, /v0/allowlist ────────────────────────────────────

/// Response body for `POST /v0/allow`, `POST /v0/unallow`, and
/// `GET /v0/allowlist`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AllowlistResponse {
    /// Full allowlist after the operation.
    pub allowed: Vec<String>,
}

// ── /v0/lists ─────────────────────────────────────────────────────────────────

/// Status for a single list source, embedded in `ListsResponse`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ListSourceStatus {
    /// Human-readable source name.
    pub name: String,
    /// Whether the source is enabled.
    pub enabled: bool,
    /// Number of rules loaded from this source; `null` if not yet fetched.
    pub rule_count: Option<u64>,
    /// Unix timestamp (ms) of the last successful fetch; `null` if never fetched.
    pub last_fetched_unix_ms: Option<u64>,
    /// HTTP status from the last fetch attempt; `null` if never attempted.
    pub last_http_status: Option<u16>,
    /// Error message from the last fetch attempt; `null` if last fetch succeeded.
    pub last_error: Option<String>,
    /// Catalog category key (e.g. `"hagezi-normal"`) for catalog sources (WP4 §4).
    /// `null` for user-custom sources not in the compiled-in catalog.
    #[serde(default)]
    pub category: Option<String>,
    /// License string for catalog sources; `null` when not stated or user-custom (WP4 §4).
    #[serde(default)]
    pub license: Option<String>,
    /// Attribution/credit string for catalog sources; `null` for user-custom sources (WP4 §4).
    #[serde(default)]
    pub attribution: Option<String>,
}

/// Response body for `GET /v0/lists`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ListsResponse {
    /// The configured list preset (WP4 §4).  Defaults to `"balanced"` when absent.
    #[serde(default = "default_balanced")]
    pub preset: String,
    /// Per-source status records.
    pub sources: Vec<ListSourceStatus>,
}

fn default_balanced() -> String {
    "balanced".to_owned()
}

// ── /v0/lists/refresh ────────────────────────────────────────────────────────

/// Response body for `POST /v0/lists/refresh`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ListsRefreshResponse {
    /// Always `true`; indicates the refresh task was kicked off.
    pub started: bool,
}

// ── /v0/takeover + /v0/restore ────────────────────────────────────────────────

/// Response body for `POST /v0/takeover`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TakeoverResponse {
    /// Whether the takeover succeeded.
    pub success: bool,
    /// Optional error message on failure.
    pub error: Option<String>,
}

/// Response body for `POST /v0/restore`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RestoreResponse {
    /// Whether the restore succeeded.
    pub success: bool,
    /// Optional error message on failure.
    pub error: Option<String>,
}

// ── /v0/config/reload (WP14 §2) ──────────────────────────────────────────────

/// Response body for `POST /v0/config/reload`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConfigReloadResponse {
    /// Config sections applied immediately without restart.
    pub applied: Vec<String>,
    /// Config sections that require a daemon restart to take effect.
    pub requires_restart: Vec<String>,
}

// ── /v0/profiles (WP14 §2) ───────────────────────────────────────────────────

/// A single profile entry.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProfileEntry {
    /// Profile name.
    pub name: String,
    /// Whether this is the currently active profile.
    pub active: bool,
}

/// Response body for `GET /v0/profiles`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProfilesResponse {
    /// Available profiles.
    pub profiles: Vec<ProfileEntry>,
    /// Currently active profile; `None` when no profile is active.
    pub active: Option<String>,
}

/// Response body for `GET /v0/profiles/:name`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProfileResponse {
    /// Profile name.
    pub name: String,
    /// Raw TOML content.
    pub content: String,
}

// ── Error shape ───────────────────────────────────────────────────────────────

/// Generic error body returned by the API for 4xx/5xx responses.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApiErrorBody {
    /// Short error code (e.g. `"unauthorized"`, `"invalid_body"`).
    pub error: String,
    /// Optional human-readable detail.
    pub detail: Option<String>,
}
