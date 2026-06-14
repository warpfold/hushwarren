//! JSON request/response types for the control API (`/v0`).
//!
//! Implements `specs/wp3-api-cli.md` §2 and `specs/wp4-privacy.md` §4 wire
//! shapes.  These are the daemon's serialisation targets — they must match the
//! CLI's `crates/cli/src/types.rs` deserialization shapes exactly.  When the
//! two diverge the spec is authoritative.

use serde::{Deserialize, Serialize};

// ── /v0/status ────────────────────────────────────────────────────────────────

/// Rule-set statistics embedded in [`StatusBody`].
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Per-query counters embedded in [`StatusBody`].
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Privacy feature toggles embedded in [`StatusBody`].
///
/// Implements `specs/wp4-privacy.md` §4 and `specs/wp8-transport-privacy.md` §6 —
/// additive surface update for `GET /v0/status`.
#[derive(Debug, Clone, Serialize)]
pub struct PrivacyStatus {
    /// Whether the browser-DoH canary (`use-application-dns.net`) responds
    /// with NXDOMAIN.  Corresponds to `[privacy].browser_doh_canary`.
    pub browser_doh_canary: bool,
    /// Whether CNAME-chain inspection is active.
    /// Corresponds to `[privacy].cname_inspection`.
    pub cname_inspection: bool,
    /// Query-log privacy mode: `"full"`, `"anonymous"`, or `"off"`.
    /// Corresponds to `[privacy].query_log`.
    pub query_log: String,
    /// Whether the DoH-bypass blocklist is active.
    /// Corresponds to `[privacy].block_doh_bypass`.
    pub block_doh_bypass: bool,
    /// Whether Private Relay blocking is active.
    /// Corresponds to `[privacy].block_private_relay`.
    pub block_private_relay: bool,
    /// Whether RFC 8467 EDNS padding is active on encrypted upstream queries.
    /// Corresponds to `[privacy].doh_padding`.  See `specs/wp8-transport-privacy.md` §3.
    pub doh_padding: bool,
    /// Whether DNS rebinding protection is active.
    /// Corresponds to `[privacy].rebind_protection`.  See `specs/wp8-transport-privacy.md` §4.
    pub rebind_protection: bool,
}

/// Response body for `GET /v0/status`.
#[derive(Debug, Clone, Serialize)]
pub struct StatusBody {
    /// Daemon state: `"filtering"`, `"snoozed"`, `"standing_by"`, or `"attention"`.
    pub state: String,
    /// Unix timestamp (ms) when the current snooze expires; `null` if not snoozed.
    pub snoozed_until_unix_ms: Option<u64>,
    /// Why we are standing by (e.g. `"vpn"`, `"portal"`, `"user_dns"`);
    /// `null` when not in `standing_by` state.
    pub standing_by_reason: Option<String>,
    /// Daemon release version string.
    pub version: String,
    /// Seconds since daemon start.
    pub uptime_secs: u64,
    /// Rule-set statistics.
    pub rules: RulesStatus,
    /// Cumulative query counters.
    pub counters: Counters,
    /// Privacy feature toggle status (WP4).
    pub privacy: PrivacyStatus,
    /// Active profile name (WP14 §2); `null` when no profile is active (normal config path).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_profile: Option<String>,
}

// ── /v0/takeover + /v0/restore ────────────────────────────────────────────────

/// Response body for `POST /v0/takeover`.
#[derive(Debug, Clone, Serialize)]
pub struct TakeoverBody {
    /// Whether the takeover succeeded.
    pub success: bool,
    /// Optional error message on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Response body for `POST /v0/restore`.
#[derive(Debug, Clone, Serialize)]
pub struct RestoreBody {
    /// Whether the restore succeeded.
    pub success: bool,
    /// Optional error message on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ── /v0/queries/recent ────────────────────────────────────────────────────────

/// Query parameters for `GET /v0/queries/recent`.
#[derive(Debug, Clone, Deserialize)]
pub struct RecentQueryParams {
    /// Max records to return; clamped to `[1, 1000]`.
    pub n: Option<u32>,
    /// If true, only blocked queries are returned.
    pub blocked_only: Option<bool>,
}

/// A single DNS query record.
#[derive(Debug, Clone, Serialize)]
pub struct QueryRecord {
    /// Unix timestamp of the query in milliseconds.
    pub ts_unix_ms: u64,
    /// Queried domain name (forward form, no trailing dot).
    pub qname: String,
    /// DNS query type (e.g., 1 = A, 28 = AAAA).
    pub qtype: u16,
    /// Decision engine verdict: `"block"`, `"forward"`, or `"forward_local"`.
    pub verdict: String,
    /// Why the verdict was produced.
    pub reason: String,
    /// Upstream round-trip in milliseconds; `null` for blocked queries.
    pub upstream_ms: Option<u32>,
}

/// Response body for `GET /v0/queries/recent`.
///
/// WP4 §3.4: `log_mode` is always present so callers can detect anonymous/off
/// modes without special-casing the empty-queries case.
#[derive(Debug, Clone, Serialize)]
pub struct QueriesBody {
    /// Records, newest first, at most `n` (clamped to `[1, 1000]` server-side).
    /// Empty when `log_mode` is `"off"`.
    pub queries: Vec<QueryRecord>,
    /// Query-log privacy mode: `"full"`, `"anonymous"`, or `"off"`.
    /// In `"anonymous"` mode qnames are stored as `"<redacted>"`.
    /// In `"off"` mode the ring is never written, so `queries` is always empty.
    pub log_mode: String,
}

// ── /v0/stats/summary ─────────────────────────────────────────────────────────

/// Response body for `GET /v0/stats/summary`.
#[derive(Debug, Clone, Serialize)]
pub struct StatsSummaryBody {
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

/// Request body for `POST /v0/snooze`.
#[derive(Debug, Clone, Deserialize)]
pub struct SnoozeReq {
    /// Duration in seconds (must be in `1..=86400`).
    pub secs: u64,
}

/// Response body for `POST /v0/snooze`.
#[derive(Debug, Clone, Serialize)]
pub struct SnoozeBody {
    /// Unix timestamp (ms) when the snooze expires.
    pub snoozed_until_unix_ms: u64,
}

// ── /v0/resume ────────────────────────────────────────────────────────────────

/// Response body for `POST /v0/resume`.
#[derive(Debug, Clone, Serialize)]
pub struct ResumeBody {
    /// New daemon state after resuming (should be `"filtering"`).
    pub state: String,
}

// ── /v0/allow, /v0/unallow ────────────────────────────────────────────────────

/// Request body for `POST /v0/allow` and `POST /v0/unallow`.
#[derive(Debug, Clone, Deserialize)]
pub struct DomainReq {
    /// Domain name to add or remove.
    pub domain: String,
}

/// Response body for `POST /v0/allow`, `POST /v0/unallow`, `GET /v0/allowlist`.
#[derive(Debug, Clone, Serialize)]
pub struct AllowlistBody {
    /// Full allowlist after the operation.
    pub allowed: Vec<String>,
}

// ── /v0/lists ─────────────────────────────────────────────────────────────────

/// Per-source status record embedded in [`ListsBody`].
///
/// Mirrors the CLI's `ListSourceStatus` — `enabled` is always `true` in P0
/// (no per-source disable control yet).  WP4 §4 adds catalog metadata fields.
#[derive(Debug, Clone, Serialize)]
pub struct ListSourceStatus {
    /// Human-readable source name.
    pub name: String,
    /// Whether the source is enabled (always `true` in P0).
    pub enabled: bool,
    /// Number of rules loaded from this source; always `null` in P0 (per-source
    /// breakdown is post-P0).
    pub rule_count: Option<u64>,
    /// Unix timestamp (ms) of the last successful fetch; `null` if never fetched.
    pub last_fetched_unix_ms: Option<u64>,
    /// HTTP status from the last fetch; `null` if never attempted.
    pub last_http_status: Option<u16>,
    /// Error message from the last fetch; `null` if last fetch succeeded.
    pub last_error: Option<String>,
    /// Catalog category key (e.g. `"hagezi-normal"`) for catalog sources;
    /// `null` for user-custom sources not in the compiled-in catalog.
    pub category: Option<String>,
    /// License string declared by the upstream project; `null` when not stated
    /// or for user-custom sources.
    pub license: Option<String>,
    /// Attribution/credit string for the upstream project; `null` for
    /// user-custom sources not in the compiled-in catalog.
    pub attribution: Option<String>,
}

/// Response body for `GET /v0/lists`.
///
/// WP4 §4: `preset` is the configured list preset name.
#[derive(Debug, Clone, Serialize)]
pub struct ListsBody {
    /// The configured list preset (`"minimal"`, `"balanced"`, `"strict"`, `"aggressive"`, or `"custom"`).
    pub preset: String,
    /// Per-source status records.
    pub sources: Vec<ListSourceStatus>,
}

// ── /v0/lists/refresh ────────────────────────────────────────────────────────

/// Response body for `POST /v0/lists/refresh` (HTTP 202).
#[derive(Debug, Clone, Serialize)]
pub struct ListsRefreshBody {
    /// Always `true`; indicates the refresh task was kicked off.
    pub started: bool,
}

// ── /v0/stats/history (WP9) ──────────────────────────────────────────────────

/// Query parameters for `GET /v0/stats/history`.
#[derive(Debug, Clone, Deserialize)]
pub struct HistoryParams {
    /// Look-back window in hours (default 24, max 8760 = 365 days).
    pub hours: Option<u32>,
    /// Bucket width in seconds (default 3600).
    pub bucket: Option<u32>,
}

/// A single time-bucket in the history response.
#[derive(Debug, Clone, Serialize)]
pub struct HistoryBucket {
    /// Bucket start (Unix ms, aligned to `bucket` seconds).
    pub ts: u64,
    /// Total queries in this bucket.
    pub total: u64,
    /// Blocked queries in this bucket.
    pub blocked: u64,
}

/// Response body for `GET /v0/stats/history`.
#[derive(Debug, Clone, Serialize)]
pub struct HistoryBody {
    /// Ordered list of time-buckets, oldest first.
    pub buckets: Vec<HistoryBucket>,
    /// Query-log privacy mode: `"full"`, `"anonymous"`, or `"off"`.
    pub log_mode: String,
}

// ── /v0/stats/top (WP9) ───────────────────────────────────────────────────────

/// Query parameters for `GET /v0/stats/top`.
#[derive(Debug, Clone, Deserialize)]
pub struct TopParams {
    /// Maximum entries to return per list (default 20, max 100).
    pub n: Option<u32>,
    /// Look-back window in hours (default 168 = 7 days).
    pub hours: Option<u32>,
}

/// A single entry in the top-domains list.
#[derive(Debug, Clone, Serialize)]
pub struct TopEntry {
    /// Domain name.
    pub qname: String,
    /// Hit count.
    pub count: u64,
}

/// Response body for `GET /v0/stats/top`.
#[derive(Debug, Clone, Serialize)]
pub struct TopBody {
    /// Top blocked domains, descending by count.
    /// Empty when `log_mode` is `"anonymous"` or `"off"`.
    pub blocked: Vec<TopEntry>,
    /// Top allowed (forwarded) domains, descending by count.
    /// Empty when `log_mode` is `"anonymous"` or `"off"`.
    pub allowed: Vec<TopEntry>,
    /// Query-log privacy mode: `"full"`, `"anonymous"`, or `"off"`.
    pub log_mode: String,
}

// ── /v0/clients (WP13) ───────────────────────────────────────────────────────

/// Query parameters for `GET /v0/clients`.
#[derive(Debug, Clone, Deserialize)]
pub struct ClientsParams {
    /// Look-back window in hours (default 24, max 8760 = 365 days).
    pub hours: Option<u32>,
}

/// A single per-client statistics row.
#[derive(Debug, Clone, Serialize)]
pub struct ClientEntry {
    /// Client IP address.
    pub client: String,
    /// Resolved hostname from passive mDNS insight (WP14 §3); `null` when unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Total queries from this client in the window.
    pub total: u64,
    /// Blocked queries from this client in the window.
    pub blocked: u64,
}

/// Response body for `GET /v0/clients`.
///
/// When `log_clients = false` (the default), `clients` is empty and
/// `log_clients_enabled` is `false` — the `explanation` field tells the
/// caller why.
#[derive(Debug, Clone, Serialize)]
pub struct ClientsBody {
    /// Whether `network_guard.log_clients` is on.
    pub log_clients_enabled: bool,
    /// Human-readable explanation when `log_clients_enabled = false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
    /// Per-client statistics, ordered by total queries descending.
    pub clients: Vec<ClientEntry>,
}

// ── /v0/config/reload (WP14 §2) ──────────────────────────────────────────────

/// Request body for `POST /v0/config/reload`.
#[derive(Debug, Clone, Deserialize)]
pub struct ConfigReloadReq {
    /// Profile name to load from `state_dir/profiles/<name>.toml`.
    /// When absent the endpoint just re-reads the current active profile
    /// (or no-ops when no profile is active).
    #[serde(default)]
    pub profile: Option<String>,
}

/// Response body for `POST /v0/config/reload`.
#[derive(Debug, Clone, Serialize)]
pub struct ConfigReloadBody {
    /// Config sections that were applied immediately without restart.
    /// E.g. `["lists", "upstream", "privacy"]`.
    pub applied: Vec<String>,
    /// Config sections that require a daemon restart to take effect.
    /// E.g. `["listen", "inbound_tls"]`.
    pub requires_restart: Vec<String>,
}

// ── /v0/profiles (WP14 §2) ───────────────────────────────────────────────────

/// A single profile entry embedded in [`ProfilesBody`].
#[derive(Debug, Clone, Serialize)]
pub struct ProfileEntry {
    /// Profile name (filename without `.toml`).
    pub name: String,
    /// Whether this is the currently active profile.
    pub active: bool,
}

/// Response body for `GET /v0/profiles`.
#[derive(Debug, Clone, Serialize)]
pub struct ProfilesBody {
    /// List of available profiles.
    pub profiles: Vec<ProfileEntry>,
    /// Currently active profile name; `null` when none is active.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<String>,
}

/// Response body for `GET /v0/profiles/<name>`.
#[derive(Debug, Clone, Serialize)]
pub struct ProfileBody {
    /// Profile name.
    pub name: String,
    /// Raw TOML content of the profile.
    pub content: String,
}

// ── Error shapes ──────────────────────────────────────────────────────────────

/// Generic 4xx/5xx error body: `{"error": "...", "detail": "..."}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorBody {
    /// Short error code (e.g., `"unauthorized"`, `"invalid_body"`).
    pub error: String,
    /// Optional human-readable detail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl ApiErrorBody {
    /// Construct with an error code and no detail.
    pub fn simple(error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            detail: None,
        }
    }

    /// Construct with an error code and a detail message.
    pub fn with_detail(error: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            detail: Some(detail.into()),
        }
    }
}
