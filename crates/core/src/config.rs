//! Configuration model for hushwarren.
//!
//! Implements `specs/wp1-core.md` §5 and `specs/wp4-privacy.md` §1.  The
//! TOML schema is documented in `docs/architecture.md` §5.  All structs carry
//! `#[serde(deny_unknown_fields, default)]` so unknown keys in the file are
//! rejected and missing keys are filled with safe defaults.
//!
//! Users never hand-edit this file — the API writes it.  The format must be
//! stable to read (a new daemon must parse old configs) and forgiving
//! (reasonable defaults for every field).
//!
//! Call [`HushConfig::validate`] after loading to collect ALL problems at
//! once before applying a config.
//!
//! ## WP4 additions
//!
//! `ListsConfig` gains `preset` and `extra_categories`.  The effective source
//! list is the union of `preset_sources(preset) ∪ catalog(extra_categories) ∪
//! sources` (dedup by URL).  `PrivacyConfig` is a new top-level section.
//!
//! See `catalog.rs` for the URL catalog that `preset` and `extra_categories`
//! reference.
//!
//! ## WP8 additions (`specs/wp8-transport-privacy.md` §1)
//!
//! `UpstreamConfig` gains `h3` (prefer DoH3 rungs).  `PrivacyConfig` gains
//! `doh_padding` (RFC 8467 block padding) and `rebind_protection` /
//! `rebind_allow` (DNS rebinding protection).  All three default to safe values
//! (h3=true, doh_padding=true, rebind_protection=true, rebind_allow=[]).
//!
//! ## WP13 additions (`specs/wp13-network-guard.md` §1)
//!
//! `NetworkGuardConfig` is a new top-level `[network_guard]` section.
//! Default: disabled.  When enabled the daemon additionally listens on every
//! IP in `bind` (explicit LAN addresses), feeding the same DNS pipeline.
//! `log_clients` opts in to per-client statistics (architecture §7).

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::domain::Domain;

/// A single DoH upstream endpoint.
///
/// The `bootstrap_ips` field is required because after takeover the system
/// resolver points at us — resolving the DoH hostname through ourselves would
/// cause a query loop.  Bootstrap IPs bypass the system resolver entirely.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DohEndpoint {
    /// Full HTTPS URL for the DNS-over-HTTPS endpoint.
    pub url: String,
    /// Direct IP addresses for the DoH hostname.  At least one is required;
    /// the forwarder picks from these without consulting the system resolver.
    pub bootstrap_ips: Vec<String>,
}

/// DNS listener addresses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ListenConfig {
    /// UDP listener socket addresses.
    pub udp: Vec<String>,
    /// TCP listener socket addresses.
    pub tcp: Vec<String>,
}

impl Default for ListenConfig {
    fn default() -> Self {
        Self {
            udp: vec!["127.0.0.1:53".to_string(), "[::1]:53".to_string()],
            tcp: vec!["127.0.0.1:53".to_string(), "[::1]:53".to_string()],
        }
    }
}

/// Configuration for the experimental ODoH (Oblivious DNS over HTTPS) upstream rung.
///
/// Implements `specs/wp7-odoh-ecs.md` §2.  This section is **only consulted when
/// `[privacy].odoh = true`**; when the feature flag is off the struct is parsed
/// (to catch typos) but ignored by the rung builder.
///
/// ## Direct-to-target honesty note
///
/// *Direct-to-target ODoH still hides client IP↔query linkage from
/// cache/transport observers, but the target sees your IP exactly like regular
/// DoH.  Unlinkability requires a relay operated by a different party.  The
/// public relay ecosystem is small and Cloudflare-centric — relay mode is
/// configured here but we ship no default relay.*  Status: experimental.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct OdohUpstreamConfig {
    /// Full HTTPS URL of the ODoH target (e.g. `https://odoh.cloudflare-dns.com/dns-query`).
    ///
    /// The config is fetched from `<target-origin>/.well-known/odohconfigs`.
    pub target: String,
    /// ODoH relay URL.  When empty the query goes **directly to the target**
    /// (see the direct-to-target honesty note above).  When set, the query
    /// is POSTed to the relay with `targethost` / `targetpath` query params
    /// per RFC 9230 §7.
    pub relay: String,
    /// Direct IP addresses for resolving the target/relay hostnames.
    ///
    /// Required — at least one entry prevents a resolution loop after DNS
    /// takeover.  Used as bootstrap IPs in the reqwest `resolve()` override.
    pub bootstrap_ips: Vec<String>,
}

impl Default for OdohUpstreamConfig {
    fn default() -> Self {
        Self {
            target: "https://odoh.cloudflare-dns.com/dns-query".to_string(),
            relay: String::new(),
            bootstrap_ips: vec!["1.1.1.1".to_string()],
        }
    }
}

/// Upstream forwarder configuration.
///
/// ## Upstream preset (`preset` field)
///
/// The `preset` knob selects a named DoH ladder without requiring the user to
/// spell out individual endpoints.  See [`UpstreamConfig::effective_doh`] for
/// the exact precedence rules.
///
/// | `preset` value | DoH ladder |
/// |---|---|
/// | `"default"` | Use `doh` as-is (default: Cloudflare → Quad9) |
/// | `"mullvad"` | Mullvad → Cloudflare → Quad9 (privacy-first; `doh` is ignored) |
/// | `"none"` | Empty DoH ladder (only `do53_fallback` rungs) |
///
/// **Mullvad endpoint details** (verified 2026-06-12 from
/// `https://mullvad.net/en/help/dns-over-https-and-dns-over-tls`):
/// - URL: `https://dns.mullvad.net/dns-query` (unfiltered — our blocking happens locally)
/// - Anycast IPv4: `194.242.2.2`
/// - Anycast IPv6: `2a07:e340::2`
/// - Policy: no-log, QNAME minimisation on; free service, no account required.
///   For the filtered profiles (adblock, base, extended, family, all) see
///   Mullvad's documentation — we intentionally use the unfiltered rung
///   because hushwarren's own block list does the filtering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct UpstreamConfig {
    /// Upstream preset: `"default"` | `"mullvad"` | `"none"`.
    ///
    /// Default: `"default"` (use `doh` field, which ships as Cloudflare → Quad9).
    /// See [`UpstreamConfig::effective_doh`] for exact precedence.
    pub preset: String,
    /// Prefer DoH3 (HTTP/3 over QUIC) rungs where the provider is verified to
    /// support them (`specs/wp8-transport-privacy.md` §1).
    ///
    /// Default: `true`.  When `false` the rung ladder is unchanged from today
    /// (DoH h2 only).  The WP8 transport agent inserts `doh3://` rungs before
    /// the corresponding `doh://` rungs at ladder construction time.
    pub h3: bool,
    /// Primary DoH endpoints used when `preset = "default"`.
    ///
    /// When `preset` is `"mullvad"` or `"none"` this field is **ignored** —
    /// the preset fully controls the DoH ladder.  Default: Cloudflare → Quad9.
    pub doh: Vec<DohEndpoint>,
    /// Plain Do53 fallback addresses (P1: Sentinel fills from DHCP resolver).
    pub do53_fallback: Vec<String>,
    /// ODoH experimental rung config.  Only active when `[privacy].odoh = true`.
    pub odoh: OdohUpstreamConfig,
}

/// The Mullvad unfiltered DoH endpoint.
///
/// Source: `https://mullvad.net/en/help/dns-over-https-and-dns-over-tls`
/// Verified: 2026-06-12.  Unfiltered profile chosen — our blocking happens
/// locally; we must not pick a Mullvad filtered profile and double-block.
fn mullvad_doh() -> DohEndpoint {
    DohEndpoint {
        url: "https://dns.mullvad.net/dns-query".to_string(),
        bootstrap_ips: vec!["194.242.2.2".to_string()],
    }
}

/// The Cloudflare DoH endpoint (default ladder rung 0).
fn cloudflare_doh() -> DohEndpoint {
    DohEndpoint {
        url: "https://cloudflare-dns.com/dns-query".to_string(),
        bootstrap_ips: vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()],
    }
}

/// The Quad9 DoH endpoint (default ladder rung 1).
///
/// Quad9 dropped HTTP/1.1 DoH support on 2025-12-15; only HTTP/2 is accepted.
/// hickory-resolver's DoH client uses h2 exclusively — verified by the
/// `live_doh_quad9` CI live test (see `crates/daemon/tests/live_doh.rs`).
fn quad9_doh() -> DohEndpoint {
    DohEndpoint {
        url: "https://dns.quad9.net/dns-query".to_string(),
        bootstrap_ips: vec!["9.9.9.9".to_string(), "149.112.112.112".to_string()],
    }
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            preset: "default".to_string(),
            h3: true,
            doh: vec![cloudflare_doh(), quad9_doh()],
            do53_fallback: vec![],
            odoh: OdohUpstreamConfig::default(),
        }
    }
}

impl UpstreamConfig {
    /// Return the effective DoH ladder to use at runtime.
    ///
    /// Precedence:
    /// - When `preset = "mullvad"`: always use the Mullvad-primary ladder
    ///   (Mullvad → Cloudflare → Quad9), regardless of `doh`.  The `doh`
    ///   field is ignored because the preset fully specifies the ladder.
    /// - When `preset = "none"`: return an empty DoH list (only `do53_fallback`
    ///   rungs are used).  Intended for test/embedded configurations that
    ///   deliberately want zero DoH rungs.
    /// - When `preset = "default"` (or any unrecognised value that passed
    ///   validation): return `doh` as-is.  The default `doh` value contains
    ///   Cloudflare → Quad9; a user who sets `doh = []` explicitly gets zero
    ///   DoH rungs.
    ///
    /// This mirrors the lists-preset philosophy: the preset knob is the
    /// recommended way to pick a named profile; explicit `doh` overrides
    /// only apply when `preset = "default"`.  Do not combine
    /// `preset = "mullvad"` with a custom `doh` list — use `preset = "default"`
    /// and populate `doh` directly if you need a fully custom ladder.
    pub fn effective_doh(&self) -> Vec<DohEndpoint> {
        match self.preset.as_str() {
            "mullvad" => vec![mullvad_doh(), cloudflare_doh(), quad9_doh()],
            "none" => vec![],
            // "default" and anything else that passed validate() → use doh as-is.
            _ => self.doh.clone(),
        }
    }
}

/// A single blocklist source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListSource {
    /// Human-readable name shown in the dashboard.
    pub name: String,
    /// URL to fetch the list from.
    pub url: String,
}

/// Blocklist refresh and source configuration.
///
/// ## Effective source list (WP4 merge rule)
///
/// Calling `effective_sources()` returns the deduplicated union of:
/// 1. Sources from `preset` (e.g. `"balanced"` → oisd-small + hagezi-normal).
/// 2. Sources from every key in `extra_categories`.
/// 3. Entries in `sources` (explicit overrides; always included).
///
/// `preset = "custom"` contributes nothing from the preset itself — only
/// `extra_categories` and `sources` matter.
///
/// ## WP12: First-run snapshot
///
/// `snapshot_dir` points at a directory containing pre-fetched Hagezi list
/// files (bundled in the installer).  When the state dir has no compiled or
/// cached rules AND this directory exists, the daemon compiles from the
/// snapshot immediately on cold start so blocking works before any network
/// fetch.  The well-known production path is
/// `/usr/local/share/hushwarren/snapshot` on Unix.  Tests override this with
/// a `tempdir` path via the config field.  `None` disables the snapshot seam
/// entirely (the original boot behaviour).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ListsConfig {
    /// List preset: `"minimal"` | `"balanced"` (default) | `"strict"` |
    /// `"aggressive"` | `"custom"`.
    ///
    /// Controls which catalog sources are included by default.
    pub preset: String,
    /// Additional catalog category keys included regardless of preset.
    ///
    /// Valid keys: `"telemetry-windows"`, `"telemetry-samsung"`, `"telemetry-xiaomi"`,
    /// `"telemetry-apple"`, `"telemetry-amazon"`, `"telemetry-huawei"`,
    /// `"threat-intel"`, `"doh-bypass"`, `"nsfw"`.
    pub extra_categories: Vec<String>,
    /// Explicit source list.  Entries here are ADDED to (not a replacement
    /// for) the preset + category sources.  Use `preset = "custom"` and only
    /// populate this field if you want full manual control.
    pub sources: Vec<ListSource>,
    /// How often to refresh (hours).
    pub refresh_hours: u32,
    /// Random jitter added to the refresh interval (minutes).
    pub jitter_minutes: u32,
    /// Path to the pre-fetched snapshot directory bundled with the installer
    /// (WP12 §1).  When `None` the snapshot seam is inactive.  Production
    /// installers set this to `/usr/local/share/hushwarren/snapshot`; tests
    /// inject a `tempdir` path via this field.  Only consulted when there are
    /// no compiled or cached lists in the state directory.
    pub snapshot_dir: Option<String>,
}

impl Default for ListsConfig {
    fn default() -> Self {
        Self {
            preset: "balanced".to_string(),
            extra_categories: Vec::new(),
            sources: Vec::new(),
            refresh_hours: 24,
            jitter_minutes: 60,
            snapshot_dir: None,
        }
    }
}

impl ListsConfig {
    /// Compute the effective deduplicated source list from preset ∪ categories ∪ explicit.
    ///
    /// This is the canonical merge rule from `specs/wp4-privacy.md` §1.
    /// Returns an empty `Vec` if the catalog resolve fails (the caller must
    /// check `validate()` first to surface catalog errors).
    pub fn effective_sources(&self) -> Vec<ListSource> {
        use crate::catalog::Catalog;

        let cat_keys: Vec<&str> = self.extra_categories.iter().map(String::as_str).collect();

        // Resolve preset + categories from catalog (best-effort; errors surfaced by validate()).
        let mut catalog_sources = Catalog::resolve(&self.preset, &cat_keys).unwrap_or_default();

        // Append explicit sources (dedup by URL).
        for src in &self.sources {
            if !catalog_sources.iter().any(|s| s.url == src.url) {
                catalog_sources.push(src.clone());
            }
        }

        catalog_sources
    }
}

/// Query-log privacy mode.
///
/// Implements `specs/wp4-privacy.md` §3.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryLogMode {
    /// Full logging: qname + verdict + reason stored in RAM ring (default).
    #[default]
    Full,
    /// Anonymous: counters and verdict/reason only — qname stored as `"<redacted>"`.
    Anonymous,
    /// Off: counters only, ring buffer never written.
    Off,
}

/// Privacy feature toggles.
///
/// Implements `specs/wp4-privacy.md` §1–§2, `specs/wp8-transport-privacy.md` §1,
/// and `specs/wp9-dashboard-rollup.md` §1.
/// Tier 1 features are on by default; Tier 2 features are off by default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PrivacyConfig {
    /// **Tier 1.2** — answer `use-application-dns.net` with NXDOMAIN so
    /// Firefox's default DoH is suppressed in favour of the system resolver.
    ///
    /// Default: `true`.  Set to `false` only when you explicitly want
    /// Firefox to use its own DoH.
    pub browser_doh_canary: bool,
    /// **Tier 1.4** — walk every CNAME hop in upstream responses and apply
    /// the same decision ladder.  Any blocked hop sinkholes the original query.
    ///
    /// Default: `true`.  Matches Pi-hole `CNAMEdeepInspect=true` behaviour.
    pub cname_inspection: bool,
    /// **Tier 1.3** — query-log privacy mode: `full` | `anonymous` | `off`.
    ///
    /// Default: `"full"` (qname + verdict in RAM ring, nothing on disk).
    pub query_log: QueryLogMode,
    /// **Tier 2.1** — block resolution of known public DoH endpoints so apps
    /// with built-in DoH fall back to system DNS.
    ///
    /// Default: `false` — this intentionally breaks a user-chosen
    /// configuration in other software; enable only when that is the goal.
    pub block_doh_bypass: bool,
    /// **Tier 2.2** — respond to `mask.icloud.com` / `mask-h2.icloud.com`
    /// with NODATA (Apple's documented disable mechanism for Private Relay).
    ///
    /// Default: `false` — Private Relay is itself a privacy feature; blocking
    /// it by default trades the user's privacy for our coverage, which violates
    /// the product principle.
    pub block_private_relay: bool,
    /// **Tier 3 — Experimental ODoH rung** — when `true`, prepends an
    /// Oblivious DoH rung (rung 0) in front of the regular DoH rungs.
    ///
    /// Requires `[upstream.odoh]` to be configured.  Default: `false`
    /// (experimental — see `specs/wp7-odoh-ecs.md` §2 for details and the
    /// direct-to-target honesty note in [`OdohUpstreamConfig`]).
    pub odoh: bool,
    /// **WP8 Tier 1** — add RFC 8467 block padding (EDNS(0) option 12) to
    /// every encrypted upstream query (DoH h2, DoH3, ODoH), rounding the
    /// serialized message to a multiple of 128 octets.
    ///
    /// Default: `true`.  Do53 rungs are never padded (RFC 7830 §6 — padding
    /// on cleartext is a tracking vector).  See `specs/wp8-transport-privacy.md` §3.
    pub doh_padding: bool,
    /// **WP8 Tier 1** — reject DNS responses for public names that contain
    /// private/loopback/link-local addresses (DNS rebinding protection).
    ///
    /// Blocked answers are returned as NODATA.  Exemptions: user allowlist,
    /// `rebind_allow` suffixes, and the built-in `plex.direct` entry.
    /// Default: `true`.  See `specs/wp8-transport-privacy.md` §4.
    pub rebind_protection: bool,
    /// **WP8** — additional domain suffixes exempt from rebind protection,
    /// in addition to the user allowlist and the built-in `plex.direct` entry.
    ///
    /// Each entry must be a well-formed domain suffix (validated by
    /// `validate()`).  Use case: corporate split-horizon DNS behind the
    /// Do53-to-DHCP fallback rung.  Default: empty.
    /// See `specs/wp8-transport-privacy.md` §4.
    pub rebind_allow: Vec<String>,
    /// **WP9** — number of days to retain SQLite query-log rows.
    ///
    /// Valid range: `1..=90`.  An hourly background job deletes rows older
    /// than this many days and enforces the 100 MB size cap.
    /// Mode interplay: when `query_log = "off"`, the SQLite file is never
    /// opened and this field has no effect.  Mode changes do not
    /// retroactively purge existing rows — only future rows are affected.
    ///
    /// Default: `7`.
    pub retain_days: u32,
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            browser_doh_canary: true,
            cname_inspection: true,
            query_log: QueryLogMode::Full,
            block_doh_bypass: false,
            block_private_relay: false,
            odoh: false,
            doh_padding: true,
            rebind_protection: true,
            rebind_allow: Vec::new(),
            retain_days: 7,
        }
    }
}

/// Dashboard SPA configuration.
///
/// Implements `specs/wp9-dashboard-rollup.md` §4.  The dashboard is served
/// at `/dashboard/` from the existing loopback API port.  Disabling it with
/// `enabled = false` returns 404 on `/dashboard/` while leaving all `/v0/*`
/// routes unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DashboardConfig {
    /// Serve the embedded SPA at `/dashboard/`.
    ///
    /// Default: `true`.  When `false`, all `/dashboard/*` requests return 404.
    /// `/v0/*` API routes are unaffected.
    pub enabled: bool,
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// What to respond with when a domain is blocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockAction {
    /// Respond with `0.0.0.0` / `::` (null IP).  Default: some apps retry on
    /// NXDOMAIN but accept an unroutable address quietly.
    #[default]
    NullIp,
    /// Respond with NXDOMAIN.
    Nxdomain,
}

/// Block response configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct BlockConfig {
    /// How to respond when a domain is blocked.
    pub action: BlockAction,
    /// TTL in seconds for block responses.  10s means an un-block takes effect
    /// quickly without hammering upstream.
    pub ttl_secs: u32,
}

impl Default for BlockConfig {
    fn default() -> Self {
        Self {
            action: BlockAction::NullIp,
            ttl_secs: 10,
        }
    }
}

/// Control API configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ApiConfig {
    /// Socket address for the control API and embedded dashboard.
    /// Must bind to localhost only (P3 — local-first, private by default).
    pub listen: String,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:5380".to_string(),
        }
    }
}

/// Runtime / filesystem configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RuntimeConfig {
    /// Directory for persistent state (compiled rules, query log, token).
    /// Empty string means "use the platform default" — the daemon resolves
    /// this; `hush-core` does not know about the OS.
    pub state_dir: String,
}

/// Sentinel (DNS takeover / crash-safety / network watcher) configuration.
///
/// All fields carry sensible defaults — the sentinel works out of the box
/// without any explicit `[sentinel]` section in the config file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SentinelConfig {
    /// How often (seconds) the watcher polls for drift, VPN changes, and wake.
    ///
    /// Default: 5 s.
    pub poll_secs: u64,

    /// Domain used as the "allowed canary" during the SELF-TEST step.
    ///
    /// Must resolve to ≥1 A record via the upstream ladder.
    /// Default: `"example.com"`.
    pub canary_domain: String,

    /// Monotonic-vs-wall-clock gap (seconds) that triggers a wake-event
    /// re-verify cycle.
    ///
    /// Default: 30 s.
    pub wake_gap_secs: u64,

    /// How long (seconds) to stay in portal pass-through mode before giving
    /// up and remaining transparent.
    ///
    /// Default: 900 s (15 min).
    pub portal_timebox_secs: u64,

    /// Number of abnormal restarts within `breaker_window_secs` that trips
    /// the crash-loop breaker.
    ///
    /// Default: 3.
    pub breaker_threshold: u32,

    /// Sliding window (seconds) for the crash-loop breaker restart counter.
    ///
    /// Default: 300 s (5 min).
    pub breaker_window_secs: u64,
}

impl Default for SentinelConfig {
    fn default() -> Self {
        Self {
            poll_secs: 5,
            canary_domain: "example.com".to_owned(),
            wake_gap_secs: 30,
            portal_timebox_secs: 900,
            breaker_threshold: 3,
            breaker_window_secs: 300,
        }
    }
}

/// Inbound DoT / DoQ listener configuration.
///
/// Implements `specs/wp14-nice.md` §1.  Default off; all fields are validated
/// but ignored at runtime when `enabled = false`.
///
/// ## Client-trust reality
///
/// Android Private DNS (DoT) expects a **trusted certificate and a hostname**.
/// A self-signed certificate requires the user to manually install it as a
/// trusted CA on every client — this feature mainly serves LAN power users
/// who control their own PKI.  For zero-touch use, provide a CA-signed cert
/// via `cert_path` / `key_path` and publish the hostname in your local DNS.
///
/// See `docs/network-guard.md` for the full trust model discussion.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct InboundTlsConfig {
    /// Enable the inbound DoT (and optionally DoQ) listener.
    ///
    /// Default: `false`.
    pub enabled: bool,

    /// Explicit IP addresses to bind DoT/DoQ on (port 853 TCP for DoT, 853
    /// UDP for DoQ).  Loopback addresses are allowed (local testing is
    /// legitimate).  An empty list with `enabled = true` is a validation
    /// error.
    pub bind: Vec<String>,

    /// Path to the PEM certificate chain file.  Empty string + `enabled = true`
    /// triggers self-signed certificate generation into
    /// `state_dir/inbound-tls/` with the bind IPs and system hostname as SANs.
    /// Regenerated automatically when the SAN list changes.
    pub cert_path: String,

    /// Path to the PEM private key file.  Must be present when `cert_path` is
    /// non-empty.  Empty string with a non-empty `cert_path` is a validation
    /// error.
    pub key_path: String,

    /// Enable DNS-over-QUIC (DoQ) on port 853/UDP in addition to DoT 853/TCP.
    ///
    /// Requires `enabled = true`.  Default: `false`.
    pub doq: bool,
}

/// Network Guard opt-in LAN protection configuration.
///
/// Implements `specs/wp13-network-guard.md` §1.
///
/// When `enabled = false` (the default) the daemon behaves identically to
/// Local Guard — this section is parsed for typos but has zero runtime effect.
/// Validation still runs even when disabled so the user gets early feedback on
/// bad addresses.
///
/// ## `log_clients` and `anonymous` mode
///
/// `anonymous` mode (`[privacy].query_log = "anonymous"`) redacts **qnames**
/// but **may keep client IPs** — per-device counters are the whole point of
/// `log_clients`.  Concretely: when `log_clients = true` and
/// `query_log = "anonymous"`, the stored row will have `qname = "<redacted>"`
/// and `client = "192.168.1.42"` (or whatever the LAN device's IP is).
/// When `query_log = "off"` nothing is stored regardless of `log_clients`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct NetworkGuardConfig {
    /// Enable the Network Guard feature.  When `false` all other fields are
    /// ignored at runtime (but still validated).
    ///
    /// Default: `false`.
    pub enabled: bool,

    /// Explicit LAN IP addresses to additionally listen on (no port — always
    /// port 53).  Entries must be non-unspecified, non-loopback `IpAddr`
    /// values.  An empty list with `enabled = true` is a validation error.
    ///
    /// Example: `["192.168.1.10"]`
    pub bind: Vec<String>,

    /// Enable per-client statistics.  When `true`, queries arriving on the
    /// guard listeners are tagged with the client IP in the SQLite log
    /// (`client` column added in schema v2).  Loopback queries (Local Guard
    /// path) always log `client = NULL` regardless of this flag.
    ///
    /// Default: `false`.  Turn on only when you want per-device counters;
    /// every household member's browsing activity is visible to the log reader.
    pub log_clients: bool,

    /// Enable passive mDNS multicast listener for per-client hostname
    /// resolution.  Implements `specs/wp14-nice.md` §3.
    ///
    /// When `true`, the daemon joins `224.0.0.251:5353` / `[ff02::fb]:5353`
    /// and maintains an IP→hostname map (TTL-aged, cap 1024 entries) from
    /// mDNS announcements.  The map is exposed via `GET /v0/clients` as the
    /// optional `name` field.
    ///
    /// Gated under `network_guard` because client-name insight is only
    /// meaningful when per-client stats are visible.  Failure to join
    /// multicast (permissions, interface) → `warn` once and feature off.
    ///
    /// Default: `false`.
    pub mdns_insight: bool,
}

/// Root configuration struct for hushwarren.
///
/// `Default::default()` produces a fully working Local Guard config.
/// Load from TOML with [`HushConfig::from_toml_str`]; serialize with
/// [`HushConfig::to_toml_string`].  Call [`HushConfig::validate`] after
/// loading — it returns ALL problems at once so the caller can surface them
/// together.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HushConfig {
    /// DNS listener configuration.
    pub listen: ListenConfig,
    /// Upstream resolver configuration.
    pub upstream: UpstreamConfig,
    /// Blocklist source and refresh configuration.
    pub lists: ListsConfig,
    /// Block response configuration.
    pub block: BlockConfig,
    /// Control API configuration.
    pub api: ApiConfig,
    /// Runtime configuration.
    pub runtime: RuntimeConfig,
    /// Privacy feature toggles (WP4) and query-log retention (WP9).
    pub privacy: PrivacyConfig,
    /// Sentinel / DNS-takeover configuration (WP5).
    pub sentinel: SentinelConfig,
    /// Dashboard SPA configuration (WP9).
    pub dashboard: DashboardConfig,
    /// Network Guard opt-in LAN protection (WP13).
    pub network_guard: NetworkGuardConfig,
    /// Inbound DoT / DoQ TLS listener (WP14).
    pub inbound_tls: InboundTlsConfig,
}

/// A single validation problem found in a [`HushConfig`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigProblem {
    /// Human-readable description of the problem.
    pub message: String,
}

impl std::fmt::Display for ConfigProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// Errors from the config module.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// TOML deserialization failed.
    #[error("TOML parse error: {0}")]
    TomlParse(String),
    /// TOML serialization failed.
    #[error("TOML serialize error: {0}")]
    TomlSerialize(String),
}

impl HushConfig {
    /// Return a [`ListsConfig`] suitable for passing to the list pipeline.
    ///
    /// Implements the Tier 2.1 auto-include rule from `specs/wp4-privacy.md` §2:
    /// when `privacy.block_doh_bypass = true`, the `doh-bypass` catalog category
    /// is automatically injected into the effective source set even if the user
    /// did not list it under `lists.extra_categories`.
    ///
    /// **Why here, not in `ListsConfig::effective_sources`?**
    /// `ListsConfig` has no knowledge of `PrivacyConfig`; keeping it pure avoids
    /// a cross-section dependency.  This method is the single wiring point that
    /// bridges the two sections at construction time (config-time only — there is
    /// no runtime toggle per WP4 §3).
    ///
    /// The returned value is a cloned, possibly-augmented `ListsConfig`.
    /// `preset` is preserved so the API can still report the user's chosen preset.
    /// Deduplication is handled by `ListsConfig::effective_sources` via
    /// `Catalog::resolve`, which skips URLs it has already emitted.
    pub fn effective_lists_config(&self) -> ListsConfig {
        let mut lists = self.lists.clone();

        if self.privacy.block_doh_bypass
            && !lists.extra_categories.iter().any(|k| k == "doh-bypass")
        {
            lists.extra_categories.push("doh-bypass".to_string());
        }

        lists
    }

    /// Deserialize from a TOML string.
    ///
    /// Returns [`ConfigError::TomlParse`] on parse failure.  Call
    /// [`validate`](Self::validate) separately to check semantic constraints.
    pub fn from_toml_str(s: &str) -> Result<Self, ConfigError> {
        toml::from_str(s).map_err(|e| ConfigError::TomlParse(e.to_string()))
    }

    /// Serialize to a TOML string.
    pub fn to_toml_string(&self) -> Result<String, ConfigError> {
        toml::to_string_pretty(self).map_err(|e| ConfigError::TomlSerialize(e.to_string()))
    }

    /// Validate semantic constraints and return ALL problems at once.
    ///
    /// Returns an empty `Vec` if the config is fully valid.
    ///
    /// Constraints checked:
    /// - Each DoH entry must have at least one `bootstrap_ip`.
    /// - Each `listen.udp` / `listen.tcp` address must parse as a socket address.
    /// - Each `api.listen` must parse as a socket address.
    /// - `lists.preset` must be a known preset name.
    /// - `lists.extra_categories` must contain only known category keys.
    /// - `preset="custom"` with an empty effective source union is an error.
    pub fn validate(&self) -> Vec<ConfigProblem> {
        let mut problems = Vec::new();

        // Validate upstream.preset unconditionally — the preset field is always
        // consulted by effective_doh() (mullvad preset ignores doh entirely).
        const VALID_UPSTREAM_PRESETS: &[&str] = &["default", "mullvad", "none"];
        if !VALID_UPSTREAM_PRESETS.contains(&self.upstream.preset.as_str()) {
            problems.push(ConfigProblem {
                message: format!(
                    "upstream.preset {:?} is unknown; valid values: default, mullvad, none",
                    self.upstream.preset
                ),
            });
        }

        // DoH entries must carry bootstrap IPs.
        for (i, doh) in self.upstream.doh.iter().enumerate() {
            if doh.bootstrap_ips.is_empty() {
                problems.push(ConfigProblem {
                    message: format!(
                        "upstream.doh[{i}] (url={}) has no bootstrap_ips; \
                         this creates a loop hazard after DNS takeover",
                        doh.url
                    ),
                });
            }
        }

        // Validate UDP listen addresses.
        for (i, addr) in self.listen.udp.iter().enumerate() {
            if addr.parse::<std::net::SocketAddr>().is_err() {
                problems.push(ConfigProblem {
                    message: format!("listen.udp[{i}] is not a valid socket address: {addr:?}"),
                });
            }
        }

        // Validate TCP listen addresses.
        for (i, addr) in self.listen.tcp.iter().enumerate() {
            if addr.parse::<std::net::SocketAddr>().is_err() {
                problems.push(ConfigProblem {
                    message: format!("listen.tcp[{i}] is not a valid socket address: {addr:?}"),
                });
            }
        }

        // Validate API listen address.
        if self.api.listen.parse::<std::net::SocketAddr>().is_err() {
            problems.push(ConfigProblem {
                message: format!(
                    "api.listen is not a valid socket address: {:?}",
                    self.api.listen
                ),
            });
        }

        // Validate lists.preset.
        use crate::catalog::Catalog;
        if !Catalog::is_valid_preset(&self.lists.preset) {
            problems.push(ConfigProblem {
                message: format!(
                    "lists.preset {:?} is unknown; valid values: minimal, balanced, strict, aggressive, custom",
                    self.lists.preset
                ),
            });
        }

        // Validate lists.extra_categories — collect all unknown keys at once.
        for key in &self.lists.extra_categories {
            if !Catalog::is_valid_category(key.as_str()) {
                problems.push(ConfigProblem {
                    message: format!("lists.extra_categories contains unknown key {key:?}"),
                });
            }
        }

        // ODoH: when the feature flag is on, require at least one bootstrap IP.
        if self.privacy.odoh && self.upstream.odoh.bootstrap_ips.is_empty() {
            problems.push(ConfigProblem {
                message: "privacy.odoh=true requires upstream.odoh.bootstrap_ips to be non-empty \
                          (loop-hazard guard)"
                    .to_owned(),
            });
        }

        // ODoH: when enabled, target must be set and start with https://.
        if self.privacy.odoh && !self.upstream.odoh.target.starts_with("https://") {
            problems.push(ConfigProblem {
                message: format!(
                    "upstream.odoh.target must start with https://, got: {:?}",
                    self.upstream.odoh.target
                ),
            });
        }

        // custom preset with empty union is an error.
        if self.lists.preset == "custom"
            && self.lists.extra_categories.is_empty()
            && self.lists.sources.is_empty()
        {
            problems.push(ConfigProblem {
                message: "lists.preset=custom requires at least one source via \
                          extra_categories or lists.sources"
                    .to_owned(),
            });
        }

        // Validate privacy.rebind_allow — each entry must parse as a domain
        // suffix using the same validation as the user allowlist.
        for (i, entry) in self.privacy.rebind_allow.iter().enumerate() {
            if let Err(e) = Domain::parse(entry) {
                problems.push(ConfigProblem {
                    message: format!(
                        "privacy.rebind_allow[{i}] is not a valid domain suffix: {entry:?} ({e})"
                    ),
                });
            }
        }

        // WP9: validate retain_days range (1..=90).
        if !(1..=90).contains(&self.privacy.retain_days) {
            problems.push(ConfigProblem {
                message: format!(
                    "privacy.retain_days {} is out of range; must be 1..=90",
                    self.privacy.retain_days
                ),
            });
        }

        // WP13: validate network_guard.bind entries.
        // Validation runs even when disabled so the user gets early feedback.
        for (i, addr_str) in self.network_guard.bind.iter().enumerate() {
            match addr_str.parse::<std::net::IpAddr>() {
                Err(_) => {
                    problems.push(ConfigProblem {
                        message: format!(
                            "network_guard.bind[{i}] is not a valid IP address: {addr_str:?}"
                        ),
                    });
                }
                Ok(ip) if ip.is_unspecified() => {
                    problems.push(ConfigProblem {
                        message: format!(
                            "network_guard.bind[{i}] is unspecified (0.0.0.0 / ::); \
                             use an explicit LAN address instead — a wildcard listener \
                             is never zero-touch-safe"
                        ),
                    });
                }
                Ok(ip) if ip.is_loopback() => {
                    problems.push(ConfigProblem {
                        message: format!(
                            "network_guard.bind[{i}] is a loopback address ({ip}); \
                             loopback is already covered by Local Guard — \
                             use an explicit LAN address"
                        ),
                    });
                }
                Ok(_) => {} // valid LAN address
            }
        }

        // WP13: enabled=true with an empty bind list is an error.
        if self.network_guard.enabled && self.network_guard.bind.is_empty() {
            problems.push(ConfigProblem {
                message: "network_guard.enabled=true requires at least one entry in \
                          network_guard.bind"
                    .to_owned(),
            });
        }

        // WP14: validate inbound_tls section.
        // Validate inbound_tls.bind entries (loopback allowed for local testing).
        for (i, addr_str) in self.inbound_tls.bind.iter().enumerate() {
            if addr_str.parse::<std::net::IpAddr>().is_err() {
                problems.push(ConfigProblem {
                    message: format!(
                        "inbound_tls.bind[{i}] is not a valid IP address: {addr_str:?}"
                    ),
                });
            }
        }

        // enabled=true with empty bind is an error.
        if self.inbound_tls.enabled && self.inbound_tls.bind.is_empty() {
            problems.push(ConfigProblem {
                message: "inbound_tls.enabled=true requires at least one entry in \
                          inbound_tls.bind"
                    .to_owned(),
            });
        }

        // cert_path without key_path is an error.
        if !self.inbound_tls.cert_path.is_empty() && self.inbound_tls.key_path.is_empty() {
            problems.push(ConfigProblem {
                message: "inbound_tls.cert_path is set but inbound_tls.key_path is empty; \
                          both must be provided together"
                    .to_owned(),
            });
        }

        // key_path without cert_path is an error.
        if !self.inbound_tls.key_path.is_empty() && self.inbound_tls.cert_path.is_empty() {
            problems.push(ConfigProblem {
                message: "inbound_tls.key_path is set but inbound_tls.cert_path is empty; \
                          both must be provided together"
                    .to_owned(),
            });
        }

        // doq=true without enabled=true is an error.
        if self.inbound_tls.doq && !self.inbound_tls.enabled {
            problems.push(ConfigProblem {
                message: "inbound_tls.doq=true requires inbound_tls.enabled=true".to_owned(),
            });
        }

        problems
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    // ── Default validates clean ───────────────────────────────────────────────

    #[test]
    fn default_validates_clean() {
        let cfg = HushConfig::default();
        let problems = cfg.validate();
        assert!(
            problems.is_empty(),
            "default config must validate without problems; got: {problems:?}"
        );
    }

    // ── Round-trip ────────────────────────────────────────────────────────────

    #[test]
    fn round_trip() {
        let cfg = HushConfig::default();
        let toml = cfg.to_toml_string().unwrap();
        let loaded = HushConfig::from_toml_str(&toml).unwrap();
        assert_eq!(cfg, loaded);
    }

    // ── Round-trip with new privacy section ──────────────────────────────────

    #[test]
    fn round_trip_with_privacy_fields() {
        let mut cfg = HushConfig::default();
        cfg.privacy.browser_doh_canary = false;
        cfg.privacy.cname_inspection = false;
        cfg.privacy.query_log = QueryLogMode::Anonymous;
        cfg.privacy.block_doh_bypass = true;
        cfg.privacy.block_private_relay = true;
        let toml = cfg.to_toml_string().unwrap();
        let loaded = HushConfig::from_toml_str(&toml).unwrap();
        assert_eq!(cfg, loaded);
    }

    // ── Unknown fields rejected ───────────────────────────────────────────────

    #[test]
    fn unknown_field_rejected() {
        let toml = r#"
[listen]
udp = ["127.0.0.1:53"]
tcp = ["127.0.0.1:53"]
mystery_field = true
"#;
        let result = HushConfig::from_toml_str(toml);
        assert!(
            result.is_err(),
            "unknown field in config must be a parse error"
        );
    }

    // ── Missing bootstrap_ips ─────────────────────────────────────────────────

    #[test]
    fn missing_bootstrap_ips_is_validation_problem() {
        let mut cfg = HushConfig::default();
        // Populate explicit doh so we can test bootstrap_ips validation.
        cfg.upstream.doh = vec![DohEndpoint {
            url: "https://cloudflare-dns.com/dns-query".to_string(),
            bootstrap_ips: vec![],
        }];
        let problems = cfg.validate();
        assert!(
            problems.iter().any(|p| p.message.contains("bootstrap_ips")),
            "missing bootstrap_ips must produce a validation problem"
        );
    }

    // ── Bad listen addr ───────────────────────────────────────────────────────

    #[test]
    fn bad_listen_addr_is_validation_problem() {
        let mut cfg = HushConfig::default();
        cfg.listen.udp.push("not-a-socket-addr".to_string());
        let problems = cfg.validate();
        assert!(
            problems
                .iter()
                .any(|p| p.message.contains("not-a-socket-addr")),
            "bad listen addr must produce a validation problem"
        );
    }

    // ── Collect-all: 3 problems at once ──────────────────────────────────────

    #[test]
    fn collect_all_three_problems() {
        let mut cfg = HushConfig::default();
        // Problem 1: explicit doh entry with no bootstrap IPs.
        cfg.upstream.doh = vec![DohEndpoint {
            url: "https://cloudflare-dns.com/dns-query".to_string(),
            bootstrap_ips: vec![],
        }];
        // Problem 2: bad UDP addr.
        cfg.listen.udp = vec!["bad-udp".to_string()];
        // Problem 3: bad API addr.
        cfg.api.listen = "bad-api".to_string();
        let problems = cfg.validate();
        assert_eq!(
            problems.len(),
            3,
            "config with 3 problems must report exactly 3; got: {problems:?}"
        );
    }

    // ── TOML parse error ──────────────────────────────────────────────────────

    #[test]
    fn malformed_toml_returns_error() {
        let result = HushConfig::from_toml_str("[[this is not toml");
        assert!(result.is_err());
    }

    // ── WP4: preset validation ────────────────────────────────────────────────

    #[test]
    fn unknown_preset_is_validation_problem() {
        let mut cfg = HushConfig::default();
        cfg.lists.preset = "super-strict".to_string();
        let problems = cfg.validate();
        assert!(
            problems
                .iter()
                .any(|p| p.message.contains("unknown") || p.message.contains("preset")),
            "unknown preset must produce a validation problem; got: {problems:?}"
        );
    }

    #[test]
    fn known_presets_validate_clean() {
        for preset in ["minimal", "balanced", "strict", "aggressive"] {
            let mut cfg = HushConfig::default();
            cfg.lists.preset = preset.to_string();
            // Remove default DoH entries so DoH bootstrap problems don't pollute.
            cfg.upstream.doh.clear();
            let problems = cfg.validate();
            assert!(
                problems.is_empty(),
                "preset {preset:?} must validate clean; got: {problems:?}"
            );
        }
    }

    // ── WP4: extra_categories validation ─────────────────────────────────────

    #[test]
    fn unknown_category_is_validation_problem() {
        let mut cfg = HushConfig::default();
        cfg.lists.extra_categories = vec!["not-a-real-category".to_string()];
        cfg.upstream.doh.clear();
        let problems = cfg.validate();
        assert!(
            problems
                .iter()
                .any(|p| p.message.contains("not-a-real-category")),
            "unknown category must produce a validation problem; got: {problems:?}"
        );
    }

    #[test]
    fn multiple_unknown_categories_collected_at_once() {
        let mut cfg = HushConfig::default();
        cfg.lists.extra_categories =
            vec!["bad1".to_string(), "bad2".to_string(), "bad3".to_string()];
        cfg.upstream.doh.clear();
        let problems = cfg.validate();
        let category_problems: Vec<_> = problems
            .iter()
            .filter(|p| p.message.contains("extra_categories"))
            .collect();
        assert_eq!(
            category_problems.len(),
            3,
            "all 3 unknown categories must be reported; got: {problems:?}"
        );
    }

    // ── WP4: custom preset empty union ────────────────────────────────────────

    #[test]
    fn custom_preset_with_empty_sources_is_error() {
        let mut cfg = HushConfig::default();
        cfg.lists.preset = "custom".to_string();
        cfg.lists.extra_categories.clear();
        cfg.lists.sources.clear();
        cfg.upstream.doh.clear();
        let problems = cfg.validate();
        assert!(
            problems.iter().any(|p| p.message.contains("custom")),
            "custom preset with empty sources must produce a problem; got: {problems:?}"
        );
    }

    #[test]
    fn custom_preset_with_explicit_sources_is_valid() {
        let mut cfg = HushConfig::default();
        cfg.lists.preset = "custom".to_string();
        cfg.lists.extra_categories.clear();
        cfg.lists.sources = vec![ListSource {
            name: "my-list".to_string(),
            url: "https://example.com/list.txt".to_string(),
        }];
        cfg.upstream.doh.clear();
        let problems = cfg.validate();
        assert!(
            problems.is_empty(),
            "custom preset with explicit sources must validate clean; got: {problems:?}"
        );
    }

    #[test]
    fn custom_preset_with_only_categories_is_valid() {
        let mut cfg = HushConfig::default();
        cfg.lists.preset = "custom".to_string();
        cfg.lists.extra_categories = vec!["telemetry-windows".to_string()];
        cfg.lists.sources.clear();
        cfg.upstream.doh.clear();
        let problems = cfg.validate();
        assert!(
            problems.is_empty(),
            "custom preset with only categories must validate clean; got: {problems:?}"
        );
    }

    // ── WP4: effective_sources merge rule ─────────────────────────────────────

    #[test]
    fn effective_sources_balanced_default() {
        let cfg = HushConfig::default();
        let sources = cfg.lists.effective_sources();
        // balanced default = oisd-small + hagezi-normal (multi.txt)
        assert_eq!(sources.len(), 2, "balanced default must have 2 sources");
        let urls: Vec<&str> = sources.iter().map(|s| s.url.as_str()).collect();
        assert!(urls.iter().any(|u| u.contains("small.oisd.nl")));
        assert!(urls.iter().any(|u| u.contains("multi.txt")));
    }

    #[test]
    fn effective_sources_merges_explicit_sources() {
        let mut cfg = HushConfig::default();
        cfg.lists.preset = "minimal".to_string();
        cfg.lists.sources = vec![ListSource {
            name: "extra".to_string(),
            url: "https://custom.example.com/extra.txt".to_string(),
        }];
        let sources = cfg.lists.effective_sources();
        // minimal (1) + explicit (1) = 2
        assert_eq!(sources.len(), 2);
        let urls: Vec<&str> = sources.iter().map(|s| s.url.as_str()).collect();
        assert!(urls.iter().any(|u| u.contains("light.txt")));
        assert!(urls.iter().any(|u| u.contains("custom.example.com")));
    }

    #[test]
    fn effective_sources_no_duplicate_when_explicit_matches_preset() {
        let mut cfg = HushConfig::default();
        cfg.lists.preset = "minimal".to_string();
        // Add the same URL that minimal already includes.
        cfg.lists.sources = vec![ListSource {
            name: "dup".to_string(),
            url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/light.txt"
                .to_string(),
        }];
        let sources = cfg.lists.effective_sources();
        assert_eq!(
            sources.len(),
            1,
            "dedup must prevent the same URL appearing twice"
        );
    }

    // ── WP4: effective_lists_config / block_doh_bypass auto-inject ─────────

    /// The doh-bypass catalog URL for use in assertions below.
    const DOH_BYPASS_URL: &str =
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/doh-vpn-proxy-bypass.txt";

    #[test]
    fn effective_lists_config_flag_off_no_doh_bypass() {
        // Default config has block_doh_bypass=false.
        let cfg = HushConfig::default();
        assert!(!cfg.privacy.block_doh_bypass);
        let lists = cfg.effective_lists_config();
        let sources = lists.effective_sources();
        let urls: Vec<&str> = sources.iter().map(|s| s.url.as_str()).collect();
        assert!(
            !urls.contains(&DOH_BYPASS_URL),
            "block_doh_bypass=false must NOT include doh-bypass URL; got: {urls:?}"
        );
    }

    #[test]
    fn effective_lists_config_flag_on_includes_doh_bypass() {
        let mut cfg = HushConfig::default();
        cfg.privacy.block_doh_bypass = true;
        let lists = cfg.effective_lists_config();
        let sources = lists.effective_sources();
        let urls: Vec<&str> = sources.iter().map(|s| s.url.as_str()).collect();
        assert!(
            urls.contains(&DOH_BYPASS_URL),
            "block_doh_bypass=true must include doh-bypass URL; got: {urls:?}"
        );
    }

    #[test]
    fn effective_lists_config_flag_on_plus_explicit_category_no_dup() {
        // User has BOTH the flag on AND extra_categories = ["doh-bypass"].
        // The URL must appear exactly once.
        let mut cfg = HushConfig::default();
        cfg.privacy.block_doh_bypass = true;
        cfg.lists.extra_categories = vec!["doh-bypass".to_string()];
        let lists = cfg.effective_lists_config();
        // extra_categories must NOT gain a second "doh-bypass" entry.
        let doh_count = lists
            .extra_categories
            .iter()
            .filter(|k| *k == "doh-bypass")
            .count();
        assert_eq!(
            doh_count, 1,
            "extra_categories must contain doh-bypass exactly once; got: {:?}",
            lists.extra_categories
        );
        let sources = lists.effective_sources();
        let doh_url_count = sources.iter().filter(|s| s.url == DOH_BYPASS_URL).count();
        assert_eq!(
            doh_url_count, 1,
            "effective_sources must contain doh-bypass URL exactly once; got: {sources:?}"
        );
    }

    #[test]
    fn effective_lists_config_preserves_preset() {
        // The augmented config must keep the original preset name for API reporting.
        let mut cfg = HushConfig::default();
        cfg.lists.preset = "strict".to_string();
        cfg.privacy.block_doh_bypass = true;
        let lists = cfg.effective_lists_config();
        assert_eq!(
            lists.preset, "strict",
            "effective_lists_config must preserve the user's preset"
        );
    }

    // ── WP4: query_log mode parsing ───────────────────────────────────────────

    #[test]
    fn query_log_mode_full_is_default() {
        let cfg = PrivacyConfig::default();
        assert_eq!(cfg.query_log, QueryLogMode::Full);
    }

    #[test]
    fn query_log_mode_roundtrip_anonymous() {
        let toml = r#"
[privacy]
query_log = "anonymous"
"#;
        let cfg = HushConfig::from_toml_str(toml).unwrap();
        assert_eq!(cfg.privacy.query_log, QueryLogMode::Anonymous);
    }

    #[test]
    fn query_log_mode_roundtrip_off() {
        let toml = r#"
[privacy]
query_log = "off"
"#;
        let cfg = HushConfig::from_toml_str(toml).unwrap();
        assert_eq!(cfg.privacy.query_log, QueryLogMode::Off);
    }

    // ── WP4: privacy defaults ─────────────────────────────────────────────────

    #[test]
    fn privacy_defaults_tier1_on_tier2_off() {
        let p = PrivacyConfig::default();
        assert!(p.browser_doh_canary, "Tier 1.2 canary must default ON");
        assert!(
            p.cname_inspection,
            "Tier 1.4 CNAME inspection must default ON"
        );
        assert_eq!(
            p.query_log,
            QueryLogMode::Full,
            "Tier 1.3 must default Full"
        );
        assert!(!p.block_doh_bypass, "Tier 2.1 doh-bypass must default OFF");
        assert!(
            !p.block_private_relay,
            "Tier 2.2 private-relay must default OFF"
        );
        assert!(!p.odoh, "Tier 3 ODoH must default OFF (experimental)");
    }

    // ── WP7: ODoH config validation ───────────────────────────────────────────

    #[test]
    fn odoh_enabled_with_empty_bootstrap_is_validation_problem() {
        let mut cfg = HushConfig::default();
        cfg.privacy.odoh = true;
        cfg.upstream.odoh.bootstrap_ips.clear();
        let problems = cfg.validate();
        assert!(
            problems.iter().any(|p| p.message.contains("bootstrap_ips")),
            "ODoH enabled with empty bootstrap_ips must be a problem; got: {problems:?}"
        );
    }

    #[test]
    fn odoh_enabled_with_http_target_is_validation_problem() {
        let mut cfg = HushConfig::default();
        cfg.privacy.odoh = true;
        cfg.upstream.odoh.target = "http://odoh.cloudflare-dns.com/dns-query".to_string();
        let problems = cfg.validate();
        assert!(
            problems
                .iter()
                .any(|p| p.message.contains("upstream.odoh.target")),
            "ODoH target without https:// must be a problem; got: {problems:?}"
        );
    }

    #[test]
    fn odoh_disabled_ignores_missing_bootstrap() {
        let mut cfg = HushConfig::default();
        cfg.privacy.odoh = false;
        cfg.upstream.odoh.bootstrap_ips.clear();
        // When disabled, missing bootstrap IPs must NOT be an error.
        let problems = cfg.validate();
        assert!(
            !problems.iter().any(|p| p.message.contains("upstream.odoh")),
            "ODoH disabled must not validate odoh section; got: {problems:?}"
        );
    }

    #[test]
    fn odoh_config_round_trip() {
        let mut cfg = HushConfig::default();
        cfg.privacy.odoh = true;
        cfg.upstream.odoh.relay = "https://relay.example.com/proxy".to_string();
        let toml = cfg.to_toml_string().unwrap();
        let loaded = HushConfig::from_toml_str(&toml).unwrap();
        assert_eq!(cfg, loaded);
    }

    // ── upstream.preset: Mullvad selectable upstream (§4) ────────────────────

    /// Default preset gives Cloudflare→Quad9.
    #[test]
    fn upstream_preset_default_gives_cloudflare_quad9() {
        let cfg = HushConfig::default();
        let doh = cfg.upstream.effective_doh();
        assert_eq!(doh.len(), 2, "default preset must have exactly 2 rungs");
        assert!(
            doh[0].url.contains("cloudflare"),
            "rung 0 must be Cloudflare; got: {}",
            doh[0].url
        );
        assert!(
            doh[1].url.contains("quad9"),
            "rung 1 must be Quad9; got: {}",
            doh[1].url
        );
    }

    /// Mullvad preset gives Mullvad→Cloudflare→Quad9 (3 rungs).
    #[test]
    fn upstream_preset_mullvad_gives_mullvad_cloudflare_quad9() {
        let mut cfg = HushConfig::default();
        cfg.upstream.preset = "mullvad".to_string();
        let doh = cfg.upstream.effective_doh();
        assert_eq!(doh.len(), 3, "mullvad preset must have exactly 3 rungs");
        assert!(
            doh[0].url.contains("mullvad"),
            "rung 0 must be Mullvad; got: {}",
            doh[0].url
        );
        assert!(
            doh[1].url.contains("cloudflare"),
            "rung 1 must be Cloudflare; got: {}",
            doh[1].url
        );
        assert!(
            doh[2].url.contains("quad9"),
            "rung 2 must be Quad9; got: {}",
            doh[2].url
        );
        // Mullvad bootstrap IP must be the verified anycast IP.
        assert!(
            doh[0].bootstrap_ips.contains(&"194.242.2.2".to_string()),
            "Mullvad bootstrap must include 194.242.2.2"
        );
    }

    /// When preset=mullvad, the preset ladder is always used; `doh` is ignored.
    /// When preset=default, `doh` is used as-is (explicit control).
    #[test]
    fn default_preset_uses_doh_field_as_is() {
        let mut cfg = HushConfig::default();
        // preset=default, explicit custom doh → doh wins
        cfg.upstream.preset = "default".to_string();
        cfg.upstream.doh = vec![DohEndpoint {
            url: "https://dns.example.com/dns-query".to_string(),
            bootstrap_ips: vec!["1.2.3.4".to_string()],
        }];
        let doh = cfg.upstream.effective_doh();
        assert_eq!(
            doh.len(),
            1,
            "default preset must use doh field; got {doh:?}"
        );
        assert!(
            doh[0].url.contains("example.com"),
            "default preset must return the custom doh entry; got: {}",
            doh[0].url
        );
    }

    /// When preset=default, doh=[] means zero DoH rungs (explicit empty).
    #[test]
    fn default_preset_with_empty_doh_gives_zero_rungs() {
        let mut cfg = HushConfig::default();
        cfg.upstream.preset = "default".to_string();
        cfg.upstream.doh = vec![]; // explicitly empty
        let doh = cfg.upstream.effective_doh();
        assert!(
            doh.is_empty(),
            "default preset with explicit doh=[] must give zero DoH rungs"
        );
    }

    /// When preset=mullvad, doh field is ignored and Mullvad ladder is used.
    #[test]
    fn mullvad_preset_ignores_doh_field() {
        let mut cfg = HushConfig::default();
        cfg.upstream.preset = "mullvad".to_string();
        cfg.upstream.doh = vec![DohEndpoint {
            url: "https://dns.example.com/dns-query".to_string(),
            bootstrap_ips: vec!["1.2.3.4".to_string()],
        }];
        let doh = cfg.upstream.effective_doh();
        assert_eq!(
            doh.len(),
            3,
            "mullvad preset must give 3 rungs; got {doh:?}"
        );
        assert!(
            doh[0].url.contains("mullvad"),
            "mullvad preset rung 0 must be Mullvad; got: {}",
            doh[0].url
        );
    }

    /// Unknown upstream preset is a validation problem.
    #[test]
    fn unknown_upstream_preset_is_validation_problem() {
        let mut cfg = HushConfig::default();
        cfg.upstream.preset = "unicorn".to_string();
        let problems = cfg.validate();
        assert!(
            problems
                .iter()
                .any(|p| p.message.contains("upstream.preset") && p.message.contains("unicorn")),
            "unknown upstream.preset must produce a validation problem; got: {problems:?}"
        );
    }

    /// Unknown preset is always a validation problem (preset is always validated).
    #[test]
    fn unknown_preset_always_flagged() {
        let mut cfg = HushConfig::default();
        cfg.upstream.preset = "unicorn".to_string();
        // Even with an explicit doh, unknown preset is flagged (preset is always
        // consulted; e.g. mullvad preset ignores doh entirely).
        let problems = cfg.validate();
        assert!(
            problems
                .iter()
                .any(|p| p.message.contains("upstream.preset")),
            "unknown preset must always produce a problem; got: {problems:?}"
        );
    }

    /// Config round-trip with upstream.preset field.
    #[test]
    fn upstream_preset_round_trip() {
        let mut cfg = HushConfig::default();
        cfg.upstream.preset = "mullvad".to_string();
        let toml = cfg.to_toml_string().unwrap();
        let loaded = HushConfig::from_toml_str(&toml).unwrap();
        assert_eq!(
            cfg, loaded,
            "upstream.preset must survive a TOML round-trip"
        );
    }

    /// Mullvad preset validates clean.
    #[test]
    fn mullvad_preset_validates_clean() {
        let mut cfg = HushConfig::default();
        cfg.upstream.preset = "mullvad".to_string();
        let problems = cfg.validate();
        assert!(
            problems.is_empty(),
            "mullvad preset must validate clean; got: {problems:?}"
        );
    }

    // ── WP8 §1: new config fields ─────────────────────────────────────────────

    /// Default config includes the new WP8 fields with correct defaults.
    #[test]
    fn wp8_defaults_on() {
        let cfg = HushConfig::default();
        assert!(cfg.upstream.h3, "upstream.h3 must default to true");
        assert!(
            cfg.privacy.doh_padding,
            "privacy.doh_padding must default to true"
        );
        assert!(
            cfg.privacy.rebind_protection,
            "privacy.rebind_protection must default to true"
        );
        assert!(
            cfg.privacy.rebind_allow.is_empty(),
            "privacy.rebind_allow must default to empty"
        );
    }

    /// Round-trip with WP8 fields set to non-default values.
    #[test]
    fn wp8_round_trip() {
        let mut cfg = HushConfig::default();
        cfg.upstream.h3 = false;
        cfg.privacy.doh_padding = false;
        cfg.privacy.rebind_protection = false;
        cfg.privacy.rebind_allow = vec!["corp.example.com".to_string(), "lan.internal".to_string()];
        let toml = cfg.to_toml_string().unwrap();
        let loaded = HushConfig::from_toml_str(&toml).unwrap();
        assert_eq!(cfg, loaded, "WP8 fields must survive a TOML round-trip");
    }

    /// Valid `rebind_allow` entries produce no validation problem.
    #[test]
    fn rebind_allow_valid_entries_pass() {
        let mut cfg = HushConfig::default();
        cfg.privacy.rebind_allow = vec![
            "example.com".to_string(),
            "corp.internal".to_string(),
            "plex.direct".to_string(),
        ];
        let problems = cfg.validate();
        assert!(
            !problems.iter().any(|p| p.message.contains("rebind_allow")),
            "valid rebind_allow entries must not produce problems; got: {problems:?}"
        );
    }

    /// Malformed `rebind_allow` entries produce a validation problem each.
    #[test]
    fn rebind_allow_invalid_entry_is_validation_problem() {
        let mut cfg = HushConfig::default();
        cfg.privacy.rebind_allow = vec!["not a domain!".to_string()];
        let problems = cfg.validate();
        assert!(
            problems
                .iter()
                .any(|p| p.message.contains("rebind_allow") && p.message.contains("[0]")),
            "invalid rebind_allow entry must produce a problem; got: {problems:?}"
        );
    }

    /// Multiple malformed `rebind_allow` entries are all reported at once.
    #[test]
    fn rebind_allow_multiple_invalid_entries_all_reported() {
        let mut cfg = HushConfig::default();
        cfg.privacy.rebind_allow = vec![
            "valid.example.com".to_string(),
            "!!bad1!!".to_string(),
            "!!bad2!!".to_string(),
        ];
        let problems = cfg.validate();
        let rebind_problems: Vec<_> = problems
            .iter()
            .filter(|p| p.message.contains("rebind_allow"))
            .collect();
        assert_eq!(
            rebind_problems.len(),
            2,
            "both invalid entries must be reported; got: {problems:?}"
        );
    }

    /// WP8 default config validates clean (h3 + doh_padding + rebind_protection).
    #[test]
    fn wp8_default_validates_clean() {
        let cfg = HushConfig::default();
        let problems = cfg.validate();
        assert!(
            problems.is_empty(),
            "WP8 default config must validate clean; got: {problems:?}"
        );
    }

    // ── WP9: retain_days validation ───────────────────────────────────────────

    #[test]
    fn retain_days_default_is_7() {
        let cfg = HushConfig::default();
        assert_eq!(cfg.privacy.retain_days, 7);
    }

    #[test]
    fn retain_days_boundary_1_valid() {
        let mut cfg = HushConfig::default();
        cfg.privacy.retain_days = 1;
        let problems = cfg.validate();
        assert!(
            !problems.iter().any(|p| p.message.contains("retain_days")),
            "retain_days=1 must be valid; got: {problems:?}"
        );
    }

    #[test]
    fn retain_days_boundary_90_valid() {
        let mut cfg = HushConfig::default();
        cfg.privacy.retain_days = 90;
        let problems = cfg.validate();
        assert!(
            !problems.iter().any(|p| p.message.contains("retain_days")),
            "retain_days=90 must be valid; got: {problems:?}"
        );
    }

    #[test]
    fn retain_days_0_is_validation_problem() {
        let mut cfg = HushConfig::default();
        cfg.privacy.retain_days = 0;
        let problems = cfg.validate();
        assert!(
            problems.iter().any(|p| p.message.contains("retain_days")),
            "retain_days=0 must produce a validation problem; got: {problems:?}"
        );
    }

    #[test]
    fn retain_days_91_is_validation_problem() {
        let mut cfg = HushConfig::default();
        cfg.privacy.retain_days = 91;
        let problems = cfg.validate();
        assert!(
            problems.iter().any(|p| p.message.contains("retain_days")),
            "retain_days=91 must produce a validation problem; got: {problems:?}"
        );
    }

    #[test]
    fn retain_days_round_trip() {
        let mut cfg = HushConfig::default();
        cfg.privacy.retain_days = 30;
        let toml = cfg.to_toml_string().unwrap();
        let loaded = HushConfig::from_toml_str(&toml).unwrap();
        assert_eq!(loaded.privacy.retain_days, 30);
    }

    // ── WP9: dashboard config ─────────────────────────────────────────────────

    #[test]
    fn dashboard_enabled_by_default() {
        let cfg = HushConfig::default();
        assert!(
            cfg.dashboard.enabled,
            "dashboard must be enabled by default"
        );
    }

    #[test]
    fn dashboard_config_round_trip() {
        let mut cfg = HushConfig::default();
        cfg.dashboard.enabled = false;
        let toml = cfg.to_toml_string().unwrap();
        let loaded = HushConfig::from_toml_str(&toml).unwrap();
        assert!(!loaded.dashboard.enabled);
    }

    // ── WP13: network_guard config validation ─────────────────────────────────

    #[test]
    fn network_guard_default_is_disabled_and_validates_clean() {
        let cfg = HushConfig::default();
        assert!(
            !cfg.network_guard.enabled,
            "network_guard must default disabled"
        );
        assert!(
            cfg.network_guard.bind.is_empty(),
            "network_guard.bind must default empty"
        );
        assert!(!cfg.network_guard.log_clients);
        let problems = cfg.validate();
        assert!(
            !problems.iter().any(|p| p.message.contains("network_guard")),
            "default network_guard must produce no validation problems; got: {problems:?}"
        );
    }

    #[test]
    fn network_guard_wildcard_refused() {
        let mut cfg = HushConfig::default();
        cfg.network_guard.bind = vec!["0.0.0.0".to_string()];
        let problems = cfg.validate();
        assert!(
            problems.iter().any(|p| p.message.contains("unspecified")),
            "0.0.0.0 in bind must be refused; got: {problems:?}"
        );
    }

    #[test]
    fn network_guard_ipv6_wildcard_refused() {
        let mut cfg = HushConfig::default();
        cfg.network_guard.bind = vec!["::".to_string()];
        let problems = cfg.validate();
        assert!(
            problems.iter().any(|p| p.message.contains("unspecified")),
            ":: in bind must be refused; got: {problems:?}"
        );
    }

    #[test]
    fn network_guard_loopback_refused() {
        let mut cfg = HushConfig::default();
        cfg.network_guard.bind = vec!["127.0.0.1".to_string()];
        let problems = cfg.validate();
        assert!(
            problems.iter().any(|p| p.message.contains("loopback")),
            "127.0.0.1 in bind must be refused; got: {problems:?}"
        );
    }

    #[test]
    fn network_guard_ipv6_loopback_refused() {
        let mut cfg = HushConfig::default();
        cfg.network_guard.bind = vec!["::1".to_string()];
        let problems = cfg.validate();
        assert!(
            problems.iter().any(|p| p.message.contains("loopback")),
            "::1 in bind must be refused; got: {problems:?}"
        );
    }

    #[test]
    fn network_guard_enabled_empty_bind_refused() {
        let mut cfg = HushConfig::default();
        cfg.network_guard.enabled = true;
        cfg.network_guard.bind = vec![];
        let problems = cfg.validate();
        assert!(
            problems
                .iter()
                .any(|p| p.message.contains("requires at least one entry")),
            "enabled=true with empty bind must be refused; got: {problems:?}"
        );
    }

    #[test]
    fn network_guard_invalid_ip_refused() {
        let mut cfg = HushConfig::default();
        cfg.network_guard.bind = vec!["not-an-ip".to_string()];
        let problems = cfg.validate();
        assert!(
            problems.iter().any(|p| p.message.contains("not-an-ip")),
            "invalid IP in bind must be refused; got: {problems:?}"
        );
    }

    #[test]
    fn network_guard_disabled_with_invalid_bind_still_validates_bind() {
        // Even when disabled, bind entries are validated (early feedback).
        let mut cfg = HushConfig::default();
        cfg.network_guard.enabled = false;
        cfg.network_guard.bind = vec!["0.0.0.0".to_string()];
        let problems = cfg.validate();
        assert!(
            problems.iter().any(|p| p.message.contains("unspecified")),
            "disabled network_guard with bad bind must still validate bind; got: {problems:?}"
        );
    }

    #[test]
    fn network_guard_valid_lan_ip_with_enabled_validates_clean() {
        let mut cfg = HushConfig::default();
        cfg.network_guard.enabled = true;
        cfg.network_guard.bind = vec!["192.168.1.10".to_string()];
        cfg.network_guard.log_clients = true;
        let problems = cfg.validate();
        assert!(
            !problems.iter().any(|p| p.message.contains("network_guard")),
            "valid network_guard config must validate clean; got: {problems:?}"
        );
    }

    #[test]
    fn network_guard_round_trip() {
        let mut cfg = HushConfig::default();
        cfg.network_guard.enabled = true;
        cfg.network_guard.bind = vec!["192.168.1.10".to_string(), "10.0.0.1".to_string()];
        cfg.network_guard.log_clients = true;
        let toml = cfg.to_toml_string().unwrap();
        let loaded = HushConfig::from_toml_str(&toml).unwrap();
        assert_eq!(cfg.network_guard, loaded.network_guard);
    }

    // ── WP12: snapshot_dir ────────────────────────────────────────────────────

    #[test]
    fn snapshot_dir_defaults_none() {
        let cfg = HushConfig::default();
        assert!(
            cfg.lists.snapshot_dir.is_none(),
            "snapshot_dir must default to None"
        );
    }

    #[test]
    fn snapshot_dir_round_trip() {
        let mut cfg = HushConfig::default();
        cfg.lists.snapshot_dir = Some("/usr/local/share/hushwarren/snapshot".to_string());
        let toml = cfg.to_toml_string().unwrap();
        let loaded = HushConfig::from_toml_str(&toml).unwrap();
        assert_eq!(
            loaded.lists.snapshot_dir.as_deref(),
            Some("/usr/local/share/hushwarren/snapshot"),
            "snapshot_dir must survive a TOML round-trip"
        );
    }

    #[test]
    fn snapshot_dir_none_round_trip() {
        let cfg = HushConfig::default();
        let toml = cfg.to_toml_string().unwrap();
        let loaded = HushConfig::from_toml_str(&toml).unwrap();
        assert!(
            loaded.lists.snapshot_dir.is_none(),
            "snapshot_dir absent in TOML must deserialise to None"
        );
    }

    // ── WP14: inbound_tls config validation ──────────────────────────────────

    #[test]
    fn inbound_tls_default_is_disabled_and_validates_clean() {
        let cfg = HushConfig::default();
        assert!(
            !cfg.inbound_tls.enabled,
            "inbound_tls must default disabled"
        );
        assert!(cfg.inbound_tls.bind.is_empty());
        assert!(cfg.inbound_tls.cert_path.is_empty());
        assert!(cfg.inbound_tls.key_path.is_empty());
        assert!(!cfg.inbound_tls.doq);
        let problems = cfg.validate();
        assert!(
            !problems.iter().any(|p| p.message.contains("inbound_tls")),
            "default inbound_tls must produce no problems; got: {problems:?}"
        );
    }

    #[test]
    fn inbound_tls_enabled_empty_bind_refused() {
        let mut cfg = HushConfig::default();
        cfg.inbound_tls.enabled = true;
        cfg.inbound_tls.bind = vec![];
        let problems = cfg.validate();
        assert!(
            problems
                .iter()
                .any(|p| p.message.contains("inbound_tls.bind")),
            "enabled with empty bind must be refused; got: {problems:?}"
        );
    }

    #[test]
    fn inbound_tls_cert_without_key_refused() {
        let mut cfg = HushConfig::default();
        cfg.inbound_tls.cert_path = "/etc/ssl/cert.pem".to_string();
        cfg.inbound_tls.key_path = String::new();
        let problems = cfg.validate();
        assert!(
            problems
                .iter()
                .any(|p| p.message.contains("cert_path") && p.message.contains("key_path")),
            "cert without key must be refused; got: {problems:?}"
        );
    }

    #[test]
    fn inbound_tls_key_without_cert_refused() {
        let mut cfg = HushConfig::default();
        cfg.inbound_tls.cert_path = String::new();
        cfg.inbound_tls.key_path = "/etc/ssl/key.pem".to_string();
        let problems = cfg.validate();
        assert!(
            problems
                .iter()
                .any(|p| p.message.contains("key_path") && p.message.contains("cert_path")),
            "key without cert must be refused; got: {problems:?}"
        );
    }

    #[test]
    fn inbound_tls_doq_without_enabled_refused() {
        let mut cfg = HushConfig::default();
        cfg.inbound_tls.doq = true;
        let problems = cfg.validate();
        assert!(
            problems.iter().any(|p| p.message.contains("doq")),
            "doq without enabled must be refused; got: {problems:?}"
        );
    }

    #[test]
    fn inbound_tls_enabled_with_bind_and_self_signed_validates_clean() {
        let mut cfg = HushConfig::default();
        cfg.inbound_tls.enabled = true;
        cfg.inbound_tls.bind = vec!["127.0.0.1".to_string()];
        // Empty cert/key → self-signed path.
        let problems = cfg.validate();
        assert!(
            !problems.iter().any(|p| p.message.contains("inbound_tls")),
            "enabled with bind and self-signed path must validate clean; got: {problems:?}"
        );
    }

    #[test]
    fn inbound_tls_enabled_with_both_cert_and_key_validates_clean() {
        let mut cfg = HushConfig::default();
        cfg.inbound_tls.enabled = true;
        cfg.inbound_tls.bind = vec!["127.0.0.1".to_string()];
        cfg.inbound_tls.cert_path = "/etc/ssl/cert.pem".to_string();
        cfg.inbound_tls.key_path = "/etc/ssl/key.pem".to_string();
        let problems = cfg.validate();
        assert!(
            !problems.iter().any(|p| p.message.contains("inbound_tls")),
            "enabled with both cert and key must validate clean; got: {problems:?}"
        );
    }

    #[test]
    fn inbound_tls_round_trip() {
        let mut cfg = HushConfig::default();
        cfg.inbound_tls.enabled = true;
        cfg.inbound_tls.bind = vec!["127.0.0.1".to_string(), "::1".to_string()];
        cfg.inbound_tls.doq = true;
        let toml = cfg.to_toml_string().unwrap();
        let loaded = HushConfig::from_toml_str(&toml).unwrap();
        assert_eq!(cfg.inbound_tls, loaded.inbound_tls);
    }

    #[test]
    fn inbound_tls_invalid_ip_refused() {
        let mut cfg = HushConfig::default();
        cfg.inbound_tls.bind = vec!["not-an-ip".to_string()];
        let problems = cfg.validate();
        assert!(
            problems.iter().any(|p| p.message.contains("not-an-ip")),
            "invalid IP in inbound_tls.bind must be refused; got: {problems:?}"
        );
    }

    // ── WP14: mdns_insight config ─────────────────────────────────────────────

    #[test]
    fn network_guard_mdns_insight_defaults_false() {
        let cfg = HushConfig::default();
        assert!(
            !cfg.network_guard.mdns_insight,
            "mdns_insight must default false"
        );
    }

    #[test]
    fn network_guard_mdns_insight_round_trip() {
        let mut cfg = HushConfig::default();
        cfg.network_guard.mdns_insight = true;
        let toml = cfg.to_toml_string().unwrap();
        let loaded = HushConfig::from_toml_str(&toml).unwrap();
        assert!(loaded.network_guard.mdns_insight);
    }

    // ── WP14: reload-subset partition table ───────────────────────────────────
    //
    // This test enumerates every top-level field of HushConfig and checks that
    // it is classified as either "hot-reloadable" or "requires_restart".
    // IT MUST FAIL if a new config field is added without being classified.
    //
    // Classification rules from specs/wp14-nice.md §2:
    //   HOT-RELOADABLE: lists, privacy, upstream
    //   REQUIRES_RESTART: listen, network_guard, inbound_tls, api, runtime,
    //                     sentinel, dashboard

    #[test]
    fn reload_subset_partition_table_complete() {
        // All top-level HushConfig fields, grouped.
        // This must stay in sync with HushConfig struct fields.
        let hot_reloadable = ["lists", "privacy", "upstream"];
        let requires_restart = [
            "listen",
            "block",
            "api",
            "runtime",
            "sentinel",
            "dashboard",
            "network_guard",
            "inbound_tls",
        ];

        // Verify no field is unclassified by building the config as TOML and
        // checking all its top-level keys appear in one of the two lists.
        let cfg = HushConfig::default();
        let toml_str = cfg.to_toml_string().unwrap();
        let toml_val: toml::Value = toml::from_str(&toml_str).unwrap();
        let table = toml_val
            .as_table()
            .expect("HushConfig must serialize to a TOML table");

        let mut all_classified: Vec<&str> = hot_reloadable.to_vec();
        all_classified.extend_from_slice(&requires_restart);

        let mut unclassified: Vec<String> = Vec::new();
        for key in table.keys() {
            if !all_classified.contains(&key.as_str()) {
                unclassified.push(key.clone());
            }
        }

        assert!(
            unclassified.is_empty(),
            "Unclassified HushConfig top-level fields (add to hot_reloadable or requires_restart): {unclassified:?}. \
             Every new config field must be explicitly classified in this test."
        );
    }
}
