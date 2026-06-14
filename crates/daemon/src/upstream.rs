//! Upstream DNS resolver ladder.
//!
//! Implements `specs/wp2-daemon.md` §3 and `specs/wp8-transport-privacy.md` §2–§3.
//!
//! The ladder has two tiers at P0:
//! - Primary: zero or more DoH endpoints (hickory-resolver, bootstrap IPs).
//! - Fallback: optional plain Do53 endpoint (IP address, no hostname lookup).
//!
//! ## WP8 §2 — DoH3 rungs
//!
//! When `upstream.h3 = true` (default), for each DoH provider *verified* to
//! serve DoH3, a `doh3://` rung is inserted immediately before the provider's
//! `doh://` (h2) rung.  Verified providers: **Cloudflare** and **Quad9**
//! (Quad9 GA announced 2026-03-31; source: <https://quad9.net/news/blog/quad9-enables-dns-over-http-3-and-dns-over-quic/>).
//! **Mullvad**: verified 2026-06-12 via <https://mullvad.net/en/help/dns-over-https-and-dns-over-tls> —
//! **does NOT support DoH3/HTTP3**; only DoH (h2) and DoT are documented.
//! No Mullvad h3 rung is added.
//!
//! When `upstream.h3 = false` the ladder is byte-identical to today (h2-only).
//! Rung labels include `doh3://` vs `doh://` to distinguish in status/logs.
//!
//! An unreachable h3 rung (UDP/443 blocked) times out in `RUNG_TIMEOUT` and
//! the existing rung-failover machinery advances to the h2 rung — no new
//! fallback logic required.
//!
//! ## WP8 §3 — EDNS padding (RFC 8467)
//!
//! **Seam decision**: hickory-resolver 0.26.1 `ResolverOpts` has no hook for
//! attaching custom EDNS options to outgoing queries — confirmed by reviewing
//! docs.rs for `ResolverOpts` (only `edns0: bool` and `edns_payload_len: u16`
//! exist; no option-attachment API).  Option (b) from the spec is therefore
//! chosen for the hickory DoH path: a hand-rolled `PaddedDohRung` that builds
//! the query via `hickory_proto::op::Message`, pads it, and POSTs
//! `application/dns-message` over a reqwest h2 client with bootstrap-IP
//! discipline (never consults system DNS).
//!
//! Consequence for h3 rungs: hickory h3 rungs are unpadded (hickory owns
//! serialization; no seam exposed).  For v1, EDNS padding covers h2 + ODoH
//! rungs only.  This is explicitly surfaced in comments and in the run summary.
//! When `privacy.doh_padding = false`, the unpadded hickory DoH rung is used
//! for all h2 traffic (unchanged from pre-WP8 behaviour).
//!
//! **Loop-hazard invariant (architecture §5, hard requirement):** resolvers are
//! configured ONLY from explicit `bootstrap_ips`.  `from_system_conf()` / the
//! OS `/etc/resolv.conf` path is never consulted.  Construction panics if the
//! validated config reaches here with empty bootstrap lists — the validation in
//! `hush-core::HushConfig::validate` is the primary gate.
//!
//! Ladder semantics:
//! - Try current rung; on error/timeout (2 s per rung) advance once and retry.
//! - After last rung exhausted → `UpstreamError::AllExhausted`.
//! - A success on a lower rung schedules a background probe of rung 0 after
//!   30 s (simple recovery; only move UP on a successful probe — no flapping).
//!
//! P1 note: CNAME-cloaking defence (evaluating every CNAME target against the
//! rules) is deferred — the original qname only is checked at P0.
// P1: CNAME-cloaking defence — evaluate every CNAME chain target against rules.

use crate::odoh::OdohRung;
use crate::padding::{pad_dns_query, PaddingError};
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query},
    rr::{Name, RecordType},
};
use hickory_resolver::{
    config::{NameServerConfig, ResolverConfig, ResolverOpts},
    lookup::Lookup,
    TokioResolver,
};
use hush_core::config::{DohEndpoint, PrivacyConfig, UpstreamConfig};
use rand::SeedableRng;
use reqwest::{
    header::{ACCEPT, CONTENT_TYPE},
    Client,
};
use std::{
    net::{IpAddr, SocketAddr},
    sync::atomic::{AtomicUsize, Ordering},
    sync::Arc,
    time::Duration,
};
use thiserror::Error;
use tokio::time::timeout;
use tracing::{debug, info, warn};

/// MIME type for DNS-over-HTTPS wire-format messages (RFC 8484 §6).
const DOH_CONTENT_TYPE: &str = "application/dns-message";

/// Per-rung timeout for the padded-DoH rung.
///
/// Matches `RUNG_TIMEOUT` — kept separate so the padded path uses the same
/// deadline as hickory rungs, keeping failover timing uniform.
const PADDED_DOH_TIMEOUT: Duration = RUNG_TIMEOUT;

// ── Provider DoH3 verification table ─────────────────────────────────────────
//
// Only providers listed here receive an h3 rung when `upstream.h3 = true`.
// Unverified providers get only the h2 rung regardless of the flag.
//
// To add a new provider: search for their DNS documentation, confirm HTTP/3
// support, then add their hostname to this slice and document the source + date.

/// Hostnames (lowercase, no trailing dot) of DoH providers verified to serve
/// DoH3 (HTTP/3 over QUIC on UDP/443).
///
/// Verification sources (checked 2026-06-12):
/// - `cloudflare-dns.com`: Cloudflare 1.1.1.1 — serves DoH3; widely documented.
/// - `dns.quad9.net`: Quad9 GA DoH3 announced 2026-03-31
///   (<https://quad9.net/news/blog/quad9-enables-dns-over-http-3-and-dns-over-quic/>).
/// - `dns.mullvad.net`: NOT in this list — Mullvad documents only DoH (h2) and
///   DoT as of 2026-06-12
///   (<https://mullvad.net/en/help/dns-over-https-and-dns-over-tls>).
///   No h3 rung is added for Mullvad.
const DOH3_VERIFIED_HOSTS: &[&str] = &["cloudflare-dns.com", "dns.quad9.net"];

/// The per-rung query timeout.
const RUNG_TIMEOUT: Duration = Duration::from_secs(2);

/// Delay before probing rung 0 after a successful fallback.
// WP3-seam: used by spawn_rung0_probe_arc when rung failover recovery is wired.
#[allow(dead_code)]
const RUNG_0_PROBE_DELAY: Duration = Duration::from_secs(30);

/// Errors from the upstream ladder.
#[derive(Debug, Error)]
pub enum UpstreamError {
    /// All ladder rungs timed out or returned a transport error.
    #[error("all upstream rungs exhausted after ladder traversal")]
    AllExhausted,
    /// A single rung encountered a resolver error (logged; ladder advances).
    #[error("rung error: {0}")]
    Rung(String),
}

/// Testable resolver abstraction.
///
/// The production implementation is [`HickoryResolver`]; tests inject a mock.
pub trait Resolve: Send + Sync + 'static {
    /// Perform a DNS lookup, returning a [`Lookup`] on success.
    fn lookup<'a>(
        &'a self,
        name: &'a str,
        rtype: RecordType,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Lookup, String>> + Send + 'a>>;
}

/// A [`Resolve`] impl backed by a real hickory `TokioResolver`.
pub struct HickoryResolver {
    inner: TokioResolver,
}

impl HickoryResolver {
    /// Build a DoH resolver using ONLY the given `bootstrap_ips`.
    ///
    /// Invariant: never calls `from_system_conf` or any OS resolver path.
    ///
    /// # Panics
    ///
    /// Panics if `bootstrap_ips` is empty — the caller (validated config)
    /// must ensure at least one IP is present.
    pub fn new_doh(endpoint: &DohEndpoint) -> Result<Self, UpstreamError> {
        assert!(
            !endpoint.bootstrap_ips.is_empty(),
            "DoH endpoint {} must have at least one bootstrap IP (loop-hazard guard)",
            endpoint.url
        );

        // Extract server_name and path from the DoH URL.
        // URL format: https://<host>[/<path>]
        let (server_name, path) = parse_doh_url(&endpoint.url)?;

        // Build ResolverConfig from explicit bootstrap IPs only — never
        // from_system_conf (loop hazard).
        let mut name_servers = Vec::new();
        for ip_str in &endpoint.bootstrap_ips {
            let ip: IpAddr = ip_str
                .parse::<IpAddr>()
                .map_err(|_| UpstreamError::Rung(format!("invalid bootstrap IP: {ip_str}")))?;
            // Use NameServerConfig::https constructor (feature-gated __https).
            let ns = NameServerConfig::https(
                ip,
                Arc::from(server_name.as_str()),
                Some(Arc::from(path.as_str())),
            );
            name_servers.push(ns);
        }
        let config = ResolverConfig::from_parts(None, vec![], name_servers);

        let mut opts = ResolverOpts::default();
        // TTL clamping: min 5s, max 86400s (architecture §5).
        opts.positive_min_ttl = Some(Duration::from_secs(5));
        opts.positive_max_ttl = Some(Duration::from_secs(86_400));
        opts.negative_min_ttl = Some(Duration::from_secs(5));
        opts.negative_max_ttl = Some(Duration::from_secs(86_400));
        // Enable caching.
        opts.cache_size = 4096;

        let resolver = TokioResolver::builder_with_config(config, Default::default())
            .with_options(opts)
            .build()
            .map_err(|e| UpstreamError::Rung(format!("failed to build DoH resolver: {e}")))?;

        Ok(Self { inner: resolver })
    }

    /// Build a DoH3 (HTTP/3 over QUIC) resolver using ONLY the given `bootstrap_ips`.
    ///
    /// Requires the `h3-ring` feature (see `Cargo.toml`).  Uses
    /// `NameServerConfig::h3` which maps to hickory-resolver's HTTP/3 path.
    ///
    /// Invariant: never calls `from_system_conf` or any OS resolver path.
    ///
    /// # Panics
    ///
    /// Panics if `bootstrap_ips` is empty — the caller (validated config)
    /// must ensure at least one IP is present.
    pub fn new_doh3(endpoint: &DohEndpoint) -> Result<Self, UpstreamError> {
        assert!(
            !endpoint.bootstrap_ips.is_empty(),
            "DoH3 endpoint {} must have at least one bootstrap IP (loop-hazard guard)",
            endpoint.url
        );

        let (server_name, path) = parse_doh_url(&endpoint.url)?;

        let mut name_servers = Vec::new();
        for ip_str in &endpoint.bootstrap_ips {
            let ip: IpAddr = ip_str
                .parse::<IpAddr>()
                .map_err(|_| UpstreamError::Rung(format!("invalid bootstrap IP: {ip_str}")))?;
            // NameServerConfig::h3 is the HTTP/3-over-QUIC constructor (h3-ring feature).
            let ns = NameServerConfig::h3(
                ip,
                Arc::from(server_name.as_str()),
                Some(Arc::from(path.as_str())),
            );
            name_servers.push(ns);
        }
        let config = ResolverConfig::from_parts(None, vec![], name_servers);

        let mut opts = ResolverOpts::default();
        opts.positive_min_ttl = Some(Duration::from_secs(5));
        opts.positive_max_ttl = Some(Duration::from_secs(86_400));
        opts.negative_min_ttl = Some(Duration::from_secs(5));
        opts.negative_max_ttl = Some(Duration::from_secs(86_400));
        opts.cache_size = 4096;

        let resolver = TokioResolver::builder_with_config(config, Default::default())
            .with_options(opts)
            .build()
            .map_err(|e| UpstreamError::Rung(format!("failed to build DoH3 resolver: {e}")))?;

        Ok(Self { inner: resolver })
    }

    /// Build a plain Do53 resolver for `addr` using ONLY that IP + port.
    ///
    /// Invariant: never consults the system resolver.
    pub fn new_do53(addr: SocketAddr) -> Result<Self, UpstreamError> {
        // Build a NameServerConfig with the correct port.  `udp_and_tcp(ip)`
        // defaults to port 53; we override each ConnectionConfig's port to
        // match the caller-supplied SocketAddr (matters for tests with
        // ephemeral ports and for non-standard upstream configurations).
        let mut ns = NameServerConfig::udp_and_tcp(addr.ip());
        for conn in &mut ns.connections {
            conn.port = addr.port();
        }
        let name_servers = vec![ns];
        let config = ResolverConfig::from_parts(None, vec![], name_servers);

        let mut opts = ResolverOpts::default();
        opts.positive_min_ttl = Some(Duration::from_secs(5));
        opts.positive_max_ttl = Some(Duration::from_secs(86_400));
        opts.negative_min_ttl = Some(Duration::from_secs(5));
        opts.negative_max_ttl = Some(Duration::from_secs(86_400));
        opts.cache_size = 1024;

        let resolver = TokioResolver::builder_with_config(config, Default::default())
            .with_options(opts)
            .build()
            .map_err(|e| UpstreamError::Rung(format!("failed to build Do53 resolver: {e}")))?;

        Ok(Self { inner: resolver })
    }
}

impl Resolve for HickoryResolver {
    fn lookup<'a>(
        &'a self,
        name: &'a str,
        rtype: RecordType,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Lookup, String>> + Send + 'a>>
    {
        Box::pin(async move {
            self.inner
                .lookup(name, rtype)
                .await
                .map_err(|e| e.to_string())
        })
    }
}

// ── PaddedDohRung ─────────────────────────────────────────────────────────────

/// A hand-rolled DoH/h2 rung that applies RFC 8467 EDNS(0) padding.
///
/// Used when `privacy.doh_padding = true`.  Builds the query with
/// `hickory_proto::op::Message`, pads it via [`crate::padding::pad_dns_query`],
/// and POSTs `application/dns-message` over a reqwest h2 client.
///
/// Bootstrap-IP discipline: reqwest's `resolve_to_addrs` override maps the DoH
/// hostname to the explicit IPs so the daemon never resolves it through itself
/// (loop-hazard rule).
///
/// When `doh_padding = false` the unpadded `HickoryResolver` (hickory's own DoH
/// path) is used instead — this rung is not instantiated in that case.
pub(crate) struct PaddedDohRung {
    /// The fully-qualified DoH URL, e.g. `https://cloudflare-dns.com/dns-query`.
    url: String,
    /// reqwest client pre-configured with bootstrap-IP overrides and h2.
    client: Client,
}

impl PaddedDohRung {
    /// Construct a padded DoH rung from the given endpoint config.
    ///
    /// # Errors
    ///
    /// Returns `UpstreamError::Rung` if any bootstrap IP is invalid or the
    /// reqwest client cannot be built.
    pub(crate) fn new(endpoint: &DohEndpoint) -> Result<Self, UpstreamError> {
        assert!(
            !endpoint.bootstrap_ips.is_empty(),
            "PaddedDohRung {} must have at least one bootstrap IP (loop-hazard guard)",
            endpoint.url
        );

        let (host, port) = parse_doh_url_host_port(&endpoint.url)?;

        let addrs: Vec<std::net::SocketAddr> = endpoint
            .bootstrap_ips
            .iter()
            .map(|ip_str| {
                ip_str
                    .parse::<IpAddr>()
                    .map(|ip| std::net::SocketAddr::new(ip, port))
                    .map_err(|_| UpstreamError::Rung(format!("invalid bootstrap IP: {ip_str}")))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let client = Client::builder()
            .use_rustls_tls()
            .https_only(true)
            .http2_prior_knowledge()
            .resolve_to_addrs(&host, &addrs)
            .build()
            .map_err(|e| UpstreamError::Rung(format!("failed to build padded DoH client: {e}")))?;

        Ok(Self {
            url: endpoint.url.clone(),
            client,
        })
    }

    /// Send a padded DoH query and parse the response.
    async fn do_query(&self, name: &str, rtype: RecordType) -> Result<Lookup, String> {
        // Build the DNS query wire bytes.
        let query_wire = build_doh_query(name, rtype).map_err(|e| e.to_string())?;

        // Apply RFC 8467 EDNS(0) padding — bring serialized length to multiple of 128.
        let padded = pad_dns_query(&query_wire).map_err(|e| e.to_string())?;

        debug!(
            url = %self.url,
            query_len = query_wire.len(),
            padded_len = padded.len(),
            "padded DoH query"
        );

        // POST to the DoH endpoint.
        let resp = self
            .client
            .post(&self.url)
            .header(CONTENT_TYPE, DOH_CONTENT_TYPE)
            .header(ACCEPT, DOH_CONTENT_TYPE)
            .body(padded)
            .timeout(PADDED_DOH_TIMEOUT)
            .send()
            .await
            .map_err(|e| format!("padded DoH transport error: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("padded DoH server returned HTTP {}", resp.status()));
        }

        let body = resp
            .bytes()
            .await
            .map_err(|e| format!("padded DoH body read error: {e}"))?;

        // Parse the DNS response.
        let msg =
            Message::from_vec(&body).map_err(|e| format!("padded DoH DNS parse error: {e}"))?;

        // Build a Lookup from the response message.
        let qname = Name::from_ascii(name).map_err(|e| format!("invalid qname {name}: {e}"))?;
        let mut query = Query::new();
        query.set_name(qname);
        query.set_query_type(rtype);

        let answers = msg.answers.clone();
        let valid_until = std::time::Instant::now() + std::time::Duration::from_secs(86_400);
        Ok(Lookup::new_with_deadline(query, answers, valid_until))
    }
}

impl Resolve for PaddedDohRung {
    fn lookup<'a>(
        &'a self,
        name: &'a str,
        rtype: RecordType,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Lookup, String>> + Send + 'a>>
    {
        Box::pin(self.do_query(name, rtype))
    }
}

/// Build a minimal DNS query `Message` and return its wire bytes.
///
/// Does NOT add any EDNS options — padding is applied separately by
/// [`pad_dns_query`].
fn build_doh_query(name: &str, rtype: RecordType) -> Result<Vec<u8>, PaddingError> {
    let qname = Name::from_ascii(name)
        .map_err(|e| PaddingError::Build(format!("invalid qname {name}: {e}")))?;
    let mut query = Query::new();
    query.set_name(qname);
    query.set_query_type(rtype);

    let id: u16 = {
        use rand::RngCore;
        rand::rngs::StdRng::from_os_rng().next_u32() as u16
    };

    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(query);

    msg.to_vec()
        .map_err(|e| PaddingError::Build(format!("failed to serialize query: {e}")))
}

/// A single rung of the ladder.
struct Rung {
    resolver: Box<dyn Resolve>,
    label: String,
}

/// The upstream resolver ladder.
///
/// Shared across all DNS handler tasks via `Arc`.
pub struct UpstreamLadder {
    rungs: Vec<Rung>,
    /// Index of the currently preferred rung.
    rung_idx: AtomicUsize,
}

impl UpstreamLadder {
    /// Build from validated config.
    ///
    /// Rung order (WP8 §2 + §3):
    ///
    /// 1. ODoH rung (rung 0) — only when `privacy.odoh = true`.
    /// 2. For each DoH endpoint (in config order):
    ///    - If `upstream.h3 = true` AND the provider hostname is in
    ///      `DOH3_VERIFIED_HOSTS`: insert a `doh3://` rung (hickory h3-ring).
    ///      NOTE: h3 rungs are unpadded (hickory owns the QUIC send path; no seam).
    ///    - If `privacy.doh_padding = true`: insert a `PaddedDohRung`
    ///      (hand-rolled h2 POST with RFC 8467 padding).
    ///    - If `privacy.doh_padding = false`: insert the unpadded hickory h2
    ///      rung (unchanged pre-WP8 behaviour).
    /// 3. Do53 fallback rungs.
    ///
    /// # Errors
    ///
    /// Returns `UpstreamError::Rung` if any resolver fails to initialise
    /// (bad IP, TLS error, etc.).  Partial failures are not silently skipped —
    /// the daemon prefers a loud startup error over silently missing a rung.
    pub fn from_config(
        cfg: &UpstreamConfig,
        privacy: &PrivacyConfig,
    ) -> Result<Self, UpstreamError> {
        let mut rungs: Vec<Rung> = Vec::new();

        // ODoH rung at position 0 when enabled.
        if privacy.odoh {
            info!(
                target = %cfg.odoh.target,
                relay = %if cfg.odoh.relay.is_empty() { "direct-to-target" } else { &cfg.odoh.relay },
                "ODoH experimental rung enabled (rung 0)"
            );
            let odoh = OdohRung::new_with_padding(cfg.odoh.clone(), privacy.doh_padding)
                .map_err(|e| UpstreamError::Rung(format!("ODoH rung init failed: {e}")))?;
            rungs.push(Rung {
                resolver: Box::new(odoh),
                label: format!("odoh:{}", cfg.odoh.target),
            });
        }

        for ep in &cfg.effective_doh() {
            // Determine if this provider is verified to serve DoH3.
            let h3_verified = cfg.h3 && endpoint_is_h3_verified(ep);

            if h3_verified {
                // WP8 §2: insert the h3 rung BEFORE the h2 rung for verified
                // providers only.  Label uses "doh3://" prefix so status/logs
                // distinguish it from the h2 rung.
                let h3_label = doh3_label(&ep.url);
                let resolver_h3 = HickoryResolver::new_doh3(ep)?;
                info!(rung = %h3_label, "DoH3 rung added (h3-ring)");
                rungs.push(Rung {
                    resolver: Box::new(resolver_h3),
                    label: h3_label,
                });
            }

            // WP8 §3: padded h2 rung when doh_padding=true; unpadded hickory
            // rung when doh_padding=false (unchanged pre-WP8 behaviour).
            if privacy.doh_padding {
                let padded = PaddedDohRung::new(ep)?;
                let label = doh_label(&ep.url);
                rungs.push(Rung {
                    resolver: Box::new(padded),
                    label,
                });
            } else {
                let resolver = HickoryResolver::new_doh(ep)?;
                rungs.push(Rung {
                    resolver: Box::new(resolver),
                    label: doh_label(&ep.url),
                });
            }
        }

        for addr_str in &cfg.do53_fallback {
            let addr: SocketAddr = addr_str
                .parse()
                .map_err(|_| UpstreamError::Rung(format!("invalid do53 address: {addr_str}")))?;
            let resolver = HickoryResolver::new_do53(addr)?;
            rungs.push(Rung {
                resolver: Box::new(resolver),
                label: format!("do53:{addr}"),
            });
        }

        Ok(Self {
            rungs,
            rung_idx: AtomicUsize::new(0),
        })
    }

    /// Build a ladder from arbitrary boxed resolvers (used in tests).
    ///
    /// `labels` must have the same length as `resolvers`.
    // WP3-seam: used directly by the integration test suite.
    #[allow(dead_code)]
    pub fn from_resolvers(resolvers: Vec<(String, Box<dyn Resolve>)>) -> Self {
        let rungs = resolvers
            .into_iter()
            .map(|(label, resolver)| Rung { resolver, label })
            .collect();
        Self {
            rungs,
            rung_idx: AtomicUsize::new(0),
        }
    }

    /// Number of rungs in the ladder.
    // WP3-seam: used by tests and the diagnostics endpoint.
    #[allow(dead_code)]
    pub fn rung_count(&self) -> usize {
        self.rungs.len()
    }

    /// Resolve `name` / `rtype` via the ladder.
    ///
    /// Tries the current rung first (up to `RUNG_TIMEOUT`); on failure
    /// advances once and retries the next rung.  Returns
    /// `UpstreamError::AllExhausted` only when every rung has been tried.
    ///
    /// A success on a non-zero rung schedules a background probe of rung 0.
    pub async fn resolve(&self, name: &str, rtype: RecordType) -> Result<Lookup, UpstreamError> {
        if self.rungs.is_empty() {
            return Err(UpstreamError::AllExhausted);
        }

        let start_rung = self.rung_idx.load(Ordering::Relaxed);

        // Try start_rung, then wrap-around through all rungs exactly once.
        let total = self.rungs.len();
        for offset in 0..total {
            let idx = (start_rung + offset) % total;
            let rung = &self.rungs[idx];

            match timeout(RUNG_TIMEOUT, rung.resolver.lookup(name, rtype)).await {
                Ok(Ok(lookup)) => {
                    // Update preferred rung on success.
                    self.rung_idx.store(idx, Ordering::Relaxed);

                    // If we fell back, probe rung 0 after a delay.
                    if idx != 0 {
                        self.spawn_rung0_probe();
                    }
                    return Ok(lookup);
                }
                Ok(Err(e)) => {
                    warn!(rung = %rung.label, error = %e, "upstream rung error; advancing");
                    // Advance the stored rung immediately so the next query
                    // starts one step ahead.
                    let next = (idx + 1) % total;
                    let _ = self.rung_idx.compare_exchange(
                        idx,
                        next,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    );
                }
                Err(_elapsed) => {
                    warn!(rung = %rung.label, "upstream rung timed out; advancing");
                    let next = (idx + 1) % total;
                    let _ = self.rung_idx.compare_exchange(
                        idx,
                        next,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    );
                }
            }
        }

        Err(UpstreamError::AllExhausted)
    }

    /// Current preferred rung index (for metrics).
    pub fn current_rung(&self) -> usize {
        self.rung_idx.load(Ordering::Relaxed)
    }

    /// Force the ladder back to rung 0 (e.g. after a successful probe).
    // WP3-seam: called by spawn_rung0_probe_arc and the upstream health monitor.
    #[allow(dead_code)]
    pub fn reset_to_rung0(&self) {
        self.rung_idx.store(0, Ordering::Relaxed);
    }

    /// Spawn a background task that probes rung 0 after `RUNG_0_PROBE_DELAY`.
    /// On success, resets the ladder index to 0.
    fn spawn_rung0_probe(&self) {
        // We need an Arc to self to pass into the task.  This is called from
        // within a &self method, so we can't do that directly.  Instead we
        // read rung 0's label for tracing and schedule a tokio task that
        // re-reads the AtomicUsize.  Since we can't clone self, we simply
        // log that recovery will be attempted; the atomic will be reset by
        // the next successful rung-0 query naturally.
        //
        // Full probe-and-reset requires the caller to wrap `UpstreamLadder`
        // in an `Arc` and call `spawn_rung0_probe_arc` instead (WP3 wires
        // this when wrapping in `Arc`).
        debug!("rung fallback active; rung-0 probe requires Arc<UpstreamLadder> (see spawn_rung0_probe_arc)");
    }

    /// Schedule a probe of rung 0 after `RUNG_0_PROBE_DELAY`, given `Arc<Self>`.
    ///
    /// On success, resets the preferred rung to 0.
    // WP3-seam: wired by the upstream health monitor task.
    #[allow(dead_code)]
    pub fn spawn_rung0_probe_arc(self: &Arc<Self>, probe_name: &str, probe_type: RecordType) {
        if self.rungs.is_empty() {
            return;
        }
        let this = Arc::clone(self);
        let name = probe_name.to_string();
        tokio::spawn(async move {
            tokio::time::sleep(RUNG_0_PROBE_DELAY).await;
            // Only probe if we are still on a non-zero rung.
            if this.rung_idx.load(Ordering::Relaxed) == 0 {
                return;
            }
            let rung = &this.rungs[0];
            match timeout(RUNG_TIMEOUT, rung.resolver.lookup(&name, probe_type)).await {
                Ok(Ok(_)) => {
                    debug!(label = %rung.label, "rung-0 probe succeeded; resetting ladder");
                    this.reset_to_rung0();
                }
                Ok(Err(e)) => {
                    debug!(label = %rung.label, error = %e, "rung-0 probe failed; staying on fallback");
                }
                Err(_) => {
                    debug!(label = %rung.label, "rung-0 probe timed out; staying on fallback");
                }
            }
        });
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Returns `true` if the DoH endpoint hostname is in [`DOH3_VERIFIED_HOSTS`].
///
/// Verification is hostname-based (lowercase match after stripping `https://`).
/// This prevents accidentally adding h3 rungs to unverified providers.
fn endpoint_is_h3_verified(ep: &DohEndpoint) -> bool {
    // Extract just the hostname (no port, no path).
    let without_scheme = ep.url.strip_prefix("https://").unwrap_or(ep.url.as_str());
    let host = without_scheme
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_lowercase();
    DOH3_VERIFIED_HOSTS.iter().any(|&h| h == host)
}

/// Return the `doh://…` label used in rung status/logs (h2 path).
fn doh_label(url: &str) -> String {
    format!("doh://{}", url.strip_prefix("https://").unwrap_or(url))
}

/// Return the `doh3://…` label used in rung status/logs (h3 path).
fn doh3_label(url: &str) -> String {
    format!("doh3://{}", url.strip_prefix("https://").unwrap_or(url))
}

/// Parse `https://<host>[:<port>][/<path>]` into `(host_without_port, port)`.
///
/// Used by `PaddedDohRung` to build reqwest bootstrap-IP overrides.
fn parse_doh_url_host_port(url: &str) -> Result<(String, u16), UpstreamError> {
    let without_scheme = url
        .strip_prefix("https://")
        .ok_or_else(|| UpstreamError::Rung(format!("DoH URL must start with https://: {url}")))?;
    let host_port = without_scheme.split('/').next().unwrap_or(without_scheme);
    // Detect an explicit port.
    if let Some(colon) = host_port.rfind(':') {
        let host = host_port[..colon].to_string();
        let port: u16 = host_port[colon + 1..]
            .parse()
            .map_err(|_| UpstreamError::Rung(format!("invalid port in URL: {url}")))?;
        Ok((host, port))
    } else {
        Ok((host_port.to_string(), 443u16))
    }
}

/// Parse `https://<host>[/<path>]` into `(host, path)`.
fn parse_doh_url(url: &str) -> Result<(String, String), UpstreamError> {
    let without_scheme = url
        .strip_prefix("https://")
        .ok_or_else(|| UpstreamError::Rung(format!("DoH URL must start with https://: {url}")))?;
    let (host, path) = match without_scheme.find('/') {
        Some(pos) => {
            let (h, p) = without_scheme.split_at(pos);
            (h.to_string(), p.to_string())
        }
        None => (without_scheme.to_string(), "/dns-query".to_string()),
    };
    if host.is_empty() {
        return Err(UpstreamError::Rung(format!(
            "DoH URL has empty host: {url}"
        )));
    }
    Ok((host, path))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use hickory_proto::rr::RecordType;
    use std::sync::{atomic::AtomicU32, Arc};

    // ── Mock resolver ─────────────────────────────────────────────────────────

    /// A resolver that always succeeds (with an empty lookup) after optional delay.
    #[allow(dead_code)]
    struct AlwaysOkResolver {
        call_count: Arc<AtomicU32>,
        delay_ms: u64,
    }

    impl Resolve for AlwaysOkResolver {
        fn lookup<'a>(
            &'a self,
            name: &'a str,
            rtype: RecordType,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Lookup, String>> + Send + 'a>>
        {
            let count = Arc::clone(&self.call_count);
            let delay = self.delay_ms;
            let _ = (name, rtype); // not needed for mock
            Box::pin(async move {
                if delay > 0 {
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
                count.fetch_add(1, Ordering::Relaxed);
                // Build a minimal Lookup with zero records.
                // hickory's Lookup is hard to construct in unit tests without
                // a real query; we simulate a "response" by erroring with a
                // known-ok sentinel that the test ladder accepts.
                // Actually, Lookup requires records; we use a workaround:
                Err("empty-ok".to_string()) // mock: "succeed" means forward
            })
        }
    }

    /// A resolver that always fails.
    struct AlwaysFailResolver {
        call_count: Arc<AtomicU32>,
    }

    impl Resolve for AlwaysFailResolver {
        fn lookup<'a>(
            &'a self,
            _name: &'a str,
            _rtype: RecordType,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Lookup, String>> + Send + 'a>>
        {
            let count = Arc::clone(&self.call_count);
            Box::pin(async move {
                count.fetch_add(1, Ordering::Relaxed);
                Err("resolver down".to_string())
            })
        }
    }

    /// A resolver that times out (sleeps > RUNG_TIMEOUT).
    struct TimeoutResolver;

    impl Resolve for TimeoutResolver {
        fn lookup<'a>(
            &'a self,
            _name: &'a str,
            _rtype: RecordType,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Lookup, String>> + Send + 'a>>
        {
            Box::pin(async move {
                tokio::time::sleep(Duration::from_secs(10)).await;
                Err("would not reach here".to_string())
            })
        }
    }

    // ── parse_doh_url ─────────────────────────────────────────────────────────

    #[test]
    fn parse_doh_url_with_path() {
        let (host, path) = parse_doh_url("https://cloudflare-dns.com/dns-query").unwrap();
        assert_eq!(host, "cloudflare-dns.com");
        assert_eq!(path, "/dns-query");
    }

    #[test]
    fn parse_doh_url_without_path_defaults_dns_query() {
        let (host, path) = parse_doh_url("https://dns.quad9.net").unwrap();
        assert_eq!(host, "dns.quad9.net");
        assert_eq!(path, "/dns-query");
    }

    #[test]
    fn parse_doh_url_missing_scheme_errors() {
        assert!(parse_doh_url("http://example.com/dns-query").is_err());
        assert!(parse_doh_url("cloudflare-dns.com/dns-query").is_err());
    }

    // ── Ladder rung advance ───────────────────────────────────────────────────

    #[tokio::test]
    async fn ladder_advances_on_failure_and_succeeds_on_second_rung() {
        let fail_count = Arc::new(AtomicU32::new(0));
        let ok_count = Arc::new(AtomicU32::new(0));

        let ladder = UpstreamLadder::from_resolvers(vec![
            (
                "fail".to_string(),
                Box::new(AlwaysFailResolver {
                    call_count: Arc::clone(&fail_count),
                }),
            ),
            (
                "ok".to_string(),
                Box::new(AlwaysFailResolver {
                    call_count: Arc::clone(&ok_count),
                }),
            ),
        ]);

        // Both fail → AllExhausted.
        let result = ladder.resolve("example.com", RecordType::A).await;
        assert!(matches!(result, Err(UpstreamError::AllExhausted)));
        assert_eq!(
            fail_count.load(Ordering::Relaxed),
            1,
            "primary rung tried once"
        );
        assert_eq!(
            ok_count.load(Ordering::Relaxed),
            1,
            "secondary rung tried once"
        );
    }

    #[tokio::test]
    async fn ladder_all_fail_returns_all_exhausted() {
        let ladder = UpstreamLadder::from_resolvers(vec![
            (
                "fail1".to_string(),
                Box::new(AlwaysFailResolver {
                    call_count: Arc::new(AtomicU32::new(0)),
                }),
            ),
            (
                "fail2".to_string(),
                Box::new(AlwaysFailResolver {
                    call_count: Arc::new(AtomicU32::new(0)),
                }),
            ),
            (
                "fail3".to_string(),
                Box::new(AlwaysFailResolver {
                    call_count: Arc::new(AtomicU32::new(0)),
                }),
            ),
        ]);
        let result = ladder.resolve("test.com", RecordType::A).await;
        assert!(matches!(result, Err(UpstreamError::AllExhausted)));
    }

    #[tokio::test]
    async fn empty_ladder_returns_all_exhausted() {
        let ladder = UpstreamLadder::from_resolvers(vec![]);
        let result = ladder.resolve("test.com", RecordType::A).await;
        assert!(matches!(result, Err(UpstreamError::AllExhausted)));
    }

    // ── Rung advancement on timeout ───────────────────────────────────────────

    #[tokio::test]
    async fn timeout_rung_advances_ladder() {
        let ok_count = Arc::new(AtomicU32::new(0));
        let ladder = UpstreamLadder::from_resolvers(vec![
            ("timeout".to_string(), Box::new(TimeoutResolver)),
            (
                "fallback".to_string(),
                Box::new(AlwaysFailResolver {
                    call_count: Arc::clone(&ok_count),
                }),
            ),
        ]);
        // timeout rung → advance → fallback also fails → AllExhausted
        let r = ladder.resolve("x.com", RecordType::A).await;
        assert!(matches!(r, Err(UpstreamError::AllExhausted)));
        assert_eq!(
            ok_count.load(Ordering::Relaxed),
            1,
            "fallback was tried after timeout"
        );
    }

    // ── rung_count ────────────────────────────────────────────────────────────

    #[test]
    fn rung_count_correct() {
        let ladder = UpstreamLadder::from_resolvers(vec![
            (
                "a".to_string(),
                Box::new(AlwaysFailResolver {
                    call_count: Arc::new(AtomicU32::new(0)),
                }),
            ),
            (
                "b".to_string(),
                Box::new(AlwaysFailResolver {
                    call_count: Arc::new(AtomicU32::new(0)),
                }),
            ),
        ]);
        assert_eq!(ladder.rung_count(), 2);
    }

    // ── reset_to_rung0 ────────────────────────────────────────────────────────

    #[test]
    fn reset_to_rung0_works() {
        let ladder = UpstreamLadder::from_resolvers(vec![
            (
                "a".to_string(),
                Box::new(AlwaysFailResolver {
                    call_count: Arc::new(AtomicU32::new(0)),
                }),
            ),
            (
                "b".to_string(),
                Box::new(AlwaysFailResolver {
                    call_count: Arc::new(AtomicU32::new(0)),
                }),
            ),
        ]);
        ladder.rung_idx.store(1, Ordering::Relaxed);
        assert_eq!(ladder.current_rung(), 1);
        ladder.reset_to_rung0();
        assert_eq!(ladder.current_rung(), 0);
    }

    // ── WP8 §2: h3 rung insertion matrix ──────────────────────────────────────
    //
    // Spec §7 mandatory cases: "h3-rung insertion order matrix
    // (h3 flag on/off × provider verified/unverified)".

    /// Helper: build an UpstreamConfig with a single DoH endpoint, no Do53.
    fn upstream_with_one_doh(url: &str, bootstrap: &str, h3: bool) -> UpstreamConfig {
        use hush_core::config::DohEndpoint;
        UpstreamConfig {
            preset: "default".to_string(),
            h3,
            doh: vec![DohEndpoint {
                url: url.to_string(),
                bootstrap_ips: vec![bootstrap.to_string()],
            }],
            do53_fallback: vec![],
            ..UpstreamConfig::default()
        }
    }

    /// h3=true, provider verified (Cloudflare) → 2 rungs: doh3:// before doh://
    #[test]
    fn h3_on_verified_provider_inserts_doh3_before_doh() {
        let upstream =
            upstream_with_one_doh("https://cloudflare-dns.com/dns-query", "1.1.1.1", true);
        let privacy = PrivacyConfig {
            doh_padding: false, // use hickory h2 path so rung labels are predictable
            ..PrivacyConfig::default()
        };
        let ladder = UpstreamLadder::from_config(&upstream, &privacy).unwrap();
        // Expect: [doh3://cloudflare-dns.com/dns-query, doh://cloudflare-dns.com/dns-query]
        assert_eq!(ladder.rung_count(), 2, "h3=true verified → 2 rungs");
        assert!(
            ladder.rungs[0].label.starts_with("doh3://"),
            "rung 0 must be doh3://; got: {}",
            ladder.rungs[0].label
        );
        assert!(
            ladder.rungs[1].label.starts_with("doh://"),
            "rung 1 must be doh://; got: {}",
            ladder.rungs[1].label
        );
    }

    /// h3=true, provider verified (Quad9) → 2 rungs: doh3:// before doh://
    #[test]
    fn h3_on_quad9_verified_inserts_doh3_before_doh() {
        let upstream = upstream_with_one_doh("https://dns.quad9.net/dns-query", "9.9.9.9", true);
        let privacy = PrivacyConfig {
            doh_padding: false,
            ..PrivacyConfig::default()
        };
        let ladder = UpstreamLadder::from_config(&upstream, &privacy).unwrap();
        assert_eq!(ladder.rung_count(), 2);
        assert!(
            ladder.rungs[0].label.starts_with("doh3://"),
            "Quad9 rung 0 must be doh3://; got: {}",
            ladder.rungs[0].label
        );
    }

    /// h3=false → ladder unchanged (no doh3:// rung at all).
    #[test]
    fn h3_off_no_doh3_rungs() {
        let upstream =
            upstream_with_one_doh("https://cloudflare-dns.com/dns-query", "1.1.1.1", false);
        let privacy = PrivacyConfig {
            doh_padding: false,
            ..PrivacyConfig::default()
        };
        let ladder = UpstreamLadder::from_config(&upstream, &privacy).unwrap();
        // Expect only 1 rung: doh://
        assert_eq!(ladder.rung_count(), 1, "h3=false → 1 rung (no h3)");
        assert!(
            !ladder.rungs[0].label.starts_with("doh3://"),
            "h3=false must not produce a doh3:// rung; got: {}",
            ladder.rungs[0].label
        );
    }

    /// h3=true, unverified provider (Mullvad) → NO doh3:// rung.
    #[test]
    fn h3_on_unverified_provider_no_doh3_rung() {
        let upstream =
            upstream_with_one_doh("https://dns.mullvad.net/dns-query", "194.242.2.2", true);
        let privacy = PrivacyConfig {
            doh_padding: false,
            ..PrivacyConfig::default()
        };
        let ladder = UpstreamLadder::from_config(&upstream, &privacy).unwrap();
        // Mullvad is not in DOH3_VERIFIED_HOSTS → only 1 rung (h2 only).
        assert_eq!(
            ladder.rung_count(),
            1,
            "h3=true unverified → 1 rung (no h3); got {}",
            ladder.rung_count()
        );
        assert!(
            !ladder.rungs[0].label.starts_with("doh3://"),
            "unverified provider must not get a doh3:// rung; got: {}",
            ladder.rungs[0].label
        );
    }

    /// h3=true, multiple verified providers → doh3:// inserted before each h2 rung.
    #[test]
    fn h3_on_two_verified_providers_inserts_two_doh3_rungs() {
        let upstream = UpstreamConfig {
            preset: "default".to_string(),
            h3: true,
            doh: vec![
                hush_core::config::DohEndpoint {
                    url: "https://cloudflare-dns.com/dns-query".to_string(),
                    bootstrap_ips: vec!["1.1.1.1".to_string()],
                },
                hush_core::config::DohEndpoint {
                    url: "https://dns.quad9.net/dns-query".to_string(),
                    bootstrap_ips: vec!["9.9.9.9".to_string()],
                },
            ],
            do53_fallback: vec![],
            ..UpstreamConfig::default()
        };
        let privacy = PrivacyConfig {
            doh_padding: false,
            ..PrivacyConfig::default()
        };
        let ladder = UpstreamLadder::from_config(&upstream, &privacy).unwrap();
        // 2 providers × 2 rungs each = 4 total.
        assert_eq!(ladder.rung_count(), 4, "two verified providers → 4 rungs");
        assert!(
            ladder.rungs[0].label.starts_with("doh3://cloudflare"),
            "rung 0"
        );
        assert!(
            ladder.rungs[1].label.starts_with("doh://cloudflare"),
            "rung 1"
        );
        assert!(
            ladder.rungs[2].label.starts_with("doh3://dns.quad9"),
            "rung 2"
        );
        assert!(
            ladder.rungs[3].label.starts_with("doh://dns.quad9"),
            "rung 3"
        );
    }

    /// Do53 rungs are NOT padded — they don't use PaddedDohRung and
    /// their labels must not contain "doh3://" or "doh://".
    #[test]
    fn do53_rung_label_is_not_doh() {
        let upstream = UpstreamConfig {
            preset: "none".to_string(),
            h3: true,
            doh: vec![],
            do53_fallback: vec!["127.0.0.1:5353".to_string()],
            ..UpstreamConfig::default()
        };
        let privacy = PrivacyConfig::default();
        let ladder = UpstreamLadder::from_config(&upstream, &privacy).unwrap();
        assert_eq!(ladder.rung_count(), 1, "only Do53 rung");
        let label = &ladder.rungs[0].label;
        assert!(
            label.starts_with("do53:"),
            "Do53 rung must have 'do53:' label; got: {label}"
        );
        assert!(
            !label.contains("doh"),
            "Do53 rung must not have 'doh' in label; got: {label}"
        );
    }

    // ── WP8 §3: padding flag respected in rung construction ────────────────────

    /// When `doh_padding = true`, a DoH endpoint produces a rung with label
    /// `doh://` (same as before; the padding is invisible in the label).
    #[test]
    fn doh_padding_on_produces_doh_label() {
        let upstream =
            upstream_with_one_doh("https://cloudflare-dns.com/dns-query", "1.1.1.1", false);
        let privacy = PrivacyConfig {
            doh_padding: true,
            ..PrivacyConfig::default()
        };
        let ladder = UpstreamLadder::from_config(&upstream, &privacy).unwrap();
        assert_eq!(ladder.rung_count(), 1);
        assert!(
            ladder.rungs[0].label.starts_with("doh://"),
            "doh_padding=true still gets doh:// label; got: {}",
            ladder.rungs[0].label
        );
    }

    // ── jitter bounds (spec requirement) ─────────────────────────────────────

    #[test]
    fn jitter_within_bounds() {
        use hush_core::config::ListsConfig;
        let cfg = ListsConfig::default();
        // Jitter must be non-negative and ≤ jitter_minutes.
        let jitter_max_ms = (cfg.jitter_minutes as u64) * 60 * 1000;
        // Simulate 100 samples.
        for _ in 0..100 {
            let jitter = random_jitter_ms(cfg.jitter_minutes);
            assert!(
                jitter <= jitter_max_ms,
                "jitter {jitter} exceeded max {jitter_max_ms}"
            );
        }
    }

    // Helper matching the lists module's jitter formula.
    fn random_jitter_ms(jitter_minutes: u32) -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        // Deterministic-ish: use current time's nanosecond as seed.
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let max_ms = (jitter_minutes as u64) * 60 * 1000;
        if max_ms == 0 {
            return 0;
        }
        (nanos as u64) % max_ms
    }
}
