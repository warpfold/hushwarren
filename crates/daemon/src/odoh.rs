//! ODoH (Oblivious DNS over HTTPS) experimental upstream rung.
//!
//! Implements `specs/wp7-odoh-ecs.md` §2 and `specs/wp8-transport-privacy.md` §3.
//! This module provides the transport layer around the `odoh-rs` crypto
//! primitives; `odoh-rs` itself handles only the RFC 9230
//! encapsulation/decapsulation.
//!
//! ## WP8 §3 — EDNS padding
//!
//! ODoH is an encrypted rung, so padding is **mandatory** here when
//! `privacy.doh_padding = true`.  We own the query wire bytes before
//! encryption, so padding is applied at step 1 of `do_odoh_query`, before
//! `ObliviousDoHMessagePlaintext::new()`.  The padded plaintext is then
//! encrypted and relayed normally.
//!
//! ## Architecture
//!
//! ```text
//! caller ──► OdohRung::lookup(name, rtype)
//!              │
//!              ├─ 1. get_config()      GET <target>/.well-known/odohconfigs
//!              │     (cached 1 h; re-fetched on decrypt failure)
//!              │
//!              ├─ 2. encrypt_query()   fresh StdRng seed per query
//!              │
//!              ├─ 3. POST application/oblivious-dns-message
//!              │     • relay ≠ ""  →  POST relay?targethost=…&targetpath=…
//!              │     • relay == "" →  POST directly to target
//!              │
//!              └─ 4. decrypt_response()  → raw DNS bytes → Lookup
//! ```
//!
//! ## Direct-to-target honesty
//!
//! *Direct-to-target ODoH still hides client IP↔query linkage from
//! cache/transport observers, but the target sees your IP exactly like
//! regular DoH.  Unlinkability requires a relay operated by a different
//! party.  The public relay ecosystem is small and Cloudflare-centric —
//! relay mode is configured but we ship no default relay.*
//! Status: experimental.
//!
//! ## Loop-hazard rule
//!
//! `bootstrap_ips` are loaded into reqwest's per-URL `resolve()` override so
//! the target/relay hostnames are never resolved through the daemon itself.

use crate::padding::pad_dns_query;
use bytes::Bytes;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use hickory_resolver::lookup::Lookup;
use hush_core::config::OdohUpstreamConfig;
use odoh_rs::{
    compose, decrypt_response, encrypt_query, parse, ObliviousDoHConfigs,
    ObliviousDoHMessagePlaintext, OdohSecret,
};
use rand::SeedableRng;
use reqwest::{
    header::{ACCEPT, CONTENT_TYPE},
    Client,
};
use std::{
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use tracing::{debug, warn};

/// Per-query timeout for the ODoH rung.
pub(crate) const ODOH_TIMEOUT: Duration = Duration::from_secs(4);

/// How long a fetched ODoH config is trusted before re-fetching.
const CONFIG_CACHE_TTL: Duration = Duration::from_secs(3600); // 1 hour

/// Content-type for ODoH messages (RFC 9230 §4.1).
const ODOH_CONTENT_TYPE: &str = "application/oblivious-dns-message";

// ── Config cache ──────────────────────────────────────────────────────────────

/// Cached ODoH target config (public key material).
struct CachedConfig {
    /// The parsed config contents (HPKE public key).
    contents: odoh_rs::ObliviousDoHConfigContents,
    /// When the config was fetched (for TTL expiry).
    fetched_at: Instant,
}

impl CachedConfig {
    fn is_fresh(&self) -> bool {
        self.fetched_at.elapsed() < CONFIG_CACHE_TTL
    }
}

// ── OdohRung ──────────────────────────────────────────────────────────────────

/// The ODoH upstream rung.
///
/// Implements [`crate::upstream::Resolve`] so it slots into
/// [`crate::upstream::UpstreamLadder`] as rung 0 when `privacy.odoh = true`.
pub struct OdohRung {
    cfg: OdohUpstreamConfig,
    client: Client,
    /// Target config cache; locked only during fetch (never across I/O).
    config_cache: Arc<Mutex<Option<CachedConfig>>>,
    /// Apply RFC 8467 EDNS(0) padding to the inner DNS query before ODoH
    /// encryption (`privacy.doh_padding`).  Default: `true`.
    pad: bool,
}

impl OdohRung {
    /// Construct an ODoH rung from the given config with optional padding.
    ///
    /// When `pad = true` (the default when `privacy.doh_padding = true`),
    /// the inner DNS query wire bytes are padded to a multiple of 128 octets
    /// before ODoH encryption, per RFC 8467.
    ///
    /// Builds a reqwest `Client` with bootstrap-IP `resolve()` overrides for
    /// the target (and relay if set) hostnames, honouring the loop-hazard rule.
    ///
    /// # Errors
    ///
    /// Returns [`OdohError::Config`] if the URL is malformed or the HTTP
    /// client cannot be built.
    pub fn new_with_padding(cfg: OdohUpstreamConfig, pad: bool) -> Result<Self, OdohError> {
        let client = build_client(&cfg)?;
        Ok(Self {
            cfg,
            client,
            config_cache: Arc::new(Mutex::new(None)),
            pad,
        })
    }

    /// Construct an ODoH rung without padding (legacy API for tests).
    ///
    /// Equivalent to `new_with_padding(cfg, false)`.
    pub fn new(cfg: OdohUpstreamConfig) -> Result<Self, OdohError> {
        Self::new_with_padding(cfg, false)
    }

    /// Perform a DNS lookup via ODoH, returning a hickory [`Lookup`].
    ///
    /// Automatically re-fetches the ODoH config on decrypt failure (stale key).
    pub async fn odoh_lookup(&self, name: &str, rtype: RecordType) -> Result<Lookup, OdohError> {
        let (contents, was_cached) = self.get_config().await?;

        let result = self.do_odoh_query(name, rtype, &contents).await;

        match result {
            Ok(lookup) => Ok(lookup),
            Err(OdohError::Decrypt(_)) if was_cached => {
                // Cached key may have rotated — evict and retry once.
                debug!("ODoH decrypt failed on cached config; evicting and retrying");
                {
                    let mut guard = self.config_cache.lock().await;
                    *guard = None;
                }
                let (fresh_contents, _) = self.get_config().await?;
                self.do_odoh_query(name, rtype, &fresh_contents).await
            }
            Err(e) => Err(e),
        }
    }

    /// Fetch (and cache) the target's ODoH config.
    ///
    /// Returns `(contents, was_already_cached)`.  The bool is `true` when the
    /// existing cache entry was valid, `false` when a fresh fetch was made.
    async fn get_config(&self) -> Result<(odoh_rs::ObliviousDoHConfigContents, bool), OdohError> {
        {
            let guard = self.config_cache.lock().await;
            if let Some(ref cached) = *guard {
                if cached.is_fresh() {
                    debug!("ODoH: using cached config");
                    return Ok((cached.contents.clone(), true));
                }
            }
        }

        // Fetch fresh config from <target-origin>/.well-known/odohconfigs.
        let configs_url = odohconfigs_url(&self.cfg.target)?;
        debug!(url = %configs_url, "ODoH: fetching odohconfigs");

        let resp = self
            .client
            .get(&configs_url)
            .timeout(ODOH_TIMEOUT)
            .send()
            .await
            .map_err(|e| OdohError::ConfigFetch(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(OdohError::ConfigFetch(format!(
                "odohconfigs endpoint returned HTTP {}",
                resp.status()
            )));
        }

        let body: Bytes = resp
            .bytes()
            .await
            .map_err(|e| OdohError::ConfigFetch(e.to_string()))?;

        let mut buf = body;
        let configs: ObliviousDoHConfigs =
            parse(&mut buf).map_err(|e| OdohError::ConfigParse(e.to_string()))?;

        let contents: odoh_rs::ObliviousDoHConfigContents = configs
            .supported()
            .into_iter()
            .next()
            .ok_or_else(|| OdohError::ConfigParse("no supported ODoH config in response".into()))?
            .into();

        let cloned = contents.clone();
        {
            let mut guard = self.config_cache.lock().await;
            *guard = Some(CachedConfig {
                contents,
                fetched_at: Instant::now(),
            });
        }

        Ok((cloned, false))
    }

    /// Execute one ODoH query+response cycle.
    async fn do_odoh_query(
        &self,
        name: &str,
        rtype: RecordType,
        contents: &odoh_rs::ObliviousDoHConfigContents,
    ) -> Result<Lookup, OdohError> {
        // 1. Build the DNS query wire bytes.
        let raw_wire = build_dns_query(name, rtype)?;

        // WP8 §3: apply RFC 8467 EDNS(0) padding before encryption when enabled.
        // The padding is part of the plaintext, so the encrypted ciphertext
        // reveals only the padded length, not the true query length.
        let query_wire: Vec<u8> = if self.pad {
            pad_dns_query(&raw_wire)
                .map_err(|e| OdohError::Encrypt(format!("EDNS padding error: {e}")))?
        } else {
            raw_wire
        };

        debug!(
            pad = self.pad,
            wire_len = query_wire.len(),
            "ODoH query wire (post-padding)"
        );

        // 2. Encrypt with a fresh RNG seed per query (no state reuse).
        let plaintext = ObliviousDoHMessagePlaintext::new(&query_wire, 0);
        let mut rng = rand::rngs::StdRng::from_os_rng();
        let (query_msg, client_secret): (_, OdohSecret) =
            encrypt_query(&plaintext, contents, &mut rng)
                .map_err(|e| OdohError::Encrypt(e.to_string()))?;

        let query_bytes = compose(&query_msg)
            .map_err(|e| OdohError::Encrypt(e.to_string()))?
            .freeze();

        // 3. POST to relay (if configured) or directly to the target.
        let post_url = self.post_url()?;
        debug!(url = %post_url, "ODoH: posting query");

        let resp = self
            .client
            .post(&post_url)
            .header(CONTENT_TYPE, ODOH_CONTENT_TYPE)
            .header(ACCEPT, ODOH_CONTENT_TYPE)
            .body(query_bytes)
            .timeout(ODOH_TIMEOUT)
            .send()
            .await
            .map_err(|e| OdohError::Transport(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(OdohError::Transport(format!(
                "ODoH server returned HTTP {}",
                resp.status()
            )));
        }

        let resp_ct = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !resp_ct.contains(ODOH_CONTENT_TYPE) {
            warn!(
                content_type = %resp_ct,
                "ODoH response has unexpected content-type; expected application/oblivious-dns-message"
            );
        }

        let resp_body: Bytes = resp
            .bytes()
            .await
            .map_err(|e| OdohError::Transport(e.to_string()))?;

        // 4. Decapsulate the response.
        let mut resp_buf = resp_body;
        let resp_msg: odoh_rs::ObliviousDoHMessage =
            parse(&mut resp_buf).map_err(|e| OdohError::Decrypt(e.to_string()))?;

        let decrypted = decrypt_response(&plaintext, &resp_msg, client_secret)
            .map_err(|e| OdohError::Decrypt(e.to_string()))?;

        let dns_bytes = decrypted.into_msg();

        // 5. Parse the inner DNS message and extract answer records.
        let msg = Message::from_vec(&dns_bytes).map_err(|e| OdohError::DnsParse(e.to_string()))?;
        message_to_lookup(msg, name, rtype).map_err(|e| OdohError::DnsParse(e.to_string()))
    }

    /// Compute the POST URL.
    ///
    /// - Relay set: `POST relay?targethost=<host>&targetpath=<path>` (RFC 9230 §7).
    /// - Relay empty: `POST` directly to the target URL.
    fn post_url(&self) -> Result<String, OdohError> {
        if self.cfg.relay.is_empty() {
            return Ok(self.cfg.target.clone());
        }
        let (target_host, target_path) = parse_https_url(&self.cfg.target)?;
        Ok(format!(
            "{}?targethost={}&targetpath={}",
            self.cfg.relay,
            percent_encode(&target_host),
            percent_encode(&target_path),
        ))
    }
}

// ── Resolve impl ──────────────────────────────────────────────────────────────

impl crate::upstream::Resolve for OdohRung {
    fn lookup<'a>(
        &'a self,
        name: &'a str,
        rtype: RecordType,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Lookup, String>> + Send + 'a>>
    {
        Box::pin(async move {
            self.odoh_lookup(name, rtype)
                .await
                .map_err(|e| e.to_string())
        })
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Build a minimal DNS query wire message for `name`/`rtype`.
fn build_dns_query(name: &str, rtype: RecordType) -> Result<Vec<u8>, OdohError> {
    let qname = Name::from_ascii(name).map_err(|e| OdohError::DnsParse(e.to_string()))?;
    let mut query = Query::new();
    query.set_name(qname);
    query.set_query_type(rtype);

    // Generate a random 16-bit query ID.
    let id: u16 = {
        use rand::RngCore;
        rand::rngs::StdRng::from_os_rng().next_u32() as u16
    };

    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    // Set recursion-desired by writing through the public `metadata` field.
    msg.metadata.recursion_desired = true;
    msg.add_query(query);

    msg.to_vec().map_err(|e| OdohError::DnsParse(e.to_string()))
}

/// Convert a hickory [`Message`] into a [`Lookup`].
///
/// Extracts answers from the message using the queried `name`/`rtype` as the
/// canonical query.
fn message_to_lookup(msg: Message, name: &str, rtype: RecordType) -> Result<Lookup, String> {
    let qname = Name::from_ascii(name).map_err(|e| e.to_string())?;
    let mut query = Query::new();
    query.set_name(qname);
    query.set_query_type(rtype);

    // Extract answer records from the DNS response message.
    // `answers` is a public Vec<Record> in hickory-proto 0.26.1.
    let answers = msg.answers.clone();
    // Use a 24 h TTL cap to honour the upstream ladder's TTL contract.
    let valid_until = std::time::Instant::now() + std::time::Duration::from_secs(86_400);
    Ok(Lookup::new_with_deadline(query, answers, valid_until))
}

/// Build a reqwest `Client` with bootstrap-IP `resolve()` overrides.
///
/// Overrides prevent the daemon from resolving target/relay hostnames through
/// itself (loop-hazard rule).
///
/// Production targets use `https://`.  An `http://` target is accepted only in
/// test builds so that in-process mock servers (plain HTTP axum) work without a
/// TLS layer; production targets always use `https://` (enforced by config
/// validation).
fn build_client(cfg: &OdohUpstreamConfig) -> Result<Client, OdohError> {
    let (target_host, default_port) = parse_url(&cfg.target)?;

    let ips: Vec<IpAddr> = cfg
        .bootstrap_ips
        .iter()
        .filter_map(|s| s.parse::<IpAddr>().ok())
        .collect();

    if ips.is_empty() {
        return Err(OdohError::Config(
            "bootstrap_ips contains no valid IP addresses".into(),
        ));
    }

    let target_addrs: Vec<std::net::SocketAddr> = ips
        .iter()
        .map(|ip| std::net::SocketAddr::new(*ip, default_port))
        .collect();

    let mut builder = Client::builder()
        .use_rustls_tls()
        .resolve_to_addrs(&target_host, &target_addrs);

    if !cfg.relay.is_empty() {
        let (relay_host, relay_port) = parse_url(&cfg.relay)?;
        let relay_addrs: Vec<std::net::SocketAddr> = ips
            .iter()
            .map(|ip| std::net::SocketAddr::new(*ip, relay_port))
            .collect();
        builder = builder.resolve_to_addrs(&relay_host, &relay_addrs);
    }

    builder
        .build()
        .map_err(|e| OdohError::Config(format!("failed to build HTTP client: {e}")))
}

/// Derive the `/.well-known/odohconfigs` URL from a target URL.
///
/// Preserves the scheme (http or https) so in-process test mocks (plain HTTP)
/// work alongside production HTTPS targets.
fn odohconfigs_url(target: &str) -> Result<String, OdohError> {
    let (scheme, rest) = split_scheme(target)?;
    let host_part = rest.split('/').next().unwrap_or(rest);
    Ok(format!("{scheme}://{}/.well-known/odohconfigs", host_part))
}

/// Parse a URL with either `https://` or `http://` scheme.
///
/// Returns `(host_with_optional_port, default_numeric_port)`.
/// The `default_numeric_port` is 443 for HTTPS and 80 for HTTP, unless
/// the host already includes an explicit port (e.g. `localhost:8080`).
fn parse_url(url: &str) -> Result<(String, u16), OdohError> {
    let (scheme, rest) = split_scheme(url)?;
    let default_port: u16 = if scheme == "https" { 443 } else { 80 };
    let host_part = rest.split('/').next().unwrap_or(rest);
    // Detect an explicit port in the host part (e.g. `localhost:8080`).
    let port: u16 = if let Some(colon) = host_part.rfind(':') {
        host_part[colon + 1..]
            .parse::<u16>()
            .unwrap_or(default_port)
    } else {
        default_port
    };
    Ok((host_part.to_string(), port))
}

/// Split a URL into its scheme and the rest (after `://`).
///
/// Accepts `https://` and `http://`.  Returns an error for anything else.
fn split_scheme(url: &str) -> Result<(&str, &str), OdohError> {
    if let Some(rest) = url.strip_prefix("https://") {
        Ok(("https", rest))
    } else if let Some(rest) = url.strip_prefix("http://") {
        Ok(("http", rest))
    } else {
        Err(OdohError::Config(format!(
            "URL must start with https:// or http://: {url}"
        )))
    }
}

/// Parse `https://<host>[/<path>]` → `(host, path)`.
///
/// Kept for `post_url` relay mode which uses the relay and target
/// host/path.  Accepts both `http://` and `https://`.
fn parse_https_url(url: &str) -> Result<(String, String), OdohError> {
    let (_scheme, without_scheme) = split_scheme(url)?;
    match without_scheme.find('/') {
        Some(pos) => {
            let (host, path) = without_scheme.split_at(pos);
            Ok((host.to_string(), path.to_string()))
        }
        None => Ok((without_scheme.to_string(), "/dns-query".to_string())),
    }
}

/// Minimal percent-encoding for query-parameter values (RFC 3986 §2.3).
///
/// Encodes everything except unreserved characters (A–Z, a–z, 0–9, `-`, `_`,
/// `.`, `~`) and `/` (needed for `targetpath`).
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char);
            }
            other => {
                use std::fmt::Write;
                // PANIC-OK: writing formatted hex digits to a String is infallible.
                let _ = write!(out, "%{:02X}", other);
            }
        }
    }
    out
}

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors from the ODoH rung.
#[derive(Debug, thiserror::Error)]
pub enum OdohError {
    /// Configuration error (bad URL, no bootstrap IPs, etc.).
    #[error("ODoH config error: {0}")]
    Config(String),
    /// Failed to fetch `/.well-known/odohconfigs`.
    #[error("ODoH config fetch failed: {0}")]
    ConfigFetch(String),
    /// Failed to parse the `odohconfigs` response.
    #[error("ODoH config parse failed: {0}")]
    ConfigParse(String),
    /// Failed to encrypt the query.
    #[error("ODoH encrypt failed: {0}")]
    Encrypt(String),
    /// Failed to decrypt the response (may indicate a stale key).
    #[error("ODoH decrypt failed: {0}")]
    Decrypt(String),
    /// HTTP transport error.
    #[error("ODoH transport error: {0}")]
    Transport(String),
    /// Failed to parse the inner DNS message.
    #[error("ODoH DNS parse failed: {0}")]
    DnsParse(String),
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn odohconfigs_url_extracts_origin() {
        assert_eq!(
            odohconfigs_url("https://odoh.cloudflare-dns.com/dns-query").unwrap(),
            "https://odoh.cloudflare-dns.com/.well-known/odohconfigs"
        );
        assert_eq!(
            odohconfigs_url("https://odoh.example.com").unwrap(),
            "https://odoh.example.com/.well-known/odohconfigs"
        );
    }

    #[test]
    fn odohconfigs_url_accepts_http_for_test_mocks() {
        // http:// is accepted so in-process test servers work without TLS.
        assert_eq!(
            odohconfigs_url("http://localhost:8080/dns-query").unwrap(),
            "http://localhost:8080/.well-known/odohconfigs"
        );
    }

    #[test]
    fn odohconfigs_url_rejects_other_schemes() {
        assert!(odohconfigs_url("ftp://odoh.example.com/dns-query").is_err());
        assert!(odohconfigs_url("ws://odoh.example.com/dns-query").is_err());
    }

    #[test]
    fn parse_https_url_with_path() {
        let (host, path) = parse_https_url("https://odoh.cloudflare-dns.com/dns-query").unwrap();
        assert_eq!(host, "odoh.cloudflare-dns.com");
        assert_eq!(path, "/dns-query");
    }

    #[test]
    fn parse_https_url_no_path_defaults_dns_query() {
        let (host, path) = parse_https_url("https://odoh.example.com").unwrap();
        assert_eq!(host, "odoh.example.com");
        assert_eq!(path, "/dns-query");
    }

    #[test]
    fn parse_https_url_accepts_http_scheme() {
        let (host, path) = parse_https_url("http://localhost:9000/dns-query").unwrap();
        assert_eq!(host, "localhost:9000");
        assert_eq!(path, "/dns-query");
    }

    #[test]
    fn parse_https_url_rejects_unknown_scheme() {
        assert!(parse_https_url("ftp://example.com/dns-query").is_err());
    }

    #[test]
    fn percent_encode_passthrough_unreserved() {
        assert_eq!(
            percent_encode("odoh.cloudflare-dns.com"),
            "odoh.cloudflare-dns.com"
        );
        assert_eq!(percent_encode("/dns-query"), "/dns-query");
    }

    #[test]
    fn percent_encode_colons_and_slashes() {
        let encoded = percent_encode("https://odoh.cloudflare-dns.com/dns-query");
        // colons must be encoded, slashes preserved
        assert!(!encoded.contains(':'), "colon must be percent-encoded");
        assert!(encoded.contains('/'), "slash must be preserved");
    }

    #[test]
    fn post_url_direct_to_target_when_relay_empty() {
        let cfg = OdohUpstreamConfig {
            target: "https://odoh.cloudflare-dns.com/dns-query".to_string(),
            relay: String::new(),
            bootstrap_ips: vec!["1.1.1.1".to_string()],
        };
        let rung = OdohRung {
            cfg,
            client: Client::new(),
            config_cache: Arc::new(Mutex::new(None)),
            pad: false,
        };
        assert_eq!(
            rung.post_url().unwrap(),
            "https://odoh.cloudflare-dns.com/dns-query"
        );
    }

    #[test]
    fn post_url_relay_mode_includes_target_params() {
        let cfg = OdohUpstreamConfig {
            target: "https://odoh.cloudflare-dns.com/dns-query".to_string(),
            relay: "https://relay.example.com/proxy".to_string(),
            bootstrap_ips: vec!["1.1.1.1".to_string()],
        };
        let rung = OdohRung {
            cfg,
            client: Client::new(),
            config_cache: Arc::new(Mutex::new(None)),
            pad: false,
        };
        let url = rung.post_url().unwrap();
        assert!(url.starts_with("https://relay.example.com/proxy?"));
        assert!(url.contains("targethost=odoh.cloudflare-dns.com"));
        assert!(url.contains("targetpath="));
    }

    #[test]
    fn build_dns_query_produces_valid_wire_message() {
        let bytes = build_dns_query("example.com", RecordType::A).unwrap();
        let msg = Message::from_vec(&bytes).unwrap();
        // `queries` is a public Vec field in hickory-proto 0.26.1.
        assert!(!msg.queries.is_empty(), "query section must be non-empty");
        let q = &msg.queries[0];
        assert_eq!(q.query_type(), RecordType::A);
        assert!(
            q.name().to_ascii().to_lowercase().contains("example"),
            "qname must contain 'example'"
        );
    }

    #[test]
    fn build_dns_query_no_opt_record() {
        // Invariant: our synthesised queries must NOT carry any EDNS OPT record.
        // An OPT record in position ARCOUNT would allow ECS to sneak in.
        let bytes = build_dns_query("example.com", RecordType::A).unwrap();
        let msg = Message::from_vec(&bytes).unwrap();
        // `additionals` is a public Vec field in hickory-proto 0.26.1.
        assert!(
            msg.additionals.is_empty(),
            "synthetic ODoH query must have no additional records (no OPT/ECS)"
        );
    }

    #[test]
    fn config_cache_freshness() {
        let contents = {
            let mut rng = rand::rngs::StdRng::from_seed([0u8; 32]);
            let kp = odoh_rs::ObliviousDoHKeyPair::new(&mut rng);
            kp.public().clone()
        };
        let cached = CachedConfig {
            contents,
            fetched_at: Instant::now(),
        };
        assert!(cached.is_fresh(), "brand-new cache entry must be fresh");
    }
}
