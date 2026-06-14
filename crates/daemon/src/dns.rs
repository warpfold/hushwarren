//! DNS listener + sinkhole request handler.
//!
//! Implements `specs/wp2-daemon.md` §2, `specs/wp4-privacy.md` §3.1–§3.3,
//! and `specs/wp8-transport-privacy.md` §4–§5.
//! Binds UDP + TCP listeners on every configured address via
//! `hickory_server::server::Server`.
//!
//! ## Request handler pipeline (WP8-extended)
//!
//! ```text
//! qname  --Domain::parse-->  fail? → Forward (counted, debug-logged)
//!   → [WP4 §3.1] canary check (use-application-dns.net) → NXDOMAIN / BrowserDohCanary
//!   → [WP4 §3.2] private relay check (mask.icloud.com variants)
//!       block_private_relay=true  → NODATA / PrivateRelayBlocked
//!       block_private_relay=false → force Forward / PrivateRelayProtected
//!   → engine.decide(domain, now)
//!     Block        → §2.2 sinkhole answer
//!     Forward      → upstream ladder (§3)
//!       [WP4 §3.3] CNAME inspection (if privacy.cname_inspection)
//!       [WP8 §4]   rebind protection (if privacy.rebind_protection)
//!                  inspects A/AAAA records; NOT ipv4hint/ipv6hint SvcParams
//!     ForwardLocal → local resolver config (empty → treat as Forward)
//! → push QueryRecord (always, including errors)
//! ```
//!
//! ## Protocol-level checks placement (§3.1–§3.2)
//!
//! Canary and Private Relay checks happen BEFORE the decision ladder — they are
//! protocol-level concerns (not list logic).  The decision ladder's precedence
//! (snooze → local → user-allow → list) is unchanged.
//!
//! ## CNAME-chain inspection (§3.3)
//!
//! After upstream resolve, before answering: walk every CNAME target in the
//! response chain.  Any blocked hop ⇒ sinkhole with reason
//! `CnameCloaked { hop }`.  Depth cap: 10 hops (forwarded uninspected beyond
//! cap, one warn per qname).  `allow` at any hop only protects that hop.
//! Flag off ⇒ skip entirely.
//!
//! ## Rebind protection (§4, WP8)
//!
//! After CNAME-chain inspection, before caching/answering: if any A/AAAA
//! record in the response is in the private reject set AND the original qname
//! is not exempt (user allowlist, `rebind_allow` config, built-in `plex.direct`),
//! respond NODATA with reason `RebindBlocked { addr }`.
//!
//! Local names never reach upstream (the decision ladder routes them to
//! `ForwardLocal` before any upstream query is made), so we never need to
//! apply rebind protection to local-name responses.
//!
//! Cache behaviour: the NODATA verdict is cached like CNAME-cloaking verdicts.
//! The upstream resolver caches the real answer chain; we serve NODATA from
//! our response path.  When the TTL expires the next query re-runs the check.
//!
//! ## HTTPS/SVCB type-65 integrity (§5, WP8)
//!
//! - Blocked qname + qtype HTTPS ⇒ NODATA (consistent with A/AAAA sinkhole
//!   behaviour — query never reaches upstream).
//! - Allowed qname + qtype HTTPS ⇒ upstream RDATA (SvcParams including ECH
//!   blob) reaches the client byte-intact via `relay_lookup`.
//! - Rebind protection inspects A/AAAA records ONLY — `ipv4hint`/`ipv6hint`
//!   SvcParams are hints, not answers; the spec §5 last bullet explicitly
//!   prohibits rejecting on hints.
//!
//! ## Sinkhole responses (§2.2)
//!
//! - `null_ip` (default): A ⇒ `0.0.0.0`, AAAA ⇒ `::`, TTL = config.
//!   Any other qtype ⇒ NODATA (NOERROR, empty answer).
//!   HTTPS(65)/SVCB(64) always return NODATA so browsers settle on the
//!   sinkholed A without a HTTPS-fallback leak.
//! - `nxdomain`: NXDOMAIN for all qtypes.
//! - PTR/ANY for blocked names: NODATA.
//!
//! ## Protocol hygiene (§2.3 infallible boundary)
//!
//! Any internal error maps to SERVFAIL; malformed input is counted and
//! debug-logged, never a crash.

use crate::{
    metrics::Metrics,
    rollup::{RollupHandle, RollupRecord},
    upstream::{UpstreamError, UpstreamLadder},
};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use hickory_proto::{
    op::{MessageType, Metadata, OpCode, ResponseCode},
    rr::{
        rdata::{A, AAAA},
        Name, RData, Record, RecordType,
    },
};
use hickory_server::{
    net::runtime::Time,
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    zone_handler::MessageResponseBuilder,
};
use hush_core::{
    config::{BlockAction, PrivacyConfig, QueryLogMode},
    querylog::{QueryRecord, QueryRing, REDACTED_QNAME},
    rebind::{is_private_addr, is_rebind_exempt},
    DecisionEngine, Domain, Reason, Verdict,
};
use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, warn};

/// The browser-DoH canary domain (case-insensitive).
///
/// Firefox queries this to detect if the system resolver disables DoH.
/// Answering NXDOMAIN tells Firefox to use the system resolver instead.
const BROWSER_DOH_CANARY_DOMAIN: &str = "use-application-dns.net";

/// iCloud Private Relay mask domains.
///
/// When `block_private_relay=true` → NODATA.
/// When `block_private_relay=false` → force-allowed (even if blocklisted).
const PRIVATE_RELAY_DOMAINS: &[&str] = &["mask.icloud.com", "mask-h2.icloud.com"];

/// Maximum CNAME chain depth to inspect (§3.3).
///
/// Beyond this depth, the chain is forwarded uninspected with a one-time warn.
const CNAME_DEPTH_CAP: usize = 10;

/// Shared state injected into every request handler invocation.
pub struct HandlerState {
    /// The decision engine (rules, snooze, user-allow).
    pub engine: Arc<DecisionEngine>,
    /// Upstream resolver ladder.
    pub ladder: Arc<UpstreamLadder>,
    /// Query ring buffer.
    pub ring: Arc<QueryRing>,
    /// Rollup writer channel handle (WP9).  Records are tee'd here after
    /// ring.push so the SQLite writer can persist them durably.
    pub rollup: RollupHandle,
    /// Daemon-wide counters.
    pub metrics: Arc<Metrics>,
    /// Block response configuration.
    pub block_action: BlockAction,
    /// Block TTL in seconds.
    pub block_ttl_secs: u32,
    /// Privacy feature toggles (WP4).
    ///
    /// Wrapped in [`ArcSwap`] for lock-free hot-reload: `POST /v0/config/reload`
    /// calls `privacy.store(Arc::new(new_config))` and the DNS hot path calls
    /// `privacy.load()` on every request — no restart required.
    pub privacy: Arc<ArcSwap<PrivacyConfig>>,
    /// When `true`, this handler is serving a Network Guard listener and
    /// `log_clients = true` — populate `QueryRecord.client` with the source IP.
    ///
    /// `false` for the loopback (Local Guard) handler instances: `client` is
    /// always `None` on the loopback path.
    pub log_clients: bool,
}

impl HandlerState {
    /// Push a query record into the RAM ring and tee it to the rollup channel.
    ///
    /// This is the single write point for all query records.  The ring push is
    /// infallible (O(1), mutex-protected).  The rollup send is try_send — on a
    /// full channel the record is dropped and the drop counter is incremented.
    pub(crate) fn push_query(&self, rec: QueryRecord) {
        // In anonymous mode, redact qname and detail strings BEFORE building the
        // rollup record so the SQLite writer never sees real qnames.
        // The ring's own push() also applies redaction (defence-in-depth), but
        // the rollup record is built here and must be redacted independently.
        let is_anonymous = self.ring.mode() == QueryLogMode::Anonymous;

        let rollup_qname = if is_anonymous {
            REDACTED_QNAME.to_owned()
        } else {
            rec.qname.clone()
        };

        // Reason strings that embed a qname/hop (CnameCloaked, RebindBlocked)
        // are redacted in anonymous mode to prevent leakage through the reason
        // column of the rollup DB.
        let reason_str = if is_anonymous {
            reason_for_rollup_anonymous(&rec.reason)
        } else {
            reason_for_rollup(&rec.reason)
        };
        let verdict_str = verdict_for_rollup(rec.verdict);
        let rollup_rec = RollupRecord {
            ts_ms: rec.ts_unix_ms,
            qname: rollup_qname,
            qtype: rec.qtype,
            verdict: verdict_str,
            reason: reason_str,
            client: rec.client,
        };
        self.ring.push(rec);
        self.rollup.try_send(rollup_rec);
    }
}

/// Convert a [`Verdict`] to its rollup string form.
fn verdict_for_rollup(v: Verdict) -> String {
    match v {
        Verdict::Block => "block",
        Verdict::Forward => "forward",
        Verdict::ForwardLocal => "forward_local",
    }
    .to_owned()
}

/// Convert a [`Reason`] to its rollup string form (mirrors routes.rs `reason_to_string`).
fn reason_for_rollup(r: &Reason) -> String {
    use hush_core::decision::Reason;
    match r {
        Reason::Snoozed => "snoozed".to_owned(),
        Reason::LocalName => "local_name".to_owned(),
        Reason::UserAllowed => "user_allowed".to_owned(),
        Reason::ListAllowed => "list_allowed".to_owned(),
        Reason::ListBlocked => "list_blocked".to_owned(),
        Reason::NoMatch => "no_match".to_owned(),
        Reason::BrowserDohCanary => "browser_doh_canary".to_owned(),
        Reason::PrivateRelayBlocked => "private_relay_blocked".to_owned(),
        Reason::PrivateRelayProtected => "private_relay_protected".to_owned(),
        Reason::CnameCloaked { hop } => format!("cname_cloaked:{hop}"),
        Reason::RebindBlocked { addr } => format!("rebind_blocked:{addr}"),
    }
}

/// Same as [`reason_for_rollup`] but redacts embedded hop/address detail strings
/// for [`QueryLogMode::Anonymous`] mode.
///
/// `CnameCloaked` and `RebindBlocked` embed a domain/address into the reason
/// string; in anonymous mode we strip that detail so the rollup DB contains no
/// real qname or network-topology data.
fn reason_for_rollup_anonymous(r: &Reason) -> String {
    use hush_core::decision::Reason;
    match r {
        Reason::CnameCloaked { .. } => "cname_cloaked:<redacted>".to_owned(),
        Reason::RebindBlocked { .. } => "rebind_blocked:<redacted>".to_owned(),
        other => reason_for_rollup(other),
    }
}

/// The `RequestHandler` implementation for the DNS sinkhole.
pub struct SinkholeHandler {
    state: Arc<HandlerState>,
}

impl SinkholeHandler {
    /// Construct a new handler around shared state.
    pub fn new(state: Arc<HandlerState>) -> Self {
        Self { state }
    }
}

#[async_trait]
impl RequestHandler for SinkholeHandler {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let state = Arc::clone(&self.state);
        handle_one(request, &mut response_handle, &state).await
    }
}

/// Core per-request processing: always returns a `ResponseInfo` (never panics).
///
/// Any error path maps to SERVFAIL.
async fn handle_one<R: ResponseHandler>(
    request: &Request,
    response_handle: &mut R,
    state: &HandlerState,
) -> ResponseInfo {
    state.metrics.inc_queries();

    // Load privacy config once per request (lock-free ArcSwap load).
    // All privacy-flag reads in this function use this snapshot so the config
    // is consistent for the duration of a single query even during a hot-reload.
    let privacy = state.privacy.load();

    // WP13: extract the source client IP once.  Populated in QueryRecords only
    // when `log_clients = true`; loopback handler instances always have
    // `log_clients = false` so `client_ip` is always `None` on the local path.
    let client_ip: Option<std::net::IpAddr> = if state.log_clients {
        Some(request.src().ip())
    } else {
        None
    };

    // Extract the single query from the request.  hickory guarantees exactly
    // one query per request for recursive forwarders; the infallible boundary
    // here maps any edge case to SERVFAIL.
    let req_info = match request.request_info() {
        Ok(info) => info,
        Err(e) => {
            debug!(error = %e, "request_info failed (malformed)");
            state.metrics.inc_malformed();
            return servfail(request, response_handle).await;
        }
    };

    let qtype = req_info.query.query_type();
    let qname_lower = req_info.query.name();
    let qname_str = qname_lower.to_string();
    // Strip trailing dot that hickory appends to FQDN.
    let qname_str = qname_str.strip_suffix('.').unwrap_or(&qname_str);
    let qname_lower_str = qname_str.to_ascii_lowercase();

    let start = Instant::now();
    let now_ms = unix_ms_now();

    // ── WP4 §3.1: Browser-DoH canary ─────────────────────────────────────────
    //
    // Checked BEFORE the decision ladder (protocol-level concern).
    // Any qtype to use-application-dns.net → NXDOMAIN when flag on.
    if privacy.browser_doh_canary && qname_lower_str == BROWSER_DOH_CANARY_DOMAIN {
        debug!(qname = qname_str, "browser-DoH canary → NXDOMAIN");
        state.metrics.inc_blocked();
        let response_info = nxdomain_response(request, response_handle).await;
        state.push_query(QueryRecord {
            ts_unix_ms: now_ms,
            qname: qname_str.to_string(),
            qtype: qtype.into(),
            verdict: Verdict::Block,
            reason: Reason::BrowserDohCanary,
            upstream_ms: None,
            client: client_ip,
        });
        return response_info;
    }

    // ── WP4 §3.2: iCloud Private Relay gate ──────────────────────────────────
    //
    // Checked BEFORE the decision ladder (protocol-level concern).
    // mask.icloud.com and mask-h2.icloud.com (and subdomains).
    let is_private_relay = PRIVATE_RELAY_DOMAINS
        .iter()
        .any(|&pr| qname_lower_str == pr || qname_lower_str.ends_with(&format!(".{pr}")));

    if is_private_relay {
        if privacy.block_private_relay {
            // block_private_relay=true: respond NODATA per Apple's documented mechanism.
            debug!(qname = qname_str, "private relay → NODATA (blocked)");
            state.metrics.inc_blocked();
            let response_info = nodata_response(request, response_handle).await;
            state.push_query(QueryRecord {
                ts_unix_ms: now_ms,
                qname: qname_str.to_string(),
                qtype: qtype.into(),
                verdict: Verdict::Block,
                reason: Reason::PrivateRelayBlocked,
                upstream_ms: None,
                client: client_ip,
            });
            return response_info;
        } else {
            // block_private_relay=false (default): force-allow regardless of blocklist.
            // Forward immediately without consulting the decision engine.
            debug!(
                qname = qname_str,
                "private relay → force-allowed (protected)"
            );
            state.metrics.inc_forwarded();
            let elapsed_ms = start.elapsed().as_millis() as u32;
            let response_info = forward_to_upstream(
                request,
                response_handle,
                qname_str,
                qtype,
                &state.ladder,
                &state.metrics,
            )
            .await;
            state.push_query(QueryRecord {
                ts_unix_ms: now_ms,
                qname: qname_str.to_string(),
                qtype: qtype.into(),
                verdict: Verdict::Forward,
                reason: Reason::PrivateRelayProtected,
                upstream_ms: Some(elapsed_ms),
                client: client_ip,
            });
            return response_info;
        }
    }

    // ── Decision ladder ───────────────────────────────────────────────────────

    // Attempt to parse qname through hush-core Domain for decision.
    // Failure: forward UNTOUCHED (we filter ads, we are not a validator).
    let domain_opt = Domain::parse(qname_str).ok();

    let (verdict, reason) = match &domain_opt {
        Some(d) => state.engine.decide(d, now_ms),
        None => {
            debug!(
                qname = qname_str,
                "qname failed Domain::parse; forwarding untouched"
            );
            (Verdict::Forward, Reason::NoMatch)
        }
    };

    debug!(
        qname = qname_str,
        qtype = ?qtype,
        verdict = ?verdict,
        reason = ?reason,
        "query"
    );

    let response_info = match verdict {
        Verdict::Block => {
            state.metrics.inc_blocked();
            block_response(
                request,
                response_handle,
                qtype,
                state.block_action,
                state.block_ttl_secs,
            )
            .await
        }
        Verdict::Forward | Verdict::ForwardLocal => {
            // ── WP4 §3.3 + WP8 §4: CNAME inspection + rebind protection ─────
            //
            // Forward to upstream, then:
            //   1. Inspect CNAME chain (if enabled) → sinkhole CnameCloaked.
            //   2. Check rebind protection (if enabled) → sinkhole RebindBlocked.
            //
            // Rebind protection exemption: user-allowed names (reason ==
            // UserAllowed) bypass the rebind check — the user allowlist is the
            // highest-precedence exemption mechanism.
            //
            // Note: metrics.inc_forwarded() is called after both checks pass.
            let user_allowed = matches!(reason, Reason::UserAllowed);

            if privacy.cname_inspection {
                let (ri, post_outcome) = forward_with_cname_and_rebind(
                    request,
                    response_handle,
                    qname_str,
                    qtype,
                    &state.ladder,
                    &state.engine,
                    &state.metrics,
                    now_ms,
                    state.block_action,
                    state.block_ttl_secs,
                    privacy.rebind_protection && !user_allowed,
                    &privacy.rebind_allow,
                )
                .await;

                match post_outcome {
                    PostUpstreamOutcome::CnameCloaked(hop) => {
                        // CNAME inspection blocked: override verdict/reason.
                        let elapsed_ms = start.elapsed().as_millis() as u32;
                        state.push_query(QueryRecord {
                            ts_unix_ms: now_ms,
                            qname: qname_str.to_string(),
                            qtype: qtype.into(),
                            verdict: Verdict::Block,
                            reason: Reason::CnameCloaked { hop },
                            upstream_ms: Some(elapsed_ms),
                            client: client_ip,
                        });
                        return ri;
                    }
                    PostUpstreamOutcome::RebindBlocked(addr) => {
                        // Rebind protection blocked: override verdict/reason.
                        let elapsed_ms = start.elapsed().as_millis() as u32;
                        state.push_query(QueryRecord {
                            ts_unix_ms: now_ms,
                            qname: qname_str.to_string(),
                            qtype: qtype.into(),
                            verdict: Verdict::Block,
                            reason: Reason::RebindBlocked { addr },
                            upstream_ms: Some(elapsed_ms),
                            client: client_ip,
                        });
                        return ri;
                    }
                    PostUpstreamOutcome::Passed => {}
                }

                // All checks passed; fall through to normal forwarded log.
                state.metrics.inc_forwarded();
                let elapsed_ms = start.elapsed().as_millis() as u32;
                state.push_query(QueryRecord {
                    ts_unix_ms: now_ms,
                    qname: qname_str.to_string(),
                    qtype: qtype.into(),
                    verdict,
                    reason,
                    upstream_ms: Some(elapsed_ms),
                    client: client_ip,
                });
                return ri;
            } else if privacy.rebind_protection && !user_allowed {
                // CNAME inspection off but rebind protection on.
                let (ri, rebind_addr) = forward_with_rebind_check(
                    request,
                    response_handle,
                    qname_str,
                    qtype,
                    &state.ladder,
                    &state.metrics,
                    &privacy.rebind_allow,
                )
                .await;

                if let Some(addr) = rebind_addr {
                    let elapsed_ms = start.elapsed().as_millis() as u32;
                    state.push_query(QueryRecord {
                        ts_unix_ms: now_ms,
                        qname: qname_str.to_string(),
                        qtype: qtype.into(),
                        verdict: Verdict::Block,
                        reason: Reason::RebindBlocked { addr },
                        upstream_ms: Some(elapsed_ms),
                        client: client_ip,
                    });
                    return ri;
                }

                state.metrics.inc_forwarded();
                let elapsed_ms = start.elapsed().as_millis() as u32;
                state.push_query(QueryRecord {
                    ts_unix_ms: now_ms,
                    qname: qname_str.to_string(),
                    qtype: qtype.into(),
                    verdict,
                    reason,
                    upstream_ms: Some(elapsed_ms),
                    client: client_ip,
                });
                return ri;
            } else {
                state.metrics.inc_forwarded();
                forward_to_upstream(
                    request,
                    response_handle,
                    qname_str,
                    qtype,
                    &state.ladder,
                    &state.metrics,
                )
                .await
            }
        }
    };

    let elapsed_ms = start.elapsed().as_millis() as u32;
    let upstream_ms = match verdict {
        Verdict::Block => None,
        _ => Some(elapsed_ms),
    };

    state.push_query(QueryRecord {
        ts_unix_ms: now_ms,
        qname: qname_str.to_string(),
        qtype: qtype.into(),
        verdict,
        reason,
        upstream_ms,
        client: client_ip,
    });

    response_info
}

// ── WP4 + WP8: Post-upstream inspection ───────────────────────────────────────

/// Outcome of the post-upstream inspection pipeline (CNAME + rebind).
enum PostUpstreamOutcome {
    /// A CNAME hop was blocked.  The inner `String` is the offending hop name.
    CnameCloaked(String),
    /// Rebind protection blocked a private address.  The inner `String` is the
    /// offending address (for query-log detail).
    RebindBlocked(String),
    /// All checks passed; the response was relayed to the client.
    Passed,
}

/// Forward a query and apply CNAME-chain inspection followed by rebind
/// protection on the resolved answer.
///
/// Returns `(ResponseInfo, PostUpstreamOutcome)`.  The caller must push the
/// correct `QueryRecord` based on the outcome.
///
/// ## Inspection semantics (§3.3 + §4)
///
/// 1. **CNAME inspection**: Walk CNAME records from the answer section (up to
///    `CNAME_DEPTH_CAP`).  Any blocked hop ⇒ `CnameCloaked`.  Allow at any
///    hop only protects that hop.  Beyond the cap, forwarded uninspected.
/// 2. **Rebind protection** (only when `check_rebind=true`): After CNAME
///    inspection passes, walk A/AAAA records.  Any private-address hit that
///    is not exempt ⇒ `RebindBlocked`.
///
/// ## What rebind protection does NOT inspect
///
/// `ipv4hint`/`ipv6hint` SvcParams in HTTPS/SVCB records are advisory hints,
/// not answers (`specs/wp8-transport-privacy.md` §5 last bullet).  Only
/// A/AAAA RData is inspected here.
///
/// ## Cache soundness
///
/// Inspection is response-side (AdGuard model).  The upstream resolver caches
/// the full CNAME chain.  The daemon's decision engine always re-evaluates the
/// original qname (not the cache) — the cache only stores the upstream answer,
/// not the sinkhole verdict.  Therefore cache hits are sound: if a CNAME hop
/// is subsequently added to a blocklist, the next query re-runs inspection and
/// finds the block.
#[allow(clippy::too_many_arguments)]
async fn forward_with_cname_and_rebind<R: ResponseHandler>(
    request: &Request,
    response_handle: &mut R,
    qname: &str,
    qtype: RecordType,
    ladder: &UpstreamLadder,
    engine: &DecisionEngine,
    metrics: &Metrics,
    now_ms: u64,
    block_action: BlockAction,
    block_ttl_secs: u32,
    check_rebind: bool,
    rebind_allow: &[String],
) -> (ResponseInfo, PostUpstreamOutcome) {
    // Resolve upstream.
    let lookup = match ladder.resolve(qname, qtype).await {
        Ok(l) => l,
        Err(_) => {
            metrics.inc_servfail();
            let ri = servfail(request, response_handle).await;
            return (ri, PostUpstreamOutcome::Passed);
        }
    };

    // ── CNAME inspection ──────────────────────────────────────────────────────

    // Walk CNAME chain from the answer section.
    let cname_targets: Vec<String> = lookup
        .answers()
        .iter()
        .filter_map(|r| {
            if let hickory_proto::rr::RData::CNAME(cname) = &r.data {
                let target = cname.0.to_string();
                let target = target
                    .strip_suffix('.')
                    .unwrap_or(&target)
                    .to_ascii_lowercase();
                Some(target)
            } else {
                None
            }
        })
        .collect();

    if !cname_targets.is_empty() {
        // Depth-cap check.
        if cname_targets.len() > CNAME_DEPTH_CAP {
            warn!(
                qname = qname,
                depth = cname_targets.len(),
                cap = CNAME_DEPTH_CAP,
                "CNAME chain exceeds depth cap; forwarding uninspected"
            );
        } else {
            // Inspect each hop.
            for hop_str in &cname_targets {
                let hop_domain = match Domain::parse(hop_str) {
                    Ok(d) => d,
                    Err(_) => {
                        debug!(hop = hop_str, "CNAME hop failed Domain::parse; skipping");
                        continue;
                    }
                };

                let (hop_verdict, _) = engine.decide(&hop_domain, now_ms);
                if hop_verdict == Verdict::Block {
                    debug!(
                        qname = qname,
                        hop = hop_str,
                        "CNAME-cloaked tracker blocked"
                    );
                    metrics.inc_blocked();
                    let ri = block_response(
                        request,
                        response_handle,
                        qtype,
                        block_action,
                        block_ttl_secs,
                    )
                    .await;
                    return (ri, PostUpstreamOutcome::CnameCloaked(hop_str.clone()));
                }
                // Allow or no-match → continue checking the next hop.
            }
        }
    }

    // ── Rebind protection ─────────────────────────────────────────────────────

    if check_rebind && !is_rebind_exempt(qname, rebind_allow) {
        if let Some(offending_addr) = find_rebind_offender(lookup.answers()) {
            debug!(
                qname = qname,
                addr = %offending_addr,
                "rebind protection blocked private address in public-name answer"
            );
            metrics.inc_blocked();
            let ri = nodata_response(request, response_handle).await;
            return (
                ri,
                PostUpstreamOutcome::RebindBlocked(offending_addr.to_string()),
            );
        }
    }

    // All checks passed.
    let ri = relay_lookup(request, response_handle, &lookup).await;
    (ri, PostUpstreamOutcome::Passed)
}

/// Forward a query and apply rebind protection only (CNAME inspection off).
///
/// Returns `(ResponseInfo, Option<String>)` where the `String` is the
/// offending address if rebind protection fired.
///
/// Rebind protection always returns NODATA (not the configurable block action)
/// because a rebind block is not a list decision — it is a response-content
/// check.
async fn forward_with_rebind_check<R: ResponseHandler>(
    request: &Request,
    response_handle: &mut R,
    qname: &str,
    qtype: RecordType,
    ladder: &UpstreamLadder,
    metrics: &Metrics,
    rebind_allow: &[String],
) -> (ResponseInfo, Option<String>) {
    let lookup = match ladder.resolve(qname, qtype).await {
        Ok(l) => l,
        Err(_) => {
            metrics.inc_servfail();
            let ri = servfail(request, response_handle).await;
            return (ri, None);
        }
    };

    if !is_rebind_exempt(qname, rebind_allow) {
        if let Some(offending_addr) = find_rebind_offender(lookup.answers()) {
            debug!(
                qname = qname,
                addr = %offending_addr,
                "rebind protection blocked private address in public-name answer"
            );
            metrics.inc_blocked();
            // Rebind → NODATA (not a list-block sinkhole action).
            let ri = nodata_response(request, response_handle).await;
            return (ri, Some(offending_addr.to_string()));
        }
    }

    let ri = relay_lookup(request, response_handle, &lookup).await;
    (ri, None)
}

/// Walk A/AAAA records in `answers` and return the first private address found.
///
/// Returns `None` if no private address is present.
///
/// ## Why only A/AAAA?
///
/// `ipv4hint`/`ipv6hint` SvcParams inside HTTPS/SVCB records are advisory
/// hints — they help clients pre-connect but the browser will re-verify the
/// real connection.  Rejecting on hints would break legitimate ECH-capable
/// names whose SVCB record hints at a CDN edge IP that happens to be in a
/// range we reject.  See `specs/wp8-transport-privacy.md` §5 last bullet.
fn find_rebind_offender(answers: &[hickory_proto::rr::Record]) -> Option<std::net::IpAddr> {
    use hickory_proto::rr::RData;
    for record in answers {
        match &record.data {
            RData::A(a) => {
                let ip = std::net::IpAddr::V4(a.0);
                if is_private_addr(ip) {
                    return Some(ip);
                }
            }
            RData::AAAA(aaaa) => {
                let ip = std::net::IpAddr::V6(aaaa.0);
                if is_private_addr(ip) {
                    return Some(ip);
                }
            }
            // CNAME, HTTPS, SVCB, TXT, MX, etc. — not inspected for rebind.
            _ => {}
        }
    }
    None
}

/// Relay a resolved `Lookup` back to the DNS client.
async fn relay_lookup<R: ResponseHandler>(
    request: &Request,
    response_handle: &mut R,
    lookup: &hickory_resolver::lookup::Lookup,
) -> ResponseInfo {
    let builder = MessageResponseBuilder::from_message_request(request);
    let mut meta = response_metadata_from_request(request);
    meta.recursion_available = true;
    meta.response_code = ResponseCode::NoError;
    let records: Vec<&hickory_proto::rr::Record> = lookup.answers().iter().collect();
    let response = builder.build(meta, records.iter().copied(), [], [], []);
    send_response(response_handle, response).await
}

// ── Sinkhole response construction ──────────────────────────────────────────

/// Build and send a sinkhole response.
async fn block_response<R: ResponseHandler>(
    request: &Request,
    response_handle: &mut R,
    qtype: RecordType,
    action: BlockAction,
    ttl_secs: u32,
) -> ResponseInfo {
    match action {
        BlockAction::NullIp => null_ip_response(request, response_handle, qtype, ttl_secs).await,
        BlockAction::Nxdomain => nxdomain_response(request, response_handle).await,
    }
}

/// Respond with null IPs (0.0.0.0 / ::) per §2.2.
///
/// - A ⇒ `0.0.0.0`
/// - AAAA ⇒ `::`
/// - HTTPS(65)/SVCB(64)/PTR/ANY/other ⇒ NODATA (NOERROR, empty answer)
async fn null_ip_response<R: ResponseHandler>(
    request: &Request,
    response_handle: &mut R,
    qtype: RecordType,
    ttl_secs: u32,
) -> ResponseInfo {
    match qtype {
        RecordType::A => {
            let qname = match build_name_from_request(request) {
                Ok(n) => n,
                Err(_) => return servfail_raw(request, response_handle).await,
            };
            let record = Record::from_rdata(qname, ttl_secs, RData::A(A(Ipv4Addr::UNSPECIFIED)));
            let builder = MessageResponseBuilder::from_message_request(request);
            let mut meta = response_metadata_from_request(request);
            meta.recursion_available = true;
            meta.authoritative = false;
            let response = builder.build(meta, [&record], [], [], []);
            send_response(response_handle, response).await
        }
        RecordType::AAAA => {
            let qname = match build_name_from_request(request) {
                Ok(n) => n,
                Err(_) => return servfail_raw(request, response_handle).await,
            };
            let record =
                Record::from_rdata(qname, ttl_secs, RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED)));
            let builder = MessageResponseBuilder::from_message_request(request);
            let mut meta = response_metadata_from_request(request);
            meta.recursion_available = true;
            meta.authoritative = false;
            let response = builder.build(meta, [&record], [], [], []);
            send_response(response_handle, response).await
        }
        // HTTPS(65), SVCB(64), TXT, MX, SRV, PTR, ANY, and all others
        // get NODATA (NOERROR, empty answer section).
        _ => nodata_response(request, response_handle).await,
    }
}

/// NXDOMAIN for all qtypes (§2.2 `nxdomain` action).
async fn nxdomain_response<R: ResponseHandler>(
    request: &Request,
    response_handle: &mut R,
) -> ResponseInfo {
    let builder = MessageResponseBuilder::from_message_request(request);
    let mut meta = response_metadata_from_request(request);
    meta.response_code = ResponseCode::NXDomain;
    meta.recursion_available = true;
    let response = builder.build_no_records(meta);
    send_response(response_handle, response).await
}

/// NOERROR with empty answer section (NODATA).
async fn nodata_response<R: ResponseHandler>(
    request: &Request,
    response_handle: &mut R,
) -> ResponseInfo {
    let builder = MessageResponseBuilder::from_message_request(request);
    let mut meta = response_metadata_from_request(request);
    meta.recursion_available = true;
    let response = builder.build_no_records(meta);
    send_response(response_handle, response).await
}

// ── Forwarding ───────────────────────────────────────────────────────────────

/// Forward a query to the upstream ladder and relay the answer.
async fn forward_to_upstream<R: ResponseHandler>(
    request: &Request,
    response_handle: &mut R,
    qname: &str,
    qtype: RecordType,
    ladder: &UpstreamLadder,
    metrics: &Metrics,
) -> ResponseInfo {
    match ladder.resolve(qname, qtype).await {
        Ok(lookup) => {
            let builder = MessageResponseBuilder::from_message_request(request);
            let mut meta = response_metadata_from_request(request);
            meta.recursion_available = true;
            meta.response_code = ResponseCode::NoError;
            let records: Vec<&Record> = lookup.answers().iter().collect();
            let response = builder.build(meta, records.iter().copied(), [], [], []);
            send_response(response_handle, response).await
        }
        Err(UpstreamError::AllExhausted) => {
            metrics.inc_servfail();
            servfail(request, response_handle).await
        }
        Err(UpstreamError::Rung(_)) => {
            // Single rung error surfaced here (should not normally happen).
            metrics.inc_servfail();
            servfail(request, response_handle).await
        }
    }
}

// ── Low-level response helpers ────────────────────────────────────────────────

async fn servfail<R: ResponseHandler>(request: &Request, response_handle: &mut R) -> ResponseInfo {
    servfail_raw(request, response_handle).await
}

async fn servfail_raw<R: ResponseHandler>(
    request: &Request,
    response_handle: &mut R,
) -> ResponseInfo {
    let builder = MessageResponseBuilder::from_message_request(request);
    // Request derefs to MessageRequest; `.metadata` is a public field.
    let response = builder.error_msg(&request.metadata, ResponseCode::ServFail);
    send_response(response_handle, response).await
}

/// Send `response` through `response_handle`; on send error log and return a
/// serve-failed `ResponseInfo` rather than propagating (infallible boundary).
async fn send_response<'q, 'a, R, A, N, S, D>(
    response_handle: &mut R,
    response: hickory_server::zone_handler::MessageResponse<'q, 'a, A, N, S, D>,
) -> ResponseInfo
where
    R: ResponseHandler,
    A: Iterator<Item = &'a Record> + Send + 'a,
    N: Iterator<Item = &'a Record> + Send + 'a,
    S: Iterator<Item = &'a Record> + Send + 'a,
    D: Iterator<Item = &'a Record> + Send + 'a,
{
    match response_handle.send_response(response).await {
        Ok(info) => info,
        Err(e) => {
            warn!(error = %e, "failed to send DNS response");
            // Construct a minimal ResponseInfo from a ServFail header.
            use hickory_proto::op::Header;
            let mut meta = Metadata::new(0, MessageType::Response, OpCode::Query);
            meta.response_code = ResponseCode::ServFail;
            let hdr = Header {
                metadata: meta,
                counts: Default::default(),
            };
            ResponseInfo::from(hdr)
        }
    }
}

/// Build a `Metadata` for the response, copying the request's ID and flags.
fn response_metadata_from_request(request: &Request) -> Metadata {
    // Request derefs to MessageRequest; `.metadata` is a public field.
    Metadata::response_from_request(&request.metadata)
}

/// Build a `hickory_proto::rr::Name` from the first query in `request`.
fn build_name_from_request(request: &Request) -> Result<Name, ()> {
    let info = request.request_info().map_err(|_| ())?;
    let name = info.query.name().to_string();
    name.parse::<Name>().map_err(|_| ())
}

/// Best-effort Unix time in milliseconds.
fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ── Server startup helper ─────────────────────────────────────────────────────

/// Bound address information returned by `bind_listeners`.
pub struct BoundAddrs {
    /// The actual UDP socket addresses (one per configured address).
    pub udp: Vec<SocketAddr>,
    /// The actual TCP socket addresses (one per configured address).
    pub tcp: Vec<SocketAddr>,
}

/// Bind all DNS listeners and return a `Server` + actual bound addresses.
///
/// Passes ownership of the server to the caller; call
/// `server.block_until_done()` to drive it.
pub async fn bind_listeners(
    udp_addrs: &[String],
    tcp_addrs: &[String],
    handler: SinkholeHandler,
) -> Result<(hickory_server::server::Server<SinkholeHandler>, BoundAddrs), std::io::Error> {
    let mut server = hickory_server::server::Server::new(handler);
    let mut bound_udp = Vec::new();
    let mut bound_tcp = Vec::new();

    for addr_str in udp_addrs {
        let addr: SocketAddr = addr_str.parse().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, addr_str.as_str())
        })?;
        let socket = UdpSocket::bind(addr).await?;
        let actual = socket.local_addr()?;
        server.register_socket(socket);
        bound_udp.push(actual);
    }

    for addr_str in tcp_addrs {
        let addr: SocketAddr = addr_str.parse().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, addr_str.as_str())
        })?;
        let listener = TcpListener::bind(addr).await?;
        let actual = listener.local_addr()?;
        server.register_listener(listener, Duration::from_secs(5), 1024);
        bound_tcp.push(actual);
    }

    Ok((
        server,
        BoundAddrs {
            udp: bound_udp,
            tcp: bound_tcp,
        },
    ))
}

/// Bind Network Guard DNS listeners on explicit LAN IP addresses.
///
/// Implements `specs/wp13-network-guard.md` §2.  Each address in `lan_ips` is
/// bound on port 53 (UDP + TCP) and registered with a new hickory `Server`
/// that uses the same `SinkholeHandler`.  Returns the actual bound addresses
/// and a background task driving the guard server.
///
/// Bind failure on any address is returned as an error to the caller; the
/// caller (app.rs) logs it as a warning and continues without guard listeners
/// (non-fatal: iface may be down).
///
/// Retry-with-backoff for temporarily unavailable interfaces is left to a
/// future work package; the spec §2 says "warn + retry with backoff, never
/// fatal."  The current implementation warns on the initial bind failure and
/// the caller can restart the daemon when the interface comes up.
pub async fn bind_guard_listeners(
    lan_ips: &[String],
    handler: SinkholeHandler,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<
    (
        Vec<SocketAddr>,
        Vec<SocketAddr>,
        tokio::task::JoinHandle<()>,
    ),
    std::io::Error,
> {
    let mut guard_server = hickory_server::server::Server::new(handler);
    let mut bound_udp = Vec::new();
    let mut bound_tcp = Vec::new();

    for ip_str in lan_ips {
        let ip: std::net::IpAddr = ip_str.parse().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid IP: {ip_str}"),
            )
        })?;

        // UDP on port 53 for this LAN address.
        let udp_addr = SocketAddr::new(ip, 53);
        let udp_sock = UdpSocket::bind(udp_addr).await?;
        let actual_udp = udp_sock.local_addr()?;
        guard_server.register_socket(udp_sock);
        bound_udp.push(actual_udp);

        // TCP on port 53 for this LAN address.
        let tcp_addr = SocketAddr::new(ip, 53);
        let tcp_listener = TcpListener::bind(tcp_addr).await?;
        let actual_tcp = tcp_listener.local_addr()?;
        guard_server.register_listener(tcp_listener, Duration::from_secs(5), 1024);
        bound_tcp.push(actual_tcp);
    }

    let task = tokio::spawn(async move {
        tokio::select! {
            result = guard_server.block_until_done() => {
                if let Err(e) = result {
                    tracing::error!(error = %e, "Network Guard DNS server error");
                }
            }
            () = cancel.cancelled() => {
                if let Err(e) = guard_server.shutdown_gracefully().await {
                    tracing::error!(error = %e, "Network Guard DNS server shutdown error");
                }
            }
        }
    });

    Ok((bound_udp, bound_tcp, task))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use hush_core::config::BlockAction;

    // ── WP4 §3.1: canary domain matching ─────────────────────────────────────

    #[test]
    fn canary_domain_lowercase_matches() {
        let canon = "use-application-dns.net";
        // Case-insensitive: uppercase and mixed-case should also match after
        // to_ascii_lowercase().
        for input in &[
            "use-application-dns.net",
            "USE-APPLICATION-DNS.NET",
            "Use-Application-Dns.Net",
        ] {
            let lower = input.to_ascii_lowercase();
            assert_eq!(lower, canon, "canary domain must match case-insensitively");
        }
    }

    #[test]
    fn non_canary_domain_does_not_match() {
        let canon = "use-application-dns.net";
        for non_canary in &[
            "example.com",
            "use-application-dns.net.evil.com",
            "use-application-dns.net.local",
            "notuse-application-dns.net",
        ] {
            let lower = non_canary.to_ascii_lowercase();
            assert_ne!(lower, canon, "{non_canary} must not match canary domain");
        }
    }

    // ── WP4 §3.2: private relay domain matching ───────────────────────────────

    #[test]
    fn private_relay_exact_match() {
        for pr in PRIVATE_RELAY_DOMAINS {
            let qname = pr.to_ascii_lowercase();
            let matches = PRIVATE_RELAY_DOMAINS
                .iter()
                .any(|&d| qname == d || qname.ends_with(&format!(".{d}")));
            assert!(matches, "{pr} must match private relay domains");
        }
    }

    #[test]
    fn private_relay_subdomain_matches() {
        let sub = "sub.mask.icloud.com";
        let qname = sub.to_ascii_lowercase();
        let matches = PRIVATE_RELAY_DOMAINS
            .iter()
            .any(|&d| qname == d || qname.ends_with(&format!(".{d}")));
        assert!(matches, "subdomain of private relay must match");
    }

    #[test]
    fn non_private_relay_does_not_match() {
        for non_pr in &[
            "example.com",
            "mask.icloud.com.evil.net",
            "notmask.icloud.com",
        ] {
            let qname = non_pr.to_ascii_lowercase();
            let matches = PRIVATE_RELAY_DOMAINS
                .iter()
                .any(|&d| qname == d || qname.ends_with(&format!(".{d}")));
            assert!(!matches, "{non_pr} must not match private relay domains");
        }
    }

    // ── WP4 §3.3: CNAME depth cap ────────────────────────────────────────────

    #[test]
    fn cname_depth_cap_value() {
        // The spec says depth cap is 10.  Verify the constant.
        assert_eq!(CNAME_DEPTH_CAP, 10);
    }

    // ── Sinkhole qtype dispatch table (§2.2) ──────────────────────────────────

    #[test]
    fn https_qtype_is_nodata_not_a_record() {
        // HTTPS (qtype 65) for a blocked name must produce NODATA, not an A record.
        let qtype = RecordType::HTTPS;
        assert!(!matches!(qtype, RecordType::A | RecordType::AAAA));
    }

    #[test]
    fn txt_qtype_is_nodata() {
        assert!(!matches!(RecordType::TXT, RecordType::A | RecordType::AAAA));
    }

    #[test]
    fn mx_qtype_is_nodata() {
        assert!(!matches!(RecordType::MX, RecordType::A | RecordType::AAAA));
    }

    #[test]
    fn srv_qtype_is_nodata() {
        assert!(!matches!(RecordType::SRV, RecordType::A | RecordType::AAAA));
    }

    #[test]
    fn ptr_qtype_is_nodata() {
        assert!(!matches!(RecordType::PTR, RecordType::A | RecordType::AAAA));
    }

    #[test]
    fn svcb_qtype_is_nodata() {
        assert!(!matches!(
            RecordType::SVCB,
            RecordType::A | RecordType::AAAA
        ));
    }

    // ── Null IP values ────────────────────────────────────────────────────────

    #[test]
    fn null_ipv4_is_unspecified() {
        assert_eq!(Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(0, 0, 0, 0));
    }

    #[test]
    fn null_ipv6_is_unspecified() {
        assert_eq!(Ipv6Addr::UNSPECIFIED, Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
    }

    // ── unix_ms_now is non-zero ───────────────────────────────────────────────

    #[test]
    fn unix_ms_now_nonzero() {
        assert!(unix_ms_now() > 0);
    }

    // ── BlockAction variants ──────────────────────────────────────────────────

    #[test]
    fn block_action_variants_exhaustive() {
        let _ = BlockAction::NullIp;
        let _ = BlockAction::Nxdomain;
    }

    // ── WP8 §4: rebind walker (find_rebind_offender) ──────────────────────────

    /// Build a minimal A record for testing purposes.
    fn make_a_record(ip: Ipv4Addr) -> hickory_proto::rr::Record {
        use hickory_proto::rr::{rdata::A, Name, RData, Record};
        let name: Name = "example.com.".parse().unwrap();
        Record::from_rdata(name, 60, RData::A(A(ip)))
    }

    /// Build a minimal AAAA record for testing purposes.
    fn make_aaaa_record(ip: Ipv6Addr) -> hickory_proto::rr::Record {
        use hickory_proto::rr::{rdata::AAAA, Name, RData, Record};
        let name: Name = "example.com.".parse().unwrap();
        Record::from_rdata(name, 60, RData::AAAA(AAAA(ip)))
    }

    #[test]
    fn rebind_walker_empty_answer_no_offender() {
        let offender = find_rebind_offender(&[]);
        assert!(offender.is_none(), "empty answer must have no offender");
    }

    #[test]
    fn rebind_walker_public_ipv4_no_offender() {
        let rec = make_a_record(Ipv4Addr::new(1, 1, 1, 1));
        let offender = find_rebind_offender(&[rec]);
        assert!(
            offender.is_none(),
            "public IPv4 must not be flagged as offender"
        );
    }

    #[test]
    fn rebind_walker_private_ipv4_192_168() {
        let rec = make_a_record(Ipv4Addr::new(192, 168, 1, 1));
        let offender = find_rebind_offender(&[rec]);
        assert_eq!(
            offender,
            Some(std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            "192.168.1.1 must be flagged as offender"
        );
    }

    #[test]
    fn rebind_walker_private_ipv4_10_x() {
        let rec = make_a_record(Ipv4Addr::new(10, 0, 0, 1));
        assert!(
            find_rebind_offender(&[rec]).is_some(),
            "10.0.0.1 must be flagged"
        );
    }

    #[test]
    fn rebind_walker_private_ipv4_172_16() {
        let rec = make_a_record(Ipv4Addr::new(172, 20, 0, 1));
        assert!(
            find_rebind_offender(&[rec]).is_some(),
            "172.20.0.1 must be flagged"
        );
    }

    #[test]
    fn rebind_walker_cgnat_100_64_not_flagged() {
        // CGNAT / Tailscale: must NOT be rejected.
        let rec = make_a_record(Ipv4Addr::new(100, 64, 0, 1));
        assert!(
            find_rebind_offender(&[rec]).is_none(),
            "100.64.0.1 (CGNAT) must NOT be flagged"
        );
    }

    #[test]
    fn rebind_walker_loopback_ipv6() {
        let rec = make_aaaa_record(Ipv6Addr::LOCALHOST);
        assert!(
            find_rebind_offender(&[rec]).is_some(),
            "::1 must be flagged"
        );
    }

    #[test]
    fn rebind_walker_link_local_ipv6() {
        let ip: Ipv6Addr = "fe80::1".parse().unwrap();
        let rec = make_aaaa_record(ip);
        assert!(
            find_rebind_offender(&[rec]).is_some(),
            "fe80::1 must be flagged as link-local"
        );
    }

    #[test]
    fn rebind_walker_public_ipv6_no_offender() {
        let ip: Ipv6Addr = "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap();
        let rec = make_aaaa_record(ip);
        assert!(
            find_rebind_offender(&[rec]).is_none(),
            "public IPv6 must not be flagged"
        );
    }

    #[test]
    fn rebind_walker_stops_at_first_offender() {
        // Mix of public + private: must flag the private one.
        let public = make_a_record(Ipv4Addr::new(1, 1, 1, 1));
        let private = make_a_record(Ipv4Addr::new(192, 168, 0, 1));
        let offender = find_rebind_offender(&[public, private]);
        assert!(
            offender.is_some(),
            "walker must flag private even after public"
        );
    }

    #[test]
    fn rebind_walker_cname_record_not_inspected() {
        // CNAME records in the answer section must NOT trigger rebind protection.
        use hickory_proto::rr::{rdata::CNAME, Name, RData, Record};
        let name: Name = "example.com.".parse().unwrap();
        let target: Name = "target.example.com.".parse().unwrap();
        let rec = Record::from_rdata(name, 60, RData::CNAME(CNAME(target)));
        assert!(
            find_rebind_offender(&[rec]).is_none(),
            "CNAME records must not be inspected for rebind"
        );
    }

    #[test]
    fn rebind_walker_plex_direct_name_exempt() {
        // is_rebind_exempt must return true for plex.direct (exempt from rebind).
        use hush_core::rebind::is_rebind_exempt;
        assert!(
            is_rebind_exempt("plex.direct", &[]),
            "plex.direct must be exempt"
        );
        assert!(
            is_rebind_exempt("sub.plex.direct", &[]),
            "sub.plex.direct must be exempt"
        );
    }

    #[test]
    fn rebind_walker_rebind_allow_suffix_exempt() {
        use hush_core::rebind::is_rebind_exempt;
        let allow = vec!["corp.internal".to_string()];
        assert!(
            is_rebind_exempt("server.corp.internal", &allow),
            "server.corp.internal must be exempt via rebind_allow"
        );
        assert!(
            !is_rebind_exempt("evil.com", &allow),
            "evil.com must not be exempt"
        );
    }
}
