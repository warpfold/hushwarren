//! DNS rebinding protection: reject-set membership and exemption checks.
//!
//! Implements `specs/wp8-transport-privacy.md` §4.
//!
//! ## Design
//!
//! DNS rebinding attacks trick a browser into treating a public hostname as if
//! it were a local server, by returning a private IP from a public name's DNS
//! record.  This module provides a pure function ([`is_rebind_blocked`]) that
//! returns `true` when a response record should be rejected.
//!
//! ## Reject set
//!
//! An address is "private" (and should be rejected for public names) when it
//! falls in:
//! - RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
//! - Loopback: `127.0.0.0/8`, `::1`
//! - Link-local: `169.254.0.0/16`, `fe80::/10`
//! - ULA: `fc00::/7`
//! - Unspecified: `0.0.0.0`, `::`
//!
//! **Explicitly allowed (NOT rejected)**: `100.64.0.0/10` (CGNAT / Tailscale
//! MagicDNS range).
//!
//! ## Exemption precedence (checked before rejection)
//!
//! 1. User allowlist (existing mechanism — allow always wins; caller's
//!    responsibility to check before calling this module).
//! 2. `privacy.rebind_allow` suffixes (caller-supplied slice).
//! 3. Compiled-in exemption for `plex.direct` and its subdomains (documented
//!    Plex LAN-playback pattern — Plex Media Server uses `*.plex.direct` names
//!    that resolve to RFC 1918 addresses for direct LAN play).
//!
//! ## HTTPS/SVCB note
//!
//! This walker inspects **A/AAAA records only**.  `ipv4hint` and `ipv6hint`
//! SvcParams in HTTPS/SVCB records are advisory hints, not answers; rejecting
//! them would break legitimate ECH-capable names.  See spec §5 last bullet.
//!
//! ## Cache behaviour
//!
//! When rebind protection fires, the caller sinkholes the response (NODATA).
//! This verdict is cached by the upstream resolver the same way a CNAME-cloaked
//! verdict is: the next cache hit serves NODATA without re-checking, which is
//! sound because the block is for the *answer content*, not the qname — and the
//! cache TTL will eventually expire and re-run the check.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Built-in compiled-in exemption: `plex.direct` and its subdomains.
///
/// Plex Media Server uses `*.plex.direct` hostnames that resolve to RFC 1918
/// addresses for direct LAN playback.  This is a documented, intentional
/// pattern; users should not need to add it to `rebind_allow` manually.
const PLEX_DIRECT_SUFFIX: &str = "plex.direct";

/// Returns `true` if the IP address is in the rebind reject set.
///
/// Reject set:
/// - RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
/// - Loopback: `127.0.0.0/8`, `::1/128`
/// - Link-local: `169.254.0.0/16`, `fe80::/10`
/// - ULA: `fc00::/7`
/// - Unspecified: `0.0.0.0/32`, `::/128`
///
/// **NOT** in the reject set: `100.64.0.0/10` (CGNAT / Tailscale).
pub fn is_private_addr(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => is_private_v6(v6),
    }
}

/// IPv4 private address check.
///
/// Boundary verification (critical — off-by-one errors in CIDR math are
/// a common source of bugs):
///
/// - `10.0.0.0/8`:   10.0.0.0 – 10.255.255.255  (first octet == 10)
/// - `172.16.0.0/12`: 172.16.0.0 – 172.31.255.255 (first octet 172, second 16..31)
///   - 172.15.255.255 is NOT private; 172.32.0.0 is NOT private.
/// - `192.168.0.0/16`: 192.168.0.0 – 192.168.255.255
/// - `127.0.0.0/8`:  127.0.0.0 – 127.255.255.255
/// - `169.254.0.0/16`: 169.254.0.0 – 169.254.255.255
/// - `0.0.0.0/32`:   exactly 0.0.0.0
/// - `100.64.0.0/10` is EXPLICITLY NOT private (CGNAT / Tailscale).
fn is_private_v4(a: Ipv4Addr) -> bool {
    let octets = a.octets();
    let o0 = octets[0];
    let o1 = octets[1];

    // Unspecified: 0.0.0.0
    if a == Ipv4Addr::UNSPECIFIED {
        return true;
    }
    // Loopback: 127.0.0.0/8
    if o0 == 127 {
        return true;
    }
    // RFC 1918: 10.0.0.0/8
    if o0 == 10 {
        return true;
    }
    // RFC 1918: 172.16.0.0/12  (172.16 – 172.31, second octet 16..=31)
    if o0 == 172 && (16..=31).contains(&o1) {
        return true;
    }
    // RFC 1918: 192.168.0.0/16
    if o0 == 192 && o1 == 168 {
        return true;
    }
    // Link-local: 169.254.0.0/16
    if o0 == 169 && o1 == 254 {
        return true;
    }
    // CGNAT 100.64.0.0/10 is explicitly NOT private — do not add it here.
    false
}

/// IPv6 private address check.
///
/// Boundary verification:
///
/// - `::1/128`:    exactly `::1` (loopback)
/// - `::/128`:     exactly `::` (unspecified)
/// - `fe80::/10`:  fe80:: – febf::  (first 10 bits = 1111 1110 10)
///   - fe80:: is private; febf:: is private; fec0:: is NOT private.
/// - `fc00::/7`:   fc00:: – fdff::  (first 7 bits = 1111 110)
///   - fc00:: is private; fdff:: is private; fe00:: is NOT private.
fn is_private_v6(a: Ipv6Addr) -> bool {
    // Loopback: ::1
    if a == Ipv6Addr::LOCALHOST {
        return true;
    }
    // Unspecified: ::
    if a == Ipv6Addr::UNSPECIFIED {
        return true;
    }

    let segments = a.segments();
    let s0 = segments[0];

    // Link-local: fe80::/10  — first 10 bits are 1111 1110 10
    // s0 in range [0xfe80, 0xfebf] (inclusive)
    // 0xfe80 = 1111 1110 1000 0000
    // 0xfebf = 1111 1110 1011 1111
    if (0xfe80..=0xfebf).contains(&s0) {
        return true;
    }

    // ULA: fc00::/7 — first 7 bits are 1111 110
    // s0 in range [0xfc00, 0xfdff] (inclusive)
    // 0xfc00 = 1111 1100 0000 0000
    // 0xfdff = 1111 1101 1111 1111
    if (0xfc00..=0xfdff).contains(&s0) {
        return true;
    }

    false
}

/// Returns `true` if `qname` is exempt from rebind protection.
///
/// Exemptions are checked in this order (lower number = higher precedence):
/// 1. `rebind_allow_suffixes` — caller supplies the `privacy.rebind_allow`
///    slice from config.  Each entry is a domain suffix; `qname` is exempt
///    if it equals one of them or is a subdomain of one.
/// 2. Built-in `plex.direct` — `plex.direct` itself or any `*.plex.direct`.
///
/// Note: the user allowlist (highest precedence, #0) is the caller's
/// responsibility — the decision engine processes it before calling into
/// this module.
///
/// The `qname` argument is the **original** query name (before any CNAME
/// resolution).  Exemptions apply to the name the user asked for, not to
/// the IP address that came back.
pub fn is_rebind_exempt(qname: &str, rebind_allow_suffixes: &[String]) -> bool {
    // 1. rebind_allow suffixes from config.
    for suffix in rebind_allow_suffixes {
        if domain_matches_suffix(qname, suffix) {
            return true;
        }
    }

    // 2. Built-in: plex.direct (exact) or *.plex.direct (suffix).
    if domain_matches_suffix(qname, PLEX_DIRECT_SUFFIX) {
        return true;
    }

    false
}

/// Returns `true` if `name` equals `suffix` or is a subdomain of `suffix`.
///
/// Comparison is case-insensitive ASCII.  Both sides are assumed to be
/// already canonical (lowercase) in production, but we lowercase for safety.
///
/// Examples:
/// - `"plex.direct"` vs `"plex.direct"` → `true`
/// - `"sub.plex.direct"` vs `"plex.direct"` → `true`
/// - `"notplex.direct"` vs `"plex.direct"` → `false`
/// - `"plexdirect"` vs `"plex.direct"` → `false`
fn domain_matches_suffix(name: &str, suffix: &str) -> bool {
    let name_lc = name.to_ascii_lowercase();
    let suffix_lc = suffix.to_ascii_lowercase();
    if name_lc == suffix_lc {
        return true;
    }
    // Subdomain: name must end with "." + suffix.
    let dot_suffix = format!(".{suffix_lc}");
    name_lc.ends_with(&dot_suffix)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use std::net::IpAddr;

    // ── is_private_v4: RFC 1918 10/8 ─────────────────────────────────────────

    #[test]
    fn rfc1918_10_block_start() {
        assert!(is_private_v4(Ipv4Addr::new(10, 0, 0, 0)));
    }

    #[test]
    fn rfc1918_10_block_end() {
        assert!(is_private_v4(Ipv4Addr::new(10, 255, 255, 255)));
    }

    #[test]
    fn rfc1918_10_block_mid() {
        assert!(is_private_v4(Ipv4Addr::new(10, 1, 2, 3)));
    }

    #[test]
    fn before_10_block_not_private() {
        assert!(!is_private_v4(Ipv4Addr::new(9, 255, 255, 255)));
    }

    #[test]
    fn after_10_block_not_private() {
        // 11.x.x.x is not private (assuming no other range covers it)
        assert!(!is_private_v4(Ipv4Addr::new(11, 0, 0, 0)));
    }

    // ── is_private_v4: RFC 1918 172.16/12 ────────────────────────────────────

    #[test]
    fn rfc1918_172_16_start() {
        assert!(is_private_v4(Ipv4Addr::new(172, 16, 0, 0)));
    }

    #[test]
    fn rfc1918_172_31_end() {
        assert!(is_private_v4(Ipv4Addr::new(172, 31, 255, 255)));
    }

    #[test]
    fn rfc1918_172_15_not_private() {
        // 172.15.255.255 is just below the 172.16/12 block.
        assert!(!is_private_v4(Ipv4Addr::new(172, 15, 255, 255)));
    }

    #[test]
    fn rfc1918_172_32_not_private() {
        // 172.32.0.0 is just above the 172.16/12 block.
        assert!(!is_private_v4(Ipv4Addr::new(172, 32, 0, 0)));
    }

    #[test]
    fn rfc1918_172_20_is_private() {
        assert!(is_private_v4(Ipv4Addr::new(172, 20, 1, 1)));
    }

    // ── is_private_v4: RFC 1918 192.168/16 ───────────────────────────────────

    #[test]
    fn rfc1918_192_168_start() {
        assert!(is_private_v4(Ipv4Addr::new(192, 168, 0, 0)));
    }

    #[test]
    fn rfc1918_192_168_end() {
        assert!(is_private_v4(Ipv4Addr::new(192, 168, 255, 255)));
    }

    #[test]
    fn rfc1918_192_1_not_private() {
        assert!(!is_private_v4(Ipv4Addr::new(192, 1, 0, 0)));
    }

    #[test]
    fn rfc1918_192_169_not_private() {
        assert!(!is_private_v4(Ipv4Addr::new(192, 169, 0, 0)));
    }

    // ── is_private_v4: loopback ────────────────────────────────────────────────

    #[test]
    fn loopback_127_0_0_1() {
        assert!(is_private_v4(Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[test]
    fn loopback_127_0_0_0_start() {
        assert!(is_private_v4(Ipv4Addr::new(127, 0, 0, 0)));
    }

    #[test]
    fn loopback_127_255_255_255_end() {
        assert!(is_private_v4(Ipv4Addr::new(127, 255, 255, 255)));
    }

    #[test]
    fn before_loopback_not_private() {
        // 126.x is not in any private range.
        assert!(!is_private_v4(Ipv4Addr::new(126, 255, 255, 255)));
    }

    // ── is_private_v4: link-local ────────────────────────────────────────────

    #[test]
    fn link_local_169_254_start() {
        assert!(is_private_v4(Ipv4Addr::new(169, 254, 0, 0)));
    }

    #[test]
    fn link_local_169_254_end() {
        assert!(is_private_v4(Ipv4Addr::new(169, 254, 255, 255)));
    }

    #[test]
    fn link_local_169_253_not_private() {
        assert!(!is_private_v4(Ipv4Addr::new(169, 253, 0, 0)));
    }

    #[test]
    fn link_local_169_255_not_private() {
        assert!(!is_private_v4(Ipv4Addr::new(169, 255, 0, 0)));
    }

    // ── is_private_v4: unspecified ───────────────────────────────────────────

    #[test]
    fn unspecified_0_0_0_0() {
        assert!(is_private_v4(Ipv4Addr::new(0, 0, 0, 0)));
    }

    // ── is_private_v4: CGNAT explicitly allowed ───────────────────────────────

    #[test]
    fn cgnat_100_64_0_0_not_private() {
        assert!(!is_private_v4(Ipv4Addr::new(100, 64, 0, 0)));
    }

    #[test]
    fn cgnat_100_64_0_1_not_private() {
        assert!(!is_private_v4(Ipv4Addr::new(100, 64, 0, 1)));
    }

    #[test]
    fn cgnat_100_127_255_255_not_private() {
        // End of CGNAT block: 100.127.255.255
        assert!(!is_private_v4(Ipv4Addr::new(100, 127, 255, 255)));
    }

    #[test]
    fn public_1_1_1_1() {
        assert!(!is_private_v4(Ipv4Addr::new(1, 1, 1, 1)));
    }

    #[test]
    fn public_8_8_8_8() {
        assert!(!is_private_v4(Ipv4Addr::new(8, 8, 8, 8)));
    }

    // ── is_private_v6: loopback / unspecified ────────────────────────────────

    #[test]
    fn v6_loopback() {
        assert!(is_private_v6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn v6_unspecified() {
        assert!(is_private_v6(Ipv6Addr::UNSPECIFIED));
    }

    // ── is_private_v6: link-local fe80::/10 ──────────────────────────────────

    #[test]
    fn v6_link_local_fe80_start() {
        // fe80:: is the start of fe80::/10
        assert!(is_private_v6("fe80::".parse::<Ipv6Addr>().unwrap()));
    }

    #[test]
    fn v6_link_local_febf_end() {
        // febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff is the last address in fe80::/10
        assert!(is_private_v6(
            "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
                .parse::<Ipv6Addr>()
                .unwrap()
        ));
    }

    #[test]
    fn v6_fec0_not_link_local() {
        // fec0:: is just above fe80::/10 — NOT link-local (was site-local, now deprecated)
        assert!(!is_private_v6("fec0::".parse::<Ipv6Addr>().unwrap()));
    }

    #[test]
    fn v6_fe7f_not_link_local() {
        // fe7f:: is just below fe80::/10
        assert!(!is_private_v6("fe7f::".parse::<Ipv6Addr>().unwrap()));
    }

    // ── is_private_v6: ULA fc00::/7 ──────────────────────────────────────────

    #[test]
    fn v6_ula_fc00_start() {
        assert!(is_private_v6("fc00::".parse::<Ipv6Addr>().unwrap()));
    }

    #[test]
    fn v6_ula_fdff_end() {
        assert!(is_private_v6(
            "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
                .parse::<Ipv6Addr>()
                .unwrap()
        ));
    }

    #[test]
    fn v6_fe00_not_ula() {
        // fe00:: is above fc00::/7 — not ULA
        assert!(!is_private_v6("fe00::".parse::<Ipv6Addr>().unwrap()));
    }

    #[test]
    fn v6_fbff_not_ula() {
        // fbff:: is below fc00::/7
        assert!(!is_private_v6("fbff::".parse::<Ipv6Addr>().unwrap()));
    }

    // ── is_private_addr: dispatch ──────────────────────────────────────────────

    #[test]
    fn dispatch_v4_via_ip_addr() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(is_private_addr(ip));
    }

    #[test]
    fn dispatch_v6_via_ip_addr() {
        let ip: IpAddr = "::1".parse().unwrap();
        assert!(is_private_addr(ip));
    }

    #[test]
    fn dispatch_public_v4() {
        let ip: IpAddr = "93.184.216.34".parse().unwrap();
        assert!(!is_private_addr(ip));
    }

    #[test]
    fn dispatch_public_v6() {
        let ip: IpAddr = "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap();
        assert!(!is_private_addr(ip));
    }

    // ── is_rebind_exempt: plex.direct ─────────────────────────────────────────

    #[test]
    fn plex_direct_exact_exempt() {
        assert!(is_rebind_exempt("plex.direct", &[]));
    }

    #[test]
    fn plex_direct_sub_exempt() {
        assert!(is_rebind_exempt("sub.plex.direct", &[]));
    }

    #[test]
    fn plex_direct_deep_sub_exempt() {
        assert!(is_rebind_exempt("a.b.plex.direct", &[]));
    }

    #[test]
    fn notplex_direct_not_exempt() {
        // Must not match: "notplex.direct" does not end with ".plex.direct"
        // and is not equal to "plex.direct".
        assert!(!is_rebind_exempt("notplex.direct", &[]));
    }

    #[test]
    fn plex_direct_uppercase_exempt() {
        // Case insensitive.
        assert!(is_rebind_exempt("Plex.Direct", &[]));
    }

    #[test]
    fn sub_plex_direct_uppercase_exempt() {
        assert!(is_rebind_exempt("MY-DEVICE.Plex.Direct", &[]));
    }

    // ── is_rebind_exempt: rebind_allow suffixes ───────────────────────────────

    #[test]
    fn rebind_allow_exact_suffix() {
        let allow = vec!["corp.internal".to_string()];
        assert!(is_rebind_exempt("corp.internal", &allow));
    }

    #[test]
    fn rebind_allow_subdomain_matches() {
        let allow = vec!["corp.internal".to_string()];
        assert!(is_rebind_exempt("server.corp.internal", &allow));
    }

    #[test]
    fn rebind_allow_no_match() {
        let allow = vec!["corp.internal".to_string()];
        assert!(!is_rebind_exempt("evil.com", &allow));
    }

    #[test]
    fn rebind_allow_not_prefix_attack() {
        // "evilcorp.internal" must NOT match suffix "corp.internal".
        let allow = vec!["corp.internal".to_string()];
        assert!(!is_rebind_exempt("evilcorp.internal", &allow));
    }

    #[test]
    fn rebind_allow_beats_reject() {
        // A name in rebind_allow must be exempt even if the IP would be rejected.
        // (This is a precedence test — the caller checks exemption first.)
        let allow = vec!["corp.internal".to_string()];
        assert!(is_rebind_exempt("server.corp.internal", &allow));
    }

    // ── exemption precedence: rebind_allow > built-in > reject ───────────────

    #[test]
    fn plex_direct_exempt_regardless_of_allow_list() {
        // plex.direct is exempt even with an empty rebind_allow list.
        assert!(is_rebind_exempt("plex.direct", &[]));
    }

    #[test]
    fn non_exempt_name_not_exempt() {
        // A random public domain is not exempt.
        assert!(!is_rebind_exempt("example.com", &[]));
        assert!(!is_rebind_exempt("evil.com", &[]));
    }

    // ── domain_matches_suffix helper ──────────────────────────────────────────

    #[test]
    fn suffix_exact_match() {
        assert!(domain_matches_suffix("example.com", "example.com"));
    }

    #[test]
    fn suffix_subdomain_match() {
        assert!(domain_matches_suffix("sub.example.com", "example.com"));
    }

    #[test]
    fn suffix_no_partial_label_match() {
        // "notexample.com" must NOT match "example.com".
        assert!(!domain_matches_suffix("notexample.com", "example.com"));
    }

    #[test]
    fn suffix_empty_name_no_match() {
        assert!(!domain_matches_suffix("", "example.com"));
    }
}
