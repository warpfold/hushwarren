//! macOS DNS configuration via `networksetup(8)`.
//!
//! Implements `specs/wp5-sentinel-macos.md` §1 and `docs/os-integration.md` §2.
//!
//! ## What `networksetup` does to IPv6 when `-setdnsservers` sets only IPv4
//!
//! macOS applies the same DNS server list to both address families when
//! `-setdnsservers` is called.  Passing only `127.0.0.1 ::1` therefore sets
//! both IPv4 and IPv6 resolvers to the sinkhole on the same service record.
//! There is no separate `-setv6dnsservers` flag in the `networksetup` man page.
//! In practice, setting `127.0.0.1 ::1` makes mDNSResponder send queries to
//! `::1:53` for AAAA lookups — so we MUST also listen on `[::1]:53`.
//!
//! Restore to `Empty` (DHCP) restores both v4 and v6 to DHCP-provided servers.
//! Restore to a static list that only had IPv4 entries will remove any previous
//! IPv6 manual config for that service (restoring to the pre-snapshot state
//! exactly — see the snapshot roundtrip contract).
//!
//! ## Root requirement
//!
//! `-setdnsservers` requires root.  If the effective UID is not 0 the operation
//! returns [`PlatformError::NeedsRoot`] immediately without shelling out.

use std::net::IpAddr;
use std::process::Command;

use tracing::{debug, warn};

use super::{DnsSetting, DnsSnapshot, PlatformDns, PlatformError, ServiceDns};

/// The macOS implementation of [`PlatformDns`] that shells out to
/// `/usr/sbin/networksetup`.
///
/// Stateless; all operations execute synchronously in the calling context.
pub struct MacOsDns;

impl PlatformDns for MacOsDns {
    fn snapshot(&self) -> Result<DnsSnapshot, PlatformError> {
        let services = list_active_services()?;
        let mut service_dns = Vec::with_capacity(services.len());
        for svc in &services {
            let setting = get_dns_setting(svc)?;
            service_dns.push(ServiceDns {
                service: svc.clone(),
                setting,
            });
        }
        Ok(DnsSnapshot::new(service_dns))
    }

    fn point_at_self(&self, services: &[String]) -> Result<(), PlatformError> {
        check_root()?;
        for svc in services {
            debug!(service = %svc, "pointing service at sinkhole (127.0.0.1 ::1)");
            run_networksetup(&["-setdnsservers", svc, "127.0.0.1", "::1"])?;
        }
        Ok(())
    }

    fn restore(&self, snap: &DnsSnapshot) -> Result<(), PlatformError> {
        check_root()?;
        let mut errors: Vec<String> = Vec::new();
        for svc_dns in &snap.services {
            let result = restore_service(&svc_dns.service, &svc_dns.setting);
            if let Err(e) = result {
                // Collect all errors; never abort half-restored.
                warn!(service = %svc_dns.service, error = %e, "failed to restore service DNS");
                errors.push(format!("{}: {}", svc_dns.service, e));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(PlatformError::PartialFailure(errors.join("; ")))
        }
    }

    fn current_setting(&self, service: &str) -> Result<DnsSetting, PlatformError> {
        get_dns_setting(service)
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Enumerate active (non-disabled) network services.
///
/// Parses the output of `networksetup -listallnetworkservices`.  The first
/// line is a header; lines starting with `*` are disabled services (skipped).
///
/// # Example real output (captured 2025-12 on this machine)
/// ```text
/// An asterisk (*) denotes that a network service is disabled.
/// USB 10/100/1000 LAN
/// Thunderbolt Bridge
/// Wi-Fi
/// iPhone USB
/// ```
pub(crate) fn parse_list_all_network_services(output: &str) -> Vec<String> {
    output
        .lines()
        .filter(|line| {
            // Skip the header line (contains "asterisk" or starts with "An").
            if line.starts_with("An ") || line.trim().is_empty() {
                return false;
            }
            // Skip disabled services (lines starting with *).
            !line.starts_with('*')
        })
        .map(|line| line.trim().to_owned())
        .collect()
}

/// Parse the output of `networksetup -getdnsservers <service>`.
///
/// # Known output variants (from real `networksetup` on macOS)
/// - `"There aren't any DNS Servers set on Wi-Fi."` → [`DnsSetting::Dhcp`]
/// - One IP address per line → [`DnsSetting::Static`]
///
/// Unparseable IP lines are skipped with a warning; an entirely empty list
/// after filtering returns [`DnsSetting::Dhcp`].
pub(crate) fn parse_getdnsservers(output: &str) -> DnsSetting {
    // The "no servers" sentinel phrase (matches both "aren't" and edge cases).
    if output.contains("aren't any DNS Servers") || output.contains("aren't any DNS Servers") {
        return DnsSetting::Dhcp;
    }

    let servers: Vec<IpAddr> = output
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return None;
            }
            match trimmed.parse::<IpAddr>() {
                Ok(ip) => Some(ip),
                Err(_) => {
                    // Log at debug: non-IP lines appear in error messages.
                    debug!(
                        line = trimmed,
                        "skipping non-IP line in getdnsservers output"
                    );
                    None
                }
            }
        })
        .collect();

    if servers.is_empty() {
        DnsSetting::Dhcp
    } else {
        DnsSetting::Static { servers }
    }
}

/// Shell out to `networksetup` with the given arguments.
///
/// Returns [`PlatformError::CommandFailed`] if the command exits non-zero or
/// cannot be spawned.
fn run_networksetup(args: &[&str]) -> Result<String, PlatformError> {
    let output = Command::new("/usr/sbin/networksetup")
        .args(args)
        .output()
        .map_err(|e| PlatformError::CommandFailed(format!("failed to spawn networksetup: {e}")))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let msg = if stderr.is_empty() { stdout } else { stderr };
        Err(PlatformError::CommandFailed(format!(
            "networksetup {} exited {}: {msg}",
            args.join(" "),
            output.status
        )))
    }
}

/// Get the DNS setting for a single service.
fn get_dns_setting(service: &str) -> Result<DnsSetting, PlatformError> {
    let output = run_networksetup(&["-getdnsservers", service])?;
    Ok(parse_getdnsservers(&output))
}

/// Enumerate active network services by shelling out to `networksetup`.
fn list_active_services() -> Result<Vec<String>, PlatformError> {
    let output = run_networksetup(&["-listallnetworkservices"])?;
    Ok(parse_list_all_network_services(&output))
}

/// Restore a single service's DNS to the setting recorded in the snapshot.
fn restore_service(service: &str, setting: &DnsSetting) -> Result<(), PlatformError> {
    match setting {
        DnsSetting::Dhcp => {
            debug!(service, "restoring service to DHCP");
            run_networksetup(&["-setdnsservers", service, "Empty"])?;
        }
        DnsSetting::Static { servers } => {
            let server_strs: Vec<String> = servers.iter().map(|ip| ip.to_string()).collect();
            let mut args = vec!["-setdnsservers", service];
            let server_refs: Vec<&str> = server_strs.iter().map(String::as_str).collect();
            args.extend_from_slice(&server_refs);
            debug!(service, servers = ?server_strs, "restoring service to static DNS");
            run_networksetup(&args)?;
        }
    }
    Ok(())
}

/// Check that the current process is running as root (UID 0).
///
/// Shells out to `/usr/bin/id -u`; parses the result.  Returns
/// [`PlatformError::NeedsRoot`] if not root.  If `id` cannot be run, we
/// optimistically proceed and let `networksetup` surface the real error.
fn check_root() -> Result<(), PlatformError> {
    match Command::new("/usr/bin/id").arg("-u").output() {
        Ok(out) if out.status.success() => {
            let uid_str = String::from_utf8_lossy(&out.stdout);
            let uid: u32 = uid_str.trim().parse().unwrap_or(1);
            if uid == 0 {
                Ok(())
            } else {
                Err(PlatformError::NeedsRoot)
            }
        }
        // If we can't determine UID, optimistically proceed; networksetup
        // will return an error if root is truly required.
        _ => Ok(()),
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    // These tests feed captured real networksetup output as fixture strings.

    // ── parse_list_all_network_services ───────────────────────────────────────

    /// Fixture: real output from this machine (captured 2025-12).
    const LIST_ALL_SERVICES_REAL: &str = "\
An asterisk (*) denotes that a network service is disabled.
USB 10/100/1000 LAN
Thunderbolt Bridge
Wi-Fi
iPhone USB";

    /// Fixture: output with a disabled service.
    const LIST_ALL_SERVICES_WITH_DISABLED: &str = "\
An asterisk (*) denotes that a network service is disabled.
Wi-Fi
*Thunderbolt Bridge
Ethernet";

    #[test]
    fn parse_list_services_real_fixture() {
        let result = parse_list_all_network_services(LIST_ALL_SERVICES_REAL);
        assert_eq!(
            result,
            vec![
                "USB 10/100/1000 LAN",
                "Thunderbolt Bridge",
                "Wi-Fi",
                "iPhone USB",
            ]
        );
    }

    #[test]
    fn parse_list_services_skips_disabled() {
        let result = parse_list_all_network_services(LIST_ALL_SERVICES_WITH_DISABLED);
        assert_eq!(result, vec!["Wi-Fi", "Ethernet"]);
        assert!(!result.contains(&"*Thunderbolt Bridge".to_owned()));
    }

    #[test]
    fn parse_list_services_empty_input() {
        let result = parse_list_all_network_services("");
        assert!(result.is_empty());
    }

    #[test]
    fn parse_list_services_all_disabled() {
        let input = "\
An asterisk (*) denotes that a network service is disabled.
*Wi-Fi
*Ethernet";
        let result = parse_list_all_network_services(input);
        assert!(result.is_empty());
    }

    // ── parse_getdnsservers ───────────────────────────────────────────────────

    /// Fixture: real DHCP output from Wi-Fi on this machine (captured 2025-12).
    const DNS_DHCP_WIFI: &str = "There aren't any DNS Servers set on Wi-Fi.";

    /// Fixture: DHCP on Thunderbolt Bridge.
    const DNS_DHCP_BRIDGE: &str = "There aren't any DNS Servers set on Thunderbolt Bridge.";

    /// Fixture: static DNS with two entries.
    const DNS_STATIC_TWO: &str = "8.8.8.8\n8.8.4.4\n";

    /// Fixture: static DNS with single entry.
    const DNS_STATIC_ONE: &str = "1.1.1.1\n";

    /// Fixture: our own sinkhole setting.
    const DNS_SINKHOLE: &str = "127.0.0.1\n::1\n";

    #[test]
    fn parse_dns_dhcp_wifi_fixture() {
        let result = parse_getdnsservers(DNS_DHCP_WIFI);
        assert_eq!(result, DnsSetting::Dhcp);
    }

    #[test]
    fn parse_dns_dhcp_bridge_fixture() {
        let result = parse_getdnsservers(DNS_DHCP_BRIDGE);
        assert_eq!(result, DnsSetting::Dhcp);
    }

    #[test]
    fn parse_dns_static_two_servers() {
        let result = parse_getdnsservers(DNS_STATIC_TWO);
        match result {
            DnsSetting::Static { servers } => {
                assert_eq!(servers.len(), 2);
                assert!(servers.contains(&"8.8.8.8".parse::<IpAddr>().unwrap()));
                assert!(servers.contains(&"8.8.4.4".parse::<IpAddr>().unwrap()));
            }
            other => panic!("expected Static, got {other:?}"),
        }
    }

    #[test]
    fn parse_dns_static_one_server() {
        let result = parse_getdnsservers(DNS_STATIC_ONE);
        match result {
            DnsSetting::Static { servers } => {
                assert_eq!(servers.len(), 1);
                assert_eq!(servers[0], "1.1.1.1".parse::<IpAddr>().unwrap());
            }
            other => panic!("expected Static, got {other:?}"),
        }
    }

    #[test]
    fn parse_dns_sinkhole_setting() {
        let result = parse_getdnsservers(DNS_SINKHOLE);
        match result {
            DnsSetting::Static { servers } => {
                assert!(servers.contains(&"127.0.0.1".parse::<IpAddr>().unwrap()));
                assert!(servers.contains(&"::1".parse::<IpAddr>().unwrap()));
            }
            other => panic!("expected Static, got {other:?}"),
        }
    }

    #[test]
    fn parse_dns_empty_output_returns_dhcp() {
        let result = parse_getdnsservers("");
        assert_eq!(result, DnsSetting::Dhcp);
    }

    #[test]
    fn parse_dns_non_ip_lines_skipped() {
        // Simulate an error-ish output with garbage mixed in.
        let output = "Some error message\n8.8.8.8\n";
        let result = parse_getdnsservers(output);
        // Should skip the non-IP line and parse 8.8.8.8.
        match result {
            DnsSetting::Static { servers } => {
                assert_eq!(servers, vec!["8.8.8.8".parse::<IpAddr>().unwrap()]);
            }
            other => panic!("expected Static, got {other:?}"),
        }
    }

    #[test]
    fn parse_dns_all_non_ip_lines_returns_dhcp() {
        let output = "Error: no such service\nCannot get DNS\n";
        let result = parse_getdnsservers(output);
        assert_eq!(result, DnsSetting::Dhcp);
    }
}
