//! Windows DNS configuration via `reg.exe` (registry) and `powershell.exe`.
//!
//! Implements `specs/wp11-windows.md` §1 and `docs/os-integration.md` §4
//! (Windows column).
//!
//! ## Mechanism
//!
//! DNS servers are stored in the Windows registry per adapter interface:
//!
//! ```text
//! HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}\NameServer
//! HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\{GUID}\NameServer
//! ```
//!
//! An empty string value means "use DHCP-provided servers"; a comma-separated
//! list of IPs means "use these static servers".
//!
//! We shell out to `reg query` / `reg add` (not `netsh`) because `reg` uses
//! locale-stable key and value names, whereas `netsh` output is localised and
//! will break on non-English Windows installations.  `powershell Get-NetAdapter
//! | ConvertTo-Json` is also locale-stable — JSON field names are invariant
//! regardless of display language.
//!
//! ## Localization hazard
//!
//! **DO NOT** parse `netsh interface ipv4 show dns` output.  The column headers
//! and status strings are translated by the OS locale.  `reg.exe` key/value
//! names and `ConvertTo-Json` field names are NOT translated — they are the safe
//! path.
//!
//! ## Administrator check
//!
//! DNS writes require an Administrator-elevated process.  We detect elevation by
//! running `net session` — it exits 0 for administrators and non-0 for standard
//! users.  If `net session` cannot be run, we optimistically proceed and let the
//! registry write surface the real `ACCESS DENIED`.
//!
//! ## `ipconfig /flushdns`
//!
//! Called after every `point_at_self` and `restore` to flush the OS DNS cache,
//! ensuring the new servers take effect immediately.
//!
//! ## IPv6 (`Tcpip6`)
//!
//! We write to both `Tcpip\Parameters\Interfaces\{GUID}\NameServer` (IPv4) and
//! `Tcpip6\Parameters\Interfaces\{GUID}\NameServer` (IPv6) for each adapter so
//! that both `127.0.0.1` and `::1` are effective regardless of address family.
//! On restore, we apply the inverse from the snapshot.
//!
//! ## GUID in the service name
//!
//! Per `specs/wp11-windows.md` §1 ("GUID can ride in the service string"):
//! The [`ServiceDns`] `service` field encodes both the adapter GUID and friendly
//! name as `"{GUID}|<FriendlyName>"` (GUID first).  Placing the GUID first makes
//! [`decode_service_name`] unambiguous even when the friendly name contains `|`.
//! GUIDs are formatted as `{…}` and can never contain `|`, so the first `|` is
//! always the separator.  This avoids any additive snapshot field and makes the
//! snapshot human-readable.

use std::net::IpAddr;

use tracing::debug;
#[cfg(target_os = "windows")]
use tracing::warn;

use super::DnsSetting;
#[cfg(target_os = "windows")]
use super::{DnsSnapshot, PlatformDns, PlatformError, ServiceDns};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Registry path prefix for IPv4 DNS (append `\{GUID}\NameServer`).
pub const TCPIP_INTERFACES: &str =
    r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
/// Registry path prefix for IPv6 DNS (append `\{GUID}\NameServer`).
pub const TCPIP6_INTERFACES: &str =
    r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces";
/// Registry value name for DNS servers under each interface key.
pub const NAME_SERVER_VALUE: &str = "NameServer";

// ── Parsed adapter from Get-NetAdapter JSON ───────────────────────────────────

/// A network adapter as parsed from `Get-NetAdapter | ConvertTo-Json`.
///
/// Only the fields we need are deserialised; `serde(deny_unknown_fields)` is
/// intentionally NOT used because the PowerShell JSON output varies by OS
/// version and contains many fields we do not care about.
#[derive(Debug, serde::Deserialize)]
pub struct NetAdapter {
    /// The adapter's user-visible name (e.g. "Wi-Fi", "Ethernet").
    #[serde(rename = "Name")]
    pub name: String,
    /// The adapter's interface GUID as a string (e.g. `"{4C4C4544-...}"`).
    #[serde(rename = "InterfaceGuid")]
    pub interface_guid: String,
    /// Connection status — only "Up" adapters are active.
    #[serde(rename = "Status")]
    pub status: String,
    /// Human-readable description (e.g. "WireGuard Tunnel").
    #[serde(rename = "InterfaceDescription")]
    pub interface_description: String,
}

impl NetAdapter {
    /// Returns `true` when the adapter is up (active).
    pub(crate) fn is_up(&self) -> bool {
        self.status.eq_ignore_ascii_case("Up")
    }
}

// ── Pure JSON parser (unit-testable on any host) ──────────────────────────────

/// Parse the output of `Get-NetAdapter | ConvertTo-Json` into a list of active
/// [`NetAdapter`]s.
///
/// ## PowerShell ConvertTo-Json quirk
///
/// When there is only **one** adapter, `ConvertTo-Json` emits a JSON **object**
/// instead of an array.  With multiple adapters it emits a JSON **array**.
/// This function handles both shapes.
///
/// Disabled adapters (`Status != "Up"`) are filtered out.
pub fn parse_net_adapter_json(json: &str) -> Vec<NetAdapter> {
    let json = json.trim();
    if json.is_empty() {
        return Vec::new();
    }

    // Try array first (the common case with multiple adapters).
    let adapters: Vec<NetAdapter> = if json.starts_with('[') {
        serde_json::from_str(json).unwrap_or_else(|e| {
            debug!(error = %e, "Get-NetAdapter JSON array parse failed");
            Vec::new()
        })
    } else if json.starts_with('{') {
        // Single adapter — object, not array.
        match serde_json::from_str::<NetAdapter>(json) {
            Ok(a) => vec![a],
            Err(e) => {
                debug!(error = %e, "Get-NetAdapter JSON object parse failed");
                Vec::new()
            }
        }
    } else {
        debug!("Get-NetAdapter JSON: unexpected first character");
        Vec::new()
    };

    adapters.into_iter().filter(NetAdapter::is_up).collect()
}

/// Encode `guid` and `friendly_name` into the canonical service-name string.
///
/// Format: `"{GUID}|<FriendlyName>"` — GUID comes **first** so that
/// [`decode_service_name`] can split on the *first* `|` and always recover
/// the GUID unambiguously.  GUIDs are formatted as `{…}` and can never
/// contain `|`; friendly names can in principle contain any character
/// (including `|`), so placing the GUID first makes decode unambiguous
/// regardless of the adapter name.
///
/// Snapshot format change: previous versions encoded `"<FriendlyName>|{GUID}"`.
/// No Windows snapshots exist in the wild (Windows support is new), so this
/// is a non-breaking change.
pub fn encode_service_name(friendly_name: &str, guid: &str) -> String {
    format!("{guid}|{friendly_name}")
}

/// Decode the service-name string into `(friendly_name, guid)`.
///
/// Splits on the **first** `|` — the GUID is before the separator, the
/// friendly name (which may contain `|`) is everything after.
///
/// Returns `None` if the string does not contain the `|` separator.
pub fn decode_service_name(service: &str) -> Option<(&str, &str)> {
    // Split on the first '|': left = GUID, right = friendly_name.
    let (guid, friendly_name) = service.split_once('|')?;
    Some((friendly_name, guid))
}

// ── NameServer registry value parser (pure) ───────────────────────────────────

/// Parse the output of `reg query <key> /v NameServer`.
///
/// ## Known output variants
///
/// Value present (static):
/// ```text
/// HKLM\SYSTEM\...\{GUID}
///     NameServer    REG_SZ    127.0.0.1,::1
/// ```
///
/// Value absent or empty (DHCP):
/// ```text
/// ERROR: The system was unable to find the specified registry key or value.
/// ```
/// or just an empty line for the value.
///
/// Returns [`DnsSetting::Dhcp`] when the value is absent or empty.
/// Returns [`DnsSetting::Static`] with the parsed IPs otherwise.
pub fn parse_reg_query_nameserver(output: &str) -> DnsSetting {
    // Look for a line containing "NameServer" followed by "REG_SZ" and a value.
    for line in output.lines() {
        let trimmed = line.trim();
        // Skip error/empty lines.
        if trimmed.is_empty() || trimmed.starts_with("ERROR") {
            continue;
        }
        // Match "    NameServer    REG_SZ    <value>"
        if !trimmed.starts_with("NameServer") {
            continue;
        }
        // Tokenise on runs of whitespace; expect: NameServer REG_SZ <value…>.
        // (`splitn(_, char::is_whitespace)` would NOT collapse consecutive
        // spaces — reg.exe pads columns with several.) The value itself may be
        // comma- or space-separated; joining the remaining tokens with ','
        // normalises both forms.
        let mut tokens = trimmed.split_whitespace();
        let _name = tokens.next(); // "NameServer"
        let _reg_type = tokens.next(); // "REG_SZ"
        let value = tokens.collect::<Vec<_>>().join(",");
        if value.is_empty() {
            return DnsSetting::Dhcp;
        }
        let servers: Vec<IpAddr> = value
            .split(',')
            .filter_map(|s| {
                let ip = s.trim();
                match ip.parse::<IpAddr>() {
                    Ok(a) => Some(a),
                    Err(_) => {
                        debug!(raw = ip, "skipping unparseable IP in NameServer value");
                        None
                    }
                }
            })
            .collect();
        return if servers.is_empty() {
            DnsSetting::Dhcp
        } else {
            DnsSetting::Static { servers }
        };
    }
    DnsSetting::Dhcp
}

/// Parse `whoami /groups` output to check for the local Administrators SID.
///
/// Returns `true` when `S-1-5-32-544` (Administrators) appears in the groups
/// output.  This is locale-stable: SIDs are numeric and do not depend on the
/// display language.
pub fn parse_whoami_groups_for_admin(output: &str) -> bool {
    output.contains("S-1-5-32-544")
}

// ── Pure PowerShell command builders (unit-testable on any host) ──────────────
//
// The actual side effects (running these commands) are Windows-only, but the
// command *strings* are pure functions of their inputs, so they are built here
// and unit-tested on every CI host — including the non-Windows runner where the
// `#[cfg(target_os = "windows")]` callers below are not compiled. This is what
// guards the takeover mechanism against regression (e.g. a revert to the
// stack-unaware `reg add` path that silently bypassed the sinkhole).

/// Build the `Set-DnsClientServerAddress` command that applies `setting` to the
/// adapter with interface index `idx`.
///
/// - [`DnsSetting::Dhcp`] → `-ResetServerAddresses` (clears the static list for
///   both address families, reverting to DHCP).
/// - [`DnsSetting::Static`] → `-ServerAddresses '<ip>',…` (mixed v4/v6 addresses
///   in one call are routed to the correct family by Windows).
///
/// `Set-DnsClientServerAddress` is used instead of a raw `reg add` because it
/// notifies the running TCP/IP stack; a registry write alone updates stored
/// config but leaves the live resolver on the old servers (see [`apply_setting`]).
pub fn build_set_dns_command(idx: u32, setting: &DnsSetting) -> String {
    match setting {
        DnsSetting::Dhcp => {
            format!("Set-DnsClientServerAddress -InterfaceIndex {idx} -ResetServerAddresses")
        }
        DnsSetting::Static { servers } => {
            let list = servers
                .iter()
                .map(|ip| format!("'{ip}'"))
                .collect::<Vec<_>>()
                .join(",");
            format!("Set-DnsClientServerAddress -InterfaceIndex {idx} -ServerAddresses {list}")
        }
    }
}

/// Build the PowerShell query that resolves an adapter's interface index
/// (`ifIndex`) from its GUID. `-eq` is case-insensitive and `-IncludeHidden`
/// catches adapters hidden from the default `Get-NetAdapter` view.
pub fn build_ifindex_query(guid: &str) -> String {
    format!(
        "(Get-NetAdapter -IncludeHidden | Where-Object {{ $_.InterfaceGuid -eq '{guid}' }} \
         | Select-Object -First 1 -ExpandProperty ifIndex)"
    )
}

// ── Side-effecting executor (cfg(windows) only) ───────────────────────────────
//
// Everything below performs I/O (shell-outs to reg.exe / powershell.exe /
// ipconfig.exe) and is gated to `#[cfg(target_os = "windows")]` so the module
// compiles on the macOS dev host (for the pure-logic tests above) without
// including unreachable code.

#[cfg(target_os = "windows")]
use std::process::Command;

/// Check that the current process is running as Administrator.
///
/// Uses `net session`; returns [`PlatformError::NeedsRoot`] if not elevated.
/// If `net session` cannot be run, we optimistically proceed and let the
/// registry write surface the real `ACCESS DENIED`.
#[cfg(target_os = "windows")]
fn check_admin() -> Result<(), PlatformError> {
    let output = Command::new("net")
        .args(["session"])
        .output()
        .map_err(|_| PlatformError::NeedsRoot)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(PlatformError::NeedsRoot)
    }
}

/// Run `powershell.exe -NoProfile -Command <cmd>` and return stdout.
#[cfg(target_os = "windows")]
fn run_powershell(cmd: &str) -> Result<String, PlatformError> {
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", cmd])
        .output()
        .map_err(|e| PlatformError::CommandFailed(format!("failed to spawn powershell: {e}")))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let msg = if stderr.is_empty() { stdout } else { stderr };
        Err(PlatformError::CommandFailed(format!(
            "powershell exited {}: {msg}",
            output.status
        )))
    }
}

/// Run `reg.exe` with the given arguments and return stdout.
///
/// Non-zero exit is treated as success when `allow_error` is true (used for
/// `reg query` which exits non-zero when the value is absent).
#[cfg(target_os = "windows")]
fn run_reg(args: &[&str], allow_error: bool) -> Result<String, PlatformError> {
    let output = Command::new("reg.exe")
        .args(args)
        .output()
        .map_err(|e| PlatformError::CommandFailed(format!("failed to spawn reg.exe: {e}")))?;
    if output.status.success() || allow_error {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let msg = if stderr.is_empty() { stdout } else { stderr };
        Err(PlatformError::CommandFailed(format!(
            "reg.exe {} exited {}: {msg}",
            args.join(" "),
            output.status
        )))
    }
}

/// Read the NameServer registry value for a given GUID and protocol family.
///
/// `proto` is either `"Tcpip"` or `"Tcpip6"`.
#[cfg(target_os = "windows")]
fn reg_read_nameserver(guid: &str, proto: &str) -> DnsSetting {
    let key =
        format!(r"HKLM\SYSTEM\CurrentControlSet\Services\{proto}\Parameters\Interfaces\{guid}");
    match run_reg(&["query", &key, "/v", NAME_SERVER_VALUE], true) {
        Ok(out) => parse_reg_query_nameserver(&out),
        Err(_) => DnsSetting::Dhcp,
    }
}

/// Resolve an adapter's interface index (`ifIndex`) from its GUID.
///
/// The index is numeric and locale-stable. We need it to drive
/// `Set-DnsClientServerAddress`, which notifies the TCP/IP stack (a raw
/// registry write does **not** — see [`apply_setting`]).  `-IncludeHidden`
/// ensures we still find adapters that `Get-NetAdapter`'s default view hides.
#[cfg(target_os = "windows")]
fn ifindex_for_guid(guid: &str) -> Result<u32, PlatformError> {
    let out = run_powershell(&build_ifindex_query(guid))?;
    out.trim().parse::<u32>().map_err(|_| {
        PlatformError::CommandFailed(format!(
            "could not resolve ifIndex for adapter GUID {guid}: got {:?}",
            out.trim()
        ))
    })
}

/// Flush the OS DNS cache with `ipconfig /flushdns`.
#[cfg(target_os = "windows")]
fn flush_dns() {
    match Command::new("ipconfig.exe").arg("/flushdns").output() {
        Ok(out) if out.status.success() => debug!("ipconfig /flushdns: ok"),
        Ok(out) => warn!(
            status = ?out.status,
            "ipconfig /flushdns exited non-zero"
        ),
        Err(e) => warn!(error = %e, "failed to spawn ipconfig /flushdns"),
    }
}

/// Enumerate active adapters via `Get-NetAdapter | ConvertTo-Json`.
#[cfg(target_os = "windows")]
fn list_active_adapters() -> Result<Vec<NetAdapter>, PlatformError> {
    let json = run_powershell("Get-NetAdapter | ConvertTo-Json")?;
    Ok(parse_net_adapter_json(&json))
}

/// Read the current DNS setting for one adapter GUID (from Tcpip, not Tcpip6,
/// as the authoritative source for `DnsSetting`).
#[cfg(target_os = "windows")]
fn adapter_setting(guid: &str) -> DnsSetting {
    reg_read_nameserver(guid, "Tcpip")
}

/// Apply a DNS setting to one adapter (both IPv4 and IPv6 families).
///
/// **Uses `Set-DnsClientServerAddress`, NOT a raw registry write.**  A direct
/// `reg add` to `…\Interfaces\{GUID}\NameServer` updates the *stored* config —
/// so `Get-DnsClientServerAddress` and `reg query` report the new servers — but
/// it does **not** notify the running TCP/IP stack / DNS resolver, which keeps
/// using the previously-active (DHCP-provided) servers.  The net effect on a
/// real machine is a total sinkhole bypass: `Get-DnsClientServerAddress` shows
/// `127.0.0.1`, yet ad domains still resolve through the router.  This was
/// proven live on Windows 11 (`proof/zero-touch-evidence/raw-windows/diag2.txt`:
/// raw-reg → `142.251.39.132`, proper API → `0.0.0.0`).
///
/// `Set-DnsClientServerAddress` writes the same `NameServer` registry values
/// (so the [`reg_read_nameserver`] snapshot path stays correct) *and* notifies
/// the stack so the change takes effect immediately.  Its parameters
/// (`-InterfaceIndex`, `-ServerAddresses`, `-ResetServerAddresses`) are
/// locale-invariant.  Mixed v4/v6 addresses in one call are routed to the
/// correct family automatically.
#[cfg(target_os = "windows")]
fn apply_setting(guid: &str, setting: &DnsSetting) -> Result<(), PlatformError> {
    let idx = ifindex_for_guid(guid)?;
    run_powershell(&build_set_dns_command(idx, setting)).map(|_| ())
}

// ── WindowsDns struct ─────────────────────────────────────────────────────────

/// The Windows implementation of [`PlatformDns`].
///
/// Shells out to `reg.exe` and `powershell.exe` for registry reads/writes and
/// adapter enumeration.  Stateless; all operations execute synchronously.
#[cfg(target_os = "windows")]
pub struct WindowsDns;

#[cfg(target_os = "windows")]
impl PlatformDns for WindowsDns {
    /// Snapshot the current DNS configuration for all active adapters.
    ///
    /// The snapshot `service` field uses the `"<Name>|{GUID}"` encoding so
    /// `restore()` can recover the GUID without an additional adapter lookup.
    fn snapshot(&self) -> Result<DnsSnapshot, PlatformError> {
        let adapters = list_active_adapters()?;
        let services: Vec<ServiceDns> = adapters
            .iter()
            .map(|a| {
                let setting = adapter_setting(&a.interface_guid);
                ServiceDns {
                    service: encode_service_name(&a.name, &a.interface_guid),
                    setting,
                }
            })
            .collect();
        Ok(DnsSnapshot::new(services))
    }

    /// Point all adapters in `services` at `127.0.0.1` (v4) and `::1` (v6).
    ///
    /// Requires Administrator elevation; returns [`PlatformError::NeedsRoot`]
    /// otherwise.
    fn point_at_self(&self, services: &[String]) -> Result<(), PlatformError> {
        check_admin()?;
        let sinkhole = DnsSetting::Static {
            servers: vec![
                IpAddr::from([127, 0, 0, 1]),
                "::1"
                    .parse()
                    .unwrap_or(IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1])),
            ],
        };
        for svc in services {
            if let Some((_name, guid)) = decode_service_name(svc) {
                debug!(service = %svc, "pointing adapter at sinkhole");
                apply_setting(guid, &sinkhole)?;
            } else {
                warn!(service = %svc, "cannot decode GUID from service name — skipping");
            }
        }
        flush_dns();
        Ok(())
    }

    /// Restore each adapter's DNS setting from the snapshot.
    ///
    /// **Continues through ALL adapters on partial failure** — never aborts
    /// half-restored.  Requires Administrator elevation.
    fn restore(&self, snap: &DnsSnapshot) -> Result<(), PlatformError> {
        check_admin()?;
        let mut errors: Vec<String> = Vec::new();
        for svc_dns in &snap.services {
            if let Some((_name, guid)) = decode_service_name(&svc_dns.service) {
                if let Err(e) = apply_setting(guid, &svc_dns.setting) {
                    warn!(service = %svc_dns.service, error = %e, "failed to restore adapter DNS");
                    errors.push(format!("{}: {e}", svc_dns.service));
                }
            } else {
                // Service name does not encode a GUID — skip gracefully.
                debug!(service = %svc_dns.service, "no GUID in service name — skipping restore");
            }
        }
        flush_dns();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(PlatformError::PartialFailure(errors.join("; ")))
        }
    }

    /// Read the current DNS setting for a single `"<Name>|{GUID}"` service.
    fn current_setting(&self, service: &str) -> Result<DnsSetting, PlatformError> {
        match decode_service_name(service) {
            Some((_name, guid)) => Ok(adapter_setting(guid)),
            None => Err(PlatformError::ParseError(format!(
                "cannot decode GUID from service name: {service:?}"
            ))),
        }
    }
}

// ── Unit tests (pure-logic — run on any host including macOS) ─────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    // ── parse_net_adapter_json ────────────────────────────────────────────────

    /// Fixture: two adapters — normal multi-adapter JSON (array).
    const ADAPTER_JSON_ARRAY: &str = r#"[
        {
            "Name": "Wi-Fi",
            "InterfaceGuid": "{4C4C4544-0000-1000-8000-000000000000}",
            "Status": "Up",
            "InterfaceDescription": "Intel(R) Wi-Fi 6 AX200",
            "MacAddress": "AA:BB:CC:DD:EE:FF"
        },
        {
            "Name": "Ethernet",
            "InterfaceGuid": "{4C4C4544-0000-1000-8000-000000000001}",
            "Status": "Up",
            "InterfaceDescription": "Realtek PCIe GbE Family Controller",
            "MacAddress": "00:11:22:33:44:55"
        }
    ]"#;

    /// Fixture: one adapter — PowerShell ConvertTo-Json emits an object, not array.
    const ADAPTER_JSON_SINGLE_OBJECT: &str = r#"{
        "Name": "Wi-Fi",
        "InterfaceGuid": "{4C4C4544-0000-1000-8000-000000000000}",
        "Status": "Up",
        "InterfaceDescription": "Intel(R) Wi-Fi 6 AX200",
        "MacAddress": "AA:BB:CC:DD:EE:FF"
    }"#;

    /// Fixture: adapter with Status "Disconnected" (disabled — must be filtered).
    const ADAPTER_JSON_WITH_DISABLED: &str = r#"[
        {
            "Name": "Wi-Fi",
            "InterfaceGuid": "{4C4C4544-0000-1000-8000-000000000000}",
            "Status": "Up",
            "InterfaceDescription": "Intel(R) Wi-Fi 6 AX200",
            "MacAddress": "AA:BB:CC:DD:EE:FF"
        },
        {
            "Name": "Bluetooth Network Connection",
            "InterfaceGuid": "{4C4C4544-0000-1000-8000-000000000002}",
            "Status": "Disconnected",
            "InterfaceDescription": "Bluetooth Device (Personal Area Network)",
            "MacAddress": "AA:BB:CC:DD:EE:01"
        }
    ]"#;

    /// Fixture: adapter with a localised name (non-ASCII) — must parse cleanly.
    const ADAPTER_JSON_LOCALIZED: &str = r#"{
        "Name": "イーサネット",
        "InterfaceGuid": "{4C4C4544-0000-1000-8000-000000000099}",
        "Status": "Up",
        "InterfaceDescription": "Realtek PCIe GbE Family Controller",
        "MacAddress": "AA:BB:CC:DD:EE:99"
    }"#;

    #[test]
    fn parse_adapter_array_two_adapters() {
        let adapters = parse_net_adapter_json(ADAPTER_JSON_ARRAY);
        assert_eq!(adapters.len(), 2);
        assert_eq!(adapters[0].name, "Wi-Fi");
        assert_eq!(adapters[1].name, "Ethernet");
    }

    #[test]
    fn parse_adapter_single_object_not_array() {
        // PowerShell single-adapter quirk: object, not array.
        let adapters = parse_net_adapter_json(ADAPTER_JSON_SINGLE_OBJECT);
        assert_eq!(adapters.len(), 1);
        assert_eq!(adapters[0].name, "Wi-Fi");
        assert_eq!(
            adapters[0].interface_guid,
            "{4C4C4544-0000-1000-8000-000000000000}"
        );
    }

    #[test]
    fn parse_adapter_filters_disabled_adapters() {
        let adapters = parse_net_adapter_json(ADAPTER_JSON_WITH_DISABLED);
        // Only "Wi-Fi" (Status: "Up") should survive.
        assert_eq!(adapters.len(), 1);
        assert_eq!(adapters[0].name, "Wi-Fi");
    }

    #[test]
    fn parse_adapter_localized_name_parses_cleanly() {
        let adapters = parse_net_adapter_json(ADAPTER_JSON_LOCALIZED);
        assert_eq!(adapters.len(), 1);
        assert_eq!(adapters[0].name, "イーサネット");
    }

    #[test]
    fn parse_adapter_empty_json_returns_empty() {
        let adapters = parse_net_adapter_json("");
        assert!(adapters.is_empty());
    }

    #[test]
    fn parse_adapter_invalid_json_returns_empty() {
        let adapters = parse_net_adapter_json("not json at all");
        assert!(adapters.is_empty());
    }

    // ── parse_reg_query_nameserver ────────────────────────────────────────────

    /// Fixture: `reg query` output when NameServer is set to `127.0.0.1,::1`.
    const REG_SINKHOLE: &str = r"
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4C4C4544-0000-1000-8000-000000000000}
    NameServer    REG_SZ    127.0.0.1,::1
";

    /// Fixture: `reg query` output with a comma-separated static list.
    const REG_STATIC_TWO: &str = r"
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}
    NameServer    REG_SZ    8.8.8.8,8.8.4.4
";

    /// Fixture: NameServer value is empty (DHCP).
    const REG_EMPTY: &str = r"
HKEY_LOCAL_MACHINE\SYSTEM\...\{GUID}
    NameServer    REG_SZ
";

    /// Fixture: the value does not exist at all (error line from reg.exe).
    const REG_NOT_FOUND: &str =
        "ERROR: The system was unable to find the specified registry key or value.";

    /// Fixture: single IPv4 server.
    const REG_SINGLE_IP: &str = r"
HKEY_LOCAL_MACHINE\...\{GUID}
    NameServer    REG_SZ    1.1.1.1
";

    #[test]
    fn parse_reg_sinkhole_setting() {
        let result = parse_reg_query_nameserver(REG_SINKHOLE);
        match result {
            DnsSetting::Static { servers } => {
                assert!(servers.contains(&"127.0.0.1".parse::<IpAddr>().unwrap()));
                assert!(servers.contains(&"::1".parse::<IpAddr>().unwrap()));
            }
            other => panic!("expected Static, got {other:?}"),
        }
    }

    #[test]
    fn parse_reg_static_two_servers() {
        let result = parse_reg_query_nameserver(REG_STATIC_TWO);
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
    fn parse_reg_empty_value_returns_dhcp() {
        let result = parse_reg_query_nameserver(REG_EMPTY);
        assert_eq!(result, DnsSetting::Dhcp);
    }

    #[test]
    fn parse_reg_not_found_returns_dhcp() {
        let result = parse_reg_query_nameserver(REG_NOT_FOUND);
        assert_eq!(result, DnsSetting::Dhcp);
    }

    #[test]
    fn parse_reg_single_ip() {
        let result = parse_reg_query_nameserver(REG_SINGLE_IP);
        match result {
            DnsSetting::Static { servers } => {
                assert_eq!(servers.len(), 1);
                assert_eq!(servers[0], "1.1.1.1".parse::<IpAddr>().unwrap());
            }
            other => panic!("expected Static, got {other:?}"),
        }
    }

    #[test]
    fn parse_reg_empty_string_returns_dhcp() {
        let result = parse_reg_query_nameserver("");
        assert_eq!(result, DnsSetting::Dhcp);
    }

    // ── encode/decode service name ────────────────────────────────────────────

    #[test]
    fn service_name_encode_decode_roundtrip() {
        // New format: GUID-first — "{GUID}|FriendlyName".
        let encoded = encode_service_name("Wi-Fi", "{4C4C4544-0000-1000-8000-000000000000}");
        assert_eq!(encoded, "{4C4C4544-0000-1000-8000-000000000000}|Wi-Fi");
        let (name, guid) = decode_service_name(&encoded).unwrap();
        assert_eq!(name, "Wi-Fi");
        assert_eq!(guid, "{4C4C4544-0000-1000-8000-000000000000}");
    }

    #[test]
    fn service_name_no_separator_returns_none() {
        assert!(decode_service_name("no-separator-here").is_none());
    }

    /// Adapter names that contain '|' are now safe: the GUID is always before
    /// the first '|', so split_once gives us the GUID cleanly and the rest
    /// (including any embedded '|') is the friendly name.
    #[test]
    fn service_name_friendly_name_with_pipe_is_unambiguous() {
        // An adapter named "Tap|Adapter" would previously break decode.
        // With GUID-first encoding the GUID is unambiguously before the first '|'.
        let encoded = encode_service_name("Tap|Adapter", "{GUID-0}");
        // Format: "{GUID-0}|Tap|Adapter"
        assert_eq!(encoded, "{GUID-0}|Tap|Adapter");
        let (name, guid) = decode_service_name(&encoded).unwrap();
        // split_once gives left="{GUID-0}", right="Tap|Adapter"
        assert_eq!(guid, "{GUID-0}");
        assert_eq!(name, "Tap|Adapter");
    }

    #[test]
    fn service_name_simple_adapter() {
        let encoded = encode_service_name("Adapter", "{GUID}");
        let (name, guid) = decode_service_name(&encoded).unwrap();
        assert_eq!(name, "Adapter");
        assert_eq!(guid, "{GUID}");
    }

    // ── snapshot round-trip with GUID-bearing service names ──────────────────

    #[test]
    fn snapshot_with_guid_service_name_round_trips() {
        use crate::platform::{DnsSnapshot, ServiceDns};

        // GUID-first format: "{GUID}|FriendlyName"
        let service_name =
            encode_service_name("Ethernet", "{4C4C4544-0000-1000-8000-000000000001}");
        assert_eq!(
            service_name,
            "{4C4C4544-0000-1000-8000-000000000001}|Ethernet"
        );
        let snap = DnsSnapshot {
            v: 1,
            taken_unix_ms: 1_700_000_000_000,
            services: vec![ServiceDns {
                service: service_name.clone(),
                setting: DnsSetting::Static {
                    servers: vec!["8.8.8.8".parse().unwrap()],
                },
            }],
            linux_regime: None,
        };
        let json = serde_json::to_string(&snap).unwrap();
        let back: crate::platform::DnsSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(back.services[0].service, service_name);
        // Verify decode recovers the correct name and GUID.
        let (name, guid) = decode_service_name(&back.services[0].service).unwrap();
        assert_eq!(name, "Ethernet");
        assert_eq!(guid, "{4C4C4544-0000-1000-8000-000000000001}");
    }

    #[test]
    fn snapshot_dhcp_service_round_trips() {
        use crate::platform::{DnsSnapshot, ServiceDns};

        let snap = DnsSnapshot {
            v: 1,
            taken_unix_ms: 0,
            services: vec![ServiceDns {
                service: encode_service_name("Wi-Fi", "{GUID-0}"),
                setting: DnsSetting::Dhcp,
            }],
            linux_regime: None,
        };
        let json = serde_json::to_string(&snap).unwrap();
        let back: DnsSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(back.services[0].setting, DnsSetting::Dhcp);
        // Verify the service name was stored in GUID-first format.
        assert_eq!(back.services[0].service, "{GUID-0}|Wi-Fi");
    }

    // ── apply-command builders (the real takeover mechanism) ──────────────────
    //
    // These assert the exact PowerShell that `apply_setting` runs. They are the
    // regression guard for the live-proven bug: DNS must be applied via
    // `Set-DnsClientServerAddress` (which notifies the TCP/IP stack), NOT a raw
    // `reg add` (which silently leaves the live resolver on the old servers).

    #[test]
    fn build_set_dns_command_dhcp_resets_servers() {
        // DHCP restore MUST use -ResetServerAddresses (not write an empty list)
        // so the stack is notified to fall back to DHCP.
        let cmd = build_set_dns_command(10, &DnsSetting::Dhcp);
        assert_eq!(
            cmd,
            "Set-DnsClientServerAddress -InterfaceIndex 10 -ResetServerAddresses"
        );
        // It must be the stack-notifying cmdlet, never a raw registry write.
        assert!(!cmd.contains("reg "));
        assert!(!cmd.contains("NameServer"));
    }

    #[test]
    fn build_set_dns_command_sinkhole_sets_v4_and_v6() {
        let setting = DnsSetting::Static {
            servers: vec![
                "127.0.0.1".parse::<IpAddr>().unwrap(),
                "::1".parse::<IpAddr>().unwrap(),
            ],
        };
        let cmd = build_set_dns_command(7, &setting);
        assert_eq!(
            cmd,
            "Set-DnsClientServerAddress -InterfaceIndex 7 -ServerAddresses '127.0.0.1','::1'"
        );
    }

    #[test]
    fn build_set_dns_command_static_quotes_each_server() {
        let setting = DnsSetting::Static {
            servers: vec![
                "8.8.8.8".parse::<IpAddr>().unwrap(),
                "8.8.4.4".parse::<IpAddr>().unwrap(),
            ],
        };
        let cmd = build_set_dns_command(3, &setting);
        assert_eq!(
            cmd,
            "Set-DnsClientServerAddress -InterfaceIndex 3 -ServerAddresses '8.8.8.8','8.8.4.4'"
        );
    }

    #[test]
    fn build_ifindex_query_matches_guid_and_extracts_ifindex() {
        let guid = "{4C4C4544-0000-1000-8000-000000000000}";
        let q = build_ifindex_query(guid);
        // Locale-stable GUID match, hidden adapters included, single ifIndex out.
        assert!(q.contains("-IncludeHidden"));
        assert!(q.contains(&format!("$_.InterfaceGuid -eq '{guid}'")));
        assert!(q.contains("-ExpandProperty ifIndex"));
    }

    // ── admin check string parsing ────────────────────────────────────────────

    #[test]
    fn admin_check_sid_present_returns_true() {
        // Fixture: sample output from `whoami /groups` on an elevated prompt.
        let output = "GROUP INFORMATION\n\
            BUILTIN\\Administrators         Well-known group S-1-5-32-544 Enabled by default\n\
            NT AUTHORITY\\SYSTEM            Well-known group S-1-5-18      Enabled by default";
        assert!(parse_whoami_groups_for_admin(output));
    }

    #[test]
    fn admin_check_sid_absent_returns_false() {
        // Standard user: Administrators group is listed but disabled.
        let output = "GROUP INFORMATION\n\
            NT AUTHORITY\\INTERACTIVE       Well-known group S-1-5-4 Enabled by default\n\
            NT AUTHORITY\\Authenticated Users S-1-5-11 Enabled by default";
        assert!(!parse_whoami_groups_for_admin(output));
    }

    #[test]
    fn admin_check_empty_output_returns_false() {
        assert!(!parse_whoami_groups_for_admin(""));
    }

    // ── TCPIP_INTERFACES / TCPIP6_INTERFACES constants ────────────────────────

    #[test]
    fn registry_key_constants_are_correct() {
        assert!(TCPIP_INTERFACES.contains("Tcpip\\Parameters\\Interfaces"));
        assert!(TCPIP6_INTERFACES.contains("Tcpip6\\Parameters\\Interfaces"));
    }
}
