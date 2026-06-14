//! Platform-specific DNS configuration primitives.
//!
//! Implements `docs/os-integration.md` §1–§2 (the macOS column) and
//! `specs/wp5-sentinel-macos.md` §1.
//!
//! The [`PlatformDns`] trait abstracts per-OS DNS read/write.  All OS-specific
//! code lives in the sub-modules behind `cfg` — everything else compiles on
//! every target.
//!
//! ## Snapshot schema
//!
//! [`DnsSnapshot`] is persisted as JSON (schema version `"v":1`) with an
//! atomic write (tmp + rename + fsync) to `state_dir/dns-snapshot.json`
//! **before** any COMMIT.  This ensures a power cut mid-takeover is
//! recoverable at next boot.

use std::net::IpAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod stub;

// `linux` is always compiled so its pure-logic functions and unit tests run on
// every host (including this macOS dev machine).  The [`linux::LinuxDns`]
// struct and its [`PlatformDns`] impl are gated to `#[cfg(target_os = "linux")]`
// inside the module itself.
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

// `windows` is always compiled (like `linux`) so its pure-logic functions and
// unit tests run on every host (including this macOS dev machine).  The
// [`windows::WindowsDns`] struct and its [`PlatformDns`] impl are gated to
// `#[cfg(target_os = "windows")]` inside the module itself.
pub mod windows;

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub mod unsupported;

// ── Types ─────────────────────────────────────────────────────────────────────

/// How DNS is configured for a single network service.
///
/// `Dhcp` means "no manually-set servers; use whatever DHCP provides."
/// `Static` means "these explicit addresses are set."
///
/// The sinkhole state is `Static(vec![127.0.0.1, ::1])`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum DnsSetting {
    /// No manually-set DNS servers; DHCP-provided resolvers are active.
    Dhcp,
    /// One or more explicit IP addresses are set.
    Static {
        /// The explicit DNS server addresses.
        servers: Vec<IpAddr>,
    },
}

/// DNS configuration for a single named network service (e.g. "Wi-Fi").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceDns {
    /// The network service name as reported by `networksetup -listallnetworkservices`.
    pub service: String,
    /// The current DNS configuration for this service.
    pub setting: DnsSetting,
}

/// The resolver management regime on Linux, carried in [`DnsSnapshot`].
///
/// Defined on all platforms so that macOS/Windows binaries can parse Linux
/// snapshot JSON without compile errors or unknown-field failures.
///
/// On non-Linux targets this type is never constructed by production code, but
/// it must exist for `serde` to round-trip JSON portably.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinuxRegime {
    /// systemd-resolved owns the stub resolver (127.0.0.53).
    SystemdResolved,
    /// NetworkManager manages `resolv.conf` without systemd-resolved.
    NetworkManager,
    /// resolvconf/openresolv owns the file.
    ///
    /// **Deviation:** hushwarren uses atomic-replace rather than resolvconf
    /// provider registration.  See `docs/os-integration.md` §3 and
    /// `platform/linux.rs` module doc for rationale.
    Resolvconf,
    /// Plain `/etc/resolv.conf` — no resolver manager detected.
    Plain,
}

/// A full snapshot of the system's DNS configuration across all active services.
///
/// Persisted to `state_dir/dns-snapshot.json` (schema `"v":1`) with
/// atomic+fsync **before** any COMMIT.
///
/// ## Schema forward-compatibility
///
/// The `linux_regime` field is additive and optional (`#[serde(default)]`).
/// Existing macOS snapshots (field absent in JSON) deserialise with
/// `linux_regime = None`.  New Linux snapshots carry the field.  A macOS
/// binary parsing a Linux snapshot simply ignores the field value and
/// produces `None` (serde `default`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsSnapshot {
    /// Schema version — always `1` for this implementation.
    pub v: u32,
    /// Unix timestamp (milliseconds since epoch) when this snapshot was taken.
    pub taken_unix_ms: u64,
    /// Per-service DNS configuration at snapshot time.
    pub services: Vec<ServiceDns>,
    /// Linux resolver regime at snapshot time.
    ///
    /// `None` for macOS snapshots or any snapshot predating this field.
    /// `restore()` re-detects the regime when the field is absent
    /// (forward-compat guard).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linux_regime: Option<LinuxRegime>,
}

impl DnsSnapshot {
    /// Create a new snapshot with the current wall-clock time.
    pub fn new(services: Vec<ServiceDns>) -> Self {
        Self {
            v: 1,
            taken_unix_ms: unix_ms_now(),
            services,
            linux_regime: None,
        }
    }

    /// Returns `true` if every active service points at the loopback sinkhole.
    pub fn all_pointing_at_self(&self) -> bool {
        self.services
            .iter()
            .all(|s| is_pointing_at_self(&s.setting))
    }
}

/// Returns `true` when `setting` points at the loopback sinkhole (`127.0.0.1` or `::1`).
pub fn is_pointing_at_self(setting: &DnsSetting) -> bool {
    match setting {
        DnsSetting::Static { servers } => servers.iter().any(|ip| {
            *ip == IpAddr::from([127, 0, 0, 1]) || *ip == IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1])
        }),
        DnsSetting::Dhcp => false,
    }
}

// ── Errors ────────────────────────────────────────────────────────────────────

/// Errors produced by the platform DNS layer.
#[derive(Debug, Error)]
pub enum PlatformError {
    /// The operation requires root privileges.
    #[error("DNS write requires root privileges; please run as root")]
    NeedsRoot,

    /// `networksetup` (or equivalent) returned an unexpected error.
    #[error("networksetup error: {0}")]
    CommandFailed(String),

    /// The platform is not supported for DNS manipulation.
    #[error("DNS takeover is not supported on this platform")]
    Unsupported,

    /// Failed to parse `networksetup` output.
    #[error("failed to parse networksetup output: {0}")]
    ParseError(String),

    /// Multiple services failed during a `restore()`.  The full list of
    /// errors is concatenated in the message.
    #[error("restore failed for some services: {0}")]
    PartialFailure(String),
}

// ── Trait ─────────────────────────────────────────────────────────────────────

/// Abstraction over OS-level DNS read/write operations.
///
/// Implementations live in sub-modules gated by `cfg(target_os = ...)`.
/// The state machine and transaction code in `sentinel/takeover.rs` work
/// exclusively through this trait — they are OS-agnostic and fully testable
/// with [`stub::MockPlatform`].
pub trait PlatformDns: Send + Sync + 'static {
    /// Return the current per-service DNS configuration.
    ///
    /// Used for both SNAPSHOT (before COMMIT) and drift detection (watcher poll).
    fn snapshot(&self) -> Result<DnsSnapshot, PlatformError>;

    /// Point every service in `services` at `127.0.0.1` and `::1`.
    ///
    /// # macOS
    /// Calls `networksetup -setdnsservers <svc> 127.0.0.1 ::1` for each name.
    fn point_at_self(&self, services: &[String]) -> Result<(), PlatformError>;

    /// Restore the DNS configuration recorded in `snap`.
    ///
    /// **Must be idempotent** and **must continue through ALL services** on
    /// partial failure — never abort half-restored.
    fn restore(&self, snap: &DnsSnapshot) -> Result<(), PlatformError>;

    /// Read the current DNS setting for a single service by name.
    ///
    /// Used by the watcher for efficient drift detection: poll each service
    /// individually rather than re-snapshotting the whole system.
    fn current_setting(&self, service: &str) -> Result<DnsSetting, PlatformError>;
}

// ── Snapshot persistence ──────────────────────────────────────────────────────

/// Persist `snap` to `state_dir/dns-snapshot.json` atomically (tmp + rename)
/// with an fsync on the written file to guarantee durability before COMMIT.
///
/// The schema version `"v":1` is embedded in [`DnsSnapshot`].
pub fn persist_snapshot(state_dir: &Path, snap: &DnsSnapshot) -> Result<(), std::io::Error> {
    use std::fs::File;
    use std::io::Write;

    let path = state_dir.join("dns-snapshot.json");
    let tmp = state_dir.join(".dns-snapshot.json.tmp");

    let json = serde_json::to_string_pretty(snap)
        .unwrap_or_else(|_| r#"{"v":1,"taken_unix_ms":0,"services":[]}"#.to_owned());

    let mut f = File::create(&tmp)?;
    f.write_all(json.as_bytes())?;
    f.sync_all()?; // fsync before rename
    drop(f);

    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// Load `state_dir/dns-snapshot.json`.
///
/// Returns `None` if the file does not exist.
/// Returns an error if the file exists but is corrupt.
pub fn load_snapshot(state_dir: &Path) -> Result<Option<DnsSnapshot>, std::io::Error> {
    let path = state_dir.join("dns-snapshot.json");
    match std::fs::read_to_string(&path) {
        Ok(s) => {
            let snap: DnsSnapshot = serde_json::from_str(&s).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("dns-snapshot.json parse error: {e}"),
                )
            })?;
            Ok(Some(snap))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Remove `state_dir/dns-snapshot.json` after a successful restore.
///
/// Best-effort; logs a warning on failure.
pub fn remove_snapshot(state_dir: &Path) {
    let path = state_dir.join("dns-snapshot.json");
    if let Err(e) = std::fs::remove_file(&path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(error = %e, "failed to remove dns-snapshot.json after restore");
        }
    }
}

// ── Platform constructor ──────────────────────────────────────────────────────

/// Return the platform-native [`PlatformDns`] implementation.
///
/// - macOS: [`macos::MacOsDns`]
/// - Linux: [`linux::LinuxDns`]
/// - Windows: [`windows::WindowsDns`]
/// - Other: [`unsupported::UnsupportedDns`]
pub fn native() -> Box<dyn PlatformDns> {
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacOsDns)
    }
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxDns)
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(windows::WindowsDns)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Box::new(unsupported::UnsupportedDns)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn unix_ms_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use tempfile::TempDir;

    // ── DnsSnapshot round-trip ────────────────────────────────────────────────

    #[test]
    fn snapshot_json_round_trip_dhcp() {
        let snap = DnsSnapshot {
            v: 1,
            taken_unix_ms: 1_700_000_000_000,
            services: vec![ServiceDns {
                service: "Wi-Fi".to_owned(),
                setting: DnsSetting::Dhcp,
            }],
            linux_regime: None,
        };
        let json = serde_json::to_string(&snap).unwrap();
        let back: DnsSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, back);
    }

    #[test]
    fn snapshot_json_round_trip_static() {
        let snap = DnsSnapshot {
            v: 1,
            taken_unix_ms: 1_700_000_000_000,
            services: vec![ServiceDns {
                service: "Ethernet".to_owned(),
                setting: DnsSetting::Static {
                    servers: vec!["8.8.8.8".parse().unwrap(), "8.8.4.4".parse().unwrap()],
                },
            }],
            linux_regime: None,
        };
        let json = serde_json::to_string(&snap).unwrap();
        let back: DnsSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, back);
    }

    #[test]
    fn snapshot_schema_version_is_1() {
        let snap = DnsSnapshot::new(vec![]);
        assert_eq!(snap.v, 1);
    }

    // ── Persist / load / remove ───────────────────────────────────────────────

    #[test]
    fn persist_and_load_roundtrip() {
        let dir = TempDir::new().unwrap();
        let snap = DnsSnapshot {
            v: 1,
            taken_unix_ms: 9999,
            services: vec![ServiceDns {
                service: "Wi-Fi".to_owned(),
                setting: DnsSetting::Dhcp,
            }],
            linux_regime: None,
        };
        persist_snapshot(dir.path(), &snap).unwrap();
        let loaded = load_snapshot(dir.path()).unwrap().unwrap();
        assert_eq!(snap, loaded);
    }

    #[test]
    fn load_snapshot_missing_returns_none() {
        let dir = TempDir::new().unwrap();
        let result = load_snapshot(dir.path()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn remove_snapshot_missing_is_noop() {
        let dir = TempDir::new().unwrap();
        // Should not panic or error.
        remove_snapshot(dir.path());
    }

    #[test]
    fn remove_snapshot_removes_file() {
        let dir = TempDir::new().unwrap();
        let snap = DnsSnapshot::new(vec![]);
        persist_snapshot(dir.path(), &snap).unwrap();
        assert!(dir.path().join("dns-snapshot.json").exists());
        remove_snapshot(dir.path());
        assert!(!dir.path().join("dns-snapshot.json").exists());
    }

    // ── is_pointing_at_self ───────────────────────────────────────────────────

    #[test]
    fn dhcp_is_not_self() {
        assert!(!is_pointing_at_self(&DnsSetting::Dhcp));
    }

    #[test]
    fn static_loopback_v4_is_self() {
        let setting = DnsSetting::Static {
            servers: vec!["127.0.0.1".parse().unwrap()],
        };
        assert!(is_pointing_at_self(&setting));
    }

    #[test]
    fn static_loopback_v6_is_self() {
        let setting = DnsSetting::Static {
            servers: vec!["::1".parse().unwrap()],
        };
        assert!(is_pointing_at_self(&setting));
    }

    #[test]
    fn static_external_is_not_self() {
        let setting = DnsSetting::Static {
            servers: vec!["8.8.8.8".parse().unwrap()],
        };
        assert!(!is_pointing_at_self(&setting));
    }

    #[test]
    fn all_pointing_at_self_mixed() {
        let snap = DnsSnapshot {
            v: 1,
            taken_unix_ms: 0,
            services: vec![
                ServiceDns {
                    service: "Wi-Fi".to_owned(),
                    setting: DnsSetting::Static {
                        servers: vec!["127.0.0.1".parse().unwrap()],
                    },
                },
                ServiceDns {
                    service: "Ethernet".to_owned(),
                    setting: DnsSetting::Dhcp,
                },
            ],
            linux_regime: None,
        };
        assert!(!snap.all_pointing_at_self());
    }

    #[test]
    fn all_pointing_at_self_all_loopback() {
        let snap = DnsSnapshot {
            v: 1,
            taken_unix_ms: 0,
            services: vec![ServiceDns {
                service: "Wi-Fi".to_owned(),
                setting: DnsSetting::Static {
                    servers: vec!["127.0.0.1".parse().unwrap(), "::1".parse().unwrap()],
                },
            }],
            linux_regime: None,
        };
        assert!(snap.all_pointing_at_self());
    }
}
