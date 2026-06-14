//! Stub [`PlatformDns`] for non-macOS targets.
//!
//! Returns [`PlatformError::Unsupported`] for every operation.
//! Linux and Windows implementations are P2.

use super::{DnsSetting, DnsSnapshot, PlatformDns, PlatformError};

/// A platform-DNS stub that always returns [`PlatformError::Unsupported`].
///
/// Used on Linux and Windows until those platform implementations land (P2).
pub struct UnsupportedDns;

impl PlatformDns for UnsupportedDns {
    fn snapshot(&self) -> Result<DnsSnapshot, PlatformError> {
        Err(PlatformError::Unsupported)
    }

    fn point_at_self(&self, _services: &[String]) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported)
    }

    fn restore(&self, _snap: &DnsSnapshot) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported)
    }

    fn current_setting(&self, _service: &str) -> Result<DnsSetting, PlatformError> {
        Err(PlatformError::Unsupported)
    }
}
