//! In-memory mock [`PlatformDns`] for unit and integration tests.
//!
//! [`MockPlatform`] maintains a `HashMap<service_name, DnsSetting>` and
//! exposes injectable failure points so the `sentinel/` transaction and
//! watcher tests can drive every error path without touching the OS.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::{DnsSetting, DnsSnapshot, PlatformDns, PlatformError, ServiceDns};

/// Failure injection targets for [`MockPlatform`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Fail {
    /// No injected failures.
    #[default]
    Never,
    /// `snapshot()` returns an error.
    OnSnapshot,
    /// `point_at_self()` returns an error (immediately, before any service is written).
    OnPointAtSelf,
    /// `point_at_self()` applies `n` services successfully then returns an error.
    ///
    /// Used to test the partial-COMMIT rollback path: some adapters are
    /// sinkholed before the error, so the rollback must undo them.
    OnPointAtSelfAfter(usize),
    /// `restore()` returns an error.
    OnRestore,
}

/// In-memory DNS state shared by cloned [`MockPlatform`] handles.
#[derive(Debug, Default)]
struct Inner {
    /// Current DNS setting per service name.
    settings: HashMap<String, DnsSetting>,
    /// Failure injection.
    fail: Fail,
    /// Record of calls made.
    calls: Vec<String>,
}

/// An in-memory [`PlatformDns`] implementation for tests.
///
/// Construct with [`MockPlatform::new`]; clone the handle to share across
/// threads (backed by `Arc<Mutex>`).
#[derive(Debug, Clone)]
pub struct MockPlatform {
    inner: Arc<Mutex<Inner>>,
}

impl MockPlatform {
    /// Create a new mock with the given initial per-service settings.
    pub fn new(initial: impl IntoIterator<Item = (impl Into<String>, DnsSetting)>) -> Self {
        let mut settings = HashMap::new();
        for (k, v) in initial {
            settings.insert(k.into(), v);
        }
        Self {
            inner: Arc::new(Mutex::new(Inner {
                settings,
                ..Default::default()
            })),
        }
    }

    /// Inject a failure for the next operation of the given type.
    pub fn inject_failure(&self, fail: Fail) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.fail = fail;
    }

    /// Return all calls recorded so far (method + args as strings).
    pub fn calls(&self) -> Vec<String> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .calls
            .clone()
    }

    /// Return the current DNS setting for a service (test inspection).
    pub fn get_setting(&self, service: &str) -> Option<DnsSetting> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .settings
            .get(service)
            .cloned()
    }

    /// Directly set the DNS setting for a service (test injection).
    pub fn set_setting(&self, service: &str, setting: DnsSetting) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.settings.insert(service.to_owned(), setting);
    }
}

impl PlatformDns for MockPlatform {
    fn snapshot(&self) -> Result<DnsSnapshot, PlatformError> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.calls.push("snapshot".to_owned());
        if guard.fail == Fail::OnSnapshot {
            guard.fail = Fail::Never;
            return Err(PlatformError::CommandFailed(
                "injected snapshot failure".to_owned(),
            ));
        }
        let services: Vec<ServiceDns> = guard
            .settings
            .iter()
            .map(|(k, v)| ServiceDns {
                service: k.clone(),
                setting: v.clone(),
            })
            .collect();
        Ok(DnsSnapshot {
            v: 1,
            taken_unix_ms: 0,
            services,
            linux_regime: None,
        })
    }

    fn point_at_self(&self, services: &[String]) -> Result<(), PlatformError> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.calls.push(format!("point_at_self({services:?})"));
        // Immediate failure: no services written.
        if guard.fail == Fail::OnPointAtSelf {
            guard.fail = Fail::Never;
            return Err(PlatformError::CommandFailed(
                "injected point_at_self failure".to_owned(),
            ));
        }
        // PANIC-OK: these literals are always valid IP addresses.
        let loopback_v4: std::net::IpAddr = [127, 0, 0, 1].into();
        let loopback_v6: std::net::IpAddr =
            [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1].into();
        // Partial failure: apply N services then error.
        if let Fail::OnPointAtSelfAfter(n) = guard.fail {
            guard.fail = Fail::Never;
            for svc in services.iter().take(n) {
                guard.settings.insert(
                    svc.clone(),
                    DnsSetting::Static {
                        servers: vec![loopback_v4, loopback_v6],
                    },
                );
            }
            return Err(PlatformError::CommandFailed(
                "injected partial point_at_self failure".to_owned(),
            ));
        }
        for svc in services {
            guard.settings.insert(
                svc.clone(),
                DnsSetting::Static {
                    servers: vec![loopback_v4, loopback_v6],
                },
            );
        }
        Ok(())
    }

    fn restore(&self, snap: &DnsSnapshot) -> Result<(), PlatformError> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .calls
            .push(format!("restore({} services)", snap.services.len()));
        if guard.fail == Fail::OnRestore {
            guard.fail = Fail::Never;
            return Err(PlatformError::CommandFailed(
                "injected restore failure".to_owned(),
            ));
        }
        for svc_dns in &snap.services {
            guard
                .settings
                .insert(svc_dns.service.clone(), svc_dns.setting.clone());
        }
        Ok(())
    }

    fn current_setting(&self, service: &str) -> Result<DnsSetting, PlatformError> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.calls.push(format!("current_setting({service})"));
        match guard.settings.get(service) {
            Some(s) => Ok(s.clone()),
            None => Err(PlatformError::CommandFailed(format!(
                "service {service:?} not found in mock"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn mock_snapshot_returns_initial_state() {
        let mock = MockPlatform::new([("Wi-Fi", DnsSetting::Dhcp)]);
        let snap = mock.snapshot().unwrap();
        assert_eq!(snap.services.len(), 1);
        assert_eq!(snap.services[0].service, "Wi-Fi");
        assert_eq!(snap.services[0].setting, DnsSetting::Dhcp);
    }

    #[test]
    fn mock_point_at_self_updates_settings() {
        let mock = MockPlatform::new([("Wi-Fi", DnsSetting::Dhcp)]);
        mock.point_at_self(&["Wi-Fi".to_owned()]).unwrap();
        let setting = mock.get_setting("Wi-Fi").unwrap();
        assert!(matches!(setting, DnsSetting::Static { .. }));
    }

    #[test]
    fn mock_restore_restores_dhcp() {
        let mock = MockPlatform::new([("Wi-Fi", DnsSetting::Dhcp)]);
        mock.point_at_self(&["Wi-Fi".to_owned()]).unwrap();
        let snap = DnsSnapshot {
            v: 1,
            taken_unix_ms: 0,
            services: vec![ServiceDns {
                service: "Wi-Fi".to_owned(),
                setting: DnsSetting::Dhcp,
            }],
            linux_regime: None,
        };
        mock.restore(&snap).unwrap();
        assert_eq!(mock.get_setting("Wi-Fi").unwrap(), DnsSetting::Dhcp);
    }

    #[test]
    fn mock_inject_snapshot_failure() {
        let mock = MockPlatform::new([("Wi-Fi", DnsSetting::Dhcp)]);
        mock.inject_failure(Fail::OnSnapshot);
        assert!(mock.snapshot().is_err());
        // Failure cleared after one use; next call succeeds.
        assert!(mock.snapshot().is_ok());
    }

    #[test]
    fn mock_records_calls() {
        let mock = MockPlatform::new([("Wi-Fi", DnsSetting::Dhcp)]);
        mock.snapshot().unwrap();
        mock.point_at_self(&["Wi-Fi".to_owned()]).unwrap();
        let calls = mock.calls();
        assert_eq!(calls[0], "snapshot");
        assert!(calls[1].starts_with("point_at_self"));
    }
}
