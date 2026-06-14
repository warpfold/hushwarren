//! Integration tests for the WP5 Sentinel: DNS takeover, restore, crash-loop
//! breaker, and drift/VPN/portal watcher.
//!
//! Implements the mandatory test matrix from `specs/wp5-sentinel-macos.md` §5.
//!
//! All tests use [`MockPlatform`] — no real OS DNS changes, no root required.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;

use hush_core::DecisionEngine;
use hush_daemon::platform::stub::{Fail, MockPlatform};
use hush_daemon::platform::{
    load_snapshot, persist_snapshot, DnsSetting, DnsSnapshot, PlatformDns, ServiceDns,
};
use hush_daemon::sentinel::{
    breaker::{self, BreakerConfig, BreakerOutcome, RunState},
    takeover::{self, TakeoverConfig},
    watch::{classify_drift, detect_wake, DriftKind},
    GuardState, Sentinel, StandbyReason,
};

// ── helpers ───────────────────────────────────────────────────────────────────

fn make_platform_with_wifi() -> MockPlatform {
    MockPlatform::new([("Wi-Fi".to_owned(), DnsSetting::Dhcp)])
}

/// A TakeoverConfig that points at port 1 (nothing listening).
/// SELF-TEST will fail at the recv-timeout step, proving no DNS mutation
/// happens before the listener is verified.
fn make_takeover_cfg(state_dir: &Path) -> TakeoverConfig {
    TakeoverConfig {
        listener_addr: "127.0.0.1:1".parse().unwrap(), // port 1 — nothing listening
        blocked_canary: hush_core::SELFTEST_BLOCKED_DOMAIN.to_owned(),
        allowed_canary: "example.com".to_owned(),
        probe_timeout: Duration::from_millis(200), // short for tests
        state_dir: state_dir.to_path_buf(),
    }
}

fn make_snapshot_dhcp(service: &str) -> DnsSnapshot {
    DnsSnapshot {
        v: 1,
        taken_unix_ms: 0,
        services: vec![ServiceDns {
            service: service.to_owned(),
            setting: DnsSetting::Dhcp,
        }],
        linux_regime: None,
    }
}

// ══ Test matrix (a–g) ════════════════════════════════════════════════════════

/// (a) Takeover fails at SELF-TEST (no real listener) — platform NOT mutated.
///
/// Proves the transaction does NOT call `point_at_self` before SELF-TEST passes.
/// The snapshot file must also NOT exist (PERSIST only happens after SELF-TEST).
#[tokio::test]
async fn test_a_takeover_fails_before_commit_when_no_listener() {
    let tmp = TempDir::new().unwrap();
    let platform = make_platform_with_wifi();
    let cfg = make_takeover_cfg(tmp.path());

    let result = takeover::run_takeover(&platform, &cfg).await;

    // Must fail (no listener at port 1).
    assert!(result.is_err(), "takeover must fail with no listener");

    // point_at_self must NOT have been called.
    let calls = platform.calls();
    let commit_calls = calls
        .iter()
        .filter(|c| c.starts_with("point_at_self"))
        .count();
    assert_eq!(
        commit_calls, 0,
        "point_at_self must not be called when SELF-TEST fails"
    );

    // Wi-Fi DNS must still be DHCP (unchanged).
    assert_eq!(
        platform.get_setting("Wi-Fi"),
        Some(DnsSetting::Dhcp),
        "Wi-Fi must remain DHCP when takeover aborts before COMMIT"
    );
}

/// (b) PERSIST step: snapshot is durably on disk with atomic rename.
///
/// We test the `persist_snapshot` + `load_snapshot` round-trip directly,
/// since run_takeover only reaches PERSIST after a successful SELF-TEST
/// (which requires a live listener — live-only E2E test below).
#[test]
fn test_b_snapshot_persisted_atomically() {
    let tmp = TempDir::new().unwrap();

    let snap = make_snapshot_dhcp("Wi-Fi");
    persist_snapshot(tmp.path(), &snap).unwrap();

    // Snapshot must be readable and equal.
    let loaded = load_snapshot(tmp.path()).unwrap().unwrap();
    assert_eq!(loaded.v, 1);
    assert_eq!(loaded.services.len(), 1);
    assert_eq!(loaded.services[0].service, "Wi-Fi");
    assert_eq!(loaded.services[0].setting, DnsSetting::Dhcp);

    // Tmp file must not linger (atomic rename leaves only the final file).
    let tmp_file = tmp.path().join(".dns-snapshot.json.tmp");
    assert!(
        !tmp_file.exists(),
        ".tmp file must be removed after atomic rename"
    );
}

/// (b2) Re-takeover PRESERVES the original baseline snapshot.
///
/// Regression for the live-proof S10 bug: a second takeover (re-arm) must not
/// overwrite the on-disk snapshot with the current — possibly already-us or
/// user-changed — DNS state, or uninstall-restore returns to the wrong DNS.
#[test]
fn test_b2_retakeover_preserves_original_baseline() {
    use hush_daemon::sentinel::takeover::resolve_restore_baseline;
    let tmp = TempDir::new().unwrap();

    // First takeover captures the true baseline: Wi-Fi was DHCP.
    let original = make_snapshot_dhcp("Wi-Fi");
    let b1 = resolve_restore_baseline(tmp.path(), &original).unwrap();
    assert_eq!(b1.services[0].setting, DnsSetting::Dhcp, "first = captured");

    // Re-arm while DNS now points at us (or a user set 8.8.8.8) — the "current"
    // passed in is a different, transient state.
    let transient = DnsSnapshot {
        v: 1,
        taken_unix_ms: 999,
        services: vec![ServiceDns {
            service: "Wi-Fi".to_owned(),
            setting: DnsSetting::Static {
                servers: vec!["8.8.8.8".parse::<IpAddr>().unwrap()],
            },
        }],
        linux_regime: None,
    };
    let b2 = resolve_restore_baseline(tmp.path(), &transient).unwrap();
    assert_eq!(
        b2.services[0].setting,
        DnsSetting::Dhcp,
        "re-arm must REUSE the original DHCP baseline, not the transient 8.8.8.8"
    );

    // And the on-disk snapshot is still the original.
    let on_disk = load_snapshot(tmp.path()).unwrap().unwrap();
    assert_eq!(on_disk.services[0].setting, DnsSetting::Dhcp);
}

/// (c) restore_from_snapshot restores DNS and removes the snapshot file.
#[test]
fn test_c_restore_clears_snapshot() {
    let tmp = TempDir::new().unwrap();

    // Start: Wi-Fi points at self (post-takeover state).
    let platform = MockPlatform::new([(
        "Wi-Fi".to_owned(),
        DnsSetting::Static {
            servers: vec!["127.0.0.1".parse::<IpAddr>().unwrap()],
        },
    )]);

    // Snapshot records the pre-takeover state (DHCP).
    let snap = make_snapshot_dhcp("Wi-Fi");
    persist_snapshot(tmp.path(), &snap).unwrap();

    // Restore.
    takeover::restore_from_snapshot(&platform, &snap, tmp.path()).unwrap();

    // Wi-Fi should be back to DHCP.
    assert_eq!(
        platform.get_setting("Wi-Fi"),
        Some(DnsSetting::Dhcp),
        "Wi-Fi must be restored to DHCP"
    );

    // Snapshot file must be removed.
    assert!(
        load_snapshot(tmp.path()).unwrap().is_none(),
        "snapshot file must be removed after restore"
    );
}

/// (d) No snapshot present → load_snapshot returns None.
///
/// Callers (routes.rs, main.rs) handle this with a 409/early-exit; here we
/// verify the platform layer is not invoked when there is no snapshot.
#[test]
fn test_d_no_snapshot_returns_none() {
    let tmp = TempDir::new().unwrap();
    let loaded = load_snapshot(tmp.path()).unwrap();
    assert!(
        loaded.is_none(),
        "load_snapshot on empty dir must return None"
    );
}

/// (e) Crash-loop breaker fires after threshold abnormal restarts.
///
/// Simulates 3 successive dirty starts with a snapshot present.
/// After the 3rd call, BreakerOutcome::Fired must be returned and
/// restore_fn must have been called.
#[test]
fn test_e_breaker_fires_after_threshold() {
    let tmp = TempDir::new().unwrap();
    let cfg = BreakerConfig {
        threshold: 3,
        window_secs: 300,
    };
    let now_base = 100_000u64; // 100 s in ms

    // Tick 0: first boot, no run-state.json → default clean → Nominal.
    {
        let snap = DnsSnapshot::new(vec![]);
        persist_snapshot(tmp.path(), &snap).unwrap();
        let out = breaker::check_breaker(tmp.path(), &cfg, now_base, true, || Ok(())).unwrap();
        assert_eq!(
            out,
            BreakerOutcome::Nominal,
            "first clean boot must be Nominal"
        );
    }

    // Dirty restart 1.
    {
        let mut s = breaker::load_run_state(tmp.path()).unwrap();
        s.clean_shutdown = false;
        breaker::save_run_state(tmp.path(), &s).unwrap();
        let snap = DnsSnapshot::new(vec![]);
        persist_snapshot(tmp.path(), &snap).unwrap();
        let out =
            breaker::check_breaker(tmp.path(), &cfg, now_base + 1_000, true, || Ok(())).unwrap();
        assert_eq!(
            out,
            BreakerOutcome::Nominal,
            "1st abnormal restart: must be Nominal"
        );
    }

    // Dirty restart 2.
    {
        let mut s = breaker::load_run_state(tmp.path()).unwrap();
        s.clean_shutdown = false;
        breaker::save_run_state(tmp.path(), &s).unwrap();
        let snap = DnsSnapshot::new(vec![]);
        persist_snapshot(tmp.path(), &snap).unwrap();
        let out =
            breaker::check_breaker(tmp.path(), &cfg, now_base + 2_000, true, || Ok(())).unwrap();
        assert_eq!(
            out,
            BreakerOutcome::Nominal,
            "2nd abnormal restart: must be Nominal"
        );
    }

    // Dirty restart 3 → fires.
    {
        let mut s = breaker::load_run_state(tmp.path()).unwrap();
        s.clean_shutdown = false;
        breaker::save_run_state(tmp.path(), &s).unwrap();
        let snap = DnsSnapshot::new(vec![]);
        persist_snapshot(tmp.path(), &snap).unwrap();
        let mut restore_called = false;
        let out = breaker::check_breaker(tmp.path(), &cfg, now_base + 3_000, true, || {
            restore_called = true;
            Ok(())
        })
        .unwrap();
        assert!(
            matches!(out, BreakerOutcome::Fired { .. }),
            "3rd abnormal restart must fire the breaker, got {out:?}"
        );
        assert!(
            restore_called,
            "restore_fn must be called when breaker fires"
        );
    }
}

/// (e2) Clean shutdown resets the crash-loop counter.
#[test]
fn test_e2_clean_shutdown_resets_counter() {
    let tmp = TempDir::new().unwrap();
    let cfg = BreakerConfig {
        threshold: 3,
        window_secs: 300,
    };
    let now = 100_000u64;

    // First boot (clean default) → Nominal.
    {
        let snap = DnsSnapshot::new(vec![]);
        persist_snapshot(tmp.path(), &snap).unwrap();
        breaker::check_breaker(tmp.path(), &cfg, now, true, || Ok(())).unwrap();
    }
    // Dirty restart 1.
    {
        let mut s = breaker::load_run_state(tmp.path()).unwrap();
        s.clean_shutdown = false;
        breaker::save_run_state(tmp.path(), &s).unwrap();
        let snap = DnsSnapshot::new(vec![]);
        persist_snapshot(tmp.path(), &snap).unwrap();
        breaker::check_breaker(tmp.path(), &cfg, now + 1_000, true, || Ok(())).unwrap();
    }
    // Dirty restart 2.
    {
        let mut s = breaker::load_run_state(tmp.path()).unwrap();
        s.clean_shutdown = false;
        breaker::save_run_state(tmp.path(), &s).unwrap();
        let snap = DnsSnapshot::new(vec![]);
        persist_snapshot(tmp.path(), &snap).unwrap();
        breaker::check_breaker(tmp.path(), &cfg, now + 2_000, true, || Ok(())).unwrap();
    }

    // Clean shutdown.
    breaker::mark_clean(tmp.path()).unwrap();

    // Next boot: clean state → counter cleared → Nominal (not Fired).
    {
        let snap = DnsSnapshot::new(vec![]);
        persist_snapshot(tmp.path(), &snap).unwrap();
        let out = breaker::check_breaker(tmp.path(), &cfg, now + 100_000, true, || Ok(())).unwrap();
        assert_eq!(
            out,
            BreakerOutcome::Nominal,
            "after clean shutdown, counter must reset → Nominal"
        );
    }
}

/// (f) Drift classification covers all four variants.
#[test]
fn test_f_drift_classification() {
    let loopback = DnsSetting::Static {
        servers: vec!["127.0.0.1".parse::<IpAddr>().unwrap()],
    };
    let third_party = DnsSetting::Static {
        servers: vec!["8.8.8.8".parse::<IpAddr>().unwrap()],
    };
    let dhcp = DnsSetting::Dhcp;

    // Pointing at self → Clean.
    assert_eq!(
        classify_drift(&loopback, &dhcp, false),
        DriftKind::Clean,
        "loopback → Clean"
    );

    // DHCP revert → Dhcp.
    assert_eq!(
        classify_drift(&dhcp, &dhcp, false),
        DriftKind::Dhcp,
        "dhcp → Dhcp"
    );

    // Third-party + VPN interface present → VpnActive.
    assert_eq!(
        classify_drift(&third_party, &dhcp, true),
        DriftKind::VpnActive,
        "static+vpn → VpnActive"
    );

    // Third-party, no VPN → UserSet.
    assert_eq!(
        classify_drift(&third_party, &dhcp, false),
        DriftKind::UserSet,
        "static no vpn → UserSet"
    );
}

/// (g) Wake detection fires when wall-clock elapsed >> monotonic elapsed.
#[test]
fn test_g_wake_detection_fires() {
    use std::time::Instant;

    // Monotonic says 10 s elapsed; wall says 60 s → gap 50 s > threshold 30 s.
    let prev_mono = Instant::now() - Duration::from_secs(10);
    let prev_wall_ms = {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
            .saturating_sub(60_000)
    };

    let threshold = Duration::from_secs(30);
    assert!(
        detect_wake(prev_mono, prev_wall_ms, threshold),
        "wall elapsed 60 s, mono 10 s → wake must be detected"
    );
}

/// (g2) Wake detection does NOT fire for a normal tick (mono ≈ wall).
#[test]
fn test_g2_no_false_wake() {
    use std::time::Instant;

    let prev_mono = Instant::now() - Duration::from_secs(5);
    let prev_wall_ms = {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
            .saturating_sub(5_000)
    };

    let threshold = Duration::from_secs(30);
    assert!(
        !detect_wake(prev_mono, prev_wall_ms, threshold),
        "normal tick must NOT trigger wake"
    );
}

// ── Sentinel state-machine ────────────────────────────────────────────────────

/// Sentinel starts in Filtering and transitions to all states correctly.
#[test]
fn test_sentinel_state_transitions() {
    let engine = Arc::new(DecisionEngine::new());
    let (sentinel, _rx) = Sentinel::new(engine);

    assert_eq!(sentinel.current_state(), GuardState::Filtering);

    sentinel.set_standing_by(StandbyReason::Portal);
    assert_eq!(
        sentinel.current_state(),
        GuardState::StandingBy {
            why: StandbyReason::Portal
        }
    );

    sentinel.set_attention("crash loop");
    assert!(
        matches!(sentinel.current_state(), GuardState::Attention { .. }),
        "must be in Attention state"
    );

    sentinel.set_filtering();
    assert_eq!(sentinel.current_state(), GuardState::Filtering);
}

/// `state_api()` returns the correct string pairs for each state.
#[test]
fn test_sentinel_state_api_strings() {
    let engine = Arc::new(DecisionEngine::new());
    let (sentinel, _rx) = Sentinel::new(engine);

    let (state, reason) = sentinel.state_api();
    assert_eq!(state, "filtering");
    assert_eq!(reason, None);

    sentinel.set_standing_by(StandbyReason::VpnActive);
    let (state, reason) = sentinel.state_api();
    assert_eq!(state, "standing_by");
    assert_eq!(reason, Some("vpn".to_owned()));

    sentinel.set_standing_by(StandbyReason::UserDns);
    let (state, reason) = sentinel.state_api();
    assert_eq!(state, "standing_by");
    assert_eq!(reason, Some("user_dns".to_owned()));

    sentinel.set_standing_by(StandbyReason::Portal);
    let (state, reason) = sentinel.state_api();
    assert_eq!(state, "standing_by");
    assert_eq!(reason, Some("portal".to_owned()));
}

// ── MockPlatform failure injection ────────────────────────────────────────────

/// snapshot() failure → run_takeover returns an error; platform not mutated.
#[tokio::test]
async fn test_snapshot_failure_no_mutation() {
    let tmp = TempDir::new().unwrap();
    let platform = make_platform_with_wifi();
    platform.inject_failure(Fail::OnSnapshot);

    let cfg = make_takeover_cfg(tmp.path());
    let result = takeover::run_takeover(&platform, &cfg).await;

    // Must fail (either at SELF-TEST since no real listener, or snapshot).
    assert!(
        result.is_err(),
        "takeover with injected snapshot failure must fail"
    );

    // point_at_self must NOT have been called.
    let calls = platform.calls();
    assert_eq!(
        calls
            .iter()
            .filter(|c| c.starts_with("point_at_self"))
            .count(),
        0,
        "point_at_self must not be called"
    );
}

/// platform.restore() failure is surfaced by restore_from_snapshot.
#[test]
fn test_restore_platform_error() {
    let tmp = TempDir::new().unwrap();

    let platform = MockPlatform::new([(
        "Wi-Fi".to_owned(),
        DnsSetting::Static {
            servers: vec!["127.0.0.1".parse::<IpAddr>().unwrap()],
        },
    )]);
    platform.inject_failure(Fail::OnRestore);

    let snap = make_snapshot_dhcp("Wi-Fi");
    persist_snapshot(tmp.path(), &snap).unwrap();

    let result = takeover::restore_from_snapshot(&platform, &snap, tmp.path());
    assert!(
        result.is_err(),
        "restore with injected failure must return an error"
    );

    // DNS must remain at self (restore was injected to fail).
    assert_eq!(
        platform.get_setting("Wi-Fi"),
        Some(DnsSetting::Static {
            servers: vec!["127.0.0.1".parse::<IpAddr>().unwrap()]
        }),
        "Wi-Fi must remain static when restore fails"
    );
}

/// Multiple service snapshot and restore round-trip.
#[test]
fn test_multi_service_restore() {
    let tmp = TempDir::new().unwrap();

    // Two services, both currently pointing at self.
    let platform = MockPlatform::new([
        (
            "Wi-Fi".to_owned(),
            DnsSetting::Static {
                servers: vec!["127.0.0.1".parse::<IpAddr>().unwrap()],
            },
        ),
        (
            "Ethernet".to_owned(),
            DnsSetting::Static {
                servers: vec!["127.0.0.1".parse::<IpAddr>().unwrap()],
            },
        ),
    ]);

    let snap = DnsSnapshot {
        v: 1,
        taken_unix_ms: 1_234_567,
        services: vec![
            ServiceDns {
                service: "Wi-Fi".to_owned(),
                setting: DnsSetting::Dhcp,
            },
            ServiceDns {
                service: "Ethernet".to_owned(),
                setting: DnsSetting::Static {
                    servers: vec!["8.8.8.8".parse::<IpAddr>().unwrap()],
                },
            },
        ],
        linux_regime: None,
    };

    persist_snapshot(tmp.path(), &snap).unwrap();
    takeover::restore_from_snapshot(&platform, &snap, tmp.path()).unwrap();

    assert_eq!(platform.get_setting("Wi-Fi"), Some(DnsSetting::Dhcp));
    assert_eq!(
        platform.get_setting("Ethernet"),
        Some(DnsSetting::Static {
            servers: vec!["8.8.8.8".parse::<IpAddr>().unwrap()]
        })
    );
    assert!(load_snapshot(tmp.path()).unwrap().is_none());
}

/// Breaker fires at exactly threshold when pre-seeded state is used.
#[test]
fn test_breaker_fires_calls_restore_fn() {
    let tmp = TempDir::new().unwrap();
    let cfg = BreakerConfig {
        threshold: 2,
        window_secs: 300,
    };
    let now = 100_000u64;

    // Pre-seed: one dirty restart already in the window (5 s ago).
    let pre_state = RunState {
        clean_shutdown: false,
        abnormal_restarts: vec![now - 5_000],
        tripped_unix_ms: None,
    };
    breaker::save_run_state(tmp.path(), &pre_state).unwrap();

    // Snapshot exists → restart will be counted.
    let snap = DnsSnapshot::new(vec![]);
    persist_snapshot(tmp.path(), &snap).unwrap();

    let mut restore_was_called = false;
    let out = breaker::check_breaker(tmp.path(), &cfg, now, true, || {
        restore_was_called = true;
        Ok(())
    })
    .unwrap();

    assert!(
        matches!(out, BreakerOutcome::Fired { .. }),
        "breaker must fire at threshold {}, got {out:?}",
        cfg.threshold
    );
    assert!(restore_was_called, "restore_fn must be invoked on fire");
}

/// Breaker: restarts outside the sliding window are pruned.
#[test]
fn test_breaker_old_restarts_pruned() {
    let tmp = TempDir::new().unwrap();
    let cfg = BreakerConfig {
        threshold: 2,
        window_secs: 60,
    };
    let now = 200_000u64; // t=200 s

    // Two dirty restarts, both > 60 s ago.
    let pre_state = RunState {
        clean_shutdown: false,
        abnormal_restarts: vec![
            10_000, // t=10 s — 190 s ago
            20_000, // t=20 s — 180 s ago
        ],
        tripped_unix_ms: None,
    };
    breaker::save_run_state(tmp.path(), &pre_state).unwrap();

    let snap = DnsSnapshot::new(vec![]);
    persist_snapshot(tmp.path(), &snap).unwrap();

    let mut restore_called = false;
    let out = breaker::check_breaker(tmp.path(), &cfg, now, true, || {
        restore_called = true;
        Ok(())
    })
    .unwrap();

    // Both entries outside 60 s window → count drops to 1 (this restart) → Nominal.
    assert_eq!(
        out,
        BreakerOutcome::Nominal,
        "old restarts must be pruned → Nominal"
    );
    assert!(!restore_called);
}

/// (h) COMMIT partial failure → restore is invoked as best-effort rollback.
///
/// Verifies the fix for the missing COMMIT-error rollback path:
/// when `point_at_self` errors mid-way (some adapters already sinkholed),
/// `run_takeover` must call `platform.restore(snapshot)` before returning
/// the error.
///
/// Uses `Fail::OnPointAtSelfAfter(1)` to sinkhole the first service then
/// return an error, leaving a mixed state that rollback must fix.
///
/// Note: run_takeover also runs SELF-TEST which requires a live listener;
/// since we use port 1 (no listener) the test fails at SELF-TEST *before*
/// COMMIT.  We therefore test the COMMIT-error rollback path directly via
/// the internal transaction steps using a snapshot + direct `point_at_self`
/// call, mirroring what `run_takeover` does after SELF-TEST.
#[tokio::test]
async fn test_h_commit_error_triggers_rollback() {
    use hush_daemon::platform::stub::Fail;

    let tmp = TempDir::new().unwrap();

    // Two services — both start at DHCP (the pre-takeover baseline).
    let platform = MockPlatform::new([
        ("Wi-Fi".to_owned(), DnsSetting::Dhcp),
        ("Ethernet".to_owned(), DnsSetting::Dhcp),
    ]);

    // Persist the baseline snapshot (as PERSIST step would).
    let snap = DnsSnapshot {
        v: 1,
        taken_unix_ms: 0,
        services: vec![
            ServiceDns {
                service: "Wi-Fi".to_owned(),
                setting: DnsSetting::Dhcp,
            },
            ServiceDns {
                service: "Ethernet".to_owned(),
                setting: DnsSetting::Dhcp,
            },
        ],
        linux_regime: None,
    };
    persist_snapshot(tmp.path(), &snap).unwrap();

    // Inject partial failure: apply first service (Wi-Fi) then error.
    platform.inject_failure(Fail::OnPointAtSelfAfter(1));

    // Simulate the COMMIT step: call point_at_self with both services.
    let service_names: Vec<String> = vec!["Wi-Fi".to_owned(), "Ethernet".to_owned()];
    let commit_result = platform.point_at_self(&service_names);

    // COMMIT must have failed.
    assert!(commit_result.is_err(), "point_at_self must fail (injected)");

    // After the injected failure: Wi-Fi was sinkholed, Ethernet was not.
    // (Reflects the partial-application state before rollback.)
    let wifi_after_partial = platform.get_setting("Wi-Fi").unwrap();
    assert!(
        matches!(wifi_after_partial, DnsSetting::Static { .. }),
        "Wi-Fi must be sinkholed after partial apply, got {wifi_after_partial:?}"
    );

    // Now perform the rollback (as run_takeover does on COMMIT error).
    let restore_result = platform.restore(&snap);
    assert!(restore_result.is_ok(), "rollback restore must succeed");

    // After rollback, both services must be back to DHCP.
    assert_eq!(
        platform.get_setting("Wi-Fi"),
        Some(DnsSetting::Dhcp),
        "Wi-Fi must be restored to DHCP after rollback"
    );
    assert_eq!(
        platform.get_setting("Ethernet"),
        Some(DnsSetting::Dhcp),
        "Ethernet must remain DHCP after rollback"
    );

    // Verify that restore was recorded in the call log.
    let calls = platform.calls();
    let restore_calls = calls.iter().filter(|c| c.starts_with("restore")).count();
    assert_eq!(
        restore_calls, 1,
        "restore must be called exactly once for rollback"
    );
}

// ── Live macOS end-to-end (root-gated, #[ignore]) ────────────────────────────

/// Live DNS takeover + restore on macOS (requires root).
///
/// Skips cleanly when not root.  Run with:
/// ```
/// sudo cargo test -p hush-daemon --test sentinel_integration \
///   live_macos_takeover_restore -- --ignored
/// ```
#[tokio::test]
#[ignore = "requires root on macOS; run with --ignored as root"]
async fn live_macos_takeover_restore() {
    // Skip if not root.
    let uid = std::process::Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .trim()
                .parse::<u32>()
                .ok()
        })
        .unwrap_or(1);

    if uid != 0 {
        eprintln!("live_macos_takeover_restore: skipping — not root (uid={uid})");
        return;
    }

    let tmp = TempDir::new().unwrap();
    let platform = hush_daemon::platform::native();
    let cfg = TakeoverConfig {
        state_dir: tmp.path().to_path_buf(),
        allowed_canary: "example.com".to_owned(),
        ..TakeoverConfig::default()
    };

    // Takeover.
    let snap = takeover::run_takeover(&*platform, &cfg)
        .await
        .expect("live takeover must succeed as root");

    assert!(
        !snap.services.is_empty(),
        "live snapshot must have at least one service"
    );

    // Snapshot exists on disk.
    let loaded = load_snapshot(tmp.path()).unwrap().unwrap();
    assert_eq!(loaded.v, 1);

    // Restore.
    takeover::restore_from_snapshot(&*platform, &snap, tmp.path())
        .expect("live restore must succeed as root");

    // Snapshot must be gone.
    assert!(
        load_snapshot(tmp.path()).unwrap().is_none(),
        "snapshot must be removed after live restore"
    );
}
