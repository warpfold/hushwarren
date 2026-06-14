//! Integration tests for the `hush` CLI binary.
//!
//! These tests drive the REAL compiled `hush` binary via `assert_cmd`
//! against a FAKE in-process API server (see `fake_server.rs`).
//!
//! Standards `specs/standards.md` §5 integration layer rules:
//! - In-process components on ephemeral ports (port 0).
//! - No external network, no fixed ports.
//! - No `sleep`-based synchronisation — server is ready before `Command` runs
//!   because `start_*()` awaits `axum::serve` in a spawned task and the
//!   ephemeral port is bound before returning.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod fake_server;

use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt as _;
use predicates::str::contains;
use tempfile::TempDir;

/// Helper: build a `Command` for the `hush` binary pointing at `state_dir`.
fn hush_cmd(state_dir: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("hush").expect("hush binary must exist");
    cmd.arg("--state-dir").arg(state_dir);
    cmd
}

// ── status ────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn status_happy_path_exit_0_and_shows_state() {
    let (addr, token, _guard) = fake_server::start_filtering().await;
    let tmp = TempDir::new().unwrap();
    fake_server::write_state_files(tmp.path(), addr, &token);

    hush_cmd(tmp.path())
        .arg("status")
        .assert()
        .success()
        .stdout(contains("filtering"));
}

#[tokio::test(flavor = "multi_thread")]
async fn status_json_flag_returns_valid_json_with_state_key() {
    let (addr, token, _guard) = fake_server::start_filtering().await;
    let tmp = TempDir::new().unwrap();
    fake_server::write_state_files(tmp.path(), addr, &token);

    let output = hush_cmd(tmp.path())
        .args(["status", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let parsed: serde_json::Value =
        serde_json::from_slice(&output).expect("--json output must be valid JSON");
    assert!(parsed.get("state").is_some(), "JSON must have 'state' key");
    assert!(
        parsed.get("counters").is_some(),
        "JSON must have 'counters' key"
    );
    assert!(parsed.get("rules").is_some(), "JSON must have 'rules' key");
}

// ── 401 wrong token → exit 1 ─────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn wrong_token_exits_1_with_api_error_message() {
    let (addr, _token, _guard) = fake_server::start_filtering().await;
    let tmp = TempDir::new().unwrap();
    // Write the wrong token.
    fake_server::write_state_files(tmp.path(), addr, "wrong-token-000000000000000000000000000");

    hush_cmd(tmp.path())
        .arg("status")
        .assert()
        .failure()
        .code(1)
        .stderr(contains("unauthorized"));
}

// ── connection refused → exit 2 ──────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn connection_refused_exits_2_with_isnt_running_message() {
    let tmp = TempDir::new().unwrap();
    // Point at a port that has nothing listening.
    fake_server::write_state_files(tmp.path(), "127.0.0.1:19999".parse().unwrap(), "sometoken");

    hush_cmd(tmp.path())
        .arg("status")
        .assert()
        .failure()
        .code(2)
        .stderr(contains("isn't running"));
}

// ── missing state dir → exit 2 ───────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn missing_state_dir_exits_2() {
    let tmp = TempDir::new().unwrap();
    let nonexistent = tmp.path().join("no_such_dir");
    // Don't create it — api.addr won't exist.

    let mut cmd = Command::cargo_bin("hush").unwrap();
    cmd.arg("--state-dir").arg(&nonexistent).arg("status");
    cmd.assert()
        .failure()
        .code(2)
        .stderr(contains("isn't running"));
}

// ── snooze ────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn snooze_5m_exits_0() {
    let (addr, token, _guard) = fake_server::start_filtering().await;
    let tmp = TempDir::new().unwrap();
    fake_server::write_state_files(tmp.path(), addr, &token);

    hush_cmd(tmp.path())
        .args(["snooze", "5m"])
        .assert()
        .success()
        .stdout(contains("snoozed"));
}

#[tokio::test(flavor = "multi_thread")]
async fn snooze_off_calls_resume_and_exits_0() {
    let (addr, token, _guard) = fake_server::start_filtering().await;
    let tmp = TempDir::new().unwrap();
    fake_server::write_state_files(tmp.path(), addr, &token);

    hush_cmd(tmp.path())
        .args(["snooze", "off"])
        .assert()
        .success()
        .stdout(contains("resumed"));
}

#[tokio::test(flavor = "multi_thread")]
async fn snooze_invalid_duration_exits_1_no_crash() {
    let (addr, token, _guard) = fake_server::start_filtering().await;
    let tmp = TempDir::new().unwrap();
    fake_server::write_state_files(tmp.path(), addr, &token);

    hush_cmd(tmp.path())
        .args(["snooze", "garbage"])
        .assert()
        .failure()
        .code(1)
        .stderr(contains("invalid duration"));
}

// ── allow / unallow / allowlist ───────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn allow_domain_exits_0() {
    let (addr, token, _guard) = fake_server::start_filtering().await;
    let tmp = TempDir::new().unwrap();
    fake_server::write_state_files(tmp.path(), addr, &token);

    hush_cmd(tmp.path())
        .args(["allow", "example.com"])
        .assert()
        .success();
}

#[tokio::test(flavor = "multi_thread")]
async fn unallow_domain_exits_0() {
    let (addr, token, _guard) = fake_server::start_filtering().await;
    let tmp = TempDir::new().unwrap();
    fake_server::write_state_files(tmp.path(), addr, &token);

    hush_cmd(tmp.path())
        .args(["unallow", "example.com"])
        .assert()
        .success();
}

#[tokio::test(flavor = "multi_thread")]
async fn allowlist_exits_0_and_shows_domains() {
    let (addr, token, _guard) = fake_server::start_filtering().await;
    let tmp = TempDir::new().unwrap();
    fake_server::write_state_files(tmp.path(), addr, &token);

    hush_cmd(tmp.path())
        .arg("allowlist")
        .assert()
        .success()
        .stdout(contains("example.com"));
}

#[tokio::test(flavor = "multi_thread")]
async fn allowlist_json_returns_valid_json() {
    let (addr, token, _guard) = fake_server::start_filtering().await;
    let tmp = TempDir::new().unwrap();
    fake_server::write_state_files(tmp.path(), addr, &token);

    let output = hush_cmd(tmp.path())
        .args(["allowlist", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let parsed: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert!(parsed.get("allowed").is_some());
}

// ── log ───────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn log_exits_0_and_shows_queries() {
    let (addr, token, _guard) = fake_server::start_filtering().await;
    let tmp = TempDir::new().unwrap();
    fake_server::write_state_files(tmp.path(), addr, &token);

    hush_cmd(tmp.path())
        .arg("log")
        .assert()
        .success()
        .stdout(contains("ads.evil.com"));
}

#[tokio::test(flavor = "multi_thread")]
async fn log_blocked_filter_shows_only_blocked() {
    let (addr, token, _guard) = fake_server::start_filtering().await;
    let tmp = TempDir::new().unwrap();
    fake_server::write_state_files(tmp.path(), addr, &token);

    let output = hush_cmd(tmp.path())
        .args(["log", "--blocked"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let out = String::from_utf8_lossy(&output);
    // Blocked domain should appear.
    assert!(out.contains("ads.evil.com"), "blocked domain should appear");
    // Non-blocked domain should NOT appear.
    assert!(
        !out.contains("good.example.com"),
        "non-blocked domain should not appear when --blocked"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn log_n_flag_accepted() {
    let (addr, token, _guard) = fake_server::start_filtering().await;
    let tmp = TempDir::new().unwrap();
    fake_server::write_state_files(tmp.path(), addr, &token);

    hush_cmd(tmp.path())
        .args(["log", "-n", "5"])
        .assert()
        .success();
}

// ── lists ─────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn lists_exits_0_and_shows_sources() {
    let (addr, token, _guard) = fake_server::start_filtering().await;
    let tmp = TempDir::new().unwrap();
    fake_server::write_state_files(tmp.path(), addr, &token);

    // The fake server returns last_fetched_unix_ms=1700000000000 and no error,
    // so the CLI must render "ok" (not "pending") and a "fetched HH:MM:SS" field.
    hush_cmd(tmp.path())
        .arg("lists")
        .assert()
        .success()
        .stdout(contains("oisd-small"))
        .stdout(contains("fetched"))
        .stdout(contains("ok"));
}

#[tokio::test(flavor = "multi_thread")]
async fn lists_refresh_exits_0() {
    let (addr, token, _guard) = fake_server::start_filtering().await;
    let tmp = TempDir::new().unwrap();
    fake_server::write_state_files(tmp.path(), addr, &token);

    hush_cmd(tmp.path())
        .args(["lists", "--refresh"])
        .assert()
        .success();
}

// ── WP4: status shows privacy line ───────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn status_shows_privacy_line() {
    let (addr, token, _guard) = fake_server::start_filtering().await;
    let tmp = TempDir::new().unwrap();
    fake_server::write_state_files(tmp.path(), addr, &token);

    hush_cmd(tmp.path())
        .arg("status")
        .assert()
        .success()
        .stdout(contains("privacy"))
        .stdout(contains("canary"))
        .stdout(contains("log=full"));
}

// ── WP8 §6: status shows pad and rebind markers ───────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn status_shows_wp8_privacy_markers() {
    let (addr, token, _guard) = fake_server::start_filtering().await;
    let tmp = TempDir::new().unwrap();
    fake_server::write_state_files(tmp.path(), addr, &token);

    // The fake server returns doh_padding=true and rebind_protection=true.
    hush_cmd(tmp.path())
        .arg("status")
        .assert()
        .success()
        .stdout(contains("pad✓"))
        .stdout(contains("rebind✓"));
}

// ── WP4: hush log in anonymous mode prints notice ────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn log_anonymous_mode_prints_notice() {
    // Spin up a fake server that returns log_mode="anonymous".
    use axum::{routing::get, Router};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = Router::new().route(
        "/v0/queries/recent",
        get(|| async {
            axum::response::Json(serde_json::json!({
                "queries": [
                    {
                        "ts_unix_ms": 1700000001000u64,
                        "qname": "<redacted>",
                        "qtype": 1,
                        "verdict": "forward",
                        "reason": "no_match",
                        "upstream_ms": null
                    }
                ],
                "log_mode": "anonymous"
            }))
        }),
    );

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await
            .unwrap();
    });

    let tmp = TempDir::new().unwrap();
    // Use any token — the fake server above has no auth.
    fake_server::write_state_files(tmp.path(), addr, "anytoken");

    hush_cmd(tmp.path())
        .arg("log")
        .assert()
        .success()
        .stdout(contains("notice"))
        .stdout(contains("anonymous").or(contains("redacted")));

    let _ = tx.send(());
}

// ── WP4: hush log in off mode prints off notice ───────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn log_off_mode_prints_off_notice() {
    use axum::{routing::get, Router};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = Router::new().route(
        "/v0/queries/recent",
        get(|| async {
            axum::response::Json(serde_json::json!({
                "queries": [],
                "log_mode": "off"
            }))
        }),
    );

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await
            .unwrap();
    });

    let tmp = TempDir::new().unwrap();
    fake_server::write_state_files(tmp.path(), addr, "anytoken");

    hush_cmd(tmp.path())
        .arg("log")
        .assert()
        .success()
        .stdout(contains("notice"))
        .stdout(contains("off").or(contains("disabled")));

    let _ = tx.send(());
}

// ── WP4: hush lists shows attribution ────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn lists_shows_attribution() {
    let (addr, token, _guard) = fake_server::start_filtering().await;
    let tmp = TempDir::new().unwrap();
    fake_server::write_state_files(tmp.path(), addr, &token);

    hush_cmd(tmp.path())
        .arg("lists")
        .assert()
        .success()
        .stdout(contains("attribution").or(contains("OISD")));
}

// ── malformed JSON from server → exit 1, not panic ───────────────────────────

/// Spin up a server that returns malformed JSON for /v0/status.
#[tokio::test(flavor = "multi_thread")]
async fn malformed_json_from_server_exits_1_not_panic() {
    use axum::{routing::get, Router};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let router = Router::new().route(
        "/v0/status",
        get(|| async {
            (
                axum::http::StatusCode::OK,
                axum::response::Html("this is not json"),
            )
        }),
    );

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await
            .unwrap();
    });

    let tmp = TempDir::new().unwrap();
    fake_server::write_state_files(tmp.path(), addr, "anytoken");

    hush_cmd(tmp.path())
        .arg("status")
        .assert()
        .failure()
        .code(1);

    let _ = tx.send(());
}
