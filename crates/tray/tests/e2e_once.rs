//! E2E test: `hush-tray --once` against a real running daemon.
//!
//! Implements `specs/wp10-tray.md` §5 E2E mandatory case.
//!
//! Architecture:
//! - Spawn a real `hushd` process with a temp state dir (mirrors
//!   `crates/cli/tests/e2e_cli.rs` pattern).
//! - Run `hush-tray --once`; expect stdout == "filtering\n".
//! - `--once` must NOT initialise any tray UI (no event loop, no GUI) so
//!   this test is safe on headless CI.
//!
//! Gate: no sleeps; daemon readiness detected by polling `api.addr`.
//!
//! Note: the test is bracketed with `#[cfg(unix)]` because the spawn+kill
//! pattern uses `kill -TERM`.  It is unconditionally compiled on macOS (the
//! only verified OS per the spec) and on Linux CI runners.

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[cfg(unix)]
mod once_tests {
    use std::{net::SocketAddr, process::Stdio, time::Duration};

    use assert_cmd::Command;
    use tempfile::TempDir;
    use tokio::{
        io::AsyncBufReadExt as _,
        process::Command as TokioCommand,
        time::{sleep, timeout},
    };

    use hush_core::{
        rules::{RuleSink as _, RulesBuilder},
        Domain,
    };

    // ── DaemonGuard ───────────────────────────────────────────────────────────

    struct DaemonGuard {
        child: tokio::process::Child,
    }

    impl Drop for DaemonGuard {
        fn drop(&mut self) {
            if let Some(id) = self.child.id() {
                let _ = std::process::Command::new("kill")
                    .arg("-TERM")
                    .arg(format!("{id}"))
                    .status();
            }
        }
    }

    // ── Setup helpers ─────────────────────────────────────────────────────────

    fn setup_state_dir(state_dir: &TempDir, upstream_addr: SocketAddr) {
        // Pre-compile a minimal rule set (one blocked domain).
        let compiled_dir = state_dir.path().join("compiled");
        std::fs::create_dir_all(&compiled_dir).unwrap();
        let mut builder = RulesBuilder::new();
        builder.block(Domain::parse("ads.blocked.test").unwrap());
        let rules = builder.build().unwrap();
        rules.save(&compiled_dir).unwrap();

        let config = format!(
            r#"
[listen]
udp = ["127.0.0.1:0"]
tcp = ["127.0.0.1:0"]

[upstream]
doh = []
do53_fallback = ["{upstream}"]

[lists]
sources = [{{ name = "fixture", url = "http://127.0.0.1:1/list" }}]
refresh_hours = 24
jitter_minutes = 0

[block]
action = "null_ip"
ttl_secs = 5

[api]
listen = "127.0.0.1:0"
"#,
            upstream = upstream_addr,
        );
        std::fs::write(state_dir.path().join("hushwarren.toml"), config).unwrap();
    }

    /// Spawn `hushd` and wait for `api.addr` to appear (readiness signal).
    async fn spawn_daemon(state_dir: &TempDir) -> DaemonGuard {
        let bin = assert_cmd::cargo::cargo_bin("hushd");

        let mut child = TokioCommand::new(bin)
            .arg("--state-dir")
            .arg(state_dir.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn hushd");

        let stdout = child.stdout.take().unwrap();
        let mut lines = tokio::io::BufReader::new(stdout).lines();

        // Wait for LISTENING line (signals DNS listener bound).
        timeout(Duration::from_secs(10), async {
            loop {
                match lines.next_line().await {
                    Ok(Some(line)) => {
                        let trimmed = line.trim();
                        if trimmed.starts_with("LISTENING udp=") {
                            return;
                        }
                    }
                    Ok(None) => panic!("hushd stdout closed before LISTENING"),
                    Err(e) => panic!("reading hushd stdout: {e}"),
                }
            }
        })
        .await
        .expect("timeout waiting for hushd LISTENING");

        // Wait for api.addr (signals API server bound and token written).
        timeout(Duration::from_secs(5), async {
            loop {
                let path = state_dir.path().join("api.addr");
                if std::fs::read_to_string(&path).is_ok() {
                    return;
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("timeout waiting for api.addr");

        DaemonGuard { child }
    }

    // ── Minimal UDP mock upstream (echoes a fixed IP for all A queries) ───────
    //
    // hushd needs an upstream to start in a non-degraded state.

    struct MockUpstream {
        addr: SocketAddr,
        _shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl MockUpstream {
        async fn start() -> Self {
            use tokio::net::UdpSocket;
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = socket.local_addr().unwrap();
            let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let stop = std::sync::Arc::clone(&shutdown);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    if let Ok(Ok((n, peer))) =
                        tokio::time::timeout(Duration::from_millis(100), socket.recv_from(&mut buf))
                            .await
                    {
                        if n < 12 {
                            continue;
                        }
                        let qid = u16::from_be_bytes([buf[0], buf[1]]);
                        let mut resp = Vec::with_capacity(n + 16);
                        resp.extend_from_slice(&qid.to_be_bytes());
                        resp.push(0x81);
                        resp.push(0x80);
                        resp.push(0x00);
                        resp.push(0x01);
                        resp.push(0x00);
                        resp.push(0x01);
                        resp.push(0x00);
                        resp.push(0x00);
                        resp.push(0x00);
                        resp.push(0x00);
                        // Copy the question section.
                        if n > 12 {
                            resp.extend_from_slice(&buf[12..n]);
                        }
                        resp.push(0xC0);
                        resp.push(0x0C);
                        resp.push(0x00);
                        resp.push(0x01);
                        resp.push(0x00);
                        resp.push(0x01);
                        resp.push(0x00);
                        resp.push(0x00);
                        resp.push(0x00);
                        resp.push(0x3C);
                        resp.push(0x00);
                        resp.push(0x04);
                        resp.extend_from_slice(&[192u8, 0, 2, 10]);
                        let _ = socket.send_to(&resp, peer).await;
                    }
                }
            });
            Self {
                addr,
                _shutdown: shutdown,
            }
        }
    }

    // ── Test: --once against running daemon → "filtering" ────────────────────

    #[tokio::test(flavor = "multi_thread")]
    async fn once_against_running_daemon_prints_filtering() {
        let tmp = TempDir::new().unwrap();
        let mock = MockUpstream::start().await;
        setup_state_dir(&tmp, mock.addr);
        let _guard = spawn_daemon(&tmp).await;

        // Run `hush-tray --once` with HUSH_STATE_DIR pointing at the temp dir.
        let output = Command::cargo_bin("hush-tray")
            .unwrap()
            .arg("--once")
            .env("HUSH_STATE_DIR", tmp.path())
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let stdout = String::from_utf8_lossy(&output);
        let trimmed = stdout.trim();
        assert_eq!(
            trimmed, "filtering",
            "hush-tray --once must print 'filtering' when daemon is running; got: {trimmed:?}"
        );
    }

    // ── Test: --once with no daemon running → "standing_by" (grey, exit 0) ───

    #[tokio::test(flavor = "multi_thread")]
    async fn once_with_no_daemon_prints_standing_by() {
        let tmp = TempDir::new().unwrap();
        // No daemon spawned; no api.addr file.

        let output = Command::cargo_bin("hush-tray")
            .unwrap()
            .arg("--once")
            .env("HUSH_STATE_DIR", tmp.path())
            .assert()
            .success() // exit 0 — unreachable is not fatal
            .get_output()
            .stdout
            .clone();

        let stdout = String::from_utf8_lossy(&output);
        let trimmed = stdout.trim();
        assert_eq!(
            trimmed, "standing_by",
            "hush-tray --once must print 'standing_by' when daemon is not running; got: {trimmed:?}"
        );
    }
}
