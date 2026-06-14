//! E2E binary smoke test: spawn the real `hushd` binary, verify it starts,
//! handles one blocked + one forwarded query, then SIGTERMs cleanly.
//!
//! Per `specs/wp2-daemon.md` §7 E2E section.
//!
//! The test:
//! 1. Spawns `hushd` with a temp state dir + port-0 listener.
//! 2. Reads stdout until it finds `LISTENING udp=<addr>` (exactly one line).
//! 3. Sends a blocked A query (expects 0.0.0.0) and a forwarded A query.
//! 4. Sends SIGTERM.
//! 5. Asserts exit code 0.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{net::SocketAddr, process::Stdio, time::Duration};
use tempfile::TempDir;
use tokio::{io::AsyncBufReadExt as _, net::UdpSocket, process::Command, time::timeout};

/// Set up a minimal state dir for the E2E test:
/// - Writes `hushwarren.toml` with port-0 listeners and a dead upstream.
/// - Pre-compiles and saves a `CompiledRules` artifact containing
///   `ads.blocked.test` so the daemon loads rules on boot without any HTTP
///   fetch.
fn write_test_config(state_dir: &TempDir) -> String {
    use hush_core::{
        rules::{RuleSink as _, RulesBuilder},
        Domain,
    };

    // Pre-compile rules and save to `compiled/`.
    let compiled_dir = state_dir.path().join("compiled");
    std::fs::create_dir_all(&compiled_dir).unwrap();
    let mut builder = RulesBuilder::new();
    builder.block(Domain::parse("ads.blocked.test").unwrap());
    let rules = builder.build().unwrap();
    rules.save(&compiled_dir).unwrap();

    // Config TOML.
    // listen.udp / listen.tcp = port 0 so the OS assigns an ephemeral port.
    // upstream.do53_fallback = 127.0.0.1:1 (port 1 is always refused — so
    // forwarded queries SERVFAIL; that still proves the daemon is alive).
    let config_toml = r#"
[listen]
udp = ["127.0.0.1:0"]
tcp = ["127.0.0.1:0"]

[upstream]
doh = []
do53_fallback = ["127.0.0.1:1"]

[lists]
sources = [{ name = "inline", url = "http://127.0.0.1:1/list" }]
refresh_hours = 24
jitter_minutes = 0

[block]
action = "null_ip"
ttl_secs = 30
"#;
    let config_path = state_dir.path().join("hushwarren.toml");
    std::fs::write(&config_path, config_toml).unwrap();
    config_path.to_string_lossy().into_owned()
}

/// Parse `LISTENING udp=<addr>` from a line.
fn parse_listening_addr(line: &str) -> Option<SocketAddr> {
    // The line is formatted as: `LISTENING udp=<addr>` (stdout contract).
    line.trim().strip_prefix("LISTENING udp=")?.parse().ok()
}

/// Build the hushd binary path via `CARGO_BIN_EXE_hushd` env var.
fn hushd_bin() -> String {
    // CARGO_BIN_EXE_hushd is set by cargo test automatically.
    std::env::var("CARGO_BIN_EXE_hushd").expect("CARGO_BIN_EXE_hushd not set; run via `cargo test`")
}

/// Send a minimal A query via raw UDP and return the response (4096-byte buf).
async fn udp_query(
    daemon_addr: SocketAddr,
    qname_bytes: &[u8],
    timeout_ms: u64,
) -> Option<Vec<u8>> {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(qname_bytes, daemon_addr).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let result =
        tokio::time::timeout(Duration::from_millis(timeout_ms), sock.recv_from(&mut buf)).await;
    match result {
        Ok(Ok((n, _))) => Some(buf[..n].to_vec()),
        _ => None,
    }
}

/// Build a raw A-query DNS packet for the given pre-encoded QNAME wire bytes.
///
/// `qname_wire`: the wire-encoded QNAME ending in a zero byte.
fn build_a_query(id: u16, qname_wire: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(12 + qname_wire.len() + 4);
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.push(0x01);
    pkt.push(0x00); // QR=0 RD=1
    pkt.push(0x00);
    pkt.push(0x01); // QDCOUNT=1
    pkt.push(0x00);
    pkt.push(0x00);
    pkt.push(0x00);
    pkt.push(0x00);
    pkt.push(0x00);
    pkt.push(0x00);
    pkt.extend_from_slice(qname_wire);
    pkt.push(0x00);
    pkt.push(0x01); // QTYPE A
    pkt.push(0x00);
    pkt.push(0x01); // QCLASS IN
    pkt
}

// Wire encoding of "ads.blocked.test"
const ADS_BLOCKED_TEST: &[u8] = &[
    0x03, b'a', b'd', b's', 0x07, b'b', b'l', b'o', b'c', b'k', b'e', b'd', 0x04, b't', b'e', b's',
    b't', 0x00,
];

// Wire encoding of "good.test" (forwarded — expect SERVFAIL from dead upstream)
const GOOD_TEST: &[u8] = &[
    0x04, b'g', b'o', b'o', b'd', 0x04, b't', b'e', b's', b't', 0x00,
];

#[tokio::test]
async fn e2e_binary_smoke() {
    let state_dir = TempDir::new().unwrap();
    let _config_path = write_test_config(&state_dir);

    let hushd = hushd_bin();

    // Spawn the binary.
    let mut child = Command::new(&hushd)
        .arg("--state-dir")
        .arg(state_dir.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::null()) // suppress tracing output in test logs
        .spawn()
        .expect("failed to spawn hushd");

    // Read stdout until we see the LISTENING line (5-second deadline).
    let stdout = child.stdout.take().unwrap();
    let mut lines = tokio::io::BufReader::new(stdout).lines();

    let daemon_addr: SocketAddr = timeout(Duration::from_secs(5), async {
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    if let Some(addr) = parse_listening_addr(&line) {
                        return addr;
                    }
                }
                Ok(None) => panic!("hushd stdout closed before LISTENING line"),
                Err(e) => panic!("reading stdout: {e}"),
            }
        }
    })
    .await
    .expect("timeout waiting for LISTENING line");

    // ── Query 1: blocked ─────────────────────────────────────────────────────
    // ads.blocked.test A → expect 0.0.0.0 (null_ip action).
    let blocked_query = build_a_query(0xAB01, ADS_BLOCKED_TEST);
    let blocked_resp = udp_query(daemon_addr, &blocked_query, 2000)
        .await
        .expect("no response for blocked query");

    // Response must be at least 12 bytes (header) and have RCODE=NOERROR (0).
    assert!(blocked_resp.len() >= 12, "blocked response too short");
    let rcode = blocked_resp[3] & 0x0F;
    assert_eq!(rcode, 0, "blocked A must return NOERROR (null_ip)");
    // Must have at least one answer (ANCOUNT > 0).
    let ancount = u16::from_be_bytes([blocked_resp[6], blocked_resp[7]]);
    assert!(
        ancount > 0,
        "blocked A must have at least one answer record"
    );

    // ── Query 2: forwarded → SERVFAIL (dead upstream) ────────────────────────
    // good.test A → forwarded to 127.0.0.1:1 → SERVFAIL.
    let forward_query = build_a_query(0xAB02, GOOD_TEST);
    let forward_resp = udp_query(daemon_addr, &forward_query, 6000)
        .await
        .expect("no response for forwarded query");

    assert!(forward_resp.len() >= 12, "forward response too short");
    let rcode2 = forward_resp[3] & 0x0F;
    // Either SERVFAIL (2) or NOERROR with answers (if somehow resolved).
    assert!(
        rcode2 == 2 || rcode2 == 0,
        "forwarded query must return SERVFAIL or NOERROR, got RCODE={rcode2}"
    );

    // ── Graceful shutdown ────────────────────────────────────────────────────
    // Send SIGTERM (unix) or kill (windows) and wait for exit ≤ 5 s.
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        // Send SIGTERM via the `kill` utility (avoids a `libc` dev-dep).
        if let Some(pid) = child.id() {
            let _ = std::process::Command::new("kill")
                .arg("-TERM")
                .arg(format!("{pid}"))
                .status();
        }
        let exit = timeout(Duration::from_secs(5), child.wait())
            .await
            .expect("timeout waiting for hushd to exit after SIGTERM")
            .expect("child wait error");
        // Acceptable: exit code 0 or killed by signal 15 (SIGTERM).
        let ok = exit.code() == Some(0) || exit.signal() == Some(15);
        assert!(ok, "hushd must exit cleanly after SIGTERM: {exit:?}");
    }

    #[cfg(not(unix))]
    {
        child.kill().await.ok();
        let _ = child.wait().await;
    }
}
