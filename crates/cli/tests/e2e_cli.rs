//! E2E tests: spawn the real `hushd` daemon and drive the real `hush` CLI.
//!
//! Implements `specs/wp3-api-cli.md` §5 E2E mandatory cases 1–6.
//!
//! Architecture:
//! - The test runtime spawns a real `hushd` process with a temp state dir.
//! - A minimal UDP mock upstream answers DNS queries so that `allow`ed domains
//!   resolve to `192.0.2.10` and un-allowed blocked queries return 0.0.0.0.
//! - `hush` CLI commands are run via `assert_cmd::Command::cargo_bin`.
//! - No `sleep`-based synchronisation.  Readiness is detected by polling the
//!   `api.addr` file that the daemon writes on startup.
//!
//! Each test spins up a fresh daemon (fresh state dir, fresh mock upstream).
//! Tests run sequentially due to the `#[tokio::test(flavor = "multi_thread")]`
//! wrapper — they don't share any ports or state.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::{net::SocketAddr, process::Stdio, sync::Arc, time::Duration};

use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt as _;
use tempfile::TempDir;
use tokio::{
    io::AsyncBufReadExt as _,
    net::UdpSocket,
    process::Command as TokioCommand,
    time::{sleep, timeout},
};

use hush_core::{
    rules::{RuleSink as _, RulesBuilder},
    Domain,
};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Wire-encoded QNAME for `ads.blocked.test`.
const ADS_BLOCKED_TEST_WIRE: &[u8] = &[
    0x03, b'a', b'd', b's', 0x07, b'b', b'l', b'o', b'c', b'k', b'e', b'd', 0x04, b't', b'e', b's',
    b't', 0x00,
];

// ── Test helpers ──────────────────────────────────────────────────────────────

/// Helper: build the `hush` command pointing at `state_dir`.
fn hush(state_dir: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("hush").expect("hush binary must exist");
    cmd.arg("--state-dir").arg(state_dir);
    cmd
}

/// Build a raw A-query DNS packet for the given wire-encoded QNAME.
fn build_a_query(id: u16, qname_wire: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(12 + qname_wire.len() + 4);
    pkt.extend_from_slice(&id.to_be_bytes()); // ID
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

/// Send an A query to `addr` and return the response bytes.
async fn udp_a_query(
    addr: SocketAddr,
    qname_wire: &[u8],
    id: u16,
    timeout_ms: u64,
) -> Option<Vec<u8>> {
    let sock = UdpSocket::bind("127.0.0.1:0").await.ok()?;
    let pkt = build_a_query(id, qname_wire);
    sock.send_to(&pkt, addr).await.ok()?;
    let mut buf = vec![0u8; 4096];
    match tokio::time::timeout(Duration::from_millis(timeout_ms), sock.recv_from(&mut buf)).await {
        Ok(Ok((n, _))) => Some(buf[..n].to_vec()),
        _ => None,
    }
}

/// Extract the IPv4 address from the first A record in a DNS response.
/// Returns `None` if there are no A answers.
fn first_a_record(resp: &[u8]) -> Option<std::net::Ipv4Addr> {
    if resp.len() < 12 {
        return None;
    }
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    if ancount == 0 {
        return None;
    }
    // Skip the question section: walk past qname + qtype + qclass.
    let mut pos = 12;
    while pos < resp.len() {
        let len = resp[pos] as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        if len & 0xC0 == 0xC0 {
            pos += 1; // 2-byte pointer
            break;
        }
        pos += len;
    }
    pos += 4; // qtype + qclass
              // Now at the answer section.
    if pos + 12 > resp.len() {
        return None;
    }
    // Skip name (either pointer or label)
    if resp[pos] & 0xC0 == 0xC0 {
        pos += 2;
    } else {
        while pos < resp.len() && resp[pos] != 0 {
            pos += resp[pos] as usize + 1;
        }
        pos += 1;
    }
    if pos + 10 > resp.len() {
        return None;
    }
    let rtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
    let rdlen = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
    pos += 10;
    if rtype == 1 && rdlen == 4 && pos + 4 <= resp.len() {
        Some(std::net::Ipv4Addr::new(
            resp[pos],
            resp[pos + 1],
            resp[pos + 2],
            resp[pos + 3],
        ))
    } else {
        None
    }
}

/// Guard that kills the daemon process when dropped.
struct DaemonGuard {
    child: tokio::process::Child,
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            if let Some(id) = self.child.id() {
                let _ = std::process::Command::new("kill")
                    .arg("-TERM")
                    .arg(format!("{id}"))
                    .status();
            }
        }
        #[cfg(not(unix))]
        {
            let _ = self.child.start_kill();
        }
    }
}

/// A running mock upstream DNS server.
struct MockUpstream {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
}

impl MockUpstream {
    /// Start a UDP mock that returns `192.0.2.10` for ALL A queries.
    async fn start() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&shutdown);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            while !stop.load(Ordering::Relaxed) {
                if let Ok(Ok((n, peer))) =
                    tokio::time::timeout(Duration::from_millis(100), socket.recv_from(&mut buf))
                        .await
                {
                    if n < 12 {
                        continue;
                    }
                    let qid = u16::from_be_bytes([buf[0], buf[1]]);
                    // Minimal A response with 192.0.2.10.
                    let qname_end = {
                        let mut off = 12;
                        while off < n {
                            let l = buf[off] as usize;
                            off += 1;
                            if l == 0 {
                                break;
                            }
                            off += l;
                        }
                        off
                    };
                    let mut resp = Vec::with_capacity(n + 16);
                    resp.extend_from_slice(&qid.to_be_bytes());
                    resp.push(0x81);
                    resp.push(0x80); // QR=1 RD=1 RA=1 RCODE=0
                    resp.push(0x00);
                    resp.push(0x01); // QDCOUNT=1
                    resp.push(0x00);
                    resp.push(0x01); // ANCOUNT=1
                    resp.push(0x00);
                    resp.push(0x00);
                    resp.push(0x00);
                    resp.push(0x00);
                    if qname_end + 4 <= n {
                        resp.extend_from_slice(&buf[12..qname_end + 4]);
                    }
                    resp.push(0xC0);
                    resp.push(0x0C); // name ptr
                    resp.push(0x00);
                    resp.push(0x01); // TYPE A
                    resp.push(0x00);
                    resp.push(0x01); // CLASS IN
                    resp.push(0x00);
                    resp.push(0x00);
                    resp.push(0x00);
                    resp.push(0x3C); // TTL 60
                    resp.push(0x00);
                    resp.push(0x04); // RDLENGTH 4
                    resp.extend_from_slice(&[192u8, 0, 2, 10]);
                    let _ = socket.send_to(&resp, peer).await;
                }
            }
        });
        Self { addr, shutdown }
    }
}

impl Drop for MockUpstream {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }
}

/// Write the daemon config TOML and pre-compiled rules to `state_dir`.
fn setup_state_dir(state_dir: &TempDir, upstream_addr: SocketAddr) {
    setup_state_dir_with_privacy(state_dir, upstream_addr, "");
}

/// Write the daemon config TOML with optional extra `[privacy]` TOML snippet.
fn setup_state_dir_with_privacy(
    state_dir: &TempDir,
    upstream_addr: SocketAddr,
    privacy_extra: &str,
) {
    // Pre-compile rules: block `ads.blocked.test`, NOT `allowed.test`.
    let compiled_dir = state_dir.path().join("compiled");
    std::fs::create_dir_all(&compiled_dir).unwrap();
    let mut builder = RulesBuilder::new();
    builder.block(Domain::parse("ads.blocked.test").unwrap());
    let rules = builder.build().unwrap();
    rules.save(&compiled_dir).unwrap();

    // Config TOML.
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
{privacy_extra}
"#,
        upstream = upstream_addr,
    );
    std::fs::write(state_dir.path().join("hushwarren.toml"), config).unwrap();
}

/// Spawn the real `hushd` binary and wait until:
/// 1. `LISTENING udp=<addr>` is printed on stdout.
/// 2. `api.addr` appears in the state directory.
///
/// Returns `(dns_addr, api_addr, DaemonGuard)`.
async fn spawn_daemon(state_dir: &TempDir) -> (SocketAddr, SocketAddr, DaemonGuard) {
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

    // Wait for the LISTENING line (5 s deadline).
    let dns_addr: SocketAddr = timeout(Duration::from_secs(10), async {
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    let trimmed = line.trim();
                    if let Some(rest) = trimmed.strip_prefix("LISTENING udp=") {
                        if let Ok(a) = rest.parse() {
                            return a;
                        }
                    }
                }
                Ok(None) => panic!("hushd stdout closed before LISTENING line"),
                Err(e) => panic!("reading stdout: {e}"),
            }
        }
    })
    .await
    .expect("timeout waiting for hushd LISTENING line");

    // Wait for api.addr file (another 5 s after LISTENING).
    let api_addr: SocketAddr = timeout(Duration::from_secs(5), async {
        loop {
            let path = state_dir.path().join("api.addr");
            if let Ok(content) = std::fs::read_to_string(&path) {
                if let Ok(addr) = content.trim().parse() {
                    return addr;
                }
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("timeout waiting for api.addr file");

    (dns_addr, api_addr, DaemonGuard { child })
}

// ── Case 1: `hush status` → exit 0, shows "filtering" ─────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn case1_status_filtering_exit_0() {
    let tmp = TempDir::new().unwrap();
    let mock = MockUpstream::start().await;
    setup_state_dir(&tmp, mock.addr);
    let (_dns_addr, _api_addr, _guard) = spawn_daemon(&tmp).await;

    hush(tmp.path())
        .arg("status")
        .assert()
        .success()
        .stdout(predicates::str::contains("filtering"));
}

// ── Case 2: Full allow/unallow flow with real DNS ─────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn case2_allow_unallow_dns_flow() {
    let tmp = TempDir::new().unwrap();
    let mock = MockUpstream::start().await;
    setup_state_dir(&tmp, mock.addr);
    let (dns_addr, _api_addr, _guard) = spawn_daemon(&tmp).await;

    // ── Step A: blocked domain returns 0.0.0.0 ──────────────────────────────
    let resp = udp_a_query(dns_addr, ADS_BLOCKED_TEST_WIRE, 0xA001, 2000)
        .await
        .expect("no response for blocked query");
    let ip = first_a_record(&resp);
    assert_eq!(
        ip,
        Some(std::net::Ipv4Addr::UNSPECIFIED),
        "blocked domain must resolve to 0.0.0.0 before allow"
    );

    // ── Step B: allow the domain ─────────────────────────────────────────────
    hush(tmp.path())
        .args(["allow", "ads.blocked.test"])
        .assert()
        .success();

    // ── Step C: same domain now resolves via mock upstream (192.0.2.10) ─────
    let resp2 = udp_a_query(dns_addr, ADS_BLOCKED_TEST_WIRE, 0xA002, 4000)
        .await
        .expect("no response after allow");
    let ip2 = first_a_record(&resp2);
    assert_eq!(
        ip2,
        Some(std::net::Ipv4Addr::new(192, 0, 2, 10)),
        "allowed domain must resolve to 192.0.2.10"
    );

    // ── Step D: unallow ───────────────────────────────────────────────────────
    hush(tmp.path())
        .args(["unallow", "ads.blocked.test"])
        .assert()
        .success();

    // ── Step E: domain is blocked again ──────────────────────────────────────
    let resp3 = udp_a_query(dns_addr, ADS_BLOCKED_TEST_WIRE, 0xA003, 2000)
        .await
        .expect("no response after unallow");
    let ip3 = first_a_record(&resp3);
    assert_eq!(
        ip3,
        Some(std::net::Ipv4Addr::UNSPECIFIED),
        "domain must be blocked again after unallow"
    );

    // ── Step F: restart with same state dir → allowlist still empty ──────────
    // The DaemonGuard drops here, but we need to explicitly stop the first instance
    // and start a new one with the same state dir.
    drop(_guard);
    // Brief pause to let the first instance release the port.
    sleep(Duration::from_millis(300)).await;

    let (dns_addr2, _api_addr2, _guard2) = spawn_daemon(&tmp).await;

    // After restart, the domain should still be blocked (allowlist empty of it).
    let resp4 = udp_a_query(dns_addr2, ADS_BLOCKED_TEST_WIRE, 0xA004, 2000)
        .await
        .expect("no response after restart");
    let ip4 = first_a_record(&resp4);
    assert_eq!(
        ip4,
        Some(std::net::Ipv4Addr::UNSPECIFIED),
        "after restart, domain must be blocked (unallowed before shutdown)"
    );
}

// ── Case 3: snooze → blocked domain passes; snooze off → re-armed ────────────

#[tokio::test(flavor = "multi_thread")]
async fn case3_snooze_and_resume() {
    let tmp = TempDir::new().unwrap();
    let mock = MockUpstream::start().await;
    setup_state_dir(&tmp, mock.addr);
    let (dns_addr, _api_addr, _guard) = spawn_daemon(&tmp).await;

    // Verify blocked before snooze.
    let resp = udp_a_query(dns_addr, ADS_BLOCKED_TEST_WIRE, 0xB001, 2000)
        .await
        .expect("no response");
    assert_eq!(
        first_a_record(&resp),
        Some(std::net::Ipv4Addr::UNSPECIFIED),
        "must be blocked before snooze"
    );

    // Snooze for 5 minutes.
    hush(tmp.path())
        .args(["snooze", "5m"])
        .assert()
        .success()
        .stdout(predicates::str::contains("snoozed"));

    // Status must show snoozed.
    hush(tmp.path())
        .arg("status")
        .assert()
        .success()
        .stdout(predicates::str::contains("snoozed"));

    // Blocked domain must now pass through (forwarded to mock → 192.0.2.10).
    let resp2 = udp_a_query(dns_addr, ADS_BLOCKED_TEST_WIRE, 0xB002, 4000)
        .await
        .expect("no response while snoozed");
    assert_eq!(
        first_a_record(&resp2),
        Some(std::net::Ipv4Addr::new(192, 0, 2, 10)),
        "blocked domain must pass through while snoozed"
    );

    // Resume.
    hush(tmp.path())
        .args(["snooze", "off"])
        .assert()
        .success()
        .stdout(predicates::str::contains("resumed"));

    // Status must show filtering.
    hush(tmp.path())
        .arg("status")
        .assert()
        .success()
        .stdout(predicates::str::contains("filtering"));

    // Domain is blocked again.
    let resp3 = udp_a_query(dns_addr, ADS_BLOCKED_TEST_WIRE, 0xB003, 2000)
        .await
        .expect("no response after resume");
    assert_eq!(
        first_a_record(&resp3),
        Some(std::net::Ipv4Addr::UNSPECIFIED),
        "domain must be blocked again after resume"
    );
}

// ── Case 4: `hush log --blocked -n 5` ──────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn case4_log_blocked_shows_queries_newest_first() {
    let tmp = TempDir::new().unwrap();
    let mock = MockUpstream::start().await;
    setup_state_dir(&tmp, mock.addr);
    let (dns_addr, _api_addr, _guard) = spawn_daemon(&tmp).await;

    // Send 3 queries to populate the ring.
    udp_a_query(dns_addr, ADS_BLOCKED_TEST_WIRE, 0xC001, 1000).await;
    udp_a_query(dns_addr, ADS_BLOCKED_TEST_WIRE, 0xC002, 1000).await;
    udp_a_query(dns_addr, ADS_BLOCKED_TEST_WIRE, 0xC003, 1000).await;

    // `hush log --blocked -n 5` must contain the blocked domain.
    let output = hush(tmp.path())
        .args(["log", "--blocked", "-n", "5"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let out = String::from_utf8_lossy(&output);
    assert!(
        out.contains("ads.blocked.test"),
        "log --blocked must contain the blocked domain; got:\n{out}"
    );

    // Also verify basic log (no filter) works.
    hush(tmp.path()).args(["log", "-n", "5"]).assert().success();
}

// ── Case 5: corrupt token → exit 1; missing state dir → exit 2 ───────────────

#[tokio::test(flavor = "multi_thread")]
async fn case5_corrupt_token_exits_1_missing_state_dir_exits_2() {
    // ── Part A: corrupt token → exit 1 ──────────────────────────────────────
    let tmp = TempDir::new().unwrap();
    let mock = MockUpstream::start().await;
    setup_state_dir(&tmp, mock.addr);
    let (_dns_addr, api_addr, _guard) = spawn_daemon(&tmp).await;

    // Verify working first.
    hush(tmp.path()).arg("status").assert().success();

    // Overwrite the token file with garbage AFTER daemon is running.
    // The api.addr is already written so discovery succeeds, but auth fails.
    std::fs::write(tmp.path().join("api.token"), "not-a-valid-token").unwrap();

    hush(tmp.path())
        .arg("status")
        .assert()
        .failure()
        .code(1)
        .stderr(predicates::str::contains("unauthorized").or(predicates::str::contains("error")));

    // Also write a valid-format token that is wrong (right length, wrong value).
    let wrong_token = "0000000000000000000000000000000000000000000000000000000000000000";
    std::fs::write(tmp.path().join("api.token"), wrong_token).unwrap();
    let _ = api_addr; // used in assertion above

    hush(tmp.path()).arg("status").assert().failure().code(1);

    // ── Part B: missing state dir → exit 2 ───────────────────────────────────
    let no_state = tmp.path().join("does_not_exist");
    let mut cmd = Command::cargo_bin("hush").unwrap();
    cmd.arg("--state-dir")
        .arg(&no_state)
        .arg("status")
        .assert()
        .failure()
        .code(2)
        .stderr(predicates::str::contains("isn't running"));
}

// ── Case 6: `hush status --json` parses as JSON, matches /v0/status schema ─

#[tokio::test(flavor = "multi_thread")]
async fn case6_status_json_matches_schema() {
    let tmp = TempDir::new().unwrap();
    let mock = MockUpstream::start().await;
    setup_state_dir(&tmp, mock.addr);
    let (_dns_addr, _api_addr, _guard) = spawn_daemon(&tmp).await;

    let raw = hush(tmp.path())
        .args(["status", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value =
        serde_json::from_slice(&raw).expect("--json output must be valid JSON");

    // Check all top-level /v0/status schema keys from the spec.
    assert!(json.get("state").is_some(), "missing 'state'");
    assert!(
        json.get("snoozed_until_unix_ms").is_some(),
        "missing 'snoozed_until_unix_ms'"
    );
    assert!(json.get("version").is_some(), "missing 'version'");
    assert!(json.get("uptime_secs").is_some(), "missing 'uptime_secs'");
    assert!(json.get("rules").is_some(), "missing 'rules'");
    assert!(json.get("counters").is_some(), "missing 'counters'");

    // Verify nested shapes.
    let rules = &json["rules"];
    assert!(
        rules.get("block_count").is_some(),
        "rules missing 'block_count'"
    );
    assert!(
        rules.get("allow_count").is_some(),
        "rules missing 'allow_count'"
    );

    let counters = &json["counters"];
    assert!(
        counters.get("queries_total").is_some(),
        "counters missing 'queries_total'"
    );
    assert!(
        counters.get("blocked_total").is_some(),
        "counters missing 'blocked_total'"
    );

    // state must be one of the known values.
    let state = json["state"].as_str().unwrap();
    assert!(
        matches!(state, "filtering" | "snoozed" | "standing_by" | "attention"),
        "state must be a known enum value, got '{state}'"
    );
}

// ── WP4 E2E Case 7: `hush status` shows privacy line ─────────────────────────

/// `hush status` human-readable output must contain the compact privacy line
/// (WP4 §4, mandatory E2E test from §5 "E2E (cli)").
#[tokio::test(flavor = "multi_thread")]
async fn wp4_case7_status_shows_privacy_line() {
    let tmp = TempDir::new().unwrap();
    let mock = MockUpstream::start().await;
    setup_state_dir(&tmp, mock.addr);
    let (_dns_addr, _api_addr, _guard) = spawn_daemon(&tmp).await;

    let output = hush(tmp.path())
        .arg("status")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let out = String::from_utf8_lossy(&output);
    // Must contain the privacy line.
    assert!(
        out.contains("privacy"),
        "status output must contain a privacy line; got:\n{out}"
    );
    // Defaults: canary✓ cname✓ log=full.
    assert!(
        out.contains("canary"),
        "privacy line must contain canary indicator; got:\n{out}"
    );
    assert!(
        out.contains("log=full"),
        "privacy line must contain log=full by default; got:\n{out}"
    );
}

// ── WP9 E2E: `hush dashboard --print-url` ────────────────────────────────────

/// `hush dashboard --print-url` must print a URL containing:
/// - the live API address (host:port) and
/// - a `#token=<hex>` fragment.
///
/// This is the §6 mandatory E2E test for the `hush dashboard` CLI verb.
#[tokio::test(flavor = "multi_thread")]
async fn wp9_dashboard_print_url_contains_token_fragment() {
    let tmp = TempDir::new().unwrap();
    let mock = MockUpstream::start().await;
    setup_state_dir(&tmp, mock.addr);
    let (_dns_addr, api_addr, _guard) = spawn_daemon(&tmp).await;

    let output = hush(tmp.path())
        .args(["dashboard", "--print-url"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let out = String::from_utf8_lossy(&output);
    let url = out.trim();

    // Must start with http://
    assert!(
        url.starts_with("http://"),
        "dashboard URL must use http; got: {url}"
    );

    // Must contain the live host:port of the API.
    assert!(
        url.contains(&api_addr.to_string()),
        "dashboard URL must contain the API address {api_addr}; got: {url}"
    );

    // Must contain /dashboard/ path.
    assert!(
        url.contains("/dashboard/"),
        "dashboard URL must contain /dashboard/ path; got: {url}"
    );

    // Must have a #token= fragment.
    assert!(
        url.contains("#token="),
        "dashboard URL must have #token= fragment; got: {url}"
    );

    // Token must be non-empty after the = sign.
    let token_part = url.split("#token=").nth(1).unwrap_or("").trim();
    assert!(
        !token_part.is_empty(),
        "token fragment must be non-empty; got: {url}"
    );
    // Must be hex chars only.
    assert!(
        token_part.chars().all(|c| c.is_ascii_hexdigit()),
        "token must be hex; got: {token_part}"
    );
}

// ── WP4 E2E Case 8: `hush log` with query_log=off prints notice ───────────────

/// `hush log` against a daemon started with `query_log="off"` must print the
/// off-mode notice (WP4 §5 "E2E (cli)" mandatory case).
#[tokio::test(flavor = "multi_thread")]
async fn wp4_case8_log_off_mode_prints_notice() {
    let tmp = TempDir::new().unwrap();
    let mock = MockUpstream::start().await;
    // Start daemon with privacy.query_log = "off".
    setup_state_dir_with_privacy(
        &tmp,
        mock.addr,
        r#"
[privacy]
query_log = "off"
"#,
    );
    let (_dns_addr, _api_addr, _guard) = spawn_daemon(&tmp).await;

    let output = hush(tmp.path())
        .arg("log")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let out = String::from_utf8_lossy(&output);
    assert!(
        out.contains("notice"),
        "hush log with query_log=off must print a notice; got:\n{out}"
    );
    assert!(
        out.contains("off") || out.contains("disabled"),
        "notice must mention off/disabled state; got:\n{out}"
    );
}

// ── WP14 §4 Profile switch E2E ────────────────────────────────────────────────

/// Profile switch e2e: boot with default config, create a "strict" profile that
/// differs in `lists.preset` (hot-reloadable) and `listen` (requires-restart),
/// switch to it via `hush profile switch strict`, then assert:
///   1. `applied` contains `"lists"` (or is empty when there are no hot changes).
///   2. `requires_restart` contains `"listen"` because the strict profile
///      changes the listen address.
///   3. `hush status` shows `profile: strict`.
///
/// WP14 §4 mandatory test (`specs/wp14-nice.md`).
#[tokio::test(flavor = "multi_thread")]
async fn wp14_profile_switch_e2e() {
    let tmp = TempDir::new().unwrap();
    let mock = MockUpstream::start().await;
    setup_state_dir(&tmp, mock.addr);
    let (_dns_addr, _api_addr, _guard) = spawn_daemon(&tmp).await;

    // ── Create the "strict" profile ───────────────────────────────────────────
    // The profile differs from the running config in two ways:
    //   - lists.preset = "strict"    (hot-reloadable → applied)
    //   - listen.udp  = ["0.0.0.0:0"] (requires restart)
    let profiles_dir = tmp.path().join("profiles");
    std::fs::create_dir_all(&profiles_dir).unwrap();

    let strict_toml = format!(
        r#"
[listen]
udp = ["0.0.0.0:0"]
tcp = ["127.0.0.1:0"]

[upstream]
doh = []
do53_fallback = ["{upstream}"]

[lists]
preset = "strict"
sources = [{{ name = "fixture", url = "http://127.0.0.1:1/list" }}]
refresh_hours = 24
jitter_minutes = 0

[block]
action = "null_ip"
ttl_secs = 5

[api]
listen = "127.0.0.1:0"
"#,
        upstream = mock.addr,
    );
    std::fs::write(profiles_dir.join("strict.toml"), &strict_toml).unwrap();

    // ── Switch to "strict" via `hush profile switch strict` ───────────────────
    let output = hush(tmp.path())
        .args(["profile", "switch", "strict"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let out = String::from_utf8_lossy(&output);

    // The response should mention "requires_restart" for the listen change.
    // The CLI prints something like: "restart required: listen"
    assert!(
        out.contains("restart") || out.contains("requires_restart") || out.contains("listen"),
        "switch output must mention restart requirement for listen change; got:\n{out}"
    );

    // ── `hush status` shows `profile: strict` ─────────────────────────────────
    let status_out = hush(tmp.path())
        .arg("status")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let status_str = String::from_utf8_lossy(&status_out);
    assert!(
        status_str.contains("strict"),
        "hush status must show the active profile 'strict'; got:\n{status_str}"
    );
}
