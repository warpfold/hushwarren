//! Inbound DoT (DNS-over-TLS) and DoQ (DNS-over-QUIC) listener setup.
//!
//! Implements `specs/wp14-nice.md` §1.  Both protocols feed the SAME
//! [`SinkholeHandler`] — zero pipeline forks.
//!
//! ## Self-signed certificate path
//!
//! When `cert_path` / `key_path` are empty, a self-signed certificate is
//! generated once into `state_dir/inbound-tls/` using `rcgen` (MIT/Apache-2.0).
//! The certificate includes the configured bind IPs and the machine hostname as
//! SANs.  Key files are created with mode 0o600 on Unix.  The certificate is
//! regenerated when the SAN set changes (detected by comparing the stored
//! `san-fingerprint` marker file with the current SAN list).
//!
//! ## DoQ verdict (WP14 §1)
//!
//! hickory-server 0.26.1 exposes `register_quic_listener_and_tls_config` behind
//! the `quic-ring` feature flag, which has been enabled and verified to compile.
//! **DoQ is implemented** and gated behind `inbound_tls.doq = true`.
//!
//! ## Client-trust note
//!
//! A self-signed certificate requires manual trust installation on each client.
//! Android Private DNS (DoT) requires a trusted cert + hostname.  This feature
//! mainly serves LAN power users.  See `docs/network-guard.md`.

use crate::dns::SinkholeHandler;
use hickory_server::server::Server;
use hush_core::config::InboundTlsConfig;
use rcgen::{CertificateParams, DistinguishedName, DnType, SanType};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use std::{
    net::{IpAddr as StdIpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use thiserror::Error;
use tokio::net::{TcpListener, UdpSocket};
use tracing::info;

/// Errors from inbound TLS setup.
#[derive(Debug, Error)]
pub enum InboundTlsError {
    /// I/O error (bind, file read/write).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Certificate generation failed.
    #[error("certificate generation error: {0}")]
    CertGen(String),
    /// TLS configuration error.
    #[error("TLS configuration error: {0}")]
    TlsConfig(String),
}

/// Bound inbound TLS listener addresses.
pub struct BoundInboundTls {
    /// Bound DoT TCP addresses.
    pub dot_addrs: Vec<SocketAddr>,
    /// Bound DoQ UDP addresses (empty when DoQ is disabled).
    pub doq_addrs: Vec<SocketAddr>,
}

/// Bind inbound DoT and optionally DoQ listeners.
///
/// Both protocols use the same [`SinkholeHandler`] — zero pipeline forks.
/// Returns the bound addresses and a background task handle.
///
/// `dot_port` is the TCP port to bind DoT on (and DoQ on the same UDP port).
/// Pass `853` for production; pass `0` in tests to use an OS-assigned port.
pub async fn bind_inbound_tls(
    cfg: &InboundTlsConfig,
    handler: SinkholeHandler,
    state_dir: &std::path::Path,
    cancel: tokio_util::sync::CancellationToken,
    dot_port: u16,
) -> Result<(BoundInboundTls, tokio::task::JoinHandle<()>), InboundTlsError> {
    let cert_resolver = build_cert_resolver(cfg, state_dir)?;

    let mut server = Server::new(handler);
    let mut dot_addrs = Vec::new();
    let mut doq_addrs = Vec::new();

    for ip_str in &cfg.bind {
        let ip: StdIpAddr = ip_str.parse().map_err(|e| {
            InboundTlsError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid bind IP {ip_str}: {e}"),
            ))
        })?;

        // DoT on the requested TCP port (853 in production, 0 for ephemeral in tests).
        let tcp_listener = TcpListener::bind(SocketAddr::new(ip, dot_port)).await?;
        let actual_dot = tcp_listener.local_addr()?;
        let tls_cfg_dot = build_server_config(b"dot", Arc::clone(&cert_resolver))?;
        server
            .register_tls_listener_with_tls_config(
                tcp_listener,
                Duration::from_secs(5),
                tls_cfg_dot,
            )
            .map_err(InboundTlsError::Io)?;
        dot_addrs.push(actual_dot);
        info!(addr = %actual_dot, "inbound DoT listener bound");

        // DoQ on the same port/UDP when enabled.
        if cfg.doq {
            let udp_sock = UdpSocket::bind(SocketAddr::new(ip, dot_port)).await?;
            let actual_doq = udp_sock.local_addr()?;
            let tls_cfg_doq = build_server_config(b"doq", Arc::clone(&cert_resolver))?;
            server
                .register_quic_listener_and_tls_config(
                    udp_sock,
                    Duration::from_secs(5),
                    tls_cfg_doq,
                )
                .map_err(|e| InboundTlsError::TlsConfig(format!("DoQ listener error: {e}")))?;
            doq_addrs.push(actual_doq);
            info!(addr = %actual_doq, "inbound DoQ listener bound");
        }
    }

    let task = tokio::spawn(async move {
        tokio::select! {
            result = server.block_until_done() => {
                if let Err(e) = result {
                    tracing::error!(error = %e, "inbound TLS server error");
                }
            }
            () = cancel.cancelled() => {
                if let Err(e) = server.shutdown_gracefully().await {
                    tracing::error!(error = %e, "inbound TLS server shutdown error");
                }
            }
        }
    });

    Ok((
        BoundInboundTls {
            dot_addrs,
            doq_addrs,
        },
        task,
    ))
}

/// A certificate resolver that exposes the leaf certificate bytes for tests.
///
/// Integration tests use this to construct a client-side trust store from the
/// generated self-signed certificate without touching the filesystem after
/// startup.
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct TestCertResolver {
    key: Arc<CertifiedKey>,
    /// DER bytes of the leaf certificate (for building a test client trust store).
    pub cert_der: Vec<u8>,
}

impl ResolvesServerCert for TestCertResolver {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.key))
    }
}

/// Build a [`TestCertResolver`] for integration tests.
///
/// Generates (or reuses) a self-signed cert in `state_dir` for `bind_ip`.
#[allow(dead_code)]
pub(crate) fn build_test_cert_resolver(
    state_dir: &std::path::Path,
    bind_ip: &str,
) -> Result<Arc<TestCertResolver>, InboundTlsError> {
    let cfg = InboundTlsConfig {
        enabled: true,
        bind: vec![bind_ip.to_string()],
        cert_path: String::new(),
        key_path: String::new(),
        doq: false,
    };

    let (cert_ders, key_der) = ensure_self_signed_cert(&cfg, state_dir)?;
    let first_cert_der = cert_ders.first().map_or(Vec::new(), |c| c.clone());
    let certified_key = build_certified_key(cert_ders, key_der)?;

    Ok(Arc::new(TestCertResolver {
        key: Arc::new(certified_key),
        cert_der: first_cert_der,
    }))
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// A simple `ResolvesServerCert` that always returns the same certified key.
#[derive(Debug)]
struct StaticCertResolver {
    key: Arc<CertifiedKey>,
}

impl ResolvesServerCert for StaticCertResolver {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.key))
    }
}

fn build_cert_resolver(
    cfg: &InboundTlsConfig,
    state_dir: &std::path::Path,
) -> Result<Arc<dyn ResolvesServerCert>, InboundTlsError> {
    let (cert_ders, key_der) = if cfg.cert_path.is_empty() {
        ensure_self_signed_cert(cfg, state_dir)?
    } else {
        let cert_pem = std::fs::read(&cfg.cert_path)?;
        let key_pem = std::fs::read(&cfg.key_path)?;
        pem_to_der(&cert_pem, &key_pem)?
    };

    let certified_key = build_certified_key(cert_ders, key_der)?;
    Ok(Arc::new(StaticCertResolver {
        key: Arc::new(certified_key),
    }))
}

fn build_server_config(
    alpn: &[u8],
    cert_resolver: Arc<dyn ResolvesServerCert>,
) -> Result<Arc<rustls::ServerConfig>, InboundTlsError> {
    hickory_server::server::default_tls_server_config(alpn, cert_resolver)
        .map(Arc::new)
        .map_err(|e| InboundTlsError::TlsConfig(e.to_string()))
}

fn pem_to_der(cert_pem: &[u8], key_pem: &[u8]) -> Result<(Vec<Vec<u8>>, Vec<u8>), InboundTlsError> {
    use rustls::pki_types::pem::PemObject as _;

    let cert_ders: Vec<Vec<u8>> = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| InboundTlsError::TlsConfig(format!("cert PEM parse error: {e}")))?
        .into_iter()
        .map(|c| c.as_ref().to_vec())
        .collect();

    if cert_ders.is_empty() {
        return Err(InboundTlsError::TlsConfig(
            "no certificate found in cert_path".to_owned(),
        ));
    }

    let key_der = PrivateKeyDer::from_pem_slice(key_pem)
        .map_err(|e| InboundTlsError::TlsConfig(format!("key PEM parse error: {e}")))?
        .secret_der()
        .to_vec();

    Ok((cert_ders, key_der))
}

fn build_certified_key(
    cert_ders: Vec<Vec<u8>>,
    key_der: Vec<u8>,
) -> Result<CertifiedKey, InboundTlsError> {
    use rustls::crypto::ring::sign::any_supported_type;

    let certs: Vec<CertificateDer<'static>> =
        cert_ders.into_iter().map(CertificateDer::from).collect();
    let key = PrivateKeyDer::try_from(key_der)
        .map_err(|e| InboundTlsError::TlsConfig(format!("invalid private key DER: {e}")))?;
    let signing_key = any_supported_type(&key)
        .map_err(|e| InboundTlsError::TlsConfig(format!("unsupported key type: {e}")))?;

    Ok(CertifiedKey::new(certs, signing_key))
}

fn san_fingerprint_path(tls_dir: &std::path::Path) -> PathBuf {
    tls_dir.join("san-fingerprint")
}

fn san_fingerprint(bind_ips: &[String]) -> String {
    let hostname = hostname_or_localhost();
    let mut sans: Vec<String> = bind_ips.to_vec();
    sans.push(hostname);
    sans.sort();
    sans.join(",")
}

/// Ensure a self-signed certificate exists in `state_dir/inbound-tls/`.
///
/// Returns the DER-encoded cert chain + key.  Regenerates when SANs change.
///
/// `pub` so integration tests can pre-generate the cert and load it into a
/// trust store before starting the listener.
pub fn ensure_self_signed_cert(
    cfg: &InboundTlsConfig,
    state_dir: &std::path::Path,
) -> Result<(Vec<Vec<u8>>, Vec<u8>), InboundTlsError> {
    let tls_dir = state_dir.join("inbound-tls");
    std::fs::create_dir_all(&tls_dir)?;

    let cert_path = tls_dir.join("cert.pem");
    let key_path = tls_dir.join("key.pem");
    let fp_path = san_fingerprint_path(&tls_dir);
    let current_fp = san_fingerprint(&cfg.bind);

    let needs_regen = if cert_path.exists() && key_path.exists() && fp_path.exists() {
        std::fs::read_to_string(&fp_path)
            .map(|s| s.trim() != current_fp.as_str())
            .unwrap_or(true)
    } else {
        true
    };

    if needs_regen {
        info!(tls_dir = %tls_dir.display(), "generating self-signed inbound TLS certificate");
        generate_self_signed_cert(cfg, &cert_path, &key_path, &fp_path, &current_fp)?;
    }

    let cert_pem = std::fs::read(&cert_path)?;
    let key_pem = std::fs::read(&key_path)?;
    pem_to_der(&cert_pem, &key_pem)
}

fn generate_self_signed_cert(
    cfg: &InboundTlsConfig,
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
    fp_path: &std::path::Path,
    current_fp: &str,
) -> Result<(), InboundTlsError> {
    let hostname = hostname_or_localhost();
    let mut san_list: Vec<SanType> =
        vec![SanType::DnsName(hostname.as_str().try_into().map_err(
            |e| InboundTlsError::CertGen(format!("invalid hostname SAN: {e}")),
        )?)];

    for ip_str in &cfg.bind {
        if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
            san_list.push(SanType::IpAddress(ip));
        }
    }

    let mut params = CertificateParams::new(vec![])
        .map_err(|e| InboundTlsError::CertGen(format!("cert params error: {e}")))?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "hushwarren inbound DNS");
    dn.push(DnType::OrganizationName, "hushwarren");
    params.distinguished_name = dn;
    params.subject_alt_names = san_list;

    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| InboundTlsError::CertGen(format!("key generation error: {e}")))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| InboundTlsError::CertGen(format!("certificate signing error: {e}")))?;

    std::fs::write(cert_path, cert.pem().as_bytes())?;
    write_key_file(key_path, key_pair.serialize_pem().as_bytes())?;
    std::fs::write(fp_path, current_fp)?;

    info!(
        cert = %cert_path.display(),
        key = %key_path.display(),
        "self-signed inbound TLS certificate written"
    );
    Ok(())
}

fn write_key_file(path: &std::path::Path, content: &[u8]) -> Result<(), InboundTlsError> {
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(content)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, content)?;
        Ok(())
    }
}

fn hostname_or_localhost() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "localhost".to_owned())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn san_fingerprint_is_stable() {
        let ips = vec!["127.0.0.1".to_string(), "192.168.1.1".to_string()];
        let fp1 = san_fingerprint(&ips);
        let fp2 = san_fingerprint(&ips);
        assert_eq!(fp1, fp2, "fingerprint must be deterministic");
    }

    #[test]
    fn san_fingerprint_changes_when_ips_change() {
        let fp1 = san_fingerprint(&["127.0.0.1".to_string()]);
        let fp2 = san_fingerprint(&["127.0.0.1".to_string(), "10.0.0.1".to_string()]);
        assert_ne!(fp1, fp2, "fingerprint must change when IPs change");
    }

    #[test]
    fn self_signed_cert_generates_and_loads() {
        let tmp = TempDir::new().unwrap();
        let cfg = InboundTlsConfig {
            enabled: true,
            bind: vec!["127.0.0.1".to_string()],
            cert_path: String::new(),
            key_path: String::new(),
            doq: false,
        };
        let (cert_ders, key_der) = ensure_self_signed_cert(&cfg, tmp.path()).unwrap();
        assert!(!cert_ders.is_empty(), "cert chain must be non-empty");
        assert!(!key_der.is_empty(), "key must be non-empty");
    }

    #[test]
    fn self_signed_cert_idempotent() {
        let tmp = TempDir::new().unwrap();
        let cfg = InboundTlsConfig {
            enabled: true,
            bind: vec!["127.0.0.1".to_string()],
            cert_path: String::new(),
            key_path: String::new(),
            doq: false,
        };
        let _ = ensure_self_signed_cert(&cfg, tmp.path()).unwrap();
        let fp_path = san_fingerprint_path(&tmp.path().join("inbound-tls"));
        let fp1 = std::fs::read_to_string(&fp_path).unwrap();
        let _ = ensure_self_signed_cert(&cfg, tmp.path()).unwrap();
        let fp2 = std::fs::read_to_string(&fp_path).unwrap();
        assert_eq!(fp1, fp2, "fingerprint must not change on idempotent call");
    }

    #[test]
    fn self_signed_cert_regenerates_on_san_change() {
        let tmp = TempDir::new().unwrap();
        let cfg1 = InboundTlsConfig {
            enabled: true,
            bind: vec!["127.0.0.1".to_string()],
            cert_path: String::new(),
            key_path: String::new(),
            doq: false,
        };
        let _ = ensure_self_signed_cert(&cfg1, tmp.path()).unwrap();
        let cert_before = std::fs::read_to_string(tmp.path().join("inbound-tls/cert.pem")).unwrap();

        let cfg2 = InboundTlsConfig {
            bind: vec!["127.0.0.1".to_string(), "10.0.0.1".to_string()],
            ..cfg1
        };
        let _ = ensure_self_signed_cert(&cfg2, tmp.path()).unwrap();
        let cert_after = std::fs::read_to_string(tmp.path().join("inbound-tls/cert.pem")).unwrap();
        assert_ne!(
            cert_before, cert_after,
            "cert must regenerate when SANs change"
        );
    }

    #[test]
    fn hostname_or_localhost_non_empty() {
        let h = hostname_or_localhost();
        assert!(!h.is_empty());
    }
}
