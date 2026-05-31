//! TLS configuration for the QUIC endpoints.
//!
//! Two ways to get a server config: a self-signed cert for development
//! (returned to the caller so a client can pin it), or a cert/key loaded from
//! PEM for production. Clients pin the server certificate — the same
//! trust-on-first-use posture the app already uses for SSH host keys.

use std::sync::{Arc, Once};
use std::time::Duration;

use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::ALPN;

static CRYPTO_INIT: Once = Once::new();

/// Install a process-wide rustls crypto provider (ring) exactly once. rustls
/// 0.23 requires a default provider before building any TLS config.
fn install_crypto_provider() {
    CRYPTO_INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn idle_timeout() -> quinn::IdleTimeout {
    quinn::IdleTimeout::try_from(Duration::from_secs(30)).expect("30s fits in a VarInt")
}

fn transport() -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    t.max_idle_timeout(Some(idle_timeout()));
    t.keep_alive_interval(Some(Duration::from_secs(10)));
    Arc::new(t)
}

fn build_server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<quinn::ServerConfig> {
    let mut rustls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("build server TLS config")?;
    rustls_config.alpn_protocols = vec![ALPN.to_vec()];

    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)
        .context("build QUIC server crypto config")?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(quic));
    config.transport_config(transport());
    Ok(config)
}

/// Build a server config with a freshly generated self-signed certificate.
/// Returns the certificate so a client can pin it (dev / TOFU).
pub fn self_signed_server_config() -> Result<(quinn::ServerConfig, CertificateDer<'static>)> {
    install_crypto_provider();
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .context("generate self-signed certificate")?;
    let cert_der = certified.cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.key_pair.serialize_der(),
    ));
    let config = build_server_config(vec![cert_der.clone()], key_der)?;
    Ok((config, cert_der))
}

/// Build a server config from a PEM cert chain + private key (production).
pub fn server_config_from_pem(cert_pem: &str, key_pem: &str) -> Result<quinn::ServerConfig> {
    install_crypto_provider();
    let certs = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse certificate PEM")?;
    anyhow::ensure!(!certs.is_empty(), "no certificates in PEM");
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .context("parse private key PEM")?
        .context("no private key in PEM")?;
    build_server_config(certs, key)
}

/// Build a client config that trusts exactly the given (pinned) server cert.
pub fn pinned_client_config(server_cert: &CertificateDer<'static>) -> Result<quinn::ClientConfig> {
    install_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(server_cert.clone()).context("pin server cert")?;

    let mut rustls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    rustls_config.alpn_protocols = vec![ALPN.to_vec()];

    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)
        .context("build QUIC client crypto config")?;
    let mut config = quinn::ClientConfig::new(Arc::new(quic));
    config.transport_config(transport());
    Ok(config)
}
