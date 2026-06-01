//! Library surface of the gateway. [`serve`] runs the whole thing and lets an
//! embedder choose the [`AuthHook`](gw_core::quota::AuthHook): the bundled
//! binary uses `AllowAll` (self-host) or the built-in [`HttpAuthHook`] webhook,
//! but anyone can build a gateway with their own hook.

use std::sync::Arc;

use anyhow::{Context, Result};
use gw_core::quota::AuthHook;
use gw_core::SessionManager;
use gw_transport::Server;

pub mod config;
pub mod http_hook;
mod handler;

pub use config::Config;
pub use http_hook::HttpAuthHook;

/// Bind the QUIC endpoint and serve clients until the endpoint closes,
/// authorizing each connection with `hook`.
pub async fn serve(config: Config, hook: Arc<dyn AuthHook>) -> Result<()> {
    let manager = SessionManager::new();
    let server = build_server(&config)?;

    tracing::info!(
        protocol_version = gw_proto::PROTOCOL_VERSION,
        listen = %config.listen,
        tls = config.tls_cert.is_some(),
        webhook = config.auth_webhook_url.is_some(),
        "shark-gateway listening"
    );

    while let Some(accepted) = server.accept().await {
        match accepted {
            Ok(client) => {
                let manager = manager.clone();
                let hook = hook.clone();
                tokio::spawn(handler::handle_connection(manager, hook, client));
            }
            Err(error) => tracing::warn!(%error, "failed to accept client"),
        }
    }
    Ok(())
}

/// Bind the QUIC endpoint: a configured PEM cert in production, otherwise a
/// self-signed dev certificate (clients must pin it out-of-band).
fn build_server(config: &Config) -> Result<Server> {
    match (&config.tls_cert, &config.tls_key) {
        (Some(cert_path), Some(key_path)) => {
            let cert = std::fs::read_to_string(cert_path)
                .with_context(|| format!("read tls_cert {cert_path}"))?;
            let key = std::fs::read_to_string(key_path)
                .with_context(|| format!("read tls_key {key_path}"))?;
            let server_config = gw_transport::tls::server_config_from_pem(&cert, &key)?;
            Server::bind(config.listen, server_config).context("bind QUIC endpoint")
        }
        _ => {
            tracing::warn!("no TLS cert configured; generating a self-signed dev certificate");
            let (server, _cert) = Server::bind_self_signed(config.listen)
                .context("bind QUIC endpoint (self-signed)")?;
            Ok(server)
        }
    }
}
