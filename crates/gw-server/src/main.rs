//! `shark-gateway` — the keep-alive SSH gateway daemon.
//!
//! Binds a QUIC endpoint, then for each client runs the keep-alive handler
//! (`handler::handle_connection`) which proxies an SSH session that survives
//! client drops.

use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use gw_core::quota::{AllowAll, AuthHook};
use gw_core::SessionManager;
use gw_transport::Server;

mod config;
mod handler;

use config::Config;

#[derive(Parser, Debug)]
#[command(name = "shark-gateway", version, about = "SharkTTY keep-alive SSH gateway")]
struct Cli {
    /// Path to the TOML config file.
    #[arg(short, long, default_value = "shark-gateway.toml")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let cli = Cli::parse();
    let config = Config::load(&cli.config)?;
    let manager = SessionManager::new();
    // OSS / self-host: no control plane, every client allowed with no limits.
    // The SaaS build swaps in an AuthHook backed by the control-plane backend.
    let hook: Arc<dyn AuthHook> = Arc::new(AllowAll);

    let server = build_server(&config)?;
    tracing::info!(
        protocol_version = gw_proto::PROTOCOL_VERSION,
        listen = %config.listen,
        tls = config.tls_cert.is_some(),
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

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new("shark_gateway=info,gw_core=info,gw_transport=info,gw_ssh=info")
    });
    tracing_subscriber::fmt().with_env_filter(filter).init();
}
