//! `shark-gateway` — the keep-alive SSH gateway daemon.
//!
//! Thin binary over [`gw_server::serve`]: load config, pick the auth hook
//! (HTTP webhook if configured, else allow-all), and serve.

use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use gw_core::quota::{AllowAll, AuthHook};
use gw_server::{serve, Config, HttpAuthHook};

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

    // Prefer the control-plane base URL; fall back to the legacy webhook URL
    // (from which a base is derived). Unset → allow everyone (self-host).
    let base = config
        .control_plane_url
        .clone()
        .or_else(|| config.auth_webhook_url.clone());
    let hook: Arc<dyn AuthHook> = match base {
        Some(base) => {
            tracing::info!(%base, has_key = config.gateway_key.is_some(), "authorizing via control plane");
            Arc::new(HttpAuthHook::new(base, config.gateway_key.clone()))
        }
        None => Arc::new(AllowAll),
    };

    serve(config, hook).await
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new("shark_gateway=info,gw_server=info,gw_core=info,gw_transport=info,gw_ssh=info")
    });
    tracing_subscriber::fmt().with_env_filter(filter).init();
}
