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

    let hook: Arc<dyn AuthHook> = match &config.auth_webhook_url {
        Some(url) => {
            tracing::info!(%url, "authorizing clients via HTTP webhook");
            Arc::new(HttpAuthHook::new(url))
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
