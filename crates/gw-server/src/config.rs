//! Daemon configuration, loaded from a TOML file (with sane defaults).

use anyhow::{Context, Result};
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    /// UDP socket the QUIC endpoint binds to.
    pub listen: SocketAddr,
    /// TLS certificate chain (PEM). If unset, the gateway generates a
    /// self-signed pair for development.
    pub tls_cert: Option<String>,
    /// TLS private key (PEM). Required if `tls_cert` is set.
    pub tls_key: Option<String>,
    /// If set, each connecting client is authorized by POSTing to this URL
    /// (an HTTP authorization webhook). Unset → allow everyone (self-host).
    ///
    /// This is the legacy single-endpoint form; `control_plane_url` is
    /// preferred and additionally enables session + usage reporting.
    pub auth_webhook_url: Option<String>,
    /// Base URL of the control plane, e.g. `http://cloud-api:8080`. When set,
    /// the gateway authorizes clients *and* reports sessions/usage to it. Takes
    /// precedence over `auth_webhook_url` (from which a base is otherwise
    /// derived). Unset and no webhook → allow everyone (self-host).
    pub control_plane_url: Option<String>,
    /// Shared secret sent as the `X-Gateway-Key` header on control-plane calls.
    pub gateway_key: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([0, 0, 0, 0], gw_transport::DEFAULT_PORT)),
            tls_cert: None,
            tls_key: None,
            auth_webhook_url: None,
            control_plane_url: None,
            gateway_key: None,
        }
    }
}

impl Config {
    /// Load config from `path` (falling back to defaults if absent), then apply
    /// environment overrides. Secrets like the gateway key are taken from the
    /// environment so they need not live in the (public) config file:
    ///   - `SHARK_CONTROL_PLANE_URL` → `control_plane_url`
    ///   - `SHARK_GATEWAY_KEY`       → `gateway_key`
    pub fn load(path: &str) -> Result<Self> {
        let mut config = if Path::new(path).exists() {
            let text =
                std::fs::read_to_string(path).with_context(|| format!("reading config {path}"))?;
            toml::from_str(&text).with_context(|| format!("parsing config {path}"))?
        } else {
            tracing::warn!(path, "config file not found; using defaults");
            Self::default()
        };

        if let Ok(v) = std::env::var("SHARK_CONTROL_PLANE_URL") {
            if !v.is_empty() {
                config.control_plane_url = Some(v);
            }
        }
        if let Ok(v) = std::env::var("SHARK_GATEWAY_KEY") {
            if !v.is_empty() {
                config.gateway_key = Some(v);
            }
        }
        Ok(config)
    }
}
