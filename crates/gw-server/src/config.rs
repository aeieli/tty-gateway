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
    pub auth_webhook_url: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([0, 0, 0, 0], gw_transport::DEFAULT_PORT)),
            tls_cert: None,
            tls_key: None,
            auth_webhook_url: None,
        }
    }
}

impl Config {
    /// Load config from `path`, falling back to defaults if the file is absent.
    pub fn load(path: &str) -> Result<Self> {
        if !Path::new(path).exists() {
            tracing::warn!(path, "config file not found; using defaults");
            return Ok(Self::default());
        }
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading config {path}"))?;
        let config: Config =
            toml::from_str(&text).with_context(|| format!("parsing config {path}"))?;
        Ok(config)
    }
}
