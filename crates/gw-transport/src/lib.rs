//! `gw-transport` — the resilient App↔Gateway link.
//!
//! QUIC (via `quinn`) with TLS 1.3, length-prefixed [`gw_proto`] framing over a
//! bidirectional control stream, and connection migration so a roaming mobile
//! client keeps its session across network changes.
//!
//! - [`Server`] binds the gateway endpoint and accepts [`ClientConnection`]s.
//! - [`Client`] connects to a gateway (used by tests and the iOS client core).
//! - [`tls`] builds self-signed (dev) or PEM (prod) server configs and pinned
//!   client configs.

pub mod client;
pub mod framed;
pub mod server;
pub mod tls;

pub use client::Client;
pub use framed::{FramedRecv, FramedSend, Result, TransportError};
pub use server::{ClientConnection, Server};
pub use tls::{pinned_client_config, self_signed_server_config, server_config_from_pem};

pub use rustls::pki_types::CertificateDer;

/// Default UDP port the gateway's QUIC endpoint binds to.
pub const DEFAULT_PORT: u16 = 4433;

/// ALPN protocol identifier negotiated on the QUIC/TLS handshake.
pub const ALPN: &[u8] = b"sharkgw/1";
