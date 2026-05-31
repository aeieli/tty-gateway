//! Client-side QUIC endpoint (used by tests and the iOS client's Rust core):
//! connect to a gateway and open the control stream.

use std::net::SocketAddr;

use crate::framed::{FramedRecv, FramedSend, Result};
use crate::server::ClientConnection;

/// A client QUIC endpoint.
pub struct Client {
    endpoint: quinn::Endpoint,
}

impl Client {
    /// Create a client endpoint bound to an ephemeral local UDP port.
    pub fn new(config: quinn::ClientConfig) -> Result<Self> {
        let mut endpoint = quinn::Endpoint::client(SocketAddr::from(([0, 0, 0, 0], 0)))?;
        endpoint.set_default_client_config(config);
        Ok(Self { endpoint })
    }

    /// Connect to a gateway and open the control stream. The caller should send
    /// its `Hello` immediately — opening a QUIC stream only materializes it on
    /// the wire once the first bytes are written, which is also what unblocks
    /// the server's `accept`.
    pub async fn connect(&self, addr: SocketAddr, server_name: &str) -> Result<ClientConnection> {
        let conn = self.endpoint.connect(addr, server_name)?.await?;
        let (send, recv) = conn.open_bi().await?;
        Ok(ClientConnection {
            conn,
            send: FramedSend::new(send),
            recv: FramedRecv::new(recv),
        })
    }

    /// Wait for all connections to close cleanly.
    pub async fn wait_idle(&self) {
        self.endpoint.wait_idle().await;
    }
}
