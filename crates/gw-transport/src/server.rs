//! Gateway-side QUIC endpoint: bind, then accept clients and their control
//! stream.

use std::net::SocketAddr;

use rustls::pki_types::CertificateDer;

use crate::framed::{FramedRecv, FramedSend, Result};
use crate::tls;

/// One accepted client: the QUIC connection plus the framed control stream.
pub struct ClientConnection {
    pub conn: quinn::Connection,
    pub send: FramedSend,
    pub recv: FramedRecv,
}

impl ClientConnection {
    /// Remote address of the client (updates across QUIC migration / roaming).
    pub fn remote_address(&self) -> SocketAddr {
        self.conn.remote_address()
    }
}

/// The gateway's listening QUIC endpoint.
pub struct Server {
    endpoint: quinn::Endpoint,
}

impl Server {
    /// Bind with a self-signed dev certificate. Returns the server and its
    /// certificate so a client can pin it.
    pub fn bind_self_signed(
        addr: SocketAddr,
    ) -> Result<(Self, CertificateDer<'static>)> {
        let (config, cert) = tls::self_signed_server_config()?;
        Ok((Self::bind(addr, config)?, cert))
    }

    /// Bind with a prepared server config (e.g. from PEM).
    pub fn bind(addr: SocketAddr, config: quinn::ServerConfig) -> Result<Self> {
        let endpoint = quinn::Endpoint::server(config, addr)?;
        Ok(Self { endpoint })
    }

    /// The actual bound address (useful when binding to port 0 in tests).
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }

    /// Accept the next client and its control stream (the first bidi stream).
    /// Returns `None` when the endpoint is closed.
    pub async fn accept(&self) -> Option<Result<ClientConnection>> {
        let incoming = self.endpoint.accept().await?;
        Some(accept_control(incoming).await)
    }

    /// Stop accepting and close the endpoint, waiting for connections to drain.
    pub async fn shutdown(&self) {
        self.endpoint.close(0u32.into(), b"shutdown");
        self.endpoint.wait_idle().await;
    }
}

async fn accept_control(incoming: quinn::Incoming) -> Result<ClientConnection> {
    let conn = incoming.await?;
    let (send, recv) = conn.accept_bi().await?;
    Ok(ClientConnection {
        conn,
        send: FramedSend::new(send),
        recv: FramedRecv::new(recv),
    })
}
