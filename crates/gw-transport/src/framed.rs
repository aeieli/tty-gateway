//! Length-prefixed [`gw_proto`] frames over a QUIC bidirectional stream.
//!
//! A connection's control channel is one bidi stream. We split it into an
//! independent [`FramedSend`] and [`FramedRecv`] so a session can pump
//! keystrokes out and terminal output in from separate tasks.

use serde::{de::DeserializeOwned, Serialize};

/// Length prefix width (big-endian u32), matching `gw_proto`'s framing.
const LEN_PREFIX: usize = 4;

pub type Result<T> = std::result::Result<T, TransportError>;

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("connection: {0}")]
    Connection(#[from] quinn::ConnectionError),
    #[error("connect: {0}")]
    Connect(#[from] quinn::ConnectError),
    #[error("write: {0}")]
    Write(#[from] quinn::WriteError),
    #[error("read: {0}")]
    Read(#[from] quinn::ReadExactError),
    #[error("codec: {0}")]
    Codec(#[from] gw_proto::CodecError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame too large: {0} bytes")]
    FrameTooLarge(usize),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Write half: serialize frames and write them length-prefixed.
pub struct FramedSend {
    inner: quinn::SendStream,
}

impl FramedSend {
    pub(crate) fn new(inner: quinn::SendStream) -> Self {
        Self { inner }
    }

    /// Serialize and write one frame.
    pub async fn send<T: Serialize>(&mut self, frame: &T) -> Result<()> {
        let bytes = gw_proto::encode_framed(frame)?;
        self.inner.write_all(&bytes).await?;
        Ok(())
    }

    /// Signal end-of-stream (best effort).
    pub fn finish(&mut self) {
        let _ = self.inner.finish();
    }
}

/// Read half: read length-prefixed frames and deserialize them.
pub struct FramedRecv {
    inner: quinn::RecvStream,
}

impl FramedRecv {
    pub(crate) fn new(inner: quinn::RecvStream) -> Self {
        Self { inner }
    }

    /// Read one frame, blocking until a full frame arrives.
    pub async fn recv<T: DeserializeOwned>(&mut self) -> Result<T> {
        let mut len = [0u8; LEN_PREFIX];
        self.inner.read_exact(&mut len).await?;
        let n = u32::from_be_bytes(len) as usize;
        if n > gw_proto::MAX_FRAME_LEN {
            return Err(TransportError::FrameTooLarge(n));
        }
        let mut body = vec![0u8; n];
        self.inner.read_exact(&mut body).await?;
        Ok(gw_proto::decode(&body)?)
    }
}
