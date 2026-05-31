//! Compact, length-prefixed framing over a byte stream.
//!
//! Frames are serialized with `postcard` (small, no schema negotiation needed
//! since both ends share this crate). `encode_framed` prepends a 4-byte
//! big-endian length so a stream reader knows where each frame ends.

use serde::{de::DeserializeOwned, Serialize};

/// Hard cap on a single encoded frame. Guards a stream reader against a hostile
/// or corrupt length prefix asking it to allocate gigabytes.
pub const MAX_FRAME_LEN: usize = 8 * 1024 * 1024;

/// Length prefix width, in bytes.
pub const LEN_PREFIX: usize = 4;

#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("serialize frame: {0}")]
    Serialize(postcard::Error),
    #[error("deserialize frame: {0}")]
    Deserialize(postcard::Error),
    #[error("frame too large: {0} bytes")]
    TooLarge(usize),
}

/// Serialize a frame to bytes (no length prefix).
pub fn encode<T: Serialize>(frame: &T) -> Result<Vec<u8>, CodecError> {
    postcard::to_stdvec(frame).map_err(CodecError::Serialize)
}

/// Deserialize a frame from exactly its bytes (no length prefix).
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CodecError> {
    postcard::from_bytes(bytes).map_err(CodecError::Deserialize)
}

/// Serialize a frame with a 4-byte big-endian length prefix, ready to write to
/// a stream.
pub fn encode_framed<T: Serialize>(frame: &T) -> Result<Vec<u8>, CodecError> {
    let body = encode(frame)?;
    if body.len() > MAX_FRAME_LEN {
        return Err(CodecError::TooLarge(body.len()));
    }
    let mut out = Vec::with_capacity(LEN_PREFIX + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::*;

    fn sample_open() -> ClientFrame {
        ClientFrame::Open {
            target: TargetSpec {
                host: "host01.example.com".into(),
                port: 22,
                user: "root".into(),
            },
            auth: AuthIntent::DelegatedKey {
                public_key: b"ssh-ed25519 AAAA...".to_vec(),
            },
            cols: 120,
            rows: 40,
        }
    }

    #[test]
    fn client_frame_roundtrip() {
        let frame = sample_open();
        let bytes = encode(&frame).unwrap();
        let back: ClientFrame = decode(&bytes).unwrap();
        assert_eq!(frame, back);
    }

    #[test]
    fn server_frame_roundtrip() {
        let frame = ServerFrame::SignRequest {
            id: 7,
            public_key: b"ssh-ed25519 AAAA...".to_vec(),
            data: vec![1, 2, 3, 4, 5],
        };
        let bytes = encode(&frame).unwrap();
        let back: ServerFrame = decode(&bytes).unwrap();
        assert_eq!(frame, back);
    }

    #[test]
    fn framed_carries_a_correct_length_prefix() {
        let frame = ClientFrame::Ping;
        let framed = encode_framed(&frame).unwrap();
        let declared = u32::from_be_bytes(framed[..LEN_PREFIX].try_into().unwrap()) as usize;
        assert_eq!(declared, framed.len() - LEN_PREFIX);

        let back: ClientFrame = decode(&framed[LEN_PREFIX..]).unwrap();
        assert_eq!(frame, back);
    }

    #[test]
    fn auth_intent_variants_roundtrip() {
        for auth in [
            AuthIntent::DelegatedKey { public_key: vec![9, 9] },
            AuthIntent::Password { secret: "hunter2".into() },
            AuthIntent::GatewayKey { key_id: "ops-key".into() },
        ] {
            let frame = ClientFrame::Open {
                target: TargetSpec { host: "h".into(), port: 22, user: "u".into() },
                auth: auth.clone(),
                cols: 80,
                rows: 24,
            };
            let back: ClientFrame = decode(&encode(&frame).unwrap()).unwrap();
            assert_eq!(frame, back);
        }
    }
}
