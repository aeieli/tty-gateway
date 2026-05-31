//! `gw-proto` — the App↔Gateway wire protocol for the SharkTTY keep-alive SSH
//! gateway.
//!
//! This crate is intentionally transport-agnostic: it defines the frames the
//! client and gateway exchange and a compact length-prefixed codec, but knows
//! nothing about QUIC, sockets, or async. The same crate is shared with the
//! iOS client so both ends agree on the format byte-for-byte.

pub mod codec;
pub mod frame;

pub use codec::{decode, encode, encode_framed, CodecError, MAX_FRAME_LEN};
pub use frame::{
    AuthIntent, ClientFrame, ResumeToken, ServerFrame, SessionId, SessionStatus, TargetSpec,
    PROTOCOL_VERSION,
};
