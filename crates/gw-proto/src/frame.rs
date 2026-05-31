//! Wire frames exchanged between the client (app) and the gateway.

use serde::{Deserialize, Serialize};

/// Bumped on any breaking change to the frame set or its semantics. The two
/// ends compare versions in the `Hello` exchange and refuse a mismatch.
pub const PROTOCOL_VERSION: u16 = 1;

/// Opaque identifier for a persisted gateway session. Unlike a transport
/// connection, a session outlives client drops — that is what "keep-alive"
/// means here.
pub type SessionId = u128;

/// Token the client presents to reattach to an existing session after a drop.
/// Opaque and unguessable; minted by the gateway.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeToken(pub Vec<u8>);

/// The remote SSH endpoint the gateway should proxy to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetSpec {
    pub host: String,
    pub port: u16,
    pub user: String,
}

/// How the client wants the gateway to authenticate to the target.
///
/// `DelegatedKey` keeps the private key on the device: the gateway forwards
/// each auth challenge to the client to sign (see `ServerFrame::SignRequest`),
/// so the gateway never holds the key and the target only sees ordinary
/// publickey auth. `Password` and `GatewayKey` trade some of that custody for
/// generality (password-only hosts, autonomous reconnect).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthIntent {
    /// Sign challenges on-device; the gateway never sees the private key.
    /// `public_key` is the OpenSSH-format public key blob used to select the
    /// auth identity on the target. The most secure mode.
    DelegatedKey { public_key: Vec<u8> },
    /// Password auth: the gateway holds the secret transiently to log in, then
    /// zeroizes it. Necessary for password-only hosts.
    Password { secret: String },
    /// A PEM private key the client hands to the gateway to use directly
    /// (optionally passphrase-protected). Trades key custody for generality —
    /// the gateway holds the key for the session.
    PrivateKey {
        pem: String,
        passphrase: Option<String>,
    },
    /// Use a private key the operator pre-loaded on the gateway, by id.
    GatewayKey { key_id: String },
}

/// Frames sent **client → gateway**.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientFrame {
    /// First frame on a fresh connection. `resume` reattaches to an existing
    /// session instead of opening a new one. `account_token` authenticates the
    /// client to the SaaS control plane (ignored by the OSS build).
    Hello {
        version: u16,
        client_name: String,
        resume: Option<ResumeToken>,
        account_token: Option<Vec<u8>>,
    },
    /// Open a new SSH session to `target`. Ignored if the connection resumed.
    Open {
        target: TargetSpec,
        auth: AuthIntent,
        cols: u16,
        rows: u16,
    },
    /// Keystrokes / stdin bytes for the remote PTY.
    Data(Vec<u8>),
    /// Terminal resize.
    Resize { cols: u16, rows: u16 },
    /// Reply to a `ServerFrame::SignRequest` (delegated signing).
    SignResponse { id: u64, signature: Vec<u8> },
    /// Liveness probe.
    Ping,
    /// Tear the session down (not just detach).
    Close,
}

/// Frames sent **gateway → client**.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerFrame {
    /// Reply to `ClientFrame::Hello`. `resumed` is true when an existing
    /// session was reattached; `resume` is the (possibly rotated) token to use
    /// next time.
    Hello {
        version: u16,
        session_id: SessionId,
        resumed: bool,
        resume: ResumeToken,
    },
    /// Terminal output from the target. Also used to replay buffered scrollback
    /// immediately after a resume.
    Data(Vec<u8>),
    /// Ask the client to sign `data` with the private key matching
    /// `public_key`. The client answers with `ClientFrame::SignResponse`.
    SignRequest {
        id: u64,
        public_key: Vec<u8>,
        data: Vec<u8>,
    },
    /// Session lifecycle updates.
    Status(SessionStatus),
    /// Liveness reply.
    Pong,
    /// A non-fatal or fatal error; `Closed` follows if the session ended.
    Error { message: String },
    /// The session has ended and the resume token is no longer valid.
    Closed,
}

/// Lifecycle of a gateway session, surfaced to the client for UI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionStatus {
    Connecting,
    Authenticating,
    Live,
    /// Client dropped but the gateway is holding the session open.
    Detached,
    Closed,
}
