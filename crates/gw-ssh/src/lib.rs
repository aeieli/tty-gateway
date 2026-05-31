//! `gw-ssh` — the SSH client that connects the gateway to a target host.
//!
//! The gateway is an ordinary SSH client to the target, so the target needs no
//! special support. Three auth modes:
//!
//! - **password** — held transiently to log in;
//! - **private key** — a PEM key (optionally passphrase-protected) the gateway
//!   holds, e.g. one supplied by the client or provisioned by the operator;
//! - **delegated signing** ([`SshSession::open_delegated`]) — the private key
//!   stays on the device. russh asks for each auth-challenge signature, which a
//!   [`RemoteSigner`] forwards to the client over `gw-proto` and back. The
//!   target only ever sees ordinary publickey auth.
//!
//! A connected session is driven as an **actor**: [`SshSession::spawn`] returns
//! an [`SshHandle`] with an input channel (keystrokes / resize) and an output
//! channel (terminal bytes).

use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use russh::client::{self, Handle};
use russh::keys::{HashAlg, PublicKey};
use russh::{ChannelMsg, CryptoVec};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

/// The remote SSH endpoint to proxy to.
#[derive(Clone, Debug)]
pub struct SshTarget {
    pub host: String,
    pub port: u16,
    pub user: String,
}

/// How the gateway authenticates to the target (gateway-held credentials).
/// Delegated signing uses [`SshSession::open_delegated`] instead.
pub enum Auth {
    /// Password auth (held transiently).
    Password(String),
    /// PEM-encoded private key the gateway holds, with optional passphrase.
    PrivateKey {
        pem: String,
        passphrase: Option<String>,
    },
}

/// Input to a live session.
#[derive(Debug)]
pub enum SshInput {
    /// stdin bytes (keystrokes) for the remote PTY.
    Data(Vec<u8>),
    /// Terminal resize.
    Resize { cols: u32, rows: u32 },
}

/// Handle to a spawned session: feed [`SshInput`], drain terminal output.
pub struct SshHandle {
    /// Send keystrokes / resizes. Dropping all senders closes the session.
    pub input: mpsc::Sender<SshInput>,
    /// Terminal output. Closes (returns `None`) when the session ends.
    pub output: mpsc::Receiver<Vec<u8>>,
    /// SHA256 fingerprint of the target's host key, for the client to verify.
    pub server_fingerprint: Option<String>,
}

/// Error returned by a [`RemoteSigner`].
#[derive(Debug, thiserror::Error)]
#[error("remote signer: {0}")]
pub struct RemoteSignerError(pub String);

/// Signs SSH auth challenges on behalf of the gateway by asking the remote
/// client (whose private key never leaves its device). Implemented by the
/// server using the client's control stream.
#[async_trait::async_trait]
pub trait RemoteSigner: Send {
    /// Sign `to_sign` with the private key matching `public_key_openssh`
    /// (authorized_keys line). `algorithm` hints the SSH signature algorithm
    /// (e.g. `rsa-sha2-512`) when relevant. Returns the SSH signature blob.
    async fn sign(
        &mut self,
        public_key_openssh: &str,
        algorithm: Option<&str>,
        to_sign: &[u8],
    ) -> Result<Vec<u8>, RemoteSignerError>;
}

/// Adapts a [`RemoteSigner`] to russh's `auth::Signer`.
struct DelegatedSigner<'a> {
    remote: &'a mut dyn RemoteSigner,
}

#[derive(Debug, thiserror::Error)]
enum SignerError {
    #[error("ssh send error")]
    Send,
    #[error("public key: {0}")]
    Key(String),
    #[error("{0}")]
    Remote(#[from] RemoteSignerError),
}

impl From<russh::SendError> for SignerError {
    fn from(_: russh::SendError) -> Self {
        SignerError::Send
    }
}

impl russh::Signer for DelegatedSigner<'_> {
    type Error = SignerError;

    // Must mirror russh's trait signature (`-> impl Future + Send`), so the
    // `async fn` rewrite clippy suggests doesn't apply — russh allows it too.
    #[allow(clippy::manual_async_fn)]
    fn auth_publickey_sign(
        &mut self,
        key: &PublicKey,
        hash_alg: Option<HashAlg>,
        to_sign: CryptoVec,
    ) -> impl std::future::Future<Output = Result<CryptoVec, Self::Error>> + Send {
        async move {
            let openssh = key
                .to_openssh()
                .map_err(|e| SignerError::Key(e.to_string()))?;
            let algorithm = hash_alg.map(hash_alg_name);
            let signature = self
                .remote
                .sign(&openssh, algorithm, &to_sign)
                .await?;
            Ok(CryptoVec::from_slice(&signature))
        }
    }
}

fn hash_alg_name(alg: HashAlg) -> &'static str {
    match alg {
        HashAlg::Sha256 => "rsa-sha2-256",
        HashAlg::Sha512 => "rsa-sha2-512",
        _ => "rsa-sha2-512",
    }
}

/// russh client handler. Records the target's host-key fingerprint (TOFU at the
/// gateway); the client can additionally pin it over `gw-proto`.
struct ClientHandler {
    fingerprint: Arc<Mutex<Option<String>>>,
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(&mut self, server_public_key: &PublicKey) -> Result<bool, Self::Error> {
        let fp = server_public_key.fingerprint(Default::default()).to_string();
        *self.fingerprint.lock().unwrap() = Some(fp);
        Ok(true)
    }
}

/// A connected SSH session with an interactive shell on the target.
pub struct SshSession {
    channel: russh::Channel<client::Msg>,
    handle: Handle<ClientHandler>,
    /// SHA256 fingerprint of the target's host key.
    pub server_fingerprint: Option<String>,
}

impl SshSession {
    /// Connect + authenticate with a gateway-held credential, then open a shell.
    pub async fn open(target: &SshTarget, auth: Auth, cols: u32, rows: u32) -> Result<Self> {
        let (mut handle, fingerprint) = connect(target).await?;

        let ok = match auth {
            Auth::Password(password) => handle
                .authenticate_password(&target.user, password)
                .await
                .context("password auth")?
                .success(),
            Auth::PrivateKey { pem, passphrase } => {
                let key = russh::keys::decode_secret_key(&pem, passphrase.as_deref())
                    .context("decode private key")?;
                let with_alg = russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), None);
                handle
                    .authenticate_publickey(&target.user, with_alg)
                    .await
                    .context("publickey auth")?
                    .success()
            }
        };
        if !ok {
            return Err(anyhow!("authentication failed for {}", target.user));
        }
        finish_open(handle, fingerprint, cols, rows).await
    }

    /// Connect + authenticate by **delegated signing**: the private key stays on
    /// the client; `signer` forwards each challenge to it. `public_key_openssh`
    /// is the authorized_keys line identifying the key.
    pub async fn open_delegated(
        target: &SshTarget,
        public_key_openssh: &str,
        signer: &mut dyn RemoteSigner,
        cols: u32,
        rows: u32,
    ) -> Result<Self> {
        let (mut handle, fingerprint) = connect(target).await?;
        let public_key =
            PublicKey::from_openssh(public_key_openssh).context("parse delegated public key")?;
        let mut adapter = DelegatedSigner { remote: signer };
        let ok = handle
            .authenticate_publickey_with(&target.user, public_key, None, &mut adapter)
            .await
            .map_err(|e| anyhow!("delegated auth: {e}"))?
            .success();
        if !ok {
            return Err(anyhow!("delegated authentication failed for {}", target.user));
        }
        finish_open(handle, fingerprint, cols, rows).await
    }

    /// Drive the session as an actor: one task owns the russh channel, reading
    /// output to `output` and applying `input`.
    pub fn spawn(self) -> SshHandle {
        let (input_tx, mut input_rx) = mpsc::channel::<SshInput>(64);
        let (output_tx, output_rx) = mpsc::channel::<Vec<u8>>(256);
        let server_fingerprint = self.server_fingerprint.clone();
        let mut channel = self.channel;
        let handle = self.handle;

        tokio::spawn(async move {
            // Keep the SSH connection alive for the whole session.
            let _handle = handle;
            // `make_writer` returns an owned writer, independent of the channel
            // borrow needed by `wait`, so reads and writes never conflict.
            let mut writer = Box::pin(channel.make_writer());
            let mut pending_resize: Option<(u32, u32)> = None;

            loop {
                // Apply a resize outside the `wait` borrow (top of the loop).
                if let Some((cols, rows)) = pending_resize.take() {
                    let _ = channel.window_change(cols, rows, 0, 0).await;
                }

                tokio::select! {
                    msg = channel.wait() => match msg {
                        Some(ChannelMsg::Data { data }) => {
                            if output_tx.send(data.to_vec()).await.is_err() {
                                break;
                            }
                        }
                        Some(ChannelMsg::ExtendedData { data, .. }) => {
                            if output_tx.send(data.to_vec()).await.is_err() {
                                break;
                            }
                        }
                        Some(ChannelMsg::Eof | ChannelMsg::Close) | None => break,
                        Some(_) => {}
                    },
                    cmd = input_rx.recv() => match cmd {
                        Some(SshInput::Data(bytes)) => {
                            if writer.write_all(&bytes).await.is_err() {
                                break;
                            }
                            let _ = writer.flush().await;
                        }
                        Some(SshInput::Resize { cols, rows }) => {
                            pending_resize = Some((cols, rows));
                        }
                        None => break,
                    },
                }
            }
            // Dropping `output_tx` here signals end-of-session to the consumer.
        });

        SshHandle {
            input: input_tx,
            output: output_rx,
            server_fingerprint,
        }
    }
}

/// Open the TCP/SSH connection and run the handshake (capturing the host-key
/// fingerprint), but do not authenticate yet.
async fn connect(target: &SshTarget) -> Result<(Handle<ClientHandler>, Option<String>)> {
    let config = Arc::new(client::Config::default());
    let fingerprint = Arc::new(Mutex::new(None));
    let handler = ClientHandler {
        fingerprint: fingerprint.clone(),
    };
    let handle = client::connect(config, (target.host.as_str(), target.port), handler)
        .await
        .with_context(|| format!("ssh connect {}:{}", target.host, target.port))?;
    let fp = fingerprint.lock().unwrap().clone();
    Ok((handle, fp))
}

/// After auth: open a session channel, request a PTY + shell.
async fn finish_open(
    handle: Handle<ClientHandler>,
    server_fingerprint: Option<String>,
    cols: u32,
    rows: u32,
) -> Result<SshSession> {
    let channel = handle.channel_open_session().await.context("open session")?;
    channel
        .request_pty(false, "xterm-256color", cols, rows, 0, 0, &[])
        .await
        .context("request pty")?;
    channel.request_shell(false).await.context("request shell")?;
    Ok(SshSession {
        channel,
        handle,
        server_fingerprint,
    })
}
