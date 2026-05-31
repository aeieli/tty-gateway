//! Per-connection orchestration: tie the QUIC control stream to a keep-alive
//! session and the SSH proxy.
//!
//! Flow: read `Hello` (optionally resuming by token), else read `Open` and
//! connect to the target. Then run two tasks — a sender (session output +
//! out-of-band frames → client) and a receiver (client frames → SSH input).
//! When the client drops, the session **detaches** and stays alive for resume;
//! an explicit `Close` (or the SSH session ending) tears it down.

use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use gw_core::quota::{AuthHook, Entitlement, TokenBucket, UsageMeter};
use gw_core::{SessionManager, SessionReader};
use gw_proto::{
    AuthIntent, ClientFrame, ResumeToken, ServerFrame, SessionStatus, TargetSpec, PROTOCOL_VERSION,
};
use gw_ssh::{Auth, SshInput, SshSession, SshTarget};
use gw_transport::{ClientConnection, FramedRecv, FramedSend};
use tokio::sync::mpsc;

/// Burst headroom for the bandwidth limiter, so a single large output chunk
/// isn't stalled below the sustained rate.
const BANDWIDTH_BURST: u64 = 1 << 20; // 1 MiB

/// Why a client's control loop ended.
enum Outcome {
    /// Client connection dropped — keep the session for resume.
    Detached,
    /// Client asked to close — tear the session down.
    Closed,
}

/// Handle one accepted client connection start to finish.
pub async fn handle_connection(
    manager: Arc<SessionManager>,
    hook: Arc<dyn AuthHook>,
    client: ClientConnection,
) {
    let ClientConnection {
        conn: _quic,
        mut send,
        mut recv,
    } = client;

    let (session, entitlement) = match negotiate(&manager, hook.as_ref(), &mut send, &mut recv).await
    {
        Ok(Some(result)) => result,
        Ok(None) => return, // negotiation already reported an error to the client
        Err(error) => {
            tracing::warn!(%error, "client negotiation failed");
            return;
        }
    };

    let meter = Arc::new(UsageMeter::default());
    let (oob_tx, oob_rx) = mpsc::channel::<ServerFrame>(16);
    let sender = tokio::spawn(sender_task(
        send,
        session.reader(),
        oob_rx,
        entitlement,
        meter.clone(),
    ));
    let outcome = receiver_loop(recv, session.clone(), oob_tx, meter.clone()).await;
    sender.abort();

    let (bytes_in, bytes_out) = meter.totals();
    tracing::debug!(session = %session.id, bytes_in, bytes_out, "connection usage");

    if matches!(outcome, Outcome::Closed) || session.is_closed() {
        manager.remove(session.id);
        tracing::info!(session = %session.id, "session closed");
    } else {
        tracing::info!(session = %session.id, "client detached; session held for resume");
    }
}

/// Run the `Hello` (+ optional `Open`) exchange and return the live session and
/// its entitlement. Returns `Ok(None)` if an error frame was already sent.
async fn negotiate(
    manager: &Arc<SessionManager>,
    hook: &dyn AuthHook,
    send: &mut FramedSend,
    recv: &mut FramedRecv,
) -> Result<Option<(Arc<gw_core::Session>, Entitlement)>> {
    let hello = recv.recv::<ClientFrame>().await?;
    let ClientFrame::Hello {
        version,
        client_name,
        resume,
        account_token,
    } = hello
    else {
        send.send(&ServerFrame::Error {
            message: "expected Hello".into(),
        })
        .await?;
        return Ok(None);
    };
    if version != PROTOCOL_VERSION {
        send.send(&ServerFrame::Error {
            message: format!("protocol version mismatch: client {version}, server {PROTOCOL_VERSION}"),
        })
        .await?;
        return Ok(None);
    }

    // Ask the control plane to authorize this client and supply its limits.
    let entitlement = match hook
        .authorize(&client_name, account_token.as_deref())
        .await
    {
        Ok(entitlement) => entitlement,
        Err(denied) => {
            send.send(&ServerFrame::Error {
                message: denied.to_string(),
            })
            .await?;
            return Ok(None);
        }
    };

    let (session, resumed) = match resume.and_then(|token| manager.resume(&token.0)) {
        Some(existing) => (existing, true),
        None => {
            // A fresh session needs an `Open` describing the target.
            match recv.recv::<ClientFrame>().await? {
                ClientFrame::Open { target, auth, cols, rows } => {
                    match open_for_auth(&target, auth, cols, rows, send, recv).await {
                        Ok(ssh) => (manager.create(ssh.spawn()), false),
                        Err(error) => {
                            send.send(&ServerFrame::Error {
                                message: format!("connect failed: {error}"),
                            })
                            .await?;
                            return Ok(None);
                        }
                    }
                }
                _ => {
                    send.send(&ServerFrame::Error {
                        message: "expected Open".into(),
                    })
                    .await?;
                    return Ok(None);
                }
            }
        }
    };

    send.send(&ServerFrame::Hello {
        version: PROTOCOL_VERSION,
        session_id: session.id,
        resumed,
        resume: ResumeToken(session.resume_token.clone()),
    })
    .await?;
    send.send(&ServerFrame::Status(SessionStatus::Live)).await?;
    Ok(Some((session, entitlement)))
}

/// Connect + authenticate to the target according to the client's `AuthIntent`.
/// Delegated signing forwards challenges to the client over `send`/`recv`.
async fn open_for_auth(
    target: &TargetSpec,
    auth: AuthIntent,
    cols: u16,
    rows: u16,
    send: &mut FramedSend,
    recv: &mut FramedRecv,
) -> Result<SshSession> {
    let ssh_target = SshTarget {
        host: target.host.clone(),
        port: target.port,
        user: target.user.clone(),
    };
    match auth {
        AuthIntent::Password { secret } => {
            SshSession::open(&ssh_target, Auth::Password(secret), cols as u32, rows as u32).await
        }
        AuthIntent::PrivateKey { pem, passphrase } => {
            SshSession::open(
                &ssh_target,
                Auth::PrivateKey { pem, passphrase },
                cols as u32,
                rows as u32,
            )
            .await
        }
        AuthIntent::DelegatedKey { public_key } => {
            let openssh = String::from_utf8(public_key)
                .map_err(|_| anyhow::anyhow!("delegated public key is not OpenSSH text"))?;
            let mut signer = ControlSigner {
                send,
                recv,
                next_id: 1,
            };
            SshSession::open_delegated(&ssh_target, &openssh, &mut signer, cols as u32, rows as u32)
                .await
        }
        AuthIntent::GatewayKey { .. } => {
            anyhow::bail!("gateway-stored keys not yet implemented")
        }
    }
}

/// A [`RemoteSigner`](gw_ssh::RemoteSigner) backed by the client's control
/// stream: send a `SignRequest`, await the matching `SignResponse`.
struct ControlSigner<'a> {
    send: &'a mut FramedSend,
    recv: &'a mut FramedRecv,
    next_id: u64,
}

#[async_trait::async_trait]
impl gw_ssh::RemoteSigner for ControlSigner<'_> {
    async fn sign(
        &mut self,
        public_key_openssh: &str,
        _algorithm: Option<&str>,
        to_sign: &[u8],
    ) -> Result<Vec<u8>, gw_ssh::RemoteSignerError> {
        let id = self.next_id;
        self.next_id += 1;
        self.send
            .send(&ServerFrame::SignRequest {
                id,
                public_key: public_key_openssh.as_bytes().to_vec(),
                data: to_sign.to_vec(),
            })
            .await
            .map_err(|e| gw_ssh::RemoteSignerError(e.to_string()))?;

        loop {
            let frame = self
                .recv
                .recv::<ClientFrame>()
                .await
                .map_err(|e| gw_ssh::RemoteSignerError(e.to_string()))?;
            match frame {
                ClientFrame::SignResponse { id: rid, signature } if rid == id => {
                    return Ok(signature)
                }
                ClientFrame::SignResponse { .. } => continue, // stale id
                ClientFrame::Ping => continue,                // tolerate keepalive
                other => {
                    return Err(gw_ssh::RemoteSignerError(format!(
                        "unexpected frame during signing: {other:?}"
                    )))
                }
            }
        }
    }
}

/// Stream session output (and out-of-band frames like `Pong`) to the client,
/// metering bytes and throttling to the entitlement's bandwidth cap.
async fn sender_task(
    mut send: FramedSend,
    mut reader: SessionReader,
    mut oob: mpsc::Receiver<ServerFrame>,
    entitlement: Entitlement,
    meter: Arc<UsageMeter>,
) {
    let mut limiter = entitlement
        .max_bytes_per_sec
        .map(|rate| (TokenBucket::new(rate, BANDWIDTH_BURST), Instant::now()));
    let mut oob_open = true;

    loop {
        tokio::select! {
            chunk = reader.next() => match chunk {
                Some(bytes) => {
                    throttle(&mut limiter, bytes.len() as u64).await;
                    meter.add_out(bytes.len() as u64);
                    if send.send(&ServerFrame::Data(bytes)).await.is_err() {
                        break;
                    }
                }
                None => {
                    let _ = send.send(&ServerFrame::Closed).await;
                    break;
                }
            },
            frame = oob.recv(), if oob_open => match frame {
                Some(frame) => {
                    if send.send(&frame).await.is_err() {
                        break;
                    }
                }
                None => oob_open = false,
            },
        }
    }
}

/// Block until the bandwidth limiter has room for `amount` bytes (no-op when
/// unlimited).
async fn throttle(limiter: &mut Option<(TokenBucket, Instant)>, amount: u64) {
    let Some((bucket, last)) = limiter else { return };
    loop {
        let now = Instant::now();
        bucket.refill(now.duration_since(*last));
        *last = now;
        if bucket.try_consume(amount) {
            return;
        }
        tokio::time::sleep(bucket.time_until(amount)).await;
    }
}

/// Read client frames and apply them to the session until the client closes or
/// drops.
async fn receiver_loop(
    mut recv: FramedRecv,
    session: Arc<gw_core::Session>,
    oob: mpsc::Sender<ServerFrame>,
    meter: Arc<UsageMeter>,
) -> Outcome {
    loop {
        match recv.recv::<ClientFrame>().await {
            Ok(ClientFrame::Data(bytes)) => {
                meter.add_in(bytes.len() as u64);
                session.send_input(SshInput::Data(bytes)).await;
            }
            Ok(ClientFrame::Resize { cols, rows }) => {
                session
                    .send_input(SshInput::Resize {
                        cols: cols as u32,
                        rows: rows as u32,
                    })
                    .await;
            }
            Ok(ClientFrame::Ping) => {
                let _ = oob.send(ServerFrame::Pong).await;
            }
            Ok(ClientFrame::Close) => return Outcome::Closed,
            // Unexpected mid-session frames are ignored (delegated-signing
            // replies will be handled here once that path is wired).
            Ok(_) => {}
            Err(_) => return Outcome::Detached,
        }
    }
}
