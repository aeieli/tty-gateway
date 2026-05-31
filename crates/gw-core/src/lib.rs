//! `gw-core` — the gateway session manager.
//!
//! This is where "keep-alive" lives. Each [`Session`] owns the actor handle to
//! a live SSH session ([`gw_ssh::SshHandle`]) and a bounded scrollback ring
//! buffer. An ingest task drains SSH output into the buffer continuously —
//! whether or not a client is attached — so a client can drop and later
//! reattach (with its resume token) and replay everything it missed.
//!
//! The buffer is addressed by an absolute byte offset, so each attached client
//! ([`SessionReader`]) tracks its own cursor and is woken by a [`Notify`] when
//! new bytes arrive. No client present means output simply accumulates (and the
//! oldest bytes age out past the cap).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use gw_proto::SessionId;
use gw_ssh::{SshHandle, SshInput};
use tokio::sync::{mpsc, Notify};

pub mod quota;

/// Default bound on per-session scrollback retained for replay on reconnect.
pub const DEFAULT_SCROLLBACK_BYTES: usize = 256 * 1024;

/// Registry of live sessions, keyed by id and by resume token.
pub struct SessionManager {
    inner: Mutex<Registry>,
    max_scrollback: usize,
}

#[derive(Default)]
struct Registry {
    by_id: HashMap<SessionId, Arc<Session>>,
    by_token: HashMap<Vec<u8>, SessionId>,
}

impl SessionManager {
    pub fn new() -> Arc<Self> {
        Self::with_scrollback(DEFAULT_SCROLLBACK_BYTES)
    }

    pub fn with_scrollback(max_scrollback: usize) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Registry::default()),
            max_scrollback,
        })
    }

    /// Register a freshly connected SSH session and start buffering its output.
    pub fn create(&self, ssh: SshHandle) -> Arc<Session> {
        let id = new_session_id();
        let token = new_resume_token();
        let session = Session::spawn(id, token.clone(), ssh, self.max_scrollback);
        let mut reg = self.inner.lock().unwrap();
        reg.by_id.insert(id, session.clone());
        reg.by_token.insert(token, id);
        session
    }

    /// Look up an existing session by its resume token.
    pub fn resume(&self, token: &[u8]) -> Option<Arc<Session>> {
        let reg = self.inner.lock().unwrap();
        let id = reg.by_token.get(token)?;
        reg.by_id.get(id).cloned()
    }

    /// Drop a session from the registry (its resume token stops working).
    pub fn remove(&self, id: SessionId) {
        let mut reg = self.inner.lock().unwrap();
        if let Some(session) = reg.by_id.remove(&id) {
            reg.by_token.remove(&session.resume_token);
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

struct SessionInner {
    buf: Vec<u8>,
    /// Absolute offset of `buf[0]` in the session's lifetime output.
    start_offset: u64,
    /// Absolute offset just past the last buffered byte.
    end_offset: u64,
    closed: bool,
    max_bytes: usize,
}

impl SessionInner {
    fn append(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
        self.end_offset += data.len() as u64;
        if self.buf.len() > self.max_bytes {
            let excess = self.buf.len() - self.max_bytes;
            self.buf.drain(..excess);
            self.start_offset += excess as u64;
        }
    }
}

/// One persistent session: a live SSH actor plus its scrollback.
pub struct Session {
    pub id: SessionId,
    pub resume_token: Vec<u8>,
    pub server_fingerprint: Option<String>,
    input: mpsc::Sender<SshInput>,
    inner: Mutex<SessionInner>,
    notify: Notify,
}

impl Session {
    fn spawn(id: SessionId, resume_token: Vec<u8>, ssh: SshHandle, max_bytes: usize) -> Arc<Self> {
        let session = Arc::new(Self {
            id,
            resume_token,
            server_fingerprint: ssh.server_fingerprint,
            input: ssh.input,
            inner: Mutex::new(SessionInner {
                buf: Vec::new(),
                start_offset: 0,
                end_offset: 0,
                closed: false,
                max_bytes,
            }),
            notify: Notify::new(),
        });
        spawn_ingest(session.clone(), ssh.output);
        session
    }

    /// A reader that replays buffered scrollback from the start, then streams
    /// live output. Each attached client gets its own.
    pub fn reader(self: &Arc<Self>) -> SessionReader {
        SessionReader {
            session: self.clone(),
            cursor: 0,
        }
    }

    /// Forward input (keystrokes / resize) to the remote shell. Returns false
    /// if the session has ended.
    pub async fn send_input(&self, input: SshInput) -> bool {
        self.input.send(input).await.is_ok()
    }

    pub fn is_closed(&self) -> bool {
        self.inner.lock().unwrap().closed
    }
}

fn spawn_ingest(session: Arc<Session>, mut output: mpsc::Receiver<Vec<u8>>) {
    tokio::spawn(async move {
        while let Some(bytes) = output.recv().await {
            session.inner.lock().unwrap().append(&bytes);
            session.notify.notify_waiters();
        }
        session.inner.lock().unwrap().closed = true;
        session.notify.notify_waiters();
    });
}

/// Per-client view of a session's output stream.
pub struct SessionReader {
    session: Arc<Session>,
    cursor: u64,
}

impl SessionReader {
    /// Next chunk of output (replayed scrollback, then live). Returns `None`
    /// once the session is closed and this reader has caught up.
    pub async fn next(&mut self) -> Option<Vec<u8>> {
        let notified = self.session.notify.notified();
        tokio::pin!(notified);
        loop {
            // Register for wakeups before checking the buffer, so a notify that
            // races our check isn't lost (Notify::notify_waiters has no permit).
            notified.as_mut().enable();
            {
                let inner = self.session.inner.lock().unwrap();
                if self.cursor < inner.start_offset {
                    self.cursor = inner.start_offset; // we missed trimmed bytes
                }
                if self.cursor < inner.end_offset {
                    let lo = (self.cursor - inner.start_offset) as usize;
                    let chunk = inner.buf[lo..].to_vec();
                    self.cursor = inner.end_offset;
                    return Some(chunk);
                }
                if inner.closed {
                    return None;
                }
            }
            notified.as_mut().await;
            notified.set(self.session.notify.notified());
        }
    }
}

fn new_session_id() -> SessionId {
    uuid::Uuid::new_v4().as_u128()
}

fn new_resume_token() -> Vec<u8> {
    let bytes: [u8; 32] = rand::random();
    bytes.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use gw_ssh::SshInput;

    /// Build a session handle whose output we feed and whose input we observe.
    fn fake_handle() -> (SshHandle, mpsc::Sender<Vec<u8>>, mpsc::Receiver<SshInput>) {
        let (in_tx, in_rx) = mpsc::channel::<SshInput>(16);
        let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(16);
        let handle = SshHandle {
            input: in_tx,
            output: out_rx,
            server_fingerprint: Some("SHA256:test".into()),
        };
        (handle, out_tx, in_rx)
    }

    async fn read_n(reader: &mut SessionReader, n: usize) -> Vec<u8> {
        let mut got = Vec::new();
        while got.len() < n {
            match reader.next().await {
                Some(chunk) => got.extend_from_slice(&chunk),
                None => break,
            }
        }
        got
    }

    #[tokio::test]
    async fn replays_scrollback_then_streams_live() {
        let mgr = SessionManager::new();
        let (handle, feed, _in) = fake_handle();
        let session = mgr.create(handle);

        feed.send(b"hello ".to_vec()).await.unwrap();
        feed.send(b"world".to_vec()).await.unwrap();

        let mut reader = session.reader();
        assert_eq!(read_n(&mut reader, 11).await, b"hello world");
    }

    #[tokio::test]
    async fn resume_returns_same_session_and_replays_all() {
        let mgr = SessionManager::new();
        let (handle, feed, _in) = fake_handle();
        let session = mgr.create(handle);
        let token = session.resume_token.clone();

        feed.send(b"abc".to_vec()).await.unwrap();
        // No client attached here — output still accumulates.
        feed.send(b"def".to_vec()).await.unwrap();

        let resumed = mgr.resume(&token).expect("resume by token");
        assert_eq!(resumed.id, session.id);

        let mut reader = resumed.reader();
        assert_eq!(read_n(&mut reader, 6).await, b"abcdef");
    }

    #[tokio::test]
    async fn reader_ends_when_session_closes() {
        let mgr = SessionManager::new();
        let (handle, feed, _in) = fake_handle();
        let session = mgr.create(handle);

        feed.send(b"bye".to_vec()).await.unwrap();
        drop(feed); // closes the session

        let mut reader = session.reader();
        assert_eq!(read_n(&mut reader, 3).await, b"bye");
        assert_eq!(reader.next().await, None);
    }

    #[tokio::test]
    async fn forwards_input_to_ssh() {
        let mgr = SessionManager::new();
        let (handle, _feed, mut in_rx) = fake_handle();
        let session = mgr.create(handle);

        assert!(session.send_input(SshInput::Data(b"ls\n".to_vec())).await);
        match in_rx.recv().await.unwrap() {
            SshInput::Data(d) => assert_eq!(d, b"ls\n"),
            other => panic!("unexpected input: {other:?}"),
        }
    }

    #[tokio::test]
    async fn scrollback_is_bounded_and_advances_cursor() {
        let mgr = SessionManager::with_scrollback(8);
        let (handle, feed, _in) = fake_handle();
        let session = mgr.create(handle);

        feed.send(b"0123456789".to_vec()).await.unwrap(); // 10 bytes > cap 8
        // Let ingest drain by waiting for a reader to catch up to the tail.
        let mut reader = session.reader();
        let tail = read_n(&mut reader, 8).await;
        assert_eq!(tail, b"23456789"); // oldest 2 bytes trimmed
    }
}
