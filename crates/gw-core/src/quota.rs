//! Multi-tenant quota primitives (Stage 4).
//!
//! These run in the data plane (the gateway) but are *driven* by an external
//! control plane through [`AuthHook`]: on each client connect the gateway asks
//! the hook to authorize the client and return its [`Entitlement`]. Output is
//! metered ([`UsageMeter`]) and bandwidth-capped ([`TokenBucket`]).
//!
//! The OSS build uses [`AllowAll`] (single tenant, no limits). The SaaS build
//! provides an `AuthHook` that calls the control-plane backend.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Per-client limits returned by the control plane.
#[derive(Clone, Debug)]
pub struct Entitlement {
    /// Max output bandwidth in bytes/sec, or `None` for unlimited.
    pub max_bytes_per_sec: Option<u64>,
    /// Max concurrent sessions for this account, or `None` for unlimited.
    pub max_sessions: Option<u32>,
}

impl Entitlement {
    /// No limits — the default for OSS self-hosting (single tenant).
    pub fn unlimited() -> Self {
        Self {
            max_bytes_per_sec: None,
            max_sessions: None,
        }
    }
}

/// Reason a connection was refused by the control plane.
#[derive(Clone, Debug, thiserror::Error)]
#[error("authorization denied: {0}")]
pub struct Denied(pub String);

/// Called by the gateway on each client connect. Implemented by the SaaS
/// control-plane integration; the OSS build uses [`AllowAll`].
///
/// `authorize` runs on connect. The session/usage hooks let the control plane
/// enforce concurrency and meter traffic; all three default to no-ops so the
/// OSS [`AllowAll`] and any minimal hook need only implement `authorize`.
#[async_trait::async_trait]
pub trait AuthHook: Send + Sync {
    async fn authorize(
        &self,
        client_name: &str,
        account_token: Option<&[u8]>,
    ) -> Result<Entitlement, Denied>;

    /// A new (non-resumed) session is starting. The control plane may refuse it
    /// (e.g. the account's concurrency cap is reached). Default: allow.
    async fn session_open(
        &self,
        _account_token: Option<&[u8]>,
        _session_id: &str,
        _client_name: &str,
    ) -> Result<(), Denied> {
        Ok(())
    }

    /// A session has fully closed (its concurrency slot is freed). Default: no-op.
    async fn session_close(&self, _account_token: Option<&[u8]>, _session_id: &str) {}

    /// Report metered bytes for one client connection of a session. Called on
    /// every connection end (including detach), so usage survives resume.
    /// Default: no-op.
    async fn report_usage(
        &self,
        _account_token: Option<&[u8]>,
        _session_id: &str,
        _bytes_in: u64,
        _bytes_out: u64,
    ) {
    }
}

/// Permit every client with no limits (OSS / self-host default).
pub struct AllowAll;

#[async_trait::async_trait]
impl AuthHook for AllowAll {
    async fn authorize(&self, _client: &str, _token: Option<&[u8]>) -> Result<Entitlement, Denied> {
        Ok(Entitlement::unlimited())
    }
}

/// Simple token-bucket rate limiter. Time is injected (`refill`) so it is
/// deterministically testable; the caller advances it from a real clock.
#[derive(Debug)]
pub struct TokenBucket {
    capacity: f64,
    tokens: f64,
    rate: f64,
}

impl TokenBucket {
    /// `rate_per_sec` sustained bytes/sec; `burst` the bucket capacity.
    pub fn new(rate_per_sec: u64, burst: u64) -> Self {
        let capacity = burst.max(1) as f64;
        Self {
            capacity,
            tokens: capacity,
            rate: rate_per_sec.max(1) as f64,
        }
    }

    /// Add tokens for `elapsed` time, capped at capacity.
    pub fn refill(&mut self, elapsed: Duration) {
        self.tokens = (self.tokens + elapsed.as_secs_f64() * self.rate).min(self.capacity);
    }

    /// Take `amount` tokens if available.
    pub fn try_consume(&mut self, amount: u64) -> bool {
        let amount = amount as f64;
        if self.tokens >= amount {
            self.tokens -= amount;
            true
        } else {
            false
        }
    }

    /// How long until `amount` tokens (capped at capacity) are available.
    pub fn time_until(&self, amount: u64) -> Duration {
        let amount = (amount as f64).min(self.capacity);
        if self.tokens >= amount {
            Duration::ZERO
        } else {
            Duration::from_secs_f64((amount - self.tokens) / self.rate)
        }
    }
}

/// Cumulative byte counters for a connection, reportable to the control plane.
#[derive(Default, Debug)]
pub struct UsageMeter {
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
}

impl UsageMeter {
    pub fn add_in(&self, n: u64) {
        self.bytes_in.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_out(&self, n: u64) {
        self.bytes_out.fetch_add(n, Ordering::Relaxed);
    }

    /// `(bytes_in, bytes_out)` so far.
    pub fn totals(&self) -> (u64, u64) {
        (
            self.bytes_in.load(Ordering::Relaxed),
            self.bytes_out.load(Ordering::Relaxed),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn allow_all_is_unlimited() {
        let ent = AllowAll.authorize("client", None).await.unwrap();
        assert!(ent.max_bytes_per_sec.is_none());
        assert!(ent.max_sessions.is_none());
    }

    #[test]
    fn bucket_consumes_then_refills() {
        let mut b = TokenBucket::new(100, 100);
        assert!(b.try_consume(100));
        assert!(!b.try_consume(1)); // empty
        b.refill(Duration::from_secs(1)); // +100
        assert!(b.try_consume(100));
    }

    #[test]
    fn bucket_refill_caps_at_capacity() {
        let mut b = TokenBucket::new(10, 10);
        b.refill(Duration::from_secs(100)); // would add 1000, capped at 10
        assert!(b.try_consume(10));
        assert!(!b.try_consume(1));
    }

    #[test]
    fn time_until_is_positive_when_empty() {
        let mut b = TokenBucket::new(10, 10);
        assert!(b.try_consume(10));
        assert!(b.time_until(10) > Duration::ZERO);
    }

    #[test]
    fn meter_accumulates() {
        let m = UsageMeter::default();
        m.add_out(120);
        m.add_out(80);
        m.add_in(5);
        assert_eq!(m.totals(), (5, 200));
    }
}
