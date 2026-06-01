//! A built-in [`AuthHook`] that talks to an HTTP control plane.
//!
//! On connect the gateway POSTs to `{base}/v1/authorize` and applies the
//! returned entitlement (or relays the denial). For managed deployments it also
//! reports session open/close (`/v1/sessions/*`, the concurrency-cap point) and
//! per-connection usage (`/v1/usage`). All calls carry an optional shared secret
//! (`X-Gateway-Key`). The SharkTTY managed control plane speaks exactly this
//! shape, but it's a generic integration point.

use async_trait::async_trait;
use gw_core::quota::{AuthHook, Denied, Entitlement};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct AuthorizeRequest<'a> {
    client_name: &'a str,
    account_token: Option<String>,
}

#[derive(Serialize)]
struct SessionOpenRequest<'a> {
    account_token: String,
    session_id: &'a str,
    client_name: &'a str,
}

#[derive(Serialize)]
struct SessionCloseRequest<'a> {
    account_token: String,
    session_id: &'a str,
}

#[derive(Serialize)]
struct UsageReport<'a> {
    account_token: String,
    session_id: &'a str,
    bytes_in: u64,
    bytes_out: u64,
}

#[derive(Deserialize)]
struct EntitlementDto {
    max_bytes_per_sec: Option<u64>,
    max_sessions: Option<u32>,
}

#[derive(Deserialize)]
struct AuthorizeResponse {
    allowed: bool,
    reason: Option<String>,
    entitlement: EntitlementDto,
}

#[derive(Deserialize)]
struct SessionOpenResponse {
    allowed: bool,
    reason: Option<String>,
}

/// Authorizes clients and reports sessions/usage to an HTTP control plane.
pub struct HttpAuthHook {
    client: reqwest::Client,
    base: String,
    key: Option<String>,
}

impl HttpAuthHook {
    /// `base` is the control-plane base URL (e.g. `http://cloud-api:8080`); a
    /// trailing `/v1/authorize` or `/` is stripped. `key` is the shared secret
    /// sent as `X-Gateway-Key`, if any.
    pub fn new(base: impl Into<String>, key: Option<String>) -> Self {
        let mut base = base.into();
        if let Some(stripped) = base.strip_suffix("/v1/authorize") {
            base = stripped.to_string();
        }
        while base.ends_with('/') {
            base.pop();
        }
        Self {
            client: reqwest::Client::new(),
            base,
            key,
        }
    }

    fn post(&self, path: &str) -> reqwest::RequestBuilder {
        let mut req = self.client.post(format!("{}{}", self.base, path));
        if let Some(key) = &self.key {
            req = req.header("x-gateway-key", key);
        }
        req
    }

    fn token_string(account_token: Option<&[u8]>) -> String {
        account_token
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default()
    }
}

#[async_trait]
impl AuthHook for HttpAuthHook {
    async fn authorize(
        &self,
        client_name: &str,
        account_token: Option<&[u8]>,
    ) -> Result<Entitlement, Denied> {
        let body = AuthorizeRequest {
            client_name,
            account_token: account_token.map(|b| String::from_utf8_lossy(b).into_owned()),
        };

        let response = self
            .post("/v1/authorize")
            .json(&body)
            .send()
            .await
            .map_err(|e| Denied(format!("control plane unreachable: {e}")))?;

        if !response.status().is_success() {
            return Err(Denied(format!("control plane returned {}", response.status())));
        }

        let parsed: AuthorizeResponse = response
            .json()
            .await
            .map_err(|e| Denied(format!("bad control-plane response: {e}")))?;

        if !parsed.allowed {
            return Err(Denied(
                parsed.reason.unwrap_or_else(|| "authorization denied".into()),
            ));
        }

        Ok(Entitlement {
            max_bytes_per_sec: parsed.entitlement.max_bytes_per_sec,
            max_sessions: parsed.entitlement.max_sessions,
        })
    }

    async fn session_open(
        &self,
        account_token: Option<&[u8]>,
        session_id: &str,
        client_name: &str,
    ) -> Result<(), Denied> {
        let body = SessionOpenRequest {
            account_token: Self::token_string(account_token),
            session_id,
            client_name,
        };
        let response = self
            .post("/v1/sessions/open")
            .json(&body)
            .send()
            .await
            .map_err(|e| Denied(format!("control plane unreachable: {e}")))?;

        if !response.status().is_success() {
            return Err(Denied(format!("control plane returned {}", response.status())));
        }
        let parsed: SessionOpenResponse = response
            .json()
            .await
            .map_err(|e| Denied(format!("bad control-plane response: {e}")))?;
        if parsed.allowed {
            Ok(())
        } else {
            Err(Denied(parsed.reason.unwrap_or_else(|| "session refused".into())))
        }
    }

    async fn session_close(&self, account_token: Option<&[u8]>, session_id: &str) {
        let body = SessionCloseRequest {
            account_token: Self::token_string(account_token),
            session_id,
        };
        if let Err(e) = self.post("/v1/sessions/close").json(&body).send().await {
            tracing::warn!(session_id, error = %e, "failed to report session close");
        }
    }

    async fn report_usage(
        &self,
        account_token: Option<&[u8]>,
        session_id: &str,
        bytes_in: u64,
        bytes_out: u64,
    ) {
        if bytes_in == 0 && bytes_out == 0 {
            return;
        }
        let body = UsageReport {
            account_token: Self::token_string(account_token),
            session_id,
            bytes_in,
            bytes_out,
        };
        if let Err(e) = self.post("/v1/usage").json(&body).send().await {
            tracing::warn!(session_id, error = %e, "failed to report usage");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Start a one-shot HTTP server that replies with `body` to any request and
    /// return its base URL.
    async fn mock_base(body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf).await; // drain the request
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = sock.write_all(response.as_bytes()).await;
            let _ = sock.flush().await;
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn allowed_maps_entitlement() {
        let base = mock_base(
            r#"{"allowed":true,"reason":null,"entitlement":{"max_bytes_per_sec":1000,"max_sessions":5}}"#,
        )
        .await;
        let hook = HttpAuthHook::new(base, None);
        let entitlement = hook.authorize("ipad", Some(b"tok-123")).await.unwrap();
        assert_eq!(entitlement.max_bytes_per_sec, Some(1000));
        assert_eq!(entitlement.max_sessions, Some(5));
    }

    #[tokio::test]
    async fn denied_relays_reason() {
        let base = mock_base(
            r#"{"allowed":false,"reason":"over session quota","entitlement":{"max_bytes_per_sec":null,"max_sessions":null}}"#,
        )
        .await;
        let hook = HttpAuthHook::new(base, None);
        let err = hook.authorize("ipad", None).await.unwrap_err();
        assert!(err.to_string().contains("over session quota"));
    }

    #[tokio::test]
    async fn session_open_refused_is_denied() {
        let base = mock_base(r#"{"allowed":false,"reason":"session limit reached (3 concurrent)"}"#).await;
        let hook = HttpAuthHook::new(base, Some("secret".into()));
        let err = hook
            .session_open(Some(b"tok"), "sess-1", "ipad")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("session limit reached"));
    }

    #[test]
    fn base_url_is_normalized() {
        let h = HttpAuthHook::new("http://cp:8080/v1/authorize", None);
        assert_eq!(h.base, "http://cp:8080");
        let h = HttpAuthHook::new("http://cp:8080/", None);
        assert_eq!(h.base, "http://cp:8080");
    }
}
