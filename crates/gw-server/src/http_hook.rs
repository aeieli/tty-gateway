//! A built-in [`AuthHook`] that authorizes each client via an HTTP webhook.
//!
//! On connect the gateway POSTs `{ client_name, account_token }` to a configured
//! URL and applies the returned entitlement (or relays the denial reason). This
//! is a generic integration point — point it at any authorization service. The
//! SharkTTY managed control plane is one such service (its `/v1/authorize`
//! endpoint speaks exactly this shape).

use async_trait::async_trait;
use gw_core::quota::{AuthHook, Denied, Entitlement};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct AuthorizeRequest<'a> {
    client_name: &'a str,
    account_token: Option<String>,
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

/// Authorizes clients by calling an HTTP webhook.
pub struct HttpAuthHook {
    client: reqwest::Client,
    url: String,
}

impl HttpAuthHook {
    /// `url` is the full authorize endpoint to POST to (e.g.
    /// `http://control-plane:8080/v1/authorize`).
    pub fn new(url: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            url: url.to_string(),
        }
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
            .client
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .map_err(|e| Denied(format!("control plane unreachable: {e}")))?;

        if !response.status().is_success() {
            return Err(Denied(format!(
                "control plane returned {}",
                response.status()
            )));
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Start a one-shot HTTP server that replies with `body` to any request,
    /// and return its base URL.
    async fn mock_endpoint(body: &'static str) -> String {
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
        format!("http://{addr}/v1/authorize")
    }

    #[tokio::test]
    async fn allowed_maps_entitlement() {
        let url = mock_endpoint(
            r#"{"allowed":true,"reason":null,"entitlement":{"max_bytes_per_sec":1000,"max_sessions":5}}"#,
        )
        .await;
        let hook = HttpAuthHook::new(&url);
        let entitlement = hook.authorize("ipad", Some(b"tok-123")).await.unwrap();
        assert_eq!(entitlement.max_bytes_per_sec, Some(1000));
        assert_eq!(entitlement.max_sessions, Some(5));
    }

    #[tokio::test]
    async fn denied_relays_reason() {
        let url = mock_endpoint(
            r#"{"allowed":false,"reason":"over session quota","entitlement":{"max_bytes_per_sec":null,"max_sessions":null}}"#,
        )
        .await;
        let hook = HttpAuthHook::new(&url);
        let err = hook.authorize("ipad", None).await.unwrap_err();
        assert!(err.to_string().contains("over session quota"));
    }
}
