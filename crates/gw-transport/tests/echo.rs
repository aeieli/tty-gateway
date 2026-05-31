//! Stage 1 acceptance test: a client connects over QUIC, completes the `Hello`
//! handshake, and round-trips a `Ping`/`Pong` through length-prefixed framing.

use gw_proto::{ClientFrame, ResumeToken, ServerFrame, PROTOCOL_VERSION};
use gw_transport::{Client, Server};

#[tokio::test]
async fn quic_hello_and_ping_roundtrip() {
    let bind: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (server, cert) = Server::bind_self_signed(bind).unwrap();
    let server_addr = server.local_addr().unwrap();

    // Server: accept one client, answer Hello, then Pong each Ping until Close.
    let server_task = tokio::spawn(async move {
        let mut client = server.accept().await.unwrap().unwrap();

        let hello: ClientFrame = client.recv.recv().await.unwrap();
        assert!(matches!(hello, ClientFrame::Hello { .. }));
        client
            .send
            .send(&ServerFrame::Hello {
                version: PROTOCOL_VERSION,
                session_id: 42,
                resumed: false,
                resume: ResumeToken(vec![0xAB, 0xCD]),
            })
            .await
            .unwrap();

        loop {
            match client.recv.recv::<ClientFrame>().await.unwrap() {
                ClientFrame::Ping => client.send.send(&ServerFrame::Pong).await.unwrap(),
                ClientFrame::Close => break,
                other => panic!("unexpected frame: {other:?}"),
            }
        }
    });

    // Client side.
    let config = gw_transport::pinned_client_config(&cert).unwrap();
    let client = Client::new(config).unwrap();
    let mut conn = client.connect(server_addr, "localhost").await.unwrap();

    conn.send
        .send(&ClientFrame::Hello {
            version: PROTOCOL_VERSION,
            client_name: "integration-test".into(),
            resume: None,
            account_token: None,
        })
        .await
        .unwrap();
    let hello: ServerFrame = conn.recv.recv().await.unwrap();
    match hello {
        ServerFrame::Hello { version, session_id, resumed, .. } => {
            assert_eq!(version, PROTOCOL_VERSION);
            assert_eq!(session_id, 42);
            assert!(!resumed);
        }
        other => panic!("expected Hello, got {other:?}"),
    }

    conn.send.send(&ClientFrame::Ping).await.unwrap();
    let pong: ServerFrame = conn.recv.recv().await.unwrap();
    assert!(matches!(pong, ServerFrame::Pong));

    conn.send.send(&ClientFrame::Close).await.unwrap();
    conn.send.finish();

    server_task.await.unwrap();
    client.wait_idle().await;
}
