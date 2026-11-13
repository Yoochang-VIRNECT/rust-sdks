//! Loopback TLS regressions using a self-signed certificate with a mismatched name.

use super::*;
use futures_util::{SinkExt, StreamExt};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::{
    rustls::{
        self,
        pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    },
    TlsAcceptor,
};
use tungstenite::client::IntoClientRequest;

/// Create a test-only server that is deliberately not trusted by the OS.
fn acceptor() -> TlsAcceptor {
    let cert =
        CertificateDer::from_pem_slice(include_bytes!("../../tests/fixtures/tls-test-cert.pem"))
            .unwrap();
    let key =
        PrivateKeyDer::from_pem_slice(include_bytes!("../../tests/fixtures/tls-test-key.pem"))
            .unwrap();
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)
    .unwrap();
    // Prefer h2: desktop clients must still negotiate HTTP/1.1.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    TlsAcceptor::from(Arc::new(config))
}

/// Exercise the HTTP client and both websocket connection paths with real TLS.
#[tokio::test]
async fn self_signed_https_and_wss_obey_policy() {
    tokio::time::timeout(Duration::from_secs(20), async {
        for skip in [true, false] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let tls = acceptor();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                if let Ok(mut stream) = tls.accept(stream).await {
                    #[cfg(any(target_os = "windows", target_os = "macos"))]
                    assert_ne!(stream.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
                    let mut buf = [0; 4096];
                    if stream.read(&mut buf).await.unwrap_or(0) > 0 {
                        assert!(buf.starts_with(b"GET / HTTP/1.1\r\n"));
                        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await;
                    }
                }
            });
            let response = http_client_with_policy(skip).get(format!("https://{addr}/")).send().await;
            assert_eq!(response.is_ok(), skip, "HTTPS policy={skip}: {response:?}");
            if let Ok(response) = response { assert_eq!(response.text().await.unwrap(), "ok"); }
            server.await.unwrap();

            for tunnel in [false, true] {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                let tls = acceptor();
                let server = tokio::spawn(async move {
                    let (stream, _) = listener.accept().await.unwrap();
                    if let Ok(stream) = tls.accept(stream).await {
                        #[cfg(any(target_os = "windows", target_os = "macos"))]
                        assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"http/1.1".as_slice()));
                        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
                        assert_eq!(stream.get_ref().1.alpn_protocol(), None);
                        if let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await {
                            if let Some(Ok(message)) = ws.next().await { let _ = ws.send(message).await; }
                        }
                    }
                });
                let url = format!("wss://{addr}/rtc");
                let connector = connector_with_policy(skip).unwrap();
                let result = if tunnel {
                    let stream = TcpStream::connect(addr).await.unwrap();
                    if skip == skip_cert_verify() {
                        connect_tunnel(url.clone().into_client_request().unwrap(), stream).await
                    } else {
                        tokio_tungstenite::client_async_tls_with_config(&url, stream, None, connector).await
                    }
                } else {
                    if skip == skip_cert_verify() {
                        connect_direct(url.clone().into_client_request().unwrap()).await
                    } else {
                        tokio_tungstenite::connect_async_tls_with_config(&url, None, false, connector).await
                    }
                };
                assert_eq!(result.is_ok(), skip, "WSS tunnel={tunnel}, policy={skip}: {result:?}");
                if let Ok((mut ws, _)) = result {
                    ws.send(tungstenite::Message::Text("echo".into())).await.unwrap();
                    assert_eq!(ws.next().await.unwrap().unwrap().into_text().unwrap(), "echo");
                }
                server.await.unwrap();
            }
        }
    }).await.expect("TLS regression test timed out");
}
