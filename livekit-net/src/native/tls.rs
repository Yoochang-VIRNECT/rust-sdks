//! VIRNECT signalling TLS policy. Read once before the first native connection.

use std::sync::OnceLock;
use tokio::net::TcpStream;
use tokio_tungstenite::{tungstenite, MaybeTlsStream, WebSocketStream};

type Handshake = Result<
    (WebSocketStream<MaybeTlsStream<TcpStream>>, tungstenite::handshake::client::Response),
    tungstenite::Error,
>;

/// Preserve the custom View default; an explicit false restores verification.
fn parse_skip_cert_verify(value: Option<&str>) -> bool {
    match value {
        None => true,
        Some(value) => value.trim() == "1" || value.trim().eq_ignore_ascii_case("true"),
    }
}

/// Freeze the process-wide policy so HTTPS and WSS cannot disagree at runtime.
fn skip_cert_verify() -> bool {
    static SKIP: OnceLock<bool> = OnceLock::new();
    *SKIP.get_or_init(|| {
        let skip = match std::env::var("LIVEKIT_SKIP_CERT_VERIFY") {
            Ok(value) => parse_skip_cert_verify(Some(&value)),
            Err(std::env::VarError::NotPresent) => parse_skip_cert_verify(None),
            Err(_) => false,
        };
        if skip {
            log::warn!("VIRNECT: signalling TLS certificate verification is disabled; set LIVEKIT_SKIP_CERT_VERIFY=false before initialization to enable it");
        }
        skip
    })
}

/// Build the HTTPS client using the same policy as WSS.
pub(super) fn http_client() -> reqwest::Client {
    http_client_with_policy(skip_cert_verify())
}

/// Construct a client with a fixed policy (also used by loopback regression tests).
fn http_client_with_policy(_skip: bool) -> reqwest::Client {
    let builder = reqwest::Client::builder();
    #[cfg(any(
        feature = "native-tls",
        feature = "native-tls-vendored",
        feature = "rustls-tls-native-roots",
        feature = "rustls-tls-webpki-roots",
        feature = "__rustls-tls"
    ))]
    let builder = builder.danger_accept_invalid_certs(_skip).danger_accept_invalid_hostnames(_skip);
    builder.build().expect("failed to initialize LiveKit HTTP transport")
}

/// Connect without rewriting the URL, preserving the original Host and SNI.
pub(super) async fn connect_direct(request: http::Request<()>) -> Handshake {
    #[cfg(any(
        feature = "native-tls",
        feature = "native-tls-vendored",
        feature = "rustls-tls-native-roots",
        feature = "rustls-tls-webpki-roots",
        feature = "__rustls-tls"
    ))]
    return tokio_tungstenite::connect_async_tls_with_config(request, None, false, connector()?)
        .await;
    #[cfg(not(any(
        feature = "native-tls",
        feature = "native-tls-vendored",
        feature = "rustls-tls-native-roots",
        feature = "rustls-tls-webpki-roots",
        feature = "__rustls-tls"
    )))]
    tokio_tungstenite::connect_async(request).await
}

/// Perform TLS and the websocket handshake over an established CONNECT tunnel.
pub(super) async fn connect_tunnel(request: http::Request<()>, stream: TcpStream) -> Handshake {
    #[cfg(any(
        feature = "native-tls",
        feature = "native-tls-vendored",
        feature = "rustls-tls-native-roots",
        feature = "rustls-tls-webpki-roots",
        feature = "__rustls-tls"
    ))]
    return tokio_tungstenite::client_async_tls_with_config(request, stream, None, connector()?)
        .await;
    #[cfg(not(any(
        feature = "native-tls",
        feature = "native-tls-vendored",
        feature = "rustls-tls-native-roots",
        feature = "rustls-tls-webpki-roots",
        feature = "__rustls-tls"
    )))]
    {
        if request.uri().scheme_str() == Some("wss") {
            return Err(tungstenite::Error::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "WSS requires a TLS backend",
            )));
        }
        tokio_tungstenite::client_async(request, MaybeTlsStream::Plain(stream)).await
    }
}

/// Select an explicit bypass connector, or retain the backend's strict default.
#[cfg(any(
    feature = "native-tls",
    feature = "native-tls-vendored",
    feature = "rustls-tls-native-roots",
    feature = "rustls-tls-webpki-roots",
    feature = "__rustls-tls"
))]
fn connector() -> Result<Option<tokio_tungstenite::Connector>, tungstenite::Error> {
    connector_with_policy(skip_cert_verify())
}

/// Build a connector for one policy without mutating the process environment.
#[cfg(any(
    feature = "native-tls",
    feature = "native-tls-vendored",
    feature = "rustls-tls-native-roots",
    feature = "rustls-tls-webpki-roots",
    feature = "__rustls-tls"
))]
fn connector_with_policy(
    skip: bool,
) -> Result<Option<tokio_tungstenite::Connector>, tungstenite::Error> {
    if !skip {
        return Ok(None);
    }
    // Match tungstenite's native-tls precedence when both backends are enabled.
    #[cfg(any(feature = "native-tls", feature = "native-tls-vendored"))]
    {
        let connector = native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .build()
            .map_err(|e| tungstenite::Error::Io(std::io::Error::other(e)))?;
        Ok(Some(tokio_tungstenite::Connector::NativeTls(connector)))
    }
    #[cfg(not(any(feature = "native-tls", feature = "native-tls-vendored")))]
    {
        use std::sync::Arc;
        use tokio_rustls::rustls;
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| tungstenite::Error::Io(std::io::Error::other(e)))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(rustls_bypass::Verifier))
        .with_no_client_auth();
        Ok(Some(tokio_tungstenite::Connector::Rustls(Arc::new(config))))
    }
}

#[cfg(all(
    not(any(feature = "native-tls", feature = "native-tls-vendored")),
    any(
        feature = "rustls-tls-native-roots",
        feature = "rustls-tls-webpki-roots",
        feature = "__rustls-tls"
    )
))]
mod rustls_bypass {
    use tokio_rustls::rustls::{
        self,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{CertificateDer, ServerName, UnixTime},
        DigitallySignedStruct, Error, SignatureScheme,
    };

    /// Bypass server identity/trust checks while retaining TLS signature validation.
    #[derive(Debug)]
    pub(super) struct Verifier;

    impl ServerCertVerifier for Verifier {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &rustls::crypto::ring::default_provider().signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &rustls::crypto::ring::default_provider().signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse_skip_cert_verify;

    #[test]
    fn custom_default_and_explicit_policy() {
        assert!(parse_skip_cert_verify(None));
        for value in ["1", "true", "TRUE", " true "] {
            assert!(parse_skip_cert_verify(Some(value)));
        }
        for value in ["0", "false", "FALSE", "", "typo"] {
            assert!(!parse_skip_cert_verify(Some(value)));
        }
    }
}

#[cfg(all(
    test,
    any(
        feature = "native-tls",
        feature = "native-tls-vendored",
        feature = "rustls-tls-native-roots",
        feature = "rustls-tls-webpki-roots",
        feature = "__rustls-tls"
    )
))]
#[path = "tls_tests.rs"]
mod tls_tests;
