//! HTTPS/TLS termination for the RPC server (W119 / FIX-64).
//!
//! Opt-in HTTPS support for the JSON-RPC endpoint. When `RpcConfig::tls_cert`
//! and `RpcConfig::tls_key` are both set, [`crate::start_rpc_server`] delegates
//! to [`serve_https`] which wires `jsonrpsee`'s tower service through a
//! `tokio-rustls` acceptor instead of binding plain hyper.
//!
//! ## Design
//!
//! `jsonrpsee` 0.22 has no first-class TLS hook, but exposes
//! `ServerBuilder::to_service_builder()` which yields a `TowerServiceBuilder`
//! that we can drive against a hand-rolled accept loop. Each accepted TCP
//! connection is wrapped by [`tokio_rustls::TlsAcceptor`] and handed to
//! `hyper::server::conn::Http::new().serve_connection(tls_stream, svc)` —
//! exactly the pattern jsonrpsee uses internally for plaintext (see
//! `jsonrpsee-server/src/server.rs:1222`).
//!
//! ## Crypto provider
//!
//! `rustls` 0.23 is configured with the `ring` provider (pure Rust, no C
//! toolchain). Default features are disabled in `Cargo.toml` to drop
//! `aws-lc-rs`, which would otherwise pull in bindgen + a C compiler.
//!
//! ## Reference
//!
//! - `bitcoin-core/src/httpserver.cpp` — Core's libevent + OpenSSL HTTPS
//!   pattern. We mirror its "both cert and key, or neither" startup
//!   validation (`HTTPServerStart`).
//! - BIP-78 §"Protocol" — PayJoin requires HTTPS (or `.onion`); this module
//!   enables the clearnet half of that requirement.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use futures_util::future::{select, Either};
use jsonrpsee::server::{stop_channel, BatchRequestConfig, ServerBuilder, ServerHandle};
use jsonrpsee::Methods;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::ServiceBuilder;

use crate::auth::AuthLayer;
use crate::server::MAX_BATCH_SIZE;
use crate::wallet_route::WalletRouteLayer;

/// Load a PEM-encoded certificate chain + private key from disk and build a
/// `rustls::ServerConfig` configured for HTTP/1.1 (ALPN `http/1.1`).
///
/// The private key may be PKCS#8 (`-----BEGIN PRIVATE KEY-----`), PKCS#1 RSA
/// (`-----BEGIN RSA PRIVATE KEY-----`), or SEC1 EC
/// (`-----BEGIN EC PRIVATE KEY-----`). Returns an error if the cert chain is
/// empty or no private key is found.
pub fn load_tls_config(
    cert_path: &Path,
    key_path: &Path,
) -> Result<Arc<ServerConfig>, std::io::Error> {
    // Install the default crypto provider (ring) — required by rustls 0.23 for
    // any process that builds a ServerConfig. `install_default()` is
    // idempotent across the process; the second call returns an Err which we
    // intentionally ignore (it just means another startup path beat us to it).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cert_file = File::open(cert_path).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("could not open RPC TLS cert {}: {e}", cert_path.display()),
        )
    })?;
    let key_file = File::open(key_path).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("could not open RPC TLS key {}: {e}", key_path.display()),
        )
    })?;

    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to parse PEM certificates from {}: {e}", cert_path.display()),
            )
        })?;
    if certs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "no PEM certificates found in {} — expected at least one CERTIFICATE block",
                cert_path.display()
            ),
        ));
    }

    let mut key_reader = BufReader::new(key_file);
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to parse PEM private key from {}: {e}", key_path.display()),
            )
        })?
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "no PEM private key found in {} — expected PKCS#8, RSA, or SEC1",
                    key_path.display()
                ),
            )
        })?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("cert/key pair rejected by rustls: {e}"),
            )
        })?;
    // Advertise HTTP/1.1 only — jsonrpsee 0.22 runs on hyper 0.14 which is
    // HTTP/1.x. Without an explicit `http/1.1` ALPN, clients negotiating h2
    // would 421 on every request.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(Arc::new(config))
}

/// Bind a TLS-terminating JSON-RPC server on `bind_address`.
///
/// Spawns the accept loop on the current tokio runtime and returns a
/// [`ServerHandle`] that callers can use to stop the server (drop or
/// `handle.stop()` triggers graceful shutdown of in-flight connections).
///
/// Connections are accepted on a plain `TcpListener`, then wrapped by
/// `TlsAcceptor`; the resulting `TlsStream` is fed to
/// `hyper::server::conn::Http::new().serve_connection(stream, svc)` — same
/// surface jsonrpsee uses for its plaintext path
/// (`jsonrpsee-server/src/server.rs:1222`).
///
/// The `http_middleware` shape is hard-coded to the [`AuthLayer`] +
/// [`WalletRouteLayer`] stack that matches `start_rpc_server`'s plaintext
/// branch: jsonrpsee 0.22's tower service has internal types that make a
/// fully-generic helper impractical, and the production wiring only ever uses
/// this one shape.
pub async fn serve_https(
    bind_address: &str,
    methods: Methods,
    http_middleware: ServiceBuilder<
        tower::layer::util::Stack<
            WalletRouteLayer,
            tower::layer::util::Stack<AuthLayer, tower::layer::util::Identity>,
        >,
    >,
    tls_config: Arc<ServerConfig>,
) -> anyhow::Result<ServerHandle> {
    use hyper::server::conn::Http;
    use tower::Service;

    let listener = TcpListener::bind(bind_address).await.map_err(|e| {
        anyhow::anyhow!("could not bind HTTPS RPC on {bind_address}: {e}")
    })?;
    let local_addr = listener.local_addr().ok();

    let svc_builder = ServerBuilder::default()
        .set_batch_request_config(BatchRequestConfig::Limit(MAX_BATCH_SIZE as u32))
        .max_response_body_size(128 * 1024 * 1024)
        .set_http_middleware(http_middleware)
        .to_service_builder();

    let (stop_handle, server_handle) = stop_channel();
    let acceptor = TlsAcceptor::from(tls_config);

    // Accept loop. Lives until `stop_handle.shutdown()` resolves (caller
    // dropped the `ServerHandle` or invoked `.stop()`).
    let accept_stop = stop_handle.clone();
    tokio::spawn(async move {
        loop {
            let shutdown = accept_stop.clone().shutdown();
            tokio::pin!(shutdown);

            let accept_fut = listener.accept();
            tokio::pin!(accept_fut);

            let (tcp_stream, peer_addr) = match select(accept_fut, shutdown).await {
                Either::Left((Ok(pair), _)) => pair,
                Either::Left((Err(e), _)) => {
                    tracing::warn!("HTTPS RPC accept error: {e}");
                    continue;
                }
                Either::Right(_) => {
                    tracing::debug!("HTTPS RPC accept loop shutting down");
                    break;
                }
            };

            let acceptor = acceptor.clone();
            let svc_builder = svc_builder.clone();
            let methods = methods.clone();
            let stop_handle = accept_stop.clone();

            tokio::spawn(async move {
                let tls_stream = match acceptor.accept(tcp_stream).await {
                    Ok(s) => s,
                    Err(e) => {
                        // Common with curl -k pointing at HTTP, or browsers
                        // probing without SNI — keep at debug to avoid log
                        // spam.
                        tracing::debug!(peer = %peer_addr, "TLS handshake failed: {e}");
                        return;
                    }
                };

                let mut svc = svc_builder.build(methods, stop_handle.clone());
                // Adapt the inner service's `Error` type to `Infallible` by
                // catching any error inside the closure and converting it to
                // a 500 response. The jsonrpsee 0.22 TowerService should
                // never actually fail at the Service layer — auth + RPC
                // errors are already encoded as 4xx/JSON-RPC error
                // responses inside `Ok(Response<Body>)` — so the 500 path
                // is best-effort defensive. This shape also avoids
                // higher-ranked lifetime variance ("implementation of From
                // is not general enough") that would otherwise leak the
                // inner Service::Error's lifetime into the spawned future.
                let service = hyper::service::service_fn(
                    move |req: hyper::Request<hyper::Body>| {
                        let fut = svc.call(req);
                        async move {
                            match fut.await {
                                Ok(resp) => Ok::<_, std::convert::Infallible>(resp),
                                Err(e) => {
                                    tracing::warn!("HTTPS RPC inner service error: {e}");
                                    Ok(hyper::Response::builder()
                                        .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                                        .body(hyper::Body::from("internal server error"))
                                        .expect("static response"))
                                }
                            }
                        }
                    },
                );

                let conn = Http::new().serve_connection(tls_stream, service).with_upgrades();
                tokio::pin!(conn);
                let shutdown = stop_handle.shutdown();
                tokio::pin!(shutdown);

                let res = match select(conn.as_mut(), shutdown).await {
                    Either::Left((res, _)) => res,
                    Either::Right((_, _stopped)) => {
                        conn.as_mut().graceful_shutdown();
                        conn.await
                    }
                };
                if let Err(e) = res {
                    tracing::debug!(peer = %peer_addr, "HTTPS serve_connection ended: {e}");
                }
            });
        }
    });

    match local_addr {
        Some(addr) => tracing::info!("RPC server listening on https://{}", addr),
        None => tracing::info!("RPC server listening on https://{} (local_addr unavailable)", bind_address),
    }
    Ok(server_handle)
}

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// Generate a self-signed cert+key into two temp PEM files and return
    /// `(cert_file, key_file)` keeping the files alive for the test's
    /// lifetime.
    fn self_signed_pem(subject_alt_names: Vec<String>) -> (NamedTempFile, NamedTempFile) {
        let cert = rcgen::generate_simple_self_signed(subject_alt_names)
            .expect("rcgen self-signed cert generation");
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let mut cert_file = NamedTempFile::new().expect("temp cert file");
        cert_file
            .write_all(cert_pem.as_bytes())
            .expect("write cert pem");
        let mut key_file = NamedTempFile::new().expect("temp key file");
        key_file
            .write_all(key_pem.as_bytes())
            .expect("write key pem");
        (cert_file, key_file)
    }

    #[test]
    fn load_tls_config_accepts_self_signed_pkcs8() {
        let (cert_file, key_file) = self_signed_pem(vec!["localhost".to_string()]);
        let cfg = load_tls_config(cert_file.path(), key_file.path())
            .expect("self-signed PKCS#8 PEM should load");
        // ALPN must include http/1.1 — hyper 0.14 cannot do h2.
        assert_eq!(cfg.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn load_tls_config_rejects_missing_cert_file() {
        let nonexistent = std::path::Path::new("/nonexistent/rustoshi-tls-cert.pem");
        let (_cert_file, key_file) = self_signed_pem(vec!["localhost".to_string()]);
        let err = load_tls_config(nonexistent, key_file.path())
            .expect_err("missing cert file must error");
        let msg = err.to_string();
        assert!(
            msg.contains("could not open RPC TLS cert"),
            "expected friendly error mentioning cert path, got: {msg}"
        );
    }

    #[test]
    fn load_tls_config_rejects_missing_key_file() {
        let (cert_file, _key_file) = self_signed_pem(vec!["localhost".to_string()]);
        let nonexistent = std::path::Path::new("/nonexistent/rustoshi-tls-key.pem");
        let err = load_tls_config(cert_file.path(), nonexistent)
            .expect_err("missing key file must error");
        let msg = err.to_string();
        assert!(
            msg.contains("could not open RPC TLS key"),
            "expected friendly error mentioning key path, got: {msg}"
        );
    }

    #[test]
    fn load_tls_config_rejects_empty_pem() {
        let mut empty_cert = NamedTempFile::new().expect("temp cert");
        empty_cert.write_all(b"").expect("write empty cert");
        let (_cert_file, key_file) = self_signed_pem(vec!["localhost".to_string()]);
        let err = load_tls_config(empty_cert.path(), key_file.path())
            .expect_err("empty PEM must error");
        let msg = err.to_string();
        assert!(
            msg.contains("no PEM certificates found"),
            "expected 'no PEM certificates found' error, got: {msg}"
        );
    }

    /// End-to-end HTTPS round-trip: boot `serve_https` against a minimal
    /// `Methods` registry, then drive a JSON-RPC request through a raw
    /// `tokio_rustls` client and assert the response status + body.
    ///
    /// This proves the full stack — TCP accept → rustls handshake → hyper
    /// 0.14 HTTP/1.1 parsing → AuthLayer middleware → jsonrpsee dispatch →
    /// JSON-RPC 2.0 response — works under TLS exactly as it does under HTTP.
    #[tokio::test]
    async fn https_round_trip_returns_jsonrpc_response() {
        use jsonrpsee::server::RpcModule;
        use rustls::pki_types::ServerName;
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;
        use tokio_rustls::TlsConnector;

        // 1. Generate a self-signed cert keyed for 127.0.0.1.
        let (cert_file, key_file) = self_signed_pem(vec!["127.0.0.1".to_string()]);
        let server_cfg = load_tls_config(cert_file.path(), key_file.path())
            .expect("load self-signed TLS config");
        // Snapshot the cert DER for the client's root store.
        let cert_der: Vec<u8> = {
            let mut r = std::io::BufReader::new(
                std::fs::File::open(cert_file.path()).expect("open cert"),
            );
            let certs: Vec<_> = rustls_pemfile::certs(&mut r)
                .collect::<Result<Vec<_>, _>>()
                .expect("parse cert pem");
            assert_eq!(certs.len(), 1, "expected exactly one cert in self-signed PEM");
            certs[0].as_ref().to_vec()
        };

        // 2. Register a trivial RPC method `echo` that returns its sole arg.
        let mut module: RpcModule<()> = RpcModule::new(());
        module
            .register_method("echo", |params, _ctx| {
                let arg: String = params.one()?;
                Ok::<_, jsonrpsee::types::ErrorObjectOwned>(arg)
            })
            .expect("register echo");
        let methods: Methods = module.into();

        // 3. Build the AuthLayer-shaped middleware exactly like the production
        // wiring would (no auth credentials set → AuthLayer rejects everything
        // — but for this test we want methods to dispatch, so install a
        // matching `user:pass` credential pair).
        use crate::auth::AuthCredentials;
        let http_middleware = tower::ServiceBuilder::new()
            .layer(AuthLayer::new(AuthCredentials {
                cookie_secret: None,
                user_pass: Some(("u".to_string(), "p".to_string())),
            }))
            .layer(WalletRouteLayer::new());

        // 4. Bind on an OS-assigned port.
        let bind = "127.0.0.1:0";
        // The TCP listener inside serve_https needs an address; we'll find
        // the actual port by inspecting the log... actually let's bind here
        // first to learn the port, then drop and let serve_https rebind. A
        // small race window, but for a test that's acceptable.
        let probe = tokio::net::TcpListener::bind(bind).await.expect("probe bind");
        let port = probe.local_addr().expect("probe addr").port();
        drop(probe);
        let bind_addr = format!("127.0.0.1:{port}");

        let server_handle = serve_https(&bind_addr, methods, http_middleware, server_cfg)
            .await
            .expect("serve_https start");

        // Give the accept loop a tick to be ready.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // 5. Client: rustls with our self-signed cert as the only root.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(cert_der))
            .expect("add self-signed root");
        let mut client_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = TlsConnector::from(Arc::new(client_cfg));

        let tcp = TcpStream::connect(&bind_addr).await.expect("tcp connect");
        let server_name = ServerName::try_from("127.0.0.1").expect("server name");
        let mut tls = connector.connect(server_name, tcp).await.expect("tls handshake");

        // 6. Send a JSON-RPC 2.0 echo("hello") request with Basic auth.
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"echo","params":["hello"]}"#;
        let auth = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            b"u:p",
        );
        let request = format!(
            "POST / HTTP/1.1\r\n\
             Host: 127.0.0.1:{port}\r\n\
             Content-Type: application/json\r\n\
             Authorization: Basic {auth}\r\n\
             Content-Length: {len}\r\n\
             Connection: close\r\n\r\n\
             {body}",
            port = port,
            auth = auth,
            len = body.len(),
            body = body,
        );
        tls.write_all(request.as_bytes()).await.expect("write request");
        tls.flush().await.expect("flush");

        let mut response = Vec::new();
        tls.read_to_end(&mut response).await.expect("read response");
        let response_str = String::from_utf8_lossy(&response).to_string();

        // Stop the server (drop the handle would also work).
        server_handle.stop().expect("stop server");

        // 7. Assertions.
        assert!(
            response_str.starts_with("HTTP/1.1 200"),
            "expected 200 OK over HTTPS, got:\n{response_str}"
        );
        assert!(
            response_str.contains("\"result\":\"hello\""),
            "expected JSON-RPC result=hello, got:\n{response_str}"
        );
    }

    #[test]
    fn load_tls_config_rejects_garbage_key() {
        // The PEM parser is permissive — it just collects bytes between
        // BEGIN/END markers. The rejection happens at the rustls
        // `with_single_cert` step where the key bytes are validated against
        // RSA / ECDSA / EdDSA decoders.
        let (cert_file, _key_file) = self_signed_pem(vec!["localhost".to_string()]);
        let mut garbage_key = NamedTempFile::new().expect("temp key");
        garbage_key
            .write_all(b"-----BEGIN PRIVATE KEY-----\nbm90IGEgcmVhbCBrZXk=\n-----END PRIVATE KEY-----\n")
            .expect("write garbage key");
        let err = load_tls_config(cert_file.path(), garbage_key.path())
            .expect_err("garbage key must error");
        let msg = err.to_string();
        assert!(
            msg.contains("failed to parse PEM private key")
                || msg.contains("no PEM private key found")
                || msg.contains("cert/key pair rejected by rustls"),
            "expected PEM parse or rustls reject error, got: {msg}"
        );
    }
}
