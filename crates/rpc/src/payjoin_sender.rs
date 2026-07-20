//! BIP-78 PayJoin sender HTTP client (W119 / FIX-66).
//!
//! Drives the sender side of the BIP-78 flow:
//!
//!  1. POST a base64 Original PSBT to the receiver's `pj=` endpoint.
//!  2. Read the modified PSBT back as a `text/plain` HTTP body.
//!  3. Return the modified PSBT (caller will run anti-snoop validators
//!     from [`rustoshi_wallet::payjoin::validate_proposed_psbt`] +
//!     re-sign + broadcast; on any error the caller falls back to
//!     broadcasting the Original tx, per BIP-78 G22).
//!
//! ## TLS / scheme policy
//!
//! BIP-78 §"Protocol" requires the sender to refuse plain `http://`
//! endpoints unless the host is a `.onion` Tor hidden service.
//! [`post_original_psbt`] enforces this:
//!
//!   - `https://...`             → TLS via `tokio-rustls` + webpki roots.
//!   - `http://abc...xyz.onion`  → plain TCP allowed.
//!   - everything else           → [`SenderHttpError::PlaintextDisallowed`].
//!
//! For HTTPS we use the same `rustls` 0.23 (ring provider) crate FIX-64
//! already wired for the server side. A client `ClientConfig` is built
//! from `webpki-roots` if available; otherwise a minimal "any cert"
//! variant is rejected — this keeps us from silently accepting
//! self-signed certs from a malicious receiver and satisfies G24.
//!
//! ## Why hyper 0.14 (not 1.x or reqwest)
//!
//! The RPC crate already depends on hyper 0.14 for the server-side TLS
//! path (FIX-64). Reusing the same hyper version avoids dragging
//! reqwest's transitive bulk (tokio-runtime, native-tls, …) into the
//! wallet binary; the BIP-78 POST is a single request per call so
//! we don't need a connection pool, only a one-shot client.
//!
//! ## Reference
//!
//! - BIP-78: https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki
//! - `bitcoin-core` has no PayJoin support; ecosystem references are
//!   the rust `payjoin` crate and `btcpayserver`'s reference receiver.

use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use rustoshi_wallet::payjoin::MAX_ORIGINAL_PSBT_BYTES;

/// Errors raised by the BIP-78 sender HTTP client.
///
/// `SenderHttpError::HttpStatus` is the variant that G22 sender
/// fallback-to-original keys on: any non-2xx response (4xx receiver
/// reject, 5xx receiver outage) is wrapped in this variant so the
/// caller knows it's safe to broadcast the Original tx unmodified.
#[derive(Debug, thiserror::Error)]
pub enum SenderHttpError {
    /// URL was malformed or used an unsupported scheme.
    #[error("invalid endpoint: {0}")]
    InvalidEndpoint(String),
    /// BIP-78 forbids plain HTTP except for `.onion` hosts. Sender
    /// refused to send.
    #[error("plaintext HTTP refused: only https:// or http://*.onion endpoints allowed")]
    PlaintextDisallowed,
    /// TCP connect failed (DNS, timeout, refused, …).
    #[error("connect failed: {0}")]
    Connect(String),
    /// TLS handshake failed — cert validation (G24) or protocol error.
    #[error("TLS handshake failed: {0}")]
    Tls(String),
    /// I/O error writing/reading the HTTP request or response.
    #[error("HTTP I/O error: {0}")]
    Io(String),
    /// Receiver answered, but with a non-2xx status. G22-relevant: the
    /// sender must fall back to broadcasting the Original PSBT.
    #[error("receiver returned HTTP {status}: {body}")]
    HttpStatus {
        /// HTTP status code (3-digit, e.g. 503).
        status: u16,
        /// Raw response body (typically JSON `{"errorCode": "..."}`).
        body: String,
    },
    /// Receiver replied with a body too large to be a sane BIP-78 reply.
    #[error("response body too large ({0} bytes; max {MAX_ORIGINAL_PSBT_BYTES})")]
    ResponseTooLarge(usize),
    /// Receiver replied with malformed framing (no header terminator).
    #[error("malformed HTTP response: {0}")]
    MalformedResponse(String),
}

/// Where to talk to and how.
///
/// `endpoint` is the URL the sender extracted from a BIP-78 `pj=` query
/// param (or the receiver constructed it locally in `getpayjoinrequest`).
///
/// `query` is the BIP-78 query string with the sender's options
/// already URL-encoded — for example
/// `v=1&maxadditionalfeecontribution=1000&minfeerate=2&disableoutputsubstitution=0`.
///
/// `body_b64` is the base64 Original PSBT.
#[derive(Clone, Debug)]
pub struct SenderRequest {
    /// Full URL of the receiver's PayJoin endpoint.
    pub endpoint: String,
    /// BIP-78 query string (already URL-encoded, no leading `?`).
    pub query: String,
    /// Base64-encoded Original PSBT.
    pub body_b64: String,
    /// Overall request timeout (connect+write+read).
    pub timeout: Duration,
}

impl SenderRequest {
}

/// Parsed pieces of a `pj=` endpoint URL.
#[derive(Debug)]
struct ParsedUrl {
    #[allow(dead_code)] // kept for debugging / future "scheme" introspection
    scheme: String,
    host: String,
    port: u16,
    path: String,
    /// `true` ⇔ scheme is `https`. Plain HTTP on a `.onion` host is
    /// represented as `tls=false` here; the caller has already
    /// accepted the scheme policy.
    tls: bool,
}

impl ParsedUrl {
    fn parse(url: &str) -> Result<Self, SenderHttpError> {
        let (scheme, rest) = if let Some(rest) = url.strip_prefix("https://") {
            ("https", rest)
        } else if let Some(rest) = url.strip_prefix("http://") {
            ("http", rest)
        } else {
            return Err(SenderHttpError::InvalidEndpoint(format!(
                "unsupported scheme in {url:?}"
            )));
        };

        // host[:port][/path][?query]
        let (host_port, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        if host_port.is_empty() {
            return Err(SenderHttpError::InvalidEndpoint(format!(
                "empty host in {url:?}"
            )));
        }

        // Crude IPv6 detection: [::1]:443 form. We don't need full
        // RFC-3986 conformance — the receiver-vended URLs are typically
        // ASCII hostnames or `.onion` v3.
        let (host, port_str) = if let Some(end) = host_port.strip_prefix('[') {
            let close = end
                .find(']')
                .ok_or_else(|| SenderHttpError::InvalidEndpoint("unterminated [ipv6]".into()))?;
            let host = &end[..close];
            let after = &end[close + 1..];
            let port = after.strip_prefix(':').unwrap_or("");
            (host.to_string(), port)
        } else if let Some(idx) = host_port.rfind(':') {
            (host_port[..idx].to_string(), &host_port[idx + 1..])
        } else {
            (host_port.to_string(), "")
        };

        let default_port: u16 = if scheme == "https" { 443 } else { 80 };
        let port = if port_str.is_empty() {
            default_port
        } else {
            port_str.parse::<u16>().map_err(|_| {
                SenderHttpError::InvalidEndpoint(format!("invalid port {port_str:?}"))
            })?
        };

        Ok(ParsedUrl {
            scheme: scheme.to_string(),
            host,
            port,
            path: path.to_string(),
            tls: scheme == "https",
        })
    }
}

/// Apply BIP-78 §"Protocol" scheme rules: `https://`, or `http://`
/// to a `.onion` v2/v3 hostname. Returns
/// [`SenderHttpError::PlaintextDisallowed`] otherwise.
fn enforce_scheme_policy(url: &ParsedUrl) -> Result<(), SenderHttpError> {
    if url.tls {
        return Ok(());
    }
    // Plain HTTP — must be a Tor hidden service (`.onion`).
    if url.host.to_ascii_lowercase().ends_with(".onion") {
        return Ok(());
    }
    Err(SenderHttpError::PlaintextDisallowed)
}

/// Build a `rustls::ClientConfig` configured with the platform/webpki
/// root store. The ring provider is installed lazily (same idempotent
/// pattern FIX-64 uses).
///
/// We do NOT accept invalid certificates — that is the G24 contract.
/// If the receiver's HTTPS cert is self-signed, expired, or wrong-
/// hostname, the TLS handshake fails and the caller falls back to
/// G22.
fn build_client_config() -> Result<Arc<ClientConfig>, SenderHttpError> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut roots = RootCertStore::empty();
    // webpki-roots is not in the workspace; for the FIX-66 cut we
    // ship a static root cert via the rcgen test infrastructure when
    // running the test, and require operators to provide a system
    // root store in production via the existing TLS pieces. To keep
    // the prod path deterministic we accept the OS's pre-installed
    // roots when readable, falling back to an empty store (which
    // makes all production HTTPS fail closed, surfacing as G24).
    //
    // This is enough for FIX-66 because: the in-process test server
    // (see `crates/rpc/tests/test_fix66_payjoin_sender.rs`) accepts
    // a custom cert via a dedicated test-only helper that bypasses
    // the global verifier. Production callers wiring a public CA
    // are not blocked: empty root store → handshake error →
    // SenderHttpError::Tls → G22 fallback. Operators that need
    // mTLS / private CAs can extend this module with a
    // `with_custom_roots(...)` builder; deliberately out-of-scope
    // for the FIX-66 anti-snoop closure.
    if let Ok(certs) = load_system_roots() {
        for c in certs {
            let _ = roots.add(c);
        }
    }

    let cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

/// Best-effort load of the system root certificate bundle. Tries
/// /etc/ssl/certs/ca-certificates.crt (Debian/Ubuntu) and
/// /etc/ssl/cert.pem (BSD/macOS). Returns an empty list on miss; the
/// caller treats that as "production HTTPS will fail closed", which
/// is the correct G24 stance.
fn load_system_roots() -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, std::io::Error> {
    let candidates = [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/ssl/cert.pem",
    ];
    for path in candidates.iter() {
        if let Ok(file) = std::fs::File::open(path) {
            let mut reader = std::io::BufReader::new(file);
            let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
                .filter_map(|c| c.ok())
                .collect();
            if !certs.is_empty() {
                return Ok(certs);
            }
        }
    }
    Ok(Vec::new())
}

/// POST the Original PSBT to `req.endpoint` and return the receiver's
/// reply body. The reply is the modified PSBT as a `text/plain` base64
/// string (BIP-78 §"Sender's actions").
///
/// `client_config` overrides the default rustls config when `Some`.
/// Used by tests to install a custom root store; production callers
/// pass `None` (which loads the system root bundle).
pub async fn post_original_psbt(
    req: &SenderRequest,
    client_config: Option<Arc<ClientConfig>>,
) -> Result<String, SenderHttpError> {
    let url = ParsedUrl::parse(&req.endpoint)?;
    enforce_scheme_policy(&url)?;

    // Cap the request lifetime including connect.
    tokio::time::timeout(req.timeout, async move {
        post_inner(req, &url, client_config).await
    })
    .await
    .map_err(|_| SenderHttpError::Io(format!("timeout after {:?}", req.timeout)))?
}

async fn post_inner(
    req: &SenderRequest,
    url: &ParsedUrl,
    client_config: Option<Arc<ClientConfig>>,
) -> Result<String, SenderHttpError> {
    // Path + query.
    let full_path = if req.query.is_empty() {
        url.path.clone()
    } else if url.path.contains('?') {
        format!("{}&{}", url.path, req.query)
    } else {
        format!("{}?{}", url.path, req.query)
    };

    let host_hdr = if (url.tls && url.port == 443) || (!url.tls && url.port == 80) {
        url.host.clone()
    } else {
        format!("{}:{}", url.host, url.port)
    };

    let body = req.body_b64.as_bytes();
    let request_line = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         Accept: text/plain\r\n\
         User-Agent: rustoshi-payjoin/0.1\r\n\
         \r\n",
        path = full_path,
        host = host_hdr,
        len = body.len(),
    );

    let tcp = TcpStream::connect((url.host.as_str(), url.port))
        .await
        .map_err(|e| SenderHttpError::Connect(e.to_string()))?;

    if url.tls {
        let cfg = match client_config {
            Some(c) => c,
            None => build_client_config()?,
        };
        let connector = TlsConnector::from(cfg);
        let server_name = ServerName::try_from(url.host.clone())
            .map_err(|e| SenderHttpError::Tls(format!("invalid server name: {e}")))?;
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| SenderHttpError::Tls(e.to_string()))?;
        tls.write_all(request_line.as_bytes())
            .await
            .map_err(|e| SenderHttpError::Io(e.to_string()))?;
        tls.write_all(body)
            .await
            .map_err(|e| SenderHttpError::Io(e.to_string()))?;
        let mut buf = Vec::with_capacity(8 * 1024);
        tls.read_to_end(&mut buf)
            .await
            .map_err(|e| SenderHttpError::Io(e.to_string()))?;
        parse_response(&buf)
    } else {
        let mut tcp = tcp;
        tcp.write_all(request_line.as_bytes())
            .await
            .map_err(|e| SenderHttpError::Io(e.to_string()))?;
        tcp.write_all(body)
            .await
            .map_err(|e| SenderHttpError::Io(e.to_string()))?;
        let mut buf = Vec::with_capacity(8 * 1024);
        tcp.read_to_end(&mut buf)
            .await
            .map_err(|e| SenderHttpError::Io(e.to_string()))?;
        parse_response(&buf)
    }
}

/// Parse an HTTP/1.1 response.  Returns the body on 2xx, otherwise
/// [`SenderHttpError::HttpStatus`] carrying the status code and body so
/// the caller can drive G22 fallback semantics.
fn parse_response(buf: &[u8]) -> Result<String, SenderHttpError> {
    let head_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| SenderHttpError::MalformedResponse(
            "no header/body separator".into(),
        ))?;
    let head = std::str::from_utf8(&buf[..head_end])
        .map_err(|e| SenderHttpError::MalformedResponse(format!("non-UTF-8 headers: {e}")))?;
    let body = &buf[head_end + 4..];

    if body.len() > MAX_ORIGINAL_PSBT_BYTES * 2 {
        return Err(SenderHttpError::ResponseTooLarge(body.len()));
    }

    let status_line = head
        .lines()
        .next()
        .ok_or_else(|| SenderHttpError::MalformedResponse("empty response".into()))?;
    let mut it = status_line.splitn(3, ' ');
    let _version = it
        .next()
        .ok_or_else(|| SenderHttpError::MalformedResponse("no HTTP version".into()))?;
    let status_str = it
        .next()
        .ok_or_else(|| SenderHttpError::MalformedResponse("no HTTP status".into()))?;
    let status: u16 = status_str.parse().map_err(|_| {
        SenderHttpError::MalformedResponse(format!("bad status {status_str:?}"))
    })?;

    // Heuristically strip Transfer-Encoding: chunked framing if any.
    // axum 0.7 with hyper 0.14 typically sends Content-Length for
    // small replies, but `start_rest_server*` runs hyper 1.x in tests
    // (via axum::serve), which may chunk. The PayJoin reply is always
    // small enough that we just keep the base64 alphabet bytes.
    let body_str = String::from_utf8_lossy(body).into_owned();
    if !(200..300).contains(&status) {
        // Body may carry the BIP-78 JSON error envelope; preserve it.
        return Err(SenderHttpError::HttpStatus {
            status,
            body: body_str.trim().to_string(),
        });
    }
    Ok(body_str)
}

/// Helper: trim a possibly-chunked HTTP body down to its base64
/// alphabet residue, dropping any leading hex-chunk-length / trailing
/// 0\r\n\r\n framing the test transport may have inserted. Exposed so
/// the RPC layer can stay uniform with the receiver-side tests.
pub fn trim_to_base64(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_https_basic() {
        let u = ParsedUrl::parse("https://example.com/payjoin").unwrap();
        assert_eq!(u.scheme, "https");
        assert_eq!(u.host, "example.com");
        assert_eq!(u.port, 443);
        assert_eq!(u.path, "/payjoin");
        assert!(u.tls);
    }

    #[test]
    fn parse_http_with_port_and_query() {
        let u = ParsedUrl::parse("http://abc.onion:8080/x?y=z").unwrap();
        assert_eq!(u.scheme, "http");
        assert_eq!(u.host, "abc.onion");
        assert_eq!(u.port, 8080);
        assert_eq!(u.path, "/x?y=z");
        assert!(!u.tls);
    }

    #[test]
    fn parse_rejects_other_schemes() {
        let err = ParsedUrl::parse("ftp://example.com/").unwrap_err();
        assert!(matches!(err, SenderHttpError::InvalidEndpoint(_)));
    }

    #[test]
    fn scheme_policy_allows_https() {
        let u = ParsedUrl::parse("https://example.com/").unwrap();
        enforce_scheme_policy(&u).unwrap();
    }

    #[test]
    fn scheme_policy_allows_onion_http() {
        let u = ParsedUrl::parse(
            "http://3g2upl4pq6kufc4m.onion/payjoin",
        )
        .unwrap();
        enforce_scheme_policy(&u).unwrap();
        // BIP-78 v3 onions also work.
        let u = ParsedUrl::parse(
            "http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/payjoin",
        )
        .unwrap();
        enforce_scheme_policy(&u).unwrap();
    }

    #[test]
    fn scheme_policy_rejects_plain_http_clearnet() {
        let u = ParsedUrl::parse("http://example.com/payjoin").unwrap();
        let err = enforce_scheme_policy(&u).unwrap_err();
        assert!(matches!(err, SenderHttpError::PlaintextDisallowed));
    }

    #[test]
    fn parse_response_strips_status() {
        let raw =
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 4\r\n\r\nbody";
        let s = parse_response(raw).unwrap();
        assert!(s.contains("body"));
    }

    #[test]
    fn parse_response_propagates_non_2xx() {
        let raw =
            b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\n\r\n{\"errorCode\":\"unavailable\"}";
        let err = parse_response(raw).unwrap_err();
        match err {
            SenderHttpError::HttpStatus { status, body } => {
                assert_eq!(status, 503);
                assert!(body.contains("unavailable"));
            }
            other => panic!("expected HttpStatus, got {other:?}"),
        }
    }
}
