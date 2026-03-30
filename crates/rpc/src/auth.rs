//! HTTP Basic Auth middleware matching Bitcoin Core's cookie auth pattern.
//!
//! Bitcoin Core writes `__cookie__:<64-hex-chars>` to `<datadir>/.cookie` on startup
//! and accepts that credential (or an explicit --rpcuser/--rpcpassword pair) via
//! HTTP Basic authentication on every JSON-RPC request.
//!
//! This module provides a Tower [`Layer`] + [`Service`] that enforces the same
//! scheme so that any tool using `bitcoin-cli -rpcport=… -rpcconnect=…` can
//! authenticate against rustoshi identically to how it authenticates against
//! Bitcoin Core.
//!
//! # Auth decision matrix
//!
//! | Authorization header | Result |
//! |---|---|
//! | Missing | 401 + `WWW-Authenticate` challenge |
//! | Not "Basic …" | 401 |
//! | Decoded user = `__cookie__`, pass matches cookie_secret | 200 (pass-through) |
//! | Decoded user matches auth_user, pass matches auth_password | 200 (pass-through) |
//! | Anything else | 401 |
//!
//! # Content-Type normalisation
//!
//! Bitcoin Core's `httprpc.cpp` accepts both `application/json` and
//! `text/plain` Content-Types for JSON-RPC requests.  Some older clients
//! (including some versions of `bitcoin-cli`) send `text/plain`.  jsonrpsee
//! is strict about `application/json`, so the middleware rewrites `text/plain`
//! to `application/json` before forwarding the request.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use http::{header, Request, Response, StatusCode};
use hyper::Body;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tower::{Layer, Service};

// ============================================================
// AUTH CREDENTIALS (passed into the layer at construction time)
// ============================================================

/// Credentials accepted by the auth middleware.
///
/// At least one of `cookie` or `user_pass` must be `Some`; when neither is
/// set the middleware rejects every request.
#[derive(Clone, Debug)]
pub struct AuthCredentials {
    /// The raw hex secret from the .cookie file.  Accepted when the client
    /// presents `__cookie__:<secret>` as Basic credentials.
    pub cookie_secret: Option<String>,
    /// Explicit rpcuser/rpcpassword pair from the CLI.
    pub user_pass: Option<(String, String)>,
}

impl AuthCredentials {
    /// Returns `true` if the provided `user:pass` pair is accepted.
    pub fn verify(&self, user: &str, pass: &str) -> bool {
        // Cookie auth: user must literally be "__cookie__"
        if user == "__cookie__" {
            if let Some(ref secret) = self.cookie_secret {
                return pass == secret;
            }
            return false;
        }
        // Explicit rpcuser / rpcpassword
        if let Some((ref u, ref p)) = self.user_pass {
            if user == u && pass == p {
                return true;
            }
        }
        false
    }
}

// ============================================================
// TOWER LAYER
// ============================================================

/// Tower [`Layer`] that wraps an inner service with Bitcoin Core-compatible
/// HTTP Basic auth enforcement.
#[derive(Clone)]
pub struct AuthLayer {
    credentials: AuthCredentials,
}

impl AuthLayer {
    pub fn new(credentials: AuthCredentials) -> Self {
        Self { credentials }
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = AuthMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthMiddleware {
            inner,
            credentials: self.credentials.clone(),
        }
    }
}

// ============================================================
// TOWER SERVICE
// ============================================================

/// Tower [`Service`] that enforces HTTP Basic auth and normalises Content-Type.
#[derive(Clone)]
pub struct AuthMiddleware<S> {
    inner: S,
    credentials: AuthCredentials,
}

impl<S> Service<Request<Body>> for AuthMiddleware<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        // --- 1. Enforce HTTP Basic auth -----------------------------------
        let auth_result = check_auth(req.headers(), &self.credentials);
        if let Err(resp) = auth_result {
            return Box::pin(async move { Ok(resp) });
        }

        // --- 2. Normalise Content-Type: text/plain → application/json -----
        // Bitcoin Core accepts both; jsonrpsee only accepts application/json.
        if let Some(ct) = req.headers().get(header::CONTENT_TYPE) {
            let ct_str = ct.to_str().unwrap_or("");
            if ct_str.starts_with("text/plain") {
                req.headers_mut().insert(
                    header::CONTENT_TYPE,
                    header::HeaderValue::from_static("application/json"),
                );
            }
        }

        let fut = self.inner.call(req);
        Box::pin(async move { fut.await })
    }
}

// ============================================================
// AUTH CHECK HELPER
// ============================================================

/// Validate the `Authorization` header against the configured credentials.
///
/// Returns `Ok(())` on success, or an `Err(Response<Body>)` with a 401
/// response (including the `WWW-Authenticate` challenge header) on failure.
fn check_auth(
    headers: &http::HeaderMap,
    credentials: &AuthCredentials,
) -> Result<(), Response<Body>> {
    let unauthorized = |msg: &'static str| -> Response<Body> {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(
                header::WWW_AUTHENTICATE,
                r#"Basic realm="jsonrpc""#,
            )
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from(msg))
            .expect("static response is always valid")
    };

    let auth_header = headers
        .get(header::AUTHORIZATION)
        .ok_or_else(|| unauthorized("Missing Authorization header"))?;

    let auth_str = auth_header
        .to_str()
        .map_err(|_| unauthorized("Invalid Authorization header encoding"))?;

    let encoded = auth_str
        .strip_prefix("Basic ")
        .ok_or_else(|| unauthorized("Only Basic auth is supported"))?;

    let decoded = BASE64
        .decode(encoded.trim())
        .map_err(|_| unauthorized("Invalid Base64 in Authorization header"))?;

    let decoded_str = std::str::from_utf8(&decoded)
        .map_err(|_| unauthorized("Authorization credentials are not valid UTF-8"))?;

    // Split on the *first* colon only (password may contain colons)
    let colon = decoded_str
        .find(':')
        .ok_or_else(|| unauthorized("Authorization credentials missing ':'"))?;

    let (user, pass) = decoded_str.split_at(colon);
    let pass = &pass[1..]; // skip the ':'

    if credentials.verify(user, pass) {
        Ok(())
    } else {
        Err(unauthorized("Invalid credentials"))
    }
}

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn creds(cookie: Option<&str>, user_pass: Option<(&str, &str)>) -> AuthCredentials {
        AuthCredentials {
            cookie_secret: cookie.map(str::to_owned),
            user_pass: user_pass.map(|(u, p)| (u.to_owned(), p.to_owned())),
        }
    }

    fn make_header(user: &str, pass: &str) -> http::HeaderMap {
        let raw = format!("{}:{}", user, pass);
        let encoded = BASE64.encode(raw.as_bytes());
        let value = format!("Basic {}", encoded);
        let mut map = http::HeaderMap::new();
        map.insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_str(&value).unwrap(),
        );
        map
    }

    #[test]
    fn cookie_auth_accepted() {
        let c = creds(Some("deadbeef"), None);
        let headers = make_header("__cookie__", "deadbeef");
        assert!(check_auth(&headers, &c).is_ok());
    }

    #[test]
    fn cookie_auth_wrong_pass_rejected() {
        let c = creds(Some("deadbeef"), None);
        let headers = make_header("__cookie__", "cafebabe");
        assert!(check_auth(&headers, &c).is_err());
    }

    #[test]
    fn user_pass_auth_accepted() {
        let c = creds(None, Some(("alice", "s3cret")));
        let headers = make_header("alice", "s3cret");
        assert!(check_auth(&headers, &c).is_ok());
    }

    #[test]
    fn user_pass_wrong_rejected() {
        let c = creds(None, Some(("alice", "s3cret")));
        let headers = make_header("alice", "wrong");
        assert!(check_auth(&headers, &c).is_err());
    }

    #[test]
    fn missing_auth_header_rejected() {
        let c = creds(Some("abc"), None);
        let map = http::HeaderMap::new();
        assert!(check_auth(&map, &c).is_err());
    }

    #[test]
    fn cookie_user_with_no_cookie_configured_rejected() {
        // If no cookie_secret is set, __cookie__ auth must be rejected even
        // if the password happens to be empty.
        let c = creds(None, None);
        let headers = make_header("__cookie__", "");
        assert!(check_auth(&headers, &c).is_err());
    }

    #[test]
    fn password_with_colon_accepted() {
        // Password may contain colons; only the first colon in the decoded
        // string is the user/pass separator.
        let c = creds(None, Some(("bob", "p:a:s:s")));
        let headers = make_header("bob", "p:a:s:s");
        assert!(check_auth(&headers, &c).is_ok());
    }

    #[test]
    fn verify_cookie() {
        let c = creds(Some("secret"), None);
        assert!(c.verify("__cookie__", "secret"));
        assert!(!c.verify("__cookie__", "wrong"));
        assert!(!c.verify("other", "secret"));
    }

    #[test]
    fn verify_user_pass() {
        let c = creds(None, Some(("u", "p")));
        assert!(c.verify("u", "p"));
        assert!(!c.verify("u", "wrong"));
        assert!(!c.verify("wrong", "p"));
    }
}
