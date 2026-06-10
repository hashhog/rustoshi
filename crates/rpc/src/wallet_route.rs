//! `/wallet/<name>` URL routing for wallet RPCs (Core's
//! `WALLET_ENDPOINT_BASE` dispatch — `bitcoin-core/src/wallet/rpc/util.cpp:19,54-86`
//! `GetWalletNameFromJSONRPCRequest` / `GetWalletForJSONRPCRequest`, registered
//! through `httprpc.cpp:339-341`).
//!
//! Bitcoin Core pins a wallet RPC to a specific wallet when the request is
//! POSTed to `/wallet/<walletname>` instead of the bare endpoint. jsonrpsee
//! 0.22's HTTP transport ignores the request path entirely, so before this
//! layer existed rustoshi silently dropped the URL pin and resolved every
//! wallet RPC against the "default" wallet — which errors `-19` the moment a
//! second wallet is loaded, even ON the `/wallet/<name>` URL.
//!
//! # Mechanism
//!
//! A tower middleware extracts the wallet name from the request path and
//! scopes a tokio [`task_local`] around the inner (jsonrpsee) service call.
//! This is sound on jsonrpsee 0.22.5 because its HTTP transport awaits
//! `handle_rpc_call` INLINE in the same task (verified:
//! `jsonrpsee-server-0.22.5/src/transport/http.rs:91`; the only `tokio::spawn`
//! on the server path is the WebSocket-upgrade branch). Wallet method handlers
//! therefore observe the task-local through [`current_wallet_route`].
//!
//! # Caveat
//!
//! The task-local does NOT propagate across the WebSocket transport (which
//! spawns). Bitcoin RPC clients (bitcoin-cli, curl, every wallet harness) use
//! HTTP POST, matching Core's own HTTP-only RPC server, so the HTTP-only scope
//! is acceptable; WS callers fall back to the bare-endpoint resolution rules.

use http::Request;
use hyper::Body;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tower::{Layer, Service};

tokio::task_local! {
    /// The wallet name pinned by the current HTTP request's `/wallet/<name>`
    /// path, if any. `None` for bare-endpoint requests.
    static WALLET_ROUTE: Option<String>;
}

/// The wallet name pinned by the current request's URL path, when the request
/// arrived via HTTP `POST /wallet/<name>`. Returns `None` outside a request
/// scope (unit tests, WS transport) or for bare-endpoint requests.
pub fn current_wallet_route() -> Option<String> {
    WALLET_ROUTE.try_with(|w| w.clone()).ok().flatten()
}

/// Extract + percent-decode the wallet name from a request path.
///
/// Mirrors Core: `if (URI.substr(0, WALLET_ENDPOINT_BASE.size()) ==
/// WALLET_ENDPOINT_BASE) name = UrlDecode(URI.substr(base.size()))`
/// (wallet/rpc/util.cpp:56-59). An empty remainder (`POST /wallet/`) pins the
/// empty wallet name, exactly like Core (which then fails lookup with -18
/// unless a wallet literally named "" is loaded).
pub fn wallet_name_from_path(path: &str) -> Option<String> {
    path.strip_prefix("/wallet/").map(url_decode)
}

/// Minimal percent-decoder (Core's `UrlDecode`, urlapi.cpp): `%XX` hex pairs
/// become the encoded byte; lone/invalid `%` sequences pass through verbatim.
/// `+` is NOT decoded to space (Core does not either — it is path, not query,
/// decoding).
fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if let (Some(hi), Some(lo)) = (
                bytes.get(i + 1).and_then(|b| (*b as char).to_digit(16)),
                bytes.get(i + 2).and_then(|b| (*b as char).to_digit(16)),
            ) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Tower [`Layer`] that scopes the request's `/wallet/<name>` pin around the
/// inner service. Stacked next to [`crate::auth::AuthLayer`] in
/// `start_rpc_server` (both transports).
#[derive(Clone, Default)]
pub struct WalletRouteLayer;

impl WalletRouteLayer {
    pub fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for WalletRouteLayer {
    type Service = WalletRouteMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        WalletRouteMiddleware { inner }
    }
}

/// Tower [`Service`] produced by [`WalletRouteLayer`].
#[derive(Clone)]
pub struct WalletRouteMiddleware<S> {
    inner: S,
}

impl<S> Service<Request<Body>> for WalletRouteMiddleware<S>
where
    S: Service<Request<Body>> + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let wallet = wallet_name_from_path(req.uri().path());
        // The task-local scope wraps the ENTIRE inner future; jsonrpsee 0.22's
        // HTTP transport polls the method handlers inside it (no spawn), so
        // `current_wallet_route()` is visible from the wallet RPC impls.
        Box::pin(WALLET_ROUTE.scope(wallet, self.inner.call(req)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_paths_pin_nothing() {
        assert_eq!(wallet_name_from_path("/"), None);
        assert_eq!(wallet_name_from_path(""), None);
        assert_eq!(wallet_name_from_path("/rest/tx"), None);
        // Prefix must match exactly (no trailing slash -> not the endpoint).
        assert_eq!(wallet_name_from_path("/wallet"), None);
    }

    #[test]
    fn wallet_paths_pin_the_decoded_name() {
        assert_eq!(wallet_name_from_path("/wallet/w1"), Some("w1".into()));
        // Core UrlDecode parity: percent-escapes decode, '+' passes through.
        assert_eq!(
            wallet_name_from_path("/wallet/my%20wallet"),
            Some("my wallet".into())
        );
        assert_eq!(wallet_name_from_path("/wallet/a+b"), Some("a+b".into()));
        // Empty remainder pins the empty name (Core behaviour).
        assert_eq!(wallet_name_from_path("/wallet/"), Some(String::new()));
        // Nested slashes stay part of the name (no wallet subdirs over RPC).
        assert_eq!(
            wallet_name_from_path("/wallet/a/b"),
            Some("a/b".into())
        );
    }

    #[tokio::test]
    async fn task_local_scope_is_visible_inline_and_absent_outside() {
        assert_eq!(current_wallet_route(), None);
        WALLET_ROUTE
            .scope(Some("w9".to_string()), async {
                assert_eq!(current_wallet_route(), Some("w9".to_string()));
                // ...and through an await point.
                tokio::task::yield_now().await;
                assert_eq!(current_wallet_route(), Some("w9".to_string()));
            })
            .await;
        assert_eq!(current_wallet_route(), None);
    }
}
