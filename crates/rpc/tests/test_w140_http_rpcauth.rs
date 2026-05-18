//! W140 HTTP server + rpcauth + cookie auth + JSON-RPC dispatch audit
//! — 30-gate compile-time + behavioral sentinel suite.
//!
//! Reference surfaces:
//! - `bitcoin-core/src/httpserver.cpp` — HTTP server + libevent + workqueue.
//! - `bitcoin-core/src/httpserver.h` — `DEFAULT_HTTP_THREADS=16`,
//!   `DEFAULT_HTTP_WORKQUEUE=64`, `DEFAULT_HTTP_SERVER_TIMEOUT=30`,
//!   `MAX_HEADERS_SIZE=8192`, `MAX_SIZE` body cap.
//! - `bitcoin-core/src/httprpc.cpp` — JSON-RPC dispatch + `WWW-Authenticate` +
//!   HMAC-SHA256 (`CheckUserAuthorized`) + 250 ms brute-force sleep + per-
//!   user `g_rpc_whitelist`.
//! - `bitcoin-core/src/rpc/request.cpp` — `GenerateAuthCookie`,
//!   `COOKIEAUTH_USER`, `COOKIEAUTH_FILE`, `DeleteAuthCookie`.
//! - `bitcoin-core/src/rpc/protocol.h` — HTTP status codes (200, 204, 400,
//!   401, 403, 404, 405, 500, 503) + `RPCErrorCode` enum.
//! - `bitcoin-core/share/rpcauth/rpcauth.py` — reference `<user>:<salt>$<hash>`
//!   line format.
//!
//! Audit subject (rustoshi):
//! - `crates/rpc/src/auth.rs` — `AuthLayer`, `AuthMiddleware`,
//!   `AuthCredentials`, `check_auth`.
//! - `crates/rpc/src/server.rs::start_rpc_server` (≈10836-10905) — jsonrpsee
//!   `ServerBuilder` plaintext bind path.
//! - `crates/rpc/src/tls.rs::serve_https` — HTTPS bind path.
//! - `crates/rpc/src/types.rs::RpcConfig` — server configuration struct.
//! - `rustoshi/src/main.rs` — CLI flags, `write_cookie_file`, `delete_cookie_file`.
//!
//! Gate legend:
//! - OK      : compile-time / runtime check confirms parity with Core.
//! - PARTIAL : present but with Core-divergent semantics.
//! - MISSING : Core has the surface; rustoshi has nothing equivalent.
//! - BUG     : present but emits the wrong status/format/behaviour.
//!
//! Severity scale:
//! - P0-SEC : security-critical, immediate deployment risk.
//! - P0-OPS : operator-pain parity-break with every Core ops guide.
//! - P1     : defense-in-depth or spec-compliance gap.
//! - P2     : HTTP/protocol spec compliance.
//! - P3     : defaults / cosmetic / future-proofing.
//!
//! Wave W140 summary (30 gates):
//!   BUG-1  (P0-SEC) : No `--rpcallowip` flag, no subnet/CIDR parser, no
//!                     `ClientAllowed`-style source-IP middleware. RPC accepts
//!                     authenticated requests from any reachable source.
//!   BUG-2  (P0-SEC) : No `--rpcauth` flag, no HMAC-SHA256 (`<user>:<salt>$<hash>`)
//!                     verification path. Only cleartext rpcuser/rpcpassword +
//!                     cookie.
//!   BUG-3  (P0-SEC) : Password compare uses `==` (non-constant-time) at
//!                     `auth.rs:62, 67`. Core uses `TimingResistantEqual`.
//!   BUG-4  (P0-OPS) : Cookie file written to `base_datadir` (network-naked),
//!                     not the network-specific subdir Core uses. Cross-ref
//!                     W124 BUG-13.
//!   BUG-5  (P1)     : No 250 ms `tokio::time::sleep` on failed auth. Core's
//!                     `httprpc.cpp:128` brute-force deterrent.
//!   BUG-6  (P1)     : `--rpcbind` is a single `String`, not `Vec<String>`. Core
//!                     accepts repeated `-rpcbind=` and binds each entry.
//!   BUG-7  (P1)     : No `--rpcwhitelist` / `--rpcwhitelistdefault` per-user
//!                     method ACL.
//!   BUG-8  (P1-OPS) : No `--rpcthreads` / `--rpcworkqueue` operator-visible
//!                     capacity knobs.
//!   BUG-9  (P1-OPS) : No `--rpcservertimeout` per-request idle timeout.
//!   BUG-10 (P2)     : No 503 "Work queue depth exceeded" overload surface.
//!   BUG-11 (P2)     : No HTTP 405 for non-POST requests (Core returns 405,
//!                     rustoshi returns 200 + JSON-RPC parse error).
//!   BUG-12 (P3)     : `max_request_body_size` uses jsonrpsee default 10 MB;
//!                     Core's `MAX_SIZE` is ~32 MB - 1.
//!   BUG-13 (P3)     : `max_connections` uses jsonrpsee default 100; Core has
//!                     no analogous cap (relies on threadpool back-pressure).
//!   BUG-14 (P3)     : No `RPC_IN_WARMUP` (-28) 503 startup gate. Cross-ref
//!                     W125 BUG-4.
//!
//! 14 unique bugs across 30 gates; 3 P0-SEC + 1 P0-OPS + 5 P1 + 1 P2 + 4 P3
//! at the row level (some gates share BUGs).
//!
//! Production code changes: 0. All tests are `#[ignore]`-pinned xfail
//! sentinels that document compile-time absence or runtime
//! Core-divergent behavior. When a fix wave lands, the corresponding
//! gate flips from `#[ignore]` to active assertion in the same commit.

use rustoshi_rpc::auth::AuthCredentials;
use rustoshi_rpc::types::RpcConfig;

// ============================================================
// Helpers — source-grep sentinels that don't break the build
// ============================================================

/// Slurp the contents of a file from the workspace.  Tests use this to grep
/// for the presence/absence of CLI flags, struct fields, and middleware
/// without depending on a runnable rustoshi binary.
fn read_source(rel_path: &str) -> String {
    // Tests run with CWD = `<workspace>/crates/rpc/`.  Walk two levels up to
    // reach the workspace root.  This is the same pattern used by the rest
    // of the rustoshi audit suite.
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");
    let path = workspace_root.join(rel_path);
    std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("could not read {}: {e}", path.display());
    })
}

// ============================================================
// G1-G5 — Cookie file lifecycle
// ============================================================

/// G1 — `.cookie` file IS written at startup (Core
/// `rpc/request.cpp:100-146::GenerateAuthCookie`).  rustoshi writes it via
/// `write_cookie_file(&base_datadir)` at `main.rs:1983`.  PARTIAL: file is
/// written but to the wrong directory — see G5 / BUG-4.
#[test]
fn g1_cookie_file_written_at_startup() {
    let main_rs = read_source("rustoshi/src/main.rs");
    assert!(
        main_rs.contains("fn write_cookie_file"),
        "G1: write_cookie_file helper is missing — cookie auth not wired"
    );
    assert!(
        main_rs.contains("let cookie_secret = write_cookie_file("),
        "G1: write_cookie_file is defined but never called from async_main"
    );
}

/// G2 — Cookie file permissions are `0o600` (owner read/write only).  Core
/// uses umask 0077 (`common/system.cpp`) so the same effective bits land.
/// Status: OK.
#[test]
fn g2_cookie_file_permissions_0o600() {
    let main_rs = read_source("rustoshi/src/main.rs");
    assert!(
        main_rs.contains("Permissions::from_mode(0o600)"),
        "G2: cookie file should be chmod 0o600 but no such call exists"
    );
}

/// G3 — Cookie username is the literal `__cookie__` (Core
/// `rpc/request.cpp:81 COOKIEAUTH_USER`).
/// Status: OK.
#[test]
fn g3_cookie_username_literal() {
    let main_rs = read_source("rustoshi/src/main.rs");
    assert!(
        main_rs.contains("__cookie__:{}"),
        "G3: cookie file content should be `__cookie__:<hex>` per Core convention"
    );
    let auth_rs = read_source("crates/rpc/src/auth.rs");
    assert!(
        auth_rs.contains("\"__cookie__\""),
        "G3: AuthCredentials::verify should special-case the literal `__cookie__` username"
    );
}

/// G4 — Cookie file deleted on shutdown (Core `rpc/request.cpp:167-177`
/// `DeleteAuthCookie`).  rustoshi: `main.rs:592 fn delete_cookie_file` +
/// call at `:4269`.
/// Status: OK.
#[test]
fn g4_cookie_file_deleted_on_shutdown() {
    let main_rs = read_source("rustoshi/src/main.rs");
    assert!(
        main_rs.contains("fn delete_cookie_file"),
        "G4: delete_cookie_file helper missing"
    );
    assert!(
        main_rs.contains("delete_cookie_file(&base_datadir)"),
        "G4: delete_cookie_file is defined but never called from the shutdown path"
    );
}

/// G5 — Cookie file should live in the **network-specific** datadir
/// (`<datadir>/testnet4/.cookie`, etc.) so that
/// `bitcoin-cli -testnet4 -datadir=…` finds it.  Rustoshi writes to
/// `base_datadir` (network-naked).  BUG-4.
/// Status: MISSING / BUG-4 (P0-OPS).
#[test]
#[ignore]
fn g5_cookie_in_network_specific_datadir() {
    let main_rs = read_source("rustoshi/src/main.rs");
    // Today this line writes to base_datadir, not the per-network datadir.
    // When the fix lands the call site changes to pass `&datadir` (which
    // already includes the network subdir).
    let calls_base = main_rs.contains("write_cookie_file(&base_datadir)");
    let calls_network = main_rs.contains("write_cookie_file(&datadir)");
    assert!(
        !calls_base && calls_network,
        "BUG-4 (P0-OPS): cookie file is written to base_datadir, not the \
         network-specific datadir.  bitcoin-cli -testnet4 -datadir=... looks \
         in <datadir>/testnet4/.cookie (Core convention) and fails.  Cross-ref \
         W124 BUG-13."
    );
}

// ============================================================
// G6-G9 — rpcauth + HMAC-SHA256 + constant-time compare
// ============================================================

/// G6 — `--rpcauth` flag is registered and accepts the
/// `<user>:<salt>$<hash>` line format Core ops guides reference.
/// Status: MISSING / BUG-2 (P0-SEC).
#[test]
#[ignore]
fn g6_rpcauth_flag_present() {
    let main_rs = read_source("rustoshi/src/main.rs");
    assert!(
        main_rs.contains("rpcauth"),
        "BUG-2 (P0-SEC): rustoshi has no --rpcauth CLI flag.  Operators \
         following Core ops guides have no way to deploy with hashed \
         (HMAC-SHA256) credentials.  Only cleartext --rpcuser/--rpcpassword \
         (BUG-3 timing-attack-prone) or cookie auth is available."
    );
}

/// G7 — `<user>:<salt>$<hash>` format parser is present somewhere in the
/// rpc crate.  Mirrors Core `httprpc.cpp:290-303`.
/// Status: MISSING / BUG-2 (P0-SEC).
#[test]
#[ignore]
fn g7_rpcauth_format_parser() {
    let auth_rs = read_source("crates/rpc/src/auth.rs");
    let server_rs = read_source("crates/rpc/src/server.rs");
    // Any of these would be a clear "yes we have an rpcauth path" tell:
    let has_hmac =
        auth_rs.contains("Hmac") || server_rs.contains("Hmac") ||
        auth_rs.contains("HMAC_SHA256") || server_rs.contains("HMAC_SHA256");
    let has_split_dollar =
        auth_rs.contains("split('$')") || auth_rs.contains("splitn(2, '$')") ||
        server_rs.contains("split('$')") || server_rs.contains("splitn(2, '$')");
    assert!(
        has_hmac && has_split_dollar,
        "BUG-2 (P0-SEC): no HMAC-SHA256 path and no `<user>:<salt>$<hash>` \
         parser found in crates/rpc/src/.  The rpcauth format Core's \
         share/rpcauth/rpcauth.py emits cannot be consumed."
    );
}

/// G8 — Cleartext rpcuser/rpcpassword fallback (legacy, Core
/// `httprpc.cpp:268-273`) is wired.  Both flags are accepted, both
/// flow into `AuthCredentials::user_pass`.
/// Status: OK (regression pin).
#[test]
fn g8_cleartext_rpcuser_rpcpassword_fallback() {
    let main_rs = read_source("rustoshi/src/main.rs");
    assert!(
        main_rs.contains("rpcuser: Option<String>")
            && main_rs.contains("rpcpassword: Option<String>"),
        "G8: --rpcuser / --rpcpassword CLI flags should be wired"
    );
    let server_rs = read_source("crates/rpc/src/server.rs");
    assert!(
        server_rs.contains("user_pass: match (config.auth_user.clone(), config.auth_password.clone())"),
        "G8: start_rpc_server should fold (auth_user, auth_password) into AuthCredentials::user_pass"
    );
}

/// G9 — Password / hash compare should be constant-time
/// (`subtle::ConstantTimeEq` or `constant_time_eq`).  Rustoshi uses `==`.
/// Status: MISSING / BUG-3 (P0-SEC).
#[test]
#[ignore]
fn g9_constant_time_password_compare() {
    let auth_rs = read_source("crates/rpc/src/auth.rs");
    let uses_constant_time =
        auth_rs.contains("constant_time_eq") ||
        auth_rs.contains("ConstantTimeEq") ||
        auth_rs.contains("subtle::");
    assert!(
        uses_constant_time,
        "BUG-3 (P0-SEC): password compare uses `==` (auth.rs:62, :67).  Core \
         uses `TimingResistantEqual` (httprpc.cpp:66, :77) — constant-time \
         XOR loop.  Variable-time `==` leaks first-differing-byte position \
         over the network."
    );
}

// ============================================================
// G10-G13 — rpcallowip + IP ACL + bind safety
// ============================================================

/// G10 — `--rpcallowip` CLI flag accepts repeated subnet/CIDR entries
/// (Core `init.cpp` `gArgs.GetArgs("-rpcallowip")`).
/// Status: MISSING / BUG-1 (P0-SEC).
#[test]
#[ignore]
fn g10_rpcallowip_cli_flag() {
    let main_rs = read_source("rustoshi/src/main.rs");
    assert!(
        main_rs.contains("rpcallowip"),
        "BUG-1 (P0-SEC): no --rpcallowip CLI flag.  RPC accepts \
         authenticated requests from ANY source IP that can reach the bound \
         port.  An operator binding to 0.0.0.0:8332 silently runs a wide-open \
         node — there is no default-deny safety net like Core's \
         httpserver.cpp:319-326."
    );
}

/// G11 — CIDR (IPv4 + IPv6) subnet parser exists in the rpc crate.  Core
/// `LookupSubNet(strAllow)` in `httpserver.cpp:154`.
/// Status: MISSING / BUG-1 (P0-SEC).
#[test]
#[ignore]
fn g11_cidr_subnet_parser() {
    let auth_rs = read_source("crates/rpc/src/auth.rs");
    let server_rs = read_source("crates/rpc/src/server.rs");
    let has_cidr =
        auth_rs.contains("ipnet") || server_rs.contains("ipnet") ||
        auth_rs.contains("IpAddr") && auth_rs.contains("prefix") ||
        server_rs.contains("rpc_allow_subnets") ||
        server_rs.contains("ClientAllowed");
    assert!(
        has_cidr,
        "BUG-1 (P0-SEC): no CIDR/subnet parser found in crates/rpc/src/.  \
         Core uses `LookupSubNet` which accepts both `1.2.3.4/24` and \
         `1.2.3.4/255.255.255.0`."
    );
}

/// G12 — IP-allowlist Tower middleware is present and runs BEFORE the
/// auth middleware (so an off-net attacker can't even probe for auth
/// 401 responses).  Mirrors Core `httpserver.cpp:217-222`.
/// Status: MISSING / BUG-1 (P0-SEC).
#[test]
#[ignore]
fn g12_ip_allowlist_middleware() {
    let server_rs = read_source("crates/rpc/src/server.rs");
    let auth_rs = read_source("crates/rpc/src/auth.rs");
    let has_layer =
        server_rs.contains("AllowIpLayer") || auth_rs.contains("AllowIpLayer") ||
        server_rs.contains("RpcAllowIpLayer") || auth_rs.contains("RpcAllowIpLayer");
    assert!(
        has_layer,
        "BUG-1 (P0-SEC): no `AllowIpLayer` or equivalent Tower middleware \
         registered in start_rpc_server's middleware stack.  The auth \
         middleware is the ONLY gate."
    );
}

/// G13 — Refuse non-loopback bind when `--rpcallowip` is empty (Core
/// `httpserver.cpp:319-338`: defaults to localhost-only if either
/// `-rpcallowip` or `-rpcbind` is missing).
/// Status: MISSING / BUG-1 (P0-SEC).
#[test]
#[ignore]
fn g13_default_deny_non_loopback_bind() {
    let main_rs = read_source("rustoshi/src/main.rs");
    let server_rs = read_source("crates/rpc/src/server.rs");
    // Look for any kind of bind-address safety check at startup.
    let has_safety =
        server_rs.contains("not safe to expose to untrusted networks") ||
        main_rs.contains("not safe to expose to untrusted networks") ||
        server_rs.contains("refusing to allow everyone to connect") ||
        main_rs.contains("refusing to allow everyone to connect");
    assert!(
        has_safety,
        "BUG-1 (P0-SEC): no default-deny check for non-loopback bind when \
         --rpcallowip is empty.  Core warns/refuses; rustoshi silently binds."
    );
}

// ============================================================
// G14-G18 — HTTP status code surface (Core httpserver.cpp + httprpc.cpp)
// ============================================================

/// G14 — Missing-Authorization header response is HTTP 401 + the exact
/// `WWW-Authenticate: Basic realm="jsonrpc"` header.  Core
/// `httprpc.cpp:33,114`.
/// Status: OK (regression pin).
#[test]
fn g14_unauthorized_response_shape() {
    let auth_rs = read_source("crates/rpc/src/auth.rs");
    assert!(
        auth_rs.contains("StatusCode::UNAUTHORIZED"),
        "G14: check_auth should reply 401"
    );
    // The source literal is `r#"Basic realm="jsonrpc""#` (Rust raw string),
    // so the on-disk bytes contain `Basic realm="jsonrpc"`.
    assert!(
        auth_rs.contains(r#"Basic realm="jsonrpc""#),
        "G14: check_auth should include the WWW-Authenticate `Basic realm=\"jsonrpc\"` challenge"
    );
}

/// G15 — Source-IP-not-in-allowlist response is HTTP 403 (Core
/// `httpserver.cpp:220 HTTP_FORBIDDEN`).
/// Status: MISSING / BUG-1 (P0-SEC).
#[test]
#[ignore]
fn g15_forbidden_on_ip_allowlist_miss() {
    // This gate is gated on G10-G13 landing first.  When G12 lands the
    // IP-allowlist middleware must emit HTTP 403 (not 401) for an off-net
    // source.
    let auth_rs = read_source("crates/rpc/src/auth.rs");
    let has_forbidden = auth_rs.contains("StatusCode::FORBIDDEN");
    assert!(
        has_forbidden,
        "BUG-1 (P0-SEC): no HTTP 403 surface in the auth/IP-ACL middleware.  \
         IP allowlist miss should return 403, NOT 401 (401 would leak that the \
         auth surface exists)."
    );
}

/// G16 — HTTP 405 BAD_METHOD for non-POST requests (Core
/// `httprpc.cpp:107-110`).
/// Status: MISSING / BUG-11 (P2).
#[test]
#[ignore]
fn g16_method_not_allowed_for_non_post() {
    let server_rs = read_source("crates/rpc/src/server.rs");
    let auth_rs = read_source("crates/rpc/src/auth.rs");
    let has_405 =
        server_rs.contains("StatusCode::METHOD_NOT_ALLOWED") ||
        auth_rs.contains("StatusCode::METHOD_NOT_ALLOWED");
    assert!(
        has_405,
        "BUG-11 (P2): no HTTP 405 surface for GET/PUT/HEAD.  Core returns 405; \
         rustoshi/jsonrpsee returns 200 + JSON-RPC parse error."
    );
}

/// G17 — HTTP 503 SERVICE_UNAVAILABLE on workqueue overflow (Core
/// `httpserver.cpp:255-259`).
/// Status: MISSING / BUG-10 (P2).
#[test]
#[ignore]
fn g17_service_unavailable_on_workqueue_overflow() {
    let server_rs = read_source("crates/rpc/src/server.rs");
    let has_503 =
        server_rs.contains("StatusCode::SERVICE_UNAVAILABLE") ||
        server_rs.contains("Work queue depth exceeded");
    assert!(
        has_503,
        "BUG-10 (P2): no 503 surface for overload.  rustoshi/tokio fans out \
         RPC requests unboundedly; Core would have refused with 503 once \
         the workqueue hit -rpcworkqueue depth."
    );
}

/// G18 — HTTP 503 SERVICE_UNAVAILABLE during chain warmup (Core gates RPC
/// behind `SetRPCWarmupFinished`).  Cross-ref W125 BUG-4.
/// Status: MISSING / BUG-14 (P3).
#[test]
#[ignore]
fn g18_service_unavailable_during_warmup() {
    let server_rs = read_source("crates/rpc/src/server.rs");
    let has_warmup =
        server_rs.contains("RPC_IN_WARMUP") ||
        server_rs.contains("WarmupFinished") ||
        server_rs.contains("Loading block index");
    assert!(
        has_warmup,
        "BUG-14 (P3): RPC server accepts requests before chain warmup \
         completes.  Core returns 503 + JSON-RPC -28 (RPC_IN_WARMUP).  \
         Cross-ref W125 BUG-4."
    );
}

// ============================================================
// G19 — Brute-force deterrent
// ============================================================

/// G19 — Failed auth response is delayed by 250 ms (`UninterruptibleSleep`)
/// to deter online brute-force.  Core `httprpc.cpp:128`.
/// Status: MISSING / BUG-5 (P1).
#[test]
#[ignore]
fn g19_brute_force_sleep_on_failed_auth() {
    let auth_rs = read_source("crates/rpc/src/auth.rs");
    // Look for any sleep on the failed-auth path inside check_auth or the
    // AuthMiddleware::call closure.
    let has_sleep =
        auth_rs.contains("tokio::time::sleep") ||
        auth_rs.contains("std::thread::sleep");
    assert!(
        has_sleep,
        "BUG-5 (P1): no 250 ms sleep on failed auth.  Core's brute-force \
         deterrent (httprpc.cpp:128) is one of the cheapest, highest-leverage \
         anti-brute-force primitives; absent here."
    );
}

// ============================================================
// G20 — JSON-RPC version coexistence (1.0 + 2.0)
// ============================================================

/// G20 — Accept both JSON-RPC 1.0 and 2.0 clients.  Core
/// `rpc/request.cpp:223-229` maps `"1.0"` → V1_LEGACY, `"2.0"` → V2.
/// rustoshi PARTIAL: `auth.rs:178-212` REWRITES every request to 2.0
/// regardless of input version.  Side effects: 1.0 responses include the
/// `"jsonrpc": "2.0"` marker (Core's 1.0 omits it); 1.0 batch responses
/// have V2 shape.  Acceptable for compatibility but not strict parity.
/// Status: PARTIAL.
#[test]
fn g20_jsonrpc_version_coexistence() {
    let auth_rs = read_source("crates/rpc/src/auth.rs");
    assert!(
        auth_rs.contains(r#""jsonrpc""#) && auth_rs.contains("2.0"),
        "G20: rustoshi rewrites every request to JSON-RPC 2.0 in the auth \
         middleware (PARTIAL parity: accepts but doesn't preserve 1.0)"
    );
}

// ============================================================
// G21 — Batch request bounded
// ============================================================

/// G21 — JSON-RPC batch requests bounded.  Core has no explicit cap but
/// implicit through max-body-size + sequential dispatch.  rustoshi caps
/// at 1000 via `MAX_BATCH_SIZE`.
/// Status: OK (regression pin).
#[test]
fn g21_jsonrpc_batch_bounded() {
    use rustoshi_rpc::server::MAX_BATCH_SIZE;
    assert_eq!(
        MAX_BATCH_SIZE, 1000,
        "G21: batch size cap should be 1000 (matches mining-pool defaults)"
    );
}

// ============================================================
// G22 — rpcbind multi-bind
// ============================================================

/// G22 — `--rpcbind` accepts repeated entries (Core `httpserver.cpp:329-338`
/// iterates `gArgs.GetArgs("-rpcbind")` and binds each).
/// Status: MISSING / BUG-6 (P1).
#[test]
#[ignore]
fn g22_rpcbind_multi_bind() {
    let main_rs = read_source("rustoshi/src/main.rs");
    let server_rs = read_source("crates/rpc/src/server.rs");
    let cli_is_vec = main_rs.contains("rpcbind: Vec<String>");
    let cfg_is_vec = server_rs.contains("bind_address: Vec<String>") ||
        server_rs.contains("bind_addresses: Vec<String>");
    assert!(
        cli_is_vec && cfg_is_vec,
        "BUG-6 (P1): --rpcbind is a single String, not Vec<String>.  \
         Operator can't bind both `127.0.0.1:8332` and `[::1]:8332` \
         simultaneously without an external proxy."
    );
}

// ============================================================
// G23-G24 — Per-user method whitelist
// ============================================================

/// G23 — `--rpcwhitelist=<user>:<method,method,...>` CLI flag wired
/// (Core `httprpc.cpp:306-326`).
/// Status: MISSING / BUG-7 (P1).
#[test]
#[ignore]
fn g23_rpcwhitelist_cli_flag() {
    let main_rs = read_source("rustoshi/src/main.rs");
    assert!(
        main_rs.contains("rpcwhitelist"),
        "BUG-7 (P1): no --rpcwhitelist CLI flag.  Every authenticated user \
         can call every RPC method, including `stop`, `setban`, \
         `disconnectnode`, `getbalance`.  Multi-user deployments cannot \
         constrain by method."
    );
}

/// G24 — `--rpcwhitelistdefault` toggles deny-by-default for unmatched
/// users (Core `httprpc.cpp:306`).
/// Status: MISSING / BUG-7 (P1).
#[test]
#[ignore]
fn g24_rpcwhitelistdefault_flag() {
    let main_rs = read_source("rustoshi/src/main.rs");
    assert!(
        main_rs.contains("rpcwhitelistdefault"),
        "BUG-7 (P1): no --rpcwhitelistdefault CLI flag.  Even if --rpcwhitelist \
         lands, there's no Core-parity way to default-deny unmatched users."
    );
}

// ============================================================
// G25-G27 — Operator capacity knobs
// ============================================================

/// G25 — `--rpcthreads=N` operator-visible thread-count knob (Core
/// `httpserver.h:20 DEFAULT_HTTP_THREADS=16`).
/// Status: MISSING / BUG-8 (P1-OPS).
#[test]
#[ignore]
fn g25_rpcthreads_knob() {
    let main_rs = read_source("rustoshi/src/main.rs");
    assert!(
        main_rs.contains("rpcthreads"),
        "BUG-8 (P1-OPS): no --rpcthreads operator-visible knob.  Capacity \
         tuning requires recompilation (tokio worker count is the only \
         knob, set via #[tokio::main] attribute)."
    );
}

/// G26 — `--rpcworkqueue=N` operator-visible queue-depth knob (Core
/// `httpserver.h:26 DEFAULT_HTTP_WORKQUEUE=64`).
/// Status: MISSING / BUG-8 (P1-OPS).
#[test]
#[ignore]
fn g26_rpcworkqueue_knob() {
    let main_rs = read_source("rustoshi/src/main.rs");
    assert!(
        main_rs.contains("rpcworkqueue"),
        "BUG-8 (P1-OPS): no --rpcworkqueue operator-visible knob.  \
         Tokio fans out RPC requests unboundedly; system FDs are the only \
         back-pressure surface."
    );
}

/// G27 — `--rpcservertimeout=N` per-request idle timeout (Core
/// `httpserver.h:28 DEFAULT_HTTP_SERVER_TIMEOUT=30`).
/// Status: MISSING / BUG-9 (P1-OPS).
#[test]
#[ignore]
fn g27_rpcservertimeout_knob() {
    let main_rs = read_source("rustoshi/src/main.rs");
    assert!(
        main_rs.contains("rpcservertimeout"),
        "BUG-9 (P1-OPS): no --rpcservertimeout operator-visible knob.  \
         jsonrpsee has no per-request idle timeout; a slow client can pin a \
         connection indefinitely."
    );
}

// ============================================================
// G28 — Body-size cap
// ============================================================

/// G28 — `max_request_body_size` ≥ Core's `MAX_SIZE` (0x02000000 - 1 ≈ 32 MB).
/// rustoshi: jsonrpsee default `TEN_MB_SIZE_BYTES` (10 MB).
/// Status: PARTIAL / BUG-12 (P3).
#[test]
#[ignore]
fn g28_max_request_body_size_matches_core() {
    let server_rs = read_source("crates/rpc/src/server.rs");
    let tls_rs = read_source("crates/rpc/src/tls.rs");
    let overrides = server_rs.contains(".max_request_body_size(") ||
        tls_rs.contains(".max_request_body_size(");
    assert!(
        overrides,
        "BUG-12 (P3): max_request_body_size uses jsonrpsee default 10 MB.  \
         Core's MAX_SIZE is ~32 MB - 1 (~33,554,431 bytes).  Large \
         `submitblock` payloads may 413."
    );
}

// ============================================================
// G29 — TLS opt-in (HTTPS) cert + key validation
// ============================================================

/// G29 — TLS opt-in requires both cert AND key (or neither).  Setting
/// only one is a startup error (Core libevent+OpenSSL parity, FIX-64).
/// Status: OK (regression pin).
#[test]
fn g29_tls_opt_in_requires_both_cert_and_key() {
    let server_rs = read_source("crates/rpc/src/server.rs");
    assert!(
        server_rs.contains("(Some(_), None)") && server_rs.contains("--rpc-tls-cert is set but --rpc-tls-key is missing"),
        "G29: start_rpc_server should bail when --rpc-tls-cert is set without --rpc-tls-key"
    );
    assert!(
        server_rs.contains("(None, Some(_))") && server_rs.contains("--rpc-tls-key is set but --rpc-tls-cert is missing"),
        "G29: start_rpc_server should bail when --rpc-tls-key is set without --rpc-tls-cert"
    );
}

// ============================================================
// G30 — /wallet/<name>/ path prefix dispatcher
// ============================================================

/// G30 — Core registers `/wallet/` as a path prefix and routes wallet-
/// specific RPCs through it (httprpc.cpp:339-341).  rustoshi has no
/// equivalent.  P3: only matters once multiwallet support lands.
/// Status: MISSING.
#[test]
#[ignore]
fn g30_wallet_path_prefix_dispatcher() {
    let server_rs = read_source("crates/rpc/src/server.rs");
    let rest_rs = read_source("crates/rpc/src/rest.rs");
    let has_wallet_path = server_rs.contains("/wallet/") || rest_rs.contains("/wallet/");
    assert!(
        has_wallet_path,
        "G30 (P3): no `/wallet/<name>/` URL path-prefix routing.  rustoshi \
         supports multiwallet via the `wallet` JSON-RPC param; Core also \
         supports the URL-path form which some clients use exclusively."
    );
}

// ============================================================
// Behavioral runtime sanity — AuthCredentials::verify
// ============================================================
//
// These two tests exercise the public API of AuthCredentials to pin the
// behaviour the audit relied on when classifying the gates.  They are
// expected to PASS at the current head and serve as regression sentinels
// — if these flip the audit's premise has changed.

#[test]
fn behavior_cookie_auth_accepts_correct_pass() {
    let creds = AuthCredentials {
        cookie_secret: Some("deadbeefcafebabe".to_string()),
        user_pass: None,
    };
    assert!(
        creds.verify("__cookie__", "deadbeefcafebabe"),
        "cookie auth should accept the literal __cookie__ user + correct secret"
    );
    assert!(
        !creds.verify("__cookie__", "wrong"),
        "cookie auth should reject wrong secret"
    );
    assert!(
        !creds.verify("alice", "deadbeefcafebabe"),
        "cookie auth should reject non-__cookie__ user even with correct secret"
    );
}

#[test]
fn behavior_rpcconfig_default_is_loopback() {
    let cfg = RpcConfig::default();
    assert!(
        cfg.bind_address.starts_with("127.0.0.1:")
            || cfg.bind_address.starts_with("[::1]:"),
        "RpcConfig::default should bind loopback only (not 0.0.0.0); \
         got {}",
        cfg.bind_address
    );
    assert!(
        cfg.auth_user.is_none() && cfg.auth_password.is_none(),
        "RpcConfig::default should have NO auth credentials wired \
         (caller supplies cookie_secret at runtime)"
    );
}
