//! W125 JSON-RPC error code parity audit — 30-gate cross-method audit.
//!
//! Reference surfaces:
//! - `bitcoin-core/src/rpc/protocol.h` — `enum RPCErrorCode` (canonical numeric values).
//! - `bitcoin-core/src/rpc/blockchain.cpp` — blockchain method error sites.
//! - `bitcoin-core/src/rpc/mining.cpp` — mining/template/generate error sites.
//! - `bitcoin-core/src/rpc/mempool.cpp` — mempool / sendrawtransaction / prioritisetransaction.
//! - `bitcoin-core/src/rpc/net.cpp` — addnode / setban / disconnectnode.
//! - `bitcoin-core/src/rpc/rawtransaction.cpp` — raw tx + PSBT methods.
//! - `bitcoin-core/src/rpc/util.cpp` — parameter validation + AmountFromValue.
//! - `bitcoin-core/src/wallet/rpc/*.cpp` — wallet RPC methods + Core wallet
//!   error code conventions.
//! - JSON-RPC 2.0 spec — `-32700` parse, `-32600` invalid request,
//!   `-32601` method-not-found, `-32602` invalid params, `-32603` internal.
//!
//! Audit subject (rustoshi):
//! - `crates/rpc/src/server.rs` lines 60-95 — `mod rpc_error` (numeric table).
//! - `crates/rpc/src/wallet.rs` lines 28-55 — `mod wallet_error` (numeric table).
//! - All callers of `Self::rpc_error(rpc_error::...)` across server.rs/wallet.rs.
//!
//! Gate legend:
//! - OK      : numeric code AND message-substring match Core (regression pin).
//! - PARTIAL : numeric code matches but message wording diverges, OR vice-versa.
//! - MISSING : Core has the error path; rustoshi has no equivalent code/site.
//! - BUG     : implemented but emits a numeric code Core never returns
//!             for that situation (operator scripts grepping by code break).
//! - C-DIV   : not applicable here — error codes never cause a chain fork.
//!
//! Severity scale (operator-visible / scripting):
//! - P0      : code collision (rustoshi reuses a Core code with different meaning)
//!             — wallet/exchange scripts will trigger wrong recovery paths.
//! - P1      : wrong code emitted but no collision — scripts grepping by code fail.
//! - P2      : message wording diverges; scripts grepping by message fail.
//! - P3      : missing code constant or doc-only divergence.
//!
//! Wave W125 summary (30 gates):
//!   BUG-1  (P0) : `RPC_CLIENT_P2P_DISABLED` defined as `-9`; Core's value is `-31`.
//!                 `-9` is `RPC_CLIENT_NOT_CONNECTED` in Core → operator scripts
//!                 reading "P2P disabled" actually trigger "not connected" recovery.
//!                 Sites: server.rs:92 (definition); :4881 (addnode), :5117 (setban),
//!                 :5131 (clearbanned), :7006 (disconnectnode).
//!   BUG-2  (P0) : `RPC_WALLET_ALREADY_EXISTS` defined as `-4`; Core's value is `-36`.
//!                 `-4` is `RPC_WALLET_ERROR` (generic). Collision is silent — both
//!                 codes resolve to -4 in rustoshi but Core distinguishes.
//!                 Site: wallet.rs:43.
//!   BUG-3  (P1) : 51 call sites use `RPC_INVALID_PARAMS` (-32602, JSON-RPC standard);
//!                 Core uses `RPC_INVALID_PARAMETER` (-8) in 95+ of its 96 sites for
//!                 application-layer parameter validation. The lone Core -32602 site
//!                 is net.cpp:474 (mutually-exclusive address/nodeid). Every script
//!                 looking for -8 on "Block height out of range", "Invalid command",
//!                 "Invalid IP", etc., fails against rustoshi.
//!                 Sites: server.rs:1075, 1081, 2961, 3613, 4020, 4854, 4875, 5081,
//!                 5111, 5156, 5222, 5264, 5418, 5445, 5463, 5466, 5472, 5478, 5484,
//!                 7073, 7459, 7470, 7478 (and ~28 more).
//!   BUG-4  (P1) : No `RPC_IN_WARMUP` (-28) defined or returned. Core's
//!                 `httpserver` returns this with HTTP 503 while validation is
//!                 catching up on startup; rustoshi has no equivalent.
//!   BUG-5  (P1) : No `RPC_CLIENT_IN_INITIAL_DOWNLOAD` (-10) defined. Core's
//!                 `loadmempool` (mempool.cpp:1141) and mining methods
//!                 (mining.cpp:773, 843) refuse during IBD with this code;
//!                 rustoshi either returns no error or uses `RPC_MISC_ERROR`.
//!   BUG-6  (P1) : No `RPC_METHOD_DEPRECATED` (-32) defined. Used by Core for
//!                 -deprecatedrpc=… opt-in paths (e.g., getrawmempool size field
//!                 fields). Future-deprecated methods need this distinct code.
//!   BUG-7  (P1) : No `RPC_OUT_OF_MEMORY` (-7) defined. Core throws on OOM in
//!                 cryptographically-large operations (signrawtransaction with
//!                 millions of inputs). Rustoshi panics or returns generic error.
//!   BUG-8  (P1) : `RPC_BLOCK_NOT_FOUND` aliased to -5 (server.rs:94).
//!                 Aligned with Core (`RPC_INVALID_ADDRESS_OR_KEY` = -5 is what
//!                 Core uses for "Block not found" — see blockchain.cpp:147, 655),
//!                 BUT rustoshi exposes a confusable second alias name where Core
//!                 has one canonical name. P3 doc-clarity rather than wire bug.
//!   BUG-9  (P1) : `RPC_TRANSACTION_ALREADY_IN_CHAIN` aliased to -27 (server.rs:90);
//!                 Core renamed this enum value to `RPC_VERIFY_ALREADY_IN_UTXO_SET`
//!                 in commit 64f9ec5 (protocol.h:49). Both numeric value AND
//!                 message text ("Transaction already in block chain") trail Core's
//!                 current name ("Transaction outputs already in utxo set"). Code
//!                 OK; message wording out of sync.
//!   BUG-10 (P1) : `sendrawtransaction` collapses all mempool rejections to
//!                 `RPC_TRANSACTION_REJECTED` (-26). Core's
//!                 `JSONRPCTransactionError` switches on `TransactionError`:
//!                 -26 (MEMPOOL_REJECTED), -27 (ALREADY_IN_UTXO_SET),
//!                 -25 (RPC_TRANSACTION_ERROR fallback). Rustoshi loses the -25/-27
//!                 distinction at server.rs:3766-3789. See W120 BUG-16 cross-ref.
//!   BUG-11 (P1) : `RPC_CLIENT_NODE_ALREADY_ADDED` (-23) missing. Core's
//!                 `addnode "add"` returns this when the peer is already in the
//!                 addnode list (net.cpp:362). Rustoshi's `add_node` at
//!                 server.rs:4866 silently no-ops the duplicate.
//!   BUG-12 (P1) : `RPC_CLIENT_NODE_NOT_ADDED` (-24) missing. Core's
//!                 `addnode "remove"` (net.cpp:368) and `getaddednodeinfo`
//!                 (net.cpp:534) return this when the peer is not in the addnode
//!                 list. Rustoshi's `add_node "remove"` returns Ok(()).
//!   BUG-13 (P1) : `RPC_CLIENT_NODE_NOT_CONNECTED` (-29) missing. Core's
//!                 `disconnectnode` (net.cpp:478) returns this when the target
//!                 isn't connected. Rustoshi conflates with `RPC_INVALID_PARAMS`.
//!   BUG-14 (P1) : `RPC_CLIENT_INVALID_IP_OR_SUBNET` (-30) missing. Core's
//!                 `setban`/`unban` (net.cpp:780, 811) returns this for bad
//!                 IP/CIDR input. Rustoshi uses `RPC_INVALID_PARAMS` (-32602)
//!                 at server.rs:5081.
//!   BUG-15 (P1) : `RPC_CLIENT_NODE_CAPACITY_REACHED` (-34) missing. Core's
//!                 `addnode "onetry"` (net.cpp:428) returns this when outbound
//!                 slots are full. Rustoshi has no such limit-aware path.
//!   BUG-16 (P2) : `RPC_TYPE_ERROR` (-3) defined but used at only 1 site
//!                 (server.rs:7399, signmessage non-PKH). Core uses -3 broadly
//!                 in AmountFromValue, ParseHashV, GetVerbosity → most rustoshi
//!                 parameter-type mismatches surface as -32602 / -32700.
//!   BUG-17 (P2) : `getblockhash` returned -32602 ("Block height out of range")
//!                 vs Core's -8. FIXED (2026-06-16): the `get_block_hash`
//!                 handler now emits `RPC_INVALID_PARAMETER` (-8) with Core's
//!                 exact message text. Pinned by `g29_getblockhash_oor_emits_
//!                 invalid_parameter`. Cross-ref BUG-3.
//!   BUG-18 (P2) : `addnode` returns -32602 for "Invalid command" vs Core's
//!                 sub-codes (validates against {"add","remove","onetry"} with
//!                 JSON-RPC-shape error). server.rs:4875.
//!   BUG-19 (P2) : `pruneblockchain` returns -1 (`RPC_MISC_ERROR`) for not-in-prune-
//!                 mode (server.rs:5145) — Core returns -1 too here; OK; but
//!                 returns -32602 for height-out-of-range (server.rs:5156) where
//!                 Core uses -8. Cross-ref BUG-3.
//!   BUG-20 (P2) : `sendrawtransaction` "maxfeerate cannot exceed 1 BTC/kvB"
//!                 emits -32602 (server.rs:3613); Core emits -8
//!                 (util.cpp:113, "Fee rates larger than or equal to 1BTC/kvB").
//!                 Message text also diverges ("equal to" vs no equal).
//!   BUG-21 (P2) : `set_ban` "Invalid IP address format" emits -32602 (-32602);
//!                 Core emits -30 (`RPC_CLIENT_INVALID_IP_OR_SUBNET`).
//!                 Cross-ref BUG-14, BUG-3.
//!   BUG-22 (P2) : `prioritisetransaction` dummy-arg-not-zero emits -32602
//!                 (server.rs:7073); Core emits -8 (mining.cpp:530). Cross-ref BUG-3.
//!   BUG-23 (P2) : `createmultisig` nrequired/keys-out-of-range emits -32602
//!                 (server.rs:7470); Core emits -8 (util.cpp:239, 242, 245).
//!                 Cross-ref BUG-3.
//!   BUG-24 (P2) : `RPC_DATABASE_ERROR` (-20) used broadly in rustoshi for any
//!                 backing-store error; Core uses -20 specifically for
//!                 reconsiderblock/invalidateblock state failures (blockchain.cpp:
//!                 1709, 1734, 1779). Rustoshi's use is a superset — operator
//!                 scripts can't disambiguate "block index inconsistent" from
//!                 "RocksDB I/O failed".
//!   BUG-25 (P3) : `signmessage` hardcodes `-18` literal (server.rs:7416)
//!                 instead of `wallet_error::RPC_WALLET_NOT_FOUND`. Numeric match,
//!                 but a future refactor that changes the constant breaks silently.
//!   BUG-26 (P3) : `RPC_TRANSACTION_REJECTED` defined twice with the same value
//!                 (-26) at server.rs:84 + :86. Both alias `RPC_VERIFY_REJECTED`.
//!                 Cosmetic — operator scripts unaffected.
//!   BUG-27 (P3) : `RPC_WALLET_NOT_SELECTED` aliased to `RPC_WALLET_NOT_SPECIFIED`
//!                 (-19) at wallet.rs:51. Both names → -19. Code matches Core but
//!                 doubled-alias style differs from Core's single-name enum.
//!   BUG-28 (P3) : No `RPC_WALLET_INVALID_LABEL_NAME` (-11) defined. Core uses
//!                 for `setlabel` with bad label (wallet/rpc/addresses.cpp).
//!                 Rustoshi's `setlabel` (server.rs:822) does not validate.
//!   BUG-29 (P3) : No `RPC_WALLET_ENCRYPTION_FAILED` (-16) defined. Reserved by
//!                 Core for encryptwallet PRNG failures (rare). Not user-visible
//!                 today; reserved for future.
//!   BUG-30 (P3) : No `RPC_FORBIDDEN_BY_SAFE_MODE` (-2) defined. Core lists this
//!                 as reserved-not-reused. Documentation gap only.
//!
//! Cross-cutting findings:
//! - 7 of 30 gates are P0/P1 with operator-visible impact (BUG-1, BUG-2,
//!   BUG-3, BUG-10, BUG-11..15).
//! - BUG-3 (RPC_INVALID_PARAMS vs RPC_INVALID_PARAMETER) is the LARGEST surface:
//!   51 call sites, every parameter-validation error. Top fix priority — single
//!   constant rename in `mod rpc_error` from -32602 to -8 closes ~40 BUG-x P2
//!   findings in one diff.
//! - BUG-1 (P2P_DISABLED collision with NOT_CONNECTED) is the most dangerous P0:
//!   it silently misroutes operator alert paths.
//! - No production code changes in this commit; all tests are `#[ignore]`-pinned
//!   xfail stubs that document compile-time absence of the relevant constants
//!   and call sites.

use rustoshi_rpc::server::rpc_error;
use rustoshi_rpc::wallet::wallet_error;

// ============================================================
// G1 — Standard JSON-RPC 2.0 error codes
// ============================================================

/// G1 — Parse error -32700 defined per JSON-RPC 2.0.
/// Status: OK (regression pin).
#[test]
fn g1_jsonrpc_parse_error() {
    assert_eq!(rpc_error::RPC_PARSE_ERROR, -32700);
}

/// G2 — Invalid request -32600 defined per JSON-RPC 2.0.
/// Status: OK (regression pin).
#[test]
fn g2_jsonrpc_invalid_request() {
    assert_eq!(rpc_error::RPC_INVALID_REQUEST, -32600);
}

/// G3 — JSON-RPC standard "invalid params" code (-32602) is reserved for
/// transport-level shape errors (wrong arg count, JSON-type mismatch),
/// NOT application-layer parameter validation. Core uses -8 instead at
/// the application layer.
/// Status: PARTIAL — constant value matches but rustoshi USES it where
/// Core uses -8 (see BUG-3 / G7-G18 below).
#[test]
fn g3_jsonrpc_invalid_params() {
    assert_eq!(rpc_error::RPC_INVALID_PARAMS, -32602);
}

/// G4 — Internal error -32603 defined per JSON-RPC 2.0.
/// Status: OK.
#[test]
fn g4_jsonrpc_internal_error() {
    assert_eq!(rpc_error::RPC_INTERNAL_ERROR, -32603);
}

// ============================================================
// G5 — Bitcoin Core application error codes (numeric parity)
// ============================================================

/// G5 — `RPC_MISC_ERROR` -1 matches Core protocol.h:40.
/// Status: OK.
#[test]
fn g5_rpc_misc_error_numeric() {
    assert_eq!(rpc_error::RPC_MISC_ERROR, -1);
}

/// G6 — `RPC_TYPE_ERROR` -3 matches Core protocol.h:41.
/// Status: OK (numeric); BUG-16 (under-used at call sites).
#[test]
fn g6_rpc_type_error_numeric() {
    assert_eq!(rpc_error::RPC_TYPE_ERROR, -3);
}

/// G7 — `RPC_INVALID_ADDRESS_OR_KEY` -5 matches Core protocol.h:42.
/// Status: OK.
#[test]
fn g7_rpc_invalid_address_or_key_numeric() {
    assert_eq!(rpc_error::RPC_INVALID_ADDRESS_OR_KEY, -5);
}

/// G8 — `RPC_INVALID_PARAMETER` (-8) is the canonical Core code for
/// application-layer parameter validation (Core `protocol.h`
/// `RPC_INVALID_PARAMETER = -8`). It IS now defined in rustoshi at
/// `crates/rpc/src/server.rs::rpc_error::RPC_INVALID_PARAMETER`.
/// Status: BUG-3 (P1) — RESOLVED. The constant exists with the genuine
/// Core value, distinct from `RPC_INVALID_PARAMS` (-32602).
/// De-staled 2026-06-16 (prior `#[ignore]` xfail stub was stale — production
/// already defines the constant; pin it as a regression test instead).
#[test]
fn g8_rpc_invalid_parameter_absence() {
    // Core protocol.h:44 — RPC_INVALID_PARAMETER = -8.
    assert_eq!(rpc_error::RPC_INVALID_PARAMETER, -8);
    // Must be the application-layer code, NOT the JSON-RPC transport code
    // RPC_INVALID_PARAMS (-32602); the two must remain distinct.
    assert_ne!(
        rpc_error::RPC_INVALID_PARAMETER,
        rpc_error::RPC_INVALID_PARAMS,
        "RPC_INVALID_PARAMETER (-8) must not collide with RPC_INVALID_PARAMS (-32602)"
    );
}

/// G9 — `RPC_DATABASE_ERROR` -20 matches Core protocol.h:45.
/// Status: OK (numeric); BUG-24 (used broader than Core does).
#[test]
fn g9_rpc_database_error_numeric() {
    assert_eq!(rpc_error::RPC_DATABASE_ERROR, -20);
}

/// G10 — `RPC_DESERIALIZATION_ERROR` -22 matches Core protocol.h:46.
/// Status: OK.
#[test]
fn g10_rpc_deserialization_error_numeric() {
    assert_eq!(rpc_error::RPC_DESERIALIZATION_ERROR, -22);
}

/// G11 — `RPC_TRANSACTION_ERROR` (alias of `RPC_VERIFY_ERROR`) -25.
/// Status: OK.
#[test]
fn g11_rpc_transaction_error_numeric() {
    assert_eq!(rpc_error::RPC_TRANSACTION_ERROR, -25);
}

/// G12 — `RPC_VERIFY_REJECTED` / `RPC_TRANSACTION_REJECTED` both -26.
/// Status: OK numeric; BUG-26 (P3) is dual-defined.
#[test]
fn g12_rpc_verify_rejected_numeric() {
    assert_eq!(rpc_error::RPC_VERIFY_REJECTED, -26);
    assert_eq!(rpc_error::RPC_TRANSACTION_REJECTED, -26);
}

/// G13 — `RPC_VERIFY_ALREADY_IN_CHAIN` / `RPC_TRANSACTION_ALREADY_IN_CHAIN`
/// both -27. Core's current enum name is `RPC_VERIFY_ALREADY_IN_UTXO_SET`.
/// Status: OK numeric; BUG-9 message text trails ("block chain" vs "utxo set").
#[test]
fn g13_rpc_verify_already_in_chain_numeric() {
    assert_eq!(rpc_error::RPC_VERIFY_ALREADY_IN_CHAIN, -27);
    assert_eq!(rpc_error::RPC_TRANSACTION_ALREADY_IN_CHAIN, -27);
}

/// G14 — `RPC_IN_WARMUP` (-28) is Core's HTTP 503 surface during startup.
/// NOT DEFINED in rustoshi.
/// Status: BUG-4 (P1).
#[test]
#[ignore]
fn g14_rpc_in_warmup_absence() {
    panic!("BUG-4: rustoshi has no RPC_IN_WARMUP (-28) constant; \
            no warmup-503 surface during chain database startup.");
}

/// G15 — `RPC_METHOD_DEPRECATED` (-32) used by Core for opt-in deprecated paths.
/// NOT DEFINED in rustoshi.
/// Status: BUG-6 (P1).
#[test]
#[ignore]
fn g15_rpc_method_deprecated_absence() {
    panic!("BUG-6: rustoshi has no RPC_METHOD_DEPRECATED (-32); \
            future -deprecatedrpc=… opt-in paths have no distinct code.");
}

// ============================================================
// G16-G20 — P2P / Network error codes
// ============================================================

/// G16 — `RPC_CLIENT_P2P_DISABLED` numeric parity (BUG-1 FIXED).
/// Core's `RPC_CLIENT_P2P_DISABLED = -31` (protocol.h:64); `RPC_CLIENT_NOT_CONNECTED
/// = -9` (protocol.h:58). Rustoshi previously defined P2P_DISABLED as -9, a silent
/// collision with NOT_CONNECTED. Now remapped to the genuine Core value -31.
/// Status: BUG-1 (P0) — FIXED. Confirm-present: P2P_DISABLED == -31 and does NOT
/// collide with NOT_CONNECTED (-9).
#[test]
fn g16_p2p_disabled_collision_with_not_connected() {
    // Rustoshi's RPC_CLIENT_P2P_DISABLED, now the genuine Core value.
    let rustoshi_p2p_disabled = rpc_error::RPC_CLIENT_P2P_DISABLED;
    // Core's RPC_CLIENT_NOT_CONNECTED = -9 (protocol.h:58).
    let core_not_connected: i32 = -9;
    // Core's RPC_CLIENT_P2P_DISABLED = -31 (protocol.h:64).
    let core_p2p_disabled: i32 = -31;
    assert_eq!(rustoshi_p2p_disabled, core_p2p_disabled,
        "BUG-1 FIXED: RPC_CLIENT_P2P_DISABLED must be -31 (Core), is {}", rustoshi_p2p_disabled);
    assert_ne!(rustoshi_p2p_disabled, core_not_connected,
        "RPC_CLIENT_P2P_DISABLED must NOT collide with RPC_CLIENT_NOT_CONNECTED (-9)");
}

/// Build a `PeerServerImpl` whose `PeerState` owns a live (but un-started)
/// `PeerManager`, so the `addnode` handler exercises the real added-node list
/// instead of the `RPC_CLIENT_P2P_DISABLED` (no-peer-manager) branch.
fn server_with_peer_manager() -> rustoshi_rpc::RpcServerImpl {
    use rustoshi_consensus::ChainParams;
    use rustoshi_network::peer_manager::{PeerManager, PeerManagerConfig};
    use rustoshi_rpc::{PeerState, RpcServerImpl, RpcState};
    use rustoshi_storage::ChainDb;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    let tmp = tempfile::tempdir().expect("tempdir");
    let db = Arc::new(ChainDb::open(tmp.path()).expect("open chaindb"));
    let params = ChainParams::regtest();
    let rpc_state = RpcState::new(db, params);
    let state = Arc::new(RwLock::new(rpc_state));

    let pm = PeerManager::new(PeerManagerConfig::testnet4(), ChainParams::testnet4());
    let peer_state = Arc::new(RwLock::new(PeerState {
        peer_manager: Some(pm),
    }));
    // Keep `tmp` alive for the lifetime of the test by leaking it; the test
    // process is short-lived and tempdir cleanup is best-effort here.
    std::mem::forget(tmp);
    RpcServerImpl::new(state, peer_state)
}

/// G17 — `RPC_CLIENT_NODE_ALREADY_ADDED` (-23). Core net.cpp:359-363
/// (`CConnman::AddNode` returns false → `JSONRPCError(RPC_CLIENT_NODE_ALREADY_ADDED,
/// "Error: Node already added")`).
/// Status: BUG-11 (P1) — FIXED.
///
/// De-staled 2026-06-16: previously an `#[ignore]` `panic!` documenting the
/// absence. Now a REAL behavioral test — `addnode "add"` twice for the same
/// node must succeed once then return Core's -23, not silently no-op.
#[tokio::test]
async fn g17_addnode_duplicate_add_emits_node_already_added() {
    use rustoshi_rpc::RustoshiRpcServer;

    // The numeric constant exists and equals Core's value.
    assert_eq!(
        rpc_error::RPC_CLIENT_NODE_ALREADY_ADDED, -23,
        "RPC_CLIENT_NODE_ALREADY_ADDED must be -23 (Core protocol.h:60)"
    );

    let server = server_with_peer_manager();
    let node = "192.0.2.10:18333".to_string();

    // First add succeeds.
    RustoshiRpcServer::add_node(&server, node.clone(), "add".to_string())
        .await
        .expect("first addnode add must succeed");

    // Second add of the SAME node must error with Core's -23 (not a silent Ok).
    let err = RustoshiRpcServer::add_node(&server, node.clone(), "add".to_string())
        .await
        .expect_err("duplicate addnode add must error");
    assert_eq!(
        err.code(),
        rpc_error::RPC_CLIENT_NODE_ALREADY_ADDED,
        "duplicate add must emit -23 (RPC_CLIENT_NODE_ALREADY_ADDED), got {}: {}",
        err.code(),
        err.message(),
    );
    assert_eq!(err.message(), "Error: Node already added",
        "message must match Core net.cpp:362 exactly");
}

/// G18 — `RPC_CLIENT_NODE_NOT_ADDED` (-24). Core net.cpp:365-369
/// (`CConnman::RemoveAddedNode` returns false → `JSONRPCError(
/// RPC_CLIENT_NODE_NOT_ADDED, "Error: Node could not be removed. ...")`).
/// Status: BUG-12 (P1) — FIXED.
///
/// De-staled 2026-06-16: previously an `#[ignore]` `panic!`. Now a REAL test —
/// `addnode "remove"` for a never-added node must return Core's -24, and a
/// remove that follows a matching add must succeed.
#[tokio::test]
async fn g18_addnode_remove_unknown_emits_node_not_added() {
    use rustoshi_rpc::RustoshiRpcServer;

    assert_eq!(
        rpc_error::RPC_CLIENT_NODE_NOT_ADDED, -24,
        "RPC_CLIENT_NODE_NOT_ADDED must be -24 (Core protocol.h:61)"
    );

    let server = server_with_peer_manager();
    let node = "198.51.100.7:18333".to_string();

    // Removing a node that was never added must error with Core's -24,
    // not return Ok (the pre-fix behaviour).
    let err = RustoshiRpcServer::add_node(&server, node.clone(), "remove".to_string())
        .await
        .expect_err("removing an un-added node must error");
    assert_eq!(
        err.code(),
        rpc_error::RPC_CLIENT_NODE_NOT_ADDED,
        "remove of un-added node must emit -24 (RPC_CLIENT_NODE_NOT_ADDED), got {}: {}",
        err.code(),
        err.message(),
    );
    assert_eq!(
        err.message(),
        "Error: Node could not be removed. It has not been added previously.",
        "message must match Core net.cpp:368 exactly",
    );

    // After a matching add, remove must succeed (round-trips cleanly).
    RustoshiRpcServer::add_node(&server, node.clone(), "add".to_string())
        .await
        .expect("add must succeed");
    RustoshiRpcServer::add_node(&server, node.clone(), "remove".to_string())
        .await
        .expect("remove of a previously-added node must succeed");
}

/// G19 — `RPC_CLIENT_NODE_NOT_CONNECTED` (-29). Core net.cpp:478 (disconnectnode).
/// NOT DEFINED in rustoshi.
/// Status: BUG-13 (P1).
#[test]
#[ignore]
fn g19_rpc_client_node_not_connected_absence() {
    panic!("BUG-13: rustoshi has no RPC_CLIENT_NODE_NOT_CONNECTED (-29); \
            disconnectnode unknown-peer collapses to RPC_INVALID_PARAMS.");
}

/// G20 — `RPC_CLIENT_INVALID_IP_OR_SUBNET` (-30). Core net.cpp:780, 811.
/// NOT DEFINED in rustoshi (rustoshi uses -32602).
/// Status: BUG-14 (P1).
#[test]
#[ignore]
fn g20_rpc_client_invalid_ip_or_subnet_absence() {
    panic!("BUG-14: rustoshi has no RPC_CLIENT_INVALID_IP_OR_SUBNET (-30); \
            setban 'Invalid IP' returns -32602 instead of -30.");
}

// ============================================================
// G21 — `RPC_CLIENT_IN_INITIAL_DOWNLOAD` (-10) absence
// ============================================================

/// G21 — Core gates loadmempool, getblocktemplate, submitblock on IBD
/// with `RPC_CLIENT_IN_INITIAL_DOWNLOAD` (-10) (mempool.cpp:1141,
/// mining.cpp:773, 843). NOT DEFINED in rustoshi.
/// Status: BUG-5 (P1).
#[test]
#[ignore]
fn g21_rpc_client_in_initial_download_absence() {
    panic!("BUG-5: rustoshi has no RPC_CLIENT_IN_INITIAL_DOWNLOAD (-10); \
            loadmempool / getblocktemplate during IBD return wrong code.");
}

// ============================================================
// G22-G26 — Wallet error codes
// ============================================================

/// G22 — `RPC_WALLET_ERROR` -4 matches Core protocol.h:71.
/// Status: OK.
#[test]
fn g22_wallet_error_numeric() {
    assert_eq!(wallet_error::RPC_WALLET_ERROR, -4);
}

/// G23 — `RPC_WALLET_INSUFFICIENT_FUNDS` -6 matches Core protocol.h:72.
/// Status: OK.
#[test]
fn g23_wallet_insufficient_funds_numeric() {
    assert_eq!(wallet_error::RPC_WALLET_INSUFFICIENT_FUNDS, -6);
}

/// G24 — `RPC_WALLET_KEYPOOL_RAN_OUT` -12 / `RPC_WALLET_UNLOCK_NEEDED` -13 /
/// `RPC_WALLET_PASSPHRASE_INCORRECT` -14 / `RPC_WALLET_WRONG_ENC_STATE` -15.
/// Status: OK (4 codes match Core protocol.h:74-77).
#[test]
fn g24_wallet_enc_state_numerics() {
    assert_eq!(wallet_error::RPC_WALLET_KEYPOOL_RAN_OUT, -12);
    assert_eq!(wallet_error::RPC_WALLET_UNLOCK_NEEDED, -13);
    assert_eq!(wallet_error::RPC_WALLET_PASSPHRASE_INCORRECT, -14);
    assert_eq!(wallet_error::RPC_WALLET_WRONG_ENC_STATE, -15);
}

/// G25 — `RPC_WALLET_NOT_FOUND` -18 / `RPC_WALLET_NOT_SPECIFIED` -19 match
/// Core protocol.h:80-81.
/// Status: OK; BUG-27 P3 doubled alias on -19.
#[test]
fn g25_wallet_not_found_numerics() {
    assert_eq!(wallet_error::RPC_WALLET_NOT_FOUND, -18);
    assert_eq!(wallet_error::RPC_WALLET_NOT_SPECIFIED, -19);
    assert_eq!(wallet_error::RPC_WALLET_NOT_SELECTED, -19);
}

/// G26 — `RPC_WALLET_ALREADY_EXISTS` numeric parity (BUG-2 FIXED).
/// Core's `RPC_WALLET_ALREADY_EXISTS = -36` (protocol.h:83); `RPC_WALLET_ERROR
/// = -4` (protocol.h:71). Rustoshi previously defined ALREADY_EXISTS as -4, a
/// silent collision with the generic wallet error. Now remapped to -36.
/// Status: BUG-2 (P0) — FIXED. Confirm-present: ALREADY_EXISTS == -36 and does
/// NOT collide with RPC_WALLET_ERROR (-4).
#[test]
fn g26_wallet_already_exists_collision() {
    // Rustoshi's RPC_WALLET_ALREADY_EXISTS, now the genuine Core value.
    let rustoshi_exists = wallet_error::RPC_WALLET_ALREADY_EXISTS;
    // Core's RPC_WALLET_ALREADY_EXISTS = -36 (protocol.h:83).
    let core_exists: i32 = -36;
    assert_eq!(rustoshi_exists, core_exists,
        "BUG-2 FIXED: RPC_WALLET_ALREADY_EXISTS must be -36 (Core), is {}", rustoshi_exists);
    assert_ne!(rustoshi_exists, wallet_error::RPC_WALLET_ERROR,
        "RPC_WALLET_ALREADY_EXISTS must NOT collide with RPC_WALLET_ERROR (-4)");
}

/// G27 — `RPC_WALLET_ALREADY_LOADED` -35 matches Core protocol.h:82.
/// Status: OK.
#[test]
fn g27_wallet_already_loaded_numeric() {
    assert_eq!(wallet_error::RPC_WALLET_ALREADY_LOADED, -35);
}

// ============================================================
// G28-G30 — Cross-method behavioral parity (call-site checks)
// ============================================================

/// G28 — `sendrawtransaction` must distinguish MEMPOOL_REJECTED (-26),
/// ALREADY_IN_UTXO_SET (-27), and generic TRANSACTION_ERROR (-25) per
/// Core's `JSONRPCTransactionError` (util.cpp:408). Rustoshi collapses
/// all to -26 at server.rs:3766-3789.
/// Status: BUG-10 (P1).
#[test]
#[ignore]
fn g28_sendrawtransaction_collapses_error_codes_bug10() {
    panic!("BUG-10: sendrawtransaction maps every MempoolError variant to \
            RPC_TRANSACTION_REJECTED (-26); Core distinguishes -25/-26/-27.");
}

/// G29 — `getblockhash` height-out-of-range must emit -8 per Core
/// `src/rpc/blockchain.cpp::getblockhash`:
///   if (nHeight < 0 || nHeight > active_chain.Height())
///       throw JSONRPCError(RPC_INVALID_PARAMETER, "Block height out of range");
/// (`RPC_INVALID_PARAMETER == -8` in `src/rpc/protocol.h`).
/// Status: BUG-17 (P2), parent BUG-3 — FIXED at server.rs `get_block_hash`.
///
/// De-staled 2026-06-16: the prior `#[ignore]` `panic!` stub only documented
/// the bug. This is now a REAL behavioral test: it builds a server with only
/// the regtest genesis block (best height 0, so any height > 0 is
/// out-of-range), calls the `getblockhash` handler with an out-of-range
/// height, and asserts Core's numeric code (-8) AND exact message text.
#[tokio::test]
async fn g29_getblockhash_oor_emits_invalid_parameter() {
    use rustoshi_consensus::ChainParams;
    use rustoshi_rpc::{PeerState, RpcServerImpl, RpcState, RustoshiRpcServer};
    use rustoshi_storage::{block_store::BlockStore, ChainDb};
    use std::sync::Arc;
    use tokio::sync::RwLock;

    // Fresh tempdir-backed chain DB with only the regtest genesis block.
    let tmp = tempfile::tempdir().expect("tempdir");
    let db = Arc::new(ChainDb::open(tmp.path()).expect("open chaindb"));
    let params = ChainParams::regtest();
    {
        let store = BlockStore::new(&db);
        store.init_genesis(&params).expect("init genesis");
    }

    let mut rpc_state = RpcState::new(db.clone(), params);
    {
        let store = BlockStore::new(&db);
        rpc_state.best_hash = store
            .get_best_block_hash()
            .expect("best hash")
            .expect("genesis present");
        rpc_state.best_height = store.get_best_height().expect("best height").expect("height 0");
    }
    assert_eq!(rpc_state.best_height, 0, "fresh genesis chain must have tip height 0");

    let state = Arc::new(RwLock::new(rpc_state));
    let peer_state = Arc::new(RwLock::new(PeerState::default()));
    let server = RpcServerImpl::new(state, peer_state);

    // height 0 (genesis) is valid → returns a 64-hex hash, not an error.
    let ok = RustoshiRpcServer::get_block_hash(&server, 0)
        .await
        .expect("getblockhash(0) must succeed for genesis");
    assert_eq!(ok.len(), 64, "genesis block hash must be 64 hex chars, got {:?}", ok);

    // Out-of-range height (way past the tip) → Core's RPC_INVALID_PARAMETER (-8)
    // with the exact Core message, NOT the JSON-RPC transport code -32602.
    let err = RustoshiRpcServer::get_block_hash(&server, 999_999)
        .await
        .expect_err("getblockhash for out-of-range height must error");
    assert_eq!(
        err.code(),
        rpc_error::RPC_INVALID_PARAMETER,
        "getblockhash out-of-range must emit -8 (RPC_INVALID_PARAMETER), \
         not -32602 (RPC_INVALID_PARAMS); got {}: {}",
        err.code(),
        err.message(),
    );
    assert_eq!(err.code(), -8, "RPC_INVALID_PARAMETER numeric value must be -8");
    assert_ne!(
        err.code(),
        rpc_error::RPC_INVALID_PARAMS,
        "must not collide with the JSON-RPC transport code -32602",
    );
    assert_eq!(
        err.message(),
        "Block height out of range",
        "message must match Core exactly (no height interpolation)",
    );
}

/// G30 — Error response shape: `{"code": i32, "message": String, "data": null}`
/// per JSON-RPC 2.0 §5.1. jsonrpsee's `ErrorObjectOwned` enforces this and
/// rustoshi never overrides. Cross-cuts the entire surface.
/// Status: OK (shape correct via library); per-method code/message text
/// diverges per BUG-1..BUG-24.
#[test]
fn g30_error_response_shape_ok() {
    use jsonrpsee::types::ErrorObjectOwned;
    let err = ErrorObjectOwned::owned(rpc_error::RPC_MISC_ERROR, "test", None::<()>);
    assert_eq!(err.code(), -1);
    assert_eq!(err.message(), "test");
    assert!(err.data().is_none());
}

// ============================================================
// Cross-cutting test: count operator-visible code uses
// ============================================================

/// Sanity check: confirm rustoshi's defined codes are still the ones we audited.
/// Pin all 17 numeric constants in one place so accidental constant churn is
/// caught fast. If this fails, the W125 findings table is out of date and
/// needs re-audit before fixes can land.
#[test]
fn pin_all_w125_constants() {
    // rpc_error module (17 codes documented).
    assert_eq!(rpc_error::RPC_PARSE_ERROR, -32700);
    assert_eq!(rpc_error::RPC_INVALID_REQUEST, -32600);
    assert_eq!(rpc_error::RPC_INVALID_PARAMS, -32602);
    assert_eq!(rpc_error::RPC_INTERNAL_ERROR, -32603);
    assert_eq!(rpc_error::RPC_MISC_ERROR, -1);
    assert_eq!(rpc_error::RPC_TYPE_ERROR, -3);
    assert_eq!(rpc_error::RPC_INVALID_ADDRESS_OR_KEY, -5);
    assert_eq!(rpc_error::RPC_DATABASE_ERROR, -20);
    assert_eq!(rpc_error::RPC_DESERIALIZATION_ERROR, -22);
    assert_eq!(rpc_error::RPC_TRANSACTION_ERROR, -25);
    assert_eq!(rpc_error::RPC_VERIFY_REJECTED, -26);
    assert_eq!(rpc_error::RPC_TRANSACTION_REJECTED, -26);
    assert_eq!(rpc_error::RPC_VERIFY_ALREADY_IN_CHAIN, -27);
    assert_eq!(rpc_error::RPC_TRANSACTION_ALREADY_IN_CHAIN, -27);
    assert_eq!(rpc_error::RPC_CLIENT_P2P_DISABLED, -31); // BUG-1 FIXED: genuine Core value
    assert_eq!(rpc_error::RPC_BLOCK_NOT_FOUND, -5);
    // wallet_error module.
    assert_eq!(wallet_error::RPC_WALLET_ERROR, -4);
    assert_eq!(wallet_error::RPC_WALLET_INSUFFICIENT_FUNDS, -6);
    assert_eq!(wallet_error::RPC_WALLET_INVALID_ADDRESS_OR_KEY, -5);
    assert_eq!(wallet_error::RPC_WALLET_KEYPOOL_RAN_OUT, -12);
    assert_eq!(wallet_error::RPC_WALLET_UNLOCK_NEEDED, -13);
    assert_eq!(wallet_error::RPC_WALLET_PASSPHRASE_INCORRECT, -14);
    assert_eq!(wallet_error::RPC_WALLET_WRONG_ENC_STATE, -15);
    assert_eq!(wallet_error::RPC_WALLET_ALREADY_EXISTS, -36); // BUG-2 FIXED: genuine Core value
    assert_eq!(wallet_error::RPC_WALLET_ALREADY_LOADED, -35);
    assert_eq!(wallet_error::RPC_WALLET_NOT_FOUND, -18);
    assert_eq!(wallet_error::RPC_WALLET_NOT_SPECIFIED, -19);
    assert_eq!(wallet_error::RPC_WALLET_NOT_SELECTED, -19);
}
