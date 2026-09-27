//! R5 error-code parity pins (2026-09-26).
//!
//! Every test here drives the REAL jsonrpsee dispatch with a raw JSON-RPC
//! request, so a parameter the `#[rpc]` trait types too narrowly shows up as
//! the transport code -32602 exactly as it did on the wire. Expected codes and
//! messages were captured from Bitcoin Core v31.99 (the R5 oracle) on
//! 2026-09-26; each test names the Core source that produces them.
//!
//! The module deliberately uses only the crate's public surface (no private
//! test helpers) so it compiles against the pre-fix tree too: that is how the
//! "fails before" half of each pin was checked.

use crate::server::{PeerState, RpcServerImpl, RpcState, RustoshiRpcServer};
use rustoshi_consensus::ChainParams;
use rustoshi_storage::ChainDb;
use std::sync::Arc;
use tokio::sync::RwLock;

fn server_with_state() -> (Arc<RwLock<RpcState>>, RpcServerImpl) {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().to_path_buf();
    // Keep the directory for the life of the test process.
    std::mem::forget(tmp);
    let db = Arc::new(ChainDb::open(&path).unwrap());
    let state = Arc::new(RwLock::new(RpcState::new(db, ChainParams::regtest())));
    let peer_state = Arc::new(RwLock::new(PeerState::default()));
    let server = RpcServerImpl::new(state.clone(), peer_state);
    (state, server)
}

async fn call(server: RpcServerImpl, method: &str, params: serde_json::Value) -> serde_json::Value {
    let module = server.into_rpc();
    let req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "r5",
        "method": method,
        "params": params,
    })
    .to_string();
    let (resp, _) = module.raw_json_request(&req, 1).await.expect("dispatch");
    serde_json::from_str(&resp).expect("json response")
}

async fn rpc(method: &str, params: serde_json::Value) -> serde_json::Value {
    let (_state, server) = server_with_state();
    call(server, method, params).await
}

/// Assert an error with Core's code (and, when given, Core's exact message).
fn assert_err(resp: &serde_json::Value, code: i64, message: Option<&str>) {
    let err = resp
        .get("error")
        .filter(|e| !e.is_null())
        .unwrap_or_else(|| panic!("expected error {code}, got {resp}"));
    assert_eq!(err["code"].as_i64(), Some(code), "wrong code: {resp}");
    if let Some(m) = message {
        assert_eq!(err["message"].as_str(), Some(m), "wrong message: {resp}");
    }
}

fn result(resp: &serde_json::Value) -> &serde_json::Value {
    assert!(
        resp.get("error").map(|e| e.is_null()).unwrap_or(true),
        "expected success, got {resp}"
    );
    &resp["result"]
}

// Shared fixtures (the R5 probe's own inputs).
const K1: &str = "03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd";
const K2: &str = "03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626";
/// 1-in/1-out unsigned PSBT paying 0.001 to wpkh(G) (the key of WIF
/// KwDiBf89..., private key 1) -- the probe's PSBT.
const PSBT: &str = "cHNidP8BAFICAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9////AaCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAAA";
/// Core's descriptorprocesspsbt(PSBT, ["wpkh(KwDiBf89...)"]).psbt: the
/// output gains bip32_derivs {pubkey G: fingerprint 751e76e8, path m}.
const PSBT_DPP: &str = "cHNidP8BAFICAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9////AaCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAAiAgJ5vmZ++dy7rFWgYpXOhwsHApv82y3OKNlZ8oFbFvgXmAR1HnboAA==";
const WIF_ONE: &str = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";

// ---- decoderawtransaction (rawtransaction.cpp: DecodeHexTx -> -22) ----

#[tokio::test]
async fn decoderawtransaction_nonhex_is_deserialization_error() {
    let r = rpc("decoderawtransaction", serde_json::json!(["zz"])).await;
    assert_err(&r, -22, Some("TX decode failed"));
}

#[tokio::test]
async fn decoderawtransaction_wrong_type_is_core_type_gate() {
    let r = rpc("decoderawtransaction", serde_json::json!([123])).await;
    assert_err(
        &r,
        -3,
        Some("Wrong type passed:\n{\n    \"Position 1 (hexstring)\": \"JSON value of type number is not of expected type string\"\n}"),
    );
}

// ---- verifytxoutproof (txoutproof.cpp: ParseHexV(proof, "proof") -> -8) ----

#[tokio::test]
async fn verifytxoutproof_nonhex_is_invalid_parameter() {
    let r = rpc("verifytxoutproof", serde_json::json!(["zz"])).await;
    assert_err(&r, -8, Some("proof must be hexadecimal string (not 'zz')"));
}

// ---- importmempool (mempool.cpp) ----

#[tokio::test]
async fn importmempool_refused_during_ibd() {
    let (_state, server) = server_with_state();
    let r = call(server, "importmempool", serde_json::json!(["/nonexistent/x.dat"])).await;
    assert_err(
        &r,
        -10,
        Some("Can only import the mempool after the block download and sync is done."),
    );
}

#[tokio::test]
async fn importmempool_bad_path_is_misc_error() {
    let (state, server) = server_with_state();
    state.write().await.is_ibd = false;
    let r = call(
        server,
        "importmempool",
        serde_json::json!(["/nonexistent/r5-probe-no-such-file.dat"]),
    )
    .await;
    assert_err(&r, -1, Some("Unable to import mempool file, see debug log for details."));
}

#[tokio::test]
async fn importmempool_bad_option_type_is_type_error() {
    let (state, server) = server_with_state();
    state.write().await.is_ibd = false;
    let r = call(
        server,
        "importmempool",
        serde_json::json!(["/nonexistent/x.dat", {"use_current_time": "yes"}]),
    )
    .await;
    assert_err(&r, -3, Some("JSON value of type string is not of expected type bool"));
}

// ---- scantxoutset / scanblocks (blockchain.cpp:2471 / :2713 -> -8) ----

#[tokio::test]
async fn scantxoutset_unknown_action_is_invalid_parameter() {
    let r = rpc("scantxoutset", serde_json::json!(["bogus"])).await;
    assert_err(&r, -8, Some("Invalid action 'bogus'"));
}

#[tokio::test]
async fn scanblocks_unknown_action_is_invalid_parameter() {
    let r = rpc("scanblocks", serde_json::json!(["bogus"])).await;
    assert_err(&r, -8, Some("Invalid action 'bogus'"));
}

// ---- pruneblockchain (RPCHelpMan gate -> -3) ----

#[tokio::test]
async fn pruneblockchain_string_height_is_type_error() {
    let r = rpc("pruneblockchain", serde_json::json!(["zz"])).await;
    assert_err(
        &r,
        -3,
        Some("Wrong type passed:\n{\n    \"Position 1 (height)\": \"JSON value of type string is not of expected type number\"\n}"),
    );
}

#[tokio::test]
async fn pruneblockchain_not_prune_mode_matches_core_message() {
    let r = rpc("pruneblockchain", serde_json::json!([-1])).await;
    assert_err(&r, -1, Some("Cannot prune blocks because node is not in prune mode."));
}

// ---- decodescript (ParseHexV(.., "argument") -> -8) ----

#[tokio::test]
async fn decodescript_nonhex_is_invalid_parameter() {
    let r = rpc("decodescript", serde_json::json!(["zz"])).await;
    assert_err(&r, -8, Some("argument must be hexadecimal string (not 'zz')"));
}

// ---- converttopsbt (DecodeHexTx -> -22) ----

#[tokio::test]
async fn converttopsbt_nonhex_is_deserialization_error() {
    let r = rpc("converttopsbt", serde_json::json!(["zz"])).await;
    assert_err(&r, -22, Some("TX decode failed"));
}

// ---- createpsbt / createrawtransaction (shared ConstructTransaction) ----

#[tokio::test]
async fn createpsbt_accepts_core_object_form_outputs() {
    let r = rpc(
        "createpsbt",
        serde_json::json!([
            [{"txid": "aa".repeat(32), "vout": 0}],
            {"bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080": 0.001}
        ]),
    )
    .await;
    // Same unsigned tx as the probe's PSBT (network-independent bytes).
    assert_eq!(result(&r).as_str(), Some(PSBT), "{r}");
}

#[tokio::test]
async fn createpsbt_malformed_txid_is_invalid_parameter() {
    let r = rpc(
        "createpsbt",
        serde_json::json!([
            [{"txid": "zz", "vout": 0}],
            {"bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080": 0.001}
        ]),
    )
    .await;
    assert_err(&r, -8, Some("txid must be of length 64 (not 2, for 'zz')"));
}

#[tokio::test]
async fn createpsbt_nonhex_data_is_invalid_parameter() {
    let r = rpc(
        "createpsbt",
        serde_json::json!([[{"txid": "aa".repeat(32), "vout": 0}], [{"data": "zz"}]]),
    )
    .await;
    assert_err(&r, -8, Some("Data must be hexadecimal string (not 'zz')"));
}

#[tokio::test]
async fn createrawtransaction_negative_amount_is_out_of_range() {
    // Used to be ACCEPTED as a zero-value output.
    let r = rpc(
        "createrawtransaction",
        serde_json::json!([[], {"bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080": -1}]),
    )
    .await;
    assert_err(&r, -3, Some("Amount out of range"));
}

#[tokio::test]
async fn createrawtransaction_string_amount_is_accepted() {
    let r = rpc(
        "createrawtransaction",
        serde_json::json!([[], {"bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080": "0.001"}]),
    )
    .await;
    assert_eq!(
        result(&r).as_str(),
        Some("020000000001a086010000000000160014751e76e8199196d454941c45d1b3a323f1433bd600000000"),
        "{r}"
    );
}

#[tokio::test]
async fn createrawtransaction_wrong_network_address_is_rejected() {
    // A MAINNET address on a regtest node: Core IsValidDestination fails.
    let r = rpc(
        "createrawtransaction",
        serde_json::json!([[], {"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4": 1}]),
    )
    .await;
    assert_err(
        &r,
        -5,
        Some("Invalid Bitcoin address: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"),
    );
}

#[tokio::test]
async fn createrawtransaction_type_gate_names_position() {
    let r = rpc("createrawtransaction", serde_json::json!([[], {}, 0, "x"])).await;
    assert_err(
        &r,
        -3,
        Some("Wrong type passed:\n{\n    \"Position 4 (replaceable)\": \"JSON value of type string is not of expected type bool\"\n}"),
    );
}

// ---- combinepsbt (rawtransaction.cpp:1540 -> -8) ----

#[tokio::test]
async fn combinepsbt_empty_array_is_invalid_parameter() {
    let r = rpc("combinepsbt", serde_json::json!([[]])).await;
    assert_err(&r, -8, Some("Parameter 'txs' cannot be empty"));
}

#[tokio::test]
async fn combinepsbt_identical_still_combines() {
    let r = rpc("combinepsbt", serde_json::json!([[PSBT, PSBT]])).await;
    assert_eq!(result(&r).as_str(), Some(PSBT), "{r}");
}

// ---- utxoupdatepsbt / descriptorprocesspsbt (new methods) ----

#[tokio::test]
async fn utxoupdatepsbt_unknown_inputs_pass_through() {
    let r = rpc("utxoupdatepsbt", serde_json::json!([PSBT])).await;
    assert_eq!(result(&r).as_str(), Some(PSBT), "{r}");
}

#[tokio::test]
async fn utxoupdatepsbt_bad_base64_is_deserialization_error() {
    let r = rpc("utxoupdatepsbt", serde_json::json!(["notbase64!!"])).await;
    assert_err(&r, -22, None);
}

#[tokio::test]
async fn descriptorprocesspsbt_matches_core_exactly() {
    let r = rpc(
        "descriptorprocesspsbt",
        serde_json::json!([PSBT, [format!("wpkh({WIF_ONE})")]]),
    )
    .await;
    let res = result(&r);
    assert_eq!(res["psbt"].as_str(), Some(PSBT_DPP), "{r}");
    assert_eq!(res["complete"], serde_json::json!(false), "{r}");
    assert!(res.get("hex").is_none(), "{r}");
}

#[tokio::test]
async fn descriptorprocesspsbt_bip32derivs_false_adds_nothing() {
    let r = rpc(
        "descriptorprocesspsbt",
        serde_json::json!([PSBT, [format!("wpkh({WIF_ONE})")], "ALL", false]),
    )
    .await;
    assert_eq!(result(&r)["psbt"].as_str(), Some(PSBT), "{r}");
}

#[tokio::test]
async fn descriptorprocesspsbt_bad_descriptor_is_invalid_address_or_key() {
    let r = rpc(
        "descriptorprocesspsbt",
        serde_json::json!([PSBT, ["nonsense(desc)"]]),
    )
    .await;
    assert_err(&r, -5, None);
}

#[tokio::test]
async fn descriptorprocesspsbt_bad_sighash_is_invalid_parameter() {
    let r = rpc(
        "descriptorprocesspsbt",
        serde_json::json!([PSBT, [format!("wpkh({WIF_ONE})")], "BOGUS"]),
    )
    .await;
    assert_err(&r, -8, Some("'BOGUS' is not a valid sighash parameter."));
}

// ---- submitpackage (mempool.cpp:1363 -> -8; DecodeHexTx -> -22) ----

#[tokio::test]
async fn submitpackage_empty_array_is_invalid_parameter() {
    let r = rpc("submitpackage", serde_json::json!([[]])).await;
    assert_err(&r, -8, Some("Array must contain between 1 and 25 transactions."));
}

#[tokio::test]
async fn submitpackage_nonhex_is_deserialization_error() {
    let r = rpc("submitpackage", serde_json::json!([["zz"]])).await;
    assert_err(
        &r,
        -22,
        Some("TX decode failed: zz Make sure the tx has at least one input."),
    );
}

// ---- createmultisig (output_script.cpp + util.cpp HexToPubKey) ----

#[tokio::test]
async fn createmultisig_bad_pubkey_length_is_invalid_address_or_key() {
    let r = rpc("createmultisig", serde_json::json!([1, ["deadbeef"]])).await;
    assert_err(
        &r,
        -5,
        Some("Pubkey \"deadbeef\" must have a length of either 33 or 65 bytes"),
    );
}

#[tokio::test]
async fn createmultisig_not_enough_keys_is_invalid_parameter() {
    let r = rpc("createmultisig", serde_json::json!([3, [K1, K2]])).await;
    assert_err(
        &r,
        -8,
        Some("not enough keys supplied (got 2 keys, but need at least 3 to redeem)"),
    );
}

#[tokio::test]
async fn createmultisig_key_errors_precede_count_errors() {
    // Core parses every key before the count checks.
    let r = rpc("createmultisig", serde_json::json!([3, ["deadbeef", "deadbeef"]])).await;
    assert_err(&r, -5, None);
}

#[tokio::test]
async fn createmultisig_bech32m_is_refused() {
    let r = rpc("createmultisig", serde_json::json!([1, [K1], "bech32m"])).await;
    assert_err(&r, -5, Some("createmultisig cannot create bech32m multisig addresses"));
}

#[tokio::test]
async fn createmultisig_valid_2of2_still_succeeds() {
    let r = rpc("createmultisig", serde_json::json!([2, [K1, K2]])).await;
    let res = result(&r);
    assert_eq!(
        res["redeemScript"].as_str(),
        Some(format!("5221{K1}21{K2}52ae").as_str()),
        "{r}"
    );
    assert!(res.get("warnings").is_none(), "{r}");
}

// ---- getdescriptorinfo (output_script.cpp -> -5) ----

#[tokio::test]
async fn getdescriptorinfo_invalid_descriptor_is_invalid_address_or_key() {
    let r = rpc("getdescriptorinfo", serde_json::json!(["notadescriptor"])).await;
    assert_err(&r, -5, None);
}

#[tokio::test]
async fn getdescriptorinfo_bad_checksum_matches_core_message() {
    let r = rpc(
        "getdescriptorinfo",
        serde_json::json!([format!("wpkh({K1})#00000000")]),
    )
    .await;
    assert_err(
        &r,
        -5,
        Some("Provided checksum '00000000' does not match computed checksum 'e72f49hy'"),
    );
}

// ---- getindexinfo (RPCHelpMan gate -> -3) ----

#[tokio::test]
async fn getindexinfo_wrong_type_is_type_error() {
    let r = rpc("getindexinfo", serde_json::json!([123])).await;
    assert_err(
        &r,
        -3,
        Some("Wrong type passed:\n{\n    \"Position 1 (index_name)\": \"JSON value of type number is not of expected type string\"\n}"),
    );
}

// ---- verifymessage (rpc/signmessage.cpp -> -3) ----

#[tokio::test]
async fn verifymessage_malformed_signature_is_type_error() {
    let r = rpc(
        "verifymessage",
        serde_json::json!(["1GAehh7TsJAHuUAeKZcXf5CnwuGuGgyX2S", "not-base64!!", "hashhog r5 probe"]),
    )
    .await;
    assert_err(&r, -3, Some("Malformed base64 encoding"));
}

#[tokio::test]
async fn verifymessage_bad_address_precedes_bad_signature() {
    let r = rpc(
        "verifymessage",
        serde_json::json!(["notanaddress", "not-base64!!", "m"]),
    )
    .await;
    assert_err(&r, -5, Some("Invalid address"));
}

// ---- help parity: every probed method must be listed ----

#[tokio::test]
async fn help_lists_every_r5_method_rustoshi_serves() {
    let r = rpc("help", serde_json::json!([])).await;
    let text = result(&r).as_str().expect("help text").to_string();
    let listed: std::collections::HashSet<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('='))
        .filter_map(|l| l.split_whitespace().next())
        .collect();
    for m in [
        "gettxoutsetinfo",
        "getnetworkhashps",
        "importmempool",
        "utxoupdatepsbt",
        "descriptorprocesspsbt",
        "scanblocks",
        "scantxoutset",
        "submitpackage",
        "verifytxoutproof",
    ] {
        assert!(listed.contains(m), "help does not list {m}");
    }
}
