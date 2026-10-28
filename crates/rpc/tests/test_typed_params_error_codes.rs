//! Wrongly typed arguments get Core's -3 errors, not jsonrpsee's -32602.
//!
//! Core (`rpc/util.cpp` `RPCHelpMan::HandleRequest` type gate, and
//! `AmountFromValue`) answers -3 for these three calls; rustoshi used to
//! refuse them in jsonrpsee's typed-params layer before the handler ran.
//! Messages are the ones Core v31.1 produced in the core-regtest `operator`
//! group (`getblockheader/bad-verbose`, `testmempoolaccept/not-an-array`,
//! `sendrawtransaction/bad-maxfeerate`).

use rustoshi_consensus::ChainParams;
use rustoshi_rpc::{PeerState, RpcServerImpl, RpcState, RustoshiRpcServer};
use rustoshi_storage::ChainDb;
use std::sync::Arc;
use tokio::sync::RwLock;

async fn rpc(method: &str, params: serde_json::Value) -> serde_json::Value {
    let tmp = tempfile::tempdir().expect("tempdir");
    let db = Arc::new(ChainDb::open(tmp.path()).expect("open chaindb"));
    let state = Arc::new(RwLock::new(RpcState::new(db, ChainParams::regtest())));
    let peer_state = Arc::new(RwLock::new(PeerState::default()));
    std::mem::forget(tmp);
    let module = RpcServerImpl::new(state, peer_state).into_rpc();
    let req = serde_json::json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}).to_string();
    let (resp, _) = module.raw_json_request(&req, 1).await.expect("dispatch");
    serde_json::from_str(&resp).expect("json")
}

fn assert_err(resp: &serde_json::Value, code: i64, message: &str) {
    let err = resp
        .get("error")
        .filter(|e| !e.is_null())
        .unwrap_or_else(|| panic!("expected error {code}, got {resp}"));
    assert_eq!(err["code"].as_i64(), Some(code), "wrong code: {resp}");
    assert_eq!(err["message"].as_str(), Some(message), "wrong message: {resp}");
}

const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
// Never reaches decoding in these tests when the type gate fires first.
const SOME_TX: &str = "00";
// Decodes (one null-prevout input, one empty zero-value output), so a call
// with it gets past DecodeHexTx to Core's maxfeerate parse.
const DECODABLE_TX: &str = concat!(
    "01000000",
    "01",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "ffffffff",
    "00",
    "ffffffff",
    "01",
    "0000000000000000",
    "00",
    "00000000",
);
const FEE_RATE_TOO_HIGH: &str = "Fee rates larger than or equal to 1BTC/kvB are not accepted";
const BAD_ARRAY_LEN: &str = "Array must contain between 1 and 25 transactions.";

#[tokio::test]
async fn getblockheader_verbose_string_is_core_type_error() {
    let r = rpc("getblockheader", serde_json::json!([ZERO_HASH, "x"])).await;
    assert_err(
        &r,
        -3,
        "Wrong type passed:\n{\n    \"Position 2 (verbose)\": \"JSON value of type string is not of expected type bool\"\n}",
    );
}

#[tokio::test]
async fn testmempoolaccept_rawtxs_string_is_core_type_error() {
    let r = rpc("testmempoolaccept", serde_json::json!([SOME_TX])).await;
    assert_err(
        &r,
        -3,
        "Wrong type passed:\n{\n    \"Position 1 (rawtxs)\": \"JSON value of type string is not of expected type array\"\n}",
    );
}

#[tokio::test]
async fn sendrawtransaction_maxfeerate_string_is_invalid_amount() {
    let r = rpc("sendrawtransaction", serde_json::json!([DECODABLE_TX, "x"])).await;
    assert_err(&r, -3, "Invalid amount");
}

/// Core decodes the hex before ParseFeeRate, so a bad tx wins over a bad rate.
#[tokio::test]
async fn sendrawtransaction_decodes_before_maxfeerate() {
    let r = rpc("sendrawtransaction", serde_json::json!([SOME_TX, "x"])).await;
    assert_err(&r, -22, "TX decode failed. Make sure the tx has at least one input.");
    let r = rpc("sendrawtransaction", serde_json::json!([SOME_TX, 1])).await;
    assert_err(&r, -22, "TX decode failed. Make sure the tx has at least one input.");
}

/// ParseFeeRate: a rate >= 1 BTC/kvB (exactly 1 included) is -8.
#[tokio::test]
async fn sendrawtransaction_maxfeerate_one_btc_is_invalid_parameter() {
    let r = rpc("sendrawtransaction", serde_json::json!([DECODABLE_TX, 1])).await;
    assert_err(&r, -8, FEE_RATE_TOO_HIGH);
    let r = rpc("sendrawtransaction", serde_json::json!([DECODABLE_TX, "1.5"])).await;
    assert_err(&r, -8, FEE_RATE_TOO_HIGH);
}

/// Control: just under 1 BTC/kvB passes the rate parse.
#[tokio::test]
async fn sendrawtransaction_maxfeerate_below_one_btc_passes_rate_parse() {
    let r = rpc("sendrawtransaction", serde_json::json!([DECODABLE_TX, 0.99999999])).await;
    let code = r["error"]["code"].as_i64();
    assert!(!matches!(code, Some(-8) | Some(-3) | Some(-32602)), "{r}");
}

/// get_str() on a non-string element is UniValue::type_error -> -3.
#[tokio::test]
async fn testmempoolaccept_nonstring_element_is_type_error() {
    let r = rpc("testmempoolaccept", serde_json::json!([[1]])).await;
    assert_err(&r, -3, "JSON value of type number is not of expected type string");
}

/// Core reads and decodes elements in order: an earlier bad hex wins.
#[tokio::test]
async fn testmempoolaccept_elements_read_and_decoded_in_order() {
    let r = rpc("testmempoolaccept", serde_json::json!([[SOME_TX, 1]])).await;
    assert_err(&r, -22, "TX decode failed: 00 Make sure the tx has at least one input.");
}

/// Core's order is length, then maxfeerate, then elements.
#[tokio::test]
async fn testmempoolaccept_length_checked_before_maxfeerate_and_elements() {
    let r = rpc("testmempoolaccept", serde_json::json!([[], "x"])).await;
    assert_err(&r, -8, BAD_ARRAY_LEN);
    let too_many: Vec<serde_json::Value> = (0..26).map(|_| serde_json::json!(1)).collect();
    let r = rpc("testmempoolaccept", serde_json::json!([too_many, "x"])).await;
    assert_err(&r, -8, BAD_ARRAY_LEN);
    let r = rpc("testmempoolaccept", serde_json::json!([[], 1])).await;
    assert_err(&r, -8, BAD_ARRAY_LEN);
}

#[tokio::test]
async fn testmempoolaccept_maxfeerate_checked_before_elements() {
    let r = rpc("testmempoolaccept", serde_json::json!([[1], "x"])).await;
    assert_err(&r, -3, "Invalid amount");
    let r = rpc("testmempoolaccept", serde_json::json!([[1], 1])).await;
    assert_err(&r, -8, FEE_RATE_TOO_HIGH);
}

/// ParseFeeRate: exactly 1 BTC/kvB is -8 for testmempoolaccept too.
#[tokio::test]
async fn testmempoolaccept_maxfeerate_one_btc_is_invalid_parameter() {
    let r = rpc("testmempoolaccept", serde_json::json!([[DECODABLE_TX], 1])).await;
    assert_err(&r, -8, FEE_RATE_TOO_HIGH);
}

#[tokio::test]
async fn testmempoolaccept_maxfeerate_string_is_invalid_amount() {
    let r = rpc("testmempoolaccept", serde_json::json!([[SOME_TX], "x"])).await;
    assert_err(&r, -3, "Invalid amount");
}

/// Control: a correctly typed call must still reach the handler (not -3/-32602).
#[tokio::test]
async fn getblockheader_verbose_bool_still_reaches_handler() {
    let r = rpc("getblockheader", serde_json::json!([ZERO_HASH, false])).await;
    assert_eq!(r["error"]["code"].as_i64(), Some(-5), "{r}");
}

/// Control: string amounts are valid for AmountFromValue ("0.1" == 0.1).
#[tokio::test]
async fn sendrawtransaction_maxfeerate_numeric_string_passes_amount_gate() {
    let r = rpc("sendrawtransaction", serde_json::json!([DECODABLE_TX, "0.1"])).await;
    assert_ne!(r["error"]["code"].as_i64(), Some(-3), "{r}");
    assert_ne!(r["error"]["code"].as_i64(), Some(-32602), "{r}");
}
