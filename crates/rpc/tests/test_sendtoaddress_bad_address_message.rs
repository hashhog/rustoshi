//! Core v31.1 `sendtoaddress` refuses an undecodable destination in
//! `ParseOutputs` (rpc/rawtransaction_util.cpp:117-121) with
//! RPC_INVALID_ADDRESS_OR_KEY (-5) "Invalid Bitcoin address: <addr>".
//! The amount is parsed first (AmountFromValue on the line before), so a bad
//! amount still wins over a bad address.

use rustoshi_crypto::address::Network;
use rustoshi_rpc::{WalletRpcImpl, WalletRpcServer, WalletRpcState};
use rustoshi_wallet::{CreateWalletOptions, WalletManager};
use std::sync::Arc;
use tokio::sync::RwLock;

fn rpc() -> WalletRpcImpl {
    let dir = tempfile::tempdir().unwrap();
    let mut manager = WalletManager::new(dir.path(), Network::Regtest).unwrap();
    manager.create_wallet("w", CreateWalletOptions::default()).unwrap();
    let state = Arc::new(RwLock::new(WalletRpcState::new(manager, dir.keep())));
    WalletRpcImpl::new(state)
}

async fn send(rpc: &WalletRpcImpl, addr: &str, amount: serde_json::Value) -> (i32, String) {
    let err = rpc
        .send_to_address(addr.to_string(), amount, None, None, None, None, None, None)
        .await
        .expect_err("sendtoaddress on an empty wallet must fail");
    (err.code(), err.message().to_string())
}

#[tokio::test]
async fn sendtoaddress_bad_address_message_names_address() {
    let (code, msg) = send(&rpc(), "notanaddress", serde_json::json!(1)).await;
    assert_eq!(code, -5, "code: {msg}");
    assert_eq!(msg, "Invalid Bitcoin address: notanaddress", "Core ParseOutputs text");
}

#[tokio::test]
async fn sendtoaddress_wrong_network_address_is_invalid() {
    // A mainnet address on a regtest wallet does not decode for Core either.
    let a = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    let (code, msg) = send(&rpc(), a, serde_json::json!(1)).await;
    assert_eq!(code, -5, "code: {msg}");
    assert_eq!(msg, format!("Invalid Bitcoin address: {a}"));
}

#[tokio::test]
async fn sendtoaddress_bad_amount_wins_over_bad_address() {
    // Control: AmountFromValue runs before the destination check in Core.
    let (code, msg) = send(&rpc(), "notanaddress", serde_json::json!(-1)).await;
    assert_eq!(code, -3, "code: {msg}");
    assert_eq!(msg, "Amount out of range");
}

#[tokio::test]
async fn sendtoaddress_valid_address_is_not_an_address_error() {
    // Control: a valid regtest address passes the check and fails later
    // (empty wallet), never with the invalid-address error.
    let a = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
    let (code, msg) = send(&rpc(), a, serde_json::json!(1)).await;
    assert_ne!(code, -5, "valid address refused: {msg}");
    assert!(!msg.contains("address"), "valid address refused: {msg}");
}
