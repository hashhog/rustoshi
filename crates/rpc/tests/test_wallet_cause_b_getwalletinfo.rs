//! Core v31.1 `getwalletinfo` (wallet/rpc/wallet.cpp) has no `balance`,
//! `unconfirmed_balance` or `immature_balance`; balances live in
//! `getbalances` / `getbalance`.

use rustoshi_crypto::address::Network;
use rustoshi_rpc::{WalletRpcImpl, WalletRpcServer, WalletRpcState};
use rustoshi_wallet::{CreateWalletOptions, WalletManager};
use std::sync::Arc;
use tokio::sync::RwLock;

async fn info_json() -> serde_json::Value {
    let dir = tempfile::tempdir().unwrap();
    let mut manager = WalletManager::new(dir.path(), Network::Regtest).unwrap();
    manager.create_wallet("w", CreateWalletOptions::default()).unwrap();
    let state = Arc::new(RwLock::new(WalletRpcState::new(manager, dir.keep())));
    let rpc = WalletRpcImpl::new(state);
    let info = rpc.get_wallet_info(None).await.unwrap();
    serde_json::to_value(&info).unwrap()
}

#[tokio::test]
async fn getwalletinfo_has_no_legacy_balance_fields() {
    let v = info_json().await;
    for f in ["balance", "unconfirmed_balance", "immature_balance"] {
        assert!(v.get(f).is_none(), "getwalletinfo still reports {f:?}: Core v31 has no such field");
    }
}

#[tokio::test]
async fn getwalletinfo_keeps_core_fields() {
    let v = info_json().await;
    for f in ["walletname", "walletversion", "format", "txcount", "keypoolsize",
              "private_keys_enabled", "avoid_reuse", "scanning", "descriptors"] {
        assert!(v.get(f).is_some(), "getwalletinfo lost Core field {f:?}");
    }
}
