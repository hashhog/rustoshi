//! `listunspent` must not list immature coinbase outputs. Core's
//! `wallet/rpc/coins.cpp` ListUnspent filters through `AvailableCoins`, which
//! skips a coinbase whose `GetTxBlocksToMaturity` is above 0
//! (`wallet/spend.cpp`: `IsTxImmatureCoinBase && !include_immature_coinbase`),
//! unless the caller passes `query_options.include_immature_coinbase=true`.
//! A coinbase is mature at 101 confirmations (depth), i.e. `max(0, 101 - depth)`.

use crate::wallet::{WalletRpcServer, WalletRpcImpl, WalletRpcState};
use rustoshi_crypto::address::Network;
use rustoshi_primitives::{Hash256, OutPoint};
use rustoshi_wallet::{CreateWalletOptions, WalletManager, WalletUtxo};
use std::sync::Arc;
use tokio::sync::RwLock;

fn utxo(n: u8, coinbase: bool, confirmations: u32, height: u32) -> WalletUtxo {
    WalletUtxo {
        outpoint: OutPoint { txid: Hash256([n; 32]), vout: 0 },
        value: 50_0000_0000,
        script_pubkey: vec![],
        derivation_path: vec![],
        confirmations,
        is_change: false,
        is_coinbase: coinbase,
        height: Some(height),
    }
}

async fn setup() -> WalletRpcImpl {
    let dir = tempfile::tempdir().unwrap();
    let mut manager = WalletManager::new(dir.path(), Network::Regtest).unwrap();
    manager.create_wallet("w", CreateWalletOptions::default()).unwrap();
    {
        let wallet = manager.get_wallet("w").unwrap();
        let mut w = wallet.lock().unwrap();
        w.set_chain_height(200);
        // immature coinbase: 100 confirmations (depth 100 -> 1 block to maturity)
        w.add_utxo(utxo(1, true, 100, 101));
        // mature coinbase: 101 confirmations
        w.add_utxo(utxo(2, true, 101, 100));
        // ordinary coin
        w.add_utxo(utxo(3, false, 5, 196));
    }
    let state = Arc::new(RwLock::new(WalletRpcState::new(manager, dir.keep())));
    WalletRpcImpl::new(state)
}

fn txids(v: &[crate::wallet::UnspentOutput]) -> Vec<String> {
    let mut t: Vec<String> = v.iter().map(|u| u.txid.clone()).collect();
    t.sort();
    t
}

#[tokio::test]
async fn listunspent_skips_immature_coinbase() {
    let rpc = setup().await;
    let got = rpc.list_unspent(Some(0), None, None, None, None).await.unwrap();
    let mut want = vec![hex::encode([2u8; 32]), hex::encode([3u8; 32])];
    want.sort();
    assert_eq!(txids(&got), want, "immature coinbase (100 confs) must not be listed");
}

#[tokio::test]
async fn listunspent_include_immature_coinbase_option() {
    let rpc = setup().await;
    let opts = serde_json::json!({"include_immature_coinbase": true});
    let got = rpc
        .list_unspent(Some(0), None, None, None, Some(opts))
        .await
        .unwrap();
    assert_eq!(got.len(), 3, "include_immature_coinbase=true lists all three");
}
