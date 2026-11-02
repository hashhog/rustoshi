//! Two wallet differences the submitblock wallet scan exposed in the Core
//! regtest wallet group:
//!
//! 1. `gettransaction.details` for a confirmed wallet send. Core's
//!    `CachedTxGetAmounts` (`wallet/receive.cpp`) skips an `IsChange` output
//!    entirely when the wallet funded the tx (`nDebit > 0`), before either the
//!    `listSent` or the `listReceived` push. A 1 BTC self-payment with change
//!    therefore has exactly `[receive 1.0, send -1.0]`; the change gets no line.
//! 2. `getbalances.mine.trusted` / `getwalletinfo.balance`. Core's
//!    `GetBalance` puts immature coinbase only in `immature`, never in
//!    `trusted`.

use crate::wallet::{WalletRpcImpl, WalletRpcServer, WalletRpcState};
use rustoshi_crypto::address::{Address, Network};
use rustoshi_primitives::{Hash256, OutPoint, Transaction, TxIn, TxOut};
use rustoshi_wallet::{CreateWalletOptions, WalletManager, WalletUtxo};
use std::sync::Arc;
use tokio::sync::RwLock;

fn spk(addr: &str) -> Vec<u8> {
    Address::from_string(addr, Some(Network::Regtest))
        .unwrap()
        .to_script_pubkey()
}

#[test]
fn confirmed_send_with_change_details_skip_change() {
    let dir = tempfile::tempdir().unwrap();
    let mut manager = WalletManager::new(dir.path(), Network::Regtest).unwrap();
    manager.create_wallet("w", CreateWalletOptions::default()).unwrap();
    let wallet = manager.get_wallet("w").unwrap();
    let mut w = wallet.lock().unwrap();

    let recv = w.get_new_address().unwrap();
    let dest = w.get_new_address().unwrap();
    let change = w.get_change_address().unwrap();

    // A mature 50 BTC wallet coin to spend.
    let funding = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint { txid: Hash256([7; 32]), vout: 0 },
            script_sig: vec![],
            sequence: 0xFFFF_FFFF,
            witness: vec![],
        }],
        outputs: vec![TxOut { value: 50_0000_0000, script_pubkey: spk(&recv) }],
        lock_time: 0,
    };
    w.scan_block_at(&[funding.clone()], 1, Hash256::ZERO, 0);

    // 1 BTC to the wallet's own (non-change) address, 48.9999 BTC change,
    // 0.0001 BTC fee.
    let send = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint { txid: funding.txid(), vout: 0 },
            script_sig: vec![],
            sequence: 0xFFFF_FFFD,
            witness: vec![],
        }],
        outputs: vec![
            TxOut { value: 1_0000_0000, script_pubkey: spk(&dest) },
            TxOut { value: 48_9999_0000, script_pubkey: spk(&change) },
        ],
        lock_time: 0,
    };
    w.scan_block_at(&[send.clone()], 2, Hash256::ZERO, 0);

    let entry = w
        .history()
        .iter()
        .find(|e| e.txid == send.txid())
        .expect("send recorded in history");
    let mut details: Vec<(String, i64, u32)> = entry
        .details
        .iter()
        .map(|d| (d.category.clone(), d.amount_sats, d.vout))
        .collect();
    details.sort();
    assert_eq!(
        details,
        vec![
            ("receive".to_string(), 1_0000_0000, 0),
            ("send".to_string(), -1_0000_0000, 0),
        ],
        "change output must get no details line on a wallet-funded tx"
    );
    assert_eq!(entry.fee_sats, Some(1_0000));
}

#[test]
fn received_payment_to_change_address_still_listed() {
    // Not funded by the wallet (debit 0): Core lists every IsMine output as
    // receive, change-branch or not. Guards the skip against over-reach.
    let dir = tempfile::tempdir().unwrap();
    let mut manager = WalletManager::new(dir.path(), Network::Regtest).unwrap();
    manager.create_wallet("w", CreateWalletOptions::default()).unwrap();
    let wallet = manager.get_wallet("w").unwrap();
    let mut w = wallet.lock().unwrap();
    let change = w.get_change_address().unwrap();
    let tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint { txid: Hash256([9; 32]), vout: 0 },
            script_sig: vec![],
            sequence: 0xFFFF_FFFF,
            witness: vec![],
        }],
        outputs: vec![TxOut { value: 2_0000_0000, script_pubkey: spk(&change) }],
        lock_time: 0,
    };
    w.scan_block_at(&[tx.clone()], 1, Hash256::ZERO, 0);
    let entry = w.history().iter().find(|e| e.txid == tx.txid()).unwrap();
    assert_eq!(entry.details.len(), 1);
    assert_eq!(entry.details[0].category, "receive");
    assert_eq!(entry.details[0].amount_sats, 2_0000_0000);
}

fn coin(n: u8, coinbase: bool, confirmations: u32, height: u32) -> WalletUtxo {
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

async fn balance_rpc() -> WalletRpcImpl {
    let dir = tempfile::tempdir().unwrap();
    let mut manager = WalletManager::new(dir.path(), Network::Regtest).unwrap();
    manager.create_wallet("w", CreateWalletOptions::default()).unwrap();
    {
        let wallet = manager.get_wallet("w").unwrap();
        let mut w = wallet.lock().unwrap();
        w.set_chain_height(200);
        // immature coinbase (100 confirmations)
        w.add_utxo(coin(1, true, 100, 101));
        // mature coinbase (101 confirmations)
        w.add_utxo(coin(2, true, 101, 100));
    }
    let state = Arc::new(RwLock::new(WalletRpcState::new(manager, dir.keep())));
    WalletRpcImpl::new(state)
}

#[tokio::test]
async fn getbalances_trusted_excludes_immature_coinbase() {
    let rpc = balance_rpc().await;
    let b = rpc.get_balances(None).await.unwrap();
    let mine = b.mine.unwrap();
    assert_eq!(mine.trusted, 50.0, "only the mature coinbase is trusted");
    assert_eq!(mine.immature, 50.0);
}

#[tokio::test]
async fn getwalletinfo_balance_excludes_immature_coinbase() {
    let rpc = balance_rpc().await;
    let info = rpc.get_wallet_info(None).await.unwrap();
    assert_eq!(info.balance, 50.0, "only the mature coinbase counts");
    assert_eq!(info.immature_balance, 50.0);
}
