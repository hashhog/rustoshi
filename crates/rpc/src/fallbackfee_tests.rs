//! `sendtoaddress` fee selection against Bitcoin Core v31.1
//! `wallet/fees.cpp` `GetMinimumFeeRate` and `wallet/spend.cpp`
//! `CreateTransactionInternal`.
//!
//! With no fee estimate and `-fallbackfee` unset (Core's default is 0, which
//! disables the fallback), Core refuses the spend with
//! "Fee estimation failed. Fallbackfee is disabled. Wait a few blocks or
//! enable -fallbackfee." at RPC_WALLET_INSUFFICIENT_FUNDS (-6). The recipient
//! dust check runs first, coin selection after.

use crate::server::{PeerState, RpcServerImpl, RpcState};
use crate::wallet::{WalletRpcImpl, WalletRpcServer, WalletRpcState};
use rustoshi_consensus::ChainParams;
use rustoshi_crypto::address::{Address, Network};
use rustoshi_primitives::{Hash256, OutPoint};
use rustoshi_storage::{BlockStore, ChainDb};
use rustoshi_wallet::{CreateWalletOptions, WalletManager, WalletUtxo};
use std::sync::Arc;
use tokio::sync::RwLock;

const FALLBACK_DISABLED: &str =
    "Fee estimation failed. Fallbackfee is disabled. Wait a few blocks or enable -fallbackfee.";
const DEST: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

fn node() -> Arc<RwLock<RpcState>> {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().to_path_buf();
    std::mem::forget(tmp);
    let db = Arc::new(ChainDb::open(&path).unwrap());
    let state = Arc::new(RwLock::new(RpcState::new(db, ChainParams::regtest())));
    let _ = RpcServerImpl::new(state.clone(), Arc::new(RwLock::new(PeerState::default())));
    state
}

/// A regtest wallet holding one confirmed 100_000-sat P2WPKH coin, wired to a
/// node whose UTXO set has that coin and whose fee estimator has no data.
async fn funded_wallet() -> (Arc<RwLock<RpcState>>, WalletRpcState) {
    let state = node();
    let dir = tempfile::tempdir().unwrap();
    let mut manager = WalletManager::new(dir.path(), Network::Regtest).unwrap();
    manager
        .create_wallet("fb", CreateWalletOptions::default())
        .unwrap();
    let utxo = {
        let arc = manager.get_wallet("fb").unwrap();
        let mut wallet = arc.lock().unwrap();
        wallet.set_chain_height(200);
        let addr = wallet.get_new_address().unwrap();
        let path = wallet.get_derivation_path(&addr).unwrap().clone();
        let spk = Address::from_string(&addr, Some(Network::Regtest))
            .unwrap()
            .to_script_pubkey();
        let utxo = WalletUtxo {
            outpoint: OutPoint {
                txid: Hash256::from([0xfb; 32]),
                vout: 0,
            },
            value: 100_000,
            script_pubkey: spk,
            derivation_path: path,
            confirmations: 10,
            is_change: false,
            is_coinbase: false,
            height: Some(100),
        };
        wallet.add_utxo(utxo.clone());
        utxo
    };
    {
        let mut st = state.write().await;
        BlockStore::new(&st.db)
            .put_utxo(
                &utxo.outpoint,
                &rustoshi_storage::CoinEntry {
                    height: 1,
                    is_coinbase: false,
                    value: utxo.value,
                    script_pubkey: utxo.script_pubkey.clone(),
                },
            )
            .unwrap();
        st.mempool.notify_new_tip(200, 1_700_000_000);
    }
    let mut wallet_state = WalletRpcState::new(manager, dir.keep());
    wallet_state.node = Some(state.clone());
    (state, wallet_state)
}

async fn send(
    rpc: &WalletRpcImpl,
    amount: serde_json::Value,
) -> jsonrpsee::core::RpcResult<String> {
    rpc.send_to_address(DEST.into(), amount, None, None, None, None, None, None)
        .await
}

/// No estimate, no `-fallbackfee`: Core refuses instead of picking a fee.
/// The dust check still answers first, and nothing reaches the mempool.
#[tokio::test]
async fn sendtoaddress_without_fallbackfee_fails_like_core() {
    let (state, wallet_state) = funded_wallet().await;
    let rpc = WalletRpcImpl::new(Arc::new(RwLock::new(wallet_state)));

    let dust = send(&rpc, serde_json::json!(0.00000001))
        .await
        .expect_err("dust is refused before the fee is chosen");
    assert_eq!(dust.code(), -6, "{dust:?}");
    assert_eq!(dust.message(), "Transaction amount too small", "{dust:?}");

    let err = send(&rpc, serde_json::json!(0.0005))
        .await
        .expect_err("no estimate and no -fallbackfee must refuse the spend");
    assert_eq!(err.code(), -6, "{err:?}");
    assert_eq!(err.message(), FALLBACK_DISABLED, "{err:?}");

    // Fee estimation fails before coin selection, so an amount the wallet
    // cannot cover gets the same answer, not "Insufficient funds".
    let err = send(&rpc, serde_json::json!(1.0))
        .await
        .expect_err("fee estimation fails before coin selection");
    assert_eq!(err.code(), -6, "{err:?}");
    assert_eq!(err.message(), FALLBACK_DISABLED, "{err:?}");

    assert_eq!(
        state.read().await.mempool.size(),
        0,
        "nothing was broadcast"
    );
}
