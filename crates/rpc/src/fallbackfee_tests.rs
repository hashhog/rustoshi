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

/// `-fallbackfee=0.0002` (20 sat/vB, what Core's regtest functional tests
/// pass): with no estimate the spend goes through at that rate.
#[tokio::test]
async fn sendtoaddress_pays_fallbackfee_when_set() {
    let (state, mut wallet_state) = funded_wallet().await;
    wallet_state.fallback_fee_sat_kvb = 20_000;
    let rpc = WalletRpcImpl::new(Arc::new(RwLock::new(wallet_state)));

    // The no-input fee is 42 vB at the fallback rate: 840 sat.
    let exact = send(&rpc, serde_json::json!(0.001))
        .await
        .expect_err("the whole coin cannot also pay the fee");
    assert_eq!(exact.code(), -6, "{exact:?}");
    assert_eq!(
        exact.message(),
        "The total exceeds your balance when the 0.0000084 transaction fee is included.",
        "{exact:?}"
    );

    let txid_hex = send(&rpc, serde_json::json!(0.0005))
        .await
        .expect("fallback fee set: the spend goes through");
    let mut txid = [0u8; 32];
    txid.copy_from_slice(&hex::decode(&txid_hex).unwrap());
    txid.reverse();
    let st = state.read().await;
    let entry = st
        .mempool
        .get(&Hash256::from(txid))
        .expect("broadcast into the mempool");
    let rate = entry.fee as f64 / entry.vsize as f64;
    assert!(
        (20.0..21.0).contains(&rate),
        "fee {} over {} vB",
        entry.fee,
        entry.vsize
    );
}

/// `GetMinimumFeeRate` precedence: an estimate wins over the fallback (and is
/// used even with the fallback disabled), only a missing estimate consults
/// the fallback, and the result is floored at the mempool minimum and at
/// `max(-mintxfee, -minrelaytxfee)`.
#[test]
fn wallet_fee_rate_follows_core_precedence() {
    let rate = WalletRpcImpl::wallet_fee_rate_sat_vb;
    // No estimate: fallback disabled refuses, fallback set is used.
    assert_eq!(rate(None, 0, 100, 100), None);
    assert_eq!(rate(None, 20_000, 100, 100), Some(20.0));
    // An estimate is used whatever the fallback says.
    assert_eq!(rate(Some(12.0), 0, 100, 100), Some(12.0));
    assert_eq!(rate(Some(12.0), 20_000, 100, 100), Some(12.0));
    // Mempool minimum floors the estimate and the fallback.
    assert_eq!(rate(Some(2.0), 0, 3_000, 100), Some(3.0));
    assert_eq!(rate(None, 2_000, 3_000, 100), Some(3.0));
    // -mintxfee (1000 sat/kvB) floors a low estimate or fallback; a higher
    // -minrelaytxfee raises that floor.
    assert_eq!(rate(Some(0.5), 0, 100, 100), Some(1.0));
    assert_eq!(rate(None, 500, 100, 100), Some(1.0));
    assert_eq!(rate(None, 500, 100, 2_000), Some(2.0));
}
