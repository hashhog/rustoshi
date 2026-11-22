//! `getnewaddress` and `walletcreatefundedpsbt` change derivation on a
//! locked encrypted wallet must not return addresses of the all-zero
//! placeholder seed. They refuse with Core's RPC_WALLET_UNLOCK_NEEDED (-13)
//! "Error: Please enter the wallet passphrase with walletpassphrase first.".
//! See `crates/wallet/tests/test_cffix_locked_placeholder.rs` for the
//! wallet-level tests.

use rustoshi_crypto::address::Network;
use rustoshi_rpc::{WalletRpcImpl, WalletRpcServer, WalletRpcState};
use rustoshi_wallet::{AddressType, Wallet, WalletManager};
use std::sync::Arc;
use tokio::sync::RwLock;

const NET: Network = Network::Regtest;

async fn locked_rpc() -> (WalletRpcImpl, Vec<String>) {
    let dir = tempfile::tempdir().unwrap();
    let manager = WalletManager::new(dir.path(), NET).unwrap();
    let state = Arc::new(RwLock::new(WalletRpcState::new(manager, dir.keep())));
    let rpc = WalletRpcImpl::new(state);
    rpc.create_wallet(Some("enc".into()), None, None, Some("pw".into()), None, None, None)
        .await
        .unwrap();
    let mut real = Vec::new();
    for _ in 0..3 {
        real.push(rpc.get_new_address(None, None).await.unwrap());
    }
    rpc.wallet_lock().await.unwrap();
    (rpc, real)
}

fn zero_seed_receive(n: u32) -> Vec<String> {
    let mut z = Wallet::from_seed(&[0u8; 64], NET, AddressType::P2WPKH).unwrap();
    (0..n).map(|_| z.get_new_address().unwrap()).collect()
}

#[tokio::test]
async fn getnewaddress_on_locked_wallet_needs_unlock_not_zero_seed() {
    let (rpc, _real) = locked_rpc().await;
    let zero = zero_seed_receive(25);
    for kind in [None, Some("bech32"), Some("legacy"), Some("p2sh-segwit"), Some("bech32m")] {
        match rpc.get_new_address(None, kind.map(String::from)).await {
            Ok(a) => panic!(
                "getnewaddress({kind:?}) on a locked wallet returned {a} (zero-seed: {})",
                zero.contains(&a)
            ),
            Err(e) => {
                assert_eq!(e.code(), -13, "getnewaddress({kind:?}): {}", e.message());
                assert_eq!(
                    e.message(),
                    "Error: Please enter the wallet passphrase with walletpassphrase first."
                );
            }
        }
    }
}

/// Control: unlocking restores getnewaddress with an address the wallet
/// itself owns (`getaddressinfo ismine`), not a zero-seed one, so the -13
/// above is tied to the lock and not to encryption. Which index it resumes at
/// is not checked: walletlock rewinds the receive index to the last persisted
/// value, a separate pre-existing issue.
#[tokio::test]
async fn getnewaddress_after_unlock_is_real_again() {
    let (rpc, _real) = locked_rpc().await;
    let _ = rpc.get_new_address(None, None).await;
    rpc.wallet_passphrase("pw".into(), 60).await.unwrap();
    let a = rpc.get_new_address(None, None).await.unwrap();
    assert!(!zero_seed_receive(25).contains(&a), "unlocked wallet minted zero-seed {a}");
    let info = rpc.get_address_info(a.clone()).await.unwrap();
    assert_eq!(info["ismine"], serde_json::json!(true), "unlocked wallet does not own {a}: {info}");
}
