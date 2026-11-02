//! `submitblock` must feed the connected block to the loaded wallets, as
//! Core's `CWallet::blockConnected` does for every ConnectTip. The Core
//! regtest wallet group builds each side's chain with `submitblock`, pays the
//! coinbases to the wallet's own address, then expects `getbalance` = 50 and a
//! working `sendtoaddress`. Before the fix rustoshi's submitblock connect path
//! never scanned the block, so the wallet stayed empty ("Insufficient funds").

use crate::server::{PeerState, RpcServerImpl, RpcState, RustoshiRpcServer};
use crate::wallet::WalletRpcState;
use rustoshi_consensus::ChainParams;
use rustoshi_crypto::address::{Address, Network};
use rustoshi_primitives::Encodable;
use rustoshi_primitives::{Block, BlockHeader, Hash256, OutPoint, Transaction, TxIn, TxOut};
use rustoshi_storage::{BlockStore, ChainDb};
use rustoshi_wallet::{CreateWalletOptions, WalletManager};
use std::sync::Arc;
use tokio::sync::RwLock;

fn params() -> ChainParams {
    let mut p = ChainParams::mainnet();
    let mut limit = [0xffu8; 32];
    limit[0] = 0x7f;
    p.pow_limit = limit;
    p.genesis_block.header.bits = 0x207fffff;
    p.genesis_hash = p.genesis_block.block_hash();
    p
}

fn mine(h: u32, prev: Hash256, spk: Vec<u8>) -> Block {
    let coinbase = Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint { txid: Hash256::ZERO, vout: u32::MAX },
            script_sig: vec![0x5a, 0x5a, h as u8, (h >> 8) as u8],
            sequence: 0xFFFF_FFFF,
            witness: vec![],
        }],
        outputs: vec![TxOut { value: 50_0000_0000, script_pubkey: spk }],
        lock_time: 0,
    };
    let mut block = Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: prev,
            merkle_root: coinbase.txid(),
            timestamp: 1_700_000_000 + h,
            bits: 0x207fffff,
            nonce: 0,
        },
        transactions: vec![coinbase],
    };
    while !block.header.validate_pow_against_declared_target() {
        block.header.nonce += 1;
    }
    block
}

#[tokio::test]
async fn submitblock_credits_coinbase_to_loaded_wallet() {
    let params = params();
    let tmp = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDb::open(tmp.path()).unwrap());
    let store = BlockStore::new(&db);
    store.init_genesis(&params).unwrap();
    let mut rpc_state = RpcState::new(db.clone(), params.clone());
    rpc_state.best_hash = store.get_best_block_hash().unwrap().unwrap();
    rpc_state.best_height = store.get_best_height().unwrap().unwrap();
    rpc_state.data_dir = Some(tmp.path().to_path_buf());

    let wdir = tempfile::tempdir().unwrap();
    let mut manager = WalletManager::new(wdir.path(), Network::Regtest).unwrap();
    manager.create_wallet("w", CreateWalletOptions::default()).unwrap();
    let wallet = manager.get_wallet("w").unwrap();
    let addr = wallet.lock().unwrap().get_new_address().unwrap();
    let spk = Address::from_string(&addr, Some(Network::Regtest))
        .unwrap()
        .to_script_pubkey();
    rpc_state.wallet_state = Some(Arc::new(RwLock::new(WalletRpcState::new(
        manager,
        wdir.path().to_path_buf(),
    ))));

    let state = Arc::new(RwLock::new(rpc_state));
    let server = RpcServerImpl::new(state.clone(), Arc::new(RwLock::new(PeerState::default())));

    let block = mine(1, params.genesis_hash, spk);
    let res = server
        .submit_block(hex::encode(block.serialize()))
        .await
        .expect("submitblock rpc ok");
    assert!(res.is_none(), "block must be accepted, got {res:?}");

    let w = wallet.lock().unwrap();
    assert_eq!(
        w.balance(),
        50_0000_0000,
        "wallet must hold the coinbase paid to its address"
    );
}
