//! scantxoutset `unspents[].desc` must be Core's InferDescriptor of the
//! coin's own scriptPubKey (`addr(...)#csum` / `raw(...)#csum`), not the scan
//! object string the caller passed (rpc/blockchain.cpp scantxoutset).

use rustoshi_consensus::ChainParams;
use rustoshi_primitives::{Hash256, OutPoint};
use rustoshi_rpc::server::{PeerState, RpcServerImpl, RpcState, RustoshiRpcServer};
use rustoshi_storage::block_store::CoinEntry;
use rustoshi_storage::{BlockStore, ChainDb};
use std::sync::Arc;
use tokio::sync::RwLock;

// P2SH: OP_HASH160 <20 bytes> OP_EQUAL. Core infers addr(2N...)#csum on regtest.
const P2SH_SPK: &str = "a914da1745e9b549bd0bfa1a569971c77eba30cd5a4b87";
const P2SH_ADDR: &str = "2ND8PB9RrfCaAcjfjP1Y6nAgFd9zWHYX4DN";
const P2SH_DESC: &str = "addr(2ND8PB9RrfCaAcjfjP1Y6nAgFd9zWHYX4DN)#pn0u88a8";

async fn scan(scanobject: &str) -> serde_json::Value {
    let tmp = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDb::open(tmp.path()).unwrap());
    let tip = Hash256([7u8; 32]);
    {
        let store = BlockStore::new(&db);
        store.put_height_index(1, &tip).unwrap();
        store.set_best_block(&tip, 1).unwrap();
        let op = OutPoint { txid: Hash256([9u8; 32]), vout: 0 };
        store
            .put_utxo(
                &op,
                &CoinEntry {
                    height: 1,
                    is_coinbase: false,
                    value: 5_000,
                    script_pubkey: hex::decode(P2SH_SPK).unwrap(),
                },
            )
            .unwrap();
    }
    let state = Arc::new(RwLock::new(RpcState::new(db, ChainParams::regtest())));
    let server = RpcServerImpl::new(state, Arc::new(RwLock::new(PeerState::default())));
    let module = server.into_rpc();
    let req = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "scantxoutset",
        "params": ["start", [scanobject]],
    })
    .to_string();
    let (resp, _) = module.raw_json_request(&req, 1).await.expect("dispatch");
    serde_json::from_str(&resp).unwrap()
}

#[tokio::test]
async fn scantxoutset_desc_for_raw_scanobject_is_inferred_addr() {
    let r = scan(&format!("raw({P2SH_SPK})")).await;
    assert_eq!(r["result"]["unspents"][0]["desc"], P2SH_DESC, "{r}");
}

#[tokio::test]
async fn scantxoutset_desc_for_addr_scanobject_keeps_checksum() {
    let r = scan(&format!("addr({P2SH_ADDR})")).await;
    assert_eq!(r["result"]["unspents"][0]["desc"], P2SH_DESC, "{r}");
}
