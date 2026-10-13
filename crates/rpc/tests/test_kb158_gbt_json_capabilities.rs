//! KB-158: `getblocktemplate` template mode must include Core's `capabilities`
//! key. Bitcoin Core v31.1 (`src/rpc/mining.cpp`) always pushes
//! `"capabilities": ["proposal"]` before `version`.
//!
//! Fixture copied from `test_gbt_sigops_verbose_mempool.rs`. The check reads
//! the JSON object the RPC returns. It does not name a Rust struct field, so
//! a build that has not added the key fails this assertion.

use std::sync::Arc;

use rustoshi_consensus::ChainParams;
use rustoshi_rpc::{PeerState, RpcServerImpl, RpcState, RustoshiRpcServer};
use rustoshi_storage::ChainDb;
use serde_json::json;
use tokio::sync::RwLock;

async fn fixture() -> (RpcServerImpl, Arc<RwLock<RpcState>>) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let db = Arc::new(ChainDb::open(tmp.path()).expect("db"));
    // Leak the tempdir for the test process; the db must outlive the guard.
    std::mem::forget(tmp);
    let state = Arc::new(RwLock::new(RpcState::new(db, ChainParams::regtest())));
    let peers = Arc::new(RwLock::new(PeerState::default()));
    let rpc = RpcServerImpl::new(state.clone(), peers);
    (rpc, state)
}

#[tokio::test]
async fn test_kb158_gbt_json_missing_capabilities_key() {
    let (rpc, _state) = fixture().await;
    let result = rpc
        .get_block_template(Some(json!({"rules": ["segwit"]})))
        .await
        .expect("getblocktemplate");
    // Value the RPC already returns; `to_value` keeps the check on JSON keys.
    let v = serde_json::to_value(&result).expect("serde_json::Value");
    let obj = v.as_object().unwrap();
    assert!(
        obj.contains_key("capabilities"),
        "getblocktemplate missing `capabilities` key (KB-158): keys={:?}",
        obj.keys().collect::<Vec<_>>()
    );
    assert_eq!(obj["capabilities"], json!(["proposal"]));
}
