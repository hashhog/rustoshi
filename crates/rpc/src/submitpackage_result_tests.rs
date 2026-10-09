//! `submitpackage` result shape against Bitcoin Core v31.1 `rpc/mempool.cpp`.
//!
//! Rejected `tx-results` entries carry `error` and omit `vsize` / `fees`.
//! An already-in-mempool member keeps `vsize` and `fees.base` and omits
//! `effective-feerate` / `effective-includes`. A non-standard child does not
//! evict a parent that was valid on its own (`rpc_packages.py`).

use crate::server::{PeerState, RpcServerImpl, RpcState, RustoshiRpcServer};
use rustoshi_consensus::ChainParams;
use rustoshi_primitives::{Encodable, Hash256, OutPoint, Transaction, TxIn, TxOut};
use rustoshi_storage::{BlockStore, ChainDb};
use std::sync::Arc;
use tokio::sync::RwLock;

fn p2sh_true() -> Vec<u8> {
    let h = rustoshi_crypto::hash160(&[0x51]);
    let mut s = vec![0xa9, 0x14];
    s.extend_from_slice(&h.0);
    s.push(0x87);
    s
}

fn spend(prev: OutPoint, value: u64, fee: u64) -> Transaction {
    Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: prev,
            script_sig: vec![0x01, 0x51],
            sequence: 0xffff_ffff,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value: value - fee,
            script_pubkey: p2sh_true(),
        }],
        lock_time: 0,
    }
}

fn hex_tx(tx: &Transaction) -> String {
    let mut buf = Vec::new();
    tx.encode(&mut buf).unwrap();
    hex::encode(buf)
}

fn server() -> (Arc<RwLock<RpcState>>, RpcServerImpl) {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().to_path_buf();
    std::mem::forget(tmp);
    let db = Arc::new(ChainDb::open(&path).unwrap());
    let state = Arc::new(RwLock::new(RpcState::new(db, ChainParams::regtest())));
    let peer_state = Arc::new(RwLock::new(PeerState::default()));
    let server = RpcServerImpl::new(state.clone(), peer_state);
    (state, server)
}

async fn call(
    state: &Arc<RwLock<RpcState>>,
    method: &str,
    params: serde_json::Value,
) -> serde_json::Value {
    let server = RpcServerImpl::new(state.clone(), Arc::new(RwLock::new(PeerState::default())));
    let module = server.into_rpc();
    let req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "pkg",
        "method": method,
        "params": params,
    })
    .to_string();
    let (resp, _) = module.raw_json_request(&req, 1).await.expect("dispatch");
    serde_json::from_str(&resp).expect("json response")
}

fn result(resp: serde_json::Value) -> serde_json::Value {
    assert!(
        resp.get("error").map(|e| e.is_null()).unwrap_or(true),
        "expected success, got {resp}"
    );
    resp["result"].clone()
}

struct Funded {
    state: Arc<RwLock<RpcState>>,
    parent: Transaction,
    child: Transaction,
}

async fn funded(parent_fee: u64, child_fee: u64) -> Funded {
    let (state, _server) = server();
    let prev = OutPoint {
        txid: Hash256::from([0x11u8; 32]),
        vout: 0,
    };
    let value = 1_000_000u64;
    {
        let mut st = state.write().await;
        BlockStore::new(&st.db)
            .put_utxo(
                &prev,
                &rustoshi_storage::CoinEntry {
                    height: 1,
                    is_coinbase: false,
                    value,
                    script_pubkey: p2sh_true(),
                },
            )
            .unwrap();
        st.mempool.notify_new_tip(200, 1_700_000_000);
    }
    let parent = spend(prev, value, parent_fee);
    let child = spend(
        OutPoint {
            txid: parent.txid(),
            vout: 0,
        },
        value - parent_fee,
        child_fee,
    );
    Funded {
        state,
        parent,
        child,
    }
}

fn entry<'a>(res: &'a serde_json::Value, wtxid: &str) -> &'a serde_json::Value {
    res["tx-results"]
        .get(wtxid)
        .unwrap_or_else(|| panic!("missing {wtxid} in {res}"))
}

/// Bad-version child: parent result keeps vsize/fees and has no error; the
/// child has `error` and no vsize/fees. Parent remains in the mempool.
#[tokio::test]
async fn submitpackage_partial_version_child_result_shape() {
    let f = funded(10_000, 10_000).await;
    let mut child = f.child.clone();
    child.version = 0x7fff_ffff;
    let res = result(
        call(
            &f.state,
            "submitpackage",
            serde_json::json!([[hex_tx(&f.parent), hex_tx(&child)]]),
        )
        .await,
    );
    assert_eq!(res["package_msg"], "transaction failed");

    let parent = entry(&res, &f.parent.wtxid().to_hex());
    assert!(parent.get("error").is_none(), "{parent}");
    assert!(parent.get("vsize").is_some(), "{parent}");
    assert!(parent["fees"].get("base").is_some(), "{parent}");

    let child_res = entry(&res, &child.wtxid().to_hex());
    assert_eq!(child_res["error"], "version");
    assert!(child_res.get("vsize").is_none(), "{child_res}");
    assert!(child_res.get("fees").is_none(), "{child_res}");

    let pool = result(call(&f.state, "getrawmempool", serde_json::json!([false])).await);
    let txids: Vec<String> = serde_json::from_value(pool).unwrap();
    assert!(txids.contains(&f.parent.txid().to_hex()));
    assert!(!txids.contains(&child.txid().to_hex()));
}

/// Resubmitting a tx that is already in the mempool omits effective-feerate.
#[tokio::test]
async fn submitpackage_already_in_mempool_omits_effective_feerate() {
    let f = funded(10_000, 10_000).await;
    let first = result(
        call(
            &f.state,
            "submitpackage",
            serde_json::json!([[hex_tx(&f.parent)]]),
        )
        .await,
    );
    assert_eq!(first["package_msg"], "success");

    let second = result(
        call(
            &f.state,
            "submitpackage",
            serde_json::json!([[hex_tx(&f.parent), hex_tx(&f.child)]]),
        )
        .await,
    );
    assert_eq!(second["package_msg"], "success");
    let parent = entry(&second, &f.parent.wtxid().to_hex());
    assert!(parent.get("error").is_none(), "{parent}");
    assert!(parent.get("vsize").is_some(), "{parent}");
    assert!(parent["fees"].get("base").is_some(), "{parent}");
    assert!(
        parent["fees"].get("effective-feerate").is_none(),
        "MEMPOOL_ENTRY omits effective-feerate: {parent}"
    );
    assert!(
        parent["fees"].get("effective-includes").is_none(),
        "MEMPOOL_ENTRY omits effective-includes: {parent}"
    );
}

/// Valid CPFP: both results report one package feerate and both wtxids.
#[tokio::test]
async fn submitpackage_valid_cpfp_effective_feerate_is_package_rate() {
    let f = funded(1, 20_000).await;
    let res = result(
        call(
            &f.state,
            "submitpackage",
            serde_json::json!([[hex_tx(&f.parent), hex_tx(&f.child)]]),
        )
        .await,
    );
    assert_eq!(res["package_msg"], "success");
    let parent = entry(&res, &f.parent.wtxid().to_hex());
    let child = entry(&res, &f.child.wtxid().to_hex());
    assert_eq!(
        parent["fees"]["effective-feerate"],
        child["fees"]["effective-feerate"]
    );
    let includes = serde_json::json!([f.parent.wtxid().to_hex(), f.child.wtxid().to_hex()]);
    assert_eq!(parent["fees"]["effective-includes"], includes);
    assert_eq!(child["fees"]["effective-includes"], includes);

    let pool = result(call(&f.state, "getrawmempool", serde_json::json!([false])).await);
    let txids: Vec<String> = serde_json::from_value(pool).unwrap();
    assert!(txids.contains(&f.parent.txid().to_hex()));
    assert!(txids.contains(&f.child.txid().to_hex()));
}
