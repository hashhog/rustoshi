//! sendrawtransaction / testmempoolaccept answer Core's -22 "TX decode failed"
//! for non-hex, empty and truncated tx hex (Core rpc/rawtransaction.cpp
//! sendrawtransaction, rpc/mempool.cpp testmempoolaccept).

use std::sync::Arc;

use rustoshi_primitives::{Encodable, Hash256, OutPoint, Transaction, TxIn, TxOut};
use rustoshi_rpc::{PeerState, RpcServerImpl, RpcState, RustoshiRpcServer};
use rustoshi_storage::ChainDb;
use tokio::sync::RwLock;

const RPC_DESERIALIZATION_ERROR: i32 = -22;
const SEND_MSG: &str = "TX decode failed. Make sure the tx has at least one input.";

fn server() -> RpcServerImpl {
    let tmp = tempfile::tempdir().expect("tempdir");
    let db = Arc::new(ChainDb::open(tmp.path()).expect("open db"));
    let state = Arc::new(RwLock::new(RpcState::new(
        db,
        rustoshi_consensus::ChainParams::regtest(),
    )));
    let peer_state = Arc::new(RwLock::new(PeerState::default()));
    RpcServerImpl::new(state, peer_state)
}

fn tx_hex() -> String {
    let tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint { txid: Hash256([0xaa; 32]), vout: 0 },
            script_sig: vec![],
            sequence: 0xffff_fffd,
            witness: vec![vec![0x30; 71], vec![0x02; 33]],
        }],
        outputs: vec![TxOut { value: 50_000, script_pubkey: vec![0x00, 0x14].into_iter().chain([7u8; 20]).collect() }],
        lock_time: 0,
    };
    hex::encode(tx.serialize())
}

fn bad_inputs() -> Vec<String> {
    let h = tx_hex();
    vec!["zz".to_string(), String::new(), h[..h.len() - 20].to_string()]
}

#[tokio::test]
async fn sendrawtransaction_bad_hex_is_22_with_core_message() {
    let srv = server();
    for raw in bad_inputs() {
        let err = srv.send_raw_transaction(raw.clone(), None, None).await.expect_err("must fail");
        assert_eq!(err.code(), RPC_DESERIALIZATION_ERROR, "input {raw:?}: {}", err.message());
        assert_eq!(err.message(), SEND_MSG, "input {raw:?}");
    }
}

#[tokio::test]
async fn testmempoolaccept_bad_hex_is_22_with_core_message() {
    let srv = server();
    for raw in bad_inputs() {
        let err = srv.test_mempool_accept(vec![raw.clone()], None).await.expect_err("must fail");
        assert_eq!(err.code(), RPC_DESERIALIZATION_ERROR, "input {raw:?}: {}", err.message());
        assert_eq!(
            err.message(),
            format!("TX decode failed: {raw} Make sure the tx has at least one input."),
            "input {raw:?}"
        );
    }
}

#[tokio::test]
async fn valid_tx_hex_passes_the_decode_gate() {
    let srv = server();
    if let Err(e) = srv.send_raw_transaction(tx_hex(), None, None).await {
        assert_ne!(e.code(), RPC_DESERIALIZATION_ERROR, "message: {}", e.message());
    }
    if let Err(e) = srv.test_mempool_accept(vec![tx_hex()], None).await {
        assert_ne!(e.code(), RPC_DESERIALIZATION_ERROR, "message: {}", e.message());
    }
}
