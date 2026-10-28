//! Strict raw-tx decode shared by decoderawtransaction, sendrawtransaction and
//! testmempoolaccept (Core `core_io.cpp::DecodeTx` / `DecodeHexTx`).
//!
//! Core answers -22 "TX decode failed" when (a) the hex has trailing bytes
//! (a decode only counts if it consumes the whole input) and (b)
//! decoderawtransaction is given iswitness=false for a segwit-serialized tx
//! (only the legacy parse is tried, and it fails).

use std::sync::Arc;

use rustoshi_primitives::{Encodable, Hash256, OutPoint, Transaction, TxIn, TxOut};
use rustoshi_rpc::{PeerState, RpcServerImpl, RpcState, RustoshiRpcServer};
use rustoshi_storage::ChainDb;
use tokio::sync::RwLock;

const RPC_DESERIALIZATION_ERROR: i32 = -22;

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

fn segwit_tx_hex() -> String {
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

fn legacy_tx_hex() -> String {
    let tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint { txid: Hash256([0xbb; 32]), vout: 1 },
            script_sig: vec![0x51],
            sequence: 0xffff_ffff,
            witness: vec![],
        }],
        outputs: vec![TxOut { value: 1_000, script_pubkey: vec![0x51] }],
        lock_time: 0,
    };
    hex::encode(tx.serialize())
}

fn assert_decode_failed(err: jsonrpsee::types::ErrorObjectOwned) {
    assert_eq!(err.code(), RPC_DESERIALIZATION_ERROR, "message: {}", err.message());
    assert!(err.message().contains("TX decode failed"), "message: {}", err.message());
}

#[tokio::test]
async fn decoderawtransaction_accepts_whole_tx() {
    let srv = server();
    srv.decode_raw_transaction(serde_json::json!(segwit_tx_hex()), None).await.expect("segwit");
    srv.decode_raw_transaction(serde_json::json!(legacy_tx_hex()), None).await.expect("legacy");
    srv.decode_raw_transaction(serde_json::json!(legacy_tx_hex()), Some(serde_json::json!(false)))
        .await
        .expect("legacy with iswitness=false");
    srv.decode_raw_transaction(serde_json::json!(segwit_tx_hex()), Some(serde_json::json!(true)))
        .await
        .expect("segwit with iswitness=true");
}

#[tokio::test]
async fn decoderawtransaction_trailing_byte_is_22() {
    let srv = server();
    for h in [segwit_tx_hex(), legacy_tx_hex()] {
        let err = srv
            .decode_raw_transaction(serde_json::json!(format!("{h}00")), None)
            .await
            .expect_err("trailing byte must fail");
        assert_decode_failed(err);
    }
}

#[tokio::test]
async fn decoderawtransaction_segwit_iswitness_false_is_22() {
    let srv = server();
    let err = srv
        .decode_raw_transaction(serde_json::json!(segwit_tx_hex()), Some(serde_json::json!(false)))
        .await
        .expect_err("iswitness=false on a segwit tx must fail");
    assert_decode_failed(err);
}

#[tokio::test]
async fn sendrawtransaction_trailing_byte_is_22() {
    let srv = server();
    for h in [segwit_tx_hex(), legacy_tx_hex()] {
        let err = srv
            .send_raw_transaction(format!("{h}00"), None, None)
            .await
            .expect_err("trailing byte must fail");
        assert_decode_failed(err);
    }
}

#[tokio::test]
async fn testmempoolaccept_trailing_byte_is_22() {
    let srv = server();
    for h in [segwit_tx_hex(), legacy_tx_hex()] {
        let err = srv
            .test_mempool_accept(serde_json::json!([format!("{h}00")]), None)
            .await
            .expect_err("trailing byte must fail");
        assert_decode_failed(err);
    }
}

#[tokio::test]
async fn whole_tx_passes_the_decode_gate_in_send_and_testmempoolaccept() {
    // The tx has no inputs in the (empty) UTXO set, so it is rejected later;
    // the point is that the failure is NOT the -22 decode failure.
    let srv = server();
    if let Err(e) = srv.send_raw_transaction(segwit_tx_hex(), None, None).await {
        assert_ne!(e.code(), RPC_DESERIALIZATION_ERROR, "message: {}", e.message());
    }
    if let Err(e) = srv.test_mempool_accept(serde_json::json!([segwit_tx_hex()]), None).await {
        assert_ne!(e.code(), RPC_DESERIALIZATION_ERROR, "message: {}", e.message());
    }
}
