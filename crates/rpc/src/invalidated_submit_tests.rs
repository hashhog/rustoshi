//! submitblock of an invalidated block, and reconsiderblock = ActivateBestChain
//! (fleet conformance INV-SUBMIT / INV-RECONSIDER, 2026-10-08).
//!
//! Core: `submitblock` of a block whose index entry is BLOCK_FAILED_* answers
//! "duplicate-invalid" and never reconnects it (validation.cpp
//! AcceptBlockHeader -> BLOCK_CACHED_INVALID; rpc/mining.cpp submitblock ->
//! BIP22ValidationResult); a child of a failed block answers "bad-prevblk";
//! a block already on the active chain answers "duplicate". `reconsiderblock`
//! clears the flags (ResetBlockFailureFlags) and calls ActivateBestChain, so
//! the tip is back on the most-work chain before the RPC returns.
//!
//! Deployed 14ea3bb0: the invalidated block N was the direct child of the
//! rewound tip, so submitblock's crash/ENOSPC repair branch reconnected it
//! (answer null, tip N); reconsiderblock only cleared the flags (tip stayed
//! at N-1).

use crate::server::{PeerState, RpcServerImpl, RpcState, RustoshiRpcServer};
use rustoshi_consensus::ChainParams;
use rustoshi_primitives::{Block, BlockHeader, Encodable, Hash256, OutPoint, Transaction, TxIn, TxOut};
use rustoshi_storage::{BlockStore, ChainDb};
use std::sync::Arc;
use tokio::sync::RwLock;

const BASE_TIME: u32 = 1_700_000_000;

fn coinbase(h: u32) -> Transaction {
    // BIP34 height push (heights here are <= 16) + a marker byte.
    Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint { txid: Hash256::ZERO, vout: u32::MAX },
            script_sig: vec![0x50 + h as u8, 0x01, 0xC5],
            sequence: 0xFFFF_FFFF,
            witness: vec![],
        }],
        outputs: vec![TxOut { value: 50 * 100_000_000, script_pubkey: vec![0x51] }],
        lock_time: 0,
    }
}

fn mine(h: u32, prev: Hash256) -> Block {
    let mut block = Block {
        header: BlockHeader {
            version: 0x2000_0000,
            prev_block_hash: prev,
            merkle_root: Hash256::ZERO,
            timestamp: BASE_TIME + h * 600,
            bits: 0x207f_ffff,
            nonce: 0,
        },
        transactions: vec![coinbase(h)],
    };
    block.header.merkle_root = block.compute_merkle_root();
    while !block.header.validate_pow_against_declared_target() {
        block.header.nonce = block.header.nonce.wrapping_add(1);
    }
    block
}

fn hex_of<T: Encodable>(x: &T) -> String {
    let mut buf = Vec::new();
    x.encode(&mut buf).unwrap();
    hex::encode(buf)
}

/// Regtest chain 1..=n accepted through `submitblock`; plus block n+1 (not submitted).
async fn chain(n: u32) -> (RpcServerImpl, Vec<Block>) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    std::mem::forget(dir);
    let db = Arc::new(ChainDb::open(&path).unwrap());
    let params = ChainParams::regtest();
    BlockStore::new(&db).init_genesis(&params).unwrap();
    let mut st = RpcState::new(db.clone(), params.clone());
    st.best_hash = params.genesis_hash;
    st.best_height = 0;
    st.data_dir = Some(path);
    let state = Arc::new(RwLock::new(st));
    let server = RpcServerImpl::new(state, Arc::new(RwLock::new(PeerState::default())));
    let mut blocks = vec![params.genesis_block.clone()];
    let mut prev = params.genesis_hash;
    for h in 1..=n + 1 {
        let b = mine(h, prev);
        if h <= n {
            let r = server.submit_block(hex_of(&b)).await.expect("submitblock rpc");
            assert!(r.is_none(), "setup block {h} rejected: {r:?}");
        }
        prev = b.block_hash();
        blocks.push(b);
    }
    (server, blocks)
}

#[tokio::test]
async fn submitblock_of_invalidated_block_answers_duplicate_invalid_and_never_reconnects() {
    let (server, b) = chain(10).await;
    server.invalidate_block(b[6].block_hash().to_hex()).await.expect("invalidateblock");
    assert_eq!(server.get_block_count().await.unwrap(), 5);

    // The invalidated block itself: Core "duplicate-invalid", tip held.
    let r = server.submit_block(hex_of(&b[6])).await.expect("rpc");
    assert_eq!(r.as_deref(), Some("duplicate-invalid"));
    assert_eq!(server.get_block_count().await.unwrap(), 5, "invalidated block was reconnected");
    // A failed descendant: also already known invalid.
    let r = server.submit_block(hex_of(&b[8])).await.expect("rpc");
    assert_eq!(r.as_deref(), Some("duplicate-invalid"));
    assert_eq!(server.get_block_count().await.unwrap(), 5);
    // A block on the active chain: "duplicate".
    let r = server.submit_block(hex_of(&b[4])).await.expect("rpc");
    assert_eq!(r.as_deref(), Some("duplicate"));
    assert_eq!(server.get_best_block_hash().await.unwrap(), b[5].block_hash().to_hex());
}

#[tokio::test]
async fn reconsiderblock_activates_the_best_chain() {
    let (server, b) = chain(10).await;
    server.invalidate_block(b[6].block_hash().to_hex()).await.expect("invalidateblock");
    assert_eq!(server.get_block_count().await.unwrap(), 5);
    // Core: ReconsiderBlock + ActivateBestChain -> back on 10 before the RPC returns.
    server.reconsider_block(b[6].block_hash().to_hex()).await.expect("reconsiderblock");
    assert_eq!(server.get_block_count().await.unwrap(), 10, "reconsiderblock did not re-activate");
    assert_eq!(server.get_best_block_hash().await.unwrap(), b[10].block_hash().to_hex());
    // The chain is live again: 11 extends it, and 6 is now a plain duplicate.
    let r = server.submit_block(hex_of(&b[11])).await.expect("rpc");
    assert!(r.is_none(), "block 11 after reconsider: {r:?}");
    assert_eq!(server.get_block_count().await.unwrap(), 11);
    let r = server.submit_block(hex_of(&b[6])).await.expect("rpc");
    assert_eq!(r.as_deref(), Some("duplicate"));
}

#[tokio::test]
async fn reconsider_clears_a_descendant_invalidated_separately() {
    // invalidate 8 then 6; reconsider 6 clears 6, its ancestors and its
    // descendants (Core ResetBlockFailureFlags clears descendants too, incl. 8):
    // the whole chain comes back.
    let (server, b) = chain(10).await;
    server.invalidate_block(b[8].block_hash().to_hex()).await.unwrap();
    server.invalidate_block(b[6].block_hash().to_hex()).await.unwrap();
    assert_eq!(server.get_block_count().await.unwrap(), 5);
    server.reconsider_block(b[6].block_hash().to_hex()).await.unwrap();
    assert_eq!(server.get_block_count().await.unwrap(), 10);
}
