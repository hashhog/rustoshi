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
use rustoshi_storage::block_store::BlockStatus;
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

/// `cb_height` is the BIP-34 prefix (independent of the block's real height).
/// `step` only spaces the timestamp.
fn mine_cb(cb_height: u32, prev: Hash256, step: u32) -> Block {
    let mut block = Block {
        header: BlockHeader {
            version: 0x2000_0000,
            prev_block_hash: prev,
            merkle_root: Hash256::ZERO,
            timestamp: BASE_TIME + step * 600,
            bits: 0x207f_ffff,
            nonce: 0,
        },
        transactions: vec![coinbase(cb_height)],
    };
    block.header.merkle_root = block.compute_merkle_root();
    while !block.header.validate_pow_against_declared_target() {
        block.header.nonce = block.header.nonce.wrapping_add(1);
    }
    block
}

fn mine(h: u32, prev: Hash256) -> Block {
    mine_cb(h, prev, h)
}

fn hex_of<T: Encodable>(x: &T) -> String {
    let mut buf = Vec::new();
    x.encode(&mut buf).unwrap();
    hex::encode(buf)
}

/// Regtest chain 1..=n accepted through `submitblock`; plus block n+1 (not submitted).
async fn chain(n: u32) -> (RpcServerImpl, Vec<Block>) {
    let (server, blocks, _db) = chain_db(n).await;
    (server, blocks)
}

async fn chain_db(n: u32) -> (RpcServerImpl, Vec<Block>, Arc<ChainDb>) {
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
    (server, blocks, db)
}

fn set_failed_child_only(db: &ChainDb, hash: &Hash256) {
    let store = BlockStore::new(db);
    let mut e = store.get_block_index(hash).unwrap().expect("index");
    e.status.clear(BlockStatus::FAILED_VALIDITY);
    e.status.set(BlockStatus::FAILED_CHILD);
    store.put_block_index(hash, &e).unwrap();
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

/// Core `AcceptBlockHeader` (validation.cpp): a header whose prev has
/// `BLOCK_FAILED_MASK` is `BLOCK_INVALID_PREV` / "bad-prevblk" before
/// `ContextualCheckBlock` (so a coinbase-height mismatch is not reported).
/// `submitblock` maps that through `BIP22ValidationResult`. A context-free
/// `CheckBlock` failure still wins (`ProcessNewBlock` runs it first).
///
/// mining_basic.py builds `bad_block2` on a block that already failed
/// (`bad-txns-nonfinal` → index `BLOCK_FAILED_VALID`) and expects
/// `bad-prevblk`. rpc_invalidateblock.py: `reconsiderblock` puts the tip
/// back on the most-work chain; the child can then be submitted and extend it.
#[tokio::test]
async fn submitblock_child_and_grandchild_of_invalidated_block_are_bad_prevblk() {
    let (server, b, db) = chain_db(10).await;
    let tip = b[10].block_hash();
    server.invalidate_block(tip.to_hex()).await.expect("invalidateblock");
    assert_eq!(server.get_block_count().await.unwrap(), 9);

    // Child of the invalidated tip. BIP-34 prefix says height 1; the block's
    // real height is 11. Core answers bad-prevblk, not bad-cb-height.
    let bad_child = mine_cb(1, tip, 30);
    let r = server.submit_block(hex_of(&bad_child)).await.expect("rpc");
    assert_eq!(r.as_deref(), Some("bad-prevblk"), "child of invalidated block");
    assert_eq!(server.get_block_count().await.unwrap(), 9);
    // Not stored: a second submit is the same answer, not duplicate-invalid.
    let r = server.submit_block(hex_of(&bad_child)).await.expect("rpc");
    assert_eq!(r.as_deref(), Some("bad-prevblk"));

    // CheckBlock runs before AcceptBlockHeader. A mutated merkle root is
    // bad-txnmrklroot even though the parent is failed.
    let mut mutated = mine_cb(1, tip, 31);
    mutated.transactions[0].outputs[0].value -= 1;
    let r = server.submit_block(hex_of(&mutated)).await.expect("rpc");
    assert_eq!(r.as_deref(), Some("bad-txnmrklroot"));
    assert_eq!(server.get_block_count().await.unwrap(), 9);

    // The invalidated block itself.
    let r = server.submit_block(hex_of(&b[10])).await.expect("rpc");
    assert_eq!(r.as_deref(), Some("duplicate-invalid"));
    assert_eq!(server.get_block_count().await.unwrap(), 9);

    // Valid child, rejected while the parent is invalid, then accepted once
    // reconsiderblock has put the parent back at the tip.
    let child = mine(11, tip);
    let r = server.submit_block(hex_of(&child)).await.expect("rpc");
    assert_eq!(r.as_deref(), Some("bad-prevblk"));
    assert_eq!(server.get_block_count().await.unwrap(), 9);

    server.reconsider_block(tip.to_hex()).await.expect("reconsiderblock");
    assert_eq!(server.get_block_count().await.unwrap(), 10, "reconsiderblock did not restore the tip");
    assert_eq!(server.get_best_block_hash().await.unwrap(), tip.to_hex());
    let r = server.submit_block(hex_of(&child)).await.expect("rpc");
    assert!(r.is_none(), "child after reconsider: {r:?}");
    assert_eq!(server.get_block_count().await.unwrap(), 11);
    assert_eq!(server.get_best_block_hash().await.unwrap(), child.block_hash().to_hex());

    // Descendant of an invalidated block (on-chain child, BLOCK_FAILED_VALID
    // in Core / FAILED_VALIDITY here) and a parent that carries only
    // FAILED_CHILD. Both are BLOCK_FAILED_MASK. The new block's coinbase
    // height does not match, which is what used to surface as bad-cb-height.
    server.invalidate_block(b[8].block_hash().to_hex()).await.expect("invalidateblock");
    assert_eq!(server.get_block_count().await.unwrap(), 7);
    let on_descendant = mine_cb(1, b[10].block_hash(), 40);
    let r = server.submit_block(hex_of(&on_descendant)).await.expect("rpc");
    assert_eq!(r.as_deref(), Some("bad-prevblk"), "parent is a descendant of an invalidated block");
    assert_eq!(server.get_block_count().await.unwrap(), 7);

    set_failed_child_only(&db, &b[10].block_hash());
    let on_failed_child = mine_cb(1, b[10].block_hash(), 41);
    let r = server.submit_block(hex_of(&on_failed_child)).await.expect("rpc");
    assert_eq!(r.as_deref(), Some("bad-prevblk"), "parent is BLOCK_FAILED_CHILD only");
    assert_eq!(server.get_block_count().await.unwrap(), 7);

    let r = server.submit_block(hex_of(&b[8])).await.expect("rpc");
    assert_eq!(r.as_deref(), Some("duplicate-invalid"));

    // reconsiderblock activates the best chain (height returns).
    server.reconsider_block(b[8].block_hash().to_hex()).await.expect("reconsiderblock");
    assert_eq!(server.get_block_count().await.unwrap(), 11);
    assert_eq!(server.get_best_block_hash().await.unwrap(), child.block_hash().to_hex());
}
