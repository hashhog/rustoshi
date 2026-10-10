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

/// BIP34 height push. Heights 1..=16 are `OP_1`..`OP_16`; larger heights are
/// a minimal little-endian script-num push.
fn bip34_push(height: u32) -> Vec<u8> {
    if height == 0 {
        return vec![0x00];
    }
    if height <= 16 {
        return vec![0x50 + height as u8];
    }
    let mut h = height;
    let mut le = Vec::new();
    while h > 0 {
        le.push((h & 0xFF) as u8);
        h >>= 8;
    }
    if le.last().is_some_and(|b| b & 0x80 != 0) {
        le.push(0);
    }
    let mut out = vec![le.len() as u8];
    out.extend(le);
    out
}

fn coinbase_to(h: u32, outputs: Vec<TxOut>) -> Transaction {
    let mut script_sig = bip34_push(h);
    script_sig.extend_from_slice(&[0x01, 0xC5]);
    Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint { txid: Hash256::ZERO, vout: u32::MAX },
            script_sig,
            sequence: 0xFFFF_FFFF,
            witness: vec![],
        }],
        outputs,
        lock_time: 0,
    }
}

fn coinbase(h: u32) -> Transaction {
    coinbase_to(
        h,
        vec![TxOut { value: 50 * 100_000_000, script_pubkey: vec![0x51] }],
    )
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

fn header_hex(block: &Block) -> String {
    let mut buf = Vec::new();
    block.header.encode(&mut buf).unwrap();
    assert_eq!(buf.len(), 80);
    hex::encode(buf)
}

fn mine_at(h: u32, prev: Hash256, timestamp: u32) -> Block {
    mine_with_at(h, prev, timestamp, Vec::new())
}

fn mine_with_at(h: u32, prev: Hash256, timestamp: u32, extra: Vec<Transaction>) -> Block {
    let mut transactions = vec![coinbase(h)];
    transactions.extend(extra);
    let mut block = Block {
        header: BlockHeader {
            version: 0x2000_0000,
            prev_block_hash: prev,
            merkle_root: Hash256::ZERO,
            timestamp,
            bits: 0x207f_ffff,
            nonce: 0,
        },
        transactions,
    };
    block.header.merkle_root = block.compute_merkle_root();
    while !block.header.validate_pow_against_declared_target() {
        block.header.nonce = block.header.nonce.wrapping_add(1);
    }
    block
}

async fn chain_at(n: u32, time_of: impl Fn(u32) -> u32) -> (RpcServerImpl, Vec<Block>) {
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
    for h in 1..=n {
        let b = mine_at(h, prev, time_of(h));
        let r = server.submit_block(hex_of(&b)).await.expect("submitblock rpc");
        assert!(r.is_none(), "setup block {h} rejected: {r:?}");
        prev = b.block_hash();
        blocks.push(b);
    }
    (server, blocks)
}

/// Core `getchaintips` (rpc/blockchain.cpp): the active tip, plus every orphan
/// that is not the parent of another orphan. Status is active / invalid /
/// headers-only / valid-fork / valid-headers. branchlen is the distance back
/// to the active chain.
#[tokio::test]
async fn getchaintips_lists_every_core_status() {
    let (server, blocks) = chain(2).await;
    let genesis = blocks[0].block_hash();
    let a2 = blocks[2].block_hash();

    // Heavier fork from genesis. S1 and S2 lose to A2; S3 overtakes it.
    // A2 stays fully validated and becomes a valid-fork.
    let s1 = mine_cb(1, genesis, 100);
    assert_eq!(
        server.submit_block(hex_of(&s1)).await.unwrap().as_deref(),
        Some("inconclusive")
    );
    let s2 = mine_cb(2, s1.block_hash(), 101);
    assert_eq!(
        server.submit_block(hex_of(&s2)).await.unwrap().as_deref(),
        Some("inconclusive")
    );
    let s3 = mine_cb(3, s2.block_hash(), 102);
    assert!(
        server.submit_block(hex_of(&s3)).await.unwrap().is_none(),
        "heavier fork must become the tip"
    );
    assert_eq!(server.get_best_block_hash().await.unwrap(), s3.block_hash().to_hex());

    // Sibling of block 1 that never connects: valid-headers.
    let side = mine_cb(1, genesis, 200);
    assert_eq!(
        server.submit_block(hex_of(&side)).await.unwrap().as_deref(),
        Some("inconclusive")
    );

    // Header-only competitor of S3, parent S2 (still valid).
    let hdr = mine_cb(3, s2.block_hash(), 150);
    server
        .submit_header(header_hex(&hdr))
        .await
        .expect("header on a valid parent");

    server
        .invalidate_block(s3.block_hash().to_hex())
        .await
        .expect("invalidateblock");
    assert_eq!(server.get_block_count().await.unwrap(), 2);
    assert_eq!(server.get_best_block_hash().await.unwrap(), s2.block_hash().to_hex());

    let tips = server.get_chain_tips().await.expect("getchaintips");
    let mut got: Vec<(u64, String, u64, String)> = tips
        .as_array()
        .expect("getchaintips array")
        .iter()
        .map(|t| {
            (
                t["height"].as_u64().unwrap(),
                t["hash"].as_str().unwrap().to_string(),
                t["branchlen"].as_u64().unwrap(),
                t["status"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    got.sort();

    let mut expect = vec![
        (2, s2.block_hash().to_hex(), 0, "active".to_string()),
        (2, a2.to_hex(), 2, "valid-fork".to_string()),
        (1, side.block_hash().to_hex(), 1, "valid-headers".to_string()),
        (3, s3.block_hash().to_hex(), 1, "invalid".to_string()),
        (3, hdr.block_hash().to_hex(), 1, "headers-only".to_string()),
    ];
    expect.sort();
    assert_eq!(got, expect, "getchaintips must list every Core status");
}

/// Core `InvalidateBlock` resets `m_best_header` to the new valid tip (then
/// any non-failed header with more work). `GuessVerificationProgress` on a
/// regtest tip younger than two hours is 1 when headers == blocks, and
/// `chain_tx / (chain_tx + 0.6)` when the header tip is one block ahead
/// (`dTxRate` 0.001, spacing 600s).
#[tokio::test]
async fn invalidateblock_rewinds_headers_and_verificationprogress() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    // Every block time stays inside the 2h "recent header" window.
    let base = now - 4 * 600;
    let (server, blocks) = chain_at(3, |h| base + h * 600).await;

    let ahead = mine_at(4, blocks[3].block_hash(), blocks[3].header.timestamp + 1);
    server
        .submit_header(header_hex(&ahead))
        .await
        .expect("header extends the tip");

    let info = server.get_blockchain_info().await.unwrap();
    assert_eq!(info.blocks, 3);
    assert_eq!(info.headers, 4, "headers must follow the header tip");
    // Four chain txs (genesis + 3), one header ahead → extra 0.6 tx.
    let expected = 4.0 / 4.6;
    assert!(
        (info.verificationprogress - expected).abs() < 1e-12,
        "verificationprogress {}, Core {}",
        info.verificationprogress,
        expected
    );

    server
        .invalidate_block(blocks[3].block_hash().to_hex())
        .await
        .unwrap();
    let info = server.get_blockchain_info().await.unwrap();
    assert_eq!(info.blocks, 2);
    assert_eq!(info.headers, 2, "invalidateblock must rewind the header tip");
    assert_eq!(
        info.verificationprogress, 1.0,
        "synced recent tip is fully verified"
    );

    server
        .reconsider_block(blocks[3].block_hash().to_hex())
        .await
        .unwrap();
    let info = server.get_blockchain_info().await.unwrap();
    assert_eq!(info.blocks, 3);
    assert_eq!(info.headers, 4, "the non-failed header is ahead of the block tip again");
    assert!(
        (info.verificationprogress - expected).abs() < 1e-12,
        "verificationprogress after reconsider {}, Core {}",
        info.verificationprogress,
        expected
    );
}

fn block_file_bytes(block: &Block) -> u64 {
    let mut buf = Vec::new();
    block.encode(&mut buf).unwrap();
    // Core blk*.dat record: 4-byte magic + 4-byte size + payload.
    8 + buf.len() as u64
}

/// Coinbase-only undo record: compact-size 0 (1 byte) + 32-byte checksum,
/// plus the 8-byte rev*.dat record header. Genesis has no undo record.
const EMPTY_UNDO_RECORD: u64 = 41;

/// Core `CalculateCurrentUsage`: logical blk*.dat + rev*.dat bytes of blocks
/// that have data (and undo, once connected). Not the chainstate database.
#[tokio::test]
async fn size_on_disk_counts_block_and_undo_bytes() {
    let (server, blocks) = chain(2).await;
    let mut expected = 0u64;
    for (i, block) in blocks.iter().take(3).enumerate() {
        expected += block_file_bytes(block);
        if i > 0 {
            expected += EMPTY_UNDO_RECORD;
        }
    }
    let info = server.get_blockchain_info().await.unwrap();
    assert_eq!(info.size_on_disk, expected, "connected chain blk+rev bytes");

    let side = mine_cb(1, blocks[0].block_hash(), 80);
    assert_eq!(
        server.submit_block(hex_of(&side)).await.unwrap().as_deref(),
        Some("inconclusive")
    );
    expected += block_file_bytes(&side);
    let info = server.get_blockchain_info().await.unwrap();
    assert_eq!(info.size_on_disk, expected, "side block adds blk bytes, no undo");

    server.invalidate_block(blocks[2].block_hash().to_hex()).await.unwrap();
    let info = server.get_blockchain_info().await.unwrap();
    assert_eq!(info.size_on_disk, expected, "invalidateblock does not shrink the files");
}

/// P2SH wrapping `OP_TRUE`: standard prevout, consensus-valid without a
/// signature, no witness (so the confirming block needs no witness commitment).
fn p2sh_op_true() -> (Vec<u8>, Vec<u8>) {
    let redeem = vec![0x51u8];
    let h = rustoshi_crypto::hash160(&redeem);
    let mut script_pubkey = vec![0xa9, 0x14];
    script_pubkey.extend_from_slice(&h.0);
    script_pubkey.push(0x87);
    (script_pubkey, vec![0x01, 0x51])
}

fn spend_p2sh(prev: Hash256, vout: u32, sequence: u32, value: u64, script_pubkey: Vec<u8>, script_sig: Vec<u8>) -> Transaction {
    Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint { txid: prev, vout },
            script_sig,
            sequence,
            witness: vec![],
        }],
        outputs: vec![TxOut { value, script_pubkey }],
        lock_time: 0,
    }
}

/// Coinbase maturity is 100. Block 1 pays two P2SH(OP_TRUE) outputs so one
/// spend can signal BIP125 and the other cannot.
async fn mature_p2sh_chain() -> (RpcServerImpl, Vec<Block>, Transaction, Transaction) {
    let (script_pubkey, script_sig) = p2sh_op_true();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    std::mem::forget(dir);
    let db = Arc::new(ChainDb::open(&path).unwrap());
    let params = ChainParams::regtest();
    BlockStore::new(&db).init_genesis(&params).unwrap();
    let mut st = RpcState::new(db, params.clone());
    st.best_hash = params.genesis_hash;
    st.best_height = 0;
    st.data_dir = Some(path);
    let state = Arc::new(RwLock::new(st));
    let server = RpcServerImpl::new(state, Arc::new(RwLock::new(PeerState::default())));

    let half = 25 * 100_000_000;
    let block1 = {
        let cb = coinbase_to(
            1,
            vec![
                TxOut { value: half, script_pubkey: script_pubkey.clone() },
                TxOut { value: half, script_pubkey: script_pubkey.clone() },
            ],
        );
        let mut block = Block {
            header: BlockHeader {
                version: 0x2000_0000,
                prev_block_hash: params.genesis_hash,
                merkle_root: Hash256::ZERO,
                timestamp: BASE_TIME + 600,
                bits: 0x207f_ffff,
                nonce: 0,
            },
            transactions: vec![cb],
        };
        block.header.merkle_root = block.compute_merkle_root();
        while !block.header.validate_pow_against_declared_target() {
            block.header.nonce = block.header.nonce.wrapping_add(1);
        }
        block
    };
    assert!(server.submit_block(hex_of(&block1)).await.unwrap().is_none());

    let mut prev = block1.block_hash();
    let mut blocks = vec![params.genesis_block.clone(), block1];
    // Tip must be >= 101. Mempool maturity is `tip_height - coin_height`
    // (mempool.rs), so a height-1 coinbase is spendable only once the tip
    // is 101. The confirming block is then height 102.
    for h in 2..=101 {
        let b = mine(h, prev);
        assert!(
            server.submit_block(hex_of(&b)).await.unwrap().is_none(),
            "setup block {h}"
        );
        prev = b.block_hash();
        blocks.push(b);
    }

    let cb_txid = blocks[1].transactions[0].txid();
    let signaling = spend_p2sh(
        cb_txid,
        0,
        0xFFFF_FFFD,
        half - 10_000,
        script_pubkey.clone(),
        script_sig.clone(),
    );
    let quiet = spend_p2sh(cb_txid, 1, 0xFFFF_FFFF, half - 10_000, script_pubkey, script_sig);
    (server, blocks, signaling, quiet)
}

fn mempool_map(raw: &serde_json::value::RawValue) -> serde_json::Map<String, serde_json::Value> {
    serde_json::from_str(raw.get()).unwrap()
}

const MEMPOOL_KEYS: &[&str] = &[
    "vsize",
    "weight",
    "time",
    "height",
    "descendantcount",
    "descendantsize",
    "ancestorcount",
    "ancestorsize",
    "wtxid",
    "chunkweight",
    "fees",
    "depends",
    "spentby",
    "bip125-replaceable",
    "unbroadcast",
];

fn assert_core_mempool_entry(entry: &serde_json::Value, bip125: bool, height: u64) {
    let obj = entry.as_object().expect("mempool entry");
    let keys: Vec<&str> = obj.keys().map(|k| k.as_str()).collect();
    assert_eq!(keys, MEMPOOL_KEYS, "entry keys must match Core entryToJSON");
    assert_eq!(entry["bip125-replaceable"].as_bool(), Some(bip125));
    assert_eq!(entry["height"].as_u64(), Some(height));
    assert_eq!(entry["chunkweight"], entry["weight"]);
    let fees = entry["fees"].as_object().unwrap();
    let fee_keys: Vec<&str> = fees.keys().map(|k| k.as_str()).collect();
    assert_eq!(
        fee_keys,
        ["base", "modified", "ancestor", "descendant", "chunk"]
    );
    assert_eq!(fees["chunk"], fees["base"]);
    assert_eq!(fees["modified"], fees["base"]);
    assert!(entry["depends"].as_array().unwrap().is_empty());
    assert!(entry["spentby"].as_array().unwrap().is_empty());
}

/// Core `entryToJSON`: `bip125-replaceable` is BIP125 opt-in (sequence <=
/// 0xFFFFFFFD, or an unconfirmed ancestor that signals), not "true because
/// fullrbf". `chunkweight` / `fees.chunk` are the cluster chunk's
/// sigop-adjusted weight and modified fee. A singleton's chunk is itself.
#[tokio::test]
async fn getrawmempool_verbose_bip125_and_chunk_match_core() {
    let (server, _blocks, signaling, quiet) = mature_p2sh_chain().await;
    let sig_txid = server
        .send_raw_transaction(hex_of(&signaling), None, None)
        .await
        .expect("signaling spend");
    let quiet_txid = server
        .send_raw_transaction(hex_of(&quiet), None, None)
        .await
        .expect("non-signaling spend");
    assert_eq!(sig_txid, signaling.txid().to_hex());

    let pool = mempool_map(&server.get_raw_mempool(Some(true)).await.unwrap());
    let height = server.get_block_count().await.unwrap() as u64;
    assert_core_mempool_entry(pool.get(&sig_txid).expect("signaling tx"), true, height);
    assert_core_mempool_entry(pool.get(&quiet_txid).expect("quiet tx"), false, height);
}

/// A reorg that reconnects a block must drop the txs that block confirms.
/// Core's mempool is empty after `reconsiderblock` puts the confirming tip back.
#[tokio::test]
async fn reconsiderblock_drops_txs_confirmed_by_the_reconnected_blocks() {
    let (server, blocks, signaling, _quiet) = mature_p2sh_chain().await;
    let txid = server
        .send_raw_transaction(hex_of(&signaling), None, None)
        .await
        .expect("spend");
    let tip = blocks.last().unwrap().block_hash();
    let confirming = mine_with_at(102, tip, BASE_TIME + 102 * 600, vec![signaling]);
    assert!(
        server.submit_block(hex_of(&confirming)).await.unwrap().is_none(),
        "confirming block"
    );
    assert!(mempool_map(&server.get_raw_mempool(Some(true)).await.unwrap()).is_empty());

    server
        .invalidate_block(confirming.block_hash().to_hex())
        .await
        .unwrap();
    let pool = mempool_map(&server.get_raw_mempool(Some(true)).await.unwrap());
    assert!(pool.contains_key(&txid), "invalidateblock returns the spend to the mempool");

    server
        .reconsider_block(confirming.block_hash().to_hex())
        .await
        .unwrap();
    assert_eq!(server.get_best_block_hash().await.unwrap(), confirming.block_hash().to_hex());
    let pool = mempool_map(&server.get_raw_mempool(Some(true)).await.unwrap());
    assert!(
        pool.is_empty(),
        "reconsiderblock must remove txs the reconnected block confirms, got {pool:?}"
    );
}

/// Core `submitheader` → `AcceptBlockHeader`: a header whose parent is
/// `BLOCK_FAILED_VALID` is an RPC error -25 "bad-prevblk", and the header is
/// not stored.
#[tokio::test]
async fn submitheader_of_failed_parent_is_bad_prevblk_and_not_stored() {
    let (server, blocks) = chain(2).await;
    let tip = blocks[2].block_hash();
    server.invalidate_block(tip.to_hex()).await.unwrap();

    let child = mine_at(3, tip, blocks[2].header.timestamp + 1);
    let err = server
        .submit_header(header_hex(&child))
        .await
        .expect_err("child of an invalidated block");
    assert_eq!(err.code(), -25, "{err:?}");
    assert!(
        err.message().contains("bad-prevblk"),
        "message {:?}, want bad-prevblk",
        err.message()
    );

    let missing = server
        .get_block_header(child.block_hash().to_hex(), Some(true))
        .await;
    assert!(missing.is_err(), "failed-parent header must not be stored: {missing:?}");
    let tips = server.get_chain_tips().await.unwrap();
    let listed = tips
        .as_array()
        .unwrap()
        .iter()
        .any(|t| t["hash"].as_str() == Some(&child.block_hash().to_hex()));
    assert!(!listed, "unstored header must not be a chain tip");
}

fn mine_valued(h: u32, prev: Hash256, step: u32, value: u64, extra: u8) -> Block {
    let mut script_sig = bip34_push(h);
    script_sig.extend_from_slice(&[extra, 0xC5]);
    let mut block = Block {
        header: BlockHeader {
            version: 0x2000_0000,
            prev_block_hash: prev,
            merkle_root: Hash256::ZERO,
            timestamp: BASE_TIME + step * 600,
            bits: 0x207f_ffff,
            nonce: 0,
        },
        transactions: vec![Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Hash256::ZERO, vout: u32::MAX },
                script_sig,
                sequence: 0xFFFF_FFFF,
                witness: vec![],
            }],
            outputs: vec![TxOut { value, script_pubkey: vec![0x51] }],
            lock_time: 0,
        }],
    };
    block.header.merkle_root = block.compute_merkle_root();
    while !block.header.validate_pow_against_declared_target() {
        block.header.nonce = block.header.nonce.wrapping_add(1);
    }
    block
}

fn index_failed_valid(db: &ChainDb, hash: &Hash256) -> bool {
    BlockStore::new(db)
        .get_block_index(hash)
        .ok()
        .flatten()
        .is_some_and(|e| e.status.has(BlockStatus::FAILED_VALIDITY))
}

/// A block that passes header and context-free checks but fails ConnectBlock
/// (coinbase value above the subsidy) is stored as BLOCK_FAILED_VALID. The
/// active tip does not move. The mark is still there after the chain state
/// is reloaded, and a resubmit is duplicate-invalid rather than another
/// connect attempt.
#[tokio::test]
async fn connect_failure_is_failed_valid_and_survives_restart() {
    let (server, blocks, db) = chain_db(2).await;
    let tip = blocks[2].block_hash();
    assert_eq!(server.get_block_count().await.unwrap(), 2);

    // Tip-extending connect failure.
    let bad = mine_valued(3, tip, 3, 51 * 100_000_000, 0x01);
    let r = server.submit_block(hex_of(&bad)).await.unwrap();
    assert_eq!(r.as_deref(), Some("bad-cb-amount"), "{r:?}");
    assert_eq!(server.get_block_count().await.unwrap(), 2);
    assert_eq!(server.get_best_block_hash().await.unwrap(), tip.to_hex());
    assert!(
        index_failed_valid(&db, &bad.block_hash()),
        "tip-extending ConnectBlock failure must be BLOCK_FAILED_VALID"
    );
    let r = server.submit_block(hex_of(&bad)).await.unwrap();
    assert_eq!(r.as_deref(), Some("duplicate-invalid"), "resubmit retried the connect: {r:?}");

    // Heavier side branch whose tip fails ConnectBlock.
    let params = ChainParams::regtest();
    let s1 = mine_valued(1, params.genesis_hash, 11, 50 * 100_000_000, 0x99);
    let s2 = mine_valued(2, s1.block_hash(), 12, 50 * 100_000_000, 0x99);
    let s3 = mine_valued(3, s2.block_hash(), 13, 51 * 100_000_000, 0x99);
    assert_eq!(
        server.submit_block(hex_of(&s1)).await.unwrap().as_deref(),
        Some("inconclusive")
    );
    assert_eq!(
        server.submit_block(hex_of(&s2)).await.unwrap().as_deref(),
        Some("inconclusive")
    );
    let r = server.submit_block(hex_of(&s3)).await.unwrap();
    assert_eq!(r.as_deref(), Some("bad-cb-amount"), "heavier side tip: {r:?}");
    assert_eq!(server.get_best_block_hash().await.unwrap(), tip.to_hex());
    assert!(
        index_failed_valid(&db, &s3.block_hash()),
        "heavier side branch ConnectBlock failure must be BLOCK_FAILED_VALID"
    );
    let tips = server.get_chain_tips().await.unwrap();
    let invalid = tips.as_array().unwrap().iter().find(|t| {
        t["hash"].as_str() == Some(&s3.block_hash().to_hex())
    });
    let invalid = invalid.expect("invalid side tip must be listed");
    assert_eq!(invalid["status"], "invalid");
    assert_eq!(invalid["height"], 3);
    assert_eq!(invalid["branchlen"], 3);

    // Reload chain state from the same database (restart).
    let mut reloaded = RpcState::new(db.clone(), params);
    reloaded.init_from_db().unwrap();
    assert_eq!(reloaded.best_hash, tip);
    assert_eq!(reloaded.best_height, 2);
    assert!(index_failed_valid(&db, &bad.block_hash()));
    assert!(index_failed_valid(&db, &s3.block_hash()));
    let again = RpcServerImpl::new(
        Arc::new(RwLock::new(reloaded)),
        Arc::new(RwLock::new(PeerState::default())),
    );
    assert_eq!(
        again.submit_block(hex_of(&s3)).await.unwrap().as_deref(),
        Some("duplicate-invalid")
    );
    assert_eq!(again.get_best_block_hash().await.unwrap(), tip.to_hex());
}

/// `init_from_db` must restore Core's `m_best_header`: the most-work header
/// that is not failed, including a headers-only extension of the active tip.
/// Reloading from the active-block height drops `headers` back to `blocks`.
#[tokio::test]
async fn init_from_db_header_height_is_best_valid_header() {
    let (server, blocks, db) = chain_db(2).await;
    let tip = blocks[2].block_hash();
    let h1 = mine_at(3, tip, blocks[2].header.timestamp + 1);
    server
        .submit_header(header_hex(&h1))
        .await
        .expect("headers-only child of the tip");
    let h2 = mine_at(4, h1.block_hash(), blocks[2].header.timestamp + 2);
    server
        .submit_header(header_hex(&h2))
        .await
        .expect("second headers-only block");

    let live = server.get_blockchain_info().await.unwrap();
    assert_eq!(live.blocks, 2);
    assert_eq!(live.headers, 4, "live header tip follows the heavier chain");

    let params = ChainParams::regtest();
    let mut reloaded = RpcState::new(db, params);
    reloaded.init_from_db().unwrap();
    assert_eq!(reloaded.best_height, 2);
    assert_eq!(reloaded.best_hash, tip);
    assert_eq!(
        reloaded.header_height, 4,
        "after restart header_height must be the best valid header, not the active tip"
    );
}
