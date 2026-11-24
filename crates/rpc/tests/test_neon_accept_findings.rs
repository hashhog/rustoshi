//! Neon audit (2026-11-24) findings 8 and 13, side-branch / submitheader
//! halves, checked against Bitcoin Core v31.1 `validation.cpp`.
//!
//! * F13 (side-branch body): Core `ProcessNewBlock` runs `CheckBlock` before
//!   `AcceptBlock` (a failure there stores and marks nothing), and
//!   `AcceptBlock` runs `ContextualCheckBlock` before it writes the block (a
//!   failure there goes to `InvalidBlockFound`: the header is marked
//!   BLOCK_FAILED_VALID unless the result is BLOCK_MUTATED). rustoshi's
//!   `try_attach_and_reorg` (the P2P side-branch store and
//!   `activate_best_chain`) checked only the header and persisted the body
//!   with HAVE_DATA, so a lighter side-branch block with a bad merkle root, a
//!   mutated tx list, a bad coinbase height or a non-final tx was stored.
//! * F8 (BIP-94 timewarp): `ContextualCheckBlockHeader` compares the block
//!   time with `pindexPrev->GetBlockTime() - MAX_TIMEWARP` at every
//!   difficulty-adjustment height when `enforce_BIP94` (testnet4; regtest
//!   with `-test=bip94`). rustoshi passed a parent timestamp of 0 on the
//!   side-branch store and on `submitheader`, so the gate never fired.
//!
//! The non-control tests fail on master 93365362 and pass with the fix.

use std::sync::Arc;

use rustoshi_consensus::pow::{get_block_proof, ChainWork};
use rustoshi_consensus::ChainParams;
use rustoshi_primitives::{Block, BlockHeader, Encodable, Hash256, OutPoint, Transaction, TxIn, TxOut};
use rustoshi_rpc::server::{
    try_attach_and_reorg, try_attach_and_reorg_detailed, PeerState, RpcServerImpl,
    RustoshiRpcServer,
};
use rustoshi_rpc::RpcState;
use rustoshi_storage::block_store::{BlockIndexEntry, BlockStatus};
use rustoshi_storage::{BlockStore, ChainDb};
use tokio::sync::RwLock;

const REGTEST_BITS: u32 = 0x207fffff;
const INTERVAL: u32 = 2016;

/// BIP-34 serialisation of `h` as Core's `CScript() << nHeight` (minimal
/// push; OP_1..OP_16 for 1..=16).
fn bip34_push(h: u32) -> Vec<u8> {
    if (1..=16).contains(&h) {
        return vec![0x50 + h as u8];
    }
    let mut v = Vec::new();
    let mut n = h;
    while n > 0 {
        v.push((n & 0xff) as u8);
        n >>= 8;
    }
    if v.last().map_or(false, |b| b & 0x80 != 0) {
        v.push(0);
    }
    let mut out = vec![v.len() as u8];
    out.extend(v);
    out
}

fn coinbase(h: u32, marker: u8) -> Transaction {
    let mut script_sig = bip34_push(h);
    script_sig.extend_from_slice(&[marker, marker, marker]);
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint { txid: Hash256::ZERO, vout: u32::MAX },
            script_sig,
            sequence: 0xFFFF_FFFF,
            witness: vec![],
        }],
        outputs: vec![TxOut { value: 50_000_000, script_pubkey: vec![0x51] }],
        lock_time: 0,
    }
}

fn mk(prev: Hash256, ts: u32, txs: Vec<Transaction>) -> Block {
    let mut block = Block {
        header: BlockHeader {
            version: 4,
            prev_block_hash: prev,
            merkle_root: Hash256::ZERO,
            timestamp: ts,
            bits: REGTEST_BITS,
            nonce: 0,
        },
        transactions: txs,
    };
    block.header.merkle_root = block.compute_merkle_root();
    block
}

fn grind(mut block: Block) -> Block {
    while !block.header.validate_pow_against_declared_target() {
        block.header.nonce = block.header.nonce.wrapping_add(1);
    }
    block
}

/// Persist a block + header + height index + block-index entry. `work` is
/// the entry's cumulative chain work (callers may inflate it to make the
/// active tip heavier than any one-block side branch).
fn persist(store: &BlockStore, block: &Block, height: u32, work: [u8; 32], best: bool) {
    let hash = block.block_hash();
    store.put_block(&hash, block).unwrap();
    store.put_header(&hash, &block.header).unwrap();
    store.put_height_index(height, &hash).unwrap();
    let mut status = BlockStatus::new();
    status.set(BlockStatus::VALID_SCRIPTS);
    status.set(BlockStatus::HAVE_DATA);
    store
        .put_block_index(
            &hash,
            &BlockIndexEntry {
                height,
                status,
                n_tx: block.transactions.len() as u32,
                timestamp: block.header.timestamp,
                bits: block.header.bits,
                nonce: block.header.nonce,
                version: block.header.version,
                prev_hash: block.header.prev_block_hash,
                chain_work: work,
            },
        )
        .unwrap();
    if best {
        store.set_best_block(&hash, height).unwrap();
    }
}

fn add_work(prev: [u8; 32]) -> [u8; 32] {
    ChainWork::from_be_bytes(prev).saturating_add(&get_block_proof(REGTEST_BITS)).0
}

fn heavy_work() -> [u8; 32] {
    let mut w = [0u8; 32];
    w[0] = 0x01;
    w
}

/// Genesis G and an active tip A1 at height 1 that carries far more work, so
/// any height-1 side branch off G is lighter: `try_attach_and_reorg` must
/// only STORE it (or refuse it), never reorg.
fn small_chain(params: ChainParams) -> (tempfile::TempDir, Arc<ChainDb>, RpcState, Hash256) {
    let tmp = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDb::open(tmp.path()).unwrap());
    let mut state = RpcState::new(db.clone(), params);
    let store = BlockStore::new(&db);
    let g = mk(Hash256::ZERO, 1_700_000_100, vec![coinbase(0, 0xA0)]);
    let gh = g.block_hash();
    persist(&store, &g, 0, add_work([0u8; 32]), true);
    let a1 = grind(mk(gh, 1_700_000_200, vec![coinbase(1, 0xA1)]));
    persist(&store, &a1, 1, heavy_work(), true);
    state.best_hash = a1.block_hash();
    state.best_height = 1;
    (tmp, db, state, gh)
}

fn assert_not_stored(db: &ChainDb, h: &Hash256) {
    let store = BlockStore::new(db);
    assert!(store.get_block(h).unwrap().is_none(), "refused block body must not be stored");
    assert!(store.get_block_index(h).unwrap().is_none(), "refused block must not enter the index");
}

// ---------------------------------------------------------------------------
// F13: a side-branch body is CheckBlock'ed before it is stored
// ---------------------------------------------------------------------------

#[test]
fn neon_f13_side_branch_bad_merkle_root_is_refused_not_stored() {
    let (_tmp, db, mut state, gh) = small_chain(ChainParams::regtest());
    let mut b = mk(gh, 1_700_000_300, vec![coinbase(1, 0xB1)]);
    b.header.merkle_root = Hash256([0x42; 32]);
    let b = grind(b);
    let h = b.block_hash();
    let e = try_attach_and_reorg_detailed(&mut state, &b, &h).expect_err("bad-txnmrklroot");
    assert_eq!(e.reason, "bad-txnmrklroot", "Core CheckBlock: bad-txnmrklroot");
    assert!(e.invalid.is_none(), "a CheckBlock failure marks nothing (Core ProcessNewBlock)");
    assert_not_stored(&db, &h);
}

#[test]
fn neon_f13_side_branch_duplicate_tx_mutation_is_refused_not_stored() {
    // CVE-2012-2459: [cb, tx, tx] has the same merkle root as [cb, tx] with
    // the last leaf duplicated; Core refuses it as bad-txns-duplicate.
    let (_tmp, db, mut state, gh) = small_chain(ChainParams::regtest());
    let tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint { txid: Hash256([7u8; 32]), vout: 0 },
            script_sig: vec![0x51],
            sequence: 0xFFFF_FFFF,
            witness: vec![],
        }],
        outputs: vec![TxOut { value: 1000, script_pubkey: vec![0x51] }],
        lock_time: 0,
    };
    let b = grind(mk(gh, 1_700_000_300, vec![coinbase(1, 0xB2), tx.clone(), tx]));
    let h = b.block_hash();
    let r = try_attach_and_reorg(&mut state, &b, &h);
    assert!(r.is_err(), "Core refuses a mutated block (bad-txns-duplicate); got {r:?}");
    assert_not_stored(&db, &h);
}

/// A ContextualCheckBlock verdict: Core leaves the header in the index,
/// marked BLOCK_FAILED_VALID, with no block data.
fn assert_marked_failed_without_body(db: &ChainDb, h: &Hash256) {
    let store = BlockStore::new(db);
    assert!(store.get_block(h).unwrap().is_none(), "refused block body must not be stored");
    let entry = store.get_block_index(h).unwrap().expect("failed header is recorded");
    assert!(entry.status.has(BlockStatus::FAILED_VALIDITY), "header must be marked failed");
    assert!(!entry.status.has(BlockStatus::HAVE_DATA), "no block data for a refused body");
}

#[test]
fn neon_f13_side_branch_bad_coinbase_height_is_refused_and_marked_failed() {
    // ContextualCheckBlock (BIP-34): regtest height 1 must start with OP_1.
    let (_tmp, db, mut state, gh) = small_chain(ChainParams::regtest());
    let b = grind(mk(gh, 1_700_000_300, vec![coinbase(5, 0xB3)]));
    let h = b.block_hash();
    let e = try_attach_and_reorg_detailed(&mut state, &b, &h).expect_err("bad-cb-height");
    assert!(e.reason.ends_with("bad-cb-height"), "{:?}", e.reason);
    assert_eq!(e.invalid.map(|i| i.failed), Some(h), "a verdict names the failed block");
    assert_marked_failed_without_body(&db, &h);
}

#[test]
fn neon_f13_side_branch_non_final_tx_is_refused_and_marked_failed() {
    // ContextualCheckBlock IsFinalTx: nLockTime 500 (a height) at height 1
    // with a non-final sequence -> bad-txns-nonfinal.
    let (_tmp, db, mut state, gh) = small_chain(ChainParams::regtest());
    let tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint { txid: Hash256([8u8; 32]), vout: 0 },
            script_sig: vec![0x51],
            sequence: 0,
            witness: vec![],
        }],
        outputs: vec![TxOut { value: 1000, script_pubkey: vec![0x51] }],
        lock_time: 500,
    };
    let b = grind(mk(gh, 1_700_000_300, vec![coinbase(1, 0xBA), tx]));
    let h = b.block_hash();
    let e = try_attach_and_reorg_detailed(&mut state, &b, &h).expect_err("bad-txns-nonfinal");
    assert!(e.reason.ends_with("bad-txns-nonfinal"), "{:?}", e.reason);
    assert_marked_failed_without_body(&db, &h);
}

#[test]
fn neon_f13_control_mutated_witness_side_branch_is_refused_not_marked() {
    // Witness data with no commitment is BLOCK_MUTATED in Core
    // (CheckWitnessMalleation): refused, nothing stored, nothing marked.
    let (_tmp, db, mut state, gh) = small_chain(ChainParams::regtest());
    let tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint { txid: Hash256([9u8; 32]), vout: 0 },
            script_sig: vec![],
            sequence: 0xFFFF_FFFF,
            witness: vec![vec![0x01]],
        }],
        outputs: vec![TxOut { value: 1000, script_pubkey: vec![0x51] }],
        lock_time: 0,
    };
    let b = grind(mk(gh, 1_700_000_300, vec![coinbase(1, 0xBB), tx]));
    let h = b.block_hash();
    let e = try_attach_and_reorg_detailed(&mut state, &b, &h).expect_err("mutated");
    assert!(e.invalid.is_none(), "a mutated block is never marked; got {:?}", e.reason);
    assert_not_stored(&db, &h);
}

#[test]
fn neon_f13_control_valid_lighter_side_branch_is_stored() {
    let (_tmp, db, mut state, gh) = small_chain(ChainParams::regtest());
    let b = grind(mk(gh, 1_700_000_300, vec![coinbase(1, 0xB4)]));
    let h = b.block_hash();
    assert_eq!(try_attach_and_reorg(&mut state, &b, &h), Ok(false));
    let store = BlockStore::new(&db);
    assert!(store.get_block(&h).unwrap().is_some(), "valid side-branch body is stored");
    assert!(store
        .get_block_index(&h)
        .unwrap()
        .unwrap()
        .status
        .has(BlockStatus::HAVE_DATA));
}

// ---------------------------------------------------------------------------
// F8: BIP-94 timewarp on the side-branch store and on submitheader
// ---------------------------------------------------------------------------

/// regtest + enforce_bip94 (Core `-test=bip94`), chain G..P at heights
/// 0..=2015 where P's timestamp jumps 10_000 s ahead, and an active tip A
/// at height 2016 off P with far more work. A block/header at height 2016
/// off P is at a difficulty-adjustment height, so the timewarp gate applies.
struct BoundaryChain {
    _tmp: tempfile::TempDir,
    db: Arc<ChainDb>,
    state: RpcState,
    parent: Hash256,
    parent_ts: u32,
}

fn boundary_chain() -> BoundaryChain {
    let mut params = ChainParams::regtest();
    params.enforce_bip94 = true;
    let tmp = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDb::open(tmp.path()).unwrap());
    let mut state = RpcState::new(db.clone(), params);
    let store = BlockStore::new(&db);
    let base = 1_700_000_000u32;
    let mut prev = Hash256::ZERO;
    let mut work = [0u8; 32];
    let mut parent_ts = 0;
    for h in 0..INTERVAL {
        let ts = if h == INTERVAL - 1 { base + h + 10_000 } else { base + h };
        let b = mk(prev, ts, vec![coinbase(h, 0xC0)]);
        work = add_work(work);
        persist(&store, &b, h, work, true);
        prev = b.block_hash();
        parent_ts = ts;
    }
    let a = grind(mk(prev, parent_ts + 1, vec![coinbase(INTERVAL, 0xAA)]));
    persist(&store, &a, INTERVAL, heavy_work(), true);
    state.best_hash = a.block_hash();
    state.best_height = INTERVAL;
    state.header_height = INTERVAL;
    BoundaryChain { _tmp: tmp, db, state, parent: prev, parent_ts }
}

#[test]
fn neon_f8_side_branch_timewarp_block_is_refused_not_stored() {
    let mut c = boundary_chain();
    // 601 s before the parent (> MAX_TIMEWARP), still far above the MTP.
    let b = grind(mk(c.parent, c.parent_ts - 601, vec![coinbase(INTERVAL, 0xB5)]));
    let h = b.block_hash();
    let r = try_attach_and_reorg(&mut c.state, &b, &h);
    assert_eq!(r, Err("time-timewarp-attack".to_string()));
    assert_not_stored(&c.db, &h);
}

#[test]
fn neon_f8_control_side_branch_exactly_max_timewarp_is_stored() {
    let mut c = boundary_chain();
    let b = grind(mk(c.parent, c.parent_ts - 600, vec![coinbase(INTERVAL, 0xB6)]));
    let h = b.block_hash();
    assert_eq!(try_attach_and_reorg(&mut c.state, &b, &h), Ok(false));
}

fn header_hex(b: &Block) -> String {
    hex::encode(b.header.serialize())
}

fn server(state: RpcState) -> RpcServerImpl {
    RpcServerImpl::new(
        Arc::new(RwLock::new(state)),
        Arc::new(RwLock::new(PeerState::default())),
    )
}

#[tokio::test]
async fn neon_f8_submitheader_timewarp_header_is_refused() {
    let c = boundary_chain();
    let (parent, parent_ts) = (c.parent, c.parent_ts);
    let b = grind(mk(parent, parent_ts - 601, vec![coinbase(INTERVAL, 0xB7)]));
    let srv = server(c.state);
    let err = srv
        .submit_header(header_hex(&b))
        .await
        .expect_err("Core submitheader: time-timewarp-attack");
    assert!(
        err.message().contains("time-timewarp-attack"),
        "expected time-timewarp-attack, got {:?}",
        err.message()
    );
    assert!(BlockStore::new(&c.db).get_header(&b.block_hash()).unwrap().is_none());
}

#[tokio::test]
async fn neon_f8_control_submitheader_exactly_max_timewarp_accepted() {
    let c = boundary_chain();
    let b = grind(mk(c.parent, c.parent_ts - 600, vec![coinbase(INTERVAL, 0xB8)]));
    let srv = server(c.state);
    let r = srv.submit_header(header_hex(&b)).await;
    assert!(r.is_ok(), "header 600 s before the parent is allowed (strict <): {r:?}");
}

#[tokio::test]
async fn neon_f8_control_submitheader_time_too_old_reported_before_timewarp() {
    // A header that fails BOTH time-too-old (<= parent MTP) and the timewarp
    // gate: Core reports time-too-old (it is checked first).
    let c = boundary_chain();
    let b = grind(mk(c.parent, 1_700_000_000 + 2000, vec![coinbase(INTERVAL, 0xB9)]));
    let srv = server(c.state);
    let err = srv.submit_header(header_hex(&b)).await.expect_err("refused");
    assert!(err.message().contains("time-too-old"), "got {:?}", err.message());
}
