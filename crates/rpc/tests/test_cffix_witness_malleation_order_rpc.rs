//! cffix-rustoshi-witness-malleation-before-weight, RPC-crate paths that
//! store or connect a body: the side-branch store (`try_attach_and_reorg`,
//! used by the P2P side-branch arm and by submitblock) and `submitblock`
//! (tip-extending and side-branch arms).
//!
//! Core v31.1 order (src/validation.cpp): `CheckBlock` has no
//! witness-inclusive weight check; `ContextualCheckBlock` runs
//! `CheckWitnessMalleation` (BLOCK_MUTATED: bad-witness-nonce-size,
//! bad-witness-merkle-match, unexpected-witness) and only then the weight
//! check (bad-blk-weight, BLOCK_CONSENSUS, :4169-4181). `AcceptBlock` sends a
//! ContextualCheckBlock failure to `InvalidBlockFound` (:4351-4353), which
//! marks the block BLOCK_FAILED_VALID unless the result is BLOCK_MUTATED
//! (:1991).
//!
//! On master 7a703cbc the weight check ran in `check_block`, before the
//! malleation check, so a witness-padded copy of an honest block (same hash)
//! was answered `bad-blk-weight`; on the submitblock tip-extend arm it was
//! also persisted FAILED_VALIDITY, so the honest block was then refused. The
//! non-control tests fail on master by name.

use std::sync::Arc;

use rustoshi_consensus::pow::{get_block_proof, ChainWork};
use rustoshi_consensus::{ChainParams, MAX_BLOCK_WEIGHT};
use rustoshi_primitives::{Block, BlockHeader, Encodable, Hash256, OutPoint, Transaction, TxIn, TxOut};
use rustoshi_rpc::server::{try_attach_and_reorg, try_attach_and_reorg_detailed, PeerState};
use rustoshi_rpc::{RpcServerImpl, RpcState, RustoshiRpcServer};
use rustoshi_storage::block_store::{BlockIndexEntry, BlockStatus};
use rustoshi_storage::{BlockStore, ChainDb};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

const REGTEST_BITS: u32 = 0x207fffff;
/// Zero-filled coinbase output that brings the stripped weight close to the
/// limit: a large but valid block.
const FILLER: usize = 996_000;
/// Extra witness bytes the attacker adds (well under the 4 MB message cap).
const PAD: usize = 40_000;

fn coinbase(marker: u8, nonce: Vec<u8>, commitment: [u8; 32]) -> Transaction {
    let mut spk = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    spk.extend_from_slice(&commitment);
    Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint { txid: Hash256::ZERO, vout: u32::MAX },
            // BIP-34 height 1 is OP_1; then a marker so siblings differ.
            script_sig: vec![0x51, marker, marker],
            sequence: 0xFFFF_FFFF,
            witness: vec![nonce],
        }],
        outputs: vec![
            TxOut { value: 0, script_pubkey: vec![0u8; FILLER] },
            TxOut { value: 0, script_pubkey: spk },
        ],
        lock_time: 0,
    }
}

fn spend_with_witness(witness: Vec<Vec<u8>>) -> Transaction {
    Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint { txid: Hash256([0x11; 32]), vout: 0 },
            script_sig: vec![],
            sequence: 0xffff_fffe,
            witness,
        }],
        outputs: vec![TxOut { value: 1_000, script_pubkey: vec![0x51] }],
        lock_time: 0,
    }
}

/// A height-1 regtest block on `prev` with a valid BIP-141 commitment.
fn block_h1(prev: Hash256, marker: u8, others: Vec<Transaction>) -> Block {
    let nonce = vec![0u8; 32];
    let mut block = Block {
        header: BlockHeader {
            version: 0x2000_0000,
            prev_block_hash: prev,
            merkle_root: Hash256::ZERO,
            timestamp: 1_700_000_300,
            bits: REGTEST_BITS,
            nonce: 0,
        },
        transactions: std::iter::once(coinbase(marker, nonce.clone(), [0u8; 32]))
            .chain(others)
            .collect(),
    };
    let root = block.compute_witness_root();
    let mut preimage = Vec::with_capacity(64);
    preimage.extend_from_slice(root.as_bytes());
    preimage.extend_from_slice(&nonce);
    let commitment: [u8; 32] = Sha256::digest(Sha256::digest(&preimage)).into();
    block.transactions[0] = coinbase(marker, nonce, commitment);
    block.header.merkle_root = block.compute_merkle_root();
    while !block.header.validate_pow_against_declared_target() {
        block.header.nonce = block.header.nonce.wrapping_add(1);
    }
    block
}

fn weight(block: &Block) -> u64 {
    // header + 1-byte tx count, both non-witness.
    81 * 4 + block.transactions.iter().map(|t| t.weight() as u64).sum::<u64>()
}

fn pad_coinbase_witness(honest: &Block) -> Block {
    let mut padded = honest.clone();
    padded.transactions[0].inputs[0].witness = vec![vec![0u8; 32 + PAD]];
    assert_eq!(padded.block_hash(), honest.block_hash(), "padding keeps the hash");
    assert!(weight(&padded) > MAX_BLOCK_WEIGHT, "padded copy is overweight");
    assert!(weight(honest) <= MAX_BLOCK_WEIGHT, "honest block is within weight");
    padded
}

fn committed_overweight(prev: Hash256, marker: u8) -> Block {
    let b = block_h1(prev, marker, vec![spend_with_witness(vec![vec![0x51], vec![0u8; PAD]])]);
    assert!(weight(&b) > MAX_BLOCK_WEIGHT);
    b
}

fn status(db: &ChainDb, h: &Hash256) -> Option<BlockStatus> {
    BlockStore::new(db).get_block_index(h).unwrap().map(|e| e.status)
}

fn is_failed(s: Option<BlockStatus>) -> bool {
    s.map_or(false, |s| s.has(BlockStatus::FAILED_VALIDITY) || s.has(BlockStatus::FAILED_CHILD))
}

// ---------------------------------------------------------------------------
// Side-branch store (try_attach_and_reorg)
// ---------------------------------------------------------------------------

/// Genesis G (height 0) and an active tip A1 at height 1 with far more work,
/// so a height-1 side block off G is only stored, never activated.
fn side_chain() -> (tempfile::TempDir, Arc<ChainDb>, RpcState, Hash256) {
    let tmp = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDb::open(tmp.path()).unwrap());
    let params = ChainParams::regtest();
    let mut state = RpcState::new(db.clone(), params.clone());
    let store = BlockStore::new(&db);
    let put = |b: &Block, height: u32, work: [u8; 32]| {
        let h = b.block_hash();
        store.put_block(&h, b).unwrap();
        store.put_header(&h, &b.header).unwrap();
        store.put_height_index(height, &h).unwrap();
        let mut st = BlockStatus::new();
        st.set(BlockStatus::VALID_SCRIPTS);
        st.set(BlockStatus::HAVE_DATA);
        store
            .put_block_index(
                &h,
                &BlockIndexEntry {
                    height,
                    status: st,
                    n_tx: b.transactions.len() as u32,
                    timestamp: b.header.timestamp,
                    bits: b.header.bits,
                    nonce: b.header.nonce,
                    version: b.header.version,
                    prev_hash: b.header.prev_block_hash,
                    chain_work: work,
                },
            )
            .unwrap();
        store.set_best_block(&h, height).unwrap();
    };
    let g = params.genesis_block.clone();
    let gh = g.block_hash();
    put(&g, 0, ChainWork::ZERO.saturating_add(&get_block_proof(REGTEST_BITS)).0);
    let a1 = block_h1(gh, 0xA1, vec![]);
    let mut heavy = [0u8; 32];
    heavy[0] = 0x01;
    put(&a1, 1, heavy);
    state.best_hash = a1.block_hash();
    state.best_height = 1;
    (tmp, db, state, gh)
}

#[test]
fn cffix_sidebranch_padded_copy_is_mutated_not_marked_then_honest_stored() {
    let (_tmp, db, mut state, gh) = side_chain();
    let honest = block_h1(gh, 0xB1, vec![]);
    let padded = pad_coinbase_witness(&honest);
    let h = honest.block_hash();

    let e = try_attach_and_reorg_detailed(&mut state, &padded, &h).expect_err("padded copy");
    assert_eq!(
        e.reason, "bad-witness-nonce-size",
        "Core ContextualCheckBlock refuses the padded copy as BLOCK_MUTATED first"
    );
    assert!(e.invalid.is_none(), "a BLOCK_MUTATED result marks nothing");
    assert!(BlockStore::new(&db).get_block(&h).unwrap().is_none(), "padded body not stored");
    assert!(!is_failed(status(&db, &h)), "hash must not be marked failed");

    assert_eq!(try_attach_and_reorg(&mut state, &honest, &h), Ok(false));
    assert!(BlockStore::new(&db).get_block(&h).unwrap().is_some(), "honest body stored");
    assert!(status(&db, &h).unwrap().has(BlockStatus::HAVE_DATA));
}

/// A side block that commits to its witness and is still overweight is
/// Core bad-blk-weight from ContextualCheckBlock (BLOCK_CONSENSUS), so
/// AcceptBlock's InvalidBlockFound marks it BLOCK_FAILED_VALID. On master
/// the check ran in the first CheckBlock and marked nothing.
#[test]
fn cffix_sidebranch_committed_overweight_is_refused_and_marked_failed() {
    let (_tmp, db, mut state, gh) = side_chain();
    let heavy = committed_overweight(gh, 0xB2);
    let h = heavy.block_hash();
    let e = try_attach_and_reorg_detailed(&mut state, &heavy, &h).expect_err("bad-blk-weight");
    assert!(e.reason.ends_with("bad-blk-weight"), "{:?}", e.reason);
    assert_eq!(e.invalid.map(|i| i.failed), Some(h), "a verdict names the failed block");
    assert!(BlockStore::new(&db).get_block(&h).unwrap().is_none(), "no body stored");
    assert!(is_failed(status(&db, &h)), "header must be marked failed");
}

// ---------------------------------------------------------------------------
// submitblock
// ---------------------------------------------------------------------------

struct Node {
    _dir: tempfile::TempDir,
    db: Arc<ChainDb>,
    server: RpcServerImpl,
    genesis: Hash256,
}

fn node() -> Node {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDb::open(dir.path()).unwrap());
    let params = ChainParams::regtest();
    BlockStore::new(&db).init_genesis(&params).unwrap();
    let mut st = RpcState::new(db.clone(), params.clone());
    st.best_hash = params.genesis_hash;
    st.best_height = 0;
    st.data_dir = Some(dir.path().to_path_buf());
    let server = RpcServerImpl::new(
        Arc::new(RwLock::new(st)),
        Arc::new(RwLock::new(PeerState::default())),
    );
    Node { _dir: dir, db, server, genesis: params.genesis_hash }
}

async fn submit(n: &Node, b: &Block) -> Option<String> {
    match n.server.submit_block(hex::encode(b.serialize())).await {
        Ok(v) => v,
        Err(e) => Some(format!("rpc-error: {}", e.message())),
    }
}

/// Tip-extending submitblock: the padded copy is bad-witness-nonce-size and
/// leaves the hash unmarked; the honest block with the same hash connects.
#[tokio::test]
async fn cffix_submitblock_padded_copy_then_honest_connects() {
    let n = node();
    let honest = block_h1(n.genesis, 0xC1, vec![]);
    let padded = pad_coinbase_witness(&honest);
    let h = honest.block_hash();

    assert_eq!(submit(&n, &padded).await.as_deref(), Some("bad-witness-nonce-size"));
    assert!(!is_failed(status(&n.db, &h)), "padded copy must not mark the hash failed");

    assert_eq!(submit(&n, &honest).await, None, "honest block with the same hash connects");
    assert_eq!(n.server.get_best_block_hash().await.unwrap(), h.to_hex());
}

/// Control (passes on master): a committed overweight block is still
/// bad-blk-weight on the tip-extending arm, and the tip does not move.
#[tokio::test]
async fn cffix_control_submitblock_committed_overweight_is_bad_blk_weight() {
    let n = node();
    let heavy = committed_overweight(n.genesis, 0xC2);
    assert_eq!(submit(&n, &heavy).await.as_deref(), Some("bad-blk-weight"));
    assert_eq!(n.server.get_best_block_hash().await.unwrap(), n.genesis.to_hex());
}

/// Side-branch submitblock (the arm that runs check_block +
/// contextual_check_block before try_attach_and_reorg).
#[tokio::test]
async fn cffix_submitblock_side_branch_padded_copy_is_mutated_then_honest_stored() {
    let n = node();
    let a1 = block_h1(n.genesis, 0xD1, vec![]);
    assert_eq!(submit(&n, &a1).await, None, "active tip A1");

    let honest = block_h1(n.genesis, 0xD2, vec![]);
    let padded = pad_coinbase_witness(&honest);
    let h = honest.block_hash();
    assert_eq!(submit(&n, &padded).await.as_deref(), Some("bad-witness-nonce-size"));
    assert!(!is_failed(status(&n.db, &h)), "padded copy must not mark the hash failed");
    assert!(BlockStore::new(&n.db).get_block(&h).unwrap().is_none(), "padded body not stored");

    let r = submit(&n, &honest).await;
    assert!(
        matches!(r.as_deref(), Some("inconclusive") | None),
        "honest side block with the same hash is stored: {r:?}"
    );
    assert!(BlockStore::new(&n.db).get_block(&h).unwrap().is_some());
}

/// Control (passes on master): a committed overweight side block is still
/// bad-blk-weight through submitblock.
#[tokio::test]
async fn cffix_control_submitblock_side_branch_committed_overweight_is_bad_blk_weight() {
    let n = node();
    let a1 = block_h1(n.genesis, 0xE1, vec![]);
    assert_eq!(submit(&n, &a1).await, None, "active tip A1");
    let heavy = committed_overweight(n.genesis, 0xE2);
    assert_eq!(submit(&n, &heavy).await.as_deref(), Some("bad-blk-weight"));
    assert_eq!(n.server.get_best_block_hash().await.unwrap(), a1.block_hash().to_hex());
}
