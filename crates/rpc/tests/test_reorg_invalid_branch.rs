//! Invalid-block-over-P2P, the reorg arm: a side branch that becomes heavier
//! but fails validation while being CONNECTED must be recorded as invalid,
//! exactly like Bitcoin Core's `ActivateBestChainStep` -> `ConnectTip` failure
//! -> `InvalidBlockFound` (BLOCK_FAILED_VALID) -> `InvalidChainFound`
//! (descendants BLOCK_FAILED_CHILD), while the active tip stays on the
//! most-work VALID chain. Non-verdicts (a missing ancestor needed to evaluate a
//! rule, a BLOCK_MUTATED body) must mark NOTHING.
//!
//! Shape (= tools/p2p-invalid-block-feed.py `after`): active G -> A1. A peer
//! delivers B1 on G (equal work, coinbase overpays: bad-cb-amount) — stored,
//! no reorg. Then B2 on B1 makes the branch heavier; the reorg fails on B1.
//! Pre-fix rustoshi returned a bare string and left B1/B2 unmarked, so the P2P
//! loop kept the header chain on B2, re-fetched it, and never followed the
//! honest chain (live mainnet code, observed 2026-10-03).

use std::sync::Arc;

use rustoshi_consensus::pow::{get_block_proof, ChainWork};
use rustoshi_consensus::ChainParams;
use rustoshi_primitives::{Block, BlockHeader, Hash256, OutPoint, Transaction, TxIn, TxOut};
use rustoshi_rpc::server::{try_attach_and_reorg, try_attach_and_reorg_detailed, InvalidBranch};
use rustoshi_rpc::RpcState;
use rustoshi_storage::block_store::{BlockIndexEntry, BlockStatus, CoinEntry, UndoData};
use rustoshi_storage::{BlockStore, ChainDb};

const REGTEST_BITS: u32 = 0x207fffff;

/// BIP-34-shaped regtest coinbase at height `h` (scriptSig = OP_N height byte +
/// a unique marker so distinct branches get distinct coinbase txids).
fn rt_coinbase(h: u32, marker: u8) -> Transaction {
    rt_coinbase_value(h, marker, 50_000_000)
}

fn rt_coinbase_value(h: u32, marker: u8, value: u64) -> Transaction {
    let mut script_sig = vec![0x50u8 + h as u8]; // OP_0..OP_16 = BIP-34 height
    script_sig.extend_from_slice(&[marker, marker, marker]);
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256::ZERO,
                vout: u32::MAX,
            },
            script_sig,
            sequence: 0xFFFF_FFFF,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value,
            script_pubkey: vec![0x51], // OP_TRUE
        }],
        lock_time: 0,
    }
}

/// Header-valid block WITHOUT grinding PoW. `try_attach_and_reorg`'s header gate
/// (the code under test) never runs `check_block`'s PoW, so a block that the
/// gate rejects needs no valid nonce. `bits` is the regtest-mandated
/// 0x207fffff so the diffbits gate passes and we reach the version / time gates.
fn mk(version: i32, prev: Hash256, ts: u32, txs: Vec<Transaction>) -> Block {
    let mut block = Block {
        header: BlockHeader {
            version,
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

/// Header-valid AND PoW-valid (grind the trivial regtest target). Used for the
/// VALID heavier branch (c), which `reorganize()` actually connects.
fn rt_mine(prev: Hash256, ts: u32, txs: Vec<Transaction>) -> Block {
    let mut block = mk(4, prev, ts, txs);
    let mut nonce: u32 = 0;
    loop {
        block.header.nonce = nonce;
        if block.header.validate_pow_against_declared_target() {
            break;
        }
        nonce = nonce.wrapping_add(1);
        if nonce == 0 {
            block.header.timestamp = block.header.timestamp.wrapping_add(1);
        }
    }
    block
}

/// Persist a fully-connected chain block (block + header + height index +
/// VALID_SCRIPTS|HAVE_DATA index with real work + empty undo + coinbase UTXO +
/// best-block pointer). Used for genesis and the active tip A1, which the reorg
/// path treats as real on-chain blocks (A1 is disconnected via its undo).
fn persist_chain_block(
    store: &BlockStore,
    block: &Block,
    height: u32,
    prev_hash: Hash256,
    prev_work: [u8; 32],
) -> [u8; 32] {
    let hash = block.block_hash();
    let this_work = ChainWork::from_be_bytes(prev_work).saturating_add(&get_block_proof(REGTEST_BITS));
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
                prev_hash,
                chain_work: this_work.0,
            },
        )
        .unwrap();
    // Coinbase-only block: empty undo (nothing spent).
    store
        .put_undo(&hash, &UndoData { spent_coins: vec![] })
        .unwrap();
    // Persist the coinbase UTXO so the disconnect path has something to remove.
    let coinbase_txid = block.transactions[0].txid();
    store
        .put_utxo(
            &OutPoint {
                txid: coinbase_txid,
                vout: 0,
            },
            &CoinEntry {
                height,
                is_coinbase: true,
                value: 50_000_000,
                script_pubkey: vec![0x51],
            },
        )
        .unwrap();
    store.set_best_block(&hash, height).unwrap();
    this_work.0
}

/// Persist a side block (block + header + HAVE_DATA index with real work) so
/// `reorganize()`'s get_block / get_block_index closures resolve it. Undo + UTXO
/// are produced by the connect pass when the reorg fires.
fn persist_side_block(
    store: &BlockStore,
    block: &Block,
    height: u32,
    prev_hash: Hash256,
    prev_work: [u8; 32],
) -> [u8; 32] {
    let hash = block.block_hash();
    let this_work = ChainWork::from_be_bytes(prev_work).saturating_add(&get_block_proof(REGTEST_BITS));
    store.put_block(&hash, block).unwrap();
    store.put_header(&hash, &block.header).unwrap();
    let mut status = BlockStatus::new();
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
                prev_hash,
                chain_work: this_work.0,
            },
        )
        .unwrap();
    this_work.0
}


const SUBSIDY: u64 = 5_000_000_000; // regtest height-1 subsidy, 50 BTC

fn status(store: &BlockStore, h: &Hash256) -> BlockStatus {
    store.get_block_index(h).unwrap().expect("index entry").status
}

fn failed(st: BlockStatus) -> bool {
    st.has(BlockStatus::FAILED_VALIDITY) || st.has(BlockStatus::FAILED_CHILD)
}

/// G -> A1 active. `genesis_body`: false stores G as header + index only (no
/// body), the shape of an assumeUTXO base whose pre-base bodies are absent.
fn setup(genesis_body: bool) -> (tempfile::TempDir, Arc<ChainDb>, RpcState, Hash256, [u8; 32], Hash256) {
    let tmp = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDb::open(tmp.path()).unwrap());
    let mut state = RpcState::new(db.clone(), ChainParams::regtest());
    let store = BlockStore::new(&db);
    let genesis = mk(4, Hash256::ZERO, 1_700_000_100, vec![rt_coinbase(0, 0xA0)]);
    let gh = genesis.block_hash();
    let work_g = persist_chain_block(&store, &genesis, 0, Hash256::ZERO, [0u8; 32]);
    if !genesis_body {
        store.prune_block(&gh).unwrap();
        assert!(store.get_block(&gh).unwrap().is_none());
    }
    let a1 = mk(4, gh, 1_700_000_200, vec![rt_coinbase(1, 0xA1)]);
    let ha1 = a1.block_hash();
    persist_chain_block(&store, &a1, 1, gh, work_g);
    state.best_hash = ha1;
    state.best_height = 1;
    (tmp, db, state, gh, work_g, ha1)
}

#[test]
fn failed_reorg_marks_invalid_branch_and_keeps_valid_tip() {
    let (_tmp, db, mut state, gh, work_g, ha1) = setup(true);
    let store = BlockStore::new(&db);

    // B1: equal work, coinbase overpays by 1 sat (Core: bad-cb-amount).
    let b1 = rt_mine(gh, 1_700_000_300, vec![rt_coinbase_value(1, 0xB1, SUBSIDY + 1)]);
    let h_b1 = b1.block_hash();
    let work_b1 = persist_side_block(&store, &b1, 1, gh, work_g);
    assert_eq!(try_attach_and_reorg(&mut state, &b1, &h_b1), Ok(false));

    // B2 on B1: heavier, so the reorg is attempted and fails on B1.
    let b2 = rt_mine(h_b1, 1_700_000_400, vec![rt_coinbase(2, 0xB2)]);
    let h_b2 = b2.block_hash();
    persist_side_block(&store, &b2, 2, h_b1, work_b1);
    let err = try_attach_and_reorg_detailed(&mut state, &b2, &h_b2)
        .expect_err("reorg onto a branch with an invalid block must fail");
    assert!(err.reason.ends_with("bad-cb-amount"), "reason: {:?}", err.reason);
    assert_eq!(
        err.invalid,
        Some(InvalidBranch { failed: h_b1, invalidated: vec![h_b1, h_b2] }),
        "the verdict must name the failing block (Core InvalidBlockFound) and its descendant"
    );
    // Active chain untouched: still the valid tip.
    assert_eq!(state.best_hash, ha1);
    assert_eq!(state.best_height, 1);
    assert_eq!(store.get_best_block_hash().unwrap(), Some(ha1));
    // Core BLOCK_FAILED_VALID / BLOCK_FAILED_CHILD, durable in the index.
    assert!(status(&store, &h_b1).has(BlockStatus::FAILED_VALIDITY));
    assert!(status(&store, &h_b2).has(BlockStatus::FAILED_CHILD));
    assert!(!failed(status(&store, &ha1)), "the valid tip must never be marked");

    // Re-delivery of a failed block is refused WITHOUT another reorg attempt,
    // and the stored failure flag survives (no HAVE_DATA overwrite).
    let again = try_attach_and_reorg_detailed(&mut state, &b2, &h_b2).unwrap_err();
    assert!(again.reason.ends_with("duplicate-invalid"), "{:?}", again.reason);
    assert_eq!(again.invalid, None, "a cached-invalid re-delivery is not a new verdict");
    assert!(status(&store, &h_b2).has(BlockStatus::FAILED_CHILD));

    // A block on the failed branch is itself invalid (Core bad-prevblk).
    let b3 = rt_mine(h_b2, 1_700_000_500, vec![rt_coinbase(3, 0xB3)]);
    let h_b3 = b3.block_hash();
    let e3 = try_attach_and_reorg_detailed(&mut state, &b3, &h_b3).unwrap_err();
    assert!(e3.reason.ends_with("bad-prevblk"), "{:?}", e3.reason);
    assert_eq!(e3.invalid, Some(InvalidBranch { failed: h_b3, invalidated: vec![h_b3] }));
    assert!(status(&store, &h_b3).has(BlockStatus::FAILED_CHILD));
    assert_eq!(state.best_hash, ha1);
}

#[test]
fn missing_ancestor_on_reorg_is_not_a_verdict() {
    // G's body is absent: the reorg connect pass cannot compute B1's parent
    // MTP and must fail CLOSED with MissingAncestorHeader — even though B1 is
    // in fact invalid (overpaying coinbase), nothing may be marked: "cannot
    // decide yet" is not a verdict (b6827aba BIP68 fix contract).
    let (_tmp, db, mut state, gh, work_g, ha1) = setup(false);
    let store = BlockStore::new(&db);
    let b1 = rt_mine(gh, 1_700_000_300, vec![rt_coinbase_value(1, 0xB1, SUBSIDY + 1)]);
    let h_b1 = b1.block_hash();
    let work_b1 = persist_side_block(&store, &b1, 1, gh, work_g);
    assert_eq!(try_attach_and_reorg(&mut state, &b1, &h_b1), Ok(false));
    let b2 = rt_mine(h_b1, 1_700_000_400, vec![rt_coinbase(2, 0xB2)]);
    let h_b2 = b2.block_hash();
    persist_side_block(&store, &b2, 2, h_b1, work_b1);
    let err = try_attach_and_reorg_detailed(&mut state, &b2, &h_b2).unwrap_err();
    assert!(err.reason.contains("missing-ancestor-header"), "reason: {:?}", err.reason);
    assert_eq!(err.invalid, None, "a non-verdict must not name an invalid branch");
    assert!(!failed(status(&store, &h_b1)), "B1 must NOT be marked failed");
    assert!(!failed(status(&store, &h_b2)), "B2 must NOT be marked failed");
    assert_eq!(state.best_hash, ha1);
}

#[test]
fn mutated_block_on_reorg_is_not_a_verdict() {
    // B1's stored body no longer matches its header's merkle root (Core
    // BLOCK_MUTATED: bad-txnmrklroot). Core's InvalidBlockFound never marks a
    // mutated block — the real block with that header may still arrive.
    let (_tmp, db, mut state, gh, work_g, ha1) = setup(true);
    let store = BlockStore::new(&db);
    let mut b1 = rt_mine(gh, 1_700_000_300, vec![rt_coinbase(1, 0xB1)]);
    let h_b1 = b1.block_hash();
    let work_b1 = persist_side_block(&store, &b1, 1, gh, work_g);
    assert_eq!(try_attach_and_reorg(&mut state, &b1, &h_b1), Ok(false));
    b1.transactions[0].outputs[0].value -= 1; // header (hash) unchanged
    assert_eq!(b1.block_hash(), h_b1);
    store.put_block(&h_b1, &b1).unwrap();
    let b2 = rt_mine(h_b1, 1_700_000_400, vec![rt_coinbase(2, 0xB2)]);
    let h_b2 = b2.block_hash();
    persist_side_block(&store, &b2, 2, h_b1, work_b1);
    let err = try_attach_and_reorg_detailed(&mut state, &b2, &h_b2).unwrap_err();
    assert!(err.reason.ends_with("bad-txnmrklroot"), "reason: {:?}", err.reason);
    assert_eq!(err.invalid, None, "BLOCK_MUTATED is not a verdict: {:?}", err.reason);
    assert!(!failed(status(&store, &h_b1)));
    assert!(!failed(status(&store, &h_b2)));
    assert_eq!(state.best_hash, ha1);
}
