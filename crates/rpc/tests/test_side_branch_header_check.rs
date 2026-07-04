//! CONSENSUS-FORK regression: the side-branch STORE path
//! (`rustoshi_rpc::server::try_attach_and_reorg`) MUST run the full
//! ContextualCheckBlockHeader gate set BEFORE persisting a fork header,
//! matching Bitcoin Core `AcceptBlockHeader` (validation.cpp:4224 →
//! ContextualCheckBlockHeader, validation.cpp:4088-4118).
//!
//! Before the fix, `try_attach_and_reorg` stored the header/block/index entry
//! unconditionally and only re-ran the block-*body* gates (`check_block` /
//! `contextual_check_block`) at reconnect (chain_state.rs:810-860) — never the
//! *header* gates. Result: an invalid side-branch block was STORED and, once a
//! heavier child arrived, the active tip REORGED onto it — a live consensus
//! fork. Core refuses such a header before it ever enters the block index, so
//! no reorg is possible. This is the REORGANIZE-path companion to rustoshi
//! 0d8dd26, which closed the LINEAR/tip-extend (submitblock) diffbits gap.
//!
//! Why an rpc *integration* test (not the inline `#[cfg(test)] mod tests` in
//! server.rs): that module is pre-existing DORMANT / non-compiling (its
//! `process_block` call is stuck on an old 5-arg signature — CLAUDE.md
//! "test-rot"). This file is a separate compilation unit that drives the same
//! public `try_attach_and_reorg` entry point through the storage public API.
//!
//! Vectors (regtest — BIP-34/65/66 active at height 1):
//!   (a) v1 (nVersion=1) side-branch on genesis   → reject "bad-version".
//!   (b) now+3h (> now + MAX_FUTURE_BLOCK_TIME 7200) side-branch
//!                                                 → reject "time-too-new".
//!   (c) a VALID heavier side-branch (v4, sane time) STILL reorgs — proves the
//!       new gate does not over-reject.
//! PRE-FIX: (a)/(b) return Ok(false) (stored on a side-branch) and a heavier
//! child then reorgs the tip onto them. POST-FIX: (a)/(b) return
//! Err(reject-string) at store, the tip does not move, the header never enters
//! the index.

use std::sync::Arc;

use rustoshi_consensus::pow::{get_block_proof, ChainWork};
use rustoshi_consensus::ChainParams;
use rustoshi_primitives::{Block, BlockHeader, Hash256, OutPoint, Transaction, TxIn, TxOut};
use rustoshi_rpc::server::try_attach_and_reorg;
use rustoshi_rpc::RpcState;
use rustoshi_storage::block_store::{BlockIndexEntry, BlockStatus, CoinEntry, UndoData};
use rustoshi_storage::{BlockStore, ChainDb};

const REGTEST_BITS: u32 = 0x207fffff;

/// BIP-34-shaped regtest coinbase at height `h` (scriptSig = OP_N height byte +
/// a unique marker so distinct branches get distinct coinbase txids).
fn rt_coinbase(h: u32, marker: u8) -> Transaction {
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
            value: 50_000_000,
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
        if block.header.validate_pow() {
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

#[test]
fn side_branch_store_runs_contextual_check_block_header() {
    let tmp = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDb::open(tmp.path()).unwrap());
    let mut state = RpcState::new(db.clone(), ChainParams::regtest());
    let store = BlockStore::new(&db);

    // Genesis G (height 0, fork point — never header-re-validated) and the
    // active tip A1 (height 1, valid) so a height-1 side-branch is a genuine,
    // *lighter* competitor — exactly the shape the fork exploited. Fixed old
    // (2023) timestamps keep every candidate comfortably below now+7200 and
    // above the parent MTP.
    let genesis = mk(4, Hash256::ZERO, 1_700_000_100, vec![rt_coinbase(0, 0xA0)]);
    let genesis_hash = genesis.block_hash();
    let work_g = persist_chain_block(&store, &genesis, 0, Hash256::ZERO, [0u8; 32]);

    let a1 = mk(4, genesis_hash, 1_700_000_200, vec![rt_coinbase(1, 0xA1)]);
    let hash_a1 = a1.block_hash();
    let _work_a1 = persist_chain_block(&store, &a1, 1, genesis_hash, work_g);
    state.best_hash = hash_a1;
    state.best_height = 1;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;

    // ── Vector (a): v1 side-branch on genesis → bad-version ──────────────────
    let d1_badver = mk(1, genesis_hash, 1_700_000_500, vec![rt_coinbase(1, 0xD1)]);
    let h_badver = d1_badver.block_hash();
    let r = try_attach_and_reorg(&mut state, &d1_badver, &h_badver);
    // Core's canonical reject string embeds the offending nVersion, exactly as
    // `strprintf("bad-version(0x%08x)", block.nVersion)` (validation.cpp:4116) —
    // here "bad-version(0x00000001)".
    let err = r.expect_err("v1 side-branch header must be rejected at store");
    assert!(
        err.starts_with("bad-version"),
        "v1 side-branch header must be rejected with bad-version(..) \
         (Core ContextualCheckBlockHeader, validation.cpp:4113-4118); got {err:?}"
    );
    assert_eq!(state.best_hash, hash_a1, "tip must not move on a rejected header");
    assert!(
        store.get_block_index(&h_badver).unwrap().is_none(),
        "rejected side-branch header must NOT enter the block index (Core \
         refuses it before AcceptBlockHeader stores it — no reorg possible)"
    );

    // ── Vector (b): now+3h side-branch on genesis → time-too-new ─────────────
    let d1_future = mk(4, genesis_hash, now + 3 * 3600, vec![rt_coinbase(1, 0xD2)]);
    let h_future = d1_future.block_hash();
    let r = try_attach_and_reorg(&mut state, &d1_future, &h_future);
    assert_eq!(
        r,
        Err("time-too-new".to_string()),
        "now+3h side-branch header (> now + 7200) must be rejected time-too-new \
         (Core ContextualCheckBlockHeader, validation.cpp:4108)"
    );
    assert_eq!(state.best_hash, hash_a1, "tip must not move on a rejected header");
    assert!(
        store.get_block_index(&h_future).unwrap().is_none(),
        "rejected future-time header must NOT enter the block index"
    );

    // ── Vector (c): VALID heavier side-branch STILL reorgs (no over-reject) ──
    // B1 (height 1, equal work → stored, no reorg), then B2 (height 2, more
    // work → reorg). Both v4 with sane timestamps — the gate must accept both.
    let b1 = rt_mine(genesis_hash, 1_700_000_300, vec![rt_coinbase(1, 0xB1)]);
    let h_b1 = b1.block_hash();
    let work_b1 = persist_side_block(&store, &b1, 1, genesis_hash, work_g);
    let did = try_attach_and_reorg(&mut state, &b1, &h_b1)
        .expect("valid equal-work side-branch B1 must NOT be rejected by the header gate");
    assert!(!did, "B1 has equal work to the tip — no reorg yet");
    assert_eq!(state.best_hash, hash_a1);

    let b2 = rt_mine(h_b1, 1_700_000_400, vec![rt_coinbase(2, 0xB2)]);
    let h_b2 = b2.block_hash();
    let _work_b2 = persist_side_block(&store, &b2, 2, h_b1, work_b1);
    let did = try_attach_and_reorg(&mut state, &b2, &h_b2)
        .expect("valid heavier side-branch B2 must reorg, not be rejected");
    assert!(did, "B-branch (height 2) outweighs the tip — reorg must fire");
    assert_eq!(
        state.best_hash, h_b2,
        "tip must advance onto the valid heavier branch"
    );
    assert_eq!(state.best_height, 2);
}
