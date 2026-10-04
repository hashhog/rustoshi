//! Gate 6 (docs/RELEASE-CHECKLIST.md): a resource failure (disk full, I/O
//! error) leads to retry or halt, never to a reject or an accept.
//!
//! Audit: receipts/gate6-resource-limit-audit-2026-10-04.md, rustoshi F2 (the
//! UTXO flush drained the cache before the write), F9 (a coins-DB read error
//! became `MissingInput`), F7b (a BIP30 lookup error became "no conflict").
//!
//! Faults are injected with `ChainDb::inject_write_faults` /
//! `ChainDb::inject_read_faults`, which make RocksDB writes/reads fail with
//! the I/O error a full disk produces. Each fault test has a control showing a
//! genuinely invalid block still gets its verdict.

use crate::block_store::BlockStore;
use crate::columns::CF_UTXO;
use crate::db::ChainDb;
use rustoshi_consensus::fatal;
use rustoshi_consensus::params::ChainParams;
use rustoshi_consensus::validation::{
    connect_block_with_sequence_locks, CoinEntry, SequenceLockContext, TxValidationError,
    UtxoView, ValidationError,
};
use rustoshi_primitives::{Block, BlockHeader, Hash256, OutPoint, Transaction, TxIn, TxOut};
use tempfile::TempDir;

struct NoSeqCtx;
impl SequenceLockContext for NoSeqCtx {
    fn get_mtp_at_height(&self, _height: u32) -> u32 {
        0
    }
}

fn temp_db() -> (TempDir, ChainDb) {
    let dir = TempDir::new().expect("temp dir");
    let db = ChainDb::open(dir.path()).expect("open db");
    (dir, db)
}

fn h(n: u8) -> Hash256 {
    let mut b = [0u8; 32];
    b[0] = n;
    b[31] = 0x77;
    Hash256(b)
}

fn op(n: u8) -> OutPoint {
    OutPoint { txid: h(n), vout: 0 }
}

fn coin(value: u64) -> CoinEntry {
    CoinEntry {
        height: 1,
        is_coinbase: false,
        value,
        script_pubkey: vec![0x51],
    }
}

fn coinbase(height: u32, tag: u8) -> Transaction {
    let mut script = vec![0x03u8];
    script.extend_from_slice(&height.to_le_bytes()[..3]);
    script.push(tag);
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint { txid: Hash256([0u8; 32]), vout: 0xFFFF_FFFF },
            script_sig: script,
            sequence: 0xFFFF_FFFF,
            witness: vec![],
        }],
        outputs: vec![TxOut { value: 1_000, script_pubkey: vec![0x51] }],
        lock_time: 0,
    }
}

fn spend(prev: OutPoint, value: u64) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: prev,
            script_sig: vec![],
            sequence: 0xFFFF_FFFF,
            witness: vec![],
        }],
        outputs: vec![TxOut { value, script_pubkey: vec![0x51] }],
        lock_time: 0,
    }
}

fn block(height: u32, txs: Vec<Transaction>) -> Block {
    let mut all = vec![coinbase(height, txs.len() as u8)];
    all.extend(txs);
    Block {
        header: BlockHeader {
            version: 0x2000_0000,
            prev_block_hash: h(0xEE),
            merkle_root: Hash256([0u8; 32]),
            timestamp: 1_700_000_000 + height,
            bits: 0x207f_ffff,
            nonce: 0,
        },
        transactions: all,
    }
}

/// Connect through the production connect function with scripts skipped
/// (OP_TRUE outputs; the gate under test is coin lookup, not script).
fn connect(view: &mut dyn UtxoView, b: &Block, height: u32) -> Result<(), ValidationError> {
    let params = ChainParams::regtest();
    connect_block_with_sequence_locks(b, height, view, &params, &NoSeqCtx, 0, true, None)
        .map(|_| ())
}

fn is_missing_input(e: &ValidationError) -> bool {
    matches!(e, ValidationError::TxValidation(TxValidationError::MissingInput(_, _)))
}

/// Seed `outpoint` durably on disk (through a flush that is not faulted).
fn seed_on_disk(store: &BlockStore, outpoint: &OutPoint, c: CoinEntry) {
    let mut v = store.utxo_view();
    v.add_utxo(outpoint, c);
    v.flush().expect("seed flush");
}

// ---------------------------------------------------------------------------
// F2 -- the flush drained the cache before the write
// ---------------------------------------------------------------------------

/// A spend whose flush FAILED must still be a spend. Pre-fix the cache was
/// drained into the batch before the write, so after ENOSPC the spent coin
/// was read back off disk as unspent: a later double-spend was ACCEPTED.
#[test]
fn f2_failed_flush_keeps_spend_no_double_spend_accepted() {
    let _g = fatal::test_serial_guard();
    let (_dir, db) = temp_db();
    let store = BlockStore::new(&db);
    let a = op(1);
    seed_on_disk(&store, &a, coin(50_000));

    let mut view = store.utxo_view();
    // Block 200 spends A (connected in memory, not yet flushed).
    connect(&mut view, &block(200, vec![spend(a.clone(), 40_000)]), 200).expect("block 200");

    // The periodic flush hits a full disk -- twice, so the one retry fails too.
    db.inject_write_faults(2);
    let r = view.flush_with_tip_and_blocks(&h(0xB2), 200, &[], &[], None);
    assert!(r.is_err(), "the flush must report the write failure");

    // A is still spent in this view; it was NOT resurrected from disk.
    assert!(
        view.get_utxo(&a).is_none(),
        "spent coin came back after a failed flush (pre-fix: cache drained before the write)"
    );
    // So a block that spends A again is still the double-spend it is.
    let e = connect(&mut view, &block(201, vec![spend(a.clone(), 30_000)]), 201)
        .expect_err("double-spend of A must be rejected");
    assert!(is_missing_input(&e), "double-spend rejected as missing input: {e:?}");

    db.inject_write_faults(0);
    fatal::reset_for_tests();
}

/// A coin CREATED before a failed flush must still exist, so the next valid
/// block that spends it connects. Pre-fix the coin was lost with the drained
/// cache and the honest block was judged `bad-txns-inputs-missingorspent`
/// (persisted FAILED_VALIDITY + a 100-point ban on the live path).
#[test]
fn f2_failed_flush_keeps_created_coin_next_valid_block_connects() {
    let _g = fatal::test_serial_guard();
    let (_dir, db) = temp_db();
    let store = BlockStore::new(&db);
    let a = op(2);
    seed_on_disk(&store, &a, coin(50_000));

    let mut view = store.utxo_view();
    let tx_b = spend(a.clone(), 40_000);
    let b = OutPoint { txid: tx_b.txid(), vout: 0 };
    connect(&mut view, &block(200, vec![tx_b]), 200).expect("block 200 creates B");

    db.inject_write_faults(2);
    assert!(view.flush_with_tip(&h(0xB3), 200).is_err());
    db.inject_write_faults(0);

    assert!(view.get_utxo(&b).is_some(), "B lost by the failed flush");
    connect(&mut view, &block(201, vec![spend(b.clone(), 30_000)]), 201)
        .expect("the next VALID block must connect after a failed flush");

    // Once the disk recovers, the intact cache commits and is then cleared.
    view.flush_with_tip(&h(0xB4), 201).expect("flush after recovery");
    assert_eq!(view.cache_len(), 0);
    assert!(store.get_utxo(&a).unwrap().is_none(), "A spent on disk");
    assert!(store.get_utxo(&b).unwrap().is_none(), "B spent on disk");
    fatal::reset_for_tests();
}

/// Control: with no fault, a block spending a coin that never existed is
/// still a missing-inputs verdict.
#[test]
fn control_missing_coin_is_still_a_verdict() {
    let _g = fatal::test_serial_guard();
    let (_dir, db) = temp_db();
    let store = BlockStore::new(&db);
    let mut view = store.utxo_view();
    let e = connect(&mut view, &block(200, vec![spend(op(0x5A), 1_000)]), 200)
        .expect_err("spend of a nonexistent coin");
    assert!(is_missing_input(&e), "{e:?}");
    assert!(e.is_invalid_block_verdict());
}

// ---------------------------------------------------------------------------
// F9 -- a coins-DB read error became "absent"
// ---------------------------------------------------------------------------

/// A failing coin read must not be judged as a missing input. Pre-fix
/// `get_utxo(..).ok().flatten()` turned the I/O error into `None` ->
/// `MissingInput` -> persisted FAILED_VALIDITY + ban.
#[test]
fn f9_coin_read_error_is_not_missing_inputs() {
    let _g = fatal::test_serial_guard();
    let (_dir, db) = temp_db();
    let store = BlockStore::new(&db);
    let a = op(3);
    seed_on_disk(&store, &a, coin(50_000));

    let mut view = store.utxo_view();
    db.inject_read_faults(Some(CF_UTXO), 1000);
    let r = connect(&mut view, &block(200, vec![spend(a.clone(), 40_000)]), 200);
    db.inject_read_faults(None, 0);
    let e = r.expect_err("a block whose coin cannot be read must not connect");
    assert!(!is_missing_input(&e), "read error reported as missing input: {e:?}");
    assert!(
        !e.is_invalid_block_verdict(),
        "a read error must never be an invalid-block verdict: {e:?}"
    );
    fatal::reset_for_tests();
}

// ---------------------------------------------------------------------------
// F7b -- a BIP30 lookup error was read as "no conflict"
// ---------------------------------------------------------------------------

/// With BIP30 enforced, a coinbase-only block whose BIP30 lookups fail must
/// not CONNECT (fail-open pre-fix: the read error became "no existing coin").
#[test]
fn f7b_bip30_lookup_error_does_not_connect() {
    let _g = fatal::test_serial_guard();
    let (_dir, db) = temp_db();
    let store = BlockStore::new(&db);
    let mut view = store.utxo_view();
    db.inject_read_faults(Some(CF_UTXO), 1000);
    let r = connect(&mut view, &block(200, vec![]), 200);
    db.inject_read_faults(None, 0);
    let e = r.expect_err("BIP30 cannot be evaluated: the block must not connect");
    assert!(!e.is_invalid_block_verdict(), "{e:?}");
    fatal::reset_for_tests();
}

/// Control: a real BIP30 conflict is still `bad-txns-BIP30`.
#[test]
fn control_bip30_conflict_is_still_a_verdict() {
    let _g = fatal::test_serial_guard();
    let (_dir, db) = temp_db();
    let store = BlockStore::new(&db);
    let b = block(200, vec![]);
    let cb_out = OutPoint { txid: b.transactions[0].txid(), vout: 0 };
    seed_on_disk(&store, &cb_out, coin(1_000));
    let mut view = store.utxo_view();
    let e = connect(&mut view, &b, 200).expect_err("duplicate coinbase output");
    assert_eq!(e, ValidationError::Bip30DuplicateOutput);
    assert!(e.is_invalid_block_verdict());
}

// ---------------------------------------------------------------------------
// AbortNode latch (post-fix API)
// ---------------------------------------------------------------------------

/// One transient write failure is retried; the flush succeeds, nothing is
/// latched.
#[test]
fn single_write_failure_is_retried_once() {
    let _g = fatal::test_serial_guard();
    fatal::reset_for_tests();
    let (_dir, db) = temp_db();
    let store = BlockStore::new(&db);
    let mut view = store.utxo_view();
    view.add_utxo(&op(4), coin(7));
    db.inject_write_faults(1);
    view.flush_with_tip(&h(0xC1), 5).expect("retry absorbs one failure");
    assert!(!fatal::is_aborted());
    assert_eq!(store.get_best_height().unwrap(), Some(5));
    assert!(store.get_utxo(&op(4)).unwrap().is_some());
}

/// A write that fails on the retry too latches AbortNode, and the tip
/// pointer did not move (it is in the same failed batch as the coins).
#[test]
fn double_write_failure_latches_abort_node_and_tip_stays() {
    let _g = fatal::test_serial_guard();
    fatal::reset_for_tests();
    let (_dir, db) = temp_db();
    let store = BlockStore::new(&db);
    let mut view = store.utxo_view();
    view.add_utxo(&op(5), coin(7));
    view.flush_with_tip(&h(0xC2), 5).expect("baseline");
    view.add_utxo(&op(6), coin(8));
    db.inject_write_faults(2);
    assert!(view.flush_with_tip(&h(0xC3), 6).is_err());
    assert!(fatal::is_aborted(), "a twice-failed chainstate write must latch AbortNode");
    assert_eq!(store.get_best_height().unwrap(), Some(5), "tip must not advance");
    assert!(store.get_utxo(&op(6)).unwrap().is_none());
    assert_eq!(view.cache_len(), 1, "cache kept intact");
    fatal::reset_for_tests();
}

/// A coins-DB read that fails twice latches AbortNode (Core's
/// CCoinsViewErrorCatcher), and `try_get_utxo` reports an error, not `None`.
#[test]
fn read_failure_latches_abort_node() {
    let _g = fatal::test_serial_guard();
    fatal::reset_for_tests();
    let (_dir, db) = temp_db();
    let store = BlockStore::new(&db);
    seed_on_disk(&store, &op(7), coin(9));
    let view = store.utxo_view();
    db.inject_read_faults(Some(CF_UTXO), 1);
    assert!(view.try_get_utxo(&op(7)).unwrap().is_some(), "one failure is retried");
    assert!(!fatal::is_aborted());
    db.inject_read_faults(Some(CF_UTXO), 2);
    assert!(view.try_get_utxo(&op(7)).is_err());
    assert!(fatal::is_aborted());
    db.inject_read_faults(None, 0);
    fatal::reset_for_tests();
}
