//! cffix-rustoshi-reorg-bip68-coin-mtp: on a side-branch reorg, the BIP-68
//! coin time of a time-locked input must come from the CONNECTING block's
//! ancestry, not from the height index (which still maps the old branch until
//! the reorg's commit batch rewrites it).
//!
//! Core `CalculateSequenceLocks` (bitcoin-core/src/consensus/tx_verify.cpp:74):
//! `block.GetAncestor(std::max(nCoinHeight - 1, 0))->GetMedianTimePast()`,
//! where `block` is the block being connected.
//!
//! Every fixture forks at genesis G (height 0). Active branch A has
//! coinbase-only blocks. Side branch B is stored like
//! `try_attach_and_reorg_detailed` stores it (header + block + index entry,
//! NO height-index row); B3 carries `tx1`, which spends a seeded
//! non-coinbase coin and creates coin X at height 3, and a later B block
//! carries `tx2`, which spends X with a time-based nSequence. The coin-time
//! lookup is therefore MTP(height 2): A's MTP on master, B's MTP in Core.
//!
//! T0 = 1_700_000_000. BIP-68 / CSV is enabled from height 0 on top of the
//! synthetic-block mainnet params.

use super::*;
use rustoshi_storage::block_store::{BlockIndexEntry as StoreEntry, BlockStatus, CoinEntry, UndoData as StoreUndo};
use rustoshi_storage::ChainDb;

const T0: u32 = 1_700_000_000;
const SEED_TXID: [u8; 32] = [0x5e; 32];
/// BIP-68 time flag (1 << 22); the low 16 bits count 512-second units.
const SEQ_TIME_FLAG: u32 = 1 << 22;

fn params() -> rustoshi_consensus::ChainParams {
    let mut p = mainnet_params_for_synth_blocks();
    p.csv_height = 0;
    p
}

fn build(h: u32, prev: Hash256, ts: u32, marker: u8, extra: Vec<Transaction>) -> Block {
    let mut txs = vec![synth_coinbase(h, marker)];
    txs.extend(extra);
    let mut block = Block {
        header: rustoshi_primitives::BlockHeader {
            version: 1,
            prev_block_hash: prev,
            merkle_root: Hash256::ZERO,
            timestamp: ts,
            bits: 0x207fffff,
            nonce: 0,
        },
        transactions: txs,
    };
    block.header.merkle_root = block.compute_merkle_root();
    while !block.header.validate_pow_against_declared_target() {
        block.header.nonce = block.header.nonce.wrapping_add(1);
    }
    block
}

fn next_work(prev_work: [u8; 32], bits: u32) -> [u8; 32] {
    use rustoshi_consensus::pow::{get_block_proof, ChainWork};
    ChainWork::from_be_bytes(prev_work).saturating_add(&get_block_proof(bits)).0
}

fn put_index(store: &BlockStore, h: u32, block: &Block, work: [u8; 32], status: BlockStatus) -> Hash256 {
    let hash = block.block_hash();
    store.put_block(&hash, block).unwrap();
    store.put_header(&hash, &block.header).unwrap();
    store
        .put_block_index(
            &hash,
            &StoreEntry {
                height: h,
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
    hash
}

/// Active (connected) coinbase-only block: height index, undo, UTXO, tip.
fn put_active(store: &BlockStore, h: u32, prev: Hash256, prev_work: [u8; 32], ts: u32, marker: u8) -> (Hash256, [u8; 32]) {
    let block = build(h, prev, ts, marker, vec![]);
    let work = next_work(prev_work, block.header.bits);
    let mut status = BlockStatus::new();
    status.set(BlockStatus::VALID_SCRIPTS);
    status.set(BlockStatus::HAVE_DATA);
    let hash = put_index(store, h, &block, work, status);
    store.put_height_index(h, &hash).unwrap();
    store.put_undo(&hash, &StoreUndo { spent_coins: vec![] }).unwrap();
    store
        .put_utxo(
            &OutPoint { txid: block.transactions[0].txid(), vout: 0 },
            &CoinEntry { height: h, is_coinbase: true, value: 50_000_000, script_pubkey: vec![0x51] },
        )
        .unwrap();
    store.set_best_block(&hash, h).unwrap();
    (hash, work)
}

/// Side-branch block stored the way `try_attach_and_reorg_detailed` stores
/// one: header + block + HAVE_DATA index entry, no height-index row.
fn put_side(store: &BlockStore, h: u32, block: &Block, prev_work: [u8; 32]) -> (Hash256, [u8; 32]) {
    let work = next_work(prev_work, block.header.bits);
    let mut status = BlockStatus::new();
    status.set(BlockStatus::HAVE_DATA);
    (put_index(store, h, block, work, status), work)
}

/// tx1: spends the seeded coin (no relative lock), creates coin X.
fn tx1() -> Transaction {
    Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint { txid: Hash256(SEED_TXID), vout: 0 },
            script_sig: vec![],
            sequence: 0xFFFF_FFFF,
            witness: vec![],
        }],
        outputs: vec![TxOut { value: 9_000_000, script_pubkey: vec![0x51] }],
        lock_time: 0,
    }
}

/// tx2: spends X with a BIP-68 time lock of `units` * 512 seconds.
fn tx2(units: u32) -> Transaction {
    Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint { txid: tx1().txid(), vout: 0 },
            script_sig: vec![],
            sequence: SEQ_TIME_FLAG | units,
            witness: vec![],
        }],
        outputs: vec![TxOut { value: 8_000_000, script_pubkey: vec![0x51] }],
        lock_time: 0,
    }
}

struct Fixture {
    _tmp: tempfile::TempDir,
    db: Arc<ChainDb>,
    st: RpcState,
    old_tip: (Hash256, u32),
    /// Stored side blocks B1..B(n-1), ascending, with heights.
    side: Vec<(u32, Hash256)>,
    /// The arriving block B(n) handed to try_attach_and_reorg_detailed.
    arriving: Block,
    arriving_height: u32,
}

/// `a_ts`: timestamps of A1..; `b_ts`: timestamps of B1..Bn; tx1 goes in B3,
/// tx2(`units`) in Bn (the arriving block).
fn fixture(a_ts: &[u32], b_ts: &[u32], units: u32) -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDb::open(tmp.path()).unwrap());
    let mut st = RpcState::new(db.clone(), params());
    let store = BlockStore::new(&db);
    let (hash_g, work_g) = put_active(&store, 0, Hash256::ZERO, [0u8; 32], T0, 0xAA);
    // The coin tx1 spends: non-coinbase, created at the fork point.
    store
        .put_utxo(
            &OutPoint { txid: Hash256(SEED_TXID), vout: 0 },
            &CoinEntry { height: 0, is_coinbase: false, value: 10_000_000, script_pubkey: vec![0x51] },
        )
        .unwrap();
    let (mut tip, mut work) = (hash_g, work_g);
    for (i, ts) in a_ts.iter().enumerate() {
        (tip, work) = put_active(&store, i as u32 + 1, tip, work, *ts, 0xA0 + i as u8);
    }
    st.best_hash = tip;
    st.best_height = a_ts.len() as u32;
    let old_tip = (tip, a_ts.len() as u32);

    let n = b_ts.len() as u32;
    assert!(n >= 4, "tx1 sits in B3, tx2 in a later block");
    let (mut prev, mut prev_work) = (hash_g, work_g);
    let mut side = Vec::new();
    for h in 1..n {
        let extra = if h == 3 { vec![tx1()] } else { vec![] };
        let block = build(h, prev, b_ts[h as usize - 1], 0xB0 + h as u8, extra);
        (prev, prev_work) = put_side(&store, h, &block, prev_work);
        side.push((h, prev));
    }
    let arriving = build(n, prev, b_ts[n as usize - 1], 0xB0 + n as u8, vec![tx2(units)]);
    drop(store);
    Fixture { _tmp: tmp, db, st, old_tip, side, arriving, arriving_height: n }
}

fn attach(f: &mut Fixture) -> Result<bool, AttachReorgError> {
    let hash = f.arriving.block_hash();
    let block = f.arriving.clone();
    try_attach_and_reorg_detailed(&mut f.st, &block, &hash)
}

/// Core-INVALID reorg that master ACCEPTS.
///
/// A: A1 T0+1, A2 T0+2 (tip). B: B1 T0+10000, B2 T0+20000, B3 T0+20001 (tx1),
/// B4 T0+20002 (tx2, 30 units = 15360 s).
/// Core: coin time = MTP_B(2) = T0+10000; min_time = T0+25359 >= B4's prev
/// MTP T0+20000 -> bad-txns-nonfinal. Master read MTP_A(2) = T0+1, so
/// min_time = T0+15360 < T0+20000 and the lock looked satisfied.
#[test]
fn reorg_bip68_coin_time_uses_new_branch_ancestry() {
    let mut f = fixture(&[T0 + 1, T0 + 2], &[T0 + 10_000, T0 + 20_000, T0 + 20_001, T0 + 20_002], 30);
    let res = attach(&mut f);
    let err = match res {
        Err(e) => e,
        Ok(v) => panic!(
            "reorg onto B4 returned Ok({v}); Core rejects B4 with bad-txns-nonfinal \
             (coin time is MTP of B2, not of A2). Tip now {} @ {}",
            f.st.best_hash, f.st.best_height
        ),
    };
    assert!(
        err.reason.ends_with("bad-txns-nonfinal"),
        "expected a sequence-lock reject, got {:?}",
        err.reason
    );
    let inv = err.invalid.expect("a consensus verdict marks the branch");
    assert_eq!(inv.failed, f.arriving.block_hash(), "B4 is the invalid block");
    assert_eq!((f.st.best_hash, f.st.best_height), f.old_tip, "tip stays on A");
    let store = BlockStore::new(&f.db);
    assert_eq!(store.get_best_block_hash().unwrap().unwrap(), f.old_tip.0);
}

/// Mirror: Core-VALID reorg that master REJECTS.
///
/// A: A1 T0+30000, A2 T0+40000. B: B1 T0+1, B2 T0+2, B3 T0+50000 (tx1),
/// B4 T0+50001, B5 T0+50002, B6 T0+50003 (tx2, 60 units = 30720 s).
/// Core: coin time MTP_B(2) = T0+1, min_time = T0+30720 < B6's prev MTP
/// T0+50000 -> valid. Master used MTP_A(2) = T0+30000, min_time = T0+60719
/// -> bad-txns-nonfinal, and marked a valid branch failed.
#[test]
fn reorg_bip68_mirror_core_valid_block_is_accepted() {
    let b = [T0 + 1, T0 + 2, T0 + 50_000, T0 + 50_001, T0 + 50_002, T0 + 50_003];
    let mut f = fixture(&[T0 + 30_000, T0 + 40_000], &b, 60);
    let res = attach(&mut f);
    assert!(
        matches!(res, Ok(true)),
        "Core accepts B6 (coin time is MTP of B2 = T0+1); got {:?}",
        res.map_err(|e| e.reason)
    );
    let hash = f.arriving.block_hash();
    assert_eq!((f.st.best_hash, f.st.best_height), (hash, f.arriving_height));
    let store = BlockStore::new(&f.db);
    assert!(
        store.get_utxo(&OutPoint { txid: tx2(60).txid(), vout: 0 }).unwrap().is_some(),
        "tx2's output is in the UTXO set after the reorg"
    );
}

/// Longer branch: the coin-time height (2) is above the old tip (1), so the
/// height index has no row for it and master answered MissingAncestorHeader
/// (no verdict, no reorg) for a Core-valid block.
///
/// A: A1 T0+1. B: B1 T0+10, B2 T0+20, B3 T0+3000 (tx1), B4 T0+3001,
/// B5 T0+3002, B6 T0+3003 (tx2, 1 unit = 512 s).
/// Core: MTP_B(2) = T0+10, min_time = T0+521 < prev MTP T0+3000 -> valid.
#[test]
fn reorg_bip68_longer_branch_coin_above_old_tip() {
    let b = [T0 + 10, T0 + 20, T0 + 3_000, T0 + 3_001, T0 + 3_002, T0 + 3_003];
    let mut f = fixture(&[T0 + 1], &b, 1);
    let res = attach(&mut f);
    assert!(
        matches!(res, Ok(true)),
        "Core accepts B6; master returned {:?}",
        res.map_err(|e| e.reason)
    );
    assert_eq!(f.st.best_height, f.arriving_height);
}

/// P2P arm: header sync's `store_validated_header` (rustoshi/src/main.rs)
/// writes a height-index row for every header it accepts, so by the time
/// the P2P reorg arm calls `try_attach_and_reorg_detailed` the index already
/// maps the heavier branch. Simulate that and check the verdict is Core's.
/// This passes on master too: the P2P arm was masked, the RPC arms
/// (submitblock, invalidate/reconsider via activate_best_chain) were not.
#[test]
fn reorg_bip68_p2p_header_synced_index_matches_core() {
    let mut f = fixture(&[T0 + 1, T0 + 2], &[T0 + 10_000, T0 + 20_000, T0 + 20_001, T0 + 20_002], 30);
    {
        let store = BlockStore::new(&f.db);
        for (h, hash) in &f.side {
            store.put_height_index(*h, hash).unwrap();
        }
        store.put_header(&f.arriving.block_hash(), &f.arriving.header).unwrap();
        store.put_height_index(f.arriving_height, &f.arriving.block_hash()).unwrap();
    }
    let err = attach(&mut f).expect_err("Core rejects B4");
    assert!(err.reason.ends_with("bad-txns-nonfinal"), "{:?}", err.reason);
    assert_eq!((f.st.best_hash, f.st.best_height), f.old_tip);
}

/// Control: the same branches with a lock both MTPs satisfy (1 unit) reorg
/// on master and head alike, so the tests above fail on the coin time and
/// not on fixture construction.
#[test]
fn reorg_bip68_control_lock_met_under_both_branches() {
    let mut f = fixture(&[T0 + 1, T0 + 2], &[T0 + 10_000, T0 + 20_000, T0 + 20_001, T0 + 20_002], 1);
    let res = attach(&mut f);
    assert!(matches!(res, Ok(true)), "{:?}", res.map_err(|e| e.reason));
    assert_eq!(f.st.best_height, 4);
}
