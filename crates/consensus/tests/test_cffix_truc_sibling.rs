//! TRUC sibling eviction runs through the full RBF replacement set.
//!
//! Core reference (v31.1 `src/validation.cpp`): when `SingleTRUCChecks`
//! reports a sibling that may be evicted, `MemPoolAccept::PreChecks` adds it
//! to `ws.m_conflicts` / `ws.m_iters_conflicting` and sets
//! `ws.m_sibling_eviction`. `ReplacementChecks` then treats the sibling like
//! any other conflict: `GetEntriesForConflicts` (Rule 5), `PaysForRBF` over
//! the SUM of every evicted entry's modified fee (Rules 3/4), and
//! `ImprovesFeerateDiagram`. `AcceptSubPackage` of one transaction uses
//! `ATMPArgs::SingleInPackageAccept`, which also allows sibling eviction, so
//! the same rules hold when the child arrives as a one-new-tx package.
//!
//! rustoshi checked the sibling ad hoc (`fee > sibling_fee` plus bandwidth)
//! outside `check_rbf_rules` and `check_rbf_diagram`, and ran the diagram
//! check only when there were direct input conflicts. So a child that also
//! conflicted with an unrelated tx X only had to beat max(fee_X, fee_S), not
//! fee_X + fee_S, and a pure sibling eviction that worsened the feerate
//! diagram was accepted.

use rustoshi_consensus::mempool::{Mempool, MempoolConfig, MempoolError, TRUC_VERSION};
use rustoshi_consensus::CoinEntry;
use rustoshi_primitives::{Hash256, OutPoint, Transaction, TxIn, TxOut};
use std::collections::HashMap;

const P2PKH: [u8; 25] = [
    0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0xac,
];

fn confirmed(b: u8) -> OutPoint {
    let mut arr = [0u8; 32];
    arr[0] = b;
    arr[31] = 0x7c;
    OutPoint { txid: Hash256::from(arr), vout: 0 }
}

fn utxo_set(entries: &[(OutPoint, u64)]) -> HashMap<OutPoint, CoinEntry> {
    entries
        .iter()
        .map(|(op, value)| {
            (
                op.clone(),
                CoinEntry {
                    height: 1,
                    is_coinbase: false,
                    value: *value,
                    script_pubkey: P2PKH.to_vec(),
                },
            )
        })
        .collect()
}

fn tx(version: i32, inputs: &[OutPoint], outputs: &[u64]) -> Transaction {
    Transaction {
        version,
        inputs: inputs
            .iter()
            .map(|op| TxIn {
                previous_output: op.clone(),
                script_sig: vec![0x51],
                sequence: 0xFFFF_FFFD,
                witness: vec![],
            })
            .collect(),
        outputs: outputs
            .iter()
            .map(|v| TxOut { value: *v, script_pubkey: P2PKH.to_vec() })
            .collect(),
        lock_time: 0,
    }
}

fn out(txid: Hash256, vout: u32) -> OutPoint {
    OutPoint { txid, vout }
}

const U_PARENT: u8 = 1;
const U_X: u8 = 2;

/// Pool holding TRUC parent P (two outputs), its TRUC child S (spends P:0,
/// fee 10_000) and an unrelated low-feerate tx X (spends confirmed U_X,
/// fee 10_000).
struct SiblingAndConflict {
    pool: Mempool,
    utxos: HashMap<OutPoint, CoinEntry>,
    parent: Hash256,
    sibling: Hash256,
    x: Hash256,
}

fn sibling_and_conflict() -> SiblingAndConflict {
    let utxos = utxo_set(&[(confirmed(U_PARENT), 100_000), (confirmed(U_X), 100_000)]);
    let mut pool = Mempool::new(MempoolConfig::default());
    let lookup = |op: &OutPoint| utxos.get(op).cloned();

    // P: fee 2_000.
    let p = tx(TRUC_VERSION, &[confirmed(U_PARENT)], &[49_000, 49_000]);
    let parent = pool.add_transaction(p, &lookup).expect("parent P");
    // S: spends P:0, fee 10_000.
    let s = tx(TRUC_VERSION, &[out(parent, 0)], &[39_000]);
    let sibling = pool.add_transaction(s, &lookup).expect("sibling S");
    // X: unrelated, fee 10_000, ~2_000 vB (60 outputs) so its feerate
    // (~5 sat/vB) is low. That keeps the replacement's feerate diagram
    // better than the old one even when S is (wrongly) left out of the
    // eviction set, so the only thing separating accept from reject below
    // is whether S's fee is in the PaysForRBF sum.
    let x_tx = tx(2, &[confirmed(U_X)], &[1_500; 60]);
    assert!(x_tx.vsize() > 1_900, "X vsize {}", x_tx.vsize());
    let x = pool.add_transaction(x_tx, &lookup).expect("unrelated X");

    SiblingAndConflict { pool, utxos, parent, sibling, x }
}

/// N spends P:1 and X's input. `fee` is N's absolute fee.
fn child_with_conflict(parent: Hash256, fee: u64) -> Transaction {
    // Inputs: P:1 (49_000) + U_X (100_000).
    tx(TRUC_VERSION, &[out(parent, 1), confirmed(U_X)], &[149_000 - fee])
}

#[test]
fn truc_sibling_counts_in_rbf_fee_sum() {
    let mut f = sibling_and_conflict();
    let before = f.pool.size();
    let n = child_with_conflict(f.parent, 10_500);
    let utxos = f.utxos.clone();
    let result = f.pool.add_transaction(n, &|op: &OutPoint| utxos.get(op).cloned());

    // Evicting S and X takes 20_000 of modified fee out of the pool; 10_500
    // does not pay for it (Core PaysForRBF over all_conflicts).
    assert!(
        matches!(result, Err(MempoolError::RbfInsufficientAbsoluteFee(10_500, 20_000))),
        "N (10.5k) must pay for sibling S (10k) + conflict X (10k), got {:?}",
        result
    );
    assert_eq!(f.pool.size(), before, "a rejected replacement evicts nothing");
    assert!(f.pool.contains(&f.sibling));
    assert!(f.pool.contains(&f.x));
}

#[test]
fn truc_sibling_counts_in_rbf_fee_sum_package_path() {
    // Same shape submitted as a one-new-tx package (P already in the pool):
    // Core AcceptSubPackage -> SingleInPackageAccept runs the same
    // ReplacementChecks with the sibling in the conflict set.
    let mut f = sibling_and_conflict();
    let n = child_with_conflict(f.parent, 10_500);
    let p = f.pool.get(&f.parent).expect("P").tx.clone();
    let utxos = f.utxos.clone();
    let res = f.pool.accept_package(vec![p, n], &|op: &OutPoint| utxos.get(op).cloned());

    assert!(
        res.package_error.is_some(),
        "package must fail: N underpays S + X, got {:?}",
        res.tx_results.iter().map(|r| (&r.txid, &r.error)).collect::<Vec<_>>()
    );
    assert!(f.pool.contains(&f.sibling));
    assert!(f.pool.contains(&f.x));
}

#[test]
fn truc_sibling_plus_conflict_paying_the_sum_is_accepted() {
    // Positive control: paying both evictions plus bandwidth replaces both.
    let mut f = sibling_and_conflict();
    let n = child_with_conflict(f.parent, 22_000);
    let utxos = f.utxos.clone();
    let n_txid = f
        .pool
        .add_transaction(n, &|op: &OutPoint| utxos.get(op).cloned())
        .expect("N paying S + X + bandwidth is accepted");
    assert!(f.pool.contains(&n_txid));
    assert!(!f.pool.contains(&f.sibling), "sibling S evicted");
    assert!(!f.pool.contains(&f.x), "conflict X evicted");
    assert!(f.pool.contains(&f.parent));
}

/// Pool with TRUC parent P (fee 1_000) and a small high-feerate TRUC child S
/// (fee 10_000). Returns (pool, utxos, parent).
fn small_high_feerate_sibling() -> (Mempool, HashMap<OutPoint, CoinEntry>, Hash256, Hash256) {
    let utxos = utxo_set(&[(confirmed(U_PARENT), 100_000)]);
    let mut pool = Mempool::new(MempoolConfig::default());
    let lookup = |op: &OutPoint| utxos.get(op).cloned();
    let p = tx(TRUC_VERSION, &[confirmed(U_PARENT)], &[49_500, 49_500]);
    let parent = pool.add_transaction(p, &lookup).expect("parent P");
    let s = tx(TRUC_VERSION, &[out(parent, 0)], &[39_500]);
    let sibling = pool.add_transaction(s, &lookup).expect("sibling S");
    (pool, utxos, parent, sibling)
}

/// TRUC child of P:1 with `n_outputs` outputs and absolute `fee`.
fn wide_child(parent: Hash256, n_outputs: usize, fee: u64) -> Transaction {
    let total = 49_500 - fee;
    let each = total / n_outputs as u64;
    let mut outs = vec![each; n_outputs];
    outs[0] += total - each * n_outputs as u64;
    tx(TRUC_VERSION, &[out(parent, 1)], &outs)
}

#[test]
fn truc_sibling_eviction_must_improve_diagram() {
    let (mut pool, utxos, parent, sibling) = small_high_feerate_sibling();
    // ~900 vB child paying 11_000: more absolute fee than S (10_000) and
    // enough for bandwidth, but its feerate (~12 sat/vB) is far below S's
    // (~118 sat/vB), so the P+N chunk is worse than P+S at every size up to
    // P+S's — the diagram does not improve and Core rejects it
    // ("replacement-failed").
    let n = wide_child(parent, 25, 11_000);
    assert!(n.vsize() > 800 && n.vsize() <= 1_000, "vsize {}", n.vsize());
    let result = pool.add_transaction(n, &|op: &OutPoint| utxos.get(op).cloned());
    assert!(
        matches!(result, Err(MempoolError::RbfDiagramNotImproved)),
        "diagram-worsening sibling eviction must be rejected, got {:?}",
        result
    );
    assert!(pool.contains(&sibling), "sibling S stays");
}

#[test]
fn truc_sibling_eviction_improving_diagram_is_accepted() {
    // Positive control: same sibling, a small child paying more fee at a
    // higher feerate improves the diagram and evicts S.
    let (mut pool, utxos, parent, sibling) = small_high_feerate_sibling();
    let n = wide_child(parent, 1, 12_000);
    let n_txid = pool
        .add_transaction(n, &|op: &OutPoint| utxos.get(op).cloned())
        .expect("diagram-improving sibling eviction is accepted");
    assert!(pool.contains(&n_txid));
    assert!(!pool.contains(&sibling));
}
