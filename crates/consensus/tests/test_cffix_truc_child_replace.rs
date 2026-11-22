//! TRUC (BIP 431) descendant limit when the existing child is being replaced.
//!
//! Core v31.1 `SingleTRUCChecks` (src/policy/truc_policy.cpp) computes
//! `child_will_be_replaced`: if any in-mempool descendant of the TRUC parent is
//! a direct conflict of the new transaction, the parent's descendant count is
//! not double-counted and the "would exceed descendant count limit" error is
//! skipped. The replacement then goes through the normal RBF rules.
//!
//! Before this fix rustoshi skipped such a child only inside its
//! sibling-eviction search and then fell through to `TrucTooManyDescendants`,
//! so a TRUC child could never be fee-bumped by a replacement spending the
//! same parent output (the P2A anchor-pinning shape).

use rustoshi_consensus::mempool::{
    AtmpOptions, Mempool, MempoolConfig, MempoolError, PackageAcceptResult, TRUC_VERSION,
};
use rustoshi_consensus::CoinEntry;
use rustoshi_primitives::{Hash256, OutPoint, Transaction, TxIn, TxOut};
use std::collections::HashMap;

fn hash_from_u8(b: u8) -> Hash256 {
    let mut arr = [0u8; 32];
    arr[0] = b;
    Hash256::from(arr)
}

fn p2pkh_spk() -> Vec<u8> {
    let mut s = vec![0x76u8, 0xa9, 0x14];
    s.extend_from_slice(&[0x42u8; 20]);
    s.push(0x88);
    s.push(0xac);
    s
}

fn coin(value: u64) -> CoinEntry {
    CoinEntry {
        height: 100,
        is_coinbase: false,
        value,
        script_pubkey: p2pkh_spk(),
    }
}

/// v3 tx spending `inputs`, paying `outputs` (all P2PKH).
fn v3_tx(inputs: &[(Hash256, u32)], outputs: &[u64]) -> Transaction {
    Transaction {
        version: TRUC_VERSION,
        inputs: inputs
            .iter()
            .map(|(txid, vout)| TxIn {
                previous_output: OutPoint { txid: *txid, vout: *vout },
                script_sig: vec![0x51],
                sequence: 0xffff_ffff,
                witness: vec![],
            })
            .collect(),
        outputs: outputs
            .iter()
            .map(|v| TxOut { value: *v, script_pubkey: p2pkh_spk() })
            .collect(),
        lock_time: 0,
    }
}

fn test_mempool() -> Mempool {
    Mempool::new(MempoolConfig { verify_scripts: false, ..Default::default() })
}

fn test_opts() -> AtmpOptions {
    AtmpOptions { skip_script_checks: true, require_standard: false, ..Default::default() }
}

fn mp_add(
    mp: &mut Mempool,
    tx: Transaction,
    utxos: &HashMap<OutPoint, CoinEntry>,
) -> Result<Hash256, MempoolError> {
    mp.add_transaction_with_options(tx, &|op| utxos.get(op).cloned(), test_opts())
}

/// Parent P (v3, two outputs) in mempool plus child A spending P:0.
fn setup() -> (Mempool, HashMap<OutPoint, CoinEntry>, Hash256, Hash256) {
    let mut mp = test_mempool();
    let utxo = OutPoint { txid: hash_from_u8(0x71), vout: 0 };
    let utxos: HashMap<OutPoint, CoinEntry> = [(utxo.clone(), coin(1_000_000))].into_iter().collect();

    let parent = v3_tx(&[(utxo.txid, 0)], &[400_000, 400_000]);
    let parent_txid = mp_add(&mut mp, parent, &utxos).expect("parent accepted");

    let child_a = v3_tx(&[(parent_txid, 0)], &[399_000]); // fee 1_000
    let a_txid = mp_add(&mut mp, child_a, &utxos).expect("child A accepted");
    (mp, utxos, parent_txid, a_txid)
}

/// The item's test: B spends the same parent output as A with a higher fee.
/// Core accepts B and evicts A; master returned `TrucTooManyDescendants`.
#[test]
fn truc_child_same_input_replacement_accepted() {
    let (mut mp, utxos, parent_txid, a_txid) = setup();

    let child_b = v3_tx(&[(parent_txid, 0)], &[380_000]); // fee 20_000
    let b_txid = child_b.txid();
    let res = mp_add(&mut mp, child_b, &utxos);

    assert!(
        matches!(res, Ok(id) if id == b_txid),
        "replacement of the TRUC parent's only child must pass the descendant limit \
         (Core child_will_be_replaced) and be accepted under RBF, got {:?}",
        res
    );
    assert!(!mp.contains(&a_txid), "child A must be evicted by the replacement");
    assert!(mp.contains(&b_txid), "replacement B must be in the mempool");
    assert!(mp.contains(&parent_txid), "parent must remain");
    assert_eq!(mp.size(), 2);
}

/// Skipping the descendant limit must hand the decision to RBF, not bypass it:
/// a same-input replacement that does not pay more is still rejected, by an RBF
/// fee rule rather than the TRUC descendant limit, and A stays.
#[test]
fn truc_child_same_input_replacement_still_needs_rbf_fees() {
    let (mut mp, utxos, parent_txid, a_txid) = setup();

    let child_b = v3_tx(&[(parent_txid, 0)], &[399_500]); // fee 500 < A's 1_000
    let b_txid = child_b.txid();
    let res = mp_add(&mut mp, child_b, &utxos);

    assert!(res.is_err(), "low-fee replacement must be rejected, got {:?}", res);
    assert!(
        !matches!(res, Err(MempoolError::TrucTooManyDescendants(_))),
        "rejection must come from the RBF rules, not the TRUC descendant limit: {:?}",
        res
    );
    assert!(mp.contains(&a_txid), "A must survive a failed replacement");
    assert!(!mp.contains(&b_txid));
}

/// A child that does NOT conflict with A (spends P:1) is still sibling
/// eviction territory: unchanged behaviour, A evicted when B pays enough.
#[test]
fn truc_non_conflicting_sibling_eviction_unchanged() {
    let (mut mp, utxos, parent_txid, a_txid) = setup();

    let child_b = v3_tx(&[(parent_txid, 1)], &[380_000]); // fee 20_000
    let b_txid = child_b.txid();
    let res = mp_add(&mut mp, child_b, &utxos);

    assert!(matches!(res, Ok(id) if id == b_txid), "sibling eviction must still work: {:?}", res);
    assert!(!mp.contains(&a_txid));
    assert!(mp.contains(&b_txid));
}

/// The package path calls the same `check_truc_policy`. Its input resolver
/// treats a conflict on a mempool parent's output as missing inputs (a separate
/// rule, see `add_transaction_for_package`), so the conflict here is on a chain
/// UTXO both children spend: A spends P:0 + U2, B spends P:1 + U2. B's mempool
/// parent is P, A is P's only child and B's direct conflict, so Core's
/// `child_will_be_replaced` holds and B is accepted under RBF.
fn setup_shared_chain_input() -> (Mempool, HashMap<OutPoint, CoinEntry>, Hash256, Hash256, Hash256) {
    let mut mp = test_mempool();
    let u1 = OutPoint { txid: hash_from_u8(0x72), vout: 0 };
    let u2 = OutPoint { txid: hash_from_u8(0x73), vout: 0 };
    let utxos: HashMap<OutPoint, CoinEntry> =
        [(u1.clone(), coin(1_000_000)), (u2.clone(), coin(100_000))].into_iter().collect();

    let parent = v3_tx(&[(u1.txid, 0)], &[400_000, 400_000]);
    let parent_txid = mp_add(&mut mp, parent, &utxos).expect("parent accepted");

    let child_a = v3_tx(&[(parent_txid, 0), (u2.txid, 0)], &[499_000]); // fee 1_000
    let a_txid = mp_add(&mut mp, child_a, &utxos).expect("child A accepted");
    (mp, utxos, parent_txid, a_txid, u2.txid)
}

#[test]
fn truc_child_shared_chain_input_replacement_accepted() {
    let (mut mp, utxos, parent_txid, a_txid, u2) = setup_shared_chain_input();

    let child_b = v3_tx(&[(parent_txid, 1), (u2, 0)], &[480_000]); // fee 20_000
    let b_txid = child_b.txid();
    let res = mp_add(&mut mp, child_b, &utxos);

    assert!(matches!(res, Ok(id) if id == b_txid), "got {:?}", res);
    assert!(!mp.contains(&a_txid));
    assert!(mp.contains(&b_txid));
}

#[test]
fn truc_child_same_input_replacement_accepted_via_package() {
    let (mut mp, utxos, parent_txid, a_txid, u2) = setup_shared_chain_input();

    let child_b = v3_tx(&[(parent_txid, 1), (u2, 0)], &[480_000]); // fee 20_000
    let b_txid = child_b.txid();
    let res: PackageAcceptResult = mp.accept_package_with_options(
        vec![child_b],
        &|op| utxos.get(op).cloned(),
        test_opts(),
    );

    assert!(
        mp.contains(&b_txid) && !mp.contains(&a_txid),
        "package path must accept the replacement of the TRUC parent's only child and evict A, got {:?}",
        res
    );
}
