//! Core v31.1 `PackageRBFChecks` (validation.cpp) for a 1-parent-1-child
//! `submitpackage`. Individual submission runs first; a reconsiderable fee
//! failure (including replacement "insufficient fee") is re-evaluated with
//! the child's fee. Strings are `PackageValidationState::ToString`.

use rustoshi_consensus::mempool::{Mempool, MempoolConfig, PackageAcceptResult};
use rustoshi_consensus::CoinEntry;
use rustoshi_primitives::{Hash256, OutPoint, Transaction, TxIn, TxOut};
use std::collections::HashMap;

fn hash_n(n: u16) -> Hash256 {
    let mut bytes = [0u8; 32];
    bytes[0] = (n & 0xff) as u8;
    bytes[1] = (n >> 8) as u8;
    Hash256::from(bytes)
}

fn p2pkh_spk() -> Vec<u8> {
    let mut s = vec![0x76, 0xa9, 0x14];
    s.extend_from_slice(&[0x11u8; 20]);
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

/// OP_RETURN push of `data_len` bytes (data_len <= 75).
fn op_return(data_len: usize) -> Vec<u8> {
    assert!(data_len <= 75);
    let mut s = vec![0x6a, data_len as u8];
    s.extend(std::iter::repeat(0u8).take(data_len));
    s
}

fn tx_with_outputs(
    inputs: &[(Hash256, u32)],
    outputs: &[(u64, Vec<u8>)],
) -> Transaction {
    Transaction {
        version: 2,
        inputs: inputs
            .iter()
            .map(|(txid, vout)| TxIn {
                previous_output: OutPoint {
                    txid: *txid,
                    vout: *vout,
                },
                script_sig: vec![0x51],
                sequence: 0xffff_ffff,
                witness: vec![],
            })
            .collect(),
        outputs: outputs
            .iter()
            .map(|(value, spk)| TxOut {
                value: *value,
                script_pubkey: spk.clone(),
            })
            .collect(),
        lock_time: 0,
    }
}

/// One-input tx whose non-witness vsize is exactly `target`.
/// A bare P2PKH spend is 86 vbytes; the pad is a 0-value OP_RETURN.
fn sized_tx(prev: Hash256, value_in: u64, fee: u64, target: usize) -> Transaction {
    let mut tx = tx_with_outputs(&[(prev, 0)], &[(value_in - fee, p2pkh_spk())]);
    let base = tx.vsize();
    assert!(target >= base, "base vsize {base} already above {target}");
    let extra = target - base;
    // A second output adds 8 (value) + 1 (script compact size) + script.
    // script = OP_RETURN + direct push + data, so script len = 2 + data_len
    // and the added size is 11 + data_len while the output count stays one byte.
    assert!(extra >= 11, "cannot pad {extra} bytes");
    let data_len = extra - 11;
    tx.outputs.push(TxOut {
        value: 0,
        script_pubkey: op_return(data_len),
    });
    assert_eq!(tx.vsize(), target, "pad missed target");
    tx
}

fn pool() -> Mempool {
    Mempool::new(MempoolConfig::default())
}

fn accept(mp: &mut Mempool, txs: Vec<Transaction>, utxos: &HashMap<OutPoint, CoinEntry>) -> PackageAcceptResult {
    mp.accept_package(txs, &|op| utxos.get(op).cloned())
}

fn replaced_union(res: &PackageAcceptResult) -> Vec<Hash256> {
    let mut ids: Vec<Hash256> = res.tx_results.iter().flat_map(|r| r.replaced_txids.clone()).collect();
    ids.sort();
    ids
}

/// Original fee 10000. Package parent fee 10001 vsize 110, child fee 50000
/// vsize 110. Core accepts both at the package feerate and evicts the original.
#[test]
fn test_package_rbf_1p1c_success() {
    let mut mp = pool();
    let prev = hash_n(1);
    let value = 1_000_000u64;
    let utxos: HashMap<_, _> = [(OutPoint { txid: prev, vout: 0 }, coin(value))]
        .into_iter()
        .collect();
    let original = sized_tx(prev, value, 10_000, 110);
    let first = accept(&mut mp, vec![original.clone()], &utxos);
    assert!(first.all_accepted(), "{:?}", first.package_error);
    assert!(mp.contains(&original.txid()));

    let parent = sized_tx(prev, value, 10_001, 110);
    let child = sized_tx(parent.txid(), value - 10_001, 50_000, 110);
    assert_eq!(parent.vsize(), 110);
    assert_eq!(child.vsize(), 110);
    let res = accept(&mut mp, vec![parent.clone(), child.clone()], &utxos);

    assert_eq!(res.package_error, None, "{:?}", res.package_error);
    assert!(res.tx_results.iter().all(|r| r.error.is_none()), "{:?}", res.tx_results);
    let includes = vec![parent.wtxid(), child.wtxid()];
    for (r, tx) in res.tx_results.iter().zip([&parent, &child]) {
        assert_eq!(r.txid, tx.txid());
        assert_eq!(r.effective_fee_sat_per_kvb, Some(272_731), "{r:?}");
        assert_eq!(r.effective_includes.as_ref(), Some(&includes), "{r:?}");
    }
    // Core moves the replaced-tx vector onto the first subpackage result.
    assert_eq!(res.tx_results[0].replaced_txids, vec![original.txid()]);
    assert!(res.tx_results[1].replaced_txids.is_empty(), "{:?}", res.tx_results[1].replaced_txids);
    assert_eq!(replaced_union(&res), vec![original.txid()]);
    assert!(!mp.contains(&original.txid()));
    assert!(mp.contains(&parent.txid()));
    assert!(mp.contains(&child.txid()));
}

/// Child fee does not cover incremental relay against the conflict.
/// Package reason is anti-DoS; per-tx errors stay the individual ToStrings.
#[test]
fn test_package_rbf_insufficient_anti_dos() {
    let mut mp = pool();
    let prev = hash_n(2);
    let value = 1_000_000u64;
    let utxos: HashMap<_, _> = [(OutPoint { txid: prev, vout: 0 }, coin(value))]
        .into_iter()
        .collect();
    let original = sized_tx(prev, value, 10_000, 110);
    assert!(accept(&mut mp, vec![original.clone()], &utxos).all_accepted());

    let parent = sized_tx(prev, value, 10_001, 110);
    let child = sized_tx(parent.txid(), value - 10_001, 10, 110);
    let res = accept(&mut mp, vec![parent.clone(), child.clone()], &utxos);

    let expect = format!(
        "package RBF failed: insufficient anti-DoS fees, rejecting replacement {}, not enough additional fees to relay; 0.00000011 < 0.00000022",
        child.txid()
    );
    assert_eq!(res.package_error.as_deref(), Some(expect.as_str()), "{res:?}");
    assert_eq!(
        res.tx_results[0].error.as_deref(),
        Some(
            format!(
                "insufficient fee, rejecting replacement {}, not enough additional fees to relay; 0.00000001 < 0.00000011",
                parent.txid()
            )
            .as_str()
        ),
        "{:?}",
        res.tx_results[0].error
    );
    assert_eq!(
        res.tx_results[1].error.as_deref(),
        Some("bad-txns-inputs-missingorspent")
    );
    assert!(replaced_union(&res).is_empty(), "{:?}", replaced_union(&res));
    assert!(mp.contains(&original.txid()));
    assert!(!mp.contains(&parent.txid()));
    assert!(!mp.contains(&child.txid()));
    assert_eq!(mp.size(), 1);
}

/// Anti-DoS passes and the package feerate is still at or below the parent.
#[test]
fn test_package_rbf_feerate_le_parent() {
    let mut mp = pool();
    let prev = hash_n(3);
    let value = 1_000_000u64;
    let utxos: HashMap<_, _> = [(OutPoint { txid: prev, vout: 0 }, coin(value))]
        .into_iter()
        .collect();
    let original = sized_tx(prev, value, 10_000, 110);
    assert!(accept(&mut mp, vec![original.clone()], &utxos).all_accepted());

    let parent = sized_tx(prev, value, 10_001, 110);
    // Total fee 10022, vsize 220. Additional 22 is not strictly below
    // GetFee(220)=22, so PaysForRBF passes and the feerate compare rejects.
    let child = sized_tx(parent.txid(), value - 10_001, 21, 110);
    let res = accept(&mut mp, vec![parent.clone(), child.clone()], &utxos);

    let expect = format!(
        "package RBF failed: package feerate is less than or equal to parent feerate, package feerate 0.00045554 BTC/kvB <= parent feerate is 0.00090918 BTC/kvB"
    );
    assert_eq!(res.package_error.as_deref(), Some(expect.as_str()), "{res:?}");
    assert_eq!(
        res.tx_results[0].error.as_deref(),
        Some(
            format!(
                "insufficient fee, rejecting replacement {}, not enough additional fees to relay; 0.00000001 < 0.00000011",
                parent.txid()
            )
            .as_str()
        )
    );
    assert_eq!(
        res.tx_results[1].error.as_deref(),
        Some("bad-txns-inputs-missingorspent")
    );
    assert!(mp.contains(&original.txid()));
    assert!(!mp.contains(&parent.txid()));
    assert!(!mp.contains(&child.txid()));
}

/// Each tx is under the 100-cluster cap; the union is not.
/// Parent conflicts with 60 singleton clusters, the child with 50 others.
#[test]
fn test_package_rbf_too_many_clusters() {
    let mut mp = pool();
    let value = 50_000u64;
    let mut utxos = HashMap::new();
    let mut conflicts = Vec::new();
    for i in 0..110u16 {
        let prev = hash_n(1000 + i);
        utxos.insert(OutPoint { txid: prev, vout: 0 }, coin(value));
        let tx = tx_with_outputs(&[(prev, 0)], &[(value - 1_000, p2pkh_spk())]);
        assert_eq!(value - (value - 1_000), 1_000);
        conflicts.push(tx);
    }
    for tx in &conflicts {
        let res = accept(&mut mp, vec![tx.clone()], &utxos);
        assert!(res.all_accepted(), "{:?}", res.package_error);
    }
    assert_eq!(mp.size(), 110);

    let parent_inputs: Vec<(Hash256, u32)> = conflicts[..60]
        .iter()
        .map(|tx| (tx.inputs[0].previous_output.txid, 0))
        .collect();
    let parent_in = 60 * value;
    let parent_fee = 10_001u64;
    let parent = tx_with_outputs(&parent_inputs, &[(parent_in - parent_fee, p2pkh_spk())]);

    let mut child_inputs = vec![(parent.txid(), 0)];
    child_inputs.extend(
        conflicts[60..]
            .iter()
            .map(|tx| (tx.inputs[0].previous_output.txid, 0)),
    );
    let child_in = (parent_in - parent_fee) + 50 * value;
    let child = tx_with_outputs(&child_inputs, &[(child_in - 50_000, p2pkh_spk())]);

    let res = accept(&mut mp, vec![parent.clone(), child.clone()], &utxos);
    let expect = format!(
        "package RBF failed: too many potential replacements, rejecting replacement {}; too many conflicting clusters (110 > 100)",
        child.txid()
    );
    assert_eq!(res.package_error.as_deref(), Some(expect.as_str()), "{res:?}");
    assert_eq!(
        res.tx_results[0].error.as_deref(),
        Some(
            format!(
                "insufficient fee, rejecting replacement {}, less fees than conflicting txs; 0.00010001 < 0.0006",
                parent.txid()
            )
            .as_str()
        ),
        "{:?}",
        res.tx_results[0].error
    );
    assert_eq!(
        res.tx_results[1].error.as_deref(),
        Some("bad-txns-inputs-missingorspent")
    );
    assert_eq!(mp.size(), 110);
    assert!(!mp.contains(&parent.txid()));
    assert!(!mp.contains(&child.txid()));
    assert!(mp.contains(&conflicts[0].txid()));
}

/// Two below-min-relay parents plus a child that also conflicts is not 1p1c.
#[test]
fn test_package_rbf_not_1p1c() {
    let mut mp = pool();
    let p1_prev = hash_n(10);
    let p2_prev = hash_n(11);
    let conflict_prev = hash_n(12);
    let value = 200_000u64;
    let utxos: HashMap<_, _> = [
        (OutPoint { txid: p1_prev, vout: 0 }, coin(value)),
        (OutPoint { txid: p2_prev, vout: 0 }, coin(value)),
        (OutPoint { txid: conflict_prev, vout: 0 }, coin(value)),
    ]
    .into_iter()
    .collect();
    let occupant = tx_with_outputs(&[(conflict_prev, 0)], &[(value - 10_000, p2pkh_spk())]);
    assert!(accept(&mut mp, vec![occupant.clone()], &utxos).all_accepted());

    let parent_a = tx_with_outputs(&[(p1_prev, 0)], &[(value - 1, p2pkh_spk())]);
    let parent_b = tx_with_outputs(&[(p2_prev, 0)], &[(value - 1, p2pkh_spk())]);
    let child_in = (value - 1) + (value - 1) + value;
    let child = tx_with_outputs(
        &[
            (parent_a.txid(), 0),
            (parent_b.txid(), 0),
            (conflict_prev, 0),
        ],
        &[(child_in - 20_000, p2pkh_spk())],
    );
    let req = (100u64 * parent_a.vsize() as u64 + 999) / 1000;
    assert!(req > 1, "parent fee 1 must miss min relay, vsize {}", parent_a.vsize());

    let res = accept(
        &mut mp,
        vec![parent_a.clone(), parent_b.clone(), child.clone()],
        &utxos,
    );
    assert_eq!(
        res.package_error.as_deref(),
        Some("package RBF failed: package must be 1-parent-1-child"),
        "{res:?}"
    );
    let parent_err = format!("min relay fee not met, 1 < {req}");
    assert_eq!(res.tx_results[0].error.as_deref(), Some(parent_err.as_str()));
    assert_eq!(res.tx_results[1].error.as_deref(), Some(parent_err.as_str()));
    assert_eq!(
        res.tx_results[2].error.as_deref(),
        Some("bad-txns-inputs-missingorspent")
    );
    assert!(mp.contains(&occupant.txid()));
    assert!(!mp.contains(&parent_a.txid()));
    assert!(!mp.contains(&child.txid()));
    assert_eq!(mp.size(), 1);
}

/// Package fee beats the conflict on base fee but not its prioritised fee,
/// and the chunk diagram is worse at the conflict's size.
#[test]
fn test_package_rbf_diagram_and_modified_conflict_fee() {
    let mut mp = pool();
    let prev = hash_n(20);
    let value = 1_000_000u64;
    let utxos: HashMap<_, _> = [(OutPoint { txid: prev, vout: 0 }, coin(value))]
        .into_iter()
        .collect();
    // Unpadded singleton: fee 50000 on ~86 vB. The package chunk is larger
    // in absolute fee and lower in feerate, so CompareChunks is unordered.
    let original = tx_with_outputs(&[(prev, 0)], &[(value - 50_000, p2pkh_spk())]);
    assert!(accept(&mut mp, vec![original.clone()], &utxos).all_accepted());

    let parent = sized_tx(prev, value, 10_001, 110);
    let child = sized_tx(parent.txid(), value - 10_001, 45_000, 110);
    let res = accept(&mut mp, vec![parent.clone(), child.clone()], &utxos);
    assert_eq!(
        res.package_error.as_deref(),
        Some("package RBF failed: insufficient feerate: does not improve feerate diagram"),
        "{res:?}"
    );
    assert_eq!(
        res.tx_results[0].error.as_deref(),
        Some(
            format!(
                "insufficient fee, rejecting replacement {}, less fees than conflicting txs; 0.00010001 < 0.0005",
                parent.txid()
            )
            .as_str()
        ),
        "{:?}",
        res.tx_results[0].error
    );
    assert!(mp.contains(&original.txid()));
    assert!(!mp.contains(&parent.txid()));

    // Same shape, but prioritisetransaction lifts the original above the
    // package's total fee. PaysForRBF reports the modified fees.
    let prev2 = hash_n(21);
    let utxos2: HashMap<_, _> = [(OutPoint { txid: prev2, vout: 0 }, coin(value))]
        .into_iter()
        .collect();
    let original2 = sized_tx(prev2, value, 10_000, 110);
    assert!(accept(&mut mp, vec![original2.clone()], &utxos2).all_accepted());
    mp.prioritise_transaction(&original2.txid(), 60_000);
    let parent2 = sized_tx(prev2, value, 10_001, 110);
    let child2 = sized_tx(parent2.txid(), value - 10_001, 50_000, 110);
    let res2 = accept(&mut mp, vec![parent2.clone(), child2.clone()], &utxos2);
    let expect = format!(
        "package RBF failed: insufficient anti-DoS fees, rejecting replacement {}, less fees than conflicting txs; 0.00060001 < 0.0007",
        child2.txid()
    );
    assert_eq!(res2.package_error.as_deref(), Some(expect.as_str()), "{res2:?}");
    assert!(mp.contains(&original2.txid()));
    assert!(!mp.contains(&parent2.txid()));
    assert!(!mp.contains(&child2.txid()));
}
