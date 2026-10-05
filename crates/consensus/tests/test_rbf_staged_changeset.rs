//! RBF / TRUC evictions are STAGED, not applied, until every check passed.
//!
//! Core reference (validation.cpp): MemPoolAccept::ReplacementChecks stages
//! the eviction set into the CTxMemPool::ChangeSet (`StageRemoval`, ~1019);
//! PolicyScriptChecks (~1135) and ConsensusScriptChecks (~1158) run against
//! the UNMODIFIED pool; conflicts leave the pool only in FinalizeSubpackage →
//! `m_changeset->Apply()` (~1238); with `m_test_accept`
//! AcceptSingleTransactionInternal returns before Finalize (~1388), so a dry
//! run never mutates the pool.
//!
//! rustoshi a79ff94f called `remove_single` on the conflicts right after
//! check_rbf_rules — before the cluster gates, the script checks and the
//! test_accept early return. Consequences pinned here:
//!   1. a replacement with a BAD SIGNATURE (and a higher fee) evicted the
//!      honest original, then was itself rejected → original gone (DoS);
//!   2. testmempoolaccept of a valid replacement evicted live txs.
//!
//! Signatures are real (secp256k1, BIP-143 P2WPKH), so "bad signature" is
//! literally one flipped bit in a DER `r`, rejected by the production
//! STANDARD-flags script check — not a synthetic OP_1 placeholder.

use rustoshi_consensus::mempool::{AtmpOptions, Mempool, MempoolConfig, MempoolError};
use rustoshi_consensus::CoinEntry;
use rustoshi_crypto::{hash160, sighash::segwit_v0_sighash};
use rustoshi_primitives::{Hash256, OutPoint, Transaction, TxIn, TxOut};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use std::collections::HashMap;

const SIGHASH_ALL: u32 = 1;
const RBF_SEQ: u32 = 0xFFFF_FFFD;

struct Key {
    sk: SecretKey,
    pk: [u8; 33],
    h160: [u8; 20],
}

fn key(seed: u8) -> Key {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[seed; 32]).unwrap();
    let pk = PublicKey::from_secret_key(&secp, &sk).serialize();
    let h160 = *hash160(&pk).as_bytes();
    Key { sk, pk, h160 }
}

fn p2wpkh_spk(k: &Key) -> Vec<u8> {
    let mut v = vec![0x00, 0x14];
    v.extend_from_slice(&k.h160);
    v
}

fn p2wpkh_script_code(k: &Key) -> Vec<u8> {
    let mut v = vec![0x76, 0xa9, 0x14];
    v.extend_from_slice(&k.h160);
    v.extend_from_slice(&[0x88, 0xac]);
    v
}

fn hash_from_u8(b: u8) -> Hash256 {
    let mut arr = [0u8; 32];
    arr[0] = b;
    arr[31] = 0x5a;
    Hash256::from(arr)
}

/// Build a 1-in/1-out P2WPKH spend of `prev` (value `in_value`), paying
/// `in_value - fee` to `dest`, signed by `signer`. `corrupt` flips one bit of
/// the DER signature's `r` (still a well-formed, low-S, strict-DER encoding —
/// it simply does not verify).
fn signed_spend(
    prev: OutPoint,
    in_value: u64,
    fee: u64,
    signer: &Key,
    dest: &Key,
    corrupt: bool,
) -> Transaction {
    let mut tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: prev,
            script_sig: vec![],
            sequence: RBF_SEQ,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value: in_value - fee,
            script_pubkey: p2wpkh_spk(dest),
        }],
        lock_time: 0,
    };
    let sighash = segwit_v0_sighash(&tx, 0, &p2wpkh_script_code(signer), in_value, SIGHASH_ALL);
    let secp = Secp256k1::new();
    let msg = Message::from_digest_slice(sighash.as_bytes()).unwrap();
    let sig = secp.sign_ecdsa(&msg, &signer.sk);
    let mut der = sig.serialize_der().to_vec();
    if corrupt {
        // DER: 30 len 02 rlen r... ; flip the low bit of r's last byte.
        let rlen = der[3] as usize;
        der[4 + rlen - 1] ^= 0x01;
    }
    der.push(SIGHASH_ALL as u8);
    tx.inputs[0].witness = vec![der, signer.pk.to_vec()];
    tx
}

/// Production-shaped pool: verify_scripts ON (MempoolConfig::production()).
fn production_pool() -> Mempool {
    let mut mp = Mempool::new(MempoolConfig::production());
    mp.notify_new_tip(1_000, 1_700_000_000);
    mp
}

/// Everything observable about the pool's membership + per-entry bookkeeping.
fn snapshot(mp: &Mempool) -> Vec<(Hash256, Hash256, u64, usize, usize, usize)> {
    let mut v: Vec<_> = mp
        .collect_txid_wtxid()
        .into_iter()
        .map(|(t, w)| {
            let e = mp.get(&t).expect("entry");
            (t, w, e.fee, e.ancestor_count, e.descendant_count, e.vsize)
        })
        .collect();
    v.sort_by_key(|r| r.0);
    v
}

struct Fixture {
    utxos: HashMap<OutPoint, CoinEntry>,
    prev: OutPoint,
    alice: Key,
    bob: Key,
    carol: Key,
}

const IN_VALUE: u64 = 1_000_000;

fn fixture() -> Fixture {
    let alice = key(0x11);
    let bob = key(0x22);
    let carol = key(0x33);
    let prev = OutPoint { txid: hash_from_u8(0xa1), vout: 0 };
    let mut utxos = HashMap::new();
    utxos.insert(
        prev.clone(),
        CoinEntry { height: 500, is_coinbase: false, value: IN_VALUE, script_pubkey: p2wpkh_spk(&alice) },
    );
    Fixture { utxos, prev, alice, bob, carol }
}

/// Control for the signing helper itself: a correctly signed spend is admitted
/// by the script-verifying pool, and the SAME spend with the corrupted sig is
/// refused at the script gate. If the helper produced garbage, the first half
/// fails; if corruption did nothing, the second half fails.
#[test]
fn control_signing_helper_valid_admits_corrupt_rejects() {
    let f = fixture();
    let lookup = |op: &OutPoint| f.utxos.get(op).cloned();

    let mut mp = production_pool();
    let good = signed_spend(f.prev.clone(), IN_VALUE, 10_000, &f.alice, &f.bob, false);
    assert!(mp.add_transaction(good, &lookup).is_ok(), "validly signed spend must be admitted");

    let mut mp2 = production_pool();
    let bad = signed_spend(f.prev.clone(), IN_VALUE, 10_000, &f.alice, &f.bob, true);
    let r = mp2.add_transaction(bad, &lookup);
    assert!(
        matches!(r, Err(MempoolError::PolicyScriptCheckFailed(_, _))),
        "corrupted signature must fail the script gate; got {:?}",
        r
    );
    assert_eq!(mp2.size(), 0);
}

/// (1) DoS: a higher-fee replacement with a BAD SIGNATURE must be rejected
/// and must leave the original in the pool, untouched.
#[test]
fn bad_signature_replacement_does_not_evict_original() {
    let f = fixture();
    let lookup = |op: &OutPoint| f.utxos.get(op).cloned();
    let mut mp = production_pool();

    let original = signed_spend(f.prev.clone(), IN_VALUE, 10_000, &f.alice, &f.bob, false);
    let orig_txid = mp.add_transaction(original, &lookup).expect("original admitted");
    let before = snapshot(&mp);

    // Pays 5x the fee (passes every RBF fee rule) but the signature is bad.
    let attacker = signed_spend(f.prev.clone(), IN_VALUE, 50_000, &f.alice, &f.carol, true);
    let att_txid = attacker.txid();
    let r = mp.add_transaction(attacker, &lookup);
    assert!(
        matches!(r, Err(MempoolError::PolicyScriptCheckFailed(_, _))),
        "bad-sig replacement must be rejected at the script gate; got {:?}",
        r
    );
    assert!(mp.contains(&orig_txid), "the honest original was EVICTED by an invalid replacement");
    assert!(!mp.contains(&att_txid));
    assert_eq!(snapshot(&mp), before, "pool must be byte-for-byte unchanged");
}

/// Same, with descendants: the original has a child; neither may be lost.
#[test]
fn bad_signature_replacement_does_not_evict_original_or_descendants() {
    let f = fixture();
    let lookup = |op: &OutPoint| f.utxos.get(op).cloned();
    let mut mp = production_pool();

    let original = signed_spend(f.prev.clone(), IN_VALUE, 10_000, &f.alice, &f.bob, false);
    let orig_txid = mp.add_transaction(original, &lookup).expect("original admitted");
    let child = signed_spend(
        OutPoint { txid: orig_txid, vout: 0 },
        IN_VALUE - 10_000,
        10_000,
        &f.bob,
        &f.bob,
        false,
    );
    let child_txid = mp.add_transaction(child, &lookup).expect("child admitted");
    let before = snapshot(&mp);

    let attacker = signed_spend(f.prev.clone(), IN_VALUE, 100_000, &f.alice, &f.carol, true);
    assert!(mp.add_transaction(attacker, &lookup).is_err());
    assert!(mp.contains(&orig_txid) && mp.contains(&child_txid), "original + child must survive");
    assert_eq!(snapshot(&mp), before);
}

/// (2) testmempoolaccept (the RPC's exact options) of a VALID replacement
/// reports it acceptable and leaves the pool unchanged.
#[test]
fn testmempoolaccept_of_valid_replacement_does_not_mutate_pool() {
    let f = fixture();
    let lookup = |op: &OutPoint| f.utxos.get(op).cloned();
    let mut mp = production_pool();

    let original = signed_spend(f.prev.clone(), IN_VALUE, 10_000, &f.alice, &f.bob, false);
    let orig_txid = mp.add_transaction(original, &lookup).expect("original admitted");
    let before = snapshot(&mp);

    let replacement = signed_spend(f.prev.clone(), IN_VALUE, 50_000, &f.alice, &f.carol, false);
    let rep_txid = replacement.txid();
    // server.rs testmempoolaccept passes exactly these options.
    let r = mp.add_transaction_with_options(
        replacement.clone(),
        &lookup,
        AtmpOptions { force_script_checks: true, ..AtmpOptions::test_accept() },
    );
    assert_eq!(r.ok(), Some(rep_txid), "valid replacement must be reported acceptable");
    assert!(mp.contains(&orig_txid), "a DRY RUN evicted the original");
    assert!(!mp.contains(&rep_txid), "a dry run must not insert");
    assert_eq!(snapshot(&mp), before, "dry run mutated the pool");

    // ...and the real submission afterwards still works (state not corrupted).
    assert_eq!(mp.add_transaction(replacement, &lookup).ok(), Some(rep_txid));
    assert!(!mp.contains(&orig_txid) && mp.contains(&rep_txid));
}

/// Control: a valid replacement still replaces (conflict + descendants gone,
/// replacement in), so the fix did not just disable RBF.
#[test]
fn control_valid_replacement_still_replaces_with_descendants() {
    let f = fixture();
    let lookup = |op: &OutPoint| f.utxos.get(op).cloned();
    let mut mp = production_pool();

    let original = signed_spend(f.prev.clone(), IN_VALUE, 10_000, &f.alice, &f.bob, false);
    let orig_txid = mp.add_transaction(original, &lookup).expect("original admitted");
    let child = signed_spend(
        OutPoint { txid: orig_txid, vout: 0 },
        IN_VALUE - 10_000,
        10_000,
        &f.bob,
        &f.bob,
        false,
    );
    let child_txid = mp.add_transaction(child, &lookup).expect("child admitted");
    assert_eq!(mp.size(), 2);

    let replacement = signed_spend(f.prev.clone(), IN_VALUE, 100_000, &f.alice, &f.carol, false);
    let rep_txid = mp.add_transaction(replacement, &lookup).expect("valid replacement admitted");
    assert!(!mp.contains(&orig_txid) && !mp.contains(&child_txid));
    assert!(mp.contains(&rep_txid));
    assert_eq!(mp.size(), 1);
    // spent-outpoint index now points at the replacement: a third spend
    // conflicts with IT (and needs to beat its fee).
    let third = signed_spend(f.prev.clone(), IN_VALUE, 100_000, &f.alice, &f.bob, false);
    assert!(mp.add_transaction(third, &lookup).is_err(), "equal-fee third spend must not replace");
    assert!(mp.contains(&rep_txid));
}

/// Control: a replacement that FAILS an RBF fee rule never evicted anything,
/// before or after the fix (the rule runs before any removal in both).
#[test]
fn control_low_fee_replacement_rejected_original_kept() {
    let f = fixture();
    let lookup = |op: &OutPoint| f.utxos.get(op).cloned();
    let mut mp = production_pool();
    let original = signed_spend(f.prev.clone(), IN_VALUE, 10_000, &f.alice, &f.bob, false);
    let orig_txid = mp.add_transaction(original, &lookup).expect("original admitted");
    let low = signed_spend(f.prev.clone(), IN_VALUE, 5_000, &f.alice, &f.carol, false);
    assert!(matches!(
        mp.add_transaction(low, &lookup),
        Err(MempoolError::RbfInsufficientAbsoluteFee(_, _))
    ));
    assert!(mp.contains(&orig_txid));
}

/// Fan-out parent `P` (one input from alice, `n` P2WPKH outputs to bob of
/// `per_out` each), returned unsigned-by-pool.
fn fan_out_parent(f: &Fixture, n: usize, per_out: u64, fee: u64) -> Transaction {
    let mut tx = signed_spend(f.prev.clone(), IN_VALUE, fee, &f.alice, &f.bob, false);
    let total = per_out * n as u64;
    assert!(total + fee <= IN_VALUE);
    tx.outputs = (0..n)
        .map(|_| TxOut { value: per_out, script_pubkey: p2wpkh_spk(&f.bob) })
        .collect();
    // change back to alice so the fee is exactly `fee`
    tx.outputs.push(TxOut { value: IN_VALUE - total - fee, script_pubkey: p2wpkh_spk(&f.alice) });
    // re-sign over the final outputs
    tx.inputs[0].witness.clear();
    let sighash = segwit_v0_sighash(&tx, 0, &p2wpkh_script_code(&f.alice), IN_VALUE, SIGHASH_ALL);
    let secp = Secp256k1::new();
    let msg = Message::from_digest_slice(sighash.as_bytes()).unwrap();
    let mut der = secp.sign_ecdsa(&msg, &f.alice.sk).serialize_der().to_vec();
    der.push(SIGHASH_ALL as u8);
    tx.inputs[0].witness = vec![der, f.alice.pk.to_vec()];
    tx
}

/// The cluster gates now run BEFORE the staged removals are applied, so they
/// must be evaluated on the post-removal pool (Core: CheckMemPoolPolicyLimits
/// on the changeset). Cluster = P + 63 children = 64 = MAX_CLUSTER_SIZE.
///   * a replacement of child #0 (spends P:0) → post-removal cluster 64 → OK;
///     counting the staged-out child would give 65 and wrongly refuse it.
///   * a NON-conflicting 64th child (spends the unused P:63) → 65 → refused,
///     proving the gate really bites at this size (the first half is not
///     passing for want of a gate).
#[test]
fn cluster_gate_counts_the_post_replacement_pool() {
    let f = fixture();
    let lookup = |op: &OutPoint| f.utxos.get(op).cloned();
    let mut mp = production_pool();

    let p = fan_out_parent(&f, 64, 10_000, 20_000);
    let p_txid = mp.add_transaction(p, &lookup).expect("parent admitted");
    let mut kids = Vec::new();
    for i in 0..63u32 {
        let c = signed_spend(OutPoint { txid: p_txid, vout: i }, 10_000, 1_000, &f.bob, &f.bob, false);
        kids.push(mp.add_transaction(c, &lookup).expect("child admitted"));
    }
    assert_eq!(mp.size(), 64);

    // Gate bites: a 65th member is refused.
    let extra = signed_spend(OutPoint { txid: p_txid, vout: 63 }, 10_000, 1_000, &f.bob, &f.bob, false);
    let r = mp.add_transaction_with_options(
        extra,
        &lookup,
        AtmpOptions { force_script_checks: true, ..AtmpOptions::test_accept() },
    );
    assert!(
        matches!(r, Err(MempoolError::ClusterSizeLimitExceeded(65, 64))),
        "a 65th cluster member must be refused; got {:?}",
        r
    );

    // Replacing child #0 keeps the cluster at 64 → accepted (dry run first,
    // then for real), child #0 gone.
    let rep = signed_spend(OutPoint { txid: p_txid, vout: 0 }, 10_000, 3_000, &f.bob, &f.carol, false);
    let before = snapshot(&mp);
    let dry = mp.add_transaction_with_options(
        rep.clone(),
        &lookup,
        AtmpOptions { force_script_checks: true, ..AtmpOptions::test_accept() },
    );
    assert!(dry.is_ok(), "replacement inside a full cluster must be acceptable; got {:?}", dry);
    assert_eq!(snapshot(&mp), before);
    let rep_txid = mp.add_transaction(rep, &lookup).expect("replacement admitted");
    assert!(!mp.contains(&kids[0]) && mp.contains(&rep_txid));
    assert_eq!(mp.size(), 64);
}

/// Package path is NOT changed by this fix (add_transaction_for_package keeps
/// its own flow). Pin its observable behaviour on base and fix alike:
/// a parent+child package is admitted, and a package whose child replaces an
/// in-pool spend reports the replaced txid and evicts it.
#[test]
fn control_package_path_unchanged() {
    let f = fixture();
    let lookup = |op: &OutPoint| f.utxos.get(op).cloned();
    let mut mp = production_pool();

    let parent = signed_spend(f.prev.clone(), IN_VALUE, 1_000, &f.alice, &f.bob, false);
    let p_txid = parent.txid();
    let child = signed_spend(OutPoint { txid: p_txid, vout: 0 }, IN_VALUE - 1_000, 20_000, &f.bob, &f.bob, false);
    let c_txid = child.txid();
    let res = mp.accept_package(vec![parent.clone(), child], &lookup);
    assert_eq!(res.package_error, None, "{:?}", res.package_error);
    assert_eq!(res.accepted_count, 2);
    assert!(mp.contains(&p_txid) && mp.contains(&c_txid));

    // Fresh pool: an in-pool spend X of the confirmed coin, then a package
    // whose PARENT conflicts with X at a higher fee (no mempool ancestors, so
    // the package path's chain-only conflict lookup applies).
    let mut mp2 = production_pool();
    let x = signed_spend(f.prev.clone(), IN_VALUE, 5_000, &f.alice, &f.bob, false);
    let x_txid = mp2.add_transaction(x, &lookup).expect("X");
    let p2 = signed_spend(f.prev.clone(), IN_VALUE, 50_000, &f.alice, &f.carol, false);
    let p2_txid = p2.txid();
    let c2 = signed_spend(OutPoint { txid: p2_txid, vout: 0 }, IN_VALUE - 50_000, 5_000, &f.carol, &f.carol, false);
    let c2_txid = c2.txid();
    let res2 = mp2.accept_package(vec![p2, c2], &lookup);
    assert_eq!(res2.package_error, None, "{:?}", res2.package_error);
    assert!(mp2.contains(&p2_txid) && mp2.contains(&c2_txid) && !mp2.contains(&x_txid));
    let replaced: Vec<Hash256> = res2.tx_results.iter().flat_map(|r| r.replaced_txids.clone()).collect();
    assert_eq!(replaced, vec![x_txid]);
}
