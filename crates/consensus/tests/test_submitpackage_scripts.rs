//! `submitpackage` must run Bitcoin Core v31.1 script checks on every package tx.
//!
//! Core (`validation.cpp`, tag v31.1):
//! `ProcessNewPackage` → `MemPoolAccept::AcceptPackage` /
//! `AcceptMultipleTransactionsInternal` calls `PolicyScriptChecks` (standard
//! flags, ~1139) then `ConsensusScriptChecks` (block flags, ~1162) for each
//! package transaction before `SubmitPackage` inserts it. `CheckInputScripts`
//! (~2123) rejects a standard-flag failure as
//! `mempool-script-verify-flag-failed (<ScriptErrorString>), <debug>`.
//! `rpc/mempool.cpp` `submitpackage` puts that `TxValidationState::ToString()`
//! on the failing wtxid in `tx-results` and sets `package_msg` from
//! `PackageValidationState` (`PCKG_TX` → `"transaction failed"`). A parent
//! that already passed on its own stays in the mempool; the bad tx does not.
//!
//! Pre-fix, `Mempool::accept_package` → `add_transaction_for_package` never
//! calls those checks, so a structurally valid parent+child whose signature
//! does not verify is admitted.

use rustoshi_consensus::mempool::{AtmpOptions, Mempool, MempoolConfig};
use rustoshi_consensus::CoinEntry;
use rustoshi_crypto::{hash160, sighash::segwit_v0_sighash};
use rustoshi_primitives::{Hash256, OutPoint, Transaction, TxIn, TxOut};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use std::collections::HashMap;

const SIGHASH_ALL: u32 = 1;

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

/// 1-in/1-out P2WPKH spend. `corrupt` flips one bit of a strict-DER `r` so the
/// witness is still well-formed (2 stack items) but CHECKSIG fails NULLFAIL.
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
            sequence: 0xffff_fffd,
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
    let mut der = secp.sign_ecdsa(&msg, &signer.sk).serialize_der().to_vec();
    if corrupt {
        let rlen = der[3] as usize;
        der[4 + rlen - 1] ^= 0x01;
    }
    der.push(SIGHASH_ALL as u8);
    tx.inputs[0].witness = vec![der, signer.pk.to_vec()];
    tx
}

fn production_pool() -> Mempool {
    let mut mp = Mempool::new(MempoolConfig::production());
    mp.notify_new_tip(1_000, 1_700_000_000);
    mp
}

struct Fixture {
    utxos: HashMap<OutPoint, CoinEntry>,
    prev: OutPoint,
    alice: Key,
    bob: Key,
}

const IN_VALUE: u64 = 1_000_000;

fn fixture() -> Fixture {
    let alice = key(0x11);
    let bob = key(0x22);
    let prev = OutPoint {
        txid: hash_from_u8(0xa1),
        vout: 0,
    };
    let mut utxos = HashMap::new();
    utxos.insert(
        prev.clone(),
        CoinEntry {
            height: 500,
            is_coinbase: false,
            value: IN_VALUE,
            script_pubkey: p2wpkh_spk(&alice),
        },
    );
    Fixture {
        utxos,
        prev,
        alice,
        bob,
    }
}

fn core_script_error(tx: &Transaction, spent: &Hash256) -> String {
    format!(
        "mempool-script-verify-flag-failed (Signature must be zero for failed CHECK(MULTI)SIG operation), input 0 of {} (wtxid {}), spending {}:0",
        tx.txid(),
        tx.wtxid(),
        spent,
    )
}

/// Invalid-signature child: parent pays its own relay fee and is valid; the
/// child witness is a well-formed P2WPKH stack whose signature does not verify.
#[test]
fn submitpackage_invalid_signature_child_rejected_with_core_script_error() {
    let f = fixture();
    let lookup = |op: &OutPoint| f.utxos.get(op).cloned();
    let mut mp = production_pool();

    let parent = signed_spend(f.prev.clone(), IN_VALUE, 10_000, &f.alice, &f.bob, false);
    let parent_txid = parent.txid();
    let child = signed_spend(
        OutPoint {
            txid: parent_txid,
            vout: 0,
        },
        IN_VALUE - 10_000,
        10_000,
        &f.bob,
        &f.bob,
        true,
    );
    let child_txid = child.txid();
    let expected = core_script_error(&child, &parent_txid);

    let res = mp.accept_package(vec![parent, child], &lookup);
    assert!(
        !res.all_accepted(),
        "package with an invalid-signature child must be rejected; package_error={:?} errors={:?}",
        res.package_error,
        res.tx_results
            .iter()
            .map(|r| (r.txid, r.error.clone()))
            .collect::<Vec<_>>()
    );
    assert_eq!(res.package_error.as_deref(), Some("transaction failed"));
    assert!(
        mp.contains(&parent_txid),
        "a parent that is valid on its own stays in the mempool (Core AcceptPackage)"
    );
    assert!(
        !mp.contains(&child_txid),
        "invalid-signature child must not enter the mempool"
    );
    let child_err = res
        .tx_results
        .iter()
        .find(|r| r.txid == child_txid)
        .and_then(|r| r.error.clone())
        .unwrap_or_default();
    assert_eq!(
        child_err, expected,
        "tx-results error must be Core CheckInputScripts / PolicyScriptChecks"
    );
}

/// Invalid-signature parent: the parent is the bad tx. The child spends it, so
/// Core reports the parent's script error and `bad-txns-inputs-missingorspent`
/// for the child (`PreChecks`, validation.cpp:873). Neither enters the mempool.
#[test]
fn submitpackage_invalid_signature_parent_rejected_with_core_script_error() {
    let f = fixture();
    let lookup = |op: &OutPoint| f.utxos.get(op).cloned();
    let mut mp = production_pool();

    let parent = signed_spend(f.prev.clone(), IN_VALUE, 10_000, &f.alice, &f.bob, true);
    let parent_txid = parent.txid();
    let child = signed_spend(
        OutPoint {
            txid: parent_txid,
            vout: 0,
        },
        IN_VALUE - 10_000,
        10_000,
        &f.bob,
        &f.bob,
        false,
    );
    let child_txid = child.txid();
    let expected = core_script_error(&parent, &f.prev.txid);

    let res = mp.accept_package(vec![parent, child], &lookup);
    assert!(!res.all_accepted(), "invalid-signature parent must be rejected; {:?}", res.package_error);
    assert_eq!(res.package_error.as_deref(), Some("transaction failed"));
    assert!(!mp.contains(&parent_txid) && !mp.contains(&child_txid));
    let parent_err = res
        .tx_results
        .iter()
        .find(|r| r.txid == parent_txid)
        .and_then(|r| r.error.clone())
        .unwrap_or_default();
    assert_eq!(parent_err, expected);
    let child_err = res
        .tx_results
        .iter()
        .find(|r| r.txid == child_txid)
        .and_then(|r| r.error.clone())
        .unwrap_or_default();
    assert_eq!(child_err, "bad-txns-inputs-missingorspent");
}

/// Regtest builds the mempool with `verify_scripts = false`. `submitpackage`
/// passes `force_script_checks` so the same bad child is still rejected.
#[test]
fn submitpackage_force_script_checks_rejects_when_verify_scripts_off() {
    let f = fixture();
    let lookup = |op: &OutPoint| f.utxos.get(op).cloned();
    let mut mp = Mempool::new(MempoolConfig::default());
    mp.notify_new_tip(1_000, 1_700_000_000);
    assert!(!mp.verify_scripts());

    let parent = signed_spend(f.prev.clone(), IN_VALUE, 10_000, &f.alice, &f.bob, false);
    let parent_txid = parent.txid();
    let child = signed_spend(
        OutPoint {
            txid: parent_txid,
            vout: 0,
        },
        IN_VALUE - 10_000,
        10_000,
        &f.bob,
        &f.bob,
        true,
    );
    let child_txid = child.txid();

    let res = mp.accept_package_with_options(
        vec![parent, child],
        &lookup,
        AtmpOptions {
            force_script_checks: true,
            ..AtmpOptions::default()
        },
    );
    assert!(!res.all_accepted());
    assert!(mp.contains(&parent_txid));
    assert!(!mp.contains(&child_txid));
    let child_err = res
        .tx_results
        .iter()
        .find(|r| r.txid == child_txid)
        .and_then(|r| r.error.clone())
        .unwrap_or_default();
    assert!(
        child_err.starts_with(
            "mempool-script-verify-flag-failed (Signature must be zero for failed CHECK(MULTI)SIG operation)"
        ),
        "{child_err}"
    );
}

/// Valid 1-parent-1-child CPFP: the parent is below the relay floor on its
/// own, the child pays for both, both signatures verify. Still admitted.
#[test]
fn submitpackage_valid_cpfp_1p1c_still_accepted() {
    let f = fixture();
    let lookup = |op: &OutPoint| f.utxos.get(op).cloned();
    let mut mp = production_pool();

    let parent = signed_spend(f.prev.clone(), IN_VALUE, 1, &f.alice, &f.bob, false);
    let parent_txid = parent.txid();
    let child = signed_spend(
        OutPoint {
            txid: parent_txid,
            vout: 0,
        },
        IN_VALUE - 1,
        20_000,
        &f.bob,
        &f.bob,
        false,
    );
    let child_txid = child.txid();

    let res = mp.accept_package(vec![parent, child], &lookup);
    assert!(
        res.all_accepted(),
        "valid CPFP 1-parent-1-child must be accepted; package_error={:?}",
        res.package_error
    );
    assert!(mp.contains(&parent_txid) && mp.contains(&child_txid));
    assert!(res.tx_results.iter().all(|r| r.error.is_none()));
}
