//! `signrawtransactionwithkey` — RPC functional test
//! (Core `rpc/rawtransaction.cpp::signrawtransactionwithkey` -> `SignTransaction`).
//!
//! Verifies the walletless key-based signer end-to-end with a REAL
//! signature-verification gate:
//!
//!   1. Generate a P2WPKH key (via the wallet HD engine) + export its WIF and
//!      derive its scriptPubKey.
//!   2. Build a RAW (unsigned) tx spending a synthetic prevout locked to that
//!      P2WPKH scriptPubKey.
//!   3. Call `signrawtransactionwithkey` with the WIF in `privkeys` and the
//!      prevout supplied via `prevtxs` (scriptPubKey + amount).
//!   4. Assert:
//!      (a) `{hex, complete:true}` — every input fully signed, no `errors`.
//!      (b) ⭐ the produced witness ACTUALLY VERIFIES against the prevout
//!          scriptPubKey + BIP-143 sighash, through the impl's OWN consensus
//!          script engine (`verify_script` + `TransactionSignatureChecker`) —
//!          NOT merely that a witness field is non-empty. A non-vacuity guard
//!          confirms a tampered signature FAILS the same verifier.
//!      (c) a missing-key input -> `complete:false` + an `errors[]` entry of
//!          Core's TransactionError shape.
//!
//! The signing engine under test is `KeySigner` -> `Wallet::sign_input_with_key`
//! -> the per-script signers — the SAME BIP-143/BIP-341 sighash + ECDSA/Schnorr
//! path `signrawtransactionwithwallet` / `walletprocesspsbt` drive. The keystore
//! is the explicit WIF keys + prevtxs, NOT the wallet HD tree.

use std::sync::Arc;

use rustoshi_consensus::{verify_script, ScriptFlags, TransactionSignatureChecker};
use rustoshi_crypto::address::{Address, Network};
use rustoshi_primitives::{Decodable, Encodable, Hash256, OutPoint, Transaction, TxIn, TxOut};
use rustoshi_rpc::{WalletRpcImpl, WalletRpcServer, WalletRpcState};
use rustoshi_wallet::{CreateWalletOptions, WalletManager};
use tempfile::tempdir;
use tokio::sync::RwLock;

/// Spin up a (walletless-capable) WalletRpcState on a unique tempdir, and also
/// hand back one wallet-generated P2WPKH address's WIF + scriptPubKey so the
/// test can drive the key-based signer with a key it controls.
fn rpc_state_with_p2wpkh_key() -> (Arc<RwLock<WalletRpcState>>, String, Vec<u8>) {
    let dir = tempdir().expect("unique tempdir");
    let mut manager = WalletManager::new(dir.path(), Network::Regtest).expect("manager");
    let wallet_name = "srtwk-keygen".to_string();
    manager
        .create_wallet(&wallet_name, CreateWalletOptions::default())
        .expect("create wallet");

    let (wif, spk) = {
        let arc = manager.get_wallet(&wallet_name).unwrap();
        let mut w = arc.lock().unwrap();
        let addr = w.get_new_address().expect("new addr");
        let spk = Address::from_string(&addr, Some(Network::Regtest))
            .unwrap()
            .to_script_pubkey();
        // Default wallet address type is P2WPKH (OP_0 <20-byte hash>).
        assert!(
            spk.len() == 22 && spk[0] == 0x00 && spk[1] == 0x14,
            "fixture expects a P2WPKH scriptPubKey, got {}",
            hex::encode(&spk)
        );
        let wif = w.wif_for_address(&addr).expect("export WIF for owned addr");
        (wif, spk)
    };

    // The signer needs no loaded wallet; reuse a fresh manager on a unique
    // tempdir so the RPC state mirrors a real (possibly walletless) node.
    let state_dir = tempdir().expect("unique state tempdir");
    let state_manager = WalletManager::new(state_dir.path(), Network::Regtest).expect("manager");
    let temp_path = state_dir.keep();
    let _ = dir.keep();
    let state = Arc::new(RwLock::new(WalletRpcState::new(state_manager, temp_path)));
    (state, wif, spk)
}

/// Build a raw (unsigned) tx spending `prevout_outpoint` (locked to
/// `prevout_spk`, worth `value` sats) to a dummy P2WPKH output less `fee`.
fn raw_unsigned_tx(prevout_outpoint: OutPoint, value: u64, fee: u64) -> Transaction {
    Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: prevout_outpoint,
            script_sig: vec![],
            sequence: 0xFFFF_FFFD,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value: value - fee,
            script_pubkey: Address::from_string(
                "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
                Some(Network::Regtest),
            )
            .unwrap()
            .to_script_pubkey(),
        }],
        lock_time: 0,
    }
}

/// Build the `prevtxs` JSON entry (txid display order, scriptPubKey hex,
/// amount in BTC) the RPC accepts.
fn prevtx_json(outpoint: &OutPoint, spk: &[u8], value_sats: u64) -> serde_json::Value {
    let txid_display = hex::encode(outpoint.txid.0.iter().rev().copied().collect::<Vec<_>>());
    serde_json::json!({
        "txid": txid_display,
        "vout": outpoint.vout,
        "scriptPubKey": hex::encode(spk),
        "amount": (value_sats as f64) / 1e8,
    })
}

#[tokio::test]
async fn signrawtransactionwithkey_signs_p2wpkh_and_verifies() {
    let (state, wif, spk) = rpc_state_with_p2wpkh_key();

    let value: u64 = 100_000;
    let fee: u64 = 2_000;
    let prevout = OutPoint {
        txid: Hash256::from_bytes([0xa1; 32]),
        vout: 0,
    };
    let tx = raw_unsigned_tx(prevout.clone(), value, fee);
    let raw_hex = hex::encode(tx.serialize());

    let prevtxs: Vec<rustoshi_rpc::PrevTx> =
        serde_json::from_value(serde_json::json!([prevtx_json(&prevout, &spk, value)]))
            .expect("prevtxs deserialize");

    let rpc = WalletRpcImpl::new(state);

    let result = rpc
        .sign_raw_transaction_with_key(raw_hex, vec![wif], Some(prevtxs), None)
        .await
        .expect("signrawtransactionwithkey should succeed");

    // (a) complete=true, no errors.
    assert!(
        result.complete,
        "single key-controlled input must finalize to complete=true; errors={:?}",
        result.errors
    );
    assert!(
        result.errors.is_none(),
        "no errors expected when every input is signed: {:?}",
        result.errors
    );

    // (b) ⭐ the produced witness must VERIFY through the impl's own consensus
    //     script engine (real BIP-143 sighash + ECDSA check).
    let raw = hex::decode(&result.hex).expect("hex decodes");
    let signed = Transaction::deserialize(&raw).expect("signed tx deserializes");
    assert_eq!(signed.inputs.len(), 1, "one input");
    let input = &signed.inputs[0];
    assert!(
        input.script_sig.is_empty(),
        "P2WPKH scriptSig must be empty (signature lives in the witness)"
    );
    assert_eq!(
        input.witness.len(),
        2,
        "P2WPKH witness must be [sig+hashtype, pubkey33]"
    );
    assert_eq!(
        *input.witness[0].last().unwrap(),
        0x01,
        "sighash byte must be SIGHASH_ALL"
    );
    assert_eq!(input.witness[1].len(), 33, "compressed pubkey is 33 bytes");

    let spent_amounts = vec![value];
    let spent_scripts = vec![spk.clone()];
    let checker =
        TransactionSignatureChecker::new(&signed, 0, value, &spent_amounts, &spent_scripts);
    let flags = ScriptFlags::standard_flags();
    verify_script(&input.script_sig, &spk, &input.witness, &flags, &checker)
        .expect("the produced signature MUST verify through the impl's own script engine");

    // Non-vacuity guard: a tampered signature MUST be rejected by the same
    // verifier — proves the verify above is a real cryptographic check.
    {
        let mut bad_witness = input.witness.clone();
        let sig = &mut bad_witness[0];
        let mid = sig.len() / 2;
        sig[mid] ^= 0xff;
        let bad_checker =
            TransactionSignatureChecker::new(&signed, 0, value, &spent_amounts, &spent_scripts);
        assert!(
            verify_script(&input.script_sig, &spk, &bad_witness, &flags, &bad_checker).is_err(),
            "tampered signature must FAIL verify_script (non-vacuity)"
        );
    }
}

#[tokio::test]
async fn signrawtransactionwithkey_missing_key_is_incomplete() {
    // Two inputs: one we provide the key + prevtx for (signed), one whose
    // prevtx is provided but whose key is NOT (left unsigned). Result must be
    // complete=false with exactly one errors[] entry for the unsignable input.
    let (state, wif, spk) = rpc_state_with_p2wpkh_key();

    let value: u64 = 100_000;
    let signable_op = OutPoint {
        txid: Hash256::from_bytes([0xb2; 32]),
        vout: 0,
    };
    // A foreign P2WPKH prevout — we supply its prevtx but NOT its key.
    let foreign_spk = Address::from_string(
        "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
        Some(Network::Regtest),
    )
    .unwrap()
    .to_script_pubkey();
    let foreign_op = OutPoint {
        txid: Hash256::from_bytes([0xc3; 32]),
        vout: 1,
    };

    let tx = Transaction {
        version: 2,
        inputs: vec![
            TxIn {
                previous_output: signable_op.clone(),
                script_sig: vec![],
                sequence: 0xFFFF_FFFD,
                witness: vec![],
            },
            TxIn {
                previous_output: foreign_op.clone(),
                script_sig: vec![],
                sequence: 0xFFFF_FFFD,
                witness: vec![],
            },
        ],
        outputs: vec![TxOut {
            value: value * 2 - 4_000,
            script_pubkey: foreign_spk.clone(),
        }],
        lock_time: 0,
    };
    let raw_hex = hex::encode(tx.serialize());

    let prevtxs: Vec<rustoshi_rpc::PrevTx> = serde_json::from_value(serde_json::json!([
        prevtx_json(&signable_op, &spk, value),
        prevtx_json(&foreign_op, &foreign_spk, value),
    ]))
    .expect("prevtxs deserialize");

    let rpc = WalletRpcImpl::new(state);
    let result = rpc
        .sign_raw_transaction_with_key(raw_hex, vec![wif], Some(prevtxs), None)
        .await
        .expect("rpc succeeds even with a partially-signable tx");

    assert!(
        !result.complete,
        "a tx with an unsignable input must report complete=false"
    );
    let errors = result
        .errors
        .as_ref()
        .expect("complete=false must carry an errors[] array");
    assert_eq!(errors.len(), 1, "exactly the foreign input errors");
    let err0 = &errors[0];
    // TransactionError shape: txid (display order) + vout of the foreign input.
    let foreign_txid_display =
        hex::encode(foreign_op.txid.0.iter().rev().copied().collect::<Vec<_>>());
    assert_eq!(err0.txid, foreign_txid_display, "error points at the foreign input txid");
    assert_eq!(err0.vout, foreign_op.vout, "error points at the foreign input vout");
    assert_eq!(err0.sequence, 0xFFFF_FFFD, "error carries the input sequence");
    assert!(
        err0.error.to_lowercase().contains("private key")
            || err0.error.to_lowercase().contains("unable to sign"),
        "error message names the missing key: {}",
        err0.error
    );

    // The signable input (index 0) MUST still be signed: decode + verify it.
    let signed =
        Transaction::deserialize(&hex::decode(&result.hex).unwrap()).expect("decode signed tx");
    assert_eq!(signed.inputs.len(), 2);
    assert_eq!(
        signed.inputs[0].witness.len(),
        2,
        "the input we hold the key for must be signed (witness present)"
    );
    assert!(
        signed.inputs[1].witness.is_empty() && signed.inputs[1].script_sig.is_empty(),
        "the unsignable input stays empty"
    );

    // And the signed input verifies through the consensus engine (spending the
    // 2-input tx — both prevouts feed the checker's spent-amounts/scripts).
    let spent_amounts = vec![value, value];
    let spent_scripts = vec![spk.clone(), foreign_spk.clone()];
    let checker =
        TransactionSignatureChecker::new(&signed, 0, value, &spent_amounts, &spent_scripts);
    let flags = ScriptFlags::standard_flags();
    verify_script(
        &signed.inputs[0].script_sig,
        &spk,
        &signed.inputs[0].witness,
        &flags,
        &checker,
    )
    .expect("signed input must verify even though a sibling input is unsigned");
}
