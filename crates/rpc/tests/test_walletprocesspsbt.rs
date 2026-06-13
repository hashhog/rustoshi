//! `walletprocesspsbt` — RPC functional test (Core wallet/rpc/spend.cpp:1569).
//!
//! Verifies the Updater + Signer + Finalizer roles end-to-end against a
//! funded regtest wallet fixture, with a REAL signature-verification gate:
//!
//!   1. Build a funded regtest wallet that owns one P2WPKH UTXO.
//!   2. Build an UNSIGNED PSBT (`Psbt::from_unsigned_tx`) spending that UTXO.
//!   3. Call `walletprocesspsbt` (sign=true, finalize=true defaults).
//!   4. Assert:
//!      (a) the returned `psbt` is valid base64 that round-trips through
//!          `Psbt::from_base64`;
//!      (b) `complete == true` for the single-wallet-input PSBT, and `hex`
//!          (the finalized network tx) is present;
//!      (c) ⭐ the produced witness ACTUALLY VERIFIES against the input's
//!          prevout scriptPubKey + BIP-143 sighash, through the impl's own
//!          consensus script engine (`verify_script` +
//!          `TransactionSignatureChecker`) — NOT merely that a sig field is
//!          non-empty.
//!
//! The signing engine under test is `Wallet::sign_input` (BIP-143 segwit v0
//! sighash + ECDSA), the SAME path `signrawtransactionwithwallet` drives —
//! see `crates/rpc/src/wallet.rs::wallet_process_psbt`.

use std::sync::Arc;

use rustoshi_consensus::{
    verify_script, ScriptFlags, TransactionSignatureChecker,
};
use rustoshi_crypto::address::{Address, Network};
use rustoshi_primitives::{Decodable, Hash256, OutPoint, Transaction, TxIn, TxOut};
use rustoshi_rpc::{WalletRpcImpl, WalletRpcServer, WalletRpcState};
use rustoshi_wallet::{CreateWalletOptions, Psbt, WalletManager, WalletUtxo};
use tempfile::tempdir;
use tokio::sync::RwLock;

/// Build a funded regtest wallet on a tempdir that owns exactly one P2WPKH
/// UTXO. Returns `(state, owned_utxo)`.
fn funded_wallet_state(utxo_value: u64) -> (Arc<RwLock<WalletRpcState>>, WalletUtxo) {
    let dir = tempdir().expect("tempdir");
    let mut manager = WalletManager::new(dir.path(), Network::Regtest).expect("manager");
    let wallet_name = "wpp-test".to_string();
    manager
        .create_wallet(&wallet_name, CreateWalletOptions::default())
        .expect("create wallet");

    let utxo = {
        let arc = manager.get_wallet(&wallet_name).unwrap();
        let mut w = arc.lock().unwrap();
        w.set_chain_height(200);
        let addr = w.get_new_address().expect("new addr");
        let path = w.get_derivation_path(&addr).unwrap().clone();
        let spk = Address::from_string(&addr, Some(Network::Regtest))
            .unwrap()
            .to_script_pubkey();
        // Sanity: default wallet address type is P2WPKH (OP_0 <20-byte hash>).
        assert!(
            spk.len() == 22 && spk[0] == 0x00 && spk[1] == 0x14,
            "fixture expects a P2WPKH scriptPubKey, got {}",
            hex::encode(&spk)
        );
        let utxo = WalletUtxo {
            outpoint: OutPoint {
                txid: Hash256::from_bytes([0xa1; 32]),
                vout: 0,
            },
            value: utxo_value,
            script_pubkey: spk,
            derivation_path: path,
            confirmations: 10,
            is_change: false,
            is_coinbase: false,
            height: Some(100),
        };
        w.add_utxo(utxo.clone());
        utxo
    };

    let temp_path = dir.keep();
    let state = Arc::new(RwLock::new(WalletRpcState::new(manager, temp_path)));
    (state, utxo)
}

/// Build an UNSIGNED base64 PSBT that spends `owned` to a dummy P2WPKH output,
/// leaving `fee` sats as the miner fee.
fn unsigned_psbt_spending(owned: &WalletUtxo, fee: u64) -> String {
    let unsigned_tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: owned.outpoint.clone(),
            script_sig: vec![],
            sequence: 0xFFFF_FFFD,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value: owned.value - fee,
            // Arbitrary regtest P2WPKH destination (not ours).
            script_pubkey: Address::from_string(
                "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
                Some(Network::Regtest),
            )
            .unwrap()
            .to_script_pubkey(),
        }],
        lock_time: 0,
    };
    Psbt::from_unsigned_tx(unsigned_tx)
        .expect("build unsigned PSBT")
        .to_base64()
}

#[tokio::test]
async fn walletprocesspsbt_signs_and_finalizes_single_wallet_input() {
    let utxo_value: u64 = 100_000;
    let fee: u64 = 2_000;
    let (state, owned) = funded_wallet_state(utxo_value);
    let psbt_b64 = unsigned_psbt_spending(&owned, fee);

    let rpc = WalletRpcImpl::new(state);

    // Defaults: sign=true, sighashtype=ALL, bip32derivs=true, finalize=true.
    let result = rpc
        .wallet_process_psbt(psbt_b64, None, None, None, None)
        .await
        .expect("walletprocesspsbt should succeed");

    // (a) returned psbt is valid base64 that round-trips.
    let round_tripped = Psbt::from_base64(&result.psbt)
        .expect("returned psbt must be valid base64 that round-trips");
    assert_eq!(
        round_tripped.unsigned_tx.inputs.len(),
        1,
        "round-tripped PSBT keeps the single input"
    );

    // (b) complete == true for a single-wallet-input PSBT, with hex emitted.
    assert!(
        result.complete,
        "single wallet-owned input must finalize to complete=true"
    );
    let final_hex = result
        .hex
        .as_ref()
        .expect("complete=true must include the finalized network tx hex");

    // (c) ⭐ the produced signature ACTUALLY VERIFIES against the prevout
    //     scriptPubKey + BIP-143 sighash, through the impl's own verifier.
    let raw = hex::decode(final_hex).expect("hex decodes");
    let final_tx = Transaction::deserialize(&raw).expect("finalized tx deserializes");

    assert_eq!(final_tx.inputs.len(), 1, "one input");
    let input = &final_tx.inputs[0];
    // P2WPKH spends carry the signature in the witness, scriptSig empty.
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

    // Drive the full consensus script engine: scriptSig + scriptPubKey +
    // witness must evaluate to TRUE, which requires the ECDSA signature to
    // verify against the BIP-143 sighash computed over the prevout amount +
    // scriptPubKey. A fabricated / wrong sighash signature fails here.
    let spent_amounts = vec![owned.value];
    let spent_scripts = vec![owned.script_pubkey.clone()];
    let checker = TransactionSignatureChecker::new(
        &final_tx,
        0,
        owned.value,
        &spent_amounts,
        &spent_scripts,
    );
    let flags = ScriptFlags::standard_flags();
    verify_script(
        &input.script_sig,
        &owned.script_pubkey,
        &input.witness,
        &flags,
        &checker,
    )
    .expect("the produced signature MUST verify through the impl's own script engine");

    // Non-vacuity guard: a tampered signature MUST be rejected by the same
    // verifier — proves the verify above is a real cryptographic check, not a
    // no-op that any byte string would pass.
    {
        let mut bad_witness = input.witness.clone();
        // Flip a byte in the DER body of the signature (before the sighash byte).
        let sig = &mut bad_witness[0];
        let mid = sig.len() / 2;
        sig[mid] ^= 0xff;
        let bad_checker = TransactionSignatureChecker::new(
            &final_tx,
            0,
            owned.value,
            &spent_amounts,
            &spent_scripts,
        );
        assert!(
            verify_script(
                &input.script_sig,
                &owned.script_pubkey,
                &bad_witness,
                &flags,
                &bad_checker,
            )
            .is_err(),
            "tampered signature must FAIL verify_script (non-vacuity)"
        );
    }
}

#[tokio::test]
async fn walletprocesspsbt_rejects_malformed_base64() {
    let (state, _owned) = funded_wallet_state(100_000);
    let rpc = WalletRpcImpl::new(state);

    let err = rpc
        .wallet_process_psbt("not-a-psbt!!!".to_string(), None, None, None, None)
        .await
        .expect_err("malformed base64 PSBT must error");
    // Core: DecodeBase64PSBT failure -> RPC_DESERIALIZATION_ERROR (-22).
    assert_eq!(err.code(), -22, "malformed PSBT -> -22 (deserialization)");
}

#[tokio::test]
async fn walletprocesspsbt_foreign_input_not_complete() {
    // A PSBT spending a UTXO the wallet does NOT own can't be signed ->
    // complete=false and no hex.
    let (state, _owned) = funded_wallet_state(100_000);

    let foreign = WalletUtxo {
        outpoint: OutPoint {
            txid: Hash256::from_bytes([0xee; 32]),
            vout: 3,
        },
        value: 100_000,
        // arbitrary P2WPKH spk, not in the wallet
        script_pubkey: Address::from_string(
            "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
            Some(Network::Regtest),
        )
        .unwrap()
        .to_script_pubkey(),
        derivation_path: vec![],
        confirmations: 1,
        is_change: false,
        is_coinbase: false,
        height: Some(100),
    };
    let psbt_b64 = unsigned_psbt_spending(&foreign, 2_000);

    let rpc = WalletRpcImpl::new(state);
    let result = rpc
        .wallet_process_psbt(psbt_b64, None, None, None, None)
        .await
        .expect("walletprocesspsbt should succeed (returns incomplete PSBT)");

    assert!(
        !result.complete,
        "foreign-only input cannot be signed -> complete=false"
    );
    assert!(
        result.hex.is_none(),
        "no finalized hex when incomplete"
    );
    // The (unchanged) PSBT must still round-trip.
    Psbt::from_base64(&result.psbt).expect("incomplete psbt round-trips");
}
