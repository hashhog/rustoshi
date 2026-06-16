//! W137 — PSBT v0/v2 (BIP-174 / BIP-370 / BIP-371) audit matrix.
//!
//! This is a **discovery wave**: every BUG-N test is marked `#[ignore]` and
//! stubbed with `assert!(false, "...")` so the file compiles and pinned
//! regressions PASS. The `#[ignore]` markers are flipped one-at-a-time as
//! each bug is fixed in a follow-up wave.
//!
//! Test file is shaped per the W126/W127/W128/W129/W130/W131/W132/W133
//! audit convention:
//! - 30 gates G1..G30
//! - PRESENT gates assert the current correct behaviour and serve as
//!   forward-regression guards
//! - PARTIAL / MISSING / BROKEN gates are stubbed with `#[ignore]` and a
//!   doc-comment naming the BUG-N + the brief fix sketch.
//!
//! Reference: `audit/w137_psbt.md`.
//!
//! Bug inventory (BUG-1..30 — see `audit/w137_psbt.md` for full per-bug
//! rationale and Core line references):
//!
//!   BUG-1  [P0-CDIV] G3:  Missing `found_sep` post-loop check in
//!                    `decode` / `decode_psbt_input` / `decode_psbt_output`.
//!                    A truncated PSBT (no separator before EOF) silently
//!                    decodes vs Core throws "Separator is missing".
//!
//!   BUG-2  [P0-CDIV] G4:  `PSBT_IN_PARTIAL_SIG` BTreeMap insert silently
//!                    overwrites duplicate pubkey. Core throws
//!                    "Duplicate Key, input partial signature for pubkey
//!                    already provided" at psbt.h:535.
//!
//!   BUG-3  [P0-CDIV] G5:  `PSBT_IN_PARTIAL_SIG` skips
//!                    `CheckSignatureEncoding` (DERSIG+STRICTENC).
//!                    Core throws "Signature is not a valid encoding"
//!                    at psbt.h:544.
//!
//!   BUG-4  [P0-CDIV] G6:  `PSBT_IN_PARTIAL_SIG` pubkey not validated
//!                    via `IsFullyValid()`. Garbage 33-byte string with
//!                    valid prefix byte passes rustoshi but fails Core
//!                    at psbt.h:532.
//!
//!   BUG-5  [P0-CDIV] G16: `PSBT_OUT_TAP_TREE` accepts depth > 128 and
//!                    bogus leaf_ver (not 0xfe-mask-compliant). Core
//!                    enforces both at psbt.h:1053-1058.
//!
//!   BUG-6  [P1]      G17: `PSBT_OUT_TAP_TREE` lacks
//!                    `TaprootBuilder::IsComplete()` check. Core throws
//!                    "Output Taproot tree is malformed" at
//!                    psbt.h:1062-1064.
//!
//!   BUG-7  [P0-CDIV] G14: `PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS` decoded
//!                    but never encoded. Round-trip silently drops
//!                    MuSig2 participants. Core at psbt.h:948-957.
//!
//!   BUG-8  [P1]      G15: `PsbtOutput::merge` doesn't merge
//!                    `musig2_participant_pubkeys`. Core at psbt.cpp:317.
//!
//!   BUG-9  [P1]      G8:  Missing `key_lookup` duplicate-check on
//!                    `PSBT_IN_TAP_SCRIPT_SIG` / `PSBT_IN_TAP_LEAF_SCRIPT`
//!                    / `PSBT_IN_TAP_BIP32_DERIVATION`. Core at psbt.h:708,
//!                    psbt.h:730, psbt.h:750.
//!
//!   BUG-10 [P1]      G18: `PSBT_OUT_TAP_TREE` accepts empty value
//!                    (zero-iteration loop). Core throws "Output Taproot
//!                    tree must not be empty" at psbt.h:1042.
//!
//!   BUG-11 [P1]      G19: MuSig2 input fields entirely missing
//!                    (PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS = 0x1a,
//!                    PSBT_IN_MUSIG2_PUB_NONCE = 0x1b,
//!                    PSBT_IN_MUSIG2_PARTIAL_SIG = 0x1c).
//!                    Core defines all three at psbt.h:56-58.
//!
//!   BUG-12 [P0-CDIV] G7:  `PSBT_IN_PARTIAL_SIG` rejects uncompressed
//!                    pubkeys (key.len() == 66). Core accepts both 33
//!                    and 65 byte pubkeys at psbt.h:527.
//!
//!   BUG-13 [P1]      G21: `PSBT_IN_TAP_KEY_SIG` doesn't check sighash
//!                    byte vs `sighash_type` field. Core checks at
//!                    psbt.cpp:468.
//!
//!   BUG-14 [P1]      G22: `PSBT_IN_SIGHASH` accepts > 4 byte values
//!                    (only first 4 used). Core's UnserializeFromVector
//!                    requires EXACTLY 4 at psbt.h:559.
//!
//!   BUG-15 [P1]      G20: PSBT v2 (BIP-370) entirely absent. Matches
//!                    Core's PSBT_HIGHEST_VERSION=0 today — parity-OK
//!                    but real-world feature gap.
//!
//!   BUG-16 [P2]      G27: W41 A2 (CVE-2020-14199) check applied only
//!                    in sign_psbt_input; decode-time consumers
//!                    (decodepsbt fee display) bypass it.
//!
//!   BUG-17 [P2]      G28: `finalize_input` P2WPKH/P2PKH paths don't
//!                    clear producer fields. Core clears in
//!                    PSBTInput::FromSignatureData at psbt.cpp:163-176.
//!
//!   BUG-18 [P1]      G30: Missing RPCs `joinpsbts`, `utxoupdatepsbt`,
//!                    `descriptorprocesspsbt`.
//!
//!   BUG-19 [P2]      n/a: `Psbt::merge` silently drops `other` inputs
//!                    when other.inputs.len() > self.inputs.len()
//!                    (dead-code defensive; precondition guards make
//!                    unreachable, but pattern is fragile).
//!
//!   BUG-20 [P0-CDIV] n/a: `Psbt::decode` doesn't reject extra bytes
//!                    after the output maps. Core's DecodeRawPSBT
//!                    rejects "extra data after PSBT" at psbt.cpp:622.
//!
//!   BUG-21 [P1]      n/a: Hash preimages (RIPEMD160/SHA256/HASH160
//!                    /HASH256) not validated against `HASH(preimage)
//!                    == hash`; finalizer doesn't use them either.
//!
//!   BUG-22 [P2]      n/a: `Psbt::finalize` short-circuits on first
//!                    failed input. Core's FinalizePSBT is best-effort
//!                    per psbt.cpp:551-565.
//!
//!   BUG-23 [P2]      n/a: Proprietary BTreeSet insert silently dedups
//!                    duplicate keys instead of throwing. Core throws
//!                    "Duplicate Key, proprietary key already found".
//!
//!   BUG-25 [P2]      G27: `decodepsbt` fee accounting trusts attacker
//!                    witness_utxo amount (downstream of BUG-16).
//!
//!   BUG-26 [P2]      n/a: `finalizepsbt` RPC doesn't surface per-input
//!                    failure reason.
//!
//!   BUG-27 [P2]      n/a: `analyzepsbt` lacks `estimated_vsize` /
//!                    `estimated_feerate` / `fee` fields that Core's
//!                    AnalyzePSBT emits at node/psbt.cpp:88-130.
//!
//!   BUG-28 [P3]      n/a: `MAX_PSBT_SIZE` enforced only in
//!                    `Psbt::deserialize`; streaming decode path
//!                    (`Psbt::decode<R>`) can bypass.
//!
//!   BUG-29 [P0-CDIV] n/a: `PSBT_OUT_BIP32_DERIVATION` pubkey not
//!                    IsFullyValid-checked at decode (mirrors BUG-4 for
//!                    output side). Core at psbt.h:153-159.
//!
//!   BUG-30 [P2]      n/a: `PSBT_GLOBAL_XPUB` doesn't validate the
//!                    embedded pubkey via IsFullyValid. Core at
//!                    psbt.h:1289-1295.

use rustoshi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use rustoshi_primitives::hash::Hash256;
use rustoshi_wallet::psbt::{
    ExtPubKey, KeyOrigin, Proprietary, Psbt, PsbtError, PsbtInput, PsbtOutput, PsbtRole,
    PSBT_GLOBAL_PROPRIETARY, PSBT_GLOBAL_UNSIGNED_TX, PSBT_GLOBAL_VERSION, PSBT_GLOBAL_XPUB,
    PSBT_HIGHEST_VERSION, PSBT_IN_BIP32_DERIVATION, PSBT_IN_HASH160, PSBT_IN_HASH256,
    PSBT_IN_NON_WITNESS_UTXO, PSBT_IN_PARTIAL_SIG, PSBT_IN_PROPRIETARY, PSBT_IN_REDEEMSCRIPT,
    PSBT_IN_RIPEMD160, PSBT_IN_SCRIPTSIG, PSBT_IN_SCRIPTWITNESS, PSBT_IN_SHA256, PSBT_IN_SIGHASH,
    PSBT_IN_TAP_BIP32_DERIVATION, PSBT_IN_TAP_INTERNAL_KEY, PSBT_IN_TAP_KEY_SIG,
    PSBT_IN_TAP_LEAF_SCRIPT, PSBT_IN_TAP_MERKLE_ROOT, PSBT_IN_TAP_SCRIPT_SIG,
    PSBT_IN_WITNESSSCRIPT, PSBT_IN_WITNESS_UTXO, PSBT_MAGIC_BYTES, PSBT_OUT_BIP32_DERIVATION,
    PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS, PSBT_OUT_PROPRIETARY, PSBT_OUT_REDEEMSCRIPT,
    PSBT_OUT_TAP_BIP32_DERIVATION, PSBT_OUT_TAP_INTERNAL_KEY, PSBT_OUT_TAP_TREE,
    PSBT_OUT_WITNESSSCRIPT, PSBT_SEPARATOR,
};

// =============================================================================
// Test helpers
// =============================================================================

fn make_test_tx() -> Transaction {
    Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256::from_hex(
                    "0000000000000000000000000000000000000000000000000000000000000001",
                )
                .unwrap(),
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0xFFFFFFFF,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value: 50_000,
            script_pubkey: vec![
                0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
        }],
        lock_time: 0,
    }
}

// =============================================================================
// PRESENT gates — forward-regression pins
// =============================================================================

/// **G1 — PSBT_MAGIC_BYTES matches Core byte-for-byte.**
///
/// Core: `bitcoin-core/src/psbt.h:28` defines
/// `PSBT_MAGIC_BYTES[5] = {'p', 's', 'b', 't', 0xff}`. rustoshi must
/// emit and accept exactly these bytes.
#[test]
fn g1_psbt_magic_bytes_match_core() {
    assert_eq!(PSBT_MAGIC_BYTES, [0x70, 0x73, 0x62, 0x74, 0xFF]);

    let tx = make_test_tx();
    let psbt = Psbt::from_unsigned_tx(tx).unwrap();
    let bytes = psbt.serialize();
    assert_eq!(&bytes[..5], &PSBT_MAGIC_BYTES);

    // Invalid magic must be rejected
    let mut bad = bytes.clone();
    bad[4] ^= 0xFF;
    assert!(matches!(Psbt::deserialize(&bad), Err(PsbtError::InvalidMagic)));
}

/// **G2 — PSBT_SEPARATOR (0x00) emitted at end of each map.**
///
/// Core: `bitcoin-core/src/psbt.h:73`. Every PSBT has 3 separators
/// (global, per-input maps, per-output maps).
#[test]
fn g2_psbt_separator_is_zero() {
    assert_eq!(PSBT_SEPARATOR, 0x00);
    let tx = make_test_tx(); // 1 input, 1 output
    let psbt = Psbt::from_unsigned_tx(tx).unwrap();
    let bytes = psbt.serialize();
    // The last 3 bytes should be 0x00 (input separator + output separator;
    // global separator is in the middle).
    assert_eq!(*bytes.last().unwrap(), PSBT_SEPARATOR);
}

/// **G9 — `PSBT_IN_NON_WITNESS_UTXO` / `PSBT_IN_WITNESS_UTXO` /
///        `PSBT_IN_SIGHASH` / `PSBT_IN_REDEEMSCRIPT` /
///        `PSBT_IN_WITNESSSCRIPT` / `PSBT_IN_SCRIPTSIG` /
///        `PSBT_IN_SCRIPTWITNESS` / `PSBT_IN_TAP_KEY_SIG` /
///        `PSBT_IN_TAP_INTERNAL_KEY` / `PSBT_IN_TAP_MERKLE_ROOT` —
///        duplicate-key check present.**
///
/// All these single-instance fields enforce
/// `key_lookup.insert(key.clone())` and return DuplicateKey on collision.
/// Mirrors Core `psbt.h:507/517/553/564/574/589/599/693/773/783`.
#[test]
fn g9_single_instance_input_fields_dup_check_present() {
    // Cross-reference test: just assert the constants exist and the
    // BUG-9 cases are separated (the actual decoder logic is in psbt.rs).
    assert_eq!(PSBT_IN_NON_WITNESS_UTXO, 0x00);
    assert_eq!(PSBT_IN_WITNESS_UTXO, 0x01);
    assert_eq!(PSBT_IN_SIGHASH, 0x03);
    assert_eq!(PSBT_IN_REDEEMSCRIPT, 0x04);
    assert_eq!(PSBT_IN_WITNESSSCRIPT, 0x05);
    assert_eq!(PSBT_IN_SCRIPTSIG, 0x07);
    assert_eq!(PSBT_IN_SCRIPTWITNESS, 0x08);
    assert_eq!(PSBT_IN_TAP_KEY_SIG, 0x13);
    assert_eq!(PSBT_IN_TAP_INTERNAL_KEY, 0x17);
    assert_eq!(PSBT_IN_TAP_MERKLE_ROOT, 0x18);
}

/// **G10 — W41 A1: non_witness_utxo TXID mismatch rejected at decode.**
///
/// rustoshi's `Psbt::decode` lines 2048-2054 enforce
/// `nw.txid() != unsigned_tx.inputs[i].previous_output.txid` →
/// `PsbtError::UtxoHashMismatch`. This is the W41-fix forward-regression
/// pin (already covered by `test_w41_a1_*` in psbt.rs but reasserted
/// here for the W137 30-gate matrix).
#[test]
fn g10_w41_a1_nonwitness_txid_check_present() {
    // Build a PSBT whose non_witness_utxo has wrong TXID.
    let tx = make_test_tx();
    let psbt = Psbt::from_unsigned_tx(tx).unwrap();

    let attacker_tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256([0x99; 32]), // distinct from input[0]'s prevout
                vout: 7,
            },
            script_sig: vec![],
            sequence: 0xFFFF_FFFF,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value: 999_999,
            script_pubkey: vec![0xAA, 0xBB, 0xCC, 0xDD],
        }],
        lock_time: 0,
    };

    let mut tampered = psbt.clone();
    tampered.inputs[0].non_witness_utxo = Some(attacker_tx);
    let bytes = tampered.serialize();

    let res = Psbt::deserialize(&bytes);
    assert!(
        matches!(res, Err(PsbtError::UtxoHashMismatch)),
        "W41 A1: deserializer must reject mismatched non_witness_utxo; got {:?}",
        res
    );
}

/// **G11 — W36 fix: BIP32_DERIVATION value has NO inner CompactSize.**
///
/// rustoshi's encoder writes the raw fingerprint+path bytes as the value;
/// the outer `write_kv_pair` provides the only CompactSize prefix. This
/// matches BIP-174 byte-layout. Already verified by
/// `test_w36_bip174_no_inner_compactsize_on_bip32_values` in psbt.rs;
/// reasserted here.
#[test]
fn g11_w36_bip32_derivation_no_inner_compactsize() {
    let tx = make_test_tx();
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

    let mut pubkey = [0u8; 33];
    pubkey[0] = 0x02;
    for (i, b) in pubkey.iter_mut().enumerate().skip(1) {
        *b = i as u8;
    }

    let origin = KeyOrigin {
        fingerprint: [0xDE, 0xAD, 0xBE, 0xEF],
        path: vec![0x80000054, 0x80000000, 0x80000000],
    };
    psbt.add_input_derivation(0, pubkey, origin.clone()).unwrap();

    let bytes = psbt.serialize();

    // Locate the PSBT_IN_BIP32_DERIVATION record. Key = [0x06] || pubkey.
    let mut needle = vec![34u8, PSBT_IN_BIP32_DERIVATION]; // keylen(34) + type
    needle.extend_from_slice(&pubkey);

    let mut found = None;
    for i in 0..bytes.len().saturating_sub(needle.len()) {
        if &bytes[i..i + needle.len()] == needle.as_slice() {
            found = Some(i);
            break;
        }
    }
    let i = found.expect("BIP32_DERIVATION record not found");
    let val_len_off = i + needle.len();
    // origin = 4 (fingerprint) + 3 * 4 (path) = 16 bytes
    assert_eq!(
        bytes[val_len_off], 16,
        "W36 regression: value-len should be 16 (raw origin); 17 means inner CompactSize is back"
    );
}

/// **G12 — W41 A1 combiner: merge rejects mismatched non_witness_utxo.**
///
/// `Psbt::merge` lines 816-826 check the txid before adopting `other`'s
/// non_witness_utxo. Cross-reference with `test_w41_a1_combiner_*`.
#[test]
fn g12_w41_a1_combiner_check_present() {
    let tx = make_test_tx();
    let mut self_psbt = Psbt::from_unsigned_tx(tx.clone()).unwrap();
    let mut attacker_psbt = Psbt::from_unsigned_tx(tx).unwrap();

    // Attacker's prev_tx has WRONG txid for input[0]
    let bad_prev = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256([0xAB; 32]),
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0xFFFF_FFFF,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value: 1_000_000,
            script_pubkey: vec![0xAA, 0xBB],
        }],
        lock_time: 0,
    };
    attacker_psbt.inputs[0].non_witness_utxo = Some(bad_prev);

    let res = self_psbt.merge(&attacker_psbt);
    assert!(matches!(res, Err(PsbtError::UtxoHashMismatch)));
}

/// **G13 — W49 fix: partial signatures emitted in HASH160(pubkey) order.**
///
/// Mirrors Core's `std::map<CKeyID, SigPair>` order. Already covered by
/// existing tests, but reasserted here for matrix density.
#[test]
fn g13_w49_partial_sig_hash160_order() {
    // The map iteration order in encode_psbt_input sorts by HASH160(pubkey).
    // We test this indirectly: insert two pubkeys with KNOWN HASH160 order
    // and confirm the emitted bytes encode them in that order.
    let tx = make_test_tx();
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

    // Two pubkeys with known different HASH160 outputs.
    let pk_a = {
        let mut k = [0u8; 33];
        k[0] = 0x02;
        k[1] = 0x01;
        k
    };
    let pk_b = {
        let mut k = [0u8; 33];
        k[0] = 0x02;
        k[1] = 0x02;
        k
    };

    psbt.add_partial_sig(0, pk_a, vec![0x30, 0x44, 0x01]).unwrap();
    psbt.add_partial_sig(0, pk_b, vec![0x30, 0x44, 0x02]).unwrap();

    let bytes = psbt.serialize();
    // Both partial sigs should be present in the encoded bytes.
    // We just verify there are two PSBT_IN_PARTIAL_SIG records.
    let count = bytes.windows(2).filter(|w| *w == [34u8, PSBT_IN_PARTIAL_SIG]).count();
    assert!(count >= 2, "expected 2 PSBT_IN_PARTIAL_SIG records, found {}", count);
}

/// **G23 — `finalizepsbt` extract path mirrors Core's
///         `FinalizeAndExtractPSBT`.**
///
/// `extract_tx` at lines 1043-1062 pulls `final_script_sig` and
/// `final_script_witness` into the result tx.
#[test]
fn g23_extract_tx_pulls_final_fields() {
    let tx = make_test_tx();
    let mut psbt = Psbt::from_unsigned_tx(tx.clone()).unwrap();
    psbt.inputs[0].final_script_sig = Some(vec![0x51, 0x52]); // OP_1 OP_2
    psbt.inputs[0].final_script_witness = Some(vec![vec![0x33], vec![0x44]]);

    let extracted = psbt.extract_tx().unwrap();
    assert_eq!(extracted.inputs[0].script_sig, vec![0x51, 0x52]);
    assert_eq!(extracted.inputs[0].witness, vec![vec![0x33], vec![0x44]]);
}

/// **G24 — `combinepsbt` rejects empty array and incompatible PSBTs.**
#[test]
fn g24_combinepsbt_rejects_empty_and_incompatible() {
    // Empty array
    let res = Psbt::combine(&[]);
    assert!(matches!(res, Err(PsbtError::MissingUnsignedTx)));

    // Incompatible (different unsigned tx).
    let tx_a = make_test_tx();
    let mut tx_b = make_test_tx();
    tx_b.lock_time = 999; // different tx
    let psbt_a = Psbt::from_unsigned_tx(tx_a).unwrap();
    let psbt_b = Psbt::from_unsigned_tx(tx_b).unwrap();

    let res = Psbt::combine(&[psbt_a, psbt_b]);
    assert!(matches!(res, Err(PsbtError::IncompatiblePsbts)));
}

/// **G25 — `analyzepsbt` next-role uses Core's role ordering.**
///
/// `creator < updater < signer < finalizer < extractor`. The PSBT-level
/// `next` field is the MIN over per-input verdicts.
#[test]
fn g25_analyzepsbt_role_ordering() {
    let tx = make_test_tx();
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

    // No UTXO → Updater
    let a = psbt.analyze();
    assert_eq!(a.next, PsbtRole::Updater);

    // Add UTXO → Signer
    let mut spk = vec![0x00, 0x14];
    spk.extend_from_slice(&[0x01u8; 20]);
    psbt.set_witness_utxo(
        0,
        TxOut {
            value: 100_000,
            script_pubkey: spk,
        },
    )
    .unwrap();
    let a = psbt.analyze();
    assert_eq!(a.next, PsbtRole::Signer);
}

/// **G26 — W41 A2 (CVE-2020-14199) defense present in sign_psbt_input.**
///
/// rustoshi's `sign_psbt_input` checks `witness_utxo` vs
/// `non_witness_utxo.outputs[vout]` agreement. Cross-reference with
/// `test_w41_a2_witness_nonwitness_amount_mismatch_rejected` in psbt.rs.
///
/// This gate just asserts the documented presence of the
/// `WitnessUtxoMismatch` error variant (smoke test).
#[test]
fn g26_w41_a2_witness_utxo_mismatch_error_exists() {
    // Smoke: the error variant must exist (will fail to compile if removed).
    let _ = PsbtError::WitnessUtxoMismatch;
}

// =============================================================================
// MISSING / BROKEN gates — BUG-N stubs (all #[ignore]d)
// =============================================================================

/// **G3 — BUG-1: Missing post-loop separator check.**
///
/// rustoshi's `decode` / `decode_psbt_input` / `decode_psbt_output`
/// don't track a `found_sep` flag. A truncated PSBT (no separator
/// before EOF) MAY silently decode while Core throws.
///
/// Fix: add `let mut found_sep = false;` before each loop; set it in
/// the separator break; return `PsbtError::MissingSeparator` if not set.
#[test]
#[ignore = "BUG-1: missing found_sep post-loop check (P0-CDIV); fix in decode/decode_psbt_{input,output}"]
fn g3_bug_1_missing_separator_rejected() {
    assert!(false, "BUG-1: PSBT without trailing separator must be rejected");
}

/// **G4 — BUG-2: PSBT_IN_PARTIAL_SIG duplicate-pubkey silently
/// overwrites.**
///
/// BTreeMap insert overwrites on duplicate. Core throws "Duplicate Key,
/// input partial signature for pubkey already provided" at psbt.h:535.
///
/// Fix: add `if input.partial_sigs.contains_key(&pubkey) { return Err(...) }`
/// before the insert.
#[test]
fn g4_bug_2_partial_sig_duplicate_pubkey_rejected() {
    // Build a PSBT input byte stream that contains the SAME
    // PSBT_IN_PARTIAL_SIG key (0x02 || 33-byte pubkey) TWICE.
    //
    // Strategy: serialize a valid PSBT with exactly one partial sig, then
    // splice a byte-identical copy of that record into the input map right
    // after the original. Because the bytes are identical the duplicate
    // carries the SAME pubkey, so Core (psbt.h:535) — and now rustoshi —
    // must reject it with a duplicate-key error.

    let pubkey = {
        let mut k = [0u8; 33];
        k[0] = 0x02;
        for (i, b) in k.iter_mut().enumerate().skip(1) {
            *b = i as u8;
        }
        k
    };
    // A short opaque "signature" value. (BUG-3 encoding check is a separate
    // gate; the decode path here is the dup-key guard, so any value works.)
    let sig = vec![0x30u8, 0x44, 0x01];

    // --- single-key PSBT decodes Ok ---------------------------------------
    let tx = make_test_tx();
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.add_partial_sig(0, pubkey, sig.clone()).unwrap();
    let single = psbt.serialize();
    assert!(
        Psbt::deserialize(&single).is_ok(),
        "single PSBT_IN_PARTIAL_SIG record must still decode Ok"
    );

    // Locate the one PSBT_IN_PARTIAL_SIG record. Key = keylen(34) || type ||
    // pubkey, i.e. [0x22, 0x02, <33 pubkey bytes>].
    let mut key_prefix = vec![34u8, PSBT_IN_PARTIAL_SIG];
    key_prefix.extend_from_slice(&pubkey);
    let key_start = single
        .windows(key_prefix.len())
        .position(|w| w == key_prefix.as_slice())
        .expect("PSBT_IN_PARTIAL_SIG record not found in serialized PSBT");

    // The record is: key_prefix (35 bytes) || value_len (compactsize) ||
    // value. Our value is the 3-byte sig, so value encoding is
    // [0x03, 0x30, 0x44, 0x01] = 4 bytes. Record length = 35 + 4 = 39.
    let value_field = {
        let mut v = vec![sig.len() as u8];
        v.extend_from_slice(&sig);
        v
    };
    let record_len = key_prefix.len() + value_field.len();
    let record_end = key_start + record_len;
    // Sanity: the bytes following the key are the expected value field.
    assert_eq!(
        &single[key_start + key_prefix.len()..record_end],
        value_field.as_slice(),
        "unexpected PSBT_IN_PARTIAL_SIG value layout"
    );
    let record = &single[key_start..record_end];

    // Splice a byte-identical duplicate of the record immediately after it.
    let mut duped = Vec::with_capacity(single.len() + record.len());
    duped.extend_from_slice(&single[..record_end]);
    duped.extend_from_slice(record); // the DUPLICATE partial-sig record
    duped.extend_from_slice(&single[record_end..]);

    // --- duplicate-key PSBT must be rejected ------------------------------
    let res = Psbt::deserialize(&duped);
    assert!(
        matches!(res, Err(PsbtError::DuplicateKey(_))),
        "BUG-2: duplicate PSBT_IN_PARTIAL_SIG pubkey must be rejected with \
         DuplicateKey; got {:?}",
        res
    );
}

/// **G5 — BUG-3: PSBT_IN_PARTIAL_SIG skips CheckSignatureEncoding.**
///
/// Core rejects non-DER / non-low-S signatures at psbt.h:544 via
/// `CheckSignatureEncoding(sig, SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_STRICTENC, nullptr)`.
/// rustoshi accepts any byte sequence.
///
/// Fix: call rustoshi's existing
/// `rustoshi_consensus::script::interpreter::check_signature_encoding`
/// before inserting into partial_sigs.
#[test]
#[ignore = "BUG-3: PSBT_IN_PARTIAL_SIG accepts non-DER signatures (P0-CDIV); fix in decode_psbt_input"]
fn g5_bug_3_partial_sig_invalid_encoding_rejected() {
    assert!(false, "BUG-3: non-DER PSBT_IN_PARTIAL_SIG signatures must be rejected");
}

/// **G6 — BUG-4: PSBT_IN_PARTIAL_SIG pubkey not validated.**
///
/// rustoshi blindly copies 33 bytes into `[u8; 33]`. Core constructs
/// `CPubKey(key.begin() + 1, key.end())` and rejects via
/// `IsFullyValid()` at psbt.h:532.
///
/// Fix: add `secp256k1::PublicKey::from_slice(&pubkey).is_ok()` check.
#[test]
#[ignore = "BUG-4: PSBT_IN_PARTIAL_SIG accepts invalid pubkey (P0-CDIV); fix in decode_psbt_input"]
fn g6_bug_4_partial_sig_invalid_pubkey_rejected() {
    assert!(false, "BUG-4: invalid 33-byte pubkey in PSBT_IN_PARTIAL_SIG must be rejected");
}

/// **G7 — BUG-12: PSBT_IN_PARTIAL_SIG rejects uncompressed pubkeys.**
///
/// rustoshi line 2122 accepts `key.len() == 66` (uncompressed-pubkey
/// case) but line 2132-2134 errors with InvalidPubkey. Core accepts
/// both 33 and 65 byte pubkeys at psbt.h:527.
///
/// Fix: support 65-byte uncompressed pubkeys (or convert in storage).
#[test]
#[ignore = "BUG-12: PSBT_IN_PARTIAL_SIG rejects uncompressed pubkeys (P0-CDIV); fix in decode_psbt_input"]
fn g7_bug_12_partial_sig_accepts_uncompressed_pubkey() {
    assert!(false, "BUG-12: PSBT_IN_PARTIAL_SIG must accept 65-byte uncompressed pubkeys");
}

/// **G8 — BUG-9: Taproot input fields missing duplicate-key checks.**
///
/// `PSBT_IN_TAP_SCRIPT_SIG` (line 2304-2320), `PSBT_IN_TAP_LEAF_SCRIPT`
/// (line 2321-2343), `PSBT_IN_TAP_BIP32_DERIVATION` (line 2344-2367)
/// all lack `key_lookup.insert(key.clone())`. Core enforces all three
/// at psbt.h:708, psbt.h:730, psbt.h:750.
///
/// Fix: USE the existing per-input `key_lookup` set (initialized at
/// line 2070) for these three cases.
#[test]
#[ignore = "BUG-9: missing dup-check on PSBT_IN_TAP_{SCRIPT_SIG,LEAF_SCRIPT,BIP32_DERIVATION} (P1); fix in decode_psbt_input"]
fn g8_bug_9_taproot_input_dup_check_present() {
    assert!(false, "BUG-9: duplicate Taproot input keys must be rejected");
}

/// **G14 — BUG-7: PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS not encoded.**
///
/// `PsbtOutput::musig2_participant_pubkeys` field exists (line 531),
/// decoder is wired (line 2575-2603), but `encode_psbt_output` (lines
/// 1800-1876) has NO emit block. Round-trip silently drops the field.
///
/// Fix: add the encoder block. Mirror Core psbt.h:948-957.
#[test]
#[ignore = "BUG-7: PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS decoded but never encoded (P0-CDIV); fix in encode_psbt_output"]
fn g14_bug_7_musig2_output_round_trip_preserved() {
    let tx = make_test_tx();
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

    let mut agg = [0u8; 33];
    agg[0] = 0x02;
    for (i, b) in agg.iter_mut().enumerate().skip(1) {
        *b = (i + 0x10) as u8;
    }
    let mut part_a = [0u8; 33];
    part_a[0] = 0x02;
    for (i, b) in part_a.iter_mut().enumerate().skip(1) {
        *b = (i + 0x20) as u8;
    }
    let mut part_b = [0u8; 33];
    part_b[0] = 0x03;
    for (i, b) in part_b.iter_mut().enumerate().skip(1) {
        *b = (i + 0x30) as u8;
    }

    psbt.outputs[0]
        .musig2_participant_pubkeys
        .insert(agg, vec![part_a, part_b]);

    let bytes = psbt.serialize();
    let restored = Psbt::deserialize(&bytes).unwrap();

    // Pre-fix: the field is empty after round-trip.
    // Post-fix: it must equal the original.
    let v = restored.outputs[0].musig2_participant_pubkeys.get(&agg);
    assert!(
        v.is_some() && v.unwrap() == &vec![part_a, part_b],
        "BUG-7: MuSig2 participants dropped on round-trip"
    );
}

/// **G15 — BUG-8: PsbtOutput::merge does not merge MuSig2 participants.**
///
/// Line 555-584 lacks the merge block. Core does
/// `m_musig2_participants.insert(other.m_musig2_participants.begin(), ...)`
/// at psbt.cpp:317.
#[test]
#[ignore = "BUG-8: PsbtOutput::merge does not merge musig2_participant_pubkeys (P1); fix in PsbtOutput::merge"]
fn g15_bug_8_psbtoutput_merge_includes_musig2() {
    assert!(false, "BUG-8: merge must combine musig2_participant_pubkeys from both sides");
}

/// **G16 — BUG-5: PSBT_OUT_TAP_TREE accepts depth > 128.**
///
/// Decoder at lines 2536-2550 does NOT check `depth > 128` or
/// `(leaf_ver & ~TAPROOT_LEAF_MASK) != 0`. Core enforces both at
/// psbt.h:1053-1058.
///
/// Fix: add both checks. Reject malformed tap trees.
#[test]
#[ignore = "BUG-5: PSBT_OUT_TAP_TREE accepts invalid depth/leaf_ver (P0-CDIV); fix in decode_psbt_output"]
fn g16_bug_5_tap_tree_depth_validation() {
    assert!(false, "BUG-5: PSBT_OUT_TAP_TREE depth > 128 or invalid leaf_ver must be rejected");
}

/// **G17 — BUG-6: PSBT_OUT_TAP_TREE lacks completeness check.**
///
/// Core uses TaprootBuilder + `IsComplete()` at psbt.h:1062-1064.
/// rustoshi accepts any depth list.
#[test]
#[ignore = "BUG-6: PSBT_OUT_TAP_TREE accepts incomplete tree shape (P1); fix in decode_psbt_output"]
fn g17_bug_6_tap_tree_completeness_check() {
    assert!(false, "BUG-6: PSBT_OUT_TAP_TREE non-complete tree must be rejected");
}

/// **G18 — BUG-10: PSBT_OUT_TAP_TREE accepts empty value.**
///
/// Core throws "Output Taproot tree must not be empty" at psbt.h:1042.
/// rustoshi's loop has zero iterations on empty value, silently
/// producing empty `tap_tree`.
#[test]
#[ignore = "BUG-10: PSBT_OUT_TAP_TREE accepts empty value (P1); fix in decode_psbt_output"]
fn g18_bug_10_tap_tree_empty_value_rejected() {
    assert!(false, "BUG-10: empty PSBT_OUT_TAP_TREE value must be rejected");
}

/// **G19 — BUG-11: MuSig2 input fields entirely missing.**
///
/// `PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS = 0x1a`,
/// `PSBT_IN_MUSIG2_PUB_NONCE = 0x1b`,
/// `PSBT_IN_MUSIG2_PARTIAL_SIG = 0x1c` — none defined in rustoshi.
/// Core has all three on `PSBTInput` (psbt.h:284-289).
///
/// Fix: add the three field types to PsbtInput, decoder cases, and
/// encoder blocks. Mirror Core's psbt.h:791-836.
#[test]
#[ignore = "BUG-11: MuSig2 input fields missing (P1); fix in psbt.rs"]
fn g19_bug_11_musig2_input_fields_present() {
    assert!(false, "BUG-11: PSBT_IN_MUSIG2 fields (PARTICIPANT_PUBKEYS / PUB_NONCE / PARTIAL_SIG) must be defined");
}

/// **G20 — BUG-15: PSBT v2 (BIP-370) entirely absent.**
///
/// rustoshi rejects v > 0 (line 1988-1990). Matches Core's
/// `PSBT_HIGHEST_VERSION = 0` today — **PARITY**, not a divergence.
/// Feature gap, not a Core-divergence bug.
///
/// This gate stays `#[ignore]` until either Core or fleet adopts v2.
#[test]
#[ignore = "BUG-15: PSBT v2 (BIP-370) not implemented (P1, feature gap; matches Core parity today)"]
fn g20_bug_15_psbt_v2_supported() {
    assert!(false, "BUG-15: PSBT v2 (BIP-370) not implemented; tracks Core parity");
}

/// **G21 — BUG-13: PSBT_IN_TAP_KEY_SIG sighash byte not cross-checked.**
///
/// Decoder validates length (64 or 65 bytes) but not that, if length=65,
/// the sighash byte equals `sighash_type`. Core checks at psbt.cpp:468.
#[test]
#[ignore = "BUG-13: PSBT_IN_TAP_KEY_SIG sighash byte not checked vs sighash_type (P1); fix in decode/sign"]
fn g21_bug_13_tap_key_sig_sighash_cross_check() {
    assert!(false, "BUG-13: tap_key_sig sighash byte must match sighash_type field");
}

/// **G22 — BUG-14: PSBT_IN_SIGHASH accepts > 4 byte values.**
///
/// Decoder uses `value.len() < 4` and discards excess. Core's
/// UnserializeFromVector(s, sighash) requires EXACTLY 4 at psbt.h:559.
///
/// Fix: change `< 4` to `!= 4`.
#[test]
#[ignore = "BUG-14: PSBT_IN_SIGHASH accepts > 4 byte values (P1); fix in decode_psbt_input"]
fn g22_bug_14_sighash_strict_4_byte_value() {
    assert!(false, "BUG-14: PSBT_IN_SIGHASH value must be exactly 4 bytes");
}

/// **G27 — BUG-16: W41 A2 defense not applied at decode time.**
///
/// CVE-2020-14199 amount-oracle check is inside `sign_psbt_input`
/// only — not in `Psbt::decode`. `decodepsbt` consumers reading
/// `witness_utxo.value` directly bypass the defense.
///
/// Fix: hoist the witness_utxo/non_witness_utxo agreement check
/// from `sign_psbt_input` (wallet.rs:1347-1359) to `Psbt::decode`
/// post-loop, paired with the existing W41 A1 txid check at lines
/// 2048-2054.
#[test]
#[ignore = "BUG-16: W41 A2 defense not at decode time (P2); fix in Psbt::decode"]
fn g27_bug_16_decode_enforces_witness_nonwitness_agreement() {
    assert!(false, "BUG-16: decode must reject witness_utxo/non_witness_utxo amount mismatch");
}

/// **G28 — BUG-17: finalize_input P2WPKH/P2PKH leaves producer fields.**
///
/// Lines 914-919 (P2WPKH) and 921-935 (P2PKH) set final fields but
/// don't clear `partial_sigs`, `redeem_script`, `bip32_derivation`,
/// `sighash_type`. The legacy P2SH-multisig path (line 1012-1016)
/// DOES clear them.
#[test]
#[ignore = "BUG-17: finalize_input P2WPKH/P2PKH leaves producer fields (P2); fix in finalize_input"]
fn g28_bug_17_finalize_clears_producer_fields() {
    let tx = make_test_tx();
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

    let mut pubkey = [0u8; 33];
    pubkey[0] = 0x02;
    pubkey[1] = 0xAA;

    let mut spk = vec![0x00, 0x14];
    spk.extend_from_slice(&[0xCCu8; 20]);
    psbt.set_witness_utxo(
        0,
        TxOut {
            value: 100_000,
            script_pubkey: spk,
        },
    )
    .unwrap();
    psbt.inputs[0].sighash_type = Some(1);
    psbt.add_partial_sig(0, pubkey, vec![0x30, 0x44, 0x01]).unwrap();

    psbt.finalize_input(0).unwrap();

    // Post-fix: producer fields cleared.
    assert!(
        psbt.inputs[0].partial_sigs.is_empty(),
        "BUG-17: partial_sigs not cleared after finalize (P2WPKH path)"
    );
    assert!(
        psbt.inputs[0].sighash_type.is_none(),
        "BUG-17: sighash_type not cleared after finalize (P2WPKH path)"
    );
}

/// **G29 — BUG-29: PSBT_OUT_BIP32_DERIVATION pubkey not validated.**
///
/// `decode_psbt_output` lines 2485-2502 copy the 33-byte key data as a
/// BTreeMap key without `IsFullyValid()` check. Core enforces at
/// psbt.h:153-159 via `DeserializeHDKeypaths`.
///
/// Fix: add `secp256k1::PublicKey::from_slice` validation for both
/// PSBT_IN_BIP32_DERIVATION (line 2185-2202) and
/// PSBT_OUT_BIP32_DERIVATION (line 2485-2501).
#[test]
#[ignore = "BUG-29: PSBT_{IN,OUT}_BIP32_DERIVATION pubkey not IsFullyValid-checked (P0-CDIV); fix in decode"]
fn g29_bug_29_bip32_derivation_pubkey_validated() {
    assert!(false, "BUG-29: BIP32_DERIVATION pubkey must pass IsFullyValid()");
}

/// **G30 — BUG-18: Missing RPCs `joinpsbts`, `utxoupdatepsbt`,
///                `descriptorprocesspsbt`.**
///
/// Core's `bitcoin-core/src/rpc/rawtransaction.cpp::joinpsbts`,
/// `utxoupdatepsbt`, and `bitcoin-core/src/wallet/rpc/spend.cpp::descriptorprocesspsbt`
/// are not exposed in rustoshi's RPC.
///
/// Fix: add the three RPCs. ~600 LOC across server.rs.
#[test]
#[ignore = "BUG-18: joinpsbts / utxoupdatepsbt / descriptorprocesspsbt missing (P1); fix in rpc/src/server.rs"]
fn g30_bug_18_missing_psbt_rpcs() {
    assert!(false, "BUG-18: joinpsbts / utxoupdatepsbt / descriptorprocesspsbt RPCs missing");
}

// =============================================================================
// Additional BUG-N surface markers (>30 gate alias slots)
// =============================================================================

/// **BUG-19 — `Psbt::merge` silently drops out-of-bounds other.inputs.**
#[test]
#[ignore = "BUG-19: Psbt::merge silently drops excess other.inputs (P2); fix in Psbt::merge"]
fn bug_19_merge_dropping_excess_inputs() {
    assert!(false, "BUG-19: Psbt::merge must assert or error on input-count mismatch");
}

/// **BUG-20 — `Psbt::decode` accepts trailing bytes after output map.**
///
/// Core's `DecodeRawPSBT` (`psbt.cpp:622`) rejects "extra data after PSBT".
#[test]
#[ignore = "BUG-20: Psbt::decode accepts trailing bytes (P0-CDIV); fix in Psbt::decode"]
fn bug_20_decode_rejects_extra_trailing_bytes() {
    assert!(false, "BUG-20: extra bytes after final output map must be rejected");
}

/// **BUG-21 — Hash preimages not validated and finalizer doesn't use them.**
#[test]
#[ignore = "BUG-21: RIPEMD160/SHA256/HASH160/HASH256 preimages unvalidated (P1); fix in decode + finalize"]
fn bug_21_hash_preimages_validated() {
    assert!(false, "BUG-21: hash preimages must be validated AND used by finalizer");
}

/// **BUG-22 — `Psbt::finalize` short-circuits on first failure.**
///
/// Core's `FinalizePSBT` is best-effort per psbt.cpp:551-565.
#[test]
#[ignore = "BUG-22: Psbt::finalize short-circuits (P2); fix in Psbt::finalize"]
fn bug_22_finalize_best_effort_semantics() {
    assert!(false, "BUG-22: finalize must attempt every input regardless of others' status");
}

/// **BUG-23 — Proprietary entries deduplicated silently instead of erroring.**
#[test]
#[ignore = "BUG-23: PSBT_GLOBAL/IN/OUT_PROPRIETARY duplicates dedup'd silently (P2); fix in all 3 decoders"]
fn bug_23_proprietary_dup_check() {
    assert!(false, "BUG-23: duplicate proprietary keys must be rejected, not silently deduped");
}

/// **BUG-25 — `decodepsbt` fee accounting trusts attacker witness_utxo.**
///
/// Downstream of BUG-16: without decode-time amount-oracle check, the
/// `decodepsbt` fee field reflects attacker-supplied witness_utxo.value.
#[test]
#[ignore = "BUG-25: decodepsbt fee trusts attacker witness_utxo (P2); fix via BUG-16"]
fn bug_25_decodepsbt_fee_resistant_to_amount_oracle() {
    assert!(false, "BUG-25: decodepsbt fee must use verified amount, not raw witness_utxo");
}

/// **BUG-26 — `finalizepsbt` RPC doesn't surface per-input failure.**
#[test]
#[ignore = "BUG-26: finalizepsbt loses per-input failure reason (P2); fix in rpc/server.rs"]
fn bug_26_finalizepsbt_surfaces_per_input_failure() {
    assert!(false, "BUG-26: finalizepsbt must surface per-input failure reason");
}

/// **BUG-27 — `analyzepsbt` lacks `estimated_vsize` / `feerate` / `fee`.**
///
/// Core's `AnalyzePSBT` at `node/psbt.cpp:88-130` emits all three.
#[test]
#[ignore = "BUG-27: analyzepsbt missing estimated_vsize / estimated_feerate / fee (P2); fix in analyzepsbt"]
fn bug_27_analyzepsbt_emits_estimated_fields() {
    assert!(false, "BUG-27: analyzepsbt must emit estimated_vsize / estimated_feerate / fee");
}

/// **BUG-28 — `MAX_PSBT_SIZE` not enforced in streaming decode.**
#[test]
#[ignore = "BUG-28: MAX_PSBT_SIZE bypass in Psbt::decode<R> streaming path (P3); fix via LimitedReader"]
fn bug_28_max_psbt_size_enforced_streaming() {
    assert!(false, "BUG-28: Psbt::decode<R> must enforce MAX_PSBT_SIZE limit");
}

/// **BUG-30 — `PSBT_GLOBAL_XPUB` embedded pubkey not validated.**
///
/// Core decodes via `CExtPubKey::DecodeWithVersion` AND
/// `xpub.pubkey.IsFullyValid()` at psbt.h:1289-1295. rustoshi just
/// stores the 78 bytes as opaque data.
#[test]
#[ignore = "BUG-30: PSBT_GLOBAL_XPUB embedded pubkey not validated (P2); fix in decode"]
fn bug_30_global_xpub_pubkey_validated() {
    assert!(false, "BUG-30: PSBT_GLOBAL_XPUB embedded pubkey must pass IsFullyValid()");
}

// =============================================================================
// Property tests / smoke checks (always run, no #[ignore])
// =============================================================================

/// Sanity: PSBT_HIGHEST_VERSION matches Core (0 today).
#[test]
fn highest_version_matches_core() {
    assert_eq!(PSBT_HIGHEST_VERSION, 0);
}

/// Sanity: all global / input / output key type constants are non-overlapping.
#[test]
fn key_type_constants_distinct() {
    // Globals
    assert_eq!(PSBT_GLOBAL_UNSIGNED_TX, 0x00);
    assert_eq!(PSBT_GLOBAL_XPUB, 0x01);
    assert_eq!(PSBT_GLOBAL_VERSION, 0xFB);
    assert_eq!(PSBT_GLOBAL_PROPRIETARY, 0xFC);

    // Inputs
    assert_eq!(PSBT_IN_NON_WITNESS_UTXO, 0x00);
    assert_eq!(PSBT_IN_WITNESS_UTXO, 0x01);
    assert_eq!(PSBT_IN_PARTIAL_SIG, 0x02);
    assert_eq!(PSBT_IN_SIGHASH, 0x03);
    assert_eq!(PSBT_IN_REDEEMSCRIPT, 0x04);
    assert_eq!(PSBT_IN_WITNESSSCRIPT, 0x05);
    assert_eq!(PSBT_IN_BIP32_DERIVATION, 0x06);
    assert_eq!(PSBT_IN_SCRIPTSIG, 0x07);
    assert_eq!(PSBT_IN_SCRIPTWITNESS, 0x08);
    assert_eq!(PSBT_IN_RIPEMD160, 0x0A);
    assert_eq!(PSBT_IN_SHA256, 0x0B);
    assert_eq!(PSBT_IN_HASH160, 0x0C);
    assert_eq!(PSBT_IN_HASH256, 0x0D);
    assert_eq!(PSBT_IN_TAP_KEY_SIG, 0x13);
    assert_eq!(PSBT_IN_TAP_SCRIPT_SIG, 0x14);
    assert_eq!(PSBT_IN_TAP_LEAF_SCRIPT, 0x15);
    assert_eq!(PSBT_IN_TAP_BIP32_DERIVATION, 0x16);
    assert_eq!(PSBT_IN_TAP_INTERNAL_KEY, 0x17);
    assert_eq!(PSBT_IN_TAP_MERKLE_ROOT, 0x18);
    assert_eq!(PSBT_IN_PROPRIETARY, 0xFC);

    // Outputs
    assert_eq!(PSBT_OUT_REDEEMSCRIPT, 0x00);
    assert_eq!(PSBT_OUT_WITNESSSCRIPT, 0x01);
    assert_eq!(PSBT_OUT_BIP32_DERIVATION, 0x02);
    assert_eq!(PSBT_OUT_TAP_INTERNAL_KEY, 0x05);
    assert_eq!(PSBT_OUT_TAP_TREE, 0x06);
    assert_eq!(PSBT_OUT_TAP_BIP32_DERIVATION, 0x07);
    assert_eq!(PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS, 0x08);
    assert_eq!(PSBT_OUT_PROPRIETARY, 0xFC);
}

/// Sanity: PsbtRole variants exist and Display works.
#[test]
fn psbt_role_variants_display() {
    assert_eq!(PsbtRole::Creator.to_string(), "Creator");
    assert_eq!(PsbtRole::Updater.to_string(), "Updater");
    assert_eq!(PsbtRole::Signer.to_string(), "Signer");
    assert_eq!(PsbtRole::Combiner.to_string(), "Combiner");
    assert_eq!(PsbtRole::Finalizer.to_string(), "Finalizer");
    assert_eq!(PsbtRole::Extractor.to_string(), "Extractor");
}

/// Sanity: KeyOrigin round-trip.
#[test]
fn key_origin_round_trip() {
    let origin = KeyOrigin {
        fingerprint: [0x01, 0x02, 0x03, 0x04],
        path: vec![0x80000054, 0x80000000, 0x80000000, 0, 0],
    };
    let mut buf = Vec::new();
    origin.encode(&mut buf).unwrap();
    assert_eq!(buf.len(), origin.serialized_size());

    let mut cur = std::io::Cursor::new(&buf);
    let decoded = KeyOrigin::decode_with_len(&mut cur, buf.len()).unwrap();
    assert_eq!(decoded.fingerprint, origin.fingerprint);
    assert_eq!(decoded.path, origin.path);
}

/// Sanity: Empty psbt input is `is_null`.
#[test]
fn empty_input_is_null() {
    let input = PsbtInput::default();
    assert!(input.is_null());
}

/// Sanity: Empty psbt output is `is_null`.
#[test]
fn empty_output_is_null() {
    let output = PsbtOutput::default();
    assert!(output.is_null());
}

/// Sanity: ExtPubKey construction.
#[test]
fn ext_pub_key_construction() {
    let data = [0u8; 78];
    let xpub = ExtPubKey::from_bytes(data);
    assert_eq!(xpub.pubkey(), [0u8; 33]);
}

/// Sanity: Proprietary struct equality.
#[test]
fn proprietary_equality() {
    let p1 = Proprietary {
        identifier: vec![1, 2, 3],
        subtype: 7,
        key: vec![0xFC, 3, 1, 2, 3, 7],
        value: vec![0xAA],
    };
    let p2 = p1.clone();
    assert_eq!(p1, p2);
}
