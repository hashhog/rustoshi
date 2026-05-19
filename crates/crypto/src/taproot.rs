//! Canonical BIP-341 / BIP-342 Taproot primitives.
//!
//! This module is the single source of truth for the cryptographic
//! pieces that BIP-341 specifies: tapleaf hash, tapbranch combine,
//! taproot output-key tweak, BIP-341 sighash, and the CompactSize
//! encoder used inside those preimages.
//!
//! Lifted out of `rustoshi-consensus` so the wallet (and any other
//! crate that needs to construct or verify Taproot data) can call the
//! exact same helpers consensus uses, without taking a wallet→consensus
//! dependency edge. See `bitcoin-core/src/script/interpreter.cpp` for
//! the canonical reference.
//!
//! ## What lives here
//!
//! - [`compute_tapleaf_hash`]: `TaggedHash("TapLeaf", leaf_version || compact_size(script) || script)`
//! - [`compute_tapbranch_hash`]: lex-sorted `TaggedHash("TapBranch", a || b)`
//! - [`compute_taproot_output_key`]: BIP-341 output-key tweak (key-path or with merkle root)
//! - [`compute_taproot_sighash`] / [`build_sig_msg`]: BIP-341 sighash including
//!   annex (field 12) and tapscript ext_flag=1 (field 14).
//! - [`write_compact_size`]: 1/3/5/9-byte CompactSize encoder.
//!
//! ## CompactSize correctness (W27-C P0-2)
//!
//! `write_compact_size` here covers ALL four CompactSize size classes
//! (`< 0xfd`, `<= 0xffff`, `<= 0xffff_ffff`, full u64). The wallet
//! previously had a single-byte-only encoder in `descriptor.rs` that
//! errored out on scripts ≥ 253 bytes. That is the same bug class that
//! hit clearbit at h=947,960 (Ordinals tapscript >65535B → wrong
//! tapleaf hash). Always go through this helper.

use crate::{sha256, tagged_hash};
use rustoshi_primitives::transaction::{Transaction, TxOut};

// =====================================================================
// SIGHASH constants (BIP-341)
// =====================================================================

/// SIGHASH flag constants as defined in BIP-341.
pub const SIGHASH_DEFAULT: u8 = 0x00;
pub const SIGHASH_ALL: u8 = 0x01;
pub const SIGHASH_NONE: u8 = 0x02;
pub const SIGHASH_SINGLE: u8 = 0x03;
pub const SIGHASH_ANYONECANPAY: u8 = 0x80;

/// Per BIP-341, the only valid hash_type bytes are these:
/// 0x00 (SIGHASH_DEFAULT), 0x01, 0x02, 0x03, 0x81, 0x82, 0x83.
pub fn is_valid_taproot_hash_type(hash_type: u8) -> bool {
    let base = hash_type & 0x03;
    let upper = hash_type & !0x83;
    upper == 0 && (hash_type == 0x00 || base != 0x00)
}

/// Errors that can occur while computing a Taproot sighash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaprootSighashError {
    InvalidHashType,
    InputIndexOutOfRange,
    PrevoutsLengthMismatch,
    SighashSingleNoMatchingOutput,
}

/// Per-input prevout context required by BIP-341.
///
/// The verifier needs all spent outputs (amounts + scripts) for every
/// input in the transaction, not just the input being verified, so it
/// can compute `sha_amounts` and `sha_scriptpubkeys` correctly.
pub struct TaprootPrevouts<'a> {
    pub amounts: &'a [u64],
    pub scripts: &'a [&'a [u8]],
}

/// Optional script-path context (for tapscript OP_CHECKSIG, ext_flag = 1).
pub struct TapscriptContext<'a> {
    pub tapleaf_hash: &'a [u8; 32],
    pub codesep_pos: u32,
}

// =====================================================================
// CompactSize encoder
// =====================================================================

/// Write a Bitcoin CompactSize uint to a `Vec<u8>` buffer.
///
/// Covers all four size classes:
/// - `< 0xfd` ............ 1 byte
/// - `<= 0xffff` ......... 0xfd + 2 bytes LE
/// - `<= 0xffff_ffff` .... 0xfe + 4 bytes LE
/// - full u64 ............ 0xff + 8 bytes LE
///
/// Mirrors `bitcoin-core/src/serialize.h::WriteCompactSize`.
pub fn write_compact_size(out: &mut Vec<u8>, n: u64) {
    if n < 0xFD {
        out.push(n as u8);
    } else if n <= 0xFFFF {
        out.push(0xFD);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xFFFF_FFFF {
        out.push(0xFE);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xFF);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

// =====================================================================
// Tapleaf / Tapbranch / Taproot output-key
// =====================================================================

/// Compute a BIP-341 tapleaf hash:
///
/// `TaggedHash("TapLeaf", leaf_version || compact_size(script.len()) || script)`
///
/// Per BIP-341, `leaf_version` is the control-block byte with the parity
/// bit cleared (`control_block[0] & 0xfe`). For BIP-342 tapscript leaves
/// the value is `0xc0`.
///
/// CRITICAL: the script length is encoded as a CompactSize, NOT a single
/// byte. Scripts ≥ 253 bytes (e.g. Ordinals tapscripts, large multi-key
/// tapscripts) MUST use the multi-byte encoding or the resulting tapleaf
/// hash will diverge from Core. See [`write_compact_size`].
pub fn compute_tapleaf_hash(leaf_version: u8, script: &[u8]) -> [u8; 32] {
    let mut data = Vec::with_capacity(1 + 9 + script.len());
    data.push(leaf_version);
    write_compact_size(&mut data, script.len() as u64);
    data.extend_from_slice(script);
    tagged_hash("TapLeaf", &data)
}

/// Combine two BIP-341 merkle nodes into a parent:
///
/// `TaggedHash("TapBranch", min(a,b) || max(a,b))`
///
/// Lexicographic ordering is mandatory — Core sorts the children before
/// hashing. Pass either order; this function sorts internally.
pub fn compute_tapbranch_hash(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (left, right) = if a <= b { (a, b) } else { (b, a) };
    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(left);
    data.extend_from_slice(right);
    tagged_hash("TapBranch", &data)
}

/// Compute the raw BIP-341 TapTweak hash:
///
/// - `merkle_root = None` → `TaggedHash("TapTweak", internal_key)` (BIP-86)
/// - `merkle_root = Some(root)` → `TaggedHash("TapTweak", internal_key || root)`
///
/// Useful when the caller already has an x-only key and needs the
/// tweak as a scalar to feed into `Keypair::add_xonly_tweak` for
/// signing (e.g. wallet sign-paths). For pure output construction
/// callers should prefer [`compute_taproot_output_key`].
pub fn compute_taproot_tweak_hash(
    internal_xonly_serialized: &[u8; 32],
    merkle_root: Option<&[u8; 32]>,
) -> [u8; 32] {
    match merkle_root {
        None => tagged_hash("TapTweak", internal_xonly_serialized),
        Some(root) => {
            let mut data = Vec::with_capacity(64);
            data.extend_from_slice(internal_xonly_serialized);
            data.extend_from_slice(root);
            tagged_hash("TapTweak", &data)
        }
    }
}

/// Compute the BIP-341 Taproot tweaked output key from an internal
/// x-only key and an optional Merkle root.
///
/// - For BIP-86 key-path-only spending, pass `merkle_root = None`. The
///   tweak preimage is just the internal key (32 bytes).
/// - For full Taproot with a script tree, pass the 32-byte Merkle root.
///   The tweak preimage is `internal_key || merkle_root` (64 bytes).
///
/// Returns `(output_key_xonly_serialized, parity)`. The parity bit is
/// the LSB of the control-block byte for script-path spends; callers
/// performing pure key-path output construction can ignore it.
pub fn compute_taproot_output_key(
    internal_xonly: &secp256k1::XOnlyPublicKey,
    merkle_root: Option<&[u8; 32]>,
) -> Result<([u8; 32], secp256k1::Parity), TaprootError> {
    let internal_bytes = internal_xonly.serialize();
    let tweak_hash = compute_taproot_tweak_hash(&internal_bytes, merkle_root);

    let tweak = secp256k1::Scalar::from_be_bytes(tweak_hash)
        .map_err(|_| TaprootError::InvalidTweak)?;

    let secp = crate::context::secp_ctx();
    let (output_key, parity) = internal_xonly
        .add_tweak(secp, &tweak)
        .map_err(|_| TaprootError::TweakFailed)?;

    Ok((output_key.serialize(), parity))
}

/// Errors from Taproot output-key derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaprootError {
    InvalidTweak,
    TweakFailed,
}

// =====================================================================
// BIP-341 sighash
// =====================================================================

/// Compute the BIP-341 Taproot sighash.
///
/// Returns the 32-byte tagged hash that must equal the message argument
/// of the Schnorr signature verification.
///
/// `script_path = None` for key-path spends (ext_flag = 0). For
/// tapscript OP_CHECKSIG, pass `Some(...)` and the function will set
/// ext_flag = 1 internally and append the tapscript suffix.
///
/// `annex` should be `Some(&[..])` if a witness annex is present (the
/// 0x50-prefixed last witness item, with the 0x50 byte INCLUDED).
///
/// Validated against `bitcoin-core/src/test/data/bip341_wallet_vectors.json`.
pub fn compute_taproot_sighash(
    tx: &Transaction,
    input_index: usize,
    prevouts: TaprootPrevouts<'_>,
    hash_type: u8,
    annex: Option<&[u8]>,
    script_path: Option<TapscriptContext<'_>>,
) -> Result<[u8; 32], TaprootSighashError> {
    let preimage = build_sig_msg(tx, input_index, prevouts, hash_type, annex, script_path)?;
    Ok(tagged_hash("TapSighash", &preimage))
}

/// Build the BIP-341 "Common signature message" preimage (i.e. the bytes
/// that get fed into `tagged_hash("TapSighash", ...)`).
///
/// Exposed separately from `compute_taproot_sighash` for round-trip
/// validation against the `intermediary.sigMsg` field of the BIP-341
/// test vectors.
pub fn build_sig_msg(
    tx: &Transaction,
    input_index: usize,
    prevouts: TaprootPrevouts<'_>,
    hash_type: u8,
    annex: Option<&[u8]>,
    script_path: Option<TapscriptContext<'_>>,
) -> Result<Vec<u8>, TaprootSighashError> {
    if input_index >= tx.inputs.len() {
        return Err(TaprootSighashError::InputIndexOutOfRange);
    }
    if prevouts.amounts.len() != tx.inputs.len() || prevouts.scripts.len() != tx.inputs.len() {
        return Err(TaprootSighashError::PrevoutsLengthMismatch);
    }
    if !is_valid_taproot_hash_type(hash_type) {
        return Err(TaprootSighashError::InvalidHashType);
    }

    // For branching purposes 0x00 (SIGHASH_DEFAULT) behaves like SIGHASH_ALL,
    // but the byte we serialize into the preimage is the original hash_type.
    let output_type = if hash_type == SIGHASH_DEFAULT {
        SIGHASH_ALL
    } else {
        hash_type & 0x03
    };
    let anyone_can_pay = (hash_type & SIGHASH_ANYONECANPAY) != 0;
    let ext_flag: u8 = if script_path.is_some() { 1 } else { 0 };

    let mut out = Vec::with_capacity(206);

    // 1. Epoch byte.
    out.push(0x00);

    // 2. hash_type — write the original byte (so SIGHASH_DEFAULT serializes as 0x00).
    out.push(hash_type);

    // 3. nVersion (i32 LE).
    out.extend_from_slice(&tx.version.to_le_bytes());

    // 4. nLockTime (u32 LE).
    out.extend_from_slice(&tx.lock_time.to_le_bytes());

    // 5-8. sha_prevouts / sha_amounts / sha_scriptpubkeys / sha_sequences
    //     — only when NOT SIGHASH_ANYONECANPAY.
    if !anyone_can_pay {
        let mut prevouts_buf = Vec::with_capacity(36 * tx.inputs.len());
        for inp in &tx.inputs {
            prevouts_buf.extend_from_slice(&inp.previous_output.txid.0);
            prevouts_buf.extend_from_slice(&inp.previous_output.vout.to_le_bytes());
        }
        out.extend_from_slice(&sha256(&prevouts_buf));

        let mut amounts_buf = Vec::with_capacity(8 * tx.inputs.len());
        for amt in prevouts.amounts {
            amounts_buf.extend_from_slice(&amt.to_le_bytes());
        }
        out.extend_from_slice(&sha256(&amounts_buf));

        let mut scripts_buf = Vec::new();
        for script in prevouts.scripts {
            write_compact_size(&mut scripts_buf, script.len() as u64);
            scripts_buf.extend_from_slice(script);
        }
        out.extend_from_slice(&sha256(&scripts_buf));

        let mut sequences_buf = Vec::with_capacity(4 * tx.inputs.len());
        for inp in &tx.inputs {
            sequences_buf.extend_from_slice(&inp.sequence.to_le_bytes());
        }
        out.extend_from_slice(&sha256(&sequences_buf));
    }

    // 9. sha_outputs — only when NOT SIGHASH_NONE/SINGLE.
    if output_type != SIGHASH_NONE && output_type != SIGHASH_SINGLE {
        let mut outputs_buf = Vec::new();
        for o in &tx.outputs {
            encode_txout(&mut outputs_buf, o);
        }
        out.extend_from_slice(&sha256(&outputs_buf));
    }

    // 10. spend_type byte = (ext_flag * 2) | (annex_present ? 1 : 0).
    let mut spend_type = ext_flag * 2;
    if annex.is_some() {
        spend_type |= 1;
    }
    out.push(spend_type);

    // 11. Per-input data — outpoint+amount+script+sequence if ANYONECANPAY,
    //     else just the input_index as u32 LE.
    if anyone_can_pay {
        let inp = &tx.inputs[input_index];
        out.extend_from_slice(&inp.previous_output.txid.0);
        out.extend_from_slice(&inp.previous_output.vout.to_le_bytes());
        out.extend_from_slice(&prevouts.amounts[input_index].to_le_bytes());
        write_compact_size(&mut out, prevouts.scripts[input_index].len() as u64);
        out.extend_from_slice(prevouts.scripts[input_index]);
        out.extend_from_slice(&inp.sequence.to_le_bytes());
    } else {
        out.extend_from_slice(&(input_index as u32).to_le_bytes());
    }

    // 12. sha_annex (only when annex is present).
    if let Some(annex_bytes) = annex {
        let mut annex_buf = Vec::with_capacity(9 + annex_bytes.len());
        write_compact_size(&mut annex_buf, annex_bytes.len() as u64);
        annex_buf.extend_from_slice(annex_bytes);
        out.extend_from_slice(&sha256(&annex_buf));
    }

    // 13. sha_single_output — only for SIGHASH_SINGLE, after annex.
    //     Per BIP-341 this comes AFTER the per-input data and annex,
    //     not in place of sha_outputs.
    if output_type == SIGHASH_SINGLE {
        if input_index >= tx.outputs.len() {
            return Err(TaprootSighashError::SighashSingleNoMatchingOutput);
        }
        let mut single_buf = Vec::new();
        encode_txout(&mut single_buf, &tx.outputs[input_index]);
        out.extend_from_slice(&sha256(&single_buf));
    }

    // 14. Tapscript extensions — only for ext_flag = 1 (script-path).
    if let Some(sp) = script_path {
        out.extend_from_slice(sp.tapleaf_hash);
        out.push(0x00); // key_version
        out.extend_from_slice(&sp.codesep_pos.to_le_bytes());
    }

    Ok(out)
}

/// Encode a TxOut as `value (8 LE) || compact_size(script_len) || script`.
fn encode_txout(out: &mut Vec<u8>, txout: &TxOut) {
    out.extend_from_slice(&txout.value.to_le_bytes());
    write_compact_size(out, txout.script_pubkey.len() as u64);
    out.extend_from_slice(&txout.script_pubkey);
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// CompactSize round-trip for the four boundary cases.
    #[test]
    fn compact_size_boundaries() {
        let mut buf = Vec::new();

        write_compact_size(&mut buf, 0);
        assert_eq!(buf, vec![0x00]);
        buf.clear();

        write_compact_size(&mut buf, 252);
        assert_eq!(buf, vec![0xFC]);
        buf.clear();

        write_compact_size(&mut buf, 253);
        assert_eq!(buf, vec![0xFD, 0xFD, 0x00]);
        buf.clear();

        write_compact_size(&mut buf, 0xFFFF);
        assert_eq!(buf, vec![0xFD, 0xFF, 0xFF]);
        buf.clear();

        write_compact_size(&mut buf, 0x1_0000);
        assert_eq!(buf, vec![0xFE, 0x00, 0x00, 0x01, 0x00]);
        buf.clear();

        write_compact_size(&mut buf, 0xFFFF_FFFF);
        assert_eq!(buf, vec![0xFE, 0xFF, 0xFF, 0xFF, 0xFF]);
        buf.clear();

        write_compact_size(&mut buf, 0x1_0000_0000);
        assert_eq!(buf, vec![0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);
    }

    /// W27-C P0-2 regression: a tapleaf with a 65,536-byte script (just
    /// over the 0xffff CompactSize boundary) must hash correctly using
    /// the 5-byte CompactSize form (0xFE + u32 LE). The pre-fix wallet
    /// helper bailed out at length ≥ 253; this is the same bug class
    /// that hit clearbit at h=947,960.
    #[test]
    fn tapleaf_hash_handles_script_over_compactsize_boundary() {
        let leaf_version = 0xc0u8;
        let script = vec![0xABu8; 65_536];

        let actual = compute_tapleaf_hash(leaf_version, &script);

        // Manually compute the expected hash as
        //   TaggedHash("TapLeaf", 0xc0 || 0xFE || u32_le(65_536) || script)
        let mut expected_data = Vec::with_capacity(1 + 5 + 65_536);
        expected_data.push(leaf_version);
        expected_data.push(0xFE);
        expected_data.extend_from_slice(&(65_536u32).to_le_bytes());
        expected_data.extend_from_slice(&script);
        let expected = tagged_hash("TapLeaf", &expected_data);

        assert_eq!(actual, expected);
        // Sanity: script length is past the single-byte CompactSize cap
        // and past the 3-byte form, so this exercises the 5-byte form.
        assert!(script.len() > 0xFFFF);
    }

    /// Tapleaf hash on a 253-byte script (the smallest size that the
    /// pre-fix `wallet/descriptor.rs::compute_taproot_merkle_root`
    /// would have rejected with "script too large"). Verifies the
    /// 3-byte CompactSize encoding is used.
    #[test]
    fn tapleaf_hash_handles_script_at_3_byte_compactsize_cutoff() {
        let leaf_version = 0xc0u8;
        let script = vec![0xCDu8; 253];

        let actual = compute_tapleaf_hash(leaf_version, &script);

        let mut expected_data = Vec::with_capacity(1 + 3 + 253);
        expected_data.push(leaf_version);
        expected_data.push(0xFD);
        expected_data.extend_from_slice(&(253u16).to_le_bytes());
        expected_data.extend_from_slice(&script);
        let expected = tagged_hash("TapLeaf", &expected_data);

        assert_eq!(actual, expected);
    }

    /// Tapbranch sorts children lexicographically before hashing.
    #[test]
    fn tapbranch_hash_is_order_independent() {
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];
        assert_eq!(compute_tapbranch_hash(&a, &b), compute_tapbranch_hash(&b, &a));
    }

    /// BIP-86 output-key tweak (no merkle root) round-trips against a
    /// re-derivation of the tagged hash, and accepts the result as a
    /// valid x-only key.
    #[test]
    fn taproot_output_key_bip86_keypath_only() {
        let secp = secp256k1::Secp256k1::new();
        // Deterministic test key.
        let sk = secp256k1::SecretKey::from_slice(&[0x42u8; 32]).unwrap();
        let kp = secp256k1::Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = kp.x_only_public_key();

        let (output_key, _parity) = compute_taproot_output_key(&xonly, None).unwrap();

        // Re-derive directly to make sure we used the BIP-86 form
        // (tweak preimage = internal_key only).
        let direct_tweak = tagged_hash("TapTweak", &xonly.serialize());
        let scalar = secp256k1::Scalar::from_be_bytes(direct_tweak).unwrap();
        let (expected, _) = xonly.add_tweak(&secp, &scalar).unwrap();
        assert_eq!(output_key, expected.serialize());
    }

    // =================================================================
    // BIP-341 sighash tests (W27-C P0-1 regression coverage).
    //
    // The wallet previously shipped a duplicate of `compute_taproot_sighash`
    // that diverged on SIGHASH_SINGLE — it placed the single-output digest
    // at field 9 (where `sha_outputs` lives for ALL/NONE) instead of after
    // fields 11+12 (per-input + annex). These tests verify the canonical
    // helper (the surviving copy) gets BIP-341 right.
    // =================================================================

    use rustoshi_primitives::{Hash256, OutPoint, TxIn};
    use rustoshi_primitives::transaction::{Transaction, TxOut};

    /// Build a small, deterministic 2-input / 2-output Taproot transaction
    /// for sighash tests, plus a matching `(amounts, scripts)` set of
    /// "prevouts" (32-byte v1 witness programs).
    fn make_test_tx() -> (Transaction, Vec<u64>, Vec<Vec<u8>>) {
        // Two distinct dummy outpoints.
        let inp_a = TxIn {
            previous_output: OutPoint {
                txid: Hash256([0xAAu8; 32]),
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0xFFFF_FFFE,
            witness: vec![],
        };
        let inp_b = TxIn {
            previous_output: OutPoint {
                txid: Hash256([0xBBu8; 32]),
                vout: 1,
            },
            script_sig: vec![],
            sequence: 0xFFFF_FFFE,
            witness: vec![],
        };

        // Two outputs with distinct script + value bytes.
        let mut spk0 = vec![0x51u8, 0x20];
        spk0.extend_from_slice(&[0x11u8; 32]);
        let mut spk1 = vec![0x51u8, 0x20];
        spk1.extend_from_slice(&[0x22u8; 32]);
        let out0 = TxOut {
            value: 50_000,
            script_pubkey: spk0,
        };
        let out1 = TxOut {
            value: 60_000,
            script_pubkey: spk1,
        };

        let tx = Transaction {
            version: 2,
            inputs: vec![inp_a, inp_b],
            outputs: vec![out0, out1],
            lock_time: 0,
        };

        // Prevout amounts and v1 scriptPubKeys (32-byte witness programs).
        let amounts = vec![100_000u64, 100_000u64];
        let mut prev_spk_a = vec![0x51u8, 0x20];
        prev_spk_a.extend_from_slice(&[0x33u8; 32]);
        let mut prev_spk_b = vec![0x51u8, 0x20];
        prev_spk_b.extend_from_slice(&[0x44u8; 32]);
        let scripts = vec![prev_spk_a, prev_spk_b];

        (tx, amounts, scripts)
    }

    /// W27-C P0-1: SIGHASH_DEFAULT round-trip — sign with the canonical
    /// helper + tweaked keypair, then verify with secp256k1's Schnorr
    /// verifier against the same digest. This is the "did the wallet's
    /// sig actually verify?" guard.
    #[test]
    fn sighash_default_signs_and_verifies() {
        let (tx, amounts, scripts) = make_test_tx();
        let scripts_refs: Vec<&[u8]> = scripts.iter().map(|s| s.as_slice()).collect();

        let secp = secp256k1::Secp256k1::new();
        let sk = secp256k1::SecretKey::from_slice(&[0x77u8; 32]).unwrap();
        let kp = secp256k1::Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = kp.x_only_public_key();

        // BIP-86 tweak (no merkle root).
        let tweak_hash = compute_taproot_tweak_hash(&xonly.serialize(), None);
        let tweak = secp256k1::Scalar::from_be_bytes(tweak_hash).unwrap();
        let tweaked_kp = kp.add_xonly_tweak(&secp, &tweak).unwrap();
        let (tweaked_xonly, _) = tweaked_kp.x_only_public_key();

        let sighash = compute_taproot_sighash(
            &tx,
            0,
            TaprootPrevouts {
                amounts: &amounts,
                scripts: &scripts_refs,
            },
            SIGHASH_DEFAULT,
            None,
            None,
        )
        .expect("sighash");

        let msg = secp256k1::Message::from_digest(sighash);
        let sig = secp.sign_schnorr(&msg, &tweaked_kp);
        assert!(secp.verify_schnorr(&sig, &msg, &tweaked_xonly).is_ok());
    }

    /// W27-C P0-1 regression: SIGHASH_SINGLE must produce a digest
    /// distinct from SIGHASH_ALL on the same input, and the resulting
    /// signature must verify under the verify-side path. The pre-fix
    /// duplicate in `wallet.rs` placed the single-output digest at the
    /// SIGHASH_ALL field-9 position; that made every wallet-signed
    /// SIGHASH_SINGLE input produce a sig the consensus layer rejected.
    #[test]
    fn sighash_single_distinct_from_all_and_verifies() {
        let (tx, amounts, scripts) = make_test_tx();
        let scripts_refs: Vec<&[u8]> = scripts.iter().map(|s| s.as_slice()).collect();

        let secp = secp256k1::Secp256k1::new();
        let sk = secp256k1::SecretKey::from_slice(&[0x88u8; 32]).unwrap();
        let kp = secp256k1::Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = kp.x_only_public_key();
        let tweak_hash = compute_taproot_tweak_hash(&xonly.serialize(), None);
        let tweak = secp256k1::Scalar::from_be_bytes(tweak_hash).unwrap();
        let tweaked_kp = kp.add_xonly_tweak(&secp, &tweak).unwrap();
        let (tweaked_xonly, _) = tweaked_kp.x_only_public_key();

        // The two digests MUST differ between SIGHASH_ALL and SIGHASH_SINGLE.
        let prev_all = TaprootPrevouts {
            amounts: &amounts,
            scripts: &scripts_refs,
        };
        let prev_single = TaprootPrevouts {
            amounts: &amounts,
            scripts: &scripts_refs,
        };

        let h_all = compute_taproot_sighash(&tx, 0, prev_all, SIGHASH_ALL, None, None).unwrap();
        let h_single =
            compute_taproot_sighash(&tx, 0, prev_single, SIGHASH_SINGLE, None, None).unwrap();
        assert_ne!(
            h_all, h_single,
            "SIGHASH_SINGLE must commit to a different digest than SIGHASH_ALL"
        );

        // The SIGHASH_SINGLE preimage must place the single-output
        // digest AFTER per-input data (field 11) — never at field 9.
        // For SIGHASH_SINGLE (not ANYONECANPAY, no annex, key-path), the
        // BIP-341 sigMsg layout is:
        //   1 (epoch) + 1 (hash_type) + 4 (version) + 4 (locktime)     = 10
        //   + 32 (sha_prevouts) + 32 (sha_amounts)
        //     + 32 (sha_scriptpubkeys) + 32 (sha_sequences)             = 138
        //   + 1 (spend_type)                                            = 139
        //   + 4 (input_index)                                           = 143
        //   + 32 (sha_single_output, AFTER per-input data)              = 175
        // No field-9 sha_outputs and no annex.
        let prev_single2 = TaprootPrevouts {
            amounts: &amounts,
            scripts: &scripts_refs,
        };
        let preimage =
            build_sig_msg(&tx, 0, prev_single2, SIGHASH_SINGLE, None, None).unwrap();
        assert_eq!(preimage.len(), 175);

        // And the signature using SINGLE must verify against its own digest.
        let prev_single3 = TaprootPrevouts {
            amounts: &amounts,
            scripts: &scripts_refs,
        };
        let h2 =
            compute_taproot_sighash(&tx, 0, prev_single3, SIGHASH_SINGLE, None, None).unwrap();
        let msg = secp256k1::Message::from_digest(h2);
        let sig = secp.sign_schnorr(&msg, &tweaked_kp);
        assert!(secp.verify_schnorr(&sig, &msg, &tweaked_xonly).is_ok());
    }

    /// W27-C P0-1 regression: SIGHASH_ANYONECANPAY commits only to the
    /// signing input's own outpoint+amount+script+sequence (field 11),
    /// not to the full prevouts arrays at fields 5–8.
    ///
    /// Verifies by computing the same input's digest under two
    /// transactions that DIFFER only in the OTHER input's scriptPubKey.
    /// With ANYONECANPAY the two digests must match; without
    /// ANYONECANPAY they must differ (the other input feeds into
    /// sha_scriptpubkeys).
    #[test]
    fn sighash_anyonecanpay_only_commits_to_signing_input() {
        let (tx, amounts, scripts) = make_test_tx();
        let scripts_refs: Vec<&[u8]> = scripts.iter().map(|s| s.as_slice()).collect();

        // Now mutate the OTHER input's prevout script — input 0 is the
        // one we're "signing", so fiddle with input 1.
        let mut alt_scripts = scripts.clone();
        alt_scripts[1][2] = 0x55; // flip a byte deep inside the v1 program
        let alt_refs: Vec<&[u8]> = alt_scripts.iter().map(|s| s.as_slice()).collect();

        let prev_orig = TaprootPrevouts {
            amounts: &amounts,
            scripts: &scripts_refs,
        };

        // ANYONECANPAY|ALL = 0x81. The two digests must MATCH.
        let h_orig =
            compute_taproot_sighash(&tx, 0, prev_orig, 0x81, None, None).unwrap();
        let prev_alt_again = TaprootPrevouts {
            amounts: &amounts,
            scripts: &alt_refs,
        };
        let h_alt =
            compute_taproot_sighash(&tx, 0, prev_alt_again, 0x81, None, None).unwrap();
        assert_eq!(
            h_orig, h_alt,
            "ANYONECANPAY must NOT commit to the other input's scriptPubKey"
        );

        // Sanity: under SIGHASH_ALL (without ANYONECANPAY), the two
        // digests MUST differ (sha_scriptpubkeys covers all inputs).
        let prev_orig2 = TaprootPrevouts {
            amounts: &amounts,
            scripts: &scripts_refs,
        };
        let prev_alt2 = TaprootPrevouts {
            amounts: &amounts,
            scripts: &alt_refs,
        };
        let g_orig =
            compute_taproot_sighash(&tx, 0, prev_orig2, SIGHASH_ALL, None, None).unwrap();
        let g_alt =
            compute_taproot_sighash(&tx, 0, prev_alt2, SIGHASH_ALL, None, None).unwrap();
        assert_ne!(
            g_orig, g_alt,
            "SIGHASH_ALL must commit to all inputs' scriptPubKeys"
        );
    }

    // =================================================================
    // W95 — `is_valid_taproot_hash_type` exhaustive byte coverage
    // =================================================================
    //
    // Mirrors Bitcoin Core (interpreter.cpp:1516):
    //     if (!(hash_type <= 0x03 || (hash_type >= 0x81 && hash_type <= 0x83)))
    //         return false;
    //
    // PLUS the BIP-341 stipulation that 0x00 means SIGHASH_DEFAULT and may
    // only appear implicitly (with the 64-byte short form). The wire-format
    // check that rejects an explicit 0x00 sighash-type byte in a 65-byte sig
    // is enforced at the caller (validation.rs::check_schnorr_inner).
    //
    // Valid set:  {0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83}.
    // Everything else MUST be rejected.

    #[test]
    fn w95_is_valid_taproot_hash_type_accepts_canonical_set() {
        for ht in [0x00u8, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83] {
            assert!(
                is_valid_taproot_hash_type(ht),
                "0x{ht:02x} must be a valid taproot hash type"
            );
        }
    }

    #[test]
    fn w95_is_valid_taproot_hash_type_rejects_bare_anyonecanpay() {
        // 0x80 alone has no base-type bits — Core line 1516 needs
        // hash_type >= 0x81. Pre-fix audit: rustoshi's helper already
        // rejects this because `base == 0 && hash_type != 0x00`.
        assert!(!is_valid_taproot_hash_type(0x80));
    }

    #[test]
    fn w95_is_valid_taproot_hash_type_rejects_high_bit_garbage() {
        for ht in [0x84u8, 0x85, 0x86, 0x87, 0x88, 0x90, 0xA0, 0xC0, 0xFF] {
            assert!(
                !is_valid_taproot_hash_type(ht),
                "0x{ht:02x} must be rejected (out of canonical set)"
            );
        }
    }

    #[test]
    fn w95_is_valid_taproot_hash_type_rejects_mid_range() {
        // Any 0x04..=0x7F is non-canonical.
        for ht in [0x04u8, 0x05, 0x0F, 0x10, 0x1F, 0x40, 0x7F] {
            assert!(
                !is_valid_taproot_hash_type(ht),
                "0x{ht:02x} must be rejected"
            );
        }
    }

    /// W95 exhaustive: only 7 out of 256 possible bytes are valid.
    #[test]
    fn w95_is_valid_taproot_hash_type_exhaustive() {
        let mut accepted = 0usize;
        for b in 0u8..=255u8 {
            if is_valid_taproot_hash_type(b) {
                accepted += 1;
            }
        }
        assert_eq!(accepted, 7, "must accept exactly 7 sighash bytes");
    }

    // =================================================================
    // W95 — BIP-340 test vectors against secp256k1
    //
    // Vectors 0-4 are positive (should verify). Vectors 5 and 14 are
    // unparseable-pubkey (xonly parse must fail). Vectors 6-13 are
    // negative-signature cases (parse OK, verify must fail), each
    // probing a different rejection gate:
    //   6  — public key not on curve (lift_x fails)
    //   7  — has_even_y(R) is false (R.y odd → must reject)
    //   8  — negated message → wrong challenge
    //   9  — negated s value
    //   10 — sG - eP is the point at infinity
    //   11 — r outside the field range
    //   12 — r exactly p-1 (boundary of field; verify must still
    //        complete; for this vector verify returns false)
    //   13 — s ≥ n (scalar overflow → reject)
    //
    // These pin Core's libsecp256k1 behavior end-to-end through the
    // Rust wrapper. Source:
    //   bitcoin-core/src/secp256k1/src/modules/schnorrsig/tests_impl.h
    // =================================================================

    fn check_verify(pk_hex: &str, msg_hex: &str, sig_hex: &str, expected: bool) {
        let pk_bytes = hex::decode(pk_hex).expect("pk hex");
        let msg_bytes = hex::decode(msg_hex).expect("msg hex");
        let sig_bytes = hex::decode(sig_hex).expect("sig hex");
        assert_eq!(pk_bytes.len(), 32, "pk must be 32 bytes");
        assert_eq!(sig_bytes.len(), 64, "sig must be 64 bytes");
        assert_eq!(msg_bytes.len(), 32, "msg must be 32 bytes");

        let pk_arr: [u8; 32] = pk_bytes.try_into().unwrap();
        let xonly = match secp256k1::XOnlyPublicKey::from_slice(&pk_arr) {
            Ok(k) => k,
            Err(_) => {
                assert!(
                    !expected,
                    "vector said pass but x-only pubkey parse failed (pk={pk_hex})"
                );
                return;
            }
        };
        let sig = match secp256k1::schnorr::Signature::from_slice(&sig_bytes) {
            Ok(s) => s,
            Err(_) => {
                assert!(!expected, "vector said pass but signature parse failed");
                return;
            }
        };
        let msg_arr: [u8; 32] = msg_bytes.try_into().unwrap();
        let msg = secp256k1::Message::from_digest(msg_arr);

        let secp = secp256k1::Secp256k1::verification_only();
        let ok = secp.verify_schnorr(&sig, &msg, &xonly).is_ok();
        assert_eq!(
            ok, expected,
            "BIP-340 vector verdict mismatch (pk={pk_hex}, sig={sig_hex})"
        );
    }

    /// BIP-340 vector 0 — minimal positive case (sk=3, all-zero msg).
    /// Source: bitcoin-core/src/secp256k1/.../schnorrsig/tests_impl.h:209
    #[test]
    fn w95_bip340_vector_0_pass() {
        check_verify(
            "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
            true,
        );
    }

    /// BIP-340 vector 1 — typical positive (sk=0xB7E1…CFEF).
    /// Source: bitcoin-core/src/secp256k1/.../schnorrsig/tests_impl.h:248
    #[test]
    fn w95_bip340_vector_1_pass() {
        check_verify(
            "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
            true,
        );
    }

    /// BIP-340 vector 3 — all-FF msg + all-FF aux_rand positive.
    /// Source: bitcoin-core/src/secp256k1/.../schnorrsig/tests_impl.h:326
    #[test]
    fn w95_bip340_vector_3_pass() {
        check_verify(
            "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3",
            true,
        );
    }

    /// BIP-340 vector 4 — positive verify-only (low x).
    /// Source: bitcoin-core/src/secp256k1/.../schnorrsig/tests_impl.h:365
    #[test]
    fn w95_bip340_vector_4_pass() {
        check_verify(
            "D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9",
            "4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703",
            "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4",
            true,
        );
    }

    /// BIP-340 vector 5 — pubkey not on curve (x-only parse must fail).
    /// Source: bitcoin-core/src/secp256k1/.../schnorrsig/tests_impl.h:391
    #[test]
    fn w95_bip340_vector_5_pubkey_not_on_curve() {
        let pk_arr: [u8; 32] = hex::decode(
            "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34",
        )
        .unwrap()
        .try_into()
        .unwrap();
        assert!(
            secp256k1::XOnlyPublicKey::from_slice(&pk_arr).is_err(),
            "x-only parse must fail for unliftable x"
        );
    }

    /// BIP-340 vector 6 — sig fails verify.
    /// Source: bitcoin-core/src/secp256k1/.../schnorrsig/tests_impl.h:403
    #[test]
    fn w95_bip340_vector_6_fail() {
        check_verify(
            "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A146029755633CC2794640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2",
            false,
        );
    }

    /// BIP-340 vector 7 — has_even_y(R) is false; verify must reject.
    /// Source: bitcoin-core/src/secp256k1/.../schnorrsig/tests_impl.h:429
    #[test]
    fn w95_bip340_vector_7_r_y_odd_rejected() {
        check_verify(
            "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            "1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD",
            false,
        );
    }

    /// BIP-340 vector 8 — wrong challenge; reject.
    /// Source: bitcoin-core/src/secp256k1/.../schnorrsig/tests_impl.h:455
    #[test]
    fn w95_bip340_vector_8_wrong_challenge_rejected() {
        check_verify(
            "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6",
            false,
        );
    }

    /// BIP-340 vector 9 — negated `s`.
    /// Source: bitcoin-core/src/secp256k1/.../schnorrsig/tests_impl.h:481
    #[test]
    fn w95_bip340_vector_9_rejected() {
        check_verify(
            "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            "0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051",
            false,
        );
    }

    /// BIP-340 vector 10 — sG - eP is the point at infinity.
    /// Source: bitcoin-core/src/secp256k1/.../schnorrsig/tests_impl.h:507
    #[test]
    fn w95_bip340_vector_10_r_infinity_rejected() {
        check_verify(
            "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            "00000000000000000000000000000000000000000000000000000000000000017615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197",
            false,
        );
    }

    /// BIP-340 vector 11 — r outside field range.
    /// Pre-fix Core test ensured `fe_set_b32_limit` rejects rx >= p.
    /// Source: bitcoin-core/src/secp256k1/.../schnorrsig/tests_impl.h:533
    #[test]
    fn w95_bip340_vector_11_rx_overflow_rejected() {
        check_verify(
            "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            "4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
            false,
        );
    }

    /// BIP-340 vector 12 — r set to p (boundary). Must reject.
    /// Source: bitcoin-core/src/secp256k1/.../schnorrsig/tests_impl.h:559
    #[test]
    fn w95_bip340_vector_12_rx_equals_p_rejected() {
        check_verify(
            "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
            false,
        );
    }

    /// BIP-340 vector 13 — s ≥ n (scalar overflow). Verify must reject.
    /// Source: bitcoin-core/src/secp256k1/.../schnorrsig/tests_impl.h:585
    #[test]
    fn w95_bip340_vector_13_s_overflow_rejected() {
        check_verify(
            "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            false,
        );
    }

    /// BIP-340 vector 14 — pubkey x-coordinate ≥ p (parse must fail).
    #[test]
    fn w95_bip340_vector_14_pubkey_x_overflow() {
        let pk_arr: [u8; 32] = hex::decode(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
        )
        .unwrap()
        .try_into()
        .unwrap();
        assert!(
            secp256k1::XOnlyPublicKey::from_slice(&pk_arr).is_err(),
            "x-only parse must fail for x >= p"
        );
    }

    /// W95: 64-byte signature length is valid and parses; 63 and 65 do not
    /// for the bare Schnorr type (the 65-byte form is a Taproot-only wrapper
    /// that strips off the sighash byte before calling secp256k1).
    #[test]
    fn w95_schnorr_sig_length_64_only_for_secp() {
        // 64-byte zero sig: parses but won't verify against anything real.
        let zero64 = [0u8; 64];
        assert!(secp256k1::schnorr::Signature::from_slice(&zero64).is_ok());
        // 63-byte: must fail to parse.
        let buf63 = [0u8; 63];
        assert!(secp256k1::schnorr::Signature::from_slice(&buf63).is_err());
        // 65-byte: must fail to parse at this layer (Taproot strips the
        // sighash byte before this call).
        let buf65 = [0u8; 65];
        assert!(secp256k1::schnorr::Signature::from_slice(&buf65).is_err());
    }
}
