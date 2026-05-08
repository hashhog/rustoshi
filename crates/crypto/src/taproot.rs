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

    let secp = secp256k1::Secp256k1::verification_only();
    let (output_key, parity) = internal_xonly
        .add_tweak(&secp, &tweak)
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

}
