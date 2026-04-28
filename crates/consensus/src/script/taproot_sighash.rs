//! BIP-341 Taproot signature hash computation.
//!
//! Reference: <https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki>
//!
//! This module computes the message that gets fed into Schnorr signature
//! verification for Taproot key-path spends and tapscript OP_CHECKSIG.
//!
//! Validated 2026-04-28 against `bitcoin-core/src/test/data/bip341_wallet_vectors.json`
//! via the rustoshi-shim driver in `tools/bip341-vector-runner/`. All
//! 7/7 keyPathSpending vectors pass byte-perfect on `sigMsg` + `sigHash`.

use rustoshi_crypto::{sha256, tagged_hash};
use rustoshi_primitives::transaction::{Transaction, TxOut};

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

/// Compute the BIP-341 Taproot sighash.
///
/// Returns the 32-byte tagged hash that must equal the message argument
/// of the Schnorr signature verification.
///
/// `ext_flag` should be 0 for key-path spends. For tapscript OP_CHECKSIG,
/// pass `script_path = Some(...)` and the function will set ext_flag = 1
/// internally and append the tapscript suffix.
///
/// `annex` should be `Some(&[..])` if a witness annex is present (the
/// 0x50-prefixed last witness item, with the 0x50 byte INCLUDED).
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

/// Write a varint / CompactSize uint to a buffer.
fn write_compact_size(out: &mut Vec<u8>, n: u64) {
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

/// Encode a TxOut as `value (8 LE) || compact_size(script_len) || script`.
fn encode_txout(out: &mut Vec<u8>, txout: &TxOut) {
    out.extend_from_slice(&txout.value.to_le_bytes());
    write_compact_size(out, txout.script_pubkey.len() as u64);
    out.extend_from_slice(&txout.script_pubkey);
}
