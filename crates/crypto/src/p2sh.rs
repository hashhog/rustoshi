//! P2SH / P2WSH commitment verification helpers.
//!
//! Wallets and PSBT signers must verify that a caller-supplied script (the
//! "redeem script" or "witness script") actually commits to the prevout's
//! `scriptPubKey`. Skipping that check makes the signer a confused deputy:
//! a malicious PSBT can hand the wallet an unrelated witness_script that
//! happens to contain the wallet's pubkey, get a SIGHASH_ALL signature for
//! a value/script the wallet never intended to commit to, and steal funds.
//!
//! This is the same bug class that hit hotbuns (see
//! `wave-2026-04-XX-hotbuns-witness-script-cve/`) and that the W30-rustoshi
//! audit found in `sign_psbt_input`.
//!
//! ## Reference
//!
//! - BIP-16 (P2SH): scriptPubKey = `OP_HASH160 <20-byte-hash> OP_EQUAL`
//!   commits to `HASH160(redeem_script)`.
//! - BIP-141 (P2WSH): scriptPubKey = `OP_0 <32-byte-hash>` commits to
//!   `SHA256(witness_script)`.
//! - `bitcoin-core/src/script/interpreter.cpp::EvalScript` (P2SH branch) +
//!   `VerifyScript` (witness branch) — the consensus checks this module
//!   mirrors at the wallet layer.

use crate::hashes::{hash160, sha256};

/// Errors from commitment verification.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CommitmentError {
    /// scriptPubKey doesn't match the expected P2SH shape
    /// (`OP_HASH160 <20> ... OP_EQUAL`, 23 bytes total).
    #[error("scriptPubKey is not P2SH-shaped (expected 23 bytes OP_HASH160 PUSH20 OP_EQUAL)")]
    NotP2sh,

    /// scriptPubKey doesn't match the P2WSH shape (`OP_0 <32> ...`, 34 bytes).
    #[error("scriptPubKey is not P2WSH-shaped (expected 34 bytes OP_0 PUSH32)")]
    NotP2wsh,

    /// `HASH160(redeem_script)` did not match the 20-byte hash committed to
    /// in the P2SH scriptPubKey. Usually means a malicious or mis-built
    /// PSBT handed us a redeem_script that doesn't actually unlock the
    /// prevout we're being asked to sign.
    #[error("P2SH commitment mismatch: redeem_script does not hash to scriptPubKey commitment")]
    P2shMismatch,

    /// `SHA256(witness_script)` did not match the 32-byte hash committed to
    /// in the P2WSH scriptPubKey (the witness program). Same threat model
    /// as `P2shMismatch`.
    #[error("P2WSH commitment mismatch: witness_script does not hash to witness program")]
    P2wshMismatch,
}

/// Verify that `redeem_script` is committed to by the P2SH `pk_script`.
///
/// `pk_script` must be exactly 23 bytes: `OP_HASH160 (0xa9) <20-byte-push>
/// (0x14 || hash160) OP_EQUAL (0x87)`.
///
/// Returns `Ok(())` iff `HASH160(redeem_script) == pk_script[2..22]`.
///
/// ## Why this exists
///
/// Without this check, a PSBT signer accepting a caller-supplied redeem
/// script will produce a valid signature against any script the attacker
/// controls (as long as a wallet pubkey appears in it). The signature is
/// then trivially repackaged into a transaction the wallet never approved.
///
/// ## Reference
///
/// `bitcoin-core/src/script/interpreter.cpp::EvalScript` — the P2SH branch
/// that recognises the `OP_HASH160 PUSH20 OP_EQUAL` template and unwraps
/// the redeem script.
pub fn verify_p2sh_commitment(
    redeem_script: &[u8],
    pk_script: &[u8],
) -> Result<(), CommitmentError> {
    if !is_p2sh(pk_script) {
        return Err(CommitmentError::NotP2sh);
    }
    let expected = &pk_script[2..22];
    let got = hash160(redeem_script);
    if got.0 != *expected {
        return Err(CommitmentError::P2shMismatch);
    }
    Ok(())
}

/// Verify that `witness_script` is committed to by the P2WSH witness
/// program in `pk_script`.
///
/// `pk_script` must be exactly 34 bytes: `OP_0 (0x00) PUSH32 (0x20) ||
/// 32-byte program`.
///
/// Returns `Ok(())` iff `SHA256(witness_script) == pk_script[2..34]`.
///
/// ## Reference
///
/// BIP-141 §"Witness program" + `bitcoin-core/src/script/interpreter.cpp`
/// (`VerifyScript` witness branch).
pub fn verify_p2wsh_commitment(
    witness_script: &[u8],
    pk_script: &[u8],
) -> Result<(), CommitmentError> {
    if !is_p2wsh(pk_script) {
        return Err(CommitmentError::NotP2wsh);
    }
    let expected = &pk_script[2..34];
    let got = sha256(witness_script);
    if got != *expected {
        return Err(CommitmentError::P2wshMismatch);
    }
    Ok(())
}

/// True iff `script` is the canonical P2SH scriptPubKey shape:
/// `OP_HASH160 <20> ... OP_EQUAL` (23 bytes).
#[inline]
pub fn is_p2sh(script: &[u8]) -> bool {
    script.len() == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87
}

/// True iff `script` is the canonical P2WSH scriptPubKey shape:
/// `OP_0 <32> ...` (34 bytes).
#[inline]
pub fn is_p2wsh(script: &[u8]) -> bool {
    script.len() == 34 && script[0] == 0x00 && script[1] == 0x20
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_p2sh_spk(redeem: &[u8]) -> Vec<u8> {
        let h = hash160(redeem);
        let mut spk = Vec::with_capacity(23);
        spk.push(0xa9);
        spk.push(0x14);
        spk.extend_from_slice(&h.0);
        spk.push(0x87);
        spk
    }

    fn build_p2wsh_spk(witness_script: &[u8]) -> Vec<u8> {
        let h = sha256(witness_script);
        let mut spk = Vec::with_capacity(34);
        spk.push(0x00);
        spk.push(0x20);
        spk.extend_from_slice(&h);
        spk
    }

    #[test]
    fn p2sh_commitment_accept() {
        let redeem = b"redeem-script-bytes-arbitrary".to_vec();
        let spk = build_p2sh_spk(&redeem);
        verify_p2sh_commitment(&redeem, &spk).expect("matching redeem must verify");
    }

    #[test]
    fn p2sh_commitment_reject_forged() {
        let redeem = b"the-real-redeem".to_vec();
        let forged = b"NOT-the-real-redeem".to_vec();
        let spk = build_p2sh_spk(&redeem);
        let err = verify_p2sh_commitment(&forged, &spk).unwrap_err();
        assert_eq!(err, CommitmentError::P2shMismatch);
    }

    #[test]
    fn p2sh_commitment_reject_not_p2sh() {
        let redeem = b"any".to_vec();
        // Too short to be a P2SH scriptPubKey (23 bytes required).
        let bad_spk: Vec<u8> = vec![0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0];
        let err = verify_p2sh_commitment(&redeem, &bad_spk).unwrap_err();
        assert_eq!(err, CommitmentError::NotP2sh);
    }

    #[test]
    fn p2wsh_commitment_accept() {
        let ws = vec![0x51u8; 71]; // arbitrary 71-byte script (a multisig length)
        let spk = build_p2wsh_spk(&ws);
        verify_p2wsh_commitment(&ws, &spk).expect("matching witness script must verify");
    }

    #[test]
    fn p2wsh_commitment_reject_forged() {
        let real = vec![0x51u8; 71];
        let forged = vec![0x52u8; 71];
        let spk = build_p2wsh_spk(&real);
        let err = verify_p2wsh_commitment(&forged, &spk).unwrap_err();
        assert_eq!(err, CommitmentError::P2wshMismatch);
    }

    #[test]
    fn p2wsh_commitment_reject_not_p2wsh() {
        let ws = vec![0x51u8; 4];
        // P2WPKH-shaped (22 bytes), not P2WSH.
        let mut bad_spk: Vec<u8> = vec![0x00, 0x14];
        bad_spk.extend_from_slice(&[0u8; 20]);
        let err = verify_p2wsh_commitment(&ws, &bad_spk).unwrap_err();
        assert_eq!(err, CommitmentError::NotP2wsh);
    }

    #[test]
    fn shape_predicates() {
        assert!(is_p2sh(&[
            0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x87
        ]));
        assert!(!is_p2sh(&[0xa9, 0x14, 0x87])); // too short

        let mut p2wsh = vec![0x00, 0x20];
        p2wsh.extend_from_slice(&[0u8; 32]);
        assert!(is_p2wsh(&p2wsh));

        // P2WPKH shape (22 bytes) — not P2WSH.
        let mut p2wpkh = vec![0x00, 0x14];
        p2wpkh.extend_from_slice(&[0u8; 20]);
        assert!(!is_p2wsh(&p2wpkh));
    }
}
