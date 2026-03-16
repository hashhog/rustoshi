//! Transaction signature hash computation.
//!
//! This module implements the signature hash algorithms used in Bitcoin:
//! - Legacy sighash (pre-SegWit)
//! - BIP-143 sighash (SegWit v0)
//!
//! The signature hash is the message that gets signed by ECDSA. Different
//! sighash types allow signing different parts of the transaction.
//!
//! For legacy sighash, this module also implements:
//! - FindAndDelete: removes the push-encoded signature from the scriptCode
//! - OP_CODESEPARATOR handling: scriptCode starts after the last separator

use crate::hashes::sha256d;
use rustoshi_primitives::{write_compact_size, Encodable, Hash256, OutPoint, Transaction};
use std::io::Write;

/// OP_CODESEPARATOR opcode value.
pub const OP_CODESEPARATOR: u8 = 0xab;

/// Sighash type flags.
///
/// The sighash type is a single byte appended to the signature that determines
/// which parts of the transaction are signed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigHashType(pub u32);

impl SigHashType {
    /// Sign all inputs and outputs (default)
    pub const ALL: SigHashType = SigHashType(0x01);
    /// Sign all inputs, but no outputs (allows anyone to add outputs)
    pub const NONE: SigHashType = SigHashType(0x02);
    /// Sign all inputs, but only the output at the same index as this input
    pub const SINGLE: SigHashType = SigHashType(0x03);

    /// When combined with other types, only sign this input (not all inputs)
    pub const ANYONECANPAY: u32 = 0x80;

    /// Create a sighash type from a byte value.
    pub fn from_u8(value: u8) -> Self {
        SigHashType(value as u32)
    }

    /// Get the base type (ALL, NONE, or SINGLE) without the ANYONECANPAY flag.
    pub fn base_type(self) -> u32 {
        self.0 & 0x1f
    }

    /// Check if ANYONECANPAY is set.
    pub fn anyone_can_pay(self) -> bool {
        (self.0 & Self::ANYONECANPAY) != 0
    }

    /// Check if this is SIGHASH_ALL (without ANYONECANPAY).
    pub fn is_all(self) -> bool {
        self.base_type() == 0x01
    }

    /// Check if this is SIGHASH_NONE.
    pub fn is_none(self) -> bool {
        self.base_type() == 0x02
    }

    /// Check if this is SIGHASH_SINGLE.
    pub fn is_single(self) -> bool {
        self.base_type() == 0x03
    }
}

// ============================================================
// FindAndDelete and OP_CODESEPARATOR handling for legacy sighash
// ============================================================

/// Create a push-encoded version of the given data.
///
/// This encodes data the way it would appear in a Bitcoin script:
/// - Length 0-75: single length byte followed by data
/// - Length 76-255: OP_PUSHDATA1 (0x4c) + 1-byte length + data
/// - Length 256-65535: OP_PUSHDATA2 (0x4d) + 2-byte LE length + data
/// - Length 65536+: OP_PUSHDATA4 (0x4e) + 4-byte LE length + data
fn push_encode(data: &[u8]) -> Vec<u8> {
    let len = data.len();
    let mut result = Vec::with_capacity(len + 5);

    if len <= 75 {
        result.push(len as u8);
    } else if len <= 255 {
        result.push(0x4c); // OP_PUSHDATA1
        result.push(len as u8);
    } else if len <= 65535 {
        result.push(0x4d); // OP_PUSHDATA2
        result.extend_from_slice(&(len as u16).to_le_bytes());
    } else {
        result.push(0x4e); // OP_PUSHDATA4
        result.extend_from_slice(&(len as u32).to_le_bytes());
    }
    result.extend_from_slice(data);
    result
}

/// Remove all occurrences of the push-encoded signature from the script.
///
/// This is the "FindAndDelete" operation required for legacy sighash computation.
/// It removes all instances where the signature appears as a pushed value in the
/// script. This is necessary because when we're verifying a signature, we need
/// to compute the sighash over a version of the script that doesn't contain
/// the signature itself (since it didn't exist when the signer created it).
///
/// The signature should include the sighash type byte at the end.
///
/// # Arguments
/// * `script` - The scriptCode (script bytes)
/// * `sig` - The signature bytes (including sighash type byte)
///
/// # Returns
/// A new script with all push-encoded occurrences of the signature removed.
pub fn find_and_delete(script: &[u8], sig: &[u8]) -> Vec<u8> {
    if sig.is_empty() {
        return script.to_vec();
    }

    let pattern = push_encode(sig);
    if pattern.is_empty() || pattern.len() > script.len() {
        return script.to_vec();
    }

    // Find and remove all occurrences of the pattern
    let mut result = Vec::with_capacity(script.len());
    let mut i = 0;

    while i < script.len() {
        // Check if pattern matches at current position
        if i + pattern.len() <= script.len() && script[i..i + pattern.len()] == pattern[..] {
            // Skip the pattern
            i += pattern.len();
        } else {
            result.push(script[i]);
            i += 1;
        }
    }

    result
}

/// Remove all OP_CODESEPARATOR opcodes from the script.
///
/// In legacy sighash, OP_CODESEPARATOR is removed from the scriptCode before
/// hashing. Note that this is different from handling the "subscript" which
/// starts after the last executed OP_CODESEPARATOR - both must be done.
///
/// # Arguments
/// * `script` - The script bytes
///
/// # Returns
/// A new script with all OP_CODESEPARATOR opcodes removed.
pub fn remove_codeseparators(script: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(script.len());
    let mut i = 0;

    while i < script.len() {
        let opcode = script[i];

        if opcode == OP_CODESEPARATOR {
            // Skip OP_CODESEPARATOR
            i += 1;
            continue;
        }

        // Copy opcode
        result.push(opcode);
        i += 1;

        // Handle push data opcodes - copy their data too
        if opcode >= 0x01 && opcode <= 0x4b {
            // Direct push: opcode is length
            let len = opcode as usize;
            let end = (i + len).min(script.len());
            result.extend_from_slice(&script[i..end]);
            i = end;
        } else if opcode == 0x4c && i < script.len() {
            // OP_PUSHDATA1
            let len = script[i] as usize;
            result.push(script[i]);
            i += 1;
            let end = (i + len).min(script.len());
            result.extend_from_slice(&script[i..end]);
            i = end;
        } else if opcode == 0x4d && i + 1 < script.len() {
            // OP_PUSHDATA2
            let len = u16::from_le_bytes([script[i], script[i + 1]]) as usize;
            result.extend_from_slice(&script[i..i + 2]);
            i += 2;
            let end = (i + len).min(script.len());
            result.extend_from_slice(&script[i..end]);
            i = end;
        } else if opcode == 0x4e && i + 3 < script.len() {
            // OP_PUSHDATA4
            let len = u32::from_le_bytes([script[i], script[i + 1], script[i + 2], script[i + 3]]) as usize;
            result.extend_from_slice(&script[i..i + 4]);
            i += 4;
            let end = (i + len).min(script.len());
            result.extend_from_slice(&script[i..end]);
            i = end;
        }
    }

    result
}

/// Compute the legacy (pre-SegWit) signature hash for a transaction input.
///
/// This implements the original Bitcoin signature hash algorithm, which has
/// several quirks:
///
/// 1. All input scriptSigs are cleared except for the one being signed
/// 2. The subscript (typically the previous output's scriptPubKey) replaces
///    the current input's scriptSig
/// 3. OP_CODESEPARATOR is removed from the subscript (handled by caller)
/// 4. SIGHASH_NONE clears all outputs and sets all other input sequences to 0
/// 5. SIGHASH_SINGLE keeps only the output at the same index, clears others,
///    and sets other input sequences to 0
/// 6. ANYONECANPAY removes all inputs except the one being signed
/// 7. The 4-byte little-endian hash type is appended before double-SHA256
///
/// # Arguments
/// * `tx` - The transaction being signed
/// * `input_index` - Index of the input being signed
/// * `subscript` - The scriptCode (usually scriptPubKey of output being spent,
///   with OP_CODESEPARATOR removed)
/// * `hash_type` - The sighash type (SIGHASH_ALL, SIGHASH_NONE, etc.)
///
/// # Returns
/// The 256-bit signature hash (message to be signed)
pub fn legacy_sighash(
    tx: &Transaction,
    input_index: usize,
    subscript: &[u8],
    hash_type: u32,
) -> Hash256 {
    let sighash_type = SigHashType(hash_type);

    // SIGHASH_SINGLE bug: if input_index >= outputs.len(), return hash of 0x01
    // This is a famous Bitcoin bug that must be preserved for consensus
    if sighash_type.is_single() && input_index >= tx.outputs.len() {
        let mut result = [0u8; 32];
        result[0] = 1;
        return Hash256(result);
    }

    let mut buf = Vec::with_capacity(tx.base_size() + 4);

    // Version
    buf.write_all(&tx.version.to_le_bytes()).unwrap();

    // Inputs
    if sighash_type.anyone_can_pay() {
        // Only include the input being signed
        write_compact_size(&mut buf, 1).unwrap();
        write_legacy_input(&mut buf, tx, input_index, subscript, hash_type);
    } else {
        write_compact_size(&mut buf, tx.inputs.len() as u64).unwrap();
        for i in 0..tx.inputs.len() {
            if i == input_index {
                write_legacy_input(&mut buf, tx, i, subscript, hash_type);
            } else {
                write_legacy_input(&mut buf, tx, i, &[], hash_type);
            }
        }
    }

    // Outputs
    if sighash_type.is_none() {
        // No outputs
        write_compact_size(&mut buf, 0).unwrap();
    } else if sighash_type.is_single() {
        // Only the output at input_index
        write_compact_size(&mut buf, (input_index + 1) as u64).unwrap();
        for i in 0..=input_index {
            if i == input_index {
                tx.outputs[i].encode(&mut buf).unwrap();
            } else {
                // Empty outputs: value = -1 (0xFFFFFFFFFFFFFFFF), empty script
                buf.write_all(&(-1i64).to_le_bytes()).unwrap();
                write_compact_size(&mut buf, 0).unwrap();
            }
        }
    } else {
        // All outputs (SIGHASH_ALL)
        write_compact_size(&mut buf, tx.outputs.len() as u64).unwrap();
        for output in &tx.outputs {
            output.encode(&mut buf).unwrap();
        }
    }

    // Locktime
    buf.write_all(&tx.lock_time.to_le_bytes()).unwrap();

    // Hash type (4 bytes LE)
    buf.write_all(&hash_type.to_le_bytes()).unwrap();

    sha256d(&buf)
}

/// Write a legacy input for sighash computation.
fn write_legacy_input(
    buf: &mut Vec<u8>,
    tx: &Transaction,
    index: usize,
    script: &[u8],
    hash_type: u32,
) {
    let input = &tx.inputs[index];
    let sighash_type = SigHashType(hash_type);

    // Previous output
    input.previous_output.encode(buf).unwrap();

    // ScriptSig (either the subscript or empty)
    write_compact_size(buf, script.len() as u64).unwrap();
    buf.write_all(script).unwrap();

    // Sequence - for non-signed inputs with NONE/SINGLE, use 0
    let sequence = if script.is_empty() && (sighash_type.is_none() || sighash_type.is_single()) {
        0u32
    } else {
        input.sequence
    };
    buf.write_all(&sequence.to_le_bytes()).unwrap();
}

/// Compute the BIP-143 (SegWit v0) signature hash.
///
/// BIP-143 introduced a new sighash algorithm for SegWit transactions that:
/// 1. Fixes the O(n²) hashing vulnerability in legacy sighash
/// 2. Pre-computes hashes of prevouts, sequences, and outputs
/// 3. Commits to the value of the output being spent
///
/// The algorithm hashes (in order):
/// 1. nVersion (4 bytes LE)
/// 2. hashPrevouts: SHA256d of all outpoints (or zero if ANYONECANPAY)
/// 3. hashSequence: SHA256d of all sequences (or zero if ANYONECANPAY/NONE/SINGLE)
/// 4. outpoint being spent (32+4 bytes)
/// 5. scriptCode of the input (serialized as compact_size + script)
/// 6. value of the output being spent (8 bytes LE)
/// 7. nSequence of the input (4 bytes LE)
/// 8. hashOutputs: SHA256d of all outputs (or zero if NONE, or SHA256d of
///    the corresponding output if SINGLE and index exists, or zero if SINGLE
///    and index out of range)
/// 9. nLocktime (4 bytes LE)
/// 10. nHashType (4 bytes LE)
///
/// # Arguments
/// * `tx` - The transaction being signed
/// * `input_index` - Index of the input being signed
/// * `script_code` - The scriptCode for this input type (P2WPKH or P2WSH)
/// * `value` - Value of the output being spent (in satoshis)
/// * `hash_type` - The sighash type
///
/// # Returns
/// The 256-bit signature hash
pub fn segwit_v0_sighash(
    tx: &Transaction,
    input_index: usize,
    script_code: &[u8],
    value: u64,
    hash_type: u32,
) -> Hash256 {
    let sighash_type = SigHashType(hash_type);
    let input = &tx.inputs[input_index];

    // Compute hashPrevouts
    let hash_prevouts = if sighash_type.anyone_can_pay() {
        Hash256::ZERO
    } else {
        let mut buf = Vec::with_capacity(tx.inputs.len() * OutPoint::SIZE);
        for inp in &tx.inputs {
            inp.previous_output.encode(&mut buf).unwrap();
        }
        sha256d(&buf)
    };

    // Compute hashSequence
    let hash_sequence = if sighash_type.anyone_can_pay()
        || sighash_type.is_single()
        || sighash_type.is_none()
    {
        Hash256::ZERO
    } else {
        let mut buf = Vec::with_capacity(tx.inputs.len() * 4);
        for inp in &tx.inputs {
            buf.write_all(&inp.sequence.to_le_bytes()).unwrap();
        }
        sha256d(&buf)
    };

    // Compute hashOutputs
    let hash_outputs = if sighash_type.is_none() {
        Hash256::ZERO
    } else if sighash_type.is_single() {
        if input_index < tx.outputs.len() {
            let mut buf = Vec::with_capacity(tx.outputs[input_index].serialized_size());
            tx.outputs[input_index].encode(&mut buf).unwrap();
            sha256d(&buf)
        } else {
            Hash256::ZERO
        }
    } else {
        // SIGHASH_ALL
        let mut buf = Vec::new();
        for output in &tx.outputs {
            output.encode(&mut buf).unwrap();
        }
        sha256d(&buf)
    };

    // Build the preimage
    let mut preimage = Vec::with_capacity(156 + script_code.len());

    // 1. nVersion (4 bytes)
    preimage.write_all(&tx.version.to_le_bytes()).unwrap();

    // 2. hashPrevouts (32 bytes)
    preimage.write_all(&hash_prevouts.0).unwrap();

    // 3. hashSequence (32 bytes)
    preimage.write_all(&hash_sequence.0).unwrap();

    // 4. outpoint (36 bytes)
    input.previous_output.encode(&mut preimage).unwrap();

    // 5. scriptCode (varint + script)
    write_compact_size(&mut preimage, script_code.len() as u64).unwrap();
    preimage.write_all(script_code).unwrap();

    // 6. value (8 bytes)
    preimage.write_all(&value.to_le_bytes()).unwrap();

    // 7. nSequence (4 bytes)
    preimage.write_all(&input.sequence.to_le_bytes()).unwrap();

    // 8. hashOutputs (32 bytes)
    preimage.write_all(&hash_outputs.0).unwrap();

    // 9. nLocktime (4 bytes)
    preimage.write_all(&tx.lock_time.to_le_bytes()).unwrap();

    // 10. nHashType (4 bytes)
    preimage.write_all(&hash_type.to_le_bytes()).unwrap();

    sha256d(&preimage)
}

/// Create the scriptCode for P2WPKH from a 20-byte pubkey hash.
///
/// For P2WPKH, the scriptCode is: OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
pub fn p2wpkh_script_code(pubkey_hash: &[u8; 20]) -> [u8; 25] {
    let mut script = [0u8; 25];
    script[0] = 0x76; // OP_DUP
    script[1] = 0xa9; // OP_HASH160
    script[2] = 0x14; // Push 20 bytes
    script[3..23].copy_from_slice(pubkey_hash);
    script[23] = 0x88; // OP_EQUALVERIFY
    script[24] = 0xac; // OP_CHECKSIG
    script
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustoshi_primitives::{OutPoint, TxIn, TxOut};

    #[test]
    fn sighash_type_flags() {
        let all = SigHashType::ALL;
        assert!(all.is_all());
        assert!(!all.is_none());
        assert!(!all.is_single());
        assert!(!all.anyone_can_pay());

        let none = SigHashType::NONE;
        assert!(!none.is_all());
        assert!(none.is_none());

        let single = SigHashType::SINGLE;
        assert!(single.is_single());

        let all_acp = SigHashType(0x81);
        assert!(all_acp.is_all());
        assert!(all_acp.anyone_can_pay());
    }

    #[test]
    fn legacy_sighash_simple() {
        // A simple transaction for testing
        let tx = Transaction {
            version: 1,
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
                value: 100_000_000,
                script_pubkey: vec![0x76, 0xa9, 0x14], // Partial P2PKH
            }],
            lock_time: 0,
        };

        // Compute sighash with a simple subscript
        let subscript = vec![0x76, 0xa9, 0x14, 0x00, 0x00];
        let hash = legacy_sighash(&tx, 0, &subscript, 0x01);

        // Verify it's deterministic
        let hash2 = legacy_sighash(&tx, 0, &subscript, 0x01);
        assert_eq!(hash, hash2);

        // Verify different subscript gives different hash
        let hash3 = legacy_sighash(&tx, 0, &[0x00], 0x01);
        assert_ne!(hash, hash3);
    }

    #[test]
    fn legacy_sighash_single_bug() {
        // Test the SIGHASH_SINGLE bug: when input_index >= outputs.len(),
        // return a hash of 0x01 followed by 31 zero bytes
        let tx = Transaction {
            version: 1,
            inputs: vec![
                TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: vec![],
                    sequence: 0xFFFFFFFF,
                    witness: vec![],
                },
                TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: vec![],
                    sequence: 0xFFFFFFFF,
                    witness: vec![],
                },
            ],
            outputs: vec![TxOut {
                value: 100,
                script_pubkey: vec![],
            }],
            lock_time: 0,
        };

        // Input 1, but only 1 output (index 0)
        let hash = legacy_sighash(&tx, 1, &[], 0x03); // SIGHASH_SINGLE

        // Should return 0x01 followed by 31 zero bytes
        let mut expected = [0u8; 32];
        expected[0] = 1;
        assert_eq!(hash.0, expected);
    }

    #[test]
    fn segwit_v0_sighash_simple() {
        // Simple SegWit transaction
        let tx = Transaction {
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
                value: 99_000_000,
                script_pubkey: vec![0x00, 0x14], // P2WPKH prefix
            }],
            lock_time: 0,
        };

        let script_code = vec![0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x88, 0xac];
        let value = 100_000_000u64;

        let hash = segwit_v0_sighash(&tx, 0, &script_code, value, 0x01);

        // Verify deterministic
        let hash2 = segwit_v0_sighash(&tx, 0, &script_code, value, 0x01);
        assert_eq!(hash, hash2);

        // Different value should give different hash
        let hash3 = segwit_v0_sighash(&tx, 0, &script_code, 99_999_999, 0x01);
        assert_ne!(hash, hash3);
    }

    #[test]
    fn segwit_v0_sighash_anyonecanpay() {
        let tx = Transaction {
            version: 2,
            inputs: vec![
                TxIn {
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
                },
                TxIn {
                    previous_output: OutPoint {
                        txid: Hash256::from_hex(
                            "0000000000000000000000000000000000000000000000000000000000000002",
                        )
                        .unwrap(),
                        vout: 1,
                    },
                    script_sig: vec![],
                    sequence: 0xFFFFFFFF,
                    witness: vec![],
                },
            ],
            outputs: vec![TxOut {
                value: 99_000_000,
                script_pubkey: vec![0x00, 0x14],
            }],
            lock_time: 0,
        };

        let script_code = vec![0x76, 0xa9, 0x14];

        // SIGHASH_ALL | ANYONECANPAY
        let hash_acp = segwit_v0_sighash(&tx, 0, &script_code, 50_000_000, 0x81);

        // Regular SIGHASH_ALL
        let hash_all = segwit_v0_sighash(&tx, 0, &script_code, 50_000_000, 0x01);

        // They should differ because ANYONECANPAY zeros out hashPrevouts and hashSequence
        assert_ne!(hash_acp, hash_all);
    }

    #[test]
    fn p2wpkh_script_code_format() {
        let pubkey_hash = [0xab; 20];
        let script = p2wpkh_script_code(&pubkey_hash);

        assert_eq!(script.len(), 25);
        assert_eq!(script[0], 0x76); // OP_DUP
        assert_eq!(script[1], 0xa9); // OP_HASH160
        assert_eq!(script[2], 0x14); // Push 20 bytes
        assert_eq!(&script[3..23], &pubkey_hash);
        assert_eq!(script[23], 0x88); // OP_EQUALVERIFY
        assert_eq!(script[24], 0xac); // OP_CHECKSIG
    }

    // BIP-143 test vector (Native P2WPKH)
    // From https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
    #[test]
    fn bip143_native_p2wpkh() {
        use crate::hashes::sha256d;

        // Test case from BIP-143: Native P2WPKH
        // The unsigned transaction hex from BIP-143:
        // 0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000

        // The txids in the raw transaction are in SERIALIZATION order (internal order), not display order!
        // 9f96ade4b41d5433f4eda31e1738ec2b36f6e7d1420d94a6af99801a88f7f7ff (display) -> fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f (serialization)

        // Let's construct the transaction using the raw serialization bytes
        let tx = Transaction {
            version: 1,
            inputs: vec![
                TxIn {
                    previous_output: OutPoint {
                        // In serialization: fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f
                        // This is what appears in the raw transaction
                        txid: Hash256(
                            hex::decode(
                                "fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f",
                            )
                            .unwrap()
                            .try_into()
                            .unwrap(),
                        ),
                        vout: 0,
                    },
                    script_sig: vec![],
                    sequence: 0xffffffee,
                    witness: vec![],
                },
                TxIn {
                    previous_output: OutPoint {
                        // In serialization: ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a
                        txid: Hash256(
                            hex::decode(
                                "ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a",
                            )
                            .unwrap()
                            .try_into()
                            .unwrap(),
                        ),
                        vout: 1,
                    },
                    script_sig: vec![],
                    sequence: 0xffffffff,
                    witness: vec![],
                },
            ],
            outputs: vec![
                TxOut {
                    value: 112340000,
                    script_pubkey: hex::decode("76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac")
                        .unwrap(),
                },
                TxOut {
                    value: 223450000,
                    script_pubkey: hex::decode("76a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac")
                        .unwrap(),
                },
            ],
            lock_time: 0x00000011,
        };

        // Verify hashPrevouts matches BIP-143 expected value
        // Expected: 96b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd37
        let mut prevouts_buf = Vec::new();
        for inp in &tx.inputs {
            inp.previous_output.encode(&mut prevouts_buf).unwrap();
        }
        let hash_prevouts = sha256d(&prevouts_buf);
        let expected_prevouts: [u8; 32] =
            hex::decode("96b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd37")
                .unwrap()
                .try_into()
                .unwrap();
        assert_eq!(
            hash_prevouts.0, expected_prevouts,
            "hashPrevouts mismatch"
        );

        // Verify hashSequence matches BIP-143 expected value
        // Expected: 52b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3b
        let mut seq_buf = Vec::new();
        for inp in &tx.inputs {
            seq_buf.extend_from_slice(&inp.sequence.to_le_bytes());
        }
        let hash_sequence = sha256d(&seq_buf);
        let expected_sequence: [u8; 32] =
            hex::decode("52b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3b")
                .unwrap()
                .try_into()
                .unwrap();
        assert_eq!(
            hash_sequence.0, expected_sequence,
            "hashSequence mismatch"
        );

        // Verify hashOutputs matches BIP-143 expected value
        // Expected: 863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e5
        let mut outputs_buf = Vec::new();
        for output in &tx.outputs {
            output.encode(&mut outputs_buf).unwrap();
        }
        let hash_outputs = sha256d(&outputs_buf);
        let expected_outputs: [u8; 32] =
            hex::decode("863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e5")
                .unwrap()
                .try_into()
                .unwrap();
        assert_eq!(hash_outputs.0, expected_outputs, "hashOutputs mismatch");

        // For input 1 (the P2WPKH input), the public key hash is:
        // 1d0f172a0ecb48aee1be1f2687d2963ae33f71a1
        // The scriptCode is: 1976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac
        let pubkey_hash: [u8; 20] = hex::decode("1d0f172a0ecb48aee1be1f2687d2963ae33f71a1")
            .unwrap()
            .try_into()
            .unwrap();
        let script_code = p2wpkh_script_code(&pubkey_hash);

        // Value of the output being spent: 600,000,000 satoshis
        let value = 600_000_000u64;

        let hash = segwit_v0_sighash(&tx, 1, &script_code, value, 0x01);

        // Expected sighash from BIP-143 (raw byte order):
        // c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670
        let expected_bytes: [u8; 32] =
            hex::decode("c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670")
                .unwrap()
                .try_into()
                .unwrap();
        let expected = Hash256(expected_bytes);

        assert_eq!(hash, expected, "BIP-143 P2WPKH sighash mismatch");
    }

    // BIP-143 test vector #2 (P2SH-P2WPKH)
    #[test]
    fn bip143_p2sh_p2wpkh() {
        // Second test case from BIP-143
        // Raw unsigned transaction:
        // 0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000

        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    // Raw bytes from the transaction (serialization order)
                    txid: Hash256(
                        hex::decode(
                            "db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477",
                        )
                        .unwrap()
                        .try_into()
                        .unwrap(),
                    ),
                    vout: 1,
                },
                script_sig: hex::decode("16001479091972186c449eb1ded22b78e40d009bdf0089").unwrap(),
                sequence: 0xfffffffe,
                witness: vec![],
            }],
            outputs: vec![
                TxOut {
                    value: 199996600,
                    script_pubkey: hex::decode("76a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac")
                        .unwrap(),
                },
                TxOut {
                    value: 800000000,
                    script_pubkey: hex::decode("76a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac")
                        .unwrap(),
                },
            ],
            lock_time: 0x00000492,
        };

        // Public key hash for P2SH-P2WPKH: 79091972186c449eb1ded22b78e40d009bdf0089
        let pubkey_hash: [u8; 20] = hex::decode("79091972186c449eb1ded22b78e40d009bdf0089")
            .unwrap()
            .try_into()
            .unwrap();
        let script_code = p2wpkh_script_code(&pubkey_hash);

        // Value: 1,000,000,000 satoshis
        let value = 1_000_000_000u64;

        let hash = segwit_v0_sighash(&tx, 0, &script_code, value, 0x01);

        // Expected sighash (raw byte order):
        // 64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6
        let expected_bytes: [u8; 32] =
            hex::decode("64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6")
                .unwrap()
                .try_into()
                .unwrap();
        let expected = Hash256(expected_bytes);

        assert_eq!(hash, expected, "BIP-143 P2SH-P2WPKH sighash mismatch");
    }
}
