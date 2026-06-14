//! Bitcoin transaction types.
//!
//! This module provides types for Bitcoin transactions including OutPoint, TxIn,
//! TxOut, and Transaction with full SegWit-aware serialization support.

use crate::hash::Hash256;
use crate::serialize::{
    compact_size_len, read_compact_size, write_compact_size, Decodable, Encodable,
};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};

/// Maximum CompactSize input/output count accepted at deserialize. Bitcoin Core imposes NO
/// per-tx count cap beyond ReadCompactSize's MAX_SIZE (serialize.h, 0x02000000); the real
/// ceiling is the downstream block-weight check. A tighter cap FALSE-REJECTS a valid tx: a
/// 4M-weight block fits well over 25k small (9-byte) outputs, so the old 25k output cap
/// split the chain (bug-hunt 4D — the input cap was safe since min-input weight caps inputs
/// near 24k, but outputs are far smaller). Match Core's MAX_SIZE bound.
const MAX_TX_IN_COUNT: usize = 0x0200_0000;
const MAX_TX_OUT_COUNT: usize = 0x0200_0000;
/// Cap eager `Vec` pre-allocation so a malicious oversized count cannot OOM the node before
/// the bytes are actually read (mirrors Core's bounded reserve, serialize.h
/// MAX_VECTOR_ALLOCATE). The vec still grows if the genuine count is larger.
const MAX_ALLOC_RESERVE: usize = 16_384;
/// Maximum script size (consensus limit is 10,000 bytes for scriptSig; scriptPubKey can be
/// larger in witness but we cap at the block weight limit for safety).
const MAX_SCRIPT_SIZE: u64 = 10_000;
/// Maximum number of witness items per input.
///
/// Bitcoin Core imposes no explicit `CompactSize` cap on witness item counts;
/// the only bounds are:
///
///   - wire-level `MAX_SIZE = 0x02000000` (32 MiB) on the length prefix
///   - the 4 MiB block-weight envelope
///   - `MAX_STACK_SIZE = 1000` at script-execution time (runtime, not
///     deserialize)
///
/// The earlier cap of 500 was a DoS guard that turned out far tighter than
/// consensus: mainnet block 761249 carries an input with 500,003 witness
/// items (a legitimate Ordinals-style inscription envelope) which wedged
/// blockbrew at that height until every peer that relayed the block got
/// banned. Rustoshi exhibited the same class of wedge at h=938,374 on
/// 2026-05-05. 4,000,000 is a hard upper bound derived from
/// `MAX_BLOCK_SERIALIZED_SIZE / min-item-size` (each item costs ≥ 1 byte of
/// witness data plus a length prefix), so this still shuts down the "peer
/// sends a 100 GB witness count" DoS without rejecting valid mainnet blocks.
///
/// Mirrors blockbrew's `923727f` precedent (Apr 23 2026, 100_000 → 4_000_000).
const MAX_WITNESS_ITEMS: usize = 4_000_000;
/// Maximum size of a single witness item (capped at max block weight = 4MB).
const MAX_WITNESS_ITEM_SIZE: u64 = 4_000_000;

/// An outpoint references a specific output of a previous transaction.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct OutPoint {
    /// The transaction ID of the previous transaction.
    pub txid: Hash256,
    /// The index of the output in the previous transaction.
    pub vout: u32,
}

impl OutPoint {
    /// The serialized size of an OutPoint (36 bytes).
    pub const SIZE: usize = 36;

    /// Create a null outpoint (used in coinbase transactions).
    pub fn null() -> Self {
        Self {
            txid: Hash256::ZERO,
            vout: 0xFFFFFFFF,
        }
    }

    /// Check if this is a null outpoint.
    pub fn is_null(&self) -> bool {
        self.txid == Hash256::ZERO && self.vout == 0xFFFFFFFF
    }
}

impl Encodable for OutPoint {
    fn encode<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
        writer.write_all(&self.txid.0)?;
        writer.write_all(&self.vout.to_le_bytes())?;
        Ok(Self::SIZE)
    }

    fn serialized_size(&self) -> usize {
        Self::SIZE
    }
}

impl Decodable for OutPoint {
    fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut txid_bytes = [0u8; 32];
        reader.read_exact(&mut txid_bytes)?;
        let mut vout_bytes = [0u8; 4];
        reader.read_exact(&mut vout_bytes)?;
        Ok(Self {
            txid: Hash256(txid_bytes),
            vout: u32::from_le_bytes(vout_bytes),
        })
    }
}

/// A transaction input.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct TxIn {
    /// The previous output being spent.
    pub previous_output: OutPoint,
    /// The unlocking script (scriptSig).
    pub script_sig: Vec<u8>,
    /// The sequence number.
    pub sequence: u32,
    /// Witness data (SegWit).
    pub witness: Vec<Vec<u8>>,
}

impl TxIn {
    /// Encode without witness data.
    fn encode_no_witness<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
        let mut len = self.previous_output.encode(writer)?;
        len += write_compact_size(writer, self.script_sig.len() as u64)?;
        writer.write_all(&self.script_sig)?;
        len += self.script_sig.len();
        writer.write_all(&self.sequence.to_le_bytes())?;
        len += 4;
        Ok(len)
    }

    /// Size without witness data.
    fn serialized_size_no_witness(&self) -> usize {
        OutPoint::SIZE
            + compact_size_len(self.script_sig.len() as u64)
            + self.script_sig.len()
            + 4
    }

    /// Size of witness data.
    fn witness_size(&self) -> usize {
        let mut size = compact_size_len(self.witness.len() as u64);
        for item in &self.witness {
            size += compact_size_len(item.len() as u64) + item.len();
        }
        size
    }

    /// Encode witness data.
    fn encode_witness<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
        let mut len = write_compact_size(writer, self.witness.len() as u64)?;
        for item in &self.witness {
            len += write_compact_size(writer, item.len() as u64)?;
            writer.write_all(item)?;
            len += item.len();
        }
        Ok(len)
    }

    /// Compute the weight contribution of a single input.
    ///
    /// Mirrors Bitcoin Core consensus/validation.h `GetTransactionInputWeight`:
    /// ```text
    /// GetSerializeSize(TX_NO_WITNESS(txin)) * (WITNESS_SCALE_FACTOR - 1)
    ///     + GetSerializeSize(TX_WITH_WITNESS(txin))
    ///     + GetSerializeSize(txin.scriptWitness.stack)
    /// ```
    ///
    /// Because a `TxIn` itself does not carry the witness in its own
    /// serialization (witness is appended per-input after all outputs in the
    /// segwit wire format), the formula simplifies to:
    ///   `stripped * 3 + stripped + witness_stack_size`
    /// = `stripped * 4 + witness_stack_size`
    ///
    /// This is used for per-input virtual-size accounting (e.g. fee estimation
    /// for partially-signed transactions where only some inputs are known).
    pub fn input_weight(&self) -> usize {
        let stripped = self.serialized_size_no_witness();
        let witness = self.witness_size();
        // stripped * (WITNESS_SCALE_FACTOR - 1) + stripped + witness
        // = stripped * 4 + witness
        stripped * 4 + witness
    }
}

/// A transaction output.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct TxOut {
    /// The value in satoshis.
    pub value: u64,
    /// The locking script (scriptPubKey).
    pub script_pubkey: Vec<u8>,
}

impl Encodable for TxOut {
    fn encode<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
        writer.write_all(&self.value.to_le_bytes())?;
        let mut len = 8;
        len += write_compact_size(writer, self.script_pubkey.len() as u64)?;
        writer.write_all(&self.script_pubkey)?;
        len += self.script_pubkey.len();
        Ok(len)
    }

    fn serialized_size(&self) -> usize {
        8 + compact_size_len(self.script_pubkey.len() as u64) + self.script_pubkey.len()
    }
}

impl Decodable for TxOut {
    fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut value_bytes = [0u8; 8];
        reader.read_exact(&mut value_bytes)?;
        let value = u64::from_le_bytes(value_bytes);

        let script_len = read_compact_size(reader)?;
        if script_len > MAX_WITNESS_ITEM_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("scriptPubKey too large: {}", script_len),
            ));
        }
        let mut script_pubkey = vec![0u8; script_len as usize];
        reader.read_exact(&mut script_pubkey)?;

        Ok(Self {
            value,
            script_pubkey,
        })
    }
}

/// A Bitcoin transaction.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Transaction {
    /// Transaction version.
    pub version: i32,
    /// Transaction inputs.
    pub inputs: Vec<TxIn>,
    /// Transaction outputs.
    pub outputs: Vec<TxOut>,
    /// Lock time (block height or Unix timestamp).
    pub lock_time: u32,
}

impl Transaction {
    /// Check if this transaction has witness data.
    pub fn has_witness(&self) -> bool {
        self.inputs.iter().any(|i| !i.witness.is_empty())
    }

    /// Check if this is a coinbase transaction.
    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1 && self.inputs[0].previous_output.is_null()
    }

    /// Encode without witness data (for txid calculation).
    pub fn encode_no_witness<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
        let mut len = 0;
        writer.write_all(&self.version.to_le_bytes())?;
        len += 4;

        len += write_compact_size(writer, self.inputs.len() as u64)?;
        for input in &self.inputs {
            len += input.encode_no_witness(writer)?;
        }

        len += write_compact_size(writer, self.outputs.len() as u64)?;
        for output in &self.outputs {
            len += output.encode(writer)?;
        }

        writer.write_all(&self.lock_time.to_le_bytes())?;
        len += 4;

        Ok(len)
    }

    /// Serialize without witness data (for txid calculation).
    pub fn serialize_no_witness(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.base_size());
        self.encode_no_witness(&mut buf)
            .expect("writing to Vec never fails");
        buf
    }

    /// Decode using *legacy* (no-witness) serialization.
    ///
    /// Mirrors Bitcoin Core's `TX_NO_WITNESS` deserialization
    /// (`bitcoin-core/src/core_io.cpp::DecodeTx`). Unlike the witness-aware
    /// [`Decodable::decode`], this never interprets a leading `0x00` byte as a
    /// SegWit marker — the byte immediately following the version is always the
    /// `CompactSize` input count. This is required for the `converttopsbt`
    /// dual-decode strategy: an empty-vin transaction whose first input-count
    /// byte is `0x00` would otherwise be mis-read as a 0-input/0-output segwit
    /// transaction (silently dropping its outputs).
    pub fn decode_no_witness<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut version_bytes = [0u8; 4];
        reader.read_exact(&mut version_bytes)?;
        let version = i32::from_le_bytes(version_bytes);

        let input_count = read_compact_size(reader)?;
        if input_count > MAX_TX_IN_COUNT as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("too many inputs: {}", input_count),
            ));
        }
        let mut inputs = Vec::with_capacity((input_count as usize).min(MAX_ALLOC_RESERVE));
        for _ in 0..input_count {
            let previous_output = OutPoint::decode(reader)?;
            let script_len = read_compact_size(reader)?;
            if script_len > MAX_SCRIPT_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("scriptSig too large: {}", script_len),
                ));
            }
            let mut script_sig = vec![0u8; script_len as usize];
            reader.read_exact(&mut script_sig)?;

            let mut seq_bytes = [0u8; 4];
            reader.read_exact(&mut seq_bytes)?;
            let sequence = u32::from_le_bytes(seq_bytes);

            inputs.push(TxIn {
                previous_output,
                script_sig,
                sequence,
                witness: Vec::new(),
            });
        }

        let output_count = read_compact_size(reader)?;
        if output_count > MAX_TX_OUT_COUNT as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("too many outputs: {}", output_count),
            ));
        }
        let mut outputs = Vec::with_capacity((output_count as usize).min(MAX_ALLOC_RESERVE));
        for _ in 0..output_count {
            outputs.push(TxOut::decode(reader)?);
        }

        let mut locktime_bytes = [0u8; 4];
        reader.read_exact(&mut locktime_bytes)?;
        let lock_time = u32::from_le_bytes(locktime_bytes);

        Ok(Self {
            version,
            inputs,
            outputs,
            lock_time,
        })
    }

    /// Compute the txid (hash of the non-witness serialization, double-SHA256).
    pub fn txid(&self) -> Hash256 {
        let data = self.serialize_no_witness();
        let hash = Sha256::digest(Sha256::digest(&data));
        Hash256(hash.into())
    }

    /// Compute the wtxid (hash of the full witness serialization, double-SHA256).
    /// For non-witness transactions, wtxid equals txid.
    pub fn wtxid(&self) -> Hash256 {
        if !self.has_witness() {
            return self.txid();
        }
        let data = self.serialize();
        let hash = Sha256::digest(Sha256::digest(&data));
        Hash256(hash.into())
    }

    /// Compute the transaction weight.
    /// Weight = base_size * 3 + total_size
    /// where base_size is the size without witness data,
    /// and total_size is the size with witness data.
    pub fn weight(&self) -> usize {
        let base_size = self.base_size();
        let total_size = self.serialized_size();
        base_size * 3 + total_size
    }

    /// Virtual size = weight / 4, rounded up.
    pub fn vsize(&self) -> usize {
        self.weight().div_ceil(4)
    }

    /// Base size (size without witness data).
    pub fn base_size(&self) -> usize {
        let mut size = 4; // version
        size += compact_size_len(self.inputs.len() as u64);
        for input in &self.inputs {
            size += input.serialized_size_no_witness();
        }
        size += compact_size_len(self.outputs.len() as u64);
        for output in &self.outputs {
            size += output.serialized_size();
        }
        size += 4; // lock_time
        size
    }
}

impl Encodable for Transaction {
    fn encode<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
        let has_witness = self.has_witness();

        let mut len = 0;
        writer.write_all(&self.version.to_le_bytes())?;
        len += 4;

        if has_witness {
            // SegWit marker and flag
            writer.write_all(&[0x00, 0x01])?;
            len += 2;
        }

        len += write_compact_size(writer, self.inputs.len() as u64)?;
        for input in &self.inputs {
            len += input.encode_no_witness(writer)?;
        }

        len += write_compact_size(writer, self.outputs.len() as u64)?;
        for output in &self.outputs {
            len += output.encode(writer)?;
        }

        if has_witness {
            for input in &self.inputs {
                len += input.encode_witness(writer)?;
            }
        }

        writer.write_all(&self.lock_time.to_le_bytes())?;
        len += 4;

        Ok(len)
    }

    fn serialized_size(&self) -> usize {
        let has_witness = self.has_witness();
        let mut size = self.base_size();
        if has_witness {
            size += 2; // marker + flag
            for input in &self.inputs {
                size += input.witness_size();
            }
        }
        size
    }
}

impl Decodable for Transaction {
    fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut version_bytes = [0u8; 4];
        reader.read_exact(&mut version_bytes)?;
        let version = i32::from_le_bytes(version_bytes);

        // Read the next byte to check for SegWit marker
        let mut marker = [0u8; 1];
        reader.read_exact(&mut marker)?;

        let (has_witness, input_count) = if marker[0] == 0x00 {
            // This is a SegWit transaction
            let mut flag = [0u8; 1];
            reader.read_exact(&mut flag)?;
            if flag[0] != 0x01 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid SegWit flag",
                ));
            }
            let count = read_compact_size(reader)?;
            (true, count)
        } else {
            // Not SegWit, marker byte is actually the start of input count
            let count = if marker[0] < 253 {
                marker[0] as u64
            } else if marker[0] == 0xFD {
                let mut buf = [0u8; 2];
                reader.read_exact(&mut buf)?;
                let val = u16::from_le_bytes(buf) as u64;
                if val < 253 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "non-canonical compact size",
                    ));
                }
                val
            } else if marker[0] == 0xFE {
                let mut buf = [0u8; 4];
                reader.read_exact(&mut buf)?;
                let val = u32::from_le_bytes(buf) as u64;
                if val < 0x10000 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "non-canonical compact size",
                    ));
                }
                val
            } else {
                let mut buf = [0u8; 8];
                reader.read_exact(&mut buf)?;
                let val = u64::from_le_bytes(buf);
                if val < 0x100000000 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "non-canonical compact size",
                    ));
                }
                val
            };
            (false, count)
        };

        // Read inputs
        if input_count > MAX_TX_IN_COUNT as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("too many inputs: {}", input_count),
            ));
        }
        let mut inputs = Vec::with_capacity((input_count as usize).min(MAX_ALLOC_RESERVE));
        for _ in 0..input_count {
            let previous_output = OutPoint::decode(reader)?;
            let script_len = read_compact_size(reader)?;
            if script_len > MAX_SCRIPT_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("scriptSig too large: {}", script_len),
                ));
            }
            let mut script_sig = vec![0u8; script_len as usize];
            reader.read_exact(&mut script_sig)?;

            let mut seq_bytes = [0u8; 4];
            reader.read_exact(&mut seq_bytes)?;
            let sequence = u32::from_le_bytes(seq_bytes);

            inputs.push(TxIn {
                previous_output,
                script_sig,
                sequence,
                witness: Vec::new(),
            });
        }

        // Read outputs
        let output_count = read_compact_size(reader)?;
        if output_count > MAX_TX_OUT_COUNT as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("too many outputs: {}", output_count),
            ));
        }
        let mut outputs = Vec::with_capacity((output_count as usize).min(MAX_ALLOC_RESERVE));
        for _ in 0..output_count {
            outputs.push(TxOut::decode(reader)?);
        }

        // Read witness data if present
        if has_witness {
            for input in &mut inputs {
                let witness_count = read_compact_size(reader)?;
                if witness_count > MAX_WITNESS_ITEMS as u64 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("too many witness items: {}", witness_count),
                    ));
                }
                input.witness = Vec::with_capacity(witness_count as usize);
                for _ in 0..witness_count {
                    let item_len = read_compact_size(reader)?;
                    if item_len > MAX_WITNESS_ITEM_SIZE {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("witness item too large: {}", item_len),
                        ));
                    }
                    let mut item = vec![0u8; item_len as usize];
                    reader.read_exact(&mut item)?;
                    input.witness.push(item);
                }
            }
            // BIP-144: it is illegal to encode a witness section when no input
            // carries a non-empty witness stack.  Mirrors Bitcoin Core
            // primitives/transaction.h:228-231 ("Superfluous witness record").
            if inputs.iter().all(|i| i.witness.is_empty()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Superfluous witness record",
                ));
            }
        }

        // Read locktime
        let mut locktime_bytes = [0u8; 4];
        reader.read_exact(&mut locktime_bytes)?;
        let lock_time = u32::from_le_bytes(locktime_bytes);

        Ok(Self {
            version,
            inputs,
            outputs,
            lock_time,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outpoint_null() {
        let null = OutPoint::null();
        assert!(null.is_null());

        let not_null = OutPoint {
            txid: Hash256::ZERO,
            vout: 0,
        };
        assert!(!not_null.is_null());
    }

    #[test]
    fn outpoint_roundtrip() {
        let outpoint = OutPoint {
            txid: Hash256::from_hex(
                "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            )
            .unwrap(),
            vout: 42,
        };
        let encoded = outpoint.serialize();
        assert_eq!(encoded.len(), 36);
        let decoded = OutPoint::deserialize(&encoded).unwrap();
        assert_eq!(outpoint, decoded);
    }

    #[test]
    fn txout_roundtrip() {
        let output = TxOut {
            value: 50_000_000_000, // 500 BTC in satoshis
            script_pubkey: vec![0x76, 0xa9, 0x14], // Partial P2PKH
        };
        let encoded = output.serialize();
        let decoded = TxOut::deserialize(&encoded).unwrap();
        assert_eq!(output, decoded);
    }

    #[test]
    fn simple_legacy_transaction_roundtrip() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::from_hex(
                        "0000000000000000000000000000000000000000000000000000000000000000",
                    )
                    .unwrap(),
                    vout: 0xFFFFFFFF,
                },
                script_sig: vec![0x04, 0xFF, 0xFF, 0x00, 0x1D], // Partial genesis coinbase
                sequence: 0xFFFFFFFF,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 50_0000_0000, // 50 BTC
                script_pubkey: vec![0x41], // Partial P2PK
            }],
            lock_time: 0,
        };

        let encoded = tx.serialize();
        let decoded = Transaction::deserialize(&encoded).unwrap();
        assert_eq!(tx, decoded);
        assert!(tx.is_coinbase());
        assert!(!tx.has_witness());
    }

    #[test]
    fn segwit_transaction_roundtrip() {
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::from_hex(
                        "1111111111111111111111111111111111111111111111111111111111111111",
                    )
                    .unwrap(),
                    vout: 0,
                },
                script_sig: vec![],
                sequence: 0xFFFFFFFF,
                witness: vec![
                    vec![0x30, 0x44], // Partial signature
                    vec![0x02, 0x20], // Partial pubkey
                ],
            }],
            outputs: vec![TxOut {
                value: 10_000_000,
                script_pubkey: vec![0x00, 0x14], // Partial P2WPKH
            }],
            lock_time: 0,
        };

        let encoded = tx.serialize();
        // SegWit serialization should include marker and flag
        assert_eq!(encoded[4], 0x00); // marker
        assert_eq!(encoded[5], 0x01); // flag

        let decoded = Transaction::deserialize(&encoded).unwrap();
        assert_eq!(tx, decoded);
        assert!(tx.has_witness());
        assert!(!tx.is_coinbase());
    }

    #[test]
    fn transaction_weight_and_vsize() {
        // Non-witness transaction
        let legacy_tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: vec![0; 100],
                sequence: 0xFFFFFFFF,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 50_0000_0000,
                script_pubkey: vec![0; 25],
            }],
            lock_time: 0,
        };

        let base_size = legacy_tx.base_size();
        let total_size = legacy_tx.serialized_size();
        assert_eq!(base_size, total_size); // No witness data
        assert_eq!(legacy_tx.weight(), base_size * 4); // weight = base * 3 + total = base * 4

        // SegWit transaction
        let segwit_tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::ZERO,
                    vout: 0,
                },
                script_sig: vec![],
                sequence: 0xFFFFFFFF,
                witness: vec![vec![0; 71], vec![0; 33]], // Typical P2WPKH witness
            }],
            outputs: vec![TxOut {
                value: 10_000_000,
                script_pubkey: vec![0; 22],
            }],
            lock_time: 0,
        };

        let base = segwit_tx.base_size();
        let total = segwit_tx.serialized_size();
        assert!(total > base); // Witness data adds to total
        let weight = segwit_tx.weight();
        assert_eq!(weight, base * 3 + total);

        // vsize rounds up
        let vsize = segwit_tx.vsize();
        assert_eq!(vsize, (weight + 3) / 4);
    }

    #[test]
    fn txid_differs_from_wtxid() {
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::from_hex(
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    )
                    .unwrap(),
                    vout: 0,
                },
                script_sig: vec![],
                sequence: 0xFFFFFFFF,
                witness: vec![vec![0x30, 0x44], vec![0x02, 0x20]],
            }],
            outputs: vec![TxOut {
                value: 10_000_000,
                script_pubkey: vec![0x00, 0x14],
            }],
            lock_time: 0,
        };

        let txid = tx.txid();
        let wtxid = tx.wtxid();
        assert_ne!(txid, wtxid, "txid and wtxid should differ for segwit tx");
    }

    #[test]
    fn high_witness_item_count_deserializes() {
        // Regression: rustoshi's MAX_WITNESS_ITEMS used to be 500, which
        // rejected mainnet blocks like 761249 that carry inputs with
        // ~500k witness items (Ordinals inscription envelopes). After the
        // bump to 4_000_000 (mirrors blockbrew 923727f), the deserializer
        // must accept a tx with a witness item count well above 500.
        //
        // We use 1000 items here — enough to exercise the path that used
        // to bail out at the cap, while keeping the test fast. Each item
        // is a single byte so block-weight constraints stay irrelevant.
        const ITEM_COUNT: usize = 1000;
        let mut witness: Vec<Vec<u8>> = Vec::with_capacity(ITEM_COUNT);
        for i in 0..ITEM_COUNT {
            witness.push(vec![(i & 0xff) as u8]);
        }

        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::from_hex(
                        "2222222222222222222222222222222222222222222222222222222222222222",
                    )
                    .unwrap(),
                    vout: 0,
                },
                script_sig: vec![],
                sequence: 0xFFFFFFFF,
                witness,
            }],
            outputs: vec![TxOut {
                value: 10_000_000,
                script_pubkey: vec![0x00, 0x14],
            }],
            lock_time: 0,
        };

        // Sanity: previous cap would have been blown.
        assert!(tx.inputs[0].witness.len() > 500);

        let encoded = tx.serialize();
        let decoded = Transaction::deserialize(&encoded)
            .expect("tx with >500 witness items must deserialize after the cap bump");
        assert_eq!(decoded.inputs[0].witness.len(), ITEM_COUNT);
        assert_eq!(decoded, tx);
    }

    #[test]
    fn witness_item_count_at_cap_is_accepted_in_principle() {
        // Direct check that the constant matches the documented bump.
        // (Constructing a real 4M-item tx would exceed block-weight bounds;
        // this just guards the constant from regressing.)
        assert_eq!(MAX_WITNESS_ITEMS, 4_000_000);
    }

    #[test]
    fn txid_equals_wtxid_for_legacy() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: vec![0x04, 0xFF],
                sequence: 0xFFFFFFFF,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 50_0000_0000,
                script_pubkey: vec![0x41],
            }],
            lock_time: 0,
        };

        let txid = tx.txid();
        let wtxid = tx.wtxid();
        assert_eq!(txid, wtxid, "txid and wtxid should be equal for legacy tx");
    }

    // ── W76 BIP-141 weight / vsize comprehensive tests ─────────────────────

    /// W76-G1: non-segwit transaction weight == 4 × size.
    /// Core validation.h:128-131: for stripped == total, weight = stripped*3 + total = 4*size.
    #[test]
    fn w76_legacy_tx_weight_equals_4x_size() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: vec![0x04, 0xFF, 0xFF, 0x00, 0x1D],
                sequence: 0xFFFFFFFF,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 50_0000_0000,
                script_pubkey: vec![0x41],
            }],
            lock_time: 0,
        };
        assert!(!tx.has_witness());
        let size = tx.serialized_size();
        assert_eq!(tx.weight(), 4 * size, "legacy tx weight must be 4 × size");
    }

    /// W76-G2: P2WPKH tx weight = 3 × stripped + total.
    /// Core validation.h:134: `stripped * (WITNESS_SCALE_FACTOR - 1) + total`.
    #[test]
    fn w76_p2wpkh_tx_weight_formula() {
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::ZERO,
                    vout: 0,
                },
                script_sig: vec![],
                sequence: 0xFFFFFFFF,
                witness: vec![vec![0u8; 71], vec![0u8; 33]], // typical P2WPKH
            }],
            outputs: vec![TxOut {
                value: 10_000_000,
                script_pubkey: vec![0x00, 0x14, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            }],
            lock_time: 0,
        };
        assert!(tx.has_witness());
        let stripped = tx.base_size();
        let total = tx.serialized_size();
        assert!(total > stripped, "segwit tx total must exceed stripped");
        assert_eq!(
            tx.weight(),
            stripped * 3 + total,
            "P2WPKH weight must be 3*stripped + total"
        );
    }

    /// W76-G3: vsize uses ceiling division (weight non-multiple of 4 → ceil, not floor).
    /// Core policy.cpp:397: `(x + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR`.
    #[test]
    fn w76_vsize_ceil_rounding() {
        // Build a segwit tx with a 1-byte witness item.
        // stripped = 4(ver) + 1(vin_count) + 36(outpoint) + 1(script_sig_len)
        //            + 0(script_sig) + 4(seq) + 1(vout_count) + 8(value)
        //            + 1(script_pk_len) + 0(script_pk) + 4(locktime) = 60
        // total = 60 + 2(marker+flag) + [1(stack_count) + 1(item_len) + 1(item)] = 65
        // weight = 60*3 + 65 = 245  → not divisible by 4
        // vsize  = ceil(245/4) = 62
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::ZERO,
                    vout: 0,
                },
                script_sig: vec![],
                sequence: 0xFFFFFFFF,
                witness: vec![vec![0xABu8]], // 1-byte item → odd total weight
            }],
            outputs: vec![TxOut {
                value: 0,
                script_pubkey: vec![],
            }],
            lock_time: 0,
        };
        let w = tx.weight();
        let expected_vsize = (w + 3) / 4; // ceiling division
        assert_eq!(tx.vsize(), expected_vsize, "vsize must use ceiling division");
        // Verify the test is non-trivial: weight must not be divisible by 4
        assert_ne!(w % 4, 0, "test is only meaningful when weight % 4 != 0");
        assert_ne!(tx.vsize(), w / 4, "floor division gives wrong answer for weight={w}");
    }

    /// W76-G4: stripped serialisation excludes marker (0x00), flag (0x01), and all witness.
    /// Core validation.h:134: TX_NO_WITNESS omits the segwit marker+flag and witness stacks.
    #[test]
    fn w76_stripped_excludes_marker_flag_and_witness() {
        let witness_items: Vec<Vec<u8>> = vec![vec![0u8; 71], vec![0u8; 33]];
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::ZERO,
                    vout: 0,
                },
                script_sig: vec![],
                sequence: 0xFFFFFFFF,
                witness: witness_items.clone(),
            }],
            outputs: vec![TxOut {
                value: 5_000_000,
                script_pubkey: vec![0x00, 0x14, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            }],
            lock_time: 0,
        };
        let stripped = tx.base_size();
        let total = tx.serialized_size();
        // witness_bytes = compact_size(item_count=2) + each item's (compact_size(len) + data)
        let witness_bytes: usize = 1 // compact_size(2)
            + witness_items.iter().map(|item| 1 + item.len()).sum::<usize>();
        // total = stripped + 2 (marker+flag) + witness_bytes
        assert_eq!(
            total, stripped + 2 + witness_bytes,
            "total = stripped + marker/flag + witness"
        );
        // Sanity: stripped < total − witness_bytes (the 2 marker bytes are absent)
        assert_eq!(stripped + 2, total - witness_bytes);
    }

    /// W76-G6: TxIn::input_weight for a no-witness input.
    /// Core validation.h:140-144: stripped*3 + stripped + witness_stack_size = stripped*4 + witness_size.
    #[test]
    fn w76_txin_input_weight_no_witness() {
        let txin = TxIn {
            previous_output: OutPoint::null(),
            script_sig: vec![0x04, 0xFF],
            sequence: 0xFFFFFFFF,
            witness: Vec::new(),
        };
        let stripped = txin.serialized_size_no_witness();
        // witness_size() for empty witness = compact_size(0) = 1 byte
        let witness_sz = txin.witness_size();
        assert_eq!(witness_sz, 1, "empty witness serialises as 1 byte (compact_size(0))");
        let expected = stripped * 4 + witness_sz;
        assert_eq!(txin.input_weight(), expected, "no-witness input weight = stripped*4 + 1");
    }

    /// W76-G6b: TxIn::input_weight for a P2WPKH input with witness.
    #[test]
    fn w76_txin_input_weight_with_witness() {
        let txin = TxIn {
            previous_output: OutPoint {
                txid: Hash256::ZERO,
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0xFFFFFFFF,
            witness: vec![vec![0u8; 71], vec![0u8; 33]],
        };
        let stripped = txin.serialized_size_no_witness();
        let witness_sz = txin.witness_size();
        let expected = stripped * 4 + witness_sz;
        assert_eq!(txin.input_weight(), expected);
        // Per-input weight for a P2WPKH spend should be ≈ 108 WU (stripped=41*4=164 would be
        // wrong; witness discount makes it stripped*4 + witness, not stripped*4 + witness*4).
        assert!(
            txin.input_weight() < stripped * 4 + witness_sz * 4,
            "witness bytes count at 1 WU each, not 4"
        );
    }

    /// W76-G10: MAX_STANDARD_TX_WEIGHT boundary — a tx at exactly 400_000 WU is within policy.
    ///
    /// We do not import the policy constant from consensus (no dep on consensus crate
    /// from primitives), but we verify the formula is consistent: the tx's weight
    /// matches its own base/total serialisation sizes.
    #[test]
    fn w76_weight_formula_consistency() {
        // Construct a non-trivial segwit tx and verify both formula forms give the same result:
        //   form A: base * 3 + total
        //   form B: base * 4 + witness_overhead     (where witness_overhead = total - base)
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::ZERO,
                    vout: 1,
                },
                script_sig: vec![],
                sequence: 0xFFFFFFFE,
                witness: vec![vec![0u8; 64]], // schnorr sig
            }],
            outputs: vec![
                TxOut {
                    value: 100_000,
                    script_pubkey: vec![0x51, 0x20, 0, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                },
            ],
            lock_time: 0,
        };
        let base = tx.base_size();
        let total = tx.serialized_size();
        let form_a = base * 3 + total;
        let form_b = base * 4 + (total - base); // = base*3 + total algebraically
        assert_eq!(form_a, form_b, "both weight forms must be algebraically identical");
        assert_eq!(tx.weight(), form_a, "Transaction::weight() must match the formula");
    }

    /// BIP-144 / Core transaction.h:228-231: a tx encoded with the segwit
    /// marker (0x00) + flag (0x01) byte pair MUST have at least one input
    /// with a non-empty witness stack.  If all witness stacks are empty the
    /// encoding is malformed ("Superfluous witness record") and deserialisation
    /// MUST fail.
    ///
    /// The 63-byte hex below is a version=1 tx with 1 input (null outpoint,
    /// empty scriptSig, sequence=0xffffffff) and 1 output (50 BTC, empty
    /// scriptPubKey) followed by a single witness section with 0 items (all
    /// witness stacks empty), locktime=0.  Bitcoin Core rejects it; before
    /// this fix rustoshi silently accepted it, computing the same txid as the
    /// equivalent legacy encoding — a consensus split.
    #[test]
    fn superfluous_witness_record_is_rejected() {
        let tx_hex = "0100000000010100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff0100f2052a01000000000000000000";
        let raw = hex::decode(tx_hex).expect("valid hex");
        let result = Transaction::deserialize(&raw);
        assert!(
            result.is_err(),
            "segwit-encoded tx with all-empty witness stacks must be rejected \
             (Superfluous witness record), but deserialize returned Ok"
        );
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("Superfluous witness record"),
            "error message must mention 'Superfluous witness record', got: {err}"
        );
    }

    #[test]
    fn many_outputs_above_old_cap_round_trip_4d() {
        // Bug-hunt 4D: a consensus-valid tx can carry far more than 25_000 small
        // (9-byte) outputs within a 4M-weight block. The old MAX_TX_OUT_COUNT=25_000
        // deserialize cap FALSE-REJECTED such a tx that Bitcoin Core accepts -> chain
        // split. With the cap raised to Core's MAX_SIZE bound, 30_000 outputs must
        // round-trip. Pre-fix this deserialize errors with "too many outputs".
        let n = 30_000usize;
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Vec::new(),
                sequence: 0xffff_ffff,
                witness: Vec::new(),
            }],
            outputs: (0..n)
                .map(|_| TxOut { value: 0, script_pubkey: Vec::new() })
                .collect(),
            lock_time: 0,
        };
        let bytes = tx.serialize_no_witness();
        let decoded = Transaction::deserialize(&bytes)
            .expect("a tx with 30k outputs must deserialize (Core MAX_SIZE bound)");
        assert_eq!(decoded.outputs.len(), n, "all 30k outputs must round-trip");
    }
}
