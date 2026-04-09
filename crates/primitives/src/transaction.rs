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

/// Maximum number of inputs/outputs per transaction (consensus: MAX_BLOCK_WEIGHT / MIN_TX_WEIGHT
/// gives ~25k as a safe upper bound; Bitcoin Core uses similar limits implicitly via block size).
const MAX_TX_IN_COUNT: usize = 25_000;
const MAX_TX_OUT_COUNT: usize = 25_000;
/// Maximum script size (consensus limit is 10,000 bytes for scriptSig; scriptPubKey can be
/// larger in witness but we cap at the block weight limit for safety).
const MAX_SCRIPT_SIZE: u64 = 10_000;
/// Maximum number of witness items per input.
const MAX_WITNESS_ITEMS: usize = 500;
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
        let mut inputs = Vec::with_capacity(input_count as usize);
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
        let mut outputs = Vec::with_capacity(output_count as usize);
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
}
