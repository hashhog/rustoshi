//! Bitcoin block types.
//!
//! This module provides types for Bitcoin blocks including BlockHeader and Block
//! with full serialization support and Merkle root computation.

use crate::hash::Hash256;
use crate::serialize::{compact_size_len, read_compact_size, write_compact_size, Decodable, Encodable};
use crate::transaction::Transaction;
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};

/// Maximum number of transactions in a block. A 4MB block at minimum transaction
/// weight (60 WU each) can hold at most ~68k transactions. We use 25k as a safe
/// upper bound matching the per-transaction input/output limits.
const MAX_TX_COUNT: u64 = 25_000;

/// A block header (80 bytes).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct BlockHeader {
    /// Block version.
    pub version: i32,
    /// Hash of the previous block header.
    pub prev_block_hash: Hash256,
    /// Merkle root of the transaction tree.
    pub merkle_root: Hash256,
    /// Block timestamp (Unix time).
    pub timestamp: u32,
    /// Difficulty target in compact format.
    pub bits: u32,
    /// Nonce for proof-of-work.
    pub nonce: u32,
}

impl BlockHeader {
    /// The block header is always exactly 80 bytes.
    pub const SIZE: usize = 80;

    /// Compute the block hash (double SHA-256 of the 80-byte header).
    pub fn block_hash(&self) -> Hash256 {
        let data = self.serialize();
        let hash = Sha256::digest(Sha256::digest(&data));
        Hash256(hash.into())
    }

    /// Decode the `bits` field into a 256-bit target.
    ///
    /// bits = 0xNNBBBBBB where NN is the exponent and BBBBBB is the mantissa.
    /// target = mantissa * 2^(8 * (exponent - 3))
    ///
    /// The result is a 256-bit big-endian integer stored in a 32-byte array.
    pub fn target(&self) -> [u8; 32] {
        let exponent = (self.bits >> 24) as usize;
        let mantissa = self.bits & 0x007F_FFFF;
        let negative = (self.bits & 0x0080_0000) != 0;

        // Invalid targets
        if negative || mantissa == 0 || exponent == 0 {
            return [0u8; 32];
        }

        let mut target = [0u8; 32];

        if exponent <= 3 {
            // Mantissa needs to be shifted right
            let shift = 8 * (3 - exponent);
            let m = mantissa >> shift;
            // Write in big-endian: least significant bytes go at the end
            target[31] = (m & 0xFF) as u8;
            if exponent >= 2 {
                target[30] = ((m >> 8) & 0xFF) as u8;
            }
            if exponent >= 3 {
                target[29] = ((m >> 16) & 0xFF) as u8;
            }
        } else {
            // Position where mantissa starts (big-endian, so from the left)
            // exponent tells us the total byte length from the right
            // so start position = 32 - exponent
            let start = 32 - exponent;
            if start < 32 {
                target[start] = ((mantissa >> 16) & 0xFF) as u8;
            }
            if start + 1 < 32 {
                target[start + 1] = ((mantissa >> 8) & 0xFF) as u8;
            }
            if start + 2 < 32 {
                target[start + 2] = (mantissa & 0xFF) as u8;
            }
        }

        target
    }

    /// Check that the block hash is at or below the target encoded in `bits`.
    pub fn validate_pow(&self) -> bool {
        let hash = self.block_hash();
        let target = self.target();

        // Compare hash against target
        // Hash is stored in little-endian (internal byte order)
        // Target is big-endian, so we reverse hash for comparison
        let mut hash_be = hash.0;
        hash_be.reverse();

        hash_be <= target
    }
}

impl Encodable for BlockHeader {
    fn encode<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
        writer.write_all(&self.version.to_le_bytes())?;
        writer.write_all(&self.prev_block_hash.0)?;
        writer.write_all(&self.merkle_root.0)?;
        writer.write_all(&self.timestamp.to_le_bytes())?;
        writer.write_all(&self.bits.to_le_bytes())?;
        writer.write_all(&self.nonce.to_le_bytes())?;
        Ok(Self::SIZE)
    }

    fn serialized_size(&self) -> usize {
        Self::SIZE
    }
}

impl Decodable for BlockHeader {
    fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut version_bytes = [0u8; 4];
        reader.read_exact(&mut version_bytes)?;

        let mut prev_hash = [0u8; 32];
        reader.read_exact(&mut prev_hash)?;

        let mut merkle = [0u8; 32];
        reader.read_exact(&mut merkle)?;

        let mut timestamp_bytes = [0u8; 4];
        reader.read_exact(&mut timestamp_bytes)?;

        let mut bits_bytes = [0u8; 4];
        reader.read_exact(&mut bits_bytes)?;

        let mut nonce_bytes = [0u8; 4];
        reader.read_exact(&mut nonce_bytes)?;

        Ok(Self {
            version: i32::from_le_bytes(version_bytes),
            prev_block_hash: Hash256(prev_hash),
            merkle_root: Hash256(merkle),
            timestamp: u32::from_le_bytes(timestamp_bytes),
            bits: u32::from_le_bytes(bits_bytes),
            nonce: u32::from_le_bytes(nonce_bytes),
        })
    }
}

/// A full block (header + transactions).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Block {
    /// The block header.
    pub header: BlockHeader,
    /// The transactions in the block.
    pub transactions: Vec<Transaction>,
}

impl Block {
    /// Block hash is the header hash.
    pub fn block_hash(&self) -> Hash256 {
        self.header.block_hash()
    }

    /// Compute the Merkle root of the transactions.
    ///
    /// Algorithm: double-SHA256 each txid, then pairwise hash up the tree.
    /// If odd number of elements at any level, duplicate the last element.
    pub fn compute_merkle_root(&self) -> Hash256 {
        if self.transactions.is_empty() {
            return Hash256::ZERO;
        }

        // Start with the txids
        let mut hashes: Vec<[u8; 32]> = self
            .transactions
            .iter()
            .map(|tx| tx.txid().0)
            .collect();

        // Build the tree
        while hashes.len() > 1 {
            if hashes.len() % 2 == 1 {
                // Duplicate the last hash
                hashes.push(*hashes.last().unwrap());
            }

            let mut next_level = Vec::with_capacity(hashes.len() / 2);
            for pair in hashes.chunks(2) {
                let mut combined = [0u8; 64];
                combined[..32].copy_from_slice(&pair[0]);
                combined[32..].copy_from_slice(&pair[1]);
                let hash = Sha256::digest(Sha256::digest(combined));
                next_level.push(hash.into());
            }
            hashes = next_level;
        }

        Hash256(hashes[0])
    }

    /// Compute the witness commitment Merkle root using wtxids.
    /// The coinbase wtxid is defined as 32 zero bytes.
    pub fn compute_witness_root(&self) -> Hash256 {
        if self.transactions.is_empty() {
            return Hash256::ZERO;
        }

        // Start with the wtxids, but coinbase wtxid is all zeros
        let mut hashes: Vec<[u8; 32]> = self
            .transactions
            .iter()
            .enumerate()
            .map(|(i, tx)| {
                if i == 0 {
                    [0u8; 32] // Coinbase wtxid is all zeros
                } else {
                    tx.wtxid().0
                }
            })
            .collect();

        // Build the tree (same algorithm as merkle root)
        while hashes.len() > 1 {
            if hashes.len() % 2 == 1 {
                hashes.push(*hashes.last().unwrap());
            }

            let mut next_level = Vec::with_capacity(hashes.len() / 2);
            for pair in hashes.chunks(2) {
                let mut combined = [0u8; 64];
                combined[..32].copy_from_slice(&pair[0]);
                combined[32..].copy_from_slice(&pair[1]);
                let hash = Sha256::digest(Sha256::digest(combined));
                next_level.push(hash.into());
            }
            hashes = next_level;
        }

        Hash256(hashes[0])
    }
}

impl Encodable for Block {
    fn encode<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
        let mut len = self.header.encode(writer)?;
        len += write_compact_size(writer, self.transactions.len() as u64)?;
        for tx in &self.transactions {
            len += tx.encode(writer)?;
        }
        Ok(len)
    }

    fn serialized_size(&self) -> usize {
        let mut size = BlockHeader::SIZE;
        size += compact_size_len(self.transactions.len() as u64);
        for tx in &self.transactions {
            size += tx.serialized_size();
        }
        size
    }
}

impl Decodable for Block {
    fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let header = BlockHeader::decode(reader)?;
        let tx_count = read_compact_size(reader)?;

        // Sanity check: prevent OOM from absurdly large counts
        if tx_count > MAX_TX_COUNT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("too many transactions: {}", tx_count),
            ));
        }

        let mut transactions = Vec::with_capacity(tx_count as usize);
        for _ in 0..tx_count {
            transactions.push(Transaction::decode(reader)?);
        }

        Ok(Self {
            header,
            transactions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{OutPoint, TxIn, TxOut};

    #[test]
    fn block_header_size() {
        let header = BlockHeader::default();
        assert_eq!(header.serialized_size(), 80);
        assert_eq!(header.serialize().len(), 80);
    }

    #[test]
    fn block_header_roundtrip() {
        let header = BlockHeader {
            version: 1,
            prev_block_hash: Hash256::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
            merkle_root: Hash256::from_hex(
                "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
            )
            .unwrap(),
            timestamp: 1231006505,
            bits: 0x1d00ffff,
            nonce: 2083236893,
        };

        let encoded = header.serialize();
        assert_eq!(encoded.len(), 80);

        let decoded = BlockHeader::deserialize(&encoded).unwrap();
        assert_eq!(header, decoded);
    }

    #[test]
    fn genesis_block_hash() {
        // Bitcoin mainnet genesis block header
        let genesis_header = BlockHeader {
            version: 1,
            prev_block_hash: Hash256::ZERO,
            merkle_root: Hash256::from_hex(
                "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
            )
            .unwrap(),
            timestamp: 1231006505,
            bits: 0x1d00ffff,
            nonce: 2083236893,
        };

        let hash = genesis_header.block_hash();
        assert_eq!(
            hash.to_hex(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
    }

    #[test]
    fn genesis_block_pow() {
        let genesis_header = BlockHeader {
            version: 1,
            prev_block_hash: Hash256::ZERO,
            merkle_root: Hash256::from_hex(
                "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
            )
            .unwrap(),
            timestamp: 1231006505,
            bits: 0x1d00ffff,
            nonce: 2083236893,
        };

        assert!(genesis_header.validate_pow());
    }

    #[test]
    fn target_decoding() {
        // Genesis block bits: 0x1d00ffff
        // exponent = 0x1d = 29
        // mantissa = 0x00ffff
        // target = 0x00ffff * 2^(8*(29-3)) = 0x00ffff * 2^208
        let header = BlockHeader {
            bits: 0x1d00ffff,
            ..Default::default()
        };

        let target = header.target();
        // The target should have leading zeros followed by 0x00ffff
        // At position 32-29 = 3, we should see 0x00, then 0xff, then 0xff
        assert_eq!(target[3], 0x00);
        assert_eq!(target[4], 0xff);
        assert_eq!(target[5], 0xff);
        // Everything before should be zero
        assert_eq!(target[0], 0);
        assert_eq!(target[1], 0);
        assert_eq!(target[2], 0);
    }

    #[test]
    fn block_roundtrip() {
        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: Hash256::ZERO,
                merkle_root: Hash256::ZERO,
                timestamp: 1231006505,
                bits: 0x1d00ffff,
                nonce: 2083236893,
            },
            transactions: vec![Transaction {
                version: 1,
                inputs: vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: vec![0x04, 0xff, 0xff, 0x00, 0x1d],
                    sequence: 0xFFFFFFFF,
                    witness: Vec::new(),
                }],
                outputs: vec![TxOut {
                    value: 50_0000_0000,
                    script_pubkey: vec![0x41],
                }],
                lock_time: 0,
            }],
        };

        let encoded = block.serialize();
        let decoded = Block::deserialize(&encoded).unwrap();
        assert_eq!(block, decoded);
    }

    #[test]
    fn merkle_root_single_tx() {
        // With a single transaction, the merkle root is just the txid
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: vec![0x04],
                sequence: 0xFFFFFFFF,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 50_0000_0000,
                script_pubkey: vec![0x41],
            }],
            lock_time: 0,
        };

        let block = Block {
            header: BlockHeader::default(),
            transactions: vec![tx.clone()],
        };

        assert_eq!(block.compute_merkle_root(), tx.txid());
    }

    #[test]
    fn merkle_root_two_txs() {
        let tx1 = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: vec![0x01],
                sequence: 0xFFFFFFFF,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 50_0000_0000,
                script_pubkey: vec![0x41],
            }],
            lock_time: 0,
        };

        let tx2 = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: tx1.txid(),
                    vout: 0,
                },
                script_sig: vec![0x02],
                sequence: 0xFFFFFFFF,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 49_0000_0000,
                script_pubkey: vec![0x76],
            }],
            lock_time: 0,
        };

        let block = Block {
            header: BlockHeader::default(),
            transactions: vec![tx1.clone(), tx2.clone()],
        };

        // Manually compute expected merkle root
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&tx1.txid().0);
        combined[32..].copy_from_slice(&tx2.txid().0);
        let expected = Sha256::digest(&Sha256::digest(&combined));

        assert_eq!(block.compute_merkle_root().0, expected.as_slice());
    }

    #[test]
    fn merkle_root_empty() {
        let block = Block {
            header: BlockHeader::default(),
            transactions: vec![],
        };

        assert_eq!(block.compute_merkle_root(), Hash256::ZERO);
    }

    #[test]
    fn witness_root_coinbase_is_zero() {
        // Create a coinbase with witness and a regular tx with witness
        let coinbase = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: vec![0x03, 0x01, 0x02, 0x03],
                sequence: 0xFFFFFFFF,
                witness: vec![vec![0u8; 32]], // Witness nonce
            }],
            outputs: vec![TxOut {
                value: 50_0000_0000,
                script_pubkey: vec![0x51],
            }],
            lock_time: 0,
        };

        let block = Block {
            header: BlockHeader::default(),
            transactions: vec![coinbase],
        };

        // Witness root for single coinbase should be hash of all zeros (the coinbase wtxid)
        let witness_root = block.compute_witness_root();
        // Since there's only one tx and its wtxid is treated as zeros,
        // the witness root should be the hash of zeros
        assert_eq!(witness_root.0, [0u8; 32]);
    }
}
