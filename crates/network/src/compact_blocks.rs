//! BIP152 Compact Block Relay
//!
//! This module implements compact block relay (BIP 152), which allows nodes to
//! send and receive blocks using short transaction identifiers, enabling block
//! reconstruction from mempool transactions without transferring full transaction data.
//!
//! Key features:
//! - Version 1: Legacy transaction serialization
//! - Version 2: SegWit-aware serialization (witness data included)
//! - Short ID calculation using SipHash-2-4 truncated to 6 bytes
//! - High-bandwidth mode: Send compact blocks immediately without inv/getdata
//! - Low-bandwidth mode: Send inv first, wait for getdata
//!
//! Reference: BIP 152 (https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki)
//! Reference: Bitcoin Core `/src/blockencodings.cpp`

use crate::message::{InvType, InvVector};
use crate::peer::PeerId;
use rustoshi_crypto::sha256;
use rustoshi_primitives::serialize::{read_compact_size, write_compact_size, Decodable, Encodable};
use rustoshi_primitives::{Block, BlockHeader, Hash256, Transaction};
use siphasher::sip::SipHasher24;
use std::collections::{HashMap, HashSet};
use std::hash::Hasher;
use std::io::{self, Cursor, Read, Write};
use std::sync::Arc;
use std::time::Instant;

/// Length of short transaction IDs in bytes.
pub const SHORTTXIDS_LENGTH: usize = 6;

/// Maximum number of high-bandwidth compact block peers (Bitcoin Core default).
pub const MAX_CMPCTBLOCK_PEERS_HB: usize = 3;

/// Compact block relay version 1 (pre-SegWit serialization).
pub const CMPCT_VERSION_1: u64 = 1;

/// Compact block relay version 2 (SegWit serialization, BIP 144).
pub const CMPCT_VERSION_2: u64 = 2;

/// Minimum weight for a serializable transaction (used for DoS limits).
/// Matches MIN_SERIALIZABLE_TRANSACTION_WEIGHT in Bitcoin Core.
pub const MIN_SERIALIZABLE_TRANSACTION_WEIGHT: usize = 60;

/// Maximum block weight (for DoS protection).
pub const MAX_BLOCK_WEIGHT: usize = 4_000_000;

/// Result status for compact block operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadStatus {
    /// Operation succeeded.
    Ok,
    /// Invalid data (peer is misbehaving).
    Invalid,
    /// Processing failed (e.g., short ID collision).
    Failed,
}

/// A prefilled transaction in a compact block.
///
/// Contains the transaction along with its index in the block.
/// The index is encoded as a differential offset from the previous prefilled tx.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrefilledTx {
    /// Index in the block (absolute, not differential).
    pub index: u16,
    /// The full transaction.
    pub tx: Arc<Transaction>,
}

impl PrefilledTx {
    /// Create a new prefilled transaction.
    pub fn new(index: u16, tx: Transaction) -> Self {
        Self {
            index,
            tx: Arc::new(tx),
        }
    }

    /// Create a new prefilled transaction from an Arc.
    pub fn from_arc(index: u16, tx: Arc<Transaction>) -> Self {
        Self { index, tx }
    }
}

/// A compact block (cmpctblock message).
///
/// Contains the block header, a nonce for short ID calculation,
/// short transaction IDs, and prefilled transactions.
#[derive(Clone, Debug)]
pub struct CmpctBlock {
    /// The block header.
    pub header: BlockHeader,
    /// Random nonce for short ID calculation.
    pub nonce: u64,
    /// 6-byte short IDs for transactions not included in prefilled_txn.
    pub short_ids: Vec<u64>,
    /// Prefilled transactions (always includes coinbase at minimum).
    pub prefilled_txn: Vec<PrefilledTx>,
    /// Cached SipHash key (k0, k1) derived from header + nonce.
    siphash_keys: Option<(u64, u64)>,
}

impl CmpctBlock {
    /// Create a compact block from a full block.
    ///
    /// The nonce should be randomly generated. At minimum, the coinbase
    /// transaction is included in prefilled_txn.
    pub fn from_block(block: &Block, nonce: u64) -> Self {
        let mut compact = Self {
            header: block.header.clone(),
            nonce,
            short_ids: Vec::with_capacity(block.transactions.len().saturating_sub(1)),
            prefilled_txn: Vec::with_capacity(1),
            siphash_keys: None,
        };

        // Compute SipHash keys
        compact.fill_siphash_keys();

        // Always prefill the coinbase (index 0)
        if !block.transactions.is_empty() {
            compact.prefilled_txn.push(PrefilledTx::new(
                0,
                block.transactions[0].clone(),
            ));
        }

        // Add short IDs for remaining transactions
        for tx in block.transactions.iter().skip(1) {
            let wtxid = tx.wtxid();
            let short_id = compact.get_short_id(&wtxid);
            compact.short_ids.push(short_id);
        }

        compact
    }

    /// Create a compact block with additional prefilled transactions.
    ///
    /// Useful when we know some transactions won't be in the receiver's mempool.
    pub fn from_block_with_prefilled(
        block: &Block,
        nonce: u64,
        prefilled_indices: &[usize],
    ) -> Self {
        let mut compact = Self {
            header: block.header.clone(),
            nonce,
            short_ids: Vec::new(),
            prefilled_txn: Vec::new(),
            siphash_keys: None,
        };

        compact.fill_siphash_keys();

        // Build set of prefilled indices (always include coinbase)
        let mut prefilled_set: HashSet<usize> = prefilled_indices.iter().copied().collect();
        prefilled_set.insert(0);

        // Sort indices for deterministic prefilled_txn order
        let mut sorted_prefilled: Vec<usize> = prefilled_set.into_iter().collect();
        sorted_prefilled.sort_unstable();

        // Add prefilled transactions
        for &idx in &sorted_prefilled {
            if idx < block.transactions.len() {
                compact.prefilled_txn.push(PrefilledTx::new(
                    idx as u16,
                    block.transactions[idx].clone(),
                ));
            }
        }

        // Add short IDs for non-prefilled transactions
        let prefilled_set: HashSet<usize> = sorted_prefilled.into_iter().collect();
        for (idx, tx) in block.transactions.iter().enumerate() {
            if !prefilled_set.contains(&idx) {
                let wtxid = tx.wtxid();
                let short_id = compact.get_short_id(&wtxid);
                compact.short_ids.push(short_id);
            }
        }

        compact
    }

    /// Get the total number of transactions in the block.
    pub fn block_tx_count(&self) -> usize {
        self.short_ids.len() + self.prefilled_txn.len()
    }

    /// Compute and cache the SipHash keys from header + nonce.
    fn fill_siphash_keys(&mut self) {
        // Serialize header + nonce
        let mut data = Vec::with_capacity(BlockHeader::SIZE + 8);
        self.header.encode(&mut data).unwrap();
        data.extend_from_slice(&self.nonce.to_le_bytes());

        // Single SHA256 hash
        let hash = sha256(&data);

        // Extract k0 and k1 from the hash
        let k0 = u64::from_le_bytes(hash[0..8].try_into().unwrap());
        let k1 = u64::from_le_bytes(hash[8..16].try_into().unwrap());

        self.siphash_keys = Some((k0, k1));
    }

    /// Get the SipHash keys, computing them if necessary.
    fn get_siphash_keys(&self) -> (u64, u64) {
        self.siphash_keys.unwrap_or_else(|| {
            let mut data = Vec::with_capacity(BlockHeader::SIZE + 8);
            self.header.encode(&mut data).unwrap();
            data.extend_from_slice(&self.nonce.to_le_bytes());

            let hash = sha256(&data);
            let k0 = u64::from_le_bytes(hash[0..8].try_into().unwrap());
            let k1 = u64::from_le_bytes(hash[8..16].try_into().unwrap());
            (k0, k1)
        })
    }

    /// Calculate the short ID for a transaction.
    ///
    /// Short ID = SipHash-2-4(wtxid) truncated to 6 bytes.
    pub fn get_short_id(&self, wtxid: &Hash256) -> u64 {
        let (k0, k1) = self.get_siphash_keys();
        let mut hasher = SipHasher24::new_with_keys(k0, k1);
        hasher.write(wtxid.as_bytes());
        let full_hash = hasher.finish();

        // Truncate to 6 bytes
        full_hash & 0x0000_FFFF_FFFF_FFFF
    }

    /// Get the block hash.
    pub fn block_hash(&self) -> Hash256 {
        self.header.block_hash()
    }
}

/// Encode a compact block to bytes.
///
/// Format:
/// - header (80 bytes)
/// - nonce (8 bytes)
/// - shortids_length (compact size)
/// - shortids[] (6 bytes each)
/// - prefilled_txn_length (compact size)
/// - prefilled_txn[] (differential index + tx)
impl CmpctBlock {
    /// Encode the compact block to a writer.
    pub fn encode<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
        let mut len = self.header.encode(writer)?;
        writer.write_all(&self.nonce.to_le_bytes())?;
        len += 8;

        // Short IDs
        len += write_compact_size(writer, self.short_ids.len() as u64)?;
        for &short_id in &self.short_ids {
            // Write 6 bytes (little-endian)
            let bytes = short_id.to_le_bytes();
            writer.write_all(&bytes[..SHORTTXIDS_LENGTH])?;
            len += SHORTTXIDS_LENGTH;
        }

        // Prefilled transactions with differential encoding
        len += write_compact_size(writer, self.prefilled_txn.len() as u64)?;
        let mut last_index: i32 = -1;
        for ptx in &self.prefilled_txn {
            // Differential index
            let diff = ptx.index as i32 - last_index - 1;
            len += write_compact_size(writer, diff as u64)?;
            last_index = ptx.index as i32;

            // Transaction (with witness for version 2)
            len += ptx.tx.encode(writer)?;
        }

        Ok(len)
    }

    /// Decode a compact block from a reader.
    pub fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let header = BlockHeader::decode(reader)?;

        let mut nonce_bytes = [0u8; 8];
        reader.read_exact(&mut nonce_bytes)?;
        let nonce = u64::from_le_bytes(nonce_bytes);

        // Short IDs
        let short_ids_len = read_compact_size(reader)? as usize;
        // DoS check: too many short IDs
        if short_ids_len > MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "too many short IDs",
            ));
        }
        let mut short_ids = Vec::with_capacity(short_ids_len);
        for _ in 0..short_ids_len {
            let mut bytes = [0u8; SHORTTXIDS_LENGTH];
            reader.read_exact(&mut bytes)?;
            // Extend to u64
            let mut full_bytes = [0u8; 8];
            full_bytes[..SHORTTXIDS_LENGTH].copy_from_slice(&bytes);
            short_ids.push(u64::from_le_bytes(full_bytes));
        }

        // Prefilled transactions
        let prefilled_len = read_compact_size(reader)? as usize;
        // DoS check
        if short_ids_len + prefilled_len > MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "too many transactions",
            ));
        }
        let mut prefilled_txn = Vec::with_capacity(prefilled_len);
        let mut last_index: i32 = -1;
        for _ in 0..prefilled_len {
            let diff = read_compact_size(reader)? as i32;
            last_index = last_index.saturating_add(diff).saturating_add(1);
            if last_index < 0 || last_index > u16::MAX as i32 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "prefilled index overflow",
                ));
            }

            let tx = Transaction::decode(reader)?;
            prefilled_txn.push(PrefilledTx::new(last_index as u16, tx));
        }

        // Validate that prefilled indices don't exceed block tx count
        if !prefilled_txn.is_empty() {
            let max_index = prefilled_txn.iter().map(|p| p.index).max().unwrap();
            if max_index as usize > short_ids_len + prefilled_len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "prefilled index out of range",
                ));
            }
        }

        let mut compact = Self {
            header,
            nonce,
            short_ids,
            prefilled_txn,
            siphash_keys: None,
        };
        compact.fill_siphash_keys();

        Ok(compact)
    }

    /// Serialize to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode(&mut buf).unwrap();
        buf
    }

    /// Deserialize from bytes.
    pub fn deserialize(data: &[u8]) -> io::Result<Self> {
        let mut cursor = Cursor::new(data);
        Self::decode(&mut cursor)
    }
}

/// Request for missing transactions in a compact block (getblocktxn message).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockTxnRequest {
    /// Hash of the block for which transactions are requested.
    pub block_hash: Hash256,
    /// Indices of requested transactions (differential encoded on wire).
    pub indices: Vec<u16>,
}

impl BlockTxnRequest {
    /// Create a new request.
    pub fn new(block_hash: Hash256, indices: Vec<u16>) -> Self {
        Self { block_hash, indices }
    }

    /// Encode to a writer.
    pub fn encode<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
        let mut len = 0;
        writer.write_all(self.block_hash.as_bytes())?;
        len += 32;

        len += write_compact_size(writer, self.indices.len() as u64)?;
        let mut last_index: i32 = -1;
        for &index in &self.indices {
            let diff = index as i32 - last_index - 1;
            len += write_compact_size(writer, diff as u64)?;
            last_index = index as i32;
        }

        Ok(len)
    }

    /// Decode from a reader.
    pub fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut hash_bytes = [0u8; 32];
        reader.read_exact(&mut hash_bytes)?;
        let block_hash = Hash256(hash_bytes);

        let count = read_compact_size(reader)? as usize;
        if count > MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "too many indices",
            ));
        }

        let mut indices = Vec::with_capacity(count);
        let mut last_index: i32 = -1;
        for _ in 0..count {
            let diff = read_compact_size(reader)? as i32;
            last_index = last_index.saturating_add(diff).saturating_add(1);
            if last_index < 0 || last_index > u16::MAX as i32 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "index overflow",
                ));
            }
            indices.push(last_index as u16);
        }

        Ok(Self { block_hash, indices })
    }

    /// Serialize to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode(&mut buf).unwrap();
        buf
    }

    /// Deserialize from bytes.
    pub fn deserialize(data: &[u8]) -> io::Result<Self> {
        let mut cursor = Cursor::new(data);
        Self::decode(&mut cursor)
    }
}

/// Response with missing transactions (blocktxn message).
#[derive(Clone, Debug)]
pub struct BlockTxn {
    /// Hash of the block.
    pub block_hash: Hash256,
    /// The requested transactions.
    pub transactions: Vec<Arc<Transaction>>,
}

impl BlockTxn {
    /// Create a new response.
    pub fn new(block_hash: Hash256, transactions: Vec<Transaction>) -> Self {
        Self {
            block_hash,
            transactions: transactions.into_iter().map(Arc::new).collect(),
        }
    }

    /// Create from Arc'd transactions.
    pub fn from_arcs(block_hash: Hash256, transactions: Vec<Arc<Transaction>>) -> Self {
        Self {
            block_hash,
            transactions,
        }
    }

    /// Encode to a writer.
    pub fn encode<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
        let mut len = 0;
        writer.write_all(self.block_hash.as_bytes())?;
        len += 32;

        len += write_compact_size(writer, self.transactions.len() as u64)?;
        for tx in &self.transactions {
            len += tx.encode(writer)?;
        }

        Ok(len)
    }

    /// Decode from a reader.
    pub fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut hash_bytes = [0u8; 32];
        reader.read_exact(&mut hash_bytes)?;
        let block_hash = Hash256(hash_bytes);

        let count = read_compact_size(reader)? as usize;
        if count > MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "too many transactions",
            ));
        }

        let mut transactions = Vec::with_capacity(count);
        for _ in 0..count {
            let tx = Transaction::decode(reader)?;
            transactions.push(Arc::new(tx));
        }

        Ok(Self {
            block_hash,
            transactions,
        })
    }

    /// Serialize to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode(&mut buf).unwrap();
        buf
    }

    /// Deserialize from bytes.
    pub fn deserialize(data: &[u8]) -> io::Result<Self> {
        let mut cursor = Cursor::new(data);
        Self::decode(&mut cursor)
    }
}

/// A partially downloaded block being reconstructed from a compact block.
#[derive(Debug)]
pub struct PartiallyDownloadedBlock {
    /// The block header.
    pub header: BlockHeader,
    /// Available transactions (None for missing ones).
    txn_available: Vec<Option<Arc<Transaction>>>,
    /// Number of prefilled transactions.
    prefilled_count: usize,
    /// Number of transactions found in mempool.
    mempool_count: usize,
    /// Number of transactions from extra pool (orphan tx cache).
    extra_count: usize,
    /// Short IDs for looking up missing transactions.
    short_id_map: HashMap<u64, usize>,
}

impl PartiallyDownloadedBlock {
    /// Create a new partially downloaded block.
    fn new() -> Self {
        Self {
            header: BlockHeader::default(),
            txn_available: Vec::new(),
            prefilled_count: 0,
            mempool_count: 0,
            extra_count: 0,
            short_id_map: HashMap::new(),
        }
    }

    /// Initialize from a compact block and attempt to fill transactions from mempool.
    ///
    /// The `mempool_txns` iterator should yield (wtxid, transaction) pairs.
    /// The `extra_txns` slice contains additional transactions to check (e.g., orphan cache).
    pub fn init_data<'a>(
        cmpct: &CmpctBlock,
        mempool_txns: impl Iterator<Item = (&'a Hash256, &'a Arc<Transaction>)>,
        extra_txns: &[(&Hash256, Arc<Transaction>)],
    ) -> Result<Self, ReadStatus> {
        // Validation
        if cmpct.header == BlockHeader::default()
            || (cmpct.short_ids.is_empty() && cmpct.prefilled_txn.is_empty())
        {
            return Err(ReadStatus::Invalid);
        }

        let tx_count = cmpct.block_tx_count();
        if tx_count > MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT {
            return Err(ReadStatus::Invalid);
        }

        let mut partial = Self::new();
        partial.header = cmpct.header.clone();
        partial.txn_available = vec![None; tx_count];

        // Insert prefilled transactions
        let mut last_index: i32 = -1;
        for ptx in &cmpct.prefilled_txn {
            if ptx.tx.inputs.is_empty() && ptx.tx.outputs.is_empty() {
                return Err(ReadStatus::Invalid);
            }

            let index = ptx.index as usize;
            if index >= tx_count {
                return Err(ReadStatus::Invalid);
            }
            if ptx.index as i32 <= last_index {
                return Err(ReadStatus::Invalid);
            }
            last_index = ptx.index as i32;

            partial.txn_available[index] = Some(ptx.tx.clone());
            partial.prefilled_count += 1;
        }

        // Build map of short IDs to indices for non-prefilled transactions
        let mut short_id_map: HashMap<u64, usize> = HashMap::with_capacity(cmpct.short_ids.len());
        let mut index_offset = 0;
        for (i, &short_id) in cmpct.short_ids.iter().enumerate() {
            // Skip over prefilled positions
            while partial.txn_available[i + index_offset].is_some() {
                index_offset += 1;
            }
            let actual_index = i + index_offset;

            // Check for short ID collision
            if short_id_map.contains_key(&short_id) {
                return Err(ReadStatus::Failed);
            }
            short_id_map.insert(short_id, actual_index);
        }

        // Track which positions we've filled
        let mut have_txn = vec![false; tx_count];
        for (i, opt) in partial.txn_available.iter().enumerate() {
            if opt.is_some() {
                have_txn[i] = true;
            }
        }

        // Try to find transactions in mempool
        for (wtxid, tx) in mempool_txns {
            let short_id = cmpct.get_short_id(wtxid);
            if let Some(&index) = short_id_map.get(&short_id) {
                if !have_txn[index] {
                    partial.txn_available[index] = Some(tx.clone());
                    have_txn[index] = true;
                    partial.mempool_count += 1;
                } else if partial.txn_available[index].is_some() {
                    // Collision: two mempool txs match the same short ID
                    // Clear it and we'll request the full tx
                    partial.txn_available[index] = None;
                    have_txn[index] = false;
                    partial.mempool_count = partial.mempool_count.saturating_sub(1);
                }
            }

            // Early exit if we found all transactions
            if partial.mempool_count == cmpct.short_ids.len() {
                break;
            }
        }

        // Try extra transactions (orphan cache, etc.)
        for (wtxid, tx) in extra_txns {
            let short_id = cmpct.get_short_id(wtxid);
            if let Some(&index) = short_id_map.get(&short_id) {
                if !have_txn[index] {
                    partial.txn_available[index] = Some(tx.clone());
                    have_txn[index] = true;
                    partial.mempool_count += 1;
                    partial.extra_count += 1;
                } else if partial.txn_available[index].is_some() {
                    // Check for collision with different wtxid
                    if let Some(ref existing) = partial.txn_available[index] {
                        if existing.wtxid() != **wtxid {
                            partial.txn_available[index] = None;
                            have_txn[index] = false;
                            partial.mempool_count = partial.mempool_count.saturating_sub(1);
                            partial.extra_count = partial.extra_count.saturating_sub(1);
                        }
                    }
                }
            }

            if partial.mempool_count == cmpct.short_ids.len() {
                break;
            }
        }

        partial.short_id_map = short_id_map;

        Ok(partial)
    }

    /// Check if a transaction at the given index is available.
    pub fn is_tx_available(&self, index: usize) -> bool {
        self.txn_available
            .get(index)
            .map(|opt| opt.is_some())
            .unwrap_or(false)
    }

    /// Get indices of missing transactions.
    pub fn get_missing_indices(&self) -> Vec<u16> {
        self.txn_available
            .iter()
            .enumerate()
            .filter_map(|(i, opt)| {
                if opt.is_none() {
                    Some(i as u16)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Check if all transactions are available (block is complete).
    pub fn is_complete(&self) -> bool {
        self.txn_available.iter().all(|opt| opt.is_some())
    }

    /// Fill in missing transactions and return the complete block.
    ///
    /// `missing_txns` should contain the transactions in the same order
    /// as the indices returned by `get_missing_indices()`.
    pub fn fill_block(&mut self, missing_txns: Vec<Arc<Transaction>>) -> Result<Block, ReadStatus> {
        if self.header == BlockHeader::default() {
            return Err(ReadStatus::Invalid);
        }

        let missing_indices = self.get_missing_indices();
        if missing_txns.len() != missing_indices.len() {
            return Err(ReadStatus::Invalid);
        }

        // Fill in missing transactions
        for (tx, &index) in missing_txns.iter().zip(missing_indices.iter()) {
            self.txn_available[index as usize] = Some(tx.clone());
        }

        // Build the block
        let transactions: Vec<Transaction> = self
            .txn_available
            .iter()
            .map(|opt| {
                opt.as_ref()
                    .map(|arc| (**arc).clone())
                    .ok_or(ReadStatus::Invalid)
            })
            .collect::<Result<Vec<_>, _>>()?;

        let block = Block {
            header: self.header.clone(),
            transactions,
        };

        // Verify merkle root to detect short ID collisions
        let computed_merkle = block.compute_merkle_root();
        if computed_merkle != block.header.merkle_root {
            return Err(ReadStatus::Failed);
        }

        // Clear state
        self.header = BlockHeader::default();
        self.txn_available.clear();

        Ok(block)
    }

    /// Get statistics about reconstruction.
    pub fn stats(&self) -> (usize, usize, usize) {
        (self.prefilled_count, self.mempool_count, self.extra_count)
    }
}

/// Compact block relay mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompactBlockMode {
    /// High-bandwidth mode: send cmpctblock directly without inv.
    HighBandwidth,
    /// Low-bandwidth mode: send inv first, wait for getdata.
    LowBandwidth,
}

/// Per-peer compact block relay state.
#[derive(Debug)]
pub struct PeerCompactBlockState {
    /// Whether compact block relay is enabled for this peer.
    pub enabled: bool,
    /// Compact block version negotiated (1 or 2).
    pub version: u64,
    /// Relay mode (high or low bandwidth).
    pub mode: CompactBlockMode,
    /// Whether the peer wants high-bandwidth mode.
    pub wants_high_bandwidth: bool,
    /// Block hashes we've sent as compact blocks to this peer.
    pub blocks_in_flight: HashSet<Hash256>,
    /// Partially downloaded blocks from this peer.
    pub partial_blocks: HashMap<Hash256, PartiallyDownloadedBlock>,
    /// Last time we received a compact block from this peer.
    pub last_cmpctblock: Option<Instant>,
    /// Number of compact blocks received from this peer.
    pub cmpctblock_count: u64,
    /// Number of successful reconstructions.
    pub successful_reconstructions: u64,
    /// Number of failed reconstructions (required blocktxn).
    pub failed_reconstructions: u64,
}

impl PeerCompactBlockState {
    /// Create a new peer state.
    pub fn new() -> Self {
        Self {
            enabled: false,
            version: 0,
            mode: CompactBlockMode::LowBandwidth,
            wants_high_bandwidth: false,
            blocks_in_flight: HashSet::new(),
            partial_blocks: HashMap::new(),
            last_cmpctblock: None,
            cmpctblock_count: 0,
            successful_reconstructions: 0,
            failed_reconstructions: 0,
        }
    }

    /// Update state from sendcmpct message.
    pub fn handle_sendcmpct(&mut self, announce: bool, version: u64) {
        // We only support version 2 (SegWit)
        if version == CMPCT_VERSION_2 {
            self.enabled = true;
            self.version = version;
            self.wants_high_bandwidth = announce;
            self.mode = if announce {
                CompactBlockMode::HighBandwidth
            } else {
                CompactBlockMode::LowBandwidth
            };
        } else if version == CMPCT_VERSION_1 {
            // Accept version 1 but we prefer version 2
            if self.version == 0 {
                self.enabled = true;
                self.version = version;
                self.wants_high_bandwidth = announce;
                self.mode = if announce {
                    CompactBlockMode::HighBandwidth
                } else {
                    CompactBlockMode::LowBandwidth
                };
            }
        }
    }

    /// Record a successful reconstruction.
    pub fn record_success(&mut self) {
        self.successful_reconstructions += 1;
    }

    /// Record a failed reconstruction (needed blocktxn).
    pub fn record_failure(&mut self) {
        self.failed_reconstructions += 1;
    }

    /// Get reconstruction success rate.
    pub fn success_rate(&self) -> f64 {
        let total = self.successful_reconstructions + self.failed_reconstructions;
        if total == 0 {
            1.0
        } else {
            self.successful_reconstructions as f64 / total as f64
        }
    }
}

impl Default for PeerCompactBlockState {
    fn default() -> Self {
        Self::new()
    }
}

/// Manager for compact block relay across all peers.
#[derive(Debug)]
pub struct CompactBlockRelay {
    /// Per-peer state.
    peer_states: HashMap<PeerId, PeerCompactBlockState>,
    /// Peers in high-bandwidth mode (limited to MAX_CMPCTBLOCK_PEERS_HB).
    high_bandwidth_peers: HashSet<PeerId>,
    /// Our preferred compact block version (always 2 for SegWit).
    our_version: u64,
}

impl CompactBlockRelay {
    /// Create a new relay manager.
    pub fn new() -> Self {
        Self {
            peer_states: HashMap::new(),
            high_bandwidth_peers: HashSet::new(),
            our_version: CMPCT_VERSION_2,
        }
    }

    /// Register a new peer.
    pub fn add_peer(&mut self, peer_id: PeerId) {
        self.peer_states.insert(peer_id, PeerCompactBlockState::new());
    }

    /// Remove a peer.
    pub fn remove_peer(&mut self, peer_id: PeerId) {
        self.peer_states.remove(&peer_id);
        self.high_bandwidth_peers.remove(&peer_id);
    }

    /// Handle a sendcmpct message from a peer.
    pub fn handle_sendcmpct(&mut self, peer_id: PeerId, announce: bool, version: u64) {
        if let Some(state) = self.peer_states.get_mut(&peer_id) {
            state.handle_sendcmpct(announce, version);

            // Update high-bandwidth peer set
            if state.enabled && state.wants_high_bandwidth {
                if self.high_bandwidth_peers.len() < MAX_CMPCTBLOCK_PEERS_HB {
                    self.high_bandwidth_peers.insert(peer_id);
                }
            }
        }
    }

    /// Check if a peer supports compact blocks.
    pub fn supports_compact_blocks(&self, peer_id: PeerId) -> bool {
        self.peer_states
            .get(&peer_id)
            .map(|s| s.enabled)
            .unwrap_or(false)
    }

    /// Check if a peer is in high-bandwidth mode.
    pub fn is_high_bandwidth(&self, peer_id: PeerId) -> bool {
        self.high_bandwidth_peers.contains(&peer_id)
    }

    /// Get peers that should receive a compact block directly.
    pub fn get_high_bandwidth_peers(&self) -> impl Iterator<Item = PeerId> + '_ {
        self.high_bandwidth_peers.iter().copied()
    }

    /// Get the compact block version for a peer.
    pub fn get_version(&self, peer_id: PeerId) -> Option<u64> {
        self.peer_states
            .get(&peer_id)
            .filter(|s| s.enabled)
            .map(|s| s.version)
    }

    /// Get our preferred compact block version.
    pub fn our_version(&self) -> u64 {
        self.our_version
    }

    /// Store a partial block for a peer.
    pub fn store_partial_block(
        &mut self,
        peer_id: PeerId,
        block_hash: Hash256,
        partial: PartiallyDownloadedBlock,
    ) {
        if let Some(state) = self.peer_states.get_mut(&peer_id) {
            state.partial_blocks.insert(block_hash, partial);
        }
    }

    /// Get a partial block for a peer.
    pub fn get_partial_block(
        &mut self,
        peer_id: PeerId,
        block_hash: &Hash256,
    ) -> Option<&mut PartiallyDownloadedBlock> {
        self.peer_states
            .get_mut(&peer_id)
            .and_then(|s| s.partial_blocks.get_mut(block_hash))
    }

    /// Remove a partial block after completion.
    pub fn remove_partial_block(&mut self, peer_id: PeerId, block_hash: &Hash256) {
        if let Some(state) = self.peer_states.get_mut(&peer_id) {
            state.partial_blocks.remove(block_hash);
        }
    }

    /// Record a successful reconstruction for a peer.
    pub fn record_success(&mut self, peer_id: PeerId) {
        if let Some(state) = self.peer_states.get_mut(&peer_id) {
            state.record_success();
        }
    }

    /// Record a failed reconstruction for a peer.
    pub fn record_failure(&mut self, peer_id: PeerId) {
        if let Some(state) = self.peer_states.get_mut(&peer_id) {
            state.record_failure();
        }
    }

    /// Get reconstruction success rate for a peer.
    pub fn success_rate(&self, peer_id: PeerId) -> Option<f64> {
        self.peer_states.get(&peer_id).map(|s| s.success_rate())
    }

    /// Get the number of high-bandwidth peers.
    pub fn high_bandwidth_peer_count(&self) -> usize {
        self.high_bandwidth_peers.len()
    }

    /// Get the number of peers with compact block support.
    pub fn compact_block_peer_count(&self) -> usize {
        self.peer_states.values().filter(|s| s.enabled).count()
    }

    /// Create an inventory vector for a compact block.
    pub fn create_cmpctblock_inv(block_hash: Hash256) -> InvVector {
        InvVector {
            inv_type: InvType::MsgCmpctBlock,
            hash: block_hash,
        }
    }
}

impl Default for CompactBlockRelay {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustoshi_primitives::transaction::{OutPoint, TxIn, TxOut};

    fn create_test_transaction(value: u64) -> Transaction {
        Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256([value as u8; 32]),
                    vout: 0,
                },
                script_sig: vec![],
                sequence: 0xFFFFFFFF,
                witness: vec![vec![0x30, 0x44], vec![0x02, 0x21]],
            }],
            outputs: vec![TxOut {
                value,
                script_pubkey: vec![0x00; 22],
            }],
            lock_time: 0,
        }
    }

    fn create_test_coinbase() -> Transaction {
        Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: vec![0x03, 0x01, 0x00, 0x00],
                sequence: 0xFFFFFFFF,
                witness: vec![vec![0u8; 32]],
            }],
            outputs: vec![TxOut {
                value: 50_0000_0000,
                script_pubkey: vec![0x51],
            }],
            lock_time: 0,
        }
    }

    fn create_test_block(tx_count: usize) -> Block {
        use rustoshi_crypto::sha256d;

        let mut transactions = vec![create_test_coinbase()];
        for i in 0..tx_count.saturating_sub(1) {
            transactions.push(create_test_transaction((i + 1) as u64 * 1_000_000));
        }

        let merkle_root = {
            let mut hashes: Vec<Hash256> = transactions.iter().map(|tx| tx.txid()).collect();
            while hashes.len() > 1 {
                if hashes.len() % 2 == 1 {
                    hashes.push(*hashes.last().unwrap());
                }
                let mut next = Vec::new();
                for pair in hashes.chunks(2) {
                    let mut combined = [0u8; 64];
                    combined[..32].copy_from_slice(&pair[0].0);
                    combined[32..].copy_from_slice(&pair[1].0);
                    next.push(sha256d(&combined));
                }
                hashes = next;
            }
            hashes.get(0).copied().unwrap_or(Hash256::ZERO)
        };

        Block {
            header: BlockHeader {
                version: 0x20000000,
                prev_block_hash: Hash256::ZERO,
                merkle_root,
                timestamp: 1234567890,
                bits: 0x1d00ffff,
                nonce: 0,
            },
            transactions,
        }
    }

    #[test]
    fn test_cmpctblock_from_block() {
        let block = create_test_block(5);
        let nonce: u64 = 0x123456789ABCDEF0;

        let compact = CmpctBlock::from_block(&block, nonce);

        assert_eq!(compact.header, block.header);
        assert_eq!(compact.nonce, nonce);
        assert_eq!(compact.block_tx_count(), 5);
        assert_eq!(compact.prefilled_txn.len(), 1); // Just coinbase
        assert_eq!(compact.prefilled_txn[0].index, 0);
        assert_eq!(compact.short_ids.len(), 4); // Remaining txs
    }

    #[test]
    fn test_cmpctblock_short_id_calculation() {
        let block = create_test_block(3);
        let nonce: u64 = 0x123456789ABCDEF0;

        let compact = CmpctBlock::from_block(&block, nonce);

        // Verify short IDs are different for different transactions
        let id1 = compact.short_ids[0];
        let id2 = compact.short_ids[1];
        assert_ne!(id1, id2);

        // Verify short ID is 6 bytes (48 bits) max
        for &short_id in &compact.short_ids {
            assert!(short_id <= 0x0000_FFFF_FFFF_FFFF);
        }

        // Verify short ID matches what we'd compute manually
        let tx1_wtxid = block.transactions[1].wtxid();
        let computed_id = compact.get_short_id(&tx1_wtxid);
        assert_eq!(computed_id, id1);
    }

    #[test]
    fn test_cmpctblock_roundtrip() {
        let block = create_test_block(10);
        let compact = CmpctBlock::from_block(&block, 0xDEADBEEF);

        let serialized = compact.serialize();
        let decoded = CmpctBlock::deserialize(&serialized).unwrap();

        assert_eq!(decoded.header, compact.header);
        assert_eq!(decoded.nonce, compact.nonce);
        assert_eq!(decoded.short_ids.len(), compact.short_ids.len());
        assert_eq!(decoded.prefilled_txn.len(), compact.prefilled_txn.len());

        // Verify short IDs match
        for (a, b) in decoded.short_ids.iter().zip(compact.short_ids.iter()) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn test_cmpctblock_with_extra_prefilled() {
        let block = create_test_block(5);
        let compact = CmpctBlock::from_block_with_prefilled(&block, 0, &[2, 4]);

        // Should have coinbase (0), plus indices 2 and 4
        assert_eq!(compact.prefilled_txn.len(), 3);
        assert_eq!(compact.short_ids.len(), 2); // Indices 1 and 3
    }

    #[test]
    fn test_blocktxn_request_roundtrip() {
        let request = BlockTxnRequest::new(Hash256([0xAB; 32]), vec![0, 5, 10, 15, 100]);

        let serialized = request.serialize();
        let decoded = BlockTxnRequest::deserialize(&serialized).unwrap();

        assert_eq!(decoded.block_hash, request.block_hash);
        assert_eq!(decoded.indices, request.indices);
    }

    #[test]
    fn test_blocktxn_response_roundtrip() {
        let txs = vec![
            create_test_transaction(1_000_000),
            create_test_transaction(2_000_000),
            create_test_transaction(3_000_000),
        ];
        let response = BlockTxn::new(Hash256([0xCD; 32]), txs.clone());

        let serialized = response.serialize();
        let decoded = BlockTxn::deserialize(&serialized).unwrap();

        assert_eq!(decoded.block_hash, response.block_hash);
        assert_eq!(decoded.transactions.len(), 3);
    }

    #[test]
    fn test_partially_downloaded_block_complete_from_mempool() {
        let block = create_test_block(5);
        let compact = CmpctBlock::from_block(&block, 0x12345);

        // Put all non-coinbase transactions in "mempool"
        let mempool: Vec<(Hash256, Arc<Transaction>)> = block
            .transactions
            .iter()
            .skip(1)
            .map(|tx| (tx.wtxid(), Arc::new(tx.clone())))
            .collect();

        let mempool_refs: Vec<(&Hash256, &Arc<Transaction>)> =
            mempool.iter().map(|(h, t)| (h, t)).collect();

        let partial =
            PartiallyDownloadedBlock::init_data(&compact, mempool_refs.into_iter(), &[]).unwrap();

        assert!(partial.is_complete());
        let (prefilled, mempool_found, _extra) = partial.stats();
        assert_eq!(prefilled, 1); // Coinbase
        assert_eq!(mempool_found, 4); // Other txs
    }

    #[test]
    fn test_partially_downloaded_block_missing_txns() {
        let block = create_test_block(5);
        let compact = CmpctBlock::from_block(&block, 0x12345);

        // Only put first two non-coinbase txs in mempool
        let mempool: Vec<(Hash256, Arc<Transaction>)> = block
            .transactions
            .iter()
            .skip(1)
            .take(2)
            .map(|tx| (tx.wtxid(), Arc::new(tx.clone())))
            .collect();

        let mempool_refs: Vec<(&Hash256, &Arc<Transaction>)> =
            mempool.iter().map(|(h, t)| (h, t)).collect();

        let partial =
            PartiallyDownloadedBlock::init_data(&compact, mempool_refs.into_iter(), &[]).unwrap();

        assert!(!partial.is_complete());
        let missing = partial.get_missing_indices();
        assert_eq!(missing.len(), 2); // Indices 3 and 4
    }

    #[test]
    fn test_partially_downloaded_block_fill() {
        let block = create_test_block(5);
        let compact = CmpctBlock::from_block(&block, 0x12345);

        // Empty mempool
        let mut partial =
            PartiallyDownloadedBlock::init_data(&compact, std::iter::empty(), &[]).unwrap();

        assert!(!partial.is_complete());
        let missing = partial.get_missing_indices();
        assert_eq!(missing.len(), 4); // All except coinbase

        // Fill with missing transactions
        let missing_txs: Vec<Arc<Transaction>> = missing
            .iter()
            .map(|&idx| Arc::new(block.transactions[idx as usize].clone()))
            .collect();

        let reconstructed = partial.fill_block(missing_txs).unwrap();
        assert_eq!(reconstructed.transactions.len(), 5);
        assert_eq!(reconstructed.header, block.header);
    }

    #[test]
    fn test_peer_compact_block_state() {
        let mut state = PeerCompactBlockState::new();

        assert!(!state.enabled);
        assert_eq!(state.version, 0);

        // Handle sendcmpct with version 2, high-bandwidth
        state.handle_sendcmpct(true, CMPCT_VERSION_2);

        assert!(state.enabled);
        assert_eq!(state.version, CMPCT_VERSION_2);
        assert!(state.wants_high_bandwidth);
        assert_eq!(state.mode, CompactBlockMode::HighBandwidth);
    }

    #[test]
    fn test_peer_compact_block_state_success_rate() {
        let mut state = PeerCompactBlockState::new();

        // Initial rate should be 100%
        assert_eq!(state.success_rate(), 1.0);

        // Record some successes and failures
        state.record_success();
        state.record_success();
        state.record_failure();

        // 2 successes out of 3 total = 66.67%
        assert!((state.success_rate() - 0.6667).abs() < 0.01);
    }

    #[test]
    fn test_compact_block_relay_manager() {
        let mut manager = CompactBlockRelay::new();
        let peer1 = PeerId(1);
        let peer2 = PeerId(2);
        let peer3 = PeerId(3);
        let peer4 = PeerId(4);

        manager.add_peer(peer1);
        manager.add_peer(peer2);
        manager.add_peer(peer3);
        manager.add_peer(peer4);

        // None support compact blocks initially
        assert!(!manager.supports_compact_blocks(peer1));
        assert_eq!(manager.compact_block_peer_count(), 0);

        // Enable for peer1 (high-bandwidth) and peer2 (low-bandwidth)
        manager.handle_sendcmpct(peer1, true, CMPCT_VERSION_2);
        manager.handle_sendcmpct(peer2, false, CMPCT_VERSION_2);

        assert!(manager.supports_compact_blocks(peer1));
        assert!(manager.supports_compact_blocks(peer2));
        assert!(manager.is_high_bandwidth(peer1));
        assert!(!manager.is_high_bandwidth(peer2));
        assert_eq!(manager.high_bandwidth_peer_count(), 1);
        assert_eq!(manager.compact_block_peer_count(), 2);

        // Add more high-bandwidth peers up to limit
        manager.handle_sendcmpct(peer3, true, CMPCT_VERSION_2);
        manager.handle_sendcmpct(peer4, true, CMPCT_VERSION_2);

        assert_eq!(
            manager.high_bandwidth_peer_count(),
            MAX_CMPCTBLOCK_PEERS_HB
        );
    }

    #[test]
    fn test_short_id_uniqueness() {
        // Generate many transactions and verify short IDs are reasonably unique
        let block = create_test_block(100);
        let compact = CmpctBlock::from_block(&block, rand::random());

        let mut short_ids: HashSet<u64> = HashSet::new();
        for &id in &compact.short_ids {
            short_ids.insert(id);
        }

        // All short IDs should be unique (99 non-coinbase txs)
        assert_eq!(short_ids.len(), compact.short_ids.len());
    }

    #[test]
    fn test_cmpctblock_invalid_empty() {
        // Empty compact block should be rejected
        let compact = CmpctBlock {
            header: BlockHeader::default(),
            nonce: 0,
            short_ids: vec![],
            prefilled_txn: vec![],
            siphash_keys: None,
        };

        let result = PartiallyDownloadedBlock::init_data(&compact, std::iter::empty(), &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_differential_encoding() {
        // Test that differential encoding works correctly
        let request = BlockTxnRequest::new(Hash256::ZERO, vec![0, 1, 2, 10, 100]);

        let serialized = request.serialize();
        let decoded = BlockTxnRequest::deserialize(&serialized).unwrap();

        assert_eq!(decoded.indices, vec![0, 1, 2, 10, 100]);
    }

    #[test]
    fn test_cmpctblock_prefilled_ordering() {
        let block = create_test_block(10);
        // Prefill indices out of order
        let compact = CmpctBlock::from_block_with_prefilled(&block, 0, &[5, 2, 8]);

        // Prefilled should be in sorted order
        let indices: Vec<u16> = compact.prefilled_txn.iter().map(|p| p.index).collect();
        let mut sorted = indices.clone();
        sorted.sort_unstable();
        assert_eq!(indices, sorted);
    }

    #[test]
    fn test_version_negotiation() {
        let mut state = PeerCompactBlockState::new();

        // First sendcmpct with version 1
        state.handle_sendcmpct(false, CMPCT_VERSION_1);
        assert!(state.enabled);
        assert_eq!(state.version, CMPCT_VERSION_1);

        // Second sendcmpct with version 2 should upgrade
        state.handle_sendcmpct(true, CMPCT_VERSION_2);
        assert_eq!(state.version, CMPCT_VERSION_2);
    }

    #[test]
    fn test_inv_type_cmpctblock() {
        let inv = CompactBlockRelay::create_cmpctblock_inv(Hash256([0xAB; 32]));
        assert_eq!(inv.inv_type, InvType::MsgCmpctBlock);
    }

    #[test]
    fn test_partial_block_stores_short_id_map() {
        let block = create_test_block(5);
        let compact = CmpctBlock::from_block(&block, 0x12345);

        let partial =
            PartiallyDownloadedBlock::init_data(&compact, std::iter::empty(), &[]).unwrap();

        // Should have 4 entries in short_id_map (for indices 1-4)
        assert_eq!(partial.short_id_map.len(), 4);
    }

    #[test]
    fn test_fill_block_verifies_merkle() {
        let block = create_test_block(3);
        let compact = CmpctBlock::from_block(&block, 0x12345);

        let mut partial =
            PartiallyDownloadedBlock::init_data(&compact, std::iter::empty(), &[]).unwrap();

        // Fill with wrong transactions
        let wrong_txs: Vec<Arc<Transaction>> = (0..2)
            .map(|i| Arc::new(create_test_transaction(i * 999_999_999)))
            .collect();

        let result = partial.fill_block(wrong_txs);
        assert_eq!(result.err(), Some(ReadStatus::Failed));
    }

    #[test]
    fn test_compact_block_relay_remove_peer() {
        let mut manager = CompactBlockRelay::new();
        let peer = PeerId(1);

        manager.add_peer(peer);
        manager.handle_sendcmpct(peer, true, CMPCT_VERSION_2);

        assert!(manager.supports_compact_blocks(peer));
        assert!(manager.is_high_bandwidth(peer));

        manager.remove_peer(peer);

        assert!(!manager.supports_compact_blocks(peer));
        assert!(!manager.is_high_bandwidth(peer));
    }

    #[test]
    fn test_partial_block_storage() {
        let mut manager = CompactBlockRelay::new();
        let peer = PeerId(1);
        let block_hash = Hash256([0xAB; 32]);

        manager.add_peer(peer);

        let partial = PartiallyDownloadedBlock::new();
        manager.store_partial_block(peer, block_hash, partial);

        assert!(manager.get_partial_block(peer, &block_hash).is_some());

        manager.remove_partial_block(peer, &block_hash);
        assert!(manager.get_partial_block(peer, &block_hash).is_none());
    }
}
