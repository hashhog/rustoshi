//! Block-level storage operations.
//!
//! This module provides high-level operations for storing and retrieving
//! blocks, headers, UTXOs, and chain metadata.

use crate::columns::*;
use crate::db::{ChainDb, StorageError, META_BEST_BLOCK_HASH, META_BEST_HEIGHT};
use rustoshi_primitives::{Block, BlockHeader, Decodable, Encodable, Hash256, OutPoint};
use serde::{Deserialize, Serialize};

// ============================================================
// BLOCK STATUS FLAGS
// ============================================================

/// Block validation status flags.
///
/// These flags track how far a block has been validated and what data
/// we have available for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct BlockStatus(u32);

impl BlockStatus {
    /// Header has been validated (PoW, timestamp).
    pub const VALID_HEADER: u32 = 1;

    /// Tree structure is valid (transactions can be parsed).
    pub const VALID_TREE: u32 = 2;

    /// All transactions are valid (no double spends, valid scripts).
    pub const VALID_TRANSACTIONS: u32 = 3;

    /// Block connects to a valid chain.
    pub const VALID_CHAIN: u32 = 4;

    /// All scripts have been validated.
    pub const VALID_SCRIPTS: u32 = 5;

    /// We have the full block data.
    pub const HAVE_DATA: u32 = 8;

    /// We have the undo data for this block.
    pub const HAVE_UNDO: u32 = 16;

    /// Block failed validation.
    pub const FAILED_VALIDITY: u32 = 32;

    /// A descendant of this block failed validation.
    pub const FAILED_CHILD: u32 = 64;

    /// Create a new empty status.
    pub fn new() -> Self {
        Self(0)
    }

    /// Check if a flag is set.
    pub fn has(&self, flag: u32) -> bool {
        self.0 & flag != 0
    }

    /// Set a flag.
    pub fn set(&mut self, flag: u32) {
        self.0 |= flag;
    }

    /// Clear a flag.
    pub fn clear(&mut self, flag: u32) {
        self.0 &= !flag;
    }

    /// Get the raw flags value.
    pub fn raw(&self) -> u32 {
        self.0
    }
}

// ============================================================
// INDEX ENTRY TYPES
// ============================================================

/// Block index entry stored in CF_BLOCK_INDEX.
///
/// Contains metadata about a block for chain management without
/// requiring the full block data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockIndexEntry {
    /// Block height in the chain.
    pub height: u32,
    /// Validation status flags.
    pub status: BlockStatus,
    /// Number of transactions in the block.
    pub n_tx: u32,
    /// Block timestamp.
    pub timestamp: u32,
    /// Compact difficulty target.
    pub bits: u32,
    /// PoW nonce.
    pub nonce: u32,
    /// Block version.
    pub version: i32,
    /// Previous block hash.
    pub prev_hash: Hash256,
    /// Total chain work up to and including this block (256-bit big-endian).
    pub chain_work: [u8; 32],
}

/// Transaction index entry stored in CF_TX_INDEX.
///
/// Allows looking up a transaction's location in the block data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxIndexEntry {
    /// Hash of the block containing this transaction.
    pub block_hash: Hash256,
    /// Byte offset of the transaction within the serialized block.
    pub tx_offset: u32,
    /// Length of the serialized transaction in bytes.
    pub tx_length: u32,
}

/// UTXO entry stored in CF_UTXO.
///
/// Contains the data needed to validate spending of this output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoinEntry {
    /// Height of the block that created this output.
    pub height: u32,
    /// Whether this output is from a coinbase transaction.
    pub is_coinbase: bool,
    /// Value in satoshis.
    pub value: u64,
    /// The scriptPubKey (locking script).
    pub script_pubkey: Vec<u8>,
}

/// Undo data stored in CF_UNDO.
///
/// Contains the coins that were spent by a block's transactions,
/// needed to reverse the block during a reorganization.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UndoData {
    /// Coins spent by this block's transactions, in order.
    pub spent_coins: Vec<CoinEntry>,
}

// ============================================================
// BLOCK STORE
// ============================================================

/// High-level block storage operations.
///
/// Wraps a `ChainDb` reference and provides typed methods for
/// storing and retrieving blockchain data.
pub struct BlockStore<'a> {
    db: &'a ChainDb,
}

impl<'a> BlockStore<'a> {
    /// Create a new BlockStore wrapping the given database.
    pub fn new(db: &'a ChainDb) -> Self {
        Self { db }
    }

    // ---------------- HEADERS ----------------

    /// Store a block header.
    pub fn put_header(&self, hash: &Hash256, header: &BlockHeader) -> Result<(), StorageError> {
        let data = header.serialize();
        self.db.put_cf(CF_HEADERS, hash.as_bytes(), &data)
    }

    /// Retrieve a block header by hash.
    pub fn get_header(&self, hash: &Hash256) -> Result<Option<BlockHeader>, StorageError> {
        match self.db.get_cf(CF_HEADERS, hash.as_bytes())? {
            Some(data) => Ok(Some(
                BlockHeader::deserialize(&data)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    /// Check if we have a header for this hash.
    pub fn has_header(&self, hash: &Hash256) -> Result<bool, StorageError> {
        self.db.contains_key(CF_HEADERS, hash.as_bytes())
    }

    // ---------------- BLOCKS ----------------

    /// Store a full block.
    pub fn put_block(&self, hash: &Hash256, block: &Block) -> Result<(), StorageError> {
        let data = block.serialize();
        self.db.put_cf(CF_BLOCKS, hash.as_bytes(), &data)
    }

    /// Retrieve a full block by hash.
    pub fn get_block(&self, hash: &Hash256) -> Result<Option<Block>, StorageError> {
        match self.db.get_cf(CF_BLOCKS, hash.as_bytes())? {
            Some(data) => Ok(Some(
                Block::deserialize(&data)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    /// Check if we have the full block data for this hash.
    pub fn has_block(&self, hash: &Hash256) -> Result<bool, StorageError> {
        self.db.contains_key(CF_BLOCKS, hash.as_bytes())
    }

    // ---------------- BLOCK INDEX ----------------

    /// Store a block index entry.
    pub fn put_block_index(
        &self,
        hash: &Hash256,
        entry: &BlockIndexEntry,
    ) -> Result<(), StorageError> {
        let data =
            serde_json::to_vec(entry).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put_cf(CF_BLOCK_INDEX, hash.as_bytes(), &data)
    }

    /// Retrieve a block index entry by hash.
    pub fn get_block_index(&self, hash: &Hash256) -> Result<Option<BlockIndexEntry>, StorageError> {
        match self.db.get_cf(CF_BLOCK_INDEX, hash.as_bytes())? {
            Some(data) => {
                let entry: BlockIndexEntry = serde_json::from_slice(&data)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(entry))
            }
            None => Ok(None),
        }
    }

    // ---------------- HEIGHT INDEX ----------------

    /// Store the block hash at a given height (for the active chain).
    pub fn put_height_index(&self, height: u32, hash: &Hash256) -> Result<(), StorageError> {
        // Use big-endian for height so RocksDB iteration is numerically sorted
        self.db
            .put_cf(CF_HEIGHT_INDEX, &height.to_be_bytes(), hash.as_bytes())
    }

    /// Get the block hash at a given height in the active chain.
    pub fn get_hash_by_height(&self, height: u32) -> Result<Option<Hash256>, StorageError> {
        match self.db.get_cf(CF_HEIGHT_INDEX, &height.to_be_bytes())? {
            Some(data) => {
                if data.len() != 32 {
                    return Err(StorageError::Corruption(format!(
                        "invalid hash length at height {}: expected 32, got {}",
                        height,
                        data.len()
                    )));
                }
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&data);
                Ok(Some(Hash256(hash)))
            }
            None => Ok(None),
        }
    }

    /// Delete the height index entry (used during reorgs).
    pub fn delete_height_index(&self, height: u32) -> Result<(), StorageError> {
        self.db.delete_cf(CF_HEIGHT_INDEX, &height.to_be_bytes())
    }

    // ---------------- CHAIN METADATA ----------------

    /// Set the best (tip) block hash and height.
    pub fn set_best_block(&self, hash: &Hash256, height: u32) -> Result<(), StorageError> {
        self.db.put_cf(CF_META, META_BEST_BLOCK_HASH, hash.as_bytes())?;
        self.db
            .put_cf(CF_META, META_BEST_HEIGHT, &height.to_le_bytes())?;
        Ok(())
    }

    /// Get the best (tip) block hash.
    pub fn get_best_block_hash(&self) -> Result<Option<Hash256>, StorageError> {
        match self.db.get_cf(CF_META, META_BEST_BLOCK_HASH)? {
            Some(data) => {
                if data.len() != 32 {
                    return Err(StorageError::Corruption(
                        "invalid best block hash length".into(),
                    ));
                }
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&data);
                Ok(Some(Hash256(hash)))
            }
            None => Ok(None),
        }
    }

    /// Get the best (tip) block height.
    pub fn get_best_height(&self) -> Result<Option<u32>, StorageError> {
        match self.db.get_cf(CF_META, META_BEST_HEIGHT)? {
            Some(data) => {
                if data.len() != 4 {
                    return Err(StorageError::Corruption(
                        "invalid best height length".into(),
                    ));
                }
                let mut buf = [0u8; 4];
                buf.copy_from_slice(&data);
                Ok(Some(u32::from_le_bytes(buf)))
            }
            None => Ok(None),
        }
    }

    // ---------------- UTXO SET ----------------

    /// Store a UTXO entry.
    pub fn put_utxo(&self, outpoint: &OutPoint, coin: &CoinEntry) -> Result<(), StorageError> {
        let key = outpoint_key(outpoint);
        let data =
            serde_json::to_vec(coin).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put_cf(CF_UTXO, &key, &data)
    }

    /// Retrieve a UTXO entry.
    pub fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<CoinEntry>, StorageError> {
        let key = outpoint_key(outpoint);
        match self.db.get_cf(CF_UTXO, &key)? {
            Some(data) => {
                let coin: CoinEntry = serde_json::from_slice(&data)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(coin))
            }
            None => Ok(None),
        }
    }

    /// Delete a UTXO entry (when spent).
    pub fn delete_utxo(&self, outpoint: &OutPoint) -> Result<(), StorageError> {
        let key = outpoint_key(outpoint);
        self.db.delete_cf(CF_UTXO, &key)
    }

    /// Check if a UTXO exists.
    pub fn has_utxo(&self, outpoint: &OutPoint) -> Result<bool, StorageError> {
        let key = outpoint_key(outpoint);
        self.db.contains_key(CF_UTXO, &key)
    }

    // ---------------- UNDO DATA ----------------

    /// Store undo data for a block.
    pub fn put_undo(&self, hash: &Hash256, undo: &UndoData) -> Result<(), StorageError> {
        let data =
            serde_json::to_vec(undo).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put_cf(CF_UNDO, hash.as_bytes(), &data)
    }

    /// Retrieve undo data for a block.
    pub fn get_undo(&self, hash: &Hash256) -> Result<Option<UndoData>, StorageError> {
        match self.db.get_cf(CF_UNDO, hash.as_bytes())? {
            Some(data) => {
                let undo: UndoData = serde_json::from_slice(&data)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(undo))
            }
            None => Ok(None),
        }
    }

    /// Delete undo data for a block (after it's deep enough to never reorg).
    pub fn delete_undo(&self, hash: &Hash256) -> Result<(), StorageError> {
        self.db.delete_cf(CF_UNDO, hash.as_bytes())
    }

    // ---------------- TX INDEX ----------------

    /// Store a transaction index entry.
    pub fn put_tx_index(&self, txid: &Hash256, entry: &TxIndexEntry) -> Result<(), StorageError> {
        let data =
            serde_json::to_vec(entry).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put_cf(CF_TX_INDEX, txid.as_bytes(), &data)
    }

    /// Retrieve a transaction index entry.
    pub fn get_tx_index(&self, txid: &Hash256) -> Result<Option<TxIndexEntry>, StorageError> {
        match self.db.get_cf(CF_TX_INDEX, txid.as_bytes())? {
            Some(data) => {
                let entry: TxIndexEntry = serde_json::from_slice(&data)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(entry))
            }
            None => Ok(None),
        }
    }

    // ---------------- GENESIS INITIALIZATION ----------------

    // ---------------- BLOCK VALIDITY ----------------

    /// Mark a block as invalid.
    ///
    /// This sets the FAILED_VALIDITY flag on the block index entry.
    pub fn mark_block_invalid(&self, hash: &Hash256) -> Result<(), StorageError> {
        if let Some(mut entry) = self.get_block_index(hash)? {
            entry.status.set(BlockStatus::FAILED_VALIDITY);
            self.put_block_index(hash, &entry)?;
        }
        Ok(())
    }

    /// Remove the invalid status from a block.
    ///
    /// This clears the FAILED_VALIDITY and FAILED_CHILD flags on the block index entry.
    pub fn unmark_block_invalid(&self, hash: &Hash256) -> Result<(), StorageError> {
        if let Some(mut entry) = self.get_block_index(hash)? {
            entry.status.clear(BlockStatus::FAILED_VALIDITY);
            entry.status.clear(BlockStatus::FAILED_CHILD);
            self.put_block_index(hash, &entry)?;
        }
        Ok(())
    }

    /// Get the height of a block by its hash.
    pub fn get_height(&self, hash: &Hash256) -> Result<Option<u32>, StorageError> {
        if let Some(entry) = self.get_block_index(hash)? {
            Ok(Some(entry.height))
        } else {
            Ok(None)
        }
    }

    /// Create a UTXO view backed by this store.
    pub fn utxo_view(&self) -> BlockStoreUtxoView<'_> {
        BlockStoreUtxoView::new(self)
    }

    /// Iterate over all block index entries.
    ///
    /// Returns an iterator of `(Hash256, BlockIndexEntry)` pairs.
    /// This is useful for chain management operations that need to
    /// scan the entire block index (e.g., finding descendants).
    pub fn iter_block_index(
        &self,
    ) -> Result<impl Iterator<Item = (Hash256, BlockIndexEntry)> + '_, StorageError> {
        let iter = self.db.iter_cf(CF_BLOCK_INDEX)?;
        Ok(iter.filter_map(|(key, value)| {
            if key.len() != 32 {
                return None;
            }
            let mut hash_bytes = [0u8; 32];
            hash_bytes.copy_from_slice(&key);
            let hash = Hash256(hash_bytes);

            let entry: BlockIndexEntry = serde_json::from_slice(&value).ok()?;
            Some((hash, entry))
        }))
    }

    /// Get all block hashes in the block index.
    ///
    /// This is a convenience method for operations that only need
    /// the hashes without full entries.
    pub fn get_all_block_hashes(&self) -> Result<Vec<Hash256>, StorageError> {
        let iter = self.db.iter_cf(CF_BLOCK_INDEX)?;
        Ok(iter
            .filter_map(|(key, _)| {
                if key.len() != 32 {
                    return None;
                }
                let mut hash_bytes = [0u8; 32];
                hash_bytes.copy_from_slice(&key);
                Some(Hash256(hash_bytes))
            })
            .collect())
    }

    /// Mark a block as FAILED_CHILD (descendant of invalid block).
    pub fn mark_block_failed_child(&self, hash: &Hash256) -> Result<(), StorageError> {
        if let Some(mut entry) = self.get_block_index(hash)? {
            entry.status.set(BlockStatus::FAILED_CHILD);
            self.put_block_index(hash, &entry)?;
        }
        Ok(())
    }

    /// Check if a block is marked as invalid (either FAILED_VALIDITY or FAILED_CHILD).
    pub fn is_block_invalid(&self, hash: &Hash256) -> Result<bool, StorageError> {
        if let Some(entry) = self.get_block_index(hash)? {
            Ok(entry.status.has(BlockStatus::FAILED_VALIDITY)
                || entry.status.has(BlockStatus::FAILED_CHILD))
        } else {
            Ok(false)
        }
    }

    // ---------------- GENESIS INITIALIZATION ----------------

    /// Initialize the database with the genesis block if not already initialized.
    ///
    /// This is idempotent - calling it on an already-initialized database
    /// has no effect.
    pub fn init_genesis(&self, params: &rustoshi_consensus::ChainParams) -> Result<(), StorageError> {
        // Check if already initialized
        if self.get_best_block_hash()?.is_some() {
            return Ok(());
        }

        let genesis = &params.genesis_block;
        let hash = params.genesis_hash;

        // Store the header
        self.put_header(&hash, &genesis.header)?;

        // Store the full block
        self.put_block(&hash, genesis)?;

        // Create and store the block index entry
        let mut status = BlockStatus::new();
        status.set(BlockStatus::VALID_SCRIPTS);
        status.set(BlockStatus::HAVE_DATA);

        let entry = BlockIndexEntry {
            height: 0,
            status,
            n_tx: genesis.transactions.len() as u32,
            timestamp: genesis.header.timestamp,
            bits: genesis.header.bits,
            nonce: genesis.header.nonce,
            version: genesis.header.version,
            prev_hash: genesis.header.prev_block_hash,
            chain_work: [0u8; 32], // Genesis has minimal work
        };
        self.put_block_index(&hash, &entry)?;

        // Set height index
        self.put_height_index(0, &hash)?;

        // Set best block
        self.set_best_block(&hash, 0)?;

        tracing::info!("initialized database with genesis block: {}", hash);
        Ok(())
    }
}

/// Create the key for a UTXO lookup.
///
/// Format: txid (32 bytes) + vout (4 bytes big-endian)
fn outpoint_key(outpoint: &OutPoint) -> Vec<u8> {
    let mut key = Vec::with_capacity(36);
    key.extend_from_slice(outpoint.txid.as_bytes());
    key.extend_from_slice(&outpoint.vout.to_be_bytes());
    key
}

// ============================================================
// UTXO VIEW FOR BLOCK STORE
// ============================================================

/// A UTXO view backed by BlockStore with an in-memory cache.
///
/// This implements the `UtxoView` trait from consensus, allowing
/// block validation to work directly with the storage layer.
pub struct BlockStoreUtxoView<'a> {
    store: &'a BlockStore<'a>,
    /// In-memory cache for new UTXOs added during block connection
    cache: std::collections::HashMap<OutPoint, Option<CoinEntry>>,
}

impl<'a> BlockStoreUtxoView<'a> {
    /// Create a new UTXO view backed by the given store.
    pub fn new(store: &'a BlockStore<'a>) -> Self {
        Self {
            store,
            cache: std::collections::HashMap::new(),
        }
    }

    /// Flush all cached changes to the database.
    pub fn flush(&mut self) -> Result<(), StorageError> {
        for (outpoint, coin) in self.cache.drain() {
            match coin {
                Some(c) => self.store.put_utxo(&outpoint, &c)?,
                None => self.store.delete_utxo(&outpoint)?,
            }
        }
        Ok(())
    }
}

/// Import the consensus CoinEntry type for UtxoView trait
pub use rustoshi_consensus::validation::CoinEntry as ConsensusCoinEntry;

impl<'a> rustoshi_consensus::validation::UtxoView for BlockStoreUtxoView<'a> {
    fn get_utxo(&self, outpoint: &OutPoint) -> Option<rustoshi_consensus::validation::CoinEntry> {
        // First check the cache
        if let Some(cached) = self.cache.get(outpoint) {
            return cached.as_ref().map(|c| rustoshi_consensus::validation::CoinEntry {
                height: c.height,
                is_coinbase: c.is_coinbase,
                value: c.value,
                script_pubkey: c.script_pubkey.clone(),
            });
        }

        // Fall back to database
        self.store.get_utxo(outpoint).ok().flatten().map(|c| {
            rustoshi_consensus::validation::CoinEntry {
                height: c.height,
                is_coinbase: c.is_coinbase,
                value: c.value,
                script_pubkey: c.script_pubkey,
            }
        })
    }

    fn add_utxo(&mut self, outpoint: &OutPoint, coin: rustoshi_consensus::validation::CoinEntry) {
        let storage_coin = CoinEntry {
            height: coin.height,
            is_coinbase: coin.is_coinbase,
            value: coin.value,
            script_pubkey: coin.script_pubkey,
        };
        self.cache.insert(outpoint.clone(), Some(storage_coin));
    }

    fn spend_utxo(&mut self, outpoint: &OutPoint) {
        self.cache.insert(outpoint.clone(), None);
    }
}
