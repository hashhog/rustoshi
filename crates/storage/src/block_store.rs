//! Block-level storage operations.
//!
//! This module provides high-level operations for storing and retrieving
//! blocks, headers, UTXOs, and chain metadata.

use crate::columns::*;
use crate::db::{ChainDb, StorageError, META_BEST_BLOCK_HASH, META_BEST_HEIGHT, META_PRUNE_HEIGHT};
use rocksdb::WriteBatch;
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

    /// Borrow the underlying `ChainDb`.
    ///
    /// Exposed so that callers can construct additional index wrappers
    /// (e.g. `BlockFilterIndex::new(block_store.db())`) without having to
    /// thread the `ChainDb` reference through every helper function.
    pub fn db(&self) -> &'a ChainDb {
        self.db
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

    // ---------------- BATCH-FRIENDLY HELPERS (cross-CF atomic writes) ----------------
    //
    // These mirror the per-key public APIs above (put_height_index,
    // delete_height_index, set_best_block) but stage their writes into a
    // caller-provided `rocksdb::WriteBatch` instead of executing them
    // immediately. Combined with `BlockStoreUtxoView::flush_into_batch`
    // they let the disconnect / reorg paths package "UTXO changes + height
    // index updates + new tip pointer" into a single atomic RocksDB write,
    // matching `bitcoin-core/src/validation.cpp::DisconnectTip`'s use of
    // a single `CDBBatch`.
    //
    // A crash partway through a multi-step disconnect previously left
    // height-index entries pointing at disconnected blocks while the UTXO
    // set was already pre-disconnect — see CORE-PARITY-AUDIT
    // `_post-reorg-consistency-fleet-result-2026-05-05.md` (Pattern D).

    /// Stage a height-index put into `batch`.
    ///
    /// No DB write happens until the caller invokes
    /// [`ChainDb::write_batch`]. Returns an error only if the column
    /// family handle is missing (corruption).
    pub fn batch_put_height_index(
        &self,
        batch: &mut WriteBatch,
        height: u32,
        hash: &Hash256,
    ) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_HEIGHT_INDEX).ok_or_else(|| {
            StorageError::Corruption(format!("missing column family: {}", CF_HEIGHT_INDEX))
        })?;
        batch.put_cf(cf, height.to_be_bytes(), hash.as_bytes());
        Ok(())
    }

    /// Stage a height-index delete into `batch`.
    pub fn batch_delete_height_index(
        &self,
        batch: &mut WriteBatch,
        height: u32,
    ) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_HEIGHT_INDEX).ok_or_else(|| {
            StorageError::Corruption(format!("missing column family: {}", CF_HEIGHT_INDEX))
        })?;
        batch.delete_cf(cf, height.to_be_bytes());
        Ok(())
    }

    /// Stage the best-block (tip) pointer write into `batch`.
    ///
    /// Mirrors [`BlockStore::set_best_block`] — writes both
    /// `META_BEST_BLOCK_HASH` and `META_BEST_HEIGHT` so that on commit the
    /// hash + height pair are flipped together.
    pub fn batch_set_best_block(
        &self,
        batch: &mut WriteBatch,
        hash: &Hash256,
        height: u32,
    ) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_META).ok_or_else(|| {
            StorageError::Corruption(format!("missing column family: {}", CF_META))
        })?;
        batch.put_cf(cf, META_BEST_BLOCK_HASH, hash.as_bytes());
        batch.put_cf(cf, META_BEST_HEIGHT, height.to_le_bytes());
        Ok(())
    }

    /// Stage a tx-index delete into `batch` (used during disconnect).
    pub fn batch_delete_tx_index(
        &self,
        batch: &mut WriteBatch,
        txid: &Hash256,
    ) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_TX_INDEX).ok_or_else(|| {
            StorageError::Corruption(format!("missing column family: {}", CF_TX_INDEX))
        })?;
        batch.delete_cf(cf, txid.as_bytes());
        Ok(())
    }

    /// Stage a tx-index put into `batch` (used during reorg-connect).
    ///
    /// Mirrors [`BlockStore::put_tx_index`] but writes into a caller-owned
    /// `WriteBatch` instead of committing immediately. Used by the reorg
    /// path (`try_attach_and_reorg`) so the per-block tx-index entries for
    /// the newly-connected branch flip atomically with the UTXO + tip +
    /// height-index writes — see Pattern D fleet-wide closure
    /// (CORE-PARITY-AUDIT/_post-reorg-consistency-fleet-result-2026-05-05.md).
    pub fn batch_put_tx_index(
        &self,
        batch: &mut WriteBatch,
        txid: &Hash256,
        entry: &TxIndexEntry,
    ) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_TX_INDEX).ok_or_else(|| {
            StorageError::Corruption(format!("missing column family: {}", CF_TX_INDEX))
        })?;
        let data =
            serde_json::to_vec(entry).map_err(|e| StorageError::Serialization(e.to_string()))?;
        batch.put_cf(cf, txid.as_bytes(), &data);
        Ok(())
    }

    /// Apply a previously-built RocksDB write batch.
    ///
    /// Convenience passthrough so callers don't have to reach through to
    /// `self.db` directly when staging cross-CF batches via the
    /// `batch_*` helpers above.
    pub fn write_batch(&self, batch: WriteBatch) -> Result<(), StorageError> {
        self.db.write_batch(batch)
    }

    /// Create a fresh empty `WriteBatch` keyed against this store's DB.
    pub fn new_batch(&self) -> WriteBatch {
        self.db.new_batch()
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

    /// Delete a transaction index entry.
    ///
    /// Used by the disconnect path (Pattern C: revert-on-reorg) so that
    /// `getrawtransaction(<txid>, true)` does not return a stale block hash
    /// after a reorg has disconnected the block that originally contained
    /// the tx. Mirrors `bitcoin-core/src/index/txindex.cpp::CustomRemove`.
    ///
    /// Idempotent — silently succeeds if the entry is absent (matches Core's
    /// `BatchErase` semantics on a key that isn't there).
    pub fn delete_tx_index(&self, txid: &Hash256) -> Result<(), StorageError> {
        self.db.delete_cf(CF_TX_INDEX, txid.as_bytes())
    }

    /// FIX-88 (W121 G27 `getindexinfo`): whether ANY tx_index row exists.
    ///
    /// Used by the `getindexinfo` RPC to detect whether the txindex is
    /// active for this datadir.  Mirrors Bitcoin Core's
    /// `g_txindex != nullptr` check (the global is set iff the operator
    /// enabled `-txindex`).  Since rustoshi has no equivalent global, we
    /// probe by scanning the column family for a single key — RocksDB's
    /// `Start` iterator returns the first key cheaply.
    pub fn has_any_tx_index(&self) -> Result<bool, StorageError> {
        let mut iter = self.db.iter_cf(CF_TX_INDEX)?;
        Ok(iter.next().is_some())
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

    // ============================================================
    // PRUNING (RocksDB-backed)
    // ============================================================
    //
    // rustoshi stores block + undo data as RocksDB key/value entries
    // (CF_BLOCKS, CF_UNDO) rather than in flat blk*.dat files. The
    // `FlatBlockStore` machinery in `blockstore.rs` is only used for
    // legacy / Core-format scanning during reindex paths.
    //
    // Pruning here therefore means deleting the RocksDB key for a block's
    // serialized payload and undo data, and clearing the `HAVE_DATA` /
    // `HAVE_UNDO` flags on the corresponding `BlockIndexEntry` so that
    // chain-management code knows the block is no longer reconstructible
    // from local storage. Mirrors Bitcoin Core's behavior in
    // `bitcoin-core/src/validation.cpp::PruneBlockFilesManual` /
    // `::FindFilesToPrune` / `::UnlinkPrunedFiles` — but at the
    // block-key granularity rather than per file slot.
    //
    // Safety invariants enforced by all helpers below (mirroring Core):
    //   - Never delete data above (tip - MIN_BLOCKS_TO_KEEP) (288 blocks)
    //   - Never delete data above the assumeutxo activation height
    //   - Header + block-index entry are PRESERVED (only the body + undo
    //     are deleted); chain validity / reorg-skeleton is unaffected.

    /// Delete the body + undo for a single block hash and clear the
    /// `HAVE_DATA` / `HAVE_UNDO` flags on the index entry.
    ///
    /// Idempotent — silently succeeds if the body / undo are already
    /// absent (matches RocksDB delete-on-missing semantics).
    ///
    /// Mirrors `bitcoin-core/src/node/blockstorage.cpp::UnlinkPrunedFiles`
    /// at the key-granularity rustoshi uses.
    pub fn prune_block(&self, hash: &Hash256) -> Result<(), StorageError> {
        // Drop block body.
        self.db.delete_cf(CF_BLOCKS, hash.as_bytes())?;
        // Drop undo data.
        self.db.delete_cf(CF_UNDO, hash.as_bytes())?;
        // Clear HAVE_DATA + HAVE_UNDO flags on the index entry, leaving
        // the rest of the entry (height, status, prev_hash, chain_work)
        // intact so reorg / chain-management code still sees the block.
        if let Some(mut entry) = self.get_block_index(hash)? {
            entry.status.clear(BlockStatus::HAVE_DATA);
            entry.status.clear(BlockStatus::HAVE_UNDO);
            self.put_block_index(hash, &entry)?;
        }
        Ok(())
    }

    /// Persist the prune-height watermark.
    ///
    /// Stored as little-endian u32 in `CF_META` under `META_PRUNE_HEIGHT`.
    /// Subsequent reads (`get_prune_height`) return the highest height
    /// at-or-below which we no longer hold full block data.
    pub fn set_prune_height(&self, height: u32) -> Result<(), StorageError> {
        self.db
            .put_cf(CF_META, META_PRUNE_HEIGHT, &height.to_le_bytes())
    }

    /// Read the prune-height watermark, or `0` if pruning never ran.
    pub fn get_prune_height(&self) -> Result<u32, StorageError> {
        match self.db.get_cf(CF_META, META_PRUNE_HEIGHT)? {
            Some(data) => {
                if data.len() != 4 {
                    return Err(StorageError::Corruption(
                        "invalid prune height length".into(),
                    ));
                }
                let mut buf = [0u8; 4];
                buf.copy_from_slice(&data);
                Ok(u32::from_le_bytes(buf))
            }
            None => Ok(0),
        }
    }

    /// Delete the body + undo for every active-chain block in
    /// `[from_height, to_height]` (inclusive on both ends), updating the
    /// prune-height watermark to `max(existing, to_height)` on success.
    ///
    /// Caller is responsible for passing a `to_height` that respects
    /// MIN_BLOCKS_TO_KEEP and any assumeutxo floor; this method does not
    /// re-validate those invariants (that's done in `auto_prune` /
    /// `manual_prune_to_height`).
    ///
    /// Returns the number of blocks actually pruned (height entries that
    /// resolved to a hash AND had a non-empty body to drop).
    pub fn prune_active_chain_range(
        &self,
        from_height: u32,
        to_height: u32,
    ) -> Result<u32, StorageError> {
        if from_height > to_height {
            return Ok(0);
        }
        let mut pruned = 0u32;
        for h in from_height..=to_height {
            // Resolve height -> hash on the active chain only. Off-chain
            // / orphan branches are ignored (they're cleaned up via
            // reorg disconnect, not prune).
            let Some(hash) = self.get_hash_by_height(h)? else {
                continue;
            };
            // Skip the genesis block — Core never prunes height 0
            // (`bitcoin-core/src/node/blockstorage.cpp::FindFilesToPrune`
            // starts at file 0 but the genesis is loaded from chainparams,
            // not from disk; deleting it would break first-run init).
            if h == 0 {
                continue;
            }
            self.prune_block(&hash)?;
            pruned += 1;
        }
        // Watermark advances monotonically so subsequent prune passes
        // don't re-walk blocks we already deleted.
        let prev = self.get_prune_height()?;
        if to_height > prev {
            self.set_prune_height(to_height)?;
        }
        Ok(pruned)
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

/// Default UTXO cache memory limit: 2 GiB.
pub const DEFAULT_UTXO_CACHE_BYTES: usize = 2 * 1024 * 1024 * 1024;

/// Estimated per-entry overhead in the HashMap.
/// OutPoint (36 bytes) + Option<CoinEntry> header (8) + CoinEntry fields (8+1+8 = 17)
/// + HashMap node overhead (~80 bytes on 64-bit with hash + pointers)
/// + average scriptPubKey (~34 bytes for P2WSH/P2TR)
const CACHE_ENTRY_OVERHEAD: usize = 180;

/// A UTXO view backed by BlockStore with an in-memory cache.
///
/// This implements the `UtxoView` trait from consensus, allowing
/// block validation to work directly with the storage layer.
///
/// The cache is bounded by `max_cache_bytes`. When the estimated memory
/// usage exceeds this limit, `flush_if_needed()` writes all dirty entries
/// to RocksDB and clears the cache.
pub struct BlockStoreUtxoView<'a> {
    store: &'a BlockStore<'a>,
    /// In-memory cache for new UTXOs added during block connection
    cache: std::collections::HashMap<OutPoint, Option<CoinEntry>>,
    /// Estimated memory usage of cached entries (bytes).
    estimated_mem: usize,
    /// Maximum cache size in bytes before triggering a flush.
    max_cache_bytes: usize,
}

impl<'a> BlockStoreUtxoView<'a> {
    /// Create a new UTXO view backed by the given store.
    pub fn new(store: &'a BlockStore<'a>) -> Self {
        Self::with_cache_limit(store, DEFAULT_UTXO_CACHE_BYTES)
    }

    /// Create a new UTXO view with a custom cache byte limit.
    pub fn with_cache_limit(store: &'a BlockStore<'a>, max_cache_bytes: usize) -> Self {
        Self {
            store,
            cache: std::collections::HashMap::new(),
            estimated_mem: 0,
            max_cache_bytes,
        }
    }

    /// Estimated memory usage of the cache in bytes.
    pub fn estimated_memory(&self) -> usize {
        self.estimated_mem
    }

    /// Number of entries in the cache.
    pub fn cache_len(&self) -> usize {
        self.cache.len()
    }

    /// Returns true if the cache has exceeded its memory limit.
    pub fn needs_flush(&self) -> bool {
        self.estimated_mem >= self.max_cache_bytes
    }

    /// Flush all cached changes to the database using a WriteBatch.
    pub fn flush(&mut self) -> Result<(), StorageError> {
        if self.cache.is_empty() {
            return Ok(());
        }
        let mut batch = self.store.db.new_batch();
        self.flush_into_batch(&mut batch)?;
        self.store.db.write_batch(batch)?;
        Ok(())
    }

    /// Stage all cached UTXO changes into the caller-provided WriteBatch.
    ///
    /// Drains the cache (resetting `estimated_mem`) but does NOT execute
    /// the batch — the caller is responsible for committing it via
    /// [`ChainDb::write_batch`] (or [`BlockStore::write_batch`]). This is
    /// the building block for atomic cross-CF commits in the disconnect
    /// and reorg paths, where height-index updates + new tip pointer
    /// must land in the same RocksDB write as the UTXO mutations to
    /// avoid the Pattern D crash window
    /// (CORE-PARITY-AUDIT/_post-reorg-consistency-fleet-result-2026-05-05.md).
    ///
    /// Mirrors `bitcoin-core/src/validation.cpp::DisconnectTip` —
    /// Core flushes its `CCoinsViewCache` into a single `CDBBatch` that
    /// also carries the `BlockTreeDB` index updates, then commits once.
    pub fn flush_into_batch(&mut self, batch: &mut WriteBatch) -> Result<(), StorageError> {
        if self.cache.is_empty() {
            return Ok(());
        }
        let cf = self
            .store
            .db
            .cf_handle(CF_UTXO)
            .ok_or_else(|| StorageError::Corruption("missing UTXO column family".into()))?;
        for (outpoint, coin) in self.cache.drain() {
            let key = outpoint_key(&outpoint);
            match coin {
                Some(c) => {
                    let data = serde_json::to_vec(&c)
                        .map_err(|e| StorageError::Serialization(e.to_string()))?;
                    batch.put_cf(cf, &key, &data);
                }
                None => {
                    batch.delete_cf(cf, &key);
                }
            }
        }
        self.estimated_mem = 0;
        Ok(())
    }

    /// Flush to disk if the cache exceeds its memory limit.
    /// Returns the number of entries flushed, or 0 if no flush was needed.
    pub fn flush_if_needed(&mut self) -> Result<usize, StorageError> {
        if self.needs_flush() {
            let count = self.cache.len();
            self.flush()?;
            Ok(count)
        } else {
            Ok(0)
        }
    }

    fn estimate_entry_size(coin: &Option<CoinEntry>) -> usize {
        CACHE_ENTRY_OVERHEAD
            + coin
                .as_ref()
                .map(|c| c.script_pubkey.len())
                .unwrap_or(0)
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
        let new_size = Self::estimate_entry_size(&Some(storage_coin.clone()));
        if let Some(old) = self.cache.insert(outpoint.clone(), Some(storage_coin)) {
            // Replace: subtract old, add new
            let old_size = Self::estimate_entry_size(&old);
            self.estimated_mem = self.estimated_mem.saturating_sub(old_size) + new_size;
        } else {
            self.estimated_mem += new_size;
        }
    }

    fn spend_utxo(&mut self, outpoint: &OutPoint) {
        let new_size = Self::estimate_entry_size(&None);
        if let Some(old) = self.cache.insert(outpoint.clone(), None) {
            let old_size = Self::estimate_entry_size(&old);
            self.estimated_mem = self.estimated_mem.saturating_sub(old_size) + new_size;
        } else {
            self.estimated_mem += new_size;
        }
    }
}
