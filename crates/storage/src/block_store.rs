//! Block-level storage operations.
//!
//! This module provides high-level operations for storing and retrieving
//! blocks, headers, UTXOs, and chain metadata.

use crate::columns::*;
use crate::db::{
    ChainDb, StorageError, META_BEST_BLOCK_HASH, META_BEST_HEIGHT, META_PRUNE_HEIGHT,
    META_REORG_PRUNE_HEIGHT,
};
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

    /// Construct from a raw flags value (used by the binary on-disk
    /// decoder in `format_v2::decode_block_index_entry`).
    pub fn from_raw(raw: u32) -> Self {
        Self(raw)
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
        let data = format_v2::encode_block_index_entry(entry);
        self.db.put_cf(CF_BLOCK_INDEX, hash.as_bytes(), &data)
    }

    /// Retrieve a block index entry by hash.
    pub fn get_block_index(&self, hash: &Hash256) -> Result<Option<BlockIndexEntry>, StorageError> {
        match self.db.get_cf(CF_BLOCK_INDEX, hash.as_bytes())? {
            Some(data) => Ok(Some(format_v2::decode_block_index_entry(&data)?)),
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
        let data = format_v2::encode_tx_index_entry(entry);
        batch.put_cf(cf, txid.as_bytes(), &data);
        Ok(())
    }

    /// Stage a block-undo put into `batch`.
    ///
    /// Mirrors [`BlockStore::put_undo`] but writes into a caller-owned
    /// `WriteBatch`. Used by the reorg path (`try_attach_and_reorg`) so the
    /// per-block undo data for the newly-connected branch flips atomically
    /// with the UTXO + tip + height-index + tx-index writes. Bitcoin Core
    /// writes block undo on every `ConnectBlock` (reorg connects included);
    /// without this the new-branch blocks had no undo on disk, so a later
    /// reorg back across them would fail with "missing undo data".
    pub fn batch_put_undo(
        &self,
        batch: &mut WriteBatch,
        hash: &Hash256,
        undo: &UndoData,
    ) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_UNDO).ok_or_else(|| {
            StorageError::Corruption(format!("missing column family: {}", CF_UNDO))
        })?;
        let data = format_v2::encode_undo_data(undo);
        batch.put_cf(cf, hash.as_bytes(), &data);
        Ok(())
    }

    /// Stage a full-block body put into `batch`.
    ///
    /// Mirrors [`BlockStore::put_block`] but writes into a caller-owned
    /// `WriteBatch`. Used by the linear P2P/IBD connect path (Unit B) to
    /// persist the block body for the reorg-retention window in the SAME
    /// atomic batch as the UTXO mutations + tip pointer, so the persisted
    /// tip can never name a height whose block body is not yet durable.
    /// Bitcoin Core writes the block to disk (`SaveBlockToDisk`) before it
    /// advances the chain tip in `ConnectTip`; staging the body in the
    /// same `WriteBatch` as `DB_BEST_BLOCK` is the rustoshi equivalent.
    pub fn batch_put_block(
        &self,
        batch: &mut WriteBatch,
        hash: &Hash256,
        block: &Block,
    ) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_BLOCKS).ok_or_else(|| {
            StorageError::Corruption(format!("missing column family: {}", CF_BLOCKS))
        })?;
        let data = block.serialize();
        batch.put_cf(cf, hash.as_bytes(), &data);
        Ok(())
    }

    /// Stage deletes of a block's body + undo into `batch` (retention prune).
    ///
    /// Used by the connect path's reorg-retention pruner (Unit B): once a
    /// block is buried deeper than the reorg window it can never be needed
    /// to disconnect, so its body + undo are dropped to avoid the
    /// ~500 GB full-archive footprint. Unlike [`BlockStore::prune_block`]
    /// this does NOT clear the `HAVE_DATA`/`HAVE_UNDO` index flags or touch
    /// the prune-height watermark — the reorg-retention prune is an
    /// internal storage-economy operation distinct from BIP-159 manual /
    /// auto pruning, and the block stays fully "have data" from the chain
    /// manager's point of view at the heights where it still matters.
    /// Staged into the SAME batch as the tip advance so a crash can never
    /// observe the body deleted while the tip still references it.
    ///
    /// Idempotent — RocksDB deletes on a missing key are no-ops.
    pub fn batch_prune_block_body(
        &self,
        batch: &mut WriteBatch,
        hash: &Hash256,
    ) -> Result<(), StorageError> {
        let blocks_cf = self.db.cf_handle(CF_BLOCKS).ok_or_else(|| {
            StorageError::Corruption(format!("missing column family: {}", CF_BLOCKS))
        })?;
        let undo_cf = self.db.cf_handle(CF_UNDO).ok_or_else(|| {
            StorageError::Corruption(format!("missing column family: {}", CF_UNDO))
        })?;
        batch.delete_cf(blocks_cf, hash.as_bytes());
        batch.delete_cf(undo_cf, hash.as_bytes());
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
        let data = format_v2::encode_coin_entry(coin);
        self.db.put_cf(CF_UTXO, &key, &data)
    }

    /// Retrieve a UTXO entry.
    pub fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<CoinEntry>, StorageError> {
        let key = outpoint_key(outpoint);
        match self.db.get_cf(CF_UTXO, &key)? {
            Some(data) => Ok(Some(format_v2::decode_coin_entry(&data)?)),
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
        let data = format_v2::encode_undo_data(undo);
        self.db.put_cf(CF_UNDO, hash.as_bytes(), &data)
    }

    /// Retrieve undo data for a block.
    pub fn get_undo(&self, hash: &Hash256) -> Result<Option<UndoData>, StorageError> {
        match self.db.get_cf(CF_UNDO, hash.as_bytes())? {
            Some(data) => Ok(Some(format_v2::decode_undo_data(&data)?)),
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
        let data = format_v2::encode_tx_index_entry(entry);
        self.db.put_cf(CF_TX_INDEX, txid.as_bytes(), &data)
    }

    /// Retrieve a transaction index entry.
    pub fn get_tx_index(&self, txid: &Hash256) -> Result<Option<TxIndexEntry>, StorageError> {
        match self.db.get_cf(CF_TX_INDEX, txid.as_bytes())? {
            Some(data) => Ok(Some(format_v2::decode_tx_index_entry(&data)?)),
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

    /// Create a UTXO view with an explicit coins-cache budget in bytes
    /// (Bitcoin Core `-dbcache`). A larger budget keeps more of the hot UTXO
    /// working set in RAM, cutting the per-input chainstate disk reads that
    /// dominate the block-connect path during IBD.
    pub fn utxo_view_with_cache(&self, max_cache_bytes: usize) -> BlockStoreUtxoView<'_> {
        BlockStoreUtxoView::with_cache_limit(self, max_cache_bytes)
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

            let entry = format_v2::decode_block_index_entry(&value).ok()?;
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
            // Bitcoin Core (chain.cpp, CBlockIndex::nChainWork =
            // (pprev ? pprev->nChainWork : 0) + GetBlockProof(*this)) counts the
            // genesis block's OWN proof-of-work in its nChainWork, even though it
            // has no parent. Storing 0 here left every descendant's accumulated
            // chainwork short by exactly one block-proof (e.g. getblockheader at
            // height N returned N block-proofs instead of N+1), diverging from
            // Core's `chainwork` field. Seed genesis with GetBlockProof(genesis).
            chain_work: rustoshi_consensus::pow::get_block_proof(genesis.header.bits).0,
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

    /// Read the reorg-retention prune watermark (Unit B), or `None` if it
    /// has never been written (a pre-Unit-B datadir, or a fresh one).
    ///
    /// The watermark is the highest active-chain height whose body + undo
    /// have been dropped by the reorg-retention pruner. `None` (rather than
    /// `0`) is returned for the missing-key case so the caller can tell
    /// "never pruned, seed at the current floor" apart from "watermark is
    /// genuinely at height 0" — a backward-compatibility distinction that a
    /// `0` sentinel could not express.
    ///
    /// Distinct from [`get_prune_height`] (BIP-159 manual/auto prune) — the
    /// two watermarks live under different `CF_META` keys and never collide.
    pub fn get_reorg_prune_height(&self) -> Result<Option<u32>, StorageError> {
        match self.db.get_cf(CF_META, META_REORG_PRUNE_HEIGHT)? {
            Some(data) => {
                if data.len() != 4 {
                    return Err(StorageError::Corruption(
                        "invalid reorg prune height length".into(),
                    ));
                }
                let mut buf = [0u8; 4];
                buf.copy_from_slice(&data);
                Ok(Some(u32::from_le_bytes(buf)))
            }
            None => Ok(None),
        }
    }

    /// Persist the reorg-retention prune watermark (Unit B).
    ///
    /// Stored as little-endian u32 in `CF_META` under
    /// `META_REORG_PRUNE_HEIGHT`. Normally staged into the same atomic
    /// batch as the body/undo deletes via
    /// [`BlockStore::batch_set_reorg_prune_height`]; this immediate variant
    /// exists for symmetry / tests.
    pub fn set_reorg_prune_height(&self, height: u32) -> Result<(), StorageError> {
        self.db
            .put_cf(CF_META, META_REORG_PRUNE_HEIGHT, &height.to_le_bytes())
    }

    /// Stage the reorg-retention prune watermark write into `batch`.
    ///
    /// Lets the connect-path flush flip the watermark in the SAME atomic
    /// `WriteBatch` as the body/undo deletes + coins + tip, so a crash can
    /// never leave the watermark advanced past bodies that are still on
    /// disk (or vice-versa — bodies deleted but the watermark not advanced,
    /// which would simply re-delete them harmlessly on the next flush).
    pub fn batch_set_reorg_prune_height(
        &self,
        batch: &mut WriteBatch,
        height: u32,
    ) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_META).ok_or_else(|| {
            StorageError::Corruption(format!("missing column family: {}", CF_META))
        })?;
        batch.put_cf(cf, META_REORG_PRUNE_HEIGHT, height.to_le_bytes());
        Ok(())
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

/// Re-export of the v2 binary `CoinEntry` codec for crate-local callers
/// (`utxo_cache::CoinsViewDB`) that need to read/write coins without
/// going through `BlockStore::put_utxo` / `get_utxo`. Kept narrow on
/// purpose — outside the storage crate, callers should use the
/// `BlockStore` API and stay format-agnostic.
pub(crate) mod coin_entry_format_v2 {
    pub use super::format_v2::{decode_coin_entry, encode_coin_entry};
}

/// Decode a raw `CF_UTXO` value bytes into a `CoinEntry`.
///
/// Public escape hatch for downstream crates (`rustoshi-rpc`'s
/// `dumptxoutset` + `gettxoutsetinfo`) that need to iterate the UTXO
/// column family directly via `ChainDb::iter_cf(CF_UTXO)` for
/// streaming reasons rather than going through `BlockStore::get_utxo`
/// per key. Wraps the private `format_v2::decode_coin_entry` so the
/// on-disk encoding stays a single source of truth.
///
/// Callers that already hold an `OutPoint` should prefer
/// `BlockStore::get_utxo` — it stays format-agnostic and uses the
/// same decoder internally.
pub fn decode_utxo_value(data: &[u8]) -> Result<CoinEntry, StorageError> {
    format_v2::decode_coin_entry(data)
}

// ============================================================
// FORMAT v2 — BINARY ENCODERS FOR CF_UTXO / CF_BLOCK_INDEX /
// CF_UNDO / CF_TX_INDEX VALUES
// ============================================================
//
// Previously these values were stored via `serde_json::to_vec`, which
// was a ~5-10× perf cost vs binary AND ~4× larger on disk (RocksDB
// then had to compact the bloated SSTs). At h=367k that meant a
// `flush_with_tip` of 11M CoinEntry values cost ~87 min instead of
// ~10-15 min.
//
// The encoding is hand-rolled rather than `bincode` / `borsh` /
// `postcard` to (a) avoid pulling in a new dependency for what's a
// handful of types, (b) match the existing wire-format style in
// `crates/primitives/src/serialize.rs` (CompactSize + LE primitives),
// and (c) keep the format inspectable for forensic recovery work.
//
// Format is gated by `db::CURRENT_DB_VERSION`; bumping that constant
// invalidates this encoding and forces a re-IBD via the version-check
// in `ChainDb::check_and_init_version`.
//
// The encoders panic on `Vec` writes (which `io::Write` for `Vec` can
// never fail on); the decoders surface short / malformed input as
// `StorageError::Serialization`.
pub(crate) mod format_v2 {
    use super::{
        BlockIndexEntry, BlockStatus, CoinEntry, Hash256, StorageError, TxIndexEntry, UndoData,
    };
    use rustoshi_primitives::{compact_size_len, read_compact_size, write_compact_size};
    use std::io::{Cursor, Read};

    // -------- CoinEntry --------
    //
    // height       u32 LE        (4 bytes)
    // flags        u8            (1 byte; bit 0 = is_coinbase)
    // value        u64 LE        (8 bytes)
    // script_pk    CompactSize len + bytes
    //
    // Fixed prefix is 13 bytes; total for a typical 25-byte P2PKH
    // scriptPubKey: 13 + 1 + 25 = 39 bytes (vs ~140-180 for JSON).

    const COIN_ENTRY_FIXED_PREFIX: usize = 4 + 1 + 8;

    pub fn coin_entry_size(coin: &CoinEntry) -> usize {
        COIN_ENTRY_FIXED_PREFIX
            + compact_size_len(coin.script_pubkey.len() as u64)
            + coin.script_pubkey.len()
    }

    pub fn encode_coin_entry(coin: &CoinEntry) -> Vec<u8> {
        let mut buf = Vec::with_capacity(coin_entry_size(coin));
        buf.extend_from_slice(&coin.height.to_le_bytes());
        let flags: u8 = if coin.is_coinbase { 1 } else { 0 };
        buf.push(flags);
        buf.extend_from_slice(&coin.value.to_le_bytes());
        write_compact_size(&mut buf, coin.script_pubkey.len() as u64)
            .expect("Vec writes never fail");
        buf.extend_from_slice(&coin.script_pubkey);
        buf
    }

    pub fn decode_coin_entry(data: &[u8]) -> Result<CoinEntry, StorageError> {
        let mut cursor = Cursor::new(data);
        decode_coin_entry_from(&mut cursor)
    }

    fn decode_coin_entry_from<R: Read>(reader: &mut R) -> Result<CoinEntry, StorageError> {
        let mut u32_buf = [0u8; 4];
        reader.read_exact(&mut u32_buf).map_err(io_err)?;
        let height = u32::from_le_bytes(u32_buf);

        let mut flag_buf = [0u8; 1];
        reader.read_exact(&mut flag_buf).map_err(io_err)?;
        // Reject unknown flag bits so an accidental v1→v2 read of a
        // JSON byte (which starts with `{` = 0x7B) gets rejected
        // *immediately* rather than producing a plausible-looking
        // CoinEntry with garbage values.
        if flag_buf[0] & !0x01 != 0 {
            return Err(StorageError::Serialization(format!(
                "CoinEntry: unknown flag bits 0x{:02x} (only bit 0 is defined)",
                flag_buf[0]
            )));
        }
        let is_coinbase = flag_buf[0] & 0x01 != 0;

        let mut u64_buf = [0u8; 8];
        reader.read_exact(&mut u64_buf).map_err(io_err)?;
        let value = u64::from_le_bytes(u64_buf);

        let script_len = read_compact_size(reader).map_err(io_err)? as usize;
        // 10 MiB cap on a single scriptPubKey; mainnet maxes out at
        // ~10 KB so this is hugely generous and just stops a corrupted
        // varint from triggering a multi-GB allocation.
        if script_len > 10 * 1024 * 1024 {
            return Err(StorageError::Serialization(format!(
                "CoinEntry: scriptPubKey length {} exceeds 10 MiB cap",
                script_len
            )));
        }
        let mut script_pubkey = vec![0u8; script_len];
        reader.read_exact(&mut script_pubkey).map_err(io_err)?;

        Ok(CoinEntry {
            height,
            is_coinbase,
            value,
            script_pubkey,
        })
    }

    // -------- BlockIndexEntry --------
    //
    // Fixed 92 bytes (no variable-length fields):
    //   height     u32 LE   (4)
    //   status     u32 LE   (4)
    //   n_tx       u32 LE   (4)
    //   timestamp  u32 LE   (4)
    //   bits       u32 LE   (4)
    //   nonce      u32 LE   (4)
    //   version    i32 LE   (4)
    //   prev_hash  [u8; 32] (32)
    //   chain_work [u8; 32] (32)

    pub const BLOCK_INDEX_ENTRY_SIZE: usize = 4 * 7 + 32 + 32;

    pub fn encode_block_index_entry(entry: &BlockIndexEntry) -> Vec<u8> {
        let mut buf = Vec::with_capacity(BLOCK_INDEX_ENTRY_SIZE);
        buf.extend_from_slice(&entry.height.to_le_bytes());
        buf.extend_from_slice(&entry.status.raw().to_le_bytes());
        buf.extend_from_slice(&entry.n_tx.to_le_bytes());
        buf.extend_from_slice(&entry.timestamp.to_le_bytes());
        buf.extend_from_slice(&entry.bits.to_le_bytes());
        buf.extend_from_slice(&entry.nonce.to_le_bytes());
        buf.extend_from_slice(&entry.version.to_le_bytes());
        buf.extend_from_slice(entry.prev_hash.as_bytes());
        buf.extend_from_slice(&entry.chain_work);
        debug_assert_eq!(buf.len(), BLOCK_INDEX_ENTRY_SIZE);
        buf
    }

    pub fn decode_block_index_entry(data: &[u8]) -> Result<BlockIndexEntry, StorageError> {
        if data.len() != BLOCK_INDEX_ENTRY_SIZE {
            return Err(StorageError::Serialization(format!(
                "BlockIndexEntry: expected {} bytes, got {}",
                BLOCK_INDEX_ENTRY_SIZE,
                data.len()
            )));
        }
        // Avoid Cursor / read_exact overhead — every byte offset is fixed.
        let mut u32_buf = [0u8; 4];
        let mut i32_buf = [0u8; 4];
        let mut hash_buf = [0u8; 32];

        u32_buf.copy_from_slice(&data[0..4]);
        let height = u32::from_le_bytes(u32_buf);
        u32_buf.copy_from_slice(&data[4..8]);
        let status_raw = u32::from_le_bytes(u32_buf);
        u32_buf.copy_from_slice(&data[8..12]);
        let n_tx = u32::from_le_bytes(u32_buf);
        u32_buf.copy_from_slice(&data[12..16]);
        let timestamp = u32::from_le_bytes(u32_buf);
        u32_buf.copy_from_slice(&data[16..20]);
        let bits = u32::from_le_bytes(u32_buf);
        u32_buf.copy_from_slice(&data[20..24]);
        let nonce = u32::from_le_bytes(u32_buf);
        i32_buf.copy_from_slice(&data[24..28]);
        let version = i32::from_le_bytes(i32_buf);
        hash_buf.copy_from_slice(&data[28..60]);
        let prev_hash = Hash256(hash_buf);
        let mut chain_work = [0u8; 32];
        chain_work.copy_from_slice(&data[60..92]);

        Ok(BlockIndexEntry {
            height,
            status: BlockStatus::from_raw(status_raw),
            n_tx,
            timestamp,
            bits,
            nonce,
            version,
            prev_hash,
            chain_work,
        })
    }

    // -------- UndoData --------
    //
    // compact_size(spent_coins.len())
    // [each]: encode_coin_entry(coin)

    pub fn encode_undo_data(undo: &UndoData) -> Vec<u8> {
        let n = undo.spent_coins.len();
        let coins_size: usize = undo.spent_coins.iter().map(coin_entry_size).sum();
        let mut buf = Vec::with_capacity(compact_size_len(n as u64) + coins_size);
        write_compact_size(&mut buf, n as u64).expect("Vec writes never fail");
        for coin in &undo.spent_coins {
            buf.extend_from_slice(&encode_coin_entry(coin));
        }
        buf
    }

    pub fn decode_undo_data(data: &[u8]) -> Result<UndoData, StorageError> {
        let mut cursor = Cursor::new(data);
        let n = read_compact_size(&mut cursor).map_err(io_err)? as usize;
        // 10M coins per block is far above any plausible Bitcoin block
        // (~4M weight units / 100 wu per input = ~40k inputs hard cap).
        if n > 10_000_000 {
            return Err(StorageError::Serialization(format!(
                "UndoData: implausible spent_coins length {}",
                n
            )));
        }
        let mut spent_coins = Vec::with_capacity(n);
        for _ in 0..n {
            spent_coins.push(decode_coin_entry_from(&mut cursor)?);
        }
        Ok(UndoData { spent_coins })
    }

    // -------- TxIndexEntry --------
    //
    // Fixed 40 bytes:
    //   block_hash [u8; 32]
    //   tx_offset  u32 LE
    //   tx_length  u32 LE

    pub const TX_INDEX_ENTRY_SIZE: usize = 32 + 4 + 4;

    pub fn encode_tx_index_entry(entry: &TxIndexEntry) -> Vec<u8> {
        let mut buf = Vec::with_capacity(TX_INDEX_ENTRY_SIZE);
        buf.extend_from_slice(entry.block_hash.as_bytes());
        buf.extend_from_slice(&entry.tx_offset.to_le_bytes());
        buf.extend_from_slice(&entry.tx_length.to_le_bytes());
        debug_assert_eq!(buf.len(), TX_INDEX_ENTRY_SIZE);
        buf
    }

    pub fn decode_tx_index_entry(data: &[u8]) -> Result<TxIndexEntry, StorageError> {
        if data.len() != TX_INDEX_ENTRY_SIZE {
            return Err(StorageError::Serialization(format!(
                "TxIndexEntry: expected {} bytes, got {}",
                TX_INDEX_ENTRY_SIZE,
                data.len()
            )));
        }
        let mut hash_buf = [0u8; 32];
        hash_buf.copy_from_slice(&data[0..32]);
        let mut u32_buf = [0u8; 4];
        u32_buf.copy_from_slice(&data[32..36]);
        let tx_offset = u32::from_le_bytes(u32_buf);
        u32_buf.copy_from_slice(&data[36..40]);
        let tx_length = u32::from_le_bytes(u32_buf);
        Ok(TxIndexEntry {
            block_hash: Hash256(hash_buf),
            tx_offset,
            tx_length,
        })
    }

    fn io_err(e: std::io::Error) -> StorageError {
        StorageError::Serialization(e.to_string())
    }
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

/// Coin cache fullness signal, mirrored from Bitcoin Core's
/// `CoinsCacheSizeState` (`bitcoin-core/src/validation.h:509-516`).
///
/// The connect loop uses this to schedule flushes ahead of the hard
/// memory cap, avoiding the per-block-flush pathology that occurred on
/// mainnet 2026-05-27 (cache crossed 2 GiB at h=364k and every flush
/// from then on cost the full ~11 M-entry batch — 43-87 min each).
/// See `CORE-PARITY-AUDIT/_rustoshi-ibd-pace-decay-2026-05-27.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum UtxoCacheState {
    /// Cache is below the LARGE threshold — no flush needed.
    Ok = 0,
    /// Cache is within ~10 % of the cap — flush opportunistically
    /// on the next PERIODIC tick or block-count boundary so we never
    /// reach the CRITICAL "must-flush-every-block" state.
    Large = 1,
    /// Cache has exceeded the hard memory cap — MUST flush before
    /// connecting the next block, otherwise heap blows past
    /// `max_cache_bytes`.
    Critical = 2,
}

/// Threshold above which Core considers the coins cache "LARGE" and
/// starts flushing on PERIODIC ticks (validation.h:518-524 —
/// `max(total*9/10, total - 10 MiB)`).
///
/// Returning a `usize` for direct comparison with `estimated_mem`.
/// Uses `u128` for the `*9/10` factor to avoid both overflow on the
/// 2 GiB-default cap on 32-bit targets and the early-truncation
/// rounding error that `(total / 10) * 9` introduces.
fn large_coins_cache_threshold(total_space: usize) -> usize {
    const MAX_BLOCK_COINSDB_USAGE_BYTES: usize = 10 * 1024 * 1024;
    let nine_tenths = ((total_space as u128) * 9 / 10) as usize;
    let minus_block = total_space.saturating_sub(MAX_BLOCK_COINSDB_USAGE_BYTES);
    nine_tenths.max(minus_block)
}

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
    ///
    /// At this point the connect loop MUST flush before connecting
    /// the next block (Core's `CoinsCacheSizeState::CRITICAL`
    /// gating `FlushStateMode::IF_NEEDED`).
    pub fn needs_flush(&self) -> bool {
        self.estimated_mem >= self.max_cache_bytes
    }

    /// Returns the cache's fullness state (`Ok` / `Large` / `Critical`).
    ///
    /// Mirrors `Chainstate::GetCoinsCacheSizeState` in
    /// `bitcoin-core/src/validation.cpp:2683-2700`. The connect loop
    /// uses `Large` as an early-warning signal: it triggers a flush on
    /// the next block-count or time boundary, well before
    /// `Critical` forces a per-block flush of the full cache.
    pub fn cache_state(&self) -> UtxoCacheState {
        if self.estimated_mem > self.max_cache_bytes {
            UtxoCacheState::Critical
        } else if self.estimated_mem > large_coins_cache_threshold(self.max_cache_bytes) {
            UtxoCacheState::Large
        } else {
            UtxoCacheState::Ok
        }
    }

    /// The number of bytes above which `cache_state()` returns
    /// `Large`. Exposed for diagnostics/logging.
    pub fn large_threshold_bytes(&self) -> usize {
        large_coins_cache_threshold(self.max_cache_bytes)
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
                    let data = format_v2::encode_coin_entry(&c);
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

    /// Atomically flush all cached UTXO changes AND advance the persisted
    /// best-block (tip) pointer to `(hash, height)` in a single RocksDB
    /// `WriteBatch`.
    ///
    /// This is the durability-safe replacement for the broken
    /// "`set_best_block` eagerly per block + `flush()` lazily at 2 GiB"
    /// pattern.  The two writes MUST land together: if the persisted tip
    /// pointer is allowed to advance ahead of the durable UTXO set, a
    /// process kill (SIGKILL / OOM / crash) between the eager tip write
    /// and the next lazy flush leaves the node permanently wedged — on
    /// restart it loads the advanced tip, requests the next block, and
    /// every connect fails `MissingInput` because the coins created by
    /// the un-flushed blocks were never written to disk.
    ///
    /// This is precisely the bug that froze rustoshi mainnet at height
    /// 948,304 on 2026-05-07: the node was SIGKILLed after connecting
    /// block 948,304 (tip pointer persisted) but before any 2 GiB flush,
    /// so the UTXO created by tx `d57c33d0…29a0` in block 948,293 was
    /// lost, and block 948,305 could never connect.
    ///
    /// Mirrors Bitcoin Core `CCoinsViewDB::BatchWrite`
    /// (`bitcoin-core/src/txdb.cpp`): the `DB_BEST_BLOCK` key is written
    /// in the SAME `CDBBatch` as the coin mutations and is never advanced
    /// independently — Core asserts `!hashBlock.IsNull()` to enforce that
    /// the best block is only ever set together with coins.
    ///
    /// The caller is responsible for ensuring `(hash, height)` is the tip
    /// AT OR BELOW which every cached coin mutation belongs (i.e. flush
    /// only on a block boundary after `process_block` succeeded).
    pub fn flush_with_tip(
        &mut self,
        hash: &Hash256,
        height: u32,
    ) -> Result<(), StorageError> {
        let mut batch = self.store.db.new_batch();
        // Stage all cached UTXO mutations (drains the cache, resets mem).
        self.flush_into_batch(&mut batch)?;
        // Stage the tip pointer into the SAME batch so it can never be
        // durable without its coins.
        self.store.batch_set_best_block(&mut batch, hash, height)?;
        self.store.db.write_batch(batch)?;
        Ok(())
    }

    /// Atomic UTXO + tip flush that ALSO persists the block bodies + undo
    /// for the connected blocks accumulated since the last flush, and
    /// prunes block bodies/undo that have fallen out of the reorg-retention
    /// window — all in ONE RocksDB `WriteBatch` (Unit B).
    ///
    /// This is the linear-connect-path analogue of the atomic reorg commit
    /// in `try_attach_and_reorg` (`crates/rpc/src/server.rs`): block body +
    /// undo + UTXO + tip flip together so `chain_state.reorganize()` can
    /// ALWAYS find the body + undo for any block at or below the persisted
    /// tip and within the retention window — which is exactly what the live
    /// P2P/IBD path previously failed to guarantee (it wrote only
    /// `put_header` + `put_block_index`, never `put_block`/`put_undo`, so a
    /// reorg arriving over P2P failed at "missing undo data for disconnect").
    ///
    /// Atomicity invariant (mirrors Bitcoin Core `CCoinsViewDB::BatchWrite`
    /// + `ConnectTip`'s "write block before advancing tip"): the tip pointer
    /// is staged into the SAME batch as the block bodies, undo, and coins,
    /// so a SIGKILL/OOM/crash mid-commit either leaves EVERYTHING durable or
    /// NOTHING — the tip never names a block whose body/undo or coins are
    /// missing.
    ///
    /// * `tip_hash` / `tip_height` — the new persisted tip (the highest
    ///   block in `pending`).
    /// * `pending` — `(hash, block, undo)` for every block connected since
    ///   the previous flush, in ascending height order. The body + undo for
    ///   each is staged. May be empty (e.g. a time-only flush with no new
    ///   blocks), in which case only coins + tip are committed.
    /// * `prune_below_height` — bodies/undo for active-chain blocks at
    ///   heights `< prune_below_height` are dropped (retention prune). Pass
    ///   `0` to disable pruning for this flush. The caller supplies the
    ///   list of `(height, hash)` to prune via `prune_targets` so this
    ///   method performs no chain walk of its own.
    /// * `prune_targets` — `(height, hash)` pairs whose bodies/undo should
    ///   be deleted this flush. The caller is responsible for only passing
    ///   active-chain hashes strictly below the retention floor (and never
    ///   genesis); this method just stages the deletes.
    /// * `prune_watermark` — when `Some(h)`, advances the persisted
    ///   reorg-retention prune watermark (`META_REORG_PRUNE_HEIGHT`) to `h`
    ///   in the SAME atomic batch as the body/undo deletes. This is what
    ///   makes the prune O(1)-amortized and cadence-independent: the caller
    ///   passes `floor - 1` (the highest height it has just guaranteed is
    ///   pruned-or-genesis), and the next flush resumes the contiguous
    ///   sweep at `watermark + 1` instead of re-scanning a fixed window.
    ///   Pass `None` to leave the watermark untouched (e.g. the shutdown
    ///   flush, which does no retention prune).
    pub fn flush_with_tip_and_blocks(
        &mut self,
        tip_hash: &Hash256,
        tip_height: u32,
        pending: &[(Hash256, Block, UndoData)],
        prune_targets: &[(u32, Hash256)],
        prune_watermark: Option<u32>,
    ) -> Result<(), StorageError> {
        let mut batch = self.store.db.new_batch();
        // 1. Cached UTXO mutations (drains cache, resets mem).
        self.flush_into_batch(&mut batch)?;
        // 2. Block bodies + undo for every block connected since last flush.
        for (hash, block, undo) in pending {
            self.store.batch_put_block(&mut batch, hash, block)?;
            self.store.batch_put_undo(&mut batch, hash, undo)?;
        }
        // 3. Retention prune: drop bodies/undo that fell out of the window.
        for (_height, hash) in prune_targets {
            self.store.batch_prune_block_body(&mut batch, hash)?;
        }
        // 3b. Advance the reorg-retention prune watermark in the SAME batch
        //     so the contiguous sweep resumes exactly where it left off on
        //     the next flush — independent of flush cadence, and crash-safe
        //     (the watermark is never durable without the deletes that earned
        //     it, and a crash that loses the watermark only re-deletes
        //     already-gone bodies, an idempotent no-op).
        if let Some(wm) = prune_watermark {
            self.store.batch_set_reorg_prune_height(&mut batch, wm)?;
        }
        // 4. Tip pointer LAST so it can never be durable without (1)-(2).
        self.store
            .batch_set_best_block(&mut batch, tip_hash, tip_height)?;
        self.store.db.write_batch(batch)?;
        Ok(())
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

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod flush_with_tip_tests {
    use super::*;
    use crate::db::ChainDb;
    use rustoshi_consensus::validation::{CoinEntry as ConsCoinEntry, UtxoView};
    use tempfile::TempDir;

    fn temp_db() -> (TempDir, ChainDb) {
        let dir = TempDir::new().expect("temp dir");
        let db = ChainDb::open(dir.path()).expect("open db");
        (dir, db)
    }

    fn hash_n(n: u8) -> Hash256 {
        let mut b = [0u8; 32];
        b[0] = n;
        Hash256(b)
    }

    fn outpoint_n(n: u8) -> OutPoint {
        OutPoint { txid: hash_n(n), vout: 1 }
    }

    fn coin(value: u64, height: u32) -> ConsCoinEntry {
        ConsCoinEntry {
            height,
            is_coinbase: false,
            value,
            script_pubkey: vec![0x00, 0x14, 0xaa, 0xbb],
        }
    }

    /// `flush_with_tip` must persist BOTH the cached UTXO mutations and the
    /// best-block (tip) pointer, and must drain the cache afterwards.
    #[test]
    fn flush_with_tip_persists_utxos_and_tip_together() {
        let (_dir, db) = temp_db();
        let store = BlockStore::new(&db);

        let op = outpoint_n(7);
        let tip = hash_n(42);

        {
            let mut view = store.utxo_view();
            view.add_utxo(&op, coin(500_000, 948_293));
            assert_eq!(view.cache_len(), 1);
            view.flush_with_tip(&tip, 948_293).expect("flush_with_tip");
            // Cache drained after flush.
            assert_eq!(view.cache_len(), 0);
            assert_eq!(view.estimated_memory(), 0);
        }

        // UTXO is durable in the DB.
        let got = store.get_utxo(&op).expect("get_utxo").expect("utxo present");
        assert_eq!(got.value, 500_000);
        // Tip pointer is durable in the DB.
        assert_eq!(store.get_best_block_hash().unwrap(), Some(tip));
        assert_eq!(store.get_best_height().unwrap(), Some(948_293));
    }

    /// Regression for the 2026-05-07 mainnet wedge (frozen at height
    /// 948,304).  Root cause: the connect loop wrote the persisted tip
    /// pointer eagerly on every block but only flushed the UTXO cache at
    /// 2 GiB.  A SIGKILL between an eager tip write and the next lazy
    /// flush left the persisted tip pointing past coins that were never
    /// written to disk — on restart every block past the tip failed
    /// `MissingInput`.
    ///
    /// This test reproduces the failure mode of the OLD code and proves
    /// the new `flush_with_tip` path closes it: a coin created at the tip
    /// height MUST be durable whenever the tip pointer names that height.
    #[test]
    fn tip_pointer_never_outruns_durable_utxo_set() {
        let (_dir, db) = temp_db();
        let store = BlockStore::new(&db);

        // Coin created by a tx in "block 948293".
        let created = outpoint_n(93);
        let tip_948304 = hash_n(204);

        {
            let mut view = store.utxo_view();
            // Connect blocks 948293..948304: add the coin, never hit the
            // 2 GiB cap, then commit the tip atomically (the fixed path).
            view.add_utxo(&created, coin(29_220_454, 948_293));
            view.flush_with_tip(&tip_948304, 948_304).expect("flush");
        }

        // Simulate a process restart: a fresh view backed by the same DB.
        let view2 = store.utxo_view();

        // The persisted tip is 948304 ...
        assert_eq!(store.get_best_height().unwrap(), Some(948_304));
        assert_eq!(store.get_best_block_hash().unwrap(), Some(tip_948304));
        // ... and the coin created at 948293 is STILL durably present, so
        // "block 948305" (which spends it) can connect. Under the old
        // eager-tip / lazy-flush code this lookup returned None and the
        // chain wedged forever.
        let recovered = view2.get_utxo(&created);
        assert!(
            recovered.is_some(),
            "coin created below the persisted tip must survive a restart — \
             the tip pointer must never be durable without its UTXOs"
        );
        assert_eq!(recovered.unwrap().value, 29_220_454);
    }

    /// `flush_with_tip` must also work (and advance the tip) when the UTXO
    /// cache happens to be empty — e.g. a shutdown flush right after a
    /// prior flush already drained the cache. The tip write must NOT be
    /// silently skipped just because there are no coin mutations.
    #[test]
    fn flush_with_tip_advances_tip_even_with_empty_cache() {
        let (_dir, db) = temp_db();
        let store = BlockStore::new(&db);

        let tip = hash_n(99);
        {
            let mut view = store.utxo_view();
            assert_eq!(view.cache_len(), 0);
            view.flush_with_tip(&tip, 950_000).expect("flush empty");
        }
        assert_eq!(store.get_best_block_hash().unwrap(), Some(tip));
        assert_eq!(store.get_best_height().unwrap(), Some(950_000));
    }

    /// Spending a coin (tombstone `None` in the cache) must be flushed as
    /// a delete in the same atomic batch as the tip pointer.
    #[test]
    fn flush_with_tip_applies_spends_atomically() {
        let (_dir, db) = temp_db();
        let store = BlockStore::new(&db);

        let op = outpoint_n(5);
        // Pre-seed a coin directly into the DB.
        store
            .put_utxo(&op, &CoinEntry { height: 1, is_coinbase: false, value: 10, script_pubkey: vec![] })
            .unwrap();
        assert!(store.get_utxo(&op).unwrap().is_some());

        {
            let mut view = store.utxo_view();
            view.spend_utxo(&op);
            view.flush_with_tip(&hash_n(1), 2).expect("flush spend");
        }

        // The spend landed: coin gone, tip advanced.
        assert!(store.get_utxo(&op).unwrap().is_none());
        assert_eq!(store.get_best_height().unwrap(), Some(2));
    }

    // ---- Unit B: block body + undo persistence on the connect path ----

    use rustoshi_primitives::{BlockHeader, OutPoint as PrimOutPoint, Transaction, TxIn, TxOut};

    /// Build a distinct-hash test block at `height` (nonce makes the hash
    /// unique). One coinbase-ish tx so `serialize`/`deserialize` round-trips.
    fn test_block(height: u32, prev: Hash256) -> Block {
        Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: prev,
                merkle_root: Hash256::ZERO,
                timestamp: 1_700_000_000 + height,
                bits: 0x1d00ffff,
                nonce: height,
            },
            transactions: vec![Transaction {
                version: 1,
                inputs: vec![TxIn {
                    previous_output: PrimOutPoint::null(),
                    script_sig: vec![height as u8, (height >> 8) as u8],
                    sequence: 0xFFFF_FFFF,
                    witness: vec![],
                }],
                outputs: vec![TxOut {
                    value: 50_0000_0000,
                    script_pubkey: vec![0x51],
                }],
                lock_time: 0,
            }],
        }
    }

    fn undo_n(n: u8) -> UndoData {
        UndoData {
            spent_coins: vec![CoinEntry {
                height: n as u32,
                is_coinbase: false,
                value: 1000 + n as u64,
                script_pubkey: vec![0xaa, n],
            }],
        }
    }

    /// `flush_with_tip_and_blocks` must persist the block body + undo for
    /// every pending block in the SAME atomic batch as the UTXO + tip, so
    /// that after the flush `get_block` / `get_undo` resolve them — the
    /// precondition `chain_state.reorganize()` needs to disconnect a block
    /// that arrived over P2P. (Pre-Unit-B the connect path wrote only
    /// header + index, so these lookups returned None and a P2P reorg
    /// failed at "missing undo data for disconnect".)
    #[test]
    fn flush_with_tip_and_blocks_persists_body_and_undo() {
        let (_dir, db) = temp_db();
        let store = BlockStore::new(&db);

        let b10 = test_block(10, hash_n(9));
        let b11 = test_block(11, b10.block_hash());
        let h10 = b10.block_hash();
        let h11 = b11.block_hash();
        let u10 = undo_n(10);
        let u11 = undo_n(11);

        {
            let mut view = store.utxo_view();
            // A coin created by these blocks, to prove coins still flip too.
            view.add_utxo(&outpoint_n(10), coin(5000, 10));
            let pending = vec![
                (h10, b10.clone(), u10.clone()),
                (h11, b11.clone(), u11.clone()),
            ];
            view.flush_with_tip_and_blocks(&h11, 11, &pending, &[], None)
                .expect("flush_with_tip_and_blocks");
            // Cache drained.
            assert_eq!(view.cache_len(), 0);
        }

        // Bodies are durable and round-trip.
        assert_eq!(store.get_block(&h10).unwrap(), Some(b10));
        assert_eq!(store.get_block(&h11).unwrap(), Some(b11));
        // Undo is durable and round-trips.
        assert_eq!(
            store.get_undo(&h10).unwrap().unwrap().spent_coins,
            u10.spent_coins
        );
        assert_eq!(
            store.get_undo(&h11).unwrap().unwrap().spent_coins,
            u11.spent_coins
        );
        // Tip + coin flipped in the same batch.
        assert_eq!(store.get_best_height().unwrap(), Some(11));
        assert_eq!(store.get_best_block_hash().unwrap(), Some(h11));
        assert!(store.get_utxo(&outpoint_n(10)).unwrap().is_some());
    }

    /// The retention prune staged into the flush batch must delete the body
    /// + undo of blocks below the floor, while the tip block's body + undo
    /// stay durable — proving we keep only the bounded reorg window, not the
    /// full archive, and never strand the tip without its own body/undo.
    #[test]
    fn flush_with_tip_and_blocks_prunes_below_floor() {
        let (_dir, db) = temp_db();
        let store = BlockStore::new(&db);

        // Pre-seed an old block's body + undo + height-index (as if it was
        // connected long ago and is now below the retention floor).
        let old = test_block(5, hash_n(4));
        let old_h = old.block_hash();
        store.put_block(&old_h, &old).unwrap();
        store.put_undo(&old_h, &undo_n(5)).unwrap();
        store.put_height_index(5, &old_h).unwrap();
        assert!(store.has_block(&old_h).unwrap());
        assert!(store.get_undo(&old_h).unwrap().is_some());

        // New tip block; prune the old one in the same flush.
        let tip = test_block(300, hash_n(40));
        let tip_h = tip.block_hash();

        {
            let mut view = store.utxo_view();
            let pending = vec![(tip_h, tip.clone(), undo_n(44))];
            let prune = vec![(5u32, old_h)];
            // Advance the watermark to the highest pruned height in the same
            // atomic batch (Unit B contiguous-sweep watermark).
            view.flush_with_tip_and_blocks(&tip_h, 300, &pending, &prune, Some(5))
                .expect("flush with prune");
        }

        // Old block body + undo are gone (pruned out of the window) ...
        assert!(!store.has_block(&old_h).unwrap());
        assert!(store.get_undo(&old_h).unwrap().is_none());
        // ... but the new tip's body + undo are durable.
        assert!(store.has_block(&tip_h).unwrap());
        assert!(store.get_undo(&tip_h).unwrap().is_some());
        assert_eq!(store.get_best_height().unwrap(), Some(300));
        // The watermark advanced atomically with the prune.
        assert_eq!(store.get_reorg_prune_height().unwrap(), Some(5));
    }

    /// `cache_state()` mirrors Core's `CoinsCacheSizeState`:
    ///   - `Ok` below `large_threshold_bytes()` (= max(cap*9/10, cap-10MiB))
    ///   - `Large` between threshold and cap
    ///   - `Critical` strictly above cap
    ///
    /// This test pins the Core-parity boundary so a future refactor that
    /// drops the LARGE early-warning rung re-introduces the per-block
    /// flush pathology that triggered the 2026-05-27 IBD pace decay.
    #[test]
    fn cache_state_transitions_ok_large_critical() {
        let (_dir, db) = temp_db();
        let store = BlockStore::new(&db);

        // Use a small cap so we can drive the state by hand-adding entries
        // (one entry ≈ CACHE_ENTRY_OVERHEAD bytes = 180 B + script_pubkey).
        // 1 MiB cap → LARGE threshold = max(1 MiB * 9 / 10, 1 MiB - 10 MiB sat)
        // = max(943718, 0) = 943718 B. Critical above 1048576 B.
        const CAP: usize = 1024 * 1024;
        let mut view = BlockStoreUtxoView::with_cache_limit(&store, CAP);

        assert_eq!(view.cache_state(), UtxoCacheState::Ok);
        assert!(view.large_threshold_bytes() < CAP);
        assert!(view.large_threshold_bytes() >= CAP * 9 / 10);

        // Fill to ~80 % of cap → still Ok.
        let target_ok = (CAP * 8) / 10;
        let mut n: u32 = 0;
        while view.estimated_memory() < target_ok {
            let op = OutPoint { txid: hash_n((n & 0xff) as u8), vout: n };
            view.add_utxo(&op, coin(1, 0));
            n += 1;
        }
        assert_eq!(view.cache_state(), UtxoCacheState::Ok);

        // Fill into the 90 %-100 % band → Large.
        let target_large = view.large_threshold_bytes() + 4096;
        while view.estimated_memory() < target_large {
            let op = OutPoint { txid: hash_n((n & 0xff) as u8), vout: n };
            view.add_utxo(&op, coin(1, 0));
            n += 1;
        }
        assert_eq!(view.cache_state(), UtxoCacheState::Large);
        // needs_flush() is the CRITICAL gate — must NOT fire in LARGE.
        assert!(!view.needs_flush());

        // Push past the cap → Critical.
        while view.estimated_memory() <= CAP {
            let op = OutPoint { txid: hash_n((n & 0xff) as u8), vout: n };
            view.add_utxo(&op, coin(1, 0));
            n += 1;
        }
        assert_eq!(view.cache_state(), UtxoCacheState::Critical);
        assert!(view.needs_flush());
    }

    /// `large_coins_cache_threshold` matches Core's helper exactly at
    /// the documented boundaries (validation.h:518-524).
    /// Core evaluates `(total * 9) / 10` (multiply first), not
    /// `(total / 10) * 9` — the two differ by up to 9 bytes on
    /// non-divisible inputs.
    #[test]
    fn large_coins_cache_threshold_matches_core() {
        // Tiny cap: 9/10 dominates (cap - 10MiB underflows → 0).
        assert_eq!(large_coins_cache_threshold(100), 90);
        // Small cap below 100 MiB: 9/10 still dominates.
        assert_eq!(
            large_coins_cache_threshold(1024 * 1024),
            (1024 * 1024usize * 9) / 10
        );
        // Large cap (≥ 100 MiB): `cap - 10 MiB` dominates over `cap * 9 / 10`.
        let big = 200 * 1024 * 1024;
        assert_eq!(large_coins_cache_threshold(big), big - 10 * 1024 * 1024);
        // Default 2 GiB cap, the production value: well above the
        // 10 MiB shoulder so `cap - 10 MiB` dominates.
        let default = DEFAULT_UTXO_CACHE_BYTES;
        assert_eq!(
            large_coins_cache_threshold(default),
            default - 10 * 1024 * 1024
        );
    }
}

// ============================================================
// FORMAT v2 ROUNDTRIP TESTS
// ============================================================
//
// Pinning the on-disk encoding so a future refactor that breaks the
// bytes-on-disk shape (e.g. reorders fields, changes endianness, drops
// a flag bit) fails the test suite BEFORE it ships and silently
// corrupts every operator's chainstate.

#[cfg(test)]
mod format_v2_tests {
    use super::*;

    fn make_coin(value: u64, script: Vec<u8>, is_coinbase: bool) -> CoinEntry {
        CoinEntry {
            height: 12345,
            is_coinbase,
            value,
            script_pubkey: script,
        }
    }

    #[test]
    fn coin_entry_roundtrip_minimal() {
        let coin = make_coin(0, Vec::new(), false);
        let bytes = format_v2::encode_coin_entry(&coin);
        // 4 (height) + 1 (flags) + 8 (value) + 1 (compact_size 0) = 14 bytes
        assert_eq!(bytes.len(), 14);
        assert_eq!(bytes.len(), format_v2::coin_entry_size(&coin));
        let decoded = format_v2::decode_coin_entry(&bytes).expect("roundtrip");
        assert_eq!(decoded, coin);
    }

    #[test]
    fn coin_entry_roundtrip_typical_p2pkh() {
        // 25-byte P2PKH scriptPubKey: OP_DUP OP_HASH160 <20B push> <20B hash> OP_EQUALVERIFY OP_CHECKSIG
        let script = vec![
            0x76, 0xa9, 0x14, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x88, 0xac,
        ];
        assert_eq!(script.len(), 25);
        let coin = make_coin(50_000_000, script, true);
        let bytes = format_v2::encode_coin_entry(&coin);
        // 4 + 1 + 8 + 1 (compact_size for 25) + 25 = 39 bytes
        assert_eq!(bytes.len(), 39);
        let decoded = format_v2::decode_coin_entry(&bytes).expect("roundtrip");
        assert_eq!(decoded, coin);
    }

    #[test]
    fn coin_entry_roundtrip_large_script() {
        // 500-byte script (triggers CompactSize 0xFD prefix)
        let script = vec![0xab; 500];
        let coin = make_coin(u64::MAX, script, false);
        let bytes = format_v2::encode_coin_entry(&coin);
        // 4 + 1 + 8 + 3 (compact_size 0xFD + u16 LE for 500) + 500 = 516 bytes
        assert_eq!(bytes.len(), 516);
        let decoded = format_v2::decode_coin_entry(&bytes).expect("roundtrip");
        assert_eq!(decoded, coin);
    }

    #[test]
    fn coin_entry_is_coinbase_flag_preserved() {
        let coinbase = make_coin(50_0000_0000, vec![0x51], true);
        let regular = make_coin(50_0000_0000, vec![0x51], false);
        let cb_bytes = format_v2::encode_coin_entry(&coinbase);
        let rg_bytes = format_v2::encode_coin_entry(&regular);
        assert_ne!(cb_bytes, rg_bytes, "coinbase flag must affect bytes");
        // Flag byte is at offset 4 (after height u32 LE).
        assert_eq!(cb_bytes[4], 0x01);
        assert_eq!(rg_bytes[4], 0x00);
    }

    #[test]
    fn coin_entry_rejects_v1_json_blob() {
        // A v1 serde_json blob starts with `{` = 0x7B. The high bits of
        // 0x7B include bit 1, bit 3, bit 4, bit 5, bit 6 — all undefined
        // in our flag byte. The decoder MUST refuse rather than misread
        // a JSON byte as the height field.
        let v1_blob = br#"{"height":12345,"is_coinbase":false,"value":50000000,"script_pubkey":[81]}"#;
        // First 4 bytes get interpreted as a u32 height (junk but legal).
        // Byte 5 is `:` = 0x3A which has unknown flag bits set → rejected.
        let res = format_v2::decode_coin_entry(v1_blob);
        assert!(
            res.is_err(),
            "decoder must reject v1 JSON blob; got {:?}",
            res
        );
    }

    #[test]
    fn coin_entry_rejects_truncated_input() {
        let coin = make_coin(0, vec![1, 2, 3], false);
        let bytes = format_v2::encode_coin_entry(&coin);
        for cut in 0..bytes.len() {
            let res = format_v2::decode_coin_entry(&bytes[..cut]);
            assert!(res.is_err(), "must reject {} of {} bytes", cut, bytes.len());
        }
        // Full-length decodes.
        assert!(format_v2::decode_coin_entry(&bytes).is_ok());
    }

    fn make_block_index_entry() -> BlockIndexEntry {
        let mut status = BlockStatus::new();
        status.set(BlockStatus::VALID_SCRIPTS);
        status.set(BlockStatus::HAVE_DATA);
        status.set(BlockStatus::HAVE_UNDO);
        BlockIndexEntry {
            height: 850_000,
            status,
            n_tx: 3210,
            timestamp: 1_700_000_000,
            bits: 0x1700_0000,
            nonce: 0xdead_beef,
            version: 0x2000_0000,
            prev_hash: Hash256([0x42; 32]),
            chain_work: [0xab; 32],
        }
    }

    #[test]
    fn block_index_entry_roundtrip() {
        let entry = make_block_index_entry();
        let bytes = format_v2::encode_block_index_entry(&entry);
        assert_eq!(bytes.len(), format_v2::BLOCK_INDEX_ENTRY_SIZE);
        assert_eq!(bytes.len(), 92);
        let decoded = format_v2::decode_block_index_entry(&bytes).expect("roundtrip");
        assert_eq!(decoded.height, entry.height);
        assert_eq!(decoded.status.raw(), entry.status.raw());
        assert_eq!(decoded.n_tx, entry.n_tx);
        assert_eq!(decoded.timestamp, entry.timestamp);
        assert_eq!(decoded.bits, entry.bits);
        assert_eq!(decoded.nonce, entry.nonce);
        assert_eq!(decoded.version, entry.version);
        assert_eq!(decoded.prev_hash, entry.prev_hash);
        assert_eq!(decoded.chain_work, entry.chain_work);
    }

    #[test]
    fn block_index_entry_rejects_wrong_length() {
        let mut bytes = format_v2::encode_block_index_entry(&make_block_index_entry());
        assert!(format_v2::decode_block_index_entry(&bytes).is_ok());
        bytes.push(0);
        assert!(format_v2::decode_block_index_entry(&bytes).is_err());
        bytes.pop();
        bytes.pop();
        assert!(format_v2::decode_block_index_entry(&bytes).is_err());
    }

    #[test]
    fn block_index_entry_negative_version_preserved() {
        let mut entry = make_block_index_entry();
        entry.version = -1; // Pre-BIP9 sentinel
        let bytes = format_v2::encode_block_index_entry(&entry);
        let decoded = format_v2::decode_block_index_entry(&bytes).expect("roundtrip");
        assert_eq!(decoded.version, -1);
    }

    #[test]
    fn undo_data_roundtrip_empty() {
        let undo = UndoData { spent_coins: Vec::new() };
        let bytes = format_v2::encode_undo_data(&undo);
        assert_eq!(bytes, vec![0x00]); // compact_size(0)
        let decoded = format_v2::decode_undo_data(&bytes).expect("roundtrip");
        assert_eq!(decoded.spent_coins.len(), 0);
    }

    #[test]
    fn undo_data_roundtrip_multiple_coins() {
        let undo = UndoData {
            spent_coins: vec![
                make_coin(100, vec![0x51], true),
                make_coin(200, vec![0x76, 0xa9, 0x14], false),
                make_coin(50_0000_0000, vec![], false),
            ],
        };
        let bytes = format_v2::encode_undo_data(&undo);
        let decoded = format_v2::decode_undo_data(&bytes).expect("roundtrip");
        assert_eq!(decoded.spent_coins, undo.spent_coins);
    }

    #[test]
    fn undo_data_rejects_implausible_length() {
        // compact_size 0xFE = u32-prefix, with value 20_000_000 (>10M cap)
        let bytes = [0xFE, 0x00, 0x2D, 0x31, 0x01, /* truncated rest */];
        let res = format_v2::decode_undo_data(&bytes);
        assert!(res.is_err(), "implausible length must be rejected");
    }

    fn make_tx_index_entry() -> TxIndexEntry {
        TxIndexEntry {
            block_hash: Hash256([0xde; 32]),
            tx_offset: 0x1234_5678,
            tx_length: 0xabcd,
        }
    }

    #[test]
    fn tx_index_entry_roundtrip() {
        let entry = make_tx_index_entry();
        let bytes = format_v2::encode_tx_index_entry(&entry);
        assert_eq!(bytes.len(), format_v2::TX_INDEX_ENTRY_SIZE);
        assert_eq!(bytes.len(), 40);
        let decoded = format_v2::decode_tx_index_entry(&bytes).expect("roundtrip");
        assert_eq!(decoded.block_hash, entry.block_hash);
        assert_eq!(decoded.tx_offset, entry.tx_offset);
        assert_eq!(decoded.tx_length, entry.tx_length);
    }

    #[test]
    fn tx_index_entry_rejects_wrong_length() {
        let bytes = format_v2::encode_tx_index_entry(&make_tx_index_entry());
        assert!(format_v2::decode_tx_index_entry(&bytes[..39]).is_err());
        let mut grown = bytes.clone();
        grown.push(0);
        assert!(format_v2::decode_tx_index_entry(&grown).is_err());
    }

    /// Size delta vs serde_json — pins the perf-relevant outcome so a
    /// regression that re-introduces JSON encoding (or a CoinEntry
    /// field bloat) fails CI immediately.
    ///
    /// Typical P2PKH coin: v2 = 39 bytes; serde_json = ~140 bytes
    /// (~3.6× compression). For 11M UTXO entries on disk that's the
    /// difference between ~1.4 GiB and ~430 MiB of SST data RocksDB
    /// has to compact every flush — the diagnosis doc's
    /// "RocksDB chainstate I/O thrash" was driven by exactly this.
    #[test]
    fn coin_entry_v2_is_substantially_smaller_than_json() {
        let coin = make_coin(
            50_000_000,
            vec![
                0x76, 0xa9, 0x14, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
                0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x88, 0xac,
            ],
            false,
        );
        let v2 = format_v2::encode_coin_entry(&coin);
        let json = serde_json::to_vec(&coin).expect("json");
        assert!(
            v2.len() * 3 <= json.len(),
            "expected v2 ({}B) to be at least 3× smaller than json ({}B)",
            v2.len(),
            json.len()
        );
    }
}
