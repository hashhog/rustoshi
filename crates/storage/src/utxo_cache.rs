//! UTXO Cache Layer
//!
//! Implements a multi-layer UTXO cache with an in-memory cache backed by a
//! persistent database. Modeled after Bitcoin Core's CCoinsViewCache.
//!
//! # Architecture
//!
//! The cache follows a hierarchical view pattern:
//!
//! ```text
//! ┌─────────────────────┐
//! │  CoinsViewCache     │  ← In-memory modifications
//! └──────────┬──────────┘
//!            │ falls through on miss
//! ┌──────────┴──────────┐
//! │    CoinsViewDB      │  ← Persistent storage (RocksDB)
//! └─────────────────────┘
//! ```
//!
//! # DIRTY/FRESH Flags
//!
//! Each cache entry has two flags:
//! - **DIRTY**: Entry differs from the backing store and needs to be written on flush.
//! - **FRESH**: Entry doesn't exist in the backing store.
//!
//! The FRESH optimization: if a coin is created (FRESH+DIRTY) and later spent
//! before flush, it can simply be deleted from the cache—no disk write needed.
//!
//! # Memory Management
//!
//! The cache tracks its memory usage. When it exceeds the configured limit
//! (default 450 MiB), it should be flushed to the backing store.

use crate::block_store::CoinEntry;
use crate::columns::CF_UTXO;
use crate::db::{ChainDb, StorageError};
use rustoshi_primitives::{Hash256, OutPoint, TxOut};
use std::collections::HashMap;
use std::mem;

// ============================================================
// CONSTANTS
// ============================================================

/// Default cache size limit in bytes (450 MiB, matching Bitcoin Core's -dbcache default).
pub const DEFAULT_DB_CACHE_BYTES: usize = 450 * 1024 * 1024;

/// Prefix byte for UTXO entries in the database (matches Bitcoin Core's 'C').
pub const DB_COIN_PREFIX: u8 = b'C';

// ============================================================
// COIN TYPE
// ============================================================

/// A UTXO entry containing the output data and metadata.
///
/// This is the canonical in-memory representation of a coin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Coin {
    /// The transaction output (value and script).
    pub tx_out: TxOut,
    /// Height of the block containing this transaction.
    pub height: u32,
    /// Whether this is from a coinbase transaction.
    pub is_coinbase: bool,
}

impl Coin {
    /// Create a new coin from a transaction output.
    pub fn new(tx_out: TxOut, height: u32, is_coinbase: bool) -> Self {
        Self {
            tx_out,
            height,
            is_coinbase,
        }
    }

    /// Check if this coin is "spent" (nulled out).
    ///
    /// A spent coin has a null output (value 0, empty script).
    pub fn is_spent(&self) -> bool {
        self.tx_out.value == 0 && self.tx_out.script_pubkey.is_empty()
    }

    /// Clear this coin (mark as spent).
    pub fn clear(&mut self) {
        self.tx_out.value = 0;
        self.tx_out.script_pubkey.clear();
        self.is_coinbase = false;
        self.height = 0;
    }

    /// Estimate dynamic memory usage for this coin.
    pub fn dynamic_memory_usage(&self) -> usize {
        self.tx_out.script_pubkey.capacity()
    }

    /// Convert from CoinEntry (database format).
    pub fn from_entry(entry: &CoinEntry) -> Self {
        Self {
            tx_out: TxOut {
                value: entry.value,
                script_pubkey: entry.script_pubkey.clone(),
            },
            height: entry.height,
            is_coinbase: entry.is_coinbase,
        }
    }

    /// Convert to CoinEntry (database format).
    pub fn to_entry(&self) -> CoinEntry {
        CoinEntry {
            height: self.height,
            is_coinbase: self.is_coinbase,
            value: self.tx_out.value,
            script_pubkey: self.tx_out.script_pubkey.clone(),
        }
    }
}

impl Default for Coin {
    fn default() -> Self {
        Self {
            tx_out: TxOut {
                value: 0,
                script_pubkey: Vec::new(),
            },
            height: 0,
            is_coinbase: false,
        }
    }
}

// ============================================================
// CACHE ENTRY FLAGS
// ============================================================

bitflags::bitflags! {
    /// Flags for cache entries.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct CacheEntryFlags: u8 {
        /// Entry differs from the backing store.
        const DIRTY = 0b0000_0001;
        /// Entry doesn't exist in the backing store (newly created).
        const FRESH = 0b0000_0010;
    }
}

// ============================================================
// CACHE ENTRY
// ============================================================

/// A coin cache entry with flags tracking modification state.
#[derive(Clone, Debug)]
pub struct CoinsCacheEntry {
    /// The actual coin data.
    pub coin: Coin,
    /// Flags indicating cache state.
    pub flags: CacheEntryFlags,
}

impl CoinsCacheEntry {
    /// Create a new cache entry.
    pub fn new(coin: Coin) -> Self {
        Self {
            coin,
            flags: CacheEntryFlags::empty(),
        }
    }

    /// Check if this entry is dirty.
    pub fn is_dirty(&self) -> bool {
        self.flags.contains(CacheEntryFlags::DIRTY)
    }

    /// Check if this entry is fresh.
    pub fn is_fresh(&self) -> bool {
        self.flags.contains(CacheEntryFlags::FRESH)
    }

    /// Set the dirty flag.
    pub fn set_dirty(&mut self) {
        self.flags.insert(CacheEntryFlags::DIRTY);
    }

    /// Set the fresh flag.
    pub fn set_fresh(&mut self) {
        self.flags.insert(CacheEntryFlags::FRESH);
    }

    /// Clear all flags.
    pub fn set_clean(&mut self) {
        self.flags = CacheEntryFlags::empty();
    }

    /// Estimate dynamic memory usage.
    pub fn dynamic_memory_usage(&self) -> usize {
        self.coin.dynamic_memory_usage()
    }
}

// ============================================================
// COINS VIEW TRAIT
// ============================================================

/// Abstract view on the UTXO set.
///
/// This trait provides a common interface for different UTXO storage backends.
pub trait CoinsView {
    /// Get a coin by outpoint.
    ///
    /// Returns `None` if the coin doesn't exist or has been spent.
    fn get_coin(&self, outpoint: &OutPoint) -> Result<Option<Coin>, StorageError>;

    /// Check if a coin exists (and is unspent).
    fn have_coin(&self, outpoint: &OutPoint) -> Result<bool, StorageError> {
        Ok(self.get_coin(outpoint)?.is_some())
    }

    /// Get the best block hash this view represents.
    fn get_best_block(&self) -> Result<Option<Hash256>, StorageError>;

    /// Estimate the size of the backing store.
    fn estimate_size(&self) -> usize {
        0
    }
}

// ============================================================
// COINS VIEW DB
// ============================================================

/// Direct database-backed coins view.
///
/// Reads and writes directly to/from RocksDB without caching.
pub struct CoinsViewDB<'a> {
    db: &'a ChainDb,
}

impl<'a> CoinsViewDB<'a> {
    /// Create a new database-backed coins view.
    pub fn new(db: &'a ChainDb) -> Self {
        Self { db }
    }

    /// Write a coin to the database.
    pub fn put_coin(&self, outpoint: &OutPoint, coin: &Coin) -> Result<(), StorageError> {
        let key = outpoint_key(outpoint);
        let entry = coin.to_entry();
        let data =
            serde_json::to_vec(&entry).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put_cf(CF_UTXO, &key, &data)
    }

    /// Delete a coin from the database.
    pub fn delete_coin(&self, outpoint: &OutPoint) -> Result<(), StorageError> {
        let key = outpoint_key(outpoint);
        self.db.delete_cf(CF_UTXO, &key)
    }

    /// Get a coin from the database.
    pub fn get_coin_from_db(&self, outpoint: &OutPoint) -> Result<Option<Coin>, StorageError> {
        let key = outpoint_key(outpoint);
        match self.db.get_cf(CF_UTXO, &key)? {
            Some(data) => {
                let entry: CoinEntry = serde_json::from_slice(&data)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(Coin::from_entry(&entry)))
            }
            None => Ok(None),
        }
    }

    /// Get a reference to the underlying database.
    pub fn db(&self) -> &ChainDb {
        self.db
    }
}

impl CoinsView for CoinsViewDB<'_> {
    fn get_coin(&self, outpoint: &OutPoint) -> Result<Option<Coin>, StorageError> {
        self.get_coin_from_db(outpoint)
    }

    fn get_best_block(&self) -> Result<Option<Hash256>, StorageError> {
        use crate::db::META_BEST_BLOCK_HASH;
        use crate::columns::CF_META;

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
}

// ============================================================
// COINS VIEW CACHE
// ============================================================

/// In-memory cache backed by another CoinsView.
///
/// Implements the DIRTY/FRESH optimization for efficient batch updates.
pub struct CoinsViewCache<'a> {
    /// Backing view (typically CoinsViewDB).
    base: &'a dyn CoinsView,
    /// In-memory coin cache.
    cache: HashMap<OutPoint, CoinsCacheEntry>,
    /// Cached best block hash.
    hash_block: Option<Hash256>,
    /// Tracked dynamic memory usage of cached coins.
    cached_coins_usage: usize,
    /// Count of dirty entries.
    dirty_count: usize,
}

impl<'a> CoinsViewCache<'a> {
    /// Create a new cache on top of a backing view.
    pub fn new(base: &'a dyn CoinsView) -> Self {
        Self {
            base,
            cache: HashMap::new(),
            hash_block: None,
            cached_coins_usage: 0,
            dirty_count: 0,
        }
    }

    /// Get the number of entries in the cache.
    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }

    /// Get the number of dirty entries.
    pub fn dirty_count(&self) -> usize {
        self.dirty_count
    }

    /// Estimate total dynamic memory usage.
    pub fn dynamic_memory_usage(&self) -> usize {
        // HashMap overhead + cached coin memory
        let map_overhead = self.cache.capacity()
            * (mem::size_of::<OutPoint>() + mem::size_of::<CoinsCacheEntry>());
        map_overhead + self.cached_coins_usage
    }

    /// Set the best block hash.
    pub fn set_best_block(&mut self, hash: Hash256) {
        self.hash_block = Some(hash);
    }

    /// Check if a coin is in the cache (without falling through to backing store).
    pub fn have_coin_in_cache(&self, outpoint: &OutPoint) -> bool {
        if let Some(entry) = self.cache.get(outpoint) {
            !entry.coin.is_spent()
        } else {
            false
        }
    }

    /// Fetch a coin, potentially caching it from the backing store.
    fn fetch_coin(&mut self, outpoint: &OutPoint) -> Result<Option<&CoinsCacheEntry>, StorageError> {
        // Check cache first
        if self.cache.contains_key(outpoint) {
            return Ok(self.cache.get(outpoint));
        }

        // Fetch from backing store
        if let Some(coin) = self.base.get_coin(outpoint)? {
            // Cache it (not dirty, not fresh - it exists in backing store)
            let entry = CoinsCacheEntry::new(coin);
            self.cached_coins_usage += entry.dynamic_memory_usage();
            self.cache.insert(outpoint.clone(), entry);
            return Ok(self.cache.get(outpoint));
        }

        Ok(None)
    }

    /// Add a coin to the cache.
    ///
    /// If `possible_overwrite` is true, an existing unspent coin may be overwritten
    /// (used for pre-BIP30 coinbase duplicates).
    pub fn add_coin(
        &mut self,
        outpoint: OutPoint,
        coin: Coin,
        possible_overwrite: bool,
    ) -> Result<(), StorageError> {
        if coin.is_spent() {
            panic!("Attempted to add a spent coin");
        }

        // Check if script is unspendable (OP_RETURN)
        if is_unspendable(&coin.tx_out.script_pubkey) {
            return Ok(());
        }

        let fresh;
        if let Some(existing) = self.cache.get_mut(&outpoint) {
            // Entry already exists in cache
            if !possible_overwrite && !existing.coin.is_spent() {
                panic!("Attempted to overwrite an unspent coin (when possible_overwrite is false)");
            }

            // If the coin exists as a spent coin and is DIRTY, we can't mark the new
            // version as FRESH (we need to flush the spentness to the parent first).
            fresh = !existing.is_dirty();

            // Track memory changes
            if existing.is_dirty() {
                self.dirty_count -= 1;
            }
            self.cached_coins_usage = self.cached_coins_usage.saturating_sub(existing.dynamic_memory_usage());

            // Update the coin
            existing.coin = coin;
            existing.set_dirty();
            self.dirty_count += 1;
            if fresh {
                existing.set_fresh();
            }
            self.cached_coins_usage += existing.dynamic_memory_usage();
        } else {
            // New entry
            let mut entry = CoinsCacheEntry::new(coin);
            entry.set_dirty();
            entry.set_fresh();
            self.cached_coins_usage += entry.dynamic_memory_usage();
            self.dirty_count += 1;
            self.cache.insert(outpoint, entry);
        }

        Ok(())
    }

    /// Spend a coin.
    ///
    /// If `move_to` is provided, the spent coin data will be moved into it.
    /// Returns true if the coin was found and spent.
    pub fn spend_coin(
        &mut self,
        outpoint: &OutPoint,
        move_to: Option<&mut Coin>,
    ) -> Result<bool, StorageError> {
        // First, ensure the coin is in the cache (fetch from DB if needed)
        if !self.cache.contains_key(outpoint) {
            if let Some(coin) = self.base.get_coin(outpoint)? {
                let entry = CoinsCacheEntry::new(coin);
                self.cached_coins_usage += entry.dynamic_memory_usage();
                self.cache.insert(outpoint.clone(), entry);
            } else {
                return Ok(false);
            }
        }

        // Now we can work with the cached entry
        let entry = self.cache.get_mut(outpoint).unwrap();

        if entry.coin.is_spent() {
            return Ok(false);
        }

        // Track dirty count changes
        let was_dirty = entry.is_dirty();
        let was_fresh = entry.is_fresh();
        let mem_usage = entry.dynamic_memory_usage();

        if was_dirty {
            self.dirty_count -= 1;
        }
        self.cached_coins_usage = self.cached_coins_usage.saturating_sub(mem_usage);

        // Move data out if requested
        if let Some(dest) = move_to {
            *dest = std::mem::take(&mut entry.coin);
        }

        // If FRESH, we can just remove from cache entirely (never needs to touch disk)
        if was_fresh {
            self.cache.remove(outpoint);
        } else {
            // Mark as spent and dirty (needs to be written to backing store)
            let entry = self.cache.get_mut(outpoint).unwrap();
            entry.coin.clear();
            entry.set_dirty();
            entry.flags.remove(CacheEntryFlags::FRESH);
            self.dirty_count += 1;
            // No dynamic memory usage for spent coins
        }

        Ok(true)
    }

    /// Access a coin by reference.
    ///
    /// Returns a reference to the coin, or None if not found.
    pub fn access_coin(&mut self, outpoint: &OutPoint) -> Result<Option<&Coin>, StorageError> {
        self.fetch_coin(outpoint)?;
        Ok(self.cache.get(outpoint).map(|e| &e.coin).filter(|c| !c.is_spent()))
    }

    /// Remove an unmodified entry from the cache.
    ///
    /// Used to free memory for coins that were fetched but not modified.
    pub fn uncache(&mut self, outpoint: &OutPoint) {
        if let Some(entry) = self.cache.get(outpoint) {
            if !entry.is_dirty() {
                self.cached_coins_usage = self.cached_coins_usage.saturating_sub(entry.dynamic_memory_usage());
                self.cache.remove(outpoint);
            }
        }
    }

    /// Check if all inputs for a transaction exist in the UTXO set.
    pub fn have_inputs(&mut self, tx: &rustoshi_primitives::Transaction) -> Result<bool, StorageError> {
        if tx.is_coinbase() {
            return Ok(true);
        }

        for input in &tx.inputs {
            if !self.have_coin(&input.previous_output)? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Flush all dirty entries to a database-backed view.
    ///
    /// This writes all modifications to the backing store and clears the cache.
    pub fn flush_to_db(&mut self, db: &CoinsViewDB) -> Result<(), StorageError> {
        for (outpoint, entry) in self.cache.drain() {
            if !entry.is_dirty() {
                continue;
            }

            if entry.coin.is_spent() {
                // FRESH + spent = never existed in DB, nothing to delete
                if !entry.is_fresh() {
                    db.delete_coin(&outpoint)?;
                }
            } else {
                db.put_coin(&outpoint, &entry.coin)?;
            }
        }

        // Update best block if set
        if let Some(hash) = self.hash_block.take() {
            use crate::columns::CF_META;
            use crate::db::META_BEST_BLOCK_HASH;
            db.db().put_cf(CF_META, META_BEST_BLOCK_HASH, hash.as_bytes())?;
        }

        self.cached_coins_usage = 0;
        self.dirty_count = 0;

        Ok(())
    }

    /// Sync dirty entries to a database-backed view without clearing the cache.
    ///
    /// Unlike flush, this retains non-spent entries in the cache.
    pub fn sync_to_db(&mut self, db: &CoinsViewDB) -> Result<(), StorageError> {
        let outpoints: Vec<OutPoint> = self.cache.keys().cloned().collect();

        for outpoint in outpoints {
            let entry = self.cache.get_mut(&outpoint).unwrap();
            if !entry.is_dirty() {
                continue;
            }

            if entry.coin.is_spent() {
                // Delete and remove from cache
                if !entry.is_fresh() {
                    db.delete_coin(&outpoint)?;
                }
                if entry.is_dirty() {
                    self.dirty_count -= 1;
                }
                self.cache.remove(&outpoint);
            } else {
                // Write to DB and mark as clean
                db.put_coin(&outpoint, &entry.coin)?;
                self.dirty_count -= 1;
                entry.set_clean();
            }
        }

        // Update best block if set
        if let Some(hash) = self.hash_block.take() {
            use crate::columns::CF_META;
            use crate::db::META_BEST_BLOCK_HASH;
            db.db().put_cf(CF_META, META_BEST_BLOCK_HASH, hash.as_bytes())?;
        }

        Ok(())
    }

    /// Get an iterator over all cache entries (for debugging/testing).
    pub fn entries(&self) -> impl Iterator<Item = (&OutPoint, &CoinsCacheEntry)> {
        self.cache.iter()
    }

    /// Discard all changes without flushing.
    pub fn reset(&mut self) {
        self.cache.clear();
        self.cached_coins_usage = 0;
        self.dirty_count = 0;
        self.hash_block = None;
    }
}

impl CoinsView for CoinsViewCache<'_> {
    fn get_coin(&self, outpoint: &OutPoint) -> Result<Option<Coin>, StorageError> {
        // Check cache first
        if let Some(entry) = self.cache.get(outpoint) {
            if entry.coin.is_spent() {
                return Ok(None);
            }
            return Ok(Some(entry.coin.clone()));
        }

        // Fall through to backing store
        self.base.get_coin(outpoint)
    }

    fn have_coin(&self, outpoint: &OutPoint) -> Result<bool, StorageError> {
        // Check cache first
        if let Some(entry) = self.cache.get(outpoint) {
            return Ok(!entry.coin.is_spent());
        }

        // Fall through to backing store
        self.base.have_coin(outpoint)
    }

    fn get_best_block(&self) -> Result<Option<Hash256>, StorageError> {
        if let Some(hash) = &self.hash_block {
            return Ok(Some(*hash));
        }
        self.base.get_best_block()
    }

    fn estimate_size(&self) -> usize {
        self.dynamic_memory_usage()
    }
}

// ============================================================
// HELPER FUNCTIONS
// ============================================================

/// Create the key for a UTXO lookup.
///
/// Format: txid (32 bytes) + vout (4 bytes big-endian)
fn outpoint_key(outpoint: &OutPoint) -> Vec<u8> {
    let mut key = Vec::with_capacity(36);
    key.extend_from_slice(outpoint.txid.as_bytes());
    key.extend_from_slice(&outpoint.vout.to_be_bytes());
    key
}

/// Check if a script is unspendable (starts with OP_RETURN).
fn is_unspendable(script: &[u8]) -> bool {
    !script.is_empty() && script[0] == 0x6a // OP_RETURN
}

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_db() -> (TempDir, ChainDb) {
        let dir = TempDir::new().expect("failed to create temp dir");
        let db = ChainDb::open(dir.path()).expect("failed to open db");
        (dir, db)
    }

    fn make_coin(value: u64, height: u32, is_coinbase: bool) -> Coin {
        Coin {
            tx_out: TxOut {
                value,
                script_pubkey: vec![0x76, 0xa9, 0x14], // P2PKH prefix
            },
            height,
            is_coinbase,
        }
    }

    fn make_outpoint(n: u32) -> OutPoint {
        OutPoint {
            txid: Hash256::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .unwrap(),
            vout: n,
        }
    }

    #[test]
    fn test_coin_is_spent() {
        let mut coin = make_coin(1000, 100, false);
        assert!(!coin.is_spent());

        coin.clear();
        assert!(coin.is_spent());
    }

    #[test]
    fn test_coins_view_db_roundtrip() {
        let (_dir, db) = temp_db();
        let view = CoinsViewDB::new(&db);

        let outpoint = make_outpoint(0);
        let coin = make_coin(50_0000_0000, 100, true);

        // Initially not present
        assert!(view.get_coin(&outpoint).unwrap().is_none());

        // Store and retrieve
        view.put_coin(&outpoint, &coin).unwrap();
        let retrieved = view.get_coin(&outpoint).unwrap().unwrap();
        assert_eq!(retrieved.tx_out.value, coin.tx_out.value);
        assert_eq!(retrieved.height, coin.height);
        assert_eq!(retrieved.is_coinbase, coin.is_coinbase);

        // Delete
        view.delete_coin(&outpoint).unwrap();
        assert!(view.get_coin(&outpoint).unwrap().is_none());
    }

    #[test]
    fn test_coins_cache_add_and_get() {
        let (_dir, db) = temp_db();
        let db_view = CoinsViewDB::new(&db);
        let mut cache = CoinsViewCache::new(&db_view);

        let outpoint = make_outpoint(0);
        let coin = make_coin(1000, 100, false);

        // Add to cache
        cache.add_coin(outpoint.clone(), coin.clone(), false).unwrap();

        // Should be in cache
        assert!(cache.have_coin_in_cache(&outpoint));
        assert!(cache.have_coin(&outpoint).unwrap());

        let retrieved = cache.get_coin(&outpoint).unwrap().unwrap();
        assert_eq!(retrieved.tx_out.value, 1000);
    }

    #[test]
    fn test_coins_cache_spend() {
        let (_dir, db) = temp_db();
        let db_view = CoinsViewDB::new(&db);
        let mut cache = CoinsViewCache::new(&db_view);

        let outpoint = make_outpoint(0);
        let coin = make_coin(1000, 100, false);

        // Add and spend
        cache.add_coin(outpoint.clone(), coin, false).unwrap();
        assert!(cache.have_coin(&outpoint).unwrap());

        let result = cache.spend_coin(&outpoint, None).unwrap();
        assert!(result);

        // Should no longer be available
        assert!(!cache.have_coin(&outpoint).unwrap());
    }

    #[test]
    fn test_coins_cache_fresh_optimization() {
        let (_dir, db) = temp_db();
        let db_view = CoinsViewDB::new(&db);
        let mut cache = CoinsViewCache::new(&db_view);

        let outpoint = make_outpoint(0);
        let coin = make_coin(1000, 100, false);

        // Add (will be FRESH + DIRTY)
        cache.add_coin(outpoint.clone(), coin, false).unwrap();

        // The entry should be marked as FRESH
        let entry = cache.cache.get(&outpoint).unwrap();
        assert!(entry.is_fresh());
        assert!(entry.is_dirty());

        // Spend it
        cache.spend_coin(&outpoint, None).unwrap();

        // Since it was FRESH, it should be removed entirely (not marked as spent)
        assert!(!cache.cache.contains_key(&outpoint));
    }

    #[test]
    fn test_coins_cache_flush() {
        let (_dir, db) = temp_db();
        let db_view = CoinsViewDB::new(&db);
        let mut cache = CoinsViewCache::new(&db_view);

        let outpoint1 = make_outpoint(0);
        let outpoint2 = make_outpoint(1);
        let coin1 = make_coin(1000, 100, false);
        let coin2 = make_coin(2000, 200, true);

        // Add two coins
        cache.add_coin(outpoint1.clone(), coin1, false).unwrap();
        cache.add_coin(outpoint2.clone(), coin2, false).unwrap();

        // Spend one
        cache.spend_coin(&outpoint1, None).unwrap();

        // Flush to DB
        cache.flush_to_db(&db_view).unwrap();

        // Cache should be empty
        assert_eq!(cache.cache_size(), 0);

        // Verify DB state
        assert!(db_view.get_coin(&outpoint1).unwrap().is_none()); // Was spent+fresh, never written
        let coin = db_view.get_coin(&outpoint2).unwrap().unwrap();
        assert_eq!(coin.tx_out.value, 2000);
    }

    #[test]
    fn test_coins_cache_fallthrough() {
        let (_dir, db) = temp_db();
        let db_view = CoinsViewDB::new(&db);

        // Put a coin directly in DB
        let outpoint = make_outpoint(0);
        let coin = make_coin(5000, 50, false);
        db_view.put_coin(&outpoint, &coin).unwrap();

        // Create cache - coin should not be in cache yet
        let mut cache = CoinsViewCache::new(&db_view);
        assert!(!cache.have_coin_in_cache(&outpoint));

        // But should be accessible (falls through to DB)
        assert!(cache.have_coin(&outpoint).unwrap());

        // Access it to cache it
        let retrieved = cache.access_coin(&outpoint).unwrap().unwrap();
        assert_eq!(retrieved.tx_out.value, 5000);

        // Now it should be in cache
        assert!(cache.have_coin_in_cache(&outpoint));
    }

    #[test]
    fn test_coins_cache_spend_from_db() {
        let (_dir, db) = temp_db();
        let db_view = CoinsViewDB::new(&db);

        // Put a coin directly in DB
        let outpoint = make_outpoint(0);
        let coin = make_coin(5000, 50, false);
        db_view.put_coin(&outpoint, &coin).unwrap();

        // Create cache and spend the coin
        let mut cache = CoinsViewCache::new(&db_view);
        let result = cache.spend_coin(&outpoint, None).unwrap();
        assert!(result);

        // Should not be FRESH (exists in DB)
        let entry = cache.cache.get(&outpoint).unwrap();
        assert!(!entry.is_fresh());
        assert!(entry.is_dirty());
        assert!(entry.coin.is_spent());

        // Flush should delete from DB
        cache.flush_to_db(&db_view).unwrap();
        assert!(db_view.get_coin(&outpoint).unwrap().is_none());
    }

    #[test]
    fn test_coins_cache_sync() {
        let (_dir, db) = temp_db();
        let db_view = CoinsViewDB::new(&db);
        let mut cache = CoinsViewCache::new(&db_view);

        let outpoint1 = make_outpoint(0);
        let outpoint2 = make_outpoint(1);
        let coin1 = make_coin(1000, 100, false);
        let coin2 = make_coin(2000, 200, false);

        // Add two coins
        cache.add_coin(outpoint1.clone(), coin1, false).unwrap();
        cache.add_coin(outpoint2.clone(), coin2, false).unwrap();

        // Sync (not flush)
        cache.sync_to_db(&db_view).unwrap();

        // Coins should still be in cache but clean
        assert!(cache.have_coin_in_cache(&outpoint1));
        assert!(cache.have_coin_in_cache(&outpoint2));
        assert!(!cache.cache.get(&outpoint1).unwrap().is_dirty());

        // And in DB
        assert!(db_view.get_coin(&outpoint1).unwrap().is_some());
        assert!(db_view.get_coin(&outpoint2).unwrap().is_some());
    }

    #[test]
    fn test_coins_cache_memory_tracking() {
        let (_dir, db) = temp_db();
        let db_view = CoinsViewDB::new(&db);
        let mut cache = CoinsViewCache::new(&db_view);

        let initial_usage = cache.cached_coins_usage;
        assert_eq!(initial_usage, 0);

        // Add a coin with a large script
        let outpoint = make_outpoint(0);
        let coin = Coin {
            tx_out: TxOut {
                value: 1000,
                script_pubkey: vec![0u8; 1000], // 1000 byte script
            },
            height: 100,
            is_coinbase: false,
        };

        cache.add_coin(outpoint.clone(), coin, false).unwrap();
        assert!(cache.cached_coins_usage > 0);

        // Spend it
        cache.spend_coin(&outpoint, None).unwrap();
        // FRESH coin is removed entirely
        assert_eq!(cache.cached_coins_usage, 0);
    }

    #[test]
    fn test_coins_cache_uncache() {
        let (_dir, db) = temp_db();
        let db_view = CoinsViewDB::new(&db);

        // Put a coin directly in DB
        let outpoint = make_outpoint(0);
        let coin = make_coin(5000, 50, false);
        db_view.put_coin(&outpoint, &coin).unwrap();

        // Fetch it into cache
        let mut cache = CoinsViewCache::new(&db_view);
        cache.access_coin(&outpoint).unwrap();
        assert!(cache.have_coin_in_cache(&outpoint));

        // Uncache it (should work since it's not dirty)
        cache.uncache(&outpoint);
        assert!(!cache.have_coin_in_cache(&outpoint));

        // Still accessible via DB fallthrough
        assert!(cache.have_coin(&outpoint).unwrap());
    }

    #[test]
    fn test_coins_cache_dirty_cannot_uncache() {
        let (_dir, db) = temp_db();
        let db_view = CoinsViewDB::new(&db);
        let mut cache = CoinsViewCache::new(&db_view);

        // Add a coin (will be dirty)
        let outpoint = make_outpoint(0);
        let coin = make_coin(1000, 100, false);
        cache.add_coin(outpoint.clone(), coin, false).unwrap();

        // Try to uncache
        cache.uncache(&outpoint);

        // Should still be in cache (can't uncache dirty entries)
        assert!(cache.have_coin_in_cache(&outpoint));
    }

    #[test]
    fn test_unspendable_script_not_cached() {
        let (_dir, db) = temp_db();
        let db_view = CoinsViewDB::new(&db);
        let mut cache = CoinsViewCache::new(&db_view);

        let outpoint = make_outpoint(0);
        let op_return_coin = Coin {
            tx_out: TxOut {
                value: 0,
                script_pubkey: vec![0x6a, 0x04, 0xde, 0xad], // OP_RETURN <data>
            },
            height: 100,
            is_coinbase: false,
        };

        // Adding an OP_RETURN output should be a no-op
        cache.add_coin(outpoint.clone(), op_return_coin, false).unwrap();
        assert!(!cache.have_coin_in_cache(&outpoint));
    }

    #[test]
    fn test_coins_cache_best_block() {
        let (_dir, db) = temp_db();
        let db_view = CoinsViewDB::new(&db);
        let mut cache = CoinsViewCache::new(&db_view);

        let hash = Hash256::from_hex(
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        )
        .unwrap();

        cache.set_best_block(hash);
        assert_eq!(cache.get_best_block().unwrap(), Some(hash));

        // Flush should persist it
        cache.flush_to_db(&db_view).unwrap();
        assert_eq!(db_view.get_best_block().unwrap(), Some(hash));
    }

    #[test]
    fn test_coins_cache_move_to_on_spend() {
        let (_dir, db) = temp_db();
        let db_view = CoinsViewDB::new(&db);
        let mut cache = CoinsViewCache::new(&db_view);

        let outpoint = make_outpoint(0);
        let coin = make_coin(12345, 100, true);
        cache.add_coin(outpoint.clone(), coin, false).unwrap();

        // Spend and capture the coin
        let mut captured = Coin::default();
        cache.spend_coin(&outpoint, Some(&mut captured)).unwrap();

        assert_eq!(captured.tx_out.value, 12345);
        assert_eq!(captured.height, 100);
        assert!(captured.is_coinbase);
    }

    #[test]
    fn test_dirty_count_tracking() {
        let (_dir, db) = temp_db();
        let db_view = CoinsViewDB::new(&db);
        let mut cache = CoinsViewCache::new(&db_view);

        assert_eq!(cache.dirty_count(), 0);

        // Add coins
        for i in 0..5 {
            let outpoint = make_outpoint(i);
            let coin = make_coin(1000, 100, false);
            cache.add_coin(outpoint, coin, false).unwrap();
        }
        assert_eq!(cache.dirty_count(), 5);

        // Spend some (FRESH coins are removed, so dirty count decreases)
        cache.spend_coin(&make_outpoint(0), None).unwrap();
        cache.spend_coin(&make_outpoint(1), None).unwrap();
        // Two FRESH coins removed, so dirty count drops by 2
        assert_eq!(cache.dirty_count(), 3);
    }
}
