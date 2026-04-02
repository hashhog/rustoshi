//! Core database wrapper for RocksDB.
//!
//! Provides a type-safe interface to the underlying RocksDB instance with
//! column family management and atomic batch writes.

use crate::columns::*;
use rocksdb::{ColumnFamilyDescriptor, Options, WriteBatch, DB};
use std::path::Path;

// ============================================================
// METADATA KEYS
// ============================================================

/// Metadata key for the best (tip) block hash.
pub const META_BEST_BLOCK_HASH: &[u8] = b"best_block_hash";

/// Metadata key for the best block height.
pub const META_BEST_HEIGHT: &[u8] = b"best_height";

/// Metadata key for the header chain tip hash (may be ahead of validated blocks).
pub const META_HEADER_TIP_HASH: &[u8] = b"header_tip_hash";

/// Metadata key for the header chain tip height.
pub const META_HEADER_TIP_HEIGHT: &[u8] = b"header_tip_height";

/// Metadata key for total chain work (256-bit big-endian).
pub const META_CHAIN_WORK: &[u8] = b"chain_work";

/// Metadata key for the prune height (blocks below this have been pruned).
pub const META_PRUNE_HEIGHT: &[u8] = b"prune_height";

/// Metadata key for the database version.
pub const META_DB_VERSION: &[u8] = b"db_version";

/// Current database schema version.
pub const CURRENT_DB_VERSION: u32 = 1;

// ============================================================
// ERROR TYPES
// ============================================================

/// Storage layer errors.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// RocksDB operation failed.
    #[error("rocksdb error: {0}")]
    RocksDb(#[from] rocksdb::Error),

    /// Serialization or deserialization failed.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Requested data not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// Database corruption detected.
    #[error("corruption: {0}")]
    Corruption(String),

    /// I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

// ============================================================
// DATABASE HANDLE
// ============================================================

/// The main database handle wrapping RocksDB.
///
/// Provides methods for reading and writing data across column families,
/// with support for atomic batch writes.
pub struct ChainDb {
    db: DB,
}

impl ChainDb {
    /// Open or create the database at the given path.
    ///
    /// Creates all required column families if they don't exist.
    /// Configures optimized settings for UTXO lookups and block storage.
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        db_opts.set_max_open_files(256);
        db_opts.set_keep_log_file_num(2);
        db_opts.set_max_total_wal_size(16 * 1024 * 1024); // 16 MB
        db_opts.set_write_buffer_size(8 * 1024 * 1024); // 8 MB write buffer
        db_opts.set_max_write_buffer_number(2);
        // Limit background compaction memory
        db_opts.set_db_write_buffer_size(64 * 1024 * 1024); // 64 MB total across all CFs
        // Disable mmap reads — prevents OS from mapping 100+ GB of SST files
        // into the process's virtual memory (RSS). Use pread() instead.
        db_opts.set_allow_mmap_reads(false);
        db_opts.set_allow_mmap_writes(false);

        // Shared block cache across all column families (64 MiB)
        // Index and filter blocks are stored in the cache (not pinned) to limit memory.
        let block_cache = rocksdb::Cache::new_lru_cache(64 * 1024 * 1024);

        // Configure per-column-family options
        let cf_descriptors: Vec<ColumnFamilyDescriptor> = ALL_COLUMN_FAMILIES
            .iter()
            .map(|name| {
                let mut cf_opts = Options::default();
                let mut block_opts = rocksdb::BlockBasedOptions::default();
                block_opts.set_block_cache(&block_cache);
                // Store index/filter blocks in the block cache (evictable)
                // rather than pinning them in memory indefinitely.
                block_opts.set_cache_index_and_filter_blocks(true);
                block_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);

                // UTXO column family: add bloom filters for fast existence checks
                if *name == CF_UTXO {
                    block_opts.set_bloom_filter(10.0, false);
                }

                // Blocks column family: larger block size for sequential reads during IBD
                if *name == CF_BLOCKS {
                    block_opts.set_block_size(64 * 1024); // 64 KB blocks
                }

                cf_opts.set_block_based_table_factory(&block_opts);
                ColumnFamilyDescriptor::new(*name, cf_opts)
            })
            .collect();

        let db = DB::open_cf_descriptors(&db_opts, path, cf_descriptors)?;
        Ok(Self { db })
    }

    /// Drop all data from the blocks column family to reclaim disk space.
    /// Blocks are large (~500GB for mainnet) and don't need to be in RocksDB.
    pub fn drop_blocks_cf(&self) -> Result<(), StorageError> {
        if let Some(cf) = self.db.cf_handle(CF_BLOCKS) {
            // DeleteRange covers all possible 32-byte hash keys
            let start = [0u8; 32];
            let end = [0xFFu8; 32];
            self.db.delete_range_cf(&cf, start, end)?;
            // Compact to actually free disk space
            self.db.compact_range_cf(&cf, None::<&[u8]>, None::<&[u8]>);
        }
        Ok(())
    }

    /// Get a value from a column family.
    ///
    /// Returns `None` if the key doesn't exist.
    pub fn get_cf(&self, cf_name: &str, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .ok_or_else(|| StorageError::Corruption(format!("missing column family: {}", cf_name)))?;
        Ok(self.db.get_cf(&cf, key)?)
    }

    /// Put a value into a column family.
    pub fn put_cf(&self, cf_name: &str, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .ok_or_else(|| StorageError::Corruption(format!("missing column family: {}", cf_name)))?;
        self.db.put_cf(&cf, key, value)?;
        Ok(())
    }

    /// Delete a value from a column family.
    pub fn delete_cf(&self, cf_name: &str, key: &[u8]) -> Result<(), StorageError> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .ok_or_else(|| StorageError::Corruption(format!("missing column family: {}", cf_name)))?;
        self.db.delete_cf(&cf, key)?;
        Ok(())
    }

    /// Execute a batch of writes atomically.
    ///
    /// All writes in the batch are applied together or not at all,
    /// ensuring consistency even across multiple column families.
    pub fn write_batch(&self, batch: WriteBatch) -> Result<(), StorageError> {
        self.db.write(batch)?;
        Ok(())
    }

    /// Create a new empty WriteBatch for batching multiple writes.
    pub fn new_batch(&self) -> WriteBatch {
        WriteBatch::default()
    }

    /// Get a column family handle for use with WriteBatch.
    ///
    /// Returns `None` if the column family doesn't exist.
    pub fn cf_handle(&self, name: &str) -> Option<&rocksdb::ColumnFamily> {
        self.db.cf_handle(name)
    }

    /// Check if a key exists in a column family.
    pub fn contains_key(&self, cf_name: &str, key: &[u8]) -> Result<bool, StorageError> {
        Ok(self.get_cf(cf_name, key)?.is_some())
    }

    /// Iterate over all key-value pairs in a column family.
    ///
    /// Returns an iterator that yields `(key, value)` pairs.
    /// The iteration order depends on the column family's configuration.
    pub fn iter_cf(
        &self,
        cf_name: &str,
    ) -> Result<impl Iterator<Item = (Box<[u8]>, Box<[u8]>)> + '_, StorageError> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .ok_or_else(|| StorageError::Corruption(format!("missing column family: {}", cf_name)))?;
        Ok(self
            .db
            .iterator_cf(&cf, rocksdb::IteratorMode::Start)
            .filter_map(|result| result.ok()))
    }

    /// Open the database with optimized performance settings for IBD.
    ///
    /// This configuration is tuned for maximum throughput during initial block
    /// download, with larger write buffers, more aggressive compaction, and
    /// optimized block caching.
    ///
    /// Key optimizations:
    /// - 64 MB write buffers (reduces compaction frequency during heavy writes)
    /// - 512 MB shared block cache (keeps hot data in memory)
    /// - Bloom filters on UTXO column family (reduces disk reads)
    /// - Level compaction with dynamic level sizes
    /// - Background jobs for parallel compaction
    pub fn open_optimized(path: &Path) -> Result<Self, StorageError> {
        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);

        // Performance tuning
        db_opts.set_max_open_files(512);
        db_opts.set_keep_log_file_num(2);
        db_opts.set_max_total_wal_size(128 * 1024 * 1024); // 128 MB WAL
        db_opts.set_max_background_jobs(4);
        db_opts.set_bytes_per_sync(1024 * 1024); // 1 MB sync interval
        db_opts.set_compaction_style(rocksdb::DBCompactionStyle::Level);
        db_opts.set_level_compaction_dynamic_level_bytes(true);

        // Write buffer: 64 MB (larger = fewer compactions during IBD)
        db_opts.set_write_buffer_size(64 * 1024 * 1024);
        db_opts.set_max_write_buffer_number(3);
        db_opts.set_min_write_buffer_number_to_merge(2);

        // Block cache: 512 MB shared across all column families
        let cache = rocksdb::Cache::new_lru_cache(512 * 1024 * 1024);

        let cf_descriptors: Vec<ColumnFamilyDescriptor> = ALL_COLUMN_FAMILIES
            .iter()
            .map(|name| {
                let mut cf_opts = Options::default();

                let mut block_opts = rocksdb::BlockBasedOptions::default();
                block_opts.set_block_cache(&cache);

                if *name == CF_UTXO {
                    // UTXO: heavy random reads, benefit from bloom filter
                    block_opts.set_bloom_filter(10.0, false);
                    block_opts.set_cache_index_and_filter_blocks(true);
                    block_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);
                    cf_opts.set_write_buffer_size(128 * 1024 * 1024); // 128 MB for UTXO
                }

                if *name == CF_BLOCKS {
                    // Blocks: large sequential reads, use large blocks
                    block_opts.set_block_size(128 * 1024); // 128 KB blocks
                }

                cf_opts.set_block_based_table_factory(&block_opts);
                ColumnFamilyDescriptor::new(*name, cf_opts)
            })
            .collect();

        let db = DB::open_cf_descriptors(&db_opts, path, cf_descriptors)?;
        Ok(Self { db })
    }
}
