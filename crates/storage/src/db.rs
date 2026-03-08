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
        db_opts.set_max_total_wal_size(64 * 1024 * 1024); // 64 MB

        // Configure per-column-family options
        let cf_descriptors: Vec<ColumnFamilyDescriptor> = ALL_COLUMN_FAMILIES
            .iter()
            .map(|name| {
                let mut cf_opts = Options::default();

                // UTXO column family: add bloom filters for fast existence checks
                if *name == CF_UTXO {
                    let mut block_opts = rocksdb::BlockBasedOptions::default();
                    block_opts.set_bloom_filter(10.0, false);
                    cf_opts.set_block_based_table_factory(&block_opts);
                }

                // Blocks column family: larger block size for sequential reads during IBD
                if *name == CF_BLOCKS {
                    let mut block_opts = rocksdb::BlockBasedOptions::default();
                    block_opts.set_block_size(64 * 1024); // 64 KB blocks
                    cf_opts.set_block_based_table_factory(&block_opts);
                }

                ColumnFamilyDescriptor::new(*name, cf_opts)
            })
            .collect();

        let db = DB::open_cf_descriptors(&db_opts, path, cf_descriptors)?;
        Ok(Self { db })
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
}
