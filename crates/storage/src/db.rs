//! Core database wrapper for RocksDB.
//!
//! Provides a type-safe interface to the underlying RocksDB instance with
//! column family management and atomic batch writes.

use crate::columns::*;
use rocksdb::{ColumnFamilyDescriptor, Options, WriteBatch, DB};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

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
///
/// Bumped to 2 on 2026-05-27 (perf(storage): binary encoding for
/// CoinEntry / BlockIndexEntry / UndoData / TxIndexEntry).
///
/// Version history:
/// - 1: original `serde_json::to_vec` encoding for `CoinEntry`,
///      `BlockIndexEntry`, `UndoData`, `TxIndexEntry` in
///      `block_store.rs` and `utxo_cache.rs` (~5-10× slower + ~4×
///      larger on disk than the binary format below).
/// - 2: hand-rolled binary encoding for all four types
///      (`block_store::format_v2`). See the `_rustoshi-ibd-pace-decay`
///      diagnosis doc 2026-05-27 follow-up note for context. Format
///      is NOT wire-compatible with v1; a v1 chainstate must be
///      re-IBDed (`rm -rf <datadir>/chainstate`).
pub const CURRENT_DB_VERSION: u32 = 2;

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

    /// On-disk chainstate format version does not match the binary.
    ///
    /// The on-disk encoding for `CoinEntry`, `BlockIndexEntry`, `UndoData`,
    /// and `TxIndexEntry` changed in `CURRENT_DB_VERSION = 2`
    /// (perf(storage): binary encoding, 2026-05-27). The new format is
    /// NOT backwards-compatible with v1 (`serde_json`) data. An operator
    /// running a v2 binary against a v1 datadir must delete the
    /// chainstate and re-IBD (`rm -rf <datadir>/chainstate`).
    ///
    /// This error is intentionally loud rather than attempting a silent
    /// in-place migration: silently reading v1 JSON as v2 binary would
    /// produce corrupted `CoinEntry` lookups and wedge the node with
    /// `MissingInput` errors during validation.
    #[error(
        "chainstate format version mismatch: on-disk = v{on_disk}, binary expects v{expected}. \
         The chainstate encoding changed in v{expected} and is not backwards-compatible. \
         Delete the chainstate directory and re-IBD: `rm -rf <datadir>/chainstate`."
    )]
    VersionMismatch {
        /// Version found on disk.
        on_disk: u32,
        /// Version this binary expects.
        expected: u32,
    },
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
    /// Counter for the number of `write_batch` calls. Used by tests to
    /// assert the multi-block-atomicity invariant: a multi-block reorg
    /// must commit exactly one RocksDB batch (Pattern D fleet-wide
    /// closure, 2026-05-07).
    write_batch_count: AtomicU64,
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
        let handle = Self {
            db,
            write_batch_count: AtomicU64::new(0),
        };
        handle.check_and_init_version()?;
        Ok(handle)
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
        self.write_batch_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Number of `write_batch` calls observed by this handle.
    ///
    /// Exposed for tests that need to assert the multi-block-atomicity
    /// invariant: a multi-block reorg must commit exactly one batch.
    /// See `tests::reorg_commits_single_batch_for_multi_block_swap`
    /// (Pattern D fleet-wide closure, 2026-05-07).
    pub fn write_batch_count(&self) -> u64 {
        self.write_batch_count.load(Ordering::Relaxed)
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
    #[allow(clippy::type_complexity)]
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
        let handle = Self {
            db,
            write_batch_count: AtomicU64::new(0),
        };
        handle.check_and_init_version()?;
        Ok(handle)
    }

    /// Check the on-disk chainstate format version and either:
    ///   - write `CURRENT_DB_VERSION` if the DB is fresh (no version key
    ///     AND no best-block-hash key), OR
    ///   - succeed silently if the on-disk version matches, OR
    ///   - return `StorageError::VersionMismatch` if a different version
    ///     is on disk (i.e. an incompatible chainstate from an older
    ///     binary — the operator must re-IBD).
    ///
    /// This runs at the end of every `open*` call so that callers see a
    /// loud, actionable error at startup rather than corrupted reads
    /// later. It uses raw `META_DB_VERSION` (4 bytes LE u32) so the
    /// check has no dependency on the higher-level `block_store`
    /// encoders (which are themselves version-gated).
    fn check_and_init_version(&self) -> Result<(), StorageError> {
        // Pull both the version key and the best-block key so we can
        // tell "fresh DB" (neither present) apart from "v1 DB with no
        // version key" (best-block-hash present but version absent).
        let version_bytes = self.get_cf(CF_META, META_DB_VERSION)?;
        let has_data = self.get_cf(CF_META, META_BEST_BLOCK_HASH)?.is_some();

        match version_bytes {
            Some(bytes) => {
                if bytes.len() != 4 {
                    return Err(StorageError::Corruption(format!(
                        "META_DB_VERSION has invalid length {}: expected 4",
                        bytes.len()
                    )));
                }
                let mut buf = [0u8; 4];
                buf.copy_from_slice(&bytes);
                let on_disk = u32::from_le_bytes(buf);
                if on_disk == CURRENT_DB_VERSION {
                    Ok(())
                } else {
                    Err(StorageError::VersionMismatch {
                        on_disk,
                        expected: CURRENT_DB_VERSION,
                    })
                }
            }
            None if has_data => {
                // Version key absent but data present → this is a v1
                // chainstate from a binary that predated the version
                // bump. The on-disk `serde_json` encoding cannot be
                // safely re-interpreted as the v2 binary encoding;
                // direct the operator to re-IBD.
                Err(StorageError::VersionMismatch {
                    on_disk: 1,
                    expected: CURRENT_DB_VERSION,
                })
            }
            None => {
                // Fresh DB: stamp the current version so subsequent
                // opens go down the matching-version path above.
                self.put_cf(
                    CF_META,
                    META_DB_VERSION,
                    &CURRENT_DB_VERSION.to_le_bytes(),
                )?;
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod version_check_tests {
    use super::*;
    use tempfile::TempDir;

    /// A freshly-created DB must be stamped with `CURRENT_DB_VERSION`
    /// on open, so the next open succeeds via the matching-version
    /// path rather than re-stamping.
    #[test]
    fn fresh_db_gets_stamped_with_current_version() {
        let dir = TempDir::new().expect("tempdir");
        {
            let db = ChainDb::open(dir.path()).expect("first open");
            let bytes = db
                .get_cf(CF_META, META_DB_VERSION)
                .expect("get version")
                .expect("version key present");
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&bytes);
            assert_eq!(u32::from_le_bytes(buf), CURRENT_DB_VERSION);
        }
        // Reopen — must succeed without re-stamping.
        let _ = ChainDb::open(dir.path()).expect("reopen with matching version");
    }

    /// If the DB on disk has a different version key, open must fail
    /// with `VersionMismatch` rather than silently misreading entries.
    #[test]
    fn mismatched_version_returns_version_mismatch_error() {
        let dir = TempDir::new().expect("tempdir");
        // Create a v=99 chainstate by hand.
        {
            let db = ChainDb::open(dir.path()).expect("first open");
            // Overwrite the version key with a forged value.
            db.put_cf(CF_META, META_DB_VERSION, &99u32.to_le_bytes())
                .expect("put forged version");
        }
        match ChainDb::open(dir.path()) {
            Err(StorageError::VersionMismatch { on_disk, expected }) => {
                assert_eq!(on_disk, 99);
                assert_eq!(expected, CURRENT_DB_VERSION);
            }
            Err(other) => panic!("expected VersionMismatch, got {:?}", other),
            Ok(_) => panic!("expected error, got success"),
        }
    }

    /// A DB with data but no version key must be detected as a v1
    /// chainstate (the pre-v2 binary never wrote the version key) and
    /// refused with `VersionMismatch { on_disk: 1, expected: 2 }` —
    /// this is the path operators will hit when upgrading a pre-fix
    /// binary across a chainstate format bump.
    #[test]
    fn legacy_v1_db_without_version_key_returns_mismatch() {
        let dir = TempDir::new().expect("tempdir");
        {
            let db = ChainDb::open(dir.path()).expect("first open");
            // Simulate v1: drop the version key but seed the best-block
            // key so the heuristic identifies the DB as non-empty.
            db.delete_cf(CF_META, META_DB_VERSION)
                .expect("delete version");
            db.put_cf(CF_META, META_BEST_BLOCK_HASH, &[0u8; 32])
                .expect("seed best-block");
        }
        match ChainDb::open(dir.path()) {
            Err(StorageError::VersionMismatch { on_disk, expected }) => {
                assert_eq!(on_disk, 1);
                assert_eq!(expected, CURRENT_DB_VERSION);
            }
            Err(other) => panic!("expected VersionMismatch, got {:?}", other),
            Ok(_) => panic!("expected error, got success"),
        }
    }
}
