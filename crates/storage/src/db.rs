//! Core database wrapper for RocksDB.
//!
//! Provides a type-safe interface to the underlying RocksDB instance with
//! column family management and atomic batch writes.

use crate::columns::*;
use rocksdb::{ColumnFamilyDescriptor, Options, WriteBatch, DB};
use std::mem::ManuallyDrop;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

// ============================================================
// METADATA KEYS
// ============================================================

/// Metadata key for the best (tip) block hash.
pub const META_BEST_BLOCK_HASH: &[u8] = b"best_block_hash";

/// Metadata key for the best block height.
pub const META_BEST_HEIGHT: &[u8] = b"best_height";

/// Metadata key for the prune height (blocks below this have been pruned).
pub const META_PRUNE_HEIGHT: &[u8] = b"prune_height";

/// Metadata key for the reorg-retention prune watermark (Unit B).
///
/// Records the highest active-chain height whose block body + undo have
/// been deleted by the reorg-retention pruner (the storage-economy prune
/// that keeps only a bounded ~288-block reorg window, distinct from the
/// BIP-159 manual/auto prune tracked by [`META_PRUNE_HEIGHT`]).
///
/// ADDITIVE — introduced WITHOUT a `CURRENT_DB_VERSION` bump because it
/// neither changes any existing on-disk encoding nor invalidates a
/// chainstate that lacks it. A datadir written before Unit B simply has
/// no value under this key; `get_reorg_prune_height` then returns `None`
/// and the connect loop seeds the watermark at the current retention
/// floor (so it begins pruning forward from there rather than re-walking
/// the entire buried history). The byte string is distinct from every
/// other `META_*` key above (notably `prune_height`) so there is no
/// collision in `CF_META`.
pub const META_REORG_PRUNE_HEIGHT: &[u8] = b"reorg_prune_height";

/// Metadata key for an in-progress genesis→snapshot-base header/body backfill.
///
/// Stores the original assumeutxo index floor (u32 LE) so a restart can
/// resume after height 1 is already indexed (at which point
/// [`crate::block_store::BlockStore::snapshot_index_floor`] returns `None`
/// even though a gap remains below the tail). Additive, no format bump:
/// a datadir without the key is "no backfill in progress".
pub const META_HISTORICAL_BACKFILL_FLOOR: &[u8] = b"historical_backfill_floor";

/// Metadata key: progress marker of the historical backfill's header hole
/// (u32 LE). Every height in `1..=marker` has a `CF_HEIGHT_INDEX` row.
///
/// Written after the rows it vouches for, so after a crash it can only be
/// behind the truth, never ahead. [`crate::historical_backfill::HistoricalBackfill::detect`]
/// resumes its contiguity walk here instead of at height 1: without it every
/// boot re-read ~942k height rows (2026-10-01 mainnet, 20+ min before P2P).
/// Additive, no format bump: an absent key means "walk from height 1 once".
pub const META_HISTORICAL_BACKFILL_HEADER_TIP: &[u8] = b"historical_backfill_header_tip";

/// Metadata key: progress marker of the historical backfill's body fill
/// (u32 LE). Every height in `1..marker` has a stored body (the marker is the
/// first height that may still be missing). Same write-after rule and the
/// same purpose as [`META_HISTORICAL_BACKFILL_HEADER_TIP`]: without it every
/// boot re-read every stored historical body (multi-GB) to find the first gap.
pub const META_HISTORICAL_BACKFILL_NEXT_BODY: &[u8] = b"historical_backfill_next_body";

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

/// Per-thread count of point reads (`get_cf` / `contains_key`) for tests
/// that bound how much RocksDB work a single call does (e.g. the
/// historical-backfill body scan that wedged the mainnet main task,
/// 2026-09-26). Thread-local so parallel tests do not see each other.
#[cfg(test)]
pub(crate) mod test_read_counter {
    use std::cell::Cell;
    thread_local! {
        static READS: Cell<u64> = const { Cell::new(0) };
    }
    pub(crate) fn bump() {
        READS.with(|r| r.set(r.get() + 1));
    }
    /// Reads observed on this thread since it started.
    pub(crate) fn get() -> u64 {
        READS.with(|r| r.get())
    }
}

/// Test gate: a compaction filter blocks in `block_in_filter` until
/// `release`, so close's join of that compaction is observable.
#[cfg(test)]
struct CompactionStall {
    started: AtomicBool,
    release: AtomicBool,
}

#[cfg(test)]
impl CompactionStall {
    fn new() -> Self {
        Self {
            started: AtomicBool::new(false),
            release: AtomicBool::new(false),
        }
    }

    fn block_in_filter(&self) {
        self.started.store(true, Ordering::Release);
        while !self.release.load(Ordering::Acquire) {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    fn release(&self) {
        self.release.store(true, Ordering::Release);
    }
}

/// The main database handle wrapping RocksDB.
///
/// Provides methods for reading and writing data across column families,
/// with support for atomic batch writes.
pub struct ChainDb {
    /// `ManuallyDrop` so shutdown can skip `rocksdb_close`. That close
    /// joins every background compaction (`DBImpl::CloseHelper`); on a
    /// scratch datadir the join ran 60s+ after "Shutdown complete"
    /// (2026-10-03).
    db: ManuallyDrop<DB>,
    /// Counter for the number of `write_batch` calls. Used by tests to
    /// assert the multi-block-atomicity invariant: a multi-block reorg
    /// must commit exactly one RocksDB batch (Pattern D fleet-wide
    /// closure, 2026-05-07).
    write_batch_count: AtomicU64,
    /// Set by [`ChainDb::cancel_background_compactions`]. Drop then does
    /// not call `rocksdb_close`.
    skip_close_wait: AtomicBool,
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
            db: ManuallyDrop::new(db),
            write_batch_count: AtomicU64::new(0),
            skip_close_wait: AtomicBool::new(false),
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
        #[cfg(test)]
        test_read_counter::bump();
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
    ///
    /// Uses a pinned read, so a multi-MB value (a block body) is not copied
    /// into a fresh `Vec` just to be dropped.
    pub fn contains_key(&self, cf_name: &str, key: &[u8]) -> Result<bool, StorageError> {
        #[cfg(test)]
        test_read_counter::bump();
        let cf = self
            .db
            .cf_handle(cf_name)
            .ok_or_else(|| StorageError::Corruption(format!("missing column family: {}", cf_name)))?;
        Ok(self.db.get_pinned_cf(&cf, key)?.is_some())
    }

    /// [`Self::contains_key`] that does not populate the block cache. For
    /// one-shot background walks over cold history, which must not evict the
    /// working set that validation reads.
    pub fn contains_key_uncached(&self, cf_name: &str, key: &[u8]) -> Result<bool, StorageError> {
        #[cfg(test)]
        test_read_counter::bump();
        let cf = self
            .db
            .cf_handle(cf_name)
            .ok_or_else(|| StorageError::Corruption(format!("missing column family: {}", cf_name)))?;
        let mut ro = rocksdb::ReadOptions::default();
        ro.fill_cache(false);
        Ok(self.db.get_pinned_cf_opt(&cf, key, &ro)?.is_some())
    }

    /// Forward iteration over `cf_name` starting at the first key `>= from`.
    /// Read errors are yielded. Each yielded item counts as one read for the
    /// test read counter.
    #[allow(clippy::type_complexity)]
    pub fn iter_cf_from<'a>(
        &'a self,
        cf_name: &str,
        from: &[u8],
    ) -> Result<impl Iterator<Item = Result<(Box<[u8]>, Box<[u8]>), StorageError>> + 'a, StorageError>
    {
        let cf = self
            .db
            .cf_handle(cf_name)
            .ok_or_else(|| StorageError::Corruption(format!("missing column family: {}", cf_name)))?;
        Ok(self
            .db
            .iterator_cf(&cf, rocksdb::IteratorMode::From(from, rocksdb::Direction::Forward))
            .map(|r| {
                #[cfg(test)]
                test_read_counter::bump();
                r.map_err(StorageError::from)
            }))
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

    /// Take a point-in-time snapshot of the whole database (every column
    /// family). Reads through [`Self::get_cf_at`] / [`Self::iter_cf_at`] see
    /// exactly the state at this instant, however many batches commit after.
    ///
    /// `gettxoutsetinfo` uses this so the coin walk and the best-block
    /// pointer it reports come from ONE state (Core's `ComputeUTXOStats`
    /// reads `pcursor->GetBestBlock()` off the cursor it then iterates), and
    /// so the walk can run with no lock held while blocks keep connecting.
    pub fn snapshot(&self) -> rocksdb::Snapshot<'_> {
        self.db.snapshot()
    }

    /// Point read of `key` in `cf_name` as of `snap`.
    pub fn get_cf_at(
        &self,
        snap: &rocksdb::Snapshot<'_>,
        cf_name: &str,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .ok_or_else(|| StorageError::Corruption(format!("missing column family: {}", cf_name)))?;
        Ok(snap.get_cf(&cf, key)?)
    }

    /// Forward iteration over `cf_name` as of `snap`. Unlike [`Self::iter_cf`]
    /// a read error is yielded, not silently skipped, and the walk does not
    /// populate the block cache (a full-set scan must not evict the working
    /// set validation reads).
    #[allow(clippy::type_complexity)]
    pub fn iter_cf_at<'a>(
        &'a self,
        snap: &'a rocksdb::Snapshot<'a>,
        cf_name: &str,
    ) -> Result<impl Iterator<Item = Result<(Box<[u8]>, Box<[u8]>), StorageError>> + 'a, StorageError>
    {
        let cf = self
            .db
            .cf_handle(cf_name)
            .ok_or_else(|| StorageError::Corruption(format!("missing column family: {}", cf_name)))?;
        let mut ro = rocksdb::ReadOptions::default();
        ro.fill_cache(false);
        Ok(snap
            .iterator_cf_opt(&cf, ro, rocksdb::IteratorMode::Start)
            .map(|r| r.map_err(StorageError::from)))
    }

    /// Open the database with optimized performance settings for IBD.
    ///
    /// This configuration is tuned for maximum throughput during initial block
    /// download, with larger write buffers, more aggressive compaction, and
    /// optimized block caching.
    ///
    /// Key optimizations:
    /// - 64 MB write buffers (reduces compaction frequency during heavy writes)
    /// - Shared block cache sized from the `--dbcache` split (default 512 MiB);
    ///   keeps hot SST index/filter/data blocks in memory
    /// - Bloom filters on UTXO column family (reduces disk reads)
    /// - Level compaction with dynamic level sizes
    /// - Background jobs for parallel compaction
    pub fn open_optimized(path: &Path, block_cache_bytes: usize) -> Result<Self, StorageError> {
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

        // Block cache: caller-supplied size (the RocksDB-block-cache share of
        // the `--dbcache` budget; see `split_dbcache` in main.rs), shared
        // across all column families. Was hardcoded 512 MiB; now scales with
        // `--dbcache`.
        let cache = rocksdb::Cache::new_lru_cache(block_cache_bytes);

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
            db: ManuallyDrop::new(db),
            write_batch_count: AtomicU64::new(0),
            skip_close_wait: AtomicBool::new(false),
        };
        handle.check_and_init_version()?;
        Ok(handle)
    }

    /// Stop background compactions, fsync the WAL, and make [`Drop`] skip
    /// `rocksdb_close`'s join of in-flight ones.
    ///
    /// `cancel_all_background_work(false)` sets `shutting_down_` and returns.
    /// A running compaction sees the flag in its iterator loop and aborts
    /// after the write or `fdatasync` it is in; its output SST is not in the
    /// MANIFEST, so the next open drops it — the same recovery as a crash.
    /// Without the flag, nothing stops it: on a scratch copy of mainnet
    /// (2026-10-03) the process sat in `PosixEnv::JoinThreadsOnExit` at exit
    /// for 320 s+ after "Shutdown complete", joining an L0 compaction of the
    /// blocks CF that ran to completion.
    ///
    /// Cancel FIRST, then fsync the WAL: the compaction's writeback is what
    /// makes an fsync slow on this box. Do NOT flip `disable_auto_compactions`
    /// here: every `SetOptions` call writes and fsyncs a new OPTIONS file, and
    /// one per column family cost 67-75 s under I/O load (gdb: `SetOptions ->
    /// WriteOptionsFile -> fsync`). `shutting_down_` already stops new
    /// compactions from being scheduled.
    pub fn cancel_background_compactions(&self) -> Result<(), StorageError> {
        // wait=false sets shutting_down and returns. It does not join.
        self.db.cancel_all_background_work(false);
        self.skip_close_wait.store(true, Ordering::Release);
        // With the default WAL, memtables are recoverable from it;
        // `has_unpersisted_data_` is set only for WAL-disabled writes, which
        // this node does not issue. FlushWAL does not check shutting_down_.
        self.db.flush_wal(true)?;
        Ok(())
    }

    /// Block in a compaction filter until `stall` is released, so a test
    /// can measure that `rocksdb_close` waits for that compaction.
    #[cfg(test)]
    fn open_with_compaction_stall(
        path: &Path,
        stall: std::sync::Arc<CompactionStall>,
    ) -> Result<Self, StorageError> {
        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        db_opts.set_max_background_jobs(2);
        // A stalled compaction must not stop the flushes that create the
        // L0 files which trigger it.
        db_opts.set_level_zero_stop_writes_trigger(64);
        db_opts.set_level_zero_slowdown_writes_trigger(32);

        let cf_descriptors: Vec<ColumnFamilyDescriptor> = ALL_COLUMN_FAMILIES
            .iter()
            .map(|name| {
                let mut cf_opts = Options::default();
                cf_opts.set_compression_type(rocksdb::DBCompressionType::None);
                cf_opts.set_level_zero_file_num_compaction_trigger(2);
                cf_opts.set_write_buffer_size(8 * 1024 * 1024);
                let gate = std::sync::Arc::clone(&stall);
                cf_opts.set_compaction_filter("stall-compaction", move |_level, _key, _value| {
                    gate.block_in_filter();
                    rocksdb::CompactionDecision::Keep
                });
                ColumnFamilyDescriptor::new(*name, cf_opts)
            })
            .collect();

        let db = DB::open_cf_descriptors(&db_opts, path, cf_descriptors)?;
        let handle = Self {
            db: ManuallyDrop::new(db),
            write_batch_count: AtomicU64::new(0),
            skip_close_wait: AtomicBool::new(false),
        };
        handle.check_and_init_version()?;
        Ok(handle)
    }

    #[cfg(test)]
    fn flush_cf(&self, cf_name: &str) -> Result<(), StorageError> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .ok_or_else(|| StorageError::Corruption(format!("missing column family: {cf_name}")))?;
        self.db.flush_cf(&cf)?;
        Ok(())
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

impl Drop for ChainDb {
    fn drop(&mut self) {
        if self.skip_close_wait.load(Ordering::Acquire) {
            // Leave the DB allocated. `rocksdb_close` would join the
            // compaction threads; process exit reclaims them instead.
            return;
        }
        // SAFETY: `db` was set at open and this is the only drop of it.
        unsafe { ManuallyDrop::drop(&mut self.db) }
    }
}

#[cfg(test)]
mod close_wait_tests {
    use super::*;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    /// Write overlapping L0 files until the compaction filter blocks.
    fn drive_until_compaction_starts(db: &ChainDb, stall: &CompactionStall) {
        let value = vec![0x5Au8; 2048];
        for _round in 0..8 {
            for k in 0..40u32 {
                db.put_cf(CF_META, &k.to_be_bytes(), &value)
                    .expect("put");
            }
            db.flush_cf(CF_META).expect("flush");
            let deadline = Instant::now() + Duration::from_millis(400);
            while Instant::now() < deadline {
                if stall.started.load(Ordering::Acquire) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        panic!("compaction filter never ran; the close-wait instrument is blind");
    }

    /// Gate 5: `rocksdb_close` joins background compactions, so a process
    /// that has already logged "Shutdown complete" stays alive until they
    /// finish (scratch stops 60s+, 2026-10-03).
    ///
    /// The plain drop must wait out a stalled compaction — otherwise this
    /// test cannot see the bug. `cancel_background_compactions` then drop
    /// must return while that compaction is still stalled.
    #[test]
    fn close_skips_background_compaction() {
        // --- instrument: a normal close waits for the stalled compaction ---
        {
            let dir = TempDir::new().expect("tempdir");
            let stall = Arc::new(CompactionStall::new());
            let db =
                ChainDb::open_with_compaction_stall(dir.path(), Arc::clone(&stall)).expect("open");
            db.put_cf(CF_META, b"persist-key", b"persist-val")
                .expect("seed");
            drive_until_compaction_starts(&db, &stall);
            let gate = Arc::clone(&stall);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(1500));
                gate.release();
            });
            let started = Instant::now();
            drop(db);
            let waited = started.elapsed();
            eprintln!(
                "plain drop waited {} ms while a compaction was stalled",
                waited.as_millis()
            );
            assert!(
                waited >= Duration::from_millis(1200),
                "instrument blind: plain drop returned in {} ms; rocksdb_close must wait for the stalled compaction",
                waited.as_millis()
            );
            let reopened = ChainDb::open(dir.path()).expect("reopen after normal close");
            assert_eq!(
                reopened
                    .get_cf(CF_META, b"persist-key")
                    .expect("get")
                    .as_deref(),
                Some(b"persist-val".as_slice())
            );
        }

        // --- fix: cancel, then drop, returns while the compaction is stalled ---
        {
            let dir = TempDir::new().expect("tempdir");
            let stall = Arc::new(CompactionStall::new());
            let db =
                ChainDb::open_with_compaction_stall(dir.path(), Arc::clone(&stall)).expect("open");
            drive_until_compaction_starts(&db, &stall);
            // Backstop so a close that still joins fails the assertion
            // instead of hanging the suite.
            let gate = Arc::clone(&stall);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(3000));
                gate.release();
            });
            let started = Instant::now();
            db.cancel_background_compactions()
                .expect("cancel background compactions");
            drop(db);
            let waited = started.elapsed();
            eprintln!(
                "cancel_background_compactions + drop waited {} ms",
                waited.as_millis()
            );
            // Unblock the compaction thread now that we have the measurement,
            // so it does not sit in the filter until the backstop fires.
            stall.release();
            assert!(
                waited < Duration::from_millis(1000),
                "close waited {} ms for a stalled compaction (bound 1000 ms)",
                waited.as_millis()
            );
            // The handle was leaked on purpose; do not delete the dir out
            // from under a compaction that may still be finishing.
            std::mem::forget(dir);
        }

        let main_rs = include_str!("../../../rustoshi/src/main.rs");
        let shutdown = main_rs
            .find("// GRACEFUL SHUTDOWN")
            .expect("shutdown section missing");
        let complete = main_rs
            .find("tracing::info!(\"Shutdown complete\");")
            .expect("Shutdown complete log missing");
        assert!(shutdown < complete);
        let window = &main_rs[shutdown..complete];
        assert!(
            window.contains("cancel_background_compactions()"),
            "shutdown must cancel RocksDB compactions before logging Shutdown complete"
        );
    }
}
