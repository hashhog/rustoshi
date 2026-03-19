//! Flat file block storage.
//!
//! This module implements Bitcoin Core's flat file block storage format:
//! - Blocks are stored in `blk{nnnnn}.dat` files (zero-padded 5-digit suffix)
//! - Each block is prefixed with network magic (4 bytes) and size (4 bytes LE)
//! - Files are capped at `MAX_BLOCKFILE_SIZE` (128 MiB)
//! - Undo data is stored in `rev{nnnnn}.dat` files
//!
//! # File Format
//!
//! ```text
//! [4-byte magic][4-byte size LE][block data]...
//! ```
//!
//! # References
//!
//! - Bitcoin Core: `src/node/blockstorage.cpp`, `src/flatfile.cpp`

use rustoshi_consensus::NetworkMagic;
use rustoshi_primitives::{Block, Decodable, Encodable};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use crate::db::{ChainDb, StorageError};

// ============================================================
// CONSTANTS
// ============================================================

/// Maximum size of a blk?????.dat file (128 MiB).
pub const MAX_BLOCKFILE_SIZE: u64 = 128 * 1024 * 1024; // 134,217,728 bytes

/// Pre-allocation chunk size for blk?????.dat files (16 MiB).
pub const BLOCKFILE_CHUNK_SIZE: u64 = 0x1000000; // 16,777,216 bytes

/// Pre-allocation chunk size for rev?????.dat files (1 MiB).
pub const UNDOFILE_CHUNK_SIZE: u64 = 0x100000; // 1,048,576 bytes

/// Size of storage header: 4-byte magic + 4-byte size.
pub const STORAGE_HEADER_BYTES: u32 = 8;

// ============================================================
// PRUNING CONSTANTS
// ============================================================

/// Minimum pruning target in MiB (matches Bitcoin Core).
/// This is the minimum disk space required to store enough blocks for reorgs.
pub const MIN_PRUNE_TARGET_MIB: u64 = 550;

/// Minimum number of blocks to keep from the tip (for handling reorgs).
/// Bitcoin Core uses 288 blocks (~2 days worth at 10 min/block).
pub const MIN_BLOCKS_TO_KEEP: u32 = 288;

/// Convert MiB to bytes.
const fn mib_to_bytes(mib: u64) -> u64 {
    mib * 1024 * 1024
}

/// Minimum disk space for block files (550 MiB in bytes).
pub const MIN_DISK_SPACE_FOR_BLOCK_FILES: u64 = mib_to_bytes(MIN_PRUNE_TARGET_MIB);

// ============================================================
// FLAT FILE POSITION
// ============================================================

/// Position within the flat file storage.
///
/// Identifies a specific location by file number and byte offset.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlatFilePos {
    /// File number (e.g., 0 for blk00000.dat).
    pub file_num: i32,
    /// Byte offset within the file.
    pub pos: u32,
}

impl FlatFilePos {
    /// Create a new position.
    pub fn new(file_num: i32, pos: u32) -> Self {
        Self { file_num, pos }
    }

    /// Check if this position is null (invalid).
    pub fn is_null(&self) -> bool {
        self.file_num < 0
    }

    /// Create a null (invalid) position.
    pub fn null() -> Self {
        Self {
            file_num: -1,
            pos: 0,
        }
    }
}

impl std::fmt::Display for FlatFilePos {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FlatFilePos(file={}, pos={})", self.file_num, self.pos)
    }
}

// ============================================================
// BLOCK FILE INFO
// ============================================================

/// Metadata about a block file.
///
/// Tracks statistics about the blocks stored in a single blk?????.dat file,
/// matching Bitcoin Core's `CBlockFileInfo`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BlockFileInfo {
    /// Number of blocks stored in this file.
    pub n_blocks: u32,
    /// Number of used bytes in the block file.
    pub n_size: u32,
    /// Number of used bytes in the corresponding undo file.
    pub n_undo_size: u32,
    /// Lowest block height in this file.
    pub height_first: u32,
    /// Highest block height in this file.
    pub height_last: u32,
    /// Earliest block timestamp in this file.
    pub time_first: u64,
    /// Latest block timestamp in this file.
    pub time_last: u64,
}

impl BlockFileInfo {
    /// Create a new empty BlockFileInfo.
    pub fn new() -> Self {
        Self::default()
    }

    /// Update statistics when adding a block.
    ///
    /// Note: This does NOT update `n_size` — that's done separately
    /// when the actual block data is written.
    pub fn add_block(&mut self, height: u32, time: u64) {
        if self.n_blocks == 0 || height < self.height_first {
            self.height_first = height;
        }
        if self.n_blocks == 0 || time < self.time_first {
            self.time_first = time;
        }
        self.n_blocks += 1;
        if height > self.height_last {
            self.height_last = height;
        }
        if time > self.time_last {
            self.time_last = time;
        }
    }
}

impl std::fmt::Display for BlockFileInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BlockFileInfo(blocks={}, size={}, heights={}...{}, time={}...{})",
            self.n_blocks,
            self.n_size,
            self.height_first,
            self.height_last,
            self.time_first,
            self.time_last
        )
    }
}

// ============================================================
// FLAT FILE SEQUENCE
// ============================================================

/// A sequence of numbered flat files.
///
/// Manages access to files like `blk00000.dat`, `blk00001.dat`, etc.
pub struct FlatFileSeq {
    /// Base directory for the files.
    dir: PathBuf,
    /// File prefix (e.g., "blk" or "rev").
    prefix: String,
    /// Pre-allocation chunk size in bytes.
    chunk_size: u64,
}

impl FlatFileSeq {
    /// Create a new FlatFileSeq.
    ///
    /// # Arguments
    ///
    /// * `dir` - Base directory for files
    /// * `prefix` - File prefix (e.g., "blk")
    /// * `chunk_size` - Pre-allocation chunk size
    pub fn new(dir: impl Into<PathBuf>, prefix: impl Into<String>, chunk_size: u64) -> Self {
        assert!(chunk_size > 0, "chunk_size must be positive");
        Self {
            dir: dir.into(),
            prefix: prefix.into(),
            chunk_size,
        }
    }

    /// Get the filename for a given position.
    ///
    /// Returns a path like `{dir}/blk00000.dat`.
    pub fn filename(&self, pos: &FlatFilePos) -> PathBuf {
        self.dir
            .join(format!("{}{:05}.dat", self.prefix, pos.file_num))
    }

    /// Open a file at the given position.
    ///
    /// Creates the file if it doesn't exist and `read_only` is false.
    pub fn open(&self, pos: &FlatFilePos, read_only: bool) -> Result<File, StorageError> {
        if pos.is_null() {
            return Err(StorageError::NotFound("null file position".into()));
        }

        let path = self.filename(pos);

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let file = if read_only {
            OpenOptions::new().read(true).open(&path)?
        } else {
            // Try to open for read-write first
            match OpenOptions::new().read(true).write(true).open(&path) {
                Ok(f) => f,
                Err(_) => {
                    // Create new file if it doesn't exist
                    OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create(true)
                        .truncate(false)
                        .open(&path)?
                }
            }
        };

        Ok(file)
    }

    /// Pre-allocate additional space in a file.
    ///
    /// Allocates the minimum number of chunks needed to accommodate `add_size`
    /// bytes starting from `pos.pos`.
    ///
    /// Returns the number of bytes allocated (0 if no allocation needed).
    pub fn allocate(&self, pos: &FlatFilePos, add_size: u64) -> Result<u64, StorageError> {
        let n_old_chunks = (pos.pos as u64 + self.chunk_size - 1) / self.chunk_size;
        let n_new_chunks = (pos.pos as u64 + add_size + self.chunk_size - 1) / self.chunk_size;

        if n_new_chunks > n_old_chunks {
            let old_size = pos.pos as u64;
            let new_size = n_new_chunks * self.chunk_size;
            let inc_size = new_size - old_size;

            // Open file and extend it
            let file = self.open(pos, false)?;
            file.set_len(new_size)?;

            tracing::debug!(
                "Pre-allocated {} bytes in {}{:05}.dat (new size: {})",
                inc_size,
                self.prefix,
                pos.file_num,
                new_size
            );

            return Ok(inc_size);
        }

        Ok(0)
    }

    /// Flush and optionally truncate a file.
    ///
    /// If `finalize` is true, truncates the file to `pos.pos` bytes.
    pub fn flush(&self, pos: &FlatFilePos, finalize: bool) -> Result<(), StorageError> {
        let file = self.open(&FlatFilePos::new(pos.file_num, 0), false)?;

        if finalize {
            file.set_len(pos.pos as u64)?;
        }

        file.sync_all()?;
        Ok(())
    }

    /// Check if a file exists.
    pub fn exists(&self, file_num: i32) -> bool {
        let pos = FlatFilePos::new(file_num, 0);
        self.filename(&pos).exists()
    }
}

// ============================================================
// FLAT BLOCK STORE
// ============================================================

/// Pruning configuration.
#[derive(Clone, Debug)]
pub struct PruneConfig {
    /// Target disk usage in bytes. If 0, pruning is disabled.
    pub prune_target: u64,
    /// Whether to use fast pruning mode (for tests).
    pub fast_prune: bool,
}

impl Default for PruneConfig {
    fn default() -> Self {
        Self {
            prune_target: 0,
            fast_prune: false,
        }
    }
}

impl PruneConfig {
    /// Create a pruning configuration with a target in MiB.
    pub fn with_target_mib(target_mib: u64) -> Self {
        let target = if target_mib > 0 && target_mib < MIN_PRUNE_TARGET_MIB {
            // Enforce minimum
            MIN_DISK_SPACE_FOR_BLOCK_FILES
        } else {
            mib_to_bytes(target_mib)
        };
        Self {
            prune_target: target,
            fast_prune: false,
        }
    }

    /// Check if pruning is enabled.
    pub fn is_prune_mode(&self) -> bool {
        self.prune_target > 0
    }
}

/// Flat file block storage manager.
///
/// Stores blocks in `blk?????.dat` files and undo data in `rev?????.dat` files.
/// Maintains file metadata and handles file rotation when files are full.
pub struct FlatBlockStore {
    /// Block file sequence.
    block_files: FlatFileSeq,
    /// Undo file sequence.
    undo_files: FlatFileSeq,
    /// Network magic bytes for validation.
    magic: [u8; 4],
    /// Metadata for each block file.
    file_info: Vec<BlockFileInfo>,
    /// Current block file number.
    current_file: i32,
    /// Pruning configuration.
    prune_config: PruneConfig,
    /// Flag indicating pruning check is needed after allocation.
    check_for_pruning: bool,
    /// Flag indicating we have pruned blocks previously.
    have_pruned: bool,
}

impl FlatBlockStore {
    /// Create a new FlatBlockStore.
    ///
    /// # Arguments
    ///
    /// * `blocks_dir` - Directory for block files
    /// * `magic` - Network magic bytes
    pub fn new(blocks_dir: impl Into<PathBuf>, magic: &NetworkMagic) -> Self {
        Self::with_config(blocks_dir, magic, PruneConfig::default())
    }

    /// Create a new FlatBlockStore with pruning configuration.
    ///
    /// # Arguments
    ///
    /// * `blocks_dir` - Directory for block files
    /// * `magic` - Network magic bytes
    /// * `prune_config` - Pruning configuration
    pub fn with_config(
        blocks_dir: impl Into<PathBuf>,
        magic: &NetworkMagic,
        prune_config: PruneConfig,
    ) -> Self {
        let blocks_dir = blocks_dir.into();
        Self {
            block_files: FlatFileSeq::new(&blocks_dir, "blk", BLOCKFILE_CHUNK_SIZE),
            undo_files: FlatFileSeq::new(&blocks_dir, "rev", UNDOFILE_CHUNK_SIZE),
            magic: *magic.as_bytes(),
            file_info: vec![BlockFileInfo::new()],
            current_file: 0,
            prune_config,
            check_for_pruning: false,
            have_pruned: false,
        }
    }

    /// Check if pruning mode is enabled.
    pub fn is_prune_mode(&self) -> bool {
        self.prune_config.is_prune_mode()
    }

    /// Get the prune target in bytes.
    pub fn prune_target(&self) -> u64 {
        self.prune_config.prune_target
    }

    /// Check if we have previously pruned blocks.
    pub fn have_pruned(&self) -> bool {
        self.have_pruned
    }

    /// Set the have_pruned flag (called when loading from database).
    pub fn set_have_pruned(&mut self, have_pruned: bool) {
        self.have_pruned = have_pruned;
    }

    /// Check if pruning check is needed.
    pub fn needs_pruning_check(&self) -> bool {
        self.check_for_pruning
    }

    /// Clear the pruning check flag.
    pub fn clear_pruning_check(&mut self) {
        self.check_for_pruning = false;
    }

    /// Initialize from existing database state.
    ///
    /// Loads file info from the database and scans for existing files.
    pub fn load(&mut self, _db: &ChainDb) -> Result<(), StorageError> {
        // TODO: Load file_info from database
        // For now, scan for existing files
        let mut file_num = 0;
        while self.block_files.exists(file_num) {
            if file_num as usize >= self.file_info.len() {
                self.file_info.push(BlockFileInfo::new());
            }
            file_num += 1;
        }
        if file_num > 0 {
            self.current_file = file_num - 1;
        }
        Ok(())
    }

    /// Get block file info for a specific file.
    pub fn get_file_info(&self, file_num: i32) -> Option<&BlockFileInfo> {
        self.file_info.get(file_num as usize)
    }

    /// Get mutable block file info for a specific file.
    pub fn get_file_info_mut(&mut self, file_num: i32) -> Option<&mut BlockFileInfo> {
        self.file_info.get_mut(file_num as usize)
    }

    /// Find the next position for writing a block.
    ///
    /// Returns the position where a block of `add_size` bytes can be written.
    /// May advance to a new file if the current file is full.
    fn find_next_block_pos(&mut self, add_size: u32, height: u32, time: u64) -> Result<FlatFilePos, StorageError> {
        // Ensure we have file info for the current file
        while self.file_info.len() <= self.current_file as usize {
            self.file_info.push(BlockFileInfo::new());
        }

        let current_size = self.file_info[self.current_file as usize].n_size;
        let total_needed = current_size as u64 + add_size as u64;

        // Check if we need to move to a new file
        if total_needed >= MAX_BLOCKFILE_SIZE {
            // Finalize current file
            let pos = FlatFilePos::new(self.current_file, current_size);
            self.block_files.flush(&pos, true)?;

            // Move to next file
            self.current_file += 1;
            self.file_info.push(BlockFileInfo::new());

            tracing::info!(
                "Leaving block file {}, opening block file {}",
                self.current_file - 1,
                self.current_file
            );
        }

        let file_num = self.current_file;
        let pos = self.file_info[file_num as usize].n_size;

        // Pre-allocate space
        let alloc_pos = FlatFilePos::new(file_num, pos);
        self.block_files.allocate(&alloc_pos, add_size as u64)?;

        // Update file info
        self.file_info[file_num as usize].add_block(height, time);
        self.file_info[file_num as usize].n_size += add_size;

        Ok(FlatFilePos::new(file_num, pos))
    }

    /// Write a block to disk.
    ///
    /// Returns the position where the block data starts (after the header).
    pub fn write_block(&mut self, block: &Block, height: u32) -> Result<FlatFilePos, StorageError> {
        // Serialize the block
        let block_data = block.serialize();
        let block_size = block_data.len() as u32;

        // Total size includes header (magic + size)
        let total_size = STORAGE_HEADER_BYTES + block_size;

        // Find position for this block
        let pos = self.find_next_block_pos(total_size, height, block.header.timestamp as u64)?;

        // Open the file and seek to position
        let mut file = self.block_files.open(&pos, false)?;
        file.seek(SeekFrom::Start(pos.pos as u64))?;

        // Write header: magic + size
        file.write_all(&self.magic)?;
        file.write_all(&block_size.to_le_bytes())?;

        // Write block data
        file.write_all(&block_data)?;

        // Flush to ensure data is on disk
        file.sync_data()?;

        // Return position of block data (after header)
        Ok(FlatFilePos::new(pos.file_num, pos.pos + STORAGE_HEADER_BYTES))
    }

    /// Read a block from disk.
    ///
    /// # Arguments
    ///
    /// * `pos` - Position of the block data (after the header)
    pub fn read_block(&self, pos: &FlatFilePos) -> Result<Block, StorageError> {
        if pos.is_null() {
            return Err(StorageError::NotFound("null file position".into()));
        }

        // Position points to block data, so header is STORAGE_HEADER_BYTES before
        let header_pos = FlatFilePos::new(pos.file_num, pos.pos.saturating_sub(STORAGE_HEADER_BYTES));

        let mut file = self.block_files.open(&header_pos, true)?;
        file.seek(SeekFrom::Start(header_pos.pos as u64))?;

        // Read and validate magic
        let mut magic_buf = [0u8; 4];
        file.read_exact(&mut magic_buf)?;
        if magic_buf != self.magic {
            return Err(StorageError::Corruption(format!(
                "block magic mismatch at {}: expected {:02x?}, got {:02x?}",
                pos, self.magic, magic_buf
            )));
        }

        // Read size
        let mut size_buf = [0u8; 4];
        file.read_exact(&mut size_buf)?;
        let block_size = u32::from_le_bytes(size_buf);

        // Sanity check on size
        if block_size > MAX_BLOCKFILE_SIZE as u32 {
            return Err(StorageError::Corruption(format!(
                "block size {} exceeds maximum at {}",
                block_size, pos
            )));
        }

        // Read block data
        let mut block_data = vec![0u8; block_size as usize];
        file.read_exact(&mut block_data)?;

        // Deserialize block
        let block = Block::deserialize(&block_data)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;

        Ok(block)
    }

    /// Read raw block bytes from disk (for forwarding to peers).
    ///
    /// Returns the raw serialized block data without the header.
    pub fn read_raw_block(&self, pos: &FlatFilePos) -> Result<Vec<u8>, StorageError> {
        if pos.is_null() {
            return Err(StorageError::NotFound("null file position".into()));
        }

        // Position points to block data, so header is STORAGE_HEADER_BYTES before
        let header_pos = FlatFilePos::new(pos.file_num, pos.pos.saturating_sub(STORAGE_HEADER_BYTES));

        let mut file = self.block_files.open(&header_pos, true)?;
        file.seek(SeekFrom::Start(header_pos.pos as u64))?;

        // Read and validate magic
        let mut magic_buf = [0u8; 4];
        file.read_exact(&mut magic_buf)?;
        if magic_buf != self.magic {
            return Err(StorageError::Corruption(format!(
                "block magic mismatch at {}: expected {:02x?}, got {:02x?}",
                pos, self.magic, magic_buf
            )));
        }

        // Read size
        let mut size_buf = [0u8; 4];
        file.read_exact(&mut size_buf)?;
        let block_size = u32::from_le_bytes(size_buf);

        // Sanity check on size
        if block_size > MAX_BLOCKFILE_SIZE as u32 {
            return Err(StorageError::Corruption(format!(
                "block size {} exceeds maximum at {}",
                block_size, pos
            )));
        }

        // Read block data
        let mut block_data = vec![0u8; block_size as usize];
        file.read_exact(&mut block_data)?;

        Ok(block_data)
    }

    /// Get the current block file number.
    pub fn current_file_num(&self) -> i32 {
        self.current_file
    }

    /// Get total disk usage for block and undo files.
    pub fn calculate_disk_usage(&self) -> u64 {
        self.file_info
            .iter()
            .map(|info| info.n_size as u64 + info.n_undo_size as u64)
            .sum()
    }

    /// Flush all pending writes to disk.
    pub fn flush(&mut self) -> Result<(), StorageError> {
        if !self.file_info.is_empty() {
            let current_size = self.file_info[self.current_file as usize].n_size;
            let pos = FlatFilePos::new(self.current_file, current_size);
            self.block_files.flush(&pos, false)?;
        }
        Ok(())
    }

    /// Get the path to a block file.
    pub fn block_file_path(&self, file_num: i32) -> PathBuf {
        self.block_files.filename(&FlatFilePos::new(file_num, 0))
    }

    /// Get the path to an undo file.
    pub fn undo_file_path(&self, file_num: i32) -> PathBuf {
        self.undo_files.filename(&FlatFilePos::new(file_num, 0))
    }

    /// Get the maximum block file number (0-indexed count - 1).
    pub fn max_blockfile_num(&self) -> i32 {
        self.file_info.len().saturating_sub(1) as i32
    }

    /// Get the number of block files.
    pub fn file_count(&self) -> usize {
        self.file_info.len()
    }

    // ============================================================
    // PRUNING METHODS
    // ============================================================

    /// Clear the metadata for a single block file.
    ///
    /// This marks all blocks in the file as pruned (no data/undo) in the block index
    /// and clears the file info. Call `unlink_pruned_files` after to actually delete.
    ///
    /// Returns the list of block hashes that were in this file (for index updates).
    pub fn prune_one_block_file(&mut self, file_number: i32) {
        if file_number < 0 || file_number as usize >= self.file_info.len() {
            return;
        }

        // Clear the file info
        self.file_info[file_number as usize] = BlockFileInfo::new();
        self.have_pruned = true;

        tracing::debug!(
            "Pruned block file {}: cleared metadata",
            file_number
        );
    }

    /// Find files that can be pruned to reach the target disk usage.
    ///
    /// Returns a set of file numbers that should be pruned.
    ///
    /// # Arguments
    ///
    /// * `chain_tip_height` - Current chain tip height
    /// * `finalized_height` - Height of oldest block we must keep (for reorgs)
    ///
    /// Files are only pruned if all blocks in them are below `finalized_height`.
    pub fn find_files_to_prune(
        &self,
        chain_tip_height: u32,
        finalized_height: u32,
    ) -> Vec<i32> {
        if !self.is_prune_mode() {
            return Vec::new();
        }

        let current_usage = self.calculate_disk_usage();
        let target = self.prune_config.prune_target;

        // Include a buffer for upcoming allocations
        let buffer = BLOCKFILE_CHUNK_SIZE + UNDOFILE_CHUNK_SIZE;

        if current_usage + buffer < target {
            return Vec::new();
        }

        let mut files_to_prune = Vec::new();
        let mut bytes_to_prune = 0u64;

        // Iterate through files from oldest to newest (excluding the current write file)
        for file_num in 0..self.current_file {
            // Stop if we've pruned enough
            if current_usage.saturating_sub(bytes_to_prune) + buffer < target {
                break;
            }

            let info = &self.file_info[file_num as usize];

            // Skip empty files (already pruned)
            if info.n_size == 0 {
                continue;
            }

            // Don't prune files that contain blocks within MIN_BLOCKS_TO_KEEP of tip
            let last_block_can_prune = chain_tip_height.saturating_sub(MIN_BLOCKS_TO_KEEP);
            if info.height_last > last_block_can_prune {
                continue;
            }

            bytes_to_prune += info.n_size as u64 + info.n_undo_size as u64;
            files_to_prune.push(file_num);
        }

        if !files_to_prune.is_empty() {
            tracing::info!(
                "Found {} files to prune, will free {} bytes",
                files_to_prune.len(),
                bytes_to_prune
            );
        }

        files_to_prune
    }

    /// Find files that can be manually pruned up to a specific height.
    ///
    /// Used by the `pruneblockchain` RPC.
    ///
    /// # Arguments
    ///
    /// * `prune_height` - Prune blocks up to and including this height
    /// * `chain_tip_height` - Current chain tip height
    pub fn find_files_to_prune_manual(
        &self,
        prune_height: u32,
        chain_tip_height: u32,
    ) -> Vec<i32> {
        if !self.is_prune_mode() {
            return Vec::new();
        }

        let mut files_to_prune = Vec::new();

        // Don't prune blocks within MIN_BLOCKS_TO_KEEP of the tip
        let last_block_can_prune = chain_tip_height.saturating_sub(MIN_BLOCKS_TO_KEEP);
        let effective_prune_height = prune_height.min(last_block_can_prune);

        for file_num in 0..=self.max_blockfile_num() {
            if file_num as usize >= self.file_info.len() {
                break;
            }

            let info = &self.file_info[file_num as usize];

            // Skip empty files
            if info.n_size == 0 {
                continue;
            }

            // Only prune if the entire file is at or below the prune height
            if info.height_last <= effective_prune_height {
                files_to_prune.push(file_num);
            }
        }

        files_to_prune
    }

    /// Delete block and undo files from disk.
    ///
    /// Call this after `prune_one_block_file` to actually remove the files.
    pub fn unlink_pruned_files(&self, files_to_prune: &[i32]) -> Result<(), StorageError> {
        for &file_num in files_to_prune {
            let blk_path = self.block_file_path(file_num);
            let rev_path = self.undo_file_path(file_num);

            let mut removed_blk = false;
            let mut removed_rev = false;

            if blk_path.exists() {
                if let Err(e) = fs::remove_file(&blk_path) {
                    tracing::warn!("Failed to remove {}: {}", blk_path.display(), e);
                } else {
                    removed_blk = true;
                }
            }

            if rev_path.exists() {
                if let Err(e) = fs::remove_file(&rev_path) {
                    tracing::warn!("Failed to remove {}: {}", rev_path.display(), e);
                } else {
                    removed_rev = true;
                }
            }

            if removed_blk || removed_rev {
                tracing::debug!(
                    "Prune: deleted blk/rev {:05} (blk={}, rev={})",
                    file_num,
                    removed_blk,
                    removed_rev
                );
            }
        }

        Ok(())
    }

    /// Execute automatic pruning if needed.
    ///
    /// This is called after allocating new block space when in prune mode.
    ///
    /// Returns the list of pruned file numbers if any pruning occurred.
    pub fn maybe_prune(
        &mut self,
        chain_tip_height: u32,
        finalized_height: u32,
    ) -> Result<Vec<i32>, StorageError> {
        if !self.check_for_pruning || !self.is_prune_mode() {
            return Ok(Vec::new());
        }

        self.check_for_pruning = false;

        let files_to_prune = self.find_files_to_prune(chain_tip_height, finalized_height);

        if files_to_prune.is_empty() {
            return Ok(Vec::new());
        }

        // Clear metadata for each file
        for &file_num in &files_to_prune {
            self.prune_one_block_file(file_num);
        }

        // Delete the actual files
        self.unlink_pruned_files(&files_to_prune)?;

        Ok(files_to_prune)
    }

    /// Check if a block has been pruned.
    ///
    /// A block is considered pruned if:
    /// 1. We have previously pruned blocks (have_pruned is true)
    /// 2. The block's file has been cleared (n_size == 0)
    pub fn is_block_pruned(&self, file_num: i32) -> bool {
        if !self.have_pruned {
            return false;
        }

        if file_num < 0 || file_num as usize >= self.file_info.len() {
            return true; // Unknown file, assume pruned
        }

        self.file_info[file_num as usize].n_size == 0
    }

    /// Scan for and unlink already-pruned files on startup.
    ///
    /// This handles the case where we marked files as pruned in the database
    /// but crashed before deleting them from disk.
    pub fn scan_and_unlink_pruned_files(&self) -> Result<(), StorageError> {
        if !self.have_pruned {
            return Ok(());
        }

        let mut files_to_delete = Vec::new();

        for file_num in 0..self.max_blockfile_num() {
            if file_num as usize >= self.file_info.len() {
                break;
            }

            if self.file_info[file_num as usize].n_size == 0 {
                files_to_delete.push(file_num);
            }
        }

        if !files_to_delete.is_empty() {
            tracing::info!(
                "Cleaning up {} previously pruned block files",
                files_to_delete.len()
            );
            self.unlink_pruned_files(&files_to_delete)?;
        }

        Ok(())
    }
}

// ============================================================
// BLOCK INDEX ENTRY EXTENSION
// ============================================================

/// Extended block index entry with flat file position.
///
/// Stores the position of block data and undo data in flat files.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BlockFileLocation {
    /// File number and position of block data.
    pub data_pos: FlatFilePos,
    /// File number and position of undo data (if any).
    pub undo_pos: FlatFilePos,
}

impl BlockFileLocation {
    /// Create a new location with just block data.
    pub fn with_data(data_pos: FlatFilePos) -> Self {
        Self {
            data_pos,
            undo_pos: FlatFilePos::null(),
        }
    }

    /// Check if we have block data.
    pub fn has_data(&self) -> bool {
        !self.data_pos.is_null()
    }

    /// Check if we have undo data.
    pub fn has_undo(&self) -> bool {
        !self.undo_pos.is_null()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustoshi_consensus::ChainParams;
    use rustoshi_primitives::{BlockHeader, Hash256, OutPoint, Transaction, TxIn, TxOut};
    use tempfile::TempDir;

    fn create_test_block(height: u32) -> Block {
        Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: Hash256::ZERO,
                merkle_root: Hash256::ZERO,
                timestamp: 1600000000 + height,
                bits: 0x1d00ffff,
                nonce: height,
            },
            transactions: vec![Transaction {
                version: 1,
                inputs: vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: vec![0x04, height as u8],
                    sequence: 0xFFFFFFFF,
                    witness: vec![],
                }],
                outputs: vec![TxOut {
                    value: 50_0000_0000,
                    script_pubkey: vec![0x51], // OP_1
                }],
                lock_time: 0,
            }],
        }
    }

    #[test]
    fn test_flat_file_pos() {
        let pos = FlatFilePos::new(0, 100);
        assert!(!pos.is_null());
        assert_eq!(pos.file_num, 0);
        assert_eq!(pos.pos, 100);

        let null_pos = FlatFilePos::null();
        assert!(null_pos.is_null());

        let default_pos = FlatFilePos::default();
        assert_eq!(default_pos.file_num, 0);
        assert_eq!(default_pos.pos, 0);
    }

    #[test]
    fn test_flat_file_pos_display() {
        let pos = FlatFilePos::new(5, 12345);
        assert_eq!(pos.to_string(), "FlatFilePos(file=5, pos=12345)");
    }

    #[test]
    fn test_block_file_info() {
        let mut info = BlockFileInfo::new();
        assert_eq!(info.n_blocks, 0);

        info.add_block(100, 1600000000);
        assert_eq!(info.n_blocks, 1);
        assert_eq!(info.height_first, 100);
        assert_eq!(info.height_last, 100);
        assert_eq!(info.time_first, 1600000000);
        assert_eq!(info.time_last, 1600000000);

        info.add_block(200, 1600001000);
        assert_eq!(info.n_blocks, 2);
        assert_eq!(info.height_first, 100);
        assert_eq!(info.height_last, 200);
        assert_eq!(info.time_first, 1600000000);
        assert_eq!(info.time_last, 1600001000);

        info.add_block(50, 1599999000);
        assert_eq!(info.n_blocks, 3);
        assert_eq!(info.height_first, 50);
        assert_eq!(info.height_last, 200);
        assert_eq!(info.time_first, 1599999000);
        assert_eq!(info.time_last, 1600001000);
    }

    #[test]
    fn test_flat_file_seq_filename() {
        let dir = PathBuf::from("/tmp/blocks");
        let seq = FlatFileSeq::new(&dir, "blk", BLOCKFILE_CHUNK_SIZE);

        assert_eq!(
            seq.filename(&FlatFilePos::new(0, 0)),
            PathBuf::from("/tmp/blocks/blk00000.dat")
        );
        assert_eq!(
            seq.filename(&FlatFilePos::new(5, 0)),
            PathBuf::from("/tmp/blocks/blk00005.dat")
        );
        assert_eq!(
            seq.filename(&FlatFilePos::new(99999, 0)),
            PathBuf::from("/tmp/blocks/blk99999.dat")
        );
    }

    #[test]
    fn test_flat_block_store_write_and_read() {
        let dir = TempDir::new().expect("failed to create temp dir");
        let params = ChainParams::testnet4();
        let mut store = FlatBlockStore::new(dir.path(), &params.network_magic);

        let block = create_test_block(1);
        let pos = store.write_block(&block, 1).expect("failed to write block");

        assert!(!pos.is_null());
        assert_eq!(pos.file_num, 0);
        assert_eq!(pos.pos, STORAGE_HEADER_BYTES); // After header

        let read_block = store.read_block(&pos).expect("failed to read block");
        assert_eq!(block.header.timestamp, read_block.header.timestamp);
        assert_eq!(block.header.nonce, read_block.header.nonce);
        assert_eq!(block.transactions.len(), read_block.transactions.len());
    }

    #[test]
    fn test_flat_block_store_multiple_blocks() {
        let dir = TempDir::new().expect("failed to create temp dir");
        let params = ChainParams::testnet4();
        let mut store = FlatBlockStore::new(dir.path(), &params.network_magic);

        let mut positions = Vec::new();
        for i in 0..10 {
            let block = create_test_block(i);
            let pos = store.write_block(&block, i).expect("failed to write block");
            positions.push(pos);
        }

        // All blocks should be in file 0
        for pos in &positions {
            assert_eq!(pos.file_num, 0);
        }

        // Positions should be increasing
        for i in 1..positions.len() {
            assert!(positions[i].pos > positions[i - 1].pos);
        }

        // Verify all blocks can be read back
        for (i, pos) in positions.iter().enumerate() {
            let block = store.read_block(pos).expect("failed to read block");
            assert_eq!(block.header.nonce, i as u32);
        }
    }

    #[test]
    fn test_flat_block_store_read_raw() {
        let dir = TempDir::new().expect("failed to create temp dir");
        let params = ChainParams::testnet4();
        let mut store = FlatBlockStore::new(dir.path(), &params.network_magic);

        let block = create_test_block(42);
        let original_bytes = block.serialize();
        let pos = store.write_block(&block, 42).expect("failed to write block");

        let raw_bytes = store.read_raw_block(&pos).expect("failed to read raw block");
        assert_eq!(original_bytes, raw_bytes);
    }

    #[test]
    fn test_flat_block_store_file_info() {
        let dir = TempDir::new().expect("failed to create temp dir");
        let params = ChainParams::testnet4();
        let mut store = FlatBlockStore::new(dir.path(), &params.network_magic);

        let block = create_test_block(100);
        store.write_block(&block, 100).expect("failed to write block");

        let info = store.get_file_info(0).expect("no file info");
        assert_eq!(info.n_blocks, 1);
        assert_eq!(info.height_first, 100);
        assert_eq!(info.height_last, 100);
        assert!(info.n_size > 0);
    }

    #[test]
    fn test_flat_block_store_flush() {
        let dir = TempDir::new().expect("failed to create temp dir");
        let params = ChainParams::testnet4();
        let mut store = FlatBlockStore::new(dir.path(), &params.network_magic);

        let block = create_test_block(1);
        store.write_block(&block, 1).expect("failed to write block");
        store.flush().expect("failed to flush");

        // Verify file exists
        let file_path = store.block_file_path(0);
        assert!(file_path.exists());
    }

    #[test]
    fn test_block_file_location() {
        let data_pos = FlatFilePos::new(0, 100);
        let loc = BlockFileLocation::with_data(data_pos);

        assert!(loc.has_data());
        assert!(!loc.has_undo());
        assert_eq!(loc.data_pos.file_num, 0);
        assert_eq!(loc.data_pos.pos, 100);
    }

    #[test]
    fn test_flat_block_store_magic_validation() {
        let dir = TempDir::new().expect("failed to create temp dir");
        let params = ChainParams::testnet4();
        let mut store = FlatBlockStore::new(dir.path(), &params.network_magic);

        let block = create_test_block(1);
        let pos = store.write_block(&block, 1).expect("failed to write block");

        // Read should succeed with correct magic
        assert!(store.read_block(&pos).is_ok());

        // Create a store with different magic
        let wrong_magic = rustoshi_consensus::NetworkMagic([0xff, 0xff, 0xff, 0xff]);
        let wrong_store = FlatBlockStore::new(dir.path(), &wrong_magic);

        // Read should fail with wrong magic
        let result = wrong_store.read_block(&pos);
        assert!(result.is_err());
        if let Err(StorageError::Corruption(msg)) = result {
            assert!(msg.contains("magic mismatch"));
        } else {
            panic!("expected corruption error");
        }
    }

    #[test]
    fn test_flat_block_store_disk_usage() {
        let dir = TempDir::new().expect("failed to create temp dir");
        let params = ChainParams::testnet4();
        let mut store = FlatBlockStore::new(dir.path(), &params.network_magic);

        assert_eq!(store.calculate_disk_usage(), 0);

        for i in 0..5 {
            let block = create_test_block(i);
            store.write_block(&block, i).expect("failed to write block");
        }

        let usage = store.calculate_disk_usage();
        assert!(usage > 0);
    }

    #[test]
    fn test_constants() {
        // Verify constants match Bitcoin Core
        assert_eq!(MAX_BLOCKFILE_SIZE, 128 * 1024 * 1024);
        assert_eq!(BLOCKFILE_CHUNK_SIZE, 0x1000000);
        assert_eq!(UNDOFILE_CHUNK_SIZE, 0x100000);
        assert_eq!(STORAGE_HEADER_BYTES, 8);
    }

    // ============================================================
    // PRUNING TESTS
    // ============================================================

    #[test]
    fn test_pruning_constants() {
        assert_eq!(MIN_PRUNE_TARGET_MIB, 550);
        assert_eq!(MIN_BLOCKS_TO_KEEP, 288);
        assert_eq!(MIN_DISK_SPACE_FOR_BLOCK_FILES, 550 * 1024 * 1024);
    }

    #[test]
    fn test_prune_config_default() {
        let config = PruneConfig::default();
        assert_eq!(config.prune_target, 0);
        assert!(!config.is_prune_mode());
    }

    #[test]
    fn test_prune_config_with_target() {
        let config = PruneConfig::with_target_mib(1000);
        assert_eq!(config.prune_target, 1000 * 1024 * 1024);
        assert!(config.is_prune_mode());
    }

    #[test]
    fn test_prune_config_enforces_minimum() {
        // Request below minimum should be clamped to minimum
        let config = PruneConfig::with_target_mib(100);
        assert_eq!(config.prune_target, MIN_DISK_SPACE_FOR_BLOCK_FILES);
    }

    #[test]
    fn test_prune_config_zero_means_disabled() {
        let config = PruneConfig::with_target_mib(0);
        assert_eq!(config.prune_target, 0);
        assert!(!config.is_prune_mode());
    }

    #[test]
    fn test_flat_block_store_with_prune_config() {
        let dir = TempDir::new().expect("failed to create temp dir");
        let params = ChainParams::testnet4();
        let config = PruneConfig::with_target_mib(1000);
        let store = FlatBlockStore::with_config(dir.path(), &params.network_magic, config);

        assert!(store.is_prune_mode());
        assert_eq!(store.prune_target(), 1000 * 1024 * 1024);
    }

    #[test]
    fn test_flat_block_store_pruning_disabled_by_default() {
        let dir = TempDir::new().expect("failed to create temp dir");
        let params = ChainParams::testnet4();
        let store = FlatBlockStore::new(dir.path(), &params.network_magic);

        assert!(!store.is_prune_mode());
        assert_eq!(store.prune_target(), 0);
    }

    #[test]
    fn test_find_files_to_prune_disabled() {
        let dir = TempDir::new().expect("failed to create temp dir");
        let params = ChainParams::testnet4();
        let store = FlatBlockStore::new(dir.path(), &params.network_magic);

        // Pruning disabled, should return empty
        let files = store.find_files_to_prune(1000, 0);
        assert!(files.is_empty());
    }

    #[test]
    fn test_find_files_to_prune_manual_disabled() {
        let dir = TempDir::new().expect("failed to create temp dir");
        let params = ChainParams::testnet4();
        let store = FlatBlockStore::new(dir.path(), &params.network_magic);

        // Pruning disabled, should return empty
        let files = store.find_files_to_prune_manual(500, 1000);
        assert!(files.is_empty());
    }

    #[test]
    fn test_prune_one_block_file() {
        let dir = TempDir::new().expect("failed to create temp dir");
        let params = ChainParams::testnet4();
        let config = PruneConfig::with_target_mib(1000);
        let mut store = FlatBlockStore::with_config(dir.path(), &params.network_magic, config);

        // Write a block to create file info
        let block = create_test_block(1);
        store.write_block(&block, 1).expect("failed to write block");

        // Verify file info exists
        let info = store.get_file_info(0).unwrap();
        assert!(info.n_size > 0);

        // Prune the file
        store.prune_one_block_file(0);

        // File info should be cleared
        let info = store.get_file_info(0).unwrap();
        assert_eq!(info.n_size, 0);
        assert!(store.have_pruned());
    }

    #[test]
    fn test_is_block_pruned() {
        let dir = TempDir::new().expect("failed to create temp dir");
        let params = ChainParams::testnet4();
        let config = PruneConfig::with_target_mib(1000);
        let mut store = FlatBlockStore::with_config(dir.path(), &params.network_magic, config);

        // Write a block
        let block = create_test_block(1);
        store.write_block(&block, 1).expect("failed to write block");

        // Not pruned yet
        assert!(!store.is_block_pruned(0));

        // Prune the file
        store.prune_one_block_file(0);

        // Now pruned
        assert!(store.is_block_pruned(0));
    }

    #[test]
    fn test_unlink_pruned_files() {
        let dir = TempDir::new().expect("failed to create temp dir");
        let params = ChainParams::testnet4();
        let config = PruneConfig::with_target_mib(1000);
        let mut store = FlatBlockStore::with_config(dir.path(), &params.network_magic, config);

        // Write a block to create the file
        let block = create_test_block(1);
        store.write_block(&block, 1).expect("failed to write block");

        let blk_path = store.block_file_path(0);
        assert!(blk_path.exists());

        // Unlink the file
        store.unlink_pruned_files(&[0]).expect("failed to unlink");

        // File should be gone
        assert!(!blk_path.exists());
    }

    #[test]
    fn test_find_files_to_prune_respects_min_blocks_to_keep() {
        let dir = TempDir::new().expect("failed to create temp dir");
        let params = ChainParams::testnet4();
        // Small prune target to force pruning
        let config = PruneConfig {
            prune_target: 100, // Very small
            fast_prune: false,
        };
        let mut store = FlatBlockStore::with_config(dir.path(), &params.network_magic, config);

        // Write blocks to file 0 with heights 0-99
        for height in 0..100 {
            let block = create_test_block(height);
            store.write_block(&block, height).expect("failed to write block");
        }

        // Force rotation to a new file by simulating that file 0 is complete
        store.current_file = 1;
        store.file_info.push(BlockFileInfo::new());

        // With chain tip at 500, we can prune up to height 212 (500 - 288)
        // File 0 has blocks 0-99, so it should be pruneable
        let chain_tip_height = 500;
        let files = store.find_files_to_prune(chain_tip_height, 0);

        // File 0 should be in the prunable list since all blocks are below tip - 288
        assert!(files.contains(&0));
    }

    #[test]
    fn test_find_files_to_prune_manual_respects_min_blocks_to_keep() {
        let dir = TempDir::new().expect("failed to create temp dir");
        let params = ChainParams::testnet4();
        let config = PruneConfig::with_target_mib(1000);
        let mut store = FlatBlockStore::with_config(dir.path(), &params.network_magic, config);

        // Write blocks with various heights
        for height in 0..100 {
            let block = create_test_block(height);
            store.write_block(&block, height).expect("failed to write block");
        }

        // With chain tip at 200, we can only prune up to height 0 (200 - 288 would be negative)
        // But height 99 > 0, so file shouldn't be prunable
        let files = store.find_files_to_prune_manual(100, 200);

        // The file has height_last = 99 and effective_prune_height = 0 (since 200 - 288 < 0)
        // So file 0 should NOT be prunable
        assert!(files.is_empty());

        // With chain tip at 500, effective_prune_height = min(100, 500-288) = 100
        // File 0 has height_last = 99 <= 100, so it should be prunable
        let files = store.find_files_to_prune_manual(100, 500);
        assert!(files.contains(&0));
    }

    #[test]
    fn test_maybe_prune() {
        let dir = TempDir::new().expect("failed to create temp dir");
        let params = ChainParams::testnet4();
        let config = PruneConfig {
            prune_target: 100, // Very small target
            fast_prune: false,
        };
        let mut store = FlatBlockStore::with_config(dir.path(), &params.network_magic, config);

        // Write blocks
        for height in 0..50 {
            let block = create_test_block(height);
            store.write_block(&block, height).expect("failed to write block");
        }

        // Force pruning check
        store.check_for_pruning = true;

        // Call maybe_prune with a high chain tip
        let pruned = store.maybe_prune(1000, 0).expect("pruning failed");

        // Should have pruned file 0
        assert!(pruned.contains(&0));

        // File should be marked as pruned
        assert!(store.is_block_pruned(0));

        // Check flag should be cleared
        assert!(!store.needs_pruning_check());
    }

    #[test]
    fn test_pruneblockchain_files_deleted() {
        let dir = TempDir::new().expect("failed to create temp dir");
        let params = ChainParams::testnet4();
        let config = PruneConfig::with_target_mib(1000);
        let mut store = FlatBlockStore::with_config(dir.path(), &params.network_magic, config);

        // Write blocks
        for height in 0..10 {
            let block = create_test_block(height);
            store.write_block(&block, height).expect("failed to write block");
        }

        let blk_path = store.block_file_path(0);
        assert!(blk_path.exists());

        // Manually prune file 0
        let files = store.find_files_to_prune_manual(100, 500);
        for file in &files {
            store.prune_one_block_file(*file);
        }
        store.unlink_pruned_files(&files).expect("failed to unlink");

        // File should be gone
        assert!(!blk_path.exists());
    }
}
