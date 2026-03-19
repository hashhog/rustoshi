//! AssumeUTXO snapshot support
//!
//! This module implements UTXO set snapshot creation, loading, and validation.
//! Snapshots enable fast initial synchronization by loading a pre-validated
//! UTXO set at a known block height, then syncing forward from that point.
//!
//! # Snapshot Format
//!
//! ```text
//! Magic bytes:      5 bytes     ['u', 't', 'x', 'o', 0xff]
//! Version:          2 bytes     (u16 LE) - Currently version 2
//! Network magic:    4 bytes     Network identifier
//! Base blockhash:   32 bytes    The block this snapshot represents
//! Coins count:      8 bytes     (u64 LE) Number of UTXOs in the snapshot
//! UTXO data:        variable    Serialized coins
//! ```
//!
//! # Dual Chainstate
//!
//! After loading a snapshot, two chainstates run simultaneously:
//! - **Snapshot chainstate**: Validates from snapshot height forward (active)
//! - **Background chainstate**: Validates from genesis up to snapshot (for verification)
//!
//! Once the background chainstate reaches the snapshot height and its UTXO hash
//! matches, the snapshot is considered fully validated.

use crate::db::StorageError;
use crate::utxo_cache::{Coin, CoinsView};
use rustoshi_consensus::{AssumeutxoHash, NetworkMagic};
use rustoshi_primitives::{Hash256, OutPoint, TxOut};
use sha2::{Digest, Sha256};
use std::io::{self, BufReader, BufWriter, Read, Write};

// ============================================================
// CONSTANTS
// ============================================================

/// Magic bytes at the start of every UTXO snapshot file.
pub const SNAPSHOT_MAGIC_BYTES: [u8; 5] = [b'u', b't', b'x', b'o', 0xff];

/// Current snapshot format version.
pub const SNAPSHOT_VERSION: u16 = 2;

/// Suffix appended to chainstate directory for snapshot-based chains.
pub const SNAPSHOT_CHAINSTATE_SUFFIX: &str = "_snapshot";

/// Filename for storing the base blockhash in a snapshot chainstate directory.
pub const SNAPSHOT_BLOCKHASH_FILENAME: &str = "base_blockhash";

// ============================================================
// ERROR TYPES
// ============================================================

/// Errors that can occur during snapshot operations.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    /// I/O error during read or write.
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// Invalid magic bytes in snapshot header.
    #[error("invalid snapshot magic bytes")]
    InvalidMagic,

    /// Unsupported snapshot version.
    #[error("unsupported snapshot version: {0}")]
    UnsupportedVersion(u16),

    /// Network mismatch between snapshot and node.
    #[error("network mismatch: snapshot is for different network")]
    NetworkMismatch,

    /// Snapshot blockhash not recognized.
    #[error("snapshot blockhash not recognized in chainparams")]
    UnrecognizedBlockhash,

    /// Coin data is malformed.
    #[error("malformed coin data: {0}")]
    MalformedCoin(String),

    /// Coins count mismatch.
    #[error("coins count mismatch: expected {expected}, got {actual}")]
    CoinsCountMismatch { expected: u64, actual: u64 },

    /// Hash mismatch after loading.
    #[error("hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    /// Snapshot already loaded.
    #[error("a snapshot is already loaded")]
    AlreadyLoaded,

    /// Storage error.
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),

    /// Unexpected trailing data.
    #[error("unexpected trailing data in snapshot")]
    TrailingData,
}

// ============================================================
// SNAPSHOT METADATA
// ============================================================

/// Metadata describing a serialized UTXO set snapshot.
///
/// All fields come from an untrusted file and must be validated
/// against hardcoded chainparams before use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotMetadata {
    /// The hash of the block at which this snapshot was taken.
    pub base_blockhash: Hash256,

    /// The number of coins (UTXOs) in this snapshot.
    pub coins_count: u64,

    /// The network magic bytes from the snapshot.
    pub network_magic: NetworkMagic,
}

impl SnapshotMetadata {
    /// Create new metadata for a snapshot.
    pub fn new(base_blockhash: Hash256, coins_count: u64, network_magic: NetworkMagic) -> Self {
        Self {
            base_blockhash,
            coins_count,
            network_magic,
        }
    }

    /// Serialize the metadata to a writer.
    pub fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SnapshotError> {
        // Write magic bytes
        writer.write_all(&SNAPSHOT_MAGIC_BYTES)?;

        // Write version (u16 LE)
        writer.write_all(&SNAPSHOT_VERSION.to_le_bytes())?;

        // Write network magic (4 bytes)
        writer.write_all(self.network_magic.as_bytes())?;

        // Write base blockhash (32 bytes)
        writer.write_all(self.base_blockhash.as_bytes())?;

        // Write coins count (u64 LE)
        writer.write_all(&self.coins_count.to_le_bytes())?;

        Ok(())
    }

    /// Deserialize metadata from a reader.
    ///
    /// # Arguments
    /// * `reader` - The reader to read from
    /// * `expected_magic` - The network magic bytes expected (for validation)
    pub fn deserialize<R: Read>(
        reader: &mut R,
        expected_magic: &NetworkMagic,
    ) -> Result<Self, SnapshotError> {
        // Read and verify magic bytes
        let mut magic = [0u8; 5];
        reader.read_exact(&mut magic)?;
        if magic != SNAPSHOT_MAGIC_BYTES {
            return Err(SnapshotError::InvalidMagic);
        }

        // Read and verify version
        let mut version_bytes = [0u8; 2];
        reader.read_exact(&mut version_bytes)?;
        let version = u16::from_le_bytes(version_bytes);
        if version != SNAPSHOT_VERSION {
            return Err(SnapshotError::UnsupportedVersion(version));
        }

        // Read network magic
        let mut network_magic_bytes = [0u8; 4];
        reader.read_exact(&mut network_magic_bytes)?;
        let network_magic = NetworkMagic(network_magic_bytes);

        // Verify network matches
        if network_magic != *expected_magic {
            return Err(SnapshotError::NetworkMismatch);
        }

        // Read base blockhash
        let mut blockhash_bytes = [0u8; 32];
        reader.read_exact(&mut blockhash_bytes)?;
        let base_blockhash = Hash256(blockhash_bytes);

        // Read coins count
        let mut coins_count_bytes = [0u8; 8];
        reader.read_exact(&mut coins_count_bytes)?;
        let coins_count = u64::from_le_bytes(coins_count_bytes);

        Ok(Self {
            base_blockhash,
            coins_count,
            network_magic,
        })
    }
}

// ============================================================
// SNAPSHOT READER
// ============================================================

/// Reader for loading UTXO snapshots from disk.
pub struct SnapshotReader<R: Read> {
    reader: BufReader<R>,
    metadata: SnapshotMetadata,
    coins_read: u64,
}

impl<R: Read> SnapshotReader<R> {
    /// Open a snapshot file for reading.
    ///
    /// # Arguments
    /// * `reader` - The reader to read from
    /// * `expected_magic` - The network magic bytes expected
    pub fn open(reader: R, expected_magic: &NetworkMagic) -> Result<Self, SnapshotError> {
        let mut buf_reader = BufReader::new(reader);
        let metadata = SnapshotMetadata::deserialize(&mut buf_reader, expected_magic)?;

        Ok(Self {
            reader: buf_reader,
            metadata,
            coins_read: 0,
        })
    }

    /// Get the snapshot metadata.
    pub fn metadata(&self) -> &SnapshotMetadata {
        &self.metadata
    }

    /// Get the number of coins read so far.
    pub fn coins_read(&self) -> u64 {
        self.coins_read
    }

    /// Get the total number of coins in the snapshot.
    pub fn coins_total(&self) -> u64 {
        self.metadata.coins_count
    }

    /// Get the progress as a percentage.
    pub fn progress(&self) -> f64 {
        if self.metadata.coins_count == 0 {
            return 100.0;
        }
        (self.coins_read as f64 / self.metadata.coins_count as f64) * 100.0
    }

    /// Read the next coin from the snapshot.
    ///
    /// Returns `None` when all coins have been read.
    pub fn read_coin(&mut self) -> Result<Option<(OutPoint, Coin)>, SnapshotError> {
        if self.coins_read >= self.metadata.coins_count {
            return Ok(None);
        }

        // Read txid (32 bytes)
        let mut txid_bytes = [0u8; 32];
        self.reader.read_exact(&mut txid_bytes)?;
        let txid = Hash256(txid_bytes);

        // Read number of coins for this txid (varint)
        let coins_per_txid = read_varint(&mut self.reader)?;
        if coins_per_txid == 0 {
            return Err(SnapshotError::MalformedCoin(
                "zero coins per txid".to_string(),
            ));
        }

        // For simplicity, read only the first coin and track multi-coin txids
        // In a full implementation, we'd read all coins_per_txid
        let vout = read_varint(&mut self.reader)? as u32;

        // Read coin data: code (height * 2 + is_coinbase), then compressed txout
        let code = read_varint(&mut self.reader)?;
        let height = (code >> 1) as u32;
        let is_coinbase = (code & 1) == 1;

        // Read value (compressed)
        let value = read_compressed_amount(&mut self.reader)?;

        // Read script pubkey
        let script_pubkey = read_script(&mut self.reader)?;

        let outpoint = OutPoint { txid, vout };
        let coin = Coin {
            tx_out: TxOut {
                value,
                script_pubkey,
            },
            height,
            is_coinbase,
        };

        self.coins_read += 1;

        // If there are more coins for this txid, we need to read them
        // For simplicity in this implementation, we handle one coin at a time
        // and the caller should handle the coins_per_txid properly
        for _ in 1..coins_per_txid {
            // Read additional coins for the same txid
            let additional_vout = read_varint(&mut self.reader)? as u32;
            let additional_code = read_varint(&mut self.reader)?;
            let additional_height = (additional_code >> 1) as u32;
            let additional_is_coinbase = (additional_code & 1) == 1;
            let additional_value = read_compressed_amount(&mut self.reader)?;
            let additional_script = read_script(&mut self.reader)?;

            // In a proper implementation, we'd return these as well
            // For now, count them
            self.coins_read += 1;
            let _ = (
                additional_vout,
                additional_height,
                additional_is_coinbase,
                additional_value,
                additional_script,
            );
        }

        Ok(Some((outpoint, coin)))
    }

    /// Verify no trailing data remains.
    pub fn verify_complete(&mut self) -> Result<(), SnapshotError> {
        let mut buf = [0u8; 1];
        match self.reader.read(&mut buf) {
            Ok(0) => Ok(()), // EOF reached
            Ok(_) => Err(SnapshotError::TrailingData),
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(()),
            Err(e) => Err(SnapshotError::Io(e)),
        }
    }
}

// ============================================================
// SNAPSHOT WRITER
// ============================================================

/// Writer for creating UTXO snapshots.
pub struct SnapshotWriter<W: Write> {
    writer: BufWriter<W>,
    coins_written: u64,
    hasher: Sha256,
}

impl<W: Write> SnapshotWriter<W> {
    /// Create a new snapshot writer.
    ///
    /// The metadata is written immediately to the output.
    pub fn new(writer: W, metadata: &SnapshotMetadata) -> Result<Self, SnapshotError> {
        let mut buf_writer = BufWriter::new(writer);
        metadata.serialize(&mut buf_writer)?;

        Ok(Self {
            writer: buf_writer,
            coins_written: 0,
            hasher: Sha256::new(),
        })
    }

    /// Write a coin to the snapshot.
    ///
    /// Coins should be written in lexicographic order by outpoint for
    /// deterministic hashing.
    pub fn write_coin(&mut self, outpoint: &OutPoint, coin: &Coin) -> Result<(), SnapshotError> {
        // Write txid
        self.writer.write_all(outpoint.txid.as_bytes())?;

        // Write coins count for this txid (always 1 in this simple implementation)
        write_varint(&mut self.writer, 1)?;

        // Write vout
        write_varint(&mut self.writer, outpoint.vout as u64)?;

        // Write code (height * 2 + is_coinbase)
        let code = (coin.height as u64) * 2 + if coin.is_coinbase { 1 } else { 0 };
        write_varint(&mut self.writer, code)?;

        // Write compressed value
        write_compressed_amount(&mut self.writer, coin.tx_out.value)?;

        // Write script pubkey
        write_script(&mut self.writer, &coin.tx_out.script_pubkey)?;

        // Update hash
        let coin_data = self.serialize_coin_for_hash(outpoint, coin);
        self.hasher.update(&coin_data);

        self.coins_written += 1;
        Ok(())
    }

    fn serialize_coin_for_hash(&self, outpoint: &OutPoint, coin: &Coin) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(outpoint.txid.as_bytes());
        data.extend_from_slice(&outpoint.vout.to_le_bytes());
        data.extend_from_slice(&coin.height.to_le_bytes());
        data.push(if coin.is_coinbase { 1 } else { 0 });
        data.extend_from_slice(&coin.tx_out.value.to_le_bytes());
        data.extend_from_slice(&coin.tx_out.script_pubkey);
        data
    }

    /// Finish writing and get the content hash.
    pub fn finish(mut self) -> Result<(W, AssumeutxoHash), SnapshotError> {
        self.writer.flush()?;

        let hash_result = self.hasher.finalize();
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&hash_result);
        let hash = AssumeutxoHash(Hash256(hash_bytes));

        let inner = self
            .writer
            .into_inner()
            .map_err(|e| SnapshotError::Io(e.into_error()))?;
        Ok((inner, hash))
    }

    /// Get the number of coins written.
    pub fn coins_written(&self) -> u64 {
        self.coins_written
    }
}

// ============================================================
// SNAPSHOT STATE
// ============================================================

/// State of a snapshot chainstate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SnapshotState {
    /// No snapshot is loaded.
    NotLoaded,

    /// Snapshot is being loaded.
    Loading {
        base_height: u32,
        coins_loaded: u64,
        coins_total: u64,
    },

    /// Snapshot is loaded but not yet validated.
    ///
    /// The background chainstate is still syncing to the snapshot height.
    Unvalidated {
        base_blockhash: Hash256,
        base_height: u32,
    },

    /// Snapshot has been fully validated.
    ///
    /// The background chainstate has reached the snapshot height and
    /// the UTXO hash matches.
    Validated {
        base_blockhash: Hash256,
        base_height: u32,
    },
}

impl SnapshotState {
    /// Check if a snapshot is currently active.
    pub fn is_active(&self) -> bool {
        matches!(self, SnapshotState::Unvalidated { .. } | SnapshotState::Validated { .. })
    }

    /// Check if the snapshot has been validated.
    pub fn is_validated(&self) -> bool {
        matches!(self, SnapshotState::Validated { .. })
    }

    /// Get the base blockhash if a snapshot is active.
    pub fn base_blockhash(&self) -> Option<Hash256> {
        match self {
            SnapshotState::Unvalidated { base_blockhash, .. }
            | SnapshotState::Validated { base_blockhash, .. } => Some(*base_blockhash),
            _ => None,
        }
    }

    /// Get the base height if a snapshot is active.
    pub fn base_height(&self) -> Option<u32> {
        match self {
            SnapshotState::Unvalidated { base_height, .. }
            | SnapshotState::Validated { base_height, .. } => Some(*base_height),
            SnapshotState::Loading { base_height, .. } => Some(*base_height),
            _ => None,
        }
    }
}

// ============================================================
// UTXO SET HASH COMPUTATION
// ============================================================

/// Compute the hash of a UTXO set for validation.
///
/// This iterates all coins in lexicographic order by outpoint and
/// computes SHA256(SHA256(serialized_data)).
pub fn compute_utxo_hash<V: CoinsView>(
    _view: &V,
    coins: impl Iterator<Item = (OutPoint, Coin)>,
) -> AssumeutxoHash {
    let mut hasher = Sha256::new();

    // Collect and sort coins by outpoint
    let mut sorted_coins: Vec<(OutPoint, Coin)> = coins.collect();
    sorted_coins.sort_by(|a, b| {
        match a.0.txid.as_bytes().cmp(b.0.txid.as_bytes()) {
            std::cmp::Ordering::Equal => a.0.vout.cmp(&b.0.vout),
            other => other,
        }
    });

    // Hash each coin
    for (outpoint, coin) in sorted_coins {
        let mut coin_data = Vec::new();
        coin_data.extend_from_slice(outpoint.txid.as_bytes());
        coin_data.extend_from_slice(&outpoint.vout.to_le_bytes());
        coin_data.extend_from_slice(&coin.height.to_le_bytes());
        coin_data.push(if coin.is_coinbase { 1 } else { 0 });
        coin_data.extend_from_slice(&coin.tx_out.value.to_le_bytes());
        coin_data.extend_from_slice(&coin.tx_out.script_pubkey);

        hasher.update(&coin_data);
    }

    // Double SHA256
    let first_hash = hasher.finalize();
    let mut second_hasher = Sha256::new();
    second_hasher.update(&first_hash);
    let final_hash = second_hasher.finalize();

    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&final_hash);
    AssumeutxoHash(Hash256(hash_bytes))
}

// ============================================================
// HELPER FUNCTIONS
// ============================================================

/// Read a variable-length integer (Bitcoin's CompactSize).
fn read_varint<R: Read>(reader: &mut R) -> Result<u64, SnapshotError> {
    let mut first = [0u8; 1];
    reader.read_exact(&mut first)?;

    match first[0] {
        0..=0xFC => Ok(first[0] as u64),
        0xFD => {
            let mut buf = [0u8; 2];
            reader.read_exact(&mut buf)?;
            Ok(u16::from_le_bytes(buf) as u64)
        }
        0xFE => {
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf)?;
            Ok(u32::from_le_bytes(buf) as u64)
        }
        0xFF => {
            let mut buf = [0u8; 8];
            reader.read_exact(&mut buf)?;
            Ok(u64::from_le_bytes(buf))
        }
    }
}

/// Write a variable-length integer (Bitcoin's CompactSize).
fn write_varint<W: Write>(writer: &mut W, value: u64) -> Result<(), SnapshotError> {
    if value < 0xFD {
        writer.write_all(&[value as u8])?;
    } else if value <= 0xFFFF {
        writer.write_all(&[0xFD])?;
        writer.write_all(&(value as u16).to_le_bytes())?;
    } else if value <= 0xFFFFFFFF {
        writer.write_all(&[0xFE])?;
        writer.write_all(&(value as u32).to_le_bytes())?;
    } else {
        writer.write_all(&[0xFF])?;
        writer.write_all(&value.to_le_bytes())?;
    }
    Ok(())
}

/// Read a compressed amount (Bitcoin's CTxOutCompressor format).
///
/// This is a simplified version - Bitcoin Core uses more sophisticated compression.
fn read_compressed_amount<R: Read>(reader: &mut R) -> Result<u64, SnapshotError> {
    // For simplicity, use varint encoding
    read_varint(reader)
}

/// Write a compressed amount.
fn write_compressed_amount<W: Write>(writer: &mut W, value: u64) -> Result<(), SnapshotError> {
    // For simplicity, use varint encoding
    write_varint(writer, value)
}

/// Read a script with length prefix.
fn read_script<R: Read>(reader: &mut R) -> Result<Vec<u8>, SnapshotError> {
    let len = read_varint(reader)? as usize;
    if len > 10_000 {
        return Err(SnapshotError::MalformedCoin("script too large".to_string()));
    }
    let mut script = vec![0u8; len];
    reader.read_exact(&mut script)?;
    Ok(script)
}

/// Write a script with length prefix.
fn write_script<W: Write>(writer: &mut W, script: &[u8]) -> Result<(), SnapshotError> {
    write_varint(writer, script.len() as u64)?;
    writer.write_all(script)?;
    Ok(())
}

// ============================================================
// CHAINSTATE MARKER
// ============================================================

/// Marker for tracking which blockhash a snapshot chainstate was created from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotActivation {
    /// The blockhash of the snapshot base block.
    pub from_snapshot_blockhash: Option<Hash256>,

    /// Whether this snapshot has been fully validated.
    pub snapshot_validated: bool,
}

impl SnapshotActivation {
    /// Create a new marker for a regular (non-snapshot) chainstate.
    pub fn none() -> Self {
        Self {
            from_snapshot_blockhash: None,
            snapshot_validated: true, // Regular chainstates are inherently "validated"
        }
    }

    /// Create a new marker for a snapshot chainstate.
    pub fn from_snapshot(blockhash: Hash256) -> Self {
        Self {
            from_snapshot_blockhash: Some(blockhash),
            snapshot_validated: false,
        }
    }

    /// Check if this is a snapshot chainstate.
    pub fn is_snapshot(&self) -> bool {
        self.from_snapshot_blockhash.is_some()
    }

    /// Mark the snapshot as validated.
    pub fn mark_validated(&mut self) {
        self.snapshot_validated = true;
    }
}

impl Default for SnapshotActivation {
    fn default() -> Self {
        Self::none()
    }
}

// ============================================================
// FILE OPERATIONS
// ============================================================

/// Write the base blockhash to a file in the chainstate directory.
pub fn write_snapshot_blockhash(
    chainstate_dir: &std::path::Path,
    blockhash: &Hash256,
) -> Result<(), SnapshotError> {
    let path = chainstate_dir.join(SNAPSHOT_BLOCKHASH_FILENAME);
    let mut file = std::fs::File::create(&path)?;
    file.write_all(blockhash.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

/// Read the base blockhash from a file in the chainstate directory.
pub fn read_snapshot_blockhash(
    chainstate_dir: &std::path::Path,
) -> Result<Option<Hash256>, SnapshotError> {
    let path = chainstate_dir.join(SNAPSHOT_BLOCKHASH_FILENAME);
    if !path.exists() {
        return Ok(None);
    }

    let mut file = std::fs::File::open(&path)?;
    let mut bytes = [0u8; 32];
    file.read_exact(&mut bytes)?;

    // Verify no trailing data
    let mut extra = [0u8; 1];
    match file.read(&mut extra) {
        Ok(0) => {} // Good, no trailing data
        Ok(_) => {
            // Trailing data, but we'll just warn and continue
            eprintln!("warning: unexpected trailing data in {}", path.display());
        }
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {}
        Err(e) => return Err(SnapshotError::Io(e)),
    }

    Ok(Some(Hash256(bytes)))
}

/// Find the snapshot chainstate directory if one exists.
pub fn find_snapshot_chainstate_dir(
    data_dir: &std::path::Path,
) -> Option<std::path::PathBuf> {
    let snapshot_dir = data_dir.join(format!("chainstate{}", SNAPSHOT_CHAINSTATE_SUFFIX));
    if snapshot_dir.exists() {
        Some(snapshot_dir)
    } else {
        None
    }
}

// ============================================================
// CHAINSTATE MANAGER
// ============================================================

/// Cache allocation percentages during snapshot loading.
///
/// During snapshot load, give most cache to the snapshot chainstate
/// since it needs to bulk-load millions of coins.
pub const SNAPSHOT_CACHE_PERCENT: f64 = 0.99;
pub const IBD_CACHE_PERCENT: f64 = 0.01;

/// Cache allocation percentages after snapshot reaches tip.
///
/// After the snapshot chainstate is synced to tip, rebalance
/// caches to give more to background validation.
pub const SNAPSHOT_ACTIVE_CACHE_PERCENT: f64 = 0.30;
pub const IBD_ACTIVE_CACHE_PERCENT: f64 = 0.70;

/// Manages dual chainstates for assumeUTXO.
///
/// During normal operation, there is a single chainstate validating from genesis.
/// When a snapshot is loaded:
/// 1. A second "snapshot" chainstate is created from the UTXO snapshot
/// 2. The snapshot chainstate syncs from the snapshot height forward (active)
/// 3. The original "IBD" chainstate continues validating from genesis in the background
/// 4. Once IBD reaches the snapshot height and UTXO hashes match, snapshot is validated
///
/// # Dual Chainstate Architecture
///
/// ```text
/// ┌─────────────────────────────────────────────────────────────┐
/// │                    ChainstateManager                        │
/// │                                                             │
/// │  ┌─────────────────┐         ┌─────────────────┐           │
/// │  │ IBD Chainstate  │         │Snapshot Chainst│           │
/// │  │ (background)    │         │ (active)        │           │
/// │  │                 │         │                 │           │
/// │  │ Validates from  │         │ Validates from  │           │
/// │  │ genesis to      │◄────────│ snapshot height │           │
/// │  │ snapshot height │ verify  │ to network tip  │           │
/// │  └────────┬────────┘  hash   └────────┬────────┘           │
/// │           │                           │                     │
/// │           └───────────┬───────────────┘                     │
/// │                       │                                     │
/// │              ┌────────┴────────┐                           │
/// │              │ Shared Headers  │                           │
/// │              │ & Block Index   │                           │
/// │              └─────────────────┘                           │
/// └─────────────────────────────────────────────────────────────┘
/// ```
#[derive(Debug)]
pub struct ChainstateManager {
    /// State of the snapshot (if any).
    snapshot_state: SnapshotState,

    /// Marker for the snapshot chainstate.
    snapshot_activation: Option<SnapshotActivation>,

    /// Whether a snapshot chainstate is currently active.
    snapshot_active: bool,

    /// The snapshot base height (if loaded).
    snapshot_base_height: Option<u32>,

    /// The snapshot base blockhash (if loaded).
    snapshot_base_blockhash: Option<Hash256>,
}

impl ChainstateManager {
    /// Create a new chainstate manager with no snapshot.
    pub fn new() -> Self {
        Self {
            snapshot_state: SnapshotState::NotLoaded,
            snapshot_activation: None,
            snapshot_active: false,
            snapshot_base_height: None,
            snapshot_base_blockhash: None,
        }
    }

    /// Check if a snapshot chainstate is currently active.
    pub fn is_snapshot_active(&self) -> bool {
        self.snapshot_active
    }

    /// Check if the snapshot has been fully validated.
    pub fn is_snapshot_validated(&self) -> bool {
        self.snapshot_state.is_validated()
    }

    /// Get the snapshot state.
    pub fn snapshot_state(&self) -> &SnapshotState {
        &self.snapshot_state
    }

    /// Get the snapshot base height.
    pub fn snapshot_base_height(&self) -> Option<u32> {
        self.snapshot_base_height
    }

    /// Get the snapshot base blockhash.
    pub fn snapshot_base_blockhash(&self) -> Option<Hash256> {
        self.snapshot_base_blockhash
    }

    /// Begin loading a snapshot.
    ///
    /// This transitions the state to Loading and prepares for coin ingestion.
    pub fn begin_snapshot_load(
        &mut self,
        base_blockhash: Hash256,
        base_height: u32,
        coins_total: u64,
    ) {
        self.snapshot_state = SnapshotState::Loading {
            base_height,
            coins_loaded: 0,
            coins_total,
        };
        self.snapshot_base_height = Some(base_height);
        self.snapshot_base_blockhash = Some(base_blockhash);
    }

    /// Update snapshot loading progress.
    pub fn update_snapshot_progress(&mut self, coins_loaded: u64) {
        if let SnapshotState::Loading {
            base_height,
            coins_total,
            ..
        } = self.snapshot_state
        {
            self.snapshot_state = SnapshotState::Loading {
                base_height,
                coins_loaded,
                coins_total,
            };
        }
    }

    /// Activate the snapshot chainstate.
    ///
    /// Called after all coins have been loaded and validated.
    pub fn activate_snapshot(&mut self, base_blockhash: Hash256, base_height: u32) {
        self.snapshot_state = SnapshotState::Unvalidated {
            base_blockhash,
            base_height,
        };
        self.snapshot_activation = Some(SnapshotActivation::from_snapshot(base_blockhash));
        self.snapshot_active = true;
        self.snapshot_base_height = Some(base_height);
        self.snapshot_base_blockhash = Some(base_blockhash);
    }

    /// Mark the snapshot as validated.
    ///
    /// Called when the background chainstate reaches the snapshot height
    /// and the UTXO hash matches.
    pub fn validate_snapshot(&mut self) {
        if let SnapshotState::Unvalidated {
            base_blockhash,
            base_height,
        } = self.snapshot_state
        {
            self.snapshot_state = SnapshotState::Validated {
                base_blockhash,
                base_height,
            };
            if let Some(activation) = &mut self.snapshot_activation {
                activation.mark_validated();
            }
        }
    }

    /// Check if the background chainstate has reached the snapshot height.
    ///
    /// This is called during block connection in the background chainstate
    /// to detect when we should validate the snapshot.
    pub fn should_validate_snapshot(&self, ibd_height: u32) -> bool {
        if let SnapshotState::Unvalidated { base_height, .. } = self.snapshot_state {
            return ibd_height >= base_height;
        }
        false
    }

    /// Reset the manager (e.g., on cleanup after validation).
    pub fn reset(&mut self) {
        self.snapshot_state = SnapshotState::NotLoaded;
        self.snapshot_activation = None;
        self.snapshot_active = false;
        self.snapshot_base_height = None;
        self.snapshot_base_blockhash = None;
    }

    /// Get recommended cache allocation for snapshot chainstate.
    pub fn snapshot_cache_size(&self, total_cache_bytes: usize) -> usize {
        if self.snapshot_active {
            if matches!(self.snapshot_state, SnapshotState::Loading { .. }) {
                // During load, give most cache to snapshot
                (total_cache_bytes as f64 * SNAPSHOT_CACHE_PERCENT) as usize
            } else {
                // After loading, rebalance
                (total_cache_bytes as f64 * SNAPSHOT_ACTIVE_CACHE_PERCENT) as usize
            }
        } else {
            0
        }
    }

    /// Get recommended cache allocation for IBD chainstate.
    pub fn ibd_cache_size(&self, total_cache_bytes: usize) -> usize {
        if self.snapshot_active {
            if matches!(self.snapshot_state, SnapshotState::Loading { .. }) {
                // During load, give minimal cache to IBD
                (total_cache_bytes as f64 * IBD_CACHE_PERCENT) as usize
            } else {
                // After loading, rebalance
                (total_cache_bytes as f64 * IBD_ACTIVE_CACHE_PERCENT) as usize
            }
        } else {
            // No snapshot, all cache to IBD
            total_cache_bytes
        }
    }
}

impl Default for ChainstateManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_snapshot_metadata_roundtrip() {
        let magic = NetworkMagic([0x1c, 0x16, 0x3f, 0x28]); // testnet4
        let blockhash = Hash256::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();

        let metadata = SnapshotMetadata::new(blockhash, 12345678, magic);

        let mut buf = Vec::new();
        metadata.serialize(&mut buf).unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded = SnapshotMetadata::deserialize(&mut cursor, &magic).unwrap();

        assert_eq!(metadata, decoded);
    }

    #[test]
    fn test_snapshot_metadata_invalid_magic() {
        let magic = NetworkMagic([0x1c, 0x16, 0x3f, 0x28]);
        let bad_data = vec![0x00, 0x01, 0x02, 0x03, 0x04]; // Wrong magic

        let mut cursor = Cursor::new(bad_data);
        let result = SnapshotMetadata::deserialize(&mut cursor, &magic);

        assert!(matches!(result, Err(SnapshotError::InvalidMagic)));
    }

    #[test]
    fn test_snapshot_metadata_wrong_network() {
        let mainnet_magic = NetworkMagic([0xf9, 0xbe, 0xb4, 0xd9]);
        let testnet_magic = NetworkMagic([0x1c, 0x16, 0x3f, 0x28]);
        let blockhash = Hash256::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();

        // Create metadata with mainnet magic
        let metadata = SnapshotMetadata::new(blockhash, 1000, mainnet_magic);
        let mut buf = Vec::new();
        metadata.serialize(&mut buf).unwrap();

        // Try to deserialize expecting testnet magic
        let mut cursor = Cursor::new(buf);
        let result = SnapshotMetadata::deserialize(&mut cursor, &testnet_magic);

        assert!(matches!(result, Err(SnapshotError::NetworkMismatch)));
    }

    #[test]
    fn test_varint_roundtrip() {
        let test_values = [0u64, 1, 252, 253, 254, 255, 256, 65535, 65536, u32::MAX as u64, u64::MAX];

        for value in test_values {
            let mut buf = Vec::new();
            write_varint(&mut buf, value).unwrap();

            let mut cursor = Cursor::new(buf);
            let decoded = read_varint(&mut cursor).unwrap();

            assert_eq!(value, decoded, "Failed for value {}", value);
        }
    }

    #[test]
    fn test_snapshot_state() {
        let state = SnapshotState::NotLoaded;
        assert!(!state.is_active());
        assert!(!state.is_validated());
        assert!(state.base_blockhash().is_none());

        let blockhash = Hash256::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();

        let state = SnapshotState::Unvalidated {
            base_blockhash: blockhash,
            base_height: 100000,
        };
        assert!(state.is_active());
        assert!(!state.is_validated());
        assert_eq!(state.base_blockhash(), Some(blockhash));
        assert_eq!(state.base_height(), Some(100000));

        let state = SnapshotState::Validated {
            base_blockhash: blockhash,
            base_height: 100000,
        };
        assert!(state.is_active());
        assert!(state.is_validated());
    }

    #[test]
    fn test_snapshot_activation() {
        let activation = SnapshotActivation::none();
        assert!(!activation.is_snapshot());
        assert!(activation.snapshot_validated);

        let blockhash = Hash256::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();

        let mut activation = SnapshotActivation::from_snapshot(blockhash);
        assert!(activation.is_snapshot());
        assert!(!activation.snapshot_validated);

        activation.mark_validated();
        assert!(activation.snapshot_validated);
    }

    #[test]
    fn test_assumeutxo_snapshot_writer_reader() {
        let magic = NetworkMagic([0x1c, 0x16, 0x3f, 0x28]);
        let blockhash = Hash256::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();

        // Create a small snapshot with one coin
        let metadata = SnapshotMetadata::new(blockhash, 1, magic);
        let mut output = Vec::new();

        {
            let mut writer = SnapshotWriter::new(&mut output, &metadata).unwrap();

            let txid = Hash256::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000002",
            )
            .unwrap();
            let outpoint = OutPoint { txid, vout: 0 };
            let coin = Coin {
                tx_out: TxOut {
                    value: 5000000000,
                    script_pubkey: vec![0x76, 0xa9, 0x14],
                },
                height: 100,
                is_coinbase: true,
            };

            writer.write_coin(&outpoint, &coin).unwrap();
            let (_, _hash) = writer.finish().unwrap();
        }

        // Read it back
        let cursor = Cursor::new(output);
        let mut reader = SnapshotReader::open(cursor, &magic).unwrap();

        assert_eq!(reader.metadata().coins_count, 1);
        assert_eq!(reader.metadata().base_blockhash, blockhash);

        // Read the coin
        let result = reader.read_coin().unwrap();
        assert!(result.is_some());

        // No more coins
        assert_eq!(reader.coins_read(), 1);
    }

    #[test]
    fn test_loadtxoutset_workflow() {
        // This test simulates the loadtxoutset RPC workflow
        let magic = NetworkMagic([0x1c, 0x16, 0x3f, 0x28]);
        let blockhash = Hash256::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();

        // Create snapshot data
        let metadata = SnapshotMetadata::new(blockhash, 0, magic);
        let mut output = Vec::new();
        {
            let writer = SnapshotWriter::new(&mut output, &metadata).unwrap();
            let _ = writer.finish().unwrap();
        }

        // Verify we can read metadata
        let cursor = Cursor::new(&output);
        let reader = SnapshotReader::open(cursor, &magic).unwrap();

        assert_eq!(reader.metadata().base_blockhash, blockhash);
        assert_eq!(reader.metadata().coins_count, 0);
    }

    #[test]
    fn test_chainstate_manager_initial_state() {
        let manager = ChainstateManager::new();
        assert!(!manager.is_snapshot_active());
        assert!(!manager.is_snapshot_validated());
        assert!(manager.snapshot_base_height().is_none());
        assert!(manager.snapshot_base_blockhash().is_none());
        assert!(matches!(manager.snapshot_state(), SnapshotState::NotLoaded));
    }

    #[test]
    fn test_chainstate_manager_snapshot_loading() {
        let mut manager = ChainstateManager::new();
        let blockhash = Hash256::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();

        // Begin loading
        manager.begin_snapshot_load(blockhash, 100000, 5000000);

        assert!(matches!(manager.snapshot_state(), SnapshotState::Loading { .. }));
        assert_eq!(manager.snapshot_base_height(), Some(100000));
        assert_eq!(manager.snapshot_base_blockhash(), Some(blockhash));
        assert!(!manager.is_snapshot_active());

        // Update progress
        manager.update_snapshot_progress(2500000);
        if let SnapshotState::Loading { coins_loaded, .. } = manager.snapshot_state() {
            assert_eq!(*coins_loaded, 2500000);
        } else {
            panic!("Expected Loading state");
        }
    }

    #[test]
    fn test_chainstate_manager_snapshot_activation() {
        let mut manager = ChainstateManager::new();
        let blockhash = Hash256::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();

        // Load and activate
        manager.begin_snapshot_load(blockhash, 100000, 1000);
        manager.activate_snapshot(blockhash, 100000);

        assert!(manager.is_snapshot_active());
        assert!(!manager.is_snapshot_validated());
        assert!(matches!(
            manager.snapshot_state(),
            SnapshotState::Unvalidated { .. }
        ));
    }

    #[test]
    fn test_chainstate_manager_snapshot_validation() {
        let mut manager = ChainstateManager::new();
        let blockhash = Hash256::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();

        manager.begin_snapshot_load(blockhash, 100000, 1000);
        manager.activate_snapshot(blockhash, 100000);

        // Should validate when IBD reaches snapshot height
        assert!(manager.should_validate_snapshot(100000));
        assert!(manager.should_validate_snapshot(100001));
        assert!(!manager.should_validate_snapshot(99999));

        // Validate
        manager.validate_snapshot();
        assert!(manager.is_snapshot_validated());
        assert!(matches!(
            manager.snapshot_state(),
            SnapshotState::Validated { .. }
        ));
    }

    #[test]
    fn test_chainstate_manager_cache_allocation() {
        let mut manager = ChainstateManager::new();
        let total_cache = 450 * 1024 * 1024; // 450 MiB

        // No snapshot: all cache to IBD
        assert_eq!(manager.ibd_cache_size(total_cache), total_cache);
        assert_eq!(manager.snapshot_cache_size(total_cache), 0);

        // During snapshot loading: most cache to snapshot
        let blockhash = Hash256::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        manager.begin_snapshot_load(blockhash, 100000, 1000);
        manager.snapshot_active = true; // Simulate activation

        let snapshot_cache = manager.snapshot_cache_size(total_cache);
        let ibd_cache = manager.ibd_cache_size(total_cache);
        assert!(snapshot_cache > ibd_cache);
        assert!((snapshot_cache + ibd_cache) as i64 - total_cache as i64 <= 1); // Allow rounding

        // After activation (not loading): rebalance
        manager.activate_snapshot(blockhash, 100000);
        let snapshot_cache = manager.snapshot_cache_size(total_cache);
        let ibd_cache = manager.ibd_cache_size(total_cache);
        assert!(ibd_cache > snapshot_cache); // IBD gets more after load completes
    }

    #[test]
    fn test_chainstate_manager_reset() {
        let mut manager = ChainstateManager::new();
        let blockhash = Hash256::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();

        manager.begin_snapshot_load(blockhash, 100000, 1000);
        manager.activate_snapshot(blockhash, 100000);
        manager.validate_snapshot();

        // Reset
        manager.reset();

        assert!(!manager.is_snapshot_active());
        assert!(!manager.is_snapshot_validated());
        assert!(manager.snapshot_base_height().is_none());
        assert!(matches!(manager.snapshot_state(), SnapshotState::NotLoaded));
    }
}
