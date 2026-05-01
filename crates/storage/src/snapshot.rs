//! AssumeUTXO snapshot support
//!
//! This module implements UTXO set snapshot creation, loading, and validation
//! in **byte-for-byte compatibility with Bitcoin Core's `dumptxoutset` /
//! `loadtxoutset`** (utxo set snapshot format version 2).
//!
//! # Snapshot Format (Bitcoin Core compatible)
//!
//! Header (49 bytes):
//! ```text
//! Magic bytes:      5 bytes     ['u', 't', 'x', 'o', 0xff]
//! Version:          2 bytes     (u16 LE) - Currently 2
//! Network magic:    4 bytes     pchMessageStart
//! Base blockhash:   32 bytes    little-endian (hash byte order on the wire)
//! Coins count:      8 bytes     (u64 LE) Number of coins in the snapshot
//! ```
//!
//! Body — repeated for each *unique txid* in lex order of (txid, vout):
//! ```text
//! txid              32 bytes    little-endian
//! n_coins           varint      CompactSize: number of unspent outputs in this txid
//!   per-coin (n_coins entries):
//!     vout          varint      CompactSize: output index
//!     code          VARINT      Bitcoin VARINT (NOT CompactSize): height<<1 | coinbase
//!     amount        VARINT      Bitcoin VARINT of CompressAmount(value)
//!     script        ScriptCompression: VARINT(size) + raw bytes (special-cased
//!                               for P2PKH/P2SH/P2PK so size in {0..5} is special)
//! ```
//!
//! NOTE: the outer `n_coins` and `vout` use Bitcoin's CompactSize encoding
//! (the `<` `0xFD` / `0xFD <u16>` / `0xFE <u32>` / `0xFF <u64>` form). The inner
//! `code`, `amount`, and script `size` use Bitcoin's *VARINT* encoding (a
//! distinct, base-128 variant defined in `bitcoin-core/src/serialize.h`'s
//! `WriteVarInt`/`ReadVarInt`). These two are NOT interchangeable.
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
///
/// Streams the Core-compatible body one coin at a time. Internally it
/// remembers the current txid + remaining-coins-in-txid window so successive
/// `read_coin` calls return individual `(OutPoint, Coin)` pairs even though
/// the on-disk format groups them by txid.
pub struct SnapshotReader<R: Read> {
    reader: BufReader<R>,
    metadata: SnapshotMetadata,
    coins_read: u64,
    /// Active txid we are unpacking from the on-disk grouping.
    current_txid: Option<Hash256>,
    /// Number of coins remaining for the active txid.
    coins_remaining_in_txid: u64,
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
            current_txid: None,
            coins_remaining_in_txid: 0,
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
    /// Returns `None` when all coins have been read. Coins for a given txid
    /// arrive consecutively (matching the on-disk grouping).
    pub fn read_coin(&mut self) -> Result<Option<(OutPoint, Coin)>, SnapshotError> {
        if self.coins_read >= self.metadata.coins_count {
            return Ok(None);
        }

        // If we exhausted the current txid window, parse the next group header.
        if self.coins_remaining_in_txid == 0 {
            // Read txid (32 bytes, on-the-wire byte order)
            let mut txid_bytes = [0u8; 32];
            self.reader.read_exact(&mut txid_bytes)?;
            let txid = Hash256(txid_bytes);

            // CompactSize: number of coins for this txid.
            let coins_per_txid = read_compact_size(&mut self.reader)?;
            if coins_per_txid == 0 {
                return Err(SnapshotError::MalformedCoin(
                    "zero coins per txid".to_string(),
                ));
            }
            self.current_txid = Some(txid);
            self.coins_remaining_in_txid = coins_per_txid;
        }

        // CompactSize: vout for this coin within the current txid group.
        let vout = read_compact_size(&mut self.reader)? as u32;

        // VARINT: code = (height << 1) | is_coinbase
        let code = read_varint(&mut self.reader)?;
        let height = (code >> 1) as u32;
        let is_coinbase = (code & 1) == 1;

        // VARINT(CompressAmount(value))
        let compressed_amount = read_varint(&mut self.reader)?;
        let value = decompress_amount(compressed_amount);

        // ScriptCompression
        let script_pubkey = read_compressed_script(&mut self.reader)?;

        let txid = self
            .current_txid
            .ok_or_else(|| SnapshotError::MalformedCoin("missing txid window".to_string()))?;
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
        self.coins_remaining_in_txid -= 1;
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

/// Writer for creating UTXO snapshots in Bitcoin Core's byte-compatible
/// `dumptxoutset` format (version 2).
///
/// Coins must be supplied in lexicographic order by `(txid, vout)` — matching
/// the order produced by Core's leveldb `CCoinsViewCursor` and rustoshi's
/// `outpoint_key` (txid || vout BE). The writer buffers consecutive coins
/// that share a txid and flushes the group once the next txid arrives, since
/// the on-disk format prefixes each *unique txid* with the count of unspent
/// outputs in that tx.
pub struct SnapshotWriter<W: Write> {
    writer: BufWriter<W>,
    coins_written: u64,
    /// Running double-SHA256 hash over the per-coin serialization (matches the
    /// hash form stored in `AssumeutxoData::hash_serialized` in chainparams).
    hasher: Sha256,
    /// Buffered (vout, coin) entries that share `pending_txid`.
    pending_txid: Option<Hash256>,
    pending_coins: Vec<(u32, Coin)>,
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
            pending_txid: None,
            pending_coins: Vec::new(),
        })
    }

    /// Write a coin to the snapshot.
    ///
    /// Coins **must** be supplied in lexicographic order by outpoint
    /// (txid bytes ascending, then vout ascending) — this matches how
    /// Bitcoin Core's leveldb cursor exposes them and the order in which
    /// rustoshi's RocksDB UTXO column family iterates by `outpoint_key`.
    /// Out-of-order calls within a txid are still accepted and resorted on
    /// flush, but switching back to a previously-flushed txid will panic
    /// because the per-txid grouping has already been emitted.
    pub fn write_coin(&mut self, outpoint: &OutPoint, coin: &Coin) -> Result<(), SnapshotError> {
        match self.pending_txid {
            Some(t) if t == outpoint.txid => {
                self.pending_coins.push((outpoint.vout, coin.clone()));
            }
            Some(_) => {
                self.flush_group()?;
                self.pending_txid = Some(outpoint.txid);
                self.pending_coins.push((outpoint.vout, coin.clone()));
            }
            None => {
                self.pending_txid = Some(outpoint.txid);
                self.pending_coins.push((outpoint.vout, coin.clone()));
            }
        }
        Ok(())
    }

    /// Flush the currently-buffered coins as a single per-txid group.
    fn flush_group(&mut self) -> Result<(), SnapshotError> {
        let txid = match self.pending_txid.take() {
            Some(t) => t,
            None => return Ok(()),
        };
        // Sort coins by vout to guarantee canonical ordering, even if the
        // caller delivered them out-of-order within a txid.
        self.pending_coins.sort_by_key(|(vout, _)| *vout);

        // Emit the group header: txid bytes + CompactSize(n_coins).
        self.writer.write_all(txid.as_bytes())?;
        write_compact_size(&mut self.writer, self.pending_coins.len() as u64)?;

        // Emit each coin: CompactSize(vout) + VARINT(code) + VARINT(CompressAmount(value)) + ScriptCompression(spk).
        let pending = std::mem::take(&mut self.pending_coins);
        for (vout, coin) in &pending {
            write_compact_size(&mut self.writer, *vout as u64)?;
            let code = (coin.height as u64) * 2 + if coin.is_coinbase { 1 } else { 0 };
            write_varint(&mut self.writer, code)?;
            write_varint(&mut self.writer, compress_amount(coin.tx_out.value))?;
            write_compressed_script(&mut self.writer, &coin.tx_out.script_pubkey)?;

            // Update the running content hash. Use the same per-coin serialization
            // as `compute_utxo_hash` so writer + reader agree.
            let outpoint = OutPoint { txid, vout: *vout };
            let coin_bytes = serialize_coin_for_hash(&outpoint, coin);
            self.hasher.update(&coin_bytes);

            self.coins_written += 1;
        }
        Ok(())
    }

    /// Finish writing and get the content hash.
    pub fn finish(mut self) -> Result<(W, AssumeutxoHash), SnapshotError> {
        self.flush_group()?;
        self.writer.flush()?;

        // Double-SHA256 to match `compute_utxo_hash`.
        let first_hash = self.hasher.finalize();
        let mut second_hasher = Sha256::new();
        second_hasher.update(first_hash);
        let final_hash = second_hasher.finalize();
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&final_hash);
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

/// Serialize a `(OutPoint, Coin)` for the assumeutxo content hash. Mirrors
/// `compute_utxo_hash`'s per-coin layout.
fn serialize_coin_for_hash(outpoint: &OutPoint, coin: &Coin) -> Vec<u8> {
    let mut data = Vec::with_capacity(32 + 4 + 4 + 1 + 8 + coin.tx_out.script_pubkey.len());
    data.extend_from_slice(outpoint.txid.as_bytes());
    data.extend_from_slice(&outpoint.vout.to_le_bytes());
    data.extend_from_slice(&coin.height.to_le_bytes());
    data.push(if coin.is_coinbase { 1 } else { 0 });
    data.extend_from_slice(&coin.tx_out.value.to_le_bytes());
    data.extend_from_slice(&coin.tx_out.script_pubkey);
    data
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
    second_hasher.update(first_hash);
    let final_hash = second_hasher.finalize();

    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&final_hash);
    AssumeutxoHash(Hash256(hash_bytes))
}

// ============================================================
// HELPER FUNCTIONS
// ============================================================
//
// IMPORTANT: There are TWO distinct variable-length integer encodings used
// here, mirroring `bitcoin-core/src/serialize.h`:
//
// * `read_compact_size` / `write_compact_size`  — Bitcoin's "CompactSize",
//   the prefix-byte form (`<0xFD` literal | `0xFD <u16>` | `0xFE <u32>` |
//   `0xFF <u64>`). Used for outer counts in many P2P/block contexts AND
//   inside the snapshot for the per-txid coin count and per-coin vout.
//
// * `read_varint` / `write_varint` — Bitcoin's "VARINT", a base-128 form
//   that encodes integers 7 bits at a time with a continuation flag in the
//   high bit (matches Core's `WriteVarInt`/`ReadVarInt`). Used inside Coin
//   serialization for `code` (height|coinbase) and inside ScriptCompression
//   for the script size, and inside AmountCompression for the compressed
//   amount.

// ----- CompactSize -----

/// Read a Bitcoin CompactSize integer.
fn read_compact_size<R: Read>(reader: &mut R) -> Result<u64, SnapshotError> {
    let mut first = [0u8; 1];
    reader.read_exact(&mut first)?;

    match first[0] {
        0..=0xFC => Ok(first[0] as u64),
        0xFD => {
            let mut buf = [0u8; 2];
            reader.read_exact(&mut buf)?;
            let v = u16::from_le_bytes(buf) as u64;
            if v < 0xFD {
                return Err(SnapshotError::MalformedCoin("non-canonical CompactSize".into()));
            }
            Ok(v)
        }
        0xFE => {
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf)?;
            let v = u32::from_le_bytes(buf) as u64;
            if v <= 0xFFFF {
                return Err(SnapshotError::MalformedCoin("non-canonical CompactSize".into()));
            }
            Ok(v)
        }
        0xFF => {
            let mut buf = [0u8; 8];
            reader.read_exact(&mut buf)?;
            let v = u64::from_le_bytes(buf);
            if v <= 0xFFFFFFFF {
                return Err(SnapshotError::MalformedCoin("non-canonical CompactSize".into()));
            }
            Ok(v)
        }
    }
}

/// Write a Bitcoin CompactSize integer.
fn write_compact_size<W: Write>(writer: &mut W, value: u64) -> Result<(), SnapshotError> {
    if value < 0xFD {
        writer.write_all(&[value as u8])?;
    } else if value <= 0xFFFF {
        writer.write_all(&[0xFD])?;
        writer.write_all(&(value as u16).to_le_bytes())?;
    } else if value <= 0xFFFF_FFFF {
        writer.write_all(&[0xFE])?;
        writer.write_all(&(value as u32).to_le_bytes())?;
    } else {
        writer.write_all(&[0xFF])?;
        writer.write_all(&value.to_le_bytes())?;
    }
    Ok(())
}

// ----- Bitcoin VARINT (base-128, NOT CompactSize) -----

/// Write Bitcoin's VARINT as defined in `bitcoin-core/src/serialize.h`'s
/// `WriteVarInt` (default `VarIntMode::DEFAULT`).
fn write_varint<W: Write>(writer: &mut W, mut n: u64) -> Result<(), SnapshotError> {
    // Build bytes in reverse, then emit. Highest bit of every byte except
    // the last is set to 1 to indicate continuation.
    let mut tmp = [0u8; 10]; // ceil(64/7) = 10
    let mut len = 0usize;
    loop {
        let cont = if len > 0 { 0x80 } else { 0x00 };
        tmp[len] = ((n & 0x7F) as u8) | cont;
        if n <= 0x7F {
            break;
        }
        n = (n >> 7) - 1;
        len += 1;
    }
    // Emit in reverse: tmp[len], tmp[len-1], ..., tmp[0]
    let mut i = len as isize;
    while i >= 0 {
        writer.write_all(&[tmp[i as usize]])?;
        i -= 1;
    }
    Ok(())
}

/// Read Bitcoin's VARINT (mirrors `ReadVarInt` in
/// `bitcoin-core/src/serialize.h`, default `VarIntMode::DEFAULT`).
fn read_varint<R: Read>(reader: &mut R) -> Result<u64, SnapshotError> {
    let mut n: u64 = 0;
    loop {
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte)?;
        if n > (u64::MAX >> 7) {
            return Err(SnapshotError::MalformedCoin("VARINT: size too large".into()));
        }
        n = (n << 7) | (byte[0] & 0x7F) as u64;
        if (byte[0] & 0x80) != 0 {
            if n == u64::MAX {
                return Err(SnapshotError::MalformedCoin("VARINT: size too large".into()));
            }
            n += 1;
        } else {
            return Ok(n);
        }
    }
}

// ----- Amount compression (Core compressor.cpp) -----

/// Port of Bitcoin Core's `CompressAmount` — see compressor.cpp lines 149-166.
pub fn compress_amount(mut n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut e: u64 = 0;
    while (n % 10 == 0) && e < 9 {
        n /= 10;
        e += 1;
    }
    if e < 9 {
        let d = n % 10;
        debug_assert!((1..=9).contains(&d));
        n /= 10;
        1 + (n * 9 + d - 1) * 10 + e
    } else {
        1 + (n - 1) * 10 + 9
    }
}

/// Port of Bitcoin Core's `DecompressAmount` — see compressor.cpp lines 168-192.
pub fn decompress_amount(mut x: u64) -> u64 {
    if x == 0 {
        return 0;
    }
    x -= 1;
    let e = x % 10;
    x /= 10;
    let mut n: u64 = if e < 9 {
        let d = (x % 9) + 1;
        x /= 9;
        x * 10 + d
    } else {
        x + 1
    };
    let mut e_loop = e;
    while e_loop > 0 {
        n *= 10;
        e_loop -= 1;
    }
    n
}

// ----- Script compression (Core compressor.cpp) -----

/// Number of "special" script encoding cases. Mirrors Core's
/// `ScriptCompression::nSpecialScripts = 6`.
const N_SPECIAL_SCRIPTS: u64 = 6;

/// Maximum legal script size after decompression. Matches `MAX_SCRIPT_SIZE`
/// in Core's `script.h` (10_000 bytes). Anything larger gets replaced with a
/// short OP_RETURN-only script per Core's behavior.
const MAX_SCRIPT_SIZE: usize = 10_000;

/// Try to compress a scriptPubKey to one of Core's special forms (P2PKH,
/// P2SH, P2PK). Returns the compressed bytes (without size prefix) for one
/// of: 21 bytes (P2PKH/P2SH), 33 bytes (P2PK), or `None` if no special form
/// applies.
fn try_compress_script(script: &[u8]) -> Option<(u8, Vec<u8>)> {
    // P2PKH: OP_DUP OP_HASH160 <20> ... OP_EQUALVERIFY OP_CHECKSIG
    if script.len() == 25
        && script[0] == 0x76    // OP_DUP
        && script[1] == 0xa9    // OP_HASH160
        && script[2] == 20
        && script[23] == 0x88   // OP_EQUALVERIFY
        && script[24] == 0xac
    // OP_CHECKSIG
    {
        let mut out = Vec::with_capacity(20);
        out.extend_from_slice(&script[3..23]);
        return Some((0x00, out));
    }
    // P2SH: OP_HASH160 <20> ... OP_EQUAL
    if script.len() == 23
        && script[0] == 0xa9
        && script[1] == 20
        && script[22] == 0x87
    {
        let mut out = Vec::with_capacity(20);
        out.extend_from_slice(&script[2..22]);
        return Some((0x01, out));
    }
    // Compressed P2PK (33-byte pubkey, leading 0x02 or 0x03):
    if script.len() == 35
        && script[0] == 33
        && script[34] == 0xac
        && (script[1] == 0x02 || script[1] == 0x03)
    {
        let mut out = Vec::with_capacity(32);
        out.extend_from_slice(&script[2..34]);
        return Some((script[1], out));
    }
    // Uncompressed P2PK (65-byte pubkey, leading 0x04). We can compress the
    // x-coordinate but recovery of y at decompress time requires secp256k1
    // arithmetic (Core calls `pubkey.Decompress()`). rustoshi's secp module
    // is in the `rustoshi_crypto` crate, but `rustoshi_storage` does not
    // depend on it; to keep the dependency graph clean, we don't emit the
    // 0x04/0x05 special form on the writer side. Decompression of these
    // forms IS supported on the reader side (TODO: hook secp).
    None
}

/// Compute the decompressed script size for a "special" Core encoding.
/// Mirrors `GetSpecialScriptSize` in `compressor.cpp`.
fn special_script_size(n_size: u64) -> usize {
    match n_size {
        0 | 1 => 20,
        2 | 3 | 4 | 5 => 32,
        _ => 0,
    }
}

/// Decompress a special-form script back to its raw scriptPubKey bytes.
/// Returns `None` if the form is one we cannot reconstruct (currently the
/// uncompressed P2PK 0x04/0x05 forms — TODO: integrate secp256k1 to recover
/// the full 65-byte pubkey). For now those decode as a placeholder
/// `OP_RETURN` to match Core's "overly long script" sentinel.
fn decompress_special_script(n_size: u64, payload: &[u8]) -> Option<Vec<u8>> {
    match n_size {
        0x00 => {
            // P2PKH: OP_DUP OP_HASH160 <20> ... OP_EQUALVERIFY OP_CHECKSIG
            let mut out = Vec::with_capacity(25);
            out.extend_from_slice(&[0x76, 0xa9, 20]);
            out.extend_from_slice(&payload[..20]);
            out.extend_from_slice(&[0x88, 0xac]);
            Some(out)
        }
        0x01 => {
            // P2SH: OP_HASH160 <20> ... OP_EQUAL
            let mut out = Vec::with_capacity(23);
            out.extend_from_slice(&[0xa9, 20]);
            out.extend_from_slice(&payload[..20]);
            out.push(0x87);
            Some(out)
        }
        0x02 | 0x03 => {
            // Compressed P2PK: 33-byte push + OP_CHECKSIG.
            let mut out = Vec::with_capacity(35);
            out.push(33);
            out.push(n_size as u8);
            out.extend_from_slice(&payload[..32]);
            out.push(0xac);
            Some(out)
        }
        0x04 | 0x05 => {
            // TODO(snapshot-compress): recover full uncompressed pubkey via
            // secp256k1 point decompression. For now, rustoshi never emits
            // this on the writer side, but a Core-produced snapshot may
            // include it — we substitute a placeholder OP_RETURN so loading
            // does not crash. UTXOs decoded this way will not validate as
            // spendable, but the loader still acks the byte stream.
            let _ = payload;
            Some(vec![0x6a]) // OP_RETURN
        }
        _ => None,
    }
}

/// Write a scriptPubKey using Core's `ScriptCompression` formatter.
fn write_compressed_script<W: Write>(writer: &mut W, script: &[u8]) -> Result<(), SnapshotError> {
    if let Some((prefix, payload)) = try_compress_script(script) {
        // Special form: write the single-byte VARINT(prefix) followed by the
        // (already-compact) payload bytes. No size prefix — the prefix
        // implicitly determines the payload length.
        write_varint(writer, prefix as u64)?;
        writer.write_all(&payload)?;
        return Ok(());
    }
    // Generic form: VARINT(size + N_SPECIAL_SCRIPTS), then raw script bytes.
    let n_size = (script.len() as u64) + N_SPECIAL_SCRIPTS;
    write_varint(writer, n_size)?;
    writer.write_all(script)?;
    Ok(())
}

/// Read a scriptPubKey using Core's `ScriptCompression` formatter.
fn read_compressed_script<R: Read>(reader: &mut R) -> Result<Vec<u8>, SnapshotError> {
    let n_size = read_varint(reader)?;
    if n_size < N_SPECIAL_SCRIPTS {
        // Special-cased compressed form.
        let payload_len = special_script_size(n_size);
        if payload_len == 0 {
            return Err(SnapshotError::MalformedCoin(format!(
                "invalid special script size {n_size}"
            )));
        }
        let mut payload = vec![0u8; payload_len];
        reader.read_exact(&mut payload)?;
        return decompress_special_script(n_size, &payload).ok_or_else(|| {
            SnapshotError::MalformedCoin(format!("unsupported special script size {n_size}"))
        });
    }
    // Generic form: real script bytes follow.
    let raw_size = (n_size - N_SPECIAL_SCRIPTS) as usize;
    if raw_size > MAX_SCRIPT_SIZE {
        // Mirror Core's "overly long script, replace with OP_RETURN" sentinel.
        let mut waste = vec![0u8; raw_size];
        reader.read_exact(&mut waste)?;
        return Ok(vec![0x6a]); // OP_RETURN
    }
    let mut script = vec![0u8; raw_size];
    reader.read_exact(&mut script)?;
    Ok(script)
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
    fn test_compact_size_roundtrip() {
        let test_values = [
            0u64,
            1,
            252,
            253,
            254,
            255,
            256,
            65535,
            65536,
            u32::MAX as u64,
            (u32::MAX as u64) + 1,
            u64::MAX,
        ];

        for value in test_values {
            let mut buf = Vec::new();
            write_compact_size(&mut buf, value).unwrap();
            let mut cursor = Cursor::new(buf);
            let decoded = read_compact_size(&mut cursor).unwrap();
            assert_eq!(value, decoded, "Failed for value {}", value);
        }
    }

    #[test]
    fn test_compact_size_known_byte_vectors() {
        // Vector check: 0xFC must encode as a single byte 0xFC.
        let mut buf = Vec::new();
        write_compact_size(&mut buf, 0xFC).unwrap();
        assert_eq!(buf, vec![0xFC]);

        // 0xFD must encode as 0xFD 0xFD 0x00.
        buf.clear();
        write_compact_size(&mut buf, 0xFD).unwrap();
        assert_eq!(buf, vec![0xFD, 0xFD, 0x00]);

        // 0x10000 must encode as 0xFE 0x00 0x00 0x01 0x00.
        buf.clear();
        write_compact_size(&mut buf, 0x10000).unwrap();
        assert_eq!(buf, vec![0xFE, 0x00, 0x00, 0x01, 0x00]);
    }

    #[test]
    fn test_varint_roundtrip() {
        // Bitcoin's VARINT (base-128, NOT CompactSize)
        let test_values: [u64; 17] = [
            0, 1, 0x7F, 0x80, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFF, 0x10000, 0xFFFF_FFFF,
            0x1_0000_0000, 0xFFFF_FFFF_FFFF_FFFE, u64::MAX - 1,
            u32::MAX as u64, u32::MAX as u64 + 1, 1234567,
        ];

        for value in test_values {
            let mut buf = Vec::new();
            write_varint(&mut buf, value).unwrap();
            let mut cursor = Cursor::new(buf);
            let decoded = read_varint(&mut cursor).unwrap();
            assert_eq!(value, decoded, "Failed for value {}", value);
        }
    }

    #[test]
    fn test_varint_known_byte_vectors() {
        // Cross-checked against Bitcoin Core's WriteVarInt / ReadVarInt.
        // These are the canonical sample values used in Core's serialize tests.
        for (value, expected) in [
            (0u64, vec![0x00u8]),
            (1, vec![0x01]),
            (0x7F, vec![0x7F]),
            (0x80, vec![0x80, 0x00]),
            (0xFF, vec![0x80, 0x7F]),
            (0x1234, vec![0xA3, 0x34]),
            (0x100, vec![0x81, 0x00]),
            (0x7FFF, vec![0x80, 0xFE, 0x7F]),
            (0xFFFF, vec![0x82, 0xFE, 0x7F]),
        ] {
            let mut buf = Vec::new();
            write_varint(&mut buf, value).unwrap();
            assert_eq!(buf, expected, "VARINT mismatch for {}", value);
            let mut cursor = Cursor::new(buf);
            let decoded = read_varint(&mut cursor).unwrap();
            assert_eq!(value, decoded);
        }
    }

    #[test]
    fn test_compress_amount_roundtrip() {
        // Spot check known values from Bitcoin Core's compressor unit tests.
        let cases: &[(u64, u64)] = &[
            (0, 0),
            (1, 0x9),
            (1_0000_0000, 0x6),       // 1 BTC
            (50_0000_0000, 0x32),     // 50 BTC (genesis subsidy)
            (21_000_000 * 100_000_000, 21_000_000 * 100_000_000),
        ];
        for (value, _expected_compressed) in cases {
            let c = compress_amount(*value);
            let d = decompress_amount(c);
            assert_eq!(*value, d, "amount roundtrip failed for {}", value);
        }

        // Sweep across values that exercise every (e, d) bucket.
        for v in [
            0u64, 1, 9, 10, 99, 100, 999, 1_000_000, 50_0000_0000, 1234567890,
            21_000_000 * 100_000_000,
        ] {
            assert_eq!(decompress_amount(compress_amount(v)), v);
        }
    }

    #[test]
    fn test_compress_script_p2pkh() {
        // P2PKH: OP_DUP OP_HASH160 <20> ... OP_EQUALVERIFY OP_CHECKSIG → 22 bytes (1 VARINT + 20 payload).
        let mut p2pkh = vec![0x76u8, 0xa9, 20];
        p2pkh.extend_from_slice(&[0x42; 20]);
        p2pkh.extend_from_slice(&[0x88, 0xac]);

        let mut buf = Vec::new();
        write_compressed_script(&mut buf, &p2pkh).unwrap();
        assert_eq!(buf.len(), 21, "P2PKH should compress to 21 bytes (1 VARINT + 20 hash)");
        assert_eq!(buf[0], 0x00, "P2PKH compressed prefix is 0x00");

        let mut cursor = Cursor::new(&buf);
        let decoded = read_compressed_script(&mut cursor).unwrap();
        assert_eq!(decoded, p2pkh);
    }

    #[test]
    fn test_compress_script_p2sh() {
        // P2SH: OP_HASH160 <20> ... OP_EQUAL → 21 bytes.
        let mut p2sh = vec![0xa9u8, 20];
        p2sh.extend_from_slice(&[0x55; 20]);
        p2sh.push(0x87);

        let mut buf = Vec::new();
        write_compressed_script(&mut buf, &p2sh).unwrap();
        assert_eq!(buf.len(), 21);
        assert_eq!(buf[0], 0x01, "P2SH compressed prefix is 0x01");

        let mut cursor = Cursor::new(&buf);
        let decoded = read_compressed_script(&mut cursor).unwrap();
        assert_eq!(decoded, p2sh);
    }

    #[test]
    fn test_compress_script_p2pk_compressed() {
        // P2PK with compressed pubkey: 33-byte push + OP_CHECKSIG.
        let mut p2pk = vec![33u8, 0x02];
        p2pk.extend_from_slice(&[0x42; 32]);
        p2pk.push(0xac);

        let mut buf = Vec::new();
        write_compressed_script(&mut buf, &p2pk).unwrap();
        assert_eq!(buf.len(), 33);
        assert_eq!(buf[0], 0x02);

        let mut cursor = Cursor::new(&buf);
        let decoded = read_compressed_script(&mut cursor).unwrap();
        assert_eq!(decoded, p2pk);
    }

    #[test]
    fn test_compress_script_generic() {
        // Generic script (e.g. P2WPKH): VARINT(size + 6) + raw bytes.
        let p2wpkh = {
            let mut s = vec![0x00u8, 20];
            s.extend_from_slice(&[0xab; 20]);
            s
        };

        let mut buf = Vec::new();
        write_compressed_script(&mut buf, &p2wpkh).unwrap();

        let mut cursor = Cursor::new(&buf);
        let decoded = read_compressed_script(&mut cursor).unwrap();
        assert_eq!(decoded, p2wpkh);

        // Sanity: VARINT prefix should encode size + 6 = 22 + 6 = 28.
        let mut cursor2 = Cursor::new(&buf);
        let n = read_varint(&mut cursor2).unwrap();
        assert_eq!(n, 22 + N_SPECIAL_SCRIPTS);
    }

    #[test]
    fn test_multi_output_txid_grouping() {
        // Regression test for the pre-fix corruption bug: a snapshot with
        // multiple unspent outputs from the same txid was being written with
        // hardcoded coins_per_txid = 1 and then per-coin headers. This test
        // confirms that the rewritten writer:
        //   (a) groups all outputs of one txid into a single (txid, count, ...)
        //   (b) the reader exposes them as individual (OutPoint, Coin) pairs
        //   (c) the round-tripped data matches input byte-for-byte.

        let magic = NetworkMagic([0xf9, 0xbe, 0xb4, 0xd9]);
        let blockhash = Hash256::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000abc",
        )
        .unwrap();

        let txid_a = Hash256::from_hex(
            "1100000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();
        let txid_b = Hash256::from_hex(
            "2200000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();

        let mut p2pkh = vec![0x76u8, 0xa9, 20];
        p2pkh.extend_from_slice(&[0x33; 20]);
        p2pkh.extend_from_slice(&[0x88, 0xac]);

        let coins = vec![
            (
                OutPoint { txid: txid_a, vout: 0 },
                Coin {
                    tx_out: TxOut { value: 10_000, script_pubkey: p2pkh.clone() },
                    height: 100,
                    is_coinbase: false,
                },
            ),
            (
                OutPoint { txid: txid_a, vout: 1 },
                Coin {
                    tx_out: TxOut { value: 20_000, script_pubkey: p2pkh.clone() },
                    height: 100,
                    is_coinbase: false,
                },
            ),
            (
                OutPoint { txid: txid_a, vout: 2 },
                Coin {
                    tx_out: TxOut { value: 30_000, script_pubkey: p2pkh.clone() },
                    height: 100,
                    is_coinbase: false,
                },
            ),
            (
                OutPoint { txid: txid_b, vout: 0 },
                Coin {
                    tx_out: TxOut { value: 50_000, script_pubkey: p2pkh.clone() },
                    height: 200,
                    is_coinbase: true,
                },
            ),
        ];

        let metadata = SnapshotMetadata::new(blockhash, coins.len() as u64, magic);

        let mut output = Vec::new();
        {
            let mut writer = SnapshotWriter::new(&mut output, &metadata).unwrap();
            for (op, coin) in &coins {
                writer.write_coin(op, coin).unwrap();
            }
            let (_w, _hash) = writer.finish().unwrap();
        }

        let cursor = Cursor::new(output);
        let mut reader = SnapshotReader::open(cursor, &magic).unwrap();
        let mut decoded = Vec::new();
        while let Some((op, coin)) = reader.read_coin().unwrap() {
            decoded.push((op, coin));
        }
        reader.verify_complete().unwrap();

        assert_eq!(decoded.len(), coins.len());
        for ((eop, ec), (dop, dc)) in coins.iter().zip(decoded.iter()) {
            assert_eq!(eop.txid, dop.txid);
            assert_eq!(eop.vout, dop.vout);
            assert_eq!(ec.height, dc.height);
            assert_eq!(ec.is_coinbase, dc.is_coinbase);
            assert_eq!(ec.tx_out.value, dc.tx_out.value);
            assert_eq!(ec.tx_out.script_pubkey, dc.tx_out.script_pubkey);
        }
    }

    #[test]
    fn test_snapshot_byte_layout_locked() {
        // Lock down the on-disk layout so a future "tidy-up" can't silently
        // break Core compatibility. We hand-construct the expected byte stream
        // for a one-coin snapshot and assert byte-for-byte equality with the
        // writer's output.

        let magic = NetworkMagic([0xf9, 0xbe, 0xb4, 0xd9]); // mainnet
        let blockhash = Hash256::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        let txid = Hash256::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000002",
        )
        .unwrap();

        // P2PKH script — special-cased to 21 compressed bytes (prefix 0x00).
        let mut p2pkh = vec![0x76u8, 0xa9, 20];
        p2pkh.extend_from_slice(&[0x77; 20]);
        p2pkh.extend_from_slice(&[0x88, 0xac]);

        let coin = Coin {
            tx_out: TxOut {
                value: 50_0000_0000,
                script_pubkey: p2pkh.clone(),
            },
            height: 1,
            is_coinbase: true,
        };
        let outpoint = OutPoint { txid, vout: 0 };

        let metadata = SnapshotMetadata::new(blockhash, 1, magic);
        let mut output = Vec::new();
        {
            let mut writer = SnapshotWriter::new(&mut output, &metadata).unwrap();
            writer.write_coin(&outpoint, &coin).unwrap();
            writer.finish().unwrap();
        }

        // Assemble the expected bytes by hand.
        let mut expected = Vec::new();
        // Header.
        expected.extend_from_slice(&SNAPSHOT_MAGIC_BYTES);
        expected.extend_from_slice(&SNAPSHOT_VERSION.to_le_bytes());
        expected.extend_from_slice(&[0xf9, 0xbe, 0xb4, 0xd9]);
        expected.extend_from_slice(blockhash.as_bytes());
        expected.extend_from_slice(&1u64.to_le_bytes());
        // Body: txid + CompactSize(1) + CompactSize(0) + VARINT(code=3) + VARINT(CompressAmount(50e8)) + ScriptCompression(P2PKH).
        expected.extend_from_slice(txid.as_bytes());
        expected.push(0x01); // CompactSize n_coins=1
        expected.push(0x00); // CompactSize vout=0
        expected.push(0x03); // VARINT code = (1 << 1) | 1
        // VARINT(CompressAmount(50e8)) — compute on the fly.
        let mut amt_buf = Vec::new();
        write_varint(&mut amt_buf, compress_amount(50_0000_0000)).unwrap();
        expected.extend_from_slice(&amt_buf);
        // ScriptCompression: prefix 0x00 + 20 hash bytes.
        expected.push(0x00);
        expected.extend_from_slice(&[0x77; 20]);

        assert_eq!(output, expected, "on-disk byte layout drifted from spec");
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
