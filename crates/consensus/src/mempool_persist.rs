//! Bitcoin Core-compatible `mempool.dat` persistence.
//!
//! Implements byte-for-byte the same on-disk format as Bitcoin Core's
//! `bitcoin-core/src/node/mempool_persist.cpp` so that the resulting
//! `mempool.dat` file can be exchanged with any Core-compatible node:
//!
//! ```text
//!   uint64 LE  version          (1 = no XOR key, 2 = obfuscated)
//!   if version == 2:
//!     compactsize(8)             always 0x08
//!     [u8; 8]    obfuscation key
//!   --- payload, XOR-obfuscated when version == 2 ---
//!   uint64 LE  count             number of transactions
//!   for each tx:
//!     CTransaction (with witness)
//!     int64 LE   nTime           wall-clock seconds since Unix epoch
//!     int64 LE   nFeeDelta       prioritisetransaction delta (sats)
//!   compactsize  num_deltas
//!   for each:
//!     [u8; 32]   txid (LE)
//!     int64 LE   amount delta (sats)
//!   compactsize  num_unbroadcast
//!   for each:
//!     [u8; 32]   txid (LE)
//! ```
//!
//! The XOR obfuscation in version 2 stretches an 8-byte key over the
//! whole payload: byte `j` of the payload is XORed with `key[j % 8]`,
//! starting from `j = 0` immediately after the obfuscation key itself.
//!
//! On dump, rustoshi writes version 2 with a freshly-randomised key,
//! matching the Core default. On load, both versions are accepted.
//!
//! # Cross-implementation goal
//!
//! All ten Hashhog implementations target byte-for-byte compatibility
//! with this format so that operators can move `mempool.dat` between
//! nodes (and Core) without regenerating it.

use crate::mempool::{Mempool, MempoolError};
use crate::validation::CoinEntry;
use rustoshi_primitives::serialize::{
    compact_size_len, read_compact_size, write_compact_size, Decodable, Encodable,
};
use rustoshi_primitives::{Hash256, OutPoint, Transaction};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

/// Versions understood by [`load_mempool`]. We always dump as v2.
pub const MEMPOOL_DUMP_VERSION_NO_XOR_KEY: u64 = 1;
pub const MEMPOOL_DUMP_VERSION: u64 = 2;

/// Length in bytes of the Core-format obfuscation key.
pub const OBFUSCATION_KEY_LEN: usize = 8;

/// Sanity cap on the per-section count fields to avoid OOM on a corrupt
/// or hostile file. 16 million is well above any realistic mempool size
/// and well below the 32-bit count cap Core uses for its CompactSize
/// guards.
const MAX_DUMP_ENTRIES: u64 = 16_000_000;

// ---------------------------------------------------------------------
// XOR-obfuscated stream wrappers
// ---------------------------------------------------------------------

/// Reader that XORs bytes against an 8-byte rolling key as they are read.
///
/// Mirrors `Obfuscation::operator()` in Bitcoin Core's `util/obfuscation.h`:
/// for an absolute byte offset `j` from the start of the obfuscated
/// region, the byte is XORed with `key[j % 8]`.
struct XorReader<R> {
    inner: R,
    key: [u8; OBFUSCATION_KEY_LEN],
    /// Number of bytes consumed since the obfuscation began.
    pos: u64,
}

impl<R: Read> XorReader<R> {
    fn new(inner: R, key: [u8; OBFUSCATION_KEY_LEN]) -> Self {
        Self { inner, key, pos: 0 }
    }
}

impl<R: Read> Read for XorReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if !is_zero_key(&self.key) {
            for i in 0..n {
                let key_index = ((self.pos + i as u64) % OBFUSCATION_KEY_LEN as u64) as usize;
                buf[i] ^= self.key[key_index];
            }
        }
        self.pos += n as u64;
        Ok(n)
    }
}

/// Writer that XORs bytes against an 8-byte rolling key as they are written.
struct XorWriter<W> {
    inner: W,
    key: [u8; OBFUSCATION_KEY_LEN],
    pos: u64,
}

impl<W: Write> XorWriter<W> {
    fn new(inner: W, key: [u8; OBFUSCATION_KEY_LEN]) -> Self {
        Self { inner, key, pos: 0 }
    }
}

impl<W: Write> Write for XorWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if is_zero_key(&self.key) {
            let n = self.inner.write(buf)?;
            self.pos += n as u64;
            return Ok(n);
        }
        // Apply XOR into a small stack buffer and forward; we deliberately
        // avoid mutating the caller's slice.
        let mut scratch = [0u8; 4096];
        let chunk = buf.len().min(scratch.len());
        for i in 0..chunk {
            let key_index = ((self.pos + i as u64) % OBFUSCATION_KEY_LEN as u64) as usize;
            scratch[i] = buf[i] ^ self.key[key_index];
        }
        let n = self.inner.write(&scratch[..chunk])?;
        self.pos += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn is_zero_key(key: &[u8; OBFUSCATION_KEY_LEN]) -> bool {
    key.iter().all(|b| *b == 0)
}

// ---------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------

/// Result of a successful load, returned for diagnostics and for the
/// `loadmempool` RPC.
#[derive(Debug, Default, Clone)]
pub struct LoadStats {
    /// Format version of the file we read.
    pub version: u64,
    /// Number of transactions recorded in the file.
    pub total: u64,
    /// Number of transactions successfully reinserted into the mempool.
    pub accepted: u64,
    /// Number of transactions skipped because they failed reinsertion
    /// (missing UTXOs, conflict with another loaded tx, etc.).
    pub failed: u64,
    /// Number of `mapDeltas` entries read.
    pub deltas: u64,
    /// Number of unbroadcast txids read.
    pub unbroadcast: u64,
}

/// Result of a successful dump.
#[derive(Debug, Default, Clone)]
pub struct DumpStats {
    /// Number of transactions written to disk.
    pub txs: u64,
    /// On-disk size in bytes (including version + key headers).
    pub bytes: u64,
}

/// Dump the current mempool contents to `path` in Core-format v2 (XOR
/// obfuscated). The write goes through `path.new` and is renamed
/// atomically over `path` on success.
pub fn dump_mempool(mempool: &Mempool, path: &Path) -> io::Result<DumpStats> {
    let mut key = [0u8; OBFUSCATION_KEY_LEN];
    fill_random(&mut key);
    // A non-zero key is required so the XOR path actually fires; the
    // probability of randomly drawing all-zero is 2^-64 but we paper
    // over it deterministically.
    if is_zero_key(&key) {
        key[0] = 1;
    }
    dump_mempool_with_key(mempool, path, key)
}

/// Variant of [`dump_mempool`] that lets the caller fix the obfuscation
/// key. Public so that round-trip tests can assert byte-for-byte
/// equality against a hand-built fixture.
pub fn dump_mempool_with_key(
    mempool: &Mempool,
    path: &Path,
    key: [u8; OBFUSCATION_KEY_LEN],
) -> io::Result<DumpStats> {
    let tmp_path = path.with_extension("dat.new");
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp_path)?;
    let mut writer = BufWriter::new(file);

    // Header: version + (for v2) the obfuscation key wrapped in a
    // CompactSize-prefixed byte vector.
    let version: u64 = MEMPOOL_DUMP_VERSION;
    writer.write_all(&version.to_le_bytes())?;
    write_compact_size(&mut writer, OBFUSCATION_KEY_LEN as u64)?;
    writer.write_all(&key)?;

    // Switch the underlying writer into XOR-obfuscation mode for the
    // payload. Everything past this point is bytewise XORed against
    // `key` in Core's rotation scheme.
    let stats = {
        let mut xor = XorWriter::new(writer, key);
        let mut stats = DumpStats::default();

        // Snapshot the entries so the iteration order is stable across
        // the count and the body, even if the caller is sharing the
        // mempool with other threads via interior mutability later.
        let entries: Vec<_> = mempool.entries().collect();

        let count = entries.len() as u64;
        xor.write_all(&count.to_le_bytes())?;

        for entry in &entries {
            entry.tx.encode(&mut xor)?;
            xor.write_all(&entry.time_seconds.to_le_bytes())?;
            xor.write_all(&entry.fee_delta.to_le_bytes())?;
            stats.txs += 1;
        }

        // mapDeltas: rustoshi does not implement prioritisetransaction
        // yet, so this is always empty. We still write the
        // CompactSize(0) so the format is well-formed.
        write_compact_size(&mut xor, 0)?;

        // Unbroadcast set: rustoshi does not track an explicit
        // unbroadcast set yet, so this is always empty too.
        write_compact_size(&mut xor, 0)?;

        xor.flush()?;
        stats
    };

    let metadata_size = std::fs::metadata(&tmp_path)?.len();

    // fsync on the temp file before the rename so a crash mid-rename
    // never leaves a torn `mempool.dat`.
    let file = OpenOptions::new().read(true).open(&tmp_path)?;
    file.sync_all()?;
    drop(file);

    std::fs::rename(&tmp_path, path)?;

    Ok(DumpStats {
        txs: stats.txs,
        bytes: metadata_size,
    })
}

/// Load mempool entries from `path` and reinsert them via the standard
/// validation path. Each transaction's `time_seconds` and `fee_delta`
/// are restored from the file.
///
/// `utxo_lookup` is consulted by the standard `add_transaction` path to
/// resolve confirmed inputs. Mempool-internal inputs are resolved
/// against the mempool itself, exactly like a normal `acceptToMemoryPool`.
///
/// The function never panics on malformed files: on any I/O or decode
/// error it returns `Err(io::Error)` and leaves the mempool in
/// whatever state it had reached.
pub fn load_mempool<F>(
    mempool: &mut Mempool,
    path: &Path,
    utxo_lookup: &F,
) -> io::Result<LoadStats>
where
    F: Fn(&OutPoint) -> Option<CoinEntry>,
{
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    // ---- header ----
    let mut version_buf = [0u8; 8];
    reader.read_exact(&mut version_buf)?;
    let version = u64::from_le_bytes(version_buf);

    let key = match version {
        MEMPOOL_DUMP_VERSION_NO_XOR_KEY => [0u8; OBFUSCATION_KEY_LEN],
        MEMPOOL_DUMP_VERSION => {
            let key_len = read_compact_size(&mut reader)?;
            if key_len != OBFUSCATION_KEY_LEN as u64 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("obfuscation key must be {} bytes", OBFUSCATION_KEY_LEN),
                ));
            }
            let mut key = [0u8; OBFUSCATION_KEY_LEN];
            reader.read_exact(&mut key)?;
            key
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported mempool.dat version: {}", other),
            ));
        }
    };

    let mut stats = LoadStats {
        version,
        ..Default::default()
    };

    // ---- payload (XOR-obfuscated when version == 2) ----
    let mut xor = XorReader::new(reader, key);

    let mut count_buf = [0u8; 8];
    xor.read_exact(&mut count_buf)?;
    let count = u64::from_le_bytes(count_buf);
    if count > MAX_DUMP_ENTRIES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("mempool.dat tx count {} exceeds sanity cap", count),
        ));
    }
    stats.total = count;

    for _ in 0..count {
        let tx = Transaction::decode(&mut xor)?;
        let mut time_buf = [0u8; 8];
        xor.read_exact(&mut time_buf)?;
        let time_seconds = i64::from_le_bytes(time_buf);
        let mut fee_delta_buf = [0u8; 8];
        xor.read_exact(&mut fee_delta_buf)?;
        let fee_delta = i64::from_le_bytes(fee_delta_buf);

        let txid = tx.txid();
        match mempool.add_transaction(tx, utxo_lookup) {
            Ok(_) => {
                mempool.set_entry_time_seconds(&txid, time_seconds);
                if fee_delta != 0 {
                    mempool.set_entry_fee_delta(&txid, fee_delta);
                }
                stats.accepted += 1;
            }
            Err(MempoolError::AlreadyExists) => {
                // Idempotent: still patch the metadata so that a load
                // followed by a load is a no-op.
                mempool.set_entry_time_seconds(&txid, time_seconds);
                if fee_delta != 0 {
                    mempool.set_entry_fee_delta(&txid, fee_delta);
                }
                stats.accepted += 1;
            }
            Err(_) => {
                stats.failed += 1;
            }
        }
    }

    // ---- mapDeltas ----
    let n_deltas = read_compact_size(&mut xor)?;
    if n_deltas > MAX_DUMP_ENTRIES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("mempool.dat mapDeltas count {} exceeds sanity cap", n_deltas),
        ));
    }
    stats.deltas = n_deltas;
    for _ in 0..n_deltas {
        let mut txid_bytes = [0u8; 32];
        xor.read_exact(&mut txid_bytes)?;
        let mut delta_buf = [0u8; 8];
        xor.read_exact(&mut delta_buf)?;
        let delta = i64::from_le_bytes(delta_buf);
        let txid = Hash256::from_bytes(txid_bytes);
        // Apply only if the tx is in the mempool (Core does the same).
        mempool.set_entry_fee_delta(&txid, delta);
    }

    // ---- unbroadcast txids ----
    let n_unbroadcast = read_compact_size(&mut xor)?;
    if n_unbroadcast > MAX_DUMP_ENTRIES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "mempool.dat unbroadcast count {} exceeds sanity cap",
                n_unbroadcast
            ),
        ));
    }
    stats.unbroadcast = n_unbroadcast;
    for _ in 0..n_unbroadcast {
        let mut txid_bytes = [0u8; 32];
        xor.read_exact(&mut txid_bytes)?;
        // We do not yet maintain an explicit unbroadcast set; the
        // txid is read so the file pointer advances correctly. A
        // future implementation can call `mempool.add_unbroadcast(...)`
        // here.
        let _ = txid_bytes;
    }

    Ok(stats)
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

fn fill_random(buf: &mut [u8; OBFUSCATION_KEY_LEN]) {
    use rand::RngCore;
    rand::thread_rng().fill_bytes(buf);
}

/// Compute the on-disk size of a header (version + key vector) for a
/// given version. Useful for tests and for callers that want to
/// pre-flight space.
pub fn header_size(version: u64) -> usize {
    match version {
        MEMPOOL_DUMP_VERSION_NO_XOR_KEY => 8,
        _ => 8 + compact_size_len(OBFUSCATION_KEY_LEN as u64) + OBFUSCATION_KEY_LEN,
    }
}

// Suppress unused-import warning when the file is built without the
// loader being exercised — `Seek/SeekFrom` are referenced indirectly
// by `BufReader<File>` in tests.
#[allow(dead_code)]
fn _assert_io_traits() {
    fn _take<R: Read + Seek>(_: R) {}
    fn _from(_: SeekFrom) {}
    let _ = HashMap::<Hash256, ()>::new();
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mempool::{Mempool, MempoolConfig};
    use crate::validation::CoinEntry;
    use rustoshi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
    use std::collections::HashMap;

    fn make_dummy_tx(prev_txid: Hash256, prev_vout: u32, value: u64) -> Transaction {
        Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: prev_txid,
                    vout: prev_vout,
                },
                script_sig: vec![],
                sequence: 0xffff_ffff,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value,
                script_pubkey: vec![0x6a], // OP_RETURN, simplest standard-ish
            }],
            lock_time: 0,
        }
    }

    fn build_utxo(prev_txid: Hash256, prev_vout: u32, value: u64) -> HashMap<OutPoint, CoinEntry> {
        let mut m = HashMap::new();
        m.insert(
            OutPoint {
                txid: prev_txid,
                vout: prev_vout,
            },
            CoinEntry {
                height: 1,
                is_coinbase: false,
                value,
                script_pubkey: vec![0x76, 0xa9, 0x14, 0x00, 0x88, 0xac],
            },
        );
        m
    }

    fn lookup_for<'a>(
        utxos: &'a HashMap<OutPoint, CoinEntry>,
    ) -> impl Fn(&OutPoint) -> Option<CoinEntry> + 'a {
        move |op: &OutPoint| utxos.get(op).cloned()
    }

    #[test]
    fn xor_reader_writer_roundtrip() {
        // Hand-build the obfuscated stream manually and verify the
        // wrappers cancel out.
        let key = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let plain: Vec<u8> = (0..1024).map(|i| (i as u8).wrapping_mul(7)).collect();

        let mut buf = Vec::new();
        {
            let mut w = XorWriter::new(&mut buf, key);
            // Write in oddly-sized chunks to exercise the rolling offset.
            w.write_all(&plain[..3]).unwrap();
            w.write_all(&plain[3..17]).unwrap();
            w.write_all(&plain[17..512]).unwrap();
            w.write_all(&plain[512..]).unwrap();
            w.flush().unwrap();
        }

        // Manual XOR check: byte j XORed with key[j%8].
        for (i, byte) in buf.iter().enumerate() {
            assert_eq!(*byte, plain[i] ^ key[i % 8]);
        }

        let mut out = vec![0u8; plain.len()];
        let mut r = XorReader::new(&buf[..], key);
        r.read_exact(&mut out).unwrap();
        assert_eq!(out, plain);
    }

    #[test]
    fn xor_zero_key_is_identity() {
        let key = [0u8; 8];
        let plain = b"hello world".to_vec();

        let mut buf = Vec::new();
        {
            let mut w = XorWriter::new(&mut buf, key);
            w.write_all(&plain).unwrap();
        }
        assert_eq!(buf, plain);

        let mut out = vec![0u8; plain.len()];
        let mut r = XorReader::new(&buf[..], key);
        r.read_exact(&mut out).unwrap();
        assert_eq!(out, plain);
    }

    #[test]
    fn empty_mempool_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mempool.dat");

        let mut empty = Mempool::new(MempoolConfig::default());
        let stats = dump_mempool(&empty, &path).unwrap();
        assert_eq!(stats.txs, 0);

        // Verify header bytes: 8-byte version, then compactsize(8)+key.
        let bytes = std::fs::read(&path).unwrap();
        assert!(bytes.len() >= 8 + 1 + 8);
        let version = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        assert_eq!(version, MEMPOOL_DUMP_VERSION);
        assert_eq!(bytes[8], 0x08); // CompactSize(8)

        let utxos: HashMap<OutPoint, CoinEntry> = HashMap::new();
        let load = load_mempool(&mut empty, &path, &lookup_for(&utxos)).unwrap();
        assert_eq!(load.total, 0);
        assert_eq!(load.deltas, 0);
        assert_eq!(load.unbroadcast, 0);
        assert_eq!(load.version, MEMPOOL_DUMP_VERSION);
    }

    #[test]
    fn single_tx_roundtrip_preserves_time_and_fee_delta() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mempool.dat");

        // Deposit UTXO that the test tx will spend.
        let prev = Hash256::from_bytes([7u8; 32]);
        let utxos = build_utxo(prev, 0, 100_000);

        let tx = make_dummy_tx(prev, 0, 90_000);
        let txid = tx.txid();

        let mut src = Mempool::new(MempoolConfig::default());
        src.add_transaction(tx.clone(), &lookup_for(&utxos)).unwrap();

        // Force a known nTime / fee delta.
        src.set_entry_time_seconds(&txid, 1_700_000_000);
        src.set_entry_fee_delta(&txid, 12_345);

        let dump = dump_mempool(&src, &path).unwrap();
        assert_eq!(dump.txs, 1);

        let mut dst = Mempool::new(MempoolConfig::default());
        let load = load_mempool(&mut dst, &path, &lookup_for(&utxos)).unwrap();

        assert_eq!(load.total, 1);
        assert_eq!(load.accepted, 1);
        assert_eq!(load.failed, 0);

        let entry = dst.get(&txid).expect("tx restored to mempool");
        assert_eq!(entry.time_seconds, 1_700_000_000);
        assert_eq!(entry.fee_delta, 12_345);
    }

    #[test]
    fn version_1_no_xor_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mempool.dat");

        // Hand-build a v1 file: empty mempool.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MEMPOOL_DUMP_VERSION_NO_XOR_KEY.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes()); // count
        write_compact_size(&mut bytes, 0).unwrap(); // mapDeltas
        write_compact_size(&mut bytes, 0).unwrap(); // unbroadcast
        std::fs::write(&path, &bytes).unwrap();

        let mut mempool = Mempool::new(MempoolConfig::default());
        let utxos: HashMap<OutPoint, CoinEntry> = HashMap::new();
        let stats = load_mempool(&mut mempool, &path, &lookup_for(&utxos)).unwrap();
        assert_eq!(stats.version, MEMPOOL_DUMP_VERSION_NO_XOR_KEY);
        assert_eq!(stats.total, 0);
    }

    #[test]
    fn unknown_version_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mempool.dat");
        let bytes = 99u64.to_le_bytes().to_vec();
        std::fs::write(&path, &bytes).unwrap();

        let mut mempool = Mempool::new(MempoolConfig::default());
        let utxos: HashMap<OutPoint, CoinEntry> = HashMap::new();
        let err = load_mempool(&mut mempool, &path, &lookup_for(&utxos)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn fixed_key_dump_is_byte_stable() {
        // Two dumps with the same key must produce identical bytes.
        let dir = tempfile::tempdir().unwrap();
        let path_a = dir.path().join("a.dat");
        let path_b = dir.path().join("b.dat");
        let key = [0xAA; 8];

        let prev = Hash256::from_bytes([3u8; 32]);
        let utxos = build_utxo(prev, 0, 50_000);
        let tx = make_dummy_tx(prev, 0, 40_000);
        let txid = tx.txid();

        let mut src = Mempool::new(MempoolConfig::default());
        src.add_transaction(tx, &lookup_for(&utxos)).unwrap();
        src.set_entry_time_seconds(&txid, 42);
        src.set_entry_fee_delta(&txid, 0);

        dump_mempool_with_key(&src, &path_a, key).unwrap();
        dump_mempool_with_key(&src, &path_b, key).unwrap();

        let a = std::fs::read(&path_a).unwrap();
        let b = std::fs::read(&path_b).unwrap();
        assert_eq!(a, b, "fixed-key dump must be deterministic");

        // First 8 bytes must be the version, next byte must be
        // CompactSize(8), next 8 bytes the key, and then the
        // obfuscated payload.
        let version = u64::from_le_bytes(a[..8].try_into().unwrap());
        assert_eq!(version, MEMPOOL_DUMP_VERSION);
        assert_eq!(a[8], 0x08);
        assert_eq!(&a[9..17], &key);
    }
}
