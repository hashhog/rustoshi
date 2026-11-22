//! cffix-rustoshi-snapshot-script-skip-alloc.
//!
//! Core's `ScriptCompression::Unser` (bitcoin-core/src/compressor.h) handles a
//! generic script whose size exceeds `MAX_SCRIPT_SIZE` by pushing `OP_RETURN`
//! and calling `s.ignore(nSize)`: the over-long bytes are discarded without
//! any allocation, and a short stream throws. The size is an unbounded VARINT
//! read from the (still unauthenticated) snapshot, so the skip must not size
//! a buffer from it — the coin stream is read before the `hash_serialized`
//! gate in both `loadtxoutset` and `--load-snapshot`.

#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use rustoshi_consensus::NetworkMagic;
use rustoshi_primitives::Hash256;
use rustoshi_storage::snapshot::{SnapshotError, SnapshotMetadata, SnapshotReader};
use std::io::Cursor;
use std::panic::{catch_unwind, AssertUnwindSafe};

const N_SPECIAL_SCRIPTS: u64 = 6;

fn magic() -> NetworkMagic {
    NetworkMagic([0xfa, 0xbf, 0xb5, 0xda])
}

/// Bitcoin's VARINT (serialize.h `WriteVarInt`, `VarIntMode::DEFAULT`).
fn write_varint(out: &mut Vec<u8>, mut n: u64) {
    let mut tmp = [0u8; 10];
    let mut len = 0usize;
    loop {
        tmp[len] = ((n & 0x7f) as u8) | if len > 0 { 0x80 } else { 0x00 };
        if n <= 0x7f {
            break;
        }
        n = (n >> 7) - 1;
        len += 1;
    }
    for i in (0..=len).rev() {
        out.push(tmp[i]);
    }
}

/// Header + one txid group, then one coin record per `n_size`, each coin's
/// script being `n_size` followed by `script_bytes[i]` raw bytes.
fn snapshot_with_scripts(coins: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut buf = Vec::new();
    SnapshotMetadata::new(Hash256([7u8; 32]), coins.len() as u64, magic())
        .serialize(&mut buf)
        .unwrap();
    buf.extend_from_slice(&[0x11u8; 32]); // txid
    buf.push(coins.len() as u8); // CompactSize coins-per-txid (< 0xfd)
    for (vout, (n_size, bytes)) in coins.iter().enumerate() {
        buf.push(vout as u8); // CompactSize vout
        write_varint(&mut buf, 2); // code: height 1, not coinbase
        write_varint(&mut buf, 0); // CompressAmount(0)
        write_varint(&mut buf, *n_size);
        buf.extend_from_slice(bytes);
    }
    buf
}

fn read_first_coin(bytes: Vec<u8>) -> std::thread::Result<Result<bool, SnapshotError>> {
    catch_unwind(AssertUnwindSafe(move || {
        let mut reader = SnapshotReader::open(Cursor::new(bytes), &magic())?;
        reader.read_coin().map(|c| c.is_some())
    }))
}

/// The finding: a script-size VARINT of `6 + 2^63 + 1` with no trailing bytes.
/// Master does `vec![0u8; 2^63 + 1]`, which panics with "capacity overflow"
/// (or, for sizes below isize::MAX, aborts the process on allocation failure).
/// Core ignores the bytes and fails on the short read.
#[test]
fn oversized_script_skip_does_not_allocate() {
    let n_size = N_SPECIAL_SCRIPTS + (1u64 << 63) + 1;
    let bytes = snapshot_with_scripts(&[(n_size, Vec::new())]);
    let outcome = read_first_coin(bytes);
    let result = outcome.expect("read_coin panicked on an oversized script size");
    assert!(
        result.is_err(),
        "a script size past the end of the stream must be a clean error, got {result:?}"
    );
}

/// The same skip with a size that is large but well inside isize — the
/// allocation-abort shape on master. Must error on the short read, not
/// allocate ~1 TiB.
#[test]
fn oversized_script_skip_short_read_is_error() {
    let n_size = N_SPECIAL_SCRIPTS + (1u64 << 40);
    let bytes = snapshot_with_scripts(&[(n_size, vec![0u8; 100])]);
    let result = read_first_coin(bytes).expect("read_coin panicked");
    assert!(result.is_err(), "short over-long script must error, got {result:?}");
}

/// Control: an over-long script whose bytes ARE present is replaced by the
/// OP_RETURN sentinel (Core `script << OP_RETURN`) and exactly `raw_size`
/// bytes are consumed, so the next coin decodes at the right offset.
#[test]
fn oversized_script_skip_consumes_exactly_raw_size() {
    let long = 10_001usize; // MAX_SCRIPT_SIZE + 1
    let good = vec![0x51u8, 0x52, 0x93]; // OP_1 OP_2 OP_ADD
    let bytes = snapshot_with_scripts(&[
        (N_SPECIAL_SCRIPTS + long as u64, vec![0xabu8; long]),
        (N_SPECIAL_SCRIPTS + good.len() as u64, good.clone()),
    ]);
    let mut reader = SnapshotReader::open(Cursor::new(bytes), &magic()).unwrap();
    let (op0, c0) = reader.read_coin().unwrap().unwrap();
    assert_eq!(op0.vout, 0);
    assert_eq!(c0.tx_out.script_pubkey, vec![0x6a], "over-long script → OP_RETURN");
    let (op1, c1) = reader.read_coin().unwrap().unwrap();
    assert_eq!(op1.vout, 1);
    assert_eq!(c1.tx_out.script_pubkey, good, "next coin must decode after the skip");
    assert!(reader.read_coin().unwrap().is_none());
}

/// Control: exactly MAX_SCRIPT_SIZE stays a real script (boundary is `>`).
#[test]
fn max_size_script_is_kept() {
    let max = 10_000usize;
    let bytes = snapshot_with_scripts(&[(N_SPECIAL_SCRIPTS + max as u64, vec![0x61u8; max])]);
    let mut reader = SnapshotReader::open(Cursor::new(bytes), &magic()).unwrap();
    let (_, c) = reader.read_coin().unwrap().unwrap();
    assert_eq!(c.tx_out.script_pubkey.len(), max);
}
