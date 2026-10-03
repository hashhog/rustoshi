//! Give a COPY of an assumeutxo-booted rustoshi chainstate the shape of the
//! live mainnet store mid-backfill, for boot-time measurement of
//! `HistoricalBackfill::detect` (2026-10-01: 20+ min before P2P).
//!
//! Live shape (OBSERVED 2026-10-02 via RPC): the genesis-side header hole is
//! closed (height rows 1..floor-1 present) and bodies are stored from height
//! 1 up to somewhere between 200,000 and 250,000; the backfill-floor marker
//! is persisted; there are no progress markers (they did not exist).
//!
//! This writes, for every height 1..floor-1, a height-index row and a
//! block-index entry under a synthetic hash, and for heights 1..=BODY_TOP a
//! body of mainnet-like size (incompressible bytes; detect only checks
//! presence). It never touches heights >= floor, the tip, or the UTXO set.
//!
//! Usage: synth_backfill_store <chainstate dir> [BODY_TOP=225000] [START=1]
//! NEVER point this at a live datadir.

use rustoshi_primitives::Hash256;
use rustoshi_storage::block_store::{BlockIndexEntry, BlockStatus, BlockStore};
use rustoshi_storage::{ChainDb, CF_BLOCKS};
use sha2::{Digest, Sha256};

fn synth_hash(h: u32) -> Hash256 {
    let mut s = Sha256::new();
    s.update(b"rustoshi-synth-backfill");
    s.update(h.to_le_bytes());
    Hash256(s.finalize().into())
}

/// Rough mainnet average block size by height.
fn body_size(h: u32) -> usize {
    match h {
        0..=99_999 => 250,
        100_000..=129_999 => 1_000,
        130_000..=169_999 => 10_000,
        170_000..=199_999 => 100_000,
        _ => 250_000,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = args.get(1).expect("usage: synth_backfill_store <chainstate dir> [BODY_TOP]");
    assert!(
        !path.contains("hashhog-mainnet"),
        "refusing to write into a live mainnet datadir"
    );
    let body_top: u32 = args.get(2).map(|s| s.parse().unwrap()).unwrap_or(225_000);
    // Resume point: heights below it are assumed already written by an
    // earlier (interrupted) run.
    let start: u32 = args.get(3).map(|s| s.parse().unwrap()).unwrap_or(1).max(1);

    let db = ChainDb::open(std::path::Path::new(path)).expect("open");
    let store = BlockStore::new(&db);
    let tip = store.get_best_height().unwrap().expect("best height");
    let floor = match store.historical_backfill_floor().unwrap() {
        Some(f) => f,
        None => {
            let f = store
                .snapshot_index_floor(tip)
                .unwrap()
                .expect("store has no snapshot hole");
            store.set_historical_backfill_floor(f).unwrap();
            f
        }
    };
    eprintln!("tip {tip}, floor {floor}, bodies 1..={body_top}");

    let mut rng: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut buf: Vec<u8> = Vec::new();
    let mut body_bytes: u64 = 0;
    for h in start..floor {
        let hash = synth_hash(h);
        let has_body = h <= body_top;
        if has_body {
            let n = body_size(h);
            buf.resize(n, 0);
            for chunk in buf.chunks_mut(8) {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                let b = rng.to_le_bytes();
                chunk.copy_from_slice(&b[..chunk.len()]);
            }
            db.put_cf(CF_BLOCKS, hash.as_bytes(), &buf).unwrap();
            body_bytes += n as u64;
        }
        let mut status = BlockStatus::new();
        status.set(BlockStatus::VALID_HEADER);
        status.set(BlockStatus::VALID_TREE);
        if has_body {
            status.set(BlockStatus::HAVE_DATA);
        }
        store
            .put_block_index(
                &hash,
                &BlockIndexEntry {
                    height: h,
                    status,
                    n_tx: 0,
                    timestamp: 1_231_006_505 + h * 600,
                    bits: 0x1d00ffff,
                    nonce: h,
                    version: 1,
                    prev_hash: if h == 1 { Hash256::ZERO } else { synth_hash(h - 1) },
                    chain_work: [0u8; 32],
                },
            )
            .unwrap();
        store.put_height_index(h, &hash).unwrap();
        if h % 50_000 == 0 {
            eprintln!("  height {h}, {:.2} GiB of bodies", body_bytes as f64 / (1u64 << 30) as f64);
        }
    }
    eprintln!(
        "done: {} height rows, {:.2} GiB of bodies; markers: header_tip={:?} next_body={:?}",
        floor - 1,
        body_bytes as f64 / (1u64 << 30) as f64,
        store.historical_backfill_header_tip().unwrap(),
        store.historical_backfill_next_body().unwrap()
    );
}
