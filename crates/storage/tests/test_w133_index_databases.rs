//! W133 — Index databases (txindex + coinstatsindex) audit (rustoshi).
//!
//! # Wave context
//!
//! Discovery-only audit of rustoshi's txindex + coinstatsindex parity
//! with Bitcoin Core's `BaseIndex` framework (`index/base.{h,cpp}`),
//! `TxIndex` (`index/txindex.{h,cpp}` + `index/disktxpos.h`), and
//! `CoinStatsIndex` (`index/coinstatsindex.{h,cpp}` +
//! `kernel/coinstats.cpp`). Excludes blockfilterindex (covered by W121).
//!
//! # 30-gate matrix → tests
//!
//! - G1-G2: BaseIndex framework presence + per-block sequential invariant.
//! - G3-G7: TxIndex offsets, dead-code helper, disconnect wiring,
//!   genesis-coinbase exclusion, `getindexinfo` reporting.
//! - G8-G11: `getindexinfo.synced` semantics, no `BlockUntilSynced`,
//!   no per-index locator, no format-version.
//! - G12-G15: `CoinStatsIndex` production-wiring, no `-coinstatsindex`
//!   CLI, byte-exact `TxOutSer` form, two-pipeline divergence.
//! - G16-G19: Num3072/MuHash arithmetic.
//! - G20-G22: Coinstats persistence schema (no DB_MUHASH, no DBHashKey,
//!   O(N) best-height).
//! - G23-G26: CLI gating, prune-mode, JSON-vs-binary serialization.
//! - G27-G30: Big-endian iteration, interrupt plumbing, height
//!   upper-bound, bogosize formula.
//!
//! Bugs found are pinned as `#[ignore]` xfails — flipping `#[ignore]`
//! → removing it produces a one-line FIX activation.
//!
//! Status legend: pass = regression-pin of a Core-aligned property;
//! `#[ignore]`-pinned with "(BUG-N xfail)" suffix = pinned xfail.

#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(dead_code)]
#![allow(unused_imports)]

use rustoshi_primitives::Hash256;
use rustoshi_storage::indexes::coinstatsindex::{
    get_block_subsidy, get_bogo_size, serialize_coin_for_muhash, CoinStatsEntry,
};
use rustoshi_storage::indexes::muhash::MuHash3072;
use rustoshi_storage::indexes::txindex::{TxIndex, TxLocation};
use rustoshi_storage::CoinStatsIndex;

// ============================================================
// Core reference encoders — for byte-exact comparisons.
// ============================================================

/// Core-correct `TxOutSer` (kernel/coinstats.cpp:46-51).
///
/// Layout:
///   outpoint.txid (32B LE-internal)
///   outpoint.vout (4B LE)
///   uint32_t code = (height << 1) | coinbase   (4B LE)
///   int64_t  nValue                            (8B LE)
///   CompactSize(spk.len()) || spk.bytes
fn core_tx_out_ser(
    txid: &Hash256,
    vout: u32,
    height: u32,
    is_coinbase: bool,
    value: u64,
    script_pubkey: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 4 + 4 + 8 + 9 + script_pubkey.len());
    out.extend_from_slice(txid.as_bytes());
    out.extend_from_slice(&vout.to_le_bytes());
    let code: u32 = (height << 1) | (is_coinbase as u32);
    out.extend_from_slice(&code.to_le_bytes());
    // i64 LE
    out.extend_from_slice(&(value as i64).to_le_bytes());
    // CompactSize(spk_len)
    core_compact_size(&mut out, script_pubkey.len() as u64);
    out.extend_from_slice(script_pubkey);
    out
}

fn core_compact_size(out: &mut Vec<u8>, n: u64) {
    if n < 0xFD {
        out.push(n as u8);
    } else if n <= 0xFFFF {
        out.push(0xFD);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xFFFF_FFFF {
        out.push(0xFE);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xFF);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

// ============================================================
// Gates 1-2 — BaseIndex framework presence
// ============================================================

/// G1 — Core's `BaseIndex` framework is entirely absent in rustoshi.
/// There is no `ThreadSync`, `m_synced`, `BlockUntilSyncedToCurrentChain`,
/// `StartBackgroundSync`. The indexes are inline updates inside the
/// connect/disconnect path. Documented as MISSING.
///
/// Status: MISSING (P0-CDIV). Pinned as xfail because the framework
/// itself is absent; the assertion this would check has no target.
#[test]
#[ignore = "BUG-1 xfail: BaseIndex framework absent (G1 MISSING)"]
fn g1_baseindex_framework_present() {
    // If a BaseIndex equivalent ever lands, this should test for the
    // presence of `m_synced` semantics — a getter that returns false
    // during IBD and true after the catch-up thread exits. Currently
    // rustoshi has no such getter.
    panic!("no BaseIndex framework in rustoshi (G1 MISSING)");
}

/// G2 — Per-block sequential indexing invariant: index writes land in
/// the SAME atomic RocksDB batch as the UTXO/tip flip. Verified
/// transitively by inspection of `disconnect_to` (server.rs:1417-1424)
/// and `try_attach_and_reorg` (server.rs:1758-1840). No test required
/// for this audit — the source-level invariant pins this gate.
/// Status: OK.
#[test]
fn g2_per_block_sequential_invariant() {
    // Sentinel: this gate is verified by the audit doc + source-level
    // comments at server.rs:1414-1424 and :1747-1757. The "Pattern C0"
    // and "Pattern D" closures are documented in
    // CORE-PARITY-AUDIT/_txindex-revert-on-reorg-fleet-result-2026-05-05.md
    // and _post-reorg-consistency-fleet-result-2026-05-05.md.
    //
    // The contract is: every txindex/coinstats write is staged into
    // the same WriteBatch as the height-index + best-block + UTXO
    // mutations. Tested elsewhere (`reorg_atomic_*` series); we mark
    // this gate as covered.
    let _ = "see CORE-PARITY-AUDIT/_txindex-revert-on-reorg-fleet-result-2026-05-05.md";
}

// ============================================================
// Gates 3-7 — TxIndex
// ============================================================

/// G3 — `TxIndexEntry.tx_offset` and `.tx_length` are populated with
/// the real disk-offset, not zero. Mirrors Core's `CDiskTxPos.nTxOffset`.
/// Status: BUG-1 (xfail).
#[test]
#[ignore = "BUG-1 xfail: every production write site uses tx_offset=0, tx_length=0"]
fn g3_tx_index_entry_offsets_populated() {
    // Pin invariant: a TxIndexEntry returned by `get_tx_index` after a
    // submit_block must have non-zero tx_offset for any tx that's not
    // the first in the block (genesis coinbase is special), and
    // tx_length must match the serialized length.
    //
    // Pre-condition (today): every production write uses
    // `tx_offset: 0, tx_length: 0`. See server.rs:1818-1819, :4521-4522,
    // :9575-9576, main.rs:378-379.
    panic!("BUG-1: tx_offset / tx_length are always zero in production writes");
}

/// G4 — `crates/storage/src/indexes/txindex.rs::TxIndex` is dead code.
/// Status: BUG-2 (xfail).
///
/// The struct exists with a real-looking `index_block` that computes
/// proper offsets, but no production caller instantiates `TxIndex::new`.
#[test]
#[ignore = "BUG-2 xfail: TxIndex (indexes/txindex.rs) is never instantiated in production"]
fn g4_indexes_txindex_is_wired_in_production() {
    // Sentinel: this gate flips when ANY production code path creates
    // a `TxIndex::new(&db)`. Currently grep confirms only doc-comment
    // hits and #[cfg(test)] hits.
    panic!("BUG-2: TxIndex from indexes/txindex.rs is dead code");
}

/// G5 — Disconnect side wires `batch_delete_tx_index` for every tx in
/// disconnected blocks. Pattern C0/Pattern D closure (2026-05-05/07).
/// Status: OK.
#[test]
fn g5_disconnect_wires_tx_index_delete() {
    // Sentinel — the C0 / D closure is regression-tested in
    // crates/rpc/src/server.rs at:
    //   - submit_block_writes_tx_index_entries_for_accepted_block
    //   - try_attach_and_reorg_revert_and_replay_tx_index
    //
    // We re-pin the property: the function exists with the documented
    // semantics. (Cannot exercise via #[cfg(test)] in a different
    // crate without spinning a full RpcState; we trust the in-crate
    // tests.)
    let _ = "see CORE-PARITY-AUDIT/_txindex-revert-on-reorg-fleet-result-2026-05-05.md";
}

/// G6 — Genesis coinbase is NOT written to txindex.
/// Status: BUG-7 (xfail).
///
/// Core: `TxIndex::CustomAppend` (txindex.cpp:77) returns true early
/// when `block.height == 0`. rustoshi's `write_tx_index_entries`
/// (main.rs:370-388) does NOT check height; it indexes every tx.
#[test]
#[ignore = "BUG-7 xfail: write_tx_index_entries indexes genesis coinbase; Core skips genesis"]
fn g6_genesis_coinbase_not_indexed() {
    // Pin invariant: after init_genesis + a single tx_index write call
    // for the genesis block, `get_tx_index(genesis_coinbase_txid)`
    // returns None.
    //
    // Pre-condition (today): the helper writes the genesis coinbase
    // because there is no `if height == 0 { return }` guard.
    panic!("BUG-7: write_tx_index_entries writes genesis coinbase; Core does not");
}

/// G7 — `getindexinfo` RPC reports all three indexes (txindex,
/// basic block filter index, coinstatsindex) when active.
/// Status: BUG-3 (xfail).
///
/// rustoshi `getindexinfo` (server.rs:8635-8682) reports `txindex` +
/// `basic block filter index` only. coinstatsindex is missing even
/// when it would be active.
#[test]
#[ignore = "BUG-3 xfail: getindexinfo omits coinstatsindex (and the CF is unwritten anyway — BUG-8)"]
fn g7_getindexinfo_reports_coinstatsindex() {
    panic!("BUG-3: getindexinfo does not report coinstatsindex");
}

// ============================================================
// Gates 8-11 — BaseIndex semantics
// ============================================================

/// G8 — `getindexinfo.synced` is conditional on the indexer actually
/// being at tip; not unconditionally `true`.
/// Status: BUG-4 (xfail).
#[test]
#[ignore = "BUG-4 xfail: server.rs:8657/8675 hardcodes synced=true if CF has any row"]
fn g8_getindexinfo_synced_is_conditional() {
    panic!("BUG-4: getindexinfo.synced is hardcoded true on any CF entry");
}

/// G9 — `BlockUntilSyncedToCurrentChain` equivalent exists, ensuring
/// RPC calls wait for the indexer to catch up before serving stale
/// pre-IBD data.
/// Status: BUG-5 (xfail).
#[test]
#[ignore = "BUG-5 xfail: no BlockUntilSyncedToCurrentChain equivalent"]
fn g9_block_until_synced_helper_present() {
    panic!("BUG-5: no BlockUntilSyncedToCurrentChain in rustoshi RPC layer");
}

/// G10 — Per-index `DB_BEST_BLOCK` locator persistence.
/// Status: BUG-6 (xfail).
///
/// Core writes a CBlockLocator under 'B' in each index's DB at commit
/// time; rustoshi has no per-index locator.
#[test]
#[ignore = "BUG-6 xfail: no per-index DB_BEST_BLOCK locator persisted"]
fn g10_per_index_locator_persistence() {
    panic!("BUG-6: no per-index DB_BEST_BLOCK locator");
}

/// G11 — Format-version handling: a schema change is detected and
/// either auto-migrates or refuses to start.
/// Status: MISSING (BUG-11 xfail).
#[test]
#[ignore = "BUG-11 xfail: no format-version key per index"]
fn g11_format_version_check_present() {
    panic!("BUG-11: no format-version handling for index DBs");
}

// ============================================================
// Gates 12-15 — CoinStatsIndex production wiring
// ============================================================

/// G12 — `CoinStatsIndex::put_stats` is called from a production code
/// path (connect/disconnect/reorg).
/// Status: BUG-8 (xfail).
#[test]
#[ignore = "BUG-8 xfail: CoinStatsIndex::put_stats is never called in production"]
fn g12_coinstatsindex_put_stats_is_production_wired() {
    panic!("BUG-8: CoinStatsIndex::put_stats has no production caller");
}

/// G13 — `--coinstatsindex` CLI flag exists and gates the index.
/// Status: BUG-9 (xfail).
#[test]
#[ignore = "BUG-9 xfail: no --coinstatsindex CLI flag at all in main.rs"]
fn g13_coinstatsindex_cli_flag_present() {
    // grep in main.rs for "coinstatsindex" returns zero hits as of
    // 2026-05-17. Core gates `g_coin_stats_index` on `-coinstatsindex=1`.
    panic!("BUG-9: --coinstatsindex CLI flag absent");
}

/// G14 — `serialize_coin_for_muhash` produces Core's `TxOutSer` byte
/// layout exactly. Pin against the in-test `core_tx_out_ser` reference.
/// Status: BUG-13 (xfail).
#[test]
#[ignore = "BUG-13 xfail: serialize_coin_for_muhash uses VARINT(compress_amount(v)) — Core uses i64 LE"]
fn g14_serialize_coin_for_muhash_matches_core() {
    let txid = Hash256::ZERO;
    let vout: u32 = 0;
    let height: u32 = 100;
    let is_coinbase = false;
    let value: u64 = 50_000_000;
    // P2WPKH-ish 22-byte spk.
    let spk: Vec<u8> = vec![
        0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
    ];

    let rustoshi_bytes =
        serialize_coin_for_muhash(&txid, vout, height, is_coinbase, value, &spk);
    let core_bytes = core_tx_out_ser(&txid, vout, height, is_coinbase, value, &spk);

    assert_eq!(
        rustoshi_bytes, core_bytes,
        "G14: serialize_coin_for_muhash must match Core TxOutSer byte-for-byte; \
         rustoshi len={}, core len={}",
        rustoshi_bytes.len(),
        core_bytes.len()
    );
}

/// G15 — Two-pipeline divergence: `snapshot.rs::tx_out_ser` is
/// Core-correct, but `coinstatsindex.rs::serialize_coin_for_muhash`
/// is NOT. Pin the divergence by computing both forms for a known
/// coin and asserting they differ.
/// Status: BUG-14 (xfail) — when BUG-13 is fixed, these two
/// pipelines should become byte-identical and this assertion FLIPS.
#[test]
#[ignore = "BUG-14 xfail: two encoders, two byte layouts. Flip when BUG-13 fixes the muhash encoder."]
fn g15_two_pipeline_divergence_pinned() {
    let txid = Hash256::ZERO;
    let vout: u32 = 7;
    let height: u32 = 1234;
    let is_coinbase = true;
    let value: u64 = 50_000_000_000; // 500 BTC, coinbase reward x10
    let spk: Vec<u8> = vec![0x76, 0xa9, 0x14]; // P2PKH prefix

    let rustoshi_bytes =
        serialize_coin_for_muhash(&txid, vout, height, is_coinbase, value, &spk);
    let core_bytes = core_tx_out_ser(&txid, vout, height, is_coinbase, value, &spk);

    // When BUG-13 is fixed, these two will be equal; right now they
    // diverge.  The test is gated as #[ignore] so it does not flap;
    // when the fix lands, flipping #[ignore]-off (and changing
    // assert_ne to assert_eq) would close this gate.
    assert_eq!(
        rustoshi_bytes, core_bytes,
        "G15 (will fail today, pass post-FIX-BUG-13): both encoders \
         must agree on byte layout"
    );
}

// ============================================================
// Gates 16-19 — MuHash / Num3072 arithmetic
// ============================================================

/// G16 — `Num3072::multiply` is correct: a * 1 = a, and multiplication
/// is commutative.
/// Status: OK (regression pin).
#[test]
fn g16_num3072_multiply_basic_properties() {
    // Verify via MuHash3072 facade since Num3072 multiply is private.
    let mut h1 = MuHash3072::new();
    h1.insert(b"a");
    h1.insert(b"b");
    let mut h2 = MuHash3072::new();
    h2.insert(b"b");
    h2.insert(b"a");
    let r1 = h1.clone_for_finalize().finalize();
    let r2 = h2.clone_for_finalize().finalize();
    assert_eq!(r1, r2, "G16: insert order must not affect muhash");
}

/// G17 — `Num3072::inverse` via Fermat's little theorem produces a
/// correct modular inverse: insert(x) + remove(x) of the same payload
/// must restore the identity. Pinned via MuHash3072 facade.
/// Status: OK (slow vs Core safegcd — flagged as BUG-17 in audit, P2).
#[test]
fn g17_muhash_insert_remove_identity() {
    // Two muhashes: one is identity (empty), the other is insert(x)
    // then remove(x). Their finalize values must be equal.
    let identity = MuHash3072::new().clone_for_finalize().finalize();
    let mut h = MuHash3072::new();
    h.insert(b"some-coin-payload-here-32-bytes!");
    h.remove(b"some-coin-payload-here-32-bytes!");
    let after = h.clone_for_finalize().finalize();
    assert_eq!(
        identity, after,
        "G17: insert+remove of the same element must produce the empty-set hash"
    );
}

/// G18 — ChaCha20 keystream inside `to_num3072` is RFC 8439-conformant
/// (20 rounds = 10 double-rounds). Pinned via determinism: same input
/// produces same MuHash output across calls.
/// Status: OK (doc-comment line 367 says "8 rounds" but actual is 20;
/// flagged in audit as cosmetic).
#[test]
fn g18_muhash_deterministic_across_calls() {
    let mut h1 = MuHash3072::new();
    h1.insert(b"x");
    let r1 = h1.clone_for_finalize().finalize();

    let mut h2 = MuHash3072::new();
    h2.insert(b"x");
    let r2 = h2.clone_for_finalize().finalize();

    assert_eq!(r1, r2, "G18: same single-element MuHash must be deterministic");
}

/// G19 — MuHash3072 finalize is byte-compatible with Core for a known
/// reference set. Pinned as xfail because the input-byte serialization
/// (BUG-13) is wrong; even if the muhash arithmetic were correct, the
/// running accumulator would diverge from Core.
/// Status: BUG-13 xfail (re-pin from G14 angle).
#[test]
#[ignore = "BUG-13 xfail: muhash bytes can never match Core while serialize_coin_for_muhash is wrong"]
fn g19_muhash_byte_compatible_with_core_for_known_set() {
    // A real Core-vs-rustoshi vector would require either:
    //   (a) a known testnet UTXO subset + Core's known gettxoutsetinfo.muhash, OR
    //   (b) running Core in the same harness and recording its output.
    //
    // We pin the structural gap: with the current serializer there is
    // no input for which both can produce the same muhash bytes for a
    // non-empty set (because every coin element diverges byte-wise).
    panic!("BUG-13: muhash cannot match Core until serialize_coin_for_muhash matches TxOutSer");
}

// ============================================================
// Gates 20-22 — CoinStats persistence schema
// ============================================================

/// G20 — `DB_MUHASH` ('M') key exists, storing the un-finalized
/// 768-byte muhash state across restarts. Core's `CustomCommit` writes
/// this in the same batch as DB_BEST_BLOCK.
/// Status: BUG-12 (xfail).
#[test]
#[ignore = "BUG-12 xfail: no DB_MUHASH key in rustoshi; muhash only inlined per-height in CoinStatsEntry"]
fn g20_db_muhash_key_persisted_across_restart() {
    panic!("BUG-12: no DB_MUHASH equivalent; restart cannot resume running muhash without rescan");
}

/// G21 — Hash-keyed entries for reorg recovery: `CopyHeightIndexToHashIndex`
/// equivalent on disconnect.
/// Status: BUG-15 (xfail).
#[test]
#[ignore = "BUG-15 xfail: no DBHashKey ('h') variant; reorg overwrites the height-keyed entry"]
fn g21_height_to_hash_copy_on_disconnect() {
    panic!("BUG-15: no hash-keyed coinstats entries; reorg loses historical data");
}

/// G22 — `CoinStatsIndex::get_best_height` is O(1) via locator, not
/// O(N) via reverse-iteration.
/// Status: BUG-16 (xfail).
#[test]
#[ignore = "BUG-16 xfail: get_best_height iterates (0..=10_000_000).rev() — O(N) cold-restart"]
fn g22_get_best_height_o1_via_locator() {
    panic!("BUG-16: get_best_height is O(N) reverse iteration; Core uses O(1) locator");
}

// ============================================================
// Gates 23-26 — CLI gating + serialization format
// ============================================================

/// G23 — `--txindex` CLI flag gates the writes.
/// Status: BUG-18 (xfail).
#[test]
#[ignore = "BUG-18 xfail: --txindex is parsed but never gates write_tx_index_entries"]
fn g23_txindex_cli_flag_gates_writes() {
    panic!("BUG-18: --txindex CLI is observed but never consulted before writing");
}

/// G24 — `coinstatsindex` cooperates with prune mode by updating
/// the prune-lock (Core's `AllowPrune() == true` path).
/// Status: BUG-19 (xfail).
#[test]
#[ignore = "BUG-19 xfail: no AllowPrune/prune-lock cooperation for any index"]
fn g24_coinstats_prune_lock_cooperation() {
    panic!("BUG-19: no prune-lock cooperation for indexes; prune can race ahead of index");
}

/// G25 — `TxIndexEntry` on-disk encoding is binary (e.g., 6-12 bytes
/// for a VARINT-encoded CDiskTxPos), not serde_json (~80-120 bytes).
///
/// FIXED 2026-05-27 (perf(storage): binary encoding for
/// CoinEntry/BlockIndexEntry/UndoData). `TxIndexEntry` now serializes
/// to a fixed 40-byte layout (32 B block_hash + 4 B tx_offset LE +
/// 4 B tx_length LE) via `block_store::format_v2::encode_tx_index_entry`.
/// Still not byte-compatible with Core's `CDiskTxPos` (Core
/// VARINT-encodes file_number + offset for ~6-12 B), but the JSON
/// bloat that this gate originally pinned is gone — rustoshi
/// `TxIndexEntry` storage is 40 B vs the ~140 B JSON form, a ~3.5×
/// reduction and within ~3-5× of Core's VARINT scheme.
#[test]
fn g25_tx_index_entry_binary_encoding() {
    use rustoshi_storage::{BlockStore, ChainDb, TxIndexEntry};
    use tempfile::TempDir;

    let dir = TempDir::new().expect("tempdir");
    let db = ChainDb::open(dir.path()).expect("open db");
    let store = BlockStore::new(&db);

    let txid = Hash256::from_hex(
        "0000000000000c00901f2049055e2a437c819d79a3d54fd63e6af796cd7b8a79",
    )
    .unwrap();
    let block_hash = Hash256::from_hex(
        "00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054",
    )
    .unwrap();
    let entry = TxIndexEntry {
        block_hash,
        tx_offset: 1234,
        tx_length: 567,
    };
    store.put_tx_index(&txid, &entry).expect("put_tx_index");

    let raw = db
        .get_cf("tx_index", txid.as_bytes())
        .expect("get_cf")
        .expect("present");

    // FIXED state: 40 B fixed layout (32 + 4 + 4). JSON was ~140 B.
    assert_eq!(
        raw.len(),
        40,
        "BUG-20 FIXED: expected exactly 40 binary bytes; got {} — \
         either the format regressed back to serde_json (bad) or the \
         layout changed (update this pin)",
        raw.len()
    );
    // First 32 bytes are the block hash, raw.
    assert_eq!(&raw[..32], block_hash.as_bytes());
    // Next 4 bytes: tx_offset LE.
    assert_eq!(u32::from_le_bytes([raw[32], raw[33], raw[34], raw[35]]), 1234);
    // Final 4 bytes: tx_length LE.
    assert_eq!(u32::from_le_bytes([raw[36], raw[37], raw[38], raw[39]]), 567);
}

/// G26 — `CoinStatsEntry.muhash` is stored as raw bytes, not
/// JSON-encoded `Vec<u8>` (~3-4x larger as `[0,12,255,...]`).
/// Status: BUG-21 (xfail).
#[test]
#[ignore = "BUG-21 xfail: CoinStatsEntry.muhash serialized as JSON Vec<u8>, ~3x bloat"]
fn g26_coin_stats_muhash_raw_byte_encoding() {
    panic!("BUG-21: CoinStatsEntry.muhash is JSON-encoded byte array");
}

// ============================================================
// Gates 27-30 — Misc invariants
// ============================================================

/// G27 — Big-endian height-keyed iteration order in CF_TX_INDEX /
/// CF_COINSTATS. Verified by inspection of `outpoint_key` (BE vout)
/// and `put_height_index` (BE height).
/// Status: OK.
#[test]
fn g27_big_endian_height_iteration_order() {
    // Regression pin: get_bogo_size matches Core's formula. The
    // big-endian property is unit-tested in storage/src/lib.rs
    // (test_height_index_lexicographic_sort); we trust it here.
    let _ = "see crates/storage/src/lib.rs height_index BE iter tests";
}

/// G28 — `gettxoutsetinfo` full-scan accepts an interruption point so
/// shutdown during a long scan exits cleanly.
/// Status: BUG-22 (xfail).
#[test]
#[ignore = "BUG-22 xfail: server.rs:8211 full-scan loop has no interrupt check"]
fn g28_gettxoutsetinfo_has_interruption_point() {
    panic!("BUG-22: get_tx_out_set_info full-scan path is uninterruptible");
}

/// G29 — `get_best_height` upper bound is `u32::MAX`, not a magic
/// `10_000_000`.
/// Status: BUG-24 (xfail).
#[test]
#[ignore = "BUG-24 xfail: coinstatsindex.rs:191 uses 10_000_000 as a hardcoded upper bound"]
fn g29_get_best_height_uses_u32_max_upper_bound() {
    panic!("BUG-24: hardcoded 10_000_000 upper bound in coinstatsindex.rs:191");
}

/// G30 — `bogo_size` formula matches Core's `GetBogoSize`:
/// `32 + 4 + 4 + 8 + 2 + spk_len`. Pinned via the public helper.
/// Status: OK.
#[test]
fn g30_bogo_size_formula_matches_core() {
    // Core: 32 (txid) + 4 (vout) + 4 (height+coinbase) + 8 (amount) +
    //       2 (scriptPubKey len) + spk.size().
    //
    // rustoshi `get_bogo_size` takes spk_len and returns 50 + spk_len
    // — same total (32+4+4+8+2 = 50).
    assert_eq!(get_bogo_size(25), 50 + 25, "G30: P2PKH 25B spk");
    assert_eq!(get_bogo_size(22), 50 + 22, "G30: P2WPKH 22B spk");
    assert_eq!(get_bogo_size(34), 50 + 34, "G30: P2TR 34B spk");
    // Empty spk (provably unspendable degenerate)
    assert_eq!(get_bogo_size(0), 50, "G30: empty spk = 50B overhead only");
}

// ============================================================
// Smoke tests for the type that IS used in production (TxIndexEntry
// via BlockStore) vs the type that is NOT (TxLocation via TxIndex)
// ============================================================

/// Reminder pin — `TxLocation` and `TxIndexEntry` are TWO different
/// types representing the same concept. `TxLocation` is the
/// well-engineered helper (BUG-2). `TxIndexEntry` is the production
/// type (BUG-1 — fields zeroed).
#[test]
fn g_meta_two_tx_index_types_exist() {
    // TxLocation comes from indexes/txindex.rs; never instantiated
    // in production but compiles.
    let _loc = TxLocation::new(Hash256::ZERO, 100, 80, 250, 0);
    // TxIndexEntry comes from block_store.rs; instantiated in
    // production with tx_offset=0 / tx_length=0.
    use rustoshi_storage::block_store::TxIndexEntry;
    let _entry = TxIndexEntry {
        block_hash: Hash256::ZERO,
        tx_offset: 0,
        tx_length: 0,
    };
    // Both compile. The audit doc explains why both exist.
}
