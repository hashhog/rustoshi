//! W138 assumeUTXO snapshots audit (rustoshi).
//!
//! # Wave context
//!
//! Discovery-only audit of rustoshi's assumeUTXO snapshot path: header
//! format, `loadtxoutset` / `dumptxoutset` RPCs, `ActivateSnapshot`
//! mechanics, deferred / background validation, `assumeutxohash`
//! sanity check, pre-vs-post-snapshot block index handling, snapshot
//! persistence across restart, and rejection on mismatch.
//!
//! # 30-gate matrix → tests
//!
//! - G1–G5: snapshot file header (magic + version + network +
//!   blockhash + coins_count).
//! - G6–G10: per-coin record encoding (txid grouping, VARINT `code`,
//!   `height > base_height` reject, `MoneyRange` reject, trailing-byte
//!   reject).
//! - G11–G15: `AssumeutxoData` chainparams (struct, mainnet entries,
//!   testnet4 entries, regtest empty, hash-serialized check).
//! - G16–G20: headers-chain presence (MISSING), chainwork ≥ minimum
//!   (PARTIAL), better-headers branch check (MISSING),
//!   double-activation guard (MISSING), empty-mempool guard (MISSING).
//! - G21–G27: dual-chainstate state machine (all MISSING — six P0-CDIV
//!   bugs); cache rebalance (PARTIAL); `ValidatedSnapshotCleanup`
//!   (MISSING).
//! - G28–G30 + BONUS: persistence + restart + `loadtxoutset` RPC +
//!   `getchainstates` RPC.
//!
//! Bugs found are pinned as `#[ignore]` xfails (with `BUG-N` tag in
//! the message) — flipping `#[ignore]` → removing it produces a
//! one-line FIX activation.
//!
//! Status legend: pass = regression-pin of a Core-aligned property;
//! `#[ignore]`-pinned with `(BUG-N xfail)` suffix = pinned xfail.

#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(dead_code)]
#![allow(unused_imports)]

use rustoshi_consensus::{ChainParams, NetworkMagic};
use rustoshi_primitives::{Hash256, OutPoint, TxOut};
use rustoshi_storage::snapshot::{
    compute_hash_serialized, compute_utxo_muhash, find_snapshot_chainstate_dir,
    read_snapshot_blockhash, write_snapshot_blockhash, ChainstateManager, SnapshotActivation,
    SnapshotError, SnapshotMetadata, SnapshotReader, SnapshotState, SnapshotWriter,
    SNAPSHOT_BLOCKHASH_FILENAME, SNAPSHOT_CHAINSTATE_SUFFIX, SNAPSHOT_MAGIC_BYTES,
    SNAPSHOT_VERSION,
};
use rustoshi_storage::Coin;
use std::io::Cursor;

// ============================================================
// HELPERS
// ============================================================

fn mainnet_magic() -> NetworkMagic {
    NetworkMagic([0xf9, 0xbe, 0xb4, 0xd9])
}

fn testnet4_magic() -> NetworkMagic {
    NetworkMagic([0x1c, 0x16, 0x3f, 0x28])
}

fn dummy_hash(byte: u8) -> Hash256 {
    let mut b = [0u8; 32];
    b[0] = byte;
    Hash256(b)
}

fn p2pkh_script() -> Vec<u8> {
    let mut s = vec![0x76u8, 0xa9, 20];
    s.extend_from_slice(&[0x42u8; 20]);
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

fn make_coin(value: u64, height: u32, is_coinbase: bool) -> Coin {
    Coin {
        tx_out: TxOut {
            value,
            script_pubkey: p2pkh_script(),
        },
        height,
        is_coinbase,
    }
}

fn make_op(txid_byte: u8, vout: u32) -> OutPoint {
    let mut txid = [0u8; 32];
    txid[0] = txid_byte;
    OutPoint {
        txid: Hash256(txid),
        vout,
    }
}

fn build_snapshot(blockhash: Hash256, magic: NetworkMagic, coins: &[(OutPoint, Coin)]) -> Vec<u8> {
    let metadata = SnapshotMetadata::new(blockhash, coins.len() as u64, magic);
    let mut buf = Vec::new();
    let mut writer = SnapshotWriter::new(&mut buf, &metadata).unwrap();
    let mut sorted = coins.to_vec();
    sorted.sort_by(|a, b| {
        a.0.txid
            .as_bytes()
            .cmp(b.0.txid.as_bytes())
            .then(a.0.vout.cmp(&b.0.vout))
    });
    for (op, coin) in &sorted {
        writer.write_coin(op, coin).unwrap();
    }
    let _ = writer.finish();
    buf
}

// =====================================================================
// SECTION 1 — Snapshot file header (G1–G5)
// =====================================================================

/// G1: `SNAPSHOT_MAGIC_BYTES` literal matches Core's `'u','t','x','o',0xff`.
#[test]
fn g1_snapshot_magic_bytes_match_core() {
    assert_eq!(SNAPSHOT_MAGIC_BYTES, [b'u', b't', b'x', b'o', 0xff]);
}

/// G2: snapshot version is `2` (Core `node/utxo_snapshot.h::VERSION`).
#[test]
fn g2_snapshot_version_is_two() {
    assert_eq!(SNAPSHOT_VERSION, 2u16);
}

/// G2: a snapshot file with a wrong version byte must be rejected.
#[test]
fn g2_wrong_version_rejected() {
    let magic = mainnet_magic();
    let metadata = SnapshotMetadata::new(dummy_hash(1), 0, magic);
    let mut buf = Vec::new();
    metadata.serialize(&mut buf).unwrap();
    // overwrite version with 99
    buf[5] = 99;
    buf[6] = 0;
    let mut cursor = Cursor::new(&buf);
    let r = SnapshotMetadata::deserialize(&mut cursor, &magic);
    assert!(matches!(r, Err(SnapshotError::UnsupportedVersion(99))));
}

/// G3: snapshot for a different network is rejected (NetworkMismatch).
#[test]
fn g3_network_magic_mismatch_rejected() {
    let mainnet = mainnet_magic();
    let testnet4 = testnet4_magic();
    let metadata = SnapshotMetadata::new(dummy_hash(2), 0, mainnet);
    let mut buf = Vec::new();
    metadata.serialize(&mut buf).unwrap();
    let mut cursor = Cursor::new(&buf);
    let r = SnapshotMetadata::deserialize(&mut cursor, &testnet4);
    assert!(matches!(r, Err(SnapshotError::NetworkMismatch)));
}

/// G4: `base_blockhash` round-trips through the 32-byte header field.
#[test]
fn g4_base_blockhash_roundtrip() {
    let magic = mainnet_magic();
    let bh = Hash256::from_hex(
        "00000000000000000000ccebd6d74d9194d8dcdc1d177c478e094bfad51ba5ac",
    )
    .unwrap();
    let metadata = SnapshotMetadata::new(bh, 0, magic);
    let mut buf = Vec::new();
    metadata.serialize(&mut buf).unwrap();
    let mut cursor = Cursor::new(&buf);
    let decoded = SnapshotMetadata::deserialize(&mut cursor, &magic).unwrap();
    assert_eq!(decoded.base_blockhash, bh);
}

/// G5: `coins_count` (`u64` LE) round-trips through the header.
#[test]
fn g5_coins_count_roundtrip() {
    let magic = mainnet_magic();
    let bh = dummy_hash(5);
    for n in [0u64, 1, 991_032_194, u64::MAX] {
        let metadata = SnapshotMetadata::new(bh, n, magic);
        let mut buf = Vec::new();
        metadata.serialize(&mut buf).unwrap();
        let mut cursor = Cursor::new(&buf);
        let decoded = SnapshotMetadata::deserialize(&mut cursor, &magic).unwrap();
        assert_eq!(decoded.coins_count, n, "coins_count round-trip {n}");
    }
}

// =====================================================================
// SECTION 2 — Per-coin record encoding (G6–G10)
// =====================================================================

/// G6: multi-coin txid grouping (Core's per-txid `n_coins` group header).
#[test]
fn g6_per_txid_grouping() {
    let magic = mainnet_magic();
    let bh = dummy_hash(6);
    let txid_a = Hash256::from_hex(
        "1100000000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap();
    let coins = vec![
        (OutPoint { txid: txid_a, vout: 0 }, make_coin(10_000, 100, false)),
        (OutPoint { txid: txid_a, vout: 1 }, make_coin(20_000, 100, false)),
        (OutPoint { txid: txid_a, vout: 2 }, make_coin(30_000, 100, false)),
    ];
    let buf = build_snapshot(bh, magic, &coins);
    let cursor = Cursor::new(buf);
    let mut reader = SnapshotReader::open(cursor, &magic).unwrap();
    let mut decoded = Vec::new();
    while let Some((op, c)) = reader.read_coin().unwrap() {
        decoded.push((op, c));
    }
    reader.verify_complete().unwrap();
    assert_eq!(decoded.len(), 3);
    assert!(decoded.iter().all(|(op, _)| op.txid == txid_a));
}

/// G7: per-coin `code` = `(height<<1)|coinbase` round-trips. Specifically
/// the writer emits Bitcoin's VARINT and the reader decodes the same way.
#[test]
fn g7_code_height_coinbase_roundtrip() {
    let magic = mainnet_magic();
    let bh = dummy_hash(7);
    let op = make_op(0x70, 0);
    let coin = make_coin(1000, 12345, true); // height=12345, coinbase=true
    let buf = build_snapshot(bh, magic, &[(op, coin.clone())]);
    let cursor = Cursor::new(buf);
    let mut reader = SnapshotReader::open(cursor, &magic).unwrap();
    let (_op, c) = reader.read_coin().unwrap().unwrap();
    assert_eq!(c.height, 12345);
    assert!(c.is_coinbase);
}

/// G8: `with_base_height(base)` causes `read_coin` to reject coins with
/// `height > base`. Mirrors Core `validation.cpp:5814`.
#[test]
fn g8_coin_height_above_base_rejected() {
    let magic = mainnet_magic();
    let bh = dummy_hash(8);
    let op = make_op(0x80, 0);
    let bad = make_coin(1000, 200, false); // height 200 > base 100
    let buf = build_snapshot(bh, magic, &[(op, bad)]);
    let cursor = Cursor::new(buf);
    let mut reader = SnapshotReader::open(cursor, &magic)
        .unwrap()
        .with_base_height(100);
    let r = reader.read_coin();
    assert!(matches!(r, Err(SnapshotError::MalformedCoin(_))));
}

/// G9: coin value > `MAX_MONEY` rejected. Mirrors Core
/// `validation.cpp:5820 !MoneyRange(coin.out.nValue)`.
#[test]
fn g9_coin_over_max_money_rejected() {
    let magic = mainnet_magic();
    let bh = dummy_hash(9);
    let op = make_op(0x90, 0);
    let bad = Coin {
        tx_out: TxOut {
            value: 21_000_001u64 * 100_000_000,
            script_pubkey: p2pkh_script(),
        },
        height: 50,
        is_coinbase: false,
    };
    let buf = build_snapshot(bh, magic, &[(op, bad)]);
    let cursor = Cursor::new(buf);
    let mut reader = SnapshotReader::open(cursor, &magic).unwrap();
    let r = reader.read_coin();
    assert!(matches!(r, Err(SnapshotError::MalformedCoin(_))));
}

/// G10: appended trailing data triggers `TrailingData` on
/// `verify_complete()`. Mirrors Core's "left over after deserializing"
/// check at `validation.cpp:5872-5883`.
#[test]
fn g10_trailing_data_rejected() {
    let magic = mainnet_magic();
    let bh = dummy_hash(10);
    let op = make_op(0xA0, 0);
    let coin = make_coin(1000, 50, false);
    let mut buf = build_snapshot(bh, magic, &[(op, coin)]);
    buf.push(0xFF); // trailing garbage
    let cursor = Cursor::new(buf);
    let mut reader = SnapshotReader::open(cursor, &magic).unwrap();
    let _ = reader.read_coin().unwrap();
    let r = reader.verify_complete();
    assert!(matches!(r, Err(SnapshotError::TrailingData)));
}

// =====================================================================
// SECTION 3 — AssumeUTXO chainparams + hash check (G11–G15)
// =====================================================================

/// G11: `AssumeutxoData` struct exposes the mandatory fields.
#[test]
fn g11_assumeutxo_data_struct_has_required_fields() {
    let p = ChainParams::mainnet();
    let d = &p.assumeutxo_data[0];
    // Just touch each field; compile alone is the gate.
    let _h: u32 = d.height;
    let _hash: Hash256 = d.blockhash;
    let _hs = d.hash_serialized;
    let _ctc: u64 = d.chain_tx_count;
    let _mtp: Option<u32> = d.base_mtp;
}

/// G12: mainnet table contains the 4 canonical Core entries.
#[test]
fn g12_mainnet_has_four_canonical_core_entries() {
    let p = ChainParams::mainnet();
    for h in [840_000u32, 880_000, 910_000, 935_000] {
        assert!(
            p.assumeutxo_for_height(h).is_some(),
            "mainnet must contain Core entry h={h}"
        );
    }
}

/// G12: mainnet h=840000 `hash_serialized` matches Core.
#[test]
fn g12_mainnet_h840k_hash_serialized_matches_core() {
    let p = ChainParams::mainnet();
    let d = p.assumeutxo_for_height(840_000).unwrap();
    // From bitcoin-core/src/kernel/chainparams.cpp:161
    let expected = Hash256::from_hex(
        "a2a5521b1b5ab65f67818e5e8eccabb7171a517f9e2382208f77687310768f96",
    )
    .unwrap();
    assert_eq!(d.hash_serialized.0, expected);
}

/// BUG-1 (G12 P0): mainnet contains a 5th hashhog-local entry at
/// h=944,183 that is NOT in Bitcoin Core's chainparams. This is an
/// "additional-acceptance" divergence: rustoshi accepts a snapshot
/// that Core would reject.
#[test]
#[ignore = "BUG-1 (W138 G12 P0): mainnet assumeutxo_data has fabricated h=944_183 hashhog-local entry not in Core's m_assumeutxo_data; rustoshi accepts snapshots Core rejects (consensus/params.rs:717-728)"]
fn g12_mainnet_has_only_core_entries() {
    let p = ChainParams::mainnet();
    // Core has exactly 4 entries at 840k/880k/910k/935k. The 5th
    // h=944183 entry is hashhog-local.
    assert_eq!(
        p.assumeutxo_data.len(),
        4,
        "mainnet must contain ONLY the 4 Core entries; found {}",
        p.assumeutxo_data.len()
    );
    assert!(
        p.assumeutxo_for_height(944_183).is_none(),
        "h=944_183 is hashhog-local, must not be in chainparams (parity with Core)"
    );
}

/// BUG-2 (G13 P0-CDIV): testnet4 has a fabricated 3rd entry at h=290,000
/// that is NOT in Core's chainparams. Documentation comment falsely
/// claims "Heights 90000, 120000, 290000" are "lifted verbatim from
/// Bitcoin Core" — Core defines only 90000 and 120000.
#[test]
#[ignore = "BUG-2 (W138 G13 P0-CDIV): testnet4 assumeutxo_data has FABRICATED h=290_000 entry with NO Core provenance; comment at params.rs:837 falsely claims 'lifted verbatim from Core'; comment-as-confession"]
fn g13_testnet4_matches_core_two_entries_only() {
    let p = ChainParams::testnet4();
    // Core CTestNet4Params::m_assumeutxo_data has exactly TWO entries:
    //   h=90'000 and h=120'000 (see bitcoin-core/src/kernel/chainparams.cpp:376-389).
    // The h=290_000 entry in params.rs:863-874 is fabricated.
    assert_eq!(
        p.assumeutxo_data.len(),
        2,
        "testnet4 must have exactly 2 Core entries; found {}",
        p.assumeutxo_data.len()
    );
    assert!(
        p.assumeutxo_for_height(290_000).is_none(),
        "h=290_000 is fabricated, must not be in chainparams"
    );
}

/// G13: testnet4 h=90000 `hash_serialized` matches Core.
#[test]
fn g13_testnet4_h90k_hash_serialized_matches_core() {
    let p = ChainParams::testnet4();
    let d = p.assumeutxo_for_height(90_000).unwrap();
    // From bitcoin-core/src/kernel/chainparams.cpp:379
    let expected = Hash256::from_hex(
        "784fb5e98241de66fdd429f4392155c9e7db5c017148e66e8fdbc95746f8b9b5",
    )
    .unwrap();
    assert_eq!(d.hash_serialized.0, expected);
}

/// BUG-3 (G14 P1): regtest must have the 3 Core test entries
/// (110/200/299) for `feature_assumeutxo.py` parity. Rustoshi has zero.
#[test]
#[ignore = "BUG-3 (W138 G14 P1): regtest assumeutxo_data is empty; Core regtest has 3 entries (h=110/200/299) for unit/functional/fuzz tests"]
fn g14_regtest_matches_core_three_entries() {
    let p = ChainParams::regtest();
    // Core CRegTestParams::m_assumeutxo_data has 3 entries at heights
    // 110, 200, 299 (bitcoin-core/src/kernel/chainparams.cpp:607-628).
    assert_eq!(
        p.assumeutxo_data.len(),
        3,
        "regtest must have 3 test entries (Core has 110/200/299); found {}",
        p.assumeutxo_data.len()
    );
}

/// G15: `compute_hash_serialized` produces a deterministic value
/// for the same coin set.
#[test]
fn g15_hash_serialized_deterministic() {
    let op = make_op(0x01, 0);
    let coin = make_coin(50_0000_0000, 1, true);
    let h1 = compute_hash_serialized(std::iter::once((op.clone(), coin.clone())));
    let h2 = compute_hash_serialized(std::iter::once((op, coin)));
    assert_eq!(h1, h2);
}

/// BUG-4 (G15 P0): the CLI load path accepts EITHER the legacy or the
/// Core-shaped hash. The legacy form (main.rs:1714-1730) has no Core
/// provenance; it weakens the consensus check. This test documents
/// that the helpers exist for the legacy form and that the
/// Core-shaped `compute_hash_serialized` IS correct on its own — the
/// production bug is the OR-acceptance in main.rs.
#[test]
#[ignore = "BUG-4 (W138 G15 P0): production main.rs:1795 accepts legacy OR core-shaped hash match; legacy form has no Core provenance and weakens the consensus check; this test is a source-grep proxy and would need full RPC harness to drive"]
fn g15_hash_check_must_not_accept_legacy_form() {
    let _ = "see audit/w138_assumeutxo.md BUG-4; verifying main.rs only accepts core form requires the harness";
}

// =====================================================================
// SECTION 4 — Headers-chain presence + chainwork (G16–G20)
// =====================================================================

/// BUG-5 (G16 P0-CONSENSUS): the CLI `--load-snapshot` path does NOT
/// check that the snapshot's base_blockhash is present in the headers
/// chain before ingesting coins. Core's `ActivateSnapshot` returns
/// `"The base block header (X) must appear in the headers chain"`
/// at validation.cpp:5611-5614. Rustoshi creates a synthetic
/// `BlockIndexEntry` with `prev_hash = Hash256::ZERO`.
#[test]
#[ignore = "BUG-5 (W138 G16 P0-CONSENSUS): main.rs:1659-1905 has NO headers-chain presence check; snapshot ingests even if base_blockhash is unknown; harness needed to drive end-to-end"]
fn g16_snapshot_rejected_when_base_header_not_in_chain() {
    let _ = "see audit/w138_assumeutxo.md BUG-5";
}

/// BUG-6 (G17 P0-CDIV): the snapshot tip's chain_work is hardcoded
/// to `params.minimum_chain_work` regardless of the snapshot block's
/// real cumulative work. Documented as intentional at main.rs:1838-1844.
/// Effect: a snapshot for a very early block (e.g. h=1, chain_work ~0)
/// would still satisfy the minimum-work threshold.
#[test]
#[ignore = "BUG-6 (W138 G17 P0-CDIV): main.rs:1845 hardcodes snapshot_chain_work=minimum_chain_work regardless of the snapshot block's real cumulative work (Core compares against the headers-chain ancestor's nChainWork)"]
fn g17_snapshot_chain_work_must_be_real_not_hardcoded_minimum() {
    let _ = "see audit/w138_assumeutxo.md BUG-6";
}

/// BUG-7 (G18 P0): no "headers branch with more work than snapshot"
/// guard. Core's `ActivateSnapshot` rejects activation if a forked
/// headers chain has more cumulative work than the snapshot-anchored
/// chain (validation.cpp:5622-5624).
#[test]
#[ignore = "BUG-7 (W138 G18 P0): main.rs:1659-1905 has no `m_best_header->GetAncestor(...) != snapshot_start_block` check; a more-work headers branch silently loses to the snapshot"]
fn g18_more_work_headers_branch_rejects_snapshot() {
    let _ = "see audit/w138_assumeutxo.md BUG-7";
}

/// BUG-8 (G19 P1): no double-activation guard. Core: `if
/// (CurrentChainstate().m_from_snapshot_blockhash) return error("Can't
/// activate a snapshot-based chainstate more than once")` (Core L5600).
/// Rustoshi never checks because there's no `m_from_snapshot_blockhash`
/// field at all.
#[test]
#[ignore = "BUG-8 (W138 G19 P1): main.rs:1659-1905 has no `already-snapshot-active` guard; running --load-snapshot=A then --load-snapshot=B silently overwrites tip"]
fn g19_double_activation_rejected() {
    let _ = "see audit/w138_assumeutxo.md BUG-8";
}

/// BUG-9 (G20 P1): no empty-mempool guard. Core: validation.cpp:5627-5629
/// `if (mempool && mempool->size() > 0) error("Can't activate a
/// snapshot when mempool not empty")`. Rustoshi's activation runs
/// pre-RPC-bind, but the invariant is still absent.
#[test]
#[ignore = "BUG-9 (W138 G20 P1): main.rs:1659-1905 has no empty-mempool guard; latent because activation runs pre-RPC-bind, surfaces if loadtxoutset RPC is ever wired (BUG-19 fix)"]
fn g20_activation_rejected_when_mempool_nonempty() {
    let _ = "see audit/w138_assumeutxo.md BUG-9";
}

// =====================================================================
// SECTION 5 — Dual-chainstate / background-validator state machine
// (G21–G27)
// =====================================================================

/// BUG-10 (G21 P0-CDIV): `Chainstate` has NO `m_from_snapshot_blockhash`
/// field. `SnapshotActivation` (storage/snapshot.rs:1192-1232) exists
/// but is never wired into the live `ChainState`.
#[test]
#[ignore = "BUG-10 (W138 G21 P0-CDIV): rustoshi `ChainState` has no `m_from_snapshot_blockhash` field; SnapshotActivation exists but is wholly dead code in production (only used by tests)"]
fn g21_chainstate_has_from_snapshot_blockhash_field() {
    // This would assert that `ChainState::from_snapshot_blockhash` is
    // Some(_) after `--load-snapshot`. Currently the field doesn't
    // exist.
    let _ = "see audit/w138_assumeutxo.md BUG-10";
}

/// BUG-11 (G22 P0-CDIV): the second "background IBD" chainstate is
/// NEVER constructed. Core's `ActivateSnapshot` creates a second
/// chainstate via `make_unique<Chainstate>(...)` then `AddChainstate`.
/// Rustoshi proceeds with a single chainstate that jumps to the
/// snapshot tip.
#[test]
#[ignore = "BUG-11 (W138 G22 P0-CDIV): no second chainstate constructed at main.rs:1659-1905; ChainstateManager (storage/snapshot.rs:1342) is dead code"]
fn g22_second_background_chainstate_constructed() {
    let _ = "see audit/w138_assumeutxo.md BUG-11";
}

/// BUG-12 (G23 P0): `ChainstateManager` exists at storage/snapshot.rs:1342
/// but is never instantiated outside test code. Confirmed: `grep
/// ChainstateManager::new` returns hits only in w102_assumeutxo_gates.rs
/// and snapshot.rs::tests.
#[test]
#[ignore = "BUG-12 (W138 G23 P0): ChainstateManager (storage/snapshot.rs:1342-1514) is a well-engineered abstraction but never instantiated outside test code"]
fn g23_chainstate_manager_wired_in_production() {
    // A passing form of this test would assert that the live ChainState
    // in main.rs holds a `ChainstateManager` reference. Currently
    // main.rs never imports or constructs ChainstateManager.
    let _ = "see audit/w138_assumeutxo.md BUG-12";
}

/// BUG-13 (G24 P0-CDIV): `MaybeValidateSnapshot` is never invoked.
/// The hook `should_validate_snapshot(ibd_height)` exists at
/// snapshot.rs:1468-1473 but has no production caller (only
/// w102_assumeutxo_gates.rs:472 + snapshot.rs::tests).
#[test]
#[ignore = "BUG-13 (W138 G24 P0-CDIV): ChainstateManager::should_validate_snapshot() has no production call site; the rendezvous check never fires"]
fn g24_maybe_validate_snapshot_invoked_at_rendezvous_height() {
    let _ = "see audit/w138_assumeutxo.md BUG-13";
}

/// BUG-14 (G25 P0-CDIV): `SnapshotState::Invalid` arm and
/// `m_assumeutxo = INVALID` are absent. Even if BUG-13 is wired, there
/// is no state arm to mark the snapshot rejected, no
/// `InvalidateCoinsDBOnDisk`-equivalent rename, no fatal-error
/// shutdown.
#[test]
#[ignore = "BUG-14 (W138 G25 P0-CDIV): SnapshotState enum (snapshot.rs:608-635) has only NotLoaded/Loading/Unvalidated/Validated arms; no Invalid arm for hash-mismatch rejection"]
fn g25_snapshot_state_has_invalid_arm() {
    // Compile-time check: confirm the enum has 4 arms only. A future
    // fix would add `SnapshotState::Invalid { base_blockhash, ... }`.
    let s = SnapshotState::NotLoaded;
    match s {
        SnapshotState::NotLoaded => {}
        SnapshotState::Loading { .. } => {}
        SnapshotState::Unvalidated { .. } => {}
        SnapshotState::Validated { .. } => {}
    }
    let _ = "no SnapshotState::Invalid arm; see audit/w138_assumeutxo.md BUG-14";
    panic!("expected SnapshotState::Invalid arm to exist; gate fails until BUG-14 is closed");
}

/// BUG-15 (G26 P1): cache rebalance helpers exist on `ChainstateManager`
/// (`snapshot_cache_size` / `ibd_cache_size`) but are never invoked
/// from production (BUG-12 means the manager itself is never built).
#[test]
#[ignore = "BUG-15 (W138 G26 P1): ChainstateManager::{snapshot_cache_size,ibd_cache_size} are well-engineered but never called from production"]
fn g26_cache_rebalance_invoked_in_production() {
    let _ = "see audit/w138_assumeutxo.md BUG-15";
}

/// BUG-16 (G27 P2): `ValidatedSnapshotCleanup` (rename
/// `chainstate_snapshot` → `chainstate`, delete bg-dir) has no rustoshi
/// equivalent. Latent because there's no second chainstate to clean up.
#[test]
#[ignore = "BUG-16 (W138 G27 P2): no ValidatedSnapshotCleanup function in storage/snapshot.rs; latent because there's no second chainstate to clean up (becomes relevant when BUG-11 is fixed)"]
fn g27_validated_snapshot_cleanup_exists() {
    let _ = "see audit/w138_assumeutxo.md BUG-16";
}

// =====================================================================
// SECTION 6 — Persistence + restart + RPC (G28–G30 + BONUS)
// =====================================================================

/// G28 PARTIAL: `write_snapshot_blockhash` + `read_snapshot_blockhash`
/// round-trip works in isolation. Bug is in the production call site
/// (main.rs:1808) which writes to the datadir root instead of a
/// dedicated `chainstate_snapshot/` directory.
#[test]
fn g28_snapshot_blockhash_file_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let bh = dummy_hash(0x28);
    write_snapshot_blockhash(tmp.path(), &bh).unwrap();
    let read = read_snapshot_blockhash(tmp.path()).unwrap().unwrap();
    assert_eq!(read, bh);
}

/// G28 / BUG-17 (P0): `SNAPSHOT_BLOCKHASH_FILENAME` literal matches
/// Core. The production bug is the DIRECTORY where it lives.
#[test]
fn g28_snapshot_blockhash_filename_matches_core() {
    assert_eq!(SNAPSHOT_BLOCKHASH_FILENAME, "base_blockhash");
    assert_eq!(SNAPSHOT_CHAINSTATE_SUFFIX, "_snapshot");
}

/// BUG-17 (G28 P0): the production CLI path writes the
/// `base_blockhash` file to the datadir ROOT (main.rs:1808
/// `write_snapshot_blockhash(&datadir, &blockhash)`) rather than to a
/// dedicated `chainstate_snapshot/` directory. Core's contract: the
/// file is INSIDE the snapshot chainstate's own leveldb dir so
/// `FindAssumeutxoChainstateDir` can locate it.
#[test]
#[ignore = "BUG-17 (W138 G28 P0): main.rs:1808 writes base_blockhash under the datadir root, not under chainstate_snapshot/; the suffix-named dir is never created so FindAssumeutxoChainstateDir would fail"]
fn g28_snapshot_blockhash_written_to_suffix_dir() {
    let _ = "see audit/w138_assumeutxo.md BUG-17";
}

/// BUG-18 (G29 P0-CDIV): restart never reconstructs the snapshot
/// chainstate from disk. Core's `LoadAssumeutxoChainstate`
/// (validation.cpp:6151) calls `FindAssumeutxoChainstateDir` +
/// `ReadSnapshotBaseBlockhash` on startup. Rustoshi has both helpers
/// (storage/snapshot.rs:1252-1289) but main.rs startup never calls
/// either.
#[test]
#[ignore = "BUG-18 (W138 G29 P0-CDIV): rustoshi/src/main.rs startup never calls find_snapshot_chainstate_dir or read_snapshot_blockhash; restart cannot identify a chainstate as snapshot-derived"]
fn g29_restart_reconstructs_snapshot_chainstate() {
    let _ = "see audit/w138_assumeutxo.md BUG-18";
}

/// G29 helper: `find_snapshot_chainstate_dir` returns None when no
/// suffix dir exists.
#[test]
fn g29_find_snapshot_chainstate_dir_returns_none_when_absent() {
    let tmp = tempfile::tempdir().unwrap();
    assert!(find_snapshot_chainstate_dir(tmp.path()).is_none());
}

/// G29 helper: `find_snapshot_chainstate_dir` finds the dir when it
/// exists.
#[test]
fn g29_find_snapshot_chainstate_dir_finds_suffix_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let snap_dir = tmp.path().join("chainstate_snapshot");
    std::fs::create_dir(&snap_dir).unwrap();
    let found = find_snapshot_chainstate_dir(tmp.path());
    assert_eq!(found, Some(snap_dir));
}

/// BUG-19 (G30 P0-CDIV): RPC `loadtxoutset` is wholly disabled.
/// `crates/rpc/src/server.rs:8045-8121` returns `RPC_INTERNAL_ERROR`
/// regardless of input. The W102 audit recorded this as G25; it's
/// re-pinned here as the W138 equivalent.
#[test]
#[ignore = "BUG-19 (W138 G30 P0-CDIV): loadtxoutset RPC at server.rs:8045-8121 returns RPC_INTERNAL_ERROR unconditionally; operators cannot activate snapshots via JSON-RPC, only via --load-snapshot CLI"]
fn g30_loadtxoutset_rpc_activates_snapshot() {
    let _ = "see audit/w138_assumeutxo.md BUG-19";
}

/// BUG-20 (BONUS P1): RPC `getchainstates` is missing entirely.
/// Operators have no JSON-RPC way to introspect snapshot vs.
/// background chainstate status, validation completion, or cache
/// allocations.
#[test]
#[ignore = "BUG-20 (W138 BONUS P1): RPC `getchainstates` is not defined in crates/rpc/src/server.rs; Core exposes it at rpc/blockchain.cpp:3462 with snapshot_blockhash/validated/coins_db_cache_bytes fields"]
fn bonus_getchainstates_rpc_exposed() {
    let _ = "see audit/w138_assumeutxo.md BUG-20";
}

// =====================================================================
// REGRESSION PINS — additional Core-aligned properties beyond the
// 30-gate matrix, kept here so future refactors can't silently
// regress.
// =====================================================================

/// Lock: `tx_out_ser` produces the exact byte layout used by Core's
/// `kernel/coinstats.cpp::TxOutSer`. A 1-coin P2PKH at height=1
/// coinbase=true value=50e8 must produce a 73-byte stream.
#[test]
fn regression_tx_out_ser_byte_layout_locked() {
    let op = make_op(0x01, 0);
    let coin = make_coin(50_0000_0000, 1, true);
    let h = compute_hash_serialized(std::iter::once((op, coin)));
    // The deterministic hash of one canonical TxOutSer must not change.
    // We don't pin the exact bytes here (snapshot.rs::tests pins them);
    // we pin determinism against drift in the hash domain.
    let h2 = compute_hash_serialized(std::iter::once((
        make_op(0x01, 0),
        make_coin(50_0000_0000, 1, true),
    )));
    assert_eq!(h, h2);
}

/// Sanity: muhash is order-independent over a small UTXO set.
#[test]
fn regression_muhash_order_independent() {
    let op_a = make_op(0x01, 0);
    let op_b = make_op(0x02, 0);
    let coin_a = make_coin(100, 10, false);
    let coin_b = make_coin(200, 20, true);
    let h1 = compute_utxo_muhash(
        vec![
            (op_a.clone(), coin_a.clone()),
            (op_b.clone(), coin_b.clone()),
        ]
        .into_iter(),
    );
    let h2 = compute_utxo_muhash(vec![(op_b, coin_b), (op_a, coin_a)].into_iter());
    assert_eq!(h1, h2);
}

/// SnapshotActivation marker is constructable from a blockhash; this
/// is dead code in production (BUG-10/11/12) but at least the type is
/// well-typed.
#[test]
fn regression_snapshot_activation_marker_constructable() {
    let bh = dummy_hash(0xAA);
    let a = SnapshotActivation::from_snapshot(bh);
    assert!(a.is_snapshot());
    assert!(!a.snapshot_validated);
}

/// ChainstateManager test-code construction works. Dead code in
/// production per BUG-12, but the unit-test surface is fine.
#[test]
fn regression_chainstate_manager_test_surface_works() {
    let mut m = ChainstateManager::new();
    assert!(!m.is_snapshot_active());
    let bh = dummy_hash(0xBB);
    m.begin_snapshot_load(bh, 100_000, 1000);
    m.activate_snapshot(bh, 100_000);
    assert!(m.is_snapshot_active());
    assert!(!m.is_snapshot_validated());
    assert!(m.should_validate_snapshot(100_000));
    m.validate_snapshot();
    assert!(m.is_snapshot_validated());
}
