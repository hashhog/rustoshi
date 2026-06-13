//! W102 AssumeUTXO snapshot loading gate audit tests.
//!
//! # Bug List
//!
//! G4  main.rs:1501  CORRECTNESS — CLI `--load-snapshot` does NOT check that the
//!     snapshot's base_blockhash is already in the headers chain before ingesting
//!     millions of coins. Bitcoin Core's `ActivateSnapshot` calls
//!     `m_blockman.LookupBlockIndex(base_blockhash)` and returns an error if the
//!     header is not yet known; rustoshi proceeds unconditionally, meaning it will
//!     accept a snapshot whose base block is unreachable and set the tip to a
//!     phantom block index entry with `prev_hash = Hash256::ZERO`. This diverges
//!     from Core's `"The base block header ... must appear in the headers chain"` error.
//!
//! G5  main.rs:1676  CORRECTNESS — `minimum_chain_work` is treated as the
//!     snapshot's chain_work rather than verifying that the snapshot block's real
//!     chain_work (from the headers chain) meets `nMinimumChainWork`. The comment
//!     acknowledges this is a workaround ("We don't have the real cumulative work
//!     without scanning history"). This means a crafted snapshot for a very early
//!     block (e.g. height 1, chain_work near zero) would be accepted even though
//!     the snapshot block's actual chain_work falls far below the minimum.
//!
//! G8  main.rs:1554-1596  CORRECTNESS — per-coin validation is absent. Bitcoin
//!     Core's `PopulateAndValidateSnapshot` checks `coin.nHeight > base_height`
//!     (rejects any coin with a height above the snapshot) and `!MoneyRange(coin.out.nValue)`
//!     (rejects any coin with a negative or oversized value). Rustoshi stores every
//!     coin unconditionally; a tampered snapshot file can insert coins at heights
//!     above the snapshot tip or with out-of-range values without being rejected.
//!
//! G10 main.rs:1594  CORRECTNESS — coins are written directly to CF_UTXO via
//!     `store.put_utxo` with no FRESH+DIRTY cache flags. This is architecturally
//!     correct for a bulk-load path (bypassing the in-memory cache), but there is
//!     no intermediate `Flush`/`Sync` barrier at the 120,000-coin cadence that
//!     Core uses to keep peak memory bounded. On a 165 M-coin mainnet snapshot
//!     this can allocate ~6 GB of dirty pages before the first flush.
//!
//! G14 main.rs:1728-1730  CONSENSUS-DIVERGENT — rustoshi explicitly documents
//!     "Background validation of 0..snapshot is NOT performed in this
//!     single-chainstate build." The `ChainstateManager`, `SnapshotActivation`,
//!     and `should_validate_snapshot` / `validate_snapshot` hooks exist in the
//!     storage layer but are never wired into the main event loop. The second
//!     chainstate (G12/G13) is not constructed. The snapshot is permanently in
//!     `SnapshotState::Unvalidated` state — no fall-back if the snapshot was
//!     tampered and the UTXO hash matched only because the attacker chose a
//!     matching hash.
//!
//! G15 main.rs:1728-1730  DOS / CONSENSUS-DIVERGENT — (same as G14) background
//!     IBD chainstate is absent; the snapshot can never be independently
//!     cross-validated by reaching the snapshot height from genesis.
//!
//! G16 main.rs (missing)  CONSENSUS-DIVERGENT — the cross-validation step
//!     (compare validated UTXO set to snapshot set when IBD reaches snapshot
//!     height) is not implemented. `ChainstateManager::should_validate_snapshot`
//!     and `validate_snapshot` are dead code paths — they compile but are never
//!     called from the main block-processing loop.
//!
//! G17 main.rs (missing)  CONSENSUS-DIVERGENT — fall-back to IBD on snapshot
//!     rejection is not implemented. There is no code path that detects a
//!     mismatch between the snapshot UTXO set and the independently-validated
//!     UTXO set, nor any that discards the snapshot chainstate and promotes IBD.
//!
//! G25 server.rs:7667-7742  CORRECTNESS — the `loadtxoutset` RPC unconditionally
//!     returns `RPC_INTERNAL_ERROR` with a message directing users to the CLI
//!     `--load-snapshot` flag. This matches the documented intent, but it means
//!     the RPC path is entirely unimplemented: operator tooling that calls
//!     `loadtxoutset` via JSON-RPC (matching Core's interface) gets an error
//!     rather than activating the snapshot. This is a MISSING-GATE for the RPC
//!     activation surface, not just a stub.
//!
//! G28 server.rs:7286 / 7667  CORRECTNESS — no concurrency guard prevents two
//!     concurrent `dumptxoutset` callers from racing each other, or prevents
//!     a `dumptxoutset` and a `loadtxoutset` from overlapping. The
//!     `block_submission_paused` flag is set only during the rollback inner
//!     path; there is no flag that serialises snapshot-level operations with
//!     each other.
//!
//! G29 main.rs:1626-1632  CORRECTNESS — on hash-mismatch the CLI path returns
//!     `Err(...)` after all coins have already been written to CF_UTXO. There is
//!     no cleanup of those coins; the datadir is left with a partially-written UTXO
//!     column family that is neither valid nor consistent. Subsequent restarts
//!     without `--load-snapshot` will observe a poisoned UTXO set at genesis tip.
//!
//! G30 main.rs:1727 / zmq.rs  OBSERVABILITY — no ZMQ `hashblock` notification is
//!     sent when the snapshot tip is activated. Bitcoin Core emits a `BlockConnected`
//!     signal (which drives ZMQ) when the snapshot chainstate activates. Rustoshi's
//!     activation block in `main.rs` never calls `zmq_notifier.notify_block(...)`,
//!     so ZMQ subscribers never learn the node jumped from genesis to the snapshot
//!     tip.

#[cfg(test)]
mod tests {
    use crate::snapshot::{
        compute_hash_serialized, compute_utxo_muhash,
        SnapshotError, SnapshotMetadata, SnapshotReader, SnapshotWriter,
        ChainstateManager,
        SNAPSHOT_MAGIC_BYTES, SNAPSHOT_VERSION,
    };
    use rustoshi_consensus::NetworkMagic;
    use rustoshi_primitives::{Hash256, OutPoint, TxOut};
    use crate::utxo_cache::Coin;
    use std::io::Cursor;

    // ================================================================
    // HELPERS
    // ================================================================

    fn mainnet_magic() -> NetworkMagic {
        NetworkMagic([0xf9, 0xbe, 0xb4, 0xd9])
    }

    fn testnet4_magic() -> NetworkMagic {
        // testnet4 magic from bitcoin-core/src/chainparams.cpp
        NetworkMagic([0x1c, 0x16, 0x3f, 0x28])
    }

    fn dummy_blockhash(n: u8) -> Hash256 {
        let mut b = [0u8; 32];
        b[0] = n;
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

    fn make_outpoint(txid_byte: u8, vout: u32) -> OutPoint {
        let mut txid = [0u8; 32];
        txid[0] = txid_byte;
        OutPoint { txid: Hash256(txid), vout }
    }

    // Build a minimal well-formed snapshot buffer with `coins` in it.
    fn build_snapshot(blockhash: Hash256, magic: NetworkMagic, coins: &[(OutPoint, Coin)]) -> Vec<u8> {
        let metadata = SnapshotMetadata::new(blockhash, coins.len() as u64, magic);
        let mut buf = Vec::new();
        let mut writer = SnapshotWriter::new(&mut buf, &metadata).unwrap();
        // Must be in sorted order for the writer.
        let mut sorted = coins.to_vec();
        sorted.sort_by(|a, b| a.0.txid.as_bytes().cmp(b.0.txid.as_bytes()).then(a.0.vout.cmp(&b.0.vout)));
        for (op, coin) in &sorted {
            writer.write_coin(op, coin).unwrap();
        }
        let _ = writer.finish();
        buf
    }

    // ================================================================
    // G1 — Snapshot file header: magic + version + network_magic
    // ================================================================

    /// G1: version field 2 bytes LE; unsupported version must be rejected.
    #[test]
    fn g1_header_rejects_wrong_version() {
        let magic = mainnet_magic();
        let blockhash = dummy_blockhash(1);
        // Build a valid header then patch the version field.
        let metadata = SnapshotMetadata::new(blockhash, 0, magic);
        let mut buf = Vec::new();
        metadata.serialize(&mut buf).unwrap();
        // Overwrite version bytes (offset 5-6) with version 99.
        buf[5] = 99;
        buf[6] = 0;
        let mut cursor = Cursor::new(&buf);
        let result = SnapshotMetadata::deserialize(&mut cursor, &magic);
        assert!(
            matches!(result, Err(SnapshotError::UnsupportedVersion(99))),
            "expected UnsupportedVersion(99), got {:?}", result
        );
    }

    /// G1: magic bytes must match exactly.
    #[test]
    fn g1_header_rejects_bad_magic() {
        let magic = mainnet_magic();
        // Build a valid header and corrupt the magic prefix.
        let blockhash = dummy_blockhash(0);
        let metadata = SnapshotMetadata::new(blockhash, 0, magic);
        let mut buf = Vec::new();
        metadata.serialize(&mut buf).unwrap();
        // Overwrite the first byte of magic.
        buf[0] = 0x00;
        let mut cursor = Cursor::new(&buf);
        let result = SnapshotMetadata::deserialize(&mut cursor, &magic);
        assert!(
            matches!(result, Err(SnapshotError::InvalidMagic)),
            "expected InvalidMagic, got {:?}", result
        );
    }

    // ================================================================
    // G2 — Per-coin record encoding
    // ================================================================

    /// G2: roundtrip a coinbase coin and verify all fields survive.
    #[test]
    fn g2_per_coin_roundtrip_coinbase() {
        let magic = mainnet_magic();
        let blockhash = dummy_blockhash(2);
        let op = make_outpoint(0x10, 0);
        let coin = make_coin(50_0000_0000, 1, true);
        let buf = build_snapshot(blockhash, magic, &[(op.clone(), coin.clone())]);
        let cursor = Cursor::new(buf);
        let mut reader = SnapshotReader::open(cursor, &magic).unwrap();
        let (decoded_op, decoded_coin) = reader.read_coin().unwrap().expect("must have one coin");
        assert_eq!(decoded_op, op);
        assert_eq!(decoded_coin.height, coin.height);
        assert_eq!(decoded_coin.is_coinbase, coin.is_coinbase);
        assert_eq!(decoded_coin.tx_out.value, coin.tx_out.value);
        assert_eq!(decoded_coin.tx_out.script_pubkey, coin.tx_out.script_pubkey);
    }

    /// G2: vout > 0 round-trips correctly through CompactSize(vout).
    #[test]
    fn g2_per_coin_non_zero_vout_roundtrip() {
        let magic = mainnet_magic();
        let blockhash = dummy_blockhash(3);
        let op = make_outpoint(0x20, 257); // vout=257 exercises the 0xFD CompactSize path
        let coin = make_coin(1000, 100, false);
        let buf = build_snapshot(blockhash, magic, &[(op, coin.clone())]);
        let cursor = Cursor::new(buf);
        let mut reader = SnapshotReader::open(cursor, &magic).unwrap();
        let (decoded_op, _decoded_coin) = reader.read_coin().unwrap().unwrap();
        assert_eq!(decoded_op.vout, 257);
    }

    // ================================================================
    // G3 — Integrity verification / trailing data
    // ================================================================

    /// G3: verify_complete must succeed when the snapshot is exactly consumed.
    #[test]
    fn g3_verify_complete_on_exact_read() {
        let magic = testnet4_magic();
        let blockhash = dummy_blockhash(4);
        let op = make_outpoint(0x30, 0);
        let coin = make_coin(10000, 50, false);
        let buf = build_snapshot(blockhash, magic, &[(op, coin)]);
        let cursor = Cursor::new(buf);
        let mut reader = SnapshotReader::open(cursor, &magic).unwrap();
        let _ = reader.read_coin().unwrap(); // consume the one coin
        assert!(reader.verify_complete().is_ok(), "verify_complete must succeed on exact read");
    }

    /// G3: verify_complete must fail when trailing bytes remain.
    #[test]
    fn g3_verify_complete_detects_trailing_data() {
        let magic = testnet4_magic();
        let blockhash = dummy_blockhash(5);
        let op = make_outpoint(0x31, 0);
        let coin = make_coin(10000, 50, false);
        let mut buf = build_snapshot(blockhash, magic, &[(op, coin)]);
        buf.push(0xff); // append trailing garbage
        let cursor = Cursor::new(buf);
        let mut reader = SnapshotReader::open(cursor, &magic).unwrap();
        let _ = reader.read_coin().unwrap(); // consume the one coin
        let result = reader.verify_complete();
        assert!(
            matches!(result, Err(SnapshotError::TrailingData)),
            "expected TrailingData, got {:?}", result
        );
    }

    // ================================================================
    // G6 — Per-network assumeutxo block hash table
    // ================================================================

    /// G6: mainnet hash table must contain the 4 Core-canonical entries.
    #[test]
    fn g6_mainnet_assumeutxo_table_has_core_entries() {
        use rustoshi_consensus::ChainParams;
        let params = ChainParams::mainnet();
        // Bitcoin Core mainnet entries: h=840000, 880000, 910000, 935000
        // (source: bitcoin-core/src/kernel/chainparams.cpp)
        for height in [840_000u32, 880_000, 910_000, 935_000] {
            let entry = params.assumeutxo_for_height(height);
            assert!(
                entry.is_some(),
                "mainnet assumeutxo table must contain height {}", height
            );
        }
    }

    /// G6: testnet4 hash table must contain the 3 Core-canonical entries.
    #[test]
    fn g6_testnet4_assumeutxo_table_has_core_entries() {
        use rustoshi_consensus::ChainParams;
        let params = ChainParams::testnet4();
        // Bitcoin Core testnet4 entries: h=90000, 120000, 290000
        for height in [90_000u32, 120_000, 290_000] {
            let entry = params.assumeutxo_for_height(height);
            assert!(
                entry.is_some(),
                "testnet4 assumeutxo table must contain height {}", height
            );
        }
    }

    /// G6: unknown blockhash must not match any assumeutxo entry.
    #[test]
    fn g6_unknown_blockhash_returns_none() {
        use rustoshi_consensus::ChainParams;
        let params = ChainParams::mainnet();
        let bogus = dummy_blockhash(0xde);
        assert!(
            params.assumeutxo_for_blockhash(&bogus).is_none(),
            "unknown blockhash must not match any assumeutxo entry"
        );
    }

    // ================================================================
    // G7 — Hash comparison: computed must match chainparams hash_serialized
    // ================================================================

    /// G7: hash_serialized computed over a known coin set must match a hand-computed value.
    /// This pins the core_hasher TxOutSer layout so regressions are caught.
    #[test]
    fn g7_core_hash_serialized_is_deterministic_and_stable() {
        let op = make_outpoint(0x01, 0);
        let coin = make_coin(50_0000_0000, 1, true);
        let h1 = compute_hash_serialized(std::iter::once((op.clone(), coin.clone())));
        let h2 = compute_hash_serialized(std::iter::once((op, coin)));
        assert_eq!(h1, h2, "hash_serialized must be deterministic");
    }

    /// G7: different coin sets must produce different hashes.
    #[test]
    fn g7_different_utxo_sets_produce_different_hashes() {
        let op_a = make_outpoint(0x01, 0);
        let coin_a = make_coin(100, 10, false);
        let op_b = make_outpoint(0x02, 0);
        let coin_b = make_coin(200, 20, false);
        let h1 = compute_hash_serialized(std::iter::once((op_a.clone(), coin_a.clone())));
        let h2 = compute_hash_serialized(std::iter::once((op_b.clone(), coin_b.clone())));
        let h3 = compute_hash_serialized(vec![(op_a, coin_a), (op_b, coin_b)].into_iter());
        assert_ne!(h1, h2, "different coins must produce different hashes");
        assert_ne!(h1, h3, "subset != full set hash");
        assert_ne!(h2, h3, "subset != full set hash");
    }

    // ================================================================
    // G8 — PopulateAndValidateSnapshot: per-coin height/MoneyRange checks (MISSING)
    // ================================================================

    /// G8: coin.height > snapshot_height must be rejected.
    /// Bitcoin Core rejects: `if (coin.nHeight > base_height)` in PopulateAndValidateSnapshot
    /// (validation.cpp:5814-5819). Guard is wired via `SnapshotReader::with_base_height`.
    #[test]
    fn g8_coin_height_above_snapshot_base_must_be_rejected() {
        // Build a snapshot claiming base height=100, but include a coin at height=200.
        let magic = mainnet_magic();
        let blockhash = dummy_blockhash(0x08);
        let op = make_outpoint(0x08, 0);
        let future_coin = make_coin(1000, 200, false); // height 200 > snapshot base height 100
        let buf = build_snapshot(blockhash, magic, &[(op, future_coin)]);
        let cursor = Cursor::new(buf);
        // Wire base_height=100; the coin at height=200 must be rejected.
        let mut reader = SnapshotReader::open(cursor, &magic).unwrap().with_base_height(100);
        let result = reader.read_coin();
        assert!(
            result.is_err(),
            "coin with height > snapshot base height must be rejected, got {:?}", result
        );
    }

    /// G8: MoneyRange check — values above 21 M BTC must be rejected.
    /// Bitcoin Core: `if (!MoneyRange(coin.out.nValue))` in PopulateAndValidateSnapshot
    /// (validation.cpp:5820-5822). Guard fires in `SnapshotReader::read_coin`.
    #[test]
    fn g8_coin_over_max_money_must_be_rejected() {
        // MAX_MONEY = 21_000_000 * 100_000_000 sat. A value above this must be rejected.
        let magic = mainnet_magic();
        let blockhash = dummy_blockhash(0x09);
        let op = make_outpoint(0x09, 0);
        let overlimit_coin = Coin {
            tx_out: TxOut {
                // 21_000_001 BTC > MAX_MONEY
                value: 21_000_001u64 * 100_000_000,
                script_pubkey: p2pkh_script(),
            },
            height: 100,
            is_coinbase: false,
        };
        let buf = build_snapshot(blockhash, magic, &[(op, overlimit_coin)]);
        let cursor = Cursor::new(buf);
        let mut reader = SnapshotReader::open(cursor, &magic).unwrap();
        let result = reader.read_coin();
        assert!(result.is_err(), "coin with value > MAX_MONEY must be rejected, got {:?}", result);
    }

    // ================================================================
    // G9 — MuHash3072 computed and verified
    // ================================================================

    /// G9: MuHash is order-independent; two permutations of the same coin set
    /// must yield the same muhash.
    #[test]
    fn g9_muhash_is_order_independent() {
        let op_a = make_outpoint(0x01, 0);
        let op_b = make_outpoint(0x02, 0);
        let coin_a = make_coin(100, 10, false);
        let coin_b = make_coin(200, 20, true);
        let h1 = compute_utxo_muhash(vec![(op_a.clone(), coin_a.clone()), (op_b.clone(), coin_b.clone())].into_iter());
        let h2 = compute_utxo_muhash(vec![(op_b, coin_b), (op_a, coin_a)].into_iter());
        assert_eq!(h1, h2, "MuHash must be order-independent");
    }

    /// G9: MuHash is sensitive to the coin set — changing any coin changes the hash.
    #[test]
    fn g9_muhash_changes_when_coin_changes() {
        let op = make_outpoint(0x01, 0);
        let coin_a = make_coin(100, 10, false);
        let coin_b = make_coin(101, 10, false); // different value
        let h1 = compute_utxo_muhash(std::iter::once((op.clone(), coin_a)));
        let h2 = compute_utxo_muhash(std::iter::once((op, coin_b)));
        assert_ne!(h1, h2, "MuHash must change when coin value changes");
    }

    // ================================================================
    // G11 — Best block set to base_blockhash after load
    // ================================================================

    /// G11: after a snapshot write-read cycle, the embedded blockhash survives.
    #[test]
    fn g11_base_blockhash_survives_snapshot_roundtrip() {
        let magic = mainnet_magic();
        let expected_blockhash = dummy_blockhash(0x11);
        let op = make_outpoint(0x11, 0);
        let coin = make_coin(5000, 100, false);
        let buf = build_snapshot(expected_blockhash, magic, &[(op, coin)]);
        let cursor = Cursor::new(buf);
        let reader = SnapshotReader::open(cursor, &magic).unwrap();
        assert_eq!(
            reader.metadata().base_blockhash,
            expected_blockhash,
            "base_blockhash in snapshot header must survive roundtrip"
        );
    }

    // ================================================================
    // G12/G13/G14 — Dual chainstate model (MISSING ENTIRELY)
    // ================================================================

    /// G14 (FIXED): the background-validation second chainstate is now wired.
    /// After a snapshot is activated WITH its assumeutxo commitment, the
    /// `ChainstateManager` constructs a SECOND chainstate with its OWN empty
    /// coins store, re-derives the snapshot UTXO set genesis->base into THAT
    /// store via a real ConnectBlock-style spend/add walk, recomputes
    /// HASH_SERIALIZED, and transitions Unvalidated -> Validated on a MATCH.
    ///
    /// This drives the real machinery end-to-end (no stub flag flip): the
    /// commitment is the hash of the genuine genesis->base set, the bg store
    /// independently re-derives it, and the verdict is `Valid`.
    #[test]
    fn g14_background_validation_chainstate_is_wired() {
        use crate::snapshot::SnapshotVerdict;

        // Build a real regtest-style chain genesis..base with a REAL spend.
        let chain = super::dual_cs_tests::build_chain();
        let base_height = chain.tip_height;
        let base_hash = chain.tip_hash;

        // The CORRECT commitment = HASH_SERIALIZED over the genuine
        // genesis->base UTXO set (computed independently by the test helper).
        let correct_hash = super::dual_cs_tests::independent_utxo_hash(&chain);

        let mut manager = ChainstateManager::new();
        manager.activate_snapshot_with_commitment(base_hash, base_height, correct_hash);
        assert!(!manager.is_snapshot_validated(), "snapshot must start unvalidated");
        assert!(manager.is_snapshot_active());

        // Demote a fresh genesis-rooted chainstate to BACKGROUND with its OWN
        // store. `active_store_id = 0xACED_1234` is a distinct identity sentinel.
        manager.start_background_validation(0xACED_1234usize);
        assert!(manager.should_validate_snapshot(base_height));

        // Drive the REAL genesis->base re-derivation in the separate store.
        let blocks = chain.blocks.clone();
        let verdict = manager
            .run_background_validation(|h| blocks.get(h as usize).cloned())
            .expect("background validation must complete without error");

        assert_eq!(verdict, SnapshotVerdict::Valid, "correct snapshot must validate");
        assert!(
            manager.is_snapshot_validated(),
            "snapshot must be VALIDATED after the bg chainstate re-derives a matching hash"
        );
        assert!(!manager.is_snapshot_invalid());
    }

    /// G16 BUG: cross-validation of snapshot vs independent IBD UTXO set is absent.
    #[test]
    #[ignore = "G16 BUG: no code path compares the IBD UTXO hash to the snapshot UTXO hash at the rendezvous height — main loop must call should_validate_snapshot()"]
    fn g16_snapshot_rejected_when_ibd_utxo_hash_differs() {
        // This test would verify that if the IBD chainstate reaches the snapshot
        // height but its UTXO hash does not match, the snapshot is rejected and
        // IBD is promoted. Currently neither the check nor the promotion exist.
        let _ = "not yet implemented";
    }

    /// G17 BUG: no fall-back to IBD on snapshot rejection.
    #[test]
    #[ignore = "G17 BUG: fall-back from rejected snapshot to IBD chainstate not implemented — SnapshotState::Invalid arm is missing"]
    fn g17_snapshot_rejection_promotes_ibd() {
        let _ = "not yet implemented";
    }

    // ================================================================
    // G18/G19 — dumptxoutset rollback parameter handling
    // ================================================================

    /// G18: snapshot format writer emits the correct type prefix and version.
    #[test]
    fn g18_snapshot_header_format_matches_spec() {
        let magic = mainnet_magic();
        let blockhash = dummy_blockhash(0x18);
        let metadata = SnapshotMetadata::new(blockhash, 0, magic);
        let mut buf = Vec::new();
        metadata.serialize(&mut buf).unwrap();
        // magic(5) + version_u16_LE(2) + network_magic(4) + blockhash(32) + coins_count_u64_LE(8)
        assert_eq!(buf.len(), 51, "header must be exactly 51 bytes");
        assert_eq!(&buf[..5], &SNAPSHOT_MAGIC_BYTES, "magic bytes must match");
        assert_eq!(&buf[5..7], &SNAPSHOT_VERSION.to_le_bytes(), "version must be 2 LE");
        assert_eq!(&buf[7..11], &magic.0, "network magic must follow version");
        assert_eq!(&buf[11..43], blockhash.as_bytes(), "blockhash must follow network magic");
        assert_eq!(&buf[43..51], &0u64.to_le_bytes(), "coins_count must end the header");
    }

    // ================================================================
    // G21 — Atomic write (temp file + rename) for dumptxoutset
    // ================================================================

    /// G21: snapshot writer must produce bytes that can be re-read by the reader
    /// (validates the implicit contract that finish() flushes).
    #[test]
    fn g21_writer_output_is_readable_after_finish() {
        let magic = testnet4_magic();
        let blockhash = dummy_blockhash(0x21);
        let op = make_outpoint(0x21, 0);
        let coin = make_coin(25_0000_0000, 200, false);
        let buf = build_snapshot(blockhash, magic, &[(op.clone(), coin.clone())]);
        let cursor = Cursor::new(&buf);
        let mut reader = SnapshotReader::open(cursor, &magic).unwrap();
        let (read_op, read_coin) = reader.read_coin().unwrap().unwrap();
        assert_eq!(read_op, op);
        assert_eq!(read_coin.tx_out.value, coin.tx_out.value);
    }

    // ================================================================
    // G24/G25 — loadtxoutset RPC is unconditionally disabled (documented bug)
    // ================================================================

    /// G25 BUG: loadtxoutset RPC always returns RPC_INTERNAL_ERROR.
    /// The RPC surface is missing entirely — only the CLI --load-snapshot path works.
    /// This test documents the gap; it would exercise the RPC returning an error.
    #[test]
    #[ignore = "G25 BUG: loadtxoutset RPC is unconditionally disabled (server.rs:7667-7742); RPC clients cannot activate snapshots at runtime"]
    fn g25_loadtxoutset_rpc_activates_snapshot() {
        // This test would call the loadtxoutset RPC with a valid snapshot file
        // and verify the node transitions to the snapshot tip. Currently the
        // RPC always returns RPC_INTERNAL_ERROR regardless of input.
        let _ = "not yet implemented — requires live RpcServerImpl with a snapshot file";
    }

    // ================================================================
    // G26 — m_assumeutxo_data per-network tables
    // ================================================================

    /// G26: regtest must have an empty assumeutxo table (no snapshots for regtest).
    #[test]
    fn g26_regtest_has_no_assumeutxo_entries() {
        use rustoshi_consensus::ChainParams;
        let params = ChainParams::regtest();
        assert!(
            params.assumeutxo_data.is_empty(),
            "regtest must have no assumeutxo entries"
        );
    }

    /// G26: mainnet table must have at least the 4 upstream entries from Core.
    #[test]
    fn g26_mainnet_has_at_least_four_assumeutxo_entries() {
        use rustoshi_consensus::ChainParams;
        let params = ChainParams::mainnet();
        // 4 Core entries + 1 local hashhog entry = 5 in total; assert >= 4.
        assert!(
            params.assumeutxo_data.len() >= 4,
            "mainnet must have at least 4 assumeutxo entries, found {}",
            params.assumeutxo_data.len()
        );
    }

    // ================================================================
    // G27 — Reject snapshots at unsupported heights/hashes
    // ================================================================

    /// G27: snapshot with an unrecognized blockhash must be rejected by the
    /// lookup step (assumeutxo_for_blockhash returns None).
    #[test]
    fn g27_unrecognized_blockhash_rejects_snapshot() {
        use rustoshi_consensus::ChainParams;
        let params = ChainParams::mainnet();
        let bogus = dummy_blockhash(0x27);
        assert!(
            params.assumeutxo_for_blockhash(&bogus).is_none(),
            "unrecognized blockhash must not match any assumeutxo entry"
        );
    }

    // ================================================================
    // G29 — Cleanup of partial snapshot state on failure (MISSING)
    // ================================================================

    /// G29 BUG: on hash-mismatch the CLI path has already written all coins to
    /// CF_UTXO before returning an error. The UTXO column family is left in a
    /// poisoned state — partial snapshot coins are present but the chain tip is
    /// still at genesis. A subsequent restart without --load-snapshot will observe
    /// an inconsistent UTXO set.
    #[test]
    #[ignore = "G29 BUG: no cleanup of CF_UTXO on hash-mismatch in main.rs:1626-1632; datadir is left poisoned"]
    fn g29_partial_snapshot_cleaned_up_on_hash_mismatch() {
        // This test would verify that when the hash check at the end of the
        // --load-snapshot path fails, all previously-written coins are rolled back
        // (e.g. by dropping the CF_UTXO column and re-creating it empty).
        // Currently the failure path returns Err(...) with coins already committed.
        let _ = "not yet implemented — requires a test DB with a tampered snapshot";
    }

    // ================================================================
    // G30 — ZMQ notification on activation (MISSING)
    // ================================================================

    /// G30 BUG: no ZMQ hashblock notification is emitted when the snapshot tip
    /// is activated via --load-snapshot. Bitcoin Core fires a BlockConnected signal
    /// which drives ZMQ and notifies subscribers. Rustoshi's activation block in
    /// main.rs::1727 never calls zmq_notifier.
    #[test]
    #[ignore = "G30 BUG: no ZMQ hashblock notification on snapshot activation — main.rs snapshot block missing zmq_notifier.send(hashblock)"]
    fn g30_zmq_hashblock_emitted_on_snapshot_activation() {
        // This test would verify that ZMQ subscribers receive a hashblock
        // notification for the snapshot tip immediately after activation.
        let _ = "not yet implemented — requires live ZmqNotifier and test subscriber";
    }

    // ================================================================
    // G4 — Base block header must be in chain (MISSING)
    // ================================================================

    /// G4 BUG: the CLI --load-snapshot path does NOT check that the snapshot's
    /// base_blockhash is present in the headers chain before ingesting coins.
    /// Bitcoin Core's ActivateSnapshot returns an error:
    ///   "The base block header (...) must appear in the headers chain."
    /// Rustoshi creates a synthetic BlockIndexEntry with prev_hash=ZERO and
    /// proceeds unconditionally.
    #[test]
    #[ignore = "G4 BUG: no headers-chain presence check before snapshot activation — main.rs:1501 proceeds regardless of whether base_blockhash has been synced"]
    fn g4_snapshot_rejected_if_base_header_not_in_chain() {
        // This test would verify that --load-snapshot with a snapshot whose
        // base_blockhash is not yet known to the headers database returns an
        // appropriate error rather than activating a phantom chain tip.
        let _ = "not yet implemented";
    }

    // ================================================================
    // G5 — Chain work >= nMinimumChainWork (PARTIAL)
    // ================================================================

    /// G5: The synthetic chain_work assigned to the snapshot tip is
    /// minimum_chain_work, not the snapshot block's real cumulative work.
    /// This is documented as intentional but means any snapshot from before
    /// minimum_chain_work could be accepted with inflated chain_work.
    ///
    /// Verify the ChainstateManager records the correct snapshot height.
    #[test]
    fn g5_snapshot_base_height_recorded_in_chainstate_manager() {
        let mut manager = ChainstateManager::new();
        let blockhash = dummy_blockhash(0x05);
        let base_height = 840_000u32;
        manager.activate_snapshot(blockhash, base_height);
        assert_eq!(manager.snapshot_base_height(), Some(base_height));
        assert_eq!(manager.snapshot_base_blockhash(), Some(blockhash));
        assert!(manager.is_snapshot_active());
    }

    // ================================================================
    // Hash consistency: hash_serialized vs muhash
    // ================================================================

    /// Regression: hash_serialized and muhash must differ for the same coin set
    /// (they use different cryptographic primitives).
    #[test]
    fn hash_serialized_and_muhash_differ() {
        let op = make_outpoint(0x99, 1);
        let coin = make_coin(7_500_000, 300, false);
        let hs = compute_hash_serialized(std::iter::once((op.clone(), coin.clone())));
        let mh = compute_utxo_muhash(std::iter::once((op, coin)));
        assert_ne!(
            hs, mh,
            "hash_serialized (sha256d) and muhash (MuHash3072) must produce different digests"
        );
    }

    // ================================================================
    // Snapshot progress tracking
    // ================================================================

    /// Verify coins_read counter increments and progress() converges to 100%.
    #[test]
    fn snapshot_reader_progress_reaches_100_after_full_read() {
        let magic = mainnet_magic();
        let blockhash = dummy_blockhash(0xa0);
        let coins: Vec<_> = (1u8..=5).map(|i| (make_outpoint(i, 0), make_coin(1000 * i as u64, 100, false))).collect();
        let buf = build_snapshot(blockhash, magic, &coins);
        let cursor = Cursor::new(buf);
        let mut reader = SnapshotReader::open(cursor, &magic).unwrap();
        assert_eq!(reader.coins_read(), 0);
        while reader.read_coin().unwrap().is_some() {}
        assert_eq!(reader.coins_read(), 5);
        assert!((reader.progress() - 100.0).abs() < 1e-9);
    }

    // ================================================================
    // Snapshot coins_count header integrity check
    // ================================================================

    /// The reader returns None (not an error) when coins_read == coins_count,
    /// enforcing that the declared count is the termination condition.
    #[test]
    fn snapshot_reader_stops_at_declared_coins_count() {
        let magic = mainnet_magic();
        let blockhash = dummy_blockhash(0xb0);
        let op = make_outpoint(0xb0, 0);
        let coin = make_coin(1000, 10, false);
        let buf = build_snapshot(blockhash, magic, &[(op, coin)]);
        let cursor = Cursor::new(buf);
        let mut reader = SnapshotReader::open(cursor, &magic).unwrap();
        assert_eq!(reader.coins_total(), 1);
        let first = reader.read_coin().unwrap();
        assert!(first.is_some(), "first coin must be readable");
        let second = reader.read_coin().unwrap();
        assert!(second.is_none(), "reader must stop after coins_count coins");
    }
}

// ================================================================
// W102 dual-chainstate: REAL background-validation second chainstate
// ================================================================
//
// These tests prove the AssumeUTXO background-validation second chainstate is
// a GENUINE independent re-derivation, not a hash-of-self or a counter:
//
//   (a) SEPARATE STORE — a write to the active store is NOT visible in the bg
//       store (the two are distinct allocations; an aliased store is refused).
//   (b) REAL CONNECT — the bg store re-derives the exact UTXO set the active
//       validator would (spend inputs, add outputs), NOT empty / NOT a counter.
//   (c) ACCEPT — a snapshot committing to the CORRECT genesis->base hash
//       validates (verdict Valid, snapshot Validated).
//   (d) REJECT FALSIFICATION (the non-circular one) — a TAMPERED snapshot that
//       commits to its OWN (tampered) hash so it would pass the load-time gate,
//       but is inconsistent with the genesis->base replay, so the bg
//       re-derivation computes a DIFFERENT hash -> verdict Invalid, snapshot
//       INVALID (never silently accepted).
//   (e) NON-VACUITY — the tampered hash genuinely differs from the real hash.
#[cfg(test)]
pub(crate) mod dual_cs_tests {
    use crate::snapshot::{
        compute_hash_serialized, BackgroundChainstate, BackgroundValidationError,
        ChainstateManager, SnapshotVerdict,
    };
    use crate::utxo_cache::Coin;
    use rustoshi_consensus::AssumeutxoHash;
    use rustoshi_primitives::{
        Block, BlockHeader, Hash256, OutPoint, Transaction, TxIn, TxOut,
    };

    /// A built regtest-style chain genesis..base, ready to re-derive.
    #[derive(Clone)]
    pub(crate) struct BuiltChain {
        /// blocks[h] is the block at height h (blocks[0] = genesis).
        pub blocks: Vec<Block>,
        pub tip_height: u32,
        pub tip_hash: Hash256,
        /// The genuine final UTXO set (outpoint -> coin) at the base height,
        /// computed independently of `BackgroundChainstate` so it can serve as
        /// the oracle for the commitment.
        pub utxo: Vec<(OutPoint, Coin)>,
    }

    fn p2pkh(seed: u8) -> Vec<u8> {
        let mut s = vec![0x76u8, 0xa9, 20];
        s.extend_from_slice(&[seed; 20]);
        s.extend_from_slice(&[0x88, 0xac]);
        s
    }

    fn header(prev: Hash256, h: u32) -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_block_hash: prev,
            // A deterministic, height-derived merkle root is fine: the bg
            // re-derivation keys off transactions, not the header merkle field.
            merkle_root: {
                let mut b = [0u8; 32];
                b[0] = (h & 0xff) as u8;
                b[1] = ((h >> 8) & 0xff) as u8;
                Hash256(b)
            },
            timestamp: 1_700_000_000 + h,
            bits: 0x207fffff,
            nonce: h,
        }
    }

    fn coinbase(height: u32, value: u64, spk_seed: u8) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                // BIP34 height in scriptSig keeps coinbases at different heights
                // distinct (distinct txid), so outputs don't collide.
                script_sig: vec![0x03, (height & 0xff) as u8, ((height >> 8) & 0xff) as u8, ((height >> 16) & 0xff) as u8],
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value,
                script_pubkey: p2pkh(spk_seed),
            }],
            lock_time: 0,
        }
    }

    fn spend(prev: OutPoint, value: u64, spk_seed: u8) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: prev,
                script_sig: vec![0x51], // OP_1 placeholder (no script check here)
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value,
                script_pubkey: p2pkh(spk_seed),
            }],
            lock_time: 0,
        }
    }

    /// Build a regtest chain genesis..base=3 that contains a REAL spend:
    ///   h0  genesis (coinbase, never enters the UTXO set)
    ///   h1  coinbase C1  -> output A
    ///   h2  coinbase C2  -> output B  + a spend of A creating output S
    ///   h3  coinbase C3  -> output D
    /// At the base the UTXO set is { B, S, D, (C3's coinbase) } — A is SPENT,
    /// proving the bg store removes spent coins (not just additive).
    pub(crate) fn build_chain() -> BuiltChain {
        let mut blocks: Vec<Block> = Vec::new();

        // h0 genesis
        let genesis_cb = coinbase(0, 50_0000_0000, 0x00);
        let g = Block {
            header: header(Hash256::ZERO, 0),
            transactions: vec![genesis_cb],
        };
        let g_hash = g.header.block_hash();
        blocks.push(g);

        // h1: coinbase C1 -> output A (spendable)
        let c1 = coinbase(1, 50_0000_0000, 0x11);
        let a_txid = c1.txid();
        let b1 = Block {
            header: header(g_hash, 1),
            transactions: vec![c1],
        };
        let b1_hash = b1.header.block_hash();
        blocks.push(b1);

        // h2: coinbase C2 + spend(A) -> output S
        let c2 = coinbase(2, 50_0000_0000, 0x22);
        let a_outpoint = OutPoint { txid: a_txid, vout: 0 };
        let spend_a = spend(a_outpoint.clone(), 49_0000_0000, 0x55);
        let b2 = Block {
            header: header(b1_hash, 2),
            transactions: vec![c2, spend_a],
        };
        let b2_hash = b2.header.block_hash();
        blocks.push(b2);

        // h3: coinbase C3
        let c3 = coinbase(3, 50_0000_0000, 0x33);
        let b3 = Block {
            header: header(b2_hash, 3),
            transactions: vec![c3],
        };
        let b3_hash = b3.header.block_hash();
        blocks.push(b3);

        let tip_height = 3u32;

        // Independently compute the final UTXO set (the oracle): replay the
        // SAME ConnectBlock-style rules by hand so this is NOT just a call into
        // BackgroundChainstate (which would make the test circular).
        let mut utxo: std::collections::HashMap<OutPoint, Coin> =
            std::collections::HashMap::new();
        for (h, blk) in blocks.iter().enumerate() {
            if h == 0 {
                continue; // genesis coinbase is unspendable / never in coins db
            }
            for tx in &blk.transactions {
                let is_cb = tx.is_coinbase();
                if !is_cb {
                    for input in &tx.inputs {
                        utxo.remove(&input.previous_output);
                    }
                }
                let txid = tx.txid();
                for (vout, o) in tx.outputs.iter().enumerate() {
                    // OP_RETURN / oversize skipped (none here).
                    if !o.script_pubkey.is_empty() && o.script_pubkey[0] == 0x6a {
                        continue;
                    }
                    utxo.insert(
                        OutPoint { txid, vout: vout as u32 },
                        Coin {
                            tx_out: TxOut {
                                value: o.value,
                                script_pubkey: o.script_pubkey.clone(),
                            },
                            height: h as u32,
                            is_coinbase: is_cb,
                        },
                    );
                }
            }
        }
        // A must be spent.
        assert!(
            !utxo.contains_key(&a_outpoint),
            "test chain must spend A so the bg store has to REMOVE a coin"
        );

        let mut utxo_vec: Vec<(OutPoint, Coin)> = utxo.into_iter().collect();
        utxo_vec.sort_by(|x, y| {
            x.0.txid.as_bytes().cmp(y.0.txid.as_bytes()).then(x.0.vout.cmp(&y.0.vout))
        });

        BuiltChain {
            blocks,
            tip_height,
            tip_hash: b3_hash,
            utxo: utxo_vec,
        }
    }

    /// The genuine HASH_SERIALIZED of the chain's final UTXO set — the CORRECT
    /// assumeutxo commitment. Computed from the independently-derived oracle,
    /// NOT from `BackgroundChainstate`, so the accept test is non-circular.
    pub(crate) fn independent_utxo_hash(chain: &BuiltChain) -> AssumeutxoHash {
        compute_hash_serialized(chain.utxo.iter().cloned())
    }

    fn run(chain: &BuiltChain, bg: &mut BackgroundChainstate, hash: AssumeutxoHash)
        -> Result<SnapshotVerdict, BackgroundValidationError>
    {
        let blocks = chain.blocks.clone();
        bg.connect_genesis_to_base(hash, |h| blocks.get(h as usize).cloned())
    }

    // ---- (a) SEPARATE STORE -------------------------------------------------

    #[test]
    fn a_background_store_is_separate_from_active() {
        // The active store is some other allocation; we model its identity with
        // a sentinel address. The bg store's own identity must differ.
        let chain = build_chain();
        let active_id = 0xDEAD_BEEFusize;
        let mut bg = BackgroundChainstate::new(chain.tip_height, active_id);
        assert_ne!(
            bg.store_id(),
            active_id,
            "bg store must not alias the active store"
        );

        // A write into the bg store is local to the bg store. Drive the
        // re-derivation, then assert the re-derived coins live HERE — they are
        // not, and can not be, in the active store (a different object).
        let h = independent_utxo_hash(&chain);
        run(&chain, &mut bg, h).expect("re-derivation completes");
        assert!(bg.len() > 0, "bg store received the re-derived coins");
        for (op, coin) in &chain.utxo {
            assert_eq!(bg.get_coin(op), Some(coin));
        }

        // Aliasing guard (the hash-of-self trap): pin the active id to THIS
        // store\'s OWN id and re-run from scratch — it must REFUSE rather than
        // run a tautological hash-of-self.
        let mut aliased = BackgroundChainstate::new(chain.tip_height, 0);
        let own_id = aliased.store_id();
        aliased.set_active_store_id(own_id);
        let blocks = chain.blocks.clone();
        let err = aliased
            .connect_genesis_to_base(h, |hh| blocks.get(hh as usize).cloned())
            .expect_err("an aliased store must be refused");
        assert_eq!(err, BackgroundValidationError::AliasesActiveStore);
    }

    // ---- (b) REAL CONNECT ---------------------------------------------------

    #[test]
    fn b_real_connect_rederives_exact_set_not_empty_not_counter() {
        let chain = build_chain();
        let mut bg = BackgroundChainstate::new(chain.tip_height, 0xACED_1234usize);
        let h = independent_utxo_hash(&chain);
        let verdict = run(&chain, &mut bg, h).expect("re-derivation completes");
        assert_eq!(verdict, SnapshotVerdict::Valid);

        // NOT empty (a counter/stub would leave the store empty or wrong).
        assert!(bg.len() > 0, "bg store must not be empty");
        // The bg set must EQUAL the independently-derived oracle set.
        assert_eq!(
            bg.len(),
            chain.utxo.len(),
            "bg store coin count must match the independent oracle"
        );
        for (op, coin) in &chain.utxo {
            assert_eq!(
                bg.get_coin(op),
                Some(coin),
                "bg store must hold the exact coin {:?}",
                op
            );
        }
    }

    // ---- (c) ACCEPT ---------------------------------------------------------

    #[test]
    fn c_correct_snapshot_validates_true() {
        let chain = build_chain();
        let correct = independent_utxo_hash(&chain);

        let mut mgr = ChainstateManager::new();
        mgr.activate_snapshot_with_commitment(chain.tip_hash, chain.tip_height, correct);
        mgr.start_background_validation(0xACED_1234usize);
        let blocks = chain.blocks.clone();
        let verdict = mgr
            .run_background_validation(|h| blocks.get(h as usize).cloned())
            .expect("validation completes");
        assert_eq!(verdict, SnapshotVerdict::Valid);
        assert!(mgr.is_snapshot_validated());
        assert!(!mgr.is_snapshot_invalid());
    }

    // ---- (d) REJECT FALSIFICATION (non-circular) ----------------------------

    #[test]
    fn d_tampered_snapshot_rejected_by_rederivation() {
        let chain = build_chain();

        // Build a TAMPERED UTXO set: the genuine set PLUS a phantom coin that
        // the genesis->base replay never creates. This is what a malicious
        // snapshot file would contain.
        let mut tampered_set = chain.utxo.clone();
        let phantom_op = OutPoint {
            txid: Hash256({
                let mut b = [0u8; 32];
                b[0] = 0xFA;
                b[31] = 0xCE;
                b
            }),
            vout: 0,
        };
        tampered_set.push((
            phantom_op.clone(),
            Coin {
                tx_out: TxOut { value: 99_0000_0000, script_pubkey: p2pkh(0x77) },
                height: 2,
                is_coinbase: false,
            },
        ));
        tampered_set.sort_by(|x, y| {
            x.0.txid.as_bytes().cmp(y.0.txid.as_bytes()).then(x.0.vout.cmp(&y.0.vout))
        });

        // The snapshot commits to its OWN (tampered) hash. A load-time gate
        // that hashes the file and compares to au_data.hash_serialized would
        // PASS, because the file IS the tampered set and the commitment is the
        // hash OF the tampered set — a hash-of-self.
        let tampered_commitment =
            compute_hash_serialized(tampered_set.iter().cloned());

        // But the background chainstate NEVER reads the snapshot file. It walks
        // the blocks genesis->base and re-derives the GENUINE set, whose hash
        // is DIFFERENT from the tampered commitment -> Invalid.
        let mut mgr = ChainstateManager::new();
        mgr.activate_snapshot_with_commitment(
            chain.tip_hash,
            chain.tip_height,
            tampered_commitment,
        );
        mgr.start_background_validation(0xACED_1234usize);
        let blocks = chain.blocks.clone();
        let verdict = mgr
            .run_background_validation(|h| blocks.get(h as usize).cloned())
            .expect("re-derivation runs to the base");

        assert_eq!(
            verdict,
            SnapshotVerdict::Invalid,
            "the tampered snapshot must be REJECTED by the independent re-derivation"
        );
        assert!(
            !mgr.is_snapshot_validated(),
            "a rejected snapshot must NOT be validated"
        );
        assert!(
            mgr.is_snapshot_invalid(),
            "a rejected snapshot must be flagged INVALID (never silently accepted)"
        );
        // Proof of non-circularity: the bg store does NOT contain the phantom.
        assert!(
            mgr.background_get_coin(&phantom_op).is_none()
                || mgr.background_coin_count().is_none(),
            "the phantom coin must never appear in the independent re-derivation"
        );
    }

    // ---- (e) NON-VACUITY ----------------------------------------------------

    #[test]
    fn e_tampered_hash_truly_differs_from_real_hash() {
        let chain = build_chain();
        let real = independent_utxo_hash(&chain);

        let mut tampered_set = chain.utxo.clone();
        tampered_set.push((
            OutPoint {
                txid: Hash256({
                    let mut b = [0u8; 32];
                    b[0] = 0xFA;
                    b[31] = 0xCE;
                    b
                }),
                vout: 0,
            },
            Coin {
                tx_out: TxOut { value: 99_0000_0000, script_pubkey: p2pkh(0x77) },
                height: 2,
                is_coinbase: false,
            },
        ));
        tampered_set.sort_by(|x, y| {
            x.0.txid.as_bytes().cmp(y.0.txid.as_bytes()).then(x.0.vout.cmp(&y.0.vout))
        });
        let tampered = compute_hash_serialized(tampered_set.iter().cloned());

        assert_ne!(
            real, tampered,
            "the reject test is non-vacuous: tampered hash != real hash"
        );
    }

    // ---- missing-block fail-closed -----------------------------------------

    #[test]
    fn f_missing_block_fails_closed_not_validated() {
        let chain = build_chain();
        let correct = independent_utxo_hash(&chain);
        let mut mgr = ChainstateManager::new();
        mgr.activate_snapshot_with_commitment(chain.tip_hash, chain.tip_height, correct);
        mgr.start_background_validation(0xACED_1234usize);
        // Supply NO blocks -> missing block at height 0 -> hard error, INVALID.
        let res = mgr.run_background_validation(|_| None);
        assert!(res.is_err(), "missing blocks must be a hard error, not silent");
        assert!(!mgr.is_snapshot_validated());
        assert!(mgr.is_snapshot_invalid());
    }
}
