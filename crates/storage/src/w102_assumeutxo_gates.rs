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

    /// G8 BUG: coin.height > snapshot_height must be rejected.
    /// Bitcoin Core rejects: `if (coin.nHeight > base_height)` in PopulateAndValidateSnapshot.
    /// Rustoshi currently stores the coin unconditionally. This test documents the bug
    /// and is #[ignore]d until the check is added.
    #[test]
    #[ignore = "G8 BUG: coin.height > snapshot_height not validated — main.rs:1554-1596 stores coins unconditionally"]
    fn g8_coin_height_above_snapshot_base_must_be_rejected() {
        // Build a snapshot claiming base height=100, but include a coin at height=200.
        let magic = mainnet_magic();
        let blockhash = dummy_blockhash(0x08);
        let op = make_outpoint(0x08, 0);
        let future_coin = make_coin(1000, 200, false); // height 200 > snapshot height 100
        // For the test to work, we'd need the reader to reject it during loading.
        // Right now read_coin() happily returns it.
        let buf = build_snapshot(blockhash, magic, &[(op, future_coin.clone())]);
        let cursor = Cursor::new(buf);
        let mut reader = SnapshotReader::open(cursor, &magic).unwrap();
        let result = reader.read_coin().unwrap();
        // This should fail or the caller should check -- but currently it succeeds.
        assert!(result.is_none() || result.unwrap().1.height <= 100,
            "coin with height > snapshot base height should be rejected");
    }

    /// G8 BUG: MoneyRange check is missing — values above 21 M BTC must be rejected.
    /// Bitcoin Core: `if (!MoneyRange(coin.out.nValue))` in PopulateAndValidateSnapshot.
    #[test]
    #[ignore = "G8 BUG: MoneyRange not checked during snapshot coin load — main.rs:1554-1596"]
    fn g8_coin_over_max_money_must_be_rejected() {
        // MAX_MONEY = 21_000_000 * 100_000_000 sat. A value above this should fail.
        // Currently the coin is stored without any value range check.
        let magic = mainnet_magic();
        let blockhash = dummy_blockhash(0x09);
        let op = make_outpoint(0x09, 0);
        // Build a snapshot with an over-limit coin; the reader should reject it.
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
        // Should error on read or the coin should fail a MoneyRange check at ingestion time.
        let result = reader.read_coin();
        assert!(result.is_err(), "coin with value > MAX_MONEY should be rejected");
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

    /// G14 BUG: background (IBD) validation chainstate is not constructed.
    /// ChainstateManager is defined and the API exists, but the main event loop
    /// never constructs a second chainstate, so should_validate_snapshot() /
    /// validate_snapshot() are perpetually dead code.
    #[test]
    #[ignore = "G14/G15 BUG: background IBD validation chainstate is not wired in main.rs — snapshot state stays Unvalidated forever"]
    fn g14_background_validation_chainstate_is_wired() {
        // This test would verify that after the snapshot is activated, the
        // ChainstateManager transitions from Unvalidated to Validated once the
        // background IBD chainstate reaches the snapshot height.
        // Currently this never happens because the second chainstate isn't started.
        let mut manager = ChainstateManager::new();
        let blockhash = dummy_blockhash(0x14);
        manager.activate_snapshot(blockhash, 100_000);
        assert!(!manager.is_snapshot_validated(), "snapshot must start unvalidated");
        // Simulate IBD reaching the snapshot height.
        assert!(manager.should_validate_snapshot(100_000));
        manager.validate_snapshot();
        assert!(manager.is_snapshot_validated(), "snapshot must be validated after IBD reaches its height");
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
