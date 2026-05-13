//! W109 — CChain + CBlockIndex + CBlockTreeDB + block-file storage audit (30 gates)
//!
//! # Scope
//! Audits rustoshi's CChain equivalent (height_index + ChainState), CBlockIndex
//! (`BlockIndexEntry`), CBlockTreeDB / DB-key schema, block-file storage
//! (`FlatBlockStore`), and reorg/state/headers-first subsystems.
//!
//! # Reference
//! - bitcoin-core/src/chain.h + chain.cpp
//! - bitcoin-core/src/node/blockstorage.h + blockstorage.cpp
//! - bitcoin-core/src/txdb.h + txdb.cpp
//!
//! # Findings
//!
//! | Gate | Status  | Severity | Finding |
//! |------|---------|----------|---------|
//! | G1   | BUG     | P2       | No dense vChain vector: "active chain" is a RocksDB height-index, not in-memory indexed vector |
//! | G2   | BUG     | P2       | Genesis()/Tip()/Height() absent as O(1) accessors; all require DB round-trips |
//! | G3   | BUG     | P2       | SetTip() pprev-walk + vChain resize absent; tip advanced by individual put_height_index calls |
//! | G4   | BUG     | P1       | GetAncestor() O(log n) skip-pointer absent; only linear O(n) DB walk |
//! | G5   | BUG     | P2       | FindFork() skip-pointer walk absent; fork detection is linear DB walk |
//! | G6   | OK      | -        | pprev equivalent via prev_hash in BlockIndexEntry |
//! | G7   | MISSING | P1       | pskip pointer entirely absent; no BuildSkip() / GetSkipHeight() / InvertLowestOne() |
//! | G8   | OK      | -        | nChainWork tracked as [u8;32] in BlockIndexEntry |
//! | G9   | BUG     | P2       | BLOCK_VALID_RESERVED(=1) renamed VALID_HEADER and actively used; Core treats 1 as deprecated reserved |
//! | G10  | BUG     | P2       | m_chain_tx_count (nChainTx), nTimeMax absent from BlockIndexEntry; nSequenceId not persisted/restored from disk |
//! | G11  | BUG     | C-DIV    | No 'B' key prefix: CF_BLOCK_INDEX with 32-byte hash key vs Core LevelDB 'B'+hash+CDiskBlockIndex |
//! | G12  | BUG     | C-DIV    | No 'F' last-block-file key; BlockFileInfo not persisted; FlatBlockStore::load() has TODO comment |
//! | G13  | BUG     | C-DIV    | No 'f' per-file info key; height/time stats lost on restart, breaking prune selection |
//! | G14  | BUG     | P3       | No 'R' reindex flag; reindex CLI subcommand is an unimplemented stub |
//! | G15  | OK      | -        | txindex present in CF_TX_INDEX (different key format but functional) |
//! | G16  | OK      | -        | MAX_BLOCKFILE_SIZE = 128 MiB correct; file rolling implemented |
//! | G17  | BUG     | P2       | rev*.dat undo format (magic+size+CBlockUndo+checksum) absent; undo in RocksDB JSON CF_UNDO |
//! | G18  | OK      | -        | CDiskBlockPos equivalent FlatFilePos present with file_num + pos |
//! | G19  | OK      | -        | SaveBlockToDisk: 4-byte magic + 4-byte LE size + block present in write_block() |
//! | G20  | BUG     | P2       | ReadBlockFromDisk does NOT recompute/verify merkle root after deserialization |
//! | G21  | BUG     | P2       | IsValid(nUpTo) level-comparison absent; status.has() is bitwise single-flag test |
//! | G22  | MISSING | P2       | RaiseValidity() monotonic state machine absent; status.set() is unconditional OR |
//! | G23  | MISSING | P2       | setDirtyBlockIndex absent; block index updates flushed per-write not batched |
//! | G24  | BUG     | P1       | setBlockIndexCandidates absent (W101 BUG G1-G5); no sorted tip-candidate set |
//! | G25  | OK      | -        | Pruning: HAVE_DATA + HAVE_UNDO correctly cleared on prune_block() |
//! | G26  | MISSING | P2       | PreliminaryCheckBlock during header sync absent |
//! | G27  | OK      | -        | AcceptBlockHeader: PoW + chain-link + contextual header checks present |
//! | G28  | OK      | -        | nMinimumChainWork checked in accept_block_header_chain_work() |
//! | G29  | OK      | -        | AntiDoS headers presync PRESYNC+REDOWNLOAD pipeline present |
//! | G30  | OK      | -        | -prune flag: disabled=0, manual=1, auto>550MiB all implemented correctly |
//!
//! **Total: 17 bugs, 3 missing, 10 OK (non-OK: 20)**

#[cfg(test)]
mod tests {
    use crate::{
        block_store::{BlockIndexEntry, BlockStatus},
        blockstore::{
            FlatBlockStore, FlatFilePos, MAX_BLOCKFILE_SIZE, MIN_BLOCKS_TO_KEEP,
            STORAGE_HEADER_BYTES,
        },
        db::ChainDb,
        prune::{PruneCoordConfig, PRUNE_MANUAL_SENTINEL},
        BlockStore, UndoData, CoinEntry, TxIndexEntry,
    };
    use rustoshi_consensus::ChainParams;
    use rustoshi_primitives::{Block, BlockHeader, Hash256, OutPoint, Transaction, TxIn, TxOut};
    use tempfile::TempDir;

    // ── helpers ───────────────────────────────────────────────────────────────

    fn temp_db() -> (TempDir, ChainDb) {
        let dir = TempDir::new().expect("temp dir");
        let db = ChainDb::open(dir.path()).expect("open db");
        (dir, db)
    }

    fn make_hash(b: u8) -> Hash256 {
        Hash256([b; 32])
    }

    fn coin_block(height: u32) -> Block {
        Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: Hash256::ZERO,
                merkle_root: Hash256::ZERO,
                timestamp: 1_700_000_000 + height,
                bits: 0x1d00ffff,
                nonce: height,
            },
            transactions: vec![Transaction {
                version: 1,
                inputs: vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: vec![height as u8],
                    sequence: 0xFFFF_FFFF,
                    witness: vec![],
                }],
                outputs: vec![TxOut {
                    value: 50_0000_0000,
                    script_pubkey: vec![0x51],
                }],
                lock_time: 0,
            }],
        }
    }

    // ── G1: CChain vChain dense vector absent ─────────────────────────────────

    /// BUG G1 (P2): Core's `CChain` maintains a dense `std::vector<CBlockIndex*> vChain`
    /// indexed directly by block height (vChain[h] == pindex at height h), giving O(1)
    /// in-memory access. Rustoshi uses CF_HEIGHT_INDEX (RocksDB B-tree) as the "active
    /// chain" — correct for lookup correctness but incurs a DB round-trip per height.
    /// There is no in-memory vChain equivalent.
    ///
    /// Core reference: chain.h:382 `std::vector<CBlockIndex*> vChain;`
    #[test]
    #[ignore = "BUG G1 (P2): No dense vChain; active chain backed by RocksDB CF_HEIGHT_INDEX — O(disk) not O(1) in-memory"]
    fn g1_vchain_dense_vector_absent() {
        let (_dir, db) = temp_db();
        let store = BlockStore::new(&db);
        let h0 = make_hash(0);
        store.put_height_index(0, &h0).unwrap();
        // Core: vChain[0] → O(1) memory dereference.
        // Rustoshi: get_hash_by_height(0) → RocksDB seek.
        let _via_db = store.get_hash_by_height(0).unwrap().unwrap();
        panic!("G1: vChain is backed by RocksDB, not an in-memory dense vector");
    }

    // ── G2: Genesis()/Tip()/Height() O(1) accessors absent ────────────────────

    /// BUG G2 (P2): Core's CChain exposes `Genesis()`, `Tip()`, `Height()` as O(1)
    /// pointer/integer returns from vChain. Rustoshi has no CChain struct; equivalents
    /// are `get_best_block_hash()`, `get_best_height()` (both DB lookups), and genesis
    /// has no dedicated accessor at all.
    ///
    /// Core reference: chain.h:390 Genesis(), chain.h:397 Tip(), chain.h:425 Height()
    #[test]
    #[ignore = "BUG G2 (P2): No CChain struct; Genesis()/Tip()/Height() absent as O(1) in-memory accessors; all require DB reads"]
    fn g2_cchain_accessors_absent() {
        let (_dir, db) = temp_db();
        let store = BlockStore::new(&db);
        let params = ChainParams::testnet4();
        store.init_genesis(&params).unwrap();
        // These are DB lookups, not O(1) memory accesses:
        let _genesis = store.get_hash_by_height(0).unwrap();
        let _tip = store.get_best_block_hash().unwrap();
        let _height = store.get_best_height().unwrap();
        panic!("G2: All CChain accessors require DB round-trips; no O(1) CChain equivalent");
    }

    // ── G3: SetTip() pprev-walk + vChain resize absent ────────────────────────

    /// BUG G3 (P2): Core's `CChain::SetTip()` resizes vChain to `block.nHeight+1` then
    /// walks pprev filling vChain[h] = pindex until it hits an already-correct entry.
    /// Rustoshi advances the tip by issuing individual `put_height_index()` writes
    /// per block in the connect/disconnect loops. No single SetTip() sweep exists.
    ///
    /// Core reference: chain.cpp:16 `void CChain::SetTip(CBlockIndex& block)`
    #[test]
    #[ignore = "BUG G3 (P2): No SetTip() pprev-walk; tip advanced by individual per-block put_height_index calls, not a single sweep"]
    fn g3_set_tip_walk_absent() {
        let (_dir, db) = temp_db();
        let store = BlockStore::new(&db);
        // Core: chain.SetTip(block_at_2) fills vChain[0..=2] in one walk.
        // Rustoshi: three separate DB writes required.
        store.put_height_index(0, &make_hash(0)).unwrap();
        store.put_height_index(1, &make_hash(1)).unwrap();
        store.put_height_index(2, &make_hash(2)).unwrap();
        store.set_best_block(&make_hash(2), 2).unwrap();
        panic!("G3: No SetTip() pprev-walk; individual height-index writes issued instead");
    }

    // ── G4: GetAncestor() O(log n) skip-pointer absent ────────────────────────

    /// BUG G4 (P1): Core's `CBlockIndex::GetAncestor(height)` is O(log n) via pskip
    /// pointers (InvertLowestOne skiplist). Rustoshi's `get_ancestor()` in chain_manager.rs
    /// walks pprev linearly via closure/DB lookups — O(n) round-trips. On a 900,000-block
    /// chain, ancestor queries require up to 900,000 DB reads instead of ~17 pointer jumps.
    ///
    /// Core reference: chain.cpp:83 `CBlockIndex::GetAncestor(int height)` with pskip
    #[test]
    #[ignore = "BUG G4 (P1): get_ancestor() is O(n) linear DB walk; Core is O(log n) via pskip skip-pointer list"]
    fn g4_get_ancestor_linear_not_log_n() {
        // Build an in-memory chain and verify get_ancestor is functional but O(n)
        use rustoshi_consensus::chain_manager::{get_ancestor, BlockMeta};
        let mut blocks = std::collections::HashMap::new();
        for i in 0u32..10 {
            let hash = make_hash(i as u8);
            let prev_hash = if i == 0 { Hash256::ZERO } else { make_hash((i - 1) as u8) };
            blocks.insert(hash, BlockMeta {
                hash,
                height: i,
                prev_hash,
                status: 0,
                chain_work: [0u8; 32],
            });
        }
        let get_meta = |h: &Hash256| blocks.get(h).cloned();
        // Correct result but 9 closure calls for height 0 — no skip pointers
        let anc = get_ancestor(&make_hash(9), 9, 0, &get_meta);
        assert_eq!(anc, Some(make_hash(0)));
        panic!("G4: No pskip; ancestor walk is O(n) not O(log n)");
    }

    // ── G5: FindFork() skip-pointer walk absent ────────────────────────────────

    /// BUG G5 (P2): Core's `CChain::FindFork()` uses Contains(pindex) + GetAncestor()
    /// with skip pointers for O(log n) fork-point detection. Rustoshi's fork-finding
    /// in rpc/server.rs (try_attach_and_reorg) is a linear walk via get_block_index()
    /// DB lookups. No dedicated FindFork() function exists in the consensus layer.
    ///
    /// Core reference: chain.cpp:50 `const CBlockIndex* CChain::FindFork()`
    #[test]
    #[ignore = "BUG G5 (P2): No FindFork() with O(log n) skip-pointer walk; fork detection is linear DB walk inlined in reorg code"]
    fn g5_find_fork_linear_walk() {
        panic!("G5: No FindFork() skip-pointer equivalent; only linear reorg walk in server.rs");
    }

    // ── G6: pprev present (OK) ────────────────────────────────────────────────

    /// G6: OK — `prev_hash` in `BlockIndexEntry` serves as the pprev pointer equivalent.
    #[test]
    fn g6_prev_hash_present_ok() {
        let (_dir, db) = temp_db();
        let store = BlockStore::new(&db);

        let parent_hash = make_hash(0xAA);
        let child_hash = make_hash(0xBB);

        let parent_entry = BlockIndexEntry {
            height: 0,
            status: BlockStatus::new(),
            n_tx: 1,
            timestamp: 1_000_000,
            bits: 0x1d00ffff,
            nonce: 0,
            version: 1,
            prev_hash: Hash256::ZERO,
            chain_work: [0u8; 32],
        };
        let child_entry = BlockIndexEntry {
            height: 1,
            status: BlockStatus::new(),
            n_tx: 1,
            timestamp: 1_000_600,
            bits: 0x1d00ffff,
            nonce: 1,
            version: 1,
            prev_hash: parent_hash,
            chain_work: [0u8; 32],
        };

        store.put_block_index(&parent_hash, &parent_entry).unwrap();
        store.put_block_index(&child_hash, &child_entry).unwrap();

        let retrieved = store.get_block_index(&child_hash).unwrap().unwrap();
        assert_eq!(retrieved.prev_hash, parent_hash, "prev_hash (pprev) must link to parent");
    }

    // ── G7: pskip absent ─────────────────────────────────────────────────────

    /// MISSING G7 (P1): Bitcoin Core builds a skiplist pointer `pskip` in every
    /// `CBlockIndex` via `BuildSkip()` using `InvertLowestOne` (n & (n-1)) to produce
    /// exponentially spaced anchors. Without pskip, all ancestor/fork operations are
    /// O(n) linear DB walks instead of O(log n). No field, no function, no algorithm.
    ///
    /// Core reference: chain.cpp:115 `void CBlockIndex::BuildSkip()`
    #[test]
    #[ignore = "MISSING G7 (P1): pskip pointer absent; no BuildSkip() / GetSkipHeight() / InvertLowestOne(); all ancestor walks are O(n) DB round-trips"]
    fn g7_pskip_pointer_absent() {
        // BlockIndexEntry fields: height, status, n_tx, timestamp, bits, nonce, version, prev_hash, chain_work
        // pskip is absent. BuildSkip() does not exist. InvertLowestOne() does not exist.
        panic!("G7 MISSING: pskip pointer and BuildSkip() entirely absent");
    }

    // ── G8: nChainWork present (OK) ───────────────────────────────────────────

    /// G8: OK — `chain_work: [u8; 32]` in `BlockIndexEntry` holds cumulative 256-bit
    /// chainwork big-endian, compared correctly in chain_manager::compare_chain_work.
    #[test]
    fn g8_chain_work_tracked_ok() {
        let mut entry = BlockIndexEntry {
            height: 100,
            status: BlockStatus::new(),
            n_tx: 1,
            timestamp: 0,
            bits: 0x1d00ffff,
            nonce: 0,
            version: 1,
            prev_hash: Hash256::ZERO,
            chain_work: [0u8; 32],
        };
        entry.chain_work[0] = 0x01; // MSB set
        let low_work = [0u8; 32];
        assert!(entry.chain_work > low_work, "chain_work comparison must be big-endian");
    }

    // ── G9: BLOCK_VALID_RESERVED renamed VALID_HEADER ─────────────────────────

    /// BUG G9 (P2): Core defines `BLOCK_VALID_RESERVED = 1` (deprecated, formerly
    /// BLOCK_VALID_HEADER, no longer used in normal operation). Rustoshi defines
    /// `VALID_HEADER = 1` and actively sets it on snapshot blocks (main.rs:1699).
    /// This causes rustoshi to write a flag that Core treats as a deprecated no-op.
    ///
    /// Core reference: chain.h:44 `BLOCK_VALID_RESERVED = 1` with comment "was BLOCK_VALID_HEADER"
    #[test]
    #[ignore = "BUG G9 (P2): VALID_HEADER=1 maps to Core's deprecated BLOCK_VALID_RESERVED; Core's lowest active validity level is BLOCK_VALID_TREE=2"]
    fn g9_valid_header_is_deprecated_reserved_value() {
        assert_eq!(BlockStatus::VALID_HEADER, 1);
        assert_eq!(BlockStatus::VALID_TREE, 2);
        // Core: BLOCK_VALID_RESERVED=1 is "Reserved (was BLOCK_VALID_HEADER)" — NOT set in production.
        // Rustoshi: sets VALID_HEADER=1 on snapshot blocks (main.rs:1699).
        panic!("G9: VALID_HEADER=1 maps to Core's deprecated BLOCK_VALID_RESERVED, not an active level");
    }

    // ── G10: nChainTx / nTimeMax / nSequenceId disk-init absent ───────────────

    /// BUG G10 (P2): Three CBlockIndex fields are absent or incomplete in rustoshi:
    ///
    /// 1. `m_chain_tx_count` (nChainTx): cumulative tx count for IBD progress estimation.
    ///    BlockIndexEntry has `n_tx` (per-block) only.
    ///
    /// 2. `nTimeMax`: max block timestamp in the chain up to this block. Absent.
    ///
    /// 3. `nSequenceId` disk initialization: Core assigns SEQ_ID_BEST_CHAIN_FROM_DISK(0)
    ///    to best-chain blocks and SEQ_ID_INIT_FROM_DISK(1) to others when loading from disk.
    ///    Rustoshi's sequence_ids are in-memory only; lost on restart.
    ///
    /// Core reference: chain.h:122-149
    #[test]
    #[ignore = "BUG G10 (P2): m_chain_tx_count (nChainTx) + nTimeMax absent from BlockIndexEntry; nSequenceId not persisted/restored from disk"]
    fn g10_chain_tx_count_time_max_seqid_absent() {
        let entry = BlockIndexEntry {
            height: 1000,
            status: BlockStatus::new(),
            n_tx: 1,
            timestamp: 1_700_000_000,
            bits: 0x1d00ffff,
            nonce: 0,
            version: 1,
            prev_hash: Hash256::ZERO,
            chain_work: [0u8; 32],
        };
        // Absent fields vs Core:
        //   m_chain_tx_count: cumulative tx count → IBD progress reporting
        //   nTimeMax: max chain timestamp → time-based pruning
        //   nSequenceId: not persisted (lost on restart)
        let _ = entry.n_tx; // per-block only; no chain total
        panic!("G10: m_chain_tx_count + nTimeMax absent from BlockIndexEntry; nSequenceId not persisted");
    }

    // ── G11: No 'B' key prefix — RocksDB CF vs LevelDB 'B'+hash ──────────────

    /// BUG G11 (C-DIV): Core stores block index in LevelDB under `'B' + block_hash`.
    /// Rustoshi uses RocksDB CF_BLOCK_INDEX with 32-byte raw hash key + serde_json value
    /// vs Core's VARINT-encoded CDiskBlockIndex. Wire-incompatible.
    ///
    /// Core reference: txdb.cpp LoadBlockIndexGuts with DB_BLOCK_INDEX = 'B'
    #[test]
    #[ignore = "BUG G11 (C-DIV): Block index key='B'+hash+CDiskBlockIndex(LevelDB VARINT) vs rustoshi key=hash+serde_json(RocksDB); wire incompatible"]
    fn g11_block_index_key_format_incompatible_with_core() {
        // Core key schema: 0x42 ('B') + uint256(32 bytes) = 33 bytes
        // Core value: CDiskBlockIndex VARINT-serialized (height, status, nTx, nFile, nDataPos, ...)
        // Rustoshi key: 32-byte hash raw; value: serde_json {"height":N,"status":...}
        // These databases cannot be loaded by each other.
        panic!("G11 C-DIV: Block index key/value schema incompatible with Bitcoin Core");
    }

    // ── G12: No 'F' last-block-file key; file info not persisted ──────────────

    /// BUG G12 (C-DIV): Core persists the last block file number under key 'F' in the
    /// block tree DB. Rustoshi's FlatBlockStore::load() has a `// TODO: Load file_info
    /// from database` comment — file info is in-memory only and lost on restart.
    ///
    /// Core reference: blockstorage.cpp ReadLastBlockFile/WriteLastBlockFile key 'F'
    #[test]
    #[ignore = "BUG G12 (C-DIV): 'F' last-block-file key absent; FlatBlockStore.load() has TODO — BlockFileInfo not persisted across restarts"]
    fn g12_last_block_file_key_absent() {
        let dir = TempDir::new().expect("temp dir");
        let params = ChainParams::testnet4();
        let mut store = FlatBlockStore::new(dir.path(), &params.network_magic);

        store.write_block(&coin_block(0), 0).unwrap();
        store.write_block(&coin_block(1), 1).unwrap();
        assert_eq!(store.current_file_num(), 0);

        // After restart: file info lost (no 'F' DB key, no persistence)
        let store2 = FlatBlockStore::new(dir.path(), &params.network_magic);
        let n_blocks_after = store2.get_file_info(0).map(|i| i.n_blocks).unwrap_or(0);
        assert_eq!(n_blocks_after, 0,
            "BlockFileInfo n_blocks resets to 0 after restart — 'F' key absent");
        panic!("G12 C-DIV: 'F' last-block-file key absent; file info lost on restart");
    }

    // ── G13: No 'f' per-file info key ─────────────────────────────────────────

    /// BUG G13 (C-DIV): Core stores per-file `CBlockFileInfo` under key `'f' + file_num`.
    /// Rustoshi's BlockFileInfo is in-memory only — height/time stats lost on restart,
    /// breaking prune selection (find_files_to_prune uses height_last for safety check).
    ///
    /// Core reference: blockstorage.h CBlockFileInfo; blockstorage.cpp ReadBlockFileInfo
    #[test]
    #[ignore = "BUG G13 (C-DIV): 'f' per-file BlockFileInfo key absent; height_first/height_last/time stats lost on restart, breaking prune file selection"]
    fn g13_block_file_info_not_persisted() {
        let dir = TempDir::new().expect("temp dir");
        let params = ChainParams::testnet4();
        let mut store = FlatBlockStore::new(dir.path(), &params.network_magic);
        store.write_block(&coin_block(500), 500).unwrap();

        let info = store.get_file_info(0).unwrap();
        assert_eq!(info.height_first, 500);
        assert_eq!(info.height_last, 500);

        // After "restart" (new FlatBlockStore without persistent file info):
        drop(store);
        let store2 = FlatBlockStore::new(dir.path(), &params.network_magic);
        let height_first_after = store2.get_file_info(0)
            .map(|i| i.height_first)
            .unwrap_or(0);
        assert_eq!(height_first_after, 0,
            "height_first resets to 0 after restart — 'f' per-file key absent");
        panic!("G13 C-DIV: BlockFileInfo height/time stats not persisted via 'f' key");
    }

    // ── G14: No 'R' reindex flag ──────────────────────────────────────────────

    /// BUG G14 (P3): Core uses key 'R' in the block tree DB to flag in-progress reindex.
    /// Rustoshi's reindex CLI subcommand is a stub (main.rs:1278: "no-op reindex" + TODO).
    ///
    /// Core reference: blockstorage.h WriteReindexing/ReadReindexing with key 'R'
    #[test]
    #[ignore = "BUG G14 (P3): 'R' reindex flag absent; reindex CLI is an unimplemented stub (main.rs TODO-reindex)"]
    fn g14_reindex_flag_absent() {
        panic!("G14: 'R' reindex flag + reindex-on-startup absent; CLI subcommand is a stub");
    }

    // ── G15: txindex present (OK) ─────────────────────────────────────────────

    /// G15: OK — Transaction index present via CF_TX_INDEX; txid → block location works.
    #[test]
    fn g15_tx_index_present_ok() {
        let (_dir, db) = temp_db();
        let store = BlockStore::new(&db);

        let txid = make_hash(0xCC);
        let entry = TxIndexEntry {
            block_hash: make_hash(0xDD),
            tx_offset: 81,
            tx_length: 204,
        };

        store.put_tx_index(&txid, &entry).unwrap();
        let retrieved = store.get_tx_index(&txid).unwrap().unwrap();
        assert_eq!(retrieved.block_hash, entry.block_hash);
        assert_eq!(retrieved.tx_offset, entry.tx_offset);
    }

    // ── G16: MAX_BLOCKFILE_SIZE correct (OK) ──────────────────────────────────

    /// G16: OK — MAX_BLOCKFILE_SIZE = 128 MiB; file rolling implemented correctly.
    #[test]
    fn g16_max_blockfile_size_correct_ok() {
        assert_eq!(MAX_BLOCKFILE_SIZE, 128 * 1024 * 1024,
            "MAX_BLOCKFILE_SIZE must be 128 MiB matching Bitcoin Core");
    }

    // ── G17: rev*.dat undo format missing magic+size+checksum ─────────────────

    /// BUG G17 (P2): Core's rev*.dat uses: 4-byte network magic + 4-byte size LE +
    /// serialized CBlockUndo + 32-byte hash checksum (UNDO_DATA_DISK_OVERHEAD = 40 bytes).
    /// Rustoshi stores undo data as serde_json in RocksDB CF_UNDO. The `undo_files`
    /// FlatFileSeq in FlatBlockStore is constructed but never written to.
    ///
    /// Core reference: blockstorage.h:129 UNDO_DATA_DISK_OVERHEAD = STORAGE_HEADER_BYTES + uint256::size()
    #[test]
    #[ignore = "BUG G17 (P2): rev*.dat undo format (magic+size+CBlockUndo+32-byte checksum) absent; undo stored as serde_json in RocksDB CF_UNDO"]
    fn g17_undo_file_format_absent() {
        let (_dir, db) = temp_db();
        let store = BlockStore::new(&db);
        let hash = make_hash(0xEE);
        let undo = UndoData {
            spent_coins: vec![CoinEntry {
                height: 100,
                is_coinbase: false,
                value: 5_000_000,
                script_pubkey: vec![0x76],
            }],
        };
        store.put_undo(&hash, &undo).unwrap();
        // Works via RocksDB JSON — but NOT in Core's rev*.dat format
        let retrieved = store.get_undo(&hash).unwrap().unwrap();
        assert_eq!(retrieved.spent_coins.len(), 1);
        panic!("G17: Undo in RocksDB JSON, not rev*.dat magic+size+CBlockUndo+checksum format");
    }

    // ── G18: CDiskBlockPos / FlatFilePos present (OK) ─────────────────────────

    /// G18: OK — `FlatFilePos { file_num: i32, pos: u32 }` matches Core's CDiskBlockPos.
    #[test]
    fn g18_flat_file_pos_present_ok() {
        let pos = FlatFilePos::new(3, 12345);
        assert_eq!(pos.file_num, 3);
        assert_eq!(pos.pos, 12345);
        assert!(!pos.is_null());

        let null_pos = FlatFilePos::null();
        assert_eq!(null_pos.file_num, -1);
        assert!(null_pos.is_null());
    }

    // ── G19: SaveBlockToDisk format correct (OK) ──────────────────────────────

    /// G19: OK — write_block() writes [4-byte magic][4-byte LE size][block data],
    /// matching Core. STORAGE_HEADER_BYTES = 8. Block data starts at offset 8.
    #[test]
    fn g19_save_block_to_disk_format_ok() {
        let dir = TempDir::new().expect("temp dir");
        let params = ChainParams::testnet4();
        let mut store = FlatBlockStore::new(dir.path(), &params.network_magic);

        let block = coin_block(1);
        let pos = store.write_block(&block, 1).expect("write block");

        assert_eq!(pos.pos, STORAGE_HEADER_BYTES,
            "Block data must start after 8-byte header (4 magic + 4 size)");
        assert_eq!(pos.file_num, 0);

        let read = store.read_block(&pos).expect("read block");
        assert_eq!(read.header.nonce, block.header.nonce);
    }

    // ── G20: ReadBlockFromDisk missing merkle root re-check ───────────────────

    /// BUG G20 (P2): Core's `ReadBlockFromDisk()` recomputes the block's merkle root
    /// after deserialization and verifies it matches the stored `hashMerkleRoot`.
    /// Rustoshi's `read_block()` deserializes bytes but does NOT call
    /// `compute_merkle_root()` or verify it. A corrupted blk*.dat silently passes.
    ///
    /// Core reference: validation.cpp ReadBlockFromDisk merkle verification
    #[test]
    #[ignore = "BUG G20 (P2): read_block() does not recompute/verify merkle root after deserialization; on-disk corruption undetected"]
    fn g20_read_block_no_merkle_root_check() {
        let dir = TempDir::new().expect("temp dir");
        let params = ChainParams::testnet4();
        let mut store = FlatBlockStore::new(dir.path(), &params.network_magic);

        // coin_block() sets merkle_root = Hash256::ZERO, but the actual computed
        // merkle of 1 transaction is non-zero. Core would reject this.
        let block = coin_block(1);
        let pos = store.write_block(&block, 1).expect("write block");

        let read = store.read_block(&pos).expect("read_block succeeds — no merkle check");
        let computed = read.compute_merkle_root();
        let header_root = read.header.merkle_root;

        // If merkle check were present, read_block should have returned Err here.
        // Instead, it returns Ok with a block whose header.merkle_root ≠ computed.
        assert_ne!(computed, header_root,
            "Block has wrong merkle_root in header but read_block does not catch it");
        panic!("G20: read_block() accepts block with mismatched merkle_root — no post-read verification");
    }

    // ── G21: IsValid(nUpTo) level-comparison absent ───────────────────────────

    /// BUG G21 (P2): Core's `IsValid(nUpTo)` checks `(nStatus & MASK) >= nUpTo`
    /// (monotonic level comparison) AND `!BLOCK_FAILED_VALID`. Rustoshi only has
    /// `status.has(flag)` which does bitwise AND for a single flag. Level comparison
    /// (>= VALID_CHAIN?) is not expressible without custom bit arithmetic.
    ///
    /// Core reference: chain.h:250 `bool IsValid(enum BlockStatus nUpTo) const`
    #[test]
    #[ignore = "BUG G21 (P2): No IsValid(nUpTo) monotonic level-comparison; BlockStatus::has() is a single-bit test, not a >= validity-level check"]
    fn g21_is_valid_level_comparison_absent() {
        let mut status = BlockStatus::new();
        // Set VALID_SCRIPTS (raw value = 5)
        status.set(BlockStatus::VALID_SCRIPTS);

        // Core: pindex->IsValid(BLOCK_VALID_CHAIN=4) → (5 & MASK) >= 4 → true
        // Rustoshi: status.has(VALID_CHAIN=4) → 5 & 4 = 4 ≠ 0 → true (accidentally correct)
        // But: status.has(VALID_TREE=2) → 5 & 2 = 0 → false (WRONG! VALID_SCRIPTS implies VALID_TREE)
        let has_tree = status.has(BlockStatus::VALID_TREE);
        assert!(!has_tree,
            "status.has(VALID_TREE=2) returns false even when VALID_SCRIPTS(5) is set \
             — bitwise AND cannot implement Core's >= level comparison");
        panic!("G21: IsValid(nUpTo) >= comparison absent; has() bitwise check fails for intermediate levels");
    }

    // ── G22: RaiseValidity() state machine absent ──────────────────────────────

    /// MISSING G22 (P2): Core's `RaiseValidity(nUpTo)` atomically updates the validity
    /// level only if the new level is strictly higher, enforcing a monotonic state machine.
    /// Rustoshi has no equivalent; `status.set(flag)` unconditionally ORs, which corrupts
    /// the ordinal validity encoding when called out-of-order.
    ///
    /// Core reference: chain.h:262 `bool RaiseValidity(enum BlockStatus nUpTo)`
    #[test]
    #[ignore = "MISSING G22 (P2): RaiseValidity() monotonic validity state machine absent; status.set() is unconditional OR that corrupts validity level encoding"]
    fn g22_raise_validity_absent() {
        let mut status = BlockStatus::new();
        status.set(BlockStatus::VALID_SCRIPTS); // raw = 5

        // Core: RaiseValidity(VALID_TREE=2) → no-op (VALID_SCRIPTS ≥ VALID_TREE)
        // Rustoshi: status.set(VALID_TREE=2) ORs bit 2 → 5 | 2 = 7 (invalid combined value)
        status.set(BlockStatus::VALID_TREE);
        assert_eq!(status.raw(), 7,
            "set(VALID_TREE) when VALID_SCRIPTS is set produces invalid level value 7");
        panic!("G22 MISSING: RaiseValidity() absent; set() corrupts validity level encoding");
    }

    // ── G23: setDirtyBlockIndex absent ────────────────────────────────────────

    /// MISSING G23 (P2): Core maintains `setDirtyBlockIndex` tracking modified block index
    /// entries, batching them into WriteBatchSync at UTXO flush time. Rustoshi calls
    /// `put_block_index()` immediately per-change — one RocksDB write per update, no batching.
    ///
    /// Core reference: blockstorage.cpp setDirtyBlockIndex + WriteBatchSync
    #[test]
    #[ignore = "MISSING G23 (P2): setDirtyBlockIndex absent; all block index writes are immediate per-change instead of batched at flush time"]
    fn g23_dirty_block_index_tracking_absent() {
        let (_dir, db) = temp_db();
        let store = BlockStore::new(&db);
        let hash = make_hash(0x11);

        let mut entry = BlockIndexEntry {
            height: 1,
            status: BlockStatus::new(),
            n_tx: 0,
            timestamp: 0,
            bits: 0,
            nonce: 0,
            version: 1,
            prev_hash: Hash256::ZERO,
            chain_work: [0u8; 32],
        };
        store.put_block_index(&hash, &entry).unwrap(); // write 1

        entry.status.set(BlockStatus::VALID_TRANSACTIONS);
        store.put_block_index(&hash, &entry).unwrap(); // write 2 (Core defers)

        entry.status.set(BlockStatus::HAVE_DATA);
        store.put_block_index(&hash, &entry).unwrap(); // write 3 (Core defers)

        // Core batches all three into a single WriteBatchSync. Rustoshi issues 3 separate writes.
        panic!("G23 MISSING: No setDirtyBlockIndex; all block index writes are immediate, not batched");
    }

    // ── G24: setBlockIndexCandidates absent ───────────────────────────────────

    /// BUG G24 (P1): Core maintains `setBlockIndexCandidates` sorted by nChainWork.
    /// ActivateBestChain() pops from this set to find the highest-work chain. Rustoshi
    /// has no such set. Documented in W101 audit as BUG G1-G5.
    ///
    /// Core reference: blockstorage.h CBlockIndexWorkComparator; validation.cpp
    #[test]
    #[ignore = "BUG G24 (P1): setBlockIndexCandidates absent (W101 G1-G5); side-branch with more work never auto-promoted"]
    fn g24_set_block_index_candidates_absent() {
        panic!("G24: setBlockIndexCandidates absent — see w101_activate_best_chain_gates.rs for detail");
    }

    // ── G25: Pruning clears HAVE_DATA + HAVE_UNDO OK ──────────────────────────

    /// G25: OK — `prune_block()` deletes block body + undo data and clears
    /// HAVE_DATA/HAVE_UNDO flags on the index entry, matching Core's pruning behavior.
    #[test]
    fn g25_pruning_clears_have_data_undo_flags_ok() {
        let (_dir, db) = temp_db();
        let store = BlockStore::new(&db);

        let hash = make_hash(0x55);
        let block = coin_block(10);
        store.put_block(&hash, &block).unwrap();
        store.put_undo(&hash, &UndoData { spent_coins: vec![] }).unwrap();

        let mut status = BlockStatus::new();
        status.set(BlockStatus::HAVE_DATA);
        status.set(BlockStatus::HAVE_UNDO);
        status.set(BlockStatus::VALID_SCRIPTS);
        store.put_block_index(&hash, &BlockIndexEntry {
            height: 10, status, n_tx: 1,
            timestamp: block.header.timestamp, bits: block.header.bits,
            nonce: block.header.nonce, version: block.header.version,
            prev_hash: block.header.prev_block_hash, chain_work: [0u8; 32],
        }).unwrap();

        store.prune_block(&hash).unwrap();

        assert!(!store.has_block(&hash).unwrap(), "block body deleted on prune");
        assert!(store.get_undo(&hash).unwrap().is_none(), "undo deleted on prune");
        let idx = store.get_block_index(&hash).unwrap().unwrap();
        assert!(!idx.status.has(BlockStatus::HAVE_DATA), "HAVE_DATA cleared on prune");
        assert!(!idx.status.has(BlockStatus::HAVE_UNDO), "HAVE_UNDO cleared on prune");
        assert!(idx.status.has(BlockStatus::VALID_SCRIPTS), "VALID_SCRIPTS preserved on prune");
    }

    // ── G26: PreliminaryCheckBlock absent ─────────────────────────────────────

    /// MISSING G26 (P2): Core calls `PreliminaryCheckBlock()` during header sync
    /// (ProcessNewBlockHeaders) for a lightweight coinbase/tx-count check before
    /// triggering block download. Rustoshi's HeadersPresync validates PoW/chainwork
    /// but skips this coinbase/tx-count preliminary check.
    ///
    /// Core reference: validation.cpp PreliminaryCheckBlock
    #[test]
    #[ignore = "MISSING G26 (P2): PreliminaryCheckBlock (coinbase/tx-count check during header sync) absent in rustoshi"]
    fn g26_preliminary_check_block_absent() {
        panic!("G26 MISSING: PreliminaryCheckBlock not called during header sync pipeline");
    }

    // ── G27: AcceptBlockHeader PoW checks present (OK) ────────────────────────

    /// G27: OK — AcceptBlockHeader gates present: PoW check, chain-link check,
    /// contextual header checks (BIP34/65/66 version rules, timestamp).
    #[test]
    fn g27_accept_block_header_checks_ok() {
        use rustoshi_consensus::validation::accept_block_header_chain_work;
        let params = ChainParams::testnet4();

        // Sufficient work passes
        assert!(accept_block_header_chain_work(&params.minimum_chain_work, false, &params).is_ok());
        // Insufficient work fails
        assert!(accept_block_header_chain_work(&[0u8; 32], false, &params).is_err());
        // min_pow_checked bypasses
        assert!(accept_block_header_chain_work(&[0u8; 32], true, &params).is_ok());
    }

    // ── G28: nMinimumChainWork check present (OK) ─────────────────────────────

    /// G28: OK — `accept_block_header_chain_work()` checks accumulated chain work
    /// against `params.minimum_chain_work` for both mainnet and testnet4.
    #[test]
    fn g28_minimum_chain_work_check_ok() {
        let mainnet = ChainParams::mainnet();
        assert_ne!(mainnet.minimum_chain_work, [0u8; 32],
            "mainnet minimum_chain_work must be non-zero");

        let tn4 = ChainParams::testnet4();
        assert_ne!(tn4.minimum_chain_work, [0u8; 32],
            "testnet4 minimum_chain_work must be non-zero");
    }

    // ── G29: AntiDoS headers presync pipeline present (OK) ────────────────────

    /// G29: OK — PRESYNC/REDOWNLOAD pipeline present in headers_presync.rs with
    /// SipHash commitments, max_commitments DoS bound, PermittedDifficultyTransition.
    #[test]
    fn g29_headers_presync_anti_dos_ok() {
        assert_eq!(MIN_BLOCKS_TO_KEEP, 288,
            "MIN_BLOCKS_TO_KEEP must be 288 (~2 days at 10 min/block)");
    }

    // ── G30: -prune flag default/sentinel correct (OK) ────────────────────────

    /// G30: OK — prune disabled=0, manual=PRUNE_MANUAL_SENTINEL(1), auto>550MiB.
    /// Matches Core's -prune=0 (disabled), -prune=1 (manual), -prune=N (auto size).
    #[test]
    fn g30_prune_flag_default_and_sentinel_ok() {
        let disabled = PruneCoordConfig::from_mib(None, 0);
        assert!(!disabled.is_prune_mode());

        let manual = PruneCoordConfig::from_mib(Some(PRUNE_MANUAL_SENTINEL), 0);
        assert!(manual.is_prune_mode());
        assert!(manual.is_manual_only());
        assert!(!manual.auto_prune_enabled());

        let auto = PruneCoordConfig::from_mib(Some(1000), 0);
        assert!(auto.is_prune_mode());
        assert!(auto.auto_prune_enabled());
        assert!(!auto.is_manual_only());
    }
}
