//! Rustoshi storage crate
//!
//! Persistent storage for blocks, transactions, and chain state using RocksDB.
//!
//! # Architecture
//!
//! The storage layer uses RocksDB with separate column families for different
//! data types:
//!
//! - **headers**: Block headers indexed by hash
//! - **blocks**: Full blocks indexed by hash
//! - **block_index**: Block metadata (height, status, chain work)
//! - **height_index**: Mapping from height to block hash (active chain)
//! - **utxo**: Unspent transaction outputs
//! - **tx_index**: Transaction location index
//! - **meta**: Chain metadata (best block, chain work, etc.)
//! - **undo**: Data needed to reverse blocks during reorganizations
//!
//! # Atomic Writes
//!
//! Use `ChainDb::write_batch()` to atomically apply multiple changes.
//! This ensures consistency when updating the UTXO set, block index,
//! and metadata together.
//!
//! # Example
//!
//! ```ignore
//! use rustoshi_storage::{ChainDb, BlockStore};
//! use std::path::Path;
//!
//! let db = ChainDb::open(Path::new("./data"))?;
//! let store = BlockStore::new(&db);
//!
//! // Initialize with genesis block
//! store.init_genesis(&params)?;
//!
//! // Get the current chain tip
//! if let Some(hash) = store.get_best_block_hash()? {
//!     let header = store.get_header(&hash)?;
//! }
//! ```

pub mod block_store;
pub mod blockstore;
pub mod columns;
pub mod db;
pub mod indexes;
pub mod prune;
pub mod snapshot;
pub mod undo;
pub mod utxo_cache;

pub use block_store::{BlockIndexEntry, BlockStatus, BlockStore, BlockStoreUtxoView, CoinEntry, TxIndexEntry, UndoData};
pub use blockstore::{
    BlockFileInfo, BlockFileLocation, FlatBlockStore, FlatFilePos, FlatFileSeq, PruneConfig,
    BLOCKFILE_CHUNK_SIZE, MAX_BLOCKFILE_SIZE, MIN_BLOCKS_TO_KEEP, MIN_DISK_SPACE_FOR_BLOCK_FILES,
    MIN_PRUNE_TARGET_MIB, STORAGE_HEADER_BYTES, UNDOFILE_CHUNK_SIZE,
};
pub use prune::{auto_prune, manual_prune_to_height, PruneCoordConfig, PruneOutcome, PRUNE_MANUAL_SENTINEL};
pub use undo::{BlockUndo, TxUndo};
pub use columns::*;
pub use db::{ChainDb, StorageError, CURRENT_DB_VERSION};
pub use indexes::{
    BlockFilter, BlockFilterError, BlockFilterIndex, BlockFilterType, CoinStatsEntry,
    CoinStatsError, CoinStatsIndex, FilterHeaderEntry, GCSError, GCSFilter, MuHash3072, Num3072,
    TxIndex, TxIndexError, TxLocation, BASIC_FILTER_M, BASIC_FILTER_P,
};
pub use utxo_cache::{
    CacheEntryFlags, Coin, CoinsCacheEntry, CoinsView, CoinsViewCache, CoinsViewDB,
    DEFAULT_DB_CACHE_BYTES,
};
pub use snapshot::{
    compute_hash_serialized, compute_utxo_hash, compute_utxo_muhash, find_snapshot_chainstate_dir,
    read_snapshot_blockhash, write_snapshot_blockhash, ChainstateManager, SnapshotActivation,
    SnapshotError, SnapshotMetadata, SnapshotReader, SnapshotState, SnapshotWriter,
    IBD_ACTIVE_CACHE_PERCENT, IBD_CACHE_PERCENT, SNAPSHOT_ACTIVE_CACHE_PERCENT,
    SNAPSHOT_BLOCKHASH_FILENAME, SNAPSHOT_CACHE_PERCENT, SNAPSHOT_CHAINSTATE_SUFFIX,
    SNAPSHOT_MAGIC_BYTES, SNAPSHOT_VERSION,
};

#[cfg(test)]
mod tests {
    use super::*;
    use rustoshi_consensus::ChainParams;
    use rustoshi_primitives::{Block, BlockHeader, Hash256, OutPoint, Transaction, TxIn, TxOut};
    use tempfile::TempDir;

    /// Create a temporary database for testing.
    fn temp_db() -> (TempDir, ChainDb) {
        let dir = TempDir::new().expect("failed to create temp dir");
        let db = ChainDb::open(dir.path()).expect("failed to open db");
        (dir, db)
    }

    #[test]
    fn test_open_database() {
        let (_dir, _db) = temp_db();
        // Database opened successfully
    }

    #[test]
    fn test_header_roundtrip() {
        let (_dir, db) = temp_db();
        let store = BlockStore::new(&db);

        let header = BlockHeader {
            version: 1,
            prev_block_hash: Hash256::ZERO,
            merkle_root: Hash256::from_hex(
                "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
            )
            .unwrap(),
            timestamp: 1231006505,
            bits: 0x1d00ffff,
            nonce: 2083236893,
        };

        let hash = header.block_hash();

        // Store and retrieve
        store.put_header(&hash, &header).unwrap();
        let retrieved = store.get_header(&hash).unwrap().unwrap();

        assert_eq!(header, retrieved);
        assert!(store.has_header(&hash).unwrap());
    }

    #[test]
    fn test_block_roundtrip() {
        let (_dir, db) = temp_db();
        let store = BlockStore::new(&db);

        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: Hash256::ZERO,
                merkle_root: Hash256::ZERO,
                timestamp: 1231006505,
                bits: 0x1d00ffff,
                nonce: 2083236893,
            },
            transactions: vec![Transaction {
                version: 1,
                inputs: vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: vec![0x04, 0xff, 0xff, 0x00, 0x1d],
                    sequence: 0xFFFFFFFF,
                    witness: Vec::new(),
                }],
                outputs: vec![TxOut {
                    value: 50_0000_0000,
                    script_pubkey: vec![0x41],
                }],
                lock_time: 0,
            }],
        };

        let hash = block.block_hash();

        // Store and retrieve
        store.put_block(&hash, &block).unwrap();
        let retrieved = store.get_block(&hash).unwrap().unwrap();

        assert_eq!(block, retrieved);
        assert!(store.has_block(&hash).unwrap());
    }

    #[test]
    fn test_best_block_metadata() {
        let (_dir, db) = temp_db();
        let store = BlockStore::new(&db);

        // Initially empty
        assert!(store.get_best_block_hash().unwrap().is_none());
        assert!(store.get_best_height().unwrap().is_none());

        let hash = Hash256::from_hex(
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        )
        .unwrap();

        store.set_best_block(&hash, 0).unwrap();

        assert_eq!(store.get_best_block_hash().unwrap().unwrap(), hash);
        assert_eq!(store.get_best_height().unwrap().unwrap(), 0);

        // Update to a new height
        let hash2 = Hash256::from_hex(
            "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
        )
        .unwrap();

        store.set_best_block(&hash2, 1).unwrap();

        assert_eq!(store.get_best_block_hash().unwrap().unwrap(), hash2);
        assert_eq!(store.get_best_height().unwrap().unwrap(), 1);
    }

    #[test]
    fn test_utxo_roundtrip() {
        let (_dir, db) = temp_db();
        let store = BlockStore::new(&db);

        let outpoint = OutPoint {
            txid: Hash256::from_hex(
                "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
            )
            .unwrap(),
            vout: 0,
        };

        let coin = CoinEntry {
            height: 0,
            is_coinbase: true,
            value: 50_0000_0000,
            script_pubkey: vec![0x41, 0x04, 0x67, 0x8a],
        };

        // Store and retrieve
        store.put_utxo(&outpoint, &coin).unwrap();
        let retrieved = store.get_utxo(&outpoint).unwrap().unwrap();

        assert_eq!(coin.height, retrieved.height);
        assert_eq!(coin.is_coinbase, retrieved.is_coinbase);
        assert_eq!(coin.value, retrieved.value);
        assert_eq!(coin.script_pubkey, retrieved.script_pubkey);
        assert!(store.has_utxo(&outpoint).unwrap());
    }

    #[test]
    fn test_utxo_delete() {
        let (_dir, db) = temp_db();
        let store = BlockStore::new(&db);

        let outpoint = OutPoint {
            txid: Hash256::from_hex(
                "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
            )
            .unwrap(),
            vout: 0,
        };

        let coin = CoinEntry {
            height: 0,
            is_coinbase: true,
            value: 50_0000_0000,
            script_pubkey: vec![0x41],
        };

        store.put_utxo(&outpoint, &coin).unwrap();
        assert!(store.has_utxo(&outpoint).unwrap());

        store.delete_utxo(&outpoint).unwrap();
        assert!(!store.has_utxo(&outpoint).unwrap());
        assert!(store.get_utxo(&outpoint).unwrap().is_none());
    }

    #[test]
    fn test_undo_data_roundtrip() {
        let (_dir, db) = temp_db();
        let store = BlockStore::new(&db);

        let hash = Hash256::from_hex(
            "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
        )
        .unwrap();

        let undo = UndoData {
            spent_coins: vec![
                CoinEntry {
                    height: 0,
                    is_coinbase: true,
                    value: 50_0000_0000,
                    script_pubkey: vec![0x41, 0x04],
                },
                CoinEntry {
                    height: 100,
                    is_coinbase: false,
                    value: 10_0000_0000,
                    script_pubkey: vec![0x76, 0xa9, 0x14],
                },
            ],
        };

        store.put_undo(&hash, &undo).unwrap();
        let retrieved = store.get_undo(&hash).unwrap().unwrap();

        assert_eq!(undo.spent_coins.len(), retrieved.spent_coins.len());
        for (a, b) in undo.spent_coins.iter().zip(retrieved.spent_coins.iter()) {
            assert_eq!(a.height, b.height);
            assert_eq!(a.is_coinbase, b.is_coinbase);
            assert_eq!(a.value, b.value);
            assert_eq!(a.script_pubkey, b.script_pubkey);
        }
    }

    #[test]
    fn test_height_index() {
        let (_dir, db) = temp_db();
        let store = BlockStore::new(&db);

        let hash0 = Hash256::from_hex(
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        )
        .unwrap();

        let hash1 = Hash256::from_hex(
            "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
        )
        .unwrap();

        store.put_height_index(0, &hash0).unwrap();
        store.put_height_index(1, &hash1).unwrap();

        assert_eq!(store.get_hash_by_height(0).unwrap().unwrap(), hash0);
        assert_eq!(store.get_hash_by_height(1).unwrap().unwrap(), hash1);
        assert!(store.get_hash_by_height(2).unwrap().is_none());

        // Test delete
        store.delete_height_index(1).unwrap();
        assert!(store.get_hash_by_height(1).unwrap().is_none());
    }

    #[test]
    fn test_block_index_entry() {
        let (_dir, db) = temp_db();
        let store = BlockStore::new(&db);

        let hash = Hash256::from_hex(
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        )
        .unwrap();

        let mut status = BlockStatus::new();
        status.set(BlockStatus::VALID_SCRIPTS);
        status.set(BlockStatus::HAVE_DATA);

        let entry = BlockIndexEntry {
            height: 0,
            status,
            n_tx: 1,
            timestamp: 1231006505,
            bits: 0x1d00ffff,
            nonce: 2083236893,
            version: 1,
            prev_hash: Hash256::ZERO,
            chain_work: [0u8; 32],
        };

        store.put_block_index(&hash, &entry).unwrap();
        let retrieved = store.get_block_index(&hash).unwrap().unwrap();

        assert_eq!(entry.height, retrieved.height);
        assert_eq!(entry.status, retrieved.status);
        assert_eq!(entry.n_tx, retrieved.n_tx);
        assert_eq!(entry.timestamp, retrieved.timestamp);
        assert_eq!(entry.bits, retrieved.bits);
        assert_eq!(entry.nonce, retrieved.nonce);
        assert_eq!(entry.version, retrieved.version);
        assert_eq!(entry.prev_hash, retrieved.prev_hash);
    }

    #[test]
    fn test_assumeutxo_tip_activation_persists_across_reload() {
        // Regression test for the 2026-05-03 mainnet snapshot wedge.
        //
        // Simulates the persistence pipeline that `--load-snapshot` needs
        // for foreground IBD past the snapshot tip to survive a restart:
        //   1. Genesis is initialized normally.
        //   2. The snapshot block is recorded via:
        //      - put_block_index
        //      - put_height_index
        //      - set_best_block
        //   3. We reopen the same datadir.
        //   4. Restart-time recovery reads the persisted "best block"
        //      pointer back as the snapshot tip — NOT genesis.
        //
        // Without this round-trip, a fresh `cargo build && start` after
        // `--load-snapshot` re-binds chain_state.tip = genesis on
        // restart, even though the UTXO set in RocksDB is at the
        // snapshot tip. That divergence is the wedge: foreground IBD
        // re-walks from height 1 forever.
        let dir = TempDir::new().expect("temp dir");
        let snapshot_hash = Hash256::from_hex(
            "0000000000000000000007e9c8b1c2c3d4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9",
        )
        .unwrap();
        let snapshot_height: u32 = 944_183;

        // Phase 1: write the snapshot tip.
        {
            let db = ChainDb::open(dir.path()).expect("open db");
            let store = BlockStore::new(&db);
            let params = ChainParams::mainnet();
            store.init_genesis(&params).unwrap();

            // Genesis is the tip immediately after init.
            assert_eq!(
                store.get_best_block_hash().unwrap().unwrap(),
                params.genesis_hash
            );
            assert_eq!(store.get_best_height().unwrap().unwrap(), 0);

            // Activate the snapshot tip.
            let mut status = BlockStatus::new();
            status.set(BlockStatus::VALID_HEADER);
            status.set(BlockStatus::VALID_SCRIPTS);
            status.set(BlockStatus::HAVE_DATA);
            let snap_entry = BlockIndexEntry {
                height: snapshot_height,
                status,
                n_tx: 0,
                timestamp: 0,
                bits: 0,
                nonce: 0,
                version: 0,
                prev_hash: Hash256::ZERO,
                chain_work: params.minimum_chain_work,
            };
            store.put_block_index(&snapshot_hash, &snap_entry).unwrap();
            store
                .put_height_index(snapshot_height, &snapshot_hash)
                .unwrap();
            store.set_best_block(&snapshot_hash, snapshot_height).unwrap();
        }

        // Phase 2: reopen the same datadir; verify the snapshot tip persisted.
        {
            let db = ChainDb::open(dir.path()).expect("reopen db");
            let store = BlockStore::new(&db);

            assert_eq!(
                store.get_best_block_hash().unwrap().unwrap(),
                snapshot_hash,
                "best block hash must persist as the snapshot tip across reopen"
            );
            assert_eq!(
                store.get_best_height().unwrap().unwrap(),
                snapshot_height,
                "best height must persist as the snapshot height across reopen"
            );
            assert_eq!(
                store
                    .get_hash_by_height(snapshot_height)
                    .unwrap()
                    .unwrap(),
                snapshot_hash,
                "height index must map snapshot height -> snapshot hash"
            );
            let idx = store.get_block_index(&snapshot_hash).unwrap().unwrap();
            assert_eq!(idx.height, snapshot_height);
            // chain_work must be at least minimum_chain_work so the IBD-exit
            // latch can flip when wall-clock + tip-recency conditions are met.
            assert_ne!(
                idx.chain_work, [0u8; 32],
                "snapshot block index entry must record a non-zero chain_work"
            );
        }
    }

    #[test]
    fn test_genesis_initialization() {
        let (_dir, db) = temp_db();
        let store = BlockStore::new(&db);
        let params = ChainParams::testnet4();

        // Initialize
        store.init_genesis(&params).unwrap();

        // Check that genesis is set as best block
        let best_hash = store.get_best_block_hash().unwrap().unwrap();
        assert_eq!(best_hash, params.genesis_hash);
        assert_eq!(store.get_best_height().unwrap().unwrap(), 0);

        // Check height index
        let hash_at_0 = store.get_hash_by_height(0).unwrap().unwrap();
        assert_eq!(hash_at_0, params.genesis_hash);

        // Check block index entry exists
        let index = store.get_block_index(&best_hash).unwrap().unwrap();
        assert_eq!(index.height, 0);
        assert!(index.status.has(BlockStatus::VALID_SCRIPTS));
        assert!(index.status.has(BlockStatus::HAVE_DATA));
    }

    #[test]
    fn test_genesis_initialization_idempotent() {
        let (_dir, db) = temp_db();
        let store = BlockStore::new(&db);
        let params = ChainParams::testnet4();

        // Initialize twice
        store.init_genesis(&params).unwrap();
        store.init_genesis(&params).unwrap();

        // Should still have genesis as best
        let best_hash = store.get_best_block_hash().unwrap().unwrap();
        assert_eq!(best_hash, params.genesis_hash);
    }

    #[test]
    fn test_reopen_database() {
        let dir = TempDir::new().expect("failed to create temp dir");
        let params = ChainParams::testnet4();

        {
            // Open and initialize
            let db = ChainDb::open(dir.path()).unwrap();
            let store = BlockStore::new(&db);
            store.init_genesis(&params).unwrap();
        }

        {
            // Reopen and verify data persisted
            let db = ChainDb::open(dir.path()).unwrap();
            let store = BlockStore::new(&db);

            let best_hash = store.get_best_block_hash().unwrap().unwrap();
            assert_eq!(best_hash, params.genesis_hash);

            let header = store.get_header(&best_hash).unwrap().unwrap();
            assert_eq!(header.timestamp, params.genesis_block.header.timestamp);
        }
    }

    #[test]
    fn test_block_status_flags() {
        let mut status = BlockStatus::new();
        assert!(!status.has(BlockStatus::VALID_HEADER));
        assert!(!status.has(BlockStatus::HAVE_DATA));

        status.set(BlockStatus::VALID_HEADER);
        assert!(status.has(BlockStatus::VALID_HEADER));
        assert!(!status.has(BlockStatus::HAVE_DATA));

        status.set(BlockStatus::HAVE_DATA);
        assert!(status.has(BlockStatus::VALID_HEADER));
        assert!(status.has(BlockStatus::HAVE_DATA));

        status.clear(BlockStatus::VALID_HEADER);
        assert!(!status.has(BlockStatus::VALID_HEADER));
        assert!(status.has(BlockStatus::HAVE_DATA));
    }

    #[test]
    fn test_tx_index() {
        let (_dir, db) = temp_db();
        let store = BlockStore::new(&db);

        let txid = Hash256::from_hex(
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
        )
        .unwrap();

        let entry = TxIndexEntry {
            block_hash: Hash256::from_hex(
                "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
            )
            .unwrap(),
            tx_offset: 81,
            tx_length: 204,
        };

        store.put_tx_index(&txid, &entry).unwrap();
        let retrieved = store.get_tx_index(&txid).unwrap().unwrap();

        assert_eq!(entry.block_hash, retrieved.block_hash);
        assert_eq!(entry.tx_offset, retrieved.tx_offset);
        assert_eq!(entry.tx_length, retrieved.tx_length);
    }

    /// Pattern C (txindex-revert-on-reorg): `delete_tx_index` removes a
    /// previously-written entry and is idempotent for missing keys.
    /// Mirrors `bitcoin-core/src/index/txindex.cpp::CustomRemove`.
    #[test]
    fn test_delete_tx_index() {
        let (_dir, db) = temp_db();
        let store = BlockStore::new(&db);

        let txid = Hash256::from_hex(
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
        )
        .unwrap();
        let entry = TxIndexEntry {
            block_hash: Hash256::from_hex(
                "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
            )
            .unwrap(),
            tx_offset: 81,
            tx_length: 204,
        };

        // Idempotent on a key that was never written.
        store.delete_tx_index(&txid).unwrap();
        assert!(store.get_tx_index(&txid).unwrap().is_none());

        // Round-trip: write, then delete, then verify the entry is gone.
        store.put_tx_index(&txid, &entry).unwrap();
        assert!(store.get_tx_index(&txid).unwrap().is_some());
        store.delete_tx_index(&txid).unwrap();
        assert!(
            store.get_tx_index(&txid).unwrap().is_none(),
            "delete_tx_index must remove the entry"
        );
    }

    // =========================
    // BlockUndo and TxUndo tests
    // =========================

    #[test]
    fn test_block_undo_storage_roundtrip() {
        use crate::undo::{BlockUndo, TxUndo};

        let (_dir, db) = temp_db();
        let store = BlockStore::new(&db);

        let hash = Hash256::from_hex(
            "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
        )
        .unwrap();

        // Create a BlockUndo with structured tx undos
        let mut block_undo = BlockUndo::new();

        // Transaction 1 spent 2 inputs
        let mut tx1_undo = TxUndo::new();
        tx1_undo.add_spent_coin(CoinEntry {
            height: 0,
            is_coinbase: true,
            value: 50_0000_0000,
            script_pubkey: vec![0x51], // OP_1
        });
        tx1_undo.add_spent_coin(CoinEntry {
            height: 50,
            is_coinbase: false,
            value: 10_0000_0000,
            script_pubkey: vec![0x76, 0xa9, 0x14], // P2PKH prefix
        });
        block_undo.add_tx_undo(tx1_undo);

        // Transaction 2 spent 1 input
        let mut tx2_undo = TxUndo::new();
        tx2_undo.add_spent_coin(CoinEntry {
            height: 100,
            is_coinbase: false,
            value: 5_0000_0000,
            script_pubkey: vec![0x00, 0x14], // P2WPKH prefix
        });
        block_undo.add_tx_undo(tx2_undo);

        // Convert to flat UndoData for storage
        let undo_data = UndoData {
            spent_coins: block_undo.to_flat(),
        };

        store.put_undo(&hash, &undo_data).unwrap();
        let retrieved = store.get_undo(&hash).unwrap().unwrap();

        assert_eq!(retrieved.spent_coins.len(), 3);
        assert_eq!(retrieved.spent_coins[0].height, 0);
        assert!(retrieved.spent_coins[0].is_coinbase);
        assert_eq!(retrieved.spent_coins[0].value, 50_0000_0000);
        assert_eq!(retrieved.spent_coins[1].height, 50);
        assert!(!retrieved.spent_coins[1].is_coinbase);
        assert_eq!(retrieved.spent_coins[2].height, 100);
    }

    #[test]
    fn test_block_undo_from_flat_conversion() {
        use crate::undo::BlockUndo;

        // Simulate what connect_block produces: flat list of spent coins
        let spent_coins = vec![
            CoinEntry {
                height: 100,
                is_coinbase: true,
                value: 50_0000_0000,
                script_pubkey: vec![0x51],
            },
            CoinEntry {
                height: 200,
                is_coinbase: false,
                value: 25_0000_0000,
                script_pubkey: vec![0x52],
            },
            CoinEntry {
                height: 300,
                is_coinbase: false,
                value: 12_5000_0000,
                script_pubkey: vec![0x53],
            },
        ];

        // First tx (non-coinbase) had 2 inputs, second had 1 input
        let input_counts = vec![2, 1];

        let block_undo = BlockUndo::from_flat(&spent_coins, &input_counts);

        // Verify structure
        assert_eq!(block_undo.len(), 2);
        assert_eq!(block_undo.tx_undo[0].len(), 2);
        assert_eq!(block_undo.tx_undo[1].len(), 1);

        // Verify roundtrip
        let flat_again = block_undo.to_flat();
        assert_eq!(flat_again.len(), 3);
        assert_eq!(flat_again[0].height, 100);
        assert_eq!(flat_again[1].height, 200);
        assert_eq!(flat_again[2].height, 300);
    }

    #[test]
    fn test_undo_delete() {
        let (_dir, db) = temp_db();
        let store = BlockStore::new(&db);

        let hash = Hash256::from_hex(
            "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
        )
        .unwrap();

        let undo = UndoData {
            spent_coins: vec![CoinEntry {
                height: 100,
                is_coinbase: false,
                value: 1_0000_0000,
                script_pubkey: vec![0x51],
            }],
        };

        store.put_undo(&hash, &undo).unwrap();
        assert!(store.get_undo(&hash).unwrap().is_some());

        store.delete_undo(&hash).unwrap();
        assert!(store.get_undo(&hash).unwrap().is_none());
    }

    #[test]
    fn test_undo_with_have_undo_flag() {
        let (_dir, db) = temp_db();
        let store = BlockStore::new(&db);

        let hash = Hash256::from_hex(
            "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
        )
        .unwrap();

        // Create block index entry without HAVE_UNDO flag
        let mut status = BlockStatus::new();
        status.set(BlockStatus::HAVE_DATA);
        status.set(BlockStatus::VALID_SCRIPTS);

        let entry = BlockIndexEntry {
            height: 1,
            status,
            n_tx: 2,
            timestamp: 1231469665,
            bits: 0x1d00ffff,
            nonce: 2573394689,
            version: 1,
            prev_hash: Hash256::ZERO,
            chain_work: [0u8; 32],
        };

        store.put_block_index(&hash, &entry).unwrap();

        // Verify HAVE_UNDO is not set
        let retrieved = store.get_block_index(&hash).unwrap().unwrap();
        assert!(!retrieved.status.has(BlockStatus::HAVE_UNDO));

        // Store undo data
        let undo = UndoData {
            spent_coins: vec![CoinEntry {
                height: 0,
                is_coinbase: true,
                value: 50_0000_0000,
                script_pubkey: vec![0x51],
            }],
        };
        store.put_undo(&hash, &undo).unwrap();

        // Update block index with HAVE_UNDO flag
        let mut updated_entry = retrieved;
        updated_entry.status.set(BlockStatus::HAVE_UNDO);
        store.put_block_index(&hash, &updated_entry).unwrap();

        // Verify HAVE_UNDO is now set
        let final_entry = store.get_block_index(&hash).unwrap().unwrap();
        assert!(final_entry.status.has(BlockStatus::HAVE_UNDO));
        assert!(final_entry.status.has(BlockStatus::HAVE_DATA));
        assert!(final_entry.status.has(BlockStatus::VALID_SCRIPTS));
    }

    // =====================================================================
    // Pattern D (post-reorg-consistency) — atomic disconnect/reorg batch
    // =====================================================================
    //
    // Verifies that the building blocks the disconnect/reorg paths use to
    // commit "UTXO mutations + tx-index deletes + height-index updates +
    // best-block tip pointer" land as a single RocksDB write — all-or-
    // nothing — matching `bitcoin-core/src/validation.cpp::DisconnectTip`'s
    // `CDBBatch` semantics.
    //
    // Today's static audit
    // (CORE-PARITY-AUDIT/_post-reorg-consistency-fleet-result-2026-05-05.md)
    // found that pre-fix rustoshi ran `utxo_view.flush()` and the
    // height-index/tip writes in two separate RocksDB calls; a crash
    // between them left the height index pointing at disconnected blocks
    // while the UTXO set was already pre-disconnect. The fix merges them
    // into a single WriteBatch via `BlockStoreUtxoView::flush_into_batch`
    // + `BlockStore::batch_*` helpers + `ChainDb::write_batch`.

    /// `flush_into_batch` MUST not touch RocksDB — observable state only
    /// changes when the caller commits the batch. Inversely, before the
    /// commit, the cache MUST be drained (so a second commit attempt can
    /// not double-write).
    #[test]
    fn test_flush_into_batch_defers_disk_writes_until_commit() {
        use rustoshi_consensus::validation::UtxoView;

        let (_dir, db) = temp_db();
        let store = BlockStore::new(&db);

        let outpoint = OutPoint {
            txid: Hash256::from_hex(
                "1111111111111111111111111111111111111111111111111111111111111111",
            )
            .unwrap(),
            vout: 7,
        };
        let coin = rustoshi_consensus::validation::CoinEntry {
            height: 42,
            is_coinbase: false,
            value: 12345,
            script_pubkey: vec![0x51],
        };

        let mut view = store.utxo_view();
        view.add_utxo(&outpoint, coin.clone());

        // Before flush_into_batch + commit, the UTXO is NOT in RocksDB.
        assert!(
            store.get_utxo(&outpoint).unwrap().is_none(),
            "cache hit must not be visible to fresh DB readers"
        );

        // Stage into a batch — still no disk write.
        let mut batch = store.new_batch();
        view.flush_into_batch(&mut batch).unwrap();
        assert!(
            store.get_utxo(&outpoint).unwrap().is_none(),
            "flush_into_batch alone must not commit anything to disk"
        );
        // Cache has been drained.
        assert_eq!(view.cache_len(), 0);

        // Commit the batch — now the UTXO is visible.
        store.write_batch(batch).unwrap();
        let on_disk = store.get_utxo(&outpoint).unwrap().unwrap();
        assert_eq!(on_disk.value, 12345);
    }

    /// Atomicity contract: the disconnect path's full set of writes
    /// (UTXO mutations + tx-index deletes + height-index deletes + new
    /// tip pointer) staged via `flush_into_batch` + `batch_*` helpers
    /// must all become visible after a single `write_batch`, and none
    /// must be visible before. This is the cross-CF guarantee that
    /// makes a Pattern D crash safe.
    #[test]
    fn test_atomic_disconnect_batch_all_or_nothing() {
        use rustoshi_consensus::validation::UtxoView;

        let (_dir, db) = temp_db();
        let store = BlockStore::new(&db);

        // Pre-disconnect ground truth on disk:
        //   * UTXO at outpoint_kept exists (will survive)
        //   * UTXO at outpoint_spent exists (will be re-spent ... no, in a
        //     real disconnect we'd RE-CREATE a spent UTXO; but for the
        //     batch-atomicity contract we only care that the cross-CF
        //     ops staged below all flip together)
        //   * Height index has h=10 -> hash_old (pre-disconnect tip)
        //   * Best block points at hash_old / h=10
        //   * Tx-index has an entry that the disconnect will revoke.
        let hash_old = Hash256::from_hex(
            "00000000000000000000000000000000000000000000000000000000000000aa",
        )
        .unwrap();
        let hash_new = Hash256::from_hex(
            "00000000000000000000000000000000000000000000000000000000000000bb",
        )
        .unwrap();
        let outpoint_create = OutPoint {
            txid: Hash256::from_hex(
                "2222222222222222222222222222222222222222222222222222222222222222",
            )
            .unwrap(),
            vout: 0,
        };
        let outpoint_remove = OutPoint {
            txid: Hash256::from_hex(
                "3333333333333333333333333333333333333333333333333333333333333333",
            )
            .unwrap(),
            vout: 0,
        };
        let txid_evicted = Hash256::from_hex(
            "4444444444444444444444444444444444444444444444444444444444444444",
        )
        .unwrap();

        // Initialize pre-disconnect state directly (no batch, just the
        // pre-existing per-key APIs — this is the "before crash" snapshot).
        let pre_existing = CoinEntry {
            height: 5,
            is_coinbase: false,
            value: 999,
            script_pubkey: vec![0x76],
        };
        store.put_utxo(&outpoint_remove, &pre_existing).unwrap();
        store.put_height_index(10, &hash_old).unwrap();
        store.set_best_block(&hash_old, 10).unwrap();
        store
            .put_tx_index(
                &txid_evicted,
                &TxIndexEntry {
                    block_hash: hash_old,
                    tx_offset: 0,
                    tx_length: 0,
                },
            )
            .unwrap();

        // Now build the disconnect batch the same way `disconnect_to`
        // does: UTXO add (re-create the disconnected coin) + UTXO spend
        // (delete a coin that the disconnected block had created) +
        // tx-index delete + height-index delete + best-block flip.
        let mut view = store.utxo_view();
        view.add_utxo(
            &outpoint_create,
            rustoshi_consensus::validation::CoinEntry {
                height: 9,
                is_coinbase: false,
                value: 5_0000_0000,
                script_pubkey: vec![0x51],
            },
        );
        view.spend_utxo(&outpoint_remove);

        let mut batch = store.new_batch();
        store
            .batch_delete_tx_index(&mut batch, &txid_evicted)
            .unwrap();
        view.flush_into_batch(&mut batch).unwrap();
        store
            .batch_set_best_block(&mut batch, &hash_new, 9)
            .unwrap();
        store.batch_delete_height_index(&mut batch, 10).unwrap();

        // Atomicity contract: NOTHING is visible yet.
        assert_eq!(
            store.get_best_block_hash().unwrap().unwrap(),
            hash_old,
            "tip must not flip before write_batch"
        );
        assert_eq!(store.get_best_height().unwrap().unwrap(), 10);
        assert!(
            store.get_utxo(&outpoint_create).unwrap().is_none(),
            "added coin must not be visible before write_batch"
        );
        assert!(
            store.get_utxo(&outpoint_remove).unwrap().is_some(),
            "spent coin must still exist before write_batch"
        );
        assert_eq!(
            store
                .get_hash_by_height(10)
                .unwrap()
                .expect("pre-batch height-10 entry should still exist"),
            hash_old,
        );
        assert!(
            store.get_tx_index(&txid_evicted).unwrap().is_some(),
            "tx-index entry must survive until write_batch"
        );

        // Commit. After this, EVERYTHING flips together.
        store.write_batch(batch).unwrap();

        assert_eq!(store.get_best_block_hash().unwrap().unwrap(), hash_new);
        assert_eq!(store.get_best_height().unwrap().unwrap(), 9);
        assert_eq!(
            store.get_utxo(&outpoint_create).unwrap().unwrap().value,
            5_0000_0000,
            "added coin must be visible after write_batch"
        );
        assert!(
            store.get_utxo(&outpoint_remove).unwrap().is_none(),
            "spent coin must be deleted after write_batch"
        );
        assert!(
            store.get_hash_by_height(10).unwrap().is_none(),
            "height-index entry must be deleted after write_batch"
        );
        assert!(
            store.get_tx_index(&txid_evicted).unwrap().is_none(),
            "tx-index entry must be deleted after write_batch"
        );
    }

    /// Symmetric test for the reorg arm: UTXO mutations + height-index
    /// puts (new branch) + height-index deletes (old suffix) + best-block
    /// pointer all flip in a single batch.
    #[test]
    fn test_atomic_reorg_batch_all_or_nothing() {
        use rustoshi_consensus::validation::UtxoView;

        let (_dir, db) = temp_db();
        let store = BlockStore::new(&db);

        let hash_old = Hash256::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000011",
        )
        .unwrap();
        let hash_new_a = Hash256::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000022",
        )
        .unwrap();
        let hash_new_b = Hash256::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000033",
        )
        .unwrap();

        // Old chain: tip at h=8 / hash_old, with stale entries at h=7..=8.
        store
            .put_height_index(
                7,
                &Hash256::from_hex(
                    "0000000000000000000000000000000000000000000000000000000000000077",
                )
                .unwrap(),
            )
            .unwrap();
        store.put_height_index(8, &hash_old).unwrap();
        store.set_best_block(&hash_old, 8).unwrap();

        let outpoint = OutPoint {
            txid: Hash256::from_hex(
                "5555555555555555555555555555555555555555555555555555555555555555",
            )
            .unwrap(),
            vout: 1,
        };

        // Reorg target: new tip at h=9 / hash_new_b, parent hash_new_a at h=8.
        let mut view = store.utxo_view();
        view.add_utxo(
            &outpoint,
            rustoshi_consensus::validation::CoinEntry {
                height: 9,
                is_coinbase: false,
                value: 7_0000_0000,
                script_pubkey: vec![0x52],
            },
        );

        let mut batch = store.new_batch();
        view.flush_into_batch(&mut batch).unwrap();
        store
            .batch_put_height_index(&mut batch, 8, &hash_new_a)
            .unwrap();
        store
            .batch_put_height_index(&mut batch, 9, &hash_new_b)
            .unwrap();
        store
            .batch_set_best_block(&mut batch, &hash_new_b, 9)
            .unwrap();

        // Pre-commit: nothing has changed.
        assert_eq!(store.get_best_block_hash().unwrap().unwrap(), hash_old);
        assert_eq!(store.get_hash_by_height(8).unwrap().unwrap(), hash_old);
        assert!(store.get_utxo(&outpoint).unwrap().is_none());

        store.write_batch(batch).unwrap();

        // Post-commit: everything has flipped together.
        assert_eq!(store.get_best_block_hash().unwrap().unwrap(), hash_new_b);
        assert_eq!(store.get_best_height().unwrap().unwrap(), 9);
        assert_eq!(store.get_hash_by_height(8).unwrap().unwrap(), hash_new_a);
        assert_eq!(store.get_hash_by_height(9).unwrap().unwrap(), hash_new_b);
        assert_eq!(
            store.get_utxo(&outpoint).unwrap().unwrap().value,
            7_0000_0000,
        );
    }

    /// `flush()` (the convenience wrapper) MUST still write everything
    /// in one batch. Regression guard: keep the wrapper API working
    /// after refactoring `flush()` to delegate to `flush_into_batch`.
    #[test]
    fn test_flush_wrapper_still_commits() {
        use rustoshi_consensus::validation::UtxoView;

        let (_dir, db) = temp_db();
        let store = BlockStore::new(&db);

        let outpoint = OutPoint {
            txid: Hash256::from_hex(
                "6666666666666666666666666666666666666666666666666666666666666666",
            )
            .unwrap(),
            vout: 2,
        };

        let mut view = store.utxo_view();
        view.add_utxo(
            &outpoint,
            rustoshi_consensus::validation::CoinEntry {
                height: 1,
                is_coinbase: true,
                value: 50_0000_0000,
                script_pubkey: vec![0x21],
            },
        );
        view.flush().unwrap();

        let on_disk = store.get_utxo(&outpoint).unwrap().unwrap();
        assert_eq!(on_disk.value, 50_0000_0000);
    }

    // ============================================================
    // PRUNE TESTS (RocksDB-backed prune subsystem)
    // ============================================================
    //
    // Validate the dormant prune subsystem is now wired correctly:
    //   - `prune_block` drops body + undo + clears HAVE_DATA/HAVE_UNDO
    //   - `prune_active_chain_range` walks height-index correctly
    //   - watermark advances monotonically
    //   - `auto_prune` respects MIN_BLOCKS_TO_KEEP=288 + assumeutxo floor
    //   - `manual_prune_to_height` respects same invariants
    //   - `-prune=1` manual-only mode disables auto-prune
    //
    // Reference: `bitcoin-core/src/validation.cpp::FindFilesToPrune`,
    // `::PruneBlockFilesManual`, `::UnlinkPrunedFiles`.

    /// Build a synthetic chain of `n` blocks below an arbitrary tip,
    /// each with valid `BlockIndexEntry` + body + height-index entry.
    /// Heights are 1..=n (genesis at 0 is initialized via params).
    fn build_synth_chain(store: &BlockStore<'_>, n: u32) {
        for h in 1..=n {
            let header = BlockHeader {
                version: 1,
                prev_block_hash: Hash256::ZERO,
                merkle_root: Hash256::ZERO,
                timestamp: 1_700_000_000 + h,
                bits: 0x1d00ffff,
                nonce: h,
            };
            // Make the hash deterministic from height so we don't have
            // to actually hash the block.
            let mut hash_bytes = [0u8; 32];
            hash_bytes[0..4].copy_from_slice(&h.to_be_bytes());
            let hash = Hash256(hash_bytes);

            let block = Block {
                header: header.clone(),
                transactions: vec![Transaction {
                    version: 1,
                    inputs: vec![TxIn {
                        previous_output: OutPoint::null(),
                        script_sig: vec![h as u8],
                        sequence: 0xFFFFFFFF,
                        witness: Vec::new(),
                    }],
                    outputs: vec![TxOut {
                        value: 50_0000_0000,
                        script_pubkey: vec![0x51],
                    }],
                    lock_time: 0,
                }],
            };

            store.put_header(&hash, &header).unwrap();
            store.put_block(&hash, &block).unwrap();
            store.put_height_index(h, &hash).unwrap();

            let mut status = BlockStatus::new();
            status.set(BlockStatus::VALID_SCRIPTS);
            status.set(BlockStatus::HAVE_DATA);
            status.set(BlockStatus::HAVE_UNDO);
            let entry = BlockIndexEntry {
                height: h,
                status,
                n_tx: 1,
                timestamp: header.timestamp,
                bits: header.bits,
                nonce: header.nonce,
                version: header.version,
                prev_hash: header.prev_block_hash,
                chain_work: [0u8; 32],
            };
            store.put_block_index(&hash, &entry).unwrap();
            // Stash undo data so the prune path has something to drop.
            let undo = UndoData { spent_coins: vec![] };
            store.put_undo(&hash, &undo).unwrap();
        }
        // Set tip pointer to the last block.
        let mut tip_bytes = [0u8; 32];
        tip_bytes[0..4].copy_from_slice(&n.to_be_bytes());
        store.set_best_block(&Hash256(tip_bytes), n).unwrap();
    }

    /// `prune_block` drops body + undo and clears HAVE_DATA/HAVE_UNDO,
    /// preserving the index entry. Idempotent on a missing body.
    #[test]
    fn test_prune_block_drops_body_and_undo() {
        let (_dir, db) = temp_db();
        let store = BlockStore::new(&db);
        build_synth_chain(&store, 1);

        let mut hash_bytes = [0u8; 32];
        hash_bytes[0..4].copy_from_slice(&1u32.to_be_bytes());
        let hash = Hash256(hash_bytes);

        // Pre-prune: body, undo, and flags all present.
        assert!(store.has_block(&hash).unwrap());
        assert!(store.get_undo(&hash).unwrap().is_some());
        let entry = store.get_block_index(&hash).unwrap().unwrap();
        assert!(entry.status.has(BlockStatus::HAVE_DATA));
        assert!(entry.status.has(BlockStatus::HAVE_UNDO));

        store.prune_block(&hash).unwrap();

        // Post-prune: body + undo gone, flags cleared, index entry kept.
        assert!(!store.has_block(&hash).unwrap());
        assert!(store.get_undo(&hash).unwrap().is_none());
        let entry = store.get_block_index(&hash).unwrap().unwrap();
        assert!(!entry.status.has(BlockStatus::HAVE_DATA));
        assert!(!entry.status.has(BlockStatus::HAVE_UNDO));
        // Header is preserved so reorg-skeleton stays intact.
        assert!(store.has_header(&hash).unwrap());

        // Idempotent — calling again is a no-op (no error).
        store.prune_block(&hash).unwrap();
    }

    /// `auto_prune` fires when tip >= MIN_BLOCKS_TO_KEEP + 1 and
    /// `-prune=550` is set; respects the keep window.
    #[test]
    fn test_auto_prune_fires_above_keep_window() {
        let (_dir, db) = temp_db();
        let store = BlockStore::new(&db);
        // Build a tip well above the keep window.
        let tip = MIN_BLOCKS_TO_KEEP + 50;
        build_synth_chain(&store, tip);

        let cfg = PruneCoordConfig::from_mib(Some(550), 0);
        assert!(cfg.auto_prune_enabled());

        let outcome = auto_prune(&store, &cfg, tip).unwrap().unwrap();
        // Last block we can prune = tip - MIN_BLOCKS_TO_KEEP - 1
        let expected_last = tip - MIN_BLOCKS_TO_KEEP - 1;
        assert_eq!(outcome.new_prune_height, expected_last);
        assert_eq!(outcome.blocks_pruned, expected_last); // heights 1..=expected_last

        // Verify body deleted at low heights, preserved at high heights.
        let mut h_low = [0u8; 32];
        h_low[0..4].copy_from_slice(&1u32.to_be_bytes());
        assert!(!store.has_block(&Hash256(h_low)).unwrap());

        let mut h_high = [0u8; 32];
        h_high[0..4].copy_from_slice(&tip.to_be_bytes());
        assert!(store.has_block(&Hash256(h_high)).unwrap());

        // Watermark persisted.
        assert_eq!(store.get_prune_height().unwrap(), expected_last);

        // A second pass at the same tip is a no-op (watermark didn't move).
        assert!(auto_prune(&store, &cfg, tip).unwrap().is_none());
    }

    /// `auto_prune` is a no-op when tip is inside the keep window.
    #[test]
    fn test_auto_prune_noop_inside_keep_window() {
        let (_dir, db) = temp_db();
        let store = BlockStore::new(&db);
        // Tip is below the keep-window boundary -> nothing to prune.
        build_synth_chain(&store, MIN_BLOCKS_TO_KEEP - 5);
        let cfg = PruneCoordConfig::from_mib(Some(550), 0);
        assert!(auto_prune(&store, &cfg, MIN_BLOCKS_TO_KEEP - 5).unwrap().is_none());
    }

    /// `-prune=1` manual-only mode disables auto-prune entirely; the
    /// `pruneblockchain`-driven `manual_prune_to_height` path still works.
    #[test]
    fn test_prune_manual_only_disables_auto_but_allows_manual() {
        let (_dir, db) = temp_db();
        let store = BlockStore::new(&db);
        let tip = MIN_BLOCKS_TO_KEEP + 50;
        build_synth_chain(&store, tip);

        let cfg = PruneCoordConfig::from_mib(Some(1), 0);
        assert!(cfg.is_prune_mode());
        assert!(cfg.is_manual_only());
        assert!(!cfg.auto_prune_enabled());

        // Auto-prune is a no-op under manual-only.
        assert!(auto_prune(&store, &cfg, tip).unwrap().is_none());

        // But manual-prune to a specific height still drops blocks.
        let target = 10u32;
        let outcome = manual_prune_to_height(&store, &cfg, tip, target).unwrap();
        assert_eq!(outcome.new_prune_height, target);
        assert_eq!(outcome.blocks_pruned, target);

        // Verify low heights got dropped.
        let mut h_low = [0u8; 32];
        h_low[0..4].copy_from_slice(&5u32.to_be_bytes());
        assert!(!store.has_block(&Hash256(h_low)).unwrap());
        // Heights above target still intact.
        let mut h_above = [0u8; 32];
        h_above[0..4].copy_from_slice(&20u32.to_be_bytes());
        assert!(store.has_block(&Hash256(h_above)).unwrap());
    }

    /// `manual_prune_to_height` clamps requested height against
    /// MIN_BLOCKS_TO_KEEP and the assumeutxo floor.
    #[test]
    fn test_manual_prune_clamps_to_keep_window_and_assumeutxo() {
        let (_dir, db) = temp_db();
        let store = BlockStore::new(&db);
        let tip = MIN_BLOCKS_TO_KEEP + 100;
        build_synth_chain(&store, tip);

        let assumeutxo_h = 50;
        let cfg = PruneCoordConfig::from_mib(Some(550), assumeutxo_h);

        // Request prune well into the keep window — should clamp.
        let requested = tip; // far above tip - 288
        let outcome = manual_prune_to_height(&store, &cfg, tip, requested).unwrap();
        // Effective height is min(keep_window_floor, assumeutxo_h) = 50.
        assert_eq!(outcome.new_prune_height, assumeutxo_h);
    }

    /// Genesis (height 0) is never pruned even if requested.
    #[test]
    fn test_genesis_never_pruned() {
        let (_dir, db) = temp_db();
        let store = BlockStore::new(&db);
        let params = ChainParams::regtest();
        store.init_genesis(&params).unwrap();
        let tip = MIN_BLOCKS_TO_KEEP + 5;
        build_synth_chain(&store, tip);

        // Genesis hash from params.
        let genesis_hash = params.genesis_hash;
        assert!(store.has_block(&genesis_hash).unwrap());

        // Force prune with an aggressive range starting at 0.
        let cfg = PruneCoordConfig::from_mib(Some(550), 0);
        let _ = manual_prune_to_height(&store, &cfg, tip, 5).unwrap();

        // Genesis still has its body.
        assert!(store.has_block(&genesis_hash).unwrap());
    }

    /// The watermark survives across `BlockStore` instances (persisted).
    #[test]
    fn test_prune_height_persists_across_block_store_handles() {
        let (_dir, db) = temp_db();
        {
            let store = BlockStore::new(&db);
            store.set_prune_height(12345).unwrap();
        }
        let store2 = BlockStore::new(&db);
        assert_eq!(store2.get_prune_height().unwrap(), 12345);
    }
}
