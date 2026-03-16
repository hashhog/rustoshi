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
pub mod undo;
pub mod utxo_cache;

pub use block_store::{BlockIndexEntry, BlockStatus, BlockStore, CoinEntry, TxIndexEntry, UndoData};
pub use blockstore::{
    BlockFileInfo, BlockFileLocation, FlatBlockStore, FlatFilePos, FlatFileSeq,
    BLOCKFILE_CHUNK_SIZE, MAX_BLOCKFILE_SIZE, STORAGE_HEADER_BYTES, UNDOFILE_CHUNK_SIZE,
};
pub use undo::{BlockUndo, TxUndo};
pub use columns::*;
pub use db::{ChainDb, StorageError, CURRENT_DB_VERSION};
pub use utxo_cache::{
    CacheEntryFlags, Coin, CoinsCacheEntry, CoinsView, CoinsViewCache, CoinsViewDB,
    DEFAULT_DB_CACHE_BYTES,
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
}
