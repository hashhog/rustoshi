//! Integration tests for the complete rustoshi node.
//!
//! These tests exercise the full stack from primitives through consensus
//! validation to storage.

use rustoshi_consensus::{
    block_subsidy, check_block, ChainParams, MAX_MONEY, COINBASE_MATURITY,
};
use rustoshi_crypto::{merkle_root, sha256d};
use rustoshi_primitives::{Block, BlockHeader, Hash256, OutPoint, Transaction, TxIn, TxOut};
use rustoshi_primitives::serialize::{read_compact_size, write_compact_size, Decodable, Encodable};
use rustoshi_storage::{BlockStore, ChainDb};
use std::io::Cursor;

/// Helper to create a temporary database for testing.
fn temp_db() -> (ChainDb, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let db = ChainDb::open(tmp.path()).unwrap();
    (db, tmp)
}

// =============================================================================
// Genesis Block Tests
// =============================================================================

#[test]
fn test_genesis_block_validation_mainnet() {
    let params = ChainParams::mainnet();
    let genesis = &params.genesis_block;

    // Verify genesis block hash
    assert_eq!(genesis.block_hash(), params.genesis_hash);

    // Verify genesis passes context-free validation
    check_block(genesis, &params).unwrap();

    // Verify genesis merkle root
    let txids: Vec<Hash256> = genesis.transactions.iter().map(|tx| tx.txid()).collect();
    let computed = merkle_root(&txids);
    assert_eq!(computed, genesis.header.merkle_root);

    // Verify genesis header PoW
    assert!(genesis.header.validate_pow());

    // Verify genesis coinbase
    assert!(genesis.transactions[0].is_coinbase());
    assert_eq!(genesis.transactions[0].outputs[0].value, 50 * 100_000_000);
}

#[test]
fn test_genesis_block_all_networks() {
    for params in &[
        ChainParams::mainnet(),
        ChainParams::testnet3(),
        ChainParams::testnet4(),
        ChainParams::signet(),
        ChainParams::regtest(),
    ] {
        let genesis = &params.genesis_block;

        // Verify genesis coinbase is valid
        assert!(genesis.transactions[0].is_coinbase());
        assert_eq!(genesis.transactions.len(), 1);

        // Verify genesis header fields
        assert_eq!(genesis.header.prev_block_hash, Hash256::ZERO);

        // Verify network ID matches
        assert!(!params.network_id.name().is_empty());
    }
}

#[test]
fn test_mainnet_genesis_hash() {
    let params = ChainParams::mainnet();
    assert_eq!(
        params.genesis_hash.to_hex(),
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    );
}

#[test]
fn test_testnet3_genesis_hash() {
    let params = ChainParams::testnet3();
    assert_eq!(
        params.genesis_hash.to_hex(),
        "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
    );
}

#[test]
fn test_testnet4_genesis_hash() {
    let params = ChainParams::testnet4();
    assert_eq!(
        params.genesis_hash.to_hex(),
        "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043"
    );
}

#[test]
fn test_regtest_genesis_hash() {
    let params = ChainParams::regtest();
    assert_eq!(
        params.genesis_hash.to_hex(),
        "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
    );
}

// =============================================================================
// Database Tests
// =============================================================================

#[test]
fn test_database_genesis_init() {
    let (db, _tmp) = temp_db();
    let store = BlockStore::new(&db);
    let params = ChainParams::regtest();

    store.init_genesis(&params).unwrap();

    let best_hash = store.get_best_block_hash().unwrap().unwrap();
    assert_eq!(best_hash, params.genesis_hash);

    let best_height = store.get_best_height().unwrap().unwrap();
    assert_eq!(best_height, 0);

    let header = store.get_header(&params.genesis_hash).unwrap().unwrap();
    assert_eq!(header.timestamp, params.genesis_block.header.timestamp);
}

#[test]
fn test_database_reopen_persistence() {
    let tmp = tempfile::tempdir().unwrap();
    let params = ChainParams::testnet4();

    // First session: open, init, close
    {
        let db = ChainDb::open(tmp.path()).unwrap();
        let store = BlockStore::new(&db);
        store.init_genesis(&params).unwrap();
    }

    // Second session: reopen and verify
    {
        let db = ChainDb::open(tmp.path()).unwrap();
        let store = BlockStore::new(&db);

        let best_hash = store.get_best_block_hash().unwrap().unwrap();
        assert_eq!(best_hash, params.genesis_hash);

        let header = store.get_header(&best_hash).unwrap().unwrap();
        assert_eq!(header.timestamp, params.genesis_block.header.timestamp);
    }
}

// =============================================================================
// Serialization Round-trip Tests
// =============================================================================

#[test]
fn test_transaction_serialization_roundtrip() {
    // Create a sample transaction
    let tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256([0xab; 32]),
                vout: 0,
            },
            script_sig: vec![0x48, 0x30, 0x45],
            sequence: 0xFFFFFFFF,
            witness: vec![vec![0x30, 0x44], vec![0x02, 0x20]],
        }],
        outputs: vec![TxOut {
            value: 50000,
            script_pubkey: vec![0x00, 0x14, 0xab, 0xcd],
        }],
        lock_time: 0,
    };

    let serialized = tx.serialize();
    let deserialized = Transaction::deserialize(&serialized).unwrap();
    assert_eq!(tx, deserialized);
    assert_eq!(tx.txid(), deserialized.txid());
    assert_eq!(tx.wtxid(), deserialized.wtxid());
}

#[test]
fn test_transaction_legacy_serialization_roundtrip() {
    // Legacy transaction without witness
    let tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256([0xaa; 32]),
                vout: 1,
            },
            script_sig: vec![0x47, 0x30, 0x44, 0x02, 0x20],
            sequence: 0xFFFFFFFF,
            witness: vec![],
        }],
        outputs: vec![
            TxOut {
                value: 100_000_000,
                script_pubkey: vec![0x76, 0xa9, 0x14],
            },
            TxOut {
                value: 50_000_000,
                script_pubkey: vec![0xa9, 0x14],
            },
        ],
        lock_time: 500_000,
    };

    let serialized = tx.serialize();
    let deserialized = Transaction::deserialize(&serialized).unwrap();
    assert_eq!(tx, deserialized);

    // For legacy transactions, txid should equal wtxid
    assert_eq!(tx.txid(), tx.wtxid());
}

#[test]
fn test_block_header_serialization_roundtrip() {
    let header = BlockHeader {
        version: 0x20000000,
        prev_block_hash: Hash256([0xff; 32]),
        merkle_root: Hash256([0xaa; 32]),
        timestamp: 1700000000,
        bits: 0x1d00ffff,
        nonce: 12345,
    };

    let serialized = header.serialize();
    assert_eq!(serialized.len(), 80);
    let deserialized = BlockHeader::deserialize(&serialized).unwrap();
    assert_eq!(header, deserialized);
}

#[test]
fn test_block_serialization_roundtrip() {
    let block = Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: Hash256::ZERO,
            merkle_root: Hash256::ZERO,
            timestamp: 1231006505,
            bits: 0x1d00ffff,
            nonce: 2083236893,
        },
        transactions: vec![
            Transaction {
                version: 1,
                inputs: vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: vec![0x04, 0xff, 0xff, 0x00, 0x1d],
                    sequence: 0xFFFFFFFF,
                    witness: vec![],
                }],
                outputs: vec![TxOut {
                    value: 50_0000_0000,
                    script_pubkey: vec![0x41],
                }],
                lock_time: 0,
            },
        ],
    };

    let serialized = block.serialize();
    let deserialized = Block::deserialize(&serialized).unwrap();
    assert_eq!(block, deserialized);
    assert_eq!(block.block_hash(), deserialized.block_hash());
}

// =============================================================================
// Subsidy Schedule Tests
// =============================================================================

#[test]
fn test_subsidy_schedule() {
    assert_eq!(block_subsidy(0, 210_000), 5_000_000_000);
    assert_eq!(block_subsidy(209_999, 210_000), 5_000_000_000);
    assert_eq!(block_subsidy(210_000, 210_000), 2_500_000_000);
    assert_eq!(block_subsidy(420_000, 210_000), 1_250_000_000);
    assert_eq!(block_subsidy(630_000, 210_000), 625_000_000);
    assert_eq!(block_subsidy(13_440_000, 210_000), 0); // after all halvings
}

#[test]
fn test_total_supply_limit() {
    // Verify total supply converges to MAX_MONEY
    // Sum: 50 * 210,000 + 25 * 210,000 + 12.5 * 210,000 + ...
    // = 210,000 * (50 + 25 + 12.5 + ...) = 210,000 * 100 = 21,000,000 BTC
    // In satoshis: 21,000,000 * 100,000,000 = 2,100,000,000,000,000

    let halving_interval: u64 = 210_000;
    let mut total: u64 = 0;

    for epoch in 0..33u32 {
        let subsidy = block_subsidy(epoch * halving_interval as u32, halving_interval as u32);
        if subsidy == 0 {
            break;
        }
        // This won't overflow because subsidy decreases exponentially
        total += subsidy * halving_interval;
    }

    // Total should be very close to MAX_MONEY
    // Due to integer division in halving, we lose some satoshis each epoch
    // The total will be slightly less than MAX_MONEY
    assert!(total <= MAX_MONEY);
    // Should be within 1 BTC of MAX_MONEY (100M satoshis)
    assert!(
        total > MAX_MONEY - 100_000_000,
        "Total {} should be close to MAX_MONEY {}",
        total,
        MAX_MONEY
    );
}

// =============================================================================
// CompactSize Tests
// =============================================================================

#[test]
fn test_compact_size_roundtrip() {
    let test_values = vec![0u64, 1, 252, 253, 0xFFFF, 0x10000, 0xFFFFFFFF, 0x100000000];

    for val in test_values {
        let mut buf = Vec::new();
        write_compact_size(&mut buf, val).unwrap();
        let mut cursor = Cursor::new(&buf);
        let decoded = read_compact_size(&mut cursor).unwrap();
        assert_eq!(val, decoded, "CompactSize round-trip failed for {}", val);
    }
}

#[test]
fn test_compact_size_encoding_lengths() {
    // 0-252: 1 byte
    let mut buf = Vec::new();
    write_compact_size(&mut buf, 252).unwrap();
    assert_eq!(buf.len(), 1);

    // 253-65535: 3 bytes
    buf.clear();
    write_compact_size(&mut buf, 253).unwrap();
    assert_eq!(buf.len(), 3);

    // 65536-4294967295: 5 bytes
    buf.clear();
    write_compact_size(&mut buf, 0x10000).unwrap();
    assert_eq!(buf.len(), 5);

    // >4294967295: 9 bytes
    buf.clear();
    write_compact_size(&mut buf, 0x100000000u64).unwrap();
    assert_eq!(buf.len(), 9);
}

// =============================================================================
// Consensus Constants Tests
// =============================================================================

#[test]
fn test_max_money_constant() {
    assert_eq!(MAX_MONEY, 2_100_000_000_000_000);
    assert_eq!(MAX_MONEY, 21_000_000 * 100_000_000);
}

#[test]
fn test_coinbase_maturity() {
    assert_eq!(COINBASE_MATURITY, 100);
}

#[test]
fn test_network_magic_bytes() {
    let params = ChainParams::mainnet();
    assert_eq!(params.network_magic.0, [0xf9, 0xbe, 0xb4, 0xd9]);

    let params = ChainParams::testnet3();
    assert_eq!(params.network_magic.0, [0x0b, 0x11, 0x09, 0x07]);

    let params = ChainParams::regtest();
    assert_eq!(params.network_magic.0, [0xfa, 0xbf, 0xb5, 0xda]);

    let params = ChainParams::testnet4();
    assert_eq!(params.network_magic.0, [0x1c, 0x16, 0x3f, 0x28]);
}

#[test]
fn test_default_ports() {
    assert_eq!(ChainParams::mainnet().default_port, 8333);
    assert_eq!(ChainParams::testnet3().default_port, 18333);
    assert_eq!(ChainParams::testnet4().default_port, 48333);
    assert_eq!(ChainParams::signet().default_port, 38333);
    assert_eq!(ChainParams::regtest().default_port, 18444);
}

// =============================================================================
// Hash Tests
// =============================================================================

#[test]
fn test_hash256_hex_roundtrip() {
    let genesis_hash = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    let hash = Hash256::from_hex(genesis_hash).unwrap();
    assert_eq!(hash.to_hex(), genesis_hash);
}

#[test]
fn test_hash256_byte_order() {
    // Bitcoin displays hashes in reverse byte order
    let hex = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    let hash = Hash256::from_hex(hex).unwrap();

    // Internal bytes should be reversed
    assert_eq!(hash.0[31], 0x00);
    assert_eq!(hash.0[30], 0x00);
    assert_eq!(hash.0[0], 0x6f);
    assert_eq!(hash.0[1], 0xe2);
}

#[test]
fn test_sha256d_deterministic() {
    let data = b"test data for hashing";
    let hash1 = sha256d(data);
    let hash2 = sha256d(data);
    assert_eq!(hash1, hash2);
}

#[test]
fn test_sha256d_different_inputs() {
    let hash_a = sha256d(b"input A");
    let hash_b = sha256d(b"input B");
    assert_ne!(hash_a, hash_b);
}

// =============================================================================
// Merkle Tree Tests
// =============================================================================

#[test]
fn test_merkle_root_single_tx() {
    let hash = sha256d(b"test transaction");
    let root = merkle_root(&[hash]);
    assert_eq!(root, hash);
}

#[test]
fn test_merkle_root_empty() {
    let root = merkle_root(&[]);
    assert_eq!(root, Hash256::ZERO);
}

#[test]
fn test_merkle_root_two_txs() {
    let hash1 = sha256d(b"tx1");
    let hash2 = sha256d(b"tx2");
    let root = merkle_root(&[hash1, hash2]);

    // Manual calculation
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(&hash1.0);
    combined[32..].copy_from_slice(&hash2.0);
    let expected = sha256d(&combined);

    assert_eq!(root, expected);
}

// =============================================================================
// Soft Fork Activation Tests
// =============================================================================

#[test]
fn test_mainnet_soft_fork_activation() {
    let params = ChainParams::mainnet();

    // BIP-34: coinbase height
    assert!(!params.is_bip34_active(227_930));
    assert!(params.is_bip34_active(227_931));

    // SegWit
    assert!(!params.is_segwit_active(481_823));
    assert!(params.is_segwit_active(481_824));

    // Taproot
    assert!(!params.is_taproot_active(709_631));
    assert!(params.is_taproot_active(709_632));
}

#[test]
fn test_testnet4_all_forks_active() {
    let params = ChainParams::testnet4();

    // All forks active from block 1
    assert!(params.is_bip34_active(1));
    assert!(params.is_bip65_active(1));
    assert!(params.is_bip66_active(1));
    assert!(params.is_csv_active(1));
    assert!(params.is_segwit_active(1));
    assert!(params.is_taproot_active(1));

    // But not at block 0 (genesis)
    assert!(!params.is_bip34_active(0));
}

// =============================================================================
// Transaction Property Tests
// =============================================================================

#[test]
fn test_coinbase_transaction_detection() {
    let coinbase_tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: vec![0x04, 0x00, 0x00, 0x00],
            sequence: 0xFFFFFFFF,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value: 50_0000_0000,
            script_pubkey: vec![0x76, 0xa9, 0x14],
        }],
        lock_time: 0,
    };

    assert!(coinbase_tx.is_coinbase());

    let normal_tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256([0xaa; 32]),
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0xFFFFFFFF,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value: 50_0000_0000,
            script_pubkey: vec![],
        }],
        lock_time: 0,
    };

    assert!(!normal_tx.is_coinbase());
}

#[test]
fn test_witness_detection() {
    let witness_tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256([0xaa; 32]),
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0xFFFFFFFF,
            witness: vec![vec![0x30, 0x44]],
        }],
        outputs: vec![TxOut {
            value: 50_000,
            script_pubkey: vec![],
        }],
        lock_time: 0,
    };

    assert!(witness_tx.has_witness());

    let legacy_tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256([0xbb; 32]),
                vout: 1,
            },
            script_sig: vec![0x47, 0x30],
            sequence: 0xFFFFFFFF,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value: 50_000,
            script_pubkey: vec![],
        }],
        lock_time: 0,
    };

    assert!(!legacy_tx.has_witness());
}

#[test]
fn test_txid_vs_wtxid() {
    let witness_tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256([0xaa; 32]),
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0xFFFFFFFF,
            witness: vec![vec![0x30, 0x44, 0x02, 0x20], vec![0x02, 0x21]],
        }],
        outputs: vec![TxOut {
            value: 50_000,
            script_pubkey: vec![0x00, 0x14, 0xab, 0xcd],
        }],
        lock_time: 0,
    };

    // For witness transactions, txid != wtxid
    assert_ne!(witness_tx.txid(), witness_tx.wtxid());

    let legacy_tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256([0xbb; 32]),
                vout: 0,
            },
            script_sig: vec![0x47],
            sequence: 0xFFFFFFFF,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value: 50_000,
            script_pubkey: vec![],
        }],
        lock_time: 0,
    };

    // For legacy transactions, txid == wtxid
    assert_eq!(legacy_tx.txid(), legacy_tx.wtxid());
}

// =============================================================================
// OutPoint Tests
// =============================================================================

#[test]
fn test_outpoint_null() {
    let null = OutPoint::null();
    assert!(null.is_null());
    assert_eq!(null.txid, Hash256::ZERO);
    assert_eq!(null.vout, 0xFFFFFFFF);
}

#[test]
fn test_outpoint_serialization() {
    let outpoint = OutPoint {
        txid: Hash256([0xab; 32]),
        vout: 42,
    };

    let serialized = outpoint.serialize();
    assert_eq!(serialized.len(), 36);

    let deserialized = OutPoint::deserialize(&serialized).unwrap();
    assert_eq!(outpoint, deserialized);
}
