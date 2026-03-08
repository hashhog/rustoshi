//! Performance benchmarks for rustoshi.
//!
//! These benchmarks establish performance baselines for critical operations
//! during IBD (initial block download) and normal operation.
//!
//! Run with: `cargo bench --workspace`

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rustoshi_consensus::CompressedScript;
use rustoshi_crypto::{hash160, merkle_root, sha256d};
use rustoshi_primitives::{
    Block, BlockHeader, Decodable, Encodable, Hash256, OutPoint, Transaction, TxIn, TxOut,
};

/// Benchmark SHA256d for various data sizes.
///
/// SHA256d is used extensively: block hashes, txid computation, merkle trees.
fn bench_sha256d(c: &mut Criterion) {
    let data_32 = vec![0u8; 32];
    let data_80 = vec![0u8; 80]; // block header size
    let data_1kb = vec![0u8; 1024];
    let data_1mb = vec![0u8; 1024 * 1024];

    c.bench_function("sha256d_32b", |b| {
        b.iter(|| sha256d(black_box(&data_32)))
    });

    c.bench_function("sha256d_80b", |b| {
        b.iter(|| sha256d(black_box(&data_80)))
    });

    c.bench_function("sha256d_1kb", |b| {
        b.iter(|| sha256d(black_box(&data_1kb)))
    });

    c.bench_function("sha256d_1mb", |b| {
        b.iter(|| sha256d(black_box(&data_1mb)))
    });
}

/// Benchmark HASH160 (used for P2PKH and P2SH addresses).
fn bench_hash160(c: &mut Criterion) {
    let pubkey_compressed = vec![0u8; 33];
    let pubkey_uncompressed = vec![0u8; 65];

    c.bench_function("hash160_33b", |b| {
        b.iter(|| hash160(black_box(&pubkey_compressed)))
    });

    c.bench_function("hash160_65b", |b| {
        b.iter(|| hash160(black_box(&pubkey_uncompressed)))
    });
}

/// Benchmark transaction serialization and deserialization.
fn bench_transaction_serialize(c: &mut Criterion) {
    // Create a typical transaction with 2 inputs and 2 outputs
    let tx = Transaction {
        version: 2,
        inputs: vec![
            TxIn {
                previous_output: OutPoint {
                    txid: Hash256([0xab; 32]),
                    vout: 0,
                },
                script_sig: vec![0; 100], // typical scriptSig size
                sequence: 0xFFFFFFFF,
                witness: vec![vec![0; 72], vec![0; 33]], // sig + pubkey
            },
            TxIn {
                previous_output: OutPoint {
                    txid: Hash256([0xcd; 32]),
                    vout: 1,
                },
                script_sig: vec![0; 100],
                sequence: 0xFFFFFFFF,
                witness: vec![vec![0; 72], vec![0; 33]],
            },
        ],
        outputs: vec![
            TxOut {
                value: 50_000,
                script_pubkey: vec![0; 25], // P2PKH
            },
            TxOut {
                value: 40_000,
                script_pubkey: vec![0; 22], // P2WPKH
            },
        ],
        lock_time: 0,
    };

    c.bench_function("tx_serialize", |b| {
        b.iter(|| black_box(&tx).serialize())
    });

    let serialized = tx.serialize();
    c.bench_function("tx_deserialize", |b| {
        b.iter(|| Transaction::deserialize(black_box(&serialized)))
    });

    c.bench_function("tx_txid", |b| b.iter(|| black_box(&tx).txid()));

    c.bench_function("tx_wtxid", |b| b.iter(|| black_box(&tx).wtxid()));

    c.bench_function("tx_weight", |b| b.iter(|| black_box(&tx).weight()));
}

/// Benchmark block header hashing (critical for mining and validation).
fn bench_block_header_hash(c: &mut Criterion) {
    let header = BlockHeader {
        version: 0x20000000,
        prev_block_hash: Hash256([0xff; 32]),
        merkle_root: Hash256([0xaa; 32]),
        timestamp: 1700000000,
        bits: 0x1d00ffff,
        nonce: 0,
    };

    c.bench_function("block_header_hash", |b| {
        b.iter(|| black_box(&header).block_hash())
    });

    c.bench_function("block_header_serialize", |b| {
        b.iter(|| black_box(&header).serialize())
    });
}

/// Benchmark merkle root computation for various transaction counts.
fn bench_merkle_root(c: &mut Criterion) {
    let hashes_10: Vec<Hash256> = (0..10)
        .map(|i| sha256d(&(i as u32).to_le_bytes()))
        .collect();

    let hashes_100: Vec<Hash256> = (0..100)
        .map(|i| sha256d(&(i as u32).to_le_bytes()))
        .collect();

    let hashes_1000: Vec<Hash256> = (0..1000)
        .map(|i| sha256d(&(i as u32).to_le_bytes()))
        .collect();

    c.bench_function("merkle_root_10", |b| {
        b.iter(|| merkle_root(black_box(&hashes_10)))
    });

    c.bench_function("merkle_root_100", |b| {
        b.iter(|| merkle_root(black_box(&hashes_100)))
    });

    c.bench_function("merkle_root_1000", |b| {
        b.iter(|| merkle_root(black_box(&hashes_1000)))
    });
}

/// Benchmark CompressedScript compression and decompression.
fn bench_compressed_script(c: &mut Criterion) {
    // P2PKH script
    let p2pkh = vec![
        0x76, 0xa9, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x88, 0xac,
    ];

    // P2WPKH script
    let p2wpkh = vec![
        0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
    ];

    // P2TR script
    let mut p2tr = vec![0x51, 0x20];
    p2tr.extend(std::iter::repeat(0x77).take(32));

    c.bench_function("compressed_script_p2pkh", |b| {
        b.iter(|| CompressedScript::compress(black_box(&p2pkh)))
    });

    c.bench_function("compressed_script_p2wpkh", |b| {
        b.iter(|| CompressedScript::compress(black_box(&p2wpkh)))
    });

    c.bench_function("compressed_script_p2tr", |b| {
        b.iter(|| CompressedScript::compress(black_box(&p2tr)))
    });

    let compressed_p2pkh = CompressedScript::compress(&p2pkh);
    c.bench_function("compressed_script_decompress_p2pkh", |b| {
        b.iter(|| black_box(&compressed_p2pkh).decompress())
    });

    let compressed_p2wpkh = CompressedScript::compress(&p2wpkh);
    c.bench_function("compressed_script_decompress_p2wpkh", |b| {
        b.iter(|| black_box(&compressed_p2wpkh).decompress())
    });
}

/// Benchmark block serialization and deserialization.
fn bench_block_serialize(c: &mut Criterion) {
    // Create a small block with 10 transactions
    let coinbase = Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: vec![0x03, 0x01, 0x00, 0x00], // height encoding
            sequence: 0xFFFFFFFF,
            witness: vec![vec![0; 32]], // witness nonce
        }],
        outputs: vec![TxOut {
            value: 625_000_000,
            script_pubkey: vec![0x51], // OP_1
        }],
        lock_time: 0,
    };

    let regular_tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256([0xab; 32]),
                vout: 0,
            },
            script_sig: vec![0; 72], // signature
            sequence: 0xFFFFFFFF,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value: 50_000,
            script_pubkey: vec![0; 25],
        }],
        lock_time: 0,
    };

    let mut transactions = vec![coinbase];
    transactions.extend(std::iter::repeat(regular_tx.clone()).take(9));

    let block = Block {
        header: BlockHeader {
            version: 0x20000000,
            prev_block_hash: Hash256([0xff; 32]),
            merkle_root: Hash256([0xaa; 32]),
            timestamp: 1700000000,
            bits: 0x1d00ffff,
            nonce: 12345,
        },
        transactions,
    };

    c.bench_function("block_serialize_10tx", |b| {
        b.iter(|| black_box(&block).serialize())
    });

    let serialized = block.serialize();
    c.bench_function("block_deserialize_10tx", |b| {
        b.iter(|| Block::deserialize(black_box(&serialized)))
    });

    c.bench_function("block_compute_merkle_root_10tx", |b| {
        b.iter(|| black_box(&block).compute_merkle_root())
    });
}

/// Benchmark Hash256 operations.
fn bench_hash256(c: &mut Criterion) {
    let hash = Hash256([0xab; 32]);
    let data = [0u8; 32];

    c.bench_function("hash256_from_bytes", |b| {
        b.iter(|| Hash256::from_bytes(black_box(data)))
    });

    c.bench_function("hash256_to_hex", |b| {
        b.iter(|| black_box(&hash).to_hex())
    });

    let hex_str = hash.to_hex();
    c.bench_function("hash256_from_hex", |b| {
        b.iter(|| Hash256::from_hex(black_box(&hex_str)))
    });
}

criterion_group!(
    benches,
    bench_sha256d,
    bench_hash160,
    bench_transaction_serialize,
    bench_block_header_hash,
    bench_merkle_root,
    bench_compressed_script,
    bench_block_serialize,
    bench_hash256,
);
criterion_main!(benches);
