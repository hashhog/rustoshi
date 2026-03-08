//! Property-based tests using proptest.
//!
//! These tests generate random inputs to find edge cases that manual tests miss.
//! Especially valuable for serialization code and cryptographic operations.

use proptest::prelude::*;
use rustoshi_consensus::{block_subsidy, MAX_MONEY, SUBSIDY_HALVING_INTERVAL};
use rustoshi_crypto::{base58check_decode, base58check_encode, merkle_root, sha256, sha256d};
use rustoshi_primitives::serialize::{read_compact_size, write_compact_size, Decodable, Encodable};
use rustoshi_primitives::{BlockHeader, Hash256, OutPoint, Transaction, TxIn, TxOut};
use std::io::Cursor;

proptest! {
    // =========================================================================
    // Hash256 Property Tests
    // =========================================================================

    #[test]
    fn hash256_hex_roundtrip(bytes in prop::array::uniform32(any::<u8>())) {
        let hash = Hash256(bytes);
        let hex = hash.to_hex();
        let decoded = Hash256::from_hex(&hex).unwrap();
        prop_assert_eq!(hash, decoded);
    }

    #[test]
    fn hash256_reversed_involution(bytes in prop::array::uniform32(any::<u8>())) {
        let hash = Hash256(bytes);
        let double_reversed = hash.reversed().reversed();
        prop_assert_eq!(hash, double_reversed);
    }

    #[test]
    fn hash256_display_is_hex(bytes in prop::array::uniform32(any::<u8>())) {
        let hash = Hash256(bytes);
        let display = format!("{}", hash);
        let hex = hash.to_hex();
        prop_assert_eq!(display, hex);
    }

    // =========================================================================
    // CompactSize Property Tests
    // =========================================================================

    #[test]
    fn compact_size_roundtrip(val in 0u64..=0xFFFFFFFFFFu64) {
        let mut buf = Vec::new();
        write_compact_size(&mut buf, val).unwrap();
        let mut cursor = Cursor::new(&buf);
        let decoded = read_compact_size(&mut cursor).unwrap();
        prop_assert_eq!(val, decoded);
    }

    #[test]
    fn compact_size_length_bounds(val in any::<u64>()) {
        let mut buf = Vec::new();
        write_compact_size(&mut buf, val).unwrap();

        // Verify length based on value
        let expected_len = if val < 253 { 1 }
            else if val <= 0xFFFF { 3 }
            else if val <= 0xFFFFFFFF { 5 }
            else { 9 };
        prop_assert_eq!(buf.len(), expected_len);
    }

    // =========================================================================
    // SHA256 Property Tests
    // =========================================================================

    #[test]
    fn sha256d_deterministic(data in prop::collection::vec(any::<u8>(), 0..1000)) {
        let hash1 = sha256d(&data);
        let hash2 = sha256d(&data);
        prop_assert_eq!(hash1, hash2);
    }

    #[test]
    fn sha256d_different_inputs_mostly_different(
        a in prop::collection::vec(any::<u8>(), 1..100),
        b in prop::collection::vec(any::<u8>(), 1..100)
    ) {
        prop_assume!(a != b);
        let hash_a = sha256d(&a);
        let hash_b = sha256d(&b);
        // Different inputs should (with overwhelming probability) produce different hashes
        prop_assert_ne!(hash_a, hash_b);
    }

    #[test]
    fn sha256_output_is_32_bytes(data in prop::collection::vec(any::<u8>(), 0..1000)) {
        let hash = sha256(&data);
        prop_assert_eq!(hash.len(), 32);
    }

    // =========================================================================
    // Transaction Serialization Property Tests
    // =========================================================================

    #[test]
    fn transaction_basic_roundtrip(
        version in any::<i32>(),
        lock_time in any::<u32>(),
        value in 0u64..=MAX_MONEY,
    ) {
        let tx = Transaction {
            version,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: vec![0x04, 0xff, 0xff, 0x00, 0x1d],
                sequence: 0xFFFFFFFF,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value,
                script_pubkey: vec![0x76, 0xa9, 0x14],
            }],
            lock_time,
        };

        let serialized = tx.serialize();
        let deserialized = Transaction::deserialize(&serialized).unwrap();
        prop_assert_eq!(tx.version, deserialized.version);
        prop_assert_eq!(tx.lock_time, deserialized.lock_time);
        prop_assert_eq!(tx.outputs[0].value, deserialized.outputs[0].value);
    }

    #[test]
    fn transaction_witness_roundtrip(
        version in any::<i32>(),
        witness_item_count in 1usize..5,
        witness_item_len in 1usize..100,
    ) {
        let witness: Vec<Vec<u8>> = (0..witness_item_count)
            .map(|i| vec![i as u8; witness_item_len])
            .collect();

        let tx = Transaction {
            version,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256([0xaa; 32]),
                    vout: 0,
                },
                script_sig: vec![],
                sequence: 0xFFFFFFFF,
                witness,
            }],
            outputs: vec![TxOut {
                value: 50000,
                script_pubkey: vec![0x00, 0x14],
            }],
            lock_time: 0,
        };

        let serialized = tx.serialize();
        let deserialized = Transaction::deserialize(&serialized).unwrap();
        prop_assert_eq!(tx.inputs[0].witness.len(), deserialized.inputs[0].witness.len());
        prop_assert!(tx.has_witness());
        prop_assert!(deserialized.has_witness());
    }

    // =========================================================================
    // BlockHeader Serialization Property Tests
    // =========================================================================

    #[test]
    fn block_header_roundtrip(
        version in any::<i32>(),
        timestamp in any::<u32>(),
        bits in any::<u32>(),
        nonce in any::<u32>(),
    ) {
        let header = BlockHeader {
            version,
            prev_block_hash: Hash256([0xaa; 32]),
            merkle_root: Hash256([0xbb; 32]),
            timestamp,
            bits,
            nonce,
        };

        let serialized = header.serialize();
        prop_assert_eq!(serialized.len(), 80);
        let deserialized = BlockHeader::deserialize(&serialized).unwrap();
        prop_assert_eq!(header, deserialized);
    }

    // =========================================================================
    // OutPoint Serialization Property Tests
    // =========================================================================

    #[test]
    fn outpoint_roundtrip(
        txid_bytes in prop::array::uniform32(any::<u8>()),
        vout in any::<u32>(),
    ) {
        let outpoint = OutPoint {
            txid: Hash256(txid_bytes),
            vout,
        };

        let serialized = outpoint.serialize();
        prop_assert_eq!(serialized.len(), 36);
        let deserialized = OutPoint::deserialize(&serialized).unwrap();
        prop_assert_eq!(outpoint, deserialized);
    }

    // =========================================================================
    // Base58Check Property Tests
    // =========================================================================

    #[test]
    fn base58_roundtrip(data in prop::collection::vec(any::<u8>(), 1..50)) {
        let encoded = base58check_encode(&data);
        let decoded = base58check_decode(&encoded).unwrap();
        prop_assert_eq!(data, decoded);
    }

    #[test]
    fn base58_preserves_leading_zeros(
        num_zeros in 0usize..10,
        suffix in prop::collection::vec(1u8..=255u8, 1..20),
    ) {
        let mut data = vec![0u8; num_zeros];
        data.extend(suffix);

        let encoded = base58check_encode(&data);
        let decoded = base58check_decode(&encoded).unwrap();
        prop_assert_eq!(data, decoded);
    }

    // =========================================================================
    // Merkle Root Property Tests
    // =========================================================================

    #[test]
    fn merkle_root_single_tx(hash_bytes in prop::array::uniform32(any::<u8>())) {
        let hash = Hash256(hash_bytes);
        let root = merkle_root(&[hash]);
        prop_assert_eq!(root, hash);
    }

    #[test]
    fn merkle_root_deterministic(
        num_hashes in 1usize..20,
        seed in any::<u64>(),
    ) {
        // Generate deterministic hashes from seed
        let hashes: Vec<Hash256> = (0..num_hashes)
            .map(|i| sha256d(&[seed.to_le_bytes().as_slice(), &i.to_le_bytes()].concat()))
            .collect();

        let root1 = merkle_root(&hashes);
        let root2 = merkle_root(&hashes);
        prop_assert_eq!(root1, root2);
    }

    // =========================================================================
    // Subsidy Schedule Property Tests
    // =========================================================================

    #[test]
    fn subsidy_never_exceeds_initial(height in 0u32..20_000_000) {
        let subsidy = block_subsidy(height, SUBSIDY_HALVING_INTERVAL);
        prop_assert!(subsidy <= 50_0000_0000);
    }

    #[test]
    fn subsidy_halves_correctly(epoch in 0u32..63) {
        let height = epoch * SUBSIDY_HALVING_INTERVAL;
        let subsidy = block_subsidy(height, SUBSIDY_HALVING_INTERVAL);
        let expected = 50_0000_0000u64 >> epoch;
        prop_assert_eq!(subsidy, expected);
    }

    #[test]
    fn subsidy_eventually_zero(epoch in 64u32..100) {
        let height = epoch * SUBSIDY_HALVING_INTERVAL;
        let subsidy = block_subsidy(height, SUBSIDY_HALVING_INTERVAL);
        prop_assert_eq!(subsidy, 0);
    }

    // =========================================================================
    // TxOut Property Tests
    // =========================================================================

    #[test]
    fn txout_roundtrip(
        value in 0u64..=MAX_MONEY,
        script_len in 0usize..1000,
    ) {
        let txout = TxOut {
            value,
            script_pubkey: vec![0xab; script_len],
        };

        let serialized = txout.serialize();
        let deserialized = TxOut::deserialize(&serialized).unwrap();
        prop_assert_eq!(txout.value, deserialized.value);
        prop_assert_eq!(txout.script_pubkey, deserialized.script_pubkey);
    }

    // =========================================================================
    // Primitive Type Serialization Property Tests
    // =========================================================================

    #[test]
    fn u8_roundtrip(val in any::<u8>()) {
        let serialized = val.serialize();
        let deserialized = u8::deserialize(&serialized).unwrap();
        prop_assert_eq!(val, deserialized);
    }

    #[test]
    fn u16_roundtrip(val in any::<u16>()) {
        let serialized = val.serialize();
        let deserialized = u16::deserialize(&serialized).unwrap();
        prop_assert_eq!(val, deserialized);
    }

    #[test]
    fn u32_roundtrip(val in any::<u32>()) {
        let serialized = val.serialize();
        let deserialized = u32::deserialize(&serialized).unwrap();
        prop_assert_eq!(val, deserialized);
    }

    #[test]
    fn u64_roundtrip(val in any::<u64>()) {
        let serialized = val.serialize();
        let deserialized = u64::deserialize(&serialized).unwrap();
        prop_assert_eq!(val, deserialized);
    }

    #[test]
    fn i32_roundtrip(val in any::<i32>()) {
        let serialized = val.serialize();
        let deserialized = i32::deserialize(&serialized).unwrap();
        prop_assert_eq!(val, deserialized);
    }

    #[test]
    fn i64_roundtrip(val in any::<i64>()) {
        let serialized = val.serialize();
        let deserialized = i64::deserialize(&serialized).unwrap();
        prop_assert_eq!(val, deserialized);
    }

    #[test]
    fn bool_roundtrip(val in any::<bool>()) {
        let serialized = val.serialize();
        let deserialized = bool::deserialize(&serialized).unwrap();
        prop_assert_eq!(val, deserialized);
    }

    #[test]
    fn vec_u8_roundtrip(data in prop::collection::vec(any::<u8>(), 0..1000)) {
        let serialized = data.serialize();
        let deserialized = Vec::<u8>::deserialize(&serialized).unwrap();
        prop_assert_eq!(data, deserialized);
    }

    #[test]
    fn array_32_roundtrip(arr in prop::array::uniform32(any::<u8>())) {
        let serialized = arr.serialize();
        prop_assert_eq!(serialized.len(), 32);
        let deserialized = <[u8; 32]>::deserialize(&serialized).unwrap();
        prop_assert_eq!(arr, deserialized);
    }
}

// =========================================================================
// Non-proptest Tests for Edge Cases
// =========================================================================

#[test]
fn compact_size_boundary_values() {
    // Test all boundary values precisely
    let boundaries = [
        (0u64, 1),
        (252u64, 1),
        (253u64, 3),
        (0xFFFFu64, 3),
        (0x10000u64, 5),
        (0xFFFFFFFFu64, 5),
        (0x100000000u64, 9),
        (u64::MAX, 9),
    ];

    for (val, expected_len) in boundaries {
        let mut buf = Vec::new();
        write_compact_size(&mut buf, val).unwrap();
        assert_eq!(
            buf.len(),
            expected_len,
            "Failed for value {}: expected len {}, got {}",
            val,
            expected_len,
            buf.len()
        );

        let mut cursor = Cursor::new(&buf);
        let decoded = read_compact_size(&mut cursor).unwrap();
        assert_eq!(val, decoded, "Roundtrip failed for value {}", val);
    }
}

#[test]
fn hash256_zero_constant() {
    assert_eq!(Hash256::ZERO, Hash256([0u8; 32]));
    assert_eq!(
        Hash256::ZERO.to_hex(),
        "0000000000000000000000000000000000000000000000000000000000000000"
    );
}

#[test]
fn transaction_txid_deterministic() {
    let tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256([0x11; 32]),
                vout: 0,
            },
            script_sig: vec![0x47, 0x30],
            sequence: 0xFFFFFFFF,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value: 100_000,
            script_pubkey: vec![0x76, 0xa9, 0x14],
        }],
        lock_time: 0,
    };

    let txid1 = tx.txid();
    let txid2 = tx.txid();
    assert_eq!(txid1, txid2);
}

#[test]
fn merkle_root_odd_count_duplicates_last() {
    let hash1 = sha256d(b"tx1");
    let hash2 = sha256d(b"tx2");
    let hash3 = sha256d(b"tx3");

    let root_odd = merkle_root(&[hash1, hash2, hash3]);

    // Manually compute: should duplicate hash3
    let mut combined12 = [0u8; 64];
    combined12[..32].copy_from_slice(&hash1.0);
    combined12[32..].copy_from_slice(&hash2.0);
    let h12 = sha256d(&combined12);

    let mut combined33 = [0u8; 64];
    combined33[..32].copy_from_slice(&hash3.0);
    combined33[32..].copy_from_slice(&hash3.0);
    let h33 = sha256d(&combined33);

    let mut combined_final = [0u8; 64];
    combined_final[..32].copy_from_slice(&h12.0);
    combined_final[32..].copy_from_slice(&h33.0);
    let expected = sha256d(&combined_final);

    assert_eq!(root_odd, expected);
}
