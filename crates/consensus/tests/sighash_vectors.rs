//! Test harness for Bitcoin Core's sighash.json test vectors.
//!
//! Each test case verifies that the legacy sighash computation matches
//! the expected result from Bitcoin Core's test data.

use rustoshi_crypto::legacy_sighash;
use rustoshi_primitives::{Decodable, Hash256, Transaction};

/// Path to the sighash test vectors JSON file (relative to crate root at build time).
const SIGHASH_JSON: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/sighash.json");

/// Decode a hex string into bytes (no byte-order reversal).
fn hex_to_bytes(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("invalid hex \"{}\": {}", s, e))
}

#[test]
fn sighash_vectors() {
    let data = std::fs::read_to_string(SIGHASH_JSON)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", SIGHASH_JSON, e));

    let vectors: Vec<serde_json::Value> =
        serde_json::from_str(&data).expect("failed to parse sighash.json");

    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut skip = 0usize;

    for (i, entry) in vectors.iter().enumerate() {
        let arr = match entry.as_array() {
            Some(a) => a,
            None => {
                skip += 1;
                continue;
            }
        };

        // The first entry is a comment header (single-element array of strings).
        if arr.len() == 1 {
            skip += 1;
            continue;
        }

        if arr.len() != 5 {
            eprintln!("vector {}: unexpected length {}, skipping", i, arr.len());
            skip += 1;
            continue;
        }

        let raw_tx_hex = arr[0].as_str().expect("raw_tx should be string");
        let script_hex = arr[1].as_str().expect("script should be string");
        let input_index = arr[2].as_i64().expect("input_index should be integer") as usize;
        // hash_type is a signed 32-bit integer in the test vectors; cast to u32
        // to match Bitcoin Core's behavior (C++ reinterpret from int to uint32_t).
        let hash_type = arr[3].as_i64().expect("hash_type should be integer") as i32 as u32;
        let expected_hex = arr[4].as_str().expect("expected_hash should be string");

        // Deserialize the raw transaction.
        let tx_bytes = hex_to_bytes(raw_tx_hex);
        let tx = match Transaction::deserialize(&tx_bytes) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("vector {}: failed to deserialize tx: {}", i, e);
                fail += 1;
                continue;
            }
        };

        // Parse the script (subscript / scriptCode).
        let script = hex_to_bytes(script_hex);

        // Compute the legacy sighash.
        let result = legacy_sighash(&tx, input_index, &script, hash_type);

        // The expected hash in sighash.json is stored in display byte order
        // (little-endian / reversed from the raw SHA256d output), matching
        // Bitcoin Core's convention for printing transaction hashes.
        // Reverse the bytes so we compare against the raw SHA256d output order.
        let mut expected_bytes: [u8; 32] = hex_to_bytes(expected_hex)
            .try_into()
            .expect("expected hash should be 32 bytes");
        expected_bytes.reverse();
        let expected = Hash256(expected_bytes);

        if result == expected {
            pass += 1;
        } else {
            eprintln!(
                "FAIL vector {}: input_index={} hash_type={:#010x}\n  expected: {}\n  got:      {}",
                i,
                input_index,
                hash_type,
                hex::encode(expected.0),
                hex::encode(result.0),
            );
            fail += 1;
        }
    }

    eprintln!(
        "\nsighash vectors: {} passed, {} failed, {} skipped (total {})",
        pass,
        fail,
        skip,
        vectors.len()
    );

    assert_eq!(fail, 0, "{} sighash vectors failed", fail);
    assert!(pass > 0, "no sighash vectors were tested");
}
