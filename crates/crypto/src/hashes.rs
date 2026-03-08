//! Cryptographic hash functions for Bitcoin.
//!
//! Bitcoin uses SHA-256d (double SHA-256) for most hashes, including block hashes,
//! transaction IDs, and Merkle trees. HASH160 (RIPEMD-160(SHA-256(x))) is used for
//! address generation. BIP-340 introduces tagged hashes for Schnorr signatures.

use ripemd::Ripemd160;
use rustoshi_primitives::{Hash160, Hash256};
use sha2::{Digest, Sha256};

/// Double SHA-256: SHA256(SHA256(data))
/// This is used for block hashes, transaction IDs, and Merkle trees.
pub fn sha256d(data: &[u8]) -> Hash256 {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut result = [0u8; 32];
    result.copy_from_slice(&second);
    Hash256(result)
}

/// Single SHA-256.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let hash = Sha256::digest(data);
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    result
}

/// HASH160: RIPEMD160(SHA256(data))
/// Used for P2PKH and P2SH address generation.
pub fn hash160(data: &[u8]) -> Hash160 {
    let sha = Sha256::digest(data);
    let ripemd = Ripemd160::digest(sha);
    let mut result = [0u8; 20];
    result.copy_from_slice(&ripemd);
    Hash160(result)
}

/// BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data)
/// Pre-computing the tag hash midstate is an optimization but not required.
pub fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let tag_hash = sha256(tag.as_bytes());
    let mut engine = Sha256::new();
    engine.update(tag_hash);
    engine.update(tag_hash);
    engine.update(data);
    let result = engine.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Compute the SHA-256d Merkle root from a list of hashes.
/// If the list has an odd number of elements, duplicate the last one.
/// If the list is empty, return the zero hash.
pub fn merkle_root(hashes: &[Hash256]) -> Hash256 {
    if hashes.is_empty() {
        return Hash256::ZERO;
    }

    let mut current_level: Vec<Hash256> = hashes.to_vec();

    while current_level.len() > 1 {
        if !current_level.len().is_multiple_of(2) {
            let last = *current_level.last().unwrap();
            current_level.push(last);
        }

        let mut next_level = Vec::with_capacity(current_level.len() / 2);
        for pair in current_level.chunks(2) {
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&pair[0].0);
            combined[32..].copy_from_slice(&pair[1].0);
            next_level.push(sha256d(&combined));
        }
        current_level = next_level;
    }

    current_level[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256d_empty() {
        // SHA256d of empty bytes
        // Hash256::to_hex() returns display order (reversed from internal)
        let result = sha256d(b"");
        assert_eq!(
            result.to_hex(),
            "56944c5d3f98413ef45cf54545538103cc9f298e0575820ad3591376e2e0f65d"
        );
    }

    #[test]
    fn sha256_single() {
        // SHA256 of "hello"
        let result = sha256(b"hello");
        assert_eq!(
            hex::encode(result),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn hash160_known_pubkey() {
        // A known compressed public key and its HASH160
        // This is a common test vector
        let pubkey_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let pubkey = hex::decode(pubkey_hex).unwrap();
        let result = hash160(&pubkey);
        // This is the HASH160 of the generator point's compressed pubkey
        assert_eq!(result.to_hex(), "751e76e8199196d454941c45d1b3a323f1433bd6");
    }

    #[test]
    fn tagged_hash_bip340_challenge() {
        // BIP-340 test: tagged hash with "BIP0340/challenge"
        // This is a simplified test - the actual challenge hash includes more data
        let tag = "BIP0340/challenge";
        let data = [0u8; 32]; // 32 zero bytes
        let result = tagged_hash(tag, &data);
        // Verify it's deterministic and non-zero
        assert_ne!(result, [0u8; 32]);
        // Running again should give same result
        let result2 = tagged_hash(tag, &data);
        assert_eq!(result, result2);
    }

    #[test]
    fn merkle_root_empty() {
        let result = merkle_root(&[]);
        assert_eq!(result, Hash256::ZERO);
    }

    #[test]
    fn merkle_root_single() {
        // Single hash should be returned as-is
        let hash = sha256d(b"test");
        let result = merkle_root(&[hash]);
        assert_eq!(result, hash);
    }

    #[test]
    fn merkle_root_two() {
        // Two hashes: SHA256d(hash1 || hash2)
        let hash1 = sha256d(b"a");
        let hash2 = sha256d(b"b");
        let result = merkle_root(&[hash1, hash2]);

        // Manually compute expected
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&hash1.0);
        combined[32..].copy_from_slice(&hash2.0);
        let expected = sha256d(&combined);

        assert_eq!(result, expected);
    }

    #[test]
    fn merkle_root_three_duplicates_last() {
        // Three hashes: last one is duplicated
        let hash1 = sha256d(b"a");
        let hash2 = sha256d(b"b");
        let hash3 = sha256d(b"c");
        let result = merkle_root(&[hash1, hash2, hash3]);

        // Level 1: [H(1||2), H(3||3)]
        let mut combined12 = [0u8; 64];
        combined12[..32].copy_from_slice(&hash1.0);
        combined12[32..].copy_from_slice(&hash2.0);
        let h12 = sha256d(&combined12);

        let mut combined33 = [0u8; 64];
        combined33[..32].copy_from_slice(&hash3.0);
        combined33[32..].copy_from_slice(&hash3.0);
        let h33 = sha256d(&combined33);

        // Level 0: H(H(1||2) || H(3||3))
        let mut combined_final = [0u8; 64];
        combined_final[..32].copy_from_slice(&h12.0);
        combined_final[32..].copy_from_slice(&h33.0);
        let expected = sha256d(&combined_final);

        assert_eq!(result, expected);
    }

    #[test]
    fn merkle_root_genesis_block() {
        // Genesis block has only one transaction, so merkle root = txid
        // The genesis coinbase txid in internal byte order
        let genesis_txid = Hash256::from_hex(
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
        )
        .unwrap();
        let result = merkle_root(&[genesis_txid]);
        assert_eq!(result, genesis_txid);
    }

    #[test]
    fn sha256d_known_value() {
        // "abc" -> known double SHA256
        // Hash256::to_hex() returns display order (reversed from internal)
        let result = sha256d(b"abc");
        assert_eq!(
            result.to_hex(),
            "58636c3ec08c12d55aedda056d602d5bcca72d8df6a69b519b72d32dc2428b4f"
        );
    }
}
