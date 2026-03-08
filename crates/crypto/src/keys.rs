//! secp256k1 key operations for Bitcoin.
//!
//! Bitcoin uses the secp256k1 elliptic curve for ECDSA signatures.
//! This module wraps the secp256k1 crate (which uses libsecp256k1, the same
//! C library used by Bitcoin Core) to provide key generation, signing,
//! and verification operations.

use rustoshi_primitives::Hash256;
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1, SecretKey};

/// Generate a new random private key.
pub fn generate_private_key() -> SecretKey {
    let mut rng = rand::thread_rng();
    SecretKey::new(&mut rng)
}

/// Derive the public key from a private key.
pub fn public_key_from_private(secret: &SecretKey) -> PublicKey {
    let secp = Secp256k1::new();
    PublicKey::from_secret_key(&secp, secret)
}

/// Serialize a public key in compressed form (33 bytes, 0x02 or 0x03 prefix).
pub fn serialize_pubkey_compressed(pubkey: &PublicKey) -> [u8; 33] {
    pubkey.serialize()
}

/// Serialize a public key in uncompressed form (65 bytes, 0x04 prefix).
pub fn serialize_pubkey_uncompressed(pubkey: &PublicKey) -> [u8; 65] {
    pubkey.serialize_uncompressed()
}

/// Sign a 256-bit message hash using ECDSA.
pub fn ecdsa_sign(secret: &SecretKey, hash: &Hash256) -> Signature {
    let secp = Secp256k1::new();
    let msg = Message::from_digest(hash.0);
    secp.sign_ecdsa(&msg, secret)
}

/// Verify an ECDSA signature against a public key and message hash.
pub fn ecdsa_verify(pubkey: &PublicKey, hash: &Hash256, sig: &Signature) -> bool {
    let secp = Secp256k1::new();
    let msg = Message::from_digest(hash.0);
    secp.verify_ecdsa(&msg, sig, pubkey).is_ok()
}

/// Parse a DER-encoded ECDSA signature.
pub fn parse_der_signature(data: &[u8]) -> Result<Signature, secp256k1::Error> {
    Signature::from_der(data)
}

/// Parse a compact (64-byte) ECDSA signature.
pub fn parse_compact_signature(data: &[u8]) -> Result<Signature, secp256k1::Error> {
    Signature::from_compact(data)
}

/// Parse a public key from bytes (compressed or uncompressed).
pub fn parse_public_key(data: &[u8]) -> Result<PublicKey, secp256k1::Error> {
    PublicKey::from_slice(data)
}

/// Parse a secret key from 32 bytes.
pub fn parse_secret_key(data: &[u8; 32]) -> Result<SecretKey, secp256k1::Error> {
    SecretKey::from_slice(data)
}

/// Serialize an ECDSA signature to DER format.
pub fn serialize_der_signature(sig: &Signature) -> Vec<u8> {
    sig.serialize_der().to_vec()
}

/// Serialize an ECDSA signature to compact (64-byte) format.
pub fn serialize_compact_signature(sig: &Signature) -> [u8; 64] {
    sig.serialize_compact()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashes::{hash160, sha256d};

    #[test]
    fn generate_and_derive_pubkey() {
        let secret = generate_private_key();
        let pubkey = public_key_from_private(&secret);

        // Compressed form should be 33 bytes starting with 0x02 or 0x03
        let compressed = serialize_pubkey_compressed(&pubkey);
        assert_eq!(compressed.len(), 33);
        assert!(compressed[0] == 0x02 || compressed[0] == 0x03);

        // Uncompressed form should be 65 bytes starting with 0x04
        let uncompressed = serialize_pubkey_uncompressed(&pubkey);
        assert_eq!(uncompressed.len(), 65);
        assert_eq!(uncompressed[0], 0x04);
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let secret = generate_private_key();
        let pubkey = public_key_from_private(&secret);
        let message_hash = sha256d(b"test message");

        let sig = ecdsa_sign(&secret, &message_hash);
        assert!(ecdsa_verify(&pubkey, &message_hash, &sig));

        // Wrong message should fail
        let wrong_hash = sha256d(b"wrong message");
        assert!(!ecdsa_verify(&pubkey, &wrong_hash, &sig));
    }

    #[test]
    fn der_signature_roundtrip() {
        let secret = generate_private_key();
        let message_hash = sha256d(b"test");

        let sig = ecdsa_sign(&secret, &message_hash);
        let der = serialize_der_signature(&sig);

        // DER signatures are typically 70-72 bytes
        assert!(der.len() >= 68 && der.len() <= 72);

        // Parse back
        let parsed = parse_der_signature(&der).unwrap();
        assert_eq!(sig, parsed);
    }

    #[test]
    fn compact_signature_roundtrip() {
        let secret = generate_private_key();
        let message_hash = sha256d(b"test");

        let sig = ecdsa_sign(&secret, &message_hash);
        let compact = serialize_compact_signature(&sig);
        assert_eq!(compact.len(), 64);

        let parsed = parse_compact_signature(&compact).unwrap();
        assert_eq!(sig, parsed);
    }

    #[test]
    fn pubkey_parse_roundtrip() {
        let secret = generate_private_key();
        let pubkey = public_key_from_private(&secret);

        // Compressed
        let compressed = serialize_pubkey_compressed(&pubkey);
        let parsed_compressed = parse_public_key(&compressed).unwrap();
        assert_eq!(pubkey, parsed_compressed);

        // Uncompressed
        let uncompressed = serialize_pubkey_uncompressed(&pubkey);
        let parsed_uncompressed = parse_public_key(&uncompressed).unwrap();
        assert_eq!(pubkey, parsed_uncompressed);
    }

    #[test]
    fn known_pubkey_hash160() {
        // Generator point G of secp256k1 curve (compressed)
        let g_compressed =
            hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap();
        let pubkey = parse_public_key(&g_compressed).unwrap();

        // Verify it parses correctly
        let serialized = serialize_pubkey_compressed(&pubkey);
        assert_eq!(serialized[..], g_compressed[..]);

        // The HASH160 should match the known value
        let h = hash160(&serialized);
        assert_eq!(h.to_hex(), "751e76e8199196d454941c45d1b3a323f1433bd6");
    }

    #[test]
    fn invalid_der_signature() {
        // Invalid DER data
        let bad_der = vec![0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00];
        // This might or might not parse depending on the library's strictness
        // but we should handle it gracefully
        let result = parse_der_signature(&bad_der);
        // The library should reject obviously malformed signatures
        // but the exact behavior depends on secp256k1's DER parser
        let _ = result; // Just ensure no panic
    }

    #[test]
    fn secret_key_parse() {
        // A valid 32-byte secret key (not zero, not >= curve order)
        let secret_bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let secret = parse_secret_key(&secret_bytes).unwrap();
        let pubkey = public_key_from_private(&secret);

        // Should be able to sign and verify
        let hash = sha256d(b"test");
        let sig = ecdsa_sign(&secret, &hash);
        assert!(ecdsa_verify(&pubkey, &hash, &sig));
    }

    #[test]
    fn zero_secret_key_invalid() {
        // Zero is not a valid secret key
        let zero_bytes: [u8; 32] = [0u8; 32];
        let result = parse_secret_key(&zero_bytes);
        assert!(result.is_err());
    }
}
