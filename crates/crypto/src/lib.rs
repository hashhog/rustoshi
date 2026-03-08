//! Rustoshi crypto crate
//!
//! Cryptographic primitives for Bitcoin: hashing, signing, verification.

pub mod hashes;
pub mod keys;

pub use hashes::{hash160, merkle_root, sha256, sha256d, tagged_hash};
pub use keys::{
    ecdsa_sign, ecdsa_verify, generate_private_key, parse_compact_signature, parse_der_signature,
    parse_public_key, parse_secret_key, public_key_from_private, serialize_compact_signature,
    serialize_der_signature, serialize_pubkey_compressed, serialize_pubkey_uncompressed,
};

// Re-export secp256k1 types that are used in the public API
pub use secp256k1::{ecdsa::Signature, PublicKey, SecretKey};
