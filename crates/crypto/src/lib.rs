//! Rustoshi crypto crate
//!
//! Cryptographic primitives for Bitcoin: hashing, signing, verification, address encoding.
//!
//! This crate uses hardware-accelerated cryptographic operations when available:
//! - SHA-256: SHA-NI (x86_64), SHA2 (AArch64), or portable fallback
//! - secp256k1: Uses the rust-secp256k1 crate with assembly optimizations

pub mod address;
pub mod base58;
pub mod bech32;
pub mod hashes;
pub mod hwaccel;
pub mod keys;
pub mod sha256;
pub mod sighash;

pub use address::{Address, AddressError, Network};
pub use base58::{base58check_decode, base58check_encode, Base58Error};
pub use bech32::{
    bech32_decode, bech32_encode, convert_bits, decode_segwit_address, encode_segwit_address,
    Bech32Error, Bech32Variant,
};
pub use hashes::{hash160, merkle_root, sha256, sha256d, tagged_hash};
pub use hwaccel::{sha256_capabilities, Sha256Capabilities};
pub use sha256::sha256_implementation;
pub use keys::{
    ecdsa_sign, ecdsa_verify, generate_private_key, parse_compact_signature, parse_der_signature,
    parse_public_key, parse_secret_key, public_key_from_private, recover_message_pubkey,
    serialize_compact_signature, serialize_der_signature, serialize_pubkey_compressed,
    serialize_pubkey_uncompressed, sign_message_compact, signed_message_hash,
    BITCOIN_SIGNED_MESSAGE_MAGIC,
};
pub use sighash::{
    find_and_delete, legacy_sighash, p2wpkh_script_code, remove_codeseparators, segwit_v0_sighash,
    SigHashType, OP_CODESEPARATOR,
};

// Re-export secp256k1 types that are used in the public API
pub use secp256k1::{ecdsa::Signature, PublicKey, SecretKey};
