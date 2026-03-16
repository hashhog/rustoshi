//! BIP-32 Hierarchical Deterministic Key Derivation.
//!
//! This module implements the BIP-32 standard for hierarchical deterministic wallets,
//! allowing derivation of an entire tree of key pairs from a single master seed.

use hmac::{Hmac, Mac};
use rustoshi_crypto::hash160;
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

/// BIP-32 hardened child derivation flag.
///
/// Child indices >= 2^31 use hardened derivation, which uses the private key
/// as input, preventing public-key-only derivation of hardened children.
pub const HARDENED_FLAG: u32 = 0x80000000;

/// An extended private key (BIP-32).
///
/// Contains a private key along with the chain code needed for child key derivation.
/// Extended keys track their position in the derivation tree via depth, parent fingerprint,
/// and child number.
#[derive(Clone)]
pub struct ExtendedPrivKey {
    /// The secret key.
    pub secret_key: SecretKey,
    /// The chain code for deriving child keys.
    pub chain_code: [u8; 32],
    /// Depth in the derivation tree (master key is depth 0).
    pub depth: u8,
    /// First 4 bytes of the parent key's identifier (HASH160 of public key).
    pub parent_fingerprint: [u8; 4],
    /// Child number (index used to derive this key).
    pub child_number: u32,
}

impl std::fmt::Debug for ExtendedPrivKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtendedPrivKey")
            .field("depth", &self.depth)
            .field("parent_fingerprint", &hex::encode(self.parent_fingerprint))
            .field("child_number", &self.child_number)
            .field("chain_code", &hex::encode(self.chain_code))
            .field("secret_key", &"<hidden>")
            .finish()
    }
}

/// An extended public key (BIP-32).
///
/// Contains a public key along with the chain code needed for child key derivation.
/// Can only derive non-hardened child public keys.
#[derive(Clone, Debug)]
pub struct ExtendedPubKey {
    /// The public key.
    pub public_key: PublicKey,
    /// The chain code for deriving child keys.
    pub chain_code: [u8; 32],
    /// Depth in the derivation tree.
    pub depth: u8,
    /// First 4 bytes of the parent key's identifier.
    pub parent_fingerprint: [u8; 4],
    /// Child number (index used to derive this key).
    pub child_number: u32,
}

/// Wallet errors.
#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    /// Key derivation failed.
    #[error("key derivation error")]
    KeyDerivation,

    /// Insufficient funds to complete the transaction.
    #[error("insufficient funds: have {have}, need {need}")]
    InsufficientFunds {
        /// Amount available.
        have: u64,
        /// Amount required.
        need: u64,
    },

    /// Invalid address format.
    #[error("invalid address: {0}")]
    InvalidAddress(String),

    /// Transaction signing failed.
    #[error("signing error: {0}")]
    SigningError(String),

    /// I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Invalid seed length.
    #[error("invalid seed length: {0} (expected 16-64 bytes)")]
    InvalidSeedLength(usize),

    /// Cannot derive hardened child from public key.
    #[error("cannot derive hardened child from public key")]
    HardenedFromPublic,

    /// Invalid derivation path format.
    #[error("invalid derivation path: {0}")]
    InvalidPath(String),

    /// Cryptographic operation failed.
    #[error("crypto error: {0}")]
    Crypto(String),
}

impl ExtendedPrivKey {
    /// Generate a master key from a seed (BIP-32).
    ///
    /// The seed should be 16-64 bytes. BIP-39 mnemonic phrases produce a 64-byte seed.
    /// The master key is derived by computing HMAC-SHA512 with the key "Bitcoin seed".
    ///
    /// # Errors
    /// Returns an error if the seed is not 16-64 bytes, or if the derived key is invalid.
    pub fn from_seed(seed: &[u8]) -> Result<Self, WalletError> {
        if seed.len() < 16 || seed.len() > 64 {
            return Err(WalletError::InvalidSeedLength(seed.len()));
        }

        let mut mac =
            HmacSha512::new_from_slice(b"Bitcoin seed").map_err(|_| WalletError::KeyDerivation)?;
        mac.update(seed);
        let result = mac.finalize().into_bytes();

        let secret_key =
            SecretKey::from_slice(&result[..32]).map_err(|_| WalletError::KeyDerivation)?;
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&result[32..64]);

        Ok(Self {
            secret_key,
            chain_code,
            depth: 0,
            parent_fingerprint: [0; 4],
            child_number: 0,
        })
    }

    /// Derive a child key (BIP-32).
    ///
    /// For hardened derivation (child_number >= 2^31):
    ///   data = 0x00 || private_key || child_number (4 bytes BE)
    ///
    /// For normal derivation:
    ///   data = public_key (33 bytes) || child_number (4 bytes BE)
    ///
    /// HMAC-SHA512(chain_code, data) -> (key_material, new_chain_code)
    /// child_key = parse256(key_material) + parent_key (mod n)
    ///
    /// # Errors
    /// Returns an error if the derivation produces an invalid key (astronomically unlikely).
    pub fn derive_child(&self, child_number: u32) -> Result<Self, WalletError> {
        let secp = Secp256k1::new();
        let parent_pub = PublicKey::from_secret_key(&secp, &self.secret_key);
        let fingerprint = key_fingerprint(&parent_pub);

        let mut data = Vec::with_capacity(37);
        if child_number >= HARDENED_FLAG {
            // Hardened: use private key
            data.push(0x00);
            data.extend_from_slice(&self.secret_key.secret_bytes());
        } else {
            // Normal: use public key
            data.extend_from_slice(&parent_pub.serialize());
        }
        data.extend_from_slice(&child_number.to_be_bytes());

        let mut mac =
            HmacSha512::new_from_slice(&self.chain_code).map_err(|_| WalletError::KeyDerivation)?;
        mac.update(&data);
        let result = mac.finalize().into_bytes();

        let mut tweak_bytes = [0u8; 32];
        tweak_bytes.copy_from_slice(&result[..32]);

        // child = parent + tweak (mod n)
        let tweak = Scalar::from_be_bytes(tweak_bytes).map_err(|_| WalletError::KeyDerivation)?;
        let child_secret = self
            .secret_key
            .add_tweak(&tweak)
            .map_err(|_| WalletError::KeyDerivation)?;

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&result[32..64]);

        Ok(Self {
            secret_key: child_secret,
            chain_code,
            depth: self.depth.saturating_add(1),
            parent_fingerprint: fingerprint,
            child_number,
        })
    }

    /// Derive a key from a path like [84', 0', 0', 0, 0].
    ///
    /// The path is a slice of child indices. Hardened indices should have
    /// the HARDENED_FLAG (0x80000000) set.
    ///
    /// # Errors
    /// Returns an error if any derivation step fails.
    pub fn derive_path(&self, path: &[u32]) -> Result<Self, WalletError> {
        let mut key = self.clone();
        for &child in path {
            key = key.derive_child(child)?;
        }
        Ok(key)
    }

    /// Get the extended public key.
    pub fn to_public(&self) -> ExtendedPubKey {
        let secp = Secp256k1::new();
        ExtendedPubKey {
            public_key: PublicKey::from_secret_key(&secp, &self.secret_key),
            chain_code: self.chain_code,
            depth: self.depth,
            parent_fingerprint: self.parent_fingerprint,
            child_number: self.child_number,
        }
    }

    /// Get the key fingerprint (first 4 bytes of HASH160 of the public key).
    pub fn fingerprint(&self) -> [u8; 4] {
        let secp = Secp256k1::new();
        let pubkey = PublicKey::from_secret_key(&secp, &self.secret_key);
        key_fingerprint(&pubkey)
    }
}

impl ExtendedPubKey {
    /// Derive a non-hardened child public key.
    ///
    /// # Errors
    /// Returns an error if trying to derive a hardened child, or if derivation fails.
    pub fn derive_child(&self, child_number: u32) -> Result<Self, WalletError> {
        if child_number >= HARDENED_FLAG {
            return Err(WalletError::HardenedFromPublic);
        }

        let fingerprint = key_fingerprint(&self.public_key);

        let mut data = Vec::with_capacity(37);
        data.extend_from_slice(&self.public_key.serialize());
        data.extend_from_slice(&child_number.to_be_bytes());

        let mut mac =
            HmacSha512::new_from_slice(&self.chain_code).map_err(|_| WalletError::KeyDerivation)?;
        mac.update(&data);
        let result = mac.finalize().into_bytes();

        let mut tweak_bytes = [0u8; 32];
        tweak_bytes.copy_from_slice(&result[..32]);

        // child_pub = parent_pub + tweak * G
        let secp = Secp256k1::new();
        let tweak =
            SecretKey::from_slice(&tweak_bytes).map_err(|_| WalletError::KeyDerivation)?;
        let tweak_pub = PublicKey::from_secret_key(&secp, &tweak);
        let child_pub = self
            .public_key
            .combine(&tweak_pub)
            .map_err(|_| WalletError::KeyDerivation)?;

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&result[32..64]);

        Ok(Self {
            public_key: child_pub,
            chain_code,
            depth: self.depth.saturating_add(1),
            parent_fingerprint: fingerprint,
            child_number,
        })
    }

    /// Derive a key from a path of non-hardened indices.
    ///
    /// # Errors
    /// Returns an error if any index is hardened or if derivation fails.
    pub fn derive_path(&self, path: &[u32]) -> Result<Self, WalletError> {
        let mut key = self.clone();
        for &child in path {
            key = key.derive_child(child)?;
        }
        Ok(key)
    }

    /// Get the key fingerprint (first 4 bytes of HASH160 of the public key).
    pub fn fingerprint(&self) -> [u8; 4] {
        key_fingerprint(&self.public_key)
    }
}

/// Compute the fingerprint of a public key (first 4 bytes of HASH160).
fn key_fingerprint(pubkey: &PublicKey) -> [u8; 4] {
    let hash = hash160(&pubkey.serialize());
    let mut fp = [0u8; 4];
    fp.copy_from_slice(&hash.0[..4]);
    fp
}

/// Parse a BIP-32 derivation path string like "m/84'/0'/0'/0/0".
///
/// # Format
/// - Starts with "m" (master key)
/// - Each level separated by "/"
/// - Hardened indices denoted by "'" or "h" suffix
///
/// # Examples
/// - "m/84'/0'/0'/0/0" for BIP-84 first receiving address
/// - "m/44'/0'/0'/1/0" for BIP-44 first change address
///
/// # Returns
/// A vector of child indices with HARDENED_FLAG set for hardened levels.
pub fn parse_derivation_path(path: &str) -> Result<Vec<u32>, WalletError> {
    let path = path.trim();
    if path.is_empty() {
        return Ok(vec![]);
    }

    // Remove leading "m/" if present
    let path = path.strip_prefix("m/").unwrap_or(path);
    let path = path.strip_prefix("m").unwrap_or(path);

    if path.is_empty() {
        return Ok(vec![]);
    }

    let mut result = Vec::new();
    for segment in path.split('/') {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }

        let (index_str, hardened) = if let Some(s) = segment.strip_suffix('\'') {
            (s, true)
        } else if let Some(s) = segment.strip_suffix('h') {
            (s, true)
        } else if let Some(s) = segment.strip_suffix('H') {
            (s, true)
        } else {
            (segment, false)
        };

        let index: u32 = index_str
            .parse()
            .map_err(|_| WalletError::InvalidPath(format!("invalid index: {}", segment)))?;

        if index >= HARDENED_FLAG {
            return Err(WalletError::InvalidPath(format!(
                "index too large: {}",
                index
            )));
        }

        let child_number = if hardened {
            index | HARDENED_FLAG
        } else {
            index
        };
        result.push(child_number);
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    // BIP-32 Test Vector 1
    // Seed: 000102030405060708090a0b0c0d0e0f
    #[test]
    fn bip32_test_vector_1_master() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivKey::from_seed(&seed).unwrap();

        // Chain m
        // ext pub: xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8
        // ext prv: xprv9s21ZrQH143K3GJpoapnV8SFfuZcEQAgLNnG9X5X38kPpoxQqVCt6Gr9p3v7M5TnLvKt5GXS7LRMN8t8bxfGSqQsfMNvA8fKknKLCGUqEZz

        // The master private key should be:
        // e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35
        assert_eq!(
            hex::encode(master.secret_key.secret_bytes()),
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        );

        // Chain code: 873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508
        assert_eq!(
            hex::encode(master.chain_code),
            "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
        );

        assert_eq!(master.depth, 0);
        assert_eq!(master.parent_fingerprint, [0; 4]);
        assert_eq!(master.child_number, 0);
    }

    #[test]
    fn bip32_test_vector_1_m_0h() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivKey::from_seed(&seed).unwrap();

        // Chain m/0'
        let child = master.derive_child(0 | HARDENED_FLAG).unwrap();

        // Private key: edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea
        assert_eq!(
            hex::encode(child.secret_key.secret_bytes()),
            "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
        );

        // Chain code: 47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141
        assert_eq!(
            hex::encode(child.chain_code),
            "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"
        );

        assert_eq!(child.depth, 1);
        assert_eq!(child.child_number, 0 | HARDENED_FLAG);
    }

    #[test]
    fn bip32_test_vector_1_m_0h_1() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivKey::from_seed(&seed).unwrap();

        // Chain m/0'/1
        let child = master
            .derive_path(&[0 | HARDENED_FLAG, 1])
            .unwrap();

        // Private key: 3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368
        assert_eq!(
            hex::encode(child.secret_key.secret_bytes()),
            "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"
        );

        assert_eq!(child.depth, 2);
        assert_eq!(child.child_number, 1);
    }

    #[test]
    fn bip32_test_vector_1_m_0h_1_2h() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivKey::from_seed(&seed).unwrap();

        // Chain m/0'/1/2'
        let child = master
            .derive_path(&[0 | HARDENED_FLAG, 1, 2 | HARDENED_FLAG])
            .unwrap();

        // Private key: cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca
        assert_eq!(
            hex::encode(child.secret_key.secret_bytes()),
            "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca"
        );

        assert_eq!(child.depth, 3);
    }

    #[test]
    fn bip32_test_vector_1_m_0h_1_2h_2() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivKey::from_seed(&seed).unwrap();

        // Chain m/0'/1/2'/2
        let child = master
            .derive_path(&[0 | HARDENED_FLAG, 1, 2 | HARDENED_FLAG, 2])
            .unwrap();

        // From BIP-32 test vectors:
        // Private key: 0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4
        // Chain code: cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd
        assert_eq!(
            hex::encode(child.secret_key.secret_bytes()),
            "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4"
        );
        assert_eq!(
            hex::encode(child.chain_code),
            "cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd"
        );

        assert_eq!(child.depth, 4);
        assert_eq!(child.child_number, 2);
    }

    #[test]
    fn bip32_test_vector_1_full_path() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivKey::from_seed(&seed).unwrap();

        // Chain m/0'/1/2'/2/1000000000
        let child = master
            .derive_path(&[
                0 | HARDENED_FLAG,
                1,
                2 | HARDENED_FLAG,
                2,
                1000000000,
            ])
            .unwrap();

        // From BIP-32 test vectors:
        // Private key: 471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8
        // Chain code: c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e
        assert_eq!(
            hex::encode(child.secret_key.secret_bytes()),
            "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8"
        );
        assert_eq!(
            hex::encode(child.chain_code),
            "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e"
        );

        assert_eq!(child.depth, 5);
        assert_eq!(child.child_number, 1000000000);
    }

    // BIP-32 Test Vector 2
    // Seed: fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542
    #[test]
    fn bip32_test_vector_2_master() {
        let seed = hex::decode(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        ).unwrap();
        let master = ExtendedPrivKey::from_seed(&seed).unwrap();

        // Chain m - private key
        assert_eq!(
            hex::encode(master.secret_key.secret_bytes()),
            "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e"
        );

        assert_eq!(
            hex::encode(master.chain_code),
            "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689"
        );
    }

    #[test]
    fn bip32_test_vector_2_m_0() {
        let seed = hex::decode(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        ).unwrap();
        let master = ExtendedPrivKey::from_seed(&seed).unwrap();

        // Chain m/0
        let child = master.derive_child(0).unwrap();

        assert_eq!(
            hex::encode(child.secret_key.secret_bytes()),
            "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e"
        );
    }

    #[test]
    fn public_key_derivation() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivKey::from_seed(&seed).unwrap();

        // Derive m/0'/1 using private key
        let priv_derived = master.derive_path(&[0 | HARDENED_FLAG, 1]).unwrap();

        // Derive m/0'/1 public from m/0' public
        let m_0h = master.derive_child(0 | HARDENED_FLAG).unwrap();
        let m_0h_pub = m_0h.to_public();
        let pub_derived = m_0h_pub.derive_child(1).unwrap();

        // Public keys should match
        assert_eq!(
            priv_derived.to_public().public_key,
            pub_derived.public_key
        );
    }

    #[test]
    fn hardened_from_public_fails() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivKey::from_seed(&seed).unwrap();
        let master_pub = master.to_public();

        // Should fail to derive hardened child from public key
        let result = master_pub.derive_child(0 | HARDENED_FLAG);
        assert!(matches!(result, Err(WalletError::HardenedFromPublic)));
    }

    #[test]
    fn parse_derivation_path_bip84() {
        let path = parse_derivation_path("m/84'/0'/0'/0/0").unwrap();
        assert_eq!(
            path,
            vec![
                84 | HARDENED_FLAG,
                0 | HARDENED_FLAG,
                0 | HARDENED_FLAG,
                0,
                0
            ]
        );
    }

    #[test]
    fn parse_derivation_path_variants() {
        // With h suffix
        let path = parse_derivation_path("m/44h/0h/0h/1/5").unwrap();
        assert_eq!(
            path,
            vec![
                44 | HARDENED_FLAG,
                0 | HARDENED_FLAG,
                0 | HARDENED_FLAG,
                1,
                5
            ]
        );

        // Without leading m
        let path = parse_derivation_path("84'/0'/0'/0/0").unwrap();
        assert_eq!(
            path,
            vec![
                84 | HARDENED_FLAG,
                0 | HARDENED_FLAG,
                0 | HARDENED_FLAG,
                0,
                0
            ]
        );

        // Just m
        let path = parse_derivation_path("m").unwrap();
        assert_eq!(path, vec![]);

        // Empty
        let path = parse_derivation_path("").unwrap();
        assert_eq!(path, vec![]);
    }

    #[test]
    fn invalid_seed_length() {
        // Too short
        let result = ExtendedPrivKey::from_seed(&[0u8; 15]);
        assert!(matches!(result, Err(WalletError::InvalidSeedLength(15))));

        // Too long
        let result = ExtendedPrivKey::from_seed(&[0u8; 65]);
        assert!(matches!(result, Err(WalletError::InvalidSeedLength(65))));

        // Valid boundary cases
        let result = ExtendedPrivKey::from_seed(&[0u8; 16]);
        assert!(result.is_ok());

        let result = ExtendedPrivKey::from_seed(&[0u8; 64]);
        assert!(result.is_ok());
    }

    #[test]
    fn fingerprint_calculation() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivKey::from_seed(&seed).unwrap();

        let child = master.derive_child(0 | HARDENED_FLAG).unwrap();

        // Child's parent fingerprint should match master's fingerprint
        assert_eq!(child.parent_fingerprint, master.fingerprint());
    }

    #[test]
    fn depth_increments() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivKey::from_seed(&seed).unwrap();
        assert_eq!(master.depth, 0);

        let child1 = master.derive_child(0).unwrap();
        assert_eq!(child1.depth, 1);

        let child2 = child1.derive_child(0).unwrap();
        assert_eq!(child2.depth, 2);

        // Using derive_path
        let deep = master.derive_path(&[0, 1, 2, 3, 4]).unwrap();
        assert_eq!(deep.depth, 5);
    }
}
