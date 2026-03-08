//! Fixed-size hash types for Bitcoin.
//!
//! Bitcoin uses SHA-256d (double SHA-256) for most hashes, producing 32-byte results.
//! RIPEMD-160 is used for address hashes, producing 20-byte results.

use std::fmt;

/// Error type for hex string parsing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HexError {
    #[error("invalid hex string length: expected {expected}, got {got}")]
    InvalidLength { expected: usize, got: usize },
    #[error("invalid hex character at position {position}")]
    InvalidChar { position: usize },
}

/// A 256-bit hash (SHA-256d result), stored as 32 bytes in internal byte order.
///
/// # Byte Order
/// Bitcoin displays transaction and block hashes in reversed byte order compared
/// to how they are serialized on the wire. The internal representation stores
/// bytes in serialization (little-endian) order. The `from_hex` and `to_hex`
/// methods automatically reverse byte order for display.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Hash256(pub [u8; 32]);

impl Hash256 {
    /// A hash with all zero bytes.
    pub const ZERO: Self = Self([0u8; 32]);

    /// The length in bytes.
    pub const LEN: usize = 32;

    /// Create from a hex string (displayed byte order — reversed from internal).
    pub fn from_hex(s: &str) -> Result<Self, HexError> {
        if s.len() != 64 {
            return Err(HexError::InvalidLength {
                expected: 64,
                got: s.len(),
            });
        }

        let mut bytes = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let high = hex_char_to_nibble(chunk[0]).ok_or(HexError::InvalidChar { position: i * 2 })?;
            let low =
                hex_char_to_nibble(chunk[1]).ok_or(HexError::InvalidChar { position: i * 2 + 1 })?;
            // Reverse byte order: display order -> internal order
            bytes[31 - i] = (high << 4) | low;
        }

        Ok(Self(bytes))
    }

    /// Create from raw bytes (internal byte order, no reversal).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return the hash as a hex string in display order (reversed).
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for &byte in self.0.iter().rev() {
            s.push(nibble_to_hex_char(byte >> 4));
            s.push(nibble_to_hex_char(byte & 0x0f));
        }
        s
    }

    /// Return a reference to the raw internal bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Reverse the byte order (convert between internal and display order).
    pub fn reversed(&self) -> Self {
        let mut bytes = self.0;
        bytes.reverse();
        Self(bytes)
    }
}

impl fmt::Display for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash256({})", self.to_hex())
    }
}

impl AsRef<[u8]> for Hash256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for Hash256 {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// A 160-bit hash (RIPEMD-160 result).
///
/// Used primarily for Bitcoin addresses (P2PKH, P2SH).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Hash160(pub [u8; 20]);

impl Hash160 {
    /// A hash with all zero bytes.
    pub const ZERO: Self = Self([0u8; 20]);

    /// The length in bytes.
    pub const LEN: usize = 20;

    /// Create from a hex string (no byte reversal for Hash160).
    pub fn from_hex(s: &str) -> Result<Self, HexError> {
        if s.len() != 40 {
            return Err(HexError::InvalidLength {
                expected: 40,
                got: s.len(),
            });
        }

        let mut bytes = [0u8; 20];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let high = hex_char_to_nibble(chunk[0]).ok_or(HexError::InvalidChar { position: i * 2 })?;
            let low =
                hex_char_to_nibble(chunk[1]).ok_or(HexError::InvalidChar { position: i * 2 + 1 })?;
            bytes[i] = (high << 4) | low;
        }

        Ok(Self(bytes))
    }

    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    /// Return the hash as a hex string.
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(40);
        for &byte in self.0.iter() {
            s.push(nibble_to_hex_char(byte >> 4));
            s.push(nibble_to_hex_char(byte & 0x0f));
        }
        s
    }

    /// Return a reference to the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

impl fmt::Display for Hash160 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Debug for Hash160 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash160({})", self.to_hex())
    }
}

impl AsRef<[u8]> for Hash160 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 20]> for Hash160 {
    fn from(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }
}

/// Convert a hex character to its nibble value.
fn hex_char_to_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Convert a nibble value to its lowercase hex character.
fn nibble_to_hex_char(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'a' + nibble - 10) as char,
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash256_zero() {
        let hash = Hash256::ZERO;
        assert_eq!(
            hash.to_hex(),
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn hash256_from_hex_genesis_block() {
        // Bitcoin genesis block hash in display order
        let genesis_hash = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
        let hash = Hash256::from_hex(genesis_hash).unwrap();

        // The internal bytes should be reversed
        assert_eq!(hash.0[31], 0x00);
        assert_eq!(hash.0[30], 0x00);
        assert_eq!(hash.0[0], 0x6f);
        assert_eq!(hash.0[1], 0xe2);

        // Round-trip should work
        assert_eq!(hash.to_hex(), genesis_hash);
    }

    #[test]
    fn hash256_from_hex_invalid_length() {
        let result = Hash256::from_hex("0000");
        assert!(matches!(result, Err(HexError::InvalidLength { .. })));
    }

    #[test]
    fn hash256_from_hex_invalid_char() {
        let result = Hash256::from_hex(
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26g",
        );
        assert!(matches!(result, Err(HexError::InvalidChar { .. })));
    }

    #[test]
    fn hash256_reversed() {
        let hash = Hash256::from_hex(
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        )
        .unwrap();
        let reversed = hash.reversed();
        let back = reversed.reversed();
        assert_eq!(hash, back);
    }

    #[test]
    fn hash256_display() {
        let genesis_hash = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
        let hash = Hash256::from_hex(genesis_hash).unwrap();
        assert_eq!(format!("{}", hash), genesis_hash);
    }

    #[test]
    fn hash160_from_hex() {
        let hex = "62e907b15cbf27d5425399ebf6f0fb50ebb88f18";
        let hash = Hash160::from_hex(hex).unwrap();
        assert_eq!(hash.to_hex(), hex);
    }

    #[test]
    fn hash160_from_hex_invalid_length() {
        let result = Hash160::from_hex("0000");
        assert!(matches!(result, Err(HexError::InvalidLength { .. })));
    }

    #[test]
    fn hash256_uppercase_hex() {
        let lower = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
        let upper = "000000000019D6689C085AE165831E934FF763AE46A2A6C172B3F1B60A8CE26F";
        let hash_lower = Hash256::from_hex(lower).unwrap();
        let hash_upper = Hash256::from_hex(upper).unwrap();
        assert_eq!(hash_lower, hash_upper);
    }
}
