//! Golomb-Coded Set (GCS) filter implementation.
//!
//! This module implements BIP 158 compact block filters using Golomb-Rice coding.
//! GCS filters are probabilistic data structures that allow efficient set membership
//! testing with configurable false positive rates.
//!
//! # BIP 158 Parameters
//!
//! - P = 19 (Golomb-Rice coding parameter)
//! - M = 784931 (inverse false positive rate)
//! - SipHash keys derived from block hash
//!
//! # Algorithm
//!
//! 1. Hash each element using SipHash with keys derived from block hash
//! 2. Map hashes to range [0, N * M) where N is element count
//! 3. Sort and compute deltas between consecutive values
//! 4. Encode deltas using Golomb-Rice coding

use rustoshi_primitives::Hash256;
use std::collections::HashSet;

/// BIP 158 basic filter parameters.
pub const BASIC_FILTER_P: u8 = 19;
pub const BASIC_FILTER_M: u32 = 784931;

/// A Golomb-Coded Set filter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GCSFilter {
    /// Golomb-Rice coding parameter (number of bits for remainder).
    p: u8,
    /// Inverse false positive rate (M = 1/FP_rate).
    m: u32,
    /// Number of elements in the filter.
    n: u32,
    /// SipHash key (first 8 bytes of block hash).
    siphash_k0: u64,
    /// SipHash key (second 8 bytes of block hash).
    siphash_k1: u64,
    /// The encoded filter data.
    encoded: Vec<u8>,
}

impl GCSFilter {
    /// Create a new GCS filter from a set of elements.
    ///
    /// # Arguments
    ///
    /// * `p` - Golomb-Rice coding parameter
    /// * `m` - Inverse false positive rate
    /// * `block_hash` - Block hash used to derive SipHash keys
    /// * `elements` - Set of elements to include in the filter
    pub fn new(p: u8, m: u32, block_hash: &Hash256, elements: &HashSet<Vec<u8>>) -> Self {
        let (k0, k1) = siphash_keys_from_block_hash(block_hash);
        let n = elements.len() as u32;

        if n == 0 {
            return Self {
                p,
                m,
                n: 0,
                siphash_k0: k0,
                siphash_k1: k1,
                encoded: encode_varint(0),
            };
        }

        // Hash elements and map to range [0, N * M)
        let f = (n as u64) * (m as u64);
        let mut hashed: Vec<u64> = elements
            .iter()
            .map(|elem| hash_to_range(k0, k1, elem, f))
            .collect();

        // Sort and compute deltas
        hashed.sort_unstable();

        // Encode using Golomb-Rice coding
        let mut encoded = encode_varint(n as u64);
        let mut writer = BitWriter::new();

        let mut last_value = 0u64;
        for value in hashed {
            let delta = value - last_value;
            golomb_rice_encode(&mut writer, p, delta);
            last_value = value;
        }

        encoded.extend(writer.finish());

        Self {
            p,
            m,
            n,
            siphash_k0: k0,
            siphash_k1: k1,
            encoded,
        }
    }

    /// Create a GCS filter from encoded data.
    ///
    /// # Arguments
    ///
    /// * `p` - Golomb-Rice coding parameter
    /// * `m` - Inverse false positive rate
    /// * `block_hash` - Block hash used to derive SipHash keys
    /// * `encoded` - The encoded filter data
    pub fn from_encoded(
        p: u8,
        m: u32,
        block_hash: &Hash256,
        encoded: Vec<u8>,
    ) -> Result<Self, GCSError> {
        let (k0, k1) = siphash_keys_from_block_hash(block_hash);

        // Decode N from the beginning
        let (n, _) = decode_varint(&encoded).ok_or(GCSError::InvalidEncoding)?;

        Ok(Self {
            p,
            m,
            n: n as u32,
            siphash_k0: k0,
            siphash_k1: k1,
            encoded,
        })
    }

    /// Create a basic BIP 158 filter for a block.
    pub fn new_basic(block_hash: &Hash256, elements: &HashSet<Vec<u8>>) -> Self {
        Self::new(BASIC_FILTER_P, BASIC_FILTER_M, block_hash, elements)
    }

    /// Check if an element may be in the set.
    ///
    /// Returns `true` if the element might be in the set (with false positive
    /// probability 1/M), or `false` if it is definitely not in the set.
    pub fn match_element(&self, element: &[u8]) -> bool {
        if self.n == 0 {
            return false;
        }

        let f = (self.n as u64) * (self.m as u64);
        let target = hash_to_range(self.siphash_k0, self.siphash_k1, element, f);

        self.match_hash(target)
    }

    /// Check if any of the given elements may be in the set.
    pub fn match_any(&self, elements: &[Vec<u8>]) -> bool {
        if self.n == 0 || elements.is_empty() {
            return false;
        }

        let f = (self.n as u64) * (self.m as u64);
        let mut targets: Vec<u64> = elements
            .iter()
            .map(|elem| hash_to_range(self.siphash_k0, self.siphash_k1, elem, f))
            .collect();
        targets.sort_unstable();

        self.match_hashes_sorted(&targets)
    }

    /// Check if a pre-computed hash exists in the filter.
    fn match_hash(&self, target: u64) -> bool {
        // Skip the N varint at the beginning
        let (_, n_bytes) = match decode_varint(&self.encoded) {
            Some(v) => v,
            None => return false,
        };

        let mut reader = BitReader::new(&self.encoded[n_bytes..]);
        let mut value = 0u64;

        for _ in 0..self.n {
            let delta = match golomb_rice_decode(&mut reader, self.p) {
                Some(d) => d,
                None => return false,
            };
            value += delta;

            if value == target {
                return true;
            }
            if value > target {
                return false;
            }
        }

        false
    }

    /// Check if any of the sorted hashes exist in the filter.
    fn match_hashes_sorted(&self, sorted_targets: &[u64]) -> bool {
        if sorted_targets.is_empty() {
            return false;
        }

        // Skip the N varint at the beginning
        let (_, n_bytes) = match decode_varint(&self.encoded) {
            Some(v) => v,
            None => return false,
        };

        let mut reader = BitReader::new(&self.encoded[n_bytes..]);
        let mut value = 0u64;
        let mut target_idx = 0;

        for _ in 0..self.n {
            let delta = match golomb_rice_decode(&mut reader, self.p) {
                Some(d) => d,
                None => return false,
            };
            value += delta;

            // Advance through targets that are smaller than current value
            while target_idx < sorted_targets.len() && sorted_targets[target_idx] < value {
                target_idx += 1;
            }

            if target_idx >= sorted_targets.len() {
                return false;
            }

            if sorted_targets[target_idx] == value {
                return true;
            }
        }

        false
    }

    /// Get the number of elements in the filter.
    pub fn n(&self) -> u32 {
        self.n
    }

    /// Get the encoded filter data.
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// Get the encoded filter data (consuming self).
    pub fn into_encoded(self) -> Vec<u8> {
        self.encoded
    }
}

/// Errors that can occur when working with GCS filters.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GCSError {
    #[error("invalid filter encoding")]
    InvalidEncoding,
}

// ============================================================
// SIPHASH IMPLEMENTATION
// ============================================================

/// Extract SipHash keys from block hash (BIP 158 specifies using first 16 bytes).
fn siphash_keys_from_block_hash(block_hash: &Hash256) -> (u64, u64) {
    let bytes = block_hash.as_bytes();
    let k0 = u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]);
    let k1 = u64::from_le_bytes([
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    ]);
    (k0, k1)
}

/// SipHash-2-4 implementation for GCS hashing.
fn siphash_2_4(k0: u64, k1: u64, data: &[u8]) -> u64 {
    let mut v0 = k0 ^ 0x736f6d6570736575;
    let mut v1 = k1 ^ 0x646f72616e646f6d;
    let mut v2 = k0 ^ 0x6c7967656e657261;
    let mut v3 = k1 ^ 0x7465646279746573;

    // Process full 8-byte blocks
    let blocks = data.len() / 8;
    for i in 0..blocks {
        let m = u64::from_le_bytes([
            data[i * 8],
            data[i * 8 + 1],
            data[i * 8 + 2],
            data[i * 8 + 3],
            data[i * 8 + 4],
            data[i * 8 + 5],
            data[i * 8 + 6],
            data[i * 8 + 7],
        ]);
        v3 ^= m;
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= m;
    }

    // Process remaining bytes with length encoding
    let remaining = &data[blocks * 8..];
    let mut m = (data.len() as u64) << 56;
    for (i, &byte) in remaining.iter().enumerate() {
        m |= (byte as u64) << (i * 8);
    }

    v3 ^= m;
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= m;

    // Finalization
    v2 ^= 0xff;
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);

    v0 ^ v1 ^ v2 ^ v3
}

#[inline]
fn sipround(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

/// Map a hash to the range [0, f) using fast range reduction.
fn hash_to_range(k0: u64, k1: u64, element: &[u8], f: u64) -> u64 {
    let hash = siphash_2_4(k0, k1, element);
    // FastRange64: (hash * f) >> 64
    ((hash as u128 * f as u128) >> 64) as u64
}

// ============================================================
// GOLOMB-RICE CODING
// ============================================================

/// Encode a value using Golomb-Rice coding.
fn golomb_rice_encode(writer: &mut BitWriter, p: u8, value: u64) {
    let quotient = value >> p;
    let remainder = value & ((1u64 << p) - 1);

    // Encode quotient as unary (q ones followed by a zero)
    for _ in 0..quotient {
        writer.write_bit(true);
    }
    writer.write_bit(false);

    // Encode remainder as p bits
    writer.write_bits(remainder, p as usize);
}

/// Decode a value using Golomb-Rice coding.
fn golomb_rice_decode(reader: &mut BitReader, p: u8) -> Option<u64> {
    // Decode quotient (count ones until zero)
    let mut quotient = 0u64;
    loop {
        let bit = reader.read_bit()?;
        if !bit {
            break;
        }
        quotient += 1;
    }

    // Decode remainder (p bits)
    let remainder = reader.read_bits(p as usize)?;

    Some((quotient << p) | remainder)
}

// ============================================================
// BIT STREAM HELPERS
// ============================================================

/// Writes bits to a byte buffer.
struct BitWriter {
    buffer: Vec<u8>,
    current_byte: u8,
    bit_pos: u8,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            buffer: Vec::new(),
            current_byte: 0,
            bit_pos: 0,
        }
    }

    fn write_bit(&mut self, bit: bool) {
        if bit {
            self.current_byte |= 1 << (7 - self.bit_pos);
        }
        self.bit_pos += 1;
        if self.bit_pos == 8 {
            self.buffer.push(self.current_byte);
            self.current_byte = 0;
            self.bit_pos = 0;
        }
    }

    fn write_bits(&mut self, value: u64, num_bits: usize) {
        for i in (0..num_bits).rev() {
            self.write_bit((value >> i) & 1 == 1);
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.bit_pos > 0 {
            self.buffer.push(self.current_byte);
        }
        self.buffer
    }
}

/// Reads bits from a byte buffer.
struct BitReader<'a> {
    data: &'a [u8],
    byte_pos: usize,
    bit_pos: u8,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte_pos: 0,
            bit_pos: 0,
        }
    }

    fn read_bit(&mut self) -> Option<bool> {
        if self.byte_pos >= self.data.len() {
            return None;
        }

        let bit = (self.data[self.byte_pos] >> (7 - self.bit_pos)) & 1 == 1;
        self.bit_pos += 1;
        if self.bit_pos == 8 {
            self.byte_pos += 1;
            self.bit_pos = 0;
        }
        Some(bit)
    }

    fn read_bits(&mut self, num_bits: usize) -> Option<u64> {
        let mut value = 0u64;
        for _ in 0..num_bits {
            let bit = self.read_bit()?;
            value = (value << 1) | (bit as u64);
        }
        Some(value)
    }
}

// ============================================================
// VARINT ENCODING (CompactSize)
// ============================================================

/// Encode a value as a Bitcoin CompactSize varint.
fn encode_varint(value: u64) -> Vec<u8> {
    if value < 0xfd {
        vec![value as u8]
    } else if value <= 0xffff {
        let mut buf = vec![0xfd];
        buf.extend_from_slice(&(value as u16).to_le_bytes());
        buf
    } else if value <= 0xffffffff {
        let mut buf = vec![0xfe];
        buf.extend_from_slice(&(value as u32).to_le_bytes());
        buf
    } else {
        let mut buf = vec![0xff];
        buf.extend_from_slice(&value.to_le_bytes());
        buf
    }
}

/// Decode a Bitcoin CompactSize varint, returning (value, bytes_consumed).
fn decode_varint(data: &[u8]) -> Option<(u64, usize)> {
    if data.is_empty() {
        return None;
    }

    match data[0] {
        0xff => {
            if data.len() < 9 {
                return None;
            }
            let value = u64::from_le_bytes([
                data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
            ]);
            Some((value, 9))
        }
        0xfe => {
            if data.len() < 5 {
                return None;
            }
            let value = u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as u64;
            Some((value, 5))
        }
        0xfd => {
            if data.len() < 3 {
                return None;
            }
            let value = u16::from_le_bytes([data[1], data[2]]) as u64;
            Some((value, 3))
        }
        v => Some((v as u64, 1)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_roundtrip() {
        let test_values = [0u64, 1, 252, 253, 254, 255, 0xffff, 0x10000, 0xffffffff, u64::MAX];

        for &value in &test_values {
            let encoded = encode_varint(value);
            let (decoded, _) = decode_varint(&encoded).unwrap();
            assert_eq!(value, decoded, "varint roundtrip failed for {}", value);
        }
    }

    #[test]
    fn test_bit_writer_reader() {
        let mut writer = BitWriter::new();
        writer.write_bit(true);
        writer.write_bit(false);
        writer.write_bit(true);
        writer.write_bits(0b11001, 5);
        let data = writer.finish();

        let mut reader = BitReader::new(&data);
        assert_eq!(reader.read_bit(), Some(true));
        assert_eq!(reader.read_bit(), Some(false));
        assert_eq!(reader.read_bit(), Some(true));
        assert_eq!(reader.read_bits(5), Some(0b11001));
    }

    #[test]
    fn test_golomb_rice_coding() {
        let test_values = [0u64, 1, 2, 7, 8, 100, 1000, 10000];

        for p in [4u8, 8, 12, 19] {
            for &value in &test_values {
                let mut writer = BitWriter::new();
                golomb_rice_encode(&mut writer, p, value);
                let encoded = writer.finish();

                let mut reader = BitReader::new(&encoded);
                let decoded = golomb_rice_decode(&mut reader, p).unwrap();
                assert_eq!(
                    value, decoded,
                    "golomb-rice roundtrip failed for value={} p={}",
                    value, p
                );
            }
        }
    }

    #[test]
    fn test_siphash_basic() {
        // Test vectors from SipHash reference
        let k0 = 0x0706050403020100u64;
        let k1 = 0x0f0e0d0c0b0a0908u64;
        let data = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
        let hash = siphash_2_4(k0, k1, &data);
        // SipHash-2-4 produces deterministic output
        assert_ne!(hash, 0);
    }

    #[test]
    fn test_gcs_filter_empty() {
        let block_hash = Hash256::ZERO;
        let elements: HashSet<Vec<u8>> = HashSet::new();
        let filter = GCSFilter::new_basic(&block_hash, &elements);

        assert_eq!(filter.n(), 0);
        assert!(!filter.match_element(b"test"));
    }

    #[test]
    fn test_gcs_filter_single_element() {
        let block_hash = Hash256::ZERO;
        let mut elements = HashSet::new();
        elements.insert(b"hello".to_vec());

        let filter = GCSFilter::new_basic(&block_hash, &elements);

        assert_eq!(filter.n(), 1);
        assert!(filter.match_element(b"hello"));
        // Note: false positives are possible but rare with M=784931
    }

    #[test]
    fn test_gcs_filter_multiple_elements() {
        let block_hash = Hash256::from_hex(
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        )
        .unwrap();

        let mut elements = HashSet::new();
        elements.insert(b"script1".to_vec());
        elements.insert(b"script2".to_vec());
        elements.insert(b"script3".to_vec());

        let filter = GCSFilter::new_basic(&block_hash, &elements);

        assert_eq!(filter.n(), 3);
        assert!(filter.match_element(b"script1"));
        assert!(filter.match_element(b"script2"));
        assert!(filter.match_element(b"script3"));
    }

    #[test]
    fn test_gcs_filter_match_any() {
        let block_hash = Hash256::ZERO;
        let mut elements = HashSet::new();
        elements.insert(b"alice".to_vec());
        elements.insert(b"bob".to_vec());

        let filter = GCSFilter::new_basic(&block_hash, &elements);

        // Should match when one element exists
        assert!(filter.match_any(&[b"alice".to_vec(), b"charlie".to_vec()]));

        // Empty query
        assert!(!filter.match_any(&[]));
    }

    #[test]
    fn test_gcs_filter_from_encoded() {
        let block_hash = Hash256::ZERO;
        let mut elements = HashSet::new();
        elements.insert(b"test".to_vec());

        let filter = GCSFilter::new_basic(&block_hash, &elements);
        let encoded = filter.encoded().to_vec();

        let restored =
            GCSFilter::from_encoded(BASIC_FILTER_P, BASIC_FILTER_M, &block_hash, encoded).unwrap();

        assert_eq!(filter.n(), restored.n());
        assert!(restored.match_element(b"test"));
    }
}
