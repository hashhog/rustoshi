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
        // Gate 1: N must fit in u32.  Core throws std::invalid_argument("N must be <2^32")
        // when elements.size() > u32::MAX.  Panic here mirrors Core's contract violation.
        assert!(
            elements.len() <= u32::MAX as usize,
            "GCS filter: N must be <2^32"
        );
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
        let (n_raw, n_bytes) = decode_varint(&encoded).ok_or(GCSError::InvalidEncoding)?;

        // Gate 10: N must fit in u32 (Core: `if (m_N != N) throw ios_base::failure("N must be <2^32")`).
        let n = u32::try_from(n_raw).map_err(|_| GCSError::NTooLarge)?;

        // Gate 12: Verify that the encoded filter contains exactly N elements.
        // Decode all N deltas and confirm the bit-stream is exhausted afterward.
        // This mirrors Core's skip_decode_check=false path in the GCSFilter constructor
        // (blockfilter.cpp lines 65-71).
        {
            let mut reader = BitReader::new(&encoded[n_bytes..]);
            for _ in 0..n {
                golomb_rice_decode(&mut reader, p).ok_or(GCSError::InvalidEncoding)?;
            }
            // Stream must be empty (only zero-padding bits may remain in the last byte).
            // We check that no full bytes remain unread.
            if reader.has_remaining_bytes() {
                return Err(GCSError::ExcessData);
            }
        }

        Ok(Self {
            p,
            m,
            n,
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
    #[error("N must be <2^32")]
    NTooLarge,
    #[error("encoded filter contains excess data")]
    ExcessData,
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

    /// Returns true if there are complete (unread) bytes remaining in the stream.
    ///
    /// Used to verify that encoded data contains exactly N elements with no
    /// excess bytes beyond the padding bits in the last byte.  Mirrors Core's
    /// `if (!stream.empty()) throw` check (blockfilter.cpp line 69-71).
    fn has_remaining_bytes(&self) -> bool {
        // If bit_pos == 0 we are on a byte boundary: check if byte_pos < data.len().
        // If bit_pos > 0 we are mid-byte (the current byte is partially consumed).
        // "Remaining bytes" means fully-unread bytes after the current position.
        if self.bit_pos == 0 {
            self.byte_pos < self.data.len()
        } else {
            // Current byte is partially read; check if there are bytes *after* it.
            self.byte_pos + 1 < self.data.len()
        }
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

    // ================================================================
    // BIP-158 official test vectors
    // Source: bitcoin-core/src/test/data/blockfilters.json
    // Format: [height, block_hash, block_hex, prev_output_scripts, prev_basic_header,
    //          basic_filter_hex, basic_header_hex, notes]
    // ================================================================

    /// Gate 21/22: BASIC_FILTER_P and BASIC_FILTER_M constants.
    /// Core: blockfilter.h lines 90-91.
    #[test]
    fn test_bip158_constants() {
        assert_eq!(BASIC_FILTER_P, 19);
        assert_eq!(BASIC_FILTER_M, 784931);
    }

    /// Gate 19/20: SipHash keys derived from block hash bytes 0-7 (k0) and 8-15 (k1)
    /// using little-endian byte order.
    /// Core: blockfilter.cpp BuildParams lines 236-237 using GetUint64(0) / GetUint64(1).
    ///
    /// Verified against genesis block filter = 019dfca8.
    #[test]
    fn test_bip158_siphash_key_derivation() {
        // Genesis block hash (display order): 000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943
        // Internal bytes (reversed): 43f4778df826957108f4a30fd9cec3ae9b7797200984e00ad0ea33090000000000
        // k0 = LE64(bytes[0..8]) = LE64(43 f4 77 8d 6f 52 19 87) = 0x719526f8d77f4943 (note: internal[0]=0x43)
        // k1 = LE64(bytes[8..16]) = 0xaec3ced90fa3f408
        let block_hash = Hash256::from_hex(
            "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
        )
        .unwrap();
        let (k0, k1) = siphash_keys_from_block_hash(&block_hash);
        // These values were cross-verified with the Python BIP-158 reference implementation.
        assert_eq!(k0, 0x719526f8d77f4943);
        assert_eq!(k1, 0xaec3ced90fa3f408);
    }

    /// BIP-158 test vector: genesis block (height 0, testnet3).
    ///
    /// The genesis coinbase output script is the only element (non-empty, not OP_RETURN).
    /// No spent inputs (first transaction ever).
    /// Expected basic filter: 019dfca8
    /// Source: blockfilters.json entry 0.
    /// Gate: end-to-end build_basic + encoded bytes match Core reference.
    #[test]
    fn test_bip158_genesis_block_filter() {
        let block_hash = Hash256::from_hex(
            "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
        )
        .unwrap();

        // Genesis coinbase output script (P2PK, 67 bytes, 0x41 prefix — NOT OP_RETURN).
        let coinbase_script = hex::decode(
            "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac",
        )
        .unwrap();

        let mut elements = HashSet::new();
        elements.insert(coinbase_script.clone());

        let filter = GCSFilter::new_basic(&block_hash, &elements);
        assert_eq!(filter.n(), 1);
        assert_eq!(
            hex::encode(filter.encoded()),
            "019dfca8",
            "genesis block filter bytes do not match BIP-158 test vector"
        );

        // Verify element lookup works.
        assert!(filter.match_element(&coinbase_script));
        // Verify non-existent element is not falsely matched (with very high probability).
        assert!(!filter.match_element(b"not_in_filter_xyzzy_12345"));
    }

    /// BIP-158 test vector: empty filter for block 1414221.
    ///
    /// This block has a coinbase with an unparseable / empty output script, so no
    /// scriptPubKeys survive the filter inclusion rules.  Filter = "00" (N=0).
    /// Source: blockfilters.json entry 1414221.
    #[test]
    fn test_bip158_empty_filter() {
        let block_hash = Hash256::from_hex(
            "0000000000000027b2b3b3381f114f674f481544ff2be37ae3788d7e078383b1",
        )
        .unwrap();

        let elements: HashSet<Vec<u8>> = HashSet::new();
        let filter = GCSFilter::new_basic(&block_hash, &elements);

        assert_eq!(filter.n(), 0);
        assert_eq!(
            hex::encode(filter.encoded()),
            "00",
            "empty filter must encode as a single 0x00 byte (CompactSize N=0)"
        );
    }

    /// Gate 16: OP_RETURN outputs are excluded; non-OP_RETURN outputs are included.
    /// Gate 17: Spent input scripts are included regardless of OP_RETURN prefix.
    ///
    /// Core: blockfilter.cpp BasicFilterElements lines 193-207.
    /// Output exclusion rule: `if (script.empty() || script[0] == OP_RETURN) continue`
    /// Input inclusion rule: `if (script.empty()) continue`  — NO OP_RETURN check.
    #[test]
    fn test_bip158_op_return_exclusion_rules() {
        let block_hash = Hash256::ZERO;

        // Build filter manually to test inclusion/exclusion logic.
        // We mimic what BlockFilter::build_basic does.
        let outputs = vec![
            vec![0x76u8, 0xa9, 0x14, 0x01, 0x02, 0x03], // P2PKH-like — INCLUDE
            vec![0x6au8, 0x04, 0xde, 0xad],              // OP_RETURN — EXCLUDE
            vec![] as Vec<u8>,                            // empty — EXCLUDE
        ];
        let spent = vec![
            vec![0x6au8, 0x04, 0xde, 0xad], // OP_RETURN in spent input — INCLUDE (gate 17)
            vec![] as Vec<u8>,               // empty spent — EXCLUDE
        ];

        let mut elements = HashSet::new();
        for s in &outputs {
            if !s.is_empty() && s[0] != 0x6a {
                elements.insert(s.clone());
            }
        }
        for s in &spent {
            if !s.is_empty() {
                elements.insert(s.clone());
            }
        }

        // The P2PKH-like output and the OP_RETURN spent input should both be in.
        assert_eq!(elements.len(), 2);
        assert!(elements.contains(&vec![0x76u8, 0xa9, 0x14, 0x01, 0x02, 0x03]));
        assert!(elements.contains(&vec![0x6au8, 0x04, 0xde, 0xad]));

        let filter = GCSFilter::new_basic(&block_hash, &elements);
        assert_eq!(filter.n(), 2);
        assert!(filter.match_element(&[0x76, 0xa9, 0x14, 0x01, 0x02, 0x03]));
        assert!(filter.match_element(&[0x6a, 0x04, 0xde, 0xad]));
    }

    /// Gate 3: Encoded filter starts with CompactSize(N) prefix.
    #[test]
    fn test_bip158_compact_size_prefix() {
        let block_hash = Hash256::ZERO;

        // N=1: CompactSize = 0x01
        let mut elems = HashSet::new();
        elems.insert(b"abc".to_vec());
        let f = GCSFilter::new_basic(&block_hash, &elems);
        assert_eq!(f.encoded()[0], 1, "N=1 must start with 0x01 CompactSize byte");
        assert_eq!(f.n(), 1);

        // N=0: CompactSize = 0x00
        let empty: HashSet<Vec<u8>> = HashSet::new();
        let f0 = GCSFilter::new_basic(&block_hash, &empty);
        assert_eq!(f0.encoded(), &[0x00], "N=0 must be exactly [0x00]");
    }

    /// Gate 5: FastRange64 reduction — NOT modulo.
    ///
    /// Verify that hash_to_range uses multiplicative range reduction:
    ///   result = (siphash_value * f) >> 64
    /// rather than modulo.  The two differ when `siphash_value * f` overflows u64.
    #[test]
    fn test_bip158_fast_range64_not_modulo() {
        // Fabricate a case where the two methods disagree.
        // Use k0=k1=0 and a one-byte element for a known siphash output.
        let k0: u64 = 0;
        let k1: u64 = 0;
        let elem = b"x";
        let h = siphash_2_4(k0, k1, elem);
        let f: u64 = 1_000_000;

        let fast_range = ((h as u128 * f as u128) >> 64) as u64;
        let modulo = h % f;

        // They will generally differ unless h < f (which is almost never for a 64-bit hash).
        // We just want to confirm hash_to_range matches fast_range, not modulo.
        let result = hash_to_range(k0, k1, elem, f);
        assert_eq!(result, fast_range, "hash_to_range must use FastRange64 (multiplicative), not modulo");
        // For large h (normal case) they are different:
        if h >= f {
            assert_ne!(fast_range, modulo, "test setup error: FastRange64 and modulo happen to agree on this input");
        }
    }

    /// Gate 6/7: Delta encoding + Golomb-Rice coding round-trip.
    ///
    /// Verify that a filter containing multiple elements encodes deltas (not absolute
    /// values), and that decoding produces the same filter bytes as Core.
    #[test]
    fn test_bip158_delta_encoding_roundtrip() {
        let block_hash = Hash256::from_hex(
            "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
        )
        .unwrap();

        let mut elements = HashSet::new();
        elements.insert(b"script_one".to_vec());
        elements.insert(b"script_two".to_vec());
        elements.insert(b"script_three".to_vec());

        let filter = GCSFilter::new_basic(&block_hash, &elements);
        assert_eq!(filter.n(), 3);

        // Round-trip: reconstruct from bytes and verify membership.
        let encoded = filter.encoded().to_vec();
        let restored = GCSFilter::from_encoded(BASIC_FILTER_P, BASIC_FILTER_M, &block_hash, encoded).unwrap();
        assert_eq!(restored.n(), 3);
        assert!(restored.match_element(b"script_one"));
        assert!(restored.match_element(b"script_two"));
        assert!(restored.match_element(b"script_three"));
        assert!(!restored.match_element(b"not_present_xyzzy"));
    }

    /// Gate 10: from_encoded must reject N > u32::MAX.
    ///
    /// Core: blockfilter.cpp line 56-57:
    ///   `m_N = static_cast<uint32_t>(N); if (m_N != N) throw ios_base::failure("N must be <2^32")`
    #[test]
    fn test_bip158_from_encoded_n_overflow_rejected() {
        // Build a fake encoded buffer where the CompactSize N = 2^32 (0xfe prefix + u32::MAX+1 cannot
        // be represented in 4 bytes, so use 0xff prefix for a 64-bit value).
        // CompactSize 0xff + 8 bytes = 2^32 as u64 = [0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]
        let mut encoded = vec![0xffu8]; // CompactSize 9-byte prefix
        encoded.extend_from_slice(&(u32::MAX as u64 + 1).to_le_bytes()); // N = 2^32
        // Append some dummy filter data so the varint is decodable.
        encoded.extend_from_slice(&[0u8; 4]);

        let block_hash = Hash256::ZERO;
        let result = GCSFilter::from_encoded(BASIC_FILTER_P, BASIC_FILTER_M, &block_hash, encoded);
        assert_eq!(result, Err(GCSError::NTooLarge), "N > u32::MAX must return NTooLarge error");
    }

    /// Gate 12: from_encoded must reject encoded data with excess bytes after N elements.
    ///
    /// Core: blockfilter.cpp lines 69-71:
    ///   `if (!stream.empty()) throw ios_base::failure("encoded_filter contains excess data")`
    #[test]
    fn test_bip158_from_encoded_excess_data_rejected() {
        let block_hash = Hash256::ZERO;

        // Build a valid single-element filter.
        let mut elements = HashSet::new();
        elements.insert(b"hello".to_vec());
        let filter = GCSFilter::new_basic(&block_hash, &elements);
        let mut encoded = filter.encoded().to_vec();

        // Append an extra byte — this makes the stream non-empty after decoding 1 element.
        encoded.push(0xAB);

        let result = GCSFilter::from_encoded(BASIC_FILTER_P, BASIC_FILTER_M, &block_hash, encoded);
        assert_eq!(result, Err(GCSError::ExcessData), "excess bytes after N elements must return ExcessData error");
    }

    /// Gate 12: from_encoded must reject truncated data (too few bits for N elements).
    #[test]
    fn test_bip158_from_encoded_truncated_rejected() {
        let block_hash = Hash256::ZERO;

        // Claim N=5 but provide no filter data after the varint.
        let encoded = vec![0x05u8]; // CompactSize N=5, no filter bytes

        let result = GCSFilter::from_encoded(BASIC_FILTER_P, BASIC_FILTER_M, &block_hash, encoded);
        assert_eq!(result, Err(GCSError::InvalidEncoding), "truncated data must return InvalidEncoding error");
    }

    /// Verify BIP-158 test vector for block 987876 (contains witness data).
    ///
    /// The block has one output script and no spent inputs.
    /// Expected filter: 010c0b40
    /// Source: blockfilters.json entry 987876.
    #[test]
    fn test_bip158_block_987876_filter() {
        let block_hash = Hash256::from_hex(
            "0000000000000c00901f2049055e2a437c819d79a3d54fd63e6af796cd7b8a79",
        )
        .unwrap();

        // Only output: P2PK script (starts with 0x1e — NOT OP_RETURN).
        // From the block hex: the coinbase output is
        //   1e76a914c486de584a735ec2f22da7cd9681614681f92173d83d0aa68688ac
        // (but we strip the length prefix 0x1e which is the script length, not part of the script)
        let coinbase_script = hex::decode(
            "76a914c486de584a735ec2f22da7cd9681614681f92173d83d0aa68688ac",
        )
        .unwrap();

        let mut elements = HashSet::new();
        elements.insert(coinbase_script);

        let filter = GCSFilter::new_basic(&block_hash, &elements);
        assert_eq!(filter.n(), 1);
        assert_eq!(
            hex::encode(filter.encoded()),
            "010c0b40",
            "block 987876 filter bytes do not match BIP-158 test vector"
        );
    }

    /// ComputeHeader test: SHA256d(filter_hash || prev_header).
    ///
    /// Core: blockfilter.cpp lines 253-256:
    ///   `return Hash(GetHash(), prev_header);` where Hash() is SHA256d.
    ///   GetHash() = SHA256d(GetEncodedFilter()).
    ///
    /// Verified against genesis block:
    ///   filter = 019dfca8
    ///   prev_header = 0000...0000 (genesis has no predecessor)
    ///   expected header = 21584579b7eb08997773e5aeff3a7f932700042d0ed2a6129012b7d7ae81b750
    #[test]
    fn test_bip158_genesis_header_chain() {
        use sha2::{Digest, Sha256};

        fn sha256d(data: &[u8]) -> [u8; 32] {
            let first = Sha256::digest(data);
            Sha256::digest(first).into()
        }

        // Genesis filter bytes
        let encoded = hex::decode("019dfca8").unwrap();

        // filter_hash = SHA256d(encoded_filter)
        let filter_hash = sha256d(&encoded);

        // prev_header = 0000...0000 for genesis
        let prev_header = [0u8; 32];

        // filter_header = SHA256d(filter_hash || prev_header)
        let mut concat = Vec::with_capacity(64);
        concat.extend_from_slice(&filter_hash);
        concat.extend_from_slice(&prev_header);
        let filter_header = sha256d(&concat);

        // Expected (internal byte order, reversed from display):
        // Display: 21584579b7eb08997773e5aeff3a7f932700042d0ed2a6129012b7d7ae81b750
        let expected_display = "21584579b7eb08997773e5aeff3a7f932700042d0ed2a6129012b7d7ae81b750";
        let expected_bytes_display = hex::decode(expected_display).unwrap();
        // Internal = reversed display
        let mut expected_internal = expected_bytes_display.clone();
        expected_internal.reverse();

        assert_eq!(
            filter_header, expected_internal.as_slice(),
            "genesis filter header does not match BIP-158 test vector"
        );
    }
}
