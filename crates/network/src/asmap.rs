//! ASMap subsystem — Bitcoin Core-compatible autonomous system number (ASN) lookup.
//!
//! Provides a compressed mapping from IP address prefixes to Autonomous System
//! Numbers (ASNs). Uses a binary trie structure encoded as bytecode instructions
//! that are interpreted at runtime to find the ASN for a given IP address.
//!
//! The format is a bit-packed binary format where the entire mapping is treated
//! as a continuous sequence of bits. Instructions and their arguments are encoded
//! using variable numbers of bits and concatenated together without regard for
//! byte boundaries. The bits are stored in bytes using little-endian bit ordering.
//!
//! Core reference: `bitcoin-core/src/util/asmap.cpp` and `asmap.h`.

use rustoshi_crypto::sha256;

/// Maximum allowed asmap file size (8 MiB).
///
/// Core reference: `src/util/asmap.h` — enforced in `DecodeAsmap()`.
pub const MAX_ASMAP_FILESIZE: usize = 0x800_000; // 8 MiB

// ─────────────────────────────────────────────────────────────────────────────
// Bit-stream helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Sentinel value used to signal decoding errors or invalid data.
const INVALID: u32 = 0xFFFF_FFFF;

/// Read one bit from `bytes` at `bitpos` using little-endian bit ordering (LSB first).
///
/// Core reference: `ConsumeBitLE` in `asmap.cpp`.
#[inline]
fn consume_bit_le(bitpos: &mut usize, bytes: &[u8]) -> bool {
    let bit = (bytes[*bitpos / 8] >> (*bitpos % 8)) & 1;
    *bitpos += 1;
    bit != 0
}

/// Read one bit from `bytes` at `bitpos` using big-endian bit ordering (MSB first).
/// Used for IP address bits (network byte order).
///
/// Core reference: `ConsumeBitBE` in `asmap.cpp`.
#[inline]
fn consume_bit_be(bitpos: &mut u8, bytes: &[u8]) -> bool {
    let bit = (bytes[*bitpos as usize / 8] >> (7 - (*bitpos % 8))) & 1;
    *bitpos += 1;
    bit != 0
}

// ─────────────────────────────────────────────────────────────────────────────
// Variable-length integer decoder
// ─────────────────────────────────────────────────────────────────────────────

/// Variable-length integer decoder using a custom encoding scheme.
///
/// Encoding scheme (example: minval=100, bit_sizes=[4,2,2,3]):
/// - x in [100..115]: [0] + [4-bit BE encoding of (x-100)]
/// - x in [116..119]: [1,0] + [2-bit BE encoding of (x-116)]
/// - x in [120..123]: [1,1,0] + [2-bit BE encoding of (x-120)]
/// - x in [124..131]: [1,1,1] + [3-bit BE encoding of (x-124)]
///
/// Each number is encoded as:
/// - k "1"-bits (continuation bits), where k is the class
/// - a "0"-bit, unless k is the highest class
/// - bit_sizes[k] bits in big-endian encoding the position within the class
///
/// Core reference: `DecodeBits` in `asmap.cpp`.
fn decode_bits(bitpos: &mut usize, data: &[u8], minval: u32, bit_sizes: &[u8]) -> u32 {
    let endpos = data.len() * 8;
    let mut val = minval;
    let last_idx = bit_sizes.len() - 1;

    for (i, &bs) in bit_sizes.iter().enumerate() {
        // Read continuation bit (skip for last class)
        let bit = if i < last_idx {
            if *bitpos >= endpos {
                return INVALID; // EOF in exponent
            }
            consume_bit_le(bitpos, data)
        } else {
            false // Last class has no continuation bit
        };

        if bit {
            // Value doesn't fit in this class — subtract its range and try next
            val += 1 << bs;
        } else {
            // Decode position within this class in big-endian
            for b in 0..bs {
                if *bitpos >= endpos {
                    return INVALID; // EOF in mantissa
                }
                let bit_val = consume_bit_le(bitpos, data);
                if bit_val {
                    val += 1 << (bs - 1 - b);
                }
            }
            return val;
        }
    }
    INVALID // EOF in exponent
}

// ─────────────────────────────────────────────────────────────────────────────
// Instruction encoding constants
// ─────────────────────────────────────────────────────────────────────────────

// Instruction type: RETURN=[0], JUMP=[1,0], MATCH=[1,1,0], DEFAULT=[1,1,1]
// Encoded as DecodeBits(bitpos, data, 0, TYPE_BIT_SIZES).
const TYPE_BIT_SIZES: &[u8] = &[0, 0, 1];

// ASN encoding: encodes ASNs from 1 to ~16.7 million (start at 1, not 0).
// ASN 0 is reserved ("no match").
const ASN_BIT_SIZES: &[u8] = &[15, 16, 17, 18, 19, 20, 21, 22, 23, 24];

// MATCH argument: values in [2, 511]. Highest set bit = length, lower bits = pattern.
const MATCH_BIT_SIZES: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];

// JUMP offset: minimum value 17. Variable-length for large subtree skips.
const JUMP_BIT_SIZES: &[u8] = &[
    5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
    29, 30,
];

/// Instruction type.
///
/// Core reference: `enum class Instruction` in `asmap.cpp`.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u32)]
enum Instruction {
    Return = 0,
    Jump = 1,
    Match = 2,
    Default = 3,
}

impl Instruction {
    fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Return),
            1 => Some(Self::Jump),
            2 => Some(Self::Match),
            3 => Some(Self::Default),
            _ => None,
        }
    }
}

#[inline]
fn decode_type(bitpos: &mut usize, data: &[u8]) -> Option<Instruction> {
    let v = decode_bits(bitpos, data, 0, TYPE_BIT_SIZES);
    if v == INVALID {
        None
    } else {
        Instruction::from_u32(v)
    }
}

#[inline]
fn decode_asn(bitpos: &mut usize, data: &[u8]) -> u32 {
    decode_bits(bitpos, data, 1, ASN_BIT_SIZES)
}

#[inline]
fn decode_match(bitpos: &mut usize, data: &[u8]) -> u32 {
    decode_bits(bitpos, data, 2, MATCH_BIT_SIZES)
}

#[inline]
fn decode_jump(bitpos: &mut usize, data: &[u8]) -> u32 {
    decode_bits(bitpos, data, 17, JUMP_BIT_SIZES)
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Execute the ASMap bytecode to find the ASN for an IP address.
///
/// Returns the ASN (Autonomous System Number) for the given IP, or 0 if not found.
/// ASN 0 is the sentinel for "unknown / not in map" (AS0 is reserved per RFC 7607).
///
/// `ip` must be exactly 16 bytes (IPv4-mapped-in-IPv6 or full IPv6 address).
///
/// Core reference: `uint32_t Interpret(asmap, ip)` in `asmap.cpp`.
pub fn interpret(asmap: &[u8], ip: &[u8]) -> u32 {
    let mut pos: usize = 0;
    let endpos: usize = asmap.len() * 8;
    let mut ip_bit: u8 = 0;
    let ip_bits_end: u8 = (ip.len() * 8) as u8;
    let mut default_asn: u32 = 0;

    while pos < endpos {
        let opcode = match decode_type(&mut pos, asmap) {
            Some(op) => op,
            None => break, // Instruction straddles EOF
        };

        match opcode {
            Instruction::Return => {
                // Found leaf node — return the ASN
                let asn = decode_asn(&mut pos, asmap);
                if asn == INVALID {
                    break; // ASN straddles EOF
                }
                return asn;
            }
            Instruction::Jump => {
                // Binary branch: if IP bit is 1, jump forward; else continue
                let jump = decode_jump(&mut pos, asmap);
                if jump == INVALID {
                    break; // Jump offset straddles EOF
                }
                if ip_bit == ip_bits_end {
                    break; // No input bits left
                }
                if (jump as i64) >= (endpos as i64 - pos as i64) {
                    break; // Jumping past EOF
                }
                if consume_bit_be(&mut ip_bit, ip) {
                    pos += jump as usize; // Bit = 1: skip to right subtree
                }
                // Bit = 0: fall through to left subtree
            }
            Instruction::Match => {
                // Compare multiple IP bits against a pattern
                let match_val = decode_match(&mut pos, asmap);
                if match_val == INVALID {
                    break; // Match bits straddle EOF
                }
                // Bit width of match_val gives (length + 1); lower bits are the pattern
                let matchlen = (u32::BITS - match_val.leading_zeros() - 1) as usize;
                if ((ip_bits_end - ip_bit) as usize) < matchlen {
                    break; // Not enough input bits
                }
                for bit in 0..matchlen {
                    if consume_bit_be(&mut ip_bit, ip)
                        != (((match_val >> (matchlen - 1 - bit)) & 1) != 0)
                    {
                        return default_asn; // Pattern mismatch — use default
                    }
                }
                // Pattern matched — continue execution
            }
            Instruction::Default => {
                // Update the default ASN for subsequent MATCH failures
                let asn = decode_asn(&mut pos, asmap);
                if asn == INVALID {
                    break; // ASN straddles EOF
                }
                default_asn = asn;
            }
        }
    }
    // Reached EOF without RETURN, or aborted — should have been caught by SanityCheckAsmap.
    // Return 0 (unknown) rather than panic in production.
    debug_assert!(false, "interpret: reached EOF without RETURN — asmap not sanity-checked");
    0
}

/// Validate ASMap trie structure by simulating all possible execution paths.
///
/// Ensures well-formed bytecode, valid jumps, proper termination.
/// Returns `true` if valid, `false` if malformed.
///
/// `bits` is the number of input bits expected (128 for IPv6, 32 for IPv4-only maps).
///
/// Core reference: `bool SanityCheckAsmap(asmap, bits)` in `asmap.cpp`.
pub fn sanity_check_asmap(asmap: &[u8], bits: i32) -> bool {
    let mut pos: usize = 0;
    let endpos: usize = asmap.len() * 8;
    // Stack of (jump_target_bit_offset, bits_remaining_at_target)
    let mut jumps: Vec<(usize, i32)> = Vec::with_capacity(bits as usize);
    let mut prev_opcode = Instruction::Jump; // Sentinel — not DEFAULT
    let mut had_incomplete_match = false;
    let mut bits = bits;

    while pos != endpos {
        // A jump target must not land in the middle of the previous instruction
        if !jumps.is_empty() && pos >= jumps.last().unwrap().0 {
            return false;
        }

        let opcode = match decode_type(&mut pos, asmap) {
            Some(op) => op,
            None => return false, // Instruction straddles EOF
        };

        match opcode {
            Instruction::Return => {
                // RETURN immediately after DEFAULT is redundant — could be combined
                if prev_opcode == Instruction::Default {
                    return false;
                }
                let asn = decode_asn(&mut pos, asmap);
                if asn == INVALID {
                    return false; // ASN straddles EOF
                }
                if jumps.is_empty() {
                    // Nothing more to execute
                    if endpos - pos > 7 {
                        return false; // Excessive padding
                    }
                    // All remaining bits must be zero padding
                    let pad_start = pos;
                    while pos != endpos {
                        if consume_bit_le(&mut pos, asmap) {
                            return false; // Nonzero padding bit
                        }
                    }
                    let _ = pad_start;
                    return true; // Valid
                } else {
                    // Continue execution at the queued jump target
                    let (target, bits_at_target) = jumps.pop().unwrap();
                    if pos != target {
                        return false; // Unreachable code between RETURN and jump target
                    }
                    bits = bits_at_target;
                    prev_opcode = Instruction::Jump; // Reset
                }
            }
            Instruction::Jump => {
                let jump = decode_jump(&mut pos, asmap);
                if jump == INVALID {
                    return false; // Jump offset straddles EOF
                }
                if (jump as i64) > (endpos as i64 - pos as i64) {
                    return false; // Jump out of range
                }
                if bits == 0 {
                    return false; // Consuming bits past end of input
                }
                bits -= 1;
                let jump_offset = pos + jump as usize;
                if !jumps.is_empty() && jump_offset >= jumps.last().unwrap().0 {
                    return false; // Intersecting jumps
                }
                jumps.push((jump_offset, bits));
                prev_opcode = Instruction::Jump;
            }
            Instruction::Match => {
                let match_val = decode_match(&mut pos, asmap);
                if match_val == INVALID {
                    return false; // Match bits straddle EOF
                }
                let matchlen = (u32::BITS - match_val.leading_zeros() - 1) as i32;
                if prev_opcode != Instruction::Match {
                    had_incomplete_match = false;
                }
                // Within a sequence of matches, at most one may be incomplete (<8 bits)
                if matchlen < 8 && had_incomplete_match {
                    return false;
                }
                had_incomplete_match = matchlen < 8;
                if bits < matchlen {
                    return false; // Consuming bits past end of input
                }
                bits -= matchlen;
                prev_opcode = Instruction::Match;
            }
            Instruction::Default => {
                // Two consecutive DEFAULTs could be combined — reject as malformed
                if prev_opcode == Instruction::Default {
                    return false;
                }
                let asn = decode_asn(&mut pos, asmap);
                if asn == INVALID {
                    return false; // ASN straddles EOF
                }
                prev_opcode = Instruction::Default;
            }
        }
    }
    false // Reached EOF without RETURN
}

/// Check standard asmap data (128-bit IPv6 input).
///
/// Core reference: `bool CheckStandardAsmap(data)` in `asmap.cpp`.
pub fn check_standard_asmap(data: &[u8]) -> bool {
    if !sanity_check_asmap(data, 128) {
        tracing::warn!("Sanity check of asmap data failed");
        return false;
    }
    true
}

/// Load and validate an ASMap binary file from disk.
///
/// Returns the raw bytes on success, or an empty Vec on error.
/// Rejects files larger than `MAX_ASMAP_FILESIZE` (8 MiB).
///
/// Core reference: `std::vector<std::byte> DecodeAsmap(path)` in `asmap.cpp`.
pub fn decode_asmap(path: &std::path::Path) -> Vec<u8> {
    match std::fs::metadata(path) {
        Ok(meta) => {
            if meta.len() as usize > MAX_ASMAP_FILESIZE {
                tracing::warn!(
                    "asmap file {} is too large ({} bytes, max {})",
                    path.display(),
                    meta.len(),
                    MAX_ASMAP_FILESIZE
                );
                return Vec::new();
            }
        }
        Err(e) => {
            tracing::warn!("Failed to stat asmap file {}: {}", path.display(), e);
            return Vec::new();
        }
    }

    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!("Failed to open asmap file {}: {}", path.display(), e);
            return Vec::new();
        }
    };

    tracing::info!(
        "Opened asmap file {} ({} bytes) from disk",
        path.display(),
        data.len()
    );

    if !check_standard_asmap(&data) {
        tracing::warn!(
            "Sanity check of asmap file {} failed",
            path.display()
        );
        return Vec::new();
    }

    data
}

/// Compute SHA256 of ASMap data for versioning and consistency checks.
///
/// Returns the first 8 hex characters (32 bits) of the SHA256 hash.
/// Used for the startup log line.
///
/// Core reference: `AsmapVersion` in `asmap.cpp` (returns full SHA256).
pub fn asmap_version_hex(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    let hash = sha256(data);
    hex::encode(&hash[..4]) // First 8 hex chars = 4 bytes
}

/// Compute full SHA256 of ASMap data (32 bytes).
///
/// Core reference: `uint256 AsmapVersion(data)` in `asmap.cpp`.
pub fn asmap_version(data: &[u8]) -> [u8; 32] {
    sha256(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─────────────────────────────────────────────────────────────────────────
    // Minimal hand-crafted asmap for unit tests
    //
    // A single RETURN instruction returning ASN 1:
    //   Instruction type RETURN:
    //     TYPE_BIT_SIZES = [0, 0, 1].
    //     Class 0 (bit_size=0): reads 1 continuation bit (not last class), if 0 → RETURN.
    //     So bit 0 = 0.
    //   ASN encoding:
    //     ASN_BIT_SIZES = [15, 16, ...], minval = 1.
    //     Class 0 (bit_size=15): reads 1 continuation bit (not last class), if 0 → class 0.
    //     Then reads 15 big-endian bits for (asn - 1). ASN 1 → value 0 → 15 zero bits.
    //     So bit 1 = 0 (continuation), bits 2..16 = all zeros (15-bit mantissa).
    //   Total: 17 bits → 3 bytes (bits 0..23), with 7 zero padding bits.
    //   byte[0] (bits 0..7 LE) = 0x00
    //   byte[1] (bits 8..15 LE) = 0x00
    //   byte[2] (bits 16..23 LE) = 0x00 (bit 16 is last mantissa bit=0, bits 17..23 are padding zeros)
    // ─────────────────────────────────────────────────────────────────────────

    /// Build a minimal valid asmap that returns ASN 1 for any IP.
    fn minimal_asmap_asn1() -> Vec<u8> {
        // RETURN (1 LE bit=0) + ASN=1 (class 0 continuation=0, 15-bit mantissa=0)
        // Total: 17 bits → 3 bytes, all zeros (7 zero padding bits in last byte).
        vec![0x00, 0x00, 0x00]
    }

    #[test]
    fn test_interpret_returns_asn1() {
        let asmap = minimal_asmap_asn1();
        // Any IP, any length — RETURN is immediate
        let ip = [0u8; 16];
        let asn = interpret(&asmap, &ip);
        assert_eq!(asn, 1, "minimal asmap (RETURN ASN=1) should return 1 for any IP");
    }

    #[test]
    fn test_sanity_check_minimal_asmap() {
        let asmap = minimal_asmap_asn1();
        assert!(
            sanity_check_asmap(&asmap, 128),
            "minimal valid asmap should pass sanity check"
        );
    }

    #[test]
    fn test_sanity_check_empty_fails() {
        // Empty file: no RETURN instruction → invalid
        assert!(!sanity_check_asmap(&[], 128), "empty asmap should fail sanity check");
    }

    #[test]
    fn test_check_standard_asmap() {
        let asmap = minimal_asmap_asn1();
        assert!(check_standard_asmap(&asmap), "minimal asmap should pass check_standard_asmap");
    }

    #[test]
    fn test_asmap_version_hex_nonempty() {
        let asmap = minimal_asmap_asn1();
        let hex = asmap_version_hex(&asmap);
        assert_eq!(hex.len(), 8, "asmap_version_hex should return 8 hex chars");
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()), "should be hex");
    }

    #[test]
    fn test_asmap_version_hex_empty() {
        let hex = asmap_version_hex(&[]);
        assert!(hex.is_empty(), "empty data should return empty hex");
    }

    #[test]
    fn test_max_asmap_filesize_constant() {
        assert_eq!(MAX_ASMAP_FILESIZE, 8_388_608, "MAX_ASMAP_FILESIZE should be 8 MiB");
    }

    /// Verify decode_bits works for a simple case: RETURN encoding.
    /// RETURN is DecodeBits(pos, data, 0, [0,0,1]).
    /// Class 0 has bit_size=0: read continuation bit (=0 for first class in [0,0,1]),
    /// then 0 mantissa bits → val = 0.
    #[test]
    fn test_decode_type_return() {
        // First bit is 0 (RETURN in class 0 of [0,0,1])
        let data = [0x00u8];
        let mut pos = 0usize;
        let t = decode_type(&mut pos, &data);
        assert_eq!(t, Some(Instruction::Return));
    }

    /// Verify that ASN 1 is decoded as 1.
    #[test]
    fn test_decode_asn_one() {
        // ASN_BIT_SIZES = [15, 16, ...], minval = 1.
        // ASN 1: (1-1)=0, fits in class 0 (0..2^15-1).
        // Encoding: continuation_bit=0 (class 0), then 15 big-endian bits = all zeros.
        // Total: 16 bits = 2 bytes = 0x00 0x00.
        let data = [0x00u8, 0x00u8];
        let mut pos = 0usize;
        let asn = decode_asn(&mut pos, &data);
        assert_eq!(asn, 1, "ASN encoding of 1 should decode back to 1");
        assert_eq!(pos, 16, "should consume 16 bits for ASN 1");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Core reference test vectors
    //
    // From `bitcoin-core/src/test/netbase_tests.cpp::asmap_test_vectors`.
    // Randomly generated encoded ASMap with 128 ranges, up to 20-bit AS numbers.
    // ─────────────────────────────────────────────────────────────────────────

    /// The reference asmap data from Bitcoin Core's netbase_tests.cpp.
    fn core_reference_asmap() -> Vec<u8> {
        hex::decode(concat!(
            "fd38d50f7d5d665357f64bba6bfc190d6078a7e68e5d3ac032edf47f8b5755f8788",
            "1bfd3633d9aa7c1fa279b36fe26c63bbc9de44e0f04e5a382d8e1cddbe1c26653b",
            "c939d4327f287e8b4d1f8aff33176787cb0ff7cb28e3fdaef0f8f47357f801c9f7",
            "ff7a99f7f9c9f99de7f3156ae00f23eb27a303bc486aa3ccc31ec19394c2f8a53d",
            "ddea3cc56257f3b7e9b1f488be9c1137db823759aa4e071eef2e984aaf97b52d5f",
            "88d0f373dd190fe45e06efef1df7278be680a73a74c76db4dd910f1d30752c57fe",
            "2bc9f079f1a1e1b036c2a69219f11c5e11980a3fa51f4f82d36373de73b1863a8c",
            "27e36ae0e4f705be3d76ecff038a75bc0f92ba7e7f6f4080f1c47c34d095367ecf",
            "4406c1e3bbc17ba4d6f79ea3f031b876799ac268b1e0ea9babf0f9a8e5f6c55e36",
            "3c6363df46afc696d7afceaf49b6e62df9e9dc27e70664cafe5c53df66dd0b8237",
            "678ada90e73f05ec60e6f6e96c3cbb1ea2f9dece115d5bdba1033e53662a7d72a2",
            "9477b5beb35710591d3e23e5f0379baea62ffdee535bcdf879cbf69b88d7ea37c8",
            "015381cf63dc33d28f757a4a5e15d6a08"
        ))
        .expect("Core reference asmap hex is valid")
    }

    /// Parse an IPv6 address into its 16-byte representation.
    fn parse_ipv6(s: &str) -> [u8; 16] {
        let addr: std::net::Ipv6Addr = s.parse().expect("valid IPv6");
        addr.octets()
    }

    /// Core test vector: ASMAP_DATA + 19 known (IPv6, expected_asn) pairs.
    ///
    /// Source: `bitcoin-core/src/test/netbase_tests.cpp::asmap_test_vectors`.
    #[test]
    fn test_core_reference_vectors() {
        let asmap = core_reference_asmap();

        // Sanity check the reference data first
        assert!(
            check_standard_asmap(&asmap),
            "Core reference asmap should pass sanity check"
        );

        let vectors: &[(&str, u32)] = &[
            ("0:1559:183:3728:224c:65a5:62e6:e991", 961340),
            ("d0:d493:faa0:8609:e927:8b75:293c:f5a4", 961340),
            ("2a0:26f:8b2c:2ee7:c7d1:3b24:4705:3f7f", 693761),
            ("a77:7cd4:4be5:a449:89f2:3212:78c6:ee38", 0),
            ("1336:1ad6:2f26:4fe3:d809:7321:6e0d:4615", 672176),
            ("1d56:abd0:a52f:a8d5:d5a7:a610:581d:d792", 499880),
            ("378e:7290:54e5:bd36:4760:971c:e9b9:570d", 0),
            ("406c:820b:272a:c045:b74e:fc0a:9ef2:cecc", 248495),
            ("46c2:ae07:9d08:2d56:d473:2bc7:57e3:20ac", 248495),
            ("50d2:3db6:52fa:2e7:12ec:5bc4:1bd1:49f9", 124471),
            ("53e1:1812:ffa:dccf:f9f2:64be:75fa:795", 539993),
            ("544d:eeba:3990:35d1:ad66:f9a3:576d:8617", 374443),
            ("6a53:40dc:8f1d:3ffa:efeb:3aa3:df88:b94b", 435070),
            ("87aa:d1c9:9edb:91e7:aab1:9eb9:baa0:de18", 244121),
            ("9f00:48fa:88e3:4b67:a6f3:e6d2:5cc1:5be2", 862116),
            ("c49f:9cc6:86ad:ba08:4580:315e:dbd1:8a62", 969411),
            ("dff5:8021:61d:b17d:406d:7888:fdac:4a20", 969411),
            ("e888:6791:2960:d723:bcfd:47e1:2d8c:599f", 824019),
            ("ffff:d499:8c4b:4941:bc81:d5b9:b51e:85a8", 824019),
        ];

        for &(ip_str, expected_asn) in vectors {
            let ip = parse_ipv6(ip_str);
            let got = interpret(&asmap, &ip);
            assert_eq!(
                got, expected_asn,
                "IP {} expected ASN {} got {}",
                ip_str, expected_asn, got
            );
        }
    }
}
