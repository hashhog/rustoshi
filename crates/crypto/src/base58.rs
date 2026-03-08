//! Base58Check encoding and decoding for Bitcoin addresses.
//!
//! Base58Check is used for legacy P2PKH and P2SH addresses. It uses the alphabet
//! `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz` (no 0, O, I, l
//! to avoid visual ambiguity).
//!
//! The encoding includes a 4-byte checksum (first 4 bytes of SHA256d(payload)).

use crate::hashes::sha256d;

/// The Base58 alphabet, ordered by value.
const BASE58_ALPHABET: &[u8; 58] =
    b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Lookup table: ASCII byte -> alphabet index (255 = invalid)
const BASE58_DECODE: [u8; 128] = {
    let mut table = [255u8; 128];
    let mut i = 0;
    while i < 58 {
        table[BASE58_ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    table
};

/// Error type for Base58Check decoding.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Base58Error {
    /// Invalid character in input string.
    #[error("invalid character: {0}")]
    InvalidCharacter(char),
    /// Checksum mismatch.
    #[error("checksum mismatch")]
    ChecksumMismatch,
    /// Data too short to contain a valid checksum.
    #[error("data too short")]
    TooShort,
}

/// Encode bytes to a Base58Check string.
///
/// # Steps
/// 1. Append 4-byte checksum: first 4 bytes of SHA256d(payload)
/// 2. Treat the payload+checksum as a big-endian unsigned integer
/// 3. Repeatedly divide by 58, collecting remainders (these index into the alphabet)
/// 4. The result characters are in reverse order, so reverse them
/// 5. For each leading 0x00 byte in the original payload, prepend a '1' character
pub fn base58check_encode(payload: &[u8]) -> String {
    // Step 1: Compute checksum and append
    let checksum = sha256d(payload);
    let mut data = Vec::with_capacity(payload.len() + 4);
    data.extend_from_slice(payload);
    data.extend_from_slice(&checksum.0[..4]);

    // Count leading zeros in original payload (for prepending '1's later)
    let leading_zeros = payload.iter().take_while(|&&b| b == 0).count();

    // Step 2-4: Convert to base58
    // Treat data as a big-endian number and repeatedly divide by 58
    let mut result = Vec::new();

    // Work on a mutable copy of the data as our "big integer"
    let mut num = data;

    while !num.is_empty() {
        // Remove leading zeros from our working number
        while !num.is_empty() && num[0] == 0 {
            num.remove(0);
        }
        if num.is_empty() {
            break;
        }

        // Divide the number by 58, keeping track of the remainder
        let mut remainder = 0u32;
        for byte in num.iter_mut() {
            let value = (remainder << 8) | (*byte as u32);
            *byte = (value / 58) as u8;
            remainder = value % 58;
        }

        result.push(BASE58_ALPHABET[remainder as usize]);
    }

    // Step 5: Prepend '1' for each leading zero byte in the original payload
    result.extend(std::iter::repeat_n(b'1', leading_zeros));

    // Reverse and convert to string
    result.reverse();
    String::from_utf8(result).expect("Base58 alphabet is ASCII")
}

/// Decode a Base58Check string back to bytes.
///
/// # Steps
/// 1. Map each character to its index in the alphabet (error on invalid chars)
/// 2. Treat the indices as digits of a base-58 number, convert to bytes
/// 3. For each leading '1' character, prepend a 0x00 byte
/// 4. Split off the last 4 bytes as the checksum
/// 5. Verify the checksum matches SHA256d(remaining_bytes)[..4]
/// 6. Return the remaining bytes (without checksum)
pub fn base58check_decode(s: &str) -> Result<Vec<u8>, Base58Error> {
    if s.is_empty() {
        return Err(Base58Error::TooShort);
    }

    // Count leading '1's (these represent leading zero bytes)
    let leading_ones = s.chars().take_while(|&c| c == '1').count();

    // Step 1: Convert characters to base58 indices
    let indices: Vec<u8> = s
        .chars()
        .map(|c| {
            if c as u32 >= 128 {
                return Err(Base58Error::InvalidCharacter(c));
            }
            let idx = BASE58_DECODE[c as usize];
            if idx == 255 {
                return Err(Base58Error::InvalidCharacter(c));
            }
            Ok(idx)
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Step 2: Convert from base58 to bytes
    // Start with zero and accumulate: num = num * 58 + digit
    let mut result: Vec<u8> = Vec::new();

    for &digit in &indices {
        // Multiply result by 58 and add the digit
        let mut carry = digit as u32;
        for byte in result.iter_mut().rev() {
            let value = (*byte as u32) * 58 + carry;
            *byte = (value & 0xff) as u8;
            carry = value >> 8;
        }
        while carry > 0 {
            result.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }

    // Step 3: Prepend leading zero bytes for each leading '1'
    let mut final_result = vec![0u8; leading_ones];
    final_result.extend(result);

    // Step 4: Split off checksum (last 4 bytes)
    if final_result.len() < 4 {
        return Err(Base58Error::TooShort);
    }
    let checksum_start = final_result.len() - 4;
    let payload = &final_result[..checksum_start];
    let checksum = &final_result[checksum_start..];

    // Step 5: Verify checksum
    let computed = sha256d(payload);
    if &computed.0[..4] != checksum {
        return Err(Base58Error::ChecksumMismatch);
    }

    // Step 6: Return payload without checksum
    Ok(payload.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_satoshi_address() {
        // Satoshi's genesis block address
        // Hash160: 62e907b15cbf27d5425399ebf6f0fb50ebb88f18
        // Version byte 0x00 (mainnet P2PKH)
        let hash160 = hex::decode("62e907b15cbf27d5425399ebf6f0fb50ebb88f18").unwrap();
        let mut payload = vec![0x00];
        payload.extend_from_slice(&hash160);

        let encoded = base58check_encode(&payload);
        assert_eq!(encoded, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
    }

    #[test]
    fn decode_satoshi_address() {
        let decoded = base58check_decode("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap();

        // Should be version byte + 20-byte hash
        assert_eq!(decoded.len(), 21);
        assert_eq!(decoded[0], 0x00); // mainnet P2PKH

        let expected_hash = hex::decode("62e907b15cbf27d5425399ebf6f0fb50ebb88f18").unwrap();
        assert_eq!(&decoded[1..], expected_hash.as_slice());
    }

    #[test]
    fn roundtrip_empty_payload() {
        // Edge case: just a version byte
        let payload = vec![0x00];
        let encoded = base58check_encode(&payload);
        let decoded = base58check_decode(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn roundtrip_leading_zeros() {
        // Payload with leading zeros
        let payload = vec![0x00, 0x00, 0x00, 0x01, 0x02, 0x03];
        let encoded = base58check_encode(&payload);
        let decoded = base58check_decode(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn decode_invalid_character() {
        let result = base58check_decode("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfN0"); // '0' is invalid
        assert!(matches!(result, Err(Base58Error::InvalidCharacter('0'))));
    }

    #[test]
    fn decode_invalid_checksum() {
        // Modify last character to corrupt checksum
        let result = base58check_decode("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb");
        assert!(matches!(result, Err(Base58Error::ChecksumMismatch)));
    }

    #[test]
    fn decode_too_short() {
        let result = base58check_decode("1A");
        assert!(matches!(result, Err(Base58Error::TooShort)));
    }

    #[test]
    fn encode_p2sh_address() {
        // Known P2SH address: 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy
        // This is hash160: b472a266d0bd89c13706a4132ccfb16f7c3b9fcb with version 0x05
        let hash160 = hex::decode("b472a266d0bd89c13706a4132ccfb16f7c3b9fcb").unwrap();
        let mut payload = vec![0x05];
        payload.extend_from_slice(&hash160);

        let encoded = base58check_encode(&payload);
        assert_eq!(encoded, "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy");
    }

    #[test]
    fn decode_p2sh_address() {
        let decoded = base58check_decode("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy").unwrap();

        assert_eq!(decoded.len(), 21);
        assert_eq!(decoded[0], 0x05); // mainnet P2SH

        let expected_hash = hex::decode("b472a266d0bd89c13706a4132ccfb16f7c3b9fcb").unwrap();
        assert_eq!(&decoded[1..], expected_hash.as_slice());
    }

    #[test]
    fn roundtrip_testnet_address() {
        // Testnet P2PKH uses version byte 0x6F
        let hash160 = hex::decode("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        let mut payload = vec![0x6F];
        payload.extend_from_slice(&hash160);

        let encoded = base58check_encode(&payload);
        let decoded = base58check_decode(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn encode_all_zeros() {
        // 21 zero bytes should produce 21 leading '1's plus some chars for the checksum
        let payload = vec![0u8; 21];
        let encoded = base58check_encode(&payload);

        // Should start with 21 '1's (one per leading zero byte)
        assert!(
            encoded.starts_with("111111111111111111111"),
            "Expected 21 leading '1's but got: {}",
            encoded
        );

        // Verify round-trip
        let decoded = base58check_decode(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }
}
