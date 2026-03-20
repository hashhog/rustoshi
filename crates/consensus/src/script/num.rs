//! Bitcoin Script number encoding.
//!
//! Bitcoin Script uses a unique sign-magnitude representation for integers,
//! not two's complement. The MSB of the last byte is the sign bit:
//!
//! - Positive numbers: standard little-endian, MSB of last byte is 0
//! - Negative numbers: same magnitude in little-endian, MSB of last byte is 1
//! - Zero: empty byte array `[]`
//! - Negative zero: `[0x80]` (treated as false in boolean context)
//!
//! Script integers must be minimally encoded:
//! - No leading zero bytes unless needed for the sign bit
//! - The only valid encoding for zero is the empty array
//!
//! Most operations require numbers to fit in 4 bytes (±2^31-1).
//! CHECKLOCKTIMEVERIFY and CHECKSEQUENCEVERIFY allow 5 bytes.

use thiserror::Error;

/// Maximum byte length for most script number operations.
pub const DEFAULT_MAX_NUM_SIZE: usize = 4;

/// Maximum byte length for CLTV/CSV operations (allows 5-byte numbers).
pub const LOCKTIME_MAX_NUM_SIZE: usize = 5;

/// Errors that can occur during script number operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ScriptNumError {
    /// Number encoding exceeds the maximum allowed size.
    #[error("script number overflow: {0} bytes exceeds maximum {1}")]
    Overflow(usize, usize),

    /// Number is not minimally encoded (has unnecessary leading zeros).
    #[error("non-minimal script number encoding")]
    NonMinimal,
}

/// Decode a script number from bytes.
///
/// Script numbers use sign-magnitude representation:
/// - Empty array = 0
/// - Little-endian magnitude with sign bit in MSB of last byte
///
/// # Arguments
/// * `data` - The encoded script number bytes
/// * `require_minimal` - If true, reject non-minimal encodings (MINIMALDATA flag)
/// * `max_len` - Maximum allowed byte length (usually 4, 5 for CLTV/CSV)
///
/// # Returns
/// The decoded integer value, or an error if invalid.
///
/// # Example
/// ```
/// use rustoshi_consensus::script::num::decode_script_num;
///
/// // Empty = 0
/// assert_eq!(decode_script_num(&[], true, 4).unwrap(), 0);
///
/// // Single byte positive
/// assert_eq!(decode_script_num(&[0x7f], true, 4).unwrap(), 127);
///
/// // Single byte negative (0x80 is sign bit)
/// assert_eq!(decode_script_num(&[0x81], true, 4).unwrap(), -1);
///
/// // Two bytes for 128 (needs extra byte for sign bit)
/// assert_eq!(decode_script_num(&[0x80, 0x00], true, 4).unwrap(), 128);
/// ```
pub fn decode_script_num(data: &[u8], require_minimal: bool, max_len: usize) -> Result<i64, ScriptNumError> {
    if data.is_empty() {
        return Ok(0);
    }

    if data.len() > max_len {
        return Err(ScriptNumError::Overflow(data.len(), max_len));
    }

    // Check for non-minimal encoding if required
    if require_minimal {
        // If the most-significant-byte (minus the sign bit) is zero,
        // then we're not minimally encoded unless the next byte's high
        // bit would conflict with the sign bit.
        if let Some(&last) = data.last() {
            if last & 0x7f == 0 {
                // For single byte: both 0x00 and 0x80 (negative zero) are non-minimal
                // For multi-byte: non-minimal unless second-to-last has high bit set
                if data.len() <= 1 || data[data.len() - 2] & 0x80 == 0 {
                    return Err(ScriptNumError::NonMinimal);
                }
            }
        }
    }

    // Build the magnitude from little-endian bytes
    let mut result: i64 = 0;
    for (i, &byte) in data.iter().enumerate() {
        result |= (byte as i64) << (8 * i);
    }

    // Extract sign bit from the MSB of the last byte
    let last = data[data.len() - 1];
    if last & 0x80 != 0 {
        // Negative number: clear the sign bit and negate
        result &= !(0x80i64 << (8 * (data.len() - 1)));
        result = -result;
    }

    Ok(result)
}

/// Encode an integer as a script number.
///
/// Uses sign-magnitude representation:
/// - 0 encodes as empty array
/// - Positive numbers: little-endian, add extra 0x00 byte if high bit would be set
/// - Negative numbers: little-endian magnitude, set high bit of last byte
///
/// # Example
/// ```
/// use rustoshi_consensus::script::num::encode_script_num;
///
/// assert_eq!(encode_script_num(0), vec![]);
/// assert_eq!(encode_script_num(1), vec![0x01]);
/// assert_eq!(encode_script_num(-1), vec![0x81]);
/// assert_eq!(encode_script_num(127), vec![0x7f]);
/// assert_eq!(encode_script_num(128), vec![0x80, 0x00]);
/// assert_eq!(encode_script_num(-128), vec![0x80, 0x80]);
/// assert_eq!(encode_script_num(255), vec![0xff, 0x00]);
/// assert_eq!(encode_script_num(-255), vec![0xff, 0x80]);
/// ```
pub fn encode_script_num(value: i64) -> Vec<u8> {
    if value == 0 {
        return vec![];
    }

    let negative = value < 0;
    let mut abs_val = value.unsigned_abs();

    // Build magnitude in little-endian
    let mut result = Vec::with_capacity(8);
    while abs_val > 0 {
        result.push((abs_val & 0xff) as u8);
        abs_val >>= 8;
    }

    // Handle sign bit
    if let Some(last) = result.last_mut() {
        if *last & 0x80 != 0 {
            // High bit is set, need extra byte for sign
            if negative {
                result.push(0x80);
            } else {
                result.push(0x00);
            }
        } else if negative {
            // Set the sign bit in the last byte
            *last |= 0x80;
        }
    }

    result
}

/// Check if a byte array represents a "true" value in script boolean context.
///
/// In Bitcoin Script, false is defined as:
/// - Empty array
/// - Array of all zeros
/// - Negative zero: any byte array ending with 0x80 where all other bytes are 0x00
///
/// Everything else is true.
///
/// # Example
/// ```
/// use rustoshi_consensus::script::num::stack_bool;
///
/// assert!(!stack_bool(&[]));           // Empty is false
/// assert!(!stack_bool(&[0x00]));       // Zero is false
/// assert!(!stack_bool(&[0x00, 0x00])); // Multi-byte zero is false
/// assert!(!stack_bool(&[0x80]));       // Negative zero is false
/// assert!(stack_bool(&[0x01]));        // Non-zero is true
/// assert!(stack_bool(&[0x81]));        // -1 is true
/// ```
pub fn stack_bool(data: &[u8]) -> bool {
    for (i, &byte) in data.iter().enumerate() {
        if byte != 0 {
            // Check for negative zero: only the last byte can be 0x80,
            // and all preceding bytes must be 0x00
            if i == data.len() - 1 && byte == 0x80 {
                return false;
            }
            return true;
        }
    }
    // All zeros (or empty)
    false
}

/// Convert a boolean to a script stack element.
pub fn bool_to_stack(b: bool) -> Vec<u8> {
    if b {
        vec![0x01]
    } else {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_zero() {
        assert_eq!(decode_script_num(&[], true, 4).unwrap(), 0);
    }

    #[test]
    fn decode_positive_single_byte() {
        assert_eq!(decode_script_num(&[0x01], true, 4).unwrap(), 1);
        assert_eq!(decode_script_num(&[0x7f], true, 4).unwrap(), 127);
    }

    #[test]
    fn decode_negative_single_byte() {
        // -1 = 0x81 (1 with sign bit)
        assert_eq!(decode_script_num(&[0x81], true, 4).unwrap(), -1);
        // -127 = 0xff (127 with sign bit)
        assert_eq!(decode_script_num(&[0xff], true, 4).unwrap(), -127);
    }

    #[test]
    fn decode_positive_two_bytes() {
        // 128 needs two bytes: [0x80, 0x00] because 0x80 has high bit set
        assert_eq!(decode_script_num(&[0x80, 0x00], true, 4).unwrap(), 128);
        // 255 = [0xff, 0x00]
        assert_eq!(decode_script_num(&[0xff, 0x00], true, 4).unwrap(), 255);
        // 256 = [0x00, 0x01]
        assert_eq!(decode_script_num(&[0x00, 0x01], true, 4).unwrap(), 256);
    }

    #[test]
    fn decode_negative_two_bytes() {
        // -128 = [0x80, 0x80]
        assert_eq!(decode_script_num(&[0x80, 0x80], true, 4).unwrap(), -128);
        // -255 = [0xff, 0x80]
        assert_eq!(decode_script_num(&[0xff, 0x80], true, 4).unwrap(), -255);
        // -256 = [0x00, 0x81]
        assert_eq!(decode_script_num(&[0x00, 0x81], true, 4).unwrap(), -256);
    }

    #[test]
    fn decode_negative_zero() {
        // 0x80 is negative zero, decodes to 0
        assert_eq!(decode_script_num(&[0x80], true, 4).unwrap(), 0);
    }

    #[test]
    fn decode_overflow() {
        // 5 bytes should fail with max_len=4
        let data = [0x01, 0x02, 0x03, 0x04, 0x05];
        assert!(matches!(
            decode_script_num(&data, true, 4),
            Err(ScriptNumError::Overflow(5, 4))
        ));
    }

    #[test]
    fn decode_non_minimal() {
        // [0x00] should be [] (non-minimal encoding of 0)
        assert!(matches!(
            decode_script_num(&[0x00], true, 4),
            Err(ScriptNumError::NonMinimal)
        ));

        // [0x00, 0x00] is non-minimal
        assert!(matches!(
            decode_script_num(&[0x00, 0x00], true, 4),
            Err(ScriptNumError::NonMinimal)
        ));

        // [0x01, 0x00] is non-minimal (should be [0x01])
        assert!(matches!(
            decode_script_num(&[0x01, 0x00], true, 4),
            Err(ScriptNumError::NonMinimal)
        ));

        // [0x7f, 0x00] is non-minimal (should be [0x7f])
        assert!(matches!(
            decode_script_num(&[0x7f, 0x00], true, 4),
            Err(ScriptNumError::NonMinimal)
        ));

        // But [0x80, 0x00] is minimal (128 needs the extra byte)
        assert_eq!(decode_script_num(&[0x80, 0x00], true, 4).unwrap(), 128);
    }

    #[test]
    fn decode_non_minimal_allowed() {
        // With require_minimal=false, non-minimal encodings are accepted
        assert_eq!(decode_script_num(&[0x00], false, 4).unwrap(), 0);
        assert_eq!(decode_script_num(&[0x01, 0x00], false, 4).unwrap(), 1);
    }

    #[test]
    fn encode_zero() {
        assert_eq!(encode_script_num(0), vec![]);
    }

    #[test]
    fn encode_positive() {
        assert_eq!(encode_script_num(1), vec![0x01]);
        assert_eq!(encode_script_num(127), vec![0x7f]);
        assert_eq!(encode_script_num(128), vec![0x80, 0x00]);
        assert_eq!(encode_script_num(255), vec![0xff, 0x00]);
        assert_eq!(encode_script_num(256), vec![0x00, 0x01]);
    }

    #[test]
    fn encode_negative() {
        assert_eq!(encode_script_num(-1), vec![0x81]);
        assert_eq!(encode_script_num(-127), vec![0xff]);
        assert_eq!(encode_script_num(-128), vec![0x80, 0x80]);
        assert_eq!(encode_script_num(-255), vec![0xff, 0x80]);
        assert_eq!(encode_script_num(-256), vec![0x00, 0x81]);
    }

    #[test]
    fn encode_decode_round_trip() {
        let test_values = [
            0i64,
            1,
            -1,
            127,
            -127,
            128,
            -128,
            255,
            -255,
            256,
            -256,
            32767,
            -32767,
            32768,
            -32768,
            65535,
            -65535,
            2147483647,  // max 4-byte
            -2147483647, // min 4-byte (almost)
        ];

        for &value in &test_values {
            let encoded = encode_script_num(value);
            let decoded = decode_script_num(&encoded, true, 8).unwrap();
            assert_eq!(
                decoded, value,
                "Round-trip failed for {}: encoded {:?}, decoded {}",
                value, encoded, decoded
            );
        }
    }

    #[test]
    fn stack_bool_empty() {
        assert!(!stack_bool(&[]));
    }

    #[test]
    fn stack_bool_zero() {
        assert!(!stack_bool(&[0x00]));
        assert!(!stack_bool(&[0x00, 0x00]));
        assert!(!stack_bool(&[0x00, 0x00, 0x00]));
    }

    #[test]
    fn stack_bool_negative_zero() {
        // Negative zero is false
        assert!(!stack_bool(&[0x80]));
        // Multi-byte negative zero
        assert!(!stack_bool(&[0x00, 0x80]));
        assert!(!stack_bool(&[0x00, 0x00, 0x80]));
    }

    #[test]
    fn stack_bool_nonzero() {
        assert!(stack_bool(&[0x01]));
        assert!(stack_bool(&[0x7f]));
        assert!(stack_bool(&[0x81])); // -1
        assert!(stack_bool(&[0xff])); // -127
        assert!(stack_bool(&[0x00, 0x01])); // 256
        // 0x80 somewhere other than last byte is nonzero
        assert!(stack_bool(&[0x80, 0x00])); // 128
    }

    #[test]
    fn bool_to_stack_values() {
        assert_eq!(bool_to_stack(true), vec![0x01]);
        assert_eq!(bool_to_stack(false), vec![]);
    }

    #[test]
    fn large_numbers() {
        // 5-byte numbers for CLTV/CSV
        let large = 0x7FFFFFFFFFi64; // max 5-byte positive
        let encoded = encode_script_num(large);
        assert_eq!(encoded.len(), 5);
        let decoded = decode_script_num(&encoded, true, 5).unwrap();
        assert_eq!(decoded, large);

        // Negative large
        let neg_large = -0x7FFFFFFFFFi64;
        let encoded_neg = encode_script_num(neg_large);
        assert_eq!(encoded_neg.len(), 5);
        let decoded_neg = decode_script_num(&encoded_neg, true, 5).unwrap();
        assert_eq!(decoded_neg, neg_large);
    }
}
