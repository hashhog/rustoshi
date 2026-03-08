//! Bech32 and Bech32m encoding for SegWit addresses.
//!
//! BIP-173 defines Bech32 encoding for SegWit v0 addresses (P2WPKH, P2WSH).
//! BIP-350 defines Bech32m encoding for SegWit v1+ addresses (P2TR).
//!
//! The only difference between Bech32 and Bech32m is the checksum constant.

/// The Bech32 character set for encoding 5-bit values.
const BECH32_CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Lookup table: ASCII byte -> 5-bit value (255 = invalid)
const BECH32_DECODE: [u8; 128] = {
    let charset = BECH32_CHARSET.as_bytes();
    let mut table = [255u8; 128];
    let mut i = 0;
    while i < 32 {
        table[charset[i] as usize] = i as u8;
        i += 1;
    }
    table
};

/// Generator polynomial coefficients for Bech32 checksum.
const BECH32_GENERATOR: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

/// Checksum constant for Bech32 (BIP-173).
const BECH32_CONST: u32 = 1;

/// Checksum constant for Bech32m (BIP-350).
const BECH32M_CONST: u32 = 0x2bc830a3;

/// Bech32 encoding variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bech32Variant {
    /// BIP-173 Bech32, used for SegWit v0 (P2WPKH, P2WSH).
    Bech32,
    /// BIP-350 Bech32m, used for SegWit v1+ (P2TR).
    Bech32m,
}

/// Error type for Bech32 encoding/decoding.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Bech32Error {
    /// Invalid character in input string.
    #[error("invalid character: {0}")]
    InvalidCharacter(char),
    /// Missing separator ('1').
    #[error("missing separator")]
    MissingSeparator,
    /// Invalid checksum.
    #[error("invalid checksum")]
    InvalidChecksum,
    /// HRP (human-readable part) is empty or invalid.
    #[error("invalid HRP")]
    InvalidHrp,
    /// Data is too short (need at least 6 characters for checksum).
    #[error("data too short")]
    TooShort,
    /// Mixed case in input.
    #[error("mixed case")]
    MixedCase,
    /// Padding error during bit conversion.
    #[error("invalid padding")]
    InvalidPadding,
    /// Invalid witness program length.
    #[error("invalid witness program length: {0}")]
    InvalidProgramLength(usize),
    /// Invalid witness version.
    #[error("invalid witness version: {0}")]
    InvalidWitnessVersion(u8),
}

/// Expand the human-readable part for checksum computation.
///
/// For each character c in HRP: emit (c >> 5), then emit 0, then for each c: emit (c & 31)
fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut result = Vec::with_capacity(hrp.len() * 2 + 1);

    // High bits of each character
    for c in hrp.bytes() {
        result.push(c >> 5);
    }

    // Separator
    result.push(0);

    // Low bits of each character
    for c in hrp.bytes() {
        result.push(c & 31);
    }

    result
}

/// Compute the Bech32/Bech32m polymod checksum.
fn polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for &v in values {
        let top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ (v as u32);
        for (i, &gen) in BECH32_GENERATOR.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= gen;
            }
        }
    }
    chk
}

/// Create the 6-value checksum for a given HRP and data.
fn create_checksum(hrp: &str, data: &[u8], variant: Bech32Variant) -> Vec<u8> {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0u8; 6]);

    let constant = match variant {
        Bech32Variant::Bech32 => BECH32_CONST,
        Bech32Variant::Bech32m => BECH32M_CONST,
    };

    let polymod_val = polymod(&values) ^ constant;
    (0..6)
        .map(|i| ((polymod_val >> (5 * (5 - i))) & 31) as u8)
        .collect()
}

/// Verify a Bech32/Bech32m checksum.
///
/// Returns the variant if valid, or None if invalid.
fn verify_checksum(hrp: &str, data: &[u8]) -> Option<Bech32Variant> {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    let residue = polymod(&values);

    if residue == BECH32_CONST {
        Some(Bech32Variant::Bech32)
    } else if residue == BECH32M_CONST {
        Some(Bech32Variant::Bech32m)
    } else {
        None
    }
}

/// Encode data as a Bech32/Bech32m string.
///
/// The data should already be in 5-bit groups. Use `convert_bits` to convert
/// 8-bit data to 5-bit groups first.
pub fn bech32_encode(hrp: &str, data: &[u8], variant: Bech32Variant) -> String {
    let checksum = create_checksum(hrp, data, variant);

    let charset = BECH32_CHARSET.as_bytes();
    let mut result = String::with_capacity(hrp.len() + 1 + data.len() + 6);

    result.push_str(hrp);
    result.push('1'); // separator

    for &d in data {
        result.push(charset[d as usize] as char);
    }
    for &c in &checksum {
        result.push(charset[c as usize] as char);
    }

    result
}

/// Decode a Bech32/Bech32m string.
///
/// Returns (HRP, data in 5-bit groups, variant).
pub fn bech32_decode(s: &str) -> Result<(String, Vec<u8>, Bech32Variant), Bech32Error> {
    // Check for mixed case
    let has_lower = s.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err(Bech32Error::MixedCase);
    }

    // Convert to lowercase for processing
    let s = s.to_ascii_lowercase();

    // Find the separator (last '1' in the string)
    let sep_pos = s.rfind('1').ok_or(Bech32Error::MissingSeparator)?;

    if sep_pos == 0 {
        return Err(Bech32Error::InvalidHrp);
    }

    let hrp = &s[..sep_pos];
    let data_part = &s[sep_pos + 1..];

    if data_part.len() < 6 {
        return Err(Bech32Error::TooShort);
    }

    // Validate HRP characters (must be ASCII 33-126)
    for c in hrp.chars() {
        if !(33..=126).contains(&(c as u32)) {
            return Err(Bech32Error::InvalidHrp);
        }
    }

    // Decode data characters to 5-bit values
    let mut data = Vec::with_capacity(data_part.len());
    for c in data_part.chars() {
        if c as u32 >= 128 {
            return Err(Bech32Error::InvalidCharacter(c));
        }
        let value = BECH32_DECODE[c as usize];
        if value == 255 {
            return Err(Bech32Error::InvalidCharacter(c));
        }
        data.push(value);
    }

    // Verify checksum
    let variant = verify_checksum(hrp, &data).ok_or(Bech32Error::InvalidChecksum)?;

    // Remove checksum from data (last 6 values)
    let data_without_checksum = data[..data.len() - 6].to_vec();

    Ok((hrp.to_string(), data_without_checksum, variant))
}

/// Convert between bit groups.
///
/// Used to convert 8-bit data to 5-bit groups (for encoding) and back (for decoding).
/// `from_bits` and `to_bits` specify the group sizes.
/// `pad` controls whether to zero-pad the last group when encoding.
pub fn convert_bits(
    data: &[u8],
    from_bits: u32,
    to_bits: u32,
    pad: bool,
) -> Result<Vec<u8>, Bech32Error> {
    let mut result = Vec::new();
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let max_value = (1u32 << to_bits) - 1;

    for &value in data {
        if (value as u32) >> from_bits != 0 {
            return Err(Bech32Error::InvalidPadding);
        }
        acc = (acc << from_bits) | (value as u32);
        bits += from_bits;
        while bits >= to_bits {
            bits -= to_bits;
            result.push(((acc >> bits) & max_value) as u8);
        }
    }

    if pad {
        if bits > 0 {
            result.push(((acc << (to_bits - bits)) & max_value) as u8);
        }
    } else if bits >= from_bits || ((acc << (to_bits - bits)) & max_value) != 0 {
        return Err(Bech32Error::InvalidPadding);
    }

    Ok(result)
}

/// Encode a SegWit witness program to a Bech32/Bech32m address.
///
/// - `hrp`: Human-readable part ("bc" for mainnet, "tb" for testnet, "bcrt" for regtest)
/// - `version`: Witness version (0-16)
/// - `program`: Witness program (20 or 32 bytes)
pub fn encode_segwit_address(
    hrp: &str,
    version: u8,
    program: &[u8],
) -> Result<String, Bech32Error> {
    // Validate witness version
    if version > 16 {
        return Err(Bech32Error::InvalidWitnessVersion(version));
    }

    // Validate program length
    if program.len() < 2 || program.len() > 40 {
        return Err(Bech32Error::InvalidProgramLength(program.len()));
    }

    // For witness v0, program must be exactly 20 or 32 bytes
    if version == 0 && program.len() != 20 && program.len() != 32 {
        return Err(Bech32Error::InvalidProgramLength(program.len()));
    }

    // For witness v1 (Taproot), program must be exactly 32 bytes
    if version == 1 && program.len() != 32 {
        return Err(Bech32Error::InvalidProgramLength(program.len()));
    }

    // Convert program to 5-bit groups
    let conv = convert_bits(program, 8, 5, true)?;

    // Prepend witness version
    let mut data = vec![version];
    data.extend_from_slice(&conv);

    // Use Bech32 for v0, Bech32m for v1+
    let variant = if version == 0 {
        Bech32Variant::Bech32
    } else {
        Bech32Variant::Bech32m
    };

    Ok(bech32_encode(hrp, &data, variant))
}

/// Decode a Bech32/Bech32m SegWit address.
///
/// Returns (HRP, witness version, witness program).
pub fn decode_segwit_address(s: &str) -> Result<(String, u8, Vec<u8>), Bech32Error> {
    let (hrp, data, variant) = bech32_decode(s)?;

    if data.is_empty() {
        return Err(Bech32Error::TooShort);
    }

    let version = data[0];
    if version > 16 {
        return Err(Bech32Error::InvalidWitnessVersion(version));
    }

    // Check variant matches version
    let expected_variant = if version == 0 {
        Bech32Variant::Bech32
    } else {
        Bech32Variant::Bech32m
    };

    if variant != expected_variant {
        return Err(Bech32Error::InvalidChecksum);
    }

    // Convert from 5-bit to 8-bit
    let program = convert_bits(&data[1..], 5, 8, false)?;

    // Validate program length
    if program.len() < 2 || program.len() > 40 {
        return Err(Bech32Error::InvalidProgramLength(program.len()));
    }

    // For witness v0, program must be exactly 20 or 32 bytes
    if version == 0 && program.len() != 20 && program.len() != 32 {
        return Err(Bech32Error::InvalidProgramLength(program.len()));
    }

    // For witness v1, program must be exactly 32 bytes
    if version == 1 && program.len() != 32 {
        return Err(Bech32Error::InvalidProgramLength(program.len()));
    }

    Ok((hrp, version, program))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_p2wpkh() {
        // Known P2WPKH address: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
        // Program: 751e76e8199196d454941c45d1b3a323f1433bd6 (20 bytes)
        let program = hex::decode("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        let address = encode_segwit_address("bc", 0, &program).unwrap();
        assert_eq!(address, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    }

    #[test]
    fn decode_p2wpkh() {
        let (hrp, version, program) =
            decode_segwit_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();

        assert_eq!(hrp, "bc");
        assert_eq!(version, 0);
        assert_eq!(
            hex::encode(&program),
            "751e76e8199196d454941c45d1b3a323f1433bd6"
        );
    }

    #[test]
    fn encode_p2wsh() {
        // Known P2WSH address
        // Program: 32-byte script hash
        let program = hex::decode(
            "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
        )
        .unwrap();
        let address = encode_segwit_address("bc", 0, &program).unwrap();
        assert_eq!(
            address,
            "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"
        );
    }

    #[test]
    fn decode_p2wsh() {
        let (hrp, version, program) =
            decode_segwit_address("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3")
                .unwrap();

        assert_eq!(hrp, "bc");
        assert_eq!(version, 0);
        assert_eq!(program.len(), 32);
    }

    #[test]
    fn encode_p2tr() {
        // P2TR address for output key a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c
        let program =
            hex::decode("a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c")
                .unwrap();
        let address = encode_segwit_address("bc", 1, &program).unwrap();
        assert_eq!(
            address,
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        );
    }

    #[test]
    fn decode_p2tr() {
        let (hrp, version, program) =
            decode_segwit_address("bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr")
                .unwrap();

        assert_eq!(hrp, "bc");
        assert_eq!(version, 1);
        assert_eq!(
            hex::encode(&program),
            "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"
        );
    }

    #[test]
    fn roundtrip_testnet_p2wpkh() {
        let program = hex::decode("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        let address = encode_segwit_address("tb", 0, &program).unwrap();
        let (hrp, version, decoded_program) = decode_segwit_address(&address).unwrap();

        assert_eq!(hrp, "tb");
        assert_eq!(version, 0);
        assert_eq!(decoded_program, program);
    }

    #[test]
    fn roundtrip_regtest_p2tr() {
        let program =
            hex::decode("a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c")
                .unwrap();
        let address = encode_segwit_address("bcrt", 1, &program).unwrap();
        let (hrp, version, decoded_program) = decode_segwit_address(&address).unwrap();

        assert_eq!(hrp, "bcrt");
        assert_eq!(version, 1);
        assert_eq!(decoded_program, program);
    }

    #[test]
    fn decode_uppercase() {
        // Bech32 should handle uppercase input
        let (hrp, version, program) =
            decode_segwit_address("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4").unwrap();

        assert_eq!(hrp, "bc");
        assert_eq!(version, 0);
        assert_eq!(
            hex::encode(&program),
            "751e76e8199196d454941c45d1b3a323f1433bd6"
        );
    }

    #[test]
    fn reject_mixed_case() {
        let result = decode_segwit_address("BC1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        assert!(matches!(result, Err(Bech32Error::MixedCase)));
    }

    #[test]
    fn reject_invalid_checksum() {
        // Modify last character to corrupt checksum
        let result = decode_segwit_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5");
        assert!(matches!(result, Err(Bech32Error::InvalidChecksum)));
    }

    #[test]
    fn reject_invalid_character() {
        // 'b' is not in the Bech32 charset
        let result = decode_segwit_address("bc1qw508b6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        assert!(matches!(result, Err(Bech32Error::InvalidCharacter('b'))));
    }

    #[test]
    fn reject_wrong_variant() {
        // Try to decode a v1 address as if it were v0 (wrong checksum constant)
        // This should fail because the checksum was computed with Bech32m but
        // we expect Bech32 for v0
        // Actually, this test verifies that using wrong variant is rejected

        // Create a v0 address but manually change version to 1
        let program = hex::decode("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        let conv = convert_bits(&program, 8, 5, true).unwrap();
        let mut data = vec![1u8]; // version 1
        data.extend_from_slice(&conv);

        // Encode with Bech32 (wrong for v1)
        let wrong_address = bech32_encode("bc", &data, Bech32Variant::Bech32);

        // This should fail because v1 requires Bech32m
        let result = decode_segwit_address(&wrong_address);
        assert!(matches!(result, Err(Bech32Error::InvalidChecksum)));
    }

    #[test]
    fn convert_bits_8_to_5() {
        // Test the bit conversion
        let data = vec![0xff, 0x00];
        let converted = convert_bits(&data, 8, 5, true).unwrap();
        // 0xff 0x00 = 11111111 00000000
        // 5-bit groups: 11111 11100 00000 0 (with padding)
        // = 31, 28, 0, 0
        assert_eq!(converted, vec![31, 28, 0, 0]);
    }

    #[test]
    fn convert_bits_5_to_8() {
        // Round-trip test
        let original = vec![0x75, 0x1e, 0x76, 0xe8];
        let five_bit = convert_bits(&original, 8, 5, true).unwrap();
        let back = convert_bits(&five_bit, 5, 8, false).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn reject_invalid_program_length_v0() {
        // v0 requires 20 or 32 bytes
        let program = vec![0u8; 25]; // Invalid length
        let result = encode_segwit_address("bc", 0, &program);
        assert!(matches!(result, Err(Bech32Error::InvalidProgramLength(25))));
    }

    #[test]
    fn reject_invalid_program_length_v1() {
        // v1 requires exactly 32 bytes
        let program = vec![0u8; 20];
        let result = encode_segwit_address("bc", 1, &program);
        assert!(matches!(result, Err(Bech32Error::InvalidProgramLength(20))));
    }

    #[test]
    fn bip173_test_vectors() {
        // Test vectors from BIP-173
        let valid_addresses = [
            ("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", "bc", 0, 20),
            (
                "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
                "bc",
                0,
                32,
            ),
        ];

        for (address, expected_hrp, expected_version, expected_len) in valid_addresses {
            let (hrp, version, program) = decode_segwit_address(address).unwrap();
            assert_eq!(hrp, expected_hrp);
            assert_eq!(version, expected_version);
            assert_eq!(program.len(), expected_len);
        }
    }

    #[test]
    fn bip350_test_vectors() {
        // Valid bech32m test vectors from BIP-350 and P2TR addresses
        let valid_addresses = [
            // Simple bech32m test
            ("a1lqfn3a", "a", 0),
            // P2TR address with all-zero witness program
            ("bc1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpqqenm", "bc", 32),
            // P2TR address with real output key
            ("bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr", "bc", 32),
        ];

        for (address, expected_hrp, expected_program_len) in valid_addresses {
            // Only decode and verify the checksum is valid and HRP matches
            let (hrp, data, variant) = bech32_decode(address).unwrap();
            assert_eq!(hrp, expected_hrp);

            // For P2TR (witness version 1), should be Bech32m
            if !data.is_empty() && data[0] == 1 {
                assert_eq!(variant, Bech32Variant::Bech32m);
            }

            // If this is a segwit address with data, verify program length
            if expected_program_len > 0 && !data.is_empty() {
                // Convert 5-bit to 8-bit for program
                let program = convert_bits(&data[1..], 5, 8, false).unwrap();
                assert_eq!(program.len(), expected_program_len);
            }
        }
    }
}
