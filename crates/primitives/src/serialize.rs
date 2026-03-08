//! Bitcoin binary serialization traits and helpers.
//!
//! This module provides the `Encodable` and `Decodable` traits for Bitcoin wire format
//! serialization, as well as CompactSize (variable-length integer) encoding.

use std::io::{self, Cursor, Read, Write};

/// Trait for types that can be serialized to Bitcoin wire format.
pub trait Encodable {
    /// Encode this value to a writer, returning the number of bytes written.
    fn encode<W: Write>(&self, writer: &mut W) -> io::Result<usize>;

    /// Return the serialized size in bytes.
    fn serialized_size(&self) -> usize;

    /// Serialize to a new Vec<u8>.
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.serialized_size());
        self.encode(&mut buf).expect("writing to Vec never fails");
        buf
    }
}

/// Trait for types that can be deserialized from Bitcoin wire format.
pub trait Decodable: Sized {
    /// Decode a value from a reader.
    fn decode<R: Read>(reader: &mut R) -> io::Result<Self>;

    /// Deserialize from a byte slice.
    fn deserialize(data: &[u8]) -> io::Result<Self> {
        let mut cursor = Cursor::new(data);
        Self::decode(&mut cursor)
    }
}

/// Read a Bitcoin-style CompactSize (variable-length integer).
///
/// Encoding:
/// - 0x00..0xFC: 1 byte, value is the byte itself
/// - 0xFD: 3 bytes total, next 2 bytes are u16 LE (value must be >= 253)
/// - 0xFE: 5 bytes total, next 4 bytes are u32 LE (value must be >= 0x10000)
/// - 0xFF: 9 bytes total, next 8 bytes are u64 LE (value must be >= 0x100000000)
pub fn read_compact_size<R: Read>(reader: &mut R) -> io::Result<u64> {
    let mut b = [0u8; 1];
    reader.read_exact(&mut b)?;
    match b[0] {
        0..=0xFC => Ok(b[0] as u64),
        0xFD => {
            let mut buf = [0u8; 2];
            reader.read_exact(&mut buf)?;
            let val = u16::from_le_bytes(buf) as u64;
            if val < 253 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "non-canonical compact size",
                ));
            }
            Ok(val)
        }
        0xFE => {
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf)?;
            let val = u32::from_le_bytes(buf) as u64;
            if val < 0x10000 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "non-canonical compact size",
                ));
            }
            Ok(val)
        }
        0xFF => {
            let mut buf = [0u8; 8];
            reader.read_exact(&mut buf)?;
            let val = u64::from_le_bytes(buf);
            if val < 0x100000000 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "non-canonical compact size",
                ));
            }
            Ok(val)
        }
    }
}

/// Write a Bitcoin-style CompactSize.
pub fn write_compact_size<W: Write>(writer: &mut W, val: u64) -> io::Result<usize> {
    if val < 253 {
        writer.write_all(&[val as u8])?;
        Ok(1)
    } else if val <= 0xFFFF {
        writer.write_all(&[0xFD])?;
        writer.write_all(&(val as u16).to_le_bytes())?;
        Ok(3)
    } else if val <= 0xFFFF_FFFF {
        writer.write_all(&[0xFE])?;
        writer.write_all(&(val as u32).to_le_bytes())?;
        Ok(5)
    } else {
        writer.write_all(&[0xFF])?;
        writer.write_all(&val.to_le_bytes())?;
        Ok(9)
    }
}

/// Return the size in bytes needed to encode a CompactSize value.
pub fn compact_size_len(val: u64) -> usize {
    if val < 253 {
        1
    } else if val <= 0xFFFF {
        3
    } else if val <= 0xFFFF_FFFF {
        5
    } else {
        9
    }
}

// Implement Encodable and Decodable for primitive types

impl Encodable for u8 {
    fn encode<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
        writer.write_all(&[*self])?;
        Ok(1)
    }

    fn serialized_size(&self) -> usize {
        1
    }
}

impl Decodable for u8 {
    fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf)?;
        Ok(buf[0])
    }
}

impl Encodable for u16 {
    fn encode<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
        writer.write_all(&self.to_le_bytes())?;
        Ok(2)
    }

    fn serialized_size(&self) -> usize {
        2
    }
}

impl Decodable for u16 {
    fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut buf = [0u8; 2];
        reader.read_exact(&mut buf)?;
        Ok(u16::from_le_bytes(buf))
    }
}

impl Encodable for u32 {
    fn encode<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
        writer.write_all(&self.to_le_bytes())?;
        Ok(4)
    }

    fn serialized_size(&self) -> usize {
        4
    }
}

impl Decodable for u32 {
    fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }
}

impl Encodable for u64 {
    fn encode<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
        writer.write_all(&self.to_le_bytes())?;
        Ok(8)
    }

    fn serialized_size(&self) -> usize {
        8
    }
}

impl Decodable for u64 {
    fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }
}

impl Encodable for i32 {
    fn encode<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
        writer.write_all(&self.to_le_bytes())?;
        Ok(4)
    }

    fn serialized_size(&self) -> usize {
        4
    }
}

impl Decodable for i32 {
    fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        Ok(i32::from_le_bytes(buf))
    }
}

impl Encodable for i64 {
    fn encode<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
        writer.write_all(&self.to_le_bytes())?;
        Ok(8)
    }

    fn serialized_size(&self) -> usize {
        8
    }
}

impl Decodable for i64 {
    fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf)?;
        Ok(i64::from_le_bytes(buf))
    }
}

impl Encodable for bool {
    fn encode<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
        writer.write_all(&[if *self { 1 } else { 0 }])?;
        Ok(1)
    }

    fn serialized_size(&self) -> usize {
        1
    }
}

impl Decodable for bool {
    fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf)?;
        Ok(buf[0] != 0)
    }
}

// Fixed-size byte arrays

impl Encodable for [u8; 4] {
    fn encode<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
        writer.write_all(self)?;
        Ok(4)
    }

    fn serialized_size(&self) -> usize {
        4
    }
}

impl Decodable for [u8; 4] {
    fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        Ok(buf)
    }
}

impl Encodable for [u8; 8] {
    fn encode<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
        writer.write_all(self)?;
        Ok(8)
    }

    fn serialized_size(&self) -> usize {
        8
    }
}

impl Decodable for [u8; 8] {
    fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf)?;
        Ok(buf)
    }
}

impl Encodable for [u8; 20] {
    fn encode<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
        writer.write_all(self)?;
        Ok(20)
    }

    fn serialized_size(&self) -> usize {
        20
    }
}

impl Decodable for [u8; 20] {
    fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut buf = [0u8; 20];
        reader.read_exact(&mut buf)?;
        Ok(buf)
    }
}

impl Encodable for [u8; 32] {
    fn encode<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
        writer.write_all(self)?;
        Ok(32)
    }

    fn serialized_size(&self) -> usize {
        32
    }
}

impl Decodable for [u8; 32] {
    fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut buf = [0u8; 32];
        reader.read_exact(&mut buf)?;
        Ok(buf)
    }
}

// Vec<u8> with CompactSize length prefix

impl Encodable for Vec<u8> {
    fn encode<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
        let mut len = write_compact_size(writer, self.len() as u64)?;
        writer.write_all(self)?;
        len += self.len();
        Ok(len)
    }

    fn serialized_size(&self) -> usize {
        compact_size_len(self.len() as u64) + self.len()
    }
}

impl Decodable for Vec<u8> {
    fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let len = read_compact_size(reader)?;
        // Sanity check to prevent OOM attacks
        if len > 0x02000000 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "vec length too large",
            ));
        }
        let mut buf = vec![0u8; len as usize];
        reader.read_exact(&mut buf)?;
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_size_single_byte() {
        for val in [0u64, 1, 127, 252] {
            let mut buf = Vec::new();
            write_compact_size(&mut buf, val).unwrap();
            assert_eq!(buf.len(), 1);
            assert_eq!(buf[0], val as u8);

            let result = read_compact_size(&mut Cursor::new(&buf)).unwrap();
            assert_eq!(result, val);
        }
    }

    #[test]
    fn compact_size_two_bytes() {
        for val in [253u64, 0xFFFF] {
            let mut buf = Vec::new();
            write_compact_size(&mut buf, val).unwrap();
            assert_eq!(buf.len(), 3);
            assert_eq!(buf[0], 0xFD);

            let result = read_compact_size(&mut Cursor::new(&buf)).unwrap();
            assert_eq!(result, val);
        }
    }

    #[test]
    fn compact_size_four_bytes() {
        for val in [0x10000u64, 0xFFFFFFFF] {
            let mut buf = Vec::new();
            write_compact_size(&mut buf, val).unwrap();
            assert_eq!(buf.len(), 5);
            assert_eq!(buf[0], 0xFE);

            let result = read_compact_size(&mut Cursor::new(&buf)).unwrap();
            assert_eq!(result, val);
        }
    }

    #[test]
    fn compact_size_eight_bytes() {
        for val in [0x100000000u64, u64::MAX] {
            let mut buf = Vec::new();
            write_compact_size(&mut buf, val).unwrap();
            assert_eq!(buf.len(), 9);
            assert_eq!(buf[0], 0xFF);

            let result = read_compact_size(&mut Cursor::new(&buf)).unwrap();
            assert_eq!(result, val);
        }
    }

    #[test]
    fn compact_size_non_canonical_two_bytes() {
        // Value 252 encoded as 3 bytes (non-canonical)
        let buf = [0xFD, 252, 0];
        let result = read_compact_size(&mut Cursor::new(&buf[..]));
        assert!(result.is_err());
    }

    #[test]
    fn compact_size_non_canonical_four_bytes() {
        // Value 0xFFFF encoded as 5 bytes (non-canonical)
        let buf = [0xFE, 0xFF, 0xFF, 0, 0];
        let result = read_compact_size(&mut Cursor::new(&buf[..]));
        assert!(result.is_err());
    }

    #[test]
    fn compact_size_non_canonical_eight_bytes() {
        // Value 0xFFFFFFFF encoded as 9 bytes (non-canonical)
        let buf = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0];
        let result = read_compact_size(&mut Cursor::new(&buf[..]));
        assert!(result.is_err());
    }

    #[test]
    fn primitive_u8_roundtrip() {
        for val in [0u8, 1, 127, 255] {
            let encoded = val.serialize();
            let decoded = u8::deserialize(&encoded).unwrap();
            assert_eq!(val, decoded);
        }
    }

    #[test]
    fn primitive_u16_roundtrip() {
        for val in [0u16, 1, 0xFF, 0xFFFF] {
            let encoded = val.serialize();
            assert_eq!(encoded.len(), 2);
            let decoded = u16::deserialize(&encoded).unwrap();
            assert_eq!(val, decoded);
        }
    }

    #[test]
    fn primitive_u32_roundtrip() {
        for val in [0u32, 1, 0xFFFF, 0xFFFFFFFF] {
            let encoded = val.serialize();
            assert_eq!(encoded.len(), 4);
            let decoded = u32::deserialize(&encoded).unwrap();
            assert_eq!(val, decoded);
        }
    }

    #[test]
    fn primitive_u64_roundtrip() {
        for val in [0u64, 1, 0xFFFFFFFF, u64::MAX] {
            let encoded = val.serialize();
            assert_eq!(encoded.len(), 8);
            let decoded = u64::deserialize(&encoded).unwrap();
            assert_eq!(val, decoded);
        }
    }

    #[test]
    fn primitive_i32_roundtrip() {
        for val in [0i32, 1, -1, i32::MIN, i32::MAX] {
            let encoded = val.serialize();
            assert_eq!(encoded.len(), 4);
            let decoded = i32::deserialize(&encoded).unwrap();
            assert_eq!(val, decoded);
        }
    }

    #[test]
    fn primitive_i64_roundtrip() {
        for val in [0i64, 1, -1, i64::MIN, i64::MAX] {
            let encoded = val.serialize();
            assert_eq!(encoded.len(), 8);
            let decoded = i64::deserialize(&encoded).unwrap();
            assert_eq!(val, decoded);
        }
    }

    #[test]
    fn primitive_bool_roundtrip() {
        for val in [true, false] {
            let encoded = val.serialize();
            assert_eq!(encoded.len(), 1);
            let decoded = bool::deserialize(&encoded).unwrap();
            assert_eq!(val, decoded);
        }
    }

    #[test]
    fn fixed_arrays_roundtrip() {
        let arr4: [u8; 4] = [1, 2, 3, 4];
        assert_eq!(<[u8; 4]>::deserialize(&arr4.serialize()).unwrap(), arr4);

        let arr8: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(<[u8; 8]>::deserialize(&arr8.serialize()).unwrap(), arr8);

        let arr20: [u8; 20] = [1; 20];
        assert_eq!(<[u8; 20]>::deserialize(&arr20.serialize()).unwrap(), arr20);

        let arr32: [u8; 32] = [1; 32];
        assert_eq!(<[u8; 32]>::deserialize(&arr32.serialize()).unwrap(), arr32);
    }

    #[test]
    fn vec_u8_roundtrip() {
        let empty: Vec<u8> = vec![];
        let decoded_empty = Vec::<u8>::deserialize(&empty.serialize()).unwrap();
        assert_eq!(empty, decoded_empty);

        let small: Vec<u8> = vec![1, 2, 3, 4, 5];
        let decoded_small = Vec::<u8>::deserialize(&small.serialize()).unwrap();
        assert_eq!(small, decoded_small);

        // Test with length > 252 to trigger 3-byte compact size
        let large: Vec<u8> = vec![0xAB; 300];
        let decoded_large = Vec::<u8>::deserialize(&large.serialize()).unwrap();
        assert_eq!(large, decoded_large);
    }

    #[test]
    fn little_endian_encoding() {
        // Verify little-endian encoding
        let val: u32 = 0x12345678;
        let encoded = val.serialize();
        assert_eq!(encoded, [0x78, 0x56, 0x34, 0x12]);
    }
}
