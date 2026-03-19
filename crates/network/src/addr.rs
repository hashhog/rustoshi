//! BIP155 ADDRv2 protocol implementation.
//!
//! This module implements the ADDRv2 protocol (BIP155) which supports
//! variable-length network addresses for Tor v3, I2P, and CJDNS networks.
//!
//! ## Network Address Types
//!
//! | Network ID | Name  | Address Length | Description |
//! |------------|-------|----------------|-------------|
//! | 1          | IPv4  | 4 bytes        | IPv4 address |
//! | 2          | IPv6  | 16 bytes       | IPv6 address |
//! | 3          | TorV2 | 10 bytes       | Deprecated Tor v2 (not supported) |
//! | 4          | TorV3 | 32 bytes       | Tor v3 ed25519 public key |
//! | 5          | I2P   | 32 bytes       | I2P SHA256 destination hash |
//! | 6          | CJDNS | 16 bytes       | CJDNS IPv6 address (fc00::/8) |
//!
//! ## Protocol Flow
//!
//! 1. Node sends `sendaddrv2` message between VERSION and VERACK
//! 2. If peer also sends `sendaddrv2`, both use ADDRv2 format
//! 3. Otherwise, legacy ADDR format is used for compatibility

use rustoshi_primitives::serialize::{read_compact_size, write_compact_size};
use std::io::{self, Cursor, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

/// BIP155 Network ID constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Bip155NetworkId {
    /// IPv4 address (4 bytes)
    Ipv4 = 1,
    /// IPv6 address (16 bytes)
    Ipv6 = 2,
    /// Tor v2 address (10 bytes) - deprecated, not supported
    TorV2 = 3,
    /// Tor v3 address (32 bytes) - ed25519 public key
    TorV3 = 4,
    /// I2P address (32 bytes) - SHA256 destination hash
    I2P = 5,
    /// CJDNS address (16 bytes) - starts with fc00::/8
    Cjdns = 6,
}

impl Bip155NetworkId {
    /// Convert from raw byte value.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            1 => Some(Self::Ipv4),
            2 => Some(Self::Ipv6),
            3 => Some(Self::TorV2),
            4 => Some(Self::TorV3),
            5 => Some(Self::I2P),
            6 => Some(Self::Cjdns),
            _ => None, // Unknown network IDs are silently ignored (forward compatibility)
        }
    }

    /// Get the expected address length for this network type.
    pub fn addr_len(&self) -> usize {
        match self {
            Self::Ipv4 => 4,
            Self::Ipv6 => 16,
            Self::TorV2 => 10,
            Self::TorV3 => 32,
            Self::I2P => 32,
            Self::Cjdns => 16,
        }
    }
}

/// Maximum ADDRv2 address size (for DoS protection).
pub const MAX_ADDRV2_SIZE: usize = 512;

/// A BIP155 network address (variable length).
///
/// This can represent IPv4, IPv6, Tor v3, I2P, or CJDNS addresses.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NetworkAddr {
    /// IPv4 address.
    Ipv4(Ipv4Addr),
    /// IPv6 address.
    Ipv6(Ipv6Addr),
    /// Tor v3 address (32-byte ed25519 public key).
    TorV3([u8; 32]),
    /// I2P address (32-byte SHA256 destination hash).
    I2P([u8; 32]),
    /// CJDNS address (16-byte IPv6 in fc00::/8 range).
    Cjdns([u8; 16]),
}

impl NetworkAddr {
    /// Get the BIP155 network ID for this address.
    pub fn network_id(&self) -> Bip155NetworkId {
        match self {
            Self::Ipv4(_) => Bip155NetworkId::Ipv4,
            Self::Ipv6(_) => Bip155NetworkId::Ipv6,
            Self::TorV3(_) => Bip155NetworkId::TorV3,
            Self::I2P(_) => Bip155NetworkId::I2P,
            Self::Cjdns(_) => Bip155NetworkId::Cjdns,
        }
    }

    /// Check if this address is compatible with legacy ADDR messages.
    ///
    /// Only IPv4 and IPv6 addresses can be sent in legacy ADDR format.
    pub fn is_addr_v1_compatible(&self) -> bool {
        matches!(self, Self::Ipv4(_) | Self::Ipv6(_))
    }

    /// Get the raw address bytes.
    pub fn addr_bytes(&self) -> Vec<u8> {
        match self {
            Self::Ipv4(ip) => ip.octets().to_vec(),
            Self::Ipv6(ip) => ip.octets().to_vec(),
            Self::TorV3(pubkey) => pubkey.to_vec(),
            Self::I2P(hash) => hash.to_vec(),
            Self::Cjdns(addr) => addr.to_vec(),
        }
    }

    /// Try to convert this address to a SocketAddr (for IPv4/IPv6 only).
    pub fn to_socket_addr(&self, port: u16) -> Option<SocketAddr> {
        match self {
            Self::Ipv4(ip) => Some(SocketAddr::new((*ip).into(), port)),
            Self::Ipv6(ip) => Some(SocketAddr::new((*ip).into(), port)),
            _ => None, // Privacy networks don't map to SocketAddr
        }
    }

    /// Create from a SocketAddr.
    pub fn from_socket_addr(addr: &SocketAddr) -> Self {
        match addr.ip() {
            std::net::IpAddr::V4(ip) => Self::Ipv4(ip),
            std::net::IpAddr::V6(ip) => Self::Ipv6(ip),
        }
    }

    /// Create an IPv4 address from octets.
    pub fn from_ipv4_octets(octets: [u8; 4]) -> Self {
        Self::Ipv4(Ipv4Addr::from(octets))
    }

    /// Create an IPv6 address from octets.
    pub fn from_ipv6_octets(octets: [u8; 16]) -> Self {
        Self::Ipv6(Ipv6Addr::from(octets))
    }

    /// Create a TorV3 address from the 32-byte ed25519 public key.
    ///
    /// Note: This does NOT validate that the public key is valid.
    /// Use `TorV3Address::from_pubkey` for validation.
    pub fn from_torv3_pubkey(pubkey: [u8; 32]) -> Self {
        Self::TorV3(pubkey)
    }

    /// Create an I2P address from the 32-byte destination hash.
    pub fn from_i2p_hash(hash: [u8; 32]) -> Self {
        Self::I2P(hash)
    }

    /// Create a CJDNS address from the 16-byte IPv6 address.
    ///
    /// Returns None if the address doesn't start with fc00::/8.
    pub fn from_cjdns_addr(addr: [u8; 16]) -> Option<Self> {
        if addr[0] == 0xfc {
            Some(Self::Cjdns(addr))
        } else {
            None
        }
    }

    /// Serialize this address in ADDRv2 format.
    ///
    /// Format: [network_id(1)] [addr_len(compactsize)] [addr(variable)]
    pub fn serialize_addrv2<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&[self.network_id() as u8])?;
        let bytes = self.addr_bytes();
        write_compact_size(writer, bytes.len() as u64)?;
        writer.write_all(&bytes)?;
        Ok(())
    }

    /// Deserialize an address in ADDRv2 format.
    ///
    /// Returns None for unknown network IDs (forward compatibility).
    pub fn deserialize_addrv2<R: Read>(reader: &mut R) -> io::Result<Option<Self>> {
        let mut net_id_buf = [0u8; 1];
        reader.read_exact(&mut net_id_buf)?;
        let net_id = net_id_buf[0];

        let addr_len = read_compact_size(reader)? as usize;

        // DoS protection
        if addr_len > MAX_ADDRV2_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("addrv2 address too large: {} bytes", addr_len),
            ));
        }

        // Read address bytes
        let mut addr_bytes = vec![0u8; addr_len];
        if addr_len > 0 {
            reader.read_exact(&mut addr_bytes)?;
        }

        // Parse based on network ID
        let Some(network_id) = Bip155NetworkId::from_u8(net_id) else {
            // Unknown network ID - skip silently for forward compatibility
            return Ok(None);
        };

        // Validate address length matches expected
        if addr_len != network_id.addr_len() {
            // Wrong size for known network - this is an error
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "invalid addrv2 size for network {}: got {} bytes, expected {}",
                    net_id,
                    addr_len,
                    network_id.addr_len()
                ),
            ));
        }

        match network_id {
            Bip155NetworkId::Ipv4 => {
                let mut octets = [0u8; 4];
                octets.copy_from_slice(&addr_bytes);
                Ok(Some(Self::Ipv4(Ipv4Addr::from(octets))))
            }
            Bip155NetworkId::Ipv6 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&addr_bytes);
                Ok(Some(Self::Ipv6(Ipv6Addr::from(octets))))
            }
            Bip155NetworkId::TorV2 => {
                // TorV2 is deprecated, we don't support it
                Ok(None)
            }
            Bip155NetworkId::TorV3 => {
                let mut pubkey = [0u8; 32];
                pubkey.copy_from_slice(&addr_bytes);
                Ok(Some(Self::TorV3(pubkey)))
            }
            Bip155NetworkId::I2P => {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&addr_bytes);
                Ok(Some(Self::I2P(hash)))
            }
            Bip155NetworkId::Cjdns => {
                let mut addr = [0u8; 16];
                addr.copy_from_slice(&addr_bytes);
                // Validate CJDNS prefix
                if addr[0] != 0xfc {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "CJDNS address must start with fc00::/8",
                    ));
                }
                Ok(Some(Self::Cjdns(addr)))
            }
        }
    }

    /// Serialize this address in legacy ADDR format (16-byte IPv6 style).
    ///
    /// Returns None if the address is not compatible with legacy format.
    pub fn serialize_legacy(&self) -> Option<[u8; 16]> {
        match self {
            Self::Ipv4(ip) => {
                // IPv4-mapped IPv6: ::ffff:x.x.x.x
                let mut buf = [0u8; 16];
                buf[10] = 0xff;
                buf[11] = 0xff;
                buf[12..16].copy_from_slice(&ip.octets());
                Some(buf)
            }
            Self::Ipv6(ip) => Some(ip.octets()),
            _ => None, // Privacy networks not supported in legacy format
        }
    }

    /// Deserialize from legacy 16-byte format.
    pub fn deserialize_legacy(bytes: &[u8; 16]) -> Self {
        // Check for IPv4-mapped IPv6
        if bytes[0..10] == [0; 10] && bytes[10] == 0xff && bytes[11] == 0xff {
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&bytes[12..16]);
            Self::Ipv4(Ipv4Addr::from(octets))
        } else {
            Self::Ipv6(Ipv6Addr::from(*bytes))
        }
    }
}

/// A timestamped BIP155 network address entry.
///
/// This is the format used in ADDRV2 messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddrV2Entry {
    /// Unix timestamp (seconds since epoch) when this address was last seen.
    pub timestamp: u32,
    /// Service flags advertised by this node.
    pub services: u64,
    /// The network address.
    pub addr: NetworkAddr,
    /// Port number.
    pub port: u16,
}

impl AddrV2Entry {
    /// Create a new entry.
    pub fn new(timestamp: u32, services: u64, addr: NetworkAddr, port: u16) -> Self {
        Self {
            timestamp,
            services,
            addr,
            port,
        }
    }

    /// Try to convert to a SocketAddr (for IPv4/IPv6 only).
    pub fn to_socket_addr(&self) -> Option<SocketAddr> {
        self.addr.to_socket_addr(self.port)
    }

    /// Check if this entry is compatible with legacy ADDR messages.
    pub fn is_addr_v1_compatible(&self) -> bool {
        self.addr.is_addr_v1_compatible()
    }

    /// Serialize in ADDRV2 format.
    ///
    /// Format: [timestamp(4)] [services(compactsize)] [network_id(1)] [addr_len(compactsize)] [addr(var)] [port(2 BE)]
    pub fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        // Timestamp (4 bytes little-endian)
        writer.write_all(&self.timestamp.to_le_bytes())?;

        // Services (CompactSize encoded in ADDRv2, not fixed 8 bytes)
        write_compact_size(writer, self.services)?;

        // Network address (network_id + addr_len + addr)
        self.addr.serialize_addrv2(writer)?;

        // Port (2 bytes big-endian, per Bitcoin protocol)
        writer.write_all(&self.port.to_be_bytes())?;

        Ok(())
    }

    /// Deserialize from ADDRV2 format.
    ///
    /// Returns None for entries with unknown network IDs (forward compatibility).
    pub fn deserialize<R: Read>(reader: &mut R) -> io::Result<Option<Self>> {
        // Timestamp
        let mut ts_buf = [0u8; 4];
        reader.read_exact(&mut ts_buf)?;
        let timestamp = u32::from_le_bytes(ts_buf);

        // Services (CompactSize)
        let services = read_compact_size(reader)?;

        // Network address
        let addr = match NetworkAddr::deserialize_addrv2(reader)? {
            Some(a) => a,
            None => {
                // Unknown network - need to still read the port
                let mut port_buf = [0u8; 2];
                reader.read_exact(&mut port_buf)?;
                return Ok(None);
            }
        };

        // Port
        let mut port_buf = [0u8; 2];
        reader.read_exact(&mut port_buf)?;
        let port = u16::from_be_bytes(port_buf);

        Ok(Some(Self {
            timestamp,
            services,
            addr,
            port,
        }))
    }
}

/// Tor v3 address utilities.
///
/// Tor v3 .onion addresses encode a 32-byte ed25519 public key.
/// The full format is: base32(pubkey || checksum || version) + ".onion"
/// where checksum = SHA3-256(".onion checksum" || pubkey || version)[0:2]
/// and version = 0x03
pub mod torv3 {
    /// The Tor v3 version byte.
    pub const TORV3_VERSION: u8 = 0x03;

    /// Validate that a 32-byte array could be a valid ed25519 public key.
    ///
    /// This performs basic validation:
    /// - Not all zeros
    /// - Not all ones
    ///
    /// Full cryptographic validation would require the ed25519 library.
    pub fn validate_pubkey(pubkey: &[u8; 32]) -> bool {
        // Basic sanity checks
        let all_zeros = pubkey.iter().all(|&b| b == 0);
        let all_ones = pubkey.iter().all(|&b| b == 0xff);

        !all_zeros && !all_ones
    }

    /// Encode a public key to a .onion address string.
    ///
    /// Note: This requires SHA3-256 which we don't have implemented.
    /// For now, this returns None. In production, implement with sha3 crate.
    pub fn encode_onion_address(_pubkey: &[u8; 32]) -> Option<String> {
        // Would require SHA3-256 for checksum computation:
        // checksum = sha3_256(".onion checksum" || pubkey || [0x03])[0:2]
        // result = base32(pubkey || checksum || 0x03) + ".onion"
        None
    }

    /// Decode a .onion address to extract the public key.
    ///
    /// Note: This requires SHA3-256 for checksum validation.
    /// For now, this returns None. In production, implement with sha3 crate.
    pub fn decode_onion_address(_onion: &str) -> Option<[u8; 32]> {
        // Would require:
        // 1. Strip ".onion" suffix
        // 2. Base32 decode to get pubkey || checksum || version
        // 3. Verify version == 0x03
        // 4. Verify checksum using SHA3-256
        // 5. Return pubkey
        None
    }
}

/// I2P address utilities.
pub mod i2p {
    /// The base32 alphabet used by I2P.
    const I2P_BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

    /// Encode a 32-byte hash to I2P base32 format.
    ///
    /// Returns a 52-character base32 string (without .b32.i2p suffix).
    pub fn encode_base32(hash: &[u8; 32]) -> String {
        let mut result = String::with_capacity(52);
        let mut bits = 0u32;
        let mut num_bits = 0;

        for &byte in hash {
            bits = (bits << 8) | (byte as u32);
            num_bits += 8;

            while num_bits >= 5 {
                num_bits -= 5;
                let index = ((bits >> num_bits) & 0x1f) as usize;
                result.push(I2P_BASE32_ALPHABET[index] as char);
            }
        }

        // Handle remaining bits
        if num_bits > 0 {
            let index = ((bits << (5 - num_bits)) & 0x1f) as usize;
            result.push(I2P_BASE32_ALPHABET[index] as char);
        }

        result
    }

    /// Format as full I2P address with .b32.i2p suffix.
    pub fn format_address(hash: &[u8; 32]) -> String {
        format!("{}.b32.i2p", encode_base32(hash))
    }
}

/// Serialize a list of ADDRv2 entries.
pub fn serialize_addrv2_message(entries: &[AddrV2Entry]) -> Vec<u8> {
    let mut buf = Vec::new();
    write_compact_size(&mut buf, entries.len() as u64).unwrap();
    for entry in entries {
        entry.serialize(&mut buf).unwrap();
    }
    buf
}

/// Deserialize a list of ADDRv2 entries.
///
/// Entries with unknown network IDs are silently skipped (forward compatibility).
pub fn deserialize_addrv2_message(data: &[u8]) -> io::Result<Vec<AddrV2Entry>> {
    let mut cursor = Cursor::new(data);
    let count = read_compact_size(&mut cursor)? as usize;

    // DoS protection
    const MAX_ADDRV2_ENTRIES: usize = 1000;
    if count > MAX_ADDRV2_ENTRIES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("too many addrv2 entries: {}", count),
        ));
    }

    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        if let Some(entry) = AddrV2Entry::deserialize(&mut cursor)? {
            entries.push(entry);
        }
        // Unknown network entries are silently skipped
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_id_roundtrip() {
        for id in [
            Bip155NetworkId::Ipv4,
            Bip155NetworkId::Ipv6,
            Bip155NetworkId::TorV2,
            Bip155NetworkId::TorV3,
            Bip155NetworkId::I2P,
            Bip155NetworkId::Cjdns,
        ] {
            assert_eq!(Bip155NetworkId::from_u8(id as u8), Some(id));
        }
    }

    #[test]
    fn test_unknown_network_id() {
        assert_eq!(Bip155NetworkId::from_u8(0), None);
        assert_eq!(Bip155NetworkId::from_u8(7), None);
        assert_eq!(Bip155NetworkId::from_u8(255), None);
    }

    #[test]
    fn test_ipv4_addrv2_roundtrip() {
        let addr = NetworkAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1));
        let mut buf = Vec::new();
        addr.serialize_addrv2(&mut buf).unwrap();

        let mut cursor = Cursor::new(&buf);
        let decoded = NetworkAddr::deserialize_addrv2(&mut cursor)
            .unwrap()
            .unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_ipv6_addrv2_roundtrip() {
        let addr = NetworkAddr::Ipv6(Ipv6Addr::new(
            0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334,
        ));
        let mut buf = Vec::new();
        addr.serialize_addrv2(&mut buf).unwrap();

        let mut cursor = Cursor::new(&buf);
        let decoded = NetworkAddr::deserialize_addrv2(&mut cursor)
            .unwrap()
            .unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_torv3_addrv2_roundtrip() {
        let mut pubkey = [0u8; 32];
        pubkey[0] = 0x42;
        pubkey[31] = 0xff;
        let addr = NetworkAddr::TorV3(pubkey);

        let mut buf = Vec::new();
        addr.serialize_addrv2(&mut buf).unwrap();

        let mut cursor = Cursor::new(&buf);
        let decoded = NetworkAddr::deserialize_addrv2(&mut cursor)
            .unwrap()
            .unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_i2p_addrv2_roundtrip() {
        let mut hash = [0u8; 32];
        for (i, byte) in hash.iter_mut().enumerate() {
            *byte = i as u8;
        }
        let addr = NetworkAddr::I2P(hash);

        let mut buf = Vec::new();
        addr.serialize_addrv2(&mut buf).unwrap();

        let mut cursor = Cursor::new(&buf);
        let decoded = NetworkAddr::deserialize_addrv2(&mut cursor)
            .unwrap()
            .unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_cjdns_addrv2_roundtrip() {
        let mut addr_bytes = [0u8; 16];
        addr_bytes[0] = 0xfc; // Required CJDNS prefix
        addr_bytes[1] = 0x01;
        let addr = NetworkAddr::Cjdns(addr_bytes);

        let mut buf = Vec::new();
        addr.serialize_addrv2(&mut buf).unwrap();

        let mut cursor = Cursor::new(&buf);
        let decoded = NetworkAddr::deserialize_addrv2(&mut cursor)
            .unwrap()
            .unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_cjdns_invalid_prefix() {
        // CJDNS address without fc prefix
        let data = vec![
            6,    // Network ID = CJDNS
            16,   // Address length
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // Not starting with fc
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];

        let mut cursor = Cursor::new(&data);
        let result = NetworkAddr::deserialize_addrv2(&mut cursor);
        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_network_skipped() {
        // Network ID 99 with 10 bytes of data
        let data = vec![
            99,   // Unknown network ID
            10,   // Address length
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, // Dummy data
        ];

        let mut cursor = Cursor::new(&data);
        let result = NetworkAddr::deserialize_addrv2(&mut cursor).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_wrong_length_error() {
        // IPv4 with wrong length
        let data = vec![
            1,  // Network ID = IPv4
            6,  // Wrong length (should be 4)
            0, 0, 0, 0, 0, 0,
        ];

        let mut cursor = Cursor::new(&data);
        let result = NetworkAddr::deserialize_addrv2(&mut cursor);
        assert!(result.is_err());
    }

    #[test]
    fn test_addrv2_entry_roundtrip() {
        let entry = AddrV2Entry {
            timestamp: 1700000000,
            services: 1033, // NODE_NETWORK | NODE_WITNESS
            addr: NetworkAddr::Ipv4(Ipv4Addr::new(8, 8, 8, 8)),
            port: 8333,
        };

        let mut buf = Vec::new();
        entry.serialize(&mut buf).unwrap();

        let mut cursor = Cursor::new(&buf);
        let decoded = AddrV2Entry::deserialize(&mut cursor).unwrap().unwrap();

        assert_eq!(decoded.timestamp, entry.timestamp);
        assert_eq!(decoded.services, entry.services);
        assert_eq!(decoded.addr, entry.addr);
        assert_eq!(decoded.port, entry.port);
    }

    #[test]
    fn test_addrv2_entry_torv3() {
        let mut pubkey = [0u8; 32];
        pubkey.iter_mut().enumerate().for_each(|(i, b)| *b = i as u8);

        let entry = AddrV2Entry {
            timestamp: 1700000000,
            services: 1,
            addr: NetworkAddr::TorV3(pubkey),
            port: 9050,
        };

        let mut buf = Vec::new();
        entry.serialize(&mut buf).unwrap();

        let mut cursor = Cursor::new(&buf);
        let decoded = AddrV2Entry::deserialize(&mut cursor).unwrap().unwrap();

        assert_eq!(decoded.addr, entry.addr);
        assert_eq!(decoded.port, 9050);
    }

    #[test]
    fn test_addrv2_message_roundtrip() {
        let entries = vec![
            AddrV2Entry {
                timestamp: 1700000000,
                services: 1033,
                addr: NetworkAddr::Ipv4(Ipv4Addr::new(8, 8, 8, 8)),
                port: 8333,
            },
            AddrV2Entry {
                timestamp: 1700000001,
                services: 1,
                addr: NetworkAddr::TorV3([0x42; 32]),
                port: 9050,
            },
            AddrV2Entry {
                timestamp: 1700000002,
                services: 1,
                addr: NetworkAddr::I2P([0xab; 32]),
                port: 4567,
            },
        ];

        let serialized = serialize_addrv2_message(&entries);
        let decoded = deserialize_addrv2_message(&serialized).unwrap();

        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0], entries[0]);
        assert_eq!(decoded[1], entries[1]);
        assert_eq!(decoded[2], entries[2]);
    }

    #[test]
    fn test_legacy_format_ipv4() {
        let addr = NetworkAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1));
        let legacy = addr.serialize_legacy().unwrap();

        // Should be IPv4-mapped IPv6
        assert_eq!(&legacy[0..10], &[0; 10]);
        assert_eq!(legacy[10], 0xff);
        assert_eq!(legacy[11], 0xff);
        assert_eq!(legacy[12], 192);
        assert_eq!(legacy[13], 168);
        assert_eq!(legacy[14], 1);
        assert_eq!(legacy[15], 1);

        // Roundtrip
        let decoded = NetworkAddr::deserialize_legacy(&legacy);
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_legacy_format_ipv6() {
        let ip = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        let addr = NetworkAddr::Ipv6(ip);
        let legacy = addr.serialize_legacy().unwrap();

        let decoded = NetworkAddr::deserialize_legacy(&legacy);
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_legacy_format_not_supported() {
        let addr = NetworkAddr::TorV3([0u8; 32]);
        assert!(addr.serialize_legacy().is_none());

        let addr = NetworkAddr::I2P([0u8; 32]);
        assert!(addr.serialize_legacy().is_none());

        let addr = NetworkAddr::Cjdns([0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(addr.serialize_legacy().is_none());
    }

    #[test]
    fn test_is_addr_v1_compatible() {
        assert!(NetworkAddr::Ipv4(Ipv4Addr::new(1, 2, 3, 4)).is_addr_v1_compatible());
        assert!(NetworkAddr::Ipv6(Ipv6Addr::LOCALHOST).is_addr_v1_compatible());
        assert!(!NetworkAddr::TorV3([0; 32]).is_addr_v1_compatible());
        assert!(!NetworkAddr::I2P([0; 32]).is_addr_v1_compatible());
        assert!(!NetworkAddr::Cjdns([0xfc; 16]).is_addr_v1_compatible());
    }

    #[test]
    fn test_services_compact_encoding() {
        // Test that services use CompactSize in ADDRv2
        let entry = AddrV2Entry {
            timestamp: 0,
            services: 252, // Fits in 1 byte
            addr: NetworkAddr::Ipv4(Ipv4Addr::new(1, 2, 3, 4)),
            port: 8333,
        };

        let mut buf = Vec::new();
        entry.serialize(&mut buf).unwrap();

        // 4 (timestamp) + 1 (services <= 252) + 1 (netid) + 1 (len) + 4 (ipv4) + 2 (port)
        assert_eq!(buf.len(), 13);

        // Now with larger services value
        let entry2 = AddrV2Entry {
            timestamp: 0,
            services: 1033, // Needs 3 bytes in CompactSize
            addr: NetworkAddr::Ipv4(Ipv4Addr::new(1, 2, 3, 4)),
            port: 8333,
        };

        let mut buf2 = Vec::new();
        entry2.serialize(&mut buf2).unwrap();

        // 4 (timestamp) + 3 (0xFD + 2 bytes) + 1 (netid) + 1 (len) + 4 (ipv4) + 2 (port)
        assert_eq!(buf2.len(), 15);
    }

    #[test]
    fn test_torv3_pubkey_validation() {
        // Valid pubkey (not all zeros or ones)
        let mut pubkey = [0u8; 32];
        pubkey[0] = 0x42;
        assert!(torv3::validate_pubkey(&pubkey));

        // All zeros - invalid
        assert!(!torv3::validate_pubkey(&[0u8; 32]));

        // All ones - invalid
        assert!(!torv3::validate_pubkey(&[0xff; 32]));
    }

    #[test]
    fn test_i2p_base32_encode() {
        let hash = [0u8; 32];
        let encoded = i2p::encode_base32(&hash);
        // 32 bytes = 256 bits, base32 needs 52 chars (256/5 = 51.2, round up)
        assert_eq!(encoded.len(), 52);
        assert!(encoded.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
    }

    #[test]
    fn test_i2p_address_format() {
        let hash = [0u8; 32];
        let addr = i2p::format_address(&hash);
        assert!(addr.ends_with(".b32.i2p"));
    }

    #[test]
    fn test_socket_addr_conversion() {
        let socket: SocketAddr = "192.168.1.1:8333".parse().unwrap();
        let addr = NetworkAddr::from_socket_addr(&socket);
        assert!(matches!(addr, NetworkAddr::Ipv4(_)));

        let back = addr.to_socket_addr(8333).unwrap();
        assert_eq!(back, socket);
    }

    #[test]
    fn test_bip155_vector_ipv4() {
        // Test vector: IPv4 address 1.2.3.4
        let addr = NetworkAddr::Ipv4(Ipv4Addr::new(1, 2, 3, 4));
        let mut buf = Vec::new();
        addr.serialize_addrv2(&mut buf).unwrap();

        // Network ID 1, length 4, address bytes
        assert_eq!(buf, vec![0x01, 0x04, 1, 2, 3, 4]);
    }

    #[test]
    fn test_bip155_vector_torv3() {
        // Test vector: TorV3 with all 0x42 bytes
        let addr = NetworkAddr::TorV3([0x42; 32]);
        let mut buf = Vec::new();
        addr.serialize_addrv2(&mut buf).unwrap();

        // Network ID 4, length 32, address bytes
        assert_eq!(buf[0], 0x04);
        assert_eq!(buf[1], 0x20); // 32 in CompactSize
        assert_eq!(&buf[2..], &[0x42; 32]);
    }

    #[test]
    fn test_addrv2_too_many_entries() {
        // Create message claiming 10000 entries
        let mut data = Vec::new();
        write_compact_size(&mut data, 10000).unwrap();

        let result = deserialize_addrv2_message(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_addrv2_address_too_large() {
        // Address claiming to be 1000 bytes
        let mut data = Vec::new();
        data.push(99); // Unknown network
        write_compact_size(&mut data, 1000).unwrap();

        let mut cursor = Cursor::new(&data);
        let result = NetworkAddr::deserialize_addrv2(&mut cursor);
        assert!(result.is_err());
    }
}
