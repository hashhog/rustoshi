//! Network group calculation for eclipse attack protection.
//!
//! This module implements network grouping similar to Bitcoin Core's NetGroupManager.
//! Network groups are used to ensure diversity in outbound connections, preventing
//! eclipse attacks where an attacker controls all of a node's connections.
//!
//! Grouping rules:
//! - IPv4: /16 prefix (first 2 bytes)
//! - IPv6: /32 prefix (first 4 bytes)
//! - Tor/I2P: 4-bit prefix (minimal grouping since addresses are pseudorandom)
//! - Local addresses: all belong to same group
//! - Unroutable addresses: all belong to same group

use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Network type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetworkType {
    /// IPv4 network
    Ipv4,
    /// IPv6 network
    Ipv6,
    /// Tor onion network (addresses starting with fd87:d87e:eb43)
    Tor,
    /// I2P network (addresses starting with specific prefix)
    I2P,
    /// CJDNS network (addresses starting with fc00)
    Cjdns,
    /// Local/loopback addresses
    Local,
    /// Unroutable addresses
    Unroutable,
}

/// A network group identifier.
///
/// Addresses in the same network group are considered "close" from a network topology
/// perspective. For eclipse attack prevention, we want outbound connections to be
/// spread across different network groups.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct NetGroup(Vec<u8>);

impl NetGroup {
    /// Create a network group from raw bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes of this network group.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Create a keyed version of this network group for deterministic sorting.
    ///
    /// This is used by eviction logic to protect diverse netgroups.
    pub fn keyed(&self, key: u64) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        self.0.hash(&mut hasher);
        hasher.finish()
    }
}

impl std::fmt::Debug for NetGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NetGroup({:02x?})", self.0)
    }
}

/// Network group manager for computing network groups from addresses.
#[derive(Debug, Clone)]
pub struct NetGroupManager {
    /// Random key for keyed netgroup hashing (set once at startup).
    /// This makes netgroup selection unpredictable to attackers.
    key: u64,
}

impl NetGroupManager {
    /// Create a new network group manager with a random key.
    pub fn new() -> Self {
        Self {
            key: rand::random(),
        }
    }

    /// Create a network group manager with a specific key (for testing).
    pub fn with_key(key: u64) -> Self {
        Self { key }
    }

    /// Get the random key used for keyed hashing.
    pub fn key(&self) -> u64 {
        self.key
    }

    /// Classify the network type of an IP address.
    pub fn classify_network(&self, addr: &IpAddr) -> NetworkType {
        match addr {
            IpAddr::V4(v4) => self.classify_v4(v4),
            IpAddr::V6(v6) => self.classify_v6(v6),
        }
    }

    /// Classify an IPv4 address.
    fn classify_v4(&self, addr: &Ipv4Addr) -> NetworkType {
        let octets = addr.octets();

        // Loopback (127.0.0.0/8)
        if octets[0] == 127 {
            return NetworkType::Local;
        }

        // Private networks - still routable for our purposes
        // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        // We treat these as regular IPv4 for grouping

        // Link-local (169.254.0.0/16)
        if octets[0] == 169 && octets[1] == 254 {
            return NetworkType::Unroutable;
        }

        // Unspecified (0.0.0.0)
        if octets == [0, 0, 0, 0] {
            return NetworkType::Unroutable;
        }

        // Broadcast (255.255.255.255)
        if octets == [255, 255, 255, 255] {
            return NetworkType::Unroutable;
        }

        NetworkType::Ipv4
    }

    /// Classify an IPv6 address.
    fn classify_v6(&self, addr: &Ipv6Addr) -> NetworkType {
        let octets = addr.octets();

        // Check for IPv4-mapped IPv6 (::ffff:x.x.x.x)
        if octets[0..10] == [0; 10] && octets[10] == 0xff && octets[11] == 0xff {
            let v4 = Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
            return self.classify_v4(&v4);
        }

        // Loopback (::1)
        if addr.is_loopback() {
            return NetworkType::Local;
        }

        // Unspecified (::)
        if addr.is_unspecified() {
            return NetworkType::Unroutable;
        }

        // Tor onion addresses: fd87:d87e:eb43::/48
        // Bitcoin Core's internal representation of Tor v3
        if octets[0] == 0xfd
            && octets[1] == 0x87
            && octets[2] == 0xd8
            && octets[3] == 0x7e
            && octets[4] == 0xeb
            && octets[5] == 0x43
        {
            return NetworkType::Tor;
        }

        // I2P addresses: fd87:d87e:eb44::/48
        // Bitcoin Core's internal representation of I2P
        if octets[0] == 0xfd
            && octets[1] == 0x87
            && octets[2] == 0xd8
            && octets[3] == 0x7e
            && octets[4] == 0xeb
            && octets[5] == 0x44
        {
            return NetworkType::I2P;
        }

        // CJDNS addresses: fc00::/8
        if octets[0] == 0xfc {
            return NetworkType::Cjdns;
        }

        // Link-local (fe80::/10)
        if octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80 {
            return NetworkType::Unroutable;
        }

        NetworkType::Ipv6
    }

    /// Get the network group for an IP address.
    ///
    /// This implements the grouping rules from Bitcoin Core's NetGroupManager::GetGroup():
    /// - IPv4: /16 prefix
    /// - IPv6: /32 prefix
    /// - Tor/I2P: 4-bit prefix
    /// - CJDNS: 12-bit prefix (skip constant first byte)
    /// - Local/Unroutable: single group each
    pub fn get_group(&self, addr: &IpAddr) -> NetGroup {
        let net_type = self.classify_network(addr);

        let mut group = Vec::new();
        group.push(net_type as u8);

        match addr {
            IpAddr::V4(v4) => {
                match net_type {
                    NetworkType::Ipv4 => {
                        // IPv4: use /16 (first 2 bytes)
                        let octets = v4.octets();
                        group.push(octets[0]);
                        group.push(octets[1]);
                    }
                    NetworkType::Local | NetworkType::Unroutable => {
                        // All local/unroutable addresses in same group
                    }
                    _ => {}
                }
            }
            IpAddr::V6(v6) => {
                let octets = v6.octets();

                // Check for IPv4-mapped
                if octets[0..10] == [0; 10] && octets[10] == 0xff && octets[11] == 0xff {
                    if net_type == NetworkType::Ipv4 {
                        // IPv4-mapped: use /16 of the IPv4 part
                        group.push(octets[12]);
                        group.push(octets[13]);
                    }
                    return NetGroup::new(group);
                }

                match net_type {
                    NetworkType::Ipv6 => {
                        // IPv6: use /32 (first 4 bytes)
                        group.extend_from_slice(&octets[0..4]);
                    }
                    NetworkType::Tor | NetworkType::I2P => {
                        // Tor/I2P: use 4 bits
                        // Since addresses are pseudorandom, minimal grouping
                        group.push(octets[6] >> 4);
                    }
                    NetworkType::Cjdns => {
                        // CJDNS: skip the constant fc prefix, use 12 bits
                        group.push(octets[1]);
                        group.push(octets[2] >> 4);
                    }
                    NetworkType::Local | NetworkType::Unroutable => {
                        // All local/unroutable in same group
                    }
                    _ => {}
                }
            }
        }

        NetGroup::new(group)
    }

    /// Get the network group for a socket address.
    pub fn get_group_for_socket(&self, addr: &SocketAddr) -> NetGroup {
        self.get_group(&addr.ip())
    }

    /// Get a keyed hash of the network group (for deterministic eviction protection).
    pub fn get_keyed_group(&self, addr: &IpAddr) -> u64 {
        self.get_group(addr).keyed(self.key)
    }

    /// Check if two addresses are in the same network group.
    pub fn same_group(&self, a: &IpAddr, b: &IpAddr) -> bool {
        self.get_group(a) == self.get_group(b)
    }

    /// Check if an address is in a "privacy network" (Tor, I2P, CJDNS).
    ///
    /// Privacy networks get special treatment in connection diversity logic
    /// because their addresses don't have meaningful geographic grouping.
    pub fn is_privacy_network(&self, addr: &IpAddr) -> bool {
        matches!(
            self.classify_network(addr),
            NetworkType::Tor | NetworkType::I2P | NetworkType::Cjdns
        )
    }

    /// Check if an address is local (loopback).
    pub fn is_local(&self, addr: &IpAddr) -> bool {
        self.classify_network(addr) == NetworkType::Local
    }

    /// Check if an address is routable.
    pub fn is_routable(&self, addr: &IpAddr) -> bool {
        !matches!(
            self.classify_network(addr),
            NetworkType::Local | NetworkType::Unroutable
        )
    }
}

impl Default for NetGroupManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_same_slash_16() {
        let mgr = NetGroupManager::with_key(12345);

        let a: IpAddr = "192.168.1.1".parse().unwrap();
        let b: IpAddr = "192.168.255.255".parse().unwrap();

        assert!(mgr.same_group(&a, &b));
    }

    #[test]
    fn test_ipv4_different_slash_16() {
        let mgr = NetGroupManager::with_key(12345);

        let a: IpAddr = "192.168.1.1".parse().unwrap();
        let b: IpAddr = "192.169.1.1".parse().unwrap();

        assert!(!mgr.same_group(&a, &b));
    }

    #[test]
    fn test_ipv6_same_slash_32() {
        let mgr = NetGroupManager::with_key(12345);

        let a: IpAddr = "2001:db8:1234:5678::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1234:ffff::1".parse().unwrap();

        // Both have same first 32 bits (2001:db8:)
        assert!(mgr.same_group(&a, &b));
    }

    #[test]
    fn test_ipv6_different_slash_32() {
        let mgr = NetGroupManager::with_key(12345);

        let a: IpAddr = "2001:db8::1".parse().unwrap();
        let b: IpAddr = "2001:db9::1".parse().unwrap();

        assert!(!mgr.same_group(&a, &b));
    }

    #[test]
    fn test_ipv4_mapped_ipv6() {
        let mgr = NetGroupManager::with_key(12345);

        // IPv4-mapped IPv6 address ::ffff:192.168.1.1
        let v6: IpAddr = "::ffff:192.168.1.1".parse().unwrap();
        let v4: IpAddr = "192.168.1.2".parse().unwrap();

        // Should be in the same group (same /16)
        assert!(mgr.same_group(&v4, &v6));
    }

    #[test]
    fn test_loopback_same_group() {
        let mgr = NetGroupManager::with_key(12345);

        let a: IpAddr = "127.0.0.1".parse().unwrap();
        let b: IpAddr = "127.0.0.2".parse().unwrap();

        assert!(mgr.same_group(&a, &b));
        assert!(mgr.is_local(&a));
    }

    #[test]
    fn test_ipv6_loopback() {
        let mgr = NetGroupManager::with_key(12345);

        let a: IpAddr = "::1".parse().unwrap();

        assert!(mgr.is_local(&a));
        assert_eq!(mgr.classify_network(&a), NetworkType::Local);
    }

    #[test]
    fn test_classify_privacy_networks() {
        let mgr = NetGroupManager::with_key(12345);

        // Tor v3 internal representation: fd87:d87e:eb43::/48
        let tor: IpAddr = "fd87:d87e:eb43::1".parse().unwrap();
        assert_eq!(mgr.classify_network(&tor), NetworkType::Tor);
        assert!(mgr.is_privacy_network(&tor));

        // I2P internal representation: fd87:d87e:eb44::/48
        let i2p: IpAddr = "fd87:d87e:eb44::1".parse().unwrap();
        assert_eq!(mgr.classify_network(&i2p), NetworkType::I2P);
        assert!(mgr.is_privacy_network(&i2p));

        // CJDNS: fc00::/8
        let cjdns: IpAddr = "fc00::1".parse().unwrap();
        assert_eq!(mgr.classify_network(&cjdns), NetworkType::Cjdns);
        assert!(mgr.is_privacy_network(&cjdns));
    }

    #[test]
    fn test_regular_not_privacy_network() {
        let mgr = NetGroupManager::with_key(12345);

        let ipv4: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(!mgr.is_privacy_network(&ipv4));

        let ipv6: IpAddr = "2001:4860:4860::8888".parse().unwrap();
        assert!(!mgr.is_privacy_network(&ipv6));
    }

    #[test]
    fn test_keyed_group_deterministic() {
        let mgr = NetGroupManager::with_key(12345);

        let addr: IpAddr = "192.168.1.1".parse().unwrap();

        let keyed1 = mgr.get_keyed_group(&addr);
        let keyed2 = mgr.get_keyed_group(&addr);

        assert_eq!(keyed1, keyed2);
    }

    #[test]
    fn test_keyed_group_different_keys() {
        let mgr1 = NetGroupManager::with_key(12345);
        let mgr2 = NetGroupManager::with_key(67890);

        let addr: IpAddr = "192.168.1.1".parse().unwrap();

        let keyed1 = mgr1.get_keyed_group(&addr);
        let keyed2 = mgr2.get_keyed_group(&addr);

        // Different keys should produce different keyed hashes
        assert_ne!(keyed1, keyed2);
    }

    #[test]
    fn test_netgroup_bytes() {
        let mgr = NetGroupManager::with_key(12345);

        let addr: IpAddr = "192.168.1.1".parse().unwrap();
        let group = mgr.get_group(&addr);

        // Should be network type (Ipv4=0) + two bytes (192, 168)
        let bytes = group.as_bytes();
        assert_eq!(bytes[0], NetworkType::Ipv4 as u8);
        assert_eq!(bytes[1], 192);
        assert_eq!(bytes[2], 168);
    }

    #[test]
    fn test_socket_addr_group() {
        let mgr = NetGroupManager::with_key(12345);

        let socket: SocketAddr = "192.168.1.1:8333".parse().unwrap();
        let group = mgr.get_group_for_socket(&socket);

        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let ip_group = mgr.get_group(&ip);

        assert_eq!(group, ip_group);
    }

    #[test]
    fn test_is_routable() {
        let mgr = NetGroupManager::with_key(12345);

        // Routable
        assert!(mgr.is_routable(&"8.8.8.8".parse().unwrap()));
        assert!(mgr.is_routable(&"2001:4860:4860::8888".parse().unwrap()));

        // Not routable
        assert!(!mgr.is_routable(&"127.0.0.1".parse().unwrap()));
        assert!(!mgr.is_routable(&"::1".parse().unwrap()));
        assert!(!mgr.is_routable(&"0.0.0.0".parse().unwrap()));
    }

    #[test]
    fn test_eclipse_diversity_scenario() {
        // Simulate eclipse attack scenario: attacker controls addresses in same /16
        let mgr = NetGroupManager::with_key(12345);

        let attacker_addrs: Vec<IpAddr> = (1..=10)
            .map(|i| format!("192.168.1.{}", i).parse().unwrap())
            .collect();

        // All attacker addresses should be in the same group
        let first_group = mgr.get_group(&attacker_addrs[0]);
        for addr in &attacker_addrs[1..] {
            assert_eq!(mgr.get_group(addr), first_group);
        }

        // Legitimate diverse addresses
        let diverse_addrs: Vec<IpAddr> = vec![
            "8.8.8.8".parse().unwrap(),
            "1.1.1.1".parse().unwrap(),
            "9.9.9.9".parse().unwrap(),
        ];

        // Each should be in a different group
        let groups: Vec<_> = diverse_addrs.iter().map(|a| mgr.get_group(a)).collect();
        assert_ne!(groups[0], groups[1]);
        assert_ne!(groups[1], groups[2]);
        assert_ne!(groups[0], groups[2]);
    }
}
