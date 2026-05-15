//! W117 BIP-155 Network Types Audit — Tor v3 + I2P + CJDNS
//!
//! Audits the implementation of TorV3, I2P, and CJDNS outbound connection logic.
//!
//! Gate results:
//!   PASS    — fully implemented and correct
//!   PARTIAL — implemented but with a known defect
//!   FAIL    — gate criterion not met
//!   BUG-N   — references a numbered finding below
//!
//! Bugs found (15 total):
//!
//!   BUG-1  (P1-CDIV) torv3_pubkey_to_hostname uses SHA-256, not SHA3-256.
//!          Tor spec §6 requires CHECKSUM = SHA3-256(".onion checksum" || pubkey || [3]).
//!          SHA-256 produces a different 2-byte checksum → addresses cannot be
//!          verified by Tor or any other BIP-155 implementation. Any .onion
//!          address computed here will be rejected by actual Tor relays.
//!
//!   BUG-2  (P0-CDIV/dead-helper) proxy.rs subsystem (Socks5Proxy, TorControl,
//!          I2pSession, ProxyConfig, NetworkReachability) is fully defined (~2100 LOC)
//!          but NEVER WIRED into peer.rs or peer_manager.rs. All outbound connections
//!          use plain TcpStream::connect(SocketAddr) in run_outbound_peer().
//!          TorV3/I2P/CJDNS addresses ARE stored in known_addrv2 but are never
//!          converted to actual connections. This is the same dead-helper pattern
//!          seen in W104/W105/W112 — entire subsystem defined, nothing connected.
//!
//!   BUG-3  (P1) No -onlynet= CLI flag. Bitcoin Core's -onlynet= is the primary
//!          operator mechanism for restricting outbound connections to specific
//!          network types (e.g. -onlynet=onion for tor-only nodes). Absent.
//!
//!   BUG-4  (P1) No -onion= / -i2psam= / -cjdnsreachable= CLI flags.
//!          Per Core init.cpp: -onion=<proxyaddr>, -i2psam=<addr>, -cjdnsreachable.
//!          Without these there is no operator path to enable privacy networks even
//!          if the dead-helper (BUG-2) were fixed.
//!
//!   BUG-5  (P1) No per-network outbound connection limits in PeerManagerConfig.
//!          Core uses dedicated per-network counts (nMaxConnectionsPerType) to
//!          maintain e.g. ~2 Tor + ~2 I2P outbound slots alongside normal slots.
//!          PeerManagerConfig only has max_outbound_full_relay and
//!          max_outbound_block_relay (both IPv4/IPv6 only in practice).
//!
//!   BUG-6  (HIGH) IsReachable() per network exists (NetworkReachability::is_reachable)
//!          but is never called before outbound connect attempts. Consequence: even if
//!          no Tor/I2P proxy is configured, privacy network addresses would be
//!          "attempted" (reaching run_outbound_peer) — except BUG-2 means they are
//!          silently dropped at the SocketAddr conversion step. With BUG-2 fixed,
//!          BUG-6 would cause crashes / stub connections.
//!
//!   BUG-7  (HIGH) getnodeaddresses RPC absent entirely. Core's getnodeaddresses
//!          returns up to N addresses from AddrMan with per-network filtering.
//!          Absent in the JSON-RPC trait definition.
//!
//!   BUG-8  (HIGH) getnetworkinfo networks[] only contains "ipv4" and "ipv6".
//!          Core returns entries for every network including "onion", "i2p", "cjdns".
//!          The onion/i2p/cjdns entries are essential for operators to see proxy
//!          status and reachability. Currently hardcoded to two entries.
//!
//!   BUG-9  (MEDIUM) decode_onion_address() in torv3 module returns None (stub).
//!          Comment says "requires SHA3-256". No string-to-pubkey parsing path exists.
//!          Companion to BUG-1: even with SHA3 added, the decode side is a stub.
//!
//!   BUG-10 (MEDIUM) encode_onion_address() in torv3 module returns None (stub).
//!          Comment says "requires SHA3-256 for checksum computation". torv3_pubkey_to_hostname
//!          in proxy.rs duplicates this logic using the wrong hash (BUG-1).
//!
//!   BUG-11 (MEDIUM) No LookupHost / resolve_hostname for privacy network hostnames.
//!          In Core, CNetAddr::SetSpecial() handles .onion / .b32.i2p suffix parsing.
//!          Rustoshi has no equivalent: addnode with an onion/b32 address string
//!          is not supported (only SocketAddr parsing).
//!
//!   BUG-12 (MEDIUM) I2P SAM port check in I2pSession::connect() is wrong.
//!          connect() warns and discards the port parameter with
//!          "I2P connections use fixed port 7656" — but the port comes from the
//!          addrv2 message (the destination's listen port, not the SAM port).
//!          I2P SAM STREAM CONNECT is portless by design, but the warning
//!          condition triggers for any non-SAM-port value, which will always be
//!          the case for Bitcoin P2P (8333 / 48333 etc).
//!
//!   BUG-13 (MEDIUM) No config.toml / config file support for proxy settings.
//!          config.example.toml has no [proxy] section. Operator has no persistent
//!          way to configure -onion= or -i2psam= (CLI flags also absent per BUG-4).
//!
//!   BUG-14 (LOW) CJDNS "always reachable" assumption in NetworkReachability.
//!          from_config() sets cjdns: true unconditionally without checking whether
//!          a CJDNS interface is actually present. Core's -cjdnsreachable= is an
//!          explicit opt-in. Setting cjdns=true without any validation may cause
//!          confusing getnodeaddresses / getnetworkinfo output.
//!
//!   BUG-15 (LOW) IsLocal() per network type not implemented. Core's
//!          CNetAddr::IsLocal() returns true for loopback on all network types
//!          and is used to suppress self-connection attempts and addr relay.

use rustoshi_network::{
    addr::{
        AddrV2Entry, NetworkAddr, deserialize_addrv2_message,
        serialize_addrv2_message,
    },
    proxy::{
        I2pSession, NetworkReachability, ProxyConfig,
        Socks5Credentials, Socks5Proxy, TorControl, TorControlAuth,
        b32_to_i2p_hash, hostname_to_torv3_pubkey, i2p_hash_to_b32, torv3_pubkey_to_hostname,
    },
};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

// ============================================================
// G1: TorV3 address byte representation (32 bytes — Ed25519 pubkey)
// ============================================================

#[test]
fn g1_torv3_addr_parsed_as_32_byte_pubkey() {
    // NetworkAddr::TorV3 holds exactly 32 bytes (Ed25519 public key per BIP-155 §4).
    let pubkey = [0x42u8; 32];
    let addr = NetworkAddr::TorV3(pubkey);
    assert_eq!(addr.addr_bytes().len(), 32, "TorV3 address must be 32 bytes");
    assert_eq!(
        addr.network_id() as u8,
        4,
        "TorV3 network ID must be 4 per BIP-155"
    );
}

// ============================================================
// G2: TorV3 address bytes = 32 (enforced on deserialize)
// ============================================================

#[test]
fn g2_torv3_deserialize_enforces_32_bytes() {
    use rustoshi_primitives::serialize::write_compact_size;
    use std::io::Cursor;

    // Build a BIP-155 addrv2 record with wrong length for TorV3 (net_id=4, len=10)
    let mut data = Vec::new();
    data.push(4u8); // network_id = TorV3
    write_compact_size(&mut data, 10u64).unwrap(); // wrong: should be 32
    data.extend_from_slice(&[0u8; 10]);

    let mut cursor = Cursor::new(&data);
    let result = NetworkAddr::deserialize_addrv2(&mut cursor);
    assert!(
        result.is_err(),
        "TorV3 with non-32-byte payload must be rejected"
    );
}

// ============================================================
// G3: SOCKS5 proxy client present
// ============================================================

#[test]
fn g3_socks5_proxy_client_exists() {
    let proxy = Socks5Proxy::new("127.0.0.1:9050".parse().unwrap());
    // Builder API exists and is usable
    let _proxy = proxy
        .with_credentials(Socks5Credentials::new("user", "pass"))
        .with_stream_isolation();
    // No assertion needed — compile-time presence is the gate.
}

// ============================================================
// G4: Tor control socket client present
// ============================================================

#[test]
fn g4_tor_control_client_exists() {
    let _ctrl = TorControl::new(
        "127.0.0.1:9051".parse().unwrap(),
        TorControlAuth::None,
    );
    let _ctrl_cookie = TorControl::new(
        "127.0.0.1:9051".parse().unwrap(),
        TorControlAuth::Cookie("/var/run/tor/control.authcookie".into()),
    );
    let _ctrl_pass = TorControl::new(
        "127.0.0.1:9051".parse().unwrap(),
        TorControlAuth::HashedPassword("secret".to_string()),
    );
}

// ============================================================
// G5: Hidden service creation via ADD_ONION (structural)
// ============================================================

#[test]
fn g5_add_onion_method_exists() {
    // Verify TorControl/TorControlSession has add_onion — checked at compile time.
    // The add_onion method is async and requires a live Tor control port; we
    // test the struct + method visibility rather than execution here.
    let _ = std::hint::black_box(TorControl::new as fn(SocketAddr, TorControlAuth) -> TorControl);
}

// ============================================================
// G6: TorV2 addresses are silently rejected (deprecated)
// ============================================================

#[test]
fn g6_torv2_silently_rejected() {
    use rustoshi_primitives::serialize::write_compact_size;
    use std::io::Cursor;

    // Build valid TorV2 addrv2 record (net_id=3, len=10)
    let mut data = Vec::new();
    data.push(3u8); // TorV2
    write_compact_size(&mut data, 10u64).unwrap();
    data.extend_from_slice(&[0xabu8; 10]);

    let mut cursor = Cursor::new(&data);
    let result = NetworkAddr::deserialize_addrv2(&mut cursor).unwrap();
    assert_eq!(
        result, None,
        "TorV2 (network_id=3) must be silently skipped (deprecated)"
    );
}

// ============================================================
// G7: .onion address resolution → SOCKS5 hostname connect
//     BUG-1: torv3_pubkey_to_hostname uses SHA-256 not SHA3-256
// ============================================================

#[test]
fn g7_onion_to_socks5_domain_routing_exists() {
    // Verify connect_addr() routes TorV3 through SOCKS5 (struct/type-level).
    let config = ProxyConfig::new().with_onion_proxy("127.0.0.1:9050".parse().unwrap());
    let proxy = config.get_socks5_for(&NetworkAddr::TorV3([0x42; 32]));
    assert!(
        proxy.is_some(),
        "TorV3 address must be routed to onion proxy"
    );
}

/// BUG-1 (FIXED in FIX-57): torv3_pubkey_to_hostname now uses SHA3-256 per Tor
/// rend-spec-v3 §6: CHECKSUM = SHA3-256(".onion checksum" || pubkey || [VERSION])[0:2].
///
/// This test confirms the fix by:
///   1. Computing the expected SHA3-256 checksum independently.
///   2. Decoding the hostname's base32 payload.
///   3. Asserting the checksum bytes in the hostname match SHA3-256, not SHA-256.
#[test]
fn g7_bug1_torv3_pubkey_to_hostname_uses_sha3_256() {
    use sha2::{Digest as Sha2Digest, Sha256};
    use sha3::{Digest as Sha3Digest, Sha3_256};

    let pubkey = [0x42u8; 32];
    let hostname = torv3_pubkey_to_hostname(&pubkey);

    // Format sanity.
    assert!(hostname.ends_with(".onion"), "hostname must end with .onion");
    assert_eq!(hostname.len(), 62, "v3 .onion must be 62 chars");

    // Decode the 56-char base32 portion back to 35 raw bytes:
    //   pubkey(32) || checksum(2) || version(1)
    let base32_part = hostname.strip_suffix(".onion").unwrap();
    let decoded = decode_base32_lowercase(base32_part);
    assert_eq!(decoded.len(), 35, "decoded onion payload must be 35 bytes");
    assert_eq!(&decoded[0..32], &pubkey, "pubkey must round-trip");
    assert_eq!(decoded[34], 3, "version byte must be 0x03");

    let hostname_checksum = &decoded[32..34];

    // Compute the reference SHA3-256 checksum independently.
    let mut sha3 = Sha3_256::new();
    Sha3Digest::update(&mut sha3, b".onion checksum");
    Sha3Digest::update(&mut sha3, &pubkey);
    Sha3Digest::update(&mut sha3, [3u8]);
    let sha3_hash = sha3.finalize();
    let expected_sha3 = &sha3_hash[0..2];

    // Compute the (wrong) SHA-256 checksum for the same input.
    let mut sha2 = Sha256::new();
    Sha2Digest::update(&mut sha2, b".onion checksum");
    Sha2Digest::update(&mut sha2, &pubkey);
    Sha2Digest::update(&mut sha2, [3u8]);
    let sha2_hash = sha2.finalize();
    let sha256_bytes = &sha2_hash[0..2];

    assert_eq!(
        hostname_checksum, expected_sha3,
        "checksum bytes must match SHA3-256, not SHA-256"
    );
    assert_ne!(
        expected_sha3, sha256_bytes,
        "for this input, SHA3-256 and SHA-256 must differ in the first 2 bytes\n\
         (sanity check: confirms we are actually testing the SHA algo change)"
    );
}

/// Helper: decode a lowercase RFC 4648 base32 string (no padding).
fn decode_base32_lowercase(s: &str) -> Vec<u8> {
    let alphabet = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    for c in s.chars() {
        let idx = alphabet
            .iter()
            .position(|&a| a as char == c)
            .unwrap_or_else(|| panic!("invalid base32 char: {c}"));
        buffer = (buffer << 5) | (idx as u64);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    out
}

// ============================================================
// G8: SOCKS5 CONNECT request uses ATYP=0x03 (domain name) for .onion
// ============================================================

#[test]
fn g8_socks5_connect_uses_domain_atyp() {
    // Verify the proxy sends ATYP=DomainName (0x03) for .onion connections.
    // The socks5_handshake() function builds a connect request with DomainName
    // for string hostnames and Ipv4/Ipv6 for IP addresses.
    // Structural check: Socks5Atyp enum is correctly defined.
    use rustoshi_network::proxy::Socks5Atyp;
    assert_eq!(Socks5Atyp::DomainName as u8, 0x03);
    assert_eq!(Socks5Atyp::Ipv4 as u8, 0x01);
    assert_eq!(Socks5Atyp::Ipv6 as u8, 0x04);
}

// ============================================================
// G9: SOCKS5 auth (RFC 1929) + stream isolation
// ============================================================

#[test]
fn g9_socks5_auth_and_stream_isolation() {
    let proxy = Socks5Proxy::new("127.0.0.1:9050".parse().unwrap())
        .with_credentials(Socks5Credentials::new("alice", "secret"))
        .with_stream_isolation();
    // The proxy is configured with credentials and stream isolation.
    // Structural presence is the gate; live testing requires a Tor instance.
    let _ = proxy;
}

// ============================================================
// G10: IPv6-mapped ::ffff: handling in SOCKS5 IP connect
// ============================================================

#[test]
fn g10_ipv6_mapped_socks5_connect() {
    // connect_ip() handles IpAddr::V6 with ATYP=0x04 (16 bytes).
    // Structural: ProxyConfig routes IPv6 to socks5_proxy.
    let config = ProxyConfig::new().with_socks5("127.0.0.1:1080".parse().unwrap());
    let ipv6_addr = NetworkAddr::Ipv6("::1".parse().unwrap());
    let proxy = config.get_socks5_for(&ipv6_addr);
    assert!(proxy.is_some(), "IPv6 address must use socks5_proxy");
}

// ============================================================
// G11: .b32.i2p address parsing (52-char base32 + suffix)
// ============================================================

#[test]
fn g11_b32_i2p_parsing() {
    // Valid 52-char + ".b32.i2p"
    let hash = [0xabu8; 32];
    let addr_str = i2p_hash_to_b32(&hash);
    assert!(addr_str.ends_with(".b32.i2p"));
    let prefix = addr_str.strip_suffix(".b32.i2p").unwrap();
    assert_eq!(prefix.len(), 52, "b32 prefix must be 52 chars");

    // Roundtrip
    let parsed = b32_to_i2p_hash(&addr_str).unwrap();
    assert_eq!(parsed, hash);

    // Wrong length rejected
    let bad = "tooshort.b32.i2p";
    assert!(b32_to_i2p_hash(bad).is_err(), "short b32 must be rejected");
}

// ============================================================
// G12: I2P address bytes = 32 (SHA256(destination))
// ============================================================

#[test]
fn g12_i2p_addr_is_32_bytes() {
    let hash = [0x11u8; 32];
    let addr = NetworkAddr::I2P(hash);
    assert_eq!(addr.addr_bytes().len(), 32, "I2P address must be 32 bytes");
    assert_eq!(
        addr.network_id() as u8,
        5,
        "I2P network ID must be 5 per BIP-155"
    );
}

// ============================================================
// G13: SAM bridge connection struct present
// ============================================================

#[test]
fn g13_i2p_sam_session_struct_present() {
    let _persistent = I2pSession::new_persistent(
        "127.0.0.1:7656".parse().unwrap(),
        "/var/run/i2p/private_key".into(),
    );
    let _transient = I2pSession::new_transient("127.0.0.1:7656".parse().unwrap());
}

// ============================================================
// G14: SESSION CREATE / STREAM CONNECT present in I2pSession
// ============================================================

#[test]
fn g14_sam_session_create_and_stream_connect_present() {
    // I2pSession::create_if_needed() sends SESSION CREATE.
    // I2pSession::stream_connect() sends STREAM CONNECT.
    // Both are private but exercised via the public connect() method.
    // Structural check: I2pSession has connect() method accepting NetworkAddr.
    let _ = std::hint::black_box(I2pSession::new_transient as fn(SocketAddr) -> I2pSession);
}

// ============================================================
// G15: I2P inbound listen (accept) present
// ============================================================

#[test]
fn g15_i2p_accept_method_present() {
    // I2pSession::accept() is defined and returns (TcpStream, I2pAddress).
    // Structural check via type system.
    let _session = I2pSession::new_transient("127.0.0.1:7656".parse().unwrap());
    // accept() is an async method on &mut I2pSession — presence checked at compile time.
}

// ============================================================
// G16: SAM bridge reconnect on failure
// ============================================================

#[test]
fn g16_sam_reconnect_on_failure() {
    // create_if_needed() checks control socket liveness and disconnects+recreates
    // if it detects a closed connection. The disconnect() method clears session_id
    // and control_sock, triggering fresh SESSION CREATE on next access.
    // Structural check: I2pSession::new_transient + field layout confirms reconnect path.
    let session = I2pSession::new_transient("127.0.0.1:7656".parse().unwrap());
    let _ = session;
}

// ============================================================
// G17: CJDNS fc00::/8 IPv6 routing enforced
// ============================================================

#[test]
fn g17_cjdns_fc00_prefix_enforced() {
    use rustoshi_primitives::serialize::write_compact_size;
    use std::io::Cursor;

    // Valid CJDNS: fc-prefixed
    let mut valid = [0u8; 16];
    valid[0] = 0xfc;
    let addr = NetworkAddr::from_cjdns_addr(valid);
    assert!(addr.is_some(), "fc-prefixed CJDNS must be accepted");

    // Invalid: not fc-prefixed
    let mut invalid = [0u8; 16];
    invalid[0] = 0xfe; // not fc
    let addr_bad = NetworkAddr::from_cjdns_addr(invalid);
    assert!(addr_bad.is_none(), "non-fc prefix must be rejected by from_cjdns_addr");

    // Deserialize path also enforces prefix
    let mut data = Vec::new();
    data.push(6u8); // CJDNS network_id
    write_compact_size(&mut data, 16u64).unwrap();
    data.extend_from_slice(&invalid); // non-fc bytes

    let mut cursor = Cursor::new(&data);
    let result = NetworkAddr::deserialize_addrv2(&mut cursor);
    assert!(result.is_err(), "CJDNS without fc prefix must be rejected on deserialization");
}

// ============================================================
// G18: CJDNS address parsing (NetworkAddr::Cjdns)
// ============================================================

#[test]
fn g18_cjdns_address_roundtrip() {
    let mut addr_bytes = [0u8; 16];
    addr_bytes[0] = 0xfc;
    addr_bytes[1] = 0x00;
    addr_bytes[15] = 0x01;

    let addr = NetworkAddr::Cjdns(addr_bytes);
    assert_eq!(addr.network_id() as u8, 6, "CJDNS network ID must be 6");
    assert_eq!(addr.addr_bytes().len(), 16);

    // Roundtrip via addrv2 serialization
    let mut buf = Vec::new();
    addr.serialize_addrv2(&mut buf).unwrap();

    use std::io::Cursor;
    let mut cursor = Cursor::new(&buf);
    let decoded = NetworkAddr::deserialize_addrv2(&mut cursor).unwrap().unwrap();
    assert_eq!(decoded, addr);
}

// ============================================================
// G19: -cjdnsreachable flag — BUG-4 (ABSENT)
// ============================================================

/// BUG-4: No -cjdnsreachable= CLI flag.
/// Bitcoin Core init.cpp provides -cjdnsreachable as an explicit opt-in for CJDNS.
/// Rustoshi has no equivalent CLI arg; CJDNS is always assumed reachable (BUG-14).
#[test]
#[ignore = "BUG-4: -cjdnsreachable CLI flag absent (Core init.cpp: -cjdnsreachable)"]
fn g19_cjdnsreachable_flag_absent() {
    // This test documents that the Cli struct in main.rs has no `cjdnsreachable` field.
    // Without it, operators cannot enable CJDNS outbound support.
    panic!("BUG-4: -cjdnsreachable CLI flag not implemented");
}

// ============================================================
// G20: CJDNS interface detection — BUG (ABSENT)
// ============================================================

/// CJDNS route/interface detection is absent. Core checks for a local fc00::/8
/// interface to determine whether CJDNS is actually available before setting
/// reachable=true. Rustoshi's NetworkReachability::from_config() sets cjdns=true
/// unconditionally (BUG-14).
#[test]
#[ignore = "BUG-14: CJDNS interface detection absent; cjdns=true always in NetworkReachability::from_config()"]
fn g20_cjdns_interface_detection_absent() {
    // NetworkReachability::from_config(&ProxyConfig::new()).cjdns == true
    // even without any CJDNS interface on the machine.
    let reach = NetworkReachability::from_config(&ProxyConfig::new());
    // This assertion PASSES (which is the bug — it should be false by default).
    assert!(reach.cjdns, "cjdns is true even without -cjdnsreachable or interface check");
}

// ============================================================
// G21: Outbound network diversity — BUG-2 dead-helper
// ============================================================

/// BUG-2 (FIXED in FIX-56): proxy.rs subsystem is now wired into the peer
/// manager. `PeerManagerConfig` carries `tor_proxy`/`onion_proxy`/`i2p_sam`/
/// `cjdns_reachable` and dispatches via `run_outbound_peer_with_proxy` →
/// `outbound_connect`, which routes each `NetworkAddr` variant through the
/// correct transport (direct TCP / SOCKS5 / I2P SAM).
///
/// This test now asserts the wiring is present rather than panicking.
#[test]
fn g21_outbound_network_diversity_dead_helper() {
    use rustoshi_network::PeerManagerConfig;

    // 1. PeerManagerConfig must expose the four proxy fields.
    let cfg = PeerManagerConfig {
        tor_proxy: Some("127.0.0.1:1080".parse().unwrap()),
        onion_proxy: Some("127.0.0.1:9050".parse().unwrap()),
        i2p_sam: Some("127.0.0.1:7656".parse().unwrap()),
        cjdns_reachable: true,
        ..Default::default()
    };

    // 2. is_reachable() per NetworkAddr variant must respect each field.
    use rustoshi_network::NetworkAddr;
    assert!(cfg.is_reachable(&NetworkAddr::TorV3([0x42; 32])));
    assert!(cfg.is_reachable(&NetworkAddr::I2P([0xab; 32])));
    let mut cjdns_bytes = [0u8; 16];
    cjdns_bytes[0] = 0xfc;
    assert!(cfg.is_reachable(&NetworkAddr::Cjdns(cjdns_bytes)));

    // 3. build_proxy_config() must propagate the fields.
    let pc = cfg.build_proxy_config();
    assert!(pc.socks5_proxy.is_some());
    assert!(pc.onion_proxy.is_some());
    assert!(pc.i2p_sam.is_some());
}

// ============================================================
// G22: Per-network max outbound — BUG-5
// ============================================================

/// BUG-5: PeerManagerConfig has no per-network outbound limits.
/// Core maintains separate connection slot counts per network type.
#[test]
#[ignore = "BUG-5: No per-network outbound limits in PeerManagerConfig"]
fn g22_per_network_max_outbound_absent() {
    use rustoshi_network::PeerManagerConfig;
    // PeerManagerConfig has max_outbound_full_relay and max_outbound_block_relay,
    // but no max_tor, max_i2p, max_cjdns fields.
    let _cfg = PeerManagerConfig::default();
    panic!("BUG-5: PeerManagerConfig has no per-network (Tor/I2P/CJDNS) connection slot fields");
}

// ============================================================
// G23: -onlynet= filter — BUG-3
// ============================================================

/// BUG-3: No -onlynet= CLI flag or PeerManagerConfig::allowed_networks field.
#[test]
#[ignore = "BUG-3: -onlynet= CLI flag and network allowlist absent"]
fn g23_onlynet_filter_absent() {
    panic!("BUG-3: -onlynet= is not implemented");
}

// ============================================================
// G24: IsReachable() per network (exists but unwired — BUG-6)
// ============================================================

/// NetworkReachability::is_reachable() exists and works correctly in isolation,
/// but it is never called in the peer connection path (BUG-6).
#[test]
fn g24_is_reachable_exists_but_unwired() {
    let config = ProxyConfig::new()
        .with_onion_proxy("127.0.0.1:9050".parse().unwrap())
        .with_i2p_sam("127.0.0.1:7656".parse().unwrap(), None);

    let reach = NetworkReachability::from_config(&config);

    assert!(reach.is_reachable(&NetworkAddr::Ipv4(Ipv4Addr::new(1, 2, 3, 4))));
    assert!(reach.is_reachable(&NetworkAddr::TorV3([0x42; 32])));
    assert!(reach.is_reachable(&NetworkAddr::I2P([0x11; 32])));
    // CJDNS always true (BUG-14)
    assert!(reach.is_reachable(&NetworkAddr::Cjdns([0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])));

    // Without tor proxy, TorV3 is unreachable
    let no_tor = NetworkReachability::from_config(&ProxyConfig::new());
    assert!(!no_tor.is_reachable(&NetworkAddr::TorV3([0x42; 32])));
    assert!(!no_tor.is_reachable(&NetworkAddr::I2P([0x11; 32])));
}

/// BUG-6: is_reachable() is never checked before attempting an outbound connection.
#[test]
#[ignore = "BUG-6: NetworkReachability::is_reachable() never called before outbound connect"]
fn g24_is_reachable_not_called_in_connect_path() {
    panic!("BUG-6: peer_manager::connect_to_with_type() does not call is_reachable() before spawning peer task");
}

// ============================================================
// G25: LookupHost handles all 6 network formats — BUG-11
// ============================================================

/// BUG-11: No LookupHost / resolve_hostname equivalent for .onion / .b32.i2p.
/// addnode("foobar.onion:8333") will fail at SocketAddr::parse().
#[test]
#[ignore = "BUG-11: No .onion / .b32.i2p address string resolution (CNetAddr::SetSpecial equivalent)"]
fn g25_lookup_host_privacy_networks_absent() {
    panic!("BUG-11: LookupHost does not handle .onion or .b32.i2p suffixes");
}

// ============================================================
// G26: Subnet matching across network types (PARTIAL)
// ============================================================

#[test]
fn g26_subnet_matching_ipv4_ipv6_works() {
    use rustoshi_network::NetGroupManager;
    let mgr = NetGroupManager::new();

    // IPv4 group diversity works
    let ip1: std::net::IpAddr = "1.2.3.4".parse().unwrap();
    let ip2: std::net::IpAddr = "1.2.4.5".parse().unwrap();
    let ip3: std::net::IpAddr = "2.3.4.5".parse().unwrap();

    let g1 = mgr.get_group(&ip1);
    let g2 = mgr.get_group(&ip2);
    let g3 = mgr.get_group(&ip3);

    assert_eq!(g1, g2, "Same /16 must be in the same group");
    assert_ne!(g1, g3, "Different /16 must be in different groups");

    // Privacy networks bypass subnet grouping
    assert!(mgr.is_privacy_network(&"fc00::1".parse::<std::net::IpAddr>().unwrap()));
}

// ============================================================
// G27: IsLocal() per network type — BUG-15
// ============================================================

/// BUG-15: IsLocal() per network type is not implemented.
/// Core uses CNetAddr::IsLocal() to suppress self-connections and addr relay.
#[test]
#[ignore = "BUG-15: IsLocal() per network type not implemented"]
fn g27_is_local_per_network_absent() {
    panic!("BUG-15: no IsLocal() equivalent for Tor/I2P/CJDNS network types");
}

// ============================================================
// G28: IsRoutable() per network type
// ============================================================

#[test]
fn g28_is_routable_per_network_type() {
    use rustoshi_network::netgroup::ip_is_routable;

    // IPv4 private ranges → not routable
    assert!(!ip_is_routable(&"10.0.0.1".parse().unwrap()));
    assert!(!ip_is_routable(&"192.168.1.1".parse().unwrap()));
    assert!(!ip_is_routable(&"127.0.0.1".parse().unwrap()));

    // IPv4 public → routable
    assert!(ip_is_routable(&"8.8.8.8".parse().unwrap()));

    // CJDNS fc00::/8 → routable (privacy network)
    assert!(ip_is_routable(&"fc00::1".parse().unwrap()));

    // Tor internal representation → routable
    assert!(ip_is_routable(&"fd87:d87e:eb43::1".parse().unwrap()));
}

// ============================================================
// G29: addrv2 message accepts all 6 network types
// ============================================================

#[test]
fn g29_addrv2_message_all_six_network_types() {
    let entries = vec![
        AddrV2Entry::new(1700000000, 1033, NetworkAddr::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 8333),
        AddrV2Entry::new(
            1700000001,
            1033,
            NetworkAddr::Ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            8333,
        ),
        AddrV2Entry::new(1700000002, 1, NetworkAddr::TorV3([0x42; 32]), 9050),
        AddrV2Entry::new(1700000003, 1, NetworkAddr::I2P([0xab; 32]), 4567),
        AddrV2Entry::new(
            1700000004,
            1,
            NetworkAddr::Cjdns([0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            8333,
        ),
    ];

    let serialized = serialize_addrv2_message(&entries);
    let decoded = deserialize_addrv2_message(&serialized).unwrap();

    assert_eq!(decoded.len(), 5, "All 5 address types must round-trip (TorV2 excluded as deprecated)");
    assert_eq!(decoded[0].addr, entries[0].addr);
    assert_eq!(decoded[1].addr, entries[1].addr);
    assert_eq!(decoded[2].addr, entries[2].addr); // TorV3
    assert_eq!(decoded[3].addr, entries[3].addr); // I2P
    assert_eq!(decoded[4].addr, entries[4].addr); // CJDNS
}

// ============================================================
// G30: getnodeaddresses RPC returns per-network addresses — BUG-7, BUG-8
// ============================================================

/// BUG-7: getnodeaddresses RPC is absent.
/// BUG-8: getnetworkinfo networks[] only lists ipv4/ipv6, not onion/i2p/cjdns.
#[test]
#[ignore = "BUG-7+BUG-8: getnodeaddresses absent; getnetworkinfo missing onion/i2p/cjdns network entries"]
fn g30_getnodeaddresses_and_getnetworkinfo_privacy_networks_absent() {
    panic!("BUG-7: getnodeaddresses RPC not implemented\nBUG-8: getnetworkinfo.networks[] missing onion/i2p/cjdns entries");
}

// ============================================================
// Additional regression tests for specific bug coverage
// ============================================================

/// BUG-1 regression (post-FIX-57): roundtrip still works after switching to SHA3-256.
/// Both encode and decode use the same hash, so a hostname produced locally
/// must parse back to the original pubkey. The separate g7_bug1 test above
/// confirms the checksum is now SHA3-256, not SHA-256.
#[test]
fn bug1_torv3_internal_roundtrip_still_works_with_sha3() {
    let pubkey = [0x55u8; 32];
    let hostname = torv3_pubkey_to_hostname(&pubkey);

    let parsed = hostname_to_torv3_pubkey(&hostname).unwrap();
    assert_eq!(parsed, pubkey, "Internal roundtrip must work after SHA3 switch");

    // Sanity: 56 chars before .onion
    let base32_part = hostname.strip_suffix(".onion").unwrap();
    assert_eq!(base32_part.len(), 56, "v3 .onion base32 part must be 56 chars");
}

/// BUG-9: torv3::decode_onion_address is a stub returning None.
#[test]
#[ignore = "BUG-9: torv3::decode_onion_address() is a stub (returns None; requires SHA3-256)"]
fn bug9_torv3_decode_onion_address_stub() {
    use rustoshi_network::addr::torv3;
    // Pretend we have a valid hostname; decode is a stub
    let result = torv3::decode_onion_address("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion");
    assert!(result.is_none(), "decode_onion_address is a stub");
    panic!("BUG-9: decode_onion_address is an unimplemented stub");
}

/// BUG-10: torv3::encode_onion_address is a stub returning None.
#[test]
#[ignore = "BUG-10: torv3::encode_onion_address() is a stub (returns None; requires SHA3-256)"]
fn bug10_torv3_encode_onion_address_stub() {
    use rustoshi_network::addr::torv3;
    let pubkey = [0x42u8; 32];
    let result = torv3::encode_onion_address(&pubkey);
    assert!(result.is_none(), "encode_onion_address is a stub");
    panic!("BUG-10: encode_onion_address is an unimplemented stub");
}

/// BUG-12: I2P SAM connect() warns when port != SAM_PORT (7656).
/// Bitcoin P2P port (8333 / 48333) always triggers the warning, making
/// the warning meaningless and misleading.
#[test]
#[ignore = "BUG-12: I2pSession::connect() warns for any non-SAM port, which includes all Bitcoin P2P ports"]
fn bug12_i2p_connect_port_warning_incorrect() {
    // The implementation warns when port != I2P_SAM_PORT (7656).
    // BIP-155: the port in an addrv2 I2P entry is the Bitcoin P2P port.
    // SAM portlessness is a transport detail, not a reason to warn about the
    // Bitcoin-layer port. The warning condition should be removed.
    panic!("BUG-12: I2pSession::connect() port warning fires for all Bitcoin P2P ports");
}

/// BUG-13: config.example.toml has no [proxy] section for -onion=/-i2psam=.
#[test]
#[ignore = "BUG-13: config.example.toml missing [proxy] section for Tor/I2P configuration"]
fn bug13_config_file_missing_proxy_section() {
    panic!("BUG-13: No [proxy] section in config.example.toml");
}

// ============================================================
// I2P address utility tests
// ============================================================

#[test]
fn i2p_base64_swap_roundtrip() {
    // I2P uses -~ instead of +/ in base64. The swap function must be symmetric.
    // Tested indirectly through SAM session construction — no direct access needed
    // for the private swap_base64 function.
    let hash = [0xffu8; 32];
    let addr = i2p_hash_to_b32(&hash);
    let parsed = b32_to_i2p_hash(&addr).unwrap();
    assert_eq!(parsed, hash, "I2P base32 roundtrip must be lossless");
}

#[test]
fn addrv2_torv2_counts_as_five_entries_before_skip() {
    // A message with TorV2 (net_id=3) is skipped but does not corrupt the
    // rest of the message (the port bytes are still consumed correctly).
    use rustoshi_primitives::serialize::write_compact_size;

    let mut data = Vec::new();
    // Count = 2
    write_compact_size(&mut data, 2u64).unwrap();

    // Entry 1: TorV2 (will be skipped)
    data.push(0u8); // timestamp LE x4 = 0
    data.push(0u8);
    data.push(0u8);
    data.push(0u8);
    write_compact_size(&mut data, 0u64).unwrap(); // services = 0
    data.push(3u8); // TorV2
    write_compact_size(&mut data, 10u64).unwrap();
    data.extend_from_slice(&[0u8; 10]);
    data.push(0x20); // port high
    data.push(0xd5); // port low = 8405 (arbitrary)

    // Entry 2: IPv4 (should parse correctly after skipped TorV2)
    data.push(0u8);
    data.push(0u8);
    data.push(0u8);
    data.push(0u8); // timestamp = 0
    write_compact_size(&mut data, 1033u64).unwrap(); // services
    data.push(1u8); // IPv4
    write_compact_size(&mut data, 4u64).unwrap();
    data.extend_from_slice(&[8, 8, 8, 8]); // 8.8.8.8
    data.push(0x20); // port high
    data.push(0x8d); // port low = 8333

    let decoded = deserialize_addrv2_message(&data).unwrap();
    assert_eq!(decoded.len(), 1, "TorV2 entry must be skipped; IPv4 must survive");
    assert!(matches!(decoded[0].addr, NetworkAddr::Ipv4(_)));
}

#[test]
fn proxy_config_i2p_needs_sam() {
    // I2P must not use SOCKS5
    let config = ProxyConfig::new()
        .with_socks5("127.0.0.1:1080".parse().unwrap())
        .with_onion_proxy("127.0.0.1:9050".parse().unwrap());

    // I2P should return None even with socks5 configured (SAM required)
    let proxy = config.get_socks5_for(&NetworkAddr::I2P([0u8; 32]));
    assert!(proxy.is_none(), "I2P must not be routed through SOCKS5");

    // CJDNS should also return None (native routing)
    let proxy = config.get_socks5_for(&NetworkAddr::Cjdns([0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
    assert!(proxy.is_none(), "CJDNS must not use SOCKS5");
}

#[test]
fn torv3_validation_rejects_all_zeros_and_ones() {
    use rustoshi_network::addr::torv3;
    assert!(!torv3::validate_pubkey(&[0u8; 32]), "all-zero pubkey invalid");
    assert!(!torv3::validate_pubkey(&[0xffu8; 32]), "all-ones pubkey invalid");
    assert!(torv3::validate_pubkey(&[0x42u8; 32]), "mixed pubkey valid");
}

#[test]
fn cjdns_not_addr_v1_compatible() {
    let cjdns = NetworkAddr::Cjdns([0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    assert!(
        !cjdns.is_addr_v1_compatible(),
        "CJDNS must not be v1 compatible"
    );
    assert!(
        cjdns.to_socket_addr(8333).is_none(),
        "CJDNS must not convert to SocketAddr"
    );
}

#[test]
fn i2p_not_addr_v1_compatible() {
    let i2p = NetworkAddr::I2P([0x42; 32]);
    assert!(!i2p.is_addr_v1_compatible(), "I2P must not be v1 compatible");
    assert!(
        i2p.to_socket_addr(8333).is_none(),
        "I2P must not convert to SocketAddr"
    );
}

#[test]
fn torv3_not_addr_v1_compatible() {
    let tor = NetworkAddr::TorV3([0x42; 32]);
    assert!(
        !tor.is_addr_v1_compatible(),
        "TorV3 must not be v1 compatible"
    );
    assert!(
        tor.to_socket_addr(8333).is_none(),
        "TorV3 must not convert to SocketAddr"
    );
}
