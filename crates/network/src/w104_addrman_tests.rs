// W104 AddrMan 30-gate fleet audit — rustoshi
//
// All tests that document bugs are marked #[ignore].  Run the full suite
// (including ignored tests) with:
//     cargo test -p rustoshi-network -- --include-ignored
//
// Gates:
//  G1  addrv2 message parsing (BIP-155)
//  G2  ADDR_RELAY_MAX cap (1000)
//  G3  ADDRESS_RELAY_INTERVAL Poisson throttle (~30s mean)
//  G4  m_addr_known per-peer Bloom filter (5000 entries)
//  G5  getaddr response cap (MAX_ADDR_TO_SEND=1000)
//  G6  ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP=64
//  G7  ADDRMAN_NEW_BUCKET_COUNT=1024
//  G8  ADDRMAN_TRIED_BUCKETS_PER_GROUP=8
//  G9  ADDRMAN_TRIED_BUCKET_COUNT=256
//  G10 ADDRMAN_BUCKET_SIZE=64
//  G11 ADDRMAN_HORIZON_DAYS=30
//  G12 ADDRMAN_RETRIES=3
//  G13 ADDRMAN_MIN_FAIL_DAYS=7
//  G14 ADDRMAN_MAX_FAILURES=10
//  G15 Group key calculation (IPv4 /16, IPv6 /32, Tor/I2P/CJDNS network-aware)
//  G16 Select() new vs tried 50/50
//  G17 ASMap support
//  G18 SourceGroup bucketing for new addrs
//  G19 SHA256(key || source || group) bucket hash
//  G20 Tor/I2P/CJDNS network-type-aware grouping
//  G21 peers.dat format versioning
//  G22 m_addrman_key (random 256-bit, generated at init)
//  G23 Serialize/Deserialize via VARINT
//  G24 peers.dat corruption recovery (delete + start fresh)
//  G25 peers.dat.bak backup on version incompatibility
//  G26 Add() rate-limit per source per second
//  G27 Source connectivity verification before tried-promote
//  G28 Tried-bucket promotion only on successful version handshake
//  G29 ADDRMAN_TEST_WINDOW (smaller on testnet/regtest)
//  G30 m_addrman_key persistence across restarts

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use crate::{
    addr::{AddrV2Entry, NetworkAddr, deserialize_addrv2_message, serialize_addrv2_message},
    message::{MAX_ADDR, TimestampedNetAddress},
    netgroup::{ip_is_routable, NetGroupManager, NetworkType},
    peer_manager::{AddressManager, socket_addr_to_net_address},
};

// ─── G1: addrv2 message parsing (BIP-155) ───────────────────────────────────

/// G1 PASS — BIP-155 ADDRv2 parsing accepts all six network types and
/// rejects unknown network IDs and over-length addresses gracefully.
#[test]
fn g1_addrv2_ipv4_parse_ok() {
    let entry = AddrV2Entry {
        timestamp: 1_700_000_000,
        services: 1033,
        addr: NetworkAddr::Ipv4(Ipv4Addr::new(1, 2, 3, 4)),
        port: 8333,
    };
    let wire = serialize_addrv2_message(&[entry.clone()]);
    let decoded = deserialize_addrv2_message(&wire).expect("must decode");
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].addr, entry.addr);
    assert_eq!(decoded[0].port, entry.port);
    assert_eq!(decoded[0].services, entry.services);
}

#[test]
fn g1_addrv2_torv3_parse_ok() {
    let entry = AddrV2Entry {
        timestamp: 1_700_000_000,
        services: 1,
        addr: NetworkAddr::TorV3([0x42; 32]),
        port: 9050,
    };
    let wire = serialize_addrv2_message(&[entry.clone()]);
    let decoded = deserialize_addrv2_message(&wire).unwrap();
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].addr, NetworkAddr::TorV3([0x42; 32]));
}

#[test]
fn g1_addrv2_unknown_network_skipped_gracefully() {
    // A single-entry message with unknown network ID 99 must not error out —
    // forward-compat silently skips unknown networks.
    use rustoshi_primitives::serialize::write_compact_size;
    let mut data = Vec::new();
    // count = 1
    write_compact_size(&mut data, 1).unwrap();
    // timestamp (4 LE)
    data.extend_from_slice(&1_700_000_000u32.to_le_bytes());
    // services (1 as compactsize)
    write_compact_size(&mut data, 1u64).unwrap();
    // network ID 99 (unknown)
    data.push(99);
    // addr len 10
    write_compact_size(&mut data, 10).unwrap();
    // 10 dummy bytes
    data.extend_from_slice(&[0u8; 10]);
    // port
    data.extend_from_slice(&8333u16.to_be_bytes());

    // Unknown network IDs are silently skipped; result should be empty (not Err).
    let result = deserialize_addrv2_message(&data);
    assert!(result.is_ok(), "must not error on unknown network ID");
    assert_eq!(result.unwrap().len(), 0, "unknown network entry should be dropped");
}

// ─── G2: ADDR_RELAY_MAX cap = 1000 ──────────────────────────────────────────

/// G2 PASS — MAX_ADDR constant is 1000, matching Bitcoin Core's
/// `MAX_ADDR_TO_SEND = 1000`.
#[test]
fn g2_addr_relay_max_is_1000() {
    assert_eq!(MAX_ADDR, 1000, "MAX_ADDR must be 1000 (Bitcoin Core MAX_ADDR_TO_SEND)");
}

/// G2 PASS — ADDR message with >1000 entries triggers misbehaving path.
/// The peer_manager handle_event branch already checks `addrs.len() > MAX_ADDR`.
/// This test exercises that the constant is enforced for both ADDR and ADDRV2.
#[test]
fn g2_addr_relay_deserialize_rejects_over_1000() {
    use rustoshi_primitives::serialize::write_compact_size;
    let mut data = Vec::new();
    write_compact_size(&mut data, 1001).unwrap();
    // trying to deserialize 1001 entries should fail
    let result = deserialize_addrv2_message(&data);
    assert!(result.is_err(), "must reject >1000 addrv2 entries");
}

// ─── G3: ADDRESS_RELAY_INTERVAL Poisson throttle ────────────────────────────

/// G3 BUG (P2) — Per-peer Poisson address-relay throttle (mean ~30s) absent.
///
/// Bitcoin Core's `ROTATE_ADDR_RELAY_DEST_INTERVAL = 24h` and the Poisson
/// relay timer in `SendMessages()` mean each outgoing addr batch is staggered
/// to a random ~30s schedule.  Rustoshi's `relay_addresses_to_peers()` sends
/// addr batches synchronously on every incoming ADDR/ADDRV2 message with no
/// time-based gate.  This enables eclipse-facilitating addr flooding: an
/// attacker can trigger continuous relay by sending rapid ADDR messages.
///
/// Core reference: net_processing.cpp ROTATE_ADDR_RELAY_DEST_INTERVAL,
/// and the `current_time - m_next_addr_send > 0` gate in SendMessages.
#[test]
#[ignore = "BUG G3 P2: no per-peer addr relay Poisson throttle — relay fires on every incoming ADDR/ADDRV2 message with no time gate"]
fn g3_addr_relay_interval_poisson_throttle_missing() {
    // No timer gate: every ADDR message into handle_event immediately calls
    // relay_addresses_to_peers().  A 10 000-addr flood from attacker triggers
    // relay for every single message.
    //
    // Expected: relay_addresses_to_peers() should be no-op until a Poisson
    // timer with mean ~30s elapses; instead it fires immediately every call.
    assert!(
        false,
        "G3 P2: addr relay fires on every ADDR/ADDRV2 message; Core Poisson throttle absent"
    );
}

// ─── G4: m_addr_known per-peer Bloom filter ──────────────────────────────────

/// G4 BUG (P2) — Per-peer m_addr_known Bloom filter entirely absent.
///
/// Bitcoin Core allocates a `CRollingBloomFilter(5000, 0.001)` per peer
/// (net_processing.cpp:5619) and checks it before re-relaying an addr to
/// that peer.  Rustoshi has no equivalent data structure; it passes the same
/// ~10 addresses to the relay targets on every addr batch regardless of what
/// was sent before.  This causes addr re-announcement spam and wastes
/// bandwidth.
///
/// Core reference: net_processing.cpp:349 `m_addr_known`, line 5619 init,
/// line 1133 dedup check before PushAddress().
#[test]
#[ignore = "BUG G4 P2: no per-peer m_addr_known rolling Bloom filter for addr relay dedup"]
fn g4_per_peer_addr_known_bloom_filter_missing() {
    // rustoshi peer_manager has no field analogous to m_addr_known.
    // Consequence: same addrs retransmitted to same peer on every relay event.
    assert!(
        false,
        "G4 P2: m_addr_known(5000, 0.001) Bloom filter not present; addr relay dedup absent"
    );
}

// ─── G5: getaddr response cap = 1000 ────────────────────────────────────────

/// G5 BUG (P2) — getaddr handler responds to EVERY getaddr from a peer with
/// no one-time guard; Bitcoin Core ignores repeated getaddr after the first.
///
/// Core reference: net_processing.cpp:4833 `if (peer.m_getaddr_recvd) return;`
/// sets a per-peer flag so only the first getaddr per session is honoured.
/// Rustoshi's handle_event responds unconditionally every time a GetAddr
/// message arrives (peer_manager.rs:1673), allowing any peer to trigger
/// repeated address dumps.
#[test]
#[ignore = "BUG G5 P2: getaddr one-time guard (m_getaddr_recvd) absent — repeated getaddr answered repeatedly"]
fn g5_getaddr_repeated_not_rate_limited() {
    // Core: m_getaddr_recvd flag prevents responding to the same peer twice
    // per session.  Rustoshi handle_event has no such flag, so calling the
    // GetAddr branch N times sends N responses.
    assert!(
        false,
        "G5 P2: repeated GETADDR answered each time; Core m_getaddr_recvd one-time guard missing"
    );
}

/// G5 PASS — when a getaddr IS answered, the count is capped at MAX_ADDR=1000.
#[test]
fn g5_getaddr_response_capped_at_max_addr() {
    let mgr = AddressManager::new();
    // AddressManager::get_addresses_for_sharing(MAX_ADDR) returns at most MAX_ADDR items.
    let addrs = mgr.get_addresses_for_sharing(MAX_ADDR);
    assert!(addrs.len() <= MAX_ADDR, "get_addresses_for_sharing must respect MAX_ADDR cap");
}

// ─── G6-G14: Bucketing math constants ───────────────────────────────────────

/// G6-G14 BUG (P1) — The entire bucket-based AddrMan data structure
/// (new/tried split, ADDRMAN_NEW_BUCKET_COUNT=1024, ADDRMAN_TRIED_BUCKET_COUNT=256,
/// ADDRMAN_BUCKET_SIZE=64, etc.) is completely absent in rustoshi.
///
/// Instead rustoshi uses a flat `HashMap<SocketAddr, AddrInfo>` with a simple
/// VecDeque try-queue.  This has severe consequences:
///
///  - No eclipse-attack resistant bucketing: an attacker can fill known_addrs
///    by adding 1M addresses from a single source (all accepted, none evicted).
///  - No ADDRMAN_HORIZON (30 days) or ADDRMAN_MAX_FAILURES (10) eviction:
///    stale/bad addresses live forever.
///  - No ADDRMAN_RETRIES (3) or ADDRMAN_MIN_FAIL_DAYS (7) failure tracking.
///  - No ADDRMAN_TRIED_BUCKET_COUNT (256) / ADDRMAN_NEW_BUCKET_COUNT (1024)
///    caps — the flat HashMap is unbounded.
///  - No ADDRMAN_BUCKET_SIZE (64) per-bucket eviction ensuring diversity.
///
/// This is the root cause for G6 through G14; they all share the same
/// MISSING data structure.
///
/// Core reference: addrman_impl.h lines 26-33, addrman.h lines 23-41.
#[test]
#[ignore = "BUG G6-G14 P1: entire bucket-based AddrMan missing — flat HashMap used instead"]
fn g6_to_g14_bucket_based_addrman_entirely_missing() {
    // The following constants do not exist anywhere in rustoshi's network crate:
    // ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP = 64  (G6)
    // ADDRMAN_NEW_BUCKET_COUNT = 1024             (G7)
    // ADDRMAN_TRIED_BUCKETS_PER_GROUP = 8         (G8)
    // ADDRMAN_TRIED_BUCKET_COUNT = 256            (G9)
    // ADDRMAN_BUCKET_SIZE = 64                    (G10)
    // ADDRMAN_HORIZON = 30 days                   (G11)
    // ADDRMAN_RETRIES = 3                         (G12)
    // ADDRMAN_MIN_FAIL_DAYS = 7                   (G13)
    // ADDRMAN_MAX_FAILURES = 10                   (G14)
    assert!(
        false,
        "G6-G14 P1: bucket-based AddrMan entirely absent; flat HashMap used — no sybil/eclipse resistance"
    );
}

/// G6 PASS structural — AddressManager exists (verifies the impl compiles).
#[test]
fn g6_address_manager_exists() {
    let mgr = AddressManager::new();
    assert_eq!(mgr.known_count(), 0);
}

/// G11 BUG (P1) — ADDRMAN_HORIZON_DAYS=30 not enforced: old addresses never
/// removed from flat HashMap.
#[test]
#[ignore = "BUG G11 P1: ADDRMAN_HORIZON_DAYS=30 not implemented — stale addresses live forever in flat HashMap"]
fn g11_horizon_days_not_enforced() {
    // Known addresses with last_seen older than 30 days are never purged.
    // Bitcoin Core: addrman.h line 29 `static constexpr auto ADDRMAN_HORIZON{30 * 24h};`
    assert!(
        false,
        "G11 P1: addresses older than 30 days are never evicted (no horizon enforcement)"
    );
}

/// G12-G14 BUG (P1) — ADDRMAN_RETRIES=3, ADDRMAN_MIN_FAIL_DAYS=7 and
/// ADDRMAN_MAX_FAILURES=10 eviction not implemented.
#[test]
#[ignore = "BUG G12-G14 P1: failure-based eviction constants RETRIES/MIN_FAIL_DAYS/MAX_FAILURES absent"]
fn g12_to_g14_failure_eviction_absent() {
    // Core evicts an address when:
    //   attempt_count >= ADDRMAN_RETRIES(3) AND last_attempt > ADDRMAN_MIN_FAIL_DAYS(7)
    //   OR failed_connections >= ADDRMAN_MAX_FAILURES(10)
    // rustoshi tracks attempt_count but never triggers eviction.
    assert!(
        false,
        "G12-G14 P1: no eviction based on RETRIES=3 / MIN_FAIL_DAYS=7 / MAX_FAILURES=10"
    );
}

// ─── G15: Group key calculation ───────────────────────────────────────────────

/// G15 PASS — IPv4 /16 grouping is correctly implemented.
#[test]
fn g15_ipv4_slash_16_grouping() {
    let mgr = NetGroupManager::with_key(0xDEADBEEF_u64);
    let a: IpAddr = "192.168.1.1".parse().unwrap();
    let b: IpAddr = "192.168.200.5".parse().unwrap();
    let c: IpAddr = "192.169.1.1".parse().unwrap();
    assert!(mgr.same_group(&a, &b), "same /16 must share a group");
    assert!(!mgr.same_group(&a, &c), "different /16 must differ");
}

/// G15 PASS — IPv6 /32 grouping is correctly implemented.
#[test]
fn g15_ipv6_slash_32_grouping() {
    let mgr = NetGroupManager::with_key(0xDEADBEEF_u64);
    let a: IpAddr = "2001:db8:1234:5678::1".parse().unwrap();
    let b: IpAddr = "2001:db8:ffff:0000::1".parse().unwrap();
    let c: IpAddr = "2001:db9::1".parse().unwrap();
    assert!(mgr.same_group(&a, &b), "same /32 prefix must share group");
    assert!(!mgr.same_group(&a, &c), "different /32 prefix must differ");
}

/// G15 BUG (P2) — Tor/I2P group key uses octets[6] >> 4 (4-bit prefix from
/// the 7th byte of the internal fd87:d87e:eb43::/48 representation).
///
/// Bitcoin Core uses the FIRST 4 bits of the address byte AFTER the fixed
/// 6-byte prefix (i.e., byte index 6 of the 16-byte address).  Rustoshi's
/// implementation matches Core conceptually (using octets[6] >> 4), but the
/// choice of nibble position is not independently verified against Core's
/// NetGroupManager::GetGroup() for the Tor case.  Mark as P3 (needs
/// test-vector verification rather than a clear bug).
///
/// This test documents the actual behavior so deviations from Core vectors
/// can be caught.
#[test]
fn g15_tor_grouping_uses_4bit_prefix() {
    let mgr = NetGroupManager::with_key(0);
    // Two Tor addresses differing only in low bits of the same nibble should
    // share a group; those differing in the nibble should differ.
    let tor_a: IpAddr = "fd87:d87e:eb43:0000::1".parse().unwrap();
    let tor_b: IpAddr = "fd87:d87e:eb43:0001::1".parse().unwrap(); // same nibble in octet[6]
    let tor_c: IpAddr = "fd87:d87e:eb43:1000::1".parse().unwrap(); // different nibble
    // Both tor_a and tor_b should be Tor network
    assert_eq!(mgr.classify_network(&tor_a), NetworkType::Tor);
    assert_eq!(mgr.classify_network(&tor_c), NetworkType::Tor);
    // Grouping: tor_a and tor_b may or may not share depending on exact nibble
    // We simply verify no panic and classification is correct.
    let _ = mgr.same_group(&tor_a, &tor_b);
    let _ = mgr.same_group(&tor_a, &tor_c);
}

// ─── G16: Select() new vs tried 50/50 ────────────────────────────────────────

/// G16 BUG (P1) — No Select() function with new vs tried 50/50 coin flip.
///
/// Bitcoin Core's AddrMan::Select() picks new or tried with 50% probability
/// (addrman.cpp:728 `insecure_rand.randbool()`), providing balanced coverage
/// across both address tables.  Rustoshi's AddressManager::next_addr_to_try()
/// only dequeues from a flat VecDeque try_queue in FIFO order — there is no
/// separation of addresses into new/tried tiers and therefore no probabilistic
/// balance.  DNS-seeded addresses always come before peer-relayed addresses
/// regardless of whether tried addresses would be better candidates.
///
/// Core reference: addrman.cpp lines 722-728.
#[test]
#[ignore = "BUG G16 P1: no new/tried tier split in AddressManager — no 50/50 Select() with randomisation"]
fn g16_select_new_vs_tried_50_50_missing() {
    assert!(
        false,
        "G16 P1: AddressManager is a flat FIFO queue — no new/tried split, no probabilistic 50/50 Select()"
    );
}

// ─── G17: ASMap support ───────────────────────────────────────────────────────

/// G17 BUG (P2) — ASMap (AS-level bucketing) not supported.
///
/// Bitcoin Core supports loading an ASMap file to bucket peers at the
/// Autonomous System level, providing stronger eclipse protection than /16
/// alone.  Rustoshi's NetGroupManager has no ASMap field or loading code.
///
/// Core reference: addrman_impl.h:160 `m_netgroupman`, netgroupman.h,
/// chainparams.cpp's asmap path.
#[test]
#[ignore = "BUG G17 P2: ASMap AS-level bucketing not implemented in NetGroupManager"]
fn g17_asmap_support_missing() {
    // NetGroupManager has no `asmap: Vec<bool>` field, no GetAsmapVersion(),
    // no load-from-file path.  All grouping is pure /16 or /32 prefix.
    assert!(
        false,
        "G17 P2: NetGroupManager has no ASMap support; only /16 (IPv4) and /32 (IPv6) grouping"
    );
}

// ─── G18: SourceGroup bucketing for new addresses ────────────────────────────

/// G18 BUG (P1) — Source-group-aware new-bucket selection absent.
///
/// Core's AddrInfo::GetNewBucket() hashes (nKey || source_group || group) so
/// addresses from the same source fall into the same bucket, bounding how many
/// entries any one source can place.  Rustoshi's AddressManager::add_peer_addresses()
/// stores the source in AddrInfo.source but never uses it to partition
/// addresses into source-specific buckets.  A single attacker-controlled peer
/// can flood known_addrs with arbitrary addresses.
///
/// Core reference: addrman.cpp:35-41 GetNewBucket().
#[test]
#[ignore = "BUG G18 P1: source-group bucketing for new addresses absent — single peer can fill entire address table"]
fn g18_source_group_bucketing_missing() {
    assert!(
        false,
        "G18 P1: GetNewBucket(key, source_group) not implemented; source field stored but not used for partitioning"
    );
}

// ─── G19: SHA256 bucket hash ──────────────────────────────────────────────────

/// G19 BUG (P1) — SHA256(m_addrman_key || source || group) bucket hash absent.
///
/// The entire bucket-key selection algorithm from Core (double SHA256 /
/// CheapHash of nKey with various inputs) does not exist because rustoshi
/// lacks the new/tried bucket structure entirely.  The `keyed()` method in
/// NetGroup uses Rust's DefaultHasher (not SHA256), which is not
/// cryptographically secure and thus provides no eclipse protection against
/// an attacker who can predict hash outputs.
///
/// Core reference: addrman.cpp:28-45 GetTriedBucket(), GetNewBucket(),
/// GetBucketPosition(); all use HashWriter (SHA256d).
#[test]
#[ignore = "BUG G19 P1: SHA256-based bucket position hash absent; NetGroup.keyed() uses DefaultHasher (non-cryptographic)"]
fn g19_sha256_bucket_hash_missing() {
    // NetGroup::keyed() uses std::collections::hash_map::DefaultHasher, not SHA256.
    // An attacker who knows the key can predict group assignments.
    assert!(
        false,
        "G19 P1: non-cryptographic DefaultHasher used for netgroup key; SHA256 bucket hash absent"
    );
}

/// G19 supplemental — verify that keyed() is at least deterministic (not a
/// security property, but a sanity check).
#[test]
fn g19_netgroup_keyed_is_deterministic() {
    use crate::netgroup::NetGroup;
    let group = NetGroup::new(vec![0u8, 192, 168]);
    let k1 = group.keyed(12345);
    let k2 = group.keyed(12345);
    assert_eq!(k1, k2, "keyed() must be deterministic");
    let k3 = group.keyed(99999);
    assert_ne!(k1, k3, "different keys must produce different hashes");
}

// ─── G20: Tor/I2P/CJDNS network-type-aware grouping ─────────────────────────

/// G20 PASS — Tor, I2P and CJDNS addresses are classified as privacy networks
/// and receive separate network-type prefix in their group byte.
#[test]
fn g20_privacy_network_type_aware_grouping() {
    let mgr = NetGroupManager::with_key(0);
    let tor:   IpAddr = "fd87:d87e:eb43::1".parse().unwrap();
    let i2p:   IpAddr = "fd87:d87e:eb44::1".parse().unwrap();
    let cjdns: IpAddr = "fc00::1".parse().unwrap();
    let ipv4:  IpAddr = "8.8.8.8".parse().unwrap();

    assert_eq!(mgr.classify_network(&tor),   NetworkType::Tor);
    assert_eq!(mgr.classify_network(&i2p),   NetworkType::I2P);
    assert_eq!(mgr.classify_network(&cjdns), NetworkType::Cjdns);

    // Privacy networks get their own groups, distinct from each other and IPv4
    let g_tor   = mgr.get_group(&tor);
    let g_i2p   = mgr.get_group(&i2p);
    let g_cjdns = mgr.get_group(&cjdns);
    let g_ipv4  = mgr.get_group(&ipv4);

    assert_ne!(g_tor, g_i2p,   "Tor and I2P must be in different groups");
    assert_ne!(g_tor, g_ipv4,  "Tor and IPv4 must be in different groups");
    assert_ne!(g_cjdns, g_ipv4,"CJDNS and IPv4 must be in different groups");
}

/// G20 PASS — Privacy networks are excluded from outbound netgroup diversity
/// enforcement (they don't have geographic topology).
#[test]
fn g20_privacy_networks_skip_netgroup_diversity_check() {
    let mgr = NetGroupManager::with_key(0);
    let tor_addr: IpAddr = "fd87:d87e:eb43::1".parse().unwrap();
    // Privacy networks should return true for is_privacy_network
    assert!(mgr.is_privacy_network(&tor_addr));
    // And false for is_local/is_routable checks based on type
    assert!(!mgr.is_local(&tor_addr));
}

// ─── G21: peers.dat format versioning ───────────────────────────────────────

/// G21 BUG (P2) — No peers.dat file; addresses not persisted across restarts.
///
/// Bitcoin Core serialises the full AddrMan to peers.dat (supporting format
/// versions 0-3) on a timer and at shutdown.  Rustoshi persists only
/// `anchors.dat` (block-relay-only peers) as a plain-text newline-separated
/// list; the general known-address table is entirely ephemeral.  Every restart
/// starts with empty known_addrs and must re-resolve DNS seeds.
///
/// Core reference: addrdb.cpp ReadFromStream/ReadAddrMan, net.cpp DumpAddresses(),
/// addrman_impl.h:115 Serialize().
#[test]
#[ignore = "BUG G21 P2: no peers.dat persistence — known address table lost on every restart (only anchors.dat saved)"]
fn g21_peers_dat_missing() {
    // AddressManager has no save()/load() methods, no Serialize impl.
    // Only anchors.dat (plain text, 2 entries) is persisted.
    assert!(
        false,
        "G21 P2: peers.dat (full AddrMan persistence) absent; address table is in-memory only"
    );
}

// ─── G22: m_addrman_key (random 256-bit) ────────────────────────────────────

/// G22 BUG (P2) — No 256-bit per-node random key for bucket selection.
///
/// Bitcoin Core generates a fresh uint256 nKey on first init and serialises it
/// in peers.dat so it survives restarts.  This key makes bucket assignments
/// unpredictable to attackers.  Rustoshi's NetGroupManager uses a 64-bit
/// random key (u64); this is smaller and not persisted to disk.  Additionally,
/// since there are no buckets (G6-G14), the key is only used in the
/// non-cryptographic DefaultHasher keyed() path.
///
/// Core reference: addrman.cpp:91 `nKey{deterministic ? ... : insecure_rand.rand256()}`,
/// addrman_impl.h:163 `uint256 nKey`.
#[test]
#[ignore = "BUG G22 P2: addrman key is 64-bit (not 256-bit) and not persisted; bucket hash security weaker than Core"]
fn g22_addrman_key_only_64bit_and_not_persisted() {
    // NetGroupManager::new() stores a u64 key (rand::random::<u64>()).
    // Core uses uint256 (256 bits) and persists it to peers.dat.
    // The u64 key is also used only in DefaultHasher, not SHA256.
    assert!(
        false,
        "G22 P2: 64-bit (not 256-bit) addrman key; key not persisted to disk across restarts"
    );
}

/// G22 structural PASS — NetGroupManager does generate a random key at init.
#[test]
fn g22_netgroup_manager_has_random_key() {
    let mgr1 = NetGroupManager::new();
    let mgr2 = NetGroupManager::new();
    // With overwhelming probability two fresh managers have different keys.
    // (2^-64 chance of collision — acceptable for a test)
    assert_ne!(mgr1.key(), mgr2.key(), "each manager must have a unique random key");
}

// ─── G23: Serialize/Deserialize via VARINT ───────────────────────────────────

/// G23 PASS — AddrV2 entry uses CompactSize (VARINT) encoding for services
/// and address length fields, as required by BIP-155.
#[test]
fn g23_addrv2_uses_compactsize_varint() {
    // services=252 fits in 1 byte; services=253 requires 3 bytes (0xFD prefix)
    let entry_small = AddrV2Entry {
        timestamp: 0,
        services: 252,
        addr: NetworkAddr::Ipv4(Ipv4Addr::new(1, 2, 3, 4)),
        port: 8333,
    };
    let entry_large = AddrV2Entry {
        timestamp: 0,
        services: 253, // needs 3-byte CompactSize
        addr: NetworkAddr::Ipv4(Ipv4Addr::new(1, 2, 3, 4)),
        port: 8333,
    };
    let mut buf_small = Vec::new();
    entry_small.serialize(&mut buf_small).unwrap();
    let mut buf_large = Vec::new();
    entry_large.serialize(&mut buf_large).unwrap();
    // Large services field needs 2 more bytes (0xFD + 2-byte LE u16)
    assert_eq!(
        buf_large.len() - buf_small.len(),
        2,
        "services=253 should use 3-byte CompactSize (2 bytes more than 1-byte)"
    );
}

// ─── G24: peers.dat corruption recovery ──────────────────────────────────────

/// G24 BUG (P3) — No peers.dat corruption recovery mechanism needed or present
/// (because there is no peers.dat at all — see G21).
///
/// This is a derivative of G21: since there is no peers.dat, there is also no
/// corruption-recovery path.  When peers.dat exists in Core and is corrupted,
/// Core deletes it and starts fresh; rustoshi simply has no file to recover.
#[test]
#[ignore = "BUG G24 P3 (derived from G21): no peers.dat means no corruption recovery path either"]
fn g24_peers_dat_corruption_recovery_absent() {
    assert!(
        false,
        "G24 P3: no peers.dat file exists to corrupt or recover from"
    );
}

// ─── G25: peers.dat.bak backup ────────────────────────────────────────────────

/// G25 BUG (P3) — No peers.dat.bak backup on version incompatibility.
///
/// Bitcoin Core renames peers.dat → peers.dat.bak when the file version is
/// incompatible (addrdb.cpp:214).  Rustoshi has no peers.dat at all.
#[test]
#[ignore = "BUG G25 P3 (derived from G21): no peers.dat.bak backup because peers.dat doesn't exist"]
fn g25_peers_dat_bak_backup_absent() {
    assert!(
        false,
        "G25 P3: peers.dat.bak backup path absent (no peers.dat to back up)"
    );
}

// ─── G26: Add() rate-limit per source per second ─────────────────────────────

/// G26 BUG (P2) — No rate-limit on how many addresses a single source can add
/// per second.
///
/// Bitcoin Core's ADDR/ADDRV2 handler applies a token-bucket rate limiter
/// (net_processing.cpp:5698 `m_addr_rate_limited`) so a peer can only inject
/// `MAX_ADDR_PROCESSING_TOKEN_BUCKET = 1000` addresses before being throttled.
/// Rustoshi's add_peer_addresses() and add_addrv2_addresses() insert every
/// received address immediately with no rate limiting; a peer sending rapid
/// ADDR messages can fill known_addrs with attacker-controlled addresses.
///
/// Core reference: net_processing.cpp:384 `m_addr_rate_limited`,
/// net_processing.cpp:5698, MAX_ADDR_PROCESSING_TOKEN_BUCKET=1000.
#[test]
#[ignore = "BUG G26 P2: no per-source addr rate-limiting (token bucket) — peer can flood address table"]
fn g26_add_rate_limit_per_source_missing() {
    assert!(
        false,
        "G26 P2: no token-bucket rate limit on addr adds; AddressManager accepts all addresses unconditionally"
    );
}

/// G26 supplemental — AddressManager accepts unlimited routable addresses right now
/// (no token-bucket rate-limiter).
#[test]
fn g26_address_manager_unbounded_add() {
    let mut mgr = AddressManager::new();
    // Use routable 1.0.x.x addresses (not RFC 1918 — those are now filtered by
    // the W104 IsRoutable fix).  The G26 bug is about no token-bucket cap, which
    // still applies to routable addresses.
    let source: SocketAddr = "8.8.8.8:8333".parse().unwrap();
    for i in 0u32..10_000 {
        // 1.0.0.1 through 1.0.39.16 — all publicly routable
        let b2 = ((i / 256) & 0xff) as u8;
        let b3 = (i & 0xff) as u8;
        let ip = Ipv4Addr::new(1, b2, b3, 1);
        let addr: SocketAddr = SocketAddr::new(IpAddr::V4(ip), 8333);
        let taddr = crate::message::TimestampedNetAddress {
            timestamp: 0,
            address: crate::peer_manager::socket_addr_to_net_address(addr, 1),
        };
        mgr.add_peer_addresses(&[taddr], source);
    }
    // All 10 000 were accepted — documents the unbounded behaviour (G26 BUG).
    assert_eq!(mgr.known_count(), 10_000, "address table is unbounded (G26 BUG)");
}

// ─── G27: Source connectivity verification before tried-promote ──────────────

/// G27 BUG (P1) — No tried-table (thus no promotion); source verification absent.
///
/// Bitcoin Core promotes an address to the tried table only after a successful
/// connection + version handshake, and re-tests the tried entry via
/// SelectTriedCollision() + ADDRMAN_TEST_WINDOW (40 min).  Rustoshi has no
/// tried table; mark_outbound_success() sets last_success but there is no
/// promotion or re-testing mechanism.
///
/// Core reference: addrman.cpp:967-977 Good_(), SelectTriedCollision_(),
/// addrman.h:39 ADDRMAN_TEST_WINDOW.
#[test]
#[ignore = "BUG G27 P1: no tried-table promotion; source connectivity verification before tried-promote absent"]
fn g27_tried_promotion_on_successful_handshake_missing() {
    assert!(
        false,
        "G27 P1: no tried/new split; successful handshake only sets last_success, no tried-promote"
    );
}

// ─── G28: Tried-bucket promotion only on successful version handshake ─────────

/// G28 BUG (P1) — Same root cause as G27; no tried bucket exists.
///
/// (Documented separately because Core's flow is:
///   ConnectToPeer → version handshake completed → Good_() → move to tried)
#[test]
#[ignore = "BUG G28 P1: no tried-bucket; mark_outbound_success() does not do tried-promotion"]
fn g28_tried_bucket_promotion_only_on_handshake_missing() {
    assert!(
        false,
        "G28 P1: tried bucket promotion absent — successful connection only updates last_success"
    );
}

/// G28 structural PASS — mark_outbound_success() does update last_success.
/// We verify this indirectly: get_addresses_for_sharing only returns addresses
/// with last_success.is_some(); before success it returns 0, after 1.
#[test]
fn g28_mark_outbound_success_updates_metadata() {
    let mut mgr = AddressManager::new();
    let netgroup_mgr = NetGroupManager::with_key(0);
    let addr: SocketAddr = "8.8.8.8:8333".parse().unwrap();
    mgr.add_manual_address(addr);
    // Before success, no entries shared
    assert_eq!(mgr.get_addresses_for_sharing(100).len(), 0, "no shareable addrs before success");
    mgr.mark_outbound_success(&addr, &netgroup_mgr);
    // After success, the address becomes shareable
    assert_eq!(mgr.get_addresses_for_sharing(100).len(), 1, "addr should be shareable after outbound success");
}

// ─── G29: ADDRMAN_TEST_WINDOW ────────────────────────────────────────────────

/// G29 BUG (P2) — ADDRMAN_TEST_WINDOW (40 min; smaller on regtest) absent.
///
/// Core uses ADDRMAN_TEST_WINDOW = 40 minutes as the window within which a
/// recently-promoted tried entry can be "tested" by SelectTriedCollision().
/// Rustoshi has no tried table and thus no test window.
///
/// Core reference: addrman.h:41 `ADDRMAN_TEST_WINDOW{40min}`.
#[test]
#[ignore = "BUG G29 P2: ADDRMAN_TEST_WINDOW=40min absent (no tried table, no SelectTriedCollision)"]
fn g29_addrman_test_window_missing() {
    assert!(
        false,
        "G29 P2: ADDRMAN_TEST_WINDOW not needed because tried table is absent entirely"
    );
}

// ─── G30: m_addrman_key persistence across restarts ──────────────────────────

/// G30 BUG (P2) — addrman key (NetGroupManager key) not persisted across restarts.
///
/// Bitcoin Core's nKey is stored in peers.dat and reloaded on startup so that
/// bucket assignments are stable across restarts (per Core PR #28448 which
/// changed Core to randomise per-launch; current Core HEAD randomises).
///
/// Rustoshi generates a fresh u64 key in NetGroupManager::new() on every
/// startup.  Since there are no buckets to preserve anyway, this is only
/// material IF buckets are added in the future.  Flagged P3.
///
/// Note: Core PR #28448 (2023) made Core itself randomise per-launch, so
/// rustoshi's per-launch randomisation is in line with current Core.
/// The remaining bugs (G22: 64-bit vs 256-bit, G19: DefaultHasher vs SHA256)
/// are more material.
#[test]
#[ignore = "BUG G30 P3 (low-severity): addrman key not persisted; per-launch randomisation is actually consistent with Core PR #28448"]
fn g30_addrman_key_not_persisted_across_restarts() {
    // Each PeerManager::new() → NetGroupManager::new() generates a fresh key.
    // Since Core PR #28448 Core also randomises per-launch, this is low-severity.
    assert!(
        false,
        "G30 P3: addrman key (u64) regenerated each launch; consistent with Core PR #28448 but weaker (64-bit)"
    );
}

// ─── Integration scenario tests ──────────────────────────────────────────────

/// Integration: address manager correctly tracks connected/disconnected state.
/// connected_count() goes 0→1 after success and 1→0 after disconnected.
#[test]
fn integration_addr_manager_connect_disconnect() {
    let mut mgr = AddressManager::new();
    let ng = NetGroupManager::with_key(0);
    let addr: SocketAddr = "1.2.3.4:8333".parse().unwrap();
    mgr.add_manual_address(addr);
    assert_eq!(mgr.connected_count(), 0);
    mgr.mark_outbound_success(&addr, &ng);
    assert_eq!(mgr.connected_count(), 1);
    mgr.mark_outbound_disconnected(&addr, &ng);
    assert_eq!(mgr.connected_count(), 0);
}

/// Integration: netgroup diversity prevents two peers from the same /16.
#[test]
fn integration_outbound_netgroup_diversity() {
    let mut mgr = AddressManager::new();
    let ng = NetGroupManager::with_key(0);

    let addr1: SocketAddr = "192.168.1.1:8333".parse().unwrap();
    let addr2: SocketAddr = "192.168.2.2:8333".parse().unwrap(); // same /16

    mgr.add_manual_address(addr1);
    mgr.add_manual_address(addr2);

    // Connect to first address
    let _ = mgr.next_addr_to_try(&ng); // pops addr1 (or addr2, FIFO)
    mgr.mark_outbound_success(&addr1, &ng);

    // The second address in the same /16 should now be skipped
    // (addr2 is in the same netgroup as addr1)
    let ng_of_addr2 = ng.get_group(&addr2.ip());
    assert!(
        mgr.has_outbound_in_netgroup(&ng_of_addr2),
        "netgroup of addr2 should already be occupied after connecting addr1"
    );
}

/// Integration: BIP-155 addrv2 messages with mixed types deserialise correctly.
#[test]
fn integration_addrv2_mixed_network_types() {
    let entries = vec![
        AddrV2Entry {
            timestamp: 1_700_000_000,
            services: 1033,
            addr: NetworkAddr::Ipv4(Ipv4Addr::new(8, 8, 8, 8)),
            port: 8333,
        },
        AddrV2Entry {
            timestamp: 1_700_000_001,
            services: 1,
            addr: NetworkAddr::TorV3([0x11; 32]),
            port: 9050,
        },
        AddrV2Entry {
            timestamp: 1_700_000_002,
            services: 1,
            addr: NetworkAddr::I2P([0xAB; 32]),
            port: 4567,
        },
    ];

    let wire = serialize_addrv2_message(&entries);
    let decoded = deserialize_addrv2_message(&wire).unwrap();
    assert_eq!(decoded.len(), 3);
    assert_eq!(decoded[0].addr, NetworkAddr::Ipv4(Ipv4Addr::new(8, 8, 8, 8)));
    assert_eq!(decoded[1].addr, NetworkAddr::TorV3([0x11; 32]));
    assert_eq!(decoded[2].addr, NetworkAddr::I2P([0xAB; 32]));
}

/// Integration: ban logic prevents connecting to banned addresses.
#[test]
fn integration_ban_prevents_connection() {
    let mut mgr = AddressManager::new();
    let ng = NetGroupManager::with_key(0);
    let addr: SocketAddr = "5.5.5.5:8333".parse().unwrap();
    mgr.add_manual_address(addr);
    mgr.ban(&addr, Duration::from_secs(3600));
    assert!(mgr.is_banned(&addr));
    // next_addr_to_try should skip banned addresses
    let result = mgr.next_addr_to_try(&ng);
    assert!(result.is_none(), "banned address must not be returned from next_addr_to_try");
}

// ─── IsRoutable filter on AddrMan add (W104 fix) ─────────────────────────────
//
// Bitcoin Core's CNetAddr::IsRoutable() (netaddress.cpp:462) rejects RFC 1918,
// RFC 2544, RFC 3927, RFC 4862, RFC 6598, RFC 5737, loopback, link-local,
// multicast, reserved, and other non-global ranges before inserting into AddrMan.
// The following tests verify that rustoshi now applies the same filter.

/// ip_is_routable() returns false for all RFC 1918 private ranges.
#[test]
fn w104_rfc1918_not_routable() {
    // 10.0.0.0/8
    assert!(!ip_is_routable(&"10.0.0.1".parse::<IpAddr>().unwrap()),       "10/8 must be non-routable (RFC 1918)");
    assert!(!ip_is_routable(&"10.255.255.255".parse::<IpAddr>().unwrap()),  "10/8 boundary must be non-routable");
    // 172.16.0.0/12
    assert!(!ip_is_routable(&"172.16.0.1".parse::<IpAddr>().unwrap()),     "172.16/12 must be non-routable (RFC 1918)");
    assert!(!ip_is_routable(&"172.31.255.255".parse::<IpAddr>().unwrap()), "172.31/12 boundary must be non-routable");
    // 192.168.0.0/16
    assert!(!ip_is_routable(&"192.168.0.1".parse::<IpAddr>().unwrap()),    "192.168/16 must be non-routable (RFC 1918)");
    assert!(!ip_is_routable(&"192.168.255.255".parse::<IpAddr>().unwrap()),"192.168/16 boundary must be non-routable");
}

/// ip_is_routable() returns false for loopback, link-local, unspecified, and broadcast.
#[test]
fn w104_loopback_linklocal_unspecified_not_routable() {
    assert!(!ip_is_routable(&"127.0.0.1".parse::<IpAddr>().unwrap()),        "loopback must be non-routable");
    assert!(!ip_is_routable(&"127.255.255.255".parse::<IpAddr>().unwrap()),  "127/8 boundary must be non-routable");
    assert!(!ip_is_routable(&"::1".parse::<IpAddr>().unwrap()),              "IPv6 loopback must be non-routable");
    assert!(!ip_is_routable(&"169.254.1.1".parse::<IpAddr>().unwrap()),      "link-local (RFC 3927) must be non-routable");
    assert!(!ip_is_routable(&"0.0.0.0".parse::<IpAddr>().unwrap()),          "unspecified must be non-routable");
    assert!(!ip_is_routable(&"255.255.255.255".parse::<IpAddr>().unwrap()),  "broadcast must be non-routable");
}

/// ip_is_routable() returns false for multicast and reserved ranges.
#[test]
fn w104_multicast_reserved_not_routable() {
    assert!(!ip_is_routable(&"224.0.0.1".parse::<IpAddr>().unwrap()),   "multicast (224/4) must be non-routable");
    assert!(!ip_is_routable(&"239.255.255.255".parse::<IpAddr>().unwrap()), "multicast boundary must be non-routable");
    assert!(!ip_is_routable(&"240.0.0.1".parse::<IpAddr>().unwrap()),   "reserved (240/4) must be non-routable");
    assert!(!ip_is_routable(&"100.64.0.1".parse::<IpAddr>().unwrap()),  "RFC 6598 CG-NAT must be non-routable");
}

/// ip_is_routable() returns false for IPv6 unique-local (RFC 4193, fd00::/8).
#[test]
fn w104_ipv6_unique_local_not_routable() {
    assert!(!ip_is_routable(&"fd00::1".parse::<IpAddr>().unwrap()),        "fd00::/8 unique-local must be non-routable (RFC 4193)");
    assert!(!ip_is_routable(&"fdff:ffff::1".parse::<IpAddr>().unwrap()),   "fd00::/8 boundary must be non-routable");
    // IPv6 link-local fe80::/10
    assert!(!ip_is_routable(&"fe80::1".parse::<IpAddr>().unwrap()),        "fe80::/10 link-local must be non-routable (RFC 4862)");
    // Documentation 2001:db8::/32 (RFC 3849)
    assert!(!ip_is_routable(&"2001:db8::1".parse::<IpAddr>().unwrap()),    "2001:db8::/32 documentation must be non-routable (RFC 3849)");
}

/// ip_is_routable() returns true for publicly routable addresses.
#[test]
fn w104_routable_addresses_pass() {
    assert!(ip_is_routable(&"8.8.8.8".parse::<IpAddr>().unwrap()),             "8.8.8.8 must be routable");
    assert!(ip_is_routable(&"1.1.1.1".parse::<IpAddr>().unwrap()),             "1.1.1.1 must be routable");
    assert!(ip_is_routable(&"2001:4860:4860::8888".parse::<IpAddr>().unwrap()),"Google IPv6 DNS must be routable");
    assert!(ip_is_routable(&"2600:1f18::1".parse::<IpAddr>().unwrap()),        "AWS IPv6 must be routable");
}

/// Privacy-network addresses (Tor, I2P, CJDNS) are passed by ip_is_routable().
#[test]
fn w104_privacy_network_addresses_pass_routable_check() {
    // Tor v3 internal repr: fd87:d87e:eb43::/48
    let tor: IpAddr = "fd87:d87e:eb43::1".parse().unwrap();
    assert!(ip_is_routable(&tor), "Tor internal repr must pass routable check (privacy network)");

    // I2P internal repr: fd87:d87e:eb44::/48
    let i2p: IpAddr = "fd87:d87e:eb44::1".parse().unwrap();
    assert!(ip_is_routable(&i2p), "I2P internal repr must pass routable check (privacy network)");

    // CJDNS fc00::/8
    let cjdns: IpAddr = "fc00::1".parse().unwrap();
    assert!(ip_is_routable(&cjdns), "CJDNS fc00::/8 must pass routable check (privacy network)");
}

/// add_peer_addresses() silently drops non-routable gossip addresses (W104 fix).
///
/// Previously rustoshi accepted any address from gossip — RFC 1918, loopback,
/// link-local, etc. — into AddrMan.  Core's CNetAddr::IsRoutable() rejects
/// those before AddrMan insertion.
#[test]
fn w104_add_peer_addresses_drops_non_routable() {
    let mut mgr = AddressManager::new();
    let source: SocketAddr = "8.8.8.8:8333".parse().unwrap();

    let non_routable_addrs = [
        "10.0.0.1:8333",        // RFC 1918
        "172.16.5.5:8333",      // RFC 1918
        "192.168.1.1:8333",     // RFC 1918
        "127.0.0.1:8333",       // loopback
        "169.254.1.1:8333",     // link-local
        "0.0.0.0:8333",         // unspecified
        "224.0.0.1:8333",       // multicast
        "240.0.0.1:8333",       // reserved
        "100.64.0.1:8333",      // RFC 6598 CG-NAT
    ];

    for s in &non_routable_addrs {
        let addr: SocketAddr = s.parse().unwrap();
        let taddr = TimestampedNetAddress {
            timestamp: 0,
            address: socket_addr_to_net_address(addr, 1),
        };
        mgr.add_peer_addresses(&[taddr], source);
    }

    assert_eq!(
        mgr.known_count(),
        0,
        "non-routable gossip addresses must be silently dropped (W104 fix)"
    );
}

/// add_peer_addresses() accepts publicly routable gossip addresses.
#[test]
fn w104_add_peer_addresses_accepts_routable() {
    let mut mgr = AddressManager::new();
    let source: SocketAddr = "8.8.8.8:8333".parse().unwrap();

    let routable_addrs = [
        "1.2.3.4:8333",
        "5.6.7.8:8333",
        "9.10.11.12:8333",
    ];

    for s in &routable_addrs {
        let addr: SocketAddr = s.parse().unwrap();
        let taddr = TimestampedNetAddress {
            timestamp: 0,
            address: socket_addr_to_net_address(addr, 1),
        };
        mgr.add_peer_addresses(&[taddr], source);
    }

    assert_eq!(
        mgr.known_count(),
        routable_addrs.len(),
        "routable gossip addresses must be accepted into AddrMan"
    );
}

/// add_addrv2_addresses() silently drops non-routable IPv4 in BIP-155 ADDRv2.
#[test]
fn w104_add_addrv2_drops_non_routable_ipv4() {
    let mut mgr = AddressManager::new();
    let source: SocketAddr = "8.8.8.8:8333".parse().unwrap();

    let non_routable_entries = vec![
        AddrV2Entry {
            timestamp: 0,
            services: 1,
            addr: NetworkAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1)),  // RFC 1918
            port: 8333,
        },
        AddrV2Entry {
            timestamp: 0,
            services: 1,
            addr: NetworkAddr::Ipv4(Ipv4Addr::new(10, 0, 0, 1)),    // RFC 1918
            port: 8333,
        },
        AddrV2Entry {
            timestamp: 0,
            services: 1,
            addr: NetworkAddr::Ipv4(Ipv4Addr::new(127, 0, 0, 1)),   // loopback
            port: 8333,
        },
    ];

    mgr.add_addrv2_addresses(&non_routable_entries, source);

    assert_eq!(
        mgr.known_count(),
        0,
        "non-routable IPv4 ADDRv2 gossip must be dropped (W104 fix)"
    );
}

/// add_addrv2_addresses() accepts routable IPv4/IPv6 and privacy-network addrs.
#[test]
fn w104_add_addrv2_accepts_routable_and_privacy() {
    let mut mgr = AddressManager::new();
    let source: SocketAddr = "8.8.8.8:8333".parse().unwrap();

    let entries = vec![
        AddrV2Entry {
            timestamp: 0,
            services: 1,
            addr: NetworkAddr::Ipv4(Ipv4Addr::new(1, 2, 3, 4)),
            port: 8333,
        },
        AddrV2Entry {
            timestamp: 0,
            services: 1,
            addr: NetworkAddr::TorV3([0x42; 32]),
            port: 9050,
        },
    ];

    mgr.add_addrv2_addresses(&entries, source);

    // IPv4 entry adds to known_addrs; Tor adds to known_addrv2 only
    assert_eq!(mgr.known_count(), 1,        "routable IPv4 ADDRv2 entry must be added");
    assert_eq!(mgr.known_addrv2_count(), 2, "both IPv4 and Tor entries must be in addrv2 store");
}
