// W115 ASMap (anti-eclipse via AS bucketing) fleet audit — rustoshi
//
// STATUS: **MISSING ENTIRELY** — No part of the Bitcoin Core ASMap subsystem
// is implemented in rustoshi.  NetGroupManager contains only /16 (IPv4) and
// /32 (IPv6) subnet bucketing.  None of G1-G30 pass.
//
// All tests that document bugs are marked #[ignore].  Run with:
//     cargo test -p rustoshi-network -- --include-ignored 2>&1 | grep -E 'PASS|FAIL|ignore'
//     cargo test -p rustoshi-network --test test_w115_asmap 2>&1 | tail -40
//
// Gates:
//  G1  -asmap=<file> startup arg recognized
//  G2  ASMap binary file format parsed (compressed prefix tree)
//  G3  SanityCheckASMap validates file
//  G4  Default: ASMap not loaded (no implicit lookup)
//  G5  Path relative to datadir if not absolute
//  G6  ASMap stored as bit-vector (efficient memory)
//  G7  ASN lookup via DecodeBits + DecodeType prefix-tree traversal
//  G8  Interpret(ip) returns u32 ASN (or 0 if not found)
//  G9  Default ASN 0 = "unknown / not in map"
//  G10 IPv6 IPs mapped via 128-bit input (different from IPv4)
//  G11 GetMappedAS(net) replaces GetGroup(net) when asmap loaded
//  G12 GetTriedBucket uses ASN-keyed bucket
//  G13 GetNewBucket uses ASN-keyed bucket
//  G14 Fall back to GetGroup when asmap=0
//  G15 ASN bucket count same as /16 bucket count
//  G16 SanityCheckASMap returns false on malformed file
//  G17 ASMap version compatibility check
//  G18 ASMap file size bounded MAX_ASMAP_FILESIZE=8MiB
//  G19 File hash logged at startup
//  G20 ASMap reload not supported at runtime (load-once)
//  G21 Inbound peer ASN logged with connection
//  G22 Outbound peer selection prefers ASN diversity
//  G23 Eviction prefers same-ASN peers (anti-eclipse)
//  G24 getpeerinfo includes `mapped_as` field per peer
//  G25 Loaded ASMap reports cardinality (unique ASNs)
//  G26 Loaded ASMap reports total mapped prefix coverage
//  G27 Coverage warning if < 90% of routable IPv4 space
//  G28 getnodeaddresses RPC returns ASN per node
//  G29 ASMap NOT in peers.dat (loaded fresh at startup)
//  G30 ASMap file detached from data dir — can be updated independently

// Note: Since the entire subsystem is missing, most tests below simply
// assert the absence of the feature (documenting bugs).  A handful of
// structural tests for the *existing* NetGroupManager are PASS and verify
// properties that should be preserved when ASMap support is added.

use crate::netgroup::{NetGroup, NetGroupManager, NetworkType};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// ────────────────────────────────────────────────────────────────────────────
// G1 — -asmap startup arg recognized
// ────────────────────────────────────────────────────────────────────────────

/// G1 BUG (P2) — No `-asmap` CLI flag in rustoshi.
///
/// Bitcoin Core's `init.cpp` registers `-asmap=<file>`.  Rustoshi's main.rs
/// Clap struct has no `asmap` field and no `asmap_path` field.  The node
/// therefore silently ignores any `-asmap` argument passed at startup.
///
/// Core reference: `src/init.cpp:540` `-asmap=<file>` argsman registration.
#[test]
#[ignore = "BUG G1 P2: No -asmap CLI arg — NetGroupManager has no asmap field; AS-based bucketing not implemented"]
fn g1_asmap_startup_arg_missing() {
    // If this were implemented, NetGroupManager would accept an optional asmap
    // bit-vector and NetGroupManager::using_asmap() would return true after loading.
    // For now, the only constructor is new() / with_key() — no asmap parameter.
    let mgr = NetGroupManager::new();
    // The field `asmap: Vec<bool>` (or `Vec<u8>`) does not exist on NetGroupManager.
    // `mgr.using_asmap()` does not compile.
    panic!("G1 BUG: no -asmap startup arg; NetGroupManager has no asmap support");
}

// ────────────────────────────────────────────────────────────────────────────
// G2 — Binary file format parsed (compressed prefix tree)
// ────────────────────────────────────────────────────────────────────────────

/// G2 BUG (P2) — No ASMap binary file parser.
///
/// Bitcoin Core's `DecodeAsmap(path)` reads the raw binary prefix tree, then
/// calls `CheckStandardAsmap` to validate.  Rustoshi has no equivalent
/// `decode_asmap()` function, no `DecodeBits` / `DecodeType` / `DecodeASN`
/// helpers, and no `Interpret(asmap, ip)` top-level function.
///
/// Core reference: `src/util/asmap.cpp:322` DecodeAsmap(), `src/util/asmap.h`.
#[test]
#[ignore = "BUG G2 P2: No ASMap binary file parser — decode_asmap/interpret functions absent"]
fn g2_asmap_binary_parser_missing() {
    // Expected API (does not exist):
    //   fn decode_asmap(path: &std::path::Path) -> Option<Vec<u8>>
    //   fn interpret(asmap: &[u8], ip: &[u8]) -> u32
    panic!("G2 BUG: no ASMap binary file parser; decode_asmap() absent");
}

// ────────────────────────────────────────────────────────────────────────────
// G3 — SanityCheckASMap validates file
// ────────────────────────────────────────────────────────────────────────────

/// G3 BUG (P2) — No SanityCheckAsmap.
///
/// Bitcoin Core traverses all possible execution paths in the bit-packed trie
/// to ensure no infinite loops, no invalid jumps, and proper termination bits.
/// Rustoshi has no `sanity_check_asmap()` function.
///
/// Core reference: `src/util/asmap.cpp:239` SanityCheckAsmap().
#[test]
#[ignore = "BUG G3 P2: sanity_check_asmap() absent — malformed asmap files would be accepted silently"]
fn g3_sanity_check_asmap_missing() {
    // Expected API (does not exist):
    //   fn sanity_check_asmap(data: &[u8], bits: u32) -> bool
    panic!("G3 BUG: no SanityCheckAsmap; malformed asmap files accepted silently");
}

// ────────────────────────────────────────────────────────────────────────────
// G4 — Default: ASMap not loaded (no implicit lookup)
// ────────────────────────────────────────────────────────────────────────────

/// G4 PASS (structural) — Default NetGroupManager does not load any ASMap.
///
/// Bitcoin Core defaults to `NoAsmap()` (empty m_asmap) unless `-asmap` is
/// given.  Rustoshi's NetGroupManager::new() also has no asmap, so the
/// default behavior (subnet-based bucketing) matches Core's default.
///
/// This is only a PASS for the "no implicit asmap" property — the actual
/// AS bucketing feature is still absent.
#[test]
fn g4_default_no_asmap_loaded() {
    let mgr = NetGroupManager::new();
    // NetGroupManager has no using_asmap() method.  We verify the structural
    // property indirectly: get_group on a public IPv4 returns a /16-based group,
    // which is the correct default behaviour when no asmap is loaded.
    let addr: IpAddr = "8.8.8.8".parse().unwrap();
    let group = mgr.get_group(&addr);
    let bytes = group.as_bytes();
    // Network-type byte (0 = Ipv4) + first two octets (8, 8)
    assert_eq!(bytes[0], NetworkType::Ipv4 as u8, "network type should be Ipv4");
    assert_eq!(bytes[1], 8, "first octet of /16 group should be 8");
    assert_eq!(bytes[2], 8, "second octet of /16 group should be 8");
    // Total group length: 3 bytes (type + 2 prefix bytes)
    assert_eq!(bytes.len(), 3, "default IPv4 group is /16 = 3 bytes");
}

// ────────────────────────────────────────────────────────────────────────────
// G5 — Path relative to datadir if not absolute
// ────────────────────────────────────────────────────────────────────────────

/// G5 BUG (P3) — No relative-path resolution for asmap file.
///
/// Bitcoin Core: if `-asmap=ip_asn.map` (relative), it prepends
/// `args.GetDataDirNet()`.  Since rustoshi has no -asmap at all, this
/// path resolution is also absent.
///
/// Core reference: `src/init.cpp:1591` relative-path prefix logic.
#[test]
#[ignore = "BUG G5 P3: no asmap path resolution — depends on G1 being implemented first"]
fn g5_asmap_path_relative_to_datadir() {
    panic!("G5 BUG: no asmap path resolution; blocked by G1");
}

// ────────────────────────────────────────────────────────────────────────────
// G6 — ASMap stored as bit-vector (efficient memory)
// ────────────────────────────────────────────────────────────────────────────

/// G6 BUG (P2) — No bit-vector storage for ASMap.
///
/// Core stores asmap as `Vec<std::byte>` (packed bytes, accessed bit-by-bit).
/// Rustoshi's NetGroupManager has only a `key: u64` field — no asmap data.
#[test]
#[ignore = "BUG G6 P2: NetGroupManager has no asmap bit-vector field"]
fn g6_asmap_bitvector_storage_missing() {
    // Expected: NetGroupManager { key: u64, asmap: Vec<u8> }
    // Actual:   NetGroupManager { key: u64 }
    panic!("G6 BUG: no asmap bit-vector storage on NetGroupManager");
}

// ────────────────────────────────────────────────────────────────────────────
// G7 — ASN lookup via DecodeBits + DecodeType prefix-tree traversal
// ────────────────────────────────────────────────────────────────────────────

/// G7 BUG (P2) — No trie traversal (DecodeBits/DecodeType/DecodeASN) logic.
///
/// Core: RETURN/JUMP/MATCH/DEFAULT instruction set decoded from the bit
/// stream.  Rustoshi has no equivalent.
///
/// Core reference: `src/util/asmap.cpp:87-171` DecodeBits + instruction set.
#[test]
#[ignore = "BUG G7 P2: No DecodeBits/DecodeType/DecodeASN/Interpret — full trie traversal absent"]
fn g7_asn_lookup_trie_traversal_missing() {
    panic!("G7 BUG: no prefix-tree traversal for ASN lookup");
}

// ────────────────────────────────────────────────────────────────────────────
// G8 — Interpret(ip) returns u32 ASN (or 0 if not found)
// ────────────────────────────────────────────────────────────────────────────

/// G8 BUG (P2) — No Interpret(asmap, ip) → u32 function.
///
/// Core's `Interpret()` executes the bytecode trie and returns the matching
/// ASN for the given IP address bit string (32 bits for IPv4, 128 for IPv6).
/// Returns 0 if no match.
///
/// Core reference: `src/util/asmap.cpp:182` uint32_t Interpret(...).
#[test]
#[ignore = "BUG G8 P2: interpret(asmap, ip) -> u32 absent"]
fn g8_interpret_returns_asn() {
    // Minimal valid asmap encoding: a single RETURN instruction returning ASN 13335.
    // Format: RETURN opcode ([0] bit), then ASN encoded as DecodeBits(1, ASN_BIT_SIZES).
    // For ASN 13335 (Cloudflare), encoding is: 0b0 (RETURN) + variable-length ASN.
    // We cannot test this without the Interpret function.
    panic!("G8 BUG: interpret() absent; cannot look up ASN for IP");
}

// ────────────────────────────────────────────────────────────────────────────
// G9 — Default ASN 0 = "unknown / not in map"
// ────────────────────────────────────────────────────────────────────────────

/// G9 BUG (P2) — No ASN 0 sentinel for "not in map".
///
/// Core uses ASN=0 as the default_asn sentinel when the trie search falls
/// through a MATCH without a prior DEFAULT instruction.  Rustoshi has no
/// ASN concept at all in NetGroupManager.
///
/// Core reference: `src/util/asmap.cpp:188` `uint32_t default_asn = 0`.
#[test]
#[ignore = "BUG G9 P2: ASN 0 sentinel absent — whole ASN lookup system missing"]
fn g9_default_asn_zero_unknown() {
    panic!("G9 BUG: no ASN sentinel; whole ASN lookup system absent");
}

// ────────────────────────────────────────────────────────────────────────────
// G10 — IPv6 IPs mapped via 128-bit input (different code path from IPv4)
// ────────────────────────────────────────────────────────────────────────────

/// G10 BUG (P2) — No 128-bit IPv6 ASN lookup.
///
/// Core passes the full 16-byte IPv6 address into Interpret() (128 input bits).
/// For IPv4 it uses 32 bits.  Rustoshi has no Interpret() at all.
///
/// Core reference: `src/netgroup.cpp` GetMappedAS() IPv4 vs IPv6 dispatch.
#[test]
#[ignore = "BUG G10 P2: IPv6 ASN lookup absent; Interpret() for 128-bit input missing"]
fn g10_ipv6_128bit_asn_lookup_missing() {
    panic!("G10 BUG: 128-bit IPv6 input to Interpret() absent");
}

// ────────────────────────────────────────────────────────────────────────────
// G11 — GetMappedAS(net) replaces GetGroup when asmap loaded
// ────────────────────────────────────────────────────────────────────────────

/// G11 BUG (P2) — No GetMappedAS method on NetGroupManager.
///
/// Core's `NetGroupManager::GetMappedAS(addr)` calls `Interpret(m_asmap, ip)`.
/// When asmap is loaded, AddrMan uses the ASN as the group key instead of the
/// subnet prefix.  Rustoshi's NetGroupManager has no `get_mapped_as()` method.
///
/// Core reference: `src/netgroup.h:56` uint32_t GetMappedAS(const CNetAddr&).
#[test]
#[ignore = "BUG G11 P2: get_mapped_as() absent on NetGroupManager"]
fn g11_get_mapped_as_missing() {
    let mgr = NetGroupManager::new();
    let addr: IpAddr = "8.8.8.8".parse().unwrap();
    // Does not compile: mgr.get_mapped_as(&addr)
    let _ = mgr;
    let _ = addr;
    panic!("G11 BUG: get_mapped_as() absent");
}

// ────────────────────────────────────────────────────────────────────────────
// G12 — GetTriedBucket uses ASN-keyed bucket
// ────────────────────────────────────────────────────────────────────────────

/// G12 BUG (P2) — GetTriedBucket does not use ASN.
///
/// Core's `AddrInfo::GetTriedBucket(nKey, netgroupman)` uses
/// `netgroupman.GetGroup(addr)` which, when asmap is loaded, is an ASN-derived
/// group not a subnet prefix.  Rustoshi's AddrMan equivalent (in peer_manager)
/// does not support ASN-keyed buckets.
///
/// Core reference: `src/addrman_impl.h:86` GetTriedBucket(nKey, netgroupman).
#[test]
#[ignore = "BUG G12 P2: GetTriedBucket does not use ASN-keyed buckets — asmap not integrated into AddrMan"]
fn g12_tried_bucket_no_asn_keying() {
    panic!("G12 BUG: tried-bucket not keyed by ASN; asmap absent from AddrMan");
}

// ────────────────────────────────────────────────────────────────────────────
// G13 — GetNewBucket uses ASN-keyed bucket
// ────────────────────────────────────────────────────────────────────────────

/// G13 BUG (P2) — GetNewBucket does not use ASN.
///
/// Same as G12 but for new-table bucketing.
/// Core: `GetNewBucket(nKey, src, netgroupman)` uses both src ASN and dest ASN.
///
/// Core reference: `src/addrman_impl.h:89`.
#[test]
#[ignore = "BUG G13 P2: GetNewBucket does not use ASN-keyed buckets — asmap absent from AddrMan"]
fn g13_new_bucket_no_asn_keying() {
    panic!("G13 BUG: new-bucket not keyed by ASN; asmap absent from AddrMan");
}

// ────────────────────────────────────────────────────────────────────────────
// G14 — Fall back to GetGroup when asmap=0
// ────────────────────────────────────────────────────────────────────────────

/// G14 PASS (structural) — When no asmap is loaded, get_group() is used for
/// bucketing, which is the correct subnet-based fallback.
///
/// This effectively always fires in rustoshi (since asmap is never loaded).
/// The test verifies the /16 fallback path works correctly.
///
/// Core reference: `src/netgroup.cpp` GetGroup() fallback when m_asmap.empty().
#[test]
fn g14_fallback_to_get_group_when_no_asmap() {
    let mgr = NetGroupManager::new();

    // Two IPs in the same /16 should share the same group (fallback behaviour).
    let a: IpAddr = "203.0.113.1".parse().unwrap();
    let b: IpAddr = "203.0.113.254".parse().unwrap();

    // Both are in RFC 5737 documentation range, which rustoshi classifies as
    // Unroutable — same group regardless.
    let ga = mgr.get_group(&a);
    let gb = mgr.get_group(&b);
    assert_eq!(ga, gb, "same /24 documentation range → same unroutable group");

    // Diverse routable IPs should be in different /16 groups.
    let x: IpAddr = "8.8.8.8".parse().unwrap();
    let y: IpAddr = "1.1.1.1".parse().unwrap();
    let gx = mgr.get_group(&x);
    let gy = mgr.get_group(&y);
    assert_ne!(gx, gy, "different /16 prefixes → different groups");
}

// ────────────────────────────────────────────────────────────────────────────
// G15 — ASN bucket count = same as /16 bucket count
// ────────────────────────────────────────────────────────────────────────────

/// G15 BUG (P2) — ASN bucketing is absent; cannot verify bucket count parity.
///
/// Core: ADDRMAN_TRIED_BUCKET_COUNT=256 and ADDRMAN_NEW_BUCKET_COUNT=1024
/// apply equally whether bucketing by /16 or by ASN.  The bucket *count* does
/// not change when asmap is loaded — only the *key* changes.  Since rustoshi
/// has no asmap at all, G15 is moot but still a missing feature.
#[test]
#[ignore = "BUG G15 P2: ASN bucketing absent; bucket-count parity cannot be verified"]
fn g15_asn_bucket_count_equals_subnet_bucket_count() {
    panic!("G15 BUG: ASN bucketing absent");
}

// ────────────────────────────────────────────────────────────────────────────
// G16 — SanityCheckASMap returns false on malformed file
// ────────────────────────────────────────────────────────────────────────────

/// G16 BUG (P2) — No SanityCheckASMap; malformed files not rejected.
///
/// Core's SanityCheckAsmap() walks all possible paths and returns false for:
/// - EOF in exponent / mantissa
/// - Jump past EOF
/// - Intersecting jumps
/// - Unreachable code after RETURN
/// - Non-zero padding bits
/// - Consecutive DEFAULT instructions
///
/// Rustoshi has none of this; any byte sequence would be "accepted" if an
/// Interpret() were called on it (panicking with assert!).
#[test]
#[ignore = "BUG G16 P2: sanity_check_asmap() absent — malformed files not rejected"]
fn g16_sanity_check_rejects_malformed() {
    // A zero-length file is malformed (no RETURN instruction).
    // A file with non-zero padding bits is malformed.
    // Both should return false from sanity_check_asmap().
    panic!("G16 BUG: sanity_check_asmap() absent");
}

// ────────────────────────────────────────────────────────────────────────────
// G17 — ASMap version compatibility check
// ────────────────────────────────────────────────────────────────────────────

/// G17 BUG (P2) — No AsmapVersion() / asmap version hash.
///
/// Core: `AsmapVersion(data)` returns SHA256(data) used both for logging at
/// startup and for peers.dat invalidation (re-bucketing when asmap changes).
/// Rustoshi has no `asmap_version()` function.
///
/// Core reference: `src/util/asmap.cpp:348` AsmapVersion(); `src/addrman.cpp:205`
/// serialization of asmap_version into peers.dat.
#[test]
#[ignore = "BUG G17 P2: asmap_version() absent — no version hash; peers.dat re-bucketing impossible"]
fn g17_asmap_version_hash_missing() {
    panic!("G17 BUG: AsmapVersion() absent; no SHA256 hash of asmap data");
}

// ────────────────────────────────────────────────────────────────────────────
// G18 — ASMap file size bounded MAX_ASMAP_FILESIZE=8MiB
// ────────────────────────────────────────────────────────────────────────────

/// G18 BUG (P3) — No MAX_ASMAP_FILESIZE guard.
///
/// Core: `DecodeAsmap()` reads the entire file without an explicit cap in the
/// current source, but the realistic maximum for production asmap data is ~8 MiB.
/// Rustoshi has no file-size check (and no file loading at all).
///
/// Note: The audit spec says MAX_ASMAP_FILESIZE = 0x800000 (8 MiB), but in the
/// current Core source the cap is enforced via AutoFile::size() indirectly.
/// The important thing is that a pathologically large file is bounded.
#[test]
#[ignore = "BUG G18 P3: no MAX_ASMAP_FILESIZE cap — no file loading at all; blocked by G2"]
fn g18_asmap_file_size_cap_missing() {
    panic!("G18 BUG: no asmap file size cap; entire loading subsystem absent");
}

// ────────────────────────────────────────────────────────────────────────────
// G19 — File hash logged at startup
// ────────────────────────────────────────────────────────────────────────────

/// G19 BUG (P3) — No asmap file hash logged.
///
/// Core logs `"Using asmap version %s for IP bucketing"` where %s is the
/// hex SHA256 of the asmap data.  Rustoshi logs no such message.
///
/// Core reference: `src/init.cpp:1628`.
#[test]
#[ignore = "BUG G19 P3: no asmap hash logged at startup; blocked by G1/G2"]
fn g19_asmap_hash_logged_at_startup() {
    panic!("G19 BUG: asmap hash not logged; loading subsystem absent");
}

// ────────────────────────────────────────────────────────────────────────────
// G20 — ASMap reload not supported at runtime (load-once)
// ────────────────────────────────────────────────────────────────────────────

/// G20 PASS (trivially) — Runtime reload is correctly not supported.
///
/// Since rustoshi never loads an asmap at all, it trivially satisfies the
/// "no runtime reload" constraint.  This is a vacuous pass — the feature
/// is missing rather than correctly disabled.
///
/// Core: asmap is loaded once in AppInitMain(), stored in const NetGroupManager.
#[test]
fn g20_asmap_no_runtime_reload() {
    // NetGroupManager is not reloaded at runtime — it has no set_asmap() method.
    // This is a vacuous pass (feature absent, not intentionally disabled).
    let mgr = NetGroupManager::new();
    // No `mgr.reload_asmap()` method exists.  Confirm by inspecting the manager
    // is purely const after creation.
    let _key = mgr.key();
    // Nothing to reload — passes by absence.
    // Real PASS requires G1 to be implemented first.
}

// ────────────────────────────────────────────────────────────────────────────
// G21 — Inbound peer ASN logged with connection
// ────────────────────────────────────────────────────────────────────────────

/// G21 BUG (P3) — Inbound peer ASN not logged.
///
/// Core: when a new inbound connection is accepted, `GetMappedAS(addr)` is
/// called and the ASN appears in the log message.  Rustoshi logs peer
/// connections but includes no ASN.
#[test]
#[ignore = "BUG G21 P3: inbound peer ASN not logged — get_mapped_as() absent"]
fn g21_inbound_peer_asn_logged() {
    panic!("G21 BUG: inbound peer ASN not logged; get_mapped_as() absent");
}

// ────────────────────────────────────────────────────────────────────────────
// G22 — Outbound peer selection prefers ASN diversity
// ────────────────────────────────────────────────────────────────────────────

/// G22 BUG (P2) — Outbound peer selection ignores ASN diversity.
///
/// Bitcoin Core's outbound connection logic uses the ASN (when asmap loaded) as
/// the "group" for diversity checking — no two outbound peers should share the
/// same ASN.  Rustoshi uses only subnet (/16) grouping.
///
/// Core reference: `src/net.cpp` SelectNodeToEvict / outbound slot logic.
#[test]
#[ignore = "BUG G22 P2: outbound peer selection ignores ASN; only /16 diversity enforced"]
fn g22_outbound_prefers_asn_diversity() {
    panic!("G22 BUG: outbound selection uses /16 only; ASN diversity absent");
}

// ────────────────────────────────────────────────────────────────────────────
// G23 — Eviction prefers same-ASN peers (anti-eclipse)
// ────────────────────────────────────────────────────────────────────────────

/// G23 BUG (P2) — Eviction does not protect against same-ASN eclipse.
///
/// Core's inbound eviction logic (SelectNodeToEvict) preferentially evicts
/// peers from the same network group, which is ASN-based when asmap is loaded.
/// This protects against an attacker controlling many IPs within a single AS.
///
/// Rustoshi's eviction.rs uses NetGroupManager::get_group() which is /16-based.
/// When asmap is loaded, this should transparently use the ASN group instead.
///
/// Core reference: `src/net.cpp` SelectNodeToEvict() group-diversity step.
#[test]
#[ignore = "BUG G23 P2: eviction uses /16 groups; ASN-based eclipse protection absent"]
fn g23_eviction_same_asn_preference() {
    // Rustoshi's eviction.rs already calls mgr.get_group() correctly.
    // The fix for this gate is: when asmap is loaded, get_group() should
    // return an ASN-derived group, not a subnet prefix.
    // Since asmap is never loaded, eviction always uses /16 grouping only.
    panic!("G23 BUG: eviction uses /16 groups only; ASN-based anti-eclipse absent");
}

// ────────────────────────────────────────────────────────────────────────────
// G24 — getpeerinfo includes `mapped_as` field per peer
// ────────────────────────────────────────────────────────────────────────────

/// G24 BUG (P2) — `mapped_as` field absent from getpeerinfo response.
///
/// Bitcoin Core: `getpeerinfo` includes `"mapped_as": <uint32>` for each peer
/// when asmap is loaded.  Also includes `"source_mapped_as"` in getnodeaddresses.
/// Rustoshi's `PeerInfoRpc` struct (crates/rpc/src/types.rs) has no `mapped_as`
/// field.
///
/// Core reference: `src/rpc/net.cpp:236` `obj.pushKV("mapped_as", mapped_as)`.
///
/// This is ALSO a P2 RPC parity bug: even if a user loads an asmap via a custom
/// fork, the RPC response will not include the field.
#[test]
#[ignore = "BUG G24 P2: PeerInfoRpc.mapped_as absent — getpeerinfo missing mapped_as field"]
fn g24_getpeerinfo_mapped_as_absent() {
    // PeerInfoRpc in crates/rpc/src/types.rs has no `mapped_as: Option<u32>` field.
    // Any peer returned by getpeerinfo will not include the AS number.
    panic!("G24 BUG: PeerInfoRpc.mapped_as absent; field not in getpeerinfo response");
}

// ────────────────────────────────────────────────────────────────────────────
// G25 — Loaded ASMap reports cardinality (unique ASNs)
// ────────────────────────────────────────────────────────────────────────────

/// G25 BUG (P3) — No ASMap cardinality reporting.
///
/// Core: `ASMapHealthCheck()` reports unique ASN count, coverage, etc.
/// Rustoshi has no `asmap_health_check()` or equivalent.
///
/// Core reference: `src/netgroup.cpp` ASMapHealthCheck().
#[test]
#[ignore = "BUG G25 P3: no ASMap cardinality reporting — ASMapHealthCheck() absent"]
fn g25_asmap_cardinality_reporting() {
    panic!("G25 BUG: asmap_health_check() absent; no cardinality reporting");
}

// ────────────────────────────────────────────────────────────────────────────
// G26 — Loaded ASMap reports total mapped prefix coverage
// ────────────────────────────────────────────────────────────────────────────

/// G26 BUG (P3) — No ASMap prefix coverage reporting.
///
/// ASMapHealthCheck also reports what fraction of the routable IPv4 space
/// is covered by the loaded asmap.  This is used to detect stale/incomplete
/// asmap files.
#[test]
#[ignore = "BUG G26 P3: no ASMap prefix coverage reporting — blocked by G25"]
fn g26_asmap_prefix_coverage_reporting() {
    panic!("G26 BUG: prefix coverage reporting absent");
}

// ────────────────────────────────────────────────────────────────────────────
// G27 — Coverage warning if < 90% of routable IPv4 space
// ────────────────────────────────────────────────────────────────────────────

/// G27 BUG (P3) — No coverage warning threshold.
///
/// Core emits a warning if < 90% of routable IPv4 space is covered.
/// Rustoshi has no coverage check.
#[test]
#[ignore = "BUG G27 P3: no coverage warning if < 90% IPv4 space covered — blocked by G25/G26"]
fn g27_coverage_warning_below_90pct() {
    panic!("G27 BUG: no 90% coverage warning threshold");
}

// ────────────────────────────────────────────────────────────────────────────
// G28 — getnodeaddresses RPC returns ASN per node
// ────────────────────────────────────────────────────────────────────────────

/// G28 BUG (P3) — getnodeaddresses does not include `mapped_as` per address.
///
/// Core reference: `src/rpc/net.cpp:1124` `ret.pushKV("mapped_as", mapped_as)`.
/// Also `src/rpc/net.cpp:1133` `source_mapped_as`.
/// Rustoshi's getnodeaddresses RPC (if implemented) would not include ASN.
#[test]
#[ignore = "BUG G28 P3: getnodeaddresses lacks mapped_as/source_mapped_as — asmap absent"]
fn g28_getnodeaddresses_asn_missing() {
    panic!("G28 BUG: getnodeaddresses lacks mapped_as field");
}

// ────────────────────────────────────────────────────────────────────────────
// G29 — ASMap NOT in peers.dat (loaded fresh at startup)
// ────────────────────────────────────────────────────────────────────────────

/// G29 BUG (P2) — peers.dat does not serialize asmap version for re-bucketing.
///
/// Bitcoin Core peers.dat stores the asmap version hash to detect when a new
/// asmap has been loaded (different hash → re-bucket all addrman entries).
/// Rustoshi's peers.dat format (to the extent it exists) has no asmap version
/// field, so changing the asmap file would not trigger re-bucketing.
///
/// Core reference: `src/addrman.cpp:205` `s << m_netgroupman.GetAsmapVersion()`.
///                 `src/addrman.cpp:313-322` asmap version comparison on load.
///
/// The asmap DATA is correctly NOT in peers.dat (it is loaded from disk).
/// But the VERSION (checksum) must be in peers.dat for invalidation to work.
#[test]
#[ignore = "BUG G29 P2: asmap version not in peers.dat — re-bucketing on asmap change impossible"]
fn g29_asmap_version_not_in_peers_dat() {
    panic!("G29 BUG: asmap version absent from peers.dat serialization");
}

// ────────────────────────────────────────────────────────────────────────────
// G30 — ASMap file detached from data dir — can be updated independently
// ────────────────────────────────────────────────────────────────────────────

/// G30 BUG (P3) — No asmap file loading at all; detachability moot.
///
/// Core supports `-asmap=<absolute_path>` to put the asmap file anywhere on
/// the filesystem, independent of the datadir.  This is correctly NOT inside
/// peers.dat.  Since rustoshi has no asmap loading, this property is vacuously
/// absent.
#[test]
#[ignore = "BUG G30 P3: asmap file support entirely absent; detachability moot — blocked by G1"]
fn g30_asmap_file_detachable_from_datadir() {
    panic!("G30 BUG: asmap loading absent; no detachable file support");
}

// ────────────────────────────────────────────────────────────────────────────
// Extra structural tests (PASS) — preserve properties needed when asmap lands
// ────────────────────────────────────────────────────────────────────────────

/// PASS — NetGroupManager correctly groups diverse routable IPs differently.
///
/// This verifies the existing /16 bucketing is correct, which ASMap builds on.
/// Each /16 block of the public internet should map to a distinct group.
#[test]
fn structural_diverse_ips_in_different_groups() {
    let mgr = NetGroupManager::with_key(0xDEAD_BEEF_CAFE_BABE_u64);

    let addrs: Vec<IpAddr> = vec![
        "8.8.8.8".parse().unwrap(),    // Google DNS (AS15169)
        "1.1.1.1".parse().unwrap(),    // Cloudflare (AS13335)
        "9.9.9.9".parse().unwrap(),    // Quad9 (AS19281)
        "208.67.222.222".parse().unwrap(), // OpenDNS (AS36692)
    ];

    let groups: Vec<NetGroup> = addrs.iter().map(|a| mgr.get_group(a)).collect();

    // All from different /8s — should all be in different /16 groups.
    assert_ne!(groups[0], groups[1], "8.8/16 != 1.1/16");
    assert_ne!(groups[0], groups[2], "8.8/16 != 9.9/16");
    assert_ne!(groups[0], groups[3], "8.8/16 != 208.67/16");
    assert_ne!(groups[1], groups[2], "1.1/16 != 9.9/16");
    assert_ne!(groups[1], groups[3], "1.1/16 != 208.67/16");
    assert_ne!(groups[2], groups[3], "9.9/16 != 208.67/16");
}

/// PASS — NetGroupManager key is random and persistent within an instance.
///
/// The key must be random (prevents attacker from predicting bucket assignments)
/// and constant within the lifetime of a NetGroupManager instance.
#[test]
fn structural_key_random_and_stable() {
    let mgr = NetGroupManager::new();
    let k1 = mgr.key();
    let k2 = mgr.key();
    assert_eq!(k1, k2, "key must be stable within an instance");

    // Two distinct instances should have different keys with overwhelming probability.
    let mgr2 = NetGroupManager::new();
    // This could theoretically fail (1 in 2^64 chance) — acceptable.
    assert_ne!(mgr.key(), mgr2.key(), "two new() instances must have independent random keys");
}

/// PASS — get_group() returns consistent results (deterministic given the same key).
///
/// This property must hold whether using /16 bucketing or ASN bucketing.
#[test]
fn structural_get_group_deterministic() {
    let mgr = NetGroupManager::with_key(42);
    let addr: IpAddr = "8.8.8.8".parse().unwrap();

    let g1 = mgr.get_group(&addr);
    let g2 = mgr.get_group(&addr);
    assert_eq!(g1, g2, "get_group() must be deterministic for the same address and key");
}

/// PASS — IPv6 /32 grouping works correctly.
///
/// When asmap is added, this will be replaced by ASN-based grouping for IPv6.
/// Until then, /32 is the correct fallback for IPv6.
#[test]
fn structural_ipv6_slash32_grouping() {
    let mgr = NetGroupManager::with_key(0);

    // 2001:4860:4860::8888 (Google) vs 2001:4860:1234::1 — same /32 prefix
    let a: IpAddr = "2001:4860:4860::8888".parse().unwrap();
    let b: IpAddr = "2001:4860:1234::1".parse().unwrap();
    let c: IpAddr = "2001:db8::1".parse().unwrap(); // different /32

    let ga = mgr.get_group(&a);
    let gb = mgr.get_group(&b);
    let gc = mgr.get_group(&c);

    assert_eq!(ga, gb, "same /32 prefix should yield same group");
    // 2001:db8::/32 is documentation range — classified as Unroutable by rustoshi.
    // So gc != ga because ga is Ipv6 type and gc is Unroutable type.
    assert_ne!(ga, gc, "different /32 prefix (one is documentation range) → different group");
}
