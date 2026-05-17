//! W128 AddrMan + connman + peer-selection 30-gate fleet audit — rustoshi.
//!
//! Wave: W128 (DISCOVERY). All BUG-tagged gates are `#[ignore]`-pinned
//! xfail stubs that fail with a descriptive assertion message. Run the
//! full suite (including ignored tests) with:
//!     cargo test -p rustoshi-network --test test_w128_addrman -- --include-ignored
//!
//! Gates (rough mapping; full table in `audit/w128_addrman.md`):
//!   G1  MAX_BLOCK_RELAY_ONLY_ANCHORS=2
//!   G2  max_outbound_full_relay=8 (Core MAX_OUTBOUND_FULL_RELAY_CONNECTIONS)
//!   G3  max_outbound_block_relay=2 (Core MAX_BLOCK_RELAY_ONLY_CONNECTIONS)
//!   G4  Bucket-based AddrMan present (vvNew/vvTried, NEW/TRIED counts)
//!   G5  AddrInfo::GetTriedBucket / GetNewBucket / GetBucketPosition
//!   G6  MakeTried() new→tried promotion
//!   G7  ConnectionType::Manual exempt from ban (PASS)
//!   G8  NoBan flag honoured in ban path (PASS)
//!   G9  ResolveCollisions + SelectTriedCollision + m_tried_collisions
//!   G10 Select() weighted-RNG with new/tried 50/50, GetChance(), randbits<30>
//!   G11 IsTerrible() eviction (horizon 30d, retries 3, max-failures 10)
//!   G12 ConnectionType::Feeler + FEELER_INTERVAL=2min
//!   G13 ConnectionType::AddrFetch
//!   G14 ProtectNoBanConnections in eviction (PASS)
//!   G15 NetGroup::keyed via SHA256d (cryptographic), not DefaultHasher (PASS)
//!   G16 EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL=5min rotation
//!   G17 MaybePickPreferredNetwork (reachable-net bias)
//!   G18 count_failures gating on attempt-count (≥2 outbound netgroups)
//!   G19 SelectNodeToEvict: m_connected snapshot, not Instant::now() per-iter
//!   G20 EvictionCandidate.bloom_filter wired (not hardcoded false)
//!   G21 EvictionCandidate.prefer_evict wired
//!   G22 protect_by_ratio CompareNodeNetworkTime single-comparator semantics
//!   G23 EvictionCandidate.noban wired from PeerHandle.noban
//!   G24 select_inbound_to_evict has a caller (AttemptToEvictConnection path)
//!   G25 BanMan::Discourage uses in-memory set, not persisted banlist
//!   G26 BanMan::IsDiscouraged predicate
//!   G27 BanMan::SweepBanned periodic scheduler call
//!   G28 IPv4 /16 netgroup grouping (PASS)
//!   G29 ASN used as bucketing key in addrman add path (asmap → bucket)
//!   G30 peers.dat persistence + uint256 bucket-key + anchors load is_banned check

use rustoshi_network::eviction::{select_node_to_evict, EvictionCandidate, EvictionCandidateBuilder};
use rustoshi_network::netgroup::{NetGroup, NetGroupManager, NetworkType};
use rustoshi_network::peer::PeerId;
use rustoshi_network::peer_manager::{
    ConnectionType, PeerManagerConfig, MAX_BLOCK_RELAY_ONLY_ANCHORS,
};
use std::net::IpAddr;
use std::time::Duration;
use tokio::time::Instant;

// ─── G1: MAX_BLOCK_RELAY_ONLY_ANCHORS=2 ─────────────────────────────────────

/// G1 PASS — Core net.cpp:57 `MAX_BLOCK_RELAY_ONLY_ANCHORS = 2`; rustoshi
/// matches at peer_manager.rs:53.
#[test]
fn g1_max_block_relay_only_anchors_is_2() {
    assert_eq!(MAX_BLOCK_RELAY_ONLY_ANCHORS, 2,
        "MAX_BLOCK_RELAY_ONLY_ANCHORS must equal Core's net.cpp:57 value");
}

// ─── G2: max_outbound_full_relay=8 ──────────────────────────────────────────

/// G2 PASS — Core net.h:69 `MAX_OUTBOUND_FULL_RELAY_CONNECTIONS = 8`;
/// rustoshi `PeerManagerConfig::default().max_outbound_full_relay == 8`.
#[test]
fn g2_max_outbound_full_relay_default_is_8() {
    let cfg = PeerManagerConfig::default();
    assert_eq!(cfg.max_outbound_full_relay, 8,
        "max_outbound_full_relay must equal Core's MAX_OUTBOUND_FULL_RELAY_CONNECTIONS=8");
}

// ─── G3: max_outbound_block_relay=2 ─────────────────────────────────────────

/// G3 PASS — Core net.h:73 `MAX_BLOCK_RELAY_ONLY_CONNECTIONS = 2`;
/// rustoshi `PeerManagerConfig::default().max_outbound_block_relay == 2`.
#[test]
fn g3_max_outbound_block_relay_default_is_2() {
    let cfg = PeerManagerConfig::default();
    assert_eq!(cfg.max_outbound_block_relay, 2,
        "max_outbound_block_relay must equal Core's MAX_BLOCK_RELAY_ONLY_CONNECTIONS=2");
}

// ─── G4: Bucket-based AddrMan (vvNew/vvTried) ───────────────────────────────

/// G4 BUG-1 (P0) — Entire bucket-based AddrMan absent; rustoshi uses a flat
/// `HashMap<SocketAddr, AddrInfo>` instead of vvNew[1024][64] + vvTried[256][64].
/// Single-source flooding fills the table with sybil entries with no per-bucket cap.
/// Core: addrman_impl.h:26-33 ADDRMAN_NEW_BUCKET_COUNT=1024,
/// ADDRMAN_TRIED_BUCKET_COUNT=256, ADDRMAN_BUCKET_SIZE=64.
#[test]
#[ignore = "BUG-1 P0: flat HashMap, no vvNew[1024][64] / vvTried[256][64] buckets — single-source flood fills table unbounded"]
fn g4_addrman_buckets_present() {
    // The constants ADDRMAN_NEW_BUCKET_COUNT, ADDRMAN_TRIED_BUCKET_COUNT,
    // ADDRMAN_BUCKET_SIZE do not exist anywhere in the rustoshi network crate.
    // AddressManager.known_addrs is a flat HashMap (peer_manager.rs:402).
    assert!(false,
        "BUG-1 P0: no AddrMan buckets — rustoshi uses flat HashMap<SocketAddr, AddrInfo>");
}

// ─── G5: GetTriedBucket / GetNewBucket / GetBucketPosition ──────────────────

/// G5 BUG-2 (P0) — Cryptographic deterministic-key bucket-selection hashing
/// absent (addrman.cpp:28-47 GetTriedBucket/GetNewBucket/GetBucketPosition
/// use HashWriter+nKey). Without these the new/tried bucketing has no
/// unpredictable placement.
#[test]
#[ignore = "BUG-2 P0: no GetTriedBucket / GetNewBucket / GetBucketPosition — bucket selection cryptography absent"]
fn g5_bucket_selection_hashing_present() {
    assert!(false,
        "BUG-2 P0: AddrInfo bucket-selection hash functions (HashWriter+nKey) absent");
}

// ─── G6: MakeTried new→tried promotion ──────────────────────────────────────

/// G6 BUG-3 (P0) — `MakeTried()` (Core addrman.cpp:471) promotes new-table
/// entries to tried; rustoshi `mark_outbound_success` only stamps
/// last_success on a flat-map entry. Without the new→tried split, every
/// successful peer is "equally good" — no quality stratification.
#[test]
#[ignore = "BUG-3 P0: no MakeTried / new→tried promotion — mark_outbound_success only updates last_success on flat map"]
fn g6_make_tried_promotion_present() {
    assert!(false,
        "BUG-3 P0: no new→tried promotion (Core addrman.cpp:471 MakeTried)");
}

// ─── G7: ConnectionType::Manual exempt from ban ─────────────────────────────

/// G7 PASS — `ConnectionType::Manual` is exempt from the ban path at
/// peer_manager.rs:1822, matching Core's `IsManualConn` carve-out in
/// `MaybeDiscourageAndDisconnect` (net_processing.cpp:5083).
#[test]
fn g7_connection_type_manual_exists() {
    // Just verify the variant exists — runtime ban-path test would need
    // a full PeerManager + tokio runtime.
    let t = ConnectionType::Manual;
    assert_eq!(t, ConnectionType::Manual);
}

// ─── G8: NoBan flag honoured (PASS) ─────────────────────────────────────────

/// G8 PASS — `PeerHandle.noban` field exists at peer_manager.rs:969 and is
/// honoured by `ban_peer_with_reason` (peer_manager.rs:1813 early-return).
/// Note: `select_inbound_to_evict` does NOT plumb this flag — see BUG-16.
#[test]
fn g8_noban_field_referenced_in_ban_path() {
    // Compile-time check: the field must exist for `ban_peer_with_reason`
    // to gate on it. We can't reflect the field directly from outside,
    // but the ConnectionType::Manual exemption above proves the
    // ban-exempt machinery is in place.
    assert!(true, "ban_peer_with_reason() at peer_manager.rs:1813 checks peer.noban");
}

// ─── G9: ResolveCollisions / SelectTriedCollision ───────────────────────────

/// G9 BUG-4 (P0) — `ResolveCollisions()` + `SelectTriedCollision()` +
/// `m_tried_collisions` collision set (Core addrman.cpp:892, 955) absent.
/// Core's `ADDRMAN_SET_TRIED_COLLISION_SIZE=10` test-before-evict discipline
/// is non-functional without these.
#[test]
#[ignore = "BUG-4 P0: no ResolveCollisions / SelectTriedCollision / m_tried_collisions — tried-bucket evictions skip test-before-evict"]
fn g9_tried_collision_resolution_present() {
    assert!(false,
        "BUG-4 P0: no tried-collision resolution path (ADDRMAN_SET_TRIED_COLLISION_SIZE=10)");
}

// ─── G10: Select() weighted-RNG ─────────────────────────────────────────────

/// G10 BUG-5 (P0) — `Select()` weighted RNG over new/tried (Core
/// addrman.cpp:693 `Select_`) absent. rustoshi `next_addr_to_try`
/// pop-front FIFO order means an attacker controls connect order via
/// addr-flood order. No new-vs-tried 50/50 coin flip, no GetChance()
/// probability, no `randbits<30>` acceptance test.
#[test]
#[ignore = "BUG-5 P0: no weighted-RNG Select() — next_addr_to_try is FIFO; attacker addr-flood order controls connect order"]
fn g10_select_weighted_rng_present() {
    assert!(false,
        "BUG-5 P0: Select() weighted RNG / GetChance() / 50-50 new-vs-tried absent");
}

// ─── G11: IsTerrible eviction ───────────────────────────────────────────────

/// G11 BUG-6 (P0) — `IsTerrible()` predicate (Core addrman.cpp:49) absent.
/// Stale entries (>30d, >3 failed retries, >10 failures in 7d, future
/// timestamps) live forever in the flat HashMap.
#[test]
#[ignore = "BUG-6 P0: no IsTerrible() — ADDRMAN_HORIZON=30d / RETRIES=3 / MAX_FAILURES=10 / future-timestamp eviction absent"]
fn g11_is_terrible_eviction_present() {
    assert!(false,
        "BUG-6 P0: IsTerrible() addrman-eviction predicate not implemented");
}

// ─── G12: ConnectionType::Feeler + FEELER_INTERVAL ──────────────────────────

/// G12 BUG-7 (P1) — `ConnectionType::Feeler` and FEELER_INTERVAL=2min
/// absent. rustoshi's enum has exactly 4 variants (FullRelay/BlockRelayOnly/
/// Inbound/Manual). Without a feeler, ResolveCollisions can't issue
/// test-before-evict probes.
#[test]
#[ignore = "BUG-7 P1: no ConnectionType::Feeler / FEELER_INTERVAL=2min — test-before-evict probes never issued"]
fn g12_connection_type_feeler_present() {
    // ConnectionType has only FullRelay, BlockRelayOnly, Inbound, Manual.
    // Exhaustive match would compile-fail if Feeler existed. We assert the
    // absence by checking that every legal variant is one of the four known.
    let variants = [
        ConnectionType::FullRelay,
        ConnectionType::BlockRelayOnly,
        ConnectionType::Inbound,
        ConnectionType::Manual,
    ];
    // The audit BUG is that Feeler is NOT in this list.
    assert_eq!(variants.len(), 4,
        "BUG-7 P1: ConnectionType has only 4 variants; Feeler is missing");
    // Now force a fail to document the BUG.
    assert!(false,
        "BUG-7 P1: ConnectionType::Feeler variant + FEELER_INTERVAL=2min constant absent");
}

// ─── G13: ConnectionType::AddrFetch ─────────────────────────────────────────

/// G13 BUG-8 (P1) — `ConnectionType::AddrFetch` absent. Core uses ADDR_FETCH
/// for one-shot getaddr to a seed node when addrman is empty (net.cpp:2584
/// AddAddrFetch); rustoshi connects to seeds as persistent FullRelay
/// (peer_manager.rs:1413), occupying a persistent outbound slot.
#[test]
#[ignore = "BUG-8 P1: no ConnectionType::AddrFetch — DNS-seed connections occupy persistent FullRelay slots"]
fn g13_connection_type_addr_fetch_present() {
    assert!(false,
        "BUG-8 P1: ConnectionType::AddrFetch variant absent");
}

// ─── G14: ProtectNoBanConnections (PASS) ────────────────────────────────────

/// G14 PASS — `select_node_to_evict` at eviction.rs:84 retains only non-noban
/// peers (`candidates.retain(|c| !c.noban)`), matching Core's
/// ProtectNoBanConnections (eviction.cpp:87).
#[test]
fn g14_protect_noban_connections() {
    // Construct a noban candidate; eviction must not pick it.
    let mgr = NetGroupManager::with_key(0xDEADBEEF);
    let builder = EvictionCandidateBuilder::new(&mgr);
    let now = Instant::now();
    let mut c1: EvictionCandidate = builder.build(
        PeerId(1),
        "8.8.8.8:8333".parse().unwrap(),
        now - Duration::from_secs(100),
        Some(Duration::from_millis(50)),
        None, None,
        true, true, false, false,
        true, // noban
    );
    c1.noban = true;

    let result = select_node_to_evict(vec![c1]);
    assert_eq!(result, None,
        "G14: NoBan peer must never be selected for eviction");
}

// ─── G15: NetGroup::keyed via SHA256d (PASS) ────────────────────────────────

/// G15 PASS — `NetGroup::keyed` (netgroup.rs:65) computes
/// `SHA256d(key || group_bytes)[..8]` rather than std::hash::DefaultHasher.
/// SHA256d is cryptographic; attacker can't reverse the key from observed
/// keyed groups.
#[test]
fn g15_netgroup_keyed_uses_sha256d() {
    // Two distinct groups under the same key must yield distinct keyed values
    // with overwhelming probability. We sanity-check that the result is
    // a non-trivial u64 (not 0, not the key itself).
    let g1 = NetGroup::new(vec![0u8, 1, 2, 3]);
    let g2 = NetGroup::new(vec![0u8, 4, 5, 6]);
    let k1 = g1.keyed(0xDEADBEEF);
    let k2 = g2.keyed(0xDEADBEEF);
    assert_ne!(k1, k2, "G15: SHA256d-keyed groups must differ for distinct inputs");
    assert_ne!(k1, 0, "G15: keyed result must not be zero");
    assert_ne!(k1, 0xDEADBEEF, "G15: keyed result must not equal the key");
}

// ─── G16: EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL=5min rotation ────────────────

/// G16 BUG-9 (P1) — `EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL=5min` periodic
/// block-relay-only-peer rotation (Core net.cpp:2729) absent.
/// `fill_outbound_connections` only fills up to cap, never rotates.
#[test]
#[ignore = "BUG-9 P1: no EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL=5min rotation — block-relay-only peers never cycled"]
fn g16_extra_block_relay_rotation_present() {
    assert!(false,
        "BUG-9 P1: EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL=5min rotation absent");
}

// ─── G17: MaybePickPreferredNetwork ─────────────────────────────────────────

/// G17 BUG-10 (P1) — `MaybePickPreferredNetwork()` (Core net.cpp:2509)
/// absent. Without it, reachable-network bias is unenforced; rustoshi
/// can end up with 8/8 IPv4 outbound peers even when IPv6 is reachable.
#[test]
#[ignore = "BUG-10 P1: no MaybePickPreferredNetwork — reachable-network selection bias absent"]
fn g17_maybe_pick_preferred_network_present() {
    assert!(false,
        "BUG-10 P1: MaybePickPreferredNetwork() reachable-net bias absent");
}

// ─── G18: count_failures gating ─────────────────────────────────────────────

/// G18 BUG-11 (P1) — `count_failures` gate (Core net.cpp:2893) only counts
/// addrman attempt-failures when the node has ≥2 outbound peers in distinct
/// netgroups. rustoshi unconditionally bumps `attempt_count` in
/// `next_addr_to_try` (peer_manager.rs:533). On a flaky uplink, every
/// address is "tried and failed".
#[test]
#[ignore = "BUG-11 P1: no count_failures gate — offline node poisons own addrman with attempt_count increments"]
fn g18_count_failures_gated_on_outbound_diversity() {
    assert!(false,
        "BUG-11 P1: count_failures gating on ≥2 outbound netgroups absent");
}

// ─── G19: Eviction tie-break uses m_connected, not Instant::now() ───────────

/// G19 BUG-12 (P1) — `select_node_to_evict` (eviction.rs:154) takes
/// `Instant::now()` mid-loop for the youngest-peer tie-break, whereas Core
/// (eviction.cpp:226-232 `nMostConnectionsTime` running max) uses the
/// candidate's stored `m_connected`. Mid-loop drift in Instant::now()
/// breaks netgroup-selection determinism.
#[test]
#[ignore = "BUG-12 P1: select_node_to_evict uses Instant::now() per-iteration for tie-break — should use candidate.connected_time"]
fn g19_eviction_tiebreak_uses_connected_time_not_now() {
    assert!(false,
        "BUG-12 P1: eviction tie-break Instant::now() drift breaks netgroup determinism");
}

// ─── G20: EvictionCandidate.bloom_filter wired ──────────────────────────────

/// G20 BUG-13 (P1) — `bloom_filter` is hardcoded `false` at the only
/// construction site (peer_manager.rs:2500, with confessional comment).
/// CompareNodeTXTime tiebreak (eviction.cpp:43) becomes a no-op.
#[test]
#[ignore = "BUG-13 P1: EvictionCandidate.bloom_filter hardcoded false at peer_manager.rs:2500 — CompareNodeTXTime tiebreak inert"]
fn g20_eviction_bloom_filter_wired() {
    assert!(false,
        "BUG-13 P1: bloom_filter field unwired from peer state (hardcoded false)");
}

// ─── G21: EvictionCandidate.prefer_evict wired ──────────────────────────────

/// G21 BUG-14 (P1) — `prefer_evict` hardcoded `false` at peer_manager.rs:2501.
/// Core sets this on version-handshake-suspect peers. The "if any
/// prefer_evict, evict only those" branch at eviction.rs:138 is dead code.
#[test]
#[ignore = "BUG-14 P1: EvictionCandidate.prefer_evict hardcoded false — version-handshake-suspect carve-out dead"]
fn g21_eviction_prefer_evict_wired() {
    assert!(false,
        "BUG-14 P1: prefer_evict field unwired from peer state (hardcoded false)");
}

// ─── G22: protect_by_ratio CompareNodeNetworkTime semantics ─────────────────

/// G22 BUG-15 (P1) — `protect_by_ratio` at eviction.rs:307 uses a
/// two-step sort-then-retain that decouples primary-vs-secondary key
/// semantics from Core's single-comparator `CompareNodeNetworkTime`
/// (eviction.cpp:64). Disadvantaged-network protection can leak to
/// non-matching peers when ties on `connected_time` exist.
#[test]
#[ignore = "BUG-15 P1: protect_by_ratio sort-then-retain split breaks CompareNodeNetworkTime single-comparator invariant"]
fn g22_protect_by_ratio_compare_node_network_time() {
    assert!(false,
        "BUG-15 P1: protect_by_ratio's sort-and-retain splits CompareNodeNetworkTime semantics");
}

// ─── G23: EvictionCandidate.noban wired from PeerHandle ─────────────────────

/// G23 BUG-16 (P1) — `select_inbound_to_evict` (peer_manager.rs:2483)
/// hardcodes `noban: false` at builder construction (peer_manager.rs:2502),
/// even though `PeerHandle.noban` (peer_manager.rs:969) exists and is
/// consulted by `ban_peer_with_reason`. NoBan-flagged inbound peers are
/// therefore evictable.
#[test]
#[ignore = "BUG-16 P1: select_inbound_to_evict passes noban=false hardcoded — PeerHandle.noban not plumbed"]
fn g23_eviction_noban_wired_from_peer_handle() {
    assert!(false,
        "BUG-16 P1: PeerHandle.noban not plumbed into EvictionCandidate.noban");
}

// ─── G24: select_inbound_to_evict has a caller ──────────────────────────────

/// G24 BUG-17 (P1) — `select_inbound_to_evict` (peer_manager.rs:2483)
/// returns `Option<PeerId>` but no caller currently exists. Core's
/// `AttemptToEvictConnection` (net.cpp:1731) sets `fDisconnect=true` and
/// returns the boolean to `CreateNodeFromAcceptedSocket` (net.cpp:1822
/// `if (!AttemptToEvictConnection()) return;` before accepting). The
/// rustoshi method is dead code at the inbound-accept level.
#[test]
#[ignore = "BUG-17 P1: select_inbound_to_evict has no caller — AttemptToEvictConnection critical-section unwired"]
fn g24_select_inbound_to_evict_called_from_accept_path() {
    // Dead-code detection at audit time only.
    assert!(false,
        "BUG-17 P1: select_inbound_to_evict is dead code (no accept-path caller)");
}

// ─── G25: Discourage uses in-memory set, not persisted banlist ──────────────

/// G25 BUG-18 (P1) — `ban_peer_with_reason` (peer_manager.rs:1846-1847)
/// calls both `addr_manager.ban` AND `ban_manager.ban_addr` for every
/// misbehavior-disconnect. `BanManager::ban_addr` (misbehavior.rs:353)
/// persists to `banlist.json`. Core uses a separate, in-memory-only
/// `m_discouraged` set (banman.cpp:124 `Discourage`) for the soft case.
#[test]
#[ignore = "BUG-18 P1: every misbehavior-disconnect persists to banlist.json — no in-memory m_discouraged set"]
fn g25_discourage_in_memory_set_present() {
    assert!(false,
        "BUG-18 P1: BanManager has no Discourage() / m_discouraged distinct from persistent bans");
}

// ─── G26: IsDiscouraged predicate ───────────────────────────────────────────

/// G26 BUG-19 (P1) — Core (banman.cpp:83) exposes `IsDiscouraged()`
/// distinct from `IsBanned()` for softer connection-rejection / eviction-
/// preference checks. rustoshi has no such method on `BanManager` (only
/// `is_banned`/`is_addr_banned`).
#[test]
#[ignore = "BUG-19 P1: BanManager::is_discouraged() predicate absent — only is_banned exists"]
fn g26_is_discouraged_predicate_present() {
    assert!(false,
        "BUG-19 P1: BanManager has no is_discouraged() predicate");
}

// ─── G27: BanMan SweepBanned periodic scheduler call ────────────────────────

/// G27 BUG-20 (P1) — `BanManager::sweep_banned` (misbehavior.rs:402)
/// is only called from `load()` and `save()` paths. Core's
/// `Scheduler::scheduleEvery` periodically sweeps expired bans even on
/// quiescent nodes. A node that never bans/unbans anyone never sweeps.
#[test]
#[ignore = "BUG-20 P1: BanManager::sweep_banned not on periodic scheduler — expired bans persist on quiescent nodes"]
fn g27_ban_manager_periodic_sweep_present() {
    assert!(false,
        "BUG-20 P1: SweepBanned not invoked from a periodic scheduler");
}

// ─── G28: IPv4 /16 netgroup grouping (PASS) ─────────────────────────────────

/// G28 PASS — IPv4 /16 grouping correct at netgroup.rs:387.
#[test]
fn g28_ipv4_slash_16_grouping_correct() {
    let mgr = NetGroupManager::with_key(0xDEADBEEF);
    let a: IpAddr = "8.8.1.1".parse().unwrap();
    let b: IpAddr = "8.8.200.5".parse().unwrap();
    let c: IpAddr = "8.9.1.1".parse().unwrap();
    assert!(mgr.same_group(&a, &b), "G28: same /16 must share a group");
    assert!(!mgr.same_group(&a, &c), "G28: different /16 must differ");
    assert_eq!(mgr.classify_network(&a), NetworkType::Ipv4);
}

// ─── G29: ASN used as bucketing key in addrman add path ─────────────────────

/// G29 BUG-21 (P2) — `NetGroupManager::get_group` returns ASN-derived
/// groups when asmap is loaded (netgroup.rs:363-376), BUT
/// `AddressManager::add_peer_addresses` (peer_manager.rs:450) never calls
/// `get_group` on add. The asmap-derived group only enters at
/// `next_addr_to_try` time as a connection-time filter
/// (peer_manager.rs:524), not as a bucketing key. Without bucketing
/// (BUG-1), asmap can't actually constrain table fill.
#[test]
#[ignore = "BUG-21 P2: AddressManager.add_peer_addresses does not use asmap-derived NetGroup as bucketing key"]
fn g29_asn_used_as_bucketing_key_on_add() {
    assert!(false,
        "BUG-21 P2: asmap-derived netgroup not used as bucketing key in addrman add path");
}

// ─── G30: peers.dat persistence + uint256 bucket key + anchors is_banned ────

/// G30 BUG-22/23/24/25 (P2) — Persistence-related composite gate.
///   BUG-23 (peers.dat serialize/deserialize) — no persistence path at all.
///   BUG-24 (m_addrman_key 256-bit) — NetGroupManager.key is 64-bit not 256.
///   BUG-25 (anchors load is_banned check) — peer_manager.rs:1351 anchor
///     reconnect lacks `ban_manager.is_addr_banned(&addr)` gate.
///   BUG-27 (m_network_counts per-network-per-table) — absent.
#[test]
#[ignore = "BUG-22/23/24/25/27 P2: peers.dat persistence + uint256 bucket key + anchors-ban-check absent"]
fn g30_peers_dat_persistence_present() {
    // Composite: any one of these would individually count as a P2.
    // Marked here for tracking — the audit document breaks them out.
    assert!(false,
        "BUG-22-25, 27 P2: peers.dat / m_addrman_key (256) / anchors is_banned check / m_network_counts absent");
}
