//! Guards for cffix-rustoshi-addrman-outbound-select: drawing outbound peers
//! from the (non-consuming) bucketed addrman must not dial one address twice
//! while it is still connecting, must not bury operator-named (`addnode add`)
//! addresses in the random draw, and must give every non-empty bucket the
//! same chance (Core `AddrMan::Select_`).
//!
//! Core builds both exclusion sets in `CConnman::ThreadOpenConnections` from
//! `m_nodes`, which already holds peers that are still connecting:
//! `AlreadyConnectedToAddress` for addresses, `outbound_ipv46_peer_netgroups`
//! for the netgroups of full-relay / block-relay-only / manual peers.
//!
//! Fixtures that depend on the bucket draw use a fixed nkey (through a
//! peers.dat round-trip) and assert their addresses sit in distinct NEW
//! buckets, so placement is deterministic and only the draw is random. The
//! manual-priority tests do not depend on the draw (the manual stage runs
//! first).

use rustoshi_network::message::{NetAddress, TimestampedNetAddress, NODE_NETWORK, NODE_WITNESS};
use rustoshi_network::netgroup::NetGroupManager;
use rustoshi_network::peer_manager::{AddrManTable, AddressManager};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

const NKEY: [u8; 32] = [0x42; 32];

/// Compile shim so this file builds on a base commit that lacks
/// `AddressManager::next_addr_to_try_excluding` (added by rustoshi#71).
/// Where the inherent method exists it takes precedence over this trait
/// method, so the shim is never called on the fix. On a base commit the
/// tests run against plain `next_addr_to_try`, which ignores the busy sets,
/// and fail on their assertions rather than on compilation.
#[allow(dead_code)]
trait NextAddrExcludingShim {
    fn next_addr_to_try_excluding(
        &mut self,
        ng: &NetGroupManager,
        busy_addrs: &HashSet<SocketAddr>,
        busy_groups: &HashSet<Vec<u8>>,
    ) -> Option<SocketAddr>;
}

#[allow(dead_code)]
impl NextAddrExcludingShim for AddressManager {
    fn next_addr_to_try_excluding(
        &mut self,
        ng: &NetGroupManager,
        _busy_addrs: &HashSet<SocketAddr>,
        _busy_groups: &HashSet<Vec<u8>>,
    ) -> Option<SocketAddr> {
        self.next_addr_to_try(ng)
    }
}

fn addr(a: u8, b: u8) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, 0, 1)), 8333)
}

fn group(ng: &NetGroupManager, a: &SocketAddr) -> Vec<u8> {
    ng.get_group(&a.ip()).as_bytes().to_vec()
}

/// A self-sourced (DNS-like) NEW table with a fixed nkey.
fn table_with(addrs: &[SocketAddr], ng: &NetGroupManager) -> AddrManTable {
    let mut t = AddrManTable::with_nkey(NKEY);
    for a in addrs {
        assert!(t.add(*a, a.ip(), NODE_NETWORK | NODE_WITNESS, 1_700_000_000, ng));
    }
    t
}

fn assert_distinct_buckets(t: &AddrManTable, addrs: &[SocketAddr], ng: &NetGroupManager) {
    let buckets: HashSet<usize> = addrs
        .iter()
        .map(|a| t.new_slot_of(a, ng).expect("held in NEW").0)
        .collect();
    assert_eq!(buckets.len(), addrs.len(), "fixture needs distinct buckets");
}

/// An address manager loaded from a peers.dat holding `addrs` (fixed nkey).
fn manager_with(addrs: &[SocketAddr], ng: &NetGroupManager) -> (AddressManager, tempfile::TempDir) {
    let t = table_with(addrs, ng);
    assert_distinct_buckets(&t, addrs, ng);
    let dir = tempfile::tempdir().unwrap();
    t.save(dir.path());
    let mgr = AddressManager::with_persisted(dir.path(), ng);
    assert_eq!(mgr.addrman().total_count(), addrs.len());
    (mgr, dir)
}

/// One fill pass with fewer eligible addresses than slots: each pick is
/// "connecting" (in the busy sets) before the next pick, so no address is
/// returned twice and the pass ends with None, not a duplicate dial.
#[test]
fn fill_pass_never_picks_a_connecting_address_twice() {
    let ng = NetGroupManager::with_key(7);
    let already_peer = addr(34, 1); // e.g. an inbound peer we already have
    let book = vec![addr(31, 1), addr(32, 1), addr(33, 1), already_peer];
    let (mut mgr, _dir) = manager_with(&book, &ng);

    let mut busy_addrs: HashSet<SocketAddr> = [already_peer].into_iter().collect();
    let mut busy_groups = HashSet::new();
    let mut picked = Vec::new();
    for _ in 0..10 {
        match mgr.next_addr_to_try_excluding(&ng, &busy_addrs, &busy_groups) {
            Some(a) => {
                assert!(
                    !picked.contains(&a),
                    "{a} picked twice in one pass: {picked:?}"
                );
                busy_addrs.insert(a);
                busy_groups.insert(group(&ng, &a));
                picked.push(a);
            }
            None => break,
        }
    }
    let mut sorted = picked.clone();
    sorted.sort();
    let mut want: Vec<SocketAddr> = book.into_iter().filter(|a| *a != already_peer).collect();
    want.sort();
    assert_eq!(
        sorted, want,
        "every book address except the existing peer dialled exactly once"
    );
}

/// A peer that is still connecting holds its netgroup: another address in
/// the same /16 is not picked (Core counts connecting nodes in
/// `outbound_ipv46_peer_netgroups`).
#[test]
fn connecting_peer_netgroup_is_skipped() {
    let ng = NetGroupManager::with_key(7);
    let a = addr(41, 7);
    let b = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(41, 7, 9, 9)), 8333);
    let mut t = table_with(&[a, b], &ng);
    // Same /16 and same (self) source group: same bucket, distinct slots.
    assert!(t.new_slot_of(&a, &ng).is_some() && t.new_slot_of(&b, &ng).is_some());
    let dir = tempfile::tempdir().unwrap();
    t.save(dir.path());
    t = AddrManTable::load(dir.path(), &ng);
    assert_eq!(t.total_count(), 2);
    let mut mgr = AddressManager::with_persisted(dir.path(), &ng);

    let first = mgr.next_addr_to_try(&ng).expect("book has addresses");
    let busy_addrs: HashSet<SocketAddr> = [first].into_iter().collect();
    let busy_groups: HashSet<Vec<u8>> = [group(&ng, &first)].into_iter().collect();
    // Repeat: each call is one pass of up to 100 draws, and the other
    // address can sit behind a small gap in the shared bucket.
    for _ in 0..20 {
        assert_eq!(
            mgr.next_addr_to_try_excluding(&ng, &busy_addrs, &busy_groups),
            None,
            "the other address in {first}'s /16 must wait for the netgroup"
        );
    }
}

/// `addnode add` / testnet4 fallback peers (`add_manual_address`) keep
/// priority over the random addrman draw even when routable, as on master.
#[test]
fn routable_manual_address_keeps_priority() {
    let ng = NetGroupManager::with_key(7);
    let book: Vec<SocketAddr> = (1..=60u8).map(|i| addr(100 + i, 3)).collect();
    let mut mgr = AddressManager::new();
    mgr.add_dns_addresses(book);
    let manual = addr(8, 8);
    mgr.add_manual_address(manual);
    assert_eq!(mgr.next_addr_to_try(&ng), Some(manual));

    // Already connecting to it: the manual stage skips it, and the draw
    // falls through to the addrman book.
    let other = addr(51, 1);
    let (mut mgr, _dir) = manager_with(&[other, manual], &ng);
    mgr.add_manual_address(manual);
    let busy: HashSet<SocketAddr> = [manual].into_iter().collect();
    assert_eq!(
        mgr.next_addr_to_try_excluding(&ng, &busy, &HashSet::new()),
        Some(other)
    );
}

/// `addnode add` for an address we already learned from DNS or a peer still
/// gets the manual priority (it is re-tagged as operator-named).
#[test]
fn already_known_address_added_manually_keeps_priority() {
    let ng = NetGroupManager::with_key(7);
    let book: Vec<SocketAddr> = (1..=60u8).map(|i| addr(100 + i, 3)).collect();
    let from_dns = addr(8, 8);
    let from_peer = addr(9, 9);

    // Learned from DNS first.
    let mut mgr = AddressManager::new();
    mgr.add_dns_addresses(book.clone());
    mgr.add_dns_addresses(vec![from_dns]);
    let _ = mgr.next_addr_to_try(&ng); // binds the netgroup manager
    mgr.add_manual_address(from_dns);
    assert_eq!(mgr.next_addr_to_try(&ng), Some(from_dns));

    // Learned from a peer's addr message first.
    let mut mgr = AddressManager::new();
    mgr.add_dns_addresses(book);
    let _ = mgr.next_addr_to_try(&ng);
    let IpAddr::V4(v4) = from_peer.ip() else {
        unreachable!()
    };
    mgr.add_peer_addresses(
        &[TimestampedNetAddress {
            timestamp: 1_700_000_000,
            address: NetAddress::from_ipv4(v4.octets(), from_peer.port(), 9),
        }],
        "45.33.1.1:8333".parse().unwrap(),
    );
    mgr.add_manual_address(from_peer);
    assert_eq!(mgr.next_addr_to_try(&ng), Some(from_peer));
}

/// Core `Select_` draws random buckets until one is non-empty, so with every
/// address in its own bucket each is drawn about equally often. Walking on
/// from a random start bucket (master) gives each address the share of the
/// table's empty run in front of it instead.
#[test]
fn select_gives_each_occupied_bucket_an_equal_chance() {
    let ng = NetGroupManager::with_key(7);
    let book: Vec<SocketAddr> = (0..8u8).map(|i| addr(70 + i, 5)).collect();
    let t = table_with(&book, &ng);
    assert_distinct_buckets(&t, &book, &ng);

    const DRAWS: usize = 8000;
    let mut hits: HashMap<SocketAddr, usize> = HashMap::new();
    for _ in 0..DRAWS {
        *hits.entry(t.select(false).expect("non-empty")).or_default() += 1;
    }
    // Expected 1000 each (sd ~30); a gap-weighted walk over 8 random bucket
    // positions in 1024 leaves some address far below half of that.
    for a in &book {
        let n = hits.get(a).copied().unwrap_or(0);
        assert!(
            n * 8 * 2 >= DRAWS,
            "{a} drawn {n} of {DRAWS} times (expected ~{}): {hits:?}",
            DRAWS / 8
        );
    }
}

/// A pick that never completes a handshake is not re-dialled straight away
/// (rustoshi refills on every `Disconnected` event, with no pause between
/// passes), but a peer that did connect and then dropped is.
#[test]
fn failed_pick_is_not_redialled_inside_backoff() {
    let ng = NetGroupManager::with_key(7);
    let a = addr(61, 1);
    let b = addr(62, 1);
    let (mut mgr, _dir) = manager_with(&[a, b], &ng);

    let first = mgr.next_addr_to_try(&ng).expect("book has addresses");
    // The dial fails (refused): no handshake, nothing busy. The next pass
    // must take the other address, then find nothing left to dial.
    let second = mgr.next_addr_to_try(&ng).expect("other address");
    assert_ne!(first, second, "failed {first} re-dialled at once");
    for _ in 0..20 {
        assert_eq!(mgr.next_addr_to_try(&ng), None, "dead book re-dialled");
    }

    // A completed handshake clears the backoff: after the peer drops it is
    // dialable again (once Core's 30-draw recent-try grace is used up).
    mgr.mark_outbound_success(&first, &ng);
    mgr.mark_outbound_disconnected(&first, &ng);
    assert_eq!(mgr.next_addr_to_try(&ng), Some(first));
}

/// Merge guard for rustoshi#69 + #71: after #71, gossip never queues, so the
/// only `try_queue` hints left are DNS / manual. #69's stale-hint skip (a
/// queued address that `make_room_legacy` evicted is not dialled) must still
/// hold on the non-routable stage that drains them. `evicted_addresses_are_not_dialed`
/// in test_cffix_addrman_bounds.rs fills through gossip, so on this branch it
/// has nothing queued; this fills through the DNS path instead.
#[test]
fn evicted_dns_hint_is_not_dialed() {
    use rustoshi_network::ADDRMAN_CEILING;
    let mut mgr = AddressManager::new();
    let ng = NetGroupManager::with_key(12345);
    // Non-routable 10.x.y.z, so the bucketed addrman refuses them and the
    // `try_queue` stage is what dials them (regtest / local setups).
    let total = ADDRMAN_CEILING as u32 + 5000;
    let addrs: Vec<SocketAddr> = (0..total)
        .map(|n| SocketAddr::from(((0x0A00_0000u32 + n).to_be_bytes(), 8333)))
        .collect();
    mgr.add_dns_addresses(addrs);
    assert!(mgr.known_count() <= ADDRMAN_CEILING);
    let known: HashSet<IpAddr> = mgr.all_known_ips().into_iter().collect();
    assert!(mgr.queue_size() > 0, "DNS path queued nothing: test is vacuous");
    // ~5000 of the ~65k queued hints are stale; 1000 picks reach ~75 of them.
    let mut picks = 0;
    for _ in 0..1000 {
        match mgr.next_addr_to_try(&ng) {
            Some(a) => {
                picks += 1;
                assert!(known.contains(&a.ip()), "dialed evicted DNS address {a}");
            }
            None => break,
        }
    }
    assert!(picks > 0, "no picks made: test is vacuous");
}
