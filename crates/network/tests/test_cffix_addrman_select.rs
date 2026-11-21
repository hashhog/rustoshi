//! cffix-rustoshi-addrman-outbound-select: full-relay and block-relay-only
//! outbound slots must be filled from the bucketed addrman, like Core.
//!
//! Core `CConnman::ThreadOpenConnections` (src/net.cpp, the non-feeler branch)
//! picks every automatic outbound peer with `addrman.Select(false, ...)`, a
//! random draw over the NEW/TRIED bucket tables. A single announcing source
//! can only reach `ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP` (64) of the 1024 NEW
//! buckets, so it cannot decide on its own which peers get dialled.
//!
//! Before this fix `AddressManager::next_addr_to_try` never read the bucketed
//! table: it popped the peer-fed `try_queue` FIFO and then fell back to the
//! flat `known_addrs` map, preferring never-tried entries. Whoever announced
//! addresses last chose all eight outbound peers, and addresses that only
//! lived in the bucketed table (everything loaded from peers.dat at startup)
//! were never dialled at all.

use rustoshi_network::message::{NetAddress, TimestampedNetAddress, NODE_NETWORK, NODE_WITNESS};
use rustoshi_network::netgroup::NetGroupManager;
use rustoshi_network::peer_manager::{AddrManTable, AddressManager};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

const SERVICES: u64 = NODE_NETWORK | NODE_WITNESS;
const TRIALS: usize = 32;
const PICKS_PER_TRIAL: usize = 8;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// 8 honest addresses, each in its own /16 (20.10/16 .. 27.10/16).
fn honest_addrs() -> Vec<SocketAddr> {
    (0..8u8)
        .map(|i| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(20 + i, 10, 0, 1)), 8333))
        .collect()
}

/// 8 attacker addresses, each in its own /16 (60.77/16 .. 67.77/16), all
/// announced by one source.
fn attacker_addrs() -> Vec<SocketAddr> {
    (0..8u8)
        .map(|i| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(60 + i, 77, 0, 1)), 8333))
        .collect()
}

fn attacker_source() -> SocketAddr {
    "45.33.1.1:8333".parse().unwrap()
}

/// Build an address manager the way a restarted node has one: the honest
/// DNS-learned addresses sit in peers.dat (self-sourced, as DNS seeds are),
/// each attempted once an hour ago without an answer. Then one attacker peer
/// announces its 8 addresses.
fn restarted_manager(dir: &std::path::Path, ng: &NetGroupManager) -> AddressManager {
    let now = now_unix();
    let mut table = AddrManTable::new();
    for a in honest_addrs() {
        // Two honest addresses can (rarely) hash to the same NEW slot under a
        // random nkey; the loser is simply not held, as in Core.
        table.add(a, a.ip(), SERVICES, now, ng);
        table.attempt(&a, now - 3600);
    }
    let held = table.total_count();
    assert!(held >= 6, "honest fixture: only {held} of 8 placed");
    table.save(dir);

    let mut mgr = AddressManager::with_persisted(dir, ng);
    assert_eq!(
        mgr.addrman().total_count(),
        held,
        "peers.dat round-trip must restore the honest addresses"
    );

    let announced: Vec<TimestampedNetAddress> = attacker_addrs()
        .iter()
        .map(|a| {
            let IpAddr::V4(v4) = a.ip() else { unreachable!() };
            TimestampedNetAddress {
                timestamp: now as u32,
                address: NetAddress::from_ipv4(v4.octets(), a.port(), SERVICES),
            }
        })
        .collect();
    mgr.add_peer_addresses(&announced, attacker_source());
    mgr
}

#[test]
fn outbound_selection_uses_bucketed_addrman() {
    let ng = NetGroupManager::with_key(0x5eed_cafe);
    let honest: HashSet<SocketAddr> = honest_addrs().into_iter().collect();
    let attacker: HashSet<SocketAddr> = attacker_addrs().into_iter().collect();

    let mut honest_picks = 0usize;
    let mut attacker_picks = 0usize;
    let mut total_picks = 0usize;
    let mut not_in_table: Vec<SocketAddr> = Vec::new();

    for trial in 0..TRIALS {
        let dir = tempfile::tempdir().unwrap();
        // Each trial gets a fresh random nkey, so bucket placement varies.
        let mut mgr = restarted_manager(dir.path(), &ng);
        for pick in 0..PICKS_PER_TRIAL {
            let addr = mgr
                .next_addr_to_try(&ng)
                .unwrap_or_else(|| panic!("trial {trial} pick {pick}: no outbound candidate"));
            // Core only ever dials what addrman.Select returned, so every pick
            // must be an address the bucketed addrman holds.
            if mgr.addrman().new_slot_of(&addr, &ng).is_none()
                && mgr.addrman().tried_slot_of(&addr, &ng).is_none()
            {
                not_in_table.push(addr);
            }
            if honest.contains(&addr) {
                honest_picks += 1;
            } else if attacker.contains(&addr) {
                attacker_picks += 1;
            } else {
                panic!("trial {trial} pick {pick}: unexpected address {addr}");
            }
            total_picks += 1;
            // Fill the slot: the connection succeeds, so the next pick must
            // come from a different netgroup.
            mgr.mark_outbound_success(&addr, &ng);
        }
    }

    // Master dials the attacker for all 256 slots and never an honest peer.
    // A random draw over the buckets gives each side about half; the bound
    // below sits many standard deviations away from both outcomes.
    assert!(
        honest_picks * 4 >= total_picks,
        "outbound selection is not drawing from the bucketed addrman: \
         {attacker_picks} of {total_picks} slots went to the one attacker source, \
         only {honest_picks} to the honest peers.dat addresses"
    );
    assert!(
        not_in_table.is_empty(),
        "{} outbound picks were addresses the bucketed addrman does not hold: {:?}",
        not_in_table.len(),
        not_in_table
    );
}
