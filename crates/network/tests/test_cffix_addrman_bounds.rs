//! cfaudit 2026-11-09 (cffix-rustoshi-addrman-flat-stores-unbounded):
//! `AddressManager`'s flat `known_addrs`, `known_addrv2` and `try_queue` had
//! no cap and no removal, and `try_queue` took a duplicate push for every
//! re-announcement of an address it already held. Any peer could grow them
//! without limit with addr/addrv2 messages (TorV3/I2P/CJDNS entries need no
//! routability, so 2^256 distinct keys are free). Core keeps every address in
//! the fixed new/tried table (`AddrManImpl::Add_`, src/addrman.cpp), so its
//! address book can never hold more than ADDRMAN_CEILING entries.

use rustoshi_network::{
    socket_addr_to_net_address, AddrV2Entry, AddressManager, NetworkAddr, TimestampedNetAddress,
    ADDRMAN_CEILING,
};
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

fn now_u32() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}

fn torv3(i: u64) -> AddrV2Entry {
    let mut key = [0u8; 32];
    key[..8].copy_from_slice(&i.to_le_bytes());
    AddrV2Entry {
        timestamp: now_u32(),
        services: 1,
        addr: NetworkAddr::TorV3(key),
        port: 8333,
    }
}

#[test]
fn flat_addr_stores_are_bounded() {
    let mut mgr = AddressManager::new();
    let from: SocketAddr = "1.2.3.4:8333".parse().unwrap();

    // 2 x ADDRMAN_CEILING distinct TorV3 entries, in addrv2-sized batches.
    let total = 2 * ADDRMAN_CEILING as u64;
    let mut i = 0u64;
    while i < total {
        let batch: Vec<AddrV2Entry> = (i..(i + 1000).min(total)).map(torv3).collect();
        mgr.add_addrv2_addresses(&batch, from);
        i += 1000;
    }
    assert!(
        mgr.known_addrv2_count() <= ADDRMAN_CEILING,
        "known_addrv2 grew to {} (> ADDRMAN_CEILING {})",
        mgr.known_addrv2_count(),
        ADDRMAN_CEILING
    );

    // The same IPv4 announced twice must not be queued more than once. Since
    // rustoshi#71 gossiped addresses take no `try_queue` hint at all (outbound
    // slots come from the bucketed addrman), so "at most once" is exactly 0.
    let mut mgr = AddressManager::new();
    let a: SocketAddr = "8.8.8.8:8333".parse().unwrap();
    let ta = TimestampedNetAddress {
        timestamp: now_u32(),
        address: socket_addr_to_net_address(a, 1),
    };
    mgr.add_peer_addresses(&[ta.clone()], from);
    mgr.add_peer_addresses(&[ta], from);
    assert_eq!(mgr.queue_size(), 0, "gossiped addr announce was queued");

    // Same through addrv2.
    let mut mgr = AddressManager::new();
    let e = AddrV2Entry {
        timestamp: now_u32(),
        services: 1,
        addr: NetworkAddr::Ipv4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
        port: 8333,
    };
    mgr.add_addrv2_addresses(&[e.clone()], from);
    mgr.add_addrv2_addresses(&[e], from);
    assert_eq!(mgr.queue_size(), 0, "gossiped addrv2 announce was queued");
}

#[test]
fn legacy_known_addrs_is_bounded() {
    let mut mgr = AddressManager::new();
    let from: SocketAddr = "1.2.3.4:8333".parse().unwrap();
    let total = 2 * ADDRMAN_CEILING as u32;
    let ts = now_u32();
    let mut batch = Vec::with_capacity(1000);
    for n in 0..total {
        // Routable unicast 11.x.y.z / 12.x.y.z space, all distinct.
        let ip = 0x0B00_0000u32 + n;
        let a = SocketAddr::from((ip.to_be_bytes(), 8333));
        batch.push(TimestampedNetAddress {
            timestamp: ts,
            address: socket_addr_to_net_address(a, 1),
        });
        if batch.len() == 1000 {
            mgr.add_peer_addresses(&batch, from);
            batch.clear();
        }
    }
    mgr.add_peer_addresses(&batch, from);
    assert!(
        mgr.known_count() <= ADDRMAN_CEILING,
        "known_addrs grew to {} (> ADDRMAN_CEILING {})",
        mgr.known_count(),
        ADDRMAN_CEILING
    );
    assert!(
        mgr.queue_size() <= ADDRMAN_CEILING,
        "try_queue grew to {} (> ADDRMAN_CEILING {})",
        mgr.queue_size(),
        ADDRMAN_CEILING
    );
}

/// The duplicate-push half of `flat_addr_stores_are_bounded` on its own, so
/// it is seen failing on the base commit even though the size assertion
/// above stops that test first there.
#[test]
fn try_queue_is_deduplicated() {
    let mut mgr = AddressManager::new();
    let from: SocketAddr = "1.2.3.4:8333".parse().unwrap();
    let a: SocketAddr = "8.8.4.4:8333".parse().unwrap();
    let ta = TimestampedNetAddress {
        timestamp: now_u32(),
        address: socket_addr_to_net_address(a, 1),
    };
    for _ in 0..5 {
        mgr.add_peer_addresses(&[ta.clone()], from);
    }
    let e = AddrV2Entry {
        timestamp: now_u32(),
        services: 1,
        addr: NetworkAddr::Ipv4(std::net::Ipv4Addr::new(8, 8, 4, 4)),
        port: 8333,
    };
    mgr.add_addrv2_addresses(&[e.clone(), e], from);
    // rustoshi#71: gossip never queues, so five announcements leave nothing.
    assert_eq!(mgr.queue_size(), 0, "gossiped address was queued");
    // The operator path still queues, and a re-add moves the entry rather
    // than duplicating it.
    mgr.add_manual_address(a);
    assert_eq!(mgr.queue_size(), 1, "manual add did not queue the address");
    mgr.add_manual_address(a);
    assert_eq!(
        mgr.queue_size(),
        1,
        "manual re-add duplicated the queue entry"
    );
}

/// An address evicted from the full store after it was queued must not be
/// dialed from its stale queue hint.
#[test]
fn evicted_addresses_are_not_dialed() {
    let mut mgr = AddressManager::new();
    let ng = rustoshi_network::NetGroupManager::with_key(12345);
    let from: SocketAddr = "1.2.3.4:8333".parse().unwrap();
    let ts = now_u32();
    let total = ADDRMAN_CEILING as u32 + 5000;
    let mut batch = Vec::with_capacity(1000);
    for n in 0..total {
        let a = SocketAddr::from(((0x0B00_0000u32 + n).to_be_bytes(), 8333));
        batch.push(TimestampedNetAddress {
            timestamp: ts,
            address: socket_addr_to_net_address(a, 1),
        });
        if batch.len() == 1000 {
            mgr.add_peer_addresses(&batch, from);
            batch.clear();
        }
    }
    mgr.add_peer_addresses(&batch, from);
    let known: std::collections::HashSet<_> = mgr.all_known_ips().into_iter().collect();
    // Drain the whole hint queue; every address handed out must still be known.
    while mgr.queue_size() > 0 {
        match mgr.next_addr_to_try(&ng) {
            Some(a) => assert!(known.contains(&a.ip()), "dialed evicted address {a}"),
            None => break,
        }
    }
}
