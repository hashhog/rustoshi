//! cfaudit 2026-11-09 (cffix-rustoshi-addr-relay-own-history): every addr or
//! addrv2 message at or under MAX_ADDR -- empty ones included -- made the
//! node send `get_addresses_for_sharing(10)` to two random peers. That list
//! is the node's own `last_success` connection history, outbound peers
//! included, so an attacker holding two connections could learn the node's
//! outbound topology by sending empty `addr` messages from one and reading
//! the other.
//!
//! Core relays only addresses taken from the received message
//! (`PeerManagerImpl::ProcessAddrs`, net_processing.cpp:5625, ->
//! `RelayAddress` :2277), and only when the message holds at most 10
//! entries, the entry passed the token bucket and the service check, is
//! routable, and its timestamp is within the last 10 minutes.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use rustoshi_consensus::params::ChainParams;
use rustoshi_network::{
    AddrV2Entry, NetAddress, NetworkAddr, NetworkMessage, PeerCommand, PeerEvent, PeerId,
    PeerManager, PeerManagerConfig, TimestampedNetAddress, NODE_NETWORK, NODE_WITNESS,
};
use tokio::sync::mpsc::Receiver;

const A: PeerId = PeerId(1);
const B: PeerId = PeerId(2);
const C: PeerId = PeerId(3);

fn now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}

/// The node's own outbound peer, recorded in its connection history.
fn outbound_o() -> SocketAddr {
    "9.9.9.9:8333".parse().unwrap()
}

struct Rig {
    mgr: PeerManager,
    rx_b: Receiver<PeerCommand>,
    rx_c: Receiver<PeerCommand>,
    _rx_a: Receiver<PeerCommand>,
}

/// Three established peers A, B, C and an outbound address O marked as a
/// successful outbound connection (so it is in `get_addresses_for_sharing`).
fn rig() -> Rig {
    let mut mgr = PeerManager::new(PeerManagerConfig::default(), ChainParams::regtest());
    let o = outbound_o();
    mgr.add_address_entry(o, NODE_NETWORK | NODE_WITNESS, now() as u64);
    let ng = mgr.netgroup_manager().clone();
    mgr.addr_manager_mut().mark_outbound_success(&o, &ng);
    assert!(
        mgr.addr_manager()
            .get_addresses_for_sharing(10)
            .iter()
            .any(|i| i.addr == o),
        "rig: O must be in the node's shareable history"
    );
    let _rx_a = mgr.insert_observable_peer(A, "1.1.1.1:8333".parse().unwrap());
    let rx_b = mgr.insert_observable_peer(B, "2.2.2.2:8333".parse().unwrap());
    let rx_c = mgr.insert_observable_peer(C, "3.3.3.3:8333".parse().unwrap());
    Rig {
        mgr,
        rx_b,
        rx_c,
        _rx_a,
    }
}

/// Every address relayed to this peer (addr and addrv2), drained.
fn relayed(rx: &mut Receiver<PeerCommand>) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    while let Ok(cmd) = rx.try_recv() {
        match cmd {
            PeerCommand::SendMessage(NetworkMessage::Addr(v)) => {
                for t in v {
                    out.push(net_to_socket(&t.address));
                }
            }
            PeerCommand::SendMessage(NetworkMessage::AddrV2(v)) => {
                for e in v {
                    if let Some(s) = e.to_socket_addr() {
                        out.push(s);
                    }
                }
            }
            _ => {}
        }
    }
    out
}

fn net_to_socket(a: &NetAddress) -> SocketAddr {
    let ip = if a.ip[..10] == [0u8; 10] && a.ip[10] == 0xff && a.ip[11] == 0xff {
        IpAddr::V4(Ipv4Addr::new(a.ip[12], a.ip[13], a.ip[14], a.ip[15]))
    } else {
        IpAddr::V6(a.ip.into())
    };
    SocketAddr::new(ip, a.port)
}

fn ts_addr(addr: SocketAddr, ts: u32, services: u64) -> TimestampedNetAddress {
    let ip = match addr.ip() {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    };
    TimestampedNetAddress {
        timestamp: ts,
        address: NetAddress {
            services,
            ip,
            port: addr.port(),
        },
    }
}

async fn deliver(r: &mut Rig, msg: NetworkMessage) {
    r.mgr.handle_event(PeerEvent::Message(A, msg)).await;
}

/// The finding: an empty `addr` from A must not leak O to B or C.
#[tokio::test]
async fn empty_addr_relays_nothing() {
    let mut r = rig();
    deliver(&mut r, NetworkMessage::Addr(vec![])).await;
    let o = outbound_o();
    let b = relayed(&mut r.rx_b);
    let c = relayed(&mut r.rx_c);
    assert!(
        !b.contains(&o) && !c.contains(&o),
        "empty addr from A leaked the node's outbound peer O: B got {b:?}, C got {c:?}"
    );
    assert!(
        b.is_empty() && c.is_empty(),
        "empty addr relayed {b:?} / {c:?}"
    );
}

/// Same leak through the BIP155 path.
#[tokio::test]
async fn empty_addrv2_relays_nothing() {
    let mut r = rig();
    deliver(&mut r, NetworkMessage::AddrV2(vec![])).await;
    let b = relayed(&mut r.rx_b);
    let c = relayed(&mut r.rx_c);
    assert!(
        b.is_empty() && c.is_empty(),
        "empty addrv2 relayed {b:?} / {c:?}"
    );
}

/// Control: a fresh, routable, full-node address from A is relayed (to both
/// other peers, as Core relays a reachable address to 2), and only it.
#[tokio::test]
async fn fresh_received_addr_is_relayed_alone() {
    let mut r = rig();
    let x: SocketAddr = "5.6.7.8:8333".parse().unwrap();
    deliver(
        &mut r,
        NetworkMessage::Addr(vec![ts_addr(x, now(), NODE_NETWORK | NODE_WITNESS)]),
    )
    .await;
    let b = relayed(&mut r.rx_b);
    let c = relayed(&mut r.rx_c);
    assert_eq!(b, vec![x], "B must receive exactly the announced address");
    assert_eq!(c, vec![x], "C must receive exactly the announced address");
}

/// Control through addrv2.
#[tokio::test]
async fn fresh_received_addrv2_is_relayed_alone() {
    let mut r = rig();
    let x: SocketAddr = "5.6.7.9:8333".parse().unwrap();
    let e = AddrV2Entry::new(
        now(),
        NODE_NETWORK | NODE_WITNESS,
        NetworkAddr::Ipv4(Ipv4Addr::new(5, 6, 7, 9)),
        8333,
    );
    deliver(&mut r, NetworkMessage::AddrV2(vec![e])).await;
    assert_eq!(relayed(&mut r.rx_b), vec![x]);
    assert_eq!(relayed(&mut r.rx_c), vec![x]);
}

/// Core: `addr.nTime > current_time - 10min`. A stale address is stored, not
/// relayed.
#[tokio::test]
async fn stale_addr_is_not_relayed() {
    let mut r = rig();
    let x: SocketAddr = "5.6.7.10:8333".parse().unwrap();
    deliver(
        &mut r,
        NetworkMessage::Addr(vec![ts_addr(x, now() - 3600, NODE_NETWORK | NODE_WITNESS)]),
    )
    .await;
    assert!(relayed(&mut r.rx_b).is_empty());
    assert!(relayed(&mut r.rx_c).is_empty());
}

/// Core: `vAddr.size() <= 10` -- a larger message (a getaddr-style response)
/// is never relayed, even the entries the token bucket admitted.
#[tokio::test]
async fn large_addr_message_is_not_relayed() {
    let mut r = rig();
    let msg: Vec<_> = (1..=11u8)
        .map(|i| {
            ts_addr(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(5, 6, 8, i)), 8333),
                now(),
                NODE_NETWORK | NODE_WITNESS,
            )
        })
        .collect();
    deliver(&mut r, NetworkMessage::Addr(msg)).await;
    assert!(relayed(&mut r.rx_b).is_empty());
    assert!(relayed(&mut r.rx_c).is_empty());
}

/// Core: `addr.IsRoutable()` gates relay.
#[tokio::test]
async fn unroutable_addr_is_not_relayed() {
    let mut r = rig();
    let x: SocketAddr = "10.0.0.5:8333".parse().unwrap();
    deliver(
        &mut r,
        NetworkMessage::Addr(vec![ts_addr(x, now(), NODE_NETWORK | NODE_WITNESS)]),
    )
    .await;
    assert!(relayed(&mut r.rx_b).is_empty());
    assert!(relayed(&mut r.rx_c).is_empty());
}

/// Core: an address with neither NODE_NETWORK nor NODE_NETWORK_LIMITED is
/// skipped (`!MayHaveUsefulAddressDB && !HasAllDesirableServiceFlags`).
#[tokio::test]
async fn non_full_node_addr_is_not_relayed() {
    let mut r = rig();
    let x: SocketAddr = "5.6.7.11:8333".parse().unwrap();
    deliver(
        &mut r,
        NetworkMessage::Addr(vec![ts_addr(x, now(), NODE_WITNESS)]),
    )
    .await;
    assert!(relayed(&mut r.rx_b).is_empty());
    assert!(relayed(&mut r.rx_c).is_empty());
}

/// Core: the token bucket runs before relay. A fresh peer has 1 token, so
/// of two fresh addresses only one may be relayed.
#[tokio::test]
async fn rate_limited_addrs_are_not_relayed() {
    let mut r = rig();
    let x: SocketAddr = "5.6.7.12:8333".parse().unwrap();
    let y: SocketAddr = "5.6.7.13:8333".parse().unwrap();
    deliver(
        &mut r,
        NetworkMessage::Addr(vec![
            ts_addr(x, now(), NODE_NETWORK | NODE_WITNESS),
            ts_addr(y, now(), NODE_NETWORK | NODE_WITNESS),
        ]),
    )
    .await;
    let b = relayed(&mut r.rx_b);
    assert_eq!(
        b.len(),
        1,
        "only the admitted address may be relayed, got {b:?}"
    );
    assert!(b[0] == x || b[0] == y);
}
