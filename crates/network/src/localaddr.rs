//! Self-address advertisement (Bitcoin Core parity).
//!
//! A listening node must tell the network where it can be reached, or nobody
//! ever dials it: peers only learn addresses from addr/addrv2 gossip, and the
//! only gossip source for OUR address is us. Core does this in three parts,
//! mirrored here (the design follows blockbrew a255986 `localaddr.go`):
//!
//! 1. A table of local addresses (Core `net.cpp` `mapLocalHost` / `AddLocal`
//!    / `SeenLocal`). Entries come from `--externalip` (score
//!    [`LOCAL_MANUAL`]) and from discovery: an outbound peer's VERSION carries
//!    `addr_recv`, the address it sees us at. A discovered entry's score is
//!    the number of DISTINCT peer netgroups that confirmed it, so one peer (or
//!    one /16) cannot talk us into advertising an address; it must be
//!    confirmed by [`MIN_DISCOVERED_LOCAL_SCORE`] groups before it is used,
//!    and it ages out after [`DISCOVERED_LOCAL_ADDR_TTL`] without a fresh
//!    confirmation, so a changed public IP replaces the old one.
//! 2. The per-peer choice of which address to advertise (Core `net.cpp`
//!    `GetLocalAddrForPeer`, 240-268): the best table entry, but if the peer
//!    itself told us a routable address for us, use that instead when the
//!    table has nothing routable, and otherwise sometimes (1/2, or 1/8 when
//!    the best entry scores above `LOCAL_MANUAL`).
//! 3. The send (Core `net_processing.cpp` `MaybeSendAddr`, 5445-5479): only
//!    when listening and out of IBD, one addr/addrv2 carrying just our
//!    address right after the handshake, then again on a Poisson timer
//!    averaging 24h (`AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL`). Never to
//!    block-relay-only or feeler connections (Core: `m_addr_relay_enabled`
//!    is false for them). The send itself lives in `peer_manager.rs`.

use crate::addr::{AddrV2Entry, NetworkAddr};
use crate::message::{NetworkMessage, TimestampedNetAddress};
use crate::peer_manager::socket_addr_to_net_address;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
// tokio Instant to match PeerManager (tokio::time::Instant) callers.
use tokio::time::Instant;

/// Local address scores (Core `net.h` enum `LOCAL_NONE..LOCAL_MANUAL`).
pub const LOCAL_NONE: i32 = 0;
/// Address a local interface listens on.
pub const LOCAL_IF: i32 = 1;
/// Address explicitly bound to.
pub const LOCAL_BIND: i32 = 2;
/// Address reported by PCP/NAT-PMP.
pub const LOCAL_MAPPED: i32 = 3;
/// Address explicitly specified (`--externalip`).
pub const LOCAL_MANUAL: i32 = 4;

/// Mean of the exponential delay between self-announcements to one peer
/// (Core `net_processing.cpp:158`).
pub const AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// A discovered (non-manual) entry not confirmed by any peer for this long is
/// dropped. Outbound churn re-confirms a stable address many times per hour,
/// so this only bites after the public IP changes.
pub const DISCOVERED_LOCAL_ADDR_TTL: Duration = Duration::from_secs(3 * 60 * 60);

/// How many distinct peer netgroups must confirm a discovered address before
/// it is advertised to OTHER peers.
pub const MIN_DISCOVERED_LOCAL_SCORE: usize = 2;

/// Cap on discovered entries so peers cannot grow the table without bound;
/// the weakest entry is evicted.
pub const MAX_DISCOVERED_LOCAL_ADDRS: usize = 8;

/// Cap on the per-entry confirmer set (score ceiling).
const MAX_LOCAL_ADDR_CONFIRMERS: usize = 64;

/// Normalise an IP (IPv4-mapped IPv6 -> IPv4) so table keys and the routable
/// check see one canonical form.
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    ip.to_canonical()
}

/// Publicly routable (Core `CNetAddr::IsRoutable`), reusing the node's
/// netgroup classifier. IPv4-mapped IPv6 is judged as the IPv4 it carries.
pub fn is_routable_ip(ip: &IpAddr) -> bool {
    crate::netgroup::ip_is_routable(&canonical_ip(*ip))
}

/// One row of `getnetworkinfo.localaddresses`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalAddress {
    pub ip: IpAddr,
    pub port: u16,
    pub score: i32,
}

#[derive(Debug, Clone)]
struct Entry {
    port: u16,
    manual: bool,
    /// LOCAL_MANUAL for `--externalip`, else 0.
    base_score: i32,
    /// Distinct peer netgroups that confirmed this address.
    confirmers: HashSet<Vec<u8>>,
    last_seen: Instant,
}

impl Entry {
    fn score(&self) -> i32 {
        self.base_score + self.confirmers.len() as i32
    }

    /// Whether the entry may be advertised to arbitrary peers.
    fn usable(&self) -> bool {
        self.manual || self.confirmers.len() >= MIN_DISCOVERED_LOCAL_SCORE
    }
}

/// The node's set of known local addresses (Core `mapLocalHost`). Keyed by IP
/// only, like Core (`map<CNetAddr, ...>`).
#[derive(Debug, Default)]
pub struct LocalAddrTable {
    entries: HashMap<IpAddr, Entry>,
}

impl LocalAddrTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an operator-specified address (`--externalip`). Returns false
    /// for a non-routable address, which Core's `AddLocal` also refuses.
    pub fn add_manual(&mut self, ip: IpAddr, port: u16, now: Instant) -> bool {
        let ip = canonical_ip(ip);
        if !is_routable_ip(&ip) || port == 0 {
            return false;
        }
        let e = self.entries.entry(ip).or_insert_with(|| Entry {
            port,
            manual: true,
            base_score: LOCAL_MANUAL,
            confirmers: HashSet::new(),
            last_seen: now,
        });
        e.manual = true;
        e.base_score = LOCAL_MANUAL;
        e.port = port;
        true
    }

    /// Record that a peer in netgroup `group` sees us at `ip`. When `create`
    /// is false (inbound peers, Core `SeenLocal`) only an existing entry is
    /// scored; when true (outbound `addr_recv` discovery) a new entry is
    /// created with `port`.
    pub fn confirm(
        &mut self,
        ip: IpAddr,
        port: u16,
        group: Vec<u8>,
        create: bool,
        now: Instant,
    ) -> bool {
        let ip = canonical_ip(ip);
        if !is_routable_ip(&ip) {
            return false;
        }
        self.expire(now);
        if !self.entries.contains_key(&ip) {
            if !create || port == 0 {
                return false;
            }
            self.make_room();
            self.entries.insert(
                ip,
                Entry {
                    port,
                    manual: false,
                    base_score: LOCAL_NONE,
                    confirmers: HashSet::new(),
                    last_seen: now,
                },
            );
        }
        let e = self.entries.get_mut(&ip).expect("present");
        if e.confirmers.len() < MAX_LOCAL_ADDR_CONFIRMERS {
            e.confirmers.insert(group);
        }
        e.last_seen = now;
        true
    }

    fn expire(&mut self, now: Instant) {
        self.entries.retain(|_, e| {
            e.manual || now.saturating_duration_since(e.last_seen) <= DISCOVERED_LOCAL_ADDR_TTL
        });
    }

    /// Evict the weakest (lowest score, then oldest) discovered entry when the
    /// discovered set is full.
    fn make_room(&mut self) {
        let discovered: Vec<(&IpAddr, &Entry)> =
            self.entries.iter().filter(|(_, e)| !e.manual).collect();
        if discovered.len() < MAX_DISCOVERED_LOCAL_ADDRS {
            return;
        }
        let worst = discovered
            .into_iter()
            .min_by(|(_, a), (_, b)| {
                a.score()
                    .cmp(&b.score())
                    .then_with(|| a.last_seen.cmp(&b.last_seen))
            })
            .map(|(k, _)| *k);
        if let Some(k) = worst {
            self.entries.remove(&k);
        }
    }

    /// Best usable local address for a peer at `peer_ip` (Core `GetLocal`):
    /// same address family as the peer first, then the highest score, then
    /// the most recently confirmed.
    pub fn best(&mut self, peer_ip: Option<IpAddr>, now: Instant) -> Option<LocalAddress> {
        self.expire(now);
        let peer_v4 = peer_ip.map(|p| canonical_ip(p).is_ipv4());
        let reach = |ip: &IpAddr| -> u8 {
            match peer_v4 {
                Some(v4) if ip.is_ipv4() == v4 => 1,
                _ => 0,
            }
        };
        self.entries
            .iter()
            .filter(|(_, e)| e.usable())
            .max_by(|(ia, a), (ib, b)| {
                reach(ia)
                    .cmp(&reach(ib))
                    .then_with(|| a.score().cmp(&b.score()))
                    .then_with(|| a.last_seen.cmp(&b.last_seen))
            })
            .map(|(ip, e)| LocalAddress {
                ip: *ip,
                port: e.port,
                score: e.score(),
            })
    }

    /// Every entry, highest score first (getnetworkinfo).
    /// Read-only: expired discovered entries are skipped, not removed.
    pub fn list(&self, now: Instant) -> Vec<LocalAddress> {
        let mut out: Vec<LocalAddress> = self
            .entries
            .iter()
            .filter(|(_, e)| {
                e.manual
                    || now.saturating_duration_since(e.last_seen) <= DISCOVERED_LOCAL_ADDR_TTL
            })
            .map(|(ip, e)| LocalAddress {
                ip: *ip,
                port: e.port,
                score: e.score(),
            })
            .collect();
        out.sort_by(|a, b| {
            b.score
                .cmp(&a.score)
                .then_with(|| a.ip.to_string().cmp(&b.ip.to_string()))
        });
        out
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Pick the address to advertise to one peer (Core `GetLocalAddrForPeer`,
/// net.cpp:240-268).
///
/// * `best` — the table's best usable entry for this peer (may be `None`).
/// * `listen_port` — our P2P listen port (Core `GetListenPort`).
/// * `peer_ip` — the remote peer's IP.
/// * `addr_local` — the peer's VERSION `addr_recv` (how it sees us).
/// * `use_peer_view(bits)` — random draw: returns true with probability
///   `1 / 2^bits` (Core `rng.randbits(bits) == 0`).
pub fn local_addr_for_peer(
    best: Option<&LocalAddress>,
    listen_port: u16,
    peer_ip: IpAddr,
    addr_local: Option<SocketAddr>,
    inbound: bool,
    discover: bool,
    use_peer_view: impl FnOnce(u32) -> bool,
) -> Option<SocketAddr> {
    let (mut ip, mut port) = match best {
        Some(b) => (Some(b.ip), b.port),
        // Core GetLocalAddress with nothing known: unroutable IP, listen port.
        None => (None, listen_port),
    };
    // Core IsPeerAddrLocalGood: fDiscover && peer routable && addrLocal routable.
    let peer_good = discover
        && is_routable_ip(&peer_ip)
        && addr_local.map(|a| is_routable_ip(&a.ip())).unwrap_or(false);
    if peer_good {
        let bits = if best.map(|b| b.score > LOCAL_MANUAL).unwrap_or(false) {
            3
        } else {
            1
        };
        if best.is_none() || use_peer_view(bits) {
            let seen = addr_local.expect("peer_good implies addr_local");
            ip = Some(canonical_ip(seen.ip()));
            if inbound {
                // The peer dialed our listening port, so it saw it too.
                port = seen.port();
            }
            // Outbound: the peer cannot observe our listening port; keep ours.
        }
    }
    match ip {
        Some(ip) if is_routable_ip(&ip) && port != 0 => Some(SocketAddr::new(ip, port)),
        _ => None,
    }
}

/// Draw the Poisson inter-announcement delay (Core `rand_exp_duration`).
pub fn next_local_addr_delay() -> Duration {
    let u: f64 = rand::random::<f64>(); // [0, 1)
    let secs = -(1.0 - u).ln() * AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL.as_secs_f64();
    Duration::from_secs_f64(secs.max(0.0))
}

/// Build the self-announcement: ONE addr (or addrv2, if the peer sent
/// sendaddrv2) carrying just our address, our VERSION services and `time`.
pub fn build_self_announcement(
    addr: SocketAddr,
    services: u64,
    time: u32,
    addrv2: bool,
) -> NetworkMessage {
    let addr = SocketAddr::new(canonical_ip(addr.ip()), addr.port());
    if addrv2 {
        NetworkMessage::AddrV2(vec![AddrV2Entry::new(
            time,
            services,
            NetworkAddr::from_socket_addr(&addr),
            addr.port(),
        )])
    } else {
        NetworkMessage::Addr(vec![TimestampedNetAddress {
            timestamp: time,
            address: socket_addr_to_net_address(addr, services),
        }])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn routable_filter() {
        assert!(is_routable_ip(&ip("1.2.3.4")));
        assert!(is_routable_ip(&ip("2a01:4f8::1")));
        assert!(is_routable_ip(&ip("::ffff:1.2.3.4")));
        for bad in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.1.128",
            "172.16.0.1",
            "100.64.0.1",
            "169.254.1.1",
            "0.0.0.0",
            "::1",
            "::",
            "fe80::1",
            "::ffff:192.168.1.1",
            "::ffff:127.0.0.1",
        ] {
            assert!(!is_routable_ip(&ip(bad)), "{bad} must be unroutable");
        }
        let mut t = LocalAddrTable::new();
        let now = Instant::now();
        assert!(!t.add_manual(ip("192.168.1.128"), 8334, now));
        assert!(!t.confirm(ip("10.0.0.1"), 8334, vec![1], true, now));
        assert!(t.is_empty());
    }

    #[test]
    fn manual_entry_is_usable_with_score_4() {
        let mut t = LocalAddrTable::new();
        let now = Instant::now();
        assert!(t.add_manual(ip("1.2.3.4"), 8334, now));
        let b = t.best(None, now).unwrap();
        assert_eq!(b, LocalAddress { ip: ip("1.2.3.4"), port: 8334, score: LOCAL_MANUAL });
        // Manual entries never expire.
        let later = now + DISCOVERED_LOCAL_ADDR_TTL * 10;
        assert!(t.best(None, later).is_some());
    }

    #[test]
    fn discovery_needs_two_distinct_netgroups() {
        let mut t = LocalAddrTable::new();
        let now = Instant::now();
        assert!(t.confirm(ip("5.6.7.8"), 8334, vec![1, 2], true, now));
        // One confirmer: recorded (score 1) but not advertisable.
        assert_eq!(t.list(now), vec![LocalAddress { ip: ip("5.6.7.8"), port: 8334, score: 1 }]);
        assert!(t.best(None, now).is_none());
        // Same netgroup again: still one confirmer.
        assert!(t.confirm(ip("5.6.7.8"), 8334, vec![1, 2], true, now));
        assert!(t.best(None, now).is_none());
        // Second distinct group: now usable.
        assert!(t.confirm(ip("5.6.7.8"), 8334, vec![9, 9], true, now));
        let b = t.best(None, now).unwrap();
        assert_eq!((b.ip, b.port, b.score), (ip("5.6.7.8"), 8334, 2));
    }

    #[test]
    fn inbound_only_bumps_existing() {
        let mut t = LocalAddrTable::new();
        let now = Instant::now();
        assert!(!t.confirm(ip("5.6.7.8"), 8334, vec![1], false, now));
        assert!(t.is_empty());
        t.confirm(ip("5.6.7.8"), 8334, vec![1], true, now);
        assert!(t.confirm(ip("5.6.7.8"), 9999, vec![2], false, now));
        let l = t.list(now);
        // Port stays the one set at creation (our listen port).
        assert_eq!(l, vec![LocalAddress { ip: ip("5.6.7.8"), port: 8334, score: 2 }]);
    }

    #[test]
    fn discovered_entries_expire() {
        let mut t = LocalAddrTable::new();
        let now = Instant::now();
        t.confirm(ip("5.6.7.8"), 8334, vec![1], true, now);
        t.confirm(ip("5.6.7.8"), 8334, vec![2], true, now);
        assert!(t.best(None, now + DISCOVERED_LOCAL_ADDR_TTL).is_some());
        let later = now + DISCOVERED_LOCAL_ADDR_TTL + Duration::from_secs(1);
        assert!(t.best(None, later).is_none());
        assert!(t.is_empty());
    }

    #[test]
    fn discovered_entries_are_capped() {
        let mut t = LocalAddrTable::new();
        let now = Instant::now();
        t.add_manual(ip("1.2.3.4"), 8334, now);
        for i in 0..(MAX_DISCOVERED_LOCAL_ADDRS as u8 + 5) {
            let a = IpAddr::from([5, 6, 7, i + 1]);
            t.confirm(a, 8334, vec![i], true, now + Duration::from_secs(i as u64));
        }
        assert_eq!(t.len(), MAX_DISCOVERED_LOCAL_ADDRS + 1);
        // The manual entry survives eviction.
        assert!(t.list(now).iter().any(|e| e.ip == ip("1.2.3.4")));
    }

    #[test]
    fn best_prefers_same_family_then_score() {
        let mut t = LocalAddrTable::new();
        let now = Instant::now();
        t.add_manual(ip("1.2.3.4"), 8334, now);
        t.add_manual(ip("2a01:4f8::1"), 8334, now);
        assert_eq!(t.best(Some(ip("8.8.8.8")), now).unwrap().ip, ip("1.2.3.4"));
        assert_eq!(t.best(Some(ip("2001:4860::8888")), now).unwrap().ip, ip("2a01:4f8::1"));
    }

    #[test]
    fn peer_choice_follows_get_local_addr_for_peer() {
        let manual = LocalAddress { ip: ip("1.2.3.4"), port: 8334, score: LOCAL_MANUAL };
        let peer = ip("8.8.8.8");
        let seen: SocketAddr = "5.6.7.8:51234".parse().unwrap();
        // Table entry, coin says keep it.
        assert_eq!(
            local_addr_for_peer(Some(&manual), 8334, peer, Some(seen), false, true, |_| false),
            Some("1.2.3.4:8334".parse().unwrap())
        );
        // Coin says use the peer's view: outbound keeps OUR port.
        assert_eq!(
            local_addr_for_peer(Some(&manual), 8334, peer, Some(seen), false, true, |b| {
                assert_eq!(b, 1);
                true
            }),
            Some("5.6.7.8:8334".parse().unwrap())
        );
        // Inbound: the peer's view, including the port it dialed.
        assert_eq!(
            local_addr_for_peer(Some(&manual), 8334, peer, Some(seen), true, true, |_| true),
            Some("5.6.7.8:51234".parse().unwrap())
        );
        // Nothing in the table: peer view always used, with the listen port.
        assert_eq!(
            local_addr_for_peer(None, 8334, peer, Some(seen), false, true, |_| panic!("no draw")),
            Some("5.6.7.8:8334".parse().unwrap())
        );
        // Nothing in the table, discovery off: nothing to advertise.
        assert_eq!(local_addr_for_peer(None, 8334, peer, Some(seen), false, false, |_| true), None);
        // Loopback peer (regtest): peer view not trusted, table entry used.
        assert_eq!(
            local_addr_for_peer(
                Some(&manual),
                18444,
                ip("127.0.0.1"),
                Some("127.0.0.1:40000".parse().unwrap()),
                false,
                true,
                |_| true
            ),
            Some("1.2.3.4:8334".parse().unwrap())
        );
        // Score above LOCAL_MANUAL -> 3 random bits (1/8).
        let strong = LocalAddress { score: LOCAL_MANUAL + 2, ..manual };
        local_addr_for_peer(Some(&strong), 8334, peer, Some(seen), false, true, |b| {
            assert_eq!(b, 3);
            false
        });
    }

    #[test]
    fn announcement_contents_addr_v1_and_v2() {
        let a: SocketAddr = "1.2.3.4:39777".parse().unwrap();
        match build_self_announcement(a, 0xC09, 1_700_000_000, false) {
            NetworkMessage::Addr(v) => {
                assert_eq!(v.len(), 1);
                assert_eq!(v[0].timestamp, 1_700_000_000);
                assert_eq!(v[0].address.services, 0xC09);
                assert_eq!(v[0].address.port, 39777);
                assert_eq!(
                    v[0].address.ip,
                    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4]
                );
                // Round-trips through the wire codec.
                let msg = NetworkMessage::Addr(v);
                let back = NetworkMessage::deserialize("addr", &msg.serialize_payload()).unwrap();
                assert!(matches!(back, NetworkMessage::Addr(ref x) if x.len() == 1 && x[0].address.port == 39777));
            }
            other => panic!("expected addr, got {:?}", other),
        }
        match build_self_announcement(a, 0xC09, 1_700_000_000, true) {
            NetworkMessage::AddrV2(v) => {
                assert_eq!(v.len(), 1);
                assert_eq!(v[0].timestamp, 1_700_000_000);
                assert_eq!(v[0].services, 0xC09);
                assert_eq!(v[0].port, 39777);
                assert_eq!(v[0].addr, NetworkAddr::Ipv4("1.2.3.4".parse().unwrap()));
            }
            other => panic!("expected addrv2, got {:?}", other),
        }
    }

    #[test]
    fn poisson_delay_is_sane() {
        let n = 2000;
        let total: f64 = (0..n).map(|_| next_local_addr_delay().as_secs_f64()).sum();
        let mean_h = total / n as f64 / 3600.0;
        assert!((16.0..32.0).contains(&mean_h), "mean {mean_h}h");
    }
}
