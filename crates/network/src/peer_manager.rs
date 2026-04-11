//! Peer manager for maintaining Bitcoin P2P connections.
//!
//! This module implements:
//! - Connection pool management (target 8 outbound + 2 block-relay-only, up to 117 inbound)
//! - DNS seed resolution for initial peer discovery
//! - Address manager for tracking known peers
//! - Peer quality tracking (ban scores, response times, attempt counts)
//! - Misbehavior scoring and ban management
//! - Eclipse attack protections:
//!   - Network group diversity (no two outbound connections in same /16 or /32)
//!   - Anchor connections (persist 2 block-relay-only peers across restarts)
//!   - Inbound eviction protection (protect diverse, high-quality peers)
//!
//! The peer manager coordinates outbound connection attempts, accepts inbound
//! connections, and routes messages between peers and the node's message handler.

use crate::eviction::{select_node_to_evict, EvictionCandidate, EvictionCandidateBuilder};
use crate::message::{
    parse_message_header, serialize_message, NetAddress, NetworkMessage,
    TimestampedNetAddress, VersionMessage, MAX_ADDR, MAX_MESSAGE_SIZE, MESSAGE_HEADER_SIZE,
    MIN_WITNESS_PROTO_VERSION, NODE_NETWORK, NODE_WITNESS, PROTOCOL_VERSION, SENDHEADERS_VERSION,
};
use crate::misbehavior::{BanEntry, BanManager, MisbehaviorReason, MisbehaviorTracker};
use crate::netgroup::{NetGroup, NetGroupManager};
use crate::peer::{
    run_outbound_peer, DisconnectReason, PeerCommand, PeerEvent, PeerId,
    PeerInfo, PeerState,
};
use crate::stale_detection::{
    StalePeerDetector, StalePeerState, EXTRA_PEER_CHECK_INTERVAL, MINIMUM_CONNECT_TIME,
};
use rustoshi_consensus::{ChainParams, NetworkId};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{Read as IoRead, Write as IoWrite};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant};

/// Maximum number of block-relay-only anchor connections to persist.
pub const MAX_BLOCK_RELAY_ONLY_ANCHORS: usize = 2;

/// Filename for anchor peer persistence.
pub const ANCHORS_DATABASE_FILENAME: &str = "anchors.dat";

/// Configuration for the peer manager.
#[derive(Clone, Debug)]
pub struct PeerManagerConfig {
    /// Target number of full-relay outbound connections (default: 8).
    pub max_outbound_full_relay: usize,
    /// Target number of block-relay-only outbound connections (default: 2).
    pub max_outbound_block_relay: usize,
    /// Maximum inbound connections (default: 117).
    pub max_inbound: usize,
    /// Maximum total connections (default: 125).
    pub max_total: usize,
    /// How long to ban misbehaving peers (default: 24h).
    pub ban_duration: Duration,
    /// Port to listen on for inbound connections.
    pub listen_port: u16,
    /// Whether to accept inbound connections.
    pub listen: bool,
    /// Data directory for persistent state (banlist, anchors.dat, etc.).
    pub data_dir: PathBuf,
}

impl PeerManagerConfig {
    /// Total maximum outbound connections.
    pub fn max_outbound(&self) -> usize {
        self.max_outbound_full_relay + self.max_outbound_block_relay
    }
}

impl Default for PeerManagerConfig {
    fn default() -> Self {
        Self {
            max_outbound_full_relay: 8,
            max_outbound_block_relay: 2,
            max_inbound: 117,
            max_total: 125,
            ban_duration: Duration::from_secs(24 * 60 * 60),
            listen_port: 8333,
            listen: true,
            data_dir: PathBuf::from("."),
        }
    }
}

impl PeerManagerConfig {
    /// Create a config for testnet4.
    pub fn testnet4() -> Self {
        Self {
            listen_port: 48333,
            ..Default::default()
        }
    }

    /// Set the data directory.
    pub fn with_data_dir(mut self, data_dir: PathBuf) -> Self {
        self.data_dir = data_dir;
        self
    }
}

// ============================================================
// ADDRESS MANAGER
// ============================================================

/// Source of a peer address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddrSource {
    /// From DNS seed resolution.
    Dns,
    /// From an addr message from another peer.
    Peer(SocketAddr),
    /// Manually added (e.g., command line).
    Manual,
}

/// Metadata about a known peer address.
#[derive(Debug, Clone)]
pub struct AddrInfo {
    /// The socket address.
    pub addr: SocketAddr,
    /// Services advertised by this peer.
    pub services: u64,
    /// When this address was last seen (from addr message or connection).
    pub last_seen: Instant,
    /// When we last attempted to connect.
    pub last_attempt: Option<Instant>,
    /// When we last successfully connected.
    pub last_success: Option<Instant>,
    /// Number of connection attempts.
    pub attempt_count: u32,
    /// Where we learned about this address.
    pub source: AddrSource,
}

/// Unique identifier for a BIP155 address (used as hash map key).
///
/// This allows storing addresses that don't map to SocketAddr
/// (TorV3, I2P, CJDNS).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AddrV2Key {
    /// The network address.
    pub addr: crate::addr::NetworkAddr,
    /// Port number.
    pub port: u16,
}

impl AddrV2Key {
    /// Create from a NetworkAddr and port.
    pub fn new(addr: crate::addr::NetworkAddr, port: u16) -> Self {
        Self { addr, port }
    }

    /// Try to convert to SocketAddr (IPv4/IPv6 only).
    pub fn to_socket_addr(&self) -> Option<SocketAddr> {
        self.addr.to_socket_addr(self.port)
    }
}

/// Metadata about a known BIP155 address (supports all network types).
#[derive(Debug, Clone)]
pub struct AddrV2Info {
    /// The network address.
    pub addr: crate::addr::NetworkAddr,
    /// Port number.
    pub port: u16,
    /// Services advertised by this peer.
    pub services: u64,
    /// Unix timestamp when this address was last seen.
    pub timestamp: u32,
    /// When this address was last seen locally.
    pub last_seen: Instant,
    /// When we last attempted to connect.
    pub last_attempt: Option<Instant>,
    /// When we last successfully connected.
    pub last_success: Option<Instant>,
    /// Number of connection attempts.
    pub attempt_count: u32,
    /// Where we learned about this address.
    pub source: AddrSource,
}

impl AddrV2Info {
    /// Get the unique key for this address.
    pub fn key(&self) -> AddrV2Key {
        AddrV2Key {
            addr: self.addr.clone(),
            port: self.port,
        }
    }

    /// Try to convert to SocketAddr (IPv4/IPv6 only).
    pub fn to_socket_addr(&self) -> Option<SocketAddr> {
        self.addr.to_socket_addr(self.port)
    }

    /// Check if this is a privacy network address (Tor, I2P, CJDNS).
    pub fn is_privacy_network(&self) -> bool {
        matches!(
            self.addr,
            crate::addr::NetworkAddr::TorV3(_)
                | crate::addr::NetworkAddr::I2P(_)
                | crate::addr::NetworkAddr::Cjdns(_)
        )
    }

    /// Convert to an AddrV2Entry for sending.
    pub fn to_addrv2_entry(&self) -> crate::addr::AddrV2Entry {
        crate::addr::AddrV2Entry {
            timestamp: self.timestamp,
            services: self.services,
            addr: self.addr.clone(),
            port: self.port,
        }
    }
}

/// Address manager: tracks known peer addresses with metadata.
///
/// Supports both legacy SocketAddr-based addresses (IPv4/IPv6) and
/// BIP155 addresses (Tor v3, I2P, CJDNS).
#[derive(Debug)]
pub struct AddressManager {
    /// Known addresses with metadata (legacy format for IPv4/IPv6).
    known_addrs: HashMap<SocketAddr, AddrInfo>,
    /// BIP155 addresses (supports all network types including privacy networks).
    known_addrv2: HashMap<AddrV2Key, AddrV2Info>,
    /// Addresses to try next (prioritized queue).
    try_queue: VecDeque<SocketAddr>,
    /// Banned addresses with unban time.
    banned: HashMap<SocketAddr, Instant>,
    /// Currently connected addresses (to avoid duplicates).
    connected: HashSet<SocketAddr>,
    /// Network groups of currently connected outbound peers (for diversity).
    connected_outbound_netgroups: HashSet<Vec<u8>>,
}

impl AddressManager {
    /// Create a new empty address manager.
    pub fn new() -> Self {
        Self {
            known_addrs: HashMap::new(),
            known_addrv2: HashMap::new(),
            try_queue: VecDeque::new(),
            banned: HashMap::new(),
            connected: HashSet::new(),
            connected_outbound_netgroups: HashSet::new(),
        }
    }

    /// Add addresses discovered from DNS seeds.
    pub fn add_dns_addresses(&mut self, addrs: Vec<SocketAddr>) {
        for addr in addrs {
            if !self.known_addrs.contains_key(&addr) && !self.is_banned(&addr) {
                self.known_addrs.insert(
                    addr,
                    AddrInfo {
                        addr,
                        services: NODE_NETWORK | NODE_WITNESS,
                        last_seen: Instant::now(),
                        last_attempt: None,
                        last_success: None,
                        attempt_count: 0,
                        source: AddrSource::Dns,
                    },
                );
                self.try_queue.push_back(addr);
            }
        }
    }

    /// Add addresses from an addr message from a peer.
    pub fn add_peer_addresses(&mut self, addrs: &[TimestampedNetAddress], from: SocketAddr) {
        for taddr in addrs {
            if let Some(socket_addr) = net_address_to_socket_addr(&taddr.address) {
                if !self.is_banned(&socket_addr) {
                    let entry = self
                        .known_addrs
                        .entry(socket_addr)
                        .or_insert_with(|| AddrInfo {
                            addr: socket_addr,
                            services: taddr.address.services,
                            last_seen: Instant::now(),
                            last_attempt: None,
                            last_success: None,
                            attempt_count: 0,
                            source: AddrSource::Peer(from),
                        });
                    entry.last_seen = Instant::now();
                    entry.services = taddr.address.services;

                    // Add to try queue if not already connected
                    if !self.connected.contains(&socket_addr) {
                        self.try_queue.push_back(socket_addr);
                    }
                }
            }
        }
    }

    /// Add a manually specified address.
    pub fn add_manual_address(&mut self, addr: SocketAddr) {
        self.known_addrs.entry(addr).or_insert_with(|| AddrInfo {
            addr,
            services: NODE_NETWORK | NODE_WITNESS,
            last_seen: Instant::now(),
            last_attempt: None,
            last_success: None,
            attempt_count: 0,
            source: AddrSource::Manual,
        });
        // Manual addresses go to the front of the queue
        self.try_queue.push_front(addr);
    }

    /// Get the next address to try connecting to with network group diversity.
    ///
    /// For IPv4/IPv6 outbound connections, this enforces that no two outbound
    /// connections share the same /16 (IPv4) or /32 (IPv6) network group.
    /// Privacy networks (Tor, I2P, CJDNS) are not subject to this restriction.
    ///
    /// Returns None if no addresses are available.
    pub fn next_addr_to_try(&mut self, netgroup_manager: &NetGroupManager) -> Option<SocketAddr> {
        while let Some(addr) = self.try_queue.pop_front() {
            // Skip banned addresses
            if self.is_banned(&addr) {
                continue;
            }

            // Skip already-connected addresses
            if self.connected.contains(&addr) {
                continue;
            }

            // Check network group diversity for IPv4/IPv6 outbound connections
            // Privacy networks (Tor, I2P, CJDNS) don't need this check as their
            // addresses are pseudorandom and don't correlate with network topology
            if !netgroup_manager.is_privacy_network(&addr.ip()) {
                let netgroup = netgroup_manager.get_group(&addr.ip());
                let netgroup_bytes = netgroup.as_bytes().to_vec();

                if self.connected_outbound_netgroups.contains(&netgroup_bytes) {
                    // Already have an outbound in this netgroup, skip
                    continue;
                }
            }

            // Update attempt metadata
            if let Some(info) = self.known_addrs.get_mut(&addr) {
                info.last_attempt = Some(Instant::now());
                info.attempt_count += 1;
            }

            return Some(addr);
        }
        None
    }

    /// Mark an address as successfully connected (outbound).
    pub fn mark_outbound_success(&mut self, addr: &SocketAddr, netgroup_manager: &NetGroupManager) {
        self.connected.insert(*addr);

        // Track netgroup for diversity enforcement (IPv4/IPv6 only)
        if !netgroup_manager.is_privacy_network(&addr.ip()) {
            let netgroup = netgroup_manager.get_group(&addr.ip());
            self.connected_outbound_netgroups
                .insert(netgroup.as_bytes().to_vec());
        }

        if let Some(info) = self.known_addrs.get_mut(addr) {
            info.last_success = Some(Instant::now());
            info.attempt_count = 0;
        }
    }

    /// Mark an address as successfully connected (inbound - no netgroup tracking).
    pub fn mark_inbound_success(&mut self, addr: &SocketAddr) {
        self.connected.insert(*addr);
        if let Some(info) = self.known_addrs.get_mut(addr) {
            info.last_success = Some(Instant::now());
            info.attempt_count = 0;
        }
    }

    /// Mark an address as successfully connected.
    ///
    /// DEPRECATED: Use mark_outbound_success or mark_inbound_success instead.
    pub fn mark_success(&mut self, addr: &SocketAddr) {
        self.connected.insert(*addr);
        if let Some(info) = self.known_addrs.get_mut(addr) {
            info.last_success = Some(Instant::now());
            info.attempt_count = 0;
        }
    }

    /// Mark an address as disconnected (outbound).
    pub fn mark_outbound_disconnected(&mut self, addr: &SocketAddr, netgroup_manager: &NetGroupManager) {
        self.connected.remove(addr);

        // Remove netgroup from tracking
        if !netgroup_manager.is_privacy_network(&addr.ip()) {
            let netgroup = netgroup_manager.get_group(&addr.ip());
            self.connected_outbound_netgroups
                .remove(netgroup.as_bytes());
        }
    }

    /// Mark an address as disconnected.
    pub fn mark_disconnected(&mut self, addr: &SocketAddr) {
        self.connected.remove(addr);
    }

    /// Check if a netgroup is already represented in our outbound connections.
    pub fn has_outbound_in_netgroup(&self, netgroup: &NetGroup) -> bool {
        self.connected_outbound_netgroups
            .contains(netgroup.as_bytes())
    }

    /// Get the number of unique netgroups in outbound connections.
    pub fn outbound_netgroup_count(&self) -> usize {
        self.connected_outbound_netgroups.len()
    }

    /// Ban an address for a specified duration.
    pub fn ban(&mut self, addr: &SocketAddr, duration: Duration) {
        self.banned.insert(*addr, Instant::now() + duration);
        self.connected.remove(addr);
    }

    /// Check if an address is currently banned.
    pub fn is_banned(&self, addr: &SocketAddr) -> bool {
        if let Some(unban_time) = self.banned.get(addr) {
            if Instant::now() < *unban_time {
                return true;
            }
        }
        false
    }

    /// Get addresses suitable for sharing with other peers.
    ///
    /// Returns addresses that have been successfully connected to recently.
    pub fn get_addresses_for_sharing(&self, count: usize) -> Vec<&AddrInfo> {
        self.known_addrs
            .values()
            .filter(|info| info.last_success.is_some())
            .take(count)
            .collect()
    }

    /// Number of known addresses.
    pub fn known_count(&self) -> usize {
        self.known_addrs.len()
    }

    /// Number of addresses in the try queue.
    pub fn queue_size(&self) -> usize {
        self.try_queue.len()
    }

    /// Number of banned addresses.
    pub fn banned_count(&self) -> usize {
        self.banned.len()
    }

    /// Number of currently connected addresses.
    pub fn connected_count(&self) -> usize {
        self.connected.len()
    }

    /// Expire old bans (cleanup).
    pub fn expire_bans(&mut self) {
        let now = Instant::now();
        self.banned.retain(|_, unban_time| *unban_time > now);
    }

    // ============================================================
    // BIP155 ADDRV2 METHODS
    // ============================================================

    /// Add addresses from an addrv2 message from a peer.
    ///
    /// This handles all BIP155 address types including Tor v3, I2P, and CJDNS.
    /// IPv4/IPv6 addresses are also added to the legacy known_addrs for compatibility.
    pub fn add_addrv2_addresses(&mut self, entries: &[crate::addr::AddrV2Entry], from: SocketAddr) {
        let now = Instant::now();

        for entry in entries {
            let key = AddrV2Key::new(entry.addr.clone(), entry.port);

            // For IPv4/IPv6, also add to legacy storage
            if let Some(socket_addr) = entry.to_socket_addr() {
                if !self.is_banned(&socket_addr) {
                    let addr_entry = self
                        .known_addrs
                        .entry(socket_addr)
                        .or_insert_with(|| AddrInfo {
                            addr: socket_addr,
                            services: entry.services,
                            last_seen: now,
                            last_attempt: None,
                            last_success: None,
                            attempt_count: 0,
                            source: AddrSource::Peer(from),
                        });
                    addr_entry.last_seen = now;
                    addr_entry.services = entry.services;

                    // Add to try queue if not already connected
                    if !self.connected.contains(&socket_addr) {
                        self.try_queue.push_back(socket_addr);
                    }
                }
            }

            // Store in addrv2 storage
            let v2_entry = self
                .known_addrv2
                .entry(key)
                .or_insert_with(|| AddrV2Info {
                    addr: entry.addr.clone(),
                    port: entry.port,
                    services: entry.services,
                    timestamp: entry.timestamp,
                    last_seen: now,
                    last_attempt: None,
                    last_success: None,
                    attempt_count: 0,
                    source: AddrSource::Peer(from),
                });
            v2_entry.last_seen = now;
            v2_entry.services = entry.services;
            v2_entry.timestamp = entry.timestamp;
        }
    }

    /// Get addresses suitable for sharing via addrv2 format.
    ///
    /// Returns addresses that have been successfully connected to recently,
    /// including privacy network addresses.
    pub fn get_addrv2_for_sharing(&self, count: usize) -> Vec<crate::addr::AddrV2Entry> {
        self.known_addrv2
            .values()
            .filter(|info| info.last_success.is_some())
            .take(count)
            .map(|info| info.to_addrv2_entry())
            .collect()
    }

    /// Get addresses suitable for sharing via legacy addr format.
    ///
    /// Returns only IPv4/IPv6 addresses that can be encoded in legacy format.
    pub fn get_addr_for_sharing(&self, count: usize) -> Vec<TimestampedNetAddress> {
        self.known_addrs
            .values()
            .filter(|info| info.last_success.is_some())
            .take(count)
            .map(|info| {
                let services = info.services;
                TimestampedNetAddress {
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as u32,
                    address: socket_addr_to_net_address(info.addr, services),
                }
            })
            .collect()
    }

    /// Number of known BIP155 addresses.
    pub fn known_addrv2_count(&self) -> usize {
        self.known_addrv2.len()
    }

    /// Number of privacy network addresses (Tor, I2P, CJDNS).
    pub fn privacy_network_count(&self) -> usize {
        self.known_addrv2
            .values()
            .filter(|info| info.is_privacy_network())
            .count()
    }
}

impl Default for AddressManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================
// ADDRESS CONVERSION HELPERS
// ============================================================

/// Convert a NetAddress to a SocketAddr.
pub fn net_address_to_socket_addr(addr: &NetAddress) -> Option<SocketAddr> {
    // Check for IPv4-mapped IPv6 (::ffff:x.x.x.x)
    if addr.ip[0..10] == [0u8; 10] && addr.ip[10] == 0xff && addr.ip[11] == 0xff {
        let ip = std::net::Ipv4Addr::new(addr.ip[12], addr.ip[13], addr.ip[14], addr.ip[15]);
        Some(SocketAddr::new(std::net::IpAddr::V4(ip), addr.port))
    } else {
        let ip = std::net::Ipv6Addr::from(addr.ip);
        Some(SocketAddr::new(std::net::IpAddr::V6(ip), addr.port))
    }
}

/// Convert a SocketAddr to a NetAddress.
pub fn socket_addr_to_net_address(addr: SocketAddr, services: u64) -> NetAddress {
    let ip = match addr.ip() {
        std::net::IpAddr::V4(v4) => {
            let mut ip = [0u8; 16];
            ip[10] = 0xff;
            ip[11] = 0xff;
            ip[12..16].copy_from_slice(&v4.octets());
            ip
        }
        std::net::IpAddr::V6(v6) => v6.octets(),
    };
    NetAddress {
        services,
        ip,
        port: addr.port(),
    }
}

// ============================================================
// DNS SEED RESOLUTION
// ============================================================

/// Resolve DNS seeds to socket addresses.
///
/// Returns all resolved addresses from all seeds.
pub async fn resolve_dns_seeds(seeds: &[&str], port: u16) -> Vec<SocketAddr> {
    let mut addrs = Vec::new();
    for seed in seeds {
        match tokio::net::lookup_host(format!("{}:{}", seed, port)).await {
            Ok(resolved) => {
                let resolved_addrs: Vec<_> = resolved.collect();
                tracing::info!(
                    "DNS seed {} resolved to {} addresses",
                    seed,
                    resolved_addrs.len()
                );
                addrs.extend(resolved_addrs);
            }
            Err(e) => {
                tracing::warn!("DNS seed {} failed: {}", seed, e);
            }
        }
    }
    addrs
}

/// Hardcoded fallback peers for testnet4.
///
/// DNS seeds are unreliable for testnet4, so we provide fallback addresses.
pub fn testnet4_fallback_peers() -> Vec<SocketAddr> {
    vec![
        // These are well-known testnet4 nodes
        // Add more fallback IPs as needed
    ]
}

// ============================================================
// PEER MANAGER
// ============================================================

/// Connection type for outbound connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionType {
    /// Full-relay connection (relays blocks and transactions).
    FullRelay,
    /// Block-relay-only connection (only relays blocks, not transactions).
    BlockRelayOnly,
    /// Inbound connection.
    Inbound,
}

/// Result of checking for stale peers.
#[derive(Debug, Clone, Default)]
pub struct StalePeerCheckResult {
    /// Peers to disconnect due to ping timeout.
    pub ping_timeouts: Vec<PeerId>,
    /// Peers to disconnect due to chain sync failure.
    pub chain_sync_failures: Vec<PeerId>,
    /// Peers to send getheaders to (chain sync warning).
    pub send_getheaders_to: Vec<PeerId>,
    /// Whether our tip may be stale (need extra outbound peer).
    pub tip_may_be_stale: bool,
}

impl StalePeerCheckResult {
    /// Check if any action was taken.
    pub fn has_disconnects(&self) -> bool {
        !self.ping_timeouts.is_empty() || !self.chain_sync_failures.is_empty()
    }

    /// Get all peers that were disconnected.
    pub fn disconnected_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.ping_timeouts.iter().chain(self.chain_sync_failures.iter())
    }
}

/// Handle for a connected peer, held by the peer manager.
struct PeerHandle {
    /// Peer metadata.
    info: PeerInfo,
    /// Channel to send commands to the peer task.
    command_tx: mpsc::Sender<PeerCommand>,
    /// Connection type.
    conn_type: ConnectionType,
    /// Time when connection was established.
    connected_time: Instant,
    /// Minimum observed ping time.
    min_ping_time: Option<Duration>,
    /// Last time we received a block from this peer.
    last_block_time: Option<Instant>,
    /// Last time we received a transaction from this peer.
    last_tx_time: Option<Instant>,
    /// Stale peer detection state.
    stale_state: StalePeerState,
}

/// The peer manager coordinates all peer connections.
pub struct PeerManager {
    /// Configuration.
    config: PeerManagerConfig,
    /// Chain parameters (for network magic, DNS seeds, etc.).
    params: ChainParams,
    /// Connected peers indexed by PeerId.
    peers: HashMap<PeerId, PeerHandle>,
    /// Inbound peer command senders — kept alive until the peer is
    /// registered via Connected event in handle_event().
    #[allow(clippy::type_complexity)]
    inbound_cmd_txs: Option<Arc<std::sync::Mutex<HashMap<PeerId, mpsc::Sender<PeerCommand>>>>>,
    /// Address manager for peer discovery.
    addr_manager: AddressManager,
    /// Misbehavior tracker for all peers.
    misbehavior_tracker: MisbehaviorTracker,
    /// Ban manager for persistent bans.
    ban_manager: BanManager,
    /// Network group manager for diversity enforcement.
    netgroup_manager: NetGroupManager,
    /// Stale peer detector for timeout enforcement.
    stale_detector: StalePeerDetector,
    /// Last time we ran the stale peer check.
    last_stale_check: Instant,
    /// Next peer ID to assign.
    next_peer_id: u64,
    /// Channel for receiving events from peer tasks.
    event_tx: mpsc::Sender<PeerEvent>,
    /// Receiver for peer events (Option so it can be taken for independent polling).
    event_rx: Option<mpsc::Receiver<PeerEvent>>,
    /// Our current best block height (for version messages).
    start_height: i32,
    /// Anchor connections loaded from disk.
    anchors: Vec<SocketAddr>,
}

impl PeerManager {
    /// Create a new peer manager with the given configuration and chain parameters.
    pub fn new(config: PeerManagerConfig, params: ChainParams) -> Self {
        let (event_tx, event_rx) = mpsc::channel(1024);
        let ban_manager = BanManager::with_duration(config.data_dir.clone(), config.ban_duration);

        // Load anchor connections from disk
        let anchors = read_anchors(&config.data_dir);
        if !anchors.is_empty() {
            tracing::info!(
                "{} block-relay-only anchors loaded from {}",
                anchors.len(),
                config.data_dir.join(ANCHORS_DATABASE_FILENAME).display()
            );
        }

        Self {
            config,
            params,
            peers: HashMap::new(),
            inbound_cmd_txs: None,
            addr_manager: AddressManager::new(),
            misbehavior_tracker: MisbehaviorTracker::new(),
            ban_manager,
            netgroup_manager: NetGroupManager::new(),
            stale_detector: StalePeerDetector::new(),
            last_stale_check: Instant::now(),
            next_peer_id: 1,
            event_tx,
            event_rx: Some(event_rx),
            start_height: 0,
            anchors,
        }
    }

    /// Create a peer manager for testnet4 with default configuration.
    pub fn testnet4() -> Self {
        Self::new(PeerManagerConfig::testnet4(), ChainParams::testnet4())
    }

    /// Set the current best block height (used in version messages).
    pub fn set_start_height(&mut self, height: i32) {
        self.start_height = height;
    }

    /// Get a reference to the network group manager.
    pub fn netgroup_manager(&self) -> &NetGroupManager {
        &self.netgroup_manager
    }

    /// Take the event receiver out of the peer manager.
    ///
    /// This allows the caller to poll events independently (e.g., in a `tokio::select!`)
    /// without holding a lock on the peer manager itself. Returns `None` if already taken.
    pub fn take_event_receiver(&mut self) -> Option<mpsc::Receiver<PeerEvent>> {
        self.event_rx.take()
    }

    /// Start the peer manager: resolve DNS seeds, begin connecting, and optionally
    /// start a TCP listener for inbound connections.
    pub async fn start(&mut self) {
        // Start TCP listener for inbound connections if configured
        if self.config.listen {
            let listen_addr: SocketAddr =
                format!("0.0.0.0:{}", self.config.listen_port).parse().unwrap();
            match tokio::net::TcpListener::bind(listen_addr).await {
                Ok(listener) => {
                    tracing::info!("P2P listening on {}", listen_addr);
                    let event_tx = self.event_tx.clone();
                    let magic = self.params.network_magic.0;
                    let our_services = NODE_NETWORK | NODE_WITNESS;
                    let our_start_height = self.start_height;
                    // We need a shared counter for peer IDs for inbound peers.
                    // Use an AtomicU64 to generate unique IDs.
                    let next_id = Arc::new(std::sync::atomic::AtomicU64::new(
                        self.next_peer_id + 10000, // offset to avoid collision with outbound IDs
                    ));
                    // Shared map to keep command senders alive until the peer
                    // manager moves them into PeerHandle on Connected event.
                    let inbound_senders: Arc<std::sync::Mutex<HashMap<PeerId, mpsc::Sender<PeerCommand>>>> =
                        Arc::new(std::sync::Mutex::new(HashMap::new()));
                    self.inbound_cmd_txs = Some(inbound_senders.clone());
                    tokio::spawn(async move {
                        loop {
                            match listener.accept().await {
                                Ok((stream, addr)) => {
                                    let peer_id = PeerId(
                                        next_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                                    );
                                    let event_tx = event_tx.clone();
                                    let (cmd_tx, cmd_rx) = mpsc::channel(32);
                                    // Store cmd_tx so it stays alive until the peer
                                    // manager registers the peer in its handle map.
                                    tracing::info!("Storing cmd_tx for inbound peer {}", peer_id.0);
                                    inbound_senders.lock().unwrap().insert(peer_id, cmd_tx);
                                    let senders_ref = inbound_senders.clone();
                                    tokio::spawn(async move {
                                        run_inbound_peer(
                                            peer_id,
                                            stream,
                                            addr,
                                            magic,
                                            our_services,
                                            our_start_height,
                                            event_tx,
                                            cmd_rx,
                                        )
                                        .await;
                                        // Clean up sender on disconnect
                                        senders_ref.lock().unwrap().remove(&peer_id);
                                    });
                                }
                                Err(e) => {
                                    tracing::warn!("Failed to accept inbound connection: {}", e);
                                }
                            }
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("Failed to bind P2P listener on {}: {}", listen_addr, e);
                }
            }
        }

        // First, try to connect to anchor peers (block-relay-only)
        // These are persisted from previous sessions for eclipse attack resistance
        self.connect_to_anchors().await;

        // Resolve DNS seeds
        let addrs = resolve_dns_seeds(&self.params.dns_seeds, self.params.default_port).await;

        if addrs.is_empty() {
            tracing::warn!("No addresses from DNS seeds, trying fallback peers");
            // Add fallback peers for testnet4
            if self.params.network_id == NetworkId::Testnet4 {
                for addr in testnet4_fallback_peers() {
                    self.addr_manager.add_manual_address(addr);
                }
            }
        }

        self.addr_manager.add_dns_addresses(addrs);

        tracing::info!(
            "Address manager initialized with {} known addresses",
            self.addr_manager.known_count()
        );

        // Fill outbound connections
        self.fill_outbound_connections().await;
    }

    /// Add a manual peer address (e.g., from command line).
    pub fn add_peer(&mut self, addr: SocketAddr) {
        self.addr_manager.add_manual_address(addr);
    }

    /// Immediately initiate an outbound connection to a peer (for addnode "onetry").
    pub async fn connect_to_peer(&mut self, addr: SocketAddr) {
        self.connect_to_with_type(addr, ConnectionType::FullRelay)
            .await;
    }

    /// Connect to anchor peers (block-relay-only connections from previous session).
    async fn connect_to_anchors(&mut self) {
        // Take anchors and clear them (we only try each once on startup)
        let anchors = std::mem::take(&mut self.anchors);

        let block_relay_count = self.block_relay_only_count();
        let needed = self
            .config
            .max_outbound_block_relay
            .saturating_sub(block_relay_count);

        for addr in anchors.into_iter().take(needed) {
            // Skip if already connected or in same netgroup as existing outbound
            if self.addr_manager.connected.contains(&addr) {
                continue;
            }

            // Check netgroup diversity (IPv4/IPv6 only)
            if !self.netgroup_manager.is_privacy_network(&addr.ip()) {
                let netgroup = self.netgroup_manager.get_group(&addr.ip());
                if self.addr_manager.has_outbound_in_netgroup(&netgroup) {
                    tracing::debug!(
                        "Skipping anchor {} - already have outbound in netgroup",
                        addr
                    );
                    continue;
                }
            }

            tracing::info!("Attempting anchor connection to {}", addr);
            self.connect_to_with_type(addr, ConnectionType::BlockRelayOnly)
                .await;
        }
    }

    /// Try to maintain the target number of outbound connections.
    ///
    /// This enforces network group diversity: no two IPv4/IPv6 outbound connections
    /// may share the same /16 (IPv4) or /32 (IPv6) network group.
    async fn fill_outbound_connections(&mut self) {
        // Count full-relay outbound connections
        let full_relay_count = self
            .peers
            .values()
            .filter(|p| p.conn_type == ConnectionType::FullRelay && p.info.state == PeerState::Established)
            .count();

        let full_relay_connecting = self
            .peers
            .values()
            .filter(|p| p.conn_type == ConnectionType::FullRelay && p.info.state == PeerState::Connecting)
            .count();

        // Count block-relay-only outbound connections
        let block_relay_count = self
            .peers
            .values()
            .filter(|p| p.conn_type == ConnectionType::BlockRelayOnly && p.info.state == PeerState::Established)
            .count();

        let block_relay_connecting = self
            .peers
            .values()
            .filter(|p| p.conn_type == ConnectionType::BlockRelayOnly && p.info.state == PeerState::Connecting)
            .count();

        // Fill full-relay connections first
        let full_relay_needed = self
            .config
            .max_outbound_full_relay
            .saturating_sub(full_relay_count + full_relay_connecting);

        for _ in 0..full_relay_needed {
            if let Some(addr) = self.addr_manager.next_addr_to_try(&self.netgroup_manager) {
                self.connect_to_with_type(addr, ConnectionType::FullRelay)
                    .await;
            } else {
                break;
            }
        }

        // Then fill block-relay-only connections
        let block_relay_needed = self
            .config
            .max_outbound_block_relay
            .saturating_sub(block_relay_count + block_relay_connecting);

        for _ in 0..block_relay_needed {
            if let Some(addr) = self.addr_manager.next_addr_to_try(&self.netgroup_manager) {
                self.connect_to_with_type(addr, ConnectionType::BlockRelayOnly)
                    .await;
            } else {
                break;
            }
        }
    }

    /// Count the number of block-relay-only outbound connections.
    fn block_relay_only_count(&self) -> usize {
        self.peers
            .values()
            .filter(|p| {
                p.conn_type == ConnectionType::BlockRelayOnly
                    && matches!(p.info.state, PeerState::Established | PeerState::Connecting)
            })
            .count()
    }

    /// Initiate an outbound connection to a peer.
    #[allow(dead_code)]
    async fn connect_to(&mut self, addr: SocketAddr) {
        self.connect_to_with_type(addr, ConnectionType::FullRelay)
            .await;
    }

    /// Initiate an outbound connection to a peer with a specific connection type.
    async fn connect_to_with_type(&mut self, addr: SocketAddr, conn_type: ConnectionType) {
        // Skip banned addresses
        if self.ban_manager.is_addr_banned(&addr) {
            tracing::debug!("Skipping banned address: {}", addr);
            return;
        }

        let peer_id = PeerId(self.next_peer_id);
        self.next_peer_id += 1;

        let (cmd_tx, cmd_rx) = mpsc::channel(32);
        let event_tx = self.event_tx.clone();
        let magic = self.params.network_magic.0;

        // For block-relay-only connections, set relay=false
        let relay = conn_type != ConnectionType::BlockRelayOnly;
        let our_version = self.build_version_message_with_relay(addr, relay);

        tracing::debug!(
            "Connecting to peer {} (id={}, type={:?})",
            addr,
            peer_id.0,
            conn_type
        );

        // Spawn the peer connection task
        tokio::spawn(async move {
            run_outbound_peer(peer_id, addr, magic, our_version, event_tx, cmd_rx).await;
        });

        self.peers.insert(
            peer_id,
            PeerHandle {
                info: PeerInfo {
                    addr,
                    version: 0,
                    services: 0,
                    user_agent: String::new(),
                    start_height: 0,
                    relay,
                    inbound: false,
                    state: PeerState::Connecting,
                    last_send: Instant::now(),
                    last_recv: Instant::now(),
                    ping_nonce: None,
                    ping_time: None,
                    bytes_sent: 0,
                    bytes_recv: 0,
                    supports_witness: false,
                    supports_sendheaders: false,
                    supports_wtxid_relay: false,
                    supports_addrv2: false,
                    feefilter: 0,
                },
                command_tx: cmd_tx,
                conn_type,
                connected_time: Instant::now(),
                min_ping_time: None,
                last_block_time: None,
                last_tx_time: None,
                stale_state: StalePeerState::new(),
            },
        );
    }

    /// Build a version message for outgoing connections.
    #[allow(dead_code)]
    fn build_version_message(&self, addr: SocketAddr) -> VersionMessage {
        self.build_version_message_with_relay(addr, true)
    }

    /// Build a version message for outgoing connections with relay flag.
    fn build_version_message_with_relay(&self, addr: SocketAddr, relay: bool) -> VersionMessage {
        VersionMessage {
            version: PROTOCOL_VERSION,
            services: NODE_NETWORK | NODE_WITNESS,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            addr_recv: socket_addr_to_net_address(addr, 0),
            addr_from: socket_addr_to_net_address(
                "0.0.0.0:0".parse().unwrap(),
                NODE_NETWORK | NODE_WITNESS,
            ),
            nonce: rand::random(),
            user_agent: "/Rustoshi:0.1.0/".to_string(),
            start_height: self.start_height,
            relay,
        }
    }

    /// Send a message to a specific peer.
    /// Uses blocking send to ensure critical messages (getheaders, getdata)
    /// are not dropped. For bulk responses (headers serving), use
    /// try_send_to_peer instead.
    pub async fn send_to_peer(&self, peer_id: PeerId, msg: NetworkMessage) -> bool {
        if let Some(peer) = self.peers.get(&peer_id) {
            peer.command_tx
                .send(PeerCommand::SendMessage(msg))
                .await
                .is_ok()
        } else {
            false
        }
    }

    /// Try to send a message without blocking. Drops the message if the
    /// peer's send buffer is full. Use for non-critical bulk responses.
    pub fn try_send_to_peer(&self, peer_id: PeerId, msg: NetworkMessage) -> bool {
        if let Some(peer) = self.peers.get(&peer_id) {
            peer.command_tx.try_send(PeerCommand::SendMessage(msg)).is_ok()
        } else {
            false
        }
    }

    /// Broadcast a message to all established peers.
    pub async fn broadcast(&self, msg: NetworkMessage) {
        for peer in self.peers.values() {
            if peer.info.state == PeerState::Established {
                let _ = peer
                    .command_tx
                    .send(PeerCommand::SendMessage(msg.clone()))
                    .await;
            }
        }
    }

    /// Disconnect from a specific peer.
    pub async fn disconnect_peer(&mut self, peer_id: PeerId) {
        if let Some(peer) = self.peers.get(&peer_id) {
            let _ = peer.command_tx.send(PeerCommand::Disconnect).await;
        }
    }

    /// Ban a peer for misbehavior.
    pub async fn ban_peer(&mut self, peer_id: PeerId) {
        self.ban_peer_with_reason(peer_id, "manual ban".to_string()).await;
    }

    /// Ban a peer with a specific reason.
    pub async fn ban_peer_with_reason(&mut self, peer_id: PeerId, reason: String) {
        if let Some(peer) = self.peers.get(&peer_id) {
            let addr = peer.info.addr;
            self.addr_manager.ban(&addr, self.config.ban_duration);
            self.ban_manager.ban_addr(addr, self.config.ban_duration, reason);
            let _ = peer.command_tx.send(PeerCommand::Disconnect).await;
        }
    }

    /// Record misbehavior for a peer. Returns true if the peer was banned.
    ///
    /// If the misbehavior score reaches 100, the peer is disconnected and banned.
    pub async fn misbehaving(&mut self, peer_id: PeerId, reason: MisbehaviorReason) -> bool {
        let should_ban = self.misbehavior_tracker.misbehaving(peer_id, reason.clone());

        if should_ban {
            self.ban_peer_with_reason(peer_id, reason.to_string()).await;
        }

        should_ban
    }

    /// Record misbehavior with a custom score and message. Returns true if the peer was banned.
    ///
    /// This mirrors Bitcoin Core's Misbehaving(peer, howmuch, message) signature.
    pub async fn misbehaving_with_score(
        &mut self,
        peer_id: PeerId,
        howmuch: u32,
        message: &str,
    ) -> bool {
        let should_ban = self.misbehavior_tracker.misbehaving_with_score(peer_id, howmuch, message);

        if should_ban {
            self.ban_peer_with_reason(peer_id, message.to_string()).await;
        }

        should_ban
    }

    /// Get the misbehavior score for a peer.
    pub fn get_misbehavior_score(&self, peer_id: PeerId) -> u32 {
        self.misbehavior_tracker.get_score(peer_id)
    }

    /// Check if an IP address is banned.
    pub fn is_banned(&self, ip: &IpAddr) -> bool {
        self.ban_manager.is_banned(ip)
    }

    /// Check if a socket address is banned.
    pub fn is_addr_banned(&self, addr: &SocketAddr) -> bool {
        self.ban_manager.is_addr_banned(addr)
    }

    /// Ban an IP address directly (e.g., via RPC).
    pub fn ban_ip(&mut self, ip: IpAddr, duration: Duration, reason: String) {
        self.ban_manager.ban(ip, duration, reason);
    }

    /// Unban an IP address. Returns true if the IP was previously banned.
    pub fn unban(&mut self, ip: &IpAddr) -> bool {
        self.ban_manager.unban(ip)
    }

    /// Get all banned addresses.
    pub fn list_banned(&self) -> Vec<(IpAddr, &BanEntry)> {
        self.ban_manager.get_banned()
    }

    /// Clear all bans.
    pub fn clear_banned(&mut self) {
        self.ban_manager.clear();
    }

    /// Get the next peer event.
    ///
    /// This should be called in a loop to process incoming events.
    pub async fn next_event(&mut self) -> Option<PeerEvent> {
        if let Some(ref mut rx) = self.event_rx {
            rx.recv().await
        } else {
            // event_rx was taken; use a pending future that never resolves
            std::future::pending().await
        }
    }

    /// Get the event sender for spawning new peer tasks.
    pub fn event_sender(&self) -> mpsc::Sender<PeerEvent> {
        self.event_tx.clone()
    }

    /// Handle a peer event internally.
    ///
    /// Returns the event for external processing if needed.
    pub async fn handle_event(&mut self, event: PeerEvent) -> Option<PeerEvent> {
        match &event {
            PeerEvent::Connected(id, info) => {
                tracing::info!(
                    "Peer {} connected: {} ({})",
                    id.0,
                    info.addr,
                    info.user_agent
                );

                // For inbound peers, create a PeerHandle from the shared
                // command sender stored by the listener task.
                if !self.peers.contains_key(id) {
                    tracing::info!("Peer {} not in peers map, checking inbound_cmd_txs (is_some={})", id.0, self.inbound_cmd_txs.is_some());
                    if let Some(ref inbound_map) = self.inbound_cmd_txs {
                        if let Some(cmd_tx) = inbound_map.lock().unwrap().remove(id) {
                            self.peers.insert(
                                *id,
                                PeerHandle {
                                    info: info.clone(),
                                    command_tx: cmd_tx,
                                    conn_type: ConnectionType::Inbound,
                                    connected_time: Instant::now(),
                                    min_ping_time: None,
                                    last_block_time: None,
                                    last_tx_time: None,
                                    stale_state: StalePeerState::new(),
                                },
                            );
                            self.addr_manager.mark_inbound_success(&info.addr);
                        }
                    }
                }

                // Track netgroup for outbound connections
                if let Some(peer) = self.peers.get(id) {
                    if peer.conn_type != ConnectionType::Inbound {
                        self.addr_manager
                            .mark_outbound_success(&info.addr, &self.netgroup_manager);
                    }
                }

                if let Some(peer) = self.peers.get_mut(id) {
                    peer.info = info.clone();
                    peer.connected_time = Instant::now();
                }

                // BIP133: Send initial feefilter after handshake
                // Use high fee rate (100 sat/vbyte) to discourage tx relay during sync
                if info.relay {
                    self.send_initial_feefilter(*id).await;
                }
            }
            PeerEvent::Disconnected(id, reason) => {
                tracing::info!("Peer {} disconnected: {:?}", id.0, reason);
                if let Some(peer) = self.peers.remove(id) {
                    // Remove netgroup tracking for outbound connections
                    if peer.conn_type != ConnectionType::Inbound {
                        self.addr_manager
                            .mark_outbound_disconnected(&peer.info.addr, &self.netgroup_manager);
                    } else {
                        self.addr_manager.mark_disconnected(&peer.info.addr);
                    }
                }
                // Clean up misbehavior tracking for this peer
                self.misbehavior_tracker.remove_peer(*id);
                // Try to replace the connection
                self.fill_outbound_connections().await;
            }
            PeerEvent::Message(id, msg) => {
                // Update last_recv timestamp
                if let Some(peer) = self.peers.get_mut(id) {
                    peer.info.last_recv = Instant::now();

                    // Track block/tx times for eviction logic
                    match msg {
                        NetworkMessage::Block(_) => {
                            peer.last_block_time = Some(Instant::now());
                            // Update stale detection state with block height
                            // Use the peer's start_height as approximation
                            peer.stale_state.block_received(peer.info.start_height);
                        }
                        NetworkMessage::Tx(_) => {
                            peer.last_tx_time = Some(Instant::now());
                            peer.stale_state.tx_received();
                        }
                        NetworkMessage::Headers(headers) => {
                            // Update best known height from headers
                            // The actual height tracking is done elsewhere;
                            // here we just note we received headers
                            if !headers.is_empty() {
                                // Headers received; height will be updated by header sync
                            }
                        }
                        _ => {}
                    }
                }

                // Handle addr messages internally
                if let NetworkMessage::Addr(addrs) = msg {
                    if let Some(peer) = self.peers.get(id) {
                        self.addr_manager.add_peer_addresses(addrs, peer.info.addr);
                    }
                    // BIP155: Relay a random subset of new addresses to 2 other peers
                    if addrs.len() <= MAX_ADDR {
                        self.relay_addresses_to_peers(*id).await;
                    }
                }

                // Handle addrv2 messages (BIP155)
                if let NetworkMessage::AddrV2(entries) = msg {
                    if entries.len() <= MAX_ADDR {
                        self.addr_manager.add_addrv2_addresses(entries, self.peers.get(id).map(|p| p.info.addr).unwrap_or_else(|| "0.0.0.0:0".parse().unwrap()));
                        // Relay to 2 other peers
                        self.relay_addresses_to_peers(*id).await;
                    }
                }

                // Handle feefilter messages (BIP133)
                if let NetworkMessage::FeeFilter(fee_rate) = msg {
                    if let Some(peer) = self.peers.get_mut(id) {
                        // Validate: must be within money range (max 21M BTC in sats)
                        if *fee_rate <= 2_100_000_000_000_000 {
                            peer.info.feefilter = *fee_rate;
                        }
                    }
                }

                // Handle getaddr messages
                if let NetworkMessage::GetAddr = msg {
                    // Send addrv2 if peer supports it, otherwise legacy addr
                    let peer_supports_addrv2 = self.peers.get(id).map(|p| p.info.supports_addrv2).unwrap_or(false);
                    if peer_supports_addrv2 {
                        let entries = self.addr_manager.get_addrv2_for_sharing(MAX_ADDR);
                        if !entries.is_empty() {
                            let _ = self.send_to_peer(*id, NetworkMessage::AddrV2(entries)).await;
                        }
                    } else {
                        let addrs = self.addr_manager.get_addresses_for_sharing(MAX_ADDR);
                        let timestamped_addrs: Vec<TimestampedNetAddress> = addrs
                            .into_iter()
                            .map(|info| TimestampedNetAddress {
                                timestamp: info
                                    .last_seen
                                    .elapsed()
                                    .as_secs()
                                    .saturating_sub(info.last_seen.elapsed().as_secs())
                                    as u32,
                                address: socket_addr_to_net_address(info.addr, info.services),
                            })
                            .collect();
                        if !timestamped_addrs.is_empty() {
                            let _ = self
                                .send_to_peer(*id, NetworkMessage::Addr(timestamped_addrs))
                                .await;
                        }
                    }
                }

                // Handle pong to track ping times
                if let NetworkMessage::Pong(nonce) = msg {
                    if let Some(peer) = self.peers.get_mut(id) {
                        if let Some(ping_nonce) = peer.info.ping_nonce {
                            if *nonce == ping_nonce {
                                let ping_time = peer.info.last_send.elapsed();
                                peer.info.ping_time = Some(ping_time);

                                // Track minimum ping time for eviction
                                match peer.min_ping_time {
                                    Some(min) if ping_time < min => {
                                        peer.min_ping_time = Some(ping_time);
                                    }
                                    None => {
                                        peer.min_ping_time = Some(ping_time);
                                    }
                                    _ => {}
                                }

                                peer.info.ping_nonce = None;

                                // Update stale detection state
                                peer.stale_state.pong_received();
                            }
                        }
                    }
                }
            }
        }

        Some(event)
    }

    /// Relay addresses to up to 2 random peers (excluding the source).
    /// This implements Bitcoin Core's RelayAddress behavior.
    async fn relay_addresses_to_peers(&mut self, source_id: PeerId) {
        use rand::seq::SliceRandom;
        let candidates: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|(pid, peer)| {
                **pid != source_id
                    && peer.conn_type != ConnectionType::BlockRelayOnly
                    && peer.info.state == PeerState::Established
            })
            .map(|(pid, _)| *pid)
            .collect();
        let mut rng = rand::thread_rng();
        let targets: Vec<PeerId> = candidates
            .choose_multiple(&mut rng, std::cmp::min(2, candidates.len()))
            .cloned()
            .collect();
        for target_id in targets {
            let target_supports_addrv2 = self
                .peers
                .get(&target_id)
                .map(|p| p.info.supports_addrv2)
                .unwrap_or(false);
            if target_supports_addrv2 {
                let entries = self.addr_manager.get_addrv2_for_sharing(10);
                if !entries.is_empty() {
                    let _ = self.send_to_peer(target_id, NetworkMessage::AddrV2(entries)).await;
                }
            } else {
                let addrs = self.addr_manager.get_addresses_for_sharing(10);
                let timestamped: Vec<TimestampedNetAddress> = addrs
                    .into_iter()
                    .map(|info| TimestampedNetAddress {
                        timestamp: 0,
                        address: socket_addr_to_net_address(info.addr, info.services),
                    })
                    .collect();
                if !timestamped.is_empty() {
                    let _ = self.send_to_peer(target_id, NetworkMessage::Addr(timestamped)).await;
                }
            }
        }
    }

    /// Send initial feefilter to a peer (BIP133).
    /// Without mempool, we set a high fee rate (100 sat/vbyte = 100000 sat/kvB)
    /// to discourage transaction relay.
    pub async fn send_initial_feefilter(&mut self, peer_id: PeerId) {
        // 100 sat/vbyte = 100,000 sat/kvB (sat per 1000 virtual bytes)
        let fee_rate: u64 = 100_000;
        let _ = self.send_to_peer(peer_id, NetworkMessage::FeeFilter(fee_rate)).await;
    }

    /// Update our tip height for stale peer detection.
    ///
    /// Call this when a new block is connected to our chain.
    pub fn update_tip_height(&mut self, height: u32) {
        self.stale_detector.update_tip(height);
        self.start_height = height as i32;
    }

    /// Check for stale peers and take appropriate action.
    ///
    /// This implements Bitcoin Core's CheckForStaleTipAndEvictPeers() logic:
    /// - Check every EXTRA_PEER_CHECK_INTERVAL (45 seconds)
    /// - Detect ping timeouts (20 minutes)
    /// - Detect chain sync failures (20 min + 2 min response time)
    /// - Evict stale peers, preferring inbound over outbound
    ///
    /// Returns lists of peers to disconnect.
    pub async fn check_for_stale_peers(
        &mut self,
        blocks_in_flight: usize,
    ) -> StalePeerCheckResult {
        let now = Instant::now();

        // Only check every EXTRA_PEER_CHECK_INTERVAL
        if now.duration_since(self.last_stale_check) < EXTRA_PEER_CHECK_INTERVAL {
            return StalePeerCheckResult::default();
        }
        self.last_stale_check = now;

        let mut result = StalePeerCheckResult::default();

        // Check if our tip may be stale
        if self.stale_detector.tip_may_be_stale(blocks_in_flight) {
            result.tip_may_be_stale = true;
            self.stale_detector.set_try_extra_outbound(true);
            tracing::info!(
                "Potential stale tip detected (last tip update: {} seconds ago)",
                self.stale_detector.our_tip_height()
            );
        } else {
            self.stale_detector.set_try_extra_outbound(false);
        }

        // Collect peers to check (avoid borrowing issues)
        let peer_ids: Vec<(PeerId, bool, bool)> = self
            .peers
            .iter()
            .filter(|(_, p)| p.info.state == PeerState::Established)
            .map(|(id, p)| {
                let is_outbound = p.conn_type != ConnectionType::Inbound;
                let is_protected = p.stale_state.chain_sync.protected;
                (*id, is_outbound, is_protected)
            })
            .collect();

        // Check each peer
        for (peer_id, is_outbound, is_protected) in peer_ids {
            // Check ping timeout
            if let Some(peer) = self.peers.get(&peer_id) {
                if peer.stale_state.is_ping_timed_out() {
                    tracing::info!(
                        "Peer {} disconnecting due to ping timeout (>20 minutes)",
                        peer_id.0
                    );
                    result.ping_timeouts.push(peer_id);
                    continue;
                }
            }

            // Check minimum connect time before considering for eviction
            if let Some(peer) = self.peers.get(&peer_id) {
                if peer.connected_time.elapsed() < MINIMUM_CONNECT_TIME {
                    continue;
                }
            }

            // Check chain sync timeout for outbound peers
            if is_outbound {
                if let Some(peer) = self.peers.get_mut(&peer_id) {
                    let action = self.stale_detector.check_chain_sync(
                        &mut peer.stale_state,
                        true,
                        is_protected,
                    );

                    match action {
                        Some(true) => {
                            // Send getheaders
                            result.send_getheaders_to.push(peer_id);
                        }
                        Some(false) => {
                            // Disconnect
                            tracing::info!(
                                "Peer {} disconnecting due to chain sync timeout",
                                peer_id.0
                            );
                            result.chain_sync_failures.push(peer_id);
                        }
                        None => {}
                    }
                }
            }
        }

        // Disconnect ping timeout peers
        for peer_id in &result.ping_timeouts {
            self.disconnect_peer(*peer_id).await;
        }

        // Disconnect chain sync failure peers
        for peer_id in &result.chain_sync_failures {
            self.disconnect_peer(*peer_id).await;
        }

        result
    }

    /// Evict one extra outbound peer if we have too many.
    ///
    /// This is called periodically to maintain the target number of connections.
    /// We prefer to evict:
    /// 1. Block-relay-only peers over full-relay peers
    /// 2. Peers that haven't announced a block recently
    /// 3. Peers with longer connect times (newer peers get a chance)
    pub async fn evict_extra_outbound_peer(&mut self) -> Option<PeerId> {
        let full_relay_count = self
            .peers
            .values()
            .filter(|p| {
                p.conn_type == ConnectionType::FullRelay
                    && p.info.state == PeerState::Established
            })
            .count();

        let block_relay_count = self
            .peers
            .values()
            .filter(|p| {
                p.conn_type == ConnectionType::BlockRelayOnly
                    && p.info.state == PeerState::Established
            })
            .count();

        // Check if we have excess block-relay-only peers
        if block_relay_count > self.config.max_outbound_block_relay {
            // Find the youngest block-relay-only peer to evict
            // (unless it recently sent us a block)
            let evict_candidate = self
                .peers
                .iter()
                .filter(|(_, p)| {
                    p.conn_type == ConnectionType::BlockRelayOnly
                        && p.info.state == PeerState::Established
                        && p.connected_time.elapsed() >= MINIMUM_CONNECT_TIME
                        // Don't evict if peer recently sent a block
                        && p.last_block_time
                            .is_none_or(|t| t.elapsed() > Duration::from_secs(60))
                })
                .max_by_key(|(_, p)| p.connected_time) // Youngest = most recent connected_time
                .map(|(id, _)| *id);

            if let Some(peer_id) = evict_candidate {
                tracing::info!(
                    "Evicting extra block-relay-only peer {} (excess: {} > {})",
                    peer_id.0,
                    block_relay_count,
                    self.config.max_outbound_block_relay
                );
                self.disconnect_peer(peer_id).await;
                return Some(peer_id);
            }
        }

        // Check if we have excess full-relay peers
        if full_relay_count > self.config.max_outbound_full_relay {
            // Find the peer that least recently announced a new block
            let evict_candidate = self
                .peers
                .iter()
                .filter(|(_, p)| {
                    p.conn_type == ConnectionType::FullRelay
                        && p.info.state == PeerState::Established
                        && p.connected_time.elapsed() >= MINIMUM_CONNECT_TIME
                        && !p.stale_state.chain_sync.protected
                })
                .min_by_key(|(_, p)| {
                    // Prefer to evict peers with oldest last_block_time
                    p.last_block_time.map_or(0, |t| {
                        (Instant::now() - t).as_secs()
                    })
                })
                .map(|(id, _)| *id);

            if let Some(peer_id) = evict_candidate {
                tracing::info!(
                    "Evicting extra full-relay peer {} (excess: {} > {})",
                    peer_id.0,
                    full_relay_count,
                    self.config.max_outbound_full_relay
                );
                self.disconnect_peer(peer_id).await;
                return Some(peer_id);
            }
        }

        None
    }

    /// Check if we should try to add an extra outbound peer.
    pub fn should_try_extra_outbound(&self) -> bool {
        self.stale_detector.should_try_extra_outbound()
    }

    /// Get the stale peer detector (for testing).
    #[cfg(test)]
    pub fn stale_detector(&self) -> &StalePeerDetector {
        &self.stale_detector
    }

    /// Get a mutable reference to a peer's stale state (for testing).
    #[cfg(test)]
    pub fn get_peer_stale_state_mut(&mut self, peer_id: PeerId) -> Option<&mut StalePeerState> {
        self.peers.get_mut(&peer_id).map(|p| &mut p.stale_state)
    }

    /// Save anchor connections to disk.
    ///
    /// Called before shutdown to persist block-relay-only connections
    /// for eclipse attack resistance.
    pub fn save_anchors(&self) {
        let anchors: Vec<SocketAddr> = self
            .peers
            .values()
            .filter(|p| {
                p.conn_type == ConnectionType::BlockRelayOnly
                    && p.info.state == PeerState::Established
            })
            .take(MAX_BLOCK_RELAY_ONLY_ANCHORS)
            .map(|p| p.info.addr)
            .collect();

        if !anchors.is_empty() {
            dump_anchors(&self.config.data_dir, &anchors);
            tracing::info!(
                "Saved {} anchor connections to {}",
                anchors.len(),
                self.config.data_dir.join(ANCHORS_DATABASE_FILENAME).display()
            );
        }
    }

    /// Select an inbound peer to evict when slots are full.
    ///
    /// Returns None if no peer should be evicted (all protected).
    pub fn select_inbound_to_evict(&self) -> Option<PeerId> {
        let builder = EvictionCandidateBuilder::new(&self.netgroup_manager);

        let candidates: Vec<EvictionCandidate> = self
            .peers
            .iter()
            .filter(|(_, p)| p.conn_type == ConnectionType::Inbound && p.info.state == PeerState::Established)
            .map(|(id, p)| {
                builder.build(
                    *id,
                    p.info.addr,
                    p.connected_time,
                    p.min_ping_time,
                    p.last_block_time,
                    p.last_tx_time,
                    (p.info.services & NODE_NETWORK != 0) && (p.info.services & NODE_WITNESS != 0),
                    p.info.relay,
                    false, // bloom_filter - we don't track this currently
                    false, // prefer_evict
                    false, // noban
                )
            })
            .collect();

        select_node_to_evict(candidates)
    }

    /// Get list of connected peers.
    pub fn connected_peers(&self) -> Vec<(PeerId, &PeerInfo)> {
        self.peers
            .iter()
            .filter(|(_, h)| h.info.state == PeerState::Established)
            .map(|(id, h)| (*id, &h.info))
            .collect()
    }

    /// Get list of all peers (including connecting).
    pub fn all_peers(&self) -> Vec<(PeerId, &PeerInfo)> {
        self.peers.iter().map(|(id, h)| (*id, &h.info)).collect()
    }

    /// Get the number of established connections.
    pub fn peer_count(&self) -> usize {
        self.peers
            .values()
            .filter(|p| p.info.state == PeerState::Established)
            .count()
    }

    /// Get the number of outbound connections.
    pub fn outbound_count(&self) -> usize {
        self.peers
            .values()
            .filter(|p| !p.info.inbound && p.info.state == PeerState::Established)
            .count()
    }

    /// Get the number of inbound connections.
    pub fn inbound_count(&self) -> usize {
        self.peers
            .values()
            .filter(|p| p.info.inbound && p.info.state == PeerState::Established)
            .count()
    }

    /// Get information about a specific peer.
    pub fn get_peer_info(&self, peer_id: PeerId) -> Option<&PeerInfo> {
        self.peers.get(&peer_id).map(|h| &h.info)
    }

    /// Get a reference to the address manager.
    pub fn addr_manager(&self) -> &AddressManager {
        &self.addr_manager
    }

    /// Get a mutable reference to the address manager.
    pub fn addr_manager_mut(&mut self) -> &mut AddressManager {
        &mut self.addr_manager
    }
}

// ============================================================
// INBOUND CONNECTION HANDLING
// ============================================================

/// Run an inbound peer connection task.
///
/// Similar to run_outbound_peer but for connections initiated by remote peers.
/// Enforces pre-handshake message validation:
/// - First message must be version
/// - Minimum protocol version (70015 for witness)
/// - Self-connection detection via nonce
/// - Duplicate version rejection
/// - Pre-handshake message rejection
#[allow(clippy::too_many_arguments)]
pub async fn run_inbound_peer(
    peer_id: PeerId,
    stream: tokio::net::TcpStream,
    addr: SocketAddr,
    magic: [u8; 4],
    our_services: u64,
    our_start_height: i32,
    event_tx: mpsc::Sender<PeerEvent>,
    command_rx: mpsc::Receiver<PeerCommand>,
) {
    use tokio::time::timeout;

    // Split the stream
    let (reader, writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut writer = BufWriter::new(writer);

    // Generate our nonce for self-connection detection
    let our_nonce: u64 = rand::random();

    // Apply 60-second handshake timeout (Bitcoin Core default)
    let handshake_timeout = Duration::from_secs(60);

    // Read their version message first (with timeout)
    let mut header_buf = [0u8; MESSAGE_HEADER_SIZE];
    let read_result = timeout(handshake_timeout, reader.read_exact(&mut header_buf)).await;

    match read_result {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            let _ = event_tx
                .send(PeerEvent::Disconnected(
                    peer_id,
                    DisconnectReason::IoError(format!("failed to read version header: {}", e)),
                ))
                .await;
            return;
        }
        Err(_) => {
            let _ = event_tx
                .send(PeerEvent::Disconnected(peer_id, DisconnectReason::Timeout))
                .await;
            return;
        }
    }

    let (msg_magic, command, length, checksum) = parse_message_header(&header_buf);
    if msg_magic != magic {
        let _ = event_tx
            .send(PeerEvent::Disconnected(
                peer_id,
                DisconnectReason::ProtocolError("bad magic".to_string()),
            ))
            .await;
        return;
    }

    // First message MUST be version (pre-handshake validation)
    if command != "version" {
        let _ = event_tx
            .send(PeerEvent::Disconnected(
                peer_id,
                DisconnectReason::PreHandshakeMessage(command.clone()),
            ))
            .await;
        return;
    }

    // Validate length
    if length as usize > MAX_MESSAGE_SIZE {
        let _ = event_tx
            .send(PeerEvent::Disconnected(
                peer_id,
                DisconnectReason::ProtocolError("message too large".to_string()),
            ))
            .await;
        return;
    }

    let mut payload = vec![0u8; length as usize];
    if !payload.is_empty() {
        match timeout(handshake_timeout, reader.read_exact(&mut payload)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                let _ = event_tx
                    .send(PeerEvent::Disconnected(
                        peer_id,
                        DisconnectReason::IoError(format!("failed to read version payload: {}", e)),
                    ))
                    .await;
                return;
            }
            Err(_) => {
                let _ = event_tx
                    .send(PeerEvent::Disconnected(peer_id, DisconnectReason::Timeout))
                    .await;
                return;
            }
        }
    }

    // Validate checksum
    let computed = rustoshi_crypto::sha256d(&payload);
    if checksum != computed.0[..4] {
        let _ = event_tx
            .send(PeerEvent::Disconnected(
                peer_id,
                DisconnectReason::ProtocolError("checksum mismatch".to_string()),
            ))
            .await;
        return;
    }

    let their_version = match NetworkMessage::deserialize("version", &payload) {
        Ok(NetworkMessage::Version(v)) => v,
        _ => {
            let _ = event_tx
                .send(PeerEvent::Disconnected(
                    peer_id,
                    DisconnectReason::HandshakeFailed("invalid version message".to_string()),
                ))
                .await;
            return;
        }
    };

    // Check minimum protocol version (70015 for witness support)
    if their_version.version < MIN_WITNESS_PROTO_VERSION {
        let _ = event_tx
            .send(PeerEvent::Disconnected(
                peer_id,
                DisconnectReason::ObsoleteVersion(their_version.version),
            ))
            .await;
        return;
    }

    // Check for self-connection (matching nonce)
    if their_version.nonce == our_nonce && our_nonce != 0 {
        let _ = event_tx
            .send(PeerEvent::Disconnected(
                peer_id,
                DisconnectReason::SelfConnection,
            ))
            .await;
        return;
    }

    // Send our version
    let our_version = VersionMessage {
        version: PROTOCOL_VERSION,
        services: our_services,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
        addr_recv: socket_addr_to_net_address(addr, their_version.services),
        addr_from: socket_addr_to_net_address("0.0.0.0:0".parse().unwrap(), our_services),
        nonce: our_nonce,
        user_agent: "/Rustoshi:0.1.0/".to_string(),
        start_height: our_start_height,
        relay: true,
    };

    let version_msg = serialize_message(&magic, &NetworkMessage::Version(our_version));
    if writer.write_all(&version_msg).await.is_err() {
        let _ = event_tx
            .send(PeerEvent::Disconnected(
                peer_id,
                DisconnectReason::IoError("failed to send version".to_string()),
            ))
            .await;
        return;
    }

    // Send verack
    let verack_msg = serialize_message(&magic, &NetworkMessage::Verack);
    if writer.write_all(&verack_msg).await.is_err() {
        let _ = event_tx
            .send(PeerEvent::Disconnected(
                peer_id,
                DisconnectReason::IoError("failed to send verack".to_string()),
            ))
            .await;
        return;
    }

    if writer.flush().await.is_err() {
        let _ = event_tx
            .send(PeerEvent::Disconnected(
                peer_id,
                DisconnectReason::IoError("flush failed".to_string()),
            ))
            .await;
        return;
    }

    // Track whether we've received version (for duplicate detection)
    let mut version_received = true;
    let mut handshake_complete = false;
    let mut wants_addrv2 = false;

    // Wait for their verack (with pre-handshake message validation)
    while !handshake_complete {
        let read_result = timeout(handshake_timeout, reader.read_exact(&mut header_buf)).await;

        match read_result {
            Ok(Ok(_)) => {}
            Ok(Err(_)) => {
                let _ = event_tx
                    .send(PeerEvent::Disconnected(
                        peer_id,
                        DisconnectReason::IoError("failed to read message header".to_string()),
                    ))
                    .await;
                return;
            }
            Err(_) => {
                let _ = event_tx
                    .send(PeerEvent::Disconnected(peer_id, DisconnectReason::Timeout))
                    .await;
                return;
            }
        }

        let (_, cmd, len, chk) = parse_message_header(&header_buf);

        // Read payload if any
        let mut msg_payload = vec![0u8; len as usize];
        if !msg_payload.is_empty() {
            match timeout(handshake_timeout, reader.read_exact(&mut msg_payload)).await {
                Ok(Ok(_)) => {}
                Ok(Err(_)) => {
                    let _ = event_tx
                        .send(PeerEvent::Disconnected(
                            peer_id,
                            DisconnectReason::IoError("failed to read message payload".to_string()),
                        ))
                        .await;
                    return;
                }
                Err(_) => {
                    let _ = event_tx
                        .send(PeerEvent::Disconnected(peer_id, DisconnectReason::Timeout))
                        .await;
                    return;
                }
            }

            // Validate checksum
            let computed = rustoshi_crypto::sha256d(&msg_payload);
            if chk != computed.0[..4] {
                let _ = event_tx
                    .send(PeerEvent::Disconnected(
                        peer_id,
                        DisconnectReason::ProtocolError("checksum mismatch".to_string()),
                    ))
                    .await;
                return;
            }
        }

        match cmd.as_str() {
            "verack" => {
                handshake_complete = true;
            }
            "version" => {
                // Duplicate version message (misbehavior score 1)
                if version_received {
                    let _ = event_tx
                        .send(PeerEvent::Disconnected(
                            peer_id,
                            DisconnectReason::DuplicateVersion,
                        ))
                        .await;
                    return;
                }
                version_received = true;
            }
            // Pre-verack negotiation messages are allowed
            "wtxidrelay" | "sendaddrv2" | "sendtxrcncl" => {
                if cmd == "sendaddrv2" {
                    wants_addrv2 = true;
                }
                continue;
            }
            // Any other message before handshake is complete is a protocol violation
            _ => {
                let _ = event_tx
                    .send(PeerEvent::Disconnected(
                        peer_id,
                        DisconnectReason::PreHandshakeMessage(cmd),
                    ))
                    .await;
                return;
            }
        }
    }

    // Connection established
    let peer_info = PeerInfo {
        addr,
        version: their_version.version,
        services: their_version.services,
        user_agent: their_version.user_agent,
        start_height: their_version.start_height,
        relay: their_version.relay,
        inbound: true,
        state: PeerState::Established,
        last_send: Instant::now(),
        last_recv: Instant::now(),
        ping_nonce: None,
        ping_time: None,
        bytes_sent: 0,
        bytes_recv: 0,
        supports_witness: their_version.services & NODE_WITNESS != 0,
        supports_sendheaders: their_version.version >= SENDHEADERS_VERSION,
        supports_wtxid_relay: false,
        supports_addrv2: wants_addrv2,
        feefilter: 0,
    };

    let _ = event_tx
        .send(PeerEvent::Connected(peer_id, peer_info))
        .await;

    // BIP 130: sendheaders - request headers announcements instead of inv
    if their_version.version >= SENDHEADERS_VERSION {
        let msg = serialize_message(&magic, &NetworkMessage::SendHeaders);
        let _ = writer.write_all(&msg).await;
    }
    let _ = writer.flush().await;

    // Full message loop — same as outbound peers
    crate::peer::run_message_loop(peer_id, &magic, reader, writer, event_tx, command_rx).await;
}

// ============================================================
// ANCHOR CONNECTION PERSISTENCE
// ============================================================

/// Read anchor connections from disk.
///
/// Anchors are block-relay-only peers persisted across restarts to provide
/// eclipse attack resistance. The file is deleted after reading to prevent
/// stale data from being used on subsequent restarts without new anchors.
pub fn read_anchors(data_dir: &std::path::Path) -> Vec<SocketAddr> {
    let path = data_dir.join(ANCHORS_DATABASE_FILENAME);

    if !path.exists() {
        return Vec::new();
    }

    let result = (|| -> Result<Vec<SocketAddr>, std::io::Error> {
        let mut file = fs::File::open(&path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        let mut anchors = Vec::new();
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Ok(addr) = line.parse::<SocketAddr>() {
                anchors.push(addr);
            }
        }

        // Delete the file after reading (matches Bitcoin Core behavior)
        // This prevents stale anchors from being used on multiple restarts
        let _ = fs::remove_file(&path);

        Ok(anchors)
    })();

    match result {
        Ok(anchors) => {
            if !anchors.is_empty() {
                tracing::debug!("Read {} anchors from {}", anchors.len(), path.display());
            }
            anchors
        }
        Err(e) => {
            tracing::warn!("Failed to read anchors from {}: {}", path.display(), e);
            Vec::new()
        }
    }
}

/// Write anchor connections to disk.
///
/// Persists block-relay-only peer addresses for use on next startup.
pub fn dump_anchors(data_dir: &std::path::Path, anchors: &[SocketAddr]) {
    let path = data_dir.join(ANCHORS_DATABASE_FILENAME);

    let result = (|| -> Result<(), std::io::Error> {
        // Ensure directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut file = fs::File::create(&path)?;
        writeln!(file, "# Anchor connections for eclipse attack resistance")?;
        writeln!(file, "# These block-relay-only peers will be reconnected on startup")?;
        writeln!(file, "# This file is automatically deleted after reading")?;

        for addr in anchors.iter().take(MAX_BLOCK_RELAY_ONLY_ANCHORS) {
            writeln!(file, "{}", addr)?;
        }

        Ok(())
    })();

    if let Err(e) = result {
        tracing::warn!("Failed to write anchors to {}: {}", path.display(), e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_manager_config_default() {
        let config = PeerManagerConfig::default();
        assert_eq!(config.max_outbound_full_relay, 8);
        assert_eq!(config.max_inbound, 117);
        assert_eq!(config.max_total, 125);
        assert_eq!(config.ban_duration, Duration::from_secs(24 * 60 * 60));
        assert_eq!(config.listen_port, 8333);
        assert!(config.listen);
    }

    #[test]
    fn test_peer_manager_config_testnet4() {
        let config = PeerManagerConfig::testnet4();
        assert_eq!(config.listen_port, 48333);
        assert_eq!(config.max_outbound(), 10); // 8 full-relay + 2 block-relay-only
    }

    #[test]
    fn test_address_manager_add_dns_addresses() {
        let mut mgr = AddressManager::new();
        let addrs = vec![
            "192.168.1.1:8333".parse().unwrap(),
            "192.168.1.2:8333".parse().unwrap(),
            "192.168.1.3:8333".parse().unwrap(),
        ];
        mgr.add_dns_addresses(addrs);

        assert_eq!(mgr.known_count(), 3);
        assert_eq!(mgr.queue_size(), 3);
    }

    #[test]
    fn test_address_manager_next_addr_to_try() {
        let mut mgr = AddressManager::new();
        let netgroup_mgr = NetGroupManager::with_key(12345);
        // Use different /16 subnets to avoid netgroup diversity blocking
        let addrs: Vec<SocketAddr> = vec![
            "192.168.1.1:8333".parse().unwrap(),
            "10.0.0.1:8333".parse().unwrap(),
        ];
        mgr.add_dns_addresses(addrs.clone());

        let first = mgr.next_addr_to_try(&netgroup_mgr);
        assert_eq!(first, Some(addrs[0]));

        let second = mgr.next_addr_to_try(&netgroup_mgr);
        assert_eq!(second, Some(addrs[1]));

        let third = mgr.next_addr_to_try(&netgroup_mgr);
        assert!(third.is_none());
    }

    #[test]
    fn test_address_manager_ban() {
        let mut mgr = AddressManager::new();
        let netgroup_mgr = NetGroupManager::with_key(12345);
        let addr: SocketAddr = "192.168.1.1:8333".parse().unwrap();
        mgr.add_dns_addresses(vec![addr]);

        assert!(!mgr.is_banned(&addr));
        mgr.ban(&addr, Duration::from_secs(3600));
        assert!(mgr.is_banned(&addr));

        // Banned address should be skipped
        assert!(mgr.next_addr_to_try(&netgroup_mgr).is_none());
    }

    #[test]
    fn test_address_manager_mark_success() {
        let mut mgr = AddressManager::new();
        let netgroup_mgr = NetGroupManager::with_key(12345);
        let addr: SocketAddr = "192.168.1.1:8333".parse().unwrap();
        mgr.add_dns_addresses(vec![addr]);

        // Get the address (this increments attempt_count)
        let _ = mgr.next_addr_to_try(&netgroup_mgr);
        assert_eq!(mgr.known_addrs.get(&addr).unwrap().attempt_count, 1);

        // Mark as successful
        mgr.mark_success(&addr);
        assert_eq!(mgr.known_addrs.get(&addr).unwrap().attempt_count, 0);
        assert!(mgr.known_addrs.get(&addr).unwrap().last_success.is_some());
        assert!(mgr.connected.contains(&addr));
    }

    #[test]
    fn test_address_manager_mark_disconnected() {
        let mut mgr = AddressManager::new();
        let addr: SocketAddr = "192.168.1.1:8333".parse().unwrap();
        mgr.add_dns_addresses(vec![addr]);
        mgr.mark_success(&addr);

        assert!(mgr.connected.contains(&addr));
        mgr.mark_disconnected(&addr);
        assert!(!mgr.connected.contains(&addr));
    }

    #[test]
    fn test_address_manager_connected_addresses_skipped() {
        let mut mgr = AddressManager::new();
        let netgroup_mgr = NetGroupManager::with_key(12345);
        let addr: SocketAddr = "192.168.1.1:8333".parse().unwrap();
        mgr.add_dns_addresses(vec![addr]);

        // Mark as connected
        mgr.mark_success(&addr);

        // Re-add to queue
        mgr.try_queue.push_back(addr);

        // Should skip connected address
        assert!(mgr.next_addr_to_try(&netgroup_mgr).is_none());
    }

    #[test]
    fn test_address_manager_manual_address_priority() {
        let mut mgr = AddressManager::new();
        let netgroup_mgr = NetGroupManager::with_key(12345);
        // Use different /16 subnets
        let dns_addr: SocketAddr = "192.168.1.1:8333".parse().unwrap();
        let manual_addr: SocketAddr = "10.0.0.1:8333".parse().unwrap();

        mgr.add_dns_addresses(vec![dns_addr]);
        mgr.add_manual_address(manual_addr);

        // Manual address should be tried first
        assert_eq!(mgr.next_addr_to_try(&netgroup_mgr), Some(manual_addr));
        assert_eq!(mgr.next_addr_to_try(&netgroup_mgr), Some(dns_addr));
    }

    #[test]
    fn test_netgroup_diversity_enforcement() {
        let mut mgr = AddressManager::new();
        let netgroup_mgr = NetGroupManager::with_key(12345);

        // Add addresses in the same /16 subnet
        let addrs: Vec<SocketAddr> = vec![
            "192.168.1.1:8333".parse().unwrap(),
            "192.168.1.2:8333".parse().unwrap(),
            "192.168.1.3:8333".parse().unwrap(),
        ];
        mgr.add_dns_addresses(addrs.clone());

        // First address should succeed
        let first = mgr.next_addr_to_try(&netgroup_mgr);
        assert_eq!(first, Some(addrs[0]));

        // Mark the first as connected (this adds netgroup to tracking)
        mgr.mark_outbound_success(&addrs[0], &netgroup_mgr);

        // Other addresses in same /16 should be skipped
        let second = mgr.next_addr_to_try(&netgroup_mgr);
        assert!(second.is_none()); // All remaining are same netgroup
    }

    #[test]
    fn test_netgroup_diversity_allows_different_groups() {
        let mut mgr = AddressManager::new();
        let netgroup_mgr = NetGroupManager::with_key(12345);

        // Add addresses in different /16 subnets
        let addrs: Vec<SocketAddr> = vec![
            "192.168.1.1:8333".parse().unwrap(),
            "10.0.0.1:8333".parse().unwrap(),
            "172.16.0.1:8333".parse().unwrap(),
        ];
        mgr.add_dns_addresses(addrs.clone());

        // All should be allowed since they're in different netgroups
        for expected in &addrs {
            let addr = mgr.next_addr_to_try(&netgroup_mgr);
            assert_eq!(addr, Some(*expected));
            mgr.mark_outbound_success(expected, &netgroup_mgr);
        }
    }

    #[test]
    fn test_address_manager_get_addresses_for_sharing() {
        let mut mgr = AddressManager::new();
        let addrs = vec![
            "192.168.1.1:8333".parse().unwrap(),
            "192.168.1.2:8333".parse().unwrap(),
            "192.168.1.3:8333".parse().unwrap(),
        ];
        mgr.add_dns_addresses(addrs.clone());

        // No successful connections yet
        assert!(mgr.get_addresses_for_sharing(10).is_empty());

        // Mark one as successful
        mgr.mark_success(&addrs[0]);
        let shared = mgr.get_addresses_for_sharing(10);
        assert_eq!(shared.len(), 1);
        assert_eq!(shared[0].addr, addrs[0]);
    }

    #[test]
    fn test_net_address_to_socket_addr_ipv4() {
        let net_addr = NetAddress::from_ipv4([192, 168, 1, 1], 8333, NODE_NETWORK);
        let socket_addr = net_address_to_socket_addr(&net_addr).unwrap();

        assert_eq!(socket_addr, "192.168.1.1:8333".parse().unwrap());
    }

    #[test]
    fn test_net_address_to_socket_addr_ipv6() {
        let net_addr = NetAddress {
            services: NODE_NETWORK,
            ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            port: 8333,
        };
        let socket_addr = net_address_to_socket_addr(&net_addr).unwrap();

        assert_eq!(socket_addr, "[::1]:8333".parse().unwrap());
    }

    #[test]
    fn test_socket_addr_to_net_address_roundtrip_ipv4() {
        let socket_addr: SocketAddr = "10.0.0.1:48333".parse().unwrap();
        let net_addr = socket_addr_to_net_address(socket_addr, NODE_NETWORK | NODE_WITNESS);
        let back = net_address_to_socket_addr(&net_addr).unwrap();

        assert_eq!(socket_addr, back);
        assert_eq!(net_addr.services, NODE_NETWORK | NODE_WITNESS);
        assert_eq!(net_addr.port, 48333);
    }

    #[test]
    fn test_socket_addr_to_net_address_roundtrip_ipv6() {
        let socket_addr: SocketAddr = "[2001:db8::1]:8333".parse().unwrap();
        let net_addr = socket_addr_to_net_address(socket_addr, NODE_NETWORK);
        let back = net_address_to_socket_addr(&net_addr).unwrap();

        assert_eq!(socket_addr, back);
    }

    #[test]
    fn test_peer_manager_build_version_message() {
        let config = PeerManagerConfig::testnet4();
        let params = ChainParams::testnet4();
        let mgr = PeerManager::new(config, params);

        let addr: SocketAddr = "192.168.1.1:48333".parse().unwrap();
        let version = mgr.build_version_message(addr);

        assert_eq!(version.version, PROTOCOL_VERSION);
        assert!(version.services & NODE_NETWORK != 0);
        assert!(version.services & NODE_WITNESS != 0);
        assert_eq!(version.user_agent, "/Rustoshi:0.1.0/");
        assert_eq!(version.start_height, 0);
        assert!(version.relay);
    }

    #[test]
    fn test_address_manager_expire_bans() {
        let mut mgr = AddressManager::new();
        let addr: SocketAddr = "192.168.1.1:8333".parse().unwrap();

        // Ban with zero duration (already expired)
        mgr.banned.insert(addr, Instant::now() - Duration::from_secs(1));
        assert_eq!(mgr.banned_count(), 1);

        mgr.expire_bans();
        assert_eq!(mgr.banned_count(), 0);
    }

    #[test]
    fn test_address_manager_add_peer_addresses() {
        let mut mgr = AddressManager::new();
        let from: SocketAddr = "192.168.1.1:8333".parse().unwrap();

        let addrs = vec![
            TimestampedNetAddress {
                timestamp: 1700000000,
                address: NetAddress::from_ipv4([10, 0, 0, 1], 8333, NODE_NETWORK),
            },
            TimestampedNetAddress {
                timestamp: 1700000001,
                address: NetAddress::from_ipv4([10, 0, 0, 2], 8333, NODE_NETWORK | NODE_WITNESS),
            },
        ];

        mgr.add_peer_addresses(&addrs, from);

        assert_eq!(mgr.known_count(), 2);
        let info = mgr
            .known_addrs
            .get(&"10.0.0.1:8333".parse().unwrap())
            .unwrap();
        assert_eq!(info.source, AddrSource::Peer(from));
    }

    #[tokio::test]
    async fn test_peer_manager_creation() {
        let config = PeerManagerConfig::testnet4();
        let params = ChainParams::testnet4();
        let mgr = PeerManager::new(config, params);

        assert_eq!(mgr.peer_count(), 0);
        assert_eq!(mgr.outbound_count(), 0);
        assert_eq!(mgr.inbound_count(), 0);
    }

    #[tokio::test]
    async fn test_peer_manager_add_peer() {
        let config = PeerManagerConfig::testnet4();
        let params = ChainParams::testnet4();
        let mut mgr = PeerManager::new(config, params);

        let addr: SocketAddr = "192.168.1.1:48333".parse().unwrap();
        mgr.add_peer(addr);

        assert_eq!(mgr.addr_manager.known_count(), 1);
        assert_eq!(mgr.addr_manager.queue_size(), 1);
    }

    #[tokio::test]
    async fn test_peer_manager_set_start_height() {
        let config = PeerManagerConfig::testnet4();
        let params = ChainParams::testnet4();
        let mut mgr = PeerManager::new(config, params);

        mgr.set_start_height(100000);
        let version = mgr.build_version_message("192.168.1.1:8333".parse().unwrap());
        assert_eq!(version.start_height, 100000);
    }

    #[tokio::test]
    async fn test_dns_seed_resolution_timeout() {
        // Test that DNS resolution handles failures gracefully
        let addrs = resolve_dns_seeds(&["nonexistent.invalid.domain"], 8333).await;
        assert!(addrs.is_empty());
    }

    #[tokio::test]
    async fn test_peer_manager_misbehavior_tracking() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let config = PeerManagerConfig::testnet4().with_data_dir(temp_dir.path().to_path_buf());
        let params = ChainParams::testnet4();
        let mut mgr = PeerManager::new(config, params);

        let peer_id = PeerId(1);

        // Initial score should be 0
        assert_eq!(mgr.get_misbehavior_score(peer_id), 0);

        // Record a minor violation (10 points)
        let banned = mgr.misbehaving(peer_id, MisbehaviorReason::InvalidTransaction).await;
        assert!(!banned);
        assert_eq!(mgr.get_misbehavior_score(peer_id), 10);

        // Record more violations
        mgr.misbehaving(peer_id, MisbehaviorReason::InvalidTransaction).await;
        mgr.misbehaving(peer_id, MisbehaviorReason::InvalidTransaction).await;
        assert_eq!(mgr.get_misbehavior_score(peer_id), 30);
    }

    #[tokio::test]
    async fn test_peer_manager_misbehavior_instant_ban() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let config = PeerManagerConfig::testnet4().with_data_dir(temp_dir.path().to_path_buf());
        let params = ChainParams::testnet4();
        let mut mgr = PeerManager::new(config, params);

        let peer_id = PeerId(1);

        // Invalid block header = 100 points = instant ban
        let banned = mgr.misbehaving(peer_id, MisbehaviorReason::InvalidBlockHeader).await;
        assert!(banned);
        assert_eq!(mgr.get_misbehavior_score(peer_id), 100);
    }

    #[tokio::test]
    async fn test_peer_manager_ban_and_unban() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let config = PeerManagerConfig::testnet4().with_data_dir(temp_dir.path().to_path_buf());
        let params = ChainParams::testnet4();
        let mut mgr = PeerManager::new(config, params);

        let ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();

        assert!(!mgr.is_banned(&ip));

        mgr.ban_ip(ip, Duration::from_secs(3600), "test ban".to_string());
        assert!(mgr.is_banned(&ip));

        assert!(mgr.unban(&ip));
        assert!(!mgr.is_banned(&ip));
    }

    #[tokio::test]
    async fn test_peer_manager_list_banned() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let config = PeerManagerConfig::testnet4().with_data_dir(temp_dir.path().to_path_buf());
        let params = ChainParams::testnet4();
        let mut mgr = PeerManager::new(config, params);

        let ip1: std::net::IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: std::net::IpAddr = "192.168.1.2".parse().unwrap();

        mgr.ban_ip(ip1, Duration::from_secs(3600), "test1".to_string());
        mgr.ban_ip(ip2, Duration::from_secs(3600), "test2".to_string());

        let banned = mgr.list_banned();
        assert_eq!(banned.len(), 2);
    }

    #[tokio::test]
    async fn test_peer_manager_misbehaving_with_score() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let config = PeerManagerConfig::testnet4().with_data_dir(temp_dir.path().to_path_buf());
        let params = ChainParams::testnet4();
        let mut mgr = PeerManager::new(config, params);

        let peer_id = PeerId(1);

        // Add 50 points with custom message
        let banned = mgr.misbehaving_with_score(peer_id, 50, "custom violation").await;
        assert!(!banned);
        assert_eq!(mgr.get_misbehavior_score(peer_id), 50);

        // Add 50 more points - should trigger ban
        let banned = mgr.misbehaving_with_score(peer_id, 50, "another violation").await;
        assert!(banned);
        assert_eq!(mgr.get_misbehavior_score(peer_id), 100);
    }

    #[test]
    fn test_anchor_persistence() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().to_path_buf();

        let anchors: Vec<SocketAddr> = vec![
            "192.168.1.1:8333".parse().unwrap(),
            "10.0.0.1:8333".parse().unwrap(),
        ];

        // Write anchors
        dump_anchors(&data_dir, &anchors);

        // Read them back
        let loaded = read_anchors(&data_dir);
        assert_eq!(loaded.len(), 2);
        assert!(loaded.contains(&anchors[0]));
        assert!(loaded.contains(&anchors[1]));

        // File should be deleted after reading
        let anchor_path = data_dir.join(ANCHORS_DATABASE_FILENAME);
        assert!(!anchor_path.exists());
    }

    #[test]
    fn test_anchor_limits() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().to_path_buf();

        // Try to write more than MAX_BLOCK_RELAY_ONLY_ANCHORS
        let anchors: Vec<SocketAddr> = (0..10)
            .map(|i| format!("192.168.{}.1:8333", i).parse().unwrap())
            .collect();

        dump_anchors(&data_dir, &anchors);

        let loaded = read_anchors(&data_dir);
        // Should only have MAX_BLOCK_RELAY_ONLY_ANCHORS (2)
        assert_eq!(loaded.len(), MAX_BLOCK_RELAY_ONLY_ANCHORS);
    }

    #[test]
    fn test_read_anchors_nonexistent() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().to_path_buf();

        // Reading from non-existent file should return empty vec
        let loaded = read_anchors(&data_dir);
        assert!(loaded.is_empty());
    }

    #[test]
    fn test_outbound_netgroup_tracking() {
        let mut mgr = AddressManager::new();
        let netgroup_mgr = NetGroupManager::with_key(12345);

        let addr1: SocketAddr = "192.168.1.1:8333".parse().unwrap();
        let addr2: SocketAddr = "192.168.1.2:8333".parse().unwrap(); // Same /16
        let addr3: SocketAddr = "10.0.0.1:8333".parse().unwrap(); // Different /16

        // Initially no outbound netgroups
        assert_eq!(mgr.outbound_netgroup_count(), 0);

        // Mark first as connected
        mgr.mark_outbound_success(&addr1, &netgroup_mgr);
        assert_eq!(mgr.outbound_netgroup_count(), 1);

        // Second address is in same netgroup
        let netgroup = netgroup_mgr.get_group(&addr2.ip());
        assert!(mgr.has_outbound_in_netgroup(&netgroup));

        // Third address is in different netgroup
        let netgroup3 = netgroup_mgr.get_group(&addr3.ip());
        assert!(!mgr.has_outbound_in_netgroup(&netgroup3));

        // Mark third as connected
        mgr.mark_outbound_success(&addr3, &netgroup_mgr);
        assert_eq!(mgr.outbound_netgroup_count(), 2);

        // Disconnect first
        mgr.mark_outbound_disconnected(&addr1, &netgroup_mgr);
        assert_eq!(mgr.outbound_netgroup_count(), 1);

        // Now second address netgroup should be available
        assert!(!mgr.has_outbound_in_netgroup(&netgroup));
    }

    #[test]
    fn test_eclipse_attack_scenario() {
        // Simulate an eclipse attack: attacker floods us with addresses in same /16
        let mut mgr = AddressManager::new();
        let netgroup_mgr = NetGroupManager::with_key(12345);

        // Attacker controls addresses in 192.168.x.x
        let attacker_addrs: Vec<SocketAddr> = (1..=100)
            .map(|i| format!("192.168.1.{}:8333", i % 256).parse().unwrap())
            .collect();

        // Add one legitimate address in different /16
        let legitimate_addr: SocketAddr = "8.8.8.8:8333".parse().unwrap();

        mgr.add_dns_addresses(attacker_addrs);
        mgr.add_dns_addresses(vec![legitimate_addr]);

        // First connection to attacker
        let first = mgr.next_addr_to_try(&netgroup_mgr).unwrap();
        mgr.mark_outbound_success(&first, &netgroup_mgr);

        // All other attacker addresses should be skipped (same netgroup)
        // Next should be the legitimate one
        let second = mgr.next_addr_to_try(&netgroup_mgr).unwrap();
        assert_eq!(second, legitimate_addr);
    }

    // ============================================================
    // STALE PEER EVICTION TESTS
    // ============================================================

    #[test]
    fn test_stale_peer_check_result_default() {
        let result = StalePeerCheckResult::default();
        assert!(result.ping_timeouts.is_empty());
        assert!(result.chain_sync_failures.is_empty());
        assert!(result.send_getheaders_to.is_empty());
        assert!(!result.tip_may_be_stale);
        assert!(!result.has_disconnects());
    }

    #[test]
    fn test_stale_peer_check_result_has_disconnects() {
        let mut result = StalePeerCheckResult::default();
        assert!(!result.has_disconnects());

        result.ping_timeouts.push(PeerId(1));
        assert!(result.has_disconnects());

        let mut result2 = StalePeerCheckResult::default();
        result2.chain_sync_failures.push(PeerId(2));
        assert!(result2.has_disconnects());
    }

    #[test]
    fn test_stale_peer_check_result_disconnected_peers() {
        let mut result = StalePeerCheckResult::default();
        result.ping_timeouts.push(PeerId(1));
        result.chain_sync_failures.push(PeerId(2));
        result.chain_sync_failures.push(PeerId(3));

        let disconnected: Vec<_> = result.disconnected_peers().collect();
        assert_eq!(disconnected.len(), 3);
        assert!(disconnected.contains(&&PeerId(1)));
        assert!(disconnected.contains(&&PeerId(2)));
        assert!(disconnected.contains(&&PeerId(3)));
    }

    #[tokio::test]
    async fn test_stale_peer_update_tip_height() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let config = PeerManagerConfig::testnet4().with_data_dir(temp_dir.path().to_path_buf());
        let params = ChainParams::testnet4();
        let mut mgr = PeerManager::new(config, params);

        assert_eq!(mgr.start_height, 0);
        assert_eq!(mgr.stale_detector().our_tip_height(), 0);

        mgr.update_tip_height(100000);

        assert_eq!(mgr.start_height, 100000);
        assert_eq!(mgr.stale_detector().our_tip_height(), 100000);
    }

    #[tokio::test]
    async fn test_stale_peer_should_try_extra_outbound() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let config = PeerManagerConfig::testnet4().with_data_dir(temp_dir.path().to_path_buf());
        let params = ChainParams::testnet4();
        let mgr = PeerManager::new(config, params);

        // Initially should not try extra outbound
        assert!(!mgr.should_try_extra_outbound());
    }

    #[test]
    fn test_stale_peer_state_initialization() {
        let state = StalePeerState::new();
        assert_eq!(state.best_known_height, 0);
        assert!(state.last_block_time.is_none());
        assert!(state.last_tx_time.is_none());
        assert!(state.ping_start.is_none());
        assert!(!state.ping_nonce_sent);
        assert!(state.last_getheaders_time.is_none());
        assert!(state.chain_sync.timeout.is_none());
    }

    #[test]
    fn test_stale_peer_ping_timeout_detection() {
        use crate::stale_detection::PING_TIMEOUT_INTERVAL;

        let mut state = StalePeerState::new();

        // No ping sent - not timed out
        assert!(!state.is_ping_timed_out());

        // Send ping
        state.ping_sent();
        assert!(state.ping_nonce_sent);
        assert!(state.ping_start.is_some());

        // Just sent - not timed out
        assert!(!state.is_ping_timed_out());

        // Simulate timeout by setting ping_start in the past
        state.ping_start = Some(Instant::now() - PING_TIMEOUT_INTERVAL - Duration::from_secs(1));
        assert!(state.is_ping_timed_out());

        // Receive pong - should clear
        state.pong_received();
        assert!(!state.ping_nonce_sent);
        assert!(!state.is_ping_timed_out());
    }

    #[test]
    fn test_stale_peer_block_tracking() {
        let mut state = StalePeerState::new();

        state.block_received(100);
        assert_eq!(state.best_known_height, 100);
        assert!(state.last_block_time.is_some());

        // Higher block should update
        state.block_received(200);
        assert_eq!(state.best_known_height, 200);

        // Lower block should not reduce best_known_height
        state.block_received(150);
        assert_eq!(state.best_known_height, 200);
    }

    #[test]
    fn test_stale_peer_headers_timeout_detection() {
        use crate::stale_detection::HEADERS_RESPONSE_TIME;

        let mut state = StalePeerState::new();

        // No getheaders sent - not timed out
        assert!(!state.is_headers_timed_out());

        // Send getheaders
        state.getheaders_sent();
        assert!(state.chain_sync.sent_getheaders);
        assert!(state.last_getheaders_time.is_some());

        // Just sent - not timed out
        assert!(!state.is_headers_timed_out());

        // Simulate timeout
        state.last_getheaders_time = Some(Instant::now() - HEADERS_RESPONSE_TIME - Duration::from_secs(1));
        assert!(state.is_headers_timed_out());
    }

    #[test]
    fn test_stale_peer_detector_tip_stale() {
        let mut detector = StalePeerDetector::new();

        // With blocks in flight - never stale
        assert!(!detector.tip_may_be_stale(1));

        // Just updated tip - not stale
        detector.update_tip(100);
        assert!(!detector.tip_may_be_stale(0));

        // Simulate old tip by setting last_tip_update in the past
        // (We can't easily do this without modifying the struct, so we'll test the logic)
    }

    #[test]
    fn test_stale_peer_detector_protection() {
        use crate::stale_detection::MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT;

        let mut detector = StalePeerDetector::new();
        detector.update_tip(100);

        let mut states: Vec<StalePeerState> = (0..5)
            .map(|_| {
                let mut s = StalePeerState::new();
                s.best_known_height = 100; // At tip
                s
            })
            .collect();

        // Protect up to max
        for i in 0..MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT {
            assert!(detector.try_protect_peer(&mut states[i]));
            assert!(states[i].chain_sync.protected);
        }

        assert_eq!(detector.protected_count(), MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT);

        // Can't protect more
        assert!(!detector.try_protect_peer(&mut states[4]));
        assert!(!states[4].chain_sync.protected);

        // Unprotect one
        detector.unprotect_peer(&mut states[0]);
        assert!(!states[0].chain_sync.protected);
        assert_eq!(detector.protected_count(), MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT - 1);

        // Now can protect the last one
        assert!(detector.try_protect_peer(&mut states[4]));
    }

    #[test]
    fn test_stale_peer_detector_protection_requires_good_height() {
        let mut detector = StalePeerDetector::new();
        detector.update_tip(100);

        let mut state = StalePeerState::new();
        state.best_known_height = 50; // Too far behind (> 6 blocks)

        // Can't protect peer with bad height
        assert!(!detector.try_protect_peer(&mut state));
        assert!(!state.chain_sync.protected);

        // Close to tip - can protect
        state.best_known_height = 95;
        assert!(detector.try_protect_peer(&mut state));
    }

    #[test]
    fn test_stale_peer_chain_sync_timeout_sets_timeout() {
        let mut detector = StalePeerDetector::new();
        detector.update_tip(100);

        let mut state = StalePeerState::new();
        state.best_known_height = 50; // Behind

        // First check should set timeout
        let action = detector.check_chain_sync(&mut state, true, false);
        assert!(action.is_none()); // No immediate action
        assert!(state.chain_sync.timeout.is_some());
        assert_eq!(state.chain_sync.work_header_height, Some(100));
        assert!(!state.chain_sync.sent_getheaders);
    }

    #[test]
    fn test_stale_peer_chain_sync_catches_up() {
        let mut detector = StalePeerDetector::new();
        detector.update_tip(100);

        let mut state = StalePeerState::new();
        state.best_known_height = 50; // Behind

        // Set timeout
        detector.check_chain_sync(&mut state, true, false);
        assert!(state.chain_sync.timeout.is_some());

        // Peer catches up
        state.best_known_height = 100;
        let action = detector.check_chain_sync(&mut state, true, false);
        assert!(action.is_none());
        assert!(state.chain_sync.timeout.is_none()); // Cleared
    }

    #[test]
    fn test_stale_peer_chain_sync_inbound_ignored() {
        let mut detector = StalePeerDetector::new();
        detector.update_tip(100);

        let mut state = StalePeerState::new();
        state.best_known_height = 50; // Behind

        // Inbound peers are not subject to chain sync checks
        let action = detector.check_chain_sync(&mut state, false, false);
        assert!(action.is_none());
        assert!(state.chain_sync.timeout.is_none()); // No timeout set
    }

    #[tokio::test]
    async fn test_evict_extra_outbound_peer_no_excess() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let config = PeerManagerConfig::testnet4().with_data_dir(temp_dir.path().to_path_buf());
        let params = ChainParams::testnet4();
        let mut mgr = PeerManager::new(config, params);

        // No peers - nothing to evict
        let evicted = mgr.evict_extra_outbound_peer().await;
        assert!(evicted.is_none());
    }

    #[test]
    fn test_minimum_connect_time_constant() {
        // Verify MINIMUM_CONNECT_TIME matches Bitcoin Core
        assert_eq!(MINIMUM_CONNECT_TIME, Duration::from_secs(30));
    }

    #[test]
    fn test_ping_timeout_interval_constant() {
        use crate::stale_detection::PING_TIMEOUT_INTERVAL;
        // Verify PING_TIMEOUT_INTERVAL matches Bitcoin Core's TIMEOUT_INTERVAL
        assert_eq!(PING_TIMEOUT_INTERVAL, Duration::from_secs(20 * 60));
    }

    #[test]
    fn test_extra_peer_check_interval_constant() {
        // Verify check interval is 45 seconds per Bitcoin Core
        assert_eq!(EXTRA_PEER_CHECK_INTERVAL, Duration::from_secs(45));
    }
}
