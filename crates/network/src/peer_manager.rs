//! Peer manager for maintaining Bitcoin P2P connections.
//!
//! This module implements:
//! - Connection pool management (target 8 outbound, up to 117 inbound)
//! - DNS seed resolution for initial peer discovery
//! - Address manager for tracking known peers
//! - Peer quality tracking (ban scores, response times, attempt counts)
//! - Misbehavior scoring and ban management
//!
//! The peer manager coordinates outbound connection attempts, accepts inbound
//! connections, and routes messages between peers and the node's message handler.

use crate::message::{
    parse_message_header, serialize_message, NetAddress, NetworkMessage,
    TimestampedNetAddress, VersionMessage, MAX_ADDR, MAX_MESSAGE_SIZE, MESSAGE_HEADER_SIZE,
    MIN_WITNESS_PROTO_VERSION, NODE_NETWORK, NODE_WITNESS, PROTOCOL_VERSION, SENDHEADERS_VERSION,
};
use crate::misbehavior::{BanEntry, BanManager, MisbehaviorReason, MisbehaviorTracker};
use crate::peer::{
    run_outbound_peer, DisconnectReason, PeerCommand, PeerEvent, PeerId, PeerInfo, PeerState,
};
use rustoshi_consensus::{ChainParams, NetworkId};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant};

/// Configuration for the peer manager.
#[derive(Clone, Debug)]
pub struct PeerManagerConfig {
    /// Target number of outbound connections (default: 8).
    pub max_outbound: usize,
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
    /// Data directory for persistent state (banlist, etc.).
    pub data_dir: PathBuf,
}

impl Default for PeerManagerConfig {
    fn default() -> Self {
        Self {
            max_outbound: 8,
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

/// Address manager: tracks known peer addresses with metadata.
#[derive(Debug)]
pub struct AddressManager {
    /// Known addresses with metadata.
    known_addrs: HashMap<SocketAddr, AddrInfo>,
    /// Addresses to try next (prioritized queue).
    try_queue: VecDeque<SocketAddr>,
    /// Banned addresses with unban time.
    banned: HashMap<SocketAddr, Instant>,
    /// Currently connected addresses (to avoid duplicates).
    connected: HashSet<SocketAddr>,
}

impl AddressManager {
    /// Create a new empty address manager.
    pub fn new() -> Self {
        Self {
            known_addrs: HashMap::new(),
            try_queue: VecDeque::new(),
            banned: HashMap::new(),
            connected: HashSet::new(),
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

    /// Get the next address to try connecting to.
    ///
    /// Returns None if no addresses are available.
    pub fn next_addr_to_try(&mut self) -> Option<SocketAddr> {
        while let Some(addr) = self.try_queue.pop_front() {
            // Skip banned addresses
            if self.is_banned(&addr) {
                continue;
            }

            // Skip already-connected addresses
            if self.connected.contains(&addr) {
                continue;
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

    /// Mark an address as successfully connected.
    pub fn mark_success(&mut self, addr: &SocketAddr) {
        self.connected.insert(*addr);
        if let Some(info) = self.known_addrs.get_mut(addr) {
            info.last_success = Some(Instant::now());
            info.attempt_count = 0;
        }
    }

    /// Mark an address as disconnected.
    pub fn mark_disconnected(&mut self, addr: &SocketAddr) {
        self.connected.remove(addr);
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

/// Handle for a connected peer, held by the peer manager.
struct PeerHandle {
    /// Peer metadata.
    info: PeerInfo,
    /// Channel to send commands to the peer task.
    command_tx: mpsc::Sender<PeerCommand>,
}

/// The peer manager coordinates all peer connections.
pub struct PeerManager {
    /// Configuration.
    config: PeerManagerConfig,
    /// Chain parameters (for network magic, DNS seeds, etc.).
    params: ChainParams,
    /// Connected peers indexed by PeerId.
    peers: HashMap<PeerId, PeerHandle>,
    /// Address manager for peer discovery.
    addr_manager: AddressManager,
    /// Misbehavior tracker for all peers.
    misbehavior_tracker: MisbehaviorTracker,
    /// Ban manager for persistent bans.
    ban_manager: BanManager,
    /// Next peer ID to assign.
    next_peer_id: u64,
    /// Channel for receiving events from peer tasks.
    event_tx: mpsc::Sender<PeerEvent>,
    /// Receiver for peer events.
    event_rx: mpsc::Receiver<PeerEvent>,
    /// Our current best block height (for version messages).
    start_height: i32,
}

impl PeerManager {
    /// Create a new peer manager with the given configuration and chain parameters.
    pub fn new(config: PeerManagerConfig, params: ChainParams) -> Self {
        let (event_tx, event_rx) = mpsc::channel(1024);
        let ban_manager = BanManager::with_duration(config.data_dir.clone(), config.ban_duration);
        Self {
            config,
            params,
            peers: HashMap::new(),
            addr_manager: AddressManager::new(),
            misbehavior_tracker: MisbehaviorTracker::new(),
            ban_manager,
            next_peer_id: 1,
            event_tx,
            event_rx,
            start_height: 0,
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

    /// Start the peer manager: resolve DNS seeds and begin connecting.
    pub async fn start(&mut self) {
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

    /// Try to maintain the target number of outbound connections.
    async fn fill_outbound_connections(&mut self) {
        let outbound_count = self
            .peers
            .values()
            .filter(|p| !p.info.inbound && p.info.state == PeerState::Established)
            .count();

        let connecting_count = self
            .peers
            .values()
            .filter(|p| !p.info.inbound && p.info.state == PeerState::Connecting)
            .count();

        let needed = self
            .config
            .max_outbound
            .saturating_sub(outbound_count + connecting_count);

        for _ in 0..needed {
            if let Some(addr) = self.addr_manager.next_addr_to_try() {
                self.connect_to(addr).await;
            } else {
                break;
            }
        }
    }

    /// Initiate an outbound connection to a peer.
    async fn connect_to(&mut self, addr: SocketAddr) {
        // Skip banned addresses
        if self.ban_manager.is_addr_banned(&addr) {
            tracing::debug!("Skipping banned address: {}", addr);
            return;
        }

        let peer_id = PeerId(self.next_peer_id);
        self.next_peer_id += 1;

        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        let event_tx = self.event_tx.clone();
        let magic = self.params.network_magic.0;
        let our_version = self.build_version_message(addr);

        tracing::debug!("Connecting to peer {} (id={})", addr, peer_id.0);

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
                    relay: true,
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
                    feefilter: 0,
                },
                command_tx: cmd_tx,
            },
        );
    }

    /// Build a version message for outgoing connections.
    fn build_version_message(&self, addr: SocketAddr) -> VersionMessage {
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
            relay: true,
        }
    }

    /// Send a message to a specific peer.
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
        self.event_rx.recv().await
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
                self.addr_manager.mark_success(&info.addr);
                if let Some(peer) = self.peers.get_mut(id) {
                    peer.info = info.clone();
                }
            }
            PeerEvent::Disconnected(id, reason) => {
                tracing::info!("Peer {} disconnected: {:?}", id.0, reason);
                if let Some(peer) = self.peers.remove(id) {
                    self.addr_manager.mark_disconnected(&peer.info.addr);
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
                }

                // Handle addr messages internally
                if let NetworkMessage::Addr(addrs) = msg {
                    if let Some(peer) = self.peers.get(id) {
                        self.addr_manager.add_peer_addresses(addrs, peer.info.addr);
                    }
                }

                // Handle getaddr messages
                if let NetworkMessage::GetAddr = msg {
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
        }

        Some(event)
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
        feefilter: 0,
    };

    let _ = event_tx
        .send(PeerEvent::Connected(peer_id, peer_info))
        .await;

    // The main message loop would continue here...
    // For now, we just hold the connection until disconnected
    let mut cmd_rx = command_rx;
    let mut read_buf = [0u8; 1];
    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(PeerCommand::SendMessage(msg)) => {
                        let data = serialize_message(&magic, &msg);
                        if writer.write_all(&data).await.is_err() {
                            let _ = event_tx.send(PeerEvent::Disconnected(
                                peer_id, DisconnectReason::IoError("write failed".to_string())
                            )).await;
                            return;
                        }
                        let _ = writer.flush().await;
                    }
                    Some(PeerCommand::Disconnect) | None => {
                        let _ = event_tx.send(PeerEvent::Disconnected(
                            peer_id, DisconnectReason::PeerRequested
                        )).await;
                        return;
                    }
                }
            }
            result = reader.read(&mut read_buf) => {
                match result {
                    Ok(0) => {
                        let _ = event_tx.send(PeerEvent::Disconnected(
                            peer_id, DisconnectReason::ConnectionClosed
                        )).await;
                        return;
                    }
                    Err(_) => {
                        let _ = event_tx.send(PeerEvent::Disconnected(
                            peer_id, DisconnectReason::ConnectionClosed
                        )).await;
                        return;
                    }
                    _ => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_manager_config_default() {
        let config = PeerManagerConfig::default();
        assert_eq!(config.max_outbound, 8);
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
        assert_eq!(config.max_outbound, 8);
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
        let addrs = vec![
            "192.168.1.1:8333".parse().unwrap(),
            "192.168.1.2:8333".parse().unwrap(),
        ];
        mgr.add_dns_addresses(addrs.clone());

        let first = mgr.next_addr_to_try();
        assert_eq!(first, Some(addrs[0]));

        let second = mgr.next_addr_to_try();
        assert_eq!(second, Some(addrs[1]));

        let third = mgr.next_addr_to_try();
        assert!(third.is_none());
    }

    #[test]
    fn test_address_manager_ban() {
        let mut mgr = AddressManager::new();
        let addr: SocketAddr = "192.168.1.1:8333".parse().unwrap();
        mgr.add_dns_addresses(vec![addr]);

        assert!(!mgr.is_banned(&addr));
        mgr.ban(&addr, Duration::from_secs(3600));
        assert!(mgr.is_banned(&addr));

        // Banned address should be skipped
        assert!(mgr.next_addr_to_try().is_none());
    }

    #[test]
    fn test_address_manager_mark_success() {
        let mut mgr = AddressManager::new();
        let addr: SocketAddr = "192.168.1.1:8333".parse().unwrap();
        mgr.add_dns_addresses(vec![addr]);

        // Get the address (this increments attempt_count)
        let _ = mgr.next_addr_to_try();
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
        let addr: SocketAddr = "192.168.1.1:8333".parse().unwrap();
        mgr.add_dns_addresses(vec![addr]);

        // Mark as connected
        mgr.mark_success(&addr);

        // Re-add to queue
        mgr.try_queue.push_back(addr);

        // Should skip connected address
        assert!(mgr.next_addr_to_try().is_none());
    }

    #[test]
    fn test_address_manager_manual_address_priority() {
        let mut mgr = AddressManager::new();
        let dns_addr: SocketAddr = "192.168.1.1:8333".parse().unwrap();
        let manual_addr: SocketAddr = "10.0.0.1:8333".parse().unwrap();

        mgr.add_dns_addresses(vec![dns_addr]);
        mgr.add_manual_address(manual_addr);

        // Manual address should be tried first
        assert_eq!(mgr.next_addr_to_try(), Some(manual_addr));
        assert_eq!(mgr.next_addr_to_try(), Some(dns_addr));
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
}
