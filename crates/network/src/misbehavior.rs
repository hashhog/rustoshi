//! Misbehavior scoring and ban management for Bitcoin P2P peers.
//!
//! This module implements peer misbehavior tracking following Bitcoin Core's
//! approach. Each protocol violation adds points to a peer's score. When the
//! score reaches 100, the peer is disconnected and banned.
//!
//! Reference: Bitcoin Core `net_processing.cpp` Misbehaving() and `banman.cpp`

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::peer::PeerId;

/// Threshold at which a peer is banned.
pub const BAN_THRESHOLD: u32 = 100;

/// Default ban duration (24 hours).
pub const DEFAULT_BAN_DURATION: Duration = Duration::from_secs(24 * 60 * 60);

/// Misbehavior scores for various protocol violations.
/// Reference: Bitcoin Core net_processing.cpp
pub mod scores {
    /// Invalid block header (instant ban).
    pub const INVALID_BLOCK_HEADER: u32 = 100;
    /// Invalid block (instant ban).
    pub const INVALID_BLOCK: u32 = 100;
    /// Mutated block: merkle root mismatch or witness commitment mismatch (instant ban).
    /// Bitcoin Core: MaybePunishNodeForBlock BLOCK_MUTATED → Misbehaving(peer, "mutated-block").
    pub const MUTATED_BLOCK: u32 = 100;
    /// Invalid transaction.
    pub const INVALID_TRANSACTION: u32 = 10;
    /// Unsolicited message.
    pub const UNSOLICITED_MESSAGE: u32 = 20;
    /// Protocol violation (generic).
    pub const PROTOCOL_VIOLATION: u32 = 10;
    /// Invalid headers message.
    pub const INVALID_HEADERS: u32 = 100;
    /// Message too large.
    pub const MESSAGE_TOO_LARGE: u32 = 20;
    /// Duplicate block request.
    pub const DUPLICATE_BLOCK: u32 = 1;
    /// Invalid compact block.
    pub const INVALID_COMPACT_BLOCK: u32 = 100;
    /// Invalid addr message.
    pub const INVALID_ADDR: u32 = 20;
    /// Invalid inv message.
    pub const INVALID_INV: u32 = 20;
    /// Headers that don't connect to our chain.
    pub const HEADERS_DONT_CONNECT: u32 = 20;
    /// Block download stalling (peer not delivering requested blocks).
    pub const BLOCK_DOWNLOAD_STALL: u32 = 50;
    /// Sending unrequested data (blocks/txns we didn't ask for).
    pub const UNREQUESTED_DATA: u32 = 5;
}

/// Reason for misbehavior (for logging and debugging).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MisbehaviorReason {
    /// Invalid block header received.
    InvalidBlockHeader,
    /// Invalid block received.
    InvalidBlock,
    /// Mutated block received: merkle root mismatch, witness commitment mismatch,
    /// unexpected witness data, or bad witness nonce size.
    /// Bitcoin Core: MaybePunishNodeForBlock BLOCK_MUTATED → Misbehaving(peer, "mutated-block").
    MutatedBlock,
    /// Invalid transaction received.
    InvalidTransaction,
    /// Unsolicited block/transaction.
    UnsolicitedMessage,
    /// Generic protocol violation.
    ProtocolViolation(String),
    /// Invalid headers message.
    InvalidHeaders,
    /// Message exceeds size limits.
    MessageTooLarge,
    /// Duplicate block announcement.
    DuplicateBlock,
    /// Invalid compact block.
    InvalidCompactBlock,
    /// Invalid addr message.
    InvalidAddr,
    /// Invalid inv message.
    InvalidInv,
    /// Headers that don't connect to our chain.
    HeadersDontConnect,
    /// Block download stalling.
    BlockDownloadStall,
    /// Sending unrequested data.
    UnrequestedData,
}

impl MisbehaviorReason {
    /// Get the misbehavior score for this reason.
    pub fn score(&self) -> u32 {
        match self {
            MisbehaviorReason::InvalidBlockHeader => scores::INVALID_BLOCK_HEADER,
            MisbehaviorReason::InvalidBlock => scores::INVALID_BLOCK,
            MisbehaviorReason::MutatedBlock => scores::MUTATED_BLOCK,
            MisbehaviorReason::InvalidTransaction => scores::INVALID_TRANSACTION,
            MisbehaviorReason::UnsolicitedMessage => scores::UNSOLICITED_MESSAGE,
            MisbehaviorReason::ProtocolViolation(_) => scores::PROTOCOL_VIOLATION,
            MisbehaviorReason::InvalidHeaders => scores::INVALID_HEADERS,
            MisbehaviorReason::MessageTooLarge => scores::MESSAGE_TOO_LARGE,
            MisbehaviorReason::DuplicateBlock => scores::DUPLICATE_BLOCK,
            MisbehaviorReason::InvalidCompactBlock => scores::INVALID_COMPACT_BLOCK,
            MisbehaviorReason::InvalidAddr => scores::INVALID_ADDR,
            MisbehaviorReason::InvalidInv => scores::INVALID_INV,
            MisbehaviorReason::HeadersDontConnect => scores::HEADERS_DONT_CONNECT,
            MisbehaviorReason::BlockDownloadStall => scores::BLOCK_DOWNLOAD_STALL,
            MisbehaviorReason::UnrequestedData => scores::UNREQUESTED_DATA,
        }
    }
}

impl std::fmt::Display for MisbehaviorReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MisbehaviorReason::InvalidBlockHeader => write!(f, "bad-header"),
            MisbehaviorReason::InvalidBlock => write!(f, "invalid block"),
            MisbehaviorReason::MutatedBlock => write!(f, "mutated-block"),
            MisbehaviorReason::InvalidTransaction => write!(f, "invalid transaction"),
            MisbehaviorReason::UnsolicitedMessage => write!(f, "unsolicited message"),
            MisbehaviorReason::ProtocolViolation(msg) => write!(f, "protocol violation: {}", msg),
            MisbehaviorReason::InvalidHeaders => write!(f, "invalid headers"),
            MisbehaviorReason::MessageTooLarge => write!(f, "message too large"),
            MisbehaviorReason::DuplicateBlock => write!(f, "duplicate block"),
            MisbehaviorReason::InvalidCompactBlock => write!(f, "invalid compact block"),
            MisbehaviorReason::InvalidAddr => write!(f, "invalid addr message"),
            MisbehaviorReason::InvalidInv => write!(f, "invalid inv message"),
            MisbehaviorReason::HeadersDontConnect => write!(f, "headers don't connect"),
            MisbehaviorReason::BlockDownloadStall => write!(f, "block download stalling"),
            MisbehaviorReason::UnrequestedData => write!(f, "unrequested data"),
        }
    }
}

/// Per-peer misbehavior tracking.
///
/// Follows Bitcoin Core PR #25974 (2022): any Misbehaving() call sets
/// m_should_discourage = true immediately — no score accumulation to a
/// threshold.  The score field is retained for logging only.
#[derive(Debug, Clone)]
pub struct PeerMisbehavior {
    /// Accumulated misbehavior score (retained for log context only;
    /// NOT used to gate disconnection — any non-zero score discourages).
    pub score: u32,
    /// Set to true on the first Misbehaving() call — single-event model
    /// matching Core's m_should_discourage.
    pub should_discourage: bool,
}

impl Default for PeerMisbehavior {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerMisbehavior {
    /// Create new peer misbehavior tracker.
    pub fn new() -> Self {
        Self {
            score: 0,
            should_discourage: false,
        }
    }

    /// Record a misbehavior event. Sets should_discourage=true immediately
    /// (single-event model, Core PR #25974). Score is accumulated for logging.
    /// Always returns true — one call is always enough to discourage.
    pub fn add_score(&mut self, howmuch: u32) -> bool {
        self.score = self.score.saturating_add(howmuch);
        self.should_discourage = true;
        true
    }
}

/// Entry in the ban list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanEntry {
    /// Unix timestamp when the ban was created.
    pub ban_created: u64,
    /// Unix timestamp when the ban expires.
    pub ban_until: u64,
    /// Reason for the ban.
    pub reason: String,
}

impl BanEntry {
    /// Create a new ban entry.
    pub fn new(duration: Duration, reason: String) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Self {
            ban_created: now,
            ban_until: now + duration.as_secs(),
            reason,
        }
    }

    /// Check if this ban has expired.
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now >= self.ban_until
    }
}

/// Manages the persistent ban list.
///
/// Bans are stored by IP address (not port) following Bitcoin Core's approach.
/// The banlist is persisted to a JSON file.
#[derive(Debug)]
pub struct BanManager {
    /// Banned IPs with ban entries.
    banned: HashMap<IpAddr, BanEntry>,
    /// Path to the banlist file.
    banlist_path: PathBuf,
    /// Whether the banlist has been modified and needs saving.
    is_dirty: bool,
    /// Default ban duration.
    default_ban_duration: Duration,
}

impl BanManager {
    /// Create a new ban manager with the given data directory.
    pub fn new(data_dir: PathBuf) -> Self {
        let banlist_path = data_dir.join("banlist.json");
        let mut manager = Self {
            banned: HashMap::new(),
            banlist_path,
            is_dirty: false,
            default_ban_duration: DEFAULT_BAN_DURATION,
        };
        manager.load();
        manager
    }

    /// Create a ban manager with a custom ban duration.
    pub fn with_duration(data_dir: PathBuf, duration: Duration) -> Self {
        let mut manager = Self::new(data_dir);
        manager.default_ban_duration = duration;
        manager
    }

    /// Load the banlist from disk.
    fn load(&mut self) {
        if !self.banlist_path.exists() {
            return;
        }

        match File::open(&self.banlist_path) {
            Ok(file) => {
                let reader = BufReader::new(file);
                match serde_json::from_reader::<_, BanListFile>(reader) {
                    Ok(banlist) => {
                        self.banned = banlist
                            .entries
                            .into_iter()
                            .filter_map(|(ip_str, entry)| {
                                ip_str.parse::<IpAddr>().ok().map(|ip| (ip, entry))
                            })
                            .collect();
                        // Sweep expired bans
                        self.sweep_banned();
                        tracing::debug!(
                            "Loaded {} banned addresses from {}",
                            self.banned.len(),
                            self.banlist_path.display()
                        );
                    }
                    Err(e) => {
                        tracing::warn!("Failed to parse banlist: {}", e);
                        self.banned = HashMap::new();
                        self.is_dirty = true;
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to open banlist: {}", e);
            }
        }
    }

    /// Save the banlist to disk.
    pub fn save(&mut self) {
        if !self.is_dirty {
            return;
        }

        // Sweep expired bans before saving
        self.sweep_banned();

        let banlist = BanListFile {
            entries: self
                .banned
                .iter()
                .map(|(ip, entry)| (ip.to_string(), entry.clone()))
                .collect(),
        };

        // Create parent directories if needed
        if let Some(parent) = self.banlist_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        match File::create(&self.banlist_path) {
            Ok(file) => {
                let writer = BufWriter::new(file);
                if let Err(e) = serde_json::to_writer_pretty(writer, &banlist) {
                    tracing::error!("Failed to write banlist: {}", e);
                } else {
                    self.is_dirty = false;
                    tracing::debug!(
                        "Saved {} banned addresses to {}",
                        self.banned.len(),
                        self.banlist_path.display()
                    );
                }
            }
            Err(e) => {
                tracing::error!("Failed to create banlist file: {}", e);
            }
        }
    }

    /// Ban an IP address.
    pub fn ban(&mut self, ip: IpAddr, duration: Duration, reason: String) {
        let entry = BanEntry::new(duration, reason);

        // Only update if new ban is longer than existing
        if let Some(existing) = self.banned.get(&ip) {
            if entry.ban_until <= existing.ban_until {
                return;
            }
        }

        self.banned.insert(ip, entry);
        self.is_dirty = true;
        self.save();
    }

    /// Ban a socket address (extracts IP, ignores port).
    pub fn ban_addr(&mut self, addr: SocketAddr, duration: Duration, reason: String) {
        self.ban(addr.ip(), duration, reason);
    }

    /// Ban using default duration.
    pub fn ban_default(&mut self, ip: IpAddr, reason: String) {
        self.ban(ip, self.default_ban_duration, reason);
    }

    /// Unban an IP address. Returns true if the IP was banned.
    pub fn unban(&mut self, ip: &IpAddr) -> bool {
        if self.banned.remove(ip).is_some() {
            self.is_dirty = true;
            self.save();
            true
        } else {
            false
        }
    }

    /// Check if an IP address is banned.
    pub fn is_banned(&self, ip: &IpAddr) -> bool {
        if let Some(entry) = self.banned.get(ip) {
            !entry.is_expired()
        } else {
            false
        }
    }

    /// Check if a socket address is banned.
    pub fn is_addr_banned(&self, addr: &SocketAddr) -> bool {
        self.is_banned(&addr.ip())
    }

    /// Get the ban entry for an IP if banned.
    pub fn get_ban(&self, ip: &IpAddr) -> Option<&BanEntry> {
        self.banned.get(ip).filter(|entry| !entry.is_expired())
    }

    /// Get all banned addresses.
    pub fn get_banned(&self) -> Vec<(IpAddr, &BanEntry)> {
        self.banned
            .iter()
            .filter(|(_, entry)| !entry.is_expired())
            .map(|(ip, entry)| (*ip, entry))
            .collect()
    }

    /// Remove expired bans.
    pub fn sweep_banned(&mut self) {
        let before = self.banned.len();
        self.banned.retain(|_, entry| !entry.is_expired());
        if self.banned.len() != before {
            self.is_dirty = true;
        }
    }

    /// Clear all bans.
    pub fn clear(&mut self) {
        self.banned.clear();
        self.is_dirty = true;
        self.save();
    }

    /// Number of banned IPs.
    pub fn len(&self) -> usize {
        self.banned.iter().filter(|(_, e)| !e.is_expired()).count()
    }

    /// Check if banlist is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Drop for BanManager {
    fn drop(&mut self) {
        self.save();
    }
}

/// File format for persisted banlist.
#[derive(Debug, Serialize, Deserialize)]
struct BanListFile {
    entries: HashMap<String, BanEntry>,
}

/// Misbehavior tracker for all peers.
#[derive(Debug, Default)]
pub struct MisbehaviorTracker {
    /// Per-peer misbehavior scores.
    peers: HashMap<PeerId, PeerMisbehavior>,
}

impl MisbehaviorTracker {
    /// Create a new misbehavior tracker.
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }

    /// Record misbehavior for a peer.
    ///
    /// Per Core PR #25974 (2022): always returns true — one Misbehaving call
    /// immediately sets should_discourage=true and triggers disconnection.
    pub fn misbehaving(&mut self, peer_id: PeerId, reason: MisbehaviorReason) -> bool {
        let score = reason.score();
        let peer = self.peers.entry(peer_id).or_default();
        peer.add_score(score);

        tracing::info!(
            "Misbehaving: peer={} score={} (+{}) reason={} (discouraging immediately)",
            peer_id.0,
            peer.score,
            score,
            reason
        );

        true
    }

    /// Record misbehavior with a custom score.
    ///
    /// Per Core PR #25974 (2022): always returns true — one Misbehaving call
    /// immediately sets should_discourage=true and triggers disconnection.
    pub fn misbehaving_with_score(
        &mut self,
        peer_id: PeerId,
        howmuch: u32,
        message: &str,
    ) -> bool {
        let peer = self.peers.entry(peer_id).or_default();
        peer.add_score(howmuch);

        let message_suffix = if message.is_empty() {
            String::new()
        } else {
            format!(": {}", message)
        };

        tracing::info!(
            "Misbehaving: peer={} score={} (+{}){}  (discouraging immediately)",
            peer_id.0,
            peer.score,
            howmuch,
            message_suffix
        );

        true
    }

    /// Get the current score for a peer.
    pub fn get_score(&self, peer_id: PeerId) -> u32 {
        self.peers.get(&peer_id).map(|p| p.score).unwrap_or(0)
    }

    /// Check if a peer should be discouraged (disconnected + banned).
    ///
    /// Returns true once any Misbehaving call has been recorded for this peer.
    pub fn should_disconnect(&self, peer_id: PeerId) -> bool {
        self.peers
            .get(&peer_id)
            .map(|p| p.should_discourage)
            .unwrap_or(false)
    }

    /// Remove tracking for a peer (on disconnect).
    pub fn remove_peer(&mut self, peer_id: PeerId) {
        self.peers.remove(&peer_id);
    }

    /// Clear all tracking data.
    pub fn clear(&mut self) {
        self.peers.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_peer_misbehavior_single_event_discourage() {
        // Core PR #25974 (2022): any Misbehaving call sets should_discourage=true
        // immediately, regardless of score value.
        let mut peer = PeerMisbehavior::new();
        assert_eq!(peer.score, 0);
        assert!(!peer.should_discourage);

        // A single low-score call must discourage immediately (not wait for 100).
        assert!(peer.add_score(10), "first add_score must return true (single-event)");
        assert_eq!(peer.score, 10);
        assert!(peer.should_discourage, "should_discourage must be true after first call");

        // Score accumulates for logging purposes.
        assert!(peer.add_score(50));
        assert_eq!(peer.score, 60);
        assert!(peer.should_discourage);

        assert!(peer.add_score(40));
        assert_eq!(peer.score, 100);
        assert!(peer.should_discourage);
    }

    #[test]
    fn test_peer_misbehavior_instant_ban() {
        let mut peer = PeerMisbehavior::new();

        // 100 points — discouraged immediately (same as any other value).
        assert!(peer.add_score(100));
        assert_eq!(peer.score, 100);
        assert!(peer.should_discourage);
    }

    #[test]
    fn test_misbehavior_tracker_multiple_peers() {
        let mut tracker = MisbehaviorTracker::new();
        let peer1 = PeerId(1);
        let peer2 = PeerId(2);

        // Peer 1: invalid transaction (10 points) — single-event: discouraged immediately.
        assert!(tracker.misbehaving(peer1, MisbehaviorReason::InvalidTransaction),
            "single-event: first Misbehaving call must return true");
        assert_eq!(tracker.get_score(peer1), 10);
        assert!(tracker.should_disconnect(peer1), "peer1 must be marked for discourage on first call");

        // Peer 2: invalid block header (instant ban).
        assert!(tracker.misbehaving(peer2, MisbehaviorReason::InvalidBlockHeader));
        assert_eq!(tracker.get_score(peer2), 100);
        assert!(tracker.should_disconnect(peer2));
    }

    #[test]
    fn test_misbehavior_tracker_remove_peer() {
        let mut tracker = MisbehaviorTracker::new();
        let peer_id = PeerId(1);

        tracker.misbehaving(peer_id, MisbehaviorReason::InvalidTransaction);
        assert_eq!(tracker.get_score(peer_id), 10);

        tracker.remove_peer(peer_id);
        assert_eq!(tracker.get_score(peer_id), 0);
    }

    #[test]
    fn test_ban_entry_expiration() {
        // Create a ban that expires immediately
        let entry = BanEntry::new(Duration::from_secs(0), "test".to_string());
        assert!(entry.is_expired());

        // Create a ban that lasts 1 hour
        let entry = BanEntry::new(Duration::from_secs(3600), "test".to_string());
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_ban_manager_ban_and_check() {
        let temp_dir = TempDir::new().unwrap();
        let mut manager = BanManager::new(temp_dir.path().to_path_buf());

        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        assert!(!manager.is_banned(&ip));

        manager.ban(ip, Duration::from_secs(3600), "test ban".to_string());

        assert!(manager.is_banned(&ip));

        let entry = manager.get_ban(&ip).unwrap();
        assert_eq!(entry.reason, "test ban");
    }

    #[test]
    fn test_ban_manager_unban() {
        let temp_dir = TempDir::new().unwrap();
        let mut manager = BanManager::new(temp_dir.path().to_path_buf());

        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        manager.ban(ip, Duration::from_secs(3600), "test".to_string());
        assert!(manager.is_banned(&ip));

        assert!(manager.unban(&ip));
        assert!(!manager.is_banned(&ip));

        // Unbanning non-banned IP returns false
        assert!(!manager.unban(&ip));
    }

    #[test]
    fn test_ban_manager_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Ban and save
        {
            let mut manager = BanManager::new(temp_dir.path().to_path_buf());
            manager.ban(ip, Duration::from_secs(3600), "test".to_string());
            // Drop triggers save
        }

        // Load and verify
        {
            let manager = BanManager::new(temp_dir.path().to_path_buf());
            assert!(manager.is_banned(&ip));
        }
    }

    #[test]
    fn test_ban_manager_get_banned() {
        let temp_dir = TempDir::new().unwrap();
        let mut manager = BanManager::new(temp_dir.path().to_path_buf());

        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();

        manager.ban(ip1, Duration::from_secs(3600), "test1".to_string());
        manager.ban(ip2, Duration::from_secs(3600), "test2".to_string());

        let banned = manager.get_banned();
        assert_eq!(banned.len(), 2);
    }

    #[test]
    fn test_ban_manager_clear() {
        let temp_dir = TempDir::new().unwrap();
        let mut manager = BanManager::new(temp_dir.path().to_path_buf());

        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        manager.ban(ip, Duration::from_secs(3600), "test".to_string());
        assert!(!manager.is_empty());

        manager.clear();
        assert!(manager.is_empty());
    }

    #[test]
    fn test_ban_manager_socket_addr() {
        let temp_dir = TempDir::new().unwrap();
        let mut manager = BanManager::new(temp_dir.path().to_path_buf());

        let addr: SocketAddr = "192.168.1.1:8333".parse().unwrap();
        let addr_different_port: SocketAddr = "192.168.1.1:48333".parse().unwrap();

        manager.ban_addr(addr, Duration::from_secs(3600), "test".to_string());

        // Both ports should be banned (ban is by IP)
        assert!(manager.is_addr_banned(&addr));
        assert!(manager.is_addr_banned(&addr_different_port));
    }

    #[test]
    fn test_misbehavior_reason_scores() {
        assert_eq!(MisbehaviorReason::InvalidBlockHeader.score(), 100);
        assert_eq!(MisbehaviorReason::InvalidBlock.score(), 100);
        assert_eq!(MisbehaviorReason::MutatedBlock.score(), 100);
        assert_eq!(MisbehaviorReason::InvalidTransaction.score(), 10);
        assert_eq!(MisbehaviorReason::UnsolicitedMessage.score(), 20);
        assert_eq!(MisbehaviorReason::ProtocolViolation("test".to_string()).score(), 10);
    }

    #[test]
    fn test_misbehavior_reason_display() {
        assert_eq!(
            MisbehaviorReason::InvalidBlockHeader.to_string(),
            "bad-header"
        );
        assert_eq!(
            MisbehaviorReason::MutatedBlock.to_string(),
            "mutated-block"
        );
        assert_eq!(
            MisbehaviorReason::ProtocolViolation("bad message".to_string()).to_string(),
            "protocol violation: bad message"
        );
    }

    #[test]
    fn test_misbehavior_tracker_with_custom_score() {
        let mut tracker = MisbehaviorTracker::new();
        let peer_id = PeerId(1);

        // Single-event: first call immediately triggers discourage, regardless of score.
        assert!(tracker.misbehaving_with_score(peer_id, 50, "custom reason"),
            "single-event: first misbehaving_with_score must return true");
        assert_eq!(tracker.get_score(peer_id), 50);
        assert!(tracker.should_disconnect(peer_id), "should_disconnect after first call");

        // Subsequent calls continue accumulating score for log context.
        assert!(tracker.misbehaving_with_score(peer_id, 50, "another reason"));
        assert_eq!(tracker.get_score(peer_id), 100);
        assert!(tracker.should_disconnect(peer_id));
    }

    /// Mirrors the listener-side ban-check used in `PeerManager::start`:
    /// re-read `banlist.json` directly and verify that an entry with a
    /// future `ban_until` correctly identifies a banned address, while
    /// expired or unrelated entries do not.  Closes the audit gap where
    /// the `PeerManager` has a `BanManager` but the spawn-only listener
    /// task had no way to consult it.
    #[test]
    fn test_listener_can_read_banlist_file() {
        let temp_dir = TempDir::new().unwrap();
        let banned_ip: IpAddr = "10.1.2.3".parse().unwrap();
        let other_ip: IpAddr = "10.4.5.6".parse().unwrap();

        // 1. Persist a banlist via the manager (matches what the
        //    misbehavior path does on threshold).
        {
            let mut mgr = BanManager::new(temp_dir.path().to_path_buf());
            mgr.ban(banned_ip, Duration::from_secs(3600), "test".to_string());
        }

        // 2. Re-read the banlist file directly, the way the listener
        //    accept loop does (the listener task runs in a spawned tokio
        //    task without `&mut self` access to the manager).
        let banlist_path = temp_dir.path().join("banlist.json");
        let f = File::open(&banlist_path).expect("banlist file should exist");
        let v: serde_json::Value = serde_json::from_reader(f).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let is_banned = |ip: &IpAddr| -> bool {
            v.get("entries")
                .and_then(|e| e.as_object())
                .map(|entries| {
                    entries.iter().any(|(ip_str, entry)| {
                        ip_str.parse::<IpAddr>().map(|p| p == *ip).unwrap_or(false)
                            && entry
                                .get("ban_until")
                                .and_then(|u| u.as_u64())
                                .map(|until| until > now)
                                .unwrap_or(false)
                    })
                })
                .unwrap_or(false)
        };

        assert!(
            is_banned(&banned_ip),
            "listener-side check should mark {} as banned",
            banned_ip
        );
        assert!(
            !is_banned(&other_ip),
            "unbanned IP {} must not match",
            other_ip
        );
    }

    /// Confirm that an expired entry on disk is treated as unbanned by the
    /// listener-side check — a banned IP after its ban window must be
    /// allowed to reconnect.
    #[test]
    fn test_listener_ban_check_respects_expiry() {
        let temp_dir = TempDir::new().unwrap();
        let banned_ip: IpAddr = "10.7.8.9".parse().unwrap();
        let banlist_path = temp_dir.path().join("banlist.json");

        // Hand-craft an expired-entry banlist, mirroring what the listener
        // would parse off disk.
        let mut entries = HashMap::new();
        entries.insert(
            banned_ip.to_string(),
            BanEntry {
                ban_created: 0,
                ban_until: 1, // long ago
                reason: "expired".to_string(),
            },
        );
        let banlist = BanListFile { entries };
        let f = File::create(&banlist_path).unwrap();
        serde_json::to_writer(f, &banlist).unwrap();

        // Same listener-side parser.
        let f = File::open(&banlist_path).unwrap();
        let v: serde_json::Value = serde_json::from_reader(f).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let still_banned = v
            .get("entries")
            .and_then(|e| e.as_object())
            .map(|entries| {
                entries.iter().any(|(ip_str, entry)| {
                    ip_str
                        .parse::<IpAddr>()
                        .map(|p| p == banned_ip)
                        .unwrap_or(false)
                        && entry
                            .get("ban_until")
                            .and_then(|u| u.as_u64())
                            .map(|until| until > now)
                            .unwrap_or(false)
                })
            })
            .unwrap_or(false);

        assert!(
            !still_banned,
            "expired ban must not block new connections"
        );
    }

    #[test]
    fn test_ban_manager_longer_ban_overwrites() {
        let temp_dir = TempDir::new().unwrap();
        let mut manager = BanManager::new(temp_dir.path().to_path_buf());

        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Short ban
        manager.ban(ip, Duration::from_secs(100), "short".to_string());
        let short_until = manager.get_ban(&ip).unwrap().ban_until;

        // Longer ban should overwrite
        manager.ban(ip, Duration::from_secs(1000), "long".to_string());
        let long_until = manager.get_ban(&ip).unwrap().ban_until;

        assert!(long_until > short_until);
        assert_eq!(manager.get_ban(&ip).unwrap().reason, "long");
    }

    #[test]
    fn test_ban_manager_shorter_ban_does_not_overwrite() {
        let temp_dir = TempDir::new().unwrap();
        let mut manager = BanManager::new(temp_dir.path().to_path_buf());

        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Long ban first
        manager.ban(ip, Duration::from_secs(1000), "long".to_string());
        let long_until = manager.get_ban(&ip).unwrap().ban_until;

        // Shorter ban should NOT overwrite
        manager.ban(ip, Duration::from_secs(100), "short".to_string());

        assert_eq!(manager.get_ban(&ip).unwrap().ban_until, long_until);
        assert_eq!(manager.get_ban(&ip).unwrap().reason, "long");
    }
}
