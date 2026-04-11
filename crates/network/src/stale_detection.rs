//! Stale peer detection and eviction.
//!
//! This module implements detection and disconnection of peers that are not
//! providing useful data. Based on Bitcoin Core's net_processing.cpp:
//!
//! - **Stale tip check**: If a peer's best known block is >30 minutes behind our
//!   tip and we have other peers with better chains, disconnect one stale peer
//!   every 45 seconds.
//!
//! - **Ping timeout**: Send ping messages every 2 minutes; if no pong is received
//!   within 20 minutes, disconnect.
//!
//! - **Headers timeout**: If we requested headers and got no response within
//!   2 minutes, mark the peer as misbehaving.
//!
//! - **Chain sync timeout**: If an outbound peer's best known block has less
//!   chainwork than our tip for 20 minutes, send getheaders. If still behind
//!   after another 2 minutes, disconnect (unless protected).

use crate::peer::PeerId;
use std::time::Duration;
use tokio::time::Instant;

// ============================================================
// CONSTANTS (from Bitcoin Core net_processing.cpp)
// ============================================================

/// How frequently to check for stale tips.
/// Bitcoin Core: 10 minutes
pub const STALE_CHECK_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// How frequently to check for extra outbound peers and disconnect.
/// Bitcoin Core: 45 seconds. Must be less than STALE_CHECK_INTERVAL.
pub const EXTRA_PEER_CHECK_INTERVAL: Duration = Duration::from_secs(45);

/// Timeout for (unprotected) outbound peers to sync to our chainwork.
/// Bitcoin Core: 20 minutes
pub const CHAIN_SYNC_TIMEOUT: Duration = Duration::from_secs(20 * 60);

/// How long to wait for a peer to respond to a getheaders request.
/// Bitcoin Core: 2 minutes
pub const HEADERS_RESPONSE_TIME: Duration = Duration::from_secs(2 * 60);


/// Ping timeout: disconnect if pong not received within this time.
/// Bitcoin Core: 20 minutes (configurable via -peertimeout)
pub const PING_TIMEOUT_INTERVAL: Duration = Duration::from_secs(20 * 60);

/// Minimum time an outbound peer must be connected before eviction is considered.
/// Bitcoin Core: 30 seconds
pub const MINIMUM_CONNECT_TIME: Duration = Duration::from_secs(30);

/// Maximum number of outbound peers to protect from disconnection due to
/// slow/behind headers chain.
/// Bitcoin Core: 4
pub const MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT: usize = 4;

/// Threshold for considering the tip stale (3 * target block spacing).
/// For Bitcoin: 3 * 10 minutes = 30 minutes
pub const STALE_TIP_THRESHOLD: Duration = Duration::from_secs(30 * 60);

// ============================================================
// CHAIN SYNC STATE
// ============================================================

/// State used to enforce chain sync timeout logic.
///
/// From Bitcoin Core: This tracks whether an outbound peer is keeping up with
/// our chain. If they fall behind and don't catch up within the timeout,
/// we disconnect them (unless they're protected).
#[derive(Debug, Clone)]
pub struct ChainSyncState {
    /// Absolute time when the timeout expires. None if no timeout is active.
    pub timeout: Option<Instant>,

    /// Our tip's height when the timeout was set.
    /// The peer must reach at least this height to clear the timeout.
    pub work_header_height: Option<u32>,

    /// Whether we've sent a getheaders request after the initial timeout.
    pub sent_getheaders: bool,

    /// Whether this peer is protected from eviction.
    /// Up to MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT peers with
    /// valid headers and good chainwork are protected.
    pub protected: bool,
}

impl Default for ChainSyncState {
    fn default() -> Self {
        Self::new()
    }
}

impl ChainSyncState {
    /// Create a new chain sync state with no active timeout.
    pub fn new() -> Self {
        Self {
            timeout: None,
            work_header_height: None,
            sent_getheaders: false,
            protected: false,
        }
    }

    /// Set a timeout for chain sync.
    pub fn set_timeout(&mut self, our_tip_height: u32, duration: Duration) {
        self.timeout = Some(Instant::now() + duration);
        self.work_header_height = Some(our_tip_height);
        self.sent_getheaders = false;
    }

    /// Clear the timeout (peer caught up).
    pub fn clear_timeout(&mut self) {
        self.timeout = None;
        self.work_header_height = None;
        self.sent_getheaders = false;
    }

    /// Check if the timeout has expired.
    pub fn is_timed_out(&self) -> bool {
        self.timeout.is_some_and(|t| Instant::now() >= t)
    }

    /// Check if the peer has caught up to the required height.
    pub fn has_caught_up(&self, peer_best_height: u32) -> bool {
        self.work_header_height
            .is_none_or(|h| peer_best_height >= h)
    }
}

// ============================================================
// STALE PEER STATE
// ============================================================

/// Per-peer state for stale detection.
#[derive(Debug, Clone)]
pub struct StalePeerState {
    /// Chain sync timeout tracking.
    pub chain_sync: ChainSyncState,

    /// Peer's best known block height.
    pub best_known_height: i32,

    /// Time of last block received from this peer.
    pub last_block_time: Option<Instant>,

    /// Time of last transaction received from this peer.
    pub last_tx_time: Option<Instant>,

    /// Time when ping was sent (for timeout tracking).
    pub ping_start: Option<Instant>,

    /// Whether a ping is currently outstanding.
    pub ping_nonce_sent: bool,

    /// Time of last headers request sent to this peer.
    pub last_getheaders_time: Option<Instant>,
}

impl Default for StalePeerState {
    fn default() -> Self {
        Self::new()
    }
}

impl StalePeerState {
    /// Create a new stale peer state.
    pub fn new() -> Self {
        Self {
            chain_sync: ChainSyncState::new(),
            best_known_height: 0,
            last_block_time: None,
            last_tx_time: None,
            ping_start: None,
            ping_nonce_sent: false,
            last_getheaders_time: None,
        }
    }

    /// Check if the peer has timed out on a ping.
    pub fn is_ping_timed_out(&self) -> bool {
        if !self.ping_nonce_sent {
            return false;
        }
        self.ping_start
            .is_some_and(|start| start.elapsed() > PING_TIMEOUT_INTERVAL)
    }

    /// Record that a ping was sent.
    pub fn ping_sent(&mut self) {
        self.ping_start = Some(Instant::now());
        self.ping_nonce_sent = true;
    }

    /// Record that a pong was received.
    pub fn pong_received(&mut self) {
        self.ping_nonce_sent = false;
    }

    /// Record that a block was received.
    pub fn block_received(&mut self, height: i32) {
        self.last_block_time = Some(Instant::now());
        if height > self.best_known_height {
            self.best_known_height = height;
        }
    }

    /// Record that a transaction was received.
    pub fn tx_received(&mut self) {
        self.last_tx_time = Some(Instant::now());
    }

    /// Record that headers were requested.
    pub fn getheaders_sent(&mut self) {
        self.last_getheaders_time = Some(Instant::now());
        self.chain_sync.sent_getheaders = true;
    }

    /// Check if headers response has timed out.
    pub fn is_headers_timed_out(&self) -> bool {
        if !self.chain_sync.sent_getheaders {
            return false;
        }
        self.last_getheaders_time
            .is_some_and(|t| t.elapsed() > HEADERS_RESPONSE_TIME)
    }

    /// Update best known height from headers.
    pub fn headers_received(&mut self, best_height: i32) {
        if best_height > self.best_known_height {
            self.best_known_height = best_height;
        }
        // Don't clear sent_getheaders here - that's done when chain sync catches up
    }
}

// ============================================================
// STALE PEER DETECTOR
// ============================================================

/// Result of checking for stale peers.
#[derive(Debug, Clone)]
pub struct StaleCheckResult {
    /// Peers to disconnect due to ping timeout.
    pub ping_timeouts: Vec<PeerId>,

    /// Peers to disconnect due to chain sync failure.
    pub chain_sync_failures: Vec<PeerId>,

    /// Peers to send getheaders to (chain sync warning).
    pub send_getheaders_to: Vec<PeerId>,

    /// Whether our tip may be stale (need extra outbound peer).
    pub tip_may_be_stale: bool,
}

impl Default for StaleCheckResult {
    fn default() -> Self {
        Self::new()
    }
}

impl StaleCheckResult {
    /// Create an empty result.
    pub fn new() -> Self {
        Self {
            ping_timeouts: Vec::new(),
            chain_sync_failures: Vec::new(),
            send_getheaders_to: Vec::new(),
            tip_may_be_stale: false,
        }
    }

    /// Check if any action is needed.
    pub fn has_actions(&self) -> bool {
        !self.ping_timeouts.is_empty()
            || !self.chain_sync_failures.is_empty()
            || !self.send_getheaders_to.is_empty()
    }
}

/// Tracks stale peer detection state across all peers.
#[derive(Debug)]
pub struct StalePeerDetector {
    /// Last time we checked for stale tips.
    last_stale_tip_check: Instant,

    /// Last time we updated our tip (received a new block).
    last_tip_update: Instant,

    /// Our current tip height.
    our_tip_height: u32,

    /// Number of protected outbound peers.
    protected_count: usize,

    /// Whether we should try to add an extra outbound peer.
    try_extra_outbound: bool,
}

impl Default for StalePeerDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl StalePeerDetector {
    /// Create a new stale peer detector.
    pub fn new() -> Self {
        Self {
            last_stale_tip_check: Instant::now(),
            last_tip_update: Instant::now(),
            our_tip_height: 0,
            protected_count: 0,
            try_extra_outbound: false,
        }
    }

    /// Update our tip height (called when we connect a new block).
    pub fn update_tip(&mut self, height: u32) {
        self.our_tip_height = height;
        self.last_tip_update = Instant::now();
        // Clear the flag since we have a new tip
        self.try_extra_outbound = false;
    }

    /// Get our current tip height.
    pub fn our_tip_height(&self) -> u32 {
        self.our_tip_height
    }

    /// Check if our tip may be stale.
    ///
    /// Returns true if we haven't received a new block in STALE_TIP_THRESHOLD
    /// and there are no blocks in flight.
    pub fn tip_may_be_stale(&self, blocks_in_flight: usize) -> bool {
        if blocks_in_flight > 0 {
            return false;
        }
        self.last_tip_update.elapsed() > STALE_TIP_THRESHOLD
    }

    /// Check if it's time to run the stale tip check.
    pub fn should_check_stale_tips(&self) -> bool {
        self.last_stale_tip_check.elapsed() >= STALE_CHECK_INTERVAL
    }

    /// Record that we ran the stale tip check.
    pub fn mark_stale_tip_checked(&mut self) {
        self.last_stale_tip_check = Instant::now();
    }

    /// Check if we should try to add an extra outbound peer.
    pub fn should_try_extra_outbound(&self) -> bool {
        self.try_extra_outbound
    }

    /// Set whether we should try to add an extra outbound peer.
    pub fn set_try_extra_outbound(&mut self, try_extra: bool) {
        self.try_extra_outbound = try_extra;
    }

    /// Check a peer's chain sync state and update accordingly.
    ///
    /// Returns the action to take:
    /// - None: peer is fine
    /// - Some(true): send getheaders
    /// - Some(false): disconnect
    pub fn check_chain_sync(
        &mut self,
        peer_state: &mut StalePeerState,
        is_outbound: bool,
        is_protected: bool,
    ) -> Option<bool> {
        // Only check outbound peers
        if !is_outbound {
            return None;
        }

        let peer_height = peer_state.best_known_height as u32;
        let our_height = self.our_tip_height;

        // If peer is caught up, clear any timeout
        if peer_height >= our_height {
            if peer_state.chain_sync.timeout.is_some() {
                peer_state.chain_sync.clear_timeout();
            }
            return None;
        }

        // Peer is behind - check timeout
        if peer_state.chain_sync.timeout.is_none() {
            // No timeout yet - set one
            peer_state.chain_sync.set_timeout(our_height, CHAIN_SYNC_TIMEOUT);
            return None;
        }

        if !peer_state.chain_sync.is_timed_out() {
            // Timeout not expired yet
            return None;
        }

        // Timeout expired - check if peer caught up to the old target
        if peer_state.chain_sync.has_caught_up(peer_height) {
            // They caught up to what we required, but we've advanced.
            // Reset timeout with new target.
            peer_state.chain_sync.set_timeout(our_height, CHAIN_SYNC_TIMEOUT);
            return None;
        }

        // Still behind the old target
        if !peer_state.chain_sync.sent_getheaders {
            // First timeout: send getheaders and set shorter timeout
            peer_state.getheaders_sent();
            peer_state
                .chain_sync
                .timeout = Some(Instant::now() + HEADERS_RESPONSE_TIME);
            return Some(true); // Send getheaders
        }

        // Second timeout (after getheaders): disconnect unless protected
        if is_protected {
            // Reset and try again
            peer_state.chain_sync.set_timeout(our_height, CHAIN_SYNC_TIMEOUT);
            return None;
        }

        Some(false) // Disconnect
    }

    /// Try to mark a peer as protected.
    ///
    /// Returns true if the peer was marked as protected.
    pub fn try_protect_peer(&mut self, state: &mut StalePeerState) -> bool {
        if state.chain_sync.protected {
            return true; // Already protected
        }

        if self.protected_count >= MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT {
            return false; // Too many protected peers
        }

        // Must have good chainwork (at or near our tip)
        if (state.best_known_height as u32) + 6 < self.our_tip_height {
            return false;
        }

        state.chain_sync.protected = true;
        self.protected_count += 1;
        true
    }

    /// Unprotect a peer (e.g., when disconnected).
    pub fn unprotect_peer(&mut self, state: &mut StalePeerState) {
        if state.chain_sync.protected {
            state.chain_sync.protected = false;
            self.protected_count = self.protected_count.saturating_sub(1);
        }
    }

    /// Get the number of protected peers.
    pub fn protected_count(&self) -> usize {
        self.protected_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants_match_bitcoin_core() {
        // Verify our constants match Bitcoin Core
        assert_eq!(STALE_CHECK_INTERVAL, Duration::from_secs(600)); // 10 min
        assert_eq!(EXTRA_PEER_CHECK_INTERVAL, Duration::from_secs(45)); // 45 sec
        assert_eq!(CHAIN_SYNC_TIMEOUT, Duration::from_secs(1200)); // 20 min
        assert_eq!(HEADERS_RESPONSE_TIME, Duration::from_secs(120)); // 2 min
        // PING_INTERVAL is defined in peer.rs, also 2 min (matches Bitcoin Core)
        assert_eq!(PING_TIMEOUT_INTERVAL, Duration::from_secs(1200)); // 20 min
        assert_eq!(MINIMUM_CONNECT_TIME, Duration::from_secs(30)); // 30 sec
        assert_eq!(MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT, 4);
        assert_eq!(STALE_TIP_THRESHOLD, Duration::from_secs(1800)); // 30 min

        // Extra peer check must be less than stale tip check (Bitcoin Core assertion)
        assert!(EXTRA_PEER_CHECK_INTERVAL < STALE_CHECK_INTERVAL);
    }

    #[test]
    fn test_chain_sync_state_new() {
        let state = ChainSyncState::new();
        assert!(state.timeout.is_none());
        assert!(state.work_header_height.is_none());
        assert!(!state.sent_getheaders);
        assert!(!state.protected);
    }

    #[test]
    fn test_chain_sync_set_and_clear_timeout() {
        let mut state = ChainSyncState::new();

        state.set_timeout(100, Duration::from_secs(60));
        assert!(state.timeout.is_some());
        assert_eq!(state.work_header_height, Some(100));
        assert!(!state.sent_getheaders);

        state.clear_timeout();
        assert!(state.timeout.is_none());
        assert!(state.work_header_height.is_none());
    }

    #[test]
    fn test_chain_sync_has_caught_up() {
        let mut state = ChainSyncState::new();

        // No target set - always caught up
        assert!(state.has_caught_up(50));

        // Set target at 100
        state.work_header_height = Some(100);

        assert!(!state.has_caught_up(50));
        assert!(!state.has_caught_up(99));
        assert!(state.has_caught_up(100));
        assert!(state.has_caught_up(150));
    }

    #[test]
    fn test_stale_peer_state_ping_timeout() {
        let mut state = StalePeerState::new();

        // No ping sent - not timed out
        assert!(!state.is_ping_timed_out());

        // Send ping
        state.ping_sent();
        assert!(state.ping_nonce_sent);

        // Not timed out yet (just sent)
        assert!(!state.is_ping_timed_out());

        // Receive pong
        state.pong_received();
        assert!(!state.ping_nonce_sent);
        assert!(!state.is_ping_timed_out());
    }

    #[test]
    fn test_stale_peer_state_block_received() {
        let mut state = StalePeerState::new();
        assert_eq!(state.best_known_height, 0);
        assert!(state.last_block_time.is_none());

        state.block_received(100);
        assert_eq!(state.best_known_height, 100);
        assert!(state.last_block_time.is_some());

        // Lower height doesn't update best_known_height
        state.block_received(50);
        assert_eq!(state.best_known_height, 100);
    }

    #[test]
    fn test_stale_peer_state_headers_timeout() {
        let mut state = StalePeerState::new();

        // No getheaders sent - not timed out
        assert!(!state.is_headers_timed_out());

        // Send getheaders
        state.getheaders_sent();
        assert!(state.chain_sync.sent_getheaders);

        // Not timed out yet (just sent)
        assert!(!state.is_headers_timed_out());
    }

    #[test]
    fn test_stale_peer_detector_new() {
        let detector = StalePeerDetector::new();
        assert_eq!(detector.our_tip_height(), 0);
        assert_eq!(detector.protected_count(), 0);
        assert!(!detector.should_try_extra_outbound());
    }

    #[test]
    fn test_stale_peer_detector_update_tip() {
        let mut detector = StalePeerDetector::new();
        detector.set_try_extra_outbound(true);
        assert!(detector.should_try_extra_outbound());

        detector.update_tip(100);
        assert_eq!(detector.our_tip_height(), 100);
        assert!(!detector.should_try_extra_outbound()); // Cleared on tip update
    }

    #[test]
    fn test_stale_peer_detector_tip_may_be_stale() {
        let detector = StalePeerDetector::new();

        // With blocks in flight - not stale
        assert!(!detector.tip_may_be_stale(1));

        // Without blocks in flight but tip just updated - not stale
        assert!(!detector.tip_may_be_stale(0));
    }

    #[test]
    fn test_stale_peer_detector_protection() {
        let mut detector = StalePeerDetector::new();
        detector.update_tip(100);

        let mut state = StalePeerState::new();
        state.best_known_height = 100;

        // Protect first peer
        assert!(detector.try_protect_peer(&mut state));
        assert!(state.chain_sync.protected);
        assert_eq!(detector.protected_count(), 1);

        // Can't protect again
        assert!(detector.try_protect_peer(&mut state)); // Returns true (already protected)
        assert_eq!(detector.protected_count(), 1);

        // Unprotect
        detector.unprotect_peer(&mut state);
        assert!(!state.chain_sync.protected);
        assert_eq!(detector.protected_count(), 0);
    }

    #[test]
    fn test_stale_peer_detector_max_protection() {
        let mut detector = StalePeerDetector::new();
        detector.update_tip(100);

        // Protect maximum number of peers
        for _ in 0..MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT {
            let mut state = StalePeerState::new();
            state.best_known_height = 100;
            assert!(detector.try_protect_peer(&mut state));
        }

        assert_eq!(
            detector.protected_count(),
            MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT
        );

        // Can't protect more
        let mut state = StalePeerState::new();
        state.best_known_height = 100;
        assert!(!detector.try_protect_peer(&mut state));
    }

    #[test]
    fn test_stale_peer_detector_protection_requires_good_chainwork() {
        let mut detector = StalePeerDetector::new();
        detector.update_tip(100);

        let mut state = StalePeerState::new();
        state.best_known_height = 50; // Too far behind

        // Can't protect peer with bad chainwork
        assert!(!detector.try_protect_peer(&mut state));
        assert!(!state.chain_sync.protected);
    }

    #[test]
    fn test_check_chain_sync_inbound_ignored() {
        let mut detector = StalePeerDetector::new();
        detector.update_tip(100);

        let mut state = StalePeerState::new();
        state.best_known_height = 50; // Behind

        // Inbound peers are not checked
        let action = detector.check_chain_sync(&mut state, false, false);
        assert!(action.is_none());
    }

    #[test]
    fn test_check_chain_sync_caught_up() {
        let mut detector = StalePeerDetector::new();
        detector.update_tip(100);

        let mut state = StalePeerState::new();
        state.best_known_height = 100; // At tip

        // Caught up - no action
        let action = detector.check_chain_sync(&mut state, true, false);
        assert!(action.is_none());
    }

    #[test]
    fn test_check_chain_sync_behind_sets_timeout() {
        let mut detector = StalePeerDetector::new();
        detector.update_tip(100);

        let mut state = StalePeerState::new();
        state.best_known_height = 50; // Behind

        // First check sets timeout
        let action = detector.check_chain_sync(&mut state, true, false);
        assert!(action.is_none());
        assert!(state.chain_sync.timeout.is_some());
        assert_eq!(state.chain_sync.work_header_height, Some(100));
    }

    #[test]
    fn test_stale_check_result() {
        let result = StaleCheckResult::new();
        assert!(!result.has_actions());

        let mut result = StaleCheckResult::new();
        result.ping_timeouts.push(PeerId(1));
        assert!(result.has_actions());
    }

    #[test]
    fn test_stale_peer_state_tx_received() {
        let mut state = StalePeerState::new();
        assert!(state.last_tx_time.is_none());

        state.tx_received();
        assert!(state.last_tx_time.is_some());
    }
}
