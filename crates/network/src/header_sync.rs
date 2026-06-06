//! Header-first synchronization protocol.
//!
//! This module implements Bitcoin's headers-first sync strategy (introduced in
//! Bitcoin Core 0.10). The protocol:
//!
//! 1. Download all block headers before requesting full blocks
//! 2. Validate proof-of-work on headers as they arrive
//! 3. Only download full blocks for headers that form a valid chain
//!
//! This prevents wasting bandwidth downloading blocks on an invalid chain.

use crate::message::{GetHeadersMessage, NetworkMessage, PROTOCOL_VERSION};
use crate::peer::PeerId;
use rustoshi_primitives::{BlockHeader, Hash256};
use std::collections::HashMap;

/// The maximum number of headers to request in a single getheaders message.
pub const MAX_HEADERS_PER_REQUEST: usize = 2000;

/// Maximum number of unconnecting-headers messages a single peer may send
/// before we disconnect (and ban). Mirrors Bitcoin Core's
/// `MAX_NUM_UNCONNECTING_HEADERS_MSGS` from `net_processing.cpp`. Tolerates
/// honest peers caught in a transient reorg while still bounding the
/// adversarial DoS surface.
pub const MAX_NUM_UNCONNECTING_HEADERS_MSGS: u32 = 10;

/// Sync state for header downloading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncState {
    /// Not syncing, up to date.
    Idle,
    /// Downloading headers from a peer.
    DownloadingHeaders { peer: PeerId, last_hash: Hash256 },
    /// Headers synced, downloading blocks.
    DownloadingBlocks,
    /// Fully synchronized.
    InSync,
}

/// Header synchronization manager.
///
/// Manages the process of downloading and validating block headers from peers.
/// Headers are validated for proof-of-work and chain connectivity as they arrive.
///
/// **Important**: The header tip must be tracked separately from the chain tip
/// (fully validated blocks) in the database. Headers can be thousands of blocks
/// ahead of fully validated blocks.
pub struct HeaderSync {
    state: SyncState,
    /// Our best header chain height.
    best_header_height: u32,
    /// Our best header hash.
    best_header_hash: Hash256,
    /// Per-peer: their announced best height.
    peer_heights: HashMap<PeerId, i32>,
    /// Per-peer counter of consecutive unconnecting-headers messages.
    /// Reset to 0 whenever the peer sends a connecting headers message.
    /// When the counter would exceed `MAX_NUM_UNCONNECTING_HEADERS_MSGS`,
    /// the peer is disconnected. Mirrors Core's
    /// `nUnconnectingHeaders` (net_processing.cpp).
    unconnecting_headers: HashMap<PeerId, u32>,
}

impl HeaderSync {
    /// Create a new header sync manager.
    ///
    /// # Arguments
    /// * `genesis_hash` - The genesis block hash for this network
    pub fn new(genesis_hash: Hash256) -> Self {
        Self {
            state: SyncState::Idle,
            best_header_height: 0,
            best_header_hash: genesis_hash,
            peer_heights: HashMap::new(),
            unconnecting_headers: HashMap::new(),
        }
    }

    /// Register a new peer and its announced best height.
    ///
    /// Called when a peer connects and sends their version message.
    pub fn register_peer(&mut self, peer_id: PeerId, height: i32) {
        self.peer_heights.insert(peer_id, height);
    }

    /// Record an observed best height for a peer, raising (never lowering) the
    /// tracked value.
    ///
    /// `register_peer` only ever runs at handshake, seeding `peer_heights` from
    /// the version message's `start_height`. As the chain grows, that seed goes
    /// stale: a peer that keeps announcing new blocks (via `headers`/`inv`)
    /// still shows its handshake height, so once our own `best_header_height`
    /// climbs past it, `best_sync_peer` filters the peer out
    /// (`best_sync_peer` keeps only peers with `h > best_header_height`).
    ///
    /// This mirrors Bitcoin Core's per-peer `pindexBestKnownBlock`, which is
    /// advanced by `UpdateBlockAvailability`/`ProcessBlockAvailability`
    /// (`net_processing.cpp`) as new headers and block invs arrive — and is
    /// only ever raised ("An actually better block was announced"), never
    /// lowered. We keep the same monotonic semantics here: a peer's tracked
    /// height only goes up, so a transient lower observation can't drop a peer
    /// out of the sync-candidate set.
    pub fn note_peer_height(&mut self, peer_id: PeerId, height: i32) {
        let entry = self.peer_heights.entry(peer_id).or_insert(height);
        if height > *entry {
            *entry = height;
        }
    }

    /// Number of registered peers.
    pub fn peer_count(&self) -> usize {
        self.peer_heights.len()
    }

    /// Remove a disconnected peer.
    ///
    /// If we were syncing from this peer, reset state to Idle so we can
    /// pick a new sync peer.
    pub fn remove_peer(&mut self, peer_id: PeerId) {
        self.peer_heights.remove(&peer_id);
        self.unconnecting_headers.remove(&peer_id);
        // If we were syncing from this peer, reset state
        if let SyncState::DownloadingHeaders { peer, .. } = &self.state {
            if *peer == peer_id {
                self.state = SyncState::Idle;
            }
        }
    }

    /// Increment the unconnecting-headers counter for `peer_id` and return
    /// `true` if the counter has exceeded `MAX_NUM_UNCONNECTING_HEADERS_MSGS`,
    /// meaning the caller MUST disconnect (and may ban) the peer. Returns
    /// `false` to indicate the counter is still under the bound — the caller
    /// should re-issue `getheaders` to attempt to reconnect the chain rather
    /// than disconnecting.
    ///
    /// Mirrors Bitcoin Core's `nUnconnectingHeaders` accounting in
    /// `net_processing.cpp::ProcessHeadersMessage` (HEADERS handler).
    pub fn note_unconnecting_headers(&mut self, peer_id: PeerId) -> bool {
        let count = self.unconnecting_headers.entry(peer_id).or_insert(0);
        *count += 1;
        *count > MAX_NUM_UNCONNECTING_HEADERS_MSGS
    }

    /// Reset the unconnecting-headers counter for `peer_id` (typically called
    /// when a peer sends a properly-connecting headers message). Mirrors
    /// Core's `nUnconnectingHeaders = 0` in the same handler.
    pub fn reset_unconnecting_headers(&mut self, peer_id: PeerId) {
        self.unconnecting_headers.remove(&peer_id);
    }

    /// Read the current unconnecting-headers count for `peer_id`. Used by tests.
    #[cfg(test)]
    pub fn unconnecting_headers_count(&self, peer_id: PeerId) -> u32 {
        self.unconnecting_headers.get(&peer_id).copied().unwrap_or(0)
    }

    /// Read the currently tracked best height for `peer_id`. Used by tests.
    #[cfg(test)]
    pub fn peer_height(&self, peer_id: PeerId) -> Option<i32> {
        self.peer_heights.get(&peer_id).copied()
    }

    /// Choose the best peer to sync headers from.
    ///
    /// Returns the peer with the highest announced height that's greater
    /// than our current best header height.
    pub fn best_sync_peer(&self) -> Option<PeerId> {
        self.peer_heights
            .iter()
            .max_by_key(|(_, h)| *h)
            .filter(|(_, h)| **h > self.best_header_height as i32)
            .map(|(id, _)| *id)
    }

    /// Build a block locator for getheaders.
    ///
    /// A block locator contains hashes starting from the tip and going back
    /// with exponentially increasing step sizes:
    /// - Include the most recent 10 hashes (step = 1)
    /// - Then double the step size each time
    /// - Always include the genesis hash as the last entry
    ///
    /// This pattern allows efficient communication of which chain the node
    /// knows about. A locator for height 800,000 has only about 30 entries.
    ///
    /// # Arguments
    /// * `get_hash_at_height` - Function to retrieve the block hash at a given height
    pub fn build_block_locator<F>(&self, get_hash_at_height: F) -> Vec<Hash256>
    where
        F: Fn(u32) -> Option<Hash256>,
    {
        let mut locator = Vec::new();
        let mut height = self.best_header_height;
        let mut step = 1u32;

        loop {
            if let Some(hash) = get_hash_at_height(height) {
                locator.push(hash);
            }

            if height == 0 {
                break;
            }

            // Increase step size after first 10 entries
            if locator.len() >= 10 {
                step *= 2;
            }

            if height >= step {
                height -= step;
            } else {
                height = 0;
            }
        }

        locator
    }

    /// Create a getheaders request message.
    ///
    /// # Arguments
    /// * `get_hash_at_height` - Function to retrieve the block hash at a given height
    pub fn make_getheaders<F>(&self, get_hash_at_height: F) -> GetHeadersMessage
    where
        F: Fn(u32) -> Option<Hash256>,
    {
        GetHeadersMessage {
            version: PROTOCOL_VERSION as u32,
            locator_hashes: self.build_block_locator(get_hash_at_height),
            hash_stop: Hash256::ZERO,
        }
    }

    /// Start header sync by sending getheaders to the best peer.
    ///
    /// Returns the peer to send to and the message to send, or None if
    /// no suitable sync peer is available.
    ///
    /// # Arguments
    /// * `get_hash_at_height` - Function to retrieve the block hash at a given height
    pub fn start_sync<F>(&mut self, get_hash_at_height: F) -> Option<(PeerId, NetworkMessage)>
    where
        F: Fn(u32) -> Option<Hash256>,
    {
        if let Some(peer_id) = self.best_sync_peer() {
            let msg = self.make_getheaders(get_hash_at_height);
            self.state = SyncState::DownloadingHeaders {
                peer: peer_id,
                last_hash: self.best_header_hash,
            };
            Some((peer_id, NetworkMessage::GetHeaders(msg)))
        } else {
            None
        }
    }

    /// Process received headers.
    ///
    /// Validates header chain connectivity and proof-of-work, then calls the
    /// provided closure to store each header.
    ///
    /// When the first header's prev_hash doesn't match our tip (e.g. after a
    /// reorg or if we're on a stale fork), `find_hash_height` is consulted.
    /// If the prev_hash exists in our chain at some earlier height, we rewind
    /// our header tip to that fork point and accept the new headers. This
    /// mirrors Bitcoin Core's `FindForkInGlobalIndex` behavior.
    ///
    /// # Arguments
    /// * `peer_id` - The peer that sent the headers
    /// * `headers` - The received headers
    /// * `validate_and_store` - Callback to validate and store each header
    /// * `find_hash_height` - Given a block hash, returns its height if it's in our chain
    ///
    /// # Returns
    /// - `Ok(true)` if we should request more headers (received MAX_HEADERS)
    /// - `Ok(false)` if sync is complete (received fewer than MAX_HEADERS)
    /// - `Err` if headers are invalid
    pub fn process_headers(
        &mut self,
        peer_id: PeerId,
        headers: Vec<BlockHeader>,
        validate_and_store: &mut dyn FnMut(&BlockHeader, u32) -> Result<(), String>,
        find_hash_height: &dyn Fn(&Hash256) -> Option<u32>,
    ) -> Result<bool, String> {
        // Check if we were actively syncing from this peer
        let is_active_sync = matches!(
            &self.state,
            SyncState::DownloadingHeaders { peer, .. } if *peer == peer_id
        );

        if !is_active_sync {
            // Accept unsolicited headers (BIP 130: peers announce new blocks
            // via headers messages). Process them if they connect to our chain.
            if headers.is_empty() {
                return Ok(false);
            }

            // Check if the first header connects to our tip
            if headers[0].prev_block_hash != self.best_header_hash {
                // Doesn't connect to our tip -- ignore silently.
                // This is normal: peers may be on a different fork or
                // we may not have synced to the same point yet.
                tracing::debug!(
                    "Ignoring unsolicited headers from peer {}: prev_hash {} doesn't match our tip {}",
                    peer_id.0, headers[0].prev_block_hash, self.best_header_hash
                );
                return Ok(false);
            }

            // Falls through to normal processing below -- these headers
            // extend our chain (new block announcements).
            tracing::info!(
                "Processing {} unsolicited header(s) from peer {} (new block announcement)",
                headers.len(), peer_id.0
            );
        }

        if headers.is_empty() {
            // Peer has no more headers — we're caught up to this peer
            self.state = SyncState::Idle;
            return Ok(false);
        }

        if headers.len() > MAX_HEADERS_PER_REQUEST {
            return Err("too many headers".into());
        }

        // Validate header chain connectivity
        let mut prev_hash = self.best_header_hash;
        let mut base_height = self.best_header_height;

        // Check if the first header connects to our tip. If not, see if it
        // connects to an earlier block in our chain (fork/reorg scenario).
        if !headers.is_empty() && headers[0].prev_block_hash != prev_hash {
            let fork_prev = &headers[0].prev_block_hash;
            if let Some(fork_height) = find_hash_height(fork_prev) {
                tracing::info!(
                    "Headers from peer {} fork from height {} (hash {}), rewinding header tip from height {}",
                    peer_id.0, fork_height, fork_prev, self.best_header_height
                );
                self.best_header_height = fork_height;
                self.best_header_hash = *fork_prev;
                prev_hash = *fork_prev;
                base_height = fork_height;
            } else {
                return Err(format!(
                    "first header prev_hash {} doesn't match our tip {} and is not in our chain",
                    headers[0].prev_block_hash, prev_hash
                ));
            }
        }

        for (i, header) in headers.iter().enumerate() {
            // Each header must reference the previous one
            if header.prev_block_hash != prev_hash {
                return Err("headers not connected".into());
            }

            let height = base_height + 1 + i as u32;

            // Validate proof of work
            if !header.validate_pow() {
                return Err("bad proof of work".into());
            }

            // Store and validate the header
            validate_and_store(header, height)?;

            prev_hash = header.block_hash();
        }

        // Update our best header
        self.best_header_height += headers.len() as u32;
        self.best_header_hash = headers.last().unwrap().block_hash();

        // This peer just delivered headers up to our new tip, so it
        // demonstrably knows a chain at least this tall. Refresh its tracked
        // height (monotonic raise) so it stays a valid `best_sync_peer`
        // candidate as the chain grows past its stale handshake
        // `start_height`. Core analog: `UpdateBlockAvailability(peer,
        // headers.back())` after a connecting headers batch
        // (net_processing.cpp::UpdatePeerStateForReceivedHeaders).
        self.note_peer_height(peer_id, self.best_header_height as i32);

        // Successful chain extension — reset the unconnecting-headers counter
        // for this peer (Core: nUnconnectingHeaders = 0 in the headers
        // handler's success path).
        self.unconnecting_headers.remove(&peer_id);

        // If we received a full batch, there are probably more
        let need_more = headers.len() == MAX_HEADERS_PER_REQUEST;

        if need_more {
            self.state = SyncState::DownloadingHeaders {
                peer: peer_id,
                last_hash: self.best_header_hash,
            };
        } else {
            self.state = SyncState::Idle;
        }

        tracing::info!(
            "Processed {} headers, best height: {}",
            headers.len(),
            self.best_header_height
        );

        Ok(need_more)
    }

    /// Get the current sync state.
    pub fn state(&self) -> &SyncState {
        &self.state
    }

    /// Get the best header chain height.
    pub fn best_header_height(&self) -> u32 {
        self.best_header_height
    }

    /// Get the best header hash.
    pub fn best_header_hash(&self) -> Hash256 {
        self.best_header_hash
    }

    /// Update the best header info directly.
    ///
    /// Used when loading state from the database on startup.
    pub fn set_best_header(&mut self, height: u32, hash: Hash256) {
        self.best_header_height = height;
        self.best_header_hash = hash;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a test header that passes PoW validation.
    ///
    /// We use the regtest bits (0x207fffff) which gives a target of
    /// 7fffff0000... (basically half the hash space). We vary the nonce
    /// to get different block hashes.
    fn make_test_header(prev_hash: Hash256, nonce: u32) -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_block_hash: prev_hash,
            merkle_root: Hash256::ZERO,
            timestamp: 1231006505,
            // Regtest difficulty - extremely easy target
            bits: 0x207fffff,
            nonce,
        }
    }

    fn make_valid_header_chain(genesis_hash: Hash256, count: usize) -> Vec<BlockHeader> {
        let mut headers = Vec::with_capacity(count);
        let mut prev_hash = genesis_hash;
        for i in 0..count {
            // Vary nonce to get a header that passes PoW
            // Most hashes will pass with regtest difficulty
            let mut nonce = 0u32;
            loop {
                let header = make_test_header(prev_hash, nonce);
                if header.validate_pow() {
                    prev_hash = header.block_hash();
                    headers.push(header);
                    break;
                }
                nonce += 1;
                // Safety: regtest difficulty should pass almost immediately
                if nonce > 1000 {
                    panic!("Could not find valid PoW for test header {}", i);
                }
            }
        }
        headers
    }

    #[test]
    fn test_block_locator_at_height_0() {
        let genesis_hash = Hash256::from_hex(
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        )
        .unwrap();
        let sync = HeaderSync::new(genesis_hash);

        let locator = sync.build_block_locator(|h| {
            if h == 0 {
                Some(genesis_hash)
            } else {
                None
            }
        });

        assert_eq!(locator.len(), 1);
        assert_eq!(locator[0], genesis_hash);
    }

    #[test]
    fn test_block_locator_at_height_10() {
        let genesis_hash = Hash256::from_hex(
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        )
        .unwrap();
        let mut sync = HeaderSync::new(genesis_hash);
        sync.best_header_height = 10;

        // Create mock hashes for each height
        let hashes: Vec<Hash256> = (0..=10)
            .map(|i| Hash256([i as u8; 32]))
            .collect();

        let locator = sync.build_block_locator(|h| {
            hashes.get(h as usize).copied()
        });

        // At height 10, locator should have heights: 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
        // That's 11 entries (step=1 for all since we haven't reached 10 entries yet)
        assert_eq!(locator.len(), 11);
        assert_eq!(locator[0], hashes[10]); // tip
        assert_eq!(locator[10], hashes[0]); // genesis
    }

    #[test]
    fn test_block_locator_at_height_100() {
        let genesis_hash = Hash256::from_hex(
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        )
        .unwrap();
        let mut sync = HeaderSync::new(genesis_hash);
        sync.best_header_height = 100;

        // Create mock hashes
        let hashes: Vec<Hash256> = (0..=100)
            .map(|i| Hash256([i as u8; 32]))
            .collect();

        let locator = sync.build_block_locator(|h| {
            hashes.get(h as usize).copied()
        });

        // Heights should be: 100, 99, 98, 97, 96, 95, 94, 93, 92, 91 (first 10, step=1)
        // Then: 89, 85, 77, 61, 29, 0 (step doubles each time)
        let expected_heights = vec![100, 99, 98, 97, 96, 95, 94, 93, 92, 91, 89, 85, 77, 61, 29, 0];
        assert_eq!(locator.len(), expected_heights.len());
        for (i, &height) in expected_heights.iter().enumerate() {
            assert_eq!(locator[i], hashes[height], "mismatch at index {}", i);
        }
    }

    #[test]
    fn test_process_headers_empty_returns_false() {
        let genesis_hash = Hash256([0; 32]);
        let mut sync = HeaderSync::new(genesis_hash);
        let peer = PeerId(1);
        sync.register_peer(peer, 100);
        sync.state = SyncState::DownloadingHeaders {
            peer,
            last_hash: genesis_hash,
        };

        let result = sync.process_headers(peer, vec![], &mut |_, _| Ok(()), &|_| None);
        assert_eq!(result, Ok(false));
        assert_eq!(sync.state, SyncState::Idle);
    }

    #[test]
    fn test_process_headers_disconnected_chain_returns_err() {
        let genesis_hash = Hash256([0; 32]);
        let mut sync = HeaderSync::new(genesis_hash);
        let peer = PeerId(1);
        sync.register_peer(peer, 100);
        sync.state = SyncState::DownloadingHeaders {
            peer,
            last_hash: genesis_hash,
        };

        // Create a header that doesn't connect to genesis
        let bad_header = make_test_header(Hash256([1; 32]), 0);

        let result = sync.process_headers(peer, vec![bad_header], &mut |_, _| Ok(()), &|_| None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("prev_hash"));
    }

    #[test]
    fn test_process_headers_2000_returns_true() {
        let genesis_hash = Hash256([0; 32]);
        let mut sync = HeaderSync::new(genesis_hash);
        let peer = PeerId(1);
        sync.register_peer(peer, 10000);
        sync.state = SyncState::DownloadingHeaders {
            peer,
            last_hash: genesis_hash,
        };

        let headers = make_valid_header_chain(genesis_hash, MAX_HEADERS_PER_REQUEST);

        let result = sync.process_headers(peer, headers, &mut |_, _| Ok(()), &|_| None);
        assert_eq!(result, Ok(true));
        assert_eq!(sync.best_header_height, MAX_HEADERS_PER_REQUEST as u32);
        assert!(matches!(sync.state, SyncState::DownloadingHeaders { .. }));
    }

    #[test]
    fn test_process_headers_500_returns_false() {
        let genesis_hash = Hash256([0; 32]);
        let mut sync = HeaderSync::new(genesis_hash);
        let peer = PeerId(1);
        sync.register_peer(peer, 600);
        sync.state = SyncState::DownloadingHeaders {
            peer,
            last_hash: genesis_hash,
        };

        let headers = make_valid_header_chain(genesis_hash, 500);

        let result = sync.process_headers(peer, headers, &mut |_, _| Ok(()), &|_| None);
        assert_eq!(result, Ok(false));
        assert_eq!(sync.best_header_height, 500);
        assert_eq!(sync.state, SyncState::Idle);
    }

    #[test]
    fn test_best_sync_peer_returns_highest_height() {
        let genesis_hash = Hash256([0; 32]);
        let mut sync = HeaderSync::new(genesis_hash);

        sync.register_peer(PeerId(1), 100);
        sync.register_peer(PeerId(2), 500);
        sync.register_peer(PeerId(3), 250);

        assert_eq!(sync.best_sync_peer(), Some(PeerId(2)));
    }

    #[test]
    fn test_best_sync_peer_filters_by_our_height() {
        let genesis_hash = Hash256([0; 32]);
        let mut sync = HeaderSync::new(genesis_hash);
        sync.best_header_height = 300;

        sync.register_peer(PeerId(1), 100);
        sync.register_peer(PeerId(2), 200);
        sync.register_peer(PeerId(3), 500);

        // Only peer 3 has a higher height than us
        assert_eq!(sync.best_sync_peer(), Some(PeerId(3)));
    }

    #[test]
    fn test_best_sync_peer_none_when_caught_up() {
        let genesis_hash = Hash256([0; 32]);
        let mut sync = HeaderSync::new(genesis_hash);
        sync.best_header_height = 1000;

        sync.register_peer(PeerId(1), 500);
        sync.register_peer(PeerId(2), 800);

        // We're ahead of all peers
        assert_eq!(sync.best_sync_peer(), None);
    }

    #[test]
    fn test_remove_peer_resets_sync_state() {
        let genesis_hash = Hash256([0; 32]);
        let mut sync = HeaderSync::new(genesis_hash);
        let peer = PeerId(1);

        sync.register_peer(peer, 100);
        sync.state = SyncState::DownloadingHeaders {
            peer,
            last_hash: genesis_hash,
        };

        sync.remove_peer(peer);

        assert_eq!(sync.state, SyncState::Idle);
        assert_eq!(sync.best_sync_peer(), None);
    }

    #[test]
    fn test_remove_peer_doesnt_affect_other_state() {
        let genesis_hash = Hash256([0; 32]);
        let mut sync = HeaderSync::new(genesis_hash);
        let peer1 = PeerId(1);
        let peer2 = PeerId(2);

        sync.register_peer(peer1, 100);
        sync.register_peer(peer2, 200);
        sync.state = SyncState::DownloadingHeaders {
            peer: peer1,
            last_hash: genesis_hash,
        };

        // Remove a different peer
        sync.remove_peer(peer2);

        // State should be unchanged
        assert!(matches!(
            sync.state,
            SyncState::DownloadingHeaders { peer, .. } if peer == peer1
        ));
    }

    #[test]
    fn test_start_sync_returns_none_without_peers() {
        let genesis_hash = Hash256([0; 32]);
        let mut sync = HeaderSync::new(genesis_hash);

        let result = sync.start_sync(|h| {
            if h == 0 {
                Some(genesis_hash)
            } else {
                None
            }
        });

        assert!(result.is_none());
        assert_eq!(sync.state, SyncState::Idle);
    }

    #[test]
    fn test_start_sync_sets_state_and_returns_message() {
        let genesis_hash = Hash256([0; 32]);
        let mut sync = HeaderSync::new(genesis_hash);
        let peer = PeerId(1);
        sync.register_peer(peer, 100);

        let result = sync.start_sync(|h| {
            if h == 0 {
                Some(genesis_hash)
            } else {
                None
            }
        });

        assert!(result.is_some());
        let (returned_peer, msg) = result.unwrap();
        assert_eq!(returned_peer, peer);
        assert!(matches!(msg, NetworkMessage::GetHeaders(_)));
        assert!(matches!(
            sync.state,
            SyncState::DownloadingHeaders { peer: p, .. } if p == peer
        ));
    }

    #[test]
    fn test_process_unsolicited_headers_accepted_if_connected() {
        // BIP 130: peers can send unsolicited headers to announce new blocks.
        // These should be accepted if they connect to our chain tip.
        let genesis_hash = Hash256([0; 32]);
        let mut sync = HeaderSync::new(genesis_hash);
        let peer1 = PeerId(1);
        let peer2 = PeerId(2);

        sync.register_peer(peer1, 100);
        sync.register_peer(peer2, 200);
        sync.state = SyncState::DownloadingHeaders {
            peer: peer1,
            last_hash: genesis_hash,
        };

        // peer2 sends headers that connect to our tip — should be accepted
        let headers = make_valid_header_chain(genesis_hash, 10);
        let result = sync.process_headers(peer2, headers, &mut |_, _| Ok(()), &|_| None);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), false); // fewer than MAX_HEADERS
        assert_eq!(sync.best_header_height(), 10);
    }

    #[test]
    fn test_process_unsolicited_headers_ignored_if_not_connected() {
        // Unsolicited headers that don't connect to our tip should be ignored
        let genesis_hash = Hash256([0; 32]);
        let mut sync = HeaderSync::new(genesis_hash);
        let peer2 = PeerId(2);

        sync.register_peer(peer2, 200);

        // Create headers that don't connect to genesis
        let bad_prev = Hash256([99; 32]);
        let headers = make_valid_header_chain(bad_prev, 5);
        let result = sync.process_headers(peer2, headers, &mut |_, _| Ok(()), &|_| None);

        // Should return Ok(false) — silently ignored
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), false);
        assert_eq!(sync.best_header_height(), 0); // unchanged
    }

    #[test]
    fn test_process_headers_too_many_returns_err() {
        let genesis_hash = Hash256([0; 32]);
        let mut sync = HeaderSync::new(genesis_hash);
        let peer = PeerId(1);

        sync.register_peer(peer, 10000);
        sync.state = SyncState::DownloadingHeaders {
            peer,
            last_hash: genesis_hash,
        };

        let headers = make_valid_header_chain(genesis_hash, MAX_HEADERS_PER_REQUEST + 1);
        let result = sync.process_headers(peer, headers, &mut |_, _| Ok(()), &|_| None);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too many"));
    }

    #[test]
    fn test_process_headers_calls_validate_with_correct_height() {
        let genesis_hash = Hash256([0; 32]);
        let mut sync = HeaderSync::new(genesis_hash);
        let peer = PeerId(1);

        sync.register_peer(peer, 100);
        sync.state = SyncState::DownloadingHeaders {
            peer,
            last_hash: genesis_hash,
        };

        let headers = make_valid_header_chain(genesis_hash, 3);
        let mut heights = Vec::new();

        let result = sync.process_headers(peer, headers, &mut |_, h| {
            heights.push(h);
            Ok(())
        }, &|_| None);

        assert!(result.is_ok());
        assert_eq!(heights, vec![1, 2, 3]);
    }

    #[test]
    fn test_process_headers_stops_on_validation_error() {
        let genesis_hash = Hash256([0; 32]);
        let mut sync = HeaderSync::new(genesis_hash);
        let peer = PeerId(1);

        sync.register_peer(peer, 100);
        sync.state = SyncState::DownloadingHeaders {
            peer,
            last_hash: genesis_hash,
        };

        let headers = make_valid_header_chain(genesis_hash, 5);
        let mut count = 0;

        let result = sync.process_headers(peer, headers, &mut |_, h| {
            count += 1;
            if h == 3 {
                Err("validation failed".into())
            } else {
                Ok(())
            }
        }, &|_| None);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("validation failed"));
        assert_eq!(count, 3); // Stopped at height 3
    }

    #[test]
    fn test_set_best_header() {
        let genesis_hash = Hash256([0; 32]);
        let mut sync = HeaderSync::new(genesis_hash);

        let new_hash = Hash256([1; 32]);
        sync.set_best_header(12345, new_hash);

        assert_eq!(sync.best_header_height(), 12345);
        assert_eq!(sync.best_header_hash(), new_hash);
    }

    /// Core parity: an unconnecting-headers message should NOT trigger
    /// disconnect on the first occurrence. The counter must tolerate up to
    /// `MAX_NUM_UNCONNECTING_HEADERS_MSGS` (10) before recommending disconnect.
    /// Mirrors Bitcoin Core's `nUnconnectingHeaders` behavior in
    /// `net_processing.cpp::ProcessHeadersMessage`.
    #[test]
    fn test_note_unconnecting_headers_under_threshold() {
        let genesis_hash = Hash256([0; 32]);
        let mut sync = HeaderSync::new(genesis_hash);
        let peer = PeerId(1);

        // First 10 calls must NOT recommend disconnect (Core: <= 10 tolerated).
        for i in 1..=MAX_NUM_UNCONNECTING_HEADERS_MSGS {
            let exceeded = sync.note_unconnecting_headers(peer);
            assert!(
                !exceeded,
                "unconnecting #{} should not yet exceed threshold",
                i
            );
            assert_eq!(sync.unconnecting_headers_count(peer), i);
        }
    }

    #[test]
    fn test_note_unconnecting_headers_exceeds_threshold() {
        let genesis_hash = Hash256([0; 32]);
        let mut sync = HeaderSync::new(genesis_hash);
        let peer = PeerId(1);

        // Saturate the counter at the threshold.
        for _ in 0..MAX_NUM_UNCONNECTING_HEADERS_MSGS {
            assert!(!sync.note_unconnecting_headers(peer));
        }
        // 11th unconnecting message MUST recommend disconnect.
        let exceeded = sync.note_unconnecting_headers(peer);
        assert!(exceeded, "11th unconnecting header should exceed threshold");
    }

    #[test]
    fn test_unconnecting_headers_reset_on_connecting_batch() {
        let genesis_hash = Hash256([0; 32]);
        let mut sync = HeaderSync::new(genesis_hash);
        let peer = PeerId(1);
        sync.register_peer(peer, 100);

        // Saturate near the threshold.
        for _ in 0..(MAX_NUM_UNCONNECTING_HEADERS_MSGS - 1) {
            assert!(!sync.note_unconnecting_headers(peer));
        }
        assert_eq!(
            sync.unconnecting_headers_count(peer),
            MAX_NUM_UNCONNECTING_HEADERS_MSGS - 1
        );

        // A successful connecting batch must reset the counter (Core:
        // nUnconnectingHeaders = 0 in the success path).
        sync.state = SyncState::DownloadingHeaders {
            peer,
            last_hash: genesis_hash,
        };
        let headers = make_valid_header_chain(genesis_hash, 3);
        let result = sync.process_headers(peer, headers, &mut |_, _| Ok(()), &|_| None);
        assert!(result.is_ok());
        assert_eq!(sync.unconnecting_headers_count(peer), 0);

        // The next unconnecting message starts the count fresh from 1.
        assert!(!sync.note_unconnecting_headers(peer));
        assert_eq!(sync.unconnecting_headers_count(peer), 1);
    }

    #[test]
    fn test_unconnecting_headers_per_peer_independent() {
        let genesis_hash = Hash256([0; 32]);
        let mut sync = HeaderSync::new(genesis_hash);
        let peer_a = PeerId(1);
        let peer_b = PeerId(2);

        // Saturate peer A near the threshold.
        for _ in 0..MAX_NUM_UNCONNECTING_HEADERS_MSGS {
            assert!(!sync.note_unconnecting_headers(peer_a));
        }
        // Peer B is independent — its very first unconnecting message
        // must NOT trigger disconnect.
        assert!(!sync.note_unconnecting_headers(peer_b));
        assert_eq!(sync.unconnecting_headers_count(peer_b), 1);
        // Peer A's 11th message exceeds the threshold.
        assert!(sync.note_unconnecting_headers(peer_a));
    }

    /// Core parity: a peer's tracked height must be refreshed (raised) as it
    /// delivers headers, not frozen at its handshake `start_height`. Mirrors
    /// `UpdateBlockAvailability` advancing `pindexBestKnownBlock`. Without the
    /// refresh, once our header tip climbs past the peer's stale handshake
    /// height, `best_sync_peer` filters the peer out and we stop syncing from
    /// an otherwise-useful peer.
    #[test]
    fn test_peer_height_refreshed_after_delivering_headers() {
        let genesis_hash = Hash256([0; 32]);
        let mut sync = HeaderSync::new(genesis_hash);
        let peer = PeerId(1);

        // Peer handshakes announcing height 2000 — exactly one full batch.
        sync.register_peer(peer, MAX_HEADERS_PER_REQUEST as i32);
        sync.state = SyncState::DownloadingHeaders {
            peer,
            last_hash: genesis_hash,
        };

        // Peer delivers a full 2000-header batch (it actually has more chain
        // than its handshake start_height implied).
        let headers = make_valid_header_chain(genesis_hash, MAX_HEADERS_PER_REQUEST);
        let result = sync.process_headers(peer, headers, &mut |_, _| Ok(()), &|_| None);
        assert_eq!(result, Ok(true));
        assert_eq!(sync.best_header_height(), MAX_HEADERS_PER_REQUEST as u32);

        // Pre-fix: peer_heights[peer] is still 2000 (its handshake value),
        // equal to our header tip, so `best_sync_peer` (which requires
        // h > best_header_height) returns None and we'd stop syncing from this
        // peer even though it has more to give.
        // Post-fix: the peer's tracked height was raised to our new tip, so it
        // remains a candidate (>= tip, and the next batch can lift it higher).
        assert_eq!(
            sync.peer_height(peer),
            Some(MAX_HEADERS_PER_REQUEST as i32),
            "peer height should be refreshed to the delivered tip"
        );

        // Simulate the next batch lifting both our tip and the peer's known
        // height further; the peer must still be selectable.
        sync.state = SyncState::DownloadingHeaders {
            peer,
            last_hash: sync.best_header_hash(),
        };
        let next = make_valid_header_chain(sync.best_header_hash(), 1);
        let result = sync.process_headers(peer, next, &mut |_, _| Ok(()), &|_| None);
        assert_eq!(result, Ok(false));
        assert_eq!(
            sync.peer_height(peer),
            Some(MAX_HEADERS_PER_REQUEST as i32 + 1)
        );
    }

    /// `note_peer_height` is monotonic: it raises the tracked height but never
    /// lowers it (Core only advances `pindexBestKnownBlock` to higher
    /// chainwork). A stale/lower observation must not drop a peer.
    #[test]
    fn test_note_peer_height_is_monotonic() {
        let genesis_hash = Hash256([0; 32]);
        let mut sync = HeaderSync::new(genesis_hash);
        let peer = PeerId(7);

        sync.note_peer_height(peer, 500);
        assert_eq!(sync.peer_height(peer), Some(500));

        // Higher observation raises it.
        sync.note_peer_height(peer, 900);
        assert_eq!(sync.peer_height(peer), Some(900));

        // Lower observation is ignored.
        sync.note_peer_height(peer, 100);
        assert_eq!(sync.peer_height(peer), Some(900));
    }

    /// Regression guard for the stale-height symptom directly: a peer whose
    /// handshake height is below our current header tip becomes selectable
    /// again once it proves (via a delivered header) that it actually has a
    /// taller chain.
    #[test]
    fn test_stale_handshake_height_recovered_via_headers() {
        let genesis_hash = Hash256([0; 32]);
        let mut sync = HeaderSync::new(genesis_hash);
        let peer = PeerId(1);

        // We're already at header height 10 (e.g. synced from another peer).
        // This peer handshaked long ago at height 5 — now stale.
        let chain = make_valid_header_chain(genesis_hash, 11);
        sync.set_best_header(10, chain[9].block_hash());
        sync.register_peer(peer, 5);

        // Stale: best_sync_peer ignores it (5 <= 10).
        assert_eq!(sync.best_sync_peer(), None);

        // The peer announces a new block extending our tip (unsolicited
        // headers / BIP 130). After processing, its tracked height is raised
        // to 11.
        let new_header = vec![chain[10].clone()];
        let result = sync.process_headers(peer, new_header, &mut |_, _| Ok(()), &|_| None);
        assert_eq!(result, Ok(false));
        assert_eq!(sync.best_header_height(), 11);
        assert_eq!(sync.peer_height(peer), Some(11));
    }

    #[test]
    fn test_unconnecting_headers_reset_on_remove_peer() {
        let genesis_hash = Hash256([0; 32]);
        let mut sync = HeaderSync::new(genesis_hash);
        let peer = PeerId(1);
        sync.register_peer(peer, 100);

        for _ in 0..3 {
            sync.note_unconnecting_headers(peer);
        }
        assert_eq!(sync.unconnecting_headers_count(peer), 3);
        sync.remove_peer(peer);
        assert_eq!(sync.unconnecting_headers_count(peer), 0);
    }
}
