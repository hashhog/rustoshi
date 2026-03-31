//! Block downloading for Initial Block Download (IBD) and steady-state.
//!
//! This module manages parallel block downloading from multiple peers using a
//! sliding window approach. Key features:
//!
//! - Parallel downloads from multiple peers (up to 16 blocks per peer)
//! - Sliding window that downloads ahead of the validation point
//! - Adaptive timeout handling with stall detection
//! - Out-of-order block reception with in-order validation
//!
//! IBD (Initial Block Download) is the process of downloading and validating
//! the entire blockchain from genesis. This is typically the longest phase of
//! starting a new node.

use crate::message::{InvType, InvVector, NetworkMessage};
use crate::peer::PeerId;
use rustoshi_primitives::{Block, Hash256};
use std::collections::{HashMap, VecDeque};
use tokio::time::{Duration, Instant};

/// Maximum number of blocks in flight from a single peer.
/// Bitcoin Core uses 16 as the default to prevent a single slow peer from
/// monopolizing the download pipeline.
const MAX_BLOCKS_IN_FLIGHT_PER_PEER: usize = 16;

/// Maximum total number of blocks in flight across all peers.
const MAX_BLOCKS_IN_FLIGHT: usize = 1024;

/// Base timeout for a single block request.
/// We use adaptive timeouts: double on stall, decay on success.
const BASE_BLOCK_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum timeout after adaptive increases.
const MAX_BLOCK_TIMEOUT: Duration = Duration::from_secs(64);

/// Stall timeout: disconnect peer if no block received for this long.
const BLOCK_STALL_TIMEOUT: Duration = Duration::from_secs(120);

/// Block download window size (how far ahead of the validated tip to download).
#[allow(dead_code)]
const DOWNLOAD_WINDOW_SIZE: u32 = 1024;

/// A block that has been requested but not yet received.
#[derive(Debug, Clone)]
struct InFlightBlock {
    hash: Hash256,
    height: u32,
    peer: PeerId,
    requested_at: Instant,
    timeout: Duration,
}

/// Track per-peer download state.
#[derive(Debug)]
struct PeerDownloadState {
    blocks_in_flight: usize,
    last_block_received: Instant,
    stalling: bool,
    /// Adaptive timeout for this peer (doubles on stall, decays on success).
    current_timeout: Duration,
}

impl PeerDownloadState {
    fn new() -> Self {
        Self {
            blocks_in_flight: 0,
            last_block_received: Instant::now(),
            stalling: false,
            current_timeout: BASE_BLOCK_TIMEOUT,
        }
    }

    /// Decay timeout by 15% on successful block receipt (minimum BASE_BLOCK_TIMEOUT).
    fn decay_timeout(&mut self) {
        let decayed = self.current_timeout.mul_f64(0.85);
        self.current_timeout = decayed.max(BASE_BLOCK_TIMEOUT);
    }

    /// Double timeout on stall (capped at MAX_BLOCK_TIMEOUT).
    fn increase_timeout(&mut self) {
        let doubled = self.current_timeout * 2;
        self.current_timeout = doubled.min(MAX_BLOCK_TIMEOUT);
    }
}

/// Manages block downloading during IBD and steady-state.
pub struct BlockDownloader {
    /// Blocks waiting to be requested, in order.
    download_queue: VecDeque<(Hash256, u32)>,
    /// Currently in-flight block requests: hash -> InFlightBlock
    in_flight: HashMap<Hash256, InFlightBlock>,
    /// Per-peer download state.
    peer_states: HashMap<PeerId, PeerDownloadState>,
    /// Height of the last block we have fully validated and connected.
    validated_tip_height: u32,
    /// Height of the best header we know about.
    best_header_height: u32,
    /// Blocks received but waiting to be processed in order.
    /// Blocks must be connected in order, so out-of-order blocks are buffered.
    received_blocks: HashMap<Hash256, Block>,
    /// Hashes in download-order, used to process blocks sequentially.
    pending_hashes: VecDeque<Hash256>,
}

impl BlockDownloader {
    /// Create a new block downloader.
    ///
    /// # Arguments
    /// * `validated_tip_height` - Height of the last fully validated block
    /// * `best_header_height` - Height of the best known header
    pub fn new(validated_tip_height: u32, best_header_height: u32) -> Self {
        Self {
            download_queue: VecDeque::new(),
            in_flight: HashMap::new(),
            peer_states: HashMap::new(),
            validated_tip_height,
            best_header_height,
            received_blocks: HashMap::new(),
            pending_hashes: VecDeque::new(),
        }
    }

    /// Add a range of block hashes to download (after headers are synced).
    ///
    /// Blocks should be added in chain order (lowest height first).
    pub fn enqueue_blocks(&mut self, blocks: Vec<(Hash256, u32)>) {
        for item in blocks {
            self.pending_hashes.push_back(item.0);
            self.download_queue.push_back(item);
        }
    }

    /// Register a peer as available for block downloads.
    pub fn add_peer(&mut self, peer_id: PeerId) {
        self.peer_states.insert(peer_id, PeerDownloadState::new());
    }

    /// Clear stalling flags for all peers.
    ///
    /// Called after new headers are received, indicating that peers are
    /// responsive even if they previously failed to deliver blocks.
    /// Without this, a transient stall permanently excludes a peer from
    /// block downloads, eventually deadlocking when all peers stall.
    pub fn clear_stalling(&mut self) {
        for state in self.peer_states.values_mut() {
            state.stalling = false;
        }
    }

    /// Remove a peer (disconnected or banned).
    ///
    /// Any blocks that were assigned to this peer are re-queued for
    /// download from other peers.
    pub fn remove_peer(&mut self, peer_id: PeerId) {
        self.peer_states.remove(&peer_id);

        // Re-queue any blocks that were assigned to this peer
        let to_requeue: Vec<(Hash256, u32)> = self
            .in_flight
            .iter()
            .filter(|(_, b)| b.peer == peer_id)
            .map(|(_, b)| (b.hash, b.height))
            .collect();

        for (hash, height) in &to_requeue {
            self.in_flight.remove(hash);
            self.download_queue.push_front((*hash, *height));
        }
    }

    /// Generate getdata requests to send to available peers.
    ///
    /// Returns a list of (peer_id, getdata_message) to send.
    /// Messages are batched per peer to reduce round-trips.
    pub fn assign_requests(&mut self) -> Vec<(PeerId, NetworkMessage)> {
        let mut requests: Vec<(PeerId, NetworkMessage)> = Vec::new();

        // Find peers with available capacity
        let mut available_peers: Vec<PeerId> = self
            .peer_states
            .iter()
            .filter(|(_, state)| {
                state.blocks_in_flight < MAX_BLOCKS_IN_FLIGHT_PER_PEER && !state.stalling
            })
            .map(|(id, _)| *id)
            .collect();

        if available_peers.is_empty() || self.download_queue.is_empty() {
            return requests;
        }

        // Track inventory vectors per peer for batching
        let mut peer_inv_vectors: HashMap<PeerId, Vec<InvVector>> = HashMap::new();

        // Round-robin assign blocks to peers
        let mut peer_idx = 0;
        while !self.download_queue.is_empty()
            && self.in_flight.len() < MAX_BLOCKS_IN_FLIGHT
            && !available_peers.is_empty()
        {
            let (hash, height) = self.download_queue.pop_front().unwrap();

            // Don't re-request blocks we already have
            if self.received_blocks.contains_key(&hash) {
                continue;
            }

            // Skip blocks already in flight
            if self.in_flight.contains_key(&hash) {
                continue;
            }

            let peer_id = available_peers[peer_idx % available_peers.len()];
            peer_idx += 1;

            // Get the peer's current timeout
            let timeout = self
                .peer_states
                .get(&peer_id)
                .map(|s| s.current_timeout)
                .unwrap_or(BASE_BLOCK_TIMEOUT);

            self.in_flight.insert(
                hash,
                InFlightBlock {
                    hash,
                    height,
                    peer: peer_id,
                    requested_at: Instant::now(),
                    timeout,
                },
            );

            if let Some(state) = self.peer_states.get_mut(&peer_id) {
                state.blocks_in_flight += 1;
                if state.blocks_in_flight >= MAX_BLOCKS_IN_FLIGHT_PER_PEER {
                    available_peers.retain(|id| *id != peer_id);
                }
            }

            // Use MSG_WITNESS_BLOCK to get witness data
            let inv = InvVector {
                inv_type: InvType::MsgWitnessBlock,
                hash,
            };

            peer_inv_vectors.entry(peer_id).or_default().push(inv);
        }

        // Build batched getdata messages
        for (peer_id, inv_vectors) in peer_inv_vectors {
            if !inv_vectors.is_empty() {
                requests.push((peer_id, NetworkMessage::GetData(inv_vectors)));
            }
        }

        requests
    }

    /// Handle a received block from a peer.
    ///
    /// Returns the block hash if the block was expected.
    pub fn block_received(&mut self, peer_id: PeerId, block: Block) -> Option<Hash256> {
        let hash = block.block_hash();

        if let Some(in_flight) = self.in_flight.remove(&hash) {
            if let Some(state) = self.peer_states.get_mut(&peer_id) {
                state.blocks_in_flight = state.blocks_in_flight.saturating_sub(1);
                state.last_block_received = Instant::now();
                state.stalling = false;
                // Decay timeout on success
                state.decay_timeout();
            }

            // Even if peer_id doesn't match in_flight.peer, we still accept the block
            // (peer might have forwarded it)
            let _ = in_flight;
        }

        self.received_blocks.insert(hash, block);
        Some(hash)
    }

    /// Get the next block ready to be validated (in chain order).
    ///
    /// Blocks must be validated in sequential order because each block's
    /// inputs reference UTXOs created by previous blocks.
    pub fn next_block_to_validate(&mut self) -> Option<Block> {
        let hash = self.pending_hashes.front()?;
        if let Some(block) = self.received_blocks.remove(hash) {
            self.pending_hashes.pop_front();
            self.validated_tip_height += 1;
            Some(block)
        } else {
            // Next block in sequence hasn't arrived yet
            None
        }
    }

    /// Check for timed-out requests and stalling peers.
    ///
    /// Returns peer IDs that should be disconnected due to persistent stalls.
    pub fn check_timeouts(&mut self) -> Vec<PeerId> {
        let now = Instant::now();
        let mut disconnect = Vec::new();

        // Check per-peer stall (no block received for BLOCK_STALL_TIMEOUT)
        for (peer_id, state) in &self.peer_states {
            if state.blocks_in_flight > 0
                && now.duration_since(state.last_block_received) > BLOCK_STALL_TIMEOUT
            {
                disconnect.push(*peer_id);
            }
        }

        // Check individual block timeouts (adaptive per-peer timeout)
        let timed_out: Vec<Hash256> = self
            .in_flight
            .iter()
            .filter(|(_, b)| now.duration_since(b.requested_at) > b.timeout)
            .map(|(h, _)| *h)
            .collect();

        for hash in timed_out {
            if let Some(block) = self.in_flight.remove(&hash) {
                if let Some(state) = self.peer_states.get_mut(&block.peer) {
                    state.stalling = true;
                    state.blocks_in_flight = state.blocks_in_flight.saturating_sub(1);
                    // Increase timeout for this peer
                    state.increase_timeout();
                }
                // Re-queue the block for download from another peer
                self.download_queue.push_front((block.hash, block.height));
            }
        }

        disconnect
    }

    /// Check if IBD is complete.
    ///
    /// Returns true when all known headers have been downloaded, validated,
    /// and connected to the chain.
    pub fn is_ibd_complete(&self) -> bool {
        self.validated_tip_height >= self.best_header_height
            && self.download_queue.is_empty()
            && self.in_flight.is_empty()
            && self.received_blocks.is_empty()
    }

    /// Progress as a percentage (0.0 to 100.0).
    pub fn progress(&self) -> f64 {
        if self.best_header_height == 0 {
            return 100.0;
        }
        (self.validated_tip_height as f64 / self.best_header_height as f64) * 100.0
    }

    /// Get the current validated tip height.
    pub fn validated_tip_height(&self) -> u32 {
        self.validated_tip_height
    }

    /// Get the best header height.
    pub fn best_header_height(&self) -> u32 {
        self.best_header_height
    }

    /// Update the best header height (called when headers sync progresses).
    pub fn set_best_header_height(&mut self, height: u32) {
        self.best_header_height = height;
    }

    /// Get the number of blocks currently in flight.
    pub fn blocks_in_flight(&self) -> usize {
        self.in_flight.len()
    }

    /// Get the number of blocks buffered (received but awaiting validation).
    pub fn blocks_buffered(&self) -> usize {
        self.received_blocks.len()
    }

    /// Get the number of blocks queued for download.
    pub fn blocks_queued(&self) -> usize {
        self.download_queue.len()
    }

    /// Get the number of registered peers.
    pub fn peer_count(&self) -> usize {
        self.peer_states.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustoshi_primitives::BlockHeader;

    fn make_test_block(hash_byte: u8) -> Block {
        // Create a block with a unique hash by varying the nonce
        Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: Hash256::ZERO,
                merkle_root: Hash256::ZERO,
                timestamp: 1231006505,
                bits: 0x207fffff, // Easy target
                nonce: hash_byte as u32,
            },
            transactions: vec![],
        }
    }

    #[allow(dead_code)]
    fn make_blocks_with_hashes(hashes: &[Hash256]) -> Vec<Block> {
        hashes
            .iter()
            .enumerate()
            .map(|(i, _)| make_test_block(i as u8))
            .collect()
    }

    #[test]
    fn test_new_downloader() {
        let dl = BlockDownloader::new(0, 1000);
        assert_eq!(dl.validated_tip_height(), 0);
        assert_eq!(dl.best_header_height(), 1000);
        assert_eq!(dl.blocks_in_flight(), 0);
        assert_eq!(dl.blocks_buffered(), 0);
        assert!(!dl.is_ibd_complete());
    }

    #[test]
    fn test_enqueue_and_assign_distributes_across_peers() {
        let mut dl = BlockDownloader::new(0, 100);

        // Add two peers
        let peer1 = PeerId(1);
        let peer2 = PeerId(2);
        dl.add_peer(peer1);
        dl.add_peer(peer2);

        // Enqueue some blocks
        let blocks: Vec<(Hash256, u32)> = (1..=10)
            .map(|i| (Hash256([i as u8; 32]), i))
            .collect();
        dl.enqueue_blocks(blocks);

        // Assign requests
        let requests = dl.assign_requests();

        // Should have requests for both peers
        assert!(!requests.is_empty());

        // Count blocks per peer
        let mut peer1_count = 0;
        let mut peer2_count = 0;
        for (peer_id, msg) in &requests {
            if let NetworkMessage::GetData(items) = msg {
                if *peer_id == peer1 {
                    peer1_count += items.len();
                } else if *peer_id == peer2 {
                    peer2_count += items.len();
                }
            }
        }

        // Both peers should have received blocks
        assert!(peer1_count > 0);
        assert!(peer2_count > 0);
        assert_eq!(peer1_count + peer2_count, 10);
    }

    #[test]
    fn test_block_received_clears_in_flight() {
        let mut dl = BlockDownloader::new(0, 100);

        let peer = PeerId(1);
        dl.add_peer(peer);

        // Create a specific block
        let block = make_test_block(42);
        let hash = block.block_hash();

        // Enqueue and assign
        dl.enqueue_blocks(vec![(hash, 1)]);
        let requests = dl.assign_requests();
        assert!(!requests.is_empty());
        assert_eq!(dl.blocks_in_flight(), 1);

        // Receive the block
        let received_hash = dl.block_received(peer, block);
        assert_eq!(received_hash, Some(hash));
        assert_eq!(dl.blocks_in_flight(), 0);
        assert_eq!(dl.blocks_buffered(), 1);
    }

    #[test]
    fn test_next_block_to_validate_returns_in_order() {
        let mut dl = BlockDownloader::new(0, 100);

        let peer = PeerId(1);
        dl.add_peer(peer);

        // Create blocks with known hashes
        let block1 = make_test_block(1);
        let block2 = make_test_block(2);
        let block3 = make_test_block(3);
        let hash1 = block1.block_hash();
        let hash2 = block2.block_hash();
        let hash3 = block3.block_hash();

        // Enqueue in order: 1, 2, 3
        dl.enqueue_blocks(vec![(hash1, 1), (hash2, 2), (hash3, 3)]);

        // Assign all requests
        let _ = dl.assign_requests();

        // Receive blocks out of order: 3, 1, 2
        dl.block_received(peer, block3.clone());
        dl.block_received(peer, block1.clone());

        // Should get block 1 first (it's at the front of pending_hashes)
        let first = dl.next_block_to_validate();
        assert!(first.is_some());
        assert_eq!(first.unwrap().block_hash(), hash1);
        assert_eq!(dl.validated_tip_height(), 1);

        // Block 2 hasn't arrived yet, should get None
        let second = dl.next_block_to_validate();
        assert!(second.is_none());

        // Now receive block 2
        dl.block_received(peer, block2.clone());

        // Should get block 2
        let second = dl.next_block_to_validate();
        assert!(second.is_some());
        assert_eq!(second.unwrap().block_hash(), hash2);
        assert_eq!(dl.validated_tip_height(), 2);

        // Should get block 3
        let third = dl.next_block_to_validate();
        assert!(third.is_some());
        assert_eq!(third.unwrap().block_hash(), hash3);
        assert_eq!(dl.validated_tip_height(), 3);
    }

    #[test]
    fn test_out_of_order_reception() {
        let mut dl = BlockDownloader::new(0, 100);

        let peer = PeerId(1);
        dl.add_peer(peer);

        let block2 = make_test_block(2);
        let block3 = make_test_block(3);
        let hash2 = block2.block_hash();
        let hash3 = block3.block_hash();

        // Enqueue blocks 2 and 3 (block 1 already validated)
        dl.enqueue_blocks(vec![(hash2, 2), (hash3, 3)]);
        let _ = dl.assign_requests();

        // Receive block 3 before block 2
        dl.block_received(peer, block3);

        // Should not be able to validate block 3 yet (block 2 missing)
        assert!(dl.next_block_to_validate().is_none());
        assert_eq!(dl.blocks_buffered(), 1);

        // Receive block 2
        dl.block_received(peer, block2);

        // Now should get block 2 first
        let first = dl.next_block_to_validate().unwrap();
        assert_eq!(first.block_hash(), hash2);

        // Then block 3
        let second = dl.next_block_to_validate().unwrap();
        assert_eq!(second.block_hash(), hash3);
    }

    #[test]
    fn test_remove_peer_requeues_blocks() {
        let mut dl = BlockDownloader::new(0, 100);

        let peer1 = PeerId(1);
        let peer2 = PeerId(2);
        dl.add_peer(peer1);
        dl.add_peer(peer2);

        // Enqueue blocks
        let blocks: Vec<(Hash256, u32)> = (1..=4)
            .map(|i| (Hash256([i as u8; 32]), i))
            .collect();
        dl.enqueue_blocks(blocks);

        // Assign to peers
        let _ = dl.assign_requests();
        let initial_in_flight = dl.blocks_in_flight();
        assert_eq!(initial_in_flight, 4);

        // Count how many were assigned to peer1
        let peer1_blocks: Vec<_> = dl
            .in_flight
            .values()
            .filter(|b| b.peer == peer1)
            .collect();
        let peer1_count = peer1_blocks.len();

        // Remove peer1
        dl.remove_peer(peer1);

        // Those blocks should be re-queued
        assert_eq!(dl.blocks_in_flight(), 4 - peer1_count);
        assert_eq!(dl.blocks_queued(), peer1_count);
    }

    #[test]
    fn test_check_timeouts_marks_stalling_peers() {
        let mut dl = BlockDownloader::new(0, 100);

        let peer = PeerId(1);
        dl.add_peer(peer);

        let hash = Hash256([1; 32]);
        dl.enqueue_blocks(vec![(hash, 1)]);
        let _ = dl.assign_requests();

        assert_eq!(dl.blocks_in_flight(), 1);
        assert!(!dl.peer_states.get(&peer).unwrap().stalling);

        // Manually set the request time to the past to trigger timeout
        if let Some(in_flight) = dl.in_flight.get_mut(&hash) {
            in_flight.requested_at = Instant::now() - Duration::from_secs(100);
            in_flight.timeout = Duration::from_secs(1);
        }

        // Check timeouts
        let disconnects = dl.check_timeouts();

        // No immediate disconnect (stall timeout is longer)
        assert!(disconnects.is_empty());

        // But the block should be re-queued and peer marked as stalling
        assert_eq!(dl.blocks_in_flight(), 0);
        assert_eq!(dl.blocks_queued(), 1);
        assert!(dl.peer_states.get(&peer).unwrap().stalling);
    }

    #[test]
    fn test_stalled_peers_not_assigned_new_blocks() {
        let mut dl = BlockDownloader::new(0, 100);

        let peer1 = PeerId(1);
        let peer2 = PeerId(2);
        dl.add_peer(peer1);
        dl.add_peer(peer2);

        // Mark peer1 as stalling
        dl.peer_states.get_mut(&peer1).unwrap().stalling = true;

        // Enqueue blocks
        let blocks: Vec<(Hash256, u32)> = (1..=4)
            .map(|i| (Hash256([i as u8; 32]), i))
            .collect();
        dl.enqueue_blocks(blocks);

        // Assign requests
        let requests = dl.assign_requests();

        // All blocks should go to peer2 (peer1 is stalling)
        for (peer_id, _) in &requests {
            assert_eq!(*peer_id, peer2);
        }
    }

    #[test]
    fn test_is_ibd_complete() {
        let mut dl = BlockDownloader::new(0, 3);

        let peer = PeerId(1);
        dl.add_peer(peer);

        // Not complete - no blocks yet
        assert!(!dl.is_ibd_complete());

        // Enqueue and download all blocks
        let block1 = make_test_block(1);
        let block2 = make_test_block(2);
        let block3 = make_test_block(3);
        let hash1 = block1.block_hash();
        let hash2 = block2.block_hash();
        let hash3 = block3.block_hash();

        dl.enqueue_blocks(vec![(hash1, 1), (hash2, 2), (hash3, 3)]);
        let _ = dl.assign_requests();

        // Still not complete - blocks in flight
        assert!(!dl.is_ibd_complete());

        // Receive all blocks
        dl.block_received(peer, block1);
        dl.block_received(peer, block2);
        dl.block_received(peer, block3);

        // Still not complete - blocks buffered but not validated
        assert!(!dl.is_ibd_complete());

        // Validate all blocks
        assert!(dl.next_block_to_validate().is_some());
        assert!(dl.next_block_to_validate().is_some());
        assert!(dl.next_block_to_validate().is_some());

        // Now complete
        assert!(dl.is_ibd_complete());
        assert_eq!(dl.validated_tip_height(), 3);
    }

    #[test]
    fn test_progress_calculation() {
        let mut dl = BlockDownloader::new(0, 100);

        assert_eq!(dl.progress(), 0.0);

        // Simulate validating 50 blocks
        dl.validated_tip_height = 50;
        assert_eq!(dl.progress(), 50.0);

        // All validated
        dl.validated_tip_height = 100;
        assert_eq!(dl.progress(), 100.0);
    }

    #[test]
    fn test_progress_zero_header_height() {
        let dl = BlockDownloader::new(0, 0);
        assert_eq!(dl.progress(), 100.0);
    }

    #[test]
    fn test_max_blocks_per_peer() {
        let mut dl = BlockDownloader::new(0, 100);

        let peer = PeerId(1);
        dl.add_peer(peer);

        // Enqueue more blocks than the per-peer limit
        let blocks: Vec<(Hash256, u32)> = (1..=20)
            .map(|i| (Hash256([i as u8; 32]), i))
            .collect();
        dl.enqueue_blocks(blocks);

        // Assign requests
        let requests = dl.assign_requests();

        // Should only assign MAX_BLOCKS_IN_FLIGHT_PER_PEER
        let total_assigned: usize = requests
            .iter()
            .filter_map(|(_, msg)| {
                if let NetworkMessage::GetData(items) = msg {
                    Some(items.len())
                } else {
                    None
                }
            })
            .sum();

        assert_eq!(total_assigned, MAX_BLOCKS_IN_FLIGHT_PER_PEER);
        assert_eq!(dl.blocks_in_flight(), MAX_BLOCKS_IN_FLIGHT_PER_PEER);
    }

    #[test]
    fn test_uses_witness_block_type() {
        let mut dl = BlockDownloader::new(0, 100);

        let peer = PeerId(1);
        dl.add_peer(peer);

        dl.enqueue_blocks(vec![(Hash256([1; 32]), 1)]);
        let requests = dl.assign_requests();

        assert_eq!(requests.len(), 1);
        if let (_, NetworkMessage::GetData(items)) = &requests[0] {
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].inv_type, InvType::MsgWitnessBlock);
        } else {
            panic!("expected GetData message");
        }
    }

    #[test]
    fn test_batches_requests_per_peer() {
        let mut dl = BlockDownloader::new(0, 100);

        // Single peer, multiple blocks should batch into one message
        let peer = PeerId(1);
        dl.add_peer(peer);

        let blocks: Vec<(Hash256, u32)> = (1..=5)
            .map(|i| (Hash256([i as u8; 32]), i))
            .collect();
        dl.enqueue_blocks(blocks);

        let requests = dl.assign_requests();

        // Should be a single getdata message with 5 items
        assert_eq!(requests.len(), 1);
        if let (_, NetworkMessage::GetData(items)) = &requests[0] {
            assert_eq!(items.len(), 5);
        } else {
            panic!("expected GetData message");
        }
    }

    #[test]
    fn test_adaptive_timeout_decay() {
        let mut dl = BlockDownloader::new(0, 100);

        let peer = PeerId(1);
        dl.add_peer(peer);

        // Start with base timeout
        assert_eq!(
            dl.peer_states.get(&peer).unwrap().current_timeout,
            BASE_BLOCK_TIMEOUT
        );

        // Simulate stall to increase timeout
        dl.peer_states.get_mut(&peer).unwrap().increase_timeout();
        let after_stall = dl.peer_states.get(&peer).unwrap().current_timeout;
        assert!(after_stall > BASE_BLOCK_TIMEOUT);

        // Simulate success to decay timeout
        dl.peer_states.get_mut(&peer).unwrap().decay_timeout();
        let after_decay = dl.peer_states.get(&peer).unwrap().current_timeout;
        assert!(after_decay < after_stall);
    }

    #[test]
    fn test_adaptive_timeout_caps() {
        let mut dl = BlockDownloader::new(0, 100);

        let peer = PeerId(1);
        dl.add_peer(peer);

        // Increase many times
        for _ in 0..20 {
            dl.peer_states.get_mut(&peer).unwrap().increase_timeout();
        }

        // Should be capped at max
        assert_eq!(
            dl.peer_states.get(&peer).unwrap().current_timeout,
            MAX_BLOCK_TIMEOUT
        );

        // Decay many times
        for _ in 0..100 {
            dl.peer_states.get_mut(&peer).unwrap().decay_timeout();
        }

        // Should be floored at base
        assert_eq!(
            dl.peer_states.get(&peer).unwrap().current_timeout,
            BASE_BLOCK_TIMEOUT
        );
    }

    #[test]
    fn test_skip_already_received_blocks() {
        let mut dl = BlockDownloader::new(0, 100);

        let peer = PeerId(1);
        dl.add_peer(peer);

        let block = make_test_block(1);
        let hash = block.block_hash();

        // Pre-populate received_blocks (simulating unsolicited block)
        dl.received_blocks.insert(hash, block);

        // Enqueue the same block
        dl.enqueue_blocks(vec![(hash, 1)]);

        // Should not assign it (already received)
        let requests = dl.assign_requests();
        assert!(requests.is_empty() || dl.blocks_in_flight() == 0);
    }

    #[test]
    fn test_peer_count() {
        let mut dl = BlockDownloader::new(0, 100);

        assert_eq!(dl.peer_count(), 0);

        dl.add_peer(PeerId(1));
        assert_eq!(dl.peer_count(), 1);

        dl.add_peer(PeerId(2));
        assert_eq!(dl.peer_count(), 2);

        dl.remove_peer(PeerId(1));
        assert_eq!(dl.peer_count(), 1);
    }

    #[test]
    fn test_set_best_header_height() {
        let mut dl = BlockDownloader::new(0, 100);

        assert_eq!(dl.best_header_height(), 100);

        dl.set_best_header_height(500);
        assert_eq!(dl.best_header_height(), 500);
    }
}
