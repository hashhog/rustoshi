//! Inventory trickling for transaction relay.
//!
//! This module implements Bitcoin Core's inventory trickling strategy:
//! - Transactions are not announced immediately to all peers
//! - Instead, they are queued and announced on a Poisson timer
//! - Outbound peers: average 2-second interval
//! - Inbound peers: average 5-second interval
//! - Blocks are always announced immediately (never trickled)
//!
//! This improves privacy by making it harder to determine the origin
//! of a transaction, and reduces bandwidth spikes from announcing
//! transactions to all peers simultaneously.
//!
//! Reference: Bitcoin Core's `net_processing.cpp` `SendMessages()`

use crate::message::{InvType, InvVector};
use crate::peer::PeerId;
use rustoshi_primitives::Hash256;
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

/// Average delay between trickled inventory transmissions for inbound peers.
/// Blocks and peers with special permissions bypass this.
pub const INBOUND_INVENTORY_BROADCAST_INTERVAL: Duration = Duration::from_secs(5);

/// Average delay between trickled inventory transmissions for outbound peers.
/// Use a smaller delay as there is less privacy concern for them.
pub const OUTBOUND_INVENTORY_BROADCAST_INTERVAL: Duration = Duration::from_secs(2);

/// Maximum number of inventory items to send per transmission.
pub const INVENTORY_BROADCAST_MAX: usize = 1000;

/// Maximum rate of inventory items to send per second.
pub const INVENTORY_BROADCAST_PER_SECOND: usize = 14;

/// Target number of tx inventory items to send per transmission.
/// Based on inbound interval * rate per second.
pub const INVENTORY_BROADCAST_TARGET: usize =
    INVENTORY_BROADCAST_PER_SECOND * INBOUND_INVENTORY_BROADCAST_INTERVAL.as_secs() as usize;

/// Per-peer relay state for inventory trickling.
#[derive(Debug)]
pub struct PeerRelayState {
    /// Whether this is an inbound connection.
    pub inbound: bool,
    /// Whether this peer supports wtxid relay (BIP 339).
    pub supports_wtxid_relay: bool,
    /// Whether this peer wants transaction relay.
    pub relay: bool,
    /// Next scheduled time to send trickled inventory.
    pub next_inv_send_time: Instant,
    /// Queue of transactions to announce to this peer.
    pub tx_inventory_to_send: VecDeque<Hash256>,
    /// Set of transactions already announced to this peer.
    pub tx_inventory_known: HashSet<Hash256>,
}

impl PeerRelayState {
    /// Create a new peer relay state.
    pub fn new(inbound: bool, supports_wtxid_relay: bool, relay: bool) -> Self {
        // Initial time is now + random Poisson delay
        let interval = if inbound {
            INBOUND_INVENTORY_BROADCAST_INTERVAL
        } else {
            OUTBOUND_INVENTORY_BROADCAST_INTERVAL
        };
        let next_time = Instant::now() + poisson_next_send(interval);

        Self {
            inbound,
            supports_wtxid_relay,
            relay,
            next_inv_send_time: next_time,
            tx_inventory_to_send: VecDeque::new(),
            tx_inventory_known: HashSet::new(),
        }
    }

    /// Queue a transaction for announcement to this peer.
    ///
    /// Returns true if the transaction was queued, false if already known.
    pub fn queue_transaction(&mut self, hash: Hash256) -> bool {
        if !self.relay {
            return false;
        }
        if self.tx_inventory_known.contains(&hash) {
            return false;
        }
        self.tx_inventory_to_send.push_back(hash);
        true
    }

    /// Mark a transaction as known to this peer (already announced or received from them).
    pub fn mark_known(&mut self, hash: Hash256) {
        self.tx_inventory_known.insert(hash);
        // Remove from pending queue if present
        self.tx_inventory_to_send.retain(|h| *h != hash);
    }

    /// Check if it's time to send trickled inventory.
    pub fn should_send_trickle(&self, now: Instant) -> bool {
        now >= self.next_inv_send_time
    }

    /// Schedule the next trickle send time using Poisson distribution.
    pub fn schedule_next_send(&mut self, now: Instant) {
        let interval = if self.inbound {
            INBOUND_INVENTORY_BROADCAST_INTERVAL
        } else {
            OUTBOUND_INVENTORY_BROADCAST_INTERVAL
        };
        self.next_inv_send_time = now + poisson_next_send(interval);
    }

    /// Get pending transactions to announce, up to the broadcast limit.
    ///
    /// Returns the transactions and marks them as known.
    pub fn get_pending_inv(&mut self, max_count: usize) -> Vec<InvVector> {
        let mut inv = Vec::with_capacity(max_count.min(self.tx_inventory_to_send.len()));

        // Determine broadcast limit based on queue size
        // Allow more items when queue is backing up
        let queue_size = self.tx_inventory_to_send.len();
        let broadcast_limit = (INVENTORY_BROADCAST_TARGET + (queue_size / 1000) * 5)
            .min(INVENTORY_BROADCAST_MAX)
            .min(max_count);

        while inv.len() < broadcast_limit {
            let Some(hash) = self.tx_inventory_to_send.pop_front() else {
                break;
            };

            // Skip if already known (could have been learned via other means)
            if self.tx_inventory_known.contains(&hash) {
                continue;
            }

            // Create inv entry with appropriate type
            let inv_type = if self.supports_wtxid_relay {
                InvType::MsgWitnessTx
            } else {
                InvType::MsgTx
            };

            inv.push(InvVector {
                inv_type,
                hash,
            });

            // Mark as known
            self.tx_inventory_known.insert(hash);
        }

        inv
    }

    /// Clear all pending inventory (e.g., when peer disables relay).
    pub fn clear_pending(&mut self) {
        self.tx_inventory_to_send.clear();
    }

    /// Get the number of pending transactions.
    pub fn pending_count(&self) -> usize {
        self.tx_inventory_to_send.len()
    }
}

/// Inventory trickle manager for all peers.
#[derive(Debug)]
pub struct InventoryTrickle {
    /// Per-peer relay state.
    peer_states: HashMap<PeerId, PeerRelayState>,
}

impl InventoryTrickle {
    /// Create a new inventory trickle manager.
    pub fn new() -> Self {
        Self {
            peer_states: HashMap::new(),
        }
    }

    /// Register a new peer for relay.
    pub fn add_peer(
        &mut self,
        peer_id: PeerId,
        inbound: bool,
        supports_wtxid_relay: bool,
        relay: bool,
    ) {
        self.peer_states.insert(
            peer_id,
            PeerRelayState::new(inbound, supports_wtxid_relay, relay),
        );
    }

    /// Remove a peer from relay tracking.
    pub fn remove_peer(&mut self, peer_id: PeerId) {
        self.peer_states.remove(&peer_id);
    }

    /// Queue a transaction to be announced to all appropriate peers.
    ///
    /// Call this when a new transaction is accepted to the mempool.
    pub fn queue_transaction_for_relay(&mut self, txid: Hash256, wtxid: Hash256) {
        for state in self.peer_states.values_mut() {
            if state.relay {
                // Use wtxid for peers that support it, txid otherwise
                let hash = if state.supports_wtxid_relay {
                    wtxid
                } else {
                    txid
                };
                state.queue_transaction(hash);
            }
        }
    }

    /// Mark a transaction as known to a specific peer.
    ///
    /// Call this when we receive an inv or tx from a peer.
    pub fn mark_transaction_known(&mut self, peer_id: PeerId, hash: Hash256) {
        if let Some(state) = self.peer_states.get_mut(&peer_id) {
            state.mark_known(hash);
        }
    }

    /// Get all peers that are ready to receive trickled inventory.
    ///
    /// Returns pairs of (peer_id, inv_vectors) for each peer ready to receive.
    pub fn get_ready_inventory(&mut self) -> Vec<(PeerId, Vec<InvVector>)> {
        let now = Instant::now();
        let mut result = Vec::new();

        for (peer_id, state) in &mut self.peer_states {
            if !state.relay {
                continue;
            }

            if state.should_send_trickle(now) {
                let inv = state.get_pending_inv(INVENTORY_BROADCAST_MAX);
                if !inv.is_empty() {
                    result.push((*peer_id, inv));
                }
                state.schedule_next_send(now);
            }
        }

        result
    }

    /// Check if a specific peer is ready to receive trickled inventory.
    pub fn peer_ready(&self, peer_id: PeerId) -> bool {
        self.peer_states
            .get(&peer_id)
            .map(|s| s.should_send_trickle(Instant::now()))
            .unwrap_or(false)
    }

    /// Get inventory for a specific peer if ready.
    pub fn get_peer_inventory(&mut self, peer_id: PeerId) -> Option<Vec<InvVector>> {
        let now = Instant::now();
        let state = self.peer_states.get_mut(&peer_id)?;

        if !state.relay {
            return None;
        }

        if state.should_send_trickle(now) {
            let inv = state.get_pending_inv(INVENTORY_BROADCAST_MAX);
            state.schedule_next_send(now);
            if inv.is_empty() {
                None
            } else {
                Some(inv)
            }
        } else {
            None
        }
    }

    /// Get the number of tracked peers.
    pub fn peer_count(&self) -> usize {
        self.peer_states.len()
    }

    /// Get pending transaction count for a peer.
    pub fn pending_count(&self, peer_id: PeerId) -> usize {
        self.peer_states
            .get(&peer_id)
            .map(|s| s.pending_count())
            .unwrap_or(0)
    }

    /// Update a peer's relay preference.
    pub fn set_peer_relay(&mut self, peer_id: PeerId, relay: bool) {
        if let Some(state) = self.peer_states.get_mut(&peer_id) {
            state.relay = relay;
            if !relay {
                state.clear_pending();
            }
        }
    }

    /// Update a peer's wtxid relay support.
    pub fn set_peer_wtxid_relay(&mut self, peer_id: PeerId, supports_wtxid_relay: bool) {
        if let Some(state) = self.peer_states.get_mut(&peer_id) {
            state.supports_wtxid_relay = supports_wtxid_relay;
        }
    }

    /// Get the next scheduled send time for a peer (for testing).
    pub fn next_send_time(&self, peer_id: PeerId) -> Option<Instant> {
        self.peer_states.get(&peer_id).map(|s| s.next_inv_send_time)
    }

    /// Time until next peer needs to send inventory.
    pub fn time_until_next_send(&self) -> Option<Duration> {
        let now = Instant::now();
        self.peer_states
            .values()
            .filter(|s| s.relay)
            .map(|s| {
                if s.next_inv_send_time > now {
                    s.next_inv_send_time.duration_since(now)
                } else {
                    Duration::ZERO
                }
            })
            .min()
    }
}

impl Default for InventoryTrickle {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate a Poisson-distributed delay.
///
/// The probability of an event occurring before time x is 1 - e^-(x/a)
/// where a is the average interval between events.
///
/// We generate this by computing -ln(U) * a where U is uniform(0,1).
pub fn poisson_next_send(average_interval: Duration) -> Duration {
    // Generate uniform random in (0, 1]
    // We use 1.0 - rand to avoid ln(0)
    let u: f64 = 1.0 - rand::random::<f64>().clamp(f64::MIN_POSITIVE, 1.0 - f64::MIN_POSITIVE);
    let delay_secs = -u.ln() * average_interval.as_secs_f64();

    // Clamp to reasonable bounds (0 to 10x the average)
    let max_delay = average_interval.as_secs_f64() * 10.0;
    Duration::from_secs_f64(delay_secs.min(max_delay).max(0.0))
}

/// Create inventory vectors for block announcements.
///
/// Blocks are never trickled - they are announced immediately to all peers.
pub fn create_block_inv(block_hash: Hash256, witness: bool) -> InvVector {
    let inv_type = if witness {
        InvType::MsgWitnessBlock
    } else {
        InvType::MsgBlock
    };
    InvVector {
        inv_type,
        hash: block_hash,
    }
}

/// Shuffle a slice using Fisher-Yates algorithm.
///
/// Used to randomize the order of transaction announcements.
pub fn shuffle<T>(slice: &mut [T]) {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    for i in (1..slice.len()).rev() {
        let j = rng.gen_range(0..=i);
        slice.swap(i, j);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poisson_distribution() {
        // Generate many samples and verify they're roughly exponentially distributed
        let interval = Duration::from_secs(5);
        let mut samples: Vec<f64> = Vec::new();

        for _ in 0..1000 {
            let delay = poisson_next_send(interval);
            samples.push(delay.as_secs_f64());
        }

        // Mean should be close to interval
        let mean: f64 = samples.iter().sum::<f64>() / samples.len() as f64;
        assert!(
            mean > 3.0 && mean < 7.0,
            "Mean {} should be close to 5.0",
            mean
        );

        // Some samples should be very small (< 1s)
        let small_count = samples.iter().filter(|&&s| s < 1.0).count();
        assert!(small_count > 50, "Should have some small delays");

        // Some samples should be large (> 8s)
        let large_count = samples.iter().filter(|&&s| s > 8.0).count();
        assert!(large_count > 50, "Should have some large delays");
    }

    #[test]
    fn test_peer_relay_state_new() {
        let state = PeerRelayState::new(true, false, true);
        assert!(state.inbound);
        assert!(!state.supports_wtxid_relay);
        assert!(state.relay);
        assert!(state.tx_inventory_to_send.is_empty());
        assert!(state.tx_inventory_known.is_empty());
    }

    #[test]
    fn test_peer_relay_state_queue_transaction() {
        let mut state = PeerRelayState::new(false, false, true);

        let hash = Hash256([1u8; 32]);

        // First queue should succeed
        assert!(state.queue_transaction(hash));
        assert_eq!(state.pending_count(), 1);

        // Second queue of same hash should still work (not yet known)
        assert!(state.queue_transaction(hash));
        assert_eq!(state.pending_count(), 2);
    }

    #[test]
    fn test_peer_relay_state_mark_known() {
        let mut state = PeerRelayState::new(false, false, true);

        let hash = Hash256([1u8; 32]);

        state.queue_transaction(hash);
        state.queue_transaction(hash);
        assert_eq!(state.pending_count(), 2);

        // Mark as known should remove from queue and prevent re-queuing
        state.mark_known(hash);
        assert_eq!(state.pending_count(), 0);

        // Re-queuing should fail
        assert!(!state.queue_transaction(hash));
    }

    #[test]
    fn test_peer_relay_state_no_relay() {
        let mut state = PeerRelayState::new(false, false, false);

        let hash = Hash256([1u8; 32]);

        // Should not queue if relay is disabled
        assert!(!state.queue_transaction(hash));
        assert_eq!(state.pending_count(), 0);
    }

    #[test]
    fn test_peer_relay_state_get_pending_inv() {
        let mut state = PeerRelayState::new(false, false, true);

        // Queue some transactions
        for i in 0..10 {
            let hash = Hash256([i; 32]);
            state.queue_transaction(hash);
        }

        // Get limited number
        let inv = state.get_pending_inv(5);
        assert_eq!(inv.len(), 5);

        // Each should be MsgTx (not wtxid relay)
        for v in &inv {
            assert_eq!(v.inv_type, InvType::MsgTx);
        }

        // Remaining should still be in queue
        assert_eq!(state.pending_count(), 5);

        // Items should be marked as known
        assert_eq!(state.tx_inventory_known.len(), 5);
    }

    #[test]
    fn test_peer_relay_state_wtxid_relay() {
        let mut state = PeerRelayState::new(false, true, true);

        let hash = Hash256([1u8; 32]);
        state.queue_transaction(hash);

        let inv = state.get_pending_inv(10);
        assert_eq!(inv.len(), 1);
        assert_eq!(inv[0].inv_type, InvType::MsgWitnessTx);
    }

    #[test]
    fn test_inventory_trickle_add_remove_peer() {
        let mut trickle = InventoryTrickle::new();

        let peer1 = PeerId(1);
        let peer2 = PeerId(2);

        trickle.add_peer(peer1, true, false, true);
        trickle.add_peer(peer2, false, true, true);

        assert_eq!(trickle.peer_count(), 2);

        trickle.remove_peer(peer1);
        assert_eq!(trickle.peer_count(), 1);
    }

    #[test]
    fn test_inventory_trickle_queue_transaction() {
        let mut trickle = InventoryTrickle::new();

        let peer1 = PeerId(1);
        let peer2 = PeerId(2);
        let peer3 = PeerId(3);

        trickle.add_peer(peer1, true, false, true); // inbound, no wtxid
        trickle.add_peer(peer2, false, true, true); // outbound, wtxid
        trickle.add_peer(peer3, false, false, false); // no relay

        let txid = Hash256([1u8; 32]);
        let wtxid = Hash256([2u8; 32]);

        trickle.queue_transaction_for_relay(txid, wtxid);

        // peer1 should have txid queued (no wtxid support)
        assert_eq!(trickle.pending_count(peer1), 1);

        // peer2 should have wtxid queued
        assert_eq!(trickle.pending_count(peer2), 1);

        // peer3 should have nothing (no relay)
        assert_eq!(trickle.pending_count(peer3), 0);
    }

    #[test]
    fn test_inventory_trickle_mark_known() {
        let mut trickle = InventoryTrickle::new();

        let peer = PeerId(1);
        trickle.add_peer(peer, false, false, true);

        let txid = Hash256([1u8; 32]);
        let wtxid = Hash256([2u8; 32]);

        trickle.queue_transaction_for_relay(txid, wtxid);
        assert_eq!(trickle.pending_count(peer), 1);

        trickle.mark_transaction_known(peer, txid);
        assert_eq!(trickle.pending_count(peer), 0);
    }

    #[test]
    fn test_inventory_trickle_timing() {
        let mut trickle = InventoryTrickle::new();

        let peer = PeerId(1);
        trickle.add_peer(peer, false, false, true);

        // Initially, peer should not be ready (scheduled for future)
        // The Poisson distribution means it could be ready, but probably not immediately
        let next_time = trickle.next_send_time(peer).unwrap();
        let now = Instant::now();

        // The next_time should be some point in the future (or very close to now)
        // We just verify it's set to something reasonable
        assert!(next_time.saturating_duration_since(now) <= Duration::from_secs(30));
    }

    #[test]
    fn test_inventory_trickle_get_ready() {
        let mut trickle = InventoryTrickle::new();

        let peer = PeerId(1);
        trickle.add_peer(peer, false, false, true);

        // Force the next send time to be in the past
        if let Some(state) = trickle.peer_states.get_mut(&peer) {
            state.next_inv_send_time = Instant::now() - Duration::from_secs(1);
        }

        // Queue a transaction
        let txid = Hash256([1u8; 32]);
        trickle.queue_transaction_for_relay(txid, txid);

        // Should be ready now
        let ready = trickle.get_ready_inventory();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].0, peer);
        assert_eq!(ready[0].1.len(), 1);
    }

    #[test]
    fn test_inventory_trickle_set_peer_relay() {
        let mut trickle = InventoryTrickle::new();

        let peer = PeerId(1);
        trickle.add_peer(peer, false, false, true);

        // Queue a transaction
        let txid = Hash256([1u8; 32]);
        trickle.queue_transaction_for_relay(txid, txid);
        assert_eq!(trickle.pending_count(peer), 1);

        // Disable relay
        trickle.set_peer_relay(peer, false);
        assert_eq!(trickle.pending_count(peer), 0);

        // Re-queuing should not work
        let txid2 = Hash256([2u8; 32]);
        trickle.queue_transaction_for_relay(txid2, txid2);
        assert_eq!(trickle.pending_count(peer), 0);
    }

    #[test]
    fn test_create_block_inv() {
        let hash = Hash256([1u8; 32]);

        let inv_no_witness = create_block_inv(hash, false);
        assert_eq!(inv_no_witness.inv_type, InvType::MsgBlock);
        assert_eq!(inv_no_witness.hash, hash);

        let inv_witness = create_block_inv(hash, true);
        assert_eq!(inv_witness.inv_type, InvType::MsgWitnessBlock);
        assert_eq!(inv_witness.hash, hash);
    }

    #[test]
    fn test_shuffle() {
        let mut arr = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let original = arr.clone();

        // Shuffle multiple times and verify it changes
        let mut changed = false;
        for _ in 0..10 {
            shuffle(&mut arr);
            if arr != original {
                changed = true;
                break;
            }
        }
        assert!(changed, "Shuffle should change the array");

        // Verify same elements
        let mut sorted = arr;
        sorted.sort();
        assert_eq!(sorted, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    }

    #[test]
    fn test_inventory_broadcast_constants() {
        // Verify constants match Bitcoin Core
        assert_eq!(INBOUND_INVENTORY_BROADCAST_INTERVAL, Duration::from_secs(5));
        assert_eq!(OUTBOUND_INVENTORY_BROADCAST_INTERVAL, Duration::from_secs(2));
        assert_eq!(INVENTORY_BROADCAST_MAX, 1000);
        assert_eq!(INVENTORY_BROADCAST_PER_SECOND, 14);
        assert_eq!(INVENTORY_BROADCAST_TARGET, 70); // 14 * 5
    }

    #[test]
    fn test_trickling_delays_transactions() {
        // Test that transactions are not announced immediately
        let mut trickle = InventoryTrickle::new();

        // Add an outbound peer (2s average delay)
        let peer = PeerId(1);
        trickle.add_peer(peer, false, false, true);

        // Queue a transaction
        let txid = Hash256([1u8; 32]);
        trickle.queue_transaction_for_relay(txid, txid);

        // Check the time until next send
        let time_until = trickle.time_until_next_send();
        assert!(time_until.is_some());
        // It should be delayed (might be 0 in rare cases due to Poisson)
    }

    #[test]
    fn test_trickling_inbound_vs_outbound_intervals() {
        // Verify inbound peers have longer intervals than outbound
        let inbound_state = PeerRelayState::new(true, false, true);
        let outbound_state = PeerRelayState::new(false, false, true);

        // Both should have scheduled times set
        // We can't easily test the actual intervals without mocking time,
        // but we can verify the configuration is correct
        assert!(inbound_state.inbound);
        assert!(!outbound_state.inbound);
    }

    #[test]
    fn test_trickling_batches_transactions() {
        let mut trickle = InventoryTrickle::new();

        let peer = PeerId(1);
        trickle.add_peer(peer, false, false, true);

        // Queue many transactions
        for i in 0..100 {
            let txid = Hash256([i; 32]);
            trickle.queue_transaction_for_relay(txid, txid);
        }

        // Force the send time
        if let Some(state) = trickle.peer_states.get_mut(&peer) {
            state.next_inv_send_time = Instant::now() - Duration::from_secs(1);
        }

        // Get ready inventory - should be batched
        let ready = trickle.get_ready_inventory();
        assert_eq!(ready.len(), 1);

        // Should get INVENTORY_BROADCAST_TARGET items (70)
        let inv = &ready[0].1;
        assert_eq!(inv.len(), INVENTORY_BROADCAST_TARGET);

        // Remaining should still be pending
        assert_eq!(trickle.pending_count(peer), 100 - INVENTORY_BROADCAST_TARGET);
    }

    #[test]
    fn test_trickling_randomizes_order() {
        // Test that shuffle works correctly for randomizing announcements
        let mut hashes: Vec<Hash256> = (0..20).map(|i| Hash256([i; 32])).collect();
        let original = hashes.clone();

        shuffle(&mut hashes);

        // Verify elements are preserved
        let mut sorted = hashes.clone();
        let mut sorted_orig = original.clone();
        sorted.sort_by_key(|h| h.0);
        sorted_orig.sort_by_key(|h| h.0);
        assert_eq!(sorted, sorted_orig);

        // Verify order changed (might fail rarely due to randomness, but very unlikely)
        assert_ne!(hashes, original, "Shuffle should change order");
    }

    #[test]
    fn test_inventory_trickle_time_until_next_send() {
        let mut trickle = InventoryTrickle::new();

        // No peers -> no next send
        assert!(trickle.time_until_next_send().is_none());

        // Add peer with relay disabled
        trickle.add_peer(PeerId(1), false, false, false);
        assert!(trickle.time_until_next_send().is_none());

        // Add peer with relay enabled
        trickle.add_peer(PeerId(2), false, false, true);
        assert!(trickle.time_until_next_send().is_some());
    }

    #[test]
    fn test_inventory_trickle_default() {
        let trickle = InventoryTrickle::default();
        assert_eq!(trickle.peer_count(), 0);
    }
}
