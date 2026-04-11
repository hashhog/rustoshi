//! Inventory trickling for transaction relay.
//!
//! This module implements Bitcoin Core's inventory trickling strategy:
//! - Transactions are not announced immediately to all peers
//! - Instead, they are queued and announced on a Poisson timer
//! - Outbound peers: average 2-second interval
//! - Inbound peers: average 5-second interval
//! - Blocks are always announced immediately (never trickled)
//!
//! Also implements BIP 133 feefilter:
//! - Peers announce their minimum fee rate
//! - Transactions below this rate are not relayed to that peer
//! - Reduces bandwidth waste from transactions peers will reject
//!
//! And incremental relay fee enforcement:
//! - For RBF, replacement must pay additional fees covering its own relay cost
//! - Default incremental relay fee: 1000 sat/kvB (1 sat/vB)
//!
//! This improves privacy by making it harder to determine the origin
//! of a transaction, and reduces bandwidth spikes from announcing
//! transactions to all peers simultaneously.
//!
//! Reference: Bitcoin Core's `net_processing.cpp` `SendMessages()`

use crate::message::{InvType, InvVector};
use crate::peer::PeerId;
use rustoshi_primitives::Hash256;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
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

// =============================================================================
// BIP 133 Feefilter Constants
// =============================================================================

/// Average delay between feefilter broadcasts (10 minutes).
/// Reference: Bitcoin Core `AVG_FEEFILTER_BROADCAST_INTERVAL`
pub const AVG_FEEFILTER_BROADCAST_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// Maximum feefilter broadcast delay after significant change (5 minutes).
/// If the fee filter changes substantially, we schedule a broadcast within this time.
/// Reference: Bitcoin Core `MAX_FEEFILTER_CHANGE_DELAY`
pub const MAX_FEEFILTER_CHANGE_DELAY: Duration = Duration::from_secs(5 * 60);

/// Default minimum relay fee rate in sat/kvB (1000 sat/kvB = 1 sat/vB).
/// This is the minimum fee rate we will relay transactions at.
/// Reference: Bitcoin Core `DEFAULT_MIN_RELAY_TX_FEE`
pub const DEFAULT_MIN_RELAY_FEE: u64 = 1000;

/// Default incremental relay fee rate in sat/kvB (1000 sat/kvB = 1 sat/vB).
/// For RBF, the replacement must pay at least this much per kvB more than the original.
/// Also used as the minimum fee rate step for mempool limiting.
/// Reference: Bitcoin Core `DEFAULT_INCREMENTAL_RELAY_FEE`
pub const DEFAULT_INCREMENTAL_RELAY_FEE: u64 = 1000;

/// Maximum money value (21 million BTC in satoshis).
/// Used as the feefilter value during IBD to signal "don't send me txs".
pub const MAX_MONEY: u64 = 21_000_000 * 100_000_000;

/// Fee filter spacing multiplier for privacy quantization.
/// Fee rates are rounded to multiples of this factor (1.1x steps).
/// Reference: Bitcoin Core `FeeFilterRounder::FEE_FILTER_SPACING`
pub const FEE_FILTER_SPACING: f64 = 1.1;

/// Maximum feerate for the fee filter set (10 BTC/kvB).
pub const MAX_FILTER_FEERATE: f64 = 1e7;

// =============================================================================
// FeeFilterRounder
// =============================================================================

/// Rounds fee rates for privacy before broadcasting.
///
/// This quantizes fee rates to a set of discrete values to prevent
/// fingerprinting based on the exact mempool minimum fee.
/// The values form a geometric sequence with ratio FEE_FILTER_SPACING.
///
/// Reference: Bitcoin Core `FeeFilterRounder`
#[derive(Debug)]
pub struct FeeFilterRounder {
    /// Pre-computed set of fee values (sorted).
    fee_set: BTreeSet<u64>,
}

impl FeeFilterRounder {
    /// Create a new FeeFilterRounder with fee buckets starting from `min_incremental_fee`.
    pub fn new(min_incremental_fee: u64) -> Self {
        let mut fee_set = BTreeSet::new();
        let mut fee = min_incremental_fee as f64;

        while fee <= MAX_FILTER_FEERATE {
            fee_set.insert(fee as u64);
            fee *= FEE_FILTER_SPACING;
        }

        Self { fee_set }
    }

    /// Round a fee rate to the nearest bucket value.
    ///
    /// Randomly selects between the lower and upper bound with 50% probability
    /// to add noise for privacy.
    pub fn round(&self, current_min_fee: u64) -> u64 {
        // Find the first bucket >= current_min_fee
        let upper = self.fee_set.range(current_min_fee..).next();
        // Find the last bucket < current_min_fee
        let lower = self.fee_set.range(..current_min_fee).next_back();

        match (lower, upper) {
            (None, None) => 0,
            (Some(&l), None) => l,
            (None, Some(&u)) => u,
            (Some(&l), Some(&u)) => {
                // Randomly choose between lower and upper with 50% probability
                if rand::random::<bool>() {
                    l
                } else {
                    u
                }
            }
        }
    }

    /// Get the number of fee buckets.
    pub fn bucket_count(&self) -> usize {
        self.fee_set.len()
    }
}

impl Default for FeeFilterRounder {
    fn default() -> Self {
        Self::new(DEFAULT_INCREMENTAL_RELAY_FEE)
    }
}

// =============================================================================
// FeeFilterState
// =============================================================================

/// Per-peer feefilter state for BIP 133.
///
/// Tracks:
/// - The feefilter we've received from this peer (their minimum acceptable fee)
/// - The feefilter we've sent to this peer (our minimum acceptable fee)
/// - Scheduling for when to send the next feefilter update
#[derive(Debug)]
pub struct FeeFilterState {
    /// The minimum fee rate (sat/kvB) this peer will accept.
    /// Received via feefilter message from the peer.
    pub fee_filter_received: u64,

    /// The last fee filter value we sent to this peer.
    pub fee_filter_sent: u64,

    /// Next scheduled time to send a feefilter message.
    pub next_send_feefilter: Instant,

    /// Whether this peer supports feefilter (protocol version >= 70013).
    pub supports_feefilter: bool,

    /// Whether this is a block-relay-only connection.
    /// Block-relay-only peers don't need feefilter since they don't relay txs.
    pub is_block_only: bool,
}

impl FeeFilterState {
    /// Create a new FeeFilterState for a peer.
    pub fn new(supports_feefilter: bool, is_block_only: bool) -> Self {
        Self {
            fee_filter_received: 0,
            fee_filter_sent: 0,
            next_send_feefilter: Instant::now() + poisson_next_send(AVG_FEEFILTER_BROADCAST_INTERVAL),
            supports_feefilter,
            is_block_only,
        }
    }

    /// Update the received feefilter from this peer.
    pub fn set_received(&mut self, fee_rate: u64) {
        self.fee_filter_received = fee_rate;
    }

    /// Check if a transaction with the given fee rate should be relayed to this peer.
    ///
    /// Returns true if the tx fee rate meets or exceeds the peer's feefilter.
    pub fn should_relay(&self, tx_fee_rate: u64) -> bool {
        tx_fee_rate >= self.fee_filter_received
    }

    /// Check if we should send a feefilter update now.
    ///
    /// Returns Some(fee_rate) if we should send, None otherwise.
    pub fn maybe_send_feefilter(
        &mut self,
        current_min_fee: u64,
        min_relay_fee: u64,
        rounder: &FeeFilterRounder,
        now: Instant,
        is_ibd: bool,
    ) -> Option<u64> {
        if !self.supports_feefilter || self.is_block_only {
            return None;
        }

        // During IBD, signal that we don't want transactions
        let current_filter = if is_ibd {
            MAX_MONEY
        } else {
            current_min_fee
        };

        // If we sent MAX_MONEY during IBD and are now out of IBD,
        // force an immediate update
        if !is_ibd && self.fee_filter_sent == rounder.round(MAX_MONEY) {
            self.next_send_feefilter = now;
        }

        if now >= self.next_send_feefilter {
            let mut filter_to_send = rounder.round(current_filter);
            // Always send at least the minimum relay fee
            filter_to_send = filter_to_send.max(min_relay_fee);

            let should_send = filter_to_send != self.fee_filter_sent;

            // Schedule next send regardless
            self.next_send_feefilter = now + poisson_next_send(AVG_FEEFILTER_BROADCAST_INTERVAL);

            if should_send {
                self.fee_filter_sent = filter_to_send;
                return Some(filter_to_send);
            }
        } else {
            // Check if the fee filter has changed substantially
            // and we should send earlier than scheduled
            let remaining = self.next_send_feefilter.saturating_duration_since(now);

            if remaining > MAX_FEEFILTER_CHANGE_DELAY {
                // Check for significant change: < 75% or > 133% of last sent value
                let sent = self.fee_filter_sent;
                if sent > 0 && (current_filter < 3 * sent / 4 || current_filter > 4 * sent / 3) {
                    // Reschedule to within MAX_FEEFILTER_CHANGE_DELAY
                    self.next_send_feefilter = now + rand_duration(MAX_FEEFILTER_CHANGE_DELAY);
                }
            }
        }

        None
    }
}

/// Generate a random duration up to max_duration.
fn rand_duration(max_duration: Duration) -> Duration {
    let secs = rand::random::<f64>() * max_duration.as_secs_f64();
    Duration::from_secs_f64(secs)
}

// =============================================================================
// Incremental Relay Fee
// =============================================================================

/// Check if a replacement transaction pays sufficient fees for RBF.
///
/// For BIP 125 RBF, the replacement transaction must:
/// 1. Pay at least as much total fee as the original (Rule #3)
/// 2. Pay an additional fee to cover its own relay cost (Rule #4)
///
/// The additional fee must be at least: `incremental_relay_fee * replacement_vsize`
///
/// # Arguments
/// * `original_fees` - Total fees of the transaction(s) being replaced
/// * `replacement_fees` - Total fees of the replacement transaction
/// * `replacement_vsize` - Virtual size of the replacement transaction
/// * `incremental_relay_fee` - Incremental relay fee rate in sat/kvB
///
/// # Returns
/// * `Ok(())` if the fees are sufficient
/// * `Err(String)` with an error message if insufficient
pub fn pays_for_rbf(
    original_fees: u64,
    replacement_fees: u64,
    replacement_vsize: u64,
    incremental_relay_fee: u64,
) -> Result<(), String> {
    // Rule #3: The replacement fees must be greater than or equal to fees of the
    // transactions it replaces, otherwise the bandwidth used by those conflicting
    // transactions would not be paid for.
    if replacement_fees < original_fees {
        return Err(format!(
            "insufficient fee: replacement fee {} < original fee {}",
            replacement_fees, original_fees
        ));
    }

    // Rule #4: The new transaction must pay for its own bandwidth.
    // Otherwise, we have a DoS vector where attackers can cause a transaction to be
    // replaced (and relayed) repeatedly by increasing the fee by tiny amounts.
    let additional_fees = replacement_fees.saturating_sub(original_fees);
    let required_additional = get_fee(incremental_relay_fee, replacement_vsize);

    if additional_fees < required_additional {
        return Err(format!(
            "insufficient fee: additional fee {} < required {} (incremental relay fee for {} vbytes)",
            additional_fees, required_additional, replacement_vsize
        ));
    }

    Ok(())
}

/// Calculate the fee for a given fee rate and virtual size.
///
/// fee = ceil(fee_rate * vsize / 1000)
///
/// Fee rate is in sat/kvB, vsize is in vbytes.
pub fn get_fee(fee_rate: u64, vsize: u64) -> u64 {
    // fee = ceil(fee_rate * vsize / 1000)
    // Using integer math: (fee_rate * vsize + 999) / 1000
    fee_rate.saturating_mul(vsize).div_ceil(1000)
}

/// Calculate the fee rate from fee and virtual size.
///
/// fee_rate = fee * 1000 / vsize (in sat/kvB)
pub fn get_fee_rate(fee: u64, vsize: u64) -> u64 {
    if vsize == 0 {
        return 0;
    }
    fee.saturating_mul(1000) / vsize
}

// =============================================================================
// FeeFilterManager
// =============================================================================

/// Manager for all peers' feefilter state.
#[derive(Debug)]
pub struct FeeFilterManager {
    /// Per-peer feefilter state.
    peer_states: HashMap<PeerId, FeeFilterState>,

    /// Fee filter rounder for privacy.
    rounder: FeeFilterRounder,

    /// Current minimum relay fee rate (sat/kvB).
    min_relay_fee: u64,

    /// Incremental relay fee rate (sat/kvB).
    incremental_relay_fee: u64,
}

impl FeeFilterManager {
    /// Create a new FeeFilterManager.
    pub fn new(min_relay_fee: u64, incremental_relay_fee: u64) -> Self {
        Self {
            peer_states: HashMap::new(),
            rounder: FeeFilterRounder::new(incremental_relay_fee),
            min_relay_fee,
            incremental_relay_fee,
        }
    }

    /// Add a peer to the manager.
    pub fn add_peer(&mut self, peer_id: PeerId, supports_feefilter: bool, is_block_only: bool) {
        self.peer_states.insert(
            peer_id,
            FeeFilterState::new(supports_feefilter, is_block_only),
        );
    }

    /// Remove a peer from the manager.
    pub fn remove_peer(&mut self, peer_id: PeerId) {
        self.peer_states.remove(&peer_id);
    }

    /// Handle a received feefilter message from a peer.
    pub fn handle_feefilter(&mut self, peer_id: PeerId, fee_rate: u64) {
        if let Some(state) = self.peer_states.get_mut(&peer_id) {
            state.set_received(fee_rate);
        }
    }

    /// Get the feefilter received from a peer.
    pub fn get_peer_feefilter(&self, peer_id: PeerId) -> u64 {
        self.peer_states
            .get(&peer_id)
            .map(|s| s.fee_filter_received)
            .unwrap_or(0)
    }

    /// Check if a transaction should be relayed to a specific peer.
    ///
    /// Returns true if the tx fee rate meets or exceeds the peer's feefilter.
    pub fn should_relay_to_peer(&self, peer_id: PeerId, tx_fee_rate: u64) -> bool {
        self.peer_states
            .get(&peer_id)
            .map(|s| s.should_relay(tx_fee_rate))
            .unwrap_or(true)
    }

    /// Get pending feefilter messages to send.
    ///
    /// Returns a list of (peer_id, fee_rate) for each peer that needs a feefilter update.
    pub fn get_pending_feefilters(
        &mut self,
        current_mempool_min_fee: u64,
        is_ibd: bool,
    ) -> Vec<(PeerId, u64)> {
        let now = Instant::now();
        let mut updates = Vec::new();

        for (&peer_id, state) in &mut self.peer_states {
            if let Some(fee_rate) = state.maybe_send_feefilter(
                current_mempool_min_fee,
                self.min_relay_fee,
                &self.rounder,
                now,
                is_ibd,
            ) {
                updates.push((peer_id, fee_rate));
            }
        }

        updates
    }

    /// Check if a replacement transaction pays sufficient fees.
    pub fn pays_for_rbf(
        &self,
        original_fees: u64,
        replacement_fees: u64,
        replacement_vsize: u64,
    ) -> Result<(), String> {
        pays_for_rbf(
            original_fees,
            replacement_fees,
            replacement_vsize,
            self.incremental_relay_fee,
        )
    }

    /// Get the minimum relay fee rate.
    pub fn min_relay_fee(&self) -> u64 {
        self.min_relay_fee
    }

    /// Get the incremental relay fee rate.
    pub fn incremental_relay_fee(&self) -> u64 {
        self.incremental_relay_fee
    }

    /// Set the minimum relay fee rate.
    pub fn set_min_relay_fee(&mut self, fee_rate: u64) {
        self.min_relay_fee = fee_rate;
    }

    /// Get the number of tracked peers.
    pub fn peer_count(&self) -> usize {
        self.peer_states.len()
    }
}

impl Default for FeeFilterManager {
    fn default() -> Self {
        Self::new(DEFAULT_MIN_RELAY_FEE, DEFAULT_INCREMENTAL_RELAY_FEE)
    }
}

// =============================================================================
// Inventory Trickling
// =============================================================================

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

    // =========================================================================
    // FeeFilter Tests
    // =========================================================================

    #[test]
    fn test_feefilter_constants() {
        // Verify constants match Bitcoin Core
        assert_eq!(DEFAULT_MIN_RELAY_FEE, 1000); // 1000 sat/kvB
        assert_eq!(DEFAULT_INCREMENTAL_RELAY_FEE, 1000); // 1000 sat/kvB
        assert_eq!(AVG_FEEFILTER_BROADCAST_INTERVAL, Duration::from_secs(600)); // 10 min
        assert_eq!(MAX_FEEFILTER_CHANGE_DELAY, Duration::from_secs(300)); // 5 min
        assert_eq!(MAX_MONEY, 21_000_000 * 100_000_000); // 21M BTC in satoshis
    }

    #[test]
    fn test_fee_filter_rounder_creation() {
        let rounder = FeeFilterRounder::new(DEFAULT_INCREMENTAL_RELAY_FEE);
        // Should have many buckets from 1000 to 10M
        assert!(rounder.bucket_count() > 50);
        assert!(rounder.bucket_count() < 500);
    }

    #[test]
    fn test_fee_filter_rounder_round() {
        let rounder = FeeFilterRounder::new(1000);

        // Very small fee should round to first bucket or 0
        let rounded = rounder.round(100);
        assert!(rounded <= 1000);

        // Fee at a bucket should round near it
        let rounded = rounder.round(1000);
        assert!(rounded >= 900 && rounded <= 1100);

        // Large fee should round to a large bucket
        let rounded = rounder.round(1_000_000);
        assert!(rounded >= 500_000 && rounded <= 2_000_000);
    }

    #[test]
    fn test_fee_filter_rounder_default() {
        let rounder = FeeFilterRounder::default();
        assert!(rounder.bucket_count() > 0);
    }

    #[test]
    fn test_feefilter_state_new() {
        let state = FeeFilterState::new(true, false);
        assert!(state.supports_feefilter);
        assert!(!state.is_block_only);
        assert_eq!(state.fee_filter_received, 0);
        assert_eq!(state.fee_filter_sent, 0);
    }

    #[test]
    fn test_feefilter_state_set_received() {
        let mut state = FeeFilterState::new(true, false);
        state.set_received(5000);
        assert_eq!(state.fee_filter_received, 5000);
    }

    #[test]
    fn test_feefilter_state_should_relay() {
        let mut state = FeeFilterState::new(true, false);

        // With no feefilter set, should relay everything
        assert!(state.should_relay(0));
        assert!(state.should_relay(1000));

        // Set feefilter to 1000
        state.set_received(1000);

        // Should not relay below feefilter
        assert!(!state.should_relay(0));
        assert!(!state.should_relay(999));

        // Should relay at or above feefilter
        assert!(state.should_relay(1000));
        assert!(state.should_relay(2000));
    }

    #[test]
    fn test_feefilter_manager_add_remove_peer() {
        let mut manager = FeeFilterManager::default();

        let peer1 = PeerId(1);
        let peer2 = PeerId(2);

        manager.add_peer(peer1, true, false);
        manager.add_peer(peer2, true, true);

        assert_eq!(manager.peer_count(), 2);

        manager.remove_peer(peer1);
        assert_eq!(manager.peer_count(), 1);
    }

    #[test]
    fn test_feefilter_manager_handle_feefilter() {
        let mut manager = FeeFilterManager::default();

        let peer = PeerId(1);
        manager.add_peer(peer, true, false);

        // Initially no feefilter
        assert_eq!(manager.get_peer_feefilter(peer), 0);

        // Handle feefilter message
        manager.handle_feefilter(peer, 5000);
        assert_eq!(manager.get_peer_feefilter(peer), 5000);
    }

    #[test]
    fn test_feefilter_manager_should_relay() {
        let mut manager = FeeFilterManager::default();

        let peer = PeerId(1);
        manager.add_peer(peer, true, false);
        manager.handle_feefilter(peer, 1000);

        // Should not relay below feefilter
        assert!(!manager.should_relay_to_peer(peer, 500));

        // Should relay at or above feefilter
        assert!(manager.should_relay_to_peer(peer, 1000));
        assert!(manager.should_relay_to_peer(peer, 2000));
    }

    #[test]
    fn test_feefilter_manager_unknown_peer() {
        let manager = FeeFilterManager::default();

        // Unknown peer should default to relay
        assert!(manager.should_relay_to_peer(PeerId(999), 0));
        assert_eq!(manager.get_peer_feefilter(PeerId(999)), 0);
    }

    #[test]
    fn test_bip133_feefilter_message_parsing() {
        // Test that feefilter values are u64 in sat/kvB
        let fee_rate: u64 = 1000; // 1 sat/vB = 1000 sat/kvB

        // Verify fee rate calculation
        assert_eq!(get_fee(fee_rate, 1000), 1000); // 1000 sat for 1000 vbytes
        assert_eq!(get_fee(fee_rate, 100), 100); // 100 sat for 100 vbytes
        assert_eq!(get_fee(fee_rate, 1), 1); // Minimum 1 sat for 1 vbyte (rounded up)
    }

    // =========================================================================
    // Incremental Relay Fee Tests
    // =========================================================================

    #[test]
    fn test_incremental_relay_fee_constants() {
        // Verify incremental relay fee default
        assert_eq!(DEFAULT_INCREMENTAL_RELAY_FEE, 1000); // 1000 sat/kvB = 1 sat/vB
    }

    #[test]
    fn test_get_fee() {
        // Test fee calculation: fee = ceil(fee_rate * vsize / 1000)

        // 1000 sat/kvB * 1000 vB / 1000 = 1000 sat
        assert_eq!(get_fee(1000, 1000), 1000);

        // 1000 sat/kvB * 250 vB / 1000 = 250 sat
        assert_eq!(get_fee(1000, 250), 250);

        // 1000 sat/kvB * 1 vB / 1000 = 1 sat (ceiling)
        assert_eq!(get_fee(1000, 1), 1);

        // 2000 sat/kvB * 500 vB / 1000 = 1000 sat
        assert_eq!(get_fee(2000, 500), 1000);

        // Test ceiling behavior
        // 1000 * 141 / 1000 = 141
        assert_eq!(get_fee(1000, 141), 141);

        // Test with 0 vsize
        assert_eq!(get_fee(1000, 0), 0);
    }

    #[test]
    fn test_get_fee_rate() {
        // Test fee rate calculation: fee_rate = fee * 1000 / vsize

        // 1000 sat / 1000 vB * 1000 = 1000 sat/kvB
        assert_eq!(get_fee_rate(1000, 1000), 1000);

        // 250 sat / 250 vB * 1000 = 1000 sat/kvB
        assert_eq!(get_fee_rate(250, 250), 1000);

        // 2000 sat / 1000 vB * 1000 = 2000 sat/kvB
        assert_eq!(get_fee_rate(2000, 1000), 2000);

        // Test with 0 vsize (should not panic)
        assert_eq!(get_fee_rate(1000, 0), 0);
    }

    #[test]
    fn test_pays_for_rbf_rule3() {
        // Rule #3: Replacement fees must be >= original fees
        // Note: We use incremental_fee=0 to isolate Rule #3 testing

        // Equal fees should pass (with 0 incremental fee)
        assert!(pays_for_rbf(1000, 1000, 100, 0).is_ok());

        // Higher fees should pass
        assert!(pays_for_rbf(1000, 2000, 100, 0).is_ok());

        // Lower fees should fail
        let result = pays_for_rbf(1000, 999, 100, 0);
        assert!(result.is_err());
        let err_msg = result.unwrap_err();
        assert!(err_msg.contains("insufficient fee"), "Error should mention insufficient fee: {}", err_msg);
    }

    #[test]
    fn test_pays_for_rbf_rule4() {
        // Rule #4: Additional fees must cover incremental relay fee * vsize
        let incremental_fee = DEFAULT_INCREMENTAL_RELAY_FEE; // 1000 sat/kvB

        // For 1000 vB at 1000 sat/kvB, need 1000 additional sat
        // Original: 1000, Replacement: 2000, vsize: 1000
        // Additional = 1000, Required = 1000 sat/kvB * 1000 vB / 1000 = 1000
        assert!(pays_for_rbf(1000, 2000, 1000, incremental_fee).is_ok());

        // Not enough additional (need 1000, only have 999)
        let result = pays_for_rbf(1000, 1999, 1000, incremental_fee);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("additional fee"));

        // For 250 vB, need 250 additional sat
        assert!(pays_for_rbf(1000, 1250, 250, incremental_fee).is_ok());

        // Exact boundary: 249 vB needs ceil(249 * 1000 / 1000) = 249 sat
        assert!(pays_for_rbf(1000, 1249, 249, incremental_fee).is_ok());
    }

    #[test]
    fn test_pays_for_rbf_zero_incremental_fee() {
        // With zero incremental fee, only rule #3 applies
        assert!(pays_for_rbf(1000, 1000, 1000, 0).is_ok());
        assert!(pays_for_rbf(1000, 999, 1000, 0).is_err());
    }

    #[test]
    fn test_pays_for_rbf_large_transactions() {
        // Test with large transactions
        let incremental_fee = DEFAULT_INCREMENTAL_RELAY_FEE;
        let large_vsize: u64 = 100_000; // 100 kvB
        let required_additional = get_fee(incremental_fee, large_vsize);

        // 100,000 sat additional for 100 kvB
        assert_eq!(required_additional, 100_000);

        // Should pass with exactly enough
        assert!(pays_for_rbf(1_000_000, 1_100_000, large_vsize, incremental_fee).is_ok());

        // Should fail with 1 sat less
        let result = pays_for_rbf(1_000_000, 1_099_999, large_vsize, incremental_fee);
        assert!(result.is_err());
    }

    #[test]
    fn test_feefilter_manager_rbf_check() {
        let manager = FeeFilterManager::default();

        // Test through manager interface
        assert!(manager.pays_for_rbf(1000, 2000, 1000).is_ok());
        assert!(manager.pays_for_rbf(1000, 1999, 1000).is_err());
    }

    #[test]
    fn test_feefilter_manager_min_relay_fee() {
        let mut manager = FeeFilterManager::new(2000, 1000);

        assert_eq!(manager.min_relay_fee(), 2000);
        assert_eq!(manager.incremental_relay_fee(), 1000);

        manager.set_min_relay_fee(3000);
        assert_eq!(manager.min_relay_fee(), 3000);
    }

    #[test]
    fn test_feefilter_integration_with_inventory() {
        // Test that feefilter works with inventory trickling
        let mut fee_manager = FeeFilterManager::default();
        let mut trickle = InventoryTrickle::new();

        let peer = PeerId(1);
        fee_manager.add_peer(peer, true, false);
        trickle.add_peer(peer, false, false, true);

        // Set peer's feefilter to 1000 sat/kvB
        fee_manager.handle_feefilter(peer, 1000);

        // A transaction with fee rate 500 should NOT be relayed
        assert!(!fee_manager.should_relay_to_peer(peer, 500));

        // A transaction with fee rate 1000 should be relayed
        assert!(fee_manager.should_relay_to_peer(peer, 1000));
    }

    #[test]
    fn test_feefilter_block_only_peer() {
        // Block-only peers should not participate in feefilter
        let state = FeeFilterState::new(true, true);
        assert!(state.is_block_only);

        // Even with feefilter support, block-only should not send feefilter
        let mut manager = FeeFilterManager::default();
        let peer = PeerId(1);
        manager.add_peer(peer, true, true); // block-only

        // Should still relay (block-only doesn't receive txs anyway)
        assert!(manager.should_relay_to_peer(peer, 0));
    }
}
