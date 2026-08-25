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
/// Bitcoin Core uses 1024 but we limit to 128 to bound memory for large mainnet blocks.
const MAX_BLOCKS_IN_FLIGHT: usize = 128;

/// Base timeout for a single block request.
/// We use adaptive timeouts: double on stall, decay on success.
/// 30 seconds allows time for peers to propagate blocks at tip
/// (blocks arrive every ~10 minutes, peer latency up to seconds).
const BASE_BLOCK_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum timeout after adaptive increases.
const MAX_BLOCK_TIMEOUT: Duration = Duration::from_secs(64);

/// Stall timeout: disconnect peer if no block received for this long.
const BLOCK_STALL_TIMEOUT: Duration = Duration::from_secs(120);

/// Block download window size (how far ahead of the validated tip to download).
#[allow(dead_code)]
const DOWNLOAD_WINDOW_SIZE: u32 = 1024;

/// Maximum number of received blocks buffered in memory awaiting validation.
/// Mainnet blocks average ~1.5 MB, so 512 blocks ≈ 768 MB — within the memory
/// budget while allowing enough buffer for out-of-order arrivals during IBD.
/// Without this cap, slow validation causes unbounded memory growth (e.g. 13+ GB).
///
/// NOTE: This limit is checked independently from MAX_BLOCKS_IN_FLIGHT.
/// Previously, received_blocks + in_flight shared a single 128 cap, which
/// starved the download pipeline: out-of-order blocks filled received_blocks,
/// leaving no room for new in_flight requests (observed as 0 getdata after
/// enqueueing 131K blocks, with only periodic retries of 2-8 blocks).
const MAX_RECEIVED_BLOCKS: usize = 512;

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
    /// Set of hashes in pending_hashes for O(1) dedup lookups.
    /// Maintained in sync with pending_hashes to avoid rebuilding
    /// a HashSet on every enqueue_blocks call (which was O(n) for
    /// 900K+ blocks and caused multi-second stalls).
    pending_set: std::collections::HashSet<Hash256>,
}

/// Outcome of a level-triggered gap-fill reconciliation.
#[derive(Debug, PartialEq, Eq)]
pub struct GapFill {
    /// Blocks whose bodies we are missing and should request, in chain order.
    pub to_request: Vec<(Hash256, u32)>,
    /// Heights in the examined window whose body we already hold.
    pub already_stored: u32,
}

/// Recompute, from scratch, which block bodies are missing between the
/// validated tip and the best known header — Bitcoin Core's
/// `FindNextBlocksToDownload`.
///
/// rustoshi's only non-test caller of [`BlockDownloader::enqueue_blocks`] is the
/// `headers` message handler, gated on the header tip having advanced. That makes
/// block download EDGE-TRIGGERED: once we reach the header tip, peers stop sending
/// headers, so a body that was never delivered is never re-requested. The queue
/// drains, the periodic retry has nothing to retry, and the node sits behind a
/// hole with healthy peers and zero getdata indefinitely (observed 2026-08-24:
/// nine hours at height 963853 with 7-9 peers all at the tip).
///
/// Core never relies on remembering an earlier decision — it recomputes the needed
/// set on every `SendMessages` tick. This is that recomputation, factored out of
/// the tick handler so it can be tested.
///
/// `hash_at_height` resolves the ACTIVE-chain height index. That matters: when the
/// node is stuck on a losing fork, those heights resolve to its OWN branch, whose
/// bodies it already holds. In that case `to_request` is empty while
/// `already_stored` is not — the caller should treat that as the losing-fork
/// signature and hand it to [`compute_fork_branch_fill`], because a by-height
/// fill cannot repair it; the competing branch's bodies have to be fetched by
/// hash, walking the header chain's prev pointers.
pub fn compute_gap_fill<F, G>(
    validated_tip: u32,
    best_header: u32,
    max_window: u32,
    hash_at_height: F,
    have_body: G,
) -> GapFill
where
    F: Fn(u32) -> Option<Hash256>,
    G: Fn(&Hash256) -> bool,
{
    let mut out = GapFill { to_request: Vec::new(), already_stored: 0 };
    if validated_tip >= best_header || max_window == 0 {
        return out;
    }
    let from = validated_tip + 1;
    let to = std::cmp::min(best_header, validated_tip.saturating_add(max_window));
    for h in from..=to {
        if let Some(hash) = hash_at_height(h) {
            if have_body(&hash) {
                out.already_stored += 1;
            } else {
                out.to_request.push((hash, h));
            }
        }
    }
    out
}

/// Outcome of a fork-aware, BY-HASH branch reconciliation.
#[derive(Debug, PartialEq, Eq)]
pub struct ForkBranchFill {
    /// Competing-branch blocks whose body we do NOT hold, in ascending-height
    /// (chain) order. These are the bodies a reorg onto that branch needs.
    pub to_request: Vec<(Hash256, u32)>,
    /// Competing-branch blocks walked whose body we already hold.
    pub already_stored: u32,
    /// Height of the fork point (last common ancestor of the two tips), or
    /// `None` when the walk gave up before reaching it.
    pub fork_height: Option<u32>,
    /// True when the walk hit `max_walk`, or ran out of headers, before it
    /// reached the fork point. The collected prefix is then the TOP of the
    /// branch, which cannot connect to anything we have, so a caller should
    /// report it rather than request it.
    pub truncated: bool,
}

/// Walk the HEADER chain back from the best header to its fork point with the
/// ACTIVE chain and return the competing branch's real block hashes whose body
/// we are missing — Bitcoin Core's `FindNextBlocksToDownload` operating on
/// `CBlockIndex::pprev` rather than on the active-chain height map.
///
/// [`compute_gap_fill`] cannot repair a losing fork and says so: it resolves
/// heights through the ACTIVE-chain height index, so on a losing fork every
/// height in the gap resolves to a block we already hold and it returns an empty
/// request set with a non-zero `already_stored`. THIS is the function that
/// handles that signature. The distinction is the same one haskoin's
/// `requestForkBlocks` documents: the bodies the reorg needs belong to the
/// COMPETING branch and are reachable only by hash, by walking prev pointers.
///
/// Live case (2026-08-24 mainnet, receipt
/// `receipts/one-block-race-recovery-class-2026-08-24.md`): two valid blocks
/// were mined at height 963853 seconds apart; rustoshi connected `…ec5e4ceb`,
/// the network kept `…0258f8`. Fork point 963852, header tip 963894, peers
/// healthy, ten hours wedged. The competing branch's LATER blocks arrive at the
/// tip and `try_attach_and_reorg` persists them as side-branch bodies, so a
/// `validated_tip+1 ..` window can find every height already stored and nothing
/// to request — the losing-fork signature — while the one body that would let
/// the reorg assemble, the competing 963853, sits BELOW the node's own tip
/// height, where that window can never look.
///
/// The fork point is found the way Core's `LastCommonAncestor` finds it: bring
/// both tips to a common height by prev-walking the deeper one, then step both
/// back in lockstep until the hashes are equal. It deliberately does NOT consult
/// the height index, because rustoshi rewrites that index for every accepted
/// header (`put_height_index` in the header-sync `validate_and_store` closure),
/// which means above the fork point it names the COMPETING branch, not the
/// active chain — so "is this hash the one at its height?" is not a fork test
/// here. Comparing hashes cannot invent a fork point: a wrong height only makes
/// the two walks fail to meet, which reports `truncated`, never a false fork.
///
/// The fork point itself is excluded — we have it, by definition.
///
/// # Arguments
/// * `header_tip` - `(hash, height)` of the best known header.
/// * `active_tip` - `(hash, height)` of the connected chainstate tip.
/// * `max_walk` - hard cap on prev-pointer steps, so a deep or unresolvable
///   fork cannot build an unbounded vector inside a timer tick.
/// * `prev_of` - parent of a block by hash (its header's `prev_block_hash`),
///   `None` if the header is not stored. Must see BOTH branches — a
///   hash-keyed header lookup, never a height lookup.
/// * `have_body` - whether the block's body is already on disk.
pub fn compute_fork_branch_fill<P, G>(
    header_tip: (Hash256, u32),
    active_tip: (Hash256, u32),
    max_walk: u32,
    prev_of: P,
    have_body: G,
) -> ForkBranchFill
where
    P: Fn(&Hash256) -> Option<Hash256>,
    G: Fn(&Hash256) -> bool,
{
    let (mut branch_hash, mut branch_height) = header_tip;
    let (mut ours_hash, mut ours_height) = active_tip;

    // Competing-branch blocks, collected descending as we walk; reversed below.
    let mut branch: Vec<(Hash256, u32)> = Vec::new();
    let mut steps: u32 = 0;
    let mut truncated = false;
    let mut fork_height: Option<u32> = None;

    // `loop` purely so the three phases below can bail out to one exit.
    loop {
        // Phase 1: bring the two tips to a common height. Only the competing
        // side's blocks are collected — the active side's are ones we connected.
        while branch_height > ours_height {
            if steps >= max_walk {
                truncated = true;
                break;
            }
            branch.push((branch_hash, branch_height));
            match prev_of(&branch_hash) {
                Some(parent) if branch_height > 0 => {
                    branch_hash = parent;
                    branch_height -= 1;
                }
                _ => {
                    truncated = true;
                    break;
                }
            }
            steps += 1;
        }
        if truncated {
            break;
        }

        while ours_height > branch_height {
            if steps >= max_walk {
                truncated = true;
                break;
            }
            match prev_of(&ours_hash) {
                Some(parent) if ours_height > 0 => {
                    ours_hash = parent;
                    ours_height -= 1;
                }
                _ => {
                    truncated = true;
                    break;
                }
            }
            steps += 1;
        }
        if truncated {
            break;
        }

        // Phase 2: equal heights — step both back together until they meet.
        // The two sides stay at the same height from here, so only
        // `branch_height` is tracked (it is the height of both walks).
        while branch_hash != ours_hash {
            if steps >= max_walk {
                truncated = true;
                break;
            }
            branch.push((branch_hash, branch_height));
            match (prev_of(&branch_hash), prev_of(&ours_hash)) {
                (Some(bp), Some(op)) if branch_height > 0 => {
                    branch_hash = bp;
                    ours_hash = op;
                    branch_height -= 1;
                }
                _ => {
                    truncated = true;
                    break;
                }
            }
            steps += 1;
        }
        if truncated {
            break;
        }

        // Met: `branch_hash == ours_hash` is the fork point, and it is NOT in
        // `branch` — we never push a hash we have already matched against the
        // active side.
        fork_height = Some(branch_height);
        break;
    }

    let mut out = ForkBranchFill {
        to_request: Vec::new(),
        already_stored: 0,
        fork_height,
        truncated,
    };
    for (hash, height) in branch.into_iter().rev() {
        if have_body(&hash) {
            out.already_stored += 1;
        } else {
            out.to_request.push((hash, height));
        }
    }
    out
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
            pending_set: std::collections::HashSet::new(),
        }
    }

    /// Add a range of block hashes to download (after headers are synced).
    ///
    /// Blocks should be added in chain order (lowest height first).
    /// Deduplicates against blocks already queued, in-flight, or received.
    pub fn enqueue_blocks(&mut self, blocks: Vec<(Hash256, u32)>) {
        for item in blocks {
            // Skip blocks already in the pipeline.
            // Uses the persistent pending_set for O(1) dedup instead of
            // rebuilding a HashSet from pending_hashes on every call.
            if self.in_flight.contains_key(&item.0)
                || self.received_blocks.contains_key(&item.0)
                || self.pending_set.contains(&item.0)
            {
                continue;
            }
            self.pending_set.insert(item.0);
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
    pub fn download_queue_empty(&self) -> bool {
        self.download_queue.is_empty()
    }

    /// Return the number of blocks still in the download queue.
    pub fn download_queue_len(&self) -> usize {
        self.download_queue.len()
    }

    pub fn received_blocks_count(&self) -> usize {
        self.received_blocks.len()
    }

    pub fn pending_hashes_count(&self) -> usize {
        self.pending_hashes.len()
    }

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

        // Find peers with available capacity.
        // Don't exclude "stalling" peers — they may just have had a transient
        // timeout.  The adaptive timeout handles slow peers without permanently
        // excluding them, matching Bitcoin Core's approach of giving peers
        // multiple chances before disconnecting.
        let mut available_peers: Vec<PeerId> = self
            .peer_states
            .iter()
            .filter(|(_, state)| {
                state.blocks_in_flight < MAX_BLOCKS_IN_FLIGHT_PER_PEER
            })
            .map(|(id, _)| *id)
            .collect();

        if available_peers.is_empty() || self.download_queue.is_empty() {
            return requests;
        }

        // Backpressure: don't request more blocks if the received buffer is full.
        // This prevents unbounded memory growth when validation is slower than download.
        // Exception: if the next block we need for validation is NOT in received_blocks
        // and NOT in_flight, we MUST bypass backpressure to fetch it — otherwise
        // the buffer can never drain and we deadlock.
        if self.received_blocks.len() >= MAX_RECEIVED_BLOCKS {
            let next_needed_available = self.pending_hashes.front()
                .map(|h| self.received_blocks.contains_key(h) || self.in_flight.contains_key(h))
                .unwrap_or(true);
            if next_needed_available {
                return requests;
            }
            // Next needed block is missing — allow a small number of requests through
            // to fetch it, but don't open the floodgates.
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
            let h = self.pending_hashes.pop_front().unwrap();
            self.pending_set.remove(&h);
            self.validated_tip_height += 1;
            Some(block)
        } else {
            // Next block in sequence hasn't arrived yet
            None
        }
    }

    /// Returns true if the next block in chain order is available for
    /// validation (i.e. it has been received and is buffered).
    ///
    /// Unlike `next_block_to_validate`, this does not consume the block.
    /// Used by the event loop to decide whether to set `validation_pending`.
    pub fn has_next_block(&self) -> bool {
        if let Some(hash) = self.pending_hashes.front() {
            self.received_blocks.contains_key(hash)
        } else {
            false
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

    /// Realign the validated-tip counter to an authoritative chain height.
    ///
    /// `validated_tip_height` counts blocks POPPED for validation (incremented
    /// unconditionally in `next_block_to_validate`, even when the subsequent
    /// `process_block` fails — see the GAP-FILL rationale in main.rs). After a
    /// reorg driven by the Unit C P2P arm, the active tip is repointed by a
    /// DIFFERENT path (`try_attach_and_reorg`), so this counter can be left
    /// ahead of the real tip by however many competing-fork blocks failed to
    /// connect sequentially before the reorg fired. The caller resets it to the
    /// reorg's committed tip height so subsequent connects (and the
    /// `best_height` the validation loop derives from this counter) track the
    /// real chain — otherwise getblockcount over-reports (e.g. 10 disconnected +
    /// 15 connected = 25 instead of 15). Reorg cluster Unit E follow-up.
    pub fn set_validated_tip_height(&mut self, height: u32) {
        self.validated_tip_height = height;
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

    /// Get the number of blocks currently in flight (requested but not yet received).
    pub fn in_flight_count(&self) -> usize {
        self.in_flight.len()
    }

    /// Get the number of pending hashes awaiting validation.
    pub fn pending_hashes_len(&self) -> usize {
        self.pending_hashes.len()
    }

    /// Get the hash at the front of the pending validation queue.
    pub fn pending_front_hash(&self) -> Option<Hash256> {
        self.pending_hashes.front().cloned()
    }

    /// Check if a hash is in the received blocks buffer.
    pub fn is_in_received(&self, hash: &Hash256) -> bool {
        self.received_blocks.contains_key(hash)
    }
}

#[cfg(test)]
mod tests {

    // ---- level-triggered gap fill (compute_gap_fill) ----

    fn h(n: u8) -> Hash256 { Hash256([n; 32]) }

    #[test]
    fn gap_fill_requests_a_missing_body_when_the_queue_is_idle() {
        // THE REGRESSION. Validated tip 100, best header 103, and the body for
        // 102 was never delivered. Pre-fix nothing re-enqueued it, because the
        // only enqueue site fires on header arrival and headers had stopped.
        let stored = |x: &Hash256| *x != h(102);
        let g = compute_gap_fill(100, 103, 1000, |ht| Some(h(ht as u8)), stored);
        assert_eq!(g.to_request, vec![(h(102), 102)]);
        assert_eq!(g.already_stored, 2); // 101 and 103
    }

    #[test]
    fn gap_fill_is_empty_when_caught_up() {
        // CONTROL: at the header tip there is nothing to do, so the tick stays
        // silent and cannot spam getdata.
        let g = compute_gap_fill(103, 103, 1000, |ht| Some(h(ht as u8)), |_| true);
        assert!(g.to_request.is_empty());
        assert_eq!(g.already_stored, 0);
    }

    #[test]
    fn gap_fill_reports_the_losing_fork_signature() {
        // Behind the header tip, but every height in the gap resolves — through
        // the ACTIVE-chain height index — to a block we already hold. That is
        // the losing-fork case: a by-height fill cannot repair it, and the
        // caller must say so rather than spin. to_request MUST stay empty so we
        // do not re-request our own branch in a loop.
        let g = compute_gap_fill(100, 110, 1000, |ht| Some(h(ht as u8)), |_| true);
        assert!(g.to_request.is_empty(), "must not re-request our own branch");
        assert_eq!(g.already_stored, 10);
    }

    #[test]
    fn gap_fill_window_is_bounded() {
        // A 100k-block gap must not build a 100k-entry vector in one tick.
        let g = compute_gap_fill(0, 100_000, 16, |ht| Some(h(ht as u8)), |_| false);
        assert_eq!(g.to_request.len(), 16);
        assert_eq!(g.to_request.first().unwrap().1, 1);
        assert_eq!(g.to_request.last().unwrap().1, 16);
    }

    #[test]
    fn gap_fill_skips_heights_with_no_header() {
        // A height index hole must be skipped, not treated as missing-body.
        let g = compute_gap_fill(0, 4, 1000, |ht| if ht == 2 { None } else { Some(h(ht as u8)) }, |_| false);
        assert_eq!(g.to_request, vec![(h(1), 1), (h(3), 3), (h(4), 4)]);
    }

    // ---- fork-aware by-hash branch fill (compute_fork_branch_fill) ----

    /// Fixture hash: `tag` selects the branch (0 = shared trunk, 1 = ours,
    /// 2 = the competing branch), `height` makes it unique. Analytic rather
    /// than a map so the tests can use REAL mainnet heights (963_852+) without
    /// materialising a million-entry chain.
    fn fh(tag: u8, height: u32) -> Hash256 {
        let mut b = [0u8; 32];
        b[0] = tag;
        b[1..5].copy_from_slice(&height.to_le_bytes());
        Hash256(b)
    }

    /// `prev_of` over a two-branch fixture: a shared trunk (tag 0) up to
    /// `fork`, then two competing branches (tags 1 and 2) both rooted at
    /// `fh(0, fork)`.
    fn fork_prev(fork: u32) -> impl Fn(&Hash256) -> Option<Hash256> {
        move |hash: &Hash256| {
            let tag = hash.0[0];
            let height = u32::from_le_bytes(hash.0[1..5].try_into().unwrap());
            if height == 0 {
                return None; // genesis has no parent
            }
            if tag == 0 {
                return Some(fh(0, height - 1)); // shared trunk
            }
            if height == fork + 1 {
                return Some(fh(0, fork)); // branch root attaches to the trunk
            }
            Some(fh(tag, height - 1))
        }
    }

    #[test]
    fn fork_fill_requests_the_competing_branch_by_hash() {
        // THE WEDGE, to scale. 2026-08-24 mainnet: two valid blocks at 963853,
        // rustoshi connected one, the network kept the other. Fork point
        // 963852, our tip 963853 (branch 1), header tip 963894 (branch 2).
        // Every competing block ABOVE our tip already has a body — they arrived
        // at the tip and try_attach_and_reorg persisted them as side-branch
        // blocks — so a by-height window over 963854..=963894 sees nothing
        // missing. The body that would let the reorg assemble is the competing
        // 963853, which sits BELOW our own tip height where that window cannot
        // look. Only the header walk finds it.
        const FORK: u32 = 963_852;
        let missing = fh(2, 963_853);
        let f = compute_fork_branch_fill(
            (fh(2, 963_894), 963_894),
            (fh(1, 963_853), 963_853),
            2000,
            fork_prev(FORK),
            |h: &Hash256| *h != missing,
        );
        assert_eq!(
            f.to_request,
            vec![(missing, 963_853)],
            "must request the competing 963853 by its OWN hash"
        );
        assert_eq!(f.already_stored, 41); // 963854..=963894
        assert_eq!(f.fork_height, Some(FORK));
        assert!(!f.truncated);
        // And it must never ask for our own branch's blocks back.
        assert!(f.to_request.iter().all(|(h, _)| h.0[0] != 1));
    }

    #[test]
    fn fork_fill_walks_the_whole_branch_in_ascending_order() {
        // Same fork, but none of the competing bodies ever arrived: the full
        // branch is requested, lowest height first, so the reorg can assemble
        // from the fork point upward.
        const FORK: u32 = 963_852;
        let f = compute_fork_branch_fill(
            (fh(2, 963_856), 963_856),
            (fh(1, 963_853), 963_853),
            2000,
            fork_prev(FORK),
            |_: &Hash256| false,
        );
        assert_eq!(
            f.to_request,
            vec![
                (fh(2, 963_853), 963_853),
                (fh(2, 963_854), 963_854),
                (fh(2, 963_855), 963_855),
                (fh(2, 963_856), 963_856),
            ]
        );
        assert_eq!(f.already_stored, 0);
        assert_eq!(f.fork_height, Some(FORK));
    }

    #[test]
    fn fork_fill_is_silent_when_we_are_on_the_right_chain() {
        // CONTROL — this is what proves the mechanism cannot fire spuriously.
        // Header tip IS our tip: there is no competing branch, so the walk
        // yields nothing to request even though `have_body` says we hold
        // nothing at all.
        let f = compute_fork_branch_fill(
            (fh(0, 963_894), 963_894),
            (fh(0, 963_894), 963_894),
            2000,
            fork_prev(963_852),
            |_: &Hash256| false,
        );
        assert!(
            f.to_request.is_empty(),
            "must not request anything when we are on the header chain"
        );
        assert_eq!(f.already_stored, 0);
        assert_eq!(f.fork_height, Some(963_894));
        assert!(!f.truncated);
    }

    #[test]
    fn fork_fill_on_the_right_chain_but_behind_requests_only_our_own_chain() {
        // Second control: same chain, we are simply 3 blocks behind. The walk
        // must yield exactly those 3 — all on the trunk we are already on —
        // and never a hash from another branch.
        let f = compute_fork_branch_fill(
            (fh(0, 963_894), 963_894),
            (fh(0, 963_891), 963_891),
            2000,
            fork_prev(963_852),
            |_: &Hash256| false,
        );
        assert_eq!(
            f.to_request,
            vec![
                (fh(0, 963_892), 963_892),
                (fh(0, 963_893), 963_893),
                (fh(0, 963_894), 963_894),
            ]
        );
        assert_eq!(f.fork_height, Some(963_891));
        assert!(f.to_request.iter().all(|(h, _)| h.0[0] == 0));
    }

    #[test]
    fn fork_fill_excludes_the_fork_point_itself() {
        // The last common ancestor is a block we already have and already
        // connected. Requesting it would be a wasted getdata at best and, at
        // the head of the pending queue, a self-inflicted stall at worst.
        const FORK: u32 = 100;
        let f = compute_fork_branch_fill(
            (fh(2, 105), 105),
            (fh(1, 101), 101),
            2000,
            fork_prev(FORK),
            |_: &Hash256| false,
        );
        assert_eq!(f.fork_height, Some(FORK));
        assert!(
            !f.to_request.iter().any(|(h, _)| *h == fh(0, FORK)),
            "fork point must be excluded"
        );
        assert_eq!(f.to_request.first().unwrap().1, FORK + 1);
        assert_eq!(f.to_request.last().unwrap().1, 105);
    }

    #[test]
    fn fork_fill_walk_is_bounded() {
        // A fork point 500k blocks back must not build a 500k-entry vector
        // inside a 10-second timer tick. The walk stops at `max_walk` and
        // reports `truncated` with no fork point — the collected prefix is the
        // TOP of the branch and cannot connect to anything we hold, which is
        // why the caller reports a truncated walk instead of requesting it.
        let f = compute_fork_branch_fill(
            (fh(2, 500_000), 500_000),
            (fh(1, 500_000), 500_000),
            16,
            fork_prev(0),
            |_: &Hash256| false,
        );
        assert!(f.truncated);
        assert_eq!(f.fork_height, None);
        assert_eq!(f.to_request.len(), 16, "bounded by max_walk");
        assert_eq!(f.to_request.last().unwrap().1, 500_000);
        assert_eq!(f.to_request.first().unwrap().1, 500_000 - 15);
    }

    #[test]
    fn fork_fill_truncates_when_a_header_is_missing() {
        // A prev pointer we cannot resolve (header not stored) is not a fork
        // point. Reporting `truncated` keeps us from mistaking a hole in the
        // header store for "the branches met here".
        let f = compute_fork_branch_fill(
            (fh(2, 200), 200),
            (fh(1, 200), 200),
            2000,
            |h: &Hash256| {
                let height = u32::from_le_bytes(h.0[1..5].try_into().unwrap());
                if height <= 195 {
                    None
                } else {
                    Some(fh(h.0[0], height - 1))
                }
            },
            |_: &Hash256| false,
        );
        assert!(f.truncated);
        assert_eq!(f.fork_height, None);
    }

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
    fn test_stalled_peers_still_assigned_blocks() {
        // Stalling peers are NOT excluded from assignment — the adaptive
        // timeout handles slow peers without permanently excluding them,
        // matching Bitcoin Core's approach. See assign_requests() comment.
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

        // Assign requests — both peers should get blocks
        let requests = dl.assign_requests();
        let total: usize = requests
            .iter()
            .filter_map(|(_, msg)| {
                if let NetworkMessage::GetData(items) = msg {
                    Some(items.len())
                } else {
                    None
                }
            })
            .sum();
        assert_eq!(total, 4);
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

    /// Regression: a block consumed by `next_block_to_validate` (e.g. one
    /// that subsequently FAILED validation in the caller) must be eligible
    /// for re-enqueue. Without this, a single failed block leaves a
    /// permanent gap in the download queue and the chain wedges.
    ///
    /// This is the "snapshot recovery / gap-fill" scenario: post-snapshot
    /// load, block H+1 fails validation; the downloader keeps consuming
    /// later-arriving blocks (whose parents now appear missing); each
    /// subsequent header arrival in main.rs re-enqueues the gap from the
    /// validated chainstate tip up to the new header tip — the gap-fill
    /// ONLY works if the failed block can be re-requested.
    #[test]
    fn test_failed_block_can_be_reenqueued() {
        let mut dl = BlockDownloader::new(0, 100);
        let peer = PeerId(1);
        dl.add_peer(peer);

        let block = make_test_block(42);
        let hash = block.block_hash();

        // Step 1: enqueue + assign + receive.
        dl.enqueue_blocks(vec![(hash, 1)]);
        let _requests = dl.assign_requests();
        assert_eq!(dl.blocks_in_flight(), 1);

        let received = dl.block_received(peer, block.clone());
        assert_eq!(received, Some(hash));
        assert_eq!(dl.blocks_in_flight(), 0);
        assert_eq!(dl.blocks_buffered(), 1);

        // Step 2: consume via next_block_to_validate (simulates entering
        // the validator).  The downloader assumes the validator
        // succeeded and advances validated_tip_height — but in the
        // wedge scenario the caller's process_block returned Err.
        let popped = dl.next_block_to_validate();
        assert!(popped.is_some());
        assert_eq!(dl.blocks_buffered(), 0);
        assert_eq!(dl.pending_hashes_len(), 0);
        // Note: validated_tip_height was incremented even though the
        // caller's validation failed — this is the bug the gap-fill
        // logic in main.rs works around by trusting chain_state.tip_height
        // instead of validated_tip_height.
        assert_eq!(dl.validated_tip_height(), 1);

        // Step 3: re-enqueue the same hash.  Must succeed (not be
        // silently dropped by dedup) so the gap-fill path can recover
        // from the failed validation.
        dl.enqueue_blocks(vec![(hash, 1)]);
        assert_eq!(dl.pending_hashes_len(), 1);
        assert_eq!(dl.download_queue_len(), 1);

        // And it must be assignable + receivable again.
        let requests2 = dl.assign_requests();
        assert!(!requests2.is_empty(), "re-enqueued block should be assigned");
        assert_eq!(dl.blocks_in_flight(), 1);
        let received2 = dl.block_received(peer, block);
        assert_eq!(received2, Some(hash));
    }

    /// Regression: simulate the full gap-fill loop main.rs runs after a
    /// header arrival. Setup: chain state at height H (=10), block
    /// downloader reports best_header_height=H (only the snapshot tip).
    /// Header sync advances by 1000 headers (to H+1000=1010). The
    /// downloader must accept all 1000 (H+1..=H+1000) when
    /// `enqueue_blocks` is called with the full gap, even if the
    /// downloader itself thinks its high-water-mark is H.
    #[test]
    fn test_gap_fill_enqueues_all_missing_heights() {
        const CHAIN_TIP: u32 = 10;
        const HEADER_TIP: u32 = 1010;

        // Chainstate at height 10, downloader's view starts identical.
        let mut dl = BlockDownloader::new(CHAIN_TIP, CHAIN_TIP);
        dl.add_peer(PeerId(1));
        dl.add_peer(PeerId(2));
        assert_eq!(dl.best_header_height(), CHAIN_TIP);
        assert_eq!(dl.validated_tip_height(), CHAIN_TIP);

        // After 1000 new headers arrive, main.rs computes the gap and
        // calls enqueue_blocks for heights 11..=1010 (1000 entries).
        // Use distinct 4-byte hashes (height encoded as little-endian)
        // so no two blocks collide and trigger the dedup path.
        let gap: Vec<(Hash256, u32)> = (CHAIN_TIP + 1..=HEADER_TIP)
            .map(|h| {
                let mut bytes = [0u8; 32];
                bytes[..4].copy_from_slice(&h.to_le_bytes());
                (Hash256(bytes), h)
            })
            .collect();
        assert_eq!(gap.len(), 1000);
        // Distinct hashes (sanity: avoid accidental dedup collisions).
        let unique: std::collections::HashSet<_> = gap.iter().map(|x| x.0).collect();
        assert_eq!(unique.len(), 1000);

        dl.set_best_header_height(HEADER_TIP);
        dl.enqueue_blocks(gap);

        // All 1000 must be in the download queue, NOT just the latest one.
        assert_eq!(
            dl.download_queue_len(),
            1000,
            "gap-fill must enqueue every missing height between chain tip and header tip"
        );
        assert_eq!(dl.pending_hashes_len(), 1000);
    }
}
