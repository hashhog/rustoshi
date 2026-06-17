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
use rustoshi_consensus::{get_block_proof, ChainWork};
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
    /// Reorg Unit E (E3): the fork height the most recent `process_headers`
    /// rewound the header tip to, if a (heavier-fork) rewind happened. The
    /// block-download enqueue floors at `min(chainstate_tip, this)` so the
    /// fork's bodies BELOW the active tip get requested — without this the
    /// reorg machinery (Units A–C) is unreachable over passive P2P sync
    /// (see `CORE-PARITY-AUDIT/_reorg-unit-e-fork-aware-download-2026-06-17.md`).
    /// STICKY across header batches: set (to the min fork height) on a rewind,
    /// cleared by the caller via `take_pending_rewind` once it has enqueued the
    /// fork range. This survives a multi-batch fork where the rewinding batch is
    /// a full (Ok(true)) batch that does not itself enqueue.
    pending_rewind: Option<u32>,
    /// Reorg Unit E (E1): a peer that announced headers which do NOT connect to
    /// our chain (unsolicited, prev_hash unknown). Core responds to an
    /// unconnecting announcement by sending a getheaders to discover the peer's
    /// chain; without it a competing fork is never even requested. Set per-call,
    /// consumed by the caller via `take_getheaders_hint`.
    getheaders_hint: Option<PeerId>,
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
            pending_rewind: None,
            getheaders_hint: None,
        }
    }

    /// Reorg Unit E (E3): consume the pending fork-rewind height, if any. The
    /// block-download enqueue calls this after `process_headers` and floors its
    /// enqueue at `min(chainstate_tip, fork_height)` so the fork's bodies below
    /// the active tip are requested. Sticky until consumed (see field doc).
    pub fn take_pending_rewind(&mut self) -> Option<u32> {
        self.pending_rewind.take()
    }

    /// Reorg Unit E (E1): consume the discovery-getheaders hint, if any. When
    /// `Some(peer)`, the caller should send that peer a getheaders (locator from
    /// the active chain) to discover the competing chain it just announced.
    pub fn take_getheaders_hint(&mut self) -> Option<PeerId> {
        self.getheaders_hint.take()
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
                // Reorg Unit E (review fix 1): clear a sticky fork-rewind hint
                // when the sync peer goes away. pending_rewind is only stranded
                // (set but never consumed) if a fork rewind happened on a full
                // Ok(true) batch and the continuation was then abandoned — a
                // peer disconnect is the dominant way that happens. Without
                // this, a later unrelated Ok(false) Headers message would
                // consume the stale fork height and spuriously lower its
                // download floor.
                self.pending_rewind = None;
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
        // Prefer a peer strictly taller than our header tip (normal IBD). If
        // none qualifies but we are mid-sync — Reorg Unit E (review fix 3) —
        // keep requesting from the ACTIVE sync peer. This matters for the
        // continuation of a multi-batch heavier fork: after the first batch
        // rewinds, `note_peer_height` credits the fork peer only up to our new
        // tip, so `best_sync_peer`'s strict `> best_header_height` filter would
        // exclude it and strand the fork after one 2000-header batch. The
        // fallback only fires when best_sync_peer is None AND state is
        // DownloadingHeaders, so it is a no-op for normal IBD (where a taller
        // peer always exists) and cannot loop at tip (state is Idle there).
        let target = self.best_sync_peer().or_else(|| {
            if let SyncState::DownloadingHeaders { peer, .. } = &self.state {
                Some(*peer)
            } else {
                None
            }
        });
        if let Some(peer_id) = target {
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

    /// Reorg Unit E (E1): request headers from a SPECIFIC peer (the one that
    /// announced a chain we couldn't connect), with a locator from our active
    /// chain, AND mark that peer as the active header-sync peer.
    ///
    /// This is the discovery primitive for competing chains. `start_sync` can't
    /// be used because it only targets `best_sync_peer` (a peer whose tracked
    /// height exceeds ours) — a fork that forks below our tip never qualifies.
    /// Marking the peer active is load-bearing: `process_headers` only reaches
    /// the fork-rewind path for an *active-sync* response; an unsolicited
    /// response whose first header doesn't connect to our tip is ignored early.
    /// So we must promote this peer to active sync before its fork reply lands.
    pub fn request_headers_from<F>(
        &mut self,
        peer_id: PeerId,
        get_hash_at_height: F,
    ) -> NetworkMessage
    where
        F: Fn(u32) -> Option<Hash256>,
    {
        let msg = self.make_getheaders(get_hash_at_height);
        self.state = SyncState::DownloadingHeaders {
            peer: peer_id,
            last_hash: self.best_header_hash,
        };
        NetworkMessage::GetHeaders(msg)
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
        // Reorg Unit E (E2): our CURRENT header chain's compact target (nBits) at
        // a given height, or None if unknown. Used to compare cumulative work
        // between our chain and a connecting fork, so we only rewind+overwrite
        // the height index for a STRICTLY heavier fork (Core moves the
        // best-header candidate on greater nChainWork only). Tests that don't
        // exercise forks may pass `&|_| None` (treated as zero existing work →
        // any valid fork is heavier, preserving the pre-Unit-E unconditional
        // rewind behaviour for those cases).
        get_existing_header_bits: &dyn Fn(u32) -> Option<u32>,
    ) -> Result<bool, String> {
        // Reorg Unit E: getheaders_hint is per-call advice — clear it each
        // entry. pending_rewind is intentionally NOT cleared here: it is sticky
        // until the caller consumes it via take_pending_rewind (a multi-batch
        // fork rewinds on its first batch, which may be a full Ok(true) batch
        // that does not itself enqueue).
        self.getheaders_hint = None;

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
                // Doesn't connect to our tip. We don't try to splice it in here
                // (we lack the intervening headers), but — Reorg Unit E (E1) —
                // we record the peer so the caller sends it a getheaders with a
                // full locator from our active chain. That is how a competing
                // chain (which by definition forks below or beside our tip and
                // therefore never connects to it) gets DISCOVERED at all; Core
                // does the same (MaybeSendGetHeaders on an unconnecting
                // announcement). Without this the fork is never requested and
                // the reorg machinery (Units A–C) can never fire over P2P.
                self.getheaders_hint = Some(peer_id);
                tracing::debug!(
                    "Unsolicited headers from peer {} don't connect (prev_hash {} != tip {}); will getheaders to discover its chain",
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
                let old_best = self.best_header_height;

                // Reorg Unit E (E2): only rewind to a STRICTLY heavier fork.
                // Both chains share everything up to `fork_height`, so we
                // compare the cumulative work of the two suffixes from that
                // shared point: the fork's new headers (this batch) vs our
                // current headers at fork_height+1 ..= old_best. Core moves its
                // best-header candidate on greater nChainWork only; we mirror
                // that here so a lighter/equal — or junk — connecting fork never
                // overwrites the height index (which would diverge our locator
                // from the still-active heavier chain and waste downloads).
                let mut fork_work = ChainWork::ZERO;
                for h in &headers {
                    fork_work = fork_work.saturating_add(&get_block_proof(h.bits));
                }
                let mut our_work = ChainWork::ZERO;
                for height in (fork_height + 1)..=old_best {
                    if let Some(bits) = get_existing_header_bits(height) {
                        our_work = our_work.saturating_add(&get_block_proof(bits));
                    }
                }
                if fork_work <= our_work {
                    // Not heavier. Don't overwrite our index, and do NOT
                    // re-request: the discovery getheaders that elicited this
                    // response carried a full locator from our active chain, so
                    // the peer already sent its entire fork suffix from the fork
                    // point in this batch (forks deeper than one 2000-header
                    // batch are far beyond MAX_REORG_DEPTH). Re-requesting a
                    // genuinely-lighter fork would just loop. Silent no-op, the
                    // same outcome a lighter fork had before Unit E.
                    tracing::info!(
                        "Ignoring lighter/equal fork from peer {} at height {} (fork_work {} <= our_work {}); not rewinding",
                        peer_id.0, fork_height, fork_work, our_work
                    );
                    return Ok(false);
                }

                tracing::info!(
                    "Headers from peer {} fork from height {} (hash {}), HEAVIER (fork_work {} > our_work {}); rewinding header tip from height {}",
                    peer_id.0, fork_height, fork_prev, fork_work, our_work, self.best_header_height
                );
                self.best_header_height = fork_height;
                self.best_header_hash = *fork_prev;
                prev_hash = *fork_prev;
                base_height = fork_height;
                // Reorg Unit E (E3): record the fork point so the block-download
                // enqueue floors at min(chainstate_tip, fork_height) and
                // requests the fork's bodies below the active tip. Sticky and
                // min-across-batches: a multi-batch fork rewinds on its first
                // batch (which may be a full Ok(true) batch that does not itself
                // enqueue); the lowest fork point must survive until the caller
                // consumes it via take_pending_rewind.
                self.pending_rewind = Some(match self.pending_rewind {
                    Some(existing) => existing.min(fork_height),
                    None => fork_height,
                });
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

        let result = sync.process_headers(peer, vec![], &mut |_, _| Ok(()), &|_| None, &|_| None);
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

        let result = sync.process_headers(peer, vec![bad_header], &mut |_, _| Ok(()), &|_| None, &|_| None);
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

        let result = sync.process_headers(peer, headers, &mut |_, _| Ok(()), &|_| None, &|_| None);
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

        let result = sync.process_headers(peer, headers, &mut |_, _| Ok(()), &|_| None, &|_| None);
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
        let result = sync.process_headers(peer2, headers, &mut |_, _| Ok(()), &|_| None, &|_| None);

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
        let result = sync.process_headers(peer2, headers, &mut |_, _| Ok(()), &|_| None, &|_| None);

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
        let result = sync.process_headers(peer, headers, &mut |_, _| Ok(()), &|_| None, &|_| None);

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
        }, &|_| None, &|_| None);

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
        }, &|_| None, &|_| None);

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
        let result = sync.process_headers(peer, headers, &mut |_, _| Ok(()), &|_| None, &|_| None);
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
        let result = sync.process_headers(peer, headers, &mut |_, _| Ok(()), &|_| None, &|_| None);
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
        let result = sync.process_headers(peer, next, &mut |_, _| Ok(()), &|_| None, &|_| None);
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
        let result = sync.process_headers(peer, new_header, &mut |_, _| Ok(()), &|_| None, &|_| None);
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

    // ===================================================================
    // Reorg Unit E — fork-aware block download (E1 discovery, E2 work-gate,
    // E3 rewind report). On regtest difficulty is constant, so a heavier
    // chain is exactly a longer chain — the same scenario the end-to-end
    // two-node regtest proof exercises.
    // ===================================================================

    /// Build a HashMap<height,(hash,bits)> for our current chain and seed
    /// `sync` to its tip by processing it as active sync. Returns the per-height
    /// maps (for the find_hash_height / get_existing_header_bits closures) and
    /// the chain's headers.
    fn seed_chain(
        sync: &mut HeaderSync,
        peer: PeerId,
        genesis: Hash256,
        len: usize,
    ) -> (
        std::collections::HashMap<u32, Hash256>,
        std::collections::HashMap<u32, u32>,
        Vec<BlockHeader>,
    ) {
        let chain = make_valid_header_chain(genesis, len);
        let mut h2hash = std::collections::HashMap::new();
        let mut h2bits = std::collections::HashMap::new();
        h2hash.insert(0u32, genesis);
        for (i, h) in chain.iter().enumerate() {
            let height = (i + 1) as u32;
            h2hash.insert(height, h.block_hash());
            h2bits.insert(height, h.bits);
        }
        sync.state = SyncState::DownloadingHeaders {
            peer,
            last_hash: genesis,
        };
        let r = sync.process_headers(peer, chain.clone(), &mut |_, _| Ok(()), &|_| None, &|_| None);
        assert_eq!(r, Ok(false));
        assert_eq!(sync.best_header_height(), len as u32);
        // The seeding processed no fork, so nothing should be pending.
        assert_eq!(sync.pending_rewind, None, "seeding must not set pending_rewind");
        (h2hash, h2bits, chain)
    }

    #[test]
    fn test_e3_e2_heavier_longer_fork_rewinds_and_reports_pending() {
        let genesis = Hash256([0u8; 32]);
        let mut sync = HeaderSync::new(genesis);
        let peer = PeerId(1);
        sync.register_peer(peer, 100);

        // Our chain: genesis -> a1 -> a2 -> a3 (heights 1..=3).
        let (h2hash, h2bits, our) = seed_chain(&mut sync, peer, genesis, 3);

        // Heavier fork from height 1 (after a1): 3 new headers -> heights 2,3,4.
        // fork_work = 3w, our_work over heights 2..=3 = 2w  => heavier => rewind.
        let fork_point_hash = our[0].block_hash(); // height 1
        let fork = make_valid_header_chain(fork_point_hash, 3);

        sync.state = SyncState::DownloadingHeaders {
            peer,
            last_hash: sync.best_header_hash(),
        };
        let find = |hash: &Hash256| -> Option<u32> {
            h2hash.iter().find(|(_, v)| *v == hash).map(|(k, _)| *k)
        };
        let existing_bits = |height: u32| -> Option<u32> { h2bits.get(&height).copied() };

        let r = sync.process_headers(peer, fork, &mut |_, _| Ok(()), &find, &existing_bits);
        assert_eq!(r, Ok(false));
        // Rewound to fork point (height 1) then accepted 3 fork headers -> tip 4.
        assert_eq!(sync.best_header_height(), 4);
        // E3: the fork point is reported for the download floor, then consumed.
        assert_eq!(sync.take_pending_rewind(), Some(1));
        assert_eq!(sync.take_pending_rewind(), None);
    }

    #[test]
    fn test_e2_lighter_shorter_fork_refused_no_rewind() {
        let genesis = Hash256([0u8; 32]);
        let mut sync = HeaderSync::new(genesis);
        let peer = PeerId(1);
        sync.register_peer(peer, 100);

        // Our chain length 5 (heights 1..=5).
        let (h2hash, h2bits, our) = seed_chain(&mut sync, peer, genesis, 5);

        // Lighter fork from height 1: only 2 headers -> heights 2,3.
        // fork_work = 2w, our_work over heights 2..=5 = 4w => NOT heavier => refused.
        let fork_point_hash = our[0].block_hash(); // height 1
        let fork = make_valid_header_chain(fork_point_hash, 2);

        sync.state = SyncState::DownloadingHeaders {
            peer,
            last_hash: sync.best_header_hash(),
        };
        let find = |hash: &Hash256| -> Option<u32> {
            h2hash.iter().find(|(_, v)| *v == hash).map(|(k, _)| *k)
        };
        let existing_bits = |height: u32| -> Option<u32> { h2bits.get(&height).copied() };

        let r = sync.process_headers(peer, fork, &mut |_, _| Ok(()), &find, &existing_bits);
        assert_eq!(r, Ok(false));
        // No rewind: header tip unchanged, nothing pending, index NOT overwritten.
        assert_eq!(sync.best_header_height(), 5);
        assert_eq!(sync.take_pending_rewind(), None);
    }

    #[test]
    fn test_e1_unsolicited_unconnecting_sets_getheaders_hint() {
        let genesis = Hash256([0u8; 32]);
        let mut sync = HeaderSync::new(genesis);
        let peer = PeerId(7);
        sync.register_peer(peer, 100);
        // NOT active sync (Idle), tip = genesis.

        // Headers that do not connect to our tip (prev = unknown hash).
        let unconnected = make_valid_header_chain(Hash256([42u8; 32]), 2);
        let r = sync.process_headers(peer, unconnected, &mut |_, _| Ok(()), &|_| None, &|_| None);
        assert_eq!(r, Ok(false));
        // E1: the peer is recorded so the caller sends a discovery getheaders.
        assert_eq!(sync.take_getheaders_hint(), Some(peer));
        assert_eq!(sync.take_getheaders_hint(), None);
        // The unconnecting batch must not advance our header tip.
        assert_eq!(sync.best_header_height(), 0);
    }

    #[test]
    fn test_e1_unsolicited_connecting_extends_without_hint() {
        let genesis = Hash256([0u8; 32]);
        let mut sync = HeaderSync::new(genesis);
        let peer = PeerId(7);
        sync.register_peer(peer, 100);
        // Idle, but the announcement connects to our tip (BIP-130 new block).
        let chain = make_valid_header_chain(genesis, 1);
        let r = sync.process_headers(peer, chain, &mut |_, _| Ok(()), &|_| None, &|_| None);
        assert_eq!(r, Ok(false));
        assert_eq!(sync.best_header_height(), 1);
        // A connecting announcement is normal sync — no discovery hint.
        assert_eq!(sync.take_getheaders_hint(), None);
    }

    #[test]
    fn test_request_headers_from_sets_active_sync_for_specific_peer() {
        let genesis = Hash256([0u8; 32]);
        let mut sync = HeaderSync::new(genesis);
        let peer = PeerId(9);
        // request_headers_from targets a SPECIFIC peer (not best_sync_peer) and
        // promotes it to active sync so its fork reply reaches the rewind path.
        let msg = sync.request_headers_from(peer, |h| if h == 0 { Some(genesis) } else { None });
        assert!(matches!(msg, NetworkMessage::GetHeaders(_)));
        match sync.state() {
            SyncState::DownloadingHeaders { peer: p, .. } => assert_eq!(*p, peer),
            other => panic!("expected DownloadingHeaders for the targeted peer, got {:?}", other),
        }
    }

    #[test]
    fn test_e3_normal_sync_does_not_set_pending_rewind() {
        // Guard: the no-fork path never sets pending_rewind, so the download
        // floor stays at chainstate_tip and normal IBD is byte-for-byte
        // unchanged.
        let genesis = Hash256([0u8; 32]);
        let mut sync = HeaderSync::new(genesis);
        let peer = PeerId(3);
        sync.register_peer(peer, 100);
        let _ = seed_chain(&mut sync, peer, genesis, 4);
        assert_eq!(sync.take_pending_rewind(), None);
    }

    #[test]
    fn test_remove_active_peer_clears_stranded_pending_rewind() {
        // Review fix 1: a fork rewind on a full Ok(true) batch leaves a sticky
        // pending_rewind while state == DownloadingHeaders{peer}. If that peer
        // then disconnects, the value must be cleared so a later unrelated
        // Ok(false) Headers message can't consume a stale fork height.
        let genesis = Hash256([0u8; 32]);
        let mut sync = HeaderSync::new(genesis);
        let peer = PeerId(5);
        sync.register_peer(peer, 100);
        sync.pending_rewind = Some(3);
        sync.state = SyncState::DownloadingHeaders {
            peer,
            last_hash: genesis,
        };
        sync.remove_peer(peer);
        assert_eq!(
            sync.take_pending_rewind(),
            None,
            "remove_peer of the active sync peer must clear a stranded pending_rewind"
        );
        assert_eq!(sync.state, SyncState::Idle);
    }

    #[test]
    fn test_remove_other_peer_keeps_pending_rewind() {
        // The fork sync is in progress from peer_a; an unrelated peer_b
        // disconnecting must NOT abort it.
        let genesis = Hash256([0u8; 32]);
        let mut sync = HeaderSync::new(genesis);
        let peer_a = PeerId(5);
        let peer_b = PeerId(6);
        sync.register_peer(peer_a, 100);
        sync.register_peer(peer_b, 100);
        sync.pending_rewind = Some(3);
        sync.state = SyncState::DownloadingHeaders {
            peer: peer_a,
            last_hash: genesis,
        };
        sync.remove_peer(peer_b);
        assert_eq!(sync.take_pending_rewind(), Some(3));
    }

    #[test]
    fn test_start_sync_falls_back_to_active_peer_when_none_taller() {
        // Review fix 3: when no peer is strictly taller than our header tip but
        // we're mid-sync (a multi-batch fork continuation whose peer's tracked
        // height was capped at our new tip), start_sync keeps requesting from
        // the active peer instead of stranding the fork.
        let genesis = Hash256([0u8; 32]);
        let mut sync = HeaderSync::new(genesis);
        let peer = PeerId(8);
        sync.set_best_header(100, Hash256([1u8; 32]));
        sync.register_peer(peer, 100); // == our tip, not strictly greater
        assert!(sync.best_sync_peer().is_none());
        sync.state = SyncState::DownloadingHeaders {
            peer,
            last_hash: sync.best_header_hash(),
        };
        let r = sync.start_sync(|h| if h <= 100 { Some(Hash256([h as u8; 32])) } else { None });
        let (target, msg) = r.expect("fallback should request from the active peer");
        assert_eq!(target, peer);
        assert!(matches!(msg, NetworkMessage::GetHeaders(_)));
    }

    #[test]
    fn test_start_sync_no_fallback_when_idle() {
        // At tip (Idle) with no taller peer, start_sync returns None — the
        // fallback must not fire (no getheaders loop at the tip).
        let mut sync = HeaderSync::new(Hash256([0u8; 32]));
        let peer = PeerId(8);
        sync.set_best_header(100, Hash256([1u8; 32]));
        sync.register_peer(peer, 100);
        assert_eq!(sync.state, SyncState::Idle);
        assert!(sync.start_sync(|_| None).is_none());
    }
}
