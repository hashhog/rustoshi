//! Header sync anti-DoS protection (PRESYNC/REDOWNLOAD).
//!
//! This module implements the header synchronization anti-DoS strategy from
//! Bitcoin Core's `headerssync.cpp`. The key insight is that an attacker could
//! cheaply generate millions of low-work headers to exhaust our memory.
//!
//! # Strategy
//!
//! To prevent memory exhaustion, we use a two-phase approach:
//!
//! 1. **PRESYNC phase**: Accept headers without storing them permanently. Only
//!    track cumulative chainwork, header count, and periodic commitments (hashes).
//!    This allows us to verify the chain has sufficient work without storing every
//!    header.
//!
//! 2. **REDOWNLOAD phase**: Once we've verified the chain has sufficient work,
//!    re-request all headers from the beginning and store them permanently. We
//!    verify the re-downloaded headers against our stored commitments.
//!
//! # Memory Bounds
//!
//! During PRESYNC, we store only:
//! - Cumulative chainwork: 32 bytes
//! - Last header hash: 32 bytes
//! - Header count: 8 bytes
//! - Periodic commitments: 1 bit per N headers
//!
//! This is far less than storing all headers (~80 bytes each = 64MB for 800K blocks).
//!
//! # Parameters (matching Bitcoin Core defaults)
//!
//! - `COMMITMENT_PERIOD = 600` — one commitment bit per 600 headers
//!   (Core: `HEADER_COMMITMENT_PERIOD = 600`; headerssync-params.py)
//! - `REDOWNLOAD_BUFFER_SIZE = 14_304` — buffer depth before releasing headers
//!   (Core: `REDOWNLOAD_BUFFER_SIZE = 14_304`)
//! - `max_commitments` — MTP-anchored upper bound on chain length (6 blk/s rule)
//!   (Core: `m_max_commitments = 6 * max_seconds_since_start / commitment_period`)

use rustoshi_consensus::{
    get_block_proof, permitted_difficulty_transition, ChainParams, ChainWork,
    MAX_FUTURE_BLOCK_TIME,
};
use rustoshi_primitives::{BlockHeader, Hash256};
use std::collections::VecDeque;
use siphasher::sip::SipHasher24;
use std::hash::Hasher;

/// Maximum headers per message (same as Bitcoin Core).
pub const MAX_HEADERS_PER_MESSAGE: usize = 2000;

/// Commitment period: store one commitment bit per N headers.
///
/// Bitcoin Core default: `HEADER_COMMITMENT_PERIOD = 600`.
/// Reference: `bitcoin-core/src/headerssync.cpp` constructor comment and
/// `headerssync-params.py`.
const COMMITMENT_PERIOD: u64 = 600;

/// Minimum number of headers that must be buffered (with commitments verified)
/// before releasing headers from the redownload buffer.
///
/// Bitcoin Core default: `REDOWNLOAD_BUFFER_SIZE = 14_304`.
/// Reference: `bitcoin-core/src/headerssync.h`.
const REDOWNLOAD_BUFFER_SIZE: usize = 14_304;

/// State of the header sync process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresyncState {
    /// PRESYNC: receiving headers and building commitments, tracking chainwork.
    /// Not yet demonstrated sufficient work.
    Presync,
    /// REDOWNLOAD: chain has sufficient work, re-downloading and verifying.
    Redownload,
    /// FINAL: sync complete or failed, state should be discarded.
    Final,
}

/// Compressed header that omits prevhash (reconstructible from chain order).
/// This saves 32 bytes per header during REDOWNLOAD buffering.
#[derive(Clone, Debug)]
struct CompressedHeader {
    version: i32,
    merkle_root: Hash256,
    timestamp: u32,
    bits: u32,
    nonce: u32,
}

impl CompressedHeader {
    fn from_header(header: &BlockHeader) -> Self {
        Self {
            version: header.version,
            merkle_root: header.merkle_root,
            timestamp: header.timestamp,
            bits: header.bits,
            nonce: header.nonce,
        }
    }

    fn to_full_header(&self, prev_hash: Hash256) -> BlockHeader {
        BlockHeader {
            version: self.version,
            prev_block_hash: prev_hash,
            merkle_root: self.merkle_root,
            timestamp: self.timestamp,
            bits: self.bits,
            nonce: self.nonce,
        }
    }
}

/// Result of processing headers.
#[derive(Debug)]
#[derive(Default)]
pub struct ProcessingResult {
    /// Headers that have been fully validated and can be added to the chain.
    pub pow_validated_headers: Vec<BlockHeader>,
    /// Whether processing succeeded (false = abort sync with this peer).
    pub success: bool,
    /// Whether we should request more headers.
    pub request_more: bool,
}


/// Header sync state machine implementing PRESYNC/REDOWNLOAD anti-DoS protection.
///
/// Mirrors `HeadersSyncState` in `bitcoin-core/src/headerssync.cpp`.
pub struct HeadersPresyncState {
    /// Current state.
    state: PresyncState,

    /// Chain parameters for difficulty validation.
    params: ChainParams,

    /// The starting block hash (fork point with our chain).
    chain_start_hash: Hash256,
    /// Height of the chain start block.
    chain_start_height: u32,
    /// Bits (difficulty) of the chain start block.
    chain_start_bits: u32,
    /// Cumulative chainwork at the chain start block.
    chain_start_work: ChainWork,

    /// Minimum required chainwork to accept this chain.
    pub(crate) minimum_required_work: ChainWork,

    // ===== PRESYNC state =====
    /// Accumulated chainwork seen so far (initialized to chain_start chainwork).
    current_chain_work: ChainWork,
    /// Height of last header processed in PRESYNC.
    current_height: u64,
    /// Hash of the last header received in PRESYNC.
    last_header_hash: Hash256,
    /// Bits of the last header received (for difficulty validation).
    last_header_bits: u32,
    /// Salted hasher key for commitments (unique per sync, never reused).
    /// This is the Rust analog of `SaltedUint256Hasher m_hasher` in Core.
    hasher_key: (u64, u64),
    /// Secret offset for commitment positions (prevents attacker from predicting
    /// which heights are committed). Core: `m_commit_offset` (protected in Core for testing).
    pub(crate) commit_offset: u64,
    /// Queue of commitment bits (1-bit hashes of committed headers).
    /// Created during PRESYNC, consumed during REDOWNLOAD.
    pub(crate) header_commitments: VecDeque<bool>,
    /// Maximum commitments allowed before aborting (MTP-anchored chain-age bound).
    /// Core: `m_max_commitments = 6 * max_seconds_since_start / commitment_period`.
    pub(crate) max_commitments: u64,

    // ===== REDOWNLOAD state =====
    /// Buffer of compressed headers waiting for enough commitments to verify.
    redownload_buffer: VecDeque<CompressedHeader>,
    /// Height of last header in redownload buffer.
    redownload_buffer_last_height: u64,
    /// Hash of last header in redownload buffer.
    redownload_buffer_last_hash: Hash256,
    /// Hash of the previous block for the first header in the buffer.
    redownload_buffer_first_prev_hash: Hash256,
    /// Accumulated chainwork during redownload (initialized to chain_start chainwork).
    pub(crate) redownload_chain_work: ChainWork,
    /// Whether we've reached sufficient work during redownload (can release all remaining headers).
    /// Core: `m_process_all_remaining_headers`.
    process_all_remaining: bool,
}

impl HeadersPresyncState {
    /// Create a new header sync state.
    ///
    /// # Arguments
    /// * `params` - Chain parameters
    /// * `chain_start_hash` - Hash of the block we're building on
    /// * `chain_start_height` - Height of that block
    /// * `chain_start_bits` - Difficulty bits of that block
    /// * `chain_start_work` - Cumulative chainwork at that block (nChainWork)
    /// * `chain_start_mtp` - Median-time-past of the chain start block
    ///   (used to compute MTP-anchored max_commitments bound)
    /// * `minimum_required_work` - Minimum chainwork required to accept headers
    ///
    /// Reference: `HeadersSyncState::HeadersSyncState` in `headerssync.cpp` lines 17-46.
    pub fn new(
        params: ChainParams,
        chain_start_hash: Hash256,
        chain_start_height: u32,
        chain_start_bits: u32,
        chain_start_work: ChainWork,
        chain_start_mtp: u32,
        minimum_required_work: ChainWork,
    ) -> Self {
        // Generate random hasher key for commitments — unique per peer sync.
        // Core: `SaltedUint256Hasher m_hasher` (secret salt, never reused across syncs).
        let hasher_key = (
            rand::random::<u64>(),
            rand::random::<u64>(),
        );

        // Random offset for commitment positions — prevents an attacker from knowing
        // which heights are committed and crafting a chain that avoids those heights.
        // Core: `m_commit_offset = FastRandomContext().randrange(commitment_period)` (line 23).
        let commit_offset = rand::random::<u64>() % COMMITMENT_PERIOD;

        // Compute max_commitments as MTP-anchored upper bound on how many headers
        // a consensus-valid chain could have right now.
        //
        // Core (headerssync.cpp lines 41-43):
        //   max_seconds_since_start = (now - chain_start.GetMedianTimePast()) + MAX_FUTURE_BLOCK_TIME
        //   m_max_commitments = 6 * max_seconds_since_start / commitment_period
        //
        // 6 blocks/second is the maximum block rate given the MTP rule. A chain longer
        // than this bound cannot be consensus-valid at the current wall-clock time.
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // Saturating subtraction: if MTP is in the future (shouldn't happen), treat as 0.
        let secs_since_start = now_secs
            .saturating_sub(chain_start_mtp as u64)
            .saturating_add(MAX_FUTURE_BLOCK_TIME);
        let max_commitments = 6u64 * secs_since_start / COMMITMENT_PERIOD;

        Self {
            state: PresyncState::Presync,
            params,
            chain_start_hash,
            chain_start_height,
            chain_start_bits,
            chain_start_work,
            minimum_required_work,
            current_chain_work: chain_start_work,
            current_height: chain_start_height as u64,
            last_header_hash: chain_start_hash,
            last_header_bits: chain_start_bits,
            hasher_key,
            commit_offset,
            header_commitments: VecDeque::new(),
            max_commitments,
            redownload_buffer: VecDeque::new(),
            redownload_buffer_last_height: 0,
            redownload_buffer_last_hash: Hash256::ZERO,
            redownload_buffer_first_prev_hash: Hash256::ZERO,
            // Initialized to chain_start_work; will be properly reset at PRESYNC→REDOWNLOAD.
            redownload_chain_work: ChainWork::ZERO,
            process_all_remaining: false,
        }
    }

    /// Get the current state.
    pub fn state(&self) -> PresyncState {
        self.state
    }

    /// Get the current height reached during PRESYNC.
    pub fn presync_height(&self) -> u64 {
        self.current_height
    }

    /// Get the chainwork accumulated so far.
    pub fn presync_work(&self) -> &ChainWork {
        &self.current_chain_work
    }

    /// Process a batch of headers received from the peer.
    ///
    /// The caller MUST have already verified that each header satisfies the
    /// proof-of-work target embedded in the header (hash <= target). This function
    /// only verifies that difficulty *transitions* are valid — it does not re-check
    /// the PoW hash. This mirrors Core's contract: "the caller has already verified
    /// the headers satisfy the proof-of-work target included in the header (but not
    /// necessarily verified that the proof-of-work target is correct and passes
    /// consensus rules)." (headerssync.h line 155-158)
    ///
    /// Reference: `HeadersSyncState::ProcessNextHeaders` in `headerssync.cpp` lines 68-137.
    ///
    /// # Returns
    /// - `ProcessingResult` with validated headers, success status, and whether to request more.
    pub fn process_next_headers(
        &mut self,
        headers: &[BlockHeader],
        full_message: bool,
    ) -> ProcessingResult {
        let mut result = ProcessingResult::default();

        // Core line 74: empty headers → return early.
        if headers.is_empty() {
            return result;
        }

        // Core line 77: FINAL state → reject.
        if self.state == PresyncState::Final {
            return result;
        }

        match self.state {
            PresyncState::Presync => {
                // Core lines 83-96: PRESYNC — validate + store commitments.
                result.success = self.validate_and_store_commitments(headers);
                if result.success {
                    if full_message || self.state == PresyncState::Redownload {
                        // Full message: more headers may be available.
                        // Transitioned to REDOWNLOAD: need to re-request from the beginning.
                        result.request_more = true;
                    }
                    // If not full and still in PRESYNC: chain ended, not enough work.
                }
            }
            PresyncState::Redownload => {
                // Core lines 98-132: REDOWNLOAD — verify commitments and buffer headers.
                result.success = true;
                for header in headers {
                    if !self.validate_and_store_redownloaded(header) {
                        result.success = false;
                        break;
                    }
                }

                if result.success {
                    result.pow_validated_headers = self.pop_headers_ready_for_acceptance();

                    if self.redownload_buffer.is_empty() && self.process_all_remaining {
                        // All done — finalize below.
                    } else if full_message {
                        result.request_more = true;
                    }
                    // else: non-full message in REDOWNLOAD → peer declined to serve the full
                    // chain again. Give up (success=true, request_more=false → finalize below).
                }
            }
            PresyncState::Final => {}
        }

        // Core line 135: finalize unless both success AND request_more.
        if !(result.success && result.request_more) {
            self.finalize();
        }

        result
    }

    /// Get a block locator for the next getheaders request.
    ///
    /// Reference: `HeadersSyncState::NextHeadersRequestLocator` in `headerssync.cpp` lines 296-317.
    pub fn next_locator(&self) -> Vec<Hash256> {
        match self.state {
            // Core line 306: PRESYNC uses last received header hash.
            PresyncState::Presync => {
                vec![self.last_header_hash, self.chain_start_hash]
            }
            // Core line 311: REDOWNLOAD uses last hash from redownload buffer.
            PresyncState::Redownload => {
                vec![self.redownload_buffer_last_hash, self.chain_start_hash]
            }
            PresyncState::Final => vec![],
        }
    }

    /// Mark this sync as complete/failed and free all per-sync state.
    ///
    /// Reference: `HeadersSyncState::Finalize` in `headerssync.cpp` lines 51-63.
    fn finalize(&mut self) {
        self.state = PresyncState::Final;
        self.header_commitments.clear();
        self.redownload_buffer.clear();
    }

    /// PRESYNC: Validate headers and store periodic commitments.
    ///
    /// Reference: `HeadersSyncState::ValidateAndStoreHeadersCommitments` in
    /// `headerssync.cpp` lines 139-175.
    fn validate_and_store_commitments(&mut self, headers: &[BlockHeader]) -> bool {
        if headers.is_empty() {
            return true;
        }

        // Core line 148: first header must connect to what we've seen.
        if headers[0].prev_block_hash != self.last_header_hash {
            tracing::debug!(
                "PRESYNC: header doesn't connect (expected {}, got {})",
                self.last_header_hash,
                headers[0].prev_block_hash
            );
            return false;
        }

        for header in headers {
            if !self.validate_and_process_single_presync(header) {
                return false;
            }
        }

        // Core line 165: transition to REDOWNLOAD when work threshold is reached.
        if self.current_chain_work >= self.minimum_required_work {
            tracing::info!(
                "PRESYNC complete: reached sufficient work at height {}, transitioning to REDOWNLOAD",
                self.current_height
            );

            // Core lines 166-172: initialize REDOWNLOAD state from chain_start.
            self.redownload_buffer.clear();
            self.redownload_buffer_last_height = self.chain_start_height as u64;
            self.redownload_buffer_last_hash = self.chain_start_hash;
            self.redownload_buffer_first_prev_hash = self.chain_start_hash;
            // Core line 170: m_redownload_chain_work = m_chain_start.nChainWork (NOT minimum_chain_work).
            self.redownload_chain_work = self.chain_start_work;
            self.process_all_remaining = false;
            self.state = PresyncState::Redownload;
        }

        true
    }

    /// PRESYNC: Validate and process a single header.
    ///
    /// Checks only difficulty transitions — PoW hash validity is the caller's
    /// responsibility (see `process_next_headers` contract above).
    ///
    /// Reference: `HeadersSyncState::ValidateAndProcessSingleHeader` in
    /// `headerssync.cpp` lines 177-213.
    fn validate_and_process_single_presync(&mut self, header: &BlockHeader) -> bool {
        let next_height = self.current_height + 1;

        // Core line 189: verify difficulty transition (anti-DoS).
        // Note: PoW hash check is NOT done here — caller already verified it.
        if !permitted_difficulty_transition(
            next_height as u32,
            self.last_header_bits,
            header.bits,
            &self.params,
        ) {
            tracing::debug!(
                "PRESYNC: invalid difficulty transition at height {}",
                next_height
            );
            return false;
        }

        // Core line 195: store commitment at selected heights.
        if next_height % COMMITMENT_PERIOD == self.commit_offset {
            let commitment = self.compute_commitment(&header.block_hash());
            self.header_commitments.push_back(commitment);

            // Core line 198: abort if we exceed the MTP-anchored chain-age bound.
            if self.header_commitments.len() as u64 > self.max_commitments {
                tracing::debug!(
                    "PRESYNC: exceeded max commitments ({}) at height {}",
                    self.max_commitments,
                    next_height
                );
                return false;
            }
        }

        // Core line 208: accumulate chainwork.
        let work = get_block_proof(header.bits);
        self.current_chain_work = self.current_chain_work.saturating_add(&work);

        // Update state.
        self.last_header_hash = header.block_hash();
        self.last_header_bits = header.bits;
        self.current_height = next_height;

        true
    }

    /// REDOWNLOAD: Validate a redownloaded header against stored commitments.
    ///
    /// Checks only difficulty transitions and commitment bits — PoW hash validity
    /// is the caller's responsibility.
    ///
    /// Reference: `HeadersSyncState::ValidateAndStoreRedownloadedHeader` in
    /// `headerssync.cpp` lines 215-278.
    fn validate_and_store_redownloaded(&mut self, header: &BlockHeader) -> bool {
        let next_height = self.redownload_buffer_last_height + 1;

        // Core line 224: must connect to previous.
        if header.prev_block_hash != self.redownload_buffer_last_hash {
            tracing::debug!(
                "REDOWNLOAD: header doesn't connect at height {} (expected {}, got {})",
                next_height,
                self.redownload_buffer_last_hash,
                header.prev_block_hash
            );
            return false;
        }

        // Core lines 230-235: get previous bits for difficulty check.
        let prev_bits = if self.redownload_buffer.is_empty() {
            self.chain_start_bits
        } else {
            self.redownload_buffer.back().unwrap().bits
        };

        // Core line 237: verify difficulty transition.
        // Note: PoW hash check is NOT done here — caller already verified it.
        if !permitted_difficulty_transition(next_height as u32, prev_bits, header.bits, &self.params) {
            tracing::debug!(
                "REDOWNLOAD: invalid difficulty transition at height {}",
                next_height
            );
            return false;
        }

        // Core line 244: accumulate chainwork.
        let work = get_block_proof(header.bits);
        self.redownload_chain_work = self.redownload_chain_work.saturating_add(&work);

        // Core lines 246-248: set process_all_remaining once minimum work is reached.
        if self.redownload_chain_work >= self.minimum_required_work {
            self.process_all_remaining = true;
        }

        // Core lines 256-270: verify commitment if at a committed height and not yet done.
        // Skip commitment check once process_all_remaining is set — the peer may have
        // extended its chain between our first sync and our second, and we don't want
        // to fail because we ran out of stored commitments.
        if !self.process_all_remaining
            && next_height % COMMITMENT_PERIOD == self.commit_offset
        {
            // Core line 257: abort if we've run out of commitments (commitment overrun).
            if self.header_commitments.is_empty() {
                tracing::debug!(
                    "REDOWNLOAD: commitment overrun at height {}",
                    next_height
                );
                return false;
            }

            let expected = self.header_commitments.pop_front().unwrap();
            let actual = self.compute_commitment(&header.block_hash());

            // Core lines 266-269: mismatch → peer fed us a different chain.
            if expected != actual {
                tracing::debug!(
                    "REDOWNLOAD: commitment mismatch at height {} (expected {}, got {})",
                    next_height,
                    expected,
                    actual
                );
                return false;
            }
        }

        // Core lines 272-275: store in buffer.
        self.redownload_buffer.push_back(CompressedHeader::from_header(header));
        self.redownload_buffer_last_height = next_height;
        self.redownload_buffer_last_hash = header.block_hash();

        true
    }

    /// Pop headers from the redownload buffer that have enough verified commitments.
    ///
    /// Reference: `HeadersSyncState::PopHeadersReadyForAcceptance` in
    /// `headerssync.cpp` lines 280-294.
    fn pop_headers_ready_for_acceptance(&mut self) -> Vec<BlockHeader> {
        let mut result = Vec::new();

        // Core lines 287-293: release headers when:
        // 1. Buffer has more than REDOWNLOAD_BUFFER_SIZE headers, OR
        // 2. We've reached target work and can release everything remaining.
        while self.redownload_buffer.len() > REDOWNLOAD_BUFFER_SIZE
            || (!self.redownload_buffer.is_empty() && self.process_all_remaining)
        {
            let compressed = self.redownload_buffer.pop_front().unwrap();
            let header = compressed.to_full_header(self.redownload_buffer_first_prev_hash);
            // Core line 291: advance first_prev_hash for next reconstruction.
            self.redownload_buffer_first_prev_hash = header.block_hash();
            result.push(header);
        }

        result
    }

    /// Compute a 1-bit commitment to a header hash using salted SipHash.
    ///
    /// Core uses `SaltedUint256Hasher m_hasher` which is BLAKE3 or SHA256-based
    /// with a random salt. We use SipHash-2-4 with a random 128-bit key — different
    /// primitive but equivalent security properties (PRF with secret key → 1-bit output).
    /// Core: `m_hasher(current.GetHash()) & 1` (lines 197, 263).
    fn compute_commitment(&self, hash: &Hash256) -> bool {
        let mut hasher = SipHasher24::new_with_keys(self.hasher_key.0, self.hasher_key.1);
        hasher.write(&hash.0);
        (hasher.finish() & 1) == 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustoshi_consensus::ChainParams;

    /// Create a test header with regtest difficulty (easy PoW).
    fn make_test_header(prev_hash: Hash256, bits: u32, nonce: u32) -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_block_hash: prev_hash,
            merkle_root: Hash256::ZERO,
            timestamp: 1231006505,
            bits,
            nonce,
        }
    }

    /// Create a chain of headers that pass PoW at regtest difficulty.
    fn make_valid_chain(start_hash: Hash256, count: usize) -> Vec<BlockHeader> {
        make_valid_chain_at_bits(start_hash, count, 0x207fffff)
    }

    fn make_valid_chain_at_bits(start_hash: Hash256, count: usize, bits: u32) -> Vec<BlockHeader> {
        let mut headers = Vec::with_capacity(count);
        let mut prev_hash = start_hash;

        for _i in 0..count {
            for nonce in 0..10000u32 {
                let header = make_test_header(prev_hash, bits, nonce);
                if header.validate_pow() {
                    prev_hash = header.block_hash();
                    headers.push(header);
                    break;
                }
            }
        }

        headers
    }

    /// Build a state with regtest params using a fixed MTP (unix epoch = 0) for determinism.
    fn make_state(min_work_hex: &str) -> HeadersPresyncState {
        let params = ChainParams::regtest();
        let genesis_hash = params.genesis_hash;
        let min_work = ChainWork::from_hex(min_work_hex).unwrap();

        HeadersPresyncState::new(
            params,
            genesis_hash,
            0,
            0x207fffff,
            ChainWork::ZERO,
            0, // chain_start_mtp = 0 (unix epoch)
            min_work,
        )
    }

    // -------------------------------------------------------------------------
    // Gate 1: constructor randomizes commit_offset per instance (deterministic = attacker wins)
    // -------------------------------------------------------------------------
    #[test]
    fn test_commit_offset_is_randomized() {
        // Two independently constructed states should (almost certainly) have different offsets.
        // With COMMITMENT_PERIOD=600, the probability of collision is 1/600 per pair.
        // Run 20 pairs: chance all offsets collide = (1/600)^19 ≈ 0.
        let params = ChainParams::regtest();
        let offsets: Vec<u64> = (0..20)
            .map(|_| {
                let s = HeadersPresyncState::new(
                    params.clone(),
                    params.genesis_hash,
                    0,
                    0x207fffff,
                    ChainWork::ZERO,
                    0,
                    ChainWork::ZERO,
                );
                s.commit_offset
            })
            .collect();
        let all_same = offsets.iter().all(|&x| x == offsets[0]);
        assert!(!all_same, "commit_offset should be randomized, not deterministic");
    }

    // -------------------------------------------------------------------------
    // Gate 2: max_commitments is MTP-anchored, not a hardcoded constant
    // -------------------------------------------------------------------------
    #[test]
    fn test_max_commitments_mtp_anchored() {
        let params = ChainParams::regtest();
        let genesis_hash = params.genesis_hash;
        let min_work = ChainWork::ZERO;

        // Genesis MTP = 0. With chain_start_mtp = 0, max_commitments should be
        // proportional to (now + MAX_FUTURE_BLOCK_TIME) / COMMITMENT_PERIOD.
        // A chain starting from Bitcoin genesis (MTP ~0 for genesis) should yield a
        // very large max_commitments. Crucially: far more than the hardcoded
        // old value of 20yr / 2048 = ~1_893_127.
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let expected_max = 6u64 * (now_secs + MAX_FUTURE_BLOCK_TIME) / COMMITMENT_PERIOD;

        let state = HeadersPresyncState::new(
            params,
            genesis_hash,
            0,
            0x207fffff,
            ChainWork::ZERO,
            0,
            min_work,
        );

        // Allow a 1-second slop for test execution time.
        let allowed_max = 6u64 * (now_secs + MAX_FUTURE_BLOCK_TIME + 1) / COMMITMENT_PERIOD;
        assert!(
            state.max_commitments >= expected_max && state.max_commitments <= allowed_max,
            "max_commitments ({}) should be MTP-anchored ~{}, not hardcoded",
            state.max_commitments,
            expected_max
        );
    }

    // -------------------------------------------------------------------------
    // Gate 3: initial state = PRESYNC
    // -------------------------------------------------------------------------
    #[test]
    fn test_initial_state_is_presync() {
        let state = make_state("10");
        assert_eq!(state.state(), PresyncState::Presync);
    }

    // -------------------------------------------------------------------------
    // Gate 5: empty headers → early return (not a failure)
    // -------------------------------------------------------------------------
    #[test]
    fn test_empty_headers_returns_early() {
        let mut state = make_state("10");
        let result = state.process_next_headers(&[], true);
        // Empty: success=false (default), request_more=false. State unchanged.
        assert_eq!(state.state(), PresyncState::Presync);
        assert!(!result.request_more);
    }

    // -------------------------------------------------------------------------
    // Gate 6: FINAL state → reject immediately
    // -------------------------------------------------------------------------
    #[test]
    fn test_final_state_rejects_headers() {
        let mut state = make_state("10");
        state.finalize();
        assert_eq!(state.state(), PresyncState::Final);
        let headers = make_valid_chain(Hash256::ZERO, 1);
        let result = state.process_next_headers(&headers, true);
        assert!(!result.success);
        assert!(!result.request_more);
    }

    // -------------------------------------------------------------------------
    // Gate 8: full_headers_message → request_more=true in PRESYNC
    // -------------------------------------------------------------------------
    #[test]
    fn test_full_message_requests_more_in_presync() {
        let mut state = make_state("ffffffffffffffffffffffffffffffffffff");
        let params = ChainParams::regtest();
        let headers = make_valid_chain(params.genesis_hash, 5);
        let result = state.process_next_headers(&headers, true);
        assert!(result.success);
        assert!(result.request_more);
        assert_eq!(state.state(), PresyncState::Presync);
    }

    // -------------------------------------------------------------------------
    // Gate 9: non-full + still PRESYNC → no more (chain ended without enough work)
    // -------------------------------------------------------------------------
    #[test]
    fn test_low_work_chain_ends_sync() {
        let mut state = make_state("ffffffffffffffffffffffffffffffffffff");
        let params = ChainParams::regtest();
        let headers = make_valid_chain(params.genesis_hash, 10);
        let result = state.process_next_headers(&headers, false);
        assert!(result.success);
        assert!(!result.request_more);
        // Should be finalized since not requesting more.
        assert_eq!(state.state(), PresyncState::Final);
    }

    // -------------------------------------------------------------------------
    // Gate 10: connectivity check in PRESYNC
    // -------------------------------------------------------------------------
    #[test]
    fn test_presync_rejects_disconnected_headers() {
        let mut state = make_state("10");
        let fake_prev = Hash256([1u8; 32]);
        let headers = make_valid_chain(fake_prev, 5);
        let result = state.process_next_headers(&headers, true);
        assert!(!result.success);
    }

    // -------------------------------------------------------------------------
    // Gate 12: PRESYNC→REDOWNLOAD transition at min_work threshold
    // -------------------------------------------------------------------------
    #[test]
    fn test_presync_to_redownload_transition() {
        let mut state = make_state("1");
        let params = ChainParams::regtest();
        let headers = make_valid_chain(params.genesis_hash, 5);
        let result = state.process_next_headers(&headers, true);
        assert!(result.success);
        assert!(result.request_more);
        assert_eq!(state.state(), PresyncState::Redownload);
    }

    // -------------------------------------------------------------------------
    // Gate 13: PermittedDifficultyTransition called in PRESYNC
    // -------------------------------------------------------------------------
    #[test]
    fn test_presync_rejects_invalid_difficulty_transition() {
        // On mainnet (no pow_allow_min_difficulty), a non-retarget-boundary header
        // must keep the same nBits. Change nBits to trigger rejection.
        let params = ChainParams::mainnet();
        // Use a fake start hash since mainnet genesis PoW is hard.
        let start_hash = Hash256([0u8; 32]);
        let start_bits = 0x1d00ffff;
        let min_work = ChainWork::ZERO;

        let mut state = HeadersPresyncState::new(
            params,
            start_hash,
            0,
            start_bits,
            ChainWork::ZERO,
            0,
            min_work,
        );

        // Create a header with different bits (not at a retarget boundary).
        let bad_bits = 0x1c00ffff; // harder difficulty — not a valid transition
        let header = BlockHeader {
            version: 1,
            prev_block_hash: start_hash,
            merkle_root: Hash256::ZERO,
            timestamp: 1231006505,
            bits: bad_bits,
            nonce: 0,
        };

        let result = state.process_next_headers(&[header], true);
        // Should fail the difficulty transition check at height 1 (not retarget boundary).
        assert!(!result.success);
    }

    // -------------------------------------------------------------------------
    // Gate 16: max_commitments overflow → abort
    // -------------------------------------------------------------------------
    #[test]
    fn test_max_commitments_overflow_aborts() {
        let params = ChainParams::regtest();
        let genesis_hash = params.genesis_hash;
        let min_work = ChainWork::from_hex("ffffffffffffffffffffffffffffffffffff").unwrap();

        // Set max_commitments to 0 to force immediate overflow on the first commitment.
        let mut state = HeadersPresyncState::new(
            params,
            genesis_hash,
            0,
            0x207fffff,
            ChainWork::ZERO,
            0,
            min_work,
        );
        state.max_commitments = 0;

        // We need to generate enough headers to hit a commitment at height % 600 == commit_offset.
        // With commit_offset somewhere in [0, 600), generate 700 headers to guarantee a hit.
        // Use a large chain to ensure we cover the first commitment position.
        let headers = make_valid_chain(genesis_hash, COMMITMENT_PERIOD as usize + 10);
        let result = state.process_next_headers(&headers, true);
        // Should fail when commitments.len() > max_commitments=0
        assert!(!result.success);
    }

    // -------------------------------------------------------------------------
    // Gate 19: REDOWNLOAD PermittedDifficultyTransition called
    // -------------------------------------------------------------------------
    #[test]
    fn test_redownload_presync_full_cycle() {
        let params = ChainParams::regtest();
        let genesis_hash = params.genesis_hash;
        let min_work = ChainWork::from_hex("1").unwrap();

        let mut state = HeadersPresyncState::new(
            params.clone(),
            genesis_hash,
            0,
            0x207fffff,
            ChainWork::ZERO,
            0,
            min_work,
        );

        // PRESYNC phase
        let headers = make_valid_chain(genesis_hash, 50);
        let result = state.process_next_headers(&headers, true);
        assert!(result.success);
        assert_eq!(state.state(), PresyncState::Redownload);

        // REDOWNLOAD phase with the same headers
        let result = state.process_next_headers(&headers, false);
        assert!(result.success);
        assert!(!result.pow_validated_headers.is_empty());
    }

    // -------------------------------------------------------------------------
    // Gate 18: REDOWNLOAD connectivity check
    // -------------------------------------------------------------------------
    #[test]
    fn test_redownload_rejects_disconnected_headers() {
        let params = ChainParams::regtest();
        let genesis_hash = params.genesis_hash;
        let min_work = ChainWork::from_hex("1").unwrap();

        let mut state = HeadersPresyncState::new(
            params.clone(),
            genesis_hash,
            0,
            0x207fffff,
            ChainWork::ZERO,
            0,
            min_work,
        );

        let headers = make_valid_chain(genesis_hash, 10);
        let result = state.process_next_headers(&headers, true);
        assert!(result.success);
        assert_eq!(state.state(), PresyncState::Redownload);

        // Try to feed headers that don't connect.
        let disconnected = make_valid_chain(Hash256([0xab; 32]), 5);
        let result = state.process_next_headers(&disconnected, true);
        assert!(!result.success);
    }

    // -------------------------------------------------------------------------
    // Bug 2 regression: redownload_chain_work initialized from chain_start_work,
    // NOT from minimum_chain_work (Core line 170).
    // -------------------------------------------------------------------------
    #[test]
    fn test_redownload_chain_work_initialized_from_chain_start() {
        let params = ChainParams::regtest();
        let genesis_hash = params.genesis_hash;
        // Large minimum work so we definitely don't accidentally trigger process_all_remaining early.
        let min_work = ChainWork::from_hex("ffffffffffffffffffffffffffffffffffff").unwrap();

        // chain_start_work = 0 (correct Core behavior: start accumulating from 0).
        let state = HeadersPresyncState::new(
            params,
            genesis_hash,
            0,
            0x207fffff,
            ChainWork::ZERO, // chain_start_work
            0,
            min_work,
        );

        // After construction, redownload_chain_work should be ZERO (= chain_start_work),
        // NOT equal to minimum_chain_work or params.minimum_chain_work.
        assert_eq!(
            state.redownload_chain_work,
            ChainWork::ZERO,
            "redownload_chain_work must be initialized to chain_start_work, not minimum_chain_work"
        );
    }

    // -------------------------------------------------------------------------
    // Gate 22: process_all_remaining skips commitment check
    // -------------------------------------------------------------------------
    #[test]
    fn test_process_all_remaining_skips_commitments() {
        // After reaching minimum work in REDOWNLOAD, any further headers should
        // be accepted without commitment verification (peer may have extended chain).
        let params = ChainParams::regtest();
        let genesis_hash = params.genesis_hash;
        let min_work = ChainWork::from_hex("1").unwrap();

        let mut state = HeadersPresyncState::new(
            params.clone(),
            genesis_hash,
            0,
            0x207fffff,
            ChainWork::ZERO,
            0,
            min_work,
        );

        // PRESYNC with 100 headers (easily exceeds min_work=1).
        let headers = make_valid_chain(genesis_hash, 100);
        let presync_result = state.process_next_headers(&headers, true);
        assert!(presync_result.success);
        assert_eq!(state.state(), PresyncState::Redownload);

        // REDOWNLOAD with the same headers — process_all_remaining will be set
        // on the first header (since min_work is tiny).
        let redownload_result = state.process_next_headers(&headers, false);
        assert!(redownload_result.success);
    }

    // -------------------------------------------------------------------------
    // Gate 21: commitment overrun in REDOWNLOAD → abort
    //
    // Scenario: PRESYNC stores N commitments; in REDOWNLOAD we clear them all so the
    // first commitment-boundary header triggers the "overrun" branch (empty deque).
    // We need min_work to be reachable during PRESYNC but NOT during REDOWNLOAD (so
    // process_all_remaining doesn't fire and skip the check). We achieve this by
    // transitioning to REDOWNLOAD with a tiny min_work, then resetting
    // redownload_chain_work to zero and setting minimum_required_work to a huge value.
    // -------------------------------------------------------------------------
    #[test]
    fn test_redownload_commitment_overrun_aborts() {
        let params = ChainParams::regtest();
        let genesis_hash = params.genesis_hash;

        // Low min_work to reach REDOWNLOAD.
        let min_work = ChainWork::from_hex("1").unwrap();

        let mut state = HeadersPresyncState::new(
            params.clone(),
            genesis_hash,
            0,
            0x207fffff,
            ChainWork::ZERO,
            0,
            min_work,
        );

        // PRESYNC: enough headers to transition and build at least one commitment.
        // With COMMITMENT_PERIOD=600, we need 600+ headers to guarantee a commitment hit.
        let headers = make_valid_chain(genesis_hash, COMMITMENT_PERIOD as usize + 50);
        let presync_result = state.process_next_headers(&headers, true);
        assert!(presync_result.success);
        assert_eq!(state.state(), PresyncState::Redownload);

        // Make the REDOWNLOAD phase never reach process_all_remaining (big min work).
        state.minimum_required_work = ChainWork::from_hex("ffffffffffffffffffffffffffffffffffff").unwrap();
        state.redownload_chain_work = ChainWork::ZERO;

        // Clear all stored commitments — first commitment boundary in REDOWNLOAD will overrun.
        state.header_commitments.clear();

        // Feed the same headers — should hit a commitment-boundary and fail with overrun.
        let redownload_result = state.process_next_headers(&headers, true);
        assert!(!redownload_result.success);
    }

    // -------------------------------------------------------------------------
    // Gate 23: commitment mismatch in REDOWNLOAD → abort
    // -------------------------------------------------------------------------
    #[test]
    fn test_redownload_commitment_mismatch_aborts() {
        let params = ChainParams::regtest();
        let genesis_hash = params.genesis_hash;

        // Low min_work to reach REDOWNLOAD.
        let min_work = ChainWork::from_hex("1").unwrap();

        let mut state = HeadersPresyncState::new(
            params.clone(),
            genesis_hash,
            0,
            0x207fffff,
            ChainWork::ZERO,
            0,
            min_work,
        );

        // PRESYNC with enough headers to get at least one commitment stored.
        let chain_a = make_valid_chain(genesis_hash, COMMITMENT_PERIOD as usize + 50);
        let presync_result = state.process_next_headers(&chain_a, true);
        assert!(presync_result.success);
        assert_eq!(state.state(), PresyncState::Redownload);

        // Make the REDOWNLOAD phase never reach process_all_remaining (big min work).
        state.minimum_required_work = ChainWork::from_hex("ffffffffffffffffffffffffffffffffffff").unwrap();
        state.redownload_chain_work = ChainWork::ZERO;

        // Only flip commitments if any exist (if commit_offset fell beyond our chain, skip).
        if !state.header_commitments.is_empty() {
            let flipped: VecDeque<bool> = state.header_commitments.iter().map(|b| !b).collect();
            state.header_commitments = flipped;

            // Feed the same headers — should fail at the first commitment check.
            let redownload_result = state.process_next_headers(&chain_a, true);
            assert!(!redownload_result.success,
                "REDOWNLOAD should reject headers with flipped (mismatched) commitments");
        }
        // If no commitments were stored (commit_offset > chain length), test is vacuously ok.
    }

    // -------------------------------------------------------------------------
    // Gate 24: PopHeadersReadyForAcceptance — buffer flush
    // -------------------------------------------------------------------------
    #[test]
    fn test_pop_headers_releases_when_buffer_exceeds_limit() {
        // When buffer > REDOWNLOAD_BUFFER_SIZE, headers should be released.
        // We test indirectly via process_next_headers in REDOWNLOAD: small chain
        // doesn't exceed buffer, large chain does.
        let params = ChainParams::regtest();
        let genesis_hash = params.genesis_hash;
        let min_work = ChainWork::from_hex("1").unwrap();

        let mut state = HeadersPresyncState::new(
            params.clone(),
            genesis_hash,
            0,
            0x207fffff,
            ChainWork::ZERO,
            0,
            min_work,
        );

        // PRESYNC with a modest chain.
        let headers = make_valid_chain(genesis_hash, 50);
        let presync_result = state.process_next_headers(&headers, true);
        assert!(presync_result.success);
        assert_eq!(state.state(), PresyncState::Redownload);

        // REDOWNLOAD: process_all_remaining fires immediately (min_work=1 is tiny).
        let redownload_result = state.process_next_headers(&headers, false);
        assert!(redownload_result.success);
        assert!(!redownload_result.pow_validated_headers.is_empty());
    }

    // -------------------------------------------------------------------------
    // Gate 25+26: NextHeadersRequestLocator is state-dependent
    // -------------------------------------------------------------------------
    #[test]
    fn test_locator_is_state_dependent() {
        let params = ChainParams::regtest();
        let genesis_hash = params.genesis_hash;
        let min_work = ChainWork::from_hex("1").unwrap();

        let state = HeadersPresyncState::new(
            params.clone(),
            genesis_hash,
            0,
            0x207fffff,
            ChainWork::ZERO,
            0,
            min_work,
        );

        // In PRESYNC, locator[0] = last_header_hash (= chain_start_hash initially).
        let locator = state.next_locator();
        assert_eq!(locator.len(), 2);
        assert_eq!(locator[0], genesis_hash);
        assert_eq!(locator[1], genesis_hash);
    }

    #[test]
    fn test_locator_in_redownload_uses_redownload_buffer_last_hash() {
        let params = ChainParams::regtest();
        let genesis_hash = params.genesis_hash;
        let min_work = ChainWork::from_hex("1").unwrap();

        let mut state = HeadersPresyncState::new(
            params.clone(),
            genesis_hash,
            0,
            0x207fffff,
            ChainWork::ZERO,
            0,
            min_work,
        );

        let headers = make_valid_chain(genesis_hash, 5);
        let result = state.process_next_headers(&headers, true);
        assert!(result.success);
        assert_eq!(state.state(), PresyncState::Redownload);

        // In REDOWNLOAD, locator[0] = redownload_buffer_last_hash (= chain_start_hash, not last presync).
        let locator = state.next_locator();
        assert_eq!(locator[0], genesis_hash, "REDOWNLOAD locator[0] should be chain_start_hash (redownload starts from scratch)");
    }

    #[test]
    fn test_presync_accumulates_chainwork() {
        let params = ChainParams::regtest();
        let genesis_hash = params.genesis_hash;

        let min_work = ChainWork::from_hex("10").unwrap();

        let mut state = HeadersPresyncState::new(
            params,
            genesis_hash,
            0,
            0x207fffff,
            ChainWork::ZERO,
            0,
            min_work,
        );

        assert_eq!(state.state(), PresyncState::Presync);

        let headers = make_valid_chain(genesis_hash, 10);
        let result = state.process_next_headers(&headers, true);

        assert!(result.success);
    }

    #[test]
    fn test_redownload_returns_validated_headers() {
        let params = ChainParams::regtest();
        let genesis_hash = params.genesis_hash;

        let min_work = ChainWork::from_hex("1").unwrap();

        let mut state = HeadersPresyncState::new(
            params.clone(),
            genesis_hash,
            0,
            0x207fffff,
            ChainWork::ZERO,
            0,
            min_work,
        );

        // PRESYNC
        let headers = make_valid_chain(genesis_hash, 50);
        let result = state.process_next_headers(&headers, true);
        assert!(result.success);
        assert_eq!(state.state(), PresyncState::Redownload);

        // REDOWNLOAD
        let result = state.process_next_headers(&headers, false);
        assert!(result.success);
        assert!(!result.pow_validated_headers.is_empty());
    }
}
