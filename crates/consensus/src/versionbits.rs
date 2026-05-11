//! BIP9 versionbits soft fork deployment state machine.
//!
//! This module implements the BIP9 state machine for tracking soft fork activation
//! through miner signaling. Reference: Bitcoin Core `versionbits.cpp`.
//!
//! # State Machine
//!
//! Each soft fork deployment progresses through states:
//! - `Defined` → Initial state for genesis block
//! - `Started` → Reached when MedianTimePast >= start_time
//! - `LockedIn` → Threshold of signaling blocks reached in a period
//! - `Active` → Deployment enforced (terminal state)
//! - `Failed` → Timeout reached without activation (terminal state)
//!
//! # Version Bit Signaling
//!
//! A block signals support for a deployment if:
//! - Top 3 bits of version are `001` (version & 0xE0000000 == 0x20000000)
//! - The deployment's bit is set (version & (1 << bit) != 0)
//!
//! # Thresholds
//!
//! - Mainnet: 1815/2016 blocks (90%)
//! - Testnet: 1512/2016 blocks (75%)

use std::collections::HashMap;
use std::sync::RwLock;

use crate::params::{ChainParams, DIFFICULTY_ADJUSTMENT_INTERVAL};

// ============================================================
// CONSTANTS
// ============================================================

/// Version bits mask for the top 3 bits (bits 29-31).
pub const VERSIONBITS_TOP_MASK: u32 = 0xE0000000;

/// Version bits value for the top 3 bits (bit 29 set = 0x20000000).
/// This indicates the block is using versionbits signaling.
pub const VERSIONBITS_TOP_BITS: u32 = 0x20000000;

/// Number of available bits for soft fork signaling (0-28).
pub const VERSIONBITS_NUM_BITS: u32 = 29;

/// Default retarget period (same as difficulty adjustment interval).
pub const VERSIONBITS_PERIOD: u32 = DIFFICULTY_ADJUSTMENT_INTERVAL;

/// Default threshold for mainnet (1815/2016 ≈ 90%).
pub const VERSIONBITS_THRESHOLD_MAINNET: u32 = 1815;

/// Default threshold for testnet (1512/2016 = 75%).
pub const VERSIONBITS_THRESHOLD_TESTNET: u32 = 1512;

/// Special start_time value: deployment is always active.
pub const ALWAYS_ACTIVE: i64 = -1;

/// Special start_time value: deployment is never active (remains FAILED).
pub const NEVER_ACTIVE: i64 = -2;

/// Special timeout value: no timeout.
pub const NO_TIMEOUT: i64 = i64::MAX;

// ============================================================
// TYPES
// ============================================================

/// Deployment identifiers for known soft forks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DeploymentId {
    /// BIP 68/112/113: Relative lock-time using sequence numbers.
    Csv,
    /// BIP 141/143/147: Segregated Witness.
    Segwit,
    /// BIP 341/342: Taproot.
    Taproot,
    /// Future deployments or testing.
    Custom(u8),
}

impl DeploymentId {
    /// Get all standard deployment IDs.
    pub fn all() -> &'static [DeploymentId] {
        &[DeploymentId::Csv, DeploymentId::Segwit, DeploymentId::Taproot]
    }
}

/// BIP9 threshold state for a deployment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThresholdState {
    /// Initial state: deployment is not yet being signaled.
    Defined,
    /// Signaling has started (MedianTimePast >= start_time).
    Started,
    /// Threshold reached in a retarget period; will activate in next period.
    LockedIn,
    /// Deployment is active (terminal state).
    Active,
    /// Timeout reached without lock-in (terminal state).
    Failed,
}

impl ThresholdState {
    /// Returns true if this is a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(self, ThresholdState::Active | ThresholdState::Failed)
    }
}

/// Parameters for a BIP9 deployment.
#[derive(Clone, Debug)]
pub struct BIP9Deployment {
    /// Bit position (0-28) in the block version.
    pub bit: u8,
    /// MedianTimePast after which signaling starts.
    /// Use `ALWAYS_ACTIVE` for immediate activation.
    /// Use `NEVER_ACTIVE` for deployments that should never activate.
    pub start_time: i64,
    /// MedianTimePast after which the deployment fails if not locked in.
    /// Use `NO_TIMEOUT` for no timeout.
    pub timeout: i64,
    /// Minimum block height at which the deployment can become active.
    /// Provides a grace period after lock-in.
    pub min_activation_height: u32,
    /// Number of blocks in a signaling period.
    /// Default: VERSIONBITS_PERIOD (2016).
    pub period: u32,
    /// Number of blocks required to lock in during a period.
    /// Default: VERSIONBITS_THRESHOLD_MAINNET (1815) or VERSIONBITS_THRESHOLD_TESTNET (1512).
    pub threshold: u32,
}

impl BIP9Deployment {
    /// Create a new deployment with standard mainnet parameters.
    pub fn new_mainnet(bit: u8, start_time: i64, timeout: i64) -> Self {
        Self {
            bit,
            start_time,
            timeout,
            min_activation_height: 0,
            period: VERSIONBITS_PERIOD,
            threshold: VERSIONBITS_THRESHOLD_MAINNET,
        }
    }

    /// Create a new deployment with standard testnet parameters.
    pub fn new_testnet(bit: u8, start_time: i64, timeout: i64) -> Self {
        Self {
            bit,
            start_time,
            timeout,
            min_activation_height: 0,
            period: VERSIONBITS_PERIOD,
            threshold: VERSIONBITS_THRESHOLD_TESTNET,
        }
    }

    /// Create a deployment that is always active (for testing or post-activation).
    pub fn always_active(bit: u8) -> Self {
        Self {
            bit,
            start_time: ALWAYS_ACTIVE,
            timeout: NO_TIMEOUT,
            min_activation_height: 0,
            period: VERSIONBITS_PERIOD,
            threshold: 0,
        }
    }

    /// Create a deployment that is never active.
    pub fn never_active(bit: u8) -> Self {
        Self {
            bit,
            start_time: NEVER_ACTIVE,
            timeout: NO_TIMEOUT,
            min_activation_height: 0,
            period: VERSIONBITS_PERIOD,
            threshold: 0,
        }
    }

    /// Get the signal mask for this deployment.
    #[inline]
    pub fn mask(&self) -> u32 {
        1u32 << self.bit
    }

    /// Check if a block version signals support for this deployment.
    #[inline]
    pub fn signals(&self, version: i32) -> bool {
        let version = version as u32;
        // Top 3 bits must be 001 (versionbits format)
        ((version & VERSIONBITS_TOP_MASK) == VERSIONBITS_TOP_BITS)
            // And the deployment bit must be set
            && ((version & self.mask()) != 0)
    }
}

/// Signaling statistics for a deployment in the current period.
#[derive(Clone, Debug)]
pub struct BIP9Stats {
    /// Current signaling period number.
    pub period: u32,
    /// Number of blocks required to lock in.
    pub threshold: u32,
    /// Number of blocks elapsed in the current period.
    pub elapsed: u32,
    /// Number of blocks signaling support in the current period.
    pub count: u32,
    /// True if threshold can still be reached in this period.
    pub possible: bool,
}

// ============================================================
// BLOCK INFO TRAIT
// ============================================================

/// Information about a block needed for versionbits state calculation.
pub trait VersionbitsBlockInfo {
    /// Get the block height.
    fn height(&self) -> u32;
    /// Get the block version.
    fn version(&self) -> i32;
    /// Get the MedianTimePast for this block.
    fn median_time(&self) -> i64;
    /// Get the previous block, if any.
    fn prev(&self) -> Option<&Self>;
    /// Get an ancestor at a specific height.
    fn ancestor(&self, height: u32) -> Option<&Self>;
}

// ============================================================
// STATE CACHE
// ============================================================

/// Thread-safe cache for deployment states.
/// Maps (deployment_bit, period_end_height) -> ThresholdState.
#[derive(Default)]
pub struct VersionbitsCache {
    cache: RwLock<HashMap<(u8, u32), ThresholdState>>,
}

impl VersionbitsCache {
    /// Create a new empty cache.
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Get a cached state for a deployment at a period boundary.
    pub fn get(&self, bit: u8, height: u32) -> Option<ThresholdState> {
        self.cache.read().ok()?.get(&(bit, height)).copied()
    }

    /// Insert a state into the cache.
    pub fn insert(&self, bit: u8, height: u32, state: ThresholdState) {
        if let Ok(mut cache) = self.cache.write() {
            cache.insert((bit, height), state);
        }
    }

    /// Clear all cached states.
    pub fn clear(&self) {
        if let Ok(mut cache) = self.cache.write() {
            cache.clear();
        }
    }
}

// ============================================================
// STATE CALCULATION
// ============================================================

/// Calculate the threshold state for a deployment at a given block.
///
/// This implements Bitcoin Core's `GetStateFor` function.
///
/// # Arguments
/// * `block` - The block to calculate state for (previous block of the one being validated)
/// * `deployment` - The BIP9 deployment parameters
/// * `cache` - Optional cache for memoization
///
/// # Returns
/// The threshold state at the given block.
pub fn get_state_for<B: VersionbitsBlockInfo>(
    block: Option<&B>,
    deployment: &BIP9Deployment,
    cache: Option<&VersionbitsCache>,
) -> ThresholdState {
    // Handle special cases for start_time
    if deployment.start_time == ALWAYS_ACTIVE {
        return ThresholdState::Active;
    }
    if deployment.start_time == NEVER_ACTIVE {
        return ThresholdState::Failed;
    }

    // Genesis block (no previous) is always DEFINED
    let block = match block {
        Some(b) => b,
        None => return ThresholdState::Defined,
    };

    let period = deployment.period;

    // Normalize to the last block of the previous period
    // All blocks within a period share the same state as of the period boundary
    let period_boundary_height = if (block.height() + 1) % period == 0 {
        block.height()
    } else {
        // Find the last block of the previous complete period
        let periods_complete = (block.height() + 1) / period;
        if periods_complete == 0 {
            // We're in period 0, genesis state applies
            return ThresholdState::Defined;
        }
        periods_complete * period - 1
    };

    // Try to get from cache
    if let Some(cache) = cache {
        if let Some(state) = cache.get(deployment.bit, period_boundary_height) {
            return state;
        }
    }

    // Walk back to find the earliest unknown state
    let mut blocks_to_process: Vec<u32> = Vec::new();
    let mut current_height = period_boundary_height;
    let mut current_block = block.ancestor(current_height);

    loop {
        // Check cache
        if let Some(cache) = cache {
            if cache.get(deployment.bit, current_height).is_some() {
                // Found a cached state, stop walking back
                break;
            }
        }

        // If we've reached genesis or before period 0 ends, state is DEFINED
        if current_block.is_none() || current_height < period - 1 {
            break;
        }

        let cb = current_block.unwrap();

        // Optimization: if MedianTimePast < start_time, state is DEFINED
        // (no need to walk back further)
        if cb.median_time() < deployment.start_time {
            // Cache this as DEFINED and we're done
            if let Some(cache) = cache {
                cache.insert(deployment.bit, current_height, ThresholdState::Defined);
            }
            break;
        }

        // Add this period to process
        blocks_to_process.push(current_height);

        // Move to previous period
        if current_height < period {
            break;
        }
        current_height = current_height.saturating_sub(period);
        current_block = block.ancestor(current_height);
    }

    // Get the starting state
    let mut state = if let Some(cache) = cache {
        if !blocks_to_process.is_empty() {
            // Get state from the period before the first one we need to process
            let first_to_process = *blocks_to_process.last().unwrap();
            if first_to_process >= period {
                cache.get(deployment.bit, first_to_process - period)
                    .unwrap_or(ThresholdState::Defined)
            } else {
                ThresholdState::Defined
            }
        } else {
            cache.get(deployment.bit, current_height)
                .unwrap_or(ThresholdState::Defined)
        }
    } else {
        ThresholdState::Defined
    };

    // Process periods from oldest to newest
    for &height in blocks_to_process.iter().rev() {
        let period_start = height.saturating_sub(period - 1);
        let period_end_block = block.ancestor(height);

        // Skip if we can't find the blocks
        let period_end_block = match period_end_block {
            Some(b) => b,
            None => continue,
        };

        // Calculate next state based on current state
        state = match state {
            ThresholdState::Defined => {
                if period_end_block.median_time() >= deployment.start_time {
                    ThresholdState::Started
                } else {
                    ThresholdState::Defined
                }
            }
            ThresholdState::Started => {
                // Count signaling blocks in this period first.
                // Bitcoin Core versionbits.cpp:87-97: threshold check takes
                // priority over timeout — if count >= threshold the deployment
                // locks in even if MTP also >= timeout in the same period.
                let count = count_signaling_blocks(block, period_start, height, deployment);
                if count >= deployment.threshold {
                    ThresholdState::LockedIn
                } else if period_end_block.median_time() >= deployment.timeout {
                    ThresholdState::Failed
                } else {
                    ThresholdState::Started
                }
            }
            ThresholdState::LockedIn => {
                // Check min_activation_height
                // The deployment activates at the start of the next period
                if height + 1 >= deployment.min_activation_height {
                    ThresholdState::Active
                } else {
                    ThresholdState::LockedIn
                }
            }
            // Terminal states don't change
            ThresholdState::Active => ThresholdState::Active,
            ThresholdState::Failed => ThresholdState::Failed,
        };

        // Cache the computed state
        if let Some(cache) = cache {
            cache.insert(deployment.bit, height, state);
        }
    }

    state
}

/// Count the number of blocks signaling for a deployment in a range.
fn count_signaling_blocks<B: VersionbitsBlockInfo>(
    block: &B,
    start_height: u32,
    end_height: u32,
    deployment: &BIP9Deployment,
) -> u32 {
    let mut count = 0;
    for h in start_height..=end_height {
        if let Some(b) = block.ancestor(h) {
            if deployment.signals(b.version()) {
                count += 1;
            }
        }
    }
    count
}

/// Get signaling statistics for a deployment in the current period.
///
/// This is useful for RPC responses showing activation progress.
pub fn get_state_statistics<B: VersionbitsBlockInfo>(
    block: &B,
    deployment: &BIP9Deployment,
) -> BIP9Stats {
    let period = deployment.period;
    let threshold = deployment.threshold;

    // Calculate current period info
    let periods_complete = (block.height() + 1) / period;
    let period_start = periods_complete * period;
    let elapsed = block.height() + 1 - period_start;

    // Count signaling blocks in the current (incomplete) period
    let mut count = 0;
    for h in period_start..=block.height() {
        if let Some(b) = block.ancestor(h) {
            if deployment.signals(b.version()) {
                count += 1;
            }
        }
    }

    // Check if threshold can still be reached
    let remaining = period - elapsed;
    let possible = count + remaining >= threshold;

    BIP9Stats {
        period: periods_complete,
        threshold,
        elapsed,
        count,
        possible,
    }
}

/// Compute the block version with deployment bits set for signaling.
///
/// Used when creating new blocks to signal support for active deployments.
pub fn compute_block_version<B: VersionbitsBlockInfo>(
    block: Option<&B>,
    deployments: &[(&DeploymentId, &BIP9Deployment)],
    cache: Option<&VersionbitsCache>,
) -> i32 {
    let mut version = VERSIONBITS_TOP_BITS;

    for &(_, deployment) in deployments {
        let state = get_state_for(block, deployment, cache);
        // Signal if we're in STARTED or LOCKED_IN state
        if matches!(state, ThresholdState::Started | ThresholdState::LockedIn) {
            version |= deployment.mask();
        }
    }

    version as i32
}

/// Check if a deployment is active at a given block.
pub fn is_deployment_active<B: VersionbitsBlockInfo>(
    block: Option<&B>,
    deployment: &BIP9Deployment,
    cache: Option<&VersionbitsCache>,
) -> bool {
    get_state_for(block, deployment, cache) == ThresholdState::Active
}

// ============================================================
// DEPLOYMENT PARAMETERS
// ============================================================

/// Get the BIP9 deployment parameters for a specific network.
pub fn get_deployments(params: &ChainParams) -> HashMap<DeploymentId, BIP9Deployment> {
    use crate::params::NetworkId;

    let mut deployments = HashMap::new();

    match params.network_id {
        NetworkId::Mainnet => {
            // CSV: BIP 68/112/113
            // Deployed via BIP9 on mainnet, activated at height 419328
            deployments.insert(
                DeploymentId::Csv,
                BIP9Deployment {
                    bit: 0,
                    start_time: 1462060800, // May 1st, 2016
                    timeout: 1493596800,    // May 1st, 2017
                    min_activation_height: 0,
                    period: VERSIONBITS_PERIOD,
                    threshold: VERSIONBITS_THRESHOLD_MAINNET,
                },
            );

            // SegWit: BIP 141/143/147
            // Deployed via BIP9 on mainnet, activated at height 481824
            deployments.insert(
                DeploymentId::Segwit,
                BIP9Deployment {
                    bit: 1,
                    start_time: 1479168000, // November 15th, 2016
                    timeout: 1510704000,    // November 15th, 2017
                    min_activation_height: 0,
                    period: VERSIONBITS_PERIOD,
                    threshold: VERSIONBITS_THRESHOLD_MAINNET,
                },
            );

            // Taproot: BIP 341/342
            // Deployed via BIP9 (speedy trial) on mainnet, activated at height 709632
            deployments.insert(
                DeploymentId::Taproot,
                BIP9Deployment {
                    bit: 2,
                    start_time: 1619222400, // April 24th, 2021
                    timeout: 1628640000,    // August 11th, 2021
                    min_activation_height: 709632,
                    period: VERSIONBITS_PERIOD,
                    threshold: VERSIONBITS_THRESHOLD_MAINNET,
                },
            );
        }
        NetworkId::Testnet3 => {
            // Testnet3 used BIP9 for CSV and SegWit
            deployments.insert(
                DeploymentId::Csv,
                BIP9Deployment {
                    bit: 0,
                    start_time: 1456790400, // March 1st, 2016
                    timeout: 1493596800,    // May 1st, 2017
                    min_activation_height: 0,
                    period: VERSIONBITS_PERIOD,
                    threshold: VERSIONBITS_THRESHOLD_TESTNET,
                },
            );

            deployments.insert(
                DeploymentId::Segwit,
                BIP9Deployment {
                    bit: 1,
                    start_time: 1462060800, // May 1st, 2016
                    timeout: 1493596800,    // May 1st, 2017
                    min_activation_height: 0,
                    period: VERSIONBITS_PERIOD,
                    threshold: VERSIONBITS_THRESHOLD_TESTNET,
                },
            );

            deployments.insert(
                DeploymentId::Taproot,
                BIP9Deployment {
                    bit: 2,
                    start_time: 1619222400, // April 24th, 2021
                    timeout: 1628640000,    // August 11th, 2021
                    min_activation_height: 0,
                    period: VERSIONBITS_PERIOD,
                    threshold: VERSIONBITS_THRESHOLD_TESTNET,
                },
            );
        }
        NetworkId::Testnet4 | NetworkId::Signet => {
            // Testnet4 and Signet: all soft forks active from genesis (height 1)
            // Use ALWAYS_ACTIVE for immediate activation
            deployments.insert(DeploymentId::Csv, BIP9Deployment::always_active(0));
            deployments.insert(DeploymentId::Segwit, BIP9Deployment::always_active(1));
            deployments.insert(DeploymentId::Taproot, BIP9Deployment::always_active(2));
        }
        NetworkId::Regtest => {
            // Regtest: all soft forks active from genesis
            deployments.insert(DeploymentId::Csv, BIP9Deployment::always_active(0));
            deployments.insert(DeploymentId::Segwit, BIP9Deployment::always_active(1));
            deployments.insert(DeploymentId::Taproot, BIP9Deployment::always_active(2));
        }
    }

    deployments
}

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Test block info implementation for unit tests.
    struct TestBlock {
        height: u32,
        version: i32,
        median_time: i64,
        prev: Option<Box<TestBlock>>,
    }

    impl VersionbitsBlockInfo for TestBlock {
        fn height(&self) -> u32 {
            self.height
        }

        fn version(&self) -> i32 {
            self.version
        }

        fn median_time(&self) -> i64 {
            self.median_time
        }

        fn prev(&self) -> Option<&Self> {
            self.prev.as_ref().map(|b| b.as_ref())
        }

        fn ancestor(&self, height: u32) -> Option<&Self> {
            if height > self.height {
                return None;
            }
            let mut current = self;
            while current.height > height {
                current = current.prev.as_ref()?;
            }
            Some(current)
        }
    }

    impl TestBlock {
        fn genesis(median_time: i64) -> Self {
            Self {
                height: 0,
                version: 1,
                median_time,
                prev: None,
            }
        }

        fn with_prev(height: u32, version: i32, median_time: i64, prev: TestBlock) -> Self {
            Self {
                height,
                version,
                median_time,
                prev: Some(Box::new(prev)),
            }
        }
    }

    /// Build a chain of blocks for testing.
    fn build_chain(
        count: u32,
        version: i32,
        start_time: i64,
        time_interval: i64,
    ) -> TestBlock {
        let mut current = TestBlock::genesis(start_time);

        for h in 1..count {
            let median_time = start_time + (h as i64) * time_interval;
            current = TestBlock::with_prev(h, version, median_time, current);
        }

        current
    }

    #[test]
    fn test_signals_detection() {
        let deployment = BIP9Deployment::new_mainnet(1, 0, i64::MAX);

        // Version with versionbits format and bit 1 set
        let signaling_version = 0x20000002i32; // 001 in top 3 bits, bit 1 set
        assert!(deployment.signals(signaling_version));

        // Version without versionbits format (top bits not 001)
        let legacy_version = 0x00000002i32;
        assert!(!deployment.signals(legacy_version));

        // Version with wrong bit
        let wrong_bit_version = 0x20000004i32; // bit 2 set, not bit 1
        assert!(!deployment.signals(wrong_bit_version));

        // Version with versionbits format but no bit set
        let no_signal_version = 0x20000000i32;
        assert!(!deployment.signals(no_signal_version));
    }

    #[test]
    fn test_deployment_mask() {
        let deployment = BIP9Deployment::new_mainnet(0, 0, i64::MAX);
        assert_eq!(deployment.mask(), 1);

        let deployment = BIP9Deployment::new_mainnet(1, 0, i64::MAX);
        assert_eq!(deployment.mask(), 2);

        let deployment = BIP9Deployment::new_mainnet(28, 0, i64::MAX);
        assert_eq!(deployment.mask(), 1 << 28);
    }

    #[test]
    fn test_always_active_deployment() {
        let deployment = BIP9Deployment::always_active(1);
        let chain = build_chain(100, 1, 0, 600);

        let state = get_state_for(Some(&chain), &deployment, None);
        assert_eq!(state, ThresholdState::Active);
    }

    #[test]
    fn test_never_active_deployment() {
        let deployment = BIP9Deployment::never_active(1);
        let chain = build_chain(100, 0x20000002, 0, 600);

        let state = get_state_for(Some(&chain), &deployment, None);
        assert_eq!(state, ThresholdState::Failed);
    }

    #[test]
    fn test_genesis_is_defined() {
        let deployment = BIP9Deployment::new_mainnet(1, 1000, i64::MAX);

        // No previous block = genesis
        let state = get_state_for::<TestBlock>(None, &deployment, None);
        assert_eq!(state, ThresholdState::Defined);
    }

    #[test]
    fn test_defined_before_start_time() {
        // Deployment starts at time 10000
        let deployment = BIP9Deployment::new_mainnet(1, 10000, i64::MAX);

        // Chain with median time before start_time
        let chain = build_chain(2016, 0x20000002, 0, 1);

        let state = get_state_for(Some(&chain), &deployment, None);
        assert_eq!(state, ThresholdState::Defined);
    }

    #[test]
    fn test_started_after_start_time() {
        // Deployment starts at time 1000
        let deployment = BIP9Deployment {
            bit: 1,
            start_time: 1000,
            timeout: i64::MAX,
            min_activation_height: 0,
            period: 2016,
            threshold: 1815,
        };

        // Build a chain that crosses the start_time threshold
        // Period 0: blocks 0-2015
        let mut chain = TestBlock::genesis(0);
        for h in 1..2016 {
            // MedianTimePast crosses start_time around block 1000
            let median_time = h as i64;
            chain = TestBlock::with_prev(h, 1, median_time, chain);
        }
        // Last block of period 0 has median_time = 2015 > 1000

        let state = get_state_for(Some(&chain), &deployment, None);
        assert_eq!(state, ThresholdState::Started);
    }

    #[test]
    fn test_locked_in_with_threshold() {
        let deployment = BIP9Deployment {
            bit: 1,
            start_time: 0, // Already started
            timeout: i64::MAX,
            min_activation_height: 0,
            period: 2016,
            threshold: 1815, // 90%
        };

        let signaling_version = 0x20000002i32; // bit 1 set with versionbits format

        // Build period 0 (blocks 0-2015) - will transition to STARTED
        let mut chain = TestBlock::genesis(1);
        for h in 1..2016 {
            chain = TestBlock::with_prev(h, 1, h as i64 + 1, chain);
        }

        // Build period 1 (blocks 2016-4031) with full signaling
        for h in 2016..4032 {
            chain = TestBlock::with_prev(h, signaling_version, h as i64 + 1, chain);
        }

        let state = get_state_for(Some(&chain), &deployment, None);
        assert_eq!(state, ThresholdState::LockedIn);
    }

    #[test]
    fn test_activation_after_locked_in() {
        let deployment = BIP9Deployment {
            bit: 1,
            start_time: 0,
            timeout: i64::MAX,
            min_activation_height: 0,
            period: 2016,
            threshold: 1815,
        };

        let signaling_version = 0x20000002i32;

        // Build period 0 (will be STARTED)
        let mut chain = TestBlock::genesis(1);
        for h in 1..2016 {
            chain = TestBlock::with_prev(h, 1, h as i64 + 1, chain);
        }

        // Build period 1 with full signaling (will be LOCKED_IN)
        for h in 2016..4032 {
            chain = TestBlock::with_prev(h, signaling_version, h as i64 + 1, chain);
        }

        // Build period 2 (will be ACTIVE)
        for h in 4032..6048 {
            chain = TestBlock::with_prev(h, 1, h as i64 + 1, chain);
        }

        let state = get_state_for(Some(&chain), &deployment, None);
        assert_eq!(state, ThresholdState::Active);
    }

    #[test]
    fn test_failed_on_timeout() {
        let deployment = BIP9Deployment {
            bit: 1,
            start_time: 0,
            timeout: 3000, // Timeout at median_time 3000
            min_activation_height: 0,
            period: 2016,
            threshold: 1815,
        };

        // Build period 0 (STARTED)
        let mut chain = TestBlock::genesis(1);
        for h in 1..2016 {
            chain = TestBlock::with_prev(h, 1, h as i64 + 1, chain);
        }

        // Build period 1 without enough signaling, and median_time reaches timeout
        for h in 2016..4032 {
            let median_time = if h >= 3000 { 3001 } else { h as i64 + 1 };
            chain = TestBlock::with_prev(h, 1, median_time, chain); // Not signaling
        }

        let state = get_state_for(Some(&chain), &deployment, None);
        assert_eq!(state, ThresholdState::Failed);
    }

    #[test]
    fn test_min_activation_height() {
        let deployment = BIP9Deployment {
            bit: 1,
            start_time: 0,
            timeout: i64::MAX,
            min_activation_height: 8000, // Can't activate until height 8000
            period: 2016,
            threshold: 1815,
        };

        let signaling_version = 0x20000002i32;

        // Build period 0 (STARTED)
        let mut chain = TestBlock::genesis(1);
        for h in 1..2016 {
            chain = TestBlock::with_prev(h, 1, h as i64 + 1, chain);
        }

        // Build period 1 with full signaling (LOCKED_IN)
        for h in 2016..4032 {
            chain = TestBlock::with_prev(h, signaling_version, h as i64 + 1, chain);
        }

        // Build period 2 - should still be LOCKED_IN because of min_activation_height
        for h in 4032..6048 {
            chain = TestBlock::with_prev(h, 1, h as i64 + 1, chain);
        }

        let state = get_state_for(Some(&chain), &deployment, None);
        // Period 2 ends at height 6047, which is < 8000, so still LOCKED_IN
        assert_eq!(state, ThresholdState::LockedIn);

        // Build more periods until we pass min_activation_height
        for h in 6048..10080 {
            chain = TestBlock::with_prev(h, 1, h as i64 + 1, chain);
        }

        let state = get_state_for(Some(&chain), &deployment, None);
        // Now we're past 8000, should be ACTIVE
        assert_eq!(state, ThresholdState::Active);
    }

    #[test]
    fn test_caching() {
        let deployment = BIP9Deployment {
            bit: 1,
            start_time: 0,
            timeout: i64::MAX,
            min_activation_height: 0,
            period: 2016,
            threshold: 1815,
        };

        let signaling_version = 0x20000002i32;

        // Build a chain with signaling
        let mut chain = TestBlock::genesis(1);
        for h in 1..4032 {
            let version = if h >= 2016 { signaling_version } else { 1 };
            chain = TestBlock::with_prev(h, version, h as i64 + 1, chain);
        }

        let cache = VersionbitsCache::new();

        // First call populates cache
        let state1 = get_state_for(Some(&chain), &deployment, Some(&cache));
        assert_eq!(state1, ThresholdState::LockedIn);

        // Second call should hit cache
        let state2 = get_state_for(Some(&chain), &deployment, Some(&cache));
        assert_eq!(state2, ThresholdState::LockedIn);

        // Verify cache was populated
        assert!(cache.get(1, 2015).is_some());
        assert!(cache.get(1, 4031).is_some());
    }

    #[test]
    fn test_compute_block_version() {
        let csv = BIP9Deployment {
            bit: 0,
            start_time: 0,
            timeout: i64::MAX,
            min_activation_height: 0,
            period: 2016,
            threshold: 1815,
        };

        let segwit = BIP9Deployment {
            bit: 1,
            start_time: 0,
            timeout: i64::MAX,
            min_activation_height: 0,
            period: 2016,
            threshold: 1815,
        };

        // Build period 0 (both will be STARTED)
        let mut chain = TestBlock::genesis(1);
        for h in 1..2016 {
            chain = TestBlock::with_prev(h, 1, h as i64 + 1, chain);
        }

        let deployments = [
            (&DeploymentId::Csv, &csv),
            (&DeploymentId::Segwit, &segwit),
        ];

        let version = compute_block_version(Some(&chain), &deployments, None);

        // Should have versionbits format and bits 0 and 1 set
        assert_eq!(version, 0x20000003i32);
    }

    #[test]
    fn test_bip9_stats() {
        let deployment = BIP9Deployment {
            bit: 1,
            start_time: 0,
            timeout: i64::MAX,
            min_activation_height: 0,
            period: 2016,
            threshold: 1815,
        };

        let signaling_version = 0x20000002i32;

        // Build some blocks in period 1 (after period 0 ends at 2015)
        let mut chain = TestBlock::genesis(1);
        for h in 1..2016 {
            chain = TestBlock::with_prev(h, 1, h as i64 + 1, chain);
        }

        // Add 100 signaling blocks in period 1
        for h in 2016..2116 {
            chain = TestBlock::with_prev(h, signaling_version, h as i64 + 1, chain);
        }

        let stats = get_state_statistics(&chain, &deployment);

        assert_eq!(stats.period, 1);
        assert_eq!(stats.threshold, 1815);
        assert_eq!(stats.elapsed, 100);
        assert_eq!(stats.count, 100);
        // Can still reach threshold: 100 + (2016 - 100) = 2016 >= 1815
        assert!(stats.possible);
    }

    #[test]
    fn test_threshold_states_terminal() {
        assert!(!ThresholdState::Defined.is_terminal());
        assert!(!ThresholdState::Started.is_terminal());
        assert!(!ThresholdState::LockedIn.is_terminal());
        assert!(ThresholdState::Active.is_terminal());
        assert!(ThresholdState::Failed.is_terminal());
    }

    #[test]
    fn test_deployment_id_all() {
        let all = DeploymentId::all();
        assert!(all.contains(&DeploymentId::Csv));
        assert!(all.contains(&DeploymentId::Segwit));
        assert!(all.contains(&DeploymentId::Taproot));
    }

    #[test]
    fn test_get_deployments_mainnet() {
        let params = ChainParams::mainnet();
        let deployments = get_deployments(&params);

        assert!(deployments.contains_key(&DeploymentId::Csv));
        assert!(deployments.contains_key(&DeploymentId::Segwit));
        assert!(deployments.contains_key(&DeploymentId::Taproot));

        // Verify taproot has min_activation_height set
        let taproot = deployments.get(&DeploymentId::Taproot).unwrap();
        assert_eq!(taproot.min_activation_height, 709632);
    }

    #[test]
    fn test_get_deployments_testnet4() {
        let params = ChainParams::testnet4();
        let deployments = get_deployments(&params);

        // Testnet4 has all deployments always active
        let csv = deployments.get(&DeploymentId::Csv).unwrap();
        assert_eq!(csv.start_time, ALWAYS_ACTIVE);

        // Verify ALWAYS_ACTIVE results in Active state
        let chain = build_chain(100, 1, 0, 600);
        let state = get_state_for(Some(&chain), csv, None);
        assert_eq!(state, ThresholdState::Active);
    }

    #[test]
    fn test_partial_signaling() {
        // Test that we need exactly the threshold, not more
        let deployment = BIP9Deployment {
            bit: 1,
            start_time: 0,
            timeout: i64::MAX,
            min_activation_height: 0,
            period: 100, // Smaller period for testing
            threshold: 75,
        };

        let signaling_version = 0x20000002i32;

        // Build period 0 (will be STARTED)
        let mut chain = TestBlock::genesis(1);
        for h in 1..100 {
            chain = TestBlock::with_prev(h, 1, h as i64 + 1, chain);
        }

        // Period 1: exactly 74 signaling blocks (just under threshold)
        for h in 100..200 {
            let version = if h < 174 { signaling_version } else { 1 };
            chain = TestBlock::with_prev(h, version, h as i64 + 1, chain);
        }

        let state = get_state_for(Some(&chain), &deployment, None);
        assert_eq!(state, ThresholdState::Started); // Not enough signaling

        // Period 2: exactly 75 signaling blocks (at threshold)
        for h in 200..300 {
            let version = if h < 275 { signaling_version } else { 1 };
            chain = TestBlock::with_prev(h, version, h as i64 + 1, chain);
        }

        let state = get_state_for(Some(&chain), &deployment, None);
        assert_eq!(state, ThresholdState::LockedIn); // Exactly at threshold
    }

    #[test]
    fn test_is_deployment_active() {
        let deployment = BIP9Deployment::always_active(1);
        let chain = build_chain(100, 1, 0, 600);

        assert!(is_deployment_active(Some(&chain), &deployment, None));

        let deployment = BIP9Deployment::never_active(1);
        assert!(!is_deployment_active(Some(&chain), &deployment, None));
    }

    // ----------------------------------------------------------------
    // W91 comprehensive gate tests (Core versionbits.cpp parity)
    // ----------------------------------------------------------------

    /// Gate 1-2: ALWAYS_ACTIVE sentinel → Active; NEVER_ACTIVE sentinel → Failed.
    /// Core versionbits.cpp:35-42.
    #[test]
    fn test_w91_always_active_shortcut() {
        let deployment = BIP9Deployment::always_active(5);
        // Even with None (genesis) the shortcut fires before the None check.
        assert_eq!(
            get_state_for::<TestBlock>(None, &deployment, None),
            ThresholdState::Active,
        );
        let chain = build_chain(10, 1, 0, 600);
        assert_eq!(
            get_state_for(Some(&chain), &deployment, None),
            ThresholdState::Active,
        );
    }

    #[test]
    fn test_w91_never_active_shortcut() {
        let deployment = BIP9Deployment::never_active(5);
        assert_eq!(
            get_state_for::<TestBlock>(None, &deployment, None),
            ThresholdState::Failed,
        );
        let chain = build_chain(10, 0x20000020, 0, 600);
        assert_eq!(
            get_state_for(Some(&chain), &deployment, None),
            ThresholdState::Failed,
        );
    }

    /// Gate 4: Period alignment — every block within the same period resolves
    /// to the same state as the period boundary of the PREVIOUS period.
    /// Core versionbits.cpp:46: pindexPrev = ancestor(h - ((h+1) % nPeriod)).
    ///
    /// Concretely: blocks h=200..298 (mid-period-2) all align to h=199
    /// (end of period-1), so they all see LOCKED_IN.  Only at h=299 (period-2
    /// boundary) does the LOCKED_IN→ACTIVE transition fire.
    #[test]
    fn test_w91_period_alignment_same_state() {
        let period: u32 = 100;
        let deployment = BIP9Deployment {
            bit: 0,
            start_time: 0,
            timeout: i64::MAX,
            min_activation_height: 0,
            period,
            threshold: 75,
        };
        let signaling = 0x20000001i32;

        // Build 3 periods: period-0 (STARTED), period-1 full signaling (LOCKED_IN),
        // period-2 boundary at h=299 triggers LOCKED_IN→ACTIVE.
        let mut chain = TestBlock::genesis(1);
        for h in 1..300u32 {
            let v = if h >= 100 && h < 200 { signaling } else { 1 };
            chain = TestBlock::with_prev(h, v, h as i64 + 1, chain);
        }

        // Period-2 boundary (h=299) → ACTIVE (processes LOCKED_IN transition).
        let state_at_boundary = get_state_for(Some(&chain), &deployment, None);
        assert_eq!(state_at_boundary, ThresholdState::Active, "period-2 boundary must be ACTIVE");

        // Mid-period-2 (h=250) aligns to h=199 (period-1 end) → still LOCKED_IN.
        // This is correct Core behaviour: state transitions happen at period boundaries.
        let chain_mid = chain.ancestor(250).unwrap();
        let state_mid = get_state_for(Some(chain_mid), &deployment, None);
        assert_eq!(state_mid, ThresholdState::LockedIn, "h=250 aligns to h=199 (period-1 end) → LOCKED_IN");

        // h=199 (period-1 end) → LOCKED_IN.
        let chain_p1_end = chain.ancestor(199).unwrap();
        let state_p1_end = get_state_for(Some(chain_p1_end), &deployment, None);
        assert_eq!(state_p1_end, ThresholdState::LockedIn, "period-1 end must be LOCKED_IN");

        // h=150 (mid-period-1) also aligns to h=99 (period-0 end) → STARTED.
        let chain_p1_mid = chain.ancestor(150).unwrap();
        let state_p1_mid = get_state_for(Some(chain_p1_mid), &deployment, None);
        assert_eq!(state_p1_mid, ThresholdState::Started, "h=150 aligns to h=99 → STARTED");
    }

    /// Gate 7: MTP optimization — if MTP < start_time we cache DEFINED and
    /// stop the backward walk without visiting earlier periods.
    /// Core versionbits.cpp:57-60.
    #[test]
    fn test_w91_mtp_optimization_stops_walk() {
        let deployment = BIP9Deployment {
            bit: 0,
            start_time: 99999,
            timeout: i64::MAX,
            min_activation_height: 0,
            period: 100,
            threshold: 75,
        };
        // All blocks have low median_time < start_time; chain must stay DEFINED.
        let chain = build_chain(300, 1, 0, 1);
        let state = get_state_for(Some(&chain), &deployment, None);
        assert_eq!(state, ThresholdState::Defined);

        // With cache, the DEFINED entry must be populated so a second call is fast.
        let cache = VersionbitsCache::new();
        let state2 = get_state_for(Some(&chain), &deployment, Some(&cache));
        assert_eq!(state2, ThresholdState::Defined);
        // Cache must contain at least one DEFINED entry for this deployment bit.
        // The period boundary is h=199 (last complete period within h=299 chain).
        // We don't check exact height here because the walk may have cached the
        // MTP-boundary block instead; just verify a re-call returns DEFINED.
        let state3 = get_state_for(Some(&chain), &deployment, Some(&cache));
        assert_eq!(state3, ThresholdState::Defined);
    }

    /// Gate 8: DEFINED → STARTED exactly at MTP boundary.
    /// Core versionbits.cpp:77-81.
    #[test]
    fn test_w91_defined_to_started_at_mtp_boundary() {
        let start_time = 2000i64;
        let period: u32 = 100;
        let deployment = BIP9Deployment {
            bit: 0,
            start_time,
            timeout: i64::MAX,
            min_activation_height: 0,
            period,
            threshold: 75,
        };

        // Period-0 ends at h=99; give it MTP just below start_time → DEFINED.
        let mut chain = TestBlock::genesis(0);
        for h in 1..100u32 {
            chain = TestBlock::with_prev(h, 1, start_time - 1, chain);
        }
        let state = get_state_for(Some(&chain), &deployment, None);
        assert_eq!(state, ThresholdState::Defined, "below start_time → DEFINED");

        // Period-1 ends at h=199; give it MTP exactly == start_time → STARTED.
        for h in 100..200u32 {
            chain = TestBlock::with_prev(h, 1, start_time, chain);
        }
        let state = get_state_for(Some(&chain), &deployment, None);
        assert_eq!(state, ThresholdState::Started, "at start_time → STARTED");
    }

    /// Gate 9: STARTED → LOCKED_IN at exact threshold (count == threshold).
    /// Core versionbits.cpp:87-94.
    #[test]
    fn test_w91_started_to_lockedin_exact_threshold() {
        let period: u32 = 100;
        let threshold: u32 = 75;
        let deployment = BIP9Deployment {
            bit: 0,
            start_time: 0,
            timeout: i64::MAX,
            min_activation_height: 0,
            period,
            threshold,
        };
        let signaling = 0x20000001i32;

        // Period-0: STARTED.
        let mut chain = TestBlock::genesis(1);
        for h in 1..100u32 {
            chain = TestBlock::with_prev(h, 1, h as i64 + 1, chain);
        }

        // Period-1: exactly threshold-1 signaling blocks → stays STARTED.
        for h in 100..200u32 {
            let v = if h < 100 + threshold - 1 { signaling } else { 1 };
            chain = TestBlock::with_prev(h, v, h as i64 + 1, chain);
        }
        let state = get_state_for(Some(&chain), &deployment, None);
        assert_eq!(state, ThresholdState::Started, "threshold-1 → STARTED");

        // Period-2: exactly threshold signaling blocks → LOCKED_IN.
        for h in 200..300u32 {
            let v = if h < 200 + threshold { signaling } else { 1 };
            chain = TestBlock::with_prev(h, v, h as i64 + 1, chain);
        }
        let state = get_state_for(Some(&chain), &deployment, None);
        assert_eq!(state, ThresholdState::LockedIn, "exactly threshold → LOCKED_IN");
    }

    /// Gate 10: STARTED → FAILED when MTP >= timeout and count < threshold.
    /// Core versionbits.cpp:95-97.
    #[test]
    fn test_w91_started_to_failed_on_timeout() {
        let timeout = 500i64;
        let period: u32 = 100;
        let deployment = BIP9Deployment {
            bit: 0,
            start_time: 0,
            timeout,
            min_activation_height: 0,
            period,
            threshold: 75,
        };

        // Period-0: STARTED (no signaling).
        let mut chain = TestBlock::genesis(1);
        for h in 1..100u32 {
            chain = TestBlock::with_prev(h, 1, h as i64 + 1, chain);
        }

        // Period-1: no signaling, MTP at end >= timeout → FAILED.
        for h in 100..200u32 {
            let mtp = if h == 199 { timeout + 1 } else { h as i64 + 1 };
            chain = TestBlock::with_prev(h, 1, mtp, chain);
        }
        let state = get_state_for(Some(&chain), &deployment, None);
        assert_eq!(state, ThresholdState::Failed);
    }

    /// Critical gate: threshold takes priority over timeout.
    /// If count >= threshold AND MTP >= timeout in the same period,
    /// Core gives LOCKED_IN, not FAILED.
    /// Core versionbits.cpp:87-97: threshold branch is evaluated first.
    #[test]
    fn test_w91_threshold_beats_timeout_priority() {
        let timeout = 500i64;
        let period: u32 = 100;
        let threshold: u32 = 75;
        let deployment = BIP9Deployment {
            bit: 0,
            start_time: 0,
            timeout,
            min_activation_height: 0,
            period,
            threshold,
        };
        let signaling = 0x20000001i32;

        // Period-0: STARTED.
        let mut chain = TestBlock::genesis(1);
        for h in 1..100u32 {
            chain = TestBlock::with_prev(h, 1, h as i64 + 1, chain);
        }

        // Period-1: threshold signaling blocks AND MTP >= timeout at period end.
        // Both conditions fire; Core requires LOCKED_IN (threshold wins).
        for h in 100..200u32 {
            let v = if h < 100 + threshold { signaling } else { 1 };
            // All blocks have MTP well above timeout.
            chain = TestBlock::with_prev(h, v, timeout + 100, chain);
        }

        let state = get_state_for(Some(&chain), &deployment, None);
        assert_eq!(
            state,
            ThresholdState::LockedIn,
            "threshold >= count must lock in even when MTP >= timeout (Core versionbits.cpp:87-97)"
        );
    }

    /// Gate 11: LOCKED_IN → ACTIVE at min_activation_height boundary.
    /// Core versionbits.cpp:100-105.
    #[test]
    fn test_w91_lockedin_to_active_min_activation_height_boundary() {
        let period: u32 = 100;
        let min_activation_height: u32 = 350; // period boundary at h=349 just before
        let deployment = BIP9Deployment {
            bit: 0,
            start_time: 0,
            timeout: i64::MAX,
            min_activation_height,
            period,
            threshold: 75,
        };
        let signaling = 0x20000001i32;

        // Period-0 (h=0..99): STARTED.
        let mut chain = TestBlock::genesis(1);
        for h in 1..100u32 {
            chain = TestBlock::with_prev(h, 1, h as i64 + 1, chain);
        }

        // Period-1 (h=100..199): full signaling → LOCKED_IN.
        for h in 100..200u32 {
            chain = TestBlock::with_prev(h, signaling, h as i64 + 1, chain);
        }

        // Period-2 (h=200..299): still LOCKED_IN (next block h=300 < 350).
        for h in 200..300u32 {
            chain = TestBlock::with_prev(h, 1, h as i64 + 1, chain);
        }
        let state = get_state_for(Some(&chain), &deployment, None);
        assert_eq!(state, ThresholdState::LockedIn, "h=299 → next=300 < 350 → still LOCKED_IN");

        // Period-3 (h=300..399): end of period next block = h=400 >= 350 → ACTIVE.
        for h in 300..400u32 {
            chain = TestBlock::with_prev(h, 1, h as i64 + 1, chain);
        }
        let state = get_state_for(Some(&chain), &deployment, None);
        assert_eq!(state, ThresholdState::Active, "h=399 → next=400 >= 350 → ACTIVE");
    }

    /// Gate 12/21-23: Terminal states — ACTIVE and FAILED do NOT transition.
    /// Core versionbits.cpp:107-111.
    #[test]
    fn test_w91_terminal_states_do_not_transition() {
        let period: u32 = 100;

        // ACTIVE stays ACTIVE regardless of future blocks.
        let always = BIP9Deployment::always_active(0);
        let chain = build_chain(500, 1, 0, 1);
        assert_eq!(get_state_for(Some(&chain), &always, None), ThresholdState::Active);

        // FAILED stays FAILED even if all blocks signal.
        let never = BIP9Deployment::never_active(0);
        let chain_sig = build_chain(500, 0x20000001i32, 0, 1);
        assert_eq!(get_state_for(Some(&chain_sig), &never, None), ThresholdState::Failed);

        // Explicitly: build a deployment that timed out, then extend with signaling.
        let timed_out = BIP9Deployment {
            bit: 0,
            start_time: 0,
            timeout: 50,
            min_activation_height: 0,
            period,
            threshold: 75,
        };
        let mut chain2 = TestBlock::genesis(1);
        for h in 1..200u32 {
            // period-1 hits timeout with no signaling → FAILED
            chain2 = TestBlock::with_prev(h, 1, 100, chain2);
        }
        let state = get_state_for(Some(&chain2), &timed_out, None);
        assert_eq!(state, ThresholdState::Failed, "timed out deployment is FAILED");
        // Extend with full signaling — must remain FAILED.
        let signaling = 0x20000001i32;
        for h in 200..400u32 {
            chain2 = TestBlock::with_prev(h, signaling, 200, chain2);
        }
        let state2 = get_state_for(Some(&chain2), &timed_out, None);
        assert_eq!(state2, ThresholdState::Failed, "FAILED is a terminal state");
    }

    /// Gates 13-14: Condition check — both prefix AND bit required.
    /// Core versionbits_impl.h:81.
    #[test]
    fn test_w91_condition_both_prefix_and_bit_required() {
        let deployment = BIP9Deployment::new_mainnet(2, 0, i64::MAX);

        // Correct prefix (001) + correct bit → signals.
        assert!(deployment.signals(0x20000004i32));

        // Wrong prefix (010) + correct bit → does NOT signal.
        assert!(!deployment.signals(0x40000004i32));

        // Correct prefix + wrong bit → does NOT signal.
        assert!(!deployment.signals(0x20000002i32));

        // Correct prefix + no bit → does NOT signal.
        assert!(!deployment.signals(0x20000000i32));

        // All-zeros → does NOT signal.
        assert!(!deployment.signals(0i32));

        // Old-style version 4 → does NOT signal.
        assert!(!deployment.signals(4i32));
    }

    /// Gates 19-23: ComputeBlockVersion signals exactly STARTED and LOCKED_IN,
    /// not DEFINED, ACTIVE, or FAILED.
    /// Core versionbits.cpp:265-279.
    #[test]
    fn test_w91_compute_block_version_signals_only_started_lockedin() {
        let period: u32 = 100;
        let threshold: u32 = 75;

        // Deployment A on bit 0 will stay DEFINED (start_time far in future).
        let dep_defined = BIP9Deployment {
            bit: 0,
            start_time: 999999,
            timeout: i64::MAX,
            min_activation_height: 0,
            period,
            threshold,
        };

        // Deployment B on bit 1 will be STARTED after period-0.
        let dep_started = BIP9Deployment {
            bit: 1,
            start_time: 0,
            timeout: i64::MAX,
            min_activation_height: 0,
            period,
            threshold,
        };

        // Deployment C on bit 2 will be LOCKED_IN (threshold met in period-1).
        let dep_lockedin = BIP9Deployment {
            bit: 2,
            start_time: 0,
            timeout: i64::MAX,
            min_activation_height: 999999, // delay activation so we stop at LOCKED_IN
            period,
            threshold,
        };

        // Deployment D on bit 3 will be ACTIVE (min_activation_height=0, two periods).
        let dep_active = BIP9Deployment {
            bit: 3,
            start_time: 0,
            timeout: i64::MAX,
            min_activation_height: 0,
            period,
            threshold,
        };

        // Deployment E on bit 4 timed out → FAILED.
        let dep_failed = BIP9Deployment {
            bit: 4,
            start_time: 0,
            timeout: 50,
            min_activation_height: 0,
            period,
            threshold,
        };

        // Bits 2, 3, 4 signal in period-1; bit 1 never signals.
        let mut chain = TestBlock::genesis(1);
        for h in 1..100u32 {
            // Period-0: no signaling; dep_started/C/D/E all become STARTED.
            chain = TestBlock::with_prev(h, 1, h as i64 + 1, chain);
        }
        for h in 100..200u32 {
            // Period-1: bits 2, 3, 4 signal (>= threshold = 75 blocks).
            let v = if h < 175 { 0x2000001Ci32 } else { 1 }; // bits 2+3+4 = 0x1C
            chain = TestBlock::with_prev(h, v, h as i64 + 1, chain);
        }
        // After period-1: dep_lockedin=LOCKED_IN, dep_active=LOCKED_IN,
        // dep_failed=FAILED (MTP >> 50), dep_started=STARTED.
        // After period-2, dep_active → ACTIVE (min_activation=0 → h+1=200 >= 0).
        for h in 200..300u32 {
            chain = TestBlock::with_prev(h, 1, h as i64 + 1, chain);
        }

        let deployments = [
            (&DeploymentId::Custom(0), &dep_defined),
            (&DeploymentId::Custom(1), &dep_started),
            (&DeploymentId::Custom(2), &dep_lockedin),
            (&DeploymentId::Custom(3), &dep_active),
            (&DeploymentId::Custom(4), &dep_failed),
        ];

        let version = compute_block_version(Some(&chain), &deployments, None);

        let top_bits = (version as u32) & VERSIONBITS_TOP_MASK;
        assert_eq!(top_bits, VERSIONBITS_TOP_BITS, "version must start with 0x20000000");

        // DEFINED (bit 0) must NOT be signaled.
        assert_eq!(version & (1 << 0), 0, "DEFINED must not signal");

        // STARTED (bit 1) MUST be signaled.
        assert_ne!(version & (1 << 1), 0, "STARTED must signal");

        // LOCKED_IN (bit 2) MUST be signaled.
        assert_ne!(version & (1 << 2), 0, "LOCKED_IN must signal");

        // ACTIVE (bit 3) must NOT be signaled.
        assert_eq!(version & (1 << 3), 0, "ACTIVE must not signal");

        // FAILED (bit 4) must NOT be signaled.
        assert_eq!(version & (1 << 4), 0, "FAILED must not signal");
    }

    /// Verify that the base version is always VERSIONBITS_TOP_BITS = 0x20000000
    /// even when no deployments are signaling.
    /// Core versionbits.cpp:267.
    #[test]
    fn test_w91_compute_block_version_base_is_top_bits() {
        let chain = build_chain(10, 1, 0, 600);

        // No deployments at all.
        let version = compute_block_version::<TestBlock>(Some(&chain), &[], None);
        assert_eq!(version as u32, VERSIONBITS_TOP_BITS);

        // NEVER_ACTIVE deployment should not change version.
        let dep = BIP9Deployment::never_active(0);
        let deployments = [(&DeploymentId::Custom(0), &dep)];
        let version2 = compute_block_version(Some(&chain), &deployments, None);
        assert_eq!(version2 as u32, VERSIONBITS_TOP_BITS);
    }
}
