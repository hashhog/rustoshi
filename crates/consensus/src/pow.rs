//! Proof of work and difficulty adjustment.
//!
//! This module implements Bitcoin's difficulty adjustment algorithm per the
//! Bitcoin Core reference implementation (`pow.cpp`).
//!
//! # Difficulty Adjustment Rules
//!
//! - **Mainnet**: Every 2016 blocks, retarget based on actual timespan clamped
//!   to [target_timespan/4, target_timespan*4].
//!
//! - **Testnet3/4 (min-difficulty rule)**: If a block's timestamp is >20 minutes
//!   after the previous block, allow minimum difficulty. Otherwise, walk back
//!   through the chain to find the last non-minimum-difficulty block.
//!
//! - **Testnet4/BIP94 (time warp fix)**: When retargeting, use the difficulty
//!   from the *first* block of the period instead of the last block, preventing
//!   the time warp attack where difficulty can be artificially lowered.
//!
//! - **Regtest**: Always return the current difficulty (no retargeting).

use crate::params::{
    compact_to_target, target_to_compact, ChainParams, DIFFICULTY_ADJUSTMENT_INTERVAL,
    MIN_TIMESPAN, MAX_TIMESPAN, TARGET_BLOCK_TIME, TARGET_TIMESPAN,
};

/// Information about a block in the chain, used for difficulty calculations.
/// This trait abstracts over the block index implementation.
pub trait BlockIndex {
    /// Get the block height.
    fn height(&self) -> u32;
    /// Get the block timestamp.
    fn timestamp(&self) -> u32;
    /// Get the compact difficulty target (bits field).
    fn bits(&self) -> u32;
    /// Get the previous block in the chain, if any.
    fn prev(&self) -> Option<&Self>;
    /// Get an ancestor at a specific height.
    fn ancestor(&self, height: u32) -> Option<&Self>;
}

/// Calculate the next required work (difficulty target) for a new block.
///
/// This implements Bitcoin Core's `GetNextWorkRequired` function.
///
/// # Arguments
/// * `last` - The block index of the previous block (tip)
/// * `new_block_time` - Timestamp of the block being validated (for testnet min-diff check)
/// * `params` - Chain parameters
///
/// # Returns
/// The compact target (bits) value for the next block.
pub fn get_next_work_required<I: BlockIndex>(
    last: &I,
    new_block_time: u32,
    params: &ChainParams,
) -> u32 {
    let pow_limit_compact = target_to_compact(&params.pow_limit);
    let next_height = last.height() + 1;

    // Only change difficulty once per adjustment interval
    if next_height % DIFFICULTY_ADJUSTMENT_INTERVAL != 0 {
        // Special testnet rules: allow min-difficulty blocks
        if params.pow_allow_min_difficulty_blocks {
            // If the new block's timestamp is more than 2 * TARGET_BLOCK_TIME (20 minutes)
            // after the previous block, allow min-difficulty
            if new_block_time > last.timestamp() + TARGET_BLOCK_TIME * 2 {
                return pow_limit_compact;
            }

            // Otherwise, walk back to find the last non-special-min-difficulty block
            return get_last_non_min_difficulty_bits(last, pow_limit_compact, params);
        }

        // Normal case: return the previous block's difficulty
        return last.bits();
    }

    // At a retarget boundary: calculate new difficulty
    // Go back by 2015 blocks (not 2016, because we want the time difference
    // between block N-2016 and block N-1, which spans 2015 intervals)
    let first_height = next_height.saturating_sub(DIFFICULTY_ADJUSTMENT_INTERVAL);
    let first = last
        .ancestor(first_height)
        .expect("ancestor must exist at retarget boundary");

    calculate_next_work_required(last, first.timestamp(), params)
}

/// Walk back through the chain to find the last block that doesn't use
/// minimum difficulty (for testnet).
fn get_last_non_min_difficulty_bits<I: BlockIndex>(
    last: &I,
    pow_limit_compact: u32,
    _params: &ChainParams,
) -> u32 {
    let mut current = last;

    // Walk back while:
    // 1. We have a previous block
    // 2. We're not at a retarget boundary (height % 2016 != 0)
    // 3. The current block uses minimum difficulty
    while let Some(prev) = current.prev() {
        // Stop at retarget boundaries
        if current.height() % DIFFICULTY_ADJUSTMENT_INTERVAL == 0 {
            break;
        }
        // Stop if this block doesn't use minimum difficulty
        if current.bits() != pow_limit_compact {
            break;
        }
        current = prev;
    }

    current.bits()
}

/// Calculate the next work required at a retarget boundary.
///
/// This implements Bitcoin Core's `CalculateNextWorkRequired` function.
///
/// # Arguments
/// * `last` - The last block of the current period
/// * `first_block_time` - Timestamp of the first block in the current period
/// * `params` - Chain parameters
///
/// # Returns
/// The new compact target (bits) value.
pub fn calculate_next_work_required<I: BlockIndex>(
    last: &I,
    first_block_time: u32,
    params: &ChainParams,
) -> u32 {
    // Regtest: no retargeting
    if params.pow_no_retargeting {
        return last.bits();
    }

    // Calculate actual timespan and clamp to [MIN_TIMESPAN, MAX_TIMESPAN]
    let actual_timespan = last
        .timestamp()
        .saturating_sub(first_block_time)
        .clamp(MIN_TIMESPAN, MAX_TIMESPAN);

    // BIP94 (testnet4): Use the first block of the period for the base difficulty
    // instead of the last block. This prevents the time warp attack.
    let base_bits = if params.enforce_bip94 {
        // Get the first block of this difficulty period
        let first_height = last.height().saturating_sub(DIFFICULTY_ADJUSTMENT_INTERVAL - 1);
        let first_block = last
            .ancestor(first_height)
            .expect("ancestor must exist for BIP94 calculation");
        first_block.bits()
    } else {
        last.bits()
    };

    // Calculate: new_target = current_target * actual_timespan / TARGET_TIMESPAN
    calculate_retarget(base_bits, actual_timespan, TARGET_TIMESPAN, &params.pow_limit)
}

/// Perform the actual retarget calculation.
///
/// new_target = current_target * actual_timespan / target_timespan
/// Clamped to not exceed pow_limit.
fn calculate_retarget(
    current_bits: u32,
    actual_timespan: u32,
    target_timespan: u32,
    pow_limit: &[u8; 32],
) -> u32 {
    let current_target = compact_to_target(current_bits);

    // Compute new_target = current_target * actual_timespan / target_timespan
    let new_target = multiply_target_by_ratio(&current_target, actual_timespan, target_timespan);

    // Clamp to pow_limit
    let clamped = if compare_targets(&new_target, pow_limit) > 0 {
        *pow_limit
    } else {
        new_target
    };

    target_to_compact(&clamped)
}

/// Multiply a 256-bit target by a ratio (numerator/denominator).
/// Result = target * numerator / denominator
fn multiply_target_by_ratio(target: &[u8; 32], numerator: u32, denominator: u32) -> [u8; 32] {
    // Use 512 bits to handle overflow during multiplication
    let mut result = [0u64; 8];

    // Load target into the lower 4 words (big-endian)
    for i in 0..4 {
        let offset = i * 8;
        let mut word = 0u64;
        for j in 0..8 {
            word = (word << 8) | (target[offset + j] as u64);
        }
        result[4 + i] = word;
    }

    // Multiply by numerator
    let mut carry = 0u128;
    for word in result.iter_mut().rev() {
        let product = (*word as u128) * (numerator as u128) + carry;
        *word = product as u64;
        carry = product >> 64;
    }

    // Divide by denominator
    let mut remainder = 0u128;
    for word in result.iter_mut() {
        let dividend = (remainder << 64) | (*word as u128);
        *word = (dividend / denominator as u128) as u64;
        remainder = dividend % denominator as u128;
    }

    // Extract lower 256 bits
    let mut output = [0u8; 32];
    for i in 0..4 {
        let word = result[4 + i];
        let offset = i * 8;
        for j in 0..8 {
            output[offset + j] = ((word >> (56 - j * 8)) & 0xff) as u8;
        }
    }

    output
}

/// Compare two 256-bit targets (big-endian).
/// Returns: negative if a < b, 0 if a == b, positive if a > b
fn compare_targets(a: &[u8; 32], b: &[u8; 32]) -> i32 {
    for i in 0..32 {
        if a[i] < b[i] {
            return -1;
        }
        if a[i] > b[i] {
            return 1;
        }
    }
    0
}

/// Check that a difficulty transition is valid.
///
/// This implements Bitcoin Core's `PermittedDifficultyTransition` function.
/// Used for assumeutxo validation and header-first sync.
///
/// # Arguments
/// * `height` - The height of the new block
/// * `old_bits` - The compact target of the previous retarget
/// * `new_bits` - The compact target of the new block
/// * `params` - Chain parameters
///
/// # Returns
/// `true` if the transition is valid, `false` otherwise.
pub fn permitted_difficulty_transition(
    height: u32,
    old_bits: u32,
    new_bits: u32,
    params: &ChainParams,
) -> bool {
    // Testnet allows arbitrary transitions
    if params.pow_allow_min_difficulty_blocks {
        return true;
    }

    if height % DIFFICULTY_ADJUSTMENT_INTERVAL == 0 {
        // At retarget: verify the new difficulty is within bounds
        let pow_limit = &params.pow_limit;

        // Calculate the largest allowed target (easiest difficulty)
        let largest = calculate_retarget(old_bits, MAX_TIMESPAN, TARGET_TIMESPAN, pow_limit);

        // Calculate the smallest allowed target (hardest difficulty)
        let smallest = calculate_retarget(old_bits, MIN_TIMESPAN, TARGET_TIMESPAN, pow_limit);

        let new_target = compact_to_target(new_bits);
        let largest_target = compact_to_target(largest);
        let smallest_target = compact_to_target(smallest);

        // new_bits must be between smallest and largest
        if compare_targets(&new_target, &largest_target) > 0 {
            return false;
        }
        if compare_targets(&new_target, &smallest_target) < 0 {
            return false;
        }
    } else {
        // Not at retarget: difficulty must not change
        if old_bits != new_bits {
            return false;
        }
    }

    true
}

/// Check that a block's proof of work is valid.
///
/// # Arguments
/// * `block_hash` - The block hash (as big-endian bytes)
/// * `bits` - The compact difficulty target from the block header
/// * `params` - Chain parameters
///
/// # Returns
/// `true` if the proof of work is valid, `false` otherwise.
pub fn check_proof_of_work(block_hash: &[u8; 32], bits: u32, params: &ChainParams) -> bool {
    // Decode target from bits
    let target = compact_to_target(bits);

    // Verify the target is valid (not negative, not zero, not above pow_limit)
    if target == [0u8; 32] {
        return false;
    }
    if compare_targets(&target, &params.pow_limit) > 0 {
        return false;
    }

    // Block hash must be <= target
    // Note: block_hash is already in the correct byte order for comparison
    compare_targets(block_hash, &target) <= 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::compact_to_target;

    /// Simple in-memory block index for testing
    struct TestBlockIndex {
        height: u32,
        timestamp: u32,
        bits: u32,
        prev: Option<Box<TestBlockIndex>>,
    }

    impl BlockIndex for TestBlockIndex {
        fn height(&self) -> u32 {
            self.height
        }

        fn timestamp(&self) -> u32 {
            self.timestamp
        }

        fn bits(&self) -> u32 {
            self.bits
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

    impl TestBlockIndex {
        fn genesis(bits: u32) -> Self {
            Self {
                height: 0,
                timestamp: 1231006505,
                bits,
                prev: None,
            }
        }

        fn with_prev(height: u32, timestamp: u32, bits: u32, prev: TestBlockIndex) -> Self {
            Self {
                height,
                timestamp,
                bits,
                prev: Some(Box::new(prev)),
            }
        }
    }

    /// Build a chain of blocks for testing
    fn build_chain(
        start_height: u32,
        count: u32,
        start_time: u32,
        time_interval: u32,
        bits: u32,
    ) -> TestBlockIndex {
        let mut current = TestBlockIndex::genesis(bits);
        current.timestamp = start_time;

        for h in 1..=count {
            let height = start_height + h;
            let timestamp = start_time + h * time_interval;
            current = TestBlockIndex::with_prev(height, timestamp, bits, current);
        }

        current
    }

    #[test]
    fn test_regtest_no_retargeting() {
        let params = ChainParams::regtest();
        let genesis_bits = 0x207fffff;

        // Build a chain past a retarget boundary
        let chain = build_chain(0, 2016, 0, 600, genesis_bits);

        // Even at retarget boundary with any timestamp, should return same bits
        let new_bits = get_next_work_required(&chain, 1_000_000, &params);
        assert_eq!(new_bits, genesis_bits);
    }

    #[test]
    fn test_mainnet_no_change_at_target_timespan() {
        let params = ChainParams::mainnet();
        let genesis_bits = 0x1d00ffff;

        // Build exactly 2015 blocks (heights 0..2015)
        // The timespan is measured from block 0 to block 2015
        // TARGET_TIMESPAN = 2016 * 600 = 1,209,600
        // For the difficulty to stay the same, we need the timespan to be exactly TARGET_TIMESPAN
        // So the time per block needs to be TARGET_TIMESPAN / 2015 = ~600.297 seconds
        // But for simplicity, we can directly set the timestamps to achieve TARGET_TIMESPAN

        let start_time = 1000000u32; // arbitrary start time

        // We need block 2015's timestamp to be start_time + TARGET_TIMESPAN
        // So each block should be TARGET_TIMESPAN / 2015 apart
        // Let's just construct manually with the right timestamps

        let mut chain = TestBlockIndex::genesis(genesis_bits);
        chain.timestamp = start_time;

        // Add blocks 1-2015 with timestamps that total TARGET_TIMESPAN
        for h in 1..=2015 {
            // Linear interpolation to achieve exact TARGET_TIMESPAN
            let timestamp = start_time + (TARGET_TIMESPAN as u64 * h as u64 / 2015) as u32;
            chain = TestBlockIndex::with_prev(h, timestamp, genesis_bits, chain);
        }

        // Verify our setup: block 2015's timestamp should be start_time + TARGET_TIMESPAN
        assert_eq!(chain.timestamp, start_time + TARGET_TIMESPAN);

        // At height 2016 (next block after 2015), calculate new difficulty
        let new_time = chain.timestamp + TARGET_BLOCK_TIME;
        let new_bits = get_next_work_required(&chain, new_time, &params);

        // Difficulty should not change (actual_timespan == TARGET_TIMESPAN)
        assert_eq!(new_bits, genesis_bits);
    }

    #[test]
    fn test_mainnet_difficulty_increases() {
        let params = ChainParams::mainnet();
        let genesis_bits = 0x1d00ffff;

        // Build chain where blocks come in half the expected time (5 minutes)
        let start_time = 0;
        let chain = build_chain(0, 2015, start_time, TARGET_BLOCK_TIME / 2, genesis_bits);

        let new_time = chain.timestamp() + TARGET_BLOCK_TIME / 2;
        let new_bits = get_next_work_required(&chain, new_time, &params);

        // New target should be smaller (harder difficulty)
        let old_target = compact_to_target(genesis_bits);
        let new_target = compact_to_target(new_bits);

        // Compare targets - smaller means harder
        assert!(
            compare_targets(&new_target, &old_target) < 0,
            "Difficulty should increase (target should decrease)"
        );
    }

    #[test]
    fn test_mainnet_difficulty_decreases() {
        let params = ChainParams::mainnet();
        // Use a harder starting difficulty so there's room to decrease
        let hard_bits = 0x1c00ffff; // One byte smaller exponent = 256x harder

        // Build chain where blocks come in double the expected time (20 minutes)
        let start_time = 0;
        let chain = build_chain(0, 2015, start_time, TARGET_BLOCK_TIME * 2, hard_bits);

        let new_time = chain.timestamp() + TARGET_BLOCK_TIME * 2;
        let new_bits = get_next_work_required(&chain, new_time, &params);

        // New target should be larger (easier difficulty)
        let old_target = compact_to_target(hard_bits);
        let new_target = compact_to_target(new_bits);

        assert!(
            compare_targets(&new_target, &old_target) > 0,
            "Difficulty should decrease (target should increase)"
        );
    }

    #[test]
    fn test_mainnet_clamped_to_4x() {
        let params = ChainParams::mainnet();
        let genesis_bits = 0x1c00ffff;

        // Build chain with extremely slow block times (10x expected)
        let start_time = 0;
        let chain = build_chain(0, 2015, start_time, TARGET_BLOCK_TIME * 10, genesis_bits);

        // Calculate with very long timespan and with max timespan
        let long_bits = get_next_work_required(&chain, chain.timestamp() + TARGET_BLOCK_TIME * 10, &params);

        // Should be same as if we used exactly MAX_TIMESPAN (4x)
        let max_timespan_bits =
            calculate_retarget(genesis_bits, MAX_TIMESPAN, TARGET_TIMESPAN, &params.pow_limit);

        assert_eq!(long_bits, max_timespan_bits);
    }

    #[test]
    fn test_mainnet_clamped_to_quarter() {
        let params = ChainParams::mainnet();
        let genesis_bits = 0x1d00ffff;

        // Build chain with extremely fast block times (every second)
        let start_time = 0;
        let chain = build_chain(0, 2015, start_time, 1, genesis_bits);

        let fast_bits = get_next_work_required(&chain, chain.timestamp() + 1, &params);

        // Should be same as if we used exactly MIN_TIMESPAN (1/4)
        let min_timespan_bits =
            calculate_retarget(genesis_bits, MIN_TIMESPAN, TARGET_TIMESPAN, &params.pow_limit);

        assert_eq!(fast_bits, min_timespan_bits);
    }

    #[test]
    fn test_testnet_20_minute_rule() {
        let params = ChainParams::testnet3();
        let genesis_bits = 0x1d00ffff;
        let pow_limit_bits = target_to_compact(&params.pow_limit);

        // Build a short chain
        let chain = build_chain(0, 100, 0, TARGET_BLOCK_TIME, genesis_bits);

        // If the new block is >20 minutes after the previous, should allow min difficulty
        let slow_block_time = chain.timestamp() + TARGET_BLOCK_TIME * 2 + 1;
        let bits = get_next_work_required(&chain, slow_block_time, &params);
        assert_eq!(bits, pow_limit_bits);
    }

    #[test]
    fn test_testnet_walkback() {
        let params = ChainParams::testnet3();
        let normal_bits = 0x1d00ffff;
        let pow_limit_bits = target_to_compact(&params.pow_limit);

        // Build a chain with some min-difficulty blocks
        let mut chain = TestBlockIndex::genesis(normal_bits);
        chain.timestamp = 0;

        // Add some normal blocks
        for h in 1..=10 {
            chain = TestBlockIndex::with_prev(h, h * TARGET_BLOCK_TIME, normal_bits, chain);
        }

        // Add some min-difficulty blocks
        for h in 11..=20 {
            // Each block is >20 minutes after the last
            let timestamp = chain.timestamp + TARGET_BLOCK_TIME * 3;
            chain = TestBlockIndex::with_prev(h, timestamp, pow_limit_bits, chain);
        }

        // If the new block is NOT >20 minutes after the previous,
        // should walk back to find the last non-min-difficulty block
        let normal_time = chain.timestamp + TARGET_BLOCK_TIME;
        let bits = get_next_work_required(&chain, normal_time, &params);

        // Should return the normal difficulty from block 10
        assert_eq!(bits, normal_bits);
    }

    #[test]
    fn test_testnet_walkback_stops_at_retarget() {
        let params = ChainParams::testnet3();
        let normal_bits = 0x1d00ffff;
        let pow_limit_bits = target_to_compact(&params.pow_limit);

        // Build a chain where all blocks since the last retarget are min-difficulty
        // First, build up to block 2016 with normal difficulty
        let mut chain = TestBlockIndex::genesis(normal_bits);
        chain.timestamp = 0;

        for h in 1..=2016 {
            chain = TestBlockIndex::with_prev(h, h * TARGET_BLOCK_TIME, normal_bits, chain);
        }

        // Now add min-difficulty blocks from 2017 onward
        for h in 2017..=2020 {
            let timestamp = chain.timestamp + TARGET_BLOCK_TIME * 3;
            chain = TestBlockIndex::with_prev(h, timestamp, pow_limit_bits, chain);
        }

        // Walk back should stop at height 2016 (retarget boundary)
        let normal_time = chain.timestamp + TARGET_BLOCK_TIME;
        let bits = get_next_work_required(&chain, normal_time, &params);

        // Should return the min-difficulty (since that's what block 2016 has)
        // Wait - block 2016 was set with normal_bits. Let me re-check the walkback logic...
        // The walkback stops when we hit a retarget boundary OR a non-min-difficulty block.
        // So it should stop at block 2016 which has normal_bits.
        assert_eq!(bits, normal_bits);
    }

    #[test]
    fn test_bip94_uses_first_block_of_period() {
        let params = ChainParams::testnet4();

        // Build a chain where difficulty changes within the period
        // This simulates testnet3's chaos where min-difficulty blocks appear randomly
        let initial_bits = 0x1d00ffff;
        let later_bits = 0x1c00ffff; // Harder difficulty (smaller target)

        // Block 0 (genesis) with initial difficulty
        let start_time = 1000000u32;
        let mut chain = TestBlockIndex::genesis(initial_bits);
        chain.timestamp = start_time;

        // Blocks 1-2015: varying difficulty (simulating testnet min-difficulty chaos)
        for h in 1..=2015 {
            // Use later_bits for blocks >= 1000
            let bits = if h < 1000 { initial_bits } else { later_bits };
            // Use perfect timing to achieve TARGET_TIMESPAN
            let timestamp = start_time + (TARGET_TIMESPAN as u64 * h as u64 / 2015) as u32;
            chain = TestBlockIndex::with_prev(h, timestamp, bits, chain);
        }

        // Block 2015 should have later_bits
        assert_eq!(chain.bits, later_bits);
        // Verify timespan is exactly TARGET_TIMESPAN
        assert_eq!(chain.timestamp, start_time + TARGET_TIMESPAN);

        // For BIP94, the retarget should use block 0's difficulty (initial_bits)
        // not the last block's (later_bits)
        let new_time = chain.timestamp + TARGET_BLOCK_TIME;

        // With BIP94 and perfect timespan, using initial_bits as base should give us initial_bits back
        // (since TARGET_TIMESPAN / TARGET_TIMESPAN = 1)
        let expected_bits = calculate_retarget(
            initial_bits,
            TARGET_TIMESPAN,
            TARGET_TIMESPAN,
            &params.pow_limit,
        );

        // Without BIP94, using later_bits as base would give a different result
        // (also no change since timespan is perfect, but from a different starting point)
        let non_bip94_bits = calculate_retarget(
            later_bits,
            TARGET_TIMESPAN,
            TARGET_TIMESPAN,
            &params.pow_limit,
        );

        let actual_bits = get_next_work_required(&chain, new_time, &params);

        // BIP94 should give us the calculation based on initial_bits
        assert_eq!(actual_bits, expected_bits);
        // BIP94 result should equal initial_bits (since timespan is exactly TARGET_TIMESPAN)
        assert_eq!(actual_bits, initial_bits);
        // Without BIP94, we'd get later_bits (also unchanged due to perfect timespan)
        assert_eq!(non_bip94_bits, later_bits);
        // These should be different
        assert_ne!(actual_bits, non_bip94_bits);
    }

    #[test]
    fn test_check_proof_of_work_valid() {
        let params = ChainParams::mainnet();

        // Genesis block hash (big-endian for comparison)
        let mut hash = [0u8; 32];
        // Genesis hash starts with many zeros, so it's valid for genesis difficulty
        hash[3] = 0x00;
        hash[4] = 0x00;
        hash[5] = 0x19;

        let bits = 0x1d00ffff; // Genesis difficulty

        assert!(check_proof_of_work(&hash, bits, &params));
    }

    #[test]
    fn test_check_proof_of_work_invalid() {
        let params = ChainParams::mainnet();

        // Hash that's too large (above target)
        let hash = [0xff; 32];
        let bits = 0x1d00ffff;

        assert!(!check_proof_of_work(&hash, bits, &params));
    }

    #[test]
    fn test_check_proof_of_work_invalid_bits() {
        let params = ChainParams::mainnet();
        let hash = [0; 32];

        // Invalid bits (zero mantissa)
        assert!(!check_proof_of_work(&hash, 0x1d000000, &params));

        // Invalid bits (negative)
        assert!(!check_proof_of_work(&hash, 0x1d800000, &params));
    }

    #[test]
    fn test_permitted_difficulty_transition_mainnet() {
        let params = ChainParams::mainnet();
        let old_bits = 0x1d00ffff;

        // At non-retarget height: difficulty must stay the same
        assert!(permitted_difficulty_transition(1, old_bits, old_bits, &params));
        assert!(!permitted_difficulty_transition(1, old_bits, 0x1c00ffff, &params));

        // At retarget height: difficulty can change within bounds
        let new_bits = calculate_retarget(old_bits, TARGET_TIMESPAN, TARGET_TIMESPAN, &params.pow_limit);
        assert!(permitted_difficulty_transition(2016, old_bits, new_bits, &params));
    }

    #[test]
    fn test_permitted_difficulty_transition_testnet() {
        let params = ChainParams::testnet3();
        let old_bits = 0x1d00ffff;
        let new_bits = 0x1c00ffff;

        // Testnet allows any transition
        assert!(permitted_difficulty_transition(1, old_bits, new_bits, &params));
        assert!(permitted_difficulty_transition(2016, old_bits, new_bits, &params));
    }

    #[test]
    fn test_multiply_target_by_ratio() {
        // Test that multiplying by 1/1 returns the same value
        let target = compact_to_target(0x1d00ffff);
        let result = multiply_target_by_ratio(&target, 100, 100);
        assert_eq!(target, result);

        // Test that multiplying by 2/1 doubles the target
        let doubled = multiply_target_by_ratio(&target, 2, 1);
        // The doubled target should be larger
        assert!(compare_targets(&doubled, &target) > 0);

        // Test that multiplying by 1/2 halves the target
        let halved = multiply_target_by_ratio(&target, 1, 2);
        assert!(compare_targets(&halved, &target) < 0);
    }

    #[test]
    fn test_difficulty_adjustment_non_retarget_heights() {
        let params = ChainParams::mainnet();
        let genesis_bits = 0x1d00ffff;

        // Build a chain of 10 blocks
        let chain = build_chain(0, 10, 0, TARGET_BLOCK_TIME, genesis_bits);

        // At heights 1-2015 (not retarget boundaries), should return previous bits
        for h in 1..=10 {
            if let Some(block) = chain.ancestor(h - 1) {
                let bits = get_next_work_required(block, block.timestamp() + TARGET_BLOCK_TIME, &params);
                assert_eq!(bits, genesis_bits, "Height {} should keep same difficulty", h);
            }
        }
    }
}
