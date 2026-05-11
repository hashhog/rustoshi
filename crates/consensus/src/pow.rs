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
    if !next_height.is_multiple_of(DIFFICULTY_ADJUSTMENT_INTERVAL) {
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
        if current.height().is_multiple_of(DIFFICULTY_ADJUSTMENT_INTERVAL) {
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

    if height.is_multiple_of(DIFFICULTY_ADJUSTMENT_INTERVAL) {
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

// ============================================================
// CHAINWORK CALCULATIONS
// ============================================================

/// A 256-bit unsigned integer for chainwork calculations.
///
/// Used to track cumulative proof-of-work on a chain. Stored in big-endian format.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChainWork(pub [u8; 32]);

impl ChainWork {
    /// Zero chainwork.
    pub const ZERO: Self = Self([0u8; 32]);

    /// Create chainwork from big-endian bytes.
    pub fn from_be_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create chainwork from a hex string.
    pub fn from_hex(s: &str) -> Option<Self> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        if s.len() > 64 {
            return None;
        }

        // Pad with leading zeros
        let padded = format!("{:0>64}", s);
        let mut bytes = [0u8; 32];
        for (i, chunk) in padded.as_bytes().chunks(2).enumerate() {
            let hex_str = std::str::from_utf8(chunk).ok()?;
            bytes[i] = u8::from_str_radix(hex_str, 16).ok()?;
        }
        Some(Self(bytes))
    }

    /// Convert to hex string.
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for byte in &self.0 {
            s.push_str(&format!("{:02x}", byte));
        }
        // Strip leading zeros for display
        let trimmed = s.trim_start_matches('0');
        if trimmed.is_empty() {
            "0".to_string()
        } else {
            trimmed.to_string()
        }
    }

    /// Check if this chainwork is zero.
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    /// Add another chainwork value (saturating at max).
    pub fn saturating_add(&self, other: &Self) -> Self {
        let mut result = [0u8; 32];
        let mut carry = 0u16;

        // Add from least significant byte to most significant
        for i in (0..32).rev() {
            let sum = self.0[i] as u16 + other.0[i] as u16 + carry;
            result[i] = sum as u8;
            carry = sum >> 8;
        }

        // If there's overflow, saturate to max
        if carry > 0 {
            return Self([0xff; 32]);
        }

        Self(result)
    }

    /// Compare two chainwork values.
    /// Returns Ordering::Less if self < other, etc.
    fn compare(&self, other: &Self) -> std::cmp::Ordering {
        for i in 0..32 {
            match self.0[i].cmp(&other.0[i]) {
                std::cmp::Ordering::Equal => continue,
                ord => return ord,
            }
        }
        std::cmp::Ordering::Equal
    }
}

impl std::cmp::Ord for ChainWork {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.compare(other)
    }
}

impl std::cmp::PartialOrd for ChainWork {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::fmt::Display for ChainWork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Calculate the proof-of-work for a given compact target (bits).
///
/// This implements Bitcoin Core's `GetBlockProof` function.
/// Work = 2^256 / (target + 1) = (~target / (target + 1)) + 1
///
/// # Arguments
/// * `bits` - The compact difficulty target from the block header
///
/// # Returns
/// The chainwork contribution for this block.
pub fn get_block_proof(bits: u32) -> ChainWork {
    let target = compact_to_target(bits);

    // Check for invalid target (zero or negative)
    if target == [0u8; 32] {
        return ChainWork::ZERO;
    }

    // We need to compute 2**256 / (target + 1)
    // Since 2**256 doesn't fit in 256 bits, we use the identity:
    // 2**256 / (target + 1) = (~target / (target + 1)) + 1
    //
    // This works because ~target = 2**256 - 1 - target, so:
    // ~target / (target + 1) + 1 = (2**256 - 1 - target) / (target + 1) + 1
    //                            = (2**256 - 1 - target + target + 1) / (target + 1)
    //                            = 2**256 / (target + 1)

    // Compute ~target
    let mut not_target = [0u8; 32];
    for i in 0..32 {
        not_target[i] = !target[i];
    }

    // Compute target + 1
    let mut target_plus_one = target;
    let mut carry = 1u16;
    for i in (0..32).rev() {
        let sum = target_plus_one[i] as u16 + carry;
        target_plus_one[i] = sum as u8;
        carry = sum >> 8;
        if carry == 0 {
            break;
        }
    }

    // If target + 1 overflowed (target was all 1s), this is an edge case
    // that shouldn't happen with valid targets, but handle it gracefully
    if carry > 0 {
        return ChainWork([0u8; 32]); // Would be infinite work
    }

    // Divide ~target by (target + 1)
    let quotient = divide_256(&not_target, &target_plus_one);

    // Add 1 to the quotient
    let mut result = quotient;
    let mut add_carry = 1u16;
    for i in (0..32).rev() {
        let sum = result[i] as u16 + add_carry;
        result[i] = sum as u8;
        add_carry = sum >> 8;
        if add_carry == 0 {
            break;
        }
    }

    ChainWork(result)
}

/// Divide a 256-bit number by another 256-bit number.
/// Returns the quotient (rounded down).
/// Uses a bit-by-bit shift-and-subtract algorithm operating on 256-bit values
/// represented as four 64-bit big-endian words (words[0] = most significant).
fn divide_256(dividend: &[u8; 32], divisor: &[u8; 32]) -> [u8; 32] {
    // Check for division by zero
    if divisor.iter().all(|&b| b == 0) {
        return [0xff; 32];
    }

    // Fast path: if dividend < divisor, result is 0
    if compare_targets(dividend, divisor) < 0 {
        return [0u8; 32];
    }

    // Represent as four u64 words, big-endian (words[0] = most significant)
    let load_words = |bytes: &[u8; 32]| -> [u64; 4] {
        let mut w = [0u64; 4];
        for (idx, word) in w.iter_mut().enumerate() {
            let off = idx * 8;
            *word = u64::from_be_bytes(bytes[off..off + 8].try_into().unwrap());
        }
        w
    };

    let mut rem = load_words(dividend);
    let div = load_words(divisor);
    let mut quot = [0u64; 4];

    // Count significant bits in div (position of highest set bit, 0-indexed from LSB)
    let div_bits: u32 = {
        let mut b = 256u32;
        for (idx, &d) in div.iter().enumerate() {
            if d != 0 {
                b = (3 - idx as u32) * 64 + (64 - d.leading_zeros());
                break;
            }
        }
        b
    };

    // Count significant bits in rem
    let rem_bits: u32 = {
        let mut b = 0u32;
        for (idx, &r) in rem.iter().enumerate() {
            if r != 0 {
                b = (3 - idx as u32) * 64 + (64 - r.leading_zeros());
                break;
            }
        }
        b
    };

    if rem_bits < div_bits {
        return [0u8; 32];
    }

    // Shift divisor left so its MSbit aligns with rem's MSbit
    let shift = rem_bits - div_bits;

    // shl_256: shift a 4-word big-endian number left by `n` bits
    let shl_256 = |w: &[u64; 4], n: u32| -> [u64; 4] {
        if n == 0 { return *w; }
        let word_shift = (n / 64) as usize;
        let bit_shift = n % 64;
        let mut out = [0u64; 4];
        for (i, out_word) in out.iter_mut().enumerate() {
            let src = i + word_shift;
            if src < 4 {
                *out_word |= w[src] << bit_shift;
                if bit_shift > 0 && src + 1 < 4 {
                    *out_word |= w[src + 1] >> (64 - bit_shift);
                }
            }
        }
        out
    };

    // shr1_256: shift a 4-word big-endian number right by 1 bit
    let shr1_256 = |w: &[u64; 4]| -> [u64; 4] {
        let mut out = [0u64; 4];
        for i in (0..4).rev() {
            out[i] = w[i] >> 1;
            if i > 0 {
                out[i] |= w[i - 1] << 63;
            }
        }
        out
    };

    // cmp_256: compare two 4-word big-endian numbers; returns Ordering
    let cmp_256 = |a: &[u64; 4], b: &[u64; 4]| -> std::cmp::Ordering {
        for i in 0..4 {
            match a[i].cmp(&b[i]) {
                std::cmp::Ordering::Equal => continue,
                ord => return ord,
            }
        }
        std::cmp::Ordering::Equal
    };

    // sub_256: subtract b from a (a >= b assumed); returns a - b
    let sub_256 = |a: &[u64; 4], b: &[u64; 4]| -> [u64; 4] {
        let mut out = [0u64; 4];
        let mut borrow = 0u64;
        for i in (0..4).rev() {
            let (d1, o1) = a[i].overflowing_sub(b[i]);
            let (d2, o2) = d1.overflowing_sub(borrow);
            out[i] = d2;
            borrow = if o1 || o2 { 1 } else { 0 };
        }
        out
    };

    // set_bit_256: set bit `n` (0 = LSB) in a 4-word big-endian number
    let set_bit_256 = |w: &mut [u64; 4], n: u32| {
        let word = 3 - (n / 64) as usize;
        let bit = n % 64;
        w[word] |= 1u64 << bit;
    };

    let mut shifted = shl_256(&div, shift);

    // Long division: for each bit from `shift` down to 0, check if shifted divisor fits
    for bit in (0..=shift).rev() {
        if cmp_256(&rem, &shifted) != std::cmp::Ordering::Less {
            rem = sub_256(&rem, &shifted);
            set_bit_256(&mut quot, bit);
        }
        shifted = shr1_256(&shifted);
    }

    // Convert quotient to bytes
    let mut result = [0u8; 32];
    for (idx, &q) in quot.iter().enumerate() {
        result[idx * 8..idx * 8 + 8].copy_from_slice(&q.to_be_bytes());
    }
    result
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
    // block_hash is in internal byte order (LSB first), target is big-endian (MSB first).
    // Reverse hash to big-endian before comparing.
    let mut hash_be = *block_hash;
    hash_be.reverse();
    compare_targets(&hash_be, &target) <= 0
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

    // ============================================================
    // CHAINWORK TESTS
    // ============================================================

    #[test]
    fn test_chainwork_from_hex() {
        let work = ChainWork::from_hex("ff").unwrap();
        assert_eq!(work.0[31], 0xff);
        for i in 0..31 {
            assert_eq!(work.0[i], 0);
        }

        let work = ChainWork::from_hex("0x1234").unwrap();
        assert_eq!(work.0[30], 0x12);
        assert_eq!(work.0[31], 0x34);
    }

    #[test]
    fn test_chainwork_to_hex() {
        let mut bytes = [0u8; 32];
        bytes[31] = 0xff;
        let work = ChainWork(bytes);
        assert_eq!(work.to_hex(), "ff");

        bytes[30] = 0x12;
        bytes[31] = 0x34;
        let work = ChainWork(bytes);
        assert_eq!(work.to_hex(), "1234");

        let work = ChainWork::ZERO;
        assert_eq!(work.to_hex(), "0");
    }

    #[test]
    fn test_chainwork_saturating_add() {
        let mut a_bytes = [0u8; 32];
        a_bytes[31] = 100;
        let a = ChainWork(a_bytes);

        let mut b_bytes = [0u8; 32];
        b_bytes[31] = 50;
        let b = ChainWork(b_bytes);

        let sum = a.saturating_add(&b);
        assert_eq!(sum.0[31], 150);

        // Test with carry
        let mut a_bytes = [0u8; 32];
        a_bytes[31] = 0xff;
        let a = ChainWork(a_bytes);

        let mut b_bytes = [0u8; 32];
        b_bytes[31] = 0x01;
        let b = ChainWork(b_bytes);

        let sum = a.saturating_add(&b);
        assert_eq!(sum.0[31], 0x00);
        assert_eq!(sum.0[30], 0x01);
    }

    #[test]
    fn test_chainwork_cmp() {
        let mut a_bytes = [0u8; 32];
        a_bytes[31] = 100;
        let a = ChainWork(a_bytes);

        let mut b_bytes = [0u8; 32];
        b_bytes[31] = 50;
        let b = ChainWork(b_bytes);

        assert!(a > b);
        assert!(b < a);
        assert_eq!(a.cmp(&a), std::cmp::Ordering::Equal);
    }

    #[test]
    fn test_get_block_proof_genesis() {
        // Genesis difficulty: 0x1d00ffff
        // Target: 00000000ffff00000000...
        let bits = 0x1d00ffff;
        let work = get_block_proof(bits);

        // Work should be non-zero
        assert!(!work.is_zero());

        // At genesis difficulty, work per block is approximately 2^32
        // (since target has ~32 leading zeros)
        // The exact value is 2^256 / (target + 1)
        // With target = 0x00000000ffff... the work is around 0x100010001
        assert!(work.0[28] > 0 || work.0[27] > 0 || work.0[26] > 0);
    }

    #[test]
    fn test_get_block_proof_harder_difficulty() {
        // Harder difficulty should give more work per block
        let easy_bits = 0x1d00ffff;
        let hard_bits = 0x1c00ffff; // 256x harder

        let easy_work = get_block_proof(easy_bits);
        let hard_work = get_block_proof(hard_bits);

        // Harder difficulty (smaller target) = more work
        assert!(hard_work > easy_work);
    }

    #[test]
    fn test_get_block_proof_invalid_bits() {
        // Zero mantissa should give zero work
        let work = get_block_proof(0x1d000000);
        assert!(work.is_zero());

        // Negative target should give zero work
        let work = get_block_proof(0x1d800000);
        assert!(work.is_zero());
    }

    #[test]
    fn test_chainwork_mainnet_minimum() {
        // Verify we can parse Bitcoin Core's minimum chainwork for mainnet
        let work = ChainWork::from_hex("0000000000000000000000000000000000000001128750f82f4c366153a3a030").unwrap();
        assert!(!work.is_zero());

        // Verify roundtrip
        let hex = work.to_hex();
        let work2 = ChainWork::from_hex(&hex).unwrap();
        assert_eq!(work, work2);
    }

    #[test]
    fn test_chainwork_testnet4_minimum() {
        // Verify we can parse Bitcoin Core's minimum chainwork for testnet4
        let work = ChainWork::from_hex("0000000000000000000000000000000000000000000009a0fe15d0177d086304").unwrap();
        assert!(!work.is_zero());
    }

    // ============================================================
    // W83: COMPREHENSIVE DIFFICULTY / PoW AUDIT TESTS
    // ============================================================

    // --- Gate 2: retarget only at 2016-block boundary ---

    #[test]
    fn test_retarget_boundary_exactly_at_2016() {
        // Verify that next_height=2016 triggers a retarget.
        // The result may not equal genesis_bits if the timestamps don't produce
        // exactly TARGET_TIMESPAN, but it must differ from "just return last.bits()".
        // We test this by verifying that height 2015 (non-retarget) returns last.bits()
        // while height 2016 goes through the retarget calculation.
        let params = ChainParams::mainnet();
        let genesis_bits = 0x1d00ffff;

        // Chain of 2014 blocks at TARGET_BLOCK_TIME spacing → height 2014
        // Next height = 2015, NOT a retarget → must return genesis_bits
        let chain_2014 = build_chain(0, 2014, 0, TARGET_BLOCK_TIME, genesis_bits);
        let bits_2015 = get_next_work_required(&chain_2014, chain_2014.timestamp() + TARGET_BLOCK_TIME, &params);
        assert_eq!(bits_2015, genesis_bits, "height 2015 is NOT a retarget height");

        // Chain of 2015 blocks → height 2015
        // Next height = 2016 → IS a retarget
        // With perfect 600s spacing, actual_timespan == TARGET_TIMESPAN → bits unchanged
        let start_time = 1_000_000u32;
        let mut chain = TestBlockIndex::genesis(genesis_bits);
        chain.timestamp = start_time;
        for h in 1u32..=2015 {
            let ts = start_time + h * TARGET_BLOCK_TIME;
            chain = TestBlockIndex::with_prev(h, ts, genesis_bits, chain);
        }
        // actual_timespan = block2015.time - block0.time = 2015 * 600 = 1_209_000
        // This is slightly LESS than TARGET_TIMESPAN (1_209_600) → difficulty increases slightly
        let bits_2016 = get_next_work_required(&chain, chain.timestamp() + TARGET_BLOCK_TIME, &params);
        // The result should come from the retarget calculation, not just last.bits()
        // actual_timespan = 2015*600 = 1209000 < TARGET_TIMESPAN=1209600 → slightly harder
        let old_target = compact_to_target(genesis_bits);
        let new_target = compact_to_target(bits_2016);
        // Result must be at or below genesis target (slightly harder or same due to compact rounding)
        assert!(compare_targets(&new_target, &old_target) <= 0,
            "retarget at 2016 with fast blocks should not produce an easier target");
    }

    #[test]
    fn test_no_retarget_one_before_boundary() {
        let params = ChainParams::mainnet();
        let genesis_bits = 0x1d00ffff;

        // Height 2014 → next = 2015, NOT a retarget
        let chain = build_chain(0, 2014, 0, TARGET_BLOCK_TIME, genesis_bits);
        let new_bits = get_next_work_required(&chain, chain.timestamp() + TARGET_BLOCK_TIME, &params);
        assert_eq!(new_bits, genesis_bits, "no retarget one block before boundary");
    }

    #[test]
    fn test_no_retarget_one_after_boundary() {
        let params = ChainParams::mainnet();
        let genesis_bits = 0x1d00ffff;

        // Height 2016 → next = 2017, NOT a retarget
        let chain = build_chain(0, 2016, 0, TARGET_BLOCK_TIME, genesis_bits);
        let new_bits = get_next_work_required(&chain, chain.timestamp() + TARGET_BLOCK_TIME, &params);
        assert_eq!(new_bits, genesis_bits, "no retarget one block after boundary");
    }

    // --- Gate 9/10: min/max timespan clamps ---
    // Note: clamping happens in calculate_next_work_required, not in calculate_retarget.
    // We test clamping through get_next_work_required by building chains with extreme timespans.

    #[test]
    fn test_clamp_exactly_at_min_timespan() {
        // actual_timespan == MIN_TIMESPAN → ratio = 1/4 → target shrinks
        let params = ChainParams::mainnet();
        let bits = 0x1d00ffff;

        let result = calculate_retarget(bits, MIN_TIMESPAN, TARGET_TIMESPAN, &params.pow_limit);
        let old_target = compact_to_target(bits);
        let new_target = compact_to_target(result);
        assert!(compare_targets(&new_target, &old_target) < 0,
            "at min clamp, target decreases (difficulty increases)");
    }

    #[test]
    fn test_clamp_exactly_at_max_timespan() {
        // actual_timespan == MAX_TIMESPAN → ratio = 4 → target grows
        let params = ChainParams::mainnet();
        let bits = 0x1c00ffff; // harder starting point so there's room to grow

        let result = calculate_retarget(bits, MAX_TIMESPAN, TARGET_TIMESPAN, &params.pow_limit);
        let old_target = compact_to_target(bits);
        let new_target = compact_to_target(result);
        assert!(compare_targets(&new_target, &old_target) > 0,
            "at max clamp, target increases (difficulty decreases)");
    }

    #[test]
    fn test_clamp_below_min_via_full_function() {
        // Build a chain with extremely fast blocks (1 second each) and verify the
        // result is clamped to MIN_TIMESPAN via get_next_work_required.
        let params = ChainParams::mainnet();
        let bits = 0x1d00ffff;

        // Chain with 1s per block → actual_timespan ~= 2015s << MIN_TIMESPAN
        let fast_chain = build_chain(0, 2015, 0, 1, bits);
        let fast_result = get_next_work_required(&fast_chain, fast_chain.timestamp() + 1, &params);

        // Chain with exactly MIN_TIMESPAN → should produce same result due to clamping
        let min_chain = build_chain(0, 2015, 0, MIN_TIMESPAN / 2015, bits);
        let min_result = get_next_work_required(&min_chain, min_chain.timestamp() + 1, &params);

        // Both should use MIN_TIMESPAN denominator — equal or nearly equal
        assert_eq!(fast_result, min_result,
            "very fast chain and min-timespan chain should produce same clamped result");
    }

    #[test]
    fn test_clamp_above_max_via_full_function() {
        // Two chains with timespans that both exceed MAX_TIMESPAN should produce
        // the same result because of the 4x cap.
        let params = ChainParams::mainnet();
        let bits = 0x1c00ffff;

        // Very slow: 10× target spacing → actual_timespan >> MAX_TIMESPAN → clamp to MAX
        let very_slow = build_chain(0, 2015, 0, TARGET_BLOCK_TIME * 10, bits);
        let very_slow_result = get_next_work_required(&very_slow, very_slow.timestamp() + 1, &params);

        // Also 10× but 20×: both should be clamped identically
        let super_slow = build_chain(0, 2015, 0, TARGET_BLOCK_TIME * 20, bits);
        let super_slow_result = get_next_work_required(&super_slow, super_slow.timestamp() + 1, &params);

        assert_eq!(very_slow_result, super_slow_result,
            "any timespan beyond MAX_TIMESPAN should produce same clamped result");

        // The clamped result should equal calculate_retarget with MAX_TIMESPAN
        let expected = calculate_retarget(bits, MAX_TIMESPAN, TARGET_TIMESPAN, &params.pow_limit);
        assert_eq!(very_slow_result, expected,
            "clamped slow chain should equal explicit MAX_TIMESPAN retarget");
    }

    // --- Gate 3/4: testnet 20-minute rule, exact boundary ---

    #[test]
    fn test_testnet_20min_rule_exactly_at_boundary() {
        // Core check: new_block_time > prev.time + spacing*2  (strictly greater)
        // Exactly AT the threshold (==) must NOT trigger min-diff.
        // One second over (>) MUST trigger min-diff.
        let params = ChainParams::testnet3();
        // Use harder bits so they don't coincide with pow_limit for this test
        let harder_bits = 0x1c00ffff;
        let pow_limit_bits = target_to_compact(&params.pow_limit);

        // Sanity: harder_bits != pow_limit_bits
        assert_ne!(harder_bits, pow_limit_bits);

        let chain = build_chain(0, 100, 0, TARGET_BLOCK_TIME, harder_bits);
        let boundary_time = chain.timestamp() + TARGET_BLOCK_TIME * 2;

        // Exactly AT the threshold (== not >) → should NOT return pow_limit
        let bits = get_next_work_required(&chain, boundary_time, &params);
        assert_ne!(bits, pow_limit_bits, "time exactly at 2*spacing should NOT trigger min-diff (Core pow.cpp:27 uses >)");

        // One second over → triggers min-diff
        let over_time = chain.timestamp() + TARGET_BLOCK_TIME * 2 + 1;
        let bits_over = get_next_work_required(&chain, over_time, &params);
        assert_eq!(bits_over, pow_limit_bits, "one second over boundary triggers min-diff");
    }

    // --- Gate 5/6: ancestor lookup at correct height ---

    #[test]
    fn test_retarget_uses_first_block_of_period_not_genesis() {
        // Verify that at height 4031 (next=4032=2*2016), the second retarget uses
        // block 2016's timestamp as the period start, not block 0's.
        // We set the second period (2016..4031) to have half-speed blocks (300s each)
        // so actual_timespan = 2015*300 = 604_500 < TARGET_TIMESPAN → difficulty INCREASES.
        // We use a hard starting difficulty (0x1c00ffff, 256x harder than genesis) so the
        // target CAN decrease further without hitting zero.
        let params = ChainParams::mainnet();
        // 0x1c00ffff is 256x harder than 0x1d00ffff; its target has room to halve
        let starting_bits = 0x1c00ffff;

        let mut chain = TestBlockIndex::genesis(starting_bits);
        chain.timestamp = 0;

        // First period: blocks 1..2016 at perfect 600s spacing
        for h in 1u32..=2016 {
            chain = TestBlockIndex::with_prev(h, h * TARGET_BLOCK_TIME, starting_bits, chain);
        }
        // block 2016 timestamp = 2016 * 600 = 1_209_600

        // Second period: blocks 2017..4031 at 300s spacing (half speed → harder difficulty)
        let base = 2016u32 * TARGET_BLOCK_TIME;
        for h in 2017u32..=4031 {
            let extra = (h - 2016) * (TARGET_BLOCK_TIME / 2);
            chain = TestBlockIndex::with_prev(h, base + extra, starting_bits, chain);
        }
        // block 4031 timestamp = 1_209_600 + 2015*300 = 1_209_600 + 604_500 = 1_814_100

        assert_eq!(chain.height(), 4031);

        // actual_timespan = block4031.time - block2016.time = 1_814_100 - 1_209_600 = 604_500
        // 604_500 > MIN_TIMESPAN (302_400) → no clamp
        // new_target = old_target * 604_500 / 1_209_600 ≈ old_target * 0.5 → smaller → harder
        let new_bits = get_next_work_required(&chain, chain.timestamp() + TARGET_BLOCK_TIME, &params);
        let old_target = compact_to_target(starting_bits);
        let new_target = compact_to_target(new_bits);
        assert!(compare_targets(&new_target, &old_target) < 0,
            "second period with 2x-fast blocks should have smaller (harder) target");
    }

    // --- Gate 11: BIP-94 uses first-of-period bits ---

    #[test]
    fn test_bip94_first_block_bits_not_last() {
        // Similar to existing test but verifies the path from get_next_work_required
        let params = ChainParams::testnet4();
        let first_bits = 0x1d00ffff;
        let last_bits = 0x1c00ffff; // harder — appears in the second half of the period

        let start_time = 1_000_000u32;
        let mut chain = TestBlockIndex::genesis(first_bits);
        chain.timestamp = start_time;

        // Build 2015 blocks: first half with first_bits, second half with last_bits
        for h in 1u32..=2015 {
            let bits = if h < 1008 { first_bits } else { last_bits };
            // Perfect timing so timespan = TARGET_TIMESPAN
            let ts = start_time + (TARGET_TIMESPAN as u64 * h as u64 / 2015) as u32;
            chain = TestBlockIndex::with_prev(h, ts, bits, chain);
        }

        assert_eq!(chain.bits(), last_bits, "last block of period has last_bits");

        let new_bits = get_next_work_required(&chain, chain.timestamp() + TARGET_BLOCK_TIME, &params);

        // BIP-94: base = first_bits (block 0). With perfect timespan, result = first_bits.
        // Without BIP-94 it would be last_bits.
        assert_eq!(new_bits, first_bits,
            "BIP-94 retarget must use first-of-period bits, not last");
        assert_ne!(new_bits, last_bits,
            "BIP-94 result must differ from non-BIP-94 result");
    }

    // --- Gate 12: new_target = base * actual / target, capped to pow_limit ---

    #[test]
    fn test_retarget_capped_to_pow_limit() {
        // Starting at pow_limit with maximum timespan (4x) should stay at pow_limit
        let params = ChainParams::mainnet();
        let pow_limit_bits = target_to_compact(&params.pow_limit);

        let result = calculate_retarget(pow_limit_bits, MAX_TIMESPAN, TARGET_TIMESPAN, &params.pow_limit);
        assert_eq!(result, pow_limit_bits,
            "retarget result must be capped at pow_limit");
    }

    // --- Gates 15-17: PermittedDifficultyTransition ---

    #[test]
    fn test_permitted_difficulty_at_retarget_4x_upper_bound() {
        let params = ChainParams::mainnet();
        let old_bits = 0x1c00ffff;

        // Max allowed: old * MAX_TIMESPAN / TARGET_TIMESPAN (= 4x), capped at pow_limit
        let max_bits = calculate_retarget(old_bits, MAX_TIMESPAN, TARGET_TIMESPAN, &params.pow_limit);

        // Exactly at 4x bound → permitted
        assert!(permitted_difficulty_transition(2016, old_bits, max_bits, &params),
            "4x increase in target must be permitted");

        // Slightly easier than max (larger target) → NOT permitted
        // Decrement one byte from the compact to make it slightly easier
        let too_easy_bits = (max_bits & 0x00FFFFFF) | (((max_bits >> 24) + 1) << 24);
        if too_easy_bits != max_bits {
            assert!(!permitted_difficulty_transition(2016, old_bits, too_easy_bits, &params),
                "target above 4x bound must be rejected");
        }
    }

    #[test]
    fn test_permitted_difficulty_at_retarget_quarter_lower_bound() {
        let params = ChainParams::mainnet();
        let old_bits = 0x1d00ffff;

        // Min allowed: old * MIN_TIMESPAN / TARGET_TIMESPAN (= 1/4x)
        let min_bits = calculate_retarget(old_bits, MIN_TIMESPAN, TARGET_TIMESPAN, &params.pow_limit);

        // Exactly at 1/4x bound → permitted
        assert!(permitted_difficulty_transition(2016, old_bits, min_bits, &params),
            "1/4x decrease in target must be permitted");
    }

    #[test]
    fn test_permitted_difficulty_non_retarget_must_not_change() {
        let params = ChainParams::mainnet();
        let old_bits = 0x1d00ffff;

        // Any height that is NOT a multiple of 2016
        for height in [1u32, 2015, 2017, 4031, 4033] {
            assert!(permitted_difficulty_transition(height, old_bits, old_bits, &params),
                "same bits must always be permitted at non-retarget height {}", height);
            assert!(!permitted_difficulty_transition(height, old_bits, 0x1c00ffff, &params),
                "different bits must be rejected at non-retarget height {}", height);
        }
    }

    #[test]
    fn test_permitted_difficulty_testnet_always_true() {
        // fPowAllowMinDifficultyBlocks → always true regardless of height or bits
        let params = ChainParams::testnet3();
        assert!(permitted_difficulty_transition(1, 0x1d00ffff, 0x1c00ffff, &params));
        assert!(permitted_difficulty_transition(2016, 0x1d00ffff, 0x1d00ffff, &params));
        assert!(permitted_difficulty_transition(2016, 0x1d00ffff, 0x207fffff, &params));
    }

    // --- Gates 18-23: CheckProofOfWork (check_proof_of_work) ---

    #[test]
    fn test_check_proof_of_work_overflow_compact_rejected() {
        let params = ChainParams::mainnet();
        let hash = [0u8; 32]; // all-zeros hash (hardest possible to beat)

        // exponent > 32 → overflow → DeriveTarget returns None → rejected
        // Core pow.cpp:154 fOverflow check
        let overflow_bits = 0x2100_0001u32; // exponent=33
        assert!(!check_proof_of_work(&hash, overflow_bits, &params),
            "overflow compact encoding must be rejected (Core pow.cpp:154)");

        let overflow_bits2 = 0xff00_0001u32; // exponent=255
        assert!(!check_proof_of_work(&hash, overflow_bits2, &params),
            "max-exponent compact must be rejected");
    }

    #[test]
    fn test_check_proof_of_work_target_above_pow_limit_rejected() {
        // Mainnet pow_limit is 0x1d00ffff in compact.
        // A block claiming bits=0x1e00ffff (target = 0xffff * 2^(8*27) >> pow_limit) must fail.
        let params = ChainParams::mainnet();
        let hash = [0u8; 32]; // all-zeros hash

        // 0x1f00ffff → target = 0x00ffff * 2^(8*(31-3)) = beyond mainnet pow_limit
        let above_limit_bits = 0x1f00ffffu32;
        assert!(!check_proof_of_work(&hash, above_limit_bits, &params),
            "target above pow_limit must be rejected even for all-zeros hash (Core pow.cpp:155)");
    }

    #[test]
    fn test_check_proof_of_work_zero_target_rejected() {
        let params = ChainParams::mainnet();
        let hash = [0u8; 32];
        // Zero mantissa → target == 0 → rejected (Core: bnTarget == 0 check)
        assert!(!check_proof_of_work(&hash, 0x1d00_0000, &params));
        // Zero exponent
        assert!(!check_proof_of_work(&hash, 0x0000_ffff, &params));
    }

    #[test]
    fn test_check_proof_of_work_negative_target_rejected() {
        let params = ChainParams::mainnet();
        let hash = [0u8; 32];
        // Negative compact (high bit of mantissa = 1)
        assert!(!check_proof_of_work(&hash, 0x1d80_0000, &params),
            "negative target must be rejected (Core: fNegative check)");
    }

    #[test]
    fn test_check_proof_of_work_hash_above_target_rejected() {
        let params = ChainParams::mainnet();
        // Genesis target (BE): [0,0,0,0, 0xff,0xff, 0,...,0]
        // A hash stored in LE with byte[31]=0x01 reverses to BE byte[0]=0x01 > target[0]=0x00.
        // LE byte 31 = BE byte 0.
        let mut hash = [0u8; 32];
        hash[31] = 0x01; // LE byte 31 → BE byte 0 = 0x01 > target[0] = 0x00
        assert!(!check_proof_of_work(&hash, 0x1d00ffff, &params),
            "hash above target must fail (Core pow.cpp:167)");
    }

    #[test]
    fn test_check_proof_of_work_hash_at_target_passes() {
        let params = ChainParams::mainnet();
        // Craft a hash that exactly equals the target for 0x1d00ffff.
        // Target (BE): 00 00 00 00 ff ff 00 00 ... 00
        // In LE (internal storage): reversed = 00 ... 00 ff ff 00 00 00 00
        // hash[27]=0x00, hash[28]=0x00, hash[29]=0xff, hash[30]=0xff, hash[31]=0x00 ... hmm
        // Let's recompute: target BE = [0,0,0,0, 0xff,0xff, 0,0,...,0]
        // In LE that's reversed: [0,...,0, 0xff,0xff, 0,0,0,0]
        // So hash[27]=0xff, hash[28]=0xff, hash[29..31]=0x00, hash[0..26]=0x00
        let mut hash = [0u8; 32]; // LE storage
        // target BE bytes 4,5 = 0xff, 0xff
        // reversed: LE byte 31-4=27 = 0xff, LE byte 31-5=26 = 0xff
        hash[27] = 0xff;
        hash[26] = 0xff;
        // All other bytes 0
        assert!(check_proof_of_work(&hash, 0x1d00ffff, &params),
            "hash exactly equal to target must pass (Core pow.cpp:167 uses >)");
    }

    // --- SetCompact / GetCompact round-trip ---

    #[test]
    fn test_compact_roundtrip_genesis() {
        // 0x1d00ffff → target → compact must give back 0x1d00ffff
        let bits = 0x1d00ffff;
        let target = compact_to_target(bits);
        let back = target_to_compact(&target);
        assert_eq!(back, bits, "SetCompact(GetCompact(genesis)) must be identity");
    }

    #[test]
    fn test_compact_roundtrip_various() {
        let cases = [
            0x1c00ffff,
            0x1b00ffff,
            0x1a00ffff,
            0x207fffff, // regtest
            0x1d00ffff, // mainnet genesis
        ];
        for bits in cases {
            let target = compact_to_target(bits);
            let back = target_to_compact(&target);
            assert_eq!(back, bits,
                "round-trip failed for bits=0x{:08x}", bits);
        }
    }

    // --- Regtest: fPowNoRetargeting ---

    #[test]
    fn test_regtest_never_retargets_any_height() {
        let params = ChainParams::regtest();
        let genesis_bits = 0x207fffff;

        for count in [2015, 2016, 4031, 4032, 10000] {
            let chain = build_chain(0, count, 0, 1, genesis_bits);
            let new_bits = get_next_work_required(&chain, chain.timestamp() + 1, &params);
            assert_eq!(new_bits, genesis_bits,
                "regtest must never retarget at height {}", count);
        }
    }

    // --- Testnet walkback: boundary between min-diff run and retarget block ---

    #[test]
    fn test_testnet_walkback_finds_non_min_diff_block() {
        let params = ChainParams::testnet3();
        let normal_bits = 0x1d00ffff;
        let pow_limit_bits = target_to_compact(&params.pow_limit);

        // Chain: 5 normal blocks, then 5 min-diff blocks
        let mut chain = TestBlockIndex::genesis(normal_bits);
        chain.timestamp = 0;

        for h in 1..=5 {
            chain = TestBlockIndex::with_prev(h, h * TARGET_BLOCK_TIME, normal_bits, chain);
        }
        for h in 6..=10 {
            chain = TestBlockIndex::with_prev(
                h, chain.timestamp() + TARGET_BLOCK_TIME * 3, pow_limit_bits, chain,
            );
        }

        // New block at normal spacing → walkback should skip the min-diff blocks
        let bits = get_next_work_required(&chain, chain.timestamp() + TARGET_BLOCK_TIME, &params);
        assert_eq!(bits, normal_bits,
            "walkback should return last non-min-diff bits");
    }

    #[test]
    fn test_testnet_walkback_stops_at_retarget_height() {
        // All blocks since the last retarget are min-diff.
        // Walkback must stop at the retarget boundary block (height 2016).
        let params = ChainParams::testnet3();
        let normal_bits = 0x1d00ffff;
        let pow_limit_bits = target_to_compact(&params.pow_limit);

        // Build 2016 normal blocks
        let mut chain = TestBlockIndex::genesis(normal_bits);
        chain.timestamp = 0;

        for h in 1u32..=2016 {
            chain = TestBlockIndex::with_prev(h, h * TARGET_BLOCK_TIME, normal_bits, chain);
        }
        // Add 4 min-difficulty blocks (height 2017..2020)
        for _h in 2017u32..=2020 {
            let ts = chain.timestamp() + TARGET_BLOCK_TIME * 3;
            let h = chain.height() + 1;
            chain = TestBlockIndex::with_prev(h, ts, pow_limit_bits, chain);
        }

        // next_height = 2021, not a retarget.  All recent blocks are min-diff.
        let bits = get_next_work_required(&chain, chain.timestamp() + TARGET_BLOCK_TIME, &params);
        // Walkback stops at height 2016 (which has normal_bits)
        assert_eq!(bits, normal_bits,
            "walkback should stop at retarget boundary and return its bits");
    }
}
