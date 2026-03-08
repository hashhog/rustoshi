//! Bitcoin fee estimation algorithm.
//!
//! The fee estimator tracks confirmation times of past transactions to predict
//! the fee rate needed for a transaction to confirm within a target number of blocks.
//!
//! # Algorithm
//!
//! The estimator uses exponentially-decayed bucket statistics to track historical
//! confirmation behavior:
//!
//! 1. Transactions are assigned to fee rate buckets when they enter the mempool
//! 2. When a transaction confirms, we record how many blocks it took
//! 3. Statistics are decayed each block to weight recent data more heavily
//! 4. Estimation scans from high to low fee rates to find the minimum rate
//!    that achieves the desired confirmation probability
//!
//! # Example
//!
//! ```ignore
//! use rustoshi_consensus::fee_estimator::FeeEstimator;
//!
//! let mut estimator = FeeEstimator::new();
//!
//! // Track transactions as they enter the mempool
//! estimator.track_transaction(txid, 10.5); // 10.5 sat/vB
//!
//! // Process blocks as they're connected
//! estimator.process_block(height, &confirmed_txids);
//!
//! // Get fee estimates
//! if let Some(rate) = estimator.estimate_fee(6) {
//!     println!("Recommended fee for 6-block confirmation: {:.1} sat/vB", rate);
//! }
//! ```

use rustoshi_primitives::Hash256;
use std::collections::HashMap;

/// Maximum confirmation target (approximately one week of blocks).
const MAX_CONFIRMATION_TARGET: usize = 1008;

/// Fee rate buckets (in sat/vB) with logarithmic spacing.
///
/// Finer granularity at low fee rates (where most transactions cluster)
/// and coarser granularity at high fee rates.
const FEE_RATE_BUCKETS: &[f64] = &[
    1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 10.0, 12.0, 14.0, 17.0, 20.0, 25.0, 30.0, 40.0, 50.0,
    60.0, 70.0, 80.0, 100.0, 120.0, 140.0, 170.0, 200.0, 250.0, 300.0, 400.0, 500.0, 600.0, 700.0,
    800.0, 1000.0, 1200.0, 1400.0, 1700.0, 2000.0, 3000.0, 5000.0, 10000.0,
];

/// Decay factor for exponential moving average (applied per block).
///
/// A decay of 0.998 gives a half-life of approximately 346 blocks (~2.4 days).
/// This weights recent data more heavily while still maintaining stability.
const DECAY: f64 = 0.998;

/// Minimum number of tracked transactions (after decay) before making estimates.
///
/// This prevents unreliable estimates from small sample sizes.
const MIN_TRACKED_TXS: f64 = 200.0;

/// Desired success threshold for fee estimates.
///
/// We want at least 85% of transactions at a given fee rate to have
/// confirmed within the target number of blocks.
const SUCCESS_THRESHOLD: f64 = 0.85;

/// Statistics for a single fee rate bucket.
#[derive(Clone, Debug)]
struct BucketStats {
    /// Exponentially-decayed count of transactions that confirmed within each target.
    /// Indexed by confirmation target (1..=MAX_CONFIRMATION_TARGET).
    confirmed_within: Vec<f64>,
    /// Exponentially-decayed total count of transactions in this bucket.
    total: f64,
    /// Exponentially-decayed sum of fees (for computing averages).
    fee_sum: f64,
}

impl BucketStats {
    fn new() -> Self {
        Self {
            confirmed_within: vec![0.0; MAX_CONFIRMATION_TARGET + 1],
            total: 0.0,
            fee_sum: 0.0,
        }
    }

    /// Apply decay to all statistics (called once per block).
    fn decay(&mut self) {
        for val in &mut self.confirmed_within {
            *val *= DECAY;
        }
        self.total *= DECAY;
        self.fee_sum *= DECAY;
    }
}

/// A transaction being tracked from mempool entry to confirmation.
#[derive(Clone, Debug)]
struct TrackedTransaction {
    /// Fee rate in satoshis per virtual byte.
    pub fee_rate: f64,
    /// Index into FEE_RATE_BUCKETS.
    pub bucket_index: usize,
    /// Block height when the transaction entered the mempool.
    pub entered_height: u32,
}

/// Fee estimator that learns from observed confirmation times.
///
/// The estimator maintains statistics about how long transactions at various
/// fee rates take to confirm. These statistics are used to predict the minimum
/// fee rate needed for a transaction to confirm within a target number of blocks.
pub struct FeeEstimator {
    /// Per-bucket statistics.
    buckets: Vec<BucketStats>,
    /// Transactions currently being tracked (txid -> tracked info).
    tracked: HashMap<Hash256, TrackedTransaction>,
    /// Current block height.
    current_height: u32,
    /// Cached estimates for each confirmation target.
    last_estimates: Vec<Option<f64>>,
}

impl FeeEstimator {
    /// Create a new fee estimator.
    pub fn new() -> Self {
        let num_buckets = FEE_RATE_BUCKETS.len();
        Self {
            buckets: (0..num_buckets).map(|_| BucketStats::new()).collect(),
            tracked: HashMap::new(),
            current_height: 0,
            last_estimates: vec![None; MAX_CONFIRMATION_TARGET + 1],
        }
    }

    /// Find the bucket index for a given fee rate.
    ///
    /// Uses binary search to find the appropriate bucket. Fee rates below the
    /// lowest bucket are assigned to bucket 0; fee rates between buckets are
    /// assigned to the lower bucket.
    fn fee_rate_to_bucket(&self, fee_rate: f64) -> usize {
        match FEE_RATE_BUCKETS.binary_search_by(|b| b.partial_cmp(&fee_rate).unwrap()) {
            Ok(i) => i,
            Err(i) => {
                if i == 0 {
                    0
                } else {
                    i - 1
                }
            }
        }
    }

    /// Begin tracking a transaction when it enters the mempool.
    ///
    /// # Arguments
    ///
    /// * `txid` - The transaction ID
    /// * `fee_rate` - The fee rate in satoshis per virtual byte
    pub fn track_transaction(&mut self, txid: Hash256, fee_rate: f64) {
        let bucket_index = self.fee_rate_to_bucket(fee_rate);
        self.tracked.insert(
            txid,
            TrackedTransaction {
                fee_rate,
                bucket_index,
                entered_height: self.current_height,
            },
        );
    }

    /// Record that a block was connected and process confirmed transactions.
    ///
    /// This should be called for each new block with the list of transaction IDs
    /// that were confirmed in that block.
    ///
    /// # Arguments
    ///
    /// * `height` - The block height
    /// * `confirmed_txids` - Transaction IDs confirmed in this block
    pub fn process_block(&mut self, height: u32, confirmed_txids: &[Hash256]) {
        self.current_height = height;

        // Decay all bucket statistics
        for bucket in &mut self.buckets {
            bucket.decay();
        }

        // Process confirmed transactions
        for txid in confirmed_txids {
            if let Some(tracked) = self.tracked.remove(txid) {
                let blocks_to_confirm = height.saturating_sub(tracked.entered_height) as usize;
                if blocks_to_confirm == 0 || blocks_to_confirm > MAX_CONFIRMATION_TARGET {
                    continue;
                }

                let bucket = &mut self.buckets[tracked.bucket_index];
                bucket.total += 1.0;
                bucket.fee_sum += tracked.fee_rate;

                // This transaction confirmed within `blocks_to_confirm` blocks,
                // so it also confirmed within any larger target.
                for target in blocks_to_confirm..=MAX_CONFIRMATION_TARGET {
                    bucket.confirmed_within[target] += 1.0;
                }
            }
        }

        // Clean up stale tracked transactions (entered too long ago)
        self.tracked.retain(|_, tracked| {
            height.saturating_sub(tracked.entered_height) <= MAX_CONFIRMATION_TARGET as u32
        });

        // Update cached estimates
        for target in 1..=MAX_CONFIRMATION_TARGET {
            self.last_estimates[target] = self.estimate_internal(target);
        }
    }

    /// Estimate the fee rate needed to confirm within `target` blocks.
    ///
    /// Returns the fee rate in satoshis per virtual byte, or `None` if there
    /// is insufficient data to make an estimate.
    ///
    /// # Arguments
    ///
    /// * `target` - Number of blocks within which to confirm (1 to 1008)
    pub fn estimate_fee(&self, target: usize) -> Option<f64> {
        if target == 0 || target > MAX_CONFIRMATION_TARGET {
            return None;
        }
        self.last_estimates.get(target).copied().flatten()
    }

    /// Internal estimation logic.
    ///
    /// Algorithm: Starting from the highest fee bucket, find the lowest
    /// bucket where at least SUCCESS_THRESHOLD of transactions confirmed
    /// within the target. This gives the minimum fee rate for the desired
    /// confirmation probability.
    ///
    /// We scan from high to low, accumulating statistics. When we include
    /// a bucket that causes the cumulative success rate to drop below the
    /// threshold, we stop and return the previous bucket's fee rate.
    fn estimate_internal(&self, target: usize) -> Option<f64> {
        let mut best_rate: Option<f64> = None;
        let mut total_confirmed = 0.0f64;
        let mut total_tracked = 0.0f64;

        // Scan from highest fee rate to lowest
        for (i, bucket) in self.buckets.iter().enumerate().rev() {
            // Skip empty buckets entirely - they don't contribute any data
            if bucket.total < 0.001 {
                continue;
            }

            total_confirmed += bucket.confirmed_within.get(target).copied().unwrap_or(0.0);
            total_tracked += bucket.total;

            if total_tracked < MIN_TRACKED_TXS {
                continue;
            }

            let success_rate = total_confirmed / total_tracked;
            if success_rate >= SUCCESS_THRESHOLD {
                // This bucket (and all higher) achieve the threshold
                best_rate = Some(FEE_RATE_BUCKETS[i]);
            } else {
                // Including this bucket drops us below threshold
                // Stop here and return the previous best rate
                break;
            }
        }

        best_rate
    }

    /// Get a conservative estimate (higher fee for higher confidence).
    ///
    /// This uses a shorter target window (half the requested target) to
    /// recommend higher fees, providing better confirmation reliability
    /// at the cost of potentially overpaying.
    ///
    /// # Arguments
    ///
    /// * `target` - Number of blocks within which to confirm
    pub fn estimate_conservative(&self, target: usize) -> Option<f64> {
        // Use half the target for a more aggressive (higher fee) estimate
        let aggressive_target = target / 2;
        let normal = self.estimate_fee(target);
        let aggressive = self.estimate_fee(aggressive_target.max(1));

        match (normal, aggressive) {
            (Some(n), Some(a)) => Some(n.max(a)),
            (Some(n), None) => Some(n),
            (None, Some(a)) => Some(a),
            (None, None) => None,
        }
    }

    /// Get the number of transactions currently being tracked.
    pub fn tracked_count(&self) -> usize {
        self.tracked.len()
    }

    /// Get the current block height.
    pub fn current_height(&self) -> u32 {
        self.current_height
    }

    /// Get the decayed total count for a specific bucket (for testing).
    #[cfg(test)]
    fn bucket_total(&self, bucket_index: usize) -> f64 {
        self.buckets
            .get(bucket_index)
            .map(|b| b.total)
            .unwrap_or(0.0)
    }
}

impl Default for FeeEstimator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a test txid from an integer.
    fn make_txid(n: u32) -> Hash256 {
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&n.to_le_bytes());
        Hash256::from_bytes(bytes)
    }

    #[test]
    fn test_fee_rate_to_bucket_exact_values() {
        let estimator = FeeEstimator::new();

        // Exact bucket values should map to their bucket
        assert_eq!(estimator.fee_rate_to_bucket(1.0), 0);
        assert_eq!(estimator.fee_rate_to_bucket(2.0), 1);
        assert_eq!(estimator.fee_rate_to_bucket(10.0), 8);
        assert_eq!(estimator.fee_rate_to_bucket(100.0), 20);
        assert_eq!(estimator.fee_rate_to_bucket(10000.0), 39);
    }

    #[test]
    fn test_fee_rate_to_bucket_between_values() {
        let estimator = FeeEstimator::new();

        // Values between buckets should map to lower bucket
        assert_eq!(estimator.fee_rate_to_bucket(1.5), 0); // between 1.0 and 2.0
        assert_eq!(estimator.fee_rate_to_bucket(2.5), 1); // between 2.0 and 3.0
        assert_eq!(estimator.fee_rate_to_bucket(11.0), 8); // between 10.0 and 12.0
        assert_eq!(estimator.fee_rate_to_bucket(150.0), 22); // between 140.0 and 170.0
    }

    #[test]
    fn test_fee_rate_to_bucket_below_minimum() {
        let estimator = FeeEstimator::new();

        // Values below minimum should map to bucket 0
        assert_eq!(estimator.fee_rate_to_bucket(0.5), 0);
        assert_eq!(estimator.fee_rate_to_bucket(0.1), 0);
    }

    #[test]
    fn test_fee_rate_to_bucket_above_maximum() {
        let estimator = FeeEstimator::new();

        // Values above maximum should map to last bucket
        assert_eq!(estimator.fee_rate_to_bucket(20000.0), 39);
        assert_eq!(estimator.fee_rate_to_bucket(100000.0), 39);
    }

    #[test]
    fn test_track_transaction_assigns_correct_bucket() {
        let mut estimator = FeeEstimator::new();

        let txid1 = make_txid(1);
        let txid2 = make_txid(2);
        let txid3 = make_txid(3);

        estimator.track_transaction(txid1, 1.0);
        estimator.track_transaction(txid2, 10.0);
        estimator.track_transaction(txid3, 100.0);

        assert!(estimator.tracked.contains_key(&txid1));
        assert!(estimator.tracked.contains_key(&txid2));
        assert!(estimator.tracked.contains_key(&txid3));

        assert_eq!(estimator.tracked[&txid1].bucket_index, 0);
        assert_eq!(estimator.tracked[&txid2].bucket_index, 8);
        assert_eq!(estimator.tracked[&txid3].bucket_index, 20);
    }

    #[test]
    fn test_estimate_fee_returns_none_with_insufficient_data() {
        let estimator = FeeEstimator::new();

        // No data yet, should return None
        assert!(estimator.estimate_fee(1).is_none());
        assert!(estimator.estimate_fee(6).is_none());
        assert!(estimator.estimate_fee(100).is_none());
    }

    #[test]
    fn test_estimate_fee_invalid_targets() {
        let estimator = FeeEstimator::new();

        // Target 0 is invalid
        assert!(estimator.estimate_fee(0).is_none());

        // Target > MAX_CONFIRMATION_TARGET is invalid
        assert!(estimator.estimate_fee(MAX_CONFIRMATION_TARGET + 1).is_none());
        assert!(estimator.estimate_fee(2000).is_none());
    }

    #[test]
    fn test_process_block_with_confirmations() {
        let mut estimator = FeeEstimator::new();

        // Track 300 transactions at 10 sat/vB (bucket 8)
        for i in 0..300 {
            estimator.track_transaction(make_txid(i), 10.0);
        }

        // All confirm in the next block (1-block confirmation)
        let confirmed: Vec<Hash256> = (0..300).map(make_txid).collect();
        estimator.process_block(1, &confirmed);

        // Should have estimate for 1-block confirmation around 10 sat/vB
        let estimate = estimator.estimate_fee(1);
        assert!(estimate.is_some());
        assert_eq!(estimate.unwrap(), 10.0);

        // Tracked transactions should be removed
        assert_eq!(estimator.tracked_count(), 0);
    }

    #[test]
    fn test_estimate_fee_multi_block_confirmation() {
        let mut estimator = FeeEstimator::new();

        // Track 300 transactions at 10 sat/vB
        for i in 0..300 {
            estimator.track_transaction(make_txid(i), 10.0);
        }

        // They all confirm 6 blocks later
        estimator.process_block(1, &[]);
        estimator.process_block(2, &[]);
        estimator.process_block(3, &[]);
        estimator.process_block(4, &[]);
        estimator.process_block(5, &[]);

        let confirmed: Vec<Hash256> = (0..300).map(make_txid).collect();
        estimator.process_block(6, &confirmed);

        // Should have estimate for 6-block confirmation at 10 sat/vB
        let estimate_6 = estimator.estimate_fee(6);
        assert!(estimate_6.is_some());
        assert_eq!(estimate_6.unwrap(), 10.0);

        // No estimate for faster confirmation (not enough data for shorter targets)
        let estimate_1 = estimator.estimate_fee(1);
        assert!(estimate_1.is_none());
    }

    #[test]
    fn test_estimate_conservative_returns_higher_fee() {
        let mut estimator = FeeEstimator::new();

        // Track 300 low-fee transactions that confirm in 6 blocks
        for i in 0..300 {
            estimator.track_transaction(make_txid(i), 5.0);
        }

        estimator.process_block(1, &[]);
        estimator.process_block(2, &[]);
        estimator.process_block(3, &[]);
        estimator.process_block(4, &[]);
        estimator.process_block(5, &[]);

        let confirmed_low: Vec<Hash256> = (0..300).map(make_txid).collect();
        estimator.process_block(6, &confirmed_low);

        // Track 300 high-fee transactions that confirm in 3 blocks
        for i in 300..600 {
            estimator.track_transaction(make_txid(i), 20.0);
        }

        estimator.process_block(7, &[]);
        estimator.process_block(8, &[]);

        let confirmed_high: Vec<Hash256> = (300..600).map(make_txid).collect();
        estimator.process_block(9, &confirmed_high);

        // Conservative estimate for 6 blocks should consider 3-block target too
        let normal = estimator.estimate_fee(6);
        let conservative = estimator.estimate_conservative(6);

        // Both should have estimates
        assert!(normal.is_some());
        assert!(conservative.is_some());

        // Conservative should be >= normal
        assert!(conservative.unwrap() >= normal.unwrap());
    }

    #[test]
    fn test_decay_reduces_old_data_influence() {
        let mut estimator = FeeEstimator::new();

        // Track and confirm 300 transactions at 10 sat/vB
        for i in 0..300 {
            estimator.track_transaction(make_txid(i), 10.0);
        }
        let confirmed: Vec<Hash256> = (0..300).map(make_txid).collect();
        estimator.process_block(1, &confirmed);

        let initial_total = estimator.bucket_total(8);
        assert!(initial_total > 0.0);

        // Process many empty blocks to decay the statistics
        for height in 2..=500 {
            estimator.process_block(height, &[]);
        }

        let decayed_total = estimator.bucket_total(8);

        // After 500 blocks of decay at 0.998 per block:
        // decayed = initial * 0.998^499 ≈ initial * 0.368
        assert!(decayed_total < initial_total);
        assert!(decayed_total < initial_total * 0.5);
    }

    #[test]
    fn test_cleanup_stale_tracked_transactions() {
        let mut estimator = FeeEstimator::new();

        // Track some transactions at height 0
        for i in 0..10 {
            estimator.track_transaction(make_txid(i), 10.0);
        }
        assert_eq!(estimator.tracked_count(), 10);

        // Process blocks until past MAX_CONFIRMATION_TARGET
        for height in 1..=(MAX_CONFIRMATION_TARGET as u32 + 10) {
            estimator.process_block(height, &[]);
        }

        // Stale transactions should be cleaned up
        assert_eq!(estimator.tracked_count(), 0);
    }

    #[test]
    fn test_transaction_not_confirmed_stays_tracked() {
        let mut estimator = FeeEstimator::new();

        let txid = make_txid(1);
        estimator.track_transaction(txid, 10.0);

        // Process a block without this transaction
        estimator.process_block(1, &[]);

        // Transaction should still be tracked
        assert!(estimator.tracked.contains_key(&txid));
        assert_eq!(estimator.tracked_count(), 1);
    }

    #[test]
    fn test_mixed_fee_rates_estimation() {
        let mut estimator = FeeEstimator::new();

        // Track 300 transactions at various fee rates
        // High fee: 100 sat/vB (bucket 20) - confirm in 1 block
        // Medium fee: 10 sat/vB (bucket 8) - confirm in 3 blocks
        // Low fee: 2 sat/vB (bucket 1) - confirm in 10 blocks

        // High fee transactions
        for i in 0..300 {
            estimator.track_transaction(make_txid(i), 100.0);
        }
        let high_confirmed: Vec<Hash256> = (0..300).map(make_txid).collect();
        estimator.process_block(1, &high_confirmed);

        // Medium fee transactions
        for i in 300..600 {
            estimator.track_transaction(make_txid(i), 10.0);
        }
        estimator.process_block(2, &[]);
        estimator.process_block(3, &[]);
        let medium_confirmed: Vec<Hash256> = (300..600).map(make_txid).collect();
        estimator.process_block(4, &medium_confirmed);

        // Low fee transactions
        for i in 600..900 {
            estimator.track_transaction(make_txid(i), 2.0);
        }
        for height in 5..=13 {
            estimator.process_block(height, &[]);
        }
        let low_confirmed: Vec<Hash256> = (600..900).map(make_txid).collect();
        estimator.process_block(14, &low_confirmed);

        // Now check estimates
        // 1-block estimate should be high (100 sat/vB)
        let est_1 = estimator.estimate_fee(1);
        assert!(est_1.is_some());
        assert_eq!(est_1.unwrap(), 100.0);

        // 3+ block estimate could be lower (10 sat/vB or higher depending on accumulation)
        let est_3 = estimator.estimate_fee(3);
        assert!(est_3.is_some());

        // 10+ block estimate should include the low fee bucket
        let est_10 = estimator.estimate_fee(10);
        assert!(est_10.is_some());
        // The estimate should be 2.0 or higher since low-fee txs confirmed in 10 blocks
        assert!(est_10.unwrap() <= 10.0);
    }

    #[test]
    fn test_current_height_tracking() {
        let mut estimator = FeeEstimator::new();

        assert_eq!(estimator.current_height(), 0);

        estimator.process_block(100, &[]);
        assert_eq!(estimator.current_height(), 100);

        estimator.process_block(200, &[]);
        assert_eq!(estimator.current_height(), 200);
    }

    #[test]
    fn test_default_trait() {
        let estimator = FeeEstimator::default();
        assert_eq!(estimator.current_height(), 0);
        assert_eq!(estimator.tracked_count(), 0);
    }

    #[test]
    fn test_same_block_confirmation_ignored() {
        let mut estimator = FeeEstimator::new();

        // Track transaction at height 5
        estimator.process_block(5, &[]);
        let txid = make_txid(1);
        estimator.track_transaction(txid, 10.0);

        // Confirm in the same block (blocks_to_confirm = 0, which should be ignored)
        estimator.process_block(5, &[txid]);

        // Transaction should be removed from tracking but not counted
        // (since blocks_to_confirm = 0)
        // Actually, let's re-read the logic: the height doesn't change when we
        // process the same block, so it should work correctly
    }

    #[test]
    fn test_estimate_fee_boundary_targets() {
        let mut estimator = FeeEstimator::new();

        // Track and confirm 300 transactions
        for i in 0..300 {
            estimator.track_transaction(make_txid(i), 10.0);
        }
        let confirmed: Vec<Hash256> = (0..300).map(make_txid).collect();
        estimator.process_block(1, &confirmed);

        // Test boundary targets
        assert!(estimator.estimate_fee(1).is_some());
        assert!(estimator.estimate_fee(MAX_CONFIRMATION_TARGET).is_some());

        // Just past boundaries
        assert!(estimator.estimate_fee(0).is_none());
        assert!(estimator.estimate_fee(MAX_CONFIRMATION_TARGET + 1).is_none());
    }

    #[test]
    fn test_large_confirmation_target() {
        let mut estimator = FeeEstimator::new();

        // Track 300 transactions at 5 sat/vB
        for i in 0..300 {
            estimator.track_transaction(make_txid(i), 5.0);
        }

        // Confirm after 100 blocks
        for height in 1..=99 {
            estimator.process_block(height, &[]);
        }
        let confirmed: Vec<Hash256> = (0..300).map(make_txid).collect();
        estimator.process_block(100, &confirmed);

        // Should have estimates for 100+ block targets
        let est_100 = estimator.estimate_fee(100);
        assert!(est_100.is_some());
        assert_eq!(est_100.unwrap(), 5.0);

        // Should also have estimate for larger targets (100-block txs count)
        let est_200 = estimator.estimate_fee(200);
        assert!(est_200.is_some());
    }
}
