//! Bitcoin fee estimation algorithm.
//!
//! The fee estimator tracks confirmation times of past transactions to predict
//! the fee rate needed for a transaction to confirm within a target number of blocks.
//!
//! # Algorithm
//!
//! The estimator uses three independent `TxConfirmStats` instances (SHORT, MEDIUM, LONG),
//! matching Bitcoin Core's `CBlockPolicyEstimator`. Each horizon has its own exponential
//! decay constant, scale factor, and number of periods:
//!
//! - **SHORT**:  12 periods,  scale=1,  decay=0.962   (half-life ~18 blocks)
//! - **MEDIUM**: 24 periods,  scale=2,  decay=0.9952  (half-life ~144 blocks)
//! - **LONG**:   42 periods,  scale=24, decay=0.99931 (half-life ~1008 blocks)
//!
//! `estimateSmartFee` dispatches to the appropriate horizon by `conf_target`:
//! - target ≤ 12             → SHORT
//! - target ≤ 48  (24*2)     → MEDIUM
//! - target ≤ 1008 (42*24)   → LONG
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
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
use std::path::Path;

// ─── Core-compatible horizon constants ─────────────────────────────────────

/// SHORT horizon: 12 block periods, scale=1, decay≈0.962 (half-life ~18 blocks).
pub const SHORT_BLOCK_PERIODS: usize = 12;
/// SHORT horizon scale: each period = 1 block.
pub const SHORT_SCALE: usize = 1;
/// SHORT horizon per-block decay factor (matches Core's SHORT_DECAY).
pub const SHORT_DECAY: f64 = 0.962;

/// MEDIUM horizon: 24 block periods, scale=2, decay≈0.9952 (half-life ~144 blocks).
pub const MED_BLOCK_PERIODS: usize = 24;
/// MEDIUM horizon scale: each period = 2 blocks.
pub const MED_SCALE: usize = 2;
/// MEDIUM horizon per-block decay factor (matches Core's MED_DECAY).
pub const MED_DECAY: f64 = 0.9952;

/// LONG horizon: 42 block periods, scale=24, decay≈0.99931 (half-life ~1008 blocks).
pub const LONG_BLOCK_PERIODS: usize = 42;
/// LONG horizon scale: each period = 24 blocks.
pub const LONG_SCALE: usize = 24;
/// LONG horizon per-block decay factor (matches Core's LONG_DECAY).
pub const LONG_DECAY: f64 = 0.99931;

/// Maximum confirmation target (approximately one week of blocks).
/// Derived from LONG_BLOCK_PERIODS * LONG_SCALE = 42 * 24 = 1008.
const MAX_CONFIRMATION_TARGET: usize = LONG_BLOCK_PERIODS * LONG_SCALE; // 1008

/// Fee rate buckets (in sat/vB) with logarithmic spacing.
///
/// Finer granularity at low fee rates (where most transactions cluster)
/// and coarser granularity at high fee rates.
const FEE_RATE_BUCKETS: &[f64] = &[
    1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 10.0, 12.0, 14.0, 17.0, 20.0, 25.0, 30.0, 40.0, 50.0,
    60.0, 70.0, 80.0, 100.0, 120.0, 140.0, 170.0, 200.0, 250.0, 300.0, 400.0, 500.0, 600.0, 700.0,
    800.0, 1000.0, 1200.0, 1400.0, 1700.0, 2000.0, 3000.0, 5000.0, 10000.0,
];

/// Minimum number of tracked transactions (after decay) before making estimates.
const MIN_TRACKED_TXS: f64 = 200.0;

/// Desired success threshold for fee estimates (85%).
const SUCCESS_THRESHOLD: f64 = 0.85;

// ─── Horizon enum ───────────────────────────────────────────────────────────

/// Fee estimation horizon — controls which TxConfirmStats instance to query.
///
/// Maps to Core's three `TxConfirmStats` instances: `feeStats` (SHORT),
/// `shortStats` (MEDIUM), and `longStats` (LONG).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Horizon {
    /// Short horizon: targets ≤ SHORT_BLOCK_PERIODS (12) blocks.
    Short,
    /// Medium horizon: targets ≤ MED_BLOCK_PERIODS * MED_SCALE (48) blocks.
    Medium,
    /// Long horizon: targets ≤ LONG_BLOCK_PERIODS * LONG_SCALE (1008) blocks.
    Long,
}

impl Horizon {
    /// Return the decay constant for this horizon.
    pub fn decay(self) -> f64 {
        match self {
            Horizon::Short => SHORT_DECAY,
            Horizon::Medium => MED_DECAY,
            Horizon::Long => LONG_DECAY,
        }
    }

    /// Return the scale (blocks per period) for this horizon.
    pub fn scale(self) -> usize {
        match self {
            Horizon::Short => SHORT_SCALE,
            Horizon::Medium => MED_SCALE,
            Horizon::Long => LONG_SCALE,
        }
    }

    /// Return the number of periods tracked by this horizon.
    pub fn periods(self) -> usize {
        match self {
            Horizon::Short => SHORT_BLOCK_PERIODS,
            Horizon::Medium => MED_BLOCK_PERIODS,
            Horizon::Long => LONG_BLOCK_PERIODS,
        }
    }

    /// Maximum block target covered by this horizon (periods * scale).
    pub fn max_target(self) -> usize {
        self.periods() * self.scale()
    }
}

/// Choose the appropriate horizon for a given confirmation target.
///
/// Mirrors Core's horizon selection in `estimateSmartFee`:
/// - target ≤ 12         → SHORT
/// - target ≤ 48 (24*2)  → MEDIUM
/// - target ≤ 1008       → LONG
fn horizon_for_target(conf_target: usize) -> Horizon {
    if conf_target <= SHORT_BLOCK_PERIODS {
        Horizon::Short
    } else if conf_target <= MED_BLOCK_PERIODS * MED_SCALE {
        Horizon::Medium
    } else {
        Horizon::Long
    }
}

// ─── TxConfirmStats ─────────────────────────────────────────────────────────

/// Statistics for one fee-rate bucket within a single horizon.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct BucketStats {
    /// Exponentially-decayed count of transactions that confirmed within each period.
    /// Indexed 0..=periods (period 0 unused; period k = confirmed within k periods).
    confirmed_within: Vec<f64>,
    /// Exponentially-decayed total count of transactions in this bucket.
    total: f64,
    /// Exponentially-decayed sum of fees (for computing averages).
    fee_sum: f64,
}

impl BucketStats {
    fn new(periods: usize) -> Self {
        Self {
            confirmed_within: vec![0.0; periods + 1],
            total: 0.0,
            fee_sum: 0.0,
        }
    }

    /// Apply per-block decay.
    fn decay(&mut self, factor: f64) {
        for val in &mut self.confirmed_within {
            *val *= factor;
        }
        self.total *= factor;
        self.fee_sum *= factor;
    }
}

/// One independent TxConfirmStats instance — mirrors Core's `TxConfirmStats` class.
///
/// Each of SHORT, MEDIUM, and LONG gets one instance, with its own decay constant,
/// scale factor, and period count.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct TxConfirmStats {
    /// Per-bucket statistics.
    buckets: Vec<BucketStats>,
    /// Decay factor applied each block.
    decay: f64,
    /// Scale: number of blocks per period.
    scale: usize,
    /// Number of periods tracked.
    periods: usize,
}

impl TxConfirmStats {
    fn new(decay: f64, scale: usize, periods: usize) -> Self {
        let num_buckets = FEE_RATE_BUCKETS.len();
        Self {
            buckets: (0..num_buckets).map(|_| BucketStats::new(periods)).collect(),
            decay,
            scale,
            periods,
        }
    }

    /// Apply per-block decay to all buckets.
    fn decay_all(&mut self) {
        let factor = self.decay;
        for bucket in &mut self.buckets {
            bucket.decay(factor);
        }
    }

    /// Record a confirmed transaction.
    ///
    /// `blocks_to_confirm` is the raw block count. We convert to a period index
    /// (ceiling division) and update all periods ≥ that index.
    fn record(&mut self, bucket_index: usize, fee_rate: f64, blocks_to_confirm: usize) {
        if blocks_to_confirm == 0 || blocks_to_confirm > self.periods * self.scale {
            return;
        }
        // Convert blocks → period (1-based, ceiling division).
        let period = blocks_to_confirm.div_ceil(self.scale).max(1);
        let bucket = &mut self.buckets[bucket_index];
        bucket.total += 1.0;
        bucket.fee_sum += fee_rate;
        // Cumulative fill: also confirmed within any larger period.
        for p in period..=self.periods {
            if let Some(v) = bucket.confirmed_within.get_mut(p) {
                *v += 1.0;
            }
        }
    }

    /// Estimate the minimum fee rate achieving `SUCCESS_THRESHOLD` within `conf_target` blocks.
    ///
    /// Returns `None` if insufficient data.
    fn estimate(&self, conf_target: usize) -> Option<f64> {
        if conf_target == 0 || conf_target > self.periods * self.scale {
            return None;
        }
        // Convert target blocks → period index (ceiling).
        let period = conf_target.div_ceil(self.scale).max(1);
        if period > self.periods {
            return None;
        }

        let mut best_rate: Option<f64> = None;
        let mut total_confirmed = 0.0f64;
        let mut total_tracked = 0.0f64;

        // Scan from highest fee rate to lowest.
        for (i, bucket) in self.buckets.iter().enumerate().rev() {
            if bucket.total < 0.001 {
                continue;
            }
            total_confirmed += bucket.confirmed_within.get(period).copied().unwrap_or(0.0);
            total_tracked += bucket.total;

            if total_tracked < MIN_TRACKED_TXS {
                continue;
            }

            let success_rate = total_confirmed / total_tracked;
            if success_rate >= SUCCESS_THRESHOLD {
                best_rate = Some(FEE_RATE_BUCKETS[i]);
            } else {
                break;
            }
        }
        best_rate
    }

    /// Per-bucket raw statistics for a given target (for `estimaterawfee`).
    fn raw_bucket_stats(&self, conf_target: usize) -> Vec<RawBucketStats> {
        let period = if conf_target == 0 || self.scale == 0 {
            1
        } else {
            conf_target.div_ceil(self.scale).max(1).min(self.periods)
        };
        let n = FEE_RATE_BUCKETS.len();
        let mut out = Vec::with_capacity(n);
        for (i, bucket) in self.buckets.iter().enumerate() {
            let start = FEE_RATE_BUCKETS[i];
            let end = if i + 1 < n { FEE_RATE_BUCKETS[i + 1] } else { FEE_RATE_BUCKETS[i] };
            let confirmed = bucket.confirmed_within.get(period).copied().unwrap_or(0.0);
            out.push(RawBucketStats {
                startrange: start,
                endrange: end,
                total: bucket.total,
                confirmed,
            });
        }
        out
    }
}

// ─── Public types ───────────────────────────────────────────────────────────

/// Per-bucket statistics surfaced to the RPC layer for `estimaterawfee`.
#[derive(Clone, Debug)]
pub struct RawBucketStats {
    /// Inclusive low end of the bucket fee-rate range (sat/vB).
    pub startrange: f64,
    /// Exclusive high end of the bucket fee-rate range (sat/vB).
    pub endrange: f64,
    /// Decayed total transactions seen in this bucket.
    pub total: f64,
    /// Decayed transactions that confirmed within the requested target.
    pub confirmed: f64,
}

// ─── Tracked transaction ────────────────────────────────────────────────────

/// A transaction being tracked from mempool entry to confirmation.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct TrackedTransaction {
    /// Fee rate in satoshis per virtual byte.
    pub fee_rate: f64,
    /// Index into FEE_RATE_BUCKETS.
    pub bucket_index: usize,
    /// Block height when the transaction entered the mempool.
    pub entered_height: u32,
}

// ─── Persistence ────────────────────────────────────────────────────────────

/// Serializable state for fee estimator persistence.
#[derive(Serialize, Deserialize)]
struct FeeEstimatorState {
    short_stats: TxConfirmStats,
    med_stats: TxConfirmStats,
    long_stats: TxConfirmStats,
    tracked: HashMap<Hash256, TrackedTransaction>,
    current_height: u32,
}

// ─── FeeEstimator ───────────────────────────────────────────────────────────

/// Fee estimator that learns from observed confirmation times.
///
/// Maintains three independent [`TxConfirmStats`] instances (SHORT, MEDIUM, LONG)
/// matching Bitcoin Core's `CBlockPolicyEstimator`. Each instance tracks data with
/// its own decay constant and time scale, preventing cross-horizon contamination.
pub struct FeeEstimator {
    /// SHORT-horizon statistics (decay=0.962, scale=1, periods=12).
    short_stats: TxConfirmStats,
    /// MEDIUM-horizon statistics (decay=0.9952, scale=2, periods=24).
    med_stats: TxConfirmStats,
    /// LONG-horizon statistics (decay=0.99931, scale=24, periods=42).
    long_stats: TxConfirmStats,
    /// Transactions currently being tracked (txid → tracked info).
    tracked: HashMap<Hash256, TrackedTransaction>,
    /// Current block height.
    current_height: u32,
    /// Cached estimates for each confirmation target.
    last_estimates: Vec<Option<f64>>,
}

impl FeeEstimator {
    /// Create a new fee estimator with three independent horizons.
    pub fn new() -> Self {
        Self {
            short_stats: TxConfirmStats::new(SHORT_DECAY, SHORT_SCALE, SHORT_BLOCK_PERIODS),
            med_stats:   TxConfirmStats::new(MED_DECAY,   MED_SCALE,   MED_BLOCK_PERIODS),
            long_stats:  TxConfirmStats::new(LONG_DECAY,  LONG_SCALE,  LONG_BLOCK_PERIODS),
            tracked: HashMap::new(),
            current_height: 0,
            last_estimates: vec![None; MAX_CONFIRMATION_TARGET + 1],
        }
    }

    /// Find the bucket index for a given fee rate (binary search).
    fn fee_rate_to_bucket(&self, fee_rate: f64) -> usize {
        match FEE_RATE_BUCKETS.binary_search_by(|b| b.partial_cmp(&fee_rate).unwrap()) {
            Ok(i) => i,
            Err(i) => {
                if i == 0 { 0 } else { i - 1 }
            }
        }
    }

    /// Return a shared reference to the stats for a given horizon.
    fn stats(&self, horizon: Horizon) -> &TxConfirmStats {
        match horizon {
            Horizon::Short  => &self.short_stats,
            Horizon::Medium => &self.med_stats,
            Horizon::Long   => &self.long_stats,
        }
    }

    /// Begin tracking a transaction when it enters the mempool.
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
    pub fn process_block(&mut self, height: u32, confirmed_txids: &[Hash256]) {
        self.current_height = height;

        // Decay all three horizons independently each block.
        self.short_stats.decay_all();
        self.med_stats.decay_all();
        self.long_stats.decay_all();

        // Process confirmed transactions — record into all three horizons.
        for txid in confirmed_txids {
            if let Some(tracked) = self.tracked.remove(txid) {
                let blocks_to_confirm = height.saturating_sub(tracked.entered_height) as usize;
                if blocks_to_confirm == 0 {
                    continue;
                }
                // Record in all three horizons; each TxConfirmStats::record() ignores
                // blocks_to_confirm values that exceed its own window.
                self.short_stats.record(tracked.bucket_index, tracked.fee_rate, blocks_to_confirm);
                self.med_stats.record(tracked.bucket_index, tracked.fee_rate, blocks_to_confirm);
                self.long_stats.record(tracked.bucket_index, tracked.fee_rate, blocks_to_confirm);
            }
        }

        // Clean up stale tracked transactions.
        self.tracked.retain(|_, tracked| {
            height.saturating_sub(tracked.entered_height) <= MAX_CONFIRMATION_TARGET as u32
        });

        // Update cached estimates.
        for target in 1..=MAX_CONFIRMATION_TARGET {
            self.last_estimates[target] = self.estimate_internal(target);
        }
    }

    /// Internal estimation: dispatch to the correct horizon and call its `estimate()`.
    fn estimate_internal(&self, target: usize) -> Option<f64> {
        let horizon = horizon_for_target(target);
        self.stats(horizon).estimate(target)
    }

    /// Estimate the fee rate needed to confirm within `target` blocks.
    ///
    /// Dispatches to the appropriate horizon (SHORT/MEDIUM/LONG) based on `target`.
    /// Returns the fee rate in sat/vB, or `None` if there is insufficient data.
    pub fn estimate_fee(&self, target: usize) -> Option<f64> {
        if target == 0 || target > MAX_CONFIRMATION_TARGET {
            return None;
        }
        self.last_estimates.get(target).copied().flatten()
    }

    /// Get a conservative estimate (higher fee for higher confidence).
    pub fn estimate_conservative(&self, target: usize) -> Option<f64> {
        let aggressive_target = target / 2;
        let normal = self.estimate_fee(target);
        let aggressive = self.estimate_fee(aggressive_target.max(1));
        match (normal, aggressive) {
            (Some(n), Some(a)) => Some(n.max(a)),
            (Some(n), None)    => Some(n),
            (None, Some(a))    => Some(a),
            (None, None)       => None,
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

    /// Get the decayed total count for a specific bucket in the SHORT horizon (for testing).
    #[cfg(test)]
    fn bucket_total(&self, bucket_index: usize) -> f64 {
        self.short_stats.buckets
            .get(bucket_index)
            .map(|b| b.total)
            .unwrap_or(0.0)
    }

    /// Per-bucket raw statistics for `estimaterawfee`.
    ///
    /// Returns data for the horizon that covers `target`. Use `raw_bucket_stats_horizon`
    /// to query a specific horizon directly.
    pub fn raw_bucket_stats(&self, target: usize) -> Vec<RawBucketStats> {
        let horizon = horizon_for_target(target.max(1));
        self.stats(horizon).raw_bucket_stats(target)
    }

    /// Per-bucket raw statistics for a specific horizon (for three-horizon estimaterawfee output).
    pub fn raw_bucket_stats_horizon(&self, horizon: Horizon, target: usize) -> Vec<RawBucketStats> {
        self.stats(horizon).raw_bucket_stats(target)
    }

    /// Number of fee-rate buckets (constant).
    pub fn bucket_count(&self) -> usize {
        FEE_RATE_BUCKETS.len()
    }

    /// Save fee estimator state to a JSON file.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        let state = FeeEstimatorState {
            short_stats: self.short_stats.clone(),
            med_stats:   self.med_stats.clone(),
            long_stats:  self.long_stats.clone(),
            tracked: self.tracked.clone(),
            current_height: self.current_height,
        };
        let json = serde_json::to_string(&state).map_err(io::Error::other)?;
        let tmp_path = path.with_extension("json.tmp");
        std::fs::write(&tmp_path, &json)?;
        std::fs::rename(&tmp_path, path)?;
        Ok(())
    }

    /// Load fee estimator state from a JSON file.
    ///
    /// Returns a new FeeEstimator with default state if the file doesn't exist
    /// or contains invalid data (safe fallback).
    pub fn load(path: &Path) -> Self {
        let data = match std::fs::read_to_string(path) {
            Ok(d) => d,
            Err(_) => return Self::new(),
        };
        let state: FeeEstimatorState = match serde_json::from_str(&data) {
            Ok(s) => s,
            Err(_) => return Self::new(),
        };
        // Basic sanity checks on loaded stats.
        if state.short_stats.buckets.len() != FEE_RATE_BUCKETS.len()
            || state.med_stats.buckets.len() != FEE_RATE_BUCKETS.len()
            || state.long_stats.buckets.len() != FEE_RATE_BUCKETS.len()
        {
            return Self::new();
        }
        let mut estimator = Self {
            short_stats: state.short_stats,
            med_stats:   state.med_stats,
            long_stats:  state.long_stats,
            tracked: state.tracked,
            current_height: state.current_height,
            last_estimates: vec![None; MAX_CONFIRMATION_TARGET + 1],
        };
        // Rebuild cached estimates from loaded state.
        for target in 1..=MAX_CONFIRMATION_TARGET {
            estimator.last_estimates[target] = estimator.estimate_internal(target);
        }
        estimator
    }
}

impl Default for FeeEstimator {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Unit tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_txid(n: u32) -> Hash256 {
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&n.to_le_bytes());
        Hash256::from_bytes(bytes)
    }

    #[test]
    fn test_fee_rate_to_bucket_exact_values() {
        let estimator = FeeEstimator::new();
        assert_eq!(estimator.fee_rate_to_bucket(1.0), 0);
        assert_eq!(estimator.fee_rate_to_bucket(2.0), 1);
        assert_eq!(estimator.fee_rate_to_bucket(10.0), 8);
        assert_eq!(estimator.fee_rate_to_bucket(100.0), 20);
        assert_eq!(estimator.fee_rate_to_bucket(10000.0), 39);
    }

    #[test]
    fn test_fee_rate_to_bucket_between_values() {
        let estimator = FeeEstimator::new();
        assert_eq!(estimator.fee_rate_to_bucket(1.5), 0);
        assert_eq!(estimator.fee_rate_to_bucket(2.5), 1);
        assert_eq!(estimator.fee_rate_to_bucket(11.0), 8);
        assert_eq!(estimator.fee_rate_to_bucket(150.0), 22);
    }

    #[test]
    fn test_fee_rate_to_bucket_below_minimum() {
        let estimator = FeeEstimator::new();
        assert_eq!(estimator.fee_rate_to_bucket(0.5), 0);
        assert_eq!(estimator.fee_rate_to_bucket(0.1), 0);
    }

    #[test]
    fn test_fee_rate_to_bucket_above_maximum() {
        let estimator = FeeEstimator::new();
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
        assert!(estimator.estimate_fee(1).is_none());
        assert!(estimator.estimate_fee(6).is_none());
        assert!(estimator.estimate_fee(100).is_none());
    }

    #[test]
    fn test_estimate_fee_invalid_targets() {
        let estimator = FeeEstimator::new();
        assert!(estimator.estimate_fee(0).is_none());
        assert!(estimator.estimate_fee(MAX_CONFIRMATION_TARGET + 1).is_none());
        assert!(estimator.estimate_fee(2000).is_none());
    }

    #[test]
    fn test_process_block_with_confirmations() {
        let mut estimator = FeeEstimator::new();
        for i in 0..300 {
            estimator.track_transaction(make_txid(i), 10.0);
        }
        let confirmed: Vec<Hash256> = (0..300).map(make_txid).collect();
        estimator.process_block(1, &confirmed);
        let estimate = estimator.estimate_fee(1);
        assert!(estimate.is_some());
        assert_eq!(estimate.unwrap(), 10.0);
        assert_eq!(estimator.tracked_count(), 0);
    }

    #[test]
    fn test_estimate_fee_multi_block_confirmation() {
        let mut estimator = FeeEstimator::new();
        for i in 0..300 {
            estimator.track_transaction(make_txid(i), 10.0);
        }
        estimator.process_block(1, &[]);
        estimator.process_block(2, &[]);
        estimator.process_block(3, &[]);
        estimator.process_block(4, &[]);
        estimator.process_block(5, &[]);
        let confirmed: Vec<Hash256> = (0..300).map(make_txid).collect();
        estimator.process_block(6, &confirmed);
        let estimate_6 = estimator.estimate_fee(6);
        assert!(estimate_6.is_some());
        assert_eq!(estimate_6.unwrap(), 10.0);
        let estimate_1 = estimator.estimate_fee(1);
        assert!(estimate_1.is_none());
    }

    #[test]
    fn test_estimate_conservative_returns_higher_fee() {
        let mut estimator = FeeEstimator::new();
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
        for i in 300..600 {
            estimator.track_transaction(make_txid(i), 20.0);
        }
        estimator.process_block(7, &[]);
        estimator.process_block(8, &[]);
        let confirmed_high: Vec<Hash256> = (300..600).map(make_txid).collect();
        estimator.process_block(9, &confirmed_high);
        let normal = estimator.estimate_fee(6);
        let conservative = estimator.estimate_conservative(6);
        assert!(normal.is_some());
        assert!(conservative.is_some());
        assert!(conservative.unwrap() >= normal.unwrap());
    }

    #[test]
    fn test_decay_reduces_old_data_influence() {
        let mut estimator = FeeEstimator::new();
        for i in 0..300 {
            estimator.track_transaction(make_txid(i), 10.0);
        }
        let confirmed: Vec<Hash256> = (0..300).map(make_txid).collect();
        estimator.process_block(1, &confirmed);
        let initial_total = estimator.bucket_total(8);
        assert!(initial_total > 0.0);
        for height in 2..=500 {
            estimator.process_block(height, &[]);
        }
        let decayed_total = estimator.bucket_total(8);
        assert!(decayed_total < initial_total);
        assert!(decayed_total < initial_total * 0.5);
    }

    #[test]
    fn test_cleanup_stale_tracked_transactions() {
        let mut estimator = FeeEstimator::new();
        for i in 0..10 {
            estimator.track_transaction(make_txid(i), 10.0);
        }
        assert_eq!(estimator.tracked_count(), 10);
        for height in 1..=(MAX_CONFIRMATION_TARGET as u32 + 10) {
            estimator.process_block(height, &[]);
        }
        assert_eq!(estimator.tracked_count(), 0);
    }

    #[test]
    fn test_transaction_not_confirmed_stays_tracked() {
        let mut estimator = FeeEstimator::new();
        let txid = make_txid(1);
        estimator.track_transaction(txid, 10.0);
        estimator.process_block(1, &[]);
        assert!(estimator.tracked.contains_key(&txid));
        assert_eq!(estimator.tracked_count(), 1);
    }

    #[test]
    fn test_mixed_fee_rates_estimation() {
        let mut estimator = FeeEstimator::new();
        // Use 400 high-fee txs confirming in 1 block.
        // After 13 further blocks of SHORT decay: 400 * 0.962^13 ≈ 242 > MIN_TRACKED_TXS=200,
        // so the 1-block SHORT-horizon estimate remains valid until block 14.
        for i in 0..400 {
            estimator.track_transaction(make_txid(i), 100.0);
        }
        let high_confirmed: Vec<Hash256> = (0..400).map(make_txid).collect();
        estimator.process_block(1, &high_confirmed);
        for i in 400..700 {
            estimator.track_transaction(make_txid(i), 10.0);
        }
        estimator.process_block(2, &[]);
        estimator.process_block(3, &[]);
        let medium_confirmed: Vec<Hash256> = (400..700).map(make_txid).collect();
        estimator.process_block(4, &medium_confirmed);
        for i in 700..1000 {
            estimator.track_transaction(make_txid(i), 2.0);
        }
        for height in 5..=13 {
            estimator.process_block(height, &[]);
        }
        let low_confirmed: Vec<Hash256> = (700..1000).map(make_txid).collect();
        estimator.process_block(14, &low_confirmed);
        let est_1 = estimator.estimate_fee(1);
        assert!(est_1.is_some());
        assert_eq!(est_1.unwrap(), 100.0);
        let est_3 = estimator.estimate_fee(3);
        assert!(est_3.is_some());
        let est_10 = estimator.estimate_fee(10);
        assert!(est_10.is_some());
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
        estimator.process_block(5, &[]);
        let txid = make_txid(1);
        estimator.track_transaction(txid, 10.0);
        estimator.process_block(5, &[txid]);
    }

    #[test]
    fn test_estimate_fee_boundary_targets() {
        let mut estimator = FeeEstimator::new();
        for i in 0..300 {
            estimator.track_transaction(make_txid(i), 10.0);
        }
        let confirmed: Vec<Hash256> = (0..300).map(make_txid).collect();
        estimator.process_block(1, &confirmed);
        assert!(estimator.estimate_fee(1).is_some());
        assert!(estimator.estimate_fee(MAX_CONFIRMATION_TARGET).is_some());
        assert!(estimator.estimate_fee(0).is_none());
        assert!(estimator.estimate_fee(MAX_CONFIRMATION_TARGET + 1).is_none());
    }

    #[test]
    fn test_large_confirmation_target() {
        let mut estimator = FeeEstimator::new();
        for i in 0..300 {
            estimator.track_transaction(make_txid(i), 5.0);
        }
        for height in 1..=99 {
            estimator.process_block(height, &[]);
        }
        let confirmed: Vec<Hash256> = (0..300).map(make_txid).collect();
        estimator.process_block(100, &confirmed);
        let est_100 = estimator.estimate_fee(100);
        assert!(est_100.is_some());
        assert_eq!(est_100.unwrap(), 5.0);
        let est_200 = estimator.estimate_fee(200);
        assert!(est_200.is_some());
    }

    // ─── 3-horizon architecture tests ───────────────────────────────────────

    #[test]
    fn test_three_horizon_decay_constants() {
        // Verify the three public decay constants match Core's values.
        assert!((SHORT_DECAY - 0.962).abs() < 1e-6,
            "SHORT_DECAY should be 0.962, got {}", SHORT_DECAY);
        assert!((MED_DECAY - 0.9952).abs() < 1e-6,
            "MED_DECAY should be 0.9952, got {}", MED_DECAY);
        assert!((LONG_DECAY - 0.99931).abs() < 1e-6,
            "LONG_DECAY should be 0.99931, got {}", LONG_DECAY);
    }

    #[test]
    fn test_three_horizon_period_constants() {
        assert_eq!(SHORT_BLOCK_PERIODS, 12, "SHORT_BLOCK_PERIODS must be 12");
        assert_eq!(MED_BLOCK_PERIODS,   24, "MED_BLOCK_PERIODS must be 24");
        assert_eq!(LONG_BLOCK_PERIODS,  42, "LONG_BLOCK_PERIODS must be 42");
    }

    #[test]
    fn test_three_horizon_scale_constants() {
        assert_eq!(SHORT_SCALE,  1, "SHORT_SCALE must be 1");
        assert_eq!(MED_SCALE,    2, "MED_SCALE must be 2");
        assert_eq!(LONG_SCALE,  24, "LONG_SCALE must be 24");
    }

    #[test]
    fn test_horizon_dispatch() {
        assert_eq!(horizon_for_target(1),   Horizon::Short,  "target 1 → Short");
        assert_eq!(horizon_for_target(12),  Horizon::Short,  "target 12 → Short");
        assert_eq!(horizon_for_target(13),  Horizon::Medium, "target 13 → Medium");
        assert_eq!(horizon_for_target(48),  Horizon::Medium, "target 48 → Medium");
        assert_eq!(horizon_for_target(49),  Horizon::Long,   "target 49 → Long");
        assert_eq!(horizon_for_target(1008),Horizon::Long,   "target 1008 → Long");
    }

    #[test]
    fn test_horizons_have_independent_stats() {
        let mut estimator = FeeEstimator::new();
        // Confirm 300 txs in 1 block (goes into SHORT horizon, period 1).
        for i in 0..300 {
            estimator.track_transaction(make_txid(i), 10.0);
        }
        let confirmed: Vec<Hash256> = (0..300).map(make_txid).collect();
        estimator.process_block(1, &confirmed);

        // SHORT horizon (target ≤ 12) should have estimate.
        assert!(estimator.estimate_fee(1).is_some(), "SHORT horizon estimate missing");
        // Check short_stats directly has data.
        assert!(estimator.short_stats.buckets[8].total > 0.0,
            "short_stats should have data for 10 sat/vB bucket");
        // Check med_stats also got the data (all 3 horizons are fed the same confirmation).
        assert!(estimator.med_stats.buckets[8].total > 0.0,
            "med_stats should also have data for 10 sat/vB bucket");
        assert!(estimator.long_stats.buckets[8].total > 0.0,
            "long_stats should also have data for 10 sat/vB bucket");
    }

    #[test]
    fn test_short_and_long_decay_differ() {
        // After 18 blocks, short horizon should decay far more than long.
        let mut estimator = FeeEstimator::new();
        for i in 0..300 {
            estimator.track_transaction(make_txid(i), 10.0);
        }
        let confirmed: Vec<Hash256> = (0..300).map(make_txid).collect();
        estimator.process_block(1, &confirmed);

        let short_after_1 = estimator.short_stats.buckets[8].total;
        let long_after_1  = estimator.long_stats.buckets[8].total;
        assert!(short_after_1 > 0.0);
        assert!(long_after_1 > 0.0);

        // Decay 18 more empty blocks.
        for h in 2..=19 {
            estimator.process_block(h, &[]);
        }
        let short_after_19 = estimator.short_stats.buckets[8].total;
        let long_after_19  = estimator.long_stats.buckets[8].total;

        // SHORT_DECAY^18 ≈ 0.962^18 ≈ 0.500 → half the data gone.
        // LONG_DECAY^18  ≈ 0.99931^18 ≈ 0.988 → nearly unchanged.
        let short_ratio = short_after_19 / short_after_1;
        let long_ratio  = long_after_19  / long_after_1;
        assert!(short_ratio < 0.55,
            "SHORT horizon should have decayed >45% after 18 blocks (got ratio {})", short_ratio);
        assert!(long_ratio > 0.97,
            "LONG horizon should have decayed <3% after 18 blocks (got ratio {})", long_ratio);
        // The two ratios should be clearly different.
        assert!(short_ratio < long_ratio - 0.3,
            "Short decay ratio ({}) should be much less than long decay ratio ({})",
            short_ratio, long_ratio);
    }

    #[test]
    fn test_estimaterawfee_all_three_horizons_accessible() {
        let mut estimator = FeeEstimator::new();
        for i in 0..300 {
            estimator.track_transaction(make_txid(i), 10.0);
        }
        let confirmed: Vec<Hash256> = (0..300).map(make_txid).collect();
        estimator.process_block(1, &confirmed);

        // Each horizon should return a full bucket array.
        let short_stats  = estimator.raw_bucket_stats_horizon(Horizon::Short, 6);
        let medium_stats = estimator.raw_bucket_stats_horizon(Horizon::Medium, 6);
        let long_stats   = estimator.raw_bucket_stats_horizon(Horizon::Long, 6);
        assert_eq!(short_stats.len(),  FEE_RATE_BUCKETS.len());
        assert_eq!(medium_stats.len(), FEE_RATE_BUCKETS.len());
        assert_eq!(long_stats.len(),   FEE_RATE_BUCKETS.len());
        // The 10 sat/vB bucket (index 8) should have data in all three horizons.
        assert!(short_stats[8].total > 0.0);
        assert!(medium_stats[8].total > 0.0);
        assert!(long_stats[8].total > 0.0);
    }

    #[test]
    fn test_max_confirmation_target_is_1008() {
        assert_eq!(MAX_CONFIRMATION_TARGET, 1008,
            "MAX_CONFIRMATION_TARGET must be LONG_BLOCK_PERIODS*LONG_SCALE = 42*24 = 1008");
    }
}
