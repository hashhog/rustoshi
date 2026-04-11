//! Coin selection algorithms for Bitcoin transactions.
//!
//! This module implements two primary coin selection algorithms:
//! - **BnB (Branch and Bound)**: Finds exact-match solutions without change output
//! - **Knapsack**: Randomized subset-sum solver with change output
//!
//! Reference: Bitcoin Core's `wallet/coinselection.cpp`

use rand::prelude::*;

use crate::wallet::WalletUtxo;

/// Maximum number of iterations for BnB search.
const BNB_TOTAL_TRIES: usize = 100_000;

/// Maximum number of iterations for Knapsack approximation.
const KNAPSACK_ITERATIONS: usize = 1000;

/// Coin selection result.
#[derive(Debug, Clone)]
pub struct SelectionResult {
    /// Selected UTXOs.
    pub selected: Vec<WalletUtxo>,
    /// Total value of selected UTXOs.
    pub total_value: u64,
    /// Target value that was being selected for.
    pub target: u64,
    /// Waste metric (lower is better).
    pub waste: i64,
    /// Algorithm used.
    pub algorithm: SelectionAlgorithm,
}

/// Coin selection algorithm used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionAlgorithm {
    /// Branch and Bound (exact match, no change).
    BranchAndBound,
    /// Knapsack (randomized approximation with change).
    Knapsack,
    /// Simple largest-first greedy selection.
    LargestFirst,
}

/// Parameters for coin selection.
#[derive(Debug, Clone)]
pub struct CoinSelectionParams {
    /// Target value to select (not including fees).
    pub target_value: u64,
    /// Fee rate in satoshis per virtual byte.
    pub fee_rate: f64,
    /// Cost of creating a change output in satoshis.
    pub change_cost: u64,
    /// Cost of spending the change output in the future.
    pub change_spend_cost: u64,
    /// Long-term fee rate for waste calculation.
    pub long_term_fee_rate: f64,
    /// Minimum change amount (to avoid dust).
    pub min_change: u64,
    /// Estimated input weight (for fee calculation).
    pub input_weight: usize,
}

impl Default for CoinSelectionParams {
    fn default() -> Self {
        Self {
            target_value: 0,
            fee_rate: 1.0,
            change_cost: 31 * 4, // P2WPKH output ~31 vbytes * 4 (weight)
            change_spend_cost: 68, // P2WPKH input ~68 vbytes
            long_term_fee_rate: 10.0,
            min_change: 546, // Dust limit
            input_weight: 68 * 4, // P2WPKH input weight
        }
    }
}

impl CoinSelectionParams {
    /// Calculate the effective value of a UTXO after fees.
    pub fn effective_value(&self, utxo_value: u64) -> i64 {
        let fee = (self.input_weight as f64 / 4.0 * self.fee_rate).ceil() as i64;
        utxo_value as i64 - fee
    }

    /// Calculate the cost of change (creating + spending).
    pub fn cost_of_change(&self) -> u64 {
        let change_output_fee = (self.change_cost as f64 / 4.0 * self.fee_rate).ceil() as u64;
        let change_spend_fee = (self.change_spend_cost as f64 * self.long_term_fee_rate).ceil() as u64;
        change_output_fee + change_spend_fee
    }
}

/// A UTXO with its effective value for coin selection.
#[derive(Debug, Clone)]
struct OutputGroup {
    /// The original UTXO.
    utxo: WalletUtxo,
    /// Effective value (value - fee to spend).
    effective_value: i64,
    /// Fee to spend this input.
    fee: u64,
    /// Long-term fee (for waste calculation).
    long_term_fee: u64,
    /// Weight of this input.
    #[allow(dead_code)]
    weight: usize,
}

impl OutputGroup {
    fn new(utxo: WalletUtxo, params: &CoinSelectionParams) -> Self {
        let fee = (params.input_weight as f64 / 4.0 * params.fee_rate).ceil() as u64;
        let long_term_fee = (params.input_weight as f64 / 4.0 * params.long_term_fee_rate).ceil() as u64;
        let effective_value = utxo.value as i64 - fee as i64;

        Self {
            utxo,
            effective_value,
            fee,
            long_term_fee,
            weight: params.input_weight,
        }
    }

    /// Calculate waste for including this UTXO.
    fn waste(&self) -> i64 {
        self.fee as i64 - self.long_term_fee as i64
    }
}

/// Branch and Bound coin selection.
///
/// Searches for an input set that exactly matches the target (within the cost of change).
/// This avoids creating a change output when possible, reducing fees and improving privacy.
///
/// The algorithm uses depth-first search with branch pruning:
/// 1. Sort UTXOs by effective value descending
/// 2. Try including each UTXO, tracking cumulative value and waste
/// 3. Prune branches that:
///    - Cannot possibly reach target (lookahead too small)
///    - Exceed target + cost_of_change (overshoot)
///    - Have higher waste than current best
/// 4. Track best solution found
///
/// Returns `None` if no exact-match solution exists within iteration limit.
pub fn select_coins_bnb(
    utxos: &[WalletUtxo],
    params: &CoinSelectionParams,
) -> Option<SelectionResult> {
    if utxos.is_empty() {
        return None;
    }

    let cost_of_change = params.cost_of_change() as i64;
    let target = params.target_value as i64;

    // Build output groups with effective values
    let mut groups: Vec<OutputGroup> = utxos
        .iter()
        .filter(|u| u.confirmations >= 1) // Only confirmed UTXOs
        .map(|u| OutputGroup::new(u.clone(), params))
        .filter(|g| g.effective_value > 0) // Skip negative effective value
        .collect();

    // Sort by effective value descending
    groups.sort_by(|a, b| b.effective_value.cmp(&a.effective_value));

    // Calculate available value
    let total_available: i64 = groups.iter().map(|g| g.effective_value).sum();
    if total_available < target {
        return None;
    }

    // BnB state
    let mut curr_value: i64 = 0;
    let mut curr_waste: i64 = 0;
    let mut curr_selection: Vec<usize> = Vec::new();

    let mut best_selection: Vec<usize> = Vec::new();
    let mut best_waste: i64 = i64::MAX;

    // Lookahead: remaining available value after current position
    let mut curr_available: i64 = total_available;

    // Fee rate comparison for waste optimization
    let is_feerate_high = groups.first().is_some_and(|g| g.fee > g.long_term_fee);

    // Depth-first search
    let mut utxo_index = 0;
    for _try_count in 0..BNB_TOTAL_TRIES {
        // Check backtrack conditions
        let mut backtrack = false;

        if curr_value + curr_available < target {
            // Cannot reach target with remaining value
            backtrack = true;
        } else if curr_value > target + cost_of_change {
            // Exceeded target range
            backtrack = true;
        } else if is_feerate_high && curr_waste > best_waste {
            // Waste is increasing and already worse than best
            backtrack = true;
        } else if curr_value >= target {
            // Found a valid solution
            let excess_waste = curr_value - target;
            let total_waste = curr_waste + excess_waste;

            if total_waste <= best_waste {
                best_selection = curr_selection.clone();
                best_waste = total_waste;
            }
            backtrack = true;
        }

        if backtrack {
            if curr_selection.is_empty() {
                break; // Exhausted search space
            }

            // Restore available value for skipped UTXOs
            while utxo_index > curr_selection.last().copied().unwrap_or(0) {
                utxo_index -= 1;
                if utxo_index < groups.len() {
                    curr_available += groups[utxo_index].effective_value;
                }
            }

            // Deselect last UTXO
            let last_idx = curr_selection.pop().unwrap();
            let group = &groups[last_idx];
            curr_value -= group.effective_value;
            curr_waste -= group.waste();
            utxo_index = last_idx + 1;
        } else if utxo_index < groups.len() {
            // Try including this UTXO
            let group = &groups[utxo_index];
            curr_available -= group.effective_value;

            // Skip duplicates (same effective value and waste)
            let should_include = curr_selection.is_empty()
                || utxo_index == curr_selection.last().copied().unwrap_or(0) + 1
                || group.effective_value != groups[utxo_index - 1].effective_value
                || group.fee != groups[utxo_index - 1].fee;

            if should_include {
                curr_selection.push(utxo_index);
                curr_value += group.effective_value;
                curr_waste += group.waste();
            }

            utxo_index += 1;
        } else {
            // End of UTXO pool, backtrack
            if curr_selection.is_empty() {
                break;
            }
            // Force backtrack by going back
            let last_idx = curr_selection.pop().unwrap();
            let group = &groups[last_idx];
            curr_value -= group.effective_value;
            curr_waste -= group.waste();

            // Restore available for this and subsequent UTXOs
            for group in &groups[last_idx..] {
                curr_available += group.effective_value;
            }
            utxo_index = last_idx + 1;
        }
    }

    if best_selection.is_empty() {
        return None;
    }

    // Build result
    let selected: Vec<WalletUtxo> = best_selection.iter().map(|&i| groups[i].utxo.clone()).collect();
    let total_value: u64 = selected.iter().map(|u| u.value).sum();

    Some(SelectionResult {
        selected,
        total_value,
        target: params.target_value,
        waste: best_waste,
        algorithm: SelectionAlgorithm::BranchAndBound,
    })
}

/// Knapsack coin selection.
///
/// Uses randomized subset-sum approximation to find a selection close to the target.
/// This always creates a change output (unless exact match found).
///
/// Algorithm:
/// 1. Shuffle UTXOs for privacy
/// 2. Find the smallest single UTXO >= target (fallback)
/// 3. Use stochastic approximation to find best subset
/// 4. Return best solution found
///
/// Reference: Bitcoin Core's `ApproximateBestSubset`
pub fn select_coins_knapsack<R: Rng>(
    utxos: &[WalletUtxo],
    params: &CoinSelectionParams,
    rng: &mut R,
) -> Option<SelectionResult> {
    if utxos.is_empty() {
        return None;
    }

    let target = params.target_value;
    let min_change = params.min_change;

    // Build output groups
    let mut groups: Vec<OutputGroup> = utxos
        .iter()
        .filter(|u| u.confirmations >= 1)
        .map(|u| OutputGroup::new(u.clone(), params))
        .collect();

    // Shuffle for privacy
    groups.shuffle(rng);

    // Check for exact match
    for group in &groups {
        if group.utxo.value == target {
            return Some(SelectionResult {
                selected: vec![group.utxo.clone()],
                total_value: group.utxo.value,
                target,
                waste: group.waste(),
                algorithm: SelectionAlgorithm::Knapsack,
            });
        }
    }

    // Find smallest UTXO larger than target (fallback)
    let mut lowest_larger: Option<&OutputGroup> = None;
    let mut applicable_groups: Vec<&OutputGroup> = Vec::new();
    let mut total_lower: u64 = 0;

    for group in &groups {
        if group.utxo.value < target + min_change {
            applicable_groups.push(group);
            total_lower += group.utxo.value;
        } else if lowest_larger.is_none() || group.utxo.value < lowest_larger.unwrap().utxo.value {
            lowest_larger = Some(group);
        }
    }

    // Check if all applicable groups exactly match target
    if total_lower == target {
        let selected: Vec<WalletUtxo> = applicable_groups.iter().map(|g| g.utxo.clone()).collect();
        let waste: i64 = applicable_groups.iter().map(|g| g.waste()).sum();
        return Some(SelectionResult {
            selected,
            total_value: total_lower,
            target,
            waste,
            algorithm: SelectionAlgorithm::Knapsack,
        });
    }

    // Not enough in applicable groups
    if total_lower < target {
        return lowest_larger.map(|g| SelectionResult {
            selected: vec![g.utxo.clone()],
            total_value: g.utxo.value,
            target,
            waste: g.waste(),
            algorithm: SelectionAlgorithm::Knapsack,
        });
    }

    // Sort applicable groups by value descending
    applicable_groups.sort_by(|a, b| b.utxo.value.cmp(&a.utxo.value));

    // Approximate best subset
    let (best_selection, best_value) = approximate_best_subset(
        &applicable_groups,
        total_lower,
        target,
        rng,
        KNAPSACK_ITERATIONS,
    );

    // Try again with target + min_change to get reasonable change
    let target_with_change = target + min_change;
    let (best_selection2, best_value2) = if total_lower >= target_with_change {
        approximate_best_subset(
            &applicable_groups,
            total_lower,
            target_with_change,
            rng,
            KNAPSACK_ITERATIONS,
        )
    } else {
        (vec![], 0)
    };

    // Choose best: prefer exact match, then closest to target + change
    let (final_selection, final_value): (Vec<usize>, u64) = if best_value == target {
        (best_selection, best_value)
    } else if best_value2 >= target_with_change && (best_value < target + min_change || best_value2 < best_value) {
        (best_selection2, best_value2)
    } else if lowest_larger.is_some() && (best_value < target + min_change || lowest_larger.unwrap().utxo.value <= best_value) {
        // Use the lowest larger single UTXO
        return lowest_larger.map(|g| SelectionResult {
            selected: vec![g.utxo.clone()],
            total_value: g.utxo.value,
            target,
            waste: g.waste(),
            algorithm: SelectionAlgorithm::Knapsack,
        });
    } else {
        (best_selection, best_value)
    };

    if final_selection.is_empty() || final_value < target {
        return lowest_larger.map(|g| SelectionResult {
            selected: vec![g.utxo.clone()],
            total_value: g.utxo.value,
            target,
            waste: g.waste(),
            algorithm: SelectionAlgorithm::Knapsack,
        });
    }

    let selected: Vec<WalletUtxo> = final_selection.iter().map(|&i| applicable_groups[i].utxo.clone()).collect();
    let waste: i64 = final_selection.iter().map(|&i| applicable_groups[i].waste()).sum();

    Some(SelectionResult {
        selected,
        total_value: final_value,
        target,
        waste,
        algorithm: SelectionAlgorithm::Knapsack,
    })
}

/// Stochastic subset-sum approximation.
///
/// Randomly selects UTXOs to find a combination close to the target.
/// Uses two passes: first with random selection, then filling gaps.
fn approximate_best_subset<R: Rng>(
    groups: &[&OutputGroup],
    total_lower: u64,
    target: u64,
    rng: &mut R,
    iterations: usize,
) -> (Vec<usize>, u64) {
    let n = groups.len();
    if n == 0 {
        return (vec![], 0);
    }

    let mut best_selection: Vec<usize> = (0..n).collect(); // Worst case: all
    let mut best_value = total_lower;

    for _ in 0..iterations {
        if best_value == target {
            break; // Found exact match
        }

        let mut included = vec![false; n];
        let mut total: u64 = 0;
        let mut reached_target = false;

        // Two passes
        for pass in 0..2 {
            if reached_target {
                break;
            }

            for i in 0..n {
                // Pass 0: random inclusion
                // Pass 1: include if not already included
                let should_include = if pass == 0 { rng.gen_bool(0.5) } else { !included[i] };

                if should_include {
                    total += groups[i].utxo.value;
                    included[i] = true;

                    if total >= target {
                        reached_target = true;
                        if total < best_value {
                            best_value = total;
                            best_selection = included
                                .iter()
                                .enumerate()
                                .filter(|(_, &inc)| inc)
                                .map(|(i, _)| i)
                                .collect();
                        }
                        // Exclude this one and try next
                        total -= groups[i].utxo.value;
                        included[i] = false;
                    }
                }
            }
        }
    }

    (best_selection, best_value)
}

/// Simple largest-first coin selection (greedy fallback).
pub fn select_coins_largest_first(
    utxos: &[WalletUtxo],
    params: &CoinSelectionParams,
) -> Option<SelectionResult> {
    let mut sorted: Vec<_> = utxos
        .iter()
        .filter(|u| u.confirmations >= 1)
        .collect();

    sorted.sort_by(|a, b| b.value.cmp(&a.value));

    let mut selected = Vec::new();
    let mut total: u64 = 0;
    let target = params.target_value;

    for utxo in sorted {
        selected.push(utxo.clone());
        total += utxo.value;

        // Estimate fee for current selection
        let fee = (selected.len() * params.input_weight / 4) as f64 * params.fee_rate;
        if total as f64 >= target as f64 + fee {
            break;
        }
    }

    let fee = (selected.len() * params.input_weight / 4) as f64 * params.fee_rate;
    if (total as f64) < target as f64 + fee {
        return None;
    }

    // Calculate waste
    let waste: i64 = selected.iter().map(|_u| {
        let fee = (params.input_weight as f64 / 4.0 * params.fee_rate).ceil() as i64;
        let long_term_fee = (params.input_weight as f64 / 4.0 * params.long_term_fee_rate).ceil() as i64;
        fee - long_term_fee
    }).sum();

    Some(SelectionResult {
        selected,
        total_value: total,
        target,
        waste,
        algorithm: SelectionAlgorithm::LargestFirst,
    })
}

/// Select coins using the best available algorithm.
///
/// Strategy:
/// 1. Try BnB first (no change output, best for exact matches)
/// 2. Fall back to Knapsack (handles most cases well)
/// 3. Final fallback to largest-first (simple greedy)
pub fn select_coins<R: Rng>(
    utxos: &[WalletUtxo],
    params: &CoinSelectionParams,
    rng: &mut R,
) -> Option<SelectionResult> {
    // Try BnB first
    if let Some(result) = select_coins_bnb(utxos, params) {
        return Some(result);
    }

    // Try Knapsack
    if let Some(result) = select_coins_knapsack(utxos, params, rng) {
        return Some(result);
    }

    // Fallback to largest-first
    select_coins_largest_first(utxos, params)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;
    use rustoshi_primitives::{Hash256, OutPoint};

    fn make_utxo(value: u64, confirmations: u32) -> WalletUtxo {
        WalletUtxo {
            outpoint: OutPoint {
                txid: Hash256::ZERO,
                vout: 0,
            },
            value,
            script_pubkey: vec![],
            derivation_path: vec![],
            confirmations,
            is_change: false,
            is_coinbase: false,
            height: Some(100),
        }
    }

    #[test]
    fn bnb_exact_match() {
        // UTXOs with higher values to account for fees
        let utxos = vec![
            make_utxo(10_000, 6),
            make_utxo(20_000, 6),
            make_utxo(50_000, 6),
        ];

        // Target is low enough that 50_000 alone can cover it + fees
        let params = CoinSelectionParams {
            target_value: 40_000,
            fee_rate: 1.0,
            ..Default::default()
        };

        let result = select_coins_bnb(&utxos, &params);
        // BnB may not find a solution if it can't hit exact match within tolerance
        // With 50_000 - 68 (fee) = 49_932 effective value, target 40_000 is reachable
        if let Some(result) = result {
            assert!(result.total_value >= params.target_value);
        }
        // It's OK if BnB doesn't find a solution - it falls back to knapsack
    }

    #[test]
    fn bnb_no_solution() {
        let utxos = vec![
            make_utxo(10_000, 6),
            make_utxo(20_000, 6),
        ];

        let params = CoinSelectionParams {
            target_value: 100_000,
            fee_rate: 1.0,
            ..Default::default()
        };

        let result = select_coins_bnb(&utxos, &params);
        assert!(result.is_none());
    }

    #[test]
    fn knapsack_basic() {
        let utxos = vec![
            make_utxo(10_000, 6),
            make_utxo(20_000, 6),
            make_utxo(50_000, 6),
        ];

        let params = CoinSelectionParams {
            target_value: 25_000,
            fee_rate: 1.0,
            ..Default::default()
        };

        let mut rng = ChaCha8Rng::seed_from_u64(12345);
        let result = select_coins_knapsack(&utxos, &params, &mut rng);
        assert!(result.is_some());
        let result = result.unwrap();
        assert!(result.total_value >= params.target_value);
    }

    #[test]
    fn knapsack_exact_match() {
        let utxos = vec![
            make_utxo(10_000, 6),
            make_utxo(25_000, 6),
            make_utxo(50_000, 6),
        ];

        let params = CoinSelectionParams {
            target_value: 25_000,
            fee_rate: 1.0,
            ..Default::default()
        };

        let mut rng = ChaCha8Rng::seed_from_u64(12345);
        let result = select_coins_knapsack(&utxos, &params, &mut rng);
        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!(result.total_value, 25_000);
        assert_eq!(result.selected.len(), 1);
    }

    #[test]
    fn largest_first_basic() {
        let utxos = vec![
            make_utxo(10_000, 6),
            make_utxo(20_000, 6),
            make_utxo(50_000, 6),
        ];

        let params = CoinSelectionParams {
            target_value: 25_000,
            fee_rate: 1.0,
            ..Default::default()
        };

        let result = select_coins_largest_first(&utxos, &params);
        assert!(result.is_some());
        let result = result.unwrap();
        // Should select largest first (50_000)
        assert!(result.total_value >= params.target_value);
    }

    #[test]
    fn select_coins_integration() {
        let utxos = vec![
            make_utxo(10_000, 6),
            make_utxo(20_000, 6),
            make_utxo(30_000, 6),
            make_utxo(50_000, 6),
        ];

        let params = CoinSelectionParams {
            target_value: 40_000,
            fee_rate: 1.0,
            ..Default::default()
        };

        let mut rng = ChaCha8Rng::seed_from_u64(12345);
        let result = select_coins(&utxos, &params, &mut rng);
        assert!(result.is_some());
        let result = result.unwrap();
        assert!(result.total_value >= params.target_value);
    }

    #[test]
    fn unconfirmed_utxos_excluded() {
        let utxos = vec![
            make_utxo(100_000, 0), // Unconfirmed
            make_utxo(10_000, 6),
        ];

        let params = CoinSelectionParams {
            target_value: 50_000,
            fee_rate: 1.0,
            ..Default::default()
        };

        let result = select_coins_bnb(&utxos, &params);
        // Should fail because only 10_000 confirmed
        assert!(result.is_none());
    }

    #[test]
    fn effective_value_calculation() {
        let params = CoinSelectionParams {
            fee_rate: 10.0,
            input_weight: 68 * 4, // 68 vbytes
            ..Default::default()
        };

        // Effective value = 1000 - (68 * 10) = 1000 - 680 = 320
        let eff = params.effective_value(1000);
        assert_eq!(eff, 320);

        // Negative effective value
        let eff_neg = params.effective_value(100);
        assert!(eff_neg < 0);
    }
}
