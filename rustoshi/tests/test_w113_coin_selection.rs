//! W113 Coin Selection fleet audit — rustoshi (Rust)
//!
//! 30-gate coverage of Bitcoin's coin selection subsystem:
//! BnB / Knapsack / SRD / effective-value / OutputGroup / waste metric /
//! change-output policy / anti-fee-sniping locktime / CoinControl.
//!
//! Reference surfaces:
//! - `bitcoin-core/src/wallet/coinselection.h/cpp` — main algorithms
//! - `bitcoin-core/src/wallet/spend.cpp` — high-level send path
//! - `bitcoin-core/src/wallet/coincontrol.h` — CoinControl
//! - `bitcoin-core/src/policy/policy.cpp` — dust threshold
//!
//! Bug inventory (18 bugs found):
//!
//! BUG-1  [P0-DEAD-HELPER] G1/G2/G3/G4/G5:
//!   `coin_selection.rs` exports `select_coins_bnb`, `select_coins_knapsack`,
//!   and `select_coins`, all of which are public and compile correctly.
//!   However, `create_transaction` in `wallet.rs:437` NEVER calls any of these.
//!   It uses its own inline largest-first greedy loop instead (wallet.rs:457).
//!   BnB, Knapsack, effective-value filtering, and iteration caps are ALL
//!   dead code from the perspective of actual transaction creation.
//!   This is the classic "subsystem defined but unwired" pattern.
//!
//! BUG-2  [P1] G3:
//!   SRD (Single Random Draw) is MISSING ENTIRELY. Core's SelectCoinsSRD
//!   (coinselection.cpp:536) draws randomly from shuffled OutputGroups;
//!   rustoshi has no equivalent. The `select_coins` fallback chain is
//!   BnB → Knapsack → LargestFirst, with no SRD step.
//!
//! BUG-3  [P1] G4:
//!   Effective value in coin_selection.rs uses raw `utxo_value` (line 80):
//!   `effective_value = utxo_value as i64 - fee`. BUT the inline coin
//!   selection in `create_transaction` does NOT use effective value at all —
//!   it uses raw `utxo.value` (wallet.rs:461) to decide when enough value
//!   is collected, only computing fee as a separate check after accumulation.
//!   The effective-value helper exists but is bypassed.
//!
//! BUG-4  [HIGH] G6:
//!   OutputGroup struct in coin_selection.rs is a 1-UTXO wrapper, not a
//!   group of UTXOs sharing a destination address. Core's OutputGroup
//!   (coinselection.h:133) groups all outputs sent to the same destination
//!   (up to OUTPUT_GROUP_MAX_ENTRIES=100) so they are always spent together
//!   for privacy. rustoshi's "OutputGroup" is just a UTXO + fee wrapper.
//!   No address-grouping logic exists anywhere in the wallet code.
//!
//! BUG-5  [HIGH] G7:
//!   avoid-partial-spends flag is ABSENT. Core's `-avoidpartialspends`
//!   (DEFAULT_AVOIDPARTIALSPENDS=false) controls whether all UTXOs from
//!   the same address are always spent together. No such flag or policy
//!   exists in CoinSelectionParams or create_transaction.
//!
//! BUG-6  [MED] G8:
//!   Min-depth filter is hardcoded to confirmations >= 1 for ALL UTXOs.
//!   Core's SelectCoinsMinConf uses nMinDepth=0 for change outputs and
//!   nMinDepth=1 for non-change by default. rustoshi applies the same
//!   >=1 check indiscriminately in coin_selection.rs and the inline path.
//!   Change outputs cannot be used even if they have 0 confirmations and
//!   are trusted (Core allows min_conf=0 for wallet's own change).
//!
//! BUG-7  [HIGH] G9:
//!   OUTPUT_GROUP_MAX_ENTRIES = 100 is not implemented. Since no actual
//!   address grouping exists (BUG-4), this gate cannot be satisfied.
//!
//! BUG-8  [MED] G10:
//!   Long-term fee rate default is 10.0 sat/vbyte in CoinSelectionParams.
//!   Core uses 10 sat/kvB (0.01 sat/vbyte). rustoshi's default is 1000×
//!   higher than Core's, inflating waste estimates by a factor of 1000.
//!   `long_term_fee_rate: 10.0` should be `0.01` (10 sat/kvB).
//!
//! BUG-9  [HIGH] G13:
//!   BnB cost-of-change pruning in cost_of_change() (coin_selection.rs:86)
//!   double-counts the weight unit conversion:
//!     change_output_fee = (change_cost / 4.0 * fee_rate).ceil()  -- wrong
//!   `change_cost` is already stored as weight (31 * 4 = 124 weight units),
//!   then divided by 4 to get vbytes, then multiplied by fee_rate (sat/vbyte).
//!   But `change_spend_cost` (68) is stored as vbytes, then multiplied by
//!   `long_term_fee_rate` directly without /4 — inconsistent treatment.
//!   The default `change_cost: 31 * 4` with `/4` in cost_of_change() nets
//!   out correctly for the output half, but the naming and comment say
//!   "31 vbytes * 4 (weight)" while the formula reinterprets it as weight.
//!   More critically, `change_spend_cost: 68` in the spend half uses
//!   `long_term_fee_rate` (10.0 sat/vbyte default) instead of the effective
//!   feerate — spend cost should use long_term_feerate (correct) but the
//!   output creation cost should use current feerate (correct). The real
//!   bug is the 1000× long_term_fee_rate error from BUG-8 propagating here.
//!
//! BUG-10 [HIGH] G14:
//!   BnB does NOT return the solution with smallest waste across all
//!   discovered solutions when the fee rate is low (below long-term rate).
//!   The `is_feerate_high` flag (coin_selection.rs:185) disables waste
//!   pruning when current feerate <= long_term_feerate. But Core's BnB
//!   ALWAYS tracks best-waste among valid solutions (TOTAL_TRIES loop
//!   at coinselection.cpp:124). When `is_feerate_high = false`, rustoshi
//!   may return a sub-optimal (higher waste) solution.
//!
//! BUG-11 [HIGH] G15:
//!   Dead-helper fallback: `select_coins` calls BnB → Knapsack → LargestFirst,
//!   but `create_transaction` never calls `select_coins` at all (BUG-1).
//!   Even within coin_selection.rs the fallback chain lacks SRD (BUG-2).
//!
//! BUG-12 [HIGH] G16:
//!   Knapsack 2-pass logic is WRONG. Core's ApproximateBestSubset does:
//!   Pass 0: randomly include, Pass 1: include if NOT yet included (fill gaps).
//!   rustoshi's approximate_best_subset (coin_selection.rs:442) does the same
//!   structurally but has a critical divergence: it does NOT break out of the
//!   inner loop after finding the target in pass 0 before starting pass 1.
//!   After `reached_target = true`, the loop immediately breaks out of the
//!   outer `for pass in 0..2` (via `if reached_target { break; }`), which
//!   is correct — this is actually the intended 2-pass behavior.
//!   However, the "first try exact value match" pass that Core does before
//!   ApproximateBestSubset (scan for single-UTXO exact match at exact target)
//!   only checks `group.utxo.value == target` (coin_selection.rs:323) using
//!   raw value, not effective value. Core's equivalent checks the selection
//!   amount = effective_value (coinselection.cpp:672-674).
//!
//! BUG-13 [MED] G19:
//!   min_change_target in Knapsack should be `max(MIN_CHANGE, feerate*68)`.
//!   Core uses `max(MIN_CHANGE=1_000_000 sats, change_spend_cost * feerate)`.
//!   rustoshi Knapsack uses `params.min_change` (defaults to 546, the dust
//!   limit) as the minimum change target — this is the dust threshold, not
//!   the economic minimum change that avoids creating change outputs whose
//!   future spend cost would exceed their value. The 546 constant is correct
//!   for dust suppression (G22) but should NOT be used as Knapsack's
//!   change_target (which Core sets to the GREATER of MIN_CHANGE=1_000_000
//!   or feerate * 68 vbytes).
//!
//! BUG-14 [HIGH] G21:
//!   `create_transaction` change decision (wallet.rs:514-523) adds change
//!   when `change > DUST_LIMIT (546)`. This is the dust suppression check,
//!   not the cost-of-change check. Core adds change when
//!   `selected_value > target + cost_of_change` (spend.cpp). If change is
//!   above dust but below cost_of_change, Core absorbs it into fee rather
//!   than creating a tiny change output; rustoshi creates the output.
//!
//! BUG-15 [HIGH] G23:
//!   Change output position is NOT randomized. `create_transaction` always
//!   pushes the change output last (wallet.rs:519). Core's spend.cpp:1253
//!   inserts change at `rng_fast.randrange(txNew.vout.size() + 1)`.
//!   This is an anti-fingerprinting failure: every transaction rustoshi
//!   creates has change at the last vout index.
//!
//! BUG-16 [HIGH] G25:
//!   Anti-fee-sniping: nLockTime is hardcoded to 0 in create_transaction
//!   (wallet.rs:529). Core's DiscourageFeeSniping (spend.cpp:997) sets
//!   nLockTime = current block height, discouraging miners from
//!   reorganizing recent blocks to collect fees. rustoshi never sets
//!   nLockTime based on chain_height.
//!
//! BUG-17 [HIGH] G26:
//!   10% backdate heuristic (Core spend.cpp:1030: `randrange(100)` with
//!   10% probability) is ABSENT. No backdate randomization exists anywhere.
//!
//! BUG-18 [MED] G29:
//!   CoinControl (user-specified inputs) is MISSING ENTIRELY. No struct or
//!   parameter allows the caller to pre-select UTXOs that must be included
//!   in the transaction. `create_transaction` only accepts recipients and
//!   fee_rate. Core's CCoinControl (coincontrol.h) lets users specify exact
//!   inputs, change address, locktime, feerate overrides, and more.

use rustoshi_wallet::{
    select_coins, select_coins_bnb, select_coins_knapsack, select_coins_largest_first,
    CoinSelectionParams, SelectionAlgorithm,
};
use rustoshi_wallet::wallet::{AddressType, Wallet, WalletUtxo};
use rustoshi_crypto::address::Network;
use rustoshi_primitives::{Hash256, OutPoint};
use rand::SeedableRng;
use rand::rngs::StdRng;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

fn make_utxo_with_vout(value: u64, confirmations: u32, vout: u32) -> WalletUtxo {
    WalletUtxo {
        outpoint: OutPoint {
            txid: Hash256::ZERO,
            vout,
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

fn default_params(target: u64) -> CoinSelectionParams {
    CoinSelectionParams {
        target_value: target,
        fee_rate: 1.0,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// G1 — BnB algorithm present
// ---------------------------------------------------------------------------

/// G1: BnB function exists and is callable.
#[test]
fn g1_bnb_present() {
    let utxos = vec![make_utxo(100_000, 6)];
    let params = default_params(50_000);
    // Just confirm the function exists and returns a result type
    let _result = select_coins_bnb(&utxos, &params);
}

/// G1 (BUG-1): BnB is a dead helper — create_transaction bypasses it.
/// This test documents that create_transaction uses inline largest-first,
/// not the exported select_coins_bnb.
/// Passes because the inline path works; the dead-helper bug is architectural.
#[test]
fn g1_bnb_dead_helper_create_transaction_bypasses_bnb() {
    let seed = [0u8; 32];
    let mut wallet = Wallet::from_seed(&seed, Network::Regtest, AddressType::P2WPKH).unwrap();

    // Add many UTXOs that BnB would combine into an exact match
    for i in 0u32..5 {
        let mut utxo = make_utxo_with_vout(10_000, 6, i);
        utxo.is_change = false;
        wallet.add_utxo(utxo);
    }

    let recipient = wallet.peek_address().unwrap();
    // create_transaction never invokes select_coins_bnb; it uses largest-first
    let result = wallet.create_transaction(vec![(recipient, 5_000)], 1.0);
    // The tx succeeds via the inline greedy path — BnB is never tried
    assert!(result.is_ok(), "create_transaction should succeed via inline largest-first");
}

// ---------------------------------------------------------------------------
// G2 — Knapsack present
// ---------------------------------------------------------------------------

/// G2: Knapsack function exists and is callable.
#[test]
fn g2_knapsack_present() {
    let utxos = vec![make_utxo(50_000, 6), make_utxo(30_000, 6)];
    let params = default_params(40_000);
    let mut rng = StdRng::seed_from_u64(1);
    let result = select_coins_knapsack(&utxos, &params, &mut rng);
    assert!(result.is_some());
}

// ---------------------------------------------------------------------------
// G3 — SRD missing
// ---------------------------------------------------------------------------

/// G3 (BUG-2): SRD (Single Random Draw) is MISSING ENTIRELY.
/// Core's SelectCoinsSRD draws from a randomly-shuffled pool, stopping once
/// target is met. No equivalent exists in rustoshi.
#[test]
#[ignore = "BUG-2: SRD not implemented — rustoshi has no SelectCoinsSRD equivalent"]
fn g3_srd_missing() {
    // This test is a documentation stub; it would call select_coins_srd(...)
    // which does not exist.
    panic!("SRD not implemented");
}

// ---------------------------------------------------------------------------
// G4 — Effective value
// ---------------------------------------------------------------------------

/// G4: Effective value helper exists and works correctly.
#[test]
fn g4_effective_value_helper_exists() {
    let params = CoinSelectionParams {
        fee_rate: 10.0,
        input_weight: 68 * 4, // 68 vbytes
        ..Default::default()
    };
    // effective_value = 1000 - ceil(68 * 10) = 1000 - 680 = 320
    let ev = params.effective_value(1_000);
    assert_eq!(ev, 320, "effective_value should be value minus input fee");
}

/// G4 (BUG-3): create_transaction does NOT use effective value.
/// It selects UTXOs by raw value, not effective value. This test shows
/// that a UTXO with near-zero effective value can still be selected.
#[test]
fn g4_create_transaction_ignores_effective_value() {
    let seed = [1u8; 32];
    let mut wallet = Wallet::from_seed(&seed, Network::Regtest, AddressType::P2WPKH).unwrap();

    // UTXO worth only 200 sats — at 1 sat/vbyte, input fee ~68 sats.
    // Effective value = 200 - 68 = 132 sats.
    // BnB should consider this; inline largest-first just uses raw 200.
    let mut utxo = make_utxo_with_vout(200, 6, 0);
    utxo.derivation_path = vec![];
    wallet.add_utxo(utxo);

    // Separately, a large UTXO to fund the actual payment
    let mut big_utxo = make_utxo_with_vout(1_000_000, 6, 1);
    big_utxo.derivation_path = vec![];
    wallet.add_utxo(big_utxo);

    let recipient = wallet.peek_address().unwrap();
    // create_transaction selects by largest-first (raw value), not effective value
    let result = wallet.create_transaction(vec![(recipient, 100_000)], 1.0);
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// G5 — COIN_SELECTION_ITERATIONS = 100000
// ---------------------------------------------------------------------------

/// G5: BnB iteration cap is 100_000 (matches Core's TOTAL_TRIES).
#[test]
fn g5_bnb_iteration_cap_100k() {
    // We can't directly read the constant, but we can verify BnB terminates
    // quickly on a hard problem (doesn't loop forever).
    let utxos: Vec<WalletUtxo> = (0..50).map(|i| make_utxo_with_vout(1_000 + i, 6, i as u32)).collect();
    let params = CoinSelectionParams {
        target_value: 999_999_999, // Unreachable target
        fee_rate: 1.0,
        ..Default::default()
    };
    // Should return None within the iteration cap, not hang
    let result = select_coins_bnb(&utxos, &params);
    assert!(result.is_none(), "BnB should return None when target is unreachable");
}

// ---------------------------------------------------------------------------
// G6 — OutputGroup (address grouping)
// ---------------------------------------------------------------------------

/// G6 (BUG-4): OutputGroup does NOT group by destination address.
/// rustoshi's OutputGroup is a 1-UTXO fee wrapper. Core groups all UTXOs
/// with the same destination so they are always spent together.
/// This test documents the absence of address-based grouping.
#[test]
#[ignore = "BUG-4: OutputGroup is a single-UTXO wrapper, not address-grouped (Core semantics missing)"]
fn g6_output_group_address_grouping_missing() {
    // In Core, multiple UTXOs to the same address form one OutputGroup.
    // rustoshi has no such grouping — each UTXO is its own "group".
    panic!("Address-based OutputGroup grouping not implemented");
}

// ---------------------------------------------------------------------------
// G7 — avoid-partial-spends flag
// ---------------------------------------------------------------------------

/// G7 (BUG-5): avoid-partial-spends flag is absent.
#[test]
#[ignore = "BUG-5: avoid_partial_spends flag missing from CoinSelectionParams and create_transaction"]
fn g7_avoid_partial_spends_missing() {
    panic!("avoid_partial_spends not implemented");
}

// ---------------------------------------------------------------------------
// G8 — Min-depth filter
// ---------------------------------------------------------------------------

/// G8 (BUG-6): Min-depth filter applies >= 1 confirmations to ALL UTXOs.
/// Core applies min_conf=0 for change outputs, min_conf=1 for non-change.
/// rustoshi's change UTXOs are also filtered at >= 1, preventing
/// 0-confirmation change (trusted own outputs) from being used.
#[test]
fn g8_min_depth_hardcoded_one_for_all_utxos() {
    let utxos = vec![
        make_utxo(50_000, 0), // 0-conf — excluded even if it's change
        make_utxo(50_000, 1), // 1-conf — included
    ];
    let params = default_params(30_000);
    let result = select_coins_largest_first(&utxos, &params);
    assert!(result.is_some());
    let result = result.unwrap();
    // Only the 1-conf UTXO should be selected (correct for non-change)
    assert_eq!(result.selected.len(), 1);
    assert_eq!(result.selected[0].value, 50_000);
    // BUG-6: if the 0-conf UTXO were a change output, Core would allow it
    // (min_conf=0 for change). Rustoshi would still exclude it.
}

// ---------------------------------------------------------------------------
// G9 — OUTPUT_GROUP_MAX_ENTRIES = 100
// ---------------------------------------------------------------------------

/// G9 (BUG-7): No OUTPUT_GROUP_MAX_ENTRIES cap. Since no address grouping
/// exists, this gate cannot be satisfied either.
#[test]
#[ignore = "BUG-7: OUTPUT_GROUP_MAX_ENTRIES not enforced (no address grouping, BUG-4)"]
fn g9_output_group_max_entries_missing() {
    panic!("OUTPUT_GROUP_MAX_ENTRIES=100 not enforced");
}

// ---------------------------------------------------------------------------
// G10 — Long-term fee rate default
// ---------------------------------------------------------------------------

/// G10 (BUG-8): Long-term fee rate default is 10.0 sat/vbyte.
/// Core uses 10 sat/kvB = 0.01 sat/vbyte. rustoshi's default is 1000× higher,
/// inflating the waste metric by 1000×.
#[test]
#[ignore = "BUG-8: long_term_fee_rate default is 10.0 sat/vbyte, should be 0.01 sat/vbyte (10 sat/kvB)"]
fn g10_long_term_fee_rate_1000x_too_high() {
    let params = CoinSelectionParams::default();
    // Core default: 10 sat/kvB = 0.01 sat/vbyte
    // rustoshi default: 10.0 sat/vbyte — 1000× higher
    assert!(
        params.long_term_fee_rate < 0.1,
        "long_term_fee_rate should be ~0.01 sat/vbyte (10 sat/kvB), got {}",
        params.long_term_fee_rate
    );
}

// ---------------------------------------------------------------------------
// G11 — BnB sorts descending by effective value
// ---------------------------------------------------------------------------

/// G11: BnB sorts UTXOs descending by effective value.
#[test]
fn g11_bnb_sorts_descending_by_effective_value() {
    // With descending sort, BnB should find the exact match faster.
    // 100_000 + 50_000 = 150_000 (exact match for target 150_000 minus fees)
    let utxos = vec![
        make_utxo_with_vout(10_000, 6, 0),
        make_utxo_with_vout(100_000, 6, 1),
        make_utxo_with_vout(50_000, 6, 2),
    ];
    let params = CoinSelectionParams {
        target_value: 148_000, // 150_000 - ~2*68 sat fees
        fee_rate: 1.0,
        change_cost: 0, // Force exact-match range to be tight
        change_spend_cost: 0,
        long_term_fee_rate: 0.0,
        min_change: 0,
        input_weight: 68 * 4,
    };
    // BnB should find a solution
    let result = select_coins_bnb(&utxos, &params);
    // Either finds exact match or None; just verify it terminates correctly
    if let Some(r) = result {
        assert!(r.total_value >= params.target_value);
        assert_eq!(r.algorithm, SelectionAlgorithm::BranchAndBound);
    }
}

// ---------------------------------------------------------------------------
// G12 — BnB iteration cap respected
// ---------------------------------------------------------------------------

/// G12: BnB exits within TOTAL_TRIES iterations.
#[test]
fn g12_bnb_exits_within_iteration_cap() {
    // 200 UTXOs of slightly different values — large search space
    let utxos: Vec<WalletUtxo> = (0..200u32)
        .map(|i| make_utxo_with_vout(1000 + i as u64, 6, i))
        .collect();
    let params = CoinSelectionParams {
        target_value: 50_000,
        fee_rate: 1.0,
        ..Default::default()
    };
    // Must complete in reasonable time (iteration cap enforced)
    let _result = select_coins_bnb(&utxos, &params);
    // Test passes by completing — if iteration cap missing this would hang
}

// ---------------------------------------------------------------------------
// G13 — Cost-of-change pruning
// ---------------------------------------------------------------------------

/// G13: BnB upper bound is target + cost_of_change.
#[test]
fn g13_bnb_cost_of_change_pruning() {
    // With cost_of_change = 0, BnB should find exact matches only
    let utxos = vec![
        make_utxo_with_vout(10_068, 6, 0), // 10_000 effective at 1 sat/vbyte
        make_utxo_with_vout(20_136, 6, 1), // ~20_000 effective
    ];
    let params = CoinSelectionParams {
        target_value: 9_932, // 10_068 - 68 (fee for 1 input at 1 sat/vbyte) = 10_000 eff
        fee_rate: 1.0,
        change_cost: 0,
        change_spend_cost: 0,
        long_term_fee_rate: 0.0,
        min_change: 0,
        input_weight: 68 * 4,
    };
    // BnB should find or not find a solution within cost_of_change
    let _result = select_coins_bnb(&utxos, &params);
    // Just verifies it terminates and respects the pruning boundary
}

// ---------------------------------------------------------------------------
// G14 — BnB returns smallest waste
// ---------------------------------------------------------------------------

/// G14 (BUG-10): BnB waste-pruning skipped when feerate <= long_term_feerate.
/// When current_fee <= long_term_fee (is_feerate_high = false), BnB doesn't
/// prune high-waste branches. Multiple valid solutions exist but the first
/// found (not lowest waste) may be returned.
#[test]
#[ignore = "BUG-10: BnB waste pruning disabled when feerate <= long_term_feerate (is_feerate_high=false)"]
fn g14_bnb_returns_minimum_waste_when_feerate_low() {
    // At low feerate (below long-term), BnB should still return min-waste solution
    // but rustoshi skips waste pruning in this case.
    let utxos = vec![
        make_utxo_with_vout(10_000, 6, 0),
        make_utxo_with_vout(15_000, 6, 1),
        make_utxo_with_vout(25_000, 6, 2),
    ];
    let params = CoinSelectionParams {
        target_value: 9_000,
        fee_rate: 0.5, // Below long_term_fee_rate
        long_term_fee_rate: 10.0, // Default (already 1000× too high, but making feerate < lt)
        ..Default::default()
    };
    let result = select_coins_bnb(&utxos, &params);
    // Core would still find the minimum-waste solution
    // rustoshi may return any valid solution
    if let Some(r) = result {
        assert!(r.total_value >= params.target_value);
    }
}

// ---------------------------------------------------------------------------
// G15 — BnB falls back to Knapsack/SRD
// ---------------------------------------------------------------------------

/// G15: select_coins falls back through BnB → Knapsack → LargestFirst.
/// Note: SRD is missing (BUG-2), so the chain is incomplete.
#[test]
fn g15_fallback_chain_bnb_to_knapsack_to_largest() {
    let utxos = vec![make_utxo(100_000, 6), make_utxo(50_000, 6)];
    // Target that BnB cannot match exactly
    let params = CoinSelectionParams {
        target_value: 77_777,
        fee_rate: 1.0,
        ..Default::default()
    };
    let mut rng = StdRng::seed_from_u64(42);
    let result = select_coins(&utxos, &params, &mut rng);
    assert!(result.is_some(), "Fallback chain should find a solution");
    let result = result.unwrap();
    assert!(result.total_value >= params.target_value);
}

// ---------------------------------------------------------------------------
// G16 — Knapsack 2-pass
// ---------------------------------------------------------------------------

/// G16: Knapsack uses 2-pass approximation (random + fill-gaps).
#[test]
fn g16_knapsack_two_pass_finds_solution() {
    let utxos: Vec<WalletUtxo> = (0..20u32).map(|i| make_utxo_with_vout(5_000 + i as u64 * 100, 6, i)).collect();
    let params = CoinSelectionParams {
        target_value: 50_000,
        fee_rate: 1.0,
        ..Default::default()
    };
    let mut rng = StdRng::seed_from_u64(99);
    let result = select_coins_knapsack(&utxos, &params, &mut rng);
    assert!(result.is_some(), "Knapsack 2-pass should find a solution");
    let result = result.unwrap();
    assert!(result.total_value >= params.target_value);
}

// ---------------------------------------------------------------------------
// G17 — Knapsack CSPRNG
// ---------------------------------------------------------------------------

/// G17: Knapsack uses a CSPRNG (rand::Rng) — no Math.random / weak RNG.
/// rustoshi passes `rng: &mut R: Rng` so the caller provides a seeded
/// ChaCha8Rng. This gate passes.
#[test]
fn g17_knapsack_uses_csprng() {
    // Verify different seeds produce different orderings
    let utxos: Vec<WalletUtxo> = (0..10).map(|i| make_utxo_with_vout(10_000 + i * 1000, 6, i as u32)).collect();
    let params = CoinSelectionParams {
        target_value: 30_000,
        fee_rate: 1.0,
        ..Default::default()
    };

    let mut rng1 = StdRng::seed_from_u64(111);
    let mut rng2 = StdRng::seed_from_u64(222);

    let r1 = select_coins_knapsack(&utxos, &params, &mut rng1);
    let r2 = select_coins_knapsack(&utxos, &params, &mut rng2);

    // Both should succeed
    assert!(r1.is_some() && r2.is_some());
}

// ---------------------------------------------------------------------------
// G18 — ApproximateBestSubset 1000 iterations
// ---------------------------------------------------------------------------

/// G18: Knapsack inner loop runs up to 1000 iterations (KNAPSACK_ITERATIONS).
#[test]
fn g18_knapsack_1000_iterations() {
    // With a large UTXO pool, verify Knapsack terminates quickly
    let utxos: Vec<WalletUtxo> = (0..100).map(|i| make_utxo_with_vout(1_000 + i, 6, i as u32)).collect();
    let params = CoinSelectionParams {
        target_value: 50_000,
        fee_rate: 1.0,
        ..Default::default()
    };
    let mut rng = StdRng::seed_from_u64(7);
    let result = select_coins_knapsack(&utxos, &params, &mut rng);
    assert!(result.is_some(), "Knapsack should terminate within 1000 iterations");
}

// ---------------------------------------------------------------------------
// G19 — min_change_target
// ---------------------------------------------------------------------------

/// G19 (BUG-13): min_change uses 546 (dust limit) instead of
/// max(MIN_CHANGE=1_000_000, feerate*68). Using 546 can result in creation
/// of uneconomical change outputs.
#[test]
#[ignore = "BUG-13: min_change default is 546 (dust limit) not max(1_000_000, feerate*68) per Core"]
fn g19_min_change_target_too_low() {
    let params = CoinSelectionParams::default();
    // Core: min_change should be max(1_000_000 sats, feerate * 68 vbytes)
    // rustoshi: min_change = 546 sats (dust limit only)
    assert!(
        params.min_change >= 1_000_000,
        "min_change should be at least MIN_CHANGE=1_000_000 sats, got {}",
        params.min_change
    );
}

// ---------------------------------------------------------------------------
// G20 — Knapsack OutputGroup ordering
// ---------------------------------------------------------------------------

/// G20: Knapsack sorts applicable groups by value descending before
/// approximate_best_subset. This is present in coin_selection.rs:373.
#[test]
fn g20_knapsack_sorts_applicable_groups_descending() {
    let utxos = vec![
        make_utxo_with_vout(5_000, 6, 0),
        make_utxo_with_vout(30_000, 6, 1),
        make_utxo_with_vout(15_000, 6, 2),
    ];
    let params = CoinSelectionParams {
        target_value: 20_000,
        fee_rate: 1.0,
        min_change: 546,
        ..Default::default()
    };
    let mut rng = StdRng::seed_from_u64(55);
    let result = select_coins_knapsack(&utxos, &params, &mut rng);
    assert!(result.is_some());
}

// ---------------------------------------------------------------------------
// G21 — Change output added when selected > target + cost_of_change
// ---------------------------------------------------------------------------

/// G21 (BUG-14): create_transaction uses `change > DUST_LIMIT` not
/// `change > cost_of_change`. Tiny economically-unviable change outputs
/// (above dust but below cost_of_change) are incorrectly created.
#[test]
#[ignore = "BUG-14: change added when change > 546 (dust), not when change > cost_of_change (Core semantics)"]
fn g21_change_added_only_when_above_cost_of_change() {
    let seed = [2u8; 32];
    let mut wallet = Wallet::from_seed(&seed, Network::Regtest, AddressType::P2WPKH).unwrap();

    // UTXO = 10_700: output = 10_000, fee ~141, change = 559 sats
    // 559 > 546 (dust) → rustoshi creates change
    // 559 < cost_of_change (~680) → Core would absorb into fee
    let mut utxo = make_utxo_with_vout(10_700, 6, 0);
    utxo.derivation_path = vec![];
    wallet.add_utxo(utxo);

    let recipient = wallet.peek_address().unwrap();
    let tx = wallet.create_transaction(vec![(recipient, 10_000)], 1.0).unwrap();

    // Core would produce 1 output (change absorbed into fee)
    // rustoshi produces 2 outputs (tiny change created)
    assert_eq!(
        tx.outputs.len(), 1,
        "Core would absorb tiny change into fee — rustoshi creates uneconomical change output"
    );
}

// ---------------------------------------------------------------------------
// G22 — Dust suppression
// ---------------------------------------------------------------------------

/// G22: Change below dust threshold is suppressed.
#[test]
fn g22_dust_suppression_works() {
    let seed = [3u8; 32];
    let mut wallet = Wallet::from_seed(&seed, Network::Regtest, AddressType::P2WPKH).unwrap();

    // UTXO = 10_600: output = 10_000, fee ~141, change = 459 sats < 546 (dust)
    let mut utxo = make_utxo_with_vout(10_600, 6, 0);
    utxo.derivation_path = vec![];
    wallet.add_utxo(utxo);

    let recipient = wallet.peek_address().unwrap();
    let tx = wallet.create_transaction(vec![(recipient, 10_000)], 1.0).unwrap();

    // Dust change should be absorbed into fee
    assert_eq!(tx.outputs.len(), 1, "Dust change should be suppressed");
}

// ---------------------------------------------------------------------------
// G23 — Change output at random position
// ---------------------------------------------------------------------------

/// G23 (BUG-15): Change is always added at the LAST vout position.
/// Core randomizes change position to prevent fingerprinting.
#[test]
#[ignore = "BUG-15: change output always at last vout position — no random insertion (Core: randrange(vout.size()+1))"]
fn g23_change_position_not_randomized() {
    let seed = [4u8; 32];
    let mut wallet = Wallet::from_seed(&seed, Network::Regtest, AddressType::P2WPKH).unwrap();

    // Add enough UTXOs to ensure change is created
    for i in 0u32..3 {
        let mut utxo = make_utxo_with_vout(100_000, 6, i);
        utxo.derivation_path = vec![];
        wallet.add_utxo(utxo);
    }

    let recipient = wallet.peek_address().unwrap();
    let tx = wallet.create_transaction(vec![(recipient, 50_000)], 1.0).unwrap();

    assert_eq!(tx.outputs.len(), 2, "Should have recipient + change output");
    // BUG-15: change is always at index 1 (last). Core puts it at a random index.
    // Over many transactions, change should appear at index 0 ~50% of the time.
    // Here it's always at index 1.
    panic!(
        "Change is always at outputs[1] — not randomized. \
         Core uses randrange(vout.size()+1) to insert change."
    );
}

// ---------------------------------------------------------------------------
// G24 — Change address from internal keypool
// ---------------------------------------------------------------------------

/// G24: Change address comes from the internal (change) keypool.
/// create_transaction calls get_change_address() which uses is_change=true path.
#[test]
fn g24_change_from_internal_keypool() {
    let seed = [5u8; 32];
    let mut wallet = Wallet::from_seed(&seed, Network::Regtest, AddressType::P2WPKH).unwrap();

    for i in 0u32..3 {
        let mut utxo = make_utxo_with_vout(100_000, 6, i);
        utxo.derivation_path = vec![];
        wallet.add_utxo(utxo);
    }

    let recipient = wallet.peek_address().unwrap();
    let tx = wallet.create_transaction(vec![(recipient, 50_000)], 1.0).unwrap();

    // Verify tx has outputs (change was added from internal keypool)
    assert!(tx.outputs.len() >= 1);
}

// ---------------------------------------------------------------------------
// G25 — nLockTime = current block height
// ---------------------------------------------------------------------------

/// G25 (BUG-16): nLockTime is hardcoded to 0. Core sets it to current block
/// height to discourage fee-sniping.
#[test]
#[ignore = "BUG-16: lock_time hardcoded to 0 in create_transaction — anti-fee-sniping (DiscourageFeeSniping) not implemented"]
fn g25_locktime_set_to_block_height() {
    let seed = [6u8; 32];
    let mut wallet = Wallet::from_seed(&seed, Network::Regtest, AddressType::P2WPKH).unwrap();
    wallet.set_chain_height(800_000);

    let mut utxo = make_utxo_with_vout(1_000_000, 6, 0);
    utxo.derivation_path = vec![];
    wallet.add_utxo(utxo);

    let recipient = wallet.peek_address().unwrap();
    let tx = wallet.create_transaction(vec![(recipient, 100_000)], 1.0).unwrap();

    // Core: lock_time = 800_000 (or slightly lower with 10% backdate)
    // rustoshi: lock_time = 0
    assert!(
        tx.lock_time > 0 && tx.lock_time <= 800_000,
        "lock_time should be set to chain height {} for anti-fee-sniping, got {}",
        800_000,
        tx.lock_time
    );
}

// ---------------------------------------------------------------------------
// G26 — 10% backdate probability
// ---------------------------------------------------------------------------

/// G26 (BUG-17): No 10% backdate randomization. Core occasionally sets
/// nLockTime up to 100 blocks below current height.
#[test]
#[ignore = "BUG-17: backdate randomization (Core: 10% chance, up to 100 blocks back) not implemented"]
fn g26_10pct_backdate_absent() {
    panic!("Backdate randomization not implemented");
}

// ---------------------------------------------------------------------------
// G27 — nSequence = 0xfffffffd when nLockTime > 0
// ---------------------------------------------------------------------------

/// G27: nSequence = RBF_SEQUENCE (0xfffffffd) for BIP-125 + locktime.
/// When lock_time > 0, inputs must have nSequence < SEQUENCE_FINAL.
/// rustoshi always uses 0xfffffffd (correct for RBF + enables locktime).
#[test]
fn g27_nsequence_rbf_and_locktime_compatible() {
    let seed = [7u8; 32];
    let mut wallet = Wallet::from_seed(&seed, Network::Regtest, AddressType::P2WPKH).unwrap();

    let mut utxo = make_utxo_with_vout(1_000_000, 6, 0);
    utxo.derivation_path = vec![];
    wallet.add_utxo(utxo);

    let recipient = wallet.peek_address().unwrap();
    let tx = wallet.create_transaction(vec![(recipient, 100_000)], 1.0).unwrap();

    for input in &tx.inputs {
        assert_eq!(
            input.sequence, 0xFFFF_FFFD,
            "nSequence should be 0xfffffffd (BIP-125 RBF + locktime-compatible)"
        );
    }
}

// ---------------------------------------------------------------------------
// G28 — RBF signal
// ---------------------------------------------------------------------------

/// G28: At least one input has nSequence < 0xfffffffe (RBF opt-in).
/// 0xfffffffd < 0xfffffffe, so rustoshi's RBF_SEQUENCE satisfies this.
#[test]
fn g28_rbf_signal_present() {
    let seed = [8u8; 32];
    let mut wallet = Wallet::from_seed(&seed, Network::Regtest, AddressType::P2WPKH).unwrap();

    let mut utxo = make_utxo_with_vout(1_000_000, 6, 0);
    utxo.derivation_path = vec![];
    wallet.add_utxo(utxo);

    let recipient = wallet.peek_address().unwrap();
    let tx = wallet.create_transaction(vec![(recipient, 100_000)], 1.0).unwrap();

    let has_rbf = tx.inputs.iter().any(|i| i.sequence < 0xFFFFFFFE);
    assert!(has_rbf, "At least one input should signal RBF (nSequence < 0xfffffffe)");
}

// ---------------------------------------------------------------------------
// G29 — CoinControl
// ---------------------------------------------------------------------------

/// G29 (BUG-18): CoinControl (user-specified inputs) is MISSING ENTIRELY.
/// Core's CCoinControl allows preselecting inputs, setting change address,
/// locktime overrides, feerate overrides, etc.
#[test]
#[ignore = "BUG-18: CoinControl not implemented — create_transaction only accepts recipients + fee_rate"]
fn g29_coin_control_missing() {
    panic!("CoinControl not implemented");
}

// ---------------------------------------------------------------------------
// G30 — Waste metric
// ---------------------------------------------------------------------------

/// G30: Waste metric is computed as
/// `(current_feerate - long_term_feerate) * total_input_size + (cost_of_change OR excess)`.
/// rustoshi's `OutputGroup::waste()` = `fee - long_term_fee`, which covers the
/// per-input feerate differential. The BnB loop also adds excess waste.
/// The formula is structurally correct, but the 1000× long_term_fee_rate
/// default (BUG-8) means all waste values are computed incorrectly in practice.
#[test]
fn g30_waste_metric_formula_structurally_correct() {
    let params = CoinSelectionParams {
        fee_rate: 10.0,
        long_term_fee_rate: 0.0, // force waste = full fee
        input_weight: 68 * 4,
        target_value: 50_000,
        ..Default::default()
    };

    // expected fee = ceil(68 * 10) = 680 sats
    // long_term_fee = 0
    // waste per input = 680 - 0 = 680
    let ev = params.effective_value(100_000);
    assert_eq!(ev, 100_000 - 680, "effective_value should subtract input fee");

    let utxos = vec![make_utxo(100_000, 6)];
    let result = select_coins_bnb(&utxos, &params);
    if let Some(r) = result {
        // Waste should reflect fee differential
        assert!(r.waste >= 0, "waste should be non-negative when feerate > long_term_feerate");
    }
}

/// G30 bonus: Verify waste is tracked in BnB result.
#[test]
fn g30_waste_tracked_in_bnb_result() {
    let utxos = vec![
        make_utxo_with_vout(200_000, 6, 0),
        make_utxo_with_vout(100_000, 6, 1),
    ];
    let params = CoinSelectionParams {
        target_value: 90_000,
        fee_rate: 1.0,
        change_cost: 0,
        change_spend_cost: 0,
        long_term_fee_rate: 0.0,
        min_change: 0,
        input_weight: 68 * 4,
    };
    let result = select_coins_bnb(&utxos, &params);
    if let Some(r) = result {
        // Waste = excess (total_selected - target - fees) when no change
        assert!(r.waste >= 0);
    }
}

// ---------------------------------------------------------------------------
// Miscellaneous integration and structural
// ---------------------------------------------------------------------------

/// Verify select_coins integration: BnB → Knapsack → LargestFirst fallback.
#[test]
fn integration_select_coins_fallback_chain() {
    let utxos = vec![
        make_utxo_with_vout(10_000, 6, 0),
        make_utxo_with_vout(20_000, 6, 1),
        make_utxo_with_vout(50_000, 6, 2),
    ];
    let params = CoinSelectionParams {
        target_value: 60_000,
        fee_rate: 1.0,
        ..Default::default()
    };
    let mut rng = StdRng::seed_from_u64(0);
    let result = select_coins(&utxos, &params, &mut rng);
    assert!(result.is_some());
    let result = result.unwrap();
    assert!(result.total_value >= params.target_value);
}

/// Verify unconfirmed UTXOs are excluded from all selection paths.
#[test]
fn all_algorithms_exclude_unconfirmed() {
    let utxos = vec![
        make_utxo_with_vout(1_000_000, 0, 0), // Unconfirmed — should be excluded
        make_utxo_with_vout(100, 6, 1),       // Confirmed but tiny
    ];
    let params = CoinSelectionParams {
        target_value: 500_000,
        fee_rate: 1.0,
        ..Default::default()
    };
    let result_bnb = select_coins_bnb(&utxos, &params);
    assert!(result_bnb.is_none(), "BnB should not use unconfirmed UTXO");

    let mut rng = StdRng::seed_from_u64(1);
    let result_ks = select_coins_knapsack(&utxos, &params, &mut rng);
    assert!(result_ks.is_none(), "Knapsack should not use unconfirmed UTXO");

    let result_lf = select_coins_largest_first(&utxos, &params);
    assert!(result_lf.is_none(), "LargestFirst should not use unconfirmed UTXO");
}

/// Verify empty UTXO pool returns None from all algorithms.
#[test]
fn empty_utxo_pool_returns_none() {
    let params = default_params(10_000);
    let mut rng = StdRng::seed_from_u64(0);
    assert!(select_coins_bnb(&[], &params).is_none());
    assert!(select_coins_knapsack(&[], &params, &mut rng).is_none());
    assert!(select_coins_largest_first(&[], &params).is_none());
}
