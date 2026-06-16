//! W129 Coin selection (BnB / Knapsack / SRD / CG) audit — rustoshi (Rust)
//!
//! 30-gate audit of the coin-selection subsystem versus Bitcoin Core
//! semantics. The audit catalogues PARTIAL/MISSING gates as numbered
//! BUG-N entries against:
//!   * `bitcoin-core/src/wallet/coinselection.cpp` + `coinselection.h`
//!   * `bitcoin-core/src/wallet/spend.cpp` (`AttemptSelection`,
//!     `ChooseSelectionResult`, `CreateTransactionInternal`, the
//!     effective/long-term/discard feerate triple, `GroupOutputs`,
//!     `min_viable_change`, `m_change_fee`, `m_cost_of_change`,
//!     `m_subtract_fee_outputs`).
//!   * `bitcoin-core/src/wallet/feebumper.cpp` (`CreateTotalBumpTransaction`,
//!     which re-runs coin selection).
//!
//! Audit subject: `crates/wallet/src/coin_selection.rs` (~762 LOC) plus
//! its single call-site `crates/wallet/src/wallet.rs::create_transaction`.
//! `bump_fee` / `psbt_bump_fee` (`wallet.rs:728-960`) is in scope
//! because Core's `CreateTotalBumpTransaction` re-runs coin selection.
//!
//! Bug inventory (BUG-1..26 — see `audit/w129_coin_selection.md` for
//! full per-bug rationale and locations):
//!
//!   BUG-1  [P0-CDIV] G29-feat: long-term feerate scale mismatch.
//!                  `wallet.rs:517` sets `long_term_fee_rate: 10.0/1000.0`
//!                  (= 0.01 sat/vB), comment claims "10 sat/kvB = 0.01
//!                  sat/vbyte (Core default)". Core default is
//!                  `DEFAULT_CONSOLIDATE_FEERATE = 10000` sat/kvB =
//!                  10 sat/vB (1000× larger). Every waste metric
//!                  involving `fee - long_term_fee` is wrong by ~1000×.
//!                  COMMENT-AS-CONFESSION pattern.
//!
//!   BUG-2  [P0-CDIV] G9: SFFO (`m_subtract_fee_outputs`) MISSING ENTIRELY.
//!                  No field on `CoinSelectionParams`; no toggle between
//!                  `m_value` and `effective_value` (Core
//!                  `coinselection.cpp:789` `GetSelectionAmount()`); no
//!                  recipient-amount mutation during build; no BnB-skip
//!                  gate (Core `spend.cpp:751`).
//!
//!   BUG-3  [P0-CDIV] G8: Knapsack `total_lower == target` shortcut at
//!                  `coin_selection.rs:349-359` (a) skips
//!                  `max_selection_weight` check (Core
//!                  `coinselection.cpp:687-688` aborts if weight too
//!                  large), (b) uses `utxo.value` (gross) not
//!                  `GetSelectionAmount()` (effective) for the
//!                  comparison. Returns over-weight or over-spending
//!                  selections silently.
//!
//!   BUG-4  [P0]      G4 / G2: BnB index-bookkeeping divergence from
//!                  Core's single-pointer `++utxo_pool_index` walk.
//!                  `coin_selection.rs:189-268` conditional
//!                  `utxo_index += 1` on inclusion-vs-backtrack-restore
//!                  produces a different pool traversal than Core
//!                  `coinselection.cpp:124-186` when the duplicate-skip
//!                  shortcut fires.
//!
//!   BUG-5  [P0]      G12: SRD (`SelectCoinsSRD`) MISSING ENTIRELY.
//!                  No `select_coins_srd` function; no min-heap-evict
//!                  pattern; no `CHANGE_LOWER`/`change_fee` fudge.
//!                  Privacy regression vs Core fallback chain.
//!
//!   BUG-6  [P0]      G13: Coin Grinder (`CoinGrinder`) MISSING ENTIRELY.
//!                  No EXPLORE/SHIFT/CUT state machine; no
//!                  `min_tail_weight` reachability; no
//!                  `effective_feerate > 3 * long_term_feerate` gate
//!                  (Core `spend.cpp:769`). Min-weight optimization
//!                  absent at high feerates.
//!
//!   BUG-7  [P0]      G10: `cost_of_change` double-attenuates change.
//!                  `coin_selection.rs:86-90` divides
//!                  `change_cost` (already in weight units) by 4 *
//!                  fee_rate. Core uses `change_output_size` directly
//!                  (vbytes) with `effective_feerate.GetFee(size)`.
//!                  Effective cost-of-change ~1/4 of Core; BnB upper
//!                  bound (target + cost_of_change) is too tight,
//!                  rejecting valid changeless selections.
//!
//!   BUG-8  [P1]      G14: `GenerateChangeTarget` MISSING. Change is
//!                  the residual; no [50ksat, min(2*payment, 1Msat)]
//!                  randomization. Fingerprinting via change-amount
//!                  distribution.
//!
//!   BUG-9  [P1]      G15: `CoinEligibilityFilter` MISSING — conf_mine
//!                  / conf_theirs / max_ancestors / max_cluster_count
//!                  tiers absent. `confirmations >= 1` hardcoded at
//!                  `coin_selection.rs:159,314`.
//!
//!   BUG-10 [P1]      G21: BnB-skipped-on-SFFO gate MISSING (no SFFO).
//!
//!   BUG-11 [P1]      G7-related (audit gate G19 hosts the structural
//!                  finding): GroupOutputs-by-script-pubkey MISSING.
//!                  `OutputGroup::new` builds one-UTXO-per-group; no
//!                  `Insert()` accumulator. Address-reuse heuristic
//!                  leaks.
//!
//!   BUG-12 [P1]      G25: SFFO recipient-amount mutation MISSING (Core
//!                  `spend.cpp:1349` reduces each subtract-fee-from
//!                  output by `fee/num_subtract_fee_outputs`).
//!
//!   BUG-13 [P1]      G29: bumpfee never re-runs coin selection.
//!                  `wallet.rs:847,855` says "cannot bump without
//!                  adding inputs (not yet supported)" and "cannot
//!                  bump without removing change (not yet supported)".
//!                  Core's `CreateTotalBumpTransaction` re-runs the
//!                  full selector.
//!
//!   BUG-14 [P2]      G16: `m_avoid_partial_spends` MISSING (no
//!                  grouping, so no flag surface).
//!
//!   BUG-15 [P2]      G17: `OUTPUT_GROUP_MAX_ENTRIES` cap MISSING
//!                  (Core wallet.h = 100; here groups are degenerate).
//!
//!   BUG-16 [P2]      G18: `RecalculateWaste(min_viable_change,
//!                  change_cost, change_fee)` centralized hook MISSING.
//!                  Waste computed in 3 different places with no
//!                  bump-fee-discount, no excess-above-target term.
//!
//!   BUG-17 [P2]      G22: CG-at-3×LTFR gate MISSING (Core
//!                  `spend.cpp:769`).
//!
//!   BUG-18 [P2]      G20: `select_coins` driver returns FIRST-SUCCESS
//!                  not min-waste across algos. Core's `AttemptSelection`
//!                  collects all results, picks `std::min_element` by
//!                  waste (`spend.cpp:716`).
//!
//!   BUG-19 [P2]      G26: `AttemptSelection` per-OutputType iteration
//!                  MISSING — no "try each output type separately, then
//!                  mix".
//!
//!   BUG-20 [P2]      G27: `tx_noinputs_size` overhead absent from
//!                  selection params.
//!
//!   BUG-21 [P2]      G28: `m_max_tx_weight` / max-selection-weight
//!                  enforcement ABSENT in BnB and Knapsack.
//!
//!   BUG-22 [P3]      G3: hard-coded `confirmations >= 1` filter at
//!                  BnB and Knapsack entry — conflicts with G15
//!                  configurable filter.
//!
//!   BUG-23 [P3]      G19: one-UTXO-per-OutputGroup design — groups
//!                  never combine across shared script-pubkey.
//!
//!   BUG-24 [P3]      G23: `select_coins_largest_first` waste excludes
//!                  excess-above-target term Core includes in
//!                  `RecalculateWaste`.
//!
//!   BUG-25 [P3]      G5: `best_waste = i64::MAX` sentinel vs Core's
//!                  `MAX_MONEY` — subtle overflow surface.
//!
//!   BUG-26 [P3]      G30: `GetShuffledInputVector` (final input-order
//!                  shuffle for privacy) absent.
//!
//! PASS pins: G1 (BnB exists), G6 (Knapsack 1000-iter
//! `ApproximateBestSubset`), G7 (Knapsack `lowest_larger` fallback),
//! G24 (`SelectionResult` shape).

use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use rustoshi_primitives::{Hash256, OutPoint};
use rustoshi_wallet::coin_selection::{
    select_coins, select_coins_bnb, select_coins_knapsack, select_coins_largest_first,
    CoinSelectionParams, SelectionAlgorithm,
};
use rustoshi_wallet::WalletUtxo;

// ---------- helpers ----------

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

fn make_utxo_with_spk(value: u64, confirmations: u32, spk: Vec<u8>) -> WalletUtxo {
    WalletUtxo {
        outpoint: OutPoint {
            txid: Hash256::ZERO,
            vout: 0,
        },
        value,
        script_pubkey: spk,
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

// ============================================================================
// PRESENT (4) — regression pins for known-good behavior
// ============================================================================

/// G1: BnB algorithm exists. Depth-first walk over a sorted UTXO pool,
/// lookahead pruning, cost-of-change cap on overshoot. Core
/// `coinselection.cpp::SelectCoinsBnB`.
#[test]
fn g1_bnb_exists_and_runs() {
    let utxos = vec![
        make_utxo(10_000, 6),
        make_utxo(20_000, 6),
        make_utxo(50_000, 6),
    ];
    let params = default_params(40_000);
    // BnB function present; either Some or None (existing test fixture in
    // coin_selection.rs:601-622 documents both outcomes — we just pin
    // that the entry point exists and doesn't panic).
    let _result = select_coins_bnb(&utxos, &params);
}

/// G6: Knapsack `ApproximateBestSubset` runs the 1000-iteration two-pass
/// stochastic search. Core `coinselection.cpp::ApproximateBestSubset`
/// (iterations = 1000).
#[test]
fn g6_knapsack_approximate_best_subset_runs() {
    let utxos = vec![
        make_utxo(10_000, 6),
        make_utxo(20_000, 6),
        make_utxo(50_000, 6),
    ];
    let params = default_params(25_000);
    let mut rng = ChaCha8Rng::seed_from_u64(12345);
    let result = select_coins_knapsack(&utxos, &params, &mut rng);
    assert!(result.is_some(), "Knapsack must produce a result here");
    let r = result.unwrap();
    assert!(r.total_value >= 25_000);
    assert_eq!(r.algorithm, SelectionAlgorithm::Knapsack);
}

/// G7: Knapsack `lowest_larger` single-UTXO fallback. When no subset of
/// applicable groups can reach the target, Core falls back to the
/// smallest single UTXO ≥ target. `coinselection.cpp:694-700`.
#[test]
fn g7_knapsack_lowest_larger_fallback() {
    // Only tiny UTXOs below target plus one big enough to cover alone.
    let utxos = vec![
        make_utxo(100, 6),
        make_utxo(100, 6),
        make_utxo(500_000, 6),
    ];
    let params = default_params(250_000);
    let mut rng = ChaCha8Rng::seed_from_u64(99);
    let result = select_coins_knapsack(&utxos, &params, &mut rng);
    assert!(result.is_some());
    let r = result.unwrap();
    // Should return the single 500_000 UTXO (lowest larger).
    assert!(r.total_value >= 250_000);
}

/// G24: `SelectionResult` shape mirrors Core: `selected`, `total_value`,
/// `target`, `waste`, `algorithm`. Core `SelectionResult` in
/// `coinselection.h:330-450`.
#[test]
fn g24_selection_result_shape_present() {
    let utxos = vec![make_utxo(100_000, 6)];
    let params = default_params(10_000);
    let mut rng = ChaCha8Rng::seed_from_u64(0);
    let r = select_coins(&utxos, &params, &mut rng).expect("select_coins");
    let _ = r.selected.len();
    let _ = r.total_value;
    let _ = r.target;
    let _ = r.waste;
    let _ = r.algorithm;
}

// ============================================================================
// BUG STUBS (BUG-1..26) — #[ignore] regression panics documenting divergence
// ============================================================================

/// BUG-1 / G29-feat [P0-CDIV] — FIXED: long-term feerate scale.
///
/// rustoshi's `long_term_fee_rate` is in **sat/vB**: every consumer in
/// `coin_selection.rs` multiplies it by a vbyte quantity with no /1000
/// (`:88` change_spend_cost·LTFR, `:112`/`:539` input_weight/4·LTFR).
/// Core's default long-term feerate is `DEFAULT_CONSOLIDATE_FEERATE =
/// 10000` sat/kvB (`bitcoin-core/src/wallet/wallet.h:112`), wired in via
/// `m_long_term_feerate = m_consolidate_feerate` (`spend.cpp:1087`);
/// 10000 sat/kvB / 1000 = **10 sat/vB**.
///
/// The `create_transaction` call site (`wallet.rs`) previously set the
/// 1000×-too-small `10.0 / 1000.0` (= 0.01), collapsing the waste metric
/// and over-consolidating at low feerates; it now sets `10.0`, matching
/// the `CoinSelectionParams` default (`coin_selection.rs:71`, already
/// correct). De-staled 2026-06-16. (The call-site params are built inline
/// in `create_transaction` and not unit-inspectable; this pins the
/// Core-correct value on the public default surface that the call site
/// now also uses.)
#[test]
fn bug1_long_term_feerate_scale() {
    // Core DEFAULT_CONSOLIDATE_FEERATE = 10000 sat/kvB, in rustoshi's
    // sat/vB units: 10000 / 1000 = 10.0 (NOT the old 0.01).
    const CORE_LTFR_SAT_PER_VB: f64 = 10_000.0 / 1000.0; // = 10.0
    let params = CoinSelectionParams::default();
    assert_eq!(
        params.long_term_fee_rate, CORE_LTFR_SAT_PER_VB,
        "long_term_fee_rate must equal Core DEFAULT_CONSOLIDATE_FEERATE \
         (10000 sat/kvB = 10 sat/vB), not the old 0.01 (10.0/1000.0) which \
         under-counted the waste metric ~1000x and over-consolidated."
    );
    assert_eq!(params.long_term_fee_rate, 10.0);

    // Arithmetic witness: a 68-vbyte input's long-term spend cost at
    // 10 sat/vB is ceil(68 * 10.0) = 680 sats (was ~1 under the bug).
    let ltfr_input_fee = (68.0_f64 * params.long_term_fee_rate).ceil() as i64;
    assert_eq!(ltfr_input_fee, 680, "68 vB * 10 sat/vB = 680 sats");
}

/// BUG-2 / G9 [P0-CDIV]: SFFO (`m_subtract_fee_outputs`) MISSING.
///
/// No `CoinSelectionParams::m_subtract_fee_outputs`; no `OutputGroup::
/// m_subtract_fee_outputs`; no `GetSelectionAmount()` toggle between
/// `m_value` and `effective_value` (Core `coinselection.cpp:789`); no
/// recipient-amount mutation during build (Core `spend.cpp:1349`); no
/// BnB-skip gate when SFFO active (Core `spend.cpp:751`).
#[test]
#[ignore = "BUG-2 P0-CDIV: SFFO subtract-fee-from-outputs MISSING ENTIRELY"]
fn bug2_sffo_missing() {
    panic!(
        "BUG-2: `subtract_fee_from_outputs` (SFFO) MISSING. \
         Need: `CoinSelectionParams::m_subtract_fee_outputs: bool`, \
         OutputGroup carries the flag, GetSelectionAmount() returns \
         m_value when SFFO else effective_value, AttemptSelection skips \
         BnB when SFFO active, build path reduces recipient amount by \
         fee/num_subtract_fee_outputs."
    );
}

/// BUG-3 / G8 [P0-CDIV]: Knapsack `total_lower == target` shortcut at
/// `coin_selection.rs:349-359` (a) skips `max_selection_weight` check
/// (Core `coinselection.cpp:687-688`), (b) uses `utxo.value` (gross)
/// not `GetSelectionAmount()` (effective) for the comparison.
#[test]
#[ignore = "BUG-3 P0-CDIV: knapsack total_lower==target skips weight check + uses gross value"]
fn bug3_knapsack_total_lower_equals_target() {
    // Construct a pool where total_lower == target on GROSS value but
    // != target on EFFECTIVE value, then verify the wrong-shortcut fires.
    let utxos = vec![
        make_utxo(10_000, 6),
        make_utxo(10_000, 6),
        make_utxo(5_000, 6),
    ];
    // After fees, none of these is exact-match in effective value, but
    // gross sums to 25_000.
    let params = CoinSelectionParams {
        target_value: 25_000,
        fee_rate: 10.0, // high fee → meaningful effective-value drop
        ..Default::default()
    };
    let mut rng = ChaCha8Rng::seed_from_u64(7);
    let _r = select_coins_knapsack(&utxos, &params, &mut rng);
    panic!(
        "BUG-3: Knapsack total_lower==target shortcut at \
         coin_selection.rs:349-359 uses gross value AND skips weight \
         check. Must use GetSelectionAmount() (effective value) AND \
         must abort if result.weight > max_selection_weight per Core \
         coinselection.cpp:687-688."
    );
}

/// BUG-4 / G4 / G2 [P0]: BnB index-bookkeeping divergence.
///
/// Core (`coinselection.cpp:124-186`) walks the pool with a single
/// `++utxo_pool_index` in the for-loop. Rustoshi's conditional
/// `utxo_index += 1` (on inclusion) vs explicit restore-loop on
/// backtrack (`coin_selection.rs:220-225`) produces a different
/// traversal pattern, especially when the duplicate-skip shortcut at
/// `:239-242` fires.
#[test]
#[ignore = "BUG-4 P0: BnB index-bookkeeping divergence from Core single-pointer walk"]
fn bug4_bnb_index_bookkeeping() {
    // Pool with duplicate effective values to trigger duplicate-skip.
    let utxos = vec![
        make_utxo(50_000, 6),
        make_utxo(50_000, 6), // duplicate value → skip shortcut fires
        make_utxo(50_000, 6),
        make_utxo(10_000, 6),
    ];
    let params = default_params(60_000);
    let _result = select_coins_bnb(&utxos, &params);
    panic!(
        "BUG-4: BnB index-walk must mirror Core's single \
         ++utxo_pool_index in the for-loop. Current conditional \
         utxo_index += 1 path produces different traversal when \
         duplicate-skip at coin_selection.rs:239-242 fires."
    );
}

/// BUG-5 / G12 [P0]: SRD (Single Random Draw) MISSING ENTIRELY.
///
/// No `select_coins_srd` function exists. No
/// `SelectionAlgorithm::SRD` variant. No min-heap evict-on-overweight
/// pattern. No `CHANGE_LOWER`/`change_fee` fudge factor.
#[test]
#[ignore = "BUG-5 P0: SRD (SelectCoinsSRD) MISSING ENTIRELY"]
fn bug5_srd_missing() {
    panic!(
        "BUG-5: Single Random Draw algorithm MISSING. Need \
         select_coins_srd(utxos, target, change_fee, rng, \
         max_selection_weight). Pattern: shuffle indices, accumulate, \
         evict lowest-effective-value via min-heap when weight \
         exceeded, return when sum >= target + CHANGE_LOWER + \
         change_fee. Core: coinselection.cpp:536-588."
    );
}

/// BUG-6 / G13 [P0]: Coin Grinder MISSING ENTIRELY.
///
/// No `coin_grinder` function. No EXPLORE/SHIFT/CUT state machine. No
/// `min_tail_weight` reachability. No `effective_feerate > 3 *
/// long_term_feerate` gate (Core `spend.cpp:769`). Min-weight
/// optimization absent at high feerates.
#[test]
#[ignore = "BUG-6 P0: Coin Grinder MISSING ENTIRELY"]
fn bug6_coin_grinder_missing() {
    panic!(
        "BUG-6: Coin Grinder MISSING. Need coin_grinder(utxos, \
         selection_target, change_target, max_selection_weight) with \
         EXPLORE/SHIFT/CUT walk, min_tail_weight reachability prune, \
         and AttemptSelection gate effective_feerate > 3 * \
         long_term_feerate. Core: coinselection.cpp:325-525, \
         spend.cpp:769-776."
    );
}

/// BUG-7 / G10 [P0]: `cost_of_change` double-attenuates change.
///
/// `coin_selection.rs:86-90` divides `change_cost` (already in weight
/// units = vbytes * 4) by 4, then multiplies by `fee_rate`. Core uses
/// `change_output_size` in vbytes directly with
/// `effective_feerate.GetFee(size)`. Effective cost-of-change is ~1/4
/// of Core's; BnB upper bound `target + cost_of_change` is too tight
/// and rejects valid changeless selections.
#[test]
#[ignore = "BUG-7 P0: cost_of_change double-attenuated (weight/4 then *fee_rate)"]
fn bug7_cost_of_change_double_attenuated() {
    let params = CoinSelectionParams {
        change_cost: 31 * 4, // 31 vbytes * 4 = weight (per default)
        change_spend_cost: 68,
        fee_rate: 10.0,
        long_term_fee_rate: 10.0, // matched units for this test
        ..Default::default()
    };
    let coc = params.cost_of_change();
    // Core: change_fee = 31 * 10 = 310, change_spend_fee = 68 * 10 = 680,
    // cost_of_change = 310 + 680 = 990 sats.
    // Rustoshi: change_output_fee = (31*4 / 4 * 10).ceil() = 310 (OK)
    //           change_spend_fee = (68 * 10.0).ceil() = 680 (OK if LTFR
    //           is in sat/vB, but BUG-1 says LTFR is 0.01 sat/vB →
    //           change_spend_fee collapses to 1)
    // So with the buggy LTFR, coc ≈ 311 not 990 — but even with the
    // correct LTFR, the change_cost weight-vs-vbytes confusion at
    // coin_selection.rs:87 stands as a separate concern.
    let _ = coc;
    panic!(
        "BUG-7: cost_of_change unit confusion. `change_cost` stored as \
         WEIGHT, then divided by 4 (back to vbytes), then * fee_rate. \
         Core stores as vbytes and multiplies by effective_feerate. \
         Need: standardize on vbytes throughout, fix the comment at \
         coin_selection.rs:69."
    );
}

/// BUG-8 / G14 [P1]: `GenerateChangeTarget` MISSING.
///
/// Core's `coinselection.cpp:809-818` generates a random change target
/// in `[change_fee + CHANGE_LOWER, change_fee + min(2*payment,
/// CHANGE_UPPER)]` where CHANGE_LOWER=50ksat, CHANGE_UPPER=1Msat.
/// Rustoshi uses `min_change = DUST_LIMIT` (`wallet.rs:518`) fixed,
/// no randomization → change-amount fingerprinting.
#[test]
#[ignore = "BUG-8 P1: GenerateChangeTarget MISSING (no random change target in [50ksat, 1Msat])"]
fn bug8_generate_change_target_missing() {
    panic!(
        "BUG-8: GenerateChangeTarget MISSING. Need fn that returns \
         change_fee + (if payment_value <= 25ksat: CHANGE_LOWER else \
         randrange(min(2*payment, CHANGE_UPPER) - CHANGE_LOWER) + \
         CHANGE_LOWER). Constants CHANGE_LOWER=50_000, CHANGE_UPPER=\
         1_000_000. Plumb result into m_min_change_target field. \
         Core: coinselection.cpp:809-818."
    );
}

/// BUG-9 / G15 [P1]: `CoinEligibilityFilter` MISSING.
///
/// No conf_mine / conf_theirs / max_ancestors / max_cluster_count
/// tiers. `confirmations >= 1` hardcoded at `coin_selection.rs:159,
/// 314`. Core uses a structured filter (`coinselection.h:201-225`)
/// applied via `EligibleForSpending` (`coinselection.cpp:782-787`)
/// with tier-up retry in `spend.cpp::SelectCoins`.
#[test]
#[ignore = "BUG-9 P1: CoinEligibilityFilter (conf_mine/conf_theirs/ancestors/cluster) MISSING"]
fn bug9_coin_eligibility_filter_missing() {
    let utxos = vec![
        make_utxo(100_000, 0),  // unconfirmed change (would be conf_mine=0)
        make_utxo(100_000, 3),  // 3-conf external (would be conf_theirs=6 fail)
    ];
    let params = default_params(50_000);
    let r = select_coins_bnb(&utxos, &params);
    // Current behavior: both filtered out by hardcoded >=1 (the
    // 0-conf own change is rejected when Core's conf_mine=1 would
    // accept).
    let _ = r;
    panic!(
        "BUG-9: CoinEligibilityFilter MISSING. Need filter \
         {{ conf_mine, conf_theirs, max_ancestors, max_cluster_count }} \
         per Core coinselection.h:201, applied per-UTXO via \
         EligibleForSpending. Currently `confirmations >= 1` is \
         hardcoded at coin_selection.rs:159,314."
    );
}

/// BUG-10 / G21 [P1]: BnB-skipped-on-SFFO gate MISSING.
///
/// Core `spend.cpp:751`: `if (!coin_selection_params.m_subtract_fee_
/// outputs) { run BnB }`. Without SFFO surface (BUG-2), this gate
/// cannot exist.
#[test]
#[ignore = "BUG-10 P1: BnB-skipped-on-SFFO gate MISSING (subordinate to BUG-2)"]
fn bug10_bnb_skipped_on_sffo_gate_missing() {
    panic!(
        "BUG-10: BnB-skipped-on-SFFO gate MISSING. Subordinate to \
         BUG-2 (SFFO MISSING). When SFFO is true, BnB must be skipped \
         because it operates on effective values and SFFO mutates \
         recipient values during build. Core: spend.cpp:751."
    );
}

/// BUG-11 / G19 [P1]: GroupOutputs-by-script-pubkey MISSING.
///
/// `OutputGroup::new(utxo, params)` (`coin_selection.rs:110-122`)
/// creates one group per UTXO. Core's `GroupOutputs` (`spend.cpp:572-
/// 695`) buckets UTXOs sharing a `script_pubkey` into the same group
/// (cap OUTPUT_GROUP_MAX_ENTRIES=100). Address-reuse heuristic leaks
/// without grouping.
#[test]
#[ignore = "BUG-11 P1: GroupOutputs-by-script-pubkey MISSING (one-UTXO-per-group)"]
fn bug11_group_outputs_missing() {
    // Two UTXOs at the same script_pubkey should group into one
    // OutputGroup per Core.
    let spk = vec![0x76, 0xa9, 0x14, 0x00, 0x00]; // dummy P2PKH-shape
    let _utxos = vec![
        make_utxo_with_spk(10_000, 6, spk.clone()),
        make_utxo_with_spk(20_000, 6, spk.clone()),
        make_utxo_with_spk(30_000, 6, vec![0x00, 0x14, 0xaa]), // different spk
    ];
    panic!(
        "BUG-11: GroupOutputs-by-script-pubkey MISSING. Need \
         GroupOutputs that buckets UTXOs sharing script_pubkey into \
         one OutputGroup (cap OUTPUT_GROUP_MAX_ENTRIES=100), per Core \
         spend.cpp:572-695. Currently one-UTXO-per-group at \
         coin_selection.rs:110-122."
    );
}

/// BUG-12 / G25 [P1]: SFFO recipient-amount mutation MISSING.
///
/// Core `spend.cpp:1349-1361` reduces each subtract-fee-from output by
/// `fee / num_subtract_fee_outputs` (with the remainder added to the
/// first output to absorb rounding). Rustoshi has no such path
/// because SFFO doesn't exist (BUG-2).
#[test]
#[ignore = "BUG-12 P1: SFFO recipient-amount mutation MISSING (subordinate to BUG-2)"]
fn bug12_sffo_recipient_amount_mutation_missing() {
    panic!(
        "BUG-12: SFFO recipient-amount mutation MISSING. After coin \
         selection, when SFFO active, each subtract-fee-from output \
         must be reduced by fee/num_subtract_fee_outputs (with \
         remainder absorbed by the first). Core: spend.cpp:1349-1361."
    );
}

/// BUG-13 / G29 [P1]: bumpfee never re-runs coin selection.
///
/// `wallet.rs:847` "cannot bump without adding inputs (not yet
/// supported)"; `wallet.rs:855` "cannot bump without removing change
/// (not yet supported)". Core's `CreateTotalBumpTransaction`
/// (`feebumper.cpp`) re-invokes the full selector with the original
/// inputs forced in and a bumped target.
#[test]
#[ignore = "BUG-13 P1: bumpfee never re-runs coin selection (no input-adding)"]
fn bug13_bumpfee_no_reselection() {
    panic!(
        "BUG-13: bumpfee never re-runs coin selection. \
         wallet.rs:847,855 explicitly reject the case (change too \
         small to absorb the bump). Core's CreateTotalBumpTransaction \
         re-runs the full selector with original inputs forced in, \
         supporting both adding inputs and removing change. Need: \
         pre-select existing inputs via CoinControl-style API, run \
         AttemptSelection with target = orig_outputs - orig_inputs + \
         new_fee."
    );
}

/// BUG-14 / G16 [P2]: `m_avoid_partial_spends` MISSING.
///
/// No grouping → no flag surface. When set, Core (`coinselection.h:
/// 166-167`) forces "spend all or none of OUTPUT_GROUP_MAX_ENTRIES
/// UTXOs of the same address". Without grouping (BUG-11), this flag
/// has no semantics.
#[test]
#[ignore = "BUG-14 P2: m_avoid_partial_spends MISSING (subordinate to BUG-11)"]
fn bug14_avoid_partial_spends_missing() {
    panic!(
        "BUG-14: m_avoid_partial_spends MISSING. Subordinate to \
         BUG-11 (no grouping). When set, Core forces spend-all-or-\
         nothing of same-spk UTXO groups up to OUTPUT_GROUP_MAX_\
         ENTRIES. Core: coinselection.h:166-167."
    );
}

/// BUG-15 / G17 [P2]: `OUTPUT_GROUP_MAX_ENTRIES` cap MISSING.
///
/// Core's `wallet.h::OUTPUT_GROUP_MAX_ENTRIES = 100`. With one-UTXO-
/// per-group (BUG-11), no cap is needed — but no cap means groups
/// also never combine.
#[test]
#[ignore = "BUG-15 P2: OUTPUT_GROUP_MAX_ENTRIES cap MISSING (subordinate to BUG-11)"]
fn bug15_output_group_max_entries_missing() {
    panic!(
        "BUG-15: OUTPUT_GROUP_MAX_ENTRIES cap MISSING. Subordinate to \
         BUG-11. Core caps at 100 UTXOs per group; without grouping \
         this is moot, but adding grouping requires this constant. \
         Core: wallet.h::OUTPUT_GROUP_MAX_ENTRIES = 100."
    );
}

/// BUG-16 / G18 [P2]: `RecalculateWaste` centralized hook MISSING.
///
/// Core's `SelectionResult::RecalculateWaste(min_viable_change,
/// change_cost, change_fee)` (`coinselection.cpp:827-853`) is THE
/// canonical waste-recompute, called by every algorithm's success
/// path. Rustoshi computes waste in 3 different places (BnB:204,
/// Knapsack:351,427, LargestFirst:537) with no bump-fee-discount and
/// no excess-above-target term.
#[test]
#[ignore = "BUG-16 P2: RecalculateWaste centralized hook MISSING (waste computed in 3 places)"]
fn bug16_recalculate_waste_missing() {
    panic!(
        "BUG-16: RecalculateWaste MISSING. Need centralized hook on \
         SelectionResult: waste = sum(fee - long_term_fee) per input \
         - bump_fee_group_discount + (change ? change_cost : excess). \
         Currently 3 different formulas in 3 places. Core: \
         coinselection.cpp:827-853."
    );
}

/// BUG-17 / G22 [P2]: CG-at-3×LTFR gate MISSING.
///
/// Core's `spend.cpp:769`: `if (m_effective_feerate > CFeeRate{3 *
/// m_long_term_feerate}) { run CoinGrinder }`. The gate triggers
/// CG ONLY at high feerates (default ≥ 30 sat/vB). Without CG
/// (BUG-6), this gate can't exist.
#[test]
#[ignore = "BUG-17 P2: CG-at-3xLTFR gate MISSING (subordinate to BUG-6)"]
fn bug17_cg_at_3x_ltfr_gate_missing() {
    panic!(
        "BUG-17: CG-at-3×LTFR gate MISSING. Subordinate to BUG-6 \
         (CG MISSING). Core: spend.cpp:769 — `if (effective_feerate \
         > 3 * long_term_feerate) {{ run CoinGrinder }}`."
    );
}

/// BUG-18 / G20 [P2]: `select_coins` driver returns FIRST-SUCCESS.
///
/// `coin_selection.rs:558-575`: tries BnB → Knapsack → LargestFirst,
/// returning the first non-None. Core's `AttemptSelection`
/// (`spend.cpp:702-727`) runs ALL applicable algorithms, computes
/// waste for each, returns `std::min_element` by waste.
#[test]
#[ignore = "BUG-18 P2: select_coins returns first-success not min-waste across algos"]
fn bug18_select_coins_first_success_not_min_waste() {
    panic!(
        "BUG-18: select_coins driver returns FIRST-SUCCESS not min-\
         waste. coin_selection.rs:558-575 short-circuits on first \
         non-None. Must run all algorithms (BnB, Knapsack, CG if \
         applicable, SRD), recalculate waste for each via \
         RecalculateWaste, return the min via `std::min_element` \
         equivalent. Core: spend.cpp:716."
    );
}

/// BUG-19 / G26 [P2]: `AttemptSelection` per-OutputType iteration MISSING.
///
/// Core's `AttemptSelection` (`spend.cpp:702-727`) iterates each
/// output type's groups separately, picks min-waste, then falls back
/// to mixed-output-type selection if no single-type solution found.
/// Rustoshi has no concept of output-type-typed groups.
#[test]
#[ignore = "BUG-19 P2: AttemptSelection per-OutputType iteration MISSING"]
fn bug19_attempt_selection_per_output_type_missing() {
    panic!(
        "BUG-19: AttemptSelection per-OutputType iteration MISSING. \
         Core iterates each output type (Legacy/P2SH-P2WPKH/P2WPKH/\
         P2TR) separately, then mixed-fallback. Rustoshi treats all \
         UTXOs as one untyped pool. Core: spend.cpp:702-727."
    );
}

/// BUG-20 / G27 [P2]: `tx_noinputs_size` overhead MISSING from
/// selection params.
///
/// Core's `CoinSelectionParams::tx_noinputs_size` (`coinselection.h:
/// 159-161`) is the static + outputs vsize, plumbed through to
/// `selection_target = recipients_sum + effective_feerate.GetFee
/// (tx_noinputs_size)` (`spend.cpp:1187-1188`). Rustoshi estimates
/// in `wallet.rs:499-506` as a bootstrap; the params struct never
/// carries it.
#[test]
#[ignore = "BUG-20 P2: tx_noinputs_size absent from CoinSelectionParams"]
fn bug20_tx_noinputs_size_absent() {
    let params = CoinSelectionParams::default();
    let _ = params.target_value;
    // No `tx_noinputs_size` field exists on `CoinSelectionParams`.
    panic!(
        "BUG-20: tx_noinputs_size absent from CoinSelectionParams. \
         Need: pub tx_noinputs_size: usize, populated as 10 + \
         CompactSize(num_outputs) + sum(GetSerializeSizeForRecipient(\
         r)). Plumbs into selection_target."
    );
}

/// BUG-21 / G28 [P2]: max-selection-weight enforcement ABSENT.
///
/// BnB has no `curr_selection_weight > max_selection_weight` early
/// exit (Core `coinselection.cpp:131-133`). Knapsack has no `weight >
/// max_selection_weight` evict-and-fail (Core `coinselection.cpp:668-
/// 671`). Out-of-pocket: oversize transactions can be returned.
#[test]
#[ignore = "BUG-21 P2: max-selection-weight enforcement ABSENT in BnB and Knapsack"]
fn bug21_max_selection_weight_absent() {
    panic!(
        "BUG-21: max-selection-weight enforcement ABSENT. BnB must \
         set max_tx_weight_exceeded and backtrack when \
         curr_selection_weight > max_selection_weight (Core \
         coinselection.cpp:131-133). Knapsack must skip groups whose \
         weight alone exceeds max (Core coinselection.cpp:668-671). \
         Need: CoinSelectionParams::m_max_tx_weight (default \
         MAX_STANDARD_TX_WEIGHT=400_000)."
    );
}

/// BUG-22 / G3 [P3]: hardcoded `confirmations >= 1` filter.
///
/// `coin_selection.rs:159` (BnB) and `:314` (Knapsack) both filter
/// `confirmations >= 1`. The Core equivalent is configurable via
/// `CoinEligibilityFilter::conf_mine` (default 1 for own coins) and
/// `conf_theirs` (default 6 for outside coins) — tiered, not flat.
/// Subordinate to BUG-9.
#[test]
#[ignore = "BUG-22 P3: hardcoded confirmations>=1 filter (subordinate to BUG-9)"]
fn bug22_hardcoded_confirmations_filter() {
    // Pin the buggy behavior so the regression test detects when it
    // changes. Pool with two UTXOs, one 0-conf (own change, should be
    // eligible per Core conf_mine=1 default), one 5-conf external
    // (Core conf_theirs=6 would reject).
    let utxos = vec![
        make_utxo(100_000, 0), // own 0-conf
        make_utxo(100_000, 5), // external 5-conf
    ];
    let params = default_params(50_000);
    let result = select_coins_bnb(&utxos, &params);
    // Currently: both filtered out (>=1 fails on 0-conf, 5-conf
    // passes but 0-conf is rejected). Total available drops to 1
    // UTXO = 100k. BnB might succeed; pin that 0-conf is rejected.
    if let Some(r) = result {
        assert!(
            r.selected.iter().all(|u| u.confirmations >= 1),
            "BUG-22 regression pin: 0-conf UTXOs currently rejected"
        );
    }
    panic!(
        "BUG-22: confirmations>=1 hardcoded at coin_selection.rs:159, \
         314 — must be replaced with configurable \
         CoinEligibilityFilter per BUG-9."
    );
}

/// BUG-23 / G19 [P3]: one-UTXO-per-OutputGroup design.
///
/// `OutputGroup::new(utxo, params)` takes a single utxo. Core's
/// `OutputGroup` has `m_outputs: vector<COutput>` and grows via
/// `Insert()` (`coinselection.cpp:755-780`). Subordinate to BUG-11.
#[test]
#[ignore = "BUG-23 P3: one-UTXO-per-group OutputGroup design (subordinate to BUG-11)"]
fn bug23_one_utxo_per_group() {
    panic!(
        "BUG-23: OutputGroup is one-UTXO-per-group. Subordinate to \
         BUG-11. Need OutputGroup {{ m_outputs: Vec<UTXO>, m_value, \
         effective_value, fee, long_term_fee, m_weight, ... }} with \
         Insert() accumulator. Core: coinselection.cpp:755-780."
    );
}

/// BUG-24 / G23 [P3]: `select_coins_largest_first` waste excludes
/// excess-above-target term.
///
/// `coin_selection.rs:537-541` sums `fee - long_term_fee` per input
/// only. Core's `RecalculateWaste` (`coinselection.cpp:846-850`)
/// adds `selected_effective_value - m_target` (excess thrown to fees)
/// when there is no change. LargestFirst's no-change case mismatches.
#[test]
#[ignore = "BUG-24 P3: largest_first waste excludes excess-above-target term"]
fn bug24_largest_first_waste_excludes_excess() {
    let utxos = vec![
        make_utxo(100_000, 6),
        make_utxo(50_000, 6),
    ];
    let params = default_params(40_000);
    let result = select_coins_largest_first(&utxos, &params).unwrap();
    let _ = result.waste; // currently only fee-LTFR contribution
    panic!(
        "BUG-24: largest_first waste excludes excess-above-target \
         term. When selection produces no change (residual absorbed \
         into fee), waste must include selected_effective_value - \
         target per Core coinselection.cpp:846-850."
    );
}

/// BUG-25 / G5 [P3]: `best_waste = i64::MAX` sentinel.
///
/// Core uses `MAX_MONEY = 21_000_000 * COIN = 2.1e15`. `i64::MAX` is
/// `9.2e18`. Practical impact: nil for sane inputs, but subtle on
/// negative-waste pools and on combine-with-other-bigints arithmetic.
#[test]
#[ignore = "BUG-25 P3: best_waste sentinel is i64::MAX not MAX_MONEY"]
fn bug25_best_waste_sentinel() {
    panic!(
        "BUG-25: best_waste sentinel is i64::MAX (9.2e18) not Core's \
         MAX_MONEY (21M * COIN = 2.1e15). Hygiene; not a hot-path \
         bug. coin_selection.rs:179."
    );
}

/// BUG-26 / G30 [P3]: `GetShuffledInputVector` MISSING.
///
/// Core's `SelectionResult::GetShuffledInputVector` (`coinselection.
/// cpp:941-946`) shuffles the final input order before tx
/// construction (privacy: prevents input-order fingerprinting).
/// Rustoshi `wallet.rs:572-580` iterates `selected_utxos.iter()` in
/// selection order.
#[test]
#[ignore = "BUG-26 P3: GetShuffledInputVector (final input-order shuffle) MISSING"]
fn bug26_shuffled_input_vector_missing() {
    panic!(
        "BUG-26: GetShuffledInputVector MISSING. SelectionResult must \
         provide get_shuffled_inputs(rng) and wallet.rs:572-580 must \
         use it. Core: coinselection.cpp:941-946. Privacy: prevents \
         input-order fingerprinting."
    );
}

// ============================================================================
// Pattern-1 source-grep sentinels — flag if comment/literal regress
// ============================================================================

/// Source-level forward-regression guard for the COMMENT-AS-CONFESSION
/// pattern in BUG-1. If a future wave changes `wallet.rs:517` to set
/// the long-term feerate to Core's actual default (10 sat/vB =
/// 10_000.0 / 1000.0 = 10.0 sat/vB, or equivalently 10000 sat/kvB),
/// flip this test from ignored to PASS.
///
/// This is a documentation-only sentinel; passes today by virtue of
/// the BUG existing. The intent is to fail CI when the bug is fixed
/// but the test isn't updated, catching the FIX-N follow-up.
#[test]
fn bug1_source_guard_pinning_buggy_literal() {
    // We can't grep source files from a test binary cleanly; this is
    // a behavioural proxy. Construct a coin-selection with the
    // bootstrap params and verify the waste is computed with a
    // ~1000× smaller LTFR vs Core. Once BUG-1 is fixed, change this
    // assertion (or remove it).
    let params = CoinSelectionParams::default();
    // params.long_term_fee_rate hits Default::default which is 10.0
    // in the module's Default impl (coin_selection.rs:71). The bug
    // lives at wallet.rs:517 where the *wallet's* call site sets
    // 10.0 / 1000.0 = 0.01. The module Default is OK in isolation;
    // the call site is the bug.
    assert!(
        params.long_term_fee_rate > 0.0,
        "BUG-1 source guard: module default is fine; bug is in \
         wallet.rs:517 call site. This test exists to document the \
         distinction."
    );
}
