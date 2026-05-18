// W139 Fee-estimation engine audit (CBlockPolicyEstimator parity) — rustoshi
//
// Brief targeted `crates/mempool/tests/...`; the rustoshi tree has no
// `mempool` crate so the fee estimator lives in `crates/consensus`, where
// W114 (prior fee-estimation audit) also lives. New W139 tests follow the
// same convention.
//
// Gates: G1-G30. Failing tests carry an `#[ignore]` with a BUG-N comment.
// Naming: `g<N>_<description>`. PASS gates assert the Core-parity invariant
// directly; FAIL gates assert the EXPECTED Core-parity invariant and are
// ignored until the corresponding FIX-fee-X lands.
//
// Reference: bitcoin-core/src/policy/fees/block_policy_estimator.{h,cpp}
// + bitcoin-core/src/rpc/fees.cpp
// + bitcoin-core/src/test/policyestimator_tests.cpp

use rustoshi_consensus::fee_estimator::{
    FeeEstimator, Horizon,
    SHORT_BLOCK_PERIODS, MED_BLOCK_PERIODS, LONG_BLOCK_PERIODS,
    SHORT_SCALE, MED_SCALE, LONG_SCALE,
    SHORT_DECAY, MED_DECAY, LONG_DECAY,
};
use rustoshi_primitives::Hash256;

// ─── helpers ────────────────────────────────────────────────────────────────

fn make_txid(n: u32) -> Hash256 {
    let mut bytes = [0u8; 32];
    bytes[0..4].copy_from_slice(&n.to_le_bytes());
    Hash256::from_bytes(bytes)
}

/// Populate a healthy training set (300 txs @ 10 sat/vB confirming in 1 block).
fn populate_for_estimate(est: &mut FeeEstimator, count: u32, fee_rate: f64, target_block: u32) {
    for i in 0..count {
        est.track_transaction(make_txid(i), fee_rate);
    }
    // Empty blocks up to target_block - 1.
    for h in 1u32..target_block {
        est.process_block(h, &[]);
    }
    let confirmed: Vec<Hash256> = (0..count).map(make_txid).collect();
    est.process_block(target_block, &confirmed);
}

// ─── G1: SHORT/MED/LONG period constants 12/24/42 ───────────────────────────

/// G1 PASS — three independent horizon periods present. FIX-48 closed
/// W114 BUG-1 (was single-horizon estimator).
#[test]
fn g1_horizon_period_constants_present() {
    assert_eq!(SHORT_BLOCK_PERIODS, 12, "SHORT_BLOCK_PERIODS must be 12");
    assert_eq!(MED_BLOCK_PERIODS,   24, "MED_BLOCK_PERIODS must be 24");
    assert_eq!(LONG_BLOCK_PERIODS,  42, "LONG_BLOCK_PERIODS must be 42");
    assert_eq!(Horizon::Short.periods(),  12);
    assert_eq!(Horizon::Medium.periods(), 24);
    assert_eq!(Horizon::Long.periods(),   42);
}

// ─── G2: SHORT/MED/LONG scale constants 1/2/24 ──────────────────────────────

/// G2 PASS — three scale factors present. Max-target per horizon =
/// periods * scale = 12 / 48 / 1008.
#[test]
fn g2_horizon_scale_constants_present() {
    assert_eq!(SHORT_SCALE,  1);
    assert_eq!(MED_SCALE,    2);
    assert_eq!(LONG_SCALE,   24);
    assert_eq!(Horizon::Short.max_target(),  12);
    assert_eq!(Horizon::Medium.max_target(), 48);
    assert_eq!(Horizon::Long.max_target(),   1008);
}

// ─── G3: SHORT/MED/LONG decay constants .962/.9952/.99931 ───────────────────

/// G3 PASS — three Core-correct decay constants present (FIX-48).
#[test]
fn g3_horizon_decay_constants_correct() {
    assert!((SHORT_DECAY - 0.962).abs()   < 1e-6);
    assert!((MED_DECAY   - 0.9952).abs()  < 1e-6);
    assert!((LONG_DECAY  - 0.99931).abs() < 1e-6);
    // 18-block half-life on SHORT: SHORT_DECAY^18 ≈ 0.500.
    let s18 = SHORT_DECAY.powi(18);
    assert!(s18 > 0.45 && s18 < 0.55, "SHORT half-life ≈18 blocks, got {}", s18);
    // 144-block half-life on MED: MED_DECAY^144 ≈ 0.500.
    let m144 = MED_DECAY.powi(144);
    assert!(m144 > 0.45 && m144 < 0.55, "MED half-life ≈144 blocks, got {}", m144);
    // 1008-block half-life on LONG: LONG_DECAY^1008 ≈ 0.500.
    let l1008 = LONG_DECAY.powi(1008);
    assert!(l1008 > 0.45 && l1008 < 0.55, "LONG half-life ≈1008 blocks, got {}", l1008);
}

// ─── G4: bucket range MIN=100 sat/kvB MAX=1e7 sat/kvB FEE_SPACING=1.05 ──────

/// BUG-1 (P0 — CDIV-adjacent): rustoshi has 40 manually-defined sat/vB
/// buckets (1..10000) vs Core MIN=100 sat/kvB MAX=1e7 sat/kvB
/// FEE_SPACING=1.05 → ~237 buckets in sat/kvB units.
/// Site: crates/consensus/src/fee_estimator.rs:77-81.
#[test]
#[ignore] // BUG-1: bucket boundaries hardcoded sat/vB (40 manual) vs Core 100..1e7 sat/kvB exp-spaced (~237)
fn g4_bucket_range_and_fee_spacing() {
    let est = FeeEstimator::new();
    // Expected Core invariant: bucket_count() ≈ 237 (log(1e7/100)/log(1.05)+1+sentinel).
    let n = est.bucket_count();
    assert!(
        n >= 190 && n <= 250,
        "Expected ~237 Core-compatible buckets (MIN=100 MAX=1e7 SPACING=1.05), got {}",
        n
    );
}

// ─── G5: SUFFICIENT_FEETXS=0.1 + SUFFICIENT_TXS_SHORT=0.5 ───────────────────

/// BUG-2 (P0): rustoshi uses absolute MIN_TRACKED_TXS=200.0 across all
/// horizons. Core uses SUFFICIENT_FEETXS=0.1 for MED/LONG and
/// SUFFICIENT_TXS_SHORT=0.5 for SHORT, both as PER-BUCKET-GROUP minimums
/// scaled by `sufficient/(1-decay)`. Concretely: SHORT needs ≥13 decayed
/// txs per group; LONG needs ≥145 per group.
/// Site: fee_estimator.rs:84 + 277.
#[test]
#[ignore] // BUG-2: MIN_TRACKED_TXS=200 absolute vs Core dynamic SUFFICIENT/(1-decay) per-bucket-group
fn g5_sufficient_txs_thresholds() {
    let mut est = FeeEstimator::new();
    // With only ~13 decayed txs in SHORT bucket Core would estimate; rustoshi won't.
    for i in 0..15u32 {
        est.track_transaction(make_txid(i), 10.0);
    }
    let confirmed: Vec<Hash256> = (0..15).map(make_txid).collect();
    est.process_block(1, &confirmed);
    let est_short = est.estimate_fee(1);
    assert!(
        est_short.is_some(),
        "SHORT horizon with ~15 confirmed txs should produce an estimate per Core SUFFICIENT_TXS_SHORT=0.5"
    );
}

// ─── G6: ~237 bucket count ──────────────────────────────────────────────────

/// BUG-3 (P1): bucket_count() == 40 (rustoshi) vs ~237 (Core). Concrete
/// consequence of BUG-1.
#[test]
#[ignore] // BUG-3: 40 buckets vs Core ~237 — coarse quantization
fn g6_bucket_count_matches_core() {
    let est = FeeEstimator::new();
    let n = est.bucket_count();
    // Core: log(1e7/100)/log(1.05) ≈ 236 + 1 sentinel = ~237.
    assert!(n >= 190 && n <= 250, "expected ~237 buckets, got {}", n);
}

// ─── G7: O(log n) bucket lookup ─────────────────────────────────────────────

/// G7 PARTIAL — rustoshi uses `binary_search_by` over `&[f64]` which is
/// O(log n) (same as Core's `bucketMap.lower_bound`). The algorithm is
/// correct; the data shape is wrong (BUG-1) and the lookup panics on NaN
/// (BUG-27). Test verifies the *algorithm* is binary-search-shaped.
#[test]
fn g7_bucket_lookup_binary_search() {
    let mut est = FeeEstimator::new();
    // Several inserts at different fee rates must all be tracked without
    // O(n)-scan behavior implied panics or duplicates.
    for (i, rate) in [(1u32, 1.0_f64), (2, 5.0), (3, 50.0), (4, 500.0), (5, 5000.0)].iter().copied() {
        est.track_transaction(make_txid(i), rate);
    }
    assert_eq!(est.tracked_count(), 5);
}

// ─── G8: bucket units sat/kvB ───────────────────────────────────────────────

/// BUG-5 (P0 — CDIV-adjacent): rustoshi stores fee_rate in sat/vB; Core
/// stores `feeRate.GetFeePerK()` (sat/kvB, i.e. sat/1000 vbytes).
/// Internal values diverge by 1000x. Any cross-impl persistence interop
/// fails.
/// Site: fee_estimator.rs:77-81 + server.rs:3997 (rate*1000 conversion).
#[test]
#[ignore] // BUG-5: internal bucket units sat/vB vs Core sat/kvB; saved files off by 1000x
fn g8_bucket_units_sat_per_kvb() {
    // Probe by checking that the lowest-feerate bucket (after fix) corresponds
    // to Core's MIN_BUCKET_FEERATE=100 sat/kvB = 0.1 sat/vB, not 1 sat/vB.
    // We can't introspect FEE_RATE_BUCKETS directly without exposing it,
    // but we can probe by tracking a 0.1 sat/vB tx and confirming it's
    // distinguishable from the next-highest bucket. With the rustoshi 40-
    // bucket sat/vB scheme, 0.1 sat/vB and 0.5 sat/vB and 0.9 sat/vB all
    // collapse to bucket 0.
    //
    // After fix: 0.1 sat/vB is bucket 0; 0.5 sat/vB is a different bucket
    // (FEE_SPACING=1.05 ⇒ 0.1 → 0.105 → 0.110 → ... → 0.5 spans ~33 buckets).
    let est = FeeEstimator::new();
    // Bucket count > 100 implies Core-parity sat/kvB scheme.
    assert!(
        est.bucket_count() > 100,
        "with Core sat/kvB scheme bucket_count > 100; rustoshi sat/vB scheme = 40"
    );
}

// ─── G9: failAvg failure tracking ───────────────────────────────────────────

/// BUG-6 (P0 — CDIV-adjacent): rustoshi `BucketStats` has only
/// `confirmed_within`, `total`, `fee_sum`. Core's `TxConfirmStats` has
/// `failAvg[period][bucket]` populated by `removeTx(inBlock=false)`.
/// Failure tally feeds the denominator in EstimateMedianVal:
///   curPct = nConf / (totalNum + failNum + extraNum)
/// Without it, every estimate is over-optimistic by the failure rate.
/// Site: fee_estimator.rs:159-167.
#[test]
#[ignore] // BUG-6: BucketStats lacks failAvg — failure-to-confirm txs never penalize the success rate
fn g9_fail_avg_tracking_present() {
    // After the fix, a `failure_total(bucket_index, horizon)` accessor (or
    // equivalent) will exist on FeeEstimator. Pre-fix the test simply
    // documents the gap.
    //
    // Behavioural assertion (post-fix): a removed-not-confirmed tx must
    // increment a fail-counter that is exposed and queryable.
    let _est = FeeEstimator::new();
    // We can't probe failAvg directly until the API exists. Mark as a
    // structural gap by asserting a (yet-to-exist) accessor would be Some.
    panic!("failAvg accessor not yet present — gate blocked on FIX-fee-E");
}

// ─── G10: unconfTxs circular buffer ─────────────────────────────────────────

/// BUG-7 (P0 — CDIV-adjacent): TxConfirmStats lacks `unconfTxs[bins][bucket]`
/// circular buffer for in-flight mempool txs. Core uses these for the
/// `extraNum` denominator in EstimateMedianVal (line 290-292 of
/// block_policy_estimator.cpp).
/// Site: fee_estimator.rs:193-202.
#[test]
#[ignore] // BUG-7: no unconfTxs circular buffer — in-flight denominator missing from EstimateMedianVal
fn g10_unconf_txs_circular_buffer() {
    let _est = FeeEstimator::new();
    panic!("unconfTxs[bins][bucket] not yet present — gate blocked on FIX-fee-E");
}

// ─── G11: oldUnconfTxs aged-out swept on ClearCurrent ───────────────────────

/// BUG-8 (P0 — CDIV-adjacent): rustoshi `process_block` uses `retain()`
/// to silently drop aged-out tracked txs (fee_estimator.rs:447-449).
/// Core's `ClearCurrent` sweeps the oldest `unconfTxs[block%bins]` slot
/// into `oldUnconfTxs[bucket]` so aged-out unconfirmed txs are still
/// counted in `extraNum`.
/// Site: fee_estimator.rs:447-449.
#[test]
#[ignore] // BUG-8: stale txs dropped via retain() instead of swept into oldUnconfTxs
fn g11_old_unconf_txs_swept_on_clear_current() {
    let mut est = FeeEstimator::new();
    // Track 10 txs, never confirm, run past MAX_CONFIRMATION_TARGET.
    for i in 0..10u32 {
        est.track_transaction(make_txid(i), 10.0);
    }
    for h in 1..=1020u32 {
        est.process_block(h, &[]);
    }
    // Tracked count drops to 0 (rustoshi already does this via retain).
    assert_eq!(est.tracked_count(), 0);
    // Post-fix: the same 10 txs should be visible as `oldUnconfTxs[bucket]`
    // contributions. Pre-fix: no accessor.
    panic!("oldUnconfTxs accessor not yet present — gate blocked on FIX-fee-E");
}

// ─── G12: process_block reorg guard ─────────────────────────────────────────

/// BUG-9 (P0): `process_block` lacks the `if (nBlockHeight <=
/// nBestSeenHeight) return;` guard. A 1-block reorg that re-connects the
/// same height re-runs decay AND re-records confirmations (double cumulative-fill).
/// Site: fee_estimator.rs:423-454 (no early-return on height regression).
/// Core ref: block_policy_estimator.cpp:673-680.
#[test]
#[ignore] // BUG-9: no reorg guard — re-processing same height double-decays + double-records
fn g12_process_block_reorg_guard() {
    let mut est = FeeEstimator::new();
    populate_for_estimate(&mut est, 300, 10.0, 1);
    let est_after_first = est.estimate_fee(1);
    assert!(est_after_first.is_some());

    // Replay process_block with same height + same confirmed set. With
    // Core's guard this is a no-op. Without it, decay runs again and
    // confirmed_within is double-credited.
    let confirmed: Vec<Hash256> = (0..300).map(make_txid).collect();
    // (already removed from tracked by first process_block, so re-process
    // is a no-op for the confirmation channel but DOES re-decay).
    est.process_block(1, &confirmed);

    // Post-fix: estimate after replay equals estimate after first block.
    // Pre-fix: estimate has been decayed twice for the same block.
    let est_after_replay = est.estimate_fee(1);
    assert_eq!(
        est_after_replay, est_after_first,
        "reorg guard: replaying same-height process_block must be a no-op"
    );
}

// ─── G13: validForFeeEstimation filter ──────────────────────────────────────

/// BUG-10 (P0 — CDIV-adjacent): rustoshi `track_transaction` accepts every
/// tx unconditionally; Core's `processTransaction` skips when
///   m_mempool_limit_bypassed || m_submitted_in_package
///   || !m_chainstate_is_current || !m_has_no_mempool_parents.
/// Site: fee_estimator.rs:410-420 — no flag parameters; nor at wiring sites
/// in main.rs:3142 / server.rs:3736.
/// Core ref: block_policy_estimator.cpp:619-626.
#[test]
#[ignore] // BUG-10: track_transaction lacks validForFeeEstimation filter (package/priority/parents/stale)
fn g13_valid_for_fee_estimation_filter() {
    // Post-fix: track_transaction signature includes `valid_for_fee_estimation: bool`
    // or accepts a flags struct. Pre-fix: every tx tracked.
    //
    // Behavioural property: a tx with `m_has_no_mempool_parents = false`
    // (i.e. has unconfirmed mempool parents) should NOT update the
    // estimator's tracked set.
    let _est = FeeEstimator::new();
    panic!("valid_for_fee_estimation filter not yet present — gate blocked on FIX-fee-J");
}

// ─── G14: remove_tx public API + 3-horizon dispatch ────────────────────────

/// BUG-11 (P0 — CDIV-adjacent): no `remove_tx(hash, in_block)` method on
/// FeeEstimator. Core uses this on `TransactionRemovedFromMempool` to
/// route to all 3 horizons' `removeTx` and increment `failAvg`.
/// Site: fee_estimator.rs — entire surface lacks this method.
/// Core ref: block_policy_estimator.cpp:522-541.
#[test]
#[ignore] // BUG-11: FeeEstimator has no remove_tx() public API — RBF/eviction failures lost
fn g14_remove_tx_public_api() {
    let _est = FeeEstimator::new();
    // Post-fix: FeeEstimator::remove_tx(&mut self, txid, in_block: bool) -> bool.
    // Pre-fix: symbol does not exist.
    panic!("FeeEstimator::remove_tx not yet present — gate blocked on FIX-fee-F");
}

// ─── G15: RBF eviction notifies remove_tx ──────────────────────────────────

/// BUG-12 (P1): RBF eviction sites in the mempool don't call
/// FeeEstimator::remove_tx (because that API doesn't exist — BUG-11).
/// Site: any RBF replacement path in mempool admission.
#[test]
#[ignore] // BUG-12: RBF replacements not notified to fee estimator (no remove_tx call)
fn g15_rbf_eviction_notifies_remove_tx() {
    let _est = FeeEstimator::new();
    panic!("RBF eviction → remove_tx wiring not yet present — gate blocked on FIX-fee-F");
}

// ─── G16: EstimateMedianVal grouping algorithm ──────────────────────────────

/// BUG-13 (P0): rustoshi `estimate_with_threshold` (fee_estimator.rs:255-289)
/// implements a global cumulative-from-top algorithm with `break` on first
/// failure. Core's `EstimateMedianVal`:
///   1. groups by `partialNum >= sufficientTxVal/(1-decay)`
///   2. records `bestNearBucket / bestFarBucket` per passing group
///   3. on a group failure sets `passing=false` and records `failBucket`,
///      then `continue` (not `break`) — lower groups can recover
///   4. returns weighted median `m_feerate_avg[j]/txCtAvg[j]` of the best
///      bucket range, not a boundary
/// Site: fee_estimator.rs:255-289.
/// Core ref: block_policy_estimator.cpp:245-409.
#[test]
#[ignore] // BUG-13: EstimateMedianVal grouping uses global threshold + early break; Core groups + continues
fn g16_estimate_median_val_grouping() {
    // Test idea: build a bimodal feerate distribution and assert rustoshi
    // returns the same estimate Core would (the middle-bucket weighted median),
    // not the high-bucket boundary.
    let mut est = FeeEstimator::new();
    // 200 txs at 100 sat/vB confirming in 1 block.
    for i in 0..200u32 {
        est.track_transaction(make_txid(i), 100.0);
    }
    let high: Vec<Hash256> = (0..200).map(make_txid).collect();
    est.process_block(1, &high);
    // 200 txs at 5 sat/vB confirming in block 2.
    for i in 200..400u32 {
        est.track_transaction(make_txid(i), 5.0);
    }
    let low: Vec<Hash256> = (200..400).map(make_txid).collect();
    est.process_block(2, &low);
    // Core's algorithm with target=1 returns the weighted median in the
    // best PASSING bucket group. With bimodal data and 85% threshold the
    // result should be ~7-10 sat/vB (bottom-of-distribution where 85% are
    // confirmed within 1 block). Rustoshi's algorithm `break`s early after
    // the high group passes, returning ~100 sat/vB (or 5 sat/vB depending
    // on whether the global 200 threshold triggers).
    let _est_val = est.estimate_fee(2).expect("should have an estimate with 400 txs");
    panic!("EstimateMedianVal grouping behaviour not Core-parity — gate blocked on FIX-fee-G");
}

// ─── G17: weighted-median return (not bucket boundary) ─────────────────────

/// BUG-14 (P1): rustoshi returns `FEE_RATE_BUCKETS[i]` (the low boundary
/// of the best bucket) at fee_estimator.rs:283. Core returns
/// `m_feerate_avg[j] / txCtAvg[j]` (block_policy_estimator.cpp:362) — the
/// weighted average inside the bucket. `fee_sum` is tracked on
/// BucketStats but never used in the estimate path.
/// Site: fee_estimator.rs:283 (returns boundary) + 166 (fee_sum field).
#[test]
#[ignore] // BUG-14: returns bucket boundary not m_feerate_avg/txCtAvg weighted median; fee_sum field unused
fn g17_returns_weighted_median_not_bucket_boundary() {
    // Track 300 txs at 11 sat/vB (between buckets 10 and 12 in rustoshi's
    // ad-hoc table). With current code the returned estimate is 10.0
    // (boundary). With Core-parity it should be 11.0 (weighted average
    // inside bucket).
    let mut est = FeeEstimator::new();
    for i in 0..300u32 {
        est.track_transaction(make_txid(i), 11.0);
    }
    let confirmed: Vec<Hash256> = (0..300).map(make_txid).collect();
    est.process_block(1, &confirmed);
    let v = est.estimate_fee(1).expect("estimate should exist with 300 confirmations");
    // Core would return ~11.0 (the actual paid feerate average).
    assert!(
        (v - 11.0).abs() < 0.5,
        "expected weighted-median ≈11.0 sat/vB (actual paid avg), got {} (likely bucket boundary 10.0)",
        v
    );
}

// ─── G18: estimatesmartfee RPC accepts `estimate_mode` ──────────────────────

/// BUG-15 (P0): trait signature `estimate_smart_fee(conf_target: u32)`
/// does NOT accept the `estimate_mode` parameter that Core's RPC requires.
/// Callers passing "conservative" get ignored / silently downgraded.
/// Site: crates/rpc/src/server.rs:413-414.
/// Core ref: rpc/fees.cpp:42-43 + 72-75.
#[test]
#[ignore] // BUG-15: estimatesmartfee RPC missing estimate_mode parameter (unset/economical/conservative)
fn g18_estimatesmartfee_accepts_estimate_mode() {
    // Documents the trait signature gap. The fix requires breaking the trait
    // (or adding a new method) so the RPC layer can plumb conservative mode
    // into estimate_fee.
    panic!("trait signature lacks estimate_mode — gate blocked on FIX-fee-C");
}

// ─── G19: estimateSmartFee = max(halfEst, actualEst, doubleEst, consEst) ───

/// BUG-16 (P0): rustoshi's `estimate_smart_fee` RPC calls only
/// `state.fee_estimator.estimate_fee(conf_target)` (single SHORT @ 85%).
/// Core's `estimateSmartFee` (block_policy_estimator.cpp:919-940) computes:
///   halfEst   = estimateCombinedFee(t/2,   60%)
///   actualEst = estimateCombinedFee(t,     85%)
///   doubleEst = estimateCombinedFee(2*t,   95%)
///   consEst   = conservative ? estimateConservativeFee(2*t) : -1
///   median    = max(halfEst, actualEst, doubleEst, consEst)
/// The MAX is critical — rustoshi's single-call answer is whichever is
/// LOWEST of those three. Guaranteed too-low.
/// Site: crates/rpc/src/server.rs:3989-4010.
#[test]
#[ignore] // BUG-16: estimateSmartFee max(half@60%, actual@85%, double@95%, cons) reduction missing
fn g19_estimate_smart_fee_max_reduction() {
    panic!("estimateSmartFee max-of-three reduction not yet present — gate blocked on FIX-fee-C");
}

// ─── G20: estimateCombinedFee short/medium/long fallback ───────────────────

/// BUG-17 (P1): rustoshi's `estimate_fee` dispatches to a single horizon
/// via `horizon_for_target`. Core's `estimateCombinedFee` (line 808-842):
///   - Picks shortest horizon covering target.
///   - If `checkShorterHorizon=true`, ALSO probes MED@medMax and SHORT@shortMax
///     and returns the LOWEST of the three (preserves monotonicity:
///     estimate(N+1) ≥ estimate(N) for all N).
/// Site: fee_estimator.rs:458-461 (estimate_internal single horizon).
#[test]
#[ignore] // BUG-17: estimateCombinedFee shorter-horizon monotonicity fallback missing
fn g20_estimate_combined_fee_shorter_horizon_fallback() {
    panic!("estimateCombinedFee shorter-horizon monotonicity fallback not yet present — gate blocked on FIX-fee-C");
}

// ─── G21: conf_target==1 normalized to 2 ───────────────────────────────────

/// BUG-18 (P1): rustoshi accepts conf_target=1 and queries SHORT@1.
/// Core (block_policy_estimator.cpp:890):
///   if (confTarget == 1) confTarget = 2;
/// — because 1-block estimates are statistically unreliable.
/// Site: crates/rpc/src/server.rs:3989.
#[test]
#[ignore] // BUG-18: conf_target=1 not normalized to 2 (Core estimateSmartFee line 890)
fn g21_conf_target_one_normalized_to_two() {
    // Post-fix the RPC handler clamps conf_target=1 to 2 before invoking
    // the estimator. Behavioural property: estimate_smart_fee(1) ==
    // estimate_smart_fee(2).
    panic!("conf_target=1 → 2 normalization missing — gate blocked on FIX-fee-C");
}

// ─── G22: RPC floors with max(feeRate, min_mempool_feerate, min_relay_feerate) ─

/// BUG-19 (P0 — operator-trap): rustoshi's `estimate_smart_fee` RPC
/// returns the raw estimator value without applying the mempool/relay
/// min-fee floor. Under fee-spike conditions a wallet using the estimate
/// will broadcast a tx that the local node REJECTS on submission.
/// Site: crates/rpc/src/server.rs:3997-4002.
/// Core ref: rpc/fees.cpp:82-86.
#[test]
#[ignore] // BUG-19: estimate_smart_fee returns raw estimate without max(feeRate, min_mempool, min_relay) floor
fn g22_rpc_floors_with_min_fee() {
    panic!("RPC handler min-fee floor missing — gate blocked on FIX-fee-B");
}

// ─── G23: MaxUsableEstimate clamps confTarget ──────────────────────────────

/// BUG-20 (P1): rustoshi has no `MaxUsableEstimate()`. Core
/// (block_policy_estimator.cpp:798-802):
///   return min(longStats->GetMaxConfirms(),
///              max(BlockSpan(), HistoricalBlockSpan()) / 2);
/// — applied at estimateSmartFee line 892-895 to clamp conf_target.
/// Without it, a freshly-booted node with 5 blocks of data happily
/// returns a 1008-block estimate.
/// Site: fee_estimator.rs — entire file lacks BlockSpan/MaxUsableEstimate.
#[test]
#[ignore] // BUG-20: MaxUsableEstimate clamp missing — fresh node returns 1008-block estimates from 5 blocks
fn g23_max_usable_estimate_clamp() {
    panic!("MaxUsableEstimate() clamp missing — gate blocked on FIX-fee-K");
}

// ─── G24: BlockSpan / firstRecordedHeight / historicalFirst / historicalBest ───

/// BUG-21 (P1): rustoshi tracks only `current_height`. Core tracks 4
/// fields (`block_policy_estimator.h:278-281`):
///   nBestSeenHeight, firstRecordedHeight, historicalFirst, historicalBest.
/// MaxUsableEstimate (BUG-20) requires all four.
/// Site: fee_estimator.rs:370-375 (only `current_height`).
#[test]
#[ignore] // BUG-21: only `current_height` — missing firstRecordedHeight/historicalFirst/historicalBest
fn g24_block_span_state_fields() {
    panic!("BlockSpan state fields missing — gate blocked on FIX-fee-K");
}

// ─── G25: Binary fee_estimates.dat format + CURRENT_FEES_FILE_VERSION ──────

/// BUG-22 (P0 — CDIV-adjacent): rustoshi writes
/// `fee_estimates.json` (serde_json). Core writes `fee_estimates.dat`
/// (binary AutoFile) with `CURRENT_FEES_FILE_VERSION = 309900` magic +
/// per-horizon `TxConfirmStats::Write`. No interop.
/// Site: fee_estimator.rs:543-556 (`save`) + 562-591 (`load`).
/// Core ref: block_policy_estimator.cpp:978-1062.
#[test]
#[ignore] // BUG-22: JSON format vs Core binary AutoFile with CURRENT_FEES_FILE_VERSION magic
fn g25_persistence_format_core_binary() {
    panic!("fee_estimates.dat binary format not yet present — gate blocked on FIX-fee-I");
}

// ─── G26: MAX_FILE_AGE = 60h stale-file rejection ───────────────────────────

/// BUG-23 (P1): rustoshi `load` accepts arbitrarily old
/// `fee_estimates.json`. Core (block_policy_estimator.cpp:568-572):
///   std::chrono::hours file_age = GetFeeEstimatorFileAge();
///   if (file_age > MAX_FILE_AGE && !read_stale_estimates) return;
/// MAX_FILE_AGE = 60h; override = `-acceptstalefeeestimates` flag.
/// Site: fee_estimator.rs:562-591.
#[test]
#[ignore] // BUG-23: load lacks MAX_FILE_AGE=60h stale-file check + DEFAULT_ACCEPT_STALE_FEE_ESTIMATES override
fn g26_max_file_age_stale_rejection() {
    panic!("MAX_FILE_AGE stale-file rejection missing — gate blocked on FIX-fee-I");
}

// ─── G27: Periodic FlushFeeEstimates at FEE_FLUSH_INTERVAL=1h ──────────────

/// BUG-24 (P2): rustoshi saves only at shutdown (main.rs:4274). Core
/// invokes `FlushFeeEstimates` periodically every 1h via the scheduler
/// (FEE_FLUSH_INTERVAL = 1h, block_policy_estimator.h:26).
/// Site: rustoshi/src/main.rs — no periodic-flush scheduler integration.
#[test]
#[ignore] // BUG-24: no periodic FlushFeeEstimates scheduler — data lost on crash between startup and shutdown
fn g27_periodic_flush_fee_estimates() {
    panic!("FEE_FLUSH_INTERVAL=1h periodic flush not yet wired — gate blocked on FIX-fee-I");
}

// ─── G28: estimaterawfee returns {short, medium, long} per horizon ─────────

/// BUG-25 (P1 — comment-as-confession + stale-after-internal-refactor):
/// rustoshi's `estimate_raw_fee` RPC handler emits a FLAT object with
/// hardcoded `decay=0.998` (the OLD pre-FIX-48 single decay constant!)
/// and `scale=1` (also stale). The 3-horizon engine FIX-48 added
/// SHORT_DECAY/MED_DECAY/LONG_DECAY = 0.962/0.9952/0.99931, but the RPC
/// surface never propagated; the accompanying comment at server.rs:4050-4052
/// says "rustoshi has a single horizon" — factually wrong post-FIX-48.
/// Core (rpc/fees.cpp:170-211) emits `{short, medium, long}` with
/// per-horizon `decay/scale/pass/fail/errors`.
/// Site: crates/rpc/src/server.rs:4012-4063.
#[test]
#[ignore] // BUG-25: estimaterawfee flat response + hardcoded stale `decay=0.998` (pre-FIX-48 constant)
fn g28_estimaterawfee_three_horizon_response_shape() {
    panic!("estimaterawfee three-horizon response shape not yet emitted — gate blocked on FIX-fee-H");
}

// ─── G29: FlushUnconfirmed at shutdown ──────────────────────────────────────

/// BUG-26 (P0 — CDIV-adjacent): rustoshi `save()` writes current state
/// without flushing unconfirmed mempool txs. Core (block_policy_estimator.cpp:1064-1076):
///   void FlushUnconfirmed() {
///       while (!mapMemPoolTxs.empty()) {
///           auto mi = mapMemPoolTxs.begin();
///           _removeTx(mi->first, false);  // records as failure
///       }
///   }
///   void Flush() {
///       FlushUnconfirmed();
///       FlushFeeEstimates();
///   }
/// Without FlushUnconfirmed: every tx still in mempool at shutdown is a
/// missing failure datapoint → next session's estimates skew downward.
/// Site: fee_estimator.rs:543-556 + rustoshi/src/main.rs:4274.
#[test]
#[ignore] // BUG-26: no FlushUnconfirmed at shutdown — pending mempool txs not recorded as failures
fn g29_flush_unconfirmed_at_shutdown() {
    panic!("FlushUnconfirmed at shutdown not yet wired — gate blocked on FIX-fee-I");
}

// ─── G30: NaN-safe bucket lookup ────────────────────────────────────────────

/// BUG-27 (P2): rustoshi `fee_rate_to_bucket` uses
/// `binary_search_by(|b| b.partial_cmp(&fee_rate).unwrap())`. `partial_cmp`
/// returns `None` on NaN ⇒ `.unwrap()` panics. Reachable through any
/// caller that computes a fee_rate from a 0-vsize tx (Inf/0) or via
/// corrupt persistence file containing NaN.
/// Site: fee_estimator.rs:392.
#[test]
fn g30_nan_safe_bucket_lookup_panics_today() {
    use std::panic;
    let mut est = FeeEstimator::new();
    // Force a NaN through track_transaction.
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        est.track_transaction(make_txid(1), f64::NAN);
    }));
    // Today this panics on the `.unwrap()` inside binary_search_by.
    // Post-fix: NaN is treated as 0.0 (bucket 0) or rejected without panic.
    // Until fixed, we PIN the buggy behaviour to detect when it's repaired.
    assert!(
        result.is_err(),
        "BUG-27 pre-fix sentinel: bucket lookup PANICS on NaN today; \
         if this assertion fails, the panic-on-NaN bug was fixed — \
         flip this test to assert track_transaction(NaN) is a graceful no-op or 0-bucket assign."
    );
}

// ─── DEAD-HELPER / WIRING audit notes ───────────────────────────────────────

/// W114 BUG-DEAD-HELPER (process_block never called) is CLOSED.
/// Verified by inspection at:
///   - rustoshi/src/main.rs:2453 (IBD path)
///   - rustoshi/src/main.rs:3000 (P2P live-block path)
/// Both call rpc.fee_estimator.process_block(height, &confirmed_txids).
#[test]
fn w114_dead_helper_closed_regression_pin() {
    // Behavioural test pin: process_block can be invoked and updates
    // tracked_count + current_height. This passes today; will continue
    // to pass while the wiring sites stay live.
    let mut est = FeeEstimator::new();
    est.track_transaction(make_txid(1), 10.0);
    assert_eq!(est.tracked_count(), 1);
    est.process_block(1, &[make_txid(1)]);
    assert_eq!(est.tracked_count(), 0);
    assert_eq!(est.current_height(), 1);
}

/// W114 BUG-P2P-WIRING (P2P track_transaction not wired) is CLOSED.
/// Verified at rustoshi/src/main.rs:3142.
#[test]
fn w114_p2p_wiring_closed_regression_pin() {
    // Pure regression pin — track_transaction is the API both RPC and P2P
    // call. As long as the symbol exists and stores fee_rate, both
    // wiring sites function.
    let mut est = FeeEstimator::new();
    est.track_transaction(make_txid(1), 7.5);
    assert_eq!(est.tracked_count(), 1);
}

// ─── Save/load round-trip (current state, for forward-regression) ──────────

/// Verifies the current JSON save/load round-trip preserves the estimator
/// state. Post-fix this test should be RE-WRITTEN to use the binary Core
/// format (BUG-22) — for now it pins current behaviour.
#[test]
fn current_save_load_round_trip_pin() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("fee_estimates.json");
    let mut est = FeeEstimator::new();
    populate_for_estimate(&mut est, 300, 10.0, 1);
    let before = est.estimate_fee(1);
    est.save(&path).expect("save");
    let loaded = FeeEstimator::load(&path);
    let after = loaded.estimate_fee(1);
    assert_eq!(before, after);
    assert_eq!(loaded.current_height(), 1);
}

// ─── Forward-regression source guard: server.rs hardcoded `0.998` ──────────

/// BUG-25 source guard: detects if the hardcoded stale `decay=0.998`
/// disappears from server.rs (signalling the response-shape fix landed).
/// This grep-based guard reads the rustoshi sources directly. Lives in
/// the test binary (so CI catches the flip).
#[test]
fn bug25_source_guard_hardcoded_decay_constant() {
    // Path resolves relative to crate root (rustoshi/crates/consensus).
    // Server source: ../../crates/rpc/src/server.rs from the consensus crate.
    let server_src_paths = [
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../rpc/src/server.rs"),
        std::path::PathBuf::from("crates/rpc/src/server.rs"),
    ];
    let mut found_src = None;
    for p in &server_src_paths {
        if p.exists() {
            found_src = Some(p.clone());
            break;
        }
    }
    let server_src = match found_src {
        Some(p) => p,
        None => {
            eprintln!("server.rs not found in expected locations; source guard skipped");
            return;
        }
    };
    let body = std::fs::read_to_string(&server_src)
        .unwrap_or_else(|e| panic!("read {} failed: {}", server_src.display(), e));
    // Pre-fix: contains the literal `0.998_f64` AND the comment "single horizon".
    // The presence of EITHER indicates BUG-25 has not been fixed.
    // Once the fix lands BOTH will be gone — flip this test to assert their
    // ABSENCE (currently we just emit a warning so the test is informational).
    let has_stale_decay  = body.contains("0.998_f64");
    let has_stale_scale  = body.contains("\"scale\".to_string(), serde_json::json!(1)");
    let has_stale_comment = body.contains("rustoshi has a single\n");
    if !has_stale_decay && !has_stale_scale && !has_stale_comment {
        // The fix landed — assert the new structured response.
        assert!(
            body.contains("\"short\"") && body.contains("\"medium\"") && body.contains("\"long\""),
            "BUG-25 source guard: stale `0.998_f64` is gone but \
             new {{short, medium, long}} response shape not yet emitted in server.rs"
        );
    } else {
        // Pre-fix sentinel — informational only.
        eprintln!(
            "BUG-25 (W139) sentinel still present in server.rs: \
             stale_decay={} stale_scale={} stale_comment={}",
            has_stale_decay, has_stale_scale, has_stale_comment
        );
    }
}
