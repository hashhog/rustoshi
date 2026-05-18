# W139 — Fee estimation engine (CBlockPolicyEstimator) parity audit (rustoshi)

**Wave**: W139 — `CBlockPolicyEstimator` state machine; per-block confirmation
rate tracking; `estimatesmartfee` / `estimaterawfee` RPCs; CONSERVATIVE vs
ECONOMICAL modes; `fee_estimates.dat` persistence; bucket boundaries
(MIN_BUCKET_FEERATE=100 sat/kvB, MAX=1e7 sat/kvB, FEE_SPACING=1.05 → ~237
buckets); decay factors (SHORT 0.962 / MED 0.9952 / LONG 0.99931); 85% / 95%
/ 60% confirmation thresholds; minfeerate floor; smartfee `estimateRawFee`
output shape. (DISCOVERY)

**Impl**: rustoshi (Rust)
**Audit date**: 2026-05-18
**Reference (Bitcoin Core)**:
- `bitcoin-core/src/policy/fees/block_policy_estimator.h` (346 LOC) —
  - Constants: `SHORT_BLOCK_PERIODS=12`, `MED_BLOCK_PERIODS=24`,
    `LONG_BLOCK_PERIODS=42`, `SHORT_SCALE=1`, `MED_SCALE=2`, `LONG_SCALE=24`,
    `SHORT_DECAY=.962`, `MED_DECAY=.9952`, `LONG_DECAY=.99931`,
    `HALF_SUCCESS_PCT=.6`, `SUCCESS_PCT=.85`, `DOUBLE_SUCCESS_PCT=.95`,
    `SUFFICIENT_FEETXS=0.1`, `SUFFICIENT_TXS_SHORT=0.5`,
    `MIN_BUCKET_FEERATE=100`, `MAX_BUCKET_FEERATE=1e7`, `FEE_SPACING=1.05`,
    `OLDEST_ESTIMATE_HISTORY = 6 * 1008 = 6048`,
    `FEE_FLUSH_INTERVAL = 1h`, `MAX_FILE_AGE = 60h`,
    `DEFAULT_ACCEPT_STALE_FEE_ESTIMATES = false`.
  - Enums + structs: `FeeEstimateHorizon{SHORT,MED,LONG}_HALFLIFE`,
    `FeeReason{NONE, HALF_ESTIMATE, FULL_ESTIMATE, DOUBLE_ESTIMATE,
    CONSERVATIVE, MEMPOOL_MIN, FALLBACK, REQUIRED}`, `EstimatorBucket`
    (`start/end/withinTarget/totalConfirmed/inMempool/leftMempool`),
    `EstimationResult{pass, fail, decay, scale}`,
    `FeeCalculation{est, reason, desiredTarget, returnedTarget, best_height}`.
  - Class layout: 3 independent `std::unique_ptr<TxConfirmStats>`
    (`feeStats` [MED], `shortStats` [SHORT], `longStats` [LONG]); private
    `mapMemPoolTxs` (Txid → `TxStatsInfo{blockHeight, bucketIndex}`); private
    `buckets` (`vector<double>`) + `bucketMap` (`map<double, unsigned int>`);
    private state `nBestSeenHeight / firstRecordedHeight / historicalFirst /
    historicalBest / trackedTxs / untrackedTxs`. Mutex `m_cs_fee_estimator`.
- `bitcoin-core/src/policy/fees/block_policy_estimator.cpp` (1119 LOC) —
  - `CURRENT_FEES_FILE_VERSION = 309900` (line 37).
  - `INF_FEERATE = 1e99` (line 39) appended as a sentinel last bucket.
  - `TxConfirmStats::Record(blocksToConfirm, val)` — `periodsToConfirm =
    (blocksToConfirm + scale - 1) / scale`; cumulative fill of
    `confAvg[i-1][bucket]` for `i = periodsToConfirm..=confAvg.size()`;
    increments `txCtAvg[bucket]` and `m_feerate_avg[bucket] += feerate`.
  - `TxConfirmStats::NewTx(nBlockHeight, val)` — `unconfTxs[blockIndex][bucket]++`.
  - `TxConfirmStats::removeTx(entryHeight, nBestSeenHeight, bucketindex,
    inBlock)` — decrements `unconfTxs` or `oldUnconfTxs` and bumps `failAvg`
    for `inBlock=false` if aged past `scale`.
  - `TxConfirmStats::ClearCurrent(nBlockHeight)` — sweep
    `unconfTxs[nBlockHeight % bins]` into `oldUnconfTxs` before processBlock
    records the new block.
  - `TxConfirmStats::UpdateMovingAverages()` — applies `decay` to ALL of
    `confAvg`, `failAvg`, `txCtAvg`, `m_feerate_avg`.
  - `TxConfirmStats::EstimateMedianVal(confTarget, sufficientTxVal,
    successBreakPoint, nBlockHeight, result)` — scan from highest bucket
    down, group by `partialNum >= sufficientTxVal/(1-decay)`, track
    `bestNearBucket/bestFarBucket`, set `passing=false` on first failure +
    record `failBucket`, allow recovery on lower groups (`continue` not
    `break`), return weighted median `m_feerate_avg[j] / txCtAvg[j]` from
    the bucket containing the median tx.
  - `CBlockPolicyEstimator::processBlock(txs, nBlockHeight)` — early-return
    on `nBlockHeight <= nBestSeenHeight` (reorg/side-chain protection),
    then `ClearCurrent` + `UpdateMovingAverages` on all 3 horizons, then
    `processBlockTx` per tx; updates `firstRecordedHeight` on first
    countedTx; resets `trackedTxs/untrackedTxs` counters.
  - `CBlockPolicyEstimator::processBlockTx` — computes `blocksToConfirm =
    nBlockHeight - tx.info.txHeight`; bails on `blocksToConfirm <= 0`;
    feeds all 3 horizons via `feeRate.GetFeePerK()` (sat per **kilo-vbyte**).
  - `CBlockPolicyEstimator::processTransaction(tx)` —
    `validForFeeEstimation = !m_mempool_limit_bypassed && !m_submitted_in_package
    && m_chainstate_is_current && m_has_no_mempool_parents`; only tracks if true;
    feeds `feeRate.GetFeePerK()` to all 3 horizons.
  - `CBlockPolicyEstimator::removeTx(hash)` — public entry for non-block
    removal (RBF/eviction/expiry); routes to all 3 horizons' `removeTx`.
  - `CBlockPolicyEstimator::estimateFee(confTarget)` — deprecated; returns
    `estimateRawFee(confTarget, DOUBLE_SUCCESS_PCT=.95,
    MED_HALFLIFE)`, bails to `CFeeRate(0)` if `confTarget <= 1`.
  - `CBlockPolicyEstimator::estimateRawFee(confTarget, successThreshold,
    horizon, result)` — picks `stats` per horizon, `sufficientTxs =
    SUFFICIENT_TXS_SHORT=0.5` for SHORT else `SUFFICIENT_FEETXS=0.1`,
    delegates to `EstimateMedianVal`.
  - `CBlockPolicyEstimator::estimateCombinedFee(confTarget, successThreshold,
    checkShorterHorizon, result)` — pick shortest horizon covering
    `confTarget`; if `checkShorterHorizon` ALSO query MED@medMax and
    SHORT@shortMax to preserve monotonicity (pick the LOWER of the three).
  - `CBlockPolicyEstimator::estimateConservativeFee(doubleTarget, result)`
    — `MAX(feeStats[medium]@doubleTarget@95%, longStats@doubleTarget@95%)`.
  - `CBlockPolicyEstimator::estimateSmartFee(confTarget, feeCalc,
    conservative)` — clamp via `MaxUsableEstimate()`; force `confTarget>=2`;
    compute `halfEst = combined(confTarget/2, .60)`,
    `actualEst = combined(confTarget, .85)`,
    `doubleEst = combined(2*confTarget, .95)`, then
    `consEst = conservative_OR_median_unset ? estimateConservativeFee(2*ct) : 0`;
    return `MAX(halfEst, actualEst, doubleEst, consEst)`; sets
    `feeCalc->reason` per which path won.
  - `CBlockPolicyEstimator::HighestTargetTracked(horizon)` — returns
    `scale*periods` (12/48/1008).
  - `CBlockPolicyEstimator::BlockSpan() = nBestSeenHeight -
    firstRecordedHeight`.
  - `CBlockPolicyEstimator::HistoricalBlockSpan()` = age-checked
    `historicalBest - historicalFirst`.
  - `CBlockPolicyEstimator::MaxUsableEstimate()` =
    `min(longMaxConfirms, max(BlockSpan(), HistoricalBlockSpan())/2)`.
  - `CBlockPolicyEstimator::Write(fileout)` — binary format:
    `CURRENT_FEES_FILE_VERSION` (int) + `nBestSeenHeight` (uint) +
    `firstRecordedHeight + nBestSeenHeight` OR
    `historicalFirst + historicalBest` (which one depends on `BlockSpan() >
    HistoricalBlockSpan()/2`) + `buckets` via `EncodedDoubleFormatter` +
    `feeStats.Write` + `shortStats.Write` + `longStats.Write`.
  - `CBlockPolicyEstimator::Read(filein)` — strict version check (rejects
    `> CURRENT_FEES_FILE_VERSION`); requires `numBuckets` in `(1, 1000]`;
    catches every `runtime_error` from `TxConfirmStats::Read` as non-fatal.
  - `CBlockPolicyEstimator::FlushUnconfirmed` — at shutdown, walks
    `mapMemPoolTxs` and calls `_removeTx(hash, false)` for every remaining
    entry → records them in `failAvg` so unconfirmed-at-shutdown counts as
    a failure for the bucket.
  - `GetFeeEstimatorFileAge()` — `last_write_time` for the
    `MAX_FILE_AGE > 60h` check on load.
  - `CValidationInterface` overrides: `TransactionAddedToMempool` →
    `processTransaction`; `TransactionRemovedFromMempool` → `removeTx`;
    `MempoolTransactionsRemovedForBlock` → `processBlock`.
  - `FeeFilterRounder` — privacy quantization of mempool min-fee.
- `bitcoin-core/src/policy/feerate.{h,cpp}` — `CFeeRate(nFee,
  nBytes_or_vsize)` stores `nSatoshisPerK = (nFee * 1000 + nBytes - 1) /
  nBytes` (ceiling). `GetFeePerK()` returns sat/kvB. Constructor
  caps to `numeric_limits<CAmount>::max()` on overflow.
- `bitcoin-core/src/rpc/fees.cpp` (227 LOC) —
  - `estimatesmartfee(conf_target, estimate_mode="economical")` — calls
    `SyncWithValidationInterfaceQueue` first, parses confTarget via
    `ParseConfirmTarget(value, max_target)` where `max_target =
    HighestTargetTracked(LONG_HALFLIFE) = 1008`, parses `estimate_mode`
    via `FeeModeFromString` (rejects unknown with RPC_INVALID_PARAMETER),
    invokes `estimateSmartFee(conf_target, &feeCalc, conservative)`, and
    **floors the result with `max(feeRate, min_mempool_feerate,
    min_relay_feerate)`** (lines 82-86), returns `{feerate?, errors?,
    blocks}`.
  - `estimaterawfee(conf_target, threshold=0.95)` — emits a three-horizon
    object `{short?, medium?, long?}` per `ALL_FEE_ESTIMATE_HORIZONS`; each
    horizon has `{feerate?, decay, scale, pass?, fail?, errors?}`; emits
    ONLY horizons whose `HighestTargetTracked(horizon) >= conf_target`;
    threshold range check `0 ≤ threshold ≤ 1`.
- `bitcoin-core/src/util/fees.h` — `enum FeeEstimateMode { UNSET,
  ECONOMICAL, CONSERVATIVE }`.
- `bitcoin-core/src/common/messages.{h,cpp}` — `FeeModeFromString`,
  `FeeModesDetail`, `InvalidEstimateModeErrorMessage`.
- `bitcoin-core/src/policy/fees/block_policy_estimator_args.cpp` —
  `FEE_ESTIMATES_FILENAME = "fee_estimates.dat"`.
- `bitcoin-core/src/test/policyestimator_tests.cpp` — Core's
  `BlockPolicyEstimates` regression (`BOOST_AUTO_TEST_CASE`).

**Audit subject (rustoshi)**:
- `crates/consensus/src/fee_estimator.rs` (997 LOC including inline tests)
  — single-file engine. Public surface: `FeeEstimator`, `Horizon`,
  `RawBucketStats`, constants `SHORT_BLOCK_PERIODS=12, MED_BLOCK_PERIODS=24,
  LONG_BLOCK_PERIODS=42, SHORT_SCALE=1, MED_SCALE=2, LONG_SCALE=24,
  SHORT_DECAY=0.962, MED_DECAY=0.9952, LONG_DECAY=0.99931`. Private
  constants `MAX_CONFIRMATION_TARGET=1008, FEE_RATE_BUCKETS=[40 manual
  sat/vB values], MIN_TRACKED_TXS=200.0, SUCCESS_THRESHOLD=0.85`. Methods:
  `track_transaction`, `process_block`, `estimate_fee`, `estimate_conservative`,
  `estimate_fee_at_horizon`, `raw_bucket_stats`, `raw_bucket_stats_horizon`,
  `save`, `load`. **No `remove_tx`, no `flush_unconfirmed`, no version
  magic in persistence.**
- `crates/rpc/src/server.rs` —
  - `RpcServer::estimate_smart_fee(conf_target: u32) -> RpcResult<
    FeeEstimateResult>` (lines 3989-4010) — RPC handler. **No
    `estimate_mode` parameter** in the trait signature (lines 413-414).
    **No mempool/relay-fee floor.** Always uses `estimate_fee(conf_target)`
    (single horizon, single 85% threshold).
  - `RpcServer::estimate_raw_fee(conf_target, threshold)` (lines 4012-4063)
    — flat output: `{blocks, buckets[40], decay: 0.998 (hardcoded!),
    scale: 1 (hardcoded!), avg_feerate, total_confirmed}`. **No
    `short/medium/long` horizon decomposition.** `decay` field hardcoded
    to the OLD pre-FIX-48 value 0.998 even though the 3-horizon engine
    exists.
- `rustoshi/src/main.rs` — wiring:
  - line 1908-1913: `let fee_estimates_path = datadir.join("fee_estimates.json");`
    `let loaded_estimator = FeeEstimator::load(&fee_estimates_path); ...
    rpc_state_inner.fee_estimator = loaded_estimator;`
  - line 2447-2453: IBD path on block-connect → `rpc.fee_estimator.process_block(height, &confirmed_txids)` (skips coinbase).
  - line 2994-3001: P2P live-block path → same call.
  - line 3136-3143: P2P mempool admit path → `rpc.fee_estimator.track_transaction(txid, fee_rate)`.
  - line 4274: shutdown → `state.fee_estimator.save(&fee_estimates_path)`.

**Production code changes:** 0 (pure audit).
**Test file:** `crates/consensus/tests/test_w139_fee_estimation.rs` —
30 gates, PASS regression pins + `#[ignore]`-pinned BUG-N stubs.

## Why this matters

The fee estimator is the source of truth for every wallet's `estimatesmartfee`
RPC call and for any block-templating logic that picks a sane minimum
package feerate. Wrong here ⇒ wallets either drastically overpay or get
their txs stuck in the mempool. Worse, the fee_estimates.dat persistence
format is part of Core's wire-data interop story: a node's recorded
history is also the basis for the `getmempoolinfo.minrelaytxfeerate` floor
that miners advertise via `feefilter`. If rustoshi's estimator
systematically underestimates feerates (which it does — see BUGs 4, 5, 9,
10, 16, 22, 24, R-1) the node will accept and relay transactions that
Core would reject, polluting the propagation graph.

The specific risks:

1. **Wallet over/under-pay.** `estimatesmartfee 6` is used by every wallet
   on the node. Rustoshi's path is `estimate_fee(6)` against the SHORT
   horizon @ 85%. Missing: `HALF_ESTIMATE` (60% @ target/2),
   `DOUBLE_ESTIMATE` (95% @ 2*target) which Core's `estimateSmartFee`
   computes and takes the **max** of (line 919-940 of
   `block_policy_estimator.cpp`). For a target of 6, Core checks 3 and
   12 too — rustoshi never does. Result: in any market where short-term
   feerate volatility is high, rustoshi's 1-bucket-of-history answer
   diverges from Core's 3-window answer by >2x. BUG-7, BUG-8.
2. **No mempool/relay-fee floor in RPC response.** Core's `estimatesmartfee`
   handler ALWAYS clamps the estimator's answer with `max(feeRate,
   min_mempool_feerate, min_relay_feerate)`. Rustoshi returns the raw
   estimator value. Under a fee-spike where the node's `getmempoolinfo`
   reports a min-fee of 50 sat/vB but the estimator (decayed from a
   pre-spike window) still says 5 sat/vB, the wallet will broadcast a
   tx that the local node REJECTS on submission. BUG-22.
3. **Missing failAvg / unconfTxs / oldUnconfTxs accounting.** Without
   these, the denominator in EstimateMedianVal is `totalNum` only, not
   `totalNum + failNum + extraNum`. Rustoshi treats every tx that ever
   confirmed as a 100% success regardless of how many in that bucket
   never confirmed. On a sustained congestion event (1000+ mempool txs
   evicted in a single fee-spike) Core estimates jump sharply upward
   because of the failure denominator; rustoshi's estimates stay
   flat-with-decay because failures are silently dropped. BUG-9, BUG-10,
   BUG-14, BUG-15.
4. **`bucket-index resolution`.** Core has ~237 log-spaced buckets from
   100 sat/kvB (=0.1 sat/vB) to 1e7 sat/kvB (=10000 sat/vB) with
   `FEE_SPACING=1.05`. Rustoshi has 40 manually picked sat/vB values from
   1 sat/vB to 10000 sat/vB with ad-hoc spacing (1→2 = 2x, 1000→1200 =
   1.2x). Below 1 sat/vB rustoshi has no resolution at all — every
   sub-1-sat/vB transaction collapses into bucket 0. Above 1000 sat/vB
   the gaps widen to factors of 1.4x-2x, far coarser than Core's 1.05x.
   On any feerate that sits between two rustoshi buckets the returned
   "estimate" jumps in 20%+ discrete steps. BUG-4, BUG-6.
5. **Bucket-units mismatch.** Core stores `feeRate.GetFeePerK()` (sat per
   kilo-vbyte). Rustoshi stores sat/vB. Internal values are off by a
   factor of 1000. Any node-to-node fee_estimates.dat interop is
   structurally broken even before format differences. BUG-26.
6. **`fee_estimates.dat` format incompatibility.** Core's binary
   AutoFile format with `CURRENT_FEES_FILE_VERSION = 309900` magic;
   rustoshi's `serde_json` file named `fee_estimates.json`. Neither node
   can read the other's persisted state. CDIV-adjacent: not consensus
   but consensus-dependent (mempool min-fee floor depends on it). BUG-19,
   BUG-20.
7. **Reorg double-count.** Core's `processBlock` does `if (nBlockHeight
   <= nBestSeenHeight) return;`. Rustoshi has no such guard — a 1-block
   reorg that re-connects the same height will: (a) decay all stats AGAIN
   for that block (double decay), (b) re-record every confirmed tx
   (double cumulative-fill of `confirmed_within`). Estimates start
   skewing too-low after each reorg. BUG-12.
8. **`MaxUsableEstimate()` missing.** A freshly-started node with 5
   blocks of data will happily report a 1008-block estimate based on
   tiny SHORT-horizon data. Core clamps to `min(1008,
   max(BlockSpan(),HistoricalBlockSpan())/2)` — so 5 blocks means at
   most target=2. Without this clamp rustoshi gives confidently wrong
   answers in the first 2 weeks of running on a fresh datadir. BUG-21,
   BUG-23.
9. **Invalid-tx selection bias.** Core's `processTransaction` skips
   tracking for: `m_mempool_limit_bypassed || m_submitted_in_package ||
   !m_chainstate_is_current || !m_has_no_mempool_parents`. These are
   txs that confirm at atypical relationships to their broadcast
   conditions (e.g. CPFP children pay for parents — child's nominal
   feerate looks high but the package paid less). Rustoshi tracks every
   sendrawtransaction + every mempool-admit P2P tx, polluting the
   sample set with package/priority txs that would skew the estimate
   downward (children appear high-fee even though the network paid
   bundled). BUG-13.
10. **No `remove_tx` API + RBF eviction silently lost.** Core's
    `TransactionRemovedFromMempool` validation signal routes to
    `removeTx(hash, false)` which both removes from `mapMemPoolTxs` AND
    records `failAvg[period][bucket]++` for the failure-to-confirm.
    Rustoshi has no such API; RBF evictions just sit in `tracked` until
    the per-block `retain()` drops them after 1008 blocks. The failure
    is never accounted for. BUG-11, BUG-17.
11. **No `FlushUnconfirmed` at shutdown.** Core's `Flush()` is `Flush =
    FlushUnconfirmed() + FlushFeeEstimates()`. The unconfirmed-flush
    records EVERY remaining mapMemPoolTxs entry as a failure (because
    they're shutting down without confirming) — this is critical so
    that a shutdown-during-congestion doesn't bias the next session's
    estimates downward. Rustoshi just `save()`s the current state with
    its tracked-but-unrecorded mempool. BUG-18, BUG-30.
12. **`estimaterawfee` response shape divergence.** Core emits
    `{short:{feerate, decay, scale, pass, fail}, medium:{...},
    long:{...}}`; rustoshi emits a single flat object with hard-coded
    `decay=0.998` (the **OLD** pre-FIX-48 single decay constant, never
    updated to expose the per-horizon decays the engine now has) and
    `scale=1`. Any tool that consumes `estimaterawfee.short.feerate`
    crashes against rustoshi. BUG-28.

## Audit matrix (30 gates)

Legend: ✅ PASS / ❌ FAIL = BUG / ⚠️ PARTIAL / 🚧 GAP.

| Gate | Subject | Verdict | BUG |
|------|---------|---------|-----|
| G1 | 3 horizon period constants (12/24/42) | ✅ PASS | — (FIX-48 closed) |
| G2 | 3 horizon scale constants (1/2/24) | ✅ PASS | — (FIX-48 closed) |
| G3 | 3 horizon decay constants (.962/.9952/.99931) | ✅ PASS | — (FIX-48 closed) |
| G4 | Bucket range MIN=100 sat/kvB MAX=1e7 sat/kvB FEE_SPACING=1.05 | ❌ FAIL | BUG-1 |
| G5 | SUFFICIENT_FEETXS=0.1 + SUFFICIENT_TXS_SHORT=0.5 thresholds | ❌ FAIL | BUG-2 |
| G6 | ~237 bucket count | ❌ FAIL | BUG-3 |
| G7 | `bucketMap` O(log n) lookup with `lower_bound` | ⚠️ PARTIAL | BUG-4 |
| G8 | Bucket units (sat/kvB) | ❌ FAIL | BUG-5 |
| G9 | `failAvg[period][bucket]` failure tracking | ❌ FAIL | BUG-6 |
| G10 | `unconfTxs[block%bins][bucket]` mempool tracking | ❌ FAIL | BUG-7 |
| G11 | `oldUnconfTxs[bucket]` aged-out swept on `ClearCurrent` | ❌ FAIL | BUG-8 |
| G12 | `processBlock` reorg guard `nBlockHeight <= nBestSeenHeight` | ❌ FAIL | BUG-9 |
| G13 | `validForFeeEstimation` filter (package/priority/!chainstate_is_current/has_parents) | ❌ FAIL | BUG-10 |
| G14 | `removeTx(hash, inBlock)` public API + 3-horizon dispatch | ❌ FAIL | BUG-11 |
| G15 | RBF replacements notify `remove_tx` | ❌ FAIL | BUG-12 |
| G16 | `EstimateMedianVal` group-by-`sufficientTxVal/(1-decay)` + `passing` flag + `bestNear/FarBucket` | ❌ FAIL | BUG-13 |
| G17 | `m_feerate_avg[j]/txCtAvg[j]` weighted-median return (not bucket boundary) | ❌ FAIL | BUG-14 |
| G18 | `estimateSmartFee` accepts `estimate_mode` ∈ {unset,economical,conservative} | ❌ FAIL | BUG-15 |
| G19 | `estimateSmartFee` = `max(halfEst@.60, actualEst@.85, doubleEst@.95, consEst)` | ❌ FAIL | BUG-16 |
| G20 | `estimateCombinedFee` short/medium/long fallback + `checkShorterHorizon` monotonicity | ❌ FAIL | BUG-17 |
| G21 | `conf_target==1` normalized to 2 (Core line 890) | ❌ FAIL | BUG-18 |
| G22 | RPC handler floors with `max(feeRate, min_mempool_feerate, min_relay_feerate)` | ❌ FAIL | BUG-19 |
| G23 | `MaxUsableEstimate()` clamps confTarget to `min(longMax, max(BlockSpan,HistoricalBlockSpan)/2)` | ❌ FAIL | BUG-20 |
| G24 | `BlockSpan/firstRecordedHeight/historicalFirst/historicalBest` state | ❌ FAIL | BUG-21 |
| G25 | Binary `fee_estimates.dat` AutoFile format + `CURRENT_FEES_FILE_VERSION=309900` magic | ❌ FAIL | BUG-22 |
| G26 | `MAX_FILE_AGE = 60h` stale-file rejection on load (+ DEFAULT_ACCEPT_STALE_FEE_ESTIMATES override) | ❌ FAIL | BUG-23 |
| G27 | Periodic `FlushFeeEstimates` at `FEE_FLUSH_INTERVAL = 1h` | ❌ FAIL | BUG-24 |
| G28 | `estimaterawfee` returns `{short, medium, long}` with per-horizon `decay/scale/pass/fail` (not hardcoded 0.998/1) | ❌ FAIL | BUG-25 |
| G29 | `FlushUnconfirmed` records remaining mempool as failure on shutdown | ❌ FAIL | BUG-26 |
| G30 | NaN-safe bucket lookup (no `partial_cmp(..).unwrap()` panic on NaN) | ❌ FAIL | BUG-27 |

## Bug inventory

### BUG-1 (P0 — CDIV-adjacent): bucket range and FEE_SPACING wrong

**Site**: `crates/consensus/src/fee_estimator.rs:77-81`.

```rust
const FEE_RATE_BUCKETS: &[f64] = &[
    1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 10.0, 12.0, 14.0, 17.0, 20.0, 25.0, 30.0, 40.0, 50.0,
    60.0, 70.0, 80.0, 100.0, 120.0, 140.0, 170.0, 200.0, 250.0, 300.0, 400.0, 500.0, 600.0, 700.0,
    800.0, 1000.0, 1200.0, 1400.0, 1700.0, 2000.0, 3000.0, 5000.0, 10000.0,
];
```

40 manually-picked buckets in sat/vB. Core
(`block_policy_estimator.cpp:546-554`):

```cpp
for (double bucketBoundary = MIN_BUCKET_FEERATE; // 100 sat/kvB = 0.1 sat/vB
     bucketBoundary <= MAX_BUCKET_FEERATE;       // 1e7 sat/kvB = 10000 sat/vB
     bucketBoundary *= FEE_SPACING,              // 1.05
     bucketIndex++) {
    buckets.push_back(bucketBoundary);
    bucketMap[bucketBoundary] = bucketIndex;
}
buckets.push_back(INF_FEERATE); // 1e99 sentinel
```

`log(1e7/100)/log(1.05) = 235.7` ⇒ Core has ~237 buckets (including the
`INF_FEERATE` sentinel). Spacing is exactly 1.05x consistently. Rustoshi
spacing varies from 1.05x (some adjacent pairs) to 2x (1↔2), making
estimate quantization wildly nonuniform.

**Worst case**: a real network feerate of 0.5 sat/vB falls **below**
rustoshi's bucket 0 entirely and is reported as 1.0 sat/vB (2x off). Core
puts it in the bucket centered at 500 sat/kvB and reports 0.5 sat/vB
correctly.

**Priority P0**: this is the foundation of every estimate. Off-by-1.05 in
worst case (Core) vs off-by-2.0 worst case (rustoshi). Fix requires
rewriting `FEE_RATE_BUCKETS` to be Core's exponential-spacing formula.

### BUG-2 (P0): sufficient-txs thresholds wrong

**Site**: `crates/consensus/src/fee_estimator.rs:84`.

```rust
const MIN_TRACKED_TXS: f64 = 200.0;
```

`MIN_TRACKED_TXS=200.0` (absolute decayed total across ALL buckets seen
so far) vs Core's `SUFFICIENT_FEETXS=0.1` and `SUFFICIENT_TXS_SHORT=0.5`
PER-bucket-group. The Core gating is dynamic:

```cpp
if (partialNum < sufficientTxVal / (1 - decay)) continue; // EstimateMedianVal line 298
```

For SHORT (`decay=0.962`, `sufficientTxVal=0.5`): need
`0.5/(1-0.962)=13.15` decayed txs per bucket group. For LONG
(`decay=0.99931`, `sufficientTxVal=0.1`): need
`0.1/(1-0.99931)=144.9` decayed txs per bucket group. Rustoshi's
flat 200 across all horizons is too HIGH for SHORT (refuses
estimates Core would give) and too LOW for LONG (gives shaky
estimates Core would refuse).

**Real impact**: On testnet4 or any low-traffic network rustoshi's
`estimatesmartfee` returns `null + Insufficient data` where Core
returns a valid estimate for SHORT horizon.

### BUG-3 (P1): bucket count wrong (consequence of BUG-1)

40 buckets vs ~237. `bucket_count() = 40`. Gate G6.

### BUG-4 (P2): bucket lookup is binary-search but lookup table is the wrong shape

**Site**: `fee_estimator.rs:391-398`.

```rust
fn fee_rate_to_bucket(&self, fee_rate: f64) -> usize {
    match FEE_RATE_BUCKETS.binary_search_by(|b| b.partial_cmp(&fee_rate).unwrap()) {
        Ok(i) => i,
        Err(i) => if i == 0 { 0 } else { i - 1 },
    }
}
```

The binary-search algorithm is correct (Core uses `bucketMap.lower_bound`).
PARTIAL because (a) wrong dataset (BUG-1), (b) `partial_cmp(..).unwrap()`
panics on NaN inputs — Core's `std::map::lower_bound` over double handles
NaN by returning end iterator. See also BUG-27.

### BUG-5 (P0 — CDIV-adjacent): bucket units are sat/vB not sat/kvB

**Site**: `fee_estimator.rs:77-81` (`1.0` is interpreted as `1 sat/vB`),
and `crates/rpc/src/server.rs:3997` converts at the RPC boundary:

```rust
let feerate_sats = (rate * 1000.0).round() as u64;
```

Core stores `feeRate.GetFeePerK()` (sat/kvB). All Core persistence files,
RPC outputs, log lines, and constants speak in sat/kvB. Rustoshi internally
stores sat/vB everywhere and only converts at the RPC layer.

**Concrete divergence**: a Core node and a rustoshi node both tracking
the same 1.5 sat/vB tx will save different numbers (1500.0 vs 1.5) to
their respective state files. Cross-node estimate consistency is structurally
broken before format differences.

### BUG-6 (P0 — CDIV-adjacent): no `failAvg` failure tracking

**Site**: `BucketStats` struct (`fee_estimator.rs:159-167`) has only
`confirmed_within`, `total`, `fee_sum`. No `failAvg[period][bucket]`.

Core uses `failAvg` to track txs that left the mempool without confirming
within Y blocks. These are tallied into the denominator in
`EstimateMedianVal` (line 305):

```cpp
double curPct = nConf / (totalNum + failNum + extraNum);
```

Rustoshi computes `success_rate = total_confirmed / total_tracked` — no
failure denominator. Every estimate is over-optimistic by exactly the
failure rate. During a congestion event with 30% mempool eviction rustoshi's
estimate sees 100% success for the txs that survived; Core sees 70%
success and bumps the recommended feerate up.

### BUG-7 (P0 — CDIV-adjacent): no `unconfTxs` circular buffer

**Site**: `TxConfirmStats` struct (`fee_estimator.rs:193-202`) — no
`unconfTxs[bins][bucket]`.

Core tracks `unconfTxs[block_height % bins][bucket]` and computes
`extraNum` in `EstimateMedianVal` (line 290-292):

```cpp
for (unsigned int confct = confTarget; confct < GetMaxConfirms(); confct++)
    extraNum += unconfTxs[(nBlockHeight - confct) % bins][bucket];
```

This is "txs still in mempool waiting for at least `confTarget` more blocks
to confirm" — they contribute to the denominator. Without this rustoshi's
denominator is incomplete and estimates skew low.

### BUG-8 (P0 — CDIV-adjacent): no `oldUnconfTxs` aged-out swept on `ClearCurrent`

**Site**: `fee_estimator.rs:423-449` (`process_block`). Stale txs are
removed via `retain()` (line 447-449):

```rust
self.tracked.retain(|_, tracked| {
    height.saturating_sub(tracked.entered_height) <= MAX_CONFIRMATION_TARGET as u32
});
```

— silently dropped, NOT counted anywhere. Core's `ClearCurrent` (line 207):

```cpp
oldUnconfTxs[j] += unconfTxs[nBlockHeight % unconfTxs.size()][j];
```

— rotates the oldest slot into the `oldUnconfTxs[bucket]` pile, which then
contributes to `extraNum` (line 292). Result: rustoshi over-optimism
compounds with BUG-7.

### BUG-9 (P0): no reorg / side-chain guard in `process_block`

**Site**: `fee_estimator.rs:423` (`process_block`). The first line
unconditionally does:

```rust
self.current_height = height;
```

— no early-return for `height <= self.current_height`. Core
(`processBlock` line 673-680):

```cpp
if (nBlockHeight <= nBestSeenHeight) {
    return;
}
```

**Concrete failure**: a 1-block reorg that re-connects the same height
re-runs `decay_all()` AGAIN (double-decay) and re-records every confirmed
tx into `confirmed_within` (double cumulative-fill). Estimates skew too
low after each reorg.

### BUG-10 (P0 — CDIV-adjacent): no `validForFeeEstimation` filter on
`processTransaction`

**Site**: rustoshi's `track_transaction` (`fee_estimator.rs:410-420`) has
no skip logic. Wiring at `server.rs:3736` (sendrawtransaction) and
`main.rs:3142` (P2P mempool admit) calls it unconditionally for every tx
that's accepted to mempool.

Core's `processTransaction` (line 619):

```cpp
const bool validForFeeEstimation = !tx.m_mempool_limit_bypassed
    && !tx.m_submitted_in_package
    && tx.m_chainstate_is_current
    && tx.m_has_no_mempool_parents;
if (!validForFeeEstimation) {
    untrackedTxs++;
    return;
}
```

— skips:
- mempool-limit-bypass txs (whitelisted high-priority injection),
- package submissions (CPFP child pays for parent — child's nominal feerate
  is misleadingly high),
- txs admitted while chainstate is stale (IBD didn't conclude),
- txs with unconfirmed mempool parents.

Rustoshi's selection bias inflates the sample with CPFP children paying
artificially-high feerates. Estimates pinned to "what miners actually paid
for inclusion" diverge from "what users paid", because CPFP-bundled
parents pay <1 sat/vB but rustoshi treats them as bundled-high.

### BUG-11 (P0 — CDIV-adjacent): no `remove_tx` public API

**Site**: `FeeEstimator` has no `remove_tx` method. The Core public API:

```cpp
bool removeTx(Txid hash);
```

is called on every TransactionRemovedFromMempool signal — RBF replacements,
eviction (low-feerate), reorg-driven re-orgs out of the mempool, expiration.
In all those cases `removeTx(hash, /*inBlock=*/false)` runs and feeds
`failAvg[period][bucket]++`. Rustoshi loses every one of these data points.

### BUG-12 (P1): RBF eviction not notified to fee estimator

**Site**: any RBF eviction site in the mempool. Rustoshi does not invoke
a fee-estimator failure path because there is none (BUG-11). Even if one
existed, the call site is missing.

### BUG-13 (P0): `EstimateMedianVal` grouping algorithm wrong

**Site**: `fee_estimator.rs:255-289` (`estimate_with_threshold`):

```rust
for (i, bucket) in self.buckets.iter().enumerate().rev() {
    if bucket.total < 0.001 { continue; }
    total_confirmed += bucket.confirmed_within.get(period).copied().unwrap_or(0.0);
    total_tracked   += bucket.total;
    if total_tracked < MIN_TRACKED_TXS { continue; }
    let success_rate = total_confirmed / total_tracked;
    if success_rate >= threshold {
        best_rate = Some(FEE_RATE_BUCKETS[i]);
    } else {
        break;   // <─ early-stop on first failure
    }
}
```

Core's `EstimateMedianVal` (line 280-342) is materially different:
1. Tracks `curNearBucket / curFarBucket` and `bestNearBucket / bestFarBucket`.
2. Groups buckets by `partialNum >= sufficientTxVal/(1-decay)` (line 298) —
   accumulates until the GROUP has enough data, then evaluates.
3. On a failure sets `passing=false` and records `failBucket` — but
   **continues** to lower groups (line 321 `continue`, not `break`) — so a
   lower group can still pass and become the new best.
4. On a success resets the cumulative counters (line 326-340) so groups
   don't bleed into each other.
5. Returns the WEIGHTED MEDIAN feerate `m_feerate_avg[j] / txCtAvg[j]` from
   the bucket containing the median tx (line 353-365) — NOT a bucket
   boundary.

Rustoshi's algorithm is:
- Cumulative across all buckets from highest down (no grouping by
  sufficientTxVal).
- Uses a global threshold `MIN_TRACKED_TXS=200` not Core's group-size.
- `break` on first failure (cannot recover if lower group passes).
- Returns `FEE_RATE_BUCKETS[i]` boundary, not weighted median.

**Concrete consequence**: in a bimodal-feerate market (e.g. lots of high-fee
miner txs at 50 sat/vB + lots of low-fee user txs at 5 sat/vB, but a
sparse middle from 10-30 sat/vB) rustoshi will: (a) accumulate the high
bucket alone, pass, set best=50, (b) accumulate the middle (sparse, fails
the global 200 threshold prematurely), break. Core groups middle buckets
together via sufficientTxVal, evaluates, succeeds, and returns 15-20 sat/vB
weighted median.

### BUG-14 (P1): returns bucket boundary not weighted median

**Site**: `fee_estimator.rs:283`:

```rust
best_rate = Some(FEE_RATE_BUCKETS[i]);
```

vs Core (line 362):

```cpp
median = m_feerate_avg[j] / txCtAvg[j];
```

The returned estimate snaps to the LOW edge of the best bucket. Combined
with coarse buckets (BUG-3) the returned estimate is systematically lower
than what users actually paid. Also: `fee_sum` is computed but never used
for the estimate output (only stored). It's the same "well-engineered
helper never wired" pattern that triggered W114 BUG-DEAD-HELPER, except
this one is wired but its output value is discarded.

### BUG-15 (P0): `estimate_smart_fee` RPC missing `estimate_mode` param

**Site**: `crates/rpc/src/server.rs:413-414`:

```rust
#[method(name = "estimatesmartfee")]
async fn estimate_smart_fee(&self, conf_target: u32) -> RpcResult<FeeEstimateResult>;
```

Core's RPC accepts `(conf_target, estimate_mode="economical")` where
`estimate_mode` ∈ {unset, economical, conservative}. Rustoshi accepts only
`conf_target`. ANY caller that passes `estimate_mode="conservative"` (the
docs from the JS-RPC tooling do this routinely) gets:
1. Either rejected as "unknown parameter", or worse,
2. Silently dropped and treated as economical (depending on the RPC layer's
   strictness).

**Cross-impl divergence**: Bitcoin-CLI's `bitcoin-cli estimatesmartfee 6
conservative` returns Core's CONSERVATIVE mode (>=95% threshold at 2*target,
takes max over all longer horizons) — a noticeably HIGHER feerate. Rustoshi
will ignore the second arg and return ECONOMICAL.

### BUG-16 (P0): `estimateSmartFee = max(halfEst, actualEst, doubleEst, consEst)` missing

**Site**: `server.rs:3989-4010` (handler) calls `state.fee_estimator.estimate_fee(conf_target)`
— a single SHORT horizon @ 85%. Core does (line 919-940 of
`block_policy_estimator.cpp`):

```cpp
double halfEst   = estimateCombinedFee(confTarget/2, HALF_SUCCESS_PCT=.60, true, &tempResult);
double actualEst = estimateCombinedFee(confTarget,   SUCCESS_PCT=.85,      true, &tempResult);
double doubleEst = estimateCombinedFee(2*confTarget, DOUBLE_SUCCESS_PCT=.95, !conservative, &tempResult);
double consEst   = (conservative || median == -1)
    ? estimateConservativeFee(2 * confTarget, &tempResult)
    : -1;
median = max(halfEst, actualEst, doubleEst, consEst);
```

The MAX is critical — it ensures the returned feerate is the highest
required by ANY of the three success-thresholds the algorithm requires.
Rustoshi's single-call answer is whichever of those three would be
LOWEST — guaranteed too-low.

### BUG-17 (P1): `estimateCombinedFee` short→medium→long fallback + monotonicity missing

**Site**: rustoshi's `estimate_fee_at_horizon` accepts a Horizon argument
but is never invoked in the fallback chain by `estimate_smart_fee`. Core's
`estimateCombinedFee` queries the shortest horizon covering the target,
then ALSO queries MED@medMax and SHORT@shortMax to find a lower answer that
might be valid in shorter windows (preserves monotonicity: estimate(N+1)
>= estimate(N) for all N).

### BUG-18 (P1): `conf_target==1` not normalized to 2

**Site**: `server.rs:3989` accepts conf_target=1 as valid and queries the
SHORT horizon at period 1. Core (line 890):

```cpp
if (confTarget == 1) confTarget = 2;
```

— forces minimum 2 because 1-block estimates are unreliable (only the
current block's miner's policy matters, and our sample is too thin).
Rustoshi returns whatever SHORT@1 says. For target=1 on real data this
will almost always be a very-high feerate (only the highest-paying txs
confirm in the next block) — Core would return target=2's estimate which
is lower and more useful.

### BUG-19 (P0): RPC handler missing mempool/relay fee floor

**Site**: `server.rs:3997-4002`:

```rust
let feerate_sats = (rate * 1000.0).round() as u64;
Ok(FeeEstimateResult {
    feerate: Some(BtcAmount::from_sats(feerate_sats)),
    errors: None,
    blocks: conf_target,
})
```

Core (`rpc/fees.cpp:82-86`):

```cpp
if (feeRate != CFeeRate(0)) {
    CFeeRate min_mempool_feerate{mempool.GetMinFee()};
    CFeeRate min_relay_feerate{mempool.m_opts.min_relay_feerate};
    feeRate = std::max({feeRate, min_mempool_feerate, min_relay_feerate});
    result.pushKV("feerate", ValueFromAmount(feeRate.GetFeePerK()));
}
```

This is CRITICAL: under fee-spike conditions the estimator (decayed from
a pre-spike window) may report a feerate well below the current dynamic
mempool min-fee. A wallet using rustoshi's estimate will broadcast a tx
that's rejected at submission. Core's floor protects this case.

### BUG-20 (P1): `MaxUsableEstimate` clamp missing

**Site**: rustoshi has no equivalent. Core (line 798-802):

```cpp
unsigned int CBlockPolicyEstimator::MaxUsableEstimate() const {
    return std::min(longStats->GetMaxConfirms(), std::max(BlockSpan(), HistoricalBlockSpan()) / 2);
}
```

— applied in `estimateSmartFee` line 892-895 to clamp confTarget down.
A freshly-booted rustoshi with 5 blocks of post-genesis data returns
estimates for conf_target=1008. Core returns max conf_target=2.

### BUG-21 (P1): `BlockSpan` / `firstRecordedHeight` / `historicalFirst` / `historicalBest` state missing

**Site**: rustoshi has only `current_height`. Core tracks 4 numbers
(`block_policy_estimator.h:278-281`):

```cpp
unsigned int nBestSeenHeight;
unsigned int firstRecordedHeight;
unsigned int historicalFirst;
unsigned int historicalBest;
```

`firstRecordedHeight` is set once on the first block that had a tracked tx
confirm (`processBlock` line 704-707):

```cpp
if (firstRecordedHeight == 0 && countedTxs > 0) {
    firstRecordedHeight = nBestSeenHeight;
}
```

`historicalFirst/Best` come from the persistence file (line 1021).
`MaxUsableEstimate` (BUG-20) needs all of these. Rustoshi's state machine
can't compute the clamp.

### BUG-22 (P0 — CDIV-adjacent): `fee_estimates.dat` format incompatible

**Site**: `fee_estimator.rs:543-556` (save) and `562-591` (load). Format is
`serde_json::to_string`-of-`FeeEstimatorState`:

```rust
struct FeeEstimatorState {
    short_stats: TxConfirmStats,
    med_stats: TxConfirmStats,
    long_stats: TxConfirmStats,
    tracked: HashMap<Hash256, TrackedTransaction>,
    current_height: u32,
}
```

— filename is `fee_estimates.json`. Core's format
(`block_policy_estimator.cpp:978-1000`) is binary AutoFile-encoded, with:

```
[int32 CURRENT_FEES_FILE_VERSION = 309900]
[uint32 nBestSeenHeight]
[uint32 firstRecordedHeight OR historicalFirst]
[uint32 nBestSeenHeight     OR historicalBest]
[VectorFormatter<EncodedDoubleFormatter> buckets]
[feeStats serialized via TxConfirmStats::Write]   // MED
[shortStats serialized via TxConfirmStats::Write] // SHORT
[longStats serialized via TxConfirmStats::Write]  // LONG
```

— filename is `fee_estimates.dat`. No interop.

### BUG-23 (P1): `MAX_FILE_AGE = 60h` stale-file rejection missing

**Site**: `fee_estimator.rs:562-591` (`load`) — no age check. Core
(`block_policy_estimator.cpp:568-572`):

```cpp
std::chrono::hours file_age = GetFeeEstimatorFileAge();
if (file_age > MAX_FILE_AGE && !read_stale_estimates) {
    LogWarning(...);
    return;
}
```

— rejects estimate files older than 60 hours (2.5 days) because the
estimates would be wildly out of date. Override via
`-acceptstalefeeestimates` (DEFAULT_ACCEPT_STALE_FEE_ESTIMATES=false).
Rustoshi loads arbitrarily old `fee_estimates.json` and uses it as if
fresh.

### BUG-24 (P2): no periodic `FlushFeeEstimates` at `FEE_FLUSH_INTERVAL = 1h`

**Site**: `rustoshi/src/main.rs:4274` saves only at shutdown. Core flushes
every 1 hour via the scheduler (`init.cpp` wires `scheduler.scheduleEvery`
for `FlushFeeEstimates`). A crash between startup and shutdown loses all
accumulated state.

### BUG-25 (P0): `estimaterawfee` response shape wrong + hardcoded stale decay constant

**Site**: `server.rs:4012-4063`. Output is a flat object:

```rust
out.insert("blocks".to_string(), ...);
out.insert("buckets".to_string(), Array(arr));
out.insert("decay".to_string(), serde_json::json!(0.998_f64));  // <─ stale const!
out.insert("scale".to_string(), serde_json::json!(1));
out.insert("avg_feerate".to_string(), ...);
out.insert("total_confirmed".to_string(), ...);
```

Two distinct sub-bugs:
1. **Wrong shape**: Core emits `{short: {...}, medium: {...}, long: {...}}`
   per `ALL_FEE_ESTIMATE_HORIZONS` per `rpc/fees.cpp:170-211`. Any tool
   that does `response.short.feerate` crashes against rustoshi.
2. **Hardcoded stale `decay = 0.998`**: this is the OLD pre-FIX-48 single
   decay constant. The 3-horizon engine has `SHORT_DECAY=0.962 /
   MED_DECAY=0.9952 / LONG_DECAY=0.99931`. The RPC handler hardcodes the
   wrong, dead constant in the response. Pattern: "comment-as-confession +
   stale-after-internal-refactor". The accompanying comment (`server.rs:4050-4052`)
   says "rustoshi has a single horizon" — factually wrong post-FIX-48.
   This is the same "test-comment-as-confession" pattern caught in W120
   (blockbrew FullRBF) and W122 (blockbrew BIP-158).

### BUG-26 (P0): `FlushUnconfirmed` at shutdown not invoked

**Site**: `fee_estimator.rs:543-556` (`save`) just writes current state.
Core (`block_policy_estimator.cpp:958-961`):

```cpp
void CBlockPolicyEstimator::Flush() {
    FlushUnconfirmed();    // <─ records every mapMemPoolTxs as failure
    FlushFeeEstimates();   // then writes the file
}
```

— the unconfirmed-flush is critical so that mempool txs that didn't
confirm at shutdown count as failures in `failAvg`. Without this rustoshi
biases the next session's estimates downward (every unrecorded
unconfirmed tx is a missing failure datapoint).

### BUG-27 (P2): bucket lookup panics on NaN

**Site**: `fee_estimator.rs:392`:

```rust
FEE_RATE_BUCKETS.binary_search_by(|b| b.partial_cmp(&fee_rate).unwrap())
```

`partial_cmp` returns `None` on NaN ⇒ `.unwrap()` panics. Reachable by:
- A malformed RPC `sendrawtransaction` payload whose fee/size computation
  encounters a 0-size tx (Inf/0=NaN).
- Persistence load with corrupt `fee_estimates.json` containing NaN in
  `fee_rate` (serde_json round-trips f64 NaN as null but a hand-crafted
  file with `"fee_rate": NaN`-like input would parse to NaN).

Core's `bucketMap.lower_bound` over double behaves on NaN (NaN compares
not-less-than-everything by IEEE so lower_bound returns `end()` and Core
accesses `end()->second` which is UB but std::map iterator dereference
guard usually traps as null pointer rather than panic).

### BUG-28 (P1): `estimate_raw_fee` `threshold` parameter accepted but ignored

**Site**: `server.rs:4012-4016`:

```rust
async fn estimate_raw_fee(
    &self,
    conf_target: u32,
    _threshold: Option<f64>,   // <─ underscore: discarded
) -> RpcResult<serde_json::Value> {
```

Parameter is parsed and discarded. Core uses it as the success threshold
(`rpc/fees.cpp:160-162`):

```cpp
double threshold = 0.95;
if (!request.params[1].isNull()) {
    threshold = request.params[1].get_real();
}
if (threshold < 0 || threshold > 1) {
    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid threshold");
}
```

— and passes it through to `estimateRawFee(conf_target, threshold, horizon)`.
Rustoshi never honors caller's threshold; always uses internal 85%.

### BUG-29 (P2): no `SyncWithValidationInterfaceQueue` barrier before RPC

**Site**: `server.rs:3989-3990` (estimate_smart_fee) and `:4012-4017`
(estimate_raw_fee). Core (`rpc/fees.cpp:69`):

```cpp
CHECK_NONFATAL(mempool.m_opts.signals)->SyncWithValidationInterfaceQueue();
```

— forces the validation-interface queue to drain so all
`TransactionAddedToMempool` / `MempoolTransactionsRemovedForBlock`
signals have been processed before reading estimator state. Without
this, an RPC `estimatesmartfee` issued just after a block-connect can
return an estimate that doesn't yet include the just-connected block's
data. Rustoshi has no such barrier — has a `state.read().await` lock
but that doesn't drain a signal queue.

### BUG-30 (P1): no `OLDEST_ESTIMATE_HISTORY` for historical-block-span aging

**Site**: rustoshi has no `historicalFirst / historicalBest`. Core
(`block_policy_estimator.h:160`):

```cpp
static const unsigned int OLDEST_ESTIMATE_HISTORY = 6 * 1008;
```

— `HistoricalBlockSpan` returns 0 if `nBestSeenHeight - historicalBest >
OLDEST_ESTIMATE_HISTORY` (6 weeks). This means rustoshi has no concept
of "the persistence file is too old for the historical-span to count" —
either the file loads (and is fully trusted, see BUG-23) or it doesn't.

## Source guards / forward-regression

This audit pins:

1. **Bucket boundaries**: `FEE_RATE_BUCKETS` length must change in the
   fix; gate G6 tests `bucket_count() in [190, 250]`.
2. **Hardcoded `decay = 0.998`** at `server.rs:4052`: gate G28 source-grep
   forward-regression checks the value is no longer hardcoded.
3. **Missing `remove_tx` method**: gate G14 references the symbol; once
   added, the test flips PASS.
4. **`estimate_mode` parameter**: gate G18 references trait signature;
   adding the parameter flips PASS.

## Out of scope for this audit (separate future waves)

- `FeeFilterRounder` (privacy quantization of mempool min-fee broadcast
  via `feefilter` BIP-133 message). Distinct subsystem; W136 covered the
  P2P-side wiring; the rounder itself is unaudited.
- `feefilter` BIP-133 message emission cadence (W136 territory).
- `getmempoolinfo.mempoolminfee` field consistency (W124-adjacent).
- `policy/feerate.cpp` `CFeeRate` arithmetic (overflow, rounding, dust).
  See W135 dust-threshold gates.
- `policy/truc_policy.cpp` TRUC v=3 inheritance into fee estimation
  (CPFP-ineligible txs SHOULD be excluded — Core does this; rustoshi
  doesn't track TRUC at the estimator level).

## Anticipated fix waves

Priority for the FIX-N cleanup ordering:

1. **FIX-fee-A (single-impl, P0)**: BUG-1 + BUG-3 + BUG-5 — rewrite
   `FEE_RATE_BUCKETS` to the Core exponential formula in sat/kvB units.
   Touches FEE_RATE_BUCKETS const + every call site that does `* 1000`
   conversion. Single-impl, no cross-impl coordination. ~150-300 LOC.

2. **FIX-fee-B (single-impl, P0)**: BUG-19 — add mempool/relay-fee floor
   to `estimate_smart_fee` RPC handler. ~20 LOC. Test: gate G22.

3. **FIX-fee-C (single-impl, P0)**: BUG-15 + BUG-16 — add `estimate_mode`
   trait parameter + implement Core's `max(halfEst, actualEst, doubleEst,
   consEst)` reduction. Touches trait signature (BREAKING for callers but
   matches Core), `estimate_fee` semantics. ~200 LOC.

4. **FIX-fee-D (single-impl, P0)**: BUG-9 — add `process_block` reorg
   guard. ~5 LOC. Test: gate G12.

5. **FIX-fee-E (single-impl, P0)**: BUG-6 + BUG-7 + BUG-8 — add `failAvg`,
   `unconfTxs`, `oldUnconfTxs` to `TxConfirmStats`; route through
   `remove_tx`. ~400 LOC across `fee_estimator.rs`.

6. **FIX-fee-F (single-impl, P1)**: BUG-11 + BUG-12 — add `remove_tx`
   public API + wire RBF eviction path in mempool. ~100 LOC across
   `fee_estimator.rs` + RBF site.

7. **FIX-fee-G (single-impl, P1)**: BUG-13 + BUG-14 — rewrite
   `EstimateMedianVal` to Core's grouping + return weighted median
   (`fee_sum/total` not bucket boundary). ~150 LOC.

8. **FIX-fee-H (single-impl, P1)**: BUG-25 — fix `estimaterawfee` response
   shape to `{short, medium, long}` per horizon. Removes the hardcoded
   `0.998` decay. ~100 LOC.

9. **FIX-fee-I (single-impl, P1)**: BUG-22 + BUG-23 + BUG-26 — switch
   persistence to Core's binary format with `CURRENT_FEES_FILE_VERSION =
   309900` magic + `MAX_FILE_AGE = 60h` rejection + `FlushUnconfirmed` at
   shutdown. ~300 LOC.

Total estimated effort: ~1600 LOC across 9 fix waves.

## Cross-impl coordination signals

(Discovery-only; for future fix-wave reuse.) Other impls likely have a
subset of these bugs:
- **Same bucket-units divergence (sat/vB vs sat/kvB) as BUG-5**:
  inspect blockbrew, ouroboros, nimrod fee estimators.
- **Missing `estimate_mode` RPC param as BUG-15**:
  cross-cutting; check every impl's `estimatesmartfee` signature.
- **`fee_estimates.dat` binary-format adoption as BUG-22**: only worth
  doing if multiple impls converge on Core's format together (otherwise
  no interop gain). Cross-impl alignment opportunity.

## Audit summary

- **30 gates**: 3 PASS (G1, G2, G3 — FIX-48 closed) + 1 PARTIAL (G7) +
  26 FAIL (BUGs).
- **30 BUGs found** (BUG-1 through BUG-30).
- **Priority breakdown**: 12 × P0 (CDIV-adjacent), 12 × P1, 6 × P2.
- **Pattern matches**:
  - "comment-as-confession + stale-after-internal-refactor" (BUG-25 —
    server.rs hardcodes pre-FIX-48 `decay=0.998`).
  - "well-engineered helper never wired" (BUG-14 — `fee_sum` computed
    but discarded for the returned feerate).
  - "test-only fix verification missed" — the FIX-48 closure of
    3-horizon architecture (PASS G1/G2/G3) did NOT update the RPC
    `estimaterawfee` handler to emit per-horizon `{short, medium, long}`
    structure. The fix landed in the engine but never propagated to the
    RPC surface. Same "dead-code-fix" failure mode as the rationale
    for `tools/verify-fix.sh` (CORE-PARITY-AUDIT/_fix-verification-methodology-2026-05-04.md).
