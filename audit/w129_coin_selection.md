# W129 — Coin selection (BnB / Knapsack / SRD / CG) parity audit (rustoshi)

**Wave**: W129 (Coin selection DISCOVERY)
**Impl**: rustoshi (Rust)
**Audit date**: 2026-05-17
**Reference**:
- `bitcoin-core/src/wallet/coinselection.cpp` + `coinselection.h`
  (`SelectCoinsBnB`, `SelectCoinsSRD`, `CoinGrinder`, `KnapsackSolver`,
  `ApproximateBestSubset`, `GenerateChangeTarget`, `OutputGroup`,
  `CoinEligibilityFilter`, `SelectionResult::RecalculateWaste/GetChange`,
  `CHANGE_LOWER`/`CHANGE_UPPER`).
- `bitcoin-core/src/wallet/spend.cpp` (`AttemptSelection`,
  `ChooseSelectionResult`, `GroupOutputs`, `CreateTransactionInternal`,
  `min_viable_change`, `m_change_fee`, `m_cost_of_change`,
  `m_min_change_target`, `m_subtract_fee_outputs` plumbing).
- `bitcoin-core/src/wallet/feebumper.cpp` (`CreateTotalBumpTransaction`).

**Production code changes**: 0 (pure audit).
**Audit subject**: `crates/wallet/src/coin_selection.rs` (~762 LOC) plus
its only call-site `crates/wallet/src/wallet.rs::create_transaction`
(`wallet.rs:478-650`). `bump_fee` / `psbt_bump_fee` paths
(`wallet.rs:728-960`) are part of the audit because Core's
`CreateTotalBumpTransaction` re-runs coin selection — the rustoshi
counterpart does not.
**Test file**: `crates/wallet/tests/test_w129_coin_selection.rs` — 30
gates, mix of PASS regression pins + `#[ignore]`-pinned xfail BUG-N stubs.

## Why this matters

Coin selection is the single most-touched wallet code path: every send,
sendmany, send, sendtoaddress, fundrawtransaction, walletcreatefunded-
psbt, and bumpfee runs it. Its correctness is **observable** in three
distinct ways:

1. **Fee outcomes** (waste metric). Two different selection paths from
   the same UTXO pool produce different fees — and operators benchmark
   wallet implementations on long-term consolidation cost. A
   `long_term_feerate` that's mis-scaled (sat/kvB vs sat/vB confusion
   in this audit subject — see BUG-3) systematically over-spends.
2. **Privacy / address-reuse leakage**. Core's
   `m_avoid_partial_spends` and `GroupOutputs`-by-script-pubkey
   eliminate "spent only some UTXOs of this address" heuristics. A
   wallet without grouping leaks address-cluster info on every
   transaction.
3. **Determinism gaps**. Core's BnB + CG are deterministic up to
   tie-break order, and Knapsack/SRD are RNG-seeded. A
   non-deterministic BnB or a Knapsack with the wrong-arity
   `vfIncluded`-reset-on-success pattern produces different selections
   for the same inputs across calls.

## Scope

30 gates across the full coin selection stack:

- **BnB** (`SelectCoinsBnB`): depth-first search, lookahead pruning,
  cost-of-change upper bound, equivalent-subtree skip, waste-metric
  tracking, `max_selection_weight` early exit, `is_feerate_high`
  branch-prune.
- **Knapsack** (`KnapsackSolver` + `ApproximateBestSubset`): 1000-iter
  stochastic subset-sum, two-pass scan, `lowest_larger` fallback,
  exact-match early return, weight ceiling.
- **SRD** (`SelectCoinsSRD`): shuffled-pool draw, min-heap-evict on
  over-weight, `CHANGE_LOWER`-fudge factor.
- **Coin Grinder** (`CoinGrinder`): min-weight DFS, EXPLORE/SHIFT/CUT
  state machine, clone-skip, `min_tail_weight` reachability prune.
- **Selection driver** (`AttemptSelection` /
  `ChooseSelectionResult`): per-OutputType waste-min selection then
  mixed-fallback, SFFO skip-BnB, CG-only-at-3×LTFR gate, result-waste
  comparison.
- **Plumbing** (`spend.cpp::CreateTransactionInternal`):
  `effective_feerate` vs `long_term_feerate` vs `discard_feerate`
  triple, `m_change_fee` from effective feerate, `m_cost_of_change` =
  `change_fee + discard_feerate.GetFee(change_spend_size)`,
  `min_viable_change` = max(change_spend_fee+1, dust),
  `GenerateChangeTarget` (random in [50ksat, min(2*payment, 1Msat)]).
- **OutputGroup / GroupOutputs**: per-script-pubkey grouping (Core
  default), avoid_partial_spends, OUTPUT_GROUP_MAX_ENTRIES,
  `CoinEligibilityFilter` (conf_mine / conf_theirs / ancestors / cluster).
- **SFFO** (`m_subtract_fee_outputs`): m_use_effective flag flip,
  recipient-amount mutation during build, BnB skip.
- **`RecalculateWaste` / `GetChange`**: change-vs-no-change branching,
  excess-throw-away accounting, bump-fee discount.
- **bumpfee**: Core's `CreateTotalBumpTransaction` re-runs coin
  selection with the previously-selected coins forced in and a
  bumped feerate target; rustoshi's `bump_fee` reduces change only.

## Summary

| Status | Count | Gates |
|--------|------:|-------|
| PRESENT | 4 | G1, G6, G7, G24 |
| PARTIAL | 11 | G2, G3, G4, G5, G8, G10, G11, G19, G20, G23, G29 |
| MISSING | 15 | G9, G12, G13, G14, G15, G16, G17, G18, G21, G22, G25, G26, G27, G28, G30 |

**26 bugs** (PARTIAL + MISSING): **3 × P0-CDIV** / **4 × P0** / **6 × P1** / **8 × P2** / **5 × P3**.

## Headline findings (top 5)

1. **BUG-1 [P0-CDIV] long-term feerate scale mismatch.** Core's
   `m_long_term_feerate` is a `CFeeRate` (sat/kvB internally; Core
   default `wallet.m_consolidate_feerate = CFeeRate(DEFAULT_CONSOLIDATE_FEERATE)
   = 10000` ≈ 10 sat/vB at `spend.cpp:1087`). Rustoshi
   (`wallet.rs:517`) sets `long_term_fee_rate: 10.0 / 1000.0` (= 0.01
   sat/vB) and `coin_selection.rs:112`
   `(input_weight as f64 / 4.0 * long_term_fee_rate).ceil()` reads
   that as `sat/vB`. **The long-term fee per input is computed as ~1
   sat for a 68-vbyte input** vs Core's ~680 sat (≈ 3 orders of
   magnitude under). Every waste calculation that uses
   `fee - long_term_fee` overshoots toward "consolidate now" — the
   wallet systematically over-spends UTXOs at low feerates because
   waste appears nearly equal to current fee. Plus the comment is
   **factually wrong** ("10 sat/kvB = 0.01 sat/vbyte (Core default)"
   — Core's actual default is 10 sat/vB / 10000 sat/kvB). Universal
   pattern: "comment-as-confession".

2. **BUG-2 [P0-CDIV] SFFO (subtract-fee-from-outputs) MISSING ENTIRELY.**
   `CoinSelectionParams` has no
   `m_subtract_fee_outputs` field; `OutputGroup` has no
   `subtract_fee_outputs` field; `GetSelectionAmount()` equivalent is
   absent (rustoshi always uses effective value). Core's
   `coinselection.cpp:789`
   `m_subtract_fee_outputs ? m_value : effective_value` toggles the
   selection target between gross and effective value depending on the
   SFFO flag at `spend.cpp:1104-1107`. Without SFFO support, any
   `sendmany`/`send`/`sendtoaddress` with `subtractfeefrom*` would
   either be rejected (no path through coin selection) or compute the
   wrong target. Compounds: BUG-21 (BnB-skipped-on-SFFO not honored)
   and BUG-25 (no recipient-amount mutation during build).

3. **BUG-3 [P0-CDIV] Knapsack `total_lower == target` shortcut spends
   uneconomic dust.** Core (`coinselection.cpp:683-692`) checks
   `nTotalLower == nTargetValue` and includes every applicable group
   ONLY IF the resulting weight `<= max_selection_weight`; otherwise
   it sets `max_weight_exceeded` and falls through. Rustoshi
   (`coin_selection.rs:349-359`) takes the same shortcut **without
   weight-checking** and **without iterating in waste-order** —
   returns a `SelectionResult` summing every applicable UTXO even when
   that exceeds standard tx weight. Plus rustoshi uses `utxo.value`
   not `GetSelectionAmount()` for the comparison
   (`coin_selection.rs:340,349`), so the equality check fires on gross
   value instead of effective value, producing false positives.

4. **BUG-4 [P0] BnB `is_feerate_high` short-circuit applied
   unconditionally.** Core (`coinselection.cpp:120`) computes
   `is_feerate_high = utxo_pool.at(0).fee > utxo_pool.at(0).long_term_fee`
   **after** the descending sort. Rustoshi (`coin_selection.rs:185`)
   reads `groups.first()` **after sorting by descending effective
   value**, which is the same UTXO, BUT the cumulative-waste-prune
   `is_feerate_high && curr_waste > best_waste` at `:199-201` is
   evaluated as `curr_waste > best_waste`. Core's bound is
   `curr_waste > best_waste` AND increasing (`coinselection.cpp:129`
   only fires when waste is **increasing** as more inputs are added);
   rustoshi's reads it as a generic ≥ check against the running best.
   When `is_feerate_high == false` (long-term feerate ≥ current —
   common at the bottom of the fee market), Core does NOT prune by
   waste because waste might *decrease* by adding more inputs; rustoshi
   honors that gate too, so this is the same algorithm — BUT see
   `:189-268` where the index-tracking loop diverges from Core. The
   Core inner loop uses a single `utxo_pool_index` that walks the pool
   linearly with `++utxo_pool_index` per iteration; rustoshi's
   conditional `utxo_index += 1` on inclusion vs separate restore-loop
   on backtrack produces different traversal order for some pools
   (e.g. when the inclusion branch is skipped via the duplicate-skip
   shortcut at `:239-242`, `utxo_index` still increments at `:250`,
   matching Core's `++utxo_pool_index` from the for-loop — but the
   subsequent backtrack restore at `:220-225` decrements past the same
   index, double-counting available value). Test G4 pins behavior.

5. **BUG-5 [P0] SRD (Single Random Draw) MISSING ENTIRELY.** No
   `select_coins_srd` function; no `SelectionAlgorithm::SRD` variant
   in the enum (`coin_selection.rs:36`); no min-heap evict-on-overweight
   pattern. Core uses SRD as the privacy-preferred algorithm at high
   feerates AND as a fallback when CG/Knapsack/BnB all fail. Rustoshi
   falls through to `select_coins_largest_first` which is **strictly
   worse for privacy** (deterministic, address-reuse correlatable).

(Also notable but not in the top 5: BUG-6 [P0] Coin Grinder MISSING
ENTIRELY — no CG-at-3×-LTFR path, no min-weight optimization at high
feerates; BUG-7 [P1] GroupOutputs-by-script-pubkey absent — every UTXO
is its own group, address-reuse heuristic leaks; BUG-8 [P1]
`GenerateChangeTarget` MISSING — change target is fixed at
`DUST_LIMIT` not randomized in [50ksat, min(2*payment, 1Msat)] which is a
direct fingerprinting risk.)

## Per-gate findings

### PRESENT (4)

| Gate | Surface | Location |
|------|---------|----------|
| G1   | BnB exists, depth-first walk with lookahead, cost-of-change cap | `coin_selection.rs:145-285` |
| G6   | Knapsack 1000-iteration `ApproximateBestSubset` loop with two-pass scan | `coin_selection.rs:442-502` |
| G7   | Knapsack `lowest_larger` single-UTXO fallback | `coin_selection.rs:343-345,362-369` |
| G24  | `SelectionResult { selected, total_value, target, waste, algorithm }` shape mirrors Core's `SelectionResult` | `coin_selection.rs:20-32` |

### PARTIAL (11)

| Gate | Severity | Gap | Location |
|------|---------|-----|----------|
| G2   | P0-CDIV | BnB `is_feerate_high` and backtrack-restore double-count available value when duplicate-skip fires (see BUG-4) | `coin_selection.rs:185,189-268` |
| G3   | P1      | BnB excludes negative-effective-value UTXOs (`:161`), matching Core, but ALSO excludes unconfirmed UTXOs by hard-coding `confirmations >= 1` (`:159`). Core delegates this to `CoinEligibilityFilter` which is configurable; rustoshi has no path to spend own change with 0 confirmations. | `coin_selection.rs:159` |
| G4   | P0      | BnB duplicate-skip at `:239-242` uses `groups[utxo_index - 1]` but `utxo_index` may have been incremented past a different group on a previous backtrack — the predecessor referenced is the **iteration predecessor** not the **sort predecessor** Core uses | `coin_selection.rs:239-242` |
| G5   | P1      | BnB `best_waste = i64::MAX` is the **wrong sentinel** vs Core's `best_waste = MAX_MONEY = 21000000 * COIN`; `curr_waste <= best_waste` accepts any selection on the first hit, which matches Core. But waste is stored in i64 (not CAmount) — overflow risk on negative-waste UTXO pools is wider | `coin_selection.rs:179` |
| G8   | P0-CDIV | Knapsack uses `utxo.value` for `total_lower` comparison (`:340-349`) instead of `GetSelectionAmount()` (Core `coinselection.cpp:675-680`). When SFFO would normally toggle this, the comparison is wrong on both branches; see BUG-3. | `coin_selection.rs:340-349` |
| G10  | P2      | `cost_of_change` computation (`coin_selection.rs:86-90`) uses fixed `change_cost` (= "P2WPKH output ~31 vbytes * 4 (weight)") and `change_spend_cost = 68` BUT divides change_cost by 4 again at `:87`: `change_cost / 4.0 * fee_rate`. Result: change_cost is double-attenuated. Core (`spend.cpp:1174-1175`) uses `change_output_size` directly (not weight) with `effective_feerate.GetFee(change_output_size)`. | `coin_selection.rs:86-90` |
| G11  | P1      | `min_change` is fixed at `DUST_LIMIT = 546`. Core's `min_viable_change` is `max(change_spend_fee + 1, dust)` (`spend.cpp:1184`), recomputed per-tx. | `wallet.rs:518` + `coin_selection.rs:309` |
| G19  | P3      | `OutputGroup::new` (`:110-122`) is one-UTXO-per-group; Core's `OutputGroup` collects up to OUTPUT_GROUP_MAX_ENTRIES UTXOs per script-pubkey via `Insert()`. | `coin_selection.rs:109-128` |
| G20  | P2      | `select_coins` driver tries BnB → Knapsack → LargestFirst in that order (`:558-575`); Core picks the **min-waste** result across {BnB, Knapsack, CG-if-applicable, SRD} via `std::min_element` (`spend.cpp:716`). Rustoshi returns the first one that succeeds without comparing waste. | `coin_selection.rs:558-575` |
| G23  | P2      | `select_coins_largest_first` waste calculation sums `fee - long_term_fee` per input (`:537-541`), which is correct, but excludes the excess-above-target term Core includes in `RecalculateWaste` (`coinselection.cpp:849`). Largest-first inherits BnB's no-change semantics but isn't recognized as a change-or-not path. | `coin_selection.rs:537-541` |
| G29  | P1      | bumpfee path (`wallet.rs:728-960`) never re-runs coin selection. Core's `CreateTotalBumpTransaction` does. Rustoshi only reduces change; "cannot bump without adding inputs (not yet supported)" at `:847`. | `wallet.rs:847,855` |

### MISSING (15)

| Gate | Severity | Surface absence | Location |
|------|---------|-----------------|----------|
| G9   | **P0-CDIV** | **SFFO (`m_subtract_fee_outputs`) — no field on params or output group; no `m_value` vs `effective_value` toggle.** | `coin_selection.rs::CoinSelectionParams` |
| G12  | **P0** | **SRD (`SelectCoinsSRD`) absent.** No min-heap evict-on-overweight; no `CHANGE_LOWER`/`change_fee` fudge factor. | (no `select_coins_srd` function) |
| G13  | **P0** | **Coin Grinder (`CoinGrinder`) absent.** No EXPLORE/SHIFT/CUT state machine; no min_tail_weight reachability; no `effective_feerate > 3 * long_term_feerate` gate. | (no `coin_grinder` function) |
| G14  | P1      | `GenerateChangeTarget` (random in [50ksat, min(2*payment, 1Msat)]) absent. Change is the residual after fee; no targeted randomization. | (no equivalent) |
| G15  | P1      | `CoinEligibilityFilter` (conf_mine / conf_theirs / max_ancestors / max_cluster_count) absent. The `confirmations >= 1` filter is hard-coded; can't tier-up to conf_theirs=6 for outside coins. | `coin_selection.rs:159,314` |
| G16  | P2      | `m_avoid_partial_spends` absent. Without `GroupOutputs`-by-script-pubkey, this flag has no surface. | (no equivalent) |
| G17  | P2      | `OUTPUT_GROUP_MAX_ENTRIES` (Core wallet.h:120 = 100) cap absent — one-UTXO-per-group means no cap is needed, but groups also never combine. | (no equivalent) |
| G18  | P2      | `RecalculateWaste(min_viable_change, change_cost, change_fee)` absent. Waste is computed inline in BnB at `:204-205`, and in Knapsack as `sum(group.waste())` at `:351,427`. There is no centralized recalculation hook; no bump-fee-discount, no excess-above-target term. | (no equivalent) |
| G21  | P1      | `m_subtract_fee_outputs ? skip BnB : run BnB` gate absent (Core spend.cpp:751). | (no gate site) |
| G22  | P2      | `m_effective_feerate > 3 * m_long_term_feerate ? run CoinGrinder` gate absent (Core spend.cpp:769). | (no gate site) |
| G25  | P1      | SFFO recipient-amount mutation (Core spend.cpp:1349 reduces each subtract-fee-from output by `fee/num_subtract_fee_outputs`) absent. | (no path) |
| G26  | P2      | `AttemptSelection` per-OutputType iteration with mixed-fallback absent. Rustoshi has no concept of "try each output type group separately, then mix". | (no equivalent) |
| G27  | P2      | `tx_noinputs_size` overhead (10 + compact-size-of-output-count + per-recipient serialize) absent from params. Rustoshi estimates fee from `estimate_tx_vsize(inputs, outputs)` which approximates the same surface but lazily. | `wallet.rs:499-506` |
| G28  | P2      | `m_max_tx_weight` / `MAX_STANDARD_TX_WEIGHT` enforcement absent. BnB has no max-selection-weight check (Core coinselection.cpp:131-133); Knapsack's `weight > max_selection_weight` evict (Core coinselection.cpp:668-671) absent. | `coin_selection.rs::OutputGroup` (no `weight > max_selection_weight` branch) |
| G30  | P3      | `SelectionResult::GetShuffledInputVector` (Core coinselection.cpp:941) — final tx inputs are shuffled to randomize input order for privacy. Rustoshi build path preserves selection order. | `wallet.rs:572-580` |

## Bug inventory (P0-CDIV / P0 / P1 / P2 / P3)

### P0-CDIV (consensus-divergence-class fee/privacy bugs, 3)

- **BUG-1** [P0-CDIV] G29-feat / BUG-1 headline: long-term feerate
  scale mismatch (sat/vB read as sat/kvB). `wallet.rs:517`. Every
  waste metric is wrong by ~1000×.
- **BUG-2** [P0-CDIV] G9: SFFO MISSING ENTIRELY. Compounds with
  BUG-21, BUG-25.
- **BUG-3** [P0-CDIV] G8: Knapsack `total_lower == target` shortcut
  skips weight check AND uses gross value not effective value.
  `coin_selection.rs:340-359`.

### P0 (consensus-relevant correctness, 4)

- **BUG-4** [P0] G4 / G2: BnB index-bookkeeping divergence from Core's
  single `++utxo_pool_index`. Effects: pool-dependent missed solutions.
- **BUG-5** [P0] G12: SRD missing entirely.
- **BUG-6** [P0] G13: Coin Grinder missing entirely.
- **BUG-7** [P0] G10: `cost_of_change` double-attenuates the change
  output (`change_cost / 4.0 * fee_rate` where `change_cost` is
  already in weight units). Effective cost-of-change is ~1/4 of
  Core's, so BnB's upper bound (target + cost_of_change) is too tight
  and rejects valid selections.

### P1 (bug, 6)

- **BUG-8** [P1] G14: `GenerateChangeTarget` missing — change target
  fixed at `DUST_LIMIT`, no `CHANGE_LOWER`/`CHANGE_UPPER`
  randomization. Privacy: change-amount fingerprinting.
- **BUG-9** [P1] G15: `CoinEligibilityFilter` missing — confirmations
  filter hardcoded to `>= 1`; can't apply Core's `conf_mine` vs
  `conf_theirs` tier-up.
- **BUG-10** [P1] G21: BnB-skipped-on-SFFO gate missing (no SFFO).
- **BUG-11** [P1] G7: GroupOutputs-by-script-pubkey missing. Every
  UTXO is its own group; address-reuse heuristic leaks.
- **BUG-12** [P1] G25: SFFO recipient-amount mutation missing.
- **BUG-13** [P1] G29: bumpfee never re-runs coin selection (no
  input-adding); only reduces change. Core's
  `CreateTotalBumpTransaction` re-runs the full selector with
  preserved inputs forced in.

### P2 (bug, 8)

- **BUG-14** [P2] G16: `m_avoid_partial_spends` missing.
- **BUG-15** [P2] G17: `OUTPUT_GROUP_MAX_ENTRIES` cap missing.
- **BUG-16** [P2] G18: `RecalculateWaste` centralized hook missing —
  waste computed in 3 different places with no bump-fee-discount.
- **BUG-17** [P2] G22: CG-at-3×LTFR gate missing.
- **BUG-18** [P2] G20: `select_coins` driver returns first-success
  instead of min-waste across all algorithms.
- **BUG-19** [P2] G26: `AttemptSelection` per-OutputType iteration
  missing — no "try each output type separately, then mix" path.
- **BUG-20** [P2] G27: `tx_noinputs_size` overhead absent from
  selection params; non-input-fees folded into bootstrap estimate.
- **BUG-21** [P2] G28: `m_max_tx_weight` / max-selection-weight
  enforcement absent in BnB and Knapsack.

### P3 (minor / hygiene, 5)

- **BUG-22** [P3] G3: hard-coded `confirmations >= 1` filter at BnB
  and Knapsack entry. Conflicts with G15 (eligibility-filter
  configuration absent).
- **BUG-23** [P3] G19: one-UTXO-per-OutputGroup design — groups never
  combine multiple UTXOs sharing a script-pubkey.
- **BUG-24** [P3] G23: `select_coins_largest_first` waste excludes
  excess-above-target term Core includes in `RecalculateWaste`.
- **BUG-25** [P3] G5: `best_waste = i64::MAX` sentinel vs Core's
  `MAX_MONEY = 21M * COIN`; subtle overflow surface for negative-
  waste pools.
- **BUG-26** [P3] G30: `GetShuffledInputVector` (final input-order
  shuffle for privacy) absent.

## Universal patterns (W129)

1. **"Comment-as-confession" — long-term-feerate scale.**
   `wallet.rs:517` says "10 sat/kvB = 0.01 sat/vbyte (Core default)"
   but Core's `DEFAULT_CONSOLIDATE_FEERATE = 10000 sat/kvB =
   10 sat/vB`. The comment correctly identifies the unit but documents
   the wrong target. Same pattern seen in blockbrew W122 BIP-158 codec
   audit ("test-comment-as-confession") and W121 BUG-5 FullRBF
   comment. This audit's instance is a *value*-confession not a
   *gating*-confession: the unit conversion is correct, the desired
   Core-target is documented, but the literal stored is off by 1000×.

2. **"Algorithm missing entirely, fallback exists" — 3 of 4 modern
   algos absent.** SRD missing (BUG-5), CG missing (BUG-6), SFFO
   missing (BUG-2). The fallback `select_coins_largest_first` is a
   greedy 1-pass heuristic that **doesn't appear in Core at all**
   (Core's fallback chain is BnB → Knapsack → CG → SRD, never
   largest-first). Pattern: rather than implementing the modern
   algorithms (post-2018: BnB; post-2024: CG; SRD added 2022), the
   implementation went sideways with a non-Core heuristic. Distinct
   from W121's "well-engineered helper never wired" — here the
   helpers aren't engineered at all, and a non-Core helper is wired
   in their place.

3. **"Selection driver returns first-success not min-waste"** (BUG-18
   / G20). `select_coins` tries BnB then Knapsack then LargestFirst,
   returning the first non-None. Core's `AttemptSelection` runs ALL
   applicable algorithms, recomputes waste for each, and selects via
   `std::min_element`. This is a categorically different selection
   semantics: Core compares N solutions, rustoshi short-circuits at
   the first solution it gets. Effect: a worse BnB selection
   suppresses a better Knapsack selection that would have been
   considered if both ran.

4. **"Filter hard-coded at entry vs configurable via params"** —
   `confirmations >= 1` at `coin_selection.rs:159,314` is the
   eligibility filter. Core's `CoinEligibilityFilter` (BUG-9 / G15)
   is **structured**: conf_mine / conf_theirs / max_ancestors /
   max_cluster_count, applied as a filtered iteration in `spend.cpp`.
   This audit's filter is structurally degenerate: a single ≥1 gate
   inline. Pattern shared with W120 RBF-rule-1 ("Rule X hardcoded at
   call site, not enforced via centralized predicate").

5. **"Triple-feerate plumbing missing — discard_feerate absent."**
   Core uses 3 distinct feerates: `m_effective_feerate` (current
   target), `m_long_term_feerate` (consolidation cost), and
   `m_discard_feerate` (cost of *dropping* a UTXO to fee). Rustoshi
   has only `fee_rate` and `long_term_fee_rate`; no discard feerate
   means `m_cost_of_change = m_discard_feerate.GetFee(change_spend_size)
   + m_change_fee` (Core spend.cpp:1175) collapses to `change_fee`
   alone (BUG-7 / G10), which over-attenuates the cost-of-change
   ceiling in BnB.

6. **"Test fixtures encode the bugs"** — Three of the existing tests
   in `coin_selection.rs:601-761` accept the buggy behavior:
   `bnb_exact_match` (`:619-622`) explicitly says "It's OK if BnB
   doesn't find a solution — it falls back to knapsack", and
   `unconfirmed_utxos_excluded` (`:728-744`) pins BUG-22 (hardcoded
   confirmations >= 1) as expected behavior. The
   `effective_value_calculation` test (`:746-761`) uses `fee_rate:
   10.0` which is sat/vB — but the long_term_feerate elsewhere uses
   sat/kvB scale — so the unit confusion is encoded in the tests
   themselves, masking BUG-1 from regression detection.

## Out of scope (for W129 — explicitly future waves)

- Operator RPC surfaces that *invoke* coin selection (`sendmany`,
  `send`, `fundrawtransaction`, `walletcreatefundedpsbt`) — covered
  by W118 BUG-5, BUG-6, BUG-7.
- `m_avoid_partial_spends` interaction with `m_include_partial_groups`
  — second-order; first-order grouping is missing (BUG-11).
- Cluster-mempool ancestor/descendant tracking for `OutputGroup.
  m_ancestors` / `m_max_cluster_count` — covered by W120 mempool
  audit; coin selection just reads them.
- `walletcreatefundedpsbt`'s `solving_data` (BIP-174 round-trip with
  pre-known script and witness) — touches PSBT not selection.
- Hardware-wallet input bytes precomputation for non-keypath signing —
  Core delegates to `CalculateMaximumSignedInputSize`; rustoshi has
  `input_vsize_for(address_type)` which is fine for the audit subject.

## Verification harness

`crates/wallet/tests/test_w129_coin_selection.rs` — 30 gates. PASS
regression pins for G1/G6/G7/G24. Each BUG-N has an `#[ignore]`
test that documents the divergence and `panic!()`s with the Core
behavior. Gates that are pure source-grep ("function MUST exist") use
a compile-time-equivalent `let _ = ...` against a sentinel value;
where the function is absent, the test calls a stand-in that asserts
the gap.

Run:
```
cargo test --package rustoshi-wallet --test test_w129_coin_selection
```

## Cross-wave references

- **W118 Wallet fleet audit (BUG-5/6/7/14)**: `sendmany` / `send` /
  `settxfee` / `walletcreatefundedpsbt` absences. These are the
  *callers* of coin selection. W129 audits the *callees*; the two
  audits compose.
- **W120 mempool RBF (BUG-9 prioritise / BUG-10 modified fee)**:
  `OutputGroup` consumes `m_ancestors` from the mempool — if FIX-72's
  `get_modified_fee` doesn't propagate, BnB sees stale ancestor fees.
- **W117 BIP-155 (universal): "well-engineered helper never wired"**:
  Distinct shape here — the helpers (SRD, CG, SFFO) don't exist at
  all. W129's pattern is "modern algorithm absent" not "wired but
  dead".
- **W122 BIP-158 codec ("test-comment-as-confession")**: BUG-1
  long-term feerate comment is the same pattern at a different layer
  (selection feerate instead of BIP-158 byte order).
- **W125 RPC error parity (BUG-3 RPC_INVALID_PARAMETER mass-divergence)**:
  No direct overlap with W129 except that SFFO/conf_target params
  flow into coin selection and W125 already noted the parameter-error
  code mismatch.
