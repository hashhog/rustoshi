# W130 — BIP-125 RBF Feebumper Rule 3 parity audit (rustoshi)

**Wave**: W130 (BIP-125 RBF feebumper Rule 3 DISCOVERY)
**Impl**: rustoshi (Rust)
**Audit date**: 2026-05-17
**Reference**:
- `bitcoin-core/src/wallet/feebumper.cpp` (`CreateRateBumpTransaction`,
  `CheckFeeRate`, `EstimateFeeRate`, `PreconditionChecks`).
- `bitcoin-core/src/policy/rbf.cpp` + `policy/rbf.h` (`PaysForRBF`,
  `GetEntriesForConflicts`, `EntriesAndTxidsDisjoint`, `IsRBFOptIn`,
  `MAX_REPLACEMENT_CANDIDATES`, `ImprovesFeerateDiagram`).
- `bitcoin-core/src/util/rbf.cpp` + `util/rbf.h` (`SignalsOptInRBF`,
  `MAX_BIP125_RBF_SEQUENCE` = 0xfffffffd).
- `bitcoin-core/src/policy/feerate.cpp` +
  `bitcoin-core/src/util/feefrac.h` (`CFeeRate::GetFee` →
  `EvaluateFeeUp` rounds **up** via `CeilDiv`, not truncates).
- `bitcoin-core/src/policy/policy.h:48`
  (`DEFAULT_INCREMENTAL_RELAY_FEE = 100` sat/kvB = 1 sat/vB).
- `bitcoin-core/src/wallet/wallet.h:124`
  (`WALLET_INCREMENTAL_RELAY_FEE = 5000` sat/kvB = 5 sat/vB; wallet
  ensures replacements pay at least this much per vbyte on top of
  the original fee, future-proofing against network-wide policy).

**Production code changes**: 0 (pure audit).
**Audit subject**:
- `crates/wallet/src/wallet.rs::build_bumped_tx`
  (`wallet.rs:761-932`) — invoked by both `bump_fee` and
  `psbt_bump_fee`. Pre-existing **FIX-61** closure for W118 BUG-2/3.
- `crates/consensus/src/mempool.rs::check_rbf_rules`
  (`mempool.rs:2767-2879`) + `is_bip125_replaceable`
  (`mempool.rs:2690-2711`) + `signals_opt_in_rbf` (`:2682-2684`) +
  the sibling-eviction RBF mirror at `mempool.rs:1751-1769`.
- Plumbed config: `MempoolConfig::incremental_relay_fee`
  (`mempool.rs:698`) + `MempoolConfig::full_rbf`
  (`mempool.rs:695`) + `MAX_REPLACEMENT_CANDIDATES`
  (`mempool.rs:92`) + `MAX_BIP125_RBF_SEQUENCE` (`:96`) +
  `DEFAULT_INCREMENTAL_RELAY_FEE` (`:101`).
- RPC surface: `bumpfee`/`psbtbumpfee` (`rpc/src/wallet.rs:816,834`),
  `getrawmempool verbose.bip125_replaceable` (`rpc/src/server.rs:7018`).

**Test file**: `crates/wallet/tests/test_w130_bip125_feebumper_rule3.rs`
— 30 gates, mix of PASS regression pins for already-correct surfaces +
`#[ignore]`-pinned `panic!()` stubs for BUG-N divergences.

## Why this matters

BIP-125 Rule 3 has a well-known fleet-wide trap: it is naively
expressed as **"new fee > old fee"**, but Core's actual invariant is
**`new_total_fee >= old_fee + incrementalRelayFee.GetFee(maxTxSize)`**.
The `incrementalRelayFee` defaults to 1 sat/vB (`policy.h:48`), and
the *wallet* uses `max(node_incremental, WALLET_INCREMENTAL_RELAY_FEE)`
= 5 sat/vB by default (`wallet.h:124`). `CFeeRate::GetFee` rounds **up**
via `CeilDiv` (`feefrac.h:212`), not truncates.

Three independent failure modes can hide here:

1. **Naive new>old.** Builds a replacement with `new_fee = old_fee +
   1 sat`. Mempool rejects (Rule 4 / bandwidth). Operator confused.
2. **Wrong incremental constant.** Wallet picks 1 sat/vB hardcoded,
   ignoring `WALLET_INCREMENTAL_RELAY_FEE = 5 sat/vB`. Mempool accepts
   locally because its check is also 1 sat/vB, BUT every Core peer
   (which defaults to 5 sat/vB on its wallet build path) and any node
   with `-incrementalrelayfee > 1` will reject the tx. The wallet path
   diverges from the relay path.
3. **Truncate vs round-up.** Uses `(rate * vsize) / 1000` integer
   truncation instead of Core's `EvaluateFeeUp`/`CeilDiv`. For a
   non-multiple-of-1000 vsize, the required fee is one sat too low.
   Core's W129-style "off-by-one rejection" precedent.

This audit catalogues which of the three modes rustoshi exhibits, and
which adjacent Rule 1/2/4/5 invariants drift.

## Scope

30 gates split across:

- **Rule 1** (signaling-or-mempool-replaceable):
  `IsRBFOptIn` / `SignalsOptInRBF` / ancestor-signaling / `full_rbf`
  override / TRUC implicit replaceability (`mempool.rs:2782-2793`,
  `wallet.rs:779-790`).
- **Rule 2** (no-new-unconfirmed-inputs in wallet + ancestors-not-in-
  conflict in mempool): wallet `new_coin_control.m_min_depth = 1`
  vs rustoshi's bumpfee path that **reuses original inputs only**;
  mempool `EntriesAndTxidsDisjoint` (`policy/rbf.cpp:85-98`).
- **Rule 3** (bandwidth fee floor): `incrementalRelayFee.GetFee
  (maxTxSize)` (Core feebumper.cpp:93). The headline gate. Test
  combinations: default 1 sat/vB, operator-overridden 5 sat/vB,
  WALLET_INCREMENTAL_RELAY_FEE max-fence (5 sat/vB), CeilDiv
  rounding, and `maxTxSize` source (vsize of original vs estimated
  replacement).
- **Rule 4** (pays-for-own-bandwidth): `additional_fees >=
  relay_fee.GetFee(replacement_vsize)` (Core rbf.cpp:114-123).
- **Rule 5** (eviction cap):
  `MAX_REPLACEMENT_CANDIDATES = 100` direct + descendants
  (Core rbf.h:26, GetEntriesForConflicts).
- **EstimateFeeRate** (`feebumper.cpp:119-144`): bump rate =
  `max(old_feerate + 1 sat + max(node_incremental, wallet_incremental),
  min_feerate)`.
- **CheckFeeRate** (`feebumper.cpp:60-117`): mempool-min-fee guard,
  `combined_bump_fee` for descendant-aware fee accounting, required-
  fee floor, `max_tx_fee` ceiling.
- **PreconditionChecks** (`feebumper.cpp:23-57`): descendant-in-
  wallet, descendant-in-mempool, mined / `replaced_by_txid` guard,
  `AllInputsMine` for `require_mine`.
- **ImprovesFeerateDiagram** (cluster-mempool, Core 27+): explicitly
  noted not-implemented at `mempool.rs:2765-2766`.
- **Dead-error-variant**: `RbfInsufficientFeeRate` at
  `mempool.rs:920` declared but never constructed.

## Out of scope (deferred to future waves)

- **Cluster-mempool `ImprovesFeerateDiagram`** (Core 27+) — already
  explicitly disclaimed at `mempool.rs:2765-2766`. Covered by a
  follow-on cluster-mempool wave.
- **TRUC sibling-eviction RBF mirror** (`mempool.rs:1751-1769`) —
  uses the same incremental_relay_fee math; W120 already audited the
  TRUC v3 path. We touch it only via G29 source-grep continuity.
- **`replaced_by_txid` wallet map-value** (Core feebumper.cpp:42-45)
  — covered by W118 BUG-14 (the listtransactions `replaced_by_txid`
  field). The chain side of "is this tx still bumpable" lookup is
  handled, but the field doesn't propagate to RPC.
- **`prioritisetransaction` interaction with RBF** — W120 BUG-9 +
  FIX-72 closed `GetModifiedFee` in the conflicts-fee accumulation
  (mempool.rs:2811,2818). No new gate here.
- **`AllInputsMine`** for `require_mine=true` (Core feebumper.cpp:
  47-54) — touches wallet-vs-foreign input partition; deferred.
- **Hardware-wallet external-input weight estimation** (Core
  feebumper.cpp:209-231) — `SignatureWeightChecker`; defer to
  PSBTv2/HWI wave.

## Verification harness

`crates/wallet/tests/test_w130_bip125_feebumper_rule3.rs` — 30 gates.

- Gates whose feature IS present pass as regression pins (compile-time
  re-export of the constant, runtime round-trip against the BIP-125
  invariant).
- Gates with PARTIAL/MISSING surfaces are `#[test] #[ignore]` with a
  `panic!()` whose message names the BUG-N and references the Core
  source line. The `#[ignore]` opt-out keeps the test binary green
  in CI while keeping the divergence pinned for forward regression.
- Source-grep gates (e.g. confirming that
  `(self.config.incremental_relay_fee * new_vsize as u64 + 999) /
  1000` literal still lives at `mempool.rs:2870`) use `include_str!`
  on the source file and a `contains` check; this is the same shape
  W120 used in `g11_modified_fee_unused_in_rbf_comparison_bug9`.

Run:
```
cargo test --package rustoshi-wallet --test test_w130_bip125_feebumper_rule3
```

## Summary

| Status  | Count | Gates |
|---------|------:|-------|
| PRESENT | 11    | G1, G3, G4, G5, G6, G7, G8, G9, G14, G18, G24 |
| PARTIAL | 11    | G2, G10, G11, G12, G13, G15, G17, G19, G20, G22, G30 |
| MISSING | 8     | G16, G21, G23, G25, G26, G27, G28, G29 |

**19 bugs** (PARTIAL + MISSING): **2 × P0-CDIV** / **3 × P0** /
**6 × P1** / **5 × P2** / **3 × P3**.

## Headline findings (top 5)

1. **BUG-1 [P0-CDIV] Wallet bumpfee uses hardcoded 1 sat/vB
   incremental, ignoring `WALLET_INCREMENTAL_RELAY_FEE = 5 sat/vB`.**
   `wallet.rs:817` `const INCREMENTAL_FEE_RATE: f64 = 1.0; // sat/vB;
   Core DEFAULT_INCREMENTAL_RELAY_FEE`. Core's `feebumper.cpp:137`:
   `feerate += std::max(node_incremental_relay_fee,
   wallet_incremental_relay_fee)` where `WALLET_INCREMENTAL_RELAY_FEE
   = 5000` sat/kvB = **5 sat/vB**. Rustoshi's wallet builds a
   replacement that is 5× under Core's wallet floor. The local mempool
   accepts (matches its own 1 sat/vB Rule 4), BUT every Core peer
   on the network rejects with `insufficient fee` and refuses to
   relay. **The wallet-relay path silently diverges from peer-relay
   path.** This is the canonical "naive new_fee>old_fee" trap stated
   in W130 brief — rustoshi instantiates the trap structurally
   instead of relying on the operator misconfiguring.

2. **BUG-2 [P0-CDIV] Wallet bumpfee never reads
   `MempoolConfig::incremental_relay_fee`.** `wallet.rs:817` is a
   compile-time `f64` constant, not a runtime read. If the operator
   sets `-incrementalrelayfee=10` (sat/vB) the mempool will require
   10 sat/vB of additional fee per vbyte, but the wallet still
   builds a replacement with 1 sat/vB delta. Every bump fails with
   `RbfInsufficientBandwidthFee`, and the operator sees a confusing
   "tx accepted at fee_rate X but bumpfee rejected" loop. Core
   feebumper.cpp:90: `wallet.chain().relayIncrementalFee()` is the
   plumbed accessor. Rustoshi has the equivalent
   (`MempoolConfig::incremental_relay_fee` `mempool.rs:698`) but
   the wallet path doesn't reach it.

3. **BUG-3 [P0] `CheckFeeRate` Core-parity guard MISSING ENTIRELY.**
   Core `feebumper.cpp:60-117` performs **five** Core-parity checks on
   `bumpfee`:
   (a) `newFeerate >= mempoolMinFee` (don't bump into a rate that
       won't enter the mempool);
   (b) `combined_bump_fee` calculation including descendant fees
       (Core 27+ `calculateCombinedBumpFee`);
   (c) `new_total_fee >= old_fee + incrementalRelayFee.GetFee
       (maxTxSize)` (Rule 3 floor);
   (d) `new_total_fee >= GetRequiredFee(wallet, maxTxSize)` (network
       min-relay floor);
   (e) `new_total_fee <= max_tx_fee` (wallet `-maxtxfee` ceiling).
   **Rustoshi's wallet skips ALL FIVE.** `build_bumped_tx` only
   compares `new_fee > orig_fee` after the change-output reduction
   math (`wallet.rs:834-843`); the floor check at `:820` uses
   hardcoded 1 sat/vB (BUG-1/2). There is no maxtxfee, no required
   fee floor, no mempool-min-fee guard. The wallet is willing to
   build a replacement at a fee rate the mempool will reject.

4. **BUG-4 [P0] Wallet path doesn't enforce BIP-125 rule 2
   (no new unconfirmed inputs).** Core `feebumper.cpp:312`:
   `new_coin_control.m_min_depth = 1;` is set before re-running coin
   selection, so any *new* input pulled in for the bump must have at
   least 1 confirmation. Rustoshi's `build_bumped_tx` **does not
   re-run coin selection** — it reuses the original inputs only
   (`wallet.rs:864-874`). This means rule 2 is *vacuously* satisfied,
   BUT only because input adding isn't supported (W129 BUG-13 / G29
   pre-existing). The minute `bump_fee` adds an input-adding path
   (planned in the FIX-61 follow-up), rule 2 will not be enforced.
   This is a "minefield bug" — present-but-asleep. Audit pins it
   now so the test fires the day input-adding lands.

5. **BUG-5 [P0] Dead error variant `RbfInsufficientFeeRate` at
   `mempool.rs:920`.** Declared but never constructed. The comment
   block at `mempool.rs:2862-2865` confirms it was intentionally
   removed ("There is NO rule requiring the replacement's fee rate to
   exceed the original's fee rate. That spurious check has been
   removed.") yet the error variant remains as a leftover. Plus
   `RbfInsufficientFeeRate` carries `(f64, f64)` payloads; nothing in
   the codebase constructs an `f64` for it. **Dead-helper-at-call-
   site precedent** — Universal pattern from the 34-wave streak.
   Distinct from BUG-1/2 (which are bugs in the *bumpfee* path);
   this one is in the *mempool* path's error API surface.

(Also notable but not in the top 5: BUG-6 [P1] `EstimateFeeRate`
helper MISSING — rustoshi's `build_bumped_tx` has no equivalent of
Core's `feebumper.cpp:119-144` `EstimateFeeRate`. BUG-7 [P1]
`PreconditionChecks` half-present — confirmed-tx + RBF-signaling
checked, but the descendant-in-wallet and descendant-in-mempool
guards are MISSING. BUG-8 [P1] `bumpfee` wallet helper does not call
`is_bip125_replaceable` — only checks own-input sequences, missing
the ancestor-signaling path (less critical because the only ancestors
in scope on a wallet-originated tx are also wallet-originated, but
the helper is the wrong shape vs Core).)

## Per-gate findings

### PRESENT (11)

| Gate | Surface                                                                                                                       | Location                                       |
|------|-------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------|
| G1   | `MAX_BIP125_RBF_SEQUENCE = 0xFFFFFFFD` constant matches Core `util/rbf.h:12`.                                                  | `mempool.rs:96`, `wallet.rs:49`                |
| G3   | `is_bip125_replaceable` checks self-sequence + ancestor-sequence (`IsRBFOptIn` Core parity).                                   | `mempool.rs:2690-2711`                         |
| G4   | `signals_opt_in_rbf` private helper iterates inputs and applies `<= MAX_BIP125_RBF_SEQUENCE`.                                  | `mempool.rs:2682-2684`                         |
| G5   | Rule 1 enforced (`!full_rbf && !is_bip125_replaceable && !is_truc_replaceable` → reject).                                     | `mempool.rs:2782-2793`                         |
| G6   | Rule 1 honors TRUC implicit replaceability (BIP-431 v3 always replaceable).                                                    | `mempool.rs:2724-2745,2788`                    |
| G7   | Rule 5 cap is exactly `MAX_REPLACEMENT_CANDIDATES = 100`, matching Core `policy/rbf.h:26`.                                     | `mempool.rs:92,2828-2832`                      |
| G8   | Rule 3 fee comparison uses `Self::get_modified_fee` not raw `entry.fee` (FIX-72 / W120 BUG-9 closure).                          | `mempool.rs:2811,2818`                         |
| G9   | `full_rbf` defaults to `true` (Core v28+ parity).                                                                              | `mempool.rs:730`                               |
| G14  | Rule 2 (replacement ancestors disjoint from direct conflicts) is enforced via `replacement_ancestors`/`direct_conflicts` walk. | `mempool.rs:2844-2849`                         |
| G18  | `DEFAULT_INCREMENTAL_RELAY_FEE = 100` (sat/kvB) constant matches `policy/policy.h:48`.                                         | `mempool.rs:101`                               |
| G24  | `MempoolError::ReplacementDisallowed` ("bip125-replacement-disallowed") fires when `args.allow_replacement == false`.          | `mempool.rs:1015-1018,1447-1449`               |

### PARTIAL (11)

| Gate | Severity | Gap                                                                                                                                                                                                                                                                                                                                                                                                                                                | Location                                                  |
|------|----------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------|
| G2   | P0-CDIV  | Rule 3 invariant compiled-time hardcoded **1 sat/vB** in wallet (`INCREMENTAL_FEE_RATE: f64 = 1.0`), should be `max(node_incremental, WALLET_INCREMENTAL_RELAY_FEE=5 sat/vB)`. **BUG-1**.                                                                                                                                                                                                                                                            | `wallet.rs:817`                                           |
| G10  | P0-CDIV  | Wallet bumpfee doesn't read `MempoolConfig::incremental_relay_fee` at runtime; operator-set `-incrementalrelayfee` is ignored by the wallet. **BUG-2**.                                                                                                                                                                                                                                                                                            | `wallet.rs:817`                                           |
| G11  | P0       | `CheckFeeRate` Core-parity guard MISSING — no mempool-min-fee gate, no `combined_bump_fee`, no `GetRequiredFee` floor, no `max_tx_fee` ceiling. Only ad-hoc `new_fee > orig_fee` after change reduction. **BUG-3**.                                                                                                                                                                                                                                  | `wallet.rs:816-858`                                       |
| G12  | P0       | Rule 2 (no new unconfirmed inputs) not enforced in wallet — vacuously satisfied because input-adding is not supported, but the day input-adding lands, the rule will not be honored (Core: `new_coin_control.m_min_depth = 1;`). **BUG-4**.                                                                                                                                                                                                         | `wallet.rs:864-874` (absent)                              |
| G13  | P0       | `RbfInsufficientFeeRate` error variant declared but never constructed; dead code per intentional removal at `:2862-2865`. **BUG-5**.                                                                                                                                                                                                                                                                                                                | `mempool.rs:919-920`                                      |
| G15  | P1       | `EstimateFeeRate` helper absent. Core's `feebumper.cpp:119-144`: `feerate = max(old_feerate + 1 sat + max(node_incremental, wallet_incremental), min_feerate)`. Rustoshi uses naive `min_new_fee = orig_fee + incremental_delta`; the new feerate isn't re-derived from `old_feerate + 1 sat`. **BUG-6**.                                                                                                                                            | `wallet.rs:816-822` (no equiv)                            |
| G17  | P1       | `PreconditionChecks` partial: confirmed-tx checked (`:774-778`); RBF-signaling checked (`:779-790`). MISSING: descendant-in-wallet (`feebumper.cpp:25-28`), descendant-in-mempool (`:31-35`), `replaced_by_txid` mapValue lookup (`:42-45`). **BUG-7**.                                                                                                                                                                                              | `wallet.rs:774-790`                                       |
| G19  | P1       | `bump_fee` checks own-input sequences but doesn't call `is_bip125_replaceable` — the ancestor-signaling path is skipped. For self-originated txs this is fine (no foreign ancestors), but the helper shape diverges from Core's `IsRBFOptIn`. **BUG-8**.                                                                                                                                                                                            | `wallet.rs:779-783`                                       |
| G20  | P1       | `EvaluateFeeUp`/`CeilDiv` parity OK for mempool path (`(fee * vsize + 999) / 1000` at `:2870`), but wallet uses **f64 `(vsize as f64 * 1.0).ceil() as u64`** at `wallet.rs:818`. For an exact integer multiple this works; for arbitrary vsize with non-1.0 rates it round-trips through floating-point precision. **BUG-9**.                                                                                                                       | `wallet.rs:818,829`                                       |
| G22  | P1       | Sibling-eviction RBF mirror at `mempool.rs:1751-1769` uses the same `(incremental_relay_fee * vsize + 999) / 1000` math but DOES NOT enforce Rule 5 eviction-cap and does NOT call `check_rbf_rules`. TRUC sibling-eviction path takes a degenerate fast path that may admit replacements which the standard RBF path would reject. **BUG-10**.                                                                                                       | `mempool.rs:1751-1769`                                    |
| G30  | P2       | `MempoolConfig::incremental_relay_fee` comment at `mempool.rs:697-698` claims the unit is "satoshis per virtual byte"; at `mempool.rs:100-101` the same field is documented as "satoshis per 1000 virtual bytes (sat/kvB)". The defaults match the kvB reading; the policy.h:48 const is sat/kvB. The wallet at `:819` claims sat/vB. **Unit-confusion comment-as-confession.** **BUG-11**.                                                            | `mempool.rs:100-101,697-698`, `wallet.rs:817-819`         |

### MISSING (8)

| Gate | Severity | Surface absence                                                                                                                                                                                                                          | Location                |
|------|----------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------|
| G16  | P1       | `WALLET_INCREMENTAL_RELAY_FEE` constant (Core wallet.h:124 = 5000 sat/kvB = 5 sat/vB) absent from rustoshi-wallet. No "future-proofing-against-network-wide-policy" floor. **BUG-12**.                                                     | (no equiv)              |
| G21  | P2       | `calculateCombinedBumpFee` (Core `interfaces/chain.cpp` + Core 27+) absent — wallet doesn't account for descendant fees when computing the bump target. Light wallets that bump a parent whose child is also in mempool under-pay. **BUG-13**.| (no equiv)              |
| G23  | P2       | `max_tx_fee` (Core `wallet.m_default_max_tx_fee`, `feebumper.cpp:109-114`) absent. No upper guard against a misconfigured `-maxtxfee`. **BUG-14**.                                                                                          | (no equiv)              |
| G25  | P2       | `getrawmempool verbose.bip125_replaceable` is wired (`server.rs:7018`), but `gettransaction` output's `bip125_replaceable` field is MISSING in the wallet RPC layer. **BUG-15**.                                                              | `rpc/wallet.rs` (absent) |
| G26  | P2       | `ImprovesFeerateDiagram` (Core 27+ cluster-mempool gate, `rbf.cpp:127-140`) explicitly disclaimed at `mempool.rs:2765-2766`. Once cluster mempool lands, Rule 3+4 are *replaced* by the diagram check; this audit notes the absence. **BUG-16**. | (no equiv, deferred)    |
| G27  | P3       | `EntriesAndTxidsDisjoint` (Core `policy/rbf.cpp:85-98`) is open-coded inline at `mempool.rs:2844-2849` rather than factored as a helper, so it cannot be reused by the TRUC sibling-eviction path (G22 / BUG-10 makes this concrete). **BUG-17**. | `mempool.rs:2844-2849` |
| G28  | P3       | `RBFTransactionState` enum (Core `rbf.h:29-36`: `UNKNOWN`/`REPLACEABLE_BIP125`/`FINAL`) MISSING. Rustoshi uses a `bool` from `is_bip125_replaceable`; the three-state distinction (UNKNOWN if tx not in mempool) is collapsed. **BUG-18**.    | (no equiv)              |
| G29  | P3       | `IsRBFOptInEmptyMempool` helper (Core `rbf.cpp:52-56`) absent. Rustoshi falls back to nothing — callers that want "is this replaceable *outside* a mempool context?" must reimplement. Affects fee-estimation UIs. **BUG-19**.               | (no equiv)              |

## Bug catalogue

### P0-CDIV (2)

- **BUG-1 [P0-CDIV] / G2** — Wallet hardcodes 1 sat/vB
  incremental, ignoring `WALLET_INCREMENTAL_RELAY_FEE = 5 sat/vB`.
  Every wallet-built replacement that the local mempool accepts will
  be rejected by Core peers with the default
  `WALLET_INCREMENTAL_RELAY_FEE = 5000`. Wallet-relay path diverges
  from peer-relay path. Fix: replace `INCREMENTAL_FEE_RATE` constant
  at `wallet.rs:817` with
  `max(MempoolConfig.incremental_relay_fee / 1000.0,
       WALLET_INCREMENTAL_RELAY_FEE_SAT_PER_VBYTE)`,
  where the latter is a new `pub const = 5.0`.

- **BUG-2 [P0-CDIV] / G10** — Wallet bumpfee never reads
  `MempoolConfig::incremental_relay_fee`. The constant is a
  compile-time `f64`. Operator override is silently dropped. Fix:
  plumb `&MempoolConfig` through `Wallet::build_bumped_tx` (matching
  how Core wires `wallet.chain().relayIncrementalFee()`).

### P0 (3)

- **BUG-3 [P0] / G11** — `CheckFeeRate` 5-check Core-parity guard
  MISSING. No mempool-min-fee guard, no `combined_bump_fee`, no
  `GetRequiredFee` floor, no `max_tx_fee` ceiling. Wallet builds
  out-of-range replacements.

- **BUG-4 [P0] / G12** — Rule 2 (no new unconfirmed inputs) not
  enforceable in wallet (vacuously OK because input-adding absent,
  but minefield).

- **BUG-5 [P0] / G13** — Dead error variant `RbfInsufficientFeeRate`
  at `mempool.rs:920`. Per intentional comment-removal at
  `:2862-2865`. Dead-helper-at-call-site pattern.

### P1 (6)

- **BUG-6 [P1] / G15** — `EstimateFeeRate` helper absent in wallet.
- **BUG-7 [P1] / G17** — `PreconditionChecks` half-present.
- **BUG-8 [P1] / G19** — `bump_fee` skips ancestor-signaling check.
- **BUG-9 [P1] / G20** — `EvaluateFeeUp` parity uses f64 in wallet.
- **BUG-10 [P1] / G22** — TRUC sibling-eviction mirror doesn't go
  through `check_rbf_rules` (no Rule 5 cap, no full check).
- **BUG-12 [P1] / G16** — `WALLET_INCREMENTAL_RELAY_FEE` constant
  absent in rustoshi-wallet.

### P2 (5)

- **BUG-11 [P2] / G30** — Unit-confusion comment-as-confession on
  `incremental_relay_fee` (kvB vs vB documented inconsistently
  across `:100-101`, `:697-698`, `wallet.rs:817-819`).
- **BUG-13 [P2] / G21** — `calculateCombinedBumpFee` (descendant-
  aware bump fee) absent.
- **BUG-14 [P2] / G23** — `max_tx_fee` ceiling absent.
- **BUG-15 [P2] / G25** — `gettransaction.bip125_replaceable` field
  not surfaced in wallet RPC.
- **BUG-16 [P2] / G26** — `ImprovesFeerateDiagram` cluster-mempool
  gate disclaimed (deferred).

### P3 (3)

- **BUG-17 [P3] / G27** — `EntriesAndTxidsDisjoint` open-coded
  rather than factored as a helper.
- **BUG-18 [P3] / G28** — `RBFTransactionState` enum collapses to
  `bool` (`UNKNOWN`/`REPLACEABLE_BIP125`/`FINAL` distinction lost).
- **BUG-19 [P3] / G29** — `IsRBFOptInEmptyMempool` helper absent.

## Patterns observed

1. **"Audit framework requires byte-exact, not naive new>old."**
   Direct echo of W129 BUG-3 (CFeeRate `EvaluateFeeUp` rounds up,
   not truncates) at a different code layer. Rustoshi gets the
   mempool path right (+999/1000 ceiling arithmetic) and the wallet
   path wrong (f64 ceil with a hardcoded constant). The same numeric
   invariant has two implementations of different fidelity.

2. **"Dead-helper-at-call-site" — extended to dead-error-variant.**
   `RbfInsufficientFeeRate` was intentionally removed from the
   construction site, but the variant remained in the error enum.
   34-wave streak's universal pattern, now with a third sub-shape:
   "the dead site is the *exception*, not the *function*."

3. **"Minefield bug" (BUG-4).** Code is currently correct only
   because the adjacent code is incomplete. Audit pins it now so
   that the day input-adding lands, the regression test fires
   *before* the gap surfaces in production.

4. **"Wallet path vs relay path divergence."** Rustoshi's wallet
   builds replacements at a fee floor strictly below what any Core
   peer's wallet builds replacements at. The local mempool accepts;
   the network rejects. Operator visibility into this gap is zero
   (no log message correlates the two paths). This pattern recurs
   across W118/W119/W120: when wallet and mempool share an invariant
   that comes from different code paths, audit must verify the two
   paths agree at runtime, not just at the constant table.

5. **Comment-as-confession recurrence (BUG-11).** Three sites
   document `incremental_relay_fee` units differently (sat/kvB,
   sat/vB, plain "satoshis"). W129 had the same shape with
   `long_term_feerate`. Persistent fleet-wide pattern.

## Cross-wave references

- **W118 Wallet fleet audit (BUG-2 / BUG-3 / BUG-14)**: closed by
  FIX-61 (`bumpfee` + `psbtbumpfee` RPC surfaces wired). W130 audits
  the *internals* of the closure, which is where Rule 3 parity
  drift hides.
- **W120 mempool RBF (BUG-9 prioritise / BUG-10 modified fee)**:
  FIX-72 closed `get_modified_fee` propagation into Rule 3 fee
  accumulation. W130 builds on the same code paths
  (`mempool.rs:2811,2818`).
- **W129 Coin selection (BUG-1 long-term feerate scale mismatch /
  BUG-13 bumpfee never re-runs coin selection)**: structurally
  adjacent. W129 BUG-13 = W130 BUG-4's input-adding precondition.
  The two audits compose.
- **W129 BUG-3 CFeeRate truncate-vs-ceil (Core `feerate.cpp`)**:
  W130 BUG-9 is the wallet-layer instance of the same numeric
  invariant.
- **W122 BIP-158 codec ("test-comment-as-confession")**: BUG-11
  unit-confusion comment-as-confession is the same pattern at a
  different layer (RBF feerate unit instead of GCS byte-order).
- **W125 RPC error parity (BUG-3 RPC_INVALID_PARAMETER mass-
  divergence)**: BUG-15 (`gettransaction.bip125_replaceable`
  absent) is a sibling RPC-surface gap.
