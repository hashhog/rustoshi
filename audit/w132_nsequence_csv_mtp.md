# W132 — BIP-68 nSequence / BIP-112 OP_CSV / BIP-113 MTP audit (rustoshi)

**Wave:** W132 — BIP-68 relative locktime / BIP-112 OP_CHECKSEQUENCEVERIFY /
BIP-113 Median-Time-Past as lockTime cutoff (DISCOVERY)
**Date:** 2026-05-17
**Audit subject:** rustoshi's nSequence / OP_CSV / MTP consensus surface:
- `crates/consensus/src/validation.rs` —
  - `calculate_sequence_locks` (lines 1292-1366)
  - `check_sequence_locks` (lines 1384-1394)
  - `connect_block_with_sequence_locks` (lines 1539-1790, BIP-113
    IsFinalTx gate and BIP-68 enforcement gate)
  - `is_final_tx` (validation copy at line 1050; `u32` cutoff)
  - `SequenceLockContext` trait (line 1267)
  - `NullSequenceLockContext` `#[cfg(test)]` stub (line 1515)
  - `TransactionSignatureChecker::check_sequence` (line 2526)
  - `TransactionSignatureChecker::check_locktime` (line 2490)
- `crates/consensus/src/block_template.rs` —
  - `is_final_tx` production copy (line 201; `i64` cutoff)
  - `SEQUENCE_FINAL = 0xFFFFFFFF`, `MAX_SEQUENCE_NONFINAL = 0xFFFFFFFE`
- `crates/consensus/src/script/interpreter.rs` —
  - OP_CHECKSEQUENCEVERIFY dispatch (lines 1952-1972)
  - `SEQUENCE_LOCKTIME_DISABLE_FLAG`/`TYPE_FLAG`/`MASK` constants
    (lines 59-61)
- `crates/consensus/src/mempool.rs` —
  - `MempoolSeqLockCtx` (lines 51-74)
  - BIP-113 IsFinalTx gate at mempool admit (line 1420)
  - BIP-68 SequenceLocks gate at mempool admit (line 1668)
- `crates/consensus/src/chain_state.rs` —
  - `ChainStateNullSeqContext` (lines 946-952) — production
    `SequenceLockContext` impl
  - `compute_mtp` / `compute_mtp_via_get_block` (lines 806, 855)
  - `process_block` → `connect_block_with_sequence_locks` wiring
    (line 489 with `null_seq_context = ChainStateNullSeqContext`,
    line 514 passes `prev_block_mtp`).
- `crates/consensus/src/params.rs` —
  - `SEQUENCE_LOCKTIME_DISABLE_FLAG = 1 << 31` (line 237)
  - `SEQUENCE_LOCKTIME_TYPE_FLAG = 1 << 22` (line 240)
  - `SEQUENCE_LOCKTIME_MASK = 0x0000_ffff` (line 243)
  - `LOCKTIME_THRESHOLD = 500_000_000` (line 234)
  - `MEDIAN_TIME_PAST_WINDOW = 11` (line 216)
  - `csv_height` per-network (mainnet 419_328 at line 575)

**References:**
- `bitcoin-core/src/consensus/tx_verify.cpp:17-37` — `IsFinalTx`.
- `bitcoin-core/src/consensus/tx_verify.cpp:39-95` —
  `CalculateSequenceLocks`.
- `bitcoin-core/src/consensus/tx_verify.cpp:97-105` —
  `EvaluateSequenceLocks`.
- `bitcoin-core/src/consensus/tx_verify.cpp:107-110` — `SequenceLocks`.
- `bitcoin-core/src/script/interpreter.cpp:561-593` — OP_CSV opcode
  handler.
- `bitcoin-core/src/script/interpreter.cpp:1782-1826` —
  `CheckSequence` (BIP-112 input-vs-stack comparison).
- `bitcoin-core/src/chain.h:225-245` — `CBlockIndex::GetMedianTimePast`
  (`nMedianTimeSpan = 11`).
- `bitcoin-core/src/validation.cpp:147-167` — `CheckFinalTxAtTip`
  (BIP-113 cutoff = parent MTP).
- `bitcoin-core/src/validation.cpp:201-244` —
  `CalculateLockPointsAtTip`.
- `bitcoin-core/src/validation.cpp:246-262` — `CheckSequenceLocksAtTip`.
- `bitcoin-core/src/validation.cpp:2478-2562` — ConnectBlock BIP-68
  enforcement (`SequenceLocks(tx, nLockTimeFlags, prevheights,
  *pindex)` at :2557 with `bad-txns-nonfinal`).
- `bitcoin-core/src/validation.cpp:4129-4149` — `ContextualCheckBlock`
  BIP-113 path (`nLockTimeCutoff = pindexPrev->GetMedianTimePast()`).
- `bitcoin-core/src/policy/policy.h:138` —
  `STANDARD_LOCKTIME_VERIFY_FLAGS = LOCKTIME_VERIFY_SEQUENCE`.
- `bitcoin-core/src/primitives/transaction.h:70-114` — constants
  (`SEQUENCE_FINAL`, `MAX_SEQUENCE_NONFINAL`,
  `SEQUENCE_LOCKTIME_DISABLE_FLAG`, `SEQUENCE_LOCKTIME_TYPE_FLAG`,
  `SEQUENCE_LOCKTIME_MASK`, `SEQUENCE_LOCKTIME_GRANULARITY = 9`).
- BIPs **68**, **112**, **113**.

**Production code changes:** 0 (pure audit).
**Test file:** `crates/consensus/tests/test_w132_nsequence_csv_mtp.rs`
— 30 gates, PASS regression pins + `#[ignore]`-pinned BUG-N stubs.

## Why this matters

BIP-68/112/113 are bundled into the CSV soft-fork (BIP-9 bit 0,
locked-in 2016-07-04 at h=419,328). Together they are the consensus
contract for **relative locktime** (the technology underpinning
Lightning, vaults, time-locked HTLCs) and the **monotonic-time
cutoff** (replacing wall-clock `block.GetBlockTime()` with the
median-of-11 anti-grinding cutoff).

A divergence in any of:

1. **BIP-68 height-vs-time-bit decoding** (type-flag at bit 22, mask
   = 0xffff, granularity = 2^9 seconds)
2. **BIP-68 SequenceLocks enforcement gating** (tx.version >= 2 AND
   CSV active)
3. **BIP-68 SequenceLocks evaluation** (`min_height >= block.nHeight
   || min_time >= block.pprev->GetMedianTimePast()` — Core uses both
   conditions)
4. **BIP-112 OP_CSV interpreter semantics** (apples-to-apples
   height/time-type comparison, disable-flag short-circuit,
   tx.version >= 2 gate)
5. **BIP-113 MTP-as-cutoff for IsFinalTx** (parent's MTP — *not*
   block.nTime — when CSV active)
6. **`GetMedianTimePast` semantics** (median of 11 prior blocks,
   `pmedian[(pend-pbegin)/2]`, partial-window behaviour for
   genesis-adjacent heights)

produces a mainnet chain split: any v2 tx with a non-trivial
nSequence is a deterministic test vector. **W132 is the highest-risk
audit wave since W127 Taproot — every gate is P0-CONSENSUS unless
explicitly downgraded.**

## Headline findings

- **3 P0-CONSENSUS bugs identified.** Two are direct under-rejection
  consensus splits; one is a code-path gap that masks the first two
  from caller view.

- **BUG-1 (P0-CDIV)** — `connect_block_with_sequence_locks`
  (validation.rs:1781-1789) **enforces only the height-based**
  component of BIP-68 `min_height >= block.nHeight`, and intentionally
  **skips the time-based** component `min_time >= block_mtp`. The
  comment at lines 1750-1779 documents this as an under-rejection bug
  ("an under-rejection / consensus-split bug under a malicious-miner
  scenario"), justifying it by saying "rely on BIP-112 (OP_CSV) inside
  the script interpreter". **That justification is wrong**: BIP-68
  SequenceLocks applies automatically to every v2 input with the
  disable-flag clear, regardless of whether OP_CSV is in any redeem
  script. A v2 tx with `nSequence = 0x00400064` (time-based, 100
  units = 51,200 s) that does *not* invoke OP_CSV will be rejected
  by Core (`bad-txns-nonfinal` at validation.cpp:2558) but accepted
  by rustoshi. Pattern: **comment-as-confession** — the divergence
  is documented in prose and merged anyway. Core ref:
  consensus/tx_verify.cpp:88 (`nMinTime = max(nMinTime, nCoinTime +
  ((seq & MASK) << GRANULARITY) - 1)`) and
  validation.cpp:2557-2559 (block rejection). Severity rationale:
  forks the chain on any time-based BIP-68 input. Production-relevant
  for Lightning channels using time-based hold scripts, HTLC
  refund branches, vaults.

- **BUG-2 (P0-CDIV)** — `ChainStateNullSeqContext`
  (chain_state.rs:946-952) is the **production** `SequenceLockContext`
  passed to `connect_block_with_sequence_locks` from `process_block`
  (chain_state.rs:507) and `reorganize` (chain_state.rs:696). Its
  `get_mtp_at_height` returns `0` unconditionally for every height.
  Even if BUG-1 were fixed and `min_time` enforcement re-enabled,
  this null context would produce `coin_time = 0` and thus
  `min_time = (seq & MASK) << 9 - 1` (a small absolute value, e.g.
  ~51,200 for seq=100). That value compared against
  `block_mtp ≈ 1.7e9` (any post-CSV mainnet block) is *always* false
  → BIP-68 time-locks **silently always pass**. Pattern:
  **engineered-helper-never-wired** — `SequenceLockContext` trait
  exists, `calculate_sequence_locks` honours it, but no production
  `SequenceLockContext` impl walks the block-index/header-store to
  return real MTP-at-historical-height. The `compute_mtp_via_get_block`
  helper (chain_state.rs:855) walks the tip; it does not accept a
  target height. Reach BUG-2's threshold and BUG-1's gate together
  and rustoshi accepts blocks with unsatisfied BIP-68 time-locks.

- **BUG-3 (P0-CDIV)** — `validation::is_final_tx` (validation.rs:1050)
  is **a duplicate function** that shadows `block_template::is_final_tx`
  (block_template.rs:201). Both live in the `consensus` crate. The
  `block_template` copy uses `i64` for `median_time_past`; the
  `validation` copy uses `u32` for `lock_time_cutoff`. Only the
  `block_template` copy is re-exported from `lib.rs:79-82`. The
  `validation` copy is the one actually called from production
  `connect_block_with_sequence_locks` (validation.rs:1569). The
  `u32` cutoff truncates to 0xFFFF_FFFF (~year 2106), so for any
  MTP after 2106-02-07T06:28:15Z the comparison silently overflows.
  This is post-2106 only, so its *current* P0-CDIV grade is
  conservatively **P1** in 2026, but it remains a long-tail
  silent-fork. Pattern: **shadowed-helper-with-narrower-type** —
  two functions of the same name in the same crate, one exported,
  the other actually used. The exported one is not. Adjacent risk:
  a future refactor that consolidates them via `pub use` could
  silently flip the production call to the i64 variant — *that*
  would be byte-identical to Core, fixing the bug but invisibly.

- **BUG-4 (P1)** — `MempoolSeqLockCtx::get_mtp_at_height`
  (mempool.rs:70-74) returns `tip_mtp` for **every** queried
  `coin_height`. The doc-comment claims this is "stricter (it adds
  more to the lock_time value), which may produce false-rejects but
  never false-admits — safe for mempool." That is half-true:
  using `tip_mtp ≈ block_mtp` as `coin_time` makes
  `min_time = block_mtp + ((seq & MASK) << 9) - 1`, which is
  always ≥ `block_mtp` for any positive lock value, so
  `check_sequence_locks` rejects. The result: **every v2 tx with
  a time-based relative locktime is rejected from mempool**, not
  just unsatisfied ones. Pattern: **comment-as-confession** —
  documents that the over-rejection is intentional. Severity: P1
  (mempool-only over-rejection, not consensus, but breaks any wallet
  trying to relay a Lightning HTLC refund or time-based vault
  payment through rustoshi's mempool).

- **BUG-5 (P1)** — `compute_mtp_via_get_block` (chain_state.rs:855-878)
  uses `return 0;` on the first `get_block` miss, **abandoning all
  collected timestamps**. Core's `CBlockIndex::GetMedianTimePast`
  (chain.h:233-245) walks at most `nMedianTimeSpan = 11` ancestors
  via `for (int i = 0; i < nMedianTimeSpan && pindex; i++,
  pindex = pindex->pprev)` — uses *whatever* it could collect.
  rustoshi's *cache-style* `compute_mtp` (chain_state.rs:806-838)
  uses `break;` (collects partial). The two helpers disagree.
  `compute_mtp_via_get_block` is used in the reorg/connect path
  (chain_state.rs:689); a transient block-store miss during reorg
  would feed `prev_block_mtp = 0` to `connect_block_with_sequence_locks`,
  which then uses `0` as the BIP-113 lock_time_cutoff — making every
  time-based-locktime tx final (cutoff=0 < tx.lock_time for any
  time-based tx). Mainnet impact: only on cold-cache reorgs. Genesis-
  adjacent: rustoshi correctly returns 0 (no parent). Pattern:
  **divergent-helper-from-sibling** — two MTP helpers exist with
  different missing-ancestor behaviour.

- **BUG-6 (P2)** — `calculate_sequence_locks` (validation.rs:1320-1322)
  on `input.sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG` *continues*
  without mutating `spent_heights[idx]`. Core
  (consensus/tx_verify.cpp:65-69) does `prevHeights[txinIndex] = 0`
  before `continue`. The mutated `prevHeights` is consumed
  downstream in `CalculateLockPointsAtTip`
  (validation.cpp:230-235) to skip disabled inputs when computing
  `max_input_height` (the lockpoint anchor block). rustoshi does
  not compute any `LockPoints::maxInputBlock` yet, so this is
  **dormant**, but a future LockPoints port would silently include
  disabled inputs in the lockpoint anchor. Pattern:
  **pre-broken-future-port** — the upstream subtlety is missed in
  the helper used by the future port.

- **BUG-7 (P2)** — `is_final_tx` (validation.rs:1050) uses
  `tx.lock_time: u32 < threshold: u32`. Core uses
  `(int64_t)tx.nLockTime < (... ? (int64_t)nBlockHeight :
  nBlockTime)` — both sides int64_t. For block-height locktime
  values both u32 fit. For time-based locktimes (>= 500_000_000),
  `lock_time_cutoff` is taken from `prev_block_mtp: u32` which
  overflows in 2106. Same long-tail issue as BUG-3 (overlaps).
  Severity: P2 (sub-aspect of BUG-3, no fresh consensus impact
  until 2106).

- **BUG-8 (P2)** — `script_flags_for_height` (validation.rs:2342-2365)
  gates BIP-112/CSV via `height >= params.csv_height` (a static
  height). Core gates via `DeploymentActiveAt(*pindex, m_chainman,
  Consensus::DEPLOYMENT_CSV)` — the BIP-9 versionbits state
  machine. Mainnet activation height (419,328) is hard-coded, so
  *on mainnet* the two are byte-identical. On any future deployment
  that uses BIP-9 (e.g. signet custom params), the static path is
  divergent. `is_deployment_active` (versionbits.rs:523) exists,
  is fully implemented, has test coverage — but is **never called
  from production**. Pattern: **engineered-helper-never-wired**
  (same as BUG-2). Severity: P2 (mainnet/testnet4/regtest hard-coded
  heights are byte-correct; signet/custom networks would diverge).

- **BUG-9 (P3)** — `check_sequence_locks` (validation.rs:1384-1394)
  is **dead code from the production block-validation path**.
  `connect_block_with_sequence_locks` (validation.rs:1787) does its
  own `locks.min_height >= height as i32` check inline (skipping
  `min_time` per BUG-1) and does NOT call `check_sequence_locks`.
  The exported helper is only consumed from the mempool path
  (mempool.rs:1682). Re-reading `check_sequence_locks` shows it
  is byte-correct against Core's `EvaluateSequenceLocks`. Risk: a
  future fix for BUG-1 might forget the helper exists and re-derive
  the check, perpetuating BUG-1. Pattern: **dead-helper-at-call-site**.

- **BUG-10 (P3)** — `contextual_check_block` (validation.rs:1079-1102)
  does NOT call `is_final_tx` for every tx in the block. Core's
  ContextualCheckBlock (validation.cpp:4144-4148) does. The
  equivalent check is performed *inside*
  `connect_block_with_sequence_locks` (validation.rs:1568-1572),
  which runs immediately after `contextual_check_block` in
  `process_block` (chain_state.rs:489+508). Net effect: the check
  *does* run before any UTXO mutation, just from a different
  function. Cosmetic / architectural-divergence only. Pattern:
  **same-check-different-function-than-core** — defensive against
  future caller re-arrangement only.

- **BUG-11 (P3)** — `contextual_check_block_header`
  (validation.rs:914-955) is the only production caller of the
  `ChainContext::get_median_time_past` trait method (validation.rs:927)
  — and `contextual_check_block_header` itself is **dead code**.
  `w97_accept_block_gates.rs:192` documents the gap as
  G7-ignored: "rustoshi has no production caller of
  `contextual_check_block_header`". BIP-113 block-timestamp >
  MTP gate is enforced via a different path in reorg
  (chain_state.rs:693). Pattern: **dead-defensive-helper**. Same
  flavour as BUG-9, BUG-10.

- **BUG-12 (P3)** — `compute_mtp_via_get_block` is invoked on the
  reorg/connect path (chain_state.rs:689) but **not on the
  `process_block` happy path**: `process_block_inner`
  (chain_state.rs:514) calls `connect_block_with_sequence_locks`
  with a `prev_block_mtp` argument **that is supplied by an earlier
  caller** (the closure that computed MTP off the parent). Inspection
  shows the actual call site (chain_state.rs:413, `process_block`)
  passes a `prev_block_mtp` it computed via `compute_mtp_via_get_block`
  earlier (matches the reorg path). So the same-helper-different-arity
  surface stays consistent, just confusingly threaded. Cosmetic.

- **BUG-13 (P3)** — `validation::is_final_tx`'s third parameter is
  named `lock_time_cutoff: u32` but used as either a block height
  (when `tx.lock_time < LOCKTIME_THRESHOLD`) **OR** an MTP timestamp
  (when `tx.lock_time >= LOCKTIME_THRESHOLD`). The caller
  (validation.rs:1563-1567) overloads it: passes `prev_block_mtp`
  when CSV active, `block.header.timestamp` otherwise. The block
  timestamp is *the actual block's* time, not the parent's. For
  the pre-CSV branch this matches Core's
  `block.GetBlockTime()` (validation.cpp:4140-4142). Correct. The
  parameter name is misleading though — should be
  `cutoff: i64` (and `is_final_tx` itself should use `i64`).

## Gate summary (30/30)

| # | Surface | Status | Code | Severity |
|---|---------|--------|------|----------|
| G1  | `SEQUENCE_LOCKTIME_DISABLE_FLAG = 1 << 31` constant | OK | — | — |
| G2  | `SEQUENCE_LOCKTIME_TYPE_FLAG = 1 << 22` constant | OK | — | — |
| G3  | `SEQUENCE_LOCKTIME_MASK = 0x0000_ffff` constant | OK | — | — |
| G4  | `SEQUENCE_LOCKTIME_GRANULARITY = 9` (= 512 s) | OK | — | — |
| G5  | `SEQUENCE_FINAL = 0xFFFF_FFFF` constant | OK | — | — |
| G6  | `MAX_SEQUENCE_NONFINAL = 0xFFFF_FFFE` constant | OK | — | — |
| G7  | `LOCKTIME_THRESHOLD = 500_000_000` | OK | — | — |
| G8  | `MEDIAN_TIME_PAST_WINDOW = 11` | OK | — | — |
| G9  | `params.csv_height = 419_328` (mainnet) | OK | — | — |
| G10 | BIP-68 disable-flag short-circuit in `calculate_sequence_locks` | OK | — | — |
| G11 | BIP-68 type-flag time-vs-height branching | OK | — | — |
| G12 | BIP-68 value masking with `MASK = 0xffff` | OK | — | — |
| G13 | BIP-68 height-based `nMinHeight` accumulation | OK | — | — |
| G14 | BIP-68 time-based `nMinTime` accumulation in `calculate_sequence_locks` | OK | — | — |
| G15 | BIP-68 `enforce_bip68 = tx.version >= 2 AND CSV active` gating | OK | — | — |
| G16 | BIP-68 SequenceLocks block-acceptance gate uses BOTH `min_height` AND `min_time` | **BUG-1** | validation.rs:1781-1789 | **P0-CDIV** |
| G17 | Production `SequenceLockContext` impl walks block-index for real MTP-at-height | **BUG-2** | chain_state.rs:946-952 | **P0-CDIV** |
| G18 | `is_final_tx` cutoff parameter type is `i64` (matches Core int64_t) | **BUG-3** | validation.rs:1050 (u32 used in production); block_template.rs:201 (i64 not exported as the production one) | **P0-CDIV** (2106 long-tail; today P1) |
| G19 | Mempool `SequenceLockContext` returns MTP-at-coin-height-1 | **BUG-4** | mempool.rs:70-74 | **P1** |
| G20 | `compute_mtp_via_get_block` uses partial collection on missing ancestor | **BUG-5** | chain_state.rs:855-878 | **P1** |
| G21 | BIP-68 disable-flag mutates `prevHeights[idx]` (LockPoints maxInputBlock anchor) | **BUG-6** | validation.rs:1320-1322 | **P2** (dormant) |
| G22 | BIP-113 IsFinalTx cutoff uses `int64_t` MTP comparison (2106-proof) | **BUG-7** | validation.rs:1050 | **P2** |
| G23 | BIP-112/CSV soft-fork gating via BIP-9 `DeploymentActiveAt` (versionbits-aware) | **BUG-8** | validation.rs:2356 | **P2** (mainnet OK) |
| G24 | `check_sequence_locks` called from block validation | **BUG-9** | validation.rs:1787 (inline) | **P3** (dead helper) |
| G25 | `is_final_tx` called from `contextual_check_block` (not delegated to `connect_block`) | **BUG-10** | validation.rs:1079 | **P3** (same effect) |
| G26 | `contextual_check_block_header` wired into production header-accept path | **BUG-11** | validation.rs:914 (dead code) | **P3** |
| G27 | OP_CSV opcode handler: disable-flag short-circuit (treat as NOP) | OK | interpreter.rs:1966-1971 | — |
| G28 | OP_CSV opcode handler: negative sequence reject | OK | interpreter.rs:1962 | — |
| G29 | OP_CSV `CheckSequence` apples-to-apples height/time-type comparison | OK | validation.rs:2571-2575 | — |
| G30 | OP_CSV `CheckSequence` v1 tx reject (tx.version < 2) | OK | validation.rs:2546-2548 | — |

Additional cross-cut checks (covered indirectly):
- BIP-113 cutoff = parent MTP when CSV active, block.nTime otherwise
  (validation.rs:1563-1567) — OK.
- Mempool BIP-113 IsFinalTx at admit (mempool.rs:1420) — OK
  (uses `block_template::is_final_tx` with i64).
- OP_CLTV (`check_locktime`) apples-to-apples height/time-type
  comparison and SEQUENCE_FINAL bypass-blocker (validation.rs:2506-2520)
  — OK (out-of-scope but adjacent).
- 5-byte CScriptNum max for OP_CSV operand
  (interpreter.rs:1961 `LOCKTIME_MAX_NUM_SIZE = 5`) — OK.
- `verify_minimaldata` for OP_CSV: enforced only when policy flag is
  on (mempool `standard_flags`), not consensus (validation.rs:2342-2365)
  — OK, matches Core MANDATORY_VERIFY vs STANDARD_VERIFY split.

## Cross-cutting notes

### Why BUG-1 and BUG-2 together produce a fork

A single v2 tx is enough:

```
tx.version = 2
tx.inputs[0].sequence = 0x0040_0001  // type-flag set, lock = 1 unit = 512s
tx.inputs[0].prevout = <some UTXO at height H>
tx.lock_time = 0
```

Spent UTXO `coin_height = H` mined at chain MTP T0. Block being
validated has MTP T_block.

- Core: `nCoinTime = block.GetAncestor(H-1)->GetMedianTimePast() ≈
  T0_minus_some_seconds`. `nMinTime = T0 + 512 - 1`. Accept iff
  `T_block > T0 + 511`. If miner publishes early (`T_block ≤ T0 +
  511`), Core rejects with `bad-txns-nonfinal`.
- rustoshi: BUG-1 skips the `min_time` check entirely. Even with
  `T_block == T0 + 1` (clearly unsatisfied), `min_height = -1`
  (no height lock), so `min_height >= block.nHeight` is false →
  accept.

Result: any malicious miner can mine a block including a tx with
unsatisfied time-based BIP-68. Core nodes reject the block;
rustoshi accepts → chain split.

The bug is documented with a long apology in code comments. The
self-aware confession "an under-rejection / consensus-split bug
under a malicious-miner scenario" makes this a "test-comment-as-
confession" exemplar: every text-search for that phrase in 2026 was
the same wave (W122 blockbrew BIP-158 codec, W120 ouroboros mempool
RBF, here). **The pattern is: rustoshi inherited the same comment
from clearbit's matching resolution** (cited in the comment as
`clearbit 44454c1`, `src/validation.zig`). Cross-impl propagation
of a documented bug.

### Why BUG-3 is subtle

The `is_final_tx` name lives in **two** modules with **two**
signatures:

| Location                                    | Sig                                                       | Caller                                                  |
|---------------------------------------------|-----------------------------------------------------------|---------------------------------------------------------|
| `validation.rs:1050`                        | `fn(tx, block_height: u32, lock_time_cutoff: u32) -> bool` | `connect_block_with_sequence_locks` (validation.rs:1569) |
| `block_template.rs:201`                     | `fn(tx, block_height: u32, median_time_past: i64) -> bool` | `mempool.rs:1420`, `block_template.rs:333, 434`         |

`lib.rs:80` re-exports the **block_template** version as
`rustoshi_consensus::is_final_tx`. So an external caller using the
public API gets the i64 (correct) variant. The internal validation
path uses the u32 (BUG-3) variant. The two will diverge for any
MTP > u32::MAX (~year 2106).

### Why MempoolSeqLockCtx is non-trivially broken (BUG-4)

The comment says "stricter" — and that's true — but it makes
**every** v2 time-based-locktime tx reject. The mempool path is
explicitly walking spent_heights from confirmed UTXOs, so it has
access to a `block_store` lookup that *could* produce real
`MTP@coin_height-1`. None of that wiring happens. Lightning HTLCs
relayed through rustoshi will silently 404.

### Cross-impl pattern echo

BUG-2 (`ChainStateNullSeqContext`) + BUG-8
(`is_deployment_active` never wired) follow the same
**engineered-helper-never-wired** pattern documented across W119
(rustoshi RBF cluster builder), W121 (ouroboros cfheaders zero-
fallback), W120 nimrod RBF Rule 8. Pattern depth: ~12 closures
across recent waves.

### Why no fix is in this audit

W132 is **discovery-only** per the brief. The three P0-CDIV findings
collectively need a single coordinated fix: (a) a `BlockStoreSeqLockCtx`
that walks `params.headers_db.get_header(hash_at_height(h-1)).timestamp`
for the MTP-window, (b) re-enabling the `min_time` check at
validation.rs:1787, (c) unifying the two `is_final_tx` copies on
an `i64` cutoff. Each is single-impl scope; together they form a
clean follow-on FIX-NN candidate.

## References to W127 / W118 etc.

- Pattern `comment-as-confession` documented in
  W120 (ouroboros mempool RBF), W122 (blockbrew BIP-158), here:
  three impls in two months.
- Pattern `engineered-helper-never-wired` documented in
  W119 (rustoshi RBF cluster builder), W121 (BIP-157 P2P
  fleet-wide), here.
- Pattern `dead-helper-at-call-site` documented across
  W118 wallet (10 closures), W120 mempool (5 closures), here
  (BUG-9, BUG-10, BUG-11 — 3 in this audit alone).

## Future work (not in W132 scope)

- Wire a real `SequenceLockContext` impl (BUG-2). Likely path:
  `BlockStoreSeqLockCtx { headers: Arc<HeaderStore> }` whose
  `get_mtp_at_height` walks the header-store backwards from
  `headers.get_hash_at_height(h)`. Cache via the existing
  `mtp_cache` on `ChainState`.
- Re-enable `min_time` check (BUG-1). Single-line at
  validation.rs:1787: change `if locks.min_height >= height as i32`
  to `if !check_sequence_locks(&locks, height, prev_block_mtp as i64)`.
- Consolidate `is_final_tx` (BUG-3). Delete validation.rs:1050,
  use `block_template::is_final_tx` everywhere, change
  `lock_time_cutoff` param from `u32` to `i64`.
- Wire BIP-9 versionbits state into validation (BUG-8). Production
  callers of `script_flags_for_height` and
  `connect_block_with_sequence_locks` already have access to the
  chain state needed to call `is_deployment_active`.
