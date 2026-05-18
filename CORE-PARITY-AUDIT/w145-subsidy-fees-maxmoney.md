# W145 — Coinbase + subsidy + fees + MAX_MONEY invariants audit (rustoshi)

**Wave:** W145 — Coinbase subsidy / fees / MAX_MONEY (DISCOVERY)
**Date:** 2026-05-18
**Audit subject:** the rustoshi consensus arithmetic surface around block
subsidy, fee accumulation, MAX_MONEY MoneyRange invariants, COINBASE_MATURITY,
and CVE-2018-17144 duplicate-input detection.

**Files audited:**
- `crates/consensus/src/params.rs` — `block_subsidy` (298–304),
  `SUBSIDY_HALVING_INTERVAL=210_000` (228), `INITIAL_SUBSIDY=50*COIN` (231),
  `COINBASE_MATURITY=100` (80), `MAX_MONEY=21M*COIN` (83), `COIN=1e8` (86),
  per-network chain params (`mainnet` 538-, `testnet3` 740-, `testnet4` 787-,
  `signet` 879-, `regtest` 924-).
- `crates/consensus/src/validation.rs` — `check_transaction` (376),
  `connect_block_with_sequence_locks` (1539), `coinbase_value` /
  `max_coinbase_value` gate (1893–1903), `total_fees` accumulator
  (1841–1844), per-input MoneyRange (1706–1717), `COINBASE_MATURITY`
  enforcement (1697–1704), `output_sum` raw `.sum()` (1829),
  `CoinEntry` struct (1402).
- `crates/consensus/src/mempool.rs` — `add_transaction` (~1368),
  per-input MoneyRange (1471–1479), `saturating_sub` coinbase-age (1525),
  `output_sum` (1687, 4039, 4218), unchecked `input_sum += coin.value`
  (4032, 4205, 4209), W96 fee accumulation.
- `crates/consensus/src/block_template.rs` — `build_coinbase_tx` (558),
  unchecked `coinbase_value = subsidy + total_fees` (454).
- `crates/storage/src/indexes/coinstatsindex.rs` — duplicate
  `get_block_subsidy(height)` (293–303), `total_unspendable` raw add chain
  (112–117), `CoinStatsEntry::genesis` (84–93).
- `crates/storage/src/indexes/mod.rs` — `pub use coinstatsindex::get_block_subsidy`
  (33) — exports the parallel subsidy fn.
- `crates/storage/src/block_store.rs` — `CoinEntry` (124–133).
- `crates/storage/src/utxo_cache.rs` — `Coin` (59–66),
  `Coin::from_entry`/`to_entry` (98–118).
- `crates/wallet/src/wallet.rs` — duplicate `COINBASE_MATURITY` (66),
  `is_mature` height add (438).

**Bitcoin Core references:**
- `bitcoin-core/src/validation.cpp`:
  - `GetBlockSubsidy` (1839–1850) — `halvings = nHeight / interval; if
    (halvings >= 64) return 0; nSubsidy = 50 * COIN; nSubsidy >>=
    halvings;`. The `>= 64` guard avoids C++ undefined right-shift.
  - `ConnectBlock` subsidy check (2610–2614) —
    `blockReward = nFees + GetBlockSubsidy(); if (block.vtx[0]->GetValueOut()
    > blockReward) state.Invalid(..., "bad-cb-amount", ...)`.
  - Per-tx fee accumulator (2542–2547) — `nFees += txfee; if
    (!MoneyRange(nFees)) "bad-txns-accumulated-fee-outofrange"`.
- `bitcoin-core/src/consensus/amount.h`:
  - `COIN = 100000000` (15),
  - `MAX_MONEY = 21000000 * COIN` (26),
  - `MoneyRange(nValue) := nValue >= 0 && nValue <= MAX_MONEY` (27).
- `bitcoin-core/src/consensus/consensus.h`:
  - `COINBASE_MATURITY = 100` (19).
- `bitcoin-core/src/consensus/tx_check.cpp`:
  - `CheckTransaction` — `bad-txns-vout-negative` (28),
    `bad-txns-vout-toolarge` (30), `bad-txns-txouttotal-toolarge` (33),
    `bad-txns-inputs-duplicate` (CVE-2018-17144, 41–44),
    `bad-cb-length` (49–50).
- `bitcoin-core/src/consensus/tx_verify.cpp`:
  - `CheckTxInputs` (164–214) — `COINBASE_MATURITY` gate via signed
    `nSpendHeight - coin.nHeight < COINBASE_MATURITY` (179–181),
    `MoneyRange(coin.out.nValue)` per-input + `MoneyRange(nValueIn)`
    accumulator (185–188), `bad-txns-in-belowout` (196–198),
    `bad-txns-fee-outofrange` (203–209).
- `bitcoin-core/src/kernel/chainparams.cpp`:
  - `nSubsidyHalvingInterval = 210_000` (mainnet 84, testnet3 209,
    testnet4 310, signet 454),
  - `nSubsidyHalvingInterval = 150` (regtest 535).

**BIPs / CVEs covered:** CVE-2010-5139 (tx output overflow),
CVE-2018-17144 (duplicate-input inflation), BIP-30 (duplicate coinbase
suppression — only the subsidy-emission cross-section).

**Production code changes:** 0 (pure audit).

## Why this matters

These four invariants are the **monetary load-bearing wall** of Bitcoin
consensus. Subsidy emits new coins; fees recycle them; MAX_MONEY caps
both per-output and accumulated values; COINBASE_MATURITY prevents the
miner-time-machine attack class. Any divergence here is one of:

1. **Inflation bug** — a malicious miner gets more BTC than Core would
   permit, silently breaking the 21M cap.
2. **Chain split** — rustoshi rejects a block Core accepts (or vice
   versa) at the subsidy boundary, blackholing the rustoshi fleet at
   that height.
3. **DoS / under-rejection** — the same path that should reject
   `bad-cb-amount` panics on integer overflow instead, or silently
   accepts wraparound.

Three failure modes recur in this audit and all three are fleet
patterns documented in MEMORY.md:

1. **Two-pipeline guard.** Two implementations of the same primitive
   coexist. `params::block_subsidy(height, halving_interval)` is the
   live, network-parameterised consensus path; `coinstatsindex::
   get_block_subsidy(height)` is a parallel, hard-coded
   `HALVING_INTERVAL=210_000` copy exported via
   `storage::indexes::get_block_subsidy` but called by no production
   code. Either one is dead-code waiting to be wired (and silently
   diverging on regtest's interval=150), or both should converge on
   the params-aware function. This is the same fleet shape as
   blockbrew's `MaybeSendFeeFilter` zero-callers and clearbit's
   dual-pipeline pattern (W136).

2. **Inconsistent integer-arithmetic defensive depth.** rustoshi mixes
   `checked_add`, `saturating_add`, `saturating_sub`, raw `+`, and
   raw `.sum()` on `u64` money values across paths that all enforce the
   same invariant. Mempool's coinbase-age check uses `saturating_sub`
   (mempool.rs:1525) but ConnectBlock's identical check uses raw `-`
   (validation.rs:1698). Block-template's coinbase value uses raw `+`
   (block_template.rs:454) while ConnectBlock's coinbase cap uses
   `saturating_add` (validation.rs:1894). The raw paths would panic
   in debug builds and silently wrap in release.

3. **`COINBASE_MATURITY` is duplicated as a top-level `const`** in
   `consensus::params::COINBASE_MATURITY = 100` AND
   `wallet::wallet::COINBASE_MATURITY = 100`. The wallet does not
   `use rustoshi_consensus::COINBASE_MATURITY` — it redefines. They
   currently agree but a future fix to consensus that does not
   update the wallet redefinition produces a wallet-vs-validator
   policy disagreement (wallet would refuse to spend coins the
   validator already accepts, or vice versa).

## Audit framework (30 gates / 20 BUGS catalogued)

Gate legend:
- **PASS** — behaviour matches Core (regression pin).
- **BUG-N** — divergence, gap, or arithmetic-safety hazard.

| #   | Behaviour                                                                                       | Status |
|-----|--------------------------------------------------------------------------------------------------|--------|
| G1  | `block_subsidy` halves correctly at h=210_000, 420_000, 630_000                                  | PASS |
| G2  | `block_subsidy` returns 0 after 64 halvings (avoids C++ UB on right-shift)                       | PASS |
| G3  | `block_subsidy` uses `height: u32` and `halving_interval: u32` (semantic: signed vs unsigned)    | BUG-1 |
| G4  | `SUBSIDY_HALVING_INTERVAL=210_000` matches Core mainnet/testnet3/testnet4/signet                 | PASS |
| G5  | Regtest `subsidy_halving_interval = 150`                                                         | PASS |
| G6  | `block_subsidy(h, halving_interval=0)` is safe (no divide-by-zero panic)                         | BUG-2 |
| G7  | Single canonical `block_subsidy` callsite per chain                                              | BUG-3 (two parallel impls) |
| G8  | `INITIAL_SUBSIDY = 50 * COIN`                                                                    | PASS |
| G9  | `MAX_MONEY = 21M * COIN` constant                                                                 | PASS |
| G10 | `CheckTransaction` rejects `nValue > MAX_MONEY` per output (CVE-2010-5139)                       | PASS |
| G11 | `CheckTransaction` rejects total-out > MAX_MONEY via `checked_add` + bound                       | PASS |
| G12 | `CheckTransaction` rejects duplicate inputs (CVE-2018-17144)                                     | PASS |
| G13 | Per-input MoneyRange + accumulator MoneyRange in ConnectBlock                                    | PASS |
| G14 | Coinbase `bad-cb-amount` cap at `block.vtx[0].GetValueOut() > subsidy + nFees`                   | PASS |
| G15 | `coinbase_value` accumulator uses `checked_add` (defensive vs CVE-2010-5139 class)               | PASS |
| G16 | Per-tx `output_sum` in `connect_block_with_sequence_locks` uses checked / bounded arithmetic     | BUG-4 |
| G17 | Per-tx `output_sum` in mempool `add_transaction` uses checked arithmetic                         | BUG-5 |
| G18 | `input_sum += coin.value` in mempool RBF / package paths uses checked arithmetic                 | BUG-6 |
| G19 | `coinbase_value = subsidy + total_fees` in block template uses checked arithmetic                | BUG-7 |
| G20 | `COINBASE_MATURITY` enforced in ConnectBlock                                                     | PASS (but BUG-8 underflow) |
| G21 | `COINBASE_MATURITY` underflow-safe (`height < coin.height` does NOT panic / wrap)                | BUG-8 |
| G22 | `COINBASE_MATURITY` defined once at the consensus boundary                                       | BUG-9 (duplicated in wallet) |
| G23 | `COINBASE_MATURITY` enforced symmetrically in mempool + ConnectBlock                             | BUG-10 (asymmetric defensive depth) |
| G24 | Wallet `is_mature` uses checked add for `utxo.height + COINBASE_MATURITY`                        | BUG-11 |
| G25 | Per-tx fee error uses Core's `bad-txns-fee-outofrange` string                                    | BUG-12 |
| G26 | Block-template `total_fees` accumulator uses checked arithmetic                                  | BUG-13 |
| G27 | `coinbase_value` cap uses `>` (not `>=`) so miner CAN underclaim subsidy (burn fees)             | PASS |
| G28 | `CoinEntry` (one canonical type) shared across storage + consensus                               | BUG-14 (three parallel structs) |
| G29 | `CoinStatsEntry::total_unspendable()` uses checked arithmetic                                    | BUG-15 |
| G30 | RPC `getmininginfo`/`getblockstats` expose subsidy via the canonical fn                          | BUG-16 |

Additional findings outside the gate matrix:
- **BUG-17:** `block_subsidy` signature does not bound check the `>=64`
  guard against `halvings` of u32::MAX (no overflow risk in practice, but
  the divergence-style comment Core has — "Force block reward to zero
  when right shift is undefined" — does not appear here).
- **BUG-18:** `coinbase_value` recomputation in `connect_block_with_sequence_locks`
  uses `try_fold` on the coinbase outputs; if any value is `u64::MAX`
  the fold returns `None` and `unwrap_or(u64::MAX)` is fed into the cap
  comparison. Combined with `saturating_add` on the cap, the wrong
  error message can surface ("bad-cb-amount" with `coinbase_value =
  u64::MAX`) rather than "bad-txns-vout-toolarge" that should have
  caught the malformed coinbase upstream in `CheckTransaction`.
- **BUG-19:** `total_fees.saturating_add(tx_fee)` in the
  `FeesOutOfRange` error path (validation.rs:1844) is used only for the
  *error payload* — Core does not include a number in
  `bad-txns-accumulated-fee-outofrange` and the saturated number is
  misleading to operators reading rejection logs.
- **BUG-20:** `coinstatsindex::CoinStatsEntry` is serialized as JSON
  (`serde_json::to_vec`, coinstatsindex.rs:156) rather than the binary
  on-disk format Core writes for `coinstats.dat`. The total_subsidy and
  unspendable fields are part of the canonical UTXO-set-stats output;
  any future tooling that compares rustoshi's `gettxoutsetinfo` to
  Core's at the byte level will diverge.

## BUGS

### BUG-1 — `block_subsidy` uses `u32` for height; Core uses signed `int`

**Severity:** P3
**File:** `crates/consensus/src/params.rs:298`
**Core ref:** `bitcoin-core/src/validation.cpp:1839` —
              `CAmount GetBlockSubsidy(int nHeight, ...)`

**Description:**
Core uses `int nHeight` (signed 32-bit). Rustoshi uses `u32`. The two
disagree on the boundary case of negative heights, but in practice
`int nHeight` is never negative in any consensus path because the
block index tree is rooted at genesis (h=0). The bigger semantic
divergence is that `u32::MAX / 210_000 = 20457`, well above the `>= 64`
guard, so the function is correct even for `u32::MAX`. Cosmetic / future-
proofing only.

**Excerpt:**
```rust
// params.rs:298
pub fn block_subsidy(height: u32, halving_interval: u32) -> u64 {
    let halvings = height / halving_interval;
    if halvings >= 64 {
        return 0;
    }
    INITIAL_SUBSIDY >> halvings
}
```

**Impact:**
None at runtime. Documents the type-shape divergence between rustoshi's
`u32`-everywhere height and Core's `int`-everywhere height — a long-
standing rustoshi-wide invariant that may surface elsewhere if a future
chain enables negative-height regtest scenarios (vanishingly unlikely).

---

### BUG-2 — `block_subsidy` panics on `halving_interval == 0` (divide-by-zero)

**Severity:** P2
**File:** `crates/consensus/src/params.rs:298-303`
**Core ref:** `bitcoin-core/src/validation.cpp:1841` —
              `int halvings = nHeight / consensusParams.nSubsidyHalvingInterval;`

**Description:**
Rust panics on integer divide-by-zero (it is *defined* to panic, not
UB like C++). If a malformed `ChainParams` ever reaches
`block_subsidy`, the validator process aborts on every block. Core's
C++ behaviour would be UB (an `int / 0` is undefined), so this is
technically *safer than Core*, but it is also a process-crash DoS
primitive if a corrupted on-disk chain params file is ever read at
startup. No existing chain params (mainnet=210000, testnet*=210000,
signet=210000, regtest=150) hit this, but the absence of a sanity
check / `debug_assert!` is the same lack-of-defensive-depth pattern
documented in MEMORY.md.

**Excerpt:**
```rust
// params.rs:298
pub fn block_subsidy(height: u32, halving_interval: u32) -> u64 {
    let halvings = height / halving_interval;   // PANIC if halving_interval == 0
    if halvings >= 64 {
        return 0;
    }
    INITIAL_SUBSIDY >> halvings
}
```

**Impact:**
Process-crash DoS if a corrupted ChainParams ever flows into
`block_subsidy`. Defense-in-depth gap. One-line fix:
`if halving_interval == 0 { return 0; }` at the top.

---

### BUG-3 — Two parallel `block_subsidy` implementations (`params::block_subsidy` + `coinstatsindex::get_block_subsidy`); the second hardcodes `HALVING_INTERVAL=210_000` so it is wrong on regtest

**Severity:** P1
**File:** `crates/storage/src/indexes/coinstatsindex.rs:293-303` (the
parallel copy) — `crates/consensus/src/params.rs:298-303` (the canonical fn)
**Core ref:** Core has exactly one `GetBlockSubsidy` symbol
              (`validation.cpp:1839`) re-used everywhere (UTXO
              statistics, mining info, ConnectBlock cap).

**Description:**
`storage::indexes::coinstatsindex::get_block_subsidy(height: u32) -> u64`
re-implements `block_subsidy` with a hardcoded
`const HALVING_INTERVAL: u32 = 210_000;`. It is exported via
`storage::indexes::mod.rs::pub use coinstatsindex::get_block_subsidy`
and re-exported one more time at the crate boundary. **Grep confirms
zero production callers** (only the in-file `test_block_subsidy` test
references it). Two failure modes:

1. **Dead-code-waiting-to-be-wired.** A future maintainer wiring
   `gettxoutsetinfo` to populate `CoinStatsEntry::total_subsidy` may
   reach for this function — which would silently produce wrong
   subsidy on regtest (the only chain where the divergence shows up,
   because regtest's interval is 150, not 210_000).
2. **Two-pipeline guard fleet pattern.** Fleet-wide pattern
   (W122/W136/W137/W138 cross-cite) where two parallel implementations
   of the same consensus primitive coexist, one with hardcoded
   constants and zero callers, the other parameterised and wired.

**Excerpt:**
```rust
// coinstatsindex.rs:292
/// Block subsidy calculation (50 BTC halving every 210,000 blocks).
pub fn get_block_subsidy(height: u32) -> u64 {
    const INITIAL_SUBSIDY: u64 = 50 * 100_000_000; // 50 BTC in satoshis
    const HALVING_INTERVAL: u32 = 210_000;        // <-- hardcoded; regtest is 150

    let halvings = height / HALVING_INTERVAL;
    if halvings >= 64 {
        return 0;
    }

    INITIAL_SUBSIDY >> halvings
}
```

```rust
// coinstatsindex/mod.rs:33  (the public re-export)
pub use coinstatsindex::{
    CoinStatsEntry, CoinStatsError, CoinStatsIndex,
    get_block_subsidy,   // <-- exported but zero production callers
    get_bogo_size, serialize_coin_for_muhash,
};
```

**Impact:**
On any chain with `subsidy_halving_interval != 210_000` (i.e.,
regtest at 150), any future caller of `storage::indexes::get_block_subsidy`
silently computes the wrong subsidy and any code path that uses it for
**any** assertion (`CoinStatsEntry::total_subsidy`, UTXO supply
auditing) would silently produce wrong numbers on regtest. Today this
is latent because nothing calls it, but the parallel implementation
will outlive the next refactor and surface as a regtest-only chain
split if wired naively. The right fix is to delete the parallel impl
and have `coinstatsindex` call `consensus::params::block_subsidy`
with the params-driven interval.

---

### BUG-4 — `output_sum` in `connect_block_with_sequence_locks` uses raw `.sum()` which silently wraps on u64 overflow

**Severity:** P1 (defensive-depth)
**File:** `crates/consensus/src/validation.rs:1829`
**Core ref:** `bitcoin-core/src/primitives/transaction.h::GetValueOut`
              — throws on `!MoneyRange(nValueOut)` (CVE-2010-5139 fix).

**Description:**
After per-output `MAX_MONEY` is enforced earlier in
`check_transaction` (validation.rs:404, 410), the connect path
re-computes `output_sum` via:

```rust
let output_sum: u64 = tx.outputs.iter().map(|o| o.value).sum();
```

`Iterator::sum::<u64>` for `u64` is implemented via the `Sum` trait and
in release builds **silently wraps on overflow** (it is not `checked_add`).
The structural guarantee that gets us here — `check_transaction` already
bounded `total_out <= MAX_MONEY` (~2.1e15) — assumes the same
`Transaction` instance flows through both functions, which is true on
the happy path. But:

1. **Defensive duplication is the point.** Core wraps every cumulative
   amount in `MoneyRange`. Rustoshi has bounded checked-add at lines
   404-410 (CheckTransaction) but unchecked `.sum()` at the connect-path
   site, breaking the symmetry that's a recurring rustoshi pattern in
   block_template.rs (saturating_add at line 1894) and validation.rs
   (checked_add at line 1714).
2. **Fuzz / synthetic test paths.** Any test that constructs a
   `Transaction` in memory without going through `check_transaction`
   (which is the common pattern for unit tests around connect/disconnect)
   will silently wrap and the rest of the function operates on the
   wrapped sum.

**Excerpt:**
```rust
// validation.rs:1828
        // Calculate output sum
        let output_sum: u64 = tx.outputs.iter().map(|o| o.value).sum();  // <-- silent wrap

        // Inputs must cover outputs (difference is fee)
        if input_sum < output_sum {
            return Err(TxValidationError::InsufficientFunds(input_sum, output_sum).into());
        }
```

**Impact:**
A malformed `Transaction` (constructed in a fuzz / test path that
bypasses `check_transaction`) with `outputs.iter().map(|o|
o.value).sum::<u64>()` wrapping past `u64::MAX` would produce a
small `output_sum`, then `input_sum >= output_sum` trivially holds,
and the fee accumulator drains the real `input_sum` into `tx_fee`.
On the happy path the upstream guard prevents this, but the
defensive-depth gap is real and one-line-fixable
(`checked_sum`-equivalent via `try_fold`).

---

### BUG-5 — Mempool's `output_sum` recomputes the same unchecked `.sum()` (three sites: 1687, 4039, 4218)

**Severity:** P1 (defensive-depth)
**File:** `crates/consensus/src/mempool.rs:1687, 4039, 4218`
**Core ref:** Same as BUG-4 — `GetValueOut` throws on MoneyRange.

**Description:**
Three separate mempool paths (`add_transaction`, package-accept,
TRUC-policy accept) all do
`let output_sum: u64 = tx.outputs.iter().map(|o| o.value).sum();` —
identical unchecked-wrap shape as BUG-4. Because mempool's
`add_transaction` calls `check_transaction` at line 1368, the happy
path is bounded the same way as ConnectBlock. But the **package-accept**
path at line 4039 sums values BEFORE `check_transaction` is invoked on
the package transactions (the loop at 4014–4051 collects metadata
before per-tx validation). A maliciously-crafted package broadcast over
RPC `submitpackage` could feed wrapping values into the package_fee
total which is then used for the RBF feerate comparison.

**Excerpt:**
```rust
// mempool.rs:4030  (the unbounded-input-sum + unbounded-output-sum site)
                if let Some(coin) = utxo_lookup(&input.previous_output) {
                    input_sum += coin.value;     // <-- BUG-6, unchecked
                } else {
                    // Missing input - this will fail when we try to add
                    // Continue for now to calculate what we can
                }
            }

            let output_sum: u64 = tx.outputs.iter().map(|o| o.value).sum();
            let fee = input_sum.saturating_sub(output_sum);
```

**Impact:**
The package_fee / package_vsize feerate that gets used for RBF / TRUC
parent-child enforcement at lines 4044-4045 can be silently wrong. A
synthetic input with `value = u64::MAX` and outputs that sum to
`u64::MAX - 100` would yield `fee = 100` after `saturating_sub`, an
arbitrary fee gift that gets folded into the package's feerate. The
mitigation lives downstream (per-tx checks reject the values), but the
package-level decision is made before the per-tx checks fire.

---

### BUG-6 — Mempool's RBF / package paths use unchecked `input_sum += coin.value` (three sites: 4032, 4205, 4209)

**Severity:** P1 (defensive-depth)
**File:** `crates/consensus/src/mempool.rs:4032, 4205, 4209`
**Core ref:** `bitcoin-core/src/consensus/tx_verify.cpp:185-188` —
              `nValueIn += coin.out.nValue; if (!MoneyRange(nValueIn))
              "bad-txns-inputvalues-outofrange";`

**Description:**
The "W96 gate 11" MoneyRange enforcement at mempool.rs:1471–1479 uses
`checked_add` + filter `<= MAX_MONEY`. But three other mempool paths
that compute `input_sum` use raw `+=`:

```rust
// mempool.rs:4032
                if let Some(coin) = utxo_lookup(&input.previous_output) {
                    input_sum += coin.value;
                } else { ... }
```

```rust
// mempool.rs:4205
                input_sum += parent.tx.outputs[vout].value;
                mempool_parents.insert(*parent_txid);
            } else if let Some(coin) = utxo_lookup(&input.previous_output) {
                prevout_scripts.push(coin.script_pubkey.clone());
                input_sum += coin.value;       // line 4209
```

**Impact:**
Symmetric to BUG-5. Package-accept and TRUC-accept paths compute
`input_sum` and feed it into a `saturating_sub` for fee calculation;
the fee is then used for prioritisation. Same defensive-depth gap
fleet pattern: one impl uses checked, parallel impl uses raw. Easy
fix: replace `+=` with `checked_add().filter(...).ok_or(...)?`
matching the W96 pattern.

---

### BUG-7 — `block_template::build_coinbase_tx` callsite uses raw `subsidy + total_fees`

**Severity:** P2 (defensive-depth on the miner path)
**File:** `crates/consensus/src/block_template.rs:453-454`
**Core ref:** `bitcoin-core/src/node/miner.cpp:172-176` — Core sums
              `nFees` via `nFees += iter->GetFee();` which is bounded
              by per-tx `MoneyRange(txfee)` in CheckTxInputs.

**Description:**
The block template assembler computes the coinbase value as:

```rust
// block_template.rs:452
    // Calculate coinbase value (subsidy + fees)
    let subsidy = block_subsidy(height, params.subsidy_halving_interval);
    let coinbase_value = subsidy + total_fees;       // <-- raw add, can overflow
```

`subsidy` is bounded `<= 50 * COIN = 5e9` (well below `u64::MAX`),
and `total_fees` is accumulated upstream via `total_fees += entry.fee`
(block_template.rs:445) which is itself unchecked. If a corrupted
mempool entry has a synthetic huge `entry.fee` (operator bug,
deserialization mismatch, etc.), the coinbase tx then carries the
wrapped value in `outputs[0].value`.

Asymmetric with the ConnectBlock-side check at validation.rs:1894
which uses `saturating_add`.

**Excerpt:**
```rust
// block_template.rs:445
            total_fees += entry.fee;          // raw +=, unbounded
            total_weight += entry.weight as u64;
...
// block_template.rs:453
    let subsidy = block_subsidy(height, params.subsidy_halving_interval);
    let coinbase_value = subsidy + total_fees;
```

**Impact:**
A block template handed out via `getblocktemplate` can carry a wrong
coinbase value if any mempool entry has an inflated `entry.fee`. The
miner attempting to submit the block then fails block validation at
`bad-cb-amount`, so this does not produce a chain split, but it does
produce a confusing miner-side rejection of a template the same node
just emitted (CR-OPS bug — operator distrust of `getblocktemplate`).

---

### BUG-8 — `COINBASE_MATURITY` check in ConnectBlock uses raw `height - coin.height`; silently wraps if `coin.height > height` (e.g., during reorg or snapshot UTXO with future height)

**Severity:** P0 (consensus arithmetic safety)
**File:** `crates/consensus/src/validation.rs:1698-1703`
**Core ref:** `bitcoin-core/src/consensus/tx_verify.cpp:179` —
              `if (coin.IsCoinBase() && nSpendHeight - coin.nHeight <
              COINBASE_MATURITY)` — Core uses signed `int`, so the
              subtraction is well-defined and a negative result is
              correctly `< COINBASE_MATURITY` (a coinbase from a
              future block is treated as "premature" — correct).

**Description:**
```rust
// validation.rs:1697
            // Check coinbase maturity
            if coin.is_coinbase && height - coin.height < COINBASE_MATURITY {
                return Err(TxValidationError::PrematureCoinbaseSpend(
                    height - coin.height,         // <-- same subtraction, twice
                    COINBASE_MATURITY,
                )
                .into());
            }
```

`height: u32`, `coin.height: u32`. If `coin.height > height` (e.g., a
reorg-induced UTXO state where a snapshot from a higher tip is being
re-walked, or a corrupted UTXO row from a partially-flushed RocksDB
batch), the subtraction:

- **panics in debug builds** (Rust integer overflow check), wedging
  the validator with `attempt to subtract with overflow`.
- **silently wraps to a huge number (~4 billion) in release builds**,
  which is `>= COINBASE_MATURITY=100`, so the maturity check passes
  and the coinbase is treated as mature when it should be rejected.

The **release-build behaviour is the bug**: a corrupted UTXO row's
coinbase becomes spendable from height 0. Compare with mempool.rs:1525
which already does `let age = self.tip_height.saturating_sub(coin.height);` —
mempool already has the safer pattern, validator does not.

**Excerpt (compare with mempool):**
```rust
// mempool.rs:1523  (the safer pattern)
                if coin.is_coinbase {
                    spends_coinbase = true;
                    let age = self.tip_height.saturating_sub(coin.height);
                    if age < COINBASE_MATURITY {
                        return Err(MempoolError::CoinbaseNotMature { ... });
                    }
                }
```

**Impact:**
Defensive-depth gap that could become consensus-relevant under
specific UTXO corruption / reorg snapshot scenarios. The
release-build wrap is the worst case (under-rejection of premature
coinbase spend). Mempool already uses `saturating_sub`; ConnectBlock
must converge. One-line fix.

---

### BUG-9 — `COINBASE_MATURITY` defined twice (`consensus::params:80` AND `wallet::wallet:66`)

**Severity:** P2
**File:** `crates/consensus/src/params.rs:80` (canonical),
          `crates/wallet/src/wallet.rs:66` (duplicate)
**Core ref:** `bitcoin-core/src/consensus/consensus.h:19` —
              `static const int COINBASE_MATURITY = 100;` (exactly one
              definition site).

**Description:**
The wallet does not `use rustoshi_consensus::COINBASE_MATURITY` — it
redefines:

```rust
// wallet.rs:65
/// Coinbase maturity: coinbase outputs cannot be spent for 100 blocks.
pub const COINBASE_MATURITY: u32 = 100;
```

The values currently agree, but a future fix to the consensus
constant that does not update the wallet redefinition produces a
wallet-vs-validator policy disagreement. This is the same fleet
pattern as the duplicate `MAX_MONEY` definitions documented across
W137/W138 — the constant-duplication anti-pattern.

**Excerpt:**
```rust
// consensus/params.rs:79
/// Coinbase maturity: coinbase outputs cannot be spent for 100 blocks.
pub const COINBASE_MATURITY: u32 = 100;
```
```rust
// wallet/wallet.rs:65   (the parallel copy)
/// Coinbase maturity: coinbase outputs cannot be spent for 100 blocks.
pub const COINBASE_MATURITY: u32 = 100;
```

**Impact:**
None today. Future-proofing gap. One-line fix:
`use rustoshi_consensus::COINBASE_MATURITY;` at the top of `wallet.rs`,
delete the local redefinition.

---

### BUG-10 — `COINBASE_MATURITY` enforcement uses raw subtraction in ConnectBlock + `saturating_sub` in mempool — asymmetric defensive depth

**Severity:** P2 (operational consistency)
**File:** `crates/consensus/src/validation.rs:1698` (raw) vs
          `crates/consensus/src/mempool.rs:1525` (`saturating_sub`)
**Core ref:** `bitcoin-core/src/consensus/tx_verify.cpp:179` (one
              canonical signed-int check).

**Description:**
See BUG-8 for the deeper consensus impact. The asymmetry alone is
worth cataloguing because it makes future audits harder: the two
sites enforce the same Core rule, look almost identical, but use
different arithmetic primitives. Any future change to one site
(e.g., adding bounds checking) is unlikely to be mirrored at the
other.

**Excerpt:**
```rust
// validation.rs:1697-1700  (raw)
if coin.is_coinbase && height - coin.height < COINBASE_MATURITY {
    return Err(TxValidationError::PrematureCoinbaseSpend(
        height - coin.height,
        COINBASE_MATURITY,
    ).into());
}
```
```rust
// mempool.rs:1525-1531  (saturating)
let age = self.tip_height.saturating_sub(coin.height);
if age < COINBASE_MATURITY {
    return Err(MempoolError::CoinbaseNotMature {
        age,
        required: COINBASE_MATURITY,
    });
}
```

**Impact:**
Two paths enforcing the same consensus rule with different
defensive primitives. Cross-site refactor friction.

---

### BUG-11 — Wallet `is_mature` uses unchecked `utxo.height + COINBASE_MATURITY`

**Severity:** P3
**File:** `crates/wallet/src/wallet.rs:438`
**Core ref:** `bitcoin-core/src/wallet/wallet.cpp` — wallet-side maturity
              uses signed int.

**Description:**
```rust
// wallet.rs:432
    pub fn is_mature(&self, utxo: &WalletUtxo) -> bool {
        if !utxo.is_coinbase { return true; }
        if let Some(height) = utxo.height {
            self.chain_height >= height + COINBASE_MATURITY     // <-- u32 + u32, can panic
        } else {
            utxo.confirmations >= COINBASE_MATURITY
        }
    }
```

`utxo.height + COINBASE_MATURITY` panics in debug if `height ==
u32::MAX - 99..u32::MAX`. Not reachable on any real chain, but
inconsistent with the checked-arithmetic standard documented
elsewhere in the codebase.

**Excerpt:** above.

**Impact:**
Theoretical only. One-line fix:
`self.chain_height.saturating_sub(height) >= COINBASE_MATURITY`.

---

### BUG-12 — Per-tx fee out-of-range uses block-level error string `bad-txns-accumulated-fee-outofrange` instead of Core's per-tx `bad-txns-fee-outofrange`

**Severity:** P2 (RPC parity)
**File:** `crates/consensus/src/validation.rs:1842-1844, 347`
**Core ref:** `bitcoin-core/src/consensus/tx_verify.cpp:203-209` —
              `if (!MoneyRange(txfee_aux))
              return state.Invalid(..., "bad-txns-fee-outofrange");`
              (per-tx) vs `bitcoin-core/src/validation.cpp:2545` —
              `bad-txns-accumulated-fee-outofrange` (block-level).

**Description:**
Core emits two distinct error strings on overlapping conditions:

- **`bad-txns-fee-outofrange`** — per-tx fee (`txfee_aux = nValueIn -
  value_out`) outside MoneyRange. Inside `CheckTxInputs`.
- **`bad-txns-accumulated-fee-outofrange`** — block-level `nFees`
  accumulator outside MoneyRange. Inside `ConnectBlock`.

rustoshi only maps the block-level path (validation.rs:347 →
`bad-txns-accumulated-fee-outofrange`). The per-tx path is
structurally bounded (input_sum < MAX_MONEY by the per-input check at
line 1716, and `input_sum < output_sum` returns `InsufficientFunds`
first at line 1832, so `tx_fee = input_sum - output_sum` is always
in `[0, MAX_MONEY]`). But for *RPC compatibility* — operators
matching log strings against Core — the per-tx path's distinct error
is missing.

**Impact:**
RPC / log-grep parity gap. Any monitoring or alerting that pattern-
matches `bad-txns-fee-outofrange` against rustoshi logs will silently
miss the (admittedly unreachable) per-tx case.

---

### BUG-13 — Block-template `total_fees` accumulator uses raw `+=`

**Severity:** P2 (defensive-depth on the miner path)
**File:** `crates/consensus/src/block_template.rs:445`
**Core ref:** `bitcoin-core/src/node/miner.cpp:172-176` — Core's
              `nFees += iter->GetFee();` is bounded by per-tx
              `MoneyRange(txfee)` in CheckTxInputs.

**Description:**
```rust
// block_template.rs:442-446
            // FIX-72: total_fees uses the entry's actual base fee — the
            // delta is a mining-selection knob, not an additional payment.
            // Core BlockAssembler sums actual fees too (miner.cpp:172-176).
            total_fees += entry.fee;       // <-- raw add, no MoneyRange guard
            total_weight += entry.weight as u64;
            total_sigops += tx_sigops;
```

`entry.fee` is `u64`. If multiple mempool entries with synthetic fees
exist (operator bug or test fixture), `total_fees` can wrap. The
downstream `let coinbase_value = subsidy + total_fees;` then uses
the wrapped value as the cap. BUG-7 already catches the symptom; this
is the root-cause site.

**Impact:**
Same as BUG-7. One-line fix:
`total_fees = total_fees.checked_add(entry.fee).ok_or(...)?;`
or use `saturating_add` to keep `getblocktemplate` from emitting a
template whose miner-side validation will fail at `bad-cb-amount`.

---

### BUG-14 — Three parallel `CoinEntry`/`Coin` types across `storage::block_store`, `storage::utxo_cache`, `consensus::validation`

**Severity:** P2 (architectural fork-in-the-road)
**File:** `crates/storage/src/block_store.rs:124` (CoinEntry),
          `crates/storage/src/utxo_cache.rs:59` (Coin),
          `crates/consensus/src/validation.rs:1402` (CoinEntry)
**Core ref:** `bitcoin-core/src/coins.h` — exactly one `Coin` class.

**Description:**
Three distinct types, all with `(height, is_coinbase, value, script_pubkey)`
shape:

1. `storage::block_store::CoinEntry` — on-disk format, serde-serializable.
2. `storage::utxo_cache::Coin` — in-memory format with `tx_out: TxOut`
   composition, has `Coin::from_entry` / `Coin::to_entry` convert-wrappers.
3. `consensus::validation::CoinEntry` — validator's view, used by
   `connect_block_with_sequence_locks` and `UndoData`.

`utxo_cache::Coin::from_entry` already documents the impedance mismatch:

```rust
// utxo_cache.rs:98
    /// Convert from CoinEntry (database format).
    pub fn from_entry(entry: &CoinEntry) -> Self {
```

This is the W134/W137 fleet pattern of multi-pipeline storage abstractions
where each layer has its own representation and conversion code mediates
between them.

**Impact:**
Architectural friction. Future field additions (e.g., a new "spent
height" marker) must thread through three structs + two conversions.
Compounds the BUG-3 two-pipeline-guard fleet pattern: rustoshi has both
parallel subsidy fns AND parallel Coin types.

---

### BUG-15 — `CoinStatsEntry::total_unspendable` uses chained raw `+` on four `u64` fields

**Severity:** P2 (defensive-depth)
**File:** `crates/storage/src/indexes/coinstatsindex.rs:112-117`
**Core ref:** `bitcoin-core/src/kernel/coinstats.cpp` — Core uses
              CAmount accumulation throughout.

**Description:**
```rust
// coinstatsindex.rs:112
    pub fn total_unspendable(&self) -> u64 {
        self.unspendables_genesis
            + self.unspendables_bip30
            + self.unspendables_scripts
            + self.unspendables_unclaimed
    }
```

Four chained `u64 + u64` without any overflow guard. Bounded in
practice by MAX_MONEY (so `4 * MAX_MONEY = 8.4e15 < u64::MAX`), but
the defensive primitive is missing. Compounded with the
`circulating_supply` `saturating_sub` at line 121 — half the
arithmetic uses saturating, the other half uses raw. Same asymmetric-
defensive-depth pattern as BUG-10.

**Impact:**
Theoretical only at MAX_MONEY-bounded values. Cosmetic / consistency
gap.

---

### BUG-16 — RPC mining info / block stats does not expose `subsidy` via the canonical `block_subsidy` fn

**Severity:** P3 (RPC parity)
**File:** `crates/rpc/src/types.rs:572` (MiningInfoNext — no
          `subsidy` field), `crates/rpc/src/server.rs` (no
          `getblockstats` impl found).
**Core ref:** `bitcoin-core/src/rpc/mining.cpp::getmininginfo` (Core
              31.99 exposes the "next" subsidy in some shapes).

**Description:**
The Core 31.99 `getmininginfo` `next` sub-object includes a `subsidy`
field on some builds. `MiningInfoNext` exposes `height`, `bits`,
`difficulty`, `target` — no subsidy. Similarly, `getblockstats` (which
Core uses to expose per-block subsidy in JSON) is not implemented at
all in rustoshi's RPC server. Combined with BUG-3 (two parallel
`block_subsidy` impls), there is no RPC surface that exposes the
canonical subsidy for the next block.

**Impact:**
RPC parity gap. Mining pool operators relying on `getblockstats` for
per-block fee/subsidy decomposition will not find the data. Trivial
fix at the type-shape level once `getblockstats` is plumbed.

---

### BUG-17 — `block_subsidy` lacks the explicit "right-shift undefined" comment Core carries

**Severity:** P3 (documentation)
**File:** `crates/consensus/src/params.rs:298-303`
**Core ref:** `bitcoin-core/src/validation.cpp:1842-1844` —
              `// Force block reward to zero when right shift is
              undefined. if (halvings >= 64) return 0;`

**Description:**
The `>= 64` guard is correct, but the *reason* — to avoid C++
undefined-behaviour on right-shift-by-≥64-of-int64 — is not
captured in the rustoshi comment. Rust's `>>` on `u64` is well-defined
(panic in debug, masked in release on overflow), so the guard is
defending against a different (Rust-specific) behaviour while
producing the same observable consensus result. A future maintainer
might think the guard is redundant in Rust and remove it.

**Excerpt:**
```rust
// params.rs:294
/// Calculate the block subsidy for a given height.
///
/// The subsidy starts at 50 BTC and halves every `halving_interval` blocks.
/// After 64 halvings, the subsidy is 0.
pub fn block_subsidy(height: u32, halving_interval: u32) -> u64 {
    let halvings = height / halving_interval;
    if halvings >= 64 {
        return 0;
    }
    INITIAL_SUBSIDY >> halvings
}
```

Compare Core's load-bearing comment:

```cpp
// validation.cpp:1842
    // Force block reward to zero when right shift is undefined.
    if (halvings >= 64)
        return 0;
```

**Impact:**
Documentation hazard. A future "simplification" PR might remove the
guard reasoning that Rust well-defines `u64 >> N` for `N >= 64`
(it actually **panics in debug** for `N >= 64` on `u64`, and the
behaviour is **architecture-dependent** at runtime). The guard is
needed in Rust just as much as in C++, for different reasons.

---

### BUG-18 — Coinbase value sum uses `try_fold` with `unwrap_or(u64::MAX)` — overflow surfaces as `bad-cb-amount` instead of the upstream `bad-txns-vout-toolarge`

**Severity:** P2 (error-message parity)
**File:** `crates/consensus/src/validation.rs:1895-1902`
**Core ref:** `bitcoin-core/src/validation.cpp:2610-2614` plus
              `bitcoin-core/src/primitives/transaction.h::GetValueOut`
              (the upstream MoneyRange check).

**Description:**
```rust
// validation.rs:1895
    let coinbase_value: u64 = block.transactions[0]
        .outputs
        .iter()
        .try_fold(0u64, |acc, o| acc.checked_add(o.value))
        .unwrap_or(u64::MAX);

    if coinbase_value > max_coinbase_value {
        return Err(ValidationError::BadSubsidy(coinbase_value, max_coinbase_value));
    }
```

If any coinbase output overflows the fold, `coinbase_value = u64::MAX`
which is `> max_coinbase_value`, so the function rejects with
`bad-cb-amount`. But Core would reject *upstream* with
`bad-txns-vout-toolarge` (CheckTransaction would have caught the
oversized output before connect-block ran). The rustoshi error path
is structurally correct (the block is rejected) but emits the wrong
canonical error string.

**Impact:**
RPC log-grep parity. Operators matching `bad-txns-vout-toolarge` won't
see the symptom; they'll see `bad-cb-amount`. Compare W125 / W138's
"30-of-30-gates-buggy" `bad-cb-amount` vs `bad-cb-height` mixup
pattern.

---

### BUG-19 — `FeesOutOfRange(...)` carries a saturating-sum in the error payload (misleading number)

**Severity:** P3
**File:** `crates/consensus/src/validation.rs:1841-1844`
**Core ref:** Core's `bad-txns-accumulated-fee-outofrange` carries
              no payload.

**Description:**
```rust
// validation.rs:1841
        total_fees = total_fees
            .checked_add(tx_fee)
            .filter(|&f| f <= MAX_MONEY)
            .ok_or(ValidationError::FeesOutOfRange(total_fees.saturating_add(tx_fee)))?;
```

The `saturating_add` is computed only as a parameter for the error
payload (to feed `FeesOutOfRange(u64)` for the `Display`/Debug
impl). A future log-reader sees `accumulated fee in block out of
range: 21000000000000000` (the saturated value) which is u64::MAX,
not the actual `total_fees + tx_fee` value. Cosmetic but misleading.

**Impact:**
Cosmetic. Misleading operator output. One-line fix: drop the payload
or use the un-saturated overflow value (which can't be computed in
u64 anyway — this is the structural reason for using `saturating_add`).

---

### BUG-20 — `CoinStatsEntry` is JSON-serialized to disk; Core uses binary `coinstats.dat`

**Severity:** P2 (interop)
**File:** `crates/storage/src/indexes/coinstatsindex.rs:155-158`
**Core ref:** `bitcoin-core/src/kernel/coinstats.cpp` — Core uses
              binary serialization for `coinstats.dat`.

**Description:**
```rust
// coinstatsindex.rs:154
    pub fn put_stats(&self, entry: &CoinStatsEntry) -> Result<(), CoinStatsError> {
        let data =
            serde_json::to_vec(entry).map_err(|e| CoinStatsError::Storage(e.to_string()))?;
        self.db
            .put_cf(CF_COINSTATS, &entry.height.to_be_bytes(), &data)?;
        Ok(())
    }
```

`serde_json::to_vec` produces ~5× the size of Core's binary format,
plus rustoshi cannot consume Core's `coinstats.dat` and Core cannot
consume rustoshi's stats. Same fleet pattern as
W139's "persistence JSON vs Core binary v309900" finding (5 of 10
impls — rustoshi was in the cluster).

**Impact:**
Interop: rustoshi's coin-stats DB is not byte-compatible with Core's
`coinstats.dat`. Disk usage roughly 5× larger than Core for the same
data. Cross-impl chain-state verification harnesses that compare
serialized UTXO-set stats against Core's binary fail.

---

## Cross-impl parity smell

This audit reinforces three fleet patterns documented in MEMORY.md:

1. **Two-pipeline guard.** rustoshi has two `block_subsidy` impls
   (params + coinstatsindex) and three `CoinEntry`/`Coin` structs
   (storage::block_store + storage::utxo_cache + consensus::validation).
   Same shape as blockbrew's `MaybeSendFeeFilter` (W136) and clearbit's
   handshake-vs-dispatcher dual paths (W136).

2. **Asymmetric defensive depth.** rustoshi mixes `checked_add`,
   `saturating_add`, `saturating_sub`, raw `+`, and raw `.sum()` on
   the same `u64` consensus-relevant amount values across paths that
   enforce the same MoneyRange invariant (validation.rs:1714 vs
   1829 vs mempool.rs:1474 vs 4032 vs block_template.rs:445).
   Two paths use the safe primitive, two paths use raw arithmetic;
   the upstream check covers the happy path but the defensive-depth
   gap surfaces on synthetic fuzz / test fixtures bypassing
   CheckTransaction.

3. **Constant duplication.** `COINBASE_MATURITY` is defined in
   `consensus::params:80` AND `wallet::wallet:66` without a `use`
   bridge. Future fix to one side does not propagate.

The first finding (BUG-3 two-pipeline subsidy) is a one-deletion fix:
remove `coinstatsindex::get_block_subsidy` and have the index call
`consensus::params::block_subsidy(height, halving_interval)`.
The second class (BUG-4..8, BUG-10, BUG-11, BUG-13, BUG-15) is a
small architectural sweep — one PR converging on `checked_add` /
`saturating_sub` everywhere money flows. The third (BUG-9, BUG-14) is
a structural cleanup.

No P0-CONSENSUS findings: the canonical subsidy check at
validation.rs:1893–1903 is correctly wired, `bad-cb-amount` fires on
over-claim, CVE-2018-17144 duplicate-input check is present, and
COINBASE_MATURITY is correctly enforced. The P0 *category* (BUG-8) is
the silent-wrap risk in the COINBASE_MATURITY subtraction itself —
release-build under-rejection in a corrupted-UTXO scenario.
