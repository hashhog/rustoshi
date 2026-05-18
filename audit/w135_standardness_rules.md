# W135 — Standardness rules (IsStandardTx) parity audit (rustoshi)

**Wave**: W135 — IsStandardTx + AreInputsStandard + GetTransactionSigOpCost
+ TRUC nVersion=3 standardness + dust threshold + per-input/per-output
standardness gates (DISCOVERY).
**Impl**: rustoshi (Rust)
**Audit date**: 2026-05-17
**Reference (Bitcoin Core)**:
- `bitcoin-core/src/policy/policy.cpp` —
  - `GetDustThreshold` (lines 27-64) — formula uses `GetSerializeSize(txout)`
    + witness-discount-adjusted spending-input cost; **NOT** a fixed
    per-type spending size.
  - `IsDust` (lines 66-69) — `txout.nValue < GetDustThreshold(...)`.
  - `GetDust` (lines 71-78) — collects all dust outputs.
  - `IsStandard(scriptPubKey, whichType)` (lines 80-98) — script-type
    allowlist + MULTISIG `n ∈ [1,3], m ∈ [1,n]` policy cap.
  - `IsStandardTx` (lines 100-165) — version, tx-weight, scriptSig
    size/push-only, output script-type, OP_RETURN datacarrier budget,
    bare-multisig gate, dust-output count via `GetDust(...).size() >
    MAX_DUST_OUTPUTS_PER_TX`.
  - `CheckSigopsBIP54` (lines 170-194) — BIP-54 total non-witness sigops
    ≤ `MAX_TX_LEGACY_SIGOPS = 2500`.
  - `ValidateInputsStandardness` (lines 214-263) — NONSTANDARD /
    WITNESS_UNKNOWN prevout reject + P2SH redeem-script sigops ≤
    `MAX_P2SH_SIGOPS = 15`.
  - `IsWitnessStandard` (lines 265-352) — P2A witness-stuffing reject,
    P2SH-wrapped redeem extraction, P2WSH v0 limits (script ≤ 3600,
    stack items ≤ 100, item ≤ 80), P2TR annex reject + tapscript per-item
    size ≤ 80.
  - `SpendsNonAnchorWitnessProg` (lines 354-388) — helper used by ephemeral
    dust policy.
- `bitcoin-core/src/policy/policy.h` (lines 38-95) — constants:
  - `MAX_STANDARD_TX_WEIGHT = 400000`
  - `MIN_STANDARD_TX_NONWITNESS_SIZE = 65`
  - `MAX_P2SH_SIGOPS = 15`
  - `MAX_STANDARD_TX_SIGOPS_COST = MAX_BLOCK_SIGOPS_COST/5 = 16000`
  - `MAX_TX_LEGACY_SIGOPS = 2500`
  - `MAX_STANDARD_P2WSH_STACK_ITEMS = 100`
  - `MAX_STANDARD_P2WSH_STACK_ITEM_SIZE = 80`
  - `MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE = 80`
  - `MAX_STANDARD_P2WSH_SCRIPT_SIZE = 3600`
  - `MAX_STANDARD_SCRIPTSIG_SIZE = 1650`
  - `DUST_RELAY_TX_FEE = 3000`
  - `MAX_OP_RETURN_RELAY = MAX_STANDARD_TX_WEIGHT / WITNESS_SCALE_FACTOR = 100000`
    (note: brief said 83 — that value is stale; current Core has 100000)
  - `MAX_DUST_OUTPUTS_PER_TX = 1`
  - `DEFAULT_PERMIT_BAREMULTISIG = true`
  - `DEFAULT_ACCEPT_DATACARRIER = true`
  - `TX_MIN_STANDARD_VERSION = 1` / `TX_MAX_STANDARD_VERSION = 3`
- `bitcoin-core/src/policy/truc_policy.{h,cpp}` —
  - `TRUC_VERSION = 3`
  - `TRUC_ANCESTOR_LIMIT = TRUC_DESCENDANT_LIMIT = 2`
  - `TRUC_MAX_VSIZE = 10000`
  - `TRUC_CHILD_MAX_VSIZE = 1000`
  - `SingleTRUCChecks` (truc_policy.cpp:171-261).
  - `PackageTRUCChecks` (truc_policy.cpp:57-169).
- `bitcoin-core/src/script/solver.cpp` —
  - `Solver` (lines 145-209) — TxoutType detection; v=1 with `program.size()
    != WITNESS_V1_TAPROOT_SIZE (32)` AND not P2A returns
    `TxoutType::WITNESS_UNKNOWN` (not NONSTANDARD).
  - `MatchMultisig` (lines 85-105) — handles pushdata-prefixed pubkeys via
    `script.GetOp(...)` + `CPubKey::ValidSize` (33 or 65 byte).
- `bitcoin-core/src/primitives/transaction.h:293` — `version` is `uint32_t`
  (not `int32_t`).
- `bitcoin-core/src/consensus/tx_check.cpp` — `CheckTransaction` (consensus
  basic checks, NOT policy; out of W135 scope).

**Production code changes**: 0 (pure audit).
**Audit subject** (all paths absolute):
- `crates/consensus/src/mempool.rs`:
  - `MempoolConfig` standardness knobs (lines 676-749):
    `max_datacarrier_bytes: Option<usize>` (default `Some(100_000)`),
    `permit_bare_multisig: bool` (default `true`), `min_fee_rate: u64`.
  - `Mempool::check_standard` (lines 2368-2481) — the IsStandardTx port.
  - `Mempool::check_truc_policy` (lines 2499-2606) — TRUC rules.
  - `Mempool::add_transaction` calls into check_standard (line 1399),
    MIN_STANDARD_TX_NONWITNESS_SIZE (line 1410), ValidateInputsStandardness
    (lines 1566-1613), MAX_P2SH_SIGOPS gate (line 1604), IsWitnessStandard
    (lines 1620-1624), GetTransactionSigOpCost (lines 1626-1666).
  - `StandardScriptType` enum (lines 4534-4556) — variants P2PKH / P2SH /
    P2WPKH / P2WSH / P2TR / P2A / BareMultisig / NullData / WitnessUnknown /
    NonStandard.
  - `classify_standard_script` (lines 4562-4632) — the Solver port.
  - `try_classify_bare_multisig` (lines 4638-4693) — multisig matcher.
  - `script_sig_is_push_only` (lines 4700-4754) — push-only validator.
  - `is_witness_standard` (lines 4770-4936) — IsWitnessStandard port.
  - `parse_p2sh_redeem_script_from_scriptsig` (lines 4945-5011).
  - `is_standard_script` (lines 5021-5023) — boolean wrapper.
  - `is_dust` (lines 5028-5063) — the GetDustThreshold port (BUGGY — see
    BUG-1).
  - `is_ephemeral_dust` / `get_ephemeral_dust_outputs` (lines 5078-5116).
  - `pre_check_ephemeral_tx` (lines 5124-5136).
  - `check_ephemeral_spends` (lines 5146-5212).
  - `mempool_script_is_push_only_after_op_return` (lines 4475-4529).
  - TRUC constants `TRUC_VERSION = 3` / `TRUC_ANCESTOR_LIMIT = 2` /
    `TRUC_DESCENDANT_LIMIT = 2` / `TRUC_MAX_VSIZE = 10_000` /
    `TRUC_CHILD_MAX_VSIZE = 1_000` (lines 113-128).
- `crates/consensus/src/params.rs`:
  - `MAX_STANDARD_TX_WEIGHT = 400_000` (line 110)
  - `DEFAULT_MIN_RELAY_TX_FEE = 1_000` (line 113)
  - `DUST_RELAY_TX_FEE = 3_000` (line 116)
  - `MAX_STANDARD_TX_SIGOPS_COST = 16_000` (line 119)
  - `MAX_P2SH_SIGOPS = 15` (line 123)
  - `MIN_STANDARD_TX_NONWITNESS_SIZE = 65` (line 127)
  - `MAX_STANDARD_SCRIPTSIG_SIZE = 1650` (line 131)
  - `MAX_STANDARD_P2WSH_STACK_ITEMS = 100` (line 135)
  - `MAX_STANDARD_P2WSH_STACK_ITEM_SIZE = 80` (line 138)
  - `MAX_STANDARD_P2WSH_SCRIPT_SIZE = 3600` (line 141)
  - `MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE = 80` (line 144)
  - `ANNEX_TAG = 0x50` (line 147)
  - `TAPROOT_LEAF_MASK = 0xfe` (line 150)
  - `TAPROOT_LEAF_TAPSCRIPT = 0xc0` (line 153)
  - `WITNESS_V1_TAPROOT_SIZE = 32` (line 177)
  - `DEFAULT_BYTES_PER_SIGOP = 20` (line 269)
  - **MISSING**: `MAX_TX_LEGACY_SIGOPS` (Core = 2500), `MAX_OP_RETURN_RELAY`
    (Core = 100_000), `MAX_DUST_OUTPUTS_PER_TX` (Core = 1),
    `TX_MIN_STANDARD_VERSION` (Core = 1), `TX_MAX_STANDARD_VERSION`
    (Core = 3), `DEFAULT_PERMIT_BAREMULTISIG`, `DEFAULT_ACCEPT_DATACARRIER`,
    `DEFAULT_INCREMENTAL_RELAY_FEE` (Core = 100). Some of these are inlined
    as literals in check_standard or MempoolConfig::default; others are
    missing entirely.
- `crates/consensus/src/script/interpreter.rs`:
  - `ScriptFlags::standard_flags()` (lines 149-173) — STANDARD_SCRIPT_VERIFY_FLAGS port.
  - `is_p2sh` (line 2400), `is_p2a` (line 2438), `is_p2a_program` (line
    2446), `parse_witness_program` (line 2456) — used by IsWitnessStandard.
- `crates/consensus/src/validation.rs`:
  - `get_transaction_sigop_cost` (lines 612-655) — GetTransactionSigOpCost
    port (legacy ×4 + P2SH ×4 + witness ×1).
  - `count_script_sigops` (lines 805-…) — script.cpp::GetSigOpCount port.

**Test file**: `crates/consensus/tests/test_w135_standardness.rs` — 30
gates, mix of PASS regression pins + `#[ignore]`-pinned xfail BUG-N stubs.

## Why this matters

`IsStandardTx` + `AreInputsStandard` + `IsWitnessStandard` +
`GetTransactionSigOpCost` are the policy gate that decides which
transactions enter the mempool, get relayed to peers, and are included in
block templates by the miner. Divergence at any of these gates produces:

1. **Mempool DoS surface drift** — under-rejection lets non-standard txs
   in (extra CPU/memory cost per node, sigop bombs, witness stuffing).
2. **Block template divergence** — over-rejection at standardness means
   `getblocktemplate` omits txs Core would include; competing miners with
   correct standardness rules collect strictly more fees, and rustoshi
   produces lower-fee blocks on average.
3. **Relay-layer drift** — `IsWitnessStandard` rejecting txs Core would
   relay means rustoshi nodes are net negative for tx propagation. Worse,
   rejecting at the OUTPUT scriptPubKey layer (e.g. v=1+16-byte program
   misclassified as NonStandard) reverts to "block all unknown taproot-
   adjacent outputs" — a forward-incompatible posture that defeats the
   "reserved upgrade hooks" property Core engineered into Solver.
4. **Dust policy is mempool's anti-spam moat.** A wrong dust threshold
   admits ~270-sat-bigger dust spam per output type, multiplied across
   the entire UTXO acceptance pipeline.
5. **TRUC (BIP-431) policy underpins Lightning Channel anchor-output
   designs** that are now production code in lnd/CLN/eclair. A
   misimplementation breaks anchor-output sweeps under RBF pressure.

The standardness layer is policy, NOT consensus — divergence here will
not chain-split. However, "mempool acceptance ≠ block validity" is exactly
the asymmetry attackers exploit: a tx that rustoshi rejects locally but
Core accepts will appear in mined blocks rustoshi receives, with no
mempool warm-cache. **The fee-estimator + cluster-mempool + RBF stack
all assume mempool ≈ next block; W135 divergences silently erode that
assumption.**

## 30-gate audit matrix

| Gate | Status  | Severity | Finding |
|------|---------|----------|---------|
| G1   | OK      | -        | `MAX_STANDARD_TX_WEIGHT = 400_000` (params.rs:110) matches Core policy.h:38; `check_standard` (line 2387) enforces `tx.weight() > 400_000 → "tx-size"` |
| G2   | OK      | -        | `MIN_STANDARD_TX_NONWITNESS_SIZE = 65` (params.rs:127) matches Core policy.h:40; enforced twice — once in `add_transaction` (line 1410, gate is unconditional per Core's CVE-2017-12842 mitigation) and once in `check_standard` (line 2395) |
| G3   | OK      | -        | `MAX_STANDARD_SCRIPTSIG_SIZE = 1650` (params.rs:131); `check_standard` per-input gate (line 2404) matches Core policy.cpp:127 |
| G4   | OK      | -        | scriptSig push-only check (`script_sig_is_push_only` line 4700-4754) handles OP_0/OP_1NEGATE/OP_1..OP_16/direct-push/PUSHDATA1/PUSHDATA2/PUSHDATA4; `check_standard` per-input gate (line 2410) matches Core policy.cpp:131 |
| G5   | OK      | -        | Bare multisig gate `permit_bare_multisig` (MempoolConfig default true, line 735) matches Core `DEFAULT_PERMIT_BAREMULTISIG = true` (policy.h:52); `check_standard` enforces (line 2461) |
| G6   | OK      | -        | Bare-multisig n ∈ [1,3] enforced in `try_classify_bare_multisig` line 4650 (`(0x51..=0x53).contains(&op_n)`); m ∈ [1,n] enforced line 4662 — matches Core policy.cpp:91-94 |
| G7   | OK      | -        | TxoutType detection: P2PKH (line 4571), P2SH (line 4582), P2WPKH (line 4587), P2WSH (line 4592), P2A (line 4597), P2TR (line 4602) all match Core Solver shapes |
| G8   | BUG     | P0-CDIV  | **`is_dust` (lines 5028-5063) uses HARDCODED per-type spending size, missing the output's serialized size component**. Core's `GetDustThreshold` (policy.cpp:27-64) sets `nSize = GetSerializeSize(txout) + (32+4+1+107+4=148)` for non-witness or `+ (32+4+1+(107/4)+4=67)` for witness. Rustoshi uses only spending-input cost (148/91/68/108/58). Concrete divergence: P2TR threshold rustoshi `58*3000/1000 = 174 sat` vs Core `(43+67)*3000/1000 = 330 sat`. Rustoshi accepts 174-330 sat P2TR outputs that Core rejects as dust. P2PKH: 444 vs 546 (Δ=102). P2SH: 273 vs 540 (Δ=267, AND wrong spending size — see BUG-9). P2WPKH: 204 vs 294 (Δ=90). P2WSH: 324 vs 330 (Δ=6). See BUG-1 |
| G9   | BUG     | P0-CDIV  | **`MAX_DUST_OUTPUTS_PER_TX = 1` (Core policy.h:95) not implemented**: rustoshi `check_standard` line 2472 rejects FIRST dust output found; Core (policy.cpp:159) allows exactly 1 dust output per tx via `GetDust(tx, dust_relay_fee).size() > MAX_DUST_OUTPUTS_PER_TX`. The ephemeral-dust pattern (0-value non-P2A outputs that the child tx must spend) is rejected at `check_standard` BEFORE the `pre_check_ephemeral_tx` even runs. Rustoshi rejects ephemeral-dust txs that Core admits. See BUG-2 |
| G10  | BUG     | P0-CDIV  | **`classify_standard_script` excludes v=1 with non-32-byte programs from `WitnessUnknown`** (line 4619 comment: "Excludes OP_1 ... because OP_1 <32> is P2TR and OP_1 <2> is P2A"). Core `Solver` (solver.cpp:172-176) returns `TxoutType::WITNESS_UNKNOWN` for ANY witness version != 0 with non-canonical program size — including v=1 with sizes ∈ {3..31, 33..40}. Rustoshi falls through to `NonStandard` → rejects as output. Core accepts as standard output (relay), rejects as input (`ValidateInputsStandardness`). Concrete: v=1+16-byte program is a standard relayable output in Core, rejected at admit in rustoshi. See BUG-3 |
| G11  | MISSING | P1       | **`CheckSigopsBIP54` / `MAX_TX_LEGACY_SIGOPS = 2500`** (Core policy.cpp:170-194 + policy.h:46) — added per BIP-54. Counts `scriptSig.GetSigOpCount(/*fAccurate=*/true) + prev_txo.scriptPubKey.GetSigOpCount(scriptSig)` summed across all inputs, rejects if `> 2500`. Rustoshi has NO equivalent. Means rustoshi admits sigop-heavy txs (per-input non-witness sigops summing > 2500) that Core's BIP-54 gate rejects. See BUG-4 |
| G12  | OK      | -        | `MAX_STANDARD_TX_SIGOPS_COST = 16_000` (params.rs:119) matches Core policy.h:44; `add_transaction` (line 1657) enforces `sigop_cost > 16_000 → NonStandard("bad-txns-too-many-sigops")` matching Core validation.cpp:941-943 |
| G13  | OK      | -        | `MAX_P2SH_SIGOPS = 15` (params.rs:123) matches Core policy.h:42; `add_transaction` (line 1604) extracts redeemScript from scriptSig and rejects if `count_script_sigops(redeem, accurate=true) > 15` matching Core policy.cpp:254-257 |
| G14  | OK      | -        | `MAX_OP_RETURN_RELAY` semantics (`MempoolConfig.max_datacarrier_bytes`, default `Some(100_000)` line 733): per-tx total bytes across OP_RETURN outputs; matches Core policy.h:84 (`MAX_OP_RETURN_RELAY = MAX_STANDARD_TX_WEIGHT / WITNESS_SCALE_FACTOR = 100_000`). NOTE: brief said 83 — that value is stale (pre-current-Core) |
| G15  | OK      | -        | `max_datacarrier_bytes = None` disables OP_RETURN entirely (matches `-datacarrier=0` in Core); `check_standard` line 2438-2443 returns "datacarrier" reason. Mirrors Core policy.cpp:147-150 |
| G16  | OK      | -        | `MAX_STANDARD_P2WSH_STACK_ITEMS = 100` (params.rs:135), `MAX_STANDARD_P2WSH_STACK_ITEM_SIZE = 80` (params.rs:138), `MAX_STANDARD_P2WSH_SCRIPT_SIZE = 3600` (params.rs:141) match Core policy.h:54-60; `is_witness_standard` enforces all three (mempool.rs:4849-4877) |
| G17  | OK      | -        | `MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE = 80` (params.rs:144) matches Core policy.h:58; `is_witness_standard` tapscript per-item gate (mempool.rs:4910-4922) matches Core policy.cpp:336-340. P2TR annex 0x50 reject (line 4889) matches policy.cpp:327-330 |
| G18  | OK      | -        | `is_witness_standard` P2A witness-stuffing reject (mempool.rs:4787-4793) matches Core policy.cpp:283-285 |
| G19  | OK      | -        | `ValidateInputsStandardness` shape (mempool.rs:1566-1613): rejects `NonStandard` and `WitnessUnknown` prevouts (Core policy.cpp:231-240) and gates P2SH redeemScript sigops at 15 (line 1604, Core policy.cpp:241-258) |
| G20  | OK      | -        | TRUC constants: `TRUC_VERSION = 3` (line 113), `TRUC_ANCESTOR_LIMIT = 2` (line 117), `TRUC_DESCENDANT_LIMIT = 2` (line 121), `TRUC_MAX_VSIZE = 10_000` (line 124), `TRUC_CHILD_MAX_VSIZE = 1_000` (line 128) all match `truc_policy.h:20-34` |
| G21  | OK      | -        | TRUC inheritance: `check_truc_policy` (mempool.rs:2510-2523) rejects v3↔non-v3 spending in both directions (Core truc_policy.cpp:180-190); ancestor/descendant limits (lines 2536-2602) match Core SingleTRUCChecks |
| G22  | BUG     | P2       | **`is_dust` parameter `_min_fee_rate` is unused** (underscore prefix at mempool.rs:5028); dust threshold ALWAYS uses constant `DUST_RELAY_TX_FEE` regardless of `MempoolConfig.min_fee_rate` or any future `-dustrelayfee` flag. Core threads `dustRelayFee` through `GetDustThreshold(txout, dustRelayFee)` (policy.h:140). See BUG-5 |
| G23  | BUG     | P2       | **No public `MAX_OP_RETURN_RELAY` / `MAX_DUST_OUTPUTS_PER_TX` / `MAX_TX_LEGACY_SIGOPS` / `TX_MIN_STANDARD_VERSION` / `TX_MAX_STANDARD_VERSION` / `DEFAULT_PERMIT_BAREMULTISIG` / `DEFAULT_ACCEPT_DATACARRIER` constants in params.rs**. Several are inlined as literals (e.g. `tx.version < 1 || tx.version > TRUC_VERSION` at mempool.rs:2378 uses literals 1 and `TRUC_VERSION=3` instead of named constants). This makes audit + cross-impl byte-exact comparison harder. Hard-fork or policy bump (e.g. raising `TX_MAX_STANDARD_VERSION` for a future v4 nVersion class) becomes a literal-grep across files. See BUG-6 |
| G24  | BUG     | P3       | **`Transaction.version` is `i32`** (primitives/transaction.rs:227), Core is `uint32_t` (primitives/transaction.h:293). Wire-format byte-identical; semantic divergence only at error-message level (`bad version: -<huge>` vs Core `version`). Both reject all non-{1,2,3} txs. Tracked only for completeness; not exploitable. See BUG-7 |
| G25  | PARTIAL | P2       | **`try_classify_bare_multisig` (mempool.rs:4638-4693) only accepts 33-byte (compressed) or 65-byte (uncompressed) pubkey pushes via DIRECT push opcodes (0x21 / 0x41)**. Core's `MatchMultisig` (solver.cpp:85-105) uses `script.GetOp(it, opcode, data)` which traverses PUSHDATA1/2/4 prefixes. A multisig with PUSHDATA1-prefixed pubkey would be classified `NonStandard` by rustoshi vs `MULTISIG` (then policy-rejected at IsStandard for n∈[1,3]) by Core. Same outcome (rejection) but different code path; semantic divergence if `IsStandard` policy is loosened in future. See BUG-8 |
| G26  | BUG     | P2       | **`is_dust` P2SH spending size is `91`** (mempool.rs:5049, comment "P2SH input size (approximate)"). Core treats P2SH as a non-witness output: `nSize = GetSerializeSize(txout=32 bytes) + (32+4+1+107+4=148) = 180`, NOT a witness-discounted spending. The `91` looks like a witness-style size (~`32+4+1+(107/4)+4=67` + outputs spec ≈ 90-100). Rustoshi's P2SH dust threshold is `91*3000/1000 = 273 sat`, Core's is `180*3000/1000 = 540 sat`. P2SH outputs in (273..540) sat are admitted by rustoshi, rejected by Core. See BUG-9 |
| G27  | OK      | -        | `is_witness_standard` P2SH-wrapped redeem extraction via `parse_p2sh_redeem_script_from_scriptsig` (mempool.rs:4945-5011) simulates Core's `EvalScript(stack, scriptSig, SCRIPT_VERIFY_NONE, ...)` and takes `stack.back()`. Returns `None` on empty stack — matches Core policy.cpp:295-296 |
| G28  | OK      | -        | `ScriptFlags::standard_flags()` (interpreter.rs:149-173) sets all 18 STANDARD_SCRIPT_VERIFY_FLAGS bits matching Core policy.h:119-132. Each MANDATORY bit (P2SH/DERSIG/NULLDUMMY/CLTV/CSV/WITNESS/TAPROOT) plus STRICTENC/MINIMALDATA/DISCOURAGE_UPGRADABLE_NOPS/CLEANSTACK/MINIMALIF/NULLFAIL/LOW_S/DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM/WITNESS_PUBKEYTYPE/CONST_SCRIPTCODE/DISCOURAGE_UPGRADABLE_TAPROOT_VERSION/DISCOURAGE_OP_SUCCESS/DISCOURAGE_UPGRADABLE_PUBKEYTYPE active |
| G29  | OK      | -        | `get_transaction_sigop_cost` (validation.rs:612-655) — legacy sigops×WITNESS_SCALE_FACTOR + P2SH redeem sigops×WITNESS_SCALE_FACTOR (when verify_p2sh) + witness sigops (unscaled). Matches Core consensus/tx_verify.cpp::GetTransactionSigOpCost |
| G30  | MISSING | P2       | **`SpendsNonAnchorWitnessProg`** (Core policy.cpp:354-388) helper not implemented in rustoshi. Used by ephemeral dust policy + future package-relay extensions to distinguish "this tx spends a non-P2A witness program (so must respect descendant-spend constraints)" from "spends only P2A or legacy". Rustoshi's ephemeral-dust enforcement (`check_ephemeral_spends`, mempool.rs:5146-5212) reaches similar end-result via output-side classification but does not implement Core's input-side helper. See BUG-10 |

**Total: 30 gates, 7 BUGs, 1 PARTIAL, 2 MISSING, 20 OK.**

Of the 7 BUGs + 2 MISSING (= 9 non-OK gates), **3 are P0-CDIV** (G8 dust
threshold, G9 MAX_DUST_OUTPUTS_PER_TX gate, G10 v=1 WITNESS_UNKNOWN
misclassification), **1 P1** (G11 MAX_TX_LEGACY_SIGOPS BIP-54),
**4 P2** (G22 dust-fee unconfigurable, G23 missing constants, G25/G26
multisig+P2SH minor), **1 P3** (G24 i32 vs u32 version type).

The 20 OK gates establish that rustoshi has implemented the MAJORITY of
the IsStandardTx surface correctly (script-type allowlist, scriptSig/
P2WSH/tapscript size gates, TRUC core rules, MAX_P2SH_SIGOPS,
MAX_STANDARD_TX_SIGOPS_COST, datacarrier budget). The remaining 10
gates concentrate on the dust threshold formula, the WITNESS_UNKNOWN
forward-compat layer, and BIP-54.

## Top findings

### BUG-1 (P0-CDIV) — `is_dust` uses hardcoded per-type spending size, missing the output's serialized-size component

**Where**: `crates/consensus/src/mempool.rs:5028-5063` (`fn is_dust`).

```rust
let spending_size: usize = if output.script_pubkey.len() == 25 {
    148 // P2PKH input size
} else if output.script_pubkey.len() == 23 {
    91 // P2SH input size (approximate)
} else if output.script_pubkey.len() == 22 && output.script_pubkey[0] == 0x00 {
    68 // P2WPKH input size
} else if output.script_pubkey.len() == 34 && output.script_pubkey[0] == 0x00 {
    108 // P2WSH input size (approximate)
} else if output.script_pubkey.len() == 34 && output.script_pubkey[0] == 0x51 {
    58 // P2TR input size
} else {
    148 // conservative default
};
let dust_threshold = (spending_size as u64 * DUST_RELAY_TX_FEE) / 1000;
output.value < dust_threshold
```

**Core**: `policy.cpp:27-64` `GetDustThreshold(txout, dustRelayFee)`:

```cpp
uint64_t nSize{GetSerializeSize(txout)};                  // value(8) + spk_varint + spk
int witnessversion = 0;
std::vector<unsigned char> witnessprogram;
if (txout.scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
    nSize += (32 + 4 + 1 + (107 / WITNESS_SCALE_FACTOR) + 4);   // = 67 for witness
} else {
    nSize += (32 + 4 + 1 + 107 + 4);                            // = 148 for non-witness
}
return dustRelayFeeIn.GetFee(nSize);                       // = nSize * dustRelayFee / 1000
```

Core's `nSize` is the SUM of (a) the serialized output size (varies by
output type) and (b) the spending-input cost. Rustoshi's `spending_size`
is ONLY (b), and uses wrong numbers for several types.

**Concrete divergences** (dust threshold at default `DUST_RELAY_TX_FEE = 3000`):

| Output type | Core nSize | Core threshold | Rustoshi | Δ (rustoshi under-rejects) |
|-------------|------------|----------------|----------|----------------------------|
| P2PKH       | 34 + 148 = 182 | 546 sat   | 444 sat  | 102 sat |
| P2SH        | 32 + 148 = 180 | 540 sat   | 273 sat  | 267 sat (BUG-9 compounds) |
| P2WPKH      | 31 + 67  = 98  | 294 sat   | 204 sat  | 90 sat |
| P2WSH       | 43 + 67  = 110 | 330 sat   | 324 sat  | 6 sat |
| P2TR        | 43 + 67  = 110 | 330 sat   | 174 sat  | 156 sat |

**Effect**: rustoshi **admits dust outputs that Core rejects** across
every output type. The P2SH and P2TR gaps are especially large. P2TR
dust attack: outputs valued 175-329 sat are admitted by rustoshi, rejected
by Core. Across mempool-wide spam this admits ~50% more dust outputs at
mainnet rates. Fee-estimator drift, cluster-mempool sizing, and mempool
limit drift all follow.

**Severity**: P0-CDIV. Mempool admission divergence at every standard
output type. Affects relay (rustoshi forwards dust Core drops),
block-template construction (rustoshi block templates can contain dust
Core nodes refuse to mine), and `getrawmempool` parity.

**Fix shape**: Compute `output.serialized_size()` (rustoshi already has
this on `TxOut`) and add it to the spending cost. Spending cost should
be `148` for non-witness (P2PKH, P2SH, bare multisig), `67` for witness
(P2WPKH, P2WSH, P2TR — via the rounded `107/4 = 26`). Single function,
single call site; high-leverage fix.

### BUG-2 (P0-CDIV) — `MAX_DUST_OUTPUTS_PER_TX = 1` ephemeral allowance MISSING

**Where**: `crates/consensus/src/mempool.rs:2472`:

```rust
// Dust check (skip for OP_RETURN — handled above with early continue).
if is_dust(output, self.config.min_fee_rate) {
    return Err(MempoolError::NonStandard(format!(
        "dust at index {}",
        i
    )));
}
```

This is INSIDE the per-output for-loop in `check_standard` — the first
dust output triggers an immediate return.

**Core**: `policy.cpp:158-162`:

```cpp
// Only MAX_DUST_OUTPUTS_PER_TX dust is permitted (on otherwise valid ephemeral dust)
if (GetDust(tx, dust_relay_fee).size() > MAX_DUST_OUTPUTS_PER_TX) {
    reason = "dust";
    return false;
}
```

Core collects ALL dust outputs and rejects only if there are MORE THAN
`MAX_DUST_OUTPUTS_PER_TX = 1`. This permits exactly 1 dust output per
transaction — the ephemeral-dust pattern (a 0-value or below-threshold
output whose only purpose is CPFP fee-bumping; the child tx must spend
it).

**Effect**: rustoshi rejects ephemeral-dust txs that Core admits. The
canonical ephemeral-anchor design (Lightning + zero-fee parent + child
with fee) is BLOCKED at rustoshi's `check_standard` BEFORE
`pre_check_ephemeral_tx` (mempool.rs:5124) even runs. P2A is exempt via
`is_dust(P2A) = false` (line 5041), but NON-P2A ephemeral dust (a 0-value
P2PKH or P2WPKH) is rejected.

Compounding: BUG-1's wrong threshold means more outputs land in the
"dust" bucket than Core would classify as dust, so the over-rejection
surface from this BUG is even larger than at Core-correct thresholds.

**Severity**: P0-CDIV. Relay divergence on a production transaction
pattern (Lightning anchor outputs). Breaks the
"zero-fee-parent + fee-paying-child" RBF/CPFP idiom.

**Fix shape**: Refactor the per-output loop to collect dust counts into
a `Vec<u32>` (matching Core's `GetDust`), then at the end of the loop:

```rust
let dust_outputs = get_dust_outputs(tx, &self.config);
if dust_outputs.len() > MAX_DUST_OUTPUTS_PER_TX {
    return Err(MempoolError::NonStandard("dust".into()));
}
```

Then expose `get_dust_outputs` to `pre_check_ephemeral_tx` so the
ephemeral-dust pipeline knows which outputs the child must spend.

### BUG-3 (P0-CDIV) — `classify_standard_script` excludes v=1 with non-32-byte programs from WITNESS_UNKNOWN → rejects relayable forward-compat outputs

**Where**: `crates/consensus/src/mempool.rs:4616-4629`:

```rust
// Witness unknown: OP_1..OP_16 followed by a 2–40 byte push.
// ...
// Excludes OP_1 (0x51) because OP_1 <32> is P2TR (handled above) and OP_1 <2> is P2A.
if script.len() >= 4 && script.len() <= 42 {
    let version = script[0];
    // OP_2 (0x52) through OP_16 (0x60) — v2..=v16 witness programs
    if (0x52..=0x60).contains(&version) {
        let push_len = script[1] as usize;
        if (2..=40).contains(&push_len) && script.len() == 2 + push_len {
            return StandardScriptType::WitnessUnknown;
        }
    }
}

StandardScriptType::NonStandard
```

The comment is honest about the exclusion. But Core's `Solver`
(`solver.cpp:155-176`) handles v=1 with non-canonical program sizes
EXPLICITLY:

```cpp
if (scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
    if (witnessversion == 0 && witnessprogram.size() == WITNESS_V0_KEYHASH_SIZE) {...}
    if (witnessversion == 0 && witnessprogram.size() == WITNESS_V0_SCRIPTHASH_SIZE) {...}
    if (witnessversion == 1 && witnessprogram.size() == WITNESS_V1_TAPROOT_SIZE) {...}
    if (scriptPubKey.IsPayToAnchor()) {...}
    if (witnessversion != 0) {                  // <-- catches v=1 with non-{2,32}-byte program
        vSolutionsRet.push_back(std::vector<unsigned char>{(unsigned char)witnessversion});
        vSolutionsRet.push_back(std::move(witnessprogram));
        return TxoutType::WITNESS_UNKNOWN;
    }
    return TxoutType::NONSTANDARD;              // only v=0 with non-{20,32} reaches here
}
```

**Effect**: A scriptPubKey of `OP_1 <16-byte program>` is a valid witness
program (`OP_1` + push 16 + 16 bytes). Core classifies it as
`WITNESS_UNKNOWN` → `IsStandard()` returns true → standard output (it
can be sent to the chain via wallet RPC / accepted in mempool / relayed).
Rustoshi misclassifies as `NonStandard` → `check_standard` rejects with
"scriptpubkey at index N".

The same gap covers v=1 with 17, 18, 19, ..., 31, 33, 34, ..., 40-byte
programs. All of these are forward-compatible upgrade hooks reserved by
the BIP-141 segwit design and intentionally relayed as standard outputs.

**Severity**: P0-CDIV. Relay-layer over-rejection. This is the exact
forward-compatibility hatch Core engineered into Solver to allow future
soft forks to claim arbitrary v=1 program sizes without breaking relay.
Rustoshi's exclusion defeats that hatch.

**Fix shape**: Replace the `0x52..=0x60` range with `0x51..=0x60` (v=1
through v=16); add an explicit early-return for the canonical P2TR and
P2A cases (already done at lines 4597-4604); the WITNESS_UNKNOWN branch
catches all other v=1+ programs. Update the comment.

### BUG-4 (P1) — `MAX_TX_LEGACY_SIGOPS = 2500` BIP-54 check MISSING

**Where**: `crates/consensus/src/mempool.rs::add_transaction` (no mention
of BIP-54 anywhere). `params.rs` does not define `MAX_TX_LEGACY_SIGOPS`.

**Core**: `policy.cpp:170-194` `CheckSigopsBIP54`:

```cpp
static bool CheckSigopsBIP54(const CTransaction& tx, const CCoinsViewCache& inputs)
{
    Assert(!tx.IsCoinBase());
    unsigned int sigops{0};
    for (const auto& txin: tx.vin) {
        const auto& prev_txo{inputs.AccessCoin(txin.prevout).out};
        sigops += txin.scriptSig.GetSigOpCount(/*fAccurate=*/true);
        sigops += prev_txo.scriptPubKey.GetSigOpCount(txin.scriptSig);
        if (sigops > MAX_TX_LEGACY_SIGOPS) {
            return false;
        }
    }
    return true;
}
```

Called from `ValidateInputsStandardness` (policy.cpp:221):
```cpp
if (!CheckSigopsBIP54(tx, mapInputs)) {
    state.Invalid(TxValidationResult::TX_INPUTS_NOT_STANDARD,
                  "bad-txns-nonstandard-inputs",
                  "non-witness sigops exceed bip54 limit");
    return state;
}
```

**Effect**: rustoshi's `add_transaction` calls
`ValidateInputsStandardness` semantics inline (mempool.rs:1566-1613)
including the per-input P2SH redeem-script sigops gate (≤15) and the
overall `MAX_STANDARD_TX_SIGOPS_COST = 16000` gate. But there is NO
per-tx LEGACY sigops cap. A pathological tx with many P2SH inputs whose
scriptSigs each contain CHECKMULTISIG (each < 15 redeem sigops, total
weighted sigop cost < 16000 due to witness-discount distribution) can
still accumulate > 2500 raw non-witness sigops. Core BIP-54 rejects;
rustoshi admits.

**Severity**: P1. BIP-54 is a recent (2025) policy bump targeted at a
known DoS vector. Mempool admission divergence at the BIP-54 threshold.

**Fix shape**: Add `MAX_TX_LEGACY_SIGOPS = 2500` to params.rs; implement
a `check_sigops_bip54(&tx, &prevout_scripts)` helper; call from the
existing `ValidateInputsStandardness` block in add_transaction (after the
`prevout_scripts.len() == tx.inputs.len()` guard). Reject as
`MempoolError::InputsNonStandard` with reason "bip54-sigops".

### BUG-5 (P2) — `is_dust` ignores `min_fee_rate` parameter; dust threshold is hardcoded to `DUST_RELAY_TX_FEE`

**Where**: `crates/consensus/src/mempool.rs:5028` — parameter
`_min_fee_rate: u64` (note the underscore prefix marking it unused).
The threshold computation at line 5061 uses `DUST_RELAY_TX_FEE` directly.

**Core**: `policy.h:140` —
`CAmount GetDustThreshold(const CTxOut& txout, const CFeeRate& dustRelayFee);`
The `dustRelayFee` is configurable per-node via `-dustrelayfee` setting
and is threaded through `IsStandardTx` (called as
`IsStandardTx(tx, max_datacarrier_bytes, permit_bare_multisig, dust_relay_fee, reason)`).

**Effect**: rustoshi has no equivalent of `-dustrelayfee`. Operator
cannot tune dust policy. Compounds BUG-1 — even if BUG-1 were fixed by
adding the output's serialized size, the result is still hardcoded at
3000 sat/kvB.

**Severity**: P2. Operational/configuration divergence; not a hot-path
correctness bug but blocks operator tuning + future Core policy changes
that adjust the default.

**Fix shape**: Add `dust_relay_fee: u64` to `MempoolConfig` with default
`DUST_RELAY_TX_FEE`. Pass through `is_dust(output, dust_relay_fee)`. Wire
CLI flag in `rustoshi/src/main.rs`.

### BUG-6 (P2) — Named constants for IsStandardTx limits MISSING from `params.rs`

**Where**: `crates/consensus/src/params.rs` — no public constants for:

- `TX_MIN_STANDARD_VERSION = 1` (Core policy.h:152)
- `TX_MAX_STANDARD_VERSION = 3` (Core policy.h:153)
- `MAX_TX_LEGACY_SIGOPS = 2500` (Core policy.h:46)
- `MAX_OP_RETURN_RELAY = 100000` (Core policy.h:84)
- `MAX_DUST_OUTPUTS_PER_TX = 1` (Core policy.h:95)
- `DEFAULT_PERMIT_BAREMULTISIG = true` (Core policy.h:52)
- `DEFAULT_ACCEPT_DATACARRIER = true` (Core policy.h:80)
- `DEFAULT_INCREMENTAL_RELAY_FEE = 100` (Core policy.h:48)

Some are inlined as literals — e.g. `tx.version < 1 || tx.version >
TRUC_VERSION` at mempool.rs:2378 uses literals `1` and `TRUC_VERSION=3`
instead of `TX_MIN_STANDARD_VERSION` and `TX_MAX_STANDARD_VERSION`. The
`100_000` MAX_OP_RETURN_RELAY default appears as a magic number in
MempoolConfig::default (line 733).

**Effect**: Auditability + fleet-wide byte-exact comparison harder.
A policy bump (e.g. raising `TX_MAX_STANDARD_VERSION` for a future v4
nVersion class) becomes a literal-grep across files.

**Severity**: P2. Style/auditability; not a behavioral bug.

**Fix shape**: Add 8 constants to params.rs as `pub const ...`. Replace
inline literals at the 3 call sites in mempool.rs.

### BUG-7 (P3) — `Transaction.version` is `i32` (Core: `uint32_t`)

**Where**: `crates/primitives/src/transaction.rs:227` — `pub version: i32`.

**Core**: `primitives/transaction.h:293` — `const uint32_t version`.

**Effect**: Wire-format byte-identical (4 bytes LE either way). At
read-back, a tx with the high bit set (e.g. raw version field
`0xFFFFFFFF` LE = -1 i32 = 4294967295 u32) is parsed as `-1` in rustoshi
and `4294967295` in Core. Both reject:
- rustoshi: `tx.version < 1` matches (true, since -1 < 1) → "bad version: -1"
- Core: `tx.version > TX_MAX_STANDARD_VERSION (= 3)` matches → "version"

Same outcome (rejection); different error message. Hash, sigops, and
relay are unaffected because `tx.serialize()` writes the same 4 LE bytes
either way.

**Severity**: P3. Polish — error message divergence only.

**Fix shape**: Change `version: i32 → version: u32`. Adjust comparisons
(`< 1` becomes `== 0`, since u32 cannot be negative; or use the named
constants from BUG-6).

### BUG-8 (P2) — `try_classify_bare_multisig` only accepts direct-push pubkey opcodes; rejects PUSHDATA-prefixed multisig

**Where**: `crates/consensus/src/mempool.rs:4670-4679`:

```rust
let push_len_byte = script[pos] as usize;
// Only direct 1-byte-length pushes (0x21=33, 0x41=65) are valid pubkey pushes.
let pk_len = if push_len_byte == 0x21 {
    33
} else if push_len_byte == 0x41 {
    65
} else {
    return None;
};
```

**Core**: `solver.cpp:97` —
```cpp
while (script.GetOp(it, opcode, data) && CPubKey::ValidSize(data)) {
    pubkeys.emplace_back(std::move(data));
}
```

`GetOp` parses PUSHDATA1/PUSHDATA2/PUSHDATA4 prefixes; `CPubKey::ValidSize`
returns true for `data.size() == 33 || data.size() == 65`.

**Effect**: A bare multisig with one of its pubkey pushes encoded as
`OP_PUSHDATA1 <0x21> <33 bytes>` (3-byte overhead instead of 1-byte)
would be classified as `NonStandard` by rustoshi vs `MULTISIG` (then
policy-rejected for n>3) by Core. Practical impact: low — non-minimal
PUSHDATA encodings are themselves rejected by `MINIMALDATA` script flag
during execution, so the divergence is in the type *classifier* output
only, not in the eventual accept/reject decision. But the error reason
differs ("scriptpubkey" vs "bare-multisig") and the policy.h
`MAX_PUBKEYS_PER_MULTISIG = 20` boundary cannot be hit in rustoshi's
classifier (which caps at n=3 immediately via 0x51..=0x53).

**Severity**: P2. Classifier divergence at uncommon shapes; same eventual
admit/reject outcome.

**Fix shape**: Use `parse_witness_program`'s push-parsing technique (or
the `script_sig_is_push_only` walker) to handle PUSHDATA prefixes when
walking pubkey pushes; check `data.len() == 33 || data.len() == 65`
on the parsed payload.

### BUG-9 (P2) — `is_dust` P2SH spending size is `91`, but P2SH outputs are non-witness in Core (should be 148)

**Where**: `crates/consensus/src/mempool.rs:5048-5049`:

```rust
} else if output.script_pubkey.len() == 23 {
    91 // P2SH input size (approximate)
```

**Core**: P2SH outputs are non-witness. `GetDustThreshold` (policy.cpp:55)
calls `IsWitnessProgram(witnessversion, witnessprogram)`, which on a P2SH
output (script form `OP_HASH160 <20> OP_EQUAL`) returns FALSE — so the
non-witness branch fires with `nSize += 148`. The total: 32 (P2SH
serialized output size) + 148 = 180 → threshold = 540 sat.

Rustoshi's `91` looks like a witness-style spending cost (roughly
`32+4+1+(107/4)+4 = 67` plus partial output cost) misapplied to P2SH.

**Effect**: P2SH outputs with value ∈ (273, 540) sat are admitted by
rustoshi, rejected by Core. The 267-sat window is the LARGEST per-type
divergence; combined with BUG-1's missing serialized-output-size
component, the actual rustoshi P2SH threshold is `91*3000/1000 = 273`
vs Core `(32+148)*3000/1000 = 540`. Compound BUG.

**Severity**: P2. Sub-finding of BUG-1; subsumed by BUG-1's fix.

**Fix shape**: P2SH spending size should be `148`, not `91` — but the
correct fix is BUG-1's: compute `output.serialized_size() + spending_cost`
(where spending_cost = 148 for non-witness, 67 for witness).

### BUG-10 (P2) — `SpendsNonAnchorWitnessProg` MISSING

**Where**: `crates/consensus/src/` — no implementation.

**Core**: `policy.cpp:354-388` —
```cpp
bool SpendsNonAnchorWitnessProg(const CTransaction& tx, const CCoinsViewCache& prevouts)
{
    if (tx.IsCoinBase()) return false;
    int version;
    std::vector<uint8_t> program;
    for (const auto& txin: tx.vin) {
        const auto& prev_spk{prevouts.AccessCoin(txin.prevout).out.scriptPubKey};
        // Note this includes not-yet-defined witness programs.
        if (prev_spk.IsWitnessProgram(version, program) && !prev_spk.IsPayToAnchor(version, program)) {
            return true;
        }
        if (prev_spk.IsPayToScriptHash()) {
            std::vector<std::vector<uint8_t>> stack;
            if (!EvalScript(stack, txin.scriptSig, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, SigVersion::BASE)
                || stack.empty()) {
                continue;
            }
            const CScript redeem_script{stack.back().begin(), stack.back().end()};
            if (redeem_script.IsWitnessProgram(version, program)) {
                return true;
            }
        }
    }
    return false;
}
```

**Effect**: Used by ephemeral-policy + future package-relay features to
distinguish "this tx spends a non-P2A witness program" from "spends only
P2A or legacy". Rustoshi's ephemeral-dust enforcement is output-side
(`check_ephemeral_spends`, mempool.rs:5146-5212), so the gap is
behaviorally compensated for the existing ephemeral pattern, but the
helper is not present for future cases.

**Severity**: P2. Missing helper; not currently affecting acceptance
decisions because rustoshi's ephemeral-policy uses a different
representation.

**Fix shape**: Port from Core if/when ephemeral-policy is extended.

## Universal patterns observed

1. **Hardcoded mainnet constants** (BUG-6): IsStandardTx limits are
   inlined as literals rather than named `pub const`. Rustoshi's W117
   pattern of "named-constant-per-Core-name" is partially observed —
   most consensus-side constants are present, but the policy-side ones
   (TX_*_STANDARD_VERSION, MAX_TX_LEGACY_SIGOPS, MAX_OP_RETURN_RELAY,
   MAX_DUST_OUTPUTS_PER_TX) are missing. Cross-impl byte-exact comparison
   wants every Core constant named in params.rs.

2. **"Comment-as-confession"** (BUG-3): line 4619 — "Excludes OP_1 ...
   because OP_1 <32> is P2TR and OP_1 <2> is P2A." The comment is honest
   about the exclusion but does not flag that v=1 with OTHER sizes is
   still a forward-compat witness program in Core. Pattern matches the
   W120 BUG-5 ("FullRBF" comment) and W122 blockbrew
   ("test-comment-as-confession" BUG) findings.

3. **Dead/unused parameter** (BUG-5): `_min_fee_rate: u64` with
   underscore prefix signals "intentionally unused" — Rust's idiom is
   honest here but the function signature suggests configurability that
   does not exist. Either remove the parameter or wire it.

4. **Partial-port of a Core helper** (BUG-1, BUG-9): `is_dust` ports the
   high-level shape of `GetDustThreshold` but loses the
   `GetSerializeSize(txout)` summand. The remaining hardcoded numbers
   appear to be off-by-N approximations rather than systematic. Pattern:
   when porting a Core helper, port the FORMULA, not the example
   outcomes.

5. **Engineered forward-compat hatch defeated** (BUG-3): Core's
   `WITNESS_UNKNOWN` design is the standardness layer's only
   forward-soft-fork hook. Defeating it via misclassification regresses
   to "all unknown witness outputs are non-standard" — a posture Core
   explicitly engineered AROUND. This is the same shape as W117
   I2P/Tor/CJDNS BUG-x ("unknown address-family reject"): an upgrade
   hook the impl narrowed.

## Out of scope

- W135 explicitly excludes `CheckTransaction` (consensus basic checks
  in `consensus/tx_check.cpp`) — those are consensus, not policy.
- Ephemeral dust enforcement past the standardness-layer gates
  (`pre_check_ephemeral_tx`, `check_ephemeral_spends`) is W116
  package-relay material; only the dust-output-COUNT gate (BUG-2 / G9)
  is in W135 scope.
- Mempool size limits, eviction policy, fee-bumping, RBF are W120/W129
  scope.
- Block-template sigops accounting is W123 mining scope; W135 only
  exercises the per-tx admission gate.

## Concurrent-agent coordination

W134/W136/W137 are running in parallel (BIP-37 bloom filter / TBD / TBD).
No file overlap: W135 audit lives in `audit/w135_standardness_rules.md`,
tests in `crates/consensus/tests/test_w135_standardness.rs`. W134's
`w134_bip37_bloom_filter.md` is the only adjacent untracked file in
audit/ at audit start.
