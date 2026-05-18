# W144 — Script-verify flag mux audit (rustoshi)

**Wave:** W144 — Script-verify flag mux (DISCOVERY)
**Date:** 2026-05-18
**Audit subject:** the rustoshi script-flag-derivation surface that drives
`SCRIPT_VERIFY_*` bit selection at script-eval time — the rustoshi
equivalent of Bitcoin Core's `GetBlockScriptFlags(pindex, chainman)`
function (validation.cpp:2250-2289) and the flag-application call sites
inside `EvalScript` and `VerifyWitnessProgram`.

**Files audited:**
- `crates/consensus/src/script/interpreter.rs` (5,800+ LOC) —
  `ScriptFlags` struct (line 70), `consensus_flags` (line 123),
  `standard_flags` (line 149), `to_bits` (line 179), all `verify_*`
  check sites in `eval_script` (line 880+), `verify_script` (line 2540+),
  `verify_witness_program` (line 2685+).
- `crates/consensus/src/validation.rs` —
  `script_flags_for_height` (line 2342), the **production** flag
  selector called from `connect_block_with_sequence_locks` (line 1547);
  `skip_scripts` assume-valid gate (line 1554).
- `crates/consensus/src/mempool.rs` lines 1885-1934 — two-pass
  PolicyScriptChecks / ConsensusScriptChecks mempool harness, both
  call `verify_script` with `ScriptFlags::standard_flags()` or a
  hand-rolled subset.
- `crates/consensus/src/params.rs` —
  `bip34_height`/`bip65_height`/`bip66_height`/`csv_height`/
  `segwit_height`/`taproot_height` fields (lines 493-498),
  mainnet/testnet3/testnet4/signet/regtest constructors
  (lines 540-940). No `bip16_height`, no `script_flag_exceptions`,
  no `bip16_exception_blocks` field.
- `crates/consensus/src/lib.rs:24` — documentation pointer to
  `consensus_flags()` (which the production path does not use).
- `crates/consensus/src/chain_state.rs:508` — production caller into
  `connect_block_with_sequence_locks`.

**Bitcoin Core references:**
- `bitcoin-core/src/script/interpreter.h:41-152` —
  `script_verify_flag_name` enum: P2SH, STRICTENC, DERSIG, LOW_S,
  NULLDUMMY, SIGPUSHONLY, MINIMALDATA, DISCOURAGE_UPGRADABLE_NOPS,
  CLEANSTACK, CHECKLOCKTIMEVERIFY, CHECKSEQUENCEVERIFY, WITNESS,
  DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, MINIMALIF, NULLFAIL,
  WITNESS_PUBKEYTYPE, CONST_SCRIPTCODE, TAPROOT,
  DISCOURAGE_UPGRADABLE_TAPROOT_VERSION, DISCOURAGE_OP_SUCCESS,
  DISCOURAGE_UPGRADABLE_PUBKEYTYPE.
- `bitcoin-core/src/policy/policy.h:105-132` —
  `MANDATORY_SCRIPT_VERIFY_FLAGS` = P2SH | DERSIG | NULLDUMMY | CLTV |
  CSV | WITNESS | TAPROOT.
  `STANDARD_SCRIPT_VERIFY_FLAGS` = MANDATORY ∪ STRICTENC | MINIMALDATA |
  DISCOURAGE_UPGRADABLE_NOPS | CLEANSTACK | MINIMALIF | NULLFAIL |
  LOW_S | DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM | WITNESS_PUBKEYTYPE |
  CONST_SCRIPTCODE | DISCOURAGE_UPGRADABLE_TAPROOT_VERSION |
  DISCOURAGE_OP_SUCCESS | DISCOURAGE_UPGRADABLE_PUBKEYTYPE.
- `bitcoin-core/src/validation.cpp:2250-2289` — `GetBlockScriptFlags`:
  starts `flags = P2SH | WITNESS | TAPROOT`, applies
  `script_flag_exceptions` carve-outs (mainnet has 2: BIP16 exception
  `00000000000002dc756e…` → `SCRIPT_VERIFY_NONE`; Taproot exception
  `0000…e395ad` → `P2SH | WITNESS`), then conditionally adds DERSIG /
  CLTV / CSV / NULLDUMMY via `DeploymentActiveAt(block_index, …,
  DEPLOYMENT_DERSIG / DEPLOYMENT_CLTV / DEPLOYMENT_CSV /
  DEPLOYMENT_SEGWIT)`.
- `bitcoin-core/src/validation.cpp:2344-2383` — assume-valid
  `script_check_reason` gate: requires assume-valid hash to be IN
  m_block_index, ancestor at pindex height to equal pindex (in
  assume-valid chain), best_header to include pindex (in best chain),
  best_header chain-work ≥ MinimumChainWork, AND block-proof
  equivalent-time check (≥ 2 weeks). Only after ALL five succeed does
  `script_check_reason = nullptr` and script verification is skipped.
- `bitcoin-core/src/deploymentstatus.h:14-37` — `DeploymentActiveAt`
  for buried: `index.nHeight >= params.DeploymentHeight(dep)`;
  `DeploymentActiveAfter` for buried: `(pindexPrev->nHeight+1) >=
  params.DeploymentHeight(dep)`.
- `bitcoin-core/src/consensus/params.h:142-156` —
  `DeploymentHeight(BuriedDeployment)` switch: HEIGHTINCB→BIP34Height,
  CLTV→BIP65Height, DERSIG→BIP66Height, CSV→CSVHeight,
  SEGWIT→SegwitHeight. **No DEPLOYMENT_P2SH** — P2SH is unconditionally
  set in GetBlockScriptFlags + only the script_flag_exceptions
  map controls the exception block.
- `bitcoin-core/src/script/interpreter.cpp:201-216` — Core's
  `CheckSignatureEncoding`: DERSIG ∨ LOW_S ∨ STRICTENC ⇒ DER required;
  LOW_S ⇒ low-S; STRICTENC ⇒ defined hashtype.
- `bitcoin-core/src/script/interpreter.cpp:229-249` — `FindAndDelete`.
- `bitcoin-core/src/script/interpreter.cpp:321-333` —
  `EvalChecksigPreTapscript`: in BASE sigversion, run FindAndDelete on
  scriptCode; if any signature was found AND
  `SCRIPT_VERIFY_CONST_SCRIPTCODE` is set ⇒
  `SCRIPT_ERR_SIG_FINDANDDELETE`.
- `bitcoin-core/src/script/interpreter.cpp:1140-1150` — same for
  `OP_CHECKMULTISIG`.
- `bitcoin-core/src/script/interpreter.cpp:1858-1861` — witness stack
  item size cap before `ExecuteWitnessScript`.
- `bitcoin-core/src/script/interpreter.cpp:1917-1998` —
  `VerifyWitnessProgram` flag-dispatch tree (taproot inactive ⇒
  set_success; v1+32+!is_p2sh ⇒ Taproot; v0+20 P2WPKH; v0+32 P2WSH;
  P2A short-circuit; else
  `DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM` → error).
- `bitcoin-core/src/script/interpreter.h:130-132` —
  `SCRIPT_VERIFY_CONST_SCRIPTCODE` semantics.
- `bitcoin-core/src/kernel/chainparams.cpp:85-94` — mainnet
  `script_flag_exceptions.emplace(...)` for BIP16 + Taproot
  exception blocks; `BIP34Height = 227931`, `BIP65Height = 388381`,
  `BIP66Height = 363725`, `CSVHeight = 419328`, `SegwitHeight = 481824`.
- `bitcoin-core/src/kernel/chainparams.cpp:305-320` — testnet4
  has all softforks at height 1, `BIP34Hash = uint256{}`,
  no script_flag_exceptions.

**Production code changes:** 0 (pure audit).

BIPs covered: BIP-16 (P2SH), BIP-65 (CLTV), BIP-66 (strict DER),
BIP-68/112/113 (CSV / nSequence / MTP-locktime), BIP-141 (witness),
BIP-143 (witness sighash), BIP-146 (NULLFAIL), BIP-147 (NULLDUMMY),
BIP-148 (forced-segwit, historical), BIP-341 (Taproot key path),
BIP-342 (Tapscript), BIP-444 (P2A).

## Why this matters

The script-flag mux is the **dispatcher between consensus rules and
mempool policy**. Every script-eval site reads `ScriptFlags` to decide
which BIPs to enforce: P2SH redeem-script unpacking, DERSIG signature
encoding, CLTV/CSV locktime/sequence checks, segregated witness
dispatch, Taproot verification. A wrong bit here means either:

- **Consensus split** if a *consensus-mandatory* bit is omitted from
  block validation but Core sets it (rustoshi accepts a block Core
  rejects, or vice versa).
- **Policy/relay divergence** if a *policy-only* bit leaks into block
  validation (rustoshi rejects a Core-accepted block — fork-causing
  divergence).
- **Historical-block re-validation failure** if the exception list
  (`script_flag_exceptions`) is missing — rustoshi fails to validate
  the BIP16 exception block at h=174,062 or the Taproot exception
  block at h=692,263 during a from-genesis reindex.

Three failure modes are particularly dangerous and recur in this
audit:

1. **Two-pipeline + comment-as-confession in flag selection.**
   `ScriptFlags::consensus_flags(height, testnet4)` (interpreter.rs:123)
   and the production `script_flags_for_height(height, params)`
   (validation.rs:2342) are TWO independent flag-derivation
   pipelines, BOTH live in the codebase. The doc-comment in
   `lib.rs:24` literally points readers at `consensus_flags()` as
   "the correct flags to use during block validation" — but
   production `connect_block_with_sequence_locks` calls
   `script_flags_for_height` instead. The two functions disagree on
   four flags (P2SH height-gate, NULLFAIL inclusion,
   WITNESS_PUBKEYTYPE inclusion, hardcoded mainnet/testnet4 heights
   that ignore signet/regtest/testnet3). This is **well-engineered
   helper + comment-as-confession**, repeating the W117/W118/W137/
   W141 pattern. (BUG-1)

2. **`script_flag_exceptions` is entirely absent.**
   rustoshi has zero representation of either mainnet exception block
   (`00000000000002dc756e…` at h=174,062, BIP16 exception →
   `SCRIPT_VERIFY_NONE` in Core; `0000…e395ad` at h=692,263, Taproot
   exception → `P2SH|WITNESS` in Core). On a from-genesis reindex,
   rustoshi will apply P2SH (always-on per `script_flags_for_height`)
   to block 174,062 and reject the redeem-script execution that Core
   accepts; the divergence is a hard rebroadcast/reindex failure.
   (BUG-2)

3. **Assume-valid gate is HEIGHT-ONLY — five Core preconditions
   missing.**
   Production `script_flags_for_height` is called regardless of
   assume-valid, but the script-skip itself
   (`connect_block_with_sequence_locks` line 1554) reduces Core's
   five-condition gate (`AssumedValidBlock not null` + ancestor at
   pindex height + best_header chain + min-chain-work + 2-week
   equivalent-time) to a single `height ≤ assumed_valid_height`
   comparison. Under a side-chain reorg, blocks below
   `assumed_valid_height` on the *non-canonical* chain have their
   script verification skipped. (BUG-3)

Beyond these, this audit catalogues: missing `bip16_height` field
(BUG-4), missing FindAndDelete + `SIG_FINDANDDELETE` consensus rule
(BUG-5), wrong error variant for upgradable-witness-program (BUG-6),
hardcoded testnet4 heights in `consensus_flags` make it unusable for
signet/regtest/testnet3 (BUG-7), missing `script_verify_flags::value_type`
overflow guard (BUG-8), `verify_taproot` height-gated instead of
exception-list (BUG-9), `MANDATORY_SCRIPT_VERIFY_FLAGS` constant
absent (BUG-10), `STANDARD_NOT_MANDATORY_VERIFY_FLAGS` absent
(BUG-11), policy-flag drift in `consensus_flags` that incorrectly
enables NULLFAIL and WITNESS_PUBKEYTYPE as consensus rules (BUG-12),
no defense-in-depth re-check in `connect_block` (BUG-13),
`verify_const_scriptcode` flag bit defined but only check site is
OP_CODESEPARATOR — FindAndDelete path absent (BUG-14), defaultable
ScriptFlags allows uninitialised script verification (BUG-15),
`to_bits` ordering is rustoshi-internal — not Core-compatible for
cache-key interop (BUG-16), missing `BIP-30` script-flag interaction
gap (P2 informational, BUG-17), test-only path uses different height
constants than production (BUG-18), `IsPayToAnchor` recognised inside
verify_witness_program but P2A discouragement gating mismatched
(BUG-19), Tapscript validation-weight budget gated on
`flags.verify_taproot` only but Core also requires versionbits
(BUG-20), no `SCRIPT_VERIFY_END_MARKER` static-assert guarding the
flag width (BUG-21), `verify_script` accepts default-constructed
`ScriptFlags{}` and gives anyone-can-spend semantics — no minimum-
flag-set assertion (BUG-22).

## Audit framework (30 gates / 22 BUGS catalogued; 13 are P0/P1
testable)

Gate legend:
- **PASS** — behaviour matches Core (regression pin).
- **BUG-N** — divergence or absent check (numbered consecutively).

| # | Behaviour | Status |
|---|-----------|--------|
| G1 | Single production flag-selector reachable from connect_block | BUG-1 (two pipelines) |
| G2 | `script_flag_exceptions` lookup at block_hash before flag mux | BUG-2 |
| G3 | Assume-valid gate checks all 5 Core preconditions | BUG-3 |
| G4 | `bip16_height` field present on ChainParams | BUG-4 |
| G5 | FindAndDelete on signatures in BASE scriptCode | BUG-5 |
| G6 | `SCRIPT_ERR_SIG_FINDANDDELETE` reachable when CONST_SCRIPTCODE set + sig found | BUG-5 |
| G7 | DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM has dedicated ScriptError variant | BUG-6 |
| G8 | `consensus_flags(height, testnet4)` supports signet/regtest/testnet3 | BUG-7 |
| G9 | `script_verify_flags::value_type` cardinality guard | BUG-8 |
| G10 | Taproot activation parity with Core (exception-list, not height) | BUG-9 |
| G11 | `MANDATORY_SCRIPT_VERIFY_FLAGS` named constant | BUG-10 |
| G12 | `STANDARD_NOT_MANDATORY_VERIFY_FLAGS` named constant | BUG-11 |
| G13 | `consensus_flags` excludes NULLFAIL + WITNESS_PUBKEYTYPE per Core | BUG-12 |
| G14 | Two-pass PolicyScriptChecks/ConsensusScriptChecks in connect_block | BUG-13 |
| G15 | `verify_const_scriptcode` enforces FindAndDelete error | BUG-14 |
| G16 | `ScriptFlags::default()` rejected at script-eval entry | BUG-15 |
| G17 | `to_bits` maps each flag to Core's bit position for cache interop | BUG-16 |
| G18 | BIP-30 ↔ script flag interaction documented | BUG-17 (P2 doc) |
| G19 | Test-only `consensus_flags` uses same constants as production | BUG-18 |
| G20 | P2A discouragement gate matches Core | BUG-19 |
| G21 | Tapscript validation-weight budget version-gated | BUG-20 |
| G22 | `SCRIPT_VERIFY_END_MARKER`/`MAX_SCRIPT_VERIFY_FLAGS_BITS` enforced | BUG-21 |
| G23 | `verify_script` asserts minimum-flag-set on entry | BUG-22 |
| G24 | DERSIG triggers DER-encoding check (with STRICTENC ∨ LOW_S) | PASS |
| G25 | LOW_S triggers low-S check independently | PASS |
| G26 | NULLDUMMY rejects non-empty dummy push (CHECKMULTISIG / VERIFY) | PASS |
| G27 | CLTV (OP_NOP2 → OP_CLTV) re-numbered with `verify_checklocktimeverify` | PASS |
| G28 | CSV (OP_NOP3 → OP_CSV) re-numbered with `verify_checksequenceverify` | PASS |
| G29 | OP_NOP1/NOP4..NOP10 → DISCOURAGE_UPGRADABLE_NOPS guarded by flag | PASS |
| G30 | Tapscript OP_SUCCESS pre-scan honours DISCOURAGE_OP_SUCCESS | PASS |

## BUGS

### BUG-1 — Two independent flag-derivation pipelines, the production one ignored by the documented entry point (`consensus_flags`)

**Severity:** P0-CDIV
**File:** `crates/consensus/src/script/interpreter.rs:123-144`
       (`consensus_flags(height, testnet4)` — the documented entry)
       `crates/consensus/src/validation.rs:2342-2366`
       (`script_flags_for_height(height, params)` — the production
       entry called from `connect_block_with_sequence_locks:1547`)
       `crates/consensus/src/lib.rs:24`
       (doc comment pointing to `consensus_flags`)
**Core ref:** `bitcoin-core/src/validation.cpp:2250-2289`
              (single `GetBlockScriptFlags(block_index, chainman)`)

**Description:**
rustoshi has **two** functions that derive the per-block `ScriptFlags`
bitmask and they disagree on four bits:

| Flag | `consensus_flags` | `script_flags_for_height` | Core (GetBlockScriptFlags) |
|------|-------------------|---------------------------|----------------------------|
| `verify_p2sh` | `height >= 173_805` (mainnet) / `height >= 1` (testnet4) | **always `true`** | always `true` (carved out via `script_flag_exceptions`) |
| `verify_nullfail` | `height >= segwit_height` | **`false`** (Default) | **policy-only** — never set in `GetBlockScriptFlags` |
| `verify_witness_pubkeytype` | `height >= segwit_height` | **`false`** (Default) | **policy-only** — never set in `GetBlockScriptFlags` |
| Height source | hardcoded mainnet/testnet4 ternaries | reads from `params` | reads from `consensus` params |

`lib.rs:24` documents:

```rust
//! See `ScriptFlags::consensus_flags()` for the correct flags to use during
//! block validation.
```

But the **actual** production call path is:

```
ChainState::connect_block (chain_state.rs:508)
  → connect_block_with_sequence_locks (validation.rs:1539)
    → script_flags_for_height(height, params) (validation.rs:1547)
```

— never `consensus_flags`. `consensus_flags` has 11 callers in tests
and zero callers in production source. The production
`script_flags_for_height` matches Core's
`GetBlockScriptFlags` semantics correctly (P2SH always-on, NULLFAIL
absent, WITNESS_PUBKEYTYPE absent); `consensus_flags` is divergent.

The two-pipeline pattern is identical to W117 (sig verification
helper / wallet code-path), W137 (PSBT decode helpers), W141 (ZMQ
notifier wired in tests but unreachable from production), and
W143 (`contextual_check_block_header` defined but never called).

**Excerpt (lib.rs:24 — comment-as-confession):**
```rust
//! When validating blocks, only use consensus flags. Adding policy flags
//! (CLEANSTACK, LOW_S, etc.) to block validation will cause valid blocks
//! to be rejected, forking the node from the network.
//!
//! See `ScriptFlags::consensus_flags()` for the correct flags to use during
//! block validation.
```

The note **directly points future contributors at the wrong function**
— anyone who reads lib.rs and wires `consensus_flags` into a new
caller will *introduce* the NULLFAIL + WITNESS_PUBKEYTYPE-as-consensus
divergence.

**Excerpt (consensus_flags, the WRONG one):**
```rust
// interpreter.rs:123
pub fn consensus_flags(height: u32, testnet4: bool) -> Self {
    let p2sh_height = if testnet4 { 1 } else { 173_805 };
    let bip66_height = if testnet4 { 1 } else { 363_725 };
    let bip65_height = if testnet4 { 1 } else { 388_381 };
    let csv_height = if testnet4 { 1 } else { 419_328 };
    let segwit_height = if testnet4 { 1 } else { 481_824 };
    let taproot_height = if testnet4 { 1 } else { 709_632 };

    ScriptFlags {
        verify_p2sh: height >= p2sh_height,
        verify_dersig: height >= bip66_height,
        verify_checklocktimeverify: height >= bip65_height,
        verify_checksequenceverify: height >= csv_height,
        verify_witness: height >= segwit_height,
        verify_nulldummy: height >= segwit_height,
        verify_nullfail: height >= segwit_height,  // ← WRONG (Core: policy only)
        verify_witness_pubkeytype: height >= segwit_height, // ← WRONG (Core: policy only)
        verify_taproot: height >= taproot_height,
        ..Default::default()
    }
}
```

**Excerpt (script_flags_for_height, the production one):**
```rust
// validation.rs:2342
fn script_flags_for_height(height: u32, params: &ChainParams) -> ScriptFlags {
    ScriptFlags {
        verify_p2sh: true,                                // always on
        verify_dersig: height >= params.bip66_height,
        verify_checklocktimeverify: height >= params.bip65_height,
        verify_checksequenceverify: height >= params.csv_height,
        verify_witness: height >= params.segwit_height,
        verify_nulldummy: height >= params.segwit_height,
        verify_taproot: height >= params.taproot_height,
        // verify_nullfail absent ✓
        // verify_witness_pubkeytype absent ✓
        ..Default::default()
    }
}
```

**Impact:**
- Any future code path that follows `lib.rs:24` and calls
  `consensus_flags` for connecting a block will reject valid mainnet
  blocks where a CHECKMULTISIG returns `false` with non-empty
  signatures (NULLFAIL fires) or where a witness-v0 P2WPKH uses an
  uncompressed pubkey (WITNESS_PUBKEYTYPE fires) — both
  **valid-Core-block → rustoshi-reject** divergences.
- Comment-as-confession: lib.rs:24 actively mis-documents the
  production entry point.
- Two-pipeline guard 7th dedicated extension inside rustoshi (latest
  major occurrence per memory log).

---

### BUG-2 — `script_flag_exceptions` for the BIP16 and Taproot exception blocks is entirely absent

**Severity:** P0-CDIV
**File:** `crates/consensus/src/params.rs:480-530`
       (ChainParams struct — no `script_flag_exceptions` field)
       `crates/consensus/src/validation.rs:2342-2366`
       (`script_flags_for_height` — does not accept or check
       a block hash)
**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:85-88`
              (mainnet `script_flag_exceptions.emplace(BIP16
              exception hash, SCRIPT_VERIFY_NONE)` +
              `(Taproot exception hash, SCRIPT_VERIFY_P2SH |
              SCRIPT_VERIFY_WITNESS)`)
              `bitcoin-core/src/validation.cpp:2263-2266`
              (the lookup at the head of `GetBlockScriptFlags`)

**Description:**
Bitcoin Core carries **two** mainnet blocks that historically violated
script-verify rules:

1. **BIP-16 exception** — block hash
   `00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22`
   at height ~174,062. Its scriptSig pushed `OP_1` instead of the
   expected redeem-script wrapping P2SH expects. Core carves this
   block to `SCRIPT_VERIFY_NONE` (no flags at all).

2. **Taproot exception** — block hash
   `0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad`
   at height ~692,263. A Taproot output predating activation got
   spent in a way that fails the live BIP-341 rules. Core carves this
   block to `SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS` (no TAPROOT).

rustoshi has **no representation** of either. `ChainParams` has no
`script_flag_exceptions` field (grep confirms); `script_flags_for_height`
does not even take a block hash as input. On a from-genesis reindex of
mainnet:

- At h=174,062 rustoshi runs P2SH (always-on) → the redeem-script
  evaluation that Core skipped fires and the block is **rejected**.
- At h=692,263 rustoshi runs TAPROOT (gated on
  `height >= taproot_height = 709_632`, so actually NOT active in
  rustoshi at h=692,263 — coincidentally rustoshi's height-gated
  Taproot saves it from THIS specific exception, BUT for blocks in
  `[692,263, 709,631]` rustoshi is **laxer than Core** because Core
  carves out only h=692,263 and applies TAPROOT to all other blocks
  starting from genesis-equivalent semantics post-versionbits
  signaling. See also BUG-9.).

**Excerpt (Core, the exception list):**
```cpp
// kernel/chainparams.cpp:85-88
consensus.script_flag_exceptions.emplace( // BIP16 exception
    uint256{"00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"},
    SCRIPT_VERIFY_NONE);
consensus.script_flag_exceptions.emplace( // Taproot exception
    uint256{"0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad"},
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS);
```

**Excerpt (Core, the lookup at the head of GetBlockScriptFlags):**
```cpp
// validation.cpp:2262-2266
script_verify_flags flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT};
const auto it{consensusparams.script_flag_exceptions.find(*Assert(block_index.phashBlock))};
if (it != consensusparams.script_flag_exceptions.end()) {
    flags = it->second;
}
```

**Excerpt (rustoshi — no equivalent):**
```rust
// validation.rs:2342  (no block hash argument!)
fn script_flags_for_height(height: u32, params: &ChainParams) -> ScriptFlags {
    ScriptFlags {
        verify_p2sh: true,
        verify_dersig: height >= params.bip66_height,
        // … no exception-list lookup
    }
}
```

```rust
// params.rs:493-498  (no script_flag_exceptions field)
pub bip34_height: u32,
pub bip65_height: u32,
pub bip66_height: u32,
pub csv_height: u32,
pub segwit_height: u32,
pub taproot_height: u32,
// missing: pub script_flag_exceptions: HashMap<Hash256, ScriptFlags>,
```

**Impact:**
- **From-genesis reindex of mainnet HARD-FAILS at h=174,062** —
  rustoshi rejects the BIP16 exception block. Operators running a
  `-reindex` will hit a permanent stop point.
- **Same on `verifychain`/`TestBlockValidity`** at any reorg that
  re-validates h=174,062.
- The Taproot exception block is currently not a divergence
  *because* rustoshi's height-gated Taproot (`taproot_height =
  709_632`) leaves h=692,263 below the activation gate — but this is
  coincidental, not by design (see BUG-9).

Cross-impl audit memo: this same gap may exist in blockbrew /
clearbit / nimrod / hotbuns / ouroboros / lunarblock / haskoin —
the W144 sweep should confirm.

---

### BUG-3 — Assume-valid gate is HEIGHT-ONLY, missing all 5 Core preconditions

**Severity:** P0-SEC
**File:** `crates/consensus/src/validation.rs:1553-1557`
**Core ref:** `bitcoin-core/src/validation.cpp:2344-2383`

**Description:**
Core's assume-valid gate (`script_check_reason`) checks **five**
distinct conditions before deciding to skip script verification:

```cpp
// validation.cpp:2346-2383
if (m_chainman.AssumedValidBlock().IsNull()) {
    script_check_reason = "assumevalid=0 (always verify)";
} else {
    BlockMap::const_iterator it{m_blockman.m_block_index.find(m_chainman.AssumedValidBlock())};
    if (it == m_blockman.m_block_index.end()) {
        script_check_reason = "assumevalid hash not in headers";                       // (1)
    } else if (it->second.GetAncestor(pindex->nHeight) != pindex) {                    // (2)
        script_check_reason = (pindex->nHeight > it->second.nHeight)
            ? "block height above assumevalid height"
            : "block not in assumevalid chain";
    } else if (m_chainman.m_best_header->GetAncestor(pindex->nHeight) != pindex) {     // (3)
        script_check_reason = "block not in best header chain";
    } else if (m_chainman.m_best_header->nChainWork < m_chainman.MinimumChainWork()) { // (4)
        script_check_reason = "best header chainwork below minimumchainwork";
    } else if (GetBlockProofEquivalentTime(*m_chainman.m_best_header, *pindex,
                  *m_chainman.m_best_header, params.GetConsensus()) <= TWO_WEEKS_IN_SECONDS) {
        script_check_reason = "block too recent relative to best header";               // (5)
    } else {
        script_check_reason = nullptr; // skip script verification
    }
}
```

Conditions 2-5 prevent:
- (2) skipping scripts on a block at the same height as
  assumed-valid but *on a different chain*;
- (3) skipping scripts on a block not in the best-header chain
  (defends against a malicious peer's reorg);
- (4) skipping scripts when total chainwork is below the hardcoded
  `MinimumChainWork` (defends against low-work spam chains);
- (5) skipping scripts on blocks <2 weeks of equivalent proof-of-work
  from the best header tip (defends against extortion DoS where an
  attacker withholds work to make us run the assumevalid skip on
  insufficient evidence).

rustoshi's equivalent:

```rust
// validation.rs:1553-1557
let skip_scripts = match params.assumed_valid_height {
    Some(av_height) => height <= av_height,
    None => false,
};
```

— **a single `height ≤ av_height` comparison** with no hash check,
no best-chain check, no chainwork check, no equivalent-time check.

**Excerpt (the production gate):**
```rust
// validation.rs:1547-1557
let flags = script_flags_for_height(height, params);
let csv_active = height >= params.csv_height;
let mut total_fees: u64 = 0;
let mut spent_coins = Vec::new();
let mut block_sigop_cost: u64 = 0;

// Assume-valid: skip script verification for blocks at or below the assume-valid height
let skip_scripts = match params.assumed_valid_height {
    Some(av_height) => height <= av_height,
    None => false,
};
```

**Impact:**
- **Side-chain attack vector**: A malicious peer that feeds a
  side-chain reorg block at `height <= assumed_valid_height` slips
  past script verification in rustoshi but is fully script-verified
  in Core. The attack surface is the entire IBD chain below the
  assume-valid height (testnet4: 123,613; mainnet:
  938,343-equivalent). Combined with BIP-30 short-circuit issues
  (W143 BUG-2) the side-chain attack surface is large.
- **No minimum-chain-work defense**: rustoshi cannot defend against
  the extortion-DoS where an attacker withholds work to make the
  node believe a low-work side chain is the canonical chain and
  skip script verification.
- **No equivalent-time defense**: rustoshi cannot defend against
  the "blocks just below the tip" extortion vector where an attacker
  serves freshly mined blocks at heights near the assume-valid
  marker.

This is a **defense-in-depth gap that becomes an exploit class
when combined with any chainwork/headers-tree manipulation**.

---

### BUG-4 — `ChainParams` has no `bip16_height` field — P2SH activation cannot be configured per network

**Severity:** P1
**File:** `crates/consensus/src/params.rs:492-498`
**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:85-86`
              (P2SH governed via `script_flag_exceptions` only)
              `bitcoin-core/src/validation.cpp:2262`
              (`flags |= SCRIPT_VERIFY_P2SH` unconditional)

**Description:**
Core's modern approach to P2SH is "always-on", with the BIP-16
exception block carved out via `script_flag_exceptions`. There is no
`BIP16Height` in Core's `Consensus::Params`. rustoshi's
`script_flags_for_height` hardcodes `verify_p2sh: true` — which
matches Core's "always-on" semantics — but the **`consensus_flags`
function** (BUG-1) hardcodes mainnet `173_805` (the documented BIP-16
activation height) and `1` for testnet4.

This causes:

- On any future network (signet, regtest, testnet3) the `consensus_flags`
  test-only function evaluates `height >= 173_805` and disables P2SH
  for all blocks below 173,805 — which is wrong for signet/regtest
  (P2SH active from h=1) and wrong for testnet3
  (active from h=1 per Core kernel/chainparams.cpp:212).
- No `bip16_height` field on `ChainParams` means a future patch that
  switches `script_flags_for_height` to "configurable bury" semantics
  has nowhere to read the height from.

**Excerpt (the gap):**
```rust
// params.rs:493-498
pub bip34_height: u32,
pub bip65_height: u32,
pub bip66_height: u32,
pub csv_height: u32,
pub segwit_height: u32,
pub taproot_height: u32,
// missing: pub bip16_height: u32,
//          pub script_flag_exceptions: HashMap<Hash256, ScriptFlags>,
```

**Impact:**
- Hardcoded `173_805` in `consensus_flags` blocks signet/regtest
  from being audited correctly via this function.
- New networks (e.g. a testnet5 spin-up) cannot configure P2SH
  activation per Core's pattern.
- The two-pipeline issue (BUG-1) is partly *caused* by this missing
  field: `consensus_flags` cannot read from `params` so it carries
  its own hardcoded constants.

---

### BUG-5 — `FindAndDelete` + `SCRIPT_ERR_SIG_FINDANDDELETE` consensus rule entirely absent

**Severity:** P1
**File:** `crates/consensus/src/script/interpreter.rs:1490-1610`
       (`OP_CHECKSIG` / `OP_CHECKSIGVERIFY` evaluation — no
       FindAndDelete call before the signature check)
       `crates/consensus/src/script/interpreter.rs:1750-1810`
       (`OP_CHECKMULTISIG` — same gap)
**Core ref:** `bitcoin-core/src/script/interpreter.cpp:321-333`
              (FindAndDelete inside `EvalChecksigPreTapscript`)
              `bitcoin-core/src/script/interpreter.cpp:1146-1149`
              (FindAndDelete inside `OP_CHECKMULTISIG`)

**Description:**
Pre-segwit (`SigVersion::BASE`) script evaluation in Core runs
`FindAndDelete` on the scriptCode to strip any embedded copy of the
signature **before** computing the sighash. If `FindAndDelete`
returns >0 (signature was found and stripped) AND
`SCRIPT_VERIFY_CONST_SCRIPTCODE` is in the flags, Core returns
`SCRIPT_ERR_SIG_FINDANDDELETE`. This is a defensive consensus rule
that prevents legacy scripts from embedding their own signatures.

rustoshi has:
- No `FindAndDelete` function.
- No `find_and_delete` helper in `script/interpreter.rs`.
- No `SigFindAndDelete` variant on `ScriptError`.
- `OP_CHECKSIG` / `OP_CHECKSIGVERIFY` / `OP_CHECKMULTISIG` in BASE
  sigversion compute the subscript via `get_subscript(full_script,
  ctx.codesep_pos)` — only stripping the prefix before the last
  OP_CODESEPARATOR — and pass the result directly to
  `checker.check_sig`. No signature-removal step.

**Excerpt (Core):**
```cpp
// interpreter.cpp:329-333
if (sigversion == SigVersion::BASE) {
    int found = FindAndDelete(scriptCode, CScript() << vchSig);
    if (found > 0 && (flags & SCRIPT_VERIFY_CONST_SCRIPTCODE))
        return set_error(serror, SCRIPT_ERR_SIG_FINDANDDELETE);
}
```

**Excerpt (rustoshi, OP_CHECKSIG path — no FindAndDelete):**
```rust
// interpreter.rs:1488-1510 (paraphrased)
// Compute the subscript starting after the last OP_CODESEPARATOR
let subscript = get_subscript(full_script, ctx.codesep_pos);
let sig = ctx.pop()?;
let pubkey = ctx.pop()?;
check_signature_encoding(&sig, ctx.flags)?;
check_pubkey_encoding(&pubkey, ctx.flags)?;
// … no FindAndDelete here …
let success = ctx.checker.check_sig(&sig, &pubkey, subscript, ctx.sig_version);
```

**Impact:**
- For **mainnet replay**, this has no historical effect — no
  confirmed block contains a script where the signature appears
  embedded in the scriptCode AND would have been removed by Core's
  FindAndDelete BEFORE the sighash is computed. (Such scripts are
  pathological, low-value, and were never used at scale.)
- For **fuzzing / adversarial inputs**, rustoshi can disagree with
  Core: a hand-crafted script that puts its own signature inside
  the scriptPubKey followed by `OP_CHECKSIG` will:
  - In Core: FindAndDelete strips the embedded sig from scriptCode,
    sighash is computed without it, signature is checked against the
    "stripped" sighash, succeeds or fails depending on the actual
    signature value.
  - In rustoshi: FindAndDelete is absent, scriptCode keeps the
    embedded sig, sighash is computed WITH it (different digest),
    signature check is against a different sighash → different
    accept/reject outcome.
- **`SCRIPT_VERIFY_CONST_SCRIPTCODE` is defined** (interpreter.rs:114)
  but only used at the `OP_CODESEPARATOR` check (interpreter.rs:1037).
  The companion FindAndDelete error path is dead — the flag does
  HALF its job. **Comment-as-confession candidate**: the flag is
  described as "OP_CODESEPARATOR and FindAndDelete fail any
  non-segwit scripts" (Core interpreter.h:130) but rustoshi
  implements only the first half.

---

### BUG-6 — `verify_discourage_upgradable_witness_program` returns `WitnessProgramLength` (wrong error variant)

**Severity:** P1
**File:** `crates/consensus/src/script/interpreter.rs:3017-3019,
       3025-3027`
**Core ref:** `bitcoin-core/src/script/interpreter.cpp:1993-1995`
              (`SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM`)

**Description:**
When `SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM` is set and
an unknown witness program is encountered, Core returns the
dedicated error variant
`SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM`. rustoshi conflates
this with `WitnessProgramLength`:

```rust
// interpreter.rs:3007-3027
} else if program.len() == 2 && program[0] == 0x4e && program[1] == 0x73 {
    // BIP-444 Pay-to-Anchor (P2A): OP_1 <0x4e73>. Always spendable;
    // the relay DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM flag does NOT
    // apply (Core script/interpreter.cpp:1990 returns true
    // unconditionally for P2A).
    Ok(())
} else {
    // v1 + non-32 (non-P2A) or taproot inactive: anyone-can-spend
    // per BIP-141 forward soft-fork compatibility, with optional
    // relay-only DISCOURAGE flag.
    if flags.verify_discourage_upgradable_witness_program {
        return Err(ScriptError::WitnessProgramLength);   // ← wrong variant
    }
    Ok(())
}
}
2..=16 => {
    // Future SegWit versions
    if flags.verify_discourage_upgradable_witness_program {
        return Err(ScriptError::WitnessProgramLength);   // ← wrong variant
    }
    Ok(())
}
```

The `ScriptError` enum has no `DiscourageUpgradableWitnessProgram`
variant (grep confirms — interpreter.rs:296 is `WitnessProgramLength`,
the program-size-wrong error). This conflates a relay-only
soft-fork discouragement signal with a hard length mismatch.

**Impact:**
- Test/diagnostic output collapses two distinct Core errors into
  one. Core fuzz vectors that distinguish them would fail rustoshi's
  outcome-matching.
- An interop layer that reads the script-error variant (RPC error
  strings, test fixtures) sees "Witness program wrong length" when
  Core sends "discouraged-upgradable-witness-program" — observably
  divergent for `testmempoolaccept` and similar RPCs.

---

### BUG-7 — `consensus_flags(height, testnet4)` hardcodes mainnet/testnet4 heights — unusable for signet, regtest, testnet3

**Severity:** P1
**File:** `crates/consensus/src/script/interpreter.rs:123-144`
**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp` —
              testnet3, signet, regtest all have distinct buried
              heights.

**Description:**
The `consensus_flags` function takes only `(height, testnet4: bool)`
— no `ChainParams`. The activation heights are hardcoded:

```rust
let p2sh_height = if testnet4 { 1 } else { 173_805 };
let bip66_height = if testnet4 { 1 } else { 363_725 };
let bip65_height = if testnet4 { 1 } else { 388_381 };
let csv_height = if testnet4 { 1 } else { 419_328 };
let segwit_height = if testnet4 { 1 } else { 481_824 };
let taproot_height = if testnet4 { 1 } else { 709_632 };
```

For **testnet3**:
- `bip66_height = 330_776` (Core kernel/chainparams.cpp:214)
- `bip65_height = 581_885`
- `csv_height = 770_112`
- `segwit_height = 834_624`

For **signet** (Core line 455-460): all = 1.
For **regtest** (Core line 311-316): all = 1.

`consensus_flags(height, false)` returns wrong activation status for
all three networks. The only saving grace is that **no production
caller exists** (BUG-1) — but the function is exported in
`script/mod.rs:67` and is reachable from external callers via
`rustoshi_consensus::ScriptFlags::consensus_flags`.

**Impact:**
- Any external consumer (fuzzer, diff-test harness) that calls
  `consensus_flags` on signet/regtest/testnet3 will receive wrong
  flag bits.
- Reinforces BUG-1: this function should be deleted, with all
  callers re-routed to `script_flags_for_height(height, &params)`.

---

### BUG-8 — `to_bits` uses 21 of 32 bit positions, no `MAX_SCRIPT_VERIFY_FLAGS_BITS` static-assert

**Severity:** P2
**File:** `crates/consensus/src/script/interpreter.rs:179-244`
**Core ref:** `bitcoin-core/src/script/interpreter.h:154-159`

**Description:**
Core enforces:
```cpp
static constexpr int MAX_SCRIPT_VERIFY_FLAGS_BITS = static_cast<int>(SCRIPT_VERIFY_END_MARKER);
static_assert(0 < MAX_SCRIPT_VERIFY_FLAGS_BITS && MAX_SCRIPT_VERIFY_FLAGS_BITS <= 63);
static constexpr script_verify_flags::value_type MAX_SCRIPT_VERIFY_FLAGS = ((script_verify_flags::value_type{1} << MAX_SCRIPT_VERIFY_FLAGS_BITS) - 1);
```

rustoshi's `to_bits` is a hand-rolled `u32` mapping with 21 named
positions (P2SH=0 … CONST_SCRIPTCODE=20). There is no static-assert
that the bit width fits, no compile-time check that a new flag added
to `ScriptFlags` is wired into `to_bits`, and no constant equivalent
to `MAX_SCRIPT_VERIFY_FLAGS`. If a future flag is appended without a
corresponding `to_bits` entry, `to_bits` silently drops it from the
cache key.

**Excerpt (rustoshi):**
```rust
// interpreter.rs:179-244 (paraphrased — 21 conditional sets)
pub fn to_bits(&self) -> u32 {
    let mut bits: u32 = 0;
    if self.verify_p2sh { bits |= 1 << 0; }
    if self.verify_dersig { bits |= 1 << 1; }
    // … 19 more …
    if self.verify_const_scriptcode { bits |= 1 << 20; }
    bits
}
```

**Impact:**
- Defensive-coding gap. A future contributor adding
  `verify_pay_to_anchor_strict` or similar to `ScriptFlags` without
  also extending `to_bits` will get sig-cache hits/misses keyed on
  stale bitmaps — wrong cache key, theoretically a soundness bug
  if any caller treats `to_bits` as canonical.

---

### BUG-9 — Taproot activation gated by `taproot_height` (height), not the exception-list approach Core uses

**Severity:** P2
**File:** `crates/consensus/src/params.rs:577` (`taproot_height = 709_632`)
       `crates/consensus/src/validation.rs:2362`
       (`verify_taproot: height >= params.taproot_height`)
**Core ref:** `bitcoin-core/src/validation.cpp:2262`
              (`SCRIPT_VERIFY_TAPROOT` unconditional; exception block
              carved via `script_flag_exceptions`)

**Description:**
Modern Core (post-Taproot-activation cleanup) sets
`SCRIPT_VERIFY_TAPROOT` *unconditionally* in `GetBlockScriptFlags` and
carves out the single Taproot exception block via
`script_flag_exceptions`. rustoshi gates Taproot on a hardcoded
height (`709_632`).

Consequences:

- **Identical net effect for h ≥ 709,632 and h < 692,263** —
  Core's "always-on minus exception" matches rustoshi's "on starting
  at 709,632" because all blocks below the exception block predate
  Taproot signaling.
- **Divergence for h in [692,264, 709,631]** — Core treats these as
  Taproot-active (709,631 of them are not the exception block).
  rustoshi treats them as Taproot-inactive (since
  height < taproot_height). A block in this range containing a v1
  witness program that fails BIP-341 rules:
  - **Core**: returns `set_error` (Taproot active, but rule fails).
  - **rustoshi**: returns `Ok(())` (Taproot pre-activation, anyone-
    can-spend semantics).
  → **block-acceptance divergence on mainnet reindex** for any
  taproot-violating tx in `[692,264, 709,631]`.

This is bounded because the network coordinated Taproot enforcement
at h=709,632 (versionbits min_activation_height) and no Taproot
spends were broadcast in that interval that actually fail BIP-341 —
but the *consensus rule* itself is divergent.

**Impact:**
- Mainnet reindex divergence on adversarially-constructed v1
  witness programs in `[692,264, 709,631]`.
- Cleaner long-term fix: switch
  `verify_taproot: true` unconditional and add a
  `script_flag_exceptions` map carving out h=692,263 (covered by
  BUG-2).

---

### BUG-10 — `MANDATORY_SCRIPT_VERIFY_FLAGS` named constant absent

**Severity:** P2
**File:** `crates/consensus/src/script/interpreter.rs:118-244`
       (no const set; mempool.rs:1912 hand-rolls the equivalent)
**Core ref:** `bitcoin-core/src/policy/policy.h:105-111`

**Description:**
Core exports `MANDATORY_SCRIPT_VERIFY_FLAGS` and
`STANDARD_SCRIPT_VERIFY_FLAGS` as named constants. rustoshi has only
`ScriptFlags::standard_flags()` (interpreter.rs:149) — the
"mandatory" set is hand-rolled inline at `mempool.rs:1912`:

```rust
// mempool.rs:1912-1921
let consensus_flags = ScriptFlags {
    verify_p2sh: true,
    verify_dersig: true,
    verify_checklocktimeverify: true,
    verify_checksequenceverify: true,
    verify_witness: true,
    verify_nulldummy: true,
    verify_taproot: true,
    ..Default::default()
};
```

Duplication-via-copy is brittle: if a future BIP softfork adds a new
mandatory flag, this site must be updated in lockstep with
`standard_flags`. There is no compile-time enforcement of the
relationship `STANDARD ⊇ MANDATORY`.

**Impact:**
- Hand-rolled "consensus" flags in mempool.rs:1912 risks drifting
  out of sync with `script_flags_for_height` and `standard_flags`.
  Both are correct today but require manual review on every
  softfork.
- Cleaner pattern: define
  `ScriptFlags::mandatory_flags()` and re-export, then write
  `standard_flags()` as `mandatory_flags() | { policy bits }`.

---

### BUG-11 — `STANDARD_NOT_MANDATORY_VERIFY_FLAGS` absent

**Severity:** P2
**File:** `crates/consensus/src/script/interpreter.rs:118-244`
**Core ref:** `bitcoin-core/src/policy/policy.h:135`

**Description:**
Core exports
`STANDARD_NOT_MANDATORY_VERIFY_FLAGS = STANDARD & ~MANDATORY` — the
policy-only delta used in `MemPoolAccept::PolicyScriptChecks` and the
`testmempoolaccept` RPC. rustoshi has no such constant — every caller
that wants to enforce policy-only flags must hand-roll the
subtraction.

**Impact:**
- Cosmetic / engineering-hygiene; reinforces BUG-10.

---

### BUG-12 — `consensus_flags` incorrectly classifies NULLFAIL + WITNESS_PUBKEYTYPE as consensus rules

**Severity:** P1
**File:** `crates/consensus/src/script/interpreter.rs:139-140`
**Core ref:** `bitcoin-core/src/validation.cpp:2250-2289`
              (`GetBlockScriptFlags` sets P2SH, DERSIG, CLTV, CSV,
              WITNESS, NULLDUMMY, TAPROOT — NOT NULLFAIL, NOT
              WITNESS_PUBKEYTYPE)
              `bitcoin-core/src/policy/policy.h:119-132`
              (STANDARD_SCRIPT_VERIFY_FLAGS includes NULLFAIL +
              WITNESS_PUBKEYTYPE)

**Description:**
The `consensus_flags` function (BUG-1) enables
`verify_nullfail` and `verify_witness_pubkeytype` at
`height >= segwit_height`. Both are **policy-only** in Core:

- **NULLFAIL** (BIP-146): when `CHECKMULTISIG` returns false, all
  signatures must be empty. Adopted as policy at the same time as
  SegWit but NOT a consensus rule — Core handles it as a
  `STANDARD` flag (policy.h:125).
- **WITNESS_PUBKEYTYPE** (BIP-141 rule 4): segwit-v0 P2WPKH pubkeys
  must be compressed. Also `STANDARD` only (policy.h:128).

The doc-comment at interpreter.rs:139-140 calls both
"activated with SegWit" — accurate as **policy** activation, but
miscategorised as **consensus**. If anyone wires `consensus_flags`
into block validation (per the lib.rs:24 hint), the node will
**reject Core-accepted blocks** containing:
- a CHECKMULTISIG that returns false with non-empty sigs (NULLFAIL
  fires);
- a P2WPKH spend with an uncompressed pubkey (WITNESS_PUBKEYTYPE
  fires).

Both are valid-on-mainnet edge cases that exist in historical
blocks.

**Impact:**
- The two-pipeline pattern (BUG-1) leaves a loaded gun: any
  contributor who refactors `connect_block_with_sequence_locks` to
  use `consensus_flags` (the documented function) will introduce a
  **block-rejection consensus split**.
- The minimal one-liner safety patch is renaming
  `consensus_flags` → `policy_for_block_height` or deleting it
  entirely.

---

### BUG-13 — No defense-in-depth Mandatory re-check after Standard pass

**Severity:** P2
**File:** `crates/consensus/src/validation.rs:1798-1820`
       (`connect_block_with_sequence_locks` script-verify loop)
**Core ref:** `bitcoin-core/src/validation.cpp:1135-1190`
              (`MemPoolAccept::PolicyScriptChecks` +
              `ConsensusScriptChecks`)

**Description:**
Core mempool admission does TWO passes:
1. `PolicyScriptChecks` with `STANDARD_SCRIPT_VERIFY_FLAGS` →
   failure → `TX_NOT_STANDARD`.
2. `ConsensusScriptChecks` with `MANDATORY_SCRIPT_VERIFY_FLAGS` →
   failure → real consensus bug.

rustoshi's **mempool path** does both (`mempool.rs:1885-1934` —
Gate 27 + Gate 28). But the **block path**
(`connect_block_with_sequence_locks`) runs only one pass with
`script_flags_for_height(height, params)`. There is no
defense-in-depth re-check: if a future bug in
`script_flags_for_height` over-relaxes a bit, no second pass catches
it.

**Excerpt:**
```rust
// validation.rs:1798-1819 — single pass
if !skip_scripts {
    let checker = TransactionSignatureChecker::new(tx, input_idx,
        coin.value, &spent_amounts, &spent_scripts);
    verify_script(
        &input.script_sig,
        &coin.script_pubkey,
        &input.witness,
        &flags,         // ← script_flags_for_height(height, params)
        &checker,
    ).map_err(|e| TxValidationError::ScriptFailed(e.to_string()))?;
}
```

**Impact:**
- No second-pass safety net for block validation. A bug in
  `script_flags_for_height` is silently consensus-relevant.
- Cosmetic vs. real-attack: low; defense-in-depth gap.

---

### BUG-14 — `verify_const_scriptcode` flag fires only on OP_CODESEPARATOR — FindAndDelete sub-rule unreachable

**Severity:** P2 (folds into BUG-5 as the same gap from the other end)
**File:** `crates/consensus/src/script/interpreter.rs:1035-1040`
**Core ref:** `bitcoin-core/src/script/interpreter.h:130-132`
              (flag description: "fail any non-segwit scripts with
              OP_CODESEPARATOR or FindAndDelete")

**Description:**
The flag bit `verify_const_scriptcode` is fully wired for the
OP_CODESEPARATOR-in-BASE rejection at interpreter.rs:1037, but the
companion FindAndDelete rule (when a sig is embedded in scriptCode)
is absent (BUG-5). The flag therefore does **half its documented job**
— a contributor who sees `verify_const_scriptcode = true` will assume
both sub-rules are enforced.

**Impact:**
- Re-states BUG-5 from the flag-side rather than the opcode-side.
- Doc-string in `ScriptFlags::verify_const_scriptcode` should be
  updated to clarify which half is implemented.

---

### BUG-15 — `ScriptFlags::default()` allows uninitialised script verification — no entry-point assertion

**Severity:** P2
**File:** `crates/consensus/src/script/interpreter.rs:70`
       (`#[derive(Default)]`)
       `crates/consensus/src/script/interpreter.rs:2540`
       (`verify_script` entry — no check that flags is non-empty)
**Core ref:** `bitcoin-core/src/script/interpreter.h:47`
              (`SCRIPT_VERIFY_NONE` is constructable; Core also
              accepts; but the calling convention is documented)

**Description:**
`ScriptFlags { Default }` returns `false` for every flag —
"anyone-can-spend" semantics for P2SH, witness, taproot, locktime
all disabled. If any caller passes `ScriptFlags::default()` to
`verify_script`, the resulting validation is effectively a syntactic
check only.

Two sites in tests deliberately use `ScriptFlags::default()`
(test_w127_taproot.rs:298, 349). The production path is
`script_flags_for_height` which never returns an all-zero
struct — but there is no `debug_assert!` or compile-time guard
that a production caller has actually populated the flags.

**Impact:**
- Defensive-coding gap. A future caller wiring
  `verify_script(... , &ScriptFlags::default(), ...)` from
  production code would silently disable all script checks.
- Cosmetic / hygiene-only; no current attack vector.

---

### BUG-16 — `to_bits` bit ordering is rustoshi-internal — not aligned with Core's enum order, blocks cache-key interop

**Severity:** P3
**File:** `crates/consensus/src/script/interpreter.rs:179-244`
**Core ref:** `bitcoin-core/src/script/interpreter.h:49-150`
              (enum order: P2SH=0, STRICTENC=1, DERSIG=2, LOW_S=3,
              NULLDUMMY=4, SIGPUSHONLY=5, MINIMALDATA=6, …)

**Description:**
rustoshi `to_bits` ordering:

| flag | rustoshi bit | Core enum value |
|------|--------------|-----------------|
| P2SH | 0 | 0 |
| DERSIG | 1 | 2 |
| CHECKLOCKTIMEVERIFY | 2 | 8 |
| CHECKSEQUENCEVERIFY | 3 | 9 |
| WITNESS | 4 | 10 |
| NULLDUMMY | 5 | 4 |
| NULLFAIL | 6 | 13 |
| WITNESS_PUBKEYTYPE | 7 | 14 |
| TAPROOT | 8 | 17 |
| STRICTENC | 9 | 1 |
| LOW_S | 10 | 3 |
| SIGPUSHONLY | 11 | 5 |
| MINIMALDATA | 12 | 6 |
| CLEANSTACK | 13 | 8 conflict! (CLTV is at 8 in Core) |
| DISCOURAGE_UPGRADABLE_NOPS | 14 | 7 |
| DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM | 15 | 11 |
| MINIMALIF | 16 | 12 |
| DISCOURAGE_UPGRADABLE_TAPROOT_VERSION | 17 | 18 |
| DISCOURAGE_OP_SUCCESS | 18 | 19 |
| DISCOURAGE_UPGRADABLE_PUBKEYTYPE | 19 | 20 |
| CONST_SCRIPTCODE | 20 | 16 |

The mappings are **completely scrambled**. A serialized
sig-cache from rustoshi cannot interop with a Core sig-cache (and
vice versa). For local-only sig-cache, ordering is irrelevant — but
documentation should call out the divergence.

**Impact:**
- Interop block. Any future feature that wants to share script-verify
  caches across implementations (or sync them via RPC) must
  re-derive the mapping.
- Low impact today; pure documentation/portability gap.

---

### BUG-17 — BIP-30 ↔ script-flag interaction undocumented

**Severity:** P3 (informational)
**File:** `crates/consensus/src/validation.rs:1574-1610`
       (BIP-30 short-circuit logic; does not reference script-flag
       exceptions)
**Core ref:** the BIP-16 exception block IS within the BIP-30
              short-circuit range; SCRIPT_VERIFY_NONE + BIP-30
              skip are independent but co-located in history.

**Description:**
The BIP-16 exception block hash
`00000000000002dc756e…` is at h=174,062. BIP-30 short-circuits at
h=227,931 (BIP-34). For mainnet replay of the window
`[174,062, 227,930]`, two distinct exceptions interact:
- BIP-16 exception → SCRIPT_VERIFY_NONE (no P2SH check).
- BIP-30 exception list → h=91842 + h=91880 (duplicates predate
  this window).

rustoshi has neither documented nor coded the BIP-16 exception
(BUG-2); the BIP-30 exception list is correctly modeled. The
comments around the BIP-30 short-circuit do not mention the BIP-16
script-flag exception — future contributors won't know to look for
it.

**Impact:**
- Documentation gap. Not a runtime bug per se; the runtime divergence
  is covered by BUG-2.

---

### BUG-18 — Test-only `consensus_flags` uses different height constants than production `script_flags_for_height`

**Severity:** P2
**File:** `crates/consensus/src/script/interpreter.rs:124-130`
       (hardcoded `173_805`, `363_725`, etc.)
       vs `crates/consensus/src/validation.rs:2348-2363`
       (reads from `params.bip66_height`, etc.)
**Core ref:** N/A — rustoshi-internal consistency issue.

**Description:**
Tests call `ScriptFlags::consensus_flags(height, false)` with
expectation that activation thresholds match mainnet. Production
calls `script_flags_for_height(height, &params)` where heights
come from `ChainParams` initialised in `params.rs:572-577`.

The values DO match today (`bip66_height = 363_725` in both places,
etc.) but they are independently maintained. A future patch that
shifts one (e.g. to fix a chain-params bug for a custom signet)
will leave the other stale, and tests will silently pass while
production diverges.

**Impact:**
- Hidden coupling between two source-of-truth locations for
  activation heights. Single point of failure on refactor.

---

### BUG-19 — P2A `IsPayToAnchor` is detected inside `verify_witness_program` but the discouragement gate matches Core only by coincidence

**Severity:** P3
**File:** `crates/consensus/src/script/interpreter.rs:3007-3012`
**Core ref:** `bitcoin-core/src/script/interpreter.cpp:1990-1991`
              (`IsPayToAnchor(witversion, program)` returns true
              unconditionally with no DISCOURAGE check)

**Description:**
rustoshi's v1 branch checks for P2A by directly inspecting program
bytes (`program[0] == 0x4e && program[1] == 0x73`) rather than
calling a named predicate `is_pay_to_anchor`. The semantics match
(P2A is always-spendable, DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
does not apply) — but the dispatch is inline:

```rust
} else if program.len() == 2 && program[0] == 0x4e && program[1] == 0x73 {
    // BIP-444 Pay-to-Anchor (P2A): OP_1 <0x4e73>. Always spendable;
    Ok(())
} else { ... }
```

The named predicate `is_p2a_program` exists (interpreter.rs:2446)
but is **not called here**. Inline-matching by literal bytes is
fragile if P2A semantics evolve (e.g. BIP-345 anchor variants).

**Impact:**
- Engineering hygiene; defensive-coding gap. Replace the inline byte
  match with `is_p2a_program(version, program)`.

---

### BUG-20 — Tapscript validation-weight budget gated on `flags.verify_taproot` only — Core consensus also requires versionbits-style activation

**Severity:** P3
**File:** `crates/consensus/src/script/interpreter.rs:2785-2815`
       (entry into v1+32+!is_p2sh Taproot path)
**Core ref:** `bitcoin-core/src/script/interpreter.cpp:1947-1949`

**Description:**
Per Core, the v1+32+!is_p2sh combination ALWAYS enters
`VerifyWitnessProgram`, and the gate `(!(flags &
SCRIPT_VERIFY_TAPROOT))` returns `set_success(serror)` early. The
validation-weight budget (BIP-342) is initialised AFTER this gate.

rustoshi matches:
```rust
if program.len() == WITNESS_V1_TAPROOT_SIZE && !is_p2sh {
    if !flags.verify_taproot {
        return Ok(());  // ← anyone-can-spend (correct)
    }
    // …weight budget logic continues
}
```

The check at line 2811 (`!flags.verify_taproot → Ok(())`) is
correct. **However**, the **height-gated** taproot_height (BUG-9)
means the flag itself is wrong: for heights in `[692,264, 709,631]`
Core sets `verify_taproot=true` (taproot active) but rustoshi has
`verify_taproot=false`. So an unspendable / discouraged Tapscript in
this window:
- Core: hits the budget check, may fail validation.
- rustoshi: returns `Ok(())` immediately — anyone-can-spend.

This is the same divergence as BUG-9, re-stated for the tapscript
path.

**Impact:**
- Folds into BUG-9.

---

### BUG-21 — `SCRIPT_VERIFY_END_MARKER`/`MAX_SCRIPT_VERIFY_FLAGS` static-assert absent

**Severity:** P3
**File:** `crates/consensus/src/script/interpreter.rs:70-116`
**Core ref:** `bitcoin-core/src/script/interpreter.h:148-159`

**Description:**
Core has:
```cpp
SCRIPT_VERIFY_END_MARKER
};
static constexpr int MAX_SCRIPT_VERIFY_FLAGS_BITS = static_cast<int>(SCRIPT_VERIFY_END_MARKER);
static_assert(0 < MAX_SCRIPT_VERIFY_FLAGS_BITS && MAX_SCRIPT_VERIFY_FLAGS_BITS <= 63);
```

— a compile-time guard that the flag width fits in 63 bits. rustoshi
has no equivalent. The `ScriptFlags` struct uses `bool` fields, so
the absolute width is unbounded in principle, but `to_bits` returns
`u32` — silently dropping any flag added beyond bit 31. Defensive-
coding gap.

**Impact:**
- Future-proofing. Unlikely to bite today (only 21 flags); will
  bite if BIPs continue to ship.

---

### BUG-22 — `verify_script` accepts default-constructed `ScriptFlags{}` — no entry-side validation

**Severity:** P3 (folds with BUG-15)
**File:** `crates/consensus/src/script/interpreter.rs:2540` (entry)
**Core ref:** N/A (Core accepts SCRIPT_VERIFY_NONE; this is a
              rustoshi-internal defensive option)

**Description:**
The entry function `verify_script(script_sig, script_pubkey, witness,
flags, checker)` has no `debug_assert!` on `flags`. A caller passing
`ScriptFlags::default()` runs an empty-bitmask validation — anyone-
can-spend semantics. Currently no production caller does this, but
the absence of an entry-side assertion means a future refactor that
accidentally drops the `script_flags_for_height` call (and passes
default flags) would silently bypass all consensus checks.

**Impact:**
- Pure hygiene; reinforces BUG-15.

## Fleet-pattern smell

This audit confirms or extends the following cross-impl patterns:

1. **Two-pipeline guard** — 7th distinct extension inside rustoshi
   (per memory log: W117/W118/W137/W141/W143). The
   `consensus_flags`/`script_flags_for_height` pair fits the same
   shape as `contextual_check_block_header`/inline-header-sync
   (W143 BUG-1).

2. **Comment-as-confession** — lib.rs:24 actively misdirects future
   contributors at the WRONG entry point. 4th distinct instance in
   rustoshi (per memory log: W141 zmq.rs:271-275 + W143 BUG-2 +
   W124 RPC-error mapping).

3. **Well-engineered helper + dead-callsite** — `consensus_flags`
   has 11 test callers and zero production callers. Same shape as
   `contextual_check_block_header` (W143 BUG-1),
   `MaybeSendFeeFilter`/`InventoryTrickle` (W136 BUG-1..4).

4. **Already-exports-the-primitive-just-not-called** —
   `verify_const_scriptcode` flag is wired for half its rule
   (OP_CODESEPARATOR) but absent for the FindAndDelete half. Same
   shape as W140 BUG-5 haskoin `constantTimeEq` exported + not
   called.

5. **DEAD FIELD** — `taproot_height = 709_632` is read by
   `script_flags_for_height`, but the **proper Core-parity primitive**
   (`script_flag_exceptions`) is entirely absent from
   `ChainParams`. Cross-impl: same pattern as W140 haskoin
   `rpcAllowIp` (defined, defaulted, never read).

6. **30-of-30-gates-buggy candidate (negative)** — 17 of 30 gates
   show BUGs. Not the "subsystem rewrite" threshold (per W138
   clearbit + W139 lunarblock + W141 clearbit each at 30-of-30)
   but a high-density divergence cluster.
