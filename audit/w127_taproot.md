# W127 — Taproot / Schnorr / Tapscript audit (rustoshi)

**Wave:** W127 — BIP-340 Schnorr / BIP-341 Taproot / BIP-342 Tapscript (DISCOVERY)
**Date:** 2026-05-17
**Audit subject:** the rustoshi consensus Taproot/tapscript verifier:
- `crates/consensus/src/script/interpreter.rs` (~6,060 LOC) —
  `verify_witness_program` v1 path, `eval_script_tapscript`,
  `eval_script_internal` OP_CHECKSIG/OP_CHECKSIGVERIFY/OP_CHECKSIGADD
  branches, `scan_for_op_success`, `TapscriptCtx`, validation-weight
  accounting, MINIMALIF in tapscript context.
- `crates/consensus/src/script/taproot_sighash.rs` — re-exports of the
  canonical `rustoshi_crypto::taproot` helpers.
- `crates/consensus/src/script/opcodes.rs` — `OP_CHECKSIGADD` (0xba),
  `is_tapscript_success_byte` (BIP-342 IsOpSuccess).
- `crates/consensus/src/validation.rs` — `TransactionSignatureChecker`:
  `check_schnorr_sig` (key-path, ext_flag=0) +
  `check_schnorr_sig_tapscript` (script-path, ext_flag=1) sharing
  `check_schnorr_inner`.
- `crates/crypto/src/taproot.rs` — canonical primitives:
  `compute_tapleaf_hash`, `compute_tapbranch_hash`,
  `compute_taproot_tweak_hash`, `compute_taproot_output_key`,
  `compute_taproot_sighash`, `build_sig_msg`, `write_compact_size`.
- `crates/consensus/src/params.rs` — Taproot/tapscript constants
  (`TAPROOT_LEAF_MASK = 0xfe`, `TAPROOT_LEAF_TAPSCRIPT = 0xc0`,
  `TAPROOT_CONTROL_BASE_SIZE = 33`, `TAPROOT_CONTROL_NODE_SIZE = 32`,
  `TAPROOT_CONTROL_MAX_NODE_COUNT = 128`, `TAPROOT_CONTROL_MAX_SIZE = 4129`,
  `WITNESS_V1_TAPROOT_SIZE = 32`, `ANNEX_TAG = 0x50`,
  `VALIDATION_WEIGHT_PER_SIGOP_PASSED = 50`, `VALIDATION_WEIGHT_OFFSET = 50`).

**References:**
- `bitcoin-core/src/script/interpreter.cpp`:
  - `EvalChecksigTapscript` (lines 347-385)
  - `SignatureHashSchnorr` (lines 1483-1570)
  - `CheckSchnorrSignature` (lines 1717-1742)
  - `ComputeTapleafHash` / `ComputeTapbranchHash` / `ComputeTaprootMerkleRoot`
    (lines 1872-1901)
  - `VerifyTaprootCommitment` (lines 1903-1915)
  - `VerifyWitnessProgram` v1 path (lines 1947-1999)
  - `ExecuteWitnessScript` (lines 1832-1870)
- `bitcoin-core/src/script/interpreter.h:241-246` — constants
- `bitcoin-core/src/script/script.cpp:364` — `IsOpSuccess`
- `bitcoin-core/src/script/script.h:61-64` — VALIDATION_WEIGHT_*
- `bitcoin-core/src/pubkey.cpp:230-260` — `XOnlyPubKey::IsFullyValid`,
  `CheckTapTweak`
- BIPs **340**, **341**, **342**.

**Production code changes:** 0 (pure audit).
**Test file:** `crates/consensus/tests/test_w127_taproot.rs` — 30 gates,
PASS regression pins + `#[ignore]`-pinned BUG-N stubs.

## Why this matters

Taproot is the largest live consensus surface still under flux: every
mainnet block since height 709,632 may include Schnorr/tapscript inputs
(now ~30-40 % of inputs in 2026). A divergence in any of:

1. **Schnorr signature verification** (BIP-340 lift_x, SIGHASH_DEFAULT
   vs SIGHASH_ALL byte handling, sighash extension fields)
2. **Taproot output-key tweak** (key-path vs script-path tweak
   construction, parity bit handling)
3. **Tapscript control block validation** (33-4129 byte range, leaf
   version masking, merkle path length, parity)
4. **Tapscript opcode set** (OP_CHECKSIGADD, OP_SUCCESS pre-scan,
   disabled CHECKMULTISIG, MAX_STACK_SIZE at entry)
5. **BIP-342 validation-weight budget** (50-unit decrement per non-empty
   sigop, regardless of pubkey-type branch)
6. **key_version 0x01** vs unknown pubkey-type handling
   (`success = !sig.empty()` semantics)

...produces a mainnet chain split. Every W127 gate is therefore
P0-CONSENSUS / P0-CDIV unless explicitly downgraded.

The cluster of historical bugs at clearbit (`h=947960`, single-byte
CompactSize encoder hitting Ordinals tapscripts >65535B → wrong tapleaf
hash → wrong merkle root → wrong tweak), and the closely-related
mainnet-944279 inscription tapscript (>10 KB tapscript, would have
tripped `MAX_SCRIPT_SIZE` if rustoshi hadn't gated that on
`Base | WitnessV0`), are the exact failure-mode templates we audit
against here.

## Headline findings

- **Zero P0-CONSENSUS bugs.** Every active code-path-decision gate is
  PRESENT and aligned with Core. The W94 / W95 regression suites
  (already in `crates/consensus/src/script/interpreter.rs::tests`)
  cover the highest-risk gates (control-block size, leaf-version
  dispatch, OP_SUCCESS pre-scan, BIP-342 validation-weight, MINIMALIF,
  unknown-pubkey-type branching).

- **2 P2 cosmetic / error-name divergences** with no consensus impact
  (script accept/reject decisions match Core; only the rejection-reason
  string differs):
  - **BUG-1** (P2): Invalid non-empty Schnorr signature in **tapscript**
    OP_CHECKSIG/CHECKSIGVERIFY/CHECKSIGADD reports `ScriptError::NullFail`
    instead of Core's `SCRIPT_ERR_SCHNORR_SIG`. Both reject. Surfaces in
    error-name parity vectors (script_assets_test.json `flags = ""`
    cases). Sites: `interpreter.rs:1564-1566` (CHECKSIG),
    `1646-1648` (CHECKSIGVERIFY), `2047-2049` (CHECKSIGADD).
  - **BUG-2** (P2): Schnorr sighash computation failure (e.g.
    SIGHASH_SINGLE with no matching output, invalid hash_type) reports
    `ScriptError::EvalFalse` (key-path) or `ScriptError::NullFail`
    (script-path) instead of Core's `SCRIPT_ERR_SCHNORR_SIG_HASHTYPE`.
    Site: `validation.rs:2655-2665` (`check_schnorr_inner` returns
    `false` on `compute_taproot_sighash` Err, collapsing distinct error
    causes).

- **1 P3 unreachable-but-divergent corner**:
  - **BUG-3** (P3, COSMETIC): P2SH-wrapped Pay-to-Anchor (P2A, v1 +
    program `0x4e73`, `is_p2sh=true`) returns `Ok(())` unconditionally
    instead of falling through to the upgradable-witness-program
    DISCOURAGE path. Core (`interpreter.cpp:1990`) gates the P2A
    success on `!is_p2sh && IsPayToAnchor(...)`; rustoshi
    (`interpreter.rs:3007-3012`) checks the program bytes alone. In
    practice this case is unreachable from real-world blockchain data
    (P2A is a native witness output by design; you cannot construct a
    P2SH-wrapped P2A scriptPubKey), but it is a real code-path
    divergence. Standardness-only impact even if reachable
    (DISCOURAGE is policy).

- **3 P3 surface-area / documentation findings**:
  - **BUG-4** (P3, COSMETIC): `validation.rs:2468-2471` `check_sig`
    legacy path's tapscript arm has the comment "Tapscript uses BIP-341
    sighash (not implemented yet)" — but it IS implemented via the
    separate `check_schnorr_sig_tapscript` Schnorr path. The legacy
    `check_sig` is correctly never invoked for `SigVersion::Tapscript`
    (the tapscript opcode handlers in `interpreter.rs:1551-1557, 1636-
    1642, 2021-2027` route to `check_schnorr_sig_tapscript`). Risk:
    confusing future readers; the early-return `false` would be a
    silent consensus failure if a future refactor accidentally dispatched
    tapscript sigops through legacy `check_sig`. Pattern:
    **dead-defensive-return** that masks intent.
  - **BUG-5** (P3, COSMETIC): `interpreter.rs:1559-1563`,
    `1643-1645`, `2028-2030` each contain a defensive
    `} else { false }` branch that fires when `ctx.tapscript.is_none()`
    — i.e. someone called `eval_script_internal` with
    `SigVersion::Tapscript` but without setting up a `TapscriptCtx`.
    Core does not have this branch (it ASSERTs
    `m_validation_weight_left_init` at line 361 and the
    `m_tapleaf_hash_init` at line 1561). The defensive `false` is a
    silent fail-closed rather than an assertion. Risk: an internal-API
    misuse propagates as a misleading "NullFail" rather than a clear
    panic. Pattern: **silent-defensive-fail-closed** vs Core's
    `assert(...)`.
  - **BUG-6** (P3, COSMETIC): `script/mod.rs:65-72` does not
    re-export `eval_script_tapscript`, `TapscriptCtx`,
    `verify_witness_program`, `get_serialize_size_of_witness_stack`,
    `is_p2a`, `is_p2a_program`, `parse_witness_program`,
    `compact_size_len`, or any of the Taproot constants
    (`TAPROOT_LEAF_TAPSCRIPT`, `TAPROOT_CONTROL_BASE_SIZE`, etc.). The
    constants are reachable only via `rustoshi_consensus::script::interpreter::*`
    (the inner module is `pub`, so this works) but the surface looks
    cosmetically inconsistent — `is_p2tr` is re-exported,
    `is_p2a` is not. Cross-impl audits keying off the `script::*`
    namespace miss tapscript primitives that exist but are buried.

## Gate summary (30/30)

| # | Surface | Status | Code | Severity |
|---|---------|--------|------|----------|
| G1  | `TAPROOT_LEAF_MASK = 0xfe` constant | OK | — | — |
| G2  | `TAPROOT_LEAF_TAPSCRIPT = 0xc0` constant | OK | — | — |
| G3  | `TAPROOT_CONTROL_BASE_SIZE = 33` | OK | — | — |
| G4  | `TAPROOT_CONTROL_NODE_SIZE = 32` | OK | — | — |
| G5  | `TAPROOT_CONTROL_MAX_SIZE = 4129` | OK | — | — |
| G6  | `WITNESS_V1_TAPROOT_SIZE = 32` | OK | — | — |
| G7  | `ANNEX_TAG = 0x50` | OK | — | — |
| G8  | `VALIDATION_WEIGHT_OFFSET = 50` | OK | — | — |
| G9  | `VALIDATION_WEIGHT_PER_SIGOP_PASSED = 50` | OK | — | — |
| G10 | `is_p2tr` detection (OP_1 + push-32) | OK | — | — |
| G11 | `verify_taproot=false` → unconditional success on v1+32+!p2sh | OK | — | — |
| G12 | P2SH-wrapped Taproot (v1+32, is_p2sh=true) falls through | OK | — | — |
| G13 | empty witness on v1+32+!p2sh → `WitnessProgramWitnessEmpty` | OK | — | — |
| G14 | annex detection (last item starts with 0x50, len>=2) | OK | — | — |
| G15 | key-path Schnorr verify against witness program (xonly) | OK | — | — |
| G16 | control block size in [33, 4129] AND (size-33)%32==0 | OK | — | — |
| G17 | control block out-of-range → `TaprootWrongControlSize` | OK | — | — |
| G18 | leaf version masking `control[0] & 0xfe` | OK | — | — |
| G19 | tapleaf hash via canonical `compute_tapleaf_hash` (BIP-341) | OK | — | — |
| G20 | tapbranch combine, lex-sorted (BIP-341) | OK | — | — |
| G21 | taproot tweak (`taproot_output_key` = `internal_key + H(internal||root)*G`) | OK | — | — |
| G22 | parity-bit verification (output_parity vs control[0]&1) | OK | — | — |
| G23 | leaf_version==0xc0 → execute tapscript (BIP-342) | OK | — | — |
| G24 | unknown leaf version → anyone-can-spend (no DISCOURAGE = pass) | OK | — | — |
| G25 | unknown leaf version + DISCOURAGE → `DiscourageUpgradableTaprootVersion` | OK | — | — |
| G26 | OP_CHECKSIGADD opcode = 0xba | OK | — | — |
| G27 | OP_SUCCESS pre-scan (BIP-342 IsOpSuccess bytes) | OK | — | — |
| G28 | OP_SUCCESS + `verify_discourage_op_success` → `DiscourageOpSuccess` | OK | — | — |
| G29 | OP_CHECKMULTISIG / OP_CHECKMULTISIGVERIFY disabled in tapscript | OK | — | — |
| G30 | BIP-342 validation-weight decrement on non-empty sig (key version 0x01 included) | OK | — | — |

Additional cross-cut checks (covered by W94/W95 regression suites in
`interpreter.rs::tests` rather than new gates here):
- Initial stack size cap at tapscript entry → `StackOverflow`
- Per-element size cap at tapscript entry → `PushSize`
- OP_SUCCESS overrides element-size cap
- Unknown-pubkey-type (size != 0 and != 32) BIP-342 success semantics
- DISCOURAGE_UPGRADABLE_PUBKEYTYPE relay-only rejection
- MINIMALIF unconditional in tapscript, flag-gated in WitnessV0
- MAX_SCRIPT_SIZE / MAX_OPS_PER_SCRIPT gated on Base|WitnessV0 only
  (tapscript has no opcode limit)
- BIP-341 sighash matches `bip341_wallet_vectors.json` (validated
  2026-04-28 via `tools/bip341-vector-runner/`)

## Cross-cutting notes

### Why no P0-CDIV findings

Rustoshi's Taproot surface received an intense W94/W95 audit pass (see
`interpreter.rs:5497-6056` and `tests/script_vectors.rs`) that already
closed every consensus-critical gate. Specifically:
- Control-block size bounds and `TaprootWrongControlSize` distinct
  error.
- `WitnessProgramWitnessEmpty` distinct error vs generic mismatch.
- `is_p2sh` gating of v1+32 Taproot (W94 Bug #1).
- Pre-activation `verify_taproot=false` short-circuit (W94 Bug #6).
- Unknown leaf-version anyone-can-spend semantics (W94 Bug #5).
- Tapscript entry-time stack-size + element-size caps (W94 Bugs #7/#8).
- OP_SUCCESS overrides element-size cap (W94 Bug #8 corollary).
- BIP-342 unknown-pubkey-type `success = !sig.empty()` semantics for
  OP_CHECKSIG / OP_CHECKSIGVERIFY / OP_CHECKSIGADD (W95).
- BIP-342 validation-weight decrement on EVERY non-empty signature
  (including unknown-pubkey path, per Core comment "Passing with an
  upgradable public key version is also counted").
- DISCOURAGE_UPGRADABLE_PUBKEYTYPE rejection for tapscript unknown
  pubkey type (Core lines 379-381).
- MINIMALIF unconditional in tapscript (Core line 614).
- `is_tapscript_success_byte` dispatches off the raw byte (not the
  parsed Opcode enum, which collapses 0xbb..=0xfe to OP_INVALIDOPCODE).
- `compact_size_len` + `get_serialize_size_of_witness_stack` match
  Core's `::GetSerializeSize(witness.stack)` byte-for-byte.

The CompactSize-encoder bug class that hit clearbit at `h=947,960` is
also closed in rustoshi: `rustoshi_crypto::taproot::write_compact_size`
covers all four size classes (`<0xfd`, `<=0xffff`, `<=0xffffffff`,
full u64), with a regression test pinning the 65,536-byte boundary
(`crates/crypto/src/taproot.rs:425-445`).

The W127 audit therefore reads as a *regression pin* — its primary
deliverable is the 30-gate test matrix that captures the current
correctness and locks it against future drift. Every PRESENT gate
becomes a forward-regression guard.

### Patterns observed

1. **Canonical helper unification (W27-C).** The Taproot primitives
   live in `rustoshi-crypto` and are re-exported by
   `consensus::script::taproot_sighash`. The wallet (`descriptor.rs`)
   does NOT carry a duplicate `compute_tapleaf_hash` — this is the
   exact bug class that hit clearbit. Pattern: **single source of
   truth for crypto primitives, dependency edge crypto ← {consensus,
   wallet} keeps the wallet from re-implementing.**

2. **Dispatch-off-raw-byte for OP_SUCCESS.** `is_tapscript_success_byte`
   takes a `u8` (not an `Opcode`) because `Opcode::from_u8` collapses
   0xbb..=0xfe to `OP_INVALIDOPCODE`, losing the original byte
   identity. Without this, a tapscript containing an undefined opcode
   in the OP_SUCCESS range (e.g. 0xbd) would have been rejected as
   `BadOpcode` instead of succeeding unconditionally. Pattern:
   **never parse-then-test for soft-fork-success ranges; the parser
   is lossy.**

3. **Pre-scan before stack-size check.** `eval_script_tapscript`
   pre-scans for OP_SUCCESS BEFORE checking
   `stack.len() > MAX_STACK_SIZE` — because OP_SUCCESS "overrides
   everything, including stack element size limits"
   (Core `interpreter.cpp:1837` comment). Without this ordering, a
   tapscript with a witness stack of 1001 items that triggers
   OP_SUCCESS would have been rejected at the stack cap, diverging
   from Core. Pattern: **soft-fork-success short-circuit must come
   first.**

4. **Validation-weight decrement BEFORE pubkey-size branching.**
   `consume_validation_weight()` fires at `interpreter.rs:1537-1539`
   (CHECKSIG) BEFORE the `if pubkey.len() == 32 { ... } else { ... }`
   branching. This is what Core's comment at `interpreter.cpp:360`
   ("Passing with an upgradable public key version is also counted")
   demands. A naive impl that decrements only inside the 32-byte
   branch would have given attackers a free sigop with an unknown
   pubkey type. Pattern: **count first, branch second.**

5. **Forward-regression via source-grep guards.** `interpreter.rs`
   carries inline assertions like the W94 constant-check
   (`fn w94_taproot_constants_match_core`) that pin every numeric
   constant against Core. If any of these drift, the test fails.
   Pattern: **lock the constants, not just the behavior.**

### Recommendations (deferred follow-on, not in scope for W127)

- **FIX target 1 (P2, BUG-1):** map tapscript invalid-non-empty-sig to
  a new `ScriptError::SchnorrSig` (or rename `NullFail` → behavior
  unchanged) so script_assets_test.json `flags=""` vectors match Core
  byte-for-byte. Currently rustoshi rejects but with a different error
  string. Single-impl, single-file change in `interpreter.rs` (3 sites).

- **FIX target 2 (P2, BUG-2):** add a dedicated
  `ScriptError::SchnorrSigHashType` and route
  `check_schnorr_inner`'s `compute_taproot_sighash` Err arm to it
  instead of collapsing to a generic `false`. Requires adding the new
  enum variant + plumbing the failure cause out of `check_schnorr_inner`
  (via Result instead of bool).

- **FIX target 3 (P3, BUG-3):** add `&& !is_p2sh` to the P2A check at
  `interpreter.rs:3007`. Unreachable in practice (no real-world P2SH-
  wrapped P2A), but mechanically aligns with Core's
  `!is_p2sh && IsPayToAnchor(...)` gate. One-line change.

- **FIX target 4 (P3, BUG-4):** delete the dead "(not implemented
  yet)" comment at `validation.rs:2468-2471` or, better, replace the
  early-return `false` with `unreachable!()` to make the dispatch
  intent explicit (tapscript should NEVER reach legacy `check_sig`).

- **FIX target 5 (P3, BUG-5):** replace the three
  `} else { false }` arms in OP_CHECKSIG / OP_CHECKSIGVERIFY /
  OP_CHECKSIGADD tapscript branches with `unreachable!()` or
  `debug_assert!(false, ...)`. The branch is only reachable via
  internal-API misuse (calling `eval_script` instead of
  `eval_script_tapscript` for a tapscript leaf).

- **FIX target 6 (P3, BUG-6):** re-export
  `eval_script_tapscript`, `TapscriptCtx`, `verify_witness_program`,
  `is_p2a`, `is_p2a_program`, `parse_witness_program`,
  `compact_size_len`, `get_serialize_size_of_witness_stack` from
  `script::mod.rs`, plus the Taproot constants from `params.rs`.

## Cumulative project context

- 65 consecutive clean fix waves; 53 discovery waves preceding W127.
- W127 is the first dedicated Taproot/Schnorr/Tapscript audit on
  rustoshi. The W94 (BIP-141/341 dispatch) + W95 (BIP-342 unknown
  pubkey type) regression suites cover the highest-risk gates already.
- Cross-impl pattern: every impl that has reached this stack
  (rustoshi, blockbrew, ouroboros) has accumulated a similar W94/W95-
  shaped pre-existing closure body. Rustoshi differs in being most
  granular (88 inline tests just for tapscript dispatch).

## Test file

See `crates/consensus/tests/test_w127_taproot.rs`. 30 gates total —
all PRESENT, so all are PASS regression pins. The 6 BUG-N follow-on
recommendations are not gates in this file (they are cosmetic /
error-code / unreachable-corner issues that don't change accept/reject
decisions); they are documented above for future single-impl fix waves.
