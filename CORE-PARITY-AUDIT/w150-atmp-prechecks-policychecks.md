# W150 — AcceptToMemoryPool + PreChecks + PolicyScriptChecks + ConsensusScriptChecks (rustoshi)

**Wave:** W150 — `MemPoolAccept::AcceptToMemoryPool` / `AcceptSingleTransactionInternal`,
`MemPoolAccept::PreChecks` (~782-981), `MemPoolAccept::PolicyScriptChecks`
(~1135-1156, `STANDARD_SCRIPT_VERIFY_FLAGS`),
`MemPoolAccept::ConsensusScriptChecks` (~1158-1189,
`GetBlockScriptFlags(tip)` re-check), `MemPoolAccept::Finalize` /
`SubmitPackage`, `IsStandardTx` / `AreInputsStandard` / `IsWitnessStandard`,
`MIN_STANDARD_TX_NONWITNESS_SIZE`, `MAX_STANDARD_TX_WEIGHT`,
`MAX_STANDARD_TX_SIGOPS_COST`, `DUST_RELAY_TX_FEE`, `GetDustThreshold`,
`-minrelaytxfee` / `-incrementalrelayfee` / `-dustrelayfee` /
`-acceptnonstdtxn` / `-permitbaremultisig` / `-datacarriersize` /
`-maxmempool` / `-mempoolexpiry` operator knobs, reject-token wire format,
RBF detection.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/validation.cpp:782-981` — `MemPoolAccept::PreChecks`:
  CheckTransaction (798), coinbase reject (803-804),
  IsStandardTx if `require_standard` (807-810),
  `MIN_STANDARD_TX_NONWITNESS_SIZE=65` always (812-814),
  `CheckFinalTxAtTip` (819-821), wtxid duplicate → `txn-already-in-mempool`
  (823-825), txid duplicate → `txn-same-nonwitness-data-in-mempool` (826-829),
  conflict loop / `m_allow_replacement` → `bip125-replacement-disallowed`
  (832-843), inputs exist / orphan / `txn-already-known` (847-868),
  `CheckSequenceLocksAtTip` (886-889) **BEFORE** CheckTxInputs,
  `Consensus::CheckTxInputs` (892), `ValidateInputsStandardness` if
  `require_standard` (897-901), `IsWitnessStandard` if `require_standard`
  (903-906), `GetTransactionSigOpCost(tx, view, STANDARD_SCRIPT_VERIFY_FLAGS)`
  (908), `fSpendsCoinbase` tracking (913-918), `entry_sequence = bypass_limits ? 0
  : m_pool.GetSequence()` (923), `PreCheckEphemeralTx` if `require_standard`
  (935-939), `MAX_STANDARD_TX_SIGOPS_COST` policy cap (941-943),
  `CheckFeeRate(vsize, modified_fees, ::nMinRelayTxFee)` unless `bypass_limits ||
  package_feerates` (948), `SingleTRUCChecks` (956).
- `bitcoin-core/src/validation.cpp:1135-1156` — `PolicyScriptChecks`:
  `CheckInputScripts(tx, state, m_view, STANDARD_SCRIPT_VERIFY_FLAGS, true,
  false, ws.m_precomputed_txdata, GetValidationCache())`; on failure tests
  `SpendsNonAnchorWitnessProg` and emits `TX_WITNESS_STRIPPED` for p2p
  rejection-cache parity.
- `bitcoin-core/src/validation.cpp:1158-1189` — `ConsensusScriptChecks`:
  computes `currentBlockScriptVerifyFlags =
  GetBlockScriptFlags(*m_active_chainstate.m_chain.Tip(),
  m_active_chainstate.m_chainman)` and re-runs the check via
  `CheckInputsFromMempoolAndCache`. Critically uses **TIP-DERIVED** flags
  (post-soft-fork-activation) not a static MANDATORY constant — at heights
  near a soft-fork boundary the tip-flags can differ from
  `MANDATORY_SCRIPT_VERIFY_FLAGS`.
- `bitcoin-core/src/policy/policy.h:48` — `DEFAULT_INCREMENTAL_RELAY_FEE = 100`
  (sat/kvB), `:70` — `DEFAULT_MIN_RELAY_TX_FEE = 100` (sat/kvB), `:68` —
  `DUST_RELAY_TX_FEE = 3000` (sat/kvB), `:38` — `MAX_STANDARD_TX_WEIGHT
  = 400000`, `:40` — `MIN_STANDARD_TX_NONWITNESS_SIZE = 65`, `:42` —
  `MAX_P2SH_SIGOPS = 15`, `:52` — `DEFAULT_PERMIT_BAREMULTISIG = true`,
  `:90` — `EXTRA_DESCENDANT_TX_SIZE_LIMIT = 10000`.
- `bitcoin-core/src/policy/policy.h:105-111` —
  `MANDATORY_SCRIPT_VERIFY_FLAGS = P2SH | DERSIG | NULLDUMMY | CLTV | CSV |
  WITNESS | TAPROOT` (7 flags; explicitly EXCLUDES NULLFAIL, STRICTENC,
  CLEANSTACK, MINIMALDATA, MINIMALIF, LOW_S, WITNESS_PUBKEYTYPE,
  CONST_SCRIPTCODE, DISCOURAGE_*).
- `bitcoin-core/src/policy/policy.h:119-132` —
  `STANDARD_SCRIPT_VERIFY_FLAGS = MANDATORY | STRICTENC | MINIMALDATA |
  DISCOURAGE_UPGRADABLE_NOPS | CLEANSTACK | MINIMALIF | NULLFAIL | LOW_S |
  DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM | WITNESS_PUBKEYTYPE | CONST_SCRIPTCODE |
  DISCOURAGE_UPGRADABLE_TAPROOT_VERSION | DISCOURAGE_OP_SUCCESS |
  DISCOURAGE_UPGRADABLE_PUBKEYTYPE` (20 flags). **Excludes SIGPUSHONLY** —
  Core does NOT enable SIGPUSHONLY at the script-verify layer; it is enforced
  via the orthogonal `IsPushOnly()` test inside `IsStandardTx` per-input.
- `bitcoin-core/src/policy/policy.cpp:27-64` — `GetDustThreshold`: dust = `nSize *
  dustRelayFee / 1000` where `nSize = GetSerializeSize(txout) + (32+4+1+107/4+4)`
  for witness programs or `+ (32+4+1+107+4)` for legacy. The function takes a
  `CFeeRate dustRelayFeeIn` argument — operator-tunable via `-dustrelayfee`.
- `bitcoin-core/src/policy/policy.cpp:80-98` — `IsStandard` MULTISIG branch:
  `n ∈ [1,3]`, `m ∈ [1,n]`. Bare-multisig non-standard with `n > 3`.

**Files audited**
- `crates/consensus/src/mempool.rs` (10 753 LOC) — `Mempool` struct,
  `AtmpOptions` (`:612-635`, `Default` `:637-647`, `reorg_refill` `:652-660`,
  `test_accept` `:663-671`), `MempoolConfig` (`:676-749`, `verify_scripts`
  field `:714` with default `false` `:747`, `production()` constructor
  `:785-790`), `add_transaction` (`:1326-1335` thin wrapper),
  `add_transaction_with_options` (`:1350-2046` — single-tx ATMP),
  `check_standard` (`:2368-2481`), `check_truc_policy` (`:2499-`),
  `accept_package` (`:3919-4141`), `add_transaction_for_package`
  (`:4143-4500` — second ATMP entry, missing every script gate),
  `block_disconnected` (`:2294-2328` reorg refill via
  `AtmpOptions::reorg_refill()`), `classify_standard_script` (`:4562-4632`),
  `try_classify_bare_multisig` (`:4638-4693`), `is_witness_standard`
  (`:4770-4936`), `is_dust` (`:5028-5063`), `pre_check_ephemeral_tx`
  (`:5124-`).
- `crates/consensus/src/script/interpreter.rs:118-246` — `ScriptFlags`,
  `standard_flags()` (`:149-173`, 21 flags including the EXTRA
  `verify_sigpushonly`), `consensus_flags(height, testnet4)`
  (`:123-144` — tip-aware activation), `to_bits()`.
- `crates/consensus/src/params.rs:110-144` — `MAX_STANDARD_TX_WEIGHT`,
  `DEFAULT_MIN_RELAY_TX_FEE = 1000` (NOTE: rustoshi has `1_000` here per
  rustoshi/crates/consensus/src/params.rs:113 — but `MempoolConfig::default`
  ignores this value; see BUG-2), `DUST_RELAY_TX_FEE = 3_000`,
  `MAX_STANDARD_TX_SIGOPS_COST = 16_000`, `MAX_P2SH_SIGOPS = 15`,
  `MIN_STANDARD_TX_NONWITNESS_SIZE = 65`, `MAX_STANDARD_SCRIPTSIG_SIZE = 1650`.
- `crates/consensus/src/validation.rs:228-353` — `bip22_string()` reject-token
  Core-parity mapping for `TxValidationError` / `ValidationError` (Core
  wire-format strings); `check_transaction` (`:376-`).
- `crates/rpc/src/server.rs:144-219` — `RpcState` with `mempool: Mempool::new(
  MempoolConfig::default())` at `:172` AND `:199` (production
  constructors); `recently_rejected: HashSet<Hash256>` at `:144`;
  `orphanage: TxOrphanage::new()` at `:164`.
- `crates/rpc/src/server.rs:3680-3792` — `sendrawtransaction` (single-tx
  ATMP entry); `:6595-6699` — `testmempoolaccept` (second ATMP-via-RPC
  using `AtmpOptions::test_accept()`); `:1205-1226` —
  `compute_prev_block_mtp`.
- `crates/network/src/peer_manager.rs:2030-2033` — P2P `NetworkMessage::Tx`
  arm in `peer_manager`: only updates `last_tx_time`, never dispatches
  to the mempool (the actual dispatch happens in main.rs — second
  ATMP entry).
- `rustoshi/src/main.rs:3098-3247` — second ATMP entry (P2P MSG_TX),
  calls `rpc.mempool.add_transaction(...)` then orphan-promotion
  via `rpc.orphanage.find_children(&txid)` (non-recursive),
  `recently_rejected.insert(txid)` on any non-MissingInput error;
  `:325-353` — `compute_mtp_via_store` (duplicate of `compute_prev_block_mtp`).

---

## Gate matrix (34 sub-gates / 11 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | PreChecks order vs Core (validation.cpp:782-981) | G1: CheckTransaction first | PASS (`mempool.rs:1368`) |
| 1 | … | G2: Coinbase reject as TX_CONSENSUS class | PASS (`:1376-1378` `MempoolError::CoinbaseRejected`) |
| 1 | … | G3: IsStandardTx BEFORE wtxid-duplicate check (Core :807 vs :823) | **BUG-1 (P1)** — rustoshi checks wtxid-dup (`:1383`) BEFORE check_standard (`:1398`); order divergence |
| 1 | … | G4: MIN_STANDARD_TX_NONWITNESS_SIZE always-enforced (Core :813 outside require_standard) | PASS (`:1410-1412` runs outside `require_standard` guard) |
| 1 | … | G5: CheckFinalTxAtTip uses height+1 + tip MTP | PASS (`:1419-1422`) |
| 1 | … | G6: wtxid-dup → `txn-already-in-mempool` distinct from txid-dup → `txn-same-nonwitness-data-in-mempool` | PASS (`:1383-1392`) |
| 1 | … | G7: conflict + !allow_replacement → `bip125-replacement-disallowed` | PASS (`:1444-1448`) |
| 1 | … | G8: CheckSequenceLocksAtTip BEFORE CheckTxInputs / sigops (Core :886) | **BUG-3 (P1)** — rustoshi runs BIP-68 (`:1678-1685`) AFTER sigops gate AFTER fee compute; Core runs it BEFORE sigops + before CheckTxInputs |
| 1 | … | G9: PreCheckEphemeralTx on single-tx ATMP (Core :935-939) | **BUG-4 (P0-CDIV)** — `pre_check_ephemeral_tx` exists at mempool.rs:5124 but is called ONLY from `accept_package` (`:4048`); single-tx path admits txs with ephemeral dust + non-zero fee silently |
| 1 | … | G10: MAX_STANDARD_TX_SIGOPS_COST policy cap | PASS (`:1657-1662`) |
| 1 | … | G11: CheckFeeRate skipped on bypass_limits | PASS (`:1713`) |
| 2 | PolicyScriptChecks (STANDARD flags, validation.cpp:1135-1156) | G12: PolicyScriptChecks runs on canonical ATMP path | **BUG-2 (P0-SEC)** — `verify_scripts: false` is the `MempoolConfig::default()` default (mempool.rs:747); both production constructors (`server.rs:172,199`) use `default()` so PolicyScriptChecks **never runs in production**. The TODO at :745 admits this is awaiting test-fixture migration |
| 2 | … | G13: STANDARD_SCRIPT_VERIFY_FLAGS = MANDATORY ∪ 13 policy bits matching Core's policy.h:119-132 | **BUG-5 (P1)** — rustoshi `standard_flags()` (`script/interpreter.rs:149-173`) includes `verify_sigpushonly: true` which is NOT in Core's STANDARD_SCRIPT_VERIFY_FLAGS (SIGPUSHONLY is enforced separately via `IsStandardTx::IsPushOnly` per-input, not at script-verify layer). 21 flags vs Core's 20. Causes non-standard scriptSig rejection at PolicyScriptChecks on testnet/regtest even when `IsStandardTx` is bypassed |
| 2 | … | G14: TX_WITNESS_STRIPPED detection on witness-strip failure (Core :1148-1151) | **BUG-6 (P1)** — rustoshi has no `SpendsNonAnchorWitnessProg` analogue; all PolicyScript failures become `MempoolError::PolicyScriptCheckFailed(input_idx, msg)` with no witness-stripping distinction. p2p rejection-cache cannot distinguish witness-mutated from genuinely-invalid |
| 3 | ConsensusScriptChecks (TIP-DERIVED block flags, validation.cpp:1158-1189) | G15: Uses `GetBlockScriptFlags(tip)` not static MANDATORY | **BUG-7 (P0-CDIV)** — rustoshi `add_transaction_with_options:1912-1921` constructs a **static MANDATORY-only `ScriptFlags`** (P2SH | DERSIG | CLTV | CSV | WITNESS | NULLDUMMY | TAPROOT) regardless of tip height or soft-fork activation state. Core uses `GetBlockScriptFlags(*tip)`. At heights near a soft-fork activation boundary, rustoshi accepts txs that fail the tip's actual flag-set and would then be rejected when mined |
| 3 | … | G16: Defense-in-depth re-check exists | PASS-as-implemented (`:1908-1944` runs the re-check, but with the wrong static-flag set — see BUG-7) |
| 4 | IsStandardTx + AreInputsStandard + IsWitnessStandard | G17: `n ∈ [1,3]` bare-multisig cap | PASS (`:4650-4655`) |
| 4 | … | G18: P2SH redeemScript sigops ≤ MAX_P2SH_SIGOPS=15 | PASS (`:1599-1611`) |
| 4 | … | G19: Witness-program v2-v16 rejected as `InputsNonStandard` (Core: WitnessUnknown) | PASS (`:4621-4628`, `:1584-1589`) |
| 4 | … | G20: IsWitnessStandard P2WSH stack-item caps (100 items / 80 bytes / 3600-byte script) | PASS (`:4837-4877`) |
| 4 | … | G21: IsWitnessStandard P2TR annex (0x50) reject + tapscript 80-byte stack-item cap | PASS (`:4882-4922`) |
| 5 | Operator knobs (Core init.cpp / settings.cpp) | G22: `-minrelaytxfee` CLI flag | **BUG-8 (P1)** — rustoshi's `parseFlags` (`rustoshi/src/main.rs:55-300+`) defines no `-minrelaytxfee` flag; `MempoolConfig::default().min_fee_rate = 1` is hardcoded |
| 5 | … | G23: `-incrementalrelayfee` CLI flag | **BUG-8 cross-cite** — no flag defined |
| 5 | … | G24: `-dustrelayfee` CLI flag | **BUG-9 (P1)** — `is_dust` signature takes `_min_fee_rate: u64` (unused, prefixed `_`); dust threshold is hardcoded to `DUST_RELAY_TX_FEE = 3000` constant. No operator-knob path |
| 5 | … | G25: `-acceptnonstdtxn` CLI flag (regtest bypass for IsStandardTx) | **BUG-10 (P0-CDIV)** — no `-acceptnonstdtxn` flag; `AtmpOptions::default().require_standard = true` is the only value any production code ever uses. On regtest, rustoshi enforces standardness while Core admits non-standard txs. Test-suite tests that build non-standard txs cannot interoperate |
| 5 | … | G26: `-permitbaremultisig` / `-datacarriersize` / `-maxmempool` / `-mempoolexpiry` / `-limitancestorcount` / `-limitdescendantcount` / `-mempoolfullrbf` | **BUG-11 (P1)** — none of these are wired via CLI; values are baked into `MempoolConfig::default()` constants |
| 6 | Reject-string / wire-format parity | G27: `MempoolError → reject-token` maps to Core's `bad-txns-*` strings | **BUG-12 (P1)** — `sendrawtransaction` error-mapping at `server.rs:3758-3789` uses thiserror Display strings ("Missing input: ...", "Transaction conflicts with mempool entry ...", "Transaction validation failed: ...", "Transaction rejected: ...") instead of Core wire tokens (`bad-txns-inputs-missingorspent`, `txn-mempool-conflict`, the `bip22_string()` token, etc.). `bip22_string()` is defined in validation.rs:228 but never called from the sendrawtransaction path |
| 6 | … | G28: `MempoolError::WtxidAlreadyInMempool` mapped to RPC success (Core: no-op success) | **BUG-13 (P0-CDIV)** — server.rs:3758-3789 only treats the OLD `MempoolError::AlreadyExists` variant as success. The W96 split (`WtxidAlreadyInMempool` / `TxidSameNonwitnessData`) falls through to the catch-all `_ => Err("Transaction rejected: ...")`. A peer relaying a tx already in our mempool gets a spurious RPC error from rustoshi while Core returns success |
| 7 | Two-pipeline ATMP guard | G29: Single ATMP entry shared by RPC + P2P | **BUG-14 (P0-CDIV)** — TWO production ATMP entry points: `server.rs:3699` (sendrawtransaction) and `rustoshi/src/main.rs:3117` (P2P MSG_TX). Both call `mempool.add_transaction(tx, &utxo_lookup)` (default opts) but differ in: orphan-promotion (only main.rs), recently_rejected insertion (only main.rs), broadcast strategy (server: all peers; main: all-except-source) |
| 7 | … | G30: P2P MSG_TX correctly dispatched to mempool | PARTIAL — peer_manager.rs:2030 matches `NetworkMessage::Tx(_)` ONLY to update `last_tx_time`; the actual `add_transaction` call lives in the main.rs event loop (`:3098-3127`). The dispatch works but is split across two crates with the peer_manager's match arm being inert |
| 7 | … | G31: Package-path `add_transaction_for_package` mirrors single-tx pipeline | **BUG-15 (P0-CONS)** "three-pipeline drift" — `add_transaction_for_package` (`:4143-4500`) **skips every consensus gate beyond `check_transaction`/`check_standard`/TRUC/ancestor limits**. No `IsFinalTx`, no `CheckSequenceLocks` (BIP-68), no `IsWitnessStandard`, no `AreInputsStandard`, no `GetTransactionSigOpCost`, no `MoneyRange` on inputs, no coinbase-maturity check, no PolicyScriptChecks, no ConsensusScriptChecks. A submitpackage RPC bypasses ~12 ATMP gates that sendrawtransaction enforces |
| 7 | … | G32: `spends_coinbase` tracking on package path | **BUG-16 (P0-CONS)** — `add_transaction_for_package:4417` hardcodes `spends_coinbase: false` for every package-admitted entry. Comment ("safe because non-coinbase-spending entries are simply excluded from the reorg re-scan set") is **backwards** — `remove_for_reorg` re-scans entries WITH `spends_coinbase=true`; a tx that DOES spend coinbase but is admitted via package path will have `spends_coinbase=false`, so reorg crossing the 100-block maturity boundary leaves now-immature coinbase spenders in the mempool |
| 8 | Orphan handling | G33: Orphan resolution recursive (Core OrphanWorkSet) | **BUG-17 (P1)** — `main.rs:3145-3187` resolves orphans single-pass: `find_children(&txid)` returns direct children only; if a grandchild orphan's parent is one of those children that just got promoted, the grandchild is NEVER retried. Core's `OrphanWorkSet` walks transitively |
| 9 | Sequence-lock context | G34: BIP-68 enforce_bip68 = (tx.version >= 2) AND post-CSV-activation | **BUG-18 (P1)** — `:1680` `enforce_bip68 := tx.version >= 2` ignores chain-tip CSV-activation state. Pre-CSV blocks (mainnet height <419,328) had BIP-68 not yet active; rustoshi's mempool gate fires for any v2+ tx regardless. Currently latent (mainnet activation done long ago) but breaks regtest fixtures that turn CSV off |

---

## BUG-1 (P1) — `IsStandardTx` runs AFTER wtxid-duplicate check; order divergence from Core

**Severity:** P1 (order divergence; reject-string priority slip).
Bitcoin Core `MemPoolAccept::PreChecks` runs `IsStandardTx` at
validation.cpp:807-810, BEFORE the wtxid-duplicate gate at :823-825 and the
txid-duplicate gate at :826-829. The reasoning: standardness is a
context-free shape check that can reject malformed input without consulting
the mempool, while duplicate-detection requires the per-mempool index.

rustoshi's `add_transaction_with_options` runs the wtxid-dup gate first
(`mempool.rs:1383-1385`), then the txid-dup gate (`:1390-1392`), then
standardness (`:1398-1400`). Order swap.

**File:** `crates/consensus/src/mempool.rs:1383-1400`.

**Core ref:** `bitcoin-core/src/validation.cpp:807-829`.

**Excerpt (rustoshi order)**
```rust
if self.wtxid_index.contains_key(&wtxid) {
    return Err(MempoolError::WtxidAlreadyInMempool);
}
if self.transactions.contains_key(&txid) {
    return Err(MempoolError::TxidSameNonwitnessData);
}
// Check standardness (only when require_standard).
if require_standard {
    self.check_standard(&tx)?;
}
```

**Impact:** for a single-tx where the SAME tx is already in mempool AND
violates standardness (e.g., a tx that was admitted via `require_standard=
false` testnet path then re-relayed to a `require_standard=true` node), Core
would report the standardness reason first; rustoshi reports duplicate
first. Reject-string priority slip detectable by cross-impl test harness.
Effectively benign in normal flow (a duplicate tx by definition already
passed standardness), but documented for fleet pattern continuity.

---

## BUG-2 (P0-SEC) — `verify_scripts: false` is the production default → PolicyScriptChecks + ConsensusScriptChecks NEVER RUN

**Severity:** P0-SEC.
Bitcoin Core's `MemPoolAccept::PolicyScriptChecks` (validation.cpp:1135)
unconditionally runs CheckInputScripts with STANDARD_SCRIPT_VERIFY_FLAGS for
every tx admitted to the mempool. `ConsensusScriptChecks` (:1158) re-runs
with tip-derived consensus flags. This is the load-bearing CPU-DoS-mitigated
script-verification gate that prevents invalid-signature txs from entering
the mempool and being relayed.

rustoshi's `MempoolConfig` has a `verify_scripts: bool` field
(`mempool.rs:714`); `Default` sets it to `false` (`:747`) with the comment:

```rust
// W96: script verification defaults to FALSE for backward
// compatibility with the pre-W96 test suite (which builds
// synthetic OP_1 transactions without real signatures).
// Production callers (rpc/sendrawtransaction, p2p tx-relay)
// MUST set this to true at config-construction time to enable
// PolicyScriptChecks + ConsensusScriptChecks.  Use
// `MempoolConfig::production()` for the canonical Core-parity
// configuration.
//
// TODO(W96 follow-up): flip default to true once test fixtures
// are migrated to real signatures (or to test_no_scripts()).
verify_scripts: false,
```

The TODO admits the gap. Both production constructors of `RpcState`
(`crates/rpc/src/server.rs:172` `RpcState::new` and `:199`
`with_prune_config`) instantiate via `MempoolConfig::default()`. **No
production caller invokes `MempoolConfig::production()`**. Confirmed via
grep: only test files use `production()` / `test_no_scripts()`.

Effect: at `mempool.rs:1861`, the script-verify block is gated as
`if self.config.verify_scripts && !opts.skip_script_checks && ...`. Since
`verify_scripts = false`, the entire 80-line script-verification block
(`:1861-1944` covering PolicyScriptChecks + ConsensusScriptChecks) is dead
code in production.

**Failure modes:**
- Invalid-signature txs admitted to the mempool via sendrawtransaction or
  P2P MSG_TX, relayed to all peers, only caught when a miner builds the next
  block and the script-verify in `ConnectBlock` rejects them.
- Per-tx CPU-DoS mitigation absent: an attacker that submits e.g. 1000 txs
  with deliberately invalid signatures pollutes our mempool and our peers'
  mempools.
- `recently_rejected` cache (which Core uses to suppress re-request of
  known-bad wtxids) cannot cache the "bad-signature" verdict because we
  never reach the verdict.

**File:** `crates/consensus/src/mempool.rs:714, 747, 1861`;
`crates/rpc/src/server.rs:172, 199`; `rustoshi/src/main.rs:3117` (P2P
dispatch).

**Core ref:** `bitcoin-core/src/validation.cpp:1135-1189` (PolicyScript +
ConsensusScript run unconditionally on every ATMP call).

**Impact:**
- P0-SEC: production mempool admits invalid-signature txs and relays them.
- Defense-in-depth gap: even when `bypass_limits` is false (the normal
  loose-tx path), no script verification runs.
- Cross-cite W144 STANDARD-flags-missing fleet finding: 5 of 10 impls had
  STANDARD_SCRIPT_VERIFY_FLAGS incomplete; rustoshi has the WHOLE flag-set
  defined correctly but **never actually runs the check** in production.
- "Wiring-look-but-no-wire" / "plumb-gate-then-flip" — the gates are wired
  (W96 audit work), the flag is plumbed, the production path is missing
  the one-line `MempoolConfig::production()` swap.

---

## BUG-3 (P1) — BIP-68 sequence-lock check runs AFTER sigops + fee compute; Core runs it BEFORE

**Severity:** P1.
Core `PreChecks` order at validation.cpp:881-893:
1. CheckSequenceLocksAtTip (BIP-68) — line 886-889
2. Consensus::CheckTxInputs (CheckTxInputs computes nValueIn / nValueOut /
   nFees) — line 892
3. ValidateInputsStandardness / IsWitnessStandard — line 896-906
4. GetTransactionSigOpCost — line 908
5. PreCheckEphemeralTx — line 935-939
6. MAX_STANDARD_TX_SIGOPS_COST policy cap — line 941-943
7. CheckFeeRate — line 948

The sequence-lock check is FIRST in this sequence so we can early-exit on a
non-BIP68-final tx without computing sigops or running the expensive
ValidateInputsStandardness loop.

rustoshi's `add_transaction_with_options` order:
1. Input loop (computes input_sum) — `:1441-1564`
2. AreInputsStandard — `:1576-1613`
3. IsWitnessStandard — `:1620-1624`
4. GetTransactionSigOpCost + MAX_STANDARD_TX_SIGOPS_COST — `:1638-1666`
5. **BIP-68 CheckSequenceLocks** — `:1678-1685` (LAST in the policy-check
   sequence)
6. Fee compute, min-fee — `:1687-1718`

A non-BIP68-final tx pays for the entire sigop/standardness walk before
being rejected. Performance regression; also reorders the failure-class
priority (rustoshi reports e.g. `MAX_STANDARD_TX_SIGOPS_COST` rejection on
a tx that Core would reject with `non-BIP68-final` first).

**File:** `crates/consensus/src/mempool.rs:1676-1685`.

**Core ref:** `bitcoin-core/src/validation.cpp:881-948`.

**Impact:**
- CPU cost on legitimate-but-not-yet-BIP68-final txs (wallet retry loops).
- Reject-class priority slip on cross-impl harness.

---

## BUG-4 (P0-CDIV) — `PreCheckEphemeralTx` not called on single-tx ATMP path

**Severity:** P0-CDIV.
Bitcoin Core `MemPoolAccept::PreChecks` at validation.cpp:935-939 runs
`PreCheckEphemeralTx(*ptx, m_pool.m_opts.dust_relay_feerate, ws.m_base_fees,
ws.m_modified_fees, state)` for every standard tx. The function enforces:
- Txs with ephemeral dust outputs must have zero fee (disincentive to mine
  alone),
- Cap on number of ephemeral dust outputs per tx.

rustoshi has `pre_check_ephemeral_tx` defined at `mempool.rs:5124`. Grep
shows it is invoked from EXACTLY one site:
`accept_package:4048` (package-path only).

**Failure modes:**
- A standalone tx with `value=0` P2A or other ephemeral-dust output paying
  non-zero fee enters the mempool via sendrawtransaction.
- Miner picks it up alone; the P2A output is never spent by a child
  (because the operator submitted the wrong shape); the ephemeral-anchor
  protocol semantics are violated.
- Cross-impl divergence: Core rejects with `mempool min fee not met`-class
  while rustoshi admits and relays.

**File:** `crates/consensus/src/mempool.rs:1350-2046` (whole
`add_transaction_with_options`, no `pre_check_ephemeral_tx` call site);
`:5124` (function defined).

**Core ref:** `bitcoin-core/src/validation.cpp:935-939`.

**Impact:**
- Ephemeral-anchor protocol semantics broken on single-tx admission.
- "Dead-helper-at-call-site" pattern — the function exists, is correct,
  and is invoked from the package path only.

---

## BUG-5 (P1) — `standard_flags()` includes `verify_sigpushonly` which is NOT in Core's STANDARD_SCRIPT_VERIFY_FLAGS

**Severity:** P1 ("STANDARD-flag superset" — Core+1 instance of the W144
fleet-wide flag-set finding).
Core `policy/policy.h:119-132` defines `STANDARD_SCRIPT_VERIFY_FLAGS` as
exactly 20 bits: `MANDATORY_SCRIPT_VERIFY_FLAGS` (7) plus STRICTENC,
MINIMALDATA, DISCOURAGE_UPGRADABLE_NOPS, CLEANSTACK, MINIMALIF, NULLFAIL,
LOW_S, DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, WITNESS_PUBKEYTYPE,
CONST_SCRIPTCODE, DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
DISCOURAGE_OP_SUCCESS, DISCOURAGE_UPGRADABLE_PUBKEYTYPE (13).

Note: SCRIPT_VERIFY_SIGPUSHONLY (BIP62 rule 2) is **NOT** in
STANDARD_SCRIPT_VERIFY_FLAGS. Core enforces non-push scriptSig via the
orthogonal `IsPushOnly()` test inside `IsStandardTx` per-input
(policy/policy.cpp::IsStandardTx :230+), NOT at the script-verify layer.

rustoshi's `ScriptFlags::standard_flags()`
(`script/interpreter.rs:149-173`) sets `verify_sigpushonly: true` (line
160). That makes rustoshi's STANDARD flag-set 21 bits — superset of Core.

**Failure modes:**
- On the (currently dead in production but if BUG-2 is fixed, live) PolicyScriptChecks path, a
  txn with a non-push scriptSig fails at the script-verify level even on
  paths that have `require_standard=false` (testnet/regtest with
  -acceptnonstdtxn, which BUG-10 also blocks but conceptually).
- A tx that Core admits under non-standard-relay-allowed config (Core
  testnet/regtest passes the non-push scriptSig through PolicyScriptChecks
  even though it fails IsStandardTx) would be rejected by rustoshi at
  PolicyScriptChecks once it's actually wired.

**File:** `crates/consensus/src/script/interpreter.rs:149-173` (extra flag);
`crates/consensus/src/mempool.rs:1885` (call site).

**Core ref:** `bitcoin-core/src/policy/policy.h:119-132`.

**Excerpt (rustoshi, extra bit)**
```rust
pub fn standard_flags() -> Self {
    ScriptFlags {
        verify_p2sh: true, ...                  // mandatory (7)
        verify_strictenc: true,
        verify_low_s: true,
        verify_sigpushonly: true,               // <-- NOT in Core STANDARD
        verify_minimaldata: true, ...
    }
}
```

**Impact:** flag-set superset; latent until BUG-2 wires
PolicyScriptChecks. Cross-cite W144.

---

## BUG-6 (P1) — No `SpendsNonAnchorWitnessProg` / `TX_WITNESS_STRIPPED` distinction on PolicyScriptChecks failure

**Severity:** P1.
Bitcoin Core `PolicyScriptChecks` at validation.cpp:1146-1152:
```cpp
if (!CheckInputScripts(tx, state, m_view, scriptVerifyFlags, true, false,
                       ws.m_precomputed_txdata, GetValidationCache())) {
    if (!tx.HasWitness() && SpendsNonAnchorWitnessProg(tx, m_view)) {
        state.Invalid(TxValidationResult::TX_WITNESS_STRIPPED,
                state.GetRejectReason(), state.GetDebugMessage());
    }
    return false;
}
```

The `TX_WITNESS_STRIPPED` distinction feeds the p2p rejection-cache so that
honest re-relay of the same tx-with-witness is not blocked on the basis of
the witness-stripped failure. Without it, a tx that fails because the
witness was stripped by an upstream relay node gets cached as
"permanently-rejected" by wtxid, and any peer that tries to re-send the
same tx with its witness intact may be silently dropped from the request
loop.

rustoshi's PolicyScriptChecks branch (`mempool.rs:1884-1906`) emits all
failures as `MempoolError::PolicyScriptCheckFailed(input_idx, msg)` with no
witness-stripping detection.

**File:** `crates/consensus/src/mempool.rs:1894-1905`.

**Core ref:** `bitcoin-core/src/validation.cpp:1146-1151`,
`policy/policy.cpp::SpendsNonAnchorWitnessProg`.

**Impact:** p2p rejection-cache cannot distinguish witness-stripped from
genuinely-invalid; honest re-relay of correctly-witnessed tx may be
blackholed.

---

## BUG-7 (P0-CDIV) — `ConsensusScriptChecks` uses STATIC MANDATORY flags, not `GetBlockScriptFlags(tip)`

**Severity:** P0-CDIV ("ConsensusScriptChecks scope-creep" — Core uses
tip-derived flags, rustoshi uses static).
Bitcoin Core `ConsensusScriptChecks` at validation.cpp:1158-1189:

```cpp
script_verify_flags currentBlockScriptVerifyFlags{
    GetBlockScriptFlags(*m_active_chainstate.m_chain.Tip(),
                        m_active_chainstate.m_chainman)};
if (!CheckInputsFromMempoolAndCache(tx, state, m_view, m_pool,
                                    currentBlockScriptVerifyFlags, ...)) {
    LogError("BUG! PLEASE REPORT THIS! ...");
    return Assume(false);
}
```

The flags here are the **tip-derived block-script-flags** — i.e., the
flag-set that would be enforced on a tx mined into the NEXT block. This
incorporates soft-fork activation transitions (BIP-9 / BIP-341 / future)
and the per-network exception table (`script_flag_exceptions` for the BIP-16
grandfather block, the Taproot exception at h=692,263, etc.).

rustoshi's `add_transaction_with_options` ConsensusScriptChecks block
(`mempool.rs:1912-1921`) constructs a STATIC `ScriptFlags`:

```rust
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

This is **`MANDATORY_SCRIPT_VERIFY_FLAGS` always on, regardless of tip
height**. Failure modes:

- Heights below BIP-65 (CLTV) activation (mainnet 388,381): Core would
  NOT enforce CLTV; rustoshi DOES. A tx using OP_CLTV pre-activation
  enters the mempool under rustoshi's MANDATORY-static gate but is then
  rejected when actually mined under tip-flags. Cross-impl divergence.
- Heights below SegWit activation (mainnet 481,824): Core would NOT enforce
  WITNESS; rustoshi DOES. Same shape as CLTV case.
- Heights below Taproot activation (mainnet 709,632): Core would NOT
  enforce TAPROOT; rustoshi DOES. A v1 32-byte witness program is "anyone
  can spend" pre-activation per BIP-341; rustoshi's static-MANDATORY
  validates against post-activation rules.
- BIP-16 exception block (mainnet h=174,062): Core's
  `script_flag_exceptions` table grandfather-excludes a specific block from
  P2SH enforcement. rustoshi has no such table at any layer (cross-cite
  W144 BUG-2 — rustoshi has zero `script_flag_exceptions` support fleet-wide
  finding).

In practice on mainnet IBD-current nodes the divergence is silent (all soft
forks long-activated), but on a from-genesis reindex or testnet-fresh node
the mempool admits txs that the chain rejects.

**File:** `crates/consensus/src/mempool.rs:1912-1921`.

**Core ref:** `bitcoin-core/src/validation.cpp:1181`.

**Impact:**
- Mempool admits txs that next-block-mining will reject (mining-template
  drift, wasted CPU).
- On from-genesis reindex / testnet-fresh, cross-impl chain-split
  candidate.
- Cross-cite W144 BUG-1 (rustoshi) — same `script_flag_exceptions = ABSENT`
  finding, here surfacing on the mempool side.

---

## BUG-8 (P1) — No `-minrelaytxfee` / `-incrementalrelayfee` CLI flags

**Severity:** P1 ("operator-knob absence" — fleet pattern, 7+ rustoshi
instances per prior audits).
Bitcoin Core `init.cpp` exposes `-minrelaytxfee=<amt>` and
`-incrementalrelayfee=<amt>` (sat/kvB units) to control:
- `nMinRelayTxFee` (CheckFeeRate gate at validation.cpp:948 and feefilter
  broadcast),
- `incrementalRelayFee` (RBF additional-fee requirement,
  rolling-min-fee-rate floor).

rustoshi's `parseFlags` (`rustoshi/src/main.rs:55-300+`) defines neither
flag. `MempoolConfig::default()` (`mempool.rs:717-749`) hardcodes
`min_fee_rate: 1` and `incremental_relay_fee: DEFAULT_INCREMENTAL_RELAY_FEE
= 100`.

**Note: `min_fee_rate` UNIT MISMATCH.** Comparing to Core:
- Core: `DEFAULT_MIN_RELAY_TX_FEE = 100` (sat/kvB).
  `CheckFeeRate(vsize, fee, ::nMinRelayTxFee)` computes
  `nMinRelayTxFee.GetFee(vsize) = 100 * vsize / 1000 = 0.1 sat/vB`
  threshold.
- rustoshi: `min_fee_rate: 1` (sat/vB; see comment "1 sat/vbyte" at line
  724). Compared at `mempool.rs:1713` as `(fee_rate as u64) < min_fee_rate`
  where `fee_rate = fee / vsize` (sat/vB).
- Effective rustoshi min-fee threshold: 1 sat/vB. **10× too strict
  compared to Core's 0.1 sat/vB.**

A tx paying 0.5 sat/vB (admissible by Core default) is rejected by
rustoshi with `InsufficientFee(0.5, 1)`. This is a wallet-interop
regression: any wallet bumping a tx based on Core's `nMinRelayTxFee` will
build a tx that rustoshi rejects from relay.

**File:** `crates/consensus/src/mempool.rs:683 (field), 724 (default),
1713 (gate)`; `rustoshi/src/main.rs:55-300+` (CLI parse).

**Core ref:** `bitcoin-core/src/policy/policy.h:70`,
`bitcoin-core/src/init.cpp` `-minrelaytxfee`,
`bitcoin-core/src/policy/settings.cpp`.

**Impact:**
- Wallet-interop: bumped txs at Core-default min-fee are silently dropped
  by rustoshi.
- No operator-knob to lower fees for free-relay test networks.
- 10× too-strict fee gate compared to Core (unit confusion: sat/vB vs
  sat/kvB).

---

## BUG-9 (P1) — `is_dust` ignores its `_min_fee_rate` parameter; dust threshold is hardcoded

**Severity:** P1.
Bitcoin Core `policy/policy.cpp::IsDust(txout, dustRelayFeeIn)` parameterises
the dust threshold on the `dustRelayFeeIn` argument (default 3000 sat/kvB,
operator-tunable via `-dustrelayfee`).

rustoshi's `is_dust` (`mempool.rs:5028`):
```rust
fn is_dust(output: &TxOut, _min_fee_rate: u64) -> bool {
    ...
    let dust_threshold = (spending_size as u64 * DUST_RELAY_TX_FEE) / 1000;
    output.value < dust_threshold
}
```

The `_min_fee_rate` parameter is prefixed `_` (Rust convention for
deliberately-unused param) and the dust threshold uses the **hardcoded**
`DUST_RELAY_TX_FEE = 3000` constant. There is no `-dustrelayfee` CLI knob.

Additionally, rustoshi's per-script-type `spending_size` table is hardcoded
to `148/91/68/108/58` based on `script_pubkey.len()` matching certain shapes:

```rust
let spending_size: usize = if output.script_pubkey.len() == 25 {
    148 // P2PKH
} else if output.script_pubkey.len() == 23 {
    91 // P2SH (approximate)
} else if output.script_pubkey.len() == 22 && output.script_pubkey[0] == 0x00 {
    68 // P2WPKH
} else if output.script_pubkey.len() == 34 && output.script_pubkey[0] == 0x00 {
    108 // P2WSH (approximate)
} else if output.script_pubkey.len() == 34 && output.script_pubkey[0] == 0x51 {
    58 // P2TR
} else {
    148 // conservative default
};
```

Core computes `nSize = GetSerializeSize(txout) + (32+4+1+107/4+4)` for any
witness program OR `+ (32+4+1+107+4)` for legacy, derived from real bytes
not type-shape. The numerical values rustoshi uses (148/68) match Core's
constants in the common cases, but the P2SH (91) and P2WSH (108)
"approximate" values diverge from Core's actual computation (Core would
compute P2SH at 32+4+1+107+4+23 = 171, P2WSH at 32+4+1+26+4+34 = 101 with
the segwit-discounted witness-size accounting). The "(approximate)"
comment is a comment-as-confession.

**File:** `crates/consensus/src/mempool.rs:5028-5062`.

**Core ref:** `bitcoin-core/src/policy/policy.cpp:27-69`.

**Impact:**
- No `-dustrelayfee` operator knob.
- P2SH and P2WSH dust threshold values diverge from Core; a 100-sat P2SH
  output is dust under Core's 171-byte calc (= 513 sats threshold), passes
  rustoshi's 91-byte calc (= 273 sats threshold). Net: rustoshi admits
  outputs Core rejects as dust on P2SH/P2WSH paths.

---

## BUG-10 (P0-CDIV) — No `-acceptnonstdtxn` operator knob; `require_standard=true` is permanent

**Severity:** P0-CDIV.
Bitcoin Core's `-acceptnonstdtxn` CLI flag (regtest/testnet-only) sets
`m_pool.m_opts.require_standard = false`, which gates the `IsStandardTx`,
`AreInputsStandard`, `IsWitnessStandard`, MAX_STANDARD_TX_SIGOPS_COST,
`PreCheckEphemeralTx`, and AreInputsStandard checks in PreChecks.

rustoshi's `AtmpOptions::default().require_standard = true`
(`mempool.rs:642`). Searching for any production code that sets
`require_standard: false`: only test files (lines 10361, 10401, 10648,
10725). The CLI parse has no `-acceptnonstdtxn` flag.

This means **rustoshi enforces standardness even on regtest**, breaking the
test-suite-interop assumption that regtest can admit synthetic non-standard
txs. Core's regtest network is the canonical place to exercise edge-case
tx shapes; rustoshi-regtest rejects what Core-regtest accepts.

**File:** `crates/consensus/src/mempool.rs:626 (field doc says "False on
testnet/regtest or via the -acceptnonstdtxn knob"), 642 (Default::default
sets true)`; `rustoshi/src/main.rs:55-300+` (no flag).

**Core ref:** `bitcoin-core/src/init.cpp::-acceptnonstdtxn`,
`bitcoin-core/src/kernel/mempool_options.h::require_standard`.

**Impact:**
- Cross-impl regtest harness breaks: rustoshi-regtest is stricter than
  Core-regtest.
- Operator cannot run a permissive testnet/regtest node.
- Field doc-as-confession: the comment promises a knob that doesn't exist.

---

## BUG-11 (P1) — No `-permitbaremultisig` / `-datacarriersize` / `-maxmempool` / `-mempoolexpiry` / `-limitancestorcount` / `-limitdescendantcount` / `-mempoolfullrbf` operator knobs

**Severity:** P1 ("operator-knob absence" cluster).
Bitcoin Core exposes a large set of policy knobs that operators rely on to
tune their node. rustoshi exposes **none** of these via CLI:

- `-permitbaremultisig` — `MempoolConfig::default().permit_bare_multisig = true`
  (`mempool.rs:734`); no flag.
- `-datacarriersize=<bytes>` — `max_datacarrier_bytes: Some(100_000)`
  (`mempool.rs:733`); no flag.
- `-maxmempool=<MB>` — `max_size_bytes: 300 * 1_000_000` (`mempool.rs:722`);
  no flag.
- `-mempoolexpiry=<hours>` — `expiry_seconds: 336 * 3600` (`mempool.rs:723`);
  no flag.
- `-limitancestorcount=<n>` — `max_ancestor_count: DEFAULT_ANCESTOR_LIMIT`
  (`mempool.rs:726`); no flag.
- `-limitdescendantcount=<n>` — `max_descendant_count: DEFAULT_DESCENDANT_LIMIT`
  (`mempool.rs:728`); no flag.
- `-mempoolfullrbf` — `full_rbf: true` (`mempool.rs:730`); no flag.
- `-bytespersigop=<n>` — `DEFAULT_BYTES_PER_SIGOP` const used at `:1703`;
  no flag.

**File:** `crates/consensus/src/mempool.rs:717-749`;
`rustoshi/src/main.rs:55-300+`.

**Core ref:** `bitcoin-core/src/init.cpp`,
`bitcoin-core/src/kernel/mempool_options.h`.

**Impact:** operator-tooling parity gap; ports of bitcoin.conf to
rustoshi.conf silently drop all mempool knobs.

---

## BUG-12 (P1) — `sendrawtransaction` reject-string mapping bypasses `bip22_string()` Core wire tokens

**Severity:** P1 ("reject-string wire-parity slippage" — fleet pattern;
cross-cite W145 lunarblock 9-token sweep, W125 ouroboros companion).
Bitcoin Core `sendrawtransaction` returns the wire-format reject token
from `TxValidationState::GetRejectReason()` (e.g.
`bad-txns-inputs-missingorspent`, `txn-mempool-conflict`,
`mempool min fee not met`, `mandatory-script-verify-flag-failed (X)`).

rustoshi has a Core-parity `bip22_string()` mapping at
`crates/consensus/src/validation.rs:228-353` covering ~40 error
variants. But the `sendrawtransaction` error-mapping at
`crates/rpc/src/server.rs:3758-3789` does NOT call `bip22_string()`:

```rust
match &e {
    MempoolError::AlreadyExists => Ok(txid.to_hex()),     // SUCCESS map
    MempoolError::MissingInput(prev_txid, vout) =>
        Err(format!("Missing input: {}:{}", prev_txid.to_hex(), vout)),
    MempoolError::Conflict(conflicting_txid) =>
        Err(format!("Transaction conflicts with mempool entry {}", ...)),
    MempoolError::InsufficientFee(rate, min) =>
        Err(format!("Fee rate too low: {:.2} sat/vB (minimum: {})", ...)),
    MempoolError::Validation(verr) =>
        Err(format!("Transaction validation failed: {}", verr)),  // <-- verr.to_string() not verr.bip22_string()
    _ => Err(format!("Transaction rejected: {}", e)),
}
```

Specific divergences:
- `MissingInput` → "Missing input: <hex>:<vout>" — Core emits
  `bad-txns-inputs-missingorspent` (no hash payload).
- `Conflict` → "Transaction conflicts with mempool entry <hex>" — Core
  emits `txn-mempool-conflict` (no hash payload).
- `InsufficientFee` → "Fee rate too low: 0.50 sat/vB (minimum: 1)" — Core
  emits `min relay fee not met, X < Y` or `mempool min fee not met`.
- `MempoolError::Validation(verr)` → "Transaction validation failed:
  <thiserror display>" — calls `verr.to_string()` which produces
  the human-readable Display string, NOT `verr.bip22_string()` which
  produces the Core-parity wire token already implemented.
- The catch-all `_ => "Transaction rejected: <thiserror display>"`
  collapses 10+ W96 error variants (CoinbaseRejected, WtxidAlreadyInMempool,
  TxidSameNonwitnessData, ReplacementDisallowed, TxnAlreadyKnown,
  InputValueOutOfRange, InputsNonStandard, PolicyScriptCheckFailed,
  ConsensusScriptCheckFailed, NonFinal, SequenceLockNotSatisfied,
  CoinbaseNotMature, TooManyAncestors, etc.) into a generic-prefix wrapper.

**File:** `crates/rpc/src/server.rs:3758-3789`.

**Core ref:** `bitcoin-core/src/rpc/rawtransaction.cpp::sendrawtransaction`,
`bitcoin-core/src/util/validation.cpp::TxValidationState::GetRejectReason`.

**Impact:**
- Cross-impl wire-parity break: test harnesses that scrape Core reject
  strings see rustoshi's prose strings.
- `bip22_string()` is a "dead helper at call-site" — defined, exported,
  Core-parity-tested, never called from the sendrawtransaction path.

---

## BUG-13 (P0-CDIV) — `WtxidAlreadyInMempool` mapped to RPC error; Core maps to RPC success

**Severity:** P0-CDIV.
Bitcoin Core `sendrawtransaction` returns SUCCESS (the original txid)
when the tx is already in the mempool (Core's
`MempoolAcceptResult::ResultType::MEMPOOL_ENTRY` for tx-already-known); the
RPC does NOT error.

rustoshi's mapping at `crates/rpc/src/server.rs:3762-3765` only treats the
**legacy `MempoolError::AlreadyExists` variant** as success:
```rust
MempoolError::AlreadyExists => Ok(txid.to_hex()),
```

But the W96 audit work split this into two variants:
- `MempoolError::WtxidAlreadyInMempool` (exact wtxid match — true
  duplicate; Core returns SUCCESS)
- `MempoolError::TxidSameNonwitnessData` (txid match, different witness —
  witness-mutated duplicate; Core errors with
  `txn-same-nonwitness-data-in-mempool`)

The new variants fall through to the catch-all
`_ => Err("Transaction rejected: {e}")`. So:
- A peer or operator re-submitting the same tx-with-the-same-witness gets
  an RPC error from rustoshi where Core returns success. Wallet retry
  loops that key on RPC success/failure for "is my tx confirmed?" mis-state.
- The `recently_rejected` cache at `main.rs:3242-3244` then INSERTS the
  wtxid into the reject-cache. Subsequent honest peer relays of the same
  tx are silently dropped at the inv-handling code
  (`main.rs:3076-3078`: `if !rpc.mempool.contains(&item.hash) && !rpc.recently_rejected.contains(&item.hash)`).

**File:** `crates/rpc/src/server.rs:3762`; `rustoshi/src/main.rs:3242-3244`.

**Core ref:** `bitcoin-core/src/node/transaction.cpp::BroadcastTransaction`,
`bitcoin-core/src/rpc/rawtransaction.cpp::sendrawtransaction`.

**Impact:**
- Honest wtxid-duplicate gets cached as rejected and blackholes future
  re-relays.
- Wallet retry loops error-out where Core succeeds.
- Cross-cite BUG-12 (catch-all mapping); this is the most severe single
  consequence of the catch-all.

---

## BUG-14 (P0-CDIV) — Two production ATMP entry points with divergent post-admit behaviour

**Severity:** P0-CDIV ("two-pipeline guard 17th distinct rustoshi
extension" per W138/W141 tracking).
Bitcoin Core has ONE production ATMP entry: `ProcessTransaction`
→ `AcceptToMemoryPool` → `MemPoolAccept::AcceptSingleTransaction`.
RPC `sendrawtransaction` calls it via `BroadcastTransaction` (node/transaction.cpp);
P2P `tx` message handler calls it via the same entry. Both paths execute
**identical** post-admit work (orphan promotion, recently-rejected cache
insert, peer-relay broadcast, ZMQ notification).

rustoshi has TWO production ATMP entry points:
- **RPC `sendrawtransaction`** at `crates/rpc/src/server.rs:3699`
  (`state.mempool.add_transaction(tx, &utxo_lookup)`)
- **P2P MSG_TX dispatch** at `rustoshi/src/main.rs:3117`
  (`rpc.mempool.add_transaction(tx.clone(), &|outpoint| ...)`)

Both use `AtmpOptions::default()`, but the post-admit logic diverges
across the boundary:

| Post-admit behaviour | server.rs (RPC) | main.rs (P2P) |
|---|---|---|
| Orphan promotion via `find_children` | ABSENT | PRESENT (`:3152-3187`) |
| `recently_rejected.insert(txid)` on err | ABSENT | PRESENT (`:3242-3244`) |
| Broadcast strategy | All connected peers (`:3749-3754`) | All-except-source (`:3201-3210`) |
| Fee-estimator track | PRESENT (`:3736`) | PRESENT (`:3141-3143`) |

Failure modes:
- A tx admitted via RPC has its orphan-children INVISIBLE to the orphan
  promote loop; they only get resolved when a *P2P* MSG_TX whose parent is
  the RPC-admitted tx arrives. Pure-RPC workflows leak orphans into the
  orphanage forever.
- A tx rejected via RPC is NOT inserted into `recently_rejected`, so the
  same tx repeatedly arriving via P2P is repeatedly fetched/rejected
  (consumes bandwidth).
- The RPC path broadcasts the inv to ALL peers including (potentially) a
  peer that just announced the same tx; the P2P path correctly excludes
  the source. Cross-pipeline gossip-loop possible.

**File:** `crates/rpc/src/server.rs:3699-3791`;
`rustoshi/src/main.rs:3098-3247`.

**Core ref:** `bitcoin-core/src/node/transaction.cpp::BroadcastTransaction`,
`bitcoin-core/src/net_processing.cpp::ProcessMessage(NetMsgType::TX)`
(both route through the same `AcceptToMemoryPool` and post-admit hook).

**Impact:**
- Orphan promotion missing on RPC path.
- Reject cache asymmetric — RPC rejections leak through.
- "Two-pipeline guard" canonical fleet pattern.

---

## BUG-15 (P0-CONS) — `add_transaction_for_package` skips every consensus gate beyond CheckTransaction/CheckStandard/TRUC

**Severity:** P0-CONS ("three-pipeline drift" — first rustoshi instance of
the fleet-wide pattern catalogued at W143 ouroboros / camlcoin /
clearbit).
The package-path ATMP entry `add_transaction_for_package`
(`mempool.rs:4143-4500`) is a parallel implementation of the single-tx
ATMP. It runs:
- `check_transaction` ✓
- `check_standard` ✓
- input lookup + conflict collection ✓
- `tx_sigop_cost` calc for vsize ✓
- `package_fee_rate` floor check ✓
- TRUC policy check ✓
- RBF rule check ✓
- TRUC sibling eviction ✓
- cluster size limit ✓
- ancestor + descendant limit checks ✓
- TrimToSize / eviction ✓

It SKIPS, for every package-admitted tx:

1. **`is_final_tx` (BIP-113)** — no nLockTime gate.
2. **`calculate_sequence_locks` / `check_sequence_locks` (BIP-68)** — no
   relative-locktime gate.
3. **`AreInputsStandard` / `ValidateInputsStandardness`** — txs spending
   WitnessUnknown (v2-v16) prevouts can enter the mempool via package.
4. **`is_witness_standard`** — P2WSH stack-item / 80-byte / 3600-byte
   witness-script caps not enforced; P2TR annex 0x50 reject not enforced.
5. **`MAX_STANDARD_TX_SIGOPS_COST` policy cap** — sigop_cost is computed
   for vsize purposes but never compared against the 16,000 cap.
6. **`COINBASE_MATURITY` per-input check** — a package tx can spend a
   coinbase output less than 100 blocks old.
7. **`MAX_MONEY` MoneyRange per-input + accumulated** — `input_sum +=
   coin.value` uses raw `+=` (not `checked_add`); silently wraps on
   overflow.
8. **`PolicyScriptChecks` (STANDARD flags)** — no script verification.
9. **`ConsensusScriptChecks` (MANDATORY/tip flags)** — no script
   verification.
10. **`PreCheckEphemeralTx`** — ALSO not called on this path (cross-cite
    BUG-4) for individual package txs (only the package-level wrapper at
    `:4048-4050` runs, which has slightly different semantics).
11. **`MIN_STANDARD_TX_NONWITNESS_SIZE`** — `check_standard` does enforce
    this, so partial-pass — but the standalone gate (which runs outside
    require_standard on the single-tx path) is absent.

A submitpackage RPC user can therefore admit a tx with:
- non-final nLockTime → reorg replay of mempool fails when tip MTP
  changes the inFinalTx result;
- BIP-68 sequence-lock not satisfied → mempool churn on tip changes;
- coinbase-maturity violation → on reorg, the coinbase becomes immature
  and the spend becomes invalid;
- invalid script signature → bypasses all script verification.

**File:** `crates/consensus/src/mempool.rs:4143-4500` (whole function;
verify with `grep -in 'verify_script\|is_witness_standard\|is_final_tx\|check_sequence_locks\|COINBASE_MATURITY' mempool.rs:4143,4500` — zero hits).

**Core ref:** `bitcoin-core/src/validation.cpp::MemPoolAccept::PreChecks`
runs ALL of the above unconditionally for every workspace-tx in package
processing (validation.cpp:1447-1494 calls `PreChecks(args, ws)` for each
ws in the package loop).

**Impact:**
- P0-CONS: invalid-signature, immature-coinbase-spending, witness-bloat,
  non-standard-input txs can enter the mempool via submitpackage.
- Package-relay attack surface: an attacker crafts a malicious package
  that bypasses single-tx gates.
- Fleet pattern "three-pipeline drift" — main `add_transaction_with_options`,
  package `add_transaction_for_package`, reorg-refill `block_disconnected`
  (which DOES use `add_transaction_with_options` via `AtmpOptions::reorg_refill()`
  with `skip_script_checks=true`).

---

## BUG-16 (P0-CONS) — Package-admitted entries hardcoded `spends_coinbase: false`, breaking reorg coinbase-maturity re-scan

**Severity:** P0-CONS.
Bitcoin Core `CTxMemPoolEntry::spendsCoinbase` is a bool field set during
PreChecks (validation.cpp:912-919) by walking inputs and checking
`coin.IsCoinBase()`. `CTxMemPool::UpdateForReorg` /
`removeForReorg` filter mempool entries on `e.GetSpendsCoinbase() &&
::ChainstateActive().m_chain.Height() - e.GetHeight() < COINBASE_MATURITY`
to re-evict txs whose coinbase parent is no longer mature after a reorg.

rustoshi's `add_transaction_for_package` at `mempool.rs:4417`:

```rust
let entry = MempoolEntry {
    ...
    spends_coinbase: false,    // <-- HARDCODED
    entry_sequence: entry_sequence_pkg,
};
```

The inline comment (`:4390-4395`) is a comment-as-confession:

```
// W96: package-path entry_sequence + spends_coinbase.
// Package admissions get a fresh sequence number (no bypass_limits).
// spends_coinbase here is approximated as false because the
// package path does not yet track per-input coinbase status; this
// is safe because non-coinbase-spending entries are simply
// excluded from the reorg re-scan set.
```

The "safe because excluded" claim is **backwards**: `remove_for_reorg`
re-scans entries where `spends_coinbase = TRUE`. By marking package-admitted
entries as `false`, rustoshi EXCLUDES them from the re-scan. A tx that DOES
spend a coinbase output is therefore NEVER re-checked for maturity on
reorg.

**Failure scenario:**
1. Coinbase tx C mined at height 1000 (now mature: tip=1100).
2. User submits package P=[parent, child] via submitpackage. `parent`
   spends C. Admitted with `spends_coinbase=false` (incorrect).
3. Reorg: tip drops to 1050. C is now immature (1050-1000=50 < 100).
4. `remove_for_reorg` iterates entries where `spends_coinbase=true`. P
   is NOT in that set. P stays in the mempool.
5. Next block built from the mempool includes `parent` which spends
   immature C → block rejected.

**File:** `crates/consensus/src/mempool.rs:4390-4395, 4417`.

**Core ref:** `bitcoin-core/src/validation.cpp:912-919,
bitcoin-core/src/txmempool.cpp::removeForReorg`.

**Impact:**
- P0-CONS: package-admitted txs that spend immature coinbase survive
  reorgs that should evict them, leading to invalid block builds.
- "Comment-as-confession" — the comment justifies the bug it perpetuates;
  6th distinct rustoshi instance per recent audit tracking.

---

## BUG-17 (P1) — Orphan promotion is single-pass; multi-step orphan chains never resolve

**Severity:** P1.
Bitcoin Core's `OrphanWorkSet` (txorphanage.cpp + net_processing.cpp)
resolves orphans transitively: when tx A is admitted, all orphans whose
inputs reference A are pushed onto the work-set and admitted; for each
admitted orphan B, all orphans whose inputs reference B are pushed onto
the set; this continues until the set is empty.

rustoshi's orphan-promote at `rustoshi/src/main.rs:3152-3187`:

```rust
let children = rpc.orphanage.find_children(&txid);
for entry in children {
    let child_txid = entry.tx.txid();
    let admit = rpc.mempool.add_transaction((*entry.tx).clone(), &...);
    ...
    rpc.orphanage.erase(&child_txid);
}
```

Only the DIRECT children of the newly-arrived txid are tried. If orphan A
arrived earlier (parent missing), then orphan B arrived earlier (parent =
A), then the real parent of A arrives — A is promoted; B is NOT promoted
(it was never directly a child of the just-arrived tx). B stays in the
orphanage until either (a) its TTL expires or (b) someone re-relays B and
the lookup happens at admission time.

**File:** `rustoshi/src/main.rs:3152-3187`.

**Core ref:** `bitcoin-core/src/txorphanage.cpp::OrphanWorkSet`,
`bitcoin-core/src/net_processing.cpp::ProcessOrphanTx`.

**Impact:**
- Multi-step orphan chains (depth ≥2) never resolve transitively.
- TTL-based timeout-evict becomes the only release mechanism.
- Wallet-broadcast-then-rebroadcast strategy with chained child txs is
  silently broken.

---

## BUG-18 (P1) — BIP-68 enforcement gate ignores CSV soft-fork activation state

**Severity:** P1 (latent on mainnet; breaks regtest/pre-CSV scenarios).
Bitcoin Core's `CheckSequenceLocksAtTip` is called unconditionally in
`PreChecks`; the activation gate is inside `CalculateSequenceLocks` which
returns `LockPoints{maxInputHeight=0, time=0}` for any tx where the chain
is pre-CSV-activation, effectively making the check a no-op.

rustoshi's `add_transaction_with_options:1680`:

```rust
let enforce_bip68 = tx.version >= 2;
let locks = calculate_sequence_locks(&tx, &spent_heights, &seq_ctx, enforce_bip68);
if !check_sequence_locks(&locks, next_height, self.median_time_past) {
    return Err(MempoolError::SequenceLockNotSatisfied);
}
```

`enforce_bip68` is computed PURELY from tx.version, ignoring chain state.
On mainnet pre-CSV-activation (height < 419,328), a v2 tx with a relative
sequence-lock would have been treated as a no-op by Core (CSV not active
→ no semantic for sequence-lock fields), but rustoshi enforces the lock.

Currently latent on mainnet because CSV has been active since 2016. Breaks
regtest test fixtures that explicitly disable CSV (regtest activates CSV
at height 0 by default, but some fixtures override this).

**File:** `crates/consensus/src/mempool.rs:1678-1685`.

**Core ref:** `bitcoin-core/src/validation.cpp::CheckSequenceLocksAtTip`,
`bitcoin-core/src/consensus/tx_verify.cpp::CalculateSequenceLocks`.

**Impact:**
- Regtest fixture breakage where CSV is overridden off.
- Pre-CSV reindex (mainnet from-genesis): the mempool gate fires for v2
  txs at heights where Core wouldn't enforce — cross-impl divergence
  during IBD.

---

## BUG-19 (P2) — `output_sum` in `add_transaction_with_options` uses raw `.sum()`; theoretical overflow path

**Severity:** P2 (defensive depth; latent).
`crates/consensus/src/mempool.rs:1687`:
```rust
let output_sum: u64 = tx.outputs.iter().map(|o| o.value).sum();
```

`std::iter::Iterator::sum` for `u64` panics in debug builds and silently
wraps in release builds. `check_transaction` at the top of the function
(`:1368`) does enforce per-output `value <= MAX_MONEY` and cumulative
output `total_out <= MAX_MONEY`, so this path is currently unreachable in
practice. But:

- The cumulative check inside `check_transaction` uses
  `checked_add(...).ok_or(TotalOutputTooLarge)` — defense in depth.
- The `add_transaction_with_options` recomputation uses raw `.sum()` — no
  defense in depth.
- A theoretical bypass of `check_transaction` (e.g., a future refactor
  that adds a fast-path) would expose this to overflow.

This is the same "asymmetric defensive depth" pattern catalogued at W145
rustoshi (checked_add / saturating_add / raw on same MAX_MONEY-bounded
amounts within one impl).

**File:** `crates/consensus/src/mempool.rs:1687`.

**Core ref:** `bitcoin-core/src/consensus/tx_verify.cpp::CheckTxInputs`
uses `MoneyRange(nValueIn)` checks after every accumulation.

**Impact:** theoretical; documented for fleet pattern continuity.

---

## BUG-20 (P1) — `accept_package` uses package-fee saturating_sub which silently zeroes outputs > inputs

**Severity:** P1.
`crates/consensus/src/mempool.rs:4040`:
```rust
let fee = input_sum.saturating_sub(output_sum);
```

If a package-tx has missing inputs (input_sum=0) or has output > input by
design, `saturating_sub` returns 0 instead of erroring. The fee is then
summed into `package_fee` and used for the `package_fee_rate` floor check
(`:4067`). A package can thus pass the `package_fee_rate >= min_fee_rate`
gate while individual txs have **silently-zeroed** fees (or genuinely
negative balance).

The downstream `add_transaction_for_package` will catch genuinely missing
inputs via `MempoolError::MissingInput`, but the package-level fee gate
has already been satisfied by the inflated `package_fee_rate`.

**File:** `crates/consensus/src/mempool.rs:4040`.

**Core ref:** `bitcoin-core/src/validation.cpp::CheckTxInputs` errors with
`bad-txns-in-belowout` for input < output.

**Impact:** package-fee-rate gate can be bypassed via a package containing
a tx with input=0 (which will fail individually but already inflated the
package average).

---

## BUG-21 (P1) — `MempoolConfig` plumbed but `MempoolConfig::production()` never called from production code

**Severity:** P1 (dead-data plumbing; reverse of BUG-2).
Symmetric to BUG-2: the `MempoolConfig::production()` constructor exists
at `mempool.rs:785-790`:

```rust
pub fn production() -> Self {
    Self {
        verify_scripts: true,
        ..Default::default()
    }
}
```

Grep for call sites: ZERO production callers; only test files reference it.

The pattern: gate-defined ✓, constructor-defined ✓, no production wiring ✗.
This is the "wiring-look-but-no-wire" archetype (W138 fleet finding).

**File:** `crates/consensus/src/mempool.rs:785-790`;
`crates/rpc/src/server.rs:172, 199` (both use
`MempoolConfig::default()` not `MempoolConfig::production()`).

**Impact:** classic dead-helper plumbing. Single-line fix in
`server.rs` to swap `default()` → `production()` would close BUG-2.

---

## BUG-22 (P1) — Duplicate MTP helper functions `compute_prev_block_mtp` and `compute_mtp_via_store`

**Severity:** P1 ("code-duplication smell" — byte-similar helpers, cf.
W143 beamchain `merkle_pairs` / `merkle_pairs_check`).
Two MTP-computation helpers exist:

- `crates/rpc/src/server.rs:1205-1226` — `compute_prev_block_mtp(block_store,
  tip_hash) -> u32`; returns `0` for genesis-adjacent (window < 11).
- `rustoshi/src/main.rs:325-353` — `compute_mtp_via_store(block_store,
  tip_hash) -> Option<u32>`; returns `None` for genesis-adjacent.

Both compute the same median-of-11-timestamps quantity. The implementations
are functionally identical except for the genesis-edge return type (`u32`
zero vs `Option<u32> None`). Both are used by ATMP code paths to pass MTP
into `mempool.notify_new_tip()`:

- `server.rs:3694` (sendrawtransaction) — `compute_prev_block_mtp(...) as i64`
- `main.rs:3114` (P2P MSG_TX) — `compute_mtp_via_store(...).unwrap_or(0) as i64`

When the helpers DIVERGE in semantics (one returns 0 and one returns None
mapped to 0 via `unwrap_or(0)`), both currently land on the same value, but
a future fix to one helper that doesn't also fix the other would silently
diverge the two ATMP entry points (cross-cite BUG-14 two-pipeline ATMP).

**File:** `crates/rpc/src/server.rs:1205-1226`;
`rustoshi/src/main.rs:325-353`.

**Core ref:** `bitcoin-core/src/chain.cpp::CBlockIndex::GetMedianTimePast`
(single canonical implementation).

**Impact:**
- Future-fix divergence risk.
- Code-duplication smell; refactor candidate.

---

## BUG-23 (P1) — `recently_rejected` cache treats benign `WtxidAlreadyInMempool` as rejection

**Severity:** P1 (compounds BUG-13).
`rustoshi/src/main.rs:3239-3244`:

```rust
Err(e) => {
    tracing::debug!("Rejected tx {}: {}", txid, e);
    if rpc.recently_rejected.len() < 50_000 {
        rpc.recently_rejected.insert(txid);
    }
}
```

Any non-`MissingInput` mempool error is treated as a "real" rejection and
the txid is inserted into `recently_rejected`. This includes:

- `MempoolError::WtxidAlreadyInMempool` (benign — tx already in mempool;
  Core does NOT cache this as rejected)
- `MempoolError::TxnAlreadyKnown` (benign — tx already mined; Core does
  cache this but in a separate cache, not the reject cache)
- Various transient errors (e.g. `MempoolFull` should NOT be cached as
  reject — the tx may be admissible later when eviction frees space)

When `recently_rejected` contains a tx's txid, the P2P inv handler at
`main.rs:3076-3078` SUPPRESSES requesting the tx body:

```rust
if !rpc.mempool.contains(&item.hash)
    && !rpc.recently_rejected.contains(&item.hash)
{
    tx_requests.push(item.clone());
}
```

So a wtxid-duplicate that we (correctly) admitted gets re-relayed by a
peer; we error-cached it; we now ignore the inv → the tx is effectively
"forgotten" from our view of the network.

**File:** `rustoshi/src/main.rs:3239-3244, 3076-3078`.

**Core ref:**
`bitcoin-core/src/net_processing.cpp::PeerManagerImpl::ProcessMessage(TX)`
distinguishes cache classes via the `TxValidationResult` enum
(`TX_CONSENSUS` vs `TX_NOT_STANDARD` vs `TX_RECONSIDERABLE` vs `TX_CONFLICT`).

**Impact:** benign duplicates and transient failures get cached as
permanent rejections; downstream inv-handling silently drops honest
re-relay attempts.

---

## Summary

**Bug count:** 23 (BUG-1 through BUG-23).

**Severity distribution:**
- **P0-SEC:** 1 (BUG-2)
- **P0-CONS:** 2 (BUG-15, BUG-16)
- **P0-CDIV:** 5 (BUG-4, BUG-7, BUG-10, BUG-13, BUG-14)
- **P1:** 14 (BUG-1, BUG-3, BUG-5, BUG-6, BUG-8, BUG-9, BUG-11, BUG-12, BUG-17, BUG-18, BUG-20, BUG-21, BUG-22, BUG-23)
- **P2:** 1 (BUG-19)

**Fleet patterns confirmed:**
- **"verify_scripts=false default + production() unused"** (BUG-2 + BUG-21) — gates wired and tested but production constructor not flipped; first rustoshi instance of "wiring-look-but-no-wire" applied to the script-verification gate itself, equivalent in severity class to W138 ChainstateManager fleet pattern.
- **"three-pipeline drift"** (BUG-15) — main `add_transaction_with_options` / package `add_transaction_for_package` / reorg `block_disconnected` (via reorg_refill opts); package path is **byte-incompatible** with single-tx path on ~10 consensus gates. First rustoshi instance of the fleet-wide W143 pattern.
- **"two-pipeline guard 17th distinct extension"** (BUG-14) — RPC sendrawtransaction vs P2P MSG_TX; diverging post-admit behaviour.
- **"ConsensusScriptChecks static-MANDATORY scope-creep"** (BUG-7) — uses static instead of `GetBlockScriptFlags(tip)`; cross-cite W144 BUG-1 (rustoshi) `script_flag_exceptions` absent.
- **"reject-string wire-parity slippage"** (BUG-12, BUG-13) — `bip22_string()` exists Core-parity but the sendrawtransaction match arms use thiserror Display strings; W125 / W145 lunarblock 9-token sweep companion.
- **"operator-knob absence"** (BUG-8, BUG-10, BUG-11) — none of `-minrelaytxfee`, `-incrementalrelayfee`, `-dustrelayfee`, `-acceptnonstdtxn`, `-permitbaremultisig`, `-datacarriersize`, `-maxmempool`, `-mempoolexpiry`, `-limitancestorcount`, `-limitdescendantcount`, `-mempoolfullrbf` wired via CLI.
- **"comment-as-confession"** — BUG-2 `verify_scripts: false` (TODO admits gap), BUG-9 `is_dust` `_min_fee_rate` underscore-prefixed parameter, BUG-10 doc-comment "False on testnet/regtest or via the -acceptnonstdtxn knob" promises a knob that doesn't exist, BUG-16 comment "safe because non-coinbase-spending entries are simply excluded" is backwards. 4 distinct instances in one wave.
- **"dead-helper at-call-site"** (BUG-4, BUG-21) — `pre_check_ephemeral_tx` defined but called only from package path; `MempoolConfig::production()` defined but called only from tests.
- **"code-duplication smell"** (BUG-22) — two MTP helpers `compute_prev_block_mtp` and `compute_mtp_via_store`.
- **"unit-mismatch on fee rate"** (BUG-8) — `min_fee_rate: 1` (sat/vB) vs Core's `nMinRelayTxFee` (sat/kvB) = 10× too-strict gate.
- **"asymmetric defensive depth"** (BUG-19) — `check_transaction` uses `checked_add`, ATMP recomputation uses raw `.sum()`. Same shape as W145 rustoshi BUG cluster.
- **"STANDARD-flag superset"** (BUG-5) — rustoshi adds `SIGPUSHONLY` to STANDARD; Core does not. Cross-cite W144 fleet-wide flag-table discrepancies.
- **"orphan promote non-recursive"** (BUG-17) — single-pass children only.

**Top three findings:**

1. **BUG-2 (P0-SEC `verify_scripts: false` is production default)** —
   `MempoolConfig::default().verify_scripts = false` (`mempool.rs:747`).
   Both production constructors of `RpcState`
   (`crates/rpc/src/server.rs:172`, `:199`) use `MempoolConfig::default()`.
   The 80-line PolicyScriptChecks + ConsensusScriptChecks block at
   `mempool.rs:1861-1944` is **dead code in production**. Both
   sendrawtransaction and P2P MSG_TX admit invalid-signature transactions
   to the mempool and relay them to peers. The TODO at line 745 admits the
   gap is awaiting test-fixture migration. One-line fix: swap `default()`
   → `production()` in `server.rs:172, 199`. This is the largest in-rustoshi
   audit finding of this scope.

2. **BUG-15 (P0-CONS package-path skips every consensus gate)** —
   `add_transaction_for_package` (`mempool.rs:4143-4500`) is a parallel
   ATMP that runs check_transaction / check_standard / TRUC / cluster /
   ancestor / descendant / TrimToSize **but skips IsFinalTx, BIP-68
   CheckSequenceLocks, AreInputsStandard, IsWitnessStandard,
   MAX_STANDARD_TX_SIGOPS_COST, COINBASE_MATURITY, MoneyRange on inputs,
   PolicyScriptChecks, ConsensusScriptChecks, and PreCheckEphemeralTx**.
   Submitpackage RPC is the attack vector. Combined with BUG-16 (package
   entries hardcode `spends_coinbase: false`) gives a primitive for
   immature-coinbase spend that survives reorg.

3. **BUG-7 + BUG-14 cluster (ConsensusScriptChecks static-MANDATORY + two
   ATMP entries with divergent post-admit)** — `ConsensusScriptChecks` at
   `mempool.rs:1912-1921` uses a STATIC `ScriptFlags` (MANDATORY-only,
   ignores tip-derived activation state). Core uses
   `GetBlockScriptFlags(tip)`. Combined with BUG-14 (two ATMP entries —
   RPC at `server.rs:3699` and P2P at `main.rs:3117`), the same tx can be
   admitted/rejected differently across the two entries because each
   entry's post-admit work (orphan-promote, recently_rejected, broadcast
   strategy) is divergent. The RPC path leaks orphans into the orphanage
   forever; the P2P path correctly resolves them. Wire-parity divergence
   visible to cross-impl harness.
